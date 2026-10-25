// 文件职责：无 IAT/GOT 的自定义符号解析器，直接读 dyld_all_image_infos 与 Mach-O Export Trie。
// 在链路中的位置：为装甲/反调试代码解析系统符号，避免标准 dlsym 暴露外部依赖并被静态分析或 hook。
// 线程模型：只读 dyld 内存，无锁、可重入；并发 dlopen/dlclose 时的镜像列表一致性由 dyld 保证。
// 平台限制：依赖 Mach 的 TASK_DYLD_INFO 与 64 位 Mach-O；仅支持常规 Export Trie，不支持 re-export。
// 失败语义：所有入口失败均返回 NULL/0，不写 errno；调用方必须按“符号不可用”降级。
/*
 * cprisk_dlsym.h — Custom IAT/GOT-free symbol resolver.
 *
 * Locates dyld_all_image_infos, finds the target image by name,
 * and parses its Mach-O Export Trie to find symbol addresses.
 * Avoids standard dlsym to hide external dependencies from static analysis.
 */

#ifndef CPRISK_DLSYM_H
#define CPRISK_DLSYM_H

#include <stdint.h>
#include <stddef.h>
#include <mach-o/loader.h>
#include <mach-o/dyld_images.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_init.h>

// 旧 SDK 可能缺少该常量；值与 <mach-o/loader.h> 中的 LC_DYLD_EXPORTS_TRIE 一致。
#ifndef LC_DYLD_EXPORTS_TRIE
#define LC_DYLD_EXPORTS_TRIE (0x80000033)
#endif

/// 自实现的字符串比较，语义与 libc strcmp 相同（按 unsigned char 比较）。
/// - Returns: 负数/0/正数，分别表示 s1 小于/等于/大于 s2。
/// - Thread safety: 可重入。
/// - 失败语义: s1/s2 为 NULL 时未定义；调用方须保证有效。
static inline __attribute__((always_inline))
int cprisk_strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

/// 自实现的子串查找，语义与 libc strstr 相同。
/// - Returns: 首次出现位置指针；未找到返回 NULL；needle 为空串时返回 haystack。
/// - Thread safety: 可重入。
static inline __attribute__((always_inline))
const char *cprisk_strstr(const char *haystack, const char *needle) {
    if (!*needle) return haystack;
    for (; *haystack; haystack++) {
        const char *h = haystack;
        const char *n = needle;
        while (*h && *n && *h == *n) {
            h++;
            n++;
        }
        if (!*n) return haystack;
    }
    return NULL;
}

/// 自实现的字符串长度，语义与 libc strlen 相同（不含结尾 NUL）。
/// - Thread safety: 可重入；s 为 NULL 时未定义。
static inline __attribute__((always_inline))
size_t cprisk_strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

// ULEB128 最多 10 字节（64 位值 × 7 bit/字节向上取整），超过即视为损坏数据。
#define CPRISK_ULEB128_MAX_ITER 10

/// 从 [*p, end) 解码一个 ULEB128 无符号整数，并前移 *p。
/// - Parameters:
///   - p: 输入输出游标；不允许 NULL，且 *p 必须落在 [start, end] 内。
///   - end: 缓冲区末尾（不含）；用于边界检查。
/// - Returns: 解码值；越界或迭代超限时返回 0 且 *p 位置不确定。
/// - Thread safety: 只操作调用方状态，可重入。
/// - 失败语义: 0 同时可能是合法值，调用方需结合游标是否前进判断解码失败。
static inline __attribute__((always_inline))
uint64_t cprisk_read_uleb128(const uint8_t **p, const uint8_t *end) {
    uint64_t result = 0;
    int bit = 0;
    int iter = 0;
    do {
        if (*p >= end || iter >= CPRISK_ULEB128_MAX_ITER)
            return 0;
        uint64_t slice = **p & 0x7f;
        result |= (slice << bit);
        bit += 7;
        iter++;
    } while (*(*p)++ & 0x80);
    return result;
}

/// 深度优先遍历 Export Trie 查找符号，返回导出偏移（相对镜像基址）。
/// - Parameters:
///   - start: Trie 起始地址（镜像内），用于换算 node_offset。
///   - end: Trie 末尾（不含），所有读取都需先与它比较。
///   - p: 当前节点地址；首次调用传 start。
///   - symbol: 待查符号名（通常是带前导下划线的 C 符号）。
/// - Returns: 命中返回非零导出偏移（尚未加 ASLR slide）；未命中/数据损坏返回 NULL。
/// - Thread safety: 只读，可重入。
/// - 失败语义: 不支持 REEXPORT 节点，遇到即返回 NULL；递归深度受符号长度约束。
static inline __attribute__((always_inline))
void *cprisk_walk_export_trie(const uint8_t *start, const uint8_t *end, const uint8_t *p, const char *symbol) {
    if (p >= end) return NULL;
    uint64_t terminal_size = cprisk_read_uleb128(&p, end);
    const uint8_t *children = p + terminal_size;
    // terminal_size 可能被损坏成超大值，先确认子节点区仍在 Trie 内。
    if (children > end) return NULL;

    if (terminal_size != 0 && *symbol == '\0') {
        uint64_t flags = cprisk_read_uleb128(&p, end);
        if (flags & EXPORT_SYMBOL_FLAGS_REEXPORT) {
            return NULL; /* Re-exports not supported in basic resolver */
        }
        uint64_t symbol_offset = cprisk_read_uleb128(&p, end);
        return (void *)(uintptr_t)symbol_offset;
    }

    if (children >= end) return NULL;
    uint8_t child_count = *children++;
    for (uint8_t i = 0; i < child_count; i++) {
        if (children >= end) return NULL;
        // edge_label 是 NUL 结尾的边标签；结点布局为 [label\0][uleb node_offset]。
        const char *edge_label = (const char *)children;
        while (children < end && *children != '\0') {
            children++;
        }
        if (children >= end) return NULL;
        children++;
        uint64_t node_offset = cprisk_read_uleb128(&children, end);
        // 偏移 0 或越界都视为损坏结点，跳过而不是中止整次遍历。
        if (node_offset == 0 || (start + node_offset) >= end) continue; /* skip invalid node */

        int match = 1;
        int j = 0;
        while (edge_label[j] != '\0') {
            if (symbol[j] != edge_label[j]) {
                match = 0;
                break;
            }
            j++;
        }
        if (match) {
            // 命中前缀后递归匹配剩余符号名；j 为已消费的字符数。
            return cprisk_walk_export_trie(start, end, start + node_offset, symbol + j);
        }
    }
    return NULL;
}

/// 在指定镜像中解析符号运行时地址（替代 dlsym 的自定义实现）。
/// - Parameters:
///   - image_name: 镜像路径的子串（如 "libSystem.B.dylib"），按 cprisk_strstr 匹配首个命中。
///   - symbol: 不带前导下划线的符号名；内部补 '_' 后到 Export Trie 查找，最长 254 字节。
/// - Returns: 成功返回运行时地址；失败（镜像未找到、无 __LINKEDIT/导出表、符号未命中）返回 NULL。
/// - Thread safety: 只读 dyld 数据，可重入；不做缓存，每次调用重新遍历。
/// - Platform: 依赖 TASK_DYLD_INFO；仅 64 位 Mach-O；不支持 re-export 符号。
/// - 失败语义: 不写 errno；调用方应把 NULL 当作“功能不可用”并 fail-closed/降级。
static inline __attribute__((always_inline))
void *cprisk_dlsym(const char *image_name, const char *symbol) {
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;

    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) != 0) {
        return NULL;
    }

    struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyld_info.all_image_info_addr;
    if (!infos) return NULL;

    for (uint32_t i = 0; i < infos->infoArrayCount; i++) {
        const char *path = infos->infoArray[i].imageFilePath;
        if (!path) continue;
        if (cprisk_strstr(path, image_name) != NULL) {
            const struct mach_header_64 *hdr = (const struct mach_header_64 *)infos->infoArray[i].imageLoadAddress;
            const uint8_t *p = (const uint8_t *)(hdr + 1);
            const uint8_t *end = (const uint8_t *)hdr + sizeof(struct mach_header_64) + hdr->sizeofcmds;
            intptr_t slide = 0;
            const struct segment_command_64 *linkedit = NULL;
            uint32_t export_off = 0;
            uint32_t export_size = 0;

            // 遍历 load commands，收集 ASLR slide、__LINKEDIT 段与导出表位置。
            for (uint32_t j = 0; j < hdr->ncmds; j++) {
                if (p + sizeof(struct load_command) > end) break;
                const struct load_command *lc = (const struct load_command *)p;
                if (lc->cmdsize == 0) break;
                if (p + lc->cmdsize > end) break;
                if (lc->cmd == LC_SEGMENT_64) {
                    const struct segment_command_64 *seg = (const struct segment_command_64 *)p;
                    if (cprisk_strcmp(seg->segname, "__TEXT") == 0) {
                        slide = (intptr_t)hdr - seg->vmaddr;
                    } else if (cprisk_strcmp(seg->segname, "__LINKEDIT") == 0) {
                        linkedit = seg;
                    }
                } else if (lc->cmd == LC_DYLD_INFO || lc->cmd == LC_DYLD_INFO_ONLY) {
                    const struct dyld_info_command *cmd = (const struct dyld_info_command *)p;
                    export_off = cmd->export_off;
                    export_size = cmd->export_size;
                } else if (lc->cmd == LC_DYLD_EXPORTS_TRIE) {
                    const struct linkedit_data_command *cmd = (const struct linkedit_data_command *)p;
                    export_off = cmd->dataoff;
                    export_size = cmd->datasize;
                }
                p += lc->cmdsize;
            }

            if (linkedit && export_off != 0 && export_size != 0) {
                // __LINKEDIT 的文件偏移与虚拟地址不同，需要先按 slide 换算成运行时基址。
                uintptr_t linkedit_base = linkedit->vmaddr + slide - linkedit->fileoff;
                const uint8_t *export_trie = (const uint8_t *)(linkedit_base + export_off);

                /* Mach-O symbols in export trie typically begin with an underscore '_' */
                // 栈上固定 256 字节：1 个下划线 + 最多 254 字符 + NUL，超长符号直接截断。
                char sym_with_underscore[256];
                sym_with_underscore[0] = '_';
                size_t sym_len = cprisk_strlen(symbol);
                if (sym_len > 254) sym_len = 254;
                for (size_t k = 0; k < sym_len; k++) {
                    sym_with_underscore[k + 1] = symbol[k];
                }
                sym_with_underscore[sym_len + 1] = '\0';

                // Trie 返回的是相对镜像基址的偏移，需加到运行时 header 地址上。
                void *offset = cprisk_walk_export_trie(export_trie, export_trie + export_size, export_trie, sym_with_underscore);
                if (offset) {
                    return (void *)((uintptr_t)hdr + (uintptr_t)offset); 
                }
            }
        }
    }
    return NULL;
}

#endif /* CPRISK_DLSYM_H */
