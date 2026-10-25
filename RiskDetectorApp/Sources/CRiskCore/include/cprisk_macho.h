// 文件职责：不依赖 dyld/dladdr 的自包含 Mach-O 头发现与 section 查找。
// 在链路中的位置：为装甲/文本解密/完整性校验提供“当前镜像真实布局”，阻断 Clean Copy 攻击
// （攻击者 hook dyld API 后喂回一份干净副本）。
// 线程模型：全部为只读遍历，无全局状态、可重入；调用方需保证传入的 header 有效且镜像未被卸载。
// 平台限制：仅面向 64 位 Mach-O（mach_header_64）；不处理 fat/32 位镜像。
// 失败语义：查不到返回 NULL（fail-closed），调用方必须按“不可信/不可用”处理。
/*
 * cprisk_macho.h — Self-contained Mach-O header discovery & section lookup.
 *
 * Replaces dladdr() / getsectiondata() / _dyld_* to block Clean Copy attacks
 * where an attacker hooks dyld APIs to feed a pristine binary copy.
 *
 * All functions are static inline __attribute__((always_inline)) so the
 * compiler emits code directly in the caller's text section — no PLT/GOT
 * entries, no hookable symbols.
 */

#ifndef CPRISK_MACHO_H
#define CPRISK_MACHO_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <mach-o/loader.h>

/* ── Header discovery ─────────────────────────────────────────────── */

/*
 * Scan backward from addr_in_image (page-aligned) to locate the
 * mach_header_64 of the image containing that address.
 * Mach-O headers are always page-aligned and start with MH_MAGIC_64.
 * Limit: 256 MB (65536 × 4 KB pages) to prevent runaway scans.
 */
/// 从镜像内任意地址向上（低地址）逐页搜索所属镜像的 mach_header_64。
/// - Parameters:
///   - addr_in_image: 镜像内地址；允许未对齐，函数会先按 4 KiB 向下对齐。
/// - Returns: 找到则返回 header 指针（只读、由内核镜像持有）；否则 NULL。
/// - Thread safety: 只读，可重入。
/// - Platform: 仅 64 位 Mach-O；假设 header 页对齐且以 MH_MAGIC_64 开头。
/// - 失败语义: 返回 NULL 表示“无法证明镜像归属”，调用方不得继续信任该地址。
static inline __attribute__((always_inline))
const struct mach_header_64 *cprisk_find_own_header(const void *addr_in_image) {
    uintptr_t addr = (uintptr_t)addr_in_image;
    addr &= ~(uintptr_t)0xFFF;

    // 最多回退 65536 个 4 KiB 页（256 MiB），防止异常地址导致无界扫描。
    for (int i = 0; i < 65536; i++) {
        const struct mach_header_64 *hdr = (const struct mach_header_64 *)addr;
        // 组合校验 magic/cputype/filetype/ncmds/sizeofcmds，降低把普通数据误认成 header 的概率。
        if ((hdr->magic == MH_MAGIC_64 || hdr->magic == 0) &&
            hdr->cputype != 0 &&
            (hdr->filetype == MH_EXECUTE || hdr->filetype == MH_DYLIB ||
             hdr->filetype == MH_BUNDLE) &&
            hdr->ncmds > 0 && hdr->ncmds < 4096 &&
            hdr->sizeofcmds > 0 && hdr->sizeofcmds < 0x2000000u) {
            return hdr;
        }
        // 已到地址空间底部则停止，避免 uintptr_t 下溢回绕。
        if (addr < 0x1000) break;
        addr -= 0x1000;
    }
    return NULL;
}

/* ── ASLR slide computation ───────────────────────────────────────── */

/*
 * Compute the ASLR slide for an image given its runtime header address.
 * slide = runtime_header_addr − __TEXT.vmaddr (the on-disk virtual address).
 */
/// 计算镜像的 ASLR 偏移。
/// - Parameters:
///   - hdr: 运行时 mach_header_64 指针，必须来自 cprisk_find_own_header 或 dyld 有效镜像。
/// - Returns: slide = 运行时 __TEXT 地址 − 链接期 vmaddr；找不到 __TEXT 时返回 0。
/// - Thread safety: 只读，可重入。
/// - Platform: 仅 64 位 Mach-O。
/// - 失败语义: 返回 0 既可能是“无 slide”，也可能是“未找到 __TEXT”，调用方需结合镜像校验判断。
static inline __attribute__((always_inline))
intptr_t cprisk_compute_slide(const struct mach_header_64 *hdr) {
    const uint8_t *p = (const uint8_t *)(hdr + 1);
    const uint8_t *end = (const uint8_t *)hdr + sizeof(struct mach_header_64)
                        + hdr->sizeofcmds;
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        // 任何越界或零长度 load command 都说明 header 不可信，立即停止解析。
        if (lc->cmdsize == 0 || p + lc->cmdsize > end)
            break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)p;
            if (strncmp(seg->segname, "__TEXT", 6) == 0)
                return (intptr_t)((uintptr_t)hdr - seg->vmaddr);
        }
        p += lc->cmdsize;
    }
    return 0;
}

/* ── Section lookup ───────────────────────────────────────────────── */

/*
 * Locate a section by segment + section name, returning its runtime
 * (slid) address and size.  Drop-in replacement for getsectiondata().
 */
/// 按 segment/section 名查找 section 的运行时地址与大小，替代 getsectiondata()。
/// - Parameters:
///   - hdr: 有效的 mach_header_64 指针；NULL 会导致未定义行为，调用方须先校验。
///   - seg_name: segment 名（最多比较 16 字节，含结尾 NUL）。
///   - sect_name: section 名（最多比较 16 字节，含结尾 NUL）。
///   - size_out: 可选输出，写入 section 字节数；允许 NULL；失败时写 0。
/// - Returns: 成功返回运行时（已加 slide）地址；失败返回 NULL。
/// - Thread safety: 只读，可重入；返回指针指向镜像内存，生命周期同该镜像。
/// - Platform: 仅 64 位 Mach-O。
/// - 失败语义: 返回 NULL 且 *size_out=0；调用方不得把空 section 当成“校验通过”。
static inline __attribute__((always_inline))
const uint8_t *cprisk_find_section(
    const struct mach_header_64 *hdr,
    const char *seg_name,
    const char *sect_name,
    unsigned long *size_out
) {
    const intptr_t slide = cprisk_compute_slide(hdr);
    const uint8_t *p = (const uint8_t *)(hdr + 1);
    const uint8_t *end = (const uint8_t *)hdr + sizeof(struct mach_header_64)
                         + hdr->sizeofcmds;

    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize == 0 || p + lc->cmdsize > end)
            break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)p;
            // 先做乘法溢出与命令长度校验，再信任 nsects 去遍历 section 表。
            size_t seg_sz = sizeof(struct segment_command_64);
            size_t sect_sz = (size_t)seg->nsects * sizeof(struct section_64);
            if (sect_sz / sizeof(struct section_64) != (size_t)seg->nsects ||
                seg_sz + sect_sz > (size_t)lc->cmdsize)
                goto next_cmd;  /* overflow or malformed */
            if (strncmp(seg->segname, seg_name, 16) == 0) {
                const struct section_64 *sections =
                    (const struct section_64 *)(p + sizeof(*seg));
                for (uint32_t s = 0; s < seg->nsects; s++) {
                    if (strncmp(sections[s].sectname, sect_name, 16) == 0) {
                        if (size_out)
                            *size_out = (unsigned long)sections[s].size;
                        return (const uint8_t *)(sections[s].addr + slide);
                    }
                }
            }
        }
next_cmd:
        p += lc->cmdsize;
    }

    // 统一失败出口：清零 size_out，避免调用方读到上一次查询遗留的大小。
    if (size_out) *size_out = 0;
    return NULL;
}

#endif /* CPRISK_MACHO_H */
