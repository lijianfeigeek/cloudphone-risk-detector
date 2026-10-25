/*
 * cprisk_image_check.c — Address-in-image check without dladdr.
 *
 * Uses task_info + dyld_all_image_infos to iterate loaded images and
 * parse Mach-O segments. Returns 1 if addr falls within any image's
 * __TEXT/__DATA/__LINKEDIT/etc., 0 otherwise.
 *
 * Resistant to dladdr hook: does not call dladdr or _dyld_*.
 */

// 文件职责：不依赖 dladdr/_dyld_*，直接经 TASK_DYLD_INFO 取 dyld_all_image_infos，
// 解析每个 Mach-O 的 LC_SEGMENT_64，判断地址是否归属某个已加载镜像（可选只看可执行段）。
// 归属判定：用 __TEXT.vmaddr 推得 slide，再把各段 vmaddr+vmsize 映射到运行期区间，
//   完全按段区间判断，不信任路径字符串；路径只用于布局摘要，且按 dyld 原样字节哈希。
// 失败语义：dyld 信息不可读、镜像头非法、段命令越界时返回 0（未归属/未命中），
//   调用方不能把 0 当成“地址一定不属于镜像”的证明（fail-open 的采样器）。
// 线程模型：只读进程内 dyld 结构，可并发调用；摘要基线用原子 valid 标志发布。

#include <stdint.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <mach-o/loader.h>
#include <mach-o/dyld_images.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_init.h>
#include <mach/vm_prot.h>

#include "include/cprisk_sha256.h"

// 比较最多 n 字节的段名：任一串先遇到 '\0' 即视为相等（兼容 16 字节定长字段）。
// 只用于 "__TEXT" 这类短常量名，不参与路径匹配。
static int segname_eq(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return 0;
        if (a[i] == '\0') return 1;
    }
    return 1;
}

// 对 addr 所在整页（向下对齐）做 SHA-256：调用方用页级摘要比较代码是否被改写。
// 页大小来自 sysconf，异常值回退 4096；摘要覆盖整页而非 len，因为 __TEXT 的
// 完整性以页为粒度，且调用方通常只持有页内地址。
// 要求该页可读；不可读会触发访问异常，本函数不做保护，NULL 输入直接返回。
void cprisk_sha256_text_page(const void *addr, uint8_t out_digest[32]) {
    if (!addr || !out_digest) {
        return;
    }
    long pgsz = sysconf(_SC_PAGESIZE);
    if (pgsz <= 0 || pgsz > 0x1000000l) {
        pgsz = 4096l;
    }
    const uintptr_t mask = (uintptr_t)((size_t)pgsz - 1u);
    const uint8_t *page = (const uint8_t *)((uintptr_t)addr & ~mask);
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, page, (size_t)pgsz);
    cprisk_sha256_final(&ctx, out_digest);
}

// 判断地址是否落在任一已加载镜像的任意段内（不区分权限）。
// 两遍扫描：第一遍找 __TEXT 计算 slide，第二遍用 slide 还原各段运行期区间；
// 没有 __TEXT 的镜像直接跳过（无法可靠定位）。
// 返回 1 = 归属某镜像；0 = 不归属或无法判定（dyld 信息不可读等）。
int cprisk_addr_in_any_image(const void *addr) {
    uintptr_t target = (uintptr_t)addr;

    // 通过 TASK_DYLD_INFO 取内部指针，不经过可能被 hook 的 dladdr/_dyld_* API。
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;

    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) != 0) {
        return 0;
    }

    struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyld_info.all_image_info_addr;
    if (!infos || !infos->infoArray) return 0;

    for (uint32_t i = 0; i < infos->infoArrayCount; i++) {
        const struct mach_header_64 *hdr = (const struct mach_header_64 *)infos->infoArray[i].imageLoadAddress;
        if (!hdr) continue;

        // 魔数与 sizeofcmds 上限是防御性校验：损坏/伪造的镜像头可能让
        // load command 指针越界，宁可跳过该镜像也不读非法内存。
        if (hdr->magic != MH_MAGIC_64) continue;
        /* Guard against corrupt sizeofcmds causing pointer overflow */
        if (hdr->sizeofcmds > 0x100000u) continue;

        intptr_t slide = 0;
        int found_text = 0;
        const uint8_t *p = (const uint8_t *)(hdr + 1);
        const uint8_t *end = (const uint8_t *)hdr + sizeof(struct mach_header_64) + hdr->sizeofcmds;

        /* First pass: get slide from __TEXT */
        // slide = 实际加载地址 - 链接时 vmaddr；同一镜像所有段共用这一个 slide。
        // 命令长度做 end 边界检查，损坏的 cmdsize 只会提前结束扫描，不会越界。
        for (uint32_t j = 0; j < hdr->ncmds; j++) {
            if (p + sizeof(struct load_command) > end) break;
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmdsize == 0 || p + lc->cmdsize > end) break;

            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)p;
                if (segname_eq(seg->segname, "__TEXT", 16)) {
                    slide = (intptr_t)hdr - (intptr_t)seg->vmaddr;
                    found_text = 1;
                    break;
                }
            }
            p += lc->cmdsize;
        }

        if (!found_text) continue;

        /* Second pass: check each segment */
        // 第二遍只做区间比较；加法前检查 vmsize 非零且不溢出，避免回绕后误判归属。
        p = (const uint8_t *)(hdr + 1);
        for (uint32_t j = 0; j < hdr->ncmds; j++) {
            if (p + sizeof(struct load_command) > end) break;
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmdsize == 0 || p + lc->cmdsize > end) break;

            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)p;
                uintptr_t runtime_start = (uintptr_t)seg->vmaddr + (uintptr_t)slide;
                if (seg->vmsize > 0 && runtime_start <= UINTPTR_MAX - seg->vmsize) {
                    uintptr_t runtime_end = runtime_start + seg->vmsize;
                    if (target >= runtime_start && target < runtime_end) {
                        return 1;
                    }
                }
            }
            p += lc->cmdsize;
        }
    }
    return 0;
}

// 段是否“可执行”：initprot 或 maxprot 含 EXECUTE，或段名就是 __TEXT。
// 名称兜底用于部分工具链把 __TEXT 的权限位标成非典型值的镜像。
static int seg_is_executable_mapping_i(const struct segment_command_64 *seg) {
    if (!seg) {
        return 0;
    }
    if (((seg->initprot & VM_PROT_EXECUTE) != 0) || ((seg->maxprot & VM_PROT_EXECUTE) != 0)) {
        return 1;
    }
    /* __TEXT conventionally holds executable pages even if prot bits are unusual. */
    return segname_eq(seg->segname, "__TEXT", 16) ? 1 : 0;
}

// 与 cprisk_addr_in_any_image 相同的两遍扫描，但只统计可执行段。
// 用途：判断某个“声称来自系统库”的函数指针是否真的落在已加载镜像的可执行段内；
// 返回 0 可能是“不归属”，也可能是 dyld 信息不可读，调用方需区分场景使用。
int cprisk_addr_in_any_image_executable(const void *addr) {
    uintptr_t target = (uintptr_t)addr;

    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;

    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) != 0) {
        return 0;
    }

    struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyld_info.all_image_info_addr;
    if (!infos || !infos->infoArray) return 0;

    for (uint32_t i = 0; i < infos->infoArrayCount; i++) {
        const struct mach_header_64 *hdr = (const struct mach_header_64 *)infos->infoArray[i].imageLoadAddress;
        if (!hdr) continue;

        if (hdr->magic != MH_MAGIC_64) continue;
        if (hdr->sizeofcmds > 0x100000u) continue;

        intptr_t slide = 0;
        int found_text = 0;
        const uint8_t *p = (const uint8_t *)(hdr + 1);
        const uint8_t *end = (const uint8_t *)hdr + sizeof(struct mach_header_64) + hdr->sizeofcmds;

        for (uint32_t j = 0; j < hdr->ncmds; j++) {
            if (p + sizeof(struct load_command) > end) break;
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmdsize == 0 || p + lc->cmdsize > end) break;

            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)p;
                if (segname_eq(seg->segname, "__TEXT", 16)) {
                    slide = (intptr_t)hdr - (intptr_t)seg->vmaddr;
                    found_text = 1;
                    break;
                }
            }
            p += lc->cmdsize;
        }

        if (!found_text) continue;

        p = (const uint8_t *)(hdr + 1);
        for (uint32_t j = 0; j < hdr->ncmds; j++) {
            if (p + sizeof(struct load_command) > end) break;
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmdsize == 0 || p + lc->cmdsize > end) break;

            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)p;
                // 非可执行段直接跳过；这里显式推进游标后再 continue，
                // 是为了绕开循环底部的统一推进，避免同一条 load command 被前进两次。
                if (!seg_is_executable_mapping_i(seg)) {
                    p += lc->cmdsize;
                    continue;
                }
                uintptr_t runtime_start = (uintptr_t)seg->vmaddr + (uintptr_t)slide;
                if (seg->vmsize > 0 && runtime_start <= UINTPTR_MAX - seg->vmsize) {
                    uintptr_t runtime_end = runtime_start + seg->vmsize;
                    if (target >= runtime_start && target < runtime_end) {
                        return 1;
                    }
                }
            }
            p += lc->cmdsize;
        }
    }
    return 0;
}

/*
 * Runtime __TEXT bounds for a loaded Mach-O 64 image (dyld infoArray entry).
 * Used by layout digest v2 for segment-ownership differential vs path+base alone.
 */
// 取单个 Mach-O 的 __TEXT 运行期 [start, start+size)，供布局摘要 v2 使用。
// 找不到 __TEXT、头部非法或命令越界返回 -1；成功写入 out_start/out_size 并返回 0。
// 该区间是“段归属”证据：仅靠 path+base 无法发现同路径镜像内部的段布局漂移。
static int cprisk_macho64_text_runtime_bounds(
    const struct mach_header_64 *hdr,
    uintptr_t *out_start,
    uint64_t *out_size
) {
    if (!hdr || !out_start || !out_size || hdr->magic != MH_MAGIC_64 || hdr->sizeofcmds > 0x100000u) {
        return -1;
    }
    const uint8_t *p = (const uint8_t *)(hdr + 1);
    const uint8_t *end = (const uint8_t *)hdr + sizeof(struct mach_header_64) + hdr->sizeofcmds;
    intptr_t slide = 0;
    uintptr_t text_start = 0u;
    uint64_t text_size = 0u;
    int found_text = 0;

    for (uint32_t j = 0; j < hdr->ncmds; j++) {
        if (p + sizeof(struct load_command) > end) {
            break;
        }
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize == 0 || p + lc->cmdsize > end) {
            break;
        }
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)p;
            if (segname_eq(seg->segname, "__TEXT", 16)) {
                slide = (intptr_t)hdr - (intptr_t)seg->vmaddr;
                text_start = (uintptr_t)seg->vmaddr + (uintptr_t)slide;
                text_size = seg->vmsize;
                found_text = 1;
                break;
            }
        }
        p += lc->cmdsize;
    }
    if (!found_text) {
        return -1;
    }
    *out_start = text_start;
    *out_size = text_size;
    return 0;
}

// 计算 dyld 镜像布局摘要 v2：标签 || 镜像数(LE32) || 每个镜像的
//   path 原样字节 || NUL || load base(LE64) || __TEXT start(LE64) || __TEXT size(LE64)。
// path 不做大小写/符号链接/尾部斜杠归一化，直接使用 dyld 提供的内存表示，
// 因为同一进程内该表示稳定；跨构建比较需在采集端做同等归一化。
// 返回 0 = 摘要已写；-1 = task_info/dyld 数组不可用、镜像数为 0 或超过 4096（拒绝病态输入）。
// 这是结构指纹，不是代码签名：它不校验代码字节，只反映“加载了谁、加载在哪”。
int cprisk_vm_dyld_image_layout_digest(uint8_t out_digest[32]) {
    if (!out_digest)
        return -1;

    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) != 0) {
        return -1;
    }

    struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyld_info.all_image_info_addr;
    if (!infos || !infos->infoArray || infos->infoArrayCount == 0u) {
        return -1;
    }

    // 4096 是正常进程镜像数的量级上限；超过即视为异常/被污染，直接拒绝计算，
    // 避免攻击者用超大 infoArrayCount 造成长时间遍历。
    uint32_t ic = infos->infoArrayCount;
    if (ic > 4096u) {
        return -1;
    }

    // 域标签参与哈希，防止摘要被跨版本/跨用途重放。
    static const uint8_t k_lab[] = "cprisk.dyld.layout.v2";
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, k_lab, sizeof(k_lab) - 1u);

    uint8_t ic_le[4];
    ic_le[0] = (uint8_t)(ic & 0xFFu);
    ic_le[1] = (uint8_t)((ic >> 8) & 0xFFu);
    ic_le[2] = (uint8_t)((ic >> 16) & 0xFFu);
    ic_le[3] = (uint8_t)((ic >> 24) & 0xFFu);
    cprisk_sha256_update(&ctx, ic_le, sizeof(ic_le));

    for (uint32_t i = 0; i < ic; i++) {
        const char *path = infos->infoArray[i].imageFilePath;
        if (path) {
            size_t plen = 0;
            while (path[plen] != '\0' && plen < 4096u) {
                plen++;
            }
            cprisk_sha256_update(&ctx, (const uint8_t *)path, plen);
        }
        const uint8_t z = 0;
        cprisk_sha256_update(&ctx, &z, 1);

        const uintptr_t base = (uintptr_t)infos->infoArray[i].imageLoadAddress;
        uint8_t ble[8];
        for (unsigned b = 0; b < 8; b++) {
            ble[b] = (uint8_t)(base >> (8u * b));
        }
        cprisk_sha256_update(&ctx, ble, sizeof(ble));

        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)infos->infoArray[i].imageLoadAddress;
        uintptr_t tstart = 0u;
        uint64_t tsz = 0u;
        if (!mh || mh->magic != MH_MAGIC_64 ||
            cprisk_macho64_text_runtime_bounds(mh, &tstart, &tsz) != 0) {
            tstart = 0u;
            tsz = 0u;
        }
        uint8_t tle[8];
        for (unsigned b = 0; b < 8; b++) {
            tle[b] = (uint8_t)(tstart >> (8u * b));
        }
        cprisk_sha256_update(&ctx, tle, sizeof(tle));
        uint8_t tszle[8];
        for (unsigned b = 0; b < 8; b++) {
            tszle[b] = (uint8_t)(tsz >> (8u * b));
        }
        cprisk_sha256_update(&ctx, tszle, sizeof(tszle));
    }

    cprisk_sha256_final(&ctx, out_digest);
    return 0;
}

// 布局摘要基线（32 字节）与“基线已建立”发布标志。
// 写入顺序：先 memcpy 摘要，再 release 置 valid；读取侧 acquire 后再比较，
// 保证不会读到半个基线。
static uint8_t s_dyld_layout_digest_baseline[32];
static atomic_int s_dyld_layout_digest_baseline_valid;

// 显式建立基线：仅当当前摘要可计算时覆盖旧基线；计算失败则保持原基线不变。
// 用于“确认当前状态可信”的初始化阶段，例如解密/加固完成之后。
void cprisk_vm_dyld_image_layout_digest_baseline_snapshot(void) {
    uint8_t d[32];
    if (cprisk_vm_dyld_image_layout_digest(d) != 0) {
        return;
    }
    memcpy(s_dyld_layout_digest_baseline, d, sizeof(s_dyld_layout_digest_baseline));
    atomic_store_explicit(&s_dyld_layout_digest_baseline_valid, 1, memory_order_release);
}

// 与基线比较：1 = 布局已变化；0 = 一致或“本次刚建立基线”；-1 = 当前摘要无法计算。
// 首次调用（基线未建立）会就地建立基线并返回 0，因此调用方不能把首次结果当“无变化”证据。
// -1 表示未知，调用方应按“无法确认”处理，不得当作 0。
int cprisk_vm_dyld_image_layout_digest_differs_from_baseline(void) {
    uint8_t now[32];
    if (cprisk_vm_dyld_image_layout_digest(now) != 0) {
        return -1;
    }
    if (atomic_load_explicit(&s_dyld_layout_digest_baseline_valid, memory_order_acquire) == 0) {
        memcpy(s_dyld_layout_digest_baseline, now, sizeof(s_dyld_layout_digest_baseline));
        atomic_store_explicit(&s_dyld_layout_digest_baseline_valid, 1, memory_order_release);
        return 0;
    }
    return memcmp(now, s_dyld_layout_digest_baseline, sizeof(s_dyld_layout_digest_baseline)) != 0 ? 1 : 0;
}
