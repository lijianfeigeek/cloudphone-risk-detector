// 文件职责：把任意指针区间换算成页对齐的 [起始页, 跨度) 表示，供 mprotect/vm_protect 使用。
// 安全不变量：所有地址运算先做溢出检查；非法输入返回 -1，绝不产出回绕后“看似合法”的范围。
// 线程模型：纯函数、无全局状态、可重入，可并发调用。
// 平台限制：页大小取自 sysconf(_SC_PAGESIZE)；iOS arm64 通常为 16 KiB，旧设备/模拟器可能为 4 KiB。
// 失败语义：返回 -1 时不写输出参数，调用方不得沿用输出参数的旧值。

#ifndef CPRISK_PAGE_SPAN_H
#define CPRISK_PAGE_SPAN_H

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

/// 查询系统页大小。
/// - Returns: 页大小（字节）；sysconf 失败或返回值不是 2 的幂时返回 0（表示“不可用”）。
/// - Thread safety: 可重入。
/// - Platform: 真机与模拟器一致，均走 sysconf。
static inline size_t cprisk_system_page_size_i(void) {
    const long value = sysconf(_SC_PAGESIZE);
    // 页大小必须是 2 的幂，否则后续位掩码对齐会算错；异常值一律视为不可用。
    if (value <= 0 || ((size_t)value & ((size_t)value - 1u)) != 0u)
        return 0u;
    return (size_t)value;
}

/* Explicit page size also permits deterministic 4K/16K boundary validation. */
/// 按指定页大小计算 [ptr, ptr+len) 覆盖的页范围。
/// - Parameters:
///   - ptr: 任意地址；允许未对齐，但不允许 NULL。
///   - len: 字节数，必须大于 0。
///   - size: 页大小，必须是非零的 2 的幂；显式传入便于测试 4K/16K 两种边界。
///   - page: 输出页对齐起始地址，不允许 NULL。
///   - span: 输出覆盖字节数（size 的整数倍），不允许 NULL。
/// - Returns: 0 成功；-1 表示参数非法、页大小非 2 的幂或地址运算溢出，此时不写输出参数。
/// - Thread safety: 可重入。
/// - 失败语义: 调用方必须放弃本次保护/擦除操作，不能假定范围部分有效。
static inline int cprisk_page_span_for_size_i(const void *ptr, size_t len,
                                              size_t size, uintptr_t *page,
                                              size_t *span) {
    if (!ptr || !len || !page || !span || !size || (size & (size - 1u)))
        return -1;
    const uintptr_t addr = (uintptr_t)ptr;
    const uintptr_t mask = size - 1u;
    // 先验证 addr+len 与向上取整都不会越过 uintptr_t，避免回绕成极小值。
    if (len > UINTPTR_MAX - addr || addr + len > UINTPTR_MAX - mask)
        return -1;
    const uintptr_t start = addr & ~mask;
    const uintptr_t end = (addr + len + mask) & ~mask;
    // 理论上不会发生；保留防御以挡住异常页大小导致的空跨度。
    if (end <= start)
        return -1;
    *page = start;
    *span = (size_t)(end - start);
    return 0;
}

/// 使用当前系统页大小计算页范围，是 cprisk_page_span_for_size_i 的便捷封装。
/// - Parameters:
///   - ptr: 任意地址；允许未对齐，但不允许 NULL。
///   - len: 字节数，必须大于 0。
///   - page: 输出页对齐起始地址（void*），不允许 NULL。
///   - span: 输出覆盖字节数，不允许 NULL。
/// - Returns: 0 成功；-1 表示参数非法、系统页大小不可用或地址运算溢出。
/// - Thread safety: 可重入。
/// - 失败语义: 系统页大小返回 0 时同样失败，调用方不应退化为猜测页大小。
static inline int cprisk_system_page_span_i(const void *ptr, size_t len,
                                            void **page, size_t *span) {
    uintptr_t start = 0u;
    if (!page || cprisk_page_span_for_size_i(ptr, len, cprisk_system_page_size_i(),
                                            &start, span) != 0)
        return -1;
    *page = (void *)start;
    return 0;
}
#endif
