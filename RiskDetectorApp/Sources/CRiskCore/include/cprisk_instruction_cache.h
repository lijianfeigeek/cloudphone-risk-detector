// 文件职责：在运行时代码写入/解密之后刷新指令缓存，保证 CPU 取到新指令。
// 使用时机：对可执行页完成写入（inline patch、VM 解密回填、跳板生成）之后、跳转执行之前。
// 线程模型：无全局状态、可重入；但调用方必须保证刷新期间目标区间没有其他线程正在执行。
// 平台限制：Apple 平台走 sys_icache_invalidate（处理 D-cache/I-cache 一致性）；
//           其他平台退回 __builtin___clear_cache，实际语义由编译器与目标架构决定。
// 失败语义：无返回值；NULL 或 0 长度静默返回，不会报错。

#ifndef CPRISK_INSTRUCTION_CACHE_H
#define CPRISK_INSTRUCTION_CACHE_H

#include <stddef.h>

#if defined(__APPLE__)
#include <libkern/OSCacheControl.h>
#endif

/// 使 [address, address+length) 区间的指令缓存失效。
/// - Parameters:
///   - address: 代码区间起始地址；允许 NULL（无操作）。
///   - length: 字节数；0 表示无操作。
/// - Returns: 无。
/// - Thread safety: 函数自身可重入、无锁；与目标区间并发执行的互斥由调用方负责。
/// - Platform: Apple 使用 sys_icache_invalidate；其他平台使用编译器内建清理。
/// - 失败语义: 无错误反馈；若平台缺少有效实现，调用方需自行加内存屏障或降级。
static inline void cprisk_flush_instruction_cache(void *address, size_t length) {
    if (address == NULL || length == 0u) {
        return;
    }

#if defined(__APPLE__)
    sys_icache_invalidate(address, length);
#else
    char *start = (char *)address;
    __builtin___clear_cache(start, start + length);
#endif
}

#endif /* CPRISK_INSTRUCTION_CACHE_H */
