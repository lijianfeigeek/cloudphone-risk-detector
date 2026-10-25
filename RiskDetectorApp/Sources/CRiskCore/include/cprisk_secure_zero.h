// 文件职责：提供编译器无法优化掉的敏感内存清零原语，供密钥、摘要与 MAC 中间态擦除使用。
// 安全不变量：逐字节 volatile 写，保证清零不会被“死存储消除”优化删掉。
// 线程模型：无全局状态、可重入；调用方需自行保证目标区间不被并发读写。
// 平台限制：纯 C，无平台分支；只保证本进程视角的写入，不覆盖 DMA/其他进程。
// 失败语义：无返回值；参数非法时静默返回，调用方应传入真实长度。
/*
 * cprisk_secure_zero.h — Compiler-safe secure memory wipe.
 *
 * Uses volatile writes to prevent dead-store elimination. Forced inline
 * so no PLT/GOT symbol is generated for hooking.
 */

#ifndef CPRISK_SECURE_ZERO_H
#define CPRISK_SECURE_ZERO_H

#include <stddef.h>
#include <stdint.h>

/// 将 [ptr, ptr+len) 区间清零，用于擦除密钥、摘要、MAC 中间态等敏感数据。
/// - Parameters:
///   - ptr: 目标缓冲区，所有权仍归调用方；允许 NULL（直接返回）。
///   - len: 要清零的字节数；0 或超过 1 GiB 时直接返回。
/// - Returns: 无。
/// - Thread safety: 可重入、无锁；但不得与对同一区间的并发访问同时进行。
/// - Platform: 所有平台一致，仅依赖 volatile 写语义。
/// - 失败语义: 参数非法时不触碰任何内存，也不报错；调用方不能据此判断清零成功。
static inline __attribute__((always_inline))
void cprisk_secure_zero(void *ptr, size_t len) {
    // 1 GiB 上限用于挡住 len 为 (size_t)-1 之类的整型下溢，避免误清零整段地址空间后崩溃。
    if (!ptr || len == 0 || len > (1UL << 30))
        return;
    // volatile 指针让优化器无法证明这些写入“不可观察”，从而必须保留每一次清零写。
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
}

#endif /* CPRISK_SECURE_ZERO_H */
