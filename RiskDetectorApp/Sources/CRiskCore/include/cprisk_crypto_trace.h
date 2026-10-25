// 文件职责：SHA-256 / CPRisk-MAC 入口的耗时与执行扰动哨兵。
// 检测目标：(1) 小负载上的整体拖慢；(2) 同一区间 CNTPCT_EL0 与 mach_absolute_time 读数不一致；
//           (3) 确定性微工作负载结果偏离黄金摘要，说明执行被扰动（hook/trace/DBI）。
// 线程模型：所有共享状态为 C11 原子，无锁；flags 只增不减，consume 原子取走并清零。
// 平台限制：CNT/Mach 偏斜检测仅 arm64 真机有效；其他平台只保留慢速与不变量检查。
// 失败语义：flags 是“观测到异常”的累积位，调用方需结合上下文判定风险，不可单凭一位拒绝服务。
/*
 * cprisk_crypto_trace.h — Timing / trace sentinel for SHA-256 and CPRisk-MAC entry paths.
 *
 * Surfaces (1) gross slowdown on a tiny workload, (2) CNTPCT_EL0 vs Mach
 * disagreement on the same region (orthogonal to pure wall dilation), and
 * (3) deterministic LCG digest mismatch if execution is perturbed.
 */

#ifndef CPRISK_CRYPTO_TRACE_H
#define CPRISK_CRYPTO_TRACE_H

#include <stdint.h>

// 观测标志位集合；每一位由 cprisk_crypto_trace_primitive_enter_i 或记录路径置位。
enum {
    // bit0：小负载耗时超过阈值（cprisk_crypto_trace_threshold_ns_i 给出基准）。
    CPRISK_CRYPTO_TRACE_FLAG_SLOW = 1u << 0,
    /** CNTPCT-derived elapsed vs mach_absolute_time elapsed disagree (arm64 device). */
    // bit1：同区间 CNTPCT 与 mach 时间差显著不一致，提示虚拟化/时间Hook。
    CPRISK_CRYPTO_TRACE_FLAG_CNT_MACH_SKEW = 1u << 1,
    /** Deterministic micro-workload result diverged from the golden uint64 digest. */
    // bit2：确定性微工作负载结果与黄金 uint64 摘要不符，提示执行被扰动。
    CPRISK_CRYPTO_TRACE_FLAG_INVARIANT_FAIL = 1u << 2,
};

/// 读取单调时钟 tick（Mach absolute time 口径），惰性初始化 timebase。
/// - Returns: 自开机以来的 tick 数；换算纳秒需配合 timebase。
/// - Thread safety: 原子/一次性初始化，可并发调用。
/// - 副作用: 首次调用可能初始化 timebase，不修改任何 flag。
uint64_t cprisk_crypto_trace_now_i(void);

/// 记录一次耗时 span：换算为纳秒写入 last_ns，超过阈值则置 SLOW。
/// - Parameters:
///   - delta_ticks: cprisk_crypto_trace_now_i 的两次读数差；0 也合法。
/// - Returns: 无。
/// - Thread safety: 两次原子写、无锁；并发时 last_ns 只保留最新样本。
/// - 失败语义: 无错误返回；timebase 异常由调用方在读取 last_ns 时自行判断。
void cprisk_crypto_trace_record_span_ticks_i(uint64_t delta_ticks);

/// 加密原语入口探针：计时一小段确定性工作负载，并检测 CNT/Mach 偏斜与不变量。
/// - Returns: 无。
/// - Thread safety: 只写原子 flags/last_ns，可并发。
/// - Platform: CNT/Mach 偏斜仅 arm64 真机可比；其他平台跳过该项。
/// - 失败语义: 观测到异常时置对应 flag，不抛错、不阻断原语执行。
void cprisk_crypto_trace_primitive_enter_i(void);

/// 读取当前累积 flags，不清零。
/// - Returns: CPRISK_CRYPTO_TRACE_FLAG_* 位掩码。
/// - Thread safety: 原子读取，可并发。
uint32_t cprisk_crypto_trace_peek_flags_i(void);

/// 读取最近一次记录的 span 耗时。
/// - Returns: 纳秒数；尚未记录过时为 0。
/// - Thread safety: 原子读取。
uint64_t cprisk_crypto_trace_last_ns_i(void);

/// 返回 SLOW 判定阈值。
/// - Returns: 阈值纳秒数；供调用方/测试用同一基准解释 last_ns，避免两边写死数字产生漂移。
/// - Thread safety: 纯函数。
uint64_t cprisk_crypto_trace_threshold_ns_i(void);

/** Atomically ORs observed flags and returns the previous value (for tests/diagnostics). */
/// 原子读取并清零累积 flags。
/// - Returns: 清零前的 flags 位掩码（供测试/诊断消费一次）。
/// - Thread safety: 原子交换，可并发；每个位只会被一个调用方取走。
/// - 失败语义: 无。
uint32_t cprisk_crypto_trace_consume_flags_i(void);

#endif /* CPRISK_CRYPTO_TRACE_H */
