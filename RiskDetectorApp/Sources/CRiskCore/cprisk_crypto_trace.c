/*
 * cprisk_crypto_trace.c — Mach time + orthogonal trace sentinels for crypto primitive paths.
 */

// 职责：为 SHA-256 / CPRisk-MAC 等密码原语入口提供轻量计时哨兵与确定性工作负载，
//   用于发现 DBI/Stalker 插桩、时钟虚拟化以及指令流扰动。
// 线程模型：跨调用状态用 C11 原子保护；探针可在任意线程并发执行，flag 在两次 consume
//   之间只增不减，消费方用 consume 原子取走并清零。
// 平台/架构：CNTPCT_EL0 分支只在 arm64 Apple 真机上启用，模拟器仅保留 Mach 时钟与不变量校验。
// 失败语义：fail-open——只置位报告，不改变被观测密码原语自身的返回值。

#include "include/cprisk_crypto_trace.h"

#include <TargetConditionals.h>
#include <mach/mach_time.h>
#include <stdatomic.h>

// 平台闸门：只有 arm64 Apple 真机才有可信的 CNTPCT_EL0；模拟器读到的是宿主计数器，
// 拿它做正交比较会产生假阳性。下面所有相关分支都据此裁剪。
#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__)) && \
    (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
#define CPRISK_CRYPTO_TRACE_ARM64_DEVICE 1
#else
#define CPRISK_CRYPTO_TRACE_ARM64_DEVICE 0
#endif

/* Conservative: native runs are sub-µs; DBI/Stalker often pushes this to 10µs+. */
// SLOW 阈值取 25 微秒：原生 64 轮整数运算远低于 1 微秒，而 DBI/Stalker 往往推到
// 10 微秒以上；留出调度抖动余量，避免偶发抢占被判成插桩。
enum { CPRISK_CRYPTO_TRACE_SLOW_NS = 25000u };

/* Golden digest for the 64-round inline workload (uint64 wrap). */
// 固定工作负载的期望摘要（依赖 uint64 自然回绕）。指令流被改写、模拟或虚拟化后
// 结果几乎必然不同；修改工作负载必须同步更新此常量，否则会永久误报。
static const uint64_t k_cprisk_crypto_trace_acc_expected =
    UINT64_C(0x05F45B2ECA50430B);

// mach_timebase_info 缓存：成功取一次即可。ready 用普通 uint32 而非原子，
// 因为重复初始化写入的是同一组值，最坏情况只是多一次系统调用。
static mach_timebase_info_data_t s_timebase;
static uint32_t s_timebase_ready;

// 全局观测状态：flags 只增不减（peek 读取、consume 取走并清零）；last_ns 记录
// 最近一次有效 span，0 表示尚无样本。原子类型保证读者不会看到撕裂值。
static atomic_uint_fast32_t s_trace_flags;
static atomic_uint_fast64_t s_trace_last_ns;

// 惰性初始化 timebase。若 mach_timebase_info 失败，denom 保持为 0，换算函数会据此
// 返回 0 并丢弃样本，因此这里不需要单独的错误分支。
static void cprisk_crypto_trace_timebase_once_i(void) {
    if (s_timebase_ready != 0u)
        return;
    (void)mach_timebase_info(&s_timebase);
    s_timebase_ready = 1u;
}

// 把 Mach ticks 换算成纳秒。商与余数分别乘 numer，避免 delta*numer 在 64 位下溢出。
// denom 为 0 表示 timebase 不可用，返回 0，调用方据此丢弃本次样本。
static uint64_t cprisk_crypto_trace_ticks_to_ns_i(uint64_t delta_ticks) {
    cprisk_crypto_trace_timebase_once_i();
    if (s_timebase.denom == 0u)
        return 0u;
    return delta_ticks / (uint64_t)s_timebase.denom * (uint64_t)s_timebase.numer +
           (delta_ticks % (uint64_t)s_timebase.denom) * (uint64_t)s_timebase.numer / (uint64_t)s_timebase.denom;
}

#if CPRISK_CRYPTO_TRACE_ARM64_DEVICE
// 用 CNTPCT_EL0 与 CNTFRQ_EL0 计算两点之间的物理计时差（纳秒）。频率只读一次并缓存；
// 计数器倒退或频率不可用时返回 0，调用方会把它当成“本平台没有可用样本”。
static uint64_t cprisk_crypto_cntpct_delta_ns_i(uint64_t c0, uint64_t c1) {
    static _Atomic uint64_t s_cntfrq = 0u;
    uint64_t freq = atomic_load_explicit(&s_cntfrq, memory_order_relaxed);
    if (freq == 0u) {
        // CNTFRQ_EL0 是只读寄存器，给出计数器频率（Hz）；多个线程可能重复读，值相同。
        __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
        atomic_store_explicit(&s_cntfrq, freq, memory_order_relaxed);
    }
    // 频率未知或计数回绕时放弃：没有样本好过用错误频率算出假的 skew。
    if (freq == 0u || c1 < c0) {
        return 0u;
    }
    const uint64_t dt = c1 - c0;
    return (dt / freq) * 1000000000ull +
           ((dt % freq) * 1000000000ull) / freq;
}

// 无符号绝对差，避免 a-b 在 a<b 时下溢成巨大值。
static uint64_t cprisk_crypto_u64_abs_diff_i(uint64_t a, uint64_t b) {
    return a > b ? a - b : b - a;
}
#endif

// 采样点接口：返回 Mach 绝对时间（未换算的 ticks）。调用方成对取差后交给
// record_span_ticks。只做一次 timebase 惰性初始化，不修改任何 flag。
uint64_t cprisk_crypto_trace_now_i(void) {
    cprisk_crypto_trace_timebase_once_i();
    return mach_absolute_time();
}

// 记录一次 span：换算为纳秒后写入 last_ns，超过阈值则置 SLOW。
// ns==0（timebase 不可用或差值为 0）直接丢弃本次样本，避免把“无法测量”记成“很快”。
// 线程安全：两次原子写、无锁；并发时 last_ns 只保留最新样本。
void cprisk_crypto_trace_record_span_ticks_i(uint64_t delta_ticks) {
    const uint64_t ns = cprisk_crypto_trace_ticks_to_ns_i(delta_ticks);
    if (ns == 0u)
        return;
    atomic_store(&s_trace_last_ns, ns);
    if (ns > (uint64_t)CPRISK_CRYPTO_TRACE_SLOW_NS)
        atomic_fetch_or(&s_trace_flags, CPRISK_CRYPTO_TRACE_FLAG_SLOW);
}

// 密码原语入口哨兵：在固定工作负载前后各采一次 Mach 时钟（真机再加 CNTPCT），
// 一次调用完成三件事——校验确定性摘要、统计耗时、比较两种时钟的增速。
// 无参数、无返回值；所有结论通过 s_trace_flags 暴露。
// 线程安全：状态全在栈上，仅原子置位全局 flag，可并发调用。
void cprisk_crypto_trace_primitive_enter_i(void) {
#if CPRISK_CRYPTO_TRACE_ARM64_DEVICE
    // 真机额外读物理计数器；它与 Mach 时钟正交，用于抓只虚拟化其中一个时钟的 DBI。
    uint64_t cntpct0 = 0u;
    uint64_t cntpct1 = 0u;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(cntpct0));
#endif

    const uint64_t t0 = cprisk_crypto_trace_now_i();
    // volatile 阻止编译器把整个循环常量折叠：被优化掉的检测会永远“通过”。
    volatile uint64_t acc = UINT64_C(0xC6A4A7935BD1E995);
    // 64 轮整数乘加：足够短以免触发 SLOW 误判，又足够复杂使指令级改写难以保持结果不变。
    for (unsigned n = 0u; n < 64u; n++) {
        acc ^= acc * UINT64_C(6364136223846793005) + (uint64_t)n;
    }
    const uint64_t t1 = cprisk_crypto_trace_now_i();

#if CPRISK_CRYPTO_TRACE_ARM64_DEVICE
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(cntpct1));
#endif

    // 摘要不符即说明执行路径被扰动（插桩/模拟/指令替换），单次命中就置位。
    if (acc != k_cprisk_crypto_trace_acc_expected) {
        atomic_fetch_or(&s_trace_flags, CPRISK_CRYPTO_TRACE_FLAG_INVARIANT_FAIL);
    }

    (void)acc;
    // 阈值统计只用 Mach span；CNTPCT 差值单独用于下面的 skew 判定，不与 SLOW 混用。
    cprisk_crypto_trace_record_span_ticks_i(t1 - t0);

#if CPRISK_CRYPTO_TRACE_ARM64_DEVICE
    // 正交性检查：只改一个时钟的 hook，会让两个 ns 读数对同一段工作负载给出不同答案。
    /*
     * Orthogonal to pure mach_absolute_time dilation: DBI that patches or
     * virtualizes one clock but not the other (or scales them differently)
     * leaves CNTPCT_EL0-derived ns and mach-derived ns in disagreement for the
     * same bounded workload — including cases where wall-clock ratios look
     * “natural” relative to a baseline.
     */
    {
        const uint64_t d_cnt_ns = cprisk_crypto_cntpct_delta_ns_i(cntpct0, cntpct1);
        uint64_t d_mach_ns = 0u;
        if (t1 >= t0) {
            d_mach_ns = cprisk_crypto_trace_ticks_to_ns_i(t1 - t0);
        } else {
            d_mach_ns = cprisk_crypto_trace_ticks_to_ns_i(t0 - t1);
        }
        const uint64_t dmax = d_cnt_ns > d_mach_ns ? d_cnt_ns : d_mach_ns;
        // 工作负载太短（<8 微秒）时噪声占比过高，不做 skew 判定。
        if (dmax >= 8000u) {
            const uint64_t skew_ns = cprisk_crypto_u64_abs_diff_i(d_cnt_ns, d_mach_ns);
            // 偏差超过 25% 才判定为时钟不一致；调度与降频造成的轻微差异不应报。
            if (skew_ns > dmax / 4u) {
                atomic_fetch_or(&s_trace_flags, CPRISK_CRYPTO_TRACE_FLAG_CNT_MACH_SKEW);
            }
        }
    }
#endif
}

// 只读当前 flag 快照、不清零，适合周期性观察；返回 CPRISK_CRYPTO_TRACE_FLAG_* 位组合。
uint32_t cprisk_crypto_trace_peek_flags_i(void) {
    return (uint32_t)atomic_load(&s_trace_flags);
}

// 返回最近一次成功记录的 span（纳秒）；0 表示尚无样本或 timebase 不可用。
uint64_t cprisk_crypto_trace_last_ns_i(void) {
    return (uint64_t)atomic_load(&s_trace_last_ns);
}

// 暴露 SLOW 阈值，让调用方/测试用同一基准解释 last_ns，避免两边各自写死数字而漂移。
uint64_t cprisk_crypto_trace_threshold_ns_i(void) {
    return (uint64_t)CPRISK_CRYPTO_TRACE_SLOW_NS;
}

// 原子取走并清零 flags（exchange）：保证每个异常只被一个消费者看到，适合“上报一次即可”
// 的告警路径。返回值是交换前的 bit 组合，之后 peek 看到的是新一轮累积。
uint32_t cprisk_crypto_trace_consume_flags_i(void) {
    return (uint32_t)atomic_exchange(&s_trace_flags, 0u);
}
