// cprisk_vm_sync_barrier.c — VM 执行同步屏障，用于打断批量 trace 引擎的推测执行。
// 每 64 条 VM 指令读取一次由 watchdog 线程维护的进程级原子计数，并把其增量
// 混入 acc[0] 的最低位；该外部数据依赖无法在不真正运行 watchdog 的情况下预算。
// 两个全局原子量：s_watchdog_counter（单调递增）与 s_global_stuck（首次卡死后
// 永不复位）。ctx 非原子，属于单帧、单线程。平台无关，仅用 C11 stdatomic。
// 失败语义：watchdog 不前进超过阈值时置 stuck，并通过毒化签名层让结果不可信。
/*
 * cprisk_vm_sync_barrier.c
 * CRiskCore
 *
 * VM execution synchronisation barrier — see cprisk_vm_sync_barrier.h for
 * full design rationale.
 *
 * Summary: inserts an external data dependency every 64 VM instructions to
 * break the speculative batch-execution model used by optimised trace engines.
 */

#include "include/cprisk_vm_sync_barrier.h"
#include "include/cprisk_emulator_detect.h"
#include "include/CRiskCore.h"

#include <stdatomic.h>
#include <string.h>

/* ── Global watchdog counter (written by watchdog thread) ────────────────── */

// watchdog 线程每次 tick 自增的进程级计数；只有它写入，VM 线程只读。
// 使用 relaxed 原子是为了避免数据竞争并保证最终可见，而不是建立 happens-before。
static _Atomic(uint32_t) s_watchdog_counter = 0u;

/*
 * Process-global stuck flag.
 * Set to 1 the first time any VM frame detects a stuck watchdog.
 * Never reset — once stuck, always stuck (a real device would have threads).
 * Read by cprisk_vm_sync_barrier_global_stuck() for signing-layer poison.
 */
// 进程级“曾经卡死”标志：0/1，只由首次检测到卡死的 VM 帧写 1，永不回写 0。
// store 用 release、load 用 acquire 配对，确保 signing 层读到 1 时能看到置位前的状态。
static _Atomic(uint32_t) s_global_stuck = 0u;

// watchdog 线程每 tick 调用一次：relaxed fetch_add 递增全局计数。
// - 返回: 无；参数: 无。线程安全（多写者亦可，计数只要求近似单调）。
// - 平台: 依赖 C11 原子在 arm64/x86_64 上 lock-free；无分支。
// - 失败语义: 无；uint32 回绕是允许的，差分只用来判断“是否变化”，不要求单调严格。
void cprisk_vm_sync_barrier_note_watchdog_tick(void) {
    /* Relaxed store: the watchdog and the VM run on different threads;
     * we only need eventual visibility, not synchronisation. */
    // relaxed 足够：计数器值不保护任何其他内存，VM 侧只关心“是否读到新值”。
    atomic_fetch_add_explicit(&s_watchdog_counter, 1u, memory_order_relaxed);
}

// 读取当前 watchdog 计数（relaxed 快照），用于初始化与测试。
// 返回值可能立刻过期；不提供同步语义，不要用它判断控制流正确性。线程安全；平台无关。
uint32_t cprisk_vm_sync_barrier_get_watchdog(void) {
    return atomic_load_explicit(&s_watchdog_counter, memory_order_relaxed);
}

/* ── Barrier context ─────────────────────────────────────────────────────── */

// 初始化每帧屏障上下文，并把 last_watchdog_val 设为当前全局计数的快照。
// - ctx NULL 时无操作；返回: 无。线程: ctx 必须由该 VM 帧独占；平台: 无。
// - 失败语义: 无；快照与随后第一次 step 之间若有 tick，只会让首次增量偏大，不影响正确性。
// - 注意: last_watchdog_val 是“上次观察值”，首次触发时 delta 可包含初始化后的所有 tick。
void cprisk_vm_sync_barrier_init(cprisk_vm_sync_barrier_ctx_t *ctx) {
    if (!ctx) return;
    ctx->step_counter      = 0u;
    // relaxed 快照可能略旧；只要它不超前于真实值，delta 就非负，语义仍然成立。
    ctx->last_watchdog_val = atomic_load_explicit(&s_watchdog_counter, memory_order_relaxed);
    ctx->accumulated_mix   = 0u;
    ctx->no_advance_count  = 0u;
    ctx->watchdog_stuck    = 0u;
}

// 返回该帧是否已判定 watchdog 卡死（0/1）；ctx NULL 视为 0。
// 只读非原子字段，调用方须与 step 串行；平台无关。
int cprisk_vm_sync_barrier_watchdog_stuck(const cprisk_vm_sync_barrier_ctx_t *ctx) {
    if (!ctx) return 0;
    return (int)ctx->watchdog_stuck;
}

// 读取进程级卡死标志，acquire 语义，与 step 中的 release store 配对。
// 返回 0/1；线程安全；任何帧一旦置位，所有后续调用都返回 1（永不复位）。
uint32_t cprisk_vm_sync_barrier_global_stuck(void) {
    return atomic_load_explicit(&s_global_stuck, memory_order_acquire);
}

/*
 * Fast inline avalanche used to mix the watchdog value into the accumulator.
 * Must be cheap (< 5 ns) since it runs every 64 VM instructions.
 */
// 32 位快速雪崩混合（xor-shift + 两次奇数乘法），把 watchdog 增量扩散到低位。
// - 纯函数、无状态；平台无关，依赖 uint32 无符号回绕。线程安全，可重入。
// - 不是密码学哈希，只求廉价与位扩散；常量来自 murmur 风格混合器。
static inline uint32_t sb_avalanche32(uint32_t x) {
    // 两次“右移异或 + 奇数乘法”交替，使输入任一比特都能影响输出的多数比特。
    x ^= x >> 16u;
    x *= 0x7FEB352Du;
    x ^= x >> 15u;
    x *= 0x846CA68Bu;
    x ^= x >> 16u;
    return x;
}

// 推进一条指令；每 CPRISK_VM_SYNC_BARRIER_INTERVAL(64) 步触发一次屏障。
// - ctx/acc_inout 非 NULL；pc 为当前虚拟 PC，只参与混合；acc_inout[0] 可能被翻转 1 位。
// - 返回: 触发返回 1，未触发返回 0；参数 NULL 也返回 0。
// - 线程: ctx 与 acc 由调用线程独占；全局计数用原子读取，可与其他线程并发。
// - 平台: 无分支差异；atomic 在 Apple 64 位上无锁。
// - 失败语义: 无错误码；watchdog 连续 STUCK_THRESHOLD(3) 次触发未前进即置 stuck，
//   并写全局标志 + 通知 emulator 缓存；置位后本帧不再清除。
int cprisk_vm_sync_barrier_step(cprisk_vm_sync_barrier_ctx_t *ctx,
                                 uint8_t acc_inout[4],
                                 uint32_t pc) {
    if (!ctx || !acc_inout) return 0;

    // step_counter 是 uint32 无符号回绕（定义良好）；只在取模为 0 时触发，回绕不影响节奏。
    ctx->step_counter += 1u;
    if ((ctx->step_counter % CPRISK_VM_SYNC_BARRIER_INTERVAL) != 0u)
        return 0;

    /* Read the external watchdog counter — this is the mandatory data
     * dependency that a batch-trace engine cannot pre-compute without
     * actually running the watchdog thread. */
    // acquire 在这里主要起编译器/CPU 重排约束作用：写侧用的是 relaxed，并不构成
    // 严格的 release-acquire 配对；正确性依赖“计数只增”与读到的值必然已真实发生。
    const uint32_t wdog_now = atomic_load_explicit(&s_watchdog_counter,
                                                    memory_order_acquire);

    /*
     * Mix the watchdog value into acc[0] using an avalanche function keyed
     * by pc so the perturbation is instruction-position-specific.
     *
     * The mix term is accumulated in ctx->accumulated_mix so that the
     * hardening layer (FNV chain) can reconstruct and cancel it on the
     * recovery / output path — net semantic effect on the final VM result
     * is zero, but the batch-trace engine cannot skip the read.
     *
     * mix = avalanche(watchdog XOR pc XOR step_counter)
     *
     * We XOR only bit-0 of the high byte of acc[0] so the perturbation is
     * a single-bit flip — invisible to casual inspection but sufficient to
     * create the data dependency.  The recovery path (cprisk_vm_hardening)
     * sees the flipped bit and restores it via the FNV chain delta.
     */
    // 增量用异或：计数正常递增时得到非零值；即使回绕，差异值也能反映“变了”。
    // 这里只关心 0/非 0 与混合熵，不需要算术减法。
    const uint32_t delta_wdog = wdog_now ^ ctx->last_watchdog_val;

    /* Track whether the watchdog is actually advancing.
     * On unidbg, the watchdog pthread typically never runs, so the counter
     * never moves.  After STUCK_THRESHOLD consecutive barrier fires with no
     * change, flag the context as stuck. */
    // 连续 3 次屏障触发（约 192 条指令）都没看到计数变化，按“watchdog 线程不存在”处理。
    // 这是启发式：真实设备上若 VM 跑得极快也可能短暂命中，命中后即永久置位（fail-closed）。
    if (delta_wdog == 0u) {
        ctx->no_advance_count += 1u;
        if (ctx->no_advance_count >= CPRISK_VM_SYNC_BARRIER_STUCK_THRESHOLD) {
            ctx->watchdog_stuck = 1u;
            /* Propagate to the process-global flag so the signing layer can
             * read it without access to the VM frame context. */
            // release 保证：读到 1 的线程也能看到置位前本线程写入的其他状态。
            atomic_store_explicit(&s_global_stuck, 1u, memory_order_release);
            /* Also update the emulator-detect cache so the signing-layer
             * HKDF poison path sees the stuck flag even if the full probe
             * ran before the watchdog was detected as stuck. */
            cprisk_emulator_mark_watchdog_stuck();
        }
    } else {
        // 看到前进就清零连续计数；但 watchdog_stuck 本身不回退（一旦卡死则保持）。
        ctx->no_advance_count = 0u;
        /* Once stuck, stay stuck per-frame too — matches the global semantics.
         * On a real device the watchdog never stalls long enough to trip the
         * threshold; if it ever did then recovered, that itself is anomalous
         * and should remain flagged for the lifetime of the frame. */
    }

    // 混合输入包含增量、PC、步计数与固定常量 0xBAADF00D；固定常量避免全零输入产生固定输出。
    const uint32_t mix = sb_avalanche32(delta_wdog ^ pc ^ ctx->step_counter ^ 0xBAADF00Du);

    /* Single-bit injection into acc[0] — sufficient for the data dependency */
    // 只翻转最低位：对最终语义影响最小，却足以让批量 trace 无法在不读 watchdog 时预算 acc。
    acc_inout[0] ^= (uint8_t)(mix & 0x01u);

    // 记录累计混合项，供加固/恢复路径按同样顺序抵消；xor 自反，重复应用可还原。
    ctx->accumulated_mix ^= mix;
    // 更新观察基线：下次 delta 只反映本次触发之后的新 tick。
    ctx->last_watchdog_val = wdog_now;
    return 1;
}
