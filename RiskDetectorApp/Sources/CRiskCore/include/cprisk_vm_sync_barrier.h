#ifndef CPRISK_VM_SYNC_BARRIER_H
#define CPRISK_VM_SYNC_BARRIER_H

// VM 同步屏障：每 64 条指令强制读取看门狗计数器并混入 acc，破坏批量跟踪的可预测性。
// 线程模型：VM 线程调用 step（acquire 读），看门狗线程调用 note_tick（relaxed 写）。
// 进程级 stuck 标志一经置位永不复位，供签名层读取并对 HKDF 下毒（fail-closed）。
// 所有函数都不分配内存；ctx 由调用方拥有，仅限其所属 VM 线程访问。
/*
 * cprisk_vm_sync_barrier.h
 *
 * VM execution synchronisation barrier.
 *
 * Counter-measure: Native batch-trace pipeline (unidbg魔改版 §7.1 future work).
 *
 * unidbg's remaining bottleneck after the Java-layer optimisations is the
 * JNI boundary crossing and the N × reg_read() calls per instruction.  The
 * logical next step (already partially implemented as a "binary trace format")
 * is to move the hot loop — disassembly + register capture + formatting — fully
 * into a native C layer that processes a *batch* of instructions without
 * returning to Java between each one.
 *
 * A pure batch approach can pre-compute all VM states for a block of bytecode
 * if each instruction's inputs depend only on prior outputs within the batch
 * (no external data dependencies).  If the batch is self-contained, the
 * tracer can speculatively execute the whole block and emit a formatted trace
 * in one shot.
 *
 * The sync barrier breaks this by inserting a mandatory *external* read every
 * CPRISK_VM_SYNC_BARRIER_INTERVAL steps.  The external state is a value
 * maintained by the watchdog thread (an atomically-updated counter) that the
 * VM must read and mix into its accumulator.  Key properties:
 *
 * 1. **Data dependency**: the acc after step N depends on a value not available
 *    until the watchdog has executed at least once since step N-interval.
 * 2. **Non-predictable**: the watchdog counter is updated at ~1 Hz with jitter;
 *    no batch-trace pipeline can pre-compute its value.
 * 3. **Cheap**: one atomic load per K=64 steps; negligible overhead vs
 *    the existing CFF/VM hardening.
 * 4. **Correct**: the accumulator is also perturbed by cprisk_vm_hardening
 *    (FNV chain + MBA); the barrier term is additive and cancelled by the
 *    same hardening on the recovery path.  Net semantic effect on the final
 *    VM output is zero.
 *
 * API:
 *   cprisk_vm_sync_barrier_init():  call once at VM frame initialisation.
 *   cprisk_vm_sync_barrier_step():  call on every instruction; returns
 *     non-zero when it fires (so callers can measure overhead if needed).
 *   cprisk_vm_sync_barrier_note_watchdog_tick(): watchdog thread calls this
 *     to advance the external counter.
 */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 屏障间隔 64 步：摊薄原子读开销，同时保证外部依赖足够频繁。
/* How often (in VM instructions) to fire the barrier. */
#ifndef CPRISK_VM_SYNC_BARRIER_INTERVAL
#define CPRISK_VM_SYNC_BARRIER_INTERVAL 64u
#endif

// 每帧屏障上下文：所有字段由该 frame 的 VM 线程独占更新，不跨线程共享。
typedef struct cprisk_vm_sync_barrier_ctx {
// 本地步数计数器，每步 +1（模 interval 判断触发）。
    uint32_t step_counter;        /* local instruction counter */
// 上次观察到的看门狗计数器值（32 位，约 1 Hz 抖动推进）。
    uint32_t last_watchdog_val;   /* last observed watchdog tick */
// 已注入的混合项累积（XOR），恢复路径据此抵消。
    uint32_t accumulated_mix;     /* running mix term (subtracted at recovery) */
// 连续触发但看门狗未推进的次数 0..threshold。
    uint32_t no_advance_count;    /* consecutive barrier fires with no watchdog advance */
// 1 = 本帧判定看门狗卡死；一经置位不复位。
    uint32_t watchdog_stuck;      /* 1 when watchdog appears not advancing (unidbg heuristic) */
} cprisk_vm_sync_barrier_ctx_t;

// 连续 3 个屏障周期无推进才判定卡死（约 192 条指令），避免瞬时抖动误报。
/* How many consecutive barrier intervals with no watchdog advance before flagging stuck. */
#ifndef CPRISK_VM_SYNC_BARRIER_STUCK_THRESHOLD
#define CPRISK_VM_SYNC_BARRIER_STUCK_THRESHOLD 3u
#endif

// 初始化每帧上下文；必须在 VM 帧初始化时、开始解释前调用；ctx 判空后直接返回。
/** Initialise a per-frame barrier context. */
void cprisk_vm_sync_barrier_init(cprisk_vm_sync_barrier_ctx_t *ctx);

// 推进一个指令步；每 64 步读取一次看门狗值（acquire），混入 acc_inout[0] 最低位。
// - acc_inout: 指向 VM 累加器前 4 字节；仅用第 0 字节，所有权归 frame。
// - 返回 1 表示本步触发；触发时的混合项记入 accumulated_mix 供恢复抵消。
// - 必须在 VM 执行线程调用；ctx 与 acc_inout 不可为 NULL。
/**
 * Advance the barrier by one instruction step.
 *
 * Every CPRISK_VM_SYNC_BARRIER_INTERVAL calls this reads the external
 * watchdog counter, mixes it into `acc_inout[0]`, and updates ctx.
 *
 * @param ctx       Per-frame barrier context (mutated).
 * @param acc_inout VM accumulator bytes [0..3] (acc_inout[0] mutated).
 * @param pc        Current virtual PC (used as mixing key).
 * @returns 1 if the barrier fired this step, 0 otherwise.
 */
int cprisk_vm_sync_barrier_step(cprisk_vm_sync_barrier_ctx_t *ctx,
                                 uint8_t acc_inout[4],
                                 uint32_t pc);

// 看门狗线程专用：relaxed 递增计数器；只保证最终可见，不建立同步。
/**
 * Called by the watchdog thread to advance the external counter.
 * Thread-safe (uses stdatomic).
 */
void cprisk_vm_sync_barrier_note_watchdog_tick(void);

// 读取当前看门狗计数（relaxed）；仅供测试/诊断，不参与屏障数据依赖。
/** Read the current watchdog counter value (for testing). */
uint32_t cprisk_vm_sync_barrier_get_watchdog(void);

// 返回本帧是否已判定卡死；只读 ctx，可在 VM 线程安全调用。
/**
 * Returns non-zero if the watchdog counter appears stuck (not advancing).
 * This is a strong indicator that the watchdog thread is not running —
 * consistent with unidbg's limited thread emulation.
 */
int cprisk_vm_sync_barrier_watchdog_stuck(const cprisk_vm_sync_barrier_ctx_t *ctx);

// 进程级“曾检测到卡死”标志（acquire 读，release 置位）；一经置位保持到进程结束。
// 签名层据此在无看门狗时污染 HKDF，使 CPRisk-MAC 与服务端不符（静默失败）。
/**
 * Returns non-zero when ANY VM frame has detected a stuck watchdog since
 * process start.  Uses a process-global atomic so the result persists even
 * after the originating VM frame is torn down.
 *
 * Used by the signing layer to poison the HKDF derivation when the watchdog
 * is absent (strong unidbg indicator), causing the resulting CPRisk-MAC to differ
 * from what the server expects — silently and without an observable crash.
 */
uint32_t cprisk_vm_sync_barrier_global_stuck(void);

#ifdef __cplusplus
}
#endif

#endif /* CPRISK_VM_SYNC_BARRIER_H */
