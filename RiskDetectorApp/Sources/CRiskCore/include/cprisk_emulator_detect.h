// 文件职责：C 层模拟器/unidbg 检测，返回结构化异常标志位。
// 在链路中的位置：由 VM 解释器初始化路径调用，绕过 Swift 调用栈，攻击者直接调 C 导出也仍会执行。
// 检测思路：每个 bit 对应一条“真实 iOS 成立、unidbg-on-Linux 不成立”的结构/行为不变量。
// 线程模型：结果用原子缓存，首次探测可能耗时至 ~2 ms；之后在 TTL 内走缓存，可并发调用。
// 平台限制：完整探测仅 Apple 真机；模拟器/非 Apple 平台无法探测，必须用 probe_status 区分“未探测”和“干净”。
// 失败语义：结果进入 VM 加固完整性链；异常分高会污染链并影响最终输出，但不会直接崩溃（避免暴露检测点）。
#ifndef CPRISK_EMULATOR_DETECT_H
#define CPRISK_EMULATOR_DETECT_H

/*
 * cprisk_emulator_detect.h
 * CRiskCore
 *
 * C-layer emulator / unidbg detection.
 *
 * ## Why C-layer?
 * Swift-layer detectors (EmulatorLayoutDetector, EmulatorBehaviorDetector) only
 * execute when the caller enters through the Swift call stack.  Attackers using
 * unidbg commonly call specific exported C functions directly, bypassing Swift
 * entirely.  This module runs at the C level and is called from the VM
 * interpreter's init path, so it executes regardless of entry point.
 *
 * ## Design
 * `cprisk_emulator_probe()` returns a bitmask of detected anomalies.  Each bit
 * corresponds to one structural or behavioural invariant that holds on real iOS
 * but is violated or absent in a unidbg-on-Linux environment.
 *
 * The probe is cheap (< 2 ms) and is called once per VM execution frame.  The
 * result is stored in `cprisk_vm_interp_frame_t.emulator_flags` and fed into
 * the VM hardening integrity chain — a high score poisons the chain and taints
 * the final VM output, making the risk-detection result unreliable for the
 * attacker without triggering a visible crash.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Anomaly flag bits ───────────────────────────────────────────────────── */

/** dyld shared cache absent (unidbg Linux has no dyld shared cache). */
// bit0：缺少 dyld shared cache；unidbg/Linux 环境通常不存在该缓存。
#define CPRISK_EMU_FLAG_DYLD_CACHE_ABSENT   (1u << 0)

/** Fewer than 40 vm_region_64 regions (unidbg synthesises a sparse map). */
// bit1：vm_region_64 区段数少于 40；unidbg 往往合成稀疏地址映射。
#define CPRISK_EMU_FLAG_LOW_VM_REGIONS      (1u << 1)

/** Main-thread stack pointer below 0x0001_0000_0000 (iOS always above). */
// bit2：主线程栈指针低于 0x1_0000_0000；真实 iOS 栈地址始终高于该阈值。
#define CPRISK_EMU_FLAG_LOW_STACK_ADDR      (1u << 2)

/** kern.ostype sysctl does not return "Darwin" (Linux or query failure). */
// bit3：kern.ostype 不是 "Darwin"（Linux 或查询失败）。
#define CPRISK_EMU_FLAG_OSTYPE_NOT_DARWIN   (1u << 3)

/** Fewer than 4 Mach threads (unidbg harness typically spawns 1–3). */
// bit4：Mach 线程数少于 4；unidbg 测试框架通常只起 1–3 个线程。
#define CPRISK_EMU_FLAG_LOW_THREAD_COUNT    (1u << 4)

/** A JVM indicator env var is set (JAVA_HOME, CLASSPATH, etc.). */
// bit5：检测到 JVM 相关环境变量（JAVA_HOME/CLASSPATH 等），提示宿主为 Java 沙箱。
#define CPRISK_EMU_FLAG_JVM_ENV_VAR         (1u << 5)

/** mach_timebase_info returns 1:1 AND dyld shared cache is absent. */
// bit6：timebase 为 1:1 且无 dyld shared cache；真机 timebase 通常不是 1:1。
#define CPRISK_EMU_FLAG_TIMEBASE_FLAT       (1u << 6)

/** CLOCK_PROCESS_CPUTIME_ID does not advance over a busy loop. */
// bit7：忙循环期间 CLOCK_PROCESS_CPUTIME_ID 不前进，提示时钟被冻结/虚拟化。
#define CPRISK_EMU_FLAG_CPU_CLOCK_FROZEN    (1u << 7)

/** VM sync barrier: watchdog thread appears not running. */
// bit8：VM 同步屏障发现看门狗线程未推进；由解释器外部标记，探测本身不置位。
#define CPRISK_EMU_FLAG_WATCHDOG_STUCK      (1u << 8)

/* ── API ─────────────────────────────────────────────────────────────────── */

/**
 * Run all emulator detection probes and return a bitmask of anomaly flags.
 *
 * Thread-safe; does not allocate.  First call may take up to ~2 ms (CPU-clock
 * probe).  Subsequent calls within the same process are fast (< 50 µs) due to
 * a cached result.
 *
 * @returns Bitmask of CPRISK_EMU_FLAG_* bits for each detected anomaly.
 *
 * NOTE (probe-status distinction): a return of 0 from cprisk_emulator_probe()
 * means "probed, no anomaly found" ONLY on platforms where probing is
 * actually performed. On platforms where probing is impossible (non-Apple
 * builds, simulator), the probe never runs and 0 would be misleading, so
 * use cprisk_emulator_probe_status() below to distinguish "not probed"
 * (-1) from "probed and clean" (0) from "probed, anomalies found" (1).
 * The cached result is also re-probed when older than
 * CPRISK_EMULATOR_PROBE_TTL_SECONDS, so a one-time clean result cannot
 * mask an emulator that attaches later.
 */
/// 运行全部模拟器探测并返回异常位掩码。
/// - Returns: CPRISK_EMU_FLAG_* 位组合；0 表示“已探测且未发现异常”，但不适用于无法探测的平台。
/// - Thread safety: 原子缓存，可并发调用；不会分配堆内存。
/// - Platform: 完整探测仅 Apple 真机；模拟器/非 Apple 平台不执行探测，结果恒为 0。
/// - 缓存: 结果按 CPRISK_EMULATOR_PROBE_TTL_SECONDS 过期重探，避免一次性“干净”结果掩盖后接入的模拟器。
/// - 失败语义: 探测单项失败通常按“异常/不可信”方向置位；需要区分“未探测”时改用 probe_status。
uint32_t cprisk_emulator_probe(void);

/** Cache time-to-live for cprisk_emulator_probe(), in seconds. */
// 缓存 5 秒：兼顾“及时覆盖后接入的调试器/模拟器”与“避免每帧重复跑昂贵探测”的成本折中。
#define CPRISK_EMULATOR_PROBE_TTL_SECONDS 5u

/**
 * Probe and report status explicitly:
 *   -1 = not probed (platform cannot probe: non-Apple / simulator),
 *    0 = probed and clean (no anomaly flags),
 *    1 = probed, one or more anomaly flags set.
 * On return, *out_flags holds the anomaly bitmask (0 when not probed).
 * Use this whenever "not probed" must not be confused with "clean".
 */
/// 显式区分“未探测”与“探测干净”的探测入口。
/// - Parameters:
///   - out_flags: 输出异常位掩码，不允许 NULL；未探测时写 0。所有权归调用方。
/// - Returns: -1 = 平台无法探测；0 = 已探测且干净；1 = 已探测并发现至少一个异常。
/// - Thread safety: 复用 probe 的原子缓存，可并发。
/// - Platform: 非 Apple 或模拟器恒返回 -1。
/// - 失败语义: out_flags 为 NULL 时返回 -1；调用方必须把 -1 与 0 严格区分。
int cprisk_emulator_probe_status(uint32_t *out_flags);

/**
 * Convert an anomaly flags bitmask into a weighted integer score (0–100).
 * Weights mirror those in the Swift-layer detectors.
 */
/// 把异常位掩码换算成 0–100 的加权分数。
/// - Parameters:
///   - flags: CPRISK_EMU_FLAG_* 位组合；未知位忽略。
/// - Returns: 加权和，封顶 100。
/// - Thread safety: 纯函数，可并发。
/// - 说明: 权重与 Swift 层检测器保持一致，避免同一证据在两处得出矛盾分数。
int cprisk_emulator_score(uint32_t flags);

/**
 * Returns non-zero if the emulator score exceeds the threshold at which the
 * VM hardening integrity chain should be poisoned.
 */
/// 判断是否应污染 VM 加固完整性链。
/// - Parameters:
///   - flags: CPRISK_EMU_FLAG_* 位组合。
/// - Returns: 1 = 敌对（分数 ≥25，或 dyld cache 缺失/栈地址过低任一高置信位）；0 = 未达阈值。
/// - Thread safety: 纯函数。
/// - 失败语义: 判定偏保守，宁可把可疑环境当敌对，也不放行高危宿主。
int cprisk_emulator_is_hostile(uint32_t flags);

/**
 * Lightweight re-probe: runs only the two cheapest invariant checks
 * (kern.ostype sysctl and stack-pointer address) WITHOUT updating the cache.
 *
 * Call from the signing critical path to detect cache-patching attacks:
 * an attacker who zeroes `s_cached_flags` must also handle this re-probe.
 * Returns a flag bitmask using the same CPRISK_EMU_FLAG_* constants.
 */
/// 轻量复探：只跑最便宜的两项不变量检查，且不写缓存。
/// - Returns: 复用 CPRISK_EMU_FLAG_* 的位掩码；非 Apple/模拟器恒为 0。
/// - Thread safety: 只读探测，可并发。
/// - 用途: 放在签名关键路径上，攻击者清零缓存后仍需同时绕过本实时检查。
/// - 失败语义: 单项探测失败按异常置位；0 只表示这两项未发现问题。
uint32_t cprisk_emulator_quick_probe(void);

/**
 * OR the CPRISK_EMU_FLAG_WATCHDOG_STUCK bit into the cached result.
 *
 * Called by the VM sync barrier when a stuck watchdog is first detected.
 * Safe to call multiple times; idempotent once the bit is set.
 */
/// 把 WATCHDOG_STUCK 位并入缓存结果。
/// - Returns: 无。
/// - Thread safety: CAS 循环原子更新，可并发；缓存尚未初始化时不写，留待完整探测从全局状态读取。
/// - 失败语义: 重复调用是幂等的；不影响其他位。
void cprisk_emulator_mark_watchdog_stuck(void);

#ifdef __cplusplus
}
#endif

#endif /* CPRISK_EMULATOR_DETECT_H */
