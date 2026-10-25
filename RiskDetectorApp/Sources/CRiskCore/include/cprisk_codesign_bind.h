// 文件职责：从运行中 App 的代码签名 Team Identifier 派生 64 位签名绑定盐。
// 在链路中的位置：白盒 S-box 的 XOR pad 混入该盐；TeamID 不同则解出错误密钥，重打包后风险结果静默失真。
// 回退策略：读不到 entitlement（模拟器/无签名）时改用可执行路径的 SHA-256，保证盐非零且同二进制内确定。
// 线程模型：首次调用可能查询 Security.framework（毫秒级），之后原子缓存；可并发调用。
// 平台限制：真实 TeamID 仅真机签名构建可得；模拟器直接返回 0（中性盐）。
// 失败语义：返回 0 表示派生完全失败，调用方应把 0 当作“不绑定”，不得当作有效签名身份。

#ifndef CPRISK_CODESIGN_BIND_H
#define CPRISK_CODESIGN_BIND_H

/*
 * cprisk_codesign_bind.h
 * CRiskCore
 *
 * Derives a 64-bit salt from the running app's code-signing Team Identifier.
 *
 * ## Purpose
 * Without this binding, a repackaged app (different TeamID) can call the SDK
 * and get correct risk-detection output.  By mixing the TeamID into the
 * whitebox S-box table XOR pad, the tables only decrypt to valid keys when
 * the same Team Identifier is present at runtime.  A repackaged binary uses a
 * different TeamID → wrong XOR pad → corrupted S-box → wrong PRF output →
 * risk score is silently incorrect without any crash.
 *
 * ## Derivation
 * 1. `SecTaskCopyValueForEntitlement(NULL, "com.apple.developer.team-identifier")`
 *    — reads the in-memory entitlement blob attached to the running task.
 * 2. If unavailable (simulator, no entitlement), falls back to
 *    `_NSGetExecutablePath` + SHA-256 path hash so the salt is still non-zero
 *    and deterministic within the same binary.
 * 3. Result is cached after first call (atomic).
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returns a stable 64-bit salt derived from the running app's TeamID.
 * Thread-safe; first call may take up to ~1 ms (Security framework lookup).
 * Subsequent calls return a cached value in < 1 ns.
 *
 * Returns 0 only if derivation completely failed — callers should treat 0
 * as a neutral (do-nothing) salt so legitimate apps without entitlements
 * still function normally.
 */
/// 返回由运行中 App 的 TeamID 派生的稳定 64 位盐。
/// - Returns: 非零盐值；0 表示派生完全失败（中性盐，不做任何绑定）。
/// - Thread safety: 原子缓存，可并发；首次并发调用可能各算一次，但写入值相同。
/// - Platform: 真机签名构建读取 entitlement；模拟器恒返回 0。
/// - 缓存: 首次成功后写入原子变量，后续为纳秒级读取；0 结果同样被缓存，不会反复重试。
/// - 失败语义: 调用方必须把 0 当“无签名绑定”，不得用它参与会破坏正常功能的校验。
uint64_t cprisk_codesign_team_salt(void);

#ifdef __cplusplus
}
#endif

#endif /* CPRISK_CODESIGN_BIND_H */
