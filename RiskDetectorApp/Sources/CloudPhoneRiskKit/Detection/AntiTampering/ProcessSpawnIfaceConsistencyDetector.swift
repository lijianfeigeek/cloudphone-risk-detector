import CRiskCore
import Darwin
import Foundation

// MARK: - 进程派生接口一致性
//
// 校验 posix_spawn / posix_spawnp 在 dyld 默认解析、显式 libsystem_c 句柄、
// 导出表（export trie）三条获取路径上的地址是否一致；三条路径出现分歧说明
// 符号解析被 hook 或替换。arm64 上再叠加函数序言内联 hook 启发式作为旁证。

/// posix_spawn / posix_spawnp 解析路径一致性检测器。
/// - 线程模型：纯同步探测，可在任意线程调用。
/// - 失败降级：C 探针返回非 0（接口不可用/被阻断）时不产生信号。
/// - 信号：`ifaceSpawnPathDivergence`，路径分歧为 hard（`.tampered`），
///   仅序言异常时为 soft 方向的 72 分。
struct ProcessSpawnIfaceConsistencyDetector {
    /// 执行 C 侧探针并生成信号。
    /// - 路径地址不一致计 88 分；仅 arm64 序言校验失败计 72 分。
    func asSignals() -> [RiskSignal] {
        var raw = cprisk_spawn_iface_probe_result_t()
        // 探针失败说明底层接口不可用（如受限环境），直接降级不误报。
        guard cprisk_spawn_iface_probe(&raw) == 0 else { return [] }

        let pathBits = UInt32(raw.flags)
        var prologueMarks: [String] = []
        // 仅 arm64/arm64e 有稳定的函数序言特征；其他架构跳过，避免无意义比较。
        #if arch(arm64) || arch(arm64e)
        if LibcPrologueGuard.isInlineHooked(symbol: "posix_spawn") {
            prologueMarks.append("s")
        }
        if LibcPrologueGuard.isInlineHooked(symbol: "posix_spawnp") {
            prologueMarks.append("p")
        }
        #endif

        // 既无路径分歧也无序言异常 → 视为干净。
        guard pathBits != 0 || !prologueMarks.isEmpty else { return [] }

        // 路径分歧是确定性证据，权重高于仅序言异常的启发式判断。
        let score: Double = pathBits != 0 ? 88 : 72
        var evidence: [String: String] = [
            "f": String(pathBits, radix: 16),
            "ds": String(raw.addr_rtld_default_spawn, radix: 16),
            "es": String(raw.addr_dlopen_libc_spawn, radix: 16),
            "ts": String(raw.addr_export_trie_spawn, radix: 16),
            "dp": String(raw.addr_rtld_default_spawnp, radix: 16),
            "ep": String(raw.addr_dlopen_libc_spawnp, radix: 16),
            "tp": String(raw.addr_export_trie_spawnp, radix: 16),
        ]
        if !prologueMarks.isEmpty {
            evidence["pr"] = prologueMarks.joined(separator: ",")
        }

        return [
            RiskSignal(
                id: SignalID.ifaceSpawnPathDivergence,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: score,
                evidence: evidence,
                state: .tampered,
                layer: 2,
                weightHint: 90
            ),
        ]
    }
}
