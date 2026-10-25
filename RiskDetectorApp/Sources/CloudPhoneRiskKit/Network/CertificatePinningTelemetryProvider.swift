// 文件职责：把证书固定侧信道事件转换为 `RiskSignal`。
// 管道位置：Risk 评估阶段的内置 Provider，随 `CPRiskKit.start()` 注册生效。
// 安全不变量：事件 drain 后即清空以避免重复计分；完整性类事件标记为篡改态。
import Foundation

/// 将证书固定路径侧信道事件转为 `RiskSignal`（内置注册，随 `CPRiskKit.start()` 生效）。
/// 单例无状态；每次评估消费一次遥测缓冲。
final class CertificatePinningTelemetryProvider: RiskSignalProvider {
    static let shared = CertificatePinningTelemetryProvider()

    /// Provider 唯一标识，用于信号去重与诊断。
    let id = "certificate_pinning_telemetry"

    /// 单例构造，外部不可创建。
    private init() {}

    /// 取出并清空 pinning 遥测缓冲，逐条转换为网络类风险信号。
    /// - 无事件时返回空数组，不产生噪声。
    /// - `drainEvents()` 保证同一事件不会被重复计分。
    /// - Parameter snapshot: 当前风险评估快照（本 Provider 不依赖其内容）。
    /// - Returns: 对应的风险信号列表。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let drained = CertificatePinningTelemetry.shared.drainEvents()
        guard !drained.isEmpty else { return [] }

        // 证据中补全类型、主机与时间戳，便于服务端复现。
        return drained.map { ev in
            let (score, state) = scoreAndState(for: ev.kind)
            var evidence = ev.detail
            evidence["kind"] = ev.kind.rawValue
            evidence["host"] = ev.host
            evidence["ts"] = String(format: "%.3f", ev.recordedAt.timeIntervalSince1970)
            return RiskSignal(
                id: SignalID.certificatePinningAnomaly,
                category: SignalCategory.network,
                score: score,
                evidence: evidence,
                state: state
            )
        }
    }

    /// 将事件类型映射为风险分与判决状态。
    /// - 完整性/校验分歧类：78 分并标记 `tampered`。
    /// - 信任失败/无命中类：65 分，按 hard 检测处理。
    /// - 时序异常：38 分低置信 soft 信号，避免单独误杀。
    private func scoreAndState(for kind: CertificatePinningTelemetryKind) -> (Double, RiskSignalState?) {
        switch kind {
        // 明确指向篡改或校验链路被干扰的高危事件。
        case .trustResultMismatch, .integrityRecheckTamper, .svcStubIntegrity, .integrityRecheckComputeFailed, .pinValidatorDiverged, .trustHookSurfaceIntegrity:
            return (78, .tampered)
        // 证书不可信但未必是主动攻击，按 hard 检测计入。
        case .trustEvalFailed, .leafPublicKeyMissing, .pinMismatch, .emptyCertificateChain:
            return (65, .hard(detected: true))
        // 时序侧信道单独不作为硬判决。
        case .trustEvalSuspiciouslyFast:
            return (38, .soft(confidence: 0.55))
        }
    }
}
