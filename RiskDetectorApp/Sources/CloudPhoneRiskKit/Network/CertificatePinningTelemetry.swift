// 文件职责：收集证书固定路径上的可观测事件，作为网络侧信道供 Risk 管线聚合。
// 管道位置：Network（TLS pinning）→ 本缓冲 → RiskSignalProvider → 本地判决。
// 安全不变量：缓冲有上限且线程安全；事件只描述校验异常，不携带证书或密钥材料。
import Foundation

/// 证书固定路径上的可观测事件类型（供后续聚合为 `RiskSignal`）。
/// 每个 case 对应一类失败/异常原因，便于区分误报与真实攻击。
public enum CertificatePinningTelemetryKind: String, Sendable {
    /// 系统信任评估（SecTrustEvaluateWithError）失败。
    case trustEvalFailed
    /// 两种信任结果 API 的结论不一致。
    case trustResultMismatch
    /// 叶证书公钥缺失，无法做 SPKI pin。
    case leafPublicKeyMissing
    /// 全局完整性复检判定为篡改。
    case integrityRecheckTamper
    /// 完整性复检计算失败（无法证明未篡改）。
    case integrityRecheckComputeFailed
    /// SVC stub 被改写（疑似 inline hook）。
    case svcStubIntegrity
    /// 信任评估异常过快，可能被短路或 hook。
    case trustEvalSuspiciouslyFast
    /// Swift/C pin 校验结果分歧，或 C 侧返回错误。
    case pinValidatorDiverged
    /// 整条证书链都没有 pin 命中。
    case pinMismatch
    /// 证书链为空，无法校验。
    case emptyCertificateChain
    /// Security.framework / dlsym / dlopen 入口 prologue 与基线不一致（Frida Interceptor 等）。
    case trustHookSurfaceIntegrity
}

/// 线程安全的侧信道缓冲：网络 delegate 写入，Risk 管线读取。
/// 使用 `UnfairLock` 保护；容量上限防止持续失败把内存刷爆。
public final class CertificatePinningTelemetry: @unchecked Sendable {
    public static let shared = CertificatePinningTelemetry()

    /// 保护 `events` 的互斥锁；网络回调与 Risk 读取可能并发。
    private let lock = UnfairLock()
    /// 事件缓冲；超过上限时丢弃最旧事件。
    private var events: [CertificatePinningTelemetryEvent] = []
    /// 最多保留的事件条数。
    private let maxBuffered = 32

    /// 单例构造，外部不可创建。
    private init() {}

    /// 记录一条 pinning 遥测事件。
    /// - Parameters:
    ///   - host: 目标主机名（仅用于归因）。
    ///   - kind: 事件类型。
    ///   - detail: 附加上下文（错误码、链下标等）。
    public func record(host: String, kind: CertificatePinningTelemetryKind, detail: [String: String] = [:]) {
        let ev = CertificatePinningTelemetryEvent(
            host: host,
            kind: kind,
            detail: detail,
            recordedAt: Date()
        )
        lock.withLock {
            events.append(ev)
            if events.count > maxBuffered {
                events.removeFirst(events.count - maxBuffered)
            }
        }
    }

    /// 取出并清空缓冲，供 `RiskSignalProvider` 转为 `RiskSignal`。
    /// - Returns: 缓冲中的事件快照（保持写入顺序）。
    public func drainEvents() -> [CertificatePinningTelemetryEvent] {
        lock.withLock {
            let out = events
            events.removeAll(keepingCapacity: true)
            return out
        }
    }

    /// 测试或调试：不清空读取。
    func peekEventsForTesting() -> [CertificatePinningTelemetryEvent] {
        lock.withLock { events }
    }

    /// 清空缓冲（测试/重置用）。
    func resetForTesting() {
        lock.withLock { events.removeAll(keepingCapacity: true) }
    }
}

/// 一条不可变的 pinning 遥测事件快照。
public struct CertificatePinningTelemetryEvent: Sendable {
    /// 目标主机名。
    public let host: String
    /// 事件类型。
    public let kind: CertificatePinningTelemetryKind
    /// 附加诊断上下文。
    public let detail: [String: String]
    /// 事件记录时间（墙上时钟）。
    public let recordedAt: Date
}
