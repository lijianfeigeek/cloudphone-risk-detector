// 挑战结果存储：保存服务端最近一次 ChallengeVerificationResult 的分数偏移，
// 供下一次 evaluate 一次性消费；同时缓存 HMAC 校验失败信号等待注入。
// 线程模型：所有状态由 `UnfairLock` 保护，apply/consume 可跨线程调用。
// 安全不变量：adjustedScore 必须是增量 delta 且限制在 [-100,100]；
// 偏移消费后立即清除，避免同一次结果重复影响多次评估。
import Foundation

// MARK: - ChallengeResultStore

/// 存储服务端返回的挑战验证结果，用于下一次 evaluate 的分数偏移
/// adjustedScore 语义：增量偏移（delta），与 baseScore 相加得到调整后分数；非绝对分数。
/// 一次性消费后清除。
public final class ChallengeResultStore: @unchecked Sendable {

    /// 增量偏移的合理范围 [-100, 100]，超出则裁剪并打日志，避免绝对分误用或异常值污染
    private static let offsetRange = -100.0 ... 100.0

    // 进程级共享存储。
    public static let shared = ChallengeResultStore()

    // 保护下方全部状态；apply/consume 都在锁内完成。
    private let lock = UnfairLock()
    // 最近一次结果的 challengeId/passed，仅用于调试与 consume 配对。
    private var _lastChallengeId: String?
    // 待消费的分数偏移；consumeScoreOffset 后置 nil。
    private var _lastAdjustedScore: Double?
    private var _lastPassed: Bool?
    // HMAC 校验失败信号队列，由下一次 evaluate 整体取走。
    private var _pendingMismatchSignals: [RiskSignal] = []

    private init() {}

    /// 追加一条待注入的篡改信号，供下一次 evaluate 注入。
    func storePendingMismatchSignal(_ signal: RiskSignal) {
        lock.withLock { _pendingMismatchSignals.append(signal) }
    }

    /// 消费并返回待注入的 HMAC 校验失败信号。
    /// 取出后清空队列，保证每条信号只影响一次评估。
    func consumePendingMismatchSignals() -> [RiskSignal] {
        lock.withLock {
            let signals = _pendingMismatchSignals
            _pendingMismatchSignals = []
            return signals
        }
    }

    /// 应用挑战验证结果（由 CPRiskKit.applyChallengeResult 调用）。
    /// - Parameter result: 已通过（或未配置）HMAC 校验的服务端结果。
    /// 对 adjustedScore 做范围校验：超出 [-100, 100] 时裁剪并记录日志，避免负值或超大值污染分数。
    public func apply(result: ChallengeVerificationResult) {
        lock.withLock {
            _lastChallengeId = result.challengeId
            _lastPassed = result.passed

            // 服务端可能误把绝对分当 delta 返回：越界值裁剪并告警，避免把分数打穿。
            let raw = result.adjustedScore
            if let v = raw {
                if Self.offsetRange.contains(v) {
                    _lastAdjustedScore = v
                } else {
                    let clamped = min(max(v, Self.offsetRange.lowerBound), Self.offsetRange.upperBound)
                    _lastAdjustedScore = clamped
                    Logger.log("ChallengeResultStore.apply: adjustedScore=\(v) out of range [\(Self.offsetRange.lowerBound), \(Self.offsetRange.upperBound)], clamped to \(clamped) — check if server returns absolute score instead of delta")
                }
            } else {
                // 未提供偏移表示本次不调整分数。
                _lastAdjustedScore = nil
            }

            #if DEBUG
            Logger.log("ChallengeResultStore.apply: challengeId=\(result.challengeId) passed=\(result.passed) adjustedScore=\(_lastAdjustedScore?.description ?? "nil")")
            #endif
        }
    }

    /// 消费并返回分数偏移（下一次 evaluate 使用后清除）。
    /// - Returns: 偏移量，无则返回 nil。
    /// 一次性语义：读取后连同元数据一起清空，防止重复应用。
    public func consumeScoreOffset() -> Double? {
        lock.withLock {
            let offset = _lastAdjustedScore
            _lastAdjustedScore = nil
            _lastChallengeId = nil
            _lastPassed = nil
            return offset
        }
    }

    /// 获取当前分数偏移（不消费，用于诊断/日志）。
    public func currentScoreOffset() -> Double? {
        lock.withLock { _lastAdjustedScore }
    }

    /// 是否有待消费的偏移（只读检查，不触发消费）。
    public var hasPendingOffset: Bool {
        lock.withLock { _lastAdjustedScore != nil }
    }
}
