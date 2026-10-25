// ChallengeSession 的 actor 门面：把基于锁的同步会话 API 包装成 async/await 接口，
// 供 Swift Concurrency 调用方（Task/async 上下文）访问。
// actor 只提供串行化调用入口，实际状态仍由 `ChallengeSession` 的 `UnfairLock` 保护。
// 所有方法同步转发、不跨 await 持有隔离状态，因此不会引入额外死锁点。
import Foundation

// MARK: - Actor-based Challenge Session Facade
//
// Provides async/await access to ChallengeSession for modern Swift concurrency code paths.

/// Actor-based facade for challenge session operations.
/// 挑战会话的 actor 门面；对外暴露与 `ChallengeSession` 等价的异步接口。
@available(iOS 13.0, macOS 10.15, *)
public actor ChallengeSessionActor {

    // 共享门面，默认包装进程级 ChallengeSession.shared。
    public static let shared = ChallengeSessionActor()

    // 被包装的同步会话；actor 隔离保证同一时刻只有一个调用进入。
    private let session: ChallengeSession

    /// 创建门面；可注入自定义 session（测试用），默认使用共享实例。
    init(session: ChallengeSession = .shared) {
        self.session = session
    }

    /// 读取当前状态（快照，不阻塞后续调用）。
    public func state() -> ChallengeSessionState {
        session.state
    }

    /// Bind a challenge and transition to issued state.
    /// 绑定挑战并迁移到 issued；语义同 `ChallengeSession.bindChallenge`。
    @discardableResult
    public func bindChallenge(_ challenge: ChallengeTrigger.BlindChallenge) -> Bool {
        session.bindChallenge(challenge)
    }

    /// Advance to the next state in the flow.
    /// 按预设顺序推进状态；终止态返回 false。
    @discardableResult
    public func advance() -> Bool {
        session.advance()
    }

    /// Transition to a specific state.
    /// 迁移到指定状态；非法迁移返回 false 且状态不变。
    @discardableResult
    public func transition(to target: ChallengeSessionState) -> Bool {
        session.transition(to: target)
    }

    /// Mark a challenge ID as submitted (anti-replay).
    /// 原子标记已提交；重复提交返回 false。
    @discardableResult
    public func markSubmitted(_ challengeId: String) -> Bool {
        session.markSubmitted(challengeId)
    }

    /// Check if a challenge ID has been submitted.
    /// 查询是否已提交（防重放只读检查）。
    public func hasSubmitted(_ challengeId: String) -> Bool {
        session.hasSubmitted(challengeId)
    }

    /// Reset session to idle.
    /// 重置会话；保留已提交记录以持续防重放。
    public func reset() {
        session.reset()
    }

    /// Verify a challenge result's HMAC.
    /// 校验结果 HMAC；失败返回篡改信号，成功或未配置密钥返回 nil。
    public func verifyResult(_ result: ChallengeVerificationResult) -> RiskSignal? {
        session.verifyResult(result)
    }
}
