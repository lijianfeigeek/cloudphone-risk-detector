// 挑战（Challenge）会话状态机：绑定服务端下发的 challengeId，维护
// idle→issued→executing→submitted→verified/failed→closed 的合法迁移。
// 负责防重放（submittedChallengeIds）、多轮挑战（nextChallenge）、探针执行状态与结果 HMAC 校验。
// 线程模型：所有可变状态由 `UnfairLock` 保护，可在任意线程调用；状态迁移在锁内原子完成。
// 安全不变量：非法迁移一律返回 false；当前会话提交过的 challengeId 不能再次提交。
import CryptoKit
import Foundation

// MARK: - ChallengeSession 状态机

/// 为控制流平坦化（CFF）状态机派生盐值：状态、challengeId、提交数等参与混淆，
/// 使不同会话/阶段的分支状态码不同，增加静态逆向难度。
private enum ChallengeSessionCFF {
    /// 组合当前状态、执行状态、提交计数与额外输入，生成 32 位盐。
    /// 相同输入得到稳定盐；额外字符串/单词用于把目标状态也绑进状态码。
    static func salt(
        state: ChallengeSessionState,
        currentChallengeId: String?,
        executionStatus: ChallengeExecutionStatus,
        submittedCount: Int,
        extraStrings: [String] = [],
        extraWords: [UInt64] = []
    ) -> UInt32 {
        CFFRuntimeSalt.combine(
            words: [
                UInt64(state.rawValue.utf8.reduce(0) { ($0 &* 16777619) ^ UInt64($1) }),
                UInt64(executionStatus.rawValue.utf8.reduce(0) { ($0 &* 131) &+ UInt64($1) }),
                UInt64(submittedCount),
            ] + extraWords,
            strings: [currentChallengeId ?? ""] + extraStrings,
            flags: [
                currentChallengeId != nil,
                submittedCount > 0,
                executionStatus != .completed,
            ]
        )
    }
}

/// Challenge 会话状态
/// 状态流转：idle → issued → executing → submitted → verified/failed → closed
/// - idle：未绑定挑战；issued：已绑定待执行；executing：探针执行中；
/// - submitted：结果已提交待服务端判定；verified/failed：服务端判定结果；closed：会话终结。
public enum ChallengeSessionState: String, Codable, Sendable {
    case idle
    case issued
    case executing
    case submitted
    case verified
    case failed
    case closed
}

/// 挑战会话状态机
/// 每个 session 绑定唯一 challengeId，防止跨 session 混用。
/// 支持多轮递进挑战（nextChallenge）、防重放（submittedChallengeIds）、超时与降级（executionStatus）。
/// 线程模型：所有读写经 `UnfairLock`；状态迁移的校验与提交在同一临界区完成。
public final class ChallengeSession: @unchecked Sendable {

    // MARK: - 状态

    // 保护下方全部可变状态；业务方法通常持锁完成一次原子操作。
    private let lock = UnfairLock()
    // 当前状态；只能通过 transition/advance/bindChallenge 等受控入口修改。
    private var _state: ChallengeSessionState = .idle
    // 当前绑定的 challengeId；同一时刻至多一个。
    private var _currentChallengeId: String?
    // 历史上已提交的 challengeId；reset 不清空以持续防重放。
    private var _submittedChallengeIds: Set<String> = []
    // 服务端下发的下一轮挑战；多轮递进时由调用方读取。
    private var _nextChallenge: ChallengeTrigger.BlindChallenge?
    // 最近一次探针执行状态（完成/超时/不支持），随结果一起上报。
    private var _executionStatus: ChallengeExecutionStatus = .completed
    // 验证 ChallengeVerificationResult HMAC 的对称密钥；未配置时跳过校验。
    private var _challengeKey: SymmetricKey?

    /// 当前状态
    public var state: ChallengeSessionState {
        lock.withLock { _state }
    }

    /// 当前绑定的 challengeId（与 session 一一对应）
    public var currentChallengeId: String? {
        lock.withLock { _currentChallengeId }
    }

    /// 已提交的 challengeId 集合（防重放：每个 challengeId 只能提交一次）
    public var submittedChallengeIds: Set<String> {
        lock.withLock { _submittedChallengeIds }
    }

    /// 下一轮挑战（服务端通过 nextChallenge 下发，用于多轮递进）
    /// 第一轮：轻量探针（GPU 渲染、传感器熵）
    /// 第二轮：重量级探针（内存完整性、代码签名验证）
    public var nextChallenge: ChallengeTrigger.BlindChallenge? {
        lock.withLock { _nextChallenge }
    }

    /// 探针执行状态（超时/不支持时上报）
    public var executionStatus: ChallengeExecutionStatus {
        lock.withLock { _executionStatus }
    }

    // MARK: - 合法状态转换

    /// 合法迁移白名单：只允许单向推进，防止状态回退或跳级。
    private static let validTransitions: [ChallengeSessionState: Set<ChallengeSessionState>] = [
        .idle: [.issued],
        .issued: [.executing],
        .executing: [.submitted],
        .submitted: [.verified, .failed],
        .verified: [.closed],
        .failed: [.closed],
        .closed: []
    ]

    // MARK: - 初始化

    /// 创建空会话（idle，无绑定挑战）。
    public init() {}

    /// 共享会话实例（用于防重放、多轮挑战等）
    // 进程级共享会话；宿主通常通过 CPRiskKit 使用它。
    public static let shared = ChallengeSession()

    // MARK: - 状态转换

    /// 尝试迁移到目标状态。
    /// - Parameter target: 目标状态；必须出现在 `validTransitions[当前状态]`。
    /// - Returns: 迁移成功返回 true；非法迁移返回 false 且状态不变。
    /// 校验与提交在锁内完成，并通过 CFF 状态机执行，避免单点分支被轻易定位。
    @discardableResult
    public func transition(to target: ChallengeSessionState) -> Bool {
        lock.withLock {
            // 盐值把当前状态与目标状态绑进混淆状态码，迁移路径不可静态枚举。
            let salt = ChallengeSessionCFF.salt(
                state: _state,
                currentChallengeId: _currentChallengeId,
                executionStatus: _executionStatus,
                submittedCount: _submittedChallengeIds.count,
                extraStrings: [target.rawValue]
            )
            let seed: UInt32 = 0x1D4F29B7
            let entryState: UInt32 = 0x11
            let validateState: UInt32 = 0x12
            let rejectState: UInt32 = 0x13
            let commitState: UInt32 = 0x14

            var sink = CFFReturnSink<Bool>()
            var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: salt)

            while !sink.isResolved {
                let decodedState = CFFStateCodec.decode(encodedState, seed: seed, salt: salt)

                if decodedState == entryState {
                    encodedState = CFFStateCodec.encode(validateState, seed: seed, salt: salt)
                } else if decodedState == validateState {
                    // 白名单校验是唯一放行条件。
                    let allowed = Self.validTransitions[_state]?.contains(target) ?? false
                    encodedState = CFFStateCodec.encode(allowed ? commitState : rejectState, seed: seed, salt: salt)
                } else if decodedState == rejectState {
                    #if DEBUG
                    Logger.log("ChallengeSession.transition rejected: \(_state.rawValue) -> \(target.rawValue)")
                    #endif
                    sink.store(false)
                } else if decodedState == commitState {
                    _state = target
                    #if DEBUG
                    Logger.log("ChallengeSession.transition: \(target.rawValue)")
                    #endif
                    sink.store(true)
                } else {
                    // 状态机异常（被篡改/解码失败）按拒绝处理，fail-closed。
                    sink.store(false)
                }
            }

            return sink.resolve(or: false)
        }
    }

    /// 按预设顺序推进到下一状态（idle→issued→executing→submitted→closed）。
    /// - Returns: 成功返回 true；`submitted`/`closed` 为终止态，返回 false。
    @discardableResult
    public func advance() -> Bool {
        lock.withLock {
            let salt = ChallengeSessionCFF.salt(
                state: _state,
                currentChallengeId: _currentChallengeId,
                executionStatus: _executionStatus,
                submittedCount: _submittedChallengeIds.count
            )
            let seed: UInt32 = 0x6B7A3E19
            let entryState: UInt32 = 0x21
            let classifyState: UInt32 = 0x22
            let commitState: UInt32 = 0x23

            var sink = CFFReturnSink<Bool>()
            var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: salt)
            var nextState: ChallengeSessionState?

            while !sink.isResolved {
                switch CFFStateCodec.decode(encodedState, seed: seed, salt: salt) {
                case entryState:
                    encodedState = CFFStateCodec.encode(classifyState, seed: seed, salt: salt)
                case classifyState:
                    // submitted 需要服务端判定，不能自动推进；verified/failed 之后统一关闭。
                    switch _state {
                    case .idle:
                        nextState = .issued
                    case .issued:
                        nextState = .executing
                    case .executing:
                        nextState = .submitted
                    case .submitted:
                        nextState = nil
                    case .verified, .failed:
                        nextState = .closed
                    case .closed:
                        nextState = nil
                    }
                    if nextState != nil {
                        encodedState = CFFStateCodec.encode(commitState, seed: seed, salt: salt)
                    } else {
                        sink.store(false)
                    }
                case commitState:
                    if let nextState {
                        _state = nextState
                        sink.store(true)
                    } else {
                        sink.store(false)
                    }
                default:
                    sink.store(false)
                }
            }

            return sink.resolve(or: false)
        }
    }

    // MARK: - 业务方法

    /// 绑定 challenge 并进入 issued 状态。
    /// - Parameter challenge: 当前挑战（含 challengeId/seed/过期时间/探针列表）。
    /// - Returns: 仅当当前状态为 idle 时成功；否则拒绝，防止会话被中途换绑。
    @discardableResult
    public func bindChallenge(_ challenge: ChallengeTrigger.BlindChallenge) -> Bool {
        lock.withLock {
            let salt = ChallengeSessionCFF.salt(
                state: _state,
                currentChallengeId: _currentChallengeId,
                executionStatus: _executionStatus,
                submittedCount: _submittedChallengeIds.count,
                extraStrings: [challenge.challengeId, challenge.seed],
                extraWords: [UInt64(challenge.probeIds.count), UInt64(bitPattern: challenge.expiresAt)]
            )
            let seed: UInt32 = 0x54A73C91
            let entryState: UInt32 = 0x31
            let validateState: UInt32 = 0x32
            let commitState: UInt32 = 0x33
            let rejectState: UInt32 = 0x34

            var sink = CFFReturnSink<Bool>()
            var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: salt)

            while !sink.isResolved {
                let decodedState = CFFStateCodec.decode(encodedState, seed: seed, salt: salt)

                if decodedState == entryState {
                    encodedState = CFFStateCodec.encode(validateState, seed: seed, salt: salt)
                } else if decodedState == validateState {
                    // 只允许 idle→issued：已绑定/执行中的会话不能换 challenge。
                    encodedState = CFFStateCodec.encode(_state == .idle ? commitState : rejectState, seed: seed, salt: salt)
                } else if decodedState == commitState {
                    _currentChallengeId = challenge.challengeId
                    _state = .issued
                    sink.store(true)
                } else if decodedState == rejectState {
                    #if DEBUG
                    Logger.log("ChallengeSession.bindChallenge rejected: state=\(_state.rawValue)")
                    #endif
                    sink.store(false)
                } else {
                    sink.store(false)
                }
            }

            return sink.resolve(or: false)
        }
    }

    /// 检查 challengeId 是否与当前 session 绑定一致（防止跨会话结果注入）。
    public func isChallengeIdBound(_ challengeId: String) -> Bool {
        lock.withLock { _currentChallengeId == challengeId }
    }

    /// 查询 challengeId 是否已提交（防重放只读检查）。
    public func hasSubmitted(_ challengeId: String) -> Bool {
        lock.withLock { _submittedChallengeIds.contains(challengeId) }
    }

    /// 标记 challengeId 已提交（原子防重放）。
    /// - Parameter challengeId: 已提交的 challengeId。
    /// - Returns: 首次提交返回 true；重复提交返回 false 且不改变集合。
    @discardableResult
    public func markSubmitted(_ challengeId: String) -> Bool {
        lock.withLock {
            let salt = ChallengeSessionCFF.salt(
                state: _state,
                currentChallengeId: _currentChallengeId,
                executionStatus: _executionStatus,
                submittedCount: _submittedChallengeIds.count,
                extraStrings: [challengeId]
            )
            let seed: UInt32 = 0x7C92E40D
            let entryState: UInt32 = 0x41
            let replayCheckState: UInt32 = 0x42
            let insertState: UInt32 = 0x43
            let rejectState: UInt32 = 0x44

            var sink = CFFReturnSink<Bool>()
            var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: salt)

            while !sink.isResolved {
                switch CFFStateCodec.decode(encodedState, seed: seed, salt: salt) {
                case entryState:
                    encodedState = CFFStateCodec.encode(replayCheckState, seed: seed, salt: salt)
                case replayCheckState:
                    // 集合查询与插入在同一锁内完成，避免并发提交同时通过检查。
                    let nextState = _submittedChallengeIds.contains(challengeId) ? rejectState : insertState
                    encodedState = CFFStateCodec.encode(nextState, seed: seed, salt: salt)
                case insertState:
                    _submittedChallengeIds.insert(challengeId)
                    sink.store(true)
                case rejectState:
                    #if DEBUG
                    Logger.log("ChallengeSession.markSubmitted rejected: challengeId=\(challengeId) already submitted (replay)")
                    #endif
                    sink.store(false)
                default:
                    sink.store(false)
                }
            }

            return sink.resolve(or: false)
        }
    }

    /// 设置/清除下一轮挑战（服务端下发）；仅保存，不改变当前状态。
    public func setNextChallenge(_ challenge: ChallengeTrigger.BlindChallenge?) {
        lock.withLock { _nextChallenge = challenge }
    }

    /// 记录探针执行状态（如超时/不支持），用于上报与降级。
    public func setExecutionStatus(_ status: ChallengeExecutionStatus) {
        lock.withLock { _executionStatus = status }
    }

    /// 重置 session 到 idle（用于新一轮）；保留已提交记录以持续防重放。
    public func reset() {
        lock.withLock {
            _state = .idle
            _currentChallengeId = nil
            _nextChallenge = nil
            _executionStatus = .completed
            // 保留 _submittedChallengeIds 以持续防重放
        }
    }

    /// 完全清空（包括已提交记录和 challenge key，慎用）。
    /// 清空防重放集合会允许旧 challengeId 再次提交，仅在会话/密钥彻底轮换时调用。
    public func clearAll() {
        lock.withLock {
            _state = .idle
            _currentChallengeId = nil
            _submittedChallengeIds.removeAll()
            _nextChallenge = nil
            _executionStatus = .completed
            _challengeKey = nil
        }
    }
}

// MARK: - ChallengeVerificationResult

/// 服务端返回的挑战验证结果
/// 客户端解析并应用，用于回注到下一次 evaluate 的分数调整
public struct ChallengeVerificationResult: Codable, Sendable {
    /// 对应的挑战 id；必须与本地会话绑定值一致
    public let challengeId: String
    /// 服务端判定是否通过
    public let passed: Bool
    /// 未通过的探针 id 列表
    public let failedProbes: [String]
    /// 分数增量偏移（delta），不是绝对分；服务端应返回 [-100,100]
    public let adjustedScore: Double?
    /// 对 challengeId|score|passed 的 MAC（十六进制），用于防伪造
    public let hmac: String?

    // 短键：ci/p/fp/as/h。
    private enum CodingKeys: String, CodingKey {
        case challengeId = "ci"
        case passed = "p"
        case failedProbes = "fp"
        case adjustedScore = "as"
        case hmac = "h"
    }

    /// 创建服务端验证结果；failedProbes/adjustedScore/hmac 可选。
    public init(
        challengeId: String,
        passed: Bool,
        failedProbes: [String] = [],
        adjustedScore: Double? = nil,
        hmac: String? = nil
    ) {
        self.challengeId = challengeId
        self.passed = passed
        self.failedProbes = failedProbes
        self.adjustedScore = adjustedScore
        self.hmac = hmac
    }
}

// MARK: - Challenge HMAC Verification

extension ChallengeSession {
    /// Configure the MAC key used to verify `ChallengeVerificationResult`.
    /// 配置验证密钥；未配置时 `verifyResult` 直接返回 nil（不做校验）。
    public func configureChallengeKey(_ key: Data) {
        lock.withLock { _challengeKey = SymmetricKey(data: key) }
    }

    /// Verify the custom SHA-256 MAC on a `ChallengeVerificationResult`.
    /// Returns a `challenge_hmac_mismatch` signal if verification fails, or nil on success / no key configured.
    /// 校验服务端结果的 HMAC。
    /// - Returns: 校验失败返回 `challenge_hmac_mismatch` 信号；成功或未配置密钥返回 nil。
    /// - 失败语义：缺少 hmac、格式错误、MAC 不匹配都视为篡改，交由上层注入评分。
    public func verifyResult(_ result: ChallengeVerificationResult) -> RiskSignal? {
        let key: SymmetricKey? = lock.withLock { _challengeKey }

        guard let key else { return nil }

        guard let hmacHex = result.hmac, !hmacHex.isEmpty else {
            Logger.log("ChallengeSession.verifyResult: hmac field missing")
            return makeMismatchSignal(challengeId: result.challengeId, reason: "hmac_missing")
        }

        // MAC 覆盖 challengeId、格式化后的分数与 passed，任一被改都会导致校验失败。
        let scoreStr = result.adjustedScore.map { String(format: "%.6f", $0) } ?? "nil"
        let input = "\(result.challengeId)|\(scoreStr)|\(result.passed)"
        let inputData = Data(input.utf8)
        let expectedHex = CPRiskMessageAuth.authenticationCodeHex(for: inputData, using: key)

        // 常量时间比较，避免通过响应时间侧信道猜测 MAC。
        guard timingSafeCompare(hmacHex.lowercased(), expectedHex.lowercased()) else {
            Logger.log("ChallengeSession.verifyResult: MAC mismatch for challengeId=\(result.challengeId)")
            return makeMismatchSignal(challengeId: result.challengeId, reason: "hmac_mismatch")
        }

        return nil
    }

    /// 构造 HMAC 校验失败信号：`.tampered`、layer 3、weightHint 80。
    private func makeMismatchSignal(challengeId: String, reason: String) -> RiskSignal {
        RiskSignal(
            id: "challenge_hmac_mismatch",
            category: "integrity",
            score: 35,
            evidence: ["challenge_id": challengeId, "reason": reason],
            state: .tampered,
            layer: 3,
            weightHint: 80
        )
    }
}

// ChallengeExecutionStatus 定义于 RiskReport.swift
