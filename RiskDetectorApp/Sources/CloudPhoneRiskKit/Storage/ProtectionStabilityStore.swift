// 文件职责：保护链路的启动阶段归因、崩溃计数、自动回滚与本地安全模式持久化。
// 管道位置：SDK 启动早期调用 beginSession/markPhase，为稳定性 kill switch 提供依据。
// 安全不变量：状态文件 AES-GCM 加密 + HMAC 校验 + Keychain 新鲜度锚点；
// 校验失败即清空并按空状态启动，避免被篡改的状态抑制防护。
import Foundation

// MARK: - 阶段与数据模型

/// SDK 启动保护链路的阶段标记，用于崩溃归因。
/// 顺序即启动顺序；越靠前的阶段崩溃越可能是远程配置导致。
public enum ProtectionStartupPhase: String, Codable, Sendable, CaseIterable {
    /// start() 已进入，尚未开始任何保护准备。
    case startInvoked = "start_invoked"
    /// 反调试准备阶段。
    case antiDebugPrepare = "anti_debug_prepare"
    /// 加固运行时初始化阶段。
    case armorRuntimeInit = "armor_runtime_init"
    /// 反 dump 准备阶段。
    case antiDumpPrepare = "anti_dump_prepare"
    /// 信号 Provider 注册阶段。
    case providerRegistration = "provider_registration"
    /// 启动完成（健康标记）。
    case startupCompleted = "startup_completed"
}

/// 阶段便捷判断。
extension ProtectionStartupPhase {
    /// 是否属于 `armor_runtime_init` 及更早阶段（含 anti_debug_prepare）。
    /// 早期阶段崩溃更可能与加固/远程配置相关，用于触发回滚。
    var isEarlyStartupPhase: Bool {
        switch self {
        case .startInvoked, .antiDebugPrepare, .armorRuntimeInit:
            return true
        case .antiDumpPrepare, .providerRegistration, .startupCompleted:
            return false
        }
    }
}

/// 上次 session 未正常完成启动时的归因结果。
public struct ProtectionAttributionResult: Sendable {
    /// 异常 session 的 ID。
    public let previousSessionId: String
    /// 崩溃时停留的阶段。
    public let phase: ProtectionStartupPhase
    /// 当时生效的远程配置版本。
    public let remoteConfigVersion: Int?
    /// 当时使用的反调试模式标签。
    public let antiDebugModeLabel: String
    /// 异常发生时是否已处于本地安全模式。
    public let localSafeProfileActive: Bool
    /// 加固运行时状态/原因摘要。
    public let armorRuntimeSummary: String
    /// watchdog 是否启动失败。
    public let watchdogStartFailed: Bool
    /// 反 dump 是否启动失败。
    public let antiDumpStartFailed: Bool
    /// 上次记录的 watchdog 异常标志位。
    public let lastWatchdogAnomalyFlags: UInt32?
}

/// 供线上/测试读取的保护稳定性快照。
public struct ProtectionStabilitySnapshot: Sendable {
    /// 是否处于降级（安全模式或 kill switch）。
    public let isDegraded: Bool
    /// 本地安全模式是否生效。
    public let isLocalSafeProfileActive: Bool
    /// 稳定性 kill switch 是否生效。
    public let isLocalStabilityKillSwitchActive: Bool
    /// 最近一次异常归因阶段。
    public let lastAttributionPhase: ProtectionStartupPhase?
    /// 最近失败的配置版本。
    public let lastFailedConfigVersion: Int?
    /// 同一配置版本连续失败次数。
    public let consecutiveFailuresSameVersion: Int
    /// 早期阶段连续失败次数。
    public let consecutiveEarlyPhaseFailures: Int
    /// 已回滚并钉住的配置版本。
    public let pinnedRollbackVersion: Int?
    /// 最近一次健康启动时间。
    public let lastHealthyStartupAt: TimeInterval?
    /// 当前 session ID。
    public let currentSessionId: String?
    /// 当前启动阶段。
    public let currentPhase: ProtectionStartupPhase
    /// 降级后连续成功启动次数。
    public let successfulStartsWhileDegraded: Int
    /// 进入安全模式时的配置版本。
    public let safeProfileEnteredAtConfigVersion: Int?
}

/// `beginSession` 返回：归因结果，以及是否触发回滚/降级。
public struct ProtectionStabilityBootstrapResult: Sendable {
    /// 上次异常归因；正常退出为 nil。
    public let attribution: ProtectionAttributionResult?
    /// 是否回滚了远程配置。
    public let didRollbackRemoteConfig: Bool
    /// 回滚到的配置版本。
    public let rolledBackToVersion: Int?
    /// 是否进入本地安全模式。
    public let didEnterLocalSafeProfile: Bool
    /// 是否启用稳定性 kill switch。
    public let didActivateLocalStabilityKillSwitch: Bool
}

// MARK: - 存储实现

/// 保护链路的稳定性与崩溃归因持久化（SecureFileStore + HMAC + 新鲜度锚点）。
/// 所有公开方法内部加锁；调用方可从任意线程使用。
public final class ProtectionStabilityStore: @unchecked Sendable {
    public static let shared = ProtectionStabilityStore(fileStore: .shared, configCache: ConfigCache.shared)

    /// 落盘信封：session/阶段/计数/新鲜度等完整状态。
    private struct StoredEnvelope: Codable {
        /// 信封结构版本。
        var schemaVersion: Int
        var sessionId: String?
        var phase: ProtectionStartupPhase
        /// 本次启动是否已完成（区分正常退出与崩溃）。
        var startupCompleted: Bool
        var remoteConfigVersion: Int?
        var antiDebugModeLabel: String
        /// 本地安全模式开关。
        var localSafeProfileActive: Bool
        /// 稳定性 kill switch 开关。
        var localStabilityKillSwitchActive: Bool
        var armorRuntimeStatus: String
        var armorRuntimeReason: String
        var watchdogStartResult: Int32
        var antiDumpStartResult: Int32
        var lastWatchdogAnomalyFlags: UInt32?
        var startupBeganAt: TimeInterval
        var startupCompletedAt: TimeInterval?
        /// 按阶段统计的连续崩溃次数。
        var phaseConsecutiveCrashCounts: [String: Int]
        /// 同配置版本连续失败次数。
        var consecutiveFailuresSameVersion: Int
        var lastFailedConfigVersion: Int?
        /// 早期阶段连续失败次数。
        var consecutiveEarlyPhaseFailures: Int
        var pinnedRollbackVersion: Int?
        var lastHealthyStartupAt: TimeInterval?
        var successfulStartsWhileDegraded: Int
        var safeProfileEnteredAtConfigVersion: Int?
        var lastWatchdogFailed: Bool
        var lastAntiDumpFailed: Bool
        var lastSessionIdForAttribution: String?
        var lastAttributedPhase: ProtectionStartupPhase?
        var lastAttributedConfigVersion: Int?
        /// 新鲜度锚点镜像，用于防回滚。
        var freshness: FreshnessState

        // 短键压缩落盘体积。
        private enum CodingKeys: String, CodingKey {
            case schemaVersion = "sv"
            case sessionId = "sid"
            case phase = "ph"
            case startupCompleted = "sc"
            case remoteConfigVersion = "rcv"
            case antiDebugModeLabel = "adm"
            case localSafeProfileActive = "lsp"
            case localStabilityKillSwitchActive = "lsk"
            case armorRuntimeStatus = "ars"
            case armorRuntimeReason = "arr"
            case watchdogStartResult = "wsr"
            case antiDumpStartResult = "adsr"
            case lastWatchdogAnomalyFlags = "waf"
            case startupBeganAt = "sba"
            case startupCompletedAt = "sca"
            case phaseConsecutiveCrashCounts = "pcc"
            case consecutiveFailuresSameVersion = "cfsv"
            case lastFailedConfigVersion = "lfcv"
            case consecutiveEarlyPhaseFailures = "cepf"
            case pinnedRollbackVersion = "prv"
            case lastHealthyStartupAt = "lhs"
            case successfulStartsWhileDegraded = "sswd"
            case safeProfileEnteredAtConfigVersion = "spev"
            case lastWatchdogFailed = "lwf"
            case lastAntiDumpFailed = "ladf"
            case lastSessionIdForAttribution = "lsida"
            case lastAttributedPhase = "lap"
            case lastAttributedConfigVersion = "lacv"
            case freshness = "fr"
        }

        init(
            schemaVersion: Int,
            sessionId: String?,
            phase: ProtectionStartupPhase,
            startupCompleted: Bool,
            remoteConfigVersion: Int?,
            antiDebugModeLabel: String,
            localSafeProfileActive: Bool,
            localStabilityKillSwitchActive: Bool,
            armorRuntimeStatus: String,
            armorRuntimeReason: String,
            watchdogStartResult: Int32,
            antiDumpStartResult: Int32,
            lastWatchdogAnomalyFlags: UInt32?,
            startupBeganAt: TimeInterval,
            startupCompletedAt: TimeInterval?,
            phaseConsecutiveCrashCounts: [String: Int],
            consecutiveFailuresSameVersion: Int,
            lastFailedConfigVersion: Int?,
            consecutiveEarlyPhaseFailures: Int,
            pinnedRollbackVersion: Int?,
            lastHealthyStartupAt: TimeInterval?,
            successfulStartsWhileDegraded: Int,
            safeProfileEnteredAtConfigVersion: Int?,
            lastWatchdogFailed: Bool,
            lastAntiDumpFailed: Bool,
            lastSessionIdForAttribution: String?,
            lastAttributedPhase: ProtectionStartupPhase?,
            lastAttributedConfigVersion: Int?,
            freshness: FreshnessState
        ) {
            self.schemaVersion = schemaVersion
            self.sessionId = sessionId
            self.phase = phase
            self.startupCompleted = startupCompleted
            self.remoteConfigVersion = remoteConfigVersion
            self.antiDebugModeLabel = antiDebugModeLabel
            self.localSafeProfileActive = localSafeProfileActive
            self.localStabilityKillSwitchActive = localStabilityKillSwitchActive
            self.armorRuntimeStatus = armorRuntimeStatus
            self.armorRuntimeReason = armorRuntimeReason
            self.watchdogStartResult = watchdogStartResult
            self.antiDumpStartResult = antiDumpStartResult
            self.lastWatchdogAnomalyFlags = lastWatchdogAnomalyFlags
            self.startupBeganAt = startupBeganAt
            self.startupCompletedAt = startupCompletedAt
            self.phaseConsecutiveCrashCounts = phaseConsecutiveCrashCounts
            self.consecutiveFailuresSameVersion = consecutiveFailuresSameVersion
            self.lastFailedConfigVersion = lastFailedConfigVersion
            self.consecutiveEarlyPhaseFailures = consecutiveEarlyPhaseFailures
            self.pinnedRollbackVersion = pinnedRollbackVersion
            self.lastHealthyStartupAt = lastHealthyStartupAt
            self.successfulStartsWhileDegraded = successfulStartsWhileDegraded
            self.safeProfileEnteredAtConfigVersion = safeProfileEnteredAtConfigVersion
            self.lastWatchdogFailed = lastWatchdogFailed
            self.lastAntiDumpFailed = lastAntiDumpFailed
            self.lastSessionIdForAttribution = lastSessionIdForAttribution
            self.lastAttributedPhase = lastAttributedPhase
            self.lastAttributedConfigVersion = lastAttributedConfigVersion
            self.freshness = freshness
        }

        /// 宽容解码：缺失字段使用安全默认值，保证旧版本数据可读。
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            schemaVersion = try c.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? 1
            sessionId = try c.decodeIfPresent(String.self, forKey: .sessionId)
            phase = try c.decodeIfPresent(ProtectionStartupPhase.self, forKey: .phase) ?? .startInvoked
            startupCompleted = try c.decodeIfPresent(Bool.self, forKey: .startupCompleted) ?? true
            remoteConfigVersion = try c.decodeIfPresent(Int.self, forKey: .remoteConfigVersion)
            antiDebugModeLabel = try c.decodeIfPresent(String.self, forKey: .antiDebugModeLabel) ?? "production"
            localSafeProfileActive = try c.decodeIfPresent(Bool.self, forKey: .localSafeProfileActive) ?? false
            localStabilityKillSwitchActive = try c.decodeIfPresent(Bool.self, forKey: .localStabilityKillSwitchActive) ?? false
            armorRuntimeStatus = try c.decodeIfPresent(String.self, forKey: .armorRuntimeStatus) ?? "n/a"
            armorRuntimeReason = try c.decodeIfPresent(String.self, forKey: .armorRuntimeReason) ?? "n/a"
            watchdogStartResult = try c.decodeIfPresent(Int32.self, forKey: .watchdogStartResult) ?? 0
            antiDumpStartResult = try c.decodeIfPresent(Int32.self, forKey: .antiDumpStartResult) ?? 0
            lastWatchdogAnomalyFlags = try c.decodeIfPresent(UInt32.self, forKey: .lastWatchdogAnomalyFlags)
            startupBeganAt = try c.decodeIfPresent(TimeInterval.self, forKey: .startupBeganAt) ?? 0
            startupCompletedAt = try c.decodeIfPresent(TimeInterval.self, forKey: .startupCompletedAt)
            phaseConsecutiveCrashCounts = try c.decodeIfPresent([String: Int].self, forKey: .phaseConsecutiveCrashCounts) ?? [:]
            consecutiveFailuresSameVersion = try c.decodeIfPresent(Int.self, forKey: .consecutiveFailuresSameVersion) ?? 0
            lastFailedConfigVersion = try c.decodeIfPresent(Int.self, forKey: .lastFailedConfigVersion)
            consecutiveEarlyPhaseFailures = try c.decodeIfPresent(Int.self, forKey: .consecutiveEarlyPhaseFailures) ?? 0
            pinnedRollbackVersion = try c.decodeIfPresent(Int.self, forKey: .pinnedRollbackVersion)
            lastHealthyStartupAt = try c.decodeIfPresent(TimeInterval.self, forKey: .lastHealthyStartupAt)
            successfulStartsWhileDegraded = try c.decodeIfPresent(Int.self, forKey: .successfulStartsWhileDegraded) ?? 0
            safeProfileEnteredAtConfigVersion = try c.decodeIfPresent(Int.self, forKey: .safeProfileEnteredAtConfigVersion)
            lastWatchdogFailed = try c.decodeIfPresent(Bool.self, forKey: .lastWatchdogFailed) ?? false
            lastAntiDumpFailed = try c.decodeIfPresent(Bool.self, forKey: .lastAntiDumpFailed) ?? false
            lastSessionIdForAttribution = try c.decodeIfPresent(String.self, forKey: .lastSessionIdForAttribution)
            lastAttributedPhase = try c.decodeIfPresent(ProtectionStartupPhase.self, forKey: .lastAttributedPhase)
            lastAttributedConfigVersion = try c.decodeIfPresent(Int.self, forKey: .lastAttributedConfigVersion)
            freshness = try c.decodeIfPresent(FreshnessState.self, forKey: .freshness) ?? .zero
        }
    }

    /// 保护全部读写与文件操作的互斥锁。
    private let lock = UnfairLock()
    /// 底层安全文件存储。
    private let fileStore: SecureFileStore
    /// 加密载荷的文件 key。
    private let key = "cloudphone_protection_stability_v1"
    /// HMAC 签名单独存放的 key。
    private let hmacKey = "cloudphone_protection_stability_v1_hmac"
    /// 签名域分隔标识，防止与其他业务签名互相移植。
    private let hmacPurpose = "protection_stability"
    /// Keychain 新鲜度锚点：检测状态文件回滚。
    private let freshnessAnchor = FreshnessAnchor(account: "protection_stability_v1_freshness")
    /// 远程配置缓存，用于选择可回滚的已验证版本。
    private let configCache: ConfigCaching

    /// 进入 safe profile 后至少成功启动次数才允许解除（与更高版本条件组合）。
    private let minimumSuccessfulStartsToExitSafeProfile = 3

    /// 默认构造：复用共享依赖。
    public convenience init() {
        self.init(fileStore: .shared, configCache: ConfigCache.shared)
    }

    /// 测试用构造，可注入文件存储与配置缓存。
    init(fileStore: SecureFileStore, configCache: ConfigCaching) {
        self.fileStore = fileStore
        self.configCache = configCache
    }

    // MARK: - 公开 API

    /// 新进程启动时调用：检测上次异常、累计计数、触发自动回滚/降级，并开启新 session。
    /// - Parameters:
    ///   - remoteConfigVersion: 本次加载的远程配置版本（无则 nil）。
    ///   - antiDebugMode: 当前反调试运行时模式。
    ///   - safeProfileAlreadyActive: 外部是否已判定需要安全模式。
    /// - Returns: 归因结果与本次采取的回滚/降级动作。
    public func beginSession(
        remoteConfigVersion: Int?,
        antiDebugMode: CPRiskAntiDebugRuntimeMode,
        safeProfileAlreadyActive: Bool
    ) -> ProtectionStabilityBootstrapResult {
        lock.withLock {
            let previous = loadStateLocked()
            let attribution = detectPreviousAbnormalTerminationLocked(previous: previous)

            var working = previous
            var didRollback = false
            var rolledBackVersion: Int?
            var didEnterSafe = false
            var didKillSwitch = false

            // 仅当上次启动未正常完成时才归因并考虑回滚。
            if let attr = attribution {
                Self.logAttribution(attr)
                working.lastAttributedPhase = attr.phase
                working.lastAttributedConfigVersion = attr.remoteConfigVersion
                applyCountersAfterAbnormalLocked(attr: attr, state: &working)

                // 依据连续失败次数决定：回滚 / 仅降级 / 不处理。
                let decision = evaluateAutoRollbackLocked(
                    attribution: attr,
                    state: &working
                )

                switch decision {
                case .rollback(let version):
                    // 只回滚到已验证且低于故障版本的配置。
                    if let cfg = rollbackVerifiedConfigLocked(below: version) {
                        didRollback = true
                        rolledBackVersion = cfg.version
                        working.pinnedRollbackVersion = cfg.version
                        resetFailureCountersLocked(&working)
                    // 无可用回滚版本：进入本地安全模式并启用 kill switch。
                    } else {
                        enterDegradedModeLocked(state: &working, remoteVersion: remoteConfigVersion)
                        didEnterSafe = working.localSafeProfileActive
                        didKillSwitch = working.localStabilityKillSwitchActive
                    }
                case .degradedOnly:
                    enterDegradedModeLocked(state: &working, remoteVersion: remoteConfigVersion)
                    didEnterSafe = working.localSafeProfileActive
                    didKillSwitch = working.localStabilityKillSwitchActive
                case .none:
                    break
                }
            }

            // 开启新 session：重置阶段与运行时状态，保留降级开关。
            let newSession = UUID().uuidString
            working.sessionId = newSession
            working.phase = .startInvoked
            working.startupCompleted = false
            working.remoteConfigVersion = remoteConfigVersion
            working.antiDebugModeLabel = Self.label(for: antiDebugMode)
            // 一旦进入安全模式或外部要求，本次 session 保持生效（只增不减）。
            working.localSafeProfileActive = working.localSafeProfileActive || safeProfileAlreadyActive
            working.armorRuntimeStatus = "pending"
            working.armorRuntimeReason = "pending"
            working.watchdogStartResult = 0
            working.antiDumpStartResult = 0
            working.lastWatchdogAnomalyFlags = nil
            working.startupBeganAt = Date().timeIntervalSince1970
            working.startupCompletedAt = nil
            working.lastWatchdogFailed = false
            working.lastAntiDumpFailed = false
            working.lastSessionIdForAttribution = newSession

            saveLocked(working)
            return ProtectionStabilityBootstrapResult(
                attribution: attribution,
                didRollbackRemoteConfig: didRollback,
                rolledBackToVersion: rolledBackVersion,
                didEnterLocalSafeProfile: didEnterSafe,
                didActivateLocalStabilityKillSwitch: didKillSwitch
            )
        }
    }

    /// 记录当前启动阶段（崩溃时据此归因）。
    public func markPhase(_ phase: ProtectionStartupPhase) {
        lock.withLock {
            var state = loadStateLocked()
            state.phase = phase
            saveLocked(state)
        }
    }

    /// 标记启动完成：刷新健康时间、清零失败计数，并尝试退出安全模式。
    /// - Parameter remoteConfigVersion: 本次成功启动所使用的配置版本。
    public func markStartupCompleted(remoteConfigVersion: Int?) {
        lock.withLock {
            var state = loadStateLocked()
            state.phase = .startupCompleted
            state.startupCompleted = true
            state.startupCompletedAt = Date().timeIntervalSince1970
            state.lastHealthyStartupAt = state.startupCompletedAt
            state.remoteConfigVersion = remoteConfigVersion ?? state.remoteConfigVersion
            resetFailureCountersLocked(&state)
            state.consecutiveEarlyPhaseFailures = 0

            // 降级状态下累积成功启动次数，满足条件才允许退出安全模式。
            if state.localSafeProfileActive {
                state.successfulStartsWhileDegraded += 1
                maybeExitSafeProfileLocked(remoteVersion: remoteConfigVersion, state: &state)
            } else {
                state.successfulStartsWhileDegraded = 0
            }

            saveLocked(state)
        }
    }

    /// 记录加固/watchdog/反 dump 的运行时健康信息。
    /// - Parameters:
    ///   - armorStatus: 加固运行时状态。
    ///   - armorReason: 加固运行时原因。
    ///   - watchdogStartResult: watchdog 启动返回值（非 0 视为失败）。
    ///   - antiDumpStartResult: 反 dump 启动返回值（非 0 视为失败）。
    ///   - watchdogAnomalyFlags: watchdog 异常标志位。
    public func recordRuntimeHealth(
        armorStatus: String,
        armorReason: String,
        watchdogStartResult: Int32,
        antiDumpStartResult: Int32,
        watchdogAnomalyFlags: UInt32?
    ) {
        lock.withLock {
            var state = loadStateLocked()
            state.armorRuntimeStatus = armorStatus
            state.armorRuntimeReason = armorReason
            state.watchdogStartResult = watchdogStartResult
            state.antiDumpStartResult = antiDumpStartResult
            state.lastWatchdogAnomalyFlags = watchdogAnomalyFlags
            state.lastWatchdogFailed = watchdogStartResult != 0
            state.lastAntiDumpFailed = antiDumpStartResult != 0
            saveLocked(state)
        }
    }

    /// 只读检测上次是否异常终止。
    /// - Returns: 异常归因；上次正常完成或没有 session 时为 nil。
    public func detectPreviousAbnormalTermination() -> ProtectionAttributionResult? {
        lock.withLock {
            let state = loadStateLocked()
            return detectPreviousAbnormalTerminationLocked(previous: state)
        }
    }

    /// 读取当前稳定性快照（供决策引擎与诊断使用）。
    public func currentSnapshot() -> ProtectionStabilitySnapshot {
        lock.withLock {
            let s = loadStateLocked()
            let degraded = s.localSafeProfileActive || s.localStabilityKillSwitchActive
            return ProtectionStabilitySnapshot(
                isDegraded: degraded,
                isLocalSafeProfileActive: s.localSafeProfileActive,
                isLocalStabilityKillSwitchActive: s.localStabilityKillSwitchActive,
                lastAttributionPhase: s.lastAttributedPhase,
                lastFailedConfigVersion: s.lastFailedConfigVersion,
                consecutiveFailuresSameVersion: s.consecutiveFailuresSameVersion,
                consecutiveEarlyPhaseFailures: s.consecutiveEarlyPhaseFailures,
                pinnedRollbackVersion: s.pinnedRollbackVersion,
                lastHealthyStartupAt: s.lastHealthyStartupAt,
                currentSessionId: s.sessionId,
                currentPhase: s.phase,
                successfulStartsWhileDegraded: s.successfulStartsWhileDegraded,
                safeProfileEnteredAtConfigVersion: s.safeProfileEnteredAtConfigVersion
            )
        }
    }

    /// 稳定性 kill-switch 是否启用（只影响 allow/log，不直接拦截）。
    public func isLocalStabilityKillSwitchEnabled() -> Bool {
        lock.withLock { loadStateLocked().localStabilityKillSwitchActive }
    }

    /// 是否应强制宽松 anti-debug（本地安全模式）。
    public func isLocalSafeProfileActive() -> Bool {
        lock.withLock { loadStateLocked().localSafeProfileActive }
    }

    // MARK: - 测试辅助

    /// 清空持久化状态与锚点（仅测试用）。
    internal func resetForTesting() {
        lock.withLock {
            fileStore.remove(key: key)
            fileStore.remove(key: hmacKey)
            freshnessAnchor.remove()
        }
    }

    // MARK: - 回滚决策

    /// 自动回滚决策。
    private enum AutoRollbackDecision {
        /// 回滚到低于该上限的最近已验证版本。
        case rollback(ceilingVersion: Int)
        /// 无可回滚版本，仅进入降级模式。
        case degradedOnly
        /// 保持现状。
        case none
    }

    /// 根据归因与连续失败计数决定是否回滚。
    /// - 同版本连续失败 ≥ 2、早期阶段连续失败 ≥ 2，或 watchdog+反 dump 同时失败且同版本失败 ≥ 2 时触发回滚。
    private func evaluateAutoRollbackLocked(
        attribution: ProtectionAttributionResult,
        state: inout StoredEnvelope
    ) -> AutoRollbackDecision {
        let v = attribution.remoteConfigVersion ?? -1
        guard v >= 0 else {
            return .degradedOnly
        }

        // 阈值取 2：单次崩溃可能由偶发因素导致，两次才视为配置问题。
        let sameVersionTwice = state.consecutiveFailuresSameVersion >= 2
        let earlyTwice = state.consecutiveEarlyPhaseFailures >= 2
        let watchdogDumpPairFailure = attribution.watchdogStartFailed && attribution.antiDumpStartFailed
            && state.consecutiveFailuresSameVersion >= 2

        // 任一条件命中即回滚到更低版本；无版本可回时由调用方降级。
        if sameVersionTwice || earlyTwice || watchdogDumpPairFailure {
            return .rollback(ceilingVersion: v)
        }

        return .none
    }

    /// 从配置缓存选择低于 `ceilingVersion` 的最近已验证版本。
    private func rollbackVerifiedConfigLocked(below ceilingVersion: Int) -> RemoteConfig? {
        configCache.rollbackToNewestVerifiedVersion(below: ceilingVersion)
    }

    /// 进入本地安全模式并启用稳定性 kill switch（无可用回滚版本时的兜底）。
    private func enterDegradedModeLocked(state: inout StoredEnvelope, remoteVersion: Int?) {
        state.localSafeProfileActive = true
        state.localStabilityKillSwitchActive = true
        if state.safeProfileEnteredAtConfigVersion == nil {
            state.safeProfileEnteredAtConfigVersion = remoteVersion ?? state.remoteConfigVersion
        }
        state.successfulStartsWhileDegraded = 0
        Logger.log("protection_stability: entered local safe profile + stability kill-switch (no verified rollback)")
    }

    /// 满足“连续健康启动 + 更新配置版本”后退出安全模式。
    private func maybeExitSafeProfileLocked(remoteVersion: Int?, state: inout StoredEnvelope) {
        guard state.localSafeProfileActive else { return }
        let rv = remoteVersion ?? state.remoteConfigVersion ?? -1
        let enteredAt = state.safeProfileEnteredAtConfigVersion ?? -1
        let versionOk = rv > enteredAt
        let successOk = state.successfulStartsWhileDegraded >= minimumSuccessfulStartsToExitSafeProfile
        // 两个条件必须同时满足，避免在旧配置上过早恢复严格防护。
        guard successOk && versionOk else { return }

        state.localSafeProfileActive = false
        state.localStabilityKillSwitchActive = false
        state.safeProfileEnteredAtConfigVersion = nil
        state.successfulStartsWhileDegraded = 0
        Logger.log("protection_stability: exited safe profile after \(minimumSuccessfulStartsToExitSafeProfile) healthy starts and newer config version")
    }

    /// 清零各类失败计数（成功启动或成功回滚后调用）。
    private func resetFailureCountersLocked(_ state: inout StoredEnvelope) {
        state.consecutiveFailuresSameVersion = 0
        state.phaseConsecutiveCrashCounts = [:]
        state.lastFailedConfigVersion = nil
    }

    /// 根据异常归因累计同版本失败、早期阶段失败与分阶段崩溃次数。
    private func applyCountersAfterAbnormalLocked(attr: ProtectionAttributionResult, state: inout StoredEnvelope) {
        let v = attr.remoteConfigVersion
        if let v {
            if state.lastFailedConfigVersion == v {
                state.consecutiveFailuresSameVersion += 1
            } else {
                state.consecutiveFailuresSameVersion = 1
                state.lastFailedConfigVersion = v
            }
        } else {
            state.consecutiveFailuresSameVersion += 1
        }

        // 早期阶段失败单独累计；一旦崩溃发生在后期阶段则清零该计数。
        if attr.phase.isEarlyStartupPhase {
            state.consecutiveEarlyPhaseFailures += 1
        } else {
            state.consecutiveEarlyPhaseFailures = 0
        }

        let key = attr.phase.rawValue
        state.phaseConsecutiveCrashCounts[key] = (state.phaseConsecutiveCrashCounts[key] ?? 0) + 1
    }

    /// 判断上次 session 是否异常终止：有 session、未完成启动且停留阶段不是 completed 才算异常。
    private func detectPreviousAbnormalTerminationLocked(previous: StoredEnvelope) -> ProtectionAttributionResult? {
        guard let sid = previous.sessionId, !previous.startupCompleted else {
            return nil
        }
        guard previous.startupBeganAt > 0 else {
            return nil
        }
        guard previous.phase != .startupCompleted else {
            return nil
        }

        return ProtectionAttributionResult(
            previousSessionId: sid,
            phase: previous.phase,
            remoteConfigVersion: previous.remoteConfigVersion,
            antiDebugModeLabel: previous.antiDebugModeLabel,
            localSafeProfileActive: previous.localSafeProfileActive,
            armorRuntimeSummary: "\(previous.armorRuntimeStatus)/\(previous.armorRuntimeReason)",
            watchdogStartFailed: previous.watchdogStartResult != 0,
            antiDumpStartFailed: previous.antiDumpStartResult != 0,
            lastWatchdogAnomalyFlags: previous.lastWatchdogAnomalyFlags
        )
    }

    // MARK: - 持久化

    /// 加载并校验状态（调用方必须持有 `lock`）。
    /// - HMAC/解密/解码/新鲜度任一失败都会清空持久化数据并返回空状态（fail-closed）。
    private func loadStateLocked() -> StoredEnvelope {
        let anchor = freshnessAnchor.read() ?? .zero
        guard let stored = fileStore.read(key: key) else {
            return Self.emptyState(freshness: anchor)
        }
        // 签名缺失或不匹配：状态不可信，清空后按空状态启动。
        guard let signature = fileStore.read(key: hmacKey),
              StorageIntegrityGuard.verify(stored, signature: signature, purpose: hmacPurpose) else {
            clearPersistedLocked(resetAnchor: false)
            return Self.emptyState(freshness: anchor)
        }
        #if DEBUG
        let data: Data
        // 调试构建允许解密失败时回退明文，便于排查。
        if let decrypted = try? PayloadCrypto.decrypt(stored) {
            data = decrypted
        } else {
            data = stored
        }
        #else
        // Release 构建解密失败即视为数据被破坏，清空缓存。
        guard let data = try? PayloadCrypto.decrypt(stored) else {
            Logger.log("ProtectionStabilityStore: decrypt failed, clearing")
            clearPersistedLocked(resetAnchor: false)
            return Self.emptyState(freshness: anchor)
        }
        #endif

        guard var env = try? JSONDecoder().decode(StoredEnvelope.self, from: data) else {
            clearPersistedLocked(resetAnchor: false)
            return Self.emptyState(freshness: anchor)
        }

        // 文件新鲜度落后于 Keychain 锚点，说明状态被回滚或替换。
        if env.freshness.sequence < anchor.sequence || env.freshness.latestTimestamp < anchor.latestTimestamp {
            Logger.log("ProtectionStabilityStore: freshness rollback detected, resetting")
            clearPersistedLocked(resetAnchor: false)
            return Self.emptyState(freshness: anchor)
        }

        let merged = maxFreshness(anchor, env.freshness)
        if merged.sequence > anchor.sequence || merged.latestTimestamp > anchor.latestTimestamp {
            _ = freshnessAnchor.write(merged)
        }
        env.freshness = merged
        return env
    }

    /// 加密、签名并原子保存状态（调用方必须持有 `lock`）。
    /// - 写入失败会清空持久化数据（fail-closed）。
    private func saveLocked(_ state: StoredEnvelope) {
        var toSave = state
        let anchor = freshnessAnchor.read() ?? .zero
        // 取所有时间字段与锚点的最大值，避免旧 session 拉低新鲜度。
        let maxTs = max(toSave.startupCompletedAt ?? 0, toSave.startupBeganAt, toSave.lastHealthyStartupAt ?? 0, anchor.latestTimestamp)
        toSave.freshness = FreshnessState(
            latestTimestamp: max(maxTs, anchor.latestTimestamp),
            sequence: anchor.sequence + 1
        )

        guard let encoded = try? JSONEncoder().encode(toSave) else {
            Logger.log("ProtectionStabilityStore: encode failed")
            return
        }
        #if DEBUG
        // 调试构建加密失败时允许明文落盘。
        let stored = (try? PayloadCrypto.encrypt(encoded)) ?? encoded
        #else
        // Release 构建必须加密成功，否则放弃本次保存。
        guard let stored = try? PayloadCrypto.encrypt(encoded) else {
            Logger.log("ProtectionStabilityStore: encrypt failed")
            return
        }
        #endif
        let signature = StorageIntegrityGuard.sign(stored, purpose: hmacPurpose)
        let didWritePayload = fileStore.write(key: key, data: stored)
        let didWriteSignature = fileStore.write(key: hmacKey, data: signature)
        // 载荷与签名必须同时成功；否则清空，避免留下不一致状态。
        guard didWritePayload && didWriteSignature else {
            Logger.log("ProtectionStabilityStore: failed to persist state atomically")
            clearPersistedLocked(resetAnchor: false)
            return
        }
        if !freshnessAnchor.write(toSave.freshness) {
            Logger.log("ProtectionStabilityStore: freshness write failed")
        }
    }

    /// 删除载荷与签名；`resetAnchor` 为真时同时删除 Keychain 锚点。
    private func clearPersistedLocked(resetAnchor: Bool) {
        fileStore.remove(key: key)
        fileStore.remove(key: hmacKey)
        if resetAnchor {
            freshnessAnchor.remove()
        }
    }

    /// 取两个新鲜度状态在各字段上的较大值。
    private func maxFreshness(_ lhs: FreshnessState, _ rhs: FreshnessState) -> FreshnessState {
        FreshnessState(
            latestTimestamp: max(lhs.latestTimestamp, rhs.latestTimestamp),
            sequence: max(lhs.sequence, rhs.sequence)
        )
    }

    /// 构造安全的空状态（视为上次启动已完成，不触发回滚）。
    private static func emptyState(freshness: FreshnessState) -> StoredEnvelope {
        StoredEnvelope(
            schemaVersion: 1,
            sessionId: nil,
            phase: .startInvoked,
            startupCompleted: true,
            remoteConfigVersion: nil,
            antiDebugModeLabel: "production",
            localSafeProfileActive: false,
            localStabilityKillSwitchActive: false,
            armorRuntimeStatus: "n/a",
            armorRuntimeReason: "n/a",
            watchdogStartResult: 0,
            antiDumpStartResult: 0,
            lastWatchdogAnomalyFlags: nil,
            startupBeganAt: 0,
            startupCompletedAt: nil,
            phaseConsecutiveCrashCounts: [:],
            consecutiveFailuresSameVersion: 0,
            lastFailedConfigVersion: nil,
            consecutiveEarlyPhaseFailures: 0,
            pinnedRollbackVersion: nil,
            lastHealthyStartupAt: nil,
            successfulStartsWhileDegraded: 0,
            safeProfileEnteredAtConfigVersion: nil,
            lastWatchdogFailed: false,
            lastAntiDumpFailed: false,
            lastSessionIdForAttribution: nil,
            lastAttributedPhase: nil,
            lastAttributedConfigVersion: nil,
            freshness: freshness
        )
    }

    /// 将反调试运行时模式转为稳定的上报标签。
    private static func label(for mode: CPRiskAntiDebugRuntimeMode) -> String {
        switch mode {
        case .production: return "production"
        case .relaxedDevelopmentQA: return "relaxed"
        case .appStoreSafe: return "app_store_safe"
        @unknown default: return "unknown"
        }
    }

    /// 记录异常归因日志，便于线上定位启动崩溃。
    private static func logAttribution(_ attr: ProtectionAttributionResult) {
        let ver = attr.remoteConfigVersion.map { String($0) } ?? "nil"
        Logger.log(
            "protection_stability: ABNORMAL previous session=\(attr.previousSessionId) phase=\(attr.phase.rawValue) " +
            "remoteConfigVersion=\(ver) antiDebug=\(attr.antiDebugModeLabel) armor=\(attr.armorRuntimeSummary) " +
            "watchdogFail=\(attr.watchdogStartFailed) antiDumpFail=\(attr.antiDumpStartFailed)"
        )
    }
}
