// 决策引擎适配层：把 RiskDetectionEngine 适配到 DecisionEngine 协议。
// 负责本地配置覆盖、可选远程策略拉取与远程模型到 EnginePolicy 的转换。
// 输出仅为端侧建议动作，不授予服务端业务权限；远程失败时回落到本地策略。

import Foundation

// MARK: - 决策引擎适配器
///
/// 适配器层，将 RiskDetectionEngine 实现适配到 DecisionEngine 协议。
/// 由于内部已统一命名，适配层主要处理协议实现、阈值覆盖和远程配置。

/// 本地评估适配器；输出建议动作，不授予服务端业务权限。
///
/// 实现 DecisionEngine 协议，内部委托给 RiskDetectionEngine。
public final class LocalAssessmentAdapter: DecisionEngine {

    // MARK: - 属性

    /// 内部委托的决策引擎（持有默认/严格等基础策略）。
    private let engine: RiskDetectionEngine

    /// 配置管理器；仅在 `useRemoteConfig` 为真时用于拉取远程策略。
    private let configManager: AdapterConfigManager?

    // MARK: - 初始化

    /// 创建适配器。
    /// - Parameters:
    ///   - engine: 委托引擎，默认使用默认策略实例；
    ///   - configManager: 远程配置提供者，nil 表示只走本地策略。
    public init(
        engine: RiskDetectionEngine = RiskDetectionEngine(),
        configManager: AdapterConfigManager? = nil
    ) {
        self.engine = engine
        self.configManager = configManager
    }

    // MARK: - DecisionEngine 协议实现

    /// 基于信号快照进行决策。
    /// 若配置允许会先拉取远程策略；随后应用本地阈值覆盖并委托引擎评估。
    /// - Parameters:
    ///   - snapshot: 设备/网络/行为/越狱信号快照；
    ///   - config: 本次评估的本地配置（场景、检测器开关、阈值覆盖等）。
    /// - Returns: 本地判决；远程拉取失败时基于本地策略生成。
    public func assess(
        snapshot: RiskSnapshot,
        config: LocalAssessmentConfig
    ) async -> LocalAssessment {
        let policy = await applyRemoteConfigIfNeeded(config)
        return assessLocally(snapshot: snapshot, config: config, policy: policy)
    }

    /// 旧版入口：保留既有调用方，直接转发到本地评估。
    public func decide(
        snapshot: RiskSnapshot,
        config: DecisionConfig
    ) async -> RiskVerdict {
        await assess(snapshot: snapshot, config: config)
    }

    /// 当前实现支持的信号特征名列表，供调用方做能力探测。
    public var supportedFeatures: [String] {
        // 与检测器实际产出的信号 ID 保持一致，避免调用方请求到不存在的特征。
        [
            "jailbreak_score",
            ObfuscatedConstants.requiredSignalVpnActive,
            "proxy_enabled",
            "device_age_days",
            "touch_spread",
            "touch_interval_cv",
            "swipe_linearity",
            "motion_stillness",
            "touch_motion_correlation"
        ]
    }

    /// 重置引擎状态。
    /// 当前适配器本身无状态，保留钩子以便未来清理引擎内部缓存。
    public func reset() async {
        // 当前实现无状态，但为未来扩展预留
        Logger.log("[LocalAssessmentAdapter] Engine reset")
    }

    // MARK: - 私有辅助方法

    /// 同步/异步/旧版入口共用的本地评估路径。
    /// 同步入口不会拉取远程配置，只应用本地覆盖。
    private func assessLocally(
        snapshot: RiskSnapshot,
        config: LocalAssessmentConfig,
        policy: EnginePolicy
    ) -> LocalAssessment {
        let effectivePolicy = Self.applyingLocalOverrides(config, to: policy)
        let configuredEngine = engine.replacingPolicy(effectivePolicy)
            .selectingDetectorFamilies(config.enabledDetectors)
        return configuredEngine.evaluate(
            context: convertSnapshotToContext(snapshot),
            scenario: config.scenario
        ).retainingLocalExtras(config.extras)
    }

    /// 只替换调用方指定的 high 阈值，其余策略字段保持不变。
    /// 覆盖值必须落在 `medium < high < critical` 内且为有限值，否则整体放弃覆盖。
    static func applyingLocalOverrides(_ config: LocalAssessmentConfig, to policy: EnginePolicy) -> EnginePolicy {
        let base = policy.scenarioPolicy(for: config.scenario)
        // 无效覆盖会被静默忽略，防止调用方传入 NaN/越界值破坏阈值单调性。
        guard let high = config.customThreshold, high.isFinite,
              base.mediumThreshold < high, high < base.criticalThreshold else { return policy }
        var scenarios = policy.scenarioPolicies
        scenarios[config.scenario] = ScenarioPolicy(
            mediumThreshold: base.mediumThreshold,
            highThreshold: high,
            criticalThreshold: base.criticalThreshold,
            actionMapping: base.actionMapping,
            signalWeights: base.signalWeights,
            comboRules: base.comboRules,
            enableForceRules: base.enableForceRules,
            compressedVerdictRules: base.compressedVerdictRules
        )
        return EnginePolicy(
            name: policy.name,
            version: policy.version,
            killSwitchEnabled: policy.killSwitchEnabled,
            enableNetworkSignals: policy.enableNetworkSignals,
            enableBehaviorDetection: policy.enableBehaviorDetection,
            enableDeviceFingerprint: policy.enableDeviceFingerprint,
            forceActionOnJailbreak: policy.forceActionOnJailbreak,
            signalWeightOverrides: policy.signalWeightOverrides,
            mutationStrategy: policy.mutationStrategy,
            blindChallengePolicy: policy.blindChallengePolicy,
            serverBlocklist: policy.serverBlocklist,
            blocklistAction: policy.blocklistAction,
            scenarioPolicies: scenarios
        )
    }

    /// 按需拉取远程配置并转换为引擎策略。
    /// 未启用远程配置、无管理器或拉取失败时均回落到引擎当前策略（fail-safe 到本地）。
    private func applyRemoteConfigIfNeeded(_ config: DecisionConfig) async -> EnginePolicy {
        guard config.useRemoteConfig,
              let manager = configManager else {
            return engine.policy
        }

        // 尝试从远程获取策略配置
        do {
            let remoteConfig = try await manager.getCurrentConfig()
            // 转换远程配置为 EnginePolicy
            return convertRemoteConfig(remoteConfig)
        } catch {
            // 远程失败不应阻断评估：记录后继续使用本地策略。
            Logger.log("[LocalAssessmentAdapter] Failed to fetch remote config: \(error)")
            return engine.policy
        }
    }

    /// 转换 RiskSnapshot 到 RiskContext（只做字段透传，不做裁剪）。
    private func convertSnapshotToContext(_ snapshot: RiskSnapshot) -> RiskContext {
        RiskContext(
            device: snapshot.device,
            deviceID: snapshot.deviceID,
            network: snapshot.network,
            behavior: snapshot.behavior,
            jailbreak: snapshot.jailbreak
        )
    }

    /// 把远程配置模型转换为可直接执行的 EnginePolicy。
    /// 阈值非法时整组回退到 30/55/80，避免远程脏数据放宽或收紧到危险区间。
    private func convertRemoteConfig(_ config: AdapterConfig) -> EnginePolicy {
        // 从远程配置构建策略
        var scenarioPolicies: [RiskScenario: ScenarioPolicy] = [:]

        // 转换各场景策略；未识别的场景键回落到 .default。
        for (scenarioKey, policyData) in config.policy.scenarios {
            let scenario = findRiskScenario(for: scenarioKey)
            let base = ScenarioPolicy.policy(for: scenario)
            // 远程组合规则为空时沿用内置规则，避免远程漏配导致高危组合失效。
            let comboRules: [ComboRule] = config.policy.comboRules.isEmpty
                ? base.comboRules
                : config.policy.comboRules.map { Self.comboRule(from: $0) }
            let m = policyData.thresholds.medium
            let h = policyData.thresholds.high
            let c = policyData.thresholds.critical
            // 强校验：有限、非负、严格递增且不超过 100，缺一不可。
            let validThresholds = m.isFinite && h.isFinite && c.isFinite && (0 <= m && m < h && h < c && c <= 100)
            let policy: ScenarioPolicy
            if validThresholds {
                policy = ScenarioPolicy(
                    mediumThreshold: m,
                    highThreshold: h,
                    criticalThreshold: c,
                    comboRules: comboRules
                )
            } else {
                // 非法阈值使用保守的内置默认值，而不是信任远程输入。
                policy = ScenarioPolicy(
                    mediumThreshold: 30,
                    highThreshold: 55,
                    criticalThreshold: 80,
                    comboRules: comboRules
                )
            }
            scenarioPolicies[scenario] = policy
        }

        return EnginePolicy(
            name: "remote_\(config.version)",
            version: config.version,
            enableNetworkSignals: config.detectors.network?.enabled ?? true,
            enableBehaviorDetection: config.detectors.behavior?.enabled ?? true,
            enableDeviceFingerprint: config.detectors.device?.enabled ?? true,
            scenarioPolicies: scenarioPolicies
        )
    }

    /// 根据远程配置键查找 RiskScenario；兼容 snake_case 与 camelCase。
    private func findRiskScenario(for key: String) -> ProtocolRiskScenario {
        switch key.lowercased() {
        case "login": return .login
        case "payment": return .payment
        case "register": return .register
        case "query": return .query
        case "account_change", "accountchange": return .accountChange
        case "sensitive_action", "sensitiveaction": return .sensitiveAction
        case "api_access", "apiaccess": return .apiAccess
        default: return .default
        }
    }

    /// 将远程 ComboRuleData 转为运行时 ComboRule，并把 forceAction 字符串解析为枚举。
    private static func comboRule(from data: ComboRuleData) -> ComboRule {
        ComboRule(
            name: data.name,
            requiredSignals: data.requiredSignals,
            bonusScore: data.bonusScore,
            forceAction: Self.parseRiskAction(from: data.forceAction),
            description: nil
        )
    }

    /// 解析远程动作字符串；大小写不敏感，未知值返回 nil（由规则自身缺省处理）。
    private static func parseRiskAction(from string: String?) -> RiskAction? {
        guard let s = string?.lowercased() else { return nil }
        switch s {
        case "block": return .block
        case "challenge": return .challenge
        case "stepupauth", "step_up_auth": return .stepUpAuth
        case "allow": return .allow
        default: return nil
        }
    }
}

// MARK: - 配置管理器协议（简化版）
/// 配置管理器协议，用于适配器获取远程配置。
/// 实现方应自行处理缓存、签名校验与失败降级。
public protocol AdapterConfigManager: Sendable {
    /// 获取当前生效的远程配置；失败时抛出错误，由适配器回落本地策略。
    func getCurrentConfig() async throws -> AdapterConfig
}

// MARK: - 远程配置模型（简化）
/// 远程配置结构：版本号、策略与检测器开关。
public struct AdapterConfig: Sendable {
    /// 配置版本，会写入 EnginePolicy.name/version 便于回溯。
    public let version: String
    /// 场景阈值与组合规则。
    public let policy: PolicyConfigData
    /// 各检测器族开关与阈值。
    public let detectors: AdapterDetectorsConfigData

    public init(version: String, policy: PolicyConfigData, detectors: AdapterDetectorsConfigData) {
        self.version = version
        self.policy = policy
        self.detectors = detectors
    }
}

/// 策略配置数据：以场景键索引的阈值表，以及全局组合规则。
public struct PolicyConfigData: Sendable, Codable {
    /// 场景键（login/payment/...）到阈值配置的映射。
    public let scenarios: [String: ScenarioPolicyData]
    /// 全局组合规则；为空时使用内置规则。
    public let comboRules: [ComboRuleData]

    // 单字母键压缩下发体积。
    private enum CodingKeys: String, CodingKey {
        case scenarios = "s"
        case comboRules = "cr"
    }

    public init(scenarios: [String: ScenarioPolicyData], comboRules: [ComboRuleData] = []) {
        self.scenarios = scenarios
        self.comboRules = comboRules
    }
}

/// 单个场景的远程策略数据（当前仅包含阈值）。
public struct ScenarioPolicyData: Sendable, Codable {
    /// 该场景的 medium/high/critical 阈值。
    public let thresholds: ThresholdsData

    private enum CodingKeys: String, CodingKey {
        case thresholds = "th"
    }

    public init(thresholds: ThresholdsData) {
        self.thresholds = thresholds
    }
}

/// 阈值数据：三个分界必须有限且严格递增（0 ≤ medium < high < critical ≤ 100）。
public struct ThresholdsData: Sendable, Codable {
    public let medium: Double
    public let high: Double
    public let critical: Double

    private enum CodingKeys: String, CodingKey {
        case medium = "m"
        case high = "h"
        case critical = "c"
    }

    public init(medium: Double, high: Double, critical: Double) {
        self.medium = medium
        self.high = high
        self.critical = critical
    }
}

/// 组合规则数据：信号 ID 列表 + 加分 + 可选强制动作。
public struct ComboRuleData: Sendable, Codable {
    public let name: String
    /// 必须同时/按规则在场的信号 ID。
    public let requiredSignals: [String]
    /// 命中后追加的分数。
    public let bonusScore: Double
    /// 命中后的强制动作字符串（block/challenge/stepUpAuth/allow），可空。
    public let forceAction: String?

    private enum CodingKeys: String, CodingKey {
        case name = "n"
        case requiredSignals = "rs"
        case bonusScore = "bs"
        case forceAction = "fa"
    }

    public init(name: String, requiredSignals: [String], bonusScore: Double, forceAction: String? = nil) {
        self.name = name
        self.requiredSignals = requiredSignals
        self.bonusScore = bonusScore
        self.forceAction = forceAction
    }
}

/// 检测器族配置数据；nil 表示该族未下发，转换时按启用处理。
public struct AdapterDetectorsConfigData: Sendable, Codable {
    public let jailbreak: AdapterDetectorConfig?
    public let network: AdapterDetectorConfig?
    public let behavior: AdapterDetectorConfig?
    public let device: AdapterDetectorConfig?

    private enum CodingKeys: String, CodingKey {
        case jailbreak = "j"
        case network = "n"
        case behavior = "b"
        case device = "d"
    }

    public init(
        jailbreak: AdapterDetectorConfig? = nil,
        network: AdapterDetectorConfig? = nil,
        behavior: AdapterDetectorConfig? = nil,
        device: AdapterDetectorConfig? = nil
    ) {
        self.jailbreak = jailbreak
        self.network = network
        self.behavior = behavior
        self.device = device
    }
}

/// 单个检测器配置。
public struct AdapterDetectorConfig: Sendable, Codable {
    /// 是否启用该检测器。
    public let enabled: Bool
    /// 可选的检测阈值，nil 表示使用检测器内置默认值。
    public let threshold: Double?

    private enum CodingKeys: String, CodingKey {
        case enabled = "e"
        case threshold = "t"
    }

    public init(enabled: Bool, threshold: Double? = nil) {
        self.enabled = enabled
        self.threshold = threshold
    }
}

// MARK: - 工厂方法
extension LocalAssessmentAdapter {
    /// 创建默认适配器（通用场景策略，不拉取远程配置）。
    public static func `default`() -> LocalAssessmentAdapter {
        LocalAssessmentAdapter(
            engine: RiskDetectionEngine(policy: .default),
            configManager: nil
        )
    }

    /// 创建严格策略适配器（更低的触发阈值）。
    public static func strict() -> LocalAssessmentAdapter {
        LocalAssessmentAdapter(
            engine: RiskDetectionEngine(policy: .strict),
            configManager: nil
        )
    }

    /// 创建金融级适配器（支付等高风险场景使用）。
    public static func financial() -> LocalAssessmentAdapter {
        LocalAssessmentAdapter(
            engine: RiskDetectionEngine(policy: .financial),
            configManager: nil
        )
    }
}

// MARK: - 同步版本（兼容旧 API）
extension LocalAssessmentAdapter {
    /// 同步本地评估：应用本地阈值覆盖，但绝不发起远程配置请求。
    /// 适合主线程/低延迟调用；需要远程策略时请使用异步 `assess`。
    public func decideSync(
        snapshot: RiskSnapshot,
        config: DecisionConfig = DecisionConfig()
    ) -> ProtocolRiskVerdict {
        assessLocally(snapshot: snapshot, config: config, policy: engine.policy)
    }
}

/// 旧源码兼容别名。
public typealias DecisionEngineAdapter = LocalAssessmentAdapter
