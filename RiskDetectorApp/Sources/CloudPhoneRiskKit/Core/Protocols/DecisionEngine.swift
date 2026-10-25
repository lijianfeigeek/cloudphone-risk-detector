// MARK: - 本地判决边界
//
// 职责：定义本地评估引擎、决策引擎与决策模型的协议边界，并给出配置与结果类型。
// 位于评估管线的“本地判决”环节：先由 `assess` 产出本地结论，服务端仅作最终裁决。
// 安全不变量：本地判决仅提供建议动作，不直接授权任何服务端操作（失败即拒绝由服务端兜底）。

import Foundation

/// 在本地评估设备证据。
///
/// 产出的建议动作不构成服务端操作授权，服务端必须独立复核。
public protocol LocalAssessmentEngine: Sendable {
    /// 对快照执行本地评估。
    /// - Parameters:
    ///   - snapshot: 设备、网络、行为与越狱等证据快照。
    ///   - config: 本地评估配置（阈值、启用检测类别等）。
    /// - Returns: 本地判决结果。
    func assess(snapshot: RiskSnapshot, config: LocalAssessmentConfig) async -> LocalAssessment
    /// 当前引擎支持的评估特征标识。
    var supportedFeatures: [String] { get }
    /// 重置引擎内部状态（如时序缓存）。
    func reset() async
}

/// 旧版决策协议。仅实现 `decide` 的既有适配者仍然有效。
public protocol DecisionEngine: LocalAssessmentEngine {
    /// 旧版判决入口，直接返回风险判决。
    /// - Parameters:
    ///   - snapshot: 证据快照。
    ///   - config: 判决配置。
    /// - Returns: 风险判决（分数、等级与处置动作）。
    func decide(snapshot: RiskSnapshot, config: DecisionConfig) async -> RiskVerdict
}

extension DecisionEngine {
    /// 默认桥接实现：把 `decide` 的判决直接作为本地判决返回。
    /// 这样只需实现旧协议的适配者也能满足新的 `LocalAssessmentEngine` 要求。
    public func assess(snapshot: RiskSnapshot, config: LocalAssessmentConfig) async -> LocalAssessment {
        await decide(snapshot: snapshot, config: config)
    }
}

/// 决策模型协议：把特征向量与策略转换为模型结果。
public protocol DecisionModel: Sendable {
    /// 模型唯一标识
    var id: String { get }
    /// 模型版本
    var version: String { get }
    /// 模型支持的输入特征名
    var supportedFeatures: [String] { get }

    /// 基于特征向量与策略执行模型推理。
    /// - Parameters:
    ///   - features: 输入特征向量。
    ///   - policy: 当前生效的策略配置。
    /// - Returns: 模型分数、置信度与解释信息。
    func evaluate(features: FeatureVector, policy: PolicyConfig) async -> ModelResult
    /// 重置模型内部状态。
    func reset() async
}

// MARK: - 配置与支撑类型

/// 判决配置。
public struct DecisionConfig: Sendable, Codable {
    /// 业务场景（登录、支付、注册、查询等）
    public var scenario: RiskScenario
    /// 是否启用远程配置
    public var useRemoteConfig: Bool
    /// 只覆盖所选场景的高风险阈值，且在远程策略解析完成后生效。
    /// 非有限值或不在 `(mediumThreshold, criticalThreshold)` 区间内的值会被忽略。
    public var customThreshold: Double?
    /// 选择六个内置信号类别，而非自定义提供者的注册名。
    /// 为空表示使用默认值（构造/解码后同样归一为默认）。
    /// 未知类别会保留；选择在融合前生效，强制完整性检查/篡改证据仍然有效。
    public var enabledDetectors: Set<String>
    /// 仅本地可见的元数据，以 `config.<key>` 暴露在评估结果的 extras 视图中。
    /// 它从不参与打分，也不会进入评估结果的 Codable/上报传输。
    public var extras: [String: String]

    /// JSON 编码键：使用短键名压缩配置体积。
    private enum CodingKeys: String, CodingKey {
        case scenario = "sc"
        case useRemoteConfig = "ur"
        case customThreshold = "ct"
        case enabledDetectors = "ed"
        case extras = "ex"
    }

    /// 创建判决配置。
    /// - Parameters:
    ///   - scenario: 业务场景，默认 `.default`。
    ///   - useRemoteConfig: 是否使用远程配置，默认 `true`。
    ///   - customThreshold: 场景高风险阈值覆盖值，默认 `nil`。
    ///   - enabledDetectors: 启用的信号类别；为空时归一为默认六类。
    ///   - extras: 本地元数据，默认空。
    public init(
        scenario: RiskScenario = .default,
        useRemoteConfig: Bool = true,
        customThreshold: Double? = nil,
        enabledDetectors: Set<String> = [],
        extras: [String: String] = [:]
    ) {
        self.scenario = scenario
        self.useRemoteConfig = useRemoteConfig
        self.customThreshold = customThreshold
        // 空集合归一为默认六类，保证省略配置时不会意外关闭全部检测
        self.enabledDetectors = enabledDetectors.isEmpty ? Self.defaultDetectors : enabledDetectors
        self.extras = extras
    }

    /// 默认启用的六个内置信号类别
    static var defaultDetectors: Set<String> { [
        ObfuscatedConstants.signalJailbreak,
        ObfuscatedConstants.categoryAntiTamper,
        "behavior",
        "network",
        "device",
        "environment"
    ] }
}

/// 特征向量：数值特征与字符串元数据。
public struct FeatureVector: Sendable, Codable {
    /// 特征名到数值的映射
    public var values: [String: Double]
    /// 特征名到元数据（如来源、版本）的映射
    public var metadata: [String: String]

    /// JSON 编码键：短键名
    private enum CodingKeys: String, CodingKey {
        case values = "v"
        case metadata = "m"
    }

    /// 创建特征向量。
    public init(values: [String: Double] = [:], metadata: [String: String] = [:]) {
        self.values = values
        self.metadata = metadata
    }

    /// 按特征名读写数值特征。
    public subscript(_ key: String) -> Double? {
        get { values[key] }
        set { values[key] = newValue }
    }
}

/// 模型推理结果。
public struct ModelResult: Sendable, Codable {
    /// 模型输出分数（0–100 语义由具体模型约定）
    public var score: Double
    /// 置信度（通常 0–1）
    public var confidence: Double
    /// 可解释性信息（特征贡献、命中规则等）
    public var explanation: [String: String]

    /// JSON 编码键：短键名
    private enum CodingKeys: String, CodingKey {
        case score = "s"
        case confidence = "c"
        case explanation = "e"
    }

    /// 创建模型结果。
    public init(score: Double, confidence: Double, explanation: [String: String] = [:]) {
        self.score = score
        self.confidence = confidence
        self.explanation = explanation
    }
}

// MARK: - 兼容性别名

/// 本地配置沿用旧版 Codable 表示与初始化器。
public typealias LocalAssessmentConfig = DecisionConfig
public typealias ProtocolRiskScenario = RiskScenario
public typealias ProtocolRiskLevel = PublicRiskLevel
public typealias ProtocolRiskAction = PublicRiskAction
public typealias ProtocolRiskVerdict = RiskVerdict
