// 本地判决模型 LocalAssessment：承载分数、内部/公开等级与动作、置信度、证据信号和压缩摘要。
// 它只是端侧“建议处置”，不构成服务端业务授权；最终决定权归服务端 Decision Service。
// JSON 编码使用单字母键以压缩上报体积，键名属于传输协议，不可随意修改。

import Foundation

// MARK: - 本地判决
/// 端侧风险评估结果，包含本地信号、分数和建议动作。
/// 此结果不是服务端业务授权；最终处置由服务端 Decision Service 决定。
public struct LocalAssessment: Codable, Sendable {

    /// 风险总分，正常范围 0–100；解码时会被夹取，越界值不可信。
    public let score: Double
    /// 内部 4 级风险等级，保留 `critical` 以表达比公开 high 更严重的状态。
    public let internalLevel: InternalRiskLevel

    /// 对外公开的 3 级等级（high 与 critical 合并）。
    public var level: PublicRiskLevel {
        internalLevel.toPublicRiskLevel()
    }

    /// 内部处置动作，可能包含公开协议不存在的 `stepUpAuth`。
    public let internalAction: RiskAction

    /// 对外公开的 3 种动作（challenge 与 stepUpAuth 合并）。
    public var action: PublicRiskAction {
        internalAction.toPublicRiskAction()
    }

    /// 判决置信度，范围 0–1；解码时非法值回退为 0.5。
    public let confidence: Double
    /// 主要风险原因（最多 3 条，格式 `category_id`），用于审计与上报。
    public let primaryReasons: [String]

    /// 原因拼接字符串，便于日志与 UI 直接展示。
    public var reason: String {
        primaryReasons.joined(separator: ", ")
    }

    /// 参与本次判决的完整信号证据。
    public let signals: [RiskSignal]
    /// 本次评估所属业务场景。
    public let scenario: RiskScenario
    /// SignalCompressor 生成的分层压缩摘要，可被 `CompressedVerdictRule` 直接匹配。
    public let compressedDigest: Data?
    /// 生成该摘要/映射所用的版本号，供服务端做兼容性回溯。
    public let mappingVersion: String?
    /// 引擎聚合/底线决策的可观测元数据（供上报与服务端联动；不参与分数计算）。
    public let decisionMetadata: [String: String]?
    /// 判决生成时间，参与 `extras` 与上报排序。
    public let timestamp: Date
    /// 单次评估的请求标识，用于把端侧与服务端日志串起来。
    public let requestId: String

    // 故意不编入 CodingKeys：仅本地配置附加项，不随判决序列化或上报。
    private var localConfigurationExtras: [String: String] = [:]

    /// 生成元数据 + 带命名空间的临时调用方元数据（不会被序列化）。
    /// `dm.` 前缀用于引擎决策元数据，`config.` 前缀用于本地配置附加项，避免键冲突。
    public var extras: [String: String] {
        var base = [
            "requestId": requestId,
            "timestamp": ISO8601DateFormatter().string(from: timestamp)
        ]
        if let decisionMetadata {
            for (k, v) in decisionMetadata {
                base["dm.\(k)"] = v
            }
        }
        for (key, value) in localConfigurationExtras {
            base["config.\(key)"] = value
        }
        return base
    }

    /// 值拷贝后附加本地配置信息，保留请求标识、时间、证据与引擎元数据不变。
    func retainingLocalExtras(_ extras: [String: String]) -> LocalAssessment {
        var result = self
        result.localConfigurationExtras = extras
        return result
    }

    // 单字母键用于压缩上报体积；新增字段需同步服务端解析。
    private enum CodingKeys: String, CodingKey {
        case score = "s"
        case internalLevel = "il"
        case internalAction = "ia"
        case confidence = "c"
        case primaryReasons = "pr"
        case signals = "sg"
        case scenario = "sc"
        case compressedDigest = "cd"
        case mappingVersion = "mv"
        case decisionMetadata = "dm"
        case timestamp = "ts"
        case requestId = "ri"
    }

    // MARK: - 初始化

    /// 完整初始化：由调用方显式给出等级、动作与证据。
    /// 时间戳与 requestId 自动生成；用于已经完成分级/动作映射的链路。
    public init(
        score: Double,
        internalLevel: InternalRiskLevel,
        internalAction: RiskAction,
        confidence: Double,
        primaryReasons: [String],
        signals: [RiskSignal],
        scenario: RiskScenario,
        compressedDigest: Data? = nil,
        mappingVersion: String? = nil,
        decisionMetadata: [String: String]? = nil
    ) {
        self.score = score
        self.internalLevel = internalLevel
        self.internalAction = internalAction
        self.confidence = confidence
        self.primaryReasons = primaryReasons
        self.signals = signals
        self.scenario = scenario
        self.compressedDigest = compressedDigest
        self.mappingVersion = mappingVersion
        self.decisionMetadata = decisionMetadata
        self.timestamp = Date()
        self.requestId = UUID().uuidString
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let rawScore = try container.decode(Double.self, forKey: .score)
        // 外部 JSON 可能被篡改：分数强制夹到 0–100，NaN/无穷按 0 处理。
        score = rawScore.isFinite ? min(max(rawScore, 0), 100) : 0
        internalLevel = try container.decode(InternalRiskLevel.self, forKey: .internalLevel)
        internalAction = try container.decode(RiskAction.self, forKey: .internalAction)
        let rawConfidence = try container.decode(Double.self, forKey: .confidence)
        // 置信度同样做边界清洗；缺失合理值时取 0.5 中性值。
        confidence = rawConfidence.isFinite ? min(max(rawConfidence, 0), 1) : 0.5
        primaryReasons = try container.decodeIfPresent([String].self, forKey: .primaryReasons) ?? []
        signals = try container.decodeIfPresent([RiskSignal].self, forKey: .signals) ?? []
        scenario = try container.decode(RiskScenario.self, forKey: .scenario)
        compressedDigest = try container.decodeIfPresent(Data.self, forKey: .compressedDigest)
        mappingVersion = try container.decodeIfPresent(String.self, forKey: .mappingVersion)
        decisionMetadata = try container.decodeIfPresent([String: String].self, forKey: .decisionMetadata)
        // 旧数据可能没有时间/请求 ID，补默认值保证解码不失败。
        timestamp = try container.decodeIfPresent(Date.self, forKey: .timestamp) ?? Date()
        requestId = try container.decodeIfPresent(String.self, forKey: .requestId) ?? UUID().uuidString
    }

    /// 编码为上报 JSON；`localConfigurationExtras` 不在 CodingKeys 中，因此不会外泄。
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(score, forKey: .score)
        try container.encode(internalLevel, forKey: .internalLevel)
        try container.encode(internalAction, forKey: .internalAction)
        try container.encode(confidence, forKey: .confidence)
        try container.encode(primaryReasons, forKey: .primaryReasons)
        try container.encode(signals, forKey: .signals)
        try container.encode(scenario, forKey: .scenario)
        try container.encodeIfPresent(compressedDigest, forKey: .compressedDigest)
        try container.encodeIfPresent(mappingVersion, forKey: .mappingVersion)
        try container.encodeIfPresent(decisionMetadata, forKey: .decisionMetadata)
        try container.encode(timestamp, forKey: .timestamp)
        try container.encode(requestId, forKey: .requestId)
    }

    /// 便捷初始化：从分数自动推算等级和动作。
    /// 等级与动作完全由 `policy` 决定，保证与场景阈值配置一致。
    public init(
        score: Double,
        confidence: Double,
        signals: [RiskSignal],
        scenario: RiskScenario,
        policy: ScenarioPolicy,
        compressedDigest: Data? = nil,
        mappingVersion: String? = nil
    ) {
        self.score = score
        self.internalLevel = policy.level(for: score)
        self.internalAction = policy.action(for: self.internalLevel)
        self.confidence = confidence
        self.primaryReasons = Self.extractPrimaryReasons(signals: signals, score: score)
        self.signals = signals
        self.scenario = scenario
        self.compressedDigest = compressedDigest
        self.mappingVersion = mappingVersion
        self.decisionMetadata = nil
        self.timestamp = Date()
        self.requestId = UUID().uuidString
    }

    // MARK: - 辅助方法

    /// 提取主要原因
    ///
    /// Sort key 使用 `max(score, weightHint)`，而非单纯的 `.score`。
    /// 状态驱动信号（.tampered/.hard）score=0 而 weightHint 承载实际权重，
    /// 若仅按 score 排序会将这些高危信号排到末尾，导致审计记录与真实原因脱节。
    private static func extractPrimaryReasons(signals: [RiskSignal], score: Double) -> [String] {
        signals
            .sorted { max($0.score, $0.weightHint) > max($1.score, $1.weightHint) }
            .prefix(3)
            .map { "\($0.category)_\($0.id)" }
    }

    /// 是否为高风险及以上（内部4级）
    public var isHighRisk: Bool {
        internalLevel.numericValue >= InternalRiskLevel.high.numericValue
    }

    /// 是否为高风险（公开3级）
    public var isHighRiskPublic: Bool {
        level == .high
    }

    /// 是否应该阻止操作
    public var shouldBlock: Bool {
        internalAction == .block
    }

    /// 是否需要用户交互（挑战或升级认证）
    public var requiresUserInteraction: Bool {
        internalAction == .challenge || internalAction == .stepUpAuth
    }

    /// 是否需要挑战（公开API）
    public var requiresChallenge: Bool {
        action == .challenge
    }

    /// 调试信息
    public var debugDescription: String {
        """
        LocalAssessment {
          score: \(score)
          internalLevel: \(internalLevel.rawValue)
          level: \(level.displayName)
          internalAction: \(internalAction.rawValue)
          action: \(action.displayName)
          confidence: \(confidence)
          reasons: \(reason)
          signalCount: \(signals.count)
          scenario: \(scenario.displayName)
          timestamp: \(ISO8601DateFormatter().string(from: timestamp))
        }
        """
    }
}

// MARK: - 兼容性扩展
/// 旧版 RiskScorer 已废弃（无调用方）；保留本扩展仅为历史兼容。
extension LocalAssessment {
    /// 从 RiskScoreReport 创建 LocalAssessment（向后兼容旧计分链路）。
    /// 等级/动作按场景策略重新映射；置信度由 `RiskContext` 的命中情况估算。
    public static func from(
        report: RiskScoreReport,
        context: RiskContext,
        scenario: RiskScenario = .default
    ) -> LocalAssessment {
        let policy = ScenarioPolicy.policy(for: scenario)
        let level = policy.level(for: report.score)
        let action = policy.action(for: level)

        return LocalAssessment(
            score: report.score,
            internalLevel: level,
            internalAction: action,
            confidence: calculateConfidence(context: context),
            primaryReasons: Array(report.signals.sorted { $0.score > $1.score }.prefix(5).map { "\($0.category)_\($0.id)" }),
            signals: report.signals,
            scenario: scenario,
            compressedDigest: report.compressedDigest,
            mappingVersion: report.mappingVersion
        )
    }

    /// 根据已采集上下文估算置信度：基础 0.5，命中越狱/行为/网络证据则加分。
    private static func calculateConfidence(context: RiskContext) -> Double {
        var confidence = 0.5 // 基础置信度

        // 越狱是强证据，单次命中即显著提升置信度。
        if context.jailbreak.isJailbroken {
            confidence += 0.3
        }

        // 行为样本达到 10 次后才认为统计意义足够。
        let actionCount = context.behavior.actionCount
        if actionCount >= 10 {
            confidence += 0.1
        }

        // VPN/代理说明网络环境可疑，但单独不足以定罪，只小幅加分。
        if context.network.isVPNActive || context.network.proxyEnabled {
            confidence += 0.1
        }

        // 上限 1.0，防止多项证据叠加后越界。
        return min(confidence, 1.0)
    }

    /// 生成摘要文本（兼容旧版）。按公开动作优先，其次保留内部 stepUpAuth 语义。
    public var summary: String {
        if action == .block {
            return "blocked(\(internalLevel.rawValue))"
        } else if action == .challenge {
            return "challenged(\(internalLevel.rawValue))"
        } else if internalAction == .stepUpAuth {
            return "stepup_auth(\(internalLevel.rawValue))"
        } else {
            return "allowed(\(internalLevel.rawValue))"
        }
    }
}

// MARK: - 协议兼容工厂
extension LocalAssessment {
    /// 用公开协议的等级/动作创建 LocalAssessment（供 DecisionEngine 协议调用方使用）。
    /// - Parameters:
    ///   - score: 风险分；- level: 公开 3 级等级；- confidence: 置信度；
    ///   - reason: 逗号分隔的原因文本；- signals: 证据信号；
    ///   - scenario: 业务场景；- action: 公开动作；- extras: 调用方附加信息（当前未写入）。
    /// - Returns: 内部等级/动作已按公开值反向映射的判决。
    public static func protocolCompatible(
        score: Double,
        level: PublicRiskLevel,
        confidence: Double,
        reason: String,
        signals: [RiskSignal],
        scenario: RiskScenario = .default,
        action: PublicRiskAction = .allow,
        extras: [String: String] = [:]
    ) -> LocalAssessment {
        // 公开等级无法表达 critical，反向映射为 high；需要 critical 时请用完整初始化器。
        let internalLevel: InternalRiskLevel
        switch level {
        case .low: internalLevel = .low
        case .medium: internalLevel = .medium
        case .high: internalLevel = .high  // 默认为 high，critical 需要显式创建
        }

        // 公开 challenge 可能是原 challenge 或 stepUpAuth，这里统一映射为 challenge。
        let internalAction: RiskAction
        switch action {
        case .allow: internalAction = .allow
        case .challenge: internalAction = .challenge
        case .block: internalAction = .block
        }

        return LocalAssessment(
            score: score,
            internalLevel: internalLevel,
            internalAction: internalAction,
            confidence: confidence,
            primaryReasons: reason.components(separatedBy: ", "),
            signals: signals,
            scenario: scenario
        )
    }
}

/// 旧源码兼容别名：语义仍是本地判决，而非服务端授权。
public typealias RiskVerdict = LocalAssessment
