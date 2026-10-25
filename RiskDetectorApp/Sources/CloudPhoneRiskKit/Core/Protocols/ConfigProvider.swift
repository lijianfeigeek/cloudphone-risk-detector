// MARK: - 配置提供者协议与远程配置模型
//
// 职责：定义配置的读取/更新协议，以及远程下发的检测器、策略、场景与规则模型。
// 位于评估管线的配置解析阶段：评估前由提供者拉取/缓存配置，供决策引擎构建策略。
// 安全不变量：配置带签名与有效期；过期或签名非法的配置不得用于降低本地安全基线。

import Foundation

// MARK: - 配置提供者

/// 远程配置提供者：负责拉取、缓存与清除配置。
public protocol ConfigProvider: Sendable {
    /// 从远端拉取最新配置。
    /// - Returns: 解析并校验后的配置。
    /// - Throws: 网络错误、HTTP 错误、签名非法或解析失败时抛出；调用方应保留旧缓存（失败即拒绝）。
    func fetchConfig() async throws -> ProviderConfig
    /// 返回本地缓存的配置。
    /// - Returns: 缓存配置；无缓存时返回 `nil`。
    func getCachedConfig() -> ProviderConfig?
    /// 清除本地缓存；
    func clearCache()
}

/// 配置读取视图：评估管线只依赖该协议获取已解析的策略。
public protocol ConfigReading: Sendable {
    /// 获取指定场景的判决配置。
    /// - Parameter scenario: 业务场景。
    /// - Returns: 判决配置；配置缺失时由实现决定回退到默认值。
    func getDecisionConfig(for scenario: ProtocolRiskScenario) async -> DecisionConfig
    /// 获取指定场景的策略配置。
    /// - Parameter scenario: 业务场景。
    /// - Returns: 策略配置。
    func getPolicy(for scenario: ProtocolRiskScenario) async -> PolicyConfig
    /// 获取指定检测器的配置。
    /// - Parameter detectorId: 检测器标识。
    /// - Returns: 检测器配置；未知标识返回 `nil`。
    func getProviderDetectorConfig(for detectorId: String) -> PDC?
    /// 判断检测器是否启用。
    /// - Parameter detectorId: 检测器标识。
    /// - Returns: 启用返回 `true`；未知检测器默认返回 `false`。
    func isDetectorEnabled(_ detectorId: String) -> Bool
}

/// 配置更新视图：供管理端或本地调试写入配置。
public protocol ConfigUpdating: Sendable {
    /// 更新整份配置。
    /// - Parameter config: 新配置。
    /// - Throws: 持久化或校验失败时抛出。
    func updateConfig(_ config: ProviderConfig) async throws
    /// 更新指定场景的策略。
    func updatePolicy(for scenario: ProtocolRiskScenario, policy: PolicyConfig) async
    /// 启用/禁用指定检测器。
    func setDetectorEnabled(_ detectorId: String, enabled: Bool) async
}

/// 远程下发的整份配置。
public struct ProviderConfig: Sendable, Codable {
    /// 配置版本号（单调递增，用于拒绝回滚）
    public var version: String
    /// 生效时间
    public var effectiveTime: Date
    /// 过期时间
    public var expireTime: Date
    /// 各检测器配置
    public var detectors: ProviderDetectorConfigs
    /// 策略配置
    public var policies: PolicyConfigs
    /// 场景配置
    public var scenarios: ScenarioConfigs
    /// 配置签名（用于校验来源与完整性）
    public var signature: String

    /// JSON 编码键：短键名压缩传输体积。
    private enum CodingKeys: String, CodingKey {
        case version = "v"
        case effectiveTime = "et"
        case expireTime = "xt"
        case detectors = "dt"
        case policies = "pl"
        case scenarios = "sc"
        case signature = "sg"
    }

    /// 创建配置。
    public init(
        version: String,
        effectiveTime: Date,
        expireTime: Date,
        detectors: ProviderDetectorConfigs,
        policies: PolicyConfigs,
        scenarios: ScenarioConfigs,
        signature: String
    ) {
        self.version = version
        self.effectiveTime = effectiveTime
        self.expireTime = expireTime
        self.detectors = detectors
        self.policies = policies
        self.scenarios = scenarios
        self.signature = signature
    }

    /// 配置是否已过期（当前时间晚于 `expireTime`）
    public var isExpired: Bool { Date() > expireTime }
    /// 配置是否处于有效期内（已生效且未过期）
    public var isEffective: Bool { Date() >= effectiveTime && !isExpired }
}

/// 检测器配置的统一协议（PDC：Provider Detector Config）。
public protocol PDC: Sendable, Codable {
    /// 检测器标识
    var detectorId: String { get }
    /// 是否启用该检测器
    var isEnabled: Bool { get set }
}

/// 各检测器配置的聚合容器。
public struct ProviderDetectorConfigs: Sendable, Codable {
    /// 越狱检测配置
    public var jailbreak: JailbreakProviderDetectorConfig
    /// 反篡改检测配置
    public var antiTamper: AntiTamperProviderDetectorConfig
    /// 行为检测配置
    public var behavior: BehaviorProviderDetectorConfig
    /// 网络检测配置
    public var network: NetworkProviderDetectorConfig
    /// 设备检测配置
    public var device: DeviceProviderDetectorConfig
    /// 环境检测配置
    public var environment: EnvironmentProviderDetectorConfig

    /// JSON 编码键：短键名。
    private enum CodingKeys: String, CodingKey {
        case jailbreak = "j"
        case antiTamper = "at"
        case behavior = "b"
        case network = "n"
        case device = "d"
        case environment = "ev"
    }

    /// 创建检测器配置集合，各字段默认使用各自的安全默认值。
    public init(
        jailbreak: JailbreakProviderDetectorConfig = .default,
        antiTamper: AntiTamperProviderDetectorConfig = .default,
        behavior: BehaviorProviderDetectorConfig = .default,
        network: NetworkProviderDetectorConfig = .default,
        device: DeviceProviderDetectorConfig = .default,
        environment: EnvironmentProviderDetectorConfig = .default
    ) {
        self.jailbreak = jailbreak
        self.antiTamper = antiTamper
        self.behavior = behavior
        self.network = network
        self.device = device
        self.environment = environment
    }

    /// 按检测器标识查找配置。
    /// - Parameter detectorId: 检测器标识（支持混淆常量与内置类别名）。
    /// - Returns: 对应配置；未知标识返回 `nil`。
    public subscript(_ detectorId: String) -> PDC? {
        switch detectorId {
        case ObfuscatedConstants.keywordJailbreak: return jailbreak
        case ObfuscatedConstants.categoryAntiTamper: return antiTamper
        case "behavior": return behavior
        case "network": return network
        case "device": return device
        case "environment": return environment
        default: return nil
        }
    }
}

/// 越狱检测器配置。
public struct JailbreakProviderDetectorConfig: PDC {
    /// 检测器标识（固定为越狱类别）
    public let detectorId = ObfuscatedConstants.keywordJailbreak
    /// 是否启用越狱检测
    public var isEnabled: Bool
    /// 越狱判定阈值（0–100，分数达到即判定为越狱）
    public var threshold: Double
    /// 是否启用文件系统检测
    public var enableFileDetect: Bool
    /// 是否启用 dyld 镜像检测
    public var enableDyldDetect: Bool
    /// 是否启用环境变量检测
    public var enableEnvDetect: Bool
    /// 是否启用 sysctl 检测
    public var enableSysctlDetect: Bool
    /// 是否启用 URL Scheme 检测
    public var enableSchemeDetect: Bool
    /// 是否启用 Hook 检测
    public var enableHookDetect: Bool

    /// JSON 编码键：短键名。
    private enum CodingKeys: String, CodingKey {
        case detectorId = "di"
        case isEnabled = "ie"
        case threshold = "t"
        case enableFileDetect = "ef"
        case enableDyldDetect = "ed"
        case enableEnvDetect = "ee"
        case enableSysctlDetect = "es"
        case enableSchemeDetect = "esc"
        case enableHookDetect = "eh"
    }

    /// 创建越狱检测配置；默认开启全部子检测，阈值 50。
    public init(
        isEnabled: Bool = true,
        threshold: Double = 50,
        enableFileDetect: Bool = true,
        enableDyldDetect: Bool = true,
        enableEnvDetect: Bool = true,
        enableSysctlDetect: Bool = true,
        enableSchemeDetect: Bool = true,
        enableHookDetect: Bool = true
    ) {
        self.isEnabled = isEnabled
        self.threshold = threshold
        self.enableFileDetect = enableFileDetect
        self.enableDyldDetect = enableDyldDetect
        self.enableEnvDetect = enableEnvDetect
        self.enableSysctlDetect = enableSysctlDetect
        self.enableSchemeDetect = enableSchemeDetect
        self.enableHookDetect = enableHookDetect
    }

    /// 默认配置（全量子检测开启）
    public static let `default` = Self()
    /// 轻量配置：提高阈值并关闭 Hook 检测，降低误报与开销
    public static let light = Self(threshold: 70, enableHookDetect: false)
    /// 全量配置（当前与默认一致，保留语义化命名）
    public static let full = Self()
}

/// 反篡改检测器配置。
public struct AntiTamperProviderDetectorConfig: PDC {
    /// 检测器标识（固定为反篡改类别）
    public let detectorId = ObfuscatedConstants.categoryAntiTamper
    /// 是否启用反篡改检测
    public var isEnabled: Bool
    /// 反篡改判定阈值（0–100）
    public var threshold: Double
    /// 是否启用代码完整性检查
    public var enableCodeIntegrityCheck: Bool
    /// 是否启用动态库注入检查
    public var enableDylibInjectionCheck: Bool
    /// 是否启用调试器检查
    public var enableDebuggerCheck: Bool
    /// 是否启用 Frida 检查
    public var enableFridaCheck: Bool
    /// 是否启用模拟器检查
    public var enableEmulatorCheck: Bool

    /// JSON 编码键：短键名。
    private enum CodingKeys: String, CodingKey {
        case detectorId = "di"
        case isEnabled = "ie"
        case threshold = "t"
        case enableCodeIntegrityCheck = "ec"
        case enableDylibInjectionCheck = "edl"
        case enableDebuggerCheck = "edb"
        case enableFridaCheck = "efr"
        case enableEmulatorCheck = "eem"
    }

    /// 创建反篡改配置；默认开启全部子检查，阈值 50。
    public init(
        isEnabled: Bool = true,
        threshold: Double = 50,
        enableCodeIntegrityCheck: Bool = true,
        enableDylibInjectionCheck: Bool = true,
        enableDebuggerCheck: Bool = true,
        enableFridaCheck: Bool = true,
        enableEmulatorCheck: Bool = true
    ) {
        self.isEnabled = isEnabled
        self.threshold = threshold
        self.enableCodeIntegrityCheck = enableCodeIntegrityCheck
        self.enableDylibInjectionCheck = enableDylibInjectionCheck
        self.enableDebuggerCheck = enableDebuggerCheck
        self.enableFridaCheck = enableFridaCheck
        self.enableEmulatorCheck = enableEmulatorCheck
    }

    /// 默认配置
    public static let `default` = Self()
}

/// 行为检测器配置。
public struct BehaviorProviderDetectorConfig: PDC {
    /// 检测器标识
    public let detectorId = "behavior"
    /// 是否启用行为检测
    public var isEnabled: Bool
    /// 触摸采样时长（秒）
    public var touchSamplingDuration: TimeInterval
    /// 运动采样时长（秒）
    public var motionSamplingDuration: TimeInterval
    /// 判定所需的最小触摸次数
    public var minTouchCount: Int
    /// 触摸分布低阈值
    public var touchSpreadLowThreshold: Double
    /// 触摸分布高阈值
    public var touchSpreadHighThreshold: Double
    /// 触摸间隔变异系数低阈值
    public var touchIntervalCVLowThreshold: Double
    /// 触摸间隔变异系数高阈值
    public var touchIntervalCVHighThreshold: Double

    /// JSON 编码键：短键名。
    private enum CodingKeys: String, CodingKey {
        case detectorId = "di"
        case isEnabled = "ie"
        case touchSamplingDuration = "td"
        case motionSamplingDuration = "md"
        case minTouchCount = "mt"
        case touchSpreadLowThreshold = "sl"
        case touchSpreadHighThreshold = "sh"
        case touchIntervalCVLowThreshold = "cl"
        case touchIntervalCVHighThreshold = "ch"
    }

    /// 创建行为检测配置；默认采样 30 秒、最少 6 次触摸。
    public init(
        isEnabled: Bool = true,
        touchSamplingDuration: TimeInterval = 30,
        motionSamplingDuration: TimeInterval = 30,
        minTouchCount: Int = 6,
        touchSpreadLowThreshold: Double = 2.0,
        touchSpreadHighThreshold: Double = 10.0,
        touchIntervalCVLowThreshold: Double = 0.2,
        touchIntervalCVHighThreshold: Double = 0.6
    ) {
        self.isEnabled = isEnabled
        self.touchSamplingDuration = touchSamplingDuration
        self.motionSamplingDuration = motionSamplingDuration
        self.minTouchCount = minTouchCount
        self.touchSpreadLowThreshold = touchSpreadLowThreshold
        self.touchSpreadHighThreshold = touchSpreadHighThreshold
        self.touchIntervalCVLowThreshold = touchIntervalCVLowThreshold
        self.touchIntervalCVHighThreshold = touchIntervalCVHighThreshold
    }

    /// 默认配置
    public static let `default` = Self()
}

/// 网络检测器配置。
public struct NetworkProviderDetectorConfig: PDC {
    /// 检测器标识
    public let detectorId = "network"
    /// 是否启用网络检测
    public var isEnabled: Bool
    /// 是否检测 VPN
    public var detectVPN: Bool
    /// 是否检测代理
    public var detectProxy: Bool
    /// VPN 命中的风险分
    public var vpnRiskScore: Double
    /// 代理命中的风险分
    public var proxyRiskScore: Double

    /// JSON 编码键：短键名。
    private enum CodingKeys: String, CodingKey {
        case detectorId = "di"
        case isEnabled = "ie"
        case detectVPN = "dv"
        case detectProxy = "dp"
        case vpnRiskScore = "vr"
        case proxyRiskScore = "pr"
    }

    /// 创建网络检测配置；VPN/代理风险分默认分别为 10/8。
    public init(
        isEnabled: Bool = true,
        detectVPN: Bool = true,
        detectProxy: Bool = true,
        vpnRiskScore: Double = 10,
        proxyRiskScore: Double = 8
    ) {
        self.isEnabled = isEnabled
        self.detectVPN = detectVPN
        self.detectProxy = detectProxy
        self.vpnRiskScore = vpnRiskScore
        self.proxyRiskScore = proxyRiskScore
    }

    /// 默认配置
    public static let `default` = Self()
}

/// 设备检测器配置。
public struct DeviceProviderDetectorConfig: PDC {
    /// 检测器标识
    public let detectorId = "device"
    /// 是否启用设备检测
    public var isEnabled: Bool
    /// 是否检测模拟器
    public var detectSimulator: Bool
    /// 旧设备家族判定阈值（代际编号）
    public var oldDeviceFamilyThreshold: Int
    /// 模拟器命中的风险分
    public var simulatorRiskScore: Double

    /// JSON 编码键：短键名。
    private enum CodingKeys: String, CodingKey {
        case detectorId = "di"
        case isEnabled = "ie"
        case detectSimulator = "ds"
        case oldDeviceFamilyThreshold = "of"
        case simulatorRiskScore = "sr"
    }

    /// 创建设备检测配置；旧设备代际阈值默认 11。
    public init(
        isEnabled: Bool = true,
        detectSimulator: Bool = true,
        oldDeviceFamilyThreshold: Int = 11,
        simulatorRiskScore: Double = 0
    ) {
        self.isEnabled = isEnabled
        self.detectSimulator = detectSimulator
        self.oldDeviceFamilyThreshold = oldDeviceFamilyThreshold
        self.simulatorRiskScore = simulatorRiskScore
    }

    /// 默认配置
    public static let `default` = Self()
}

/// 环境检测器配置。
public struct EnvironmentProviderDetectorConfig: PDC {
    /// 检测器标识
    public let detectorId = "environment"
    /// 是否启用环境检测
    public var isEnabled: Bool
    /// 是否检测代理环境
    public var detectProxy: Bool
    /// 是否检测越狱环境
    public var detectJailbreakEnv: Bool

    /// JSON 编码键：短键名。
    private enum CodingKeys: String, CodingKey {
        case detectorId = "di"
        case isEnabled = "ie"
        case detectProxy = "dp"
        case detectJailbreakEnv = "dj"
    }

    /// 创建环境检测配置。
    public init(
        isEnabled: Bool = true,
        detectProxy: Bool = true,
        detectJailbreakEnv: Bool = true
    ) {
        self.isEnabled = isEnabled
        self.detectProxy = detectProxy
        self.detectJailbreakEnv = detectJailbreakEnv
    }

    /// 默认配置
    public static let `default` = Self()
}

/// 策略配置集合：阈值、权重与规则。
public struct PolicyConfigs: Sendable, Codable {
    /// 分数阈值配置
    public var thresholds: ThresholdConfig
    /// 类别权重配置
    public var weights: WeightConfig
    /// 自定义规则列表
    public var rules: [RuleConfig]

    /// JSON 编码键：短键名。
    private enum CodingKeys: String, CodingKey {
        case thresholds = "th"
        case weights = "w"
        case rules = "r"
    }

    /// 创建策略配置。
    public init(thresholds: ThresholdConfig = .default, weights: WeightConfig = .default, rules: [RuleConfig] = []) {
        self.thresholds = thresholds
        self.weights = weights
        self.rules = rules
    }
}

/// 风险等级分数阈值。
public struct ThresholdConfig: Sendable, Codable {
    /// 低风险下限
    public var lowRisk: Double
    /// 中风险下限
    public var mediumRisk: Double
    /// 高风险下限
    public var highRisk: Double

    /// JSON 编码键：短键名。
    private enum CodingKeys: String, CodingKey {
        case lowRisk = "lr"
        case mediumRisk = "mr"
        case highRisk = "hr"
    }

    /// 创建阈值配置；默认 40/60/80。
    public init(lowRisk: Double = 40, mediumRisk: Double = 60, highRisk: Double = 80) {
        self.lowRisk = lowRisk
        self.mediumRisk = mediumRisk
        self.highRisk = highRisk
    }

    /// 默认阈值
    public static let `default` = Self()

    /// 按分数映射风险等级（从高到低比较）。
    /// - Parameter score: 风险分数。
    /// - Returns: 高风险 / 中风险 / 低风险。
    public func getLevel(for score: Double) -> ProtocolRiskLevel {
        if score >= highRisk { return .high }
        if score >= mediumRisk { return .medium }
        return .low
    }
}

/// 各类别信号权重。
public struct WeightConfig: Sendable, Codable {
    /// 越狱类别权重
    public var jailbreak: Double
    /// 反篡改类别权重
    public var antiTamper: Double
    /// 行为类别权重
    public var behavior: Double
    /// 网络类别权重
    public var network: Double
    /// 设备类别权重
    public var device: Double
    /// 环境类别权重
    public var environment: Double

    /// JSON 编码键：短键名。
    private enum CodingKeys: String, CodingKey {
        case jailbreak = "j"
        case antiTamper = "at"
        case behavior = "b"
        case network = "n"
        case device = "d"
        case environment = "ev"
    }

    /// 创建权重配置；默认越狱/反篡改权重最高。
    public init(
        jailbreak: Double = 0.6,
        antiTamper: Double = 0.5,
        behavior: Double = 0.3,
        network: Double = 0.1,
        device: Double = 0.1,
        environment: Double = 0.1
    ) {
        self.jailbreak = jailbreak
        self.antiTamper = antiTamper
        self.behavior = behavior
        self.network = network
        self.device = device
        self.environment = environment
    }

    /// 默认权重
    public static let `default` = Self()

    /// 按检测器标识读取权重；未知标识回退到 0.1。
    public subscript(_ detectorId: String) -> Double {
        switch detectorId {
        case ObfuscatedConstants.keywordJailbreak: return jailbreak
        case ObfuscatedConstants.categoryAntiTamper: return antiTamper
        case "behavior": return behavior
        case "network": return network
        case "device": return device
        case "environment": return environment
        default: return 0.1
        }
    }
}

/// 单条自定义规则。
public struct RuleConfig: Sendable, Codable, Identifiable {
    /// 规则唯一标识
    public var id: String
    /// 规则名称
    public var name: String
    /// 规则描述
    public var description: String
    /// 条件表达式
    public var condition: RuleCondition
    /// 命中后的处置动作
    public var action: RuleAction
    /// 优先级（数值越大越优先）
    public var priority: Int

    /// JSON 编码键：短键名。
    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case name = "n"
        case description = "ds"
        case condition = "cn"
        case action = "ac"
        case priority = "pr"
    }

    /// 创建规则。
    public init(
        id: String,
        name: String,
        description: String = "",
        condition: RuleCondition,
        action: RuleAction,
        priority: Int = 0
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.condition = condition
        self.action = action
        self.priority = priority
    }
}

/// 规则条件表达式（支持逻辑组合）。
public indirect enum RuleCondition: Sendable, Codable {
    /// 恒真
    case always
    /// 恒假
    case never
    /// 信号值等于指定字符串
    case signalEquals(signal: String, value: String)
    /// 信号数值大于阈值
    case signalGreaterThan(signal: String, value: Double)
    /// 信号数值小于阈值
    case signalLessThan(signal: String, value: Double)
    /// 信号数值落在闭区间内
    case signalInRange(signal: String, min: Double, max: Double)
    /// 所有子条件同时成立
    case and([RuleCondition])
    /// 任一子条件成立
    case or([RuleCondition])
    /// 子条件取反
    case not(RuleCondition)
}

/// 规则命中后的处置动作。
public enum RuleAction: Sendable, Codable {
    /// 直接设置风险分数
    case setScore(score: Double)
    /// 设置风险等级
    case setProtocolRiskLevel(level: ProtocolRiskLevel)
    /// 阻断
    case block
    /// 放行
    case allow
    /// 二次验证
    case challenge
}

/// 各业务场景的配置集合。
public struct ScenarioConfigs: Sendable, Codable {
    /// 登录场景配置
    public var login: ScenarioConfig
    /// 支付场景配置
    public var payment: ScenarioConfig
    /// 注册场景配置
    public var register: ScenarioConfig
    /// 查询场景配置
    public var query: ScenarioConfig
    /// 默认场景配置
    public var `default`: ScenarioConfig

    /// JSON 编码键：短键名。
    private enum CodingKeys: String, CodingKey {
        case login = "l"
        case payment = "p"
        case register = "r"
        case query = "q"
        case `default` = "df"
    }

    /// 创建场景配置集合，默认使用各场景的预设。
    public init(
        login: ScenarioConfig = .login,
        payment: ScenarioConfig = .payment,
        register: ScenarioConfig = .register,
        query: ScenarioConfig = .query,
        default: ScenarioConfig = .default
    ) {
        self.login = login
        self.payment = payment
        self.register = register
        self.query = query
        self.`default` = `default`
    }

    /// 按场景枚举读取配置；未知场景回退到默认场景。
    public subscript(_ scenario: ProtocolRiskScenario) -> ScenarioConfig {
        switch scenario {
        case .login: return login
        case .payment: return payment
        case .register: return register
        case .query: return query
        default: return `default`
        }
    }
}

/// 单个业务场景的配置。
public struct ScenarioConfig: Sendable, Codable {
    /// 是否启用该场景
    public var enabled: Bool
    /// 场景风险阈值（0–100）
    public var threshold: Double
    /// 启用的检测器标识列表
    public var enabledDetectors: [String]
    /// 场景自定义权重（可选，覆盖全局权重）
    public var customWeights: WeightConfig?
    /// 中风险时的处置动作
    public var mediumProtocolRiskAction: ProtocolRiskAction
    /// 高风险时的处置动作
    public var highProtocolRiskAction: ProtocolRiskAction

    /// JSON 编码键：短键名。
    private enum CodingKeys: String, CodingKey {
        case enabled = "e"
        case threshold = "t"
        case enabledDetectors = "ed"
        case customWeights = "cw"
        case mediumProtocolRiskAction = "ma"
        case highProtocolRiskAction = "ha"
    }

    /// 创建场景配置；`enabledDetectors` 为空时使用默认五类。
    public init(
        enabled: Bool = true,
        threshold: Double = 60,
        enabledDetectors: [String] = [],
        customWeights: WeightConfig? = nil,
        mediumProtocolRiskAction: ProtocolRiskAction = .challenge,
        highProtocolRiskAction: ProtocolRiskAction = .block
    ) {
        self.enabled = enabled
        self.threshold = threshold
        // 空列表归一为默认检测器，避免场景配置漏填导致“无检测”
        self.enabledDetectors = enabledDetectors.isEmpty ? Self.defaultDetectors : enabledDetectors
        self.customWeights = customWeights
        self.mediumProtocolRiskAction = mediumProtocolRiskAction
        self.highProtocolRiskAction = highProtocolRiskAction
    }

    /// 场景默认启用的检测器（不含 environment）
    private static let defaultDetectors: [String] = [
        ObfuscatedConstants.keywordJailbreak,
        ObfuscatedConstants.categoryAntiTamper,
        "behavior",
        "network",
        "device",
    ]

    /// 登录场景：阈值 60，中风险验证、高风险阻断
    public static let login = ScenarioConfig(threshold: 60, mediumProtocolRiskAction: .challenge, highProtocolRiskAction: .block)
    /// 支付场景：阈值更低（50），中风险即验证、高风险阻断
    public static let payment = ScenarioConfig(threshold: 50, mediumProtocolRiskAction: .challenge, highProtocolRiskAction: .block)
    /// 注册场景：阈值 70，中风险放行、高风险验证
    public static let register = ScenarioConfig(threshold: 70, mediumProtocolRiskAction: .allow, highProtocolRiskAction: .challenge)
    /// 查询场景：阈值 80，中/高风险均放行（低敏感业务）
    public static let query = ScenarioConfig(threshold: 80, mediumProtocolRiskAction: .allow, highProtocolRiskAction: .allow)
    /// 默认场景：阈值 60
    public static let `default` = ScenarioConfig(threshold: 60)
}

/// 解析后的策略配置（供决策引擎直接使用）。
public struct PolicyConfig: Sendable, Codable {
    /// 风险阈值（0–100）
    public var threshold: Double
    /// 中风险处置动作
    public var mediumProtocolRiskAction: ProtocolRiskAction
    /// 高风险处置动作
    public var highProtocolRiskAction: ProtocolRiskAction
    /// 启用的检测器集合
    public var enabledDetectors: Set<String>
    /// 自定义权重（按检测器标识）
    public var customWeights: [String: Double]?

    /// JSON 编码键：短键名。
    private enum CodingKeys: String, CodingKey {
        case threshold = "t"
        case mediumProtocolRiskAction = "ma"
        case highProtocolRiskAction = "ha"
        case enabledDetectors = "ed"
        case customWeights = "cw"
    }

    /// 创建策略配置；`enabledDetectors` 为空时使用默认五类。
    public init(
        threshold: Double,
        mediumProtocolRiskAction: ProtocolRiskAction = .challenge,
        highProtocolRiskAction: ProtocolRiskAction = .block,
        enabledDetectors: Set<String> = [],
        customWeights: [String: Double]? = nil
    ) {
        self.threshold = threshold
        self.mediumProtocolRiskAction = mediumProtocolRiskAction
        self.highProtocolRiskAction = highProtocolRiskAction
        // 空集合归一为默认检测器，保证安全基线不被空配置绕过
        self.enabledDetectors = enabledDetectors.isEmpty
            ? [ObfuscatedConstants.keywordJailbreak, ObfuscatedConstants.categoryAntiTamper, "behavior", "network", "device"]
            : enabledDetectors
        self.customWeights = customWeights
    }
}

/// 配置拉取/解析错误。
public enum ProviderConfigError: Error, Sendable {
    /// 网络请求失败（底层错误）
    case networkError(Error)
    /// 响应格式非法
    case invalidResponse
    /// HTTP 状态码错误
    case httpError(Int)
    /// 签名校验失败
    case invalidSignature
    /// 配置已过期
    case expiredConfig
    /// JSON 解码失败
    case decodeError(Error)
    /// 不支持的配置版本
    case unsupportedVersion(String)
}
