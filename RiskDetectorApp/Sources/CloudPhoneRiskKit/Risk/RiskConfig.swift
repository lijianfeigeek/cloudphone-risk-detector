// 风险配置模型：定义本地阈值、越狱检测开关，以及 Swift 值类型 `RiskConfig`
// 与 ObjC 兼容的 `CPRiskConfig` 之间的桥接。
// `RiskConfig` 创建后不可变并可跨线程传递；`CPRiskConfig` 保留旧版可变 API。
// 安全不变量：threshold 与 jailbreakThreshold 进入配置时统一裁剪到 0–100，
// 防止宿主或远程配置传入越界值绕过判决。
import Foundation

/// Armor / anti-debug 运行时策略：生产保持强约束；开发或 QA 降低 TTY、Developer Disk、timing 等弱信号导致的误伤。
@objc(CPR_AntiDebugMode)
public enum CPRiskAntiDebugRuntimeMode: Int {
    /// 生产：启用全部 anti-debug 探针，弱信号也参与评分。
    case production = 0
    /// 开发/QA：降低弱探针影响，避免调试环境被误判。
    case relaxedDevelopmentQA = 1
    /// 审核友好：Swift 层跳过 PT_DENY_ATTACH / 异常端口抢占 / watchdog / anti-dump / Mach-O 头擦除等高风险路径；C 层仍初始化 armor 与风控。
    case appStoreSafe = 2
}

/// Swift 侧风险配置值对象；构造时统一裁剪阈值，实例可安全跨线程传递。
public struct RiskConfig: Sendable {
    /// 默认风险阈值
    public static let defaultThreshold: Double = 60
    /// 轻量模式风险阈值：更高阈值意味着更少命中，适合低打扰场景
    public static let lightThreshold: Double = 70
    /// 完整模式风险阈值：更低阈值意味着更敏感，适合高安全场景
    public static let fullThreshold: Double = 55
    /// 默认越狱检测阈值
    public static let defaultJailbreakThreshold: Double = 50

    /// 越狱检测配置（各通道开关与置信度阈值）
    public var jailbreak: JailbreakConfig
    /// 是否启用行为启发式计分
    public var enableBehaviorDetect: Bool
    /// 是否启用网络信号（VPN/代理）
    public var enableNetworkSignals: Bool
    /// 高风险判决阈值（0–100）
    public var threshold: Double
    /// 行为阈值覆盖；nil 表示使用 `BehaviorThresholds.default`
    public var behaviorThresholds: BehaviorThresholds?

    /// 阈值合法范围
    public static let thresholdRange: ClosedRange<Double> = 0...100

    /// 创建配置并裁剪阈值。
    /// - Parameters:
    ///   - jailbreak: 越狱检测配置，默认 `.default`
    ///   - enableBehaviorDetect: 是否启用行为检测，默认 true
    ///   - enableNetworkSignals: 是否启用网络信号，默认 true
    ///   - threshold: 高风险阈值，越界时裁剪到 0–100
    ///   - behaviorThresholds: 行为阈值覆盖，nil 使用默认值
    /// 非法阈值只记录日志、不抛错，避免配置问题阻断 SDK 初始化。
    public init(
        jailbreak: JailbreakConfig = .default,
        enableBehaviorDetect: Bool = true,
        enableNetworkSignals: Bool = true,
        threshold: Double = RiskConfig.defaultThreshold,
        behaviorThresholds: BehaviorThresholds? = nil
    ) {
        self.jailbreak = jailbreak
        self.enableBehaviorDetect = enableBehaviorDetect
        self.enableNetworkSignals = enableNetworkSignals
        // 裁剪到合法范围：远程/宿主配置不可信，不能让其越界改变判决语义。
        let clampedThreshold = min(max(threshold, Self.thresholdRange.lowerBound), Self.thresholdRange.upperBound)
        self.threshold = clampedThreshold
        if threshold != clampedThreshold {
            Logger.log("RiskConfig: threshold \(threshold) clamped to \(clampedThreshold)")
        }
        self.behaviorThresholds = behaviorThresholds
    }

    /// 默认配置：阈值 60，启用行为与网络信号。
    public static let `default` = RiskConfig()

    /// 轻量配置：阈值 70，降低误报与打扰。
    public static let light = RiskConfig(
        jailbreak: .light,
        enableBehaviorDetect: true,
        enableNetworkSignals: true,
        threshold: lightThreshold
    )

    /// 完整配置：阈值 55，使用完整越狱检测以换取更高敏感度。
    public static let full = RiskConfig(
        jailbreak: .full,
        enableBehaviorDetect: true,
        enableNetworkSignals: true,
        threshold: fullThreshold
    )
}

/// ObjC/NSObject 兼容的可变配置桥：保持旧版 API 的二进制兼容，内部再转成值类型 `RiskConfig`。
/// 线程模型：属性本身没有同步保护，宿主应在初始化阶段配置，转换时一次性快照。
@objc(CPR_RiskConfig)
public final class CPRiskConfig: NSObject {
    /// 是否启用行为启发式计分
    @objc public var enableBehaviorDetect: Bool = true
    /// 是否启用网络信号
    @objc public var enableNetworkSignals: Bool = true
    /// 高风险判决阈值（转换时裁剪到 0–100）
    @objc public var threshold: Double = RiskConfig.defaultThreshold

    // 越狱检测各通道独立开关：关闭任一通道只影响该通道证据，其它通道仍独立计分。
    @objc public var jailbreakEnableFileDetect: Bool = true
    @objc public var jailbreakEnableDyldDetect: Bool = true
    @objc public var jailbreakEnableEnvDetect: Bool = true
    @objc public var jailbreakEnableSysctlDetect: Bool = true
    @objc public var jailbreakEnableSchemeDetect: Bool = true
    @objc public var jailbreakEnableHookDetect: Bool = true
    /// 越狱置信度阈值（0–100）；低于该值不判为越狱
    @objc public var jailbreakThreshold: Double = RiskConfig.defaultJailbreakThreshold

    // MARK: - 2.0 新增配置

    /// 是否启用远程配置
    @objc public var enableRemoteConfig: Bool = true

    /// 默认评估场景
    @objc public var defaultScenario: RiskScenario = .default

    /// 是否启用时序分析（预留开关）
    @objc public var enableTemporalAnalysis: Bool = true

    /// 是否启用反篡改检测（预留开关）
    @objc public var enableAntiTamper: Bool = true

    /// C 层 anti-debug 策略：生产默认；开发/QA 宽松（弱探针不计入 debugger 评分，init timing 阈值更高）。
    @objc public var antiDebugRuntimeMode: CPRiskAntiDebugRuntimeMode = .production

    /// 远程配置地址（可选）
    @objc public var remoteConfigURLString: String = ""

    @objc public static let `default` = CPRiskConfig()

    /// 转换成 Swift 值类型配置。
    /// 一次性读取各 ObjC 属性并快照；阈值裁剪策略与 `RiskConfig.init` 保持一致。
    func toSwift() -> RiskConfig {
        var jb = JailbreakConfig.default
        jb.enableFileDetect = jailbreakEnableFileDetect
        jb.enableDyldDetect = jailbreakEnableDyldDetect
        jb.enableEnvDetect = jailbreakEnableEnvDetect
        jb.enableSysctlDetect = jailbreakEnableSysctlDetect
        jb.enableSchemeDetect = jailbreakEnableSchemeDetect
        jb.enableHookDetect = jailbreakEnableHookDetect
        // 与 RiskConfig.init 使用同一裁剪逻辑，避免两条配置入口行为不一致。
        let clampedJBThreshold = min(max(jailbreakThreshold, RiskConfig.thresholdRange.lowerBound), RiskConfig.thresholdRange.upperBound)
        if jailbreakThreshold != clampedJBThreshold {
            Logger.log("CPRiskConfig: jailbreakThreshold \(jailbreakThreshold) clamped to \(clampedJBThreshold)")
        }
        jb.threshold = clampedJBThreshold

        return RiskConfig(
            jailbreak: jb,
            enableBehaviorDetect: enableBehaviorDetect,
            enableNetworkSignals: enableNetworkSignals,
            threshold: threshold
        )
    }
}
