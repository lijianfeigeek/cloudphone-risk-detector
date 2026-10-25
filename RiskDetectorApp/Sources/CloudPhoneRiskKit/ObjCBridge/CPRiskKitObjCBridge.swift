// Objective-C 桥接层：把 Swift 侧 CPRiskKit 的公开能力暴露给 ObjC 宿主。
// 位于 SDK 的 API 边界，只做类型转换与线程转发，不改变任何风控判定逻辑。
// 安全不变量：同步/异步评估最终都走同一个 CPRiskKit 实现，桥接层不得绕过验签、
// 加密或 Armor 检查；ObjC 枚举越界时回退到安全默认值（low/allow/default）。

import Foundation
#if canImport(UIKit)
import UIKit
#endif

// MARK: - Objective-C 风险等级封装

/// 面向 ObjC 的风险等级枚举，封装 `PublicRiskLevel`。
@objc(CPRiskLevel)
public enum CPRiskLevelObjC: Int, CaseIterable {
    case low = 0
    case medium = 1
    case high = 2

    /// 从 Swift 枚举转换；未知取值回退为 `.low`，避免越界崩溃。
    public init(from level: PublicRiskLevel) {
        self = CPRiskLevelObjC(rawValue: level.rawValue) ?? .low
    }

    /// 转回 Swift 枚举；未知取值回退为 `.low`。
    public var toSwift: PublicRiskLevel {
        PublicRiskLevel(rawValue: rawValue) ?? .low
    }

    /// 本地化显示名，直接复用 Swift 侧定义。
    public var displayName: String {
        toSwift.displayName
    }
}

// MARK: - Objective-C 处置动作封装

/// 面向 ObjC 的风险处置动作枚举，封装 `PublicRiskAction`。
@objc(CPRiskActionObjC)
public enum CPRiskActionObjC: Int, CaseIterable {
    case allow = 0
    case challenge = 1
    case block = 2

    /// 从 Swift 枚举转换；未知取值回退为 `.allow`。
    public init(from action: PublicRiskAction) {
        self = CPRiskActionObjC(rawValue: action.rawValue) ?? .allow
    }

    /// 转回 Swift 枚举；未知取值回退为 `.allow`。
    public var toSwift: PublicRiskAction {
        PublicRiskAction(rawValue: rawValue) ?? .allow
    }

    /// 本地化显示名，直接复用 Swift 侧定义。
    public var displayName: String {
        toSwift.displayName
    }
}

// MARK: - Objective-C 风险场景封装

/// 面向 ObjC 的风险场景枚举，封装 `RiskScenario`。
@objc(CPRiskScenarioObjC)
public enum CPRiskScenarioObjC: Int, CaseIterable {
    case login = 0
    case payment = 1
    case register = 2
    case query = 3
    case defaultScenario = 4
    case accountChange = 5
    case sensitiveAction = 6
    case apiAccess = 7

    /// 从 Swift 枚举转换；未知取值回退为 `.defaultScenario`。
    public init(from scenario: RiskScenario) {
        self = CPRiskScenarioObjC(rawValue: scenario.rawValue) ?? .defaultScenario
    }

    /// 转回 Swift 枚举；未知取值回退为 `.default`。
    public var toSwift: RiskScenario {
        RiskScenario(rawValue: rawValue) ?? .default
    }

    /// 本地化显示名，直接复用 Swift 侧定义。
    public var displayName: String {
        toSwift.displayName
    }
}

// MARK: - 评估结果（ObjC 友好封装）

/// ObjC 桥接评估方法返回的不可变结果对象。
@objc(CPEvaluationResult)
public final class CPEvaluationResult: NSObject {

    /// 原始评估报告（含全部信号与证据）。
    @objc public let report: CPRiskReport
    /// 风险总分。
    @objc public let score: Double
    /// 是否达到高风险线。
    @objc public let isHighRisk: Bool
    /// 风险等级（ObjC 枚举）。
    @objc public let riskLevel: CPRiskLevelObjC
    /// 面向展示的摘要文本。
    @objc public let summary: String
    /// 设备 ID（可能是持久化 ID 或 ephemeral ID）。
    @objc public let deviceID: String
    /// 本轮命中信号数量。
    @objc public let signalCount: Int

    /// 从报告派生 ObjC 结果；内部等级换算与 Swift 侧保持一致。
    init(report: CPRiskReport) {
        self.report = report
        self.score = report.score
        self.isHighRisk = report.isHighRisk
        self.riskLevel = CPRiskLevelObjC(
            from: InternalRiskLevel.from(score: report.score).toPublicRiskLevel()
        )
        self.summary = report.summary
        self.deviceID = report.deviceID
        self.signalCount = report.signals.count
        super.init()
    }

    /// 调试输出；不包含设备标识等敏感字段。
    @objc public override var description: String {
        "<CPEvaluationResult score=\(score) level=\(riskLevel.displayName) signals=\(signalCount)>"
    }
}

// MARK: - CPRiskKitObjCBridge

/// 暴露 CPRiskKit 主要 API 的 Objective-C 桥接类。
///
/// ObjC 使用示例：
/// ```objc
/// CPRiskKitObjCBridge *bridge = [[CPRiskKitObjCBridge alloc] init];
/// [bridge startWithDefaultConfig];
/// [bridge evaluateWithScenario:CPRiskScenarioObjCPayment
///                   completion:^(CPEvaluationResult *result) {
///     NSLog(@"Score: %f", result.score);
/// }];
/// ```
@objc(CPRiskKitObjCBridge)
public final class CPRiskKitObjCBridge: NSObject {

    /// 底层 Swift SDK 单例；桥接层不持有独立状态。
    private let kit: CPRiskKit

    // MARK: - 初始化

    /// 创建桥接对象并绑定全局 `CPRiskKit.shared`。
    @objc
    public override init() {
        self.kit = CPRiskKit.shared
        super.init()
    }

    // MARK: - 生命周期

    /// 使用默认配置启动 SDK。
    @objc(startWithDefaultConfig)
    public func startWithDefaultConfig() {
        kit.start()
    }

    /// 使用自定义 ObjC 配置对象启动 SDK。
    @objc(startWithConfig:)
    public func start(config: CPRiskConfig) {
        kit.start(config: config)
    }

    /// 停止 SDK，终止所有采样并释放资源。
    @objc
    public func stop() {
        kit.stop()
    }

    // MARK: - 配置

    /// 开关 SDK 日志（仅 DEBUG 构建生效）。
    @objc(setLogEnabled:)
    public func setLogEnabled(_ enabled: Bool) {
        CPRiskKit.setLogEnabled(enabled)
    }

    /// 配置服务端上报验签使用签名密钥。
    @objc(configureServerSigningKey:)
    public func configureServerSigningKey(_ key: String) {
        CPRiskKit.configureServerSigningKey(key)
    }

    /// 配置 TLS 证书 pin 哈希列表。
    @objc(configurePinnedCertificateHashes:)
    public func configurePinnedCertificateHashes(_ hashes: [String]) {
        CPRiskKit.configurePinnedCertificateHashes(hashes)
    }

    // MARK: - 账号绑定

    /// 绑定当前用户账号，用于图风控关联分析。
    @objc(bindAccount:scene:)
    public func bindAccount(_ accountId: String, scene: String?) {
        kit.bindAccount(accountId, scene: scene)
    }

    /// 解绑当前用户账号并清理相关状态。
    @objc
    public func unbindAccount() {
        kit.unbindAccount()
    }

    // MARK: - 同步评估

    /// 使用默认配置与场景同步评估。
    /// - Returns: 原始 `CPRiskReport`。
    @objc(evaluate)
    public func evaluate() -> CPRiskReport {
        kit.evaluate()
    }

    /// 同步评估并返回 ObjC 封装结果。
    @objc(evaluateAndWrap)
    public func evaluateAndWrap() -> CPEvaluationResult {
        CPEvaluationResult(report: kit.evaluate())
    }

    /// 针对指定场景同步评估，返回原始报告。
    @objc(evaluateWithScenarioRaw:)
    public func evaluateWithScenarioRaw(_ scenario: CPRiskScenarioObjC) -> CPRiskReport {
        kit.evaluate(config: .default, scenario: scenario.toSwift)
    }

    // MARK: - 异步评估（Completion Handler）

    /// 使用默认配置异步评估。
    /// completion 在后台队列回调（继承 `CPRiskKit.evaluateAsync` 的语义）。
    @objc(evaluateWithCompletion:)
    public func evaluate(completion: @escaping (CPRiskReport) -> Void) {
        kit.evaluateAsync(completion: completion)
    }

    /// 针对指定场景异步评估，回调 ObjC 封装结果。
    /// completion 在全局 utility 队列回调，调用方如需更新 UI 需自行切主线程。
    @objc(evaluateWithScenario:completion:)
    public func evaluate(
        scenario: CPRiskScenarioObjC,
        completion: @escaping (CPEvaluationResult) -> Void
    ) {
        DispatchQueue.global(qos: .utility).async { [kit] in
            let report = kit.evaluate(config: .default, scenario: scenario.toSwift)
            let result = CPEvaluationResult(report: report)
            completion(result)
        }
    }

    /// 使用自定义配置异步评估，回调 ObjC 封装结果。
    @objc(evaluateWithConfig:completion:)
    public func evaluate(
        config: CPRiskConfig,
        completion: @escaping (CPEvaluationResult) -> Void
    ) {
        DispatchQueue.global(qos: .utility).async { [kit] in
            let report = kit.evaluate(config: config)
            let result = CPEvaluationResult(report: report)
            completion(result)
        }
    }

    // MARK: - 报告获取

    /// 获取最近一次评估报告的 JSON（未加密，仅调试用）。
    /// 注意：内部会触发一次同步评估，不是读取历史缓存。
    @objc(lastReportJSONPrettyPrinted:)
    public func lastReportJSON(prettyPrinted: Bool) -> String? {
        let report = kit.evaluate()
        return report.unencryptedPayloadString(prettyPrinted: prettyPrinted)
    }

    /// 获取最近一次评估的加密载荷（生产使用）。
    /// - Throws: 加密/信封构建失败时抛出；调用方不得回退到明文 payload。
    @objc(lastReportSecurePayloadAndReturnError:)
    public func lastReportSecurePayload() throws -> Data {
        let report = kit.evaluate()
        return try report.securePayload()
    }

    // MARK: - 服务端信号

    /// 把服务端聚合信号注入到指定报告。
    /// 这是直接写报告对象的调试入口，生产环境应通过验签注入 API。
    @objc(setServerSignalsOnReport:publicIP:asn:asOrg:isDatacenter:ipDeviceAgg:ipAccountAgg:geoCountry:geoRegion:riskTags:)
    public func setServerSignals(
        on report: CPRiskReport,
        publicIP: String?,
        asn: String?,
        asOrg: String?,
        isDatacenter: NSNumber?,
        ipDeviceAgg: NSNumber?,
        ipAccountAgg: NSNumber?,
        geoCountry: String?,
        geoRegion: String?,
        riskTags: [String]?
    ) {
        report.setServerSignals(
            publicIP: publicIP,
            asn: asn,
            asOrg: asOrg,
            isDatacenter: isDatacenter,
            ipDeviceAgg: ipDeviceAgg,
            ipAccountAgg: ipAccountAgg,
            geoCountry: geoCountry,
            geoRegion: geoRegion,
            riskTags: riskTags
        )
    }

    // MARK: - 清理

    /// 清空所有缓存的外部服务端信号。
    @objc
    public func clearExternalServerSignals() {
        CPRiskKit.clearExternalServerSignals()
    }

    /// 清空缓存的实时遥测反馈。
    @objc
    public func clearRealtimeTelemetryFeedback() {
        CPRiskKit.clearRealtimeTelemetryFeedback()
    }

    // MARK: - 工具

    /// 当前 SDK 版本字符串。
    @objc public var sdkVersion: String {
        Version.current
    }

    /// 当前是否处于 Kill Switch（总开关）状态。
    /// 桥接层固定返回 false；实际总开关状态由内部策略层决定。
    @objc public var isKillSwitchActive: Bool {
        false
    }
}
