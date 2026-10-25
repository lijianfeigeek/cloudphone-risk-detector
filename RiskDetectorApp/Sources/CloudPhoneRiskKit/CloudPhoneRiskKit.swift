// CloudPhoneRiskKit 对外主入口：单例编排启动/停止、评估、配置下发与上报。
// 位于检测管道顶端：汇聚配置、生命周期、各 Provider，并输出一次评估结果。
// 具体实现拆分在 Core/ 扩展中：
//   Configuration / Lifecycle / Evaluation / ArmorBridge / Reporting / Diagnostics
// 安全不变量：未验签的端侧注入默认不被采信；Armor 不可用时失败即拒绝（fail-closed）。
// MARK: - CloudPhoneRiskKit — 主入口

import CryptoKit
import CRiskCore
import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// SDK 主入口单例。
/// - 线程模型：同步评估可任意线程调用；异步入口统一派发到 `evaluateQueue`（utility QoS）。
/// - 安全不变量：Armor 运行时、证书 pin、远端信任等安全状态均由专用锁保护；
///   生产构建禁止本地策略注入与配置回滚。
@objc(CPR_RiskKit)
public final class CPRiskKit: NSObject {
    /// 全局共享实例；初始化时会从 UserDefaults 恢复上次配置的远端配置端点。
    @objc public static let shared = CPRiskKit()

    /// 图风控反馈已应用的通知名称（直接复用聚合 Provider 的定义，避免两处字符串漂移）。
    public static let graphRiskFeedbackDidApplyNotification = ExternalServerAggregateProvider.graphRiskFeedbackDidApplyNotification
    /// 图反馈到达后是否自动重新评估；默认开启，调用方可关闭以节省算力。
    public static var autoReEvaluateOnGraphFeedback: Bool = true

    /// 安全信封构建失败的错误集合。
    /// 失败即拒绝：调用方必须把错误视为“未成功上报”，不得把明文载荷当作降级结果发送。
    public enum SecureUploadError: Error, LocalizedError {
        /// 策略要求字段混淆，但服务端未下发 payloadFieldMapping。
        case payloadFieldMappingRequired
        /// 下发的字段映射版本已过期，继续使用会导致服务端无法解析。
        case payloadFieldMappingExpired(version: String)
        /// 上报载荷结构不合法，无法构建安全信封。
        case invalidPayloadShape
        /// Armor 运行时不可用，无法派生签名密钥。
        case armorRuntimeUnavailable(reason: String)

        /// 面向日志/调试的本地化错误描述；不包含任何密钥或设备标识。
        public var errorDescription: String? {
            switch self {
            case .payloadFieldMappingRequired:
                return "当前策略要求字段混淆，但 payloadFieldMapping 未下发"
            case .payloadFieldMappingExpired(let version):
                return "payloadFieldMapping 已过期（version=\(version)）"
            case .invalidPayloadShape:
                return "上报 payload 结构无效，无法构建安全信封"
            case .armorRuntimeUnavailable(let reason):
                return "armor 运行时不可用，无法派生签名密钥（reason=\(reason)），服务端验签将失败"
            }
        }
    }

    // MARK: - 存储属性

#if canImport(UIKit)
    /// 触摸采集器（仅 iOS）：为行为信号提供原始输入。
    internal let touchCapture = TouchCapture.shared
    /// 运动采样器（仅 iOS）：为行为信号提供设备姿态数据。
    internal let motionSampler = MotionSampler.shared
    /// 越狱检测引擎：无状态，可安全持有。
    internal let jailbreakEngine = JailbreakEngine()
#else
    /// 越狱检测引擎（非 UIKit 平台同样保留，便于 macOS 调试）。
    internal let jailbreakEngine = JailbreakEngine()
#endif

    /// 评估专用串行队列：异步入口在此执行，避免阻塞调用线程，并保证评估不并发重入。
    internal let evaluateQueue = DispatchQueue(label: "CloudPhoneRiskKit.Evaluate", qos: .utility)
    /// 保护账户绑定、会话、上一轮信号等可变状态。
    internal let stateLock = UnfairLock()
    /// 串行化 Armor 运行时初始化，防止并发触发重复初始化。
    internal let armorInitLock = UnfairLock()

    /// 异常校验节流窗口（秒）：同一窗口内不重复执行高开销的异常校验。
    internal static let verifyThrottleInterval: TimeInterval = 5.0
    /// 上次异常校验时间（epoch 秒）；与 `verifyThrottleLock` 配合读写。
    internal static var lastExceptionVerifyTime: TimeInterval = 0
    /// 保护 `lastExceptionVerifyTime` 的锁。
    internal static let verifyThrottleLock = UnfairLock()

    /// 当前远端配置提供者；为 nil 时使用本地/默认配置。
    internal var remoteConfigProvider: RemoteConfigProvider?
    /// 已配置的远端配置端点。
    internal var remoteConfigEndpoint: URL?
    /// 最近一次成功采纳的远端配置。
    internal var latestRemoteConfig: RemoteConfig?
    /// 文本段引用解析器（用于反篡改基线），由宿主或测试注入。
    internal var textSegmentReferenceResolver: (any TextSegmentReferenceResolving)?

    /// 注册接收 C 层敌对环境信号的 reporter，用于服务端风险评估。
    /// 每次评估周期结束后、且存在模拟器/unidbg 信号时回调。
    ///
    /// 设为 `nil`（默认）即关闭服务端上报。
    public weak var hostileEnvironmentReporter: (any HostileEnvironmentReporter)?

    /// 当前绑定的业务账号 ID；跨线程访问需持 `stateLock`。
    internal var boundAccountId: String?
    /// 当前绑定场景标签（如 "login"/"payment"）。
    internal var boundSceneTag: String?
    /// 当前会话 ID。
    internal var currentSessionId: String?
    /// 图反馈通知观察者句柄，停止时用于注销。
    internal var graphFeedbackObserver: Any?
    /// 主线程看门狗心跳定时器。
    internal var mainThreadWatchdogHeartbeatTimer: Timer?

    /// 上一轮命中的信号 ID 集合，用于计算信号变化（新增/消失）。
    internal var previousSignalIds: Set<String> = []
    /// 上一轮信号的摘要，用于在信号未变化时跳过重复处理。
    internal var previousSignalsDigest: String?
    /// 自适应评估的报告缓存；仅在缓存键一致且未过期时复用。
    internal var adaptiveCachedReport: CPRiskReport?
    /// 自适应缓存键（配置/场景/时间窗的摘要）。
    internal var adaptiveCachedKey: String?
    /// 上次自适应评估时间（epoch 秒），用于最小评估间隔限流。
    internal var adaptiveLastEvaluationAtEpochSeconds: TimeInterval = 0

    /// 高风险信号 ID 白名单：命中任意一条即视为需要优先处置。
    /// 其中部分字符串来自混淆常量表，改名前需同步服务端约定。
    internal static let highRiskSignalIds: Set<String> = [
        ObfuscatedConstants.signalFridaDetected,
        SignalID.fridaModuleDetected, SignalID.fridaModuleImage,
        SignalID.fridaModuleSection, SignalID.fridaModuleString, SignalID.fridaModuleTrampoline,
        ObfuscatedConstants.detectorIDFridaHeap, ObfuscatedConstants.signalFridaStalker,
        ObfuscatedConstants.detectorIDFridaSocket, ObfuscatedConstants.detectorIDFridaThread,
        ObfuscatedConstants.signalFridaJSEngineHeap, ObfuscatedConstants.signalFridaStalkerJit,
        ObfuscatedConstants.signalFridaUnixSocket, ObfuscatedConstants.signalFridaExceptionPort,
        SignalID.fridaExceptionPortStartupRace,
        ObfuscatedConstants.signalThreadAnomaly,
        SignalID.hookDetected, ObfuscatedConstants.detectorIDObjCSwizzle, "rwx_memory",
        ObfuscatedConstants.signalArmorRuntimeInitFailed, ObfuscatedConstants.signalIntegrityRuntimeTampered,
        "code_signature_invalid", ObfuscatedConstants.signalTextSegmentTampered,
        ObfuscatedConstants.signalAppSigningIdentityTampered, ObfuscatedConstants.signalAppSigningBaselineChanged,
        SignalID.fridaRuntimeConsensus, SignalID.antiDebugRuntimeConsensus, SignalID.signingChainConsensus,
        ObfuscatedConstants.signalKernelHookTimingAnomaly, ObfuscatedConstants.signalKernelHookStalkerAmplified,
        "system_library_wx_mapping", "system_library_anonymous_exec_region",
        "app_image_segment_layout_anomaly",
        SignalID.antiDebugWatchdogDyldInjection, SignalID.antiDebugWatchdogAMFICsFlags,
        SignalID.antiDebugWatchdogGetTaskAllow, SignalID.antiDebugWatchdogDenyAttachVerify,
        SignalID.dylibInjectImageCountLow, SignalID.ifaceSpawnPathDivergence,
        "dyld_monitor_suspicious_injection", "dyld_monitor_silent_mutation",
        "dyld_image_overload", "dyld_env_abuse"
    ]

    /// UserDefaults 中保存远端配置端点的键。
    internal static let remoteConfigEndpointKey = "com.cloudphone.riskkit.remote.endpoint"
    /// 当前进程是否运行在 XCTest 下：用于在测试环境放宽/跳过部分安全校验。
    /// 同时检查环境变量、进程名与 XCTestCase 类是否已加载。
    internal static let isRunningUnderXCTest: Bool = {
        let env = ProcessInfo.processInfo.environment
        if env["XCTestConfigurationFilePath"] != nil || env["XCTestSessionIdentifier"] != nil { return true }
        let name = ProcessInfo.processInfo.processName.lowercased()
        if name.contains("xctest") || name.contains("swiftpm-xctest-helper") { return true }
        return NSClassFromString("XCTestCase") != nil
    }()
    /// 保护证书 pin 材料的锁。
    internal static let remoteTrustLock = UnfairLock()
    /// 当前生效的证书 pin 材料；由 `configurePinnedCertificateHashes` 更新。
    internal static var pinnedCertificatePinMaterial: PinnedCertificatePinMaterial = .empty
    /// 是否允许本地注入策略：仅 DEBUG 构建允许，生产环境硬关闭。
    internal static let localPolicyInjectionAllowed: Bool = {
        #if DEBUG
        return true
        #else
        return false
        #endif
    }()
    /// 是否允许远端配置回滚：仅 DEBUG 且显式设置环境变量时允许。
    internal static let localRemoteConfigRollbackAllowed: Bool = {
        #if DEBUG
        return ProcessInfo.processInfo.environment["CPRISKKIT_ALLOW_CONFIG_ROLLBACK"] == "1"
        #else
        return false
        #endif
    }()
    /// 是否允许本地合成挑战绑定：仅 DEBUG 构建允许，避免生产环境绕过真实挑战。
    internal static let localSynthesizedChallengeBindingAllowed: Bool = {
        #if DEBUG
        return true
        #else
        return false
        #endif
    }()
    /// 环境变量名：由宿主在启动前注入 Armor 根密钥（hex）。
    internal static let armorRootKeyEnvironmentKey = "CPRISKKIT_ARMOR_ROOT_KEY_HEX"
    // 注意：这里刻意不提供硬编码 / DEBUG 兜底 Armor 根密钥。
    // 硬编码密钥（历史上曾用顺序 hex 测试密钥）会随二进制分发，任何人都能
    // 据此派生 Armor 签名材料。未配置密钥时 Armor 运行时直接硬失败
    // （`missing_root_key`），而不是静默降级到已知密钥。

    /// Armor 运行时最近一次快照；`.inactive` 表示尚未启动。
    internal var armorRuntimeSnapshot = ArmorRuntimeSnapshot.inactive
    /// 上一次的本地反调试模式（来自本地配置）。
    internal var lastLocalAntiDebugMode: CPRiskAntiDebugRuntimeMode = .production
    /// 上一次实际生效的反调试模式（本地与远端取更严格者）。
    internal var lastAppliedEffectiveAntiDebugMode: CPRiskAntiDebugRuntimeMode = .production
    /// 上一次是否启用远端配置。
    internal var lastEnableRemoteConfig: Bool = true
    /// 上一次远端下发的 App Store 安全画像标记。
    internal var lastRemoteAppStoreSafeProfileFlag: Bool = false

    // MARK: - 初始化

    /// 私有初始化：恢复持久化的远端配置端点并尝试建立 Provider。
    private override init() {
        super.init()
        if let endpoint = UserDefaults.standard.string(forKey: Self.remoteConfigEndpointKey) {
            _ = configureRemoteConfigProvider(urlString: endpoint)
        }
    }

    // MARK: - 公开 API（薄封装——实现在 Core/*.swift 扩展中）

    /// 使用当前配置启动 SDK（采集、看门狗、Armor 等）。
    @objc public func start() { startImpl() }

    /// 使用指定配置启动 SDK。
    @objc(startWithConfig:)
    public func start(config: CPRiskConfig) { startImpl(config: config) }

    /// 停止 SDK，释放采样与看门狗资源。
    @objc public func stop() { stopImpl() }

    /// 返回保护稳定性快照（看门狗、Armor、主线程心跳等健康度）。
    public func protectionStabilitySnapshot() -> ProtectionStabilitySnapshot {
        ProtectionStabilityStore.shared.currentSnapshot()
    }

    /// 使用默认配置与默认场景同步评估。
    @objc public func evaluate() -> CPRiskReport { evaluate(config: .default) }

    /// 使用默认场景同步评估。
    @objc(evaluateWithConfig:)
    public func evaluate(config: CPRiskConfig = .default) -> CPRiskReport {
        evaluate(config: config, scenario: config.defaultScenario)
    }

    /// 指定配置与场景同步评估；可能耗时，避免在主线程调用。
    @objc(evaluateWithConfig:scenario:)
    public func evaluate(config: CPRiskConfig, scenario: RiskScenario) -> CPRiskReport {
        evaluateImpl(config: config, scenario: scenario)
    }

    /// 异步评估（旧 completion API，已弃用）；完成后在主线程回调。
    @available(*, deprecated, message: "Use async/await evaluateAsync() or RiskEvaluationActor.shared.evaluate() instead")
    @objc(evaluateAsyncWithCompletion:)
    public func evaluateAsync(completion: @escaping (CPRiskReport) -> Void) {
        evaluateAsync(config: .default, scenario: .default, completion: completion)
    }

    /// 异步评估（旧 completion API，已弃用）；完成后在主线程回调。
    @available(*, deprecated, message: "Use async/await evaluateAsync(config:) instead")
    @objc(evaluateAsyncWithConfig:completion:)
    public func evaluateAsync(config: CPRiskConfig, completion: @escaping (CPRiskReport) -> Void) {
        evaluateAsync(config: config, scenario: config.defaultScenario, completion: completion)
    }

    /// 指定场景异步评估；完成后在主线程回调。
    @objc(evaluateWithScenario:completion:)
    public func evaluate(scenario: RiskScenario, completion: @escaping (CPRiskReport) -> Void) {
        evaluateAsync(config: .default, scenario: scenario, completion: completion)
    }

    /// 异步评估实现：在专用串行队列执行，结果切回主线程回调。
    @available(*, deprecated, message: "Use async/await evaluateAsync(config:scenario:) instead")
    public func evaluateAsync(config: CPRiskConfig, scenario: RiskScenario, completion: @escaping (CPRiskReport) -> Void) {
        let cfg = config
        // 评估放到专用队列，避免阻塞调用线程；同时串行化避免重复采集与状态竞争。
        evaluateQueue.async { [self] in
            let report = evaluate(config: cfg, scenario: scenario)
            // UIKit/回调使用方通常期望主线程，统一切回 main。
            DispatchQueue.main.async { completion(report) }
        }
    }

    /// 构建带签名/加密的安全信封。
    /// - Parameters:
    ///   - report: 待上报的评估报告。
    ///   - sessionToken: 服务端下发的会话令牌，绑定本次上报。
    ///   - signingKey: 基础签名密钥；实际使用由 Armor 派生的密钥。
    ///   - keyId: 密钥标识，供服务端选择验签公钥。
    ///   - attestationKeyId: App Attest 密钥标识（可选）。
    ///   - requireArmor: 为 true 时 Armor 不可用即失败（fail-closed）。
    /// - Throws: `SecureUploadError` 或信封构建错误；调用方不得降级为明文上报。
    public func buildSecureReportEnvelope(
        report: CPRiskReport, sessionToken: String, signingKey: String,
        keyId: String = "k1", attestationKeyId: String? = nil, requireArmor: Bool = true
    ) throws -> ReportEnvelope {
        try buildSecureReportEnvelopeImpl(
            report: report, sessionToken: sessionToken, signingKey: signingKey,
            keyId: keyId, attestationKeyId: attestationKeyId, requireArmor: requireArmor
        )
    }

    /// 构建安全信封并序列化为 JSON 字符串。
    public func buildSecureReportEnvelopeJSON(
        report: CPRiskReport, sessionToken: String, signingKey: String,
        keyId: String = "k1", prettyPrinted: Bool = false
    ) throws -> String {
        try buildSecureReportEnvelope(report: report, sessionToken: sessionToken, signingKey: signingKey, keyId: keyId)
            .toJSONString(prettyPrinted: prettyPrinted)
    }

    /// 构建 gRPC 兼容的 JSON（字段布局适配服务端 gRPC 网关）。
    public func buildSecureReportEnvelopeGrpcCompatibleJSON(
        report: CPRiskReport, sessionToken: String, signingKey: String,
        keyId: String = "k1", appId: String = "", prettyPrinted: Bool = false
    ) throws -> String {
        let envelope = try buildSecureReportEnvelope(report: report, sessionToken: sessionToken, signingKey: signingKey, keyId: keyId)
        // 场景标签从绑定状态读取；未绑定时传空串，避免把 nil 写成 "null"。
        let ctx = GrpcReportContext(appId: appId, deviceId: report.deviceID, scene: stateLock.withLock { boundSceneTag } ?? "")
        return try envelope.toGrpcCompatibleJSON(context: ctx, prettyPrinted: prettyPrinted)
    }

    /// 构建 gRPC 请求体字节（含信封与上下文）。
    public func buildSecureReportEnvelopeGrpcRequestBytes(
        report: CPRiskReport, sessionToken: String, signingKey: String,
        keyId: String = "k1", appId: String = ""
    ) throws -> Data {
        let envelope = try buildSecureReportEnvelope(report: report, sessionToken: sessionToken, signingKey: signingKey, keyId: keyId)
        let ctx = GrpcReportContext(appId: appId, deviceId: report.deviceID, scene: stateLock.withLock { boundSceneTag } ?? "")
        return try envelope.toGrpcRequestBytes(context: ctx)
    }

    /// 构建携带 App Attest 证明的安全信封。
    /// - Parameter requireAttestation: 为 true 时证明失败即抛出，不降级为普通签名。
    @available(iOS 14.0, macOS 11.0, *)
    public func buildSecureReportEnvelopeWithAttestation(
        report: CPRiskReport, sessionToken: String, signingKey: String,
        keyId: String = "k1", requireAttestation: Bool = true
    ) async throws -> ReportEnvelope {
        try await buildSecureReportEnvelopeWithAttestationImpl(
            report: report, sessionToken: sessionToken, signingKey: signingKey,
            keyId: keyId, requireAttestation: requireAttestation)
    }

    /// 返回 Armor 运行时调试快照（内部诊断用）。
    internal func debugArmorRuntimeSnapshot() -> ArmorRuntimeDebugSnapshot { debugArmorRuntimeSnapshotImpl() }
    /// 返回反调试看门狗快照，供宿主上报或诊断。
    public func antiDebugWatchdogSnapshot() -> AntiDebugWatchdogSnapshot { antiDebugWatchdogSnapshotImpl() }
    /// 返回反调试计划快照（当前启用的探针与模式）。
    public func antiDebugPlanSnapshot() -> AntiDebugPlanSnapshot { antiDebugPlanSnapshotImpl() }

    /// 使用 Armor 派生密钥校验信封签名。
    /// - Returns: 成功为 `.success(())`；Armor 未激活或完整性被污染时返回 `.failure(.signingFailed)`。
    func validateEnvelopeWithArmorDerivedSignature(
        _ envelope: ReportEnvelope, baseKey: String,
        nonceStore: NonceReplayProtecting? = nil, config: ReportEnvelope.Config = .init()
    ) -> Result<Void, ReportEnvelope.ReportEnvelopeError> {
        let snapshot = ensureArmorRuntimeStarted(trigger: "validate_envelope")
        // 未激活即拒绝：没有 Armor 密钥就无法证明签名来源，不能放行。
        guard snapshot.status == .active else { return .failure(.signingFailed) }
        // 完整性被投毒时即使签名格式正确也拒绝，防止被篡改的运行时自校验通过。
        guard cprisk_is_integrity_poisoned() == 0 else { return .failure(.signingFailed) }
        return envelope.validate(
            signatureValidator: { Self.verifyWithArmorDerivedKey(baseKey: baseKey, signatureInput: $0, expectedSignature: $1) },
            nonceStore: nonceStore, config: config
        )
    }

    // MARK: - 静态公开 API

    /// 开关 SDK 日志；仅 DEBUG 构建生效，防止生产日志泄露。
    @objc public static func setLogEnabled(_ enabled: Bool) {
        #if DEBUG
        Logger.isEnabled = enabled
        #endif
    }

    @objc(setExternalServerSignalsPublicIP:asn:asOrg:isDatacenter:ipDeviceAgg:ipAccountAgg:geoCountry:geoRegion:riskTags:)
    /// 注入未验签的服务端聚合信号（调试/联调用）。
    /// - Parameters:
    ///   - publicIP/asn/asOrg/isDatacenter: 网络与机房归属信息。
    ///   - ipDeviceAgg/ipAccountAgg: IP 维度的设备/账号聚合计数。
    ///   - geoCountry/geoRegion/riskTags: 地理与风险标签。
    ///
    /// ⚠️ 未验签的端侧注入：该入口写入的信号默认不被采信
    /// （见 `ExternalServerAggregateProvider` 的验签来源门控），仅 DEBUG 联调用。
    /// 生产路径请使用 `setVerifiedExternalServerSignals(_:signature:)`，
    /// 并预先调用 `configureServerSignalKey(_:)`。
    /// 无论何种来源，服务端必须忽略端侧上报的 `server` 字段，仅以服务端
    /// 自己聚合的 IP/ASN/机房信息为准。
    public static func setExternalServerSignals(
        publicIP: String?, asn: String?, asOrg: String?, isDatacenter: NSNumber?,
        ipDeviceAgg: NSNumber?, ipAccountAgg: NSNumber?,
        geoCountry: String?, geoRegion: String?, riskTags: [String]?
    ) {
        ExternalServerAggregateProvider.shared.setDebugBypassingVerification(
            ServerSignals(publicIP: publicIP, asn: asn, asOrg: asOrg, isDatacenter: isDatacenter?.boolValue,
                          ipDeviceAgg: ipDeviceAgg?.intValue, ipAccountAgg: ipAccountAgg?.intValue,
                          geoCountry: geoCountry, geoRegion: geoRegion, riskTags: riskTags))
    }

    /// 配置外部信号的 CPRisk-MAC 密钥。
    /// 重新配置会清空此前已接受的信号；传入空密钥即关闭签名注入。
    @objc public static func configureServerSignalKey(_ key: Data) {
        ExternalServerAggregateProvider.shared.configureServerSignalKey(key)
    }

    /// 校验 `signals` 的 CPRisk-MAC（基于 JSONEncoder 排序键编码）。
    /// - Returns: 校验失败，或校验期间密钥/会话发生变化时返回 false。
    @discardableResult
    public static func setVerifiedExternalServerSignals(_ signals: ServerSignals, signature: Data) -> Bool {
        ExternalServerAggregateProvider.shared.setVerified(signals, signature: signature)
    }

    /// 注入服务端图计算特征（社区、密度、PageRank 等）用于增强本地评分。
    @objc(setGraphFeaturesWithCommunityId:communityRiskDensity:hwProfileDegree:devicePageRank:isInDenseSubgraph:riskTags:)
    public static func setGraphFeatures(
        communityId: String?, communityRiskDensity: NSNumber?, hwProfileDegree: NSNumber?,
        devicePageRank: NSNumber?, isInDenseSubgraph: NSNumber?, riskTags: [String]?
    ) {
        ExternalServerAggregateProvider.shared.setGraphFeatures(
            communityId: communityId, communityRiskDensity: communityRiskDensity?.doubleValue,
            hwProfileDegree: hwProfileDegree?.intValue, devicePageRank: devicePageRank?.doubleValue,
            isInDenseSubgraph: isInDenseSubgraph?.boolValue, riskTags: riskTags)
    }

    /// 配置服务端策略签名公钥，并立即刷新远端信任状态。
    @objc public static func configureServerSigningKey(_ key: String) {
        ConfigSignatureVerifier.configure(serverSigningKey: key)
        shared.refreshRemoteTrustState()
    }

    /// 配置 TLS 证书 pin 哈希列表（hex/base64 由内部规范化）。
    /// 空列表表示不启用 pin，需由宿主按安全策略决定。
    @objc public static func configurePinnedCertificateHashes(_ hashes: [String]) {
        let material = PinnedCertificatePinMaterial(pinStrings: normalizedPinnedCertificateHashes(from: hashes))
        // 先原子替换静态材料，再下发到 PolicyManager 与实例，保证读方看到一致视图。
        remoteTrustLock.withLock { pinnedCertificatePinMaterial = material }
        PolicyManager.shared.configurePinning(pinMaterial: material)
        shared.applyPinnedCertificateHashes(material)
    }

    /// 清空外部信号缓存。
    @objc public static func clearExternalServerSignals() { ExternalServerAggregateProvider.shared.clear() }

    /// 注入实时遥测反馈（风险压力、最小评估间隔、各类别权重缩放）。
    /// 权重使用 bps（basis point，万分之一）表示：10000 = 1.0 倍。
    /// - Parameter ttlSeconds: 反馈有效期（秒）；到点后自动失效，避免陈旧反馈长期影响决策。
    @objc(setRealtimeTelemetryFeedbackWithRiskPressure:minEvaluationIntervalMillis:defaultWeightScaleBps:jailbreakWeightScaleBps:networkWeightScaleBps:behaviorWeightScaleBps:deviceWeightScaleBps:timeWeightScaleBps:ttlSeconds:)
    public static func setRealtimeTelemetryFeedback(
        riskPressure: NSNumber?, minEvaluationIntervalMillis: NSNumber?, defaultWeightScaleBps: NSNumber?,
        jailbreakWeightScaleBps: NSNumber?, networkWeightScaleBps: NSNumber?, behaviorWeightScaleBps: NSNumber?,
        deviceWeightScaleBps: NSNumber?, timeWeightScaleBps: NSNumber?, ttlSeconds: NSNumber?
    ) {
        var cs: [String: Int] = [:]
        // 只写入调用方实际提供的类别，未提供的类别保持默认权重。
        if let v = jailbreakWeightScaleBps?.intValue { cs["jailbreak"] = v }
        if let v = networkWeightScaleBps?.intValue { cs["network"] = v }
        if let v = behaviorWeightScaleBps?.intValue { cs["behavior"] = v }
        if let v = deviceWeightScaleBps?.intValue { cs["device"] = v }
        if let v = timeWeightScaleBps?.intValue { cs["time"] = v }
        // TTL 转绝对时间戳；负值按 0 处理（立即过期），避免时钟错误导致永久有效。
        let exp = ttlSeconds.map { Date().timeIntervalSince1970 + max(0, TimeInterval($0.intValue)) }
        ExternalServerAggregateProvider.shared.setRealtimeTelemetryFeedback(
            .init(riskPressure: riskPressure?.doubleValue, minEvaluationIntervalMillis: minEvaluationIntervalMillis?.intValue,
                  defaultWeightScaleBps: defaultWeightScaleBps?.intValue, categoryWeightScaleBps: cs, expiresAtEpochSeconds: exp))
    }

    /// 清除实时遥测反馈，恢复默认权重。
    @objc public static func clearRealtimeTelemetryFeedback() { ExternalServerAggregateProvider.shared.clearRealtimeTelemetryFeedback() }
    /// 应用服务端图风险反馈（自动重评估逻辑见 `autoReEvaluateOnGraphFeedback`）。
    public static func applyGraphRiskFeedback(_ feedback: GraphRiskFeedback) { ExternalServerAggregateProvider.shared.applyGraphRiskFeedback(feedback) }

    /// 应用挑战验证结果。
    /// 若结果与会话中记录的挑战不匹配，只记录待上报的 mismatch 信号，不直接改分。
    public static func applyChallengeResult(_ result: ChallengeVerificationResult) {
        if let s = ChallengeSession.shared.verifyResult(result) { ChallengeResultStore.shared.storePendingMismatchSignal(s); return }
        ChallengeResultStore.shared.apply(result: result)
    }

    /// ObjC 友好的挑战结果入口（参数与 Swift 版本一一对应）。
    @objc(applyChallengeResultWithChallengeId:passed:failedProbes:adjustedScore:)
    public static func applyChallengeResult(challengeId: String, passed: Bool, failedProbes: [String], adjustedScore: NSNumber?) {
        applyChallengeResult(ChallengeVerificationResult(challengeId: challengeId, passed: passed, failedProbes: failedProbes, adjustedScore: adjustedScore?.doubleValue))
    }

    /// 绑定业务账号与场景；后续评估会把它们写入图特征与上报上下文。
    @objc public func bindAccount(_ accountId: String, scene: String? = nil) {
        stateLock.withLock { boundAccountId = accountId; boundSceneTag = scene }
    }

    /// 解绑账号并清理与该账号相关的状态。
    /// 会重置 Armor 运行时、策略缓存与本地设备聚类，避免跨账号串味。
    @objc public func unbindAccount() {
        resetArmorRuntime()
        stateLock.withLock { boundAccountId = nil; boundSceneTag = nil; currentSessionId = nil; previousSignalIds = []; previousSignalsDigest = nil }
        PolicyManager.shared.clearCachedPolicy()
        LocalDeviceClusterDetector.shared.clear()
    }

    /// 注入服务端下发的策略 JSON。
    /// - Returns: 生产构建恒为 false（本地注入被禁用）；DEBUG 下返回解析/应用是否成功。
    @objc(setServerRiskPolicyJSON:) @discardableResult
    public func setServerRiskPolicyJSON(_ json: String) -> Bool {
        // 生产环境拒绝本地策略注入，防止攻击者直接改写评分规则。
        guard Self.localPolicyInjectionAllowed else { return false }
        return PolicyManager.shared.update(fromJSON: json)
    }

    /// 清除服务端策略，回退到内置默认策略。
    @objc public func clearServerRiskPolicy() { PolicyManager.shared.clear() }
    /// 注册自定义信号提供者。
    public static func register(provider: RiskSignalProvider) { RiskSignalProviderRegistry.shared.register(provider) }
    /// 按 ID 注销信号提供者。
    public static func unregisterProvider(id: String) { RiskSignalProviderRegistry.shared.unregister(id: id) }
    /// 返回当前已注册的信号提供者 ID 列表。
    public static func registeredProviderIDs() -> [String] { RiskSignalProviderRegistry.shared.listIDs() }

    /// 设置远端配置端点；成功创建 Provider 时返回 true 并持久化。
    @discardableResult @objc(setRemoteConfigEndpoint:)
    public func setRemoteConfigEndpoint(_ endpoint: String) -> Bool { configureRemoteConfigProvider(urlString: endpoint) }

    /// 清除远端配置端点与已缓存的远端配置，并重新应用反调试模式。
    @objc public func clearRemoteConfigEndpoint() {
        stateLock.withLock { remoteConfigProvider = nil; remoteConfigEndpoint = nil; latestRemoteConfig = nil; lastRemoteAppStoreSafeProfileFlag = false }
        reapplyAntiDebugRuntimeModeAfterRemoteConfigChange()
        UserDefaults.standard.removeObject(forKey: Self.remoteConfigEndpointKey)
    }

    /// 注入远端配置 JSON（调试/本地联调用）。
    /// - Returns: 生产构建恒为 false；DEBUG 下返回配置是否被接受。
    @discardableResult @objc(setRemoteConfigJSON:)
    public func setRemoteConfigJSON(_ json: String) -> Bool {
        // 与策略注入相同：生产环境禁止本地配置注入。
        guard Self.localPolicyInjectionAllowed else { return false }
        guard let config = RemoteConfig.from(jsonString: json) else { return false }
        return applyRemoteConfigIfAccepted(config, source: "inject_json", validateStrictly: false)
    }

    /// 触发一次远端配置拉取；完成后在主线程回调是否采纳成功。
    /// 未配置端点、网络失败或配置未通过校验时回调 false（保留旧配置）。
    @objc(updateRemoteConfigWithCompletion:)
    public func updateRemoteConfig(completion: @escaping (Bool) -> Void) {
        guard let provider = currentRemoteConfigProvider() else { DispatchQueue.main.async { completion(false) }; return }
        provider.fetchLatest { [weak self] result in
            switch result {
            case .success(let config):
                let ok = self?.applyRemoteConfigIfAccepted(config, source: "fetch_latest") ?? false
                DispatchQueue.main.async { completion(ok) }
            case .failure:
                DispatchQueue.main.async { completion(false) }
            }
        }
    }

    /// 设置文本段引用解析器（用于反篡改基线）；传 nil 恢复默认解析。
    public func setTextSegmentReferenceResolver(_ resolver: (any TextSegmentReferenceResolving)?) {
        stateLock.withLock { textSegmentReferenceResolver = resolver }
    }
}
