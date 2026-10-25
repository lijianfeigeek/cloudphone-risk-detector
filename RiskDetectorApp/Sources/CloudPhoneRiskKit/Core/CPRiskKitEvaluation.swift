// MARK: - CPRiskKit+Evaluation（评估管线）
//
// 从 CloudPhoneRiskKit.swift 拆分：evaluate() 核心管线、信号采集、
// 自适应限流、运行时配置解析与引擎策略构建。
// 位于评估管线的核心：采集证据 → 融合信号 → 本地判决 → 组装报告。
// 安全不变量：强制完整性/篡改证据始终参与；总开关启用时强制低风险；信号消失会被判定为抑制攻击。

import CryptoKit
import CRiskCore
import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// 为 CPRiskKit 提供核心风险评估管线与策略构建能力。
extension CPRiskKit {

    // MARK: - 核心评估管线

    /// 执行一次完整风险评估。
    ///
    /// 流程：解析运行时配置并施加安全地板 → 自适应缓存命中判断 → 注册/封存 Provider →
    /// 确保 anti-debug/Armor 就绪 → 采集上下文与信号 → 融合判决 → 组装报告并更新历史。
    ///
    /// 降级语义：Armor 不可用会转为风险信号而非中断评估；Provider 超时由各自实现降级；
    /// 总开关（kill switch）启用时直接产出低风险/放行结论。
    /// - Parameters:
    ///   - config: 宿主配置。
    ///   - scenario: 业务场景。
    /// - Returns: 组装完成的评估报告。
    internal func evaluateImpl(config: CPRiskConfig, scenario: RiskScenario) -> CPRiskReport {
        var runtimeConfig = resolveRuntimeConfig(from: config)
        // 先钳制阈值，防止越界配置绕过阈值判断
        enforceSecurityFloor(&runtimeConfig)
        let remoteConfig = config.enableRemoteConfig ? currentRemoteConfig() : nil
        let realtimeAdaptiveProfile = resolveRealtimeAdaptiveProfile(remoteConfig: remoteConfig)

        // 自适应限流：高压力期间复用缓存报告，降低设备采集与检测开销
        if let cached = maybeReturnAdaptiveCachedReport(
            profile: realtimeAdaptiveProfile,
            scenario: scenario,
            runtimeConfig: runtimeConfig,
            remoteConfig: remoteConfig
        ) {
            return cached
        }

        Logger.log(
            "evaluate(config,scenario): scenario=\(scenario.identifier) threshold=\(runtimeConfig.threshold) " +
            "behavior=\(runtimeConfig.enableBehaviorDetect) network=\(runtimeConfig.enableNetworkSignals) " +
            "remote=\(remoteConfig != nil) temporal=\(config.enableTemporalAnalysis) antiTamper=\(config.enableAntiTamper)"
        )

        registerProviders(for: config)
        // 注册表一旦封存就不再接受新 Provider，防止运行期被注入伪造信号源
        if !RiskSignalProviderRegistry.shared.isSealed {
            RiskSignalProviderRegistry.shared.seal()
            ConditionExpression.sealCustomEvaluators()
        }
        applyAntiDebugRuntimeConfigToCore(config)
        let appStoreSafeEval = stateLock.withLock { lastAppliedEffectiveAntiDebugMode == .appStoreSafe }
        if !appStoreSafeEval {
            // 每次评估前重新加固：攻击者可能在两次评估之间恢复 ptrace/异常端口
            cprisk_deny_attach()
            cprisk_register_exception_handler()
        }
        let armorRuntimeSnapshot = ensureArmorRuntimeStarted(trigger: "evaluate", config: nil)
        if armorRuntimeSnapshot.status == .active {
            // Armor 已启动时复核运行期完整性，检测评估间隙的篡改
            _ = cprisk_recheck_integrity()
        }
        if !appStoreSafeEval {
            Self.maybeVerifyExceptionHandler()
        }

        let context = buildRiskContext(config: runtimeConfig)
        let serverPolicy = PolicyManager.shared.activePolicy
        let watchdogSnapshot = antiDebugWatchdogSnapshot()
        let snapshot = RiskSnapshot(
            deviceID: context.deviceID,
            device: context.device,
            network: context.network,
            behavior: context.behavior,
            jailbreak: context.jailbreak,
            mutationStrategy: resolveMutationStrategy(from: serverPolicy),
            antiDebugWatchdogSupported: watchdogSnapshot.supported,
            libcFallbackUsedMask: watchdogSnapshot.libcFallbackUsedMask,
            libcFallbackEventTotal: watchdogSnapshot.libcFallbackEventTotal
        )
        let serverSignals = RiskSignalProviderRegistry.shared.serverSignals(snapshot: snapshot)
        let (acctIdForGraph, sessIdForGraph) = stateLock.withLock {
            (boundAccountId, currentSessionId)
        }

        let graphNodeDescriptor = GraphFeatureCollector.collect(
            snapshot: snapshot,
            serverSignals: serverSignals,
            accountId: acctIdForGraph
        )
        var extraSignalsForGraph: [RiskSignal] = []
        // 本地设备簇检测：同一硬件画像在多账号/多会话间聚集时产出风险信号
        if let localClusterSignal = LocalDeviceClusterDetector.shared.recordAndDetect(
            hwProfileHash: graphNodeDescriptor.hwProfileHash,
            key: graphNodeDescriptor.installationKey ?? sessIdForGraph
        ) {
            extraSignalsForGraph = [localClusterSignal]
        }

        let capabilityRuntime = runCapabilityProbe(remoteConfig: remoteConfig)
        var extraSignals = RiskSignalProviderRegistry.shared.signals(snapshot: snapshot)
        if let armorRuntimeSignal = Self.armorRuntimeSignal(from: armorRuntimeSnapshot) {
            extraSignals.append(armorRuntimeSignal)
        }
        // 完整性被投毒是不可忽略的强信号，必须进入本轮判决
        if cprisk_is_integrity_poisoned() != 0 {
            extraSignals.append(Self.integrityRecheckPoisonedSignal())
        }
        extraSignals.append(capabilityRuntime.score.toSignal())
        extraSignals.append(contentsOf: extraSignalsForGraph)
        extraSignals.append(contentsOf: ChallengeResultStore.shared.consumePendingMismatchSignals())

        if let provider = currentRemoteConfigProvider(), provider.isConfigStale {
            // 配置陈旧给低权重信号：提示服务端配置未更新，但不足以单独判定风险
            extraSignals.append(RiskSignal(
                id: "remote_config_stale",
                category: "config",
                score: 0,
                evidence: ["age_seconds": "\(Int(provider.configAge))"],
                state: .soft(confidence: 0.3),
                layer: 4,
                weightHint: 10
            ))
        }

        let allCurrentSignalIds = Set(extraSignals.map(\.id))
        let prevIds = stateLock.withLock { previousSignalIds }
        if !prevIds.isEmpty {
            let previousHighRisk = prevIds.intersection(Self.highRiskSignalIds)
            let currentHighRisk = allCurrentSignalIds.intersection(Self.highRiskSignalIds)
            let suppressedIds = previousHighRisk.subtracting(currentHighRisk)
            // 反绕过：上一轮出现的高危信号若在本轮凭空消失（≥2 个，或全部消失），
            // 极可能是攻击者屏蔽了检测器，而非环境真的变好。
            if suppressedIds.count >= 2 || (previousHighRisk.count > 0 && currentHighRisk.isEmpty) {
                let evidence = [
                    "suppressed_ids": suppressedIds.sorted().joined(separator: ","),
                    "previous_count": "\(previousHighRisk.count)",
                    "current_count": "\(currentHighRisk.count)"
                ]
                extraSignals.append(RiskSignal(
                    id: "signal_suppression_detected",
                    category: "integrity",
                    score: 80,
                    evidence: evidence,
                    state: .tampered,
                    layer: 1,
                    weightHint: 80
                ))
                Logger.log("signal_suppression: \(suppressedIds.sorted()) disappeared between evaluations")
            }
        }

        extraSignals.append(
            contentsOf: ScenarioPolicySignalBridge.deriveSignals(
                snapshot: snapshot,
                existingSignals: extraSignals
            )
        )

        let policy = buildEnginePolicy(
            runtimeConfig: runtimeConfig,
            remoteConfig: remoteConfig,
            enableTemporalAnalysis: config.enableTemporalAnalysis,
            serverPolicy: serverPolicy,
            realtimeAdaptiveProfile: realtimeAdaptiveProfile
        )
        if policy.killSwitchEnabled {
            Logger.log("⚠️ killSwitch is ACTIVE — evaluation will force low-risk/allow verdict")
        }
        let assessmentEngine = RiskDetectionEngine(policy: policy, enableLogging: Logger.isEnabled)
        let verdict: LocalAssessment = assessmentEngine.evaluate(
            context: context,
            scenario: scenario,
            extraSignals: extraSignals
        )

        let scoreReport = RiskScoreReport(
            score: verdict.score,
            isHighRisk: verdict.isHighRisk,
            signals: verdict.signals,
            summary: verdict.summary,
            compressedDigest: verdict.compressedDigest,
            mappingVersion: verdict.mappingVersion,
            action: verdict.internalAction,
            primaryReasons: verdict.primaryReasons,
            decisionMetadata: verdict.decisionMetadata
        )

        Logger.log(
            "final: score=\(scoreReport.score) isHighRisk=\(scoreReport.isHighRisk) " +
            "signals=\(scoreReport.signals.count) summary=\(scoreReport.summary)"
        )

        let tamperedSignals = extraSignals.filter {
            if case .tampered? = $0.state { return true }
            return false
        }
        let antiTamperHit = tamperedSignals.contains { $0.category == ObfuscatedConstants.categoryAntiTamper || $0.category == "integrity" }
        var mergedJailbreak = context.jailbreak
        // 反篡改命中即使越狱引擎未判定越狱，也应提升越狱置信度（篡改通常伴随越狱手段）
        if antiTamperHit && !mergedJailbreak.isJailbroken {
            let antiTamperMethods = tamperedSignals
                .filter { $0.category == ObfuscatedConstants.categoryAntiTamper || $0.category == "integrity" }
                .map { "\(ObfuscatedConstants.antiTamperMethodPrefix)\($0.id)" }
            // 置信度取“原置信度”和“篡改分数总和 × 0.5”的较大者，上限 100
            let boostedConfidence = max(mergedJailbreak.confidence, tamperedSignals.map { $0.score }.reduce(0, +) * 0.5)
            mergedJailbreak = DetectionResult(
                isJailbroken: boostedConfidence >= 50,
                confidence: min(100, boostedConfidence),
                detectedMethods: mergedJailbreak.detectedMethods + antiTamperMethods,
                details: mergedJailbreak.details
            )
        }
        let finalContext = RiskContext(
            device: context.device,
            deviceID: context.deviceID,
            network: context.network,
            behavior: context.behavior,
            jailbreak: mergedJailbreak
        )

        let out = CPRiskReport(context: finalContext, report: scoreReport)
        out.setServerSignals(serverSignals)
        out.setGraphNodeDescriptor(graphNodeDescriptor)
        let (acctId, sessId, scnTag) = stateLock.withLock {
            (boundAccountId, currentSessionId, boundSceneTag)
        }
        out.setGraphBindings(accountId: acctId, sessionId: sessId, sceneTag: scnTag)

        RiskHistoryStore.shared.append(
            RiskHistoryEvent(
                t: Date().timeIntervalSince1970,
                score: scoreReport.score,
                isHighRisk: scoreReport.isHighRisk,
                summary: scoreReport.summary
            )
        )

        let pattern = RiskHistoryStore.shared.pattern()
        out.setLocalSignals(
            LocalSignals(
                timePattern: pattern,
                cloudPhone: CloudPhoneLocalSignalsBuilder.build(
                    device: context.device,
                    behavior: context.behavior,
                    timePattern: pattern
                )
            )
        )

        stateLock.withLock {
            previousSignalIds = allCurrentSignalIds
            previousSignalsDigest = SignalDigest.computeFullDigest(verdict.signals)
        }

        if let challengeBinding = buildChallengeBindingIfNeeded(
            remoteConfig: remoteConfig,
            serverPolicy: serverPolicy,
            capabilityRuntime: capabilityRuntime,
            signals: verdict.signals,
            deviceID: context.deviceID
        ) {
            out.setChallengeBinding(challengeBinding)
            Logger.log(
                "challenge.binding: challengeId=\(challengeBinding.challengeId) " +
                "probes=\(challengeBinding.probeIds.count) reason=\(challengeBinding.triggerReason ?? "n/a")"
            )
        }

        updateAdaptiveCachedReport(
            out,
            profile: realtimeAdaptiveProfile,
            scenario: scenario,
            runtimeConfig: runtimeConfig,
            remoteConfig: remoteConfig
        )

        // 把敌对环境相关的 C 层信号分发给已注册的 reporter，
        // 供宿主转发到服务端做第二层校验——该链路无法通过二进制补丁绕过。
        let reporter = stateLock.withLock { hostileEnvironmentReporter }
        dispatchHostileEnvironmentReport(to: reporter)

        return out
    }

    // MARK: - 风险上下文

    /// 构建本次评估的风险上下文。
    ///
    /// UIKit 平台采集触摸/运动行为与耦合特征；其他平台使用空行为与“不支持平台”的
    /// 越狱占位结果，保证评估仍可完成（降级而非中断）。
    /// - Parameter config: 运行时风险配置。
    /// - Returns: 设备、网络、行为与越狱证据的上下文。
    internal func buildRiskContext(config: RiskConfig) -> RiskContext {
#if canImport(UIKit)
        // snapshotDetailAndReset 会同时取出采样数据并清零累加器，避免重复计分
        let (touchMetrics, actionTimestamps) = touchCapture.snapshotDetailAndReset()
        let (motionMetrics, motionSeries) = motionSampler.snapshotDetailAndReset()
        let coupling = BehaviorCoupling.touchMotionCorrelation(
            actionTimestamps: actionTimestamps,
            motion: motionSeries
        )
        #if DEBUG
        Logger.log("behavior.coupling: actions=\(actionTimestamps.count) corr=\(coupling?.description ?? "nil")")
        #endif

        return RiskContext(
            device: DeviceFingerprint.current(),
            deviceID: KeychainDeviceID.shared.getOrCreate(),
            network: NetworkSignals.current(),
            behavior: BehaviorSignals(
                touch: touchMetrics,
                motion: motionMetrics,
                touchMotionCorrelation: coupling,
                actionCount: actionTimestamps.count
            ),
            jailbreak: jailbreakEngine.detect(config: config.jailbreak)
        )
#else
        // 非 UIKit 平台：行为信号置空，越狱明确标记不支持，避免误判为越狱
        return RiskContext(
            device: DeviceFingerprint.current(),
            deviceID: KeychainDeviceID.shared.getOrCreate(),
            network: NetworkSignals.current(),
            behavior: BehaviorSignals(
                touch: TouchMetrics(
                    sampleCount: 0,
                    tapCount: 0,
                    swipeCount: 0,
                    coordinateSpread: nil,
                    intervalCV: nil,
                    averageLinearity: nil,
                    forceVariance: nil,
                    majorRadiusVariance: nil
                ),
                motion: .empty
            ),
            jailbreak: DetectionResult(
                isJailbroken: false,
                confidence: 0,
                detectedMethods: [],
                details: "unsupported_platform"
            )
        )
#endif
    }

    // MARK: - 安全地板
    //
    // 注意：本函数只做“配置缺失时补安全默认值 + 越界钳制”，不再在 Release 下
    // 强制把用户显式关闭的检测开关改回 true。原因：
    // - `RiskConfig` / `JailbreakConfig` 的初始化默认值本身就是安全默认值
    //  （检测开关默认全开），“缺失”即“未显式赋值”，无需在此改写；
    // - 用户显式关闭（如 `JailbreakConfig.light` 关闭 env/sysctl/scheme/hook、
    //   或宿主设置 `enableAntiTamper = false`）是合法调用方决策，强制改写会
    //   让轻量/低功耗等配置失效且无法从外部观测。
    // - 远程下发的配置仍由 `RemoteConfig.enforcingReleaseSecurityFloor()`
    //   单独做安全地板（远程配置不可降级本地安全基线），与本函数职责不同。
    // 每次实际改写（阈值钳制）都会记录日志，便于审计。

    /// 钳制越界阈值到合法范围。
    ///
    /// 只修改阈值，不触碰任何 Bool 开关（理由见上方注释）；每次改写都会记录日志。
    /// - Parameter config: 待修正的运行时配置（inout）。
    internal func enforceSecurityFloor(_ config: inout RiskConfig) {
        // 仅钳制越界阈值到合法范围；不触碰任何 Bool 开关。
        if config.jailbreak.threshold > 100 || config.jailbreak.threshold < 0 {
            let clamped = min(max(config.jailbreak.threshold, 0), 100)
            Logger.log("enforceSecurityFloor: jailbreak.threshold \(config.jailbreak.threshold) clamped to \(clamped)")
            config.jailbreak.threshold = clamped
        }
        if config.threshold > 100 || config.threshold < 0 {
            let clamped = min(max(config.threshold, 0), 100)
            Logger.log("enforceSecurityFloor: threshold \(config.threshold) clamped to \(clamped)")
            config.threshold = clamped
        }
    }

    // MARK: - 运行时配置解析

    /// 把宿主配置解析为运行时 `RiskConfig`。
    ///
    /// 启用远程配置时优先使用远程配置；远程不可用则回退到本地配置（降级语义）。
    /// `enableAntiTamper = false` 时额外关闭 Hook 检测。
    /// - Parameter config: 宿主配置。
    /// - Returns: 可用于评估的运行时配置。
    internal func resolveRuntimeConfig(from config: CPRiskConfig) -> RiskConfig {
        var resolved: RiskConfig

        if config.enableRemoteConfig {
            _ = configureRemoteConfigProvider(urlString: config.remoteConfigURLString)
            if let remoteConfig = currentRemoteConfig() {
                resolved = remoteConfig.toRiskConfig()
            } else {
                // 远程配置不可用：回退本地配置，保证评估不中断
                resolved = config.toSwift()
            }
        } else {
            resolved = config.toSwift()
        }

        // 关闭反篡改总开关时，Hook 检测也必须关闭（避免残留子检测）
        if !config.enableAntiTamper {
            resolved.jailbreak.enableHookDetect = false
        }

        return resolved
    }

    // MARK: - 引擎策略

    /// 构建决策引擎策略。
    ///
    /// 阈值优先级：服务端策略 > 远程配置 > 场景默认；并保证
    /// medium < high < critical 且均落在 [0,100]。
    /// 权重优先级：远程权重 > 场景权重（关闭时序分析时 time 权重归零）。
    /// - Parameters:
    ///   - runtimeConfig: 运行时配置。
    ///   - remoteConfig: 远程配置（可选）。
    ///   - enableTemporalAnalysis: 是否启用时序分析。
    ///   - serverPolicy: 服务端下发的策略（可选）。
    ///   - realtimeAdaptiveProfile: 实时自适应配置档（可选）。
    /// - Returns: 组装好的引擎策略。
    internal func buildEnginePolicy(
        runtimeConfig: RiskConfig,
        remoteConfig: RemoteConfig?,
        enableTemporalAnalysis: Bool,
        serverPolicy: ServerRiskPolicy?,
        realtimeAdaptiveProfile: RealtimeAdaptiveProfile?
    ) -> EnginePolicy {
        let remoteWeights = remoteConfig.map { config in
            SignalWeights(
                jailbreak: config.policy.weights.jailbreak,
                network: config.policy.weights.network,
                behavior: config.policy.weights.behavior,
                // 远程配置中的 cloudPhone 权重映射到本地 device 维度
                device: config.policy.weights.cloudPhone,
                time: enableTemporalAnalysis ? config.policy.weights.timePattern : 0
            )
        }

        let serverHigh = serverPolicy?.thresholds.challenge
        // 高风险阈值必须落在 [1,100]，避免 0 导致所有请求都判高风险
        let highThreshold = max(1, min(100, serverHigh ?? runtimeConfig.threshold))
        let remoteMedium = remoteConfig?.policy.mediumThreshold

        var scenarioPolicies: [RiskScenario: ScenarioPolicy] = [:]
        for scenario in RiskScenario.allCases {
            let base = ScenarioPolicy.policy(for: scenario)
            let rawMedium = serverPolicy?.thresholds.monitor ?? remoteMedium ?? base.mediumThreshold
            // 中风险阈值必须严格小于高风险阈值，防止等级判定区间重叠
            let mediumThreshold = max(0, min(highThreshold - 1, rawMedium))
            let serverCritical = serverPolicy?.thresholds.block
            // 严重阈值至少比高风险高 1，且默认比高风险高 20
            let criticalThreshold = min(
                100,
                max(highThreshold + 1, serverCritical ?? max(base.criticalThreshold, highThreshold + 20))
            )

            let effectiveWeights: SignalWeights
            if let remoteWeights {
                effectiveWeights = remoteWeights
            } else if enableTemporalAnalysis {
                effectiveWeights = base.signalWeights
            } else {
                // 关闭时序分析时把 time 权重归零，避免无数据维度稀释其他信号
                effectiveWeights = SignalWeights(
                    jailbreak: base.signalWeights.jailbreak,
                    network: base.signalWeights.network,
                    behavior: base.signalWeights.behavior,
                    device: base.signalWeights.device,
                    time: 0
                )
            }
            let adaptiveWeights = applyRealtimeAdaptiveWeightScale(
                effectiveWeights,
                profile: realtimeAdaptiveProfile
            )

            scenarioPolicies[scenario] = ScenarioPolicy(
                mediumThreshold: mediumThreshold,
                highThreshold: highThreshold,
                criticalThreshold: criticalThreshold,
                actionMapping: base.actionMapping,
                signalWeights: adaptiveWeights,
                comboRules: base.comboRules,
                enableForceRules: base.enableForceRules,
                compressedVerdictRules: base.compressedVerdictRules
            )
        }

        let mutationStrategy = resolveMutationStrategy(from: serverPolicy)

        let blindChallengePolicy = serverPolicy?.blindChallenge.map { challenge in
            BlindChallengePolicy(
                enabled: challenge.enabled,
                challengeSalt: challenge.challengeSalt,
                windowSeconds: challenge.windowSeconds,
                rules: challenge.rules.map { rule in
                    BlindChallengeRule(
                        id: rule.id,
                        allOfSignalIDs: rule.allOfSignalIDs,
                        anyOfSignalIDs: rule.anyOfSignalIDs,
                        minTamperedCount: rule.minTamperedCount,
                        minDistinctRiskLayers: rule.minDistinctRiskLayers,
                        requireCrossLayerInconsistency: rule.requireCrossLayerInconsistency,
                        weight: rule.weight
                    )
                }
            )
        }
        return EnginePolicy(
            name: remoteConfig.map { "remote_\($0.version)" } ?? "local_sdk3",
            version: remoteConfig.map { String($0.version) } ?? "3.0-local",
            // 远程 kill switch 或本地稳定性总开关任一启用即生效
            killSwitchEnabled: (remoteConfig?.securityHardening?.killSwitchEnabled ?? false)
                || ProtectionStabilityStore.shared.isLocalStabilityKillSwitchEnabled(),
            enableNetworkSignals: runtimeConfig.enableNetworkSignals,
            enableBehaviorDetection: runtimeConfig.enableBehaviorDetect,
            enableDeviceFingerprint: true,
            forceActionOnJailbreak: .block,
            signalWeightOverrides: serverPolicy?.signalWeights ?? [:],
            mutationStrategy: mutationStrategy,
            blindChallengePolicy: blindChallengePolicy,
            serverBlocklist: serverPolicy?.blocklist,
            blocklistAction: (serverPolicy?.blocklist.isEmpty == false) ? .block : nil,
            scenarioPolicies: scenarioPolicies
        )
    }

    // MARK: - 自适应遥测

    /// 解析实时自适应配置档。
    ///
    /// 远程配置与外部服务反馈任一启用时生效；反馈缺失时使用安全默认档。
    /// 所有权重/间隔均做边界钳制，防止异常反馈把评估压垮或放大。
    /// - Parameter remoteConfig: 远程配置（可选）。
    /// - Returns: 自适应配置档；未启用时返回 `nil`。
    internal func resolveRealtimeAdaptiveProfile(remoteConfig: RemoteConfig?) -> RealtimeAdaptiveProfile? {
        let remoteAdaptive = remoteConfig?.realtimeTelemetryAdaptive?.enforcingReleaseSecurityFloor()
        let feedback = ExternalServerAggregateProvider.shared.realtimeAdaptiveFeedbackSnapshot()
        let enabled = (remoteAdaptive?.enabled ?? false) || (feedback != nil)
        guard enabled else { return nil }

        // 远程未下发时使用安全默认档：权重缩放 0.7–1.3 倍，反馈有效期 180 秒
        let safeAdaptive = remoteAdaptive ?? RealtimeTelemetryAdaptiveConfig(
            enabled: true,
            baseMinEvaluationIntervalMillis: 0,
            highPressureMinEvaluationIntervalMillis: 0,
            defaultWeightScaleBps: 10_000,
            minWeightScaleBps: 7_000,
            maxWeightScaleBps: 13_000,
            feedbackTTLSeconds: 180
        )
        let minBps = safeAdaptive.minWeightScaleBps
        // 防御 max < min 的非法配置
        let maxBps = max(safeAdaptive.maxWeightScaleBps, minBps)

        let pressure = {
            guard let value = feedback?.riskPressure, value.isFinite else { return 0.0 }
            // 风险压力归一化到 [0,1]，非有限值按 0 处理
            return min(max(value, 0), 1)
        }()

        let minIntervalMillis: Int
        if let direct = feedback?.minEvaluationIntervalMillis {
            // 反馈给出直接间隔时钳制到 [0, 60s]，防止被恶意放大成永久缓存
            minIntervalMillis = min(max(direct, 0), 60_000)
        } else {
            // 在基础间隔与高压间隔之间按压力线性插值
            let base = max(0, safeAdaptive.baseMinEvaluationIntervalMillis)
            let high = max(0, min(base, safeAdaptive.highPressureMinEvaluationIntervalMillis))
            let interpolated = Double(base) - (Double(base - high) * pressure)
            minIntervalMillis = Int(interpolated.rounded())
        }

        let defaultScale = min(
            max(feedback?.defaultWeightScaleBps ?? safeAdaptive.defaultWeightScaleBps, minBps),
            maxBps
        )
        var categoryScales: [String: Int] = [:]
        let feedbackScales = feedback?.categoryWeightScaleBps ?? [:]
        // 只允许固定五个类别，未知类别不进入策略，避免反馈注入任意维度
        for key in ["jailbreak", "network", "behavior", "device", "time"] {
            let raw = feedbackScales[key] ?? defaultScale
            categoryScales[key] = min(max(raw, minBps), maxBps)
        }

        let source = [
            remoteAdaptive != nil ? "remote_config" : "fallback",
            feedback?.source
        ]
            .compactMap { $0 }
            .joined(separator: "+")

        return RealtimeAdaptiveProfile(
            enabled: true,
            minEvaluationIntervalMillis: minIntervalMillis,
            defaultWeightScaleBps: defaultScale,
            categoryWeightScaleBps: categoryScales,
            source: source
        )
    }

    /// 按自适应配置缩放信号权重。
    ///
    /// BPS 以 10000 为 1.0 倍；结果钳制到 [0,10]，非有限值回退原权重。
    /// - Parameters:
    ///   - weights: 原始权重。
    ///   - profile: 自适应配置档；`nil` 或未启用时原样返回。
    /// - Returns: 缩放后的权重。
    internal func applyRealtimeAdaptiveWeightScale(
        _ weights: SignalWeights,
        profile: RealtimeAdaptiveProfile?
    ) -> SignalWeights {
        guard let profile, profile.enabled else { return weights }

        /// 按类别 BPS 缩放单个权重，并钳制到 [0,10]。
        func scaled(_ key: String, _ base: Double) -> Double {
            let bps = profile.categoryWeightScaleBps[key] ?? profile.defaultWeightScaleBps
            // 10000 BPS = 1.0 倍
            let candidate = base * (Double(bps) / 10_000.0)
            guard candidate.isFinite else { return base }
            return min(max(candidate, 0), 10)
        }

        return SignalWeights(
            jailbreak: scaled("jailbreak", weights.jailbreak),
            network: scaled("network", weights.network),
            behavior: scaled("behavior", weights.behavior),
            device: scaled("device", weights.device),
            time: scaled("time", weights.time)
        )
    }

    // MARK: - 自适应缓存

    /// 计算自适应缓存键。
    ///
    /// 键涵盖场景、阈值、行为/网络开关、远程版本与自适应签名；
    /// 任一因素变化都会使缓存失效，避免返回与当前配置不符的报告。
    /// - Returns: 稳定的缓存键字符串。
    internal func adaptiveCacheKey(
        scenario: RiskScenario,
        runtimeConfig: RiskConfig,
        remoteConfig: RemoteConfig?,
        profile: RealtimeAdaptiveProfile?
    ) -> String {
        // 阈值保留 3 位小数，避免浮点尾差导致缓存键抖动
        let threshold = String(format: "%.3f", runtimeConfig.threshold)
        let remoteVersion = remoteConfig.map { String($0.version) } ?? "none"
        let profileSignature = profile?.signature ?? "adaptive_off"
        return [
            "scn=\(scenario.identifier)",
            "thr=\(threshold)",
            "beh=\(runtimeConfig.enableBehaviorDetect ? 1 : 0)",
            "net=\(runtimeConfig.enableNetworkSignals ? 1 : 0)",
            "rv=\(remoteVersion)",
            profileSignature
        ].joined(separator: "|")
    }

    /// 若处于自适应限流窗口内，返回缓存报告。
    ///
    /// 仅当配置档启用、最小间隔 > 0、缓存键一致且距上次评估不足间隔时命中。
    /// - Returns: 缓存报告；不满足条件返回 `nil`。
    internal func maybeReturnAdaptiveCachedReport(
        profile: RealtimeAdaptiveProfile?,
        scenario: RiskScenario,
        runtimeConfig: RiskConfig,
        remoteConfig: RemoteConfig?
    ) -> CPRiskReport? {
        guard let profile,
              profile.enabled,
              profile.minEvaluationIntervalMillis > 0 else {
            return nil
        }

        let now = Date().timeIntervalSince1970
        let key = adaptiveCacheKey(
            scenario: scenario,
            runtimeConfig: runtimeConfig,
            remoteConfig: remoteConfig,
            profile: profile
        )

        let (cachedReport, cachedKey, lastEvalAt) = stateLock.withLock {
            (adaptiveCachedReport, adaptiveCachedKey, adaptiveLastEvaluationAtEpochSeconds)
        }
        // 缓存键不一致说明配置/场景已变化，不能复用旧报告
        guard let cachedReport, cachedKey == key else {
            return nil
        }

        let elapsedMillis = Int((now - lastEvalAt) * 1000)
        if elapsedMillis < profile.minEvaluationIntervalMillis {
            Logger.log(
                "adaptive.telemetry: reuse cached report elapsed_ms=\(elapsedMillis) " +
                    "min_interval_ms=\(profile.minEvaluationIntervalMillis) source=\(profile.source)"
            )
            return cachedReport
        }
        return nil
    }

    /// 更新自适应缓存。
    ///
    /// 配置档未启用时清空缓存（避免旧数据在后续启用时被误用）；
    /// 启用时记录报告、缓存键与时间戳。
    internal func updateAdaptiveCachedReport(
        _ report: CPRiskReport,
        profile: RealtimeAdaptiveProfile?,
        scenario: RiskScenario,
        runtimeConfig: RiskConfig,
        remoteConfig: RemoteConfig?
    ) {
        guard let profile, profile.enabled else {
            stateLock.withLock {
                adaptiveCachedReport = nil
                adaptiveCachedKey = nil
                adaptiveLastEvaluationAtEpochSeconds = 0
            }
            return
        }

        let key = adaptiveCacheKey(
            scenario: scenario,
            runtimeConfig: runtimeConfig,
            remoteConfig: remoteConfig,
            profile: profile
        )
        let now = Date().timeIntervalSince1970
        stateLock.withLock {
            adaptiveCachedReport = report
            adaptiveCachedKey = key
            adaptiveLastEvaluationAtEpochSeconds = now
        }
    }

    // MARK: - 变异策略

    /// 把服务端变异配置转换为引擎变异策略。
    /// - Parameter serverPolicy: 服务端策略。
    /// - Returns: 变异策略；未下发时返回 `nil`。
    internal func resolveMutationStrategy(from serverPolicy: ServerRiskPolicy?) -> MutationStrategy? {
        serverPolicy?.mutation.map { mutation in
            MutationStrategy(
                seed: mutation.seed,
                shuffleChecks: mutation.shuffleChecks,
                thresholdJitterBps: mutation.thresholdJitterBps,
                scoreJitterBps: mutation.scoreJitterBps
            )
        }
    }

    // MARK: - 能力探针

    /// 运行能力探针。
    ///
    /// 有远程探针配置时按其构建引擎，否则使用默认引擎；
    /// 探针结果只作为附加信号，不会单独中断评估。
    /// - Parameter remoteConfig: 远程配置（可选）。
    /// - Returns: 能力评分与探针明细。
    internal func runCapabilityProbe(remoteConfig: RemoteConfig?) -> CapabilityProbeRuntimeResult {
        let engine: CapabilityProbeEngine
        if let probeConfig = remoteConfig?.probeConfig {
            engine = CapabilityProbeEngine.fromRemoteConfig(probeConfig)
        } else {
            engine = CapabilityProbeEngine()
        }

        let detailed = engine.evaluateDetailed()
        Logger.log(
            "capability.probe: anomaly=\(detailed.score.basicAnomalyCount) " +
            "quality=\(detailed.score.qualitySuspicion) total=\(detailed.score.totalProbes)"
        )

        return CapabilityProbeRuntimeResult(score: detailed.score, probes: detailed.probes)
    }

    // MARK: - 挑战绑定

    /// 按需构建挑战绑定载荷。
    ///
    /// 必须同时满足：本地合成开关允许、远程加固启用挑战绑定、服务端下发盲挑战且启用、
    /// 探针池非空、触发规则命中、挑战有效且未提交（防重放）。
    /// 任一条件不满足都返回 `nil`（跳过绑定），不影响主评估。
    /// - Returns: 挑战绑定载荷；无需绑定时返回 `nil`。
    internal func buildChallengeBindingIfNeeded(
        remoteConfig: RemoteConfig?,
        serverPolicy: ServerRiskPolicy?,
        capabilityRuntime: CapabilityProbeRuntimeResult,
        signals: [RiskSignal],
        deviceID: String
    ) -> ChallengeBindingPayload? {
        // Release 默认禁止本地合成挑战，必须由服务端下发，防止客户端伪造挑战
        guard Self.localSynthesizedChallengeBindingAllowed else {
            Logger.log("challenge.binding skipped: local synthesized binding disabled in release; require server-issued challenge")
            return nil
        }

        let hardening = remoteConfig?.securityHardening ?? .default
        guard hardening.enableChallengeBinding else {
            return nil
        }

        guard let blindConfig = serverPolicy?.blindChallenge, blindConfig.enabled else {
            Logger.log("challenge.binding skipped: missing server blindChallenge context")
            return nil
        }

        if blindConfig.probePool.isEmpty {
            Logger.log("challenge.binding skipped: probePool is empty")
            return nil
        }

        // 统计篡改态信号数量，作为触发规则输入
        let tamperedCount = signals.reduce(into: 0) { partialResult, signal in
            if case .tampered? = signal.state {
                partialResult += 1
            }
        }

        let blindRules = blindConfig.rules
        let trigger = ChallengeTrigger.shouldTriggerBlindChallenge(
            capabilityScore: capabilityRuntime.score,
            tamperedCount: tamperedCount,
            existingRules: blindRules
        )
        guard trigger.triggered else {
            return nil
        }

        guard let challenge = buildBlindChallenge(config: blindConfig, deviceID: deviceID) else {
            Logger.log("challenge.binding skipped: failed to build challenge from server config")
            return nil
        }
        guard ChallengeTrigger.isChallengeValid(challenge) else {
            return nil
        }

        let session = ChallengeSession.shared
        // 防重放：同一 challengeId 只能提交一次
        if session.hasSubmitted(challenge.challengeId) {
            Logger.log("challenge.binding skipped: challengeId=\(challenge.challengeId) already submitted (replay)")
            return nil
        }
        guard session.markSubmitted(challenge.challengeId) else {
            return nil
        }
        let expectedHash = ChallengeTrigger.computeExpectedHash(
            seed: challenge.seed,
            deviceFingerprint: deviceID
        )
        return ChallengeTrigger.buildChallengeBindingPayload(
            challenge: challenge,
            capabilityScore: capabilityRuntime.score,
            tamperedCount: tamperedCount,
            executedProbeIDs: capabilityRuntime.probes.map(\.id),
            triggerReason: "local_sdk_synthesized/\(trigger.reason)",
            expectedHash: expectedHash
        )
    }

    /// 根据服务端盲挑战配置构建一次挑战。
    ///
    /// 盐值为空、探针池为空或选择结果为空时返回 `nil`；
    /// TTL 下限 10 秒，防止过期配置产生“立即失效”的挑战。
    /// - Parameters:
    ///   - config: 服务端盲挑战配置。
    ///   - deviceID: 设备标识，参与种子派生。
    /// - Returns: 盲挑战；无法构建时返回 `nil`。
    internal func buildBlindChallenge(
        config: ServerRiskPolicy.BlindChallengeConfig,
        deviceID: String
    ) -> ChallengeTrigger.BlindChallenge? {
        let now = ChallengeTrigger.nowMillis()
        // TTL 至少 10 秒（10000ms），避免配置错误导致挑战立刻失效
        let ttl = max(10_000, config.challengeTTLMillis)
        let salt = config.challengeSalt.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !salt.isEmpty else {
            return nil
        }

        let seedSource = "\(salt)|\(deviceID)|\(now)"
        let selectedProbeIDs = selectChallengeProbeIDs(
            source: config.probePool,
            seedSource: seedSource
        )
        guard !selectedProbeIDs.isEmpty else {
            return nil
        }

        // 挑战种子加入随机 UUID（去横线），保证每次挑战不可预测
        let challengeSeed = "\(salt):\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
        return ChallengeTrigger.BlindChallenge(
            challengeId: UUID().uuidString,
            probeIds: selectedProbeIDs,
            seed: challengeSeed,
            expiresAt: now + ttl
        )
    }

    /// 从探针池中确定性地选择探针 ID。
    ///
    /// 先规范化（去空白、去空、去重、排序），再用种子派生滚动哈希决定起始位置，
    /// 从而在不同设备/时间得到不同但可复现的选择，避免固定顺序被攻击者预测。
    /// - Parameters:
    ///   - source: 候选探针 ID 列表。
    ///   - seedSource: 派生种子（盐 + 设备 + 时间）。
    ///   - maxCount: 最多选择数量，默认 3。
    /// - Returns: 选中的探针 ID 列表；池为空时返回空数组。
    internal func selectChallengeProbeIDs(
        source: [String],
        seedSource: String,
        maxCount: Int = 3
    ) -> [String] {
        let normalized = Array(Set(source.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty })).sorted()
        guard !normalized.isEmpty else {
            return []
        }

        // 简单 31 进制滚动哈希，掩码到 31 位非负整数
        let rolling = seedSource.utf8.reduce(0) { partial, byte in
            ((partial &* 31) &+ Int(byte)) & 0x7fffffff
        }
        let start = rolling % normalized.count

        var selected: [String] = []
        selected.reserveCapacity(min(maxCount, normalized.count))
        // 环形遍历，保证不重复且数量不超过池大小
        for index in 0..<min(maxCount, normalized.count) {
            selected.append(normalized[(start + index) % normalized.count])
        }
        return selected
    }

}
