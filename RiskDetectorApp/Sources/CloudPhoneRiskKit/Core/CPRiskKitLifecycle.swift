// MARK: - CPRiskKit+Lifecycle（生命周期）
//
// 从 CloudPhoneRiskKit.swift 拆分：start()、stop()、deinit、
// graph feedback observer、看门狗心跳与 Provider 注册。
// 位于评估管线之前（启动期）：负责初始化保护运行时、注册信号源并封存注册表。
// 安全不变量：启动顺序不可颠倒（anti-debug → armor → anti-dump → provider 注册 → 封存）；
// App Store 安全档下主动跳过侵入式保护，避免触发审核/崩溃符号化问题。

import CRiskCore
import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// 为 CPRiskKit 提供启动、停止与运行时资源生命周期管理能力。
extension CPRiskKit {

    // MARK: - 启动

    /// 以默认配置启动（测试环境下改用默认构造的配置，避免读取外部配置）。
    internal func startImpl() {
        // XCTest 环境使用全新配置，隔离宿主 App 的远程配置/持久化状态
        if Self.isRunningUnderXCTest {
            start(config: CPRiskConfig())
        } else {
            start(config: .default)
        }
    }

    /// 以指定配置启动 SDK。
    ///
    /// 流程：测试状态重置 → 保护稳定性会话 → 计算有效 anti-debug 模式 →
    /// anti-debug/看门狗 → Armor 初始化 → anti-dump → 注册 Provider 并封存 →
    /// 启动采集器与图反馈观察者。
    /// - Parameter config: 风险评估配置。
    internal func startImpl(config: CPRiskConfig) {
        if Self.isRunningUnderXCTest {
            // 测试环境清理跨用例残留状态，保证用例可重复运行
            ProtectionStabilityStore.shared.resetForTesting()
            stateLock.withLock {
                latestRemoteConfig = nil
                lastRemoteAppStoreSafeProfileFlag = false
                lastEnableRemoteConfig = false
            }
        }

        let remoteVersion = currentRemoteConfig()?.version
        let remoteSafeFlag =
            config.enableRemoteConfig && (currentRemoteConfig()?.securityHardening?.enableAppStoreSafeProfile == true)
        let effectiveForStability = Self.effectiveAntiDebugRuntimeMode(
            localMode: config.antiDebugRuntimeMode,
            remoteRequestsAppStoreSafeProfile: remoteSafeFlag
        )
        // 开始新会话：可能触发远程配置回滚或进入本地安全档（降级策略）
        let bootstrap = ProtectionStabilityStore.shared.beginSession(
            remoteConfigVersion: remoteVersion,
            antiDebugMode: effectiveForStability,
            safeProfileAlreadyActive: false
        )
        if bootstrap.didRollbackRemoteConfig {
            refreshRemoteTrustState()
            Logger.log(
                "protection_stability: auto-rollback applied version=\(bootstrap.rolledBackToVersion.map { String($0) } ?? "nil")"
            )
        }
        if bootstrap.didEnterLocalSafeProfile || bootstrap.didActivateLocalStabilityKillSwitch {
            Logger.log(
                "protection_stability: degraded mode safeProfile=\(bootstrap.didEnterLocalSafeProfile) killSwitch=\(bootstrap.didActivateLocalStabilityKillSwitch)"
            )
        }

        let startConfig = Self.duplicatingRiskConfig(
            config,
            forceAppStoreSafe: Self.isRunningUnderXCTest ? false : ProtectionStabilityStore.shared.isLocalSafeProfileActive()
        )
        if Self.isRunningUnderXCTest {
            // 测试环境禁用远程配置，避免网络依赖导致用例不稳定
            startConfig.enableRemoteConfig = false
        }

        applyAntiDebugRuntimeConfigToCore(startConfig)
        let appStoreSafe = stateLock.withLock { lastAppliedEffectiveAntiDebugMode == .appStoreSafe }
        if appStoreSafe {
            Logger.log(
                "app_store_safe_profile: enabled — skipping cprisk_deny_attach, exception handler registration, " +
                "anti_debug_watchdog, anti_dump_probe, cprisk_erase_macho_header (armor + risk evaluation remain active)"
            )
        }

        ProtectionStabilityStore.shared.markPhase(.antiDebugPrepare)

        var watchdogStartResult: Int32 = 0
        // App Store 安全档下跳过 deny_attach/异常端口接管等侵入式 anti-debug，
        // 仅保留 Armor 与风险评估，满足合规要求
        if !appStoreSafe {
            cprisk_deny_attach()
            cprisk_register_exception_handler()
            watchdogStartResult = Int32(cprisk_start_anti_debug_watchdog())
            if watchdogStartResult != 0 {
                Logger.log("anti_debug_\(ObfuscatedConstants.keywordWatchdog).start failed rc=\(watchdogStartResult)")
                // 看门狗启动失败时撤销心跳，避免心跳定时器持续运行却无人消费
                invalidateMainThreadWatchdogHeartbeat()
            } else {
                scheduleMainThreadWatchdogHeartbeat()
            }
        }

        ProtectionStabilityStore.shared.markPhase(.armorRuntimeInit)
        let armorSnapshot = ensureArmorRuntimeStarted(trigger: "start", config: startConfig)
#if os(iOS) && !targetEnvironment(macCatalyst)
        // AppStoreSafe 下跳过 erase_macho_header（已在上方日志中说明）。
        // 副作用说明：Mach-O 头擦除是不可逆的进程内修改——擦除后 dladdr /
        // dyld 内省、符号解析、崩溃上报（crash symbolication）都会失效或
        // 退化，且无法恢复；因此仅在 Armor 运行时成功启动（status == .active）
        // 时才执行，AppStoreSafe（合规模式）下始终跳过。
        if !appStoreSafe, armorSnapshot.status == .active {
            cprisk_erase_macho_header()
        }
#endif

        ProtectionStabilityStore.shared.markPhase(.antiDumpPrepare)
        var antiDumpStartResult: Int32 = 0
        if !appStoreSafe {
            // 参数 5 为 anti-dump 探针的巡检间隔/强度参数（由 C 层解释）
            antiDumpStartResult = Int32(cprisk_start_anti_dump_probe(5))
            if antiDumpStartResult != 0 {
                Logger.log("anti_dump_probe.start failed rc=\(antiDumpStartResult)")
            }
        }

        let watchdogAnomalyFlags = antiDebugWatchdogSnapshot().anomalyFlags
        ProtectionStabilityStore.shared.recordRuntimeHealth(
            armorStatus: armorSnapshot.status.rawValue,
            armorReason: armorSnapshot.reason,
            watchdogStartResult: watchdogStartResult,
            antiDumpStartResult: antiDumpStartResult,
            watchdogAnomalyFlags: watchdogAnomalyFlags
        )

        DyldImageMonitor.shared.start()
        BuildConfig.configureForRelease()
        let sid = stateLock.withLock { () -> String? in
            currentSessionId = UUID().uuidString
            return currentSessionId
        }
        #if DEBUG
        Logger.log("sdk_start sid=\(sid ?? "")")
        #endif
        if !AppAttestSignalProvider.isHardwareTrustSupported {
            Logger.log("app_attest: hardware_trust_unsupported (evaluate will emit signal weight=95)")
        }
        ProtectionStabilityStore.shared.markPhase(.providerRegistration)
        registerProviders(for: startConfig)
        // 封存注册表与自定义条件求值器：之后不允许再注册，防止运行期注入
        RiskSignalProviderRegistry.shared.seal()
        ConditionExpression.sealCustomEvaluators()
        installGraphFeedbackReEvaluateObserver()
#if canImport(UIKit)
        touchCapture.start()
        motionSampler.start()
        PhysicalSensorProbe.prewarm()
#endif
        ProtectionStabilityStore.shared.markStartupCompleted(remoteConfigVersion: currentRemoteConfig()?.version)
    }

    // MARK: - 停止

    /// 停止 SDK 并释放运行时资源。
    ///
    /// 停止顺序与启动相反：先摘除观察者/心跳，再停 C 层探针与 Armor，最后停采集器；
    /// 测试环境额外重置持久化状态与 anti-debug 模式。
    internal func stopImpl() {
        Logger.log("sdk_stop")
        removeGraphFeedbackReEvaluateObserver()
        invalidateMainThreadWatchdogHeartbeat()
        cprisk_stop_anti_dump_probe()
        cprisk_stop_anti_debug_watchdog()
        resetArmorRuntime()
#if canImport(UIKit)
        motionSampler.stop()
        touchCapture.stop()
#endif
        if Self.isRunningUnderXCTest {
            ProtectionStabilityStore.shared.resetForTesting()
            stateLock.withLock {
                latestRemoteConfig = nil
                lastRemoteAppStoreSafeProfileFlag = false
                lastEnableRemoteConfig = false
                lastLocalAntiDebugMode = .production
                lastAppliedEffectiveAntiDebugMode = .production
            }
            applyAntiDebugRuntimeModeToCore(.production)
        }
    }

    // MARK: - 图反馈观察者

    /// 安装“图风险反馈已应用”通知观察者。
    ///
    /// 仅当服务端图反馈自动重评估开关开启时生效；先移除旧观察者避免重复注册。
    /// 通知回到主队列后再触发异步评估，保证状态修改在串行上下文完成。
    internal func installGraphFeedbackReEvaluateObserver() {
        removeGraphFeedbackReEvaluateObserver()
        guard Self.autoReEvaluateOnGraphFeedback else { return }
        graphFeedbackObserver = NotificationCenter.default.addObserver(
            forName: Self.graphRiskFeedbackDidApplyNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            // 使用 weak self 防止观察者延长 SDK 生命周期；空回调即触发一次评估
            self?.evaluateAsync { _ in }
        }
    }

    /// 移除图反馈观察者（幂等）。
    internal func removeGraphFeedbackReEvaluateObserver() {
        if let obs = graphFeedbackObserver {
            NotificationCenter.default.removeObserver(obs)
            graphFeedbackObserver = nil
        }
    }

    // MARK: - 看门狗心跳

    /// 安排主线程看门狗心跳定时器。
    ///
    /// 定时器必须安装在主 RunLoop；若当前不在主线程则派发到主队列。
    /// 每秒上报一次“主线程存活”，供看门狗检测主线程停滞。
    internal func scheduleMainThreadWatchdogHeartbeat() {
        let install = { [weak self] in
            guard let self else { return }
            // 先清理旧定时器，避免重复安装导致多次心跳
            self.invalidateMainThreadWatchdogHeartbeatOnCurrentThread()
            cprisk_watchdog_note_main_thread_alive()
            let timer = Timer(timeInterval: 1.0, repeats: true) { _ in
                cprisk_watchdog_note_main_thread_alive()
            }
            // .common 模式确保滚动/模态等场景下定时器仍然触发
            RunLoop.main.add(timer, forMode: .common)
            self.mainThreadWatchdogHeartbeatTimer = timer
        }
        if Thread.isMainThread {
            install()
        } else {
            DispatchQueue.main.async(execute: install)
        }
    }

    /// 停止看门狗心跳定时器（线程安全）。
    internal func invalidateMainThreadWatchdogHeartbeat() {
        if Thread.isMainThread {
            invalidateMainThreadWatchdogHeartbeatOnCurrentThread()
        } else {
            // Timer 必须在其所在 RunLoop 线程失效，因此派发回主线程
            DispatchQueue.main.async { [weak self] in
                self?.invalidateMainThreadWatchdogHeartbeatOnCurrentThread()
            }
        }
    }

    /// 在当前（主）线程失效心跳定时器。
    private func invalidateMainThreadWatchdogHeartbeatOnCurrentThread() {
        mainThreadWatchdogHeartbeatTimer?.invalidate()
        mainThreadWatchdogHeartbeatTimer = nil
    }

    // MARK: - Provider 注册

    /// 注册内置信号提供者。
    /// - Parameter config: 用于决定启用哪些检测类别的配置。
    internal func registerProviders(for config: CPRiskConfig) {
        BuiltInProviderBootstrap.apply(to: RiskSignalProviderRegistry.shared, config: config)
    }

    // MARK: - 配置复制

    /// 复制一份 `CPRiskConfig` 并可选强制 App Store 安全档。
    ///
    /// 之所以复制而不是直接修改调用方配置：避免 SDK 内部状态变更污染宿主持有的对象
    /// （`CPRiskConfig` 为引用类型）。
    /// - Parameters:
    ///   - config: 原始配置。
    ///   - forceAppStoreSafe: 是否强制 anti-debug 模式为 `.appStoreSafe`。
    /// - Returns: 字段逐项复制后的新配置。
    internal static func duplicatingRiskConfig(_ config: CPRiskConfig, forceAppStoreSafe: Bool) -> CPRiskConfig {
        let c = CPRiskConfig()
        c.enableBehaviorDetect = config.enableBehaviorDetect
        c.enableNetworkSignals = config.enableNetworkSignals
        c.threshold = config.threshold
        c.jailbreakEnableFileDetect = config.jailbreakEnableFileDetect
        c.jailbreakEnableDyldDetect = config.jailbreakEnableDyldDetect
        c.jailbreakEnableEnvDetect = config.jailbreakEnableEnvDetect
        c.jailbreakEnableSysctlDetect = config.jailbreakEnableSysctlDetect
        c.jailbreakEnableSchemeDetect = config.jailbreakEnableSchemeDetect
        c.jailbreakEnableHookDetect = config.jailbreakEnableHookDetect
        c.jailbreakThreshold = config.jailbreakThreshold
        c.enableRemoteConfig = config.enableRemoteConfig
        c.defaultScenario = config.defaultScenario
        c.enableTemporalAnalysis = config.enableTemporalAnalysis
        c.enableAntiTamper = config.enableAntiTamper
        c.remoteConfigURLString = config.remoteConfigURLString
        if forceAppStoreSafe {
            c.antiDebugRuntimeMode = .appStoreSafe
        } else {
            c.antiDebugRuntimeMode = config.antiDebugRuntimeMode
        }
        return c
    }
}
