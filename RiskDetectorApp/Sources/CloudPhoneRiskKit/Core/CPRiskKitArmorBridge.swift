// MARK: - CPRiskKit+ArmorBridge（Armor 桥接）
//
// 从 CloudPhoneRiskKit.swift 拆分：Armor 运行时初始化、根密钥解析、
// 签名密钥桥接与 anti-debug 运行时模式管理。
// 位于评估管线的保护运行时层：评估与信封签发前确保 Armor 已启动。
// 安全不变量：根密钥只来自环境变量（32 字节十六进制），无硬编码/DEBUG 回退；
// 初始化失败以失败即拒绝语义上报为篡改信号，绝不静默降级。

import CryptoKit
import CRiskCore
import Foundation

/// 为 CPRiskKit 提供 Armor 运行时初始化与签名密钥桥接能力。
extension CPRiskKit {

    // MARK: - Anti-Debug 运行时模式

    /// 把 anti-debug 运行时模式下发到 C 层。
    ///
    /// 未知枚举值按最严格的 `production` 处理（失败即拒绝的保守策略）。
    /// - Parameter mode: 目标运行时加固模式。
    internal func applyAntiDebugRuntimeModeToCore(_ mode: CPRiskAntiDebugRuntimeMode) {
        switch mode {
        case .production:
            cprisk_set_runtime_hardening_mode(cprisk_runtime_hardening_mode_t(CPRISK_RUNTIME_HARDENING_PRODUCTION))
        case .relaxedDevelopmentQA:
            cprisk_set_runtime_hardening_mode(cprisk_runtime_hardening_mode_t(CPRISK_RUNTIME_HARDENING_RELAXED_DEV_QA))
        case .appStoreSafe:
            cprisk_set_runtime_hardening_mode(cprisk_runtime_hardening_mode_t(CPRISK_RUNTIME_HARDENING_APP_STORE_SAFE))
        @unknown default:
            cprisk_set_runtime_hardening_mode(cprisk_runtime_hardening_mode_t(CPRISK_RUNTIME_HARDENING_PRODUCTION))
        }
    }

    /// 计算本地模式与远程诉求合成后的有效 anti-debug 模式。
    ///
    /// App Store 安全模式具有最高优先级：只要本地或远程任一方要求，就强制使用。
    /// - Parameters:
    ///   - localMode: 本地配置的模式。
    ///   - remoteRequestsAppStoreSafeProfile: 远程配置是否要求 App Store 安全档。
    /// - Returns: 最终生效模式。
    internal static func effectiveAntiDebugRuntimeMode(
        localMode: CPRiskAntiDebugRuntimeMode,
        remoteRequestsAppStoreSafeProfile: Bool
    ) -> CPRiskAntiDebugRuntimeMode {
        if localMode == .appStoreSafe { return .appStoreSafe }
        if remoteRequestsAppStoreSafeProfile { return .appStoreSafe }
        return localMode
    }

    /// 应用配置并同步更新本地记录的 anti-debug 状态。
    ///
    /// 先记录本地模式与远程开关，再在锁内读取远程安全档标志，最后落盘有效模式；
    /// 分两次取锁是为了避免在持有 stateLock 时调用 C 层（减少锁持有时间）。
    /// - Parameter config: 风险评估配置。
    internal func applyAntiDebugRuntimeConfigToCore(_ config: CPRiskConfig) {
        stateLock.withLock {
            lastLocalAntiDebugMode = config.antiDebugRuntimeMode
            lastEnableRemoteConfig = config.enableRemoteConfig
        }
        let remoteFlag = stateLock.withLock {
            lastEnableRemoteConfig && lastRemoteAppStoreSafeProfileFlag
        }
        let effective = Self.effectiveAntiDebugRuntimeMode(
            localMode: config.antiDebugRuntimeMode,
            remoteRequestsAppStoreSafeProfile: remoteFlag
        )
        stateLock.withLock { lastAppliedEffectiveAntiDebugMode = effective }
        applyAntiDebugRuntimeModeToCore(effective)
    }

    /// 远程配置变化后重新计算并应用 anti-debug 模式。
    ///
    /// 远程安全档标志可能刚被更新，因此需要重新合成有效模式，不能直接复用旧值。
    internal func reapplyAntiDebugRuntimeModeAfterRemoteConfigChange() {
        let local = stateLock.withLock { lastLocalAntiDebugMode }
        let remote = stateLock.withLock { lastEnableRemoteConfig && lastRemoteAppStoreSafeProfileFlag }
        let effective = Self.effectiveAntiDebugRuntimeMode(
            localMode: local,
            remoteRequestsAppStoreSafeProfile: remote
        )
        stateLock.withLock { lastAppliedEffectiveAntiDebugMode = effective }
        applyAntiDebugRuntimeModeToCore(effective)
    }

    // MARK: - Armor 运行时

    /// 确保 Armor 保护运行时已启动（幂等）。
    ///
    /// 已处于非 inactive 状态时直接返回现有快照；否则解析根密钥并调用 C 层初始化。
    /// 整个初始化过程由 `armorInitLock` 串行化，防止并发重复初始化。
    /// - Parameters:
    ///   - trigger: 触发位置（start / evaluate / build_envelope），用于诊断。
    ///   - config: 可选的配置；提供时先同步 anti-debug 模式。
    /// - Returns: 初始化后的运行时快照（active / unavailable / failed）。
    @discardableResult
    internal func ensureArmorRuntimeStarted(trigger: String, config: CPRiskConfig? = nil) -> ArmorRuntimeSnapshot {
        if let config {
            applyAntiDebugRuntimeConfigToCore(config)
        } else {
            let mode = stateLock.withLock { lastAppliedEffectiveAntiDebugMode }
            applyAntiDebugRuntimeModeToCore(mode)
        }

        // 快速路径：已初始化完成则直接返回，避免重复解析密钥
        let existing: ArmorRuntimeSnapshot? = stateLock.withLock {
            armorRuntimeSnapshot.status != .inactive ? armorRuntimeSnapshot : nil
        }
        if let existing { return existing }

        let (attemptCount, anchorPresent, keyResolution) = stateLock.withLock {
            (armorRuntimeSnapshot.attemptCount + 1, Self.hasArmorAnchor(), Self.resolveArmorRootKey())
        }

        var snapshot = ArmorRuntimeSnapshot(
            status: .unavailable,
            reason: "uninitialized",
            initCode: nil,
            trigger: trigger,
            rootKeySource: keyResolution.source,
            debugFallbackUsed: keyResolution.debugFallbackUsed,
            anchorPresent: anchorPresent,
            attemptCount: attemptCount
        )
        if let failureReason = keyResolution.failureReason {
            // 密钥解析失败：不进入 C 层初始化，直接标记不可用（失败即拒绝）
            snapshot = ArmorRuntimeSnapshot(
                status: .unavailable,
                reason: failureReason,
                initCode: nil,
                trigger: trigger,
                rootKeySource: keyResolution.source,
                debugFallbackUsed: keyResolution.debugFallbackUsed,
                anchorPresent: anchorPresent,
                attemptCount: attemptCount
            )
        } else if let keyData = keyResolution.keyData {
            let earlySnapshot: ArmorRuntimeSnapshot? = armorInitLock.withLock {
                // 双重检查：可能在等待 armorInitLock 期间已被其他线程初始化
                let alreadyStarted = stateLock.withLock { armorRuntimeSnapshot.status != .inactive }
                if alreadyStarted {
                    return stateLock.withLock { armorRuntimeSnapshot }
                }

                let initCode = keyData.withUnsafeBytes { rawBuffer -> Int32 in
                    guard let baseAddress = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                        return -1
                    }
                    return Int32(cprisk_init_protection(baseAddress, keyData.count))
                }

                snapshot = Self.makeArmorRuntimeSnapshot(
                    trigger: trigger,
                    initCode: initCode,
                    keySource: keyResolution.source,
                    debugFallbackUsed: keyResolution.debugFallbackUsed,
                    anchorPresent: anchorPresent,
                    attemptCount: attemptCount
                )
                stateLock.withLock { armorRuntimeSnapshot = snapshot }
                return nil
            }
            if let earlySnapshot { return earlySnapshot }
        } else {
            // 既无失败原因也无密钥：按缺少根密钥处理
            snapshot = ArmorRuntimeSnapshot(
                status: .unavailable,
                reason: "missing_root_key",
                initCode: nil,
                trigger: trigger,
                rootKeySource: .missing,
                debugFallbackUsed: false,
                anchorPresent: anchorPresent,
                attemptCount: attemptCount
            )
        }

        let finalSnapshot: ArmorRuntimeSnapshot = stateLock.withLock {
            // 只有仍为 inactive 时才写入本地快照，避免覆盖并发初始化结果
            if armorRuntimeSnapshot.status == .inactive {
                armorRuntimeSnapshot = snapshot
            }
            return armorRuntimeSnapshot
        }

        Self.logArmorRuntimeSnapshot(finalSnapshot)
        return finalSnapshot
    }

    /// 重置 Armor 运行时并清理 C 层保护状态。
    ///
    /// 把 anti-debug 模式恢复为 production 后再清理；仅当之前确有运行时活动时
    /// 才调用 C 层 cleanup，避免对未初始化状态做无意义清理。
    internal func resetArmorRuntime() {
        let shouldCleanup = stateLock.withLock {
            lastLocalAntiDebugMode = .production
            lastAppliedEffectiveAntiDebugMode = Self.effectiveAntiDebugRuntimeMode(
                localMode: .production,
                remoteRequestsAppStoreSafeProfile: lastEnableRemoteConfig && lastRemoteAppStoreSafeProfileFlag
            )
            let cleanup = armorRuntimeSnapshot.status != .inactive || armorRuntimeSnapshot.attemptCount > 0
            armorRuntimeSnapshot = .inactive
            return cleanup
        }

        if shouldCleanup {
            cprisk_cleanup_protection()
            Logger.log("armor_runtime.cleanup")
        }
        applyAntiDebugRuntimeModeToCore(
            stateLock.withLock { lastAppliedEffectiveAntiDebugMode }
        )
    }

    // MARK: - Armor 根密钥

    /// 解析 Armor 根密钥。
    ///
    /// 仅接受环境变量 `armorRootKeyEnvironmentKey` 提供的 32 字节十六进制字符串；
    /// 空值或长度/格式非法均返回失败（失败即拒绝），不提供任何硬编码或 DEBUG 回退。
    /// - Returns: 解析结果（密钥、来源与失败原因）。
    internal static func resolveArmorRootKey() -> ArmorRootKeyResolution {
        if let rawValue = ProcessInfo.processInfo.environment[armorRootKeyEnvironmentKey] {
            let trimmed = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else {
                return ArmorRootKeyResolution(
                    keyData: nil,
                    source: .invalidEnvironment,
                    debugFallbackUsed: false,
                    failureReason: "invalid_root_key_hex"
                )
            }
            // 严格校验：必须是 32 字节（256 位）密钥，长度不符直接拒绝
            guard let keyData = Data(hexString: trimmed), keyData.count == 32 else {
                return ArmorRootKeyResolution(
                    keyData: nil,
                    source: .invalidEnvironment,
                    debugFallbackUsed: false,
                    failureReason: "invalid_root_key_hex"
                )
            }
            return ArmorRootKeyResolution(
                keyData: keyData,
                source: .environment,
                debugFallbackUsed: false,
                failureReason: nil
            )
        }

        // 不提供硬编码 / DEBUG 回退根密钥：未配置密钥时直接硬失败为
        // `missing_root_key`（详见 CloudPhoneRiskKit.swift）。
        return ArmorRootKeyResolution(
            keyData: nil,
            source: .missing,
            debugFallbackUsed: false,
            failureReason: "missing_root_key"
        )
    }

    /// 判断 Armor 锚点数据是否存在。
    ///
    /// C 层返回 0 表示成功读取完整锚点哈希；任何非零返回都视为缺失。
    /// - Returns: 锚点存在返回 `true`。
    internal static func hasArmorAnchor() -> Bool {
        var anchor = [UInt8](repeating: 0, count: 32)
        return cprisk_read_full_anchor_hash(&anchor) == 0
    }

    /// 把 C 层初始化返回码映射为运行时快照。
    ///
    /// 返回码语义（与 C 层约定）：
    /// - 0：成功；-1：密钥非法；-2：完整性哈希失败；-3：锚点读取失败/载荷缺失；
    /// -4：锚点 HMAC 失败；-5：锚点累加器失败；-6：数据加载器初始化失败；
    /// -7：受保护数据加载失败；其余负数按未知失败处理。
    /// - Parameters:
    ///   - trigger: 触发位置。
    ///   - initCode: C 层返回码。
    ///   - keySource: 根密钥来源。
    ///   - debugFallbackUsed: 是否使用调试回退密钥。
    ///   - anchorPresent: 锚点是否存在。
    ///   - attemptCount: 尝试次数。
    /// - Returns: 映射后的快照。
    internal static func makeArmorRuntimeSnapshot(
        trigger: String,
        initCode: Int32,
        keySource: ArmorRootKeySource,
        debugFallbackUsed: Bool,
        anchorPresent: Bool,
        attemptCount: Int
    ) -> ArmorRuntimeSnapshot {
        let status: ArmorRuntimeStatus
        let reason: String

        switch initCode {
        case 0:
            status = .active
            reason = "initialized"
        case -1:
            status = .unavailable
            reason = "invalid_root_key"
        case -2:
            status = .failed
            reason = "integrity_hash_failed"
        case -3:
            // 有锚点却读取失败视为篡改；无锚点则视为载荷缺失（不可用）
            status = anchorPresent ? .failed : .unavailable
            reason = anchorPresent ? "full_anchor_read_failed" : "armor_payload_missing"
        case -4:
            status = .failed
            reason = "anchor_hmac_failed"
        case -5:
            status = .failed
            reason = "anchor_accumulator_failed"
        case -6:
            status = .failed
            reason = "data_loader_init_failed"
        case -7:
            status = .failed
            reason = "protected_data_load_failed"
        default:
            status = .failed
            reason = "init_failed_\(initCode)"
        }

        return ArmorRuntimeSnapshot(
            status: status,
            reason: reason,
            initCode: initCode,
            trigger: trigger,
            rootKeySource: keySource,
            debugFallbackUsed: debugFallbackUsed,
            anchorPresent: anchorPresent,
            attemptCount: attemptCount
        )
    }

    /// 输出 Armor 运行时快照日志。
    ///
    /// 非 active/inactive 的异常状态额外写入 NSLog，确保在应用未接管 Logger 时
    /// 仍能在系统日志中留下证据。
    /// - Parameter snapshot: 待记录的运行时快照。
    internal static func logArmorRuntimeSnapshot(_ snapshot: ArmorRuntimeSnapshot) {
        let message = "armor_runtime status=\(snapshot.status.rawValue) reason=\(snapshot.reason) " +
            "trigger=\(snapshot.trigger) source=\(snapshot.rootKeySource.rawValue) " +
            "anchor=\(snapshot.anchorPresent ? "present" : "missing") attempts=\(snapshot.attemptCount)" +
            (snapshot.initCode.map { " initCode=\($0)" } ?? "") +
            (snapshot.debugFallbackUsed ? " debugFallback=1" : "")

        Logger.log(message)
        if snapshot.status != .active && snapshot.status != .inactive {
            NSLog("[CloudPhoneRiskKit] %@", message)
        }
    }

    /// 把 Armor 运行时异常转换为风险信号。
    ///
    /// active/inactive 不产生信号；unavailable 根据锚点是否存在给不同分数
    /// （有锚点却不可用更可疑），failed 直接按篡改处理并给高分。
    /// - Parameter snapshot: 运行时快照。
    /// - Returns: 风险信号；运行时正常时返回 `nil`。
    internal static func armorRuntimeSignal(from snapshot: ArmorRuntimeSnapshot) -> RiskSignal? {
        guard snapshot.status != .active && snapshot.status != .inactive else {
            return nil
        }

        let signalID: String
        let score: Double
        let state: RiskSignalState

        switch snapshot.status {
        case .unavailable:
            signalID = "armor_runtime_unavailable"
            // 锚点存在却无法启动（40）比载荷本就缺失（18）风险更高
            score = snapshot.anchorPresent ? 40 : 18
            state = .unavailable
        case .failed:
            signalID = ObfuscatedConstants.signalArmorRuntimeInitFailed
            // 初始化失败意味着完整性/锚点校验不通过，按强篡改证据计分
            score = 72
            state = .tampered
        case .inactive, .active:
            return nil
        }

        var evidence: [String: String] = [
            "reason": snapshot.reason,
            "trigger": snapshot.trigger,
            "root_key_source": snapshot.rootKeySource.rawValue,
            "anchor_present": snapshot.anchorPresent ? "1" : "0",
            "attempt_count": "\(snapshot.attemptCount)"
        ]
        if let initCode = snapshot.initCode {
            evidence["init_code"] = "\(initCode)"
        }
        if snapshot.debugFallbackUsed {
            evidence["debug_fallback"] = "1"
        }

        return RiskSignal(
            id: signalID,
            category: ObfuscatedConstants.categoryAntiTamper,
            score: score,
            evidence: evidence,
            state: state,
            layer: 2,
            weightHint: score
        )
    }

    // MARK: - 异常处理器校验

    /// 按节流间隔校验异常处理器是否仍然注册。
    ///
    /// 校验本身有系统调用开销，因此用 `verifyThrottleInterval` 限制频率；
    /// 节流判定与时间戳更新在同一把锁内完成，避免并发重复校验。
    internal static func maybeVerifyExceptionHandler() {
        let shouldVerify = verifyThrottleLock.withLock {
            let now = Date().timeIntervalSince1970
            let verify = (now - lastExceptionVerifyTime) >= verifyThrottleInterval
            if verify { lastExceptionVerifyTime = now }
            return verify
        }
        if shouldVerify {
            cprisk_verify_exception_handler()
        }
    }
}
