// MARK: - CPRiskKit+Diagnostics（诊断快照）
//
// 职责：暴露 Armor 运行时、Anti-Debug 看门狗与 anti-debug 计划节的只读快照，
// 并提供基于 async/await 的评估与远程配置更新封装。
// 位于评估管线的诊断/对外 API 层：诊断只读、不改变保护状态；异步封装不改变同步语义。
// 安全不变量：所有快照通过 `stateLock` 读取一致状态；continuation 必须且只能恢复一次。

import CRiskCore
import Foundation

/// 为 CPRiskKit 提供保护运行时诊断快照能力。
extension CPRiskKit {

    // MARK: - Armor 调试快照

    /// 读取 Armor 运行时调试快照。
    ///
    /// 在锁内复制快照后再转换，避免调用方持有锁期间做字符串转换。
    /// - Returns: 当前 Armor 运行时状态的只读描述。
    internal func debugArmorRuntimeSnapshotImpl() -> ArmorRuntimeDebugSnapshot {
        let snapshot = stateLock.withLock { armorRuntimeSnapshot }
        return ArmorRuntimeDebugSnapshot(
            status: snapshot.status.rawValue,
            reason: snapshot.reason,
            initCode: snapshot.initCode,
            trigger: snapshot.trigger,
            rootKeySource: snapshot.rootKeySource.rawValue,
            debugFallbackUsed: snapshot.debugFallbackUsed,
            anchorPresent: snapshot.anchorPresent,
            attemptCount: snapshot.attemptCount
        )
    }

    // MARK: - 看门狗快照

    /// 读取 Anti-Debug 看门狗快照。
    ///
    /// 直接读取 C 层结构体并逐字段映射为 Swift 值类型；C 层返回码被忽略，
    /// 未初始化时字段为零值，快照仍然可用（看门狗不阻塞评估）。
    /// - Returns: 看门狗运行指标快照。
    internal func antiDebugWatchdogSnapshotImpl() -> AntiDebugWatchdogSnapshot {
        var raw = cprisk_anti_debug_watchdog_snapshot_t()
        _ = cprisk_get_anti_debug_watchdog_snapshot(&raw)
        return AntiDebugWatchdogSnapshot(
            supported: raw.supported != 0,
            running: raw.running != 0,
            threadActive: raw.thread_active != 0,
            intervalSeconds: raw.interval_seconds,
            anomalyFlags: raw.anomaly_flags,
            iterationCount: raw.iteration_count,
            tracedEventCount: raw.traced_event_count,
            denyAttachErrorCount: raw.deny_attach_error_count,
            exceptionAnomalyCount: raw.exception_anomaly_count,
            lastDenyAttachResult: raw.last_deny_attach_result,
            lastDenyAttachErrno: raw.last_deny_attach_errno,
            lastTraced: raw.last_traced != 0,
            lastExceptionPortHealthy: raw.last_exception_port_healthy != 0,
            lastExceptionQuerySucceeded: raw.last_exception_query_succeeded != 0,
            lastExceptionReclaimAttempted: raw.last_exception_reclaim_attempted != 0,
            lastExceptionHijackDetected: raw.last_exception_hijack_detected != 0,
            lastExceptionEarlyPhaseCaptured: raw.last_exception_early_phase_captured != 0,
            lastExceptionStartupRaceDetected: raw.last_exception_startup_race_detected != 0,
            lastExceptionQueryKernReturn: raw.last_exception_query_kern_return,
            lastExceptionRegisterKernReturn: raw.last_exception_register_kern_return,
            lastCheckMonotonicNs: raw.last_check_monotonic_ns,
            lastExceptionVerifyCount: raw.last_exception_verify_count,
            lastExceptionReclaimCount: raw.last_exception_reclaim_count,
            lastExceptionStartupDeltaNs: raw.last_exception_startup_delta_ns,
            signalProbeResult: raw.last_signal_probe_result != 0,
            hardwareBpDetected: raw.last_hardware_bp_detected != 0,
            softwareBreakpointDetected: raw.last_software_bp_detected != 0,
            csopsDebugged: raw.last_csops_debugged != 0,
            suspiciousThreadCount: raw.last_suspicious_thread_count,
            singleStepDetected: raw.last_single_step_detected != 0,
            ttyDetected: raw.last_tty_detected != 0,
            developerDiskDetected: raw.last_developer_disk_detected != 0,
            exceptionDeliveryTimeoutDetected: raw.last_exception_delivery_timeout_detected != 0,
            exceptionDeliveryProbeHandled: raw.last_exception_delivery_probe_handled != 0,
            lastExceptionDeliveryProbeNs: raw.last_exception_delivery_probe_ns,
            signalProbeAnomalyCount: raw.signal_probe_anomaly_count,
            hardwareBpAnomalyCount: raw.hardware_bp_anomaly_count,
            softwareBreakpointAnomalyCount: raw.software_bp_anomaly_count,
            csopsAnomalyCount: raw.csops_anomaly_count,
            suspiciousThreadAnomalyCount: raw.suspicious_thread_anomaly_count,
            exceptionDeliveryTimeoutAnomalyCount: raw.exception_delivery_timeout_anomaly_count,
            peerWatchdogAnomalyCount: raw.peer_watchdog_anomaly_count,
            shadowStackAnomalyCount: raw.shadow_stack_anomaly_count,
            lastPeerWatchdogStalled: raw.last_peer_watchdog_stalled != 0,
            lastShadowStackMismatch: raw.last_shadow_stack_mismatch != 0,
            dbiDetected: raw.last_dbi_detected != 0,
            dbiMarkerFlags: raw.last_dbi_marker_flags,
            timingAnomalyFlags: raw.last_timing_anomaly_flags,
            timingProbeMedianNs: raw.last_timing_probe_median_ns,
            timingProbeMaxNs: raw.last_timing_probe_max_ns,
            timingProbeThresholdNs: raw.last_timing_probe_threshold_ns,
            dbiAnomalyCount: raw.dbi_anomaly_count,
            timingAnomalyCount: raw.timing_anomaly_count,
            prologueIntegrityAnomalyCount: raw.prologue_integrity_anomaly_count,
            dyldInjectionAnomalyCount: raw.dyld_injection_anomaly_count,
            lastPrologueFailMask: raw.last_prologue_fail_mask,
            lastDyldInjectionFlags: raw.last_dyld_injection_flags,
            lastCsopsStatusFlags: raw.last_csops_status_flags,
            lastAmfiProbeBits: raw.last_amfi_probe_bits,
            lastGetTaskAllowSuspect: raw.last_get_task_allow_suspect != 0,
            lastDenyAttachVerifyBits: raw.last_deny_attach_verify_bits,
            denyAttachVerifyAnomalyCount: raw.deny_attach_verify_anomaly_count,
            amfiCsFlagsAnomalyCount: raw.amfi_cs_flags_anomaly_count,
            getTaskAllowAnomalyCount: raw.get_task_allow_anomaly_count,
            vmMprotectCrosscheckMismatchTotal: raw.vm_mprotect_crosscheck_mismatch_total,
            vmMprotectMachTrapMismatchTotal: raw.vm_mprotect_mach_trap_mismatch_total,
            libcFallbackUsedMask: raw.libc_fallback_used_mask,
            libcFallbackEventTotal: raw.libc_fallback_event_total,
            watchdogStartPathMask: raw.watchdog_start_path_mask,
            watchdogStartupLivenessOk: raw.watchdog_startup_liveness_ok != 0,
            mainThreadAliveMonotonicNs: raw.main_thread_alive_monotonic_ns,
            earlyInjectionEnvMask: raw.early_injection_env_mask,
            watchdogExtendedAnomalyFlags: raw.watchdog_extended_anomaly_flags,
            mainThreadHeartbeatSeq: raw.main_thread_heartbeat_seq,
            mainThreadHeartbeatStallCount: raw.main_thread_heartbeat_stall_count,
            lastMainThreadHeartbeatStalled: raw.last_main_thread_heartbeat_stalled != 0
        )
    }

    // MARK: - Anti-Debug 计划快照

    /// 读取 anti-debug 计划节快照。
    ///
    /// 计划节由打包期工具注入；缺失或解析失败时对应字段为 false/0，
    /// 调用方应据此决定是否降级为运行期检测。
    /// - Returns: 计划节解析与应用状态快照。
    internal func antiDebugPlanSnapshotImpl() -> AntiDebugPlanSnapshot {
        var raw = cprisk_antidebug_plan_snapshot_t()
        _ = cprisk_get_antidebug_plan_snapshot(&raw)
        return AntiDebugPlanSnapshot(
            sectionPresent: raw.section_present != 0,
            sectionValid: raw.section_valid != 0,
            parseError: raw.parse_error,
            entryCount: raw.entry_count,
            policyUnionBits: raw.policy_union_bits,
            lastAppliedPolicyBits: raw.last_applied_policy_bits,
            lastProbeBits: raw.last_probe_bits,
            lastGateClosed: raw.last_gate_closed != 0,
            lastSoftFailMode: raw.last_soft_fail_mode != 0,
            lastDelayNs: raw.last_delay_ns,
            consumeCount: raw.consume_count,
            escalationCount: raw.escalation_count,
            trapEventCount: raw.trap_event_count,
            inlinePatchCount: raw.inline_patch_count,
            inlinePatchFailureCount: raw.inline_patch_failure_count,
            inlinePatchArmed: raw.inline_patch_armed != 0,
            inlinePatchTampered: raw.last_inline_patch_tamper != 0
        )
    }
}

// MARK: - async/await API（2.0）

extension CPRiskKit {
    /// 异步执行评估（默认配置）。
    ///
    /// 通过 `withCheckedContinuation` 把回调式 API 桥接为 async；回调只会被调用一次，
    /// 因此 continuation 恰好恢复一次。
    /// - Returns: 评估报告。
    @available(iOS 13.0, macOS 10.15, *)
    public func evaluateAsync() async -> CPRiskReport {
        await withCheckedContinuation { continuation in
            evaluateAsync { report in
                continuation.resume(returning: report)
            }
        }
    }

    /// 异步执行评估（指定配置）。
    /// - Parameter config: 风险评估配置。
    /// - Returns: 评估报告。
    @available(iOS 13.0, macOS 10.15, *)
    public func evaluateAsync(config: CPRiskConfig) async -> CPRiskReport {
        await withCheckedContinuation { continuation in
            evaluateAsync(config: config) { report in
                continuation.resume(returning: report)
            }
        }
    }

    /// 异步执行评估（指定配置与场景）。
    /// - Parameters:
    ///   - config: 风险评估配置，默认 `.default`。
    ///   - scenario: 业务场景，默认 `.default`。
    /// - Returns: 评估报告。
    @available(iOS 13.0, macOS 10.15, *)
    public func evaluateAsync(
        config: CPRiskConfig = .default,
        scenario: RiskScenario = .default
    ) async -> CPRiskReport {
        await withCheckedContinuation { continuation in
            evaluateAsync(config: config, scenario: scenario) { report in
                continuation.resume(returning: report)
            }
        }
    }

    /// 异步更新远程配置。
    ///
    /// 回调仅以 Bool 表示成功/失败；失败时转换为 `ConfigError.networkError` 抛出，
    /// 由调用方决定是否重试。成功时 continuation 恢复且不返回值。
    /// - Throws: `ConfigError.networkError` 表示更新失败。
    @available(iOS 13.0, macOS 10.15, *)
    public func updateRemoteConfigAsync() async throws {
        try await withCheckedThrowingContinuation { continuation in
            updateRemoteConfig { success in
                if success {
                    continuation.resume()
                } else {
                    let error = NSError(
                        domain: "CloudPhoneRiskKit",
                        code: -1,
                        userInfo: [NSLocalizedDescriptionKey: "更新远程配置失败"]
                    )
                    continuation.resume(throwing: ConfigError.networkError(underlying: error))
                }
            }
        }
    }
}
