// 内核 Hook 旁路信道检测器：不复用 libc 包装，而是用五类正交信号寻找内核/动态插桩痕迹——
// 加密微负载的 CNTPCT 与 Mach 时钟偏斜及不变量失败、syscall 时序比值异常、inode 一致性（预留）、
// systemUptime 与 mach_absolute_time 走时偏差、以及 getpid/getuid 返回值不稳定。
// 信号按机制拆分（timing / crypto_trace_skew / crypto_trace_invariant / pid_unstable /
// stalker_amplified），便于服务端按 Hook 类型归因；模拟器全部降级为 0 分。

import CRiskCore
import Darwin
import Foundation

/// 通过“不同时钟源 / 不同 syscall 通道”的交叉校验发现内核 Hook 与 Stalker 式动态插桩。
struct KernelHookSideChannel: Detector {
    /// Mach 时基（numer/denom）只初始化一次；用于把 mach_absolute_time 的 tick 换算成纳秒。
    private static let timebaseInfo: mach_timebase_info_data_t = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info
    }()

    /// tick → 纳秒；乘法溢出（极端长时间间隔）时返回 UInt64.max 作为饱和值。
    private static func nanoseconds(from ticks: UInt64) -> UInt64 {
        let denom = max(UInt64(timebaseInfo.denom), 1)
        let (product, overflow) = ticks.multipliedReportingOverflow(by: UInt64(timebaseInfo.numer))
        return overflow ? UInt64.max : product / denom
    }

    /// 依次执行五个策略并累加；总分封顶 100。
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["kernel_hook_sc:unavailable_simulator"])
#else
        var totalScore: Double = 0
        var methods: [String] = []

        let (s0, m0) = detectCryptoTraceOrthogonal()
        totalScore += s0
        methods.append(contentsOf: m0)

        let (s1, m1) = detectTimingAnomaly()
        totalScore += s1
        methods.append(contentsOf: m1)

        let (s2, m2) = detectInodeMismatch()
        totalScore += s2
        methods.append(contentsOf: m2)

        let (s3, m3) = detectTimeDesync()
        totalScore += s3
        methods.append(contentsOf: m3)

        let (s4, m4) = detectReturnValueEntropy()
        totalScore += s4
        methods.append(contentsOf: m4)

        if methods.isEmpty {
            return DetectorResult(score: 0, methods: ["kernel_hook_sc:clean"])
        }

        return DetectorResult(score: min(totalScore, 100), methods: methods)
#endif
    }

    // MARK: - 策略 0：加密轨迹正交校验（CNTPCT vs Mach + 摘要）

    /// 复用 `cprisk_crypto_trace` 的确定性微负载：与纯 syscall 时序比值正交，覆盖「只对齐自然时钟」类对抗。
    ///
    /// 先进入微负载，再读取 C 侧累积的标志位：
    /// - `CNT_MACH_SKEW`：CNTPCT 与 Mach 时钟的推进比例异常（28 分）。
    /// - `INVARIANT_FAIL`：加密运算的不变量被破坏，基本可确定内核或指令层被改写（85 分）。
    private func detectCryptoTraceOrthogonal() -> (Double, [String]) {
#if targetEnvironment(simulator)
        return (0, [])
#else
        cprisk_crypto_trace_primitive_enter_i()
        let flags = cprisk_crypto_trace_peek_flags_i()
        var score: Double = 0
        var methods: [String] = []

        if (flags & UInt32(CPRISK_CRYPTO_TRACE_FLAG_CNT_MACH_SKEW)) != 0 {
            score += 28
            methods.append(
                "kernel_hook_crypto_trace_skew:flags=\(flags)_last_ns=\(cprisk_crypto_trace_last_ns_i())"
            )
        }
        if (flags & UInt32(CPRISK_CRYPTO_TRACE_FLAG_INVARIANT_FAIL)) != 0 {
            // 不变量失败意味着计算结果与预期不符，是最高置信度的内核/指令篡改证据。
            score += 85
            methods.append("kernel_hook_crypto_trace_invariant:flags=\(flags)")
        }

        return (score, methods)
#endif
    }

    // MARK: - 策略 1：syscall 时序分布

    /// 以 getpid 为基线，比较文件探针与 sysctl 的耗时比值；Hook/DBT 会给探针叠加固定开销。
    /// - 普通 access 探针使用默认阈值；sysctl 路径更长、噪声更大，阈值放宽到 14。
    /// - 二次放大探测通过间接函数指针与交替 syscall 放大 Stalker 的翻译成本，阈值降到 12。
    private func detectTimingAnomaly() -> (Double, [String]) {
#if targetEnvironment(simulator)
        return (0, [])
#else
        var score: Double = 0
        var methods: [String] = []

        let statProbe = TimingRatioBaseline.evaluatePair(
            baselineName: "getpid",
            probeName: "access:/usr/lib/dyld"
        ) {
            _ = cprisk_getpid_direct()
        } probe: {
            _ = SVCDirectCall.secureAccess("/usr/lib/dyld")
        }

        if let statProbe, statProbe.isAnomalous {
            // access 与 getpid 都是短路径 syscall，比值异常通常来自 Hook 的额外转发。
            score += 25
            methods.append(
                "kernel_hook_timing_anomaly:probe=\(statProbe.probeName)_baseline=\(statProbe.baselineName)_medianNs=\(statProbe.probeMedianNs)_baselineMedianNs=\(statProbe.baselineMedianNs)_ratio=\(String(format: "%.1f", statProbe.medianRatio))_ratioP95=\(String(format: "%.1f", statProbe.p95Ratio))"
            )
        }

        let sysctlProbe = TimingRatioBaseline.evaluatePair(
            baselineName: "getpid",
            probeName: "sysctl:kern.proc.pid",
            // sysctl 本身比 getpid 慢一个量级，阈值提高到 14 以吸收正常抖动。
            ratioThreshold: 14.0
        ) {
            _ = cprisk_getpid_direct()
        } probe: {
            var info = kinfo_proc()
            var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, cprisk_getpid_direct()]
            var size = MemoryLayout<kinfo_proc>.size
            _ = cprisk_sysctl_direct(&mib, 4, &info, &size, nil, 0, nil)
        }

        if let sysctlProbe, sysctlProbe.isAnomalous {
            score += 20
            methods.append(
                "kernel_hook_timing_anomaly:probe=\(sysctlProbe.probeName)_baseline=\(sysctlProbe.baselineName)_medianNs=\(sysctlProbe.probeMedianNs)_baselineMedianNs=\(sysctlProbe.baselineMedianNs)_ratio=\(String(format: "%.1f", sysctlProbe.medianRatio))_ratioP95=\(String(format: "%.1f", sysctlProbe.p95Ratio))"
            )
        }

        // 二次放大探测：间接函数指针 + 交替 syscall 使 Stalker DBT 开销显著放大，阈值更低即可触发。
        let amplified = TimingRatioBaseline.amplifiedSamples()
        if let ampEval = TimingRatioBaseline.evaluate(
            getpidSamples: amplified.getpid,
            statSamples: amplified.stat,
            ratioThreshold: 12.0
        ) {
            if ampEval.isAnomalous {
                score += 25
                methods.append(
                    "kernel_hook_stalker_amplified:ratio=\(String(format: "%.1f", ampEval.medianRatio))_ratioP95=\(String(format: "%.1f", ampEval.p95Ratio))"
                )
            }
        }

        return (score, methods)
#endif
    }

    // MARK: - 策略 2：元数据一致性

    /// 预留的 inode 一致性探测：当前版本未启用（恒返回 0），保留调用点以便后续接入而不改调用方。
    private func detectInodeMismatch() -> (Double, [String]) {
        return (0, [])
    }

    // MARK: - 策略 3：运行时长交叉校验

    /// 用 10,000 次 getpid 制造可测区间，比较 systemUptime 与 mach_absolute_time 的推进量。
    ///
    /// 判定条件要求相对误差 >15% 且绝对偏差 >10ms 同时成立：
    /// 只用相对值会在极短区间放大噪声，只用绝对值又会漏掉缓慢漂移，两者同时约束降低误报。
    private func detectTimeDesync() -> (Double, [String]) {
#if targetEnvironment(simulator)
        return (0, [])
#else
        let uptimeA = ProcessInfo.processInfo.systemUptime
        let machA = mach_absolute_time()

        // Small busy-wait to create a measurable interval
        for _ in 0..<10_000 { _ = cprisk_getpid_direct() }

        let uptimeB = ProcessInfo.processInfo.systemUptime
        let machB = mach_absolute_time()

        let uptimeDelta = uptimeB - uptimeA
        let machDeltaNs = Self.nanoseconds(from: machB - machA)
        let machDeltaSec = Double(machDeltaNs) / 1_000_000_000.0

        guard machDeltaSec > 0 else { return (0, []) }

        let divergence = abs(uptimeDelta - machDeltaSec)
        let relativeError = divergence / machDeltaSec

        // >15% divergence AND >10ms absolute difference
        if relativeError > 0.15 && divergence > 0.01 {
            return (50, [
                "kernel_hook_time_desync:divergence=\(String(format: "%.4f", divergence))s_rel=\(String(format: "%.1f", relativeError * 100))%"
            ])
        }

        return (0, [])
#endif
    }

    // MARK: - 策略 4：返回值熵

    /// 连续 9 次读取 pid/uid，只要出现一次不稳定即判 Hook。
    /// - 正常内核返回值恒定；随机化或按调用上下文伪造返回值是 Hook 的典型破绽。
    /// - 单次不稳定即给 80 分，因为该现象在未篡改系统上几乎不可能出现。
    private func detectReturnValueEntropy() -> (Double, [String]) {
#if targetEnvironment(simulator)
        return (0, [])
#else
        var score: Double = 0
        var methods: [String] = []

        let expectedPid = cprisk_getpid_direct()
        var pidUnstable = false
        for _ in 0..<9 {
            if cprisk_getpid_direct() != expectedPid {
                pidUnstable = true
                break
            }
        }

        let expectedUid = cprisk_getuid_direct()
        var uidUnstable = false
        for _ in 0..<9 {
            if cprisk_getuid_direct() != expectedUid {
                uidUnstable = true
                break
            }
        }

        if pidUnstable || uidUnstable {
            score = 80
            var detail = [String]()
            if pidUnstable { detail.append("pid") }
            if uidUnstable { detail.append("uid") }
            methods.append("kernel_hook_pid_unstable:\(detail.joined(separator: "+"))")
        }

        return (score, methods)
#endif
    }
}

// MARK: - 信号转换

extension KernelHookSideChannel {
    /// 将各策略的 methods 前缀映射为独立信号；没有任何命中时返回空数组。
    /// 不同机制的置信度不同：不变量失败/pid 不稳定为 tampered，其余以 soft 上报。
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        let timingMethods = result.methods.filter { $0.hasPrefix("kernel_hook_timing_anomaly") }
        if !timingMethods.isEmpty {
            // 多个探针同时异常时提高置信度；单探针仍可能受系统调度影响。
            signals.append(RiskSignal(
                id: "kernel_hook_timing_anomaly",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(timingMethods.count) * 20, 45),
                evidence: [
                    "detail": timingMethods.joined(separator: ","),
                    "mechanism": "mach_absolute_time_ratio_probe",
                    "sample_pairs": "\(timingMethods.count)",
                ],
                state: .soft(confidence: timingMethods.count > 1 ? 0.75 : 0.65),
                layer: 2,
                weightHint: 68
            ))
        }

        let inodeMethods = result.methods.filter { $0.hasPrefix("kernel_hook_inode_mismatch") }
        if !inodeMethods.isEmpty {
            signals.append(RiskSignal(
                id: "kernel_hook_inode_mismatch",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 70,
                evidence: ["detail": inodeMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 90
            ))
        }

        let desyncMethods = result.methods.filter { $0.hasPrefix("kernel_hook_time_desync") }
        if !desyncMethods.isEmpty {
            // 时钟源不一致可能是内核 Hook，也可能是系统休眠/时钟调整，故用软信号。
            signals.append(RiskSignal(
                id: "kernel_hook_time_desync",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 50,
                evidence: ["detail": desyncMethods.joined(separator: ",")],
                state: .soft(confidence: 0.7),
                layer: 2,
                weightHint: 65
            ))
        }

        let entropyMethods = result.methods.filter { $0.hasPrefix("kernel_hook_pid_unstable") }
        if !entropyMethods.isEmpty {
            signals.append(RiskSignal(
                id: "kernel_hook_pid_unstable",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 80,
                evidence: ["detail": entropyMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 95
            ))
        }

        let amplifiedMethods = result.methods.filter { $0.hasPrefix("kernel_hook_stalker_amplified") }
        if !amplifiedMethods.isEmpty {
            signals.append(RiskSignal(
                id: "kernel_hook_stalker_amplified",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 25,
                evidence: [
                    "detail": amplifiedMethods.joined(separator: ","),
                    "mechanism": "mach_absolute_time_stalker_amplified",
                ],
                state: .soft(confidence: 0.72),
                layer: 2,
                weightHint: 72
            ))
        }

        let cryptoSkewMethods = result.methods.filter { $0.hasPrefix("kernel_hook_crypto_trace_skew") }
        if !cryptoSkewMethods.isEmpty {
            signals.append(RiskSignal(
                id: "kernel_hook_crypto_trace_skew",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 28,
                evidence: [
                    "detail": cryptoSkewMethods.joined(separator: ","),
                    "mechanism": "cntpct_mach_crypto_trace",
                ],
                state: .soft(confidence: 0.74),
                layer: 2,
                weightHint: 74
            ))
        }

        let cryptoInvMethods = result.methods.filter { $0.hasPrefix("kernel_hook_crypto_trace_invariant") }
        if !cryptoInvMethods.isEmpty {
            signals.append(RiskSignal(
                id: "kernel_hook_crypto_trace_invariant",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 85,
                evidence: ["detail": cryptoInvMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 96
            ))
        }

        return signals
    }
}
