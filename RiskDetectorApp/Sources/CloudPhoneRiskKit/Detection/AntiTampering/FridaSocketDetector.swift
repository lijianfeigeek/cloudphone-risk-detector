// FridaSocketDetector：从 IPC 痕迹与时间侧信道识别 Frida。
// Frida 必须通过 Unix socket / 本地端口与 agent 通信；同时 Interceptor/Stalker
// 会给被 hook 的调用增加可测量的延迟。两类证据与模块/内存/线程检测互补：
// 即使模块被隐藏，socket 命名或时序放大仍可能暴露。
import CRiskCore
import Darwin
import Foundation

/// Detects Frida via Unix domain socket artifacts and timing side-channels.
///
/// Implements two detection techniques:
/// 1. **Unix domain socket detection** — detect Frida's IPC sockets in /tmp
/// 2. **Timing side-channel** — detect instrumentation latency from Frida's Interceptor
///    Uses dynamic baseline ratio (probe_median/getpid_median > 15), aligned with KernelHookSideChannel.
/// Frida socket 与时间侧信道检测器。
/// - 线程模型：同步采样与文件探测；随机化采样顺序降低被针对性优化。
/// - 降级：模拟器跳过；secure access 不可用时文件探测返回 false。
struct FridaSocketDetector: Detector {

    // 预计算 mach 时间基，避免每次采样重复调用 mach_timebase_info。
    private static let timebaseInfo: mach_timebase_info_data_t = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info
    }()

    /// 把 mach 绝对时钟 ticks 换算为纳秒；溢出时饱和到 UInt64.max。
    private static func nanoseconds(from ticks: UInt64) -> UInt64 {
        let denom = max(UInt64(timebaseInfo.denom), 1)
        let (product, overflow) = ticks.multipliedReportingOverflow(by: UInt64(timebaseInfo.numer))
        return overflow ? UInt64.max : product / denom
    }

    /// 执行 socket 与 timing 两类检测并汇总。
    func detect() throws -> DetectorResult {
// 模拟器无真实 Frida/socket 行为，跳过。
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []

        // 两类证据独立累加：socket 是强证据，timing 是弱证据。
        let socket = detectFridaSockets()
        score += socket.score
        methods.append(contentsOf: socket.methods)

        let timing = detectTimingAnomaly()
        score += timing.score
        methods.append(contentsOf: timing.methods)

        return DetectorResult(score: score, methods: methods)
#endif
    }

    // MARK: - 1. Unix Domain Socket / File Artifact Detection

    /// 检测 /tmp 条目、Unix socket 路径与可疑文件路径。
    private func detectFridaSockets() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        let suspiciousPaths = DynamicFeatureList.shared.suspiciousPaths

        // Method 1: Enumerate /tmp directory for suspicious entries
        // 动态特征列表中的可疑路径（可远程配置）。
        if let dir = opendir("/tmp") {
            defer { closedir(dir) }
            while let entry = readdir(dir) {
                let name = withUnsafePointer(to: &entry.pointee.d_name) { ptr in
                    let cptr = UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self)
                    let len = strnlen(cptr, 256)
                    return String(data: Data(bytes: cptr, count: len), encoding: .utf8) ?? ""
                }
                let lower = name.lowercased()
                // 条目名以特征开头或包含特征即命中，最多计一次。
                if ObfuscatedConstants.fridaSocketEntryMarkers.contains(where: { marker in
                    lower.hasPrefix(marker) || lower.contains(marker)
                }) {
                    score += 15
                    methods.append("\(ObfuscatedConstants.methodPrefixFridaSocketTmpEntry)\(name)")
                    break
                }
            }
        }

        // Method 2: Check for Frida's default listening sockets by scanning file descriptors
        // 遍历常见 fd 范围，检查其是否为带可疑路径的 AF_UNIX socket。
        for fd: Int32 in 3..<256 {
            var addr = sockaddr_un()
            var len = socklen_t(MemoryLayout<sockaddr_un>.size)
            let result = withUnsafeMutablePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    getsockname(fd, sockPtr, &len)
                }
            }
            if result == 0 && addr.sun_family == sa_family_t(AF_UNIX) {
                var sunPath = addr.sun_path
                let maxLen = MemoryLayout.size(ofValue: sunPath)
                let path = withUnsafePointer(to: &sunPath) { ptr in
                    let cptr = UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self)
                    let len = strnlen(cptr, maxLen)
                    return String(data: Data(bytes: cptr, count: len), encoding: .utf8) ?? ""
                }
                guard !path.isEmpty else { continue }
                let lower = path.lowercased()
                // socket 路径包含 frida 特征即命中。
                if ObfuscatedConstants.fridaSocketPathMarkers.contains(where: { lower.contains($0) }) {
                    score += 18
                    methods.append("\(ObfuscatedConstants.methodPrefixFridaSocketUnixFd)\(path)")
                    break
                }
            }
        }

        // 路径直探噪声较大，仅在已有运行时/socket 线索时作为佐证。
        // Method 3: Corroborate with direct-access path probes only after lower-noise runtime/socket hints.
        if shouldProbeSuspiciousPaths(score: score, methods: methods) {
            for prefix in suspiciousPaths where directFileExists(prefix) {
                score += 12
                methods.append("\(ObfuscatedConstants.methodPrefixFridaSocketPath)\(prefix)")
            }
        }

        return (min(score, 30), methods)
    }

    /// 判定是否值得做路径直探：已有任意 socket 命中即可。
    internal func shouldProbeSuspiciousPaths(score: Double, methods: [String]) -> Bool {
        score > 0 || !methods.isEmpty
    }

    /// 通过 CRiskCore secureAccess 判断路径存在，绕过 libc access hook。
    private func directFileExists(_ path: String) -> Bool {
        // secureAccess 不可用/失败时按不存在处理，避免误报。
        if let exists = SVCDirectCall.secureAccess(path) {
            return exists
        }
        Logger.log("[FridaSocketDetector] secure access probe unavailable")
        return false
    }

    // MARK: - 2. Timing Side-Channel Detection

    /// 动态基线比值检测，与 KernelHookSideChannel 对齐。
    /// 采样顺序随机化（先文件探针或先 getpid），每次采样前插入噪声计算以放大 Stalker DBT 开销。
    /// 时间侧信道检测。
    /// 采样 getpid 与被 hook 概率高的文件访问，比较中位数比值；
    /// 比值 >15 判异常，再做一次更敏感的放大探测（阈值 12）。
    private func detectTimingAnomaly() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        // 采样次数取自 TimingRatioBaseline，默认值由基线模块统一。
        let iterations = TimingRatioBaseline.defaultSampleCount
        let statFirst = Bool.random()

        var getpidSamples: [UInt64] = []
        getpidSamples.reserveCapacity(iterations)
        var statSamples: [UInt64] = []
        statSamples.reserveCapacity(iterations)

        /// 采样 getpid：每次前插入噪声计算，放大 Stalker DBT 的固定开销。
        func sampleGetpid() {
            for _ in 0..<iterations {
                // 噪声计算使 Stalker 需要翻译更多基本块，从而放大 hook 延迟。
                for _ in 0..<6 { TimingRatioBaseline.samplingNoise() }
                let start = mach_absolute_time()
                _ = cprisk_getpid_direct()
                let end = mach_absolute_time()
                getpidSamples.append(Self.nanoseconds(from: end - start))
            }
        }

        /// 采样 secureAccess：文件访问路径更容易被 Interceptor 插桩。
        func sampleStat() {
            for _ in 0..<iterations {
                for _ in 0..<6 { TimingRatioBaseline.samplingNoise() }
                let start = mach_absolute_time()
                // 使用不可被 libc hook 的直接访问封装，降低采样本身被篡改的可能。
                _ = SVCDirectCall.secureAccess("/usr/lib/dyld")
                let end = mach_absolute_time()
                statSamples.append(Self.nanoseconds(from: end - start))
            }
        }

        // 随机化先 stat 还是先 getpid，避免固定顺序被攻击者针对优化。
        if statFirst {
            sampleStat()
            sampleGetpid()
        } else {
            sampleGetpid()
            sampleStat()
        }

        // 动态基线比值：不受机型和系统负载影响。
        guard let evaluation = TimingRatioBaseline.evaluate(
            getpidSamples: getpidSamples,
            statSamples: statSamples
        ) else {
            return (0, [])
        }

        // 仅用比值判断：ratio > 15 为主条件，ratioP95 > 15 为辅助（均无量纲，不受机型/负载影响）
        // ratio > 15 视为异常，25 分。
        if evaluation.isAnomalous {
            score = 25
            methods.append(
                "timing_anomaly:ratio=\(String(format: "%.1f", evaluation.medianRatio))_ratioP95=\(String(format: "%.1f", evaluation.p95Ratio))"
            )
        }

        // 二次放大探测：间接函数指针 + 交替 syscall 使 Stalker DBT 开销显著放大
        // 二次放大探测：间接函数指针 + 交替 syscall，放大 Stalker 开销。
        let amplified = TimingRatioBaseline.amplifiedSamples()
        if let ampEval = TimingRatioBaseline.evaluate(
            getpidSamples: amplified.getpid,
            statSamples: amplified.stat,
            // 放大探测阈值更敏感（12.0），但单独信号置信较低。
            ratioThreshold: 12.0
        ) {
            if ampEval.isAnomalous {
                score += 20
                methods.append(
                    "timing_stalker_amplified:ratio=\(String(format: "%.1f", ampEval.medianRatio))_ratioP95=\(String(format: "%.1f", ampEval.p95Ratio))"
                )
            }
        }

        // timing 总分封顶 45。
        return (min(score, 45), methods)
    }
}

// MARK: - RiskSignal Conversion

/// 信号转换：socket、timing、Stalker 放大三类信号。
extension FridaSocketDetector {
    /// 命中时分别产出 Unix socket、timing anomaly、Stalker amplified 信号。
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        // socket 方法聚合为 signalFridaUnixSocket，每条 12 分，封顶 25。
        let socketMethods = result.methods.filter { $0.hasPrefix(ObfuscatedConstants.detectorIDFridaSocket) }
        if !socketMethods.isEmpty {
            signals.append(RiskSignal(
                id: ObfuscatedConstants.signalFridaUnixSocket,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(socketMethods.count) * 12, 25),
                evidence: ["detail": socketMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 75
            ))
        }

        // timing 方法聚合为 signalFridaTimingAnomaly，soft 状态置信 0.70。
        let timingMethods = result.methods.filter { $0.hasPrefix(ObfuscatedConstants.methodPrefixTimingAnomaly) }
        if !timingMethods.isEmpty {
            signals.append(RiskSignal(
                id: ObfuscatedConstants.signalFridaTimingAnomaly,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(timingMethods.count) * 10, 20),
                evidence: ["detail": timingMethods.joined(separator: ",")],
                state: .soft(confidence: 0.70),
                layer: 2,
                weightHint: 65
            ))
        }

        // 放大探测命中单独成信号，固定 20 分，置信 0.65。
        let amplifiedMethods = result.methods.filter { $0.hasPrefix(ObfuscatedConstants.methodPrefixTimingStalkerAmplified) }
        if !amplifiedMethods.isEmpty {
            signals.append(RiskSignal(
                id: ObfuscatedConstants.signalFridaStalkerAmplified,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 20,
                evidence: ["detail": amplifiedMethods.joined(separator: ",")],
                state: .soft(confidence: 0.65),
                layer: 2,
                weightHint: 65
            ))
        }

        return signals
    }
}
