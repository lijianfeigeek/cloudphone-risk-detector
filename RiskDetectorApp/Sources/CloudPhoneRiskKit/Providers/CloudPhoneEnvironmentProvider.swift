import Foundation
#if canImport(UIKit)
import UIKit
#endif

// 云手机环境综合 Provider。
// 从网络时延、屏幕分辨率、热状态、管理进程名、语言/时区一致性五个正交维度
// 识别云手机/虚拟化环境；每个维度独立输出信号，由上层组合评分。

// MARK: - 云手机环境检测
//
// 五个互不依赖的信号族：
//   1. 网络时延是否异常均匀（RTT）
//   2. 屏幕分辨率/缩放是否异常
//   3. 热状态是否长期恒为 nominal
//   4. 是否存在云手机管理进程
//   5. locale 与 timezone 是否不一致

/// 云手机环境综合检测器，输出 `network_latency_pattern`、`screen_resolution_anomaly`、
/// `thermal_state_anomaly`、`cloud_process_detected`、`locale_timezone_mismatch`。
/// 检查顺序可按远程策略扰动。
public final class CloudPhoneEnvironmentProvider: RiskSignalProvider {
    static let shared = CloudPhoneEnvironmentProvider()

    public let id = "cloudphone_environment"

    /// 已知云手机管理进程名片段（小写）。命中仅作佐证，权重较低。
    static let knownCloudProcessKeywords: [String] = [
        "cloudphoned",
        "armcloud",
        "redfinger",
        "bignox",
        "nowgg",
        "phonecloud",
        "remotefarm",
        "nbfarm",
        "thunder_cloud",
        "baidu_cloud_phone",
    ]

    /// 地区码 -> 期望时区前缀映射，用于发现“语言/地区与系统时区不匹配”。
    static let regionTimezonePrefixes: [String: [String]] = [
        "US": ["America/"],
        "GB": ["Europe/London"],
        "CN": ["Asia/Shanghai", "Asia/Chongqing", "Asia/Harbin", "Asia/Urumqi"],
        "JP": ["Asia/Tokyo"],
        "KR": ["Asia/Seoul"],
        "DE": ["Europe/Berlin"],
        "FR": ["Europe/Paris"],
        "IN": ["Asia/Kolkata", "Asia/Calcutta"],
        "BR": ["America/Sao_Paulo", "America/Fortaleza", "America/Manaus", "America/Recife"],
        "AU": ["Australia/"],
    ]

    /// 云手机农场常见的非典型分辨率/缩放组合，每项为 (宽, 高, scale)。
    /// iOS 真机通常为 @2x/@3x，这里出现 scale=1.0/0.5 的多为虚拟显示输出。
    static let atypicalResolutions: [(Int, Int, Double)] = [
        (720, 1280, 1.0),
        (1080, 1920, 1.0),
        (1080, 2340, 1.0),
        (1440, 2560, 1.0),
        (720, 1280, 0.5),
        (1080, 1920, 0.5),
    ]

    public init() {}

    /// 依次执行五个环境检查，每项独立产生信号；顺序可按策略打乱。
    public func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let planner = MutationPlanner(
            strategy: activeMutationStrategy(),
            scope: id,
            deviceID: snapshot.deviceID
        )

        let checks: [() -> [RiskSignal]] = [
            { self.networkLatencySignals(snapshot: snapshot) },
            { self.screenResolutionSignals(snapshot: snapshot) },
            { self.thermalStateSignals() },
            { self.processNameSignals() },
            { self.localeTimezoneSignals(snapshot: snapshot) },
        ]

        var out: [RiskSignal] = []
        for check in planner.maybeShuffle(checks, salt: "cloudphone_env_checks") {
            out.append(contentsOf: check())
        }
        return planner.maybeShuffle(out, salt: "cloudphone_env_emit_order")
    }

    // MARK: - 私有检查

    /// 1. 网络时延模式：云手机常出现异常均匀的回环 RTT。
    /// - 采样 6 次，少于 3 次视为不可用；
    /// - 用变异系数 CV 衡量离散度，再用峰度识别“人为注入抖动”的绕过手法。
    private func networkLatencySignals(snapshot: RiskSnapshot) -> [RiskSignal] {
        #if targetEnvironment(simulator)
        return [
            RiskSignal(
                id: "network_latency_pattern",
                category: "environment",
                score: 0,
                evidence: ["detail": "simulator"],
                state: .unavailable,
                layer: 3,
                weightHint: 60
            ),
        ]
        #else
        let samples = measureRTTSamples(count: 6)
        guard samples.count >= 3 else {
            return [
                RiskSignal(
                    id: "network_latency_pattern",
                    category: "environment",
                    score: 0,
                    evidence: ["detail": "insufficient_samples"],
                    state: .unavailable,
                    layer: 3,
                    weightHint: 60
                ),
            ]
        }

        let variance = computeVariance(samples)
        let mean = samples.reduce(0, +) / Double(samples.count)
        let cv = mean > 0 ? (variance.squareRoot() / mean) : 1.0
        let kurt = computeKurtosis(samples, mean: mean, variance: variance)

        // 两个正交信号组合：
        //
        // 1. CV（变异系数）：云手机虚拟调度器给出近乎恒定的回环时延，CV 接近 0。
        //    高级操作者可能注入抖动，把 CV 抬到“看似正常”的 0.03–0.15 区间。
        //
        // 2. 峰度：真实网络抖动近似高斯分布（峰度 ≈ 3）；人为注入的均匀抖动
        //    呈低峰态（峰度 ≈ 1.8）。在 0.03–0.15 的 CV 区间内出现低峰度，
        //    正好暴露“注入抖动”的绕过行为。
        let cvConfidence: Double
        if cv < 0.01 {
            cvConfidence = 0.95
        } else if cv < 0.03 {
            cvConfidence = 0.75
        } else if cv < 0.08 {
            cvConfidence = 0.45
        } else {
            cvConfidence = 0.15
        }

        // 在“抖动注入”常见的 CV 区间内出现低峰度，提示分布被人工拉平。
        // kurtosis 为 nil 表示样本不足 4 个，无法计算四阶矩，保守不加分。
        let kurtosisBoost: Double
        if let k = kurt, cv >= 0.03, cv < 0.15, k < 2.2 {
            // 有离散度但分布接近均匀，判为人工抖动。
            kurtosisBoost = 0.25
        } else {
            kurtosisBoost = 0.0
        }

        let confidence = min(cvConfidence + kurtosisBoost, 0.95)

        Logger.log("CloudPhoneEnv: RTT cv=\(String(format: "%.4f", cv)), kurtosis=\(kurt.map { String(format: "%.2f", $0) } ?? "n/a"), boost=\(kurtosisBoost), samples=\(samples.count)")

        return [
            RiskSignal(
                id: "network_latency_pattern",
                category: "environment",
                score: 0,
                evidence: [
                    "rtt_cv": String(format: "%.6f", cv),
                    "rtt_variance": String(format: "%.6f", variance),
                    "rtt_mean_ms": String(format: "%.2f", mean),
                    "rtt_kurtosis": kurt.map { String(format: "%.4f", $0) } ?? "n/a",
                    "samples": "\(samples.count)",
                ],
                state: .soft(confidence: confidence),
                layer: 3,
                weightHint: 60
            ),
        ]
        #endif
    }

    /// 2. 屏幕分辨率一致性：云手机可能上报非典型的分辨率/缩放组合。
    private func screenResolutionSignals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let width = snapshot.device.screenWidth
        let height = snapshot.device.screenHeight
        let scale = snapshot.device.screenScale

        let isAtypical = Self.atypicalResolutions.contains { res in
            res.0 == width && res.1 == height && abs(res.2 - scale) < 0.01
        }

        // iOS 高分屏若报告 scale=1.0，通常意味着虚拟显示未正确暴露 @2x/@3x。
        let suspiciousScale = scale == 1.0 && (width > 640 || height > 1136)

        let confidence: Double
        if isAtypical {
            confidence = 0.85
        } else if suspiciousScale {
            confidence = 0.65
        } else {
            confidence = 0.1
        }

        Logger.log("CloudPhoneEnv: screen \(width)x\(height)@\(scale), atypical=\(isAtypical), suspiciousScale=\(suspiciousScale)")

        return [
            RiskSignal(
                id: "screen_resolution_anomaly",
                category: "environment",
                score: 0,
                evidence: [
                    "width": "\(width)",
                    "height": "\(height)",
                    "scale": String(format: "%.2f", scale),
                    "atypical_match": "\(isAtypical)",
                ],
                state: .soft(confidence: confidence),
                layer: 2,
                weightHint: 70
            ),
        ]
    }

    // 热状态跨调用历史存于 UserDefaults；单次读取几乎总是 nominal，没有判别力。
    // 需要至少 thermalHistoryMinCount 个跨会话样本才能下结论，避免点采样误报。
    static let thermalSnapshotKey = "cprk_cpenv_thermal_snaps"
    private static let thermalHistoryMinCount = 3
    // 只保留最近 12 次，防止历史无限增长；也限制旧状态对新判决的影响。
    private static let thermalHistoryMaxCount = 12

    /// 3. 热状态异常：云手机在多次评估中始终报告 nominal，
    /// 而真实设备在负载下偶尔会进入 fair/serious。单次读取无意义，
    /// 因此累积跨调用历史，只有全部记录都是 nominal 时才标记。
    private func thermalStateSignals() -> [RiskSignal] {
        #if targetEnvironment(simulator)
        return [
            RiskSignal(
                id: "thermal_state_anomaly",
                category: "environment",
                score: 0,
                evidence: ["detail": "simulator"],
                state: .unavailable,
                layer: 2,
                weightHint: 55
            ),
        ]
        #elseif canImport(UIKit)
        let currentRaw = ProcessInfo.processInfo.thermalState.rawValue

        // 将当前读数写入滚动历史，超出上限时丢弃最旧记录。
        var history = loadThermalHistory()
        history.append(currentRaw)
        if history.count > Self.thermalHistoryMaxCount {
            history.removeFirst(history.count - Self.thermalHistoryMaxCount)
        }
        saveThermalHistory(history)

        guard history.count >= Self.thermalHistoryMinCount else {
            Logger.log("CloudPhoneEnv: thermal history insufficient (\(history.count)/\(Self.thermalHistoryMinCount)), deferring")
            return [
                RiskSignal(
                    id: "thermal_state_anomaly",
                    category: "environment",
                    score: 0,
                    evidence: [
                        "detail": "insufficient_history",
                        "sample_count": "\(history.count)",
                        "required": "\(Self.thermalHistoryMinCount)",
                    ],
                    state: .unavailable,
                    layer: 2,
                    weightHint: 55
                ),
            ]
        }

        let allNominal = history.allSatisfy { $0 == ProcessInfo.ThermalState.nominal.rawValue }
        let uniqueCount = Set(history).count

        let confidence: Double
        if allNominal {
            // 置信度随历史深度提升：样本越多越可信，范围约 [0.55 … 0.75]。
            let depth = min(Double(history.count), Double(Self.thermalHistoryMaxCount))
            let depthRatio = depth / Double(Self.thermalHistoryMaxCount)
            confidence = 0.55 + depthRatio * 0.20  // [0.55 … 0.75]
        } else {
            confidence = 0.05
        }

        Logger.log("CloudPhoneEnv: thermal history=\(history.count) readings, allNominal=\(allNominal), uniqueStates=\(uniqueCount)")

        return [
            RiskSignal(
                id: "thermal_state_anomaly",
                category: "environment",
                score: 0,
                evidence: [
                    "all_nominal": "\(allNominal)",
                    "unique_states": "\(uniqueCount)",
                    "sample_count": "\(history.count)",
                ],
                state: .soft(confidence: confidence),
                layer: 2,
                weightHint: 55
            ),
        ]
        #else
        return [
            RiskSignal(
                id: "thermal_state_anomaly",
                category: "environment",
                score: 0,
                evidence: ["detail": "platform_unsupported"],
                state: .unavailable,
                layer: 2,
                weightHint: 55
            ),
        ]
        #endif
    }

    /// 从 UserDefaults 读取热状态历史（逗号分隔的 rawValue）；无记录返回空数组。
    func loadThermalHistory() -> [Int] {
        guard let raw = UserDefaults.standard.string(forKey: Self.thermalSnapshotKey),
              !raw.isEmpty else { return [] }
        return raw.split(separator: ",")
            .compactMap { Int($0.trimmingCharacters(in: .whitespaces)) }
    }

    /// 将热状态历史写回 UserDefaults。
    func saveThermalHistory(_ history: [Int]) {
        UserDefaults.standard.set(
            history.map { String($0) }.joined(separator: ","),
            forKey: Self.thermalSnapshotKey
        )
    }

    /// 4. 进程名模式：查找云手机管理守护进程。
    private func processNameSignals() -> [RiskSignal] {
        #if targetEnvironment(simulator)
        return [
            RiskSignal(
                id: "cloud_process_detected",
                category: "environment",
                score: 0,
                evidence: ["detail": "simulator"],
                state: .unavailable,
                layer: 1,
                weightHint: 35
            ),
        ]
        #else
        let dynamicPatterns = PolicyManager.shared.activePolicy?.newVPhonePatterns.map { $0.lowercased() } ?? []
        let allPatterns = Self.knownCloudProcessKeywords + dynamicPatterns

        let suspiciousProcesses = detectSuspiciousProcesses(patterns: allPatterns)
        let detected = !suspiciousProcesses.isEmpty

        if detected {
            #if DEBUG
            Logger.log("CloudPhoneEnv: suspicious processes found: \(suspiciousProcesses)")
            #else
            Logger.log("CloudPhoneEnv: suspicious processes detected count=\(suspiciousProcesses.count)")
            #endif
        }

        // 说明：进程名匹配是弱信号——内核级 CVD 定制可以随意给守护进程改名。
        // 权重刻意压低，仅作佐证，绝不单独作为强判决依据。
        return [
            RiskSignal(
                id: "cloud_process_detected",
                category: "environment",
                score: 0,
                evidence: [
                    "matched_processes": suspiciousProcesses.joined(separator: ","),
                    "pattern_count": "\(allPatterns.count)",
                ],
                state: detected ? .hard(detected: true) : .soft(confidence: 0.05),
                layer: 1,
                weightHint: 35
            ),
        ]
        #endif
    }

    /// 5. locale/timezone 不一致：云手机的 locale 地区与系统时区可能来自不同模板。
    private func localeTimezoneSignals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let localeId = snapshot.device.localeIdentifier
        let timezoneId = snapshot.device.timeZoneIdentifier

        // 从 locale 提取地区码（如 "en_US" -> "US"，"zh-Hans_CN" -> "CN"）。
        let regionCode = extractRegionCode(from: localeId)

        guard let region = regionCode, let expectedPrefixes = Self.regionTimezonePrefixes[region] else {
            // 未知地区无法判断，只给极低置信度输出，避免把正常小语种地区误判。
            return [
                RiskSignal(
                    id: "locale_timezone_mismatch",
                    category: "environment",
                    score: 0,
                    evidence: [
                        "locale": localeId,
                        "timezone": timezoneId,
                        "region": regionCode ?? "unknown",
                    ],
                    state: .soft(confidence: 0.1),
                    layer: 2,
                    weightHint: 65
                ),
            ]
        }

        let matches = expectedPrefixes.contains { timezoneId.hasPrefix($0) }

        let confidence: Double
        if !matches {
            confidence = 0.8
        } else {
            confidence = 0.05
        }

        Logger.log("CloudPhoneEnv: locale=\(localeId), tz=\(timezoneId), region=\(region), tzMatch=\(matches)")

        return [
            RiskSignal(
                id: "locale_timezone_mismatch",
                category: "environment",
                score: 0,
                evidence: [
                    "locale": localeId,
                    "timezone": timezoneId,
                    "region": region,
                    "tz_matches_region": "\(matches)",
                ],
                state: .soft(confidence: confidence),
                layer: 2,
                weightHint: 65
            ),
        ]
    }

    // MARK: - 辅助方法

    /// 从远程策略构造变异策略；无策略时返回 nil。
    private func activeMutationStrategy() -> MutationStrategy? {
        guard let mutation = PolicyManager.shared.activePolicy?.mutation else { return nil }
        return MutationStrategy(
            seed: mutation.seed,
            shuffleChecks: mutation.shuffleChecks,
            thresholdJitterBps: mutation.thresholdJitterBps,
            scoreJitterBps: mutation.scoreJitterBps
        )
    }

    /// 计算样本方差（除以 n-1）；少于 2 个样本返回 0。
    func computeVariance(_ series: [Double]) -> Double {
        guard series.count > 1 else { return 0 }
        let mean = series.reduce(0, +) / Double(series.count)
        let squaredDiffs = series.map { pow($0 - mean, 2) }
        return squaredDiffs.reduce(0, +) / Double(series.count - 1)
    }

    /// 计算样本的 Pearson 峰度（非超额峰度）。
    /// - 少于 4 个样本或方差为 0 时返回 nil（统计上无意义）；
    /// - 正态分布 ≈ 3.0，均匀分布 ≈ 1.8，用于区分真实抖动与人工抖动。
    func computeKurtosis(_ series: [Double], mean: Double, variance: Double) -> Double? {
        guard series.count >= 4, variance > 0 else { return nil }
        let n = Double(series.count)
        let m4 = series.map { pow($0 - mean, 4) }.reduce(0, +) / n
        return m4 / (variance * variance)
    }

    /// 通过轻量 TCP 连接测量 loopback RTT 样本（毫秒）。
    /// 目的不是访问服务，而是测量本机调度/虚拟化开销。
    private func measureRTTSamples(count: Int) -> [Double] {
        var results: [Double] = []
        for _ in 0..<count {
            let start = CFAbsoluteTimeGetCurrent()
            // 连接 127.0.0.1 的任意端口，测量建立连接耗时。
            let sock = socket(AF_INET, SOCK_STREAM, 0)
            guard sock >= 0 else { continue }
            defer { close(sock) }

            // 非阻塞 + 50ms 发送超时，防止个别环境卡住采样循环。
            var timeout = timeval(tv_sec: 0, tv_usec: 50_000) // 50ms
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = UInt16(12345).bigEndian
            addr.sin_addr.s_addr = inet_addr("127.0.0.1")

            withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    _ = connect(sock, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }

            let elapsed = (CFAbsoluteTimeGetCurrent() - start) * 1000.0 // ms
            results.append(elapsed)
        }
        return results
    }

    /// 通过 sysctl KERN_PROC 枚举可见进程名，并匹配云手机关键词。
    /// 看不到其他进程时返回空数组（iOS 沙箱下也可能如此），不视为异常。
    private func detectSuspiciousProcesses(patterns: [String]) -> [String] {
        var matched: [String] = []

        // 先用 KERN_PROC_ALL 查询所需缓冲区大小，再分配并二次读取。
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size: Int = 0
        guard sysctl(&mib, UInt32(mib.count), nil, &size, nil, 0) == 0, size > 0 else {
            return matched
        }

        let count = size / MemoryLayout<kinfo_proc>.stride
        var procList = [kinfo_proc](repeating: kinfo_proc(), count: count)
        guard sysctl(&mib, UInt32(mib.count), &procList, &size, nil, 0) == 0 else {
            return matched
        }

        let actualCount = size / MemoryLayout<kinfo_proc>.stride
        for i in 0..<actualCount {
            var info = procList[i]
            var processComm = info.kp_proc.p_comm
            let commCapacity = MemoryLayout.size(ofValue: processComm)
            let name = withUnsafePointer(to: &processComm) { ptr in
                ptr.withMemoryRebound(to: CChar.self, capacity: commCapacity) {
                    String(cString: $0)
                }
            }
            let lower = name.lowercased()
            for pattern in patterns {
                if lower.contains(pattern) {
                    matched.append(name)
                    break
                }
            }
        }

        return matched
    }

    /// 从 locale 标识中提取两位大写地区码。
    /// 支持 "en_US"、"zh-Hans_CN"、"en_US@calendar=gregorian" 等格式；无法识别返回 nil。
    private func extractRegionCode(from localeIdentifier: String) -> String? {
        // 先去掉 "@..." 修饰，再取 "_" 后的最后一段。
        let cleaned = localeIdentifier.components(separatedBy: "@").first ?? localeIdentifier
        let parts = cleaned.components(separatedBy: "_")
        guard parts.count >= 2 else { return nil }
        let candidate = parts.last!
        // 地区码通常为 2 位大写字母。
        if candidate.count == 2 && candidate == candidate.uppercased() && candidate.allSatisfy({ $0.isLetter }) {
            return candidate
        }
        return nil
    }
}
