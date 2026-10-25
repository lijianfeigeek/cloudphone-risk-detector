// DylibInjectionDetector：检测 IPA 重打包/越狱注入产生的恶意 dylib。
// 适用场景：攻击者无法运行期 attach（TLS/ptrace 被拦）时，改用 LC_LOAD_DYLIB
// 或 DYLD_INSERT_LIBRARIES 在启动前注入；注入库先于 SDK 初始化加载。
// 维度：镜像数量、可疑路径关键词、DYLD_INSERT_LIBRARIES、沙盒外 dylib。
import Darwin
import Foundation
import MachO

/// Detects malicious dylib injection via IPA repackaging.
///
/// Attackers who cannot attach at runtime (Frida attach blocked by TLS/ptrace)
/// fall back to inserting `LC_LOAD_DYLIB` commands in the Mach-O header or
/// using `DYLD_INSERT_LIBRARIES`. These injected dylibs load before any SDK
/// initialisation code, making this a high-priority detection surface.
///
/// Detection dimensions:
/// 1. Abnormal loaded-image count (baseline overflow)
/// 2. Suspicious dylib path keywords (hooking frameworks, rootless jailbreak paths)
/// 3. `DYLD_INSERT_LIBRARIES` environment variable presence
/// 4. Non-system, non-bundle dylibs (loaded from outside the app sandbox)
struct DylibInjectionDetector: Detector {

    // 镜像数量阈值：正常约 300–400；过高说明注入，过低说明镜像被隐藏。
    // MARK: - Thresholds

    // 正常上限 400 / 强可疑上限 500。
    private static let imageCountSoftLimit: UInt32 = 400
    private static let imageCountHardLimit: UInt32 = 500
    // 正常下限 180 / 强可疑下限 120。
    private static let imageCountLowSoftLimit: UInt32 = 180
    private static let imageCountLowHardLimit: UInt32 = 120

    // 已知恶意/hook 框架关键词（混淆常量，小写匹配）。
    // MARK: - Known-bad keywords (lowercase)

    private static var suspiciousKeywords: [String] { ObfuscatedConstants.dylibInjectionSuspiciousKeywords }

    /// Rootless jailbreak and other non-standard prefixes.
    // rootless 越狱及非标准安装前缀。
    private static let suspiciousPrefixes: [String] = [
        "/var/jb/",
        "/var/lib/",
        "/var/ulb/",
        "/usr/lib/tweaks/",
        "/bootstrap/",
    ]

    /// System / legitimate path prefixes that are expected on a stock device.
    // 原厂系统/合法路径前缀，命中这些前缀的镜像不参与沙盒外判定。
    private static let allowedPrefixes: [String] = [
        "/usr/lib/",
        "/System/",
        "/Library/",
        "/private/var/containers/",
        "/Developer/",
    ]

    // MARK: - Detector

    /// 执行四类注入检测并汇总（封顶 100）。
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["dylib_inject:unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []

        let countResult = detectAbnormalImageCount()
        score += countResult.score
        methods.append(contentsOf: countResult.methods)

        let keywordResult = detectSuspiciousDylibPaths()
        score += keywordResult.score
        methods.append(contentsOf: keywordResult.methods)

        let envResult = detectDyldInsertEnv()
        score += envResult.score
        methods.append(contentsOf: envResult.methods)

        let sandboxResult = detectOutOfSandboxDylibs()
        score += sandboxResult.score
        methods.append(contentsOf: sandboxResult.methods)

        return DetectorResult(score: min(score, 100), methods: methods)
#endif
    }

    // MARK: - 1a. Abnormal image count

    /// 按镜像数量分类：过多或过少都异常。
    static func classifyImageCount(_ count: UInt32) -> (score: Double, methods: [String]) {
        // 数量异常可能来自注入，也可能来自镜像被卸载隐藏。
        if count > imageCountHardLimit {
            return (20, ["dylib_inject:image_count_hard:\(count)"])
        } else if count > imageCountSoftLimit {
            return (10, ["dylib_inject:image_count_soft:\(count)"])
        } else if count < imageCountLowHardLimit {
            return (14, ["dylib_inject:image_count_low_hard:\(count)"])
        } else if count < imageCountLowSoftLimit {
            return (8, ["dylib_inject:image_count_low_soft:\(count)"])
        }
        return (0, [])
    }

    /// 读取当前 dyld 镜像数量并分类。
    private func detectAbnormalImageCount() -> (score: Double, methods: [String]) {
        Self.classifyImageCount(_dyld_image_count())
    }

    // MARK: - 1b. Suspicious dylib path keywords

    /// 检查镜像路径中的可疑关键词与 rootless 前缀。
    private func detectSuspiciousDylibPaths() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []
        let count = _dyld_image_count()

        for index in 0..<count {
            guard let rawName = _dyld_get_image_name(index) else { continue }
            let path = String(cString: rawName)
            let lower = path.lowercased()

            // 关键词命中：每条 25 分，同一镜像只记一次。
            for keyword in Self.suspiciousKeywords {
                if lower.contains(keyword) {
                    score += 25
                    methods.append("dylib_inject:keyword:\(keyword)")
                    break
                }
            }

            // rootless 前缀命中：每条 20 分。
            for prefix in Self.suspiciousPrefixes {
                if lower.hasPrefix(prefix) {
                    score += 20
                    methods.append("dylib_inject:rootless_path:\(prefix)")
                    break
                }
            }
        }
        return (min(score, 50), methods)
    }

    /// 判断路径是否以 rootless 前缀开头。
    static func isSuspiciousPrefixPath(_ path: String) -> Bool {
        let lower = path.lowercased()
        return suspiciousPrefixes.contains { lower.hasPrefix($0) }
    }

    // MARK: - 1c. DYLD_INSERT_LIBRARIES

    /// 检查 DYLD_INSERT_LIBRARIES 环境变量。
    private func detectDyldInsertEnv() -> (score: Double, methods: [String]) {
        // 变量存在且非空：启动前注入的直接证据，30 分。
        guard let rawValue = getenv("DYLD_INSERT_LIBRARIES") else {
            return (0, [])
        }
        let value = String(cString: rawValue)
        guard !value.isEmpty else { return (0, []) }
        return (30, ["dylib_inject:env_dyld_insert:\(value)"])
    }

    // MARK: - 1d. Non-system, non-bundle dylibs

    /// 检测既不在 App Bundle 内、也不在系统白名单中的 dylib。
    private func detectOutOfSandboxDylibs() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        // 以 Bundle 路径与系统白名单排除合法镜像。
        let bundlePath = Bundle.main.bundlePath
        let count = _dyld_image_count()

        for index in 0..<count {
            guard let rawName = _dyld_get_image_name(index) else { continue }
            let path = String(cString: rawName)

            if path.hasPrefix(bundlePath) { continue }
            if Self.allowedPrefixes.contains(where: { path.hasPrefix($0) }) { continue }

            // 其余路径视为沙盒外加载，每个 15 分。
            // Anything else is an out-of-sandbox, non-system dylib.
            score += 15
            methods.append("dylib_inject:out_of_sandbox:\(path)")
        }
        return (min(score, 40), methods)
    }
}

// MARK: - Signal Conversion

/// 信号转换：按类别分别成信号。
extension DylibInjectionDetector {
    /// 关键词/rootless/env 为 tampered；数量与沙盒外为 soft。
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        // 拆出镜像数量方法，区分过高与过低。
        let countMethods = result.methods.filter { $0.hasPrefix("dylib_inject:image_count") }
        let isLowImageCountMethod: (String) -> Bool = {
            $0.contains("image_count_low_hard") || $0.contains("image_count_low_soft")
        }
        let highCountMethods = countMethods.filter { !isLowImageCountMethod($0) }
        // 镜像数过高：soft，置信 0.6。
        if !highCountMethods.isEmpty {
            signals.append(RiskSignal(
                id: "dylib_inject_image_count",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(highCountMethods.count) * 15, 20),
                evidence: ["detail": highCountMethods.joined(separator: ",")],
                state: .soft(confidence: 0.6),
                layer: 2,
                weightHint: 55
            ))
        }

        // 镜像数过低：可能是卸载隐藏，hard low 置信更高。
        let lowCountMethods = countMethods.filter { isLowImageCountMethod($0) }
        if !lowCountMethods.isEmpty {
            let hardLow = lowCountMethods.contains { $0.contains("low_hard") }
            signals.append(RiskSignal(
                id: SignalID.dylibInjectImageCountLow,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: hardLow ? 18 : 10,
                evidence: ["detail": lowCountMethods.joined(separator: ",")],
                state: .soft(confidence: hardLow ? 0.82 : 0.7),
                layer: 2,
                weightHint: hardLow ? 62 : 48
            ))
        }

        // 可疑关键词：tampered，每条 20 分，封顶 50。
        let keywordMethods = result.methods.filter { $0.hasPrefix("dylib_inject:keyword") }
        if !keywordMethods.isEmpty {
            signals.append(RiskSignal(
                id: "dylib_inject_suspicious_keyword",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(keywordMethods.count) * 20, 50),
                evidence: ["detail": keywordMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 85
            ))
        }

        // rootless 路径：tampered，每条 18 分，封顶 40。
        let rootlessMethods = result.methods.filter { $0.hasPrefix("dylib_inject:rootless_path") }
        if !rootlessMethods.isEmpty {
            signals.append(RiskSignal(
                id: "dylib_inject_rootless_jailbreak",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(rootlessMethods.count) * 18, 40),
                evidence: ["detail": rootlessMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 82
            ))
        }

        // DYLD_INSERT_LIBRARIES：tampered，固定 30 分。
        let envMethods = result.methods.filter { $0.hasPrefix("dylib_inject:env_dyld_insert") }
        if !envMethods.isEmpty {
            signals.append(RiskSignal(
                id: "dylib_inject_env_insert",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 30,
                evidence: ["detail": envMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 88
            ))
        }

        // 沙盒外 dylib：soft，置信 0.75。
        let sandboxMethods = result.methods.filter { $0.hasPrefix("dylib_inject:out_of_sandbox") }
        if !sandboxMethods.isEmpty {
            signals.append(RiskSignal(
                id: "dylib_inject_out_of_sandbox",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(sandboxMethods.count) * 12, 35),
                evidence: ["detail": sandboxMethods.joined(separator: ",")],
                state: .soft(confidence: 0.75),
                layer: 2,
                weightHint: 78
            ))
        }

        return signals
    }
}
