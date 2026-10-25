// ModuleWhitelistDetector：用路径白名单识别任意名称的恶意 dylib。
// DylibInjectionDetector 依赖关键词，但重签/越狱注入可使用 libutils.dylib 等任意名。
// 本检测器枚举所有已加载镜像，凡不属于系统白名单与 App Bundle 的模块均需进一步评估；
// 再按来源路径（tmp/容器 Data/未知）与磁盘可访问性（是否匿名加载）加权。
import CRiskCore
import Darwin
import Foundation
import MachO

// MARK: - Module Whitelist Detector
//
// DylibInjectionDetector 依赖关键词匹配（"frida", "substrate", "gadget" 等），
// 但 IPA 重签注入、越狱 tweak 注入、DYLD_INSERT_LIBRARIES 注入的 dylib
// 可以使用任意名称（如 "libutils.dylib"、"helper.dylib"），关键词匹配失效。
//
// 本检测器采用"白名单路径"策略：
// 1. 枚举所有已加载 dylib，路径不属于系统白名单且不属于 App Bundle → 可疑
// 2. 对可疑模块进一步评估：来源路径分类、磁盘签名状态
//
// 覆盖场景：免越狱 IPA 重签注入；越狱 tweak 注入；任意名称的恶意 dylib

/// 模块路径白名单检测器。
/// - 线程模型：同步只读遍历 dyld 镜像并对可疑路径做文件存在性探测。
/// - 误报控制：系统前缀、自身 Bundle、preboot 合法子路径均放行。
struct ModuleWhitelistDetector: Detector {

    // MARK: - Path Allowlist
    // 正常 iOS 进程中预期出现的路径前缀（小写比较）。
    // 正常 iOS 进程中预期出现的路径前缀（小写比较）。
    private static let systemPathPrefixes: [String] = [
        "/usr/lib/",
        "/system/",
        "/library/",
        "/private/var/containers/",       // App sandbox — own bundle allowed
        "/developer/",                     // Developer disk (already flagged by other detector)
        "/var/staged_system_apps/",        // OTA updates staging
    ]

    // /private/preboot 下允许的系统根目录名。
    private static let prebootSystemRoots: Set<String> = [
        "cryptexes",
        "system",
    ]

    /// Additional rootless jailbreak paths that are already covered by DylibInjectionDetector
    /// but listed here so we can give extra weight when combined with non-keyword signals.
    // 越狱路径前缀；与其他检测器重叠，用于组合加权。
    private static let jailbreakPathPrefixes: [String] = [
        "/var/jb/",
        "/var/lib/",
        "/var/ulb/",
        "/usr/lib/tweaks/",
        "/bootstrap/",
    ]

    // roothide/procursus/ellekit 等现代越狱关键词。
    private static let roothideSuspiciousKeywords: [String] = [
        "roothide", "procursus", "ellekit",
    ]

    /// File extensions that must appear in any legitimate framework or dylib name.
    // 合法模块应具有的扩展名。
    private static let legitimateExtensions: Set<String> = ["dylib", "framework", "so"]

    // MARK: - Scoring Parameters
    // 各维度基础分值：未知路径 18、越狱路径 12、匿名来源 20、无签名 15。
    private static let scoreUnknownPath: Double       = 18
    private static let scoreJailbreakPath: Double     = 12
    private static let scoreAnonOrigin: Double        = 20   // Module loaded from anonymous/tmp path
    private static let scoreUnsignedCode: Double      = 15
    // 多个未知模块的额外加分。
    private static let scoreMultipleUnknown: Double   = 12   // Bonus for ≥2 unknown modules
    // 总分封顶 80。
    private static let maxScore: Double               = 80

    // MARK: - Detector Protocol

    /// 入口：模拟器直接返回 0，真机进入 `detectKernel()`。
    @inline(never)
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["mwl:unavailable_simulator"])
#else
        return detectKernel()
#endif
    }

    /// 遍历镜像，按白名单/来源分类并计分。
    @inline(never)
    private func detectKernel() -> DetectorResult {
        // 统一小写，避免大小写差异绕过前缀匹配。
        let appBundlePath = Bundle.main.bundlePath.lowercased()
        let imageCount = _dyld_image_count()

        var score: Double = 0
        var methods: [String] = []
        var unknownModuleCount = 0

        for i in 0..<imageCount {
            guard let rawName = _dyld_get_image_name(i) else { continue }
            let imagePath = String(cString: rawName)
            let lowerPath = imagePath.lowercased()

            // Skip images in known system prefixes
            // 系统路径前缀：直接放行。
            if Self.systemPathPrefixes.contains(where: { lowerPath.hasPrefix($0) }) {
                continue
            }

            // Skip the app's own bundle
            // App 自身 Bundle：直接放行。
            if lowerPath.hasPrefix(appBundlePath) {
                continue
            }

            // Preboot volume: allow known system subpaths, flag everything else
            // preboot 卷：只允许已知系统子路径，其余可疑。
            if lowerPath.hasPrefix("/private/preboot/") {
                if Self.isAllowedPrebootSystemPath(lowerPath) {
                    continue
                }
                let hasRoothideKeyword = Self.roothideSuspiciousKeywords.contains(where: { lowerPath.contains($0) })
                // roothide/procursus/ellekit 关键词额外 +8。
                let roothideBonus: Double = hasRoothideKeyword ? 8 : 0
                score += Self.scoreJailbreakPath + roothideBonus
                methods.append("mwl:preboot_nonstandard\(hasRoothideKeyword ? "_roothide" : ""):\(sanitizeName(imagePath))")
                continue
            }

            // Check for jailbreak paths (additive with DylibInjectionDetector signal)
            // 越狱路径：基础 12 分，与其他检测器的同源信号可叠加。
            if Self.jailbreakPathPrefixes.contains(where: { lowerPath.hasPrefix($0) }) {
                score += Self.scoreJailbreakPath
                methods.append("mwl:jailbreak_path:\(sanitizeName(imagePath))")
                continue
            }

            // At this point the path doesn't match any allowlist — classify by origin
            // 未命中任何白名单，按来源分类。
            let origin = classifyOrigin(lowerPath)

            switch origin {
            // 匿名/tmp 来源：最可疑，20 分。
            case .anonymousOrTemp:
                score += Self.scoreAnonOrigin
                methods.append("mwl:anon_origin:\(sanitizeName(imagePath))")
                unknownModuleCount += 1

            // 容器 Data 内但不在 Bundle：未知路径分 + 无签名分。
            case .containerData:
                // A dylib loaded from within the container's data directory (not the app Bundle) is suspicious
                let sigOK = isCodeSignaturePresent(imagePath)
                let sigScore = sigOK ? 0.0 : Self.scoreUnsignedCode
                score += Self.scoreUnknownPath + sigScore
                methods.append("mwl:container_data\(sigOK ? "" : "_unsigned"):\(sanitizeName(imagePath))")
                unknownModuleCount += 1

            // 其他未知路径：同上。
            case .unknown:
                let sigOK = isCodeSignaturePresent(imagePath)
                let sigScore = sigOK ? 0.0 : Self.scoreUnsignedCode
                score += Self.scoreUnknownPath + sigScore
                methods.append("mwl:unknown_path\(sigOK ? "" : "_unsigned"):\(sanitizeName(imagePath))")
                unknownModuleCount += 1
            }
        }

        // Bonus for multiple unexpected modules (injection frameworks often load >1 lib)
        // 多个未知模块：注入框架通常一次加载多个库。
        if unknownModuleCount >= 2 {
            score += Self.scoreMultipleUnknown
            methods.append("mwl:multiple_unknown:\(unknownModuleCount)")
        }

        // 无异常时返回 clean 方法。
        if methods.isEmpty {
            methods.append("mwl:clean")
        }

        return DetectorResult(score: min(score, Self.maxScore), methods: methods)
    }

    // MARK: - Origin Classification

    /// 模块来源分类。
    private enum ModuleOrigin {
        case anonymousOrTemp    // /tmp, /var/tmp, /dev/shm, memory-only paths
        case containerData      // inside /private/var/mobile/Containers/Data/ but not in Bundle
        case unknown            // none of the above
    }

    /// 按路径前缀/片段判断模块来源。
    private func classifyOrigin(_ lowerPath: String) -> ModuleOrigin {
        if lowerPath.hasPrefix("/tmp/") ||
           lowerPath.hasPrefix("/var/tmp/") ||
           lowerPath.hasPrefix("/private/tmp/") ||
           lowerPath.hasPrefix("/dev/") {
            return .anonymousOrTemp
        }
        if lowerPath.contains("/containers/data/") {
            return .containerData
        }
        return .unknown
    }

    /// 判断 preboot 路径是否属于允许的系统目录。
    static func isAllowedPrebootSystemPath(_ lowerPath: String) -> Bool {
        let prefix = "/private/preboot/"
        guard lowerPath.hasPrefix(prefix) else { return false }

        let relative = lowerPath.dropFirst(prefix.count)
        let components = relative.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard !components.isEmpty else { return false }

        // 直接 system/cryptexes 根目录。
        if Self.prebootSystemRoots.contains(components[0]) {
            return true
        }

        guard components.count >= 2 else { return false }
        // <volumeUUID>/system 或 <volumeUUID>/cryptexes 形式。
        return isLikelyPrebootVolumeID(components[0]) && Self.prebootSystemRoots.contains(components[1])
    }

    /// 判断组件是否为 36 位 UUID（8-4-4-4-12）。
    private static func isLikelyPrebootVolumeID(_ component: String) -> Bool {
        // 预启动卷 ID 固定 36 位，含 4 个连字符。
        guard component.count == 36 else { return false }
        for (index, byte) in component.utf8.enumerated() {
            let shouldBeHyphen = index == 8 || index == 13 || index == 18 || index == 23
            if shouldBeHyphen {
                guard byte == 45 else { return false }
            } else {
                let isHex = (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
                guard isHex else { return false }
            }
        }
        return true
    }

    // MARK: - Code Signature Check

    /// Checks whether an image has a code signature LC command.
    /// A missing signature is a strong indicator of a dynamically injected / rebuilt library.
    /// 判断镜像文件在磁盘上是否存在（存在则假定有签名）。
    private func isCodeSignaturePresent(_ imagePath: String) -> Bool {
        /// 打不开通常意味着模块只在匿名内存中，属于强可疑。
        // Attempt to open the dylib on disk and verify it has a code signature
        // We use cprisk_access_direct to bypass any libc hook on `access(2)`
        var errnoVal: CInt = 0
        let rc = imagePath.withCString { cPath in
            cprisk_access_direct(cPath, F_OK, &errnoVal)
        }
        // 文件不可访问：可能来自匿名/注入内存，按无签名处理。
        guard rc == 0 else {
            // File not accessible on disk → likely loaded from anonymous/injected memory
            return false
        }

        // 文件存在即假定有签名：完整解析 Mach-O 成本高，且其他检测器已覆盖签名校验。
        // If file exists on disk, assume it has a code signature (full Mach-O parsing
        // would be expensive; unsigned-from-disk libs are already caught by codesign checks
        // in CodeSignatureValidator and AppSigningIdentityDetector).
        return true
    }

    // MARK: - Utilities

    /// Truncate and sanitize a path for evidence logging.
    /// 截断路径，仅保留最后两段，避免遥测泄漏完整沙盒路径。
    private func sanitizeName(_ path: String) -> String {
        // 只保留最后两个路径组件。
        // Keep only the last two path components to avoid leaking full sandbox paths
        let components = path.split(separator: "/")
        let tail = components.suffix(2).joined(separator: "/")
        return tail.isEmpty ? path : tail
    }
}

// MARK: - Signal Bridge

/// 信号转换。
extension ModuleWhitelistDetector {
    /// 未知/匿名/容器 Data 模块聚合为一条 whitelist violation 信号。
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        // 只聚合真正越界的模块，不含 jailbreak_path/preboot 方法。
        let unknownModules = result.methods.filter {
            $0.hasPrefix("mwl:unknown_path") || $0.hasPrefix("mwl:anon_origin") || $0.hasPrefix("mwl:container_data")
        }

        return [RiskSignal(
            id: "module_whitelist_violation",
            category: ObfuscatedConstants.categoryAntiTamper,
            score: result.score,
            // 违规模块数与模块名（截断前 4 条）。
            evidence: [
                "violation_count": "\(unknownModules.count)",
                "modules": unknownModules.prefix(4).joined(separator: "|"),
            ],
            // 置信度随违规模块数上升，封顶 0.92。
            state: .soft(confidence: min(0.55 + Double(unknownModules.count) * 0.12, 0.92)),
            layer: 2,
            weightHint: 70
        )]
    }
}
