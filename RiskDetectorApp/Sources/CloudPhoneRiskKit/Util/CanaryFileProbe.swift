// 金丝雀文件探针：在真正检查越狱路径之前，先 stat 一批“绝不可能不存在”的系统文件。
// 若这些文件都读不到，说明 stat/lstat 系统调用被 hook 或无差别屏蔽，本身就是强越狱/注入证据。
// 双路验证（DualPathValidator）负责区分“文件真的不存在”与“返回值被篡改”。

import Darwin
import Foundation

// MARK: - 金丝雀文件系统探针 [4.4.5]

/// 在检查越狱文件前，强制 stat 绝对存在的系统文件。
/// 如果连金丝雀文件都返回 ENOENT 或 EPERM，说明底层 syscall 遭到无差别拦截/屏蔽。
/// 同时通过 DualPathValidator 双路验证检测 stat hook 篡改。
enum CanaryFileProbe {

    // 以路径分段形式保存，避免在二进制里出现完整可读的敏感路径字面量。
    private static let allCanaryComponents: [[String]] = [
        ["usr", "lib", "dyld"],
        ["System", "Library", "CoreServices", "SystemVersion.plist"],
        ["usr", "lib", "libSystem.B.dylib"],
        ["etc", "passwd"],
        ["dev", "null"],
        ["usr", "lib", "libc++.1.dylib"],
        ["usr", "lib", "libobjc.A.dylib"],
        ["System", "Library", "Frameworks", "Foundation.framework", "Foundation"],
        ["System", "Library", "Frameworks", "UIKit.framework", "UIKit"],
        ["System", "Library", "Frameworks", "Security.framework", "Security"],
        ["System", "Library", "Frameworks", "CoreFoundation.framework", "CoreFoundation"],
        ["private", "var", "db", "timezone", "localtime"],
        ["usr", "lib", "libz.1.dylib"],
        ["usr", "lib", "libsqlite3.dylib"],
        ["dev", "urandom"],
        ["System", "Library", "CoreServices", "SpringBoard.app", "Info.plist"],
    ]

    // 每次只抽查固定数量：覆盖面足够，同时把探测开销控制在可接受范围。
    private static let subsetSize = 6

    /// 把路径分段拼回绝对路径。
    private static func buildPath(_ components: [String]) -> String {
        "/" + components.joined(separator: "/")
    }

    /// 运行时才能确定的路径（App 自身文件），用于验证沙盒内 syscall 是否正常。
    private static func dynamicCanaryPaths() -> [String] {
        var paths: [String] = []

        // 主 bundle 的 Info.plist：App 一定能访问，读不到即异常。
        let infoPlist = Bundle.main.bundlePath + "/Info.plist"
        paths.append(infoPlist)

        // 沙盒 Library 目录：正常存在且可 stat。
        let libraryDir = NSHomeDirectory() + "/Library"
        paths.append(libraryDir)

        if let executablePath = Bundle.main.executablePath {
            paths.append(executablePath)
        }

        return paths
    }

    /// 金丝雀探针权重
    /// 取 90 分：金丝雀死亡意味着整条文件检测链路可能已被致盲，属于高置信度异常。
    static let canaryDeadWeight: Double = 90

    /// 执行金丝雀探针，若 syscall 被致盲或 stat 被 hook 则返回异常结果。
    /// - Returns: 命中时返回带 `canaryDeadWeight` 分的检测结果；一切正常返回 nil。
    static func probe() -> DetectorResult? {
#if targetEnvironment(simulator)
        // 模拟器文件系统与真机差异大，金丝雀假设不成立，直接跳过避免误报。
        return nil
#else
        // 随机抽取子集并打乱顺序：让 hook 方无法针对固定路径做特判。
        let selected = Array(allCanaryComponents.shuffled().prefix(subsetSize))

        for components in selected {
            let path = buildPath(components)
            let validation = DualPathValidator.validateFileStat(path: path)

            // 文件不存在 = syscall 被致盲；这是比“发现越狱文件”更强的信号。
            if !validation.exists {
                Logger.log("jailbreak.canary.hit: syscall_blinded_canary_dead path=\(path) (+\(Int(canaryDeadWeight)))")
                return DetectorResult(score: canaryDeadWeight, methods: ["syscall_blinded_canary_dead"])
            }

            // 双路 stat 结果不一致 = stat 返回值被篡改。
            if validation.tampered {
                Logger.log("jailbreak.canary.hit: canary_stat_tampered path=\(path) (+\(Int(canaryDeadWeight)))")
                return DetectorResult(score: canaryDeadWeight, methods: ["canary_stat_tampered"])
            }

            // 检测到 DBI（动态二进制插桩）跟踪痕迹。
            if validation.traced {
                Logger.log("jailbreak.canary.hit: dbi_stalker_traced path=\(path) (+\(Int(canaryDeadWeight)))")
                return DetectorResult(score: canaryDeadWeight, methods: ["dbi_stalker_traced"])
            }
        }

        // 静态系统路径通过后，再验证 App 自身动态路径，覆盖沙盒内 hook。
        for path in dynamicCanaryPaths() {
            let validation = DualPathValidator.validateFileStat(path: path)

            if !validation.exists {
                Logger.log("jailbreak.canary.hit: syscall_blinded_canary_dead path=\(path) (+\(Int(canaryDeadWeight)))")
                return DetectorResult(score: canaryDeadWeight, methods: ["syscall_blinded_canary_dead"])
            }

            if validation.tampered {
                Logger.log("jailbreak.canary.hit: canary_stat_tampered path=\(path) (+\(Int(canaryDeadWeight)))")
                return DetectorResult(score: canaryDeadWeight, methods: ["canary_stat_tampered"])
            }

            if validation.traced {
                Logger.log("jailbreak.canary.hit: dbi_stalker_traced path=\(path) (+\(Int(canaryDeadWeight)))")
                return DetectorResult(score: canaryDeadWeight, methods: ["dbi_stalker_traced"])
            }
        }

        // 文件层面无明显异常时，再检查 libc 是否被 inline hook；权重更高（95）。
        if DualPathValidator.inlineHookDetected {
            Logger.log("jailbreak.canary.hit: libc_inline_hook_detected (+95)")
            return DetectorResult(score: 95, methods: ["libc_inline_hook_detected"])
        }

        return nil
#endif
    }
}
