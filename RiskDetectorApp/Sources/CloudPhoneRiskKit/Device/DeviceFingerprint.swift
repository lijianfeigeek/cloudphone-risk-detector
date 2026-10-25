// 设备指纹快照：采集系统、机型、时区、屏幕与内核构建等低敏设备属性。
// 位于设备信号采集层，供风险评分与图特征派生使用。
// 隐私边界：IDFV 默认做 SHA-256 后再上报（见 `hashIdentifierForVendor`），
// 原始 UUID、序列号等强标识不采集；字段缺失时以 nil/0 降级而非报错。
// 安全不变量：本文件只读系统信息，不做任何持久化或跨 App 采集。

import CryptoKit
import Foundation
#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

/// 某一时刻的设备属性快照（Codable，可安全跨线程传递）。
/// 注意：这些字段组合可用于设备关联，服务端应按隐私政策最小化存储。
public struct DeviceFingerprint: Codable, Sendable {
    /// 是否对 IDFV 做哈希化上报（默认 `true`）。
    ///
    /// ⚠️ 追踪风险：IDFV 是同一供应商下稳定的设备标识，原始 UUID 上报后
    /// 可被服务端跨会话追踪到同一台设备。默认对 IDFV 做 SHA-256 哈希：
    /// 哈希仍是稳定伪匿名标识（同一设备 → 同一哈希），因此 IDFV 变化
    /// 检测（重装/换机）逻辑仍然成立，但原始 UUID 不会出现在上报载荷、
    /// 日志与崩溃转储中。注意：哈希不是匿名化——服务端仍能按哈希关联
    /// 同一设备；如需彻底避免关联，需关闭上报（见 `hashIdentifierForVendor = false`
    /// 仅在明确需要原始 IDFV 的合规场景下使用，且须经隐私评审）。
    /// 字段名 `"iv"` 不变，避免改协议。
    public static var hashIdentifierForVendor: Bool = true

    /// IDFV 上报值：默认返回 SHA-256 哈希（hex），`hashIdentifierForVendor == false` 时返回原始 UUID。
    /// - Parameter rawUUIDString: 系统提供的原始 IDFV；为 nil 或空串时返回 nil。
    /// - Returns: 小写 hex 哈希，或调用方明确关闭哈希时的原始 UUID。
    public static func reportedIdentifierForVendor(_ rawUUIDString: String?) -> String? {
        guard let raw = rawUUIDString, !raw.isEmpty else { return nil }
        // 合规开关关闭时才允许原始 IDFV 外发，默认路径不会出现原始 UUID。
        guard hashIdentifierForVendor else { return raw }
        return SHA256.hash(data: Data(raw.utf8)).map { String(format: "%02x", $0) }.joined()
    }
    /// 操作系统名称（如 "iOS"）。
    public var systemName: String
    /// 操作系统版本（如 "17.2"）。
    public var systemVersion: String
    /// 设备类别（如 "iPhone"）。
    public var model: String
    /// 本地化设备类别（随语言变化）。
    public var localizedModel: String
    /// 供应商标识（默认已哈希）；模拟器/无法获取时为 nil。
    public var identifierForVendor: String?

    /// 当前区域标识（如 "zh_CN"）。
    public var localeIdentifier: String
    /// 当前时区标识（如 "Asia/Shanghai"）。
    public var timeZoneIdentifier: String
    /// 相对 GMT 的时区偏移（秒），东八区为 28800。
    public var timeZoneOffsetSeconds: Int

    /// 屏幕宽度（像素，已乘 scale）。
    public var screenWidth: Int
    /// 屏幕高度（像素，已乘 scale）。
    public var screenHeight: Int
    /// 屏幕缩放因子（如 3.0）。
    public var screenScale: Double

    /// 硬件机器标识（如 "iPhone15,2"，来自 hw.machine）。
    public var hardwareMachine: String? = nil
    /// 硬件型号标识（来自 hw.model）。
    public var hardwareModel: String? = nil
    /// 是否运行在模拟器；是则视为高风险环境信号之一。
    public var isSimulator: Bool = false
    /// 内核构建 ID（如 "22A400"），用于发现异常内核/越狱环境。
    public var kernelBuild: String? = nil

    /// 线上编码短键：压缩上报载荷，字段语义保持不变。
    private enum CodingKeys: String, CodingKey {
        case systemName = "sn"
        case systemVersion = "sv"
        case model = "m"
        case localizedModel = "lm"
        case identifierForVendor = "iv"
        case localeIdentifier = "li"
        case timeZoneIdentifier = "tz"
        case timeZoneOffsetSeconds = "to"
        case screenWidth = "sw"
        case screenHeight = "sh"
        case screenScale = "ss"
        case hardwareMachine = "hm"
        case hardwareModel = "hd"
        case isSimulator = "is"
        case kernelBuild = "kb"
    }

    /// 采集当前设备属性快照。
    /// - iOS：读取 UIDevice、UIScreen、Locale、TimeZone 与 sysctl。
    /// - macOS：读取 NSScreen 与 ProcessInfo；无 IDFV。
    /// - 其他平台：返回 "unknown"/0 的保守快照，保证调用方无需处理 Optional。
    /// 任何单个系统调用失败都不会抛出，只会让对应字段为 nil/0。
    public static func current() -> DeviceFingerprint {
#if canImport(UIKit)
        let device = UIDevice.current
        let locale = Locale.current
        let tz = TimeZone.current
        let bounds = UIScreen.main.bounds
        let scale = UIScreen.main.scale
        let machine = Sysctl.string("hw.machine")
        let model = Sysctl.string("hw.model")
        // 编译期即可确定是否模拟器目标，无需运行时探测。
        #if targetEnvironment(simulator)
        let simulator = true
        #else
        let simulator = false
        #endif

        return DeviceFingerprint(
            systemName: device.systemName,
            systemVersion: device.systemVersion,
            model: device.model,
            localizedModel: device.localizedModel,
            identifierForVendor: Self.reportedIdentifierForVendor(device.identifierForVendor?.uuidString),
            localeIdentifier: locale.identifier,
            timeZoneIdentifier: tz.identifier,
            timeZoneOffsetSeconds: tz.secondsFromGMT(),
            screenWidth: Int(bounds.width * scale),
            screenHeight: Int(bounds.height * scale),
            screenScale: Double(scale),
            hardwareMachine: machine,
            hardwareModel: model,
            isSimulator: simulator,
            kernelBuild: Self.extractKernelBuild(from: Sysctl.string("kern.version"))
        )
#elseif canImport(AppKit)
        // macOS 分支：无 IDFV；屏幕缺失时退化为 2x / 零尺寸，避免可选值扩散。
        let locale = Locale.current
        let tz = TimeZone.current
        let os = ProcessInfo.processInfo.operatingSystemVersion
        let version = "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"
        let scale = NSScreen.main?.backingScaleFactor ?? 2.0
        let frame = NSScreen.main?.frame ?? .zero
        return DeviceFingerprint(
            systemName: "macOS",
            systemVersion: version,
            model: "Mac",
            localizedModel: "Mac",
            identifierForVendor: nil,
            localeIdentifier: locale.identifier,
            timeZoneIdentifier: tz.identifier,
            timeZoneOffsetSeconds: tz.secondsFromGMT(),
            screenWidth: Int(frame.width * scale),
            screenHeight: Int(frame.height * scale),
            screenScale: Double(scale),
            hardwareMachine: Sysctl.string("hw.machine"),
            hardwareModel: Sysctl.string("hw.model"),
            isSimulator: false,
            kernelBuild: Self.extractKernelBuild(from: Sysctl.string("kern.version"))
        )
#else
        // 未知平台：返回占位值而非失败，确保上报载荷结构稳定。
        let locale = Locale.current
        let tz = TimeZone.current
        return DeviceFingerprint(
            systemName: "unknown",
            systemVersion: "unknown",
            model: "unknown",
            localizedModel: "unknown",
            identifierForVendor: nil,
            localeIdentifier: locale.identifier,
            timeZoneIdentifier: tz.identifier,
            timeZoneOffsetSeconds: tz.secondsFromGMT(),
            screenWidth: 0,
            screenHeight: 0,
            screenScale: 1,
            hardwareMachine: nil,
            hardwareModel: nil,
            isSimulator: false,
            kernelBuild: nil
        )
#endif
    }

    /// 从 kern.version 字符串中提取 kernel build ID（如 "22A400"、"23F79"）。
    ///
    /// ## 典型格式
    ///
    /// - Darwin Kernel Version 22.0.0: Mon Aug  7 16:06:22 PDT 2023; root:xnu-8792.1.25.3~2/RELEASE_ARM64_T8101
    ///   → "22A400"（通过 build 版本号推断）
    /// - kern.version 示例: "Darwin Kernel Version 23.0.0.0: Thu Oct 26 15:18:41 PDT 2023; root:xnu-10002.1.13.100.1~1/RELEASE_ARM64_T8101"
    ///   → "23F79"
    ///
    /// ## 提取策略
    ///
    /// 优先从 `kern.osversion` sysctl 直接读取（最可靠），
    /// 备用从 `kern.version` 字符串中解析 "Build" 后面的字母数字组合。
    public static func extractKernelBuild(from versionString: String?, osVersion: String? = nil) -> String? {
        // 策略1：直接读 kern.osversion（最可靠）
        let effectiveOSVersion = osVersion ?? Sysctl.string("kern.osversion")
        if let effectiveOSVersion, Self.looksLikeKernelBuild(effectiveOSVersion) {
            return effectiveOSVersion
        }

        // 策略2：从 kern.version 字符串解析 "Build" 标记后的内容
        guard let versionString, !versionString.isEmpty else { return nil }

        // 匹配 "Build " 后面的字符序列（不含空格和分号）
        // 例如: "... Build 22A400; ..." 或 "... Build 23F79 ..."
        if let buildRange = versionString.range(of: "Build ") {
            let afterBuild = versionString[buildRange.upperBound...]
            // Build ID 通常是连续的字母数字，最多约 8 个字符
            let buildID = afterBuild.prefix(8).trimmingCharacters(in: .whitespacesAndNewlines)
                .components(separatedBy: CharacterSet.alphanumerics.inverted).first ?? ""
            if Self.looksLikeKernelBuild(buildID) {
                return buildID
            }
        }

        // 策略3：扫描整段字符串中的 build-like token，避免把 RELEASE_ARM64_T8101 误判成 kernel build。
        let candidates = versionString.components(separatedBy: CharacterSet.alphanumerics.inverted)
        if let buildID = candidates.first(where: { Self.looksLikeKernelBuild($0) }) {
            return buildID
        }

        return nil
    }

    /// 判断字符串是否符合 Apple 内核 build ID 格式（如 "22A400"、"23F79a"）。
    /// - Returns: 形如 2–3 位数字 + 大写字母 + 2–4 位数字 + 可选小写字母时为 true。
    /// 该判断用于从任意内核版本字符串中过滤出真正的 build ID，避免误取
    /// 架构名（如 "RELEASE_ARM64_T8101"）或日期片段。
    public static func looksLikeKernelBuild(_ candidate: String) -> Bool {
        let trimmed = candidate.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }

        let bytes = Array(trimmed.utf8)
        // 典型 build ID 长度 5–8（如 "22A400"、"23F79"），过短/过长都视为噪声。
        guard (5...8).contains(bytes.count) else { return false }

        var index = 0
        // 前缀 2–3 位数字：对应 Darwin 主版本（"22"/"23"）。
        while index < bytes.count, bytes[index] >= 48, bytes[index] <= 57 {
            index += 1
        }
        guard index >= 2, index <= 3, index < bytes.count else { return false }

        let letter = bytes[index]
        // 版本字母必须是大写 A–Z；小写版本字母不符合 Apple build 格式。
        guard letter >= 65, letter <= 90 else { return false }
        index += 1

        var digitCount = 0
        // 字母后缀 2–4 位数字（如 "400"/"79"）。
        while index < bytes.count, bytes[index] >= 48, bytes[index] <= 57 {
            digitCount += 1
            index += 1
        }
        guard digitCount >= 2, digitCount <= 4 else { return false }

        if index == bytes.count {
            return true
        }

        // 允许末尾一个可选小写字母后缀（如 "22A400a"）。
        guard index == bytes.count - 1 else { return false }
        let suffix = bytes[index]
        return suffix >= 97 && suffix <= 122
    }
}
