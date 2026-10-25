// 越狱检测的配置模型：集中管理各检测器的启用开关与判定阈值。
// 由调用方在启动检测前构造并传入 JailbreakEngine；不同业务场景可选用预设配置。
// 关键安全不变量：阈值越低越敏感但误报越高；关闭检测器只会减少证据，不会提高安全性。
import Foundation

// MARK: - 越狱检测配置
/// 控制启用哪些越狱检测模块、判定阈值等
/// 值类型且 `Sendable`，可在并发评估中安全复制。
public struct JailbreakConfig: Sendable {

    // MARK: - 检测开关

    /// 是否启用文件检测
    /// 检测越狱相关文件是否存在（如 Cydia.app）
    public var enableFileDetect: Bool = true

    /// 是否启用 dyld 检测
    /// 检测是否加载了可疑动态库（如 Frida、Substrate）
    public var enableDyldDetect: Bool = true

    /// 是否启用环境变量检测
    /// 检测 DYLD_INSERT_LIBRARIES 等注入相关变量
    public var enableEnvDetect: Bool = true

    /// 是否启用系统调用检测
    /// 检测 fork() 等系统调用是否可用
    public var enableSysctlDetect: Bool = true

    /// 是否启用 URL Scheme 检测
    /// 检测 cydia:// 等 scheme 是否可打开
    public var enableSchemeDetect: Bool = true

    /// 是否启用 Hook 检测
    /// 该模块内部会串联多个反 Hook 子检测器，整体开销较高。
    public var enableHookDetect: Bool = true

    // MARK: - 阈值设置

    /// 判定阈值 (0-100)
    /// 当累计分数 >= 此值时，判定为越狱设备
    /// 阈值越低越敏感，但可能误报
    public var threshold: Double = 50.0

    // MARK: - 预设配置

    /// 默认配置 - 平衡检测
    public static let `default` = JailbreakConfig()

    /// 轻量配置 - 快速检测，适合启动时
    /// 只检测最明显的特征
    public static let light: JailbreakConfig = {
        var config = JailbreakConfig()
        config.enableFileDetect = true
        config.enableDyldDetect = true
        config.enableEnvDetect = false      // 关闭
        config.enableSysctlDetect = false   // 关闭
        config.enableSchemeDetect = false   // 关闭
        config.enableHookDetect = false     // 关闭
        config.threshold = 60.0             // 阈值提高，减少误报
        return config
    }()

    /// 完整配置 - 全面检测，适合高风险操作
    /// 开启全部检测器并降低阈值，以覆盖支付、登录等高风险链路。
    public static let full: JailbreakConfig = {
        var config = JailbreakConfig()
        config.enableFileDetect = true
        config.enableDyldDetect = true
        config.enableEnvDetect = true
        config.enableSysctlDetect = true
        config.enableSchemeDetect = true
        config.enableHookDetect = true
        config.threshold = 40.0             // 阈值降低，更敏感
        return config
    }()
}
