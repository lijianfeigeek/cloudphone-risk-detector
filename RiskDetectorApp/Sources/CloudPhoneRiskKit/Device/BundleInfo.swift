// Bundle 元信息采集器：读取安装时间、Bundle ID、版本与构建号。
// 位于设备信号采集层，为评估提供应用身份与生命周期上下文。
// 全部为只读查询；读取失败返回 nil 而不是抛出，调用方必须容忍缺失。
// 隐私边界：只读取本 App 的公开元信息，不访问其他应用或用户数据。

import Foundation

/// Bundle 元信息采集器
///
/// 提供从 Bundle 中读取应用元信息的能力：
/// - 安装时间（首次安装时间，非本次更新）
/// - Bundle ID
/// - 版本号
/// - 构建号
public final class BundleInfo {

    /// 单例实例：无状态、只读，可全局共享。
    public static let shared = BundleInfo()

    /// 私有初始化，禁止外部创建实例。
    private init() {}

    // MARK: - 安装时间

    /// 应用首次安装时间（Unix 时间戳，秒）
    ///
    /// 通过检查 App Store 收据或 NSFileManager 创建时间推断。
    /// - 在 App Store 环境：通过 `_NSBundleReceiptPath` 读取收据目录 mtime
    /// - 在非 App Store 环境：通过主 Bundle 可执行文件创建时间推断（近似安装时间）
    /// - 两路都取不到时返回 nil（例如沙箱限制或文件属性不可读）
    public var installDate: Date? {
        // 尝试 App Store 收据路径
        if let receiptPath = BundleInfo.receiptPath {
            let attrs = try? FileManager.default.attributesOfItem(atPath: receiptPath)
            if let mtime = attrs?[.modificationDate] as? Date {
                return mtime
            }
        }
        // 回退：主 Bundle 可执行文件创建时间
        guard let execPath = Bundle.main.executablePath else { return nil }
        let attrs = try? FileManager.default.attributesOfItem(atPath: execPath)
        return attrs?[.creationDate] as? Date
    }

    // MARK: - Bundle ID

    /// 当前 App 的 Bundle ID；理论上恒存在，仍以可选返回以兼容异常环境。
    public var bundleIdentifier: String? {
        Bundle.main.bundleIdentifier
    }

    // MARK: - 版本信息

    /// CFBundleShortVersionString（如 "1.2.3"）
    public var shortVersion: String? {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String
    }

    /// CFBundleVersion（如 "100"）
    public var buildVersion: String? {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String
    }

    /// 完整版本字符串（如 "1.2.3 (100)"）；字段缺失时以 "unknown" 占位。
    public var fullVersionString: String {
        let v = shortVersion ?? "unknown"
        let b = buildVersion ?? "unknown"
        return "\(v) (\(b))"
    }

    // MARK: - 私有实现

    /// App Store 收据路径
    /// 仅在能确认文件存在时返回；否则返回 nil，由调用方回退到可执行文件时间。
    private static var receiptPath: String? {
        #if os(iOS)
        // 沙盒环境下有效路径：/private/var/mobile/Applications/{GUID}/StoreKit/receipt
        // 但在 Swift 层无法直接访问，保守处理
        // macOS App Store 收据：~/Library/Receipts 或 App Bundle 内的 receipt
        #if canImport(AppKit)
        if let appStoreReceiptURL = Bundle.main.appStoreReceiptURL {
            let url = appStoreReceiptURL
            if FileManager.default.fileExists(atPath: url.path) {
                return url.path
            }
        }
        #endif
        #endif
        return nil
    }
}
