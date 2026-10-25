// 文件职责：基于文件的 key/value 安全存储（原子写入 + NSFileProtectionComplete）。
// 管道位置：Storage 层底座，RiskHistoryStore / ProtectionStabilityStore 的持久化后端。
// 安全不变量：写盘原子且锁屏后不可读；key 做路径穿越清洗，避免越出沙箱目录。
import Foundation

/// 基于文件的安全 key/value 存储，启用 NSFileProtectionComplete。
///
/// 取代 UserDefaults 保存敏感数据。每个逻辑 key 对应 Application Support 下一个沙箱文件：
///   - `<key>.dat` — 加密载荷
///
/// HMAC 签名由调用方使用另一个 key 单独保存（本类只负责按 key 读写字节）。
/// 所有文件均以 `NSFileProtectionComplete` 创建，保证设备锁屏时数据处于加密状态。
final class SecureFileStore: @unchecked Sendable {

    /// 全局单例。
    static let shared = SecureFileStore()

    private let lock = NSLock()  // NSLock：锁内包含文件 I/O
    /// 所有 key 文件的根目录。
    private let baseDirectory: URL

    /// 创建存储实例。
    /// - Parameters:
    ///   - subdirectory: Application Support 下的相对子目录。
    ///   - overrideBaseDirectory: 测试用根目录覆盖（nil 时使用 Application Support）。
    init(
        subdirectory: String = "CloudPhoneRiskKit/secure_store",
        baseDirectory overrideBaseDirectory: URL? = nil
    ) {
        if let overrideBaseDirectory {
            self.baseDirectory = overrideBaseDirectory.appendingPathComponent(subdirectory, isDirectory: true)
            return
        }
        guard let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else {
            preconditionFailure("ApplicationSupportDirectory unavailable")
        }
        self.baseDirectory = appSupport.appendingPathComponent(subdirectory, isDirectory: true)
    }

    /// 读取指定 key 的原始数据。
    /// - Returns: 文件不存在或读取失败时为 nil。
    func read(key: String) -> Data? {
        lock.withLock {
            let url = fileURL(for: key)
            return try? Data(contentsOf: url)
        }
    }

    /// 原子写入指定 key 的数据，并启用 NSFileProtectionComplete。
    /// - Returns: 成功为 true；目录/写入/属性设置失败为 false（仅记录日志）。
    @discardableResult
    func write(key: String, data: Data) -> Bool {
        lock.withLock {
            do {
                try ensureDirectory()
                let url = fileURL(for: key)
                // 原子写入 + 创建即带完整文件保护，避免锁屏窗口期出现明文。
                try data.write(to: url, options: [.atomic, .completeFileProtection])
                // 再显式设置一次保护属性，覆盖已有文件的旧属性。
                try FileManager.default.setAttributes(
                    [.protectionKey: FileProtectionType.complete],
                    ofItemAtPath: url.path
                )
                return true
            } catch {
                Logger.log("SecureFileStore.write(\(key)) failed: \(error.localizedDescription)")
                return false
            }
        }
    }

    /// 删除指定 key 的文件（不存在时静默忽略）。
    func remove(key: String) {
        lock.withLock {
            let url = fileURL(for: key)
            try? FileManager.default.removeItem(at: url)
        }
    }

    /// 判断指定 key 的文件是否存在。
    func exists(key: String) -> Bool {
        lock.withLock {
            FileManager.default.fileExists(atPath: fileURL(for: key).path)
        }
    }

    /// 返回指定 key 的落盘字节数；文件不存在或读取失败时为 0。
    func size(key: String) -> Int {
        lock.withLock {
            let url = fileURL(for: key)
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
                  let size = attrs[.size] as? Int else {
                return 0
            }
            return size
        }
    }

    // MARK: - 私有实现

    /// 将逻辑 key 映射为 `<sanitized>.dat` 路径。
    private func fileURL(for key: String) -> URL {
        // 清洗路径分隔符与 `..`，防止 key 造成目录穿越。
        let sanitized = key
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "..", with: "_")
        return baseDirectory.appendingPathComponent("\(sanitized).dat")
    }

    /// 确保根目录存在，并对其设置完整文件保护。
    private func ensureDirectory() throws {
        let fm = FileManager.default
        if !fm.fileExists(atPath: baseDirectory.path) {
            // 首次写入时创建目录；保护属性在目录创建成功后设置。
            try fm.createDirectory(at: baseDirectory, withIntermediateDirectories: true)
            try fm.setAttributes(
                [.protectionKey: FileProtectionType.complete],
                ofItemAtPath: baseDirectory.path
            )
        }
    }
}
