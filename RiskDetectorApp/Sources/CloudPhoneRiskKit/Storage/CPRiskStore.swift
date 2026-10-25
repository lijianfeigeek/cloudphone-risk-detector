// 文件职责：本地风险报告的落盘/读取（加密存储、文件保护、保留策略）。
// 管道位置：报告产出后的持久化层，供后续上报或离线诊断读取。
// 安全不变量：Release 下强制 AES-GCM 加密且拒绝读取明文；写入原子并启用
// NSFileProtectionComplete，避免设备锁屏时数据可被读取。
#if os(iOS)
import Foundation

@objc(CPR_RiskStore)
/// 本地报告存储门面（Objective-C 可见）。
public final class CPRiskStore: NSObject {
    /// 全局单例。
    @objc public static let shared = CPRiskStore()

    /// 是否启用本地加密存储（AES-GCM + Keychain key）。
    /// Release 构建下不允许关闭加密：setter 赋值 false 会被自动回退为 true。
    @objc public var encryptionEnabled: Bool = true {
            // Release 构建禁止关闭加密：任何试图关闭的赋值都回退为 true。
        didSet {
            #if !DEBUG
            if !encryptionEnabled {
                Logger.log("CPRiskStore: encryptionEnabled=false rejected in release build")
                encryptionEnabled = true
            }
            #endif
        }
    }

    /// 最多保留多少份报告（超过会删除最旧的）。
    /// 保留文件上限；超过后按修改时间删除最旧文件。
    @objc public var maxFiles: Int = 50

    /// 单例构造，外部不可创建。
    private override init() {}

    /// 保存报告到本地（Application Support/CloudPhoneRiskKit/reports）。
    /// - 使用 `.atomic` 写入并设置文件保护，随后按 `maxFiles` 清理旧文件。
    /// - Parameters:
    ///   - report: 待保存的报告。
    ///   - error: 失败时写回 NSError。
    /// - Returns: 保存后的绝对路径；失败返回 nil。
    @objc(saveReport:error:)
    public func save(_ report: CPRiskReport, error: NSErrorPointer) -> String? {
        do {
            // 目录懒创建；已存在时不会报错。
            let base = try directoryURL()
            try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)

            // 文件名使用 ISO8601 时间戳；扩展名体现是否加密。
            let filename = "risk-\(ISO8601.nowString()).\(encryptionEnabled ? "bin" : "json")"
            let url = base.appendingPathComponent(filename)

            // 加密路径由 PayloadCrypto 负责（AES-GCM）。
            let data: Data
            if encryptionEnabled {
                data = try report.encryptedData()
            } else {
                data = report.unencryptedPayloadData(prettyPrinted: true)
            }

            // 原子写入：先写临时文件再重命名，避免崩溃留下半截报告。
            try data.write(to: url, options: [.atomic])
            // 显式设置锁屏后不可读，覆盖文件系统默认保护级别。
            try applyFileProtection(url: url)
            // 保留策略：删除最旧文件，防止磁盘无限增长。
            try enforceRetention(in: base, maxFiles: maxFiles)

            #if DEBUG
            Logger.log("store.save: path=\(url.path) bytes=\(data.count) encrypted=\(encryptionEnabled)")
            #endif
            return url.path
        } catch let e as NSError {
            Logger.log("store.save: failed error=\(e)")
            error?.pointee = e
            return nil
        }
    }

    /// 读取本地报告：`.json` 仅调试构建可直接读明文，其余走 AES-GCM 解密。
    /// - Parameters:
    ///   - path: 报告文件绝对路径。
    ///   - error: 失败时写回 NSError。
    /// - Returns: 解密后的 JSON 字符串；失败返回 nil。
    @objc(decryptReportAtPath:error:)
    public func decryptReport(atPath path: String, error: NSErrorPointer) -> String? {
        do {
            // 直接按路径读取；调用方需保证路径来自本 Store。
            let url = URL(fileURLWithPath: path)
            let data = try Data(contentsOf: url)
            let plaintext: Data
            // 扩展名决定读取方式：.json 为明文，其他视为加密载荷。
            if path.hasSuffix(".json") {
                #if DEBUG
                plaintext = data
                #else
                // Release 下不允许直接读取明文报告，防止攻击者通过公开 API 获取敏感数据
                Logger.log("store.decrypt: plaintext report access rejected in release build path=\(path)")
                let e = NSError(
                    domain: "CloudPhoneRiskKit",
                    code: 403,
                    userInfo: [NSLocalizedDescriptionKey: "Plaintext report access not allowed in release build"]
                )
                error?.pointee = e
                return nil
                #endif
            } else {
                // AES-GCM 解密失败会抛错，由外层统一返回 nil。
                plaintext = try PayloadCrypto.decrypt(data)
            }
            return String(data: plaintext, encoding: .utf8) ?? "{}"
        } catch let e as NSError {
            Logger.log("store.decrypt: failed path=\(path) error=\(e)")
            error?.pointee = e
            return nil
        }
    }

    /// 报告目录：Application Support/CloudPhoneRiskKit/reports。
    /// - Throws: Application Support 不可用时抛出 NSError。
    private func directoryURL() throws -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
        guard let base else {
            throw NSError(domain: "CloudPhoneRiskKit", code: 1, userInfo: [NSLocalizedDescriptionKey: "applicationSupportDirectory unavailable"])
        }
        return base.appendingPathComponent("CloudPhoneRiskKit/reports", isDirectory: true)
    }

    /// 设置 NSFileProtectionComplete：设备锁屏后文件不可读。
    private func applyFileProtection(url: URL) throws {
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
    }

    /// 按修改时间从旧到新排序，仅保留最新的 `maxFiles` 份；删除失败只记录日志。
    private func enforceRetention(in dir: URL, maxFiles: Int) throws {
        guard maxFiles > 0 else { return }
        let fm = FileManager.default
        let items = try fm.contentsOfDirectory(
            at: dir,
            includingPropertiesForKeys: [.contentModificationDateKey],
            options: [.skipsHiddenFiles]
        )
        // 只统计报告文件：每份报告旁边还有一个 `.meta.json` 摘要缓存，
        // 若把它也算进 maxFiles，实际只能保留一半数量的报告。
        let reportItems = items.filter { !$0.lastPathComponent.hasSuffix(".meta.json") }
        // 先按修改时间升序排序，前缀即为最旧的文件。
        let sorted = try reportItems.sorted { a, b in
            let ad = (try a.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            let bd = (try b.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            return ad < bd
        }
        if sorted.count <= maxFiles { return }
        for url in sorted.prefix(sorted.count - maxFiles) {
            do {
                try fm.removeItem(at: url)
                // 同步清理摘要缓存（约定路径为 `<report>.meta.json`），
                // 避免留下指向已删除报告的孤儿 meta。
                let metaURL = URL(fileURLWithPath: url.path + ".meta.json")
                try? fm.removeItem(at: metaURL)
            } catch {
                Logger.log("store.retention: failed to remove \(url.lastPathComponent) error=\(error.localizedDescription)")
            }
        }
    }
}
#endif
