// CloudPhoneRiskKit 配置缓存模块：在内存与沙盒加密文件中保存远端配置及其验签状态，
// 为 RemoteConfigProvider 提供过期判断、可信条目过滤、版本历史与自动回滚钉扎。
// 磁盘数据经 PayloadCrypto 加密并用 StorageIntegrityGuard HMAC 签名；Release 下
// 解密失败、HMAC 不符、内容哈希不匹配或条目未经服务端验签时一律丢弃（fail-closed）。

import CryptoKit
import Foundation

/// 配置缓存抽象；`RemoteConfigProvider` 通过该协议注入内存缓存或持久化缓存。
public protocol ConfigCaching: Sendable {
    /// 读取当前可用的最新配置；无可信条目时返回 `nil`。
    func load() -> CachedConfig?
    /// 保存配置（默认视为未经服务端验签的普通缓存）。
    func save(_ config: RemoteConfig)
    /// 保存配置并显式标记是否已通过服务端签名验证。
    func save(_ config: RemoteConfig, verifiedByServer: Bool)
    /// 清空内存与磁盘缓存。
    func clear()
    /// 返回磁盘缓存字节数（内存缓存返回 0）。
    func cacheSize() -> Int
    /// 返回内存/磁盘缓存状态快照，用于诊断。
    func cacheStats() -> CacheStats
    /// 生产可用：仅允许回滚到本地已缓存且通过 `isUsableTrustedEntry` / 验签链校验的条目（Release 下等价于服务端已验证）。
    func rollbackToNewestVerifiedVersion(below ceilingVersion: Int) -> RemoteConfig?
}

extension ConfigCaching {
    /// 默认实现：不支持回滚的缓存直接返回 `nil`。
    public func rollbackToNewestVerifiedVersion(below ceilingVersion: Int) -> RemoteConfig? {
        nil
    }
}

extension ConfigCaching {
    /// 便捷重载：未指定验签状态时按“未验证”保存，Release 下不会被当作可信条目读取。
    public func save(_ config: RemoteConfig) {
        save(config, verifiedByServer: false)
    }
}

// Storage: sandboxed file with NSFileProtectionComplete via SecureFileStore.
// Migrated from UserDefaults to ensure data-at-rest encryption when device is locked.
// 存储位置：沙盒文件（SecureFileStore，NSFileProtectionComplete），
// 从 UserDefaults 迁移而来，确保设备锁定时缓存仍是加密静态数据。
/// 基于内存 + 加密文件的配置缓存实现。
///
/// 线程模型：所有读写由进程级 `globalLock`（`NSRecursiveLock`）串行化，
/// 因此以 `@unchecked Sendable` 暴露。可信性不变量：Release 构建中只有
/// 已验签且内容哈希匹配的条目可被读取；DEBUG 为便于联调放宽并在日志中告警。
public final class ConfigCache: @unchecked Sendable, ConfigCaching {
    public static let shared = ConfigCache()

    /// 单条缓存记录：配置本体、写入时间、验签标记与内容哈希。
    private struct CacheEntry: Codable {
        let config: RemoteConfig
        /// 写入缓存的 Unix 时间戳（秒），用于过期判断与历史排序。
        let cachedAt: TimeInterval
        /// 是否来自通过服务端签名验证的拉取；Release 下读取时强制为 true。
        let isVerifiedByServer: Bool
        /// 配置内容的 SHA-256；用于检测缓存被篡改或序列化不一致。
        let contentHash: String?

        // 短键减少磁盘体积。
        private enum CodingKeys: String, CodingKey {
            case config = "c"
            case cachedAt = "ca"
            case isVerifiedByServer = "iv"
            case contentHash = "ch"
        }

        /// 创建缓存条目；未显式提供内容哈希时立即计算。
        init(config: RemoteConfig, cachedAt: TimeInterval, isVerifiedByServer: Bool = false, contentHash: String? = nil) {
            self.config = config
            self.cachedAt = cachedAt
            self.isVerifiedByServer = isVerifiedByServer
            self.contentHash = contentHash ?? Self.computeContentHash(for: config)
        }

        /// 解码旧版本缓存：缺少验签标记时按“未验证”处理，避免历史数据被误信任。
        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            config = try container.decode(RemoteConfig.self, forKey: .config)
            cachedAt = try container.decode(TimeInterval.self, forKey: .cachedAt)
            isVerifiedByServer = try container.decodeIfPresent(Bool.self, forKey: .isVerifiedByServer) ?? false
            contentHash = try container.decodeIfPresent(String.self, forKey: .contentHash)
        }

        /// 计算配置内容的 SHA-256。使用 `sortedKeys` 保证同一配置得到稳定哈希。
        fileprivate static func computeContentHash(for config: RemoteConfig) -> String? {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            guard let data = try? encoder.encode(config) else { return nil }
            return SHA256.hash(data: data).compactMap { String(format: "%02x", $0) }.joined()
        }
    }

    // 全局锁：进程内所有 ConfigCache 实例共享，锁住内存缓存与磁盘读写。
    private static let globalLock = NSRecursiveLock()
    // 内存中的最新条目；nil 表示未加载或已被判定不可信。
    private var memoryCache: CacheEntry?
    private let diskKey: String
    private let hmacDiskKey: String
    private let versionKey: String
    private let rollbackVersionKey: String
    /// 磁盘最多保留的版本数，超出后丢弃最旧版本（按版本号排序）。
    private let maxDiskEntries: Int
    private let persistToDisk: Bool
    private let fileStore: SecureFileStore

    /// 创建缓存实例。
    /// - Parameters:
    ///   - namespace: 多租户/多实例隔离前缀；为空时使用默认键。
    ///   - persistToDisk: `false` 时仅内存缓存（测试用）。
    ///   - maxDiskEntries: 磁盘保留的配置版本上限，默认 5。
    ///   - fileStore: 底层安全文件存储。
    init(
        namespace: String? = nil,
        persistToDisk: Bool = true,
        maxDiskEntries: Int = 5,
        fileStore: SecureFileStore = .shared
    ) {
        if let namespace, !namespace.isEmpty {
            self.diskKey = "com.cloudphone.riskkit.remote_config_cache.\(namespace)"
            self.hmacDiskKey = "com.cloudphone.riskkit.remote_config_cache.\(namespace)_hmac"
            self.versionKey = "com.cloudphone.riskkit.config_version.\(namespace)"
            self.rollbackVersionKey = "com.cloudphone.riskkit.config_rollback_version.\(namespace)"
        } else {
            self.diskKey = "com.cloudphone.riskkit.remote_config_cache"
            self.hmacDiskKey = "com.cloudphone.riskkit.remote_config_cache_hmac"
            self.versionKey = "com.cloudphone.riskkit.config_version"
            self.rollbackVersionKey = "com.cloudphone.riskkit.config_rollback_version"
        }
        self.persistToDisk = persistToDisk
        self.maxDiskEntries = maxDiskEntries
        self.fileStore = fileStore
        self.memoryCache = nil
        // 初始化时同步加载一次磁盘缓存；加载过程已做完整性与可信性过滤。
        self.memoryCache = ConfigCache.globalLock.withLock { loadLatestFromDisk() }
    }

    /// 创建带命名空间的持久化缓存实例（不同业务/租户互不干扰）。
    public static func instance(withNamespace namespace: String) -> ConfigCache {
        ConfigCache(namespace: namespace, persistToDisk: true)
    }

    /// 创建仅内存缓存实例，适合测试或禁止落盘的场景。
    public static func inMemoryCache() -> ConfigCache {
        ConfigCache(namespace: "memory", persistToDisk: false)
    }

    /// 读取当前可用配置。
    /// 优先返回内存条目，失效后回源磁盘；Release 下只接受可信条目，
    /// 全部不可信时返回 `nil` 并清空内存缓存。
    public func load() -> CachedConfig? {
        ConfigCache.globalLock.withLock {
            // DEBUG 放宽为“可用即可”，Release 必须通过内容哈希 + 服务端验签双重校验。
            #if DEBUG
            let isUsable = { [self] (e: CacheEntry, s: String) in self.isUsableDebugEntry(e, source: s) }
            #else
            let isUsable = { [self] (e: CacheEntry, s: String) in self.isUsableTrustedEntry(e, source: s) }
            #endif
            if let memoryCache, isUsable(memoryCache, "memory_cache") {
                return CachedConfig(
                    config: memoryCache.config,
                    cachedAt: memoryCache.cachedAt,
                    isVerifiedByServer: memoryCache.isVerifiedByServer,
                    contentHash: memoryCache.contentHash
                )
            }
            memoryCache = nil

            if let latest = loadLatestFromDisk() {
                memoryCache = latest
                return CachedConfig(
                    config: latest.config,
                    cachedAt: latest.cachedAt,
                    isVerifiedByServer: latest.isVerifiedByServer,
                    contentHash: latest.contentHash
                )
            }

            return nil
        }
    }

    /// 保存配置到内存与磁盘。
    /// - Parameter verifiedByServer: 是否已通过服务端签名验证；Release 读取时会据此过滤。
    /// - Note: 磁盘写入失败会删除版本标记并返回，内存缓存不更新，避免状态与磁盘不一致。
    public func save(_ config: RemoteConfig, verifiedByServer: Bool = false) {
        ConfigCache.globalLock.withLock {
            let entry = CacheEntry(
                config: config,
                cachedAt: Date().timeIntervalSince1970,
                isVerifiedByServer: verifiedByServer
            )

            // 纯内存模式下只维护内存条目。
            guard persistToDisk else {
                memoryCache = entry
                return
            }

            var entries = loadAllDiskEntries()
            // 同一版本只保留最新一条，防止重复版本污染回滚候选集。
            entries.removeAll { $0.config.version == config.version }
            entries.append(entry)
            entries = entries.sorted { $0.config.version > $1.config.version }

            // 只保留版本号最大的 N 条，控制磁盘占用。
            if entries.count > maxDiskEntries {
                entries = Array(entries.prefix(maxDiskEntries))
            }

            guard saveDiskEntries(entries) else {
                Logger.log("ConfigCache.save: failed to persist config cache version=\(config.version)")
                // 清理版本标记，避免下次启动把未写入成功的新版本当成当前版本。
                fileStore.remove(key: versionKey)
                fileStore.remove(key: rollbackVersionKey)
                return
            }
            if let vData = "\(config.version)".data(using: .utf8) {
                guard fileStore.write(key: versionKey, data: vData) else {
                    Logger.log("ConfigCache.save: failed to persist current version=\(config.version)")
                    fileStore.remove(key: versionKey)
                    return
                }
            }
            // 成功写入新版本后解除回滚钉扎，后续读取回到“最高可信版本”。
            fileStore.remove(key: rollbackVersionKey)
            memoryCache = entry
        }
    }

    /// 清空所有缓存数据（内存、载荷、HMAC、版本与回滚钉扎）。
    public func clear() {
        ConfigCache.globalLock.withLock {
            memoryCache = nil
            guard persistToDisk else { return }
            fileStore.remove(key: diskKey)
            fileStore.remove(key: hmacDiskKey)
            fileStore.remove(key: versionKey)
            fileStore.remove(key: rollbackVersionKey)
        }
    }

    /// 磁盘缓存载荷字节数；仅内存模式返回 0。
    public func cacheSize() -> Int {
        ConfigCache.globalLock.withLock {
            guard persistToDisk,
                  let data = fileStore.read(key: diskKey) else {
                return 0
            }
            return data.count
        }
    }

    /// 返回缓存状态快照（诊断用，不触发加载副作用）。
    public func cacheStats() -> CacheStats {
        ConfigCache.globalLock.withLock {
            CacheStats(
                hasMemoryCache: memoryCache != nil,
                diskSizeBytes: cacheSizeUnlocked(),
                diskEntryCount: loadAllDiskEntries().count
            )
        }
    }

    /// 手动回滚到指定版本（仅 DEBUG）。
    /// Release 下任意指定版本可能被用于降级到存在漏洞的旧配置，因此直接拒绝。
    public func rollback(to version: Int) -> RemoteConfig? {
#if DEBUG
        ConfigCache.globalLock.withLock {
            guard let target = loadAllDiskEntries().first(where: { $0.config.version == version }) else {
                return nil
            }

            memoryCache = target
            // 钉扎回滚版本，下次启动仍读取该版本而不是最高版本。
            if persistToDisk, let data = "\(version)".data(using: .utf8),
               !fileStore.write(key: rollbackVersionKey, data: data) {
                Logger.log("ConfigCache.rollback: failed to persist rollback version=\(version)")
            }
            return target.config
        }
#else
        Logger.log("ConfigCache.rollback rejected: not allowed in release build")
        return nil
#endif
    }

    /// 自动稳定性回滚：选择 **严格小于** `ceilingVersion` 的最高可信缓存版本并写入 `rollbackVersionKey` 钉扎。
    /// - Note: 与 DEBUG-only `rollback(to:)` 不同；不允许任意指定版本号，仅能从已持久化且可信的条目中选择。
    /// - Parameter ceilingVersion: 上界（通常是刚拉取但表现异常的版本）；候选必须小于它。
    /// - Returns: 回滚目标配置；没有可信候选或钉扎写入失败时返回 `nil`。
    public func rollbackToNewestVerifiedVersion(below ceilingVersion: Int) -> RemoteConfig? {
        ConfigCache.globalLock.withLock {
            // Int.min 无法构成有效上界，直接拒绝，避免减法/比较溢出语义。
            guard ceilingVersion > Int.min else { return nil }
            let allEntries = loadAllDiskEntries()
            #if DEBUG
            let candidates = allEntries.filter { entry in
                entry.config.version < ceilingVersion && isUsableDebugEntry(entry, source: "verified_rollback_below")
            }
            #else
            let candidates = allEntries.filter { entry in
                entry.config.version < ceilingVersion && isUsableTrustedEntry(entry, source: "verified_rollback_below")
            }
            #endif
            guard let target = candidates.max(by: { $0.config.version < $1.config.version }) else {
                Logger.log("ConfigCache.rollbackToNewestVerifiedVersion: no candidate below ceiling=\(ceilingVersion)")
                return nil
            }
            if persistToDisk, let data = "\(target.config.version)".data(using: .utf8),
               !fileStore.write(key: rollbackVersionKey, data: data) {
                Logger.log("ConfigCache.rollbackToNewestVerifiedVersion: failed to persist pinned version=\(target.config.version)")
                return nil
            }
            memoryCache = target
            Logger.log("ConfigCache.rollbackToNewestVerifiedVersion: pinned version=\(target.config.version) verified=\(target.isVerifiedByServer)")
            return target.config
        }
    }

    /// 返回磁盘中所有可用版本号（降序），用于诊断与回滚候选展示。
    public func availableVersions() -> [Int] {
        ConfigCache.globalLock.withLock {
            loadAllDiskEntries().map { $0.config.version }.sorted(by: >)
        }
    }

    /// 按写入时间倒序返回版本历史，供设置页/诊断面板展示。
    public func versionHistory() -> [VersionHistoryEntry] {
        ConfigCache.globalLock.withLock {
            loadAllDiskEntries()
                .sorted { $0.cachedAt > $1.cachedAt }
                .map {
                    VersionHistoryEntry(
                        version: $0.config.version,
                        timestamp: $0.cachedAt,
                        environment: $0.config.environment,
                        description: $0.config.description
                    )
                }
        }
    }

    /// 从旧格式数据迁移：由调用方提供转换器，转换成功后按普通（未验签）条目保存。
    public func migrate(from legacyData: Data, using migrator: (Data) throws -> RemoteConfig) throws {
        let config = try migrator(legacyData)
        save(config)
    }

    /// 导出当前磁盘缓存为 JSON（DEBUG 调试/迁移用）；编码失败返回 `nil`。
    public func exportCache() -> Data? {
        ConfigCache.globalLock.withLock {
            let entries = loadAllDiskEntries()
            let payload = CacheExport(exportedAt: Date().timeIntervalSince1970, entries: entries)
            return try? JSONEncoder().encode(payload)
        }
    }

    /// 导入缓存数据（仅 DEBUG）。
    /// Release 禁止导入：外部数据未经签名链校验，导入等于给攻击者注入配置的入口。
    public func importCache(from data: Data) throws {
#if DEBUG
        let decoded = try JSONDecoder().decode(CacheExport.self, from: data)
        for entry in decoded.entries {
            // 导入条目一律标记为未验签，DEBUG 读取时才可能被接受。
            save(entry.config, verifiedByServer: false)
        }
#else
        Logger.log("ConfigCache.importCache rejected: not allowed in release build")
        throw ConfigError.importFailed(reason: "importCache not allowed in release build")
#endif
    }

    /// 缓存导出载荷（版本化字段短键）。
    private struct CacheExport: Codable {
        let exportedAt: TimeInterval
        let entries: [CacheEntry]

        private enum CodingKeys: String, CodingKey {
            case exportedAt = "ea"
            case entries = "en"
        }
    }

    /// 从磁盘选择“当前应使用”的条目。
    /// 优先级：回滚钉扎版本 > 最高已验签版本 >（仅 DEBUG）最高任意版本。
    /// Release 下没有任何已验签条目时返回 `nil`，绝不回退到未验证配置。
    private func loadLatestFromDisk() -> CacheEntry? {
        guard persistToDisk else { return nil }
        let allEntries = loadAllDiskEntries()
        #if DEBUG
        let all = allEntries.filter { isUsableDebugEntry($0, source: "disk_cache") }
        #else
        let all = allEntries.filter { isUsableTrustedEntry($0, source: "disk_cache") }
        #endif
        if let rollbackData = fileStore.read(key: rollbackVersionKey),
           let rollbackStr = String(data: rollbackData, encoding: .utf8),
           let rollbackVer = Int(rollbackStr),
           let pinned = all.first(where: { $0.config.version == rollbackVer }) {
            // 钉扎版本仍需存在于“已通过可信性过滤”的集合中，否则视为失效。
            return pinned
        }
        if let verified = all
            .filter({ $0.isVerifiedByServer })
            .max(by: { $0.config.version < $1.config.version }) {
            return verified
        }

#if DEBUG
        if let fallback = all.max(by: { $0.config.version < $1.config.version }) {
            Logger.log("⚠️ ConfigCache.loadLatestFromDisk: [DEBUG] using unverified cache entry version=\(fallback.config.version)")
            return fallback
        }
#else
        Logger.log("ConfigCache.loadLatestFromDisk: no verified cache entry in release build, returning nil")
#endif
        return nil
    }

    /// 读取并解密磁盘上的全部缓存条目。
    /// 任何完整性/解密失败都会删除磁盘载荷与 HMAC 后返回空数组（fail-closed）。
    private func loadAllDiskEntries() -> [CacheEntry] {
        guard persistToDisk,
              let stored = fileStore.read(key: diskKey) else {
            return []
        }
        // 先用 HMAC 校验密文完整性；签名缺失/不符说明文件被篡改或写坏，直接丢弃。
        guard let signature = fileStore.read(key: hmacDiskKey),
              StorageIntegrityGuard.verify(stored, signature: signature, purpose: "config_cache") else {
            fileStore.remove(key: diskKey)
            fileStore.remove(key: hmacDiskKey)
            return []
        }
        #if DEBUG
        // DEBUG 兼容早期未加密载荷：解密失败时按明文解析。
        let data: Data
        if let decrypted = try? PayloadCrypto.decrypt(stored) {
            data = decrypted
        } else {
            data = stored
        }
        #else
        // Release 只接受可解密载荷，解密失败即清空缓存。
        guard let data = try? PayloadCrypto.decrypt(stored) else {
            Logger.log("ConfigCache: decrypt failed, clearing cache in release build")
            fileStore.remove(key: diskKey)
            fileStore.remove(key: hmacDiskKey)
            return []
        }
        #endif
        return (try? JSONDecoder().decode([CacheEntry].self, from: data)) ?? []
    }

    /// 加密序列化并原子写入磁盘：载荷与 HMAC 任一写入失败都会清理两者。
    /// - Returns: 两份文件均写入成功时为 `true`。
    private func saveDiskEntries(_ entries: [CacheEntry]) -> Bool {
        guard persistToDisk,
              let encoded = try? JSONEncoder().encode(entries) else {
            return false
        }
        #if DEBUG
        // DEBUG 允许加密失败时回退明文，便于本地调试。
        let stored = (try? PayloadCrypto.encrypt(encoded)) ?? encoded
        #else
        // Release 加密失败即放弃保存，避免配置以明文落盘。
        guard let stored = try? PayloadCrypto.encrypt(encoded) else {
            Logger.log("ConfigCache: encrypt failed, skipping save in release build")
            return false
        }
        #endif
        let signature = StorageIntegrityGuard.sign(stored, purpose: "config_cache")
        let didWritePayload = fileStore.write(key: diskKey, data: stored)
        let didWriteSignature = fileStore.write(key: hmacDiskKey, data: signature)
        // 载荷与 HMAC 必须成对存在；只成功其一会导致下次读取校验失败，故主动清理。
        guard didWritePayload && didWriteSignature else {
            Logger.log("ConfigCache: failed to persist cache atomically")
            fileStore.remove(key: diskKey)
            fileStore.remove(key: hmacDiskKey)
            return false
        }
        return true
    }

    /// Release 可信性判定：内容哈希一致、签名密钥已配置、且条目经服务端验签，三者缺一不可。
    /// 任一条件不满足即拒绝该条目（fail-closed），防止磁盘篡改或旧数据被误用。
    private func isUsableTrustedEntry(_ entry: CacheEntry, source: String) -> Bool {
        guard entry.contentHash == CacheEntry.computeContentHash(for: entry.config) else {
            Logger.log("ConfigCache.\(source): rejecting cache entry due to missing or mismatched content hash")
            return false
        }

        guard ConfigSignatureVerifier.isConfigured else {
            Logger.log("ConfigCache.\(source): rejecting cache entry because signing key is not configured")
            return false
        }
        guard entry.isVerifiedByServer else {
            Logger.log("ConfigCache.\(source): rejecting unverified cache entry version=\(entry.config.version)")
            return false
        }
        return true
    }

    #if DEBUG
    /// DEBUG 放宽策略：即使不可信也允许读取，但输出醒目告警，提示 Release 会拒绝。
    private func isUsableDebugEntry(_ entry: CacheEntry, source: String) -> Bool {
        if isUsableTrustedEntry(entry, source: source) {
            return true
        }
        Logger.log("⚠️ ConfigCache.\(source): [DEBUG] allowing unverified/untrusted cache entry version=\(entry.config.version) — this would be REJECTED in Release")
        return true
    }
    #endif

    private func cacheSizeUnlocked() -> Int {
        guard persistToDisk,
              let data = fileStore.read(key: diskKey) else {
            return 0
        }
        return data.count
    }
}

/// 从缓存读出的配置及其元数据。
public struct CachedConfig: Sendable {
    public let config: RemoteConfig
    /// 写入缓存的 Unix 时间戳（秒）。
    public let cachedAt: TimeInterval
    /// 是否经服务端签名验证；Release 下为 true 才可信。
    public let isVerifiedByServer: Bool
    /// 配置内容 SHA-256，用于完整性复核。
    public let contentHash: String?

    /// 判断缓存是否超过给定有效期（秒）。
    public func isExpired(duration: TimeInterval) -> Bool {
        Date().timeIntervalSince1970 - cachedAt > duration
    }

    /// 缓存年龄（秒）。
    public var age: TimeInterval {
        Date().timeIntervalSince1970 - cachedAt
    }
}

/// 缓存状态快照。
public struct CacheStats: Sendable {
    public let hasMemoryCache: Bool
    public let diskSizeBytes: Int
    public let diskEntryCount: Int

    /// 人类可读的磁盘占用（KB/MB）。
    public var diskSizeFormatted: String {
        let formatter = ByteCountFormatter()
        formatter.allowedUnits = [.useKB, .useMB]
        formatter.countStyle = .file
        return formatter.string(fromByteCount: Int64(diskSizeBytes))
    }
}

/// 版本历史条目，用于展示配置演进与回滚依据。
public struct VersionHistoryEntry: Codable, Sendable, Identifiable {
    public let id = UUID()
    public let version: Int
    /// 写入缓存的 Unix 时间戳（秒）。
    public let timestamp: TimeInterval
    public let environment: ConfigEnvironment
    public let description: String?

    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case version = "v"
        case timestamp = "ts"
        case environment = "ev"
        case description = "ds"
    }

    public var date: Date {
        Date(timeIntervalSince1970: timestamp)
    }

    public var formattedDate: String {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }
}

extension ConfigError {
    /// 构造缓存导入失败错误，统一包装为 `validationFailed` 以便上层分类处理。
    static func importFailed(reason: String) -> ConfigError {
        .validationFailed(underlying: NSError(domain: "ConfigCache", code: -1, userInfo: [
            NSLocalizedDescriptionKey: "Import failed: \(reason)"
        ]))
    }
}
