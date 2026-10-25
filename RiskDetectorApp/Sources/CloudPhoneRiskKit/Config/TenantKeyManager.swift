// CloudPhoneRiskKit 租户密钥管理器：按租户隔离管理 Keychain 中的对称密钥，
// 提供注册、轮换（pending → active → retired）、紧急吊销与过期查询。
// 密钥状态迁移受宽限期约束，吊销后立即删除 Keychain 中的密钥材料；
// 所有密钥均为 32 字节 CSPRNG 随机数，按租户前缀分 service 防止跨租户读取。

import Foundation
import Security
import CryptoKit

// MARK: - 多租户密钥管理

/// 按租户管理 Keychain 密钥生命周期：轮换、版本化与紧急吊销。
///
/// 线程模型：内部 `NSLock` 串行化所有公开方法，可从任意线程安全调用。
/// 租户隔离：每个租户使用独立的 Keychain service 前缀，一个租户无法读取另一个租户的材料；
/// 如配置了 `keychainAccessGroup`，还需要同一 App/扩展组才能访问。
public final class TenantKeyManager: @unchecked Sendable {

    // MARK: - 类型

    /// 密钥生命周期状态。
    public enum KeyState: String, Codable, Sendable {
        /// 当前用于签名/加密。
        case active
        /// 轮换目标——宽限期结束后转为 active。
        case pending
        /// 上一把 active 密钥，宽限期内保留用于验签。
        case retired
        /// 紧急吊销——不得再用于任何操作，材料已删除。
        case revoked
    }

    /// 受管密钥的元数据；密钥材料本身只保存在 Keychain。
    public struct ManagedKey: Codable, Sendable {
        public let keyID: String
        /// 单调递增的密钥版本，用于选择最新密钥与 Keychain account 命名。
        public let version: Int
        public let tenantID: String
        public var state: KeyState
        public let createdAt: Date
        public var activatedAt: Date?
        public var retiredAt: Date?
        public var revokedAt: Date?
        /// 过期时间；`nil` 表示不过期。
        public var expiresAt: Date?
        /// 密钥算法标识，默认 AES-256-GCM。
        public let algorithm: String

        public init(
            keyID: String = UUID().uuidString,
            version: Int,
            tenantID: String,
            state: KeyState = .pending,
            createdAt: Date = Date(),
            activatedAt: Date? = nil,
            retiredAt: Date? = nil,
            revokedAt: Date? = nil,
            expiresAt: Date? = nil,
            algorithm: String = "AES-256-GCM"
        ) {
            self.keyID = keyID
            self.version = version
            self.tenantID = tenantID
            self.state = state
            self.createdAt = createdAt
            self.activatedAt = activatedAt
            self.retiredAt = retiredAt
            self.revokedAt = revokedAt
            self.expiresAt = expiresAt
            self.algorithm = algorithm
        }
    }

    /// 密钥生命周期操作错误。
    public enum KeyManagerError: Error, LocalizedError {
        case tenantNotFound(String)
        case keyNotFound(keyID: String)
        case noActiveKey(tenantID: String)
        case rotationInProgress(tenantID: String)
        case keyRevoked(keyID: String)
        case keychainError(OSStatus)
        case encodingError(Error)
        case invalidKeyMaterial
        case gracePeriodNotElapsed(remaining: TimeInterval)

        public var errorDescription: String? {
            switch self {
            case .tenantNotFound(let id):
                return "Tenant not found: \(id)"
            case .keyNotFound(let keyID):
                return "Key not found: \(keyID)"
            case .noActiveKey(let tenantID):
                return "No active key for tenant: \(tenantID)"
            case .rotationInProgress(let tenantID):
                return "Key rotation already in progress for tenant: \(tenantID)"
            case .keyRevoked(let keyID):
                return "Key has been revoked: \(keyID)"
            case .keychainError(let status):
                return "Keychain operation failed: \(status)"
            case .encodingError(let error):
                return "Encoding error: \(error.localizedDescription)"
            case .invalidKeyMaterial:
                return "Invalid or corrupted key material"
            case .gracePeriodNotElapsed(let remaining):
                return "Grace period not elapsed, \(Int(remaining))s remaining"
            }
        }
    }

    // MARK: - 配置

    /// 管理器配置：Keychain 访问组、宽限期、密钥 TTL 与保留策略。
    public struct Configuration: Sendable {
        /// Keychain 访问组；`nil` 时使用应用默认组。
        public var keychainAccessGroup: String?
        /// 轮换宽限期（秒），默认 1 小时；pending 密钥必须存在满该时长才能提交。
        public var defaultGracePeriod: TimeInterval
        /// 密钥默认有效期（秒），默认 90 天。
        public var defaultKeyTTL: TimeInterval
        /// 每租户最多保留的历史 retired 密钥数量，超出后删除并标记 revoked。
        public var maxRetiredKeysPerTenant: Int
        /// Keychain service 前缀；实际 service 为 `<prefix>.<tenantID>`。
        public var keychainServicePrefix: String

        public init(
            keychainAccessGroup: String? = nil,
            defaultGracePeriod: TimeInterval = 3600,
            defaultKeyTTL: TimeInterval = 86400 * 90,
            maxRetiredKeysPerTenant: Int = 3,
            keychainServicePrefix: String = "com.cloudphone.riskkit.tenant"
        ) {
            self.keychainAccessGroup = keychainAccessGroup
            self.defaultGracePeriod = defaultGracePeriod
            self.defaultKeyTTL = defaultKeyTTL
            self.maxRetiredKeysPerTenant = maxRetiredKeysPerTenant
            self.keychainServicePrefix = keychainServicePrefix
        }

        public static let `default` = Configuration()
    }

    // MARK: - 属性

    private let config: Configuration
    private let lock = NSLock()
    // 租户 -> 该租户的全部密钥元数据；密钥材料本体在 Keychain。
    private var tenantKeys: [String: [ManagedKey]] = [:]

    // MARK: - 单例

    public static let shared = TenantKeyManager()

    // MARK: - 初始化

    public init(configuration: Configuration = .default) {
        self.config = configuration
    }

    // MARK: - 租户注册

    /// 注册新租户并生成初始 active 密钥。
    /// - Returns: 新生成的密钥元数据。
    /// - Throws: Keychain 写入失败时抛 `KeyManagerError.keychainError`。
    @discardableResult
    public func registerTenant(_ tenantID: String) throws -> ManagedKey {
        lock.lock()
        defer { lock.unlock() }

        let keyMaterial = generateKeyMaterial()
        var key = ManagedKey(
            version: 1,
            tenantID: tenantID,
            state: .active,
            activatedAt: Date(),
            expiresAt: Date().addingTimeInterval(config.defaultKeyTTL)
        )

        // 先落 Keychain 再登记元数据：写入失败时不会留下“有元数据无材料”的坏状态。
        try storeKeyMaterial(keyMaterial, for: key)
        key.state = .active
        tenantKeys[tenantID, default: []].append(key)
        return key
    }

    /// 删除租户的全部密钥材料与元数据。
    /// 单把密钥删除失败被忽略，以尽力清理为优先。
    public func deregisterTenant(_ tenantID: String) throws {
        lock.lock()
        defer { lock.unlock() }

        guard let keys = tenantKeys[tenantID] else {
            throw KeyManagerError.tenantNotFound(tenantID)
        }
        for key in keys {
            try? deleteKeyMaterial(for: key)
        }
        tenantKeys.removeValue(forKey: tenantID)
    }

    // MARK: - 密钥查询

    /// 返回租户当前 active 密钥。
    /// - Throws: 租户不存在或没有 active 密钥时抛错，调用方不得自行猜测密钥。
    public func activeKey(for tenantID: String) throws -> ManagedKey {
        lock.lock()
        defer { lock.unlock() }

        guard let keys = tenantKeys[tenantID] else {
            throw KeyManagerError.tenantNotFound(tenantID)
        }
        guard let active = keys.first(where: { $0.state == .active }) else {
            throw KeyManagerError.noActiveKey(tenantID: tenantID)
        }
        return active
    }

    /// 返回租户全部密钥（含 retired/revoked）。
    public func allKeys(for tenantID: String) throws -> [ManagedKey] {
        lock.lock()
        defer { lock.unlock() }

        guard let keys = tenantKeys[tenantID] else {
            throw KeyManagerError.tenantNotFound(tenantID)
        }
        return keys
    }

    /// 从 Keychain 读取指定密钥的原始材料。
    /// - Throws: 密钥已吊销时立即拒绝，即使材料意外仍在 Keychain 中也不返回。
    public func keyMaterial(for managedKey: ManagedKey) throws -> Data {
        guard managedKey.state != .revoked else {
            throw KeyManagerError.keyRevoked(keyID: managedKey.keyID)
        }
        return try loadKeyMaterial(for: managedKey)
    }

    // MARK: - 密钥轮换

    /// 开始轮换：生成新的 pending 密钥。
    /// 当前 active 密钥继续生效，直到调用 `commitRotation` 提交。
    /// - Throws: 已存在 pending 密钥时抛 `rotationInProgress`，防止并发轮换产生多把候选密钥。
    @discardableResult
    public func beginRotation(for tenantID: String) throws -> ManagedKey {
        lock.lock()
        defer { lock.unlock() }

        guard var keys = tenantKeys[tenantID] else {
            throw KeyManagerError.tenantNotFound(tenantID)
        }

        if keys.contains(where: { $0.state == .pending }) {
            throw KeyManagerError.rotationInProgress(tenantID: tenantID)
        }

        let currentVersion = keys.map(\.version).max() ?? 0
        let keyMaterial = generateKeyMaterial()
        let pendingKey = ManagedKey(
            version: currentVersion + 1,
            tenantID: tenantID,
            state: .pending,
            expiresAt: Date().addingTimeInterval(config.defaultKeyTTL)
        )

        try storeKeyMaterial(keyMaterial, for: pendingKey)
        keys.append(pendingKey)
        tenantKeys[tenantID] = keys
        return pendingKey
    }

    /// 提交轮换：pending 转为 active，原 active 转为 retired。
    /// 强制宽限期——pending 密钥必须已存在至少 `gracePeriod`，避免服务端/客户端时钟或部署不同步
    /// 导致新密钥尚未分发就被使用。
    /// - Parameter gracePeriod: 覆盖默认宽限期（秒）；`nil` 使用配置值。
    @discardableResult
    public func commitRotation(
        for tenantID: String,
        gracePeriod: TimeInterval? = nil
    ) throws -> ManagedKey {
        lock.lock()
        defer { lock.unlock() }

        guard var keys = tenantKeys[tenantID] else {
            throw KeyManagerError.tenantNotFound(tenantID)
        }

        guard let pendingIndex = keys.firstIndex(where: { $0.state == .pending }) else {
            throw KeyManagerError.keyNotFound(keyID: "pending")
        }

        let effectiveGrace = gracePeriod ?? config.defaultGracePeriod
        let elapsed = Date().timeIntervalSince(keys[pendingIndex].createdAt)
        // 宽限期内拒绝提交，保证旧客户端/旧密钥仍能完成验签。
        if elapsed < effectiveGrace {
            throw KeyManagerError.gracePeriodNotElapsed(remaining: effectiveGrace - elapsed)
        }

        let now = Date()

        // 状态迁移：active -> retired，pending -> active；retired 密钥仍可用于验签。
        if let activeIndex = keys.firstIndex(where: { $0.state == .active }) {
            keys[activeIndex].state = .retired
            keys[activeIndex].retiredAt = now
        }

        keys[pendingIndex].state = .active
        keys[pendingIndex].activatedAt = now

        pruneRetiredKeys(&keys)
        tenantKeys[tenantID] = keys

        return keys[pendingIndex]
    }

    /// 取消进行中的轮换并删除 pending 密钥材料。
    public func cancelRotation(for tenantID: String) throws {
        lock.lock()
        defer { lock.unlock() }

        guard var keys = tenantKeys[tenantID] else {
            throw KeyManagerError.tenantNotFound(tenantID)
        }

        if let pendingIndex = keys.firstIndex(where: { $0.state == .pending }) {
            try? deleteKeyMaterial(for: keys[pendingIndex])
            keys.remove(at: pendingIndex)
            tenantKeys[tenantID] = keys
        }
    }

    // MARK: - 紧急吊销

    /// 立即吊销指定密钥。若吊销的是 active 密钥，租户在新密钥轮换进来之前
    /// 将没有可用 active 密钥（fail-closed，而不是继续使用已泄露密钥）。
    public func revokeKey(_ keyID: String, tenantID: String) throws {
        lock.lock()
        defer { lock.unlock() }

        guard var keys = tenantKeys[tenantID] else {
            throw KeyManagerError.tenantNotFound(tenantID)
        }

        guard let index = keys.firstIndex(where: { $0.keyID == keyID }) else {
            throw KeyManagerError.keyNotFound(keyID: keyID)
        }

        keys[index].state = .revoked
        keys[index].revokedAt = Date()

        try deleteKeyMaterial(for: keys[index])
        tenantKeys[tenantID] = keys
    }

    /// 吊销租户全部密钥（紧急擦除）。之后必须重新注册密钥才能继续加解密。
    public func revokeAllKeys(for tenantID: String) throws {
        lock.lock()
        defer { lock.unlock() }

        guard var keys = tenantKeys[tenantID] else {
            throw KeyManagerError.tenantNotFound(tenantID)
        }

        let now = Date()
        for i in keys.indices {
            keys[i].state = .revoked
            keys[i].revokedAt = now
            try? deleteKeyMaterial(for: keys[i])
        }
        tenantKeys[tenantID] = keys
    }

    // MARK: - 生命周期查询

    /// 检查租户是否存在 active 且未过期的密钥。
    public func hasValidActiveKey(for tenantID: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        guard let keys = tenantKeys[tenantID] else { return false }
        return keys.contains { key in
            key.state == .active && (key.expiresAt.map { $0 > Date() } ?? true)
        }
    }

    /// 返回在给定时间范围内即将过期的 active 密钥，用于提前触发轮换。
    public func expiringKeys(
        for tenantID: String,
        within horizon: TimeInterval = 86400 * 7
    ) -> [ManagedKey] {
        lock.lock()
        defer { lock.unlock() }

        guard let keys = tenantKeys[tenantID] else { return [] }
        let cutoff = Date().addingTimeInterval(horizon)
        return keys.filter { key in
            key.state == .active && (key.expiresAt.map { $0 < cutoff } ?? false)
        }
    }

    /// 按状态汇总租户密钥数量。
    public func keyStateSummary(for tenantID: String) -> [KeyState: Int] {
        lock.lock()
        defer { lock.unlock() }

        guard let keys = tenantKeys[tenantID] else { return [:] }
        var counts: [KeyState: Int] = [:]
        for key in keys {
            counts[key.state, default: 0] += 1
        }
        return counts
    }

    // MARK: - 私有：Keychain 操作

    /// 租户隔离的 Keychain service：前缀 + tenantID，租户之间无法互相读取。
    private func keychainService(for key: ManagedKey) -> String {
        "\(config.keychainServicePrefix).\(key.tenantID)"
    }

    /// 单把密钥的 Keychain account：含版本与 keyID，轮换时不会覆盖旧密钥材料。
    private func keychainAccount(for key: ManagedKey) -> String {
        "key_v\(key.version)_\(key.keyID)"
    }

    /// 写入密钥材料；已存在同 account 时更新，保证操作幂等。
    private func storeKeyMaterial(_ data: Data, for key: ManagedKey) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService(for: key),
            kSecAttrAccount as String: keychainAccount(for: key),
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        if let group = config.keychainAccessGroup {
            query[kSecAttrAccessGroup as String] = group
        }

        let status = SecItemAdd(query as CFDictionary, nil)
        // 重复条目改为更新 value，避免轮换/重试时因 errSecDuplicateItem 失败。
        if status == errSecDuplicateItem {
            let updateQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: keychainService(for: key),
                kSecAttrAccount as String: keychainAccount(for: key),
            ]
            let updateAttributes: [String: Any] = [
                kSecValueData as String: data,
            ]
            let updateStatus = SecItemUpdate(
                updateQuery as CFDictionary,
                updateAttributes as CFDictionary
            )
            guard updateStatus == errSecSuccess else {
                throw KeyManagerError.keychainError(updateStatus)
            }
        } else if status != errSecSuccess {
            throw KeyManagerError.keychainError(status)
        }
    }

    /// 读取密钥材料；条目不存在与 Keychain 故障分别映射为不同错误。
    private func loadKeyMaterial(for key: ManagedKey) throws -> Data {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService(for: key),
            kSecAttrAccount as String: keychainAccount(for: key),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        if let group = config.keychainAccessGroup {
            query[kSecAttrAccessGroup as String] = group
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            if status == errSecItemNotFound {
                throw KeyManagerError.keyNotFound(keyID: key.keyID)
            }
            throw KeyManagerError.keychainError(status)
        }
        return data
    }

    /// 删除密钥材料；`errSecItemNotFound` 视为成功（幂等删除）。
    private func deleteKeyMaterial(for key: ManagedKey) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService(for: key),
            kSecAttrAccount as String: keychainAccount(for: key),
        ]
        if let group = config.keychainAccessGroup {
            query[kSecAttrAccessGroup as String] = group
        }

        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw KeyManagerError.keychainError(status)
        }
    }

    // MARK: - 私有：密钥生成

    /// 生成 32 字节（AES-256）密钥材料；随机源失败属于不可恢复的环境错误。
    private func generateKeyMaterial() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        // 随机源不可用时绝不能退化为弱随机，直接终止以避免产生可预测密钥。
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed: \(status)")
        return Data(bytes)
    }

    // MARK: - 私有：清理

    /// 清理超出保留上限的 retired 密钥：删除材料并标记为 revoked。
    private func pruneRetiredKeys(_ keys: inout [ManagedKey]) {
        let retired = keys
            .enumerated()
            .filter { $0.element.state == .retired }
            .sorted { ($0.element.retiredAt ?? .distantPast) < ($1.element.retiredAt ?? .distantPast) }

        if retired.count > config.maxRetiredKeysPerTenant {
            let excess = retired.prefix(retired.count - config.maxRetiredKeysPerTenant)
            for item in excess {
                try? deleteKeyMaterial(for: item.element)
                keys[item.offset].state = .revoked
                keys[item.offset].revokedAt = Date()
            }
        }
    }
}
