// 设备 ID 持久化：优先 Keychain，失败时降级到 AES-GCM 加密文件，最后返回 ephemeral ID。
// 位于设备身份层，供指纹、图特征与上报去重使用；不是硬件级标识，也不跨 App 共享。
// 隐私边界：设备 ID 仅为本 App 随机生成的 UUID，不采集 IDFV/序列号；
// 加密文件密钥由 SecureFileStore/PayloadCrypto 管理，绝不把明文 ID 落盘。
// 安全不变量：任何持久化失败都显式暴露为 `ephemeral:` 前缀，服务端可据此降低信任。

import Foundation
import Security

/// 设备 ID 持久化（Keychain + UserDefaults 降级）
///
/// ## Keychain 可访问性（SDK 4.4 Phase 6）
/// - 使用 `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` 实现设备绑定
/// - 不使用 `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`，避免无密码设备兼容性问题
/// - 多 App 共享：仅在需要跨 App 共享时添加 `kSecAttrAccessGroup`，默认不添加
///
/// ## App Store 换号场景（同一设备、不同 Apple ID 重装）
/// 用户更换 Apple ID 后通过 App Store 重装 App，系统可能清除该 App 的 Keychain 数据。
/// 此时：
/// - `read()` 返回 nil，`readFallback()` 若 UserDefaults 也被清除则返回 nil
/// - 会生成新的 UUID，并尝试写入 Keychain
/// - 若 Keychain 写入失败，返回 `ephemeral:<uuid>` 前缀 ID，服务端可识别并限制高信任请求
/// - 所有依赖 Keychain 的基线（SDKBinaryIntegrityChecker、TextSegmentIntegrityChecker 等）
///   在 Keychain 被清除后会自动重建，视为首次运行
///
/// ## ephemeral: 前缀
/// 当 Keychain 与 UserDefaults 两层存储均无法持久化时，返回 `ephemeral:<uuid>`。
/// 服务端可通过此前缀识别设备身份不可靠，限制高信任操作。
final class KeychainDeviceID {
    /// 全局共享实例；内部状态只读，线程安全由 `lock` 保证。
    static let shared = KeychainDeviceID()
    /// 私有初始化，强制单例。
    private init() {}

    /// NSLock：Keychain I/O 在锁内执行，避免并发读写同一条目
    private let lock = NSLock()
    /// Keychain 条目所属服务名。
    private let service = "CloudPhoneRiskKit"
    /// Keychain 条目账号名。
    private let account = "device_id"
    /// SDK 4.4 Phase 6: 设备绑定，兼容无密码设备；避免 kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    private let accessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    /// Keychain 不可用时的回退存储：AES-GCM 加密文件（SecureFileStore + PayloadCrypto），
    /// 不再把设备 ID 明文写入 UserDefaults。历史明文回退（UserDefaults）仅做一次性
    /// 迁移读取，迁移成功后立即删除。
    private let fileStore = SecureFileStore.shared
    /// 加密文件中的条目键。
    private let fallbackStoreKey = "cloudphone_device_id_fallback_v1"
    // 遗留明文回退键（仅迁移读取用，读取后删除；新写入不再使用）。
    private let legacyFallbackKey = "cloudphone_device_id_fallback_v1"
    private let legacyFallbackHMACKey = "cloudphone_device_id_fallback_v1_hmac"
    /// HMAC 用途标签：防止同一密钥在不同用途间复用。
    private let fallbackHMACPurpose = "device_id_fallback"
    /// 存储层彻底不可用时的占位值（当前流程未使用，保留以兼容历史调用方）。
    private let unavailableDeviceID = "CPRISKKIT-DEVICE-ID-UNAVAILABLE"

    /// 读取已有设备 ID，不存在则创建并尽力持久化。
    /// - Returns: 稳定设备 ID；若无法持久化则返回 `ephemeral:<uuid>`。
    /// 该方法是幂等的：并发调用时依赖锁与“写后重读”保证同一进程内尽量返回同一值。
    func getOrCreate() -> String {
        lock.withLock {
            if let existing = read() {
                let usedFallback = saveFallback(existing)
                if usedFallback {
                    Logger.log("KeychainDeviceID: persisted device ID to fallback store (keychain primary read succeeded)")
                }
                return existing
            }

            if let fallback = readFallback() {
                if save(fallback) {
                    return fallback
                }
                // Keychain 写失败，仅 UserDefaults 有值：返回 ephemeral 前缀，服务端可识别并限制高信任请求
                Logger.log("KeychainDeviceID: keychain unavailable, using ephemeral-tagged fallback copy")
                return "ephemeral:\(fallback)"
            }

            let newID = UUID().uuidString
            // 先写加密回退，再尝试 Keychain；两者顺序保证进程崩溃时至少有一份持久化。
            let fallbackSaved = saveFallback(newID)
            if save(newID) {
                return newID
            }
            if fallbackSaved {
                Logger.log("KeychainDeviceID: keychain save failed, returning ephemeral-tagged fallback ID (fallback store used)")
                return "ephemeral:\(newID)"
            }
            // 并发写入竞争：再次尝试读取（另一线程可能已写入）
            if let retry = read() { return retry }
            Logger.log("KeychainDeviceID: save failed, returning ephemeral-tagged fallback ID (no fallback store)")
            return "ephemeral:\(newID)"
        }
    }

    /// 从 Keychain 读取设备 ID。
    /// - Returns: 成功返回字符串；设备锁定、认证失败或条目不存在时返回 nil（由调用方降级）。
    private func read() -> String? {
        // 读取查询中绝不能带 kSecAttrAccessible：它是写入期属性，
        // 某些 iOS 版本把它放进查询会导致查找失败。
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        // 设备锁定时 Keychain 不可访问：这是可预期降级，不视为错误。
        if status == errSecInteractionNotAllowed {
            Logger.log("KeychainDeviceID.read: errSecInteractionNotAllowed (device locked or keychain unavailable)")
            return nil
        }
        if status == errSecAuthFailed {
            Logger.log("KeychainDeviceID.read: errSecAuthFailed (auth failed)")
            return nil
        }
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// 写入设备 ID 到 Keychain。
    /// - Returns: 成功为 true；任何失败都会尝试降级写入（`saveFallback`）并返回其结果。
    private func save(_ value: String) -> Bool {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]

        // SDK 4.4 Phase 6: ACL 使用 AfterFirstUnlockThisDeviceOnly，兼容无密码设备
        var aclError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [],
            &aclError
        ) else {
            return saveFallback(data: data, query: query)
        }

        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessControl as String: accessControl,
        ]

        // 先尝试更新已有条目，避免重复 add 产生 errSecDuplicateItem。
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecSuccess { return true }
        if status == errSecInteractionNotAllowed {
            Logger.log("KeychainDeviceID.save: errSecInteractionNotAllowed (device locked or keychain unavailable)")
            return saveFallback(data: data, query: query)
        }
        if status == errSecAuthFailed {
            Logger.log("KeychainDeviceID.save: errSecAuthFailed (auth failed)")
            return saveFallback(data: data, query: query)
        }
        // 只有“条目不存在”才继续走新增；其他错误直接降级。
        if status != errSecItemNotFound { return saveFallback(data: data, query: query) }

        var addQuery = query
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessControl as String] = accessControl
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus == errSecSuccess { return true }
        if addStatus == errSecInteractionNotAllowed {
            Logger.log("KeychainDeviceID.save: SecItemAdd errSecInteractionNotAllowed")
            return saveFallback(data: data, query: query)
        }
        if addStatus == errSecAuthFailed {
            Logger.log("KeychainDeviceID.save: SecItemAdd errSecAuthFailed")
            return saveFallback(data: data, query: query)
        }
        return saveFallback(data: data, query: query)
    }

    /// 降级写入：不带 AccessControl，仅用 `accessible` 属性写入同一 Keychain 条目。
    /// - Returns: 更新或新增成功为 true；仍失败返回 false（调用方最终走 ephemeral）。
    private func saveFallback(data: Data, query: [String: Any]) -> Bool {
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessible,
        ]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecSuccess { return true }
        if status != errSecItemNotFound { return false }
        var addQuery = query
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = accessible
        return SecItemAdd(addQuery as CFDictionary, nil) == errSecSuccess
    }

    /// 读取回退存储中的设备 ID（加密文件优先，其次迁移遗留明文）。
    /// - Returns: 解密后的设备 ID；所有来源都无效时返回 nil。
    /// 遗留明文必须通过 HMAC 校验，校验失败会删除旧值（防止被篡改后继续使用）。
    private func readFallback() -> String? {
        // 首选：加密文件回退（AES-GCM 提供机密性 + 完整性）。
        if let encrypted = fileStore.read(key: fallbackStoreKey),
           let decrypted = try? PayloadCrypto.decrypt(encrypted),
           let value = String(data: decrypted, encoding: .utf8),
           !value.isEmpty {
            return value
        }
        // 遗留迁移：历史明文 UserDefaults 回退（带 HMAC 校验），读到后立即
        // 转存为加密文件，确认写入成功后再删除旧值；失败时保留供下次重试。
        let defaults = UserDefaults.standard
        guard let data = defaults.data(forKey: legacyFallbackKey),
              let signature = defaults.data(forKey: legacyFallbackHMACKey),
              StorageIntegrityGuard.verify(data, signature: signature, purpose: fallbackHMACPurpose),
              let value = String(data: data, encoding: .utf8),
              !value.isEmpty else {
            // 缺失或 HMAC 校验失败：清理残留，避免下次继续读取不可信数据。
            defaults.removeObject(forKey: legacyFallbackKey)
            defaults.removeObject(forKey: legacyFallbackHMACKey)
            return nil
        }
        if saveFallback(value) {
            // 迁移成功才删除旧明文；否则保留供下次重试。
            defaults.removeObject(forKey: legacyFallbackKey)
            defaults.removeObject(forKey: legacyFallbackHMACKey)
        } else {
            Logger.log("KeychainDeviceID: encrypted fallback migration deferred")
        }
        return value
    }

    /// 加密写入回退文件。
    /// - Returns: 加密与写入均成功且回读一致时为 true；否则 false。
    @discardableResult
    private func saveFallback(_ value: String) -> Bool {
        // 加密后写入文件；加密失败（无可用密钥）时返回 false，调用方走 ephemeral 路径，
        // 绝不明文落盘。
        guard let encrypted = try? PayloadCrypto.encrypt(Data(value.utf8)) else { return false }
        guard fileStore.write(key: fallbackStoreKey, data: encrypted) else { return false }
        // 回读比对，确认落盘内容与写入一致（防止部分写入/缓存问题）。
        return fileStore.read(key: fallbackStoreKey) == encrypted
    }
}
