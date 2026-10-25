// 文件职责：为落盘数据提供 HMAC 签名/校验（SHA-256 MAC），密钥保存在 Keychain。
// 管道位置：Storage 完整性防线，写前签名、读前校验；密钥生命周期由 Keychain 管理。
// 安全不变量：校验失败必须 fail-closed（调用方清空缓存）；密钥 ThisDeviceOnly，
// 不随备份迁移。
import Foundation
import CryptoKit

/// 自定义 pad 的 SHA-256 MAC 签名/校验，密钥存 Keychain。
/// SDK 4.4 Phase 6: kSecAttrAccessibleWhenUnlockedThisDeviceOnly。
/// 签名域通过 purpose 前缀隔离，避免不同业务之间互相重放。
enum StorageIntegrityGuard {
    /// Keychain service 标识。
    private static let keychainService = "CloudPhoneRiskKit.StorageHMAC"
    /// Keychain account（密钥版本化，便于未来轮换）。
    private static let keychainAccount = "hmac_key_v1"
    private static let lock = NSLock()  // NSLock：锁内包含 Keychain I/O
#if DEBUG
    // Keychain 不可用时（如 -34018）仅 DEBUG 回退到进程内密钥。
    private static var debugFallbackKeyData: Data?
#endif

    /// 计算数据签名：`purpose 长度 + purpose + data` 的 SHA-256 MAC。
    /// - Parameters:
    ///   - data: 待签名数据（通常为密文）。
    ///   - purpose: 域分隔标识（如 risk_history）。
    /// - Returns: MAC 字节。
    static func sign(_ data: Data, purpose: String) -> Data {
        let key = getOrCreateKey()
        let purposeData = Data(purpose.utf8)
        var combined = Data()
        // 固定 4 字节长度前缀，消除 purpose 与数据之间的边界歧义。
        var length = UInt32(purposeData.count).bigEndian
        combined.append(Data(bytes: &length, count: 4))
        combined.append(purposeData)
        combined.append(data)
        return CPRiskMessageAuth.authenticationCode(for: combined, using: key)
    }

    /// 校验签名；底层 `CPRiskMessageAuth` 使用常量时间比较。
    /// - Returns: 签名有效为 true；任何异常返回 false（调用方应 fail-closed）。
    static func verify(_ data: Data, signature: Data, purpose: String) -> Bool {
        let key = getOrCreateKey()
        let purposeData = Data(purpose.utf8)
        var combined = Data()
        var length = UInt32(purposeData.count).bigEndian
        combined.append(Data(bytes: &length, count: 4))
        combined.append(purposeData)
        combined.append(data)
        return CPRiskMessageAuth.isValidAuthenticationCode(signature, authenticating: combined, using: key)
    }

    /// 读取或创建 256 位 HMAC 密钥（Keychain 通用密码项）。
    /// - 已有则直接使用；不存在则创建并写入；并发重复则回读已有密钥。
    /// - Release 下持久化失败仍返回内存密钥，但重启后校验会失败并触发 fail-closed。
    private static func getOrCreateKey() -> SymmetricKey {
        lock.withLock {
            // 读取查询绝不能包含 kSecAttrAccessible：它是写入属性，
            // 部分 iOS 版本会因此查不到条目。
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: keychainService,
                kSecAttrAccount as String: keychainAccount,
                kSecReturnData as String: true,
            ]

            var result: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &result)

            if status == errSecSuccess, let data = result as? Data {
                var mutableData = data
                let key = SymmetricKey(data: mutableData)
                secureZeroData(&mutableData)
                return key
            }
#if DEBUG
            if keychainStatusIndicatesUnavailable(status), let fallback = debugFallbackKeyData {
                var mutableFallback = fallback
                let key = SymmetricKey(data: mutableFallback)
                secureZeroData(&mutableFallback)
                return key
            }
#endif

            // 首次使用：生成随机 256 位密钥，写入后立即清零临时 Data。
            let newKey = SymmetricKey(size: .bits256)
            var keyData = newKey.withUnsafeBytes { Data($0) }
            defer { secureZeroData(&keyData) }

            let addQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: keychainService,
                kSecAttrAccount as String: keychainAccount,
                kSecValueData as String: keyData,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            ]

            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)

            if addStatus == errSecSuccess {
                return newKey
            }

            // 并发创建可能撞上重复项，回读已存在密钥以保证一致。
            if addStatus == errSecDuplicateItem {
                var existing: AnyObject?
                if SecItemCopyMatching(query as CFDictionary, &existing) == errSecSuccess,
                   let existingData = existing as? Data {
                    var mutableExisting = existingData
                    let key = SymmetricKey(data: mutableExisting)
                    secureZeroData(&mutableExisting)
                    return key
                }
            }
#if DEBUG
            if keychainStatusIndicatesUnavailable(addStatus) {
                debugFallbackKeyData = Data(keyData)
                return newKey
            }
#endif

            // 无法持久化仍返回内存密钥；后续重启校验失败会触发 fail-closed。
            Logger.log("StorageIntegrityGuard: SecItemAdd failed with status \(addStatus)")
            return newKey
        }
    }

    /// 判断错误码是否表示 Keychain 不可用（仅 DEBUG 允许回退到内存密钥）。
    private static func keychainStatusIndicatesUnavailable(_ status: OSStatus) -> Bool {
        if status == errSecInteractionNotAllowed ||
            status == errSecMissingEntitlement ||
            status == errSecNotAvailable {
            return true
        }
        #if DEBUG && os(macOS)
        // 部分 macOS SwiftPM/XCTest 沙箱会把 Keychain 不可用报成 errSecParam；
        // 该回退仅限 DEBUG + macOS，iOS 与 Release 不允许。
        return status == errSecParam
        #else
        return false
        #endif
    }
}
