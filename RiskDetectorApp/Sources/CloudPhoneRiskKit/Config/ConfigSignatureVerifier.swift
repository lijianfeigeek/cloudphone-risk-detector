// CloudPhoneRiskKit 配置签名验证器：为远端配置提供 Ed25519 非对称验签与
// SHA-256 MAC 对称验签两条路径，任何失败都返回 isValid=false（fail-closed）。
// 密钥仅持久化在 Keychain；DEBUG 下 Keychain 不可用时退回进程内内存，
// 该退化分支不会出现在 Release 构建中。

import Foundation
import CryptoKit
import Security

/// 远端配置签名校验入口。
///
/// 验证语义：只有先成功调用 `configure` / `configureEd25519PublicKey`，
/// `verify` 才可能返回有效结果；未配置密钥、签名格式错误或校验不匹配
/// 一律视为不可信，调用方必须拒绝应用该配置。
public enum ConfigSignatureVerifier {

    /// 验签结果；`reason` 仅用于日志/诊断，不参与放行判断。
    public struct VerificationResult {
        public let isValid: Bool
        public let reason: String?
    }

    // Lock 串行化 Keychain 读写与 DEBUG 内存回退表，避免并发配置/验签竞态。
    private static let lock = UnfairLock()
    private static let keychainService = "CloudPhoneRiskKit.ConfigSigning"
    private static let keychainAccount = "verification_key"
    // AfterFirstUnlockThisDeviceOnly：后台可验签，但不随备份迁移到其他设备。
    private static let accessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
#if DEBUG
    // Simulator / CI may not expose usable Keychain entitlements (-34018).
    // Keep a process-local fallback so verification semantics remain testable.
    // 仅 DEBUG：模拟器/CI 无 Keychain 权限时用进程内表维持可测试性，Release 不编译此分支。
    private static var debugInMemoryKeys: [String: Data] = [:]
#endif

    /// 用 UTF-8 字符串配置对称签名密钥。
    /// 密钥先经 SHA-256 归一化后写入 Keychain，原始明文随即清零。
    /// - Returns: Keychain 写入成功返回 `true`；失败时验签将保持不可用（fail-closed）。
    @discardableResult
    public static func configure(serverSigningKey: String) -> Bool {
        lock.withLock {
            var keyData = Data(serverSigningKey.utf8)
            // defer 保证无论保存成功与否都擦除内存中的明文密钥副本。
            defer { secureZeroData(&keyData) }
            let hashed = SHA256.hash(data: keyData)
            let keyBytes = Data(hashed)
            guard saveKeyToKeychain(keyBytes) else {
                Logger.log("ConfigSignatureVerifier.configure(serverSigningKey): keychain save failed")
                return false
            }
            return true
        }
    }

    /// 用原始字节配置对称签名密钥。
    /// 与字符串版本一致，先做 SHA-256 再存入 Keychain。
    /// - Returns: Keychain 写入成功返回 `true`；否则验签保持失败。
    @discardableResult
    public static func configure(serverSigningKeyData: Data) -> Bool {
        lock.withLock {
            var keyData = serverSigningKeyData
            defer { secureZeroData(&keyData) }
            let hashed = SHA256.hash(data: keyData)
            let keyBytes = Data(hashed)
            guard saveKeyToKeychain(keyBytes) else {
                Logger.log("ConfigSignatureVerifier.configure(serverSigningKeyData): keychain save failed")
                return false
            }
            return true
        }
    }

    /// 是否已配置对称验签密钥；未配置时 `verify` 必定失败。
    public static var isConfigured: Bool {
        lock.withLock { keychainHasKey() }
    }

    /// 面向 DEBUG 的配置状态查询：未配置时输出告警日志，便于集成阶段排查。
    public static var isConfiguredForDebug: Bool {
        #if DEBUG
        let configured = isConfigured
        if !configured {
            Logger.log("⚠️ ConfigSignatureVerifier: signing key not configured in DEBUG build — verify() will return isValid=false. Call configure() to set up signature verification.")
        }
        return configured
        #else
        return isConfigured
        #endif
    }

    /// 校验配置载荷的签名。
    /// - Parameters:
    ///   - payload: 服务端返回的原始配置字节，必须与签名时完全一致。
    ///   - signatureHex: 十六进制签名；Ed25519 为 64 字节，MAC 路径由实现决定。
    /// - Returns: `isValid=true` 仅表示签名通过；其余情况（未配置、格式错误、
    ///   不匹配）均返回 `false`，调用方不得应用该配置。
    public static func verify(payload: Data, signatureHex: String) -> VerificationResult {
        // 优先尝试 Ed25519 非对称验签（更安全：SDK 仅嵌入公钥，无法伪造签名）
        if let ed25519Result = verifyEd25519(payload: payload, signatureHex: signatureHex) {
            return ed25519Result
        }

        // 回退到自定义 pad 的 SHA-256 MAC 对称验签（兼容旧配置接口）
        let keyBytes: Data? = lock.withLock { readKeyFromKeychain() }
        guard let keyBytes else {
            #if DEBUG
            Logger.log("⚠️ ConfigSignatureVerifier.verify: not configured in DEBUG — returning isValid=false. Use isConfiguredForDebug to check setup.")
            #endif
            return VerificationResult(isValid: false, reason: "verification_not_configured")
        }

        var mutableKeyBytes = keyBytes
        // 使用完立即擦除 Keychain 读出的密钥副本，缩短明文驻留窗口。
        defer { secureZeroData(&mutableKeyBytes) }

        // 非偶数长度/非法 hex 直接拒绝，避免把解析失败误判为签名不匹配。
        guard let signatureData = Data(hexString: signatureHex) else {
            return VerificationResult(isValid: false, reason: "invalid_signature_format")
        }

        let isValid = CPRiskMessageAuth.isValidAuthenticationCode(signatureData, authenticating: payload, keyData: mutableKeyBytes)

        return VerificationResult(isValid: isValid, reason: isValid ? nil : "signature_mismatch")
    }

    // MARK: - Ed25519 非对称签名

    // 非对称公钥单独存一个 Keychain account，与对称密钥互不影响。
    private static let ed25519KeychainAccount = "ed25519_verification_pubkey"

    /// 配置 Ed25519 公钥用于配置签名验证（推荐：SDK 仅持有公钥，无法伪造配置）
    /// - Parameter publicKeyBytes: 32 字节的 Curve25519 公钥原始表示。
    /// - Returns: 长度/格式校验与 Keychain 写入均成功时为 `true`。
    @discardableResult
    public static func configureEd25519PublicKey(_ publicKeyBytes: Data) -> Bool {
        lock.withLock {
            // Ed25519 公钥固定 32 字节；长度不符直接拒绝，防止配置错位后静默失效。
            guard publicKeyBytes.count == 32 else {
                Logger.log("ConfigSignatureVerifier.configureEd25519: invalid key size \(publicKeyBytes.count), expected 32")
                return false
            }
            // 验证公钥格式合法性
            guard (try? Curve25519.Signing.PublicKey(rawRepresentation: publicKeyBytes)) != nil else {
                Logger.log("ConfigSignatureVerifier.configureEd25519: invalid Ed25519 public key format")
                return false
            }
            return saveToKeychain(publicKeyBytes, account: ed25519KeychainAccount)
        }
    }

    /// 配置 Ed25519 公钥（hex 编码）
    @discardableResult
    public static func configureEd25519PublicKey(hex: String) -> Bool {
        // hex 解析失败或长度不为 32 字节时拒绝配置，保持 fail-closed。
        guard let keyData = Data(hexString: hex), keyData.count == 32 else {
            Logger.log("ConfigSignatureVerifier.configureEd25519(hex): invalid hex or wrong length")
            return false
        }
        return configureEd25519PublicKey(keyData)
    }

    /// 是否已配置 Ed25519 公钥。
    public static var isEd25519Configured: Bool {
        lock.withLock { readFromKeychain(account: ed25519KeychainAccount) != nil }
    }

    /// 尝试 Ed25519 验签。
    /// - Returns: 未配置 Ed25519 时返回 `nil`（交由对称 MAC 路径处理）；
    ///   已配置但签名非法/长度不符时返回无效结果，**不会**再回退到 MAC，
    ///   以防攻击者伪造短签名触发算法降级。
    private static func verifyEd25519(payload: Data, signatureHex: String) -> VerificationResult? {
        let pubKeyBytes: Data? = lock.withLock { readFromKeychain(account: ed25519KeychainAccount) }
        guard let pubKeyBytes else {
            return nil // Ed25519 未配置，回退到 HMAC
        }

        guard let signatureData = Data(hexString: signatureHex) else {
            return VerificationResult(isValid: false, reason: "invalid_signature_format")
        }

        // Ed25519 签名长度为 64 字节；若不是，拒绝而非回退到 HMAC（防止降级攻击）
        guard signatureData.count == 64 else {
            return VerificationResult(isValid: false, reason: "ed25519_configured_but_signature_not_64_bytes")
        }

        do {
            let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: pubKeyBytes)
            let isValid = publicKey.isValidSignature(signatureData, for: payload)
            return VerificationResult(
                isValid: isValid,
                reason: isValid ? nil : "ed25519_signature_mismatch"
            )
        } catch {
            Logger.log("ConfigSignatureVerifier.verifyEd25519: key reconstruction failed: \(error)")
            return VerificationResult(isValid: false, reason: "ed25519_key_error")
        }
    }

    // MARK: - Keychain 辅助方法

    private static func keychainHasKey() -> Bool {
        readFromKeychain(account: keychainAccount) != nil
    }

    private static func readKeyFromKeychain() -> Data? {
        readFromKeychain(account: keychainAccount)
    }

    private static func saveKeyToKeychain(_ keyBytes: Data) -> Bool {
        saveToKeychain(keyBytes, account: keychainAccount)
    }

    /// 从 Keychain 读取指定 account 的数据。
    /// DEBUG 且 Keychain 明确不可用时退回进程内内存表；其余错误返回 `nil`。
    private static func readFromKeychain(account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess, let data = item as? Data {
            return data
        }
#if DEBUG
        if keychainStatusIndicatesUnavailable(status) {
            return debugInMemoryKeys[account]
        }
#endif
        return nil
    }

    /// 写入 Keychain：先删除同 account 旧条目再新增，保证配置轮换时是覆盖而非重复。
    /// DEBUG 下 Keychain 不可用时写入进程内内存表并视为成功。
    private static func saveToKeychain(_ data: Data, account: String) -> Bool {
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessible,
        ]
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        if status == errSecSuccess {
            return true
        }
#if DEBUG
        if keychainStatusIndicatesUnavailable(status) {
            debugInMemoryKeys[account] = data
            return true
        }
#endif
        guard status == errSecSuccess else {
            Logger.log("ConfigSignatureVerifier.saveToKeychain(\(account)): SecItemAdd failed (status=\(status))")
            return false
        }
        return true
    }

    /// 判断 Keychain 错误是否属于“环境不可用”（而非查询逻辑错误）。
    /// 只有这类错误才允许 DEBUG 内存回退，避免掩盖真实查询缺陷。
    private static func keychainStatusIndicatesUnavailable(_ status: OSStatus) -> Bool {
        if status == errSecInteractionNotAllowed ||
            status == errSecMissingEntitlement ||
            status == errSecNotAvailable {
            return true
        }
        #if DEBUG && os(macOS)
        // SwiftPM/XCTest hosts without a usable login keychain can surface
        // keychain unavailability as errSecParam. Keep this out of iOS and
        // all Release builds so real query bugs do not become production fallback.
        return status == errSecParam
        #else
        return false
        #endif
    }
}

extension Data {
    /// 将十六进制字符串解析为字节数组；奇数长度或含非法字符时返回 `nil`。
    init?(hexString: String) {
        let hex = hexString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard hex.count.isMultiple(of: 2) else { return nil }
        if hex.isEmpty {
            self = Data()
            return
        }
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }
}
