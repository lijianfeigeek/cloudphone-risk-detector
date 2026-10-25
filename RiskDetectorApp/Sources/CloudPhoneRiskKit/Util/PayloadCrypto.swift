// 载荷加解密：使用 AES-GCM（认证加密）保护本地持久化的敏感数据，密钥保存在 Keychain。
// 密文格式固定为 magic(0xAE) || nonce || ciphertext || tag，magic 用于拒绝把明文误当密文解析。

import CryptoKit
import Foundation
import Security

/// AES-GCM 载荷加解密，密钥存 Keychain。
/// SDK 4.4 Phase 6: kSecAttrAccessibleWhenUnlockedThisDeviceOnly（设备绑定，兼容无密码设备）
enum PayloadCrypto {
    // Keychain 命名空间与账号；修改任一值都会导致旧密钥读不到、已加密数据无法解密。
    private static let keyService = "CloudPhoneRiskKit"
    private static let keyAccount = "aes_gcm_key_v1"
    // ThisDeviceOnly：不随 iCloud/备份迁移到其他设备，避免密钥跨设备扩散。
    private static let accessible = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    // 串行化“读取-生成-保存”密钥流程，防止并发首次调用生成两把不同密钥。
    private static let lock = UnfairLock()
#if DEBUG
    // Process-local key fallback for simulator/CI where Keychain may be unavailable.
    // 仅 DEBUG 生效：进程内临时密钥，重启即失效，绝不能在 Release 静默替代 Keychain。
    private static var debugFallbackKeyData: Data?
#endif

    /// 加密载荷的 magic 标识字节，用于区分密文与明文，防止静默降级
    static let encryptedMagic: UInt8 = 0xAE

    /// 使用 Keychain 主密钥加密 `plaintext`。
    /// - Returns: `magic || nonce(12) || ciphertext || tag(16)`。
    /// - Throws: 密钥不可用、GCM 封装失败，或随机栈校验发现 ROP 注入时抛错。
    static func encrypt(_ plaintext: Data) throws -> Data {
        // 以 1/10 概率插入调用栈校验：低开销地抽查 ROP/栈劫持，避免每次加密都做重检测。
        if arc4random_uniform(10) == 0 {
            let (malicious, _) = CallStackUnwinder.validateCallStack()
            if malicious {
                throw NSError(domain: "CloudPhoneRiskKit", code: 10, userInfo: [NSLocalizedDescriptionKey: "Call stack validation failed (rop_chain_detected)"])
            }
        }
        let key = try symmetricKey()
        // AES.GCM.seal 内部生成 96-bit 随机 nonce，并在加密后计算 128-bit 认证标签。
        let sealed = try AES.GCM.seal(plaintext, using: key)
        // combined 即 nonce || ciphertext || tag；无法取得说明 CryptoKit 状态异常。
        guard let combined = sealed.combined else {
            throw NSError(domain: "CloudPhoneRiskKit", code: 2, userInfo: [NSLocalizedDescriptionKey: "AES.GCM combined unavailable"])
        }
        var result = Data([encryptedMagic])
        result.append(combined)
        return result
    }

    /// 解密 `magic || nonce || ciphertext || tag` 格式的数据。
    /// - Throws: 缺少 magic、密钥不可用、认证标签校验失败（数据被篡改或密钥不匹配）。
    static func decrypt(_ combined: Data) throws -> Data {
        // 与 encrypt 对称的抽样栈校验，增加 hook 方绕过成本。
        if arc4random_uniform(10) == 0 {
            let (malicious, _) = CallStackUnwinder.validateCallStack()
            if malicious {
                throw NSError(domain: "CloudPhoneRiskKit", code: 11, userInfo: [NSLocalizedDescriptionKey: "Call stack validation failed (rop_chain_detected)"])
            }
        }
        // magic 不匹配说明调用方把明文/其他格式误传进来，直接拒绝而不是尝试解密。
        guard !combined.isEmpty, combined[combined.startIndex] == encryptedMagic else {
            throw NSError(
                domain: "CloudPhoneRiskKit",
                code: 4,
                userInfo: [NSLocalizedDescriptionKey: "Not an encrypted payload (missing magic header)"]
            )
        }
        let key = try symmetricKey()
        let cipherData = Data(combined.dropFirst())
        // SealedBox(combined:) 解析 nonce/密文/tag；AES.GCM.open 会校验 tag，
        // 认证失败即抛错，不返回任何明文。
        let box = try AES.GCM.SealedBox(combined: cipherData)
        return try AES.GCM.open(box, using: key)
    }

    /// 使用调用方提供的原始密钥加密，不写入 Keychain、不加 magic 头。
    /// - Parameter rawKey: 16/24/32 字节，分别对应 AES-128/192/256。
    static func encrypt(_ plaintext: Data, rawKey: Data) throws -> Data {
        // 只接受 AES 规范允许的三种长度；其他长度直接拒绝，避免隐式补齐削弱密钥。
        guard rawKey.count == 16 || rawKey.count == 24 || rawKey.count == 32 else {
            throw NSError(domain: "PayloadCrypto", code: -1, userInfo: [NSLocalizedDescriptionKey: "rawKey must be 16, 24, or 32 bytes"])
        }
        let key = SymmetricKey(data: rawKey)
        let sealed = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealed.combined else {
            throw NSError(domain: "CloudPhoneRiskKit", code: 2, userInfo: [NSLocalizedDescriptionKey: "AES.GCM combined unavailable"])
        }
        return combined
    }

    /// 使用调用方提供的原始密钥解密（输入为 `nonce || ciphertext || tag`，无 magic 头）。
    /// - Throws: 密钥长度非法或认证标签校验失败。
    static func decrypt(_ combined: Data, rawKey: Data) throws -> Data {
        guard rawKey.count == 16 || rawKey.count == 24 || rawKey.count == 32 else {
            throw NSError(domain: "PayloadCrypto", code: -1, userInfo: [NSLocalizedDescriptionKey: "rawKey must be 16, 24, or 32 bytes"])
        }
        let key = SymmetricKey(data: rawKey)
        let box = try AES.GCM.SealedBox(combined: combined)
        return try AES.GCM.open(box, using: key)
    }

    /// 取得 Keychain 主密钥；不存在时用 `SecRandomCopyBytes` 生成 32 字节（AES-256）并持久化。
    /// 整个流程持锁，保证并发调用只生成一把密钥。
    private static func symmetricKey() throws -> SymmetricKey {
        try lock.withLock {
            if var keyData = try readKey() {
                let key = SymmetricKey(data: keyData)
                // 中间副本用完立即清零，减少密钥在堆上驻留的时间窗口。
                secureZeroData(&keyData)
                return key
            }
            var secureData: Data?
            // SecureBuffer 保证临时密钥缓冲区在 use 返回时被清零。
            _ = SecureBuffer(size: 32).use { ptr in
                // 32 字节 = 256 bit，使用系统 CSPRNG，失败则不产生任何密钥。
                let status = SecRandomCopyBytes(kSecRandomDefault, 32, ptr)
                guard status == errSecSuccess else { return }
                secureData = Data(UnsafeRawBufferPointer(start: ptr, count: 32))
            }
            guard var data = secureData else {
                throw NSError(domain: "CloudPhoneRiskKit", code: 3, userInfo: [NSLocalizedDescriptionKey: "SecRandomCopyBytes failed"])
            }
            // 无论后续保存成功与否，函数返回前都清掉本地密钥副本。
            defer { secureZeroData(&data) }
            // 并发首次调用时可能已被其他线程写入；以 Keychain 中已有的密钥为准。
            if let existing = try saveKey(data) {
                return SymmetricKey(data: existing)
            }
            return SymmetricKey(data: data)
        }
    }

    private static func readKey() throws -> Data? {
        // kSecAttrAccessible must NOT be in read queries — it is a write-time
        // attribute and including it causes lookup failures on some iOS versions.
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keyService,
            kSecAttrAccount as String: keyAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess, let data = item as? Data {
            return data
        }
#if DEBUG
        // 模拟器/CI 没有可用 Keychain 时退回进程内临时密钥，仅用于测试。
        if keychainStatusIndicatesUnavailable(status) {
            return debugFallbackKeyData
        }
#else
        // Release 下如果 Keychain 因锁屏不可交互，必须抛错而不是生成临时密钥：
        // 临时密钥无法跨启动解密，会造成静默数据丢失/降级。
        if status == errSecInteractionNotAllowed {
            throw NSError(domain: "PayloadCrypto", code: Int(errSecInteractionNotAllowed))
        }
#endif
        return nil
    }

    /// 保存新密钥；成功返回 nil，若并发下已存在则返回既有密钥供调用方复用。
    private static func saveKey(_ data: Data) throws -> Data? {
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keyService,
            kSecAttrAccount as String: keyAccount,
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessible,
        ]

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        if status == errSecSuccess { return nil }
#if DEBUG
        // 测试环境：Keychain 不可用时把密钥留在进程内，保证同一次运行可解密。
        if keychainStatusIndicatesUnavailable(status) {
            debugFallbackKeyData = Data(data)
            return nil
        }
#else
        if status == errSecInteractionNotAllowed {
            throw NSError(domain: "PayloadCrypto", code: Int(errSecInteractionNotAllowed))
        }
#endif

        // 竞争窗口内别的线程已成功写入：读回那把密钥，避免本次生成的新密钥被丢弃后
        // 加密数据却用旧密钥解密失败。
        if status == errSecDuplicateItem, let existing = try readKey() {
            return existing
        }

        // 其余状态无法安全降级，记录后抛错，由上层决定是否停止持久化。
        Logger.log("PayloadCrypto: saveKey failed with unexpected status \(status) — key will not be persisted")
        throw NSError(
            domain: "PayloadCrypto",
            code: Int(status),
            userInfo: [NSLocalizedDescriptionKey: "SecItemAdd failed with status \(status)"]
        )
    }

    /// 判断 Keychain 错误是否属于“当前环境没有可用 Keychain”而非密钥逻辑错误。
    /// 只有这些状态才允许 DEBUG 进程内降级。
    private static func keychainStatusIndicatesUnavailable(_ status: OSStatus) -> Bool {
        if status == errSecInteractionNotAllowed ||
            status == errSecMissingEntitlement ||
            status == errSecNotAvailable {
            return true
        }
        #if DEBUG && os(macOS)
        // macOS SwiftPM/XCTest can map sandboxed keychain access failures to
        // errSecParam. Keep this test-host escape hatch out of iOS and Release.
        return status == errSecParam
        #else
        return false
        #endif
    }
}
