// Secure Enclave P-256 签名能力：私钥在 SE 内生成且永不出硬件，用于证明当前进程运行在真实设备。
// 该能力不是 App Attest；模拟器、unidbg 与无 SE 的虚拟化环境会在这里失败并降级。

import Foundation
import Security

/// Secure Enclave 私钥签名器（P-256 ECDSA over SHA-256）
///
/// **不是** App Attest（那是 Apple 服务器侧验签的应用证明）。
/// 这是**通用 SE 签名能力**：在 Secure Enclave 里生成一对 P-256 密钥，
/// 私钥永远不出 SE，公钥可导出供未来服务器或本地校验链使用。
///
/// 价值：
///   - 任何能拿到 SE 私钥签名输出 = 强证据当前进程跑在真实硬件上
///   - 攻击者即使 hook 了所有 CryptoKit / SecKey API，**也伪造不出有效 ECDSA 签名**
///     除非他们物理上有这个设备 — 因为私钥永远不出 SE
///   - 模拟器、unidbg、Frida-on-rooted-vm 全部失败：模拟器没有真 SE
///
/// 注意：
///   - 第一次 ensureKey() 会生成新密钥并存入 Keychain（受 SE 控制访问）
///   - SecKey 引用是 transient 的；每次 sign 都从 Keychain 重新拿
///   - kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly：解锁后可用，不跨设备同步
///   - `isSupported` 用懒 probe：实际尝试 ensureKey 一次后缓存结果。
///     SecAccessControlCreateWithFlags 不实际探测 SE 硬件存在性，所以不能用。
enum SecureEnclaveSigner {

    // Keychain 中定位 SE 私钥的 application tag；改值会生成一把新密钥。
    private static let keychainTag = Data("com.cloudphoneriskkit.localsign.v1".utf8)
    // 串行化 keychain load / SE keygen / 缓存读写，避免并发首次调用创建多把密钥。
    private static let lock = NSLock()
    // nil = 尚未探测；false/true = 已缓存的硬件能力结论。
    private static var probedSupport: Bool? = nil

    /// SE 签名相关错误。
    /// 只暴露 domain + code，不携带 userInfo：后者可能含 Apple 内部字符串与路径，
    /// 跨 iOS 版本不稳定，也不适合写进风险信号。
    enum SignError: Error, LocalizedError {
        case unsupportedDevice
        case keyCreationFailed(domain: String, code: Int)
        case keyLoadFailed(OSStatus)
        case publicKeyCopyFailed
        case signFailed(domain: String, code: Int)
        case publicKeyExportFailed(domain: String, code: Int)

        var errorDescription: String? {
            switch self {
            case .unsupportedDevice: return "SE_unsupported"
            case .keyCreationFailed(let d, let c): return "SE_keygen_failed:\(d):\(c)"
            case .keyLoadFailed(let s): return "SE_keyload_failed:\(s)"
            case .publicKeyCopyFailed: return "SE_pubkey_copy_failed"
            case .signFailed(let d, let c): return "SE_sign_failed:\(d):\(c)"
            case .publicKeyExportFailed(let d, let c): return "SE_pubkey_export_failed:\(d):\(c)"
            }
        }
    }

    /// 当前设备/环境是否能跑 SE 签名（懒 probe + 缓存）。
    /// 第一次调用会实际尝试生成/加载 SE 密钥，结果缓存。
    /// 不像 SecAccessControlCreateWithFlags 那种"看起来在工作"的伪 probe，
    /// 这里直接对 SE 硬件做真实交互。
    static var isSupported: Bool {
        if let cached = readCachedSupport() {
            return cached
        }
        #if targetEnvironment(simulator)
        // 模拟器没有 Secure Enclave；直接缓存 false，避免无意义的 Keychain 探测。
        cacheSupport(false)
        return false
        #else
        let result: Bool
        do {
            _ = try ensureKeyInternal()
            result = true
        } catch {
            // 探测失败视为不支持：调用方据此降级，而不是让整个评估链路失败。
            result = false
        }
        cacheSupport(result)
        return result
        #endif
    }

    /// 测试用：清空 isSupported 缓存。
    static func resetSupportCacheForTesting() {
        lock.lock()
        defer { lock.unlock() }
        probedSupport = nil
    }

    /// 取得（或第一次创建）SE 密钥，返回 transient SecKey 引用。
    /// 返回的引用不应被长期缓存：每次使用前重新从 Keychain 获取，避免失效引用。
    static func ensureKey() throws -> SecKey {
        return try ensureKeyInternal()
    }

    /// 用 SE 私钥对 `data` 做 ECDSA-P256-SHA256 签名（X9.62 DER 格式）。
    /// SE 内部会先对 data 做 SHA-256，再签摘要。
    /// - Throws: 密钥不可用或签名失败；不会返回空签名。
    static func sign(_ data: Data) throws -> Data {
        let key = try ensureKeyInternal()
        var error: Unmanaged<CFError>?
        // ecdsaSignatureMessageX962SHA256 表示“输入是原始消息”，由 SE 负责哈希；
        // 输出为 X9.62 DER 编码，可直接交给服务器用公钥验签。
        guard let signature = SecKeyCreateSignature(
            key,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) as Data? else {
            // takeRetainedValue 接管 CFError 所有权；随后只提取 domain/code。
            let cfErr = error?.takeRetainedValue()
            throw SignError.signFailed(domain: cfErrorDomain(cfErr), code: cfErrorCode(cfErr))
        }
        return signature
    }

    /// 导出公钥的 X9.62 未压缩点表示（65 字节: 0x04 || X32 || Y32），可用于服务器验签。
    /// - Throws: 私钥不可用、公钥复制失败或导出失败。
    static func publicKeyX962() throws -> Data {
        let priv = try ensureKeyInternal()
        // 公钥可以从 SE 私钥派生，但私钥本身仍留在 SE 内。
        guard let pub = SecKeyCopyPublicKey(priv) else {
            throw SignError.publicKeyCopyFailed
        }
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(pub, &error) as Data? else {
            let cfErr = error?.takeRetainedValue()
            throw SignError.publicKeyExportFailed(domain: cfErrorDomain(cfErr), code: cfErrorCode(cfErr))
        }
        return data
    }

    // MARK: - Private

    private static func readCachedSupport() -> Bool? {
        lock.lock()
        defer { lock.unlock() }
        return probedSupport
    }

    private static func cacheSupport(_ value: Bool) {
        lock.lock()
        defer { lock.unlock() }
        probedSupport = value
    }

    /// 不再走 `isSupported` 的递归。直接尝试 load → create。
    /// 整个过程持锁：SE 密钥生成较慢，但并发重复生成会产生多把同名密钥。
    private static func ensureKeyInternal() throws -> SecKey {
        lock.lock()
        defer { lock.unlock() }
        // 已存在则复用；load 失败（如 tag 不存在）再走创建分支。
        if let existing = try? loadExistingKeyLocked() {
            return existing
        }
        return try createKeyLocked()
    }

    private static func loadExistingKeyLocked() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keychainTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else {
            throw SignError.keyLoadFailed(status)
        }
        // 查询条件限定 kSecClassKey，成功时返回值必为 SecKey；此处强制转换是安全的。
        return result as! SecKey  // swiftlint:disable:this force_cast
    }

    private static func createKeyLocked() throws -> SecKey {
        var accessError: Unmanaged<CFError>?
        // .privateKeyUsage：仅允许私钥签名，不开放导出；ThisDeviceOnly 禁止迁移。
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [.privateKeyUsage],
            &accessError
        ) else {
            let cfErr = accessError?.takeRetainedValue()
            throw SignError.keyCreationFailed(domain: cfErrorDomain(cfErr), code: cfErrorCode(cfErr))
        }

        let privateKeyAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: keychainTag,
            kSecAttrAccessControl as String: access,
        ]

        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            // 指定 SE token：密钥生成/签名都在 Secure Enclave 内完成。
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateKeyAttrs,
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            // 模拟器/无 SE 设备通常在此失败；抛错由 isSupported 捕获并降级。
            let cfErr = error?.takeRetainedValue()
            throw SignError.keyCreationFailed(domain: cfErrorDomain(cfErr), code: cfErrorCode(cfErr))
        }
        return key
    }

    // MARK: - CFError helpers
    // 仅暴露 domain + code，不把 userInfo 序列化到信号里 — userInfo 会包含
    // Apple 内部字符串、可能含路径，跨 iOS 版本不稳定。

    private static func cfErrorDomain(_ err: CFError?) -> String {
        guard let err = err else { return "nil" }
        let raw = CFErrorGetDomain(err) as String? ?? "unknown"
        return raw
    }

    private static func cfErrorCode(_ err: CFError?) -> Int {
        guard let err = err else { return -1 }
        return CFErrorGetCode(err)
    }
}
