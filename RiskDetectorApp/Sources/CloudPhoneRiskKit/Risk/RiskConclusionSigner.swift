// 上报链路·本地风险结论签名：对 score/isHighRisk/timestamp/nonce/tampered 与信号摘要做 HMAC。
// 用于校验端侧结论未被改写；v2a 把信号 id/score/state 摘要绑定进签名域。
// 隐私边界：签名 hex 与结论字段随报告上报；DeviceKey 及其 Keychain 盐只在本地派生/保存，不离开设备。

import CryptoKit
import Darwin
import Foundation
import Security

/// 已签名的本地风险结论；服务端可据此验证结论未被中间层篡改。
public struct SignedRiskConclusion: Codable, Sendable {
    /// 本地风险总分（0–100）。
    public let score: Double
    /// 是否判定为高风险。
    public let isHighRisk: Bool
    /// 结论生成时间（Unix 秒），参与签名与时效校验。
    public let timestamp: TimeInterval
    /// 端侧是否检测到篡改迹象。
    public let tampered: Bool
    /// 一次性随机数，防止同一结论被重放。
    public let nonce: String
    /// HMAC 十六进制签名。
    public let signature: String
    /// "v1" = legacy（不含信号摘要），"v2" = 仅信号 ID 摘要，"v2a" = 完整信号摘要（id+score+state）
    public let signatureVersion: String?
    /// v2：排序后的信号 ID 以逗号连接的 SHA-256 hex。
    /// v2a：排序后的 "id:score:state" 条目的 SHA-256 hex，把信号值也绑定进签名。
    public let signalsDigest: String?

    // 网络传输使用短键，减少载荷体积；修改键名会破坏与服务端的兼容性。
    private enum CodingKeys: String, CodingKey {
        case score = "s"
        case isHighRisk = "hr"
        case timestamp = "ts"
        case tampered = "tp"
        case nonce = "n"
        case signature = "sg"
        case signatureVersion = "sv"
        case signalsDigest = "sd"
    }

    /// 对报告结论签名。
    /// - Parameters:
    ///   - report: 本地评估结果。
    ///   - deviceKey: 由设备不变量派生的对称密钥，只在本地使用。
    /// - Returns: 携带 v2a 签名与信号摘要的结论对象。
    public static func sign(report: CPRiskReport, deviceKey: SymmetricKey) -> SignedRiskConclusion {
        // 每次签名使用新 nonce，服务端据此拒绝重复结论。
        let nonce = UUID().uuidString
        let timestamp = Date().timeIntervalSince1970

        // 摘要覆盖信号值，攻击者仅改分数而不改信号会被发现。
        let signalsDigest = SignalDigest.computeFullDigest(report.signals)

        // 签名输入顺序是协议的一部分：字段或分隔符变更必须同步服务端。
        let input = "\(report.score)|\(report.isHighRisk)|\(timestamp)|\(nonce)|\(report.tampered)|\(signalsDigest)"
        let mac = SecureScope.withSecureBytes(Array(input.utf8)) { ptr in
            let data = Data(buffer: ptr)
            return CPRiskMessageAuth.authenticationCode(for: data, using: deviceKey)
        }
        let sigHex = mac.map { String(format: "%02x", $0) }.joined()
        return SignedRiskConclusion(
            score: report.score,
            isHighRisk: report.isHighRisk,
            timestamp: timestamp,
            tampered: report.tampered,
            nonce: nonce,
            signature: sigHex,
            signatureVersion: "v2a",
            signalsDigest: signalsDigest
        )
    }

    /// 验证结论签名与时效。
    /// - Parameters:
    ///   - deviceKey: 与签名时相同的派生密钥。
    ///   - maxAgeSeconds: 结论最大允许年龄，默认 300 秒。
    /// - Returns: 时间窗、摘要与 HMAC 均通过时为 `true`；任一失败即 `false`（fail-closed）。
    public func verify(deviceKey: SymmetricKey, maxAgeSeconds: TimeInterval = 300) -> Bool {
        let age = Date().timeIntervalSince1970 - timestamp
        // 允许最多 30 秒负年龄，容忍客户端与服务端之间的轻微时钟偏差；未来时间超出即拒绝。
        guard age >= -30, age <= maxAgeSeconds else { return false }

        guard let signatureData = Data(hexString: signature) else { return false }

        // 未知版本按 v1 处理；v2/v2a 缺少摘要直接拒绝，避免降级绕过信号绑定。
        let version = signatureVersion ?? "v1"
        let input: String
        switch version {
        case "v2a", "v2":
            guard let digest = signalsDigest else { return false }
            input = "\(score)|\(isHighRisk)|\(timestamp)|\(nonce)|\(tampered)|\(digest)"
        default:
            input = "\(score)|\(isHighRisk)|\(timestamp)|\(nonce)|\(tampered)"
        }

        return SecureScope.withSecureBytes(Array(input.utf8)) { ptr in
            let data = Data(buffer: ptr)
            return CPRiskMessageAuth.isValidAuthenticationCode(signatureData, authenticating: data, using: deviceKey)
        }
    }
}

/// DeviceKey 派生器：把设备不变量与 Keychain 盐经 SHA-256 + HKDF 聚合成 32 字节对称密钥。
/// 安全不变量：盐与派生结果只在本地/Keychain 中存在，绝不随报告上报。
public enum DeviceKeyDeriver {
    /// 默认 DeviceKey 版本（v1），与 KeyRotationPolicy.deviceKeyVersion 对应
    public static let defaultInfoVersion = "v1"

    /// 构造 HKDF info 字段；版本号进入 info，使轮换后的密钥与旧版本不同。
    private static func info(for version: String) -> Data {
        Data("CloudPhoneRiskKit.DeviceKey.\(version)".utf8)
    }

    /// 派生 DeviceKey（使用默认版本 v1）
    public static func deriveKey(
        deviceID: String,
        hardwareMachine: String,
        kernelVersion: String,
        salt: Data? = nil
    ) -> SymmetricKey {
        deriveKey(
            deviceID: deviceID,
            hardwareMachine: hardwareMachine,
            kernelVersion: kernelVersion,
            salt: salt,
            infoVersion: defaultInfoVersion
        )
    }

    /// 派生 DeviceKey（支持 infoVersion 可配置，用于密钥轮换）
    /// - Parameters:
    ///   - deviceID: 同一安装的稳定设备 ID。
    ///   - hardwareMachine: 硬件型号标识。
    ///   - kernelVersion: 内核版本，作为设备不变量的一部分。
    ///   - salt: 可选 HKDF 盐；nil 时使用空盐。
    ///   - infoVersion: 与 KeyRotationPolicy.deviceKeyVersion 对应，如 "v1"、"v2"
    /// - Returns: 32 字节对称密钥。
    public static func deriveKey(
        deviceID: String,
        hardwareMachine: String,
        kernelVersion: String,
        salt: Data? = nil,
        infoVersion: String
    ) -> SymmetricKey {
        let (keychainSalt, _) = KeychainSalt.shared.getOrCreateWithPersistedFlag()
        // 用竖线拼接不变量后先 SHA-256 压缩，再由 HKDF 扩展；密钥材料全程在安全作用域内处理。
        let combined = "\(deviceID)|\(hardwareMachine)|\(kernelVersion)|\(keychainSalt)"
        return SecureScope.withSecureValue(combined) { str in
            var dataBytes = Array(str.utf8)
            defer { secureZeroBytes(&dataBytes) }
            let hash = SHA256.hash(data: Data(dataBytes))
            let inputKeyMaterial = SymmetricKey(data: Data(hash))
            return HKDF<SHA256>.deriveKey(
                inputKeyMaterial: inputKeyMaterial,
                salt: salt ?? Data(),
                info: info(for: infoVersion),
                outputByteCount: 32
            )
        }
    }

    /// 派生 DeviceKey，返回 (key, wasPersistedSalt)
    /// wasPersistedSalt 为 false 表示 Keychain 无持久化 salt（新建），TrustLevel 应为 .degraded
    public static func deriveKeyWithTrustInfo(
        deviceID: String,
        hardwareMachine: String,
        kernelVersion: String,
        salt: Data? = nil,
        infoVersion: String = defaultInfoVersion
    ) -> (key: SymmetricKey, saltWasPersisted: Bool) {
        let (keychainSalt, wasPersisted) = KeychainSalt.shared.getOrCreateWithPersistedFlag()
        let combined = "\(deviceID)|\(hardwareMachine)|\(kernelVersion)|\(keychainSalt)"
        let key = SecureScope.withSecureValue(combined) { str in
            var dataBytes = Array(str.utf8)
            defer { secureZeroBytes(&dataBytes) }
            let hash = SHA256.hash(data: Data(dataBytes))
            let inputKeyMaterial = SymmetricKey(data: Data(hash))
            return HKDF<SHA256>.deriveKey(
                inputKeyMaterial: inputKeyMaterial,
                salt: salt ?? Data(),
                info: info(for: infoVersion),
                outputByteCount: 32
            )
        }
        return (key, wasPersisted)
    }
}

/// DeviceKey 派生盐，存 Keychain。SDK 4.4 Phase 6: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly。
/// 盐不离开设备；Keychain 不可用时以内存降级盐继续派生，但会通过 `wasPersisted == false` 暴露降级。
private final class KeychainSalt {
    /// 进程级单例，保证同一次安装内派生盐稳定。
    static let shared = KeychainSalt()
    private init() {}

    private let service = "CloudPhoneRiskKit"
    private let account = "device_key_salt"
    private let saltLength = 32
    private let lock = NSLock()  // 锁覆盖 Keychain I/O，避免并发读写出重复盐
#if DEBUG
    private var debugFallbackSalt: String?
#endif

    /// 读取或创建派生盐（忽略是否持久化的标志）。
    func getOrCreate() -> String {
        getOrCreateWithPersistedFlag().0
    }

    /// 返回 (salt, wasPersisted)：wasPersisted 为 true 表示从 Keychain 读取到已有 salt
    func getOrCreateWithPersistedFlag() -> (String, Bool) {
        return lock.withLock {
            if let existing = read() { return (existing, true) }
#if DEBUG
            if let fallback = debugFallbackSalt {
                return (fallback, false)
            }
#endif

            var bytes = [UInt8](repeating: 0, count: saltLength)
            defer { secureZeroBytes(&bytes) }
            // 优先使用系统 CSPRNG；失败重试一次，仍失败才进入降级路径。
            var status = SecRandomCopyBytes(kSecRandomDefault, saltLength, &bytes)
            if status != errSecSuccess {
                status = SecRandomCopyBytes(kSecRandomDefault, saltLength, &bytes)
            }
            // 降级盐来自 UUID + 启动时间再哈希：强度弱于 CSPRNG，因此调用方应结合 wasPersisted=false 降级信任等级。
            if status != errSecSuccess {
                let fallback = "\(UUID().uuidString)\(mach_absolute_time())"
                let hash = SHA256.hash(data: Data(fallback.utf8))
                bytes = Array(hash.prefix(saltLength))
            }

            let hex = bytes.map { String(format: "%02x", $0) }.joined()
            if let existing = save(hex) {
                return (existing, true)
            }
#if DEBUG
            debugFallbackSalt = hex
#endif
            return (hex, false)
        }
    }

    /// 从 Keychain 读取既有盐；未找到返回 nil。
    private func read() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let dataObj = item as? Data else { return nil }
        var data = dataObj
        defer { secureZeroData(&data) }
        return String(data: data, encoding: .utf8)
    }

    /// 写入盐；成功返回 nil，若已存在同账号条目则返回既有值（只增不改，避免覆盖导致 DeviceKey 漂移）。
    private func save(_ value: String) -> String? {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: data,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecSuccess { return nil }

        if status == errSecDuplicateItem, let existing = read() {
            return existing
        }

        return nil
    }
}
