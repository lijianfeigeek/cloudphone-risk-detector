// 上报链路·App Attest 证明链：生成/保存 attestation key，签发 assertion 并构造 v3 安全信封。
// 串行门保证“取挑战 → 构造并签名信封 → 上传确认”在同一事务内完成，避免挑战被并发复用。
// 隐私边界：keyId 存 Keychain（ThisDeviceOnly），私钥在 Secure Enclave 永不离开设备；出设备的只有 assertion/keyId/信封。

import CryptoKit
import DeviceCheck
import Foundation
import Security

/// App Attest 硬件信任根签名器（SDK 4.4）
/// 使用 Secure Enclave 对 payload 摘要进行硬件签名，防止伪造。
/// SDK 4.4 Phase 6: Keychain 存 keyId，kSecAttrAccessibleWhenUnlockedThisDeviceOnly。
/// 线程模型：Keychain 访问由 `lock` 串行化；注册/上传事务分别由 `TransactionGate` 串行化。
@available(iOS 14.0, macOS 11.0, *)
public enum AppAttestSigner {

    /// 是否支持 App Attest（真机 + 有效 App ID；模拟器/黑苹果/虚拟机返回 false）
    public static var isSupported: Bool {
        DCAppAttestService.shared.isSupported
    }

    /// 获取或创建 attestation key ID（不生成断言）。
    /// Keychain 中已有 keyId 时直接返回；否则必须先通过 `configureEnrollment` 配置服务端注册回调。
    public static func resolveKeyId() async throws -> String {
        try await getOrCreateKeyId()
    }

    /// 对 payload 数据生成硬件断言（内部计算 SHA256）。
    /// - Parameter payloadData: 待签名数据（通常为 canonical payload）。
    /// - Returns: (keyId, assertionData)。
    /// - Throws: 硬件信任根不可用、摘要长度异常或 Keychain/注册失败时直接抛出，不降级为软件签名。
    public static func generateAssertion(for payloadData: Data) async throws -> (keyId: String, assertion: Data) {
        guard AppAttestSigner.isSupported else {
            throw AppAttestError.hardwareTrustUnsupported
        }
        let hash = SHA256.hash(data: payloadData)
        let payloadHash = Data(hash)
        // App Attest 要求 clientDataHash 恰为 32 字节 SHA-256，长度不符即拒绝。
        guard payloadHash.count == 32 else {
            throw AppAttestError.invalidPayloadHashSize(payloadHash.count)
        }

        let keyId = try await getOrCreateKeyId()
        let assertion = try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: payloadHash)
        return (keyId, assertion)
    }

    /// 对 payload 摘要生成断言（调用方已计算 SHA256，必须为 32 字节）。
    public static func generateAssertion(forPayloadHash payloadHash: Data) async throws -> (keyId: String, assertion: Data) {
        guard payloadHash.count == 32 else {
            throw AppAttestError.invalidPayloadHashSize(payloadHash.count)
        }
        guard AppAttestSigner.isSupported else {
            throw AppAttestError.hardwareTrustUnsupported
        }
        let keyId = try await getOrCreateKeyId()
        let assertion = try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: payloadHash)
        return (keyId, assertion)
    }

    /// 服务端下发的一次性注册挑战。
    /// 提交必须在服务端验证苹果 attestation 证书链后才返回。
    public struct EnrollmentChallenge: Sendable {
        /// 挑战 ID，用于服务端关联/消费。
        public let id: String
        /// 挑战字节，至少 32 字节。
        public let bytes: Data
        public init(id: String, bytes: Data) { self.id = id; self.bytes = bytes }
    }
    /// 获取新挑战的回调。
    public typealias ChallengeProvider = @Sendable () async throws -> EnrollmentChallenge
    /// 提交注册材料的回调（keyId, attestation, challengeID）。
    public typealias EnrollmentSubmitter = @Sendable (String, Data, String) async throws -> Void
    // 注册回调在调用 configureEnrollment 前为 nil；未配置时禁止创建新 key。
    private static var enrollment: (ChallengeProvider, EnrollmentSubmitter)?

    /// 配置注册回调；重复调用会覆盖旧回调。
    public static func configureEnrollment(challenge: @escaping ChallengeProvider, submit: @escaping EnrollmentSubmitter) {
        lock.withLock { enrollment = (challenge, submit) }
    }

    /// 异步互斥门：保证注册与上传各自串行，避免并发获取/消费同一个挑战。
    private actor TransactionGate {
        private var busy = false
        private var waiters: [CheckedContinuation<Void, Never>] = []
        func acquire() async {
            if !busy { busy = true; return }
            await withCheckedContinuation { waiters.append($0) }
        }
        func release() {
            if waiters.isEmpty { busy = false } else { waiters.removeFirst().resume() }
        }
    }
    /// 上传事务门：保护“挑战 → 信封 → 上传确认”整段流程。
    private static let uploadGate = TransactionGate()
    /// 注册事务门：保护 keyId 的首次创建与注册提交。
    private static let initializationGate = TransactionGate()

    /// 串行化挑战获取直到服务端确认。提交方遇到网络结果不明时必须用**同一个**信封重试，
    /// 且只能在服务端确认（或抛错）后返回；抛错后挑战由服务端保留至消费/过期，
    /// 绝不重新获取挑战来绕过失败。
    public static func submitCollectorReport(
        payloadData: Data, reportId: String, sessionToken: String, signingKey: String,
        keyId: String, challenge: ChallengeProvider,
        submit: (ReportEnvelope) async throws -> Void
    ) async throws {
        await uploadGate.acquire()
        do {
            try Task.checkCancellation()
            let fresh = try await challenge()
            guard !fresh.id.isEmpty else { throw AppAttestError.invalidServerChallenge }
            let envelope = try await createCollectorEnvelope(payloadData: payloadData,
                reportId: reportId, sessionToken: sessionToken, signingKey: signingKey,
                keyId: keyId, serverChallenge: fresh.bytes)
            try await submit(envelope)
            await uploadGate.release()
        } catch {
            await uploadGate.release()
            throw error
        }
    }

    /// 显式 v3 Collector 路径；所有证明材料必须在信封签名之前就绪。
    /// 挑战字节来自 POST /reports/challenge，且只能使用一次。
    @available(*, deprecated, message: "Use submitCollectorReport to serialize through upload acknowledgement")
    public static func createCollectorEnvelope(
        payloadData: Data, reportId: String, sessionToken: String, signingKey: String,
        keyId: String, serverChallenge: Data
    ) async throws -> ReportEnvelope {
        guard isSupported else { throw AppAttestError.hardwareTrustUnsupported }
        // 挑战不足 32 字节视为弱随机/中间人异常，直接拒绝。
        guard serverChallenge.count >= 32 else { throw AppAttestError.invalidServerChallenge }
        let attestationKeyId = try await resolveKeyId()
        let config = ReportEnvelope.Config(signatureVersion: "v3", requireHardwareAttestation: true)
        let draft = try ReportEnvelope.create(payloadData: payloadData, reportId: reportId,
            sessionToken: sessionToken, signingKey: signingKey, keyId: keyId,
            attestationKeyId: attestationKeyId, config: config)
        // 第一次断言覆盖 canonical payload；第二次断言覆盖服务端挑战，用于证明“本次会话 freshness”。
        let canonical = Data(try draft.canonicalPayloadString().utf8)
        let assertion = try await DCAppAttestService.shared.generateAssertion(
            attestationKeyId, clientDataHash: Data(SHA256.hash(data: canonical)))
        let freshAssertion = try await DCAppAttestService.shared.generateAssertion(
            attestationKeyId, clientDataHash: Data(SHA256.hash(data: serverChallenge)))
        return try ReportEnvelope.create(payloadData: payloadData, reportId: reportId,
            sessionToken: sessionToken, signingKey: signingKey, keyId: keyId,
            attestationKeyId: attestationKeyId, attestationAssertion: assertion,
            reAttestationAssertion: freshAssertion, trustLevel: .hardware, config: config)
    }

    // MARK: - 密钥管理

    private static let keychainService = "CloudPhoneRiskKit.AppAttest"
    // 账号名带版本，变更存储格式时可通过新账号平滑迁移，避免读到旧结构。
    private static let keychainAccount = "attestation_key_id.server_enrolled.v2"
    private static let lock = NSLock()  // 锁覆盖 Keychain I/O，避免并发读写

    /// 在注册门内获取/创建 keyId；无论成功失败都释放门，防止死锁。
    private static func getOrCreateKeyId() async throws -> String {
        await initializationGate.acquire()
        do {
            try Task.checkCancellation()
            let value = try await initializeKeyId()
            await initializationGate.release()
            return value
        } catch {
            await initializationGate.release()
            throw error
        }
    }

    /// 首次注册流程：读已有 keyId；没有则取挑战、生成 key、attestKey 并提交服务端。
    /// 若并发注册导致 Keychain 已存在 keyId，以先写入者为准。
    private static func initializeKeyId() async throws -> String {
        if let existing = try loadKeyId() {
            return existing
        }
        guard let handlers = lock.withLock({ enrollment }) else {
            throw AppAttestError.enrollmentNotConfigured
        }
        let challenge = try await handlers.0()
        guard !challenge.id.isEmpty, challenge.bytes.count >= 32 else {
            throw AppAttestError.invalidServerChallenge
        }
        let keyId = try await DCAppAttestService.shared.generateKey()
        let clientDataHash = SHA256.hash(data: challenge.bytes)
        let attestation = try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: Data(clientDataHash))
        try await handlers.1(keyId, attestation, challenge.id)
        switch try saveKeyId(keyId) {
        case .saved: return keyId
        case .existing(let winner): return winner
        }
    }

    /// 读取 keyId（内部加锁）。
    private static func loadKeyId() throws -> String? {
        try lock.withLock { try loadKeyIdLocked() }
    }

    /// keyId 持久化结果：新建成功或已存在竞争赢家。
    private enum SaveResult { case saved, existing(String) }

    /// 只增不改的持久化：任何错误都不会被误当作“已保存”。
    @discardableResult
    private static func saveKeyId(_ keyId: String) throws -> SaveResult {
        try lock.withLock {
            let data = Data(keyId.utf8)
            let addQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: keychainService,
                kSecAttrAccount as String: keychainAccount,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                kSecValueData as String: data,
            ]
            let status = SecItemAdd(addQuery as CFDictionary, nil)
            if status == errSecSuccess { return .saved }
            if status == errSecDuplicateItem, let existing = try loadKeyIdLocked() {
                return .existing(existing)
            }
            throw AppAttestError.keychainFailure(status)
        }
    }

    /// 在调用方已持有 `lock` 时读取 keyId。
    private static func loadKeyIdLocked() throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw AppAttestError.keychainFailure(status) }
        guard let data = item as? Data, let str = String(data: data, encoding: .utf8), !str.isEmpty else {
            throw AppAttestError.keychainFailure(errSecDecode)
        }
        return str
    }

    // MARK: - 错误

    /// App Attest 相关错误；错误信息可安全用于日志，不含密钥材料。
    public enum AppAttestError: Error, LocalizedError {
        case keychainFailure(OSStatus)
        case enrollmentNotConfigured
        case invalidServerChallenge
        case hardwareTrustUnsupported
        case invalidPayloadHashSize(Int)

        public var errorDescription: String? {
            switch self {
            case .keychainFailure(let status): return "Keychain failure: \(status)"
            case .enrollmentNotConfigured: return "Configure authenticated server enrollment first"
            case .invalidServerChallenge: return "Server challenge must have an ID and at least 32 bytes"
            case .hardwareTrustUnsupported:
                return "App Attest 不支持（模拟器/黑苹果/虚拟机或无效 App ID）"
            case .invalidPayloadHashSize(let count):
                return "payloadHash 必须为 32 字节 (SHA256)，当前: \(count)"
            }
        }
    }
}
