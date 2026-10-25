// 上报链路·本地安全信封校验：版本白名单、attestation 成对校验、签名/HMAC 与 nonce 防重放。
// `LocalEnvelopeReplayStore` 仅用于 SDK 自测/联调；生产网关必须使用服务端一致性存储。
// Release 下存储损坏、解密/HMAC 失败或持久化失败都会进入 fail-closed，拒绝消费 nonce。

import Foundation

/// 本地信封校验错误；`reasonCode` 提供稳定的机器可读原因。
public enum SecureEnvelopeValidationError: Error, LocalizedError, Sendable {
    case invalidEnvelopeJSON
    case unsupportedSignatureVersion(actual: String, allowed: [String])
    case unknownKeyId(String)
    case reportEnvelope(ReportEnvelope.ReportEnvelopeError)

    /// 人类可读错误描述；仅含版本/状态码等非敏感信息。
    public var errorDescription: String? {
        switch self {
        case .invalidEnvelopeJSON:
            return "安全信封 JSON 无法解析"
        case .unsupportedSignatureVersion(let actual, let allowed):
            return "签名版本不被允许：actual=\(actual), allowed=\(allowed.joined(separator: ","))"
        case .unknownKeyId(let keyId):
            return "找不到 keyId 对应的签名密钥：\(keyId)"
        case .reportEnvelope(let error):
            return error.errorDescription
        }
    }
}

/// 默认本地重放保护存储（仅用于 SDK 自测与联调）。
/// 生产网关应使用服务端一致性存储。
/// 安全不变量：状态加密 + HMAC 校验 + freshness 锚点；任一完整性校验失败即 fail-closed。
public final class LocalEnvelopeReplayStore: NonceReplayProtecting, @unchecked Sendable {
    /// 进程级单例，供本地校验路径共享同一份已消费 nonce 集合。
    public static let shared = LocalEnvelopeReplayStore()

    /// 持久化结构；使用短键减小 UserDefaults 体积。
    private struct StoredEnvelope: Codable {
        var schemaVersion: Int
        var entries: [String: Int64]
        var latestExpiryMillis: Int64
        var sequence: UInt64

        private enum CodingKeys: String, CodingKey {
            case schemaVersion = "sv"
            case entries = "en"
            case latestExpiryMillis = "le"
            case sequence = "sq"
        }
    }

    private let defaults = UserDefaults.standard
    private let lock = UnfairLock()
    // 存储键与 HMAC 键分离，便于整体校验/清理；版本后缀 v2 表示当前存储格式。
    private let key = "cloudphone_envelope_replay_v2"
    private let hmacKey = "cloudphone_envelope_replay_v2_hmac"
    private let hmacPurpose = "envelope_replay"
    // freshness 锚点独立保存：用于检测回滚（sequence/时间戳倒退视为存储被替换）。
    private let freshnessAnchor = FreshnessAnchor(account: "envelope_replay_v2_freshness")
    // 2048 条上限：控制内存与持久化体积，超出后优先淘汰最早过期项。
    private let maxEntries = 2048
    private var storage: [String: Int64] = [:]
    private var freshness: FreshnessState = .zero
    private var failClosed = false

    /// 初始化时同步加载并校验持久化状态；失败会在 Release 下置 fail-closed。
    private init() {
        lock.withLock { loadLocked() }
    }

    /// 尝试消费 nonce；首次出现返回 true，已存在或存储不可信返回 false。
    public func consumeIfNew(sessionToken: String, nonce: String, expiresAtMillis: Int64) -> Bool {
        lock.withLock {
            guard !failClosed else {
                Logger.log("LocalEnvelopeReplayStore: fail-closed active, rejecting nonce consumption")
                return false
            }

            pruneExpiredLocked(nowMillis: nowMillis())

            let key = replayKey(sessionToken: sessionToken, nonce: nonce)
            if storage[key] != nil {
                return false
            }

            storage[key] = expiresAtMillis
            trimToLimitLocked()
            guard persistLocked() else {
                storage.removeValue(forKey: key)
                return false
            }
            return true
        }
    }

    /// 加载持久化状态：先验 HMAC，再解密/解码，并检查 freshness 不得回退。
    private func loadLocked() {
        let anchor = freshnessAnchor.read() ?? .zero
        guard let stored = defaults.data(forKey: key) else {
            storage = [:]
            freshness = anchor
            failClosed = false
            return
        }
        guard let signature = defaults.data(forKey: hmacKey),
              StorageIntegrityGuard.verify(stored, signature: signature, purpose: hmacPurpose) else {
            handleCorruptedStateLocked(reason: "signature verification failed", anchor: anchor)
            return
        }

        let plaintext: Data
        #if DEBUG
        if let decrypted = try? PayloadCrypto.decrypt(stored) {
            plaintext = decrypted
        } else {
            plaintext = stored
        }
        #else
        guard let decrypted = try? PayloadCrypto.decrypt(stored) else {
            handleCorruptedStateLocked(reason: "decrypt failed in release build", anchor: anchor)
            return
        }
        plaintext = decrypted
        #endif

        guard let envelope = try? JSONDecoder().decode(StoredEnvelope.self, from: plaintext) else {
            handleCorruptedStateLocked(reason: "json decode failed", anchor: anchor)
            return
        }

        let diskFreshness = FreshnessState(
            latestTimestamp: Double(envelope.latestExpiryMillis),
            sequence: envelope.sequence
        )
        // 磁盘状态的时间戳/序列号必须不落后于锚点；倒退说明状态被回滚或替换。
        if diskFreshness.sequence < anchor.sequence || diskFreshness.latestTimestamp < anchor.latestTimestamp {
            handleCorruptedStateLocked(reason: "freshness rollback detected", anchor: anchor)
            return
        }

        storage = envelope.entries
        freshness = FreshnessState(
            latestTimestamp: max(anchor.latestTimestamp, diskFreshness.latestTimestamp),
            sequence: max(anchor.sequence, diskFreshness.sequence)
        )
        pruneExpiredLocked(nowMillis: nowMillis())
        failClosed = false

        if diskFreshness.sequence > anchor.sequence || diskFreshness.latestTimestamp > anchor.latestTimestamp {
            _ = freshnessAnchor.write(diskFreshness)
        }
    }

    /// 加密、签名并持久化当前状态；任一步失败都返回 false 并触发 fail-closed。
    private func persistLocked() -> Bool {
        let anchor = freshnessAnchor.read() ?? .zero
        let latestExpiry = storage.values.max() ?? Int64(anchor.latestTimestamp)
        let nextFreshness = FreshnessState(
            latestTimestamp: max(Double(latestExpiry), max(anchor.latestTimestamp, freshness.latestTimestamp)),
            sequence: max(anchor.sequence, freshness.sequence) + 1
        )
        let envelope = StoredEnvelope(
            schemaVersion: 2,
            entries: storage,
            latestExpiryMillis: Int64(nextFreshness.latestTimestamp),
            sequence: nextFreshness.sequence
        )
        guard let raw = try? JSONEncoder().encode(envelope) else {
            activateFailClosedLocked(reason: "encode failed")
            return false
        }

        let stored: Data
        #if DEBUG
        stored = (try? PayloadCrypto.encrypt(raw)) ?? raw
        #else
        guard let encrypted = try? PayloadCrypto.encrypt(raw) else {
            activateFailClosedLocked(reason: "encrypt failed in release build")
            return false
        }
        stored = encrypted
        #endif

        defaults.set(stored, forKey: key)
        defaults.set(StorageIntegrityGuard.sign(stored, purpose: hmacPurpose), forKey: hmacKey)
        guard freshnessAnchor.write(nextFreshness) else {
            activateFailClosedLocked(reason: "freshness anchor update failed")
            return false
        }

        freshness = nextFreshness
        return true
    }

    /// 处理损坏状态：清理持久化数据；DEBUG 允许继续（便于联调），Release 置 fail-closed。
    private func handleCorruptedStateLocked(reason: String, anchor: FreshnessState) {
        Logger.log("LocalEnvelopeReplayStore: \(reason)")
        clearPersistedStateLocked(resetAnchor: false)
        storage = [:]
        freshness = anchor
        #if DEBUG
        failClosed = false
        #else
        failClosed = true
        #endif
    }

    /// 主动进入 fail-closed：Release 下后续所有 nonce 消费都会被拒绝。
    private func activateFailClosedLocked(reason: String) {
        Logger.log("LocalEnvelopeReplayStore: \(reason)")
        #if DEBUG
        failClosed = false
        #else
        failClosed = true
        #endif
        if failClosed {
            clearPersistedStateLocked(resetAnchor: false)
        }
    }

    /// 清理持久化状态；`resetAnchor` 为 true 时连 freshness 锚点一起删除（仅用于显式重置）。
    private func clearPersistedStateLocked(resetAnchor: Bool) {
        defaults.removeObject(forKey: key)
        defaults.removeObject(forKey: hmacKey)
        if resetAnchor {
            freshnessAnchor.remove()
        }
    }

    /// 惰性清理已过期条目，限制状态规模。
    private func pruneExpiredLocked(nowMillis: Int64) {
        storage = storage.filter { $0.value > nowMillis }
    }

    /// 超出容量上限时按过期时间从早到晚淘汰，保留更长时间防重放能力。
    private func trimToLimitLocked() {
        guard storage.count > maxEntries else { return }
        let sorted = storage.sorted { $0.value < $1.value }
        for item in sorted.prefix(storage.count - maxEntries) {
            storage.removeValue(forKey: item.key)
        }
    }

    /// 重放键由 sessionToken 与 nonce 共同构成，避免不同会话的 nonce 相互影响。
    private func replayKey(sessionToken: String, nonce: String) -> String {
        "\(sessionToken):\(nonce)"
    }

    /// Unix 时间戳毫秒，与 ReportEnvelope.ts 及 expiresAtMillis 时间轴一致
    private func nowMillis() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1000)
    }
}

extension CPRiskKit {
    /// 本地校验安全信封（用于 SDK 回归验证链路）。
    /// 默认允许版本与 SDK 实际签发版本一致：`v2a` / `v2d` / `v2h` / `v3`
    ///（`v2` 从未由当前 SDK 签发，故不再默认接受；`v1` 亦不接受）。
    /// ⚠️ 这只是本地兼容校验：服务端必须拒绝 legacy 版本（`v2a`/`v2d`/`v2h`），
    /// 仅接受 `v3`，因为 legacy 信封的 assertion 未纳入签名域、无法独立验证。
    ///
    /// **Attestation 一致性**：当 `validateAttestationConsistency == true`（默认）时，若 envelope 带有
    /// `attestationKeyId` 但 `attestationAssertion` 为空，视为异常（`.attestationIncomplete`），防止
    /// 硬件信任根被静默剥离或生成失败后仍被当作有效。
    ///
    /// - Parameter validateAttestationConsistency: 是否校验 attestationKeyId 与 attestationAssertion 成对存在。
    public func validateSecureReportEnvelope(
        _ envelope: ReportEnvelope,
        signingKey: String,
        allowedSignatureVersions: Set<String> = ["v2a", "v2d", "v2h", "v3"],
        enableReplayProtection: Bool = true,
        validateAttestationConsistency: Bool = true,
        nonceStore: NonceReplayProtecting? = nil,
        config: ReportEnvelope.Config = ReportEnvelope.Config()
    ) -> Result<Void, SecureEnvelopeValidationError> {
        guard allowedSignatureVersions.contains(envelope.sigVer) else {
            let allowed = Array(allowedSignatureVersions).sorted()
            return .failure(.unsupportedSignatureVersion(actual: envelope.sigVer, allowed: allowed))
        }

        if validateAttestationConsistency {
            let hasKeyId = envelope.attestationKeyId.map { !$0.isEmpty } ?? false
            let hasAssertion = envelope.attestationAssertion.map { !$0.isEmpty } ?? false
            // keyId 与 assertion 必须同时存在或同时缺失（XOR 表示不一致状态）
            if hasKeyId != hasAssertion {
                return .failure(.reportEnvelope(.attestationIncomplete))
            }
        }

        let replayStore = enableReplayProtection ? (nonceStore ?? LocalEnvelopeReplayStore.shared) : nil
        let result: Result<Void, ReportEnvelope.ReportEnvelopeError>

        // v2a 签名改为优先走 CRiskCore helper：runtime material 的读取、effective key 派生、
        // 以及最终 HMAC 验签都尽量收口到 C 层，Swift 侧不再直接拿到可用派生密钥。
        if envelope.sigVer == "v2a" {
            result = validateEnvelopeWithArmorDerivedSignature(
                envelope,
                baseKey: signingKey,
                nonceStore: replayStore,
                config: config
            )
        } else {
            result = envelope.validate(signingKey: signingKey, nonceStore: replayStore, config: config)
        }
        switch result {
        case .success:
            return .success(())
        case .failure(let error):
            return .failure(.reportEnvelope(error))
        }
    }

    /// 通过 keyId 动态解析签名密钥进行本地校验。
    /// - Parameter keyResolver: 根据 `envelope.keyId` 返回密钥；返回 nil 视为未知 keyId 并拒绝。
    public func validateSecureReportEnvelope(
        _ envelope: ReportEnvelope,
        keyResolver: (String) -> String?,
        allowedSignatureVersions: Set<String> = ["v2a", "v2d", "v2h", "v3"],
        enableReplayProtection: Bool = true,
        validateAttestationConsistency: Bool = true,
        nonceStore: NonceReplayProtecting? = nil,
        config: ReportEnvelope.Config = ReportEnvelope.Config()
    ) -> Result<Void, SecureEnvelopeValidationError> {
        let resolved = keyResolver(envelope.keyId)
        guard let signingKey = resolved else {
            return .failure(.unknownKeyId(envelope.keyId))
        }
        return validateSecureReportEnvelope(
            envelope,
            signingKey: signingKey,
            allowedSignatureVersions: allowedSignatureVersions,
            enableReplayProtection: enableReplayProtection,
            validateAttestationConsistency: validateAttestationConsistency,
            nonceStore: nonceStore,
            config: config
        )
    }

    /// 解析 JSON 并完成本地校验，成功时返回解析后的信封。
    /// 解析失败统一返回 `.invalidEnvelopeJSON`，不把底层解码错误暴露给调用方。
    public func validateSecureReportEnvelopeJSON(
        _ json: String,
        signingKey: String,
        allowedSignatureVersions: Set<String> = ["v2a", "v2d", "v2h", "v3"],
        enableReplayProtection: Bool = true,
        validateAttestationConsistency: Bool = true,
        nonceStore: NonceReplayProtecting? = nil,
        config: ReportEnvelope.Config = ReportEnvelope.Config()
    ) -> Result<ReportEnvelope, SecureEnvelopeValidationError> {
        guard let data = json.data(using: .utf8),
              let envelope = try? ReportEnvelope.fromJSON(data) else {
            return .failure(.invalidEnvelopeJSON)
        }

        switch validateSecureReportEnvelope(
            envelope,
            signingKey: signingKey,
            allowedSignatureVersions: allowedSignatureVersions,
            enableReplayProtection: enableReplayProtection,
            validateAttestationConsistency: validateAttestationConsistency,
            nonceStore: nonceStore,
            config: config
        ) {
        case .success:
            return .success(envelope)
        case .failure(let error):
            return .failure(error)
        }
    }
}

public extension SecureEnvelopeValidationError {
    /// 稳定的机器可读原因码，供日志/指标聚合；底层信封错误会带上其 reasonCode。
    var reasonCode: String {
        switch self {
        case .invalidEnvelopeJSON:
            return "invalid_envelope_json"
        case .unsupportedSignatureVersion:
            return "unsupported_signature_version"
        case .unknownKeyId:
            return "unknown_key_id"
        case .reportEnvelope(let error):
            return "report_envelope.\(error.reasonCode)"
        }
    }
}
