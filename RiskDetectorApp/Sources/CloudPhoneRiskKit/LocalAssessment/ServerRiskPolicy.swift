// 服务端风控策略模型与缓存管理器：下发信号权重、处置阈值、覆盖名单、盲挑战与变异参数。
// PolicyManager 负责拉取、签名验证、加密持久化、HMAC 完整性校验与过期降级。
// 安全不变量：release 构建下只接受服务端验证过且未过期的缓存，校验失败宁可不加载。

import CryptoKit
import Foundation

/// 服务端下发的完整风险策略。
/// 客户端消费方式：权重影响计分，阈值决定动作，blocklist/patterns 直接覆盖，mutation 控制抖动与乱序。
public struct ServerRiskPolicy: Codable, Sendable {
    /// 策略版本号，服务端用于灰度与回溯。
    public let version: Int
    /// 信号 ID 到权重系数的映射，覆盖默认权重。
    public let signalWeights: [String: Double]
    /// 分数到处置动作的阈值（block/challenge/monitor）。
    public let thresholds: PolicyThresholds
    /// 新增云手机指纹模式，命中后可直接提升风险。
    public let newVPhonePatterns: [String]
    /// 设备/信号黑名单，命中后按 `blocklistAction` 处置。
    public let blocklist: [String]
    /// 变异配置（种子、乱序、阈值/分数抖动），驱动 MutationPlanner。
    public let mutation: MutationConfig?
    /// 盲挑战配置；nil 表示不启用。
    public let blindChallenge: BlindChallengeConfig?
    /// 密钥轮换策略（SDK 5.0）
    public let keyRotationPolicy: KeyRotationPolicy?

    /// Re-attestation 服务端 challenge 占位（SDK 5.0）
    /// 服务端下发后，客户端用 App Attest key 签名并上报，用于周期性 attestation 刷新
    public let reAttestationChallenge: Data?

    /// Enable Unix domain socket full-sweep detection (default: false).
    /// When enabled, UnixSocketSweepDetector enumerates all Unix sockets
    /// and checks for anomalous IPC channels that may indicate Frida.
    public let enableUnixSocketSweep: Bool?

    // 单字母键压缩下发体积，键名与协议绑定。
    private enum CodingKeys: String, CodingKey {
        case version = "v"
        case signalWeights = "sw"
        case thresholds = "th"
        case newVPhonePatterns = "vp"
        case blocklist = "bl"
        case mutation = "mu"
        case blindChallenge = "bc"
        case keyRotationPolicy = "kr"
        case reAttestationChallenge = "ra"
        case enableUnixSocketSweep = "us"
    }

    /// 分数阈值：达到 `block` 拒绝，达到 `challenge` 挑战，达到 `monitor` 仅监控。
    /// 语义上应满足 block > challenge > monitor。
    public struct PolicyThresholds: Codable, Sendable {
        /// 拒绝阈值（最高）。
        public let block: Double
        /// 挑战阈值。
        public let challenge: Double
        /// 监控阈值（最低），低于此值可放行。
        public let monitor: Double

        private enum CodingKeys: String, CodingKey {
            case block = "b"
            case challenge = "c"
            case monitor = "m"
        }

        public init(block: Double, challenge: Double, monitor: Double) {
            self.block = block
            self.challenge = challenge
            self.monitor = monitor
        }
    }

    /// 变异配置：由 MutationPlanner 消费，使攻击者难以预测判定边界与执行顺序。
    public struct MutationConfig: Codable, Sendable {
        /// 服务端控制的变形种子，建议每版本更新；与场景、设备 ID 共同派生随机流。
        public let seed: String
        /// 是否打乱检测顺序。
        public let shuffleChecks: Bool
        /// 阈值抖动范围（basis points），如 1200 代表 ±12%。
        public let thresholdJitterBps: Int
        /// 打分抖动范围（basis points）。
        public let scoreJitterBps: Int

        // 单字母键压缩下发体积。
        private enum CodingKeys: String, CodingKey {
            case seed = "s"
            case shuffleChecks = "sc"
            case thresholdJitterBps = "tj"
            case scoreJitterBps = "sj"
        }

        public init(
            seed: String,
            shuffleChecks: Bool = true,
            thresholdJitterBps: Int = 0,
            scoreJitterBps: Int = 0
        ) {
            self.seed = seed
            self.shuffleChecks = shuffleChecks
            self.thresholdJitterBps = thresholdJitterBps
            self.scoreJitterBps = scoreJitterBps
        }
    }

    /// 盲挑战配置：在不确定是否为攻击时，向客户端下发不可见探针以收集更多证据。
    public struct BlindChallengeConfig: Codable, Sendable {
        /// 总开关；false 时忽略其余字段。
        public let enabled: Bool
        /// challenge 签名盐，防止客户端伪造/重放。
        public let challengeSalt: String
        /// 触发窗口（秒），窗口内同一设备只发一次挑战，避免骚扰。
        public let windowSeconds: Int
        /// 现场 challenge 可选探针池（beta.4）
        public let probePool: [String]
        /// challenge 有效期（毫秒）
        public let challengeTTLMillis: Int64
        /// 触发盲挑战的规则集合。
        public let rules: [BlindRule]

        private enum CodingKeys: String, CodingKey {
            case enabled = "e"
            case challengeSalt = "cs"
            case windowSeconds = "ws"
            case probePool = "pp"
            case challengeTTLMillis = "ct"
            case rules = "r"
        }

        public init(
            enabled: Bool = true,
            challengeSalt: String,
            windowSeconds: Int = 300,
            probePool: [String] = [],
            challengeTTLMillis: Int64 = 300_000,
            rules: [BlindRule]
        ) {
            self.enabled = enabled
            self.challengeSalt = challengeSalt
            self.windowSeconds = windowSeconds
            self.probePool = probePool
            self.challengeTTLMillis = challengeTTLMillis
            self.rules = rules
        }
    }

    /// 单条盲挑战触发规则：满足全部条件才下发挑战。
    public struct BlindRule: Codable, Sendable {
        /// 仅用于服务端回溯，不下发到客户端日志。
        public let id: String
        /// 必须全部在场的信号 ID。
        public let allOfSignalIDs: [String]
        /// 至少命中一个即满足的信号 ID。
        public let anyOfSignalIDs: [String]
        /// 最少篡改信号数。
        public let minTamperedCount: Int
        /// 最少覆盖的不同风险层数，避免同层信号重复计数。
        public let minDistinctRiskLayers: Int
        /// 是否要求跨层结论互相矛盾（强攻击信号）。
        public let requireCrossLayerInconsistency: Bool
        /// 最小能力探针异常数（beta.2 新增）
        public let minCapabilityAnomalyCount: Int
        /// 规则权重，用于多规则加权决策。
        public let weight: Double

        // 单字母键压缩下发体积。
        private enum CodingKeys: String, CodingKey {
            case id = "i"
            case allOfSignalIDs = "ao"
            case anyOfSignalIDs = "ay"
            case minTamperedCount = "mt"
            case minDistinctRiskLayers = "ml"
            case requireCrossLayerInconsistency = "rc"
            case minCapabilityAnomalyCount = "mc"
            case weight = "w"
        }

        public init(
            id: String,
            allOfSignalIDs: [String] = [],
            anyOfSignalIDs: [String] = [],
            minTamperedCount: Int = 0,
            minDistinctRiskLayers: Int = 0,
            requireCrossLayerInconsistency: Bool = false,
            minCapabilityAnomalyCount: Int = 0,
            weight: Double = 75
        ) {
            self.id = id
            self.allOfSignalIDs = allOfSignalIDs
            self.anyOfSignalIDs = anyOfSignalIDs
            self.minTamperedCount = minTamperedCount
            self.minDistinctRiskLayers = minDistinctRiskLayers
            self.requireCrossLayerInconsistency = requireCrossLayerInconsistency
            self.minCapabilityAnomalyCount = minCapabilityAnomalyCount
            self.weight = weight
        }
    }

    public init(
        version: Int,
        signalWeights: [String: Double],
        thresholds: PolicyThresholds,
        newVPhonePatterns: [String] = [],
        blocklist: [String] = [],
        mutation: MutationConfig? = nil,
        blindChallenge: BlindChallengeConfig? = nil,
        keyRotationPolicy: KeyRotationPolicy? = nil,
        reAttestationChallenge: Data? = nil,
        enableUnixSocketSweep: Bool? = nil
    ) {
        self.version = version
        self.signalWeights = signalWeights
        self.thresholds = thresholds
        self.newVPhonePatterns = newVPhonePatterns
        self.blocklist = blocklist
        self.mutation = mutation
        self.blindChallenge = blindChallenge
        self.keyRotationPolicy = keyRotationPolicy
        self.reAttestationChallenge = reAttestationChallenge
        self.enableUnixSocketSweep = enableUnixSocketSweep
    }
}

// 存储：通过 SecureFileStore 写入沙箱文件，启用 NSFileProtectionComplete。
// 从 UserDefaults 迁移而来，确保设备锁定时数据在静态存储中仍被加密。
/// 服务端策略缓存管理器（单例）。
/// 线程模型：内部 NSLock 保护缓存的读写与文件 I/O；`@unchecked Sendable` 由该锁保证安全。
public final class PolicyManager: @unchecked Sendable {
    /// 全局共享实例；首次访问时会尝试恢复受信任缓存。
    public static let shared = PolicyManager()

    /// 持久化缓存条目：策略本体 + 缓存时间 + 服务端验证标记 + 内容哈希。
    private struct PolicyCacheEntry: Codable {
        let policy: ServerRiskPolicy
        /// 缓存写入时间（Unix 秒），用于过期判断。
        let cachedAt: TimeInterval
        /// 是否经过服务端签名验证；release 下未验证条目会被丢弃。
        let isVerifiedByServer: Bool
        /// 策略内容的 SHA-256，用于检测缓存被篡改或截断。
        let contentHash: String?

        // 单字母键压缩磁盘格式。
        private enum CodingKeys: String, CodingKey {
            case policy = "p"
            case cachedAt = "ca"
            case isVerifiedByServer = "iv"
            case contentHash = "ch"
        }

        init(
            policy: ServerRiskPolicy,
            cachedAt: TimeInterval,
            isVerifiedByServer: Bool,
            contentHash: String? = nil
        ) {
            self.policy = policy
            self.cachedAt = cachedAt
            self.isVerifiedByServer = isVerifiedByServer
            self.contentHash = contentHash ?? Self.computeContentHash(for: policy)
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            policy = try container.decode(ServerRiskPolicy.self, forKey: .policy)
            cachedAt = (try? container.decodeIfPresent(TimeInterval.self, forKey: .cachedAt))
                ?? Date.distantPast.timeIntervalSince1970
            isVerifiedByServer = (try? container.decodeIfPresent(Bool.self, forKey: .isVerifiedByServer)) ?? false
            contentHash = try? container.decodeIfPresent(String.self, forKey: .contentHash)
        }

        /// 计算策略内容哈希；排序键后编码，保证相同内容得到稳定哈希。
        fileprivate static func computeContentHash(for policy: ServerRiskPolicy) -> String? {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            guard let data = try? encoder.encode(policy) else { return nil }
            return SHA256.hash(data: data).compactMap { String(format: "%02x", $0) }.joined()
        }
    }

    private let lock = NSLock()  // NSLock: file I/O inside lock
    private var cachedPolicy: ServerRiskPolicy?
    private let cacheKey = "com.cloudphone.riskkit.policy.v3"
    private let hmacCacheKey = "com.cloudphone.riskkit.policy.v3_hmac"
    private let verifiedKey = "com.cloudphone.riskkit.policy.v3_verified_flag"
    private let hmacPurpose = "policy_cache"
    /// 缓存有效期 24 小时；过期策略不再参与决策，等待重新拉取。
    private let cacheValidityDuration: TimeInterval = 86_400
    private let fileStore = SecureFileStore.shared
    private var urlSession: URLSession

    /// 私有初始化：建立强制 pinning 的会话并尝试恢复受信任缓存。
    private init() {
        // 所有 TLS 会话都走 pinning，失败硬拒绝：无 pin 时挑战直接被取消、
        // 策略拉取失败并回落本地缓存策略，绝不回落系统 CA。
        // DEBUG 下亦然——需在拉取前调用 configurePinning(hashes:) 配置 pin。
        self.urlSession = CertificatePinningSessionDelegate.pinnedSession(
            pinMaterial: CPRiskKit.pinnedCertificatePinMaterial,
            allowsSystemCA: false
        )
        self.cachedPolicy = loadFromCache()
    }

    /// 配置证书 pin；传入空 pin 会被拒绝并保留旧会话，避免意外退化为系统 CA。
    public func configurePinning(pinMaterial: PinnedCertificatePinMaterial) {
        lock.withLock {
            guard !pinMaterial.isEmpty else {
                Logger.log("PolicyManager.configurePinning: empty hashes provided — all TLS connections would fail")
                Logger.log("PolicyManager.configurePinning: refusing to configure pinning with empty hashes — retaining previous session")
                return
            }
            urlSession.invalidateAndCancel()
            urlSession = CertificatePinningSessionDelegate.pinnedSession(
                pinMaterial: pinMaterial,
                allowsSystemCA: false
            )
        }
    }

    /// 用 pin 字符串集合构建摘要材料（非法条目会被忽略）。
    public func configurePinning(hashes: Set<String>) {
        configurePinning(pinMaterial: PinnedCertificatePinMaterial(pinStrings: hashes))
    }

    /// 当前生效策略；无缓存或缓存不可信时为 nil。
    public var activePolicy: ServerRiskPolicy? {
        lock.withLock { cachedPolicy }
    }

    /// 更新策略并持久化；默认标记为“未经服务端验证”。
    public func update(policy: ServerRiskPolicy) {
        update(policy: policy, verifiedByServer: false)
    }

    /// 重新从磁盘加载受信任缓存并替换内存状态（用于启动后/配置变更后同步）。
    public func reloadTrustedCacheState() {
        let restored = loadFromCache()
        lock.withLock { cachedPolicy = restored }
    }

    /// 彻底清除内存与磁盘缓存（含 HMAC 与验证标记）。
    public func clear() {
        lock.withLock {
            cachedPolicy = nil
            fileStore.remove(key: cacheKey)
            fileStore.remove(key: hmacCacheKey)
            fileStore.remove(key: verifiedKey)
        }
    }

    /// 仅清空内存中的策略缓存（challengeSalt、mutation.seed、blocklist 等敏感数据），
    /// 不删除持久化存储。用于登出等场景，缩短敏感数据在内存中的驻留时间。
    /// **调用方应在用户登出时调用本方法或 `clear()`。**
    public func clearCachedPolicy() {
        lock.withLock { cachedPolicy = nil }
    }

    /// 从 JSON 文本直接更新策略；仅 DEBUG 允许，release 返回 false。
    @discardableResult
    public func update(fromJSON json: String) -> Bool {
#if DEBUG
        guard let data = json.data(using: .utf8) else { return false }
        guard let decoded = try? JSONDecoder().decode(ServerRiskPolicy.self, from: data) else {
            return false
        }
        update(policy: decoded)
        return true
#else
        Logger.log("PolicyManager.update(fromJSON:) rejected: not allowed in release build")
        return false
#endif
    }

    /// 从服务端拉取并验证策略。
    /// 流程：pinned TLS 请求 -> 读取 `X-Policy-Signature` -> 验签 -> 解码 -> 持久化。
    /// - Throws: 网络错误、缺少/非法签名、JSON 解码失败。验签失败绝不写入缓存。
    @available(iOS 13.0, macOS 10.15, *)
    public func fetchLatestPolicy(from url: URL) async throws -> ServerRiskPolicy {
        let session = currentURLSession()
        let (data, response) = try await session.data(from: url)

        // 签名放在响应头，缺失时按空串处理，必然验签失败（失败即拒绝）。
        let signatureHex = (response as? HTTPURLResponse)?
            .value(forHTTPHeaderField: "X-Policy-Signature") ?? ""
        let verification = ConfigSignatureVerifier.verify(payload: data, signatureHex: signatureHex)
        if !verification.isValid {
            throw ConfigError.signatureVerificationFailed(reason: verification.reason ?? "unknown")
        }

        let policy = try JSONDecoder().decode(ServerRiskPolicy.self, from: data)
        // 只有签名器已配置且验签通过时才标记为服务端可信，供后续缓存恢复使用。
        update(policy: policy, verifiedByServer: ConfigSignatureVerifier.isConfigured && verification.isValid)
        return policy
    }

    /// 线程安全地取出当前 URLSession（configurePinning 可能并发替换它）。
    private func currentURLSession() -> URLSession {
        lock.withLock { urlSession }
    }

    /// 在锁内原子更新内存策略并持久化，避免读到半更新状态。
    private func update(policy: ServerRiskPolicy, verifiedByServer: Bool) {
        lock.withLock {
            cachedPolicy = policy
            persist(policy: policy, verifiedByServer: verifiedByServer)
        }
    }

    /// 加密并写入缓存：密文 + HMAC 签名 + 验证标记三份数据分开存储。
    /// release 下加密失败则直接放弃写入，绝不明文落盘。
    private func persist(policy: ServerRiskPolicy, verifiedByServer: Bool) {
        let entry = PolicyCacheEntry(
            policy: policy,
            cachedAt: Date().timeIntervalSince1970,
            isVerifiedByServer: verifiedByServer
        )
        guard let encoded = try? JSONEncoder().encode(entry) else { return }
        #if DEBUG
        let stored = (try? PayloadCrypto.encrypt(encoded)) ?? encoded
        #else
        guard let stored = try? PayloadCrypto.encrypt(encoded) else {
            Logger.log("PolicyManager: encrypt failed, skipping save in release build")
            return
        }
        #endif
        fileStore.write(key: cacheKey, data: stored)
        // HMAC 绑定密文，防止磁盘上的策略被替换后仍能解密使用。
        fileStore.write(key: hmacCacheKey, data: StorageIntegrityGuard.sign(stored, purpose: hmacPurpose))
        fileStore.write(key: verifiedKey, data: Data(verifiedByServer ? [1] : [0]))
    }

    /// 从磁盘恢复策略，依次校验验证标记、HMAC、解密、内容哈希与有效期。
    /// 任一环节失败都返回 nil 并清理对应缓存（fail-closed）。
    private func loadFromCache() -> ServerRiskPolicy? {
        #if !DEBUG
        // release：未经过服务端验证的缓存一律不加载。
        let wasVerified = (fileStore.read(key: verifiedKey)?.first ?? 0) != 0
        if !wasVerified {
            Logger.log("PolicyManager.loadFromCache: skipping unverified cache in release build")
            return nil
        }
        #endif
        guard let stored = fileStore.read(key: cacheKey) else { return nil }
        // HMAC 不匹配说明缓存被篡改或损坏，删除后等待重新拉取。
        guard let signature = fileStore.read(key: hmacCacheKey),
              StorageIntegrityGuard.verify(stored, signature: signature, purpose: hmacPurpose) else {
            fileStore.remove(key: cacheKey)
            fileStore.remove(key: hmacCacheKey)
            return nil
        }
        #if DEBUG
        let data: Data
        if let decrypted = try? PayloadCrypto.decrypt(stored) {
            data = decrypted
        } else {
            data = stored
        }
        #else
        guard let data = try? PayloadCrypto.decrypt(stored) else {
            Logger.log("PolicyManager: decrypt failed, clearing cache in release build")
            fileStore.remove(key: cacheKey)
            fileStore.remove(key: hmacCacheKey)
            return nil
        }
        #endif
        // 兼容旧格式：早期缓存直接存 ServerRiskPolicy，没有缓存元数据。
        let entry = (try? JSONDecoder().decode(PolicyCacheEntry.self, from: data))
            ?? ((try? JSONDecoder().decode(ServerRiskPolicy.self, from: data)).map {
                PolicyCacheEntry(
                    policy: $0,
                    cachedAt: Date.distantPast.timeIntervalSince1970,
                    isVerifiedByServer: false,
                    contentHash: nil
                )
            })
        guard let entry, isUsableTrustedEntry(entry) else { return nil }
        return entry.policy
    }

    /// 判断缓存条目是否可用：内容哈希一致 + （release）已配置签名器、已验证、未过期。
    private func isUsableTrustedEntry(_ entry: PolicyCacheEntry) -> Bool {
        // 内容哈希不一致说明策略字段被改动，release 下拒绝；debug 下放行以便调试。
        guard entry.contentHash == PolicyCacheEntry.computeContentHash(for: entry.policy) else {
#if DEBUG
            Logger.log("PolicyManager: content hash missing or mismatch, allowing cache only in debug")
            return true
#else
            Logger.log("PolicyManager: rejecting cache entry due to missing or mismatched content hash")
            return false
#endif
        }

        let age = Date().timeIntervalSince1970 - entry.cachedAt
#if DEBUG
        if age > cacheValidityDuration {
            Logger.log("PolicyManager: stale cache entry restored in debug, age=\(Int(age))s")
        }
        return true
#else
        // 没有配置签名公钥就无法验证来源，宁可不用缓存。
        guard ConfigSignatureVerifier.isConfigured else {
            Logger.log("PolicyManager: rejecting cache entry because signing key is not configured")
            return false
        }
        // 未经服务端签名验证的条目不可信。
        guard entry.isVerifiedByServer else {
            Logger.log("PolicyManager: rejecting unverified cache entry version=\(entry.policy.version)")
            return false
        }
        // 超过 24 小时的策略视为过期，避免长期沿用旧阈值/黑名单。
        guard age <= cacheValidityDuration else {
            Logger.log("PolicyManager: rejecting stale cache entry version=\(entry.policy.version)")
            return false
        }
        return true
#endif
    }
}
