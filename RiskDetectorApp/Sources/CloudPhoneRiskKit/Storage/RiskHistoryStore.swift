// 文件职责：风险历史事件的内存 + 加密文件存储，以及 24 小时时序模式分析。
// 管道位置：每次本地判决后追加事件，供后续评估读取历史行为模式。
// 安全不变量：落盘数据 AES-GCM 加密 + HMAC 完整性校验 + Keychain 新鲜度锚点；
// 任一校验失败即清空缓存并 fail-closed，不信任被篡改的历史。
import Foundation

/// 单条风险历史事件。
public struct RiskHistoryEvent: Codable, Sendable {
    /// 事件时间戳（Unix 秒）。
    var t: TimeInterval
    /// 当时的风险分。
    var score: Double
    /// 当时是否判定为高风险。
    var isHighRisk: Bool
    /// 简短摘要（用于展示与诊断）。
    var summary: String

    // 短键压缩上报/落盘体积。
    private enum CodingKeys: String, CodingKey {
        case t = "t"
        case score = "s"
        case isHighRisk = "hr"
        case summary = "sm"
    }
}

/// 24 小时窗口内的时序模式统计。
public struct TimePattern: Codable, Sendable {
    /// 窗口内事件总数。
    public var events24h: Int
    /// 窗口内出现过事件的独立小时数。
    public var uniqueHours24h: Int
    /// 夜间（0–5 点）事件占比；无事件时为 nil。
    public var nightRatio24h: Double?
    /// 相邻事件平均间隔（秒）；少于两条时为 nil。
    public var averageIntervalSeconds24h: Double?

    // 短键压缩上报体积。
    private enum CodingKeys: String, CodingKey {
        case events24h = "e"
        case uniqueHours24h = "uh"
        case nightRatio24h = "nr"
        case averageIntervalSeconds24h = "ai"
    }
}

// 存储：通过 SecureFileStore 写入沙箱文件并启用 NSFileProtectionComplete。
// 从 UserDefaults 迁移而来，确保设备锁屏时数据仍处于加密状态。
/// 风险历史存储单例；所有读写经内部锁串行化。
public final class RiskHistoryStore {
    public static let shared = RiskHistoryStore()

    /// 落盘信封：事件数组 + schema 版本 + 新鲜度字段。
    private struct StoredEnvelope: Codable {
        /// 信封结构版本，用于未来迁移。
        var schemaVersion: Int
        /// 历史事件列表。
        var events: [RiskHistoryEvent]
        /// 已见最大事件时间戳。
        var latestTimestamp: Double
        /// 单调递增序列号，用于防回放。
        var sequence: UInt64

        // 短键压缩落盘体积。
        private enum CodingKeys: String, CodingKey {
            case schemaVersion = "sv"
            case events = "ev"
            case latestTimestamp = "lt"
            case sequence = "sq"
        }
    }

    /// 加载后的内存状态：事件与新鲜度。
    private struct LoadedState {
        var events: [RiskHistoryEvent]
        var freshness: FreshnessState
    }

    /// 保护文件读写与内存状态的互斥锁。
    private let lock = UnfairLock()
    /// 底层安全文件存储。
    private let fileStore: SecureFileStore
    /// 加密载荷的文件 key。
    private let key = "cloudphone_risk_history_v1"
    /// HMAC 签名单独存放的 key。
    private let hmacKey = "cloudphone_risk_history_v1_hmac"
    /// 签名域分隔标识，防止与其他业务的签名互相移植。
    private let hmacPurpose = "risk_history"
    /// Keychain 新鲜度锚点：检测文件回滚/重放。
    private let freshnessAnchor = FreshnessAnchor(account: "risk_history_v2_freshness")
    /// 内存/落盘保留的最大事件数。
    private let maxEvents = 200
    /// 事件最长保留时间（7 天）。
    private let maxAgeSeconds: TimeInterval = 7 * 24 * 3600

    /// 时序模式分析的时间窗口（24 小时）
    private static let patternWindowSeconds: TimeInterval = 24 * 3600
    /// 夜间时段起始小时（含）
    private static let nightHoursStart = 0
    /// 夜间时段结束小时（含）
    private static let nightHoursEnd = 5
    /// 时钟回拨容忍阈值（秒）
    private static let clockRollbackToleranceSeconds: TimeInterval = 60

    /// 默认构造：复用共享 SecureFileStore。
    public init() {
        self.fileStore = .shared
    }

    /// 测试用构造，可注入 SecureFileStore。
    init(fileStore: SecureFileStore) {
        self.fileStore = fileStore
    }

    /// 追加事件：加载 → 追加 → 裁剪 → 原子保存。
    /// - Parameter event: 待追加的历史事件。
    public func append(_ event: RiskHistoryEvent) {
        lock.withLock {
            var state = loadStateLocked()
            state.events.append(event)
            state.events = pruneLocked(state.events)
            saveLocked(state)
        }
    }

    /// 计算最近 24 小时的时序模式（事件数、活跃小时、夜间占比、平均间隔）。
    /// - Parameter now: 计算基准时间（Unix 秒）。
    /// - Returns: 时序统计；窗口内无事件时相关字段为 0/nil。
    public func pattern(now: TimeInterval = Date().timeIntervalSince1970) -> TimePattern {
        let events = lock.withLock { loadStateLocked().events }

        // 先按窗口过滤并按时间升序，后续统计依赖有序序列。
        let windowStart = now - Self.patternWindowSeconds
        let recent = events.filter { $0.t >= windowStart && $0.t <= now }.sorted { $0.t < $1.t }
        let events24h = recent.count

        var hours = Set<Int>()
        var nightCount = 0
        var intervals: [Double] = []

        let cal = Calendar(identifier: .gregorian)
        for e in recent {
            let date = Date(timeIntervalSince1970: e.t)
            let hour = cal.component(.hour, from: date)
            hours.insert(hour)
            if hour >= Self.nightHoursStart && hour <= Self.nightHoursEnd { nightCount += 1 }
        }

        // 至少两条事件才能计算相邻间隔。
        if recent.count >= 2 {
            for (a, b) in zip(recent.dropFirst(), recent) {
                let dt = a.t - b.t
                if dt > 0 { intervals.append(dt) }
            }
        }

        let nightRatio = events24h > 0 ? (Double(nightCount) / Double(events24h)) : nil
        let avgInterval = intervals.isEmpty ? nil : (intervals.reduce(0, +) / Double(intervals.count))

        return TimePattern(
            events24h: events24h,
            uniqueHours24h: hours.count,
            nightRatio24h: nightRatio,
            averageIntervalSeconds24h: avgInterval
        )
    }

    /// 加载并校验状态（调用方必须持有 `lock`）。
    /// - 任一完整性校验失败都会清空持久化数据并返回空状态（fail-closed）。
    /// - Returns: 事件列表与合并后的新鲜度。
    private func loadStateLocked() -> LoadedState {
        let anchor = freshnessAnchor.read() ?? .zero
        guard let stored = fileStore.read(key: key) else {
            return LoadedState(events: [], freshness: anchor)
        }
        // HMAC 缺失或不匹配：数据不可信，清空缓存（保留锚点）后按空状态启动。
        guard let signature = fileStore.read(key: hmacKey),
              StorageIntegrityGuard.verify(stored, signature: signature, purpose: hmacPurpose) else {
            clearPersistedDataLocked(resetAnchor: false)
            return LoadedState(events: [], freshness: anchor)
        }
        // 调试构建允许解密失败时回退明文，便于本地排查。
        #if DEBUG
        let data: Data
        if let decrypted = try? PayloadCrypto.decrypt(stored) {
            data = decrypted
        } else {
            data = stored
        }
        #else
        // Release 构建解密失败即视为数据被破坏，清空缓存。
        guard let data = try? PayloadCrypto.decrypt(stored) else {
            Logger.log("RiskHistoryStore: decrypt failed, clearing cache in release build")
            clearPersistedDataLocked(resetAnchor: false)
            return LoadedState(events: [], freshness: anchor)
        }
        #endif

        let decodedState: LoadedState?
        if let envelope = try? JSONDecoder().decode(StoredEnvelope.self, from: data) {
            decodedState = LoadedState(
                events: envelope.events,
                freshness: FreshnessState(
                    latestTimestamp: envelope.latestTimestamp,
                    sequence: envelope.sequence
                )
            )
        // 兼容旧版直接存事件数组的格式。
        } else if let legacyEvents = try? JSONDecoder().decode([RiskHistoryEvent].self, from: data) {
            decodedState = LoadedState(
                events: legacyEvents,
                freshness: FreshnessState(
                    latestTimestamp: legacyEvents.map(\.t).max() ?? 0,
                    sequence: 0
                )
            )
        } else {
            clearPersistedDataLocked(resetAnchor: false)
            return LoadedState(events: [], freshness: anchor)
        }

        var state = decodedState ?? LoadedState(events: [], freshness: anchor)
        state.events = pruneLocked(state.events)

        // 防时钟回拨/回放攻击：最新事件时间戳不允许超过当前时间 60s。
        let wallNow = Date().timeIntervalSince1970
        if let newest = state.events.max(by: { $0.t < $1.t }), newest.t > wallNow + Self.clockRollbackToleranceSeconds {
            Logger.log("RiskHistoryStore: future timestamp detected (newest=\(newest.t) now=\(wallNow)), possible replay/clock attack, clearing cache")
            clearPersistedDataLocked(resetAnchor: false)
            return LoadedState(events: [], freshness: anchor)
        }

        // 文件中的新鲜度落后于 Keychain 锚点，说明文件被回滚或替换。
        if state.freshness.sequence < anchor.sequence || state.freshness.latestTimestamp < anchor.latestTimestamp {
            Logger.log("RiskHistoryStore: freshness rollback detected")
            clearPersistedDataLocked(resetAnchor: false)
            return LoadedState(events: [], freshness: anchor)
        }

        // 合并且只增不减，并把更“新”的状态写回锚点。
        let merged = maxFreshness(anchor, state.freshness)
        if merged.sequence > anchor.sequence || merged.latestTimestamp > anchor.latestTimestamp {
            _ = freshnessAnchor.write(merged)
        }

        return LoadedState(events: state.events, freshness: merged)
    }

    /// 加密、签名并原子保存状态（调用方必须持有 `lock`）。
    /// - 加密或任一文件写入失败都会清空持久化数据（fail-closed）。
    private func saveLocked(_ state: LoadedState) {
        if state.events.isEmpty {
            clearPersistedDataLocked(resetAnchor: true)
            return
        }

        let anchor = freshnessAnchor.read() ?? .zero
        let maxEventTimestamp = state.events.map(\.t).max() ?? 0
        // 序列号在锚点与内存状态的较大值上 +1，保证严格单调。
        let freshness = FreshnessState(
            latestTimestamp: max(maxEventTimestamp, max(anchor.latestTimestamp, state.freshness.latestTimestamp)),
            sequence: max(anchor.sequence, state.freshness.sequence) + 1
        )
        let envelope = StoredEnvelope(
            schemaVersion: 2,
            events: state.events,
            latestTimestamp: freshness.latestTimestamp,
            sequence: freshness.sequence
        )
        let encoded: Data
        do {
            encoded = try JSONEncoder().encode(envelope)
        } catch {
            Logger.log("RiskHistoryStore: JSON encode failed - \(error.localizedDescription)")
            return
        }
        #if DEBUG
        // 调试构建加密失败时允许明文落盘。
        let stored = (try? PayloadCrypto.encrypt(encoded)) ?? encoded
        #else
        // Release 构建必须加密成功，否则放弃本次保存。
        guard let stored = try? PayloadCrypto.encrypt(encoded) else {
            Logger.log("RiskHistoryStore: encrypt failed, skipping save in release build")
            return
        }
        #endif
        // 对密文做 HMAC，读取时先验签再解密。
        let signature = StorageIntegrityGuard.sign(stored, purpose: hmacPurpose)
        let didWritePayload = fileStore.write(key: key, data: stored)
        let didWriteSignature = fileStore.write(key: hmacKey, data: signature)
        // 载荷与签名必须同时写入成功；否则清空，避免留下不一致状态。
        guard didWritePayload && didWriteSignature else {
            Logger.log("RiskHistoryStore: failed to persist encrypted history atomically")
            clearPersistedDataLocked(resetAnchor: false)
            return
        }

        // 锚点写失败在 Release 下也视为不可信：清空缓存。
        guard freshnessAnchor.write(freshness) else {
            Logger.log("RiskHistoryStore: failed to update freshness anchor")
            if BuildConfig.isRelease {
                clearPersistedDataLocked(resetAnchor: false)
            }
            return
        }
    }

    /// 删除过期事件，并只保留最新 `maxEvents` 条。
    private func pruneLocked(_ events: [RiskHistoryEvent]) -> [RiskHistoryEvent] {
        let now = Date().timeIntervalSince1970
        let minT = now - maxAgeSeconds
        var out = events.filter { $0.t >= minT }
        if out.count > maxEvents {
            out = Array(out.suffix(maxEvents))
        }
        return out
    }

    /// 删除载荷与签名；`resetAnchor` 为真时同时删除 Keychain 锚点。
    private func clearPersistedDataLocked(resetAnchor: Bool) {
        fileStore.remove(key: key)
        fileStore.remove(key: hmacKey)
        if resetAnchor {
            freshnessAnchor.remove()
        }
    }

    /// 取两个新鲜度状态在各字段上的较大值。
    private func maxFreshness(_ lhs: FreshnessState, _ rhs: FreshnessState) -> FreshnessState {
        FreshnessState(
            latestTimestamp: max(lhs.latestTimestamp, rhs.latestTimestamp),
            sequence: max(lhs.sequence, rhs.sequence)
        )
    }
}
