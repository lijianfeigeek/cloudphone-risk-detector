// 本地设备聚类检测器：在进程内观察同一关联键下指纹的变化频率。
// 位于本地评估的信号层，产出 `local_identity_churn` 软信号供评分使用。
// 重要边界：只观察本进程的安装身份变化，一台设备频繁变指纹不等于“多台设备”；
// 证据中不包含网络/账号键，跨设备聚合完全由服务端完成。
// 线程安全：所有缓存访问都在 `lock` 内，类标记为 @unchecked Sendable。

import Foundation

// 兼容类型名；只观察本进程的身份变化。
/// 单次安装的指纹变化不代表多台设备。
/// 证据中不输出网络/账号键；跨设备聚合仅在服务端进行。
public final class LocalDeviceClusterDetector: @unchecked Sendable {

    /// 全局共享实例。
    public static let shared = LocalDeviceClusterDetector()

    /// 同一 key 下不同指纹数量阈值
    public static let clusterThreshold = 5

    /// 时间窗口（秒）
    public static let timeWindowSeconds: TimeInterval = 300  // 5 分钟

    /// 保留最近 N 次评估
    private static let maxHistoryCount = 20

    /// 单条观察记录：指纹哈希 + 观察时间（epoch 秒）。
    private struct Entry: Sendable {
        let hwProfileHash: String
        let timestamp: TimeInterval
    }

    /// key: IP 或 sessionId，value: [(hwProfileHash, timestamp)]
    private var cache: [String: [Entry]] = [:]
    /// 保护 `cache` 的锁：评估线程与清理路径可能并发访问。
    private let lock = UnfairLock()

    /// 私有初始化，强制单例。
    private init() {}

    /// 记录一次评估，并检测是否触发 local_identity_churn
    /// - Parameters:
    ///   - hwProfileHash: 设备指纹哈希（GraphFeatureCollector 产出的 hwProfileHash）
    ///   - key: 关联键，优先使用 IP，否则 sessionId
    /// - Returns: 若触发则返回 RiskSignal，否则 nil
    /// 空 key 或空指纹直接返回 nil（不作为证据，也避免污染缓存）。
    public func recordAndDetect(
        hwProfileHash: String,
        key: String?
    ) -> RiskSignal? {
        guard let k = key, !k.isEmpty else { return nil }
        guard !hwProfileHash.isEmpty else { return nil }

        return lock.withLock {
            let now = Date().timeIntervalSince1970
            let cutoff = now - Self.timeWindowSeconds

            var entries = cache[k] ?? []
            entries.append(Entry(hwProfileHash: hwProfileHash, timestamp: now))

            // 清理过期
            entries = entries.filter { $0.timestamp > cutoff }

            // 限制历史长度
            if entries.count > Self.maxHistoryCount {
                entries = Array(entries.suffix(Self.maxHistoryCount))
            }

            cache[k] = entries

            // Evict stale keys to prevent unbounded memory growth
            // 只有当一个 key 的所有记录都过期时才整体淘汰；缓存超过 100 个 key 才触发扫描。
            if cache.count > 100 {
                let staleKeys = cache.filter { $0.value.allSatisfy { $0.timestamp <= cutoff } }.map(\.key)
                for key in staleKeys { cache.removeValue(forKey: key) }
            }

            let distinctHashes = Set(entries.map(\.hwProfileHash))
            // 达到阈值才出信号：低于阈值的变化可能只是正常重装/系统升级。
            if distinctHashes.count >= Self.clusterThreshold {
                return RiskSignal(
                    id: "local_identity_churn",
                    category: "device",
                    // 12 分为软信号，避免单凭本地指纹变化就阻断业务。
                    score: 12,
                    evidence: [
                        "scope": "local_installation",
                        "distinct_local_fingerprints": "\(distinctHashes.count)",
                        "window_seconds": "\(Int(Self.timeWindowSeconds))"
                    ],
                    // 置信度随不同指纹数线性上升，10 个封顶为 1.0。
                    state: .soft(confidence: min(1.0, Double(distinctHashes.count) / 10.0)),
                    layer: 4,
                    weightHint: 55
                )
            }

            return nil
        }
    }

    /// 清空缓存（如用户登出时调用，降低内存驻留）
    public func clear() {
        lock.withLock { cache.removeAll() }
    }
}
