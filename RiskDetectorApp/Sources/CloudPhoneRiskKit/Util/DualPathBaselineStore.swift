// 跨时间点基线存储：在 start() 时快照关键路径的 inode/dev/size，之后与实时 stat 对比。
// 用于发现“启动后才替换文件”的 late_tamper；未采集基线时（evaluate-only）自动跳过。

import Darwin
import Foundation

/// 跨时间点基线快照存储（参照 Frida map_gen 双阶段模型）
///
/// 在 CPRiskKit.start() 时对关键路径执行基线采集，记录 path + inode + st_dev + st_size。
/// 在 validateFileStat 流程中与基线对比，若 inode/st_dev 变化且基线采集时间早于当前超过 1 秒，
/// 则判定为 late_tamper（跨时间点篡改）。
///
/// - 基线采集使用 SVC 直调（cprisk_lstat_direct），与校验路径一致
/// - 存储使用 UnfairLock 保证线程安全
/// - 若 start() 未被调用（evaluate-only 路径），基线为空，跳过基线校验
public enum DualPathBaselineStore {
    // 保护 baselineByPath 与 hasCollected 的读改写；临界区只做字典访问，持锁时间极短。
    private static let lock = UnfairLock()

    /// 单条基线记录：path + inode + st_dev + st_size + 采集时间
    /// 只依赖 stat 结构中的稳定字段：三个值同时不变才认为文件未被替换。
    public struct BaselineEntry: Sendable {
        /// 被采集的绝对路径（作为字典键的冗余副本，便于调试）。
        public let path: String
        /// 文件系统 inode 号；替换文件通常会改变它。
        public let inode: UInt64
        /// 所在设备号；跨设备挂载/替换时会变化。
        public let stDev: UInt32
        /// 文件大小；作为 inode 复用场景下的辅助判据。
        public let stSize: Int64
        /// 采集时刻（Unix 秒），用于抑制启动初期的瞬时误报。
        public let timestamp: TimeInterval

        public init(path: String, inode: UInt64, stDev: UInt32, stSize: Int64, timestamp: TimeInterval) {
            self.path = path
            self.inode = inode
            self.stDev = stDev
            self.stSize = stSize
            self.timestamp = timestamp
        }
    }

    // 受 lock 保护；key 为绝对路径。
    private static var baselineByPath: [String: BaselineEntry] = [:]
    // 与 baselineByPath 在同一临界区内更新，避免出现“有数据但标记未完成”的中间态。
    private static var hasCollected = false

    /// 是否已执行过基线采集（start() 被调用后为 true）
    public static var hasBaseline: Bool {
        lock.withLock { hasCollected }
    }

    /// 对指定路径列表执行基线采集，使用 SVC 直调 cprisk_lstat_direct。
    /// 仅记录成功 stat 的路径；ENOENT/失败的不入库，校验时视为无基线可对比。
    public static func collectBaseline(paths: [String]) {
        let now = Date().timeIntervalSince1970
        var collected: [String: BaselineEntry] = [:]

        for path in paths {
            // 首次采集失败不做任何猜测：没有可信基线就不参与后续漂移判定。
            guard let detail = SVCDirectCall.secureLstatDetail(path: path) else { continue }
            collected[path] = BaselineEntry(
                path: path,
                inode: detail.inode,
                stDev: detail.stDev,
                stSize: detail.stSize,
                timestamp: now
            )
        }

        // Set hasCollected atomically with the data to prevent TOCTOU race
        // 同一临界区写入数据与完成标记，读者不会看到部分采集结果。
        lock.withLock {
            baselineByPath = collected
            hasCollected = true
        }

        #if DEBUG
        Logger.log("dual_path_baseline: collected \(collected.count) entries for \(paths.count) paths")
        #endif
    }

    /// 检查当前 stat 与基线是否发生漂移（inode/st_dev 变化）。
    /// 仅当基线采集时间早于当前超过 `minDriftIntervalSeconds` 秒时才判定为 drift，
    /// 避免启动后立即 evaluate 的瞬时差异误报。
    ///
    /// - Parameters:
    ///   - path: 路径
    ///   - currentInode: 当前 inode（来自 SVC 直调）
    ///   - currentStDev: 当前 st_dev
    ///   - minDriftIntervalSeconds: 最小时间间隔（秒），默认 1.0
    /// - Returns: 若检测到漂移返回 true，否则 false
    public static func checkForDrift(
        path: String,
        currentInode: UInt64,
        currentStDev: UInt32,
        minDriftIntervalSeconds: TimeInterval = 1.0
    ) -> Bool {
        let entry = lock.withLock { baselineByPath[path] }

        // 无基线记录说明该路径未在 start() 时采集，不能据此判恶。
        guard let entry else { return false }

        let now = Date().timeIntervalSince1970
        // 启动初期的文件访问可能触发页缓存/临时文件变化，等过了静默期再比较。
        guard (now - entry.timestamp) >= minDriftIntervalSeconds else { return false }

        // inode 或设备号任一变化都意味着“同名路径已指向不同文件”。
        if entry.inode != currentInode || entry.stDev != currentStDev {
            return true
        }
        return false
    }

    /// 判断指定路径是否有基线记录（用于短路逻辑）
    public static func hasBaseline(for path: String) -> Bool {
        lock.withLock { baselineByPath[path] != nil }
    }
}
