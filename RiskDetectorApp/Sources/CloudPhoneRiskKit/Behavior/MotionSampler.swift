// CoreMotion 运动采样器：以 20Hz 读取去重力加速度，维护聚合指标（静止占比、平均能量）
// 与最近的样本序列，供触摸-运动耦合分析使用。无传感器或用户未授权时自动降级为空指标。
// 非 iOS 平台走文件末尾的空实现，保证调用方无需条件编译。
#if os(iOS)
import CoreMotion
import Foundation

/// 运动采样单例。
/// 线程模型：CoreMotion 回调在独立 OperationQueue 上执行，所有可变状态由 `UnfairLock` 保护；
/// 安全不变量：`stop()`/`clearSensitiveData()` 后原始样本被清零，不残留于内存。
final class MotionSampler {
    // 全局单例：采样开关由 SDK 生命周期统一控制，避免多处 start 造成重复回调。
    static let shared = MotionSampler()
    private init() {}

    private let manager = CMMotionManager()
    // 独立串行队列 + .utility：运动采样不能阻塞主线程，也不能与 UI 争抢算力。
    private let queue = OperationQueue()
    private let lock = UnfairLock()

    private var started = false
    // 聚合计数：样本数、静止数、能量累计，snapshot 时换算为比例/均值。
    private var sampleCount = 0
    private var stillCount = 0
    private var energySum = 0.0
    // 最近的运动序列，仅用于耦合分析；截断上限防止长时间运行内存增长。
    private var series: [MotionSample] = []
    private let seriesMax = 3600

    // 同一窗口内重复取快照时复用结果，避免下游 5 秒内多次评估把序列反复清零。
    private let minSnapshotInterval: TimeInterval = 5.0
    private var lastSnapshotTime: TimeInterval = 0
    private var cachedSnapshot: (metrics: MotionMetrics, series: [MotionSample])?

    /// 启动运动更新。幂等；已启动或无传感器时直接返回。
    func start() {
        // 在锁内完成“检查 + 置位”，保证并发调用 start 时只有一次真正注册回调。
        let shouldStart: Bool = lock.withLock {
            guard !started else { return false }
            started = true
            return true
        }
        // 模拟器或部分设备无 deviceMotion：静默降级，快照返回 .empty，由上层标记运动维度不可用。
        guard shouldStart, manager.isDeviceMotionAvailable else { return }
        // 20Hz 足以刻画手势节奏，同时明显低于 100Hz，兼顾功耗与热开销。
        manager.deviceMotionUpdateInterval = 1.0 / 20.0
        queue.qualityOfService = .utility

        // 弱引用 self：SDK 释放后回调自然失效，避免采样器被系统强持有。
        manager.startDeviceMotionUpdates(to: queue) { [weak self] motion, _ in
            guard let self, let motion else { return }
            self.consume(motion: motion)
        }
    }

    /// 停止采样并立即清零已收集的敏感样本。
    func stop() {
        lock.withLock {
            started = false
            zeroSensitiveBuffersLocked()
        }
        manager.stopDeviceMotionUpdates()
    }

    /// 读取当前聚合指标（不清零），用于观测/调试。
    func snapshot() -> MotionMetrics {
        lock.withLock {
            // 无样本时返回中性值，而不是把 0 当作有效运动能量。
            guard sampleCount > 0 else { return .empty }

            // 静止占比 = 静止样本数 / 总样本数；平均能量 = 能量累计 / 总样本数。
            let stillness = Double(stillCount) / Double(sampleCount)
            let energy = energySum / Double(sampleCount)
            let metrics = MotionMetrics(sampleCount: sampleCount, stillnessRatio: stillness, motionEnergy: energy)
            Logger.log("behavior.motion: samples=\(metrics.sampleCount) stillness=\(metrics.stillnessRatio?.description ?? "nil") energy=\(metrics.motionEnergy?.description ?? "nil")")
            return metrics
        }
    }

    /// 取指标并清零，供评估流程消费。
    func snapshotAndReset() -> MotionMetrics {
        snapshotDetailAndReset().metrics
    }

    /// 取指标与样本序列并清零。
    /// 序列用于与触摸时间戳做耦合分析，因此只在调用方需要时返回。
    func snapshotDetailAndReset() -> (metrics: MotionMetrics, series: [MotionSample]) {
        lock.withLock {
            let now = ProcessInfo.processInfo.systemUptime
            // 5 秒内的重复取数返回缓存：期间无新样本时清零会让耦合分析丢失整段序列。
            if now - lastSnapshotTime < minSnapshotInterval, let cached = cachedSnapshot, sampleCount == 0 {
                return cached
            }

            guard sampleCount > 0 else { return (.empty, []) }

            // 与 snapshot() 相同的口径：比例与均值。
            let stillness = Double(stillCount) / Double(sampleCount)
            let energy = energySum / Double(sampleCount)
            let metrics = MotionMetrics(sampleCount: sampleCount, stillnessRatio: stillness, motionEnergy: energy)
            Logger.log("behavior.motion(reset): samples=\(metrics.sampleCount) stillness=\(metrics.stillnessRatio?.description ?? "nil") energy=\(metrics.motionEnergy?.description ?? "nil")")

            // 先交出序列副本，再原地清空聚合状态；keepingCapacity 复用容量降低分配开销。
            let outSeries = series
            sampleCount = 0
            stillCount = 0
            energySum = 0
            series.removeAll(keepingCapacity: true)

            lastSnapshotTime = now
            let result = (metrics, outSeries)
            cachedSnapshot = result
            return result
        }
    }

    /// 隐私撤回/宿主登出时调用：不等待下一次 stop，主动清零。
    func clearSensitiveData() {
        lock.withLock { zeroSensitiveBuffersLocked() }
    }

    /// 调用方必须已持有 `lock`。
    /// 先用 memset 覆盖底层字节再释放，降低样本残留被内存转储读取的可能；
    /// 乘法溢出保护防止极端容量下计算出的字节数回绕导致越界写。
    private func zeroSensitiveBuffersLocked() {
        series.withUnsafeMutableBufferPointer { buf in
            guard let base = buf.baseAddress, buf.count > 0 else { return }
            let (byteCount, overflow) = buf.count.multipliedReportingOverflow(by: MemoryLayout<MotionSample>.stride)
            guard !overflow else { return }
            memset(base, 0, byteCount)
        }
        series.removeAll(keepingCapacity: false)
        sampleCount = 0
        stillCount = 0
        energySum = 0
        lastSnapshotTime = 0
        cachedSnapshot = nil
    }

    /// CoreMotion 回调：只保留能量模长与时间戳，不落盘原始三轴数据。
    private func consume(motion: CMDeviceMotion) {
        // userAcceleration 已去除重力分量，模长直接反映用户动作强度。
        let user = motion.userAcceleration
        let magnitude = sqrt(user.x * user.x + user.y * user.y + user.z * user.z)

        lock.withLock {
            // stop() 后仍可能收到在途回调，用 started 再拦一次，避免清零后又被写入。
            guard started else { return }
            sampleCount += 1
            energySum += magnitude
            // 0.02g 接近传感器噪声底，低于该值视为静止；阈值与静止占比语义绑定。
            if magnitude < 0.02 { stillCount += 1 }
            series.append(MotionSample(timestamp: motion.timestamp, energy: magnitude))
            // 环形裁剪最旧样本，保持序列长度上界（约 3 分钟 @20Hz）。
            if series.count > seriesMax {
                series.removeFirst(series.count - seriesMax)
            }
        }
    }
}

#else
import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
/// 非 iOS 平台降级实现：所有方法为空操作。
/// 保持与 iOS 版一致的 API，调用方无需条件编译；运动维度恒为 `empty`，行为分析自动只用触摸侧。
final class MotionSampler {
    static let shared = MotionSampler()
    private init() {}
    func start() {}
    func stop() {}
    func clearSensitiveData() {}
    func snapshot() -> MotionMetrics { .empty }
    func snapshotAndReset() -> MotionMetrics { .empty }
    func snapshotDetailAndReset() -> (metrics: MotionMetrics, series: [MotionSample]) { (.empty, []) }
}
#endif
