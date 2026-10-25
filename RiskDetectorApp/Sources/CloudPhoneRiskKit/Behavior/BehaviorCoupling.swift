// 触摸-运动耦合分析：把触摸动作时间戳与设备运动能量按秒级时间桶对齐，
// 计算二者的 Pearson 相关系数，用于区分真人操作与脚本注入、无传感器环境。
// 只输出一个 [-1, 1] 的统计量，不保留原始坐标或传感器序列。
import Foundation

/// 单条运动采样。
/// - `timestamp`: 设备单调时钟（秒），与 UITouch.timestamp 同源，便于对齐。
/// - `energy`: 去重力后的加速度模长，单位约等于 g，用于表征动作强度。
struct MotionSample: Sendable {
    var timestamp: TimeInterval
    var energy: Double
}

/// 触摸-运动耦合计算工具。
/// 无状态、纯函数，可在任意线程调用；不持有任何用户数据。
enum BehaviorCoupling {
    /// 计算触摸动作密度与运动能量在时间上的 Pearson 相关系数。
    ///
    /// 先按共同时间区间分桶，触摸侧统计每桶动作次数，运动侧统计每桶平均能量，
    /// 再对两条桶序列求相关。样本不足或任一侧无波动时返回 `nil`，由调用方按“不可用”降级。
    /// 结果写入 `BehaviorSignals.touchMotionCorrelation`，由 RiskScorer 在低相关且动作量足够时
    /// 转成 `RiskSignal(id: touchMotionWeakCoupling, category: behavior, score: 阈值分, state: nil)`。
    static func touchMotionCorrelation(actionTimestamps: [TimeInterval], motion: [MotionSample]) -> Double? {
        // 样本门槛：动作少于 6 次、运动少于 40 条时相关系数噪声过大，不予计算。
        guard actionTimestamps.count >= 6 else { return nil }
        guard motion.count >= 40 else { return nil }

        // 只取触摸与运动都有覆盖的交集区间，避免把无触摸时段的运动能量算进来稀释相关性。
        let start = max(actionTimestamps.min() ?? 0, motion.first?.timestamp ?? 0)
        let end = min(actionTimestamps.max() ?? 0, motion.last?.timestamp ?? 0)
        let span = end - start
        // 共同跨度不足 4 秒时桶数太少，相关结果没有统计意义。
        guard span >= 4 else { return nil }

        // 约每秒一个桶，并限制在 4–60 个：桶太少丢节奏，桶太多会让大量空桶干扰相关系数。
        let bucketCount = Int(min(60, max(4, floor(span))))
        guard bucketCount >= 4 else { return nil }

        // 触摸侧累计次数，运动侧先累计能量与条数再求均值，保证两侧量纲都是“每桶强度”。
        var touchBuckets = [Double](repeating: 0, count: bucketCount)
        var motionSum = [Double](repeating: 0, count: bucketCount)
        var motionCount = [Double](repeating: 0, count: bucketCount)

        /// 把时间戳归一化到 [0,1] 后映射到桶下标；p == 1 时钳到最后一桶，避免越界。
        func idx(_ t: TimeInterval) -> Int? {
            let p = (t - start) / span
            guard p >= 0, p <= 1 else { return nil }
            let i = p >= 1.0 ? bucketCount - 1 : Int(floor(p * Double(bucketCount)))
            return min(max(i, 0), bucketCount - 1)
        }

        for t in actionTimestamps {
            guard let i = idx(t) else { continue }
            touchBuckets[i] += 1
        }

        for s in motion {
            guard let i = idx(s.timestamp) else { continue }
            motionSum[i] += s.energy
            motionCount[i] += 1
        }

        // 空桶保持 0 值：无运动样本的时段同样代表“无耦合证据”，不能剔除，否则会抬高相关系数。
        var motionBuckets = [Double](repeating: 0, count: bucketCount)
        for i in 0..<bucketCount {
            if motionCount[i] > 0 { motionBuckets[i] = motionSum[i] / motionCount[i] }
        }

        return pearson(x: touchBuckets, y: motionBuckets)
    }

    /// 总体 Pearson 相关系数 `cov(x,y) / (σx·σy)`。
    /// 任一侧方差为 0（序列恒定）时相关系数无定义，返回 `nil` 而不是 0，避免被误读为“无相关”。
    private static func pearson(x: [Double], y: [Double]) -> Double? {
        guard x.count == y.count, x.count >= 4 else { return nil }
        let n = Double(x.count)
        let meanX = x.reduce(0, +) / n
        let meanY = y.reduce(0, +) / n
        var cov = 0.0
        var varX = 0.0
        var varY = 0.0
        for i in 0..<x.count {
            let dx = x[i] - meanX
            let dy = y[i] - meanY
            cov += dx * dy
            varX += dx * dx
            varY += dy * dy
        }
        guard varX > 0, varY > 0 else { return nil }
        return cov / sqrt(varX * varY)
    }
}

