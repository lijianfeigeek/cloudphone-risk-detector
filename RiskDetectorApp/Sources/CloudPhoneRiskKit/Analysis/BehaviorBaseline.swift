// 行为基线：用 DeviceHistory 中的历史 BehaviorSummary 为每台设备建立统计基线
// （操作量、点击/滑动次数与比例、触摸-运动相关性），再用 Z-score 衡量当前行为偏离程度。
// 基线只保存聚合统计量，原始触摸/运动样本在采集层已清零，不进入持久化。
import Foundation

// MARK: - 统计特征
/// 一组历史样本的集中趋势与离散程度，是基线比较的计算单元。
/// 不可变语义：实例生成后由使用方按需只读，避免并发修改。
public struct StatisticalFeatures: Codable, Sendable {
    /// 算术均值
    public var mean: Double
    /// 中位数（对极端值不敏感）
    public var median: Double
    /// 标准差（总体标准差，分母 n）
    public var stdDev: Double
    /// 方差（分母 n）
    public var variance: Double
    /// 最小值
    public var min: Double
    /// 最大值
    public var max: Double
    /// 25 分位数（线性插值）
    public var percentile25: Double
    /// 75 分位数（线性插值）
    public var percentile75: Double
    /// 四分位距 = p75 - p25
    public var iqr: Double
    /// 变异系数 = 标准差 / 均值；均值非正时为 0
    public var coefficientOfVariation: Double
    /// 样本数量
    public var count: Int

    // 短键名压缩持久化体积。
    private enum CodingKeys: String, CodingKey {
        case mean = "mn"
        case median = "md"
        case stdDev = "sd"
        case variance = "vr"
        case min = "mi"
        case max = "mx"
        case percentile25 = "p2"
        case percentile75 = "p7"
        case iqr = "iq"
        case coefficientOfVariation = "cv"
        case count = "c"
    }

    public init(
        mean: Double,
        median: Double,
        stdDev: Double,
        variance: Double,
        min: Double,
        max: Double,
        percentile25: Double,
        percentile75: Double,
        iqr: Double,
        coefficientOfVariation: Double,
        count: Int
    ) {
        self.mean = mean
        self.median = median
        self.stdDev = stdDev
        self.variance = variance
        self.min = min
        self.max = max
        self.percentile25 = percentile25
        self.percentile75 = percentile75
        self.iqr = iqr
        self.coefficientOfVariation = coefficientOfVariation
        self.count = count
    }

    /// 从数组计算统计特征。
    /// - Parameter values: 同一维度（如每次评估的操作数）的历史观测值
    /// - Returns: 空数组返回 nil，由调用方决定是否建立基线
    public static func from(_ values: [Double]) -> StatisticalFeatures? {
        guard !values.isEmpty else { return nil }

        let sorted = values.sorted()
        let count = Double(values.count)

        let sum = values.reduce(0, +)
        let mean = sum / count

        // 使用总体方差（分母 n）：这里描述的是已观测序列本身的离散度，而不是抽样估计。
        let variance = values.map { pow($0 - mean, 2) }.reduce(0, +) / count
        let stdDev = sqrt(variance)

        let min = sorted.first ?? 0
        let max = sorted.last ?? 0

        // 分位数采用线性插值，与 AnomalyDetector、TemporalAnalyzer 的口径保持一致。
        let median = percentile(sorted: sorted, p: 50)
        let p25 = percentile(sorted: sorted, p: 25)
        let p75 = percentile(sorted: sorted, p: 75)

        let iqr = p75 - p25
        // 均值非正时 CV 无意义（可能除以 0 或符号反常），置 0 表示不提供该维度信息。
        let cv = mean > 0 ? stdDev / mean : 0

        return StatisticalFeatures(
            mean: mean,
            median: median,
            stdDev: stdDev,
            variance: variance,
            min: min,
            max: max,
            percentile25: p25,
            percentile75: p75,
            iqr: iqr,
            coefficientOfVariation: cv,
            count: values.count
        )
    }

    /// 线性插值分位数（p 取 0...100）。
    /// 下标公式 `p/100 * n - 0.5` 与 numpy percentile(method="linear") 一致；
    /// 边界钳制避免 p=0/100 时越界。
    private static func percentile(sorted: [Double], p: Double) -> Double {
        guard !sorted.isEmpty else { return 0 }
        let count = Double(sorted.count)
        let index = Swift.max(0, Swift.min(((p / 100.0) * count) - 0.5, count - 1))
        let lower = Int(floor(index))
        let upper = Int(ceil(index))
        guard lower >= 0, upper < sorted.count else {
            return sorted[Swift.max(0, Swift.min(lower, sorted.count - 1))]
        }

        if lower == upper {
            return sorted[lower]
        }

        let weight = index - Double(lower)
        return sorted[lower] * (1 - weight) + sorted[upper] * weight
    }
}

// MARK: - 行为基线
/// 设备行为的历史基线。
/// 各维度均以 `StatisticalFeatures` 保存，比较器据此计算 Z-score；
/// 相关性维度可能缺失（设备无运动传感器或未授权），此时为 nil 并跳过该维度。
public struct BehaviorBaseline: Codable, Sendable {
    /// 基线首次建立时间（最早历史快照时间）
    public var createdAt: TimeInterval
    /// 基线最近构建时间，用于缓存过期判断
    public var updatedAt: TimeInterval
    /// 每次评估的动作总数分布
    public var actionCountStats: StatisticalFeatures
    /// 点击次数分布
    public var tapCountStats: StatisticalFeatures
    /// 滑动次数分布
    public var swipeCountStats: StatisticalFeatures
    /// 点击占比（tap / (tap+swipe)）分布
    public var tapSwipeRatioStats: StatisticalFeatures
    /// 触摸-运动相关性分布；无运动样本时为 nil
    public var touchMotionCorrelationStats: StatisticalFeatures?
    /// 参与基线构建的行为摘要样本数
    public var sampleCount: Int

    // 短键名压缩持久化体积。
    private enum CodingKeys: String, CodingKey {
        case createdAt = "ca"
        case updatedAt = "ua"
        case actionCountStats = "ac"
        case tapCountStats = "tc"
        case swipeCountStats = "sc"
        case tapSwipeRatioStats = "tr"
        case touchMotionCorrelationStats = "tm"
        case sampleCount = "sn"
    }

    public init(
        createdAt: TimeInterval,
        updatedAt: TimeInterval,
        actionCountStats: StatisticalFeatures,
        tapCountStats: StatisticalFeatures,
        swipeCountStats: StatisticalFeatures,
        tapSwipeRatioStats: StatisticalFeatures,
        touchMotionCorrelationStats: StatisticalFeatures?,
        sampleCount: Int
    ) {
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.actionCountStats = actionCountStats
        self.tapCountStats = tapCountStats
        self.swipeCountStats = swipeCountStats
        self.tapSwipeRatioStats = tapSwipeRatioStats
        self.touchMotionCorrelationStats = touchMotionCorrelationStats
        self.sampleCount = sampleCount
    }

    /// 空基线：`sampleCount == 0`，比较器会据此直接跳过，避免把“无历史”当成异常。
    public static func empty(at timestamp: TimeInterval = Date().timeIntervalSince1970) -> BehaviorBaseline {
        let emptyStats = StatisticalFeatures(
            mean: 0,
            median: 0,
            stdDev: 0,
            variance: 0,
            min: 0,
            max: 0,
            percentile25: 0,
            percentile75: 0,
            iqr: 0,
            coefficientOfVariation: 0,
            count: 0
        )

        return BehaviorBaseline(
            createdAt: timestamp,
            updatedAt: timestamp,
            actionCountStats: emptyStats,
            tapCountStats: emptyStats,
            swipeCountStats: emptyStats,
            tapSwipeRatioStats: emptyStats,
            touchMotionCorrelationStats: nil,
            sampleCount: 0
        )
    }
}

// MARK: - 行为基线构建器
/// 负责从历史数据构建和更新行为基线。
/// 线程模型：所有缓存读写都在 `UnfairLock` 内；内部方法以 `Locked` 后缀标注“调用方须持锁”。
public final class BehaviorBaselineBuilder {
    private let history: DeviceHistory
    private let lock = UnfairLock()

    /// 每台设备最近一次构建的基线缓存（deviceID → 基线）
    private var cachedBaselines: [String: BehaviorBaseline] = [:]

    /// 基线最大有效期（秒），默认 7 天：兼顾行为漂移与反复重建的成本
    private let baselineMaxAge: TimeInterval = 7 * 24 * 3600

    /// 最小样本数量，少于则不建立基线（统计量不可靠，宁可不判）
    private let minSampleCount = 5

    public init(history: DeviceHistory = .shared) {
        self.history = history
    }

    // MARK: - 获取/构建基线

    /// 获取设备的行为基线，如果不存在或过期则重新构建。
    /// - Parameter forceRebuild: 为 true 时忽略缓存，强制从历史快照重建
    public func getBaseline(for deviceID: String, forceRebuild: Bool = false) -> BehaviorBaseline {
        lock.withLock {
            getBaselineLocked(for: deviceID, forceRebuild: forceRebuild)
        }
    }

    /// 调用方必须已持有 `lock`，避免重入 `UnfairLock` 造成死锁。
    private func getBaselineLocked(for deviceID: String, forceRebuild: Bool = false) -> BehaviorBaseline {
        let now = Date().timeIntervalSince1970

        // 检查缓存：仅当未强制重建且未超过 7 天有效期时复用。
        if !forceRebuild, let cached = cachedBaselines[deviceID] {
            let age = now - cached.updatedAt
            if age < baselineMaxAge {
                return cached
            }
        }

        // 重新构建并回填缓存
        let rebuiltBaseline = buildBaseline(for: deviceID)
        cachedBaselines[deviceID] = rebuiltBaseline

        return rebuiltBaseline
    }

    /// 增量更新基线。
    /// 说明：当前实现仍从 DeviceHistory 全量重算，避免增量统计的舍入误差逐次累积；
    /// `newBehavior` 仅作为“有新样本”的触发信号，其内容本身不单独入账。
    public func updateBaseline(for deviceID: String, with newBehavior: BehaviorSignals) {
        lock.withLock {
            // 获取当前基线（复用已持有的锁，避免递归锁死）
            let currentBaseline = getBaselineLocked(for: deviceID)

            // 样本不足以维持基线时，直接按历史数据重建（可能仍为空基线）。
            guard currentBaseline.sampleCount >= minSampleCount else {
                cachedBaselines[deviceID] = buildBaseline(for: deviceID)
                return
            }

            // 全量重建：历史快照已包含最新一次检测，无需单独合并 newBehavior。
            let rebuiltBaseline = buildBaseline(for: deviceID)
            cachedBaselines[deviceID] = rebuiltBaseline
        }
    }

    /// 清除缓存的基线；传 nil 清空全部设备。
    public func clearCache(for deviceID: String? = nil) {
        lock.withLock {
            if let deviceID = deviceID {
                cachedBaselines.removeValue(forKey: deviceID)
            } else {
                cachedBaselines.removeAll()
            }
        }
    }

    // MARK: - 私有方法

    /// 从历史数据构建基线。
    /// 只消费 `BehaviorSummary`（聚合值），不访问任何原始触摸/运动数据。
    private func buildBaseline(for deviceID: String) -> BehaviorBaseline {
        let now = Date().timeIntervalSince1970

        let snapshots = history.getSnapshots(for: deviceID)
        let summaries = snapshots.compactMap { $0.behaviorSummary }

        // 少于 5 条行为摘要时统计量不可靠，返回空基线让比较器跳过，属于正常降级。
        guard summaries.count >= minSampleCount else {
            return BehaviorBaseline.empty(at: now)
        }

        // 提取各项指标
        let actionCounts = summaries.map { Double($0.actionCount) }
        let tapCounts = summaries.map { Double($0.tapCount) }
        let swipeCounts = summaries.map { Double($0.swipeCount) }

        // 计算点击-滑动比例；分母为 0（无动作）时取 0.5 中性值，避免除零并保持分布对称。
        let tapSwipeRatios = summaries.map { summary -> Double in
            guard summary.tapCount + summary.swipeCount > 0 else { return 0.5 }
            return Double(summary.tapCount) / Double(summary.tapCount + summary.swipeCount)
        }

        // 提取触摸-运动相关性；运动不可用时该数组为空，对应统计维度整体缺失。
        let correlations = summaries.compactMap { $0.touchMotionCorrelation }

        // 计算统计特征
        guard let actionStats = StatisticalFeatures.from(actionCounts),
              let tapStats = StatisticalFeatures.from(tapCounts),
              let swipeStats = StatisticalFeatures.from(swipeCounts),
              let ratioStats = StatisticalFeatures.from(tapSwipeRatios) else {
            return BehaviorBaseline.empty(at: now)
        }

        // 相关性样本为空时保持 nil，而不是伪造一组 0 值基线。
        let correlationStats = correlations.isEmpty ? nil : StatisticalFeatures.from(correlations)

        // 找出最早的记录时间：createdAt 代表设备首次进入本 SDK 视野的时间。
        let firstSeen = snapshots.map { $0.timestamp }.min() ?? now

        return BehaviorBaseline(
            createdAt: firstSeen,
            updatedAt: now,
            actionCountStats: actionStats,
            tapCountStats: tapStats,
            swipeCountStats: swipeStats,
            tapSwipeRatioStats: ratioStats,
            touchMotionCorrelationStats: correlationStats,
            sampleCount: summaries.count
        )
    }
}

// MARK: - 基线比较器
/// 单个行为指标相对基线的偏差结果。
/// `isAnomalous` 只在基线标准差可估计（>0）且 Z-score 超阈值时为 true。
public struct BaselineDeviation: Sendable {
    /// 偏差指标名称
    public var metricName: String

    /// 当前值
    public var currentValue: Double

    /// 基线均值
    public var baselineMean: Double

    /// Z-score 值（绝对值，越大偏离越强）
    public var zScore: Double

    /// 是否异常
    public var isAnomalous: Bool

    /// 相对基线均值的偏差比例（(current - mean) / mean），均值为 0 时为 0
    public var deviationPercent: Double

    public init(
        metricName: String,
        currentValue: Double,
        baselineMean: Double,
        zScore: Double,
        isAnomalous: Bool,
        deviationPercent: Double
    ) {
        self.metricName = metricName
        self.currentValue = currentValue
        self.baselineMean = baselineMean
        self.zScore = zScore
        self.isAnomalous = isAnomalous
        self.deviationPercent = deviationPercent
    }
}

/// 比较当前行为快照与历史基线，输出每个指标的 Z-score 偏差。
/// 无状态（阈值可变但调用方通常只读），可在任意线程使用。
public final class BaselineComparator {
    /// Z-score 阈值，默认 2.5σ：比 3σ 更敏感，适合单设备样本量有限的行为基线
    public var zScoreThreshold: Double

    public init(zScoreThreshold: Double = 2.5) {
        self.zScoreThreshold = zScoreThreshold
    }

    /// 比较当前行为与基线的偏差。
    /// - Returns: 按“动作总数 → 点击 → 滑动 → 点击占比 → 耦合相关性”顺序返回的偏差列表；
    ///   基线为空时返回空数组（无历史不判异常）。
    public func compare(current: BehaviorSignals, baseline: BehaviorBaseline) -> [BaselineDeviation] {
        var deviations: [BaselineDeviation] = []

        // 空基线（样本不足）直接跳过，避免把首次使用误判为行为异常。
        guard baseline.sampleCount > 0 else {
            return deviations
        }

        // 比较操作数量
        let actionDeviation = compareMetric(
            name: "action_count",
            current: Double(current.actionCount),
            stats: baseline.actionCountStats
        )
        deviations.append(actionDeviation)

        // 比较点击数量
        let tapDeviation = compareMetric(
            name: "tap_count",
            current: Double(current.touch.tapCount),
            stats: baseline.tapCountStats
        )
        deviations.append(tapDeviation)

        // 比较滑动数量
        let swipeDeviation = compareMetric(
            name: "swipe_count",
            current: Double(current.touch.swipeCount),
            stats: baseline.swipeCountStats
        )
        deviations.append(swipeDeviation)

        // 比较点击-滑动比例；当前无动作时用 0.5 中性值，与基线构建口径一致。
        let currentRatio: Double
        if current.touch.tapCount + current.touch.swipeCount > 0 {
            currentRatio = Double(current.touch.tapCount) / Double(current.touch.tapCount + current.touch.swipeCount)
        } else {
            currentRatio = 0.5
        }
        let ratioDeviation = compareMetric(
            name: "tap_swipe_ratio",
            current: currentRatio,
            stats: baseline.tapSwipeRatioStats
        )
        deviations.append(ratioDeviation)

        // 比较触摸-运动相关性：只有基线存在该维度且当前也采集到相关系数时才比较。
        if let correlationStats = baseline.touchMotionCorrelationStats,
           let currentCorrelation = current.touchMotionCorrelation {
            let correlationDeviation = compareMetric(
                name: "touch_motion_correlation",
                current: currentCorrelation,
                stats: correlationStats
            )
            deviations.append(correlationDeviation)
        }

        return deviations
    }

    /// 获取异常偏差（只保留 `isAnomalous == true` 的指标）。
    public func getAnomalies(current: BehaviorSignals, baseline: BehaviorBaseline) -> [BaselineDeviation] {
        return compare(current: current, baseline: baseline)
            .filter { $0.isAnomalous }
    }

    // MARK: - 私有方法

    /// 计算单个指标的偏差。
    /// - 标准差 > 0：Z-score = |current - mean| / stdDev，超过阈值判异常
    /// - 标准差 == 0：Z-score 无定义，退化为相对偏差且不判异常（历史无波动时任何变化都可能是正常漂移）
    private func compareMetric(name: String, current: Double, stats: StatisticalFeatures) -> BaselineDeviation {
        guard stats.stdDev > 0 else {
            // 标准差为 0，无法计算 Z-score
            let deviation = stats.mean > 0 ? (current - stats.mean) / stats.mean : 0
            return BaselineDeviation(
                metricName: name,
                currentValue: current,
                baselineMean: stats.mean,
                zScore: 0,
                isAnomalous: false,
                deviationPercent: deviation
            )
        }

        let zScore = abs((current - stats.mean) / stats.stdDev)
        let isAnomalous = zScore > zScoreThreshold
        let deviationPercent = stats.mean > 0 ? (current - stats.mean) / stats.mean : 0

        return BaselineDeviation(
            metricName: name,
            currentValue: current,
            baselineMean: stats.mean,
            zScore: zScore,
            isAnomalous: isAnomalous,
            deviationPercent: deviationPercent
        )
    }
}

// MARK: - 数学辅助函数
/// 局部 `pow` 包装：显式走 Darwin，避免与 Swift 同名泛型函数产生重载歧义。
private func pow(_ base: Double, _ exp: Double) -> Double {
    return Darwin.pow(base, exp)
}

/// 局部 `sqrt` 包装：统一 Double 精度。
private func sqrt(_ x: Double) -> Double {
    return Darwin.sqrt(x)
}
