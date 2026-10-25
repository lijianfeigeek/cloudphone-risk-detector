// 时序特征：从 DeviceHistory 的历史快照中提炼设备年龄、风险趋势、越狱/VPN 频次、
// 风险分数分布与行为一致性等只读指标，供评分引擎判断“长期行为是否突变”。
// 全部指标按设备 ID 计算，不跨设备聚合，也不包含任何原始行为样本。
import Foundation

// MARK: - 风险趋势
/// 风险分数随时间的变化趋势
public enum RiskTrend: String, Codable, Sendable {
    /// 风险在改善（分数下降）
    case improving

    /// 风险稳定（分数变化不大）
    case stable

    /// 风险在恶化（分数上升）
    case deteriorating

    /// 未知（数据不足）
    case unknown
}

// MARK: - 时序特征
/// 从设备历史数据中计算得到的时序特征
public struct TemporalFeatures: Codable, Sendable {
    /// 设备首次被本 SDK 观察到至今的天数
    public var deviceAgeDays: Int
    /// 历史检测快照总数
    public var totalDetectionCount: Int
    /// 最近风险分数趋势（线性回归斜率方向）
    public var riskTrend: RiskTrend
    /// 首次检测到越狱的 Unix 时间戳；从未越狱为 nil
    public var firstJailbreakTime: TimeInterval?
    /// 距首次越狱的天数；无记录为 nil
    public var daysSinceFirstJailbreak: Int?
    /// 最近 7 天内的越狱快照数
    public var jailbreakCount7Days: Int
    /// 最近 30 天内的越狱快照数
    public var jailbreakCount30Days: Int
    /// 最近 7 天 VPN 活跃快照占比，范围 0...1
    public var vpnUsageFrequency: Double
    /// 最近 7 天 VPN 状态翻转次数（相邻快照状态变化即计一次）
    public var vpnSwitchCount7Days: Int
    /// 行为一致性分数，范围 0...1，1 表示历史行为指标几乎无波动
    public var behaviorConsistency: Double
    /// 历史风险分数均值
    public var averageRiskScore: Double
    /// 历史风险分数标准差（样本方差开方）
    public var riskScoreStdDev: Double
    /// 历史风险分数最大值
    public var maxRiskScore: Double
    /// 历史风险分数最小值
    public var minRiskScore: Double
    /// 高风险快照占比，范围 0...1
    public var highRiskRatio: Double
    /// 距最后一次检测的秒数
    public var secondsSinceLastDetection: TimeInterval
    /// 有检测记录的不同自然日数量
    public var activeDays: Int
    /// 本特征的计算时间（Unix 时间戳），用于判断缓存是否过期
    public var calculatedAt: TimeInterval

    // 短键名压缩持久化体积；键名是跨版本兼容契约，不可随意修改。
    private enum CodingKeys: String, CodingKey {
        case deviceAgeDays = "da"
        case totalDetectionCount = "td"
        case riskTrend = "rt"
        case firstJailbreakTime = "fj"
        case daysSinceFirstJailbreak = "dj"
        case jailbreakCount7Days = "j7"
        case jailbreakCount30Days = "j3"
        case vpnUsageFrequency = "vf"
        case vpnSwitchCount7Days = "vs"
        case behaviorConsistency = "bc"
        case averageRiskScore = "ar"
        case riskScoreStdDev = "rs"
        case maxRiskScore = "mx"
        case minRiskScore = "mn"
        case highRiskRatio = "hr"
        case secondsSinceLastDetection = "sl"
        case activeDays = "ad"
        case calculatedAt = "ca"
    }

    public init(
        deviceAgeDays: Int,
        totalDetectionCount: Int,
        riskTrend: RiskTrend,
        firstJailbreakTime: TimeInterval?,
        daysSinceFirstJailbreak: Int?,
        jailbreakCount7Days: Int,
        jailbreakCount30Days: Int,
        vpnUsageFrequency: Double,
        vpnSwitchCount7Days: Int,
        behaviorConsistency: Double,
        averageRiskScore: Double,
        riskScoreStdDev: Double,
        maxRiskScore: Double,
        minRiskScore: Double,
        highRiskRatio: Double,
        secondsSinceLastDetection: TimeInterval,
        activeDays: Int,
        calculatedAt: TimeInterval
    ) {
        self.deviceAgeDays = deviceAgeDays
        self.totalDetectionCount = totalDetectionCount
        self.riskTrend = riskTrend
        self.firstJailbreakTime = firstJailbreakTime
        self.daysSinceFirstJailbreak = daysSinceFirstJailbreak
        self.jailbreakCount7Days = jailbreakCount7Days
        self.jailbreakCount30Days = jailbreakCount30Days
        self.vpnUsageFrequency = vpnUsageFrequency
        self.vpnSwitchCount7Days = vpnSwitchCount7Days
        self.behaviorConsistency = behaviorConsistency
        self.averageRiskScore = averageRiskScore
        self.riskScoreStdDev = riskScoreStdDev
        self.maxRiskScore = maxRiskScore
        self.minRiskScore = minRiskScore
        self.highRiskRatio = highRiskRatio
        self.secondsSinceLastDetection = secondsSinceLastDetection
        self.activeDays = activeDays
        self.calculatedAt = calculatedAt
    }

    /// 便捷初始化：空特征（无历史数据时使用）。
    /// `behaviorConsistency` 取 1.0 作为中性值，表示“没有证据表明行为不一致”，避免误判。
    public static func empty(at timestamp: TimeInterval = Date().timeIntervalSince1970) -> TemporalFeatures {
        return TemporalFeatures(
            deviceAgeDays: 0,
            totalDetectionCount: 0,
            riskTrend: .unknown,
            firstJailbreakTime: nil,
            daysSinceFirstJailbreak: nil,
            jailbreakCount7Days: 0,
            jailbreakCount30Days: 0,
            vpnUsageFrequency: 0,
            vpnSwitchCount7Days: 0,
            behaviorConsistency: 1.0,
            averageRiskScore: 0,
            riskScoreStdDev: 0,
            maxRiskScore: 0,
            minRiskScore: 0,
            highRiskRatio: 0,
            secondsSinceLastDetection: 0,
            activeDays: 0,
            calculatedAt: timestamp
        )
    }
}

// MARK: - 时序特征计算器
/// 负责从历史数据中计算时序特征。
/// 无状态服务：每次调用重新读取 `DeviceHistory`，不缓存结果；线程安全由 DeviceHistory 的锁保证。
public final class TemporalFeaturesCalculator {
    private let history: DeviceHistory
    // 固定使用公历，避免用户切换历法（如佛历）导致“活跃天数”口径漂移。
    private let calendar = Calendar(identifier: .gregorian)

    public init(history: DeviceHistory = .shared) {
        self.history = history
    }

    /// 为指定设备计算时序特征。
    /// - Parameter deviceID: 设备稳定标识（来自 KeychainDeviceID）
    /// - Returns: 无任何历史快照时返回 `TemporalFeatures.empty(at:)`，而非抛错。
    public func calculate(for deviceID: String) -> TemporalFeatures {
        let now = Date().timeIntervalSince1970

        // 获取所有历史快照（DeviceHistory 内部已做 30 天/500 条修剪）
        let snapshots = history.getSnapshots(for: deviceID)

        // 无历史数据是正常冷启动状态，返回中性特征让上游跳过时序维度。
        guard !snapshots.isEmpty else {
            return TemporalFeatures.empty(at: now)
        }

        // 1. 设备年龄
        let deviceAgeDays = calculateDeviceAgeDays(snapshots: snapshots, now: now)

        // 2. 总检测次数
        let totalDetectionCount = snapshots.count

        // 3. 风险趋势
        let riskTrend = calculateRiskTrend(snapshots: snapshots)

        // 4. 越狱相关：7/30 天两个窗口兼顾短期突发与中期模式
        let firstJailbreakTime = history.getFirstJailbreakTime(for: deviceID)
        // 按 24 小时整除取整，只保留“天数”粒度，避免时区边界造成 ±1 天抖动。
        let daysSinceFirstJailbreak = firstJailbreakTime.map { Int((now - $0) / (24 * 3600)) }
        let jailbreakCount7Days = history.getJailbreakCount(days: 7, for: deviceID)
        let jailbreakCount30Days = history.getJailbreakCount(days: 30, for: deviceID)

        // 5. VPN 相关
        let vpnUsageFrequency = history.getVPNUsageFrequency(days: 7, for: deviceID)
        let vpnSwitchCount7Days = calculateVPNSwitchCount(snapshots: snapshots, windowDays: 7)

        // 6. 行为一致性
        let behaviorConsistency = calculateBehaviorConsistency(snapshots: snapshots)

        // 7. 风险分数统计：方差使用 n-1 分母，样本少时更保守；max(...,1) 防单样本除零。
        let scores = snapshots.map { $0.riskScore }
        let averageRiskScore = scores.reduce(0, +) / Double(scores.count)
        let variance = scores.map { pow($0 - averageRiskScore, 2) }.reduce(0, +) / Double(max(scores.count - 1, 1))
        let riskScoreStdDev = sqrt(variance)
        let maxRiskScore = scores.max() ?? 0
        let minRiskScore = scores.min() ?? 0

        // 8. 高风险占比
        let highRiskCount = snapshots.filter { $0.isHighRisk }.count
        let highRiskRatio = Double(highRiskCount) / Double(snapshots.count)

        // 9. 距离最后一次检测的时间：用于判断历史是否“新鲜”，过旧时趋势权重应降低。
        let lastTimestamp = snapshots.map { $0.timestamp }.max() ?? now
        let secondsSinceLastDetection = now - lastTimestamp

        // 10. 活跃天数
        let activeDays = calculateActiveDays(snapshots: snapshots)

        return TemporalFeatures(
            deviceAgeDays: deviceAgeDays,
            totalDetectionCount: totalDetectionCount,
            riskTrend: riskTrend,
            firstJailbreakTime: firstJailbreakTime,
            daysSinceFirstJailbreak: daysSinceFirstJailbreak,
            jailbreakCount7Days: jailbreakCount7Days,
            jailbreakCount30Days: jailbreakCount30Days,
            vpnUsageFrequency: vpnUsageFrequency,
            vpnSwitchCount7Days: vpnSwitchCount7Days,
            behaviorConsistency: behaviorConsistency,
            averageRiskScore: averageRiskScore,
            riskScoreStdDev: riskScoreStdDev,
            maxRiskScore: maxRiskScore,
            minRiskScore: minRiskScore,
            highRiskRatio: highRiskRatio,
            secondsSinceLastDetection: secondsSinceLastDetection,
            activeDays: activeDays,
            calculatedAt: now
        )
    }

    // MARK: - 私有计算方法

    /// 计算设备年龄（天数）
    private func calculateDeviceAgeDays(snapshots: [DeviceDetectionSnapshot], now: TimeInterval) -> Int {
        guard let firstTimestamp = snapshots.map({ $0.timestamp }).min() else {
            return 0
        }
        return Int((now - firstTimestamp) / (24 * 3600))
    }

    /// 计算风险趋势：对最近若干次风险分数做最小二乘线性回归，按斜率方向判定。
    /// 少于 3 个快照无法区分趋势与噪声，返回 `.unknown`。
    private func calculateRiskTrend(snapshots: [DeviceDetectionSnapshot]) -> RiskTrend {
        guard snapshots.count >= 3 else {
            return .unknown
        }

        // 只看最近 10 个快照（不足则全取）：久远历史会稀释近期变化，使趋势迟滞。
        let recent = Array(snapshots.suffix(min(10, snapshots.count)))
        let scores = recent.map { $0.riskScore }

        // 使用线性回归计算趋势斜率（x 为快照序号，y 为风险分数）
        let n = Double(scores.count)
        let xValues = Array(0..<scores.count).map { Double($0) }

        let sumX = xValues.reduce(0, +)
        let sumY = scores.reduce(0, +)
        let sumXY = zip(xValues, scores).map(*).reduce(0, +)
        let sumXX = xValues.map { $0 * $0 }.reduce(0, +)

        // 分母为 0 表示所有 x 相同（理论上不会发生），退化为稳定，避免除零。
        let denominator = n * sumXX - sumX * sumX
        guard abs(denominator) > 1e-9 else {
            return .stable
        }
        let slope = (n * sumXY - sumX * sumY) / denominator
        let avgScore = sumY / n

        // 根据斜率判断趋势；阈值取平均分的 10%，低于该幅度视为正常波动而非趋势。
        let threshold = avgScore * 0.1 // 10% 的平均分数作为阈值

        if abs(slope) < threshold {
            return .stable
        } else if slope < 0 {
            return .improving
        } else {
            return .deteriorating
        }
    }

    /// 计算窗口内 VPN 切换次数：相邻快照的 VPN 状态翻转即计一次。
    /// 少于 2 条窗口内记录时无法比较，返回 0。
    private func calculateVPNSwitchCount(snapshots: [DeviceDetectionSnapshot], windowDays: Int) -> Int {
        let now = Date().timeIntervalSince1970
        let windowStart = now - TimeInterval(windowDays * 24 * 3600)

        let recent = snapshots.filter { $0.timestamp >= windowStart }
        guard recent.count >= 2 else { return 0 }

        // 必须先按时间排序，否则“相邻”失去意义。
        let sorted = recent.sorted { $0.timestamp < $1.timestamp }
        var switchCount = 0
        var previousVPNStatus = sorted.first?.isVPNActive

        for snapshot in sorted.dropFirst() {
            if snapshot.isVPNActive != previousVPNStatus {
                switchCount += 1
                previousVPNStatus = snapshot.isVPNActive
            }
        }

        return switchCount
    }

    /// 计算行为一致性分数（0...1）。
    /// 对操作量、点击/滑动比例、触摸-运动相关性分别求变异系数（CV），
    /// 再用 `exp(-平均CV)` 映射：CV 越小越接近 1。样本不足时返回 1.0 表示“无异常证据”。
    private func calculateBehaviorConsistency(snapshots: [DeviceDetectionSnapshot]) -> Double {
        guard snapshots.count >= 2 else { return 1.0 }

        // 过滤出有行为摘要的快照；未启用行为采集的设备会得到空数组并走默认值。
        let withBehavior = snapshots.compactMap { $0.behaviorSummary }

        guard withBehavior.count >= 2 else { return 1.0 }

        // 计算各项指标的变异系数（CV = 标准差/均值），作为“行为波动”的度量
        var cvs: [Double] = []

        // 1. 操作数量的一致性
        let actionCounts = withBehavior.map { Double($0.actionCount) }
        if actionCounts.max() ?? 0 > 0 {
            let avg = actionCounts.reduce(0, +) / Double(actionCounts.count)
            let variance = actionCounts.map { pow($0 - avg, 2) }.reduce(0, +) / Double(max(actionCounts.count - 1, 1))
            let stdDev = sqrt(variance)
            if avg > 0 {
                cvs.append(stdDev / avg)
            }
        }

        // 2. 点击与滑动比例的一致性
        let tapSwipeRatios = withBehavior.map { summary -> Double in
            guard summary.tapCount + summary.swipeCount > 0 else { return 0 }
            return Double(summary.tapCount) / Double(summary.tapCount + summary.swipeCount)
        }
        if tapSwipeRatios.max() ?? 0 > 0 {
            let avg = tapSwipeRatios.reduce(0, +) / Double(tapSwipeRatios.count)
            let variance = tapSwipeRatios.map { pow($0 - avg, 2) }.reduce(0, +) / Double(max(tapSwipeRatios.count - 1, 1))
            let stdDev = sqrt(variance)
            if avg > 0 {
                cvs.append(stdDev / avg)
            }
        }

        // 3. 触摸-运动相关性的一致性
        let correlations = withBehavior.compactMap { $0.touchMotionCorrelation }
        if correlations.count >= 2 {
            let avg = correlations.reduce(0, +) / Double(correlations.count)
            let variance = correlations.map { pow($0 - avg, 2) }.reduce(0, +) / Double(correlations.count - 1)
            let stdDev = sqrt(variance)
            if avg > 0 {
                cvs.append(stdDev / avg)
            }
        }

        // 平均 CV 转换为一致性分数（CV 越小，一致性越高）
        guard !cvs.isEmpty else { return 1.0 }

        let avgCV = cvs.reduce(0, +) / Double(cvs.count)
        // 指数衰减把 [0, +∞) 的 CV 平滑映射到 (0, 1]：CV=0 时为 1，CV=1 时约 0.37。
        let consistency = exp(-avgCV)

        // 数值噪声可能越界，钳制到 [0, 1]。
        return max(0, min(1, consistency))
    }

    /// 计算活跃天数（有检测记录的不同自然日数量）。
    /// 使用本地公历的年-月-日组合去重，而不是按 24 小时切分，避免跨天窗口被算作同一天。
    private func calculateActiveDays(snapshots: [DeviceDetectionSnapshot]) -> Int {
        let dates = snapshots.map { Date(timeIntervalSince1970: $0.timestamp) }
        var uniqueDays = Set<String>()

        for date in dates {
            let components = calendar.dateComponents([.year, .month, .day], from: date)
            if let year = components.year, let month = components.month, let day = components.day {
                let key = "\(year)-\(month)-\(day)"
                uniqueDays.insert(key)
            }
        }

        return uniqueDays.count
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

/// 局部 `exp` 包装：用于 CV → 一致性分数的指数衰减。
private func exp(_ x: Double) -> Double {
    return Darwin.exp(x)
}
