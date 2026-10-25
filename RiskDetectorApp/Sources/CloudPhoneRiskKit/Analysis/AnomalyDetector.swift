// 异常检测：基于 DeviceHistory 的历史快照，用 Z-score / IQR 判断当前风险分数偏离，
// 用行为基线判断操作量/点击占比偏离，并识别越狱、VPN 等状态的突变。
// 所有判定都要求最小历史样本量；数据不足时返回 nil 或空列表（不判异常），避免冷启动误报。
import Foundation

// MARK: - 异常类型
/// 检测到的异常类型
public enum AnomalyType: String, Codable, Sendable {
    /// 统计异常（基于 Z-score 或 IQR）
    case statistical

    /// 行为异常（与历史基线偏离）
    case behavioral

    /// 时间异常（异常的检测时间）
    case temporal

    /// 设备状态突变（如突然越狱）
    case stateChange
}

// MARK: - 异常严重程度
/// 异常严重程度，由异常分数分档映射，供处置动作（放行/加强验证/拦截）参考。
public enum AnomalySeverity: String, Codable, Sendable {
    /// 轻微：仅记录，不改变处置
    case low
    /// 中等：可作为辅助信号加权
    case medium
    /// 高：应提高验证强度
    case high
    /// 严重：可直接触发拦截策略
    case critical
}

// MARK: - 异常检测结果
/// 单条异常结论：类型、严重度、分数、可读描述与受影响指标。
/// 只描述“哪里异常”，不包含原始样本，可直接随评分结果上报。
public struct AnomalyDetectionResult: Codable, Sendable {
    /// 是否检测到异常
    public var isAnomalous: Bool

    /// 异常类型
    public var type: AnomalyType

    /// 严重程度
    public var severity: AnomalySeverity

    /// 异常分数（0-1，越高越异常）
    public var anomalyScore: Double

    /// 异常描述
    public var description: String

    /// 异常相关的字段/指标
    public var affectedMetrics: [String]

    /// 检测方法
    public var detectionMethod: String

    private enum CodingKeys: String, CodingKey {
        case isAnomalous = "ia"
        case type = "t"
        case severity = "sv"
        case anomalyScore = "as"
        case description = "ds"
        case affectedMetrics = "am"
        case detectionMethod = "dm"
    }

    public init(
        isAnomalous: Bool,
        type: AnomalyType,
        severity: AnomalySeverity,
        anomalyScore: Double,
        description: String,
        affectedMetrics: [String],
        detectionMethod: String
    ) {
        self.isAnomalous = isAnomalous
        self.type = type
        self.severity = severity
        self.anomalyScore = anomalyScore
        self.description = description
        self.affectedMetrics = affectedMetrics
        self.detectionMethod = detectionMethod
    }
}

// MARK: - Z-score 异常检测结果
/// 单值 Z-score 检测输出；`zScore` 为绝对值，方向信息不保留（高低异常同等对待）。
public struct ZScoreResult: Sendable {
    /// Z-score 值
    public var zScore: Double

    /// 是否异常
    public var isAnomalous: Bool

    /// 异常阈值
    public var threshold: Double

    public init(zScore: Double, isAnomalous: Bool, threshold: Double) {
        self.zScore = zScore
        self.isAnomalous = isAnomalous
        self.threshold = threshold
    }
}

// MARK: - IQR 异常检测结果
/// 四分位距检测输出，同时保留上下界与越界方向，便于区分“异常偏高/偏低”。
public struct IQRResult: Sendable {
    /// 下界
    public var lowerBound: Double

    /// 上界
    public var upperBound: Double

    /// 是否低于下界
    public var isBelowLowerBound: Bool

    /// 是否高于上界
    public var isAboveUpperBound: Bool

    /// 是否异常
    public var isAnomalous: Bool

    public init(lowerBound: Double, upperBound: Double, isBelowLowerBound: Bool, isAboveUpperBound: Bool, isAnomalous: Bool) {
        self.lowerBound = lowerBound
        self.upperBound = upperBound
        self.isBelowLowerBound = isBelowLowerBound
        self.isAboveUpperBound = isAboveUpperBound
        self.isAnomalous = isAnomalous
    }
}

// MARK: - 异常检测器
/// 提供多种异常检测算法。
/// 无内部可变状态（历史数据由 DeviceHistory 加锁管理），可在并发评估中复用。
public final class AnomalyDetector {
    private let history: DeviceHistory

    public init(history: DeviceHistory = .shared) {
        self.history = history
    }

    // MARK: - Z-score 异常检测

    /// 使用 Z-score 检测单个值是否异常
    /// - Parameters:
    ///   - value: 待检测的值
    ///   - samples: 历史样本数据
    ///   - threshold: Z-score 阈值，默认 3.0（即 3σ 原则）
    /// - Returns: Z-score 检测结果
    public func detectZScore(value: Double, samples: [Double], threshold: Double = 3.0) -> ZScoreResult {
        guard samples.count >= 3 else {
            // 样本数量不足：标准差不可靠，返回“非异常”而不是猜一个分数。
            return ZScoreResult(zScore: 0, isAnomalous: false, threshold: threshold)
        }

        // 样本方差（n-1 分母），样本量小时比总体方差更保守。
        let mean = samples.reduce(0, +) / Double(samples.count)
        let variance = samples.map { pow($0 - mean, 2) }.reduce(0, +) / Double(samples.count - 1)
        let stdDev = sqrt(variance)

        guard stdDev > 0 else {
            // 历史样本完全稳定时，只要当前值偏离历史均值，就应视为强异常。
            // 1e-15 用于吸收浮点表示误差，避免把“相等”误判为偏离。
            if abs(value - mean) < 1e-15 {
                return ZScoreResult(zScore: 0, isAnomalous: false, threshold: threshold)
            }
            // Z-score 数学上为无穷大；用 .infinity 表达“确定性异常”，下游归一化时会被截断。
            return ZScoreResult(zScore: .infinity, isAnomalous: true, threshold: threshold)
        }

        // 取绝对值：偏高与偏低都算偏离，风控更关注“异常”本身而非方向。
        let zScore = abs((value - mean) / stdDev)
        let isAnomalous = zScore > threshold

        return ZScoreResult(zScore: zScore, isAnomalous: isAnomalous, threshold: threshold)
    }

    /// 使用 Z-score 检测风险分数是否异常（取该设备全部历史快照作为样本）。
    public func detectRiskScoreAnomaly(deviceID: String, currentScore: Double, threshold: Double = 3.0) -> ZScoreResult {
        let snapshots = history.getSnapshots(for: deviceID)
        let historicalScores = snapshots.map { $0.riskScore }

        return detectZScore(value: currentScore, samples: historicalScores, threshold: threshold)
    }

    // MARK: - IQR 异常检测

    /// 使用四分位距（IQR）检测异常值。
    /// 与 Z-score 相比不假设分布形态，适合小样本、偏态的风险分数历史。
    /// - Parameters:
    ///   - value: 待检测的值
    ///   - samples: 历史样本数据
    ///   - multiplier: IQR 倍数，默认 1.5（箱线图标准），越大越宽松
    /// - Returns: IQR 检测结果
    public func detectIQR(value: Double, samples: [Double], multiplier: Double = 1.5) -> IQRResult {
        guard samples.count >= 4 else {
            // 样本数量不足，至少需要 4 个值才能计算四分位数。
            return IQRResult(lowerBound: 0, upperBound: 0, isBelowLowerBound: false, isAboveUpperBound: false, isAnomalous: false)
        }

        let sorted = samples.sorted()

        // 计算四分位数（线性插值，与统计标准一致）
        let q1 = interpolatedPercentile(sorted: sorted, p: 0.25)
        let q3 = interpolatedPercentile(sorted: sorted, p: 0.75)
        let iqr = q3 - q1

        // IQR 为 0 说明中间 50% 样本完全相同，上下界会退化为同一点，此时无法区分异常与正常。
        guard iqr > 0 else {
            return IQRResult(lowerBound: q1, upperBound: q3, isBelowLowerBound: false, isAboveUpperBound: false, isAnomalous: false)
        }

        // 箱线图围栏：Q1 - k·IQR 与 Q3 + k·IQR。
        let lowerBound = q1 - multiplier * iqr
        let upperBound = q3 + multiplier * iqr

        let isBelowLowerBound = value < lowerBound
        let isAboveUpperBound = value > upperBound
        let isAnomalous = isBelowLowerBound || isAboveUpperBound

        return IQRResult(lowerBound: lowerBound, upperBound: upperBound, isBelowLowerBound: isBelowLowerBound, isAboveUpperBound: isAboveUpperBound, isAnomalous: isAnomalous)
    }

    /// 使用 IQR 检测风险分数是否异常。
    public func detectRiskScoreAnomalyIQR(deviceID: String, currentScore: Double, multiplier: Double = 1.5) -> IQRResult {
        let snapshots = history.getSnapshots(for: deviceID)
        let historicalScores = snapshots.map { $0.riskScore }

        return detectIQR(value: currentScore, samples: historicalScores, multiplier: multiplier)
    }

    // MARK: - 行为基线异常检测

    /// 检测当前行为是否偏离历史基线。
    /// 只比较两个稳定维度：每次评估的动作总数、点击占比；二者任一 Z-score 超过 2.5σ 即判定异常。
    /// - Returns: 无异常或历史样本不足时返回 nil（调用方直接跳过该维度）。
    public func detectBehaviorAnomaly(current: BehaviorSignals, deviceID: String) -> AnomalyDetectionResult? {
        let snapshots = history.getSnapshots(for: deviceID)

        // 历史快照与“带行为摘要的快照”都要求至少 5 条；未启用行为采集时后者为 0，自然降级。
        guard snapshots.count >= 5 else {
            // 历史数据不足
            return nil
        }

        let historicalSummaries = snapshots.compactMap { $0.behaviorSummary }
        guard historicalSummaries.count >= 5 else {
            return nil
        }

        // 提取历史行为特征（聚合值，不含原始触摸数据）
        let actionCounts = historicalSummaries.map { Double($0.actionCount) }
        let tapSwipeRatios = historicalSummaries.map { summary -> Double in
            guard summary.tapCount + summary.swipeCount > 0 else { return 0.5 }
            return Double(summary.tapCount) / Double(summary.tapCount + summary.swipeCount)
        }

        // 检测当前行为
        let currentActionCount = Double(current.actionCount)
        let currentTapSwipeRatio: Double
        if current.touch.tapCount + current.touch.swipeCount > 0 {
            currentTapSwipeRatio = Double(current.touch.tapCount) / Double(current.touch.tapCount + current.touch.swipeCount)
        } else {
            currentTapSwipeRatio = 0.5
        }

        // Z-score 检测：行为基线样本量有限，2.5σ 比 3σ 更灵敏。
        let actionCountZ = detectZScore(value: currentActionCount, samples: actionCounts, threshold: 2.5)
        let tapSwipeRatioZ = detectZScore(value: currentTapSwipeRatio, samples: tapSwipeRatios, threshold: 2.5)

        var anomalies: [String] = []
        var scores: [Double] = []

        // 3σ 及以上归一化为满分 1.0，防止极端 Z 值把综合分拉爆。
        if actionCountZ.isAnomalous {
            anomalies.append("action_count")
            scores.append(min(actionCountZ.zScore / 3.0, 1.0))
        }

        if tapSwipeRatioZ.isAnomalous {
            anomalies.append("tap_swipe_ratio")
            scores.append(min(tapSwipeRatioZ.zScore / 3.0, 1.0))
        }

        // 没有任何维度越界：返回 nil，不产生“分数为 0 的异常”。
        guard !anomalies.isEmpty else {
            return nil
        }

        // 计算综合异常分数（越界维度等权平均）
        let avgScore = scores.reduce(0, +) / Double(scores.count)

        // 确定严重程度：0.3/0.6/0.9 为分档边界，与评分引擎的处置阈值对齐。
        let severity: AnomalySeverity
        switch avgScore {
        case 0..<0.3:
            severity = .low
        case 0.3..<0.6:
            severity = .medium
        case 0.6..<0.9:
            severity = .high
        default:
            severity = .critical
        }

        return AnomalyDetectionResult(
            isAnomalous: true,
            type: .behavioral,
            severity: severity,
            anomalyScore: avgScore,
            description: "行为特征偏离历史基线：\(anomalies.joined(separator: ", "))",
            affectedMetrics: anomalies,
            detectionMethod: "z_score_baseline"
        )
    }

    // MARK: - 设备状态突变检测

    /// 检测设备状态是否发生突变（如突然越狱）。
    /// 只与最近 10 次快照比较，关注“突变”而非长期趋势。
    /// - Returns: 未发现突变时返回 nil。
    public func detectStateChangeAnomaly(currentSnapshot: DeviceDetectionSnapshot, deviceID: String) -> AnomalyDetectionResult? {
        let snapshots = history.getSnapshots(for: deviceID)

        guard !snapshots.isEmpty else {
            return nil
        }

        // 取最近 10 次作为“之前状态”的参照窗口。
        let recentSnapshots = Array(snapshots.suffix(10))
        let previousJailbroken = recentSnapshots.filter { $0.jailbreakStatus.isJailbroken }
        let currentJailbroken = currentSnapshot.jailbreakStatus.isJailbroken

        // 检测突然越狱：此前从未越狱、本次命中，视为强状态突变（1.0 分）。
        if currentJailbroken && previousJailbroken.isEmpty {
            return AnomalyDetectionResult(
                isAnomalous: true,
                type: .stateChange,
                severity: .critical,
                anomalyScore: 1.0,
                description: "设备首次检测到越狱状态",
                affectedMetrics: ["jailbreak_status"],
                detectionMethod: "first_jailbreak_detection"
            )
        }

        // 检测越狱状态消失（可能为反检测对抗）
        if !currentJailbroken && !previousJailbroken.isEmpty {
            let recentJailbreakRatio = Double(previousJailbroken.count) / Double(recentSnapshots.count)
            // 阈值 0.5：此前半数以上检测为越狱、本次突然“干净”，更可能是检测被绕过而非真实修复。
            if recentJailbreakRatio > 0.5 {
                // 之前 50% 以上检测都是越狱，现在正常，可疑
                return AnomalyDetectionResult(
                    isAnomalous: true,
                    type: .stateChange,
                    severity: .high,
                    anomalyScore: 0.8,
                    description: "越狱状态突然消失（可能存在反检测对抗）",
                    affectedMetrics: ["jailbreak_status"],
                    detectionMethod: "jailbreak_disappearance"
                )
            }
        }

        // 检测 VPN 突然出现：首次连接本身不必然恶意，故只给 medium/0.6。
        if currentSnapshot.isVPNActive {
            let previousVPN = recentSnapshots.filter { $0.isVPNActive }
            if previousVPN.isEmpty {
                return AnomalyDetectionResult(
                    isAnomalous: true,
                    type: .stateChange,
                    severity: .medium,
                    anomalyScore: 0.6,
                    description: "首次检测到 VPN 连接",
                    affectedMetrics: ["vpn_status"],
                    detectionMethod: "first_vpn_detection"
                )
            }
        }

        return nil
    }

    // MARK: - 综合异常检测

    /// 执行全面的异常检测。
    /// 依次执行风险分数 Z-score、IQR、状态突变、行为偏离四类检查，结果可同时存在（最多 4 条）。
    /// - Parameter currentBehavior: 传入时才会进行行为偏离检查；未启用行为采集时传 nil。
    /// - Returns: 异常结论列表；无任何异常时为空数组。
    public func detectAnomalies(deviceID: String, currentSnapshot: DeviceDetectionSnapshot, currentBehavior: BehaviorSignals? = nil) -> [AnomalyDetectionResult] {
        var results: [AnomalyDetectionResult] = []

        // 1. 风险分数异常检测（Z-score）；2.5σ 对单设备小样本更灵敏。
        let riskScoreZ = detectRiskScoreAnomaly(deviceID: deviceID, currentScore: currentSnapshot.riskScore, threshold: 2.5)
        if riskScoreZ.isAnomalous {
            let severity: AnomalySeverity
            // 按 Z 值分档：3σ 以下轻微、5σ 以上视为严重。
            switch riskScoreZ.zScore {
            case 0..<3.0:
                severity = .low
            case 3.0..<4.0:
                severity = .medium
            case 4.0..<5.0:
                severity = .high
            default:
                severity = .critical
            }

            // 5σ 归一化为 1.0，与上面的严重度分档上限保持一致。
            results.append(AnomalyDetectionResult(
                isAnomalous: true,
                type: .statistical,
                severity: severity,
                anomalyScore: min(riskScoreZ.zScore / 5.0, 1.0),
                description: "风险分数异常：Z-score = \(String(format: "%.2f", riskScoreZ.zScore))",
                affectedMetrics: [ObfuscatedConstants.keywordRiskScore],
                detectionMethod: "z_score"
            ))
        }

        // 2. 风险分数异常检测（IQR）：与 Z-score 互为补充，偏态历史下更稳健。
        let riskScoreIQR = detectRiskScoreAnomalyIQR(deviceID: deviceID, currentScore: currentSnapshot.riskScore)
        if riskScoreIQR.isAnomalous {
            let severity: AnomalySeverity
            let score: Double
            // 高于上界（分数异常升高）比低于下界更值得关注，给更高分。
            if riskScoreIQR.isAboveUpperBound {
                score = 0.8
                severity = .high
            } else {
                score = 0.5
                severity = .medium
            }

            // 避免重复添加（同一设备一次评估内同一方法只记一条）
            if !results.contains(where: { $0.detectionMethod == "iqr" }) {
                results.append(AnomalyDetectionResult(
                    isAnomalous: true,
                    type: .statistical,
                    severity: severity,
                    anomalyScore: score,
                    description: "风险分数超出四分位距范围",
                    affectedMetrics: [ObfuscatedConstants.keywordRiskScore],
                    detectionMethod: "iqr"
                ))
            }
        }

        // 3. 状态突变检测（越狱出现/消失、VPN 首次出现）
        if let stateChange = detectStateChangeAnomaly(currentSnapshot: currentSnapshot, deviceID: deviceID) {
            results.append(stateChange)
        }

        // 4. 行为异常检测：仅在调用方提供了本窗口行为信号时执行。
        if let behavior = currentBehavior {
            if let behaviorAnomaly = detectBehaviorAnomaly(current: behavior, deviceID: deviceID) {
                results.append(behaviorAnomaly)
            }
        }

        return results
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

/// 线性插值分位数（等同于 numpy percentile method='linear'）。
/// - Parameters:
///   - sorted: 已升序排序的样本
///   - p: 分位点，取值 0...1
private func interpolatedPercentile(sorted: [Double], p: Double) -> Double {
    guard !sorted.isEmpty else { return 0 }
    let n = Double(sorted.count)
    // 与 StatisticalFeatures 的分位数口径保持一致：
    // index = p*n - 0.5（p ∈ [0,1]），再在相邻两个样本间线性插值，避免不同检测器结论互相矛盾。
    let index = max(0, min((p * n) - 0.5, n - 1))
    let lower = Int(Darwin.floor(index))
    let upper = Int(Darwin.ceil(index))
    guard lower >= 0, upper < sorted.count else { return sorted[max(0, min(lower, sorted.count - 1))] }
    if lower == upper { return sorted[lower] }
    let weight = index - Double(lower)
    return sorted[lower] * (1.0 - weight) + sorted[upper] * weight
}
