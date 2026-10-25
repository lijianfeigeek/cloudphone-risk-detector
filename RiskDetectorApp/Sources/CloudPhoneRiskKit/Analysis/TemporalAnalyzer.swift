// 时序分析模型与协议：定义时间窗口、时间分布、频率指标、序列模式、基线统计等数据结构，
// 供 DefaultTemporalAnalyzer 之类的实现计算“事件在何时发生、间隔是否规律”。
// 本文件只有协议与值类型，不含具体判定逻辑；所有结构均可 Codable，便于落盘/上报。

import Foundation

// MARK: - 时序分析器协议

/// 时序分析器协议
///
/// 负责分析历史事件的时间模式，检测异常行为。
/// 
/// # 功能概述
/// - 分析 24 小时内事件的时间分布
/// - 检测异常的时间模式（如凌晨高频操作）
/// - 计算频率统计指标
/// - 识别序列模式
/// 
/// # 使用示例
/// ```swift
/// let analyzer = DefaultTemporalAnalyzer()
/// let result = await analyzer.analyze(
///     history: events,
///     window: .last24Hours
/// )
/// if result.anomalyScore > threshold {
///     // 检测到异常
/// }
/// ```
public protocol TemporalAnalyzer: Sendable {
    
    /// 分析时间模式
    ///
    /// - Parameters:
    ///   - history: 历史事件列表
    ///   - window: 分析时间窗口
    /// - Returns: 时序分析结果
    func analyze(
        history: [TemporalRiskHistoryEvent],
        window: TimeWindow
    ) async -> TemporalAnalysisResult
    
    /// 检测异常模式
    ///
    /// - Parameters:
    ///   - history: 历史事件列表
    ///   - current: 当前待检测事件
    /// - Returns: 异常检测结果
    func detectAnomaly(
        history: [TemporalRiskHistoryEvent],
        current: TemporalRiskHistoryEvent
    ) async -> TemporalAnomalyDetectionResult
    
    /// 获取基线模式
    ///
    /// 基于历史数据计算正常行为的基线
    ///
    /// - Parameter history: 历史事件列表
    /// - Returns: 基线统计信息
    func calculateBaseline(
        history: [TemporalRiskHistoryEvent]
    ) async -> BaselineStatistics
}

// MARK: - 时间窗口

/// 时间窗口
///
/// 定义分析的时间范围。若未显式给出起止时间，则以 `duration` 相对“当前时刻”回溯。
public struct TimeWindow: Sendable, Codable {

    /// 窗口长度（秒），在未指定起止时间时生效
    public var duration: TimeInterval
    /// 窗口起始时间（Unix 时间戳）；nil 表示按 duration 由 endTime 反推
    public var startTime: TimeInterval?
    /// 窗口结束时间（Unix 时间戳）；nil 表示“当前时刻”
    public var endTime: TimeInterval?

    // 短键名压缩序列化体积。
    private enum CodingKeys: String, CodingKey {
        case duration = "d"
        case startTime = "st"
        case endTime = "et"
    }

    public init(
        duration: TimeInterval,
        startTime: TimeInterval? = nil,
        endTime: TimeInterval? = nil
    ) {
        self.duration = duration
        self.startTime = startTime
        self.endTime = endTime
    }
    
    /// 预定义时间窗口：覆盖从小时级突发到月度模式的常用观察尺度。
    public static let last1Hour = TimeWindow(duration: 3600)
    public static let last6Hours = TimeWindow(duration: 21600)
    public static let last24Hours = TimeWindow(duration: 86400)
    public static let last7Days = TimeWindow(duration: 604800)
    public static let last30Days = TimeWindow(duration: 2592000)

    /// 获取窗口的实际起止时间。
    /// 优先使用显式起止时间；否则以当前时刻为终点、向前回溯 `duration`。
    public func getActualRange() -> (start: TimeInterval, end: TimeInterval) {
        let end = endTime ?? Date().timeIntervalSince1970
        let start = startTime ?? (end - duration)
        return (start, end)
    }

    /// 检查给定时间戳是否在窗口内。
    /// 左闭右开 `[start, end)`：避免相邻窗口在边界时间戳上重复计数。
    public func contains(_ timestamp: TimeInterval) -> Bool {
        let (start, end) = getActualRange()
        return timestamp >= start && timestamp < end
    }
}

// MARK: - 时序分析结果

/// 时序分析结果
///
/// 包含时间模式分析的完整结果
public struct TemporalAnalysisResult: Sendable, Codable {

    /// 本次分析使用的时间窗口
    public var window: TimeWindow
    /// 窗口内事件数量
    public var eventCount: Int
    /// 按小时/星期/昼夜的分布
    public var timeDistribution: TimeDistribution
    /// 事件间隔与频率指标
    public var frequencyMetrics: FrequencyMetrics
    /// 识别出的重复序列模式
    public var sequencePatterns: [SequencePattern]
    /// 综合异常分数，0 表示未发现异常；具体量纲由实现约定（通常 0–100）
    public var anomalyScore: Double
    /// 由时序异常转换出的风险信号，可直接进入评分管道。
    /// 每条信号包含稳定 id、0–1 或约定量纲的 score、可选的 state；具体取值由分析器实现填充。
    public var riskSignals: [RiskSignal]
    /// 分析完成时间
    public var analyzedAt: Date

    // 短键名压缩序列化体积。
    private enum CodingKeys: String, CodingKey {
        case window = "w"
        case eventCount = "ec"
        case timeDistribution = "td"
        case frequencyMetrics = "fm"
        case sequencePatterns = "sp"
        case anomalyScore = "as"
        case riskSignals = "rs"
        case analyzedAt = "aa"
    }

    public init(
        window: TimeWindow,
        eventCount: Int,
        timeDistribution: TimeDistribution,
        frequencyMetrics: FrequencyMetrics,
        sequencePatterns: [SequencePattern],
        anomalyScore: Double,
        riskSignals: [RiskSignal],
        analyzedAt: Date = Date()
    ) {
        self.window = window
        self.eventCount = eventCount
        self.timeDistribution = timeDistribution
        self.frequencyMetrics = frequencyMetrics
        self.sequencePatterns = sequencePatterns
        self.anomalyScore = anomalyScore
        self.riskSignals = riskSignals
        self.analyzedAt = analyzedAt
    }
    
    /// 是否检测到异常（任何正分都视为有异常，阈值判断由调用方完成）。
    public var hasAnomaly: Bool {
        return anomalyScore > 0
    }

    /// 获取风险摘要：按 80/50/0 分档输出稳定的枚举式字符串，便于云端聚合统计。
    public var riskSummary: String {
        if anomalyScore >= 80 {
            return "high_temporal_risk"
        } else if anomalyScore >= 50 {
            return "medium_temporal_risk"
        } else if anomalyScore > 0 {
            return "low_temporal_risk"
        } else {
            return "normal_temporal_pattern"
        }
    }
}

// MARK: - 时间分布

/// 时间分布
///
/// 描述事件在不同时间维度的分布情况
public struct TimeDistribution: Sendable, Codable {

    /// 小时（0–23）→ 事件数
    public var hourlyCount: [Int: Int]
    /// 星期（1–7，1 为周日，遵循 Calendar）→ 事件数
    public var weekdayCount: [Int: Int]
    /// 夜间时段（默认 0–5 点）事件数
    public var nightCount: Int
    /// 工作时段（默认 9–18 点）事件数
    public var workHoursCount: Int
    /// 有事件的非重复小时数，0–24
    public var activeHours: Int

    // 短键名压缩序列化体积。
    private enum CodingKeys: String, CodingKey {
        case hourlyCount = "hc"
        case weekdayCount = "wc"
        case nightCount = "nc"
        case workHoursCount = "wh"
        case activeHours = "ah"
    }

    public init(
        hourlyCount: [Int: Int] = [:],
        weekdayCount: [Int: Int] = [:],
        nightCount: Int = 0,
        workHoursCount: Int = 0,
        activeHours: Int = 0
    ) {
        self.hourlyCount = hourlyCount
        self.weekdayCount = weekdayCount
        self.nightCount = nightCount
        self.workHoursCount = workHoursCount
        self.activeHours = activeHours
    }
    
    /// 获取最活跃的小时；无事件时为 nil。
    public var mostActiveHour: Int? {
        return hourlyCount.max(by: { $0.value < $1.value })?.key
    }

    /// 获取夜间活动比例（0...1）；总事件为 0 时返回 nil。
    public var nightActivityRatio: Double? {
        let total = hourlyCount.values.reduce(0, +)
        return total > 0 ? Double(nightCount) / Double(total) : nil
    }

    /// 是否全时段活跃（24 小时中有 ≥20 个小时出现过事件）。
    /// 阈值 20 给正常作息留出 4 小时空窗，超过则更像脚本/云手机常驻运行。
    public var isFullDayActive: Bool {
        return activeHours >= 20
    }
}

// MARK: - 频率指标

/// 频率指标
///
/// 描述事件发生的频率特征
public struct FrequencyMetrics: Sendable, Codable {

    /// 平均事件间隔（秒）；事件少于 2 个时为 nil
    public var averageInterval: Double?
    /// 最小间隔（秒）
    public var minInterval: Double?
    /// 最大间隔（秒）
    public var maxInterval: Double?
    /// 间隔方差（秒²）
    public var intervalVariance: Double?
    /// 间隔标准差（秒）
    public var intervalStdDev: Double?
    /// 间隔变异系数（标准差/均值），衡量规律性
    public var intervalCV: Double?
    /// 每小时事件数
    public var eventsPerHour: Double?

    // 短键名压缩序列化体积。
    private enum CodingKeys: String, CodingKey {
        case averageInterval = "ai"
        case minInterval = "mi"
        case maxInterval = "xi"
        case intervalVariance = "iv"
        case intervalStdDev = "sd"
        case intervalCV = "cv"
        case eventsPerHour = "eh"
    }

    public init(
        averageInterval: Double? = nil,
        minInterval: Double? = nil,
        maxInterval: Double? = nil,
        intervalVariance: Double? = nil,
        intervalStdDev: Double? = nil,
        intervalCV: Double? = nil,
        eventsPerHour: Double? = nil
    ) {
        self.averageInterval = averageInterval
        self.minInterval = minInterval
        self.maxInterval = maxInterval
        self.intervalVariance = intervalVariance
        self.intervalStdDev = intervalStdDev
        self.intervalCV = intervalCV
        self.eventsPerHour = eventsPerHour
    }
    
    /// 间隔是否过于规律（机器特征）。
    /// CV < 0.2 表示间隔波动不足 20%，人工操作很难长期保持这种节拍。
    public var isTooRegular: Bool {
        guard let cv = intervalCV else { return false }
        return cv < 0.2
    }

    /// 间隔是否过于混乱（人工特征）。CV > 0.8 属于正常人类操作的随机波动范围。
    public var isTooChaotic: Bool {
        guard let cv = intervalCV else { return false }
        return cv > 0.8
    }

    /// 是否高频（平均间隔小于 1 分钟）。
    public var isHighFrequency: Bool {
        guard let avg = averageInterval else { return false }
        return avg < 60
    }
}

// MARK: - 序列模式

/// 序列模式
///
/// 描述事件序列的重复模式
public struct SequencePattern: Sendable, Codable, Identifiable {

    /// 模式唯一标识（通常由模式内容派生，便于去重）
    public let id: String
    /// 模式类型
    public var type: PatternType
    /// 构成模式的步骤序列（如场景/动作名）
    public var pattern: [String]
    /// 该模式在窗口内出现的次数
    public var frequency: Int
    /// 模式置信度，0...1
    public var confidence: Double
    /// 首次观察到该模式的时间
    public var firstSeen: Date
    /// 最近一次观察到该模式的时间
    public var lastSeen: Date

    // 短键名压缩序列化体积。
    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case type = "t"
        case pattern = "p"
        case frequency = "f"
        case confidence = "c"
        case firstSeen = "fs"
        case lastSeen = "ls"
    }

    /// 模式类型；原始值与云端枚举约定一致，不可改名。
    public enum PatternType: String, Sendable, Codable {
        case periodic = "periodic"           // 周期性
        case fixedInterval = "fixed_interval" // 固定间隔（典型脚本特征）
        case sequential = "sequential"       // 序列性
        case clustered = "clustered"         // 聚集性（短时间集中发生）
    }
    
    public init(
        id: String,
        type: PatternType,
        pattern: [String],
        frequency: Int,
        confidence: Double,
        firstSeen: Date,
        lastSeen: Date
    ) {
        self.id = id
        self.type = type
        self.pattern = pattern
        self.frequency = frequency
        self.confidence = confidence
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
    }
}

// MARK: - 异常检测结果

/// 异常检测结果
///
/// 描述单个事件是否异常及原因
public struct TemporalAnomalyDetectionResult: Sendable, Codable {

    /// 是否判定为异常
    public var isAnomalous: Bool
    /// 偏离程度（0–100），同时用于映射严重度
    public var deviation: Double
    /// 判定置信度，0...1
    public var confidence: Double
    /// 触发异常的具体原因，可多条
    public var reasons: [AnomalyReason]
    /// 检测时间
    public var detectedAt: Date

    // 短键名压缩序列化体积。
    private enum CodingKeys: String, CodingKey {
        case isAnomalous = "ia"
        case deviation = "dv"
        case confidence = "c"
        case reasons = "r"
        case detectedAt = "da"
    }

    public init(
        isAnomalous: Bool,
        deviation: Double,
        confidence: Double,
        reasons: [AnomalyReason],
        detectedAt: Date = Date()
    ) {
        self.isAnomalous = isAnomalous
        self.deviation = deviation
        self.confidence = confidence
        self.reasons = reasons
        self.detectedAt = detectedAt
    }
    
    /// 异常严重程度：按偏离度分档（30/60/100 为边界）。
    public var severity: TemporalAnomalySeverity {
        switch deviation {
        case 0..<30: return .low
        case 30..<60: return .medium
        case 60..<100: return .high
        default: return .critical
        }
    }
}

/// 异常原因
public struct AnomalyReason: Sendable, Codable, Identifiable {

    /// 原因唯一标识；默认随机 UUID，去重时应使用 type + evidence
    public let id: String
    /// 异常类型
    public var type: TemporalAnomalyType
    /// 可读描述（用于日志/运营排查，不参与判定）
    public var description: String
    /// 支撑证据的键值对（如触发阈值、实际观测值），避免直接携带原始样本
    public var evidence: [String: String]

    // 短键名压缩序列化体积。
    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case type = "t"
        case description = "ds"
        case evidence = "ev"
    }

    public init(
        id: String = UUID().uuidString,
        type: TemporalAnomalyType,
        description: String,
        evidence: [String: String] = [:]
    ) {
        self.id = id
        self.type = type
        self.description = description
        self.evidence = evidence
    }
    
    /// 异常类型；原始值与云端枚举约定一致，不可改名。
    public enum TemporalAnomalyType: String, Sendable, Codable {
        case unusualTime = "unusual_time"           // 异常时间
        case highFrequency = "high_frequency"       // 高频
        case regularPattern = "regular_pattern"     // 过于规律
        case burstActivity = "burst_activity"       // 突发活动
        case nightActivity = "night_activity"       // 夜间活跃
        case fullDayActive = "full_day_active"      // 全天活跃
    }
}

/// 异常严重程度。
/// 使用 Int 原始值而非字符串：便于比较大小与持久化，新增档位时保持向后兼容。
public enum TemporalAnomalySeverity: Int, Sendable, Codable {
    case low = 0
    case medium = 1
    case high = 2
    case critical = 3

    /// 中文展示名，仅用于日志/调试，不参与风控判定。
    public var displayName: String {
        switch self {
        case .low: return "低"
        case .medium: return "中"
        case .high: return "高"
        case .critical: return "严重"
        }
    }
}

// MARK: - 基线统计

/// 基线统计
///
/// 描述正常行为的统计基线
public struct BaselineStatistics: Sendable, Codable {

    /// 平均每日事件数
    public var averageDailyEvents: Double
    /// 典型活跃小时集合（0–23）
    public var typicalActiveHours: Set<Int>
    /// 典型夜间事件占比，0...1
    public var typicalNightRatio: Double
    /// 事件间隔的统计分布
    public var typicalIntervalStats: IntervalStatistics
    /// 基线计算时间
    public var calculatedAt: Date
    /// 参与计算的历史跨度（天），用于判断基线可信度
    public var dataRangeDays: Int

    // 短键名压缩序列化体积。
    private enum CodingKeys: String, CodingKey {
        case averageDailyEvents = "ad"
        case typicalActiveHours = "ta"
        case typicalNightRatio = "tn"
        case typicalIntervalStats = "ti"
        case calculatedAt = "ca"
        case dataRangeDays = "dr"
    }

    public init(
        averageDailyEvents: Double,
        typicalActiveHours: Set<Int>,
        typicalNightRatio: Double,
        typicalIntervalStats: IntervalStatistics,
        calculatedAt: Date = Date(),
        dataRangeDays: Int
    ) {
        self.averageDailyEvents = averageDailyEvents
        self.typicalActiveHours = typicalActiveHours
        self.typicalNightRatio = typicalNightRatio
        self.typicalIntervalStats = typicalIntervalStats
        self.calculatedAt = calculatedAt
        self.dataRangeDays = dataRangeDays
    }
}

/// 间隔统计：事件时间差的集中趋势与分位数。
/// 使用中位数/四分位数与均值并列，避免少量超长间隔（如隔夜）拉偏判断。
public struct IntervalStatistics: Sendable, Codable {

    /// 平均间隔（秒）
    public var mean: Double
    /// 间隔标准差（秒）
    public var stdDev: Double
    /// 间隔中位数（秒）
    public var median: Double
    /// 25 分位间隔（秒）
    public var p25: Double
    /// 75 分位间隔（秒）
    public var p75: Double

    // 短键名压缩序列化体积。
    private enum CodingKeys: String, CodingKey {
        case mean = "mn"
        case stdDev = "sd"
        case median = "md"
        case p25 = "p2"
        case p75 = "p7"
    }

    public init(
        mean: Double,
        stdDev: Double,
        median: Double,
        p25: Double,
        p75: Double
    ) {
        self.mean = mean
        self.stdDev = stdDev
        self.median = median
        self.p25 = p25
        self.p75 = p75
    }
}

// MARK: - 时序分析配置

/// 时序分析配置
/// 时序分析配置。
/// 所有阈值集中在此，便于按宿主/地区调整；默认值面向普通消费类 App 的作息分布。
public struct TemporalAnalysisConfig: Sendable {

    /// 异常检测阈值（偏离度分数）
    public var anomalyThreshold: Double

    /// 最小分析事件数；低于该值直接返回空结果，避免小样本误报
    public var minEventsForAnalysis: Int

    /// 夜间时段定义 (小时)，默认 0–5 点
    public var nightHoursRange: ClosedRange<Int>

    /// 工作时段定义 (小时)，默认 9–18 点
    public var workHoursRange: ClosedRange<Int>

    /// 高频阈值（秒），默认 60 秒
    public var highFrequencyThreshold: Double

    /// 规律性 CV 阈值，默认 0.2（CV 低于该值视为机器节拍）
    public var regularityCVThreshold: Double

    /// 全天活跃阈值（小时），默认 20
    public var fullDayActiveThreshold: Int

    public init(
        anomalyThreshold: Double = 2.0,
        minEventsForAnalysis: Int = 10,
        nightHoursRange: ClosedRange<Int> = 0...5,
        workHoursRange: ClosedRange<Int> = 9...18,
        highFrequencyThreshold: Double = 60,
        regularityCVThreshold: Double = 0.2,
        fullDayActiveThreshold: Int = 20
    ) {
        self.anomalyThreshold = anomalyThreshold
        self.minEventsForAnalysis = minEventsForAnalysis
        self.nightHoursRange = nightHoursRange
        self.workHoursRange = workHoursRange
        self.highFrequencyThreshold = highFrequencyThreshold
        self.regularityCVThreshold = regularityCVThreshold
        self.fullDayActiveThreshold = fullDayActiveThreshold
    }
    
    /// 默认配置的单例入口，避免各处重复构造。
    public static let `default` = TemporalAnalysisConfig()
}

// MARK: - 风险历史事件（扩展）

/// 风险历史事件（扩展版，支持时序分析）
/// 供时序分析使用的历史事件（RiskHistoryEvent 的扩展视图）。
/// 只包含评分结果与场景/动作标签，不包含设备指纹或原始行为样本。
public struct TemporalRiskHistoryEvent: Sendable, Codable {

    /// 事件发生时间（Unix 时间戳）
    public var timestamp: TimeInterval
    /// 当次风险分数
    public var score: Double
    /// 是否命中高风险
    public var isHighRisk: Bool
    /// 事件摘要（用于展示/排查）
    public var summary: String
    /// 风险场景标签
    public var scenario: RiskScenario?
    /// 当次处置动作
    public var action: RiskAction?
    /// 扩展键值对；应避免写入可识别个人身份的信息
    public var extras: [String: String]

    // 短键名压缩序列化体积。
    private enum CodingKeys: String, CodingKey {
        case timestamp = "ts"
        case score = "s"
        case isHighRisk = "hr"
        case summary = "sm"
        case scenario = "sc"
        case action = "a"
        case extras = "ex"
    }

    public init(
        timestamp: TimeInterval,
        score: Double,
        isHighRisk: Bool,
        summary: String,
        scenario: RiskScenario? = nil,
        action: RiskAction? = nil,
        extras: [String: String] = [:]
    ) {
        self.timestamp = timestamp
        self.score = score
        self.isHighRisk = isHighRisk
        self.summary = summary
        self.scenario = scenario
        self.action = action
        self.extras = extras
    }
    
    /// 获取日期（按时间戳换算）。
    public var date: Date {
        return Date(timeIntervalSince1970: timestamp)
    }

    /// 获取小时 (0-23)，使用当前时区日历。
    public var hour: Int {
        return Calendar.current.component(.hour, from: date)
    }

    /// 获取星期几 (1-7，1 为周日，遵循 Calendar 约定)
    public var weekday: Int {
        return Calendar.current.component(.weekday, from: date)
    }

    /// 是否在夜间（默认 0–5 点，与 TemporalAnalysisConfig 默认值一致）。
    public func isNight(hoursRange: ClosedRange<Int> = 0...5) -> Bool {
        return hoursRange.contains(hour)
    }

    /// 是否在工作时间（默认 9–18 点，与 TemporalAnalysisConfig 默认值一致）。
    public func isWorkHours(hoursRange: ClosedRange<Int> = 9...18) -> Bool {
        return hoursRange.contains(hour)
    }
}

// MARK: - 便捷扩展

/// 事件数组的时序便捷操作。
/// 所有方法都先排序再计算，调用方无需保证入参有序。
extension Array where Element == TemporalRiskHistoryEvent {

    /// 按时间升序排序（稳定排序，同一时间戳保持原有相对顺序）。
    public func sortedByTime() -> [TemporalRiskHistoryEvent] {
        return sorted { $0.timestamp < $1.timestamp }
    }

    /// 筛选时间窗口内的事件（左闭右开，见 TimeWindow.contains）。
    public func filtered(by window: TimeWindow) -> [TemporalRiskHistoryEvent] {
        return filter { window.contains($0.timestamp) }
    }

    /// 计算相邻事件间隔（秒）；不足 2 个事件时返回空数组。
    public func calculateIntervals() -> [Double] {
        let sorted = sortedByTime()
        guard sorted.count > 1 else { return [] }

        var intervals: [Double] = []
        for i in 1..<sorted.count {
            intervals.append(sorted[i].timestamp - sorted[i-1].timestamp)
        }
        return intervals
    }

    /// 计算平均间隔（秒）；无间隔样本时返回 nil。
    public func averageInterval() -> Double? {
        let intervals = calculateIntervals()
        return intervals.isEmpty ? nil : (intervals.reduce(0, +) / Double(intervals.count))
    }
}
