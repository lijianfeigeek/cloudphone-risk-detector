// 行为信号聚合模型：把触摸指标、运动指标与两者的耦合系数打包成可序列化结构，
// 作为 RiskSnapshot 的行为子块，供基线比较、异常检测与云端上报使用。
// 所有字段都是聚合统计量，不含原始触摸点或传感器序列，符合最小化采集原则。
import Foundation

/// 单次评估窗口内的行为统计摘要。
/// 值类型且 `Sendable`，可安全跨 actor 传递；序列化键使用短名以压缩 payload。
/// 下游 RiskScorer 按阈值逐项转换为 `category = behavior` 的 RiskSignal（如 `touchIntervalTooRegular`）。
public struct BehaviorSignals: Codable, Sendable {
    /// 触摸统计（样本量、点击/滑动次数、力度与轨迹特征）
    public var touch: TouchMetrics
    /// 运动统计（样本量、静止占比、平均能量）
    public var motion: MotionMetrics
    /// 触摸动作密度与运动能量的 Pearson 相关系数，范围 [-1, 1]；nil 表示任一侧样本不足
    public var touchMotionCorrelation: Double?
    /// 窗口内动作总数（点击 + 滑动），用于基线中的操作量维度
    public var actionCount: Int

    // 短键名压缩落盘/上报体积；键名属于持久化契约，修改会导致旧数据解码失败。
    private enum CodingKeys: String, CodingKey {
        case touch = "t"
        case motion = "m"
        case touchMotionCorrelation = "tc"
        case actionCount = "ac"
    }

    /// - Parameter actionCount: 传 nil 时由 `tapCount + swipeCount` 推导，兼容仅采集触摸侧的调用方。
    init(touch: TouchMetrics, motion: MotionMetrics, touchMotionCorrelation: Double? = nil, actionCount: Int? = nil) {
        self.touch = touch
        self.motion = motion
        self.touchMotionCorrelation = touchMotionCorrelation
        self.actionCount = actionCount ?? (touch.tapCount + touch.swipeCount)
    }

    // MARK: - 样本充足性

    /// 行为信号统计可靠的最小触摸样本量
    public static let minimumTouchSamples = 15
    /// 行为信号统计可靠的最小动作数（tap + swipe）
    public static let minimumActionCount = 8
    /// 传感器耦合分析的最小运动样本量
    public static let minimumMotionSamples = 40

    /// 触摸样本是否达到统计可靠的最小阈值
    public var hasSufficientTouchSamples: Bool {
        // 同时要求原始点数与动作数：只有大量 moved 点而缺少 completed 动作时仍不可信。
        touch.sampleCount >= Self.minimumTouchSamples && actionCount >= Self.minimumActionCount
    }

    /// 运动样本是否达到统计可靠的最小阈值
    public var hasSufficientMotionSamples: Bool {
        motion.sampleCount >= Self.minimumMotionSamples
    }

    /// 样本充足性等级，用于评分引擎判断行为信号的置信度
    public enum SampleSufficiency: Sendable {
        /// 样本充足，分析结果可信
        case sufficient
        /// 样本不足，分析结果应降权或忽略
        case insufficient
        /// 无有效样本
        case none
    }

    /// 当前行为数据的样本充足性。
    /// 运动侧单独充足不影响结论：行为判定以触摸侧为主，运动只作为耦合佐证。
    public var sampleSufficiency: SampleSufficiency {
        if touch.sampleCount == 0 && motion.sampleCount == 0 { return .none }
        if hasSufficientTouchSamples { return .sufficient }
        return .insufficient
    }
}

/// 触摸行为统计。
/// 所有可空字段为 `nil` 表示对应维度样本不足或设备不支持（如无 3D Touch 时的力度），
/// 下游评分应跳过而不是按 0 处理，否则会把“未知”误判成“异常”。
public struct TouchMetrics: Codable, Sendable {
    /// 窗口内采集到的原始触摸点数量
    public var sampleCount: Int
    /// 判定为点击的抬手次数（路径少于 2 个点）
    public var tapCount: Int
    /// 判定为滑动的抬手次数（路径至少 2 个点）
    public var swipeCount: Int
    /// 触摸点相对质心的平均距离（pt），衡量操作区域是否集中
    public var coordinateSpread: Double?
    /// 点击时间间隔的变异系数（标准差/均值），越大越不规律
    public var intervalCV: Double?
    /// 滑动路径直线度（首尾直线距离/实际路径长度），1 表示完全直线
    public var averageLinearity: Double?
    /// 按压力度方差；仅部分支持 3D Touch / 压感的设备有值
    public var forceVariance: Double?
    /// 接触半径方差，用于近似触控面积波动
    public var majorRadiusVariance: Double?
    /// 滑动速度的变异系数，反映手势速度稳定性
    public var swipeSpeedCV: Double?

    // 短键名压缩体积；字段语义与键名解耦，改名需同步云端解析。
    private enum CodingKeys: String, CodingKey {
        case sampleCount = "sc"
        case tapCount = "tp"
        case swipeCount = "sw"
        case coordinateSpread = "cs"
        case intervalCV = "cv"
        case averageLinearity = "al"
        case forceVariance = "fv"
        case majorRadiusVariance = "mr"
        case swipeSpeedCV = "ss"
    }
}

/// 运动行为统计。
/// 无传感器、用户关闭运动权限或非 iOS 平台时整体为 `empty`，行为分析自动降级为仅触摸维度。
public struct MotionMetrics: Codable, Sendable {
    /// 窗口内运动采样条数（20Hz 采样）
    public var sampleCount: Int
    /// 静止样本占比，静止判定阈值为加速度模长 < 0.02g
    public var stillnessRatio: Double?
    /// 平均运动能量（去重力加速度模长均值，单位约 g）
    public var motionEnergy: Double?

    // 短键名压缩体积。
    private enum CodingKeys: String, CodingKey {
        case sampleCount = "sc"
        case stillnessRatio = "sr"
        case motionEnergy = "me"
    }

    /// 无样本时的中性值；可空字段保持 nil 以表达“未知”，而非 0。
    public static let empty = MotionMetrics(sampleCount: 0, stillnessRatio: nil, motionEnergy: nil)
}
