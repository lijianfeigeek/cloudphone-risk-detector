// 上报时机策略：按本地判决的风险等级决定“立即/延迟/批量”上报。
// 属于评估后的上报编排层，不参与风险打分本身。
// 当前仓库无调用方（见下方 deprecated 说明），保留仅为兼容 Xcode 工程索引。
// 安全不变量：本类型不处理任何密钥或载荷加密，仅做延迟计算，不能替代安全信封。

import Foundation

/// 分级上报时机策略
///
/// ⚠️ DEPRECATED / 死代码：仓库内无调用方，上报时机由调用方自行控制。
/// 本文件未物理删除：Xcode 工程（project.pbxproj，不在本任务可改目录内）
/// 显式引用了它，删除源文件会破坏工程文件索引；如需清理，请由工程
/// 维护方同时移除 pbxproj 中的引用后再删除本文件。
@available(*, deprecated, message: "无调用方；上报时机由调用方自行控制")
public struct UploadPolicy: Codable, Sendable {

    // MARK: - 风险等级

    /// 风险等级
    public enum RiskLevel: String, Codable, Sendable {
        /// 高危：立即上报
        case high
        /// 中危：延迟上报
        case medium
        /// 低危：批量上报
        case low
    }

    // MARK: - 策略配置

    /// 上报策略配置：各等级延迟范围、批量间隔与抖动比例。
    public struct PolicyConfig: Codable, Sendable {
        /// 高危上报延迟范围（秒），默认 0-2 秒
        public let highRiskDelayRange: ClosedRange<Double>
        /// 中危上报延迟范围（秒），默认 30-120 秒
        public let mediumRiskDelayRange: ClosedRange<Double>
        /// 低危批量上报间隔（秒），默认 300 秒（5 分钟）
        public let lowRiskBatchInterval: Double
        /// 随机抖动比例，默认 0.2（20%）
        public let jitterRatio: Double

        /// 线上编码使用短键，减小载荷体积；字段语义不变。
        private enum CodingKeys: String, CodingKey {
            case highRiskDelayRange = "hr"
            case mediumRiskDelayRange = "mr"
            case lowRiskBatchInterval = "lb"
            case jitterRatio = "jr"
        }

        /// 默认配置
        public static let `default` = PolicyConfig(
            highRiskDelayRange: 0...2,
            mediumRiskDelayRange: 30...120,
            lowRiskBatchInterval: 300,
            jitterRatio: 0.2
        )

        /// 创建策略配置；参数缺省时使用默认值。
        public init(
            highRiskDelayRange: ClosedRange<Double> = 0...2,
            mediumRiskDelayRange: ClosedRange<Double> = 30...120,
            lowRiskBatchInterval: Double = 300,
            jitterRatio: Double = 0.2
        ) {
            self.highRiskDelayRange = highRiskDelayRange
            self.mediumRiskDelayRange = mediumRiskDelayRange
            self.lowRiskBatchInterval = lowRiskBatchInterval
            self.jitterRatio = jitterRatio
        }
    }

    // MARK: - 属性

    /// 风险评分阈值配置
    /// 分数大于等于 highRiskThreshold 判为高危，大于等于 mediumRiskThreshold 判为中危。
    private let highRiskThreshold: Int    // 默认 80
    private let mediumRiskThreshold: Int  // 默认 50

    /// 当前策略配置
    public let config: PolicyConfig

    /// 线上编码短键：与 PolicyConfig 一样用于压缩载荷。
    private enum CodingKeys: String, CodingKey {
        case highRiskThreshold = "ht"
        case mediumRiskThreshold = "mt"
        case config = "c"
    }

    // MARK: - 初始化

    /// 使用默认配置初始化
    public init(
        highRiskThreshold: Int = 80,
        mediumRiskThreshold: Int = 50,
        config: PolicyConfig = .default
    ) {
        self.highRiskThreshold = highRiskThreshold
        self.mediumRiskThreshold = mediumRiskThreshold
        self.config = config
    }

    // MARK: - 公开方法

    /// 根据评分计算风险等级
    /// - Parameter score: 风险评分 (0-100)
    /// - Returns: 对应的风险等级
    public func riskLevel(for score: Int) -> RiskLevel {
        // 阈值比较使用 >=，保证边界分数（如 80）归入更高等级。
        if score >= highRiskThreshold {
            return .high
        } else if score >= mediumRiskThreshold {
            return .medium
        } else {
            return .low
        }
    }

    /// 计算实际延迟（包含随机抖动）
    /// - Parameter score: 风险评分 (0-100)
    /// - Returns: 延迟秒数
    public func calculateDelay(for score: Int) -> Double {
        let level = riskLevel(for: score)

        let baseDelay: Double
        switch level {
        case .high:
            // 范围内随机，避免固定节奏被攻击者识别。
            baseDelay = Double.random(in: config.highRiskDelayRange)
        case .medium:
            baseDelay = Double.random(in: config.mediumRiskDelayRange)
        case .low:
            baseDelay = config.lowRiskBatchInterval
        }

        // 添加随机抖动（±0.5 范围，避免抖动量超过延迟本身）
        let jitter = baseDelay * config.jitterRatio * Double.random(in: -0.5...0.5)
        // 夹到非负，防止负延迟传入定时器。
        return max(0, baseDelay + jitter)
    }

    /// 判断是否应该立即上报
    /// - Parameter score: 风险评分 (0-100)
    /// - Returns: 是否应该立即上报
    public func shouldImmediateUpload(score: Int) -> Bool {
        return riskLevel(for: score) == .high
    }

    /// 判断是否应该批量上报
    /// - Parameter score: 风险评分 (0-100)
    /// - Returns: 是否应该批量上报
    public func shouldBatch(score: Int) -> Bool {
        return riskLevel(for: score) == .low
    }

    /// 获取下次批量上报的剩余时间
    /// - Parameter lastBatchTime: 上次批量上报的时间戳
    /// - Returns: 剩余秒数，如果应该立即上报则返回 0
    public func nextBatchDelay(since lastBatchTime: TimeInterval) -> Double {
        let elapsed = Date().timeIntervalSince1970 - lastBatchTime
        let remaining = config.lowRiskBatchInterval - elapsed
        // 夹到非负：已超过间隔时返回 0，表示可以立即批量上报。
        return max(0, remaining)
    }
}

// MARK: - 便捷工厂

extension UploadPolicy {

    /// 严格模式配置（更敏感的上报策略）
    public static let strict = UploadPolicy(
        highRiskThreshold: 70,
        mediumRiskThreshold: 40,
        config: PolicyConfig(
            highRiskDelayRange: 0...1,
            mediumRiskDelayRange: 15...60,
            lowRiskBatchInterval: 180,
            jitterRatio: 0.1
        )
    )

    /// 宽松模式配置（较少干扰的上报策略）
    public static let lenient = UploadPolicy(
        highRiskThreshold: 90,
        mediumRiskThreshold: 60,
        config: PolicyConfig(
            highRiskDelayRange: 0...5,
            mediumRiskDelayRange: 60...300,
            lowRiskBatchInterval: 600,
            jitterRatio: 0.3
        )
    )
}
