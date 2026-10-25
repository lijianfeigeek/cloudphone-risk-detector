// MARK: - 基于 Actor 的风险评估状态
//
// 职责：以 actor 隔离封装评估状态，替代手动 NSLock，为新的异步调用路径提供
// 编译期线程安全的状态访问；位于评估管线最外层（评估入口）。
// 安全不变量：同一时刻只有一个评估任务修改缓存与限流计数，避免数据竞争。

import Foundation

// 提供线程安全的状态隔离，替代 NSLock 手动管理。
// 新代码路径可通过此 actor 与 SDK 交互，保证状态访问不会出现数据竞争。
//
// 使用示例：
//   let result = await RiskEvaluationActor.shared.evaluate(config: .default, scenario: .payment)

/// Actor 化的风险评估状态容器 —— 提供编译期线程安全保证。
///
/// 与 `CPRiskKit` 的 NSLock 方案共存，新增的 async/await 调用路径优先走此 actor。
/// 内部代理到 `CPRiskKit.shared` 的同步方法，actor 隔离保证同一时间只有一个评估任务修改状态。
@available(iOS 13.0, macOS 10.15, *)
public actor RiskEvaluationActor {

    /// 进程内共享实例
    public static let shared = RiskEvaluationActor()

    // MARK: - 评估状态

    /// 上一次评估结果缓存（仅在限流触发时返回）
    private var lastVerdict: CPRiskReport?

    /// 上一次评估时间（用于计算调用间隔）
    private var lastEvaluationTime: Date?

    /// 连续快速评估次数（用于限流判定）
    private var consecutiveEvaluations: Int = 0

    /// 限流冷却期（秒）：两次评估间隔小于该值时视为高频调用
    private let rateLimitCooldown: TimeInterval = 0.5

    // MARK: - 评估入口

    /// 执行风险评估（actor 隔离，编译期线程安全）。
    /// - Parameters:
    ///   - config: 风险评估配置，默认 `.default`。
    ///   - scenario: 业务场景，默认 `.default`。
    /// - Returns: 本次（或限流时缓存的）评估报告。
    public func evaluate(
        config: CPRiskConfig = .default,
        scenario: RiskScenario = .default
    ) -> CPRiskReport {
        // 限流检查：连续快速调用超过阈值时返回缓存结果
        if let lastTime = lastEvaluationTime,
           Date().timeIntervalSince(lastTime) < rateLimitCooldown {
            consecutiveEvaluations += 1
            // 阈值 10：避免调用方在极短时间内重复触发昂贵的设备采集与检测
            if consecutiveEvaluations > 10 {
                Logger.warn("RiskEvaluationActor: rate limited — \(consecutiveEvaluations) rapid evaluations")
                // 有缓存则复用；无缓存时仍继续执行，避免返回空结果
                if let cached = lastVerdict {
                    return cached
                }
            }
        } else {
            // 间隔足够长，视为新的评估周期，重置计数
            consecutiveEvaluations = 0
        }

        lastEvaluationTime = Date()

        // 代理到 CPRiskKit 的同步方法（CPRiskKit 内部有自己的锁保护）
        let report = CPRiskKit.shared.evaluate(config: config, scenario: scenario)
        lastVerdict = report
        return report
    }

    /// 获取上一次评估结果。
    /// - Returns: 最近一次评估报告；尚未评估时返回 `nil`。
    public func lastResult() -> CPRiskReport? {
        lastVerdict
    }

    /// 重置评估状态（用于注销或测试场景）。
    public func reset() {
        lastVerdict = nil
        lastEvaluationTime = nil
        consecutiveEvaluations = 0
    }
}
