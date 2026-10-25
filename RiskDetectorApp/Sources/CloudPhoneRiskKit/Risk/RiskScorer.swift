// 传统本地计分器（已废弃/死代码）：把越狱置信度、网络信号、行为启发式与扩展信号
// 加权汇总为 0–100 分，并按 `RiskConfig.threshold` 给出 `isHighRisk` 判决。
// 计分入口为 `score(context:config:extraSignals:)`；权重全部是本文件内置的固定值，
// 不读取 `weightHint`、服务端覆盖或抖动（这些由主链路 RiskDetectionEngine 处理）。
// 安全不变量：越狱命中时分数至少抬升到阈值；总分与越狱置信度均受 scoreCap 约束。
import Foundation

// MARK: - Risk Scorer
//
// ⚠️ DEPRECATED / 死代码：仓库内无调用方，主评分链路使用
// `RiskDetectionEngine`（见 LocalAssessment/RiskDetectionEngine.swift）。
// 本文件未物理删除：Xcode 工程（project.pbxproj，不在本任务可改目录内）
// 显式引用了它，删除源文件会破坏工程文件索引；如需清理，请由工程
// 维护方同时移除 pbxproj 中的引用后再删除本文件。
/// 已废弃的本地计分器；保留仅为避免破坏 Xcode 工程索引。
@available(*, deprecated, message: "无调用方；主评分链路使用 RiskDetectionEngine")
enum RiskScorer {
    // MARK: - Scoring Constants

    /// 总分和越狱置信度的上限
    private static let scoreCap: Double = 100
    /// 越狱信号权重：越狱置信度按 0.6 折算，作为第一道防线（最高权重）
    private static let jailbreakWeight: Double = 0.6
    /// VPN 信号固定加分
    private static let vpnScore: Double = 10
    /// 代理信号固定加分
    private static let proxyScore: Double = 8
    /// 扩展信号（provider）总加分上限，防止插件信号淹没核心证据
    private static let maxExtraSignalsScore: Double = 20

    // MARK: - Behavior Scores (fixed point values, not remotely configurable)
    // 以下行为分值是写死的校准值，不随远程配置变化，保证本地行为模型可解释、可复现。

    /// 坐标离散度过低（落点集中）
    private static let touchSpreadLowScore: Double = 12
    /// 坐标离散度过高（落点发散）
    private static let touchSpreadHighScore: Double = 4
    /// 点击间隔过于规律
    private static let touchIntervalRegularScore: Double = 10
    /// 点击间隔过于混乱
    private static let touchIntervalChaoticScore: Double = 4
    /// 滑动轨迹过于笔直
    private static let swipeTooLinearScore: Double = 8
    /// 滑动轨迹过于弯曲
    private static let swipeTooCurvyScore: Double = 4
    /// 设备过于静止
    private static let motionTooStillScore: Double = 10
    /// 触摸与运动弱耦合
    private static let touchMotionWeakCouplingScore: Double = 8
    /// 按压力度过于均匀
    private static let forceTooUniformScore: Double = 10
    /// 接触半径过于均匀
    private static let radiusTooUniformScore: Double = 8
    /// 滑动速度过于规律
    private static let swipeSpeedTooRegularScore: Double = 6
    /// 样本不足的软兜底分
    private static let insufficientDataScore: Double = 5
    /// 升格分:app 被实际驱动(actionCount≥地板)却零真实触摸样本时,这是合成/自动化输入
    /// 的高精度签名(真人完成 ≥8 次操作不可能产生 0 触摸样本)。比软兜底 +5 显著更强,
    /// 落实"最需要检测时不能最弱"(#10/#11)。单独仍非 block 级,与其它信号叠加才升级。
    private static let interactionExpectedButAbsentScore: Double = 25

    // MARK: - Behavior Sample Counts (fixed)
    // 各启发式的最小样本门槛：样本不足时统计量（方差、Pearson 相关等）不可靠，直接不参与计分。

    private static let minSwipesForLinearity = 3
    private static let minActionsForStillness = 10
    private static let minActionsForCorrelation = 10
    private static let minForceSamples = 6
    private static let minRadiusSamples = 6

    /// 本地计分入口（legacy）。
    /// - Parameters:
    ///   - context: 本次评估上下文（越狱/网络/行为原始信号）。
    ///   - config: 阈值与开关；`enableNetworkSignals`/`enableBehaviorDetect` 控制分项是否参与。
    ///   - extraSignals: provider 追加的信号，按 `category::id` 去重后汇总，最多计 `maxExtraSignalsScore` 分。
    /// - Returns: 0–100 的分数、是否高风险、参与计分的信号与文字摘要。
    /// 说明：本函数只使用内置固定权重；`weightHint`/服务端覆盖/抖动由新引擎负责。
    static func score(context: RiskContext, config: RiskConfig, extraSignals: [RiskSignal] = []) -> RiskScoreReport {
        var total: Double = 0
        var signals: [RiskSignal] = []

        // 越狱是强信号簇：先对置信度封顶，再按权重折算，避免单项直接拉满总分。
        let jbScore = min(context.jailbreak.confidence, scoreCap)
        if jbScore > 0 {
            // 越狱是第一道防线，使用最高权重（0.6）。
            let jbContribution = jbScore * jailbreakWeight
            total += jbContribution
            signals.append(
                RiskSignal(
                    id: SignalID.jailbreak,
                    category: SignalCategory.jailbreak,
                    score: jbScore,
                    evidence: [
                        "is_jailbroken": "\(context.jailbreak.isJailbroken)",
                        "hits": "\(context.jailbreak.detectedMethods.count)",
                    ]
                )
            )
            #if DEBUG
            Logger.log("score +\(jbContribution) from jailbreak(conf=\(context.jailbreak.confidence))")
            #endif
        }

        // 网络信号可整体关闭（如企业内网/无网络场景），关闭后不影响其它分项。
        if config.enableNetworkSignals {
            if context.network.isVPNActive {
                total += vpnScore
                signals.append(RiskSignal(id: SignalID.vpnActive, category: SignalCategory.network, score: vpnScore, evidence: [:]))
                #if DEBUG
                Logger.log("score +\(vpnScore) from vpn_active")
                #endif
            }
            if context.network.proxyEnabled {
                total += proxyScore
                signals.append(RiskSignal(id: SignalID.proxyEnabled, category: SignalCategory.network, score: proxyScore, evidence: [:]))
                #if DEBUG
                Logger.log("score +\(proxyScore) from proxy_enabled")
                #endif
            }
        }

        // 行为检出自带样本门槛；关闭后完全不采信行为分。
        if config.enableBehaviorDetect {
            let thresholds = config.behaviorThresholds ?? .default
            let b = behaviorScore(behavior: context.behavior, thresholds: thresholds)
            total += b.score
            signals.append(contentsOf: b.signals)
            #if DEBUG
            Logger.log("score +\(b.score) from behavior(signals=\(b.signals.count))")
            #endif
        }

        if !extraSignals.isEmpty {
            // 按 category::id 去重：多个 provider 观测到同一检测面时只计一次，避免重复计分。
            var seen = Set<String>()
            var unique: [RiskSignal] = []
            for s in extraSignals {
                let key = "\(s.category)::\(s.id)"
                if seen.contains(key) { continue }
                seen.insert(key)
                unique.append(s)
            }
            let pluginScoreRaw = unique.map(\.score).filter { $0 > 0 }.reduce(0, +)
            // 先求和再封顶：防止大量低分 provider 信号叠加后击穿阈值。
            let pluginScore = min(pluginScoreRaw, maxExtraSignalsScore)
            total += pluginScore
            signals.append(contentsOf: unique)
            #if DEBUG
            Logger.log("score +\(pluginScore) from providers(raw=\(pluginScoreRaw) signals=\(extraSignals.count) unique=\(unique.count))")
            #endif
        }

        // 分数归一化/封顶：所有来源累加后统一裁剪到 0–100，保证下游阈值语义稳定。
        total = min(total, scoreCap)
        // 越狱命中直接判高风险，不依赖分数是否达到阈值。
        let isHighRisk = (total >= config.threshold) || context.jailbreak.isJailbroken
        if context.jailbreak.isJailbroken, total < config.threshold {
            // 硬判决：越狱时把分数抬到阈值，保证下游按高风险处置而不是看运气。
            total = min(config.threshold, scoreCap)
        }
        #if DEBUG
        Logger.log("score total=\(total) threshold=\(config.threshold) isHighRisk=\(isHighRisk)")
        #endif
        return RiskScoreReport(
            score: total,
            isHighRisk: isHighRisk,
            signals: signals,
            summary: summary(score: total, isHighRisk: isHighRisk, jailbreak: context.jailbreak),
            compressedDigest: nil,
            mappingVersion: nil
        )
    }

    /// 计算行为分与对应信号。
    /// 先检查样本充分性：不足时不再运行线性/相关性等统计启发式，避免小样本误判。
    /// - Returns: 行为分（不超过 `thresholds.maxBehaviorScore`）与命中的信号。
    private static func behaviorScore(behavior: BehaviorSignals, thresholds: BehaviorThresholds) -> (score: Double, signals: [RiskSignal]) {
        var total: Double = 0
        var signals: [RiskSignal] = []

        // 样本不足时跳过高置信度启发式（防止低样本量下 Pearson 相关等统计量误判）。
        // 但“样本不足”不再一律软兜底 +5：若 app 实际被驱动（actionCount 过人类活动地板）
        // 却没有真实触摸足迹（touch 样本为 0），这是合成/自动化输入的高精度签名——
        // 自动化最擅长在“无交互样本”窗口让强启发式全沉默，旧的 +5 等于“最需要检测时最弱”。
        // 此处对该情形升格（#10 低交互升格 / #11 基线建立期不可信），其余冷启动/空闲仍 +5。
        switch behavior.sampleSufficiency {
        case .none, .insufficient:
            let reason = behavior.sampleSufficiency == .none ? "no_samples" : "below_minimum_threshold"
            // 操作发生但零真实触摸足迹 = 该有交互却没有 → fail-closed 升格。
            let interactionExpectedButAbsent =
                behavior.actionCount >= BehaviorSignals.minimumActionCount
                && behavior.touch.sampleCount == 0
            if interactionExpectedButAbsent {
                return (interactionExpectedButAbsentScore, [RiskSignal(
                    id: SignalID.behaviorInteractionExpectedButAbsent,
                    category: SignalCategory.behavior,
                    score: interactionExpectedButAbsentScore,
                    evidence: [
                        "actionCount": "\(behavior.actionCount)",
                        "touchSampleCount": "\(behavior.touch.sampleCount)",
                        "motionSampleCount": "\(behavior.motion.sampleCount)",
                        "reason": "actions_without_touch_footprint",
                        "policy": "fail_closed_low_interaction",
                    ]
                )])
            }
            return (insufficientDataScore, [RiskSignal(
                id: SignalID.insufficientBehaviorData,
                category: SignalCategory.behavior,
                score: insufficientDataScore,
                evidence: [
                    "tapCount": "\(behavior.touch.tapCount)",
                    "sampleCount": "\(behavior.touch.sampleCount)",
                    "motionSampleCount": "\(behavior.motion.sampleCount)",
                    "actionCount": "\(behavior.actionCount)",
                    "reason": reason,
                    "minimumRequired": "\(BehaviorSignals.minimumTouchSamples)",
                ]
            )])
        case .sufficient:
            break // 样本充足，继续执行启发式分析
        }

        // 坐标离散度是触摸几何特征：过低像脚本固定落点，过高像随机注入。
        if let spread = behavior.touch.coordinateSpread, spread < thresholds.touchSpreadLow {
            total += touchSpreadLowScore
            signals.append(RiskSignal(id: SignalID.touchSpreadLow, category: SignalCategory.behavior, score: touchSpreadLowScore, evidence: ["spread": "\(spread)"]))
        }

        if let spread = behavior.touch.coordinateSpread, spread > thresholds.touchSpreadHigh {
            total += touchSpreadHighScore
            signals.append(RiskSignal(id: SignalID.touchSpreadHigh, category: SignalCategory.behavior, score: touchSpreadHighScore, evidence: ["spread": "\(spread)"]))
        }

        // 点击间隔变异系数：过低是机械节奏，过高是人工生成的混乱节奏。
        if let cv = behavior.touch.intervalCV, cv < thresholds.touchIntervalCVLow {
            total += touchIntervalRegularScore
            signals.append(RiskSignal(id: SignalID.touchIntervalTooRegular, category: SignalCategory.behavior, score: touchIntervalRegularScore, evidence: ["cv": "\(cv)"]))
        }

        if let cv = behavior.touch.intervalCV, cv > thresholds.touchIntervalCVHigh {
            total += touchIntervalChaoticScore
            signals.append(RiskSignal(id: SignalID.touchIntervalTooChaotic, category: SignalCategory.behavior, score: touchIntervalChaoticScore, evidence: ["cv": "\(cv)"]))
        }

        // 滑动线性度：过高说明轨迹是直线插值，过低说明轨迹是曲线合成；都要求足够滑动样本。
        if let lin = behavior.touch.averageLinearity, lin > thresholds.swipeLinearityHigh, behavior.touch.swipeCount >= minSwipesForLinearity {
            total += swipeTooLinearScore
            signals.append(RiskSignal(id: SignalID.swipeTooLinear, category: SignalCategory.behavior, score: swipeTooLinearScore, evidence: ["avg_linearity": "\(lin)"]))
        }

        if let lin = behavior.touch.averageLinearity, lin < thresholds.swipeLinearityLow, behavior.touch.swipeCount >= minSwipesForLinearity {
            total += swipeTooCurvyScore
            signals.append(RiskSignal(id: SignalID.swipeTooCurvy, category: SignalCategory.behavior, score: swipeTooCurvyScore, evidence: ["avg_linearity": "\(lin)"]))
        }

        // 静止率与触摸-运动相关性用于识别“有触摸事件、传感器却不动”的虚拟输入。
        if let still = behavior.motion.stillnessRatio, still > thresholds.motionStillness, (behavior.touch.tapCount + behavior.touch.swipeCount) >= minActionsForStillness {
            total += motionTooStillScore
            signals.append(RiskSignal(id: SignalID.motionTooStill, category: SignalCategory.behavior, score: motionTooStillScore, evidence: ["stillness": "\(still)"]))
        }

        if
            let corr = behavior.touchMotionCorrelation,
            corr < thresholds.touchMotionCorrelation,
            behavior.actionCount >= minActionsForCorrelation,
            (behavior.motion.stillnessRatio ?? 0) > thresholds.minStillnessForCorrelation
        {
            total += touchMotionWeakCouplingScore
            signals.append(RiskSignal(id: SignalID.touchMotionWeakCoupling, category: SignalCategory.behavior, score: touchMotionWeakCouplingScore, evidence: ["corr": "\(corr)"]))
        }

        // 力度/接触半径方差过小说明压力是常量，常见于注入事件。
        if let forceVar = behavior.touch.forceVariance,
           behavior.touch.tapCount + behavior.touch.swipeCount >= minForceSamples,
           forceVar < thresholds.forceVariance {
            total += forceTooUniformScore
            signals.append(RiskSignal(id: SignalID.forceTooUniform, category: SignalCategory.behavior, score: forceTooUniformScore, evidence: ["force_variance": "\(forceVar)"]))
        }

        if let radiusVar = behavior.touch.majorRadiusVariance,
           behavior.touch.tapCount + behavior.touch.swipeCount >= minRadiusSamples,
           radiusVar < thresholds.radiusVariance {
            total += radiusTooUniformScore
            signals.append(RiskSignal(id: SignalID.radiusTooUniform, category: SignalCategory.behavior, score: radiusTooUniformScore, evidence: ["radius_variance": "\(radiusVar)"]))
        }

        if let speedCV = behavior.touch.swipeSpeedCV,
           behavior.touch.swipeCount >= minSwipesForLinearity,
           speedCV < thresholds.swipeSpeedCV {
            total += swipeSpeedTooRegularScore
            signals.append(RiskSignal(id: SignalID.swipeSpeedTooRegular, category: SignalCategory.behavior, score: swipeSpeedTooRegularScore, evidence: ["speed_cv": "\(speedCV)"]))
        }

        // 样本不足已在函数开头的 sampleSufficiency 分支提前返回，这里不再重复检查。

        // 行为分单独封顶，给越狱/反篡改等核心证据留出权重空间。
        return (min(total, thresholds.maxBehaviorScore), signals)
    }

    /// 生成上报用的一句话摘要；越狱优先于普通高风险。
    private static func summary(score: Double, isHighRisk: Bool, jailbreak: DetectionResult) -> String {
        if jailbreak.isJailbroken {
            return "high_risk(jailbreak)"
        }
        return isHighRisk ? "high_risk" : "low_risk"
    }
}
