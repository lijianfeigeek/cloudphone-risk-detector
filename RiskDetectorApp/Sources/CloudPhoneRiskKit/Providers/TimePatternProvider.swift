import Foundation

// 时间模式 Provider。
// 读取 `RiskHistoryStore` 中最近 24 小时的评估事件分布，识别高频、全天候、夜间、
// 短间隔等非人类操作节奏；同时检测系统时间跳变、启动时间回滚与安装日期异常。
// 这些信号多用于识别自动化农场/云手机集群，且依赖历史持久化，首次运行不会产生。

/// 时间维度风险提供者：输出 `high_volume_24h`、`wide_hour_coverage`、
/// `night_activity_high`、`high_frequency` 以及时间线异常信号。
final class TimePatternProvider: RiskSignalProvider {
    static let shared = TimePatternProvider()
    private init() {}

    let id = "time_pattern"
    // UserDefaults 键：保存上次评估时推算的开机时刻，用于发现系统时间被回拨/前跳。
    private static let lastClockOffsetKey = "cprk_time_pattern.last_clock_offset"
    private static let lastBootTimeKey = "cprk_time_pattern.last_boot_time"
    // 时间跳变阈值：300s 容忍 NTP 校时与轻微漂移，超过才视为异常。
    private static let systemTimeJumpThreshold: TimeInterval = 300
    // 启动时间回滚阈值：120s 容忍正常重启抖动。
    private static let bootTimeRollbackThreshold: TimeInterval = 120
    // 安装日期允许落在未来的容差，避免时区/时钟误差误报。
    private static let installDateFutureThreshold: TimeInterval = 300
    // 安装日期最大合理年龄（10 年），超过视为伪造或设备农场批量装机。
    private static let installDateMaxAgeDays: Double = 3650

    /// 汇总 24 小时行为节律与时间线异常。
    /// 各阈值同时要求最小事件量，防止新装 App 因样本过少误报。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let pattern = RiskHistoryStore.shared.pattern()
        var out: [RiskSignal] = []

        // 24h 事件量分档：500 次以上为高频农场特征，200 次以上为可疑。
        if pattern.events24h >= 500 {
            out.append(RiskSignal(id: SignalID.highVolume24h, category: SignalCategory.time, score: 15, evidence: ["events24h": "\(pattern.events24h)"]))
        } else if pattern.events24h >= 200 {
            out.append(RiskSignal(id: SignalID.mediumVolume24h, category: SignalCategory.time, score: 8, evidence: ["events24h": "\(pattern.events24h)"]))
        }

        // 覆盖 18 个不同小时且事件量足够，说明活动跨越昼夜，接近机器 24h 运行。
        if pattern.uniqueHours24h >= 18, pattern.events24h >= 80 {
            out.append(RiskSignal(id: SignalID.wideHourCoverage, category: SignalCategory.time, score: 12, evidence: ["uniqueHours24h": "\(pattern.uniqueHours24h)"]))
        }

        // 夜间（由 RiskHistoryStore 定义）事件占比 > 40%，与正常作息不符。
        if let night = pattern.nightRatio24h, night > 0.4, pattern.events24h >= 80 {
            out.append(RiskSignal(id: SignalID.nightActivityHigh, category: SignalCategory.time, score: 10, evidence: ["nightRatio24h": "\(night)"]))
        }

        // 平均间隔 < 8s 说明评估由脚本/批处理驱动，而非用户交互。
        if let avg = pattern.averageIntervalSeconds24h, avg < 8, pattern.events24h >= 80 {
            out.append(RiskSignal(id: SignalID.highFrequency, category: SignalCategory.time, score: 8, evidence: ["avgIntervalSec": "\(avg)"]))
        }

        out.append(contentsOf: timelineSignals(snapshot: snapshot))
        return out
    }

    /// 检测系统时间跳变、启动时间回滚和安装日期异常。
    /// - `bootTime = now - systemUptime`：由两个独立时钟推算的开机时刻；
    /// - 与上次记录差异过大说明系统时间被修改或设备被快照回滚；
    /// - 每次调用都会更新 UserDefaults 基准，供下次比较。
    private func timelineSignals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let now = Date().timeIntervalSince1970
        let bootTime = now - ProcessInfo.processInfo.systemUptime
        let defaults = UserDefaults.standard
        var out: [RiskSignal] = []

        // 系统时间前跳/回拨会同时改变 now 与 bootTime 的差值；超过 300s 视为异常。
        if let previousOffset = defaults.object(forKey: Self.lastClockOffsetKey) as? Double {
            let delta = abs(bootTime - previousOffset)
            if delta >= Self.systemTimeJumpThreshold {
                out.append(
                    RiskSignal(
                        id: SignalID.systemTimeJump,
                        category: SignalCategory.time,
                        score: 0,
                        evidence: [
                            "current_offset": String(format: "%.0f", bootTime),
                            "previous_offset": String(format: "%.0f", previousOffset),
                            "delta_seconds": String(format: "%.0f", delta),
                        ],
                        state: .soft(confidence: 0.75),
                        layer: 2,
                        weightHint: 45
                    )
                )
            }
        }

        // 当前推算的开机时刻明显早于上次记录，说明时间线被回退（如恢复快照/改时钟）。
        if let previousBootTime = defaults.object(forKey: Self.lastBootTimeKey) as? Double,
           bootTime + Self.bootTimeRollbackThreshold < previousBootTime {
            out.append(
                RiskSignal(
                    id: SignalID.bootTimeRollback,
                    category: SignalCategory.time,
                    score: 0,
                    evidence: [
                        "current_boot_time": String(format: "%.0f", bootTime),
                        "previous_boot_time": String(format: "%.0f", previousBootTime),
                        "delta_seconds": String(format: "%.0f", previousBootTime - bootTime),
                    ],
                    state: .soft(confidence: 0.8),
                    layer: 2,
                    weightHint: 50
                )
            )
        }

        // 安装日期落在未来（>300s 容差）或早于 10 年，均不符合正常 App 安装生命周期。
        if let installDate = BundleInfo.shared.installDate?.timeIntervalSince1970 {
            let ageDays = (now - installDate) / 86_400
            if installDate > now + Self.installDateFutureThreshold || ageDays > Self.installDateMaxAgeDays {
                out.append(
                    RiskSignal(
                        id: SignalID.installDateUnusual,
                        category: SignalCategory.time,
                        score: 0,
                        evidence: [
                            "install_date": String(format: "%.0f", installDate),
                            "age_days": String(format: "%.1f", ageDays),
                        ],
                        state: .soft(confidence: 0.72),
                        layer: 2,
                        weightHint: 40
                    )
                )
            }
        }

        // 覆盖基准值，供下一次评估比较；即使本次无异常也要更新。
        defaults.set(bootTime, forKey: Self.lastClockOffsetKey)
        defaults.set(bootTime, forKey: Self.lastBootTimeKey)
        _ = snapshot.deviceID
        return out
    }
}
