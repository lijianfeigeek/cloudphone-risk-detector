import Foundation
#if canImport(IOKit)
import IOKit
import IOKit.ps
#endif
#if canImport(UIKit)
import UIKit
#endif

// 电池熵信号提供者。
// 通过充电计数器、电压序列方差、能量计数器三路数据判断供电环境是否“过于平稳”：
// 云手机/虚拟化环境通常没有真实电池，计数固定为 0/-1，电压采样方差接近零。
// 所有结论均为弱/中置信度佐证，需与其他设备类信号组合使用。

/// 电池原始数据采集器，按平台选择可用 API。
/// - iOS：`UIDevice` 的电池电量比例（0...1）；
/// - macOS：`IOKit.ps` 电源描述中的电压/电荷/能量计数；
/// - 模拟器或平台不支持时返回空序列 / nil。
struct BatteryEntropyCollector {
    /// 采集电压（iOS 上为电量比例×1000）时间序列。
    /// - Parameters:
    ///   - samples: 目标采样点数；采不到足够点也会返回已采部分。
    ///   - interval: 相邻采样点的休眠间隔（秒），会同步阻塞调用线程。
    /// - Returns: 采样序列；模拟器或不支持的平台返回空数组。
    func collectVoltageSeries(samples: Int, interval: TimeInterval) -> [Double] {
        #if targetEnvironment(simulator)
        return []
        #elseif canImport(UIKit)
        return collectFromUIDevice(samples: samples, interval: interval)
        #elseif canImport(IOKit)
        return collectFromIOKit(samples: samples, interval: interval)
        #else
        return []
        #endif
    }

    /// 计算样本方差（除以 n-1）。
    /// - 少于 2 个样本返回 0，表示无法判断波动性。
    func computeVariance(_ series: [Double]) -> Double {
        guard series.count > 1 else { return 0 }
        let mean = series.reduce(0, +) / Double(series.count)
        let squaredDiffs = series.map { pow($0 - mean, 2) }
        return squaredDiffs.reduce(0, +) / Double(series.count - 1)
    }

    /// 读取电荷计数器；仅 macOS + IOKit 可用，iOS/模拟器返回 nil。
    /// 真实电池的计数会随充放电缓慢变化，固定值往往意味着虚拟电源。
    func readChargeCounter() -> Int? {
        #if targetEnvironment(simulator)
        return nil
        #elseif os(macOS) && canImport(IOKit)
        return readPowerSourceInt(key: "ChargeCounter")
        #else
        return nil
        #endif
    }

    /// 读取能量计数器；与电荷计数器一样，仅 macOS + IOKit 可用。
    func readEnergyCounter() -> Int? {
        #if targetEnvironment(simulator)
        return nil
        #elseif os(macOS) && canImport(IOKit)
        return readPowerSourceInt(key: "EnergyCounter")
        #else
        return nil
        #endif
    }

    #if os(macOS) && canImport(IOKit)
    /// macOS 下按固定间隔轮询电源描述，采样不足时也返回已采到的点。
    private func collectFromIOKit(samples: Int, interval: TimeInterval) -> [Double] {
        var result: [Double] = []
        for _ in 0..<samples {
            if let voltage = readPowerSourceVoltage() {
                result.append(voltage)
            }
            // 仅在尚未采满时休眠，避免最后一次采样后多睡一个 interval。
            if result.count < samples {
                Thread.sleep(forTimeInterval: interval)
            }
        }
        return result
    }

    /// 从第一个电源描述中读取电压；字段类型在不同 macOS 版本可能是 Int 或 Double。
    /// 没有 Voltage 时退化为 Current Capacity，仅用于观察波动趋势而非绝对电压。
    private func readPowerSourceVoltage() -> Double? {
        guard let info = IOPSCopyPowerSourcesInfo()?.takeRetainedValue() as CFTypeRef? else { return nil }
        guard let list = IOPSCopyPowerSourcesList(info)?.takeRetainedValue() as? [CFTypeRef], !list.isEmpty else { return nil }
        guard let desc = IOPSGetPowerSourceDescription(info, list[0])?.takeUnretainedValue() as? [String: Any] else { return nil }
        if let v = desc["Voltage"] as? Int {
            return Double(v)
        }
        if let v = desc["Voltage"] as? Double {
            return v
        }
        if let cap = desc["Current Capacity"] as? Int {
            return Double(cap)
        }
        return nil
    }

    /// 读取指定电源字段的整数计数。
    /// IOKit 不同版本对同一字段使用驼峰或空格分隔命名（如 ChargeCounter / Charge Counter），
    /// 因此主键未命中时再尝试别名，降低跨系统版本漏采。
    private func readPowerSourceInt(key: String) -> Int? {
        guard let info = IOPSCopyPowerSourcesInfo()?.takeRetainedValue() as CFTypeRef? else { return nil }
        guard let list = IOPSCopyPowerSourcesList(info)?.takeRetainedValue() as? [CFTypeRef], !list.isEmpty else { return nil }
        guard let desc = IOPSGetPowerSourceDescription(info, list[0])?.takeUnretainedValue() as? [String: Any] else { return nil }
        if let v = desc[key] as? Int {
            return v
        }
        if let v = desc[key] as? NSNumber {
            return v.intValue
        }
        let altKey = key == "ChargeCounter" ? "Charge Counter" : (key == "EnergyCounter" ? "Energy Counter" : key)
        if let v = desc[altKey] as? Int {
            return v
        }
        if let v = desc[altKey] as? NSNumber {
            return v.intValue
        }
        return nil
    }
    #endif

    #if canImport(UIKit)
    /// iOS 下读取电池电量比例并放大 1000 倍，形成可计算方差的序列。
    /// - 会临时打开 `isBatteryMonitoringEnabled`，用 defer 恢复原值，避免影响宿主 App。
    /// - batteryLevel 为 -1 表示未知，按 0 处理以免污染方差。
    private func collectFromUIDevice(samples: Int, interval: TimeInterval) -> [Double] {
        let wasEnabled = UIDevice.current.isBatteryMonitoringEnabled
        UIDevice.current.isBatteryMonitoringEnabled = true
        defer { UIDevice.current.isBatteryMonitoringEnabled = wasEnabled }
        var result: [Double] = []
        for _ in 0..<samples {
            let level = Float(UIDevice.current.batteryLevel)
            result.append(Double(level >= 0 ? level : 0) * 1000)
            if result.count < samples {
                Thread.sleep(forTimeInterval: interval)
            }
        }
        return result
    }
    #endif
}

/// 电池熵 Provider：组合三路电池检测，输出 `battery_charge_counter`、
/// `battery_voltage_entropy`、`battery_energy_counter` 三类信号。
/// 检查顺序可按远程策略扰动（MutationPlanner），降低静态特征被绕过的概率。
final class BatteryEntropyProvider: RiskSignalProvider {
    static let shared = BatteryEntropyProvider()

    let id = "battery_entropy"

    // 采集器可注入，便于单元测试用假数据替换真实 IOKit/UIDevice 访问。
    private let collector: BatteryEntropyCollector

    /// - Parameter collector: 电池采集器，默认使用平台实现。
    init(collector: BatteryEntropyCollector = BatteryEntropyCollector()) {
        self.collector = collector
    }

    /// 依次执行三路电池检查；每路独立产生信号，互不影响。
    /// 使用 MutationPlanner 打乱检查与输出顺序，避免固定调用序列被检测。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let planner = MutationPlanner(
            strategy: activeMutationStrategy(),
            scope: id,
            deviceID: snapshot.deviceID
        )

        let checks: [() -> [RiskSignal]] = [
            { self.chargeCounterSignals() },
            { self.voltageEntropySignals() },
            { self.energyCounterSignals() },
        ]

        var out: [RiskSignal] = []
        for check in planner.maybeShuffle(checks, salt: "battery_checks") {
            out.append(contentsOf: check())
        }
        return planner.maybeShuffle(out, salt: "battery_emit_order")
    }

    /// 从远程策略构造变异策略；无策略时返回 nil，表示不扰动。
    private func activeMutationStrategy() -> MutationStrategy? {
        guard let mutation = PolicyManager.shared.activePolicy?.mutation else { return nil }
        return MutationStrategy(
            seed: mutation.seed,
            shuffleChecks: mutation.shuffleChecks,
            thresholdJitterBps: mutation.thresholdJitterBps,
            scoreJitterBps: mutation.scoreJitterBps
        )
    }

    /// 检查电荷计数器是否固定为 0 或 -1（虚拟电源特征）。
    /// 读取失败返回 nil 时不产生信号；命中给 hard + 高权重。
    private func chargeCounterSignals() -> [RiskSignal] {
        #if targetEnvironment(simulator)
        return []
        #else
        guard let cc = collector.readChargeCounter() else { return [] }
        // -1 表示系统自报未知，0 表示计数未初始化；真实电池正常充电时不会长期停留在这两个值。
        if cc == -1 || cc == 0 {
            return [
                RiskSignal(
                    id: "battery_charge_counter",
                    category: "device",
                    score: 0,
                    evidence: ["charge_counter": "\(cc)"],
                    state: .hard(detected: true),
                    layer: 1,
                    weightHint: 95
                ),
            ]
        }
        return []
        #endif
    }

    /// 采集 5 个电压点（间隔 0.1s，约 0.5s）并计算方差。
    /// - 样本不足 2 个时返回 `.unavailable`，不参与评分；
    /// - 方差越小置信度越高：<0.001 -> 0.9，<0.01 -> 0.7，<0.1 -> 0.5，否则 0.2。
    /// 真实电池电压会有微小抖动，云手机虚拟电源常表现为近乎恒定。
    private func voltageEntropySignals() -> [RiskSignal] {
        #if targetEnvironment(simulator)
        return [
            RiskSignal(
                id: "battery_voltage_entropy",
                category: "device",
                score: 0,
                evidence: ["detail": "simulator"],
                state: .unavailable,
                layer: 3,
                weightHint: 55
            ),
        ]
        #else
        let series = collector.collectVoltageSeries(samples: 5, interval: 0.1)
        guard series.count >= 2 else {
            return [
                RiskSignal(
                    id: "battery_voltage_entropy",
                    category: "device",
                    score: 0,
                    evidence: ["detail": "insufficient_samples"],
                    state: .unavailable,
                    layer: 3,
                    weightHint: 55
                ),
            ]
        }

        let variance = collector.computeVariance(series)
        // 方差分档是经验阈值：iOS 电量比例分辨率为 1%，正常放电/充电在 0.5s 内通常无变化，
        // 因此低方差不能单独定罪，仅以 confidence 体现强度。
        let confidence: Double
        if variance < 0.001 {
            confidence = 0.9
        } else if variance < 0.01 {
            confidence = 0.7
        } else if variance < 0.1 {
            confidence = 0.5
        } else {
            confidence = 0.2
        }

        return [
            RiskSignal(
                id: "battery_voltage_entropy",
                category: "device",
                score: 0,
                evidence: [
                    "variance": String(format: "%.6f", variance),
                    "samples": "\(series.count)",
                ],
                state: .soft(confidence: confidence),
                layer: 3,
                weightHint: 55
            ),
        ]
        #endif
    }

    /// 检查能量计数器是否固定为 0 或 -1。
    /// 与电荷计数器类似，但使用 soft(0.8)，因为部分 macOS 设备本身不暴露该字段。
    private func energyCounterSignals() -> [RiskSignal] {
        #if targetEnvironment(simulator)
        return []
        #else
        guard let ec = collector.readEnergyCounter() else { return [] }
        // 固定 0/-1 说明虚拟电源未实现能量累计。
        if ec == -1 || ec == 0 {
            return [
                RiskSignal(
                    id: "battery_energy_counter",
                    category: "device",
                    score: 0,
                    evidence: ["energy_counter": "\(ec)"],
                    state: .soft(confidence: 0.8),
                    layer: 1,
                    weightHint: 85
                ),
            ]
        }
        return []
        #endif
    }
}
