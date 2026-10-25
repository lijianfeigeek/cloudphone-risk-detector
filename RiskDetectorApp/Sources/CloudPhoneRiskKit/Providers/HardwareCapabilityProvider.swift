import Foundation
#if canImport(UIKit)
import UIKit
#endif
#if canImport(CoreHaptics)
import CoreHaptics
#endif

/// 硬件能力探测 Provider
///
/// 检测云手机/模拟环境中硬件能力与声称机型的不一致：
/// - Haptic Engine：iPhone 7+ 应有 Taptic Engine，若机型声称支持但 API 返回不支持则异常
/// - 刷新率：iPhone 14/15/16 Pro 系列应有 120Hz ProMotion，若声称 Pro 但 maxFPS=60 则异常
/// - 接近传感器：iPhone 应支持 proximity monitoring，若无法启用则异常
///
/// 注意：CHHapticEngine、UIScreen、UIDevice 均需在主线程访问（UIKit @MainActor），
/// 本 Provider 在 Registry 的 collectWithTimeout 中于后台线程调用，故将 UI 相关检测派发到主线程。
final class HardwareCapabilityProvider: RiskSignalProvider {
    static let shared = HardwareCapabilityProvider()

    let id = "hardware_capability"

    /// 模拟器返回空；真机依次检查触感、刷新率与接近传感器能力。
    /// UI 相关检查派发到主线程；接近传感器检查刻意留在后台线程以避免死锁。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        #if targetEnvironment(simulator)
        return []
        #else
        var out: [RiskSignal] = []

        let machine = machineFromSnapshot(snapshot)

        // CHHapticEngine、UIScreen 必须在主线程访问
        let uiSignals = runOnMainIfNeeded {
            var signals: [RiskSignal] = []
            if let s = hapticCapabilitySignal(machine: machine) { signals.append(s) }
            if let s = refreshRateSignal(machine: machine) { signals.append(s) }
            return signals
        }
        out.append(contentsOf: uiSignals)

        // proximitySensorSignal 绝对不能在主线程执行：它内部使用
        // DispatchQueue.main.asyncAfter + semaphore.wait，若经 runOnMainIfNeeded 在主线程调用，
        // 主队列会被 semaphore.wait 阻塞，asyncAfter 永不触发，必然 1s 超时，
        // 从而每次调用都误报 proximity_sensor_absent。
        // 因此这里直接在后台线程调用；其内部对 UIDevice 的访问由 DispatchQueue.main.sync 保护。
        if let s = proximitySensorSignal(machine: machine) {
            out.append(s)
        }

        return out
        #endif
    }

    /// 若当前非主线程则派发到主线程同步执行，避免 UIKit/CoreHaptics 线程违规
    private func runOnMainIfNeeded<T>(_ block: () -> T) -> T {
        if Thread.isMainThread {
            return block()
        }
        return DispatchQueue.main.sync(execute: block)
    }

    private func machineFromSnapshot(_ snapshot: RiskSnapshot) -> String {
        if let m = snapshot.device.hardwareMachine, !m.isEmpty {
            return m
        }
        return Sysctl.string("hw.machine") ?? ""
    }

    // MARK: - 触感引擎

    /// iPhone 7+ (iPhone9,x 及更新) 应支持 haptics。
    /// 若机型 >= 7 但 supportsHaptics = false -> haptic_capability_mismatch
    private func hapticCapabilitySignal(machine: String) -> RiskSignal? {
        #if canImport(CoreHaptics)
        guard isIPhone7OrNewer(machine: machine) else { return nil }

        let caps = CHHapticEngine.capabilitiesForHardware()
        guard !caps.supportsHaptics else { return nil }

        return RiskSignal(
            id: "haptic_capability_mismatch",
            category: "device",
            score: 0,
            evidence: [
                "machine": machine,
                "supportsHaptics": "false",
                "reason": "iphone7_plus_expected_haptics",
            ],
            state: .soft(confidence: 0.85),
            layer: 1,
            weightHint: 80
        )
        #else
        return nil
        #endif
    }

    /// 解析 hw.machine 判断是否为 iPhone 7 或更新（iPhone9,x 起）
    private func isIPhone7OrNewer(machine: String) -> Bool {
        let lower = machine.lowercased()
        guard lower.hasPrefix("iphone") else { return false }
        let suffix = String(lower.dropFirst("iphone".count))
        guard let commaIdx = suffix.firstIndex(of: ",") else { return false }
        let majorPart = String(suffix[..<commaIdx])
        guard let major = Int(majorPart) else { return false }
        return major >= 9
    }

    // MARK: - 刷新率

    /// iPhone 14/15/16 Pro 系列应有 120Hz。若声称 Pro 但 maxFPS=60 -> refresh_rate_mismatch
    private func refreshRateSignal(machine: String) -> RiskSignal? {
        #if canImport(UIKit)
        guard isProModelWith120Hz(machine: machine) else { return nil }

        let maxFPS = UIScreen.main.maximumFramesPerSecond
        guard maxFPS <= 60 else { return nil }

        return RiskSignal(
            id: "refresh_rate_mismatch",
            category: "device",
            score: 0,
            evidence: [
                "machine": machine,
                "maxFPS": "\(maxFPS)",
                "expected": "120",
                "reason": "pro_model_expected_promotion",
            ],
            state: .soft(confidence: 0.8),
            layer: 1,
            weightHint: 75
        )
        #else
        return nil
        #endif
    }

    /// 已知 120Hz ProMotion 的机型标识符（hw.machine 格式可能因系统返回大小写不一，故用小写比较）
    /// iPhone 14 Pro/Pro Max: iPhone15,2 iPhone15,3
    /// iPhone 15 Pro/Pro Max: iPhone16,1 iPhone16,2
    /// iPhone 16 Pro/Pro Max: iPhone17,1 iPhone17,2
    private static let pro120HzMachineIdentifiers: Set<String> = [
        "iphone15,2", "iphone15,3",
        "iphone16,1", "iphone16,2",
        "iphone17,1", "iphone17,2",
    ]

    private func isProModelWith120Hz(machine: String) -> Bool {
        Self.pro120HzMachineIdentifiers.contains(machine.lowercased())
    }

    // MARK: - 接近传感器

    /// 接近传感器：iPhone 应支持。若无法启用则 proximity_sensor_absent
    /// 设置 isProximityMonitoringEnabled 后需延迟确认（系统有启用延迟），0.5s 足够。
    /// 检测后必须恢复为 false，否则会影响通话等场景的屏幕熄灭逻辑。
    private func proximitySensorSignal(machine: String) -> RiskSignal? {
        #if canImport(UIKit)
        // 防御：若当前已在主线程，不能用 semaphore.wait 阻塞主队列去等待主队列任务，
        // 否则必然 1s 超时并产生误报；此时直接跳过检测，不返回伪造结果。
        guard !Thread.isMainThread else { return nil }
        guard machine.lowercased().hasPrefix("iphone") else { return nil }

        let device = UIDevice.current
        // UIDevice 的属性必须在主线程修改。
        DispatchQueue.main.sync { device.isProximityMonitoringEnabled = true }

        let semaphore = DispatchSemaphore(value: 0)
        var enabled = false
        // 使用全局后台队列的 asyncAfter，避免当前后台线程的 semaphore.wait 阻塞主队列；
        // 读取与恢复 isProximityMonitoringEnabled 仍通过内部的 main.sync 在主线程完成。
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 0.5) {
            DispatchQueue.main.sync {
                enabled = device.isProximityMonitoringEnabled
                device.isProximityMonitoringEnabled = false
            }
            semaphore.signal()
        }
        let waitResult = semaphore.wait(timeout: .now() + 1.0)

        // 超时或提前返回都需确保恢复：若 asyncAfter 回调未执行，isProximityMonitoringEnabled 仍为 true
        if waitResult == .timedOut {
            DispatchQueue.main.async { device.isProximityMonitoringEnabled = false }
        }

        guard !enabled else { return nil }

        return RiskSignal(
            id: "proximity_sensor_absent",
            category: "device",
            score: 0,
            evidence: [
                "machine": machine,
                "reason": "iphone_expected_proximity",
            ],
            state: .soft(confidence: 0.5),
            layer: 1,
            weightHint: 30
        )
        #else
        return nil
        #endif
    }
}
