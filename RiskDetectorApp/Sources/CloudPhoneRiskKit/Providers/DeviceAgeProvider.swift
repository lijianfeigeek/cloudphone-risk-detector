import Foundation

// 设备代际（设备年龄）信号提供者。
// 从 `hw.machine`（如 iPhone10,6）解析 iPhone 代际数字，对老机型给出弱风险分。
// 设备农场/云手机池更常复用旧机型，但真机用户也可能使用旧机，故只作为低权重佐证。

/// 根据 `hw.machine` 推断 iPhone 代际，输出 `old_device_model` 信号。
/// 无硬件标识或非 iPhone 机型时返回空数组，不做任何猜测。
final class DeviceAgeProvider: RiskSignalProvider {
    static let shared = DeviceAgeProvider()
    private init() {}

    let id = "device_age"

    /// 生成设备代际信号。
    /// - 依赖快照中的 `hardwareMachine`；缺失或无法解析时静默返回空。
    /// - 分数与代际单调递减：越老分数越高，但不会单独触发强判决。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        guard let machine = snapshot.device.hardwareMachine else { return [] }
        guard let family = parseIPhoneFamily(machine) else { return [] }

        // 粗略经验值：设备农场/云手机更常出现旧机型；分数刻意压低，避免误伤真实旧机用户。
        // 代际阈值对应 iPhone 8/X 及更早、iPhone 11/12、iPhone 13/14；15 代起不再计分。
        let score: Double
        switch family {
        case ..<10: score = 18  // iPhone X/8 及更早
        case 10...11: score = 12  // iPhone 11/12 系列
        case 12...13: score = 6  // iPhone 13/14 系列
        default: score = 0
        }

        guard score > 0 else { return [] }
        return [
            RiskSignal(
                id: "old_device_model",
                category: "device",
                score: score,
                evidence: [
                    "machine": machine,
                    "family": "\(family)",
                ]
            ),
        ]
    }

    /// 从 `hw.machine` 中提取 iPhone 主代际号。
    /// - 例：`iPhone10,6` -> 10；`iPad7,4`、空串等非 iPhone 标识返回 nil。
    private func parseIPhoneFamily(_ machine: String) -> Int? {
        // 约定格式如 iPhone10,6：前缀后紧跟数字，遇到逗号即停止。
        guard machine.hasPrefix("iPhone") else { return nil }
        let rest = machine.dropFirst("iPhone".count)
        var digits = ""
        for ch in rest {
            if ch.isNumber { digits.append(ch) } else { break }
        }
        return Int(digits)
    }
}

