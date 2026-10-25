import Foundation

// 设备硬件信号提供者。
// 汇总模拟器标识、`hw.machine`、主机名关键词与内核版本格式等硬件侧证据。
// 这些信号多为弱证据（soft），由上层组合规则与其他维度交叉后才形成强判决。

/// 采集模拟器/硬件标识类信号：
/// - `simulator` / `is_simulator`：运行在 Xcode 模拟器；
/// - `hw_machine`：原始机型标识，供服务端比对；
/// - `hostname_contains_cloud`：主机名命中云手机厂商关键词；
/// - `kernel_build_anomaly`：内核版本缺失或格式不符合 Apple 规范。
final class DeviceHardwareProvider: RiskSignalProvider {
    static let shared = DeviceHardwareProvider()
    private init() {}

    let id = "device_hardware"
    // 云手机/远程真机平台常见主机名关键词；命中只说明进程宿主环境可疑，需结合其他信号。
    private static let suspiciousHostnameKeywords = [
        "cloudphone",
        "phonecloud",
        "vphone",
        "redfinger",
        "armcloud",
        "nowgg",
        "bignox",
        "remotefarm",
    ]

    /// 汇总硬件类信号；各子检查彼此独立，任一缺失只影响对应信号。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        var out: [RiskSignal] = []

        // 同时输出旧版 `simulator` 与统一 ID `SignalID.isSimulator`：
        // 前者兼容历史规则，后者参与统一评分，`isSimulator` 用 hard 状态明确“已检测到”。
        if snapshot.device.isSimulator {
            out.append(
                RiskSignal(
                    id: "simulator",
                    category: "device",
                    score: 0,
                    evidence: ["machine": snapshot.device.hardwareMachine ?? "unknown"]
                )
            )
            out.append(
                RiskSignal(
                    id: SignalID.isSimulator,
                    category: "device",
                    score: 0,
                    evidence: ["machine": snapshot.device.hardwareMachine ?? "unknown"],
                    state: .hard(detected: true),
                    layer: 1,
                    weightHint: 90
                )
            )
        }

        // 透传原始机型字符串，本身不计分，供服务端做机型分布/一致性分析。
        if let machine = snapshot.device.hardwareMachine, machine.isEmpty == false {
            out.append(
                RiskSignal(
                    id: "hw_machine",
                    category: "device",
                    score: 0,
                    evidence: ["machine": machine]
                )
            )
        }

        if let hostnameSignal = hostnameSignal() {
            out.append(hostnameSignal)
        }

        if let kernelSignal = kernelBuildSignal(snapshot: snapshot) {
            out.append(kernelSignal)
        }

        return out
    }

    /// 检查进程主机名是否命中云手机厂商关键词。
    /// - 主机名由系统授予，真机通常为 "iPhone" 之类；为空则跳过。
    /// - 命中仅输出 soft 信号（confidence 0.82），避免企业内网自定义主机名误报。
    private func hostnameSignal() -> RiskSignal? {
        let hostname = ProcessInfo.processInfo.hostName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !hostname.isEmpty else { return nil }

        let lower = hostname.lowercased()
        let suspicious = Self.suspiciousHostnameKeywords.first(where: { lower.contains($0) })
        guard let matched = suspicious else { return nil }

        return RiskSignal(
            id: SignalID.hostnameContainsCloud,
            category: "device",
            score: 0,
            evidence: [
                "hostname": hostname,
                "matched_keyword": matched,
            ],
            state: .soft(confidence: 0.82),
            layer: 1,
            weightHint: 70
        )
    }

    /// 校验内核版本字符串是否符合 Apple 发布格式。
    /// - 模拟器上没有真实内核信息，直接跳过，避免与 simulator 信号重复。
    /// - 缺失内核版本给较低置信度（0.55）；格式非法给 0.72。
    private func kernelBuildSignal(snapshot: RiskSnapshot) -> RiskSignal? {
        guard !snapshot.device.isSimulator else { return nil }

        guard let kernelBuild = snapshot.device.kernelBuild, !kernelBuild.isEmpty else {
            return RiskSignal(
                id: SignalID.kernelBuildAnomaly,
                category: "device",
                score: 0,
                evidence: ["reason": "kernel_build_missing"],
                state: .soft(confidence: 0.55),
                layer: 1,
                weightHint: 40
            )
        }

        guard !DeviceFingerprint.looksLikeKernelBuild(kernelBuild) else { return nil }

        return RiskSignal(
            id: SignalID.kernelBuildAnomaly,
            category: "device",
            score: 0,
            evidence: [
                "reason": "kernel_build_format_invalid",
                "kernel_build": kernelBuild,
            ],
            state: .soft(confidence: 0.72),
            layer: 1,
            weightHint: 55
        )
    }
}
