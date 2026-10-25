import Foundation
#if canImport(AVFoundation)
import AVFoundation
#endif

// DRM 能力探测 Provider。
// 通过 FairPlay `AVContentKeySession` 是否能创建，判断设备是否具备硬件级 DRM 能力。
// 云手机/模拟器常缺失或降级 DRM，若同时声称是正常 iPhone，则形成强不一致信号。

/// DRM 能力等级。
/// - `hardwareSecure`：可创建 FairPlay 会话，通常具备硬件安全路径；
/// - `softwareOnly`：降级为软件实现，或机型标识命中云手机特征；
/// - `unavailable`：模拟器、macOS 或框架不可用，无法探测。
enum DRMCapabilityLevel: String, Codable {
    case hardwareSecure
    case softwareOnly
    case unavailable
}

/// DRM 探测抽象，便于在测试或特殊平台替换实现。
protocol DRMProbe {
    /// 返回当前设备的 DRM 能力等级；不应抛错或阻塞过久。
    func probeDRMLevel() -> DRMCapabilityLevel
}

#if canImport(AVFoundation)
/// 默认探测实现：创建 FairPlay `AVContentKeySession` 验证能力。
/// 模拟器与 macOS 无法代表真机 DRM 环境，直接返回 `.unavailable`。
final class AVContentKeySessionProbe: DRMProbe {
    func probeDRMLevel() -> DRMCapabilityLevel {
        #if targetEnvironment(simulator)
        return .unavailable
        #elseif os(macOS)
        return .unavailable
        #else
        _ = AVContentKeySession(keySystem: .fairPlayStreaming)
        return .hardwareSecure
        #endif
    }
}
#endif

#if !canImport(AVFoundation)
/// 无 AVFoundation 平台（如部分测试目标）的兜底实现，统一报告不可用。
struct StubDRMProbe: DRMProbe {
    func probeDRMLevel() -> DRMCapabilityLevel { .unavailable }
}
#endif

/// DRM 能力 Provider：输出 `drm_capability` 基础信号；
/// 当设备声称是正常机型却只有软件/不可用 DRM 时，额外输出强信号 `drm_device_mismatch`。
final class DRMCapabilityProvider: RiskSignalProvider {
    static let shared = DRMCapabilityProvider()

    let id = "drm_capability"

    // 探测实现可注入，默认使用 FairPlay 会话探测。
    private let probe: DRMProbe

    // 已知云手机/虚拟化机型标识；命中后即使 DRM 报告 hardwareSecure 也降级为 softwareOnly，
    // 因为虚拟环境可能伪造 DRM 查询结果。
    private static let vphoneModelPatterns: [String] = [
        "iphone99",
        "vresearch",
        "paravirtual",
    ]

    /// - Parameter probe: 自定义探测器；传 nil 时按平台选择默认实现。
    init(probe: DRMProbe? = nil) {
        #if canImport(AVFoundation)
        self.probe = probe ?? AVContentKeySessionProbe()
        #else
        self.probe = probe ?? StubDRMProbe()
        #endif
    }

    /// 执行 DRM 探测并按策略打乱检查/输出顺序。
    /// 检查数组目前只有一项，保留结构以便后续扩展多个 DRM 子检查。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let planner = MutationPlanner(
            strategy: activeMutationStrategy(),
            scope: id,
            deviceID: snapshot.deviceID
        )

        let checks: [() -> [RiskSignal]] = [
            { self.drmSignals(snapshot: snapshot) },
        ]

        var out: [RiskSignal] = []
        for check in planner.maybeShuffle(checks, salt: "drm_checks") {
            out.append(contentsOf: check())
        }
        return planner.maybeShuffle(out, salt: "drm_emit_order")
    }

    /// 从远程策略读取变异参数；无策略时返回 nil。
    private func activeMutationStrategy() -> MutationStrategy? {
        guard let mutation = PolicyManager.shared.activePolicy?.mutation else { return nil }
        return MutationStrategy(
            seed: mutation.seed,
            shuffleChecks: mutation.shuffleChecks,
            thresholdJitterBps: mutation.thresholdJitterBps,
            scoreJitterBps: mutation.scoreJitterBps
        )
    }

    /// 生成 DRM 相关信号。
    /// - `deviceNormal`：机型非空且未命中云手机模式，代表“看起来像真机”；
    /// - 云手机模式命中时把 hardwareSecure 降级为 softwareOnly，防止伪造；
    /// - 正常机型 + DRM 降级/不可用时判定为 hard 不一致（weightHint 100）。
    private func drmSignals(snapshot: RiskSnapshot) -> [RiskSignal] {
        var out: [RiskSignal] = []

        var drmLevel = probe.probeDRMLevel()
        let machine = snapshot.device.hardwareMachine ?? ""
        let machineLower = machine.lowercased()
        // 远程策略可下发新的云手机机型关键词，与内置列表合并后匹配。
        let dynamicPatterns = PolicyManager.shared.activePolicy?.newVPhonePatterns.map { $0.lowercased() } ?? []
        let allPatterns = Self.vphoneModelPatterns + dynamicPatterns
        let hasVPhonePattern = allPatterns.contains { machineLower.contains($0) }
        let deviceNormal = !hasVPhonePattern && !machine.isEmpty

        // 虚拟环境可能伪造 DRM 查询结果；机型模式命中时以更保守的 softwareOnly 处理。
        if drmLevel == .hardwareSecure && hasVPhonePattern {
            drmLevel = .softwareOnly
        }

        let drmEvidence: [String: String] = [
            "drm_level": drmLevel.rawValue,
            "hardware_machine": machine,
        ]

        out.append(
            RiskSignal(
                id: "drm_capability",
                category: "device",
                score: 0,
                evidence: drmEvidence,
                state: drmState(drmLevel: drmLevel, deviceNormal: deviceNormal),
                layer: 1,
                weightHint: 85
            )
        )

        // 正常 iPhone 却报告软件 DRM 或不可用，说明运行环境与声称机型不匹配。
        if deviceNormal && (drmLevel == .softwareOnly || drmLevel == .unavailable) {
            out.append(
                RiskSignal(
                    id: "drm_device_mismatch",
                    category: "device",
                    score: 0,
                    evidence: [
                        "drm_level": drmLevel.rawValue,
                        "hardware_machine": machine,
                        "reason": "real_device_claims_but_drm_degraded",
                    ],
                    state: .hard(detected: true),
                    layer: 1,
                    weightHint: 100
                )
            )
        }

        return out
    }

    /// 把 DRM 等级映射为信号状态。
    /// - 模拟器/macOS 上 unavailable 属预期，使用 soft，避免开发环境误报；
    /// - 真机 hardwareSecure 视为 negative（hard detected:false）；
    /// - softwareOnly 为中等可疑；unavailable 且机型正常则判 hard 命中。
    private func drmState(drmLevel: DRMCapabilityLevel, deviceNormal: Bool) -> RiskSignalState {
        #if targetEnvironment(simulator)
        if drmLevel == .unavailable {
            return .soft(confidence: 0.7)
        }
        #elseif os(macOS)
        if drmLevel == .unavailable {
            return .soft(confidence: 0.7)
        }
        #endif

        switch drmLevel {
        case .hardwareSecure:
            return .hard(detected: false)
        case .softwareOnly:
            return .soft(confidence: 0.85)
        case .unavailable:
            if deviceNormal {
                return .soft(confidence: 0.7)
            }
            return .hard(detected: true)
        }
    }
}
