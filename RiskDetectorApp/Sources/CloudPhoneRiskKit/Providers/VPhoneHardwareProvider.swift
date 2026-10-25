import Foundation
#if canImport(Metal)
import Metal
#endif
#if canImport(IOKit)
import IOKit
#endif

// vPhone（云手机）硬件一致性 Provider。
// 交叉比对 GPU 名称、sysctl 机型、IOKit 机型、内核版本与 board id，
// 识别 Apple 半虚拟化 GPU、伪造机型标识及多来源机型不一致。
// 这是云手机判定的核心层（layer 1），命中可直接给 hard 状态与高权重。

/// 硬件信息探测抽象，便于注入测试替身。
protocol V3HardwareProbe {
    /// 返回默认 Metal 设备的 GPU 名称；无 Metal 时返回 nil。
    func gpuName() -> String?
    /// 返回当前机型标识（优先快照，回退 sysctl）。
    func machine(from snapshot: RiskSnapshot) -> String
    /// 返回 IOKit 中的平台 model；非 macOS 返回空串。
    func ioKitModel() -> String
    /// 返回内核版本字符串（utsname.version）。
    func kernelVersion() -> String
}

/// 系统实现：分别通过 Metal、sysctl、IOKit、uname 读取硬件信息。
struct SystemHardwareProbe: V3HardwareProbe {
    func gpuName() -> String? {
#if canImport(Metal)
        return MTLCreateSystemDefaultDevice()?.name
#else
        return nil
#endif
    }

    func machine(from snapshot: RiskSnapshot) -> String {
        if let machine = snapshot.device.hardwareMachine, machine.isEmpty == false {
            return machine
        }
        return Sysctl.string("hw.machine") ?? ""
    }

    func ioKitModel() -> String {
#if canImport(IOKit) && os(macOS) && !targetEnvironment(macCatalyst)
        // 仅 macOS 可通过 IOPlatformExpertDevice 读取平台 model；iOS 上返回空串。
        let service = IOServiceGetMatchingService(ioKitMainPort(), IOServiceMatching("IOPlatformExpertDevice"))
        defer { IOObjectRelease(service) }
        guard service != IO_OBJECT_NULL else { return "" }
        guard
            let value = IORegistryEntryCreateCFProperty(
                service,
                "model" as CFString,
                kCFAllocatorDefault,
                0
            )?.takeRetainedValue() as? Data
        else {
            return ""
        }

        return String(data: value, encoding: .utf8)?
            .trimmingCharacters(in: .controlCharacters) ?? ""
#else
        return ""
#endif
    }

    func kernelVersion() -> String {
        var info = utsname()
        uname(&info)
        let versionTuple = info.version
        // utsname.version 是 C 定长字符数组，转成 Swift String 供格式校验。
        return withUnsafePointer(to: versionTuple) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: versionTuple)) {
                String(cString: $0)
            }
        }
    }

#if canImport(IOKit) && os(macOS) && !targetEnvironment(macCatalyst)
    private func ioKitMainPort() -> mach_port_t {
        if #available(macOS 12.0, *) {
            return kIOMainPortDefault
        }
        // `kIOMasterPortDefault` 是 MACH_PORT_NULL 的已弃用别名，直接用 0 表示默认端口。
        return 0
    }
#endif
}

/// 云手机硬件检测 Provider：输出 `gpu_virtual`、`vphone_hardware`、
/// `board_id_virtual`、`hardware_inconsistency` 等信号。
final class VPhoneHardwareProvider: RiskSignalProvider {
    static let shared = VPhoneHardwareProvider()

    let id = "vphone_hardware"

    // 探测器可注入，默认使用真实系统 API。
    private let probe: V3HardwareProbe

    // Apple 半虚拟化 GPU 及软件渲染器关键字；命中通常直接说明运行在虚拟机/云手机。
    static let knownVirtualGPUKeywords: [String] = [
        "apple paravirtual device",
        "apple paravirt",
        "llvmpipe",
        "llvm",
    ]

    // 已知云手机/虚拟化平台伪造或暴露的机型标识。
    static let vphoneModelPatterns: [String] = [
        "iphone99",
        "vresearch",
        "paravirtual",
    ]

    /// - Parameter probe: 自定义硬件探测器，默认使用 `SystemHardwareProbe`。
    init(probe: V3HardwareProbe = SystemHardwareProbe()) {
        self.probe = probe
    }

    /// 执行 GPU 与硬件一致性检查，并按策略扰动检查/输出顺序。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let planner = MutationPlanner(
            strategy: activeMutationStrategy(),
            scope: id,
            deviceID: snapshot.deviceID
        )
        let checks: [() -> [RiskSignal]] = [
            { self.gpuSignals() },
            { self.hardwareConsistencySignals(snapshot: snapshot) },
        ]

        var out: [RiskSignal] = []
        for check in planner.maybeShuffle(checks, salt: "layer1_checks") {
            out.append(contentsOf: check())
        }
        return planner.maybeShuffle(out, salt: "layer1_emit_order")
    }

    /// 检查 GPU 名称是否暴露虚拟化特征。
    /// - 无 Metal/GPU 名称：soft(0.6)，可能只是框架不可用；
    /// - 命中虚拟 GPU 关键字：hard 命中；
    /// - 含 Apple A/M/GPU 字样：视为真实硬件（hard detected:false）；
    /// - 其他未知名称：soft(0.45)，保留观察。
    private func gpuSignals() -> [RiskSignal] {
        let gpu = probe.gpuName() ?? ""
        if gpu.isEmpty {
            return [
                RiskSignal(
                    id: "gpu_virtual",
                    category: "device",
                    score: 0,
                    evidence: ["detail": "metal_unavailable"],
                    state: .soft(confidence: 0.6),
                    layer: 1,
                    weightHint: 95
                ),
            ]
        }

        let lower = gpu.lowercased()
        let hitVirtualGPU = Self.knownVirtualGPUKeywords.contains { lower.contains($0) }
        let realChipLike = lower.contains("apple a") || lower.contains("apple m") || lower.contains("apple gpu")
        return [
            RiskSignal(
                id: "gpu_virtual",
                category: "device",
                score: 0,
                evidence: ["gpu_name": gpu],
                state: hitVirtualGPU ? .hard(detected: true) : (realChipLike ? .hard(detected: false) : .soft(confidence: 0.45)),
                layer: 1,
                weightHint: 95
            ),
        ]
    }

    /// 交叉校验多来源硬件标识。
    /// - `sysctlModel` 与 `iokitModel` 不一致：典型虚拟化/伪造特征；
    /// - `board_id_virtual`：board id 缺失或命中云手机模式；
    /// - `vphone_hardware`：任一来源命中 vPhone 模式时给 hard 命中。
    private func hardwareConsistencySignals(snapshot: RiskSnapshot) -> [RiskSignal] {
        var out: [RiskSignal] = []

        let sysctlModel = probe.machine(from: snapshot)
        let iokitModel = probe.ioKitModel()
        let kernelVersion = probe.kernelVersion()
        let kernelBuild = DeviceFingerprint.extractKernelBuild(from: kernelVersion, osVersion: nil)
        let boardID = snapshot.device.hardwareModel ?? ""
        // 同时检查 sysctl、IOKit、内核版本三个来源，任一命中即可疑。
        let all = [sysctlModel, iokitModel, kernelVersion]
        // 远程策略可追加云手机机型关键词。
        let dynamicPatterns = PolicyManager.shared.activePolicy?.newVPhonePatterns.map { $0.lowercased() } ?? []
        let allPatterns = Self.vphoneModelPatterns + dynamicPatterns

        let hasVPhonePattern = all.contains { value in
            let lower = value.lowercased()
            return allPatterns.contains(where: { lower.contains($0) })
        }

        out.append(
            RiskSignal(
                id: "vphone_hardware",
                category: "device",
                score: 0,
                evidence: [
                    "sysctl_model": sysctlModel,
                    "iokit_model": iokitModel,
                    "kernel": kernelVersion,
                    "kernel_build": kernelBuild ?? "",
                ],
                state: .hard(detected: hasVPhonePattern),
                layer: 1,
                weightHint: 100
            )
        )

        // board id 缺失在越狱/虚拟环境常见，但部分测试构建也可能读不到，故只给 unavailable。
        if boardID.isEmpty {
            out.append(
                RiskSignal(
                    id: "board_id_virtual",
                    category: "device",
                    score: 0,
                    evidence: ["board_id": "unavailable"],
                    state: .unavailable,
                    layer: 1,
                    weightHint: 88
                )
            )
        } else {
            let boardLower = boardID.lowercased()
            let boardSuspicious = allPatterns.contains(where: { boardLower.contains($0) })
            out.append(
                RiskSignal(
                    id: "board_id_virtual",
                    category: "device",
                    score: 0,
                    evidence: ["board_id": boardID],
                    state: .hard(detected: boardSuspicious),
                    layer: 1,
                    weightHint: 88
                )
            )
        }

        // sysctl 与 IOKit 对同一设备的描述应一致；不一致说明机型被注入/篡改。
        if !sysctlModel.isEmpty, !iokitModel.isEmpty, sysctlModel != iokitModel {
            out.append(
                RiskSignal(
                    id: "hardware_inconsistency",
                    category: "device",
                    score: 0,
                    evidence: [
                        "sysctl": sysctlModel,
                        "iokit": iokitModel,
                    ],
                    state: .soft(confidence: 0.85),
                    layer: 2,
                    weightHint: 90
                )
            )
        }

        return out
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
}
