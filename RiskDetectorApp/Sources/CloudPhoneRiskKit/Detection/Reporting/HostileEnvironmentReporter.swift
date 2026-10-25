// 敌对环境上报桥接：把 C 层模拟器/沙箱探针返回的位图（CPRISK_EMU_FLAG_*）转换为结构化报告，
// 通过 HostileEnvironmentReporter 交给业务后端做二次判定；端上检测无法阻止结果被 patch。
// 每次评估周期后调用一次 dispatchHostileEnvironmentReport；无信号时不回调，避免空上报。

import CRiskCore
import Foundation

// MARK: - 协议

/// 实现该协议并注册到 `CPRiskKit.shared`，即可接收敌对环境信号用于服务端风险评估。
///
/// SDK 的检测全部在设备端完成。没有服务端参与时，有能力的攻击者可以直接 patch 端上结果。
/// 把这些信号接到业务后端，可以提供一层无法仅靠改二进制绕过的二次校验。
///
/// ## 用法
/// ```swift
/// class MyReporter: HostileEnvironmentReporter {
///     func reportHostileEnvironment(_ report: HostileEnvironmentReport) {
///         // 将 report.jsonPayload POST 到风控后端
///     }
/// }
/// CPRiskKit.shared.hostileEnvironmentReporter = MyReporter()
/// ```
public protocol HostileEnvironmentReporter: AnyObject, Sendable {
    /// 当 C 层检测到一个或多个敌对信号时回调。
    /// 可能在任意线程调用；实现方必须自行保证线程安全。
    func reportHostileEnvironment(_ report: HostileEnvironmentReport)
}

// MARK: - 报告模型

/// 一次敌对环境检测的结构化结果，可直接序列化后上报。
public struct HostileEnvironmentReport: Sendable {

    /// 来自 `cprisk_emulator_detect.h` 的 `CPRISK_EMU_FLAG_*` 位图；每一位对应一种环境异常。
    public let rawFlags: UInt32

    /// 由命中位加权计算出的分数（0–100）。
    public let score: Int

    /// 命中的检测项可读名称列表。
    public let activeSignals: [String]

    /// SDK 是否判定当前环境明确敌对（score ≥ 25 或命中最强置信位）。
    public let isHostile: Bool

    /// 报告生成时间的 ISO-8601 字符串。
    public let timestamp: String

    /// 可直接 POST 给风控后端的 JSON 字典。
    /// `sdk_version` 是 C 层探针表的版本标记，不是 SDK 版本号。
    public var jsonPayload: [String: Any] {
        [
            "raw_flags":      rawFlags,
            "score":          score,
            "signals":        activeSignals,
            "is_hostile":     isHostile,
            "timestamp":      timestamp,
            "sdk_version":    "cprisk.emulator.v1",
        ]
    }

    // MARK: 位名映射

    /// 位掩码到可读名称的映射；顺序即上报顺序，需与 C 头文件保持一致。
    private static let flagNames: [(UInt32, String)] = [
        (0x001, "dyld_cache_absent"),
        (0x002, "low_vm_regions"),
        (0x004, "low_stack_addr"),
        (0x008, "ostype_not_darwin"),
        (0x010, "low_thread_count"),
        (0x020, "jvm_env_var"),
        (0x040, "timebase_flat"),
        (0x080, "cpu_clock_frozen"),
        (0x100, "watchdog_stuck"),
    ]

    /// 将位图展开为命中的名称列表；未命中位直接忽略。
    static func signals(from flags: UInt32) -> [String] {
        flagNames.compactMap { (mask, name) in flags & mask != 0 ? name : nil }
    }
}

// MARK: - 桥接

/// 从 C 层读取当前模拟器位图，若有敌对信号则向已注册的 `HostileEnvironmentReporter` 派发报告。
/// 每次 SDK 评估周期后调用一次。
/// 未注册 reporter 或位图为 0 时直接返回，不产生任何开销/空回调。
internal func dispatchHostileEnvironmentReport(to reporter: HostileEnvironmentReporter?) {
    guard let reporter else { return }

    let flags = cprisk_emulator_probe()
    // 位图为 0 表示本次未发现任何异常，保持静默以降低上报噪声。
    guard flags != 0 else { return }

    let score = Int(cprisk_emulator_score(flags))
    let signals = HostileEnvironmentReport.signals(from: flags)

    let formatter = ISO8601DateFormatter()
    let report = HostileEnvironmentReport(
        rawFlags: flags,
        score: score,
        activeSignals: signals,
        isHostile: cprisk_emulator_is_hostile(flags) != 0,
        timestamp: formatter.string(from: Date())
    )

    reporter.reportHostileEnvironment(report)
}
