// 一次评估的不可变输入快照：设备标识、设备指纹、网络/行为/越狱结果，
// 以及变异策略与 anti-debug/libc 回退的运行时姿态。
// 作为 `RiskSignalProvider.signals(snapshot:)` 的唯一输入，provider 不应访问内部可变状态。
// 快照创建后字段不再变更，避免评估期间被后台采集线程改写。
import Foundation

/// 一次 `evaluate()` 调用期间收集到的稳定快照。
/// 自定义 provider 可据此派生额外 `RiskSignal`，而无需依赖 SDK 内部类型。
/// 值类型 + `Sendable`：可以安全跨线程传递；字段为快照时刻的拷贝。
public struct RiskSnapshot: Sendable {
    /// 设备稳定标识（哈希后），用于历史/聚合，不含原始 IDFV
    public var deviceID: String
    /// 设备指纹（硬件型号、系统版本、locale 等）
    public var device: DeviceFingerprint
    /// 网络信号（VPN/代理/MCC 等）
    public var network: NetworkSignals
    /// 行为信号（触摸、运动聚合统计）
    public var behavior: BehaviorSignals
    /// 越狱检测结果（置信度与命中方法）
    public var jailbreak: DetectionResult
    /// 服务端下发的变异策略；nil 表示本次不扰动权重/阈值
    public var mutationStrategy: MutationStrategy?
    /// Whether the anti-debug watchdog snapshot path is available on this build/runtime.
    /// 当前构建/运行时是否支持 anti-debug watchdog 快照路径。
    public var antiDebugWatchdogSupported: Bool
    /// Bitset from CRiskCore describing which direct-syscall surfaces fell back to libc/arc4random.
    /// C 层直接 syscall 回退位图：每位对应一个 API 面，置位表示走了 libc/arc4random。
    public var libcFallbackUsedMask: UInt32
    /// Monotonic count of fallback notifications since the C mask was last reset.
    /// 自 C 层掩码上次重置以来的回退通知累计次数（单调递增，用于判断是否持续回退）。
    public var libcFallbackEventTotal: UInt32

    /// 创建快照；可选字段默认关闭，便于不需要这些能力的调用方构造。
    public init(
        deviceID: String,
        device: DeviceFingerprint,
        network: NetworkSignals,
        behavior: BehaviorSignals,
        jailbreak: DetectionResult,
        mutationStrategy: MutationStrategy? = nil,
        antiDebugWatchdogSupported: Bool = false,
        libcFallbackUsedMask: UInt32 = 0,
        libcFallbackEventTotal: UInt32 = 0
    ) {
        self.deviceID = deviceID
        self.device = device
        self.network = network
        self.behavior = behavior
        self.jailbreak = jailbreak
        self.mutationStrategy = mutationStrategy
        self.antiDebugWatchdogSupported = antiDebugWatchdogSupported
        self.libcFallbackUsedMask = libcFallbackUsedMask
        self.libcFallbackEventTotal = libcFallbackEventTotal
    }
}

