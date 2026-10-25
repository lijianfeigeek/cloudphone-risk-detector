// 信号提供者（Provider）扩展点与注册表：宿主/内置 provider 在评估时向管线注入额外 `RiskSignal`。
// `RiskSignalProvider` 是公开协议；`RiskSignalProviderRegistry` 负责注册、封存（seal）、
// 超时隔离、失败熔断，并把各 provider 的 serverSignals 合并进上报载荷。
// 安全不变量：start 后注册表封存，替换/反注册内置 provider 会产生篡改信号；
// 单个 provider 超时不会中断整体收集，连续失败达到阈值后被跳过。
import Foundation

// MARK: - Signal Provider System
//
// Extension point for injecting custom risk signals into the evaluation pipeline.
//
// Built-in Providers (auto-registered by CPRiskKit.start()):
//   server_aggregate   → IP/ASN/datacenter signals from server injection
//   device_hardware    → hw.machine, simulator detection
//   device_age         → old model heuristic risk scoring
//   biometric_state   → LAContext biometry probe (not enrolled / not available / lockout)
//   time_pattern       → 24h activity pattern analysis
//   vphone_hardware    → GPU/BoardID/kernel cloud phone indicators
//   battery_entropy    → ChargeCounter/voltage variance
//   drm_capability     → FairPlay DRM level
//   mount_point        → filesystem mount anomalies
//   layered_consistency→ cross-layer signal coherence
//
// Security: registry is sealed after start() — attempts to replace internal
// providers inject tamper signals (provider_tamper_attempt / provider_instance_replaced)

/// 可插拔信号提供者（B2）：实现后通过 `CPRiskKit.register(provider:)` 注册。
/// 线程模型：`signals(snapshot:)` 可能在主线程或后台线程被调用，实现必须遵守注册表线程规范
/// （主线程禁止 `main.sync`/信号量等待，后台线程禁止主线程等待）。
public protocol RiskSignalProvider: AnyObject {
    /// 稳定的提供者标识（如 "device_age"、"asn_aggregate"），用于覆盖注册与封存校验。
    var id: String { get }

    /// 基于本次评估快照产出额外信号；返回空数组表示本次无发现，超时由注册表统一处理。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal]

    /// 可选：提供服务端聚合字段（IP/ASN/机房标签等），合并后嵌入上报 JSON；默认返回 nil。
    func serverSignals(snapshot: RiskSnapshot) -> ServerSignals?
}

public extension RiskSignalProvider {
    // 默认不提供 serverSignals，避免每个 provider 都写样板实现。
    func serverSignals(snapshot: RiskSnapshot) -> ServerSignals? { nil }
}

/// 内置 provider 的引导表：按 XOR 后的 token 排序执行注册，打乱静态可见的注册顺序。
/// 每个 `Entry` 同时携带启用条件，便于按配置注册/反注册（如时序分析开关）。
enum BuiltInProviderBootstrap {
    /// 一条注册计划：token 仅用于排序混淆；isEnabled 决定是否执行；apply 执行注册/反注册。
    private struct Entry {
        let token: UInt64
        let isEnabled: (CPRiskConfig) -> Bool
        let apply: (RiskSignalProviderRegistry) -> Void
    }

    // 排序混合常量：让源码中按业务分组的 token 在运行时交错，降低静态分析可读性。
    private static let tokenMix: UInt64 = 0x8F42_C193_A55E_17D4

    /// 内置 provider 实例清单（含诱饵），用于封存与“内置 provider 被替换”检测。
    private static let internalProviders: [RiskSignalProvider] =
        [
            ExternalServerAggregateProvider.shared,
            DeviceHardwareProvider.shared,
            DeviceAgeProvider.shared,
            AppAttestSignalProvider.shared,
            AppAttestActiveProbeProvider.shared,
            VPhoneHardwareProvider.shared,
            HardwareCapabilityProvider.shared,
            DisplayMuxProvider.shared,
            BiometricStateProvider.shared,
            LayeredConsistencyProvider.shared,
            MountPointProvider.shared,
            NetworkInterfaceProvider.shared,
            DRMCapabilityProvider.shared,
            BatteryEntropyProvider.shared,
            EnvironmentConsistencyProvider.shared,
            AudioRouteProvider.shared,
            BasebandIsolationProvider.shared,
            GPURenderFingerprintProvider.shared,
            IMUNoiseSpectrumProvider.shared,
            TimePatternProvider.shared,
            AntiTamperingSignalProvider.shared,
            CloudPhoneEnvironmentProvider.shared,
            CertificatePinningTelemetryProvider.shared,
            HoneypotConflictFieldProvider.shared,
            AppLifecycleHeartbeatProvider.shared,
            IntegrityChainSealProvider.shared,
        ]
        // 诱饵池（见 DecoyProviders.swift）：把它们一起纳入 internalProviderIDs 有两个作用：
        // (1) 与真实 provider 一样受封存/替换检测保护；
        // (2) 因信号数组恒为空、从不进入 activeProviderIDs，不会触发“曾活跃现为空”的篡改信号。
        // 攻击者枚举 __data 时，plan 与 internalProviders 都是 30 项，静态上无法区分真假。
        + DecoyProviderBootstrap.providers

    /// 注册计划表；token 在 apply 时与 tokenMix 异或后排序，真实/诱饵条目交错执行。
    private static let plan: [Entry] = [
        Entry(token: 0x1010_A001_B201_C301, isEnabled: { _ in true }) { registry in
            registry.register(ExternalServerAggregateProvider.shared)
        },
        Entry(token: 0x1010_A002_B202_C302, isEnabled: { _ in true }) { registry in
            registry.register(DeviceHardwareProvider.shared)
        },
        Entry(token: 0x1010_A003_B203_C303, isEnabled: { _ in true }) { registry in
            registry.register(DeviceAgeProvider.shared)
        },
        Entry(token: 0x1010_A004_B204_C304, isEnabled: { _ in true }) { registry in
            registry.register(AppAttestSignalProvider.shared)
        },
        Entry(token: 0x1010_A018_B218_C318, isEnabled: { _ in true }) { registry in
            registry.register(AppAttestActiveProbeProvider.shared)
        },
        Entry(token: 0x1010_A005_B205_C305, isEnabled: { _ in true }) { registry in
            registry.register(VPhoneHardwareProvider.shared)
        },
        Entry(token: 0x1010_A006_B206_C306, isEnabled: { _ in true }) { registry in
            registry.register(HardwareCapabilityProvider.shared)
        },
        Entry(token: 0x1010_A007_B207_C307, isEnabled: { _ in true }) { registry in
            registry.register(DisplayMuxProvider.shared)
        },
        Entry(token: 0x1010_A008_B208_C308, isEnabled: { _ in true }) { registry in
            registry.register(BiometricStateProvider.shared)
        },
        Entry(token: 0x1010_A009_B209_C309, isEnabled: { _ in true }) { registry in
            registry.register(LayeredConsistencyProvider.shared)
        },
        Entry(token: 0x1010_A00A_B20A_C30A, isEnabled: { _ in true }) { registry in
            registry.register(MountPointProvider.shared)
        },
        Entry(token: 0x1010_A00B_B20B_C30B, isEnabled: { _ in true }) { registry in
            registry.register(NetworkInterfaceProvider.shared)
        },
        Entry(token: 0x1010_A00C_B20C_C30C, isEnabled: { _ in true }) { registry in
            registry.register(DRMCapabilityProvider.shared)
        },
        Entry(token: 0x1010_A00D_B20D_C30D, isEnabled: { _ in true }) { registry in
            registry.register(BatteryEntropyProvider.shared)
        },
        Entry(token: 0x1010_A00E_B20E_C30E, isEnabled: { _ in true }) { registry in
            registry.register(EnvironmentConsistencyProvider.shared)
        },
        Entry(token: 0x1010_A00F_B20F_C30F, isEnabled: { _ in true }) { registry in
            registry.register(AudioRouteProvider.shared)
        },
        Entry(token: 0x1010_A010_B210_C310, isEnabled: { _ in true }) { registry in
            registry.register(BasebandIsolationProvider.shared)
        },
        Entry(token: 0x1010_A011_B211_C311, isEnabled: { _ in true }) { registry in
            registry.register(GPURenderFingerprintProvider.shared)
        },
        Entry(token: 0x1010_A012_B212_C312, isEnabled: { _ in true }) { registry in
            registry.register(IMUNoiseSpectrumProvider.shared)
        },
        Entry(token: 0x1010_A013_B213_C313, isEnabled: { $0.enableTemporalAnalysis }) { registry in
            registry.register(TimePatternProvider.shared)
        },
        Entry(token: 0x1010_A014_B214_C314, isEnabled: { !$0.enableTemporalAnalysis }) { registry in
            registry.unregister(id: TimePatternProvider.shared.id)
        },
        Entry(token: 0x1010_A015_B215_C315, isEnabled: { _ in true }) { registry in
            registry.register(AntiTamperingSignalProvider.shared)
        },
        Entry(token: 0x1010_A016_B216_C316, isEnabled: { _ in true }) { registry in
            registry.register(CloudPhoneEnvironmentProvider.shared)
        },
        Entry(token: 0x1010_A017_B217_C317, isEnabled: { _ in true }) { registry in
            registry.register(CertificatePinningTelemetryProvider.shared)
        },
        Entry(token: 0x1010_A019_B219_C319, isEnabled: { _ in true }) { registry in
            registry.register(HoneypotConflictFieldProvider.shared)
        },
        Entry(token: 0x1010_A01A_B21A_C31A, isEnabled: { _ in true }) { registry in
            registry.register(AppLifecycleHeartbeatProvider.shared)
        },
        Entry(token: 0x1010_A01B_B21B_C31B, isEnabled: { _ in true }) { registry in
            registry.register(IntegrityChainSealProvider.shared)
        },
        // ── 诱饵条目 — 详见 DecoyProviders.swift ──────────────────────────────
        // 它们在 __data 中与真实 provider 外观一致；token 取自不同的混合空间，
        // 使异或排序后与真实条目交错，而不是在 plan 末尾形成容易被静态识别的连续批次。
        Entry(token: 0x7E94_3F2A_18B6_D571, isEnabled: { _ in true }) { registry in
            registry.register(EnclaveAttestEntropyProvider.shared)
        },
        Entry(token: 0x4C58_E0A1_B7D3_2691, isEnabled: { _ in true }) { registry in
            registry.register(ThermalThrottleAnomalyProvider.shared)
        },
        Entry(token: 0xA39B_5C04_F2E8_481D, isEnabled: { _ in true }) { registry in
            registry.register(IndirectBranchPredictionProvider.shared)
        },
        Entry(token: 0x2D67_BA12_905E_C7F4, isEnabled: { _ in true }) { registry in
            registry.register(KernelPageTableScanProvider.shared)
        },
        Entry(token: 0xF815_4928_60AC_3E73, isEnabled: { _ in true }) { registry in
            registry.register(MachVoucherChainProvider.shared)
        },
        Entry(token: 0x5BCE_71D5_8324_6A0B, isEnabled: { _ in true }) { registry in
            registry.register(DyldClosureCacheProvider.shared)
        },
        Entry(token: 0x9302_FE6B_47CD_152A, isEnabled: { _ in true }) { registry in
            registry.register(ARM64PointerAuthProvider.shared)
        },
        Entry(token: 0x68A4_DC93_B105_72EF, isEnabled: { _ in true }) { registry in
            registry.register(XPCConnectionAuditProvider.shared)
        },
    ]

    /// 封存后允许再次注册的内置 provider id 集合；不在集合内的注册会被拒绝。
    static let internalProviderIDs: Set<String> = Set(internalProviders.map(\.id))

    /// 按混淆后的顺序执行计划：只执行 `isEnabled(config)` 为真的条目。
    static func apply(to registry: RiskSignalProviderRegistry, config: CPRiskConfig) {
        // 异或后再排序：源码中的业务分组顺序不会泄漏到运行时的注册顺序。
        let orderedPlan = plan.sorted { lhs, rhs in
            (lhs.token ^ tokenMix) < (rhs.token ^ tokenMix)
        }
        for entry in orderedPlan where entry.isEnabled(config) {
            entry.apply(registry)
        }
    }
}

/// ## 线程模型（所有 Provider 必须遵守）
///
/// `collectWithTimeout` 是 Registry 的线程模型守卫：
///
/// **主线程调用路径（来自 UI 事件 / @MainActor 方法）**
/// - `collectWithTimeout` 检测到 `Thread.isMainThread == true` 时，直接同步执行 `provider.signals`。
/// - Provider 内部**不得**使用 `DispatchQueue.main.sync` 或 `semaphore.wait`，
///   否则主线程会在等待自己的队列时死锁（self-deadlock）。
/// - Provider 内部可以自由使用 `DispatchQueue.main.async`（不等待）。
///
/// **后台线程调用路径（来自 global 队列 / Task）**
/// - `collectWithTimeout` 在后台线程使用 `DispatchQueue.global().async + semaphore.wait(timeout:3s)`。
/// - Provider 内部可以使用 `DispatchQueue.main.sync`（跨线程等待主线程，不会死锁）。
/// - Provider 内部**不得**在主线程上再 `semaphore.wait`，否则回到主线程后会形成
///   「主线程 wait → 依赖主队列的 asyncAfter → 永不触发」的二次死锁。
///
/// **Provider 实现规范（摘要）**
/// - 需要 UIKit/CoreHaptics 的调用：用 `runOnMainIfNeeded { ... }`（即 `main.sync` 包装）。
/// - 需要延迟 + 等待结果的调用（如 proximitySensor）：
///   必须先 `guard !Thread.isMainThread` 跳过主线程，延迟调度用 `DispatchQueue.global().asyncAfter`，
///   读写 UIDevice 状态仍需内嵌 `DispatchQueue.main.sync`。
/// - 纯计算或 Darwin/POSIX API（getifaddrs、sysctl、LAContext）：无线程限制，直接调用。
///
/// 进程内单例注册表；所有可变状态由 `UnfairLock` 串行化，信号收集期间不长时间持锁。
final class RiskSignalProviderRegistry {
    static let shared = RiskSignalProviderRegistry()
    private init() {}

    /// 单个 Provider 执行超时时间（秒）
    private static let providerTimeoutSeconds: Double = 3.0
    /// 连续失败阈值，超过后跳过该 provider
    private static let maxConsecutiveFailures = 3
    // 连续失败（含超时）3 次后熔断，避免慢 provider 每轮评估都拖满 3 秒预算。

    private let lock = UnfairLock()
    /// 当前生效的 provider 列表；注册/反注册时整体替换。
    private var providers: [RiskSignalProvider] = []
    /// `start()` 后置 true；封存后禁止替换内置 provider。
    private(set) var isSealed = false
    /// 封存时的 provider id → 类型指纹，用于检测同 id 换类型。
    private var sealedProviderTypes: [String: ObjectIdentifier] = [:]
    /// 封存时的内置 provider id → 实例指纹，用于检测同 id 换实例。
    private var sealedProviderInstances: [String: ObjectIdentifier] = [:]
    /// 检测到的实例替换 id；下次收集时上报篡改信号。
    private var instanceReplacedProviderIDs: Set<String> = []
    /// 曾经产出过非空信号的 provider；突然变空视为信号被抑制。
    private var activeProviderIDs: Set<String> = []
    /// 被拒绝的内置 provider 反注册次数。
    private(set) var tamperedUnregisterAttempts: Int = 0
    /// 连续失败计数（超时等）；达到阈值后跳过该 provider。
    private var consecutiveFailures: [String: Int] = [:]

    private static let internalProviderIDs = BuiltInProviderBootstrap.internalProviderIDs

    /// 封存当前注册表：记录内置 provider 的类型与实例指纹；之后注册/反注册走篡改检测路径。
    func seal() {
        lock.withLock {
            isSealed = true
            for provider in providers {
                sealedProviderTypes[provider.id] = ObjectIdentifier(type(of: provider))
                if Self.internalProviderIDs.contains(provider.id) {
                    sealedProviderInstances[provider.id] = ObjectIdentifier(provider)
                }
            }
        }
    }

    /// 注册或替换 provider（同 id 覆盖）。
    /// 封存后仅允许内置 provider 以“同类型、同实例”重新注册。
    func register(_ provider: RiskSignalProvider) {
        lock.withLock {
            if isSealed {
                // 封存后：外部 provider 一律拒绝；内置 provider 还必须类型和实例都匹配，
                // 任一不匹配都记为篡改并拒绝注册。
                if !Self.internalProviderIDs.contains(provider.id) {
                    Logger.log("provider.register rejected (sealed): id=\(provider.id)")
                    return
                }
                if let expectedType = sealedProviderTypes[provider.id],
                   ObjectIdentifier(type(of: provider)) != expectedType {
                    Logger.log("provider.register rejected (type mismatch): id=\(provider.id)")
                    return
                }
                if let expectedInstance = sealedProviderInstances[provider.id],
                   ObjectIdentifier(provider) != expectedInstance {
                    instanceReplacedProviderIDs.insert(provider.id)
                    Logger.log("provider.register rejected (instance mismatch): id=\(provider.id)")
                    return
                }
            }
            providers.removeAll { $0.id == provider.id }
            providers.append(provider)
        }
    }

    /// 反注册 provider；封存后反注册内置 provider 会被计为篡改尝试，而不是真的移除。
    func unregister(id: String) {
        lock.withLock {
            if isSealed, Self.internalProviderIDs.contains(id) {
                tamperedUnregisterAttempts += 1
                Logger.log("provider.unregister rejected (sealed internal): id=\(id) attempts=\(tamperedUnregisterAttempts)")
                return
            }
            providers.removeAll { $0.id == id }
        }
    }

    /// 返回当前已注册的 provider id 列表（诊断用快照）。
    func listIDs() -> [String] {
        lock.withLock {
            providers.map(\.id)
        }
    }

    /// 收集所有 provider 的信号。
    /// - 先注入“反注册/实例替换”篡改信号，再逐个 provider 带超时收集。
    /// - provider 从“曾活跃”变为空数组时注入 `signalCollectionFailed`，防止攻击者静默屏蔽信号。
    /// - 单个 provider 超时不会中断其余 provider；连续失败达到阈值后直接跳过。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let (current, knownActive, unregisterAttempts, replacedIDs) = lock.withLock {
            (providers, activeProviderIDs, tamperedUnregisterAttempts, instanceReplacedProviderIDs)
        }

        var out: [RiskSignal] = []
        var newlyActive: Set<String> = []

        // 被拒绝的反注册尝试是强篡改证据：固定 85 分、layer 2，优先于普通 provider 信号。
        if unregisterAttempts > 0 {
            out.append(RiskSignal(
                id: "provider_tamper_attempt",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 85,
                evidence: ["attempts": "\(unregisterAttempts)"],
                state: .tampered,
                layer: 2,
                weightHint: 85
            ))
        }

        // 内置 provider 实例被替换同样按篡改处理，避免攻击者用同 id 假实例屏蔽检测。
        if !replacedIDs.isEmpty {
            let ids = replacedIDs.sorted().joined(separator: ",")
            out.append(RiskSignal(
                id: "provider_instance_replaced",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 85,
                evidence: ["providers": ids],
                state: .tampered,
                layer: 2,
                weightHint: 85
            ))
        }

        for provider in current {
            // 跳过连续失败过多的 provider：熔断后不再调用，避免每轮都等满超时。
            let failures = lock.withLock { consecutiveFailures[provider.id] ?? 0 }
            if failures >= Self.maxConsecutiveFailures {
                Logger.log("provider[\(provider.id)]: skipped (consecutive failures=\(failures))")
                continue
            }

            let collected: [RiskSignal] = collectWithTimeout(provider: provider, snapshot: snapshot)

            if !collected.isEmpty {
                // 只要产出过信号就记为活跃，后续变空即可识别为“信号被抑制”。
                newlyActive.insert(provider.id)
                lock.withLock { consecutiveFailures[provider.id] = 0 }
                Logger.log("provider[\(provider.id)]: signals=\(collected.count)")
                for s in collected where s.score > 0 {
                    #if DEBUG
                    let keys = s.evidence.keys.sorted().joined(separator: ",")
                    Logger.log("provider.signal: provider=\(provider.id) category=\(s.category) id=\(s.id) score=\(s.score) evidenceKeys=\(keys)")
                    #endif
                }
                out.append(contentsOf: collected)
            } else if knownActive.contains(provider.id) {
                // 过去有信号、现在突然为空：视为检测面被屏蔽，而不是“环境变干净”。
                Logger.log("provider[\(provider.id)]: unexpectedly empty — injecting tamper signal")
                out.append(RiskSignal(
                    id: "signalCollectionFailed",
                    category: "tampering",
                    score: 80,
                    evidence: ["provider": provider.id, "reason": "previously_active_now_empty"]
                ))
            }
        }

        // 活跃集合只增不减，用于检测“曾经有信号、现在突然没有”。
        lock.withLock { activeProviderIDs.formUnion(newlyActive) }

        return out
    }

    /// 合并所有 provider 的 serverSignals；返回 nil 表示没有 provider 提供聚合字段。
    func serverSignals(snapshot: RiskSnapshot) -> ServerSignals? {
        let current = lock.withLock { providers }

        var merged: ServerSignals?
        // 字段级覆盖：后注册的 provider 有值则覆盖先注册者，riskTags 整体替换。
        for provider in current {
            guard let s = provider.serverSignals(snapshot: snapshot) else { continue }
            if merged == nil { merged = s }
            else { merged = merged.map { merge($0, s) } ?? s }
        }
        if merged != nil {
            Logger.log("provider.serverSignals: merged")
        }
        return merged
    }

    /// 带超时和崩溃隔离地收集 provider 信号
    /// - 主线程调用时：直接同步执行，避免 DisplayMuxProvider/AudioRouteProvider 等内部 main.sync 导致死锁
    ///   （主线程 wait 时无法处理 main queue，后台 main.sync 会永久阻塞）
    /// - 非主线程调用时：async 到后台执行，主线程 wait 不会阻塞 main queue
    private func collectWithTimeout(provider: RiskSignalProvider, snapshot: RiskSnapshot) -> [RiskSignal] {
        // 主线程路径必须同步执行：若在这里 async 后再等待，provider 内部的 main.sync 将永久阻塞。
        if Thread.isMainThread {
            return autoreleasepool { provider.signals(snapshot: snapshot) }
        }

        let semaphore = DispatchSemaphore(value: 0)
        // Use a lock-protected box to avoid data race between background write
        // and calling thread read at the exact timeout boundary.
        // 超时边界上后台线程仍可能写入 result，用锁保证读写不数据竞争。
        let resultLock = UnfairLock()
        var result: [RiskSignal] = []

        DispatchQueue.global(qos: .userInitiated).async {
            let collected: [RiskSignal] = autoreleasepool {
                provider.signals(snapshot: snapshot)
            }
            resultLock.withLock { result = collected }
            semaphore.signal()
        }

        // 超时视为一次失败并返回空信号；provider 自身无法被强制取消，只能等其自然结束。
        let timeout = DispatchTime.now() + Self.providerTimeoutSeconds
        if semaphore.wait(timeout: timeout) == .timedOut {
            Logger.log("provider[\(provider.id)]: timed out after \(Self.providerTimeoutSeconds)s")
            lock.withLock { consecutiveFailures[provider.id, default: 0] += 1 }
            return []
        }

        return resultLock.withLock { result }
    }

    /// 字段级合并两个 ServerSignals：`b` 的非 nil 字段优先，其余保留 `a`。
    private func merge(_ a: ServerSignals, _ b: ServerSignals) -> ServerSignals {
        ServerSignals(
            publicIP: b.publicIP ?? a.publicIP,
            asn: b.asn ?? a.asn,
            asOrg: b.asOrg ?? a.asOrg,
            isDatacenter: b.isDatacenter ?? a.isDatacenter,
            ipDeviceAgg: b.ipDeviceAgg ?? a.ipDeviceAgg,
            ipAccountAgg: b.ipAccountAgg ?? a.ipAccountAgg,
            geoCountry: b.geoCountry ?? a.geoCountry,
            geoRegion: b.geoRegion ?? a.geoRegion,
            riskTags: (b.riskTags ?? a.riskTags)
        )
    }
}
