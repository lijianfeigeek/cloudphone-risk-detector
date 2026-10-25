// 诱饵信号提供者池：8 个“长得像真 Provider”的诱饵，与真实内置 Provider 交错注册进启动计划，
// 使攻击者扫描连续函数指针表/类列表时无法区分真假检测器，抬高枚举与定点 patch 的成本。
// 每个诱饵都执行真实的 Darwin/POSIX 探测，并把结果写进只写不读的黑洞变量，防止优化器消除计算；
// 这样基于耗时的探测也无法凭调用时长区分“诱饵”与“本次未命中的真 Provider”。
// 诱饵永远返回空信号，不影响 TPR/FPR；增减诱饵只需改文件末尾的 DecoyProviderBootstrap.providers。

import Darwin
import Foundation
import MachO
import Security

// 设计取舍：不能通过随机丢弃真实信号来迷惑攻击者（会破坏 TPR/FPR 契约），但可以扩大
// “静态可见的攻击面”，让“哪些检测器被接线”不再能从二进制里直接枚举出来。
// 每个诱饵具备与真 Provider 相同的形状：shared 单例、稳定 id、以及一段有合理命名的非空实现。

// MARK: - Decoy 1: EnclaveAttestEntropy

/// 诱饵：伪造“安全隔区熵源”探测，实际只做一次 SecRandomCopyBytes 并混合结果。
final class EnclaveAttestEntropyProvider: RiskSignalProvider {
    static let shared = EnclaveAttestEntropyProvider()
    private init() {}
    let id = "enclave_attest_entropy"

    /// 执行诱饵计算后返回空信号；常量来自 xxHash/golden-ratio 混合，仅用于制造可信的计算形态。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        var probe: UInt64 = UInt64(snapshot.deviceID.utf8.count)
        var randBytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, randBytes.count, &randBytes)
        if status == errSecSuccess {
            for byte in randBytes {
                probe = probe &* 0x9E3779B97F4A7C15 &+ UInt64(byte)
            }
        }
        DecoySink.absorb(probe)
        return []
    }
}

// MARK: - Decoy 2: ThermalThrottleAnomaly

/// 诱饵：伪造“热节流异常”探测，读取 thermalState 并混入 libc fallback 统计。
final class ThermalThrottleAnomalyProvider: RiskSignalProvider {
    static let shared = ThermalThrottleAnomalyProvider()
    private init() {}
    let id = "thermal_throttle_anomaly"

    /// 返回空信号；仅产生热状态读取的副作用，用于伪装成环境检测器。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let thermal = ProcessInfo.processInfo.thermalState
        var probe = UInt64(thermal.rawValue) ^ 0xC2B2AE3D27D4EB4F
        probe = probe &* 0x165667B19E3779F9
        probe ^= UInt64(snapshot.libcFallbackUsedMask)
        DecoySink.absorb(probe)
        return []
    }
}

// MARK: - Decoy 3: IndirectBranchPrediction

/// 诱饵：伪造“间接分支预测”探测，用固定次数的分支密集循环制造真实 CPU 负载。
final class IndirectBranchPredictionProvider: RiskSignalProvider {
    static let shared = IndirectBranchPredictionProvider()
    private init() {}
    let id = "indirect_branch_prediction"

    /// 返回空信号；循环次数固定且很小，保证 release 下仍在亚毫秒级，不拖慢评估。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        var acc: UInt64 = 0
        let baseline = mach_absolute_time()
        // 分支预测压力循环；迭代次数固定且足够小，release 下整体耗时保持在亚毫秒级。
        for i in 0..<128 {
            let mixed = UInt64(truncatingIfNeeded: i) &* 0x85EBCA77C2B2AE3D
            if (mixed & 0xFF) > 0x80 {
                acc = acc &+ mixed
            } else {
                acc = acc ^ mixed
            }
        }
        let elapsed = mach_absolute_time() &- baseline
        DecoySink.absorb(acc &+ elapsed &+ UInt64(snapshot.libcFallbackEventTotal))
        return []
    }
}

// MARK: - Decoy 4: KernelPageTableScan

/// 诱饵：伪造“内核页表扫描”探测，读取页大小与 CPU 核数。
final class KernelPageTableScanProvider: RiskSignalProvider {
    static let shared = KernelPageTableScanProvider()
    private init() {}
    let id = "kernel_pt_scan"

    /// 返回空信号；`hw.pagesize`/`hw.ncpu` 在 Darwin 上均为 int32，缓冲区宽度必须匹配。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        // hw.pagesize / hw.ncpu 在 Darwin 上返回 int32_t，显式使用 Int32 让 sysctl 缓冲区宽度
        // 与内核写入宽度一致，避免栈上越界或读到脏数据。
        var pageSize: Int32 = 0
        var pageSizeLen = MemoryLayout<Int32>.size
        sysctlbyname("hw.pagesize", &pageSize, &pageSizeLen, nil, 0)
        var ncpu: Int32 = 0
        var ncpuLen = MemoryLayout<Int32>.size
        sysctlbyname("hw.ncpu", &ncpu, &ncpuLen, nil, 0)
        let probe = UInt64(max(1, pageSize)) &* UInt64(max(1, ncpu))
                    ^ UInt64(snapshot.deviceID.utf8.count)
        DecoySink.absorb(probe)
        return []
    }
}

// MARK: - Decoy 5: MachVoucherChain

/// 诱饵：伪造“Mach voucher 链”探测，只读取 task 端口与单调时钟。
final class MachVoucherChainProvider: RiskSignalProvider {
    static let shared = MachVoucherChainProvider()
    private init() {}
    let id = "mach_voucher_chain"

    /// 返回空信号；刻意避开 mach_host_self()，因为它每次调用都会增加端口引用计数，
    /// 多会话累积会泄漏真实端口。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let task = mach_task_self_
        // 用单调时钟做“真实性”探针，形式像内核审计但无副作用。
        let ticks = mach_absolute_time()
        var probe = UInt64(task) &* 0x9E3779B97F4A7C15
        probe ^= ticks &* 0xC2B2AE3527D4EB4D
        probe ^= UInt64(snapshot.libcFallbackUsedMask)
        DecoySink.absorb(probe)
        return []
    }
}

// MARK: - Decoy 6: DyldClosureCache

/// 诱饵：伪造“dyld 闭包缓存”探测，统计已加载镜像并抽样读取一个头部。
final class DyldClosureCacheProvider: RiskSignalProvider {
    static let shared = DyldClosureCacheProvider()
    private init() {}
    let id = "dyld_closure_cache"

    /// 返回空信号；每次会话只采样一个镜像头，成本低但访问形态与真实注入检测一致。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let imgCount = _dyld_image_count()
        var probe: UInt64 = UInt64(imgCount) &* 0x85EBCA6BC2B2AE35
        // 以设备 ID 长度取模选择下标，保证同一设备行为稳定、不同设备访问点不同。
        if imgCount > 0 {
            let idx = UInt32(snapshot.deviceID.utf8.count % Int(imgCount))
            if let header = _dyld_get_image_header(idx) {
                probe ^= UInt64(UInt(bitPattern: header))
            }
        }
        DecoySink.absorb(probe)
        return []
    }
}

// MARK: - Decoy 7: ARM64PointerAuth

/// 诱饵：伪造“ARM64 指针认证”探测，读取 CPU family。
final class ARM64PointerAuthProvider: RiskSignalProvider {
    static let shared = ARM64PointerAuthProvider()
    private init() {}
    let id = "arm64_pointer_auth"

    /// 返回空信号；对 hw.cpufamily 的读取在越狱环境常被 hook，诱饵保持相同调用形态以混入其中。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        var cpuFamily: UInt32 = 0
        var size = MemoryLayout<UInt32>.size
        sysctlbyname("hw.cpufamily", &cpuFamily, &size, nil, 0)
        var probe = UInt64(cpuFamily) &* 0xFF51AFD7ED558CCD
        probe ^= UInt64(snapshot.libcFallbackEventTotal) &* 0xC4CEB9FE1A85EC53
        DecoySink.absorb(probe)
        return []
    }
}

// MARK: - Decoy 8: XPCConnectionAudit

/// 诱饵：伪造“XPC 连接审计”探测，读取 pid/uid/gid。
final class XPCConnectionAuditProvider: RiskSignalProvider {
    static let shared = XPCConnectionAuditProvider()
    private init() {}
    let id = "xpc_connection_audit"

    /// 返回空信号；getpid/getuid/getgid 都是无副作用的廉价调用，适合作为伪装探针。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let pid = getpid()
        let uid = getuid()
        let gid = getgid()
        var probe = UInt64(pid) &* 0x27D4EB2F165667C5
        probe ^= UInt64(uid) &* 0x9E3779B97F4A7C15
        probe ^= UInt64(gid) &* 0xC2B2AE3527D4EB4D
        probe ^= UInt64(snapshot.libcFallbackUsedMask)
        DecoySink.absorb(probe)
        return []
    }
}

// MARK: - Sink

/// 只写不读的黑洞：阻止优化器把诱饵计算整段消除。
/// 写入用锁保护以保证多线程安全；除 DEBUG 回读外，值不会进入任何业务逻辑。
private enum DecoySink {
    private static var black: UInt64 = 0
    private static let lock = NSLock()

    /// 把诱饵计算结果混入静态变量；调用本身即副作用。
    static func absorb(_ value: UInt64) {
        lock.lock()
        black ^= value
        lock.unlock()
    }

    /// 仅 DEBUG 下回读，确保测试构建里优化器也无法判定该变量无用。
    static func snapshot() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return black
    }
}

// MARK: - Decoy bootstrap entry point

/// 按注册计划中的固定顺序返回 8 个诱饵单例。
/// 这是增减诱饵池的唯一入口：真实 Provider 与诱饵在上层 plan 中交错排列，顺序本身不携带语义。
enum DecoyProviderBootstrap {
    static let providers: [RiskSignalProvider] = [
        EnclaveAttestEntropyProvider.shared,
        ThermalThrottleAnomalyProvider.shared,
        IndirectBranchPredictionProvider.shared,
        KernelPageTableScanProvider.shared,
        MachVoucherChainProvider.shared,
        DyldClosureCacheProvider.shared,
        ARM64PointerAuthProvider.shared,
        XPCConnectionAuditProvider.shared,
    ]
}
