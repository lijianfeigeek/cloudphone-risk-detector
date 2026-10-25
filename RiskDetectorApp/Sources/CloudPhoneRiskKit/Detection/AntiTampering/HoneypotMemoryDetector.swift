// 蜜罐内存诱饵检测器：在虚拟地址空间分散 mmap 3 块诱饵页，写入假的凭据字符串后设为 PROT_NONE。
// 内存 dump/扫描工具强行读取时会触发 SIGBUS，handler 据此标记 memory_dump_attempt_detected；
// 同时校验 SIGBUS handler 是否被替换、页保护是否被改回可读，以及主二进制是否意外导出 Frida Gadget 入口。
// 诱饵内容从不被读取或比对，只利用“触碰即缺页”的行为；handler 内全部操作均为异步信号安全。
// 信号：memory_dump_attempt_detected / honeypot_main_export_agent_entry / handler_replaced / protection_modified。

import Darwin
import Foundation
import CRiskCore

/// 页大小在进程生命周期内固定，预先取一次避免在信号上下文里调用。
private let pageSize: Int = Int(vm_page_size)
/// 保护诱饵全局状态与安装流程的锁；只在普通线程使用，信号 handler 内绝不加锁。
private let honeypotLock = UnfairLock()

// MARK: - 三页分散诱饵布局

// 三块诱饵区域分开记录基址与大小，handler 需要用它们判断故障地址是否落在诱饵内。
private var honeypotBase0: UnsafeMutableRawPointer?
private var honeypotSize0: Int = 0
private var honeypotBase1: UnsafeMutableRawPointer?
private var honeypotSize1: Int = 0
private var honeypotBase2: UnsafeMutableRawPointer?
private var honeypotSize2: Int = 0

/// Heap-allocated triggered flag; simple Int32 store is async-signal-safe
/// (POSIX guarantees sig_atomic_t-width writes are atomic in handlers).
/// Replaces deprecated OSAtomicCompareAndSwap32 / OSAtomicAdd32.
///
/// 使用堆上单独分配的 Int32 而非 Swift 全局变量，避免访问时触发运行时/锁。
private let honeypotTriggeredPtr: UnsafeMutablePointer<Int32> = {
    let p = UnsafeMutablePointer<Int32>.allocate(capacity: 1)
    p.initialize(to: 0)
    return p
}()

/// 安装前的 SIGBUS handler，用于非诱饵地址的故障继续走原处理链。
private var previousSigbusHandler: sigaction?

// MARK: - SIGBUS handler（异步信号安全：无锁、无堆分配）

/// 诱饵页被访问时的信号处理：
/// - 故障地址落在任一诱饵范围内 → 置位触发标志并推进 PC，跳过故障指令；
/// - 否则转交给安装前的 handler，保持系统原有行为。
private let honeypotSigbusHandler: @convention(c) (
    Int32, UnsafeMutablePointer<siginfo_t>?, UnsafeMutableRawPointer?
) -> Void = { sig, info, ctx in
    // 只处理 SIGBUS；拿不到故障地址时无法判定，直接返回。
    guard sig == SIGBUS, let info = info, let addr = info.pointee.si_addr else { return }
    let a = UInt(bitPattern: addr)

    // 逐块做半开区间判断；使用 &+ 防止地址范围计算在极端值上溢出。
    var matched = false
    if let b = honeypotBase0, honeypotSize0 > 0 {
        let bv = UInt(bitPattern: b)
        if a >= bv, a < bv &+ UInt(honeypotSize0) { matched = true }
    }
    if !matched, let b = honeypotBase1, honeypotSize1 > 0 {
        let bv = UInt(bitPattern: b)
        if a >= bv, a < bv &+ UInt(honeypotSize1) { matched = true }
    }
    if !matched, let b = honeypotBase2, honeypotSize2 > 0 {
        let bv = UInt(bitPattern: b)
        if a >= bv, a < bv &+ UInt(honeypotSize2) { matched = true }
    }

    if matched {
        honeypotTriggeredPtr.pointee = 1
        // 推进 PC 越过触发缺页的指令，避免处理完返回后在同一指令上无限重复 SIGBUS。
        // Handler 运行在出错线程的上下文里，修改 ucontext_t 中保存的 PC 是异步信号安全的。
        if let ctx = ctx {
            #if arch(arm64)
            // ARM64 指令定长 4 字节，直接前进一条指令。
            _ = cprisk_advance_ucontext_pc(ctx, 4)
            #elseif arch(x86_64)
            // x86_64 指令长度可变；保守前进 1 字节，后续仍会缺页并再次进入 handler，
            // 但此时标志位已置位，最终会离开该页，可接受。
            _ = cprisk_advance_ucontext_pc(ctx, 1)
            #endif
        }
        return
    }

    // 非诱饵地址：链式调用原 handler（若存在），避免破坏系统/其它 SDK 的崩溃处理。
    if let prev = previousSigbusHandler, let fn = prev.__sigaction_u.__sa_sigaction {
        fn(sig, info, ctx)
    }
}

// MARK: - 检测器

/// 蜜罐内存诱饵检测器；初始化时自动布防（多实例共享同一组诱饵页）。
struct HoneypotMemoryDetector: Detector {

    init() {
        Self.armHoneypotIfNeeded()
    }

    /// 汇总四类迹象：
    /// - 诱饵页被触碰（dump/scan）：80 分；
    /// - 主二进制导出 Gadget 入口：92 分；
    /// - SIGBUS handler 被替换：90 分；
    /// - 诱饵页保护被修改：90 分。
    /// 模拟器无法模拟缺页语义，直接降级。
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["\(ObfuscatedConstants.methodPrefixHoneypot)unavailable_simulator"])
#else
        var methods: [String] = []
        var score: Double = 0
        let hp = ObfuscatedConstants.methodPrefixHoneypot

        if honeypotTriggeredPtr.pointee != 0 {
            // 只有外部工具触碰 PROT_NONE 页才会触发，正常业务代码不会访问这些地址。
            methods.append("memory_dump_attempt_detected")
            score = max(score, 80)
        }

        if let exportedAgentSymbol = Self.mainBinarySuspiciousAgentExport() {
            // 主镜像解析出 Gadget 形状的入口符号，说明注入框架已把代理入口暴露在宿主 App 中。
            methods.append("\(ObfuscatedConstants.methodPrefixHoneypot)main_export_agent_entry:\(exportedAgentSymbol)")
            score = max(score, 92)
        }

        if Self.isHandlerReplaced() {
            // 攻击者若替换 SIGBUS handler，就能静默吞掉诱饵触发的错误。
            methods.append("\(hp)handler_replaced")
            score = max(score, 90)
        }

        if Self.isProtectionModified() {
            // 把保护位改回可读可写，是为了让 dump 工具能顺利扫描诱饵页。
            methods.append("\(hp)protection_modified")
            score = max(score, 90)
        }

        if methods.isEmpty {
            methods.append("\(hp)clean")
        }
        return DetectorResult(score: score, methods: methods)
#endif
    }

    // MARK: - 布防

    /// 首次调用时分配并保护诱饵页、安装 SIGBUS handler；后续调用直接返回。
    ///
    /// 失败语义：任一步失败都会 munmap 已分配页并放弃布防（保持 handler 不变），
    /// 不影响 SDK 其余功能，只是本次会话没有蜜罐保护。
    private static func armHoneypotIfNeeded() {
#if targetEnvironment(simulator)
        return
#else
        honeypotLock.withLock {
            // honeypotBase0 非空表示已布防，无需重复 mmap 或重复安装 handler。
            guard honeypotBase0 == nil else { return }

            var bases: [UnsafeMutableRawPointer] = []
            var sizes: [Int] = []
            var rows = ObfuscatedConstants.honeypotBaitRows
            // 填充为无意义随机数据（永不代表真实凭据），写入后页面设为
            // PROT_NONE，仅靠触碰触发的 SIGBUS 探测；内容从不被读取/比对。
            // 打乱区域顺序，避免三块诱饵在地址空间中的相对布局形成固定 [row0,row1,row2] 特征。
            for i in stride(from: rows.count - 1, through: 1, by: -1) {
                let j = Int(arc4random_uniform(UInt32(i + 1)))
                rows.swapAt(i, j)
            }

            for baits in rows {
                // 每块随机 1~2 页，使大小不固定，增加攻击者按尺寸定位的成本。
                let pagePages = 1 + Int(arc4random_uniform(2))
                let size = pageSize * pagePages
                // 先以可读写匿名私有映射分配，写入诱饵后再降权为 PROT_NONE。
                guard let ptr = mmap(
                    nil, size,
                    PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE,
                    -1, 0
                ), ptr != MAP_FAILED else {
                    // 分配失败：回收已建立区域后放弃布防。
                    for (i, b) in bases.enumerated() { munmap(b, sizes[i]) }
                    return
                }

                let mutable = UnsafeMutableRawPointer(ptr)
                var offset = 0
                for s in baits {
                    let utf8 = Array(s.utf8)
                    // 保留 1 字节给分隔符/NUL；剩余空间不足时停止写入。
                    let copyLen = min(utf8.count, size - offset - 1)
                    guard copyLen > 0 else { break }
                    memcpy(mutable.advanced(by: offset), utf8, copyLen)
                    offset += copyLen + 1
                }

                // 降权为 PROT_NONE：任何读写（包括 dump 工具的顺序扫描）都会触发 SIGBUS。
                guard mprotect(ptr, size, PROT_NONE) == 0 else {
                    munmap(ptr, size)
                    for (i, b) in bases.enumerated() { munmap(b, sizes[i]) }
                    return
                }

                bases.append(mutable)
                sizes.append(size)
            }

            // 至少需要 3 块才能保证分散布局；不足则全部回收，避免弱化诱饵效果。
            guard bases.count >= 3 else {
                for (i, b) in bases.enumerated() { munmap(b, sizes[i]) }
                return
            }
            honeypotBase0 = bases[0]; honeypotSize0 = sizes[0]
            honeypotBase1 = bases[1]; honeypotSize1 = sizes[1]
            honeypotBase2 = bases[2]; honeypotSize2 = sizes[2]

            var newAction = sigaction()
            newAction.__sigaction_u.__sa_sigaction = honeypotSigbusHandler
            // SA_SIGINFO 提供 siginfo_t（含故障地址）；SA_NODEFER 允许 handler 内再次进入（PC 推进期间）。
            newAction.sa_flags = Int32(SA_SIGINFO | SA_NODEFER)
            sigemptyset(&newAction.sa_mask)

            // 先保存旧 handler 再安装，保证非诱饵故障可以链式转交。
            var oldAction = sigaction()
            sigaction(SIGBUS, nil, &oldAction)
            previousSigbusHandler = oldAction
            sigaction(SIGBUS, &newAction, nil)
        }
#endif
    }

    // MARK: - 导出表诱饵

    /// Low-visibility bait: resolve Gadget-shaped Mach-O symbols against the **main executable** image only.
    /// We intentionally do **not** export such symbols ourselves; this path is only for catching patched
    /// payloads that accidentally expose Frida/Gadget-like entrypoints in the host app image.
    ///
    /// 通过 `dlopen(nil)` 取主镜像句柄，再尝试带/不带下划线前缀的符号名；
    /// 正常情况下必然解析失败，只有被注入/改写过导出表的环境才会命中。
    private static func mainBinarySuspiciousAgentExport() -> String? {
#if targetEnvironment(simulator)
        return nil
#else
        guard let handle = dlopen(nil, RTLD_NOW) else { return nil }
        let primary = ObfuscatedConstants.honeypotFridaAgentMainSymbol
        let candidates = [
            primary,
            // Mach-O 符号在 C 命名空间常带前导下划线，两种写法都检查。
            String(primary.drop(while: { $0 == "_" })),
        ]
        for symbol in candidates where !symbol.isEmpty {
            if dlsym(handle, symbol) != nil {
                return symbol
            }
        }
        return nil
#endif
    }

    // MARK: - 运行时完整性检查

    /// 对比当前 SIGBUS handler 指针与我们的实现是否一致。
    /// - 未布防时返回 false（没有可比较的 handler）。
    /// - 当前 handler 为空视为被移除，返回 true。
    private static func isHandlerReplaced() -> Bool {
        guard honeypotBase0 != nil else { return false }

        var current = sigaction()
        sigaction(SIGBUS, nil, &current)

        guard let currentFn = current.__sigaction_u.__sa_sigaction else { return true }
        return unsafeBitCast(currentFn, to: Int.self)
            != unsafeBitCast(honeypotSigbusHandler, to: Int.self)
    }

    /// 逐块用 vm_region_64 校验诱饵页保护位仍为 PROT_NONE；任一块异常即视为被修改。
    private static func isProtectionModified() -> Bool {
        let pages: [(UnsafeMutableRawPointer?, Int)] = [
            (honeypotBase0, honeypotSize0),
            (honeypotBase1, honeypotSize1),
            (honeypotBase2, honeypotSize2),
        ]
        for (base, size) in pages {
            guard let base = base, size > 0 else { continue }
            if !isPageProtNone(base) { return true }
        }
        return false
    }

    /// 查询包含 `ptr` 的区域并确认其保护位为 VM_PROT_NONE。
    ///
    /// 返回 false 的三种情况都代表异常：
    /// - 区域已被 munmap（查询失败）；
    /// - 查询到的区域起始地址与预期不同（被重映射到别处）；
    /// - 保护位不再是 PROT_NONE（被改回可读/可写）。
    private static func isPageProtNone(_ ptr: UnsafeMutableRawPointer) -> Bool {
        var address = vm_address_t(UInt(bitPattern: ptr))
        let expected = address
        var regionSize: vm_size_t = 0
        var info = vm_region_basic_info_data_64_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<vm_region_basic_info_data_64_t>.stride
                / MemoryLayout<natural_t>.stride
        )
        var objectName: mach_port_t = 0

        let kr = withUnsafeMutablePointer(to: &info) { infoPtr in
            infoPtr.withMemoryRebound(to: Int32.self, capacity: Int(count)) { raw in
                vm_region_64(
                    mach_task_self_,
                    &address,
                    &regionSize,
                    VM_REGION_BASIC_INFO_64,
                    raw,
                    &count,
                    &objectName
                )
            }
        }

        // Region gone (munmap'd) or starts at a different address → tampered
        guard kr == KERN_SUCCESS, address == expected else { return false }
        return info.protection == VM_PROT_NONE
    }
}

// MARK: - 信号输出

extension HoneypotMemoryDetector {
    /// 将 detect() 的 methods 逐项映射为信号；同名/前缀匹配后生成固定分值的 RiskSignal。
    /// 未识别的 method（如 clean）被忽略，因此干净状态不会产生任何信号。
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []
        for method in result.methods {
            switch method {
            case "memory_dump_attempt_detected":
                signals.append(RiskSignal(
                    id: "memory_dump_attempt_detected",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 80,
                    evidence: [
                        "reason": "honeypot_page_accessed",
                        "description": "Memory dump or scan touched protected honeypot region",
                    ],
                    state: .tampered, layer: 2, weightHint: 95
                ))
            case let m where m.hasPrefix("\(ObfuscatedConstants.methodPrefixHoneypot)main_export_agent_entry"):
                // method 形如 prefix + 符号名，取最后一段作为证据里的符号。
                let symbol = m.split(separator: ":", maxSplits: 2, omittingEmptySubsequences: false).last.map(String.init) ?? "unknown"
                signals.append(RiskSignal(
                    id: "honeypot_main_export_agent_entry",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 92,
                    evidence: [
                        "reason": "main_image_frida_agent_symbol_resolved",
                        "symbol": symbol,
                        "description": "Main executable resolved a Gadget-shaped agent entry symbol via dlsym",
                    ],
                    state: .tampered, layer: 2, weightHint: 97
                ))
            case let m where m.contains("handler_replaced"):
                signals.append(RiskSignal(
                    id: "honeypot_handler_replaced",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 90,
                    evidence: [
                        "reason": "sigbus_handler_tampered",
                        "description": "SIGBUS handler was replaced by external code",
                    ],
                    state: .tampered, layer: 2, weightHint: 98
                ))
            case let m where m.contains("protection_modified"):
                signals.append(RiskSignal(
                    id: "honeypot_protection_modified",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 90,
                    evidence: [
                        "reason": "page_protection_tampered",
                        "description": "Honeypot page protection changed from PROT_NONE",
                    ],
                    state: .tampered, layer: 2, weightHint: 98
                ))
            default:
                break
            }
        }
        return signals
    }
}
