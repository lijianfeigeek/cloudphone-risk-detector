// 调试器附加检测器：综合 sysctl P_TRACED、父进程路径、调试环境变量、本地调试端口、
// csops 调试标志、硬件/软件断点、信号探测、tty、可疑线程、开发者磁盘与异常投递超时，
// 以累加分值判断进程是否处于被调试/被注入状态（封顶 100）。
// 单项证据都可能误报（如 IDE 调试），因此不做单项否决，而由多个弱证据叠加进入高分区。
// 模拟器直接降级为 0 分；所有探测失败均按“未命中”处理，不阻断其它检测器。

import CRiskCore
import Darwin
import Foundation

/// 调试器附加的多表面检测器。
///
/// 每一类探针命中后累加固定权重，`methods` 中保留来源前缀，便于服务端归因。
struct DebuggerDetector: Detector {
    /// 父进程路径中的调试器关键字（lldb/gdb/debugserver 等，列表在混淆常量中）。
    let debuggerParentNeedles: [String] = ObfuscatedConstants.debuggerParentNeedles

    /// 调试/注入框架常用的环境变量键；存在即视为可疑，不比较具体取值。
    let debuggerEnvKeys: [String] = ObfuscatedConstants.debuggerInstrumentationEnvironmentKeys

    /// 调试器常用本地监听端口；通过 127.0.0.1 连接尝试判断是否有进程在等调试连接。
    let debuggerPorts: [Int] = ObfuscatedConstants.debuggerPorts

    /// 执行全部调试探针并汇总分值。
    ///
    /// - 分值封顶 100，避免多个探针重复命中同一事实时溢出评分区间。
    /// - C 侧看门狗快照提供 Swift 层无法获取的断点与异常投递视角。
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []
        // 反调试看门狗由后台线程持续采样，补充当前时刻快照看不到的历史异常。
        let watchdogSnapshot = CPRiskKit.shared.antiDebugWatchdogSnapshot()

        let dp = ObfuscatedConstants.methodPrefixDebugger
        if isBeingDebugged() {
            // P_TRACED 是最可信的附加证据，单此项即可让评分进入中高区间。
            score += 35
            methods.append("\(dp)attached")
        }

        if hasDebuggerParent() {
            // 父进程为调试器可能只是 Xcode/TestFlight 调试，故权重低于 P_TRACED。
            score += 20
            methods.append("\(dp)parent")
        }

        if hasDebuggerEnv() {
            // 环境变量可被正常开发工具设置，权重进一步降低。
            score += 15
            methods.append("\(dp)environment")
        }

        if hasDebuggerPort() {
            // 本地调试端口监听说明有调试器等待连接，但端口也可能被其它进程占用。
            score += 10
            methods.append("\(dp)port")
        }

        if cprisk_csops_debug_check() != 0 {
            // csops 查询内核里的调试标志，绕过用户态对 sysctl 的 Hook。
            score += 30
            methods.append("\(dp)csops_debugged")
        }

        if cprisk_detect_hardware_breakpoints() != 0 {
            // 硬件断点由调试寄存器/内核状态体现，正常业务代码不会设置。
            score += 25
            methods.append("\(dp)hardware_breakpoint")
        }

        let softwareBreakpointCount = softwareBreakpointScanCount()
        if softwareBreakpointCount > 0 {
            // 在当前线程代码段主动扫描 BRK 指令，命中数量越多越可信。
            score += 18
            methods.append("\(dp)software_breakpoint:\(softwareBreakpointCount)")
        } else if watchdogSnapshot.softwareBreakpointDetected ||
                    watchdogSnapshot.softwareBreakpointAnomalyCount > 0 ||
                    (watchdogSnapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SOFTWARE_BP)) != 0 {
            // 当前扫描未命中但看门狗历史上见过：只给较低权重，避免瞬时竞态误判。
            score += 10
            methods.append("\(dp)software_breakpoint:\(ObfuscatedConstants.keywordWatchdog)")
        }

        if (watchdogSnapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_INSTANT_RETURN_PATCH)) != 0 {
            // 函数入口被改写为立即返回（instant return），是绕过检测的典型内联补丁。
            score += 16
            methods.append("\(dp)instant_return_patch")
        }

        if cprisk_probe_debugger_via_signal() != 0 {
            // 通过信号投递探测调试器是否接管异常，能发现部分隐藏的附加方式。
            score += 20
            methods.append("\(dp)signal_probe")
        }

        if cprisk_detect_tty_debug() != 0 {
            // 调试会话常伴随 tty 设备；权重低，仅作辅助证据。
            score += 10
            methods.append("\(dp)tty")
        }

        let suspiciousThreads = cprisk_detect_suspicious_threads()
        if suspiciousThreads > 0 {
            // 注入框架会创建特征线程；按数量放大，但封顶 30 防止线程数噪声主导评分。
            score += min(Double(suspiciousThreads) * 15, 30)
            methods.append("\(dp)suspicious_threads:\(suspiciousThreads)")
        }

        if cprisk_detect_developer_disk() != 0 {
            // 挂载开发者磁盘镜像通常意味着设备处于开发/调试配置，单此项不足以下结论。
            score += 8
            methods.append("\(dp)developer_disk")
        }

        if hasExceptionDeliveryTimeout(
            anomalyFlags: watchdogSnapshot.anomalyFlags,
            timeoutDetected: watchdogSnapshot.exceptionDeliveryTimeoutDetected,
            timeoutAnomalyCount: watchdogSnapshot.exceptionDeliveryTimeoutAnomalyCount
        ) {
            // 调试器接管异常端口后，异常投递会变慢或超时，是内核层 Hook 的间接证据。
            score += 14
            methods.append("\(dp)exception_delivery_timeout")
        }

        return DetectorResult(score: min(score, 100), methods: methods)
#endif
    }

    /// 通过 `sysctl(KERN_PROC_PID)` 读取 `kp_proc.p_flag` 的 P_TRACED 位。
    /// - 直接使用 `cprisk_getpid_direct()` 获取 pid，避免被 Hook 的 getpid 误导。
    /// - sysctl 失败时返回 false（偏向漏报而非误报）。
    private func isBeingDebugged() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, cprisk_getpid_direct()]
        var size = MemoryLayout<kinfo_proc>.size
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0 else { return false }
        return (info.kp_proc.p_flag & tracedFlag) != 0
    }

    /// 读取父进程可执行路径并匹配调试器关键字。
    /// 父进程已退出或路径不可读时返回 false，不影响其它探针。
    private func hasDebuggerParent() -> Bool {
        guard let name = processPath(for: cprisk_getppid_direct()) else { return false }
        return firstDebuggerParentToken(in: name) != nil
    }

    /// 逐个检查调试环境变量是否存在于当前进程环境。
    /// - 使用 `getenv` 而非 `ProcessInfo.environment`，避免一次性复制整个环境字典。
    private func hasDebuggerEnv() -> Bool {
        for key in debuggerEnvKeys {
            if key.withCString({ getenv($0) != nil }) {
                return true
            }
        }
        return false
    }

    /// 检查任一调试端口是否在 127.0.0.1 上可连接。
    private func hasDebuggerPort() -> Bool {
        debuggerPorts.contains(where: isPortOpen)
    }

    /// 扫描当前线程附近的软件断点（BRK）指令。
    /// - 传入信号探测函数指针而非固定地址，避免二进制里的常量地址被静态定位。
    /// - 扫描窗口固定 256 字节，兼顾命中率与执行成本。
    private func softwareBreakpointScanCount() -> Int32 {
        typealias SignalProbeFn = @convention(c) () -> Int32
        let probeFn: SignalProbeFn = cprisk_probe_debugger_via_signal
        let probePtr = unsafeBitCast(probeFn, to: UnsafeRawPointer.self)
        return cprisk_scan_software_breakpoints(probePtr, 256)
    }

    /// 汇总看门狗中“异常投递超时”的三种表示（标志位/布尔值/计数），任一成立即命中。
    private func hasExceptionDeliveryTimeout(
        anomalyFlags: UInt32,
        timeoutDetected: Bool,
        timeoutAnomalyCount: UInt64
    ) -> Bool {
        let timeoutFlag = (anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_DELIVERY_TIMEOUT)) != 0
        return timeoutFlag ||
            timeoutDetected ||
            timeoutAnomalyCount > 0
    }

    /// 通过直连 syscall 尝试连接 127.0.0.1 的指定端口。
    /// - 使用 `cprisk_socket_direct`/`cprisk_connect_direct` 绕过可能被 Hook 的 libc。
    /// - 仅本机回环，不产生外网流量；连接失败即视为端口未监听。
    private func isPortOpen(_ port: Int) -> Bool {
        var rawErrno: CInt = 0
        let socketFd = cprisk_socket_direct(AF_INET, SOCK_STREAM, 0, &rawErrno)
        guard socketFd >= 0 else { return false }
        defer { _ = cprisk_close_direct(socketFd, nil) }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        // 端口必须转网络字节序，否则会连到错误端口。
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr -> Int32 in
                var connectErrno: CInt = 0
                return cprisk_connect_direct(socketFd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size), &connectErrno)
            }
        }
        return result == 0
    }

    /// 在父进程路径中查找首个调试器关键字（大小写不敏感），返回命中的关键字供证据记录。
    func firstDebuggerParentToken(in parentProcessPath: String) -> String? {
        let normalized = parentProcessPath.lowercased()
        return debuggerParentNeedles.first(where: { normalized.contains($0) })
    }
}

/// `kp_proc.p_flag` 中的 P_TRACED 位：置位表示进程正被 ptrace 跟踪。
private let tracedFlag: Int32 = 0x00000800
