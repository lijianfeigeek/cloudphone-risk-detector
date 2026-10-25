// FridaThreadDetector：从线程与 Mach 异常端口侧识别 Frida 注入。
// Frida 运行时会创建 gum-js-loop/gmain/gdbus 等额外线程，并可能接管异常端口；
// 线程数量和异常端口独立于端口/模块/内存痕迹，是多路互补证据之一。
// 仅真机执行，模拟器语义不同直接跳过。
import Darwin
import CRiskCore
import Foundation
import MachO

/// 检测 Frida 注入的线程枚举异常与 Mach 异常端口劫持
///
/// 实现两种检测技术：
/// 1. 线程枚举异常 — 检测 Frida 的 GumJS/GLib 额外线程（gum-js-loop、gmain、gdbus 等）
/// 2. Mach 异常端口劫持 — 检测 Frida 劫持的异常处理端口
/// Frida 线程与异常端口检测器。
/// - 线程模型：同步查询 `task_threads`/`thread_info`，不修改目标线程。
/// - 误报控制：线程名需匹配特征，异常端口需非空且非占位值。
struct FridaThreadDetector: Detector {
    /// 单个线程的执行观察：线程端口、PC，以及 PC 是否落在可执行镜像内。
    private struct ThreadExecObservation {
        let threadPort: mach_port_t
        let pc: UInt64
        let isForeignExecutable: Bool
    }

    /// 执行线程异常与异常端口劫持两类检测（封顶 80）。
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []

        let (threadScore, threadMethods) = detectAnomalousThreads()
        score += threadScore
        methods.append(contentsOf: threadMethods)

        let (exceptionScore, exceptionMethods) = detectExceptionPortHijack()
        score += exceptionScore
        methods.append(contentsOf: exceptionMethods)

        return DetectorResult(score: min(score, 80), methods: methods)
#endif
    }

    // MARK: - 1. 线程枚举异常检测

    /// 枚举线程，检查挂起计数、线程级异常端口、线程名与执行位置。
    private func detectAnomalousThreads() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        var threadList: thread_act_array_t?
        var threadCount: mach_msg_type_number_t = 0
        // task_threads 获取当前任务的全部线程端口。
        let kr = task_threads(mach_task_self_, &threadList, &threadCount)
        guard kr == KERN_SUCCESS, let threads = threadList else {
            return (0, [])
        }
        // 归还内核返回的线程数组，避免端口权限泄漏。
        defer {
            vm_deallocate(
                mach_task_self_,
                vm_address_t(UInt(bitPattern: threads)),
                vm_size_t(Int(threadCount) * MemoryLayout<thread_act_t>.size)
            )
        }

        // 可疑线程名标记（gum-js-loop、gmain、gdbus 等）。
        let suspiciousNames = ObfuscatedConstants.fridaThreadNameMarkers
        // C 侧快照：记录每个线程的 PC 是否位于可执行镜像内。
        let threadExecObservations = loadThreadExecObservations(capacity: Int(threadCount))

        for i in 0..<Int(threadCount) {
            let thread = threads[i]
            
            // 1a. 线程挂起计数检测：Frida 会挂起线程以改写其状态。
            // 1a. 异常挂起检测 (thread_info: suspend_count)
            var thInfo = thread_basic_info_data_t()
            var thInfoCount = mach_msg_type_number_t(MemoryLayout<thread_basic_info_data_t>.stride / MemoryLayout<integer_t>.stride)
            let infoResult = withUnsafeMutablePointer(to: &thInfo) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(thInfoCount)) { rebound in
                    thread_info(thread, thread_flavor_t(THREAD_BASIC_INFO), rebound, &thInfoCount)
                }
            }
            if infoResult == KERN_SUCCESS {
                // 假定 index 0 为主线程；其他线程被挂起才可疑。
                // 启发式：假定 index 0 为主线程，其他为非主线程
                // 非主线程 suspend_count > 0 说明被外部挂起，给 20 分。
                if i > 0 && thInfo.suspend_count > 0 {
                    score += 20
                    methods.append("\(ObfuscatedConstants.signalThreadAnomaly)_suspension:\(thInfo.suspend_count)")
                }
            }

            // 1b. 线程级异常端口检测
            // 1b. 线程级异常端口检测。
            var masks = [exception_mask_t](repeating: 0, count: Int(EXC_TYPES_COUNT))
            var ports = [mach_port_t](repeating: 0, count: Int(EXC_TYPES_COUNT))
            var behaviors = [exception_behavior_t](repeating: 0, count: Int(EXC_TYPES_COUNT))
            var flavors = [thread_state_flavor_t](repeating: 0, count: Int(EXC_TYPES_COUNT))
            var count = mach_msg_type_number_t(EXC_TYPES_COUNT)

            // 只查询 Frida 常接管的四类异常。
            let excMask = EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_BREAKPOINT | EXC_MASK_SOFTWARE
            let excResult = thread_get_exception_ports(
                thread,
                exception_mask_t(excMask),
                &masks,
                &count,
                &ports,
                &behaviors,
                &flavors
            )

            if excResult == KERN_SUCCESS {
                for j in 0..<Int(count) {
                    let port = ports[j]
                    // 端口非空且非占位值：异常处理已被接管。
                    if port != MACH_PORT_NULL && port != mach_port_t(bitPattern: -1) {
                        score += 30
                        methods.append("\(ObfuscatedConstants.methodPrefixFridaExceptionThreadMask)\(masks[j])")
                        break
                    }
                }
            }

            // 获取 pthread 句柄以读取线程名。
            guard let pt = pthread_from_mach_thread_np(thread) else { continue }

            var name = [CChar](repeating: 0, count: 256)
            guard pthread_getname_np(pt, &name, 256) == 0 else { continue }

            let threadName = String(cString: name).lowercased()
            guard !threadName.isEmpty else { continue }

            // 线程名命中可疑标记。
            if let marker = suspiciousThreadMarker(in: threadName, markers: suspiciousNames) {
                if let foreignExecMethod = foreignExecutionMethod(
                    marker: marker,
                    observation: threadExecObservations[thread]
                ) {
                    // 若 PC 不在任何可执行镜像内，追加 foreign_exec 强证据。
                    score += 24
                    methods.append(foreignExecMethod)
                } else {
                    score += 15
                    methods.append("\(ObfuscatedConstants.methodPrefixFridaThreadName)\(marker)")
                }
            }
        }

        // 典型 iOS 应用约 5–15 个线程；超过 25 个说明有额外运行时。
        // 线程数量异常：典型 iOS 应用约 5–15 个线程，Frida 会额外增加 2–5 个
        if threadCount > 25 {
            score += 8
            methods.append("\(ObfuscatedConstants.methodPrefixFridaThreadName)count_anomaly:\(threadCount)")
        }

        // 线程证据封顶 40。
        return (min(score, 40), methods)
    }

    /// 测试入口：构造 foreign_exec 方法名。
    internal func foreignExecutionMethodForTesting(
        marker: String,
        hasForeignExecutableThread: Bool,
        threadPort: mach_port_t = 0,
        pc: UInt64 = 0
    ) -> String? {
        let observation = hasForeignExecutableThread
            ? ThreadExecObservation(threadPort: threadPort, pc: pc, isForeignExecutable: true)
            : nil
        return foreignExecutionMethod(marker: marker, observation: observation)
    }

    // MARK: - 2. Mach 异常端口劫持检测

    /// 检测任务级异常端口是否被非空端口接管。
    private func detectExceptionPortHijack() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        var masks = [exception_mask_t](repeating: 0, count: Int(EXC_TYPES_COUNT))
        var ports = [mach_port_t](repeating: 0, count: Int(EXC_TYPES_COUNT))
        var behaviors = [exception_behavior_t](repeating: 0, count: Int(EXC_TYPES_COUNT))
        var flavors = [thread_state_flavor_t](repeating: 0, count: Int(EXC_TYPES_COUNT))
        var count = mach_msg_type_number_t(EXC_TYPES_COUNT)

        // 使用常见异常类型掩码（Frida 通常劫持 BAD_ACCESS/BAD_INSTRUCTION/BREAKPOINT/SOFTWARE）
        // 与线程级一致，只查询常见异常类型。
        let excMask = EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_BREAKPOINT | EXC_MASK_SOFTWARE
        let kr = task_get_exception_ports(
            mach_task_self_,
            exception_mask_t(excMask),
            &masks,
            &count,
            &ports,
            &behaviors,
            &flavors
        )

        guard kr == KERN_SUCCESS else {
            return (0, [])
        }

        let safeCount = min(Int(count), Int(EXC_TYPES_COUNT))
        for i in 0..<safeCount {
            let port = ports[i]
            // 任务级异常端口非空：可能有调试器/Frida 接管，20 分。
            if port != MACH_PORT_NULL && port != mach_port_t(bitPattern: -1) {
                score += 20
                methods.append("\(ObfuscatedConstants.methodPrefixFridaExceptionMask)\(masks[i])")
                break
            }
        }

        return (score, methods)
    }

    /// 在候选标记中查找线程名包含的标记。
    private func suspiciousThreadMarker(in threadName: String, markers: [String]) -> String? {
        for marker in markers where threadName.contains(marker) {
            return marker
        }
        return nil
    }

    /// 读取 C 侧线程执行快照，构建 thread_port -> 观察值 的映射。
    private func loadThreadExecObservations(capacity: Int) -> [mach_port_t: ThreadExecObservation] {
        guard capacity > 0 else { return [:] }
        // 快照缓冲区容量与线程数一致；C 侧返回失败时返回空映射。
        var snapshot = cprisk_thread_pc_exec_snapshot_t()
        var entries = Array(repeating: cprisk_thread_pc_exec_entry_t(), count: capacity)
        let rc = entries.withUnsafeMutableBufferPointer { buffer in
            cprisk_thread_pc_exec_snapshot(buffer.baseAddress, UInt32(buffer.count), &snapshot)
        }
        guard rc == 0 else {
            return [:]
        }

        let written = min(Int(snapshot.entries_written), entries.count)
        var observations: [mach_port_t: ThreadExecObservation] = [:]
        observations.reserveCapacity(written)
        for entry in entries.prefix(written) {
            let threadPort = mach_port_t(entry.thread_port)
            guard threadPort != MACH_PORT_NULL else { continue }
            // state 可读、PC 非 0 且不在可执行镜像内，才判定为 foreign execution。
            let isForeignExecutable =
                entry.thread_get_state_kern_return == KERN_SUCCESS
                && entry.pc != 0
                && entry.pc_in_executable_image == 0
            observations[threadPort] = ThreadExecObservation(
                threadPort: threadPort,
                pc: entry.pc,
                isForeignExecutable: isForeignExecutable
            )
        }
        return observations
    }

    /// 若线程执行位置异常，生成带端口与 PC 的 foreign_exec 方法名。
    private func foreignExecutionMethod(
        marker: String,
        observation: ThreadExecObservation?
    ) -> String? {
        guard let observation, observation.isForeignExecutable else { return nil }
        let portHex = String(observation.threadPort, radix: 16)
        let pcHex = String(observation.pc, radix: 16)
        return "\(ObfuscatedConstants.methodPrefixFridaThreadName)foreign_exec:\(marker):port_0x\(portHex):pc_0x\(pcHex)"
    }
}

// MARK: - RiskSignal 转换

/// 信号转换：线程异常与异常端口分别成信号。
extension FridaThreadDetector {
    /// 线程异常命中 state=tampered；异常端口命中固定 20 分。
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        // 兼容旧方法前缀与 signalThreadAnomaly，聚合线程类证据。
        let threadMethods = result.methods.filter {
            $0.hasPrefix(ObfuscatedConstants.detectorIDFridaThread) || $0.hasPrefix(ObfuscatedConstants.signalThreadAnomaly)
        }
        if !threadMethods.isEmpty {
            signals.append(RiskSignal(
                id: ObfuscatedConstants.signalThreadAnomaly,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(threadMethods.count) * 10, 30),
                evidence: [
                    "methods": threadMethods.joined(separator: ","),
                    "count": "\(threadMethods.count)"
                ],
                state: .tampered,
                layer: 2,
                weightHint: 75
            ))
        }

        // 异常端口类证据单独成信号，weightHint 85 表示高置信。
        let exceptionMethods = result.methods.filter { $0.hasPrefix(ObfuscatedConstants.methodPrefixFridaException) }
        if !exceptionMethods.isEmpty {
            signals.append(RiskSignal(
                id: ObfuscatedConstants.signalFridaExceptionPort,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 20,
                evidence: ["detail": exceptionMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 85
            ))
        }

        return signals
    }
}
