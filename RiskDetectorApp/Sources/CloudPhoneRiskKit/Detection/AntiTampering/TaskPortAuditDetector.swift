// Task 端口审计：枚举当前 task 的端口命名空间与异常端口，寻找“异常端口只持发送权”
// （接收端在外部调试器/注入器）、端口权属分布异常、对 pid=1 的 task_for_pid 意外成功、
// 以及 bootstrap 中注册的 debugserver Mach 服务。结果同时供 LLDBJITDetector 复用。
// 信号：taskPortExceptionHijack（send-only 异常端口，tampered）/ taskPortRightsAnomaly（soft）。
// 端口与内存均由内核分配，读取后必须 deallocate；任何查询失败都按零值处理而不是抛错。

import Darwin
import Foundation

/// 审计 task 端口权属与异常端口归属异常。
///
/// 重点：
/// - 当前 task 只持发送权的异常端口（接收端很可能是外部调试器/注入器）
/// - 端口命名空间中异常的权限分布
struct TaskPortAuditDetector: Detector {
    /// bootstrap_look_up 的函数签名；通过 dlsym 动态解析，避免直接链接私有符号。
    private typealias BootstrapLookupFn = @convention(c) (
        mach_port_t,
        UnsafePointer<CChar>,
        UnsafeMutablePointer<mach_port_t>?
    ) -> kern_return_t

    /// RTLD_DEFAULT 句柄，用于在全局符号表查找 bootstrap_look_up。
    private static let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)

    /// 证据/方法字符串常量；以 base64 存放，避免明文字符串被静态检索并定位检测逻辑。
    private enum Keys {
        static let taskPortPrefix = ObfuscatedConstants.keywordTaskPort
        static let unavailableSimulator = StringDeobfuscator.base64Decode("dGFza19wb3J0OnVuYXZhaWxhYmxlX3NpbXVsYXRvcg==")
        static let clean = StringDeobfuscator.base64Decode("dGFza19wb3J0OmNsZWFu")
        static let taskForPidUnexpectedSuccess = StringDeobfuscator.base64Decode("dGFza19wb3J0OnRhc2tfZm9yX3BpZF91bmV4cGVjdGVkX3N1Y2Nlc3M=")
        // debugserver 相关的 Mach 服务名（com.apple.debugserver 及其变体）。
        static let debugserverServiceNames: [String] = [
            StringDeobfuscator.base64Decode("Y29tLmFwcGxlLmRlYnVnc2VydmVy"),
            StringDeobfuscator.base64Decode("Y29tLmFwcGxlLmR0LmRlYnVnc2VydmVy"),
            StringDeobfuscator.base64Decode("Y29tLmFwcGxlLmRlYnVnc2VydmVyLkRWVFNlY3VyZVNvY2tldFByb3h5"),
        ]
    }

    /// 提供给 LLDBJITDetector 的审计线索子集，避免其重复遍历端口命名空间。
    struct LLDBAuditHints {
        let sendOnlyExceptionPortCount: Int
        let taskForPidUnexpectedSuccess: Bool
        let debugserverMachServiceHits: Int

        static let empty = LLDBAuditHints(
            sendOnlyExceptionPortCount: 0,
            taskForPidUnexpectedSuccess: false,
            debugserverMachServiceHits: 0
        )
    }

    /// 一次采集的端口统计快照。
    struct Snapshot {
        let totalPortNames: Int
        let sendRightCount: Int
        let receiveRightCount: Int
        let sendOnceRightCount: Int
        let deadNameCount: Int
        let sendOnlyExceptionPortCount: Int
        let unknownExceptionPortCount: Int
        let taskForPidUnexpectedSuccess: Bool
        let debugserverServiceHits: [String]
    }

    /// 计分结果；`sendOnlyExceptionPortCount` 供信号层决定是否生成高置信度信号。
    struct Assessment {
        let score: Double
        let methods: [String]
        let sendOnlyExceptionPortCount: Int
    }

    /// 执行采集与评分；模拟器下很多端口语义不可用，直接降级。
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: [Keys.unavailableSimulator])
#else
        let snapshot = collectSnapshot()
        let assessment = assess(snapshot: snapshot)
        return DetectorResult(score: assessment.score, methods: assessment.methods)
#endif
    }

    /// 汇总各端口异常：
    /// - 仅持发送权的异常端口：每个 +12，从 40 起，封顶 75（最强证据）。
    /// - 异常端口权限未知：每个 +4，封顶 20。
    /// - 端口名总数 >2048：+10（注入框架常批量创建端口）。
    /// - 发送/接收权比值 >18 且发送权 >1024：+15。
    /// - 死端口名 >1500：+6；send-once 权 >800：+5。
    /// - task_for_pid(pid=1) 意外成功：+55；debugserver 服务命中：+28 起，封顶 52。
    /// - 最终封顶 90；无任何命中时返回 clean。
    func assess(snapshot: Snapshot) -> Assessment {
        var score: Double = 0
        var methods: [String] = []

        if snapshot.sendOnlyExceptionPortCount > 0 {
            // 只持发送权意味着异常由外部进程接收，这是调试器接管异常端口的直接证据。
            score += min(40 + Double(snapshot.sendOnlyExceptionPortCount - 1) * 12, 75)
            methods.append("\(Keys.taskPortPrefix):exception_send_only:\(snapshot.sendOnlyExceptionPortCount)")
        }

        if snapshot.unknownExceptionPortCount > 0 {
            score += min(8 + Double(snapshot.unknownExceptionPortCount) * 4, 20)
            methods.append("\(Keys.taskPortPrefix):exception_unknown_rights:\(snapshot.unknownExceptionPortCount)")
        }

        if snapshot.totalPortNames > 2048 {
            // 正常 App 的端口数通常在数百量级；超过 2048 提示批量分配或端口泄漏式注入。
            score += 10
            methods.append("\(Keys.taskPortPrefix):name_count_anomaly:\(snapshot.totalPortNames)")
        }

        // 接收权为 0 时比值退化为发送权数量，避免除零。
        let ratio = snapshot.receiveRightCount == 0
            ? Double(snapshot.sendRightCount)
            : Double(snapshot.sendRightCount) / Double(snapshot.receiveRightCount)
        if snapshot.sendRightCount > 1024 && ratio > 18 {
            score += 15
            methods.append("\(Keys.taskPortPrefix):send_receive_ratio:\(String(format: "%.2f", ratio))")
        }

        if snapshot.deadNameCount > 1500 {
            // 大量死端口名常见于注入框架反复探测/销毁端口。
            score += 6
            methods.append("\(Keys.taskPortPrefix):dead_name_burst:\(snapshot.deadNameCount)")
        }

        if snapshot.taskForPidUnexpectedSuccess {
            // 普通 App 不具备对 pid=1 取任务端口的权限，成功即说明权限被放开（越狱/调试环境）。
            score += 55
            methods.append(Keys.taskForPidUnexpectedSuccess)
        }

        if !snapshot.debugserverServiceHits.isEmpty {
            // 本机注册了 debugserver Mach 服务，说明调试服务可达。
            let hitCount = snapshot.debugserverServiceHits.count
            score += min(28 + Double(hitCount - 1) * 9, 52)
            methods.append("\(Keys.taskPortPrefix):debugserver_mach_service:\(hitCount)")
        }

        if snapshot.taskForPidUnexpectedSuccess, !snapshot.debugserverServiceHits.isEmpty {
            // 两个独立审计面同时命中，额外加权。
            score += 8
            methods.append("\(Keys.taskPortPrefix):debugserver_tfpid_correlation")
        }

        if snapshot.sendOnceRightCount > 800 {
            score += 5
            methods.append("\(Keys.taskPortPrefix):send_once_burst:\(snapshot.sendOnceRightCount)")
        }

        let finalScore = min(score, 90)
        let finalMethods = finalScore > 0 ? methods : [Keys.clean]
        return Assessment(
            score: finalScore,
            methods: finalMethods,
            sendOnlyExceptionPortCount: snapshot.sendOnlyExceptionPortCount
        )
    }

    /// 采集端口命名空间、异常端口、task_for_pid 与 debugserver 服务线索。
    ///
    /// 失败语义：`mach_port_names`/`task_get_exception_ports` 失败时对应统计保持 0，
    /// 不影响其余探测；所有内核返回的数组都会显式释放。
    private func collectSnapshot() -> Snapshot {
        var totalPortNames = 0
        var sendRightCount = 0
        var receiveRightCount = 0
        var sendOnceRightCount = 0
        var deadNameCount = 0

        var names: mach_port_name_array_t?
        var namesCount: mach_msg_type_number_t = 0
        var types: mach_port_type_array_t?
        var typesCount: mach_msg_type_number_t = 0

        let namesResult = mach_port_names(mach_task_self_, &names, &namesCount, &types, &typesCount)
        if namesResult == KERN_SUCCESS, let names {
            let count = Int(namesCount)
            totalPortNames = count

            for index in 0..<count {
                let portName = names[index]
                // 同一端口可能同时持多种权限，分别累计，互不排斥。
                if hasRight(portName, MACH_PORT_RIGHT_SEND) {
                    sendRightCount += 1
                }
                if hasRight(portName, MACH_PORT_RIGHT_RECEIVE) {
                    receiveRightCount += 1
                }
                if hasRight(portName, MACH_PORT_RIGHT_SEND_ONCE) {
                    sendOnceRightCount += 1
                }
                if hasRight(portName, MACH_PORT_RIGHT_DEAD_NAME) {
                    deadNameCount += 1
                }
            }

            vm_deallocate(
                mach_task_self_,
                vm_address_t(UInt(bitPattern: names)),
                vm_size_t(Int(namesCount) * MemoryLayout<mach_port_name_t>.size)
            )
            if let types {
                vm_deallocate(
                    mach_task_self_,
                    vm_address_t(UInt(bitPattern: types)),
                    vm_size_t(Int(typesCount) * MemoryLayout<mach_port_type_t>.size)
                )
            }
        }

        var sendOnlyExceptionPortCount = 0
        var unknownExceptionPortCount = 0

        var masks = [exception_mask_t](repeating: 0, count: Int(EXC_TYPES_COUNT))
        var ports = [mach_port_t](repeating: 0, count: Int(EXC_TYPES_COUNT))
        var behaviors = [exception_behavior_t](repeating: 0, count: Int(EXC_TYPES_COUNT))
        var flavors = [thread_state_flavor_t](repeating: 0, count: Int(EXC_TYPES_COUNT))
        var count = mach_msg_type_number_t(EXC_TYPES_COUNT)
        // 只查询调试/崩溃最相关的四类异常：错误访问、非法指令、断点与软件异常。
        let mask = EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_BREAKPOINT | EXC_MASK_SOFTWARE

        let exceptionResult = task_get_exception_ports(
            mach_task_self_,
            exception_mask_t(mask),
            &masks,
            &count,
            &ports,
            &behaviors,
            &flavors
        )

        if exceptionResult == KERN_SUCCESS {
            for index in 0..<Int(count) {
                let port = ports[index]
                // 空端口与 -1 哨兵值都不代表真实异常处理者，跳过。
                if port == MACH_PORT_NULL || port == mach_port_t(bitPattern: -1) {
                    continue
                }

                let hasSend = hasRight(port, MACH_PORT_RIGHT_SEND)
                let hasReceive = hasRight(port, MACH_PORT_RIGHT_RECEIVE)

                if !hasSend && !hasReceive {
                    unknownExceptionPortCount += 1
                    continue
                }
                if hasSend && !hasReceive {
                    // 只持发送权 = 异常被投递给外部接收者，调试器接管异常的典型形态。
                    sendOnlyExceptionPortCount += 1
                }
            }
        }

        var taskForPidUnexpectedSuccess = false
        do {
            let nullPort = mach_port_name_t(MACH_PORT_NULL)
            var foreignTask: mach_port_name_t = nullPort
            // 用 pid=1（launchd）做探针：正常沙箱下必然失败，成功说明任务端口权限被越权放开。
            let rc = DynamicSymbolResolver.taskForPid(mach_task_self_, 1, &foreignTask)
            if rc == KERN_SUCCESS, foreignTask != nullPort {
                taskForPidUnexpectedSuccess = true
                // 成功后拿到的任务端口必须归还，否则会泄漏 send right。
                mach_port_deallocate(mach_task_self_, foreignTask)
            }
        }

        let debugserverServiceHits = probeDebugserverMachServices()

        return Snapshot(
            totalPortNames: totalPortNames,
            sendRightCount: sendRightCount,
            receiveRightCount: receiveRightCount,
            sendOnceRightCount: sendOnceRightCount,
            deadNameCount: deadNameCount,
            sendOnlyExceptionPortCount: sendOnlyExceptionPortCount,
            unknownExceptionPortCount: unknownExceptionPortCount,
            taskForPidUnexpectedSuccess: taskForPidUnexpectedSuccess,
            debugserverServiceHits: debugserverServiceHits
        )
    }

    /// 只提取 LLDB 相关的三项线索；模拟器返回空结构。
    func collectLLDBAuditHints() -> LLDBAuditHints {
#if targetEnvironment(simulator)
        return .empty
#else
        let snapshot = collectSnapshot()
        return LLDBAuditHints(
            sendOnlyExceptionPortCount: snapshot.sendOnlyExceptionPortCount,
            taskForPidUnexpectedSuccess: snapshot.taskForPidUnexpectedSuccess,
            debugserverMachServiceHits: snapshot.debugserverServiceHits.count
        )
#endif
    }

    /// 查询 bootstrap 命名空间中是否注册了 debugserver 的 Mach 服务。
    /// - 服务存在但无权连接时仍算命中（能查到即说明服务已注册）。
    /// - 查询完成后归还 bootstrap 端口与命中服务端口的引用。
    private func probeDebugserverMachServices() -> [String] {
        var bootstrapPort: mach_port_t = mach_port_t(MACH_PORT_NULL)
        let bootstrapResult = task_get_special_port(
            mach_task_self_,
            Int32(TASK_BOOTSTRAP_PORT),
            &bootstrapPort
        )
        guard bootstrapResult == KERN_SUCCESS, bootstrapPort != mach_port_t(MACH_PORT_NULL) else {
            return []
        }
        defer {
            mach_port_deallocate(mach_task_self_, bootstrapPort)
        }

        var hits: [String] = []
        for serviceName in Keys.debugserverServiceNames {
            var servicePort: mach_port_t = mach_port_t(MACH_PORT_NULL)
            let lookupResult = Self.bootstrapLookUp(
                bootstrapPort: bootstrapPort,
                serviceName: serviceName,
                servicePort: &servicePort
            )

            if lookupResult == KERN_SUCCESS, servicePort != mach_port_t(MACH_PORT_NULL) {
                hits.append(serviceName)
                mach_port_deallocate(mach_task_self_, servicePort)
            }
        }
        return hits
    }

    /// 动态解析 `bootstrap_look_up` 并调用；符号缺失时返回 KERN_FAILURE。
    /// 使用 dlsym 而非直接引用，避免链接期依赖私有 API。
    private static func bootstrapLookUp(
        bootstrapPort: mach_port_t,
        serviceName: String,
        servicePort: UnsafeMutablePointer<mach_port_t>?
    ) -> kern_return_t {
        guard let symbol = "bootstrap_look_up".withCString({ cString in
            dlsym(rtldDefault, cString)
        }) else {
            return kern_return_t(KERN_FAILURE)
        }

        let function = unsafeBitCast(symbol, to: BootstrapLookupFn.self)
        return serviceName.withCString { cString in
            function(bootstrapPort, cString, servicePort)
        }
    }

    /// 查询指定端口是否持有某种权限（引用计数 >0）。
    private func hasRight(_ port: mach_port_name_t, _ right: mach_port_right_t) -> Bool {
        var refs: mach_port_urefs_t = 0
        let result = mach_port_get_refs(mach_task_self_, port, right, &refs)
        return result == KERN_SUCCESS && refs > 0
    }
}

extension TaskPortAuditDetector {
    /// 生成信号：
    /// - 存在仅持发送权的异常端口 → `taskPortExceptionHijack`（tampered、layer 1、weightHint 93）。
    /// - 其余非关键异常分（扣除异常端口贡献的 35 分基线）→ `taskPortRightsAnomaly`（soft、封顶 36）。
    func asSignals() -> [RiskSignal] {
        let snapshot = collectSnapshot()
        let assessment = assess(snapshot: snapshot)
        guard assessment.score > 0 else { return [] }

        var signals: [RiskSignal] = []
        if assessment.sendOnlyExceptionPortCount > 0 {
            signals.append(
                RiskSignal(
                    id: SignalID.taskPortExceptionHijack,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: min(58 + Double(assessment.sendOnlyExceptionPortCount) * 8, 85),
                    evidence: [
                        "send_only_exception_ports": "\(assessment.sendOnlyExceptionPortCount)",
                        "total_ports": "\(snapshot.totalPortNames)",
                        "\(ObfuscatedConstants.keywordTaskForPid)_unexpected_success": snapshot.taskForPidUnexpectedSuccess ? "1" : "0",
                        "debugserver_mach_service_hits": "\(snapshot.debugserverServiceHits.count)",
                    ],
                    state: .tampered,
                    layer: 1,
                    weightHint: 93
                )
            )
        }

        // 扣掉异常端口带来的高分贡献，避免同一事实在两个信号里重复计分。
        let nonCriticalScore = assessment.sendOnlyExceptionPortCount > 0 ? max(0, assessment.score - 35) : assessment.score
        if nonCriticalScore > 0 {
            signals.append(
                RiskSignal(
                    id: SignalID.taskPortRightsAnomaly,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: min(nonCriticalScore, 36),
                    evidence: [
                        "send_rights": "\(snapshot.sendRightCount)",
                        "receive_rights": "\(snapshot.receiveRightCount)",
                        "send_once_rights": "\(snapshot.sendOnceRightCount)",
                        "dead_name_count": "\(snapshot.deadNameCount)",
                        "\(ObfuscatedConstants.keywordTaskForPid)_unexpected_success": snapshot.taskForPidUnexpectedSuccess ? "1" : "0",
                        "debugserver_mach_services": snapshot.debugserverServiceHits.prefix(4).joined(separator: ","),
                        "methods": assessment.methods.joined(separator: ","),
                    ],
                    state: .soft(confidence: 0.72),
                    layer: 2,
                    weightHint: 62
                )
            )
        }

        return signals
    }
}
