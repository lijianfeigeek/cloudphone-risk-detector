// LLDB/JIT 匿名字段检测器：遍历当前 task 的虚拟内存区域，找出“匿名 + 可读写执行 + 小块”
// 的页面（典型 4KB~256KB），这是 LLDB JIT、debugserver 与 Stalker 代码缓存的共同特征。
// 同时吸收 TaskPortAuditDetector 的调试审计线索（debugserver Mach 服务、task_for_pid 异常成功、
// 仅持发送权的异常端口），形成“内存特征 + 端口审计”的双表面证据。
// 信号 id 为 SignalID.lldbJitSmallRWX：≥3 个可疑区域或审计面命中 → .tampered，否则 .soft。

import CRiskCore
import Darwin
import Foundation

/// 区域遍历的迭代上限；防止异常进程的 region 链无限增长拖垮检测线程。
private let lldbJitMaxIterations = 600
/// 视为“匿名”的 VM user_tag 取值：JIT/调试器分配的页常带这几个标签。
private let lldbJitAnonymousTags: Set<UInt32> = [240, 241, 242, 243, 244, 245]

/// 检测 LLDB/JIT 风格的匿名小块 RWX 页面。
///
/// 特征组合：
/// - 匿名映射（无文件后备）
/// - rwx 权限
/// - 小块（通常 4KB~256KB）
/// - 不属于任何已加载镜像
struct LLDBJITDetector: Detector {
    /// 来自 TaskPortAuditDetector 的调试审计线索，用于与内存特征交叉验证。
    /// 默认值全为空，便于单元测试只注入内存观测。
    struct AuditHints {
        let sendOnlyExceptionPortCount: Int
        let taskForPidUnexpectedSuccess: Bool
        let debugserverMachServiceHits: Int

        init(
            sendOnlyExceptionPortCount: Int = 0,
            taskForPidUnexpectedSuccess: Bool = false,
            debugserverMachServiceHits: Int = 0
        ) {
            self.sendOnlyExceptionPortCount = sendOnlyExceptionPortCount
            self.taskForPidUnexpectedSuccess = taskForPidUnexpectedSuccess
            self.debugserverMachServiceHits = debugserverMachServiceHits
        }
    }

    /// 单个可疑内存区域的观测结果，保留 tag/shareMode 供证据归类。
    struct RegionObservation {
        let address: UInt64
        let size: UInt64
        let userTag: UInt32
        let shareMode: UInt32
        let inImage: Bool
    }

    /// 计分结果；`totalSuspiciousSize` 用于区分“很多小页”与“一块大 JIT 缓存”。
    struct Assessment {
        let score: Double
        let methods: [String]
        let suspiciousRegionCount: Int
        let totalSuspiciousSize: UInt64
        let debugserverMachServiceHits: Int
        let taskForPidUnexpectedSuccess: Bool
    }

    /// 执行内存扫描并合并 task 端口审计线索；模拟器下两者都不可用，直接降级。
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["lldb_jit:unavailable_simulator"])
#else
        let observations = scanSmallAnonymousRWX()
        // 复用 TaskPort 审计快照：只取与 LLDB 相关的三项，避免重复遍历端口命名空间。
        let taskPortHints = TaskPortAuditDetector().collectLLDBAuditHints()
        let auditHints = AuditHints(
            sendOnlyExceptionPortCount: taskPortHints.sendOnlyExceptionPortCount,
            taskForPidUnexpectedSuccess: taskPortHints.taskForPidUnexpectedSuccess,
            debugserverMachServiceHits: taskPortHints.debugserverMachServiceHits
        )
        let assessment = assess(observations: observations, auditHints: auditHints)
        return DetectorResult(score: assessment.score, methods: assessment.methods)
#endif
    }

    /// 汇总内存观测与端口审计线索。
    /// - 任一表面为空时仍需继续评估，因为“只有端口线索、没有可见 RWX 页”也是有效证据。
    /// - 最终分值封顶 88，留给其它调试检测器组合加权的空间。
    func assess(observations: [RegionObservation], auditHints: AuditHints = AuditHints()) -> Assessment {
        let count = observations.count
        // 使用 &+ 防止畸形区域大小相加溢出并触发 Swift 运行时陷阱。
        let totalSize = observations.reduce(UInt64(0)) { $0 &+ $1.size }

        guard count > 0
            || auditHints.debugserverMachServiceHits > 0
            || auditHints.taskForPidUnexpectedSuccess
            || auditHints.sendOnlyExceptionPortCount > 0 else {
            return Assessment(
                score: 0,
                methods: ["lldb_jit:clean"],
                suspiciousRegionCount: 0,
                totalSuspiciousSize: 0,
                debugserverMachServiceHits: 0,
                taskForPidUnexpectedSuccess: false
            )
        }

        var score: Double = 0
        var methods: [String] = []

        if count >= 3 {
            // 多块匿名 RWX 是 JIT 代码缓存的强特征；每多一块 +7，封顶 60。
            score += min(30 + Double(count - 3) * 7, 60)
            methods.append("lldb_jit:small_rwx_count:\(count)")
        } else {
            // 1~2 块可能来自合法 JIT（如 JavaScriptCore），只给轻分。
            score += 8
            methods.append("lldb_jit:small_rwx_hint:\(count)")
        }

        if totalSize >= 512 * 1024 {
            // 累计超过 512KB 说明不是零散临时页，更接近完整 JIT/注入载荷。
            score += 10
            methods.append("lldb_jit:total_size_kb:\(totalSize / 1024)")
        }

        let tagSet = Set(observations.map(\.userTag))
        if tagSet.count >= 3 {
            // tag 种类多说明分配来源多样，符合调试器/JIT 引擎的多池分配行为。
            score += 6
            methods.append("lldb_jit:tag_diversity:\(tagSet.count)")
        }

        if auditHints.debugserverMachServiceHits > 0 {
            // 能查到 debugserver 的 Mach 服务，说明调试服务已在本机注册。
            score += min(26 + Double(auditHints.debugserverMachServiceHits - 1) * 8, 46)
            methods.append("lldb_jit:debugserver_mach_service_hits:\(auditHints.debugserverMachServiceHits)")
        }

        if auditHints.taskForPidUnexpectedSuccess {
            // 普通 App 对 pid=1 调用 task_for_pid 不应成功；成功意味着任务端口权限被放开。
            score += 24
            methods.append("lldb_jit:task_for_pid_unexpected_success")
        }

        if auditHints.sendOnlyExceptionPortCount > 0 {
            // 仅持发送权的异常端口表示接收端在外部进程（调试器/注入器）。
            score += min(12 + Double(auditHints.sendOnlyExceptionPortCount - 1) * 4, 20)
            methods.append("lldb_jit:exception_send_only:\(auditHints.sendOnlyExceptionPortCount)")
        }

        let hasAuditSurface =
            auditHints.debugserverMachServiceHits > 0
            || auditHints.taskForPidUnexpectedSuccess
            || auditHints.sendOnlyExceptionPortCount > 0
        if count > 0, hasAuditSurface {
            // 内存特征与端口审计同时命中，两个独立表面互相印证，额外加权。
            score += 10
            methods.append("lldb_jit:cross_surface_correlation")
        }

        return Assessment(
            score: min(score, 88),
            methods: methods,
            suspiciousRegionCount: count,
            totalSuspiciousSize: totalSize,
            debugserverMachServiceHits: auditHints.debugserverMachServiceHits,
            taskForPidUnexpectedSuccess: auditHints.taskForPidUnexpectedSuccess
        )
    }

    /// 使用 `vm_region_64` 从地址 0 开始线性遍历本 task 的虚拟内存区域。
    ///
    /// 两段查询：
    /// 1. `VM_REGION_BASIC_INFO_64` 拿保护位与区域大小；
    /// 2. 仅对候选区域查 `VM_REGION_EXTENDED_INFO` 拿 user_tag/share_mode，降低系统调用开销。
    ///
    /// 失败语义：任一区域查询失败即结束遍历（返回已收集结果），不抛错。
    private func scanSmallAnonymousRWX() -> [RegionObservation] {
        var observations: [RegionObservation] = []
        var address: vm_address_t = 0
        var iteration = 0

        while iteration < lldbJitMaxIterations {
            var size: vm_size_t = 0
            var objectName: mach_port_t = 0

            var basicInfo = vm_region_basic_info_data_64_t()
            // count 以 natural_t 为单位，必须按结构体 stride 换算，否则内核会返回参数错误。
            var basicCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_basic_info_data_64_t>.stride / MemoryLayout<natural_t>.stride
            )
            let basicResult = withUnsafeMutablePointer(to: &basicInfo) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(basicCount)) { rebound in
                    vm_region_64(
                        mach_task_self_,
                        &address,
                        &size,
                        VM_REGION_BASIC_INFO_64,
                        rebound,
                        &basicCount,
                        &objectName
                    )
                }
            }
            guard basicResult == KERN_SUCCESS, size > 0 else { break }

            let rwx = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE
            // 三个权限位同时置位才是 RWX；大小限制在 4KB~256KB，排除大段可执行堆与单页映射。
            if (basicInfo.protection & rwx) == rwx, size >= 4 * 1024, size <= 256 * 1024 {
                var extInfo = vm_region_extended_info_data_t()
                var extCount = mach_msg_type_number_t(
                    MemoryLayout<vm_region_extended_info_data_t>.stride / MemoryLayout<natural_t>.stride
                )
                var extAddress = address
                var extSize: vm_size_t = 0
                let extResult = withUnsafeMutablePointer(to: &extInfo) { ptr in
                    ptr.withMemoryRebound(to: integer_t.self, capacity: Int(extCount)) { rebound in
                        vm_region_64(
                            mach_task_self_,
                            &extAddress,
                            &extSize,
                            VM_REGION_EXTENDED_INFO,
                            rebound,
                            &extCount,
                            &objectName
                        )
                    }
                }

                if extResult == KERN_SUCCESS {
                    let userTag = UInt32(extInfo.user_tag)
                    let shareMode = UInt32(extInfo.share_mode)
                    // share_mode 0/3 表示私有或空共享；部分 JIT 分配器使用 240~245 的 user_tag。
                    let isAnonymous = shareMode == 0 || shareMode == 3 || lldbJitAnonymousTags.contains(userTag)
                    let pointer = UnsafeRawPointer(bitPattern: UInt(address))
                    // 落在已加载镜像内的 RWX 段属于合法代码，必须排除，否则会大面积误报。
                    let inImage = pointer.map { cprisk_addr_in_any_image($0) != 0 } ?? false

                    if isAnonymous && !inImage {
                        observations.append(
                            RegionObservation(
                                address: UInt64(address),
                                size: UInt64(size),
                                userTag: userTag,
                                shareMode: shareMode,
                                inImage: false
                            )
                        )
                    }
                }
            }

            let next = UInt64(address) &+ UInt64(size)
            // 地址回绕说明已到地址空间末尾或内核返回异常，立即停止避免死循环。
            if next <= UInt64(address) { break }
            address = vm_address_t(next)
            iteration += 1
        }

        return observations
    }
}

extension LLDBJITDetector {
    /// 重新扫描并转换为风险信号。
    /// - ≥3 个可疑区域，或任一审计面命中（debugserver / task_for_pid）→ `.tampered`（layer 2）。
    /// - 其余少量区域 → `.soft(confidence: 0.58)`（layer 3），由上层与其它信号联合判断。
    func asSignals() -> [RiskSignal] {
        let observations = scanSmallAnonymousRWX()
        let taskPortHints = TaskPortAuditDetector().collectLLDBAuditHints()
        let assessment = assess(
            observations: observations,
            auditHints: AuditHints(
                sendOnlyExceptionPortCount: taskPortHints.sendOnlyExceptionPortCount,
                taskForPidUnexpectedSuccess: taskPortHints.taskForPidUnexpectedSuccess,
                debugserverMachServiceHits: taskPortHints.debugserverMachServiceHits
            )
        )
        guard assessment.score > 0 else { return [] }

        // 最多记录 8 个地址，避免 evidence 体积随可疑区域数量膨胀。
        let addresses = observations
            .prefix(8)
            .map { String(format: "0x%llx", $0.address) }
            .joined(separator: ",")
        let tamperedByAudit =
            assessment.debugserverMachServiceHits > 0
            || assessment.taskForPidUnexpectedSuccess

        if assessment.suspiciousRegionCount >= 3 || tamperedByAudit {
            return [
                RiskSignal(
                    id: SignalID.lldbJitSmallRWX,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: min(35 + Double(assessment.suspiciousRegionCount) * 5, 62),
                    evidence: [
                        "region_count": "\(assessment.suspiciousRegionCount)",
                        "total_size_kb": "\(assessment.totalSuspiciousSize / 1024)",
                        "addresses": addresses,
                        "debugserver_mach_service_hits": "\(assessment.debugserverMachServiceHits)",
                        "task_for_pid_unexpected_success": assessment.taskForPidUnexpectedSuccess ? "1" : "0",
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 84
                ),
            ]
        }

        // 单块/双块匿名 RWX：可能是合法 JIT，用低分软信号保留观察，避免误杀。
        return [
            RiskSignal(
                id: SignalID.lldbJitSmallRWX,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 10,
                evidence: [
                    "region_count": "\(assessment.suspiciousRegionCount)",
                    "total_size_kb": "\(assessment.totalSuspiciousSize / 1024)",
                    "addresses": addresses,
                    "debugserver_mach_service_hits": "\(assessment.debugserverMachServiceHits)",
                    "task_for_pid_unexpected_success": assessment.taskForPidUnexpectedSuccess ? "1" : "0",
                ],
                state: .soft(confidence: 0.58),
                layer: 3,
                weightHint: 34
            ),
        ]
    }
}
