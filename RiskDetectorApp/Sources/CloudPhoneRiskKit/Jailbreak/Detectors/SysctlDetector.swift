// Sysctl 检测器：读取进程列表、父进程与调试标志，并通过双路径 sysctl 校验发现内核信息伪造。
// 位于越狱检测管道中 `enableSysctlDetect` 分支，覆盖调试器附加、异常进程与 sysctl Hook。
// 关键安全不变量：空/不可读进程列表按系统版本基线判定是否可疑；任何篡改/追踪标记都优先于“无进程”。
import CRiskCore
import Darwin
import Foundation

/// 通过 sysctl/kern.proc 检测调试器、可疑进程与内核信息篡改。
/// 检测什么：`P_TRACED` 调试标志、空进程列表、可疑进程/父进程名、`hw.machine` 等键的双路径不一致。
/// 命中后产生 `sysctl:debugger_attached`、`proc:<name>`、`sysctl_dual_path_mismatch:<key>` 等信号，分值 10–25。
/// 误报风险：低版本系统对进程列表的沙盒策略不同，故用 ExpectedBaseline 做版本自适应；模拟器整体跳过。
struct SysctlDetector: Detector {
    /// 可疑进程名令牌（小写），来自混淆常量表。
    private var suspiciousProcessNeedles: [String] {
        ObfuscatedConstants.sysctlSuspiciousProcessNeedles
    }

    /// 可疑父进程名令牌（小写）。
    private var suspiciousParentNeedles: [String] {
        ObfuscatedConstants.sysctlSuspiciousParentNeedles
    }

    /// 执行 sysctl 相关检测。
    /// - Returns: 累计分数封顶 85 的检测结果；模拟器返回空结果。
    /// - Note: 各子检查相互独立，单项失败只影响该项证据。
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        // 模拟器行为与真实 iOS 不同，容易误报，直接跳过。
        return .empty
#else
        var score: Double = 0
        var methods: [String] = []
        // 使用混淆常量拼接前缀，避免二进制中出现完整明文信号名。
        let hookPrefix = "\(ObfuscatedConstants.keywordHook):"
        let logPrefix = "\(ObfuscatedConstants.keywordJailbreak).sysctl.hit: "

        // [4.4.7] ExpectedBaseline: 低版本上空进程列表视为被 Hook
        if let processList = readProcessList() {
            let infos = processList.infos
            // 能读到进程列表本身是正常能力；这里 +20 用于后续组合加权。
            score += 20
            methods.append("sysctl:process_list_access")
            Logger.log("\(logPrefix)process_list_access (+20)")

            if infos.isEmpty && ExpectedBaseline.emptyProcessListIsSuspicious {
                score += 20
                methods.append("\(hookPrefix)empty_process_list_suspicious")
                Logger.log("\(logPrefix)empty_process_list_suspicious (+20)")
            }

            // 双路径结果不一致，提示 sysctl 返回值被篡改。
            if processList.tampered {
                score += 18
                methods.append("\(hookPrefix)sysctl_process_list_mismatch")
                Logger.log("\(logPrefix)process_list_mismatch (+18)")
            }

            // P_TRACED 类追踪特征，通常是 DBI/调试器。
            if processList.traced {
                score += 25
                methods.append("dbi_stalker_traced:process_list")
                Logger.log("\(logPrefix)dbi_stalker_traced process_list (+25)")
            }

            // 进程数量异常偏多可能意味着越狱守护进程/调试工具在运行。
            if infos.count > 400 {
                score += 10
                methods.append("sysctl:process_count:\(infos.count)")
                Logger.log("\(logPrefix)process_count=\(infos.count) (+10)")
            }

            let suspicious = suspiciousProcessesFound(infos: infos)
            if !suspicious.isEmpty {
                score += 22
                for name in suspicious.prefix(3) {
                    methods.append("proc:\(name)")
                }
                Logger.log("\(logPrefix)suspicious_processes=\(suspicious.joined(separator: ",")) (+22)")
            }
        } else if ExpectedBaseline.emptyProcessListIsSuspicious {
            // [4.4.7] 无法读取进程列表（nil）在低版本上视为被 Hook
            score += 20
            methods.append("\(hookPrefix)empty_process_list_suspicious")
            Logger.log("\(logPrefix)empty_process_list_suspicious (nil) (+20)")
        }

        let parentLookup = parentProcessName()
        // 父进程信息读取结果被篡改。
        if parentLookup.tampered {
            score += 12
            methods.append("\(hookPrefix)sysctl_parent_lookup_mismatch")
            Logger.log("\(logPrefix)parent_lookup_mismatch (+12)")
        }

        // 正常 App 的父进程通常是 launchd（或测试环境下的进程），异常父进程值得警惕。
        if let parent = parentLookup.name, isSuspiciousParent(parent) {
            score += 20
            methods.append("parent:\(parent)")
            Logger.log("\(logPrefix)parent_process=\(parent) (+20)")
        }

        let debugger = debuggerStatus()
        if debugger.tampered {
            score += 12
            methods.append("\(hookPrefix)sysctl_pid_flags_mismatch")
            Logger.log("\(logPrefix)pid_flags_mismatch (+12)")
        }

        // P_TRACED 置位说明当前进程正被调试器/追踪器附加。
        if debugger.attached {
            score += 10
            methods.append("sysctl:debugger_attached")
            Logger.log("\(logPrefix)debugger_attached (+10)")
        }

        // 对关键硬件/系统键做双路径校验：用于发现返回伪造值的 sysctl hook。
        let criticalSysctlKeys = ["hw.machine", "hw.model", "kern.osversion"]
        for key in criticalSysctlKeys {
            let (_, tampered, bypassed, traced, _) = DualPathValidator.validateSysctl(key: key)
            if tampered {
                score += 25
                methods.append("sysctl_dual_path_mismatch:\(key)")
                Logger.log("\(logPrefix)dual_path_mismatch key=\(key) (+25)")
            }
            if bypassed {
                score += 20
                methods.append("sysctl_short_circuit_\(ObfuscatedConstants.keywordHook):\(key)")
                Logger.log("\(logPrefix)short_circuit \(ObfuscatedConstants.keywordHook) key=\(key) (+20)")
            }
            if traced {
                score += 25
                methods.append("dbi_stalker_traced:\(key)")
                Logger.log("\(logPrefix)dbi_stalker_traced key=\(key) (+25)")
            }
        }

        return DetectorResult(score: min(score, 85), methods: methods)
#endif
    }

    /// sysctl 原始数据及其对抗性标志。
    private struct SysctlDataResult {
        /// 读取到的原始字节。
        var data: Data
        /// 双路径结果不一致（疑似篡改）。
        var tampered: Bool
        /// 处于 DBI/Stalker 追踪之下。
        var traced: Bool
    }

    /// 进程列表读取结果。
    private struct ProcessListResult {
        /// 解析后的进程信息。
        var infos: [kinfo_proc]
        /// 双路径结果不一致。
        var tampered: Bool
        /// 处于追踪之下。
        var traced: Bool
    }

    /// 单个进程信息读取结果。
    private struct ProcessInfoResult {
        /// 解析后的进程信息。
        var info: kinfo_proc
        /// 双路径结果不一致。
        var tampered: Bool
        /// 处于追踪之下。
        var traced: Bool
    }

    /// 读取全量进程列表。
    /// - Returns: 进程列表结果；读取失败或条目为空时返回 `nil`。
    private func readProcessList() -> ProcessListResult? {
        guard let result = readSysctlData(mib: [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]) else { return nil }

        let count = result.data.count / MemoryLayout<kinfo_proc>.stride
        guard count > 0 else { return nil }

        var out: [kinfo_proc] = []
        // 上限 512 个进程，限制内存占用与遍历成本。
        out.reserveCapacity(min(count, 512))
        result.data.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            let infos = baseAddress.bindMemory(to: kinfo_proc.self, capacity: count)
            for i in 0..<min(count, 512) {
                out.append(infos[i])
            }
        }
        return ProcessListResult(infos: out, tampered: result.tampered, traced: result.traced)
    }

    /// 在进程列表中查找可疑进程名。
    /// - Parameter infos: 进程信息数组。
    /// - Returns: 去重排序后的命中令牌，最多 3 个。
    private func suspiciousProcessesFound(infos: [kinfo_proc]) -> [String] {
        var found: [String] = []
        found.reserveCapacity(3)

        for info in infos {
            let n = processComm(info)
            if let hit = firstSuspiciousProcessToken(in: n) {
                found.append(hit)
                // 只需少量证据，避免把整个进程表写进上报。
                if found.count >= 3 { break }
            }
        }
        return Array(Set(found)).sorted()
    }

    /// 读取进程的 comm 名称。
    /// - Parameter info: 进程信息。
    /// - Returns: 以 NUL 结尾的 comm 字段解码结果。
    private func processComm(_ info: kinfo_proc) -> String {
        // kinfo_proc.kp_proc.p_comm 是定长 C 字符数组。
        let bytes = withUnsafeBytes(of: info.kp_proc.p_comm) { raw in
            Array(raw.prefix { $0 != 0 })
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// 读取父进程名称。
    /// - Returns: `(父进程名, 是否被篡改)`；父进程信息读取失败时名字为 `nil` 且标记篡改。
    private func parentProcessName() -> (name: String?, tampered: Bool) {
        // 通过 C 层直接取 ppid，绕开可能被 hook 的 getppid。
        let ppid = cprisk_getppid_direct()
        guard let result = readProcessInfo(pid: ppid) else { return (nil, true) }
        let name = processComm(result.info)
        return (name.isEmpty ? nil : name, result.tampered)
    }

    /// 判断父进程名是否命中可疑令牌。
    /// - Parameter name: 父进程名。
    /// - Returns: 命中返回 `true`。
    private func isSuspiciousParent(_ name: String) -> Bool {
        firstSuspiciousParentToken(in: name) != nil
    }

    /// 按 PID 读取单个进程信息。
    /// - Parameter pid: 目标进程 ID。
    /// - Returns: 进程信息；读取失败或数据长度不足时返回 `nil`。
    private func readProcessInfo(pid: Int32) -> ProcessInfoResult? {
        guard let result = readSysctlData(mib: [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]) else { return nil }
        guard result.data.count >= MemoryLayout<kinfo_proc>.size else { return nil }

        var info = kinfo_proc()
        withUnsafeMutableBytes(of: &info) { rawBuffer in
            rawBuffer.copyBytes(from: result.data.prefix(MemoryLayout<kinfo_proc>.size))
        }
        return ProcessInfoResult(info: info, tampered: result.tampered, traced: result.traced)
    }

    /// 查询当前进程是否被调试器附加。
    /// - Returns: `(P_TRACED 是否置位, 数据是否被篡改)`。
    private func debuggerStatus() -> (attached: Bool, tampered: Bool) {
        // 通过 C 层直接取 pid，绕开可能被 hook 的 getpid。
        guard let result = readProcessInfo(pid: cprisk_getpid_direct()) else { return (false, false) }
        let attached = (result.info.kp_proc.p_flag & P_TRACED) != 0
        return (attached, result.tampered)
    }

    /// 通过双路径校验读取 sysctl 数据。
    /// - Parameter mib: sysctl MIB 数组。
    /// - Returns: 数据结果；数据为空或校验未返回数据时返回 `nil`。
    private func readSysctlData(mib: [Int32]) -> SysctlDataResult? {
        let validation = DualPathValidator.validateSysctlData(mib: mib)
        guard let data = validation.data, !data.isEmpty else { return nil }
        return SysctlDataResult(data: data, tampered: validation.tampered, traced: validation.traced)
    }

    /// 在进程名中查找第一个命中的可疑令牌。
    /// - Parameter processName: 原始进程名。
    /// - Returns: 命中的令牌；未命中返回 `nil`。
    func firstSuspiciousProcessToken(in processName: String) -> String? {
        let normalized = normalizeProcessName(processName)
        return suspiciousProcessNeedles.first(where: { normalized.contains($0) })
    }

    /// 在父进程名中查找第一个命中的可疑令牌。
    /// - Parameter parentProcessName: 原始父进程名。
    /// - Returns: 命中的令牌；未命中返回 `nil`。
    func firstSuspiciousParentToken(in parentProcessName: String) -> String? {
        let normalized = normalizeProcessName(parentProcessName)
        return suspiciousParentNeedles.first(where: { normalized.contains($0) })
    }

    /// 归一化进程名，便于不区分大小写匹配。
    /// - Parameter name: 原始进程名。
    /// - Returns: 去除首尾空白并转小写后的名称。
    func normalizeProcessName(_ name: String) -> String {
        name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }
}
