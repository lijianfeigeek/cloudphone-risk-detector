// 反篡改核心检测器（CFF 控制流展平）：用编码状态机串起 P_TRACED、可疑父进程、
// 调试环境变量、syscall 时序比值、主动拒绝调试附加五类检查，使静态反编译难以还原
// 检查顺序与分支走向。分值封顶 90；模拟器与 DEBUG 构建跳过主动拒绝附加，避免影响开发。
// 时序检查采用“getpid 基线 / 文件探针”的比值而非绝对毫秒，降低低端机、冷启动与后台复起的误报。
// 所有检查失败都按未命中处理，任何一个探针异常都不会中断状态机。

import Darwin
import CRiskCore
import Foundation

/// CFF 相关常量与运行期盐值：函数种子/保护档位固定，盐值混入运行时时间与输入长度，
/// 使每次执行的编码状态不同，增加静态匹配状态值的难度。
private enum AntiTamperingDetectorCFF {
    static let detectConfig = CFFConfig.adaptive(
        functionSeed: 0x7EA1_42D0_9B53_6C2F,
        protectionTier: .light,
        dispatcherStyle: .functionPointerTable,
        codecStyle: .feistelSpn
    )

    /// 派生本次执行的状态编码盐：输入数量、时间戳与字符串内容共同参与，避免固定盐被硬编码还原。
    static func salt(
        suspiciousNeedles: [String],
        debugEnvironmentKeys: [String]
    ) -> UInt32 {
        CFFRuntimeSalt.derive(
            functionSeed: detectConfig.functionSeed,
            inputs: CFFRuntimeSaltInputs(
                extraWords: [
                    UInt64(suspiciousNeedles.count),
                    UInt64(debugEnvironmentKeys.count),
                    Date().timeIntervalSince1970.bitPattern,
                ],
                strings: [
                    "atd_core_v1",
                    suspiciousNeedles.prefix(3).joined(separator: "|"),
                    debugEnvironmentKeys.prefix(3).joined(separator: "|"),
                ],
                flags: [suspiciousNeedles.isEmpty, debugEnvironmentKeys.isEmpty]
            )
        )
    }
}

/// 反篡改核心检测器。
///
/// 状态机按 entry → traced → parent → env → timing → ptrace → connector → settle → finish
/// 单向推进；每个状态对应一项检查，命中后累加分数并记录 `methods`。
struct AntiTamperingDetector: Detector {

    /// 父进程路径中的可疑关键字（调试器、注入框架等，具体列表在混淆常量中）。
    let suspiciousParentNeedles: [String] = ObfuscatedConstants.antiTamperSuspiciousParentNeedles

    /// 调试环境变量键；存在即视为可疑，不比较取值。
    let debugEnvironmentKeys: [String] = ObfuscatedConstants.antiTamperingDebugEnvironmentKeys

    /// 执行 CFF 状态机并返回汇总结果。
    ///
    /// - 状态值在每次迁移前都会重新编码，比较时先解码，静态上不出现连续可读的控制流。
    /// - `loopBudget` 是防御性上限：状态被外部篡改为非法值时也能收敛退出。
    /// - 返回值分值封顶 90，保留其它检测器的加权空间。
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []
        let antiTamperingPrefix = ObfuscatedConstants.detectorIDAntiTampering
        let cffConfig = AntiTamperingDetectorCFF.detectConfig
        let salt = AntiTamperingDetectorCFF.salt(
            suspiciousNeedles: suspiciousParentNeedles,
            debugEnvironmentKeys: debugEnvironmentKeys
        )

        // 状态编号本身无业务含义，仅作为状态机节点标识。
        let entryState: UInt32 = 0x21
        let tracedState: UInt32 = 0x22
        let parentState: UInt32 = 0x23
        let envState: UInt32 = 0x24
        let timingState: UInt32 = 0x25
        let ptraceState: UInt32 = 0x26
        let connectorState: UInt32 = 0x27
        let settleState: UInt32 = 0x28
        let finishState: UInt32 = 0x29

        // 编码密钥由函数名与配置派生；关闭运行时盐时异或一个固定常量，保持可测试性。
        let cffKey = CFFStateCodec.deriveSeed(function: "atd_core_v1", config: cffConfig)
        let effectiveSalt = cffConfig.enableRuntimeSalt ? salt : salt ^ 0x13579BDF

        func encodeState(_ rawState: UInt32) -> UInt32 {
            CFFStateCodec.encode(state: rawState, key: cffKey, salt: effectiveSalt, style: cffConfig.codecStyle)
        }

        func decodeState(_ encoded: UInt32) -> UInt32 {
            CFFStateCodec.decode(state: encoded, key: cffKey, salt: effectiveSalt, style: cffConfig.codecStyle)
        }

        var sink = CFFReturnSink<DetectorResult>()
        var encodedState = encodeState(entryState)
        // 正常路径只需 9 次迁移；64 的预算足以覆盖分支绕行，同时防御状态污染导致的死循环。
        var loopBudget = 64

        func finalizeResult() -> DetectorResult {
            DetectorResult(score: min(score, 90), methods: methods)
        }

        while !sink.isResolved {
            guard loopBudget > 0 else {
                // 预算耗尽说明状态机被干扰，直接返回已收集的结果，避免无限循环。
                sink.store(finalizeResult())
                break
            }
            loopBudget -= 1

            let decodedState = decodeState(encodedState)
            let dispatchPlan = CFFDispatcher.plan(encodedState: encodedState, salt: salt, config: cffConfig)
            // 调度器随机选择 if-else 链或 switch 两条等价轨道，增加二进制层面的形态差异。
            let useIfElseRail = dispatchPlan.style == .ifElseChain || (dispatchPlan.branchSelector & 1) == 1

            if useIfElseRail {
                if decodedState == entryState {
                    encodedState = encodeState(tracedState)
                } else if decodedState == tracedState {
                    if isTraced() {
                        // P_TRACED 是最可信的附加证据，给最高单项分。
                        score += 30
                        methods.append("\(antiTamperingPrefix):p_traced")
                    }
                    encodedState = encodeState(parentState)
                } else if decodedState == parentState {
                    if hasSuspiciousParent() {
                        // 父进程可疑可能只是调试器启动，权重低于 P_TRACED。
                        score += 20
                        methods.append("\(antiTamperingPrefix):suspicious_parent")
                    }
                    encodedState = encodeState(envState)
                } else if decodedState == envState {
                    if hasDebugEnvironment() {
                        // 环境变量易被开发工具设置，权重进一步降低。
                        score += 15
                        methods.append("\(antiTamperingPrefix):debug_env")
                    }
                    encodedState = encodeState(timingState)
                } else if decodedState == timingState {
                    if hasTimingAnomaly() {
                        // 时序异常只作辅助证据，避免 CPU 抖动把正常设备推向高风险。
                        score += 12
                        methods.append("\(antiTamperingPrefix):timing")
                    }
                    encodedState = encodeState(ptraceState)
                } else if decodedState == ptraceState {
                    let ptraceResult = denyDebuggerAttach()
                    score += ptraceResult.score
                    methods.append(contentsOf: ptraceResult.methods)
                    encodedState = encodeState(connectorState)
                } else if decodedState == connectorState {
                    // 连接器节点由不透明谓词决定走向，两个后继最终都汇合到 finish。
                    let nextState = CFFOpaquePredicates.connectorGate(encodedState: encodedState, salt: salt) ? finishState : settleState
                    encodedState = encodeState(nextState)
                } else if decodedState == settleState {
                    encodedState = encodeState(finishState)
                } else if decodedState == finishState {
                    sink.store(finalizeResult())
                } else {
                    // 非法状态：按已收集结果收敛，防止被构造的状态值带偏。
                    sink.store(finalizeResult())
                }
            } else {
                switch decodedState {
                case entryState:
                    encodedState = encodeState(tracedState)
                case tracedState:
                    if isTraced() {
                        score += 30
                        methods.append("\(antiTamperingPrefix):p_traced")
                    }
                    encodedState = encodeState(parentState)
                case parentState:
                    if hasSuspiciousParent() {
                        score += 20
                        methods.append("\(antiTamperingPrefix):suspicious_parent")
                    }
                    encodedState = encodeState(envState)
                case envState:
                    if hasDebugEnvironment() {
                        score += 15
                        methods.append("\(antiTamperingPrefix):debug_env")
                    }
                    encodedState = encodeState(timingState)
                case timingState:
                    if hasTimingAnomaly() {
                        score += 12
                        methods.append("\(antiTamperingPrefix):timing")
                    }
                    encodedState = encodeState(ptraceState)
                case ptraceState:
                    let ptraceResult = denyDebuggerAttach()
                    score += ptraceResult.score
                    methods.append(contentsOf: ptraceResult.methods)
                    encodedState = encodeState(connectorState)
                case connectorState:
                    // 与 if-else 轨道等价的另一种不透明谓词写法。
                    let nextState = CFFDispatcher.branchKey(encodedState, salt: salt) & 1 == 0 ? finishState : settleState
                    encodedState = encodeState(nextState)
                case settleState:
                    encodedState = encodeState(finishState)
                case finishState:
                    sink.store(finalizeResult())
                default:
                    sink.store(finalizeResult())
                }
            }
        }

        return sink.resolve(or: finalizeResult())
#endif
    }

    /// 通过 `sysctl(KERN_PROC_PID)` 检查 P_TRACED 位；读取失败按未命中处理。
    private func isTraced() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, cprisk_getpid_direct()]
        var size = MemoryLayout<kinfo_proc>.size
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0 else { return false }
        return (info.kp_proc.p_flag & tracedFlag) != 0
    }

    /// 读取父进程路径并匹配可疑关键字；ppid <= 1 视为 launchd/内核，直接排除。
    private func hasSuspiciousParent() -> Bool {
        let ppid = cprisk_getppid_direct()
        guard ppid > 1 else { return false }
        guard let parentPath = processPath(for: ppid) else { return false }
        return firstSuspiciousParentToken(in: parentPath) != nil
    }

    /// 检查任一调试环境变量是否存在。
    private func hasDebugEnvironment() -> Bool {
        debugEnvironmentKeys.contains { getenv($0) != nil }
    }

    /// 主动请求内核拒绝调试器附加。
    ///
    /// - 模拟器与 DEBUG 构建直接跳过：这两个环境本就需要调试，拒绝附加会破坏开发流程。
    /// - `ENOTSUP`/`EPERM` 通常意味着调用时进程已被跟踪（拒绝附加已失效），因此给高分。
    /// - 其它 errno 说明底层调用被拦截或参数异常，仅给低分提示。
    private func denyDebuggerAttach() -> (score: Double, methods: [String]) {
        #if targetEnvironment(simulator) || DEBUG
        return (0, [])
        #else
        var rawErrno: CInt = 0
        let result = cprisk_deny_attach_status(&rawErrno)
        if result != 0 {
            if rawErrno == ENOTSUP || rawErrno == EPERM {
                    return (25, ["dbg_attach:already_attached"])
            }
                return (5, ["dbg_attach:direct_syscall_errno:\(rawErrno)"])
        }
        return (0, [])
        #endif
    }

    /// 对外暴露的比值判定入口，便于测试注入自定义样本与阈值。
    func isTimingRatioAnomalous(
        getpidSamples: [UInt64],
        statSamples: [UInt64],
        ratioThreshold: Double = TimingRatioBaseline.defaultRatioThreshold
    ) -> Bool {
        TimingRatioBaseline.isAnomalous(
            getpidSamples: getpidSamples,
            statSamples: statSamples,
            ratioThreshold: ratioThreshold
        )
    }

    /// 动态基线比值检测：先对 getpid 采样建立基准，再用「文件探针耗时/getpid_median」比值判断。
    /// 避免 50ms 绝对值在低端机/冷启动/后台复起时误报，与 KernelHookSideChannel 对齐。
    private func hasTimingAnomaly() -> Bool {
        let iterations = TimingRatioBaseline.defaultSampleCount
        var getpidSamples: [UInt64] = []
        getpidSamples.reserveCapacity(iterations)
        for _ in 0..<iterations {
            let start = DispatchTime.now().uptimeNanoseconds
            _ = cprisk_getpid_direct()
            let end = DispatchTime.now().uptimeNanoseconds
            getpidSamples.append(end - start)
        }

        var statSamples: [UInt64] = []
        statSamples.reserveCapacity(iterations)
        for _ in 0..<iterations {
            let start = DispatchTime.now().uptimeNanoseconds
            // 用 dyld 路径做 access 探针：命中页缓存后仍会走 syscall，适合度量 Hook 引入的额外开销。
            _ = SVCDirectCall.secureAccess("/usr/lib/dyld")
            let end = DispatchTime.now().uptimeNanoseconds
            statSamples.append(end - start)
        }

        return isTimingRatioAnomalous(getpidSamples: getpidSamples, statSamples: statSamples)
    }

    /// 在父进程路径中查找首个可疑关键字（大小写不敏感）。
    func firstSuspiciousParentToken(in parentProcessPath: String) -> String? {
        let normalized = parentProcessPath.lowercased()
        return suspiciousParentNeedles.first(where: { normalized.contains($0) })
    }
}

#if os(iOS) || os(tvOS) || os(watchOS)
// 各平台 P_TRACED 位定义一致；保留条件编译是为了将来按平台调整时不影响其它系统。
private let tracedFlag: Int32 = 0x00000800
#else
private let tracedFlag: Int32 = 0x00000800
#endif
