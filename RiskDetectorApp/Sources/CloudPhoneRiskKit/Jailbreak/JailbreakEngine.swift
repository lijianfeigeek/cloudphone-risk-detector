// 越狱检测引擎：按配置串行调度各检测器，聚合分数并产出最终判决。
// 位于越狱检测管道的中枢位置：向上接收 JailbreakConfig，向下依次调用 File/Dyld/Env/Sysctl/Scheme/Hook。
// 关键安全不变量：检测器故障（抛错/负分）绝不直接等同于“检测到越狱”，只有连续故障才按可疑升级计分。
import Foundation

// MARK: - Jailbreak 检测引擎
//
// 运行一条可配置的检测器链，每个检测器返回 DetectorResult（分数 + 命中方法）。
// 引擎累加分数并应用置信度阈值，产出最终 DetectionResult。
//
// 检测器链（每一项都可通过 JailbreakConfig 独立开关）：
//   FileDetector              → 对已知越狱路径执行 stat/access
//   DyldDetector              → _dyld_image_count / 镜像名扫描
//   EnvDetector               → DYLD_INSERT_LIBRARIES 等环境变量
//   SysctlDetector            → kern.proc 的 P_TRACED 标志、进程列表
//   SchemeDetector            → 用 canOpenURL 探测 Cydia/Sileo/Filza scheme（仅 UIKit）
//   HookDetector              → 复合检测：ObjC 类 + 符号镜像 + 各子检测器
//     （enableHookDetect 为真时调用；子检测器在 HookDetector.detect() 内部执行）：
//     PointerValidationDetector      → 指针认证检查
//     HookFrameworkSymbolDetector   → dlsym 探测 Substrate/fishhook/Frida 符号
//     PrologueBranchDetector        → ARM64 函数入口分支指令
//     IndirectSymbolPointerDetector → 间接符号表完整性
//     ObjCIMPDetector               → method_getImplementation + dladdr 校验
//     ObjCMetadataDetector          → objc_copyClassList / 协议 / NSObject 扩展扫描
//
// 模拟器：默认返回 unavailable（设置 CPRISK_SIMULATE_JAILBREAK=1
// 可开启模拟越狱以便测试）

/// 越狱检测引擎。
/// 线程模型：无状态检测器链可并发调用；`consecutiveFaults` 由 `UnfairLock` 保护。
/// 安全不变量：`confidence` 被裁剪到 `confidenceCap`，且故障标记不会伪装成越狱证据。
final class JailbreakEngine {
    /// 置信度上限
    private static let confidenceCap: Double = 100
    /// 单个检测器连续异常（抛异常/负分）达到该次数时才升级计分。
    /// 故障（检测器本身出错）与“检测到越狱”是两回事：单次故障只标记、
    /// 不直接加高分，避免故障设备被误判高危；连续故障才视为可疑并升级。
    private static let consecutiveFaultEscalationThreshold = 2
    /// 连续故障升级时计入的分值（远低于旧的单次故障 +80）。
    private static let consecutiveFaultEscalationScore: Double = 40
    /// 各检测器连续故障计数（跨次评估累计，成功一次即清零）。
    private var consecutiveFaults: [String: Int] = [:]
    /// 保护 `consecutiveFaults` 的互斥锁，保证并发评估下计数一致性。
    private let faultLock = UnfairLock()

    /// 执行一次完整的越狱评估。
    /// - Parameter config: 控制启用哪些检测器以及判定阈值。
    /// - Returns: 聚合后的判决；模拟器上默认返回 `unavailable == true`。
    /// - Note: 单个检测器抛错不会中止整条链路，错误会转为故障标记继续评估。
    func detect(config: JailbreakConfig) -> DetectionResult {
#if targetEnvironment(simulator)
    #if DEBUG
        // 仅 DEBUG 下允许显式开启模拟越狱，避免测试开关泄漏到线上构建。
        let simulate = ProcessInfo.processInfo.environment["CPRISK_SIMULATE_JAILBREAK"] == "1"
            || UserDefaults.standard.bool(forKey: "cloudphone_risk_debug_simulate_jailbreak")
        if simulate {
            Logger.log("jailbreak: simulator -> simulated_jailbreak (DEBUG only)")
            return DetectionResult(
                isJailbroken: true,
                confidence: Self.confidenceCap,
                detectedMethods: ["simulated:targetEnvironment(simulator)"],
                details: "simulated_jailbreak_simulator"
            )
        }
    #endif
        // 模拟器不具备真实越狱语义，必须标记为不可用而非“干净设备”。
        Logger.log("jailbreak: simulator -> unavailable")
        return DetectionResult(
            isJailbroken: false,
            confidence: 0,
            detectedMethods: [],
            details: "unavailable_simulator",
            unavailable: true
        )
#endif

        var score: Double = 0
        var methods: [String] = []
        var faultLabels: [String] = []

        #if DEBUG
        Logger.log("jailbreak: start(threshold=\(config.threshold))")
        #endif

        if config.enableFileDetect {
            accumulateDetector("file", &score, &methods, &faultLabels) { try FileDetector().detect() }
        }

        if config.enableDyldDetect {
            accumulateDetector("dyld", &score, &methods, &faultLabels) { try DyldDetector().detect() }
        }

        if config.enableEnvDetect {
            accumulateDetector("env", &score, &methods, &faultLabels) { try EnvDetector().detect() }
        }

        if config.enableSysctlDetect {
            accumulateDetector("sysctl", &score, &methods, &faultLabels) { try SysctlDetector().detect() }
        }

        #if canImport(UIKit)
        // Scheme 探测依赖 UIApplication，仅在 UIKit 平台可用。
        if config.enableSchemeDetect {
            accumulateDetector("scheme", &score, &methods, &faultLabels) { try SchemeDetector().detect() }
        }
        #endif

        if config.enableHookDetect {
            // Hook 检测器内部还会串联多个子检测器，因此其标签使用混淆常量。
            accumulateDetector(ObfuscatedConstants.keywordHook, &score, &methods, &faultLabels) { try HookDetector().detect() }
        }

        // 去重并排序，保证同一设备多次评估得到稳定的 methods 集合。
        methods = Array(Set(methods)).sorted()
        let isJailbroken = score >= config.threshold
        #if DEBUG
        Logger.log("jailbreak: done(score=\(min(score, Self.confidenceCap)) isJailbroken=\(isJailbroken) methods=\(methods.joined(separator: ",")))")
        #endif
        return DetectionResult(
            isJailbroken: isJailbroken,
            confidence: min(score, Self.confidenceCap),
            detectedMethods: methods,
            details: details(methods: methods, score: score, faults: faultLabels)
        )
    }

    /// 执行单个检测器并把结果并入累计状态。
    /// - Parameters:
    ///   - label: 检测器名称，用于故障计数与日志归因。
    ///   - score: 累计分数（inout）。
    ///   - methods: 累计命中方法（inout）。
    ///   - faults: 累计故障明细（inout）。
    ///   - block: 真正的检测闭包。
    /// - Note: 抛错与负分都视为检测器故障，只记录标记，不立即加高分。
    private func accumulateDetector(
        _ label: String,
        _ score: inout Double,
        _ methods: inout [String],
        _ faults: inout [String],
        _ block: () throws -> DetectorResult
    ) {
        do {
            let result = try block()
            if result.score < 0 {
                // 检测器故障（负分），不是“检测到越狱”：只标记，不加高分。
                recordDetectorFault(label: label, reason: "negative_score", score: &score, methods: &methods, faults: &faults)
            } else {
                // 成功执行一次即清零该检测器的连续故障计数。
                faultLock.withLock { consecutiveFaults[label] = 0 }
                #if DEBUG
                Logger.log("jailbreak.\(label): score=\(result.score) hits=\(result.methods.count)")
                #endif
                score += result.score
                methods.append(contentsOf: result.methods)
            }
        } catch {
            // 检测器故障（抛异常），不是“检测到越狱”：只标记，不加高分。
            recordDetectorFault(label: label, reason: "threw", score: &score, methods: &methods, faults: &faults)
        }
    }

    /// 记录一次检测器故障：标记 `jailbreak_fault:<label>:<reason>`，并在该检测器
    /// 连续故障达到阈值时才升级计分（熔断/去重），同时记录日志。
    /// - Parameters:
    ///   - label: 故障检测器名称。
    ///   - reason: 故障原因（`threw` / `negative_score`）。
    ///   - score: 累计分数（inout），仅在连续故障达标时增加。
    ///   - methods: 累计命中方法（inout）。
    ///   - faults: 累计故障明细（inout）。
    private func recordDetectorFault(
        label: String,
        reason: String,
        score: inout Double,
        methods: inout [String],
        faults: inout [String]
    ) {
        let streak = faultLock.withLock { () -> Int in
            // 上限保护，避免极端情况下整数溢出。
            let next = min(consecutiveFaults[label] ?? 0, Int.max - 1) + 1
            consecutiveFaults[label] = next
            return next
        }
        faults.append("\(label):\(reason):streak=\(streak)")
        methods.append("jailbreak_fault:\(label):\(reason)")
        Logger.log("jailbreak.\(label): detector fault (\(reason)), consecutive streak=\(streak) — marked, not scored as jailbreak")
        // 连续故障说明该检测器可能被针对性破坏，才把故障升级为可疑证据。
        if streak >= Self.consecutiveFaultEscalationThreshold {
            score += Self.consecutiveFaultEscalationScore
            methods.append("jailbreak_fault_escalated:\(label)")
            Logger.log("jailbreak.\(label): consecutive faults escalated (streak=\(streak), +\(Self.consecutiveFaultEscalationScore))")
        }
    }

    /// 生成便于日志排查的明细文本（多行 `key=value`）。
    /// - Parameters:
    ///   - methods: 命中的方法列表。
    ///   - score: 原始累计分数（输出时会裁剪到置信度上限）。
    ///   - faults: 检测器故障明细。
    /// - Returns: 供 `DetectionResult.details` 使用的文本。
    private func details(methods: [String], score: Double, faults: [String] = []) -> String {
        """
        jailbreak_score=\(min(score, Self.confidenceCap))
        hits=\(methods.count)
        methods=\(methods.joined(separator: ","))
        detector_faults=\(faults.isEmpty ? "none" : faults.joined(separator: ","))
        """
    }
}
