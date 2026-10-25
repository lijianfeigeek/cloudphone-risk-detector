import CRiskCore
import Darwin
import Foundation

// MARK: - 直接系统调用交叉校验
//
// 本检测器做"结果一致性"验证，属于确定性检测，而非 KernelHookSideChannel /
// FridaSocketDetector 依赖 Stalker DBT 开销的时序概率检测：
// 经 libc 包装器调用 getpid/stat/access，同时经 CRiskCore 直接执行 SVC 调用同一系统调用，
// 比较两条路径的返回值；不一致即说明 libc 层存在活跃 hook 正在篡改结果。
// 覆盖 Substrate/Dobby/Ellekit/fishhook 及 Shadow、A-Bypass 等越狱隐藏工具。

/// 直接系统调用交叉校验检测器。
/// - 线程模型：无共享可变状态，可在任意线程调用。
/// - 安全不变量：模拟器或探针异常时降级为 0 分，不产生误杀。
struct DirectSyscallCrossValidator: Detector {

    // MARK: - 测试探针

    /// 任何原厂 iOS 设备都必须存在的路径；用于对比 libc 与直接 SVC 的探测结果。
    private static let probePaths: [String] = [
        "/usr/lib/dyld",
        "/bin/sh",
        "/usr/lib/system/libsystem_kernel.dylib",
        "/usr/lib/system/libsystem_pthread.dylib",
    ]

    /// 必然不存在的随机路径；用于验证两条路径对"文件不存在"给出同样结论，
    /// 防止 hook 伪造任意文件存在性而绕过检测。
    private static let nonExistentPath = "/var/tmp/cprisk_probe_nonexistent_\(arc4random())"

    // MARK: - 计分
    // 单次 getpid 不一致几乎没有自然成因，故权重最高；stat/access 次之。
    private static let scoreGetpidMismatch: Double   = 40  // 无 hook 时几乎不可能出现
    private static let scoreStatMismatch: Double     = 30  // 强指示
    private static let scoreAccessMismatch: Double   = 25
    private static let scoreMultiMismatch: Double    = 20  // ≥2 类不一致时的叠加奖励
    private static let maxScore: Double              = 80

    // MARK: - Detector 协议

    @inline(never)
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        // 模拟器的 libc 与 CRiskCore 行为不可比，直接降级，避免宿主环境误报。
        return DetectorResult(score: 0, methods: ["dscv:unavailable_simulator"])
#else
        return detectKernel()
#endif
    }

    @inline(never)
    private func detectKernel() -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []
        var mismatchCount = 0

        // --- 探针 1：getpid 一致性 ---
        // 同一进程内两条路径必须返回同一 PID，任何差异都只能来自 libc 拦截。
        let libcPid = getpid()
        let directPid = cprisk_getpid_direct()
        if libcPid != directPid {
            score += Self.scoreGetpidMismatch
            methods.append("dscv:getpid_mismatch:\(libcPid)_vs_\(directPid)")
            mismatchCount += 1
        }

        // --- 探针 2：stat() 一致性 ---
        let statMismatches = checkStatConsistency()
        if statMismatches > 0 {
            score += Self.scoreStatMismatch
            methods.append("dscv:stat_mismatch:\(statMismatches)")
            mismatchCount += 1
        }

        // --- 探针 3：access() 一致性 ---
        let accessMismatches = checkAccessConsistency()
        if accessMismatches > 0 {
            score += Self.scoreAccessMismatch
            methods.append("dscv:access_mismatch:\(accessMismatches)")
            mismatchCount += 1
        }

        // 多类系统调用同时不一致，说明存在活跃的插桩框架，追加组合分。
        if mismatchCount >= 2 {
            score += Self.scoreMultiMismatch
            methods.append("dscv:multi_mismatch:\(mismatchCount)")
        }

        if methods.isEmpty {
            methods.append("dscv:clean")
        }

        return DetectorResult(score: min(score, Self.maxScore), methods: methods)
    }

    // MARK: - stat() 交叉校验

    /// 统计 libc `stat` 与 CRiskCore `stat_direct` 结论不一致的探针路径数量。
    /// - 返回：不一致路径数（含随机不存在路径），0 表示一致。
    private func checkStatConsistency() -> Int {
        var mismatches = 0

        for path in Self.probePaths {
            let (libcExists, directExists) = statBothPaths(path)
            if libcExists != directExists {
                mismatches += 1
            }
        }

        // 再探测随机不存在路径：hook 可能为了隐藏文件而伪造"存在"。
        let (libcNonExist, directNonExist) = statBothPaths(Self.nonExistentPath)
        if libcNonExist != directNonExist {
            mismatches += 1
        }

        return mismatches
    }

    /// 返回指定路径经 libc 与直接系统调用执行 stat 的成功标志 `(libcSuccess, directSuccess)`。
    private func statBothPaths(_ path: String) -> (Bool, Bool) {
        var libcSb = stat()
        let libcRc = path.withCString { cPath in
            Darwin.lstat(cPath, &libcSb)
        }

        var directSb = stat()
        let directRc = path.withCString { cPath in
            cprisk_stat_direct(cPath, &directSb, nil)
        }

        return (libcRc == 0, directRc == 0)
    }

    // MARK: - access() 交叉校验

    /// 统计 libc `access` 与 CRiskCore `access_direct` 结论不一致的探针路径数量。
    private func checkAccessConsistency() -> Int {
        var mismatches = 0

        for path in Self.probePaths {
            let (libcOK, directOK) = accessBothPaths(path, mode: F_OK)
            if libcOK != directOK {
                mismatches += 1
            }
        }

        // 不存在路径：两条路径都应返回错误（-1），不一致说明返回值被篡改。
        let (libcNonExist, directNonExist) = accessBothPaths(Self.nonExistentPath, mode: F_OK)
        if libcNonExist != directNonExist {
            mismatches += 1
        }

        return mismatches
    }

    /// 返回指定路径经 libc 与直接系统调用执行 access 的成功标志 `(libcSuccess, directSuccess)`。
    private func accessBothPaths(_ path: String, mode: Int32) -> (Bool, Bool) {
        let libcRc = path.withCString { cPath in
            Darwin.access(cPath, mode)
        }

        let directRc = path.withCString { cPath in
            cprisk_access_direct(cPath, mode, nil)
        }

        return (libcRc == 0, directRc == 0)
    }
}

// MARK: - 信号桥接

extension DirectSyscallCrossValidator {
    /// 将检测结果转换为 `syscall_result_mismatch` 信号。
    /// - getpid 不一致视为硬命中（真实设备不可能出现），其余情形给 0.85 软置信；
    /// - layer 2、weightHint 85：属于反篡改强证据，但仍是多信号中的一环。
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        let hasGetpidMismatch = result.methods.contains(where: { $0.hasPrefix("dscv:getpid_mismatch") })
        let hasStatMismatch = result.methods.contains(where: { $0.hasPrefix("dscv:stat_mismatch") })

        return [RiskSignal(
            id: "syscall_result_mismatch",
            category: ObfuscatedConstants.categoryAntiTamper,
            score: result.score,
            evidence: [
                "getpid_mismatch": hasGetpidMismatch ? "1" : "0",
                "stat_mismatch": hasStatMismatch ? "1" : "0",
                "channels": "\(result.methods.filter { !$0.hasSuffix(":clean") }.count)",
            ],
            state: hasGetpidMismatch ? .hard(detected: true) : .soft(confidence: 0.85),
            layer: 2,
            weightHint: 85
        )]
    }
}
