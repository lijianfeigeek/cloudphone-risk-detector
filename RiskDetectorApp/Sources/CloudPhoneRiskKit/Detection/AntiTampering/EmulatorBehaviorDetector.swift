import Darwin
import Foundation

// MARK: - 模拟器进程行为探测
//
// 面向 unidbg / Unicorn 等 Linux 宿主上的 ARM64 模拟环境：真实 iOS App 不会出现的
// 进程上下文特征（JVM 进程名、环境变量、kern.ostype、线程数与 CPU 时钟）在此类环境暴露。
// 各分项累加后封顶 40 分，作为 EmulatorLayoutDetector 的补充因子，不单独定性。

/// 模拟器进程行为检测器。
/// - 线程模型：纯同步只读探测，运行于评估线程。
/// - 误报边界：真机极少出现 JVM 变量或非 Darwin 内核；低线程数在极简后台进程中可能误报，
///   因此单项权重有限且总分封顶。
struct EmulatorBehaviorDetector: Detector {

    // MARK: - 分项分值

    private enum Score {
        // 进程名命中 JVM/unidbg/qemu/unicorn 关键字，单项最强。
        static let suspiciousProcessName: Double  = 12
        static let threadCountAnomaly: Double     = 8
        // JVM 环境变量只在宿主 JVM 进程中存在，权重较高。
        static let jvmEnvVarPresent: Double       = 14
        static let kernelOSTypeAnomaly: Double    = 8
        static let cpuTimeStalled: Double         = 6
        // 封顶 40：避免单一行为维度独自把整体风险推到高位。
        static let max: Double                    = 40
    }

    // MARK: - Detector 协议

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        // 模拟器本身即预期环境，返回 0 分避免开发/CI 噪声。
        return DetectorResult(score: 0, methods: ["emulator_behavior:unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []

        // ── 1. 进程名 ──────────────────────────────────────────────────────
        if checkProcessName() {
            score += Score.suspiciousProcessName
            methods.append("emulator_behavior:suspicious_process_name")
        } else {
            methods.append("emulator_behavior:process_name_ok")
        }

        // ── 2. 线程数 ──────────────────────────────────────────────────────
        let threadCount = countActiveThreads()
        // 真实 App 通常有主线程、GCD、网络等至少 4 条线程；模拟宿主可能只有 1–3 条。
        if threadCount > 0 && threadCount < 4 {
            score += Score.threadCountAnomaly
            methods.append("emulator_behavior:low_thread_count(\(threadCount))")
        } else {
            methods.append("emulator_behavior:thread_count_ok(\(threadCount))")
        }

        // ── 3. JVM 指示环境变量 ────────────────────────────────────────────
        if jvmEnvVarsPresent() {
            score += Score.jvmEnvVarPresent
            methods.append("emulator_behavior:jvm_env_var_found")
        } else {
            methods.append("emulator_behavior:env_clean")
        }

        // ── 4. 内核 ostype（sysctl）────────────────────────────────────────
        if !kernelOSTypeIsDarwin() {
            score += Score.kernelOSTypeAnomaly
            methods.append("emulator_behavior:ostype_anomaly")
        } else {
            methods.append("emulator_behavior:ostype_ok")
        }

        // ── 5. CLOCK_PROCESS_CPUTIME_ID 推进 ───────────────────────────────
        if cpuClockAppearsStalled() {
            score += Score.cpuTimeStalled
            methods.append("emulator_behavior:cpu_clock_stalled")
        } else {
            methods.append("emulator_behavior:cpu_clock_ok")
        }

        return DetectorResult(score: min(score, Score.max), methods: methods)
#endif
    }

    // MARK: - 私有探针

    // 所有特征串均以 XOR 混淆存储，防止攻击者直接扫描字符串定位检测逻辑。
    // 注意：数组中的字节值是混淆后的密文，不是可直接阅读的明文。

    /// 判断进程名是否像 JVM 启动器或 unidbg stub；空进程名也视为异常。
    private func checkProcessName() -> Bool {
        // 线索串 XOR 0x55：
        //   "java"    → [0x3F, 0x34, 0x23, 0x34]
        //   "unidbg"  → [0x20, 0x3B, 0x3C, 0x31, 0x37, 0x32]
        //   "qemu"    → [0x24, 0x30, 0x38, 0x20]
        //   "unicorn" → [0x20, 0x3B, 0x3C, 0x36, 0x3A, 0x27, 0x3B]
        let sentinels: [[UInt8]] = [
            [0x3F, 0x34, 0x23, 0x34],
            [0x20, 0x3B, 0x3C, 0x31, 0x37, 0x32],
            [0x24, 0x30, 0x38, 0x20],
            [0x20, 0x3B, 0x3C, 0x36, 0x3A, 0x27, 0x3B],
        ]

        let processName = ProcessInfo.processInfo.processName.lowercased()
        guard !processName.isEmpty else { return true }

        for sentinel in sentinels {
            let decoded = String(sentinel.map { Character(UnicodeScalar($0 ^ 0x55)) })
            if processName.contains(decoded) { return true }
        }

        // 可疑：进程名含路径分隔符，unidbg 可能直接透传完整可执行文件路径。
        if processName.contains("/") { return true }

        return false
    }

    /// 返回当前 task 的活跃 Mach 线程数；查询失败返回 0，调用方据此跳过该项判定。
    private func countActiveThreads() -> Int {
        var threadList: thread_act_array_t?
        var threadCount: mach_msg_type_number_t = 0
        guard task_threads(mach_task_self_, &threadList, &threadCount) == KERN_SUCCESS,
              let list = threadList else { return 0 }
        let count = Int(threadCount)
        for i in 0..<count { mach_port_deallocate(mach_task_self_, list[i]) }
        vm_deallocate(mach_task_self_,
                      vm_address_t(UInt(bitPattern: list)),
                      vm_size_t(count) * vm_size_t(MemoryLayout<thread_t>.stride))
        return count
    }

    /// 判断是否存在任一 JVM 指示环境变量。
    ///
    /// 变量名以 0x1F 做 XOR 混淆：
    ///   "JAVA_HOME"       → [0x55, 0x5E, 0x49, 0x5E, 0x40, 0x57, 0x50, 0x52, 0x5A]
    ///   "CLASSPATH"       → [0x5C, 0x53, 0x5E, 0x4C, 0x4C, 0x4F, 0x5E, 0x4B, 0x57]
    ///   "JVM_ARGS"        → [0x55, 0x49, 0x52, 0x40, 0x5E, 0x4D, 0x58, 0x4C]
    ///   "LD_LIBRARY_PATH" → [0x53, 0x5B, 0x40, 0x53, 0x56, 0x5D, 0x4D, 0x5E,
    ///                        0x4D, 0x46, 0x40, 0x4F, 0x5E, 0x4B, 0x57]
    private func jvmEnvVarsPresent() -> Bool {
        let candidates: [[UInt8]] = [
            [0x55, 0x5E, 0x49, 0x5E, 0x40, 0x57, 0x50, 0x52, 0x5A],
            [0x5C, 0x53, 0x5E, 0x4C, 0x4C, 0x4F, 0x5E, 0x4B, 0x57],
            [0x55, 0x49, 0x52, 0x40, 0x5E, 0x4D, 0x58, 0x4C],
            [0x53, 0x5B, 0x40, 0x53, 0x56, 0x5D, 0x4D, 0x5E,
             0x4D, 0x46, 0x40, 0x4F, 0x5E, 0x4B, 0x57],
        ]
        let env = ProcessInfo.processInfo.environment
        for candidate in candidates {
            let name = String(candidate.map { Character(UnicodeScalar($0 ^ 0x1F)) })
            if env[name] != nil { return true }
        }
        return false
    }

    /// 判断 `kern.ostype` 是否返回 "Darwin"。
    ///
    /// "kern.ostype" XOR 0x04 → [0x6F, 0x61, 0x76, 0x6A, 0x2A, 0x6B, 0x77, 0x70, 0x7D, 0x74, 0x61]
    /// "Darwin"      XOR 0x04 → [0x40, 0x65, 0x76, 0x73, 0x6D, 0x6A]
    private func kernelOSTypeIsDarwin() -> Bool {
        let nameEncoded: [UInt8] = [0x6F, 0x61, 0x76, 0x6A, 0x2A, 0x6B, 0x77, 0x70, 0x7D, 0x74, 0x61]
        let sysctlName = String(nameEncoded.map { Character(UnicodeScalar($0 ^ 0x04)) })

        var buf = [CChar](repeating: 0, count: 64)
        var size = buf.count
        guard sysctlbyname(sysctlName, &buf, &size, nil, 0) == 0 else {
            // 查询 kern.ostype 失败本身就属异常，按非 Darwin 处理（失败即视为可疑）。
            return false
        }

        let result = String(cString: buf)
        let expectedEncoded: [UInt8] = [0x40, 0x65, 0x76, 0x73, 0x6D, 0x6A]
        let expected = String(expectedEncoded.map { Character(UnicodeScalar($0 ^ 0x04)) })
        return result == expected
    }

    /// 判断 `CLOCK_PROCESS_CPUTIME_ID` 是否停滞——unidbg 的时间桩可能返回常量。
    /// - 返回：推进量 ≤ 0 时为 true；时钟读取失败时返回 false（不误判）。
    private func cpuClockAppearsStalled() -> Bool {
        var t1 = timespec(), t2 = timespec()
        guard clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t1) == 0 else { return false }
        // 消耗足够 CPU 周期，真实进程时间时钟必然推进；8192 次乘法足以越过计时粒度。
        var dummy: UInt64 = 0xDEAD_BEEF_1234_5678
        for _ in 0..<8192 {
            dummy = dummy &* 6364136223846793005 &+ 1442695040888963407
        }
        // volatile 风格读取，防止优化器把整个循环消掉。
        withUnsafePointer(to: dummy) { _ = $0.pointee }
        guard clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t2) == 0 else { return false }
        let ns1 = Int64(t1.tv_sec) &* 1_000_000_000 &+ Int64(t1.tv_nsec)
        let ns2 = Int64(t2.tv_sec) &* 1_000_000_000 &+ Int64(t2.tv_nsec)
        return ns2 <= ns1
    }
}
