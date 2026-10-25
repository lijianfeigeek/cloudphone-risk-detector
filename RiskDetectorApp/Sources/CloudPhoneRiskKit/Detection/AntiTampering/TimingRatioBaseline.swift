import CRiskCore
import Foundation

// MARK: - 时序比值基线
//
// 为 KernelHookSideChannel 等时序侧信道提供可复用的采样与判定原语：分别测量基线
// 系统调用与待测操作的中位/P95 耗时，用时序比值而非绝对值识别 Frida Stalker 等
// DBT 插桩带来的额外开销。比值可抵消设备代际与负载差异。

/// 时序比值基线与统计工具。
/// - 线程模型：纯函数 + 局部数组，无共享可变状态，可并发调用。
/// - 采样单位：`mach_absolute_time` tick；仅在输出报告时换算为纳秒。
struct TimingRatioBaseline {
    /// 一对基线/探针操作的评估结果（用于诊断与日志）。
    struct PairEvaluation {
        let baselineName: String
        let probeName: String
        let sampleCount: Int
        let baselineMedianNs: UInt64
        let probeMedianNs: UInt64
        let medianRatio: Double
        let p95Ratio: Double
        let isAnomalous: Bool
    }

    // timebase 在进程生命周期内固定，只读取一次，避免采样循环中反复系统调用。
    private static let timebaseInfo: mach_timebase_info_data_t = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info
    }()

    /// 将 mach tick 换算为纳秒；乘法溢出时饱和到 `UInt64.max`，避免崩溃或回绕。
    private static func nanoseconds(from ticks: UInt64) -> UInt64 {
        let denom = max(UInt64(timebaseInfo.denom), 1)
        let (product, overflow) = ticks.multipliedReportingOverflow(by: UInt64(timebaseInfo.numer))
        return overflow ? UInt64.max : product / denom
    }

    // MARK: - 采样噪声（放大 Stalker DBT 开销）

    /// 在采样循环中调用的无副作用计算噪声，用于放大 Stalker DBT 的指令翻译开销。
    /// 包含 5–10 次累加/位运算、多分支逻辑及 volatile 风格内存读写，使 Frida Stalker 产生更多开销。
    /// - 关闭优化：确保这些运算不会被编译器消除，否则噪声失效。
    @_optimize(none)
    static func samplingNoise() {
        // 初始值取常用 64 位混合常量，保证后续每轮状态都不同。
        var acc: UInt64 = 0x9E3779B97F4A7C15
        let ptr = UnsafeMutablePointer<UInt64>.allocate(capacity: 1)
        defer { ptr.deallocate() }

        for i in 0..<8 {
            // 四种分支交替执行，制造不可预测的控制流（对 Stalker 翻译更昂贵）。
            switch i & 3 {
            case 0:
                acc = acc &+ 1
                acc ^= acc << 13
            case 1:
                acc ^= acc >> 7
                acc = acc &* 0x9E3779B97F4A7C15
            case 2:
                acc ^= acc << 17
                acc = acc &+ (acc >> 11)
            default:
                acc = (acc ^ (acc << 5)) &+ (acc >> 3)
            }
            // 经内存往返读写，强制产生真实的 load/store 而非仅寄存器运算。
            ptr.pointee = acc
            acc = ptr.pointee
        }
    }

    // MARK: - 放大版 Stalker 探针

    /// 放大版时序探针：通过间接函数指针调用和交替多种 syscall，最大化 Stalker DBT 开销，
    /// 同时保持原生执行速度不变。Stalker 必须为每个间接分支目标做翻译，无法缓存优化。
    /// - Parameter count: 每类操作的采样次数，默认 30。
    /// - Returns: `(getpidSamples, statSamples)`，单位为 mach_absolute_time tick（比值不受单位影响）。
    @_optimize(none)
    static func amplifiedSamples(count: Int = defaultSampleCount) -> (getpid: [UInt64], stat: [UInt64]) {
#if targetEnvironment(simulator)
        // 模拟器上 direct syscall 不可用，返回空样本由调用方降级。
        return ([], [])
#else
        var getpidSamples: [UInt64] = []
        getpidSamples.reserveCapacity(count)
        var statSamples: [UInt64] = []
        statSamples.reserveCapacity(count)

        typealias PidFn = @convention(c) () -> pid_t
        typealias UidFn = @convention(c) () -> uid_t

        // 将 syscall wrapper 存入可变指针槽位——Stalker 无法对间接分支做静态翻译缓存。
        let fnSlot = UnsafeMutablePointer<PidFn>.allocate(capacity: 2)
        defer { fnSlot.deallocate() }
        fnSlot[0] = cprisk_getpid_direct
        fnSlot[1] = cprisk_getpid_direct

        let uidFn: UidFn = cprisk_getuid_direct

        // 随机决定 stat/getpid 的先后顺序，避免固定顺序被针对性地优化或识别。
        let statFirst = Bool.random()

        func sampleGetpidAmplified() {
            for i in 0..<count {
                samplingNoise()
                // 在测量间隙插入 getuid 调用，迫使 Stalker 翻译更多不同的 syscall 路径。
                _ = uidFn()

                // 交替使用两个槽位中的同址函数，迫使 Stalker 走间接分支。
                let slot = i & 1
                let fn = fnSlot[slot]
                let start = mach_absolute_time()
                _ = fn()
                let end = mach_absolute_time()
                // 至少记 1 tick，避免 0 值污染中位数计算。
                getpidSamples.append(max(1, end &- start))
            }
        }

        func sampleStatAmplified() {
            for i in 0..<count {
                samplingNoise()
                _ = uidFn()

                // 交替探测两条路径，覆盖不同的 VFS 路径长度。
                let pathIdx = i & 1
                let path = pathIdx == 0 ? "/usr/lib/dyld" : "/etc/passwd"
                let start = mach_absolute_time()
                _ = SVCDirectCall.secureAccess(path)
                let end = mach_absolute_time()
                statSamples.append(max(1, end &- start))
            }
        }

        if statFirst {
            sampleStatAmplified()
            sampleGetpidAmplified()
        } else {
            sampleGetpidAmplified()
            sampleStatAmplified()
        }

        return (getpidSamples, statSamples)
#endif
    }

    /// 单次比值评估结果。
    struct Evaluation {
        let medianRatio: Double
        let p95Ratio: Double
        let isAnomalous: Bool
    }

    /// 一维 tick 样本的中位数与 P95 统计。
    private struct TimingStats {
        let median: UInt64
        let p95: UInt64
    }

    // 30 个样本足以稳定估计中位数/P95，同时把单次检测耗时控制在毫秒级。
    static let defaultSampleCount = 30
    // 15 倍是保守阈值：正常设备比值接近 1，Stalker 插桩通常放大一个数量级以上。
    static let defaultRatioThreshold = 15.0

    /// 在正式测量前执行若干次噪声循环，再测量 `block` 的 tick 耗时。
    /// - 噪声用于让时钟/缓存进入稳定状态，并放大 Stalker 的翻译开销。
    @_optimize(none)
    private static func measureTicks(
        noiseIterations: Int = 6,
        block: () -> Void
    ) -> UInt64 {
        for _ in 0..<noiseIterations {
            samplingNoise()
        }
        let start = mach_absolute_time()
        block()
        let end = mach_absolute_time()
        return end &- start
    }

    /// 对一组基线/探针闭包执行预热、交错采样与比值评估。
    /// - Parameters:
    ///   - sampleCount: 采样次数，必须 > 0，否则返回 nil。
    ///   - warmupCount: 预热次数，排除首次调用的惰性初始化成本。
    ///   - noiseIterations: 每次测量前的噪声循环次数。
    ///   - ratioThreshold: 中位数或 P95 比值超过该值即判异常。
    ///   - baseline / probe: 待比较的两个操作。
    /// - Returns: 评估明细；参数非法或无有效中位数时返回 nil。
    static func evaluatePair(
        baselineName: String,
        probeName: String,
        sampleCount: Int = defaultSampleCount,
        warmupCount: Int = 3,
        noiseIterations: Int = 6,
        ratioThreshold: Double = defaultRatioThreshold,
        baseline: () -> Void,
        probe: () -> Void
    ) -> PairEvaluation? {
        guard sampleCount > 0 else { return nil }

        // 预热：排除首次调用时的惰性初始化、缺页与分支预测冷启动偏差。
        for _ in 0..<warmupCount {
            baseline()
            probe()
        }

        var baselineSamples: [UInt64] = []
        baselineSamples.reserveCapacity(sampleCount)
        var probeSamples: [UInt64] = []
        probeSamples.reserveCapacity(sampleCount)

        for i in 0..<sampleCount {
            // 奇偶交替先后顺序，抵消随时间的温漂与系统负载漂移。
            let baselineFirst = (i % 2 == 0)
            if baselineFirst {
                baselineSamples.append(measureTicks(noiseIterations: noiseIterations, block: baseline))
                probeSamples.append(measureTicks(noiseIterations: noiseIterations, block: probe))
            } else {
                probeSamples.append(measureTicks(noiseIterations: noiseIterations, block: probe))
                baselineSamples.append(measureTicks(noiseIterations: noiseIterations, block: baseline))
            }
        }

        guard let evaluation = evaluate(
            getpidSamples: baselineSamples,
            statSamples: probeSamples,
            ratioThreshold: ratioThreshold
        ) else {
            return nil
        }

        let baselineStats = computeStats(baselineSamples)
        let probeStats = computeStats(probeSamples)
        return PairEvaluation(
            baselineName: baselineName,
            probeName: probeName,
            sampleCount: sampleCount,
            baselineMedianNs: nanoseconds(from: baselineStats.median),
            probeMedianNs: nanoseconds(from: probeStats.median),
            medianRatio: evaluation.medianRatio,
            p95Ratio: evaluation.p95Ratio,
            isAnomalous: evaluation.isAnomalous
        )
    }

    /// 使用原始 tick 样本计算中位数/P95 比值与异常标志。
    /// - 返回：基线中位数为 0（无有效样本）时返回 nil。
    static func evaluate(
        getpidSamples: [UInt64],
        statSamples: [UInt64],
        ratioThreshold: Double = defaultRatioThreshold
    ) -> Evaluation? {
        let getpidStats = computeStats(getpidSamples)
        let statStats = computeStats(statSamples)

        guard getpidStats.median > 0 else { return nil }

        let medianRatio = Double(statStats.median) / Double(getpidStats.median)
        // P95 比值捕捉少数极慢样本（Stalker 偶发翻译风暴），与中位数互为补充。
        let p95Ratio = getpidStats.p95 > 0
            ? Double(statStats.p95) / Double(getpidStats.p95)
            : 0.0

        return Evaluation(
            medianRatio: medianRatio,
            p95Ratio: p95Ratio,
            isAnomalous: medianRatio > ratioThreshold || p95Ratio > ratioThreshold
        )
    }

    /// 便捷判定：样本是否异常；无有效数据时按非异常处理（失败开放，避免误杀）。
    static func isAnomalous(
        getpidSamples: [UInt64],
        statSamples: [UInt64],
        ratioThreshold: Double = defaultRatioThreshold
    ) -> Bool {
        evaluate(
            getpidSamples: getpidSamples,
            statSamples: statSamples,
            ratioThreshold: ratioThreshold
        )?.isAnomalous ?? false
    }

    /// 对样本排序后计算中位数与 P95；空样本返回全 0，由调用方按无效处理。
    private static func computeStats(_ samples: [UInt64]) -> TimingStats {
        let sorted = samples.sorted()
        let count = sorted.count
        guard count > 0 else {
            return TimingStats(median: 0, p95: 0)
        }

        // 偶数个样本取中间两项均值，奇数个直接取中位。
        let median = count % 2 == 1
            ? sorted[count / 2]
            : (sorted[count / 2 - 1] + sorted[count / 2]) / 2
        // P95 索引向下取整并夹到末元素，防止 count 较小时越界。
        let p95Index = min(Int(Double(count) * 0.95), count - 1)
        let p95 = sorted[p95Index]
        return TimingStats(median: median, p95: p95)
    }
}
