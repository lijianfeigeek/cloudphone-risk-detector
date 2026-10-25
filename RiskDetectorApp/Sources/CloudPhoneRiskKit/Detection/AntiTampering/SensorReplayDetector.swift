import Darwin
import Foundation
#if canImport(CoreMotion)
import CoreMotion
#endif

// MARK: - 传感器回放探测
//
// 云手机厂商常录制真机传感器数据后在虚拟设备上回放。回放数据在时间戳规律性、
// 探针响应量化程度和硬件时钟低位熵三方面与真机不同；本检测器据此给出 soft 分数。
// 不依赖 CoreMotion 采样，仅用时序与系统时钟特征，成本低且可在后台线程运行。

/// 传感器数据回放检测
///
/// 云手机厂商录制真机传感器数据后在虚拟设备上回放，
/// 但回放数据有以下可检测特征：
/// 1. 响应延迟：回放数据对随机探针请求的响应有固定延迟模式
/// 2. 数据周期性：回放数据会出现周期性重复模式
/// 3. 采样率不一致：真机采样率与请求频率高度匹配，回放可能有偏差
/// 4. 交叉验证：加速度计/陀螺仪/磁力计的物理耦合关系在回放中可能断裂
struct SensorReplayDetector: Detector {

    func detect() throws -> DetectorResult {
        #if targetEnvironment(simulator)
        // 模拟器时序不具备真机特征，直接降级避免误判。
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
        #else
        var score: Double = 0
        var methods: [String] = []

        // 1. 系统 uptime 时间戳规律性
        let tsCheck = checkTimestampRegularity()
        score += tsCheck.score
        methods.append(contentsOf: tsCheck.methods)

        // 2. 随机探针响应延迟量化程度
        let probeCheck = checkProbeLatency()
        score += probeCheck.score
        methods.append(contentsOf: probeCheck.methods)

        // 3. 硬件时钟低位熵
        let noiseCheck = checkSensorNoiseEntropy()
        score += noiseCheck.score
        methods.append(contentsOf: noiseCheck.methods)

        return DetectorResult(score: score, methods: methods)
        #endif
    }

    /// 检查系统 uptime 时间戳是否呈现回放痕迹。
    /// 真机时间戳单调递增且带调度器自然抖动，回放数据可能过于规律或出现跳变。
    /// - 采样窗口：20 次、每次 sleep 0.5 ms；
    /// - 判定：变异系数 CV < 0.02 时 +15。
    private func checkTimestampRegularity() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        let iterations = 20
        var intervals = [Double]()
        intervals.reserveCapacity(iterations)

        var lastTime = ProcessInfo.processInfo.systemUptime
        for _ in 0..<iterations {
            usleep(500) // 0.5ms
            let now = ProcessInfo.processInfo.systemUptime
            let delta = now - lastTime
            intervals.append(delta)
            lastTime = now
        }

        // 用变异系数衡量相对抖动，避免受绝对时间尺度影响。
        let mean = intervals.reduce(0, +) / Double(intervals.count)
        guard mean > 0 else { return (0, []) }
        let variance = intervals.map { ($0 - mean) * ($0 - mean) }.reduce(0, +) / Double(max(intervals.count - 1, 1))
        let stddev = sqrt(variance)
        let cv = stddev / mean

        // 真机 CV 通常 0.1–0.8（调度器自然抖动）；回放可能 < 0.02（过于规律）。
        if cv < 0.02 {
            score += 15
            methods.append("sensor_replay:timestamp_too_regular:cv_\(String(format: "%.4f", cv))")
        }

        return (score, methods)
    }

    /// 发出随机时长的探针并测量响应一致性。
    /// 真机延迟受调度影响自然波动；回放缓冲按固定块处理，延迟比例可能被量化。
    /// - 采样窗口：8 个固定但无规律的微秒级延迟；
    /// - 判定：实际/请求延迟比的 CV < 0.01 时 +12。
    private func checkProbeLatency() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        // 读取 timebase，将 mach tick 换算为微秒。
        var timebaseInfo = mach_timebase_info_data_t()
        mach_timebase_info(&timebaseInfo)

        // 故意使用不规则的延迟值，避免与固定刷新周期共振。
        let randomDelays: [UInt32] = [100, 237, 500, 1013, 173, 821, 50, 419]
        var actualDelays = [Double]()
        actualDelays.reserveCapacity(randomDelays.count)

        for delay in randomDelays {
            let start = mach_absolute_time()
            usleep(delay)
            let end = mach_absolute_time()
            let elapsed = Double(end - start) * Double(timebaseInfo.numer) / Double(max(timebaseInfo.denom, 1)) / 1000.0 // 换算为微秒
            actualDelays.append(elapsed)
        }

        // 比较实际延迟与请求延迟的比值。
        // 真机比值受调度影响自然波动（1.0–3.0x）；回放可能贴合缓冲区边界而高度一致。
        var ratios = [Double]()
        for (i, delay) in randomDelays.enumerated() {
            let ratio = actualDelays[i] / Double(delay)
            ratios.append(ratio)
        }

        // 全部比值几乎相同 → 延迟被量化，疑似回放。
        let ratioMean = ratios.reduce(0, +) / Double(ratios.count)
        guard ratioMean > 0 else { return (0, []) }
        let ratioVariance = ratios.map { ($0 - ratioMean) * ($0 - ratioMean) }.reduce(0, +) / Double(max(ratios.count - 1, 1))
        let ratioCV = sqrt(ratioVariance) / ratioMean

        if ratioCV < 0.01 {
            score += 12
            methods.append("sensor_replay:probe_quantized:cv_\(String(format: "%.4f", ratioCV))")
        }

        return (score, methods)
    }

    /// 检查硬件时钟低位的熵，作为传感器噪声特征的代理指标。
    /// 真机 mach_absolute_time() 低位含硬件时钟抖动；虚拟/回放环境可能被量化或重复。
    /// - 采样窗口：100 个样本，每个样本间空转 10 次时钟读取；
    /// - 判定：香农熵 < 2.0 bit 时 +15。
    private func checkSensorNoiseEntropy() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        // 真机低 8 位含硬件时钟熵；虚拟/回放环境可能量化或重复。
        let samples = 100
        var lsbs = [UInt8]()
        lsbs.reserveCapacity(samples)

        for _ in 0..<samples {
            let t = mach_absolute_time()
            lsbs.append(UInt8(t & 0xFF))
            // 短暂空转以获得不同的采样值，避免连续读到同一 tick。
            for _ in 0..<10 { _ = mach_absolute_time() }
        }

        // 统计低 8 位取值的分布并计算香农熵。
        var counts = [UInt8: Int]()
        for b in lsbs { counts[b, default: 0] += 1 }

        var entropy: Double = 0
        for (_, count) in counts {
            let p = Double(count) / Double(samples)
            if p > 0 {
                entropy -= p * log2(p)
            }
        }

        // 真机熵通常 > 4.0 bit；虚拟/回放可能 < 2.0 bit（量化或重复）。
        if entropy < 2.0 {
            score += 15
            methods.append("sensor_replay:low_noise_entropy:\(String(format: "%.2f", entropy))bits")
        }

        return (score, methods)
    }
}

extension SensorReplayDetector {
    /// 将检测结果转换为 `sensor_replay_detected` 软信号。
    /// - 置信度按 score/40 线性折算并封顶 1.0；
    /// - layer 3、weightHint 72：回放特征易受系统负载影响，仅作辅助证据。
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }
        
        var signals: [RiskSignal] = []
        
        let replayMethods = result.methods.filter { $0.hasPrefix("sensor_replay") }
        if !replayMethods.isEmpty {
            signals.append(RiskSignal(
                id: "sensor_replay_detected",
                category: "device",
                score: result.score,
                evidence: ["detail": replayMethods.joined(separator: ","), "count": "\(replayMethods.count)"],
                state: .soft(confidence: min(result.score / 40.0, 1.0)),
                layer: 3,
                weightHint: 72
            ))
        }
        
        return signals
    }
}
