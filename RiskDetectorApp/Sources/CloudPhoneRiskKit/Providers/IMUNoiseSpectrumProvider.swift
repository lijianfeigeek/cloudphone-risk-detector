// IMU 噪声频谱 Provider。
// 以 100Hz 采集 256 个加速度模长样本，做 FFT 得到频谱指纹与噪声底。
// 真实传感器存在宽带热噪声；云手机/模拟器常返回恒定或合成数据，高频噪声底异常低。
// 结果缓存 120s，避免频繁采样影响宿主 App 性能。
#if os(iOS)
import Accelerate
import CoreMotion
import CryptoKit
import Foundation

/// 加速度计噪声频谱采集器，输出指纹与合成噪声信号。
final class IMUNoiseSpectrumProvider: RiskSignalProvider {
    static let shared = IMUNoiseSpectrumProvider()
    let id = "imu_noise_spectrum"

    // 100Hz / 256 点：FFT 要求 2 的幂，256 点覆盖约 2.56s，高频段足以观察噪声底。
    private let sampleRate: Double = 100.0
    private let sampleCount = 256
    private let samplingTimeout: TimeInterval = 4.0

    private let lock = UnfairLock()
    private var cachedResult: CachedResult?
    private let cacheTTL: TimeInterval = 120

    private struct CachedResult {
        let signals: [RiskSignal]
        let time: TimeInterval
    }

    /// 返回缓存的采样结果；过期后重新采集。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let now = ProcessInfo.processInfo.systemUptime
        let cached: [RiskSignal]? = lock.withLock {
            if let c = cachedResult, now - c.time < cacheTTL { return c.signals }
            return nil
        }
        if let cached { return cached }

        let result = collect()

        lock.withLock {
            cachedResult = CachedResult(signals: result, time: ProcessInfo.processInfo.systemUptime)
        }
        return result
    }

    /// 启动加速度计采样，超时或采样不足时返回 `.unavailable`。
    /// - 加速度计不可用：soft(0.5) 的 `imu_noise_unavailable`；
    /// - 采样不足：`.unavailable` 的 `imu_noise_insufficient`；
    /// - 采样成功：固定输出指纹信号，噪声底 < -80dB 时追加 `imu_noise_synthetic`。
    private func collect() -> [RiskSignal] {
        let manager = CMMotionManager()
        guard manager.isAccelerometerAvailable else {
            return [RiskSignal(
                id: SignalID.imuNoiseUnavailable,
                category: SignalCategory.cloudphone,
                score: 0,
                evidence: ["detail": "accelerometer_unavailable"],
                state: .soft(confidence: 0.5),
                layer: 1,
                weightHint: 60
            )]
        }

        let requiredCount = sampleCount
        var samples = [Double]()
        samples.reserveCapacity(requiredCount)
        let semaphore = DispatchSemaphore(value: 0)
        let sampleLock = UnfairLock()
        let queue = OperationQueue()
        queue.qualityOfService = .userInitiated

        manager.accelerometerUpdateInterval = 1.0 / sampleRate
        // 回调在独立 OperationQueue 上执行，锁只保护样本数组与完成判断。
        manager.startAccelerometerUpdates(to: queue) { data, _ in
            guard let data else { return }
            let mag = sqrt(
                data.acceleration.x * data.acceleration.x +
                data.acceleration.y * data.acceleration.y +
                data.acceleration.z * data.acceleration.z
            )
            let done = sampleLock.withLock { () -> Bool in
                if samples.count < requiredCount {
                    samples.append(mag)
                }
                return samples.count >= requiredCount
            }
            if done { semaphore.signal() }
        }

        let timeout = DispatchTime.now() + samplingTimeout
        // 达到超时时间即停止，已采样本若不足 256 会在下方降级为 unavailable。
        _ = semaphore.wait(timeout: timeout)
        manager.stopAccelerometerUpdates()

        let collectedSamples = sampleLock.withLock { Array(samples.prefix(requiredCount)) }

        guard collectedSamples.count >= requiredCount else {
            return [RiskSignal(
                id: SignalID.imuNoiseInsufficient,
                category: SignalCategory.cloudphone,
                score: 0,
                evidence: ["samples": "\(collectedSamples.count)"],
                state: .unavailable,
                layer: 3,
                weightHint: 50
            )]
        }

        let spectrum = fftMagnitude(signal: collectedSamples)
        guard !spectrum.isEmpty else {
            return [RiskSignal(
                id: SignalID.imuNoiseUnavailable,
                category: SignalCategory.cloudphone,
                score: 0,
                evidence: ["detail": "fft_failed"],
                state: .unavailable,
                layer: 3,
                weightHint: 50
            )]
        }

        let fp = spectrumFingerprint(spectrum: spectrum)
        let noiseFloor = spectrumNoiseFloor(spectrum: spectrum)

        var out = [RiskSignal]()

        // 指纹本身作为中性证据上报（hard detected:false），供服务端聚类/比对。
        out.append(RiskSignal(
            id: SignalID.imuNoiseFingerprint,
            category: SignalCategory.cloudphone,
            score: 0,
            evidence: [
                "fingerprint": fp,
                "noise_floor_db": String(format: "%.2f", noiseFloor),
            ],
            state: .hard(detected: false),
            layer: 1,
            weightHint: 75
        ))

        // 噪声底低于 -80dB 意味着高频段几乎没有能量，常见于恒定/合成加速度数据；
        // 真实 MEMS 传感器即使静止也存在明显热噪声，通常不会低到这个量级。
        if noiseFloor < -80.0 {
            out.append(RiskSignal(
                id: SignalID.imuNoiseSynthetic,
                category: SignalCategory.cloudphone,
                score: 0,
                evidence: ["noise_floor_db": String(format: "%.2f", noiseFloor)],
                state: .soft(confidence: 0.8),
                layer: 1,
                weightHint: 80
            ))
        }

        return out
    }

    // MARK: - DSP

    /// 计算单边幅度谱（dB）。
    /// - 仅接受 2 的幂长度，否则返回空数组；
    /// - 使用 `withUnsafeMutableBufferPointer` 保证 vDSP 调用期间指针有效。
    private func fftMagnitude(signal: [Double]) -> [Double] {
        let n = signal.count
        guard n > 0, n & (n - 1) == 0 else { return [] }
        let log2n = vDSP_Length(log2(Double(n)))

        guard let fftSetup = vDSP_create_fftsetupD(log2n, FFTRadix(kFFTRadix2)) else {
            return []
        }
        defer { vDSP_destroy_fftsetupD(fftSetup) }

        var realPart = signal
        var imagPart = [Double](repeating: 0, count: n)
        let halfN = n / 2

        // 用 withUnsafeMutableBufferPointer 固定缓冲区指针生命周期，确保跨多次 vDSP 调用仍有效。
        let magnitudes: [Double] = realPart.withUnsafeMutableBufferPointer { realBuf in
            imagPart.withUnsafeMutableBufferPointer { imagBuf in
                var splitComplex = DSPDoubleSplitComplex(
                    realp: realBuf.baseAddress!,
                    imagp: imagBuf.baseAddress!
                )

                vDSP_fft_zipD(fftSetup, &splitComplex, 1, log2n, FFTDirection(kFFTDirection_Forward))

                var mags = [Double](repeating: 0, count: halfN)
                vDSP_zvmagsD(&splitComplex, 1, &mags, 1, vDSP_Length(halfN))

                var one: Double = 1.0
                vDSP_vdbconD(mags, 1, &one, &mags, 1, vDSP_Length(halfN), 0)

                return mags
            }
        }

        return magnitudes
    }

    /// 把幅度谱量化为 8 段、每段均值映射到 0...255，再取 SHA-256 前 16 字节。
    /// 量化容忍传感器/浮点微小抖动，同时保留机型间的频谱形状差异。
    private func spectrumFingerprint(spectrum: [Double]) -> String {
        guard !spectrum.isEmpty else { return "" }
        let binCount = 8
        let binSize = spectrum.count / binCount
        guard binSize > 0 else { return "" }

        var bins = [UInt8]()
        bins.reserveCapacity(binCount)
        for i in 0..<binCount {
            let start = i * binSize
            let end = min(start + binSize, spectrum.count)
            let slice = spectrum[start..<end]
            let avg = slice.reduce(0, +) / Double(slice.count)
            let quantized = UInt8(clamping: Int((avg + 100) * 2.55))
            bins.append(quantized)
        }

        let digest = SHA256.hash(data: Data(bins))
        return digest.prefix(16).map { String(format: "%02x", $0) }.joined()
    }

    /// 取高频段（后 1/4）幅度的中位数作为噪声底，单位 dB。
    /// 中位数对偶发尖峰不敏感；样本过少时返回 -100 表示无法判断。
    private func spectrumNoiseFloor(spectrum: [Double]) -> Double {
        guard spectrum.count > 4 else { return -100 }
        let highFreq = Array(spectrum.suffix(spectrum.count / 4))
        guard !highFreq.isEmpty else { return -100 }
        let sorted = highFreq.sorted()
        let mid = sorted.count / 2
        if sorted.count % 2 == 0 {
            return (sorted[mid - 1] + sorted[mid]) / 2.0
        }
        return sorted[mid]
    }
}
#else
import Foundation

/// 非 iOS 平台的空实现：无 CoreMotion/Accelerate，不产生信号。
final class IMUNoiseSpectrumProvider: RiskSignalProvider {
    static let shared = IMUNoiseSpectrumProvider()
    let id = "imu_noise_spectrum"
    /// 非 iOS 平台没有 CoreMotion，不产生信号。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] { [] }
}
#endif
