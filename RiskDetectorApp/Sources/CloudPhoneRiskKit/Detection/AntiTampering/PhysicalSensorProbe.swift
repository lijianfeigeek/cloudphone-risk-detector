import Darwin
import Foundation
#if canImport(CoreMotion)
import CoreMotion
#endif

// MARK: - 物理传感器探测
//
// 云手机/模拟器无法提供真实物理传感器数据，或数据呈现恒定重力、零噪声、零漂移、
// 磁场异常、气压恒定等特征。本检测器采集 CoreMotion 的 15 帧（约 0.5 秒）样本并分析，
// 结果按 TTL 缓存并支持启动预热，避免支付等主路径被同步采样阻塞。

/// 物理传感器异常探测
///
/// 云手机/模拟器通常无法提供真实的物理传感器数据，或数据呈现明显异常特征：
/// 1. 重力矢量锁定：真机静止时 gravity 有微小抖动，云手机可能完全恒定
/// 2. 加速度噪底：userAcceleration RMS 真机有本底噪声，虚拟设备可能为 0
/// 3. 陀螺仪零漂：rotationRate 真机有微小漂移，模拟器可能完全为 0
/// 4. 磁力计：地球磁场约 25-65 μT，异常值表示虚拟/回放
/// 5. 气压计：CMAltimeter 不可用或相对海拔恒定表示无真实硬件
/// 6. 传感器不可用：isDeviceMotionAvailable 为 false 直接判定异常
///
/// ## 预热与缓存（盲区三）
/// - start() 时后台异步预热，评估时优先读缓存，避免 .payment 场景 UX 阻塞
/// - 采样帧数 15 帧（约 0.5 秒），气压计 1 秒，缓存 TTL 60 秒
/// - 线程安全：缓存与预热状态统一由 `cacheLock` 保护，避免并发重复采集
/// - 未预热兜底：主线程冷启动直接返回 pending 并继续后台预热；后台线程仍可同步采集
struct PhysicalSensorProbe: Detector {

    // 15 帧 @30 Hz ≈ 0.5 秒：足够计算方差，又能控制支付场景的等待时间。
    private static let deviceMotionSampleCount = 15
    /// 30 Hz 采样率，15 帧约 0.5 秒（支付场景 UX 友好）
    private static let deviceMotionInterval: TimeInterval = 1.0 / 30.0
    // 2 秒总超时：覆盖传感器启动延迟，同时保证检测链路不会被无限拖住。
    private static let totalTimeoutSeconds: TimeInterval = 2.0
    // 气压计采样 1 秒：相对海拔变化缓慢，短窗口只用于判断读数是否恒定。
    private static let barometerSampleSeconds: TimeInterval = 1.0

    /// 缓存 TTL（秒），超时后评估时需同步采集兜底
    private static let cacheTTLSeconds: TimeInterval = 60.0

    private static let prewarmQueue = DispatchQueue(label: "PhysicalSensorProbe.prewarm", qos: .utility)
    private struct CacheState {
        var cachedResult: DetectorResult?
        var cachedTimestamp: TimeInterval = 0
        var isPrewarming = false
    }
    private static let cacheStateLock = UnfairLock()
    private static var cacheState = CacheState()

    /// 后台异步预热，在 CPRiskKit.start() 时调用，不阻塞主流程。
    /// - Parameter forceRefresh: 为 true 时忽略缓存直接重采（用于过期缓存的后台刷新）。
    static func prewarm(forceRefresh: Bool = false) {
        #if targetEnvironment(simulator) || !os(iOS)
        return
        #else
        let now = Date().timeIntervalSince1970
        guard beginPrewarmIfNeeded(now: now, forceRefresh: forceRefresh) else { return }
        prewarmQueue.async {
            let probe = PhysicalSensorProbe()
            defer { finishPrewarm() }
            do {
                let result = try probe.performDetection()
                storeCache(result, at: Date().timeIntervalSince1970)
                #if DEBUG
                Logger.log("physical_sensor.prewarm: cached score=\(result.score)")
                #endif
            } catch {
                #if DEBUG
                Logger.log("physical_sensor.prewarm: failed \(error.localizedDescription)")
                #endif
            }
        }
        #endif
    }

    /// 在锁内判断是否需要启动预热；正在预热或缓存仍新鲜时返回 false。
    private static func beginPrewarmIfNeeded(now: TimeInterval, forceRefresh: Bool) -> Bool {
        cacheStateLock.withLock {
            if cacheState.isPrewarming { return false }
            if !forceRefresh,
               let _ = cacheState.cachedResult,
               (now - cacheState.cachedTimestamp) < cacheTTLSeconds {
                return false
            }

            cacheState.isPrewarming = true
            return true
        }
    }

    /// 清除预热进行中标记；由 `defer` 保证异常路径也会调用。
    private static func finishPrewarm() {
        cacheStateLock.withLock { cacheState.isPrewarming = false }
    }

    /// 存储检测结果与时间戳，供后续评估零阻塞读取。
    private static func storeCache(_ result: DetectorResult, at timestamp: TimeInterval) {
        cacheStateLock.withLock {
            cacheState.cachedResult = result
            cacheState.cachedTimestamp = timestamp
        }
    }

    /// 读取缓存快照与年龄；无缓存时返回 nil。
    private static func cachedSnapshot(now: TimeInterval) -> (result: DetectorResult, age: TimeInterval)? {
        cacheStateLock.withLock {
            guard let result = cacheState.cachedResult, cacheState.cachedTimestamp > 0 else { return nil }
            return (result, now - cacheState.cachedTimestamp)
        }
    }

    /// 评估入口：优先返回新鲜缓存，其次返回过期缓存并异步刷新；
    /// 冷启动且在主线线程时返回 pending，避免阻塞 UI；后台线程可同步采集兜底。
    func detect() throws -> DetectorResult {
        #if targetEnvironment(simulator)
        // 模拟器无真实传感器，直接降级。
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
        #elseif !os(iOS)
        // 非 iOS 平台无 CoreMotion 语义，返回 0 分不参与判定。
        return DetectorResult(score: 0, methods: ["unavailable_macos"])
        #else
        let now = Date().timeIntervalSince1970

        // 优先读 fresh cache，命中则零阻塞返回。
        if let snapshot = Self.cachedSnapshot(now: now),
           snapshot.age < Self.cacheTTLSeconds {
            return snapshot.result
        }

        // 过期缓存也优先复用，后台刷新，避免支付主路径回退到同步采集。
        if let staleSnapshot = Self.cachedSnapshot(now: now) {
            Self.prewarm(forceRefresh: true)
            #if DEBUG
            Logger.log("physical_sensor: using_stale_cache age=\(Int(staleSnapshot.age))s, refresh_async")
            #endif
            return staleSnapshot.result
        }

        // 冷启动且运行在主线程时，避免同步采集阻塞 UX，转为后台预热兜底。
        if Thread.isMainThread {
            Self.prewarm()
            #if DEBUG
            Logger.log("physical_sensor: cold_start_main_thread, pending_prewarm")
            #endif
            return DetectorResult(score: 0, methods: ["physical_sensor:pending_prewarm"])
        }

        // 后台线程或非 UI 路径，允许同步采集兜底。
        #if DEBUG
        Logger.log("physical_sensor: cache_miss, sync_collect_background")
        #endif
        let result = try performDetection()
        Self.storeCache(result, at: Date().timeIntervalSince1970)
        return result
        #endif
    }

    /// 实际执行检测（供预热与 detect 兜底共用）。
    /// - 返回：各分项累加分数与明细；传感器不可用时提前返回 +20。
    private func performDetection() throws -> DetectorResult {
        #if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
        #elseif !os(iOS)
        return DetectorResult(score: 0, methods: ["unavailable_macos"])
        #else
        #if canImport(CoreMotion)
        var score: Double = 0
        var methods: [String] = []

        // 1. 传感器不可用 -> +20
        let motionManager = CMMotionManager()
        guard motionManager.isDeviceMotionAvailable else {
            score += 20
            methods.append("physical_sensor:device_motion_unavailable")
            return DetectorResult(score: score, methods: methods)
        }

        // 2-5: 采集 deviceMotion 并分析（15 帧约 0.5 秒）
        let motionResult = collectAndAnalyzeDeviceMotion(motionManager: motionManager)
        score += motionResult.score
        methods.append(contentsOf: motionResult.methods)

        // 6: 气压计检测（仅 iOS 有 CMAltimeter）
        #if os(iOS)
        let baroResult = checkBarometer()
        score += baroResult.score
        methods.append(contentsOf: baroResult.methods)
        #endif

        return DetectorResult(score: score, methods: methods)
        #else
        return DetectorResult(score: 20, methods: ["physical_sensor:coremotion_unavailable"])
        #endif
        #endif
    }

    #if canImport(CoreMotion) && !targetEnvironment(simulator) && os(iOS)
    /// 采集并分析 deviceMotion：重力/加速度/陀螺仪/磁力计四类特征。
    /// - 采样窗口：15 帧 @30 Hz，总超时 2 秒；
    /// - 失败语义：超时 +15、采集错误 +12、样本不足 +10，均提前返回。
    private func collectAndAnalyzeDeviceMotion(motionManager: CMMotionManager) -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        let semaphore = DispatchSemaphore(value: 0)
        let queue = OperationQueue()
        queue.qualityOfService = .userInitiated
        queue.maxConcurrentOperationCount = 1

        var gravitySamples: [CMAcceleration] = []
        var userAccelSamples: [CMAcceleration] = []
        var rotationSamples: [CMRotationRate] = []
        var magneticSamples: [CMMagneticField] = []
        var collectError: Error?
        let lock = UnfairLock()

        motionManager.deviceMotionUpdateInterval = Self.deviceMotionInterval
        motionManager.startDeviceMotionUpdates(
            using: .xMagneticNorthZVertical,
            to: queue
        ) { motion, error in
            lock.withLock {
                if let err = error {
                    collectError = err
                    motionManager.stopDeviceMotionUpdates()
                    semaphore.signal()
                    return
                }
                guard let m = motion else { return }
                gravitySamples.append(m.gravity)
                userAccelSamples.append(m.userAcceleration)
                rotationSamples.append(m.rotationRate)
                magneticSamples.append(m.magneticField.field)

                if gravitySamples.count >= Self.deviceMotionSampleCount {
                    motionManager.stopDeviceMotionUpdates()
                    semaphore.signal()
                }
            }
        }

        let timeout = DispatchTime.now() + Self.totalTimeoutSeconds
        if semaphore.wait(timeout: timeout) == .timedOut {
            motionManager.stopDeviceMotionUpdates()
            score += 15
            methods.append("physical_sensor:motion_sampling_timeout")
            return (score, methods)
        }

        let (err, gSamples, uSamples, rSamples, mSamples) = lock.withLock {
            (collectError, gravitySamples, userAccelSamples, rotationSamples, magneticSamples)
        }
        if let err = err {
            score += 12
            methods.append("physical_sensor:motion_error:\(err.localizedDescription)")
            return (score, methods)
        }

        guard gSamples.count >= Self.deviceMotionSampleCount else {
            score += 10
            methods.append("physical_sensor:insufficient_samples:\(gSamples.count)")
            return (score, methods)
        }

        // 重力矢量锁定：gravity 标准差 < 0.001 -> +18
        let gravityStd = stddevOfAccelerations(gSamples)
        if gravityStd < 0.001 {
            score += 18
            methods.append("physical_sensor:gravity_locked:std_\(String(format: "%.6f", gravityStd))")
        }

        // 加速度噪底：userAcceleration RMS < 0.001 -> +15
        let userRms = rmsOfAccelerations(uSamples)
        if userRms < 0.001 {
            score += 15
            methods.append("physical_sensor:accel_noise_floor:rms_\(String(format: "%.6f", userRms))")
        }

        // 陀螺仪零漂：rotationRate 均值≈0 且方差极低 -> +12
        let (rotMean, rotVar) = meanAndVarianceOfRotationRates(rSamples)
        let rotMeanMag = sqrt(rotMean.x * rotMean.x + rotMean.y * rotMean.y + rotMean.z * rotMean.z)
        if rotMeanMag < 0.001 && rotVar < 1e-8 {
            score += 12
            methods.append("physical_sensor:gyro_zero_drift:mean_\(String(format: "%.6f", rotMeanMag))_var_\(String(format: "%.2e", rotVar))")
        }

        // 磁力计：总场强 0 或不在 25-65 μT -> +15
        let magMagnitudes = mSamples.map { sqrt($0.x * $0.x + $0.y * $0.y + $0.z * $0.z) }
        guard !magMagnitudes.isEmpty else {
            score += 15
            methods.append("physical_sensor:magnetometer_no_samples")
            return (score, methods)
        }
        let magMean = magMagnitudes.reduce(0, +) / Double(magMagnitudes.count)
        if magMean < 0.1 {
            score += 15
            methods.append("physical_sensor:magnetometer_zero:mean_\(String(format: "%.2f", magMean))uT")
        } else if magMean < 25 || magMean > 65 {
            score += 15
            methods.append("physical_sensor:magnetometer_anomaly:mean_\(String(format: "%.2f", magMean))uT")
        }

        return (score, methods)
    }

    #if os(iOS)
    /// 采集气压计相对海拔读数，判断硬件是否存在及读数是否恒定。
    /// - 采样窗口：1 秒，额外 0.5 秒等待余量；
    /// - 授权不足/硬件不可用时给 10 分并提前返回。
    private func checkBarometer() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        guard CMAltimeter.isRelativeAltitudeAvailable() else {
            score += 10
            methods.append("physical_sensor:barometer_unavailable")
            return (score, methods)
        }

        // iOS 17.4+：检查 Motion & Fitness 授权，denied/restricted 时跳过气压计检测
        if #available(iOS 17.4, *) {
            switch CMAltimeter.authorizationStatus() {
            case .denied, .restricted:
                score += 10
                methods.append("physical_sensor:barometer_unauthorized")
                return (score, methods)
            case .notDetermined, .authorized:
                break
            @unknown default:
                break
            }
        }

        let semaphore = DispatchSemaphore(value: 0)
        let altimeter = CMAltimeter()
        var altitudeReadings: [Double] = []
        let lock = UnfairLock()
        let baroQueue = OperationQueue()
        baroQueue.qualityOfService = .userInitiated
        baroQueue.maxConcurrentOperationCount = 1

        // 使用后台队列回调，避免主线程调用时 semaphore.wait 导致死锁
        altimeter.startRelativeAltitudeUpdates(to: baroQueue) { data, error in
            lock.withLock {
                if error != nil {
                    altimeter.stopRelativeAltitudeUpdates()
                    semaphore.signal()
                    return
                }
                guard let d = data else { return }
                altitudeReadings.append(d.relativeAltitude.doubleValue)
            }
        }

        // 使用全局队列，避免主线程调用 checkBarometer 时 asyncAfter 无法执行导致死锁
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + Self.barometerSampleSeconds) {
            altimeter.stopRelativeAltitudeUpdates()
            semaphore.signal()
        }

        let timeout = DispatchTime.now() + Self.barometerSampleSeconds + 0.5
        _ = semaphore.wait(timeout: timeout)

        let readings = lock.withLock { altitudeReadings }

        if readings.count < 2 {
            score += 8
            methods.append("physical_sensor:barometer_insufficient_readings:\(readings.count)")
            return (score, methods)
        }

        let altStd = stddev(readings)
        if altStd < 0.01 {
            score += 10
            methods.append("physical_sensor:barometer_constant:std_\(String(format: "%.4f", altStd))")
        }

        return (score, methods)
    }
    #endif

    /// 计算三轴加速度样本各分量去均值后的总体标准差。
    private func stddevOfAccelerations(_ samples: [CMAcceleration]) -> Double {
        guard samples.count >= 2 else { return 0 }
        let n = Double(samples.count)
        var sumX = 0.0, sumY = 0.0, sumZ = 0.0
        for s in samples {
            sumX += s.x; sumY += s.y; sumZ += s.z
        }
        let meanX = sumX / n, meanY = sumY / n, meanZ = sumZ / n
        var varSum = 0.0
        for s in samples {
            let dx = s.x - meanX, dy = s.y - meanY, dz = s.z - meanZ
            varSum += dx * dx + dy * dy + dz * dz
        }
        return sqrt(varSum / (n * 3.0))
    }

    /// 计算三轴加速度的均方根（RMS），用于衡量本底噪声强度。
    private func rmsOfAccelerations(_ samples: [CMAcceleration]) -> Double {
        guard !samples.isEmpty else { return 0 }
        var sum = 0.0
        for s in samples {
            sum += s.x * s.x + s.y * s.y + s.z * s.z
        }
        return sqrt(sum / Double(samples.count * 3))
    }

    /// 计算三轴角速度的均值向量与总体方差。
    private func meanAndVarianceOfRotationRates(_ samples: [CMRotationRate]) -> (mean: CMRotationRate, variance: Double) {
        guard samples.count >= 2 else { return (CMRotationRate(x: 0, y: 0, z: 0), 0) }
        let n = Double(samples.count)
        var sumX = 0.0, sumY = 0.0, sumZ = 0.0
        for s in samples {
            sumX += s.x; sumY += s.y; sumZ += s.z
        }
        let mean = CMRotationRate(x: sumX / n, y: sumY / n, z: sumZ / n)
        var varSum = 0.0
        for s in samples {
            let dx = s.x - mean.x, dy = s.y - mean.y, dz = s.z - mean.z
            varSum += dx * dx + dy * dy + dz * dz
        }
        return (mean, varSum / (n * 3.0))
    }

    /// 计算一维样本的总体标准差。
    private func stddev(_ values: [Double]) -> Double {
        guard values.count >= 2 else { return 0 }
        let n = Double(values.count)
        let mean = values.reduce(0, +) / n
        let variance = values.map { ($0 - mean) * ($0 - mean) }.reduce(0, +) / n
        return sqrt(variance)
    }
    #endif
}

extension PhysicalSensorProbe {
    /// 将检测结果转换为 `physical_sensor_anomaly` 软信号。
    /// - 置信度按 score/70 线性折算并封顶 1.0；
    /// - layer 3、weightHint 70：物理传感器异常受设备姿态影响，需与其他证据联合判断。
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        let physicalMethods = result.methods.filter { $0.hasPrefix("physical_sensor") }
        guard !physicalMethods.isEmpty else { return [] }

        return [RiskSignal(
            id: "physical_sensor_anomaly",
            category: "device",
            score: result.score,
            evidence: ["detail": physicalMethods.joined(separator: ",")],
            state: .soft(confidence: min(result.score / 70.0, 1.0)),
            layer: 3,
            weightHint: 70
        )]
    }
}
