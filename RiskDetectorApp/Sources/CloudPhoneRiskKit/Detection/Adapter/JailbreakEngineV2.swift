// 越狱检测引擎 V2（JailbreakEngineV2）
// 职责：在旧版 JailbreakEngine 之上编排反篡改/反调试检测器，并接入 C 层证明链。
// 管道位置：Detection/Adapter 层，位于各检测器与上层 RiskEvaluationActor 之间。
// 安全要点：检测顺序随机化、逐检测器超时、canary 校验与 attest finalize；异常按故障处理，证明不可用时 fail-closed。
import Foundation
import CryptoKit
import CRiskCore

/// JailbreakEngine V2 - 集成新架构检测器
///
/// 这个适配器将新的反篡改检测器集成到现有的 JailbreakEngine 中，
/// 保持向后兼容的同时增强检测能力。
///
/// ## 设计原则
/// 1. **向后兼容**: 保持现有 API 不变
/// 2. **渐进增强**: 通过配置启用新检测器
/// 3. **职责分离**: 检测器专注检测，引擎负责编排
/// 4. **可观测性**: 详细的日志输出
///
/// ## 线程模型与安全不变量
/// - `detect`/`quickDetect` 可并发调用；故障计数器由 `faultLock` 保护。
/// - 每个检测器独立超时，单点卡死不会拖垮整轮检测。
/// - 证明链 finalize 失败或 canary 不匹配都会直接加分（fail-closed）。
public final class JailbreakEngineV2 {
    
    // MARK: - 配置
    
    /// V2 扩展配置：控制各检测器开关、单检测器超时与日志级别。
    /// 默认值偏向覆盖（全部启用）；性能敏感场景可选用 `.performance`。
    public struct V2Config {
        /// 是否启用反篡改检测
        var enableAntiTampering: Bool = true
        
        /// 是否启用调试器检测
        var enableDebugger: Bool = true
        
        /// 是否启用 Frida 检测
        var enableFrida: Bool = true
        
        /// 是否启用代码签名验证
        var enableCodeSignature: Bool = true
        
        /// 是否启用内存完整性检查
        var enableMemoryIntegrity: Bool = true

        /// 是否启用 dylib 注入检测
        var enableDylibInjection: Bool = true
        
        /// 单个检测器的超时时间（毫秒）；超时按故障处理，不直接判越狱。
        var detectionTimeout: Int = 5000
        
        /// 是否启用详细日志
        var verboseLogging: Bool = false
        
        /// 默认配置：全部检测启用，超时 5 秒。
        public static let `default` = V2Config()
        
        /// 严格配置（所有检测启用）
        public static let strict = V2Config(
            enableAntiTampering: true,
            enableDebugger: true,
            enableFrida: true,
            enableCodeSignature: true,
            enableMemoryIntegrity: true,
            enableDylibInjection: true,
            verboseLogging: true
        )
        
        /// 性能优先配置（跳过耗时检测）
        public static let performance = V2Config(
            enableAntiTampering: true,
            enableDebugger: true,
            enableFrida: true,
            enableCodeSignature: false,
            enableMemoryIntegrity: false,
            enableDylibInjection: true,
            verboseLogging: false
        )
    }
    
    // MARK: - 属性

    /// 旧版引擎，负责文件/越狱路径等基础检测；V2 在其结果上叠加新检测器分数。
    private let legacyEngine: JailbreakEngine
    /// 创建时固定的 V2 配置；实例生命周期内不变，便于并发读取。
    private let v2Config: V2Config

    /// 各检测器连续故障（抛异常/超时）计数：单次故障只标记不计高分，
    /// 连续故障达到阈值才升级计分（与 `JailbreakEngine` 一致的熔断/去重）。
    private var consecutiveDetectorFaults: [DetectorID: Int] = [:]
    /// 快速检测各类别连续故障计数。
    private var consecutiveQuickFaults: [String: Int] = [:]
    /// 保护两个连续故障计数器的锁。
    private let faultLock = UnfairLock()
    /// 连续故障达到该次数才升级计分（单次故障可能是瞬时资源问题）。
    private static let consecutiveFaultEscalationThreshold = 2
    /// 连续故障升级时追加的分数；刻意不设为 100，保留与其他证据的组合空间。
    private static let consecutiveFaultEscalationScore: Double = 40
    
    // MARK: - 初始化
    
    /// 创建 V2 引擎。
    /// - Parameter v2Config: 检测器开关与超时配置，默认 `.default`。
    public init(v2Config: V2Config = .default) {
        self.v2Config = v2Config
        self.legacyEngine = JailbreakEngine()
    }
    
    // MARK: - 公开 API
    
    /// 执行检测（V2 增强版）：旧引擎结果 + V2 检测器结果，合并去重后截断到 100。
    /// - Parameter config: 检测配置（提供判决阈值）
    /// - Returns: 检测结果；模拟器上返回 `unavailable`，不得当作干净设备采信。
    public func detect(config: JailbreakConfig) -> DetectionResult {
        Logger.log("JailbreakEngineV2: start detection")
        
#if targetEnvironment(simulator)
        return handleSimulator(config: config)
#else
        // 1. 执行原有检测
        let legacyResult = legacyEngine.detect(config: config)
        var score = legacyResult.confidence
        var methods = legacyResult.detectedMethods
        
        Logger.log("JailbreakEngineV2: legacy score=\(score), methods=\(methods.count)")
        
        // 2. 执行 V2 新增检测
        let v2Result = detectV2(baseScore: score)
        score += v2Result.score
        methods.append(contentsOf: v2Result.methods)
        
        // 3. 去重并排序
        methods = Array(Set(methods)).sorted()
        
        // 分数上限 100；阈值比较使用截断后的最终分，保证上报分与判决一致。
        let finalScore = min(score, 100)
        let isJailbroken = finalScore >= config.threshold
        
        Logger.log("JailbreakEngineV2: final score=\(finalScore), isJailbroken=\(isJailbroken), methods=\(methods.count)")
        
        return DetectionResult(
            isJailbroken: isJailbroken,
            confidence: finalScore,
            detectedMethods: methods,
            details: buildDetails(
                score: finalScore,
                methods: methods,
                legacyScore: legacyResult.confidence,
                v2Score: v2Result.score
            )
        )
#endif
    }
    
    /// 快速检测（仅执行关键检测：反篡改、调试器、Frida、dylib 注入）。
    /// - Returns: 简化的检测结果；模拟器上 `unavailable == true`。
    public func quickDetect() -> QuickDetectionResult {
        Logger.log("JailbreakEngineV2: quick detect")
        
#if targetEnvironment(simulator)
        return QuickDetectionResult(
            isRisky: false,
            riskLevel: .none,
            detectedCategories: [],
            unavailable: true
        )
#else
        var detectedCategories: [String] = []
        var totalScore: Double = 0
        
        // 只执行快速检测项
        let quickDetectors: [(String, Detector)] = [
            (ObfuscatedConstants.categoryAntiTamper, AntiTamperingDetector()),
            (ObfuscatedConstants.detectorIDDebugger, DebuggerDetector()),
            (ObfuscatedConstants.keywordFrida, FridaDetector()),
            (ObfuscatedConstants.detectorIDDylibInjection, DylibInjectionDetector()),
        ]
        
        for (category, detector) in quickDetectors {
            do {
                let result = try detector.detect()
                faultLock.withLock { consecutiveQuickFaults[category] = 0 }
                if result.score > 0 {
                    detectedCategories.append(category)
                    totalScore += result.score
                }
            } catch {
                // 单次故障只标记，不直接判高危；连续故障才升级并记录。
                let streak = faultLock.withLock { () -> Int in
                    let next = min(consecutiveQuickFaults[category] ?? 0, Int.max - 1) + 1
                    consecutiveQuickFaults[category] = next
                    return next
                }
                Logger.log("quick_detect.\(category): detector fault, consecutive streak=\(streak) — marked, not scored as risk")
                if streak >= Self.consecutiveFaultEscalationThreshold {
                    detectedCategories.append(category)
                    totalScore += Self.consecutiveFaultEscalationScore
                    Logger.log("quick_detect.\(category): consecutive faults escalated (streak=\(streak))")
                }
            }
        }
        
        // 快速路径同样只按累计分数分级；单次故障已在上方被标记而非计分。
        let riskLevel = QuickDetectionResult.RiskLevel.from(score: totalScore)
        
        return QuickDetectionResult(
            isRisky: !detectedCategories.isEmpty,
            riskLevel: riskLevel,
            detectedCategories: detectedCategories
        )
#endif
    }
    
    /// 获取检测器启用状态（直接映射 `V2Config`，不触发任何实际检测）。
    /// - Returns: 各检测器开关快照及汇总计数。
    public func detectorStatus() -> DetectorStatus {
        var status = DetectorStatus()
        
        // 检查各检测器状态
        status.antiTampering = v2Config.enableAntiTampering
        status.debugger = v2Config.enableDebugger
        status.frida = v2Config.enableFrida
        status.codeSignature = v2Config.enableCodeSignature
        status.memoryIntegrity = v2Config.enableMemoryIntegrity
        status.dylibInjection = v2Config.enableDylibInjection
        
        return status
    }
    
    // MARK: - 私有方法

    /// 单检测器超时的秒数表示，供 `DispatchSemaphore.wait` 使用。
    private var detectionTimeoutSeconds: TimeInterval {
        Double(v2Config.detectionTimeout) / 1000.0
    }

    /// 数值型检测器标识，替代旧版 `detectorName: String` 参数。
    /// 字符串字面量（如 "FridaDetector"）是静态分析的富矿：攻击者 grep `__cstring`
    /// 中的 `Detector` 后缀即可定位所有调度点。改为 UInt8 枚举后编译为小整数常量，
    /// 日志字符串也只在实际输出时才从加密字符串表解密。
    private enum DetectorID: UInt8 {
        case antiTampering = 0x11
        case debugger      = 0x23
        case frida         = 0x37
        case codeSignature = 0x4D
        case memoryIntegrity = 0x59
        case dylibInjection  = 0x6B
        case canary          = 0x7F
    }

    /// 在独立队列执行单个检测器，并用信号量实施硬超时。
    /// - Parameters:
    ///   - work: 检测器闭包；抛错视为故障而非“检测到风险”。
    ///   - id: 数值化检测器标识，用于故障计数与日志。
    ///   - timeout: 超时秒数；超时路径不等待后台任务结束。
    /// - Returns: 检测结果；抛错/超时归一到 `faultResult`。
    private func runDetectorWithTimeout(_ work: @escaping () throws -> DetectorResult, id: DetectorID, timeout: TimeInterval) -> DetectorResult {
        let semaphore = DispatchSemaphore(value: 0)
        // 后台闭包与调用方通过 box 交换结果；信号量保证 happens-before。
        final class ResultBox: @unchecked Sendable {
            var value: DetectorResult
            init(_ v: DetectorResult) { value = v }
        }
        let box = ResultBox(Self.emptyDetectorResult)
        let queue = DispatchQueue(label: "detector.timeout", qos: .userInitiated)
        queue.async {
            do {
                box.value = try work()
            } catch {
                Logger.log("detector id=\(id.rawValue) threw: \(error)")
                // 故障不是“检测到越狱”：标记为故障，由调用方按连续故障计数决定是否升级。
                box.value = DetectorResult(score: 0, methods: ["detector_fault:\(id.rawValue)"])
            }
            semaphore.signal()
        }
        // 超时即返回故障结果：不阻塞主评估链，也不把卡死误判为高风险。
        let waitResult = semaphore.wait(timeout: .now() + timeout)
        if waitResult == .timedOut {
            Logger.log("detector id=\(id.rawValue) timeout after \(timeout)s")
            return faultResult(for: id, reason: "timeout")
        }
        let result = box.value
        // 后台闭包捕获到异常时会写入 `detector_fault:` 标记，这里统一走故障路径。
        if result.methods.contains(where: { $0.hasPrefix("detector_fault:") }) {
            return faultResult(for: id, reason: "threw", preserving: result)
        }
        // 成功一次即清零该检测器的连续故障计数（与熔断器语义一致）。
        faultLock.withLock { consecutiveDetectorFaults[id] = 0 }
        return result
    }

    /// 检测器故障归一化：单次故障只标记（score 0），连续故障达到阈值才
    /// 升级计分并记录；成功一次即清零连续计数。
    private func faultResult(for id: DetectorID, reason: String, preserving base: DetectorResult? = nil) -> DetectorResult {
        let streak = faultLock.withLock { () -> Int in
            let next = min(consecutiveDetectorFaults[id] ?? 0, Int.max - 1) + 1
            consecutiveDetectorFaults[id] = next
            return next
        }
        Logger.log("detector id=\(id.rawValue) fault (\(reason)), consecutive streak=\(streak) — marked, not scored as jailbreak")
        var methods = base?.methods ?? ["detector_fault:\(id.rawValue)"]
        var score: Double = 0
        if streak >= Self.consecutiveFaultEscalationThreshold {
            score = Self.consecutiveFaultEscalationScore
            methods.append("detector_fault_escalated:\(id.rawValue)")
            Logger.log("detector id=\(id.rawValue) consecutive faults escalated (streak=\(streak), +\(score))")
        }
        return DetectorResult(score: score, methods: methods)
    }

    private static let emptyDetectorResult = DetectorResult.empty

    /// 每次调用生成不同的检测顺序种子，用于随机化调度。
    /// 种子由随机数与当前时间混合，即使 `arc4random_buf` 被 Hook 成常量，
    /// 时间项仍能让每次 `detectV2` 的顺序变化；这直接对抗“攻击者蹲守
    /// AntiTampering 检测窗口”的静态绕过策略。
    private static func detectorOrderSeed() -> UInt64 {
        var raw: UInt64 = 0
        let _ = withUnsafeMutableBytes(of: &raw) { buf in
            arc4random_buf(buf.baseAddress, buf.count)
        }
        // 混入当前时间：即使随机源被替换为常量，调度仍会逐次变化。
        return raw ^ UInt64(Date().timeIntervalSinceReferenceDate.bitPattern)
    }

    /// Canary 检测器：返回固定已知结果。调度循环结束后引擎会校验该结果是否原样返回。
    /// 若攻击者对 `runDetectorWithTimeout` 做“所有调用都返回干净”的批量 Hook，
    /// canary 校验必然失败，从而暴露 Hook。
    private static let canaryExpectedScore: Double = 13.0
    private static let canaryExpectedMethod = "_cprisk_canary_v1"
    /// 构造 canary 闭包；结果必须与 `canaryExpectedScore` / `canaryExpectedMethod` 完全一致。
    private func canaryDetectorClosure() -> () throws -> DetectorResult {
        return {
            DetectorResult(score: Self.canaryExpectedScore, methods: [Self.canaryExpectedMethod])
        }
    }

#if !targetEnvironment(simulator)

    /// 随机调度表中的一条槽位。
    /// 闭包以不透明 thunk 形式在构建槽位时捕获，供 `ResultBox` 路径以 `@escaping` 方式执行。
    private struct DispatchSlot {
        let id: DetectorID
        let work: () throws -> DetectorResult
    }

    /// 根据启用的检测器构建调度槽位数组。
    /// 这里的顺序是“确定性注册顺序”，真正的执行顺序由 `detectV2` 使用
    /// 每次调用独立的随机种子做 Fisher-Yates 洗牌决定。
    private func buildEnabledSlots() -> [DispatchSlot] {
        var slots: [DispatchSlot] = []
        if v2Config.enableAntiTampering {
            slots.append(DispatchSlot(id: .antiTampering) { try AntiTamperingDetector().detect() })
        }
        if v2Config.enableDebugger {
            slots.append(DispatchSlot(id: .debugger) { try DebuggerDetector().detect() })
        }
        if v2Config.enableFrida {
            slots.append(DispatchSlot(id: .frida) { try FridaDetector().detect() })
        }
        if v2Config.enableCodeSignature {
            slots.append(DispatchSlot(id: .codeSignature) { try CodeSignatureValidator().detect() })
        }
        if v2Config.enableMemoryIntegrity {
            slots.append(DispatchSlot(id: .memoryIntegrity) { try MemoryIntegrityChecker().detect() })
        }
        if v2Config.enableDylibInjection {
            slots.append(DispatchSlot(id: .dylibInjection) { try DylibInjectionDetector().detect() })
        }
        // Canary slot is always inserted, regardless of v2Config — its purpose
        // is to detect blanket hooks on the dispatch path. A hook returning
        // "all-clean" for every caller will not produce the expected canary
        // score/method tuple, and the post-loop check will flag the bypass.
        slots.append(DispatchSlot(id: .canary, work: canaryDetectorClosure()))
        return slots
    }

    /// SplitMix64 伪随机数生成器：自行实现调度顺序，避免依赖可被 Hook 的
    /// Foundation 随机 API，同时保证序列可复现（相同种子得到相同顺序）。
    private struct SplitMix64 {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9E37_79B9_7F4A_7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            return z ^ (z >> 31)
        }
        /// 无偏拒绝采样，把随机数映射到 `0..<bound`。
        mutating func bounded(_ bound: Int) -> Int {
            // unbiased rejection sampling
            let b = UInt64(bound)
            let threshold = (0 &- b) % b
            while true {
                let r = next()
                if r >= threshold { return Int(r % b) }
            }
        }
    }

    /// 执行 V2 新增检测：随机顺序 + 逐检测器抖动 + canary 校验 + CRiskCore 跨语言证明。
    ///
    /// 执行顺序：
    /// 1. 构建启用的槽位（canary 恒定存在），用每次调用独立的种子做 Fisher-Yates 洗牌；
    /// 2. 调用 `cprisk_attest_session_begin` 开启本次会话的证明链，生成 16 字节会话 nonce；
    /// 3. 逐个槽位执行：抖动 -> 超时执行 -> 记录证明 -> （canary 只校验不计分）；
    /// 4. `cprisk_attest_session_finalize` 收尾，输出 nonce/count/tag，失败则 fail-closed；
    /// 5. canary 未满足直接 +100，暴露调度层 Hook。
    /// - Parameter baseScore: 旧引擎基础分（当前仅保留形参，计分从 0 开始）。
    /// - Returns: V2 累计分与命中的方法/证明标签。
    private func detectV2(baseScore: Double) -> V2DetectionResult {
        var score: Double = 0
        var methods: [String] = []
        let timeout = detectionTimeoutSeconds

        var slots = buildEnabledSlots()
        // Fisher-Yates 洗牌：种子每次调用不同，攻击者无法预测下一个执行的是哪个检测器。
        var rng = SplitMix64(state: Self.detectorOrderSeed())
        if slots.count > 1 {
            for i in stride(from: slots.count - 1, through: 1, by: -1) {
                let j = rng.bounded(i + 1)
                if i != j { slots.swapAt(i, j) }
            }
        }

        // 开启 CRiskCore 侧证明会话：C 运行时独立把 (id, score, methods_hash)
        // 逐条写入由 WhiteBox PRF 派生的 SHA256 链。只 Hook Swift 调度层会让
        // 链与引擎上报不一致，服务端重放校验即可发现篡改。
        // 16 字节 nonce 标识本次会话，防止跨会话重放证明标签。
        var sessionNonce = [UInt8](repeating: 0, count: 16)
        _ = sessionNonce.withUnsafeMutableBufferPointer { buf in
            cprisk_attest_session_begin(buf.baseAddress)
        }

        var canarySatisfied = false
        for slot in slots {
            // 亚毫秒级抖动（0..<1500 微秒）：让“固定等待 50ms 再执行 AntiTamper”
            // 之类的可观测窗口失效。抖动有上界，保证总延迟仍落在超时预算内。
            let jitterMicros = rng.bounded(1500)
            if jitterMicros > 0 {
                usleep(UInt32(jitterMicros))
            }

            let result = runDetectorWithTimeout(slot.work, id: slot.id, timeout: timeout)

            // 先记录证明、再判断 canary：canary 槽位也必须进入证明链，服务端重放
            // 时必须包含它。攻击者跳过任一槽位的 `cprisk_attest_record`（或整体跳过）
            // 都会得到无法由引擎上报内容重建的 tag。
            recordAttestation(id: slot.id, result: result)

            // canary 只做一致性校验，不参与风险计分；不匹配会在循环后统一加分。
            if slot.id == .canary {
                let scoreOK = abs(result.score - Self.canaryExpectedScore) < 0.0001
                let methodsOK = result.methods == [Self.canaryExpectedMethod]
                if scoreOK && methodsOK {
                    canarySatisfied = true
                }
                continue
            }

            score += result.score
            methods.append(contentsOf: result.methods)
            logV2("d:\(slot.id.rawValue)", result.score, result.methods.count)
        }

        // 收尾 C 侧证明：32 字节 tag 与槽位计数以稳定前缀写入 methods，
        // 服务端关联器无需改协议即可提取；hex 编码以兼容现有 [String] 字段。
        var attestTag = [UInt8](repeating: 0, count: 32)
        var recordedCount: UInt32 = 0
        let finalizeRC = attestTag.withUnsafeMutableBufferPointer { tagBuf in
            cprisk_attest_session_finalize(tagBuf.baseAddress, &recordedCount)
        }
        if finalizeRC == 0 {
            methods.append("attest_nonce:\(Self.hexEncode(sessionNonce))")
            methods.append("attest_count:\(recordedCount)")
            methods.append("attest_tag:\(Self.hexEncode(attestTag))")
        } else {
            // CRiskCore 无法收尾：可能处于早期启动路径，或证明模块本身被恶意 Hook。
            // 按 fail-closed 处理，直接加 50 分并标记不可用。
            methods.append("attest_unavailable")
            score += 50
        }

        // canary 未满足说明调度路径被整体 Hook 或替换；+100 直接压过判决阈值。
        if !canarySatisfied {
            score += 100
            methods.append("dispatch_attest_failed")
        }

        return V2DetectionResult(score: score, methods: methods)
    }

    /// 对检测器方法列表做排序后 SHA256，并写入 C 侧证明链。
    /// 排序是为了归一化顺序，服务端重放时无需猜测各检测器内部的迭代顺序。
    /// - Parameters:
    ///   - id: 检测器数值标识。
    ///   - result: 检测结果；分数会量化为“分”的 Int32 后入链。
    private func recordAttestation(id: DetectorID, result: DetectorResult) {
        let sortedMethods = result.methods.sorted()
        var methodsBlob = Data()
        for m in sortedMethods {
            // 长度前缀编码：即使方法名包含分隔符字节，拼接结果也无歧义。
            var lenLE = UInt32(m.utf8.count).littleEndian
            withUnsafeBytes(of: &lenLE) { methodsBlob.append(contentsOf: $0) }
            methodsBlob.append(Data(m.utf8))
        }
        let hash = SHA256.hash(data: methodsBlob)
        let hashBytes = Array(hash)

        // Swift 侧分数是 Double；量化为“分”的整数，给 C 侧稳定的 int32 表示。
        // 手动夹紧是因为 Int32(_) 在溢出时会触发运行时陷阱。
        let cents = result.score.rounded() * 100
        let clamped: Int32
        if cents > Double(Int32.max) {
            clamped = Int32.max
        } else if cents < Double(Int32.min) {
            clamped = Int32.min
        } else {
            clamped = Int32(cents)
        }
        hashBytes.withUnsafeBufferPointer { buf in
            cprisk_attest_record(id.rawValue, clamped, buf.baseAddress)
        }
    }

    /// 小写十六进制编码，用于把 nonce/tag 嵌入可上报的字符串字段。
    private static func hexEncode(_ bytes: [UInt8]) -> String {
        let hexChars: [Character] = Array("0123456789abcdef")
        var out = String()
        out.reserveCapacity(bytes.count * 2)
        for b in bytes {
            out.append(hexChars[Int(b >> 4)])
            out.append(hexChars[Int(b & 0x0F)])
        }
        return out
    }

#endif
    
    /// 处理模拟器环境：真机检测器无法运行，返回 `unavailable`。
    /// DEBUG 下可通过环境变量 `CPRISK_SIMULATE_JAILBREAK=1` 注入越狱结果用于联调。
    private func handleSimulator(config: JailbreakConfig) -> DetectionResult {
        #if DEBUG
        let simulate = ProcessInfo.processInfo.environment["CPRISK_SIMULATE_JAILBREAK"] == "1"
        if simulate {
            return DetectionResult(
                isJailbroken: true,
                confidence: 100,
                detectedMethods: ["simulated:simulator"],
                details: "simulated_jailbreak"
            )
        }
        #endif
        
        return DetectionResult(
            isJailbroken: false,
            confidence: 0,
            detectedMethods: ["unavailable_simulator"],
            details: "simulator_environment",
            unavailable: true
        )
    }
    
    /// 构建可上报的详情字符串：总分、旧引擎分、V2 分与最多 20 个方法名。
    private func buildDetails(
        score: Double,
        methods: [String],
        legacyScore: Double,
        v2Score: Double
    ) -> String {
        """
        total_score=\(score)
        legacy_score=\(legacyScore)
        v2_score=\(v2Score)
        methods_hit=\(methods.count)
        methods=\(methods.prefix(20).joined(separator: ","))
        """
    }
    
    /// V2 日志输出；仅在 `verboseLogging` 开启时写入，避免默认日志暴露检测节奏。
    private func logV2(_ detector: String, _ score: Double, _ count: Int) {
        if v2Config.verboseLogging {
            Logger.log("JailbreakEngineV2.\(detector): score=\(score), hits=\(count)")
        }
    }
}

// MARK: - 结果类型

/// V2 检测结果：新增检测器的累计分与证据标签。
private struct V2DetectionResult {
    let score: Double
    let methods: [String]
}

/// 快速检测结果
public struct QuickDetectionResult {
    /// 是否存在风险
    public let isRisky: Bool
    
    /// 风险等级
    public let riskLevel: RiskLevel
    
    /// 检测到的风险类别
    public let detectedCategories: [String]

    /// 检测是否实际不可用（模拟器上检测器无法运行）。
    /// 与 `DetectionResult.unavailable` 同义：`true` 表示“未检测”，
    /// 不得当作干净设备采信。默认 `false`。
    public let unavailable: Bool

    public init(isRisky: Bool, riskLevel: RiskLevel, detectedCategories: [String], unavailable: Bool = false) {
        self.isRisky = isRisky
        self.riskLevel = riskLevel
        self.detectedCategories = detectedCategories
        self.unavailable = unavailable
    }
    
    /// 快速检测的风险等级。
    public enum RiskLevel {
        case none
        case low
        case medium
        case high

        /// 按累计分数分级：0–10 无风险、10–30 低、30–60 中、60 以上高。
        public static func from(score: Double) -> RiskLevel {
            switch score {
            case 0..<10: return .none
            case 10..<30: return .low
            case 30..<60: return .medium
            default: return .high
            }
        }
    }
}

/// 检测器状态快照：各开关是否启用，以及汇总计数。
public struct DetectorStatus {
    public var antiTampering: Bool = false
    public var debugger: Bool = false
    public var frida: Bool = false
    public var codeSignature: Bool = false
    public var memoryIntegrity: Bool = false
    public var dylibInjection: Bool = false
    
    /// 启用的检测器数量
    public var enabledCount: Int {
        var count = 0
        if antiTampering { count += 1 }
        if debugger { count += 1 }
        if frida { count += 1 }
        if codeSignature { count += 1 }
        if memoryIntegrity { count += 1 }
        if dylibInjection { count += 1 }
        return count
    }
    
    /// 是否启用了所有检测器
    public var isFullyEnabled: Bool {
        antiTampering && debugger && frida && codeSignature && memoryIntegrity && dylibInjection
    }
}

// MARK: - 向后兼容扩展

extension JailbreakConfig {
    
    /// 同时创建旧版越狱配置与 V2 引擎配置的便捷入口。
    /// - Returns: `(JailbreakConfig, V2Config)` 元组，旧配置默认启用全部越狱路径。
    public static func v2(
        threshold: Double = 30,
        v2Config: JailbreakEngineV2.V2Config = .default
    ) -> (JailbreakConfig, JailbreakEngineV2.V2Config) {
        let jailbreakConfig = JailbreakConfig(
            enableFileDetect: true,
            enableDyldDetect: true,
            enableEnvDetect: true,
            enableSysctlDetect: true,
            enableSchemeDetect: true,
            enableHookDetect: true,
            threshold: threshold
        )
        
        return (jailbreakConfig, v2Config)
    }
}

// MARK: - 使用示例

// MARK: - 使用示例
//
// ### 1. 基本使用（向后兼容）
// ```swift
// let engine = JailbreakEngineV2()
// let result = engine.detect(config: .default)
// if result.isJailbroken {
//     // 处理越狱设备
// }
// ```
//
// ### 2. 使用 V2 配置
// ```swift
// let v2Config = JailbreakEngineV2.V2Config.strict
// let engine = JailbreakEngineV2(v2Config: v2Config)
// let result = engine.detect(config: .default)
// ```
//
// ### 3. 快速检测
// ```swift
// let engine = JailbreakEngineV2()
// let quickResult = engine.quickDetect()
// if quickResult.isRisky {
//     // 处理风险设备
// }
// ```
//
// ### 4. 检查检测器状态
// ```swift
// let engine = JailbreakEngineV2()
// let status = engine.detectorStatus()
// print("启用了 \(status.enabledCount) 个检测器")
// ```
