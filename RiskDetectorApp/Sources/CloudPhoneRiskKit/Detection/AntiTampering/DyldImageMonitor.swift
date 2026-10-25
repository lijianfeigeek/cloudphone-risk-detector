// DyldImageMonitor：持续监听 dyld 镜像增删，识别运行期 dylib 注入与痕迹清理。
// 参考 Frida 17.8 的 map_gen 思路：每次镜像加载都会推进 generation 计数。
// 通过基线比较发现“基线后加载可疑库”“gen 跳变”“镜像数量减少”“hash 静默变化”。
// 与一次性镜像枚举检测互补，能捕获检测启动之后发生的注入。
import Darwin
import Foundation
import MachO

/// Continuous dylib monitoring inspired by Frida 17.8.0's `map_gen` mechanism.
///
/// Tracks a generation counter (`dyldGen`) that increments on every image add/remove,
/// records a baseline at `start()`, and detects anomalies at `evaluate()`:
/// - Suspicious libraries injected after baseline
/// - Generation counter jumps (image loaded then unloaded to hide traces)
/// - Image count decrease (removal to evade detection)
/// 运行期 dyld 镜像监视器。
/// - 线程模型：`_dyld_register_func_for_add_image` 回调可能在任意线程触发，
///   状态由 UnfairLock 保护；标记为 `@unchecked Sendable` 由锁保证安全。
final class DyldImageMonitor: @unchecked Sendable {
    // 进程级单例，保证基线只建立一次。
    static let shared = DyldImageMonitor()

    /// 监视器内部状态。
    private struct State {
        // dyld generation 计数，每次 add image 回调递增。
        var dyldGen: UInt64 = 0
        // 基线时的镜像数量。
        var baselineImageCount: UInt32 = 0
        // 基线时的镜像列表哈希。
        var baselineImageHash: UInt64 = 0
        // 基线建立完成时的 generation。
        var baselineDyldGen: UInt64 = 0
        // 是否已 start。
        var isStarted = false
        // add image 回调累计次数（含注册时的同步回调）。
        var addImageCallbackCount: UInt32 = 0
        // 基线后加载的可疑镜像及对应 generation。
        var suspiciousAdditions: [(name: String, gen: UInt64)] = []
    }
    // 保护 state 的锁。
    private let stateLock = UnfairLock()
    // 受锁保护的状态。
    private var state = State()

    // 从动态特征列表读取可疑库 token。
    private var suspiciousTokens: [String] {
        DynamicFeatureList.shared.suspiciousLibraries
    }

    /// 私有初始化，单例由 shared 提供。
    private init() {}

    // MARK: - Lifecycle

    /// 注册 add image 回调并记录基线。
    func start() {
    // 模拟器行为不同，跳过。
    #if targetEnvironment(simulator)
        return
    #else
        // 幂等：重复 start 不重复注册。
        let shouldRegister = stateLock.withLock { () -> Bool in
            guard !state.isStarted else { return false }
            state.isStarted = true
            // 记录基线数量、列表哈希与当前 generation。
            state.baselineImageCount = _dyld_image_count()
            state.baselineImageHash = computeImageListHash()
            state.baselineDyldGen = state.dyldGen
            return true
        }
        guard shouldRegister else { return }

        // dyld 会同步回调所有已加载镜像；这些回调属于基线，不计为注入。
        _dyld_register_func_for_add_image { mh, slide in
            DyldImageMonitor.shared.onImageAdded(mh, slide: slide)
        }

        // 回调返回后 generation 已累加完毕，重新记录基线 gen。
        // dyld 同步为每个已加载 image 调用回调，返回时 dyldGen 已累加完毕
        stateLock.withLock {
            state.baselineDyldGen = state.dyldGen
        }
    #endif
    }

    // MARK: - Callback

    /// add image 回调：递增计数，基线后的新镜像解析名称并检查可疑 token。
    private func onImageAdded(_ mh: UnsafePointer<mach_header>?, slide: Int) {
        // First: fast path under lock — increment counters and decide if we need name resolution
        // 锁内只做计数，避免持锁做路径解析。
        let needsNameResolution = stateLock.withLock { () -> (Bool, UInt64) in
            // generation 递增（溢出回绕由 &+ 处理）。
            state.dyldGen &+= 1
            state.addImageCallbackCount &+= 1

            guard state.isStarted else { return (false, state.dyldGen) }
            // 基线加载阶段的回调不计入注入。
            if state.addImageCallbackCount <= state.baselineImageCount { return (false, state.dyldGen) }
            return (true, state.dyldGen)
        }

        guard needsNameResolution.0 else { return }

        // Resolve image name OUTSIDE the lock (O(n) iteration over loaded images)
        // 锁外解析镜像名：O(n) 遍历已加载镜像，不能持锁。
        let imageName = resolveImageName(for: mh)
        guard let imageName, !imageName.isEmpty else { return }

        let lower = imageName.lowercased()
        // 仅记录基线后加载的可疑库。
        let isSuspicious = suspiciousTokens.contains { lower.contains($0) }
        if isSuspicious {
            stateLock.withLock {
                state.suspiciousAdditions.append((name: imageName, gen: needsNameResolution.1))
            }
        }
    }

    // MARK: - Evaluate

    /// 评估当前状态，输出注入/跳变/卸载/静默变化四类异常。
    func evaluate() -> DetectorResult {
    #if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["dyld_monitor:unavailable_simulator"])
    #else
        // 取状态快照后释放锁，后续遍历不再持锁。
        let snapshot = stateLock.withLock { () -> (gen: UInt64, baseGen: UInt64, baseCount: UInt32, baseHash: UInt64, additions: [(name: String, gen: UInt64)])? in
            guard state.isStarted else { return nil }
            return (state.dyldGen, state.baselineDyldGen, state.baselineImageCount, state.baselineImageHash, state.suspiciousAdditions)
        }
        // 尚未 start，无法判断。
        guard let snapshot else { return DetectorResult(score: 0, methods: ["dyld_monitor:not_started"]) }

        var score: Double = 0
        var methods: [String] = []

        // 1. Suspicious libraries loaded after baseline
        // 1. 基线后加载了可疑库，每条 70 分。
        for entry in snapshot.additions {
            score += 70
            methods.append("dyld_monitor:suspicious_load:\(entry.name):gen=\(entry.gen)")
        }

        // 2. Generation jump: images added since baseline beyond visible suspicious set
        // 2. generation 跳变：新增镜像数远多于可见可疑库。
        let genDelta = snapshot.gen &- snapshot.baseGen
        let visibleNewCount = UInt64(snapshot.additions.count)
        // 允许多出 2 次回调的噪声，超过则说明有镜像被加载后隐藏。
        if genDelta > visibleNewCount &+ 2 {
            score += 50
            methods.append(
                "dyld_monitor:gen_jump:delta=\(genDelta):visible=\(visibleNewCount)"
            )
        }

        // 3. Image count decreased (unloaded to hide)
        // 3. 镜像数量减少：攻击者卸载镜像以清除痕迹。
        let currentCount = _dyld_image_count()
        if currentCount < snapshot.baseCount {
            score += 40
            methods.append(
                "dyld_monitor:count_decrease:baseline=\(snapshot.baseCount):current=\(currentCount)"
            )
        }

        // 4. Image list hash divergence without any gen change recorded (deep tampering)
        // 4. 列表 hash 变化但 gen 未变：说明 dyld 状态被静默篡改。
        let currentHash = computeImageListHash()
        if currentHash != snapshot.baseHash && genDelta == 0 {
            score += 50
            methods.append("dyld_monitor:hash_divergence_silent")
        }

        // 总分封顶 100。
        return DetectorResult(score: min(score, 100), methods: methods)
    #endif
    }

    // MARK: - Helpers

    /// 根据 mach_header 反查镜像路径。
    private func resolveImageName(for mh: UnsafePointer<mach_header>?) -> String? {
        guard mh != nil else { return nil }
        let count = _dyld_image_count()
        for i in 0..<count {
            if _dyld_get_image_header(i) == mh, let cName = _dyld_get_image_name(i) {
                return String(cString: cName)
            }
        }
        return nil
    }

    /// 计算镜像列表的 FNV-1a 哈希，用于检测静默变化。
    private func computeImageListHash() -> UInt64 {
        // FNV-1a offset basis。
        var hash: UInt64 = 14695981039346656037 // FNV-1a offset basis
        let count = _dyld_image_count()
        let maxPathLen = 256
        for i in 0..<count {
            guard let cName = _dyld_get_image_name(i) else { continue }
            var ptr = cName
            var left = maxPathLen
            while left > 0 && ptr.pointee != 0 {
                hash ^= UInt64(UInt8(bitPattern: ptr.pointee))
                // FNV-1a prime。
                hash &*= 1099511628211 // FNV-1a prime
                ptr = ptr.advanced(by: 1)
                left -= 1
            }
            // 用 0xFF 作为路径分隔符参与哈希，避免路径拼接歧义。
            hash ^= 0xFF
            hash &*= 1099511628211
        }
        return hash
    }
}

// MARK: - Detector Conformance

/// Detector 协议适配：直接返回 evaluate 结果。
extension DyldImageMonitor: Detector {
    /// 执行评估。
    func detect() throws -> DetectorResult {
        return evaluate()
    }
}

// MARK: - RiskSignal Conversion

/// 信号转换：四类异常分别成信号。
extension DyldImageMonitor {
    /// 可疑注入为 tampered；gen 跳变/卸载/静默变化同样为 tampered。
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        // 可疑库注入信号，每条 70 分。
        let suspiciousLoads = result.methods.filter { $0.contains("suspicious_load") }
        if !suspiciousLoads.isEmpty {
            signals.append(RiskSignal(
                id: "dyld_monitor_suspicious_injection",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(suspiciousLoads.count) * 70, 100),
                evidence: ["detail": suspiciousLoads.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 90
            ))
        }

        // generation 跳变信号，固定 50 分。
        let genJumps = result.methods.filter { $0.contains("gen_jump") }
        if !genJumps.isEmpty {
            signals.append(RiskSignal(
                id: "dyld_monitor_gen_anomaly",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 50,
                evidence: ["detail": genJumps.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 80
            ))
        }

        // 镜像数量减少信号，固定 40 分。
        let countDecreases = result.methods.filter { $0.contains("count_decrease") }
        if !countDecreases.isEmpty {
            signals.append(RiskSignal(
                id: "dyld_monitor_image_removed",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 40,
                evidence: ["detail": countDecreases.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 75
            ))
        }

        // 静默 hash 变化信号，固定 50 分。
        let hashDivergences = result.methods.filter { $0.contains("hash_divergence") }
        if !hashDivergences.isEmpty {
            signals.append(RiskSignal(
                id: "dyld_monitor_silent_mutation",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 50,
                evidence: ["detail": hashDivergences.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 85
            ))
        }

        return signals
    }
}
