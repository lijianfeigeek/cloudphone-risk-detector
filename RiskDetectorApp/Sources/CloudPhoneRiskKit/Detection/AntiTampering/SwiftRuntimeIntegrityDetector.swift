// SwiftRuntimeIntegrityDetector：校验 Swift 运行时元数据、协议 witness、
// closure 上下文与 existential 容器的内部一致性，识别对 Swift 运行时的篡改。
// 攻击者 hook Swift 方法/替换 witness table 时，反射、分发结果或指针归属会出现异常。
// 四类探针各自独立评分，任一异常产生 soft/tampered 信号。
import Darwin
import Foundation

/// Swift 运行时完整性检测器。
/// - 线程模型：同步自检；`snapshotOverride` 供测试注入快照。
/// - 安全不变量：探针类型与指针分类均在本进程内完成，不依赖外部服务。
struct SwiftRuntimeIntegrityDetector: Detector {
    // 四条独立信号 id：元数据、协议 witness、closure 上下文、existential 容器。
    static let detectorID = "swift_runtime_integrity"
    static let metadataSignalID = "swift_metadata_integrity"
    static let witnessSignalID = "swift_protocol_witness_integrity"
    static let closureSignalID = "swift_closure_context_integrity"
    static let existentialSignalID = "swift_existential_container_integrity"

    /// 四类探针的快照集合。
    struct Snapshot {
        let metadata: MetadataSnapshot
        let witness: WitnessSnapshot
        let closure: ClosureSnapshot
        let existential: ExistentialSnapshot
    }

    /// Swift 元数据探针结果。
    struct MetadataSnapshot {
        let inspectedTypeCount: Int
        let reflectionMismatchCount: Int
        // 检查过的类型数、反射不一致数、可疑指针数及指针归属分桶。
        let suspiciousPointerCount: Int
        let pointerLocalityBuckets: [String: Int]
    }

    /// 协议 witness 探针结果。
    struct WitnessSnapshot {
        let sampleCount: Int
        let dispatchMismatchCount: Int
        // 分发结果不一致数、可疑指针数、非镜像可执行指针数及归属分桶。
        let suspiciousPointerCount: Int
        let nonImageExecutablePointerCount: Int
        let pointerLocalityBuckets: [String: Int]
    }

    /// closure 上下文探针结果。
    struct ClosureSnapshot {
        let sampleCount: Int
        let canaryMismatchCount: Int
        // canary 不一致、布局异常、地址不稳定计数，以及函数/上下文指针归属。
        let layoutAnomalyCount: Int
        let unstableAddressCount: Int
        let functionPointerLocality: String
        let contextPointerLocality: String
    }

    /// existential 容器探针结果。
    struct ExistentialSnapshot {
        let sampleCount: Int
        let dynamicTypeMismatchCount: Int
        // 动态类型不一致数、指针异常数及归属分桶。
        let pointerAnomalyCount: Int
        let pointerLocalityBuckets: [String: Int]
    }

    /// 四类探针的评分汇总。
    struct Assessment {
        let score: Double
        let metadataScore: Double
        let witnessScore: Double
        let closureScore: Double
        let existentialScore: Double
        let methods: [String]
    }

    // 测试注入的快照；nil 时现场采集。
    private let snapshotOverride: Snapshot?

    /// 初始化；默认现场采集，测试可传入固定快照。
    init(snapshotOverride: Snapshot? = nil) {
        self.snapshotOverride = snapshotOverride
    }

    /// 执行检测并返回汇总分数/方法。
    func detect() throws -> DetectorResult {
        let snapshot = resolvedSnapshot()
        let assessment = assess(snapshot: snapshot)
        return DetectorResult(score: assessment.score, methods: assessment.methods)
    }

    /// 转换为 RiskSignal：每类异常分桶一条信号。
    func asSignals() -> [RiskSignal] {
        let snapshot = resolvedSnapshot()
        let assessment = assess(snapshot: snapshot)
        guard assessment.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        // 元数据异常：反射不一致或类型元数据指针不在预期区域。
        if assessment.metadataScore > 0 {
            let anomalyCount = snapshot.metadata.reflectionMismatchCount + snapshot.metadata.suspiciousPointerCount
            signals.append(RiskSignal(
                id: Self.metadataSignalID,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: assessment.metadataScore,
                evidence: [
                    "mechanism": "swift_metadata_consistency",
                    "anomaly_count": "\(anomalyCount)",
                    "reflection_mismatch_count": "\(snapshot.metadata.reflectionMismatchCount)",
                    "suspicious_pointer_count": "\(snapshot.metadata.suspiciousPointerCount)",
                    "pointer_locality": formatBuckets(snapshot.metadata.pointerLocalityBuckets),
                    "inspected_type_count": "\(snapshot.metadata.inspectedTypeCount)",
                ],
                // 分数 >=40 直接 tampered，否则 soft（反射差异可能来自运行时版本）。
                state: assessment.metadataScore >= 40 ? .tampered : .soft(confidence: 0.62),
                layer: 2,
                weightHint: min(assessment.metadataScore + 20, 90)
            ))
        }

        // witness 异常：分发结果不一致或 witness 指针异常。
        if assessment.witnessScore > 0 {
            let anomalyCount = snapshot.witness.dispatchMismatchCount
                + snapshot.witness.suspiciousPointerCount
                + snapshot.witness.nonImageExecutablePointerCount
            signals.append(RiskSignal(
                id: Self.witnessSignalID,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: assessment.witnessScore,
                evidence: [
                    "mechanism": "swift_protocol_witness_consistency",
                    "anomaly_count": "\(anomalyCount)",
                    "dispatch_mismatch_count": "\(snapshot.witness.dispatchMismatchCount)",
                    "suspicious_pointer_count": "\(snapshot.witness.suspiciousPointerCount)",
                    "non_image_executable_pointer_count": "\(snapshot.witness.nonImageExecutablePointerCount)",
                    "pointer_locality": formatBuckets(snapshot.witness.pointerLocalityBuckets),
                    "sample_count": "\(snapshot.witness.sampleCount)",
                ],
                // 分数 >=45 判 tampered。
                state: assessment.witnessScore >= 45 ? .tampered : .soft(confidence: 0.66),
                layer: 2,
                weightHint: min(assessment.witnessScore + 22, 92)
            ))
        }

        // closure 异常：canary 不匹配、布局异常或上下文地址不稳定。
        if assessment.closureScore > 0 {
            let anomalyCount = snapshot.closure.canaryMismatchCount
                + snapshot.closure.layoutAnomalyCount
                + snapshot.closure.unstableAddressCount
            signals.append(RiskSignal(
                id: Self.closureSignalID,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: assessment.closureScore,
                evidence: [
                    "mechanism": "swift_closure_context_integrity",
                    "anomaly_count": "\(anomalyCount)",
                    "canary_mismatch_count": "\(snapshot.closure.canaryMismatchCount)",
                    "layout_anomaly_count": "\(snapshot.closure.layoutAnomalyCount)",
                    "unstable_address_count": "\(snapshot.closure.unstableAddressCount)",
                    "pointer_locality": "function=\(snapshot.closure.functionPointerLocality),context=\(snapshot.closure.contextPointerLocality)",
                    "sample_count": "\(snapshot.closure.sampleCount)",
                ],
                // 分数 >=40 判 tampered。
                state: assessment.closureScore >= 40 ? .tampered : .soft(confidence: 0.64),
                layer: 2,
                weightHint: min(assessment.closureScore + 20, 88)
            ))
        }

        // existential 异常：动态类型不匹配或容器指针异常。
        if assessment.existentialScore > 0 {
            let anomalyCount = snapshot.existential.dynamicTypeMismatchCount
                + snapshot.existential.pointerAnomalyCount
            signals.append(RiskSignal(
                id: Self.existentialSignalID,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: assessment.existentialScore,
                evidence: [
                    "mechanism": "swift_existential_container_sanity",
                    "anomaly_count": "\(anomalyCount)",
                    "dynamic_type_mismatch_count": "\(snapshot.existential.dynamicTypeMismatchCount)",
                    "pointer_anomaly_count": "\(snapshot.existential.pointerAnomalyCount)",
                    "pointer_locality": formatBuckets(snapshot.existential.pointerLocalityBuckets),
                    "sample_count": "\(snapshot.existential.sampleCount)",
                ],
                // 分数 >=38 判 tampered。
                state: assessment.existentialScore >= 38 ? .tampered : .soft(confidence: 0.63),
                layer: 2,
                weightHint: min(assessment.existentialScore + 18, 84)
            ))
        }

        return signals
    }

    /// 返回注入快照或现场采集的快照。
    private func resolvedSnapshot() -> Snapshot {
        if let override = snapshotOverride {
            return override
        }
        return collectSnapshot()
    }

    /// 根据快照计算四类分数与方法列表。
    func assess(snapshot: Snapshot) -> Assessment {
        var methods: [String] = []
        var metadataScore: Double = 0
        var witnessScore: Double = 0
        var closureScore: Double = 0
        var existentialScore: Double = 0

        if snapshot.metadata.reflectionMismatchCount > 0 {
            // 反射不一致：每项 +12，封顶 44。
            metadataScore += min(18 + Double(snapshot.metadata.reflectionMismatchCount) * 12, 44)
            methods.append("swift_runtime:metadata:reflection_mismatch:\(snapshot.metadata.reflectionMismatchCount)")
        }
        if snapshot.metadata.suspiciousPointerCount > 0 {
            // 元数据类型指针异常：每项 +8，封顶 26。
            metadataScore += min(10 + Double(snapshot.metadata.suspiciousPointerCount) * 8, 26)
            methods.append("swift_runtime:metadata:pointer_suspicious:\(snapshot.metadata.suspiciousPointerCount)")
        }

        if snapshot.witness.dispatchMismatchCount > 0 {
            // witness 分发不一致：每项 +14，封顶 52。
            witnessScore += min(20 + Double(snapshot.witness.dispatchMismatchCount) * 14, 52)
            methods.append("swift_runtime:witness:dispatch_mismatch:\(snapshot.witness.dispatchMismatchCount)")
        }
        if snapshot.witness.suspiciousPointerCount > 0 {
            // witness 可疑指针：每项 +10，封顶 34。
            witnessScore += min(10 + Double(snapshot.witness.suspiciousPointerCount) * 10, 34)
            methods.append("swift_runtime:witness:pointer_suspicious:\(snapshot.witness.suspiciousPointerCount)")
        }
        if snapshot.witness.nonImageExecutablePointerCount > 0 {
            // witness 非镜像可执行指针：每项 +9，封顶 28。
            witnessScore += min(8 + Double(snapshot.witness.nonImageExecutablePointerCount) * 9, 28)
            methods.append("swift_runtime:witness:pointer_non_image_exec:\(snapshot.witness.nonImageExecutablePointerCount)")
        }

        if snapshot.closure.canaryMismatchCount > 0 {
            // closure canary 不一致：每项 +14，封顶 54（最强证据）。
            closureScore += min(24 + Double(snapshot.closure.canaryMismatchCount) * 14, 54)
            methods.append("swift_runtime:closure:canary_mismatch:\(snapshot.closure.canaryMismatchCount)")
        }
        if snapshot.closure.layoutAnomalyCount > 0 {
            // closure 布局异常：每项 +10，封顶 28。
            closureScore += min(12 + Double(snapshot.closure.layoutAnomalyCount) * 10, 28)
            methods.append("swift_runtime:closure:layout_anomaly:\(snapshot.closure.layoutAnomalyCount)")
        }
        if snapshot.closure.unstableAddressCount > 0 {
            // closure 上下文地址不稳定：每项 +8，封顶 24。
            closureScore += min(10 + Double(snapshot.closure.unstableAddressCount) * 8, 24)
            methods.append("swift_runtime:closure:address_unstable:\(snapshot.closure.unstableAddressCount)")
        }

        // 函数指针不在镜像可执行区：+6。
        if snapshot.closure.functionPointerLocality != PointerLocality.imageExecutable.rawValue {
            closureScore += 6
            methods.append("swift_runtime:closure:function_pointer_locality:\(snapshot.closure.functionPointerLocality)")
        }
        // 上下文指针位于匿名可执行/未知区：+8。
        if snapshot.closure.contextPointerLocality == PointerLocality.anonymousExecutable.rawValue
            || snapshot.closure.contextPointerLocality == PointerLocality.unknown.rawValue {
            closureScore += 8
            methods.append("swift_runtime:closure:context_pointer_locality:\(snapshot.closure.contextPointerLocality)")
        }

        if snapshot.existential.dynamicTypeMismatchCount > 0 {
            // existential 动态类型不一致：每项 +12，封顶 46。
            existentialScore += min(18 + Double(snapshot.existential.dynamicTypeMismatchCount) * 12, 46)
            methods.append("swift_runtime:existential:dynamic_type_mismatch:\(snapshot.existential.dynamicTypeMismatchCount)")
        }
        if snapshot.existential.pointerAnomalyCount > 0 {
            // existential 指针异常：每项 +8，封顶 28。
            existentialScore += min(10 + Double(snapshot.existential.pointerAnomalyCount) * 8, 28)
            methods.append("swift_runtime:existential:pointer_anomaly:\(snapshot.existential.pointerAnomalyCount)")
        }

        // 总分封顶 95；各类分数在返回时再分别封顶。
        let total = min(metadataScore + witnessScore + closureScore + existentialScore, 95)
        return Assessment(
            score: total,
            metadataScore: min(metadataScore, 48),
            witnessScore: min(witnessScore, 56),
            closureScore: min(closureScore, 56),
            existentialScore: min(existentialScore, 48),
            methods: methods
        )
    }

    /// 现场采集四类快照。
    private func collectSnapshot() -> Snapshot {
        Snapshot(
            metadata: collectMetadataSnapshot(),
            witness: collectWitnessSnapshot(),
            closure: collectClosureSnapshot(),
            existential: collectExistentialSnapshot()
        )
    }

    /// 元数据探针：用 Mirror 检查结构一致性，并分类类型元数据指针。
    private func collectMetadataSnapshot() -> MetadataSnapshot {
        // 构造 sentinel 值并用 existential 擦除，比较反射结果。
        let sentinel = MetadataSentinel(counter: 7, label: "runtime")
        let erased: Any = sentinel
        var reflectionMismatchCount = 0
        // 结构体直接反射与 existential 反射的子项数应一致。
        if Mirror(reflecting: sentinel).children.count != Mirror(reflecting: erased).children.count {
            reflectionMismatchCount += 1
        }
        if Mirror(reflecting: (sentinel.counter, sentinel.label)).children.count != 2 {
            reflectionMismatchCount += 1
        }

        // 对三个探针类型的元数据指针做归属分类。
        let types: [Any.Type] = [
            MetadataSentinel.self,
            WitnessProbeImpl.self,
            ClosureCanaryBox.self,
        ]
        var suspiciousPointerCount = 0
        var pointerLocalityBuckets: [String: Int] = [:]
        for item in types {
            let pointer = unsafeBitCast(item, to: UnsafeRawPointer.self)
            let locality = classifyPointer(pointer)
            pointerLocalityBuckets[locality.rawValue, default: 0] += 1
            // 未知/匿名可执行指针说明元数据被替换或伪造。
            if locality == .unknown || locality == .anonymousExecutable {
                suspiciousPointerCount += 1
            }
        }

        return MetadataSnapshot(
            inspectedTypeCount: types.count,
            reflectionMismatchCount: reflectionMismatchCount,
            suspiciousPointerCount: suspiciousPointerCount,
            pointerLocalityBuckets: pointerLocalityBuckets
        )
    }

    /// 协议 witness 探针：比较直接调用、泛型分发与 existential 分发。
    private func collectWitnessSnapshot() -> WitnessSnapshot {
        // 三条调用路径应返回同一结果；不一致说明 witness table 被改写。
        let impl = WitnessProbeImpl(base: 0x5A17_C3D2)
        let existential: any RuntimeWitnessProbe = impl
        let seeds: [UInt64] = [1, 7, 19, 37, 61]
        var dispatchMismatchCount = 0

        // 任一路径结果不同即记一次 dispatch mismatch。
        for seed in seeds {
            let direct = impl.dispatchFingerprint(seed: seed)
            let generic = dispatchThroughGeneric(impl, seed: seed)
            let protocolCall = existential.dispatchFingerprint(seed: seed)
            if direct != generic || direct != protocolCall {
                dispatchMismatchCount += 1
            }
        }

        // 读取 existential 容器末尾的两个指针作为 witness 候选。
        let pointerWords = witnessCandidatePointers(from: existential)
        var suspiciousPointerCount = 0
        var nonImageExecutablePointerCount = 0
        var pointerLocalityBuckets: [String: Int] = [:]
        for pointer in pointerWords {
            let locality = classifyPointer(pointer)
            pointerLocalityBuckets[locality.rawValue, default: 0] += 1
            // 未知/匿名指针视为可疑。
            if locality == .unknown || locality == .anonymousExecutable || locality == .anonymousData {
                suspiciousPointerCount += 1
            }
            if locality == .anonymousExecutable || locality == .unknown {
                nonImageExecutablePointerCount += 1
            }
        }

        return WitnessSnapshot(
            sampleCount: seeds.count,
            dispatchMismatchCount: dispatchMismatchCount,
            suspiciousPointerCount: suspiciousPointerCount,
            nonImageExecutablePointerCount: nonImageExecutablePointerCount,
            pointerLocalityBuckets: pointerLocalityBuckets
        )
    }

    /// existential 探针：检查动态类型与调用结果一致性。
    private func collectExistentialSnapshot() -> ExistentialSnapshot {
        let concrete = ExistentialProbeImpl(seed: 0xD55E_A1B2_3319_7744)
        let existential: any RuntimeExistentialProbe = concrete
        let seeds: [UInt64] = [3, 9, 27, 81]

        var dynamicTypeMismatchCount = 0
        // 动态类型应等于具体实现类型，否则 existential 容器被篡改。
        if String(reflecting: type(of: existential)) != String(reflecting: ExistentialProbeImpl.self) {
            dynamicTypeMismatchCount += 1
        }
        for seed in seeds {
            if existential.stableMarker(seed: seed) != concrete.stableMarker(seed: seed) {
                dynamicTypeMismatchCount += 1
            }
        }

        // 读取 existential 容器尾部指针。
        let pointerWords: [UnsafeRawPointer] = withUnsafeBytes(of: existential) { raw in
            let words = raw.bindMemory(to: UInt.self)
            guard words.count >= 2 else { return [] }
            return [words[words.count - 2], words[words.count - 1]].compactMap { value in
                guard value > 0x1000 else { return nil }
                return UnsafeRawPointer(bitPattern: value)
            }
        }

        var pointerAnomalyCount = 0
        var pointerLocalityBuckets: [String: Int] = [:]
        for pointer in pointerWords {
            let locality = classifyPointer(pointer)
            pointerLocalityBuckets[locality.rawValue, default: 0] += 1
            if locality == .unknown || locality == .anonymousExecutable {
                pointerAnomalyCount += 1
            }
        }

        return ExistentialSnapshot(
            sampleCount: seeds.count,
            dynamicTypeMismatchCount: dynamicTypeMismatchCount,
            pointerAnomalyCount: pointerAnomalyCount,
            pointerLocalityBuckets: pointerLocalityBuckets
        )
    }

    /// closure 探针：检查 canary 计算结果与 closure 内存布局。
    private func collectClosureSnapshot() -> ClosureSnapshot {
        // 固定 canary 与向量，任何运行时替换都会导致结果不一致。
        let box = ClosureCanaryBox(canary: 0xA91C_D35F_7123_44EF, vector: [3, 5, 8, 13, 21])
        let closure: (UInt64) -> UInt64 = { [box] seed in
            Self.closureDigest(canary: box.canary, vector: box.vector, seed: seed)
        }
        let closureCopyA = closure
        let closureCopyB = closure

        // closure 布局：word0 为函数指针，word1 为捕获上下文指针。
        let functionPointer = closureWord(closure, index: 0)
        let contextPointers = [
            closureWord(closure, index: 1),
            closureWord(closureCopyA, index: 1),
            closureWord(closureCopyB, index: 1),
        ]
        let nonNilContextPointers = contextPointers.compactMap { $0 }

        // 用相同输入重算 canary，验证 closure 未被替换。
        var canaryMismatchCount = 0
        let seeds: [UInt64] = [2, 11, 23, 47]
        for seed in seeds {
            let actual = closure(seed)
            let expected = Self.closureDigest(canary: box.canary, vector: box.vector, seed: seed)
            if actual != expected {
                canaryMismatchCount += 1
            }
        }

        // 函数指针缺失或上下文指针缺失都视为布局异常。
        var layoutAnomalyCount = 0
        if functionPointer == nil { layoutAnomalyCount += 1 }
        if nonNilContextPointers.count != contextPointers.count { layoutAnomalyCount += 1 }

        // 同一 closure 的多个副本上下文地址不同，说明上下文被复制/替换。
        let unstableAddressCount = Set(nonNilContextPointers.map { UInt(bitPattern: $0) }).count > 1 ? 1 : 0

        let functionPointerLocality = classifyPointer(functionPointer).rawValue
        let contextPointerLocality = classifyPointer(nonNilContextPointers.first).rawValue

        return ClosureSnapshot(
            sampleCount: seeds.count,
            canaryMismatchCount: canaryMismatchCount,
            layoutAnomalyCount: layoutAnomalyCount,
            unstableAddressCount: unstableAddressCount,
            functionPointerLocality: functionPointerLocality,
            contextPointerLocality: contextPointerLocality
        )
    }

    /// 从 existential 容器中提取末尾两个非空指针。
    private func witnessCandidatePointers(from value: any RuntimeWitnessProbe) -> [UnsafeRawPointer] {
        withUnsafeBytes(of: value) { raw in
            let words = raw.bindMemory(to: UInt.self)
            guard words.count >= 2 else { return [] }
            let indices = [words.count - 2, words.count - 1]
            return indices.compactMap { index in
                let candidate = words[index]
                guard candidate > 0x1000 else { return nil }
                return UnsafeRawPointer(bitPattern: candidate)
            }
        }
    }

    /// 读取 closure 内存布局中指定 word 的指针。
    private func closureWord(_ closure: @escaping (UInt64) -> UInt64, index: Int) -> UnsafeRawPointer? {
        withUnsafeBytes(of: closure) { raw in
            let words = raw.bindMemory(to: UInt.self)
            guard index >= 0, index < words.count else { return nil }
            let value = words[index]
            guard value > 0x1000 else { return nil }
            return UnsafeRawPointer(bitPattern: value)
        }
    }

    /// 通过泛型约束调用 witness 方法，用于与直接调用对比。
    private func dispatchThroughGeneric<T: RuntimeWitnessProbe>(_ probe: T, seed: UInt64) -> UInt64 {
        probe.dispatchFingerprint(seed: seed)
    }

    /// closure 的确定性摘要：FNV 风格乘法 + 常量异或。
    private static func closureDigest(canary: UInt64, vector: [UInt64], seed: UInt64) -> UInt64 {
        var acc = seed ^ canary
        for item in vector {
            acc = acc &* 1099511628211
            acc ^= item &+ 0x9E37_79B9_7F4A_7C15
        }
        return acc
    }

    /// 指针归属分类。
    private enum PointerLocality: String {
        case imageExecutable = "image_exec"
        case imageData = "image_data"
        case anonymousExecutable = "anon_exec"
        case anonymousData = "anon_data"
        case unknown = "unknown"
    }

    /// 用 dladdr + vm_region 判断指针属于镜像还是匿名内存。
    private func classifyPointer(_ pointer: UnsafeRawPointer?) -> PointerLocality {
        guard let pointer else { return .unknown }

        // dladdr 能解析出镜像名，再结合 VM_PROT_EXECUTE 区分代码/数据。
        var info = Dl_info()
        let hasImage = dladdr(pointer, &info) != 0 && info.dli_fname != nil

        var address = vm_address_t(UInt(bitPattern: pointer))
        var size: vm_size_t = 0
        var basicInfo = vm_region_basic_info_data_64_t()
        var basicCount = mach_msg_type_number_t(
            MemoryLayout<vm_region_basic_info_data_64_t>.stride / MemoryLayout<natural_t>.stride
        )
        var objectName: mach_port_t = 0

        let basicKr = withUnsafeMutablePointer(to: &basicInfo) { pointerInfo in
            pointerInfo.withMemoryRebound(to: integer_t.self, capacity: Int(basicCount)) { rebound in
                vm_region_64(mach_task_self_, &address, &size, VM_REGION_BASIC_INFO_64, rebound, &basicCount, &objectName)
            }
        }
        guard basicKr == KERN_SUCCESS else {
            return .unknown
        }

        let executable = (basicInfo.protection & VM_PROT_EXECUTE) != 0

        // 镜像内且可执行 -> image_exec；镜像内不可执行 -> image_data。
        if hasImage && executable {
            return .imageExecutable
        }
        if hasImage {
            return .imageData
        }
        // 无镜像但可执行 -> anon_exec；其余 -> anon_data。
        if executable {
            return .anonymousExecutable
        }
        return .anonymousData
    }

    /// 把归属分桶格式化为 `key=count,...`，便于遥测。
    private func formatBuckets(_ buckets: [String: Int]) -> String {
        buckets
            .sorted { lhs, rhs in lhs.key < rhs.key }
            .map { "\($0.key)=\($0.value)" }
            .joined(separator: ",")
    }
}

/// 协议 witness 探针接口。
private protocol RuntimeWitnessProbe {
    func dispatchFingerprint(seed: UInt64) -> UInt64
}

/// existential 探针接口。
private protocol RuntimeExistentialProbe {
    func stableMarker(seed: UInt64) -> UInt64
}

/// witness 探针实现：用 seed 与常量混合产生确定性指纹。
private struct WitnessProbeImpl: RuntimeWitnessProbe {
    let base: UInt64

    /// 直接/泛型/协议分发应返回相同结果。
    func dispatchFingerprint(seed: UInt64) -> UInt64 {
        let mixed = seed &* 0x9E37_79B9_7F4A_7C15
        return (mixed ^ base) &+ 0xA24B_AED4_963E_E407
    }
}

/// existential 探针实现。
private struct ExistentialProbeImpl: RuntimeExistentialProbe {
    let seed: UInt64

    /// 确定性标记，用于比较具体类型与 existential 调用。
    func stableMarker(seed input: UInt64) -> UInt64 {
        (seed &+ input) ^ 0x6A09E667F3BCC909
    }
}

/// 元数据 sentinel 结构体。
private struct MetadataSentinel {
    let counter: Int
    let label: String
}

/// closure 捕获的 canary 盒。
private final class ClosureCanaryBox {
    let canary: UInt64
    let vector: [UInt64]

    init(canary: UInt64, vector: [UInt64]) {
        self.canary = canary
        self.vector = vector
    }
}
