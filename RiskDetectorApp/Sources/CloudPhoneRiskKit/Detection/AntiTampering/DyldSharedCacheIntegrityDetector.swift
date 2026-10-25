// DyldSharedCacheIntegrityDetector：校验 dyld 共享缓存中关键系统库的完整性。
// 通过 LC_UUID 存在性、关键镜像 slide 一致性、关键符号归属与 __TEXT 范围，
// 识别共享缓存被替换、镜像被重映射或符号被 interpose 的情况。
// 系统库通常共享同一 slide，异常多说明映射被篡改。
import Darwin
import Foundation
import MachO

/// Validates dyld shared-cache integrity via:
/// 1) UUID presence for critical cache images
/// 2) slide consistency across critical cache images
/// 3) critical symbol ownership / in-text-range consistency
/// dyld 共享缓存完整性检测器。
/// - 线程模型：同步只读遍历 dyld 镜像与 Mach-O load command。
/// - 误报控制：只有关键镜像/符号异常才计分，单项异常先给 soft。
struct DyldSharedCacheIntegrityDetector: Detector {
    /// 关键镜像的快照：id、路径、UUID、slide。
    struct ImageSnapshot {
        let id: String
        let path: String
        let uuidHex: String?
        let slide: Int64
    }

    /// 一次采集的完整快照。
    struct Snapshot {
        let criticalImages: [ImageSnapshot]
        let slideMismatchCount: Int
        let missingUUIDCount: Int
        let symbolMismatches: [String]
    }

    /// 评分结果及各项异常计数。
    struct Assessment {
        let score: Double
        let methods: [String]
        let slideMismatchCount: Int
        let missingUUIDCount: Int
        let symbolMismatchCount: Int
    }

    // 关键共享缓存镜像及路径后缀。
    private let criticalImageSuffixes: [(id: String, suffix: String)] = [
        ("libsystem_kernel", "/usr/lib/system/libsystem_kernel.dylib"),
        ("libsystem_c", "/usr/lib/libsystem_c.dylib"),
        ("libobjc", "/usr/lib/libobjc.A.dylib"),
        ("libdispatch", "/usr/lib/system/libdispatch.dylib"),
    ]

    // 关键符号及期望归属镜像 token。
    private let criticalSymbols: [(symbol: String, expectedTokens: [String])] = [
        ("open", ["libsystem", "/usr/lib/system"]),
        ("malloc", ["libsystem", "/usr/lib/system"]),
        ("objc_msgSend", ["libobjc"]),
        ("dispatch_async", ["libdispatch"]),
    ]

    /// 入口：模拟器直接返回 0，真机采集并评估。
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["dyld_shared_cache:unavailable_simulator"])
#else
        let snapshot = collectSnapshot()
        let assessment = assess(snapshot: snapshot)
        return DetectorResult(score: assessment.score, methods: assessment.methods)
#endif
    }

    /// 对快照评分：UUID 缺失、slide 不一致、符号归属异常。
    func assess(snapshot: Snapshot) -> Assessment {
        // 没有关键镜像也没有符号异常 -> 视为 clean。
        guard !snapshot.criticalImages.isEmpty || !snapshot.symbolMismatches.isEmpty else {
            return Assessment(
                score: 0,
                methods: ["dyld_shared_cache:clean"],
                slideMismatchCount: 0,
                missingUUIDCount: 0,
                symbolMismatchCount: 0
            )
        }

        var score: Double = 0
        var methods: [String] = []

        // UUID 缺失：每个 +9，基础 20，封顶 42。
        if snapshot.missingUUIDCount > 0 {
            score += min(20 + Double(snapshot.missingUUIDCount - 1) * 9, 42)
            methods.append("dyld_shared_cache:uuid_missing:\(snapshot.missingUUIDCount)")
        }

        // slide 不一致：每个 +12，基础 28，封顶 48。
        if snapshot.slideMismatchCount > 0 {
            score += min(28 + Double(snapshot.slideMismatchCount - 1) * 12, 48)
            methods.append("dyld_shared_cache:slide_mismatch:\(snapshot.slideMismatchCount)")
        }

        // 符号归属异常：>=2 个才高置信，1 个仅给提示分。
        let symbolMismatchCount = snapshot.symbolMismatches.count
        if symbolMismatchCount >= 2 {
            score += min(24 + Double(symbolMismatchCount - 2) * 8, 44)
            methods.append("dyld_shared_cache:symbol_mismatch:\(symbolMismatchCount)")
        } else if symbolMismatchCount == 1 {
            score += 8
            methods.append("dyld_shared_cache:symbol_mismatch_hint:1")
        }

        // slide 与符号同时异常，追加相关异常分。
        if snapshot.slideMismatchCount > 0 && symbolMismatchCount > 0 {
            score += 12
            methods.append("dyld_shared_cache:correlated_anomaly")
        }

        return Assessment(
            // 总分封顶 95。
            score: min(score, 95),
            methods: methods,
            slideMismatchCount: snapshot.slideMismatchCount,
            missingUUIDCount: snapshot.missingUUIDCount,
            symbolMismatchCount: symbolMismatchCount
        )
    }

    /// 采集关键镜像与关键符号的快照。
    private func collectSnapshot() -> Snapshot {
        var images: [ImageSnapshot] = []
        var seen = Set<String>()

        let imageCount = _dyld_image_count()
        for index in 0..<imageCount {
            guard let cPath = _dyld_get_image_name(index), let header = _dyld_get_image_header(index) else { continue }
            let path = String(cString: cPath)
            // 只收集路径后缀匹配的关键镜像，并按 id 去重。
            for rule in criticalImageSuffixes where path.hasSuffix(rule.suffix) {
                guard !seen.contains(rule.id) else { break }
                let uuid = extractUUID(from: UnsafeRawPointer(header))
                let slide = Int64(_dyld_get_image_vmaddr_slide(index))
                images.append(
                    ImageSnapshot(
                        id: rule.id,
                        path: path,
                        uuidHex: uuid,
                        slide: slide
                    )
                )
                seen.insert(rule.id)
                break
            }
        }

        let missingUUIDCount = images.filter { $0.uuidHex == nil || $0.uuidHex?.isEmpty == true }.count
        var slideMismatchCount = 0
        // 以第一个关键镜像的 slide 为基线，统计不一致数量。
        if let baselineSlide = images.first?.slide {
            slideMismatchCount = images.filter { $0.slide != baselineSlide }.count
        }

        let symbolMismatches = collectSymbolMismatches()

        return Snapshot(
            criticalImages: images,
            slideMismatchCount: slideMismatchCount,
            missingUUIDCount: missingUUIDCount,
            symbolMismatches: symbolMismatches
        )
    }

    /// 检查关键符号是否仍由预期库提供且落在 __TEXT 内。
    private func collectSymbolMismatches() -> [String] {
        var mismatches: [String] = []
        for item in criticalSymbols {
            // RTLD_DEFAULT 查全局符号。
            guard let ptr = dlsym(UnsafeMutableRawPointer(bitPattern: -2), item.symbol) else {
                mismatches.append("\(item.symbol):dlsym")
                continue
            }

            // dladdr 获取符号所属镜像。
            var info = Dl_info()
            guard dladdr(ptr, &info) != 0, let cName = info.dli_fname else {
                mismatches.append("\(item.symbol):dladdr")
                continue
            }

            let path = String(cString: cName)
            let normalized = path.lowercased()
            // 路径 token 不匹配：符号被其他镜像 interpose。
            if !item.expectedTokens.contains(where: { normalized.contains($0) }) {
                mismatches.append("\(item.symbol):unexpected_image:\(path)")
                continue
            }

            // 符号地址必须落在所属镜像的 __TEXT 范围。
            if let imageBase = info.dli_fbase,
               let textRange = MachOTextRange.textRange(header: UnsafeRawPointer(imageBase)) {
                let address = UInt64(bitPattern: Int64(Int(bitPattern: ptr)))
                if address < textRange.lowerBound || address >= textRange.upperBound {
                    mismatches.append("\(item.symbol):out_of_text")
                }
            }
        }
        return mismatches
    }

    /// 从 Mach-O load command 中提取 LC_UUID。
    private func extractUUID(from header: UnsafeRawPointer) -> String? {
        let header64 = header.assumingMemoryBound(to: mach_header_64.self)
        // 仅处理 64 位 Mach-O。
        guard header64.pointee.magic == MH_MAGIC_64 || header64.pointee.magic == MH_CIGAM_64 else {
            return nil
        }

        var command = header.advanced(by: MemoryLayout<mach_header_64>.size)
        let commandLimit = command.advanced(by: Int(header64.pointee.sizeofcmds))
        for _ in 0..<header64.pointee.ncmds {
            guard command < commandLimit else { break }
            let load = command.assumingMemoryBound(to: load_command.self).pointee
            guard load.cmdsize > 0 else { break }
            // LC_UUID 的 16 字节转十六进制。
            if load.cmd == LC_UUID {
                let uuidCommand = command.assumingMemoryBound(to: uuid_command.self).pointee
                let bytes = withUnsafeBytes(of: uuidCommand.uuid) { Array($0) }
                return bytes.map { String(format: "%02x", $0) }.joined()
            }
            command = command.advanced(by: Int(load.cmdsize))
        }
        return nil
    }
}

/// 信号转换：UUID、slide、符号异常分别成信号，另加聚合信号。
extension DyldSharedCacheIntegrityDetector {
    /// 强异常（多镜像/UUID 或 slide）使用 tampered，单项使用 soft。
    func asSignals() -> [RiskSignal] {
        let snapshot = collectSnapshot()
        let assessment = assess(snapshot: snapshot)
        guard assessment.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        // UUID 缺失信号。
        if assessment.missingUUIDCount > 0 {
            signals.append(
                RiskSignal(
                    id: SignalID.dyldSharedCacheUUIDMismatch,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: min(30 + Double(assessment.missingUUIDCount) * 8, 55),
                    evidence: [
                        "missing_uuid_count": "\(assessment.missingUUIDCount)",
                        "images": snapshot.criticalImages.map(\.path).joined(separator: ","),
                    ],
                    state: assessment.missingUUIDCount >= 2 ? .tampered : .soft(confidence: 0.65),
                    layer: 2,
                    weightHint: assessment.missingUUIDCount >= 2 ? 82 : 52
                )
            )
        }

        // slide 不一致信号，固定 tampered。
        if assessment.slideMismatchCount > 0 {
            signals.append(
                RiskSignal(
                    id: SignalID.dyldSharedCacheSlideMismatch,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: min(42 + Double(assessment.slideMismatchCount) * 10, 76),
                    evidence: [
                        "slide_mismatch_count": "\(assessment.slideMismatchCount)",
                        "slides": snapshot.criticalImages
                            .map { "\($0.id)=\($0.slide)" }
                            .sorted()
                            .joined(separator: ","),
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 90
                )
            )
        }

        // 符号归属异常信号。
        if assessment.symbolMismatchCount > 0 {
            signals.append(
                RiskSignal(
                    id: SignalID.dyldSharedCacheSymbolMismatch,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: assessment.symbolMismatchCount >= 2
                        ? min(36 + Double(assessment.symbolMismatchCount) * 8, 70)
                        : 12,
                    evidence: [
                        "symbol_mismatches": snapshot.symbolMismatches.joined(separator: ","),
                    ],
                    state: assessment.symbolMismatchCount >= 2 ? .tampered : .soft(confidence: 0.58),
                    layer: 2,
                    weightHint: assessment.symbolMismatchCount >= 2 ? 86 : 40
                )
            )
        }

        // 聚合信号：存在任一 tampered 子信号时同样标为 tampered。
        let hasHardAnomaly = signals.contains(where: { $0.state == .tampered })
        signals.append(
            RiskSignal(
                id: SignalID.dyldSharedCacheIntegrity,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: assessment.score,
                evidence: [
                    "methods": assessment.methods.joined(separator: ","),
                    "critical_image_count": "\(snapshot.criticalImages.count)",
                ],
                state: hasHardAnomaly ? .tampered : .soft(confidence: 0.7),
                layer: 2,
                weightHint: hasHardAnomaly ? 88 : 58
            )
        )

        return signals
    }
}
