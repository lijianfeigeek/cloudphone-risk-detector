// FridaModuleDetector：从已加载模块的静态特征识别 Frida/Gum/Gadget。
// 维度包括 dyld 镜像名、可疑 Mach-O section 名、__cstring/__const 中的特征串，
// 以及关键系统函数 prologue 的跳板分支。与端口/线程/内存布局检测互补：
// 模块痕迹在 attach 后长期存在，难以仅靠关闭端口清除。
import Darwin
import Foundation
import MachO

/// Detects Frida/Gum/Gadget traits from loaded in-memory modules.
///
/// The detector intentionally prefers stable heuristics over brittle byte signatures:
/// - dyld image names
/// - suspicious Mach-O section names
/// - string fragments found in loaded `__cstring` / `__const` sections
/// 已加载模块特征检测器。
/// - 优先使用稳定的名称/段/字符串启发式，而非易变的字节签名。
/// - 线程模型：同步只读遍历 dyld 镜像与 Mach-O load command。
struct FridaModuleDetector: Detector {
    // 跳板命中的方法前缀。
    private static let trampolineMethodPrefix = "frida_module:trampoline:"
    // 常被 hook 的高价值系统符号；检查其前两条指令是否为跳板。
    private let suspiciousTrampolineSymbols: [String] = [
        "objc_msgSend",
        "dlopen",
        "dlsym",
        "pthread_create",
        "mach_msg",
        "sysctl",
        "open",
    ]

    /// 单个符号 prologue 的观察值（前两条 32 位指令）。
    struct PrologueObservation: Sendable, Equatable {
        let symbol: String
        let firstInstruction: UInt32
        let secondInstruction: UInt32?
    }

    // 镜像名中的 frida/gum/gadget 等标记（混淆常量）。
    let moduleMarkers: [String] = ObfuscatedConstants.fridaModuleMarkers

    // 可疑 section 名标记。
    let suspiciousSectionMarkers: [String] = ObfuscatedConstants.fridaSectionMarkers

    // 可疑字符串标记（在 __cstring/__const 中搜索）。
    let suspiciousStringMarkers: [String] = ObfuscatedConstants.fridaStringMarkers

    // 只扫描这两个段，控制读取量；其他段与字符串特征无关。
    private let scannedSectionNames: Set<String> = ["__cstring", "__const"]
    // 每个 section 最多读取 64KB，避免大型二进制拖慢检测。
    private let maxStringScanBytes = 64 * 1024

    /// 执行镜像、段、字符串与跳板四类检测并汇总。
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: [ObfuscatedConstants.methodFridaModuleUnavailableSimulator])
#else
        var imageHits: [String] = []
        var sectionHits: [String] = []
        var stringHits: [String] = []
        // 先检查关键符号跳板：命中说明运行时被 inline hook。
        let trampolineHits = detectTrampolineMarkers(in: capturePrologueObservations())

        // 遍历所有 dyld 镜像，检查名称与来源异常。
        let imageCount = _dyld_image_count()
        for index in 0..<imageCount {
            let imageName = _dyld_get_image_name(index).map { String(cString: $0) } ?? ""
            imageHits.append(contentsOf: detectImageMarkers(in: [imageName]))
            imageHits.append(contentsOf: detectImageOriginAnomalies(in: [imageName]))

            guard let header = _dyld_get_image_header(index) else { continue }
            // 系统库不解析 Mach-O 布局：既省开销，也避免系统库噪声。
            let shouldInspectLayout = !imageName.hasPrefix("/usr/lib/") && !imageName.hasPrefix("/System/")
            guard shouldInspectLayout else { continue }

            let layout = inspectModuleLayout(header: header, imageIndex: index)
            let isMainExecutable = isMainExecutableImage(index: index, imageName: imageName)
            sectionHits.append(contentsOf: detectSectionMarkers(in: layout.sectionNames))
            stringHits.append(contentsOf: detectStringMarkers(in: layout.stringBlobs))
            // 主可执行文件额外加权：对主二进制的修改置信更高。
            if isMainExecutable {
                sectionHits.append(contentsOf: detectSectionMarkers(in: layout.sectionNames, mainBinary: true))
                stringHits.append(contentsOf: detectStringMarkers(in: layout.stringBlobs, mainBinary: true))
            }
        }

        return Self.buildResult(
            imageHits: imageHits,
            sectionHits: sectionHits,
            stringHits: stringHits,
            trampolineHits: trampolineHits
        )
#endif
    }

    /// 在镜像名中匹配 Frida/Gum 模块标记。
    func detectImageMarkers(in imageNames: [String]) -> [String] {
        var hits = Set<String>()

        for imageName in imageNames {
            let normalized = imageName.lowercased()
            for marker in moduleMarkers where normalized.contains(marker) {
                hits.insert("\(ObfuscatedConstants.methodPrefixFridaModuleImage)\(marker)")
            }
        }

        return hits.sorted()
    }

    /// 检测异常加载来源：/tmp、Documents、Caches、沙盒 Data 等。
    func detectImageOriginAnomalies(in imageNames: [String]) -> [String] {
        var hits = Set<String>()

        for imageName in imageNames {
            let normalized = imageName.lowercased()
            guard !normalized.isEmpty else { continue }
            guard !normalized.hasPrefix("/usr/lib/"), !normalized.hasPrefix("/system/") else { continue }

            // 这些目录中的 dylib/framework 是重打包或注入的典型落点。
            if normalized.contains("/tmp/") {
                hits.insert("\(ObfuscatedConstants.methodPrefixFridaModuleImage)tmp_origin")
            }
            if normalized.contains("/documents/") {
                hits.insert("\(ObfuscatedConstants.methodPrefixFridaModuleImage)documents_origin")
            }
            if normalized.contains("/library/caches/") {
                hits.insert("\(ObfuscatedConstants.methodPrefixFridaModuleImage)caches_origin")
            }
            if normalized.contains("/containers/data/application/"),
               normalized.hasSuffix(".dylib") || normalized.contains(".framework/") {
                hits.insert("\(ObfuscatedConstants.methodPrefixFridaModuleImage)sandbox_data_origin")
            }
        }

        return hits.sorted()
    }

    /// 在 section 名中匹配可疑标记；mainBinary 时加 main_binary 前缀以便加权。
    func detectSectionMarkers(in sectionNames: [String], mainBinary: Bool = false) -> [String] {
        var hits = Set<String>()
        let prefix = mainBinary
            ? "\(ObfuscatedConstants.methodPrefixFridaModuleSection)main_binary:"
            : ObfuscatedConstants.methodPrefixFridaModuleSection

        for sectionName in sectionNames {
            let normalized = sectionName.lowercased()
            for marker in suspiciousSectionMarkers where normalized.contains(marker) {
                hits.insert("\(prefix)\(marker)")
            }
        }

        return hits.sorted()
    }

    /// 在字符串 blob 中匹配可疑标记；mainBinary 时加前缀。
    func detectStringMarkers(in blobs: [String], mainBinary: Bool = false) -> [String] {
        var hits = Set<String>()
        let prefix = mainBinary
            ? "\(ObfuscatedConstants.methodPrefixFridaModuleString)main_binary:"
            : ObfuscatedConstants.methodPrefixFridaModuleString

        for blob in blobs {
            let normalized = blob.lowercased()
            for marker in suspiciousStringMarkers where normalized.contains(marker) {
                hits.insert("\(prefix)\(marker)")
            }
        }

        return hits.sorted()
    }

    /// 检查关键符号 prologue 是否呈现跳板分支。
    func detectTrampolineMarkers(in observations: [PrologueObservation]) -> [String] {
        let branchDetector = PrologueBranchDetector()
        var hits = Set<String>()

        for observation in observations where suspiciousTrampolineSymbols.contains(observation.symbol) {
            guard branchDetector.isHooked(
                firstInstruction: observation.firstInstruction,
                secondInstruction: observation.secondInstruction
            ) else {
                continue
            }

            let detail: String
            // 区分 literal load + register branch、直接 register branch 与普通 branch。
            if branchDetector.isLiteralLoad(observation.firstInstruction),
               let second = observation.secondInstruction,
               branchDetector.isRegisterBranch(second) {
                detail = "\(observation.symbol):literal_branch"
            } else if branchDetector.isRegisterBranch(observation.firstInstruction) {
                detail = "\(observation.symbol):register_branch"
            } else {
                detail = "\(observation.symbol):branch"
            }
            hits.insert("\(Self.trampolineMethodPrefix)\(detail)")
        }

        return hits.sorted()
    }

    /// 把四类命中合并为 DetectorResult（去重、排序、计分）。
    static func buildResult(
        imageHits: [String],
        sectionHits: [String],
        stringHits: [String],
        trampolineHits: [String] = []
    ) -> DetectorResult {
        let uniqueImageHits = Array(Set(imageHits)).sorted()
        let uniqueSectionHits = Array(Set(sectionHits)).sorted()
        let uniqueStringHits = Array(Set(stringHits)).sorted()
        let uniqueTrampolineHits = Array(Set(trampolineHits)).sorted()
        let mainBinarySectionHits = uniqueSectionHits.filter { $0.contains(":main_binary:") }
        let mainBinaryStringHits = uniqueStringHits.filter { $0.contains(":main_binary:") }

        // 镜像命中基础 14 分，每多一条 +3，封顶 20。
        let imageScore = uniqueImageHits.isEmpty ? 0.0 : min(14.0 + Double(max(0, uniqueImageHits.count - 1)) * 3.0, 20.0)
        // section 命中基础 8 分，每多一条 +2，封顶 12。
        let sectionScore = uniqueSectionHits.isEmpty ? 0.0 : min(8.0 + Double(max(0, uniqueSectionHits.count - 1)) * 2.0, 12.0)
        // 字符串命中基础 12 分，每多一条 +3，封顶 18。
        let stringScore = uniqueStringHits.isEmpty ? 0.0 : min(12.0 + Double(max(0, uniqueStringHits.count - 1)) * 3.0, 18.0)
        // 跳板命中基础 14 分，每多一条 +4，封顶 18。
        let trampolineScore = uniqueTrampolineHits.isEmpty
            ? 0.0
            : min(14.0 + Double(max(0, uniqueTrampolineHits.count - 1)) * 4.0, 18.0)
        // 主二进制命中额外加分：section 3 分/条、string 4 分/条，封顶 12。
        let mainBinaryBoost = min(
            Double(mainBinarySectionHits.count) * 3.0 + Double(mainBinaryStringHits.count) * 4.0,
            12.0
        )

        return DetectorResult(
            // 总分封顶 44：模块特征可能来自合法调试工具/第三方 SDK。
            score: min(imageScore + sectionScore + stringScore + trampolineScore + mainBinaryBoost, 44),
            methods: uniqueImageHits + uniqueSectionHits + uniqueStringHits + uniqueTrampolineHits
        )
    }

    /// 信号转换：按类别产出聚合信号与细分信号。
    static func asSignals(result: DetectorResult) -> [RiskSignal] {
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []
        let imageMethods = result.methods.filter { $0.hasPrefix(ObfuscatedConstants.methodPrefixFridaModuleImage) }
        let sectionMethods = result.methods.filter { $0.hasPrefix(ObfuscatedConstants.methodPrefixFridaModuleSection) }
        let stringMethods = result.methods.filter { $0.hasPrefix(ObfuscatedConstants.methodPrefixFridaModuleString) }
        let trampolineMethods = result.methods.filter { $0.hasPrefix(Self.trampolineMethodPrefix) }

        // 聚合信号：总分封顶 28，state=tampered。
        signals.append(RiskSignal(
            id: SignalID.fridaModuleDetected,
            category: ObfuscatedConstants.categoryAntiTamper,
            score: min(result.score, 28),
            evidence: [
                "methods": result.methods.joined(separator: ","),
                "detector": ObfuscatedConstants.detectorNameFridaModuleDetector,
            ],
            state: .tampered,
            layer: 2,
            weightHint: 82
        ))

        // 镜像名细分信号：每条 8 分，封顶 16。
        if !imageMethods.isEmpty {
            signals.append(RiskSignal(
                id: SignalID.fridaModuleImage,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(imageMethods.count) * 8, 16),
                evidence: ["detail": imageMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 78
            ))
        }

        // section 细分信号：每条 6 分，封顶 12。
        if !sectionMethods.isEmpty {
            signals.append(RiskSignal(
                id: SignalID.fridaModuleSection,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(sectionMethods.count) * 6, 12),
                evidence: ["detail": sectionMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 72
            ))
        }

        // 字符串细分信号：每条 8 分，封顶 16。
        if !stringMethods.isEmpty {
            signals.append(RiskSignal(
                id: SignalID.fridaModuleString,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(stringMethods.count) * 8, 16),
                evidence: ["detail": stringMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 80
            ))
        }

        // 跳板细分信号：每条 10 分，封顶 18，置信最高。
        if !trampolineMethods.isEmpty {
            signals.append(RiskSignal(
                id: SignalID.fridaModuleTrampoline,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(trampolineMethods.count) * 10, 18),
                evidence: ["detail": trampolineMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 84
            ))
        }

        return signals
    }

    /// 读取关键符号前两条指令。
    private func capturePrologueObservations() -> [PrologueObservation] {
        let branchDetector = PrologueBranchDetector()
        // RTLD_DEFAULT（-2）表示在当前进程全局符号表中查找。
        let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)

        return suspiciousTrampolineSymbols.compactMap { symbol in
            guard let addr = dlsym(rtldDefault, symbol) else {
                return nil
            }
            let pointer = UnsafeRawPointer(addr)
            guard let first = branchDetector.readInstruction(pointer) else {
                return nil
            }
            let second = branchDetector.readInstruction(
                pointer.advanced(by: MemoryLayout<UInt32>.size)
            )
            return PrologueObservation(
                symbol: symbol,
                firstInstruction: first,
                secondInstruction: second
            )
        }
    }

    private func isMainExecutableImage(index: UInt32, imageName: String) -> Bool {
        if index == 0 {
            return true
        }
        if let executablePath = Bundle.main.executablePath {
            return imageName == executablePath
        }
        return false
    }

    /// 解析单个 Mach-O 的 section 名与目标段字符串。
    private func inspectModuleLayout(
        header: UnsafePointer<mach_header>,
        imageIndex: UInt32
    ) -> (sectionNames: [String], stringBlobs: [String]) {
        // 仅处理 64 位 Mach-O；32 位/畸形头直接跳过。
        guard header.pointee.magic == MH_MAGIC_64 || header.pointee.magic == MH_CIGAM_64 else {
            return ([], [])
        }

        let rawHeader = UnsafeRawPointer(header)
        let header64 = rawHeader.assumingMemoryBound(to: mach_header_64.self)
        let slide = Int64(_dyld_get_image_vmaddr_slide(imageIndex))

        var sectionNames: [String] = []
        var stringBlobs: [String] = []
        var command = rawHeader.advanced(by: MemoryLayout<mach_header_64>.size)

        for _ in 0..<Int(header64.pointee.ncmds) {
            let loadCommand = command.assumingMemoryBound(to: load_command.self).pointee
            guard loadCommand.cmdsize >= MemoryLayout<load_command>.size else { break }
            defer { command = command.advanced(by: Int(loadCommand.cmdsize)) }

            // 只遍历 LC_SEGMENT_64，其他 load command 与 section/字符串无关。
            guard loadCommand.cmd == LC_SEGMENT_64 else { continue }

            let segment = command.assumingMemoryBound(to: segment_command_64.self).pointee
            var sectionPtr = command.advanced(by: MemoryLayout<segment_command_64>.size)

            for _ in 0..<Int(segment.nsects) {
                let section = sectionPtr.assumingMemoryBound(to: section_64.self).pointee
                let sectionName = cString(from: section.sectname)
                sectionNames.append(sectionName)

                if scannedSectionNames.contains(sectionName),
                   let blob = readBlob(section: section, slide: slide),
                   !blob.isEmpty {
                    stringBlobs.append(blob)
                }

                sectionPtr = sectionPtr.advanced(by: MemoryLayout<section_64>.size)
            }
        }

        return (sectionNames, stringBlobs)
    }

    /// 读取 section 内容并规范化为可匹配文本。
    private func readBlob(section: section_64, slide: Int64) -> String? {
        guard section.addr != 0, section.size > 0 else { return nil }

        // 限制读取长度为 maxStringScanBytes，避免超大 __const 拖慢扫描。
        let byteCount = Int(min(section.size, UInt64(maxStringScanBytes)))
        let runtimeAddress = Int64(section.addr) + slide
        guard byteCount > 0,
              runtimeAddress > 0,
              let base = UnsafeRawPointer(bitPattern: Int(runtimeAddress)) else {
            return nil
        }

        let data = Data(bytes: base, count: byteCount)
        var normalized = [UInt8]()
        normalized.reserveCapacity(data.count)

        // 非可打印字节替换为空格，避免二进制数据干扰子串匹配。
        for byte in data {
            if (32...126).contains(byte) {
                normalized.append(byte)
            } else {
                normalized.append(0x20)
            }
        }

        return String(decoding: normalized, as: UTF8.self)
    }

    /// 从固定长度 C 字符元组中读取以 NUL 结尾的字符串。
    private func cString<T>(from tuple: T) -> String {
        withUnsafeBytes(of: tuple) { rawBuffer in
            let bytes = rawBuffer.prefix { $0 != 0 }
            return String(decoding: bytes, as: UTF8.self)
        }
    }
}

extension FridaModuleDetector {
    /// Detector 协议入口：执行检测并转换信号。
    func asSignals() throws -> [RiskSignal] {
        Self.asSignals(result: try detect())
    }
}
