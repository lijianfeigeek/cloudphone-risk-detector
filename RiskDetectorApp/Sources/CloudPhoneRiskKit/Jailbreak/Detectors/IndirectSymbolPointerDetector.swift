// 间接符号指针检测器：解析 Mach-O 的 indirect symbol table，发现 fishhook 式重绑定。
// 位于 HookDetector 的子检测器链中，专门针对“替换懒/非懒符号指针”的经典 hook 手法。
// 关键安全不变量：只有解析后的指针指向非系统镜像时才计分；解析失败按无证据处理，不误报。
import Darwin
import Foundation
import MachO

/// 通过检查 indirect symbol pointer 表发现 fishhook 式重绑定。
/// 尽力而为：只关注小型 watchlist，且仅当解析后的指针指向非系统镜像时才告警。
/// 检测什么：`open/stat/getenv/objc_msgSend` 等符号的指针被改写到第三方镜像。
/// 命中后产生 `indirect_ptr:<name>` 信号，单项 10–14 分，总分封顶 60。
/// 误报风险：JIT/动态加载场景下指针可能暂时指向合法镜像；系统路径白名单降低误报。
struct IndirectSymbolPointerDetector: Detector {
    /// 需要重点核对指针落点的符号及分值。
    let watch: [(symbol: String, score: Double)] = [
        ("open", 12),
        ("openat", 12),
        ("fopen", 10),
        ("stat", 12),
        ("lstat", 12),
        ("statfs", 10),
        ("access", 12),
        ("faccessat", 10),
        ("sysctl", 12),
        ("sysctlbyname", 12),
        ("getenv", 10),
        ("dlopen", 12),
        ("syscall", 14),
        ("__syscall", 14),
        ("posix_spawn", 12),
        ("posix_spawnp", 10),
        ("objc_msgSend", 14),
    ]

    /// 可疑镜像路径令牌（核心集合）。
    let suspiciousImageTokens: [String] = ObfuscatedConstants.hookSuspiciousImageTokensCore

    /// 扫描所有已加载镜像的间接符号表。
    /// - Returns: 累计分数封顶 60 的检测结果。
    /// - Note: 只扫描前 80 个镜像以限制耗时；单个镜像解析失败会跳过。
    func detect() throws -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []

        // 符号名到分值的映射，避免在镜像循环内线性查找 watchlist。
        let needles = Dictionary(uniqueKeysWithValues: watch.map { ($0.symbol, $0.score) })

        let imageCount = Int(_dyld_image_count())
        let maxImages = min(imageCount, 80)
        for i in 0..<maxImages {
            guard let header = _dyld_get_image_header(UInt32(i)) else { continue }
            // ASLR slide 用于把 Mach-O 中的虚拟地址换算成当前进程地址。
            let slide = Int64(_dyld_get_image_vmaddr_slide(UInt32(i)))
            let result = scanImage(header: header, slide: slide, needles: needles)
            score += result.score
            methods.append(contentsOf: result.methods)
        }

        if score > 60 { score = 60 }
        return DetectorResult(score: score, methods: methods)
    }

    /// 解析单个 Mach-O 镜像的间接符号表并核对指针落点。
    /// - Parameters:
    ///   - header: 镜像的 mach header 指针。
    ///   - slide: 该镜像的 ASLR 偏移。
    ///   - needles: 需要检查的符号名到分值映射。
    /// - Returns: 该镜像产生的分值与命中方法；结构不完整时返回空结果。
    private func scanImage(header: UnsafePointer<mach_header>, slide: Int64, needles: [String: Double]) -> DetectorResult {
        // 这里只处理 64 位镜像。
        guard header.pointee.magic == MH_MAGIC_64 || header.pointee.magic == MH_CIGAM_64 else { return .empty }
        let h64 = UnsafeRawPointer(header).assumingMemoryBound(to: mach_header_64.self).pointee

        // 预先收集解析所需的三类 load command 与目标 section。
        var symtab: symtab_command?
        var dysymtab: dysymtab_command?
        var linkedit: segment_command_64?
        var sections: [section_64] = []

        // load command 从 mach_header_64 之后开始，按 cmdsize 逐条推进。
        var cmdPtr = UnsafeRawPointer(header).advanced(by: MemoryLayout<mach_header_64>.size)
        for _ in 0..<h64.ncmds {
            let lc = cmdPtr.assumingMemoryBound(to: load_command.self).pointee
            if lc.cmd == LC_SYMTAB {
                symtab = cmdPtr.assumingMemoryBound(to: symtab_command.self).pointee
            } else if lc.cmd == LC_DYSYMTAB {
                dysymtab = cmdPtr.assumingMemoryBound(to: dysymtab_command.self).pointee
            } else if lc.cmd == LC_SEGMENT_64 {
                let seg = cmdPtr.assumingMemoryBound(to: segment_command_64.self).pointee
                // segname 是定长 C 数组，取到首个 NUL 为止。
                let segname = withUnsafeBytes(of: seg.segname) { raw -> String in
                    let bytes = raw.prefix { $0 != 0 }
                    return String(decoding: bytes, as: UTF8.self)
                }
                if segname == "__LINKEDIT" {
                    linkedit = seg
                }
                // section 结构紧跟在 segment_command_64 之后。
                if seg.nsects > 0 {
                    var secPtr = cmdPtr.advanced(by: MemoryLayout<segment_command_64>.size)
                    for _ in 0..<seg.nsects {
                        let sec = secPtr.assumingMemoryBound(to: section_64.self).pointee
                        let type = sec.flags & UInt32(SECTION_TYPE)
                        // 只关心懒绑定/非懒绑定的符号指针表。
                        if type == UInt32(S_LAZY_SYMBOL_POINTERS) || type == UInt32(S_NON_LAZY_SYMBOL_POINTERS) {
                            sections.append(sec)
                        }
                        secPtr = secPtr.advanced(by: MemoryLayout<section_64>.size)
                    }
                }
            }
            // 防御 cmdsize 非法导致的死循环或越界。
            guard lc.cmdsize >= MemoryLayout<load_command>.size else { break }
            cmdPtr = cmdPtr.advanced(by: Int(lc.cmdsize))
        }

        guard let symtab, let dysymtab, let linkedit else { return .empty }
        guard dysymtab.nindirectsyms > 0 else { return .empty }

        // 计算 __LINKEDIT 在内存中的基址：vmaddr + slide - fileoff。
        let linkeditBase = UInt64(Int64(linkedit.vmaddr) + slide) - UInt64(linkedit.fileoff)
        guard linkeditBase != 0 else { return .empty }

        // 符号表、字符串表、间接符号表在 __LINKEDIT 内的偏移换算为绝对地址。
        let symAddr = linkeditBase + UInt64(symtab.symoff)
        let strAddr = linkeditBase + UInt64(symtab.stroff)
        let indirectAddr = linkeditBase + UInt64(dysymtab.indirectsymoff)
        guard symAddr <= UInt64(UInt.max), strAddr <= UInt64(UInt.max), indirectAddr <= UInt64(UInt.max) else {
            return .empty
        }
        let symPtr = UnsafeRawPointer(bitPattern: UInt(symAddr))
        let strPtr = UnsafeRawPointer(bitPattern: UInt(strAddr))
        let indirectPtr = UnsafeRawPointer(bitPattern: UInt(indirectAddr))
        guard
            let symPtr,
            let strPtr,
            let indirectPtr
        else { return .empty }

        // 指针校验通过后再绑定内存；容量取自各自 command 的计数。
        let symbols = symPtr.bindMemory(to: nlist_64.self, capacity: Int(symtab.nsyms))
        let strings = strPtr.bindMemory(to: CChar.self, capacity: Int(symtab.strsize))
        let indirect = indirectPtr.bindMemory(to: UInt32.self, capacity: Int(dysymtab.nindirectsyms))

        var score: Double = 0
        var methods: [String] = []

        for sec in sections {
            // 64 位指针每个占 8 字节，section 大小即条目数的 8 倍。
            let count = Int(sec.size / 8)
            if count <= 0 { continue }
            let startIndex = Int(sec.reserved1)
            // 边界检查：避免 section 声明的范围越过 indirect symbol 表。
            if startIndex + count > Int(dysymtab.nindirectsyms) { continue }

            let tableAddr = UInt64(Int64(sec.addr) + slide)
            guard let tablePtr = UnsafeRawPointer(bitPattern: UInt(tableAddr)) else { continue }
            let ptrs = tablePtr.bindMemory(to: UInt64.self, capacity: count)

            for j in 0..<count {
                let symIndex = indirect[startIndex + j]
                // ABS/LOCAL 是特殊标记，不对应真实符号。
                if symIndex == UInt32(INDIRECT_SYMBOL_ABS) || symIndex == UInt32(INDIRECT_SYMBOL_LOCAL) { continue }
                if symIndex >= symtab.nsyms { continue }

                let n = symbols[Int(symIndex)]
                let strx = Int(n.n_un.n_strx)
                // 字符串偏移必须落在字符串表内。
                if strx <= 0 || strx >= Int(symtab.strsize) { continue }
                let rawName = String(cString: strings.advanced(by: strx))
                // Mach-O 符号通常带前导下划线，去掉后再与 watchlist 比对。
                let name = rawName.hasPrefix("_") ? String(rawName.dropFirst()) : rawName
                guard let s = needles[name] else { continue }

                let target = ptrs[j]
                guard target != 0 else { continue }
                // 指针仍指向系统库属正常情况，不产生证据。
                if isTrustedSystemAddress(target) { continue }

                score += s
                methods.append("indirect_ptr:\(name)")
                Logger.log("\(ObfuscatedConstants.keywordJailbreak).fis\(ObfuscatedConstants.keywordHook).hit: \(name) ptr=0x\(String(target, radix: 16)) (+\(s))")
            }
        }

        return DetectorResult(score: score, methods: methods)
    }

    /// 判断指针地址是否落在系统库中。
    /// - Parameter addr: 待检查的指针值。
    /// - Returns: 能解析出系统路径时返回 `true`；解析失败按不可信处理。
    func isTrustedSystemAddress(_ addr: UInt64) -> Bool {
        let p = UnsafeRawPointer(bitPattern: UInt(addr))
        guard let p else { return false }
        var info = Dl_info()
        guard dladdr(p, &info) != 0, let cPath = info.dli_fname else { return false }
        return isTrustedSystemPath(String(cString: cPath))
    }

    /// 判断镜像路径是否可信。
    /// - Parameter path: 镜像路径。
    /// - Returns: 非可疑令牌且命中系统前缀时返回 `true`。
    func isTrustedSystemPath(_ path: String) -> Bool {
        let normalized = path.lowercased()
        if suspiciousImageTokens.contains(where: { normalized.contains($0) }) { return false }
        return normalized.hasPrefix("/usr/lib/system/")
            || normalized.hasPrefix("/usr/lib/libsystem")
            || normalized.hasPrefix("/usr/lib/libobjc.")
            || normalized.hasPrefix("/system/library/")
    }
}
