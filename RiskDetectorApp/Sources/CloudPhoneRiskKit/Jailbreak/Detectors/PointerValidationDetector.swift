// 指针校验检测器：解析关键 C 符号并验证其三要素——镜像是否可疑、是否在预期系统中、地址是否落在 __TEXT。
// 位于 HookDetector 的子检测器链中，用于发现“符号解析结果被重定向”的 hook。
// 关键安全不变量：三项校验任一失败即计分；地址范围校验失败但镜像正常时同样视为被改写。
import Darwin
import Foundation
import MachO

/// 校验关键 libc/ObjC 符号当前解析到的地址是否仍属于其预期系统库。
/// 检测什么：`open/stat/syscall/objc_msgSend` 等符号被解析到可疑或非预期镜像，或落在镜像 `__TEXT` 之外。
/// 命中后产生 `ptr_suspicious:<symbol>`、`ptr_path:<symbol>`、`ptr_range:<symbol>` 信号，分值 6–10。
/// 误报风险：不同 iOS 版本的系统库路径略有差异，因此使用前缀白名单而非精确路径。
struct PointerValidationDetector: Detector {
    /// 单个符号的校验配置。
    struct Check: Sendable {
        /// 符号名。
        var symbol: String
        /// 允许的镜像路径前缀。
        var expectedPathPrefixes: [String]
        /// 命中分值。
        var score: Double
    }

    /// 关键符号及其预期镜像前缀与分值。
    /// 这些符号是越狱检测与隐藏逻辑经常 hook 的目标。
    let checks: [Check] = [
        .init(symbol: "open", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libsystem"], score: 8),
        .init(symbol: "openat", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libsystem"], score: 10),
        .init(symbol: "fopen", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libsystem"], score: 8),
        .init(symbol: "stat", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libsystem"], score: 8),
        .init(symbol: "lstat", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libsystem"], score: 8),
        .init(symbol: "statfs", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libsystem"], score: 8),
        .init(symbol: "access", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libsystem"], score: 8),
        .init(symbol: "faccessat", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libsystem"], score: 8),
        .init(symbol: "sysctl", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libsystem"], score: 8),
        .init(symbol: "sysctlbyname", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libsystem"], score: 8),
        .init(symbol: "getenv", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libsystem"], score: 6),
        .init(symbol: "dlopen", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libsystem"], score: 8),
        .init(symbol: "dlsym", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libsystem"], score: 6),
        .init(symbol: "dladdr", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libsystem"], score: 6),
        .init(symbol: "syscall", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libsystem"], score: 10),
        .init(symbol: "__syscall", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libsystem"], score: 10),
        .init(symbol: "posix_spawn", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libsystem"], score: 8),
        .init(symbol: "objc_msgSend", expectedPathPrefixes: ["/usr/lib/libobjc.", "/usr/lib/system/"], score: 10),
        .init(symbol: "objc_getClass", expectedPathPrefixes: ["/usr/lib/libobjc.", "/usr/lib/system/"], score: 8),
    ]

    /// 可疑镜像路径令牌（核心集合）。
    let suspiciousImageTokens: [String] = ObfuscatedConstants.hookSuspiciousImageTokensCore

    /// 执行指针校验。
    /// - Returns: 累计分数封顶 100 的检测结果；符号不存在或无法解析镜像时跳过。
    func detect() throws -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []

        for check in checks {
            guard let addr = resolve(symbol: check.symbol) else { continue }
            guard let info = dlInfo(addr) else { continue }

            let imagePath = info.path
            // 第一层：镜像本身命中可疑令牌，直接按该项满分计。
            if isSuspiciousImagePath(imagePath) {
                score += check.score
                methods.append("ptr_suspicious:\(check.symbol)")
                Logger.log("\(ObfuscatedConstants.keywordJailbreak).ptr.hit: \(check.symbol) suspicious_image=\(imagePath) (+\(check.score))")
                continue
            }

            // 第二层：镜像不在该符号的预期系统路径内（可能被替换为同名的恶意库）。
            let isPathOK = isExpectedPath(imagePath, expectedPrefixes: check.expectedPathPrefixes)
            if !isPathOK {
                score += check.score
                methods.append("ptr_path:\(check.symbol)")
                Logger.log("\(ObfuscatedConstants.keywordJailbreak).ptr.hit: \(check.symbol) unexpected_image=\(imagePath) (+\(check.score))")
                continue
            }

            // 第三层：地址必须落在该镜像的 __TEXT 段内；落到数据段/外部地址说明符号被重定向。
            if let base = info.base, let range = MachOTextRange.textRange(header: base) {
                let p = UInt64(UInt(bitPattern: addr))
                if p < range.lowerBound || p >= range.upperBound {
                    score += check.score
                    methods.append("ptr_range:\(check.symbol)")
                    Logger.log("\(ObfuscatedConstants.keywordJailbreak).ptr.hit: \(check.symbol) out_of_text image=\(imagePath) (+\(check.score))")
                }
            }
        }

        return DetectorResult(score: min(score, 100), methods: methods)
    }

    /// 判断镜像路径是否命中可疑令牌。
    /// - Parameter path: 镜像路径。
    /// - Returns: 命中返回 `true`。
    func isSuspiciousImagePath(_ path: String) -> Bool {
        let normalized = path.lowercased()
        return suspiciousImageTokens.contains(where: { normalized.contains($0) })
    }

    /// 判断镜像路径是否位于预期前缀内。
    /// - Parameters:
    ///   - path: 镜像路径。
    ///   - expectedPrefixes: 允许的前缀列表。
    /// - Returns: 命中任一前缀返回 `true`。
    func isExpectedPath(_ path: String, expectedPrefixes: [String]) -> Bool {
        let normalized = path.lowercased()
        return expectedPrefixes.contains(where: { normalized.hasPrefix($0) })
    }

    /// 通过全局符号表解析符号当前地址。
    /// - Parameter symbol: 符号名。
    /// - Returns: 符号地址；不存在返回 `nil`。
    private func resolve(symbol: String) -> UnsafeMutableRawPointer? {
        // -2 即 RTLD_DEFAULT。
        dlsym(UnsafeMutableRawPointer(bitPattern: -2), symbol) // RTLD_DEFAULT
    }

    /// 查询地址所属镜像与基址。
    /// - Parameter addr: 符号地址。
    /// - Returns: `(镜像路径, 镜像基址)`；解析失败返回 `nil`。
    private func dlInfo(_ addr: UnsafeMutableRawPointer) -> (path: String, base: UnsafeRawPointer?)? {
        var info = Dl_info()
        guard dladdr(addr, &info) != 0 else { return nil }
        guard let cPath = info.dli_fname else { return nil }
        let path = String(cString: cPath)
        return (path: path, base: UnsafeRawPointer(info.dli_fbase))
    }
}

/// 解析 Mach-O 镜像的 `__TEXT` 段地址范围。
/// 用于判断某个函数指针是否仍位于其镜像的可执行文本段内。
enum MachOTextRange {
    /// 计算镜像 `__TEXT` 段在内存中的范围。
    /// - Parameter header: 镜像的 mach header 指针。
    /// - Returns: `[起始地址, 结束地址)`；header 非法或找不到 `__TEXT` 时返回 `nil`。
    static func textRange(header: UnsafeRawPointer) -> Range<UInt64>? {
        let h = header.bindMemory(to: mach_header_64.self, capacity: 1).pointee
        // 只支持 64 位 Mach-O。
        guard h.magic == MH_MAGIC_64 || h.magic == MH_CIGAM_64 else { return nil }

        // 从 header 之后逐条遍历 load command，寻找 __TEXT 段。
        var cmdPtr = header.advanced(by: MemoryLayout<mach_header_64>.size)
        for _ in 0..<h.ncmds {
            let lc = cmdPtr.bindMemory(to: load_command.self, capacity: 1).pointee
            if lc.cmd == LC_SEGMENT_64 {
                let seg = cmdPtr.bindMemory(to: segment_command_64.self, capacity: 1).pointee
                let segname = withUnsafeBytes(of: seg.segname) { raw -> String in
                    let bytes = raw.prefix { $0 != 0 }
                    return String(decoding: bytes, as: UTF8.self)
                }
                if segname == "__TEXT" {
                    let start = UInt64(UInt(bitPattern: header))
                    // vmsize 可能溢出 UInt64，溢出时视为不可信并放弃范围校验。
                    let (end, overflow) = start.addingReportingOverflow(seg.vmsize)
                    guard !overflow else { return nil }
                    return start..<end
                }
            }
            // cmdsize 必须合理，防止损坏的 Mach-O 导致死循环或越界。
            guard lc.cmdsize >= MemoryLayout<load_command>.size,
                  lc.cmdsize <= 1024 * 1024 else { break }
            cmdPtr = cmdPtr.advanced(by: Int(lc.cmdsize))
        }
        return nil
    }
}
