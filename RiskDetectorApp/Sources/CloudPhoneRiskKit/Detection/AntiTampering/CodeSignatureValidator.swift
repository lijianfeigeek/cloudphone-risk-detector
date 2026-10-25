// CodeSignatureValidator：检查主 Mach-O 是否存在代码签名命令、
// 是否加载了可疑注入库、以及是否存在 dyld 注入环境变量。
// 是重打包/越狱注入的第一道静态校验，失败时按各项独立计分。
import Darwin
import Foundation
import MachO

/// 代码签名静态校验器。
/// - 线程模型：同步只读遍历 dyld 镜像与主 Mach-O load command。
/// - 失败语义：找不到主镜像或非 64 位头时按“无法判定”放行，避免误报。
struct CodeSignatureValidator: Detector {
    /// 可疑注入库路径 token（混淆常量），小写包含匹配。
    var suspiciousInjectedLibraryTokens: [String] { ObfuscatedConstants.suspiciousInjectedLibraryTokens }

    /// 危险的 dyld 注入环境变量。
    let suspiciousEnvKeys: [String] = [
        "DYLD_INSERT_LIBRARIES",
        "DYLD_FORCE_FLAT_NAMESPACE",
    ]

    /// 执行三项静态检查并汇总分数。
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []

        // 缺少 LC_CODE_SIGNATURE 通常意味着二进制被重打包或改写，25 分。
        if !hasMachOCodeSignatureLoadCommand() {
            score += 25
            methods.append("code_signature:missing_load_command")
        }

        // 加载了路径含可疑 token 的 dylib，20 分。
        if hasSuspiciousInjectedLibrary() {
            score += 20
            methods.append("code_signature:suspicious_dylib")
        }

        // 存在 DYLD_INSERT_LIBRARIES 等注入变量，20 分。
        if let envKey = suspiciousEnvKeys.first(where: { getenv($0) != nil }) {
            score += 20
            methods.append("code_signature:env:\(envKey.lowercased())")
        }

        return DetectorResult(score: score, methods: methods)
#endif
    }

    /// 检查主镜像的 load command 中是否存在 LC_CODE_SIGNATURE。
    private func hasMachOCodeSignatureLoadCommand() -> Bool {
        // 找不到主镜像时返回 true（fail-open），避免把环境差异当成篡改。
        guard let imageIndex = findMainImageIndex(),
              let header = _dyld_get_image_header(imageIndex) else {
            return true
        }

        // 非 64 位 Mach-O 不做判断，返回 true。
        if header.pointee.magic != MH_MAGIC_64 {
            return true
        }

        let header64 = UnsafeRawPointer(header).assumingMemoryBound(to: mach_header_64.self)
        let loadCommandsStart = UnsafeRawPointer(header64).advanced(by: MemoryLayout<mach_header_64>.size)
        let loadCommandsEnd = loadCommandsStart.advanced(by: Int(header64.pointee.sizeofcmds))
        var commandPointer = loadCommandsStart

        let ncmds = header64.pointee.ncmds
        // load command 数量上限 4096，防止畸形 header 导致超长循环。
        guard ncmds <= 4096 else { return false }

        for _ in 0..<ncmds {
            guard commandPointer + MemoryLayout<load_command>.size <= loadCommandsEnd else { break }
            let command = commandPointer.assumingMemoryBound(to: load_command.self).pointee
            let cmdSize = Int(command.cmdsize)
            // cmdsize 上限 1MB，防止越界读取。
            guard cmdSize >= MemoryLayout<load_command>.size, cmdSize <= 0x100000 else { break }
            guard commandPointer.advanced(by: cmdSize) <= loadCommandsEnd else { break }
            if command.cmd == LC_CODE_SIGNATURE {
                return true
            }
            commandPointer = commandPointer.advanced(by: cmdSize)
        }

        return false
    }

    /// 找到路径包含 `.app/` 的主镜像索引。
    private func findMainImageIndex() -> UInt32? {
        let imageCount = _dyld_image_count()
        for index in 0..<imageCount {
            guard let imageName = _dyld_get_image_name(index) else { continue }
            let path = String(cString: imageName)
            if path.contains(".app/") {
                return index
            }
        }
        return nil
    }

    /// 检查已加载镜像中是否存在可疑注入库路径。
    private func hasSuspiciousInjectedLibrary() -> Bool {
        let imageCount = _dyld_image_count()
        for index in 0..<imageCount {
            guard let name = _dyld_get_image_name(index) else { continue }
            let path = String(cString: name)
            if isSuspiciousInjectedLibraryPath(path) {
                return true
            }
        }
        return false
    }

    /// 判断路径是否包含任一可疑注入库 token。
    func isSuspiciousInjectedLibraryPath(_ path: String) -> Bool {
        let normalized = path.lowercased()
        // 统一小写后做包含匹配，覆盖不同大小写/前缀变体。
        return suspiciousInjectedLibraryTokens.contains(where: { normalized.contains($0) })
    }
}
