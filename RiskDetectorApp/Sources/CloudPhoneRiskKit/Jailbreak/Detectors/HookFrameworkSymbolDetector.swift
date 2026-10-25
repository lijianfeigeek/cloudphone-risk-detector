// Hook 框架符号检测器：用 dlsym 探测 Substrate/fishhook/Frida 等框架导出的符号。
// 位于 HookDetector 的子检测器链中，负责发现“框架已加载并导出 hook API”这一事实。
// 关键安全不变量：符号存在本身按权重计分；若其落点还是非系统镜像则追加路径证据。
import Darwin
import Foundation

/// 通过导出符号探测 hook 框架。
/// 检测什么：`MSHookFunction`、`substitute_hook_functions`、`gum_interceptor_attach`、Frida agent 等符号。
/// 命中后产生 `hook_symbol:<name>` 信号（单项 10–20 分），落点异常时追加 `hook_symbol_path:<name>`（+4）。
/// 误报风险：符号名匹配依赖框架保留导出名；混淆过的框架可能漏检，而未剥离符号的合法库可能误报。
struct HookFrameworkSymbolDetector: Detector {
    /// 可疑导出符号及权重。
    /// 符号名由混淆关键字拼接而成，避免在二进制中留下完整明文特征。
    let suspiciousSymbols: [(name: String, score: Double)] = [
        ("MS\(ObfuscatedConstants.keywordHook.capitalized)Function", 20),
        ("MS\(ObfuscatedConstants.keywordHook.capitalized)MessageEx", 20),
        ("MS\(ObfuscatedConstants.keywordHook.capitalized)Memory", 18),
        ("MSFindSymbol", 12),
        ("substitute_\(ObfuscatedConstants.keywordHook)_functions", 15),
        ("substitute_\(ObfuscatedConstants.keywordHook)_objc_message", 15),
        ("LH\(ObfuscatedConstants.keywordHook.capitalized)Functions", 15),
        ("rebind_symbols", 10),
        ("rebind_symbols_image", 10),
        ("fish\(ObfuscatedConstants.keywordHook)_rebind_symbols", 10),
        ("gum_interceptor_attach", 20),
        ("gum_module_find_export_by_name", 16),
        ("\(ObfuscatedConstants.keywordFrida)_agent_main", 20),
    ]

    /// 可疑镜像路径令牌（核心集合，用于路径二次确认）。
    let suspiciousImageTokens: [String] = ObfuscatedConstants.hookSuspiciousImageTokensCore

    /// 执行符号探测。
    /// - Returns: 累计分数封顶 90 的检测结果；符号不存在时静默跳过。
    func detect() throws -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []
        for item in suspiciousSymbols {
            // -2 即 RTLD_DEFAULT，在当前进程全局符号表中查找。
            guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), item.name) else { continue }
            score += item.score
            methods.append("\(ObfuscatedConstants.keywordHook)_symbol:\(item.name)")

            // 符号存在且落点可疑/非系统路径：追加 +4，进一步锁定注入库。
            if let path = imagePath(of: symbol), isSuspiciousImagePath(path) || !isTrustedSystemPath(path) {
                score += 4
                methods.append("\(ObfuscatedConstants.keywordHook)_symbol_path:\(item.name)")
                Logger.log("\(ObfuscatedConstants.keywordJailbreak).\(ObfuscatedConstants.keywordHook).hit: exported_symbol=\(item.name) path=\(path) (+\(item.score + 4))")
            } else {
                Logger.log("\(ObfuscatedConstants.keywordJailbreak).\(ObfuscatedConstants.keywordHook).hit: exported_symbol=\(item.name) (+\(item.score))")
            }
        }
        return DetectorResult(score: min(score, 90), methods: methods)
    }

    /// 判断镜像路径是否命中可疑令牌。
    /// - Parameter path: 镜像路径。
    /// - Returns: 命中返回 `true`。
    func isSuspiciousImagePath(_ path: String) -> Bool {
        let normalized = path.lowercased()
        return suspiciousImageTokens.contains(where: { normalized.contains($0) })
    }

    /// 判断镜像路径是否为可信系统库。
    /// - Parameter path: 镜像路径。
    /// - Returns: 命中系统前缀返回 `true`。
    func isTrustedSystemPath(_ path: String) -> Bool {
        let normalized = path.lowercased()
        return normalized.hasPrefix("/usr/lib/system/")
            || normalized.hasPrefix("/usr/lib/libsystem")
            || normalized.hasPrefix("/usr/lib/libobjc.")
            || normalized.hasPrefix("/system/library/")
    }

    /// 解析符号所属镜像路径。
    /// - Parameter symbol: 已解析的符号地址。
    /// - Returns: 镜像路径；`dladdr` 失败或无文件名时返回 `nil`。
    private func imagePath(of symbol: UnsafeMutableRawPointer) -> String? {
        var info = Dl_info()
        guard dladdr(symbol, &info) != 0, let cPath = info.dli_fname else { return nil }
        return String(cString: cPath)
    }
}
