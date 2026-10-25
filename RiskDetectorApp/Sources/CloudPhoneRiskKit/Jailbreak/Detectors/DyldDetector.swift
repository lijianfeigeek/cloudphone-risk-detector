// Dyld 检测器：枚举当前进程已加载的 Mach-O 镜像，按可疑库名令牌匹配注入框架。
// 位于越狱检测管道中 `enableDyldDetect` 分支，主要针对 Frida/Substrate 等动态注入。
// 关键安全不变量：命中标记会去重，避免同一库的多个镜像重复计分抬高风险。
import Foundation
import MachO

/// 扫描 dyld 镜像列表以发现可疑注入库。
/// 检测什么：已加载镜像数量异常、镜像路径命中可疑令牌（如 Frida、Substrate）。
/// 命中后产生 `dylib_count:<n>`、`dylib:<token>`、`dylib_multi_hit:<n>` 信号，单项 15/25 分。
/// 误报风险：部分合法调试工具或企业内部分发框架也可能命中令牌，因此总分封顶 90。
struct DyldDetector: Detector {
    /// 可疑库名令牌（小写），来自混淆常量表以避免静态字符串特征。
    var suspiciousLibraries: [String] { ObfuscatedConstants.suspiciousLibraryTokensForDyld }

    /// 执行 dyld 镜像扫描。
    /// - Returns: 累计分数封顶 90 的检测结果；单个镜像解析失败会跳过，不影响其余扫描。
    func detect() throws -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []
        // 同一令牌只计一次分，防止同一库的多个镜像放大分数。
        var hitTokens = Set<String>()
        var hitImageCount = 0

        let count = _dyld_image_count()
        // 镜像数量明显偏高通常意味着注入了额外框架；阈值 500 用于过滤正常系统镜像规模。
        if count > 500 {
            score += 15
            methods.append("dylib_count:\(count)")
            Logger.log("jailbreak.dyld.hit: dylib_count=\(count) (+15)")
        }

        for i in 0..<count {
            // 镜像名可能为空（已卸载或异常镜像），直接跳过。
            guard let name = _dyld_get_image_name(i) else { continue }
            let path = String(cString: name).lowercased()
            guard let token = firstSuspiciousToken(in: path) else { continue }
            hitImageCount += 1
            if hitTokens.insert(token).inserted {
                score += 25
                methods.append("dylib:\(token)")
                Logger.log("jailbreak.dyld.hit: \(token) (+25) from=\(path)")
            }
        }

        // 多个不同可疑镜像同时存在时追加组合分，提升高置信度场景的排序。
        if hitImageCount >= 3 {
            score += 10
            methods.append("dylib_multi_hit:\(hitImageCount)")
        }

        return DetectorResult(score: min(score, 90), methods: methods)
    }

    /// 在镜像路径中查找第一个命中的可疑令牌。
    /// - Parameter imagePath: 镜像完整路径（内部会再次转小写以兼容调用方）。
    /// - Returns: 命中的令牌；未命中返回 `nil`。
    func firstSuspiciousToken(in imagePath: String) -> String? {
        let normalized = imagePath.lowercased()
        return suspiciousLibraries.first(where: { normalized.contains($0) })
    }
}
