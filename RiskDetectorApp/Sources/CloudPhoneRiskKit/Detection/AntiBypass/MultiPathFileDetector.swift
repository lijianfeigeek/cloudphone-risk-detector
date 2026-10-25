// 多路径文件探测：对同一越狱关键路径分别用 access/stat/fopen 三种独立系统调用探测，
// 以“多数一致”判定文件是否存在，出现少数派结果则说明有 hook 只拦截了部分调用路径。
// 另对 /Applications 用 FileManager 与 POSIX readdir 两条路径枚举并比较目录项差异，
// 识别只过滤单一 API 的隐藏目录，结果汇总为 DetectorResult 分数与方法标签。

import Darwin
import Foundation

/// 反绕过检测器：通过多条独立探测路径交叉验证关键文件/目录是否被 hook 隐藏。
///
/// 单一 API 被 hook 时结果会与其他 API 冲突；这里不对冲突做“多数即真相”的简单处理，
/// 而是同时把“共识存在”和“存在冲突”分别计分，避免攻击者只 hook 多数派即可完全隐身。
struct MultiPathFileDetector: Detector {
    /// 参与交叉验证的三条底层调用路径；全部为 libc/POSIX 直调，尽量少经过可被替换的上层 API。
    enum DetectionMethod: String, CaseIterable {
        case coreAccess = "core_access"
        case coreStat = "core_stat"
        case coreFopen = "core_fopen"
    }

    /// 单个路径的多方法探测结果。
    struct MultiPathResult {
        /// 被探测的绝对路径。
        let path: String
        /// 各探测方法的原始结果；缺失的键表示该方法不可用（未参与投票）。
        let methodResults: [DetectionMethod: Bool]
        /// 多数派结论：超过半数方法认为存在时为 true。
        let consensusExists: Bool
        /// 是否存在少数派结果，即疑似只 hook 了部分系统调用。
        let isHooked: Bool
        /// 处于少数派的方法名，用于上报定位 hook 点。
        let hookMethods: [String]
    }

    /// 遍历全部关键路径并汇总分数。
    /// - 多数方法认为文件存在：+25，说明设备确实处于越狱/被篡改环境。
    /// - 方法间结果冲突：+30，比单纯“文件存在”更可疑，因为这意味着探测 API 被选择性拦截。
    /// - 目录枚举不一致：+12，权重较低，避免文件系统正常波动造成误报。
    func detect() throws -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []

        let criticalPaths = ObfuscatedConstants.jailbreakConsensusCriticalPaths

        for path in criticalPaths {
            let result = checkPathWithAllMethods(path)
            if result.consensusExists {
                // 多数方法都能看到该路径，是直接的越狱/篡改证据。
                score += 25
                methods.append("multipart:\(path)")
            }
            if result.isHooked {
                // 探测结果自相矛盾，优先按 hook 处理；与上面的“存在”分数叠加，反映攻击强度。
                score += 30
                methods.append("\(ObfuscatedConstants.methodPrefixMultipartHook)\(path):\(result.hookMethods.joined(separator: ","))")
            }
        }

        if performDirectoryTraversalConsistencyCheck() {
            score += 12
            methods.append("multipart:directory_inconsistency")
        }

        return DetectorResult(score: score, methods: methods)
    }

    /// 用三条路径同时探测单个文件，并区分“共识存在”和“探测结果冲突”。
    /// - 缺失的方法结果不参与投票，避免某个 API 在特定系统版本不可用时被误判为 hook。
    private func checkPathWithAllMethods(_ path: String) -> MultiPathResult {
        var methodResults: [DetectionMethod: Bool] = [:]
        // 一次快照拿到三条直接调用结果，减少探测之间的时间窗口被攻击者利用的机会。
        let standardSnapshot = SVCDirectCall.standardPathProbeSnapshot(path)
        if let accessExists = standardSnapshot.access {
            methodResults[.coreAccess] = accessExists
        }
        if let statExists = standardSnapshot.stat {
            methodResults[.coreStat] = statExists
        }
        if let fopenExists = standardSnapshot.fopen {
            methodResults[.coreFopen] = fopenExists
        }

        let trueCount = methodResults.values.filter { $0 }.count
        let falseCount = methodResults.count - trueCount
        // 以多数派作为“路径是否真实存在”的结论；平票（如两种方法各执一词）视为不存在。
        let consensusExists = trueCount > falseCount

        var hookMethods: [String] = []
        // 只有同时出现 true/false 才存在冲突；一致结果（包括全部失败）不构成 hook 证据。
        if trueCount > 0 && falseCount > 0 {
            let minority = trueCount < falseCount
            hookMethods = methodResults
                .filter { $0.value == minority }
                .map { $0.key.rawValue }
                .sorted()
        }

        return MultiPathResult(
            path: path,
            methodResults: methodResults,
            consensusExists: consensusExists,
            isHooked: !hookMethods.isEmpty,
            hookMethods: hookMethods
        )
    }

    /// 比较 FileManager 与 POSIX readdir 枚举 /Applications 的目录项数量差异。
    /// 只枚举到单一 API 的 hook 会让两条路径看到不同数量的条目。
    private func performDirectoryTraversalConsistencyCheck() -> Bool {
#if targetEnvironment(simulator)
        // 模拟器目录结构不代表真实设备，直接跳过以免产生系统性误报。
        return false
#else
        let directory = "/Applications"
        let fmContents = Set((try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? [])
        let posixContents = getDirectoryContentsViaPosix(directory)

        let maxCount = max(fmContents.count, posixContents.count)
        let minCount = min(fmContents.count, posixContents.count)
        guard maxCount > 0 else { return false }
        // 差异率超过 30% 才判为异常：目录本身会随系统更新变化，阈值过低会误伤正常设备。
        let discrepancy = Double(maxCount - minCount) / Double(maxCount)
        return discrepancy > 0.3
#endif
    }

    /// 绕过 FileManager，直接用 opendir/readdir 读取目录项，作为第二条独立枚举路径。
    private func getDirectoryContentsViaPosix(_ path: String) -> Set<String> {
        var names: Set<String> = []
        guard let dir = opendir(path) else { return names }
        defer { closedir(dir) }

        while let entry = readdir(dir) {
            let name = withUnsafePointer(to: entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
                    String(cString: $0)
                }
            }
            if name != "." && name != ".." {
                names.insert(name)
            }
        }

        return names
    }
}
