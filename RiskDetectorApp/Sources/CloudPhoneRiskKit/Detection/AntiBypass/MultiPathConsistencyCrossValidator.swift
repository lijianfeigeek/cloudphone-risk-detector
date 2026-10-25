// 多路径一致性交叉校验：对每个越狱关键路径同时运行 6 个独立探针（3 个普通 + 3 个 secure 直调），
// 要求至少 4 个探针可用，且普通探针与 secure 探针的结论必须互相印证。
// 任何“分组级别”的交叉矛盾都视为高强度篡改，而不是普通文件存在性证据。
// 同时区分“路径不可用/覆盖不足”与“确有矛盾”，避免 secure 探针整体失效时误判。

import Darwin
import Foundation

/// 反绕过检测器：用多探针投票 + 分组交叉校验识别针对单一 API 的 hook。
///
/// 与 `MultiPathFileDetector` 的区别：这里不只看多数派，而是要求 secure 探针组和普通探针组
/// 的结论不能交叉冲突；单组内部可以有少数派（可能是系统差异），跨组冲突才更可能是 hook。
///
/// 需求目标：
/// - 每个路径至少要有 4 个可用探针（且必须包含 secure 探针）。
/// - 任意跨探针矛盾都按高强度篡改处理。
struct MultiPathConsistencyCrossValidator: Detector {
    /// 参与投票的探针；`secure*` 走不经过常规 libc PLT 的直接调用路径，用于对抗 PLT hook。
    enum Probe: String, CaseIterable {
        case coreAccess = "core_access"
        case coreStat = "core_stat"
        case coreFopen = "core_fopen"
        case secureAccess
        case secureStat
        case secureLstat
    }

    /// 单个路径的探针结果集合。
    struct PathFinding {
        /// 被探测的路径。
        let path: String
        /// 所有探针的原始结果；不可用的探针以 false 占位，必须结合 `unavailableProbes` 解读。
        let results: [Probe: Bool]
        /// 调用失败/未返回的探针集合，评估时会被剔除，避免把“不可用”当成“文件不存在”。
        let unavailableProbes: Set<Probe>

        init(path: String, results: [Probe: Bool], unavailableProbes: Set<Probe> = []) {
            self.path = path
            self.results = results
            self.unavailableProbes = unavailableProbes
        }

        /// 仅保留真正返回了结果的探针。
        var availableResults: [Probe: Bool] {
            Dictionary(uniqueKeysWithValues: results.filter { !unavailableProbes.contains($0.key) })
        }
    }

    /// 一次评估的完整产出，既供 `Detector` 使用，也供 `asSignals()` 复用。
    struct Assessment {
        let score: Double
        let methods: [String]
        /// 被判为交叉矛盾的路径，信号 evidence 中会携带其原始探针矩阵。
        let inconsistentFindings: [PathFinding]
        /// secure 探针完全不可用的路径数；用于区分“攻击者屏蔽”与“覆盖不足”。
        let secureUnavailablePathCount: Int
        /// 可用探针数不足最低要求的路径数。
        let insufficientCoveragePathCount: Int
        /// 参与评估的路径总数。
        let evaluatedPathCount: Int
    }

    /// 待校验的关键路径列表，默认来自混淆常量表。
    let criticalPaths: [String]
    /// 每个路径至少需要 4 个可用探针，否则样本太少，投票结果不可信。
    private let minimumProbeCountPerPath = 4
    /// 合法设备上各探针本应趋于一致；少数派至少 2 个才视为稳定分裂，单个离群值可能是偶发失败。
    private let minimumStableSplitPerPath = 2
    /// secure 探针分组，用于与普通探针做跨组对照。
    private let secureProbes: Set<Probe> = [.secureAccess, .secureStat, .secureLstat]

    init(criticalPaths: [String] = ObfuscatedConstants.jailbreakConsensusCriticalPaths) {
        self.criticalPaths = criticalPaths
    }

    /// 执行校验并返回分数；模拟器下所有路径语义都不可信，直接返回 0 并标注跳过原因。
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["multipath_consistency:unavailable_simulator"])
#else
        let findings = criticalPaths.map(probePath)
        let assessment = assess(findings: findings)
        return DetectorResult(score: assessment.score, methods: assessment.methods)
#endif
    }

    /// 对一批路径结果做覆盖率过滤、分组交叉校验与打分。
    ///
    /// 判定链：探针覆盖足够 → 组内出现稳定分裂 → secure 组与普通组结论交叉冲突，
    /// 三者同时成立才计为不一致；任何一步不满足都跳过，以压低误报。
    func assess(findings: [PathFinding]) -> Assessment {
        var inconsistent: [PathFinding] = []
        var methods: [String] = []
        var secureUnavailablePathCount = 0
        var insufficientCoveragePathCount = 0

        for finding in findings {
            let available = finding.availableResults
            let secureAvailable = Dictionary(uniqueKeysWithValues: available.filter { secureProbes.contains($0.key) })
            let standardAvailable = Dictionary(uniqueKeysWithValues: available.filter { !secureProbes.contains($0.key) })

            if secureAvailable.isEmpty {
                secureUnavailablePathCount += 1
            }
            // 覆盖不足时无法做出可信结论：计入统计但不参与矛盾判定，避免“探针全挂”被误报成篡改。
            if available.count < minimumProbeCountPerPath || secureAvailable.isEmpty {
                insufficientCoveragePathCount += 1
                continue
            }

            let trueCount = available.values.filter { $0 }.count
            let falseCount = available.count - trueCount
            // 全部一致时没有矛盾，直接跳过。
            guard trueCount > 0, falseCount > 0 else { continue }

            // 少数派至少 2 个才认为分裂是稳定现象，单个离群探针可能只是瞬时失败。
            let stableSplit = min(trueCount, falseCount) >= minimumStableSplitPerPath
            guard stableSplit else { continue }

            let secureTrueCount = secureAvailable.values.filter { $0 }.count
            let secureFalseCount = secureAvailable.count - secureTrueCount
            let standardTrueCount = standardAvailable.values.filter { $0 }.count
            let standardFalseCount = standardAvailable.count - standardTrueCount
            // 关键判据：secure 组说存在而普通组说不存在（或反之）。单组内部的分裂可能源于系统差异，
            // 跨组反向才强烈指向某一路径被 hook。
            let crossMismatch = (secureTrueCount > 0 && standardFalseCount > 0)
                || (secureFalseCount > 0 && standardTrueCount > 0)
            guard crossMismatch else { continue }

            // evidence 中同时保留 true/false 两组探针名，便于后端定位被 hook 的具体调用。
            let trueProbes = available
                .filter { $0.value }
                .map(\.key.rawValue)
                .sorted()
                .joined(separator: ",")
            let falseProbes = available
                .filter { !$0.value }
                .map(\.key.rawValue)
                .sorted()
                .joined(separator: ",")
            methods.append("multipath_consistency:inconsistent:\(finding.path):t=\(trueProbes):f=\(falseProbes)")
            inconsistent.append(finding)
        }

        let evaluatedPathCount = findings.count
        let coveredPathCount = max(0, evaluatedPathCount - insufficientCoveragePathCount)
        // 把覆盖率和 secure 可用性放在 methods 最前面，便于日志优先暴露“数据是否可信”。
        methods.insert("multipath_consistency:coverage:\(coveredPathCount)/\(evaluatedPathCount)", at: 0)
        methods.insert("multipath_consistency:secure_unavailable_paths:\(secureUnavailablePathCount)", at: 1)

        guard !inconsistent.isEmpty else {
            // 没有矛盾时进一步区分原因：secure 全挂是“降级”，覆盖不足是“样本不够”，否则为干净。
            if evaluatedPathCount > 0 && secureUnavailablePathCount == evaluatedPathCount {
                methods.append("multipath_consistency:secure_path_unavailable_degraded")
            } else if insufficientCoveragePathCount > 0 {
                methods.append("multipath_consistency:insufficient_probe_coverage")
            } else {
                methods.append("multipath_consistency:clean")
            }
            return Assessment(
                score: 0,
                methods: methods,
                inconsistentFindings: [],
                secureUnavailablePathCount: secureUnavailablePathCount,
                insufficientCoveragePathCount: insufficientCoveragePathCount,
                evaluatedPathCount: evaluatedPathCount
            )
        }

        // 首条矛盾即给 72 分（已属高危），每多一条 +6，封顶 90，避免单一路径异常把总分推到极值。
        let score = min(72 + Double(max(0, inconsistent.count - 1)) * 6, 90)
        return Assessment(
            score: score,
            methods: methods,
            inconsistentFindings: inconsistent,
            secureUnavailablePathCount: secureUnavailablePathCount,
            insufficientCoveragePathCount: insufficientCoveragePathCount,
            evaluatedPathCount: evaluatedPathCount
        )
    }

    /// 对单个路径采集两套快照：普通直调与 secure 直调。
    /// 快照返回 nil 表示该探针不可用，会被记录进 `unavailableProbes`，而不是当成 false 参与投票。
    private func probePath(_ path: String) -> PathFinding {
        var results: [Probe: Bool] = [:]
        var unavailableProbes = Set<Probe>()
        let standardSnapshot = SVCDirectCall.standardPathProbeSnapshot(path)
        results[.coreAccess] = standardSnapshot.access ?? false
        results[.coreStat] = standardSnapshot.stat ?? false
        results[.coreFopen] = standardSnapshot.fopen ?? false
        if standardSnapshot.access == nil { unavailableProbes.insert(.coreAccess) }
        if standardSnapshot.stat == nil { unavailableProbes.insert(.coreStat) }
        if standardSnapshot.fopen == nil { unavailableProbes.insert(.coreFopen) }
        let secureSnapshot = SVCDirectCall.securePathProbeSnapshot(path)
        results[.secureAccess] = secureSnapshot.access ?? false
        results[.secureStat] = secureSnapshot.stat ?? false
        results[.secureLstat] = secureSnapshot.lstat ?? false
        if secureSnapshot.access == nil { unavailableProbes.insert(.secureAccess) }
        if secureSnapshot.stat == nil { unavailableProbes.insert(.secureStat) }
        if secureSnapshot.lstat == nil { unavailableProbes.insert(.secureLstat) }
        return PathFinding(path: path, results: results, unavailableProbes: unavailableProbes)
    }

}

/// 信号输出：把交叉校验结果包装成 `RiskSignal`，供上层信号管道消费。
extension MultiPathConsistencyCrossValidator {
    /// 将一次交叉校验结果转换为 `RiskSignal`，供信号管道计分与上报。
    /// - 失败即拒绝：只有分数 > 0 才产出信号，干净/降级状态返回空数组。
    /// - `weightHint` 92 表示强篡改证据；layer 2 对应运行时完整性层。
    func asSignals() -> [RiskSignal] {
        let findings = criticalPaths.map(probePath)
        let assessment = assess(findings: findings)
        guard assessment.score > 0 else { return [] }

        // detail 采用“路径[探针=0/1]{不可用列表}”的紧凑格式，便于后端还原每个探针的原始结论。
        let details = assessment.inconsistentFindings.map { finding in
            let values = finding.availableResults
                .map { "\($0.key.rawValue)=\($0.value ? "1" : "0")" }
                .sorted()
                .joined(separator: ",")
            let unavailable = finding.unavailableProbes
                .map(\.rawValue)
                .sorted()
                .joined(separator: ",")
            return "\(finding.path)[\(values)]{unavailable=\(unavailable)}"
        }.joined(separator: ";")

        return [
            RiskSignal(
                id: SignalID.multiPathCrossInconsistency,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: assessment.score,
                evidence: [
                    "path_count": "\(assessment.inconsistentFindings.count)",
                    "evaluated_path_count": "\(assessment.evaluatedPathCount)",
                    "secure_unavailable_path_count": "\(assessment.secureUnavailablePathCount)",
                    "insufficient_coverage_path_count": "\(assessment.insufficientCoveragePathCount)",
                    "detail": details,
                ],
                state: .tampered,
                layer: 2,
                weightHint: 92
            ),
        ]
    }
}
