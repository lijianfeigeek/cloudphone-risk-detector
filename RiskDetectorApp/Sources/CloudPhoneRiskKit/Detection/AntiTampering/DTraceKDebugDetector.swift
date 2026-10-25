// DTrace/kdebug 活动检测器：从进程环境变量、已加载镜像名、跟踪工具路径、kdebug sysctl
// 四个表面寻找动态跟踪痕迹（dtrace/xctrace/instruments/ktrace），并读取内核调试计数器。
// 计数策略保守：命中 1 个表面只给轻分，≥2 个表面才判定为篡改，降低开发机构建的误报。
// 信号 id 为 SignalID.dtraceKdebugActivity：≥2 个表面 → .tampered(layer 2)，单表面 → .soft(layer 3)。

import Darwin
import Foundation
import MachO

/// 轻量 dtrace/kdebug 活动检测器。
///
/// 仅在非模拟器环境执行；模拟器直接返回 0 分，避免宿主 macOS 的调试工具造成误报。
struct DTraceKDebugDetector: Detector {
    /// 单次采集的证据快照：分别记录四类表面的命中项与内核 kdebug 计数。
    struct Snapshot {
        let envHits: [String]
        let imageHits: [String]
        let toolPathHits: [String]
        let kdebugValues: [String: Int]
    }

    /// 计分结果：`indicatorCount` 是有命中的表面数量，决定最终 state 与 weightHint。
    struct Assessment {
        let score: Double
        let methods: [String]
        let indicatorCount: Int
    }

    /// 调试/跟踪类环境变量；`DYLD_PRINT_*` 会让 dyld 输出加载细节，常见于调试或注入脚本。
    private let suspiciousEnvKeys = [
        "DYLD_PRINT_APIS",
        "DYLD_PRINT_LIBRARIES",
        "DYLD_PRINT_OPTS",
        "OS_ACTIVITY_DT_MODE",
        "MallocStackLogging",
        "DTXConnectionServicesEnabled",
    ]

    /// 已加载镜像名中的跟踪工具关键字；命中说明进程内加载了 dtrace/xctrace 相关库。
    private let suspiciousImageTokens = [
        "dtrace",
        "ktrace",
        "xctrace",
        "instruments",
        "dtinstruments",
        "kdump",
    ]

    /// 越狱设备上常见的跟踪工具落盘路径；用 access(F_OK) 做存在性检查。
    private let suspiciousToolPaths = [
        "/usr/sbin/dtrace",
        "/usr/bin/xctrace",
        "/usr/bin/ktrace",
    ]

    /// 内核调试计数器 sysctl 键；不同 iOS 版本导出的键名不同，逐个尝试，读不到即跳过。
    private let kdebugSysctlKeys = [
        "kern.kdebug",
        "debug.kdebug",
        "kern.kdebug_enable",
    ]

    /// 执行检测；模拟器下无法可靠区分宿主调试工具，直接降级为 0 分。
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["dtrace_kdebug:unavailable_simulator"])
#else
        let snapshot = collectSnapshot()
        let assessment = assess(snapshot: snapshot)
        return DetectorResult(score: assessment.score, methods: assessment.methods)
#endif
    }

    /// 按命中表面数量打分。
    /// - 0 个：干净；1 个：12 分（软怀疑，可能只是开发工具残留）；2 个：38 分；
    /// - ≥3 个：从 50 分起每多一个 +12，封顶 78，避免证据数量线性放大到满分。
    func assess(snapshot: Snapshot) -> Assessment {
        var score: Double = 0
        var methods: [String] = []
        var indicatorCount = 0

        if !snapshot.envHits.isEmpty {
            indicatorCount += 1
            methods.append("dtrace_kdebug:env:\(snapshot.envHits.joined(separator: ","))")
        }
        if !snapshot.imageHits.isEmpty {
            indicatorCount += 1
            methods.append("dtrace_kdebug:image:\(snapshot.imageHits.joined(separator: ","))")
        }
        if !snapshot.toolPathHits.isEmpty {
            indicatorCount += 1
            methods.append("dtrace_kdebug:tool_path:\(snapshot.toolPathHits.joined(separator: ","))")
        }
        if !snapshot.kdebugValues.isEmpty {
            indicatorCount += 1
            let detail = snapshot.kdebugValues
                .map { "\($0.key)=\($0.value)" }
                .sorted()
                .joined(separator: ",")
            methods.append("dtrace_kdebug:kdebug:\(detail)")
        }

        switch indicatorCount {
        case 0:
            return Assessment(score: 0, methods: ["dtrace_kdebug:clean"], indicatorCount: 0)
        case 1:
            // 单表面命中更像开发环境残留，仅给轻分，由上层按软信号处理。
            score = 12
        case 2:
            // 两个独立表面同时命中，误报概率显著下降，进入篡改判定区间。
            score = 38
            methods.append("dtrace_kdebug:multi_surface")
        default:
            // 多表面叠加：每多一个 +12，封顶 78，保留与其它检测器组合加权的空间。
            score = min(50 + Double(indicatorCount - 3) * 12, 78)
            methods.append("dtrace_kdebug:multi_surface")
        }

        return Assessment(score: score, methods: methods, indicatorCount: indicatorCount)
    }

    /// 采集四类表面证据；任何读取失败都按“未命中”处理，不抛错、不中断评估链路。
    private func collectSnapshot() -> Snapshot {
        let environment = ProcessInfo.processInfo.environment
        let envHits: [String] = suspiciousEnvKeys.compactMap { (key: String) -> String? in
            guard let value = environment[key], !value.isEmpty else { return nil }
            return "\(key)=\(value)"
        }

        var imageHits: [String] = []
        let imageCount = _dyld_image_count()
        for index in 0..<imageCount {
            guard let cName = _dyld_get_image_name(index) else { continue }
            let path = String(cString: cName)
            let lower = path.lowercased()
            // 镜像名匹配统一转小写，兼容不同大小写与前缀的路径写法。
            for token in suspiciousImageTokens where lower.contains(token) {
                imageHits.append("\(token)@\(path)")
                break
            }
            // 最多保留 6 条镜像证据即可说明问题，避免畸形进程镜像列表导致长循环。
            if imageHits.count >= 6 { break }
        }

        // access(F_OK) 只判断路径存在，不打开文件，成本低且不产生读 I/O 审计记录。
        let toolPathHits = suspiciousToolPaths.filter { access($0, F_OK) == 0 }
        var kdebugValues: [String: Int] = [:]
        for key in kdebugSysctlKeys {
            // 仅记录 >0 的值：0 表示内核调试未开启，不作为证据。
            if let value = Sysctl.int(key), value > 0 {
                kdebugValues[key] = value
            }
        }

        return Snapshot(
            envHits: envHits,
            // 去重后排序，保证 evidence 字符串稳定，便于服务端做同构比对。
            imageHits: Array(Set(imageHits)).sorted(),
            toolPathHits: toolPathHits,
            kdebugValues: kdebugValues
        )
    }
}

extension DTraceKDebugDetector {
    /// 转换为风险信号：多表面命中判 `tampered`（layer 2, weightHint 82），
    /// 单表面命中仅给 `.soft(confidence: 0.62)`（layer 3, weightHint 44），供上层加权。
    func asSignals() -> [RiskSignal] {
        let snapshot = collectSnapshot()
        let assessment = assess(snapshot: snapshot)
        guard assessment.score > 0 else { return [] }

        let evidence: [String: String] = [
            "indicator_count": "\(assessment.indicatorCount)",
            "env_hits": snapshot.envHits.joined(separator: ","),
            "image_hits": snapshot.imageHits.joined(separator: ","),
            "tool_hits": snapshot.toolPathHits.joined(separator: ","),
            "kdebug_hits": snapshot.kdebugValues
                .map { "\($0.key)=\($0.value)" }
                .sorted()
                .joined(separator: ","),
        ]

        if assessment.indicatorCount >= 2 {
            // ≥2 个独立表面互相印证，足以排除单一工具残留，直接判篡改。
            return [
                RiskSignal(
                    id: SignalID.dtraceKdebugActivity,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: assessment.score,
                    evidence: evidence,
                    state: .tampered,
                    layer: 2,
                    weightHint: 82
                ),
            ]
        }

        // 单表面命中保留软信号：既不漏掉真实跟踪，也不让遗留环境变量抬高风险。
        return [
            RiskSignal(
                id: SignalID.dtraceKdebugActivity,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: assessment.score,
                evidence: evidence,
                state: .soft(confidence: 0.62),
                layer: 3,
                weightHint: 44
            ),
        ]
    }
}
