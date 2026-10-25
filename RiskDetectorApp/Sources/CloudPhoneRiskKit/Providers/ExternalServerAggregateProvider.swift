import CryptoKit
import Foundation

// 服务端聚合信号 Provider。
// 承载服务端/联调注入的 IP、ASN、机房、IP 聚合度与图风控特征，并将其转为 RiskSignal。
// 端侧注入默认不可信：只有经 CPRisk-MAC 验签的 `setVerified` 数据才被采信；
// 服务端必须以自己聚合的信息为准，端侧 `server` 字段仅用于回显/联调。

/// 服务端聚合信号的本地注入点与验签入口。
/// 线程安全：内部状态由 `UnfairLock` 保护；验签使用独立 generation 防止并发覆盖。
final class ExternalServerAggregateProvider: RiskSignalProvider {
    static let shared = ExternalServerAggregateProvider()
    private init() {}

    /// 图风控反馈应用后发送，业务侧可观察此通知并调用 evaluate() 重新评估风险。
    public static let graphRiskFeedbackDidApplyNotification = Notification.Name("CloudPhoneRiskKit.graphRiskFeedbackDidApply")

    let id = "server_aggregate"

    private let lock = UnfairLock()
    private var current: ServerSignals?
    /// `current` 是否经 `setVerified(_:signature:)` 验签接受。
    /// 未验签的端侧注入（`setDebugBypassingVerification`，仅 DEBUG）默认不被采信：
    /// `serverSignals()` / `signals()` 会丢弃它。服务端必须忽略端侧上报的
    /// `server` 字段，仅以服务端自己聚合的 IP/ASN/机房信息为准；端侧 `server`
    /// 字段只能作为联调回显，不得参与服务端判决。
    private var currentIsVerified: Bool = false
    private var graphFeatures: GraphFeatures?
    private var serverSignalKey: SymmetricKey?
    // 密钥或会话变更时递增，使已经在途的验签结果失效，避免旧数据被回写。
    private var verificationGeneration: UInt64 = 0
    private var realtimeTelemetryFeedback: RealtimeTelemetryFeedback?

    /// 图风控特征（社区、风险密度、硬件画像度数等），由服务端图计算返回。
    struct GraphFeatures {
        var communityId: String?
        var communityRiskDensity: Double?
        var hwProfileDegree: Int?
        var devicePageRank: Double?
        var isInDenseSubgraph: Bool?
        var riskTags: [String]?
    }

    /// 实时遥测反馈：动态调整评估频率与权重倍率。
    /// - `riskPressure` 0...1；`minEvaluationIntervalMillis` 0...60000；
    /// - `*WeightScaleBps` 以万分比表示权重倍率，合法范围 1000...20000。
    struct RealtimeTelemetryFeedback: Sendable {
        var riskPressure: Double?
        var minEvaluationIntervalMillis: Int?
        var defaultWeightScaleBps: Int?
        var categoryWeightScaleBps: [String: Int]
        var expiresAtEpochSeconds: TimeInterval?

        init(
            riskPressure: Double? = nil,
            minEvaluationIntervalMillis: Int? = nil,
            defaultWeightScaleBps: Int? = nil,
            categoryWeightScaleBps: [String: Int] = [:],
            expiresAtEpochSeconds: TimeInterval? = nil
        ) {
            self.riskPressure = riskPressure
            self.minEvaluationIntervalMillis = minEvaluationIntervalMillis
            self.defaultWeightScaleBps = defaultWeightScaleBps
            self.categoryWeightScaleBps = categoryWeightScaleBps
            self.expiresAtEpochSeconds = expiresAtEpochSeconds
        }
    }

    /// 清理后的实时自适应快照，供评估管线读取。
    struct RealtimeAdaptiveFeedbackSnapshot: Sendable {
        let riskPressure: Double?
        let minEvaluationIntervalMillis: Int?
        let defaultWeightScaleBps: Int?
        let categoryWeightScaleBps: [String: Int]
        let source: String
    }

    /// 从 riskTags 解析出的自适应提示；`hasAny` 表示至少有一项有效。
    private struct AdaptiveTagHints {
        var riskPressure: Double?
        var minEvaluationIntervalMillis: Int?
        var defaultWeightScaleBps: Int?
        var categoryWeightScaleBps: [String: Int] = [:]

        var hasAny: Bool {
            riskPressure != nil
                || minEvaluationIntervalMillis != nil
                || defaultWeightScaleBps != nil
                || !categoryWeightScaleBps.isEmpty
        }
    }

    /// 清空图特征，避免跨账号/跨会话残留。
    func clearGraphFeatures() {
        lock.withLock { graphFeatures = nil }
    }

    /// 注入实时遥测反馈（本地联调或服务端回注）。
    /// 该反馈用于动态调整评估频率与权重倍率。
    func setRealtimeTelemetryFeedback(_ feedback: RealtimeTelemetryFeedback?) {
        lock.withLock {
            realtimeTelemetryFeedback = sanitizedRealtimeTelemetryFeedback(feedback)
        }
    }

    func clearRealtimeTelemetryFeedback() {
        lock.withLock { realtimeTelemetryFeedback = nil }
    }

    /// 配置 CPRisk-MAC 验签密钥。
    /// - 空 Data 表示禁用验签；同时清空旧数据并递增 generation，使在途验签失效。
    func configureServerSignalKey(_ key: Data) {
        lock.withLock {
            verificationGeneration &+= 1
            serverSignalKey = key.isEmpty ? nil : SymmetricKey(data: key)
            current = nil
            currentIsVerified = false
        }
    }

    /// 清空服务端信号和图特征，Release 下始终可用（用于 clearExternalServerSignals）。
    func clear() {
        lock.withLock {
            verificationGeneration &+= 1
            current = nil
            currentIsVerified = false
            graphFeatures = nil
            realtimeTelemetryFeedback = nil
        }
        Logger.log("server_aggregate.clear")
    }

    @available(*, deprecated, message: "Use setVerified(_:signature:) instead")
    func set(_ signals: ServerSignals?) {
        setDebugBypassingVerification(signals)
    }

    func setDebugBypassingVerification(_ signals: ServerSignals?) {
        if signals == nil {
            clear()
            return
        }
        #if DEBUG
        lock.withLock {
            verificationGeneration &+= 1
            current = signals
            // 未验签：默认不被采信（serverSignals/signals 会丢弃）。
            currentIsVerified = false
        }
        Logger.log("server_aggregate.set (deprecated): set")
        #else
        Logger.log("server_aggregate.set rejected: use setVerified in Release builds")
        #endif
    }

    /// 接受服务端信号，但必须先通过自定义 SHA-256 MAC 验签。
    /// 签名算法：`signature = MAC(serverSignalKey, canonicalJSON(signals))`（键排序后的 JSON）。
    /// - Returns: 验签并成功写入返回 true；无密钥、编码失败、MAC 不符或期间密钥变更返回 false。
    @discardableResult
    func setVerified(_ signals: ServerSignals, signature: Data) -> Bool {
        let (key, generation) = lock.withLock { (serverSignalKey, verificationGeneration) }
        guard let capturedKey = key else {
            Logger.log("server_aggregate.setVerified rejected: no key configured")
            return false
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        guard let payload = try? encoder.encode(signals) else {
            Logger.log("server_aggregate.setVerified rejected: encode failed")
            return false
        }

        guard CPRiskMessageAuth.isValidAuthenticationCode(signature, authenticating: payload, using: capturedKey) else {
            Logger.log("server_aggregate.setVerified rejected: MAC mismatch")
            return false
        }

        let accepted = lock.withLock { () -> Bool in
            // 验签期间若密钥被替换或 clear() 递增了 generation，则丢弃本次结果，防止旧会话数据复活。
            guard verificationGeneration == generation, serverSignalKey != nil else { return false }
            current = signals
            currentIsVerified = true
            return true
        }
        if !accepted {
            Logger.log("server_aggregate.setVerified rejected: key or session changed during verification")
            return false
        }
        Logger.log("server_aggregate.setVerified: accepted")
        return true
    }

    /// 注入图风控特征（可由服务端图计算结果转换而来）。
    func setGraphFeatures(
        communityId: String?,
        communityRiskDensity: Double?,
        hwProfileDegree: Int?,
        devicePageRank: Double?,
        isInDenseSubgraph: Bool?,
        riskTags: [String]?
    ) {
        lock.withLock {
            graphFeatures = GraphFeatures(
                communityId: communityId,
                communityRiskDensity: communityRiskDensity,
                hwProfileDegree: hwProfileDegree,
                devicePageRank: devicePageRank,
                isInDenseSubgraph: isInDenseSubgraph,
                riskTags: riskTags
            )
        }
        #if DEBUG
        Logger.log("server_aggregate.setGraphFeatures: community=\(communityId ?? "nil")")
        #endif
    }

    /// 应用图风控反馈：服务端返回图计算结果后注入，用于增强本地评分。
    /// 注入后更新 graphFeatures，并发送 `graphRiskFeedbackDidApply` 通知，供业务侧触发 re-evaluate。
    /// 业务侧可观察该通知，在收到后调用 `CPRiskKit.shared.evaluate(...)` 重新评估风险。
    /// - Parameter feedback: 图风控反馈（communityId、communityRiskDensity 等）
    func applyGraphRiskFeedback(_ feedback: GraphRiskFeedback) {
        setGraphFeatures(
            communityId: feedback.communityId,
            communityRiskDensity: feedback.communityRiskDensity,
            hwProfileDegree: feedback.hwProfileDegree,
            devicePageRank: feedback.devicePageRank,
            isInDenseSubgraph: feedback.isInDenseSubgraph,
            riskTags: feedback.riskTags
        )
        NotificationCenter.default.post(
            name: Self.graphRiskFeedbackDidApplyNotification,
            object: self
        )
    }

    /// 生成“实时遥测自适应”快照：显式反馈优先，riskTags 可覆盖。
    /// 若无可用反馈，返回 nil（调用方应回退到静态配置）。
    func realtimeAdaptiveFeedbackSnapshot(nowEpochSeconds: TimeInterval = Date().timeIntervalSince1970) -> RealtimeAdaptiveFeedbackSnapshot? {
        // 未验签的端侧 server 信号不参与自适应（riskTags 提示同理）。
        let (rawCurrent, verified, gf, explicitFeedback) = lock.withLock { (current, currentIsVerified, graphFeatures, realtimeTelemetryFeedback) }
        let s = verified ? rawCurrent : nil
        var sourceTags: [String] = []

        var riskPressure: Double?
        var minEvaluationIntervalMillis: Int?
        var defaultWeightScaleBps: Int?
        var categoryWeightScaleBps: [String: Int] = [:]

        if let explicitFeedback, !isExpired(explicitFeedback, nowEpochSeconds: nowEpochSeconds) {
            riskPressure = explicitFeedback.riskPressure
            minEvaluationIntervalMillis = explicitFeedback.minEvaluationIntervalMillis
            defaultWeightScaleBps = explicitFeedback.defaultWeightScaleBps
            categoryWeightScaleBps = explicitFeedback.categoryWeightScaleBps
            sourceTags.append("explicit")
        }

        let mergedTags = (s?.riskTags ?? []) + (gf?.riskTags ?? [])
        let tagHints = parseAdaptiveTagHints(from: mergedTags)
        if tagHints.hasAny {
            if let pressure = tagHints.riskPressure {
                riskPressure = pressure
            }
            if let interval = tagHints.minEvaluationIntervalMillis {
                minEvaluationIntervalMillis = interval
            }
            if let bps = tagHints.defaultWeightScaleBps {
                defaultWeightScaleBps = bps
            }
            if !tagHints.categoryWeightScaleBps.isEmpty {
                categoryWeightScaleBps.merge(tagHints.categoryWeightScaleBps) { _, rhs in rhs }
            }
            sourceTags.append("risk_tags")
        }

        guard riskPressure != nil
            || minEvaluationIntervalMillis != nil
            || defaultWeightScaleBps != nil
            || !categoryWeightScaleBps.isEmpty else {
            return nil
        }

        return RealtimeAdaptiveFeedbackSnapshot(
            riskPressure: riskPressure,
            minEvaluationIntervalMillis: minEvaluationIntervalMillis,
            defaultWeightScaleBps: defaultWeightScaleBps,
            categoryWeightScaleBps: categoryWeightScaleBps,
            source: sourceTags.isEmpty ? "unknown" : sourceTags.joined(separator: "+")
        )
    }

    /// 返回合并后的服务端信号，仅包含验签数据与图特征；二者都没有时返回 nil。
    func serverSignals(snapshot: RiskSnapshot) -> ServerSignals? {
        // 仅采信验签来源的 server 信号；未验签的端侧注入默认丢弃。
        // 即使验签通过，服务端也必须忽略端侧 `server` 字段、仅以服务端聚合为准。
        let (s, verified, gf) = lock.withLock { (current, currentIsVerified, graphFeatures) }
        let trusted = verified ? s : nil
        guard trusted != nil || gf != nil else { return nil }
        var merged = trusted ?? ServerSignals()
        if let gf {
            merged.communityId = gf.communityId
            merged.communityRiskDensity = gf.communityRiskDensity
            merged.hwProfileDegree = gf.hwProfileDegree
            merged.devicePageRank = gf.devicePageRank
            merged.isInDenseSubgraph = gf.isInDenseSubgraph
            if let tags = gf.riskTags, !tags.isEmpty {
                var existing = merged.riskTags ?? []
                existing.append(contentsOf: tags)
                merged.riskTags = existing
            }
        }
        return merged
    }

    /// 把服务端/图特征转换为评分信号。
    /// - IP/ASN/AS Org/riskTags 以 `.serverRequired` 上报，由服务端最终判定；
    /// - 数据中心、IP 聚合度、图风险直接带分数，参与本地评分；
    /// - 未验签的端侧注入不会产生任何信号。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        // 与 serverSignals() 一致：未验签的端侧 server 信号不产生评分信号。
        let (rawSignals, verified, gf) = lock.withLock { (current, currentIsVerified, graphFeatures) }
        let s = verified ? rawSignals : nil
        guard s != nil || gf != nil else { return [] }

        var out: [RiskSignal] = []

        if let s {
        if let ip = s.publicIP, !ip.isEmpty {
            out.append(
                RiskSignal(
                    id: "server_public_ip",
                    category: "server",
                    score: 0,
                    evidence: ["public_ip": ip],
                    state: .serverRequired,
                    layer: 4
                )
            )
        }

        if let asn = s.asn, !asn.isEmpty {
            out.append(
                RiskSignal(
                    id: "server_asn",
                    category: "server",
                    score: 0,
                    evidence: ["asn": asn],
                    state: .serverRequired,
                    layer: 4
                )
            )
        }

        if let asOrg = s.asOrg, !asOrg.isEmpty {
            out.append(
                RiskSignal(
                    id: "server_as_org",
                    category: "server",
                    score: 0,
                    evidence: ["as_org": asOrg],
                    state: .serverRequired,
                    layer: 4
                )
            )
        }

        if s.isDatacenter == true {
            // 机房 IP 是强代理特征，直接给 20 分。
            out.append(RiskSignal(id: SignalID.datacenterIP, category: SignalCategory.server, score: 20, evidence: ["is_datacenter": "true"]))
        }

        if let n = s.ipDeviceAgg {
            // 同一 IP 关联设备数分档：200+ / 50+ / 20+ 分别计 25/15/8 分。
            let score: Double
            if n >= 200 { score = 25 }
            else if n >= 50 { score = 15 }
            else if n >= 20 { score = 8 }
            else { score = 0 }
            if score > 0 {
                out.append(RiskSignal(id: SignalID.ipDeviceAgg, category: SignalCategory.server, score: score, evidence: ["ip_device_agg": "\(n)"]))
            }
        }

        if let n = s.ipAccountAgg {
            // 同一 IP 关联账号数分档：500+ / 100+ / 30+ 分别计 25/15/8 分。
            let score: Double
            if n >= 500 { score = 25 }
            else if n >= 100 { score = 15 }
            else if n >= 30 { score = 8 }
            else { score = 0 }
            if score > 0 {
                out.append(RiskSignal(id: SignalID.ipAccountAgg, category: SignalCategory.server, score: score, evidence: ["ip_account_agg": "\(n)"]))
            }
        }

        if let tags = s.riskTags, !tags.isEmpty {
            out.append(
                RiskSignal(
                    id: "risk_tags",
                    category: "server",
                    score: 0,
                    evidence: ["tags": tags.joined(separator: ",")],
                    state: .serverRequired,
                    layer: 4
                )
            )
        }
        }

        if let gf {
            // 社区风险密度 > 50 才计分，80 以上给 20 分。
            if let density = gf.communityRiskDensity, density > 50 {
                let score: Double = density > 80 ? 20 : (density > 65 ? 12 : 5)
                out.append(RiskSignal(
                    id: "graph_community_risk",
                    category: "server",
                    score: score,
                    evidence: [
                        "community_id": gf.communityId ?? "unknown",
                        "risk_density": "\(density)"
                    ],
                    state: .serverRequired,
                    layer: 4
                ))
            }

            // 硬件画像度数反映同型号/同配置设备聚集程度，10 以上开始计分。
            if let degree = gf.hwProfileDegree, degree >= 10 {
                let score: Double = degree >= 100 ? 20 : (degree >= 50 ? 15 : 8)
                out.append(RiskSignal(
                    id: "graph_hw_profile_cluster",
                    category: "server",
                    score: score,
                    evidence: ["hw_profile_degree": "\(degree)"],
                    state: .serverRequired,
                    layer: 4
                ))
            }

            if gf.isInDenseSubgraph == true {
                out.append(RiskSignal(
                    id: "graph_dense_subgraph",
                    category: "server",
                    score: 15,
                    evidence: ["in_dense_subgraph": "true"],
                    state: .serverRequired,
                    layer: 4
                ))
            }
        }

        return out
    }

    /// 清洗注入的实时反馈：丢弃非有限值、越界值与未知分类键。
    private func sanitizedRealtimeTelemetryFeedback(_ feedback: RealtimeTelemetryFeedback?) -> RealtimeTelemetryFeedback? {
        guard var feedback else { return nil }

        feedback.riskPressure = sanitizedPressure(feedback.riskPressure)
        feedback.minEvaluationIntervalMillis = sanitizedInterval(feedback.minEvaluationIntervalMillis)
        feedback.defaultWeightScaleBps = sanitizedWeightBps(feedback.defaultWeightScaleBps)

        if !feedback.categoryWeightScaleBps.isEmpty {
            var sanitized: [String: Int] = [:]
            for (rawKey, rawValue) in feedback.categoryWeightScaleBps {
                guard let key = Self.normalizedWeightKey(rawKey),
                      let value = sanitizedWeightBps(rawValue) else {
                    continue
                }
                sanitized[key] = value
            }
            feedback.categoryWeightScaleBps = sanitized
        }

        return feedback
    }

    /// 反馈是否已过期；无过期时间视为永久有效。
    private func isExpired(_ feedback: RealtimeTelemetryFeedback, nowEpochSeconds: TimeInterval) -> Bool {
        guard let expiresAt = feedback.expiresAtEpochSeconds else {
            return false
        }
        return expiresAt < nowEpochSeconds
    }

    /// 解析 `rt_pressure:`、`rt_eval_ms:`、`rt_weight_bps:` 等标签形式的自适应提示。
    private func parseAdaptiveTagHints(from tags: [String]) -> AdaptiveTagHints {
        guard !tags.isEmpty else { return AdaptiveTagHints() }

        var hints = AdaptiveTagHints()
        for rawTag in tags {
            let tag = rawTag.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if tag.isEmpty { continue }

            if let value = parseDoubleTag(tag, prefix: "rt_pressure:") {
                // 允许 0...1 或 0...100 两种写法，大于 1 时按百分比归一化。
                let normalized = value > 1.0 ? value / 100.0 : value
                hints.riskPressure = sanitizedPressure(normalized)
                continue
            }
            if let value = parseIntTag(tag, prefix: "rt_eval_ms:") {
                hints.minEvaluationIntervalMillis = sanitizedInterval(value)
                continue
            }
            if let value = parseIntTag(tag, prefix: "rt_weight_bps:") {
                hints.defaultWeightScaleBps = sanitizedWeightBps(value)
                continue
            }

            for key in Self.supportedWeightKeys {
                let prefix = "rt_weight_\(key)_bps:"
                if let value = parseIntTag(tag, prefix: prefix),
                   let safeValue = sanitizedWeightBps(value) {
                    hints.categoryWeightScaleBps[key] = safeValue
                    break
                }
            }
        }

        return hints
    }

    private func parseDoubleTag(_ tag: String, prefix: String) -> Double? {
        guard tag.hasPrefix(prefix) else { return nil }
        let raw = String(tag.dropFirst(prefix.count))
        return Double(raw)
    }

    private func parseIntTag(_ tag: String, prefix: String) -> Int? {
        guard tag.hasPrefix(prefix) else { return nil }
        let raw = String(tag.dropFirst(prefix.count))
        return Int(raw)
    }

    /// 把压力值限制在 0...1；NaN/Infinity 返回 nil。
    private func sanitizedPressure(_ value: Double?) -> Double? {
        guard let value, value.isFinite else { return nil }
        return min(max(value, 0), 1)
    }

    /// 把评估间隔限制在 0...60000ms，防止服务端下发异常值拖垮调度。
    private func sanitizedInterval(_ value: Int?) -> Int? {
        guard let value else { return nil }
        return min(max(value, 0), 60_000)
    }

    /// 把权重倍率（万分比）限制在 10%...200%（1000...20000 bps）。
    private func sanitizedWeightBps(_ value: Int?) -> Int? {
        guard let value else { return nil }
        return min(max(value, 1_000), 20_000)
    }

    /// 允许动态调权的分类白名单，避免服务端下发未知键污染评分。
    private static let supportedWeightKeys: Set<String> = [
        "jailbreak",
        "network",
        "behavior",
        "device",
        "time",
    ]

    /// 规范化分类键：去空白、转小写，非白名单返回 nil。
    private static func normalizedWeightKey(_ raw: String) -> String? {
        let normalized = raw
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        return supportedWeightKeys.contains(normalized) ? normalized : nil
    }
}
