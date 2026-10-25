// AppSigningIdentityDetector：校验 App 签名身份的一致性，覆盖 IPA 重签/重打包。
// 检查 bundle id（运行时 vs Info.plist vs entitlement）、application-identifier、
// team id、get-task-allow，并与首次运行保存的加密基线比对。
// 强不一致会毒化 code signing lane；弱异常以 soft 信号上报。
import CRiskCore
import CryptoKit
import Foundation
import Security

/// 签名身份检测器。
/// - 线程模型：`inspect()` 同步读取 Bundle 与基线；基线读写在 UnfairLock 下串行化。
/// - 安全不变量：基线必须加密存储；发现强篡改时毒化 code signing lane。
struct AppSigningIdentityDetector: Detector {
    /// Bundle 容器类型：app / appex / 其他（如测试宿主）。
    enum BundleContainer: String, Sendable, Codable {
        case app
        case appExtension = "appex"
        case other
    }

    /// 一次身份采集的快照：entitlement、bundle id、get-task-allow 与容器类型。
    struct IdentitySnapshot: Sendable, Codable, Equatable {
        let teamIdentifierEntitlement: String?
        let applicationIdentifier: String?
        let bundleIdentifier: String?
        let infoPlistBundleIdentifier: String?
        let getTaskAllow: Bool?
        let bundleContainer: BundleContainer

        /// 从 application-identifier 前缀推导 team id（iOS 上 entitlement 不可读时的回退）。
        var derivedTeamIdentifier: String? {
            AppSigningIdentityDetector.teamPrefix(from: applicationIdentifier)
        }

        /// 有效 team id：优先 entitlement，缺失时使用推导值。
        var effectiveTeamIdentifier: String? {
            AppSigningIdentityDetector.normalized(teamIdentifierEntitlement) ?? derivedTeamIdentifier
        }

        /// 有效 bundle id：优先运行时 Bundle，缺失时回退 Info.plist。
        var effectiveBundleIdentifier: String? {
            AppSigningIdentityDetector.normalized(bundleIdentifier)
                ?? AppSigningIdentityDetector.normalized(infoPlistBundleIdentifier)
        }

        /// 描述本次快照覆盖了哪些身份材料，用于遥测与基线资格判断。
        var materialCoverage: String {
            var components: [String] = []
            if AppSigningIdentityDetector.normalized(teamIdentifierEntitlement) != nil {
                components.append("team_entitlement")
            } else if derivedTeamIdentifier != nil {
                components.append("team_derived")
            }
            if AppSigningIdentityDetector.normalized(applicationIdentifier) != nil {
                components.append("application_identifier")
            }
            if effectiveBundleIdentifier != nil {
                components.append("bundle_identifier")
            }
            if getTaskAllow != nil {
                components.append("get_task_allow")
            }
            components.append("container:\(bundleContainer.rawValue)")
            return components.joined(separator: ",")
        }

        /// 身份材料指纹（SHA256），用于检测同一设备上的静默身份变化。
        var bindingFingerprint: String {
            AppSigningIdentityDetector.bindingFingerprint(for: self)
        }

        /// 只有 app/appex 才执行签名身份检查；其他容器直接放行。
        var isExecutableAppContainer: Bool {
            bundleContainer == .app || bundleContainer == .appExtension
        }
    }

    /// 首次运行保存的签名基线三要素。
    struct IdentityBaseline: Codable, Equatable, Sendable {
        let teamIdentifier: String
        let applicationIdentifier: String
        let bundleIdentifier: String
    }

    /// 单条检查发现：信号 id、方法名、分数、证据、状态与是否毒化。
    struct Finding: Sendable, Equatable {
        let signalID: String
        let method: String
        let score: Double
        let evidence: [String: String]
        let state: RiskSignalState
        let weightHint: Double
        let poison: Bool
    }

    /// 一次完整检查的结果集合。
    struct Inspection: Sendable {
        let snapshot: IdentitySnapshot
        let findings: [Finding]
        let baselineStored: Bool

        /// 是否存在需要毒化 code signing lane 的强篡改发现。
        var shouldPoison: Bool {
            findings.contains(where: \.poison)
        }

        /// 所有发现分数之和，封顶 100。
        var score: Double {
            min(findings.reduce(0) { $0 + $1.score }, 100)
        }

        /// 所有发现的方法名，用于 DetectorResult。
        var methods: [String] {
            findings.map(\.method)
        }

        /// 所有发现的信号 id，用于遥测 reason codes。
        var reasonCodes: [String] {
            findings.map(\.signalID)
        }

        /// 状态码：强篡改 -> tampered；无发现 -> clean；否则 soft_anomaly。
        var statusCode: String {
            if shouldPoison {
                return "tampered"
            }
            if findings.isEmpty {
                return "clean"
            }
            return "soft_anomaly"
        }

        /// 基线资格：三要素齐全才允许写入基线，避免把不完整身份固化。
        var baselineEligibility: String {
            if snapshot.effectiveBundleIdentifier == nil {
                return "missing_bundle_identifier"
            }
            if snapshot.applicationIdentifier == nil {
                return "missing_application_identifier"
            }
            if snapshot.effectiveTeamIdentifier == nil {
                return "missing_team_identifier"
            }
            return "eligible"
        }

        /// 遥测字段：状态、指纹、覆盖材料、原因码与基线资格。
        var telemetry: [String: String] {
            var rows: [String: String] = [
                "signing_identity_status": statusCode,
                "signing_identity_fp": snapshot.bindingFingerprint,
                "signing_identity_coverage": snapshot.materialCoverage,
                "signing_identity_reason_codes": reasonCodes.joined(separator: ","),
                "signing_identity_baseline_eligibility": baselineEligibility,
            ]
            if baselineStored {
                rows["signing_identity_baseline_stored"] = "1"
            }
            return rows
        }

        /// 转换为 Detector 协议结果。
        var detectorResult: DetectorResult {
            DetectorResult(score: score, methods: methods)
        }

        /// 转换为 RiskSignal 列表：一条聚合信号 + 每条发现一条细分信号。
        var signals: [RiskSignal] {
            guard !findings.isEmpty else { return [] }

            // 按毒化/非毒化分组，便于证据字段区分。
            let findingIDs = findings.map(\.signalID).sorted()
            let poisonFindingIDs = findings.filter(\.poison).map(\.signalID).sorted()
            let softFindingIDs = findings.filter { !$0.poison }.map(\.signalID).sorted()
            var aggregateEvidence: [String: String] = [
                "methods": methods.joined(separator: ","),
                "team_identifier": snapshot.effectiveTeamIdentifier ?? "nil",
                "derived_team_identifier": snapshot.derivedTeamIdentifier ?? "nil",
                "application_identifier": snapshot.applicationIdentifier ?? "nil",
                "bundle_identifier": snapshot.bundleIdentifier ?? "nil",
                "info_bundle_identifier": snapshot.infoPlistBundleIdentifier ?? "nil",
                "effective_bundle_identifier": snapshot.effectiveBundleIdentifier ?? "nil",
                "get_task_allow": snapshot.getTaskAllow.map { $0 ? "1" : "0" } ?? "nil",
                "finding_ids": findingIDs.joined(separator: ","),
                "finding_count": "\(findingIDs.count)",
                "poison_count": "\(poisonFindingIDs.count)",
                "soft_count": "\(softFindingIDs.count)",
                "team_identifier_source": AppSigningIdentityDetector.teamIdentifierSource(for: snapshot),
                "bundle_container": snapshot.bundleContainer.rawValue,
                "signing_identity_fp": snapshot.bindingFingerprint,
                "signing_identity_coverage": snapshot.materialCoverage,
                "signing_identity_status": statusCode,
                "baseline_eligibility": baselineEligibility,
            ]
            if !poisonFindingIDs.isEmpty {
                aggregateEvidence["poison_finding_ids"] = poisonFindingIDs.joined(separator: ",")
            }
            if !softFindingIDs.isEmpty {
                aggregateEvidence["soft_finding_ids"] = softFindingIDs.joined(separator: ",")
            }
            if !reasonCodes.isEmpty {
                aggregateEvidence["reason_codes"] = reasonCodes.joined(separator: ",")
            }
            if baselineStored {
                aggregateEvidence["baseline_stored"] = "1"
            }

            // 聚合信号：state 由是否存在毒化发现决定。
            var out = [
                RiskSignal(
                    id: ObfuscatedConstants.signalAppSigningIdentityTampered,
                    category: "integrity",
                    score: score,
                    evidence: aggregateEvidence,
                    state: shouldPoison ? .tampered : .soft(confidence: 0.8),
                    layer: 2,
                    weightHint: shouldPoison ? 92 : 68
                ),
            ]

            // 逐条发现单独成信号，保留各自分数与 weightHint。
            out.append(contentsOf: findings.map { finding in
                RiskSignal(
                    id: finding.signalID,
                    category: "integrity",
                    score: finding.score,
                    evidence: finding.evidence,
                    state: finding.state,
                    layer: 2,
                    weightHint: finding.weightHint
                )
            })

            return out
        }
    }

    // 签名基线不再明文存 UserDefaults：AES-GCM 加密文件（SecureFileStore）。
    // 明文基线可被攻击者改写为当前（已篡改）身份，从而掩盖签名变化。
    /// 签名基线不再明文存 UserDefaults：AES-GCM 加密文件（SecureFileStore）。
    /// 遗留明文记录仅做一次性迁移读取，迁移后删除。明文基线可被攻击者
    /// 篡改为当前（已篡改）身份，从而掩盖签名身份变化。
    // 加密文件中的基线 key。
    private static let baselineStorageKey = "app_signing_identity.baseline.v1"
    // 遗留明文 UserDefaults key，仅用于一次性迁移读取。
    private static let legacyBaselineDefaultsKey = "com.cloudphone.riskkit.app_signing_identity.baseline.v1"
    // 基线读写锁，保证迁移与保存不并发。
    private static let baselineLock = UnfairLock()

    init() {}

    /// Detector 协议入口：执行检查并返回分数/方法。
    func detect() throws -> DetectorResult {
        inspect().detectorResult
    }

    /// 检查并转换信号；存在毒化发现时同时毒化 code signing lane。
    func asSignals() throws -> [RiskSignal] {
        let inspection = inspect()
        // 毒化后，后续依赖 code signing lane 的校验会按失败处理（fail-closed）。
        if inspection.shouldPoison {
            Logger.log(
                "[AppSigningIdentityDetector] forcing integrity poison: " +
                inspection.findings.map(\.signalID).joined(separator: ",")
            )
            cprisk_integrity_poison_code_signing_lane()
        }
        return inspection.signals
    }

    /// 返回遥测字段（不产生信号）。
    func telemetry() -> [String: String] {
        inspect().telemetry
    }

    /// 真机采集当前快照并检查；模拟器返回空快照。
    func inspect() -> Inspection {
#if targetEnvironment(simulator)
        return Inspection(
            snapshot: IdentitySnapshot(
                teamIdentifierEntitlement: nil,
                applicationIdentifier: nil,
                bundleIdentifier: nil,
                infoPlistBundleIdentifier: nil,
                getTaskAllow: nil,
                bundleContainer: .other
            ),
            findings: [],
            baselineStored: false
        )
#else
        inspect(snapshot: captureCurrentSnapshot(), isDebugBuild: Self.isDebugBuild)
#endif
    }

    /// 对给定快照执行身份一致性检查，并维护基线。
    func inspect(snapshot: IdentitySnapshot, isDebugBuild: Bool) -> Inspection {
        // 非 app/appex 容器不做签名检查。
        guard snapshot.isExecutableAppContainer else {
            return Inspection(snapshot: snapshot, findings: [], baselineStored: false)
        }

        var findings: [Finding] = []

        let bundleIdentifier = Self.normalized(snapshot.bundleIdentifier)
        let infoBundleIdentifier = Self.normalized(snapshot.infoPlistBundleIdentifier)
        let applicationIdentifier = Self.normalized(snapshot.applicationIdentifier)
        let explicitTeamIdentifier = Self.normalized(snapshot.teamIdentifierEntitlement)
        let effectiveTeamIdentifier = snapshot.effectiveTeamIdentifier

        // bundle id 双源均缺失：身份信息不完整。
        if bundleIdentifier == nil, infoBundleIdentifier == nil {
            findings.append(Finding(
                signalID: "app_bundle_identifier_missing",
                method: "signing_identity:bundle_identifier_missing",
                score: 28,
                evidence: [
                    "bundle_identifier": "nil",
                    "info_bundle_identifier": "nil",
                    "bundle_container": snapshot.bundleContainer.rawValue,
                ],
                state: .soft(confidence: 0.88),
                weightHint: 72,
                poison: false
            ))
        }

        // application-identifier 不是 team.bundle 形式。
        if let applicationIdentifier,
           Self.teamPrefix(from: applicationIdentifier) == nil || Self.bundleSuffix(from: applicationIdentifier) == nil {
            findings.append(Finding(
                signalID: "app_identifier_malformed",
                method: "signing_identity:application_identifier_malformed",
                score: 24,
                evidence: [
                    "application_identifier": applicationIdentifier,
                ],
                state: .soft(confidence: 0.84),
                weightHint: 64,
                poison: false
            ))
        }

        // 运行时 Bundle id 与 Info.plist 不一致：常见于重打包。
        if let bundleIdentifier, let infoBundleIdentifier, bundleIdentifier != infoBundleIdentifier {
            findings.append(Finding(
                signalID: "app_bundle_identifier_mismatch",
                method: "signing_identity:bundle_identifier_mismatch",
                score: 36,
                evidence: [
                    "bundle_identifier": bundleIdentifier,
                    "info_bundle_identifier": infoBundleIdentifier,
                ],
                state: .tampered,
                weightHint: 88,
                poison: true
            ))
        }

        // application-identifier 中的 bundle 后缀与运行时不一致。
        if let applicationIdentifier {
            if let entitledBundleIdentifier = Self.bundleSuffix(from: applicationIdentifier),
               let runtimeBundleIdentifier = bundleIdentifier ?? infoBundleIdentifier,
               !Self.bundleIdentifierMatches(entitledBundleIdentifier, runtimeBundleIdentifier) {
                findings.append(Finding(
                    signalID: "app_identifier_bundle_mismatch",
                    method: "signing_identity:application_identifier_bundle_mismatch",
                    score: 42,
                    evidence: [
                        "application_identifier": applicationIdentifier,
                        "entitled_bundle_identifier": entitledBundleIdentifier,
                        "runtime_bundle_identifier": runtimeBundleIdentifier,
                    ],
                    state: .tampered,
                    weightHint: 92,
                    poison: true
                ))
            }

            // application-identifier 前缀与 entitlement 中的 team id 不一致。
            if let applicationTeamIdentifier = Self.teamPrefix(from: applicationIdentifier),
               let explicitTeamIdentifier,
               applicationTeamIdentifier != explicitTeamIdentifier {
                findings.append(Finding(
                    signalID: "app_team_identifier_mismatch",
                    method: "signing_identity:team_identifier_mismatch",
                    score: 40,
                    evidence: [
                        "team_identifier_entitlement": explicitTeamIdentifier,
                        "application_identifier_prefix": applicationTeamIdentifier,
                    ],
                    state: .tampered,
                    weightHint: 90,
                    poison: true
                ))
            }
        // Release 下缺失 application-identifier（iOS 正常签名应存在）。
        } else if Self.requiresApplicationIdentifierEntitlement && !isDebugBuild {
            findings.append(Finding(
                signalID: "app_identifier_missing",
                method: "signing_identity:application_identifier_missing",
                score: 16,
                evidence: [
                    "bundle_identifier": bundleIdentifier ?? "nil",
                    "info_bundle_identifier": infoBundleIdentifier ?? "nil",
                ],
                state: .soft(confidence: 0.75),
                weightHint: 58,
                poison: false
            ))
        }

        // team id 形态异常（Apple Team ID 应为 10 位大写字母/数字）。
        if let effectiveTeamIdentifier {
            if !Self.looksLikeAppleTeamIdentifier(effectiveTeamIdentifier) {
                findings.append(Finding(
                    signalID: "app_team_identifier_abnormal",
                    method: "signing_identity:team_identifier_abnormal",
                    score: 14,
                    evidence: [
                        "team_identifier": effectiveTeamIdentifier,
                        "source": explicitTeamIdentifier == nil ? "application_identifier_prefix" : "entitlement",
                    ],
                    state: .soft(confidence: 0.8),
                    weightHint: 55,
                    poison: false
                ))
            }
        } else if Self.requiresApplicationIdentifierEntitlement && !isDebugBuild {
            findings.append(Finding(
                signalID: "app_team_identifier_missing",
                method: "signing_identity:team_identifier_missing",
                score: 16,
                evidence: [
                    "application_identifier": applicationIdentifier ?? "nil",
                ],
                state: .soft(confidence: 0.8),
                weightHint: 60,
                poison: false
            ))
        }

        // Release 下 get-task-allow=true：调试权限未关闭，可被动态调试。
        if snapshot.getTaskAllow == true && !isDebugBuild {
            findings.append(Finding(
                signalID: "app_get_task_allow_enabled",
                method: "signing_identity:get_task_allow_enabled_in_release",
                score: 34,
                evidence: [
                    "get_task_allow": "1",
                    "build_profile": "release",
                ],
                state: .tampered,
                weightHint: 86,
                poison: true
            ))
        }

        // 与首次运行基线比对；基线变化视为身份被替换。
        let baselineStored = reconcileBaseline(
            bundleIdentifier: bundleIdentifier ?? infoBundleIdentifier,
            applicationIdentifier: applicationIdentifier,
            teamIdentifier: effectiveTeamIdentifier,
            findings: &findings
        )

        return Inspection(snapshot: snapshot, findings: findings, baselineStored: baselineStored)
    }

    /// 采集当前进程的签名身份快照。
    private func captureCurrentSnapshot() -> IdentitySnapshot {
        let bundle = Bundle.main
        let pathExtension = bundle.bundleURL.pathExtension.lowercased()
        let bundleContainer: BundleContainer

        // 通过 bundle 扩展名判断容器类型。
        switch pathExtension {
        case "app":
            bundleContainer = .app
        case "appex":
            bundleContainer = .appExtension
        default:
            bundleContainer = .other
        }

        // macOS 使用 SecTask 读取 entitlement。
        #if os(macOS)
        let task = SecTaskCreateFromSelf(nil)
        return IdentitySnapshot(
            teamIdentifierEntitlement: entitlementString("com.apple.developer.team-identifier", task: task),
            applicationIdentifier: entitlementString("application-identifier", task: task),
            bundleIdentifier: Self.normalized(bundle.bundleIdentifier),
            infoPlistBundleIdentifier: Self.normalized(bundle.object(forInfoDictionaryKey: "CFBundleIdentifier") as? String),
            getTaskAllow: entitlementBool("get-task-allow", task: task),
            bundleContainer: bundleContainer
        )
        #else
        // iOS 无 SecTask 公开 API，仅做 Bundle 一致性校验。
        // SecTask API 仅 macOS 可用，iOS 上仅做 bundle 一致性校验
        return IdentitySnapshot(
            teamIdentifierEntitlement: nil,
            applicationIdentifier: nil,
            bundleIdentifier: Self.normalized(bundle.bundleIdentifier),
            infoPlistBundleIdentifier: Self.normalized(bundle.object(forInfoDictionaryKey: "CFBundleIdentifier") as? String),
            getTaskAllow: nil,
            bundleContainer: bundleContainer
        )
        #endif
    }

    #if os(macOS)
    /// 从 SecTask 读取字符串类型 entitlement，并做空白规范化。
    private func entitlementString(_ key: String, task: SecTask?) -> String? {
        Self.normalized(entitlementValue(for: key, task: task) as? String)
    }

    /// 从 SecTask 读取布尔类型 entitlement，兼容 Bool/NSNumber。
    private func entitlementBool(_ key: String, task: SecTask?) -> Bool? {
        guard let value = entitlementValue(for: key, task: task) else {
            return nil
        }
        if let boolValue = value as? Bool {
            return boolValue
        }
        if let number = value as? NSNumber {
            return number.boolValue
        }
        return nil
    }

    /// 读取任意 entitlement 原始值。
    private func entitlementValue(for key: String, task: SecTask?) -> Any? {
        guard let task else { return nil }
        return SecTaskCopyValueForEntitlement(task, key as CFString, nil)
    }
    #endif

    /// 将当前身份与加密基线比对；必要时写入首份基线。
    private func reconcileBaseline(
        bundleIdentifier: String?,
        applicationIdentifier: String?,
        teamIdentifier: String?,
        findings: inout [Finding]
    ) -> Bool {
        // 三要素不齐时不建立基线。
        guard let bundleIdentifier, let applicationIdentifier, let teamIdentifier else {
            return false
        }

        let current = IdentityBaseline(
            teamIdentifier: teamIdentifier,
            applicationIdentifier: applicationIdentifier,
            bundleIdentifier: bundleIdentifier
        )

        // 已有基线且字段变化：强篡改，直接毒化。
        if let stored = loadBaseline() {
            let changedFields = changedFields(from: stored, to: current)
            guard !changedFields.isEmpty else {
                return false
            }

            findings.append(Finding(
                signalID: ObfuscatedConstants.signalAppSigningBaselineChanged,
                method: "signing_identity:baseline_changed",
                score: 44,
                evidence: [
                    "changed_fields": changedFields.joined(separator: ","),
                    "baseline_team_identifier": stored.teamIdentifier,
                    "current_team_identifier": current.teamIdentifier,
                    "baseline_application_identifier": stored.applicationIdentifier,
                    "current_application_identifier": current.applicationIdentifier,
                    "baseline_bundle_identifier": stored.bundleIdentifier,
                    "current_bundle_identifier": current.bundleIdentifier,
                ],
                state: .tampered,
                weightHint: 94,
                poison: true
            ))
            return false
        }

        // 本次检查已有发现时不写基线，避免把异常身份固化。
        guard findings.isEmpty else {
            return false
        }

        saveBaseline(current)
        return true
    }

    /// 比较两份基线，返回发生变化的字段名。
    private func changedFields(from oldValue: IdentityBaseline, to newValue: IdentityBaseline) -> [String] {
        var out: [String] = []
        if oldValue.teamIdentifier != newValue.teamIdentifier {
            out.append("team_identifier")
        }
        if oldValue.applicationIdentifier != newValue.applicationIdentifier {
            out.append("application_identifier")
        }
        if oldValue.bundleIdentifier != newValue.bundleIdentifier {
            out.append("bundle_identifier")
        }
        return out
    }

    /// 读取加密基线；必要时从遗留明文迁移。
    private func loadBaseline() -> IdentityBaseline? {
        Self.baselineLock.withLock {
            // 优先读取加密文件。
            if let encrypted = SecureFileStore.shared.read(key: Self.baselineStorageKey),
               let decrypted = try? PayloadCrypto.decrypt(encrypted),
               let baseline = try? JSONDecoder().decode(IdentityBaseline.self, from: decrypted) {
                return baseline
            }
            // 遗留明文迁移：读到后转存加密文件并删除明文。
            // 遗留迁移：历史明文 UserDefaults 基线，读到后转存加密文件并删除明文。
            let defaults = UserDefaults.standard
            guard let data = defaults.data(forKey: Self.legacyBaselineDefaultsKey),
                  let baseline = try? JSONDecoder().decode(IdentityBaseline.self, from: data) else {
                return nil
            }
            saveBaselineLocked(baseline)
            defaults.removeObject(forKey: Self.legacyBaselineDefaultsKey)
            return baseline
        }
    }

    /// 保存基线（加锁）。
    private func saveBaseline(_ baseline: IdentityBaseline) {
        Self.baselineLock.withLock { saveBaselineLocked(baseline) }
    }

    /// 调用方须已持有 `baselineLock`。
    /// 调用方须已持有 `baselineLock`。
    private func saveBaselineLocked(_ baseline: IdentityBaseline) {
        guard let data = try? JSONEncoder().encode(baseline),
              let encrypted = try? PayloadCrypto.encrypt(data) else {
            return
        }
        SecureFileStore.shared.write(key: Self.baselineStorageKey, data: encrypted)
    }

    /// 是否为 DEBUG 构建；Release 下 get-task-allow 才被视为异常。
    private static var isDebugBuild: Bool {
#if DEBUG
        true
#else
        false
#endif
    }

    /// iOS/UIKit 环境要求存在 application-identifier entitlement。
    private static var requiresApplicationIdentifierEntitlement: Bool {
#if canImport(UIKit)
        true
#else
        false
#endif
    }

    /// 去除首尾空白；空字符串返回 nil。
    static func normalized(_ value: String?) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty else {
            return nil
        }
        return trimmed
    }

    /// 报告 team id 的来源：entitlement / application_identifier_prefix / missing。
    static func teamIdentifierSource(for snapshot: IdentitySnapshot) -> String {
        if normalized(snapshot.teamIdentifierEntitlement) != nil {
            return "entitlement"
        }
        if snapshot.derivedTeamIdentifier != nil {
            return "application_identifier_prefix"
        }
        return "missing"
    }

    /// 从 application-identifier 中取第一个 '.' 之前的前缀作为 team id。
    static func teamPrefix(from applicationIdentifier: String?) -> String? {
        guard let applicationIdentifier = normalized(applicationIdentifier),
              let separator = applicationIdentifier.firstIndex(of: ".") else {
            return nil
        }
        let prefix = String(applicationIdentifier[..<separator])
        return normalized(prefix)
    }

    /// 从 application-identifier 中取第一个 '.' 之后的 bundle 后缀。
    static func bundleSuffix(from applicationIdentifier: String?) -> String? {
        guard let applicationIdentifier = normalized(applicationIdentifier),
              let separator = applicationIdentifier.firstIndex(of: ".") else {
            return nil
        }
        let suffix = String(applicationIdentifier[applicationIdentifier.index(after: separator)...])
        return normalized(suffix)
    }

    /// 比较 entitlement 中的 bundle id 与运行时 bundle id，支持通配符。
    static func bundleIdentifierMatches(_ entitledBundleIdentifier: String, _ runtimeBundleIdentifier: String) -> Bool {
        if entitledBundleIdentifier == runtimeBundleIdentifier {
            return true
        }

        // 支持 `com.foo.*` 形式的通配 entitlement。
        guard entitledBundleIdentifier.hasSuffix(".*"),
              entitledBundleIdentifier.count > 2 else {
            return false
        }

        let wildcardPrefix = String(entitledBundleIdentifier.dropLast(2))
        if runtimeBundleIdentifier == wildcardPrefix {
            return true
        }
        return runtimeBundleIdentifier.hasPrefix(wildcardPrefix + ".")
    }

    /// 校验 Apple Team ID 形态：恰好 10 位大写字母或数字。
    static func looksLikeAppleTeamIdentifier(_ teamIdentifier: String) -> Bool {
        // Apple Team ID 固定 10 位，长度不符直接判异常。
        guard teamIdentifier.count == 10 else {
            return false
        }

        return teamIdentifier.unicodeScalars.allSatisfy { scalar in
            let value = scalar.value
            return (48...57).contains(value) || (65...90).contains(value)
        }
    }

    /// 计算身份材料指纹（SHA256 十六进制）。
    static func bindingFingerprint(for snapshot: IdentitySnapshot) -> String {
        let material = [
            normalized(snapshot.teamIdentifierEntitlement) ?? "",
            snapshot.derivedTeamIdentifier ?? "",
            normalized(snapshot.applicationIdentifier) ?? "",
            snapshot.effectiveBundleIdentifier ?? "",
            snapshot.getTaskAllow.map { $0 ? "1" : "0" } ?? "",
            snapshot.bundleContainer.rawValue,
        ].joined(separator: "|")
        return SHA256.hash(data: Data(material.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}
