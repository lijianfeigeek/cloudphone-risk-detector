// 端侧风险评分与决策引擎：把各检测器/Provider 产出的 `RiskSignal` 汇总为 `LocalAssessment`。
// 主链路分四段：Signal Collection（收集与派生）→ Fast Digest（压缩摘要短路）
// → Score & Force（计分与强制动作）→ Tree Commit（决策树与聚合对账），任一段异常都以
// fail-closed 收尾。本文件只产出本地建议，最终业务决策由服务端 Decision Service 负责。
// 线程模型：`RiskDetectionEngine` 是无共享可变状态的值类型，`evaluate` 同步执行，
// 可在任意线程并发调用；唯一的跨实例可变状态是受审计保护的本地 kill switch 覆盖开关。
import Foundation

// MARK: - 风险检测引擎
/// 端侧风险评估引擎，支持场景化检测、动态权重和组合规则。
/// 输出本地建议；服务端业务决策由 Decision Service 负责。
///
/// ## 管道阶段
/// - **Signal Collection**：收集 Provider 信号，派生跨层一致性、服务端黑名单与调用栈信号；
/// - **Fast Digest**：用信号压缩摘要匹配位向量规则，命中即短路返回；
/// - **Score & Force**：基础分 + Combo/N-of-M 加分 + 挑战偏移，再应用强制动作与档位保底；
/// - **Tree Commit**：运行场景决策树，并与分数档位、多源聚合证据对账后输出判决。
///
/// ## 线程与并发
/// 评估过程不创建线程、不持有锁，所有中间状态都是局部变量；
/// 唯一的一次性副作用是消费 `ChallengeResultStore` 中的挑战结果偏移。
///
/// ## 核心设计原则
/// 1. **场景化**: 不同业务场景使用不同的风险阈值和权重
/// 2. **可配置**: 所有阈值、权重、规则都可通过 Policy 配置
/// 3. **可扩展**: 支持自定义信号提供者和决策树
/// 4. **向后兼容**: 旧版 RiskScorer 已废弃（无调用方），本引擎为唯一主评分链路
///
/// ## 使用示例
/// ```swift
/// let engine = RiskDetectionEngine(policy: .payment)
/// let verdict = engine.evaluate(context: riskContext, scenario: .payment)
///
/// switch verdict.internalAction {
/// case .allow: print("本地建议允许")
/// case .challenge: print("需要验证码")
/// case .stepUpAuth: print("需要短信验证")
/// case .block: print("本地建议拒绝")
/// }
/// ```
public struct RiskDetectionEngine: Sendable {

    // MARK: - 属性

    /// 引擎策略配置
    public let policy: EnginePolicy

    /// 是否启用日志
    public let enableLogging: Bool

    /// 本地 killSwitch 覆盖开关 — 设为 true 时即使远程配置启用 killSwitch 也继续正常评估。
    /// 用于防止远程配置被劫持后一键关闭所有防护。
    ///
    /// ⚠️ 风险：开启后远程 kill switch（紧急降级/止血）将失效，评估继续拦截。
    /// 因此该开关不对外部调用方公开：仅限 SDK 内部经授权调用
    /// `setLocalKillSwitchOverride(_:reason:)` 修改，每次修改都会写入审计日志。
    /// Kill switch 生效/被覆盖时，评估路径同样记录审计日志
    ///（见 `evaluate()` 中的 `kill_switch_activated` / `kill_switch_overridden`）。
    internal nonisolated(unsafe) static var localKillSwitchOverride: Bool = false

    /// 授权修改本地 kill switch 覆盖开关。`reason` 为必填审计原因，
    /// 会随审计日志记录；请勿在生产代码中无条件开启。
    ///
    /// 并发约束：底层是 `nonisolated(unsafe)` 静态变量，写入本身未加锁；
    /// 该接口只应由受控的初始化/运维路径调用，不应在评估热路径上频繁切换。
    /// 开关读取是单次原子宽度的布尔读取，最坏情况下并发评估会短暂看到旧值，
    /// 这对“紧急开关”语义可接受，但不应被当作强一致配置使用。
    internal static func setLocalKillSwitchOverride(_ enabled: Bool, reason: String) {
        localKillSwitchOverride = enabled
        Logger.audit(action: "kill_switch_override_changed", details: [
            "enabled": enabled ? "true" : "false",
            "reason": reason,
            "timestamp": ISO8601DateFormatter().string(from: Date()),
        ])
        Logger.log("kill_switch_override_changed enabled=\(enabled) reason=\(reason)")
    }

    /// 自定义信号提供者。
    /// key 仅用于稳定排序，闭包应为同步、可重入且无阻塞的实现；
    /// 引擎不会为它们创建线程，单个 Provider 的耗时直接计入评估时延。
    private let customProviders: [String: @Sendable (RiskContext) -> [RiskSignal]]

    // nil keeps direct engine callers unchanged; adapter selection is evaluation-local.
    // 这里避免把白名单写进 `policy`：家族选择只属于本实例，
    // nil 时不过滤，非 nil 时也只过滤内置家族，调用方自带 Provider 不受影响。
    private var enabledDetectorFamilies: Set<String>?

    // MARK: - 初始化

    /// 创建引擎实例。
    /// - Parameters:
    ///   - policy: 全局策略（阈值、权重覆盖、强制规则、变异策略等）。
    ///   - enableLogging: 是否输出诊断日志；关闭只影响日志，不影响判决。
    ///   - customProviders: 调用方注入的额外信号源，按 key 排序后依次执行。
    public init(
        policy: EnginePolicy = .default,
        enableLogging: Bool = true,
        customProviders: [String: @Sendable (RiskContext) -> [RiskSignal]] = [:]
    ) {
        self.policy = policy
        self.enableLogging = enableLogging
        self.customProviders = customProviders
    }

    /// Apply a policy without discarding caller-owned providers or logging settings.
    /// Keep this copy operation here so the adapter cannot reconstruct a partial engine.
    /// 返回仅替换策略的新实例，保留调用方注入的 Provider、日志开关与家族选择；
    /// 采用值拷贝而非原地修改，避免并发评估中正在使用的实例被改变。
    func replacingPolicy(_ policy: EnginePolicy) -> RiskDetectionEngine {
        var result = RiskDetectionEngine(
            policy: policy,
            enableLogging: enableLogging,
            customProviders: customProviders
        )
        result.enabledDetectorFamilies = enabledDetectorFamilies
        return result
    }

    /// 返回选择了指定检测器家族的新实例。
    /// - Parameter families: 空集合表示回退到 `DecisionConfig.defaultDetectors`，
    ///   而不是“全部关闭”，避免调用方误传空集导致防护静默失效。
    func selectingDetectorFamilies(_ families: Set<String>) -> RiskDetectionEngine {
        var result = self
        result.enabledDetectorFamilies = families.isEmpty ? DecisionConfig.defaultDetectors : families
        return result
    }

    /// 判断某个内置检测器家族是否启用；未设置白名单时一律启用。
    /// 白名单之外的自定义分类属于调用方，不受此处限制。
    private func detectorEnabled(_ category: String) -> Bool {
        guard let families = enabledDetectorFamilies else { return true }
        // Unknown categories belong to caller-owned providers, not the built-in allow-list.
        // 未知分类来自调用方 Provider，不能因为白名单没列出就被丢弃。
        guard DecisionConfig.defaultDetectors.contains(category) else { return true }
        return families.contains(category)
    }

    /// 决定单条信号是否进入评分。
    /// `.tampered` 是显式完整性失败，必须无条件保留，不能被可选的家族白名单隐藏。
    private func includeSelectedSignal(_ signal: RiskSignal) -> Bool {
        // Explicit integrity failures cannot be hidden by optional detector selection.
        signal.state == .tampered || detectorEnabled(signal.category)
    }

    // MARK: - 核心评估方法

    /// 评估风险并返回判决结果。
    ///
    /// 执行顺序：kill switch → 预检短路（调用栈/区域状态）→ 压缩摘要短路
    /// → 计分与强制动作 → 决策树提交。任何一步的完整性校验失败都会返回
    /// fail-closed 判决（critical/block），不会静默放行。
    ///
    /// 该方法同步执行、不创建线程，可重入且线程安全（实例无共享可变状态）；
    /// 每次调用都会消费一次性的挑战结果偏移，因此同一上下文重复调用可能得到不同分数。
    /// - Parameters:
    ///   - context: 风险上下文，包含所有检测信号
    ///   - scenario: 检测场景
    ///   - extraSignals: 额外的风险信号（可选）
    /// - Returns: 风险判决结果
    public func evaluate(
        context: RiskContext,
        scenario: RiskScenario = .default,
        extraSignals: [RiskSignal] = []
    ) -> LocalAssessment {
        log("=== RiskDetectionEngine evaluation started ===")
        log("Scenario: \(scenario.rawValue)")
        log("Policy: \(policy.name)")

        // kill switch 是最高优先级的止血路径：远程配置一旦开启就强制 allow。
        // 本地覆盖开关用于防止远程配置被劫持后“一键关闭所有防护”，代价是紧急降级失效。
        if policy.killSwitchEnabled && !Self.localKillSwitchOverride {
            Logger.critical("killSwitch enabled — forcing allow verdict, all risk interception bypassed",
                           metadata: ["scenario": scenario.identifier, "policy": policy.name])
            Logger.audit(action: "kill_switch_activated", details: [
                "scenario": scenario.identifier,
                "policy": policy.name,
                "timestamp": ISO8601DateFormatter().string(from: Date()),
            ])
            return LocalAssessment(
                score: 0,
                internalLevel: .low,
                internalAction: .allow,
                confidence: 1.0,
                primaryReasons: ["kill_switch_active"],
                signals: [RiskSignal(
                    id: "kill_switch_active",
                    category: "system",
                    score: 0,
                    evidence: ["policy": policy.name],
                    state: .hard(detected: true)
                )],
                scenario: scenario
            )
        } else if policy.killSwitchEnabled && Self.localKillSwitchOverride {
            // 覆盖不是静默行为：必须留下 warn 与审计记录，便于发现“远程要求关闭但本地拒绝”的异常。
            Logger.warn("killSwitch requested by remote config but overridden by local policy")
            Logger.audit(action: "kill_switch_overridden", details: [
                "scenario": scenario.identifier,
            ])
        }

        // 第一阶段 Signal Collection：收集全部信号，并可能产生预检短路判决。
        let collected = collectAndAugmentSignals(
            context: context,
            scenario: scenario,
            extraSignals: extraSignals
        )
        // 预检命中（如 dladdr 返回地址落在非可信区间）优先于评分：这类证据本身即可判定 block。
        if let preflightVerdict = collected.preflightVerdict {
            Logger.audit(action: "preflight_short_circuit", details: [
                "level": String(preflightVerdict.level.rawValue),
                "action": String(preflightVerdict.action.rawValue),
                "reasons": preflightVerdict.primaryReasons.joined(separator: ","),
            ])
            log("=== Evaluation complete (preflight) ===")
            log("Verdict - level: \(preflightVerdict.level.rawValue), action: \(preflightVerdict.action.rawValue), confidence: \(preflightVerdict.confidence)")
            return preflightVerdict
        }

        // 第二阶段 Fast Digest：压缩摘要规则命中时提前返回，省去完整计分与决策树。
        if let fastDecision = fastDigestShortCircuit(
            context: context,
            collected: collected,
            scenario: scenario
        ) {
            // 短路结论仍要与完整计分对账，防止单条摘要规则被绕过时反而放宽动作。
            let verdict = reconcileShortCircuitVerdict(
                baseVerdict: fastDecision.verdict,
                context: context,
                scenario: scenario,
                collected: collected
            )
            Logger.audit(action: "fast_digest_short_circuit", details: [
                "level": String(verdict.level.rawValue),
                "action": String(verdict.action.rawValue),
                "score": String(format: "%.1f", verdict.score),
            ])
            log("=== Evaluation complete (fast digest) ===")
            log("Verdict - level: \(verdict.level.rawValue), action: \(verdict.action.rawValue), confidence: \(verdict.confidence)")
            return verdict
        }

        // 第三阶段 Score & Force：基础计分、Combo/N-of-M 加分、强制动作与档位保底。
        let intermediate = scoreAndForceDecision(
            context: context,
            scenario: scenario,
            collected: collected
        )
        // 第四阶段 Tree Commit：决策树动作 + 聚合证据对账，产出最终判决。
        let verdict = treeCommitVerdict(
            context: context,
            scenario: scenario,
            collected: collected,
            intermediate: intermediate
        )

        log("=== Evaluation complete ===")
        log("Verdict - level: \(verdict.level.rawValue), action: \(verdict.action.rawValue), confidence: \(verdict.confidence)")

        return verdict
    }

    /// 信号收集与增强阶段。
    ///
    /// 依次执行：调用栈校验 → 场景阈值扰动 → Provider 收集 → 跨层一致性派生
    /// → 服务端黑名单派生 → 信号顺序扰动 → 压缩摘要。
    /// 流程由编码后的状态机（0x11…0x17）驱动并设有预算上限；状态被篡改、无法解码
    /// 或预算耗尽时都会生成 fail-closed 判决，而不是让上层拿到空上下文继续放行。
    ///
    /// - Returns: 冻结后的收集上下文；`preflightVerdict` 非空表示应跳过后续评分。
    private func collectAndAugmentSignals(
        context: RiskContext,
        scenario: RiskScenario,
        extraSignals: [RiskSignal]
    ) -> CollectedSignalContext {
        // 变异规划器按“策略种子 + 场景 + 设备”派生：打乱信号顺序并轻微抖动权重/阈值，
        // 让依赖固定顺序或固定阈值的离线探测难以稳定复现。
        let planner = MutationPlanner(
            strategy: policy.mutationStrategy,
            scope: scenario.identifier,
            deviceID: context.deviceID
        )
        // 挑战结果偏移是“一次性”提示：这里只读取用于派生盐值，真正消费发生在计分阶段。
        let challengeOffsetHint = ChallengeResultStore.shared.currentScoreOffset() ?? 0
        let regionKey = regionStateKey(label: "collectAndAugmentSignals", scenario: scenario)
        // 盐混入阶段名、设备、网络、越狱状态与反篡改摘要；攻击者改动任一输入都会导致状态机解码失败。
        let regionSalt = runtimeSalt(
            phase: "collect",
            scenario: scenario,
            context: context,
            signals: extraSignals,
            challengeOffsetHint: challengeOffsetHint,
            antiTamperingDigest: 0
        )

        var scenarioPolicy = policy.scenarioPolicy(for: scenario)
        var allSignals: [RiskSignal] = []
        var callStackExtraSignals: [RiskSignal] = []
        var compressResult = SignalCompressor.compress(signals: [])
        var preflightVerdict: LocalAssessment?
        var sink: CollectedSignalContext?
        var state = encodeRegionState(0x11, key: regionKey, salt: regionSalt)
        var budget = 0
        var poison = regionSalt ^ challengeOffsetHint.bitPattern

        // 状态机 + 预算上限：非法状态不会死循环，超预算也会落到 fail-closed。
        while sink == nil && budget < 12 {
            switch decodeRegionState(state, key: regionKey, salt: regionSalt) {
            case 0x11:
                // 调用栈回溯：dladdr 钩子直接预检 block；其他可疑返回地址先降级为信号参与评分。
                let (isCallStackMalicious, callStackSignalId) = CallStackUnwinder.validateCallStack()
                if isCallStackMalicious, let signalId = callStackSignalId {
                    if signalId == CallStackUnwinder.dladdrHookSignalId {
                        let hookSignal = makeCallStackSignal(id: signalId)
                        preflightVerdict = LocalAssessment(
                            score: 100,
                            internalLevel: .critical,
                            internalAction: .block,
                            confidence: 1.0,
                            primaryReasons: [hookSignal.id],
                            signals: [hookSignal],
                            scenario: scenario
                        )
                        state = encodeRegionState(0x17, key: regionKey, salt: regionSalt)
                    } else {
                        callStackExtraSignals.append(makeCallStackSignal(id: signalId))
                        log("CallStackUnwinder: \(signalId) injected as signal (not hard-exit)")
                        state = encodeRegionState(0x12, key: regionKey, salt: regionSalt)
                    }
                } else {
                    state = encodeRegionState(0x12, key: regionKey, salt: regionSalt)
                }
            case 0x12:
                // 阈值扰动后仍须保持 medium < high < critical，见 `mutatedScenarioPolicy`。
                scenarioPolicy = mutatedScenarioPolicy(
                    base: policy.scenarioPolicy(for: scenario),
                    planner: planner
                )
                log("Scenario policy - medium: \(scenarioPolicy.mediumThreshold), high: \(scenarioPolicy.highThreshold), critical: \(scenarioPolicy.criticalThreshold)")
                state = encodeRegionState(0x13, key: regionKey, salt: regionSalt)
            case 0x13:
                // 收集内置检测器、自定义 Provider 与额外信号；引擎对 Provider 不做重试或超时隔离。
                allSignals = collectSignals(
                    context: context,
                    scenarioPolicy: scenarioPolicy,
                    extraSignals: extraSignals + callStackExtraSignals,
                    planner: planner
                )
                state = encodeRegionState(0x14, key: regionKey, salt: regionSalt)
            case 0x14:
                // 跨层一致性：L1 干净/L2 被篡改、L3 数据缺失等“互相矛盾”的组合本身就是强证据。
                let crossLayerSignals = deriveCrossLayerSignals(from: allSignals)
                if !crossLayerSignals.isEmpty {
                    allSignals.append(contentsOf: crossLayerSignals)
                    log("Cross-layer inconsistency hit: +\(crossLayerSignals.count) signals")
                }
                state = encodeRegionState(0x15, key: regionKey, salt: regionSalt)
            case 0x15:
                // 服务端黑名单只匹配 category=="server"/id 前缀 "server_" 的信号，命中后派生出高权重硬信号。
                let blocklistSignals = deriveBlocklistSignals(from: allSignals)
                if !blocklistSignals.isEmpty {
                    allSignals.append(contentsOf: blocklistSignals)
                    log("Server blocklist hit: +\(blocklistSignals.count) signals")
                }
                state = encodeRegionState(0x16, key: regionKey, salt: regionSalt)
            case 0x16:
                // 先打乱再压缩：避免压缩摘要位向量的位置规律被离线分析利用。
                allSignals = planner.maybeShuffle(allSignals, salt: "signal_order")
                log("Collected \(allSignals.count) signals")
                compressResult = SignalCompressor.compress(signals: allSignals)
                state = encodeRegionState(0x17, key: regionKey, salt: regionSalt)
            case 0x17:
                // 收口：冻结上下文，并计算反篡改摘要供后续阶段派生盐值与决策元数据。
                sink = CollectedSignalContext(
                    planner: planner,
                    scenarioPolicy: scenarioPolicy,
                    allSignals: allSignals,
                    compressResult: compressResult,
                    preflightVerdict: preflightVerdict,
                    challengeOffsetHint: challengeOffsetHint,
                    antiTamperingDigest: antiTamperingDigest(from: allSignals)
                )
            default:
                // 非法状态：推进 poison 并立即生成 fail-closed 判决；仍压缩信号，保证返回结构完整。
                poison = poison &* 0x100000001b3 &+ 0x9e3779b97f4a7c15
                preflightVerdict = preflightVerdict ?? failClosedVerdict(
                    scenario: scenario,
                    phase: "collectAndAugmentSignals",
                    poison: poison
                )
                compressResult = SignalCompressor.compress(signals: allSignals)
                state = encodeRegionState(0x17, key: regionKey, salt: regionSalt)
            }
            budget += 1
        }

        // 预算耗尽兜底：即使没走到收口状态，也必须给出 fail-closed 判决。
        return sink ?? CollectedSignalContext(
            planner: planner,
            scenarioPolicy: scenarioPolicy,
            allSignals: allSignals,
            compressResult: compressResult,
            preflightVerdict: preflightVerdict ?? failClosedVerdict(
                scenario: scenario,
                phase: "collectAndAugmentSignals_budget",
                poison: poison
            ),
            challengeOffsetHint: challengeOffsetHint,
            antiTamperingDigest: antiTamperingDigest(from: allSignals)
        )
    }

    /// 压缩摘要快速判决。
    ///
    /// 把全部信号压缩成位向量摘要，再与 `CompressedVerdictRules` 做一次低成本匹配；
    /// 命中即取最严格动作短路返回，否则返回 nil 继续完整评分。
    /// 状态机异常或预算耗尽时返回 fail-closed 判决。
    private func fastDigestShortCircuit(
        context: RiskContext,
        collected: CollectedSignalContext,
        scenario: RiskScenario
    ) -> FastDigestDecision? {
        let regionKey = regionStateKey(label: "fastDigestShortCircuit", scenario: scenario)
        let regionSalt = runtimeSalt(
            phase: "fast_digest",
            scenario: scenario,
            context: context,
            signals: collected.allSignals,
            challengeOffsetHint: collected.challengeOffsetHint,
            antiTamperingDigest: collected.antiTamperingDigest
        )
        var sink: FastDigestDecision?
        var done = false
        var state = encodeRegionState(0x21, key: regionKey, salt: regionSalt)
        var candidateVerdict: LocalAssessment?
        var budget = 0
        var poison = collected.antiTamperingDigest ^ regionSalt

        while !done && budget < 8 {
            let decoded = decodeRegionState(state, key: regionKey, salt: regionSalt)
            if decoded == 0x21 {
                candidateVerdict = evaluateCompressedVerdictRules(
                    digest: collected.compressResult.digest,
                    scenarioPolicy: collected.scenarioPolicy,
                    signals: collected.allSignals,
                    scenario: scenario
                )
                state = encodeRegionState(candidateVerdict == nil ? 0x22 : 0x23, key: regionKey, salt: regionSalt)
            } else if decoded == 0x22 {
                done = true
            } else if decoded == 0x23 {
                if let verdict = candidateVerdict {
                    log("Compressed verdict rule hit, short-circuit: \(verdict.internalAction.rawValue)")
                    sink = FastDigestDecision(verdict: verdict)
                    done = true
                } else {
                    state = encodeRegionState(0x24, key: regionKey, salt: regionSalt)
                }
            } else {
                // 解码失败/非法状态：fail-closed，绝不因为“没匹配到规则”而放行。
                poison = poison &* 0x9e3779b97f4a7c15 &+ 0x517cc1b727220a95
                sink = FastDigestDecision(
                    verdict: failClosedVerdict(
                        scenario: scenario,
                        phase: "fastDigestShortCircuit",
                        poison: poison
                    )
                )
                done = true
            }
            budget += 1
        }

        if !done && sink == nil {
            return FastDigestDecision(
                verdict: failClosedVerdict(
                    scenario: scenario,
                    phase: "fastDigestShortCircuit_budget",
                    poison: poison
                )
            )
        }
        return sink
    }

    /// 计分与强制动作阶段。
    ///
    /// 组成顺序：ComboRule/N-of-M 加分 → 基础分（硬/软/篡改/legacy）→ 盲挑战加分
    /// → 挑战结果偏移 → 强制规则（黑名单/越狱/带 forceAction 的组合规则）
    /// → 证书固定场景保底。分数全程夹在 0…100。
    /// 状态机异常或预算耗尽时退化为 `criticalThreshold` + `.block`。
    private func scoreAndForceDecision(
        context: RiskContext,
        scenario: RiskScenario,
        collected: CollectedSignalContext
    ) -> IntermediateDecision {
        let regionKey = regionStateKey(label: "scoreAndForceDecision", scenario: scenario)
        let regionSalt = runtimeSalt(
            phase: "score_force",
            scenario: scenario,
            context: context,
            signals: collected.allSignals,
            challengeOffsetHint: collected.challengeOffsetHint,
            antiTamperingDigest: collected.antiTamperingDigest
        )

        var comboBonus = 0.0
        var blindBonus = 0.0
        var challengeOffset = 0.0
        var finalScore = 0.0
        var adjustedScore = collected.scenarioPolicy.criticalThreshold
        var forcedAction: RiskAction? = .block
        var scoreComponents = ScoreComponents(
            total: 0,
            legacyComponent: 0,
            hardComponent: 0,
            softComponent: 0,
            tamperedCount: 0
        )
        var sink: IntermediateDecision?
        var state = encodeRegionState(0x31, key: regionKey, salt: regionSalt)
        var budget = 0
        var poison = regionSalt ^ collected.antiTamperingDigest

        while sink == nil && budget < 14 {
            let decoded = decodeRegionState(state, key: regionKey, salt: regionSalt)
            if decoded == 0x31 {
                // ComboRule 支持硬 AND 与带权 N-of-M 两种匹配；每条规则最多贡献一次 bonus。
                let comboRules = collected.planner.maybeShuffle(collected.scenarioPolicy.comboRules, salt: "combo_rules")
                comboBonus = applyComboRules(
                    signals: collected.allSignals,
                    comboRules: comboRules
                )
                if comboBonus > 0 {
                    log("Combo rules bonus: +\(comboBonus)")
                }
                state = encodeRegionState(0x32, key: regionKey, salt: regionSalt)
            } else if decoded == 0x32 {
                // 基础分：带状态信号走硬/软/篡改权重逻辑，无状态信号走 legacy 分类权重。
                scoreComponents = calculateBaseScore(
                    signals: collected.allSignals,
                    weights: collected.scenarioPolicy.signalWeights,
                    weightOverrides: policy.signalWeightOverrides,
                    planner: collected.planner
                )
                let baseScore = scoreComponents.total
                log(
                    "Base score: \(baseScore) " +
                    "(legacy=\(scoreComponents.legacyComponent), hard=\(scoreComponents.hardComponent), " +
                    "soft=\(scoreComponents.softComponent), tampered=\(scoreComponents.tamperedCount))"
                )
                // 连接节点的二选一由 poison 低位决定：只增加控制流不确定性，不改变评分语义。
                let connectorState: UInt32 = ((poison ^ UInt64(scoreComponents.tamperedCount)) & 1) == 0 ? 0x33 : 0x34
                poison ^= UInt64(scoreComponents.tamperedCount) &+ 0xA511E9B3
                finalScore = baseScore
                state = encodeRegionState(connectorState, key: regionKey, salt: regionSalt)
            } else if decoded == 0x33 || decoded == 0x34 {
                // 盲挑战加分按时间窗口轮换规则，命中后一次性加分，降低攻击者稳定探测规则的可能性。
                blindBonus = evaluateBlindChallengeBonus(
                    signals: collected.allSignals,
                    scenario: scenario,
                    deviceID: context.deviceID
                )
                if blindBonus > 0 {
                    log("Blind challenge bonus applied")
                }
                state = encodeRegionState(0x35, key: regionKey, salt: regionSalt)
            } else if decoded == 0x35 {
                // `consumeScoreOffset` 是一次性消费：同一验证结果不会被重复计入，
                // 同时把总分夹紧到 0…100，防止负偏移或异常大偏移破坏分数档位。
                challengeOffset = ChallengeResultStore.shared.consumeScoreOffset() ?? 0
                if challengeOffset != 0 {
                    log("Challenge result offset applied: +\(challengeOffset)")
                }
                finalScore = min(max(finalScore + comboBonus + blindBonus + challengeOffset, 0), 100)
                log("Final score: \(finalScore)")
                state = encodeRegionState(0x36, key: regionKey, salt: regionSalt)
            } else if decoded == 0x36 {
                // 强制规则与分数档位解耦：命中后同时抬升动作和最低分，避免“动作 block 但分数仍是 low”。
                (adjustedScore, forcedAction) = applyForceRules(
                    score: finalScore,
                    context: context,
                    signals: collected.allSignals,
                    scenarioPolicy: collected.scenarioPolicy
                )
                if let action = forcedAction {
                    log("Force rule applied, action: \(action.rawValue)")
                }
                // 证书固定异常在支付/登录等敏感场景额外抬升分数下限与动作。
                let pinningFloor = applyCertificatePinningScenarioFloors(
                    score: adjustedScore,
                    forcedAction: forcedAction,
                    scenario: scenario,
                    signals: collected.allSignals,
                    scenarioPolicy: collected.scenarioPolicy
                )
                sink = IntermediateDecision(
                    adjustedScore: pinningFloor.adjustedScore,
                    forcedAction: pinningFloor.forcedAction,
                    rawFinalScore: finalScore,
                    scoreComponents: scoreComponents,
                    decisionHints: pinningFloor.decisionHints
                )
            } else {
                // 非法状态：直接以 criticalThreshold + block 兜底，并把已算出的分量留在结果中便于取证。
                poison = poison &* 0x100000001b3 &+ 0xC6A4A7935BD1E995
                sink = IntermediateDecision(
                    adjustedScore: collected.scenarioPolicy.criticalThreshold,
                    forcedAction: .block,
                    rawFinalScore: finalScore,
                    scoreComponents: scoreComponents,
                    decisionHints: [:]
                )
            }
            budget += 1
        }

        // 预算耗尽兜底：同样采用最高档位 + block，绝不放行。
        return sink ?? IntermediateDecision(
            adjustedScore: collected.scenarioPolicy.criticalThreshold,
            forcedAction: .block,
            rawFinalScore: collected.scenarioPolicy.criticalThreshold,
            scoreComponents: ScoreComponents(
                total: 0,
                legacyComponent: 0,
                hardComponent: 0,
                softComponent: 0,
                tamperedCount: 0
            ),
            decisionHints: [:]
        )
    }

    /// 决策树提交阶段。
    ///
    /// 在评分结果之上运行场景决策树，并把树动作与分数档位动作、多源聚合升级对账，
    /// 始终取更严格者。强制动作优先级最高；最终判决附带置信度、primaryReasons、
    /// 压缩摘要与决策元数据。状态机异常或预算耗尽时 fail-closed。
    private func treeCommitVerdict(
        context: RiskContext,
        scenario: RiskScenario,
        collected: CollectedSignalContext,
        intermediate: IntermediateDecision
    ) -> RiskConclusion {
        let regionKey = regionStateKey(label: "treeCommitVerdict", scenario: scenario)
        let regionSalt = runtimeSalt(
            phase: "tree_commit",
            scenario: scenario,
            context: context,
            signals: collected.allSignals,
            challengeOffsetHint: collected.challengeOffsetHint,
            antiTamperingDigest: collected.antiTamperingDigest,
            scoreHint: intermediate.adjustedScore
        )

        var evaluationContext = EvaluationContext(
            score: intermediate.adjustedScore,
            signals: collected.allSignals,
            scenario: scenario,
            riskContext: context,
            policy: collected.scenarioPolicy
        )
        var treeAction: RiskAction = collected.scenarioPolicy.action(for: collected.scenarioPolicy.level(for: intermediate.adjustedScore))
        var finalAction: RiskAction = intermediate.forcedAction ?? treeAction
        var sink: RiskConclusion?
        var state = encodeRegionState(0x41, key: regionKey, salt: regionSalt)
        var budget = 0
        var poison = regionSalt ^ intermediate.adjustedScore.bitPattern

        while sink == nil && budget < 10 {
            switch decodeRegionState(state, key: regionKey, salt: regionSalt) {
            case 0x41:
                // 元数据携带摘要版本与反篡改摘要，便于服务端复算与取证。
                evaluationContext = EvaluationContext(
                    score: intermediate.adjustedScore,
                    signals: collected.allSignals,
                    scenario: scenario,
                    riskContext: context,
                    policy: collected.scenarioPolicy,
                    metadata: [
                        "digestVersion": collected.compressResult.mappingVersion,
                        "antiTamper": String(collected.antiTamperingDigest, radix: 16)
                    ]
                )
                // 只有调用方显式选择了检测器家族时，才把家族开关传给决策树；
                // 未选择时保持决策树默认行为，避免改变直接调用方的语义。
                if enabledDetectorFamilies != nil {
                    evaluationContext.jailbreakEnabled = detectorEnabled(ObfuscatedConstants.signalJailbreak)
                    evaluationContext.networkEnabled = detectorEnabled("network")
                }
                state = encodeRegionState(0x42, key: regionKey, salt: regionSalt)
            case 0x42:
                // 场景决策树基于上下文（越狱、网络、分数等）给出自己的动作。
                let decisionTree = DecisionTree.tree(for: scenario)
                treeAction = decisionTree.decide(context: evaluationContext)
                log("Decision tree action: \(treeAction.rawValue)")
                state = encodeRegionState(intermediate.forcedAction == nil ? 0x44 : 0x43, key: regionKey, salt: regionSalt)
            case 0x43:
                // ForceRule 命中：强制动作覆盖树动作，树动作仅作为参考保留在元数据中。
                finalAction = intermediate.forcedAction ?? treeAction
                state = encodeRegionState(0x45, key: regionKey, salt: regionSalt)
            case 0x44:
                // 无强制动作：以决策树结果作为初步动作。
                finalAction = treeAction
                state = encodeRegionState(0x45, key: regionKey, salt: regionSalt)
            case 0x45:
                // 对账只会把动作抬得更严格（档位保底、聚合升级），不会放松初步动作。
                let reconciliation = reconcileAggregateDecision(
                    preliminaryAction: finalAction,
                    treeAction: treeAction,
                    intermediate: intermediate,
                    scenarioPolicy: collected.scenarioPolicy,
                    signals: collected.allSignals,
                    context: context
                )
                sink = LocalAssessment(
                    score: intermediate.adjustedScore,
                    internalLevel: collected.scenarioPolicy.level(for: intermediate.adjustedScore),
                    internalAction: reconciliation.action,
                    confidence: calculateConfidence(
                        context: context,
                        signals: collected.allSignals,
                        score: intermediate.adjustedScore
                    ),
                    primaryReasons: mergeEngineDecisionReasons(
                        base: extractPrimaryReasons(signals: collected.allSignals),
                        reconciliation: reconciliation
                    ),
                    signals: collected.allSignals,
                    scenario: scenario,
                    compressedDigest: collected.compressResult.digest,
                    mappingVersion: collected.compressResult.mappingVersion,
                    decisionMetadata: mergedDecisionMetadata(
                        intermediate.decisionHints,
                        reconciliation.metadata
                    ).isEmpty ? nil : mergedDecisionMetadata(
                        intermediate.decisionHints,
                        reconciliation.metadata
                    )
                )
            default:
                // 非法状态：fail-closed，确保篡改状态机不会产生“低风险”结论。
                poison = poison &* 0x9e3779b97f4a7c15 &+ 0xD6E8FEB86659FD93
                sink = failClosedVerdict(
                    scenario: scenario,
                    phase: "treeCommitVerdict",
                    poison: poison
                )
            }
            budget += 1
        }

        // 预算耗尽兜底：与非法状态同样 fail-closed。
        return sink ?? failClosedVerdict(
            scenario: scenario,
            phase: "treeCommitVerdict_budget",
            poison: poison
        )
    }

    /// 把调用栈回溯发现的可疑返回地址转换为 `.tampered` 信号。
    /// `weightHint = 90` 表示该证据权重很高，但仍走正常评分链路而非直接 block；
    /// 只有 dladdr 钩子这一确定性证据才在预检阶段直接拦截。
    private func makeCallStackSignal(id: String) -> RiskSignal {
        RiskSignal(
            id: id,
            category: ObfuscatedConstants.categoryAntiTamper,
            score: 0,
            evidence: [
                "detail": "call_stack_return_address_outside_trusted_regions",
                "mechanism": "dladdr_dual_path_vm_region_validation",
            ],
            state: .tampered,
            layer: 2,
            weightHint: 90
        )
    }

    /// 派生每个阶段独立的状态机密钥。
    /// 末位 `| 1` 保证 key 恒为奇数，避免与全零盐混合后退化为可预测的弱状态。
    private func regionStateKey(label: String, scenario: RiskScenario) -> UInt64 {
        fnv1a64("cff|\(label)|\(scenario.identifier)|\(policy.name)|\(policy.version)") | 1
    }

    /// 派生阶段运行时盐。
    /// 输入包含阶段名、场景、策略版本/种子、设备、越狱/网络状态、挑战偏移、
    /// 反篡改摘要（以及可选的分数提示），使同一状态机在不同环境/策略下不可复用；
    /// 任一输入被改动都会让后续 `decodeRegionState` 解出错误值并触发 fail-closed。
    private func runtimeSalt(
        phase: String,
        scenario: RiskScenario,
        context: RiskContext,
        signals: [RiskSignal],
        challengeOffsetHint: Double,
        antiTamperingDigest: UInt64,
        scoreHint: Double? = nil
    ) -> UInt64 {
        let antiTamperIDs = signals
            .filter { $0.category == ObfuscatedConstants.categoryAntiTamper || $0.state == .tampered }
            .map(\.id)
            .sorted()
            .prefix(4)
            .joined(separator: ",")
        let material = [
            phase,
            scenario.identifier,
            policy.name,
            policy.version,
            policy.mutationStrategy?.seed ?? "no_mutation_seed",
            context.deviceID,
            context.device.model,
            context.jailbreak.isJailbroken ? "jb1" : "jb0",
            context.network.isVPNActive ? "vpn1" : "vpn0",
            context.network.proxyEnabled ? "px1" : "px0",
            String(format: "%.2f", challengeOffsetHint),
            String(antiTamperingDigest, radix: 16),
            scoreHint.map { String(format: "%.2f", $0) } ?? "no_score",
            antiTamperIDs
        ].joined(separator: "|")
        return fnv1a64(material)
    }

    /// 计算反篡改相关信号的稳定摘要。
    /// 只纳入 `.tampered` 或反篡改分类的信号，并按 (id, layer) 排序后拼接，
    /// 因此信号顺序变化不会改变摘要；摘要用于后续阶段盐值和决策元数据，
    /// 使“删掉/改写一条篡改证据”会连带破坏状态机与可审计指纹。
    private func antiTamperingDigest(from signals: [RiskSignal]) -> UInt64 {
        let summary = signals
            .filter { $0.category == ObfuscatedConstants.categoryAntiTamper || $0.state == .tampered }
            .sorted { lhs, rhs in
                if lhs.id == rhs.id {
                    return (lhs.layer ?? -1) < (rhs.layer ?? -1)
                }
                return lhs.id < rhs.id
            }
            .map { signal in
                "\(signal.id)#\(signal.layer ?? -1)#\(signal.weightHint)#\(stableSignalStateTag(signal.state))"
            }
            .joined(separator: "|")
        guard !summary.isEmpty else { return 0 }
        return fnv1a64(summary)
    }

    /// 把信号状态映射为稳定字符串标签，供摘要计算使用。
    /// 浮点置信度固定到三位小数，避免二进制表示差异导致同一证据产生不同摘要。
    private func stableSignalStateTag(_ state: RiskSignalState?) -> String {
        guard let state else { return "none" }
        switch state {
        case .hard(let detected):
            return detected ? "hard1" : "hard0"
        case .soft(let confidence):
            return "soft:\(String(format: "%.3f", confidence))"
        case .serverRequired:
            return "serverRequired"
        case .unavailable:
            return "unavailable"
        case .tampered:
            return "tampered"
        }
    }

    /// 把状态字编码为不透明 UInt64。
    /// 先与 key/salt/固定常数混合，再按 key^salt 派生的 5…12 位循环移位；
    /// 目的不是密码学安全，而是让补丁/重放难以直接改写状态常量。
    private func encodeRegionState(_ raw: UInt32, key: UInt64, salt: UInt64) -> UInt64 {
        let shift = Int(((key ^ salt) & 0x7) + 5)
        let mixed = UInt64(raw) ^ key ^ salt ^ 0xD6E8FEB86659FD93
        return rotateLeft(mixed, by: shift) ^ 0xA5A5A5A5A5A5A5A5
    }

    /// 解码状态字；key/salt 不匹配或状态被改写时会得到非法值，由调用方走 fail-closed。
    private func decodeRegionState(_ encoded: UInt64, key: UInt64, salt: UInt64) -> UInt32 {
        let shift = Int(((key ^ salt) & 0x7) + 5)
        let mixed = rotateRight(encoded ^ 0xA5A5A5A5A5A5A5A5, by: shift)
        return UInt32(truncatingIfNeeded: mixed ^ key ^ salt ^ 0xD6E8FEB86659FD93)
    }

    /// 64 位循环左移。
    /// Swift 的 `<<` 对超范围移位会直接清零，因此先取模 64，才能得到真正的循环移位。
    private func rotateLeft(_ value: UInt64, by shift: Int) -> UInt64 {
        let normalized = shift & 63
        guard normalized != 0 else { return value }
        return (value << normalized) | (value >> (64 - normalized))
    }

    /// 64 位循环右移，与 `rotateLeft` 对称。
    private func rotateRight(_ value: UInt64, by shift: Int) -> UInt64 {
        let normalized = shift & 63
        guard normalized != 0 else { return value }
        return (value >> normalized) | (value << (64 - normalized))
    }

    /// 构造 fail-closed 判决：critical / block / 置信度 1.0。
    /// 仅在引擎内部完整性校验失败（区域状态被污染/解码失败/预算耗尽）时使用；
    /// 挂一条 `.tampered` 的 `engine_region_poison` 信号说明触发阶段与 poison 值，
    /// 便于日志取证；调用方不应把它当成正常业务风险。
    private func failClosedVerdict(
        scenario: RiskScenario,
        phase: String,
        poison: UInt64
    ) -> LocalAssessment {
        let poisonSignal = RiskSignal(
            id: "engine_region_poison",
            category: ObfuscatedConstants.categoryAntiTamper,
            score: 0,
            evidence: [
                "phase": phase,
                "poison": String(poison, radix: 16)
            ],
            state: .tampered,
            layer: 2,
            weightHint: 100
        )
        return LocalAssessment(
            score: 100,
            internalLevel: .critical,
            internalAction: .block,
            confidence: 1.0,
            primaryReasons: [poisonSignal.id],
            signals: [poisonSignal],
            scenario: scenario
        )
    }

    // MARK: - 信号收集

    /// 收集所有风险信号。
    /// 顺序：越狱 → 网络 → 行为 → 设备 → 自定义 Provider → 额外信号，最后统一打乱。
    /// 家族白名单只影响内置检测器；调用方 Provider 与 `.tampered` 信号始终保留。
    /// 注意：本方法只做采集与归一化，不做去重/阈值判断，计分职责属于 `calculateBaseScore`。
    private func collectSignals(
        context: RiskContext,
        scenarioPolicy: ScenarioPolicy,
        extraSignals: [RiskSignal],
        planner: MutationPlanner
    ) -> [RiskSignal] {
        var signals: [RiskSignal] = []

        // 1. 越狱信号：用置信度折算 0…100 分，保留 detectedMethods 便于人工排查。
        if detectorEnabled(ObfuscatedConstants.signalJailbreak), context.jailbreak.confidence > 0 {
            let jbScore = context.jailbreak.confidence * 100
            signals.append(
                RiskSignal(
                    id: ObfuscatedConstants.signalJailbreak,
                    category: ObfuscatedConstants.categoryJailbreak,
                    score: jbScore,
                    evidence: [
                        "is_jailbroken": "\(context.jailbreak.isJailbroken)",
                        "confidence": "\(jbScore)",
                        "methods": context.jailbreak.detectedMethods.joined(separator: ",")
                    ]
                )
            )
        }

        // 2. 网络信号
        if policy.enableNetworkSignals && detectorEnabled("network") {
            if context.network.isVPNActive {
                signals.append(
                    RiskSignal(
                        id: ObfuscatedConstants.requiredSignalVpnActive,
                        category: "network",
                        score: 10,
                        evidence: ["type": "VPN"]
                    )
                )
            }
            if context.network.proxyEnabled {
                signals.append(
                    RiskSignal(
                        id: "proxy_enabled",
                        category: "network",
                        score: 8,
                        evidence: ["type": "Proxy"]
                    )
                )
            }
        }

        // 3. 行为信号
        if policy.enableBehaviorDetection && detectorEnabled("behavior") {
            let behaviorSignals = extractBehaviorSignals(behavior: context.behavior)
            signals.append(contentsOf: behaviorSignals)
        }

        // 4. 设备信号
        if detectorEnabled("device") {
            let deviceSignals = extractDeviceSignals(
                device: context.device,
                jailbreak: context.jailbreak
            )
            signals.append(contentsOf: deviceSignals)
        }

        // 5. 自定义提供者信号：先排序再按策略打乱，保证同一配置下顺序可复现；
        //    Provider 的返回值仍要过家族白名单，但 `.tampered` 会被无条件保留。
        let providerKeys = planner.maybeShuffle(customProviders.keys.sorted(), salt: "custom_provider_order")
        for key in providerKeys {
            guard let provider = customProviders[key] else { continue }
            signals.append(contentsOf: provider(context).filter(includeSelectedSignal))
        }

        // 6. 额外信号：调用方显式传入，同样参与顺序扰动。
        signals.append(contentsOf: planner.maybeShuffle(extraSignals, salt: "extra_signal_order"))

        return planner.maybeShuffle(signals, salt: "collect_signal_order")
    }

    /// 从行为统计中提取信号。
    /// 每个阈值都要求最小样本量（tapCount/swipeCount/actionCount），
    /// 避免冷启动阶段样本不足被误判为“机器人”；数据不足本身只给低权重软信号。
    private func extractBehaviorSignals(behavior: BehaviorSignals) -> [RiskSignal] {
        var signals: [RiskSignal] = []

        // 触摸坐标分散度异常
        if let spread = behavior.touch.coordinateSpread, behavior.touch.tapCount >= 6 {
            if spread < 2.0 {
                signals.append(
                    RiskSignal(
                        id: "touch_spread_low",
                        category: "behavior",
                        score: 12,
                        evidence: ["spread": "\(spread)"]
                    )
                )
            } else if spread > 10.0 {
                signals.append(
                    RiskSignal(
                        id: "touch_spread_high",
                        category: "behavior",
                        score: 4,
                        evidence: ["spread": "\(spread)"]
                    )
                )
            }
        }

        // 触摸间隔规律性异常
        if let cv = behavior.touch.intervalCV, behavior.touch.tapCount >= 6 {
            if cv < 0.2 {
                signals.append(
                    RiskSignal(
                        id: "touch_interval_too_regular",
                        category: "behavior",
                        score: 10,
                        evidence: ["cv": "\(cv)"]
                    )
                )
            } else if cv > 0.6 {
                signals.append(
                    RiskSignal(
                        id: "touch_interval_too_chaotic",
                        category: "behavior",
                        score: 4,
                        evidence: ["cv": "\(cv)"]
                    )
                )
            }
        }

        // 滑动线性度异常
        if let lin = behavior.touch.averageLinearity, behavior.touch.swipeCount >= 3 {
            if lin > 0.98 {
                signals.append(
                    RiskSignal(
                        id: "swipe_too_linear",
                        category: "behavior",
                        score: 8,
                        evidence: ["linearity": "\(lin)"]
                    )
                )
            } else if lin < 0.90 {
                signals.append(
                    RiskSignal(
                        id: "swipe_too_curvy",
                        category: "behavior",
                        score: 4,
                        evidence: ["linearity": "\(lin)"]
                    )
                )
            }
        }

        // 设备静止度过高
        if let still = behavior.motion.stillnessRatio,
           still > 0.98,
           (behavior.touch.tapCount + behavior.touch.swipeCount) >= 10 {
            signals.append(
                RiskSignal(
                    id: "motion_too_still",
                    category: "behavior",
                    score: 10,
                    evidence: ["stillness": "\(still)"]
                )
            )
        }

        // 触摸与运动弱耦合
        if let corr = behavior.touchMotionCorrelation,
           corr < 0.10,
           behavior.actionCount >= 10,
           (behavior.motion.stillnessRatio ?? 0) > 0.95 {
            signals.append(
                RiskSignal(
                    id: "touch_motion_weak_coupling",
                    category: "behavior",
                    score: 8,
                    evidence: ["correlation": "\(corr)"]
                )
            )
        }

        let totalActions = behavior.touch.tapCount + behavior.touch.swipeCount
        let interactionExpectedButAbsent =
            behavior.actionCount >= BehaviorSignals.minimumActionCount
            && behavior.touch.sampleCount == 0
        // 有交互动作却完全没有触摸采样，属于“动作与触摸足迹矛盾”，给较高权重软信号；
        // 与单纯的“样本少”区分开，后者只说明数据不足，不能作为强风险。
        if interactionExpectedButAbsent {
            signals.append(
                RiskSignal(
                    id: SignalID.behaviorInteractionExpectedButAbsent,
                    category: "behavior",
                    score: 25,
                    evidence: [
                        "actionCount": "\(behavior.actionCount)",
                        "tapCount": "\(behavior.touch.tapCount)",
                        "swipeCount": "\(behavior.touch.swipeCount)",
                        "touchSampleCount": "\(behavior.touch.sampleCount)",
                        "motionSampleCount": "\(behavior.motion.sampleCount)",
                        "reason": "actions_without_touch_footprint",
                        "policy": "fail_closed_low_interaction"
                    ],
                    state: .soft(confidence: 0.75),
                    layer: 3,
                    weightHint: 25
                )
            )
        } else if totalActions < 3, behavior.touch.sampleCount < 5 {
            signals.append(
                RiskSignal(
                    id: "insufficient_behavior_data",
                    category: "behavior",
                    score: 5,
                    evidence: [
                        "tapCount": "\(behavior.touch.tapCount)",
                        "swipeCount": "\(behavior.touch.swipeCount)",
                        "sampleCount": "\(behavior.touch.sampleCount)"
                    ],
                    state: .soft(confidence: 0.4),
                    layer: 3,
                    weightHint: 15
                )
            )
        }

        return signals
    }

    /// 从设备指纹提取信号：可疑机型名（模拟器/虚拟化关键词）与越狱设备加分。
    /// 这些是弱特征，只作为普通信号参与评分，不单独触发强制动作。
    private func extractDeviceSignals(
        device: DeviceFingerprint,
        jailbreak: DetectionResult
    ) -> [RiskSignal] {
        var signals: [RiskSignal] = []

        // 设备年龄过短（可能是新设备或虚拟机）
        // 当前 DeviceFingerprint 不包含 deviceAgeDays 字段，跳过该项。

        // 设备名称可疑（如包含模拟器关键词）
        let suspiciousNames = ["simulator", "emulator", "x86", "arm64"]
        let deviceName = device.model.lowercased()
        if suspiciousNames.contains(where: { deviceName.contains($0) }) {
            signals.append(
                RiskSignal(
                    id: "suspicious_device_name",
                    category: "device",
                    score: 15,
                    evidence: ["name": device.model]
                )
            )
        }

        // 越狱设备加分
        if detectorEnabled(ObfuscatedConstants.signalJailbreak), jailbreak.isJailbroken {
            signals.append(
                RiskSignal(
                    id: "jailbreak_device",
                    category: "device",
                    score: 20,
                    evidence: ["methods": jailbreak.detectedMethods.joined(separator: ",")]
                )
            )
        }

        return signals
    }

    // MARK: - 分数计算

    /// 按信号状态计算基础风险分数，并返回各分量用于诊断。
    ///
    /// 状态语义：
    /// - `.hard(true)`：按权重参与硬信号折扣聚合；`.hard(false)` 表示“确认正常”，不计分；
    /// - `.soft(c)`：仅当 `c > softGate` 时计 `weight × c × 0.3`，低置信度推测被抑制；
    /// - `.tampered`：计入 `tamperedCount`，并按 `max(tamperedBase, weight)` 加分；
    /// - `.serverRequired` / `.unavailable`：不直接计分，前者等待服务端裁决，后者表示数据缺失；
    /// - 无状态信号：按分类权重 × `signal.score` 计入 legacy 分量。
    ///
    /// 硬/软分之和再乘 `1 + 0.5 × 篡改信号数`，最后夹到 0…100 并叠加白盒 PRF 扰动。
    private func calculateBaseScore(
        signals: [RiskSignal],
        weights: SignalWeights,
        weightOverrides: [String: Double],
        planner: MutationPlanner
    ) -> ScoreComponents {
        var legacyScore: Double = 0
        var hardWeightsBySignalID: [String: Double] = [:]
        var softScore: Double = 0
        var tamperedCount = 0
        // 软信号门限与篡改底分都会按策略抖动，分别限制在合理区间，避免配置把弱信号当强信号。
        let softGate = planner.softConfidenceGate(default: 0.3)
        let tamperedBase = planner.tamperedBase(default: 60)

        for signal in signals {
            if let state = signal.state {
                let weight = signalWeight(for: signal, overrides: weightOverrides, planner: planner)
                switch state {
                case .hard(let detected):
                    if detected {
                        // 同一 id 的硬信号只保留最大权重，防止重复上报把分数放大。
                        hardWeightsBySignalID[signal.id] = max(hardWeightsBySignalID[signal.id] ?? 0, weight)
                    }
                case .soft(let confidence):
                    let normalized = min(max(confidence, 0), 1)
                    // 软信号最多贡献权重的 30%，定位为“辅证”，不能单独定案。
                    if normalized > softGate {
                        softScore += weight * normalized * 0.3
                    }
                case .tampered:
                    // 篡改证据按固定底分计，避免伪造的低 weightHint 把篡改信号压到接近 0。
                    tamperedCount += 1
                    softScore += max(tamperedBase, weight)
                case .serverRequired, .unavailable:
                    // 故意不计分：前者需要服务端裁决，后者代表数据缺失而非风险。
                    break
                }
                continue
            }

            // legacy 路径：无状态信号沿用分类权重，权重同样做小幅抖动以削弱固定阈值探测。
            let w = weights.weight(for: signal.category)
            let categoryWeight = planner.jitter(
                base: w.isFinite ? w : 1.0,
                maxBps: policy.mutationStrategy?.scoreJitterBps ?? 0
            )
            // 非有限分数按 0 处理，避免 NaN/Inf 污染整条链路。
            let safeScore = signal.score.isFinite ? signal.score : 0
            legacyScore += safeScore * categoryWeight
        }

        // 硬信号走折扣聚合（见 aggregateHardScore），避免同源信号简单求和导致分数爆炸。
        let hardScore = aggregateHardScore(Array(hardWeightsBySignalID.values))
        // 篡改是“元证据”：出现越多，硬/软分的可信度越低，因此整体放大。
        let tamperedMultiplier = 1.0 + Double(tamperedCount) * 0.5
        let v3Component = (hardScore + softScore) * tamperedMultiplier
        let baseTotal = min(100, max(0, legacyScore + v3Component))
        var total = baseTotal
        // 白盒 PRF 扰动：可用时对总分做确定性的 ±1 偏移，增加离线复现/调参难度；
        // 白盒不可用或调用失败时静默跳过，不影响主判决。
        if cprisk_whitebox_available() != 0 {
            var prfIn = [UInt8](repeating: 0, count: 32)
            var prfOut = [UInt8](repeating: 0, count: 32)
            if cprisk_whitebox_evaluate_domain(0, &prfIn, &prfOut) == 0 {
                var fold: UInt32 = 0
                for b in prfOut {
                    fold = fold &+ UInt32(b)
                    fold = fold &* 0x01000193
                }
                let delta = ((fold >> 17) & 1) == 0 ? -1.0 : 1.0
                total = min(100, max(0, baseTotal + delta))
            }
        }

        return ScoreComponents(
            total: total,
            legacyComponent: legacyScore,
            hardComponent: hardScore,
            softComponent: softScore,
            tamperedCount: tamperedCount
        )
    }

    /// 关键信号的权重下限表。
    ///
    /// `weightHint` 由信号提供者填写，可能被篡改或伪造；若把关键信号的 hint 改成很小的值，
    /// 它就会近乎不计分，从而绕过防护。因此 `signalWeight` 对每一档权重都取
    /// `max(candidate, minWeight)`，保证这些信号即使 hint 被伪造也保持最低贡献量级。
    /// 表中数值按“证据确定性/伪造难度”分级：确定性运行时证据（如 rop_chain）最高。
    private static var criticalSignalMinWeights: [String: Double] { [
        "vphone_hardware": 50,
        "gpu_virtual": 50,
        ObfuscatedConstants.signalHookDetected: 40,
        ObfuscatedConstants.signalJailbreak: 30,
        "blocklist_hit": 50,
        "cross_layer_inconsistency": 40,
        "sdk_binary_replaced": 50,
        "plt_integrity_tampered": 40,
        "frida_thread_anomaly": 30,
        "frida_js_engine_heap": 30,
        SignalID.fridaModuleTrampoline: 42,
        SignalID.fridaRuntimeConsensus: 58,
        SignalID.antiDebugRuntimeConsensus: 54,
        SignalID.signingChainConsensus: 60,
        "dyld_interpose_detected": 40,
        SignalID.antiDebugWatchdogDyldInjection: 55,
        SignalID.antiDebugWatchdogDenyAttachVerify: 52,
        SignalID.antiDebugWatchdogAMFICsFlags: 55,
        SignalID.antiDebugWatchdogGetTaskAllow: 60,
        SignalID.antiDebugWatchdogPacThreadEntry: 58,
        SignalID.antiDebugWatchdogVmImageLayoutDrift: 52,
        SignalID.whiteboxPrfProbeDegraded: 50,
        SignalID.ifaceSpawnPathDivergence: 48,
        "rop_chain_detected": 90,
    ] }

    /// 解析单个信号的生效权重。
    ///
    /// 优先级：`weightHint` > 显式 `overrides` > 内置 v3 默认权重 > 信号自带 `score`。
    /// 每一档都与 `criticalSignalMinWeights` 取 max，确保关键信号的下限不可被绕过；
    /// 随后的 `scoreJitterBps` 抖动只会在下限附近小幅浮动，不会回到“伪造低 hint”的水平。
    private func signalWeight(
        for signal: RiskSignal,
        overrides: [String: Double],
        planner: MutationPlanner
    ) -> Double {
        let minWeight = Self.criticalSignalMinWeights[signal.id] ?? 0
        let baseWeight: Double
        if signal.weightHint > 0 {
            // minWeight must be enforced even when weightHint is explicitly set.
            // Without max(), a critical signal whose weightHint is set to a low value
            // (e.g. by a compromised/forged provider signal) would silently bypass
            // its guaranteed floor, letting it contribute near-zero to the score.
            // 显式 hint 也必须服从下限，否则伪造低 hint 就能让关键信号“消失”。
            baseWeight = max(signal.weightHint, minWeight)
            return planner.jitter(base: baseWeight, maxBps: policy.mutationStrategy?.scoreJitterBps ?? 0)
        }
        if let override = overrides[signal.id], override > 0 {
            baseWeight = max(override, minWeight)
            return planner.jitter(base: baseWeight, maxBps: policy.mutationStrategy?.scoreJitterBps ?? 0)
        }
        if let fallback = Self.defaultV3SignalWeights[signal.id], fallback > 0 {
            baseWeight = max(fallback, minWeight)
            return planner.jitter(base: baseWeight, maxBps: policy.mutationStrategy?.scoreJitterBps ?? 0)
        }
        baseWeight = max(max(signal.score, 0), minWeight)
        return planner.jitter(base: baseWeight, maxBps: policy.mutationStrategy?.scoreJitterBps ?? 0)
    }

    /// 压缩摘要快速判决：若位向量规则命中，返回短路判决；否则返回 nil。
    /// 命中多条规则时取动作严重度最高者，并把分数抬到该动作对应的最低档位，
    /// 保证“动作=block 但分数=low”这类矛盾不会出现在短路结果里。
    private func evaluateCompressedVerdictRules(
        digest: Data,
        scenarioPolicy: ScenarioPolicy,
        signals: [RiskSignal],
        scenario: RiskScenario
    ) -> LocalAssessment? {
        let rules = scenarioPolicy.compressedVerdictRules
        guard !rules.isEmpty else { return nil }

        var matchedRules: [CompressedVerdictRule] = []
        for rule in rules {
            if rule.matches(digest: digest) {
                matchedRules.append(rule)
            }
        }
        guard !matchedRules.isEmpty else { return nil }

        // 取最严格动作
        guard let strictestRule = matchedRules.max(by: { $0.action.severity < $1.action.severity }) else {
            return nil
        }
        let score = minScore(for: strictestRule.action, scenarioPolicy: scenarioPolicy)

        return LocalAssessment(
            score: score,
            internalLevel: scenarioPolicy.level(for: score),
            internalAction: strictestRule.action,
            confidence: 1.0,
            primaryReasons: ["compressed_rule:\(strictestRule.id)"],
            signals: signals,
            scenario: scenario,
            compressedDigest: digest,
            mappingVersion: SignalCompressor.mappingVersion,
            decisionMetadata: [
                "compressed_rule": strictestRule.id,
                "compressed_rule_action": String(strictestRule.action.rawValue),
                "short_circuit_path": "compressed_rule"
            ]
        )
    }

    /// 应用 ComboRule 加分。
    ///
    /// ComboRule 可表达硬 AND（全部信号在场）或带权 N-of-M（累加权重达阈值），
    /// 后者能抵抗“让任一信号失效即整体规避”的逐项绕过；这里只负责累加命中规则的
    /// bonus，强制动作由 `applyForceRules` 单独处理。非法/负 bonus 按 0 处理。
    private func applyComboRules(
        signals: [RiskSignal],
        comboRules: [ComboRule]
    ) -> Double {
        var bonus: Double = 0

        for rule in comboRules {
            if rule.matches(signals: signals) {
                let safeBonus = max(0, rule.bonusScore.isFinite ? rule.bonusScore : 0)
                log("Combo rule matched: \(rule.name), bonus: +\(safeBonus)")
                bonus += safeBonus
            }
        }

        return bonus
    }

    /// 应用强制规则，返回抬升后的分数与强制动作。
    ///
    /// 三类来源：服务端黑名单、越狱设备策略、带 `forceAction` 的 ComboRule。
    /// 强制动作与最低分同时抬升（`minScore(for:)`），避免出现动作与分数档位矛盾；
    /// 多个来源取最严格者，永远只会升级、不会降级。
    private func applyForceRules(
        score: Double,
        context: RiskContext,
        signals: [RiskSignal],
        scenarioPolicy: ScenarioPolicy
    ) -> (Double, RiskAction?) {
        var adjustedScore = score
        var forcedAction: RiskAction? = nil

        guard scenarioPolicy.enableForceRules else {
            return (adjustedScore, forcedAction)
        }

        // 服务端黑名单强制规则
        let blocklistHit = signals.contains(where: { $0.id == SignalID.blocklistHit })
        if blocklistHit, let blocklistAction = policy.blocklistAction {
            forcedAction = strictestAction(forcedAction, blocklistAction)
            adjustedScore = max(adjustedScore, minScore(for: blocklistAction, scenarioPolicy: scenarioPolicy))
        }

        // 越狱设备强制规则
        if detectorEnabled(ObfuscatedConstants.signalJailbreak), context.jailbreak.isJailbroken {
            if let jailbreakAction = policy.forceActionOnJailbreak {
                forcedAction = strictestAction(forcedAction, jailbreakAction)
                adjustedScore = max(adjustedScore, minScore(for: jailbreakAction, scenarioPolicy: scenarioPolicy))
            } else {
                // 保持向后兼容：即使没有强制动作，越狱分数也不低于高风险阈值。
                adjustedScore = max(adjustedScore, scenarioPolicy.highThreshold)
            }
        }

        // ComboRule 命中且带 forceAction 时强制应用（如 Impossible States）。
        // 例如“硬件正常 + 传感器缺失 + 反篡改命中”这种物理上矛盾的组合，应直接升级处置。
        for rule in scenarioPolicy.comboRules {
            guard let action = rule.forceAction else { continue }
            if rule.matches(signals: signals) {
                forcedAction = strictestAction(forcedAction, action)
                adjustedScore = max(adjustedScore, minScore(for: action, scenarioPolicy: scenarioPolicy))
            }
        }

        return (adjustedScore, forcedAction)
    }

    /// 取两个动作中更严格者；左侧为空时直接采用右侧。
    private func strictestAction(_ lhs: RiskAction?, _ rhs: RiskAction) -> RiskAction {
        guard let lhs else { return rhs }
        return lhs.severity >= rhs.severity ? lhs : rhs
    }

    /// 非可选版本：按 `severity` 取更严格动作。
    private func strictestAction(_ lhs: RiskAction, _ rhs: RiskAction) -> RiskAction {
        lhs.severity >= rhs.severity ? lhs : rhs
    }

    /// 证书固定（certificate pinning）异常的按场景保底。
    ///
    /// 仅在支付/注册/登录/改户/敏感操作等场景生效；根据异常强度分三档：
    /// 软时序异常 → medium 阈值，硬完整性异常 → high 阈值，`.tampered` 路径 → critical。
    /// 设计动机：中间人攻击常先表现为连接时序/证书链异常，单靠累计分可能达不到档位，
    /// 因此在敏感场景额外设置下限，并记录 `pinning_floor_*` 元数据供服务端核对。
    private func applyCertificatePinningScenarioFloors(
        score: Double,
        forcedAction: RiskAction?,
        scenario: RiskScenario,
        signals: [RiskSignal],
        scenarioPolicy: ScenarioPolicy
    ) -> (adjustedScore: Double, forcedAction: RiskAction?, decisionHints: [String: String]) {
        guard isCertificatePinningFloorScenario(scenario) else {
            return (score, forcedAction, [:])
        }

        let pinSignals = signals.filter { $0.id == SignalID.certificatePinningAnomaly }
        guard !pinSignals.isEmpty else {
            return (score, forcedAction, [:])
        }

        /// 证书固定异常的强度分级；数值越大处置越严格。
        enum Tier: Int {
            case none = 0
            case softTiming = 1
            case hardIntegrity = 2
            case tamperedPath = 3
        }

        var strongest: Tier = .none
        for signal in pinSignals {
            switch signal.state {
            case .tampered?:
                strongest = .tamperedPath
            case .hard(let detected)? where detected:
                if strongest.rawValue < Tier.hardIntegrity.rawValue {
                    strongest = .hardIntegrity
                }
            case .soft(let confidence)? where confidence >= 0.5:
                if strongest.rawValue < Tier.softTiming.rawValue {
                    strongest = .softTiming
                }
            default:
                continue
            }
        }

        guard strongest != .none else {
            return (score, forcedAction, [:])
        }

        var hints: [String: String] = [
            "pinning_floor_applied": "1",
            "pinning_floor_signal_count": "\(pinSignals.count)",
        ]
        var adjustedScore = score
        var resolvedAction = forcedAction

        switch strongest {
        case .softTiming:
            hints["pinning_floor_tier"] = "soft_timing"
            adjustedScore = max(adjustedScore, scenarioPolicy.mediumThreshold)
            let action: RiskAction = scenario == .payment ? .stepUpAuth : .challenge
            resolvedAction = strictestAction(resolvedAction, action)
        case .hardIntegrity:
            hints["pinning_floor_tier"] = "hard_integrity"
            adjustedScore = max(adjustedScore, scenarioPolicy.highThreshold)
            let action: RiskAction = scenario == .payment ? .block : .stepUpAuth
            resolvedAction = strictestAction(resolvedAction, action)
        case .tamperedPath:
            hints["pinning_floor_tier"] = "tampered_path"
            adjustedScore = max(adjustedScore, scenarioPolicy.criticalThreshold)
            resolvedAction = strictestAction(resolvedAction, .block)
        case .none:
            break
        }

        hints["pinning_floor_score"] = String(format: "%.1f", adjustedScore)
        if let resolvedAction {
            hints["pinning_floor_action"] = String(resolvedAction.rawValue)
        }
        return (adjustedScore, resolvedAction, hints)
    }

    /// 判断场景是否属于“证书固定异常需要保底”的高敏感场景。
    /// 查询/默认/API 访问不启用，避免普通读取场景被网络抖动过度处置。
    private func isCertificatePinningFloorScenario(_ scenario: RiskScenario) -> Bool {
        switch scenario {
        case .payment, .register, .login, .accountChange, .sensitiveAction:
            return true
        case .query, .default, .apiAccess:
            return false
        @unknown default:
            return false
        }
    }

    /// 将「决策树 / ForceRule」的初步动作与 **分数档位策略动作**、**多源证据聚合升级**对齐，避免：
    /// - 越狱等单点 ForceRule 被绕过时，累计分已超过档位却仍被树路径放行；
    /// - 仅依赖某一 detector 的强制规则而忽略跨层/跨家族一致性。
    ///
    /// 聚合升级条件（满足其一且分数达到 highThreshold）：
    /// - 2 条以上高置信 Frida 信号；
    /// - 3 条以上高置信反篡改信号；
    /// - 2 条以上篡改信号且分布在 2 个以上 layer；
    /// - 3 个以上独立风险家族。
    /// 命中 criticalThreshold 时升级为 block，否则至少 stepUpAuth；结果只升不降。
    /// 元数据会记录命中的规则、是否与档位保底重叠，便于服务端复核证据链。
    private func reconcileAggregateDecision(
        preliminaryAction: RiskAction,
        treeAction: RiskAction,
        intermediate: IntermediateDecision,
        scenarioPolicy: ScenarioPolicy,
        signals: [RiskSignal],
        context: RiskContext
    ) -> DecisionReconciliation {
        var meta: [String: String] = [:]
        var reasonTags: [String] = []
        let score = intermediate.adjustedScore
        let policyFloor = scenarioPolicy.action(for: scenarioPolicy.level(for: score))

        // 第一步：分数档位保底。即使决策树给出 allow，累计分到了 high/critical 也必须升级。
        var action = strictestAction(preliminaryAction, policyFloor)
        if action != preliminaryAction {
            meta["policy_score_floor"] = "1"
            meta["pre_action"] = String(preliminaryAction.rawValue)
            meta["tree_action"] = String(treeAction.rawValue)
            meta["floor_action"] = String(policyFloor.rawValue)
            reasonTags.append("engine:policy_score_floor")
        }

        let families = countRiskFamilies(signals: signals, context: context)
        meta["risk_family_count"] = String(families)

        let fridaCluster = countFridaHighConfidenceSignals(signals)
        meta["frida_cluster_signals"] = String(fridaCluster)

        let antiTamperCluster = countHighConfidenceAntiTamperSignals(signals)
        meta["anti_tamper_cluster_signals"] = String(antiTamperCluster)

        let tamperedLayers = Set(signals.filter { $0.state == .tampered }.compactMap { $0.layer })
        meta["distinct_tamper_layers"] = String(tamperedLayers.count)
        meta["tampered_signal_count"] = String(intermediate.scoreComponents.tamperedCount)

        // 第二步：多源证据聚合。单点规则可能被绕过，但“同一攻击面的多条独立证据”
        // 同时出现时，应比单条信号获得更强的处置。
        var aggregateTarget: RiskAction?
        var ruleLabel = ""

        if fridaCluster >= 2, score >= scenarioPolicy.highThreshold {
            aggregateTarget = score >= scenarioPolicy.criticalThreshold ? RiskAction.block : .stepUpAuth
            ruleLabel = "frida_cluster"
        } else if antiTamperCluster >= 3, score >= scenarioPolicy.highThreshold {
            aggregateTarget = score >= scenarioPolicy.criticalThreshold ? .block : .stepUpAuth
            ruleLabel = "anti_tamper_cluster"
        } else if intermediate.scoreComponents.tamperedCount >= 2,
                  tamperedLayers.count >= 2,
                  score >= scenarioPolicy.highThreshold {
            aggregateTarget = score >= scenarioPolicy.criticalThreshold ? .block : .stepUpAuth
            ruleLabel = "multi_layer_tamper"
        } else if families >= 3, score >= scenarioPolicy.highThreshold {
            aggregateTarget = score >= scenarioPolicy.criticalThreshold
                ? policyFloor
                : .stepUpAuth
            ruleLabel = "multi_family"
        }

        if let aggregateTarget {
            let beforeAgg = action
            action = strictestAction(action, aggregateTarget)
            meta["aggregate_rule"] = ruleLabel
            meta["aggregate_target_action"] = String(aggregateTarget.rawValue)
            if action.severity > beforeAgg.severity {
                meta["aggregate_escalation"] = "1"
                reasonTags.append("engine:aggregate_escalation")
            } else {
                // 仍记录命中：常与 policy_score_floor 同效，便于服务端核对「多源证据链」未被单点规则绑架。
                meta["aggregate_escalation"] = "0"
                meta["aggregate_redundant_with_floor"] = "1"
            }
            reasonTags.append("engine:aggregate_trace")
        }

        // 记录“证据已出现但分数未达阈值”的探测痕迹：动作不升级，但服务端可据此观察慢速渗透。
        if meta["aggregate_rule"] == nil, families >= 3 || fridaCluster >= 2 || tamperedLayers.count >= 2 {
            meta["aggregate_probe"] = "below_escalation_threshold"
        }

        if meta["policy_score_floor"] == "1" || meta["aggregate_escalation"] == "1" {
            meta["server_correlation_hint"] = "telemetry_and_policy_alignment"
            meta["local_action_grading"] = String(action.rawValue)
        }

        return DecisionReconciliation(action: action, metadata: meta, reasonTags: reasonTags)
    }

    /// 粗粒度「风险家族」计数：同一类单点被绕过时不应清零其它家族的贡献。
    private func countRiskFamilies(signals: [RiskSignal], context: RiskContext) -> Int {
        var families = Set<String>()
        if detectorEnabled(ObfuscatedConstants.signalJailbreak), context.jailbreak.isJailbroken { families.insert("jailbreak_ctx") }
        if signals.contains(where: { $0.id == ObfuscatedConstants.signalJailbreak }) {
            families.insert("jailbreak_sig")
        }
        if signals.contains(where: {
            $0.state == .tampered || $0.category == ObfuscatedConstants.categoryAntiTamper
        }) {
            families.insert("anti_tamper")
        }
        if signals.contains(where: { $0.id.lowercased().contains("frida") }) {
            families.insert("frida")
        }
        if signals.contains(where: { $0.category == "network" }) { families.insert("network") }
        if signals.contains(where: { $0.category == "behavior" }) { families.insert("behavior") }
        if signals.contains(where: { $0.category == "device" }) { families.insert("device") }
        return families.count
    }

    /// 统计高置信 Frida 信号数量。
    /// 只接受 `.hard(true)`、`.tampered` 或置信度 ≥0.85 的软信号；
    /// `.serverRequired/.unavailable` 不计数，避免把“待定/缺失”误当成证据。
    private func countFridaHighConfidenceSignals(_ signals: [RiskSignal]) -> Int {
        signals.filter { signal in
            guard signal.id.lowercased().contains("frida") else { return false }
            guard let state = signal.state else { return false }
            switch state {
            case .hard(let detected):
                return detected
            case .tampered:
                return true
            case .soft(let confidence):
                return confidence >= 0.85
            case .serverRequired, .unavailable:
                return false
            }
        }.count
    }

    /// 统计高置信反篡改信号数量（按 id 去重）。
    /// 同一 id 被多个检测器重复上报只算一条，避免单点证据被重复计数触发聚合升级。
    private func countHighConfidenceAntiTamperSignals(_ signals: [RiskSignal]) -> Int {
        var ids = Set<String>()
        for signal in signals {
            let antiTamperLike = signal.category == ObfuscatedConstants.categoryAntiTamper || signal.state == .tampered
            guard antiTamperLike else { continue }
            switch signal.state {
            case .tampered?:
                ids.insert(signal.id)
            case .hard(let detected)? where detected:
                ids.insert(signal.id)
            case .soft(let confidence)? where confidence >= 0.7:
                ids.insert(signal.id)
            default:
                continue
            }
        }
        return ids.count
    }

    /// 多硬信号折扣聚合（w1 + w2×0.45 + w3×0.30 + w4×0.20 + …×0.15，最后夹到 100）。
    ///
    /// 为什么不是简单求和：同一攻击面通常会同时触发多个同源硬信号
    /// （例如 Frida 的线程异常、堆特征、trampoline 等多条探针），直接相加会让分数
    /// 瞬间爆表并掩盖其它独立证据。折扣保留“信号越多越强”的方向，又抑制同源信号的
    /// 叠加放大；先排序再加权，保证结果与信号到达顺序无关。
    private func aggregateHardScore(_ weights: [Double]) -> Double {
        guard !weights.isEmpty else { return 0 }
        let sorted = weights.sorted(by: >)
        let discounts: [Double] = [0.45, 0.3, 0.2]
        var total = sorted[0]
        for (index, weight) in sorted.dropFirst().enumerated() {
            let factor = index < discounts.count ? discounts[index] : 0.15
            total += weight * factor
        }
        return min(total, 100)
    }

    /// 对账压缩摘要短路判决。
    ///
    /// 短路规则可能只看到部分证据，因此这里重新跑一次完整计分，并取两者分数的较大值；
    /// 再套用聚合升级逻辑，确保“短路命中”不会让最终动作比完整评分更宽松。
    /// - Returns: 合并分数、动作、置信度、原因与元数据后的最终判决。
    private func reconcileShortCircuitVerdict(
        baseVerdict: LocalAssessment,
        context: RiskContext,
        scenario: RiskScenario,
        collected: CollectedSignalContext
    ) -> LocalAssessment {
        let intermediate = scoreAndForceDecision(
            context: context,
            scenario: scenario,
            collected: collected
        )
        let effectiveScore = max(baseVerdict.score, intermediate.adjustedScore)
        let effectiveIntermediate = IntermediateDecision(
            adjustedScore: effectiveScore,
            forcedAction: intermediate.forcedAction,
            rawFinalScore: max(baseVerdict.score, intermediate.rawFinalScore),
            scoreComponents: intermediate.scoreComponents,
            decisionHints: intermediate.decisionHints
        )
        let preliminaryAction = strictestAction(
            baseVerdict.internalAction,
            intermediate.forcedAction ?? baseVerdict.internalAction
        )
        let reconciliation = reconcileAggregateDecision(
            preliminaryAction: preliminaryAction,
            treeAction: baseVerdict.internalAction,
            intermediate: effectiveIntermediate,
            scenarioPolicy: collected.scenarioPolicy,
            signals: collected.allSignals,
            context: context
        )
        let metadata = mergedDecisionMetadata(
            mergedDecisionMetadata(baseVerdict.decisionMetadata, effectiveIntermediate.decisionHints),
            reconciliation.metadata
        )
        return LocalAssessment(
            score: effectiveScore,
            internalLevel: collected.scenarioPolicy.level(for: effectiveScore),
            internalAction: reconciliation.action,
            confidence: calculateConfidence(
                context: context,
                signals: collected.allSignals,
                score: effectiveScore
            ),
            primaryReasons: mergeEngineDecisionReasons(
                base: baseVerdict.primaryReasons,
                reconciliation: reconciliation
            ),
            signals: collected.allSignals,
            scenario: scenario,
            compressedDigest: baseVerdict.compressedDigest,
            mappingVersion: baseVerdict.mappingVersion,
            decisionMetadata: metadata.isEmpty ? nil : metadata
        )
    }

    /// 合并两层决策元数据，`overlay` 覆盖同名键。
    /// 元数据只用于诊断/对账，不允许影响分数或动作。
    private func mergedDecisionMetadata(
        _ base: [String: String]?,
        _ overlay: [String: String]
    ) -> [String: String] {
        var merged = base ?? [:]
        for (key, value) in overlay {
            merged[key] = value
        }
        return merged
    }

    /// 合并引擎对账原因与信号原因，对账标签排在前面，最多保留 8 条。
    /// 上限用于控制上报体积；对账标签优先，确保“为什么升级”不会被大量信号原因挤掉。
    private func mergeEngineDecisionReasons(
        base: [String],
        reconciliation: DecisionReconciliation
    ) -> [String] {
        var merged: [String] = []
        merged.append(contentsOf: reconciliation.reasonTags)
        merged.append(contentsOf: base)
        if merged.count > 8 {
            return Array(merged.prefix(8))
        }
        return merged
    }

    /// 返回某个动作对应的最低分数档位，用于“动作与分数一致性”保底。
    /// `.allow` 必须返回 0：若返回 mediumThreshold，会出现 action=allow 但 level=medium
    /// 的矛盾，并在某个黑名单/组合规则以 `.allow` 为动作时静默抬高分数。
    private func minScore(for action: RiskAction, scenarioPolicy: ScenarioPolicy) -> Double {
        switch action {
        case .allow:
            // Forcing .allow should NOT elevate the score. Returning mediumThreshold would
            // produce a contradiction: action=allow but internalLevel=.medium, and would
            // silently inflate the score when a blocklist/comboRule uses .allow as its action.
            return 0
        case .challenge:
            return scenarioPolicy.mediumThreshold
        case .stepUpAuth:
            return scenarioPolicy.highThreshold
        case .block:
            return scenarioPolicy.criticalThreshold
        }
    }

    // MARK: - 置信度计算

    /// 计算判决置信度（0…1）。
    ///
    /// 公式：0.3 基础值
    /// + min(信号数 × 0.05, 0.3)
    /// + min(高分信号数 × 0.1, 0.2)
    /// + 越狱命中 0.2
    /// + 行为样本充足 0.1，最后夹到 1.0。
    /// 注意这里的“高分信号”只看 `signal.score`，不看 `weightHint`；
    /// 因此状态信号不会过度抬高置信度，置信度主要反映“证据数量与多样性”。
    /// 非有限或负值兜底为 0.5，避免坏数据让调用方无法判断可信程度。
    private func calculateConfidence(
        context: RiskContext,
        signals: [RiskSignal],
        score: Double
    ) -> Double {
        var confidence = 0.3 // 基础置信度

        // 信号数量越多，置信度越高
        let signalCount = signals.count
        confidence += min(Double(signalCount) * 0.05, 0.3)

        // 高分信号增加置信度
        let highScoreSignals = signals.filter { $0.score >= 10 }.count
        confidence += min(Double(highScoreSignals) * 0.1, 0.2)

        // 越狱检测命中显著提高置信度
        if detectorEnabled(ObfuscatedConstants.signalJailbreak), context.jailbreak.isJailbroken {
            confidence += 0.2
        }

        // 行为数据充足提高置信度
        if detectorEnabled("behavior"), context.behavior.actionCount >= 10 {
            confidence += 0.1
        }

        let result = min(confidence, 1.0)
        return result.isFinite && result >= 0 ? result : 0.5
    }

    /// 提取主要原因
    ///
    /// Sort key 使用 `max(score, weightHint)`，而非单纯的 `.score`。
    /// 原因：状态驱动信号（.tampered/.hard）统一将 score 设为 0，
    /// 实际权重由 weightHint 表达。若仅按 score 排序，这些高危信号会被
    /// 行为信号（score=10/8/5）压到末尾，导致主要原因与实际评分依据脱节。
    ///
    /// 返回格式为 `category_id`（当 id 与 category 相同则只保留 category），
    /// 便于服务端按稳定前缀聚合；最多保留 5 条以控制上报体积。
    private func extractPrimaryReasons(signals: [RiskSignal]) -> [String] {
        signals
            .sorted { max($0.score, $0.weightHint) > max($1.score, $1.weightHint) }
            .prefix(5)
            .map { signal in
                var reason = signal.category
                if !signal.id.isEmpty && signal.id != signal.category {
                    reason += "_" + signal.id
                }
                return reason
            }
    }

    /// 按策略对场景阈值做确定性抖动。
    /// 抖动后强制重新夹紧，保证 `medium < high < critical` 且落在 0…100：
    /// 否则一次抖动可能让阈值倒挂，导致档位判断（`level(for:)`）产生不可预测的动作。
    private func mutatedScenarioPolicy(base: ScenarioPolicy, planner: MutationPlanner) -> ScenarioPolicy {
        let jitterBps = policy.mutationStrategy?.thresholdJitterBps ?? 0
        guard jitterBps > 0 else { return base }

        var medium = planner.jitter(base: base.mediumThreshold, maxBps: jitterBps)
        var high = planner.jitter(base: base.highThreshold, maxBps: jitterBps)
        var critical = planner.jitter(base: base.criticalThreshold, maxBps: jitterBps)

        // 逐级夹紧而非各自独立夹紧：确保即使抖动方向相反也不会出现 medium ≥ high。
        medium = min(max(0, medium), 98)
        high = min(max(medium + 1, high), 99)
        critical = min(max(high + 1, critical), 100)

        return ScenarioPolicy(
            mediumThreshold: medium,
            highThreshold: high,
            criticalThreshold: critical,
            actionMapping: base.actionMapping,
            signalWeights: base.signalWeights,
            comboRules: base.comboRules,
            enableForceRules: base.enableForceRules,
            compressedVerdictRules: base.compressedVerdictRules
        )
    }

    /// 根据服务端下发的黑名单派生 `blocklist_hit` 硬信号。
    ///
    /// 只检查 `category == "server"` 或 id 以 `server_` 开头的信号，避免本地信号
    /// 意外匹配黑名单；匹配前对两侧做同构归一化（小写、按分隔符切分、去端口），
    /// 命中后生成 weightHint=100 的硬信号，由强制规则抬升动作。
    /// 没有配置、配置为空或未命中时返回空数组，不做任何隐式加码。
    private func deriveBlocklistSignals(from signals: [RiskSignal]) -> [RiskSignal] {
        guard let configured = policy.serverBlocklist, !configured.isEmpty else { return [] }
        let normalizedBlocklist = Set(configured.flatMap { blocklistTokens(from: $0) })
        guard !normalizedBlocklist.isEmpty else { return [] }

        var matchedTokens = Set<String>()
        var matchedSources = Set<String>()

        for signal in signals {
            let isServerSignal = signal.category == "server" || signal.id.hasPrefix("server_")
            guard isServerSignal else { continue }

            for (token, source) in blocklistCandidates(for: signal) where normalizedBlocklist.contains(token) {
                matchedTokens.insert(token)
                matchedSources.insert(source)
            }
        }

        // 只产生一条聚合信号，evidence 中保留全部命中 token/来源，便于服务端追溯；
        // 不逐 token 生成信号，避免黑名单命中导致硬信号数量膨胀。
        guard !matchedTokens.isEmpty else { return [] }
        return [
            RiskSignal(
                id: "blocklist_hit",
                category: "server",
                score: 0,
                evidence: [
                    "matched": matchedTokens.sorted().joined(separator: ","),
                    "sources": matchedSources.sorted().joined(separator: ","),
                ],
                state: .hard(detected: true),
                layer: 4,
                weightHint: 100
            ),
        ]
    }

    /// 枚举一条服务端信号中所有可能命中的黑名单 token，并标注来源字段。
    /// 同时检查 id 与 evidence 的每个 value，防止黑名单条目只出现在证据里而漏配。
    private func blocklistCandidates(for signal: RiskSignal) -> [(token: String, source: String)] {
        var out: [(token: String, source: String)] = []
        for token in blocklistTokens(from: signal.id) {
            out.append((token: token, source: "id:\(signal.id)"))
        }
        for (key, value) in signal.evidence {
            for token in blocklistTokens(from: value) {
                out.append((token: token, source: "\(signal.id).\(key)"))
            }
        }
        return out
    }

    /// 把原始字符串归一化为候选 token 集合。
    /// 规则：trim + 小写；整串本身、按 `,;|`/空白切分出的片段，以及去掉端口后的 host
    /// 都作为候选。这样 `evil.com:443`、`EVIL.COM`、`a,evil.com` 等形式都能命中同一条黑名单。
    private func blocklistTokens(from raw: String) -> [String] {
        let normalized = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !normalized.isEmpty else { return [] }

        var set = Set<String>()
        set.insert(normalized)
        normalized
            .split(whereSeparator: { $0 == "," || $0 == ";" || $0 == "|" || $0.isWhitespace })
            .map(String.init)
            .filter { !$0.isEmpty }
            .forEach { set.insert($0) }

        for item in Array(set) {
            if let host = stripPort(from: item) {
                set.insert(host)
            }
        }
        return Array(set)
    }

    /// 从 host:port 中剥离端口，仅返回 host。
    /// 支持 IPv6 方括号形式 `[::1]:443` 与普通 `host:80`；
    /// 不是“恰好一个冒号 + 数字后缀”的字符串返回 nil，避免把 IPv6 裸地址误当 host:port。
    private func stripPort(from value: String) -> String? {
        if value.hasPrefix("["),
           let endBracket = value.firstIndex(of: "]"),
           value.index(after: endBracket) < value.endIndex,
           value[value.index(after: endBracket)] == ":" {
            let host = value[value.index(after: value.startIndex)..<endBracket]
            return host.isEmpty ? nil : String(host)
        }

        let colonCount = value.reduce(into: 0) { count, char in
            if char == ":" { count += 1 }
        }
        guard colonCount == 1, let idx = value.lastIndex(of: ":") else { return nil }

        let suffix = value[value.index(after: idx)...]
        guard !suffix.isEmpty, suffix.allSatisfy(\.isNumber) else { return nil }
        let host = value[..<idx]
        return host.isEmpty ? nil : String(host)
    }

    /// 派生跨层一致性信号。
    ///
    /// 单层证据可能被绕过，但不同层之间的“物理矛盾”很难同时伪造：
    /// - L1 硬件/GPU 判定正常，L2 却出现篡改证据 → `l1_clean_vs_l2_tampered`；
    /// - L1 可疑、L2 篡改且 L3 传感器/触摸数据双双缺失 → `l1_risky_l2_tampered_l3_absent`；
    /// - L1 干净但 L3 呈现虚拟化特征 → `l1_clean_vs_l3_virtual`。
    /// 命中时生成 layer=2、weightHint=92 的 `.tampered` 硬信号，权重高于单层证据。
    private func deriveCrossLayerSignals(from signals: [RiskSignal]) -> [RiskSignal] {
        let hasLayer2Tampered = signals.contains(where: { $0.layer == 2 && $0.state == .tampered }) ||
            signals.contains(where: { $0.id == SignalID.hookDetected && $0.state == .hard(detected: true) })

        let l1GPUReal = signals.contains(where: { $0.id == SignalID.gpuVirtual && $0.state == .hard(detected: false) })
        let l1HardwareReal = signals.contains(where: { $0.id == SignalID.vphoneHardware && $0.state == .hard(detected: false) })

        let l1Suspicious = signals.contains(where: { $0.id == SignalID.vphoneHardware && $0.state == .hard(detected: true) }) ||
            signals.contains(where: { $0.id == SignalID.gpuVirtual && $0.state == .hard(detected: true) }) ||
            signals.contains(where: { $0.id == SignalID.hardwareInconsistency && confidence(of: $0.state) >= 0.8 })

        let l3Virtual = signals.contains(where: { ($0.id == SignalID.sensorEntropy || $0.id == SignalID.touchEntropy) && confidence(of: $0.state) >= 0.65 })
        let l3UnavailableCount = signals.filter {
            ($0.id == SignalID.sensorEntropy || $0.id == SignalID.touchEntropy) && $0.state == .unavailable
        }.count

        var reasons: [String] = []
        if l1GPUReal && l1HardwareReal && hasLayer2Tampered {
            reasons.append("l1_clean_vs_l2_tampered")
        }
        if l1Suspicious && hasLayer2Tampered && l3UnavailableCount >= 2 {
            reasons.append("l1_risky_l2_tampered_l3_absent")
        }
        if l1GPUReal && l1HardwareReal && l3Virtual {
            reasons.append("l1_clean_vs_l3_virtual")
        }

        guard !reasons.isEmpty else { return [] }
        return [
            RiskSignal(
                id: "cross_layer_inconsistency",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 0,
                evidence: [
                    "reasons": reasons.joined(separator: ","),
                    "layer2_tampered": "\(hasLayer2Tampered)",
                    "layer3_virtual": "\(l3Virtual)",
                ],
                state: .tampered,
                layer: 2,
                weightHint: 92
            ),
        ]
    }

    /// 计算“盲挑战”加分。
    ///
    /// 盲挑战指服务端未明确告知规则、由客户端按时间窗自行选择规则命中后加分，
    /// 用于提高批量脚本稳定探测规则的成本。策略未启用、规则为空或未命中时返回 0；
    /// 命中返回规则权重（负值按 0 处理）。
    /// - Parameter deviceID: 参与规则轮换种子，保证同一设备在窗口内规则稳定。
    private func evaluateBlindChallengeBonus(
        signals: [RiskSignal],
        scenario: RiskScenario,
        deviceID: String
    ) -> Double {
        guard let policy = policy.blindChallengePolicy, policy.enabled else { return 0 }
        guard !policy.rules.isEmpty else { return 0 }

        let activeRule = activeBlindRule(policy: policy, scenario: scenario, deviceID: deviceID)
        guard blindRuleMatches(activeRule, signals: signals) else { return 0 }
        return max(0, activeRule.weight)
    }

    /// 选择当前生效的盲挑战规则。
    /// 单条规则直接返回；多条规则按 `时间窗 bucket`、场景、设备与 salt 做 FNV 哈希取模，
    /// 使规则随时间轮换但对同一设备在同一窗口内保持确定，便于归因且不易被离线穷举。
    private func activeBlindRule(
        policy: BlindChallengePolicy,
        scenario: RiskScenario,
        deviceID: String
    ) -> BlindChallengeRule {
        guard !policy.rules.isEmpty else {
            return BlindChallengeRule(id: "_noop")
        }
        if policy.rules.count == 1 {
            return policy.rules[0]
        }
        let bucket = Int(Date().timeIntervalSince1970) / max(1, policy.windowSeconds)
        let seedText = "\(policy.challengeSalt)|\(scenario.identifier)|\(deviceID)|\(bucket)"
        let hash = fnv1a64(seedText)
        let idx = Int(hash % UInt64(policy.rules.count))
        return policy.rules[idx]
    }

    /// 判断盲挑战规则是否匹配当前信号集合。
    /// 条件全部为 AND：required 全在场、anyOf 至少一条（若配置）、篡改信号数达标、
    /// 独立风险层数达标（排除 `.unavailable`/`.serverRequired` 的“伪层”）、
    /// 以及可选的跨层矛盾信号在场。
    private func blindRuleMatches(_ rule: BlindChallengeRule, signals: [RiskSignal]) -> Bool {
        let ids = Set(signals.map(\.id))
        let allOfOK = rule.allOfSignalIDs.allSatisfy { ids.contains($0) }
        guard allOfOK else { return false }

        if !rule.anyOfSignalIDs.isEmpty {
            let anyOfOK = rule.anyOfSignalIDs.contains(where: { ids.contains($0) })
            guard anyOfOK else { return false }
        }

        let tamperedCount = signals.filter { $0.state == .tampered }.count
        guard tamperedCount >= rule.minTamperedCount else { return false }

        let distinctLayers = Set(signals.compactMap { signal -> Int? in
            guard signal.layer != nil else { return nil }
            guard signal.state != .unavailable else { return nil }
            if signal.state == .serverRequired { return nil }
            return signal.layer
        }).count
        guard distinctLayers >= rule.minDistinctRiskLayers else { return false }

        if rule.requireCrossLayerInconsistency {
            guard ids.contains("cross_layer_inconsistency") else { return false }
        }

        return true
    }

    /// 把信号状态折算为 0…1 的置信度。
    /// `.hard(false)` 表示“确认未命中”，置信度为 0；`.serverRequired/.unavailable`
    /// 同样返回 0，因为它们不代表“有风险的证据”，不能参与“虚拟化特征”一类判断。
    private func confidence(of state: RiskSignalState?) -> Double {
        guard let state else { return 0 }
        switch state {
        case .soft(let confidence):
            return confidence
        case .hard(let detected):
            return detected ? 1 : 0
        case .tampered:
            return 1
        case .serverRequired, .unavailable:
            return 0
        }
    }

    /// FNV-1a 64 位哈希：仅用于派生稳定密钥/盐/轮换索引，不用于安全认证。
    /// 选择该算法是因为实现简单、跨平台一致，且无需引入 CryptoKit 依赖。
    private func fnv1a64(_ text: String) -> UInt64 {
        var hash: UInt64 = 0xcbf29ce484222325
        for b in text.utf8 {
            hash ^= UInt64(b)
            hash &*= 0x100000001b3
        }
        return hash
    }

    // MARK: - 日志辅助

    /// 输出引擎诊断日志；关闭 `enableLogging` 时完全静默，不影响判决。
    private func log(_ message: String) {
        if enableLogging {
            Logger.log("[RiskDetectionEngine] \(message)")
        }
    }
}

/// 基础分拆解，供日志与决策元数据诊断使用。
/// `total` 是最终参与后续流程的分数（可能含 PRF 扰动），其余分量为中间量：
/// - `legacyComponent`：无状态信号按分类权重累计；
/// - `hardComponent`：硬信号折扣聚合结果；
/// - `softComponent`：软信号与篡改底分累计；
/// - `tamperedCount`：篡改信号条数，用于倍率与聚合升级判断。
private struct ScoreComponents: Sendable {
    /// 参与后续流程的最终基础分（含 PRF 扰动），0…100。
    let total: Double
    /// 无状态信号按分类权重累计的 legacy 分量。
    let legacyComponent: Double
    /// 硬信号折扣聚合分量。
    let hardComponent: Double
    /// 软信号与篡改底分累计分量。
    let softComponent: Double
    /// 篡改信号条数，用于倍率与聚合升级判断。
    let tamperedCount: Int
}

/// 决策树提交阶段的返回类型别名，语义上强调这是“最终结论”而非中间判决。
private typealias RiskConclusion = LocalAssessment

/// 信号收集阶段的冻结上下文，供 Fast Digest / Score / Tree Commit 三个阶段复用。
/// 所有字段在收集结束后只读；`planner` 与 `scenarioPolicy` 已包含本轮的变异结果。
private struct CollectedSignalContext: Sendable {
    /// 本轮变异规划器（顺序打乱与抖动）。
    let planner: MutationPlanner
    /// 本轮实际使用的场景策略（已应用阈值变异）。
    let scenarioPolicy: ScenarioPolicy
    /// 收集、派生并打乱后的全部信号。
    let allSignals: [RiskSignal]
    /// 信号压缩摘要，用于快速判决规则匹配。
    let compressResult: SignalCompressor.CompressResult
    /// 非空表示预检已给出结论，后续阶段应直接返回。
    let preflightVerdict: LocalAssessment?
    /// 收集阶段读取到的挑战偏移提示，仅用于派生盐值。
    let challengeOffsetHint: Double
    /// 反篡改信号摘要，用于阶段盐值与决策元数据。
    let antiTamperingDigest: UInt64
}

/// 压缩摘要短路结果；存在即表示无需进入完整评分。
private struct FastDigestDecision: Sendable {
    /// 压缩摘要规则给出的短路判决。
    let verdict: LocalAssessment
}

/// 计分与强制规则的中间结果。
/// `adjustedScore` 已应用档位保底/证书固定下限；`rawFinalScore` 保留保底前的原始分，
/// 便于服务端对比“自然评分”和“策略抬升”的差异。
private struct IntermediateDecision: Sendable {
    /// 应用强制规则/档位保底后的分数，0…100。
    let adjustedScore: Double
    /// 强制动作；nil 表示未命中强制规则。
    let forcedAction: RiskAction?
    /// 保底前的原始分（含 Combo/盲挑战/挑战偏移）。
    let rawFinalScore: Double
    /// 基础分拆解，用于诊断。
    let scoreComponents: ScoreComponents
    /// 证书固定等规则产生的决策元数据。
    let decisionHints: [String: String]
}

/// 聚合对账结果：最终动作、可上报元数据，以及需要并入 primaryReasons 的对账标签。
private struct DecisionReconciliation: Sendable {
    /// 对账后最终动作（只会比初步动作更严格）。
    let action: RiskAction
    /// 可上报的对账元数据（命中规则、保底、聚合计数等）。
    let metadata: [String: String]
    /// 需并入 primaryReasons 的引擎原因标签。
    let reasonTags: [String]
}

/// 引擎内部常量：内置信号权重表。
private extension RiskDetectionEngine {
    /// 内置状态信号的默认权重表（0…100）。
    ///
    /// 仅在信号没有 `weightHint`、也没有命中 `signalWeightOverrides` 时使用；
    /// 数值按“证据确定性/伪造难度”标定：确定性运行时证据（如 sdk_binary_replaced、
    /// antiDebugWatchdogGetTaskAllow）接近 90–100，启发式/环境类信号多在 30–75。
    /// 仍受 `criticalSignalMinWeights` 下限约束，见 `signalWeight`。
    static let defaultV3SignalWeights: [String: Double] = [
        "vphone_hardware": 100,
        "board_id_virtual": 88,
        "gpu_virtual": 95,
        "hardware_inconsistency": 90,
        "cross_layer_inconsistency": 92,
        "blocklist_hit": 100,
        "hook_detected": 80,
        "tampering_detected": 85,
        "jailbreak_file": 70,
        "dyld_injection": 65,
        "jailbreak_scheme": 40,
        "sensor_entropy": 60,
        "touch_entropy": 50,
        "timing_anomaly": 45,
        ObfuscatedConstants.requiredSignalVpnActive: 30,
        "proxy_enabled": 25,
        "datacenter_ip": 55,
        "ip_device_agg": 70,
        "cloud_phone_tag": 90,
        // 3.5 新增信号权重
        "drm_capability": 85,
        "drm_device_mismatch": 100,
        "battery_charge_counter": 95,
        "battery_voltage_entropy": 55,
        "battery_energy_counter": 85,
        "mount_virtual_fs": 75,
        "mount_missing_required": 60,
        "mount_count_anomaly": 45,
        "rwx_anonymous": 90,
        "rwx_multiple": 60,
        "plt_integrity_tampered": 92,
        // 3.5 图算法反哺信号权重
        "graph_community_risk": 65,
        "graph_hw_profile_cluster": 70,
        "graph_dense_subgraph": 60,
        "local_device_cluster": 55, // historical reports only
        "local_identity_churn": 55,
        "text_segment_tampered": 88,
        "text_segment_baseline_rejected_suspicious_env": 88,
        "text_segment_baseline_cleared_suspicious_env": 88,
        // 3.5.1 Frida 深度检测信号权重
        "frida_thread_anomaly": 75,
        "frida_exception_port": 85,
        "frida_js_engine_heap": 80,
        "frida_stalker_jit": 78,
        "objc_method_swizzled": 80,
        "frida_dispatch_queue": 70,
        "frida_unix_socket": 75,
        "frida_timing_anomaly": 65,
        "kernel_hook_timing_anomaly": 68,
        "kernel_hook_stalker_amplified": 72,
        "kernel_hook_crypto_trace_skew": 74,
        "kernel_hook_crypto_trace_invariant": 96,
        "system_library_wx_mapping": 94,
        "system_library_anonymous_exec_region": 92,
        "system_library_segment_count_drift": 68,
        "app_image_segment_layout_anomaly": 85,
        // 3.6 加固信号权重
        "multipath_hook_detected": 82,
        "multipath_jailbreak_file": 70,
        "randomized_env_anomaly": 60,
        "fingerprint_simulator": 90,
        "fingerprint_virtualization": 85,
        "fingerprint_mutation": 55,
        "fingerprint_suspicious_hw": 80,
        SignalID.fridaModuleTrampoline: 82,
        SignalID.fridaRuntimeConsensus: 90,
        SignalID.antiDebugRuntimeConsensus: 88,
        SignalID.signingChainConsensus: 92,
        "dyld_interpose_detected": 88,
        "dyld_env_abuse": 78,
        "dyld_image_overload": 45,
        SignalID.dylibInjectImageCountLow: 52,
        SignalID.ifaceSpawnPathDivergence: 86,
        SignalID.libcDirectSyscallFallback: 18,
        SignalID.antiDebugWatchdogDyldInjection: 92,
        SignalID.antiDebugWatchdogDenyAttachVerify: 84,
        SignalID.antiDebugWatchdogAMFICsFlags: 90,
        SignalID.antiDebugWatchdogGetTaskAllow: 94,
        SignalID.antiDebugWatchdogPacThreadEntry: 91,
        SignalID.antiDebugWatchdogVmImageLayoutDrift: 86,
        SignalID.whiteboxPrfProbeDegraded: 88,
        "\(ObfuscatedConstants.detectorIDAntiDebugWatchdog)_dbi_vm_trace_correl": 93,
        "sdk_code_signature_missing": 90,
        "sdk_binary_replaced": 95,
        "sdk_segment_tampered": 85,
        "sdk_binary_size_anomaly": 70,
        // 3.7 深度加固信号权重
        "sensor_replay_detected": 72,
        "gpu_render_anomaly": 75,
        "isa_swizzle_detected": 82,
        "msg_forward_hijack": 85,
        "method_count_anomaly": 50,
        // 4.4 执行流栈回溯
        "rop_chain_detected": 90,
        // 环境一致性、硬件能力、网络接口
        "physical_sensor_anomaly": 70,
        "thermal_state_static": 40,
        "battery_state_static": 50,
        "screen_brightness_static": 35,
        "haptic_capability_mismatch": 80,
        "refresh_rate_mismatch": 75,
        "proximity_sensor_absent": 30,
        "network_interface_anomaly": 55,
        SignalID.certificatePinningAnomaly: 72,
        // barometer_anomaly：PhysicalSensorProbe 当前未单独输出，预留权重供后续扩展
        "barometer_anomaly": 65,
        // SDK 5.2 新信号权重
        "screen_captured": 50,
        "external_display_attached": 45,
        "usb_audio_routed": 55,
        "no_cellular_provider": 60,
        "biometric_not_enrolled": 40,
    ]
}

// MARK: - 引擎策略配置
/// 决策引擎的全局策略配置（不可变值类型，可安全跨线程共享）。
///
/// 配置来源通常是服务端下发并经 `CPRiskKitConfiguration` 合并；解码时所有字段
/// 都使用短键（见 `CodingKeys`）并在缺失时回退到安全默认值，避免旧配置直接崩溃。
/// `killSwitchEnabled` 是唯一能整体关闭拦截的开关，但可被本地覆盖（见引擎属性）。
public struct EnginePolicy: Codable, Sendable {

    // MARK: - 紧急开关

    /// 远程紧急开关：true 时跳过全部检测并强制 allow，用于线上止血。
    /// 本地 `localKillSwitchOverride` 可拒绝该指令，防止配置被劫持后“一键关防护”。
    public let killSwitchEnabled: Bool

    // MARK: - 全局开关

    /// 是否采集 VPN/代理等网络信号；关闭后仍保留其它家族。
    public let enableNetworkSignals: Bool
    /// 是否采集触摸/运动等行为信号；关闭可降低低交互场景的误报。
    public let enableBehaviorDetection: Bool
    /// 是否启用设备指纹检测。该字段会随策略透传给上层适配器；
    /// 引擎内部的设备信号实际由检测器家族白名单（`"device"`）控制。
    public let enableDeviceFingerprint: Bool

    // MARK: - 强制规则

    /// 越狱命中时强制采取的动作；nil 表示不强制动作，但仍会把分数抬到 highThreshold。
    public let forceActionOnJailbreak: RiskAction?

    // MARK: - 场景策略

    /// 场景 → 策略映射；未配置的场景回退到 `ScenarioPolicy.policy(for:)`。
    public let scenarioPolicies: [RiskScenario: ScenarioPolicy]
    /// 按信号 id 覆盖权重；`> 0` 才生效，且仍受关键信号权重下限约束。
    public let signalWeightOverrides: [String: Double]
    /// 变异策略：控制信号顺序打乱与阈值/权重抖动；nil 表示完全确定、不抖动。
    public let mutationStrategy: MutationStrategy?
    /// 盲挑战策略：按时间窗轮换规则并给予额外加分；nil 表示不启用。
    public let blindChallengePolicy: BlindChallengePolicy?
    /// 服务端下发的黑名单 token 列表（主机名/ID 等），大小写不敏感。
    public let serverBlocklist: [String]?
    /// 黑名单命中时强制采取的动作；nil 表示只计分、不强制动作。
    public let blocklistAction: RiskAction?

    // MARK: - 元数据

    /// 策略名，参与状态机密钥与盐值派生；不同策略互不共享状态。
    public let name: String
    /// 策略版本，参与状态机密钥与盐值派生；版本变化会使旧状态/摘要失效。
    public let version: String

    // 使用短键压缩下发体积；键名是线上协议的一部分，重命名会导致旧配置无法解码。
    /// 线上协议短键；重命名会使已下发的配置无法解码。
    private enum CodingKeys: String, CodingKey {
        case killSwitchEnabled = "ks"
        case enableNetworkSignals = "en"
        case enableBehaviorDetection = "eb"
        case enableDeviceFingerprint = "ef"
        case forceActionOnJailbreak = "fj"
        case scenarioPolicies = "sp"
        case signalWeightOverrides = "wo"
        case mutationStrategy = "ms"
        case blindChallengePolicy = "bp"
        case serverBlocklist = "sb"
        case blocklistAction = "ba"
        case name = "n"
        case version = "v"
    }

    // MARK: - 初始化

    /// 创建策略；默认值即“全开检测、无强制动作、无变异”的保守配置。
    /// - Parameters:
    ///   - name/version: 参与状态机密钥派生，变更会使旧的状态与摘要失效。
    ///   - killSwitchEnabled: 紧急止血开关，生产环境应仅在服务端明确要求时开启。
    ///   - forceActionOnJailbreak: 越狱命中后的强制动作；nil 表示只抬分不强制。
    ///   - signalWeightOverrides: 按信号 id 覆盖权重，`> 0` 生效且受下限约束。
    ///   - scenarioPolicies: 场景级阈值/权重/组合规则映射，缺省回退到内置场景策略。
    public init(
        name: String = "default",
        version: String = "1.0.0",
        killSwitchEnabled: Bool = false,
        enableNetworkSignals: Bool = true,
        enableBehaviorDetection: Bool = true,
        enableDeviceFingerprint: Bool = true,
        forceActionOnJailbreak: RiskAction? = nil,
        signalWeightOverrides: [String: Double] = [:],
        mutationStrategy: MutationStrategy? = nil,
        blindChallengePolicy: BlindChallengePolicy? = nil,
        serverBlocklist: [String]? = nil,
        blocklistAction: RiskAction? = nil,
        scenarioPolicies: [RiskScenario: ScenarioPolicy] = [:]
    ) {
        self.name = name
        self.version = version
        self.killSwitchEnabled = killSwitchEnabled
        self.enableNetworkSignals = enableNetworkSignals
        self.enableBehaviorDetection = enableBehaviorDetection
        self.enableDeviceFingerprint = enableDeviceFingerprint
        self.forceActionOnJailbreak = forceActionOnJailbreak
        self.signalWeightOverrides = signalWeightOverrides
        self.mutationStrategy = mutationStrategy
        self.blindChallengePolicy = blindChallengePolicy
        self.serverBlocklist = serverBlocklist
        self.blocklistAction = blocklistAction
        self.scenarioPolicies = scenarioPolicies
    }

    /// 从服务端 JSON 解码策略。
    /// 除 `name/version` 外全部使用 `decodeIfPresent` 并提供安全默认值，
    /// 保证新增/缺失字段不会让旧版本崩溃；默认值偏保守（检测开启、开关关闭）。
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String.self, forKey: .name)
        version = try container.decode(String.self, forKey: .version)
        killSwitchEnabled = try container.decodeIfPresent(Bool.self, forKey: .killSwitchEnabled) ?? false
        enableNetworkSignals = try container.decodeIfPresent(Bool.self, forKey: .enableNetworkSignals) ?? true
        enableBehaviorDetection = try container.decodeIfPresent(Bool.self, forKey: .enableBehaviorDetection) ?? true
        enableDeviceFingerprint = try container.decodeIfPresent(Bool.self, forKey: .enableDeviceFingerprint) ?? true
        forceActionOnJailbreak = try container.decodeIfPresent(RiskAction.self, forKey: .forceActionOnJailbreak)
        signalWeightOverrides = try container.decodeIfPresent([String: Double].self, forKey: .signalWeightOverrides) ?? [:]
        mutationStrategy = try container.decodeIfPresent(MutationStrategy.self, forKey: .mutationStrategy)
        blindChallengePolicy = try container.decodeIfPresent(BlindChallengePolicy.self, forKey: .blindChallengePolicy)
        serverBlocklist = try container.decodeIfPresent([String].self, forKey: .serverBlocklist)
        blocklistAction = try container.decodeIfPresent(RiskAction.self, forKey: .blocklistAction)
        scenarioPolicies = try container.decodeIfPresent([RiskScenario: ScenarioPolicy].self, forKey: .scenarioPolicies) ?? [:]
    }

    /// 获取指定场景的策略
    public func scenarioPolicy(for scenario: RiskScenario) -> ScenarioPolicy {
        scenarioPolicies[scenario] ?? .policy(for: scenario)
    }

    // MARK: - 预设策略

    /// 默认策略：启用全部内置检测，不强制动作，行为最接近“只评分不拦截”。
    public static let `default` = EnginePolicy(
        name: "default",
        version: "1.0.0"
    )

    /// 严格策略：越狱命中直接 block，适合高价值但容忍一定误报的场景。
    public static let strict = EnginePolicy(
        name: "strict",
        version: "1.0.0",
        enableNetworkSignals: true,
        enableBehaviorDetection: true,
        enableDeviceFingerprint: true,
        forceActionOnJailbreak: .block
    )

    /// 宽松策略：只保留网络信号，关闭行为与设备检测，用于误报敏感的低风险场景。
    public static let lenient = EnginePolicy(
        name: "lenient",
        version: "1.0.0",
        enableNetworkSignals: true,
        enableBehaviorDetection: false,
        enableDeviceFingerprint: false,
        forceActionOnJailbreak: nil
    )

    /// 金融级策略（最高安全）：越狱直接 block，并为支付/登录/注册/改户/敏感操作
    /// 绑定更严格的场景策略。
    public static let financial = EnginePolicy(
        name: "financial",
        version: "1.0.0",
        enableNetworkSignals: true,
        enableBehaviorDetection: true,
        enableDeviceFingerprint: true,
        forceActionOnJailbreak: .block,
        scenarioPolicies: [
            .payment: .payment,
            .login: .login,
            .register: .register,
            .accountChange: .accountChange,
            .sensitiveAction: .sensitiveAction
        ]
    )
}

/// 变异策略：以确定性方式引入“可控随机”，提高离线复现与规则指纹化成本。
///
/// `seed` 与服务端配置绑定；同一设备/场景下结果可复现，便于服务端对账，
/// 但不同策略版本的抖动序列不同，分数分布不宜直接横向比较。
public struct MutationStrategy: Codable, Sendable {
    /// 变异种子，参与 `MutationPlanner` 的派生；变更即代表一组新的打乱/抖动序列。
    public let seed: String
    /// 是否打乱信号、Provider、ComboRule 等集合的遍历顺序；关闭后顺序完全稳定。
    public let shuffleChecks: Bool
    /// 场景阈值抖动幅度（万分比）；例如 500 表示 ±5%。
    public let thresholdJitterBps: Int
    /// 分数权重/底分抖动幅度（万分比）；0 表示不抖动。
    public let scoreJitterBps: Int

    // 短键为线上协议，重命名会导致已下发配置无法解码。
    /// 线上协议短键；重命名会使已下发配置无法解码。
    private enum CodingKeys: String, CodingKey {
        case seed = "s"
        case shuffleChecks = "sc"
        case thresholdJitterBps = "tj"
        case scoreJitterBps = "sj"
    }

    /// 创建变异策略；抖动均以万分比（bps）表示，0 表示关闭该项。
    public init(
        seed: String,
        shuffleChecks: Bool = true,
        thresholdJitterBps: Int = 0,
        scoreJitterBps: Int = 0
    ) {
        self.seed = seed
        self.shuffleChecks = shuffleChecks
        self.thresholdJitterBps = thresholdJitterBps
        self.scoreJitterBps = scoreJitterBps
    }
}

/// 盲挑战策略：按时间窗在客户端本地轮换规则，命中后给予额外风险加分。
///
/// 与“服务端明确下发挑战”不同，客户端只拿到规则集合与 salt，
/// 攻击者难以稳定探测当前窗口生效的是哪一条规则。
public struct BlindChallengePolicy: Codable, Sendable {
    /// 是否启用盲挑战加分。
    public let enabled: Bool
    /// 规则轮换种子的一部分；应使用服务端下发的随机值，避免可预测。
    public let challengeSalt: String
    /// 时间窗长度（秒），默认 300；窗口越小轮换越快，但规则命中率也更不稳定。
    public let windowSeconds: Int
    /// 候选规则列表；轮换时按窗口哈希取模选择。
    public let rules: [BlindChallengeRule]

    // 短键为线上协议。
    /// 线上协议短键；重命名会使已下发配置无法解码。
    private enum CodingKeys: String, CodingKey {
        case enabled = "e"
        case challengeSalt = "cs"
        case windowSeconds = "ws"
        case rules = "r"
    }

    /// 创建盲挑战策略。
    /// - Parameter windowSeconds: 时间窗长度（秒）；规则选择阶段会按 `max(1, ...)` 处理以防零除。
    public init(
        enabled: Bool = true,
        challengeSalt: String,
        windowSeconds: Int = 300,
        rules: [BlindChallengeRule]
    ) {
        self.enabled = enabled
        self.challengeSalt = challengeSalt
        self.windowSeconds = windowSeconds
        self.rules = rules
    }
}

/// 单条盲挑战规则：描述一组必须/可选信号、篡改数量、层数与额外加分。
/// 匹配为 AND 语义，见 `blindRuleMatches`。
public struct BlindChallengeRule: Codable, Sendable {
    /// 规则标识，用于日志与上报归因。
    public let id: String
    /// 必须全部在场的信号 id。
    public let allOfSignalIDs: [String]
    /// 至少命中一条的信号 id；空数组表示不限制。
    public let anyOfSignalIDs: [String]
    /// 至少需要的 `.tampered` 信号数量。
    public let minTamperedCount: Int
    /// 至少需要的独立风险层数（排除 unavailable/serverRequired）。
    public let minDistinctRiskLayers: Int
    /// 是否要求跨层矛盾信号 `cross_layer_inconsistency` 在场。
    public let requireCrossLayerInconsistency: Bool
    /// 命中后的加分（0…100 量级）；负值在计算时按 0 处理。
    public let weight: Double

    // 短键为线上协议。
    /// 线上协议短键；重命名会使已下发配置无法解码。
    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case allOfSignalIDs = "ao"
        case anyOfSignalIDs = "ay"
        case minTamperedCount = "mt"
        case minDistinctRiskLayers = "ml"
        case requireCrossLayerInconsistency = "rc"
        case weight = "w"
    }

    /// 创建盲挑战规则；默认要求无强制条件、加 75 分。
    public init(
        id: String,
        allOfSignalIDs: [String] = [],
        anyOfSignalIDs: [String] = [],
        minTamperedCount: Int = 0,
        minDistinctRiskLayers: Int = 0,
        requireCrossLayerInconsistency: Bool = false,
        weight: Double = 75
    ) {
        self.id = id
        self.allOfSignalIDs = allOfSignalIDs
        self.anyOfSignalIDs = anyOfSignalIDs
        self.minTamperedCount = minTamperedCount
        self.minDistinctRiskLayers = minDistinctRiskLayers
        self.requireCrossLayerInconsistency = requireCrossLayerInconsistency
        self.weight = weight
    }
}

// MARK: - 向后兼容扩展
extension RiskDetectionEngine {

    /// 兼容旧版 RiskScorer 接口（RiskScorer 已废弃，本引擎为唯一主评分链路）。
    /// 使用默认场景与从 `RiskConfig` 转换出的策略评估风险，并转换为 `RiskScoreReport`。
    /// 该入口固定 `enableDeviceFingerprint = true`，且越狱时强制 block，
    /// 行为与旧版调用方保持一致；新代码应直接使用 `evaluate`。
    func score(
        context: RiskContext,
        config: RiskConfig,
        extraSignals: [RiskSignal] = []
    ) -> RiskScoreReport {
        // 将 RiskConfig 转换为 EnginePolicy
        let policy = EnginePolicy(
            enableNetworkSignals: config.enableNetworkSignals,
            enableBehaviorDetection: config.enableBehaviorDetect,
            enableDeviceFingerprint: true,
            forceActionOnJailbreak: context.jailbreak.isJailbroken ? .block : nil
        )

        let engine = RiskDetectionEngine(policy: policy)
        let verdict = engine.evaluate(
            context: context,
            scenario: .default,
            extraSignals: extraSignals
        )

        return RiskScoreReport(
            score: verdict.score,
            isHighRisk: verdict.isHighRisk,
            signals: verdict.signals,
            summary: verdict.summary,
            compressedDigest: verdict.compressedDigest,
            mappingVersion: verdict.mappingVersion,
            action: verdict.internalAction,
            primaryReasons: verdict.primaryReasons,
            decisionMetadata: verdict.decisionMetadata
        )
    }
}

/// 旧版展示字段扩展。
extension LocalAssessment {
    /// 旧版兼容字段：把 `action + level` 拼成 `allowed/challenged/blocked(level)`。
    /// 仅用于旧调用方展示/日志，不参与任何决策；新代码应读取结构化字段。
    public var legacySummary: String {
        if action == .block {
            return "blocked(\(level.rawValue))"
        } else if action == .challenge {
            return "challenged(\(level.rawValue))"
        } else {
            return "allowed(\(level.rawValue))"
        }
    }
}
