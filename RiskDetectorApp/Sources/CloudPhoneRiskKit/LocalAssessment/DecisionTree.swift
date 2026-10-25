// 决策树引擎：由条件节点、计分节点和动作节点组成可序列化的本地判决树。
// 支持顺序（Sequence）与并行（Parallel）组合；顺序遇终止即停，并行取最严格动作。
// 求值状态机用 CFF 混淆（状态编码 + 双分支调度），增加静态定位判定分支的难度。
// `DecisionTree.decide` 在树未给出终止结果时，按场景阈值执行保底规则（最终 fail-closed 到 block）。

import Foundation

/// 决策树节点协议：每个节点读取评估上下文并返回下一步结果。
/// 实现必须是纯函数式、无副作用的，保证同一上下文可重复求值。
public protocol DecisionTreeNode: Sendable {
    func evaluate(context: EvaluationContext) -> DecisionResult
}

/// 决策树求值上下文：分数、信号、场景、原始风险上下文与生效策略。
public struct EvaluationContext: Sendable {
    /// 当前风险总分。
    public let score: Double
    /// 已采集的风险信号。
    public let signals: [RiskSignal]
    /// 当前业务场景。
    public let scenario: RiskScenario
    /// 原始设备上下文（越狱/网络等），供需要细粒度字段的节点使用。
    public let riskContext: RiskContext
    /// 当前场景生效的策略（阈值、动作映射等）。
    public let policy: ScenarioPolicy
    /// 可变元数据，供节点/适配器传递 challenge 状态等附加信息。
    public var metadata: [String: String]

    // 仅适配器使用的信号开关；保留原始上下文给 Provider 与直接调用方。
    // 关闭某类检测时，即使原始上下文命中也不参与条件判断。
    var jailbreakEnabled = true
    var networkEnabled = true
    var isJailbroken: Bool { jailbreakEnabled && riskContext.jailbreak.isJailbroken }
    var isVPNActive: Bool { networkEnabled && riskContext.network.isVPNActive }
    var proxyEnabled: Bool { networkEnabled && riskContext.network.proxyEnabled }

    /// 创建求值上下文；开关默认全部启用。
    public init(
        score: Double,
        signals: [RiskSignal],
        scenario: RiskScenario,
        riskContext: RiskContext,
        policy: ScenarioPolicy,
        metadata: [String: String] = [:]
    ) {
        self.score = score
        self.signals = signals
        self.scenario = scenario
        self.riskContext = riskContext
        self.policy = policy
        self.metadata = metadata
    }

    /// 是否存在指定 ID 的信号。
    public func hasSignal(_ id: String) -> Bool {
        signals.contains { $0.id == id }
    }

    /// 是否存在指定类别的信号。
    public func hasSignal(category: String) -> Bool {
        signals.contains { $0.category == category }
    }

    /// 指定 ID 信号的分数；不存在时返回 0。
    public func signalScore(_ id: String) -> Double {
        signals.first { $0.id == id }?.score ?? 0
    }

    /// 指定类别所有信号的分数之和。
    public func categoryScore(_ category: String) -> Double {
        signals.filter { $0.category == category }.reduce(0) { $0 + $1.score }
    }
}

/// 节点求值结果：继续、终止并给出动作，或跳转分支（由上层组合节点消费）。
public enum DecisionResult: Sendable {
    /// 当前节点未做出决定，交给后续节点/兜底逻辑。
    case next
    /// 终止求值并输出处置动作与原因。
    case terminate(action: RiskAction, reason: String)
    /// 分支跳转（保留给自定义组合节点）。
    case branch(String)

    /// 是否为终止结果。
    public var isTerminal: Bool {
        if case .terminate = self { return true }
        return false
    }
}

/// 为 CFF 状态机生成与输入相关的盐值，使状态编码随上下文变化。
private enum DecisionTreeCFF {
    /// 组合分数、信号数、阈值、关键元数据与布尔开关，派生 32 位盐。
    static func salt(context: EvaluationContext, token: String, extraWords: [UInt64] = []) -> UInt32 {
        let signalPrefix = context.signals.prefix(2).map(\.id).joined(separator: "|")
        return CFFRuntimeSalt.combine(
            words: [
                context.score.bitPattern,
                UInt64(context.signals.count),
                UInt64(context.metadata.count),
                UInt64(context.scenario.rawValue),
                context.policy.mediumThreshold.bitPattern,
                context.policy.highThreshold.bitPattern,
                context.policy.criticalThreshold.bitPattern,
            ] + extraWords,
            strings: [
                token,
                signalPrefix,
                context.metadata["challenge_state"] ?? "",
                context.metadata["trust_level"] ?? "",
            ],
            flags: [
                context.isJailbroken,
                context.isVPNActive,
                context.proxyEnabled,
            ]
        )
    }
}

/// 条件表达式：决策树中最小的布尔判定单元。
/// 所有比较对 NaN 等异常值都返回 false（`score < x` 对 NaN 也为 false），不会误放行高风险。
public enum ConditionExpression: Codable, Sendable {
    /// 分数位于 [min, max) 区间。
    case scoreRange(min: Double, max: Double)
    /// 分数不低于给定值。
    case scoreGreaterThanOrEqual(Double)
    /// 分数低于给定值。
    case scoreLessThan(Double)
    /// 指定信号存在。
    case signalExists(String)
    /// 指定信号分数大于阈值。
    case signalScore(id: String, greaterThan: Double)
    /// 指定类别信号总分为大于阈值。
    case categoryScore(category: String, greaterThan: Double)
    /// 设备已越狱（受适配器开关控制）。
    case isJailbroken
    /// 当前使用 VPN（受适配器开关控制）。
    case isVPN
    /// 当前启用代理（受适配器开关控制）。
    case isProxy
    /// 自定义条件 ID，由已注册的 evaluator 求值；未注册时视为 false。
    case custom(String)

    /// 求值条件。内部用状态机 + CFF 状态编码隐藏真实分支，语义仍是普通布尔判断。
    public func evaluate(context: EvaluationContext) -> Bool {
        let salt = DecisionTreeCFF.salt(context: context, token: "expr")
        // 状态 ID 是内部实现细节，无业务含义；编码后攻击者无法直接按常量定位分支。
        let seed: UInt32 = 0x51C2A91D
        let entryState: UInt32 = 0x10
        let scoreRangeState: UInt32 = 0x11
        let scoreGreaterState: UInt32 = 0x12
        let scoreLessState: UInt32 = 0x13
        let signalExistsState: UInt32 = 0x14
        let signalScoreState: UInt32 = 0x15
        let categoryScoreState: UInt32 = 0x16
        let jailbrokenState: UInt32 = 0x17
        let vpnState: UInt32 = 0x18
        let proxyState: UInt32 = 0x19
        let customState: UInt32 = 0x1A

        var sink = CFFReturnSink<Bool>()
        var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: salt)

        // 循环直到写回返回值；每次迭代只执行一个状态，避免直接暴露 if/switch 结构。
        while !sink.isResolved {
            let decodedState = CFFStateCodec.decode(encodedState, seed: seed, salt: salt)

            // 调度器随机选择两条等价路径之一，增加控制流图复杂度；两者语义完全一致。
            if CFFDispatcher.prefersPrimaryBranch(encodedState: encodedState, salt: salt) {
                if decodedState == entryState {
                    let targetState: UInt32
                    switch self {
                    case .scoreRange:
                        targetState = scoreRangeState
                    case .scoreGreaterThanOrEqual:
                        targetState = scoreGreaterState
                    case .scoreLessThan:
                        targetState = scoreLessState
                    case .signalExists:
                        targetState = signalExistsState
                    case .signalScore:
                        targetState = signalScoreState
                    case .categoryScore:
                        targetState = categoryScoreState
                    case .isJailbroken:
                        targetState = jailbrokenState
                    case .isVPN:
                        targetState = vpnState
                    case .isProxy:
                        targetState = proxyState
                    case .custom:
                        targetState = customState
                    }
                    encodedState = CFFStateCodec.encode(targetState, seed: seed, salt: salt)
                } else if decodedState == scoreRangeState, case let .scoreRange(min, max) = self {
                    sink.store(context.score >= min && context.score < max)
                } else if decodedState == scoreGreaterState, case let .scoreGreaterThanOrEqual(value) = self {
                    sink.store(context.score >= value)
                } else if decodedState == scoreLessState, case let .scoreLessThan(value) = self {
                    sink.store(context.score < value)
                } else if decodedState == signalExistsState, case let .signalExists(id) = self {
                    sink.store(context.hasSignal(id))
                } else if decodedState == signalScoreState, case let .signalScore(id, gt) = self {
                    sink.store(context.signalScore(id) > gt)
                } else if decodedState == categoryScoreState, case let .categoryScore(category, gt) = self {
                    sink.store(context.categoryScore(category) > gt)
                } else if decodedState == jailbrokenState {
                    sink.store(context.isJailbroken)
                } else if decodedState == vpnState {
                    sink.store(context.isVPNActive)
                } else if decodedState == proxyState {
                    sink.store(context.proxyEnabled)
                } else if decodedState == customState, case let .custom(id) = self {
                    sink.store(ConditionExpression.customEvaluatorRegistry.evaluate(id: id, context: context))
                } else {
                    // 状态与表达式不匹配说明状态机被破坏，按 false 失败关闭。
                    sink.store(false)
                }
            } else {
                switch decodedState {
                case entryState:
                    let targetState: UInt32
                    switch self {
                    case .scoreRange:
                        targetState = scoreRangeState
                    case .scoreGreaterThanOrEqual:
                        targetState = scoreGreaterState
                    case .scoreLessThan:
                        targetState = scoreLessState
                    case .signalExists:
                        targetState = signalExistsState
                    case .signalScore:
                        targetState = signalScoreState
                    case .categoryScore:
                        targetState = categoryScoreState
                    case .isJailbroken:
                        targetState = jailbrokenState
                    case .isVPN:
                        targetState = vpnState
                    case .isProxy:
                        targetState = proxyState
                    case .custom:
                        targetState = customState
                    }
                    encodedState = CFFStateCodec.encode(targetState, seed: seed, salt: salt)
                case scoreRangeState where self.isScoreRange:
                    if case let .scoreRange(min, max) = self {
                        sink.store(context.score >= min && context.score < max)
                    }
                case scoreGreaterState where self.isScoreGreaterThanOrEqual:
                    if case let .scoreGreaterThanOrEqual(value) = self {
                        sink.store(context.score >= value)
                    }
                case scoreLessState where self.isScoreLessThan:
                    if case let .scoreLessThan(value) = self {
                        sink.store(context.score < value)
                    }
                case signalExistsState where self.isSignalExists:
                    if case let .signalExists(id) = self {
                        sink.store(context.hasSignal(id))
                    }
                case signalScoreState where self.isSignalScore:
                    if case let .signalScore(id, gt) = self {
                        sink.store(context.signalScore(id) > gt)
                    }
                case categoryScoreState where self.isCategoryScore:
                    if case let .categoryScore(category, gt) = self {
                        sink.store(context.categoryScore(category) > gt)
                    }
                case jailbrokenState where self.isJailbrokenExpression:
                    sink.store(context.isJailbroken)
                case vpnState where self.isVPNExpression:
                    sink.store(context.isVPNActive)
                case proxyState where self.isProxyExpression:
                    sink.store(context.proxyEnabled)
                case customState where self.isCustom:
                    if case let .custom(id) = self {
                        sink.store(ConditionExpression.customEvaluatorRegistry.evaluate(id: id, context: context))
                    }
                default:
                    // 遇到未知状态立即收敛，避免重置到 entryState 造成死循环。
                    sink.store(false)
                }
            }
        }

        // 理论上循环只会以 store 结束；兜底返回 false，保证异常情况下不放行。
        return sink.resolve(or: false)
    }
}

// MARK: - 自定义条件求值器注册表

extension ConditionExpression {
    /// 注册自定义条件求值器。`.custom(id)` 在 evaluate 时会调用已注册的 evaluator。
    /// 若未注册或 evaluator 返回 false，则 `.custom(id)` 视为 false。
    /// 注册仅在 `seal()` 之前有效；`CPRiskKit.start()` 后注册表将被封印。
    ///
    /// 用法：
    /// ```swift
    /// ConditionExpression.registerCustomEvaluator(id: "my_check") { ctx in
    ///     ctx.score > 80 && ctx.hasSignal("vpn_active")
    /// }
    /// ```
    public static func registerCustomEvaluator(id: String, evaluator: @escaping (EvaluationContext) -> Bool) {
        customEvaluatorRegistry.register(id: id, evaluator: evaluator)
    }

    /// 移除已注册的自定义求值器；注册表已封印时该操作被拒绝。
    public static func unregisterCustomEvaluator(id: String) {
        customEvaluatorRegistry.unregister(id: id)
    }

    /// 封印自定义求值器注册表，之后拒绝一切 register/unregister。
    /// 在 `CPRiskKit.start()` 后调用，防止运行期被注入/替换判定逻辑。
    public static func sealCustomEvaluators() {
        customEvaluatorRegistry.seal()
    }

#if DEBUG
    /// 测试用：解除封印并清空注册表，允许测试中重新注册。
    public static func unsealCustomEvaluatorsForTesting() {
        customEvaluatorRegistry.unsealForTesting()
    }
#endif

    fileprivate static let customEvaluatorRegistry = CustomEvaluatorRegistry()
}

/// 自定义条件求值器注册表。
/// 线程模型：UnfairLock 保护字典与封印标记；求值前拷贝闭包，避免持锁执行用户代码。
private final class CustomEvaluatorRegistry: @unchecked Sendable {
    private let lock = UnfairLock()
    private var evaluators: [String: (EvaluationContext) -> Bool] = [:]
    private var isSealed = false

    /// 注册求值器；封印后拒绝并记录日志。
    func register(id: String, evaluator: @escaping (EvaluationContext) -> Bool) {
        let rejected = lock.withLock { () -> Bool in
            if isSealed {
                return true
            }
            evaluators[id] = evaluator
            return false
        }
        if rejected {
            Logger.log("CustomEvaluatorRegistry.register rejected (sealed): \(id)")
        }
    }

    /// 注销求值器；封印后拒绝。
    func unregister(id: String) {
        let rejected = lock.withLock { () -> Bool in
            if isSealed {
                return true
            }
            evaluators.removeValue(forKey: id)
            return false
        }
        if rejected {
            Logger.log("CustomEvaluatorRegistry.unregister rejected (sealed): \(id)")
        }
    }

    /// 封印注册表：此后任何注册/注销都无效。
    func seal() {
        lock.withLock {
            isSealed = true
        }
        Logger.log("CustomEvaluatorRegistry.sealed")
    }

#if DEBUG
    func unsealForTesting() {
        lock.withLock {
            isSealed = false
            evaluators.removeAll()
        }
    }
#endif

    /// 求值：锁内只取闭包，锁外执行；未注册返回 false。
    func evaluate(id: String, context: EvaluationContext) -> Bool {
        let evaluatorCopy: ((EvaluationContext) -> Bool)? = lock.withLock {
            evaluators[id]
        }
        return evaluatorCopy?(context) ?? false
    }
}

/// 条件节点：按 `condition` 选择 true/false 分支；false 分支缺省时返回 `.next`。
public struct ConditionNode: Codable, Sendable {
    /// 节点标识（用于日志与 CFF 盐值派生）。
    public let id: String
    /// 布尔条件。
    public let condition: ConditionExpression
    /// 条件为真时求值的子树。
    public let trueBranch: DecisionTreeNodeType
    /// 条件为假时求值的子树；nil 表示继续外层流程。
    public let falseBranch: DecisionTreeNodeType?

    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case condition = "c"
        case trueBranch = "tb"
        case falseBranch = "fb"
    }

    public init(
        id: String,
        condition: ConditionExpression,
        trueBranch: DecisionTreeNodeType,
        falseBranch: DecisionTreeNodeType? = nil
    ) {
        self.id = id
        self.condition = condition
        self.trueBranch = trueBranch
        self.falseBranch = falseBranch
    }

    /// 求值条件并进入对应分支；整个过程同样用状态机混淆。
    public func evaluate(context: EvaluationContext) -> DecisionResult {
        // id 参与盐值，使不同节点的状态编码互不相同。
        let salt = DecisionTreeCFF.salt(
            context: context,
            token: "cond-node:\(id)",
            extraWords: [UInt64(id.utf8.reduce(0) { ($0 &* 131) &+ UInt64($1) })]
        )
        let seed: UInt32 = 0x3D9E41A7
        let entryState: UInt32 = 0x21
        let conditionState: UInt32 = 0x22
        let trueState: UInt32 = 0x23
        let falseState: UInt32 = 0x24
        let falseEvalState: UInt32 = 0x25

        var sink = CFFReturnSink<DecisionResult>()
        var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: salt)
        var conditionMatched = false

        while !sink.isResolved {
            switch CFFStateCodec.decode(encodedState, seed: seed, salt: salt) {
            case entryState:
                encodedState = CFFStateCodec.encode(conditionState, seed: seed, salt: salt)
            case conditionState:
                conditionMatched = condition.evaluate(context: context)
                encodedState = CFFStateCodec.encode(conditionMatched ? trueState : falseState, seed: seed, salt: salt)
            case trueState:
                sink.store(trueBranch.evaluate(context: context))
            case falseState:
                if falseBranch != nil {
                    encodedState = CFFStateCodec.encode(falseEvalState, seed: seed, salt: salt)
                } else {
                    // 没有 false 分支时把决定权交还给父节点。
                    sink.store(.next)
                }
            case falseEvalState:
                sink.store(falseBranch?.evaluate(context: context) ?? .next)
            default:
                // 未知状态按“无决定”处理，由后续节点/兜底规则接管。
                sink.store(.next)
            }
        }

        return sink.resolve(or: .next)
    }
}

/// 动作节点：无条件终止求值并输出指定动作，是决策树的叶子。
public struct ActionNode: Codable, Sendable {
    /// 节点标识。
    public let id: String
    /// 要执行的处置动作。
    public let action: RiskAction
    /// 输出给审计/上报的原因文本。
    public let reason: String

    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case action = "a"
        case reason = "r"
    }

    public init(id: String, action: RiskAction, reason: String) {
        self.id = id
        self.action = action
        self.reason = reason
    }

    /// 直接返回终止结果（不读取上下文）。
    public func evaluate(context: EvaluationContext) -> DecisionResult {
        .terminate(action: action, reason: reason)
    }
}

/// 计分节点中的一个“上界阈值 → 动作”条目。
public struct ScoreActionThreshold: Codable, Sendable {
    /// 分数上界；score 严格小于该值时采用 `action`。
    public let threshold: Double
    /// 命中该区间时执行的动作。
    public let action: RiskAction

    private enum CodingKeys: String, CodingKey {
        case threshold = "t"
        case action = "a"
    }

    public init(threshold: Double, action: RiskAction) {
        self.threshold = threshold
        self.action = action
    }
}

/// 计分节点：按升序阈值扫描，找到第一个“分数小于其上界”的区间并执行对应动作。
/// 若分数超过所有阈值，则执行 `defaultAction`（通常是最严格动作）。
public struct ScoreActionNode: Codable, Sendable {
    /// 节点标识。
    public let id: String
    /// 已按 `threshold` 升序排列的阈值表。
    public let thresholds: [ScoreActionThreshold]
    /// 分数达到/超过最高阈值时的动作。
    public let defaultAction: RiskAction

    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case thresholds = "th"
        case defaultAction = "da"
    }

    /// 用元组形式构造；内部会按阈值升序排序，调用方无需保证顺序。
    public init(id: String, thresholds: [(Double, RiskAction)], defaultAction: RiskAction) {
        self.id = id
        self.thresholds = thresholds
            .map { ScoreActionThreshold(threshold: $0.0, action: $0.1) }
            .sorted { $0.threshold < $1.threshold }
        self.defaultAction = defaultAction
    }

    /// 用结构体数组构造；同样会排序，避免乱序阈值导致区间错判。
    public init(id: String, thresholds: [ScoreActionThreshold], defaultAction: RiskAction) {
        self.id = id
        self.thresholds = thresholds.sorted { $0.threshold < $1.threshold }
        self.defaultAction = defaultAction
    }

    /// 扫描阈值区间并返回终止结果。
    /// 非有限分数直接放行并标注原因，避免 NaN 比较全部为 false 后落入 defaultAction。
    public func evaluate(context: EvaluationContext) -> DecisionResult {
        let salt = DecisionTreeCFF.salt(
            context: context,
            token: "score-node:\(id)",
            extraWords: [UInt64(thresholds.count), UInt64(defaultAction.rawValue)]
        )
        let seed: UInt32 = 0x7B4E12CD
        let entryState: UInt32 = 0x31
        let scanState: UInt32 = 0x32
        let connectorState: UInt32 = 0x33
        let settleState: UInt32 = 0x34

        // 非有限分数（NaN/∞）无法可靠比较，按 allow 明确返回，避免误触发 defaultAction。
        let invalidScoreResult = DecisionResult.terminate(action: .allow, reason: "Invalid non-finite score")
        var sink = CFFReturnSink<DecisionResult>()
        var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: salt)
        var index = 0

        while !sink.isResolved {
            let decodedState = CFFStateCodec.decode(encodedState, seed: seed, salt: salt)

            if decodedState == entryState {
                if context.score.isFinite {
                    encodedState = CFFStateCodec.encode(scanState, seed: seed, salt: salt)
                } else {
                    sink.store(invalidScoreResult)
                }
            } else if decodedState == scanState {
                guard index < thresholds.count else {
                    // 已越过最高阈值：命中 defaultAction（调用方通常配置为 block）。
                    sink.store(.terminate(action: defaultAction, reason: "Score \(context.score) meets highest threshold"))
                    continue
                }

                let item = thresholds[index]
                if context.score < item.threshold {
                    // 阈值是区间上界：分数低于它即采用该阈值绑定的动作。
                    sink.store(.terminate(action: item.action, reason: "Score \(context.score) below threshold \(item.threshold)"))
                } else {
                    index += 1
                    encodedState = CFFStateCodec.encode(connectorState, seed: seed, salt: salt)
                }
            } else if decodedState == connectorState {
                // 连接状态随机选择下一状态，制造冗余控制流；两条路径都会回到 scanState。
                let nextState = CFFDispatcher.branchKey(encodedState, salt: salt) & 1 == 0 ? scanState : settleState
                encodedState = CFFStateCodec.encode(nextState, seed: seed, salt: salt)
            } else if decodedState == settleState {
                encodedState = CFFStateCodec.encode(scanState, seed: seed, salt: salt)
            } else {
                // 未知状态意味着状态机损坏，按“分数非法”处理。
                sink.store(invalidScoreResult)
            }
        }

        return sink.resolve(or: invalidScoreResult)
    }
}

/// 顺序节点：按数组顺序求值子节点，遇到第一个终止/分支结果立即返回。
/// 全部子节点都返回 `.next` 时才返回 `.next`。
public struct SequenceNode: Codable, Sendable {
    /// 节点标识。
    public let id: String
    /// 按顺序执行的子节点。
    public let children: [DecisionTreeNodeType]

    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case children = "ch"
    }

    public init(id: String, children: [DecisionTreeNodeType]) {
        self.id = id
        self.children = children
    }

    /// 顺序求值；首个非 `.next` 结果即为最终结果（短路）。
    public func evaluate(context: EvaluationContext) -> DecisionResult {
        for child in children {
            let result = child.evaluate(context: context)
            // `.next` 表示该子节点没有意见，继续下一个。
            if case .next = result {
                continue
            }
            return result
        }
        return .next
    }
}

/// 并行节点：独立求值所有子节点，汇总其中的终止结果并取最严格动作。
/// 子节点的 `.next` / `.branch` 被忽略，不会阻断其他子节点。
public struct ParallelNode: Codable, Sendable {
    /// 节点标识。
    public let id: String
    /// 并行求值的子节点。
    public let children: [DecisionTreeNodeType]

    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case children = "ch"
    }

    public init(id: String, children: [DecisionTreeNodeType]) {
        self.id = id
        self.children = children
    }

    /// 汇总所有终止结果；动作取 severity 最大者，原因合并保留全部证据。
    public func evaluate(context: EvaluationContext) -> DecisionResult {
        var actions: [RiskAction] = []
        var reasons: [String] = []
        for child in children {
            switch child.evaluate(context: context) {
            case .terminate(let action, let reason):
                actions.append(action)
                reasons.append(reason)
            case .next, .branch:
                break
            }
        }

        // 没有任何子节点终止时，把决定权交还父节点。
        guard !actions.isEmpty else { return .next }
        // 并行场景必须“就高不就低”，避免一个放行结果覆盖另一个拒绝结果。
        let strictestAction = actions.max(by: { $0.severity < $1.severity }) ?? .allow
        return .terminate(action: strictestAction, reason: reasons.joined(separator: "; "))
    }
}

/// 决策树节点的类型擦除枚举，支持 Codable 序列化与递归嵌套。
public indirect enum DecisionTreeNodeType: Codable, Sendable {
    case condition(ConditionNode)
    case action(ActionNode)
    case scoreAction(ScoreActionNode)
    case sequence(SequenceNode)
    case parallel(ParallelNode)

    /// 转发到具体节点实现。
    public func evaluate(context: EvaluationContext) -> DecisionResult {
        switch self {
        case .condition(let node): return node.evaluate(context: context)
        case .action(let node): return node.evaluate(context: context)
        case .scoreAction(let node): return node.evaluate(context: context)
        case .sequence(let node): return node.evaluate(context: context)
        case .parallel(let node): return node.evaluate(context: context)
        }
    }
}

/// 决策树：持有根节点，对外提供求值（可返回 `.next`）与决策（永远给出动作）两种入口。
public struct DecisionTree: Codable, Sendable {
    /// 根节点。
    public let root: DecisionTreeNodeType
    /// 树名称，参与 CFF 盐值派生并用于日志。
    public let name: String
    /// 可选说明，仅用于审计。
    public let description: String?

    // 单字母键压缩序列化体积。
    private enum CodingKeys: String, CodingKey {
        case root = "r"
        case name = "n"
        case description = "ds"
    }

    public init(name: String, root: DecisionTreeNodeType, description: String? = nil) {
        self.name = name
        self.root = root
        self.description = description
    }

    /// 求值整棵树；结果可能为 `.next`，表示树未做决定。
    public func evaluate(context: EvaluationContext) -> DecisionResult {
        root.evaluate(context: context)
    }

    /// 决策入口：先求值树，若未终止则按当前场景阈值执行保底分类。
    /// 该路径保证任何输入都有明确动作，异常分数最终落到 block（fail-closed）。
    public func decide(context: EvaluationContext) -> RiskAction {
        let salt = DecisionTreeCFF.salt(context: context, token: "tree:\(name)")
        let evaluationSeed: UInt32 = 0x6F8C21B3
        let fallbackSeed: UInt32 = 0x29D44761
        let evaluateState: UInt32 = 0x41
        let terminalState: UInt32 = 0x42
        let fallbackPreludeState: UInt32 = 0x51
        let classifyState: UInt32 = 0x52
        let allowState: UInt32 = 0x53
        let challengeState: UInt32 = 0x54
        let stepUpState: UInt32 = 0x55
        let blockState: UInt32 = 0x56

        var sink = CFFReturnSink<RiskAction>()
        var evaluationResult: DecisionResult = .next
        var needsFallback = false
        var encodedState = CFFStateCodec.encode(evaluateState, seed: evaluationSeed, salt: salt)

        // 第一阶段：执行决策树；只有 terminate 才直接产出动作。
        while !sink.isResolved && !needsFallback {
            let decodedState = CFFStateCodec.decode(encodedState, seed: evaluationSeed, salt: salt)

            if decodedState == evaluateState {
                evaluationResult = evaluate(context: context)
                encodedState = CFFStateCodec.encode(terminalState, seed: evaluationSeed, salt: salt)
            } else if decodedState == terminalState {
                switch evaluationResult {
                case .terminate(let action, _):
                    sink.store(action)
                case .next, .branch:
                    // 树未给出终止结果，进入阈值保底分类。
                    needsFallback = true
                }
            } else {
                // 状态机异常时保守拒绝。
                sink.store(.block)
            }
        }

        // 第二阶段：按场景策略阈值兜底，保证 decide 永远返回一个动作。
        if !sink.isResolved {
            var fallbackState = CFFStateCodec.encode(fallbackPreludeState, seed: fallbackSeed, salt: salt ^ 0x13579BDF)

            while !sink.isResolved {
                switch CFFStateCodec.decode(fallbackState, seed: fallbackSeed, salt: salt ^ 0x13579BDF) {
                case fallbackPreludeState:
                    if context.score.isFinite {
                        fallbackState = CFFStateCodec.encode(classifyState, seed: fallbackSeed, salt: salt ^ 0x13579BDF)
                    } else {
                        // 分数不可比较时直接拒绝，不能假设安全。
                        sink.store(.block)
                    }
                case classifyState:
                    // 保底映射比默认 actionMapping 更严格：high 已升级为 stepUpAuth。
                    let nextState: UInt32
                    if context.score >= context.policy.criticalThreshold {
                        nextState = blockState
                    } else if context.score >= context.policy.highThreshold {
                        nextState = stepUpState
                    } else if context.score >= context.policy.mediumThreshold {
                        nextState = challengeState
                    } else {
                        nextState = allowState
                    }
                    fallbackState = CFFStateCodec.encode(nextState, seed: fallbackSeed, salt: salt ^ 0x13579BDF)
                case allowState:
                    sink.store(.allow)
                case challengeState:
                    sink.store(.challenge)
                case stepUpState:
                    sink.store(.stepUpAuth)
                case blockState:
                    sink.store(.block)
                default:
                    // 兜底路径异常同样拒绝。
                    sink.store(.block)
                }
            }
        }

        // 最终兜底 block：任何未解析路径都按拒绝处理（fail-closed）。
        return sink.resolve(or: .block)
    }
}

private extension ConditionExpression {
    var isScoreRange: Bool {
        if case .scoreRange = self { return true }
        return false
    }

    var isScoreGreaterThanOrEqual: Bool {
        if case .scoreGreaterThanOrEqual = self { return true }
        return false
    }

    var isScoreLessThan: Bool {
        if case .scoreLessThan = self { return true }
        return false
    }

    var isSignalExists: Bool {
        if case .signalExists = self { return true }
        return false
    }

    var isSignalScore: Bool {
        if case .signalScore = self { return true }
        return false
    }

    var isCategoryScore: Bool {
        if case .categoryScore = self { return true }
        return false
    }

    var isCustom: Bool {
        if case .custom = self { return true }
        return false
    }

    var isJailbrokenExpression: Bool {
        if case .isJailbroken = self { return true }
        return false
    }

    var isVPNExpression: Bool {
        if case .isVPN = self { return true }
        return false
    }

    var isProxyExpression: Bool {
        if case .isProxy = self { return true }
        return false
    }
}

// MARK: - 预设决策树

extension DecisionTree {
    /// 默认计分树：<30 allow，[30,55) challenge，[55,80) stepUpAuth，>=80 block。
    public static let `default` = DecisionTree(
        name: "default_score_tree",
        root: .scoreAction(
            ScoreActionNode(
                id: "score_decision",
                thresholds: [
                    (30, .allow),
                    (55, .challenge),
                    (80, .stepUpAuth)
                ],
                defaultAction: .block
            )
        ),
        description: "默认基于分数的决策树"
    )

    /// 支付树：越狱设备一律拒绝（叠加 VPN 时记录更强原因）；
    /// 非越狱则按 <20 allow、[20,45) stepUpAuth、>=45 block 处理。
    public static let payment = DecisionTree(
        name: "payment_tree",
        root: .sequence(
            SequenceNode(
                id: "payment_sequence",
                children: [
                    .condition(
                        ConditionNode(
                            id: "check_jailbreak_vpn",
                            condition: .signalExists(ObfuscatedConstants.signalJailbreak),
                            trueBranch: .condition(
                                ConditionNode(
                                    id: "check_vpn",
                                    condition: .signalExists(ObfuscatedConstants.requiredSignalVpnActive),
                                    trueBranch: .action(ActionNode(id: "block_combo", action: .block, reason: "越狱设备使用VPN进行支付")),
                                    falseBranch: .action(ActionNode(id: "block_jailbreak_only", action: .block, reason: "越狱设备禁止支付"))
                                )
                            ),
                            falseBranch: .scoreAction(
                                ScoreActionNode(
                                    id: "payment_score_decision",
                                    thresholds: [
                                        (20, .allow),
                                        (45, .stepUpAuth)
                                    ],
                                    defaultAction: .block
                                )
                            )
                        )
                    )
                ]
            )
        ),
        description: "支付场景决策树，越狱设备直接拒绝"
    )

    /// 登录树：行为类总分 >20 直接挑战；否则 <35 allow、[35,60) challenge、>=60 stepUpAuth。
    public static let login = DecisionTree(
        name: "login_tree",
        root: .sequence(
            SequenceNode(
                id: "login_sequence",
                children: [
                    .condition(
                        ConditionNode(
                            id: "check_high_risk_behavior",
                            condition: .categoryScore(category: "behavior", greaterThan: 20),
                            trueBranch: .action(ActionNode(id: "challenge_behavior", action: .challenge, reason: "检测到高风险行为模式")),
                            falseBranch: .scoreAction(
                                ScoreActionNode(
                                    id: "login_score_decision",
                                    thresholds: [
                                        (35, .allow),
                                        (60, .challenge)
                                    ],
                                    defaultAction: .stepUpAuth
                                )
                            )
                        )
                    )
                ]
            )
        ),
        description: "登录场景决策树"
    )

    /// 按场景选择预设树；register/query/apiAccess 复用默认树，
    /// accountChange 复用登录树，sensitiveAction 复用支付树。
    public static func tree(for scenario: RiskScenario) -> DecisionTree {
        switch scenario {
        case .default: return .default
        case .login: return .login
        case .register: return .default
        case .payment: return .payment
        case .accountChange: return .login
        case .sensitiveAction: return .payment
        case .apiAccess: return .default
        case .query: return .default
        }
    }
}
