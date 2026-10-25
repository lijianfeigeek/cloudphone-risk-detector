// 挑战触发器：根据能力探针异常数与篡改信号数，匹配服务端下发的 BlindRule，决定是否触发
// 一次性 blindChallenge（服务端下发、带 seed/过期时间，客户端回传执行结果供服务端复核）。
// 本地仅在 DEBUG 下允许无规则自动触发用于联调；生产必须依赖服务端规则。规则遍历走 CFF 状态机。
// 同时提供 challenge 载荷构造、签名、防重放哈希与规则复核等辅助方法。

import CryptoKit
import Foundation

/// `shouldTriggerBlindChallenge` 专用的 CFF 配置与运行时盐派生。
/// 盐绑定入参摘要与规则预览，使不同判定输入走不同的状态编码路径。
private enum ChallengeTriggerCFF {
    static let shouldTriggerConfig = CFFConfig.adaptive(
        functionSeed: 0xB5E2_71CA_4D3F_8096,
        protectionTier: .light,
        dispatcherStyle: .functionPointerTable,
        codecStyle: .feistelSpn
    )

    /// 用计数、规则数量与前两条规则的 ID 派生盐；只取前两条是为了控制成本，同时保留规则集变化敏感性。
    static func salt(
        capabilityAnomalyCount: Int,
        tamperedCount: Int,
        rules: [ServerRiskPolicy.BlindRule]
    ) -> UInt32 {
        let preview = rules.prefix(2).map(\.id).joined(separator: "|")
        return CFFRuntimeSalt.derive(
            functionSeed: shouldTriggerConfig.functionSeed,
            inputs: CFFRuntimeSaltInputs(
                extraWords: [
                    UInt64(capabilityAnomalyCount),
                    UInt64(tamperedCount),
                    UInt64(rules.count),
                    stableHash64(preview),
                ],
                strings: ["ChallengeTrigger.shouldTriggerBlindChallenge", preview],
                flags: [rules.isEmpty, capabilityAnomalyCount > 0, tamperedCount > 0]
            )
        )
    }

    /// FNV-1a 64 位哈希：稳定映射规则 ID，避免使用每次启动都会变化的 Swift `hashValue`。
    private static func stableHash64(_ value: String) -> UInt64 {
        var hash: UInt64 = 0xCBF29CE484222325
        for byte in value.utf8 {
            hash ^= UInt64(byte)
            hash &*= 0x100000001B3
        }
        return hash
    }
}

// MARK: - Challenge Trigger

/// Challenge 触发器
/// 用于检查是否需要触发 blindChallenge。
/// 注意：SDK 内的“本地合成 challenge”仅用于联调与回归，不代表服务端下发的一次性生产挑战。
public struct ChallengeTrigger: Sendable {

    /// 服务端下发的一次性 challenge。
    /// `seed` 与设备指纹绑定，`expiresAt`（毫秒时间戳）用于服务端防重放；字段均使用短键名压缩。
    public struct BlindChallenge: Codable, Sendable {
        public let challengeId: String
        public let probeIds: [String]
        public let seed: String
        public let expiresAt: Int64

        /// 短键名属于线协议契约，改名会导致与服务端不兼容。
        private enum CodingKeys: String, CodingKey {
            case challengeId = "ci"
            case probeIds = "pi"
            case seed = "s"
            case expiresAt = "ea"
        }

        public init(
            challengeId: String,
            probeIds: [String],
            seed: String,
            expiresAt: Int64
        ) {
            self.challengeId = challengeId
            self.probeIds = probeIds
            self.seed = seed
            self.expiresAt = expiresAt
        }
    }

    // MARK: - 触发结果

    /// 触发结果
    public struct TriggerResult: Sendable {
        /// 是否触发 blindChallenge
        public let triggered: Bool
        /// 匹配的规则
        public let matchedRule: ServerRiskPolicy.BlindRule?
        /// 触发原因描述
        public let reason: String

        public init(triggered: Bool, matchedRule: ServerRiskPolicy.BlindRule?, reason: String) {
            self.triggered = triggered
            self.matchedRule = matchedRule
            self.reason = reason
        }

        /// 未触发时的统一返回值，便于调用方直接比较 `triggered`。
        public static let noTrigger = TriggerResult(triggered: false, matchedRule: nil, reason: "")
    }

    // MARK: - 默认阈值

    /// 触发 blindChallenge 的默认能力探针异常数阈值（仅 DEBUG 本地联调使用）。
    public static let defaultCapabilityAnomalyThreshold = 2

    // MARK: - 触发检查

    /// 检查是否触发 blindChallenge（仅基于聚合计数）。
    ///
    /// - Parameters:
    ///   - capabilityAnomalyCount: 能力探针异常数（来自 CapabilityScore.basicAnomalyCount）
    ///   - tamperedCount: 被篡改的信号数量
    ///   - existingRules: 服务端配置的 blindChallenge 规则
    /// - Returns: 触发结果；无规则或未命中时返回 `.noTrigger`。
    ///
    /// 说明：此重载只接收计数，无法评估规则中的 signal ID / 跨层一致性条件；
    /// 需要这些条件时请使用基于信号列表的重载。
    public static func shouldTriggerBlindChallenge(
        capabilityAnomalyCount: Int,
        tamperedCount: Int,
        existingRules: [ServerRiskPolicy.BlindRule]
    ) -> TriggerResult {
        let cffConfig = ChallengeTriggerCFF.shouldTriggerConfig
        let salt = ChallengeTriggerCFF.salt(
            capabilityAnomalyCount: capabilityAnomalyCount,
            tamperedCount: tamperedCount,
            rules: existingRules
        )
        // 状态编号仅需互不相同；可读状态经 CFFStateCodec 编码后才进入局部变量。
        let entryState: UInt32 = 0x51
        let emptyRulesState: UInt32 = 0x52
        let iterateState: UInt32 = 0x53
        let evaluateState: UInt32 = 0x54
        let triggerState: UInt32 = 0x55
        let connectorState: UInt32 = 0x56
        let settleState: UInt32 = 0x57
        let noTriggerState: UInt32 = 0x58

        let cffKey = CFFStateCodec.deriveSeed(function: "ChallengeTrigger.shouldTriggerBlindChallenge", config: cffConfig)
        let effectiveSalt = cffConfig.enableRuntimeSalt ? salt : salt ^ 0x13579BDF

        /// 把可读状态编码为运行期不可读的 CFF 状态。
        func encodeState(_ rawState: UInt32) -> UInt32 {
            CFFStateCodec.encode(state: rawState, key: cffKey, salt: effectiveSalt, style: cffConfig.codecStyle)
        }

        /// 解码 CFF 状态；仅状态机内部使用。
        func decodeState(_ encoded: UInt32) -> UInt32 {
            CFFStateCodec.decode(state: encoded, key: cffKey, salt: effectiveSalt, style: cffConfig.codecStyle)
        }

        var sink = CFFReturnSink<TriggerResult>()
        var encodedState = encodeState(entryState)
        // 状态机护栏：每条规则约 5 个状态，预算随规则数增长；耗尽则按“不触发”收尾，避免死循环。
        var loopBudget = max(24, existingRules.count * 5 + 10)
        var ruleIndex = 0
        var currentRule: ServerRiskPolicy.BlindRule?

        while !sink.isResolved {
            guard loopBudget > 0 else {
                sink.store(.noTrigger)
                break
            }
            loopBudget -= 1

            let decodedState = decodeState(encodedState)
            let dispatchPlan = CFFDispatcher.plan(encodedState: encodedState, salt: salt, config: cffConfig)
            let useIfElseRail = dispatchPlan.style == .ifElseChain
                || (dispatchPlan.usesSecondaryDispatcher && CFFOpaquePredicates.connectorGate(encodedState: encodedState, salt: salt))

            if useIfElseRail {
                if decodedState == entryState {
                    let nextState = existingRules.isEmpty ? emptyRulesState : iterateState
                    encodedState = encodeState(nextState)
                } else if decodedState == emptyRulesState {
                    // 无服务端规则时的兜底：仅 DEBUG 允许本地自动触发，生产环境必须由服务端规则驱动，
                    // 否则被 patch 的客户端可以随意触发挑战或借触发行为做指纹。
                    #if DEBUG
                    if capabilityAnomalyCount >= defaultCapabilityAnomalyThreshold && tamperedCount > 0 {
                        let defaultRule = ServerRiskPolicy.BlindRule(
                            id: "debug_local_auto_trigger",
                            minTamperedCount: 1,
                            minCapabilityAnomalyCount: defaultCapabilityAnomalyThreshold,
                            weight: 75
                        )
                        sink.store(TriggerResult(
                            triggered: true,
                            matchedRule: defaultRule,
                            reason: "DEBUG local-only trigger: capabilityAnomalyCount(\(capabilityAnomalyCount)) >= \(defaultCapabilityAnomalyThreshold) && tamperedCount(\(tamperedCount)) > 0"
                        ))
                    } else {
                        sink.store(.noTrigger)
                    }
                    #else
                    sink.store(.noTrigger)
                    #endif
                } else if decodedState == iterateState {
                    guard ruleIndex < existingRules.count else {
                        encodedState = encodeState(noTriggerState)
                        continue
                    }
                    currentRule = existingRules[ruleIndex]
                    encodedState = encodeState(evaluateState)
                } else if decodedState == evaluateState {
                    guard let rule = currentRule else {
                        sink.store(.noTrigger)
                        continue
                    }

                    // 注意：rule 的 allOfSignalIDs、anyOfSignalIDs、requireCrossLayerInconsistency 与
                    // minDistinctRiskLayers 在此不参与评估，因为本重载只拿到聚合计数，没有完整信号列表。
                    // 仅依赖计数条件的规则（最常见）会被完整评估；同时包含 signal ID 或跨层条件的规则
                    // 会因只按计数匹配而过度触发。需要强制执行这些条件时，请使用基于信号列表的重载。
                    let capabilityMatches = capabilityAnomalyCount >= rule.minCapabilityAnomalyCount
                    let tamperedMatches = tamperedCount >= rule.minTamperedCount
                    if capabilityMatches && tamperedMatches {
                        encodedState = encodeState(triggerState)
                    } else {
                        encodedState = encodeState(connectorState)
                    }
                } else if decodedState == triggerState {
                    guard let rule = currentRule else {
                        sink.store(.noTrigger)
                        continue
                    }
                    sink.store(
                        TriggerResult(
                            triggered: true,
                            matchedRule: rule,
                            reason: buildReason(
                                capabilityAnomalyCount: capabilityAnomalyCount,
                                tamperedCount: tamperedCount,
                                rule: rule
                            )
                        )
                    )
                } else if decodedState == connectorState {
                    ruleIndex += 1
                    currentRule = nil
                    let nextState = CFFOpaquePredicates.parityFence(UInt32(ruleIndex) &+ decodedState, salt: salt) ? iterateState : settleState
                    encodedState = encodeState(nextState)
                } else if decodedState == settleState {
                    encodedState = encodeState(iterateState)
                } else if decodedState == noTriggerState {
                    sink.store(.noTrigger)
                } else {
                    sink.store(.noTrigger)
                }
            } else {
                switch decodedState {
                case entryState:
                    encodedState = encodeState(existingRules.isEmpty ? emptyRulesState : iterateState)
                case emptyRulesState:
                    #if DEBUG
                    if capabilityAnomalyCount >= defaultCapabilityAnomalyThreshold && tamperedCount > 0 {
                        let defaultRule = ServerRiskPolicy.BlindRule(
                            id: "debug_local_auto_trigger",
                            minTamperedCount: 1,
                            minCapabilityAnomalyCount: defaultCapabilityAnomalyThreshold,
                            weight: 75
                        )
                        sink.store(TriggerResult(
                            triggered: true,
                            matchedRule: defaultRule,
                            reason: "DEBUG local-only trigger: capabilityAnomalyCount(\(capabilityAnomalyCount)) >= \(defaultCapabilityAnomalyThreshold) && tamperedCount(\(tamperedCount)) > 0"
                        ))
                    } else {
                        sink.store(.noTrigger)
                    }
                    #else
                    sink.store(.noTrigger)
                    #endif
                case iterateState:
                    guard ruleIndex < existingRules.count else {
                        encodedState = encodeState(noTriggerState)
                        continue
                    }
                    currentRule = existingRules[ruleIndex]
                    encodedState = encodeState(evaluateState)
                case connectorState:
                    ruleIndex += 1
                    currentRule = nil
                    let nextState = CFFDispatcher.branchKey(encodedState, salt: salt) & 1 == 0 ? iterateState : settleState
                    encodedState = encodeState(nextState)
                case settleState:
                    encodedState = encodeState(iterateState)
                case evaluateState:
                    guard let rule = currentRule else {
                        sink.store(.noTrigger)
                        continue
                    }
                    let capabilityMatches = capabilityAnomalyCount >= rule.minCapabilityAnomalyCount
                    let tamperedMatches = tamperedCount >= rule.minTamperedCount
                    if capabilityMatches && tamperedMatches {
                        encodedState = encodeState(triggerState)
                    } else {
                        encodedState = encodeState(connectorState)
                    }
                case triggerState:
                    guard let rule = currentRule else {
                        sink.store(.noTrigger)
                        continue
                    }
                    sink.store(
                        TriggerResult(
                            triggered: true,
                            matchedRule: rule,
                            reason: buildReason(
                                capabilityAnomalyCount: capabilityAnomalyCount,
                                tamperedCount: tamperedCount,
                                rule: rule
                            )
                        )
                    )
                case noTriggerState:
                    sink.store(.noTrigger)
                default:
                    sink.store(.noTrigger)
                }
            }
        }

        return sink.resolve(or: .noTrigger)
    }

    /// 检查是否触发 blindChallenge（基于 CapabilityScore）。
    /// 直接取 `basicAnomalyCount` 作为能力异常数，质量可疑度不参与规则匹配（由服务端另行加权）。
    ///
    /// - Parameters:
    ///   - capabilityScore: 能力探针得分
    ///   - tamperedCount: 被篡改的信号数量
    ///   - existingRules: 服务端配置的 blindChallenge 规则
    /// - Returns: 触发结果
    public static func shouldTriggerBlindChallenge(
        capabilityScore: CapabilityScore,
        tamperedCount: Int,
        existingRules: [ServerRiskPolicy.BlindRule]
    ) -> TriggerResult {
        return shouldTriggerBlindChallenge(
            capabilityAnomalyCount: capabilityScore.basicAnomalyCount,
            tamperedCount: tamperedCount,
            existingRules: existingRules
        )
    }

    // MARK: - 私有方法

    /// 构造触发原因字符串，只包含本重载真正验证过的计数条件。
    /// 刻意不写入 signal ID / 跨层条件：未验证的条件若写进 reason，会给服务端错误归因。
    private static func buildReason(
        capabilityAnomalyCount: Int,
        tamperedCount: Int,
        rule: ServerRiskPolicy.BlindRule
    ) -> String {
        var reasons: [String] = []

        if rule.minCapabilityAnomalyCount > 0 {
            reasons.append("capabilityAnomalyCount(\(capabilityAnomalyCount)) >= \(rule.minCapabilityAnomalyCount)")
        }

        if rule.minTamperedCount > 0 {
            reasons.append("tamperedCount(\(tamperedCount)) >= \(rule.minTamperedCount)")
        }

        // 注意：rule.requireCrossLayerInconsistency、allOfSignalIDs、anyOfSignalIDs 与
        // minDistinctRiskLayers 都需要完整信号列表才能评估，而 shouldTriggerBlindChallenge
        // 只接收计数参数，无法检查这些条件。不要把未验证的条件写进 reason，避免给服务端
        // 错误归因（例如声称检测到 crossLayerInconsistency，实际从未验证）。

        return "Rule[\(rule.id)]: \(reasons.joined(separator: " && "))"
    }
}

// MARK: - 服务端验证辅助

/// 服务端验证辅助：时间戳、载荷构造、签名与规则复核。
extension ChallengeTrigger {

    /// 当前 Unix 毫秒时间戳，与 challenge.expiresAt 单位保持一致。
    public static func nowMillis() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1000)
    }

    /// 生成键排序后的稳定 JSON 串；签名必须基于确定性字节序列，否则客户端/服务端计算结果不一致。
    private static func canonicalJSONString(_ object: [String: Any]) -> String? {
        guard JSONSerialization.isValidJSONObject(object),
              let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    /// 生成 blindChallenge 验证请求的数据
    ///
    /// - Parameters:
    ///   - capabilityScore: 能力探针得分
    ///   - tamperedCount: 被篡改的信号数量
    ///   - salt: 服务端下发的 challengeSalt
    ///   - timestamp: 当前时间戳
    /// - Returns: 验证数据字典（供服务端验证）
    public static func buildChallengePayload(
        capabilityScore: CapabilityScore,
        tamperedCount: Int,
        salt: String,
        timestamp: Int64 = nowMillis()
    ) -> [String: Any] {
        return [
            "capabilityAnomalyCount": capabilityScore.basicAnomalyCount,
            "qualitySuspicion": capabilityScore.qualitySuspicion,
            "totalProbes": capabilityScore.totalProbes,
            "tamperedCount": tamperedCount,
            "salt": salt,
            "timestamp": timestamp,
            // 探针原始数据（供服务端重新验证）
            "probeRiskContribution": capabilityScore.riskContribution
        ]
    }

    /// 生成带 challenge 绑定的 payload（beta.4）
    /// 返回值中包含 challengeId/probeIds/seed/expiresAt，可用于服务端防重放核验。
    public static func buildChallengePayload(
        challenge: BlindChallenge,
        capabilityScore: CapabilityScore,
        tamperedCount: Int,
        executedProbeIDs: [String],
        timestamp: Int64 = nowMillis()
    ) -> [String: Any] {
        [
            "challengeId": challenge.challengeId,
            "seed": challenge.seed,
            "probeIds": challenge.probeIds,
            "executedProbeIds": executedProbeIDs,
            "expiresAt": challenge.expiresAt,
            "timestamp": timestamp,
            "capabilityAnomalyCount": capabilityScore.basicAnomalyCount,
            "qualitySuspicion": capabilityScore.qualitySuspicion,
            "totalProbes": capabilityScore.totalProbes,
            "tamperedCount": tamperedCount,
            "probeRiskContribution": capabilityScore.riskContribution,
        ]
    }

    /// 生成强类型 challenge 绑定载荷，可直接写入 CPRiskReport payload。
    /// - Parameter executionStatus: 探针执行状态（超时/不支持时传入 .timeout / .unsupported）
    /// - Parameter expectedHash: seed 与设备指纹绑定占位，expectedHash = SHA256(seed + deviceFingerprint)
    public static func buildChallengeBindingPayload(
        challenge: BlindChallenge,
        capabilityScore: CapabilityScore,
        tamperedCount: Int,
        executedProbeIDs: [String],
        triggerReason: String?,
        timestamp: Int64 = nowMillis(),
        executionStatus: ChallengeExecutionStatus = .completed,
        expectedHash: String? = nil
    ) -> ChallengeBindingPayload {
        ChallengeBindingPayload(
            challengeId: challenge.challengeId,
            seed: challenge.seed,
            probeIds: challenge.probeIds,
            executedProbeIds: executedProbeIDs,
            expiresAt: challenge.expiresAt,
            timestamp: timestamp,
            capabilityAnomalyCount: capabilityScore.basicAnomalyCount,
            qualitySuspicion: capabilityScore.qualitySuspicion,
            totalProbes: capabilityScore.totalProbes,
            tamperedCount: tamperedCount,
            probeRiskContribution: capabilityScore.riskContribution,
            triggerReason: triggerReason,
            executionStatus: executionStatus,
            expectedHash: expectedHash
        )
    }

    /// 计算 seed 与设备指纹绑定的 expectedHash 占位
    /// expectedHash = SHA256(seed + deviceFingerprint)，用于服务端防重放验证
    public static func computeExpectedHash(seed: String, deviceFingerprint: String) -> String? {
        let input = seed + deviceFingerprint
        guard let data = input.data(using: .utf8) else { return nil }
        let hash = SHA256.hash(data: data)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }

    /// challenge 是否在有效期内
    public static func isChallengeValid(_ challenge: BlindChallenge, timestamp: Int64 = nowMillis()) -> Bool {
        timestamp < challenge.expiresAt
    }

    /// 客户端生成 challenge 绑定签名（HMAC）。
    /// 签名前先规范化 JSON；密钥用后立即清零，减少内存残留窗口。
    public static func signChallengePayload(payload: [String: Any], signingKey: String) -> String? {
        guard let canonical = canonicalJSONString(payload),
              let messageData = canonical.data(using: .utf8) else {
            return nil
        }
        guard var keyData = signingKey.data(using: .utf8) else {
            return nil
        }
        defer { secureZeroData(&keyData) }
        return CPRiskMessageAuth.authenticationCodeHex(for: messageData, keyData: keyData)
    }

    /// challenge 绑定签名校验
    /// 使用常量时间比较，避免通过响应时间侧信道逐字节猜测签名。
    public static func verifyChallengePayloadSignature(
        payload: [String: Any],
        signature: String,
        signingKey: String
    ) -> Bool {
        guard let expected = signChallengePayload(payload: payload, signingKey: signingKey) else {
            return false
        }
        return timingSafeCompare(expected, signature.lowercased())
    }

    /// 验证客户端上报的数据是否与服务端规则匹配
    ///
    /// - Parameters:
    ///   - capabilityAnomalyCount: 客户端上报的能力探针异常数
    ///   - tamperedCount: 客户端上报的篡改信号数
    ///   - rule: 服务端规则
    /// - Returns: 是否匹配
    public static func validateWithRule(
        capabilityAnomalyCount: Int,
        tamperedCount: Int,
        rule: ServerRiskPolicy.BlindRule
    ) -> Bool {
        // 检查能力探针异常数
        if capabilityAnomalyCount < rule.minCapabilityAnomalyCount {
            return false
        }

        // 检查篡改计数
        if tamperedCount < rule.minTamperedCount {
            return false
        }

        return true
    }
}
