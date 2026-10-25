// CFF dispatcher：根据编码状态与盐选择分支形态、主/次轨与每轮旋转策略。
// 位于 Internal/CFF 的状态机分发层，向上承接 CFFConfig，向下驱动实际基本块跳转。
// 关键安全不变量：分支选择必须是编码状态与盐的确定性函数；旋转链不得依赖外部可变状态。
import Foundation

/// 一次分发的决策结果，供状态机决定下一步走哪条基本块路径。
internal struct CFFDispatchPlan: Sendable, Equatable {
    /// 本次采用的 dispatcher 风格。
    let style: CFFDispatcherStyle
    /// 分支选择键（0..3），由状态与盐派生。
    let branchSelector: UInt32
    /// 是否倾向主轨（dual-rail 使用）。
    let prefersPrimaryRail: Bool
    /// 是否使用次级 dispatcher（仅 dualRail 为真）。
    let usesSecondaryDispatcher: Bool
    /// 每次调用递增的 epoch，用于在循环迭代间轮换 dispatcher 风格。
    /// 下游状态机应在下一次调用 `planRotating` 时把它作为 `invocationCounter`
    /// 传回，以推进旋转链。
    let invocationEpoch: UInt32
}

/// CFF 分发决策工具集。
/// 线程模型：纯函数，无共享状态，可并发调用。
internal enum CFFDispatcher {
    /// 判断是否倾向主轨（legacy blend）。
    /// - Parameters:
    ///   - encodedState: 当前编码状态。
    ///   - salt: 运行时盐。
    /// - Returns: 倾向主轨返回 `true`。
    @inline(__always)
    static func prefersPrimaryBranch(encodedState: UInt32, salt: UInt32) -> Bool {
        prefersPrimaryRail(encodedState: encodedState, salt: salt, blend: .legacy)
    }

    /// 计算 4 路分支键（legacy blend）。
    /// - Parameters:
    ///   - encodedState: 当前编码状态。
    ///   - salt: 运行时盐。
    /// - Returns: 0..3 的分支键。
    @inline(__always)
    static func branchKey(_ encodedState: UInt32, salt: UInt32) -> UInt32 {
        branchKey(encodedState, salt: salt, modulo: 4, blend: .legacy)
    }

    /// 计算 4 路分支键（指定 blend）。
    /// - Parameters:
    ///   - encodedState: 当前编码状态。
    ///   - salt: 运行时盐。
    ///   - blend: 上下文混合方案。
    /// - Returns: 0..3 的分支键。
    @inline(__always)
    static func branchKey(_ encodedState: UInt32, salt: UInt32, blend: CFFContextBlend) -> UInt32 {
        branchKey(encodedState, salt: salt, modulo: 4, blend: blend)
    }

    /// 生成一次静态分发计划（不轮换）。
    /// - Parameters:
    ///   - encodedState: 当前编码状态。
    ///   - salt: 运行时盐。
    ///   - config: CFF 配置。
    /// - Returns: 分发计划，`invocationEpoch` 固定为 0。
    @inline(__always)
    static func plan(encodedState: UInt32, salt: UInt32, config: CFFConfig) -> CFFDispatchPlan {
        let blend = config.contextBlend
        let selector = branchKey(encodedState, salt: salt, modulo: 4, blend: blend)
        let prefersPrimary = prefersPrimaryRail(encodedState: encodedState, salt: salt, blend: blend)
        let resolvedStyle: CFFDispatcherStyle

        switch config.dispatcherStyle {
        case .switchLoop:
            // 命中连接器选择子且允许连接器状态时，临时切换为 if-else 形态。
            resolvedStyle = selector == blend.switchConnectorSelector && config.allowConnectorStates ? .ifElseChain : .switchLoop
        case .ifElseChain:
            resolvedStyle = selector == blend.ifElseConnectorSelector && config.allowConnectorStates ? .switchLoop : .ifElseChain
        case .dualRail:
            // 双轨：主/次轨各自对应一种 dispatcher 形态。
            resolvedStyle = prefersPrimary ? .switchLoop : .ifElseChain
        case .functionPointerTable:
            let table = blend.fpTable
            let seed32 = UInt32(truncatingIfNeeded: config.functionSeed)
            // 用函数种子扰动状态，再映射到函数指针表索引。
            let ix = Int(CFFOpaquePredicates.boundedSelector(
                encodedState ^ seed32,
                salt: salt,
                modulo: UInt32(table.count),
                blend: blend
            ))
            resolvedStyle = table[ix]
        case .splitIndirect:
            resolvedStyle = splitIndirectStyle(
                encodedState: encodedState,
                salt: salt,
                selector: selector,
                prefersPrimary: prefersPrimary,
                config: config,
                blend: blend
            )
        }

        return CFFDispatchPlan(
            style: resolvedStyle,
            branchSelector: selector,
            prefersPrimaryRail: prefersPrimary,
            usesSecondaryDispatcher: config.dispatcherStyle == .dualRail,
            invocationEpoch: 0
        )
    }

    /// 生成每轮旋转的分发计划：把 `invocationCounter` 混入盐，使同一函数每次调用
    /// 得到可能不同的 dispatcher 风格。下一次调用时把 `plan.invocationEpoch`
    /// 作为 `invocationCounter` 传回，即可在无外部状态的情况下推进旋转链。
    ///
    /// 对抗目的：破坏 Capstone L1/L2 的分发路径缓存——同一状态机基本块入口
    /// 在每一轮循环中解析出的 `CFFDispatcherStyle` 不同，从而产生不同的 ARM64 分支目标。
    /// - Parameters:
    ///   - encodedState: 当前编码状态。
    ///   - salt: 运行时盐。
    ///   - config: CFF 配置。
    ///   - invocationCounter: 当前调用序号（上一轮的 `invocationEpoch`）。
    /// - Returns: 含下一轮 epoch 的分发计划。
    @inline(__always)
    static func planRotating(
        encodedState: UInt32,
        salt: UInt32,
        config: CFFConfig,
        invocationCounter: UInt32
    ) -> CFFDispatchPlan {
        let rotNonce = CFFRuntimeSalt.deriveRotationNonce(
            counter: invocationCounter,
            functionSeed: config.functionSeed
        )
        // 旋转 nonce 与盐异或，使每轮的派生常量都不同。
        let rotatedSalt = salt ^ rotNonce
        let blend = config.contextBlend
        let selector = branchKey(encodedState, salt: rotatedSalt, modulo: 4, blend: blend)
        let prefersPrimary = prefersPrimaryRail(
            encodedState: encodedState,
            salt: rotatedSalt,
            blend: blend
        )

        let resolvedStyle: CFFDispatcherStyle
        switch config.dispatcherStyle {
        case .switchLoop:
            resolvedStyle = selector == blend.switchConnectorSelector && config.allowConnectorStates
                ? .ifElseChain : .switchLoop
        case .ifElseChain:
            resolvedStyle = selector == blend.ifElseConnectorSelector && config.allowConnectorStates
                ? .switchLoop : .ifElseChain
        case .dualRail:
            resolvedStyle = prefersPrimary ? .switchLoop : .ifElseChain
        case .functionPointerTable:
            let table = blend.fpTable
            let seed32 = UInt32(truncatingIfNeeded: config.functionSeed)
            let ix = Int(CFFOpaquePredicates.boundedSelector(
                encodedState ^ seed32 ^ rotNonce,
                salt: rotatedSalt,
                modulo: UInt32(table.count),
                blend: blend
            ))
            resolvedStyle = table[ix]
        case .splitIndirect:
            resolvedStyle = splitIndirectStyle(
                encodedState: encodedState,
                salt: rotatedSalt,
                selector: selector,
                prefersPrimary: prefersPrimary,
                config: config,
                blend: blend
            )
        }

        // 下一 epoch：把当前 nonce 与实际选择子混入计数，使旋转链与实际执行耦合。
        let nextEpoch = invocationCounter &+ 1 &+ (selector ^ rotNonce)

        return CFFDispatchPlan(
            style: resolvedStyle,
            branchSelector: selector,
            prefersPrimaryRail: prefersPrimary,
            usesSecondaryDispatcher: config.dispatcherStyle == .dualRail,
            invocationEpoch: nextEpoch
        )
    }

    /// 判断当前状态是否倾向主轨。
    /// - Parameters:
    ///   - encodedState: 当前编码状态。
    ///   - salt: 运行时盐。
    ///   - blend: 上下文混合方案。
    /// - Returns: 最低位为 0 时倾向主轨。
    @inline(__always)
    static func prefersPrimaryRail(encodedState: UInt32, salt: UInt32, blend: CFFContextBlend) -> Bool {
        // lane 常量用于把该判定与其它派生值隔离；mask 由运行时盐混合得到。
        let mask = runtimeBlendMask(salt: salt, blend: blend, lane: 0x4346_465F_5241_494C)
        // `| 1` 保证乘子为奇数，避免乘法退化。
        let multiplier = (blend.railSaltMultiplier ^ mask) | 1
        return ((encodedState ^ (salt &* multiplier)) & 1) == 0
    }

    /// 计算分支键（自定义模数，legacy blend）。
    /// - Parameters:
    ///   - encodedState: 当前编码状态。
    ///   - salt: 运行时盐。
    ///   - modulo: 取模上界。
    /// - Returns: `[0, modulo)` 内的键。
    @inline(__always)
    static func branchKey(_ encodedState: UInt32, salt: UInt32, modulo: UInt32) -> UInt32 {
        branchKey(encodedState, salt: salt, modulo: modulo, blend: .legacy)
    }

    /// 计算分支键：状态、盐、blend 常量与运行时 mask 混合后取模。
    /// - Parameters:
    ///   - encodedState: 当前编码状态。
    ///   - salt: 运行时盐。
    ///   - modulo: 取模上界，内部会兜底为至少 1。
    ///   - blend: 上下文混合方案。
    /// - Returns: `[0, modulo)` 内的键。
    @inline(__always)
    static func branchKey(_ encodedState: UInt32, salt: UInt32, modulo: UInt32, blend: CFFContextBlend) -> UInt32 {
        let boundedModulo = max(1, modulo)
        let mask = runtimeBlendMask(salt: salt, blend: blend, lane: 0x4346_465F_4252_414E)
        return (encodedState ^ salt ^ blend.dispatchXor32 ^ mask) % boundedModulo
    }

    /// 判断本轮是否应访问一个假状态（用于注入噪声基本块）。
    /// - Parameters:
    ///   - encodedState: 当前编码状态。
    ///   - salt: 运行时盐。
    ///   - config: CFF 配置。
    /// - Returns: 应访问假状态返回 `true`；未启用假状态或非 release 构建始终返回 `false`。
    @inline(__always)
    static func shouldVisitFakeState(
        encodedState: UInt32,
        salt: UInt32,
        config: CFFConfig
    ) -> Bool {
        // 假状态只在 release 构建、显式启用且数量大于 0 时生效，避免调试期行为漂移。
        guard config.enableFakeStates, config.normalizedFakeStateCount > 0, config.buildFlavor == .release else {
            return false
        }

        let blend = config.contextBlend
        // `+2` 让命中概率低于 1/(n+2)，假状态仅作噪声而非主路径。
        return branchKey(
            encodedState &+ blend.fakeEncodedTweak,
            salt: salt ^ blend.fakeSaltXor,
            modulo: UInt32(config.normalizedFakeStateCount + 2),
            blend: blend
        ) == 0
    }

    /// splitIndirect 分发：先用质数打散的 token 选表，再用奇偶门控决定是否翻转风格。
    /// - Parameters:
    ///   - encodedState: 当前编码状态。
    ///   - salt: 运行时盐。
    ///   - selector: 已计算的分支键。
    ///   - prefersPrimary: 是否倾向主轨。
    ///   - config: CFF 配置。
    ///   - blend: 上下文混合方案。
    /// - Returns: 解析出的 dispatcher 风格。
    @inline(__always)
    private static func splitIndirectStyle(
        encodedState: UInt32,
        salt: UInt32,
        selector: UInt32,
        prefersPrimary: Bool,
        config: CFFConfig,
        blend: CFFContextBlend
    ) -> CFFDispatcherStyle {
        let table = blend.fpTable
        // 用质数放大 selector 的影响，再与 splitSaltXor 异或后映射到表索引。
        let token = CFFOpaquePredicates.boundedSelector(
            encodedState ^ (selector &* blend.splitSelectorPrime),
            salt: salt ^ blend.splitSaltXor,
            modulo: UInt32(table.count),
            blend: blend
        )

        // 奇偶门控提供一层不透明谓词；只有“允许连接器 + 门控通过 + 倾向主轨”才翻转风格。
        let gate = CFFOpaquePredicates.parityFence(encodedState ^ selector, salt: salt, blend: blend)
        let base = table[Int(token)]
        if config.allowConnectorStates && gate && prefersPrimary {
            return base == .switchLoop ? .ifElseChain : .switchLoop
        }
        return base
    }

    /// 计算运行时混合掩码。
    /// - Parameters:
    ///   - salt: 运行时盐。
    ///   - blend: 上下文混合方案。
    ///   - lane: 用途孤立常量。
    /// - Returns: 32 位掩码。
    @inline(__always)
    private static func runtimeBlendMask(salt: UInt32, blend: CFFContextBlend, lane: UInt64) -> UInt32 {
        // lane 的最低位作为 flag 一并吸收，使不同 lane 的 mask 相互独立。
        CFFRuntimeSalt.combine(
            words: [UInt64(salt), UInt64(blend.dispatchXor32), lane],
            strings: [blend.rawValue],
            flags: [(lane & 1) == 1]
        )
    }
}
