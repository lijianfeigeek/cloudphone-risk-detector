// CFF（控制流平坦化）配置模型：描述保护层级、dispatcher 风格、编码风格与失败策略。
// 位于 Internal/CFF 的配置层，被代码生成器/状态机在构建期与运行期共同读取。
// 关键安全不变量：release 构建应启用 runtime salt 与 fail-closed；配置派生常量必须由种子决定而非硬编码指纹。
import Foundation

/// CFF 保护层级：决定注入多少状态机噪声与假状态。
enum CFFProtectionTier: String, Codable, Sendable {
    /// 最重保护，允许连接器状态与假状态。
    case heavy
    /// 轻量保护，开销较低。
    case light
    /// 仅对部分区域做保护。
    case regionOnly
    /// 不启用保护。
    case never
}

/// dispatcher 的代码形态；运行时按配置与分支键选择/轮换。
enum CFFDispatcherStyle: String, CaseIterable, Codable, Sendable {
    /// `switch` 循环分发。
    case switchLoop
    /// `if-else` 链分发。
    case ifElseChain
    /// 双轨（dual-rail）分发，按 prefersPrimary 选择主/次轨。
    case dualRail
    /// 分裂间接分发（splitIndirect），token 与门控分离。
    case splitIndirect
    /// C 侧风格：通过每个 codec 的函数指针表解码（`cprisk_cff_current_state_table`）。
    case functionPointerTable
}

/// 状态编码/解码算法风格。
enum CFFStateCodecStyle: String, CaseIterable, Codable, Sendable {
    /// XOR + 循环移位。
    case xorRotate
    /// 加法 + 循环移位 + XOR。
    case addRotateXor
    /// 仿射变换（奇数乘子保证可逆）。
    case affine
    /// Feistel 网络 + SPN 字节替换（默认最强）。
    case feistelSpn
}

/// 构建类型：debug/release 会影响盐与假状态策略。
enum CFFBuildFlavor: String, Codable, Sendable {
    /// 调试构建。
    case debug
    /// 发布构建。
    case release
}

/// 上下文混合方案：把构建类型、dispatcher 风格与保护层级映射为一组派生常量。
enum CFFContextBlend: String, CaseIterable, Codable, Sendable {
    /// 兼容旧行为的最小混合。
    case legacy
    /// 调试构建的扩展混合。
    case debugExtended
    /// 发布构建的均衡混合。
    case releaseBalanced
    /// 发布构建 + 函数指针表。
    case releasePointerTable
    /// 发布构建 + 分裂间接分发。
    case releaseSplitIndirect

    /// FNV-1a 64 位哈希，把枚举 rawValue 转成稳定的 64 位上下文词。
    /// - Parameter value: 待哈希字符串。
    /// - Returns: 64 位哈希值。
    @inline(__always)
    private static func fnv1a64(_ value: String) -> UInt64 {
        // FNV offset basis / prime。
        var hash: UInt64 = 0xCBF29CE484222325
        for byte in value.utf8 {
            hash ^= UInt64(byte)
            hash &*= 0x100000001B3
        }
        return hash
    }

    /// 由 blend 上下文、基准常量与运行时盐派生 32 位常量。
    /// - Parameters:
    ///   - domain: 用途域常量，隔离不同派生值。
    ///   - base: 该 blend 的基准常量。
    ///   - runtimeSalt: 可选运行时盐。
    /// - Returns: 派生后的 32 位值。
    @inline(__always)
    private func derivedWord32(domain: UInt64, base: UInt32, runtimeSalt: UInt32 = 0) -> UInt32 {
        // 把 rawValue 哈希、base 与 domain 组合成上下文词，再做运行时混合。
        let contextWord = Self.fnv1a64(rawValue) ^ (UInt64(base) << 16) ^ domain
        let tweak = CFFSBoxRuntime.derivedWord32(domain: domain, runtimeSalt: runtimeSalt, contextWord: contextWord)
        // 循环移位后与 base 异或，避免输出等于基准常量。
        return base ^ ((tweak << 7) | (tweak >> 25))
    }

    /// 派生 0..3 的布局标签。
    /// - Parameters:
    ///   - base: 基准标签值。
    ///   - domain: 用途域常量。
    /// - Returns: 0..3 的标签。
    @inline(__always)
    private func derivedTag(base: UInt8, domain: UInt64) -> UInt8 {
        let tweak = derivedWord32(domain: domain, base: UInt32(base))
        // 与 0x3 掩码确保结果落在 2 bit 范围内；加上 base 后再取模保持分布。
        return UInt8((Int(base) + Int(tweak & 0x3)) & 0x3)
    }

    /// dispatcher 分支键的基准异或常量（每个 blend 不同）。
    private var baseDispatchXor32: UInt32 {
        switch self {
        case .legacy:
            return 0xA24B_AED5
        case .debugExtended:
            return 0x7F4A_7C15
        case .releaseBalanced:
            return 0x51ED_270B
        case .releasePointerTable:
            return 0xD1B5_4A35
        case .releaseSplitIndirect:
            return 0x94D0_49BB
        }
    }

    /// 实际用于分支键的异或常量；由基准值经运行时派生，避免静态指纹。
    var dispatchXor32: UInt32 {
        derivedWord32(domain: 0x4346_4644_4953_5058, base: baseDispatchXor32)
    }

    /// dual-rail 盐乘子的基准值。
    private var baseRailSaltMultiplier: UInt32 {
        switch self {
        case .legacy:
            return 0x45D9_F3B
        case .debugExtended:
            return 0x27D4_EB2D
        case .releaseBalanced:
            return 0x119D_E1F3
        case .releasePointerTable:
            return 0x9E37_79B1
        case .releaseSplitIndirect:
            return 0x1656_67B1
        }
    }

    /// dual-rail 盐乘子；`| 1` 强制为奇数，保证乘法在 2^32 下可逆/不退化。
    var railSaltMultiplier: UInt32 {
        derivedWord32(domain: 0x4346_4652_4149_4C4D, base: baseRailSaltMultiplier) | 1
    }

    /// switch 分发连接到 if-else 的选择子基准（0..3）。
    private var baseSwitchConnectorSelector: UInt32 {
        switch self {
        case .legacy, .releasePointerTable:
            return 1
        case .debugExtended, .releaseSplitIndirect:
            return 2
        case .releaseBalanced:
            return 3
        }
    }

    /// 实际的 switch 连接器选择子；结果被限制在 0..3。
    var switchConnectorSelector: UInt32 {
        UInt32((Int(baseSwitchConnectorSelector) + Int(derivedWord32(domain: 0x4346_4653_5743_4843, base: baseSwitchConnectorSelector) & 0x3)) & 0x3)
    }

    /// if-else 分发连接到 switch 的选择子基准（0..3）。
    private var baseIfElseConnectorSelector: UInt32 {
        switch self {
        case .legacy, .releaseBalanced:
            return 2
        case .debugExtended:
            return 3
        case .releasePointerTable:
            return 0
        case .releaseSplitIndirect:
            return 1
        }
    }

    /// 实际的 if-else 连接器选择子；结果被限制在 0..3。
    var ifElseConnectorSelector: UInt32 {
        UInt32((Int(baseIfElseConnectorSelector) + Int(derivedWord32(domain: 0x4346_4649_4645_4C53, base: baseIfElseConnectorSelector) & 0x3)) & 0x3)
    }

    /// 假状态编码扰动的基准值。
    private var baseFakeEncodedTweak: UInt32 {
        switch self {
        case .legacy:
            return 0x1357_9BDF
        case .debugExtended:
            return 0x6C8E_9CF5
        case .releaseBalanced:
            return 0x517C_C1B7
        case .releasePointerTable:
            return 0xC2B2_AE3D
        case .releaseSplitIndirect:
            return 0x85EB_CA6B
        }
    }

    /// 假状态编码时混入 encodedState 的扰动值。
    var fakeEncodedTweak: UInt32 {
        derivedWord32(domain: 0x4346_4646_414B_4554, base: baseFakeEncodedTweak)
    }

    /// 假状态盐异或值的基准。
    private var baseFakeSaltXor: UInt32 {
        switch self {
        case .legacy:
            return 0x517C_C1B7
        case .debugExtended:
            return 0x1B56_C4E9
        case .releaseBalanced:
            return 0x9E37_79B9
        case .releasePointerTable:
            return 0x7F4A_7C15
        case .releaseSplitIndirect:
            return 0xA5A5_5A5A
        }
    }

    /// 假状态判定时与盐异或的值。
    var fakeSaltXor: UInt32 {
        derivedWord32(domain: 0x4346_4646_5341_4C54, base: baseFakeSaltXor)
    }

    /// splitIndirect 质数池中的基准质数。
    private var baseSplitSelectorPrime: UInt32 {
        switch self {
        case .legacy:
            return 65_521
        case .debugExtended:
            return 65_497
        case .releaseBalanced:
            return 65_479
        case .releasePointerTable:
            return 65_449
        case .releaseSplitIndirect:
            return 65_447
        }
    }

    /// splitIndirect 使用的质数；从相邻质数池中按派生偏移选择，避免固定单个质数。
    var splitSelectorPrime: UInt32 {
        // 全部为接近 2^16 的质数，取模后分布均匀。
        let primePool: [UInt32] = [65_521, 65_519, 65_497, 65_479, 65_449, 65_447]
        let baseIndex = primePool.firstIndex(of: baseSplitSelectorPrime) ?? 0
        let offset = Int(derivedWord32(domain: 0x4346_4653_5052_494D, base: baseSplitSelectorPrime) % UInt32(primePool.count))
        return primePool[(baseIndex + offset) % primePool.count]
    }

    /// splitIndirect 盐异或值的基准。
    private var baseSplitSaltXor: UInt32 {
        switch self {
        case .legacy:
            return 0xDEAD_BEEF
        case .debugExtended:
            return 0xBADC_0FFE
        case .releaseBalanced:
            return 0xC001_D00D
        case .releasePointerTable:
            return 0xF00D_CAFE
        case .releaseSplitIndirect:
            return 0x0F10_55A1
        }
    }

    /// splitIndirect 判定时与盐异或的值。
    var splitSaltXor: UInt32 {
        derivedWord32(domain: 0x4346_4653_4C54_584F, base: baseSplitSaltXor)
    }

    /// residue 布局标签基准（0..3）。
    private var baseResidueLayoutTag: UInt8 {
        switch self {
        case .legacy:
            return 0
        case .debugExtended, .releasePointerTable:
            return 1
        case .releaseBalanced:
            return 2
        case .releaseSplitIndirect:
            return 3
        }
    }

    /// residue 布局标签，决定余数计算路径的细微差异。
    var residueLayoutTag: UInt8 {
        derivedTag(base: baseResidueLayoutTag, domain: 0x4346_4652_5344_5447)
    }

    /// 奇偶门控布局标签基准（0..3）。
    private var baseParityLayoutTag: UInt8 {
        switch self {
        case .legacy, .releaseSplitIndirect:
            return 1
        case .debugExtended:
            return 2
        case .releaseBalanced:
            return 3
        case .releasePointerTable:
            return 0
        }
    }

    /// 奇偶门控布局标签，决定 parityFence 的混合分支。
    var parityLayoutTag: UInt8 {
        derivedTag(base: baseParityLayoutTag, domain: 0x4346_4650_5254_5947)
    }

    /// 连接器布局标签基准（0..3）。
    private var baseConnectorLayoutTag: UInt8 {
        switch self {
        case .legacy:
            return 2
        case .debugExtended:
            return 0
        case .releaseBalanced:
            return 1
        case .releasePointerTable:
            return 3
        case .releaseSplitIndirect:
            return 2
        }
    }

    /// 连接器布局标签，决定 connectorGate 的折叠方式。
    var connectorLayoutTag: UInt8 {
        derivedTag(base: baseConnectorLayoutTag, domain: 0x4346_4643_4F4E_4E54)
    }

    /// 函数指针表基准序列（dispatcher 风格轮换）。
    private var baseFpTable: [CFFDispatcherStyle] {
        switch self {
        case .legacy:
            return [.switchLoop, .ifElseChain]
        case .debugExtended:
            return [.ifElseChain, .switchLoop, .ifElseChain, .switchLoop]
        case .releaseBalanced:
            return [.switchLoop, .ifElseChain, .switchLoop, .ifElseChain]
        case .releasePointerTable:
            return [.ifElseChain, .switchLoop, .switchLoop, .ifElseChain]
        case .releaseSplitIndirect:
            return [.switchLoop, .switchLoop, .ifElseChain, .ifElseChain]
        }
    }

    /// 实际函数指针表：在基准序列上做确定性旋转与首尾交换。
    var fpTable: [CFFDispatcherStyle] {
        var table = baseFpTable
        guard table.count > 1 else { return table }
        // 按派生值决定旋转量，使不同构建的表顺序不同。
        let rotation = Int(derivedWord32(domain: 0x4346_4646_5054_4142, base: UInt32(table.count)) % UInt32(table.count))
        if rotation > 0 {
            table = Array(table[rotation...] + table[..<rotation])
        }
        // 派生值最低位为 1 时交换首尾，进一步打散固定顺序。
        if (derivedWord32(domain: 0x4346_4646_5053_5750, base: UInt32(table.count)) & 1) == 1, table.count >= 2 {
            table.swapAt(0, table.count - 1)
        }
        return table
    }
}

/// 遇到非法状态时的处置策略。
enum CFFUnexpectedStatePolicy: String, Codable, Sendable {
    /// 继续执行（宽松）。
    case benign
    /// 失败即拒绝。
    case failClosed
    /// 投毒结果，禁止产生有效输出。
    case poison
    /// 调试构建下断言。
    case debugAssert
}

/// CFF 的完整配置。
/// 值类型且 `Sendable`，可在并发状态机之间安全复制。
struct CFFConfig: Sendable, Codable, Equatable {
    /// 函数级唯一种子，用于派生盐与常量。
    let functionSeed: UInt64
    /// 保护层级。
    let protectionTier: CFFProtectionTier
    /// dispatcher 风格。
    let dispatcherStyle: CFFDispatcherStyle
    /// 状态编码风格。
    let codecStyle: CFFStateCodecStyle
    /// 构建类型。
    let buildFlavor: CFFBuildFlavor
    /// 是否启用运行时盐。
    let enableRuntimeSalt: Bool
    /// 是否启用假状态。
    let enableFakeStates: Bool
    /// 假状态数量（会被归一化裁剪）。
    let fakeStateCount: Int
    /// 是否允许连接器状态（在两种 dispatcher 之间切换）。
    let allowConnectorStates: Bool
    /// 非法状态处置策略。
    let unexpectedStatePolicy: CFFUnexpectedStatePolicy

    /// 非法状态是否必须失败即拒绝（failClosed 或 poison）。
    var failClosedOnUnexpectedState: Bool {
        unexpectedStatePolicy == .failClosed || unexpectedStatePolicy == .poison
    }

    /// 归一化后的假状态数量：未启用时为 0，否则裁剪到 0...16。
    var normalizedFakeStateCount: Int {
        enableFakeStates ? max(0, min(fakeStateCount, 16)) : 0
    }

    /// 根据构建类型、dispatcher 风格与保护层级选择上下文混合方案。
    var contextBlend: CFFContextBlend {
        switch (buildFlavor, dispatcherStyle, protectionTier) {
        case (.debug, .functionPointerTable, _),
             (.debug, .splitIndirect, _),
             (.debug, _, .heavy),
             (.debug, _, .regionOnly):
            return .debugExtended
        case (.release, .functionPointerTable, .heavy):
            return .releasePointerTable
        case (.release, .splitIndirect, _):
            return .releaseSplitIndirect
        case (.release, _, .heavy),
             (.release, _, .regionOnly):
            return .releaseBalanced
        default:
            return .legacy
        }
    }

    /// 创建调试构建配置。
    /// - Parameters:
    ///   - functionSeed: 函数级种子。
    ///   - protectionTier: 保护层级，默认 `.light`。
    ///   - dispatcherStyle: dispatcher 风格，默认 `.switchLoop`。
    ///   - codecStyle: 编码风格，默认 `.xorRotate`。
    /// - Returns: 关闭 runtime salt 与假状态的调试配置。
    static func debug(
        functionSeed: UInt64,
        protectionTier: CFFProtectionTier = .light,
        dispatcherStyle: CFFDispatcherStyle = .switchLoop,
        codecStyle: CFFStateCodecStyle = .xorRotate
    ) -> CFFConfig {
        CFFConfig(
            functionSeed: functionSeed,
            protectionTier: protectionTier,
            dispatcherStyle: dispatcherStyle,
            codecStyle: codecStyle,
            buildFlavor: .debug,
            enableRuntimeSalt: false,
            enableFakeStates: false,
            fakeStateCount: 0,
            allowConnectorStates: protectionTier == .heavy || protectionTier == .regionOnly,
            unexpectedStatePolicy: .failClosed
        )
    }

    /// 创建发布构建配置。
    /// - Parameters:
    ///   - functionSeed: 函数级种子。
    ///   - protectionTier: 保护层级，默认 `.heavy`。
    ///   - dispatcherStyle: dispatcher 风格，默认 `.functionPointerTable`。
    ///   - codecStyle: 编码风格，默认 `.feistelSpn`。
    /// - Returns: 启用 runtime salt、按层级启用假状态与投毒策略的发布配置。
    static func release(
        functionSeed: UInt64,
        protectionTier: CFFProtectionTier = .heavy,
        dispatcherStyle: CFFDispatcherStyle = .functionPointerTable,
        codecStyle: CFFStateCodecStyle = .feistelSpn
    ) -> CFFConfig {
        CFFConfig(
            functionSeed: functionSeed,
            protectionTier: protectionTier,
            dispatcherStyle: dispatcherStyle,
            codecStyle: codecStyle,
            buildFlavor: .release,
            enableRuntimeSalt: true,
            // 只有重保护/区域保护才值得付出假状态的体积与开销。
            enableFakeStates: protectionTier == .heavy || protectionTier == .regionOnly,
            fakeStateCount: protectionTier == .heavy ? 2 : (protectionTier == .regionOnly ? 1 : 0),
            allowConnectorStates: protectionTier != .never,
            unexpectedStatePolicy: protectionTier == .heavy ? .poison : .failClosed
        )
    }

    /// 按编译条件自动选择 debug/release 配置。
    /// - Parameters:
    ///   - functionSeed: 函数级种子。
    ///   - protectionTier: 保护层级。
    ///   - dispatcherStyle: dispatcher 风格。
    ///   - codecStyle: 编码风格。
    /// - Returns: DEBUG 下等价于 `debug(...)`，否则等价于 `release(...)`。
    static func adaptive(
        functionSeed: UInt64,
        protectionTier: CFFProtectionTier,
        dispatcherStyle: CFFDispatcherStyle,
        codecStyle: CFFStateCodecStyle
    ) -> CFFConfig {
        #if DEBUG
        return .debug(
            functionSeed: functionSeed,
            protectionTier: protectionTier,
            dispatcherStyle: dispatcherStyle,
            codecStyle: codecStyle
        )
        #else
        return .release(
            functionSeed: functionSeed,
            protectionTier: protectionTier,
            dispatcherStyle: dispatcherStyle,
            codecStyle: codecStyle
        )
        #endif
    }
}
