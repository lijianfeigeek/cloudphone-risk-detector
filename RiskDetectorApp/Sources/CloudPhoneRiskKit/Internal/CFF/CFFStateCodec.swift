// CFF 状态编解码：把状态机原始状态编码为不可读的 32 位值，并提供严格互逆的解码。
// 位于 Internal/CFF 的核心密码学层，被平坦化状态机用于基本块间传递状态。
// 关键安全不变量：同一 (state, key, salt, style) 下 decode(encode(x)) 必须等于 x；盐/密钥不得退化为零。
import Foundation

/// 状态编码/解码工具集。
/// 线程模型：纯函数，无共享状态，可并发调用。
internal enum CFFStateCodec {
    /// 以 Feistel SPN 风格编码状态。
    /// - Parameters:
    ///   - state: 原始状态。
    ///   - seed: 编码密钥。
    ///   - salt: 运行时盐。
    /// - Returns: 编码后的 32 位状态。
    @inline(__always)
    static func encode(_ state: UInt32, seed: UInt32, salt: UInt32) -> UInt32 {
        encode(state: state, key: seed, salt: salt, style: .feistelSpn)
    }

    /// 以 Feistel SPN 风格解码状态。
    /// - Parameters:
    ///   - encoded: 编码后的状态。
    ///   - seed: 编码密钥。
    ///   - salt: 运行时盐。
    /// - Returns: 还原后的原始状态。
    @inline(__always)
    static func decode(_ encoded: UInt32, seed: UInt32, salt: UInt32) -> UInt32 {
        decode(state: encoded, key: seed, salt: salt, style: .feistelSpn)
    }

    /// 按指定风格编码状态。
    /// - Parameters:
    ///   - state: 原始状态。
    ///   - key: 函数级密钥。
    ///   - salt: 运行时盐。
    ///   - style: 编码风格，默认 `.feistelSpn`。
    /// - Returns: 编码结果；每种风格的 decode 均与其互逆。
    @inline(__always)
    static func encode(
        state: UInt32,
        key: UInt32,
        salt: UInt32,
        style: CFFStateCodecStyle = .feistelSpn
    ) -> UInt32 {
        switch style {
        case .feistelSpn:
            return feistel32EncodeCore(state: state, key: key, salt: salt)
        case .xorRotate:
            // 派生 32 位混合常量；shift 取 mix 低 5 位并强制为奇数（1..31），保证旋转可逆。
            let mix = avalanche32(key ^ salt ^ codecConst32(
                domain: 0x4346_465F_5354_5831,
                key: key,
                salt: salt,
                base: 0x9E37_79B9
            ))
            let shift = Int((mix & 0x1F) | 1)
            // 先异或状态/混合值/盐乘奇数常量，再循环左移，最后加 key 乘奇数常量。
            let masked = state ^ mix ^ (salt &* codecOddConst32(
                domain: 0x4346_465F_5354_5832,
                key: key,
                salt: salt,
                base: 0x045D_9F3B
            ))
            return masked.rotatedLeft(by: shift) &+ (key &* codecOddConst32(
                domain: 0x4346_465F_5354_5833,
                key: key,
                salt: salt,
                base: 0x27D4_EB2D
            ))
        case .addRotateXor:
            // addend 由 key+salt 派生；shift 由 key 高移与 salt 混合后强制为奇数。
            let addend = avalanche32(key &+ salt &+ codecConst32(
                domain: 0x4346_465F_5354_4131,
                key: key,
                salt: salt,
                base: 0x7F4A_7C15
            ))
            let shift = Int((((key &>> 3) ^ salt) & 0x1F) | 1)
            // 加法 → 循环左移 → 两次异或（key 派生值与盐乘常数）扩散。
            let mixed = (state &+ addend).rotatedLeft(by: shift)
            return mixed ^ avalanche32(key ^ codecConst32(
                domain: 0x4346_465F_5354_4132,
                key: key,
                salt: salt,
                base: 0xA24B_AED5
            )) ^ (salt &* codecOddConst32(
                domain: 0x4346_465F_5354_4133,
                key: key,
                salt: salt,
                base: 0x1656_67B1
            ))
        case .affine:
            // 仿射变换：先异或 mask，再乘奇数 multiplier，加 addend，最后异或 key 旋转值。
            let mask = avalanche32(key &+ salt &+ codecConst32(
                domain: 0x4346_465F_5354_4631,
                key: key,
                salt: salt,
                base: 0x51ED_270B
            ))
            // `| 1` 强制乘子为奇数，保证其在 2^32 下存在模逆。
            let multiplier = avalanche32(
                key ^ salt.rotatedLeft(by: 7) ^ codecConst32(
                    domain: 0x4346_465F_5354_4632,
                    key: key,
                    salt: salt,
                    base: 0xD1B5_4A35
                )
            ) | 1
            let addend = avalanche32(
                (key &* codecOddConst32(
                    domain: 0x4346_465F_5354_4633,
                    key: key,
                    salt: salt,
                    base: 0x9E37_79B1
                )) ^ salt ^ codecConst32(
                    domain: 0x4346_465F_5354_4634,
                    key: key,
                    salt: salt,
                    base: 0x94D0_49BB
                )
            )
            let masked = state ^ mask
            return (masked &* multiplier &+ addend) ^ key.rotatedLeft(by: Int((salt & 0x1F) | 1))
        }
    }

    /// 按指定风格解码状态（与 `encode` 严格互逆）。
    /// - Parameters:
    ///   - state: 编码后的状态。
    ///   - key: 函数级密钥。
    ///   - salt: 运行时盐。
    ///   - style: 编码风格，默认 `.feistelSpn`。
    /// - Returns: 原始状态。
    @inline(__always)
    static func decode(
        state: UInt32,
        key: UInt32,
        salt: UInt32,
        style: CFFStateCodecStyle = .feistelSpn
    ) -> UInt32 {
        switch style {
        case .feistelSpn:
            return feistel32DecodeCore(encodedState: state, key: key, salt: salt)
        case .xorRotate:
            // 重新派生与 encode 相同的常量，按相反顺序撤销：减 → 右移 → 异或。
            let mix = avalanche32(key ^ salt ^ codecConst32(
                domain: 0x4346_465F_5354_5831,
                key: key,
                salt: salt,
                base: 0x9E37_79B9
            ))
            let shift = Int((mix & 0x1F) | 1)
            let unshifted = (state &- (key &* codecOddConst32(
                domain: 0x4346_465F_5354_5833,
                key: key,
                salt: salt,
                base: 0x27D4_EB2D
            ))).rotatedRight(by: shift)
            return unshifted ^ mix ^ (salt &* codecOddConst32(
                domain: 0x4346_465F_5354_5832,
                key: key,
                salt: salt,
                base: 0x045D_9F3B
            ))
        case .addRotateXor:
            let addend = avalanche32(key &+ salt &+ codecConst32(
                domain: 0x4346_465F_5354_4131,
                key: key,
                salt: salt,
                base: 0x7F4A_7C15
            ))
            let shift = Int((((key &>> 3) ^ salt) & 0x1F) | 1)
            // 逆序：先异或，再循环右移，最后减 addend。
            let unmasked = state ^ avalanche32(key ^ codecConst32(
                domain: 0x4346_465F_5354_4132,
                key: key,
                salt: salt,
                base: 0xA24B_AED5
            )) ^ (salt &* codecOddConst32(
                domain: 0x4346_465F_5354_4133,
                key: key,
                salt: salt,
                base: 0x1656_67B1
            ))
            return unmasked.rotatedRight(by: shift) &- addend
        case .affine:
            let mask = avalanche32(key &+ salt &+ codecConst32(
                domain: 0x4346_465F_5354_4631,
                key: key,
                salt: salt,
                base: 0x51ED_270B
            ))
            let multiplier = avalanche32(
                key ^ salt.rotatedLeft(by: 7) ^ codecConst32(
                    domain: 0x4346_465F_5354_4632,
                    key: key,
                    salt: salt,
                    base: 0xD1B5_4A35
                )
            ) | 1
            // 计算奇数乘子的模逆，才能撤销乘法。
            let inverse = modularInverse32(multiplier)
            let addend = avalanche32(
                (key &* codecOddConst32(
                    domain: 0x4346_465F_5354_4633,
                    key: key,
                    salt: salt,
                    base: 0x9E37_79B1
                )) ^ salt ^ codecConst32(
                    domain: 0x4346_465F_5354_4634,
                    key: key,
                    salt: salt,
                    base: 0x94D0_49BB
                )
            )
            // 逆序：去 key 旋转异或 → 减 addend → 乘逆元 → 去 mask。
            let unxored = state ^ key.rotatedLeft(by: Int((salt & 0x1F) | 1))
            let unscaled = (unxored &- addend) &* inverse
            return unscaled ^ mask
        }
    }

    /// 派生函数级编码密钥。
    /// - Parameters:
    ///   - function: 函数名，参与哈希。
    ///   - namespace: 命名空间，默认 `CloudPhoneRiskKit`。
    ///   - config: CFF 配置（构建类型、函数种子、保护层级）。
    /// - Returns: 32 位密钥。
    @inline(__always)
    static func deriveSeed(
        function: String,
        namespace: String? = nil,
        config: CFFConfig
    ) -> UInt32 {
        // 构建类型用固定短串区分，避免 debug/release 密钥相同。
        let flavorSeed = stableHash64(config.buildFlavor == .release ? "rel" : "dbg")
        // 函数种子拆成高低 32 位，分别参与两个域常量派生。
        let functionLo = UInt32(truncatingIfNeeded: config.functionSeed)
        let functionHi = UInt32(truncatingIfNeeded: config.functionSeed >> 32)
        let flavorConstHi = UInt64(codecConst32(
            domain: 0x4346_465F_5354_4448,
            key: functionLo,
            salt: functionHi,
            base: 0x9E37_79B9
        ))
        let flavorConstLo = UInt64(codecConst32(
            domain: 0x4346_465F_5354_444C,
            key: functionLo,
            salt: functionHi,
            base: 0x7F4A_7C15
        ))
        let flavorMarkerConst = (flavorConstHi << 32) | flavorConstLo
        let flavorMarker = avalanche64(flavorSeed ^ config.functionSeed ^ flavorMarkerConst)
        let namespaceHash = stableHash64(namespace ?? "CloudPhoneRiskKit")
        let functionHash = stableHash64(function)
        // 保护层级 rawValue 用 FNV 风格滚动哈希折叠为一个 64 位值。
        let tierBits = config.protectionTier.rawValue.utf8.reduce(UInt64(0)) { partialResult, byte in
            (partialResult &* 16_777_619) ^ UInt64(byte)
        }
        // 所有输入异或/旋转后做 64 位雪崩，再折叠为 32 位。
        let mixed = functionHash ^ namespaceHash.rotatedLeft64(by: 11) ^ config.functionSeed ^ tierBits ^ flavorMarker
        return UInt32(truncatingIfNeeded: avalanche64(mixed) ^ mixed)
    }

    /// 生成一个编码后的假状态。
    /// - Parameters:
    ///   - ordinal: 假状态序号。
    ///   - key: 函数级密钥。
    ///   - salt: 运行时盐。
    ///   - config: CFF 配置。
    /// - Returns: 编码后的假状态；未启用假状态、非 release 或序号为负时返回 `nil`。
    @inline(__always)
    static func fakeState(
        ordinal: Int,
        key: UInt32,
        salt: UInt32,
        config: CFFConfig
    ) -> UInt32? {
        // 假状态只用于 release 噪声，调试构建直接禁用。
        guard config.enableFakeStates, config.buildFlavor == .release, ordinal >= 0 else {
            return nil
        }

        // `| 1` 确保 raw 非零，避免编码出退化的全零状态。
        let raw = avalanche32(UInt32(ordinal) &+ key &+ (salt &* codecOddConst32(
            domain: 0x4346_465F_4641_4B31,
            key: key,
            salt: salt,
            base: 0x9E37_79B1
        ))) | 1
        return encode(
            state: raw,
            key: key ^ codecConst32(
                domain: 0x4346_465F_4641_4B32,
                key: key,
                salt: salt,
                base: 0x6C8E_9CF5
            ),
            salt: salt,
            style: config.codecStyle
        )
    }

    /// 编码状态机入口状态。
    /// - Parameters:
    ///   - rawState: 入口原始状态。
    ///   - function: 函数名（用于派生密钥）。
    ///   - salt: 运行时盐。
    ///   - config: CFF 配置。
    /// - Returns: 编码后的入口状态。
    @inline(__always)
    static func encodedEntryState(
        rawState: UInt32,
        function: String,
        salt: UInt32,
        config: CFFConfig
    ) -> UInt32 {
        let key = deriveSeed(function: function, config: config)
        let fallbackSaltXor = codecConst32(
            domain: 0x4346_465F_454E_5331,
            key: key,
            salt: salt,
            base: 0x1357_9BDF
        )
        // 未启用 runtime salt 时，用派生常量扰动盐，避免盐退化为可预测的固定值。
        let effectiveSalt = config.enableRuntimeSalt ? salt : salt ^ fallbackSaltXor
        return encode(state: rawState, key: key, salt: effectiveSalt, style: config.codecStyle)
    }

    /// 解码状态机入口状态（与 `encodedEntryState` 对应）。
    /// - Parameters:
    ///   - encodedState: 编码后的状态。
    ///   - function: 函数名（用于派生密钥）。
    ///   - salt: 运行时盐。
    ///   - config: CFF 配置。
    /// - Returns: 原始状态。
    @inline(__always)
    static func decodedState(
        encodedState: UInt32,
        function: String,
        salt: UInt32,
        config: CFFConfig
    ) -> UInt32 {
        let key = deriveSeed(function: function, config: config)
        let fallbackSaltXor = codecConst32(
            domain: 0x4346_465F_4445_5331,
            key: key,
            salt: salt,
            base: 0x1357_9BDF
        )
        // 与 encodedEntryState 使用同一 effectiveSalt 规则，保证互逆。
        let effectiveSalt = config.enableRuntimeSalt ? salt : salt ^ fallbackSaltXor
        return decode(state: encodedState, key: key, salt: effectiveSalt, style: config.codecStyle)
    }

    /// 32 位雪崩混合（xor-shift + 奇数乘法）。
    /// - Parameter value: 输入值。
    /// - Returns: 扩散后的值。
    @inline(__always)
    private static func avalanche32(_ value: UInt32) -> UInt32 {
        var mixed = value
        mixed ^= mixed >> 16
        mixed &*= 0x7FEB352D
        mixed ^= mixed >> 15
        mixed &*= 0x846CA68B
        mixed ^= mixed >> 16
        return mixed
    }

    /// 64 位雪崩混合（MurmurHash3 finalizer 风格）。
    /// - Parameter value: 输入值。
    /// - Returns: 扩散后的值。
    @inline(__always)
    private static func avalanche64(_ value: UInt64) -> UInt64 {
        var mixed = value
        mixed ^= mixed >> 33
        mixed &*= 0xFF51AFD7ED558CCD
        mixed ^= mixed >> 33
        mixed &*= 0xC4CEB9FE1A85EC53
        mixed ^= mixed >> 33
        return mixed
    }

    /// FNV-1a 64 位稳定字符串哈希。
    /// - Parameter string: 输入字符串。
    /// - Returns: 64 位哈希值。
    private static func stableHash64(_ string: String) -> UInt64 {
        var hash: UInt64 = 0xCBF29CE484222325
        for byte in string.utf8 {
            hash ^= UInt64(byte)
            hash &*= 0x100000001B3
        }
        return hash
    }

    /// 计算奇数在模 2^32 下的乘法逆元（牛顿迭代，5 轮足够 32 位收敛）。
    /// - Parameter oddValue: 必须为奇数。
    /// - Returns: 满足 `oddValue * result == 1 (mod 2^32)` 的逆元。
    @inline(__always)
    private static func modularInverse32(_ oddValue: UInt32) -> UInt32 {
        var inverse = oddValue
        // 每轮把正确位数翻倍：1→2→4→8→16→32 位。
        inverse &*= (UInt32(2) &- (oddValue &* inverse))
        inverse &*= (UInt32(2) &- (oddValue &* inverse))
        inverse &*= (UInt32(2) &- (oddValue &* inverse))
        inverse &*= (UInt32(2) &- (oddValue &* inverse))
        inverse &*= (UInt32(2) &- (oddValue &* inverse))
        return inverse
    }

    /// 派生用于编码的 32 位常量。
    /// - Parameters:
    ///   - domain: 用途域常量（高低 32 位分别参与混合）。
    ///   - key: 函数级密钥。
    ///   - salt: 运行时盐。
    ///   - base: 基准常量。
    /// - Returns: 与 base 异或后的派生常量。
    @inline(__always)
    private static func codecConst32(domain: UInt64, key: UInt32, salt: UInt32, base: UInt32) -> UInt32 {
        let lo = UInt32(truncatingIfNeeded: domain)
        let hi = UInt32(truncatingIfNeeded: domain >> 32)
        // 旋转量由 key/hi/salt 混合得到，强制为奇数（1..31），保证旋转可逆。
        let spin = Int(((key ^ hi ^ (salt >> 1)) & 31) | 1)
        let lane = (key ^ base ^ lo).rotatedLeft(by: spin)
        let mixed0 = avalanche32(key ^ salt ^ lo ^ base)
        let mixed1 = avalanche32(lane ^ salt ^ hi ^ (base &* (key | 1)))
        return avalanche32(mixed0 ^ mixed1 ^ lo ^ hi) ^ base
    }

    /// 派生奇数常量（`| 1` 保证可用于可逆乘法）。
    /// - Parameters:
    ///   - domain: 用途域常量。
    ///   - key: 函数级密钥。
    ///   - salt: 运行时盐。
    ///   - base: 基准常量。
    /// - Returns: 奇数派生常量。
    @inline(__always)
    private static func codecOddConst32(domain: UInt64, key: UInt32, salt: UInt32, base: UInt32) -> UInt32 {
        codecConst32(domain: domain, key: key, salt: salt, base: base) | 1
    }

    /// 查询运行时 S-box 替换字节。
    /// - Parameter idx: 输入字节。
    /// - Returns: 替换后的字节。
    @inline(__always)
    private static func spnSboxByte(_ idx: UInt8) -> UInt8 {
        CFFSBoxRuntime.spnSboxByte(idx)
    }

    /// Feistel 轮数。8 轮兼顾安全性与状态机内联后的代码体积。
    private static let feistelRounds: UInt32 = 8

    /// 把 64 位运行时种子折叠为 32 位构建种子。
    /// - Returns: 32 位构建种子。
    @inline(__always)
    private static func buildSeed32() -> UInt32 {
        let buildSeed = CFFSBoxRuntime.runtimeSeed()
        let lo = UInt32(truncatingIfNeeded: buildSeed)
        let hi = UInt32(truncatingIfNeeded: buildSeed >> 32)
        return avalanche32(lo ^ hi)
    }

    /// 派生轮函数使用的 32 位标签。
    /// - Parameters:
    ///   - key: 函数级密钥。
    ///   - salt: 运行时盐。
    ///   - chainMix: 链式混合值。
    ///   - lane: 用途 lane。
    /// - Returns: 32 位标签。
    @inline(__always)
    private static func deriveTag32(
        key: UInt32,
        salt: UInt32,
        chainMix: UInt32,
        lane: UInt32
    ) -> UInt32 {
        let buildSeed = CFFSBoxRuntime.runtimeSeed()
        let lo = UInt32(truncatingIfNeeded: buildSeed)
        let hi = UInt32(truncatingIfNeeded: buildSeed >> 32)
        let buildSeed32 = avalanche32(lo ^ hi)
        let buildFold = lo ^ hi
        // lane 限制在 0..15 后 +1，得到 1..16 的旋转量，保证非零。
        let rotated = (chainMix ^ buildSeed32).rotatedLeft(by: Int((lane & 15) + 1))
        let laneMul = codecOddConst32(
            domain: 0x4346_465F_5441_4731,
            key: key ^ lane,
            salt: salt ^ chainMix,
            base: 0x9E37_79B1
        )
        return avalanche32(buildSeed32 ^ buildFold ^ key ^ salt ^ rotated ^ (lane &* laneMul))
    }

    /// 计算 key/salt 的链式混合值。
    /// - Parameters:
    ///   - key: 函数级密钥。
    ///   - salt: 运行时盐。
    /// - Returns: 链式混合值。
    @inline(__always)
    private static func codecChainMix(key: UInt32, salt: UInt32) -> UInt32 {
        avalanche32(key ^ salt.rotatedLeft(by: 7) ^ buildSeed32())
    }

    /// 派生指定 lane 的 32 位标签。
    /// - Parameters:
    ///   - key: 函数级密钥。
    ///   - salt: 运行时盐。
    ///   - lane: 用途 lane。
    /// - Returns: 32 位标签。
    @inline(__always)
    private static func codecTag32(key: UInt32, salt: UInt32, lane: UInt32) -> UInt32 {
        deriveTag32(key: key, salt: salt, chainMix: codecChainMix(key: key, salt: salt), lane: lane)
    }

    /// Feistel 轮函数 F：双层 SPN（S-box 替换 + 轮密钥混合 + 雪崩）。
    /// - Parameters:
    ///   - r: 16 位输入半块。
    ///   - key: 函数级密钥。
    ///   - salt: 运行时盐。
    ///   - round: 轮序号。
    /// - Returns: 16 位输出半块。
    @inline(__always)
    private static func feistelRoundF(_ r: UInt16, key: UInt32, salt: UInt32, round: UInt32) -> UInt16 {
        // 每轮使用不同的奇数乘子，令轮密钥随轮次变化。
        let roundMul = codecOddConst32(
            domain: 0x4346_465F_4653_5231,
            key: key,
            salt: salt,
            base: 0x9E37_79B9
        )
        let roundKey = avalanche32(key ^ salt ^ (round &* roundMul) ^ codecTag32(key: key, salt: salt, lane: 1))
        let b0 = UInt8(truncatingIfNeeded: r)
        let b1 = UInt8(truncatingIfNeeded: r >> 8)
        // 第一层：S-box 替换并与轮密钥低字节混合。
        let s0 = UInt32(spnSboxByte(b0 ^ UInt8(truncatingIfNeeded: roundKey)))
        let s1 = UInt32(spnSboxByte(b1 ^ UInt8(truncatingIfNeeded: roundKey >> 8))) << 8
        var piece = s0 ^ s1
        piece ^= roundKey ^ (roundKey >> 16)
        piece = avalanche32(piece)
        // 第二层：使用高半字节轮密钥再做一次 S-box（双 SPN 结构）。
        let s2_0 = UInt32(spnSboxByte(UInt8(truncatingIfNeeded: piece) ^ UInt8(truncatingIfNeeded: roundKey >> 16)))
        let s2_1 = UInt32(spnSboxByte(UInt8(truncatingIfNeeded: piece >> 8) ^ UInt8(truncatingIfNeeded: roundKey >> 24))) << 8
        var piece2 = s2_0 ^ s2_1
        piece2 ^= (roundKey >> 8) ^ (roundKey >> 24)
        piece2 = avalanche32(piece2)
        // 两层输出合并后折叠为 16 位。
        piece ^= piece2
        return UInt16(truncatingIfNeeded: piece ^ (piece >> 16))
    }

    /// Feistel 32 位编码核心（8 轮 + 前后白化）。
    /// - Parameters:
    ///   - state: 原始状态。
    ///   - key: 函数级密钥。
    ///   - salt: 运行时盐。
    /// - Returns: 编码后的状态。
    @inline(__always)
    private static func feistel32EncodeCore(state: UInt32, key: UInt32, salt: UInt32) -> UInt32 {
        // 前后白化使用不同 lane，防止轮输入/输出暴露固定关系。
        let prewhiten = avalanche32(key ^ salt ^ codecTag32(key: key, salt: salt, lane: 2))
        let postwhiten = avalanche32(key ^ salt ^ codecTag32(key: key, salt: salt, lane: 3))
        var value = state ^ prewhiten
        var left = UInt16(truncatingIfNeeded: value >> 16)
        var right = UInt16(truncatingIfNeeded: value)
        // 标准 Feistel：每轮的左半来自右半，右半由 F 函数更新。
        for round in 0..<feistelRounds {
            let nextLeft = right
            let nextRight = left ^ feistelRoundF(right, key: key, salt: salt, round: round)
            left = nextLeft
            right = nextRight
        }
        value = (UInt32(left) << 16) | UInt32(right)
        return value ^ postwhiten
    }

    /// Feistel 32 位解码核心（逆序 8 轮 + 逆白化）。
    /// - Parameters:
    ///   - encodedState: 编码后的状态。
    ///   - key: 函数级密钥。
    ///   - salt: 运行时盐。
    /// - Returns: 原始状态。
    @inline(__always)
    private static func feistel32DecodeCore(encodedState: UInt32, key: UInt32, salt: UInt32) -> UInt32 {
        let prewhiten = avalanche32(key ^ salt ^ codecTag32(key: key, salt: salt, lane: 2))
        let postwhiten = avalanche32(key ^ salt ^ codecTag32(key: key, salt: salt, lane: 3))
        // 先撤销后白化，再从最后一轮逆序恢复。
        var value = encodedState ^ postwhiten
        var left = UInt16(truncatingIfNeeded: value >> 16)
        var right = UInt16(truncatingIfNeeded: value)
        var round = feistelRounds
        while round > 0 {
            round &-= 1
            let prevRight = left
            let prevLeft = right ^ feistelRoundF(left, key: key, salt: salt, round: round)
            left = prevLeft
            right = prevRight
        }
        value = (UInt32(left) << 16) | UInt32(right)
        return value ^ prewhiten
    }
}

/// 32 位循环移位辅助。
private extension UInt32 {
    /// 循环左移；移位数先对 32 取模，0 位移直接返回自身。
    /// - Parameter shift: 原始移位量。
    /// - Returns: 循环左移结果。
    @inline(__always)
    func rotatedLeft(by shift: Int) -> UInt32 {
        let amount = shift & 31
        guard amount != 0 else { return self }
        return (self << amount) | (self >> (32 - amount))
    }

    /// 循环右移；移位数先对 32 取模，0 位移直接返回自身。
    /// - Parameter shift: 原始移位量。
    /// - Returns: 循环右移结果。
    @inline(__always)
    func rotatedRight(by shift: Int) -> UInt32 {
        let amount = shift & 31
        guard amount != 0 else { return self }
        return (self >> amount) | (self << (32 - amount))
    }
}

/// 64 位循环移位辅助。
private extension UInt64 {
    /// 循环左移；移位数先对 64 取模，0 位移直接返回自身。
    /// - Parameter shift: 原始移位量。
    /// - Returns: 循环左移结果。
    @inline(__always)
    func rotatedLeft64(by shift: Int) -> UInt64 {
        let amount = shift & 63
        guard amount != 0 else { return self }
        return (self << amount) | (self >> (64 - amount))
    }
}
