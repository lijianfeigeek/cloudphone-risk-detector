// CFF 不透明谓词：基于 SPN 混合、质数余数与“幽灵通道”构造难以静态求值的分支条件。
// 位于 Internal/CFF 的分发辅助层，被 CFFDispatcher 用于分支键、奇偶门控与连接器门控。
// 关键安全不变量：语义通道必须确定性可复现；幽灵通道贡献必须恒为零，只增加分析噪声。
import Foundation

/// 不透明谓词工具集。
/// 线程模型：纯函数，可并发调用。
internal enum CFFOpaquePredicates {
    // MARK: - SPN 字节替换（通过 CFFSBoxRuntime 使用 per-build 置换）

    /// 查询运行时 S-box 单字节替换。
    /// - Parameter idx: 输入字节。
    /// - Returns: 替换后的字节。
    @inline(__always)
    private static func spnSboxByte(_ idx: UInt8) -> UInt8 {
        CFFSBoxRuntime.spnSboxByte(idx)
    }
    // 余数计算使用的质数池（均接近 2^16），用于降低取模偏差并提供不同分支形态。
    private static let residuePrimes: [UInt32] = [65_521, 65_519, 65_497, 65_479, 65_449, 65_447]

    /// 对 32 位字逐字节做 S-box 替换（SubWord），保持 4 字节布局。
    /// - Parameter x: 输入字。
    /// - Returns: 替换后的字。
    @inline(__always)
    private static func subWord32(_ x: UInt32) -> UInt32 {
        // 每个字节独立替换后按原字节位置拼回。
        let b0 = UInt32(spnSboxByte(UInt8(truncatingIfNeeded: x)))
        let b1 = UInt32(spnSboxByte(UInt8(truncatingIfNeeded: x &>> 8))) &<< 8
        let b2 = UInt32(spnSboxByte(UInt8(truncatingIfNeeded: x &>> 16))) &<< 16
        let b3 = UInt32(spnSboxByte(UInt8(truncatingIfNeeded: x &>> 24))) &<< 24
        return b0 | b1 | b2 | b3
    }

    /// 32 位字节序翻转。
    /// - Parameter x: 输入字。
    /// - Returns: 字节顺序反转后的字。
    @inline(__always)
    private static func byteSwap32(_ x: UInt32) -> UInt32 {
        // 逐字节移位到对称位置，形成镜像输入。
        ((x & 0x0000_00ff) &<< 24)
            | ((x & 0x0000_ff00) &<< 8)
            | ((x & 0x00ff_0000) &>> 8)
            | ((x & 0xff00_0000) &>> 24)
    }

    /// 根据 blend 的三个布局标签选择余数质数。
    /// - Parameter blend: 上下文混合方案。
    /// - Returns: 质数池中的一个质数。
    @inline(__always)
    private static func residuePrime(for blend: CFFContextBlend) -> UInt32 {
        // 三个 0..3 标签移位组合成 6 bit 选择子，再映射到质数池。
        let selector = UInt32(blend.residueLayoutTag)
            ^ (UInt32(blend.parityLayoutTag) &<< 1)
            ^ (UInt32(blend.connectorLayoutTag) &<< 2)
        return residuePrimes[Int(selector % UInt32(residuePrimes.count))]
    }

    /// 派生 blend 相关的 32 位常量。
    /// - Parameters:
    ///   - domain: 用途域常量。
    ///   - salt: 运行时盐。
    ///   - blend: 上下文混合方案。
    ///   - base: 基准常量。
    /// - Returns: 与基准异或后的派生值。
    @inline(__always)
    private static func derivedBlendConst32(
        domain: UInt64,
        salt: UInt32,
        blend: CFFContextBlend,
        base: UInt32
    ) -> UInt32 {
        let seed = blend.dispatchXor32 ^ blend.splitSelectorPrime
        // 把三个布局标签打包进低 24 位，作为 contextWord 的一部分。
        let layoutWord = UInt32(blend.residueLayoutTag)
            | (UInt32(blend.parityLayoutTag) &<< 8)
            | (UInt32(blend.connectorLayoutTag) &<< 16)
        let runtimeSalt = salt ^ blend.splitSaltXor ^ layoutWord
        let contextWord = (UInt64(seed) &<< 32) ^ UInt64(layoutWord ^ base)
        let derived = CFFSBoxRuntime.derivedWord32(
            domain: domain ^ UInt64(base),
            runtimeSalt: runtimeSalt,
            contextWord: contextWord
        )
        return derived ^ base
    }

    /// 派生 blend 相关的奇数常量（`| 1` 保证可逆/不退化）。
    /// - Parameters:
    ///   - domain: 用途域常量。
    ///   - salt: 运行时盐。
    ///   - blend: 上下文混合方案。
    ///   - base: 基准常量。
    /// - Returns: 奇数派生值。
    @inline(__always)
    private static func derivedBlendOddConst32(
        domain: UInt64,
        salt: UInt32,
        blend: CFFContextBlend,
        base: UInt32
    ) -> UInt32 {
        derivedBlendConst32(domain: domain, salt: salt, blend: blend, base: base) | 1
    }

    /// 单轮 SPN：SubWord → 与轮密钥异或 → 循环移位（扩散/雪崩）。
    /// - Parameters:
    ///   - x: 输入字。
    ///   - roundKey: 轮密钥。
    ///   - rot: 循环左移位数（取值 1..31）。
    /// - Returns: 单轮输出。
    @inline(__always)
    private static func spnRound(_ x: UInt32, roundKey: UInt32, rot: UInt32) -> UInt32 {
        let y = subWord32(x) ^ roundKey
        return (y &<< rot) | (y &>> (32 &- rot))
    }

    /// 根据 blend 布局标签派生四轮不同的移位数。
    /// - Parameter blend: 上下文混合方案。
    /// - Returns: 四个循环移位量。
    @inline(__always)
    private static func spnRotations(for blend: CFFContextBlend) -> (UInt32, UInt32, UInt32, UInt32) {
        let r0 = 5 &+ UInt32(blend.residueLayoutTag)
        let r1 = 9 &+ UInt32(blend.parityLayoutTag)
        let r2 = 13 &+ UInt32(blend.connectorLayoutTag)
        let r3 = 17 &+ UInt32((blend.residueLayoutTag ^ blend.parityLayoutTag ^ blend.connectorLayoutTag) & 3)
        return (r0, r1, r2, r3)
    }

    /// 多轮 SPN 混合（替换 + 通过旋转/轮密钥异或实现 P 层扩散）。
    /// - Parameters:
    ///   - value: 输入值。
    ///   - salt: 运行时盐。
    ///   - blend: 上下文混合方案，默认 `.legacy`。
    /// - Returns: 四轮混合后的 32 位值。
    @inline(__always)
    private static func spnMix32(_ value: UInt32, salt: UInt32, blend: CFFContextBlend = .legacy) -> UInt32 {
        // 四个轮密钥由不同域常量派生，分别采用乘/异或两种混合方式。
        let rk0Mul = derivedBlendOddConst32(
            domain: 0x4346_465F_5350_4E30,
            salt: salt,
            blend: blend,
            base: 0x9E37_79B1
        )
        let rk1Xor = derivedBlendConst32(
            domain: 0x4346_465F_5350_4E31,
            salt: salt,
            blend: blend,
            base: 0x1357_9BDF
        )
        let rk2Mul = derivedBlendOddConst32(
            domain: 0x4346_465F_5350_4E32,
            salt: salt,
            blend: blend,
            base: 0x27D4_EB2D
        )
        let rk3Xor = derivedBlendConst32(
            domain: 0x4346_465F_5350_4E33,
            salt: salt,
            blend: blend,
            base: 0x517C_C1B7
        )
        let rk0 = salt &* rk0Mul
        let rk1 = salt ^ rk1Xor
        let rk2 = salt &* rk2Mul
        let rk3 = rk0 ^ rk2 ^ rk3Xor
        let (r0, r1, r2, r3) = spnRotations(for: blend)

        var x = value ^ salt
        x = spnRound(x, roundKey: rk0, rot: r0)
        x = spnRound(x, roundKey: rk1, rot: r1)
        x = spnRound(x, roundKey: rk2, rot: r2)
        x = spnRound(x, roundKey: rk3, rot: r3)
        return x
    }

    /// 语义余数：把 SPN 雪崩结果折叠进质数域（取代旧的 FNV 链）。
    /// - Parameters:
    ///   - value: 输入值。
    ///   - salt: 运行时盐。
    ///   - blend: 上下文混合方案，默认 `.legacy`。
    /// - Returns: `[0, prime)` 内的余数。
    @inline(__always)
    private static func spnPrimeResidue32(_ value: UInt32, salt: UInt32, blend: CFFContextBlend = .legacy) -> UInt32 {
        let prime = residuePrime(for: blend)
        // 布局标签先混入输入与盐，确保不同 blend 的余数路径不同。
        let mixed = spnMix32(
            value ^ (UInt32(blend.connectorLayoutTag) &<< 24),
            salt: salt ^ UInt32(blend.parityLayoutTag),
            blend: blend
        )
        return mixed % prime
    }

    /// 幽灵通道：使用另一套轮密钥/旋转表计算，并与语义核心按位与为零。
    /// - Parameters:
    ///   - value: 输入值。
    ///   - salt: 运行时盐。
    ///   - ghostTag: 幽灵标签，扰动轮密钥。
    ///   - blend: 上下文混合方案，默认 `.legacy`。
    /// - Returns: 幽灵通道余数（仅用于噪声，最终会被掩零）。
    @inline(__always)
    private static func ghostSpnLane(_ value: UInt32, salt: UInt32, ghostTag: UInt8, blend: CFFContextBlend = .legacy) -> UInt32 {
        let gSaltMul = derivedBlendOddConst32(
            domain: 0x4346_465F_4748_5330,
            salt: salt,
            blend: blend,
            base: 0x1111_1111
        )
        let rk0Mul = derivedBlendOddConst32(
            domain: 0x4346_465F_4748_5331,
            salt: salt ^ UInt32(ghostTag),
            blend: blend,
            base: 0xA5A5_A5A5
        )
        let rk1Xor = derivedBlendConst32(
            domain: 0x4346_465F_4748_5332,
            salt: salt,
            blend: blend,
            base: 0xA24B_AED5
        )
        let gSalt = salt ^ (UInt32(ghostTag) &* gSaltMul)
        let rk0 = gSalt &+ (UInt32(ghostTag) &* rk0Mul)
        let rk1 = gSalt ^ (~UInt32(ghostTag) &<< 5) ^ rk1Xor
        let (r0, _, r2, r3) = spnRotations(for: blend)
        var x = value ^ gSalt ^ (UInt32(ghostTag) &<< 24)
        x = spnRound(x, roundKey: rk0, rot: r0)
        // 幽灵通道刻意使用不同的旋转增量（+4），与语义通道错开。
        x = spnRound(x, roundKey: rk1, rot: r2 &+ 4)
        x = spnRound(x, roundKey: rk0 ^ rk1, rot: r3 &+ 4)
        return x % residuePrime(for: blend)
    }

    /// 恒为零的不透明表达式：`(a ^ a)` 恒 0，`(b | ~b)` 恒全 1。
    /// - Parameters:
    ///   - a: 任意值。
    ///   - b: 任意值。
    /// - Returns: 恒为 0。
    @inline(__always)
    private static func opaqueZero32(_ a: UInt32, _ b: UInt32) -> UInt32 {
        (a ^ a) & (b | ~b)
    }

    /// 兼容旧命名的入口——语义通道现在使用 SPN + 质数取模（不再是 FNV）。
    /// - Parameters:
    ///   - value: 输入值。
    ///   - salt: 运行时盐。
    /// - Returns: 质数域余数。
    @inline(__always)
    static func fnvPrimeResidue32(_ value: UInt32, salt: UInt32) -> UInt32 {
        spnPrimeResidue32(value, salt: salt, blend: .legacy)
    }

    /// 奇偶门控：混合语义余数、幽灵通道与镜像余数，再与输入最低位比较。
    /// - Parameters:
    ///   - value: 输入值。
    ///   - salt: 运行时盐。
    ///   - blend: 上下文混合方案，默认 `.legacy`。
    /// - Returns: 门控结果（布尔）。
    @inline(__always)
    static func parityFence(_ value: UInt32, salt: UInt32, blend: CFFContextBlend = .legacy) -> Bool {
        // z 恒为 0，用于把幽灵通道掩成零贡献。
        let z = opaqueZero32(value, salt)
        let rCore: UInt32 = spnPrimeResidue32(value, salt: salt, blend: blend)
        let ghostLane: UInt32 = ghostSpnLane(value, salt: salt, ghostTag: blend.residueLayoutTag, blend: blend)
        let ghost: UInt32 = ghostLane & z
        // 镜像输入：字节序翻转 + SubWord（对 salt ^ dispatchXor）再求余数。
        let mirrorSeed = byteSwap32(value) ^ subWord32(salt ^ blend.dispatchXor32)
        let mirrorResidue: UInt32 = spnPrimeResidue32(mirrorSeed, salt: salt ^ blend.splitSaltXor, blend: blend)
        // `| 1` 确保掩码非零，避免镜像通道被整体抹掉。
        let mirrorMask = mirrorResidue & UInt32(blend.switchConnectorSelector | 1)
        let r: UInt32 = rCore ^ ghost ^ mirrorMask
        // 多路奇数乘法混合，增强雪崩。
        let mixA = value &* derivedBlendOddConst32(
            domain: 0x4346_465F_5052_5441,
            salt: salt,
            blend: blend,
            base: 0x045D_9F3B
        )
        let mixB = salt &* derivedBlendOddConst32(
            domain: 0x4346_465F_5052_5442,
            salt: salt,
            blend: blend,
            base: 0x119D_E1F3
        )
        let mixC = r &* derivedBlendOddConst32(
            domain: 0x4346_465F_5052_5443,
            salt: salt,
            blend: blend,
            base: 0x9E37_79B1
        )
        let mixD = mirrorResidue &* (blend.dispatchXor32 | 1)
        let mixed0: UInt32 = mixA ^ mixB ^ mixC ^ mixD
        // z0/z1 仍恒为 0，其乘法项只增加数据流噪声。
        let z0 = opaqueZero32(value, salt)
        let z1 = opaqueZero32(salt, value)
        let mixed1 = mixed0 ^ (z0 &* derivedBlendOddConst32(
            domain: 0x4346_465F_5052_5444,
            salt: salt,
            blend: blend,
            base: 0x517C_C1B7
        ))
        let mixed2 = mixed1 ^ (z1 &* derivedBlendOddConst32(
            domain: 0x4346_465F_5052_5445,
            salt: salt,
            blend: blend,
            base: 0x1656_67B1
        ))
        // 按布局标签选择不同的末位折叠方式；所有分支都只影响最低位。
        let mixed: UInt32
        switch blend.parityLayoutTag {
        case 0:
            mixed = mixed2
        case 1:
            mixed = mixed2 ^ (z0 >> 1)
        case 2:
            mixed = mixed2 ^ (z1 << 1)
        default:
            mixed = mixed2 ^ (z0 | z1)
        }
        return ((mixed ^ (mixed >> 16)) & 1) == (value & 1)
    }

    /// 连接器门控：用 S-box 字节雪崩取代对 XOR 的原始 popcount（分支形态由 blend 驱动）。
    /// - Parameters:
    ///   - encodedState: 编码状态。
    ///   - salt: 运行时盐。
    ///   - blend: 上下文混合方案，默认 `.legacy`。
    /// - Returns: 门控结果（布尔）。
    @inline(__always)
    static func connectorGate(encodedState: UInt32, salt: UInt32, blend: CFFContextBlend = .legacy) -> Bool {
        let diff = encodedState ^ salt
        let h = spnMix32(
            diff ^ blend.dispatchXor32,
            salt: (salt &+ derivedBlendConst32(
                domain: 0x4346_465F_4347_5431,
                salt: salt,
                blend: blend,
                base: 0xDEAD_BEEF
            )) ^ blend.splitSaltXor,
            blend: blend
        )
        // 取混合结果的四个字节分别过 S-box，再折叠成单字节。
        let b0 = spnSboxByte(UInt8(truncatingIfNeeded: h))
        let b1 = spnSboxByte(UInt8(truncatingIfNeeded: h >> 8))
        let b2 = spnSboxByte(UInt8(truncatingIfNeeded: h >> 16))
        let b3 = spnSboxByte(UInt8(truncatingIfNeeded: h >> 24))
        let mirror = byteSwap32(h ^ blend.dispatchXor32)
        let folded = Int(b0 ^ b1 ^ b2 ^ b3 ^ UInt8(truncatingIfNeeded: mirror))
        // z 恒为 0，作为额外的数据流噪声参与部分分支。
        let z = opaqueZero32(encodedState, salt)
        let t = Int(z & 0xFF)
        // 不同连接器布局使用不同的末位比较方式。
        switch blend.connectorLayoutTag {
        case 0:
            return (folded & 1) == Int((salt >> 3) & 1)
        case 1:
            return ((folded ^ t) & 1) == Int((salt >> 3) & 1)
        case 2:
            return ((folded & 1) ^ (t & 1)) == Int((salt >> 3) & 1)
        default:
            return (folded & 1) == Int(((salt ^ UInt32(t)) >> 3) & 1)
        }
    }

    /// 掩码比较：两侧同时异或同一个非零掩码后再比较，避免直接比较留下明显特征。
    /// - Parameters:
    ///   - lhs: 左值。
    ///   - rhs: 右值。
    ///   - salt: 运行时盐。
    /// - Returns: 忽略掩码后是否相等。
    @inline(__always)
    static func maskedEquals(_ lhs: UInt32, _ rhs: UInt32, salt: UInt32) -> Bool {
        // `(salt | 1)` 保证掩码非零；再乘奇数常量打散。
        let mask = (salt | 1) &* derivedBlendOddConst32(
            domain: 0x4346_465F_4D45_5131,
            salt: salt,
            blend: .legacy,
            base: 0x9E37_79B1
        )
        return (lhs ^ mask) == (rhs ^ mask)
    }

    /// 有界选择器：把任意值确定性地映射到 `[0, modulo)`，用于表索引与分支键。
    /// - Parameters:
    ///   - value: 输入值。
    ///   - salt: 运行时盐。
    ///   - modulo: 上界，内部兜底为至少 1。
    ///   - blend: 上下文混合方案，默认 `.legacy`。
    /// - Returns: `[0, modulo)` 内的选择结果。
    @inline(__always)
    static func boundedSelector(_ value: UInt32, salt: UInt32, modulo: UInt32, blend: CFFContextBlend = .legacy) -> UInt32 {
        let boundedModulo = max(1, modulo)
        let z = opaqueZero32(value, salt)
        let rCore: UInt32 = spnPrimeResidue32(value, salt: salt, blend: blend)
        let ghostLane: UInt32 = ghostSpnLane(value, salt: salt, ghostTag: blend.residueLayoutTag, blend: blend)
        // 幽灵通道被 z 掩零，不改变语义选择结果。
        let ghost: UInt32 = ghostLane & z
        let mirrorResidue: UInt32 = spnPrimeResidue32(byteSwap32(value), salt: salt ^ blend.dispatchXor32, blend: blend)
        let r: UInt32 = rCore ^ ghost
        let folded = value &+ (salt &* derivedBlendOddConst32(
            domain: 0x4346_465F_424E_4431,
            salt: salt,
            blend: blend,
            base: 0x27D4_EB2D
        ))
        let mixed0: UInt32 = r ^ mirrorResidue ^ folded ^ derivedBlendConst32(
            domain: 0x4346_465F_424E_4432,
            salt: salt,
            blend: blend,
            base: 0x7F4A_7C15
        )
        // 不同 residue 布局选择不同的噪声注入方式；z 项均恒为零。
        let mixed1: UInt32
        switch blend.residueLayoutTag {
        case 0:
            mixed1 = mixed0
        case 1:
            mixed1 = mixed0 ^ (z &* derivedBlendOddConst32(
                domain: 0x4346_465F_424E_4433,
                salt: salt,
                blend: blend,
                base: 0x9E37_79B1
            ))
        case 2:
            mixed1 = mixed0 &+ (z & (value ^ value))
        default:
            mixed1 = mixed0 | (z & 0)
        }
        return mixed1 % boundedModulo
    }
}
