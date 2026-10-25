// CFF 运行时 S-box：用 SplitMix64 + Fisher–Yates 生成 256 字节双射置换表。
// 位于 Internal/CFF 的密码学基础层，被 CFFStateCodec / CFFOpaquePredicates 与 C 侧 `cprisk_cff` 共用。
// 关键安全不变量：表必须是 0..255 的双射；与 C 侧算法逐位一致；首次生成后缓存且在进程内不变。
import CRiskCore
import Foundation

// MARK: - SplitMix64 + Fisher–Yates（必须与 cprisk-armor `CFFSBoxPermutation256` 及 CRiskCore `cprisk_cff` 一致）

/// SplitMix64 随机数生成器，用于可复现的置换表生成。
private struct CFFSplitMix64: RandomNumberGenerator {
    /// 内部状态。
    private var state: UInt64

    /// 以种子初始化；零种子会被替换为 1，保证非退化序列。
    /// - Parameter seed: 初始种子。
    init(seed: UInt64) {
        self.state = seed == 0 ? 1 : seed
    }

    /// 生成下一个 64 位随机数。
    /// - Returns: 混合后的随机字。
    mutating func next() -> UInt64 {
        state &+= 0x9E3779B97F4A7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
        return z ^ (z >> 31)
    }

    /// 从 `[0, bound)` 做拒绝采样，得到无模偏的均匀分布。
    /// 必须与 `CFFSBoxPermutation.swift` 和 `cprisk_cff.c` 中的算法一致。
    /// - Parameter bound: 上界，必须大于 0。
    /// - Returns: `[0, bound)` 内的均匀随机值。
    mutating func unbiased(below bound: UInt64) -> UInt64 {
        precondition(bound > 0, "unbiased(below:) requires positive bound")
        // 丢弃落在阈值以下的样本，消除 `% bound` 的取模偏差。
        let threshold = (UInt64(0) &- bound) % bound
        var r: UInt64
        repeat { r = next() } while r < threshold
        return r % bound
    }
}

/// 256 字节置换表生成与校验。
private enum CFFSBoxPermutation256 {
    /// 以给定种子生成 S-box。
    /// - Parameter seed: 种子。
    /// - Returns: 长度 256 的双射表。
    static func generate(seed: UInt64) -> [UInt8] {
        var a = Array(0..<256).map { UInt8(truncatingIfNeeded: $0) }
        var g = CFFSplitMix64(seed: seed)
        // Fisher–Yates 自后向前洗牌。
        var i = 255
        while i > 0 {
            let j = Int(g.unbiased(below: UInt64(i + 1)))
            a.swapAt(i, j)
            i -= 1
        }
        return a
    }

    /// 校验表是否为 0..255 的双射（无重复、无缺失）。
    /// - Parameter box: 待校验表。
    /// - Returns: 合法双射返回 `true`。
    static func isBijection(_ box: [UInt8]) -> Bool {
        guard box.count == 256 else { return false }
        var seen = [Bool](repeating: false, count: 256)
        for b in box {
            let i = Int(b)
            if seen[i] { return false }
            seen[i] = true
        }
        return true
    }
}

/// 运行时 Feistel SPN 正向 S-box（256 字节双射），由 `CFFStateCodec`、
/// `CFFOpaquePredicates` 与 CRiskCore `cprisk_cff` 共用（相同 SplitMix64 + Fisher–Yates）。
/// 线程模型：内部用 `NSLock` 保护一次性缓存，首次生成后可并发读取。
internal enum CFFSBoxRuntime {
    /// 保护 `cachedForward` 的锁。
    private static let lock = NSLock()
    /// 首次生成后固定的正向表。
    private static var cachedForward: [UInt8]?

    /// SplitMix64 单步混合。
    /// - Parameter x: 输入字。
    /// - Returns: 混合结果。
    @inline(__always)
    private static func splitMix64(_ x: UInt64) -> UInt64 {
        var z = x &+ 0x9E3779B97F4A7C15
        z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
        return z ^ (z >> 31)
    }

    /// 获取运行时 S-box 种子。
    /// - Returns: C 侧安装的种子；未安装（返回 0）时回退到规范种子。
    @inline(__always)
    static func runtimeSeed() -> UInt64 {
        let resolved = cprisk_cff_runtime_spn_sbox_seed()
        // 零值在 PRNG 中是退化种子，回退到规范常量保证两侧一致。
        return resolved == 0 ? CFFSBoxMaterial.canonicalSeed : resolved
    }

    /// 从构建/运行时种子与调用方域派生进程稳定的 32 位字。
    ///
    /// 这样常量在同一构建内保持确定，又避免留下固定的字面量指纹。
    /// - Parameters:
    ///   - domain: 调用方域常量，用于区分不同用途。
    ///   - runtimeSalt: 可选运行时盐。
    ///   - contextWord: 可选上下文词。
    /// - Returns: 32 位派生结果。
    @inline(__always)
    static func derivedWord32(
        domain: UInt64,
        runtimeSalt: UInt32 = 0,
        contextWord: UInt64 = 0
    ) -> UInt32 {
        // 把 32 位盐复制到高低两半，扩大它对混合结果的影响面。
        let saltWord = UInt64(runtimeSalt) | (UInt64(runtimeSalt) << 32)
        let mixed = splitMix64(runtimeSeed() ^ domain ^ contextWord ^ saltWord)
        return UInt32(truncatingIfNeeded: mixed ^ (mixed >> 32))
    }

    /// 惰性生成正向表；首次访问后固定到进程生命周期。
    /// - Returns: 256 字节双射表。
    /// - Note: 优先使用 C 侧已安装的表；拷贝失败或非双射时用规范种子本地重建。
    static func forwardTable() -> [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        if let cachedForward {
            return cachedForward
        }
        var runtimeForward = [UInt8](repeating: 0, count: 256)
        // 向 C 侧请求一份正向表拷贝；返回 0 表示成功。
        let rc = runtimeForward.withUnsafeMutableBufferPointer { buffer -> Int32 in
            guard let base = buffer.baseAddress else { return -1 }
            return Int32(cprisk_cff_spn_sbox_copy_forward(base))
        }
        // 仅接受成功且通过双射校验的表，防止损坏的表破坏编解码可逆性。
        if rc == 0, CFFSBoxPermutation256.isBijection(runtimeForward) {
            cachedForward = runtimeForward
            return runtimeForward
        }

        let fallbackSeed = runtimeSeed()
        let fallback = CFFSBoxPermutation256.generate(seed: fallbackSeed)
        // 兜底表也必须满足双射，否则状态机将不可逆；此处直接终止而非静默运行。
        precondition(CFFSBoxPermutation256.isBijection(fallback), "CFF SPN S-box must be a bijection")
        cachedForward = fallback
        return fallback
    }

    /// 查询 S-box 单字节替换值。
    /// - Parameter idx: 输入字节。
    /// - Returns: 替换后的字节。
    @inline(__always)
    static func spnSboxByte(_ idx: UInt8) -> UInt8 {
        let table = forwardTable()
        return table[Int(idx)]
    }
}
