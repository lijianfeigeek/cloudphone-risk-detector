// 变异规划器：用“服务端种子 + 场景 + 设备 ID”派生确定性伪随机流。
// 对阈值/分数做有界抖动，并可按配置打乱检测器执行顺序，增加动态分析与批量脚本的成本。
// 同一设备在同一策略下结果稳定可复现，避免正常用户分数随机跳变。

import Foundation

/// 变异规划器。所有随机性都来自 `scopeSeed`，无系统随机源，因此跨进程可复现。
struct MutationPlanner: Sendable {
    /// 服务端下发的变异配置；nil 表示不启用抖动与乱序。
    private let strategy: MutationStrategy?
    /// 由策略种子、场景名、设备 ID 经 FNV-1a 派生的 64 位作用域种子。
    private let scopeSeed: UInt64

    /// 创建规划器。
    /// - Parameters:
    ///   - strategy: 变异配置，nil 时所有方法返回原值；- scope: 场景/作用域标识；
    ///   - deviceID: 设备标识，使不同设备的抖动序列不同。
    init(strategy: MutationStrategy?, scope: String, deviceID: String) {
        self.strategy = strategy
        // 用分隔符拼接后哈希，避免不同字段组合产生相同种子。
        let rawSeed = (strategy?.seed ?? "default") + "|" + scope + "|" + deviceID
        self.scopeSeed = Self.fnv1a64(rawSeed)
    }

    /// 对 `base` 做 ±`maxBps` 个基点内的确定性抖动。
    /// - Parameters:
    ///   - base: 原始值；- maxBps: 抖动上限（basis points，10000 = 100%）。
    /// - Returns: 抖动后的非负值；`maxBps <= 0` 时原样返回。
    func jitter(base: Double, maxBps: Int) -> Double {
        guard maxBps > 0 else { return base }
        // 基点转比例：1200 bps -> ±0.12。
        let range = Double(maxBps) / 10_000.0
        let unit = unitRandom(offset: 0xA11CE)
        // unit ∈ [0,1] 映射到 [-range, +range]，再加 1 得到乘性因子。
        let factor = 1.0 + ((unit * 2.0 - 1.0) * range)
        return max(0, base * factor)
    }

    /// 置信度软门控抖动：只允许在 0.1–0.8 之间浮动，避免抖动把置信度推到极端。
    func softConfidenceGate(default value: Double) -> Double {
        let bps = strategy?.thresholdJitterBps ?? 0
        guard bps > 0 else { return value }
        return min(0.8, max(0.1, jitter(base: value, maxBps: bps)))
    }

    /// 篡改基础分抖动：限制在 20–90，防止抖动产生必然放行或必然拒绝的分数。
    func tamperedBase(default value: Double) -> Double {
        let bps = strategy?.scoreJitterBps ?? 0
        guard bps > 0 else { return value }
        return min(90, max(20, jitter(base: value, maxBps: bps)))
    }

    /// 按配置打乱数组顺序（Fisher–Yates），用于打乱检测器执行次序。
    /// - Parameter salt: 额外盐值，使不同检测批次的洗牌顺序不同。
    /// - Returns: 打乱后的新数组；未启用 `shuffleChecks` 或元素不足 2 个时原样返回。
    func maybeShuffle<T>(_ values: [T], salt: String) -> [T] {
        // 关闭乱序时必须保持稳定顺序，保证可测试性与结果可复现。
        guard strategy?.shuffleChecks == true, values.count > 1 else { return values }
        var out = values
        // 每个 salt 使用独立 LCG 流，互不干扰。
        var rng = LCG(seed: scopeSeed ^ Self.fnv1a64(salt))
        // 从尾部向前遍历，随机下标只落在未处理区间内，保证每种排列近似等概率。
        for i in stride(from: out.count - 1, through: 1, by: -1) {
            let j = Int(rng.next() % UInt64(i + 1))
            if i != j {
                out.swapAt(i, j)
            }
        }
        return out
    }

    /// 生成 [0,1) 区间的单位随机数；`offset` 用于同一种子下派生不同用途的随机流。
    private func unitRandom(offset: UInt64) -> Double {
        let value = splitmix64(scopeSeed ^ offset)
        return Double(value) / Double(UInt64.max)
    }

    /// FNV-1a 64 位哈希：把任意种子文本稳定映射为整数，不依赖 Swift 的随机化哈希。
    private static func fnv1a64(_ text: String) -> UInt64 {
        var hash: UInt64 = 0xcbf29ce484222325
        for b in text.utf8 {
            hash ^= UInt64(b)
            // FNV 质数；使用 wrapping 乘法保证溢出时行为确定。
            hash &*= 0x100000001b3
        }
        return hash
    }
}

/// 线性同余伪随机数发生器，仅用于确定性洗牌，不用于安全用途。
private struct LCG {
    private var state: UInt64
    init(seed: UInt64) { state = seed == 0 ? 0x9e3779b97f4a7c15 : seed }

    mutating func next() -> UInt64 {
        // Numerical Recipes 常用常量；wrapping 运算避免溢出陷阱。
        state = 6364136223846793005 &* state &+ 1442695040888963407
        return state
    }
}

/// splitmix64 终混函数：把种子充分雪崩，减少相似输入产生相似输出的相关性。
private func splitmix64(_ x: UInt64) -> UInt64 {
    var z = x &+ 0x9e3779b97f4a7c15
    z = (z ^ (z >> 30)) &* 0xbf58476d1ce4e5b9
    z = (z ^ (z >> 27)) &* 0x94d049bb133111eb
    return z ^ (z >> 31)
}
