// CFF 运行时盐派生：把函数种子、设备/完整性/挑战上下文与进程信息混合成 32 位盐。
// 位于 Internal/CFF 的密码学基础层，为状态编解码与 dispatcher 提供 per-function/per-process 随机化。
// 关键安全不变量：盐必须对同一构建+同一函数稳定、对不同函数/进程不同；不得使用非确定性系统随机源。
import Foundation

/// 运行时盐的输入上下文集合。
/// 所有字段可选，缺失的字段不会参与哈希，便于不同调用方按需提供。
internal struct CFFRuntimeSaltInputs: Sendable, Equatable {
    /// 设备标识派生的 64 位字。
    var deviceWord: UInt64?
    /// 完整性校验结果派生的 64 位字。
    var integrityWord: UInt64?
    /// 挑战/会话 nonce 派生的 64 位字。
    var challengeWord: UInt64?
    /// 信任等级派生的 64 位字。
    var trustWord: UInt64?
    /// 额外 64 位字。
    var extraWords: [UInt64]
    /// 额外字符串（按字节吸收）。
    var strings: [String]
    /// 额外布尔标志（每个占 1 bit）。
    var flags: [Bool]

    /// 创建盐输入。
    /// - Parameters:
    ///   - deviceWord: 设备字，默认 `nil`。
    ///   - integrityWord: 完整性字，默认 `nil`。
    ///   - challengeWord: 挑战字，默认 `nil`。
    ///   - trustWord: 信任字，默认 `nil`。
    ///   - extraWords: 额外字列表，默认空。
    ///   - strings: 额外字符串，默认空。
    ///   - flags: 额外布尔标志，默认空。
    init(
        deviceWord: UInt64? = nil,
        integrityWord: UInt64? = nil,
        challengeWord: UInt64? = nil,
        trustWord: UInt64? = nil,
        extraWords: [UInt64] = [],
        strings: [String] = [],
        flags: [Bool] = []
    ) {
        self.deviceWord = deviceWord
        self.integrityWord = integrityWord
        self.challengeWord = challengeWord
        self.trustWord = trustWord
        self.extraWords = extraWords
        self.strings = strings
        self.flags = flags
    }

    /// 按固定顺序把非空字字段展开为数组。
    var words: [UInt64] {
        [deviceWord, integrityWord, challengeWord, trustWord].compactMap { $0 } + extraWords
    }
}

/// 运行时盐派生工具。
/// 线程模型：纯函数，无共享可变状态，可并发调用。
internal enum CFFRuntimeSalt {
    /// SplitMix64 风格的单步 64 位混合（雪崩）。
    /// - Parameter x: 输入字。
    /// - Returns: 混合后的 64 位字。
    @inline(__always)
    private static func mix64(_ x: UInt64) -> UInt64 {
        var z = x &+ 0x9E3779B97F4A7C15
        z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
        return z ^ (z >> 31)
    }

    /// 按字节把一个 64 位字吸收进 FNV-1a 哈希。
    /// - Parameters:
    ///   - word: 待吸收的字。
    ///   - hash: 当前哈希（inout）。
    ///   - prime: FNV 乘数。
    @inline(__always)
    private static func absorbWord(_ word: UInt64, hash: inout UInt64, prime: UInt64) {
        var value = word
        // 固定 8 轮，逐字节处理，保证字节序无关的稳定吸收。
        for _ in 0..<8 {
            hash ^= value & 0xFF
            hash = hash &* prime
            value >>= 8
        }
    }

    /// 派生函数级运行时盐。
    /// - Parameters:
    ///   - functionSeed: 函数级唯一种子。
    ///   - inputs: 额外上下文，默认空。
    ///   - includeProcessContext: 是否混入 pid/uptime/构建标记，默认 `true`。
    /// - Returns: 32 位盐；相同输入在同一进程内稳定。
    static func derive(
        functionSeed: UInt64,
        inputs: CFFRuntimeSaltInputs = .init(),
        includeProcessContext: Bool = true
    ) -> UInt32 {
        var words = inputs.words
        words.append(functionSeed)

        // 进程上下文让盐在进程重启后变化，但不会在进程内漂移。
        if includeProcessContext {
            words.append(contentsOf: processContextWords())
        }

        return combine(words: words, strings: inputs.strings, flags: inputs.flags)
    }

    /// 通用 FNV-1a 组合器：吸收字、标志与字符串。
    /// - Parameters:
    ///   - words: 64 位字列表。
    ///   - strings: 字符串列表（按 UTF-8 字节吸收）。
    ///   - flags: 布尔标志列表。
    ///   - includeBuildContext: 是否混入构建/运行时种子，默认 `true`。
    /// - Returns: 折叠后的 32 位结果。
    static func combine(
        words: [UInt64] = [],
        strings: [String] = [],
        flags: [Bool] = [],
        includeBuildContext: Bool = true
    ) -> UInt32 {
        // FNV-1a 64 位初始值与乘数。
        var hash: UInt64 = 0xCBF29CE484222325
        let prime: UInt64 = 0x100000001B3

        if includeBuildContext {
            // 把各输入的数量编码进一个计数词，防止“不同长度但同内容”产生相同盐。
            let countsWord = (UInt64(words.count) << 40) ^ (UInt64(strings.count) << 20) ^ UInt64(flags.count)
            let buildSeedWord = mix64(CFFSBoxRuntime.runtimeSeed() ^ 0x4346_4652_554E_5341 ^ countsWord)
            absorbWord(buildSeedWord, hash: &hash, prime: prime)
        }

        for word in words {
            absorbWord(word, hash: &hash, prime: prime)
        }

        for flag in flags {
            hash ^= flag ? 1 : 0
            hash = hash &* prime
        }

        for string in strings {
            for byte in string.utf8 {
                hash ^= UInt64(byte)
                hash = hash &* prime
            }
            // 每个字符串后追加分隔标记，避免 "ab"+"c" 与 "a"+"bc" 混淆。
            hash ^= 0xFF
            hash = hash &* prime
        }

        // 高低 32 位异或折叠，返回 32 位盐。
        return UInt32(truncatingIfNeeded: hash ^ (hash >> 32))
    }

    /// CFF dispatcher 旋转用的快速非密码学 nonce。
    ///
    /// 将 `counter`（每次迭代的调用序号）与 `functionSeed`（函数级唯一常量）耦合，
    /// 使同一 counter 下不同函数得到不同 nonce。使用 SplitMix64 单步混合，
    /// 足够廉价，可在紧凑的 dispatch 循环中调用而无可测开销。
    /// - Parameters:
    ///   - counter: 本轮调用计数。
    ///   - functionSeed: 函数级种子。
    /// - Returns: 32 位旋转 nonce。
    @inline(__always)
    static func deriveRotationNonce(counter: UInt32, functionSeed: UInt64) -> UInt32 {
        var z = functionSeed ^ (UInt64(counter) &* 0x9E3779B97F4A7C15)
        z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
        z = z ^ (z >> 31)
        return UInt32(truncatingIfNeeded: z ^ (z >> 32))
    }

    /// 收集进程级上下文：pid、运行时长（毫秒）与构建模式标记。
    /// - Returns: 三个 64 位上下文词。
    private static func processContextWords() -> [UInt64] {
        let processInfo = ProcessInfo.processInfo
        let uptimeMillis = UInt64((processInfo.systemUptime * 1_000.0).rounded(.down))
        let pid = UInt64(processInfo.processIdentifier)
        let debugMarkerBase: UInt64

        // DEBUG/RELEASE 使用不同标记，使两类构建派生出的盐不可互换。
        #if DEBUG
        debugMarkerBase = 0xD38B_D38B_D38B_D38B
        #else
        debugMarkerBase = 0xA11C_E551_A11C_E551
        #endif

        // 标记再与运行时 S-box 种子和固定域常量混合，避免成为静态可识别常量。
        let debugMarker = mix64(debugMarkerBase ^ CFFSBoxRuntime.runtimeSeed() ^ 0x4350_5249_534B_4442)

        return [pid, uptimeMillis, debugMarker]
    }
}
