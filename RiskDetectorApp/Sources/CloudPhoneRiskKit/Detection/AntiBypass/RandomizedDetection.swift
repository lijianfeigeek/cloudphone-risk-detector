// 随机化检测器：把若干快速环境检查（env/dyld/path/parent）随机打乱顺序、随机抽取子集执行，
// 并在检查之间插入随机延迟与时钟反转检测，使 hook 方难以预测调用序列与耗时特征。
// 控制流经 CFF 状态编码（函数指针表 / if-else 双轨）处理，降低静态分析可读性；种子可由服务端下发。
// 计分：时序异常 +18、时钟回拨 +20、每条命中检查 +8，均由调用方汇总后进入信号管道。

import CRiskCore
import Darwin
import Foundation
import MachO

/// 本检测器专用的 CFF 配置与运行时盐派生。
/// 盐把配置参数、命中数量与函数名绑定，使不同输入走不同的状态编码路径。
private enum RandomizedDetectionCFF {
    static let detectConfig = CFFConfig.adaptive(
        functionSeed: 0x9D42_A3F1_56C8_2B17,
        protectionTier: .light,
        dispatcherStyle: .functionPointerTable,
        codecStyle: .feistelSpn
    )

    /// 由配置与本次选择结果派生 CFF 运行时盐；`seed` 为 nil 时用 0 占位，保证派生稳定。
    static func salt(config: RandomizedDetection.Config, selectedCount: Int, totalChecks: Int) -> UInt32 {
        CFFRuntimeSalt.derive(
            functionSeed: detectConfig.functionSeed,
            inputs: CFFRuntimeSaltInputs(
                extraWords: [
                    config.seed ?? 0,
                    UInt64(config.minDelayUs),
                    UInt64(config.maxDelayUs),
                    UInt64(selectedCount),
                    UInt64(totalChecks),
                    config.subsetRatio.bitPattern,
                ],
                strings: ["RandomizedDetection.detect"],
                flags: [config.enableShuffle, config.enableRandomDelay]
            )
        )
    }
}

/// 随机化检测器：随机化检查顺序、子集大小与延迟，并额外检测时序/时钟异常。
struct RandomizedDetection: Detector {
    /// 运行参数；默认值面向线上低开销场景，可由服务端配置覆盖。
    struct Config {
        /// 是否打乱检查顺序，避免固定调用序列被 hook 特征匹配。
        var enableShuffle: Bool = true
        /// 是否在检查之间插入随机延迟，制造难以建模的耗时分布。
        var enableRandomDelay: Bool = true
        /// 单次延迟下限（微秒）。
        var minDelayUs: UInt32 = 100
        /// 单次延迟上限（微秒）。
        var maxDelayUs: UInt32 = 1000
        /// 随机种子；nil 时用当前时间戳，便于复现实验时显式指定。
        var seed: UInt64? = nil
        /// 实际执行的检查比例，0...1；小于 1 时每次只跑部分检查以增加不确定性。
        var subsetRatio: Double = 1.0
    }

    private let config: Config

    init(config: Config = Config()) {
        // 服务端配置可能给出反向区间，而 ClosedRange 要求 lower <= upper，先夹紧防止崩溃。
        var sanitized = config
        if sanitized.maxDelayUs < sanitized.minDelayUs {
            sanitized.maxDelayUs = sanitized.minDelayUs
        }
        self.config = sanitized
    }

    /// 执行随机化检查并返回分数。
    /// - 无服务端种子时用当前时间生成种子，保证每次启动序列不同。
    /// - `loopBudget` 是状态机的硬性护栏：即使分支被 hook 引导成死循环，也会在预算耗尽后退出。
    func detect() throws -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []
        var rng = SeededRandomGenerator(seed: config.seed ?? UInt64(Date().timeIntervalSince1970.bitPattern))

        let checks: [(String, () -> Bool)] = [
            ("env", quickEnvCheck),
            ("dyld", quickDyldCheck),
            ("path", quickPathCheck),
            ("parent", quickParentCheck)
        ]

        let selectedChecks = config.enableShuffle ? rng.shuffled(checks) : checks
        // 子集比例夹到 [0,1]，且至少执行 1 条，避免配置成 0 时检测被静默关闭。
        let count = max(1, Int(Double(selectedChecks.count) * max(0, min(config.subsetRatio, 1))))
        let cffConfig = RandomizedDetectionCFF.detectConfig
        let salt = RandomizedDetectionCFF.salt(config: config, selectedCount: count, totalChecks: selectedChecks.count)

        // 状态编号随意但互不相同；真正可读的状态被 CFFStateCodec 编码后才出现在寄存器里。
        let entryState: UInt32 = 0x11
        let timingState: UInt32 = 0x12
        let clockState: UInt32 = 0x13
        let iterateState: UInt32 = 0x14
        let delayState: UInt32 = 0x15
        let executeState: UInt32 = 0x16
        let connectorState: UInt32 = 0x17
        let settleState: UInt32 = 0x18
        let finishState: UInt32 = 0x19

        let cffKey = CFFStateCodec.deriveSeed(function: "RandomizedDetection.detect", config: cffConfig)
        let effectiveSalt = cffConfig.enableRuntimeSalt ? salt : salt ^ 0x13579BDF

        /// 把可读状态编码为运行期不可读的 CFF 状态。
        func encodeState(_ rawState: UInt32) -> UInt32 {
            CFFStateCodec.encode(state: rawState, key: cffKey, salt: effectiveSalt, style: cffConfig.codecStyle)
        }

        /// 解码 CFF 状态；仅状态机内部使用，避免明文状态长期驻留。
        func decodeState(_ encoded: UInt32) -> UInt32 {
            CFFStateCodec.decode(state: encoded, key: cffKey, salt: effectiveSalt, style: cffConfig.codecStyle)
        }

        var sink = CFFReturnSink<DetectorResult>()
        var encodedState = encodeState(entryState)
        var checkIndex = 0
        var currentCheck: (String, () -> Bool)?
        // 状态机护栏：正常路径远低于该预算，预算耗尽说明控制流被异常引导，直接收尾而非挂死。
        var loopBudget = max(32, count * 6 + 12)

        /// 统一收尾构造结果，保证所有状态出口返回值结构一致。
        func finalizeResult() -> DetectorResult {
            DetectorResult(score: score, methods: methods)
        }

        while !sink.isResolved {
            guard loopBudget > 0 else {
                sink.store(finalizeResult())
                break
            }
            loopBudget -= 1

            let decodedState = decodeState(encodedState)
            let dispatchPlan = CFFDispatcher.plan(encodedState: encodedState, salt: salt, config: cffConfig)
            let useIfElseRail = dispatchPlan.style == .ifElseChain
                || (dispatchPlan.usesSecondaryDispatcher && CFFOpaquePredicates.connectorGate(encodedState: encodedState, salt: salt))

            if useIfElseRail {
                if decodedState == entryState {
                    encodedState = encodeState(timingState)
                } else if decodedState == timingState {
                    if hasTimingAnomaly(using: &rng) {
                        score += 18
                        methods.append("timing:delay_anomaly")
                    }
                    encodedState = encodeState(clockState)
                } else if decodedState == clockState {
                    if hasClockReversal() {
                        score += 20
                        methods.append("timing:time_reversal")
                    }
                    encodedState = encodeState(iterateState)
                } else if decodedState == iterateState {
                    guard checkIndex < count else {
                        encodedState = encodeState(finishState)
                        continue
                    }
                    currentCheck = selectedChecks[checkIndex]
                    let nextState = config.enableRandomDelay ? delayState : executeState
                    encodedState = encodeState(nextState)
                } else if decodedState == delayState {
                    usleep(rng.randomInRange(config.minDelayUs...config.maxDelayUs))
                    encodedState = encodeState(executeState)
                } else if decodedState == executeState {
                    if let (name, check) = currentCheck, check() {
                        score += 8
                        methods.append("randomized_\(name)")
                    }
                    currentCheck = nil
                    checkIndex += 1
                    encodedState = encodeState(connectorState)
                } else if decodedState == connectorState {
                    let nextState = CFFOpaquePredicates.parityFence(UInt32(checkIndex) &+ decodedState, salt: salt) ? iterateState : settleState
                    encodedState = encodeState(nextState)
                } else if decodedState == settleState {
                    encodedState = encodeState(iterateState)
                } else if decodedState == finishState {
                    sink.store(finalizeResult())
                } else {
                    sink.store(finalizeResult())
                }
            } else {
                switch decodedState {
                case entryState:
                    encodedState = encodeState(timingState)
                case timingState:
                    if hasTimingAnomaly(using: &rng) {
                        score += 18
                        methods.append("timing:delay_anomaly")
                    }
                    encodedState = encodeState(clockState)
                case clockState:
                    if hasClockReversal() {
                        score += 20
                        methods.append("timing:time_reversal")
                    }
                    encodedState = encodeState(iterateState)
                case iterateState:
                    guard checkIndex < count else {
                        encodedState = encodeState(finishState)
                        continue
                    }
                    currentCheck = selectedChecks[checkIndex]
                    encodedState = encodeState(config.enableRandomDelay ? delayState : executeState)
                case delayState:
                    usleep(rng.randomInRange(config.minDelayUs...config.maxDelayUs))
                    encodedState = encodeState(executeState)
                case executeState:
                    if let (name, check) = currentCheck, check() {
                        score += 8
                        methods.append("randomized_\(name)")
                    }
                    currentCheck = nil
                    checkIndex += 1
                    encodedState = encodeState(connectorState)
                case connectorState:
                    let nextState = CFFDispatcher.branchKey(encodedState, salt: salt) & 1 == 0 ? iterateState : settleState
                    encodedState = encodeState(nextState)
                case settleState:
                    encodedState = encodeState(iterateState)
                case finishState:
                    sink.store(finalizeResult())
                default:
                    sink.store(finalizeResult())
                }
            }
        }

        return sink.resolve(or: finalizeResult())
    }

    /// 主动测量一次随机延迟的实际耗时，用于识别 hook 导致的时序失真。
    /// 判定窗口设为预期值的 0.5x–4x：上限留足调度抖动余量，下限则抓“根本没睡”的伪造实现。
    private func hasTimingAnomaly(using rng: inout SeededRandomGenerator) -> Bool {
        guard config.enableRandomDelay else { return false }
        let delay = rng.randomInRange(config.minDelayUs...config.maxDelayUs)
        let before = DispatchTime.now().uptimeNanoseconds
        usleep(delay)
        let after = DispatchTime.now().uptimeNanoseconds
        guard after >= before else { return true }  // 时钟倒退本身即异常
        let elapsed = after - before
        let expected = UInt64(delay) * 1_000
        return elapsed < expected / 2 || elapsed > expected * 4
    }

    /// 检测墙上时钟回拨；两次采样间隔极短，正常系统不会倒退。
    private func hasClockReversal() -> Bool {
        let first = Date().timeIntervalSince1970
        usleep(10)
        let second = Date().timeIntervalSince1970
        return second < first
    }

    /// 环境变量注入检查。
    private func quickEnvCheck() -> Bool {
        ProcessInfo.processInfo.environment["DYLD_INSERT_LIBRARIES"] != nil
    }

    /// 镜像数量阈值：正常 App 通常远低于 450，超过说明有大量注入 dylib 或调试桩。
    private func quickDyldCheck() -> Bool {
        _dyld_image_count() > 450
    }

    /// 主可执行文件不在 .app 包内，通常意味着重打包/越狱安装。
    private func quickPathCheck() -> Bool {
        guard let executable = Bundle.main.executablePath else { return false }
        return !executable.contains(".app/")
    }

    /// 父进程名包含 Frida/lldb 关键字说明调试器或注入框架在启动链上。
    private func quickParentCheck() -> Bool {
        let ppid = cprisk_getppid_direct()
        guard ppid > 1 else { return false }
        guard let parent = processPath(for: ppid)?.lowercased() else { return false }
        return parent.contains(ObfuscatedConstants.keywordFrida) || parent.contains(ObfuscatedConstants.keywordLldb)
    }
}

/// SplitMix64 伪随机生成器：确定性、无锁、无系统熵依赖，适合在检测状态机内部使用。
private struct SeededRandomGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        self.state = seed
    }

    /// 标准 SplitMix64 混合：固定常量负责扩散，输出对种子变化高度敏感。
    mutating func next() -> UInt64 {
        state &+= 0x9e3779b97f4a7c15
        var z = state
        z = (z ^ (z >> 30)) &* 0xbf58476d1ce4e5b9
        z = (z ^ (z >> 27)) &* 0x94d049bb133111eb
        return z ^ (z >> 31)
    }

    /// 在闭区间内取值；对整数全区间做取模，避免 `next() % 0` 崩溃。
    mutating func randomInRange<T>(_ range: ClosedRange<T>) -> T where T: FixedWidthInteger {
        let lower = UInt64(range.lowerBound)
        let upper = UInt64(range.upperBound)
        // upper - lower + 1 溢出时 size 回绕为 0，若直接取模会触发除零。
        let size = upper &- lower &+ 1
        guard size != 0 else { return T(next()) }
        let value = next() % size
        return T(value &+ lower)
    }

    /// Fisher–Yates 洗牌；单元素数组直接返回，避免无意义的随机消耗。
    mutating func shuffled<T>(_ array: [T]) -> [T] {
        guard array.count > 1 else { return array }
        var result = array
        for index in stride(from: result.count - 1, through: 1, by: -1) {
            let randomIndex = Int(randomInRange(0...index))
            result.swapAt(index, randomIndex)
        }
        return result
    }
}
