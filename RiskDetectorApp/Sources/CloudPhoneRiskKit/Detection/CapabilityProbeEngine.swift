// 能力探针引擎：在沙箱内执行一组“正常情况下应当失败”的探测（越狱路径、Frida dylib、
// 常见注入端口、fork/线程能力、DYLD 注入变量），把“异常成功”计为异常；B 类质量探针
// 再检查失败是否真实（耗时、errno、调用栈），识别“伪造失败”。结果折算为 capability_probe 软信号。
// 探针列表可由服务端 RemoteConfig 热下发，未知探针默认失败，防止用任意探针 ID 绕过检测。

import Darwin
import Foundation
import MachO

// MARK: - 探针结果结构

/// 能力探针的执行结果
public struct ProbeResult: Codable, Sendable {
    /// 探针标识，与 `ProbeDefinition.id` 对应。
    public let id: String
    /// 探针调用是否“成功”（成功与否是否异常由 expectedOutcome 决定）。
    public let succeeded: Bool
    /// 调用耗时（微秒），用于识别伪造失败是否引入异常延迟。
    public let elapsedMicros: UInt64
    /// 调用结束时保存的 errno，用于判断失败原因是否符合预期。
    public let errnoValue: Int32
    /// 期望结果；nil 表示兼容旧数据，按“成功即异常”处理。
    public let expectedOutcome: CapabilityProbeEngine.ProbeExpectation?
    /// 该探针的耗时上限（微秒），覆盖全局默认值。
    public let maxElapsedMicros: UInt64?
    /// 调用栈帧摘要（可选），用于发现 hook 框架帧。
    public let callerFrame: String?

    /// 短键名压缩上报体积；键名属于序列化契约，改名会导致旧数据解码失败。
    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case succeeded = "s"
        case elapsedMicros = "em"
        case errnoValue = "ev"
        case expectedOutcome = "eo"
        case maxElapsedMicros = "me"
        case callerFrame = "cf"
    }

    public init(
        id: String,
        succeeded: Bool,
        elapsedMicros: UInt64,
        errnoValue: Int32,
        expectedOutcome: CapabilityProbeEngine.ProbeExpectation? = nil,
        maxElapsedMicros: UInt64? = nil,
        callerFrame: String? = nil
    ) {
        self.id = id
        self.succeeded = succeeded
        self.elapsedMicros = elapsedMicros
        self.errnoValue = errnoValue
        self.expectedOutcome = expectedOutcome
        self.maxElapsedMicros = maxElapsedMicros
        self.callerFrame = callerFrame
    }
}

// MARK: - 能力分数

/// 能力探针的评估分数
public struct CapabilityScore: Codable, Sendable {
    /// A 类基础探针中结果异常的个数。
    public let basicAnomalyCount: Int
    /// B 类质量探针累计的可疑度（伪造失败、errno 异常、可疑栈帧）。
    public let qualitySuspicion: Int
    /// 实际执行的探针总数。
    public let totalProbes: Int
    /// 风险贡献分：基础异常每条 3 分，质量可疑度直接累加，最终在 toSignal 中限幅。
    public let riskContribution: Int

    /// 短键名压缩上报体积；键名属于序列化契约，改名会导致旧数据解码失败。
    private enum CodingKeys: String, CodingKey {
        case basicAnomalyCount = "ba"
        case qualitySuspicion = "qs"
        case totalProbes = "tp"
        case riskContribution = "rc"
    }

    public init(
        basicAnomalyCount: Int,
        qualitySuspicion: Int,
        totalProbes: Int
    ) {
        self.basicAnomalyCount = basicAnomalyCount
        self.qualitySuspicion = qualitySuspicion
        self.totalProbes = totalProbes
        // 核心逻辑：大部分失败 = 低风险，异常通过 = 高风险
        self.riskContribution = basicAnomalyCount * 3 + qualitySuspicion
    }

    /// 转换为软信号。
    /// 置信度按 riskContribution/100 线性折算并封顶 1；探针证据只作软信号，避免单独定罪。
    public func toSignal() -> RiskSignal {
        let confidence = min(Double(riskContribution) / 100.0, 1.0)
        return RiskSignal(
            id: "capability_probe",
            category: "capability",
            score: Double(riskContribution),
            evidence: [
                "basicAnomalyCount": "\(basicAnomalyCount)",
                "qualitySuspicion": "\(qualitySuspicion)",
                "totalProbes": "\(totalProbes)"
            ],
            state: RiskSignalState.soft(confidence: confidence),
            layer: 3,
            weightHint: min(Double(riskContribution), 100)
        )
    }
}

// MARK: - 能力探针引擎

/// 能力探针引擎
///
/// 核心思想：正常沙箱 = 大部分探针失败
/// - A 类探针：结论可能被伪造，权重低
/// - B 类探针：hook 伪造反而暴露自己
public final class CapabilityProbeEngine: @unchecked Sendable {

    // 时间基准只读取一次；mach_absolute_time 的单位换算依赖 numer/denom。
    private static let timebaseInfo: mach_timebase_info_data_t = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info
    }()

    private static let probeDyldFridaID = "dyld_\(ObfuscatedConstants.keywordFrida)"
    // hook 框架名称经字符串混淆/Base64 存放，避免明文特征被静态定位后 patch。
    private static let hookFrameworkNeedles: [String] = [
        ObfuscatedConstants.keywordFrida,
        StringDeobfuscator.base64Decode("c3Vic3RyYXRl"),
        StringDeobfuscator.base64Decode("c3Vic3RpdHV0ZQ=="),
        StringDeobfuscator.base64Decode("ZG9iYnk="),
        ObfuscatedConstants.hookFrameworkFishhookToken + ObfuscatedConstants.keywordHook,
    ]

    // MARK: - 配置

    /// 引擎级配置；`maxElapsedMicros` 是“失败应发生的合理耗时”上限。
    public struct Config: Sendable {
        /// 期望失败的最大耗时（微秒）；超出说明失败可能是伪造/被拦截。
        public let maxElapsedMicros: UInt64
        /// 是否启用 B 类质量探针
        public let enableQualityProbes: Bool
        /// 自定义探针列表（可选）；服务端下发时覆盖内置默认表。
        public let customProbes: [ProbeDefinition]?

        public init(
            maxElapsedMicros: UInt64 = 80,
            enableQualityProbes: Bool = true,
            customProbes: [ProbeDefinition]? = nil
        ) {
            self.maxElapsedMicros = maxElapsedMicros
            self.enableQualityProbes = enableQualityProbes
            self.customProbes = customProbes
        }

        public static let `default` = Config()
    }

    // MARK: - 探针定义

    /// 单个探针定义：期望结果、超时上限与权重（权重当前用于服务端聚合语义）。
    public struct ProbeDefinition: Sendable {
        public let id: String
        public let expectedOutcome: ProbeExpectation
        public let maxElapsedMicros: UInt64
        public let weight: Int

        public init(
            id: String,
            expectedOutcome: ProbeExpectation,
            maxElapsedMicros: UInt64 = 80,
            weight: Int = 1
        ) {
            self.id = id
            self.expectedOutcome = expectedOutcome
            self.maxElapsedMicros = maxElapsedMicros
            self.weight = weight
        }
    }

    /// 探针期望结果。`.fail` 是沙箱内的常态（路径不存在、端口不可连）；
    /// `.pass` 仅用于确实应当可用的能力，二者任一偏离都算异常。
    public enum ProbeExpectation: String, Codable, Sendable {
        case fail  // 期望失败（正常沙箱应该失败）
        case pass  // 期望通过
    }

    // MARK: - 私有属性

    private let config: Config

    // MARK: - 初始化

    public init(config: Config = .default) {
        self.config = config
    }

    // MARK: - A 类探针：基础能力探针

    /// 运行基础探针（A 类）。
    /// 有服务端自定义列表时完全替代默认列表，便于灰度新探针或临时下线噪声探针。
    public func runBasicProbes() -> [ProbeResult] {
        let definitions = config.customProbes ?? defaultProbeDefinitions()
        return definitions.map { definition in
            probe(
                definition.id,
                expectedOutcome: definition.expectedOutcome,
                maxElapsedMicros: definition.maxElapsedMicros
            ) {
                self.executeProbe(id: definition.id)
            }
        }
    }

    // MARK: - B 类探针：质量探针

    /// 运行质量探针，分析 A 类结果，返回累计可疑度。
    /// 只检查预期失败的探针：真正失败的调用通常很快、errno 合理、栈上没有 hook 帧。
    public func runQualityProbes(_ basics: [ProbeResult]) -> Int {
        var suspicion = 0

        for result in basics where !result.succeeded {
            let threshold = result.maxElapsedMicros ?? config.maxElapsedMicros

            // ① 时序异常：伪造失败比真实失败慢
            if result.elapsedMicros > threshold {
                suspicion += 2
            }

            // ② errno 不一致：懒得设置或设置错误；权重高于时序异常。
            if let expectedErrnos = expectedFailureErrnos[result.id], !expectedErrnos.contains(result.errnoValue) {
                suspicion += 3
            }

            // ③ 调用栈出现陌生帧（Hook 框架特征）；命中即强证据，权重最高。
            if let frame = result.callerFrame {
                if Self.hookFrameworkNeedles.contains(where: { frame.lowercased().contains($0) }) {
                    suspicion += 5
                }
            }
        }

        return suspicion
    }

    // MARK: - 主评估入口

    /// 执行完整评估并返回汇总分数。
    /// A 类异常按条数计，B 类可疑度单独累加，两者共同构成 riskContribution。
    public func evaluate() -> CapabilityScore {
        let basics = runBasicProbes()
        let quality = config.enableQualityProbes ? runQualityProbes(basics) : 0
        let anomalyCount = basics.filter { isAnomalous($0) }.count

        return CapabilityScore(
            basicAnomalyCount: anomalyCount,
            qualitySuspicion: quality,
            totalProbes: basics.count
        )
    }

    /// 执行评估并返回详细结果（用于调试）
    public func evaluateDetailed() -> (score: CapabilityScore, probes: [ProbeResult]) {
        let basics = runBasicProbes()
        let quality = config.enableQualityProbes ? runQualityProbes(basics) : 0
        let anomalyCount = basics.filter { isAnomalous($0) }.count

        let score = CapabilityScore(
            basicAnomalyCount: anomalyCount,
            qualitySuspicion: quality,
            totalProbes: basics.count
        )

        return (score, basics)
    }

    // MARK: - 私有方法

    /// 通用探针执行器：计时包裹实际调用，并把 errno 一并记录。
    /// 注意 errno 必须在 block 返回后立即读取，避免被后续调用覆盖（当前无中间调用）。
    private func probe(
        _ id: String,
        expectedOutcome: ProbeExpectation? = nil,
        maxElapsedMicros: UInt64? = nil,
        block: () -> Bool
    ) -> ProbeResult {
        let start = mach_absolute_time()
        let succeeded = block()
        let end = mach_absolute_time()

        // 把 mach 绝对时间换算为微秒；先除后乘配合余数，避免大数相乘溢出。
        let tb = Self.timebaseInfo
        let diff = end - start
        let denom = UInt64(max(tb.denom, 1))
        let elapsedNanos = diff / denom * UInt64(tb.numer) + (diff % denom) * UInt64(tb.numer) / denom
        let elapsedMicros = elapsedNanos / 1000

        return ProbeResult(
            id: id,
            succeeded: succeeded,
            elapsedMicros: elapsedMicros,
            errnoValue: errno,
            expectedOutcome: expectedOutcome,
            maxElapsedMicros: maxElapsedMicros
        )
    }

    /// 默认探针表：全部期望失败，覆盖越狱文件、Frida dylib、常见注入端口与沙箱能力。
    /// 端口 27042/27043 是 Frida 默认端口，23946 常见于调试服务器。
    private func defaultProbeDefinitions() -> [ProbeDefinition] {
        [
            ProbeDefinition(id: "stat_bash", expectedOutcome: .fail, maxElapsedMicros: config.maxElapsedMicros),
            ProbeDefinition(id: "stat_apt", expectedOutcome: .fail, maxElapsedMicros: config.maxElapsedMicros),
            ProbeDefinition(id: Self.probeDyldFridaID, expectedOutcome: .fail, maxElapsedMicros: config.maxElapsedMicros),
            ProbeDefinition(id: "sock_27042", expectedOutcome: .fail, maxElapsedMicros: config.maxElapsedMicros),
            ProbeDefinition(id: "sock_27043", expectedOutcome: .fail, maxElapsedMicros: config.maxElapsedMicros),
            ProbeDefinition(id: "sock_23946", expectedOutcome: .fail, maxElapsedMicros: config.maxElapsedMicros),
            ProbeDefinition(id: "fork_ability", expectedOutcome: .fail, maxElapsedMicros: config.maxElapsedMicros),
            ProbeDefinition(id: "dyld_insert", expectedOutcome: .fail, maxElapsedMicros: config.maxElapsedMicros),
        ]
    }

    /// 按 ID 分发到具体探针实现。
    private func executeProbe(id: String) -> Bool {
        switch id {
        case "stat_bash":
            return statFile("/bin/bash")
        case "stat_apt":
            return statFile("/etc/apt")
        case Self.probeDyldFridaID:
            return dlopenFrida()
        case "sock_27042":
            return canConnect(port: 27042)
        case "sock_27043":
            return canConnect(port: 27043)
        case "sock_23946":
            return canConnect(port: 23946)
        case "fork_ability":
            return canFork()
        case "dyld_insert":
            return getEnvDYLD()
        default:
            // 未知探针默认失败，避免被“任意探针ID”绕过
            return false
        }
    }

    /// 根据期望结果判断本次探针是否异常；无期望值时沿用“成功=异常”的旧语义。
    private func isAnomalous(_ result: ProbeResult) -> Bool {
        guard let expected = result.expectedOutcome else {
            // 向后兼容：无 expectedOutcome 时，沿用“成功=异常”
            return result.succeeded
        }
        switch expected {
        case .fail:
            return result.succeeded
        case .pass:
            return !result.succeeded
        }
    }

    /// 不同探针失败时应出现的 errno 值，超出集合可视作伪造失败信号。
    /// 文件类允许 ENOENT/EACCES/EPERM；端口类允许拒绝/超时/不可达。
    private let expectedFailureErrnos: [String: Set<Int32>] = [
        "stat_bash": [ENOENT, EACCES, EPERM],
        "stat_apt": [ENOENT, EACCES, EPERM],
        "fork_ability": [EPERM, EAGAIN],
        "sock_27042": [ECONNREFUSED, ETIMEDOUT, EHOSTUNREACH, ENETUNREACH],
        "sock_27043": [ECONNREFUSED, ETIMEDOUT, EHOSTUNREACH, ENETUNREACH],
        "sock_23946": [ECONNREFUSED, ETIMEDOUT, EHOSTUNREACH, ENETUNREACH],
    ]

    /// stat 文件探针：经动态符号解析调用 access，降低 PLT hook 直接命中的概率。
    private func statFile(_ path: String) -> Bool {
        path.withCString {
            DynamicSymbolResolver.access($0, F_OK) == 0
        }
    }

    /// dlopen Frida dylib 探针：尝试多个常见命名，任一可加载即视为注入证据。
    private func dlopenFrida() -> Bool {
        let keywordFrida = ObfuscatedConstants.keywordFrida
        let capitalizedFrida = keywordFrida.prefix(1).uppercased() + keywordFrida.dropFirst()
        let fridaLibs = [
            "\(capitalizedFrida)Gadget.dylib",
            "\(keywordFrida)-agent-arm64.dylib",
            "\(keywordFrida)-agent.dylib",
            "\(keywordFrida)-server"
        ]
        for lib in fridaLibs {
            let opened = lib.withCString {
                DynamicSymbolResolver.dlopen($0, RTLD_NOW)
            }
            if opened != nil {
                return true
            }
        }
        return false
    }

    /// 端口连接探针：只连本机回环地址，成功即说明对应调试/注入服务正在监听。
    private func canConnect(port: Int) -> Bool {
        let fd = DynamicSymbolResolver.socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { _ = DynamicSymbolResolver.close(fd) }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                DynamicSymbolResolver.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        // connect 返回 0 表示端口可达；非 0 的失败属正常沙箱行为。
        return result == 0
    }

    /// fork 能力探针
    /// 注意：iOS 上 fork 不可用，使用 pthread 检测线程创建能力作为替代
    private func canFork() -> Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        // 使用 pthread 创建线程能力作为 sandbox 逃逸的代理指标
        // 在受限沙箱中，pthread_create 可能会失败
        var thread: pthread_t? = nil
        let result = pthread_create(&thread, nil, { _ in return nil }, nil)
        if result == 0, let thread = thread {
            pthread_cancel(thread)
            return true
        }
        return false
        #endif
    }

    /// DYLD_INSERT_LIBRARIES 环境变量探针
    private func getEnvDYLD() -> Bool {
        return getenv("DYLD_INSERT_LIBRARIES") != nil
    }
}

// MARK: - 探针配置热下发支持

/// 探针配置热下发：把服务端探针表转换为引擎配置。
extension CapabilityProbeEngine {

    /// 从远程配置创建引擎。
    /// 只识别 "fail" 为期望失败，其他值一律按 "pass" 处理（fail-closed 于检测语义而非解析语义）。
    /// - Parameter probeConfig: 来自 RemoteConfig.probeConfig
    public static func fromRemoteConfig(_ probeConfig: ProbeConfig) -> CapabilityProbeEngine {
        let definitions = probeConfig.probes.map { config in
            ProbeDefinition(
                id: config.id,
                expectedOutcome: config.expectedOutcome == "fail" ? .fail : .pass,
                maxElapsedMicros: UInt64(config.maxElapsedUs),
                weight: config.weight
            )
        }

        let config = Config(
            maxElapsedMicros: 80,
            enableQualityProbes: true,
            customProbes: definitions
        )

        return CapabilityProbeEngine(config: config)
    }
}

// MARK: - 远程配置探针结构（使用 RemoteConfig 中的定义）

// ProbeConfig 和 ProbeConfigItem 已移至 RemoteConfig.swift
// 使用时 import CloudPhoneRiskKit 并通过 RemoteConfig.ProbeConfig 访问
