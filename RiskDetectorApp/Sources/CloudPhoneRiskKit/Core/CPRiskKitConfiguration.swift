// MARK: - CPRiskKit+Configuration（配置类型）
//
// 职责：集中定义 CPRiskKit 的静态配置、运行时枚举与嵌套快照类型。
// 位于评估管线的配置与诊断层：Anti-Debug、Armor 运行时、看门狗与能力探针共用这些类型。
// 安全不变量：Armor 根密钥只允许来自环境变量（无硬编码回退）；运行时状态以快照形式对外只读暴露。

import CryptoKit
import CRiskCore
import Foundation

// MARK: - SignalID（引用说明）

// SignalID 定义在 RiskReport.swift 中，此处不重复定义。
// ObfuscatedConstants 定义在 Util/ObfuscatedStrings.swift 中。

// MARK: - 配置扩展

extension CPRiskKit {

    // MARK: 实时自适应配置档

    /// 实时自适应遥测配置档：描述评估限流间隔与各类别权重缩放。
    ///
    /// 由远程配置与外部服务反馈合成，用于在高压力期间降低评估频率并调整权重。
    internal struct RealtimeAdaptiveProfile {
        /// 是否启用自适应
        let enabled: Bool
        /// 两次评估之间的最小间隔（毫秒）
        let minEvaluationIntervalMillis: Int
        /// 默认权重缩放（BPS，10000 表示 1.0 倍）
        let defaultWeightScaleBps: Int
        /// 各类别的权重缩放（BPS）
        let categoryWeightScaleBps: [String: Int]
        /// 配置来源标识（用于日志与缓存键）
        let source: String

        /// 稳定签名：把配置内容序列化为可比较字符串，作为自适应缓存键的一部分。
        var signature: String {
            // 对类别键排序，保证相同配置生成相同签名（避免字典遍历顺序影响缓存命中）
            let ordered = categoryWeightScaleBps.keys.sorted().map {
                "\($0):\(categoryWeightScaleBps[$0] ?? defaultWeightScaleBps)"
            }
            return "e=\(enabled ? 1 : 0)|i=\(minEvaluationIntervalMillis)|d=\(defaultWeightScaleBps)|s=\(source)|c=\(ordered.joined(separator: ","))"
        }
    }

    // MARK: Armor 根密钥来源

    /// Armor 根密钥的来源枚举。
    internal enum ArmorRootKeySource: String {
        /// 来自进程环境变量
        case environment
        /// 仅为诊断兼容保留。现已不存在回退密钥，
        /// `resolveArmorRootKey()` 永远不会产生该取值。
        case debugFallback
        /// 未提供根密钥（失败即拒绝）
        case missing
        /// 环境变量存在但格式非法（非 32 字节十六进制）
        case invalidEnvironment
    }

    // MARK: Armor 运行时状态

    /// Armor 保护运行时状态。
    internal enum ArmorRuntimeStatus: String {
        /// 未启动
        case inactive
        /// 已成功初始化并生效
        case active
        /// 不可用（缺少密钥或载荷，无法初始化）
        case unavailable
        /// 初始化失败（完整性/锚点校验失败等）
        case failed
    }

    // MARK: Armor 运行时调试快照

    /// Armor 运行时调试快照：对外暴露只读状态，供诊断接口使用。
    internal struct ArmorRuntimeDebugSnapshot {
        /// 状态原始值
        let status: String
        /// 状态原因（如 `initialized`、`missing_root_key`）
        let reason: String
        /// C 层初始化返回码（成功为 0）
        let initCode: Int32?
        /// 触发初始化的位置（start / evaluate / build_envelope）
        let trigger: String
        /// 根密钥来源原始值
        let rootKeySource: String
        /// 是否使用了调试回退密钥（当前恒为 false）
        let debugFallbackUsed: Bool
        /// 锚点数据是否存在
        let anchorPresent: Bool
        /// 初始化尝试次数
        let attemptCount: Int
    }

    // MARK: Anti-Debug 看门狗快照

    /// Anti-Debug 看门狗快照：一次性镜像 C 层看门狗的全部运行指标。
    ///
    /// 字段多为异常计数器（AnomalyCount）与最近一次探测结果，供诊断与信号构建使用；
    /// 结构体为值类型且 `Sendable`，可安全跨线程传递。
    public struct AntiDebugWatchdogSnapshot: Sendable {
        /// C 层是否支持看门狗
        public let supported: Bool
        /// 看门狗线程是否在运行
        public let running: Bool
        /// 看门狗线程是否活跃
        public let threadActive: Bool
        /// 巡检间隔（秒）
        public let intervalSeconds: UInt32
        /// 异常标志位集合（位掩码）
        public let anomalyFlags: UInt32
        /// 累计巡检迭代次数
        public let iterationCount: UInt64
        /// 检测到被跟踪的事件次数
        public let tracedEventCount: UInt64
        /// deny_attach 失败次数
        public let denyAttachErrorCount: UInt64
        /// 异常端口相关异常次数
        public let exceptionAnomalyCount: UInt64
        /// 最近一次 deny_attach 返回值
        public let lastDenyAttachResult: Int32
        /// 最近一次 deny_attach errno
        public let lastDenyAttachErrno: Int32
        /// 最近一次是否检测到被跟踪
        public let lastTraced: Bool
        /// 最近一次异常端口是否健康
        public let lastExceptionPortHealthy: Bool
        /// 最近一次异常端口查询是否成功
        public let lastExceptionQuerySucceeded: Bool
        /// 最近一次是否尝试回收异常端口
        public let lastExceptionReclaimAttempted: Bool
        /// 最近一次是否检测到异常端口被劫持
        public let lastExceptionHijackDetected: Bool
        /// 最近一次是否捕获到早期阶段异常
        public let lastExceptionEarlyPhaseCaptured: Bool
        /// 最近一次是否检测到启动竞态
        public let lastExceptionStartupRaceDetected: Bool
        /// 最近一次异常查询的内核返回值
        public let lastExceptionQueryKernReturn: Int32
        /// 最近一次异常注册的内核返回值
        public let lastExceptionRegisterKernReturn: Int32
        /// 最近一次巡检的单调时钟时间（纳秒）
        public let lastCheckMonotonicNs: UInt64
        /// 异常校验累计次数
        public let lastExceptionVerifyCount: UInt64
        /// 异常端口回收累计次数
        public let lastExceptionReclaimCount: UInt64
        /// 启动阶段耗时（纳秒）
        public let lastExceptionStartupDeltaNs: UInt64
        /// 最近一次信号探针结果
        public let signalProbeResult: Bool
        /// 是否检测到硬件断点
        public let hardwareBpDetected: Bool
        /// 是否检测到软件断点
        public let softwareBreakpointDetected: Bool
        /// csops 是否报告被调试
        public let csopsDebugged: Bool
        /// 可疑线程数量
        public let suspiciousThreadCount: UInt32
        /// 是否检测到单步执行
        public let singleStepDetected: Bool
        /// 是否检测到 TTY
        public let ttyDetected: Bool
        /// 是否检测到开发者磁盘
        public let developerDiskDetected: Bool
        /// 是否检测到异常投递超时
        public let exceptionDeliveryTimeoutDetected: Bool
        /// 异常投递探针是否被处理
        public let exceptionDeliveryProbeHandled: Bool
        /// 最近一次异常投递探针时间（纳秒）
        public let lastExceptionDeliveryProbeNs: UInt64
        /// 信号探针异常累计次数
        public let signalProbeAnomalyCount: UInt64
        /// 硬件断点异常累计次数
        public let hardwareBpAnomalyCount: UInt64
        /// 软件断点异常累计次数
        public let softwareBreakpointAnomalyCount: UInt64
        /// csops 异常累计次数
        public let csopsAnomalyCount: UInt64
        /// 可疑线程异常累计次数
        public let suspiciousThreadAnomalyCount: UInt64
        /// 异常投递超时累计次数
        public let exceptionDeliveryTimeoutAnomalyCount: UInt64
        /// 对等看门狗异常累计次数
        public let peerWatchdogAnomalyCount: UInt64
        /// 影子栈异常累计次数
        public let shadowStackAnomalyCount: UInt64
        /// 最近一次对等看门狗是否停滞
        public let lastPeerWatchdogStalled: Bool
        /// 最近一次影子栈是否不匹配
        public let lastShadowStackMismatch: Bool
        /// 是否检测到 DBI（动态二进制插桩）
        public let dbiDetected: Bool
        /// DBI 标记位
        public let dbiMarkerFlags: UInt32
        /// 时序异常标志位
        public let timingAnomalyFlags: UInt32
        /// 时序探针中位数（纳秒）
        public let timingProbeMedianNs: UInt64
        /// 时序探针最大值（纳秒）
        public let timingProbeMaxNs: UInt64
        /// 时序探针阈值（纳秒）
        public let timingProbeThresholdNs: UInt64
        /// DBI 异常累计次数
        public let dbiAnomalyCount: UInt64
        /// 时序异常累计次数
        public let timingAnomalyCount: UInt64
        /// 函数序言完整性异常累计次数
        public let prologueIntegrityAnomalyCount: UInt64
        /// dyld 注入异常累计次数
        public let dyldInjectionAnomalyCount: UInt64
        /// 最近一次序言校验失败掩码
        public let lastPrologueFailMask: UInt32
        /// 最近一次 dyld 注入标志位
        public let lastDyldInjectionFlags: UInt32
        /// 最近一次 csops 状态标志
        public let lastCsopsStatusFlags: UInt32
        /// 最近一次 AMFI 探针位
        public let lastAmfiProbeBits: UInt32
        /// 最近一次 get-task-allow 可疑标志
        public let lastGetTaskAllowSuspect: Bool
        /// 最近一次 deny_attach 校验位
        public let lastDenyAttachVerifyBits: UInt32
        /// deny_attach 校验异常累计次数
        public let denyAttachVerifyAnomalyCount: UInt64
        /// AMFI 代码签名标志异常累计次数
        public let amfiCsFlagsAnomalyCount: UInt64
        /// get-task-allow 异常累计次数
        public let getTaskAllowAnomalyCount: UInt64
        /// vm_mprotect 交叉校验不匹配累计次数
        public let vmMprotectCrosscheckMismatchTotal: UInt64
        /// vm_mprotect Mach trap 不匹配累计次数
        public let vmMprotectMachTrapMismatchTotal: UInt64
        /// libc 回退使用掩码
        public let libcFallbackUsedMask: UInt32
        /// libc 回退事件累计次数
        public let libcFallbackEventTotal: UInt32
        /// 看门狗启动路径掩码
        public let watchdogStartPathMask: UInt32
        /// 看门狗启动存活检查是否通过
        public let watchdogStartupLivenessOk: Bool
        /// 主线程存活时间（单调时钟纳秒）
        public let mainThreadAliveMonotonicNs: UInt64
        /// 早期注入环境变量掩码
        public let earlyInjectionEnvMask: UInt32
        /// 看门狗扩展异常标志位
        public let watchdogExtendedAnomalyFlags: UInt32
        /// 主线程心跳序号
        public let mainThreadHeartbeatSeq: UInt64
        /// 主线程心跳停滞累计次数
        public let mainThreadHeartbeatStallCount: UInt64
        /// 最近一次主线程心跳是否停滞
        public let lastMainThreadHeartbeatStalled: Bool

        /// 是否存在任一异常（基础异常位或扩展异常位非零）
        public var hasAnyAnomaly: Bool {
            anomalyFlags != 0 || watchdogExtendedAnomalyFlags != 0
        }
    }

    // MARK: Anti-Debug 计划快照

    /// Anti-Debug 计划快照：反映打包期注入的 anti-debug 计划节的解析与应用状态。
    public struct AntiDebugPlanSnapshot: Sendable {
        /// 计划节是否存在
        public let sectionPresent: Bool
        /// 计划节是否有效
        public let sectionValid: Bool
        /// 解析错误码
        public let parseError: UInt32
        /// 计划条目数量
        public let entryCount: UInt32
        /// 策略并集位
        public let policyUnionBits: UInt32
        /// 最近一次应用的策略位
        public let lastAppliedPolicyBits: UInt32
        /// 最近一次探针位
        public let lastProbeBits: UInt32
        /// 最近一次闸门是否关闭
        public let lastGateClosed: Bool
        /// 最近一次是否处于软失败模式
        public let lastSoftFailMode: Bool
        /// 最近一次延迟（纳秒）
        public let lastDelayNs: UInt64
        /// 消费次数
        public let consumeCount: UInt64
        /// 升级次数
        public let escalationCount: UInt64
        /// 陷阱事件次数
        public let trapEventCount: UInt64
        /// 内联补丁次数
        public let inlinePatchCount: UInt64
        /// 内联补丁失败次数
        public let inlinePatchFailureCount: UInt64
        /// 内联补丁是否已武装
        public let inlinePatchArmed: Bool
        /// 内联补丁是否被篡改
        public let inlinePatchTampered: Bool
    }

    // MARK: Armor 根密钥解析结果

    /// Armor 根密钥解析结果：携带密钥数据、来源与失败原因。
    internal struct ArmorRootKeyResolution {
        /// 解析出的 32 字节密钥；失败为 nil
        let keyData: Data?
        /// 密钥来源
        let source: ArmorRootKeySource
        /// 是否使用调试回退（当前恒为 false）
        let debugFallbackUsed: Bool
        /// 失败原因（如 `missing_root_key`、`invalid_root_key_hex`）
        let failureReason: String?
    }

    // MARK: Armor 运行时快照

    /// Armor 运行时快照：记录初始化结果与触发上下文。
    internal struct ArmorRuntimeSnapshot {
        /// 运行时状态
        let status: ArmorRuntimeStatus
        /// 状态原因
        let reason: String
        /// C 层初始化返回码
        let initCode: Int32?
        /// 触发位置
        let trigger: String
        /// 根密钥来源
        let rootKeySource: ArmorRootKeySource
        /// 是否使用调试回退密钥
        let debugFallbackUsed: Bool
        /// 锚点是否存在
        let anchorPresent: Bool
        /// 尝试次数
        let attemptCount: Int

        /// 未启动状态的初始快照
        static let inactive = ArmorRuntimeSnapshot(
            status: .inactive,
            reason: "not_started",
            initCode: nil,
            trigger: "none",
            rootKeySource: .missing,
            debugFallbackUsed: false,
            anchorPresent: false,
            attemptCount: 0
        )
    }

    // MARK: 能力探针运行时结果

    /// 能力探针运行时结果：聚合能力评分与各探针明细。
    internal struct CapabilityProbeRuntimeResult {
        /// 能力评分（异常数、质量怀疑度等）
        let score: CapabilityScore
        /// 各探针执行结果
        let probes: [ProbeResult]
    }
}
