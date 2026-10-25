// 结构化日志与审计追踪：为 SDK 内部提供分级日志、可插拔输出目标和决策审计环形缓冲。
// 日志只承载“可公开的诊断信息”，密钥、明文、指纹原文等敏感数据必须由调用方先脱敏再传入。

import Foundation

// MARK: - 结构化日志系统
//
// 替代原有 4 行 Logger：
// - 支持日志级别（debug/info/warn/error/critical）
// - Release 下保留 warn/error/critical（可选）
// - 支持结构化元数据（key-value）
// - 支持自定义日志输出目标（LogDestination 协议）
// - 支持审计追踪（决策日志）
// - 线程安全

/// 日志级别
/// 数值越大越严重；`Comparable` 让 `minimumLevel` 过滤可以直接用 `>=`。
public enum LogLevel: Int, Comparable, Sendable {
    case debug = 0
    case info = 1
    case warn = 2
    case error = 3
    case critical = 4

    public static func < (lhs: LogLevel, rhs: LogLevel) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    /// 输出到日志行中的固定英文标签，便于服务端按字符串检索。
    var label: String {
        switch self {
        case .debug: return "DEBUG"
        case .info: return "INFO"
        case .warn: return "WARN"
        case .error: return "ERROR"
        case .critical: return "CRITICAL"
        }
    }
}

/// 结构化日志条目
///
/// 脱敏边界：`message` 与 `metadata` 会原样交给所有 destination，调用方必须保证
/// 其中不含密钥、解密后明文、完整设备指纹或用户标识；这里不做也无法做自动脱敏。
public struct LogEntry: Sendable {
    public let timestamp: Date
    public let level: LogLevel
    public let message: String
    /// 结构化键值对；键名建议用稳定英文，值避免高基数与敏感内容。
    public let metadata: [String: String]
    /// 由 `#fileID` 捕获，仅保留模块/文件，不含绝对路径。
    public let file: String
    public let function: String
    public let line: UInt
}

/// 日志输出目标协议 — 实现此协议可自定义日志输出（文件、网络、第三方 SDK 等）
/// - 注意：`write` 在日志热路径上同步调用，实现方不得长时间阻塞；
///   `Logger` 已把调用移到内部锁之外，但实现方仍需自行保证线程安全。
public protocol LogDestination: Sendable {
    func write(_ entry: LogEntry)
}

/// 默认控制台输出
/// 仅在 DEBUG 构建由 `Logger.emit` 调用，Release 不会主动打印到控制台。
struct ConsoleLogDestination: LogDestination {
    private static let dateFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        return f
    }()

    func write(_ entry: LogEntry) {
        let ts = Self.dateFormatter.string(from: entry.timestamp)
        var line = "[\(ts)] [\(entry.level.label)] [CloudPhoneRiskKit] \(entry.message)"
        if !entry.metadata.isEmpty {
            // 对 key 排序，保证同一组元数据每次输出的顺序一致，便于日志比对。
            let meta = entry.metadata.map { "\($0.key)=\($0.value)" }.sorted().joined(separator: " ")
            line += " | \(meta)"
        }
        print(line)
    }
}

/// 审计日志条目 — 记录决策过程的关键步骤
public struct AuditEntry: Sendable {
    public let timestamp: Date
    /// 动作名，例如阈值匹配、降级、开关切换。
    public let action: String
    /// 与动作相关的可公开细节；同样受脱敏边界约束。
    public let details: [String: String]
}

public enum Logger {
    // MARK: - Thread-safe configuration

    // 配置整体打包，读日志时一次性快照，避免多次加锁产生不一致视图。
    private struct Config {
        var isEnabled: Bool
        // Release 下是否放行 warn 及以上级别。
        var releaseLoggingEnabled: Bool
        var minimumLevel: LogLevel
    }

    // 保护 _config；只做短临界区读写，不调用外部代码。
    private static let configLock = UnfairLock()
#if DEBUG
    private static var _config = Config(isEnabled: true, releaseLoggingEnabled: false, minimumLevel: .debug)
#else
    private static var _config = Config(isEnabled: false, releaseLoggingEnabled: false, minimumLevel: .debug)
#endif

    /// 总开关；关闭后所有级别（含审计）都不输出。
    public static var isEnabled: Bool {
        get { configLock.withLock { _config.isEnabled } }
        set { configLock.withLock { _config.isEnabled = newValue } }
    }

    /// Release 下是否保留 warn 及以上级别日志
    public static var releaseLoggingEnabled: Bool {
        get { configLock.withLock { _config.releaseLoggingEnabled } }
        set { configLock.withLock { _config.releaseLoggingEnabled = newValue } }
    }

    /// 最低日志级别
    public static var minimumLevel: LogLevel {
        get { configLock.withLock { _config.minimumLevel } }
        set { configLock.withLock { _config.minimumLevel = newValue } }
    }

    /// 自定义日志输出目标
    /// 写入时先快照数组再在锁外回调，防止用户实现里反向调用 Logger 造成死锁。
    private static var destinations: [LogDestination] = []
    private static let destinationLock = UnfairLock()
    private static let consoleDestination = ConsoleLogDestination()

    /// 审计追踪（环形缓冲区，保留最近 200 条决策日志）
    // 固定上限避免长期运行累积导致内存增长；超出后按最旧优先淘汰。
    private static var auditTrail: [AuditEntry] = []
    private static let auditLock = UnfairLock()
    private static let maxAuditEntries = 200

    // MARK: - 基础日志（兼容原有接口）

    /// 兼容旧接口：按 info 级别记录一条消息；参数是 autoclosure，被过滤时不会求值。
    public static func log(_ message: @autoclosure () -> String) {
        emit(level: .info, message: message())
    }

    // MARK: - 分级日志

    public static func debug(_ message: @autoclosure () -> String, metadata: [String: String] = [:],
                             file: String = #fileID, function: String = #function, line: UInt = #line) {
        emit(level: .debug, message: message(), metadata: metadata, file: file, function: function, line: line)
    }

    public static func info(_ message: @autoclosure () -> String, metadata: [String: String] = [:],
                            file: String = #fileID, function: String = #function, line: UInt = #line) {
        emit(level: .info, message: message(), metadata: metadata, file: file, function: function, line: line)
    }

    public static func warn(_ message: @autoclosure () -> String, metadata: [String: String] = [:],
                            file: String = #fileID, function: String = #function, line: UInt = #line) {
        emit(level: .warn, message: message(), metadata: metadata, file: file, function: function, line: line)
    }

    public static func error(_ message: @autoclosure () -> String, metadata: [String: String] = [:],
                             file: String = #fileID, function: String = #function, line: UInt = #line) {
        emit(level: .error, message: message(), metadata: metadata, file: file, function: function, line: line)
    }

    public static func critical(_ message: @autoclosure () -> String, metadata: [String: String] = [:],
                                file: String = #fileID, function: String = #function, line: UInt = #line) {
        emit(level: .critical, message: message(), metadata: metadata, file: file, function: function, line: line)
    }

    // MARK: - 审计追踪

    /// 记录决策审计条目（评估原因、分数计算、阈值匹配等）
    /// 审计本身也是一条 info 日志，因此同样受总开关与级别过滤影响。
    public static func audit(action: String, details: [String: String] = [:]) {
        let entry = AuditEntry(timestamp: Date(), action: action, details: details)
        auditLock.withLock {
            auditTrail.append(entry)
            // 环形语义：一次可能超出一条，按数量差批量淘汰，避免循环删除。
            if auditTrail.count > maxAuditEntries {
                auditTrail.removeFirst(auditTrail.count - maxAuditEntries)
            }
        }

        emit(level: .info, message: "AUDIT: \(action)", metadata: details)
    }

    /// 获取审计追踪快照
    /// 在锁内复制数组，调用方拿到的是不可变快照，后续写入不会影响它。
    public static func auditSnapshot() -> [AuditEntry] {
        auditLock.withLock { auditTrail }
    }

    /// 清除审计追踪
    public static func clearAuditTrail() {
        auditLock.withLock { auditTrail.removeAll() }
    }

    // MARK: - 目标管理

    /// 添加自定义日志输出目标
    public static func addDestination(_ destination: LogDestination) {
        destinationLock.withLock { destinations.append(destination) }
    }

    /// 移除所有自定义日志输出目标
    public static func removeAllDestinations() {
        destinationLock.withLock { destinations.removeAll() }
    }

    // MARK: - 评估性能度量

    /// 测量闭包执行时间并记录
    /// 使用 `systemUptime`（单调时钟）而非墙钟，避免系统时间调整导致出现负耗时。
    @discardableResult
    public static func measure<T>(_ label: String, _ work: () throws -> T) rethrows -> T {
        let start = ProcessInfo.processInfo.systemUptime
        let result = try work()
        let elapsed = ProcessInfo.processInfo.systemUptime - start
        debug("\(label) completed", metadata: ["duration_ms": String(format: "%.1f", elapsed * 1000)])
        return result
    }

    // MARK: - Internal

    private static func emit(level: LogLevel, message: String, metadata: [String: String] = [:],
                             file: String = #fileID, function: String = #function, line: UInt = #line) {
        // Snapshot config atomically to avoid multiple lock acquisitions per log call
        // 一次加锁取完整配置，保证 isEnabled/minimumLevel 来自同一时刻。
        let cfg = configLock.withLock { _config }
        guard level >= cfg.minimumLevel else { return }

        let shouldLog: Bool
        #if DEBUG
        shouldLog = cfg.isEnabled
        #else
        // Release 默认只允许 warn 及以上，且必须显式开启 releaseLoggingEnabled。
        shouldLog = cfg.isEnabled && cfg.releaseLoggingEnabled && level >= .warn
        #endif

        guard shouldLog else { return }

        let entry = LogEntry(
            timestamp: Date(),
            level: level,
            message: message,
            metadata: metadata,
            file: file,
            function: function,
            line: line
        )

        // 输出到控制台（DEBUG only）
        #if DEBUG
        consoleDestination.write(entry)
        #endif

        // 输出到自定义目标（Release 也可用）
        // 先快照再释放锁后回调：用户 destination 内部若再调用 Logger 也不会自死锁。
        let dests = destinationLock.withLock { destinations }
        for dest in dests {
            dest.write(entry)
        }
    }
}
