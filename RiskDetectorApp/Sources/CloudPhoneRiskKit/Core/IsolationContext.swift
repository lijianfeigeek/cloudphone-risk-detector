// MARK: - IsolationContext —— 多实例进程隔离
//
// 职责：为 CPRiskKit 提供多实例隔离能力，支持 App Extension / Widget 等多进程场景下
// 各进程持有独立的评估状态、Keychain 命名空间和存储路径。
// 安全不变量：不同 context 的 Keychain service 与存储目录互不重叠，避免跨进程数据串用；
// 每个 context 的状态读写均由 `lock` 保护，可安全跨线程访问。
//
// 设计原则：
//   - 每个 IsolationContext 拥有独立的 keychain prefix、存储目录和评估状态
//   - 支持 App Group 共享容器，用于主 App 与 Extension 共享关键配置
//   - CPRiskKit.shared 作为默认 context 保持完全向后兼容
//   - 通过 CPRiskKit.scoped(identifier:group:) 获取进程作用域实例

import Foundation
#if canImport(UIKit)
import UIKit
#endif

// MARK: - 隔离上下文（IsolationContext）

/// 进程隔离上下文：封装单个 CPRiskKit 实例的全部运行时状态。
///
/// 每个 IsolationContext 维护独立的：
/// - Keychain 命名空间（`keychainPrefix`）
/// - 本地存储目录（`storagePath`）
/// - 评估状态缓存
/// - 远程配置引用
///
/// 多进程场景（App Extension、Widget、Keyboard Extension 等）应使用不同 identifier
/// 创建各自的 context，避免 Keychain 和存储路径冲突。
public final class IsolationContext: @unchecked Sendable {

    /// 上下文唯一标识符，用于区分不同进程/实例
    public let identifier: String

    /// App Group 标识（可选），用于跨进程共享配置
    public let appGroupIdentifier: String?

    /// Keychain 项的前缀，确保不同 context 的数据互不干扰
    public let keychainPrefix: String

    /// 独立的存储根路径
    public let storagePath: URL

    /// 评估状态（线程安全，访问需持有 `lock`）
    internal let evaluationState: EvaluationState

    /// 上下文级别的配置快照（访问需持有 `lock`）
    internal var configSnapshot: ContextConfigSnapshot

    /// 保护 `evaluationState`、`configSnapshot` 及摘要读写的互斥锁
    private let lock = NSLock()

    /// 创建隔离上下文。
    ///
    /// 优先使用 App Group 共享容器作为存储根目录；无共享容器时回退到 Caches 目录
    /// （再回退到临时目录），确保 Extension 进程也有可写路径。
    /// - Parameters:
    ///   - identifier: 唯一标识符（推荐使用 reverse-DNS 风格，如 "com.app.keyboard-extension"）
    ///   - appGroupIdentifier: App Group ID（如 "group.com.company.app"），用于共享容器
    public init(identifier: String, appGroupIdentifier: String? = nil) {
        self.identifier = identifier
        self.appGroupIdentifier = appGroupIdentifier
        // 以前缀隔离 Keychain，防止多 context 读到彼此的条目
        self.keychainPrefix = "com.cprisk.\(identifier)"
        self.evaluationState = EvaluationState()
        self.configSnapshot = ContextConfigSnapshot()

        if let groupId = appGroupIdentifier,
           let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupId) {
            self.storagePath = containerURL
                .appendingPathComponent("CloudPhoneRiskKit", isDirectory: true)
                .appendingPathComponent(identifier, isDirectory: true)
        } else {
            // 无 App Group 时使用 Caches；极端情况下回退到临时目录，避免初始化失败
            let cachesURL = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first
                ?? URL(fileURLWithPath: NSTemporaryDirectory())
            self.storagePath = cachesURL
                .appendingPathComponent("CloudPhoneRiskKit", isDirectory: true)
                .appendingPathComponent(identifier, isDirectory: true)
        }

        ensureStorageDirectory()
    }

    // MARK: - 默认上下文

    /// 默认上下文（与 CPRiskKit.shared 绑定），保持向后兼容
    public static let `default` = IsolationContext(identifier: "default")

    // MARK: - 线程安全状态访问

    /// 读取当前评估缓存的报告摘要（线程安全）。
    /// - Returns: 最近一次评估摘要；尚未评估时为 `nil`。
    public var lastEvaluationDigest: String? {
        lock.lock()
        defer { lock.unlock() }
        return evaluationState.lastDigest
    }

    /// 记录评估结果摘要。
    /// - Parameter digest: 报告摘要字符串。
    internal func recordEvaluationDigest(_ digest: String) {
        lock.lock()
        defer { lock.unlock() }
        evaluationState.lastDigest = digest
    }

    /// 更新配置快照。
    /// - Parameter snapshot: 从 CPRiskConfig 提取的配置状态。
    internal func updateConfig(_ snapshot: ContextConfigSnapshot) {
        lock.lock()
        defer { lock.unlock() }
        configSnapshot = snapshot
    }

    /// 读取配置快照。
    /// - Returns: 当前 context 的配置快照副本。
    internal func currentConfig() -> ContextConfigSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return configSnapshot
    }

    // MARK: - App Group 共享状态

    /// 向 App Group 共享容器写入键值对（跨进程共享）。
    ///
    /// 适用于将主 App 的配置或状态同步给 Extension / Widget。
    /// 仅在 `appGroupIdentifier` 非空时生效；写入键会加上 keychain 前缀命名空间。
    /// - Parameters:
    ///   - value: 待写入的值；传 `nil` 等同于移除。
    ///   - key: 业务键名。
    public func setSharedValue(_ value: Any?, forKey key: String) {
        // 没有 App Group 时不落盘，避免误写到标准 UserDefaults
        guard let groupId = appGroupIdentifier else { return }
        let defaults = UserDefaults(suiteName: groupId)
        let namespacedKey = "\(keychainPrefix).\(key)"
        defaults?.set(value, forKey: namespacedKey)
    }

    /// 从 App Group 共享容器读取键值对。
    /// - Parameter key: 业务键名。
    /// - Returns: 存储值；无 App Group 或键不存在时返回 `nil`。
    public func sharedValue(forKey key: String) -> Any? {
        guard let groupId = appGroupIdentifier else { return nil }
        let defaults = UserDefaults(suiteName: groupId)
        let namespacedKey = "\(keychainPrefix).\(key)"
        return defaults?.object(forKey: namespacedKey)
    }

    /// 移除 App Group 共享容器中的键值对。
    /// - Parameter key: 业务键名。
    public func removeSharedValue(forKey key: String) {
        guard let groupId = appGroupIdentifier else { return }
        let defaults = UserDefaults(suiteName: groupId)
        let namespacedKey = "\(keychainPrefix).\(key)"
        defaults?.removeObject(forKey: namespacedKey)
    }

    // MARK: - Keychain 命名空间

    /// 生成带命名空间的 Keychain service 名。
    ///
    /// 不同 context 使用不同的 service 名，确保 Keychain 数据隔离。
    /// - Parameter component: 组件名（如设备 ID、密钥标识）。
    /// - Returns: `keychainPrefix.component` 形式的 service 名。
    public func keychainService(for component: String) -> String {
        "\(keychainPrefix).\(component)"
    }

    /// 生成带命名空间的 Keychain account 名。
    /// - Parameter key: 业务键名。
    /// - Returns: `keychainPrefix.account.key` 形式的 account 名。
    public func keychainAccount(for key: String) -> String {
        "\(keychainPrefix).account.\(key)"
    }

    // MARK: - 存储路径

    /// 返回 context 内的子路径（自动创建目录）。
    /// - Parameter component: 子目录名。
    /// - Returns: 已确保存在的子目录 URL。
    public func storagePath(for component: String) -> URL {
        let path = storagePath.appendingPathComponent(component, isDirectory: true)
        try? FileManager.default.createDirectory(at: path, withIntermediateDirectories: true)
        return path
    }

    /// 返回 context 内的文件路径。
    /// - Parameters:
    ///   - filename: 文件名。
    ///   - component: 可选子目录；提供时文件位于该子目录下。
    /// - Returns: 目标文件 URL（不保证文件存在）。
    public func storageFile(named filename: String, in component: String? = nil) -> URL {
        if let component {
            return storagePath(for: component).appendingPathComponent(filename)
        }
        return storagePath.appendingPathComponent(filename)
    }

    // MARK: - 生命周期

    /// 重置评估状态（用于注销场景或测试）。
    public func resetEvaluationState() {
        lock.lock()
        defer { lock.unlock() }
        evaluationState.reset()
    }

    /// 清除当前 context 的所有本地存储（包含缓存、历史评估数据等）。
    ///
    /// 注意：此操作不可逆，不影响 Keychain 数据和 App Group 共享数据。
    public func clearLocalStorage() {
        try? FileManager.default.removeItem(at: storagePath)
        ensureStorageDirectory()
    }

    // MARK: - 私有方法

    /// 确保存储根目录存在；创建失败时静默忽略（后续写入会再次暴露错误）。
    private func ensureStorageDirectory() {
        try? FileManager.default.createDirectory(at: storagePath, withIntermediateDirectories: true)
    }
}

// MARK: - 评估状态（EvaluationState）

extension IsolationContext {

    /// 评估状态：维护单个 context 内的评估运行时数据。
    ///
    /// 非线程安全，所有访问必须由所属 `IsolationContext.lock` 保护。
    internal final class EvaluationState {
        /// 最近一次评估摘要
        var lastDigest: String?
        /// 上一次评估出现的信号 ID 集合（用于检测信号被绕过/抑制）
        var previousSignalIds: Set<String> = []
        /// 上一次信号的摘要（用于比对信号完整性）
        var previousSignalsDigest: String?
        /// 缓存的报告对象（避免短时间重复构建）
        var cachedReport: AnyObject?
        /// 缓存键（标识缓存对应的配置/场景组合）
        var cachedKey: String?
        /// 最近一次评估时间（Unix 秒）
        var lastEvaluationEpoch: TimeInterval = 0
        /// 累计评估次数
        var evaluationCount: UInt64 = 0

        /// 清空全部评估状态。
        func reset() {
            lastDigest = nil
            previousSignalIds = []
            previousSignalsDigest = nil
            cachedReport = nil
            cachedKey = nil
            lastEvaluationEpoch = 0
            evaluationCount = 0
        }
    }
}

// MARK: - 配置快照（ContextConfigSnapshot）

extension IsolationContext {

    /// 上下文级配置快照：记录从 CPRiskConfig 提取的配置状态。
    internal struct ContextConfigSnapshot {
        /// 是否启用行为检测（默认开启）
        var enableBehaviorDetect: Bool = true
        /// 是否启用网络信号（默认开启）
        var enableNetworkSignals: Bool = true
        /// 是否启用反篡改（默认开启）
        var enableAntiTamper: Bool = true
        /// 是否启用远程配置（默认开启）
        var enableRemoteConfig: Bool = true
        /// 风险阈值（0–100，默认 55）
        var threshold: Double = 55.0
        /// 绑定的账号 ID（可选）
        var boundAccountId: String?
        /// 绑定的业务场景标签（可选）
        var boundSceneTag: String?
        /// 当前会话 ID（可选）
        var sessionId: String?
    }
}

// MARK: - 上下文注册表（ContextRegistry）

extension IsolationContext {

    /// 全局 context 注册表（线程安全）。
    ///
    /// 维护所有已创建的 IsolationContext 实例引用，支持按 identifier 查找。
    /// `CPRiskKit.scoped(identifier:group:)` 使用此注册表确保相同 identifier 只创建一个实例。
    internal static let registry = ContextRegistry()

    /// context 注册表实现：以 identifier 为键、NSLock 保护。
    internal final class ContextRegistry: @unchecked Sendable {
        /// identifier 到 context 的映射
        private var contexts: [String: IsolationContext] = [:]
        /// 保护 `contexts` 的互斥锁
        private let lock = NSLock()

        /// 获取或创建指定 identifier 的 context。
        /// 相同 identifier 始终返回同一实例（singleton per identifier）。
        func getOrCreate(identifier: String, appGroupIdentifier: String?) -> IsolationContext {
            lock.lock()
            defer { lock.unlock() }

            if let existing = contexts[identifier] {
                return existing
            }

            let context = IsolationContext(identifier: identifier, appGroupIdentifier: appGroupIdentifier)
            contexts[identifier] = context
            return context
        }

        /// 按 identifier 查找已注册的 context。
        /// - Returns: 存在的 context；未注册返回 `nil`。
        func get(identifier: String) -> IsolationContext? {
            lock.lock()
            defer { lock.unlock() }
            return contexts[identifier]
        }

        /// 移除指定 identifier 的注册项（不清理其磁盘数据）。
        func remove(identifier: String) {
            lock.lock()
            defer { lock.unlock() }
            contexts.removeValue(forKey: identifier)
        }

        /// 返回所有已注册的 identifier。
        func allIdentifiers() -> [String] {
            lock.lock()
            defer { lock.unlock() }
            return Array(contexts.keys)
        }

        /// 仅用于测试：清空注册表。
        func removeAll() {
            lock.lock()
            defer { lock.unlock() }
            contexts.removeAll()
        }
    }
}

// MARK: - CPRiskKit 作用域工厂

extension CPRiskKit {

    /// 返回指定标识符的进程作用域 IsolationContext。
    ///
    /// 相同 identifier 返回相同实例（singleton per identifier）。
    /// 适用于 App Extension / Widget / Keyboard Extension 等多进程场景。
    ///
    /// ```swift
    /// // 在 Keyboard Extension 中
    /// let context = CPRiskKit.scoped(
    ///     identifier: "keyboard-extension",
    ///     group: "group.com.company.app"
    /// )
    /// // context.keychainPrefix → "com.cprisk.keyboard-extension"
    /// // context.storagePath → <shared-container>/CloudPhoneRiskKit/keyboard-extension/
    /// ```
    ///
    /// - Parameters:
    ///   - identifier: 上下文唯一标识符
    ///   - group: App Group ID（可选），用于跨进程共享状态
    /// - Returns: 与 identifier 绑定的 IsolationContext 实例
    public static func scoped(identifier: String, group: String? = nil) -> IsolationContext {
        IsolationContext.registry.getOrCreate(identifier: identifier, appGroupIdentifier: group)
    }

    /// 返回默认的 IsolationContext（与 CPRiskKit.shared 绑定）。
    ///
    /// 等价于 `IsolationContext.default`，用于不需要多实例隔离的普通场景。
    public static var defaultContext: IsolationContext {
        IsolationContext.default
    }

    /// 列出所有已注册的 context 标识符（调试/诊断用）。
    public static var registeredContextIdentifiers: [String] {
        IsolationContext.registry.allIdentifiers()
    }
}
