// CloudPhoneRiskKit 远端配置提供者：负责拉取、验签、解析、校验并应用 RemoteConfig，
// 同时维护定时轮询、熔断退避、缓存回退与更新/错误监听者。
// 配置进入评分链路前必须通过签名验证、字段范围校验与 Release 安全地板钳制；
// 拉取失败时保留上一份可信配置或回退本地默认配置（fail-closed）。

import Foundation

/// 远端配置提供者。
///
/// 线程模型：内部状态由 `UnfairLock` 保护，可在任意线程调用；URLSession 回调线程
/// 与定时器线程通过同一把锁更新 `_currentConfig`。安全不变量：未通过
/// `ConfigSignatureVerifier` 验签的响应绝不应用、绝不标记为服务端已验证。
public final class RemoteConfigProvider: @unchecked Sendable {
    public typealias ConfigUpdateHandler = @Sendable (RemoteConfig) -> Void
    public typealias ConfigErrorHandler = @Sendable (Error) -> Void

    public let configURL: URL
    /// 定时拉取间隔（秒），默认 3600。
    public let updateInterval: TimeInterval
    /// 缓存有效期（秒），默认 86400；超龄缓存不再用于初始化。
    public let cacheValidityDuration: TimeInterval
    /// 是否启用远端拉取；关闭时始终使用 fallback/缓存配置。
    public let remoteEnabled: Bool

    private let lock = UnfairLock()
    private var _currentConfig: RemoteConfig
    private var _isFetching = false
    private let cache: ConfigCaching
    private let fallbackConfig: RemoteConfig
    private var urlSession: URLSession
    private var updateHandlers: [UUID: ConfigUpdateHandler] = [:]
    private var errorHandlers: [UUID: ConfigErrorHandler] = [:]
    private var timer: Timer?
    // 连续失败计数，用于熔断判定。
    private var _consecutiveFailures: Int = 0
    // 熔断打开截止时间（Unix 秒）；当前时间小于该值时跳过拉取。
    private var _circuitOpenUntil: TimeInterval = 0
    // 最近一次成功拉取的 Unix 时间戳（秒）；0 表示从未成功。
    private var _lastSuccessfulFetchTime: TimeInterval = 0
    // 配置“陈旧”判定阈值（秒），默认等于缓存有效期。
    private var _configStalenessThreshold: TimeInterval
    // 标记定时器正在异步调度中，防止主线程/后台线程重复创建 Timer。
    private var _schedulingTimer: Bool = false
    // 连续失败达到 3 次打开熔断。
    private static let circuitBreakerThreshold: Int = 3
    // 熔断冷却时间阶梯（秒）：失败越多退避越久，避免持续打爆配置服务。
    private static let circuitBreakerCooldowns: [TimeInterval] = [30, 60, 120, 300]

    /// 当前生效配置；读取受锁保护。
    public var currentConfig: RemoteConfig {
        lock.withLock { _currentConfig }
    }

    /// 是否有拉取请求正在进行。
    public var isFetching: Bool {
        lock.withLock { _isFetching }
    }

    /// 配置是否已超过陈旧阈值；从未成功拉取时视为陈旧。
    public var isConfigStale: Bool {
        lock.withLock {
            guard _lastSuccessfulFetchTime > 0 else { return true }
            return Date().timeIntervalSince1970 - _lastSuccessfulFetchTime > _configStalenessThreshold
        }
    }

    /// 当前配置年龄（秒）；从未成功拉取时返回 `.infinity`。
    public var configAge: TimeInterval {
        lock.withLock {
            guard _lastSuccessfulFetchTime > 0 else { return .infinity }
            return Date().timeIntervalSince1970 - _lastSuccessfulFetchTime
        }
    }

    /// 创建提供者。
    /// - Parameters:
    ///   - configURL: 配置下发地址。
    ///   - updateInterval: 轮询间隔，默认 1 小时。
    ///   - cacheValidityDuration: 缓存有效期，默认 24 小时。
    ///   - remoteEnabled: 是否启用远端拉取。
    ///   - cache: 配置缓存实现。
    ///   - fallbackConfig: 无可用缓存时的本地兜底配置。
    ///   - pinnedPinMaterial: 证书 pin 材料；为空时拉取会直接失败。
    public init(
        configURL: URL,
        updateInterval: TimeInterval = 3600,
        cacheValidityDuration: TimeInterval = 86400,
        remoteEnabled: Bool = true,
        cache: ConfigCaching = ConfigCache.shared,
        fallbackConfig: RemoteConfig = .default,
        pinnedPinMaterial: PinnedCertificatePinMaterial = .empty
    ) {
        self.configURL = configURL
        self.updateInterval = updateInterval
        self.cacheValidityDuration = cacheValidityDuration
        self.remoteEnabled = remoteEnabled
        self.cache = cache
        self.fallbackConfig = fallbackConfig
        self._configStalenessThreshold = cacheValidityDuration
        self.urlSession = CertificatePinningSessionDelegate.pinnedSession(
            pinMaterial: pinnedPinMaterial,
            // 空 pin 时也不回落系统 CA：pin 未配置时拉取直接失败（delegate 取消
            // 挑战），调用方使用本地默认配置。绝不“无 pin 即信任系统 CA”，
            // 否则攻击者只需让 pin 配置丢失即可用任意 CA 证书劫持远程配置。
            allowsSystemCA: false
        )

        if let cached = cache.load(), !cached.isExpired(duration: cacheValidityDuration) {
            // 仅接受未过期缓存；Release 下缓存层已保证条目可信。
            self._currentConfig = Self.releaseHardenedConfig(cached.config)
            self._lastSuccessfulFetchTime = cached.cachedAt
        } else {
            // 无缓存/缓存过期时使用本地默认配置，保证检测链路始终可运行。
            self._currentConfig = fallbackConfig
        }

        if remoteEnabled {
            startPeriodicUpdates()
        }
    }

    deinit {
        timer?.invalidate()
    }

    /// 运行时替换证书 pin 材料并重建 URLSession。
    /// - Note: 新会话同样禁止回落系统 CA，pin 未配置时拉取失败而不是静默信任。
    public func configurePinning(pinMaterial: PinnedCertificatePinMaterial) {
        lock.withLock {
            urlSession.invalidateAndCancel()
            urlSession = CertificatePinningSessionDelegate.pinnedSession(
                pinMaterial: pinMaterial,
                allowsSystemCA: false
            )
        }
    }

    /// Builds digest-backed material from pin strings (invalid entries ignored).
    /// 从 pin 字符串构建摘要材料；非法条目被忽略，可能得到空 pin 集合。
    public func configurePinning(hashes: Set<String>) {
        configurePinning(pinMaterial: PinnedCertificatePinMaterial(pinStrings: hashes))
    }

    /// 重新从缓存加载配置并同步信任状态。
    /// 用于配置陈旧/周期更新失败后的降级：缓存不可用时回落到本地默认配置。
    public func reloadCachedConfigTrustState() {
        if let cached = cache.load(), !cached.isExpired(duration: cacheValidityDuration) {
            applyConfig(Self.releaseHardenedConfig(cached.config))
            lock.withLock {
                _lastSuccessfulFetchTime = cached.cachedAt
            }
        } else {
            applyConfig(fallbackConfig)
        }
    }

    /// 拉取最新配置并异步回调。
    /// - 处理顺序：熔断检查 → 单飞去重 → HTTP 请求 → 签名验证 → 解析/范围校验 →
    ///   Release 安全地板钳制 → 应用、缓存并通知监听者。
    /// - 失败语义：任何一步失败都不会替换当前配置；错误通过 `completion`
    ///   和已注册的 error handler 上报，连续失败达到阈值后打开熔断。
    /// - Parameter completion: 成功返回已应用的配置；失败返回 `ConfigError`。
    public func fetchLatest(completion: @escaping @Sendable (Result<RemoteConfig, ConfigError>) -> Void) {
        guard remoteEnabled else {
            // 关闭远端时直接返回当前配置，保证调用方拿到确定结果。
            completion(.success(currentConfig))
            return
        }

        if isCircuitOpen() {
            // 熔断期内不发起网络请求，直接复用当前配置，避免放大故障。
            Logger.log("remote_config.circuit_breaker: open, skipping fetch")
            completion(.success(currentConfig))
            return
        }

        // 单飞：同一时刻只允许一个拉取任务，重复调用返回 nil。
        let session: URLSession? = lock.withLock {
            if _isFetching {
                return nil
            }
            _isFetching = true
            return urlSession
        }

        guard let session else {
            completion(.failure(.alreadyFetching))
            return
        }

        var request = URLRequest(url: configURL)
        request.httpMethod = "GET"
        // 忽略本地 URL 缓存，防止代理/缓存层返回旧配置绕过版本与签名校验。
        request.cachePolicy = .reloadIgnoringLocalCacheData
        // 15 秒超时：配置拉取不应长时间阻塞定时器或调用方。
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("CloudPhoneRiskKit/2.0", forHTTPHeaderField: "User-Agent")

        session.dataTask(with: request) { [weak self] data, response, error in
            guard let self else {
                completion(.failure(.providerDeallocated))
                return
            }

            defer {
                self.lock.withLock { self._isFetching = false }
            }

            if let error {
                let wrapped = ConfigError.networkError(underlying: error)
                self.recordFailure()
                self.handleError(wrapped)
                completion(.failure(wrapped))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                self.recordFailure()
                self.handleError(ConfigError.invalidResponse)
                completion(.failure(.invalidResponse))
                return
            }

            guard httpResponse.statusCode == 200 else {
                let wrapped = ConfigError.httpError(statusCode: httpResponse.statusCode)
                self.recordFailure()
                self.handleError(wrapped)
                completion(.failure(wrapped))
                return
            }

            guard let data else {
                self.recordFailure()
                self.handleError(ConfigError.emptyResponse)
                completion(.failure(.emptyResponse))
                return
            }

            let signatureHex = httpResponse.value(forHTTPHeaderField: "X-Config-Signature") ?? ""
            // 签名验证必须先于解析：未验签的数据不进入配置模型，更不能落入评分链路。
            let verification = ConfigSignatureVerifier.verify(payload: data, signatureHex: signatureHex)
            if !verification.isValid {
                let wrapped = ConfigError.signatureVerificationFailed(reason: verification.reason ?? "unknown")
                self.recordFailure()
                self.handleError(wrapped)
                completion(.failure(wrapped))
                return
            }

            do {
                let config = Self.releaseHardenedConfig(try self.parseAndValidate(data: data))
                self.applyConfig(config)
                // 只有密钥已配置且本次验签成功，缓存条目才能标记为“服务端已验证”。
                let verifiedByServer = ConfigSignatureVerifier.isConfigured && verification.isValid
                if !verifiedByServer {
                    Logger.log("remote_config: server signing key not configured, cache entry will be marked unverified")
                }
                self.cache.save(config, verifiedByServer: verifiedByServer)
                self.lock.withLock { self._lastSuccessfulFetchTime = Date().timeIntervalSince1970 }
                self.notifyUpdate(config)
                self.recordSuccess()
                completion(.success(config))
            } catch let configError as ConfigError {
                self.recordFailure()
                self.handleError(configError)
                completion(.failure(configError))
            } catch {
                let wrapped = ConfigError.decodeFailed(underlying: error)
                self.recordFailure()
                self.handleError(wrapped)
                completion(.failure(wrapped))
            }
        }.resume()
    }

    /// 注册配置更新回调。
    /// - Returns: 持有回调的 `Token`；释放/调用 `unregister()` 前回调一直有效。
    @discardableResult
    public func registerUpdate(handler: @escaping ConfigUpdateHandler) -> Token {
        lock.withLock {
            let id = UUID()
            updateHandlers[id] = handler
            return Token(id: id, owner: self)
        }
    }

    /// 注册配置错误回调，用于监控拉取/验签/校验失败。
    @discardableResult
    public func registerErrorHandler(handler: @escaping ConfigErrorHandler) -> Token {
        lock.withLock {
            let id = UUID()
            errorHandlers[id] = handler
            return Token(id: id, owner: self)
        }
    }

    /// 注销更新/错误回调（按 token 同时尝试两条链路移除）。
    public func unregister(token: Token) {
        lock.withLock {
            updateHandlers.removeValue(forKey: token.id)
            errorHandlers.removeValue(forKey: token.id)
        }
    }

    /// 熔断器当前是否处于打开状态。
    public var isCircuitBreakerOpen: Bool {
        isCircuitOpen()
    }

    /// 手动回退到本地默认配置（例如收到紧急 kill switch 指令时）。
    public func resetToFallback() {
        applyConfig(fallbackConfig)
    }

    /// 查询指定实验的分流结果；无匹配实验/已过期时返回 `nil`。
    public func experimentConfig(for experimentKey: String, deviceID: String) -> ExperimentVariant? {
        currentConfig.experiments.config(for: experimentKey, deviceID: deviceID)
    }

    /// 设备 ID 是否命中白名单。
    public func isWhitelisted(deviceID: String) -> Bool {
        currentConfig.whitelist.contains(deviceID: deviceID)
    }

    /// 设备 ID 是否命中黑名单。
    public func isBlacklisted(deviceID: String) -> Bool {
        currentConfig.whitelist.isBlacklisted(deviceID: deviceID)
    }

    /// 熔断判定：连续失败 ≥ 3 且仍在冷却窗口内时打开。
    private func isCircuitOpen() -> Bool {
        lock.withLock {
            guard _consecutiveFailures >= Self.circuitBreakerThreshold else { return false }
            return Date().timeIntervalSince1970 < _circuitOpenUntil
        }
    }

    /// 拉取成功：清零失败计数并关闭熔断。
    private func recordSuccess() {
        lock.withLock {
            _consecutiveFailures = 0
            _circuitOpenUntil = 0
        }
    }

    /// 记录一次失败；达到阈值后按失败次数选择冷却阶梯。
    private func recordFailure() {
        lock.withLock {
            _consecutiveFailures += 1
            if _consecutiveFailures >= Self.circuitBreakerThreshold {
                // 冷却索引随失败次数递增并封顶，实现 30s → 60s → 120s → 300s 退避。
                let cooldownIndex = min(_consecutiveFailures - Self.circuitBreakerThreshold, Self.circuitBreakerCooldowns.count - 1)
                let cooldown = Self.circuitBreakerCooldowns[cooldownIndex]
                _circuitOpenUntil = Date().timeIntervalSince1970 + cooldown
                Logger.log("remote_config.circuit_breaker: open for \(cooldown)s (failures=\(_consecutiveFailures))")
            }
        }
    }

    /// 解码并校验远端配置。
    /// 校验顺序：版本号 → 必填字段范围 → 全局范围 → 安全下限。
    /// 任何一项不通过都会抛错，配置不会被应用。
    private func parseAndValidate(data: Data) throws -> RemoteConfig {
        let decoder = JSONDecoder()
        let config = try decoder.decode(RemoteConfig.self, from: data)
        let validator = ConfigValidator()
        try validator.validateVersion(config.version)
        try validator.validateRequiredFields(config)
        try validator.validateRanges(config)
        try validator.validateSecurity(config)
        return config
    }

    /// 在锁保护下替换当前配置。
    private func applyConfig(_ config: RemoteConfig) {
        lock.withLock {
            _currentConfig = config
        }
    }

    /// Release 构建对配置做安全地板钳制；DEBUG 保留原始值以便联调。
    private static func releaseHardenedConfig(_ config: RemoteConfig) -> RemoteConfig {
#if DEBUG
        return config
#else
        return config.enforcingReleaseSecurityFloor()
#endif
    }

    /// 在主线程之外逐个回调更新监听者；单个 autoreleasepool 控制临时对象峰值。
    private func notifyUpdate(_ config: RemoteConfig) {
        let handlers = lock.withLock { Array(updateHandlers.values) }
        for handler in handlers {
            autoreleasepool {
                handler(config)
            }
        }
    }

    /// 通知所有错误监听者。
    private func handleError(_ error: Error) {
        let handlers = lock.withLock { Array(errorHandlers.values) }
        for handler in handlers {
            autoreleasepool {
                handler(error)
            }
        }
    }

    /// 启动周期拉取 Timer（RunLoop.main + .common 模式，滚动时仍可触发）。
    /// 通过 `_schedulingTimer` 与锁内二次检查避免并发调度产生重复 Timer。
    private func startPeriodicUpdates() {
        // 用 _schedulingTimer 标记"已提交调度"，防止在 async 派发期间被重复调用
        let interval: TimeInterval? = lock.withLock {
            guard timer == nil && !_schedulingTimer else { return nil }
            _schedulingTimer = true
            return updateInterval
        }
        guard let interval else { return }

        let schedule: () -> Void = { [weak self] in
            guard let self else { return }
            self.lock.withLock {
                // 二次检查：确保 Timer 仍未被创建（防止两次 async 同时执行）
                guard self.timer == nil else { return }
                let t = Timer(timeInterval: interval, repeats: true) { [weak self] _ in
                    guard let self else { return }
                    self.fetchLatest { result in
                        if case .failure(let error) = result {
                            Logger.log("remote_config.periodic_update failed: \(error.localizedDescription)")
                            if self.isConfigStale {
                                // 配置超龄且更新失败：尝试回读缓存，必要时回落到本地默认配置。
                                Logger.log("remote_config: config is stale (age=\(Int(self.configAge))s), falling back to default")
                                self.reloadCachedConfigTrustState()
                            }
                        }
                    }
                }
                RunLoop.main.add(t, forMode: .common)
                self.timer = t
                self._schedulingTimer = false
            }
        }
        if Thread.isMainThread {
            schedule()
        } else {
            DispatchQueue.main.async(execute: schedule)
        }
    }

    /// 回调注册凭据；持有者可通过 `unregister()` 主动注销。
    public struct Token {
        fileprivate let id: UUID
        // 弱引用 owner，避免 Token 延长 Provider 生命周期。
        fileprivate weak var owner: RemoteConfigProvider?

        public func unregister() {
            owner?.unregister(token: self)
        }
    }
}

/// 远端配置校验器：在应用配置前拦截越界值与危险降级。
private struct ConfigValidator {
    /// 版本号必须非负；负版本号通常意味着伪造或编码错误。
    func validateVersion(_ version: Int) throws {
        guard version >= 0 else {
            throw ConfigError.invalidVersion(version: version)
        }
    }

    /// 必填阈值必须落在 0…100，否则评分语义失效。
    func validateRequiredFields(_ config: RemoteConfig) throws {
        guard config.policy.threshold >= 0 && config.policy.threshold <= 100 else {
            throw ConfigError.invalidRange(field: "policy.threshold", value: config.policy.threshold)
        }

        guard config.detector.jailbreakThreshold >= 0 && config.detector.jailbreakThreshold <= 100 else {
            throw ConfigError.invalidRange(field: "detector.jailbreakThreshold", value: config.detector.jailbreakThreshold)
        }
    }

    /// 时间窗口必须为正；实验流量比例必须落在 0…1。
    func validateRanges(_ config: RemoteConfig) throws {
        guard config.policy.timeWindow > 0 else {
            throw ConfigError.invalidRange(field: "policy.timeWindow", value: config.policy.timeWindow)
        }

        for experiment in config.experiments.active {
            guard experiment.traffic >= 0 && experiment.traffic <= 1 else {
                throw ConfigError.invalidRange(field: "experiment.traffic", value: experiment.traffic)
            }
        }
    }

    /// 安全下限常量（防止远程配置将阈值调至 0 从而关闭检测）
    private static let minimumPolicyThreshold: Double = 15
    private static let minimumJailbreakThreshold: Double = 10
    /// BehaviorThresholds 最大行为分下限（防止通过 maxBehaviorScore=0 废掉行为检测）
    private static let minimumMaxBehaviorScore: Double = 10

    /// 安全下限校验：即使签名合法，也不允许远程把检测能力调到失效。
    /// 覆盖白名单规模、策略阈值、越狱阈值与行为分上限四类安全敏感字段。
    func validateSecurity(_ config: RemoteConfig) throws {
        // 白名单过大会显著增加匹配开销并可能被用来批量放行设备。
        if config.whitelist.deviceIDs.count > 10000 {
            throw ConfigError.validationFailed(
                underlying: NSError(domain: "RemoteConfigProvider", code: -1, userInfo: [
                    NSLocalizedDescriptionKey: "whitelist size too large"
                ])
            )
        }

        // 阈值下限保护：阻止远程配置通过极高阈值变相关闭所有检测
        if config.policy.threshold < Self.minimumPolicyThreshold {
            throw ConfigError.validationFailed(
                underlying: NSError(domain: "RemoteConfigProvider", code: -2, userInfo: [
                    NSLocalizedDescriptionKey: "policy.threshold \(config.policy.threshold) below security floor \(Self.minimumPolicyThreshold)"
                ])
            )
        }

        if config.detector.jailbreakThreshold < Self.minimumJailbreakThreshold {
            throw ConfigError.validationFailed(
                underlying: NSError(domain: "RemoteConfigProvider", code: -3, userInfo: [
                    NSLocalizedDescriptionKey: "detector.jailbreakThreshold \(config.detector.jailbreakThreshold) below security floor \(Self.minimumJailbreakThreshold)"
                ])
            )
        }

        // BehaviorThresholds 下限保护：防止攻击者通过篡改远程配置废掉行为评分
        if let bt = config.detector.behaviorThresholds {
            if bt.maxBehaviorScore < Self.minimumMaxBehaviorScore {
                throw ConfigError.validationFailed(
                    underlying: NSError(domain: "RemoteConfigProvider", code: -4, userInfo: [
                        NSLocalizedDescriptionKey: "behaviorThresholds.maxBehaviorScore \(bt.maxBehaviorScore) below security floor \(Self.minimumMaxBehaviorScore)"
                    ])
                )
            }
        }
    }
}

/// 远端配置拉取/校验错误。
///
/// `signatureVerificationFailed` 属于安全关键错误：出现时当前配置保持不变，
/// 调用方应记录告警而不是继续使用未验证响应。
public enum ConfigError: Error, LocalizedError {
    case alreadyFetching
    case providerDeallocated
    case networkError(underlying: Error)
    case httpError(statusCode: Int)
    case invalidResponse
    case emptyResponse
    case decodeFailed(underlying: Error)
    case invalidVersion(version: Int)
    case invalidRange(field: String, value: Any)
    case validationFailed(underlying: Error)
    case cacheError(underlying: Error)
    case signatureVerificationFailed(reason: String)

    /// 面向用户/日志的中文本地化描述。
    public var errorDescription: String? {
        switch self {
        case .alreadyFetching:
            return "配置正在拉取中，请勿重复请求"
        case .providerDeallocated:
            return "配置提供者已被释放"
        case .networkError(let error):
            return "网络请求失败: \(error.localizedDescription)"
        case .httpError(let statusCode):
            return "HTTP 错误: \(statusCode)"
        case .invalidResponse:
            return "无效的响应"
        case .emptyResponse:
            return "空响应"
        case .decodeFailed(let error):
            return "配置解析失败: \(error.localizedDescription)"
        case .invalidVersion(let version):
            return "无效的配置版本: \(version)"
        case .invalidRange(let field, let value):
            return "配置字段 \(field) 的值超出范围: \(value)"
        case .validationFailed(let error):
            return "配置验证失败: \(error.localizedDescription)"
        case .cacheError(let error):
            return "缓存错误: \(error.localizedDescription)"
        case .signatureVerificationFailed(let reason):
            return "配置签名验证失败: \(reason)"
        }
    }
}
