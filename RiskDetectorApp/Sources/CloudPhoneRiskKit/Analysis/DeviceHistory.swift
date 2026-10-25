// 设备历史存储：把每次检测的聚合结论（风险分数、越狱/VPN 状态、行为摘要）按设备落盘，
// 供时序特征、行为基线、异常检测跨会话使用。隐私边界：只存聚合值与稳定设备 ID，
// 不存原始触摸坐标、运动序列或网络标识；落盘前加密 + HMAC，受 Data Protection 保护。
import Foundation

// MARK: - 设备检测快照
/// 单次检测的完整快照，包含所有检测信号（均为聚合结论，不含原始样本）。
public struct DeviceDetectionSnapshot: Codable, Sendable {
  /// 检测时间戳（Unix 时间）
  public var timestamp: TimeInterval

  /// 设备 ID（来自 Keychain，跨卸载重装稳定；本身不直接上报明文）
  public var deviceID: String

  /// 当次风险分数（0–100，口径由 RiskScorer 决定）
  public var riskScore: Double

  /// 是否命中高风险阈值
  public var isHighRisk: Bool

  /// 越狱检测结果
  public var jailbreakStatus: JailbreakStatus

  /// VPN 是否激活
  public var isVPNActive: Bool

  /// 代理是否启用
  public var isProxyEnabled: Bool

  /// 行为信号摘要（仅统计量）；未启用行为采集时为 nil
  public var behaviorSummary: BehaviorSummary?

  /// 网络接口类型（如 wifi/cellular）
  public var networkInterfaceType: String

  /// libc/直系统调用回退观测到的命中位掩码（十六进制）；无观测时为 nil
  public var libcFallbackMaskHex: String?

  /// libc 回退通知的单调累计次数；仅在该能力可用时有值
  public var libcFallbackEventTotal: UInt32?

  /// 采集回退观测时 watchdog 快照路径是否受支持；用于区分“未命中”与“能力缺失”
  public var libcFallbackWatchdogSupported: Bool?

  // 短键名压缩落盘体积；键名为持久化契约。
  private enum CodingKeys: String, CodingKey {
    case timestamp = "ts"
    case deviceID = "di"
    case riskScore = "rs"
    case isHighRisk = "hr"
    case jailbreakStatus = "js"
    case isVPNActive = "va"
    case isProxyEnabled = "pe"
    case behaviorSummary = "bs"
    case networkInterfaceType = "ni"
    case libcFallbackMaskHex = "lfm"
    case libcFallbackEventTotal = "lfe"
    case libcFallbackWatchdogSupported = "lfs"
  }

  public init(
    timestamp: TimeInterval,
    deviceID: String,
    riskScore: Double,
    isHighRisk: Bool,
    jailbreakStatus: JailbreakStatus,
    isVPNActive: Bool,
    isProxyEnabled: Bool,
    behaviorSummary: BehaviorSummary? = nil,
    networkInterfaceType: String,
    libcFallbackMaskHex: String? = nil,
    libcFallbackEventTotal: UInt32? = nil,
    libcFallbackWatchdogSupported: Bool? = nil
  ) {
    self.timestamp = timestamp
    self.deviceID = deviceID
    self.riskScore = riskScore
    self.isHighRisk = isHighRisk
    self.jailbreakStatus = jailbreakStatus
    self.isVPNActive = isVPNActive
    self.isProxyEnabled = isProxyEnabled
    self.behaviorSummary = behaviorSummary
    self.networkInterfaceType = networkInterfaceType
    self.libcFallbackMaskHex = libcFallbackMaskHex
    self.libcFallbackEventTotal = libcFallbackEventTotal
    self.libcFallbackWatchdogSupported = libcFallbackWatchdogSupported
  }

  /// 从 RiskSnapshot 和 RiskScoreReport 创建快照。
  /// 只搬运已有结论字段，不做二次推断；时间戳使用当前时间，保证历史顺序可重建。
  public static func from(snapshot: RiskSnapshot, report: RiskScoreReport)
    -> DeviceDetectionSnapshot
  {
    let now = Date().timeIntervalSince1970
    // 仅当回退检测确实命中时才记录相关字段，避免把“能力不可用”写成“无异常”。
    let fallbackObserved = snapshot.libcFallbackUsedMask != 0

    return DeviceDetectionSnapshot(
      timestamp: now,
      deviceID: snapshot.deviceID,
      riskScore: report.score,
      isHighRisk: report.isHighRisk,
      jailbreakStatus: JailbreakStatus(
        isJailbroken: snapshot.jailbreak.isJailbroken,
        confidence: snapshot.jailbreak.confidence,
        detectedMethods: snapshot.jailbreak.detectedMethods
      ),
      isVPNActive: snapshot.network.isVPNActive,
      isProxyEnabled: snapshot.network.proxyEnabled,
      behaviorSummary: BehaviorSummary(from: snapshot.behavior),
      networkInterfaceType: snapshot.network.interfaceType.value,
      libcFallbackMaskHex: fallbackObserved ? String(snapshot.libcFallbackUsedMask, radix: 16) : nil,
      libcFallbackEventTotal: fallbackObserved ? snapshot.libcFallbackEventTotal : nil,
      libcFallbackWatchdogSupported: fallbackObserved ? snapshot.antiDebugWatchdogSupported : nil
    )
  }
}

// MARK: - 越狱状态摘要
/// 单次越狱检测的聚合结果。
/// 只记录命中方法与置信度，不保存检测过程中的文件路径/进程名等原始证据。
public struct JailbreakStatus: Codable, Sendable {
  /// 是否判定越狱
  public var isJailbroken: Bool
  /// 判定置信度，0...1
  public var confidence: Double
  /// 命中的检测方法标识（用于趋势与排查）
  public var detectedMethods: [String]

  // 短键名压缩落盘体积。
  private enum CodingKeys: String, CodingKey {
    case isJailbroken = "ij"
    case confidence = "c"
    case detectedMethods = "dm"
  }

  public init(isJailbroken: Bool, confidence: Double, detectedMethods: [String]) {
    self.isJailbroken = isJailbroken
    self.confidence = confidence
    self.detectedMethods = detectedMethods
  }
}

// MARK: - 行为摘要
/// 行为信号的持久化摘要，是 DeviceHistory 中唯一与行为相关的数据。
/// 隐私边界：只保留计数与相关系数，原始触摸点、时间戳序列、加速度序列都不落盘。
public struct BehaviorSummary: Codable, Sendable {
  /// 触摸点采样数
  public var touchSampleCount: Int
  /// 点击次数
  public var tapCount: Int
  /// 滑动次数
  public var swipeCount: Int
  /// 运动采样条数
  public var motionSampleCount: Int
  /// 动作总数（点击 + 滑动）
  public var actionCount: Int
  /// 触摸-运动 Pearson 相关系数；任一侧样本不足时为 nil
  public var touchMotionCorrelation: Double?

  // 短键名压缩落盘体积。
  private enum CodingKeys: String, CodingKey {
    case touchSampleCount = "tc"
    case tapCount = "tp"
    case swipeCount = "sw"
    case motionSampleCount = "ms"
    case actionCount = "ac"
    case touchMotionCorrelation = "tm"
  }

  public init(from signals: BehaviorSignals) {
    self.touchSampleCount = signals.touch.sampleCount
    self.tapCount = signals.touch.tapCount
    self.swipeCount = signals.touch.swipeCount
    self.motionSampleCount = signals.motion.sampleCount
    self.actionCount = signals.actionCount
    self.touchMotionCorrelation = signals.touchMotionCorrelation
  }
}

// MARK: - 历史查询结果
/// 查询返回的快照集合及其元信息。
public struct HistoryQueryResult: Sendable {
  public var snapshots: [DeviceDetectionSnapshot]
  /// 返回条数
  public var totalCount: Int
  /// 实际覆盖的时间范围；空结果时为 nil
  public var timeRange: (start: TimeInterval, end: TimeInterval)?

  public init(
    snapshots: [DeviceDetectionSnapshot], timeRange: (start: TimeInterval, end: TimeInterval)? = nil
  ) {
    self.snapshots = snapshots
    self.totalCount = snapshots.count
    self.timeRange = timeRange
  }
}

// MARK: - 设备历史存储
/// 负责设备检测快照的存储、查询和清理。
///
/// 持久化设计：
/// - 位置：ApplicationSupport（首选）→ Caches → tmp，均加 `FileProtectionType.complete`；
/// - 机密性：整体 JSON 经 `PayloadCrypto` 加密（DEBUG 下允许明文回退，便于本地调试）；
/// - 完整性：另存 HMAC 签名，校验失败即清空，防止外部篡改历史以绕过风控；
/// - 回滚防护：FreshnessAnchor（Keychain）记录最新时间戳与单调序号，磁盘版本落后即丢弃；
/// - 容量：最多 500 条、最多保留 30 天，超出按时间裁剪。
///
/// 线程模型：所有状态由 `NSLock` 保护；文件 I/O 与 Keychain 访问也在锁内完成，
/// 因此写入使用 utility 队列异步执行，避免阻塞评估主链路。
public final class DeviceHistory {
  public static let shared = DeviceHistory()

  /// 落盘信封：在快照数组外增加 schema 版本与新鲜度信息，便于演进与回滚检测。
  private struct StoredEnvelope: Codable {
    var schemaVersion: Int
    var snapshots: [DeviceDetectionSnapshot]
    var latestTimestamp: Double
    /// 单调递增序号，与 latestTimestamp 一起构成新鲜度锚点
    var sequence: UInt64

    // 短键名压缩落盘体积。
    private enum CodingKeys: String, CodingKey {
      case schemaVersion = "sv"
      case snapshots = "sn"
      case latestTimestamp = "lt"
      case sequence = "sq"
    }
  }

  // NSLock：锁内包含文件 I/O 与 Keychain 访问，因此不使用自旋锁，避免长时间占用 CPU。
  private let lock = NSLock()  // NSLock：锁内包含文件 I/O 与 Keychain 访问
  private let fileManager = FileManager.default
  private let storeURL: URL
  private let hmacURL: URL
  // HMAC 用途标签，防止同一密钥在不同业务间被交叉复用。
  private let hmacPurpose = "device_history"
  private let freshnessAnchor = FreshnessAnchor(account: "device_history_v2_freshness")

  // 内存与磁盘共同的条数上限，防止历史无限增长。
  private let maxSnapshots = 500

  /// 快照最大保留时间（30天）：覆盖月度模式分析，同时限制隐私数据留存周期
  private let maxAgeSeconds: TimeInterval = 30 * 24 * 3600

  /// 内存缓存（已加载并可能被裁剪）
  private var cachedSnapshots: [DeviceDetectionSnapshot] = []
  private var cachedFreshness: FreshnessState = .zero

  /// 缓存是否脏（需要持久化）；只有脏数据才触发异步写盘
  private var isDirty = false

  private init() {
    let storageDirectory = Self.resolveStorageDirectory(fileManager: fileManager)
    do {
      // .complete：设备锁屏后文件不可读，降低历史被离线提取的风险。
      try fileManager.createDirectory(
        at: storageDirectory,
        withIntermediateDirectories: true,
        attributes: [FileAttributeKey.protectionKey: FileProtectionType.complete]
      )
    } catch {
      Logger.log(
        "DeviceHistory: failed to create storage directory - \(error.localizedDescription)")
    }
    self.storeURL = storageDirectory.appendingPathComponent("cloudphone_device_history_v2.json")
    self.hmacURL = storageDirectory.appendingPathComponent("cloudphone_device_history_v2.json.hmac")
    migrateFromDocumentsIfNeeded()
    loadFromDisk()
  }

  /// 解析历史存储目录，按可靠性降级：ApplicationSupport → Caches → tmp。
  /// 后两者可能被系统清理，但在容器异常时保证 SDK 不因无法落盘而崩溃。
  static func resolveStorageDirectory(
    applicationSupportDirectories: [URL],
    cachesDirectories: [URL],
    temporaryDirectory: URL
  ) -> URL {
    if let appSupportDirectory = applicationSupportDirectories.first {
      return appSupportDirectory
    }
    if let cachesDirectory = cachesDirectories.first {
      Logger.log(
        "DeviceHistory: applicationSupportDirectory unavailable, falling back to cachesDirectory")
      return cachesDirectory.appendingPathComponent("CloudPhoneRiskKit", isDirectory: true)
    }
    Logger.log(
      "DeviceHistory: applicationSupportDirectory unavailable, falling back to temporaryDirectory")
    return temporaryDirectory.appendingPathComponent("CloudPhoneRiskKit", isDirectory: true)
  }

  private static func resolveStorageDirectory(fileManager: FileManager) -> URL {
    resolveStorageDirectory(
      applicationSupportDirectories: fileManager.urls(
        for: .applicationSupportDirectory, in: .userDomainMask),
      cachesDirectories: fileManager.urls(for: .cachesDirectory, in: .userDomainMask),
      temporaryDirectory: fileManager.temporaryDirectory
    )
  }

  /// 清理旧版本遗留在 Documents 下的历史文件。
  /// 只删除不迁移：v1 明文数据留在可备份目录本身是隐私风险，升级后直接弃用。
  private func migrateFromDocumentsIfNeeded() {
    let oldPaths = fileManager.urls(for: .documentDirectory, in: .userDomainMask)
    guard let docDir = oldPaths.first else { return }
    let oldStore = docDir.appendingPathComponent("cloudphone_device_history_v1.json")
    guard fileManager.fileExists(atPath: oldStore.path) else { return }
    do {
      try fileManager.removeItem(at: oldStore)
    } catch {
      Logger.log("DeviceHistory: failed to remove legacy store - \(error.localizedDescription)")
    }
    let oldHmac = docDir.appendingPathComponent("cloudphone_device_history_v1.json.hmac")
    do {
      try fileManager.removeItem(at: oldHmac)
    } catch {
      Logger.log("DeviceHistory: failed to remove legacy hmac - \(error.localizedDescription)")
    }
    Logger.log("DeviceHistory: migrated from Documents to ApplicationSupport")
  }

  // MARK: - 添加快照

  /// 添加新的检测快照。
  /// 内存更新同步完成，落盘异步执行：评估链路不被磁盘 I/O 阻塞。
  public func addSnapshot(_ snapshot: DeviceDetectionSnapshot) {
    lock.withLock {
      cachedSnapshots.append(snapshot)
      isDirty = true

      // 限制内存中的快照数量：只保留最近 maxSnapshots 条，丢弃最旧数据。
      if cachedSnapshots.count > maxSnapshots {
        cachedSnapshots = Array(cachedSnapshots.suffix(maxSnapshots))
      }
    }

    // 异步持久化；utility QoS 保证不与 UI/评估争抢资源，失败只记日志不重试。
    DispatchQueue.global(qos: .utility).async { [weak self] in
      self?.persistIfDirty()
    }
  }

  /// 从 RiskSnapshot 和 RiskScoreReport 创建并添加快照。
  public func addSnapshot(from riskSnapshot: RiskSnapshot, report: RiskScoreReport) {
    let snapshot = DeviceDetectionSnapshot.from(snapshot: riskSnapshot, report: report)
    addSnapshot(snapshot)
  }

  // MARK: - 查询操作

  /// 查询所有快照（返回前会按 30 天/500 条规则裁剪，并顺带标记脏数据）。
  public func getAllSnapshots() -> [DeviceDetectionSnapshot] {
    lock.withLock {
      cleanAndReturnLocked()
    }
  }

  /// 查询指定时间范围内的快照（闭区间，按时间升序）。
  public func getSnapshots(from startTime: TimeInterval, to endTime: TimeInterval)
    -> [DeviceDetectionSnapshot]
  {
    lock.withLock {
      let cleaned = cleanAndReturnLocked()
      return cleaned.filter { $0.timestamp >= startTime && $0.timestamp <= endTime }
    }
  }

  /// 查询最近的 N 个快照
  public func getRecentSnapshots(count: Int) -> [DeviceDetectionSnapshot] {
    lock.withLock {
      let cleaned = cleanAndReturnLocked()
      let recentCount = min(count, cleaned.count)
      return Array(cleaned.suffix(recentCount))
    }
  }

  /// 查询指定设备 ID 的快照（按时间升序）。
  /// 这是时序特征、基线、异常检测的共同入口；所有分析都按设备隔离，不跨设备聚合。
  public func getSnapshots(for deviceID: String) -> [DeviceDetectionSnapshot] {
    lock.withLock {
      let cleaned = cleanAndReturnLocked()
      return cleaned.filter { $0.deviceID == deviceID }
    }
  }

  /// 查询首次越狱时间；deviceID 为 nil 时跨设备取最早（供全局诊断使用，风控默认按设备）。
  public func getFirstJailbreakTime(for deviceID: String? = nil) -> TimeInterval? {
    lock.withLock {
      let cleaned = cleanAndReturnLocked()
      let filtered = deviceID != nil ? cleaned.filter { $0.deviceID == deviceID } : cleaned

      let jailbrokenSnapshots = filtered.filter { $0.jailbreakStatus.isJailbroken }
      return jailbrokenSnapshots.map { $0.timestamp }.min()
    }
  }

  /// 查询最近 N 天内的越狱次数
  public func getJailbreakCount(days: Int = 7, for deviceID: String? = nil) -> Int {
    lock.withLock {
      let now = Date().timeIntervalSince1970
      let startTime = now - TimeInterval(days * 24 * 3600)

      let cleaned = cleanAndReturnLocked()
      let filtered = deviceID != nil ? cleaned.filter { $0.deviceID == deviceID } : cleaned

      return filtered.filter { $0.timestamp >= startTime && $0.jailbreakStatus.isJailbroken }.count
    }
  }

  /// 查询首次出现时间（设备年龄）
  public func getFirstSeenTime(for deviceID: String) -> TimeInterval? {
    lock.withLock {
      let cleaned = cleanAndReturnLocked()
      let deviceSnapshots = cleaned.filter { $0.deviceID == deviceID }
      return deviceSnapshots.map { $0.timestamp }.min()
    }
  }

  /// 获取总检测次数
  public func getTotalDetectionCount(for deviceID: String) -> Int {
    lock.withLock {
      let cleaned = cleanAndReturnLocked()
      return cleaned.filter { $0.deviceID == deviceID }.count
    }
  }

  /// 获取 VPN 使用频率（最近 N 天）。
  /// 定义为“窗口内 VPN 活跃快照数 / 窗口内快照总数”，范围 0...1；无记录返回 0。
  public func getVPNUsageFrequency(days: Int = 7, for deviceID: String? = nil) -> Double {
    lock.withLock {
      let now = Date().timeIntervalSince1970
      let startTime = now - TimeInterval(days * 24 * 3600)

      let cleaned = cleanAndReturnLocked()
      let filtered = deviceID != nil ? cleaned.filter { $0.deviceID == deviceID } : cleaned
      let recentSnapshots = filtered.filter { $0.timestamp >= startTime }

      guard !recentSnapshots.isEmpty else { return 0 }

      let vpnCount = recentSnapshots.filter { $0.isVPNActive }.count
      return Double(vpnCount) / Double(recentSnapshots.count)
    }
  }

  /// 获取风险分数历史（按时间升序的 (timestamp, score) 序列，默认最近 30 天）。
  public func getRiskScoreHistory(days: Int = 30, for deviceID: String? = nil) -> [(
    timestamp: TimeInterval, score: Double
  )] {
    lock.withLock {
      let now = Date().timeIntervalSince1970
      let startTime = now - TimeInterval(days * 24 * 3600)

      let cleaned = cleanAndReturnLocked()
      let filtered = deviceID != nil ? cleaned.filter { $0.deviceID == deviceID } : cleaned
      let recentSnapshots = filtered.filter { $0.timestamp >= startTime }

      return
        recentSnapshots
        .sorted { $0.timestamp < $1.timestamp }
        .map { (timestamp: $0.timestamp, score: $0.riskScore) }
    }
  }

  // MARK: - 数据清理

  /// 执行数据清理，移除过期快照；有实际删除时立即同步落盘。
  public func cleanup() {
    lock.withLock {
      let before = cachedSnapshots.count
      _ = cleanAndReturnLocked()
      let after = cachedSnapshots.count

      if before != after {
        isDirty = true
        persistIfDirtyLocked()
      }
    }
  }

  /// 清空所有历史数据（隐私撤回/宿主登出时调用）。
  /// 同时删除落盘文件并重置 Keychain 新鲜度锚点，保证“清空”不可通过回滚文件恢复。
  public func clearAll() {
    lock.withLock {
      cachedSnapshots.removeAll()
      cachedFreshness = .zero
      isDirty = true
      persistToDiskLocked(resetAnchor: true)
    }
  }

  // MARK: - 持久化

  /// 从磁盘加载并校验历史。
  /// 任一环节失败（读失败、HMAC 不符、解密失败、回滚）都会清空内存并删除落盘文件，
  /// 采取 fail-closed：宁可丢失历史，也不接受来源不可信的数据参与风控。
  private func loadFromDisk() {
    lock.withLock {
      let anchor = freshnessAnchor.read() ?? .zero
      guard fileManager.fileExists(atPath: storeURL.path) else {
        cachedSnapshots = []
        cachedFreshness = anchor
        isDirty = false
        return
      }

      let data: Data
      do {
        data = try Data(contentsOf: storeURL)
      } catch {
        Logger.log("DeviceHistory: failed to read store file - \(error.localizedDescription)")
        cachedSnapshots = []
        cachedFreshness = anchor
        return
      }

      // 先验签再解密：签名不符说明文件被替换/损坏，直接丢弃，避免把恶意构造的 JSON 喂给解码器。
      guard let signature = (try? Data(contentsOf: hmacURL)),
        StorageIntegrityGuard.verify(data, signature: signature, purpose: hmacPurpose)
      else {
        clearPersistedFilesLocked(resetAnchor: false)
        cachedSnapshots = []
        cachedFreshness = anchor
        return
      }

      let decryptedData: Data
      #if DEBUG
        // 调试构建允许容忍未加密的旧文件，便于本地开发；Release 必须解密成功。
        if let dec = try? PayloadCrypto.decrypt(data) {
          decryptedData = dec
        } else {
          decryptedData = data
        }
      #else
        guard let dec = try? PayloadCrypto.decrypt(data) else {
          Logger.log("DeviceHistory: decrypt failed, clearing corrupted data in release build")
          clearPersistedFilesLocked(resetAnchor: false)
          cachedSnapshots = []
          cachedFreshness = anchor
          return
        }
        decryptedData = dec
      #endif

      // 优先按新信封解码；失败则兼容旧版“裸数组”格式（sequence 记为 0）。
      let decodedSnapshots: [DeviceDetectionSnapshot]
      let diskFreshness: FreshnessState
      if let envelope = try? JSONDecoder().decode(StoredEnvelope.self, from: decryptedData) {
        decodedSnapshots = envelope.snapshots
        diskFreshness = FreshnessState(
          latestTimestamp: envelope.latestTimestamp,
          sequence: envelope.sequence
        )
      } else if let legacy = try? JSONDecoder().decode(
        [DeviceDetectionSnapshot].self, from: decryptedData)
      {
        decodedSnapshots = legacy
        diskFreshness = FreshnessState(
          latestTimestamp: legacy.map(\.timestamp).max() ?? 0,
          sequence: 0
        )
      } else {
        cachedSnapshots = []
        cachedFreshness = anchor
        return
      }

      // 回滚检测：磁盘版本落后于 Keychain 锚点，说明文件被旧备份覆盖（常见于越狱环境），丢弃。
      if diskFreshness.sequence < anchor.sequence
        || diskFreshness.latestTimestamp < anchor.latestTimestamp
      {
        Logger.log("DeviceHistory: freshness rollback detected")
        clearPersistedFilesLocked(resetAnchor: false)
        cachedSnapshots = []
        cachedFreshness = anchor
        isDirty = false
        return
      }

      let cleaned = pruneSnapshotsLocked(decodedSnapshots)
      cachedSnapshots = cleaned.snapshots
      cachedFreshness = maxFreshness(anchor, diskFreshness)
      isDirty = cleaned.didPrune

      // 磁盘版本更新时回写锚点，保证下次启动仍能识别回滚。
      if diskFreshness.sequence > anchor.sequence
        || diskFreshness.latestTimestamp > anchor.latestTimestamp
      {
        _ = freshnessAnchor.write(diskFreshness)
      }
    }
  }

  /// 脏数据才写盘（异步入口）。
  private func persistIfDirty() {
    lock.withLock {
      persistIfDirtyLocked()
    }
  }

  /// 调用方必须已持有 `lock`。
  private func persistIfDirtyLocked() {
    guard isDirty else { return }
    let persisted = persistToDiskLocked(resetAnchor: false)
    if persisted {
      isDirty = false
    }
  }

  /// 写盘主流程：构造信封 → 加密 → 原子写 → 设置文件保护 → 写 HMAC → 更新新鲜度锚点。
  /// - Parameter resetAnchor: 为 true 时仅删除文件并重置锚点（clearAll 路径），不写新数据。
  /// - Returns: 写入且锚点更新成功时为 true；失败时保持脏标记，等待下次重试。
  @discardableResult
  private func persistToDiskLocked(resetAnchor: Bool) -> Bool {
    if resetAnchor {
      clearPersistedFilesLocked(resetAnchor: true)
      return true
    }

    do {
      let anchor = freshnessAnchor.read() ?? .zero
      let latestSnapshotTimestamp = cachedSnapshots.map(\.timestamp).max() ?? 0
      // 新鲜度取“内存、磁盘锚点、缓存”三者最大，序号在此基础上 +1，保证单调递增。
      let freshness = FreshnessState(
        latestTimestamp: max(
          latestSnapshotTimestamp, max(anchor.latestTimestamp, cachedFreshness.latestTimestamp)),
        sequence: max(anchor.sequence, cachedFreshness.sequence) + 1
      )
      let envelope = StoredEnvelope(
        schemaVersion: 2,
        snapshots: cachedSnapshots,
        latestTimestamp: freshness.latestTimestamp,
        sequence: freshness.sequence
      )
      let rawData = try JSONEncoder().encode(envelope)
      let dataToWrite: Data
      #if DEBUG
        // 调试构建加密失败时退回明文，避免本地环境缺密钥导致功能不可用。
        dataToWrite = (try? PayloadCrypto.encrypt(rawData)) ?? rawData
      #else
        // Release 加密失败即抛错并放弃写盘，绝不落明文。
        dataToWrite = try PayloadCrypto.encrypt(rawData)
      #endif
      // .atomic：先写临时文件再替换，防止写到一半崩溃留下半个 JSON。
      try dataToWrite.write(to: storeURL, options: .atomic)
      try fileManager.setAttributes(
        [FileAttributeKey.protectionKey: FileProtectionType.complete],
        ofItemAtPath: storeURL.path
      )
      // 对“密文”签名而非明文：读回时先验签再解密，任何字节被替换都会被发现。
      let signature = StorageIntegrityGuard.sign(dataToWrite, purpose: hmacPurpose)
      try signature.write(to: hmacURL, options: .atomic)
      try fileManager.setAttributes(
        [FileAttributeKey.protectionKey: FileProtectionType.complete],
        ofItemAtPath: hmacURL.path
      )
      // 锚点写失败时，磁盘数据无法再做回滚校验；Release 下宁可直接删除，避免留下不可信历史。
      guard freshnessAnchor.write(freshness) else {
        Logger.log("DeviceHistory: failed to update freshness anchor")
        if BuildConfig.isRelease {
          clearPersistedFilesLocked(resetAnchor: false)
        }
        return false
      }
      cachedFreshness = freshness
      Logger.log("DeviceHistory: persisted \(cachedSnapshots.count) snapshots (encrypted)")
      return true
    } catch {
      Logger.log("DeviceHistory: failed to persist - \(error.localizedDescription)")
      return false
    }
  }

  // MARK: - 辅助方法

  private func cleanAndReturn() -> [DeviceDetectionSnapshot] {
    lock.withLock {
      cleanAndReturnLocked()
    }
  }

  /// 裁剪后返回快照；裁剪属于写操作，顺手标记脏数据以便后续落盘。
  private func cleanAndReturnLocked() -> [DeviceDetectionSnapshot] {
    let pruned = pruneSnapshotsLocked(cachedSnapshots)
    cachedSnapshots = pruned.snapshots
    if pruned.didPrune {
      isDirty = true
    }

    // 按时间戳升序返回，调用方（时序/基线）依赖该顺序。
    return cachedSnapshots.sorted { $0.timestamp < $1.timestamp }
  }

  /// 同时施加时间与条数限制：先剔除 30 天前的数据，再保留最近 500 条。
  /// 返回 `didPrune` 表示是否有实际删除，用于决定是否触发持久化。
  private func pruneSnapshotsLocked(_ snapshots: [DeviceDetectionSnapshot]) -> (
    snapshots: [DeviceDetectionSnapshot], didPrune: Bool
  ) {
    let now = Date().timeIntervalSince1970
    let minTimestamp = now - maxAgeSeconds
    let timeFiltered = snapshots.filter { $0.timestamp >= minTimestamp }
    let limited =
      timeFiltered.count > maxSnapshots ? Array(timeFiltered.suffix(maxSnapshots)) : timeFiltered
    return (limited, limited.count != snapshots.count)
  }

  /// 删除落盘文件；文件本就不存在时（NSFileNoSuchFileError）不视为错误。
  /// - Parameter resetAnchor: 为 true 时同时删除 Keychain 新鲜度锚点。
  private func clearPersistedFilesLocked(resetAnchor: Bool) {
    do {
      try fileManager.removeItem(at: storeURL)
    } catch {
      if (error as NSError).code != NSFileNoSuchFileError {
        Logger.log("DeviceHistory: failed to remove store file - \(error.localizedDescription)")
      }
    }
    do {
      try fileManager.removeItem(at: hmacURL)
    } catch {
      if (error as NSError).code != NSFileNoSuchFileError {
        Logger.log("DeviceHistory: failed to remove hmac file - \(error.localizedDescription)")
      }
    }
    if resetAnchor {
      freshnessAnchor.remove()
    }
  }

  private func maxFreshness(_ lhs: FreshnessState, _ rhs: FreshnessState) -> FreshnessState {
    FreshnessState(
      latestTimestamp: max(lhs.latestTimestamp, rhs.latestTimestamp),
      sequence: max(lhs.sequence, rhs.sequence)
    )
  }
}
