import CloudPhoneRiskKit
import Foundation

public struct StoredRiskReport: Sendable, Hashable {
  public var path: String
  public var filename: String
  public var modifiedAt: Date?
  public var bytes: Int64
  public var isEncrypted: Bool
}

/// 检测 App 的“报告存储层”：负责列举/读取/清空本地报告文件。
public enum RiskReportStorage {
  #if DEBUG
    private static let testOverrideLock = NSLock()
    private static var _testBaseDirectoryOverride: URL?
    static var testBaseDirectoryOverride: URL? {
      get { testOverrideLock.withLock { _testBaseDirectoryOverride } }
      set { testOverrideLock.withLock { _testBaseDirectoryOverride = newValue } }
    }
  #endif

  static func resolveBaseDirectory(
    applicationSupportDirectories: [URL],
    cachesDirectories: [URL],
    temporaryDirectory: URL
  ) -> URL {
    // 必须与 CPRiskStore 使用同一个目录前缀：
    //   保存侧：Application Support/CloudPhoneRiskKit/reports
    //   读取侧：Application Support/CloudPhoneRiskKit/reports
    // 否则报告写成功后，历史列表仍然为空。
    if let applicationSupportDirectory = applicationSupportDirectories.first {
      return applicationSupportDirectory.appendingPathComponent(
        "CloudPhoneRiskKit", isDirectory: true)
    }
    if let cachesDirectory = cachesDirectories.first {
      return cachesDirectory.appendingPathComponent("CloudPhoneRiskKit", isDirectory: true)
    }
    return temporaryDirectory.appendingPathComponent("CloudPhoneRiskKit", isDirectory: true)
  }

  /// 旧版本（修复前）把报告写在 `Application Support/reports`，
  /// 与新目录 `Application Support/CloudPhoneRiskKit/reports` 不一致。
  /// 列表时同时扫描旧目录，避免升级后用户看到“历史记录消失”。
  private static func legacyReportsDirectoryURL() -> URL? {
    guard
      let applicationSupportDirectory = FileManager.default.urls(
        for: .applicationSupportDirectory, in: .userDomainMask
      ).first
    else { return nil }
    return applicationSupportDirectory.appendingPathComponent("reports", isDirectory: true)
  }

  /// 返回需要扫描的报告目录（主目录 + 旧目录，去重）。
  private static func reportDirectories() -> [URL] {
    #if DEBUG
      // 测试注入目录时只扫描注入目录，避免读到本机真实报告。
      if testBaseDirectoryOverride != nil {
        return (try? reportsDirectoryURL()).map { [$0] } ?? []
      }
    #endif

    var directories: [URL] = []
    if let primary = try? reportsDirectoryURL() {
      directories.append(primary)
    }
    if let legacy = legacyReportsDirectoryURL(),
      !directories.contains(where: { $0.standardizedFileURL == legacy.standardizedFileURL })
    {
      directories.append(legacy)
    }
    return directories
  }

  public static func reportsDirectoryURL() throws -> URL {
    #if DEBUG
      if let testBaseDirectoryOverride {
        return testBaseDirectoryOverride.appendingPathComponent("reports", isDirectory: true)
      }
    #endif

    let fileManager = FileManager.default
    let base = resolveBaseDirectory(
      applicationSupportDirectories: fileManager.urls(
        for: .applicationSupportDirectory, in: .userDomainMask),
      cachesDirectories: fileManager.urls(for: .cachesDirectory, in: .userDomainMask),
      temporaryDirectory: fileManager.temporaryDirectory
    )
    return base.appendingPathComponent("reports", isDirectory: true)
  }

  public static func list() -> [StoredRiskReport] {
    var seen = Set<String>()
    var merged: [StoredRiskReport] = []
    for dir in reportDirectories() {
      for report in list(in: dir) where seen.insert(report.path).inserted {
        merged.append(report)
      }
    }
    // 多个目录合并后重新按修改时间倒序，保证最近保存的排在最前。
    return merged.sorted { (a, b) in
      let ad = a.modifiedAt ?? .distantPast
      let bd = b.modifiedAt ?? .distantPast
      return ad > bd
    }
  }

  public static func list(in dir: URL) -> [StoredRiskReport] {
    let fm = FileManager.default
    guard
      let items = try? fm.contentsOfDirectory(
        at: dir,
        includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey],
        options: [.skipsHiddenFiles]
      )
    else { return [] }

    let out: [StoredRiskReport] = items.compactMap { url in
      let values = try? url.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey])
      let bytes = Int64(values?.fileSize ?? 0)
      let name = url.lastPathComponent
      if name.hasSuffix(".meta.json") { return nil }
      return StoredRiskReport(
        path: url.path,
        filename: name,
        modifiedAt: values?.contentModificationDate,
        bytes: bytes,
        isEncrypted: !name.hasSuffix(".json")
      )
    }

    return out.sorted { (a, b) in
      let ad = a.modifiedAt ?? .distantPast
      let bd = b.modifiedAt ?? .distantPast
      return ad > bd
    }
  }

  public static func loadJSONString(atPath path: String) -> String? {
    #if os(iOS)
      return CPRiskStore.shared.decryptReport(atPath: path, error: nil)
    #else
      // 与 iOS 一致：只接受加密落盘的 `.bin` 文件；解密失败返回 nil。
      // 历史明文 `.json` 文件不再被读取（Release 下明文报告不得解析）。
      guard !path.hasSuffix(".json") else { return nil }
      guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
            let plaintext = try? CPRiskReport.decryptStoredData(data) else { return nil }
      return String(data: plaintext, encoding: .utf8)
    #endif
  }

  public static func loadDTO(atPath path: String) -> RiskReportDTO? {
    guard let json = loadJSONString(atPath: path) else { return nil }
    guard let data = json.data(using: .utf8) else { return nil }
    return RiskReportMapper.dto(from: data)
  }

  public static func listSummaries() -> [(report: StoredRiskReport, summary: RiskReportSummary?)] {
    list().map { summary(for: $0) }
  }

  public static func listSummaries(in dir: URL) -> [(
    report: StoredRiskReport, summary: RiskReportSummary?
  )] {
    list(in: dir).map { summary(for: $0) }
  }

  /// 读取单份报告的摘要：优先用 `meta.json`，缺失时解密报告并补写缓存。
  private static func summary(for report: StoredRiskReport) -> (
    report: StoredRiskReport, summary: RiskReportSummary?
  ) {
    if let meta = RiskReportSummaryIO.readMeta(reportPath: report.path) {
      return (report, meta)
    }
    guard let dto = loadDTO(atPath: report.path) else { return (report, nil) }
    RiskReportSummaryIO.writeMeta(for: dto, reportPath: report.path)
    return (report, RiskReportSummaryIO.readMeta(reportPath: report.path))
  }

  public static func delete(atPath path: String) -> Bool {
    let meta = RiskReportSummaryIO.metaPath(forReportPath: path)
    _ = try? FileManager.default.removeItem(atPath: meta)
    return (try? FileManager.default.removeItem(atPath: path)) != nil
  }

  public static func deleteAll() {
    let items = list()
    for i in items {
      _ = delete(atPath: i.path)
    }
  }
}
