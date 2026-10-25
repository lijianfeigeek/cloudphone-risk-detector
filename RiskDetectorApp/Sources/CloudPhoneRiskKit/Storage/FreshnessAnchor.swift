// 文件职责：在 Keychain 中持久化“新鲜度锚点”（最新时间戳 + 单调序列号）。
// 管道位置：Storage 防回滚基础设施，被 RiskHistoryStore / ProtectionStabilityStore 使用。
// 安全不变量：锚点 ThisDeviceOnly 且首次解锁后可读；序列号只增不减，
// 用于检测业务文件被回滚/重放。
import Foundation
import Security

/// 新鲜度状态：最新事件时间戳与单调递增序列号。
struct FreshnessState: Codable, Sendable {
    /// 已见最大事件时间戳（Unix 秒）。
    var latestTimestamp: Double
    /// 单调递增序列号；每次成功写入 +1。
    var sequence: UInt64

    private enum CodingKeys: String, CodingKey {
        case latestTimestamp = "lt"
        case sequence = "sq"
    }

    /// 初始空状态。
    static let zero = FreshnessState(latestTimestamp: 0, sequence: 0)

    /// 判断自身是否在序列号与时间戳上均不落后于另一状态。
    func dominates(_ other: FreshnessState) -> Bool {
        sequence >= other.sequence && latestTimestamp >= other.latestTimestamp
    }
}

/// 新鲜度锚点。SDK 4.4 Phase 6: Keychain 用 kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly。
/// 锚点与业务文件分离存储：即使业务文件被整体替换，锚点仍能暴露回滚。
final class FreshnessAnchor {
    /// Keychain service 标识。
    private let service = "CloudPhoneRiskKit.FreshnessAnchor"
    /// Keychain account（区分不同业务的新鲜度锚点）。
    private let account: String
    /// 首次解锁后可读且不随备份迁移；保证后台启动时锚点可用。
    private let accessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    private let lock = NSLock()  // NSLock：锁内包含 Keychain I/O

    /// 创建指定 account 的锚点句柄。
    init(account: String) {
        self.account = account
    }

    /// 读取锚点。
    /// - Returns: 解码后的状态；条目不存在、读取失败或解码失败均为 nil（调用方按 `.zero` 降级）。
    func read() -> FreshnessState? {
        lock.withLock {
            // 读取查询绝不能包含 kSecAttrAccessible：它是写入属性，
            // 部分 iOS 版本会因此查不到条目。
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
                kSecReturnData as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne,
            ]
            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)
            guard status == errSecSuccess, let data = item as? Data else {
                return nil
            }
            return try? JSONDecoder().decode(FreshnessState.self, from: data)
        }
    }

    /// 写入锚点：先尝试更新，不存在时再新增。
    /// - Returns: 成功为 true；Keychain 不可用或写入失败为 false。
    func write(_ state: FreshnessState) -> Bool {
        lock.withLock {
            guard let data = try? JSONEncoder().encode(state) else {
                return false
            }

            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
            ]
            let attributes: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrAccessible as String: accessible,
            ]

            // 优先更新已有条目，避免重复 add 产生 errSecDuplicateItem。
            let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            if updateStatus == errSecSuccess {
                return true
            }
            // 非“条目不存在”的错误直接失败，绝不覆盖写入。
            if updateStatus != errSecItemNotFound {
                return false
            }

            var addQuery = query
            addQuery[kSecValueData as String] = data
            addQuery[kSecAttrAccessible as String] = accessible
            return SecItemAdd(addQuery as CFDictionary, nil) == errSecSuccess
        }
    }

    /// 删除锚点（测试/重置用）；条目不存在时视为成功。
    func remove() {
        lock.withLock {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
            ]
            let status = SecItemDelete(query as CFDictionary)
            if status != errSecSuccess && status != errSecItemNotFound {
                Logger.log("FreshnessAnchor: SecItemDelete failed with status \(status)")
            }
        }
    }
}
