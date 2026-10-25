// 跨会话纵向状态存储：用 Keychain 保存上一次的蜜罐/基线/不变量结果，供下次启动做漂移对比。
// 选择 Keychain 而非文件/UserDefaults，是因为它自带硬件后端保护且可在重装前保留设备级状态。

import Foundation
import Security

/// Keychain-backed kv store for cross-session signal state.
///
/// 用途：让蜜罐 / baseline / invariant 类信号有“上次结果”作为对照系。
/// 例如本次启动算出 invariant_seal=ABC，上次启动是 XYZ —— 显著漂移就报警。
///
/// 设计选择：
///   - Service: "CloudPhoneRiskKit.LongitudinalState"
///   - Accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
///     （解锁后可用、不跨设备同步、不进 iCloud Keychain）
///   - 不做加密层 — Keychain 本身就有硬件后端保护；额外加密只是混淆
///   - 写入策略：先 Update，失败再 Add（原子化处理首次写）
enum LongitudinalStateStore {

    // Service 名是 Keychain 中的命名空间；改动它会导致读不到旧状态。
    private static let service = "CloudPhoneRiskKit.LongitudinalState"
    // NSLock 串行化整个 Keychain 事务：Update 与 Add 之间存在竞态，必须原子化。
    private static let lock = NSLock()

    /// 读取 key 对应的 blob，不存在返回 nil。
    /// - 查不到、权限不足或数据不是 Data 时统一返回 nil，由调用方按“无历史”处理。
    static func load(key: String) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        // errSecItemNotFound 等非成功状态都视为“没有历史状态”，不是错误。
        guard status == errSecSuccess, let data = item as? Data else {
            return nil
        }
        return data
    }

    /// 保存 key→value。已存在则覆盖。返回是否成功。
    @discardableResult
    static func save(key: String, value: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        // 查询条件不含 value，供 Update 定位既有条目。
        let baseQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        let updateAttrs: [String: Any] = [
            kSecValueData as String: value,
        ]
        // 先尝试更新：绝大多数写入都是覆盖已有 key，避免重复 Add 报 errSecDuplicateItem。
        let updateStatus = SecItemUpdate(baseQuery as CFDictionary, updateAttrs as CFDictionary)
        if updateStatus == errSecSuccess {
            return true
        }
        // 仅当确认条目不存在时才 Add；其他错误直接返回 false，避免掩盖权限问题。
        if updateStatus == errSecItemNotFound {
            var addAttrs = baseQuery
            addAttrs[kSecValueData as String] = value
            // ThisDeviceOnly + AfterFirstUnlock：不随备份/设备迁移扩散，且后台首次解锁后可用。
            addAttrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            let addStatus = SecItemAdd(addAttrs as CFDictionary, nil)
            return addStatus == errSecSuccess
        }
        return false
    }

    /// 删除 key（用于测试 / 重置）。
    /// 条目本来就不存在也视为删除成功（幂等）。
    @discardableResult
    static func delete(key: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    // MARK: - String helpers

    /// 读取并按键 UTF-8 解码；数据不是合法 UTF-8 时返回 nil。
    static func loadString(key: String) -> String? {
        guard let data = load(key: key) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// 按 UTF-8 编码后保存字符串；编码失败（理论上不会）返回 false。
    @discardableResult
    static func saveString(key: String, value: String) -> Bool {
        guard let data = value.data(using: .utf8) else { return false }
        return save(key: key, value: data)
    }
}
