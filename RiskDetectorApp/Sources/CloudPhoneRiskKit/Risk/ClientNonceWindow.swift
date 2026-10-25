// 上报链路·客户端 nonce 防重放窗口：记录本进程最近签发的 nonce，拦截重复使用。
// 窗口只在本地内存中使用，不随 payload 上报；服务端侧另有 `NonceReplayProtecting` 消费表。

import Foundation

// MARK: - 客户端 nonce 去重窗口

/// 线程安全的本地上报 nonce 滚动窗口。
///
/// nonce 使用 UUID v4（122 位熵），碰撞概率可忽略；该窗口提供纵深防御，
/// 主要覆盖两类现实威胁：
///
/// - **调用方逻辑缺陷**：例如循环中重复序列化同一个信封对象而未重新调用 `create()`。
/// - **UUID 生成器被篡改**：越狱设备/模拟器把 `UUID()` 补丁成确定性值，窗口会在
///   有效期内捕获第二次重复。
///
/// 窗口只以 `nonce` 为键（不拼接 session-token），因为信封 nonce 本身设计为全局唯一。
/// 条目超过 `windowMillis` 有效期后会被惰性清理。
internal final class ClientNonceWindow: @unchecked Sendable {

    // MARK: 共享实例

    /// 进程级单例。所有 `ReportEnvelope.create()` 共用该窗口，
    /// 因此跨会话的重复 nonce 也能被发现。
    static let shared = ClientNonceWindow()

    // MARK: 状态

    private var entries: [String: Int64] = [:]   // nonce → 注册时间戳（毫秒）
    private let lock = NSLock()
    private let windowMillis: Int64

    // MARK: 初始化

    /// - Parameter windowMillis: 去重窗口长度，默认 5 分钟，与信封 nonce 有效期保持一致。
    init(windowMillis: Int64 = 300_000) {
        self.windowMillis = windowMillis
    }

    // MARK: 对外接口

    /// 尝试注册 `nonce` 及其时间戳。
    ///
    /// - Returns: `true` 表示窗口内首次出现且注册成功；`false` 表示有效期内已存在（判定为重复）。
    func registerIfNew(_ nonce: String, ts: Int64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        evictExpired(now: ts)
        guard entries[nonce] == nil else { return false }
        entries[nonce] = ts
        return true
    }

    // MARK: 私有方法

    /// 清理超出窗口的条目，防止长期运行时内存无界增长。
    private func evictExpired(now: Int64) {
        let cutoff = now - windowMillis
        entries = entries.filter { $0.value > cutoff }
    }
}
