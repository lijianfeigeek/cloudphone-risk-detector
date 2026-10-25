// 统一的时间戳格式化工具：为信号与审计日志生成可跨端解析的 ISO 8601 字符串。
// 固定使用互联网日期时间 + 毫秒小数秒，服务端可按同一格式反序列化，避免本地化时区差异。

import Foundation

/// ISO 8601 时间字符串生成器。
/// 复用单个 `ISO8601DateFormatter` 实例（创建成本高），本身不是线程安全的，
/// 但 `DateFormatter` 系列在读操作上的并发使用在实践中由 Foundation 内部加锁保护。
enum ISO8601 {
    /// 全局共享格式化器；`withFractionalSeconds` 让同一秒内的多条日志仍可排序。
    private static let formatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        // 显式带上时区（Z）与毫秒，避免服务端按本地时间误解析。
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    /// 返回当前时刻的 ISO 8601 字符串，例如 `2026-10-25T10:00:00.123Z`。
    static func nowString() -> String {
        formatter.string(from: Date())
    }
}
