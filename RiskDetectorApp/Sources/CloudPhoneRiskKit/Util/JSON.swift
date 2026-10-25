// JSON 编解码薄封装：统一排序键与输出格式，保证同一对象多次编码得到稳定字节序。
// 稳定的键序让摘要、签名与缓存比对不会因字典遍历顺序变化而误判。

import Foundation

/// 轻量 JSON 工具；只做编码，解码仍由调用方显式使用 `JSONDecoder`。
enum JSON {
    /// 将可编码值序列化为 JSON `Data`。
    /// - Parameter prettyPrinted: 为 true 时带缩进（便于日志排查），否则输出紧凑格式。
    /// - 无论哪种模式都启用 `.sortedKeys`，避免哈希随机化导致同一对象字节不稳定。
    static func encode<T: Encodable>(_ value: T, prettyPrinted: Bool) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = prettyPrinted ? [.prettyPrinted, .sortedKeys] : [.sortedKeys]
        return try encoder.encode(value)
    }

    /// 将可编码值序列化为 UTF-8 JSON 字符串（紧凑格式）。
    static func stringify<T: Encodable>(_ value: T) throws -> String {
        let data = try encode(value, prettyPrinted: false)
        // 编码器输出必定是合法 UTF-8，用非失败构造避免多余的可选处理。
        return String(decoding: data, as: UTF8.self)
    }
}
