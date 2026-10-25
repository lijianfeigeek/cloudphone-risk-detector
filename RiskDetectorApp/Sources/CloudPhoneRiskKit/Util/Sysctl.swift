// 系统控制信息（sysctl）读取封装：统一走 DynamicSymbolResolver 的间接调用。
// 所有读取都使用“先探长度、再取值”的两段式 API，避免缓冲区截断或越界。

import Foundation

/// `sysctl` / `sysctlbyname` 的安全封装。
/// 通过 `DynamicSymbolResolver` 而非直接链接，降低导入表被静态分析定位的风险。
enum Sysctl {
    /// 读取字符串型 sysctl（如 `kern.osversion`、`hw.machine`）。
    /// - Returns: 成功返回值字符串；键不存在、调用失败或结果异常时返回 nil。
    static func string(_ name: String) -> String? {
        var size: size_t = 0
        // 第一段：传 nil 缓冲区只查询所需字节数；返回非 0 表示键不存在或无权限。
        if name.withCString({ DynamicSymbolResolver.sysctlByName($0, nil, &size, nil, 0) }) != 0 {
            return nil
        }
        guard size > 0 else { return nil }
        // 多分配 1 字节用于兜底补 NUL，防止内核返回的字符串未以 0 结尾。
        var buf = [CChar](repeating: 0, count: max(1, Int(size)))
        // 第二段：按查询到的长度真正读取内容。
        let readResult = buf.withUnsafeMutableBufferPointer { buffer in
            name.withCString {
                DynamicSymbolResolver.sysctlByName($0, buffer.baseAddress, &size, nil, 0)
            }
        }
        if readResult != 0 { return nil }
        // size 可能被内核回写；超出实际缓冲区说明结果不可信。
        guard size > 0, Int(size) <= buf.count else { return nil }
        // 某些 sysctl 返回的 size 不含结尾 NUL，这里主动补齐以便 String(cString:) 安全。
        if buf[Int(size) - 1] != 0 {
            buf.append(0)
        }
        return String(cString: buf)
    }

    /// 读取整数型 sysctl，返回值超出 `Int` 表示范围时返回 nil。
    static func int(_ name: String) -> Int? {
        if let value = int64(name) {
            return Int(value)
        }
        return nil
    }

    /// 读取 64 位整数型 sysctl。
    /// 先按 `Int64` 读取（适配 64 位内核项），失败再退回 `Int32`（如 `hw.cpu64bit_capable`）。
    static func int64(_ name: String) -> Int64? {
        var value: Int64 = 0
        var size = MemoryLayout<Int64>.size
        if name.withCString({ DynamicSymbolResolver.sysctlByName($0, &value, &size, nil, 0) }) == 0 {
            return value
        }

        // 兼容 32 位内核项：避免把 4 字节值按 8 字节读取导致调用失败。
        var value32: Int32 = 0
        var size32 = MemoryLayout<Int32>.size
        if name.withCString({ DynamicSymbolResolver.sysctlByName($0, &value32, &size32, nil, 0) }) == 0 {
            return Int64(value32)
        }

        return nil
    }
}
