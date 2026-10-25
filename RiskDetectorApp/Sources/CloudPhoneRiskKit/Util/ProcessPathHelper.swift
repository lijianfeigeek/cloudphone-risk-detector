// 进程可执行路径解析：按平台选择系统 API，供调试器 / Frida 进程检测使用。
// macOS 能拿到完整路径，iOS 受沙盒限制只能拿到 16 字节进程名，调用方需按退化形式匹配。

import Darwin
import Foundation

/// 解析指定 PID 的可执行路径（macOS）或进程名（iOS 系）。
///
/// - **macOS**: 使用 `proc_pidpath(3)` 返回完整可执行路径。
/// - **iOS/tvOS/watchOS**: `proc_pidpath` 不可用，退化为 `sysctl(KERN_PROC_PID)` 读取
///   `p_comm`（进程名，最多 16 字符）。调用方应按更短的标识匹配（如 "lldb"、"frida" 仍可命中）。
///
/// - Parameter pid: 要解析的进程 ID。
/// - Returns: macOS 返回完整路径；iOS 返回进程名；失败返回 `nil`。
func processPath(for pid: pid_t) -> String? {
#if os(macOS)
    // proc_pidpath 会把路径写入调用方缓冲区；PATH_MAX 足够容纳任何合法路径。
    var pathBuffer = [CChar](repeating: 0, count: Int(PATH_MAX))
    let result = proc_pidpath(pid, &pathBuffer, UInt32(PATH_MAX))
    // 返回值 <= 0 表示进程不存在或无权查询。
    guard result > 0 else { return nil }
    return String(cString: pathBuffer)
#else
    // iOS: proc_pidpath is not available. Use sysctl(KERN_PROC_PID) to get p_comm.
    // MIB 四元组固定为 [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]。
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.size
    // 失败（如 PID 已退出）时返回 nil，由调用方决定是否视为可疑。
    guard sysctl(&mib, 4, &info, &size, nil, 0) == 0 else { return nil }
    // p_comm 是定长 C 字符数组，截到第一个 NUL 即为实际进程名。
    let bytes = withUnsafeBytes(of: info.kp_proc.p_comm) { raw in
        Array(raw.prefix { $0 != 0 })
    }
    return String(decoding: bytes, as: UTF8.self)
#endif
}
