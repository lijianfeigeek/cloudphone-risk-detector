import CRiskCore
import Darwin
import Foundation

// MARK: - Unix Socket 全量扫描
//
// 枚举进程内全部 Unix 域套接字连接，检查抽象命名空间、/tmp 路径、Frida 特征串等
// 异常 IPC 迹象，用于发现 Frida 及其注入器的通信通道。
// 默认关闭：正常系统活动也可能命中，须由远程配置显式开启，否则返回禁用态。

/// 扫描文件描述符的上限；覆盖常规 App 的 fd 范围，同时限制扫描耗时。
private let fdScanMax: Int32 = 1024

/// 可疑的 Unix socket 路径前缀（世界可写的临时目录）。
private let suspiciousPathPrefixes: [String] = [
    "/tmp/",
    "/var/tmp/",
]

/// Frida 及其相关组件常见的 Unix socket 路径/名称特征。
private let fridaPathMarkers: [String] = [
    "frida",
    "linjector",
    "gmain",
    "gum-js-loop",
    "gdbus",
    "pool-frida",
]

/// 单个 Unix 域套接字的观测记录。
private struct SocketObservation {
    let fd: Int32
    let localPath: String
    let peerPath: String
    let isAbstract: Bool
    let isSuspicious: Bool
    let reason: String
}

/// Unix 域套接字全量扫描检测器（默认关闭）。
///
/// 枚举所有 Unix 域套接字连接，发现可能指向 Frida 或其他插桩框架的异常 IPC 通道。
///
/// 注意：套接字枚举在正常系统活动上也可能产生误报，因此默认关闭；
/// 需通过远程配置 `ServerRiskPolicy.enableUnixSocketSweep` 显式开启。
struct UnixSocketSweepDetector: Detector {

    /// 是否启用（从远程配置读取，默认关闭）。
    private static var enabled: Bool {
        PolicyManager.shared.activePolicy?.enableUnixSocketSweep ?? false
    }

    @inline(never)
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        // 模拟器 fd 环境与真机不同，直接降级。
        return DetectorResult(score: 0, methods: ["unix_socket_sweep:unavailable_simulator"])
#else
        return detectKernel()
#endif
    }

    /// 保持面向 VMP 的 `detect()` 入口在优化构建中窄而稳定，实际逻辑集中于此。
    @inline(never)
    private func detectKernel() -> DetectorResult {
        // 总开关关闭时不扫描，返回明确的 disabled 标记供 asSignals 丢弃。
        guard Self.enabled else {
            return DetectorResult(score: 0, methods: ["unix_socket_sweep:disabled"])
        }

        var score: Double = 0
        var methods: [String] = []

        let observations = sweepUnixSockets()

        // 按可疑类型分类统计
        var abstractCount = 0
        var tmpCount = 0
        var fridaMarkerCount = 0
        var totalSuspicious = 0

        for obs in observations where obs.isSuspicious {
            totalSuspicious += 1

            if obs.isAbstract {
                abstractCount += 1
            }
            if obs.localPath.hasPrefix("/tmp/") || obs.localPath.hasPrefix("/var/tmp/") ||
                obs.peerPath.hasPrefix("/tmp/") || obs.peerPath.hasPrefix("/var/tmp/") {
                tmpCount += 1
            }
            let combinedLower = (obs.localPath + " " + obs.peerPath).lowercased()
            if fridaPathMarkers.contains(where: { combinedLower.contains($0) }) {
                fridaMarkerCount += 1
            }

            methods.append("unix_socket_sweep:fd=\(obs.fd):\(obs.reason):\(obs.localPath)")
        }

        // 计分：抽象命名空间在 iOS 上极罕见，单价 10 分；/tmp 路径 8 分；
        // Frida 特征串最直接，单价 15 分；可疑 socket 数量多时追加组合分。
        if abstractCount >= 1 {
            score += 10.0 * Double(abstractCount)
        }

        // /tmp 或 /var/tmp 下的 socket
        if tmpCount >= 1 {
            score += 8.0 * Double(tmpCount)
        }

        // 直接命中 Frida 路径特征
        if fridaMarkerCount >= 1 {
            score += 15.0 * Double(fridaMarkerCount)
        }

        // 多个可疑 socket 同时出现——组合加分
        if totalSuspicious >= 3 {
            score += Double(totalSuspicious) * 3
        }

        return DetectorResult(score: min(score, 80), methods: methods)
    }

    // MARK: - Socket 扫描

    /// 遍历文件描述符，收集所有 Unix 域套接字的本地/对端地址信息。
    /// - 扫描范围：fd 3..<1024（0–2 为标准流）；
    /// - 单项探测失败（非 Unix socket、已关闭 fd）直接跳过，不影响整体扫描。
    private func sweepUnixSockets() -> [SocketObservation] {
        var observations: [SocketObservation] = []

        for fd: Int32 in 3..<fdScanMax {
            let localInfo = getSocketPath(fd: fd, getPeer: false)
            guard let localPath = localInfo.path, localInfo.isUnix else { continue }

            let peerInfo = getSocketPath(fd: fd, getPeer: true)
            let peerPath = peerInfo.path ?? ""

            // 抽象命名空间：sun_path 为空或以 NUL 开头（无文件系统路径）。
            let isAbstract = localPath.isEmpty || localPath.utf8.first == 0

            // 检查可疑模式
            var isSuspicious = false
            var reason = ""

            if isAbstract {
                isSuspicious = true
                reason = "abstract_namespace"
            }

            let localLower = localPath.lowercased()
            let peerLower = peerPath.lowercased()

            if suspiciousPathPrefixes.contains(where: { localPath.hasPrefix($0) || peerPath.hasPrefix($0) }) {
                isSuspicious = true
                reason = reason.isEmpty ? "tmp_path" : reason + "+tmp_path"
            }

            if fridaPathMarkers.contains(where: { localLower.contains($0) || peerLower.contains($0) }) {
                isSuspicious = true
                reason = reason.isEmpty ? "frida_marker" : reason + "+frida_marker"
            }

            // 非预期位置：不在白名单前缀下且为相对路径的 socket 属异常。
            if !localPath.isEmpty && !isAbstract {
                let isExpectedPrefix = localPath.hasPrefix("/var/run/") ||
                    localPath.hasPrefix("/var/tmp/") ||
                    localPath.hasPrefix("/tmp/") ||
                    localPath.hasPrefix("/private/var/") ||
                    localPath.hasPrefix("/usr/") ||
                    localPath.hasPrefix("/etc/")
                if !isExpectedPrefix && !localPath.hasPrefix("/") {
                    // 相对路径 socket——不常见
                    isSuspicious = true
                    reason = reason.isEmpty ? "relative_path" : reason + "+relative_path"
                }
            }

            observations.append(SocketObservation(
                fd: fd,
                localPath: localPath,
                peerPath: peerPath,
                isAbstract: isAbstract,
                isSuspicious: isSuspicious,
                reason: reason
            ))
        }

        return observations
    }

    // MARK: - Socket 地址查询

    /// 获取 Unix 域套接字 fd 对应的路径。
    /// - Parameters:
    ///   - fd: 目标文件描述符。
    ///   - getPeer: true 用 getpeername 查对端，false 用 getsockname 查本地。
    /// - Returns: `(路径, 是否 AF_UNIX)`；非 Unix socket 或调用失败时路径为 nil。
    private func getSocketPath(fd: Int32, getPeer: Bool) -> (path: String?, isUnix: Bool) {
        var addr = sockaddr_un()
        var len = socklen_t(MemoryLayout<sockaddr_un>.size)

        let result: Int32
        if getPeer {
            result = withUnsafeMutablePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    getpeername(fd, sockPtr, &len)
                }
            }
        } else {
            result = withUnsafeMutablePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    getsockname(fd, sockPtr, &len)
                }
            }
        }

        // 调用失败或不是 AF_UNIX 都视为非目标 fd，交由调用方跳过。
        guard result == 0, addr.sun_family == sa_family_t(AF_UNIX) else {
            return (nil, false)
        }

        // 从 sockaddr_un 提取路径
        let maxLen = MemoryLayout.size(ofValue: addr.sun_path)
        let path = withUnsafePointer(to: &addr.sun_path) { ptr in
            let cptr = UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            let strLen = strnlen(cptr, maxLen)
            if strLen == 0 {
                // 可能是抽象命名空间 socket（sun_path[0] == '\0'）；
                // 首字节为 NUL 时，真正的名称从第 2 字节开始。
                if maxLen > 1 && cptr[1] != 0 {
                    let abstractLen = strnlen(cptr + 1, maxLen - 1)
                    return "@" + String(data: Data(bytes: cptr + 1, count: abstractLen), encoding: .utf8)!
                }
                return ""
            }
            return String(data: Data(bytes: cptr, count: strLen), encoding: .utf8) ?? ""
        }

        return (path, true)
    }
}

// MARK: - 信号转换

extension UnixSocketSweepDetector {
    /// 将扫描结果转换为 `unix_socket_anomaly` 软信号。
    /// - 禁用态不产生任何信号（避免默认配置下引入噪声）；
    /// - score 二次封顶 40、置信度按 score/60 折算，layer 2、weightHint 45。
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()

        // 禁用时不上报任何信号
        if result.methods.contains("unix_socket_sweep:disabled") {
            return []
        }

        guard result.score > 0 else { return [] }

        let suspiciousMethods = result.methods.filter { $0.hasPrefix("unix_socket_sweep:") && !$0.contains("disabled") }

        var signals: [RiskSignal] = []

        if !suspiciousMethods.isEmpty {
            let confidence = min(result.score / 60.0, 1.0)
            signals.append(RiskSignal(
                id: "unix_socket_anomaly",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(result.score, 40),
                evidence: [
                    "detail": suspiciousMethods.joined(separator: ","),
                    "suspicious_count": "\(suspiciousMethods.count)",
                ],
                state: .soft(confidence: confidence),
                layer: 2,
                weightHint: 45
            ))
        }

        return signals
    }
}
