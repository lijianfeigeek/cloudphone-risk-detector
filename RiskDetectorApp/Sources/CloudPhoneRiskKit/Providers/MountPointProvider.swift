import Darwin
import Foundation

// 挂载点 Provider。
// 通过 `getmntinfo` 枚举当前挂载的文件系统，识别虚拟化文件系统、缺失 APFS/根挂载、
// 以及挂载数量异常。云手机/模拟器常使用 virtiofs、9p、overlay 等虚拟文件系统。
// 所有信号均为 soft，避免越狱设备或企业 MDM 挂载造成误杀。

#if targetEnvironment(simulator)
/// 模拟器实现：无法获得有意义的挂载信息，固定返回 `.unavailable` 且 weightHint=0。
final class MountPointProvider: RiskSignalProvider {
    static let shared = MountPointProvider()
    private init() {}
    let id = "mount_point"
    /// 模拟器固定返回不可用信号，weightHint=0 表示不参与评分。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        return [
            RiskSignal(
                id: "mount_unavailable",
                category: "device",
                score: 0,
                evidence: ["detail": "simulator"],
                state: .unavailable,
                layer: 2,
                weightHint: 0
            ),
        ]
    }
}
#else
// 虚拟化文件系统类型黑名单；命中任一即说明根文件系统可能由宿主机透传。
// 其中 9p/virtiofs/vboxsf/vmhgfs 常见于虚拟机，overlay/aufs 常见于容器化云手机。
private let virtualFSBlacklist: [String] = [
    "virtfs", "9p", "virtiofs", "fuse", "overlay", "aufs", "vboxsf", "vmhgfs",
]

/// 把 C 定长字符元组（如 f_fstypename）转为 Swift String。
/// 依赖数组在内存中连续存放，并以 NUL 结尾。
private func extractCString<T>(from tuple: T) -> String {
    withUnsafePointer(to: tuple) { ptr in
        ptr.withMemoryRebound(to: CChar.self, capacity: MemoryLayout<T>.size) {
            String(cString: $0)
        }
    }
}

/// 真机实现：枚举挂载表并检查虚拟文件系统、必需挂载与数量异常。
final class MountPointProvider: RiskSignalProvider {
    static let shared = MountPointProvider()
    private init() {}
    let id = "mount_point"

    /// 采集挂载信息并转换为风险信号；`getmntinfo` 失败时返回不可用信号。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        var mntbuf: UnsafeMutablePointer<statfs>?
        let count = getmntinfo(&mntbuf, MNT_NOWAIT)
        guard count > 0, let buf = mntbuf else {
            Logger.log("mount_point: getmntinfo failed")
            return [
                RiskSignal(
                    id: "mount_unavailable",
                    category: "device",
                    score: 0,
                    evidence: ["detail": "getmntinfo_failed"],
                    state: .unavailable,
                    layer: 2,
                    weightHint: 0
                ),
            ]
        }

        var out: [RiskSignal] = []
        var hasApfs = false
        var hasRoot = false
        var hitVirtualFS: String?
        let mountCount = Int(count)

        // 单次遍历同时记录：是否使用 APFS、是否存在根挂载、是否命中虚拟文件系统。
        for i in 0..<mountCount {
            let stat = buf[i]
            let fsType = extractCString(from: stat.f_fstypename)
            let mnton = extractCString(from: stat.f_mntonname)
            let fsLower = fsType.lowercased()
            let mntonNorm = mnton.trimmingCharacters(in: .whitespaces)

            if fsLower == "apfs" { hasApfs = true }
            if mntonNorm == "/" { hasRoot = true }

            if hitVirtualFS == nil {
                for black in virtualFSBlacklist {
                    if fsLower.contains(black) {
                        hitVirtualFS = fsType
                        break
                    }
                }
            }
        }

        // 命中虚拟文件系统即高度可疑：真机用户空间通常不会挂载 virtiofs/9p 等宿主共享目录。
        if let vfs = hitVirtualFS {
            out.append(
                RiskSignal(
                    id: "mount_virtual_fs",
                    category: "device",
                    score: 0,
                    evidence: ["fstype": vfs],
                    state: .soft(confidence: 0.85),
                    layer: 2,
                    weightHint: 75
                )
            )
        }

        // 正常 iOS 启动盘应为 APFS 且挂载在 "/"；缺失任意一项说明根文件系统可能被替换或隔离。
        if !hasApfs || !hasRoot {
            var missing: [String] = []
            if !hasApfs { missing.append("apfs") }
            if !hasRoot { missing.append("/") }
            out.append(
                RiskSignal(
                    id: "mount_missing_required",
                    category: "device",
                    score: 0,
                    evidence: ["missing": missing.joined(separator: ",")],
                    state: .soft(confidence: 0.6),
                    layer: 2,
                    weightHint: 60
                )
            )
        }

        // 真机挂载数通常在个位数；少于 2 可能是信息被截断，多于 30 常见于容器/多租户环境。
        if mountCount < 2 || mountCount > 30 {
            out.append(
                RiskSignal(
                    id: "mount_count_anomaly",
                    category: "device",
                    score: 0,
                    evidence: ["count": "\(mountCount)"],
                    state: .soft(confidence: 0.5),
                    layer: 2,
                    weightHint: 45
                )
            )
        }

        return out
    }
}
#endif
