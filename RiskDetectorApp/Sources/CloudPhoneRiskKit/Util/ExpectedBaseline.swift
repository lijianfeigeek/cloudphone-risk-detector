// 按 iOS 版本自适应调整系统探测的“期望值”，避免高版本特性在低版本上被用来伪装安全。
// 版本号只从 kern.osversion 构建号推导，不信任 ProcessInfo，防止 swizzle 篡改版本判断。

import Darwin
import Foundation

// MARK: - 动态系统版本基线自适应 [4.4.7]

/// 针对不同 iOS 版本设定不同的探测期望值。
/// 防止黑产利用高版本特性在低版本上伪装安全。
/// 同时通过 kern.osversion sysctl 交叉验证，防止 ProcessInfo 被 swizzle。
enum ExpectedBaseline {

    /// iOS 主版本号（仅用 sysctl kern.osversion，不依赖 ProcessInfo 防篡改）
    /// 读取失败时回退到 16，采用相对保守的规则集而不是直接放行。
    private static var iosMajorVersion: Int {
        iosMajorFromBuildNumber() ?? 16
    }

    /// 从 kern.osversion 构建号推算 iOS 主版本
    /// 构建号格式如 "22A3354"，前两位为 Darwin 内核主版本
    /// 映射：22→iOS 18, 21→17, 20→16, 19→15 …（darwinMajor - 4）
    private static func iosMajorFromBuildNumber() -> Int? {
        // 走双路校验的 sysctl，避免单路返回值被 hook。
        let (value, _, _, _, _) = DualPathValidator.validateSysctl(key: "kern.osversion")
        guard let build = value, build.count >= 2 else { return nil }
        let prefix = build.prefix(2)
        guard let darwinMajor = Int(prefix) else { return nil }
        // Darwin 主版本与 iOS 主版本长期保持相差 4 的映射关系。
        return darwinMajor - 4
    }

    /// 空进程列表是否可疑
    /// iOS < 17：空列表视为被 Hook（正常设备应能读到进程列表）
    /// iOS 17+：空列表可能为高版本沙盒策略，予以放行
    static var emptyProcessListIsSuspicious: Bool {
        iosMajorVersion < 17
    }

    /// 受保护路径上返回 EPERM/EACCES 是否可疑
    /// iOS 16+：理应返回 ENOENT 的路径却返回 EPERM/EACCES，判定为内核级沙盒策略被篡改
    /// iOS < 16：不启用此检查
    static var epermOnProtectedPathIsSuspicious: Bool {
        iosMajorVersion >= 16
    }

    /// 判断给定 errno 是否为权限拒绝类错误。
    /// 单独封装便于所有调用点对 EPERM/EACCES 采用一致语义。
    static func isPermissionDeniedErrno(_ e: Int32) -> Bool {
        e == EPERM || e == EACCES
    }
}
