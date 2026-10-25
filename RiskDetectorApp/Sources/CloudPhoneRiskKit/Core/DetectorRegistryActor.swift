// MARK: - 基于 Actor 的检测器注册表门面
//
// 职责：为 async/await 调用路径提供对 `DetectorRegistry` 的并发安全访问入口，
// 与同步的 `DetectorRegistering` 协议实现共存；位于评估管线的检测执行阶段。
// 安全不变量：所有注册表访问经 actor 串行化，避免并发读写造成检测结果竞争。
//
// 用法：
//   let result = await DetectorRegistryActor.shared.detect(type: .frida)

import Foundation

/// 检测器注册表的 Actor 门面。
///
/// 包装 `DetectorRegistry.shared` 并以 actor 隔离提供编译期线程安全，
/// 同一时刻只允许一个异步调用方进入底层注册表。
@available(iOS 13.0, macOS 10.15, *)
public actor DetectorRegistryActor {

    /// 进程内共享门面实例（actor 单例）
    public static let shared = DetectorRegistryActor()

    // MARK: - 检测执行

    /// 执行单个检测器类型。
    /// - Parameter type: 检测器类型（如 Frida、越狱等）。
    /// - Returns: 该检测器的执行结果；检测不可用时返回对应的不可用结果。
    public func detect(type: DetectorRegistry.DetectorType) -> DetectorResult {
        DetectorRegistry.shared.detect(type: type)
    }

    /// 执行某个检测器分组的全部检测器。
    /// - Parameter group: 检测器分组。
    /// - Returns: 分组检测的聚合结果。
    public func detect(group: DetectorRegistry.DetectorGroup) -> GroupDetectionResult {
        DetectorRegistry.shared.detect(group: group)
    }

    /// 执行全部已启用的检测器类型。
    /// - Parameter enabledTypes: 本次评估允许启用的检测器集合。
    /// - Returns: 综合检测结果，包含各检测器的信号输出。
    public func detectAll(enabledTypes: Set<DetectorRegistry.DetectorType>) -> ComprehensiveDetectionResult {
        DetectorRegistry.shared.detectAll(enabledTypes: enabledTypes)
    }

    // MARK: - 查询

    /// 获取检测器清单（能力、版本、依赖等元数据）。
    /// - Parameter type: 检测器类型。
    /// - Returns: 对应的检测器清单。
    public func manifest(for type: DetectorRegistry.DetectorType) -> DetectorRegistry.DetectorManifest {
        DetectorRegistry.shared.manifest(for: type)
    }

    /// 判断检测器在指定系统版本上是否可用。
    /// - Parameters:
    ///   - type: 检测器类型。
    ///   - osVersion: 目标系统版本号（如 16.0）。
    /// - Returns: 可用返回 `true`。
    public func isAvailable(_ type: DetectorRegistry.DetectorType, osVersion: Double) -> Bool {
        DetectorRegistry.shared.isAvailable(type, osVersion: osVersion)
    }

    /// 注册表是否已封存。
    ///
    /// 封存后不再接受新的检测器注册，防止运行期被注入恶意检测器。
    /// - Returns: 已封存返回 `true`。
    public func isSealed() -> Bool {
        DetectorRegistry.shared.isSealed
    }
}
