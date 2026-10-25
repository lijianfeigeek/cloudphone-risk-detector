// 检测器注册中心协议（DetectorRegistryProtocol）
// 职责：把 DetectorRegistry 的注册、执行、封印与元数据查询能力抽象为协议。
// 管道位置：Detection/Adapter 层；DetectorRegistry 通过文件末尾的 extension 自动满足该协议。
// 扩展点：单元测试可注入 Mock 注册表，替换生产环境的 DetectorRegistry.shared。
import Foundation

// MARK: - 检测器注册中心协议
/// 将 DetectorRegistry 的核心 API 抽象为协议，便于单元测试中注入 Mock 实现。
///
/// 线程模型：实现方需保证 `register` / `unregister` / `seal` 与读取操作线程安全；
/// 本协议仅声明能力，不强制同步策略。`seal()` 之后实现方必须拒绝任何注册变更，
/// 防止运行期被第三方代码替换检测器（fail-closed）。
///
/// 典型用法（测试中）：
/// ```swift
/// class MockDetectorRegistry: DetectorRegistering {
///     var stubbedResult: DetectorResult = .empty
///     func detect(type: DetectorRegistry.DetectorType) -> DetectorResult { stubbedResult }
///     ...
/// }
/// ```
public protocol DetectorRegistering: AnyObject {
    /// 执行指定类型的检测。
    /// - Parameter type: 已注册的检测器类型。
    /// - Returns: 检测结果；检测器未注册或实例化失败时返回空结果（`.empty`）。
    func detect(type: DetectorRegistry.DetectorType) -> DetectorResult

    /// 执行指定分组的所有检测，组内按稳定顺序串行执行。
    /// - Parameter group: 检测器分组。
    /// - Returns: 分组分数、命中的方法列表与分组标识。
    func detect(group: DetectorRegistry.DetectorGroup) -> GroupDetectionResult

    /// 执行所有启用的检测，并按 `signalOverlapGroup` 做同组去重（取最高分）。
    /// - Parameter enabledTypes: 本次启用的检测器类型集合。
    /// - Returns: 各分组结果与总分；重复信号不会重复计分。
    func detectAll(enabledTypes: Set<DetectorRegistry.DetectorType>) -> ComprehensiveDetectionResult

    /// 注册自定义检测器；工厂延迟到 `createDetector` 时才执行。
    /// 封印后调用会被忽略并记录日志，不会覆盖已有实现。
    func register(type: DetectorRegistry.DetectorType, factory: @escaping DetectorRegistry.DetectorFactory)

    /// 注销检测器；封印后同样被拒绝，避免攻击者移除检测能力。
    func unregister(type: DetectorRegistry.DetectorType)

    /// 封印注册表：此后注册/注销永久失效，用于冻结已校验的检测器布局。
    func seal()

    /// 注册表是否已封印（封印后只读）。
    var isSealed: Bool { get }

    /// 创建检测器实例；未注册时返回 nil，由调用方决定是否降级。
    func createDetector(type: DetectorRegistry.DetectorType) -> Detector?

    /// 获取检测器元数据（版本区间、依赖、冲突、重叠组与优先级）。
    func manifest(for type: DetectorRegistry.DetectorType) -> DetectorRegistry.DetectorManifest

    /// 判断检测器在给定 iOS 版本是否可用（落在 `minOS...maxOS` 区间内）。
    func isAvailable(_ type: DetectorRegistry.DetectorType, osVersion: Double) -> Bool
}

// MARK: - DetectorRegistry 默认遵循协议
/// 生产实现直接复用 `DetectorRegistry` 的加锁注册表与封印语义。
extension DetectorRegistry: DetectorRegistering {}
