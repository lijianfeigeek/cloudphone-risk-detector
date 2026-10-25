// 越狱检测器的统一协议：约束所有检测模块只暴露一个 `detect()` 入口。
// 位于越狱检测管道的第一层：JailbreakEngine 按配置依次实例化并调用各 Detector。
// 关键约定：检测器通过抛错或负分表达“自身故障”，绝不与“检测到越狱”混淆。
import Foundation

// MARK: - 检测器协议
/// 所有检测模块必须实现此协议
/// 这是"面向协议编程"的体现：引擎只依赖统一接口，便于替换与扩展。
public protocol Detector {

    /// 执行检测
    /// - Returns: 检测结果（分数 + 命中方法）
    /// - Throws: 检测过程中出现不可恢复错误时抛出；引擎会将其记为检测器故障，
    ///   而不是直接判定设备越狱（故障与命中必须区分，避免误伤）。
    func detect() throws -> DetectorResult
}

// 为什么用协议：
//
// 1. 统一接口：所有检测器都有 detect() 方法
// 2. 易于扩展：添加新检测器只需实现协议
// 3. 可测试：可以 mock 实现进行单元测试
//
// 使用示例：
//    let detector: Detector = FileDetector()
//    let result = detector.detect()
