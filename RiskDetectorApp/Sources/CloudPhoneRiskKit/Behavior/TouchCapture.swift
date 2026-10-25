// 触摸采集器：交换 `UIApplication.sendEvent(_:)`，按触摸相位累计位置、时间、力度等原始事件，
// 评估时聚合成 TouchMetrics 并立即清空原始点，只保留聚合统计与动作时间戳。
// 无 UIKit 或交换失败时静默降级，不影响宿主事件链。
import Foundation
#if canImport(UIKit)
import UIKit
import ObjectiveC.runtime

/// 触摸采集单例。
/// 线程模型：事件来自主线程，读取/清零可能来自任意线程，全部通过 `UnfairLock` 串行化。
/// 安全不变量：快照或 `clearSensitiveData()` 后，原始坐标/时间/压力数组均被覆写清零。
final class TouchCapture {
    // 全局单例，与 SDK 生命周期绑定；重复 start 不会重复交换方法。
    static let shared = TouchCapture()
    private init() {}

    private let lock = UnfairLock()
    private var started = false
    // 原始触摸点（pt）；仅用于计算 spread，快照后清空。
    private var touchPoints: [CGPoint] = []
    // 点击时间戳；用于计算点击间隔变异系数。
    private var tapTimestamps: [TimeInterval] = []
    // 每次滑动的直线度（0..1）。
    private var swipeLinearities: [Double] = []
    // 当前手势的路径点，began 时重置，ended 时结算。
    private var currentSwipePath: [CGPoint] = []
    private var swipeCount = 0
    private var tapCount = 0
    // 所有动作的抬手时间戳，供触摸-运动耦合分析按时间桶对齐。
    private var actionTimestamps: [TimeInterval] = []
    // 按压力度与接触半径；仅部分设备提供有效值。
    private var forces: [Double] = []
    private var majorRadii: [Double] = []

    // 5 秒内且期间无新触摸时返回缓存，避免同一评估窗口被反复取快照而清零丢样本。
    private let minSnapshotInterval: TimeInterval = 5.0
    private var lastSnapshotTime: TimeInterval = 0
    private var cachedSnapshot: (metrics: TouchMetrics, actionTimestamps: [TimeInterval])?
    // 每次滑动的平均速度（pt/s）。
    private var swipeSpeeds: [Double] = []
    // 当前手势的起始时间，用于结算滑动时长与速度。
    private var currentSwipeStartTime: TimeInterval = 0

    /// 启动采集：首次调用时安装方法交换，之后仅置位。
    func start() {
        lock.withLock {
            guard !started else { return }
            started = true
            // swizzle 内部有一次性 token 与 IMP 比对，重复调用是安全的。
            UIApplicationSendEventSwizzler.swizzleOnce()
        }
    }

    /// 停止采集并清零所有原始样本。
    func stop() {
        lock.withLock {
            started = false
            zeroSensitiveBuffersLocked()
        }
    }

    /// 从 `sendEvent` 接收事件。只处理带触摸的事件，其他事件（遥控、按键等）直接跳过。
    func process(event: UIEvent) {
        guard let touches = event.allTouches, !touches.isEmpty else { return }
        lock.withLock {
            guard started else { return }
            for touch in touches {
                record(touch: touch)
            }
        }
    }

    /// 取指标并清零，供评估流程消费。
    func snapshotAndReset() -> TouchMetrics {
        snapshotDetailAndReset().metrics
    }

    /// 取指标与动作时间戳并清零；时间戳用于与运动序列做耦合分析。
    func snapshotDetailAndReset() -> (metrics: TouchMetrics, actionTimestamps: [TimeInterval]) {
        lock.withLock { _snapshotDetailAndResetLocked() }
    }

    /// 调用方必须已持有 `lock`。
    private func _snapshotDetailAndResetLocked() -> (metrics: TouchMetrics, actionTimestamps: [TimeInterval]) {
        let now = ProcessInfo.processInfo.systemUptime
        // 5 秒节流：期间无新触摸且已有缓存时直接复用，避免下游多次评估导致动作样本被清空。
        if now - lastSnapshotTime < minSnapshotInterval, let cached = cachedSnapshot, touchPoints.isEmpty {
            return cached
        }

        // 各维度独立计算：样本不足的工具函数返回 nil，保持“未知”语义而不是填 0。
        let spread = TouchMath.coordinateSpread(points: touchPoints)
        let intervalCV = TouchMath.intervalCoefficientOfVariation(timestamps: tapTimestamps)
        let avgLinearity = swipeLinearities.isEmpty ? nil : (swipeLinearities.reduce(0, +) / Double(swipeLinearities.count))
        let forceVar = TouchMath.variance(values: forces)
        let radiusVar = TouchMath.variance(values: majorRadii)
        let speedCV = TouchMath.coefficientOfVariation(values: swipeSpeeds)

        let metrics = TouchMetrics(
            sampleCount: touchPoints.count,
            tapCount: tapCount,
            swipeCount: swipeCount,
            coordinateSpread: spread,
            intervalCV: intervalCV,
            averageLinearity: avgLinearity,
            forceVariance: forceVar,
            majorRadiusVariance: radiusVar,
            swipeSpeedCV: speedCV
        )
        #if DEBUG
        Logger.log("behavior.touch: samples=\(metrics.sampleCount) taps=\(metrics.tapCount) swipes=\(metrics.swipeCount) spread=\(metrics.coordinateSpread?.description ?? "nil") intervalCV=\(metrics.intervalCV?.description ?? "nil") avgLinearity=\(metrics.averageLinearity?.description ?? "nil")")
        #endif

        // 先复制动作时间戳再清空数组；keepingCapacity 复用容量，减少高频评估时的内存抖动。
        let actions = actionTimestamps

        touchPoints.removeAll(keepingCapacity: true)
        tapTimestamps.removeAll(keepingCapacity: true)
        swipeLinearities.removeAll(keepingCapacity: true)
        currentSwipePath.removeAll(keepingCapacity: true)
        swipeCount = 0
        tapCount = 0
        actionTimestamps.removeAll(keepingCapacity: true)
        forces.removeAll(keepingCapacity: true)
        majorRadii.removeAll(keepingCapacity: true)
        swipeSpeeds.removeAll(keepingCapacity: true)

        lastSnapshotTime = now
        let result = (metrics, actions)
        cachedSnapshot = result
        return result
    }

    /// 隐私撤回/宿主登出时调用：不等待 stop，立即清零。
    func clearSensitiveData() {
        lock.withLock { zeroSensitiveBuffersLocked() }
    }

    /// 调用方必须已持有 `lock`。
    private func zeroSensitiveBuffersLocked() {
        zeroBuffer(&touchPoints)
        zeroBuffer(&tapTimestamps)
        zeroBuffer(&swipeLinearities)
        zeroBuffer(&currentSwipePath)
        zeroBuffer(&actionTimestamps)
        zeroBuffer(&forces)
        zeroBuffer(&majorRadii)
        zeroBuffer(&swipeSpeeds)
        swipeCount = 0
        tapCount = 0
        currentSwipeStartTime = 0
        lastSnapshotTime = 0
        cachedSnapshot = nil
    }

    /// 先覆写底层字节再释放，降低样本残留被内存转储读取的可能；
    /// 乘法溢出保护避免极端容量导致字节数回绕后越界。
    private func zeroBuffer<T>(_ array: inout [T]) {
        array.withUnsafeMutableBufferPointer { buf in
            guard let base = buf.baseAddress else { return }
            let stride = MemoryLayout<T>.stride
            let (byteCount, overflow) = buf.count.multipliedReportingOverflow(by: stride)
            if overflow { return }
            memset(base, 0, byteCount)
        }
        array.removeAll(keepingCapacity: false)
    }

    /// 记录单个触摸事件。
    private func record(touch: UITouch) {
        // 调用方长期不取快照时防止无界增长：超限丢最旧数据，保留最近约 60% 样本。
        if touchPoints.count > 10000 {
            touchPoints.removeFirst(touchPoints.count - 6000)
        }
        if tapTimestamps.count > 4000 {
            tapTimestamps.removeFirst(tapTimestamps.count - 2400)
        }
        if swipeLinearities.count > 4000 {
            swipeLinearities.removeFirst(swipeLinearities.count - 2400)
        }

        // 坐标取触摸所在视图坐标系，仅用于计算相对分布，不包含窗口绝对位置。
        let p = touch.location(in: touch.view)
        touchPoints.append(p)

        switch touch.phase {
        case .began:
            // 新手势开始：重置路径并记录起点时间。
            currentSwipePath = [p]
            currentSwipeStartTime = touch.timestamp
        case .moved:
            // 单次手势最多保留 500 个点，防止异常长手势占满内存。
            if currentSwipePath.count < 500 {
                currentSwipePath.append(p)
            }
        case .ended:
            // 按压力度与接触半径为尽力而为：设备不提供时值为 0，直接跳过，避免拉低方差。
            if touch.force > 0 { forces.append(Double(touch.force)) }
            if touch.majorRadius > 0 { majorRadii.append(Double(touch.majorRadius)) }
            // 路径至少两个点才算滑动；否则视为点击。二者都会进入动作时间戳序列。
            if currentSwipePath.count >= 2 {
                swipeCount += 1
                // 直线度计算失败（路径退化）时按 1.0 保守处理，不把未知当作异常。
                swipeLinearities.append(TouchMath.linearity(path: currentSwipePath) ?? 1.0)
                let duration = touch.timestamp - currentSwipeStartTime
                if let speed = TouchMath.averageSwipeSpeed(path: currentSwipePath, duration: duration) {
                    swipeSpeeds.append(speed)
                }
                actionTimestamps.append(touch.timestamp)
            } else {
                tapCount += 1
                tapTimestamps.append(touch.timestamp)
                actionTimestamps.append(touch.timestamp)
            }
            currentSwipePath.removeAll(keepingCapacity: true)
        default:
            break
        }
    }
}

/// `UIApplication.sendEvent(_:)` 的一次性方法交换器。
/// 用静态 let 的惰性初始化实现进程级 dispatch_once，避免多线程重复交换。
private enum UIApplicationSendEventSwizzler {
    private static let swizzleToken: Void = {
        _performSwizzle()
    }()

    /// 触发一次性交换；重复调用只读取已初始化的 token。
    static func swizzleOnce() {
        _ = swizzleToken
    }

    private static func _performSwizzle() {

        let cls: AnyClass = UIApplication.self
        let originalSelector = #selector(UIApplication.sendEvent(_:))
        let swizzledSelector = #selector(UIApplication.cprk_sendEvent(_:))

        guard
            let originalMethod = class_getInstanceMethod(cls, originalSelector),
            let swizzledMethod = class_getInstanceMethod(cls, swizzledSelector)
        else {
            return
        }

        // 防重复交换：若 original 的 IMP 已等于 swizzled 的 IMP，说明已被
        // 交换过（或宿主/其他 SDK 已交换到同一实现），再次交换会把实现
        // 换回来，导致采集静默停止。token 一次性保护之外再加 IMP 比对。
        // 宿主冲突风险：宿主 App 或其他 SDK 若也交换 `sendEvent`，交换顺序
        // 会影响调用链——宿主在 SDK 之后交换时链式转发通常仍可用，但若宿主
        // 覆盖而非转发、或重复交换，触摸采集可能静默失效；本 SDK 无法从
        // 宿主侧探测，只能保证自身不重复交换。
        let originalIMP = method_getImplementation(originalMethod)
        let swizzledIMP = method_getImplementation(swizzledMethod)
        guard originalIMP != swizzledIMP else { return }

        method_exchangeImplementations(originalMethod, swizzledMethod)
    }
}

extension UIApplication {
    /// 交换后的实现：先采集再调用“原方法”（交换后符号指向原 IMP），保持事件链不变。
    @objc fileprivate func cprk_sendEvent(_ event: UIEvent) {
        TouchCapture.shared.process(event: event)
        self.cprk_sendEvent(event)
    }
}

/// 触摸统计的纯函数工具集，不持有状态，便于单测。
private enum TouchMath {
    /// 触摸点相对质心的平均欧氏距离（pt）。样本少于 2 时返回 nil。
    static func coordinateSpread(points: [CGPoint]) -> Double? {
        guard points.count >= 2 else { return nil }
        let meanX = points.map(\.x).reduce(0, +) / CGFloat(points.count)
        let meanY = points.map(\.y).reduce(0, +) / CGFloat(points.count)
        let distances = points.map { hypot($0.x - meanX, $0.y - meanY) }
        let avg = distances.reduce(0, +) / CGFloat(distances.count)
        return Double(avg)
    }

    /// 点击间隔的变异系数 = 样本标准差 / 均值。少于 3 个时间戳或均值非正时返回 nil。
    static func intervalCoefficientOfVariation(timestamps: [TimeInterval]) -> Double? {
        guard timestamps.count >= 3 else { return nil }
        let sorted = timestamps.sorted()
        // 排序后相邻求差得到间隔；过滤非正值，防止同一时间戳导致均值被拉低。
        let intervals = zip(sorted.dropFirst(), sorted).map { $0.0 - $0.1 }.filter { $0 > 0 }
        guard intervals.count >= 2 else { return nil }
        let mean = intervals.reduce(0, +) / Double(intervals.count)
        guard mean > 0 else { return nil }
        // 使用 n-1 分母的样本方差，样本量较小时更稳健。
        let variance = intervals.map { pow($0 - mean, 2) }.reduce(0, +) / Double(intervals.count - 1)
        let std = sqrt(variance)
        return std / mean
    }

    /// 滑动直线度 = 首尾直线距离 / 实际路径长度，范围 (0, 1]，1 表示完全直线。
    /// 路径退化（总长度为 0）时返回 nil，由调用方决定回退值。
    static func linearity(path: [CGPoint]) -> Double? {
        guard path.count >= 2 else { return nil }
        var actual: CGFloat = 0
        for i in 0..<(path.count - 1) {
            actual += hypot(path[i + 1].x - path[i].x, path[i + 1].y - path[i].y)
        }
        guard actual > 0 else { return nil }
        guard let first = path.first, let last = path.last else { return nil }
        let straight = hypot(last.x - first.x, last.y - first.y)
        return Double(straight / actual)
    }

    /// 样本方差（n-1 分母）；样本少于 2 时无法估计离散度，返回 nil。
    static func variance(values: [Double]) -> Double? {
        guard values.count >= 2 else { return nil }
        let mean = values.reduce(0, +) / Double(values.count)
        let v = values.map { pow($0 - mean, 2) }.reduce(0, +) / Double(values.count - 1)
        return v
    }

    /// 变异系数 = 标准差 / 均值；均值非正或样本少于 3 时返回 nil。
    static func coefficientOfVariation(values: [Double]) -> Double? {
        guard values.count >= 3 else { return nil }
        let mean = values.reduce(0, +) / Double(values.count)
        guard mean > 0 else { return nil }
        let variance = values.map { pow($0 - mean, 2) }.reduce(0, +) / Double(values.count - 1)
        return sqrt(variance) / mean
    }

    /// 平均滑动速度（pt/s）= 路径总长度 / 手势持续时间；时长非正时返回 nil。
    static func averageSwipeSpeed(path: [CGPoint], duration: TimeInterval) -> Double? {
        guard path.count >= 2, duration > 0 else { return nil }
        var totalDistance: CGFloat = 0
        for i in 0..<(path.count - 1) {
            totalDistance += hypot(path[i + 1].x - path[i].x, path[i + 1].y - path[i].y)
        }
        return Double(totalDistance) / duration
    }
}
#else

/// 非 UIKit 平台降级实现：不安装任何交换，所有采集入口为空操作。
/// 快照返回全 0 / nil 的指标，行为分析据此判定样本不足并跳过触摸维度。
final class TouchCapture {
    static let shared = TouchCapture()
    private init() {}
    func start() {}
    func stop() {}
    func clearSensitiveData() {}
    func snapshotAndReset() -> TouchMetrics {
        snapshotDetailAndReset().metrics
    }
    func snapshotDetailAndReset() -> (metrics: TouchMetrics, actionTimestamps: [TimeInterval]) {
        let metrics = TouchMetrics(
            sampleCount: 0,
            tapCount: 0,
            swipeCount: 0,
            coordinateSpread: nil,
            intervalCV: nil,
            averageLinearity: nil,
            forceVariance: nil,
            majorRadiusVariance: nil,
            swipeSpeedCV: nil
        )
        return (metrics, [])
    }
}
#endif
