// App 生命周期心跳提供者：注册 UIApplication 生命周期通知并计数，用于识别没有 UI 驱动的
// headless 进程（协议回放 / unidbg / 注入式拉起）。思路启发自小红书 x208 心跳字段。
// 启动后 5 秒为静默期；之后 active 状态却 0 个生命周期事件 → headless_no_lifecycle_events(60, hard)；
// 状态探测超时 + 0 事件 → lifecycle_state_unknown_during_check(15, soft)；
// 只有 resign/background 而无 becomeActive → lifecycle_partial_no_become_active(25, soft)。

import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// 应用生命周期心跳提供者（单例）。
///
/// 线程模型：观察者回调统一派发到主队列，计数字段由 `UnfairLock` 保护；
/// 非主线程读取 applicationState 时通过信号量等待主线程，最多 250ms。
final class AppLifecycleHeartbeatProvider: RiskSignalProvider {

    static let shared = AppLifecycleHeartbeatProvider()
    let id = "app_lifecycle_heartbeat"

    /// 启动静默期：给系统留出投递首个 didBecomeActive 的时间，避免冷启动误报。
    private static let warmupSeconds: TimeInterval = 5.0
    /// 主线程状态探测超时；超时返回 "unknown"，不会阻塞评估链路超过该时长。
    private static let appStateProbeTimeoutMs: Int = 250

    /// 保护四个计数与 observer 数组；观察者回调可能来自任意线程。
    private let lock = UnfairLock()
    /// 提供者创建时刻，用于计算静默期是否结束。
    private let providerStartTime: Date
    private var didBecomeActiveCount: Int = 0
    private var willResignActiveCount: Int = 0
    private var didEnterBackgroundCount: Int = 0
    private var willEnterForegroundCount: Int = 0
    private var observers: [NSObjectProtocol] = []

    /// 单例初始化时立即注册观察者：避免“注册前已经发生过 didBecomeActive”导致漏计。
    private init() {
        self.providerStartTime = Date()
        registerObservers()
    }

    deinit {
        unregisterObservers()
    }

    /// 根据生命周期事件计数与当前 App 状态生成信号。
    ///
    /// - 静默期内始终返回空数组。
    /// - 0 事件时区分 active（强信号）、unknown（探测超时，轻信号）与 background（合理静默）。
    /// - 只有退出事件、从未进入 active 时给中等强度的部分信号。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let elapsed = Date().timeIntervalSince(providerStartTime)
        let counts = countsSnapshot()
        let totalEvents = counts.didBecomeActiveCount
            + counts.willResignActiveCount
            + counts.didEnterBackgroundCount
            + counts.willEnterForegroundCount

        // 静默期：刚启动，给系统时间发出第一个 didBecomeActive 通知。
        guard elapsed >= Self.warmupSeconds else {
            return []
        }

        let appState = currentApplicationStateString()

        if totalEvents == 0 {
            // 0 个事件 — 是真的 headless 还是合理的后台启动？
            switch appState {
            case "active":
                // 进程 active 但 0 个生命周期事件 — 强信号。
                return [
                    RiskSignal(
                        id: "headless_no_lifecycle_events",
                        category: ObfuscatedConstants.categoryAntiTamper,
                        score: 60,
                        evidence: [
                            "elapsed_seconds": String(format: "%.1f", elapsed),
                            "app_state": appState,
                            "hint": "AppState=.active 但未观察到任何 UIApplication 生命周期通知 — 协议模拟 / unidbg / 注入式启动",
                        ],
                        state: .hard(detected: true),
                        layer: 1,
                        weightHint: 70
                    )
                ]
            case "unknown":
                // appState 探测超时（main 拥塞）。可能是合法重负载，也可能是 headless 故意把
                // main 卡死阻止我们查询 — 给一个轻信号。
                return [
                    RiskSignal(
                        id: "lifecycle_state_unknown_during_check",
                        category: ObfuscatedConstants.categoryAntiTamper,
                        score: 15,
                        evidence: [
                            "elapsed_seconds": String(format: "%.1f", elapsed),
                            "hint": "main thread state probe timed out + 0 lifecycle events",
                        ],
                        state: .soft(confidence: 0.4),
                        layer: 1,
                        weightHint: 35
                    )
                ]
            default:
                // 后台 / 不活跃 — 合理静默。
                return []
            }
        }

        if counts.didBecomeActiveCount == 0 && counts.willResignActiveCount + counts.didEnterBackgroundCount > 0 {
            // 只有"resign / background"事件但从未"becomeActive" — 异常但不致命。
            return [
                RiskSignal(
                    id: "lifecycle_partial_no_become_active",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 25,
                    evidence: [
                        "elapsed_seconds": String(format: "%.1f", elapsed),
                        "app_state": appState,
                        "did_become_active_count": "0",
                        "will_resign_count": "\(counts.willResignActiveCount)",
                        "did_enter_background_count": "\(counts.didEnterBackgroundCount)",
                    ],
                    state: .soft(confidence: 0.6),
                    layer: 1,
                    weightHint: 50
                )
            ]
        }

        return []
    }

    // MARK: - 状态读取

    /// 四个生命周期事件的累计计数快照。
    private struct Counts {
        let didBecomeActiveCount: Int
        let willResignActiveCount: Int
        let didEnterBackgroundCount: Int
        let willEnterForegroundCount: Int
    }

    /// 加锁复制计数，保证读到的是同一时刻的一致快照。
    private func countsSnapshot() -> Counts {
        lock.withLock {
            Counts(
                didBecomeActiveCount: didBecomeActiveCount,
                willResignActiveCount: willResignActiveCount,
                didEnterBackgroundCount: didEnterBackgroundCount,
                willEnterForegroundCount: willEnterForegroundCount
            )
        }
    }

    // MARK: - 观察者注册

    /// 注册四个 UIApplication 生命周期通知；仅在可导入 UIKit 的平台生效。
    /// - 回调使用 `[weak self]`，避免 NotificationCenter 强引用导致单例无法释放。
    private func registerObservers() {
        #if canImport(UIKit)
        let center = NotificationCenter.default
        let queue = OperationQueue.main

        let didBecomeActive = center.addObserver(
            forName: UIApplication.didBecomeActiveNotification,
            object: nil, queue: queue
        ) { [weak self] _ in
            guard let self = self else { return }
            self.lock.withLock { self.didBecomeActiveCount += 1 }
        }
        let willResign = center.addObserver(
            forName: UIApplication.willResignActiveNotification,
            object: nil, queue: queue
        ) { [weak self] _ in
            guard let self = self else { return }
            self.lock.withLock { self.willResignActiveCount += 1 }
        }
        let didBackground = center.addObserver(
            forName: UIApplication.didEnterBackgroundNotification,
            object: nil, queue: queue
        ) { [weak self] _ in
            guard let self = self else { return }
            self.lock.withLock { self.didEnterBackgroundCount += 1 }
        }
        let willForeground = center.addObserver(
            forName: UIApplication.willEnterForegroundNotification,
            object: nil, queue: queue
        ) { [weak self] _ in
            guard let self = self else { return }
            self.lock.withLock { self.willEnterForegroundCount += 1 }
        }

        lock.withLock {
            observers = [didBecomeActive, willResign, didBackground, willForeground]
        }
        #endif
    }

    /// 反注册所有通知观察者；先原子取走数组，避免与注册/析构并发重复移除。
    private func unregisterObservers() {
        let toRemove = lock.withLock { () -> [NSObjectProtocol] in
            let copy = observers
            observers = []
            return copy
        }
        let center = NotificationCenter.default
        for token in toRemove {
            center.removeObserver(token)
        }
    }

    /// 读取当前 applicationState 的字符串表示。
    ///
    /// - 已处于主线程时直接读取，避免无谓等待。
    /// - 否则异步派发到主线程并最多等待 250ms；超时返回 "unknown"（可能是 main 被恶意占满）。
    /// - 非 UIKit 平台返回 "unsupported"，调用方按静默处理。
    private func currentApplicationStateString() -> String {
        #if canImport(UIKit)
        if Thread.isMainThread {
            return Self.applicationStateString(UIApplication.shared.applicationState)
        }
        var captured: String = "unknown"
        let semaphore = DispatchSemaphore(value: 0)
        DispatchQueue.main.async {
            captured = Self.applicationStateString(UIApplication.shared.applicationState)
            semaphore.signal()
        }
        _ = semaphore.wait(timeout: .now() + .milliseconds(Self.appStateProbeTimeoutMs))
        return captured
        #else
        return "unsupported"
        #endif
    }

    #if canImport(UIKit)
    /// 将 UIKit 枚举映射为稳定的字符串，便于作为 evidence 上报与跨版本对比。
    private static func applicationStateString(_ state: UIApplication.State) -> String {
        switch state {
        case .active: return "active"
        case .inactive: return "inactive"
        case .background: return "background"
        @unknown default: return "unknown"
        }
    }
    #endif
}
