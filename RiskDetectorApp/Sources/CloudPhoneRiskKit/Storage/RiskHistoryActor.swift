// 文件职责：为 RiskHistoryStore 提供 async/await 的 Actor 门面。
// 管道位置：Storage 并发访问层，异步调用方经此串行访问历史存储。
// 安全不变量：Actor 隔离保证同一时刻只有一个异步任务修改历史，避免数据竞争。
import Foundation

// MARK: - 基于 Actor 的风险历史访问
//
// 为 RiskHistoryStore 提供 async/await 访问。
// 异步调用方使用本 Actor；同步调用方仍直接使用 RiskHistoryStore。

/// 风险历史操作的 Actor 门面：把同步存储调用隔离到 Actor 执行器。
@available(iOS 13.0, macOS 10.15, *)
public actor RiskHistoryActor {

    /// 全局单例。
    public static let shared = RiskHistoryActor()

    /// 底层同步存储。
    private let store: RiskHistoryStore

    /// 创建门面；默认复用共享存储，测试可注入替身。
    init(store: RiskHistoryStore = .shared) {
        self.store = store
    }

    /// 追加一条风险历史事件（内部同步落盘）。
    public func append(_ event: RiskHistoryEvent) {
        store.append(event)
    }

    /// 计算最近 24 小时的时序模式。
    /// - Parameter now: 计算基准时间（Unix 秒）。
    /// - Returns: 24 小时窗口内的时序统计。
    public func pattern(now: TimeInterval = Date().timeIntervalSince1970) -> TimePattern {
        store.pattern(now: now)
    }
}
