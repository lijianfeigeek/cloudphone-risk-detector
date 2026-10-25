// CFF 返回槽：以三态（pending/value/poisoned）承载被平坦化状态机的返回值。
// 位于 Internal/CFF 的状态机基础设施层，供 fail-closed/poison 策略在异常状态下丢弃结果。
// 关键安全不变量：值只能从 pending 写入一次；poisoned 状态永远不可被后续 store 覆盖。
import Foundation

/// 一个单次写入的返回值容器。
/// 线程模型：值类型，非线程安全；调用方需保证单线程使用。
/// 安全语义：`poison()` 后不接受任何写入，`resolve` 只返回调用方提供的 fallback。
internal struct CFFReturnSink<Value> {
    /// 内部状态机。
    private enum Storage {
        /// 尚未写入结果。
        case pending
        /// 已写入结果。
        case value(Value)
        /// 状态异常，结果被投毒作废。
        case poisoned
    }

    /// 当前状态，初始为 `pending`。
    private var storage: Storage = .pending

    /// 是否已成功写入结果。
    internal var isResolved: Bool {
        switch storage {
        case .value:
            return true
        case .pending, .poisoned:
            return false
        }
    }

    /// 是否已进入投毒状态。
    internal var isPoisoned: Bool {
        if case .poisoned = storage {
            return true
        }
        return false
    }

    /// 写入结果；仅当当前为 `pending` 时生效，避免覆盖已定结果。
    /// - Parameter value: 要保存的返回值。
    internal mutating func store(_ value: Value) {
        guard case .pending = storage else { return }
        storage = .value(value)
    }

    /// 将槽标记为投毒；仅当当前为 `pending` 时生效。
    internal mutating func poison() {
        guard case .pending = storage else { return }
        storage = .poisoned
    }

    /// 解析最终返回值。
    /// - Parameter fallback: 未写入或已投毒时使用的兜底值（自动闭包，仅在需要时求值）。
    /// - Returns: 已写入的值，或 fallback。
    internal func resolve(or fallback: @autoclosure () -> Value) -> Value {
        switch storage {
        case .value(let value):
            return value
        case .pending, .poisoned:
            return fallback()
        }
    }
}
