// 泛型互斥容器：把“值 + 锁”封装成一个对象，调用方只能通过 withLock 访问内部状态。
// 相比散落的 NSLock.lock()/unlock()，作用域闭包能保证异常路径也会解锁。

import Darwin

/// 基于 `os_unfair_lock` 的线程安全值容器。
///
/// 用 `os_unfair_lock` 替代 `NSLock`：前者无 Objective-C 消息派发开销，且带优先级继承，
/// 能缓解低优先级线程持锁导致高优先级线程被反转的问题。
///
/// 使用方式：
/// ```swift
/// private let state = Mutex(MyState())
/// func read() -> Int { state.withLock { $0.value } }
/// func write(_ v: Int) { state.withLock { $0.value = v } }
/// ```
///
/// - 注意：锁不可重入；持有期间不要执行 I/O、网络或回调外部代码，否则可能死锁。
final class Mutex<Value>: @unchecked Sendable {
    // 堆分配的锁地址必须稳定，不能用值类型存储，否则复制后指向不同锁。
    private let _lock: os_unfair_lock_t
    // 受 _lock 保护；禁止在 withLock 之外读写。
    private var _value: Value

    init(_ value: Value) {
        _lock = .allocate(capacity: 1)
        _lock.initialize(to: os_unfair_lock())
        _value = value
    }

    deinit {
        // 先销毁锁对象再释放内存；调用方需保证 deinit 时已无并发访问。
        _lock.deinitialize(count: 1)
        _lock.deallocate()
    }

    /// 在独占锁保护下执行闭包，并返回闭包结果。
    /// - 若闭包抛错，`defer` 仍会解锁，避免锁泄漏。
    /// - body 内不得再次获取同一把锁（os_unfair_lock 不可重入，会死锁）。
    @discardableResult
    func withLock<T>(_ body: (inout Value) throws -> T) rethrows -> T {
        os_unfair_lock_lock(_lock)
        defer { os_unfair_lock_unlock(_lock) }
        return try body(&_value)
    }
}

// UnfairLock is defined in UnfairLock.swift
