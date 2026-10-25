// 热路径锁封装：提供非递归、不可跨作用域持有的轻量互斥锁。
// 供配置缓存、状态查询等临界区极短的场景使用，语义与 NSLock 一致但更快。

import Foundation
import os

/// 轻量级自旋锁包装，用于替换热路径上的 NSLock。
///
/// `os_unfair_lock` 比 NSLock 快约 2-3 倍（无 Objective-C 消息派发开销），
/// 适用于临界区极短（<10μs）的高频访问场景，如配置读取和状态查询。
///
/// 注意事项：
/// - 不可递归持有（与 NSLock 行为一致）
/// - 持锁期间不可执行可能阻塞的操作（如 I/O、网络）
/// - 适用于读多写少的快速状态访问
final class UnfairLock: @unchecked Sendable {
    // 堆分配的锁地址必须保持稳定；os_unfair_lock 本身是值类型，复制会得到不同的锁。
    private let _lock: os_unfair_lock_t

    init() {
        _lock = .allocate(capacity: 1)
        _lock.initialize(to: os_unfair_lock())
    }

    deinit {
        // 解锁对象必须先 deinitialize 再释放内存；调用方需保证销毁时无人在等待。
        _lock.deinitialize(count: 1)
        _lock.deallocate()
    }

    /// 获取锁；若锁已被同线程持有则直接死锁（不可重入）。
    @inline(__always)
    func lock() {
        os_unfair_lock_lock(_lock)
    }

    /// 释放锁；只能由当前持锁线程调用。
    @inline(__always)
    func unlock() {
        os_unfair_lock_unlock(_lock)
    }

    /// 在锁保护下执行闭包并返回结果
    ///
    /// - 使用 `defer` 保证闭包抛错时也会解锁。
    /// - 闭包内若再次调用同一实例的 `withLock` 会自死锁。
    @inline(__always)
    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}
