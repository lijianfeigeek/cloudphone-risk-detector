// 动态特征列表：集中维护可疑库名、文件路径与端口三类特征，供 SDKIntegrityChecker、
// DyldImageMonitor、FridaSocketDetector 等检测器共享；内置默认值来自混淆常量，远端配置可追加。
// 所有读写经 UnfairLock 串行化，可被多个检测器并发调用；追加只增不减，resetDynamic 才回到默认集。

import Foundation

/// 动态特征列表的线程安全容器。
/// 初始化时使用硬编码默认值，RemoteConfig 可在运行期追加额外特征；所有变更线程安全。
/// 安全不变量：远端追加项只能扩大检测面，不能移除内置默认项，防止被下发配置“关灯”。
final class DynamicFeatureList: @unchecked Sendable {
    static let shared = DynamicFeatureList()

    /// 运行期追加的可变状态；默认集始终保留在静态属性中，不进入该结构。
    private struct State {
        var additionalLibraries: [String] = []
        var additionalPaths: [String] = []
        var additionalPorts: [Int] = []
    }
    private let stateLock = UnfairLock()
    private var state = State()

    // MARK: - 可疑库特征（供 SDKIntegrityChecker、DyldImageMonitor 使用）

    /// 内置可疑库名片段，已做大小写归一（调用方按小写子串匹配）。
    private static var defaultSuspiciousLibraries: [String] { ObfuscatedConstants.suspiciousLibraryTokensForDyld }

    /// 当前生效的可疑库特征 = 内置默认 + 远端追加；每次读取都加锁复制，避免调用方持有可变引用。
    var suspiciousLibraries: [String] {
        stateLock.withLock {
            Self.defaultSuspiciousLibraries + state.additionalLibraries
        }
    }

    // MARK: - 可疑文件路径（供 FridaSocketDetector 使用）

    /// 内置可疑路径：Frida 在 /tmp 与 /private/tmp 下的常见落点（含隐藏前缀变体）。
    private static var defaultSuspiciousPaths: [String] {
        let f = ObfuscatedConstants.keywordFrida
        return [
            "/tmp/\(f)-",
            "/tmp/.\(f)-",
            "/tmp/linjector",
            "/private/tmp/\(f)-",
            "/private/tmp/.\(f)-",
        ]
    }

    /// 当前生效的可疑路径 = 内置默认 + 远端追加。
    var suspiciousPaths: [String] {
        stateLock.withLock {
            Self.defaultSuspiciousPaths + state.additionalPaths
        }
    }

    // MARK: - 可疑端口（保留给后续基于 TCP 的检测）

    /// 主用内置端口表（Frida 等工具的默认监听端口）。
    private static var defaultSuspiciousPorts: [Int] { ObfuscatedConstants.suspiciousRuntimePorts }

    /// 内置离线兜底端口（非默认监听端口）；在远端 `additionalPorts` 之前合并并去重。
    private static var builtinFallbackSuspiciousPorts: [Int] { ObfuscatedConstants.suspiciousPortsBuiltinFallback }

    /// 按段合并端口并保持首次出现顺序；只接受 1...65535 的合法端口。
    private static func orderedUniquePorts(_ segments: [[Int]]) -> [Int] {
        var seen = Set<Int>()
        var out: [Int] = []
        for seg in segments {
            for p in seg {
                guard (1...65535).contains(p), !seen.contains(p) else { continue }
                seen.insert(p)
                out.append(p)
            }
        }
        return out
    }

    /// 当前生效的可疑端口 = 内置主表 + 内置兜底 + 远端追加，按优先级去重。
    var suspiciousPorts: [Int] {
        stateLock.withLock {
            Self.orderedUniquePorts([
                Self.defaultSuspiciousPorts,
                Self.builtinFallbackSuspiciousPorts,
                state.additionalPorts,
            ])
        }
    }

    // MARK: - 从 RemoteConfig 更新

    /// 追加来自已验签 RemoteConfig 的动态特征。
    /// 调用方必须先在服务端验签通过后再调用本方法；本方法不做签名校验。
    /// 库名统一转小写后去重存储，与检测侧的 `lowercased().contains` 匹配语义保持一致。
    func applyRemoteConfig(
        additionalSuspiciousLibraries: [String]?,
        additionalSuspiciousPaths: [String]?,
        additionalSuspiciousPorts: [Int]?
    ) {
        stateLock.withLock {
            if let libs = additionalSuspiciousLibraries {
                let lowered = Set(libs.map { $0.lowercased() })
                for token in lowered where !state.additionalLibraries.contains(token) {
                    state.additionalLibraries.append(token)
                }
            }
            if let paths = additionalSuspiciousPaths {
                let unique = Set(paths)
                for path in unique where !state.additionalPaths.contains(path) {
                    state.additionalPaths.append(path)
                }
            }
            if let ports = additionalSuspiciousPorts {
                let unique = Set(ports)
                for port in unique where !state.additionalPorts.contains(port) {
                    state.additionalPorts.append(port)
                }
            }
        }

        #if DEBUG
        // 仅在 DEBUG 打印增量数量，避免 Release 日志泄露特征规模。
        Logger.log("DynamicFeatureList.applyRemoteConfig: libs=+\(additionalSuspiciousLibraries?.count ?? 0) paths=+\(additionalSuspiciousPaths?.count ?? 0) ports=+\(additionalSuspiciousPorts?.count ?? 0)")
        #endif
    }

    /// 清空运行期追加项（保留硬编码默认集）。
    /// 用于远端配置撤销/回滚，确保不会残留上一次下发的特征。
    func resetDynamic() {
        stateLock.withLock {
            state.additionalLibraries.removeAll()
            state.additionalPaths.removeAll()
            state.additionalPorts.removeAll()
        }
    }

    /// 单例由 `shared` 暴露，禁止外部构造。
    private init() {}
}
