// 环境变量检测器：查找动态链接注入相关的环境变量，并与 environ 原始表交叉校验。
// 位于越狱检测管道中 `enableEnvDetect` 分支，主要针对 DYLD_INSERT_LIBRARIES 类注入。
// 关键安全不变量：getenv 与 environ 结果不一致时视为 Hook 证据，而不是“未命中”。
import Foundation

/// 检查注入相关环境变量是否被设置。
/// 检测什么：可疑变量存在（单项独立分值）、`getenv()` 与 environ 表读取结果不一致。
/// 命中后产生 `env:<NAME>`、`env_hook:getenv_mismatch:<NAME>` 信号，后者每条 +12 分。
/// 误报风险：开发/调试环境可能主动设置某些变量，因此总分封顶 100 且 mismatch 最多计 3 次。
struct EnvDetector: Detector {
    /// 可疑环境变量及其权重（名称与分值来自混淆常量表）。
    private var suspiciousVars: [(name: String, score: Double)] {
        ObfuscatedConstants.envSuspiciousVars
    }

    /// 执行环境变量检测。
    /// - Returns: 累计分数封顶 100 的检测结果。
    /// - Note: environ 不可读时仅跳过交叉校验，不影响 getenv 主路径判定。
    func detect() throws -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []
        let envMap = readEnvironMap()
        var mismatchCount = 0

        for item in suspiciousVars {
            let g = getenvString(item.name)
            let d = envMap?[item.name]

            if let value = (g ?? d), !value.isEmpty {
                score += item.score
                // DYLD_INSERT_LIBRARIES 的值包含具体 dylib 路径，需裁剪后再上报以防泄露完整路径。
                if item.name == "DYLD_INSERT_LIBRARIES" {
                    methods.append("env:\(item.name)=\(sanitizeEnvValue(value))")
                } else {
                    methods.append("env:\(item.name)")
                }
                Logger.log("jailbreak.env.hit: \(item.name) (+\(item.score))")
            }

            // 抗 Hook 交叉校验：getenv() 与 environ 表。
            // 若 getenv 返回 nil 但 environ 中实际存在该变量，说明 getenv 可能被 hook 隐藏。
            if g == nil, d != nil, mismatchCount < 3 {
                mismatchCount += 1
                score += 12
                methods.append("env_hook:getenv_mismatch:\(item.name)")
                Logger.log("jailbreak.env.hit: getenv_mismatch var=\(item.name) (+12)")
            }
        }

        return DetectorResult(score: min(score, 100), methods: methods)
    }

    /// 通过 libc `getenv` 读取变量。
    /// - Parameter name: 变量名。
    /// - Returns: 非空值；变量不存在或为空串时返回 `nil`。
    private func getenvString(_ name: String) -> String? {
        guard let p = getenv(name) else { return nil }
        let s = String(cString: p)
        return s.isEmpty ? nil : s
    }

    /// 裁剪环境变量值，避免把完整注入路径写进上报字段。
    /// - Parameter value: 原始值。
    /// - Returns: 长度不超过 64 时原样返回，否则截断为前 60 字符并追加省略号。
    private func sanitizeEnvValue(_ value: String) -> String {
        // 避免泄露完整路径；仅保留短前缀用于上报。
        if value.count <= 64 { return value }
        let prefix = value.prefix(60)
        return "\(prefix)…"
    }

    /// 直接遍历 `environ` 原始指针表，构建变量名到值的映射。
    /// - Returns: 变量映射；`environ` 不可用时返回 `nil`（调用方据此跳过交叉校验）。
    private func readEnvironMap() -> [String: String]? {
        guard let envpPtrPtr = _NSGetEnviron() else { return nil }
        guard let envp = envpPtrPtr.pointee else { return nil }

        var out: [String: String] = [:]
        var i = 0
        // environ 以 NULL 结尾；`let entryPtr` 绑定同时处理终止符。
        // 上限 1024 防止 environ 被破坏时无限迭代。
        while i < 1024, let entryPtr = envp.advanced(by: i).pointee {
            let entry = String(cString: entryPtr)
            // 按第一个 '=' 拆分，值中允许再出现 '='。
            if let idx = entry.firstIndex(of: "=") {
                let key = String(entry[..<idx])
                let val = String(entry[entry.index(after: idx)...])
                if !key.isEmpty, out[key] == nil {
                    out[key] = val
                }
            }
            i += 1
        }
        return out
    }
}

// 直接绑定 libc 的 `_NSGetEnviron`，绕过可能被 swizzle 的 Foundation 封装。
@_silgen_name("_NSGetEnviron")
private func _NSGetEnviron() -> UnsafeMutablePointer<UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?>?
