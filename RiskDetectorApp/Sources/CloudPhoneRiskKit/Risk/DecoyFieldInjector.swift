// 上报链路·诱饵字段注入与运行期字段映射：向 payload 填充随机短键值、生成字段重命名表。
// 目的仅是增加流量逆向与字段语义分析成本，不提供机密性；机密性由 ReportEnvelope 的签名与加密承担。
// 诱饵字段会随 payload 离开设备，服务端必须忽略未知键；两类机制都不改变真实信号的语义。

import Foundation

/// 向风险 payload 注入随机诱饵字段，稀释真实字段的语义信息。
public enum DecoyFieldInjector {
    /// 字段分组标记；A=硬件、B=行为、C=诱饵，便于服务端按组统计与观测。
    enum FieldGroup: String {
        case hardware = "A"
        case behavior = "B"
        case decoy = "C"
    }

    // 诱饵数量限制在 10–15：过少容易被区分，过多会显著增大上报体积并影响压缩率。
    private static let decoyCountRange = 10...15
    // 短键字符集（小写字母 + 数字），4 字符可提供约 36^4 的键空间，足以避免与真实字段碰撞。
    private static let shortCodeChars = "abcdefghijklmnopqrstuvwxyz0123456789"

    /// 就地注入诱饵字段。相同 `seed` 会生成相同的诱饵集合，便于联调复现。
    /// - Parameters:
    ///   - payload: 待上报的字段字典（会被原地修改）。
    ///   - seed: 确定性随机种子，通常来自会话/报告维度。
    public static func inject(into payload: inout [String: Any], seed: UInt64) {
        let decoys = generateDecoyFields(count: decoyCountForPayload(payload), seed: seed, existingKeys: Set(payload.keys))
        for (k, v) in decoys {
            payload[k] = v
        }
    }

    /// 根据真实字段数量决定诱饵数量，并用取模把结果限制在 10–15 区间。
    private static func decoyCountForPayload(_ payload: [String: Any]) -> Int {
        let realCount = payload.count
        let target = decoyCountRange.lowerBound + (realCount % (decoyCountRange.upperBound - decoyCountRange.lowerBound + 1))
        return min(max(target, decoyCountRange.lowerBound), decoyCountRange.upperBound)
    }

    /// 生成不与现有键冲突的诱饵键值对。
    /// - 值类型在整数/布尔/浮点/十六进制串之间轮换，模拟真实遥测字段的分布。
    /// - `maxAttempts = count * 3` 是冲突重试上限，避免极端种子下无限循环。
    private static func generateDecoyFields(count: Int, seed: UInt64, existingKeys: Set<String>) -> [String: Any] {
        var rng = SeededRNG(seed: seed)
        var result: [String: Any] = [:]
        var attempts = 0
        let maxAttempts = count * 3
        while result.count < count, attempts < maxAttempts {
            attempts += 1
            let name = randomShortCode(length: 4, rng: &rng)
            guard !existingKeys.contains(name), result[name] == nil else { continue }
            let value: Any
            switch rng.next() % 4 {
            case 0: value = rng.next() % 101
            case 1: value = rng.next() % 2 == 0
            case 2: value = Double(rng.next() % 10001) / 10000.0
            default: value = String(format: "%08X-%04X", rng.next() & 0xFFFFFFFF, rng.next() & 0xFFFF)
            }
            result[name] = value
        }
        return result
    }

    /// 生成指定长度的随机短键；仅用于字段名/诱饵键，不用于任何密钥材料。
    private static func randomShortCode(length: Int, rng: inout SeededRNG) -> String {
        let chars = Array(shortCodeChars)
        return (0..<length).map { _ in String(chars[Int(rng.next() % UInt64(chars.count))]) }.joined()
    }
}

/// 运行期字段映射：按 seed + 版本生成“语义字段 → 短键”的重命名表。
/// 映射有效期为空表示当前会话内长期有效；服务端需持有同一张映射表才能还原字段。
public struct RuntimeFieldMapping {
    // 参与重命名的语义字段清单；新增上报字段时必须同步加入，否则会以可读键名上线。
    private static let semanticFields: [String] = [
        "\(ObfuscatedConstants.keywordJailbreak)_score", "vm_detected", "imu_variance",
        "battery_charge_counter", "drm_level", "mount_anomaly",
        "rwx_detected", ObfuscatedConstants.signalHookDetected, "timing_anomaly",
        "touch_entropy", "sensor_entropy", ObfuscatedConstants.requiredSignalVpnActive,
        "proxy_enabled", "device_model", "gpu_name",
        "kernel_version", "board_id", "score", "isHighRisk"
    ]

    private static let shortCodeChars = "abcdefghijklmnopqrstuvwxyz0123456789"

    /// 生成一张确定性映射表：相同 seed/version 得到相同短键，便于服务端复算还原。
    /// - 使用 `version.hashValue` 参与 seed，保证不同映射版本不会复用同一组短键。
    /// - 每个字段最多重试 50 次以规避短键碰撞；极端情况下仍碰撞会写入重复目标，
    ///   最终由 `PayloadFieldMapping.validate()` 在混淆阶段拒绝（fail-closed）。
    public static func generate(seed: UInt64, version: String) -> PayloadFieldMapping {
        var rng = SeededRNG(seed: seed &+ UInt64(bitPattern: Int64(version.hashValue)))
        var mappings: [String: String] = [:]
        var usedCodes: Set<String> = []
        for field in semanticFields {
            var obfuscated: String
            var attempts = 0
            repeat {
                obfuscated = randomShortCode(length: 4, rng: &rng)
                attempts += 1
            } while usedCodes.contains(obfuscated) && attempts < 50
            usedCodes.insert(obfuscated)
            mappings[field] = obfuscated
        }
        return PayloadFieldMapping(version: version, mappings: mappings, expiresAtMillis: nil)
    }

    private static func randomShortCode(length: Int, rng: inout SeededRNG) -> String {
        let chars = Array(shortCodeChars)
        return (0..<length).map { _ in String(chars[Int(rng.next() % UInt64(chars.count))]) }.joined()
    }
}

/// 确定性伪随机数生成器（LCG），仅用于生成诱饵/短键，不具备密码学安全性。
/// 固定算法常量保证跨设备、跨启动可复现；seed 为 0 时改写为 1，避免零状态退化。
private struct SeededRNG {
    private var state: UInt64

    init(seed: UInt64) {
        self.state = seed == 0 ? 1 : seed
    }

    /// 线性同余步进（Knuth MMIX 参数），返回新状态。
    mutating func next() -> UInt64 {
        state = state &* 6364136223846793005 &+ 1442695040888963407
        return state
    }
}
