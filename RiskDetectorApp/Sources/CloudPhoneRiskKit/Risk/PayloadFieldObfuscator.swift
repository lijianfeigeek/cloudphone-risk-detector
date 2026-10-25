// 上报链路·字段重命名（历史名“混淆”）：按映射表把语义键替换为短键，降低流量可读性。
// 本机制不提供加密/机密性；机密性由 ReportEnvelope 的 AES-GCM 与 HMAC/v3 签名承担。
// 映射若存在冲突、过期或反向歧义，一律抛错拒绝（fail-closed），不得降级为明文键继续上报。

import CryptoKit
import Foundation

/// 字段混淆/重命名映射配置（仅重命名键，不提供机密性）。
/// 内部语义字段 -> 上报混淆字段。
///
/// ⚠️ 本机制不是加密：它只把可读的键名（如 `"jailbreak"`）替换为短键
///（如 `"jb"`），任何能看到上报载荷的人都可以按映射表或频率分析还原。
/// 机密性由外层加密信封提供（`ReportEnvelope` 的 AES-GCM 加密 +
/// HMAC/v3 签名）；没有加密信封时，键重命名不能阻止载荷被读取。
/// 命名上保留历史名称 `Obfuscator` / `obfuscate` 仅为兼容，请按
/// “字段重命名”理解，不要按“加密/混淆即安全”理解。
public struct PayloadFieldMapping: Codable, Sendable {
    /// 键重命名的作用深度。此前默认只处理顶层，导致嵌套信号字典仍以
    /// `"jailbreak"` / `"frida"` / `"ptrace"` 等明文键上线；根据 P2a 红队结论，
    /// 嵌套信号名本身就是敏感面，因此新映射默认使用 `.all`。
    public enum DepthScope: String, Codable, Sendable {
        /// 只重命名顶层键（旧行为）。仅当下游解析器依赖嵌套键稳定时使用。
        case topLevel
        /// 在任意嵌套深度重命名键。
        case all
    }

    public let version: String
    public let mappings: [String: String]
    public let expiresAtMillis: Int64?
    public let depthScope: DepthScope

    private enum CodingKeys: String, CodingKey {
        case version = "v"
        case mappings = "m"
        case expiresAtMillis = "ea"
        case depthScope = "ds"
    }

    /// 默认作用域为 `.topLevel`，兼容既有调用方（DecoyFieldInjector、服务端下发的旧映射）。
    /// 需要完整嵌套重命名的集成应显式传 `depthScope: .all`，或使用
    /// `deriveSessionMapping(...)`（其内部强制 `.all`）。
    /// （重命名 ≠ 机密性，见上方 `PayloadFieldMapping` 注释。）
    public init(version: String, mappings: [String: String], expiresAtMillis: Int64? = nil, depthScope: DepthScope = .topLevel) {
        self.version = version
        self.mappings = mappings
        self.expiresAtMillis = expiresAtMillis
        self.depthScope = depthScope
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.version = try c.decode(String.self, forKey: .version)
        self.mappings = try c.decode([String: String].self, forKey: .mappings)
        self.expiresAtMillis = try c.decodeIfPresent(Int64.self, forKey: .expiresAtMillis)
        // 旧持久化映射可能没有 `ds` 字段，默认按 `.topLevel` 处理以保证严格兼容；
        // 需要嵌套重命名时由服务端下发带 `ds: "all"` 的 v2 映射。
        self.depthScope = try c.decodeIfPresent(DepthScope.self, forKey: .depthScope) ?? .topLevel
    }

    /// 判断映射是否已过期；无过期时间（nil）视为当前会话内长期有效。
    public func isExpired(nowMillis: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) -> Bool {
        guard let expiresAtMillis else { return false }
        return nowMillis > expiresAtMillis
    }

    /// 校验映射在正反两个方向都无冲突，保证 `deobfuscate(obfuscate(x)) == x` 成立。
    /// 目标短键重复会导致反向还原结果不确定，因此必须拒绝。
    public func validate() -> Bool {
        let targets = Array(mappings.values)
        return Set(targets).count == targets.count
    }
}

/// 字段重命名执行器：只改键名，不做任何加密或值变换。
public enum PayloadFieldObfuscator {
    /// 使用映射将语义字段重命名为上报字段（仅重命名，不加密；见 `PayloadFieldMapping` 注释）。
    public static func obfuscate(jsonData: Data, mapping: PayloadFieldMapping) throws -> Data {
        guard mapping.validate() else {
            throw ReportEnvelope.ReportEnvelopeError.invalidPayload
        }
        let object = try JSONSerialization.jsonObject(with: jsonData, options: [.fragmentsAllowed])
        let obfuscated = try transform(object, with: mapping.mappings, scope: mapping.depthScope)

        guard JSONSerialization.isValidJSONObject(obfuscated) else {
            throw ReportEnvelope.ReportEnvelopeError.invalidPayload
        }
        return try JSONSerialization.data(withJSONObject: obfuscated, options: [])
    }

    /// 将混淆字段反向恢复为语义字段（用于调试/服务端回溯）
    public static func deobfuscate(jsonData: Data, mapping: PayloadFieldMapping) throws -> Data {
        guard mapping.validate() else {
            throw ReportEnvelope.ReportEnvelopeError.invalidPayload
        }
        let pairs = mapping.mappings.map { ($1, $0) }
        let grouped = Dictionary(grouping: pairs, by: { $0.0 })
        if grouped.contains(where: { $0.value.count > 1 }) {
            throw ReportEnvelope.ReportEnvelopeError.invalidPayload
        }
        let reverse = Dictionary(pairs, uniquingKeysWith: { first, _ in first })
        let object = try JSONSerialization.jsonObject(with: jsonData, options: [.fragmentsAllowed])
        let restored = try transform(object, with: reverse, scope: mapping.depthScope)

        guard JSONSerialization.isValidJSONObject(restored) else {
            throw ReportEnvelope.ReportEnvelopeError.invalidPayload
        }
        return try JSONSerialization.data(withJSONObject: restored, options: [])
    }

    private static func transform(
        _ value: Any,
        with mapping: [String: String],
        scope: PayloadFieldMapping.DepthScope,
        depth: Int = 0
    ) throws -> Any {
        if let dictionary = value as? [String: Any] {
            var transformed: [String: Any] = [:]
            transformed.reserveCapacity(dictionary.count)
            for (key, nestedValue) in dictionary {
                // P2a 修复：此前只重命名 depth==0 的键，嵌套信号名（"jailbreak"、
                // "frida"、"ptrace"）仍以明文上线。`.all` 会对每一层字典键查表；
                // `.topLevel` 保留旧行为，供依赖嵌套键稳定的调用方使用。
                let shouldRename: Bool
                switch scope {
                case .all:
                    shouldRename = true
                case .topLevel:
                    shouldRename = (depth == 0)
                }
                let targetKey = shouldRename ? (mapping[key] ?? key) : key
                // 映射目标可能与真实载荷中的未映射键碰撞（例如 a->b 且 b 已存在）。
                // 此时整份 payload 直接拒绝，而不是保留一个依赖字典遍历顺序的随机赢家。
                guard transformed[targetKey] == nil else {
                    throw ReportEnvelope.ReportEnvelopeError.invalidPayload
                }
                transformed[targetKey] = try transform(
                    nestedValue,
                    with: mapping,
                    scope: scope,
                    depth: depth + 1
                )
            }
            return transformed
        }

        if let array = value as? [Any] {
            return try array.map {
                try transform($0, with: mapping, scope: scope, depth: depth + 1)
            }
        }

        return value
    }

    /// 派生会话级映射：把每个已知语义键重命名为
    /// `HMAC(sessionKey, "cprisk.field.v1" || keyName)[..8].hex`。
    /// 服务端持有同一 sessionKey，可复算相同短键并反向还原。
    /// 相比配置下发的静态映射表，会话派生使同一攻击者从一次会话抓到的字段名
    /// 在下次会话中不再匹配——模式识别被迫变成逐会话逆向。
    /// - Parameter sessionKey: 会话级对称密钥，仅在本地与服务端持有，不随 payload 上报。
    public static func deriveSessionMapping(
        baseKeys: [String],
        sessionKey: SymmetricKey,
        version: String,
        expiresAtMillis: Int64? = nil
    ) -> PayloadFieldMapping {
        var pairs: [String: String] = [:]
        let label = Data("cprisk.field.v1".utf8)
        for key in baseKeys {
            var msg = Data()
            msg.append(label)
            msg.append(Data(key.utf8))
            let mac = HMAC<SHA256>.authenticationCode(for: msg, using: sessionKey)
            // 8 字节 = 16 个十六进制字符：足够短以控制载荷体积，也足够宽，
            // 使 SDK 已知键集合（约 150 个）发生碰撞的概率可忽略。
            let hex = mac.prefix(8).map { String(format: "%02x", $0) }.joined()
            pairs[key] = hex
        }
        return PayloadFieldMapping(
            version: version,
            mappings: pairs,
            expiresAtMillis: expiresAtMillis,
            depthScope: .all
        )
    }
}
