// 文件职责：解析并保存 TLS SPKI pin 材料，提供常量时间的层级匹配。
// 管道位置：Network 证书固定链路的配置层，被 CertificatePinningSessionDelegate 消费。
// 安全不变量：比较使用常量时间；C 侧返回错误必须与“不匹配”区分（失败即拒绝）；
// 对象销毁时尽力清零摘要字节，减少内存中的密钥材料残留。
import CRiskCore
import Darwin
import Foundation

/// pin 可匹配证书链中的哪个位置。
public enum CertificatePinScope: UInt8, Sendable {
    /// 任意位置（兼容旧 `sha256/...` 与显式 `any/`）。
    case any = 0
    /// 仅叶证书（链下标 0）。
    case leaf = 1
    /// 任意非叶证书（链下标 ≥ 1）。
    case intermediate = 2
}

/// pinset 校验三态结果。C 侧 `cprisk_pinset_*` 返回 `-1`（错误）/ `0`（不匹配）/ `1`（匹配）；
/// Swift 侧必须区分 `-1` 与 `0`：错误时无条件取消握手，绝不回落系统 CA；
/// 仅 `0`（明确不匹配）时才按 `allowsSystemCA` 决定是否回落。
public enum PinMatchOutcome: Sendable {
    /// 明确匹配。
    case match
    /// 明确不匹配（输入有效，校验完成）。
    case noMatch
    /// 校验错误（非法输入 / 内部错误）：无法得出结论，必须按失败处理。
    case error
}

/// 运行时 TLS SPKI pin 材料：不在 delegate / 全局配置中长期保留 `sha256/...` 字符串，
/// 降低被 `strings`/堆扫描直接提取 pin 字面量的风险。
///
/// 限制：Swift/ARC 无法保证所有副本立即擦除；比较时仍会临时生成候选 `Data`。
/// 真正安全的内存需要专用分配器支持，可移植 Swift 无法提供。
public final class PinnedCertificatePinMaterial: @unchecked Sendable {

    /// 原始 SPKI SHA-256 摘要（每条 32 字节），顺序与输入一致。
    private var slots: [ContiguousArray<UInt8>]
    /// 与 `slots` 等长的 scope 字节（`CertificatePinScope.rawValue`）。
    private var scopeBytes: [UInt8]
    /// 展平后的摘要缓冲，供 CRiskCore 做常量时间校验。
    private var packedDigests: ContiguousArray<UInt8>
    /// 每个 pin 一个 scope 字节，与 `packedDigests` 并行。
    private var packedScopes: ContiguousArray<UInt8>
    /// SPKI SHA-256 摘要固定长度（字节）。
    private static let digestLength = 32

    /// 空材料：所有查询均不命中（调用方应按 fail-closed 处理）。
    public static let empty = PinnedCertificatePinMaterial(slots: [], scopeBytes: [])

    private init(slots: [ContiguousArray<UInt8>], scopeBytes: [UInt8]) {
        // 两个数组必须一一对应，否则 scope 与摘要会错位。
        precondition(slots.count == scopeBytes.count)
        self.slots = slots
        self.scopeBytes = scopeBytes
        self.packedDigests = Self.pack(slots)
        self.packedScopes = ContiguousArray(scopeBytes)
    }

    /// 从 pin 字符串解析材料；非法条目会被丢弃（效果等同永不匹配的字符串）。
    /// 支持前缀：
    /// - `sha256/<base64>` 或 `any/sha256/<base64>`：匹配任意位置（兼容旧格式）。
    /// - `leaf/sha256/<base64>`：仅叶证书。
    /// - `intermediate/sha256/<base64>`：仅中间证书（下标 ≥ 1）。
    public convenience init(pinStrings: Set<String>) {
        let parsed = Self.parsePinEntries(from: pinStrings)
        self.init(slots: parsed.slots, scopeBytes: parsed.scopes)
    }

    /// 是否没有任何有效 pin。
    public var isEmpty: Bool { slots.isEmpty }

    /// 有效 pin 数量。
    public var digestCount: Int { slots.count }

    /// 判断 base64 摘要（不含 `sha256/` 前缀）是否命中任一 pin（忽略 scope）。
    public func containsSPKISHA256Base64(_ spkiSHA256Base64: String) -> Bool {
        guard let candidate = Self.decodeBase64Digest(spkiSHA256Base64) else { return false }
        return containsRawDigest(candidate)
    }

    /// 判断 32 字节原始摘要是否命中任一 pin（忽略 scope）。
    public func containsRawDigest(_ digest: Data) -> Bool {
        guard digest.count == Self.digestLength else { return false }
        return digest.withUnsafeBytes { candBuf -> Bool in
            guard let candBase = candBuf.bindMemory(to: UInt8.self).baseAddress else { return false }
            // 常量时间：遍历全部槽位并累积结果，不提前返回。
            var acc: UInt8 = 0
            for slot in slots {
                let m: UInt8 = Self.constantTimeEqual(slot, candBase) ? 1 : 0
                acc |= m
            }
            return acc != 0
        }
    }

    /// 层级策略匹配：摘要必须命中某条 pin，且该 pin 的 scope 允许当前 `chainIndex`（0 = 叶证书）。
    public func matchesLayeredDigest(_ digest: Data, chainIndex: Int) -> Bool {
        guard digest.count == Self.digestLength, !slots.isEmpty else { return false }
        guard chainIndex >= 0 else { return false }
        let idx = UInt32(chainIndex)
        return digest.withUnsafeBytes { candBuf -> Bool in
            guard let candBase = candBuf.bindMemory(to: UInt8.self).baseAddress else { return false }
            var acc: UInt8 = 0
            for i in slots.indices {
                // 摘要相等与位置允许同时计算，避免分支泄露命中位置。
                let eq: UInt8 = Self.constantTimeEqual(slots[i], candBase) ? 1 : 0
                let posOk: UInt8 = Self.positionAllowed(scopeByte: scopeBytes[i], chainIndex: idx)
                acc |= (eq & posOk)
            }
            return acc != 0
        }
    }

    /// CRiskCore 侧的层级校验路径（三态：match / noMatch / error）。
    /// - 输入非法或 C 侧内部错误返回 `.error`，调用方必须按失败处理，不得回落系统 CA。
    /// - Parameters:
    ///   - digest: 32 字节候选 SPKI 摘要。
    ///   - chainIndex: 证书链下标（0 = 叶证书）。
    /// - Returns: 三态匹配结果。
    func matchesLayeredDigestViaCoreOutcome(_ digest: Data, chainIndex: Int) -> PinMatchOutcome {
        guard digest.count == Self.digestLength, !slots.isEmpty else { return .error }
        guard chainIndex >= 0 else { return .error }
        return digest.withUnsafeBytes { candBuf -> PinMatchOutcome in
            guard let candBase = candBuf.bindMemory(to: UInt8.self).baseAddress else { return .error }
            return packedDigests.withUnsafeBufferPointer { pinBuf in
                guard let pinBase = pinBuf.baseAddress else { return .error }
                return packedScopes.withUnsafeBufferPointer { scBuf in
                    guard let scBase = scBuf.baseAddress else { return .error }
                    let rc = cprisk_pinset_match_layered_sha256_digest(
                        candBase,
                        digest.count,
                        pinBase,
                        slots.count,
                        scBase,
                        UInt32(chainIndex)
                    )
                    switch rc {
                    case 1: return .match
                    case 0: return .noMatch
                    default: return .error
                    }
                }
            }
        }
    }

    /// 旧 Bool 包装：仅明确匹配为 true；错误按不匹配处理（调用方须用
    /// `matchesLayeredDigestViaCoreOutcome` 区分错误与不匹配）。
    func matchesLayeredDigestViaCore(_ digest: Data, chainIndex: Int) -> Bool {
        matchesLayeredDigestViaCoreOutcome(digest, chainIndex: chainIndex) == .match
    }

    /// CRiskCore 侧的非层级校验路径（打包摘要缓冲，忽略 scope），返回三态结果。
    func containsRawDigestViaCoreOutcome(_ digest: Data) -> PinMatchOutcome {
        guard digest.count == Self.digestLength, !slots.isEmpty else { return .error }
        return digest.withUnsafeBytes { candBuf -> PinMatchOutcome in
            guard let candBase = candBuf.bindMemory(to: UInt8.self).baseAddress else { return .error }
            return packedDigests.withUnsafeBufferPointer { pinBuf in
                guard let pinBase = pinBuf.baseAddress else { return .error }
                let rc = cprisk_pinset_contains_sha256_digest(
                    candBase,
                    digest.count,
                    pinBase,
                    slots.count
                )
                switch rc {
                case 1: return .match
                case 0: return .noMatch
                default: return .error
                }
            }
        }
    }

    /// 旧 Bool 包装：仅明确匹配为 true。
    func containsRawDigestViaCore(_ digest: Data) -> Bool {
        containsRawDigestViaCoreOutcome(digest) == .match
    }

    /// 判断某 scope 是否允许该链下标命中；未知 scope 一律拒绝（fail-closed）。
    /// - Returns: 允许为 1，不允许为 0（供常量时间位运算使用）。
    private static func positionAllowed(scopeByte: UInt8, chainIndex: UInt32) -> UInt8 {
        switch scopeByte {
        case CertificatePinScope.any.rawValue:
            return 1
        case CertificatePinScope.leaf.rawValue:
            return chainIndex == 0 ? 1 : 0
        case CertificatePinScope.intermediate.rawValue:
            return chainIndex >= 1 ? 1 : 0
        default:
            return 0
        }
    }

    /// 解析结果：与输入顺序一致的摘要槽位及其 scope。
    private struct ParsedPins {
        var slots: [ContiguousArray<UInt8>]
        var scopes: [UInt8]
    }

    /// 遍历 pin 字符串并解析；无法解析的条目静默跳过。
    private static func parsePinEntries(from pinStrings: Set<String>) -> ParsedPins {
        var out = ParsedPins(slots: [], scopes: [])
        out.slots.reserveCapacity(pinStrings.count)
        out.scopes.reserveCapacity(pinStrings.count)
        for raw in pinStrings {
            guard let entry = pinEntryFromPinString(raw) else { continue }
            out.slots.append(entry.digest)
            out.scopes.append(entry.scope.rawValue)
        }
        return out
    }

    /// 将多条摘要展平为连续缓冲，便于一次传给 C 侧。
    private static func pack(_ slots: [ContiguousArray<UInt8>]) -> ContiguousArray<UInt8> {
        var packed = ContiguousArray<UInt8>()
        packed.reserveCapacity(slots.count * digestLength)
        for slot in slots {
            packed.append(contentsOf: slot)
        }
        return packed
    }

    /// 单条 pin 的解析结果。
    fileprivate struct PinEntry {
        let digest: ContiguousArray<UInt8>
        let scope: CertificatePinScope
    }

    /// 解析可选的 `leaf/` / `intermediate/` / `any/` 前缀，再解析 `sha256/<base64>`（大小写不敏感）。
    fileprivate static func pinEntryFromPinString(_ raw: String) -> PinEntry? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let lower = trimmed.lowercased()
        let scope: CertificatePinScope
        let rest: String
        if lower.hasPrefix("intermediate/") {
            scope = .intermediate
            rest = String(trimmed.dropFirst("intermediate/".count))
        } else if lower.hasPrefix("leaf/") {
            scope = .leaf
            rest = String(trimmed.dropFirst("leaf/".count))
        } else if lower.hasPrefix("any/") {
            scope = .any
            rest = String(trimmed.dropFirst("any/".count))
        } else {
            scope = .any
            rest = trimmed
        }
        let cleaned = rest.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = digestFromSha256Payload(cleaned), data.count == digestLength else {
            return nil
        }
        return PinEntry(digest: ContiguousArray(data), scope: scope)
    }

    /// 兼容旧行为：只取摘要，忽略 scope 信息。
    static func digestFromPinString(_ raw: String) -> ContiguousArray<UInt8>? {
        pinEntryFromPinString(raw)?.digest
    }

    /// 去掉可选的 `sha256/` 前缀并做 base64 解码。
    private static func digestFromSha256Payload(_ trimmed: String) -> Data? {
        let lower = trimmed.lowercased()
        let payload: String
        if lower.hasPrefix("sha256/") {
            payload = String(trimmed.dropFirst("sha256/".count))
        } else {
            payload = trimmed
        }
        let cleaned = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        return decodeBase64Digest(cleaned)
    }

    /// 生成规范的 `sha256/<base64>` 字符串（带 scope 前缀），排序以保证集合比较稳定。
    static func canonicalPinStrings(from pinStrings: Set<String>) -> Set<String> {
        var canonical: [String] = []
        for raw in pinStrings {
            guard let entry = pinEntryFromPinString(raw) else { continue }
            let b64 = Data(entry.digest).base64EncodedString()
            let body = "sha256/\(b64)"
            switch entry.scope {
            case .any:
                canonical.append(body)
            case .leaf:
                canonical.append("leaf/\(body)")
            case .intermediate:
                canonical.append("intermediate/\(body)")
            }
        }
        canonical.sort()
        return Set(canonical)
    }

    /// base64 解码；忽略未知字符以兼容空白与换行。
    private static func decodeBase64Digest(_ s: String) -> Data? {
        Data(base64Encoded: s, options: [.ignoreUnknownCharacters])
    }

    /// 常量时间比较两条摘要：耗时与首个不同字节的位置无关，避免时序侧信道。
    private static func constantTimeEqual(_ a: ContiguousArray<UInt8>, _ b: UnsafePointer<UInt8>) -> Bool {
        guard a.count == digestLength else { return false }
        var diff: UInt8 = 0
        for i in 0..<digestLength {
            diff |= a[i] ^ b[i]
        }
        return diff == 0
    }

    /// 销毁时尽力清零所有摘要缓冲。
    /// Swift 无法保证 ARC 副本与临时对象同样被擦除，这里只是纵深防御。
    deinit {
        // 逐槽位 memset，缩短密钥材料在堆上的存活时间。
        for idx in slots.indices {
            slots[idx].withUnsafeMutableBufferPointer { buf in
                if let base = buf.baseAddress {
                    memset(base, 0, buf.count)
                }
            }
        }
        packedDigests.withUnsafeMutableBufferPointer { buf in
            if let base = buf.baseAddress {
                memset(base, 0, buf.count)
            }
        }
        packedScopes.withUnsafeMutableBufferPointer { buf in
            if let base = buf.baseAddress {
                memset(base, 0, buf.count)
            }
        }
        slots.removeAll(keepingCapacity: false)
        packedDigests.removeAll(keepingCapacity: false)
        packedScopes.removeAll(keepingCapacity: false)
        scopeBytes.removeAll(keepingCapacity: false)
    }
}
