// 上报链路·gRPC/HTTP JSON 载荷：把安全信封映射为 UploadRiskReportRequest 结构，并在编码前校验绑定摘要。
// 出设备字段：payload_json（base64）、signature、nonce/ts/reportId、attestation 证明与绑定诊断；
// 签名密钥、DeviceKey、HKDF 材料等只保留在本地，不进入该结构。
// 校验失败即拒绝序列化（fail-closed），避免把不一致的绑定摘要发给服务端。

import CRiskCore
import CryptoKit
import Foundation

// MARK: - gRPC/JSON 上报封装 (SDK 4.4)

/// 与 `risk_report.proto` UploadRiskReportRequest 对应的 Swift 结构体。
/// 用于手动 JSON 编码，不依赖 grpc-swift。
///
/// ## payload_json 与 payload_sha256
/// - `payload_json` 使用 bytes：JSON 传输时以 base64 编码；避免 UTF-8/转义/空白差异影响签名。
/// - `payload_sha256` 为 `SHA256(nonce|ts|reportId|payload)` 的上下文绑定摘要，防止跨请求嫁接。
///
/// ## 服务端验签顺序（必须严格按序执行）
/// 1. 校验 `ts` 是否在允许时间窗内
/// 2. 校验 `nonce` 是否首次出现（防重放）
/// 3. 校验 `session_token` 是否有效
/// 4. 校验 payload_json 是合法 JSON；保留原始签名字节，不重新编码
/// 5. 校验 `signature`
/// 6. 校验顶层 `device_id` / `scene` 与 payload 内部字段是否一致
/// 7. 最后才进入风险数据入库、聚合和策略处理
///
/// 签名语义：`sigVer|nonce|ts|sessionToken|reportId|keyId|fieldMappingVersion|attestationKeyId|canonicalPayloadJSON`
public struct GrpcReportPayload: Sendable {
    // 以下三个字段构成 App Attest 证明对：keyId + assertion；v3 中它们被纳入签名域。
    public let attestationKeyId: String?
    public let attestationAssertion: Data?
    public let trustLevel: TrustLevel?
    // 服务端下发的新鲜度挑战的二次证明（可选）。
    public let reAttestationAssertion: Data?
    // 材料绑定模式与签名输入摘要，仅用于观测，不含密钥材料。
    public let bindingMode: String?
    public let bindingDigest: String?
    public let requireHardwareAttestation: Bool
    public let appId: String
    public let sdkVersion: String
    public let reportId: String
    public let ts: Int64
    public let nonce: String
    public let sessionToken: String
    public let sigVer: String
    public let keyId: String
    public let fieldMappingVersion: String?
    public let deviceId: String
    public let scene: String
    // 规范化后的报告正文；JSON 中以 base64 传输，签名覆盖其原始字节。
    public let payloadJson: Data
    public let signature: String
    // 上下文绑定摘要：SHA-256(nonce|ts|reportId|payload)，防止跨请求嫁接。
    public let payloadSha256: Data
    /// 输出链路完整性信号：用于观测 JSONSerialization/SHA256 关键 API 路径的一致性。
    /// 仅作为上报证据，不参与信封签名语义。
    public let outputPathIntegrity: [String: String]?

    /// 按 proto 字段顺序组装载荷；所有 optional 字段缺省为 nil。
    public init(
        appId: String,
        sdkVersion: String,
        reportId: String,
        ts: Int64,
        nonce: String,
        sessionToken: String,
        sigVer: String,
        keyId: String,
        fieldMappingVersion: String?,
        deviceId: String,
        scene: String,
        payloadJson: Data,
        signature: String,
        payloadSha256: Data,
        outputPathIntegrity: [String: String]? = nil,
        attestationKeyId: String? = nil,
        attestationAssertion: Data? = nil,
        trustLevel: TrustLevel? = nil,
        reAttestationAssertion: Data? = nil,
        bindingMode: String? = nil,
        bindingDigest: String? = nil,
        requireHardwareAttestation: Bool = false
    ) {
        self.attestationKeyId = attestationKeyId
        self.attestationAssertion = attestationAssertion
        self.trustLevel = trustLevel
        self.reAttestationAssertion = reAttestationAssertion
        self.bindingMode = bindingMode
        self.bindingDigest = bindingDigest
        self.requireHardwareAttestation = requireHardwareAttestation
        self.appId = appId
        self.sdkVersion = sdkVersion
        self.reportId = reportId
        self.ts = ts
        self.nonce = nonce
        self.sessionToken = sessionToken
        self.sigVer = sigVer
        self.keyId = keyId
        self.fieldMappingVersion = fieldMappingVersion
        self.deviceId = deviceId
        self.scene = scene
        self.payloadJson = payloadJson
        self.signature = signature
        self.payloadSha256 = payloadSha256
        self.outputPathIntegrity = outputPathIntegrity
    }

    /// 转为HTTP JSON v1 字典（snake_case；并非 ProtoJSON），用于 HTTP/2 或 gRPC 客户端发送。
    /// `payload_json` 与 `payload_sha256` 以 base64 字符串形式输出。
    public func toJSONDictionary() -> [String: Any] {
        generatedWireDictionary()
    }

    /// 编码前校验并返回 wire 字典：要求硬件证明时检查证明对完整，并重算绑定摘要。
    /// - Throws: 证明缺失或摘要不一致时拒绝（fail-closed），不继续序列化/上报。
    internal func validatedJSONDictionary() throws -> [String: Any] {
        if requireHardwareAttestation && (attestationKeyId?.isEmpty != false || attestationAssertion?.isEmpty != false) {
            throw ReportEnvelope.ReportEnvelopeError.attestationIncomplete
        }
        let recomputed = Self.computePayloadSha256(
            nonce: nonce,
            ts: ts,
            reportId: reportId,
            payload: payloadJson
        )
        guard recomputed == payloadSha256 else {
            // fail-closed：关键绑定摘要出现不一致时拒绝继续序列化/上报
            throw ReportEnvelope.ReportEnvelopeError.encodingFailed
        }
        return toJSONDictionary()
    }

    /// 计算上下文绑定摘要：`SHA256(nonce|ts|reportId|payload)`。
    /// 字段带长度前缀，避免字段值本身包含 `|` 时产生拼接歧义。
    internal static func computePayloadSha256(
        nonce: String,
        ts: Int64,
        reportId: String,
        payload: Data
    ) -> Data {
        var hasher = SHA256()
        // 对每个可变长字段做长度前缀，防止分隔符碰撞。
        let nonceBytes = Data(nonce.utf8)
        let reportIdBytes = Data(reportId.utf8)
        hasher.update(data: Data("\(nonceBytes.count):\(nonce)|\(ts)|\(reportIdBytes.count):\(reportId)|".utf8))
        hasher.update(data: payload)
        return Data(hasher.finalize())
    }
}

/// 构建 gRPC 兼容 payload 时的可选上下文（app_id、device_id、scene 等索引字段）。
public struct GrpcReportContext: Sendable {
    /// 调用方 App 标识，用于服务端分租户。
    public let appId: String
    /// 设备稳定标识（与服务端索引一致）。
    public let deviceId: String
    /// 业务场景标识；空字符串表示调用方未设置。
    public let scene: String

    public init(appId: String = "", deviceId: String = "", scene: String = "") {
        self.appId = appId
        self.deviceId = deviceId
        self.scene = scene
    }
}

// MARK: - ReportEnvelope 扩展

extension ReportEnvelope {
    /// 将信封转为与 `UploadRiskReportRequest` proto 兼容的 payload 结构体。
    /// - Parameter context: 可选上下文，提供 app_id、device_id、scene；缺失时使用空字符串。
    /// - Returns: 与 proto 字段一一对应的 `GrpcReportPayload`
    public func toGrpcCompatiblePayload(context: GrpcReportContext? = nil) -> GrpcReportPayload {
        let ctx = context ?? GrpcReportContext()
        // 优先使用规范化 JSON 作为签名/摘要输入；规范化失败时退回原始 payload（签名仍覆盖原始字节）。
        let wirePayload = (try? canonicalPayloadString()).map { Data($0.utf8) } ?? payload
        let payloadSha256 = GrpcReportPayload.computePayloadSha256(
            nonce: nonce,
            ts: ts,
            reportId: reportId,
            payload: wirePayload
        )
        let outputPathIntegrity = buildOutputPathIntegritySignal(payloadSha256: payloadSha256, wirePayload: wirePayload)

        return GrpcReportPayload(
            appId: ctx.appId,
            sdkVersion: Version.current,
            reportId: reportId,
            ts: ts,
            nonce: nonce,
            sessionToken: sessionToken,
            sigVer: sigVer,
            keyId: keyId,
            fieldMappingVersion: fieldMappingVersion,
            deviceId: ctx.deviceId,
            scene: ctx.scene,
            payloadJson: wirePayload,
            signature: signature,
            payloadSha256: payloadSha256,
            outputPathIntegrity: outputPathIntegrity,
            attestationKeyId: attestationKeyId,
            attestationAssertion: attestationAssertion,
            trustLevel: trustLevel,
            reAttestationAssertion: reAttestationAssertion,
            bindingMode: bindingMode,
            bindingDigest: bindingDigest,
            requireHardwareAttestation: requireHardwareAttestation
        )
    }

    /// 序列化为HTTP contract v1 JSON 字符串，供 HTTP/2 或 gRPC 客户端发送。
    /// - Parameters:
    ///   - context: 可选上下文
    ///   - prettyPrinted: 是否格式化输出（调试用；生产建议 false）
    /// - Returns: JSON 字符串
    public func toGrpcCompatibleJSON(
        context: GrpcReportContext? = nil,
        prettyPrinted: Bool = false
    ) throws -> String {
        let payload = toGrpcCompatiblePayload(context: context)
        let dict = try payload.validatedJSONDictionary()

        let options: JSONSerialization.WritingOptions = prettyPrinted ? [.prettyPrinted, .sortedKeys] : [.sortedKeys]
        let data = try JSONSerialization.data(withJSONObject: dict, options: options)
        guard let string = String(data: data, encoding: .utf8) else {
            throw ReportEnvelopeError.encodingFailed
        }
        return string
    }

    /// 序列化为HTTP contract v1 JSON Data（bytes），供 HTTP/2 或 gRPC 客户端发送。
    /// - Parameter context: 可选上下文
    /// - Returns: JSON 编码后的 Data
    public func toGrpcRequestBytes(context: GrpcReportContext? = nil) throws -> Data {
        let payload = toGrpcCompatiblePayload(context: context)
        let dict = try payload.validatedJSONDictionary()
        return try JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys])
    }

    // MARK: - 压缩上传

    /// 返回使用 zlib deflate（RFC 1950）压缩后的请求体。
    ///
    /// **签名覆盖未压缩的 canonical payload**，服务端必须先解压再验签。
    /// 传输压缩字节时应设置 HTTP 头 `Content-Encoding: zlib`。
    ///
    /// 若压缩反而增大体积（例如极小或已压缩的 payload），返回原始未压缩字节，
    /// 并令 `isCompressed` 为 `false`。
    ///
    /// - Returns: `(data, isCompressed)`；`isCompressed` 表示 `data` 是否为 zlib 压缩结果。
    public func toCompressedGrpcRequestBytes(
        context: GrpcReportContext? = nil
    ) throws -> (data: Data, isCompressed: Bool) {
        let raw = try toGrpcRequestBytes(context: context)
        if let compressed = try? (raw as NSData).compressed(using: .zlib) as Data,
           compressed.count < raw.count {
            return (compressed, true)
        }
        return (raw, false)
    }

    /// 构建输出链路完整性观测行：核对 payload 摘要与规范化状态，并附签名身份/绑定上下文。
    /// 这些字段仅用于诊断与灰度，不参与信封签名。
    private func buildOutputPathIntegritySignal(payloadSha256: Data, wirePayload: Data) -> [String: String] {
        let recomputed = GrpcReportPayload.computePayloadSha256(
            nonce: nonce,
            ts: ts,
            reportId: reportId,
            payload: wirePayload
        )
        let payloadShaMatches = (recomputed == payloadSha256)
        let bindingDiagnostics = bindingDiagnostics()
        let canonicalizationOK = bindingDiagnostics["payload_canonical_sha256"] != "unavailable"
        let trustValue = trustLevel?.rawValue ?? "unspecified"
        let signingTelemetry = AppSigningIdentityDetector().telemetry()
        let requestBindingFingerprint = Self.sha256Hex(Data([
            sigVer,
            keyId,
            trustValue,
            bindingDiagnostics["attestation_pair_state"] ?? "absent",
            reportId,
            signingTelemetry["signing_identity_fp"] ?? "",
            bindingDiagnostics["signature_input_sha256"] ?? "unavailable",
        ].joined(separator: "|").utf8))

        let status: String
        let reason: String
        if !payloadShaMatches {
            status = "blocked"
            reason = "payload_sha256_mismatch"
        } else if !canonicalizationOK {
            status = "high_risk"
            reason = "payload_canonicalization_failed"
        } else {
            status = "ok"
            reason = "consistent"
        }

        var rows = bindingDiagnostics
        rows.merge([
            "status": status,
            "reason": reason,
            "api_chain": "json_serialization+cryptokit_sha256",
            "route": "report_envelope->grpc_payload",
            "payload_sha256_match": payloadShaMatches ? "1" : "0",
            "binding_mode": Self.signatureBindingMode(for: sigVer),
            "binding_fields": "sigVer,nonce,ts,sessionToken,reportId,keyId,fieldMappingVersion,attestationKeyId,payloadCanonical",
            "attestation_pair_state": Self.attestationPairState(
                attestationKeyId: attestationKeyId,
                attestationAssertion: attestationAssertion
            ),
            "trust_level": trustValue,
            "request_binding_fp": requestBindingFingerprint,
        ]) { _, new in new }
        for (key, value) in signingTelemetry where !value.isEmpty {
            rows[key] = value
        }
        let mixFp = cprisk_get_signing_mix_fingerprint()
        if mixFp != 0 {
            rows["signing_mix_fp"] = String(format: "%08x", mixFp)
        }
        let wbPressure = cprisk_integrity_wb_prf_pressure_mask()
        if wbPressure != 0 {
            rows["wb_prf_pressure_mask"] = String(format: "%08x", wbPressure)
        }
        return rows
    }

    private static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// 把签名版本映射为可观测的绑定模式；未知版本按基础密钥绑定处理。
    private static func signatureBindingMode(for signatureVersion: String) -> String {
        switch signatureVersion {
        case "v2h":
            return "hkdf_derived_request_bound"
        case "v2a":
            return "armor_runtime_derived_request_bound"
        case "v2d":
            return "degraded_base_key_request_bound"
        default:
            return "base_key_request_bound"
        }
    }

    /// 描述 attestationKeyId 与 assertion 的配对状态：只有 `paired` 才构成完整硬件信任根。
    private static func attestationPairState(
        attestationKeyId: String?,
        attestationAssertion: Data?
    ) -> String {
        let hasKeyId = attestationKeyId.map { !$0.isEmpty } ?? false
        let hasAssertion = attestationAssertion.map { !$0.isEmpty } ?? false
        switch (hasKeyId, hasAssertion) {
        case (true, true):
            return "paired"
        case (true, false):
            return "key_only"
        case (false, true):
            return "assertion_only"
        case (false, false):
            return "none"
        }
    }
}
