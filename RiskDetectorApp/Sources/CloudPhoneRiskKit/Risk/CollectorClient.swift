// 上报链路·Collector 传输客户端：HTTPS + 证书 pinning，负责 App Attest 挑战/注册与报告上传。
// 仅传输序列化后的安全信封，不参与 HMAC/断言计算（证明链见 `AppAttestSigner`）。
// 隐私边界：离开设备的是 `GrpcReportPayload` 中的信封字段；bearer token 只出现在 Authorization 头。

import Foundation

/// 与 Collector 服务通信的已认证 HTTP 客户端。
///
/// 客户端只负责传输机制；App Attest 注册与报告序列化留在 `AppAttestSigner` 中，
/// 使“获取挑战 → 上报确认”保持为一次串行事务。
@available(iOS 14.0, macOS 11.0, *)
public actor CollectorClient {
    /// 客户端配置；`baseURL` 必须为 HTTPS，`bearerToken` 不得为空。
    public struct Configuration: Sendable {
        /// Collector 服务根地址（仅接受 HTTPS）。
        public let baseURL: URL
        /// 服务端签发的访问令牌，仅用于请求头，不写入上报正文。
        public let bearerToken: String
        /// 单次请求/资源超时（秒），默认 10 秒。
        public let timeout: TimeInterval
        /// 上报索引字段上下文（app_id / device_id / scene）。
        public let context: GrpcReportContext

        public init(
            baseURL: URL,
            bearerToken: String,
            timeout: TimeInterval = 10,
            context: GrpcReportContext
        ) {
            self.baseURL = baseURL
            self.bearerToken = bearerToken
            self.timeout = timeout
            self.context = context
        }
    }

    /// 上传成功回执；用于确认服务端已落库并区分幂等重放。
    public struct Receipt: Sendable {
        /// 服务端生成的证据 ID。
        public let evidenceID: String
        /// 服务端生成的报告 ID。
        public let reportID: String
        /// 服务端判定为幂等重放（同一报告已上传过）。
        public let idempotentReplay: Bool
    }

    /// 传输与协议校验错误；所有错误均向上抛出，不静默吞掉。
    public enum Error: Swift.Error, LocalizedError {
        case invalidConfiguration
        case invalidResponse
        case rejected(status: Int)
        case invalidChallenge
        case invalidReceipt

        public var errorDescription: String? {
            switch self {
            case .invalidConfiguration: return "Collector requires HTTPS and a non-empty bearer token"
            case .invalidResponse: return "Collector returned a non-HTTP response"
            case .rejected(let status): return "Collector rejected request (HTTP \(status))"
            case .invalidChallenge: return "Collector challenge response is invalid"
            case .invalidReceipt: return "Collector receipt is invalid"
            }
        }
    }

    private let configuration: Configuration
    private let session: URLSession

    /// 创建客户端。
    /// - Throws: 配置非 HTTPS 或 bearer token 为空时抛 `invalidConfiguration`（fail-closed）。
    /// - Parameter session: 可注入自定义会话（测试用）；默认会话强制证书 pinning。
    public init(configuration: Configuration, session: URLSession? = nil) throws {
        // 传输层硬性要求 HTTPS；明文 HTTP 直接拒绝，避免 token 与证据泄漏。
        guard configuration.baseURL.scheme?.lowercased() == "https",
              !configuration.bearerToken.isEmpty else {
            throw Error.invalidConfiguration
        }
        self.configuration = configuration
        if let session {
            self.session = session
        } else {
            // 默认会话走证书 pinning（全局已配置的 pin 材料），失败硬拒绝：
            // 无 pin 时挑战被取消，Collector 请求失败，绝不回落系统 CA。
            let cfg = URLSessionConfiguration.ephemeral
            cfg.timeoutIntervalForRequest = configuration.timeout
            cfg.timeoutIntervalForResource = configuration.timeout
            self.session = CertificatePinningSessionDelegate.pinnedSession(
                pinMaterial: CPRiskKit.pinnedCertificatePinMaterial,
                configuration: cfg,
                allowsSystemCA: false
            )
        }
    }

    /// 配置 App Attest 注册回调，使 `AppAttestSigner` 能通过本客户端获取挑战并提交注册。
    public func configureAppAttestEnrollment() {
        AppAttestSigner.configureEnrollment(
            challenge: { [self] in try await challenge(purpose: "enrollment") },
            submit: { [self] keyID, attestation, challengeID in
                try await enroll(keyID: keyID, attestation: attestation, challengeID: challengeID)
            }
        )
    }

    /// 提交报告：先取一次性挑战并构造 App Attest 证明信封，再上传并返回回执。
    /// - Throws: 网络错误、挑战无效、服务端拒绝或回执字段缺失。
    @discardableResult
    public func submit(
        payloadData: Data,
        reportID: String,
        sessionToken: String,
        signingKey: String,
        keyID: String
    ) async throws -> Receipt {
        var receipt: Receipt?
        try await AppAttestSigner.submitCollectorReport(
            payloadData: payloadData,
            reportId: reportID,
            sessionToken: sessionToken,
            signingKey: signingKey,
            keyId: keyID,
            challenge: { [self] in try await challenge(purpose: "assertion") },
            submit: { [self] envelope in
                receipt = try await upload(envelope)
            }
        )
        guard let receipt else { throw Error.invalidReceipt }
        return receipt
    }

    /// 从服务端获取一次性挑战。
    /// - Parameter purpose: `enrollment`（注册密钥）或 `assertion`（报告断言）。
    /// - Throws: 响应非 JSON、挑战字段缺失、base64 解码失败或不足 32 字节时拒绝。
    private func challenge(purpose: String) async throws -> AppAttestSigner.EnrollmentChallenge {
        let body = try JSONSerialization.data(withJSONObject: ["purpose": purpose], options: [.sortedKeys])
        let data = try await request(path: "/attestation/challenge", body: body)
        // 挑战必须带非空 ID 且至少 32 字节（256 位熵）；不满足即视为服务端/中间人异常。
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let identifier = object["challenge_id"] as? String,
              let encoded = object["challenge"] as? String,
              let bytes = Data(base64Encoded: encoded),
              !identifier.isEmpty, bytes.count >= 32 else {
            throw Error.invalidChallenge
        }
        return .init(id: identifier, bytes: bytes)
    }

    /// 提交 attestation 注册（keyId + 苹果签发的 attestation + 挑战 ID）。
    private func enroll(keyID: String, attestation: Data, challengeID: String) async throws {
        let body = try JSONSerialization.data(withJSONObject: [
            "key_id": keyID,
            "attestation": attestation.base64EncodedString(),
            "challenge_id": challengeID,
        ], options: [.sortedKeys])
        _ = try await request(path: "/attestation/enroll", body: body)
    }

    /// 上传已签名的安全信封，并校验回执必填字段。
    /// - Throws: 序列化失败、HTTP 非 2xx 或回执缺字段时拒绝。
    private func upload(_ envelope: ReportEnvelope) async throws -> Receipt {
        let body = try envelope.toGrpcRequestBytes(context: configuration.context)
        let data = try await request(path: "/reports", body: body)
        // 回执必须同时包含非空 evidence_id 与 report_id，否则无法关联后续审计。
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let evidenceID = object["evidence_id"] as? String,
              let reportID = object["report_id"] as? String,
              !evidenceID.isEmpty, !reportID.isEmpty else {
            throw Error.invalidReceipt
        }
        return Receipt(
            evidenceID: evidenceID,
            reportID: reportID,
            idempotentReplay: object["idempotent_replay"] as? Bool ?? false
        )
    }

    /// 发送 JSON POST 请求并返回响应体。
    /// 非 HTTP 响应或非 2xx 状态码均抛错；不做自动重试，避免重放语义被掩盖。
    private func request(path: String, body: Data) async throws -> Data {
        guard let url = URL(string: path, relativeTo: configuration.baseURL)?.absoluteURL else {
            throw Error.invalidConfiguration
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = configuration.timeout
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer " + configuration.bearerToken, forHTTPHeaderField: "Authorization")
        request.httpBody = body
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw Error.invalidResponse }
        guard (200..<300).contains(http.statusCode) else { throw Error.rejected(status: http.statusCode) }
        return data
    }
}
