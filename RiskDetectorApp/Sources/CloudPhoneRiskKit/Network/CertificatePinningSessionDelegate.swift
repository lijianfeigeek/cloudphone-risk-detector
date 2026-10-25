// 文件职责：实现 TLS 证书固定（SPKI SHA-256 pinning）的 URLSessionDelegate，
// 并对服务端信任链做多重冗余校验。
// 管道位置：所有远程配置/策略/上报请求的传输层入口，位于上报管道最前端。
// 安全不变量：pinning 失败或校验出错一律取消握手；仅 allowsSystemCA（开发模式）
// 才允许回落系统 CA，生产路径绝不回退。
import CRiskCore
import Darwin
import Foundation
import Security

/// TLS 证书固定 — 防止中间人篡改远程配置与策略
///
/// 使用 SPKI (Subject Public Key Info) SHA-256 哈希进行固定，
/// 比证书固定更灵活（证书轮换时只需更新 hash，不需要嵌入新证书）。
/// 线程模型：URLSession delegate 回调在串行队列执行，本类无可变状态。
/// 安全不变量：校验错误或无 pin 命中一律取消握手，只有 allowsSystemCA 才回落系统 CA。
@objc(CPR_PinSessionDelegate)
public final class CertificatePinningSessionDelegate: NSObject, URLSessionDelegate {

    /// 已解析的 pin 材料（原始摘要字节，避免长期保留 `sha256/...` 字符串）。
    private let pinMaterial: PinnedCertificatePinMaterial
    /// 是否允许回落到系统 CA；仅开发/调试模式应为 true，生产必须为 false。
    private let allowsSystemCA: Bool

    /// 非模拟器上，`SecTrustEvaluateWithError` 耗时低于该阈值（纳秒）则记录时序异常侧信道（不单独断连）。
    private static let trustEvalSuspiciouslyFastNs: UInt64 = 5_000

    /// 创建 pinning delegate。
    /// - Parameters:
    ///   - pinMaterial: 已解析的 SPKI SHA-256 材料（见 ``PinnedCertificatePinMaterial``）。
    ///   - allowsSystemCA: 为 true 时，无 pin 命中会回落系统 CA（仅开发模式）。
    public init(pinMaterial: PinnedCertificatePinMaterial, allowsSystemCA: Bool = false) {
        self.pinMaterial = pinMaterial
        self.allowsSystemCA = allowsSystemCA
        super.init()
    }

    /// 便捷初始化：直接传入 pin 字符串集合。
    /// - Parameters:
    ///   - pinnedHashes: SPKI SHA-256 哈希集合（如 `sha256/<base64>`），内部解析为摘要字节。
    ///   - allowsSystemCA: 为 true 时，无 pin 命中会回落系统 CA（仅开发模式）。
    public convenience init(pinnedHashes: Set<String>, allowsSystemCA: Bool = false) {
        self.init(pinMaterial: PinnedCertificatePinMaterial(pinStrings: pinnedHashes), allowsSystemCA: allowsSystemCA)
    }

    /// 处理服务端信任挑战：完成系统信任评估与 SPKI pin 校验，决定是否建立连接。
    /// - 材料缺失、C 侧校验错误、Swift/C 结果分歧均取消挑战（fail-closed）。
    /// - 仅当某条证书命中且 scope 允许时使用凭据；无命中时按 allowsSystemCA 决定。
    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        // 只接管服务器信任挑战；其他认证方式交回系统默认处理。
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        let host = challenge.protectionSpace.host

        // 未配置任何 pin 时 fail-closed：没有信任锚就不允许建立 TLS 连接。
        guard !pinMaterial.isEmpty else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // 先做 C 侧完整性/反 hook 预检，防止信任评估函数本身已被劫持。
        if !preflightPinningCore(host: host) {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // 计时系统信任评估耗时；异常过快可能意味着评估被短路或 hook。
        let t0 = PinningMonotonicNanos.now()
        var error: CFError?
        let isValid = SecTrustEvaluateWithError(serverTrust, &error)
        let t1 = PinningMonotonicNanos.now()
        let elapsed = t1 &- t0

        // 模拟器时序噪声大，仅在真机上报“评估过快”侧信道。
        #if !targetEnvironment(simulator)
        if elapsed < Self.trustEvalSuspiciouslyFastNs {
            recordPinning(
                host: host,
                kind: .trustEvalSuspiciouslyFast,
                detail: [
                    "elapsed_ns": "\(elapsed)",
                    "threshold_ns": "\(Self.trustEvalSuspiciouslyFastNs)",
                ]
            )
        }
        #endif

        // 系统信任评估失败：记录 CFError 后立即取消，绝不能继续向下走。
        guard isValid else {
            var detail: [String: String] = [:]
            if let err = error {
                let ns = err as Error as NSError
                detail["cf_error_domain"] = ns.domain
                detail["cf_error_code"] = "\(ns.code)"
            }
            recordPinning(host: host, kind: .trustEvalFailed, detail: detail)
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // 用独立 API 交叉校验，降低单一函数被 hook 后仍放行的风险。
        guard crossCheckTrustEvaluation(serverTrust, host: host) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // 叶证书公钥必须可取，否则无法做 SPKI pin；视为异常并取消。
        if #available(iOS 14.0, macOS 11.0, *) {
            guard SecTrustCopyKey(serverTrust) != nil else {
                recordPinning(host: host, kind: .leafPublicKeyMissing, detail: [:])
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
        }

        // 遍历整条证书链；是否允许该位置命中由 pin 的 scope 决定。
        let certificates: [SecCertificate]
        // iOS 15+ 一次性取整条链；旧系统走逐下标读取的兼容分支。
        if #available(iOS 15.0, macOS 12.0, *) {
            guard let chain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate], !chain.isEmpty else {
                recordPinning(host: host, kind: .emptyCertificateChain, detail: ["reason": "ios15_chain"])
                if allowsSystemCA {
                    completionHandler(.performDefaultHandling, nil)
                } else {
                    completionHandler(.cancelAuthenticationChallenge, nil)
                }
                return
            }
            certificates = chain
        } else {
            var certs: [SecCertificate] = []
            let certCount = certificateCount(trust: serverTrust)
            for i in 0..<certCount {
                if let cert = certificateAt(trust: serverTrust, index: i) {
                    certs.append(cert)
                }
            }
            guard !certs.isEmpty else {
                recordPinning(host: host, kind: .emptyCertificateChain, detail: ["reason": "legacy_chain"])
                if allowsSystemCA {
                    completionHandler(.performDefaultHandling, nil)
                } else {
                    completionHandler(.cancelAuthenticationChallenge, nil)
                }
                return
            }
            certificates = certs
        }

        // 双重校验：Swift 与 CRiskCore 各算一次，任一方出错或结论不一致即取消。
        for (chainIndex, cert) in certificates.enumerated() {
            guard let spkiDigest = spkiSHA256DigestFromCore(certificate: cert) else { continue }
            let swiftMatch = pinMaterial.matchesLayeredDigest(spkiDigest, chainIndex: chainIndex)
            let coreOutcome = pinMaterial.matchesLayeredDigestViaCoreOutcome(spkiDigest, chainIndex: chainIndex)
            // C 侧返回 -1（error）时无条件取消：错误 ≠ 不匹配，绝不回落系统 CA。
            guard coreOutcome != .error else {
                recordPinning(
                    host: host,
                    kind: .pinValidatorDiverged,
                    detail: ["reason": "core_pinset_error", "chain_index": "\(chainIndex)"]
                )
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
            let coreMatch = coreOutcome == .match
            // 两套实现结论分歧说明有篡改或输入异常，fail-closed。
            if swiftMatch != coreMatch {
                recordPinning(
                    host: host,
                    kind: .pinValidatorDiverged,
                    detail: [
                        "swift_match": swiftMatch ? "1" : "0",
                        "core_match": coreMatch ? "1" : "0",
                    ]
                )
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
            // 双方一致命中且 scope 允许：使用该信任凭据建立连接。
            if swiftMatch && coreMatch {
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
                return
            }
        }

        // 整条链都无可用 pin：仅开发模式允许回落系统 CA，生产直接断开。
        recordPinning(host: host, kind: .pinMismatch, detail: ["allows_system_ca": "\(allowsSystemCA)"])
        if allowsSystemCA {
            completionHandler(.performDefaultHandling, nil)
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    // MARK: - CRiskCore 校验与冗余信任校验

    /// C 侧完整性与反 hook 预检；失败时返回 false，调用方必须取消挑战。
    /// 模拟器上仅记录遥测、不阻断，避免宿主机环境造成误杀。
    /// - Parameter host: 当前连接主机名，仅用于遥测归因。
    /// - Returns: true 表示可继续 TLS 校验。
    private func preflightPinningCore(host: String) -> Bool {
        // 校验 SVC stub 未被 inline hook / Frida 改写。
        let stubMask = cprisk_verify_svc_stub_integrity()
        if stubMask != 0 {
            recordPinning(
                host: host,
                kind: .svcStubIntegrity,
                detail: ["stub_mask": "\(stubMask)"]
            )
            #if !targetEnvironment(simulator)
            return false
            #endif
        }

        // 校验 Security.framework / dlsym / dlopen 入口 prologue 与基线一致。
        var trustHookMask: UInt32 = 0
        if cprisk_verify_trust_hook_surface_integrity(&trustHookMask) == 0 {
            recordPinning(
                host: host,
                kind: .trustHookSurfaceIntegrity,
                detail: ["fail_mask": "\(trustHookMask)"]
            )
            #if !targetEnvironment(simulator)
            return false
            #endif
        }

        // 全局完整性复检：1=篡改，-2=计算失败，均失败即拒绝；-1 表示不支持。
        let ir = cprisk_recheck_integrity()
        switch ir {
        case 1:
            recordPinning(host: host, kind: .integrityRecheckTamper, detail: ["recheck": "1"])
            return false
        case -2:
            recordPinning(host: host, kind: .integrityRecheckComputeFailed, detail: ["recheck": "-2"])
            return false
        case -1:
            break
        default:
            break
        }
        return true
    }

    /// 与 `SecTrustEvaluateWithError` 独立的 `SecTrustGetTrustResult` 交叉校验，
    /// 降低单点 hook 面；结果为 `.proceed` / `.unspecified` 才视为通过。
    private func crossCheckTrustEvaluation(_ serverTrust: SecTrust, host: String) -> Bool {
        // 另取一次信任结果；与主评估不一致时按失败处理。
        var trustResult = SecTrustResultType.invalid
        let status = SecTrustGetTrustResult(serverTrust, &trustResult)
        guard status == errSecSuccess else {
            recordPinning(
                host: host,
                kind: .trustResultMismatch,
                detail: [
                    "sec_trust_get_result_status": "\(status)",
                    "trust_result": "\(trustResult.rawValue)",
                ]
            )
            return false
        }
        switch trustResult {
        case .proceed, .unspecified:
            return true
        default:
            recordPinning(
                host: host,
                kind: .trustResultMismatch,
                detail: [
                    "trust_result": "\(trustResult.rawValue)",
                ]
            )
            return false
        }
    }

    /// 写入证书固定遥测事件，供 Risk 管线聚合为信号。
    private func recordPinning(host: String, kind: CertificatePinningTelemetryKind, detail: [String: String]) {
        CertificatePinningTelemetry.shared.record(host: host, kind: kind, detail: detail)
    }

    /// 从 SecCertificate 提取 SPKI DER 的 SHA-256 原始摘要（DER 解析与哈希在 C 侧）。
    /// - Returns: 32 字节摘要；C 侧解析失败时返回 nil（调用方跳过该证书）。
    private func spkiSHA256DigestFromCore(certificate: SecCertificate) -> Data? {
        // 固定 32 字节输出缓冲；C 侧失败时不返回半成品摘要。
        var digest = [UInt8](repeating: 0, count: 32)
        let rc = cprisk_spki_sha256_from_sec_certificate(
            Unmanaged.passUnretained(certificate).toOpaque(),
            &digest
        )
        guard rc == 0 else { return nil }
        return Data(digest)
    }

    @available(iOS, deprecated: 15.0)
    @available(macOS, deprecated: 12.0)
    /// 旧系统兼容：取证书链长度（iOS 15 / macOS 12 起弃用）。
    private func certificateCount(trust: SecTrust) -> Int {
        SecTrustGetCertificateCount(trust)
    }

    @available(iOS, deprecated: 15.0)
    @available(macOS, deprecated: 12.0)
    /// 旧系统兼容：按下标取证书（iOS 15 / macOS 12 起弃用）。
    private func certificateAt(trust: SecTrust, index: Int) -> SecCertificate? {
        SecTrustGetCertificateAtIndex(trust, index)
    }

    /// 创建启用证书固定的 URLSession。
    /// - 默认使用 `.ephemeral` 配置，避免凭据/缓存落盘。
    /// - 返回的 session 会强引用 delegate，调用方无需自行保留。
    public static func pinnedSession(
        pinMaterial: PinnedCertificatePinMaterial,
        configuration: URLSessionConfiguration = .ephemeral,
        allowsSystemCA: Bool = false
    ) -> URLSession {
        let delegate = CertificatePinningSessionDelegate(
            pinMaterial: pinMaterial,
            allowsSystemCA: allowsSystemCA
        )
        return URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
    }

    /// 便捷重载：从 pin 字符串构建 session（非法条目会被忽略）。
    public static func pinnedSession(
        hashes: Set<String>,
        configuration: URLSessionConfiguration = .ephemeral,
        allowsSystemCA: Bool = false
    ) -> URLSession {
        pinnedSession(
            pinMaterial: PinnedCertificatePinMaterial(pinStrings: hashes),
            configuration: configuration,
            allowsSystemCA: allowsSystemCA
        )
    }
}

/// 单调时钟纳秒读数，用于测量信任评估耗时（不受系统时间调整影响）。
private enum PinningMonotonicNanos {
    /// mach 时钟换算系数，进程内只读取一次。
    private static let timebase: mach_timebase_info_data_t = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info
    }()

    /// 返回自开机以来的单调纳秒数；乘法溢出时退化为 `UInt64.max`。
    static func now() -> UInt64 {
        let t = mach_absolute_time()
        let denom = max(UInt64(timebase.denom), 1)
        let (product, overflow) = t.multipliedReportingOverflow(by: UInt64(timebase.numer))
        return overflow ? UInt64.max : product / denom
    }
}
