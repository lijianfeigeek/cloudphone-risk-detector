// MARK: - CPRiskKit+Reporting（上报与配置）
//
// 从 CloudPhoneRiskKit.swift 拆分：报告构建、安全上传、信封签名、
// 远程配置管理与证书固定。
// 位于评估管线的上报阶段：把本地判决封装为带签名/证明的安全信封后交给服务端。
// 安全不变量：Armor 不可用且要求保护时失败即拒绝；远程配置拒绝回滚与同版本异内容；
// Release 构建禁止明文 HTTP，远程配置必须施加安全地板。

import CryptoKit
import CRiskCore
import Foundation

/// 为 CPRiskKit 提供安全信封构建、远程配置管理与证书固定能力。
extension CPRiskKit {

    // MARK: - 安全报告信封

    /// 构建安全上报信封。
    ///
    /// 根据远程加固配置决定签名版本与绑定模式：
    /// - Armor 正常：使用派生根密钥签名（Release 固定 v2a，DEBUG 可回退 v1）；
    /// - Armor 材料被投毒（integrity poisoned）：`requireArmor` 时抛错，否则降级 v2d；
    /// - Armor 不可用：`requireArmor` 时抛错，否则降级为普通 HMAC（v2d）。
    /// - Parameters:
    ///   - report: 本地评估报告。
    ///   - sessionToken: 会话令牌，用于防重放绑定。
    ///   - signingKey: 基础签名密钥。
    ///   - keyId: 密钥标识，默认 "k1"；存在轮换策略时自动映射到当前密钥 ID。
    ///   - attestationKeyId: App Attest 密钥标识（可选）。
    ///   - requireArmor: Armor 不可用时是否失败即拒绝，默认 `true`。
    /// - Returns: 已完成签名的安全信封。
    /// - Throws: `SecureUploadError`（字段映射缺失/过期、Armor 不可用）或签名失败。
    internal func buildSecureReportEnvelopeImpl(
        report: CPRiskReport,
        sessionToken: String,
        signingKey: String,
        keyId: String = "k1",
        attestationKeyId: String? = nil,
        requireArmor: Bool = true
    ) throws -> ReportEnvelope {
        let remoteConfig = currentRemoteConfig()
        let hardening = remoteConfig?.securityHardening ?? .default

        var mapping = remoteConfig?.payloadFieldMapping
        if let currentMapping = mapping, currentMapping.isExpired() {
            // 字段映射过期：强制模式下拒绝上报，否则退回未映射（防御性降级）
            if hardening.enforcePayloadFieldMapping {
                throw SecureUploadError.payloadFieldMappingExpired(version: currentMapping.version)
            }
            mapping = nil
        }

        if hardening.enforcePayloadFieldMapping, mapping == nil {
            throw SecureUploadError.payloadFieldMappingRequired
        }

        let payloadData = try report.secureUploadPayloadData(
            includeChallengeBinding: hardening.enableChallengeBinding
        )

        let effectiveKeyId: String
        // keyId 仍为默认 "k1" 且存在轮换策略时，改用当前轮换密钥 ID
        if keyId == "k1",
           TrustChainManager.currentKeyRotationPolicy() != nil {
            effectiveKeyId = TrustChainManager.currentKeyId(baseKeyId: keyId)
        } else {
            effectiveKeyId = keyId
        }

        let trustLevel = TrustChainManager.evaluateTrustLevel(
            deviceID: report.deviceID,
            hardwareMachine: report.device.hardwareMachine ?? "",
            kernelVersion: Sysctl.string("kern.version") ?? ""
        )

        let armorSnapshot = ensureArmorRuntimeStarted(trigger: "build_envelope")
        let signatureVersion: String
        let signatureProvider: ((Data) throws -> String)?
        let bindingMode: String

        if armorSnapshot.status == .active {
            // 运行时完整性被投毒时，派生密钥可能已泄漏/被替换，不能再用于签名
            let authentic = cprisk_is_integrity_poisoned() == 0
            if authentic {
                signatureProvider = { signatureInput in
                    guard let signature = Self.signWithArmorDerivedKey(
                        baseKey: signingKey,
                        signatureInput: signatureInput
                    ) else {
                        throw ReportEnvelope.ReportEnvelopeError.signingFailed
                    }
                    return signature
                }
                #if DEBUG
                signatureVersion = hardening.enableEnvelopeSignatureV2 ? "v2a" : "v1"
                #else
                // Release 固定使用 v2a，禁止回退到旧版签名
                signatureVersion = "v2a"
                #endif
                bindingMode = "armor_request_binding_sha256_v1"
            } else if requireArmor {
                Logger.log("buildSecureReportEnvelope: armor material marked poisoned by runtime state")
                throw SecureUploadError.armorRuntimeUnavailable(reason: "material_poisoned")
            } else {
                Logger.log("buildSecureReportEnvelope: armor material marked poisoned, degrading to v2d signature")
                signatureProvider = nil
                signatureVersion = "v2d"
                bindingMode = "plain_hmac_fallback_v1"
            }
        } else if requireArmor {
            Logger.log("buildSecureReportEnvelope: armor unavailable status=\(armorSnapshot.status.rawValue) reason=\(armorSnapshot.reason)")
            throw SecureUploadError.armorRuntimeUnavailable(reason: armorSnapshot.reason)
        } else {
            Logger.log("buildSecureReportEnvelope: armor unavailable, degrading to v2d signature (status=\(armorSnapshot.status.rawValue))")
            signatureProvider = nil
            signatureVersion = "v2d"
            bindingMode = "plain_hmac_fallback_v1"
        }

        // 过渡期显式 opt-in legacy 签发：本链路仍签发 v2a/v2d（DEBUG 下可能为 v1），
        // 线上签名字节保持不变。legacy 信封的 assertion 未纳入签名域，
        // 服务端必须拒绝 legacy 版本信封；待服务端完成 v3 切换后应移除本 opt-in。
        let envelopeConfig = ReportEnvelope.Config(
            signatureVersion: signatureVersion,
            allowLegacySignatureVersions: true
        )

        return try ReportEnvelope.create(
            payloadData: payloadData,
            reportId: report.reportID,
            sessionToken: sessionToken,
            signingKey: signingKey,
            keyId: effectiveKeyId,
            fieldMapping: mapping,
            attestationKeyId: attestationKeyId,
            trustLevel: trustLevel,
            config: envelopeConfig,
            signatureProvider: signatureProvider,
            bindingMode: bindingMode
        )
    }

    // MARK: - Armor 签名

    /// 清零 C 字符串缓冲区（安全擦除敏感中间值）。
    /// - Parameter buffer: 待清零的字符数组。
    internal static func clearCStringBuffer(_ buffer: inout [CChar]) {
        for index in buffer.indices {
            buffer[index] = 0
        }
    }

    /// 计算请求绑定摘要（签名输入域的 SHA256）。
    /// - Parameter signatureInput: 待签名数据。
    /// - Returns: 32 字节摘要，用于把请求参数绑定进签名。
    internal static func requestBindingDigest(for signatureInput: Data) -> Data {
        Data(SHA256.hash(data: signatureInput))
    }

    /// 使用 Armor 派生根密钥对请求签名。
    ///
    /// 所有中间敏感数据（基础密钥、绑定摘要、输出缓冲）在作用域结束时清零；
    /// C 层失败返回非零码时返回 nil（调用方决定失败即拒绝或降级）。
    /// - Parameters:
    ///   - baseKey: 基础密钥字符串。
    ///   - signatureInput: 待签名的请求数据。
    /// - Returns: 十六进制签名字符串；失败返回 `nil`。
    internal static func signWithArmorDerivedKey(baseKey: String, signatureInput: Data) -> String? {
        guard var keyData = baseKey.data(using: .utf8) else {
            Logger.log("armor_sign: UTF-8 encoding failed for baseKey")
            return nil
        }
        defer { secureZeroData(&keyData) }
        var bindingDigest = requestBindingDigest(for: signatureInput)
        defer { secureZeroData(&bindingDigest) }

        // +1 留给 C 字符串结尾的 NUL
        var signatureBuffer = [CChar](
            repeating: 0,
            count: Int(CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE) + 1
        )
        defer { clearCStringBuffer(&signatureBuffer) }

        let rc = signatureBuffer.withUnsafeMutableBufferPointer { signaturePtr in
            keyData.withUnsafeBytes { keyRaw in
                bindingDigest.withUnsafeBytes { digestRaw in
                    signatureInput.withUnsafeBytes { inputRaw in
                        guard let keyPtr = keyRaw.bindMemory(to: UInt8.self).baseAddress,
                              let digestPtr = digestRaw.bindMemory(to: UInt8.self).baseAddress,
                              let inputPtr = inputRaw.bindMemory(to: UInt8.self).baseAddress,
                              let sigPtr = signaturePtr.baseAddress else {
                            return Int32(-1)
                        }
                        return cprisk_sign_with_derived_key_and_request_binding_digest(
                            keyPtr,
                            keyData.count,
                            inputPtr,
                            signatureInput.count,
                            digestPtr,
                            sigPtr
                        )
                    }
                }
            }
        }
        guard rc == 0 else {
            Logger.log("armor_sign: bound cprisk_sign_with_derived_key failed rc=\(rc)")
            return nil
        }
        return String(cString: signatureBuffer)
    }

    /// 使用 Armor 派生根密钥验证签名。
    ///
    /// 与签名流程一致：绑定摘要参与验证，敏感缓冲区用后清零。
    /// - Parameters:
    ///   - baseKey: 基础密钥字符串。
    ///   - signatureInput: 原始请求数据。
    ///   - expectedSignature: 待校验的签名字符串。
    /// - Returns: 验证通过返回 `true`；编码失败、C 层失败或不匹配返回 `false`。
    internal static func verifyWithArmorDerivedKey(
        baseKey: String,
        signatureInput: Data,
        expectedSignature: String
    ) -> Bool {
        guard var keyData = baseKey.data(using: .utf8) else {
            Logger.log("armor_verify: UTF-8 encoding failed for baseKey")
            return false
        }
        defer { secureZeroData(&keyData) }
        var bindingDigest = requestBindingDigest(for: signatureInput)
        defer { secureZeroData(&bindingDigest) }

        var expectedCString = Array(expectedSignature.utf8CString)
        defer { clearCStringBuffer(&expectedCString) }

        let rc = expectedCString.withUnsafeBufferPointer { signaturePtr in
            keyData.withUnsafeBytes { keyRaw in
                bindingDigest.withUnsafeBytes { digestRaw in
                    signatureInput.withUnsafeBytes { inputRaw in
                        guard let keyPtr = keyRaw.bindMemory(to: UInt8.self).baseAddress,
                              let digestPtr = digestRaw.bindMemory(to: UInt8.self).baseAddress,
                              let inputPtr = inputRaw.bindMemory(to: UInt8.self).baseAddress,
                              let sigPtr = signaturePtr.baseAddress else {
                            return Int32(-1)
                        }
                        return cprisk_verify_with_derived_key_and_request_binding_digest(
                            keyPtr,
                            keyData.count,
                            inputPtr,
                            signatureInput.count,
                            digestPtr,
                            sigPtr
                        )
                    }
                }
            }
        }
        return rc == 0
    }

    // MARK: - 远程配置管理

    /// 获取当前远程配置提供者，必要时按已持久化的端点惰性创建。
    /// - Returns: 提供者；无端点且无法创建时返回 `nil`。
    internal func currentRemoteConfigProvider() -> RemoteConfigProvider? {
        let (provider, endpoint) = stateLock.withLock { (remoteConfigProvider, remoteConfigEndpoint) }

        if let provider {
            return provider
        }

        if let endpoint {
            _ = configureRemoteConfigProvider(urlString: endpoint.absoluteString)
        } else if let persisted = UserDefaults.standard.string(forKey: Self.remoteConfigEndpointKey) {
            // 冷启动时从持久化端点恢复，保证远程配置能力不丢失
            _ = configureRemoteConfigProvider(urlString: persisted)
        }

        return stateLock.withLock { remoteConfigProvider }
    }

    /// 获取当前生效的远程配置。
    /// - Returns: 内存缓存优先，其次提供者的当前配置；均无则 `nil`。
    internal func currentRemoteConfig() -> RemoteConfig? {
        let (cached, provider) = stateLock.withLock { (latestRemoteConfig, remoteConfigProvider) }

        if let cached {
            return cached
        }

        return provider?.currentConfig
    }

    /// 解析 SDK 版本对应的文本段哈希引用。
    ///
    /// 优先使用注入的解析器；否则从远程配置的 `textSegmentHashReference` 中查找。
    /// - Parameter sdkVersion: SDK 版本号。
    /// - Returns: 文本段引用；解析器与配置均无对应项时返回 `nil`。
    internal func resolveTextSegmentReference(for sdkVersion: String) -> TextSegmentReference? {
        let (resolver, cached, provider) = stateLock.withLock { (textSegmentReferenceResolver, latestRemoteConfig, remoteConfigProvider) }

        if let resolved = resolver?.resolveTextSegmentReference(for: sdkVersion) {
            return resolved
        }

        let config = cached ?? provider?.currentConfig
        guard let config,
              let expectedHash = config.textSegmentHashReference?[sdkVersion] else {
            return nil
        }

        return TextSegmentReference(
            expectedHash: expectedHash,
            source: "remote_config",
            version: String(config.version)
        )
    }

    /// 配置远程配置端点。
    ///
    /// 校验 URL 合法性；Release 构建拒绝明文 HTTP（防止配置被中间人篡改）。
    /// 相同端点会复用现有提供者并刷新信任状态，避免重复创建。
    /// - Parameter urlString: 配置端点 URL 字符串；`nil` 或空串直接返回 false。
    /// - Returns: 配置成功返回 `true`。
    @discardableResult
    internal func configureRemoteConfigProvider(urlString: String?) -> Bool {
        guard let rawURL = urlString?.trimmingCharacters(in: .whitespacesAndNewlines), !rawURL.isEmpty else {
            return false
        }
        guard
            let url = URL(string: rawURL),
            let scheme = url.scheme?.lowercased(),
            scheme == "https" || scheme == "http"
        else {
            Logger.log("remote_config.endpoint invalid: \(urlString ?? "nil")")
            return false
        }

#if !DEBUG
        // Release 仅允许 HTTPS：明文 HTTP 无法保证配置签名之外的内容机密性
        if scheme == "http" {
            Logger.log("remote_config.endpoint rejected: http not allowed in release build, use https")
            return false
        }
#endif

        let (sameEndpoint, existingProvider, hasCachedConfig) = stateLock.withLock {
            (remoteConfigEndpoint == url, remoteConfigProvider, latestRemoteConfig != nil)
        }

        if sameEndpoint, let existingProvider {
            // 复用提供者时重新注入证书固定材料并刷新缓存信任状态
            existingProvider.configurePinning(pinMaterial: Self.currentPinnedPinMaterial())
            existingProvider.reloadCachedConfigTrustState()
            if !hasCachedConfig {
                _ = applyRemoteConfigIfAccepted(existingProvider.currentConfig, source: "provider_reuse")
            }
            return true
        }

        let provider = RemoteConfigProvider(
            configURL: url,
            pinnedPinMaterial: Self.currentPinnedPinMaterial()
        )
        stateLock.withLock {
            remoteConfigEndpoint = url
            remoteConfigProvider = provider
        }

        _ = applyRemoteConfigIfAccepted(provider.currentConfig, source: "provider_init")
        UserDefaults.standard.set(rawURL, forKey: Self.remoteConfigEndpointKey)

        Logger.log("remote_config.endpoint set: \(url.absoluteString)")
        return true
    }

    /// 校验并应用远程配置（若被接受）。
    ///
    /// 安全策略：版本回滚一律拒绝（除非本地显式允许）；同版本但内容哈希不同也拒绝，
    /// 防止攻击者用同版本号替换配置绕过审计。
    /// - Parameters:
    ///   - config: 待应用的远程配置。
    ///   - source: 来源标识（provider_init / provider_reuse / trust_refresh），用于日志。
    ///   - validateStrictly: 校验失败时是否拒绝；`false` 仅记录警告（信任刷新场景）。
    /// - Returns: 配置被接受返回 `true`。
    @discardableResult
    internal func applyRemoteConfigIfAccepted(
        _ config: RemoteConfig,
        source: String,
        validateStrictly: Bool = true
    ) -> Bool {
        let effectiveConfig = Self.releaseHardenedRemoteConfig(config)
        let validation = effectiveConfig.validate()
        if !validation.isValid, validateStrictly {
            let detail = validation.errors.joined(separator: " | ")
            Logger.log("remote_config.\(source) rejected: invalid config, errors=\(detail)")
            return false
        }
        if !validation.isValid {
            let detail = validation.errors.joined(separator: " | ")
            Logger.log("remote_config.\(source) warning: invalid config accepted for local testing, errors=\(detail)")
        }
        if !validation.warnings.isEmpty {
            let warning = validation.warnings.joined(separator: " | ")
            Logger.log("remote_config.\(source) warning: \(warning)")
        }

        let remoteSafe = effectiveConfig.securityHardening?.enableAppStoreSafeProfile ?? false

        let accepted = stateLock.withLock { () -> Bool in
            if let currentVersion = latestRemoteConfig?.version {
                // 版本回滚检测：新版本必须不低于当前版本（本地测试可显式放行）
                if effectiveConfig.version < currentVersion, !Self.localRemoteConfigRollbackAllowed {
                    Logger.log(
                        "remote_config.\(source) rejected: rollback detected " +
                        "incoming=\(effectiveConfig.version) < current=\(currentVersion)"
                    )
                    return false
                }
                if effectiveConfig.version == currentVersion {
                    let currentHash = latestRemoteConfig.flatMap(Self.stableConfigHash)
                    let newHash = Self.stableConfigHash(effectiveConfig)
                    if let currentHash, currentHash == newHash {
                        // 内容未变化，幂等接受，避免重复触发配置应用副作用
                        return true
                    }
                    Logger.log("remote_config.\(source) rejected: same version but different content hash")
                    return false
                }
            }

            latestRemoteConfig = effectiveConfig

            // 把可疑库/路径/端口名单同步到动态特征列表
            DynamicFeatureList.shared.applyRemoteConfig(
                additionalSuspiciousLibraries: effectiveConfig.additionalSuspiciousLibraries,
                additionalSuspiciousPaths: effectiveConfig.additionalSuspiciousPaths,
                additionalSuspiciousPorts: effectiveConfig.additionalSuspiciousPorts
            )

            return true
        }

        if accepted {
            stateLock.withLock { lastRemoteAppStoreSafeProfileFlag = remoteSafe }
            // 远程安全档可能变化，需重新合成并应用 anti-debug 模式
            reapplyAntiDebugRuntimeModeAfterRemoteConfigChange()
        }

        return accepted
    }

    // MARK: - 证书固定与信任

    /// 应用证书固定材料。
    /// - Parameter material: 固定的证书哈希材料。
    internal func applyPinnedCertificateHashes(_ material: PinnedCertificatePinMaterial) {
        currentRemoteConfigProvider()?.configurePinning(pinMaterial: material)
    }

    /// 刷新远程配置信任状态。
    ///
    /// 有提供者时重新加载缓存信任状态并以非严格模式重放配置；无提供者时清空
    /// 远程配置与安全档标志，回退到本地配置（降级语义）。
    internal func refreshRemoteTrustState() {
        if let provider = currentRemoteConfigProvider() {
            provider.reloadCachedConfigTrustState()
            _ = applyRemoteConfigIfAccepted(provider.currentConfig, source: "trust_refresh", validateStrictly: false)
        } else {
            stateLock.withLock {
                latestRemoteConfig = nil
                lastRemoteAppStoreSafeProfileFlag = false
            }
            reapplyAntiDebugRuntimeModeAfterRemoteConfigChange()
        }
        PolicyManager.shared.reloadTrustedCacheState()
    }

    // MARK: - 证明信封

    /// 构建带 App Attest 证明的安全信封。
    ///
    /// 硬件信任不可用时：要求证明则失败即拒绝，否则回退为无 Armor 的普通信封。
    /// 证明生成/重证明失败时：要求证明则抛错，否则降级信任等级并返回兜底信封。
    /// - Parameters:
    ///   - report: 本地评估报告。
    ///   - sessionToken: 会话令牌。
    ///   - signingKey: 基础签名密钥。
    ///   - keyId: 密钥标识，默认 "k1"。
    ///   - requireAttestation: 是否强制要求证明，默认 `true`。
    /// - Returns: 含证明（或降级）的安全信封。
    /// - Throws: 硬件不支持、证明生成失败或信封构建失败时抛出。
    @available(iOS 14.0, macOS 11.0, *)
    internal func buildSecureReportEnvelopeWithAttestationImpl(
        report: CPRiskReport, sessionToken: String, signingKey: String,
        keyId: String = "k1", requireAttestation: Bool = true
    ) async throws -> ReportEnvelope {
        let effectiveKeyId = (keyId == "k1" && TrustChainManager.currentKeyRotationPolicy() != nil)
            ? TrustChainManager.currentKeyId(baseKeyId: keyId) : keyId
        guard AppAttestSigner.isSupported else {
            if requireAttestation { throw AppAttestSigner.AppAttestError.hardwareTrustUnsupported }
            // 不要求证明时退回普通信封，并明确关闭 Armor 强制
            return try buildSecureReportEnvelopeImpl(report: report, sessionToken: sessionToken, signingKey: signingKey, keyId: effectiveKeyId, requireArmor: false)
        }
        do {
            let attestKeyId = try await AppAttestSigner.resolveKeyId()
            var envelope = try buildSecureReportEnvelopeImpl(report: report, sessionToken: sessionToken, signingKey: signingKey, keyId: effectiveKeyId, attestationKeyId: attestKeyId)
            guard let payloadData = (try envelope.canonicalPayloadString()).data(using: .utf8) else {
                if requireAttestation { throw SecureUploadError.invalidPayloadShape }
                return envelope
            }
            // 对规范化载荷生成断言，把证明绑定到本次上报内容
            let (_, assertion) = try await AppAttestSigner.generateAssertion(for: payloadData)
            envelope = envelope.withAttestation(attestationKeyId: attestKeyId, assertion: assertion)
            if TrustChainManager.shouldRefreshAttestation(),
               let ch = PolicyManager.shared.activePolicy?.reAttestationChallenge, !ch.isEmpty {
                do {
                    // 对服务端下发的重证明挑战再次生成断言
                    let (_, ra) = try await AppAttestSigner.generateAssertion(for: ch)
                    envelope = envelope.withReAttestationAssertion(ra)
                    TrustChainManager.markAttestationChecked()
                } catch { envelope = envelope.withTrustLevel(TrustChainManager.degradedTrustLevel()) }
            } else { TrustChainManager.markAttestationChecked() }
            return envelope
        } catch {
            if requireAttestation { throw error }
            // 降级路径：构建无 Armor 的普通信封并标记信任等级下降
            let fallback = try buildSecureReportEnvelopeImpl(report: report, sessionToken: sessionToken, signingKey: signingKey, keyId: effectiveKeyId, requireArmor: false)
            return fallback.withTrustLevel(TrustChainManager.degradedTrustLevel())
        }
    }

    // MARK: - 静态辅助

    /// 规范化证书固定哈希集合（去空白、去空串）。
    /// - Parameter hashes: 原始哈希字符串数组。
    /// - Returns: 规范化后的集合。
    internal static func normalizedPinnedCertificateHashes(from hashes: [String]) -> Set<String> {
        Set(
            hashes
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
        )
    }

    /// 读取当前证书固定材料（线程安全）。
    internal static func currentPinnedPinMaterial() -> PinnedCertificatePinMaterial {
        remoteTrustLock.withLock { pinnedCertificatePinMaterial }
    }

    /// 对远程配置施加 Release 安全地板。
    ///
    /// DEBUG 构建原样返回（便于本地调试）；Release 强制不可低于本地安全基线。
    /// - Parameter config: 原始远程配置。
    /// - Returns: 加固后的远程配置。
    internal static func releaseHardenedRemoteConfig(_ config: RemoteConfig) -> RemoteConfig {
#if DEBUG
        return config
#else
        return config.enforcingReleaseSecurityFloor()
#endif
    }

    /// 计算远程配置的稳定哈希（键排序后 SHA256）。
    /// - Parameter config: 远程配置。
    /// - Returns: 十六进制哈希；编码失败返回 `nil`。
    internal static func stableConfigHash(_ config: RemoteConfig) -> String? {
        let encoder = JSONEncoder()
        // 排序键保证同一配置对象编码结果稳定，避免字典顺序影响哈希
        encoder.outputFormatting = [.sortedKeys]
        guard let data = try? encoder.encode(config) else { return nil }
        return SHA256.hash(data: data).compactMap { String(format: "%02x", $0) }.joined()
    }

    /// 构建“完整性被投毒”风险信号。
    /// - Returns: 高分篡改信号（score/weightHint 均为 85）。
    internal static func integrityRecheckPoisonedSignal() -> RiskSignal {
        RiskSignal(
            id: ObfuscatedConstants.signalIntegrityRuntimeTampered,
            category: "integrity",
            score: 85,
            evidence: ["reason": "integrity_poison_flag_set"],
            state: .tampered,
            layer: 2,
            weightHint: 85
        )
    }

    /// 构建“内存保护被绕过”风险信号。
    /// - Returns: 第 1 层篡改信号（score 85，weightHint 90）。
    private static func mprotectTamperedSignal() -> RiskSignal {
        RiskSignal(
            id: ObfuscatedConstants.signalMemoryProtectionTampered,
            category: ObfuscatedConstants.categoryAntiTamper,
            score: 85,
            evidence: ["detail": "mprotect_syscall_blocked"],
            state: .tampered,
            layer: 1,
            weightHint: 90
        )
    }
}
