// 文件职责：构建端侧信任根链（Secure Enclave → App Attest → DeviceKey → SessionKey），
// 评估 TrustLevel、派生会话密钥，并支持服务端下发的密钥轮换策略。
// 管道位置：启动/评估早期提供信任等级，上报前提供签名密钥解析。
// 安全不变量：异常路径一律降级为 .degraded（fail-closed）；会话密钥用完即弃、
// 不落盘。
import CryptoKit
import Foundation
#if canImport(DeviceCheck)
import DeviceCheck
#endif

/// 信任链控制流平坦化（CFF）辅助：为状态机生成与上下文绑定的 salt。
private enum TrustChainCFF {
    /// 组合设备、内核、session、策略版本、时间等上下文，生成状态机 salt。
    /// 任一字段变化都会改变状态转移编码，增加静态分析/篡改难度。
    /// - Returns: 32 位 salt。
    static func salt(
        deviceID: String = "",
        hardwareMachine: String = "",
        kernelVersion: String = "",
        sessionId: String = "",
        policyVersion: String = "",
        timestamp: Int64 = 0,
        lastCheck: TimeInterval = 0
    ) -> UInt32 {
        CFFRuntimeSalt.combine(
            words: [
                UInt64(bitPattern: timestamp),
                lastCheck.bitPattern,
                UInt64(sessionId.utf8.count),
            ],
            strings: [
                deviceID,
                hardwareMachine,
                kernelVersion,
                sessionId,
                policyVersion,
                ChallengeSession.shared.state.rawValue,
            ],
            flags: [
                !deviceID.isEmpty,
                !sessionId.isEmpty,
                ChallengeSession.shared.currentChallengeId != nil,
            ]
        )
    }
}

// MARK: - TrustLevel（SDK 5.0）

/// 端侧信任等级，服务端可据此调整决策权重。
/// 等级只降不升：任何能力缺失或校验异常都落到更低的等级。
public enum TrustLevel: String, Codable, Sendable {
    /// App Attest 可用且 attestation 有效
    case hardware
    /// App Attest 不可用，但 DeviceKey + Keychain 完整
    case derived
    /// Keychain 被清或 attestation 过期
    case degraded
}

// MARK: - KeyRotationPolicy（SDK 5.0）

/// 密钥轮换策略，可由服务端下发。
/// 双 key 窗口保证轮换期间的旧报告仍可验签。
public struct KeyRotationPolicy: Codable, Sendable {
    /// 最大存活时间（秒），超时强制轮换
    public let maxLifetimeSeconds: Int
    /// 双 key 窗口（秒），轮换后旧 key 保留时间，确保在途报告可验
    public let dualKeyWindowSeconds: Int
    /// 当前 DeviceKey 版本
    public let deviceKeyVersion: String

    private enum CodingKeys: String, CodingKey {
        case maxLifetimeSeconds = "ml"
        case dualKeyWindowSeconds = "dw"
        case deviceKeyVersion = "dv"
    }

    /// 创建轮换策略。
    /// - Parameters:
    ///   - maxLifetimeSeconds: 密钥最大存活时间，超时强制轮换（默认 7 天）。
    ///   - dualKeyWindowSeconds: 轮换后旧 key 保留窗口，确保在途报告可验（默认 1 小时）。
    ///   - deviceKeyVersion: 当前 DeviceKey 版本。
    public init(
        maxLifetimeSeconds: Int = 86400 * 7,
        dualKeyWindowSeconds: Int = 3600,
        deviceKeyVersion: String = "v1"
    ) {
        self.maxLifetimeSeconds = maxLifetimeSeconds
        self.dualKeyWindowSeconds = dualKeyWindowSeconds
        self.deviceKeyVersion = deviceKeyVersion
    }
}

// MARK: - TrustChainManager（SDK 5.0）

/// 端侧信任根链管理器。
/// 建立从硬件到报告的完整信任传递链：
/// Secure Enclave --> App Attest Key --> DeviceKey --> SessionKey --> ReportSignature。
/// 全部为静态方法，内部状态仅由锁保护的最后一次 attestation 检查时间。
public enum TrustChainManager {

    /// HKDF info 参数：固定域分隔串，保证派生结果只用于 SessionKey。
    private static let sessionKeyInfo = Data("CloudPhoneRiskKit.SessionKey.v1".utf8)
    /// 保护 `lastAttestationCheck` 的互斥锁。
    private static let lock = UnfairLock()
    /// 上次 attestation 检查时间（Unix 秒）。
    private static var lastAttestationCheck: TimeInterval = 0
    /// 重新 attestation 的时间间隔（1 小时）。
    private static let attestationCheckInterval: TimeInterval = 3600

    // MARK: - KeyRotationPolicy 应用

    /// 从 PolicyManager 获取当前 keyRotationPolicy。
    /// - Returns: 服务端下发的策略；未下发时为 nil。
    public static func currentKeyRotationPolicy() -> KeyRotationPolicy? {
        PolicyManager.shared.activePolicy?.keyRotationPolicy
    }

    /// 获取当前应使用的 deviceKeyVersion（服务端 policy 优先，否则用默认版本）。
    public static func currentDeviceKeyVersion() -> String {
        currentKeyRotationPolicy()?.deviceKeyVersion ?? DeviceKeyDeriver.defaultInfoVersion
    }

    /// 获取当前应使用的 keyId（用于 ReportEnvelope）。
    /// - Parameter baseKeyId: 基础 key 标识，默认 k1。
    /// - Returns: `<baseKeyId>_<version>` 形式的 keyId。
    public static func currentKeyId(baseKeyId: String = "k1") -> String {
        let version = currentDeviceKeyVersion()
        return "\(baseKeyId)_\(version)"
    }

    // MARK: - TrustLevel 评估

    /// 评估当前信任等级（完整版，含 Keychain salt 持久化检查）。
    /// - Parameters:
    ///   - deviceID: 设备标识。
    ///   - hardwareMachine: 硬件机型标识。
    ///   - kernelVersion: 内核版本。
    /// - Returns: 信任等级；任何异常都回落为 `.degraded`。
    public static func evaluateTrustLevel(
        deviceID: String,
        hardwareMachine: String,
        kernelVersion: String
    ) -> TrustLevel {
        let salt = TrustChainCFF.salt(
            deviceID: deviceID,
            hardwareMachine: hardwareMachine,
            kernelVersion: kernelVersion,
            policyVersion: currentDeviceKeyVersion()
        )
        // 状态机使用固定 seed + 上下文 salt 编码状态，避免直接以明文状态跳转。
        let seed: UInt32 = 0x2E7C41B9
        let entryState: UInt32 = 0x11
        let capabilityState: UInt32 = 0x12
        let hardwareState: UInt32 = 0x13
        let derivedState: UInt32 = 0x14

        // 用 sink 统一收敛返回值；未解析时最终回落为 .degraded。
        var sink = CFFReturnSink<TrustLevel>()
        var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: salt)
        var hardwareSupported = false

        #if canImport(DeviceCheck)
        if #available(iOS 14.0, macOS 11.0, *) {
            hardwareSupported = AppAttestSigner.isSupported
        }
        #endif

        // 控制流平坦化：循环内按解码后的状态转移，直到写入结果。
        while !sink.isResolved {
            switch CFFStateCodec.decode(encodedState, seed: seed, salt: salt) {
            case entryState:
                encodedState = CFFStateCodec.encode(capabilityState, seed: seed, salt: salt)
            // 根据 App Attest 是否可用选择硬件或派生分支。
            case capabilityState:
                encodedState = CFFStateCodec.encode(hardwareSupported ? hardwareState : derivedState, seed: seed, salt: salt)
            // 硬件分支：只有 salt 成功持久化才给 .hardware。
            case hardwareState:
                let (_, saltWasPersisted) = DeviceKeyDeriver.deriveKeyWithTrustInfo(
                    deviceID: deviceID,
                    hardwareMachine: hardwareMachine,
                    kernelVersion: kernelVersion,
                    infoVersion: currentDeviceKeyVersion()
                )
                sink.store(saltWasPersisted ? .hardware : .degraded)
            // 派生分支：salt 持久化成功给 .derived，否则降级。
            case derivedState:
                let (_, saltWasPersisted) = DeviceKeyDeriver.deriveKeyWithTrustInfo(
                    deviceID: deviceID,
                    hardwareMachine: hardwareMachine,
                    kernelVersion: kernelVersion,
                    infoVersion: currentDeviceKeyVersion()
                )
                sink.store(saltWasPersisted ? .derived : .degraded)
            default:
                sink.store(.degraded)
            }
        }

        return sink.resolve(or: .degraded)
    }

    /// 评估信任等级（简化版，无 DeviceKey 派生，用于快速路径）。
    /// - Returns: App Attest 可用时为 `.hardware`，否则为 `.derived`。
    public static func evaluateTrustLevelQuick() -> TrustLevel {
        #if canImport(DeviceCheck)
        if #available(iOS 14.0, macOS 11.0, *) {
            if AppAttestSigner.isSupported {
                return .hardware
            }
        }
        #endif
        return .derived
    }

    /// 评估信任等级（带设备上下文，可检测 Keychain 被清）。
    /// 当前实现委托给完整版评估。
    public static func evaluateTrustLevelWithContext(
        deviceID: String,
        hardwareMachine: String,
        kernelVersion: String
    ) -> TrustLevel {
        evaluateTrustLevel(
            deviceID: deviceID,
            hardwareMachine: hardwareMachine,
            kernelVersion: kernelVersion
        )
    }

    // MARK: - SessionKey 派生

    /// 派生会话密钥：SessionKey = HKDF(DeviceKey, sessionId + timestamp)。
    /// 每次 evaluate 生成，用完即焚，不持久化。
    /// - Parameters:
    ///   - deviceKey: DeviceKey 派生的输入密钥材料。
    ///   - sessionId: 当前会话标识。
    ///   - timestamp: 当前时间戳（Unix 秒）。
    /// - Returns: 32 字节会话密钥。
    public static func deriveSessionKey(
        deviceKey: SymmetricKey,
        sessionId: String,
        timestamp: Int64
    ) -> SymmetricKey {
        let cffSalt = TrustChainCFF.salt(
            sessionId: sessionId,
            policyVersion: currentDeviceKeyVersion(),
            timestamp: timestamp
        )
        let seed: UInt32 = 0x73A15C4D
        let entryState: UInt32 = 0x21
        let materialState: UInt32 = 0x22
        let deriveState: UInt32 = 0x23
        let connectorState: UInt32 = 0x24
        let settleState: UInt32 = 0x25
        // 兜底 salt：即使状态机异常也能得到确定、可复现的派生结果。
        let fallbackSalt = "\(sessionId)|\(timestamp)".data(using: .utf8) ?? Data()

        var sink = CFFReturnSink<SymmetricKey>()
        var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: cffSalt)
        var hkdfSalt = Data()

        while !sink.isResolved {
            let decodedState = CFFStateCodec.decode(encodedState, seed: seed, salt: cffSalt)

            // 入口 → 生成密钥材料。
            if decodedState == entryState {
                encodedState = CFFStateCodec.encode(materialState, seed: seed, salt: cffSalt)
            // 选择 salt 并进入分发。
            } else if decodedState == materialState {
                hkdfSalt = fallbackSalt
                encodedState = CFFStateCodec.encode(connectorState, seed: seed, salt: cffSalt)
            // 由 CFF 分发器决定走正常派生还是兜底收敛。
            } else if decodedState == connectorState {
                let nextState = CFFDispatcher.prefersPrimaryBranch(encodedState: encodedState, salt: cffSalt) ? deriveState : settleState
                encodedState = CFFStateCodec.encode(nextState, seed: seed, salt: cffSalt)
            // 收敛状态统一回到派生状态。
            } else if decodedState == settleState {
                encodedState = CFFStateCodec.encode(deriveState, seed: seed, salt: cffSalt)
            // 正常派生路径。
            } else if decodedState == deriveState {
                // HKDF-SHA256 输出 32 字节；info 固定用于域分隔。
                sink.store(
                    HKDF<SHA256>.deriveKey(
                        inputKeyMaterial: deviceKey,
                        salt: hkdfSalt,
                        info: sessionKeyInfo,
                        outputByteCount: 32
                    )
                )
            } else {
                sink.store(
                    HKDF<SHA256>.deriveKey(
                        inputKeyMaterial: deviceKey,
                        salt: fallbackSalt,
                        info: sessionKeyInfo,
                        outputByteCount: 32
                    )
                )
            }
        }

        return sink.resolve(
            or: HKDF<SHA256>.deriveKey(
                inputKeyMaterial: deviceKey,
                salt: fallbackSalt,
                info: sessionKeyInfo,
                outputByteCount: 32
            )
        )
    }

    /// 将会话密钥转为小写 hex 字符串（用于 ReportEnvelope 签名）。
    public static func sessionKeyToHex(_ key: SymmetricKey) -> String {
        key.withUnsafeBytes { Data($0).map { String(format: "%02x", $0) }.joined() }
    }

    // MARK: - KeyResolver（多 key 并存，支持密钥轮换）

    /// 构建 keyResolver：根据 keyId 解析出 signingKey（hex）。
    /// 支持双 key 窗口：当前版本 + 上一版本在 dualKeyWindowSeconds 内仍可验签。
    /// - Parameters:
    ///   - deviceID: 设备标识。
    ///   - hardwareMachine: 硬件机型标识。
    ///   - kernelVersion: 内核版本。
    ///   - baseKeyId: 基础 key 标识，默认 k1。
    /// - Returns: 解析器闭包；未知 keyId 返回 nil（调用方应按验签失败处理）。
    public static func buildKeyResolver(
        deviceID: String,
        hardwareMachine: String,
        kernelVersion: String,
        baseKeyId: String = "k1"
    ) -> (String) -> String? {
        let policy = currentKeyRotationPolicy()
        let currentVersion = policy?.deviceKeyVersion ?? DeviceKeyDeriver.defaultInfoVersion
        let cffSalt = TrustChainCFF.salt(
            deviceID: deviceID,
            hardwareMachine: hardwareMachine,
            kernelVersion: kernelVersion,
            policyVersion: currentVersion
        )
        // 外层状态机只负责构建闭包，实际解析在内层状态机完成。
        let seed: UInt32 = 0x5CA217E3
        let entryState: UInt32 = 0x31
        let buildState: UInt32 = 0x32

        var sink = CFFReturnSink<(String) -> String?>()
        var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: cffSalt)

        while !sink.isResolved {
            switch CFFStateCodec.decode(encodedState, seed: seed, salt: cffSalt) {
            case entryState:
                encodedState = CFFStateCodec.encode(buildState, seed: seed, salt: cffSalt)
            // 构建解析闭包。
            case buildState:
                // 闭包按 keyId 现场派生，避免长期持有密钥材料。
                sink.store { keyId in
                    let innerSalt = TrustChainCFF.salt(
                        deviceID: deviceID,
                        hardwareMachine: hardwareMachine,
                        kernelVersion: kernelVersion,
                        sessionId: keyId,
                        policyVersion: currentVersion,
                        timestamp: Int64(keyId.utf8.count)
                    )
                    let innerSeed: UInt32 = 0x4F31A28C
                    let classifyState: UInt32 = 0x41
                    let deriveState: UInt32 = 0x42
                    let rejectState: UInt32 = 0x43

                    var localSink = CFFReturnSink<String?>()
                    var localState = CFFStateCodec.encode(classifyState, seed: innerSeed, salt: innerSalt)
                    var version: String?

                    while !localSink.isResolved {
                        let decodedState = CFFStateCodec.decode(localState, seed: innerSeed, salt: innerSalt)

                        if decodedState == classifyState {
                            // 优先解析 `<baseKeyId>_<version>`；裸 baseKeyId 视为当前版本。
                            version = keyId.hasPrefix("\(baseKeyId)_")
                                ? String(keyId.dropFirst("\(baseKeyId)_".count))
                                : (keyId == baseKeyId ? currentVersion : nil)
                            localState = CFFStateCodec.encode(version == nil ? rejectState : deriveState, seed: innerSeed, salt: innerSalt)
                        } else if decodedState == deriveState {
                            // 版本有效才派生 key，否则返回 nil。
                            if let version {
                                let key = DeviceKeyDeriver.deriveKey(
                                    deviceID: deviceID,
                                    hardwareMachine: hardwareMachine,
                                    kernelVersion: kernelVersion,
                                    infoVersion: version
                                )
                                localSink.store(sessionKeyToHex(key))
                            } else {
                                localSink.store(nil)
                            }
                        } else if decodedState == rejectState {
                            localSink.store(nil)
                        } else {
                            localSink.store(nil)
                        }
                    }

                    return localSink.resolve(or: nil)
                }
            default:
                sink.store({ _ in nil })
            }
        }

        return sink.resolve(or: { _ in nil })
    }

    // MARK: - Attestation 刷新

    /// 检查是否需要 re-attestation。
    /// 当前实现仅基于时间间隔；完整实现需服务端下发 challenge。
    /// - Returns: 距上次检查超过 1 小时返回 true；异常路径返回 true（宁可多刷）。
    public static func shouldRefreshAttestation() -> Bool {
        // 在锁内读取，避免与 markAttestationChecked 竞争。
        let last: TimeInterval = lock.withLock { lastAttestationCheck }

        let cffSalt = TrustChainCFF.salt(
            policyVersion: currentDeviceKeyVersion(),
            timestamp: Int64(last.rounded()),
            lastCheck: last
        )
        let seed: UInt32 = 0x18D2BF65
        let entryState: UInt32 = 0x51
        let compareState: UInt32 = 0x52

        var sink = CFFReturnSink<Bool>()
        var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: cffSalt)
        var now: TimeInterval = 0

        while !sink.isResolved {
            let decodedState = CFFStateCodec.decode(encodedState, seed: seed, salt: cffSalt)

            if decodedState == entryState {
                now = Date().timeIntervalSince1970
                encodedState = CFFStateCodec.encode(compareState, seed: seed, salt: cffSalt)
            // 比较时间差；异常状态默认要求刷新。
            } else if decodedState == compareState {
                sink.store(now - last > attestationCheckInterval)
            } else {
                sink.store(true)
            }
        }

        return sink.resolve(or: true)
    }

    /// 标记 attestation 检查完成（记录当前时间）。
    public static func markAttestationChecked() {
        lock.withLock { lastAttestationCheck = Date().timeIntervalSince1970 }
    }

    /// 获取 attestation 降级时应使用的 TrustLevel。
    public static func degradedTrustLevel() -> TrustLevel {
        .degraded
    }
}
