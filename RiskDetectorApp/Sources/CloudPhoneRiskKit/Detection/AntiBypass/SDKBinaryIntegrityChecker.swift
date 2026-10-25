// SDK 二进制完整性校验：确认 CloudPhoneRiskKit 镜像本身未被整体替换或改写。
// 检查 LC_CODE_SIGNATURE 是否存在、LC_UUID 是否与 Keychain 基线一致、段权限是否合理、
// 文件大小是否在合理范围；UUID 变化时再与 __TEXT.__text 哈希交叉验证，区分正常升级与定向伪造。
// 首启/升级窗口若环境可疑则拒绝建立基线，避免把被投毒的状态写成可信锚点。

import Darwin
import Foundation
import MachO
import Security

/// SDK 二进制自身完整性校验
///
/// 防止攻击者直接替换 SDK framework 的 Mach-O 二进制。
/// Keychain 使用 `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`；换号重装后基线自动重建。
/// 检测手段：
/// 1. 验证 SDK 镜像的 LC_CODE_SIGNATURE 是否存在且有效
/// 2. 检查 SDK 的 LC_UUID 是否在运行期间被篡改（对比 Keychain 存储）
/// 3. 验证 SDK 镜像的 segment 权限是否合理
/// 4. 检查 SDK 二进制大小是否在合理范围
enum SDKBinaryIntegrityChecker {

    /// 二进制校验结果。
    struct IntegrityResult {
        /// 整体是否完整；首启建基线窗口固定为 false（不可信窗口）。
        let isIntact: Bool
        /// 各子检查的通过情况，失败项会在 detail 中列出。
        let checks: [String: Bool]
        /// 机器可读的结果摘要，如 intact / tampered:<检查项> / baseline_established。
        let detail: String
        /// UUID 变化但文本段哈希未变 — 可能是针对 UUID 的定向伪装
        let baselineAnomaly: Bool
    }

    // Keychain 服务名/账号为持久化契约，改名会导致旧基线失效并触发一次重建。
    private static let keychainService = "CloudPhoneRiskKit"
    private static let keychainUUIDAcc = "sdk_binary_uuid_v1"
    private static let keychainSizeAcc = "sdk_binary_size_v1"

    /// 执行全部二进制完整性检查。
    /// - 找不到 SDK 镜像时返回“完整”而非失败：可能是不支持的环境或镜像被完全剥离，交由其他检测器处理。
    /// - 返回 `isIntact == false` 不一定代表攻击：首启/升级窗口也返回 false，用于表达“尚不可信”。
    static func verify() -> IntegrityResult {
        #if targetEnvironment(simulator)
        // 模拟器没有真实签名/ASLR 语义，全部跳过以避免系统性误报。
        return IntegrityResult(isIntact: true, checks: [:], detail: "simulator_skip", baselineAnomaly: false)
        #else
        var checks: [String: Bool] = [:]
        var allPassed = true
        var baselineAnomaly = false

        guard let image = findSDKImage() else {
            return IntegrityResult(isIntact: true, checks: [:], detail: "sdk_image_not_found", baselineAnomaly: false)
        }

        // 首启：环境可疑时拒绝建基线，避免把已被注入的状态固化为可信基线。
        if keychainRead(account: keychainUUIDAcc) == nil {
            let envCheck = IntegrityBaselineEnvCheck.check()
            if envCheck.isSuspicious {
                return IntegrityResult(
                    isIntact: false,
                    checks: ["baseline_rejected": false],
                    detail: "baseline_rejected_suspicious_env",
                    baselineAnomaly: false
                )
            }
        }

        // 1. LC_CODE_SIGNATURE 是否存在（缺失通常意味着重签名或二进制被重写）。
        let hasCodeSig = checkCodeSignature(header: image.header)
        checks["code_signature"] = hasCodeSig
        if !hasCodeSig { allPassed = false }

        // 2. LC_UUID 与 Keychain 基线是否一致；升级会改变 UUID，需进一步交叉验证。
        let uuidCheck = checkUUIDConsistency(header: image.header)
        checks["uuid_consistent"] = uuidCheck.consistent
        if !uuidCheck.consistent { allPassed = false }

        // 交叉验证：UUID 变了但代码段哈希没变，说明可能是定向伪造 UUID 而非真实升级。
        if !uuidCheck.consistent && !uuidCheck.isFirstRun {
            baselineAnomaly = crossValidateWithTextSegment(image: image)
        }

        // 3. 段权限合理性：__TEXT 不应可写、__DATA 不应可执行。
        let permCheck = checkSegmentPermissions(header: image.header)
        checks["segment_permissions"] = permCheck
        if !permCheck { allPassed = false }

        // 4. 二进制大小合理性；允许 ±30% 波动，覆盖正常版本迭代。
        let sizeCheck = checkBinarySize(header: image.header, index: image.index)
        checks["binary_size"] = sizeCheck
        if !sizeCheck { allPassed = false }

        let detail: String
        if uuidCheck.isFirstRun {
            detail = "baseline_established"
        } else if allPassed {
            detail = "intact"
        } else {
            let failed = checks.filter { !$0.value }.map { $0.key }
            detail = "tampered:\(failed.joined(separator: ","))"
        }

        // 首启窗口无法断言完整性，故 isIntact 固定为 false；下次启动基线才可信。
        let isIntact = uuidCheck.isFirstRun ? false : allPassed
        return IntegrityResult(isIntact: isIntact, checks: checks, detail: detail, baselineAnomaly: baselineAnomaly)
        #endif
    }

    /// 用文本段哈希对 UUID 变化做交叉验证。
    /// 返回 true（异常）表示 UUID 变了但文本段哈希没变，可能是定向篡改 UUID 而非真实升级。
    private static func crossValidateWithTextSegment(image: (header: UnsafeRawPointer, index: UInt32)) -> Bool {
        guard let (currentHash, _) = TextSegmentIntegrityChecker.hashTextSection(
            header: image.header, imageIndex: image.index
        ) else {
            return false
        }

        guard let storedBaseline = TextSegmentIntegrityChecker.loadBaseline() else {
            return false
        }

        let textHashChanged = storedBaseline.hash != currentHash
        // UUID 变化 + 文本段哈希不变 = 可疑（定向修改 UUID）。
        return !textHashChanged
    }

    /// 把二进制校验结果转换为信号。
    /// 首启/环境可疑属于“不可信窗口”，给软信号或高危信号；各项失败按严重度独立计分。
    static func asSignals(result: IntegrityResult) -> [RiskSignal] {
        // 首次运行建基线：产出不可信窗口软信号，提高权重
        if result.detail == "baseline_established" {
            return [RiskSignal(
                id: "sdk_integrity_first_run",
                category: "integrity",
                score: 8,
                evidence: ["detail": "baseline_established_on_first_run"],
                state: .soft(confidence: 0.55),
                layer: 2,
                weightHint: 45
            )]
        }

        // 环境可疑拒绝建基线：高危信号
        if result.detail == "baseline_rejected_suspicious_env" {
            return [RiskSignal(
                id: "sdk_integrity_baseline_rejected_suspicious_env",
                category: "integrity",
                score: 55,
                evidence: ["detail": "baseline_rejected_suspicious_env"],
                state: .tampered,
                layer: 2,
                weightHint: 88
            )]
        }

        guard !result.isIntact else {
            if result.baselineAnomaly {
                return [RiskSignal(
                    id: "sdk_binary_baseline_anomaly",
                    category: "integrity",
                    score: 40,
                    evidence: ["detail": "uuid_changed_but_text_segment_unchanged"],
                    state: .tampered,
                    layer: 2,
                    weightHint: 85
                )]
            }
            return []
        }
        
        var signals: [RiskSignal] = []

        if result.baselineAnomaly {
            signals.append(RiskSignal(
                id: "sdk_binary_baseline_anomaly",
                category: "integrity",
                score: 40,
                evidence: ["detail": "uuid_changed_but_text_segment_unchanged"],
                state: .tampered,
                layer: 2,
                weightHint: 85
            ))
        }
        
        if result.checks["code_signature"] == false {
            signals.append(RiskSignal(
                id: "sdk_code_signature_missing",
                category: "integrity",
                score: 30,
                evidence: ["detail": "SDK binary LC_CODE_SIGNATURE missing or invalid"],
                state: .tampered,
                layer: 2,
                weightHint: 90
            ))
        }
        
        if result.checks["uuid_consistent"] == false {
            signals.append(RiskSignal(
                id: "sdk_binary_replaced",
                category: "integrity",
                score: 35,
                evidence: ["detail": "SDK binary UUID changed unexpectedly"],
                state: .tampered,
                layer: 2,
                weightHint: 95
            ))
        }
        
        if result.checks["segment_permissions"] == false {
            signals.append(RiskSignal(
                id: "sdk_segment_tampered",
                category: "integrity",
                score: 20,
                evidence: ["detail": "SDK binary has abnormal segment permissions"],
                state: .tampered,
                layer: 2,
                weightHint: 85
            ))
        }
        
        if result.checks["binary_size"] == false {
            signals.append(RiskSignal(
                id: "sdk_binary_size_anomaly",
                category: "integrity",
                score: 15,
                evidence: ["detail": "SDK binary size changed significantly"],
                state: .soft(confidence: 0.7),
                layer: 2,
                weightHint: 70
            ))
        }
        
        return signals
    }
    
    // MARK: - 检查方法

    /// 在已加载镜像中按路径名查找 SDK 自身，返回 Mach-O 头指针与 dyld 索引。
    private static func findSDKImage() -> (header: UnsafeRawPointer, index: UInt32)? {
        let count = _dyld_image_count()
        for i in 0..<count {
            guard let raw = _dyld_get_image_name(i) else { continue }
            let path = String(cString: raw)
            if path.lowercased().contains("cloudphoneriskkit") {
                guard let header = _dyld_get_image_header(i) else { continue }
                return (UnsafeRawPointer(header), i)
            }
        }
        return nil
    }
    
    /// 遍历 load commands 查找 LC_CODE_SIGNATURE；同时校验魔数，非 64 位 Mach-O 直接判失败。
    /// 每个 cmdsize 都做下界检查，防止损坏的 load command 造成指针越界。
    private static func checkCodeSignature(header: UnsafeRawPointer) -> Bool {
        let ptr = header.assumingMemoryBound(to: mach_header_64.self)
        guard ptr.pointee.magic == MH_MAGIC_64 else { return false }
        
        var cmd = header.advanced(by: MemoryLayout<mach_header_64>.size)
        for _ in 0..<ptr.pointee.ncmds {
            let loadCmd = cmd.assumingMemoryBound(to: load_command.self).pointee
            guard loadCmd.cmdsize >= MemoryLayout<load_command>.size else { break }
            if loadCmd.cmd == LC_CODE_SIGNATURE {
                return true
            }
            cmd = cmd.advanced(by: Int(loadCmd.cmdsize))
        }
        return false
    }
    
    /// 比较当前 LC_UUID 与 Keychain 基线。
    /// - 首次运行：写入基线并标记 `isFirstRun`，本次不判为篡改但整体不可信。
    /// - UUID 变化：立即刷新基线并返回不一致，交由文本段哈希判定是升级还是攻击。
    private static func checkUUIDConsistency(header: UnsafeRawPointer) -> (consistent: Bool, uuid: String?, isFirstRun: Bool) {
        guard let currentUUID = extractUUID(header: header) else {
            return (true, nil, false)
        }
        
        if let storedUUID = keychainRead(account: keychainUUIDAcc) {
            if storedUUID == currentUUID {
                return (true, currentUUID, false)
            }
            // UUID 变化：可能是正常升级，也可能是镜像替换。先更新基线，
            // 让下一次启动以新值为准；是否攻击交给文本段哈希交叉验证。
            keychainWrite(account: keychainUUIDAcc, value: currentUUID)
            return (false, currentUUID, false)
        }

        // 首次运行 — 建立基线；显式标记为 first-run 而非静默通过。
        keychainWrite(account: keychainUUIDAcc, value: currentUUID)
        return (true, currentUUID, true)
    }

    /// 从 LC_UUID 提取 32 位十六进制小写字符串；无该命令时返回 nil。
    private static func extractUUID(header: UnsafeRawPointer) -> String? {
        let ptr = header.assumingMemoryBound(to: mach_header_64.self)
        guard ptr.pointee.magic == MH_MAGIC_64 else { return nil }
        
        var cmd = header.advanced(by: MemoryLayout<mach_header_64>.size)
        for _ in 0..<ptr.pointee.ncmds {
            let loadCmd = cmd.assumingMemoryBound(to: load_command.self).pointee
            guard loadCmd.cmdsize >= MemoryLayout<load_command>.size else { break }
            if loadCmd.cmd == LC_UUID {
                let uuidCmd = cmd.assumingMemoryBound(to: uuid_command.self).pointee
                let bytes = withUnsafeBytes(of: uuidCmd.uuid) { Array($0) }
                return bytes.map { String(format: "%02x", $0) }.joined()
            }
            cmd = cmd.advanced(by: Int(loadCmd.cmdsize))
        }
        return nil
    }
    
    /// 检查关键段权限：__TEXT 不可写、__DATA 不可执行。
    /// 违反说明 Mach-O 段头被改写（常见于给 __DATA 加执行权限以运行注入代码）。
    private static func checkSegmentPermissions(header: UnsafeRawPointer) -> Bool {
        let ptr = header.assumingMemoryBound(to: mach_header_64.self)
        guard ptr.pointee.magic == MH_MAGIC_64 else { return false }
        
        var cmd = header.advanced(by: MemoryLayout<mach_header_64>.size)
        for _ in 0..<ptr.pointee.ncmds {
            let loadCmd = cmd.assumingMemoryBound(to: load_command.self).pointee
            guard loadCmd.cmdsize >= MemoryLayout<load_command>.size else { break }
            if loadCmd.cmd == LC_SEGMENT_64 {
                let seg = cmd.assumingMemoryBound(to: segment_command_64.self).pointee
                let segName = withUnsafePointer(to: seg.segname) { ptr in
                    ptr.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
                }
                // __TEXT 应为 r-x，任何写权限都是异常。
                if segName == "__TEXT" && (seg.initprot & VM_PROT_WRITE) != 0 {
                    return false
                }
                // __DATA 不应可执行。
                if segName == "__DATA" && (seg.initprot & VM_PROT_EXECUTE) != 0 {
                    return false
                }
            }
            cmd = cmd.advanced(by: Int(loadCmd.cmdsize))
        }
        return true
    }
    
    /// 汇总所有 segment 的 filesize 作为二进制体积，并与 Keychain 基线比较。
    /// 允许 ±30% 波动：正常发版会改变体积，超过该幅度更像整体替换；
    /// 超限时刷新基线并返回 false，避免同一次异常在后续启动中持续误报。
    private static func checkBinarySize(header: UnsafeRawPointer, index: UInt32) -> Bool {
        let ptr = header.assumingMemoryBound(to: mach_header_64.self)
        guard ptr.pointee.magic == MH_MAGIC_64 else { return false }
        
        var totalSize: UInt64 = 0
        var cmd = header.advanced(by: MemoryLayout<mach_header_64>.size)
        for _ in 0..<ptr.pointee.ncmds {
            let loadCmd = cmd.assumingMemoryBound(to: load_command.self).pointee
            guard loadCmd.cmdsize >= MemoryLayout<load_command>.size else { break }
            if loadCmd.cmd == LC_SEGMENT_64 {
                let seg = cmd.assumingMemoryBound(to: segment_command_64.self).pointee
                totalSize += seg.filesize
            }
            cmd = cmd.advanced(by: Int(loadCmd.cmdsize))
        }
        
        let sizeStr = "\(totalSize)"
        if let storedSize = keychainRead(account: keychainSizeAcc) {
            guard let stored = UInt64(storedSize), stored > 0 else {
                return false
            }
            let ratio = Double(totalSize) / Double(stored)
            // 体积变化超过 30% 且无法用版本更新解释时判为异常。
            if ratio < 0.7 || ratio > 1.3 {
                keychainWrite(account: keychainSizeAcc, value: sizeStr)
                return false
            }
            return true
        }
        
        keychainWrite(account: keychainSizeAcc, value: sizeStr)
        return true
    }
    
    // MARK: - Keychain 辅助

    /// 读取指定账号的 UTF-8 字符串；Keychain 不可用或条目缺失时返回 nil。
    private static func keychainRead(account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
    
    /// 更新或新增 Keychain 条目。
    /// 仅在 errSecItemNotFound 时回退到 SecItemAdd；其他错误只记日志，不覆盖已有值。
    private static func keychainWrite(account: String, value: String) {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecSuccess {
            return
        }
        if status != errSecItemNotFound {
            Logger.log("SDKBinaryIntegrityChecker.keychainWrite: SecItemUpdate failed (status=\(status))")
        }
        if status == errSecItemNotFound {
            var addQuery = query
            addQuery[kSecValueData as String] = data
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            if addStatus != errSecSuccess {
                Logger.log("SDKBinaryIntegrityChecker.keychainWrite: SecItemAdd failed (status=\(addStatus))")
            }
        }
    }
}
