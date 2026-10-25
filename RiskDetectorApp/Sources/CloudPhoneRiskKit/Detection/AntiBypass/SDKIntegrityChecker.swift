// SDK 完整性检测器（Detector 入口）：聚合 libc 直调回退、DYLD 注入、可疑镜像、主程序路径、
// 代码签名命令与 PLT 基线六类证据；PLT 基线把关键 C 符号的归属镜像持久化到 Keychain，
// 用版本 token 区分正常升级与 hook，首启/升级窗口标记为不可信。最终分数封顶 100。

import CRiskCore
import Darwin
import Foundation
import MachO
import Security

/// SDK 环境完整性检测器：把多种注入/篡改证据汇总成一个分数。
struct SDKIntegrityChecker: Detector {

    /// 汇总各类完整性证据并返回分数。
    /// 单项失败只累加自身权重，最后统一封顶，避免某一项异常掩盖其他维度。
    func detect() throws -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []

        // watchdog 位图记录发生过 libc 直调回退的调用面，回退面越广说明 hook 越深入。
        let watchdogSnap = CPRiskKit.shared.antiDebugWatchdogSnapshot()
        if let libcFallbackObservation = Self.libcDirectSyscallFallbackObservation(from: watchdogSnap) {
            score += libcFallbackObservation.score
            methods.append(libcFallbackObservation.method)
        }

        // 环境变量注入是最直接的 dylib 注入手段。
        if ObfuscatedConstants.envKeyDyldInsertLibraries.withCString({ getenv($0) != nil }) {
            score += 20
            methods.append("integrity:dyld_insert_libraries")
        }

        // 已加载镜像中命中 hook 框架特征。
        if let suspicious = firstSuspiciousImage() {
            score += 25
            methods.append("integrity:suspicious_image:\(suspicious)")
        }

        // 主程序不在 .app 包内，通常是重打包或越狱启动。
        if !isMainExecutableInBundle() {
            score += 15
            methods.append("integrity:main_executable_path")
        }

        // 缺少 LC_CODE_SIGNATURE，签名可能被剥离后重签。
        if !hasCodeSignatureCommand() {
            score += 20
            methods.append("integrity:missing_code_signature")
        }

        // PLT 基线与当前符号归属不一致：权重最高，指向明确的符号级 hook。
        let pltResult = PLTIntegrityGuard.verifyWithPersistedBaseline()
        if !pltResult.isIntact {
            score += 30
            for fn in pltResult.hookedFunctions {
                methods.append("integrity:plt_hooked:\(fn)")
            }
        }

        // 基线状态本身也是证据：首启/升级只是不可信窗口，环境可疑则按高危处理。
        switch pltResult.baselineTrustState {
        case .trusted:
            break
        case .firstObservation:
            score += 8
            methods.append("integrity:plt_baseline_pending")
        case .versionChanged:
            score += 12
            methods.append("integrity:plt_version_changed")
        case .baselineRejectedSuspiciousEnv:
            score += 55
            methods.append("integrity:plt_baseline_rejected_suspicious_env")
        }

        // 封顶 100，保留各子项的可解释性。
        return DetectorResult(score: min(score, 100), methods: methods)
    }

    /// 把 watchdog 记录的 libc 直调回退位图转换为分数与方法标签。
    /// - 未发生回退（mask == 0）返回 nil，不产生噪声。
    /// - bit7 表示“平台不支持”，不算攻击面；其余位代表实际回退过的系统调用面，得分更高。
    static func libcDirectSyscallFallbackObservation(
        from watchdogSnap: CPRiskKit.AntiDebugWatchdogSnapshot
    ) -> (score: Double, method: String)? {
        let mask = watchdogSnap.libcFallbackUsedMask
        guard mask != 0 else {
            return nil
        }

        // 平台不支持位：C 枚举未桥接到 Swift，需与 CRiskCore.h 保持同步。
        let syscallSurfaceBits = mask & ~UInt32(1 << 7)
        let score = syscallSurfaceBits != 0 ? 14.0 : 8.0
        let method =
            "integrity:libc_direct_syscall_fallback:0x\(String(mask, radix: 16))" +
            ":events_total=\(watchdogSnap.libcFallbackEventTotal)" +
            ":watchdog_supported=\(watchdogSnap.supported ? 1 : 0)"
        return (score: score, method: method)
    }

    /// 返回第一个命中可疑特征的镜像短名；特征表来自可被远端扩展的 `DynamicFeatureList`。
    private func firstSuspiciousImage() -> String? {
        let patterns = DynamicFeatureList.shared.suspiciousLibraries
        let count = _dyld_image_count()
        for index in 0..<count {
            guard let raw = _dyld_get_image_name(index) else { continue }
            let image = String(cString: raw)
            let lower = image.lowercased()
            if patterns.contains(where: { lower.contains($0) }) {
                return (image as NSString).lastPathComponent
            }
        }
        return nil
    }

    /// 主可执行文件必须位于 .app 包内；读取失败时保守返回 true（不制造假阳性）。
    private func isMainExecutableInBundle() -> Bool {
        guard let executable = Bundle.main.executablePath else { return true }
        return executable.contains(".app/")
    }

    /// 检查主程序 Mach-O 是否带有 LC_CODE_SIGNATURE。
    /// 头部不可读/非 64 位时返回 true：无法判断的情况交由其他检测器，避免误报。
    private func hasCodeSignatureCommand() -> Bool {
        guard let headerPtr = _dyld_get_image_header(0) else {
            return true
        }
        guard headerPtr.pointee.magic == MH_MAGIC_64 else {
            return true
        }

        let header64 = UnsafeRawPointer(headerPtr).assumingMemoryBound(to: mach_header_64.self)
        var cmd = UnsafeRawPointer(header64).advanced(by: MemoryLayout<mach_header_64>.size)

        for _ in 0..<header64.pointee.ncmds {
            let load = cmd.assumingMemoryBound(to: load_command.self).pointee
            guard load.cmdsize >= MemoryLayout<load_command>.size else { break }
            if load.cmd == LC_CODE_SIGNATURE {
                return true
            }
            cmd = cmd.advanced(by: Int(load.cmdsize))
        }

        return false
    }
}

/// PLT 基线的可信状态，决定信号是“待确认”“版本升级”还是“拒绝建基线”。
enum BaselineTrustState: String {
    /// 基线已建立且本次比对通过。
    case trusted
    /// 首次观测，基线刚写入，本次结果不可信。
    case firstObservation
    /// SDK 版本/UUID 变化，基线已重建，本次结果不可信。
    case versionChanged
    /// 建基线时环境可疑（DYLD_INSERT_LIBRARIES / suspicious image），拒绝建基线
    case baselineRejectedSuspiciousEnv
}

/// PLT 校验结果：是否完整、被 hook 的函数、明细与基线可信状态。
struct PLTIntegrityResult {
    var isIntact: Bool
    var hookedFunctions: [String]
    var details: [String: String]
    var baselineTrustState: BaselineTrustState
}

/// PLT 基线持久化。
/// 基线以 JSON 存入 Keychain，访问级别 `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`，
/// 保证换机/重装后不会把其他设备的状态当成自己的基线。
struct PLTIntegrityGuard {
    /// 参与 PLT 基线监控的关键函数：越狱检测、反调试与 dyld 查询最常被 hook 的入口。
    private static let criticalFunctions: [String] = [
        ObfuscatedConstants.sysctlbyname,
        ObfuscatedConstants.symbolSysctl,
        ObfuscatedConstants.symbolStat,
        ObfuscatedConstants.symbolAccess,
        ObfuscatedConstants.symbolDlsym,
        ObfuscatedConstants.symbolGetenv,
        ObfuscatedConstants.denyAttachToken,
        ObfuscatedConstants.symbolDyldImageCount,
        ObfuscatedConstants.symbolDyldGetImageName,
        ObfuscatedConstants.symbolDyldGetImageHeader,
    ]

    /// 单个关键函数的基线记录。
    struct FunctionRecord {
        /// 符号名（带下划线，如 `_stat`）。
        let name: String
        /// 基线采集时的运行期绝对地址；仅作排障参考，跨重启会因 ASLR 变化。
        let address: UInt64
        /// 所属镜像的运行时基址。
        let moduleBase: UInt64
        /// 所属镜像 __TEXT 段大小。
        let moduleSize: UInt64
        /// 函数所在镜像的绝对路径（如 /usr/lib/libSystem.B.dylib）。
        /// 与 moduleBase 不同，路径不受 ASLR 影响，跨重启比较不会误报。
        let modulePath: String
    }

    private static let keychainService = "CloudPhoneRiskKit"
    // v2→v3 升级说明：v2 存了错误的 moduleBase（imageBase+sect.addr，未做 ASLR 修正），
    // 导致每次重启都 sameModule 失配；v3 改用 modulePath 校验，旧基线自然失效并重建。
    private static let keychainBaselineAccount = "plt_baseline_v3"

    /// 持久化基线：版本 token + 全部函数记录。
    private struct PersistedBaseline {
        let versionToken: String
        let records: [FunctionRecord]
    }

    /// 采集当前进程内关键函数的地址与归属镜像，作为新基线。
    /// `dlsym(-2)` 等价于 RTLD_DEFAULT，按全局符号顺序解析，与 PLT 实际绑定一致。
    static func captureBaseline() -> [FunctionRecord] {
        var records: [FunctionRecord] = []
        for name in criticalFunctions {
            guard let ptr = dlsym(UnsafeMutableRawPointer(bitPattern: -2), name) else { continue }
            var info = Dl_info()
            guard dladdr(ptr, &info) != 0, let imageHeader = info.dli_fbase else { continue }
            let (base, size) = textSegmentRange(header: imageHeader)
            let addr = UInt64(bitPattern: Int64(Int(bitPattern: ptr)))
            let path = info.dli_fname.map { String(cString: $0) } ?? ""
            records.append(FunctionRecord(name: name, address: addr, moduleBase: base, moduleSize: size, modulePath: path))
        }
        return records
    }

    /// 读取与当前版本匹配的基线；版本不一致或不存在时重新采集并持久化。
    static func captureOrLoadBaseline() -> [FunctionRecord] {
        let versionToken = runtimeVersionToken()
        if let persisted = loadPersistedBaseline(), persisted.versionToken == versionToken {
            return persisted.records
        }
        let fresh = captureBaseline()
        persistBaseline(fresh, versionToken: versionToken)
        return fresh
    }

    /// 用持久化基线校验当前进程，并给出基线可信状态。
    ///
    /// 三条不可信路径均返回 `isIntact = false`，但用 `baselineTrustState` 区分原因：
    /// 首启、版本升级、建基线时环境可疑。这样调用方既能 fail-closed，又不会把升级误当攻击。
    static func verifyWithPersistedBaseline() -> PLTIntegrityResult {
        let versionToken = runtimeVersionToken()
        guard let persisted = loadPersistedBaseline() else {
            // 首启：环境可疑时拒绝建基线，避免投毒
            let envCheck = IntegrityBaselineEnvCheck.check()
            if envCheck.isSuspicious {
                return PLTIntegrityResult(
                    isIntact: false,
                    hookedFunctions: [],
                    details: [
                        "status": "baseline_rejected_suspicious_env",
                        "reason": envCheck.reason ?? "unknown",
                        "version_token": versionToken,
                    ],
                    baselineTrustState: .baselineRejectedSuspiciousEnv
                )
            }
            let fresh = captureBaseline()
            persistBaseline(fresh, versionToken: versionToken)
            return PLTIntegrityResult(
                isIntact: false,  // 不可信窗口：无法断言完整性
                hookedFunctions: [],
                details: [
                    "status": "baseline_established",
                    "version_token": versionToken,
                ],
                baselineTrustState: .firstObservation
            )
        }

        if persisted.versionToken != versionToken {
            // 升级：环境可疑时拒绝建基线
            let envCheck = IntegrityBaselineEnvCheck.check()
            if envCheck.isSuspicious {
                return PLTIntegrityResult(
                    isIntact: false,
                    hookedFunctions: [],
                    details: [
                        "status": "baseline_rejected_suspicious_env",
                        "reason": envCheck.reason ?? "unknown",
                        "previous_version_token": persisted.versionToken,
                        "version_token": versionToken,
                    ],
                    baselineTrustState: .baselineRejectedSuspiciousEnv
                )
            }
            let fresh = captureBaseline()
            persistBaseline(fresh, versionToken: versionToken)
            return PLTIntegrityResult(
                isIntact: false,  // 不可信窗口：无法断言完整性
                hookedFunctions: [],
                details: [
                    "status": "version_changed",
                    "previous_version_token": persisted.versionToken,
                    "version_token": versionToken,
                ],
                baselineTrustState: .versionChanged
            )
        }

        return verify(baseline: persisted.records)
    }

    /// 从 Keychain 读取并反序列化基线；JSON 结构不合法时视为无基线。
    private static func loadPersistedBaseline() -> PersistedBaseline? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainBaselineAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let versionToken = json["versionToken"] as? String,
              let rawRecords = json["records"] as? [[String: Any]] else {
            return nil
        }
        let records = rawRecords.compactMap { dict -> FunctionRecord? in
            guard let name = dict["name"] as? String,
                  let addr = (dict["address"] as? NSNumber)?.uint64Value,
                  let base = (dict["moduleBase"] as? NSNumber)?.uint64Value,
                  let size = (dict["moduleSize"] as? NSNumber)?.uint64Value else { return nil }
            let path = dict["modulePath"] as? String ?? ""
            return FunctionRecord(name: name, address: addr, moduleBase: base, moduleSize: size, modulePath: path)
        }
        return PersistedBaseline(versionToken: versionToken, records: records)
    }

    /// 序列化并写入基线；update 失败且条目不存在时回退 add，其他错误静默忽略（非关键路径）。
    private static func persistBaseline(_ records: [FunctionRecord], versionToken: String) {
        let rawRecords: [[String: Any]] = records.map { [
            "name": $0.name,
            "address": $0.address,
            "moduleBase": $0.moduleBase,
            "moduleSize": $0.moduleSize,
            "modulePath": $0.modulePath,
        ] }
        let json: [String: Any] = [
            "versionToken": versionToken,
            "records": rawRecords,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: json) else { return }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainBaselineAccount,
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var addQuery = query
            addQuery[kSecValueData as String] = data
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            SecItemAdd(addQuery as CFDictionary, nil)
        }
    }

    /// 逐条比对各关键函数的当前归属与基线。
    /// 判定条件：符号仍可解析、归属镜像路径一致、地址落在该镜像 __TEXT.__text 范围内。
    /// 任一不满足即记入 hookedFunctions，并保留路径差异用于排障。
    static func verify(baseline: [FunctionRecord]) -> PLTIntegrityResult {
        var hooked: [String] = []
        var details: [String: String] = [:]
        for record in baseline {
            guard let ptr = dlsym(UnsafeMutableRawPointer(bitPattern: -2), record.name) else {
                hooked.append(record.name)
                details[record.name] = "dlsym_failed"
                continue
            }
            let currentAddr = UInt64(bitPattern: Int64(Int(bitPattern: ptr)))
            var info = Dl_info()
            guard dladdr(ptr, &info) != 0, let imageHeader = info.dli_fbase else {
                hooked.append(record.name)
                details[record.name] = "dladdr_failed"
                continue
            }
            // 按镜像路径比较（不受 ASLR 影响）。moduleBase 是 __text 段的运行时绝对地址，
            // 每次重启都会变化，不适合跨会话比较。
            let currentPath = info.dli_fname.map { String(cString: $0) } ?? ""
            let sameModule = !record.modulePath.isEmpty && currentPath == record.modulePath
            let (base, size) = textSegmentRange(header: imageHeader)
            // 地址必须落在当前 __TEXT.__text 区间内，防止符号被重定向到注入镜像。
            let inRange = size > 0 && currentAddr >= base && currentAddr < base + size
            if !inRange || !sameModule {
                hooked.append(record.name)
                details[record.name] = "addr=0x\(String(currentAddr, radix: 16)) expected_path=\(record.modulePath) current_path=\(currentPath)"
            }
        }
        return PLTIntegrityResult(
            isIntact: hooked.isEmpty,
            hookedFunctions: hooked,
            details: details,
            baselineTrustState: .trusted
        )
    }

    /// 计算某镜像 __TEXT.__text 的运行期地址区间。
    /// 返回 (0, 0) 表示镜像格式异常或找不到该段，调用方应据此判为不可验证。
    private static func textSegmentRange(header: UnsafeRawPointer) -> (base: UInt64, size: UInt64) {
        let ptr = header.assumingMemoryBound(to: mach_header_64.self)
        guard ptr.pointee.magic == MH_MAGIC_64 else { return (0, 0) }
        // imageBase 是 Mach-O 头部的运行时地址（ASLR 后即 __TEXT 起点）。
        let imageBase = UInt64(bitPattern: Int64(Int(bitPattern: header)))
        var cmd = UnsafeRawPointer(ptr).advanced(by: MemoryLayout<mach_header_64>.size)
        for _ in 0..<ptr.pointee.ncmds {
            let load = cmd.assumingMemoryBound(to: load_command.self).pointee
            guard load.cmdsize >= MemoryLayout<load_command>.size else { break }
            if load.cmd == LC_SEGMENT_64 {
                let seg = cmd.assumingMemoryBound(to: segment_command_64.self).pointee
                if tupleStringEquals(seg.segname, "__TEXT") {
                    // slide = 运行时 __TEXT 基址 - 链接期 __TEXT vmaddr。
                    // dyld 共享缓存中的系统库 seg.vmaddr 是很大的绝对值（如 0x1920000xx），
                    // 不能直接用 (imageBase + sect.addr)，否则会把运行时地址重复叠加。
                    // 正确公式：sect.addr + slide = sect.addr + (imageBase - seg.vmaddr)。
                    let slide = imageBase &- seg.vmaddr
                    var sect = cmd.advanced(by: MemoryLayout<segment_command_64>.size)
                        .assumingMemoryBound(to: section_64.self)
                    for _ in 0..<seg.nsects {
                        if tupleStringEquals(sect.pointee.sectname, "__text") {
                            return (sect.pointee.addr &+ slide, sect.pointee.size)
                        }
                        sect = sect.advanced(by: 1)
                    }
                }
            }
            cmd = cmd.advanced(by: Int(load.cmdsize))
        }
        return (0, 0)
    }

    /// 版本 token = SDK 版本号 + 当前二进制 UUID，用于区分正常升级与 hook 后的符号漂移。
    private static func runtimeVersionToken() -> String {
        if let uuid = currentSDKBinaryUUID() {
            return "\(Version.current):\(uuid)"
        }
        return "\(Version.current):unknown"
    }

    /// 读取 SDK 镜像的 LC_UUID；找不到镜像或无该命令时返回 nil。
    private static func currentSDKBinaryUUID() -> String? {
        let count = _dyld_image_count()
        for index in 0..<count {
            guard let rawPath = _dyld_get_image_name(index) else { continue }
            let path = String(cString: rawPath).lowercased()
            guard path.contains("cloudphoneriskkit"),
                  let header = _dyld_get_image_header(index)
            else {
                continue
            }

            let headerPtr = UnsafeRawPointer(header).assumingMemoryBound(to: mach_header_64.self)
            guard headerPtr.pointee.magic == MH_MAGIC_64 else { continue }

            var cmd = UnsafeRawPointer(headerPtr).advanced(by: MemoryLayout<mach_header_64>.size)
            for _ in 0..<headerPtr.pointee.ncmds {
                let load = cmd.assumingMemoryBound(to: load_command.self).pointee
                guard load.cmdsize >= MemoryLayout<load_command>.size else { break }
                if load.cmd == LC_UUID {
                    let uuidCmd = cmd.assumingMemoryBound(to: uuid_command.self).pointee
                    let bytes = withUnsafeBytes(of: uuidCmd.uuid) { Array($0) }
                    return bytes.map { String(format: "%02x", $0) }.joined()
                }
                cmd = cmd.advanced(by: Int(load.cmdsize))
            }
        }
        return nil
    }
}

/// 比较 Mach-O 段名/节名这类固定长度 C 字符数组与目标字符串。
/// 使用 strncmp 限定在数组长度内，避免段名未以 NUL 结尾时越界读取。
private func tupleStringEquals<T>(_ tuple: T, _ target: String) -> Bool {
    withUnsafePointer(to: tuple) { ptr in
        ptr.withMemoryRebound(to: CChar.self, capacity: MemoryLayout<T>.size) { cPtr in
            strncmp(cPtr, target, MemoryLayout<T>.size) == 0
        }
    }
}

/// 信号输出：把 PLT 校验结果映射为带状态与权重提示的 `RiskSignal`。
extension PLTIntegrityGuard {
    /// 把 PLT 校验结果转换为 `RiskSignal`。
    /// 优先级：明确的 hook 证据 > 拒绝建基线 > 版本变化 > 首启 > 干净。
    /// hook 信号的 score 为 0 但 `weightHint` 92 且 state 为 tampered，交由加权层决定最终分值。
    static func asSignals(result: PLTIntegrityResult) -> [RiskSignal] {
        if !result.hookedFunctions.isEmpty {
            return [
                RiskSignal(
                    id: "plt_integrity_tampered",
                    category: "integrity",
                    score: 0,
                    evidence: ["hooked": result.hookedFunctions.joined(separator: ","), "details": (try? JSON.stringify(result.details)) ?? "{}"],
                    state: .tampered,
                    layer: 2,
                    weightHint: 92
                )
            ]
        }
        switch result.baselineTrustState {
        case .trusted:
            break
        case .firstObservation:
            return [
                RiskSignal(
                    id: "plt_integrity_baseline_pending",
                    category: "integrity",
                    score: 8,
                    evidence: result.details,
                    state: .soft(confidence: 0.55),
                    layer: 2,
                    weightHint: 45
                )
            ]
        case .versionChanged:
            return [
                RiskSignal(
                    id: "plt_integrity_version_changed",
                    category: "integrity",
                    score: 12,
                    evidence: result.details,
                    state: .soft(confidence: 0.72),
                    layer: 2,
                    weightHint: 58
                )
            ]
        case .baselineRejectedSuspiciousEnv:
            return [
                RiskSignal(
                    id: "plt_integrity_baseline_rejected_suspicious_env",
                    category: "integrity",
                    score: 55,
                    evidence: result.details,
                    state: .tampered,
                    layer: 2,
                    weightHint: 88
                )
            ]
        }
        return [
            RiskSignal(
                id: "plt_integrity_ok",
                category: "integrity",
                score: 0,
                evidence: [:],
                state: .hard(detected: false),
                layer: 2,
                weightHint: 0
            )
        ]
    }
}
