// 混淆字符串表：集中存放越狱 / Frida / 注入 / 反调试相关的敏感字面量。
// 明文特征会留在 Mach-O 的 __TEXT/__cstring 中，攻击者用 strings 即可定位检测逻辑，
// 因此条目在源码中以 XOR / ROT13 / 逆序 / Caesar / Base64 形式保存，运行时惰性解码；
// 属性名保持可读，仅隐藏真正敏感的取值。
import Foundation

/// 轻量字符串解码器集合。
/// - 全部为纯函数、无共享状态，可在任意线程调用。
/// - 仅在访问 `ObfuscatedConstants` 的计算属性时执行，结果不缓存，减少明文驻留时间。
enum StringDeobfuscator {
    /// 单字节 XOR 解码：逐字节与 `key` 异或后按 UTF-8 还原。
    /// 每个条目使用不同 key，阻止对整个表做一次异或批量还原。
    static func xorDecode(_ bytes: [UInt8], key: UInt8) -> String {
        let decoded = bytes.map { $0 ^ key }
        // 解码失败时退化为空串，调用方按“无特征”处理，避免解码错误导致崩溃。
        return String(bytes: decoded, encoding: .utf8) ?? ""
    }

    /// 字母 ROT13：仅旋转 ASCII 字母，数字、标点保持不变。
    static func rot13(_ input: String) -> String {
        return String(input.unicodeScalars.map { scalar in
            let v = scalar.value
            // 分大小写区间旋转，非字母标量原样透传。
            switch v {
            case 65...90: return Character(Unicode.Scalar((v - 65 + 13) % 26 + 65)!)
            case 97...122: return Character(Unicode.Scalar((v - 97 + 13) % 26 + 97)!)
            default: return Character(scalar)
            }
        })
    }

    /// 字节逆序解码：反向书写使 `strings` 无法直接命中敏感词。
    static func reverseBytes(_ bytes: [UInt8]) -> String {
        return String(bytes: bytes.reversed(), encoding: .utf8) ?? ""
    }

    /// Caesar 位移解码：`shift` 为编码时的位移量，这里反向还原字母区间。
    static func caesarShift(_ bytes: [UInt8], shift: Int) -> String {
        // 归一化到 0...25，保证负数或超过 26 的位移量也能正确还原。
        let s = (shift % 26 + 26) % 26
        let decoded = bytes.map { b -> UInt8 in
            switch b {
            case 65...90: return UInt8((Int(b) - 65 - s + 26) % 26 + 65)
            case 97...122: return UInt8((Int(b) - 97 - s + 26) % 26 + 97)
            default: return b
            }
        }
        return String(bytes: decoded, encoding: .utf8) ?? ""
    }

    /// 标准 Base64 解码；非法输入返回空串（fail-safe，不抛错）。
    static func base64Decode(_ base64: String) -> String {
        guard let data = Data(base64Encoded: base64),
              let s = String(data: data, encoding: .utf8) else { return "" }
        return s
    }

    /// 多阶段拼接：把拆散的片段按顺序还原成一个敏感词。
    /// - 单个片段不足以被静态扫描识别，`separator` 用于需要中间分隔符的场景。
    static func multiStage(_ stages: [() -> String], separator: String = "") -> String {
        return stages.map { $0() }.joined(separator: separator)
    }
}

/// 运行时解码后的敏感常量集合。
/// - 表结构：每个计算属性对应一条（或一组）检测特征，属性名是调用方使用的稳定语义键。
/// - 编码方式按条目选择：XOR、字母 ROT13、字节逆序、Caesar，路径类多用 Base64。
/// - 每次访问都会重新解码（无缓存），需要时再读即可，避免明文长期驻留。
/// - signal id / method prefix 参与协议或与服务端约定，改名须同步 C 层与后端。
enum ObfuscatedConstants {
    // MARK: - 设备 / 模拟器特征

    /// Apple 半虚拟化设备标识（云手机、模拟器常见），多段拼接拆散特征词。
    static var appleParavirtualDevice: String {
        StringDeobfuscator.multiStage([
            { StringDeobfuscator.xorDecode([0x03, 0x32, 0x32, 0x2e, 0x27, 0x62, 0x12, 0x23, 0x30, 0x23], key: 0x42) },
            { StringDeobfuscator.rot13("iveghny ") },
            { StringDeobfuscator.reverseBytes([0x65, 0x63, 0x69, 0x76, 0x65, 0x64]) },
        ])
    }

    /// 软件渲染器名（模拟器/云手机常见的 llvmpipe），Caesar 编码。
    static var llvmpipe: String {
        StringDeobfuscator.caesarShift([0x73, 0x73, 0x63, 0x74, 0x77, 0x70, 0x77, 0x6c], shift: 7)
    }

    /// 设备名伪装特征 "iphone99"，ROT13 编码。
    static var iphone99Pattern: String {
        StringDeobfuscator.rot13("vcubar99")
    }

    /// 云手机厂商的虚拟化主机/域名特征（"vresearch"），XOR 编码。
    static var vresearchPattern: String {
        StringDeobfuscator.xorDecode([0x41, 0x55, 0x52, 0x44, 0x52, 0x56, 0x55, 0x42, 0x5f], key: 0x37)
    }

    /// 半虚拟化标识（"paravirtual"），字节逆序存储。
    static var paravirtualPattern: String {
        StringDeobfuscator.reverseBytes([0x6c, 0x61, 0x75, 0x74, 0x69, 0x72, 0x76, 0x61, 0x72, 0x61, 0x70])
    }

    // MARK: - Frida / 注入相关路径与标记

    /// Frida server 常见安装路径表。
    /// 整表以 Base64 / XOR 存储，避免 `strings` 一次扫出全部注入工具路径。
    static var fridaServerPaths: [String] {
        [
            StringDeobfuscator.base64Decode("L3Vzci9zYmluL2ZyaWRhLXNlcnZlcg=="),
            StringDeobfuscator.base64Decode("L3Vzci9iaW4vZnJpZGEtc2VydmVy"),
            StringDeobfuscator.xorDecode([0x16, 0x16, 0x15, 0x01, 0x17, 0x17, 0x06, 0x00, 0x17, 0x14, 0x15, 0x06, 0x00, 0x17, 0x14, 0x15, 0x06, 0x15, 0x15, 0x14, 0x01, 0x15], key: 0x65),
            StringDeobfuscator.base64Decode("L3Zhci9qYi91c3Ivc2Jpbi9mcmlkYS1zZXJ2ZXI="),
            StringDeobfuscator.base64Decode("L3Zhci9qYi91c3IvYmluL2ZyaWRhLXNlcnZlcg=="),
        ]
    }

    /// Cydia 安装目录路径。
    static var cydiaPath: String {
        StringDeobfuscator.base64Decode("L0FwcGxpY2F0aW9ucy9DeWRpYS5hcHA=")
    }

    /// MobileSubstrate 库目录路径。
    static var substratePath: String {
        StringDeobfuscator.base64Decode("L0xpYnJhcnkvTW9iaWxlU3Vic3RyYXRl")
    }

    /// 敏感 libc 符号名（Caesar 编码），供 dlsym / 栈完整性检查使用。
    static var sysctlbyname: String {
        StringDeobfuscator.caesarShift([0x78, 0x64, 0x79, 0x68, 0x79, 0x71, 0x67, 0x64, 0x66, 0x73, 0x72, 0x6a], shift: 21)
    }

    /// 动态加载入口符号名，避免字符串扫描直接定位注入点。
    static var dlopen: String {
        StringDeobfuscator.caesarShift([0x67, 0x6f, 0x72, 0x73, 0x68, 0x71], shift: 23)
    }

    /// 反调试 / deny-attach 相关令牌（Caesar 编码），用于调试器与父进程相关性检查。
    static var denyAttachToken: String {
        StringDeobfuscator.caesarShift([0x61, 0x65, 0x63, 0x6c, 0x6e, 0x70], shift: 15)
    }

    /// Frida 运行期标记（线程名、模块名、gadget 名等）。
    /// 扫描内存/镜像时与这些子串匹配；表内混合使用多种编码，增加静态提取成本。
    static var fridaMarkers: [String] {
        [
            StringDeobfuscator.xorDecode([0x43, 0x57, 0x6c, 0x61, 0x44], key: 0x25),
            StringDeobfuscator.rot13("sevqn-ntrag"),
            StringDeobfuscator.reverseBytes([0x72, 0x65, 0x76, 0x72, 0x65, 0x73, 0x2d, 0x61, 0x74, 0x69, 0x72, 0x64, 0x66]),
            StringDeobfuscator.caesarShift([0x6e, 0x68, 0x6b, 0x6e, 0x6c, 0x61], shift: 7),
            StringDeobfuscator.xorDecode([0x43, 0x55, 0x4d], key: 0x24),
            StringDeobfuscator.multiStage([
                { StringDeobfuscator.xorDecode([0x43, 0x55, 0x4d], key: 0x24) },
                { StringDeobfuscator.rot13("-wf-ybbc") },
            ], separator: ""),
        ]
    }

    /// 常见 hook 框架名（substrate / substitute / libhooker 等），混合编码存储。
    static var hookFrameworkPatterns: [String] {
        [
            StringDeobfuscator.reverseBytes([0x65, 0x74, 0x61, 0x72, 0x74, 0x73, 0x62, 0x75, 0x73]),
            StringDeobfuscator.xorDecode([0x29, 0x2c, 0x27, 0x3d, 0x2a, 0x2a, 0x2e, 0x20, 0x37], key: 0x45),
            StringDeobfuscator.caesarShift([0x6c, 0x73, 0x73, 0x6c, 0x72, 0x70, 0x61], shift: 7),
            StringDeobfuscator.rot13("fhogfvghr"),
        ]
    }

    // MARK: - 关键词与端口

    /// 基础关键词 "frida"；同名变体（hook/jailbreak/tamper 等）结构相同，均用 Base64 隐藏。
    static var keywordFrida: String {
        StringDeobfuscator.base64Decode("ZnJpZGE=")
    }

    static var keywordHook: String {
        StringDeobfuscator.base64Decode("aG9vaw==")
    }

    static var keywordJailbreak: String {
        StringDeobfuscator.base64Decode("amFpbGJyZWFr")
    }

    static var keywordTamper: String {
        StringDeobfuscator.base64Decode("dGFtcGVy")
    }

    static var keywordRiskScore: String {
        StringDeobfuscator.base64Decode("cmlza19zY29yZQ==")
    }

    static var keywordWatchdog: String {
        StringDeobfuscator.base64Decode("d2F0Y2hkb2c=")
    }

    /// `debugger:` method prefix for `DebuggerDetector` (avoid raw prefix in TEXT).
    static var methodPrefixDebugger: String {
        StringDeobfuscator.base64Decode("ZGVidWdnZXI6")
    }

    /// Debugger / Frida-adjacent ports checked by `DebuggerDetector`.
    /// 表中存的是 `端口 ^ 0x5A5A`；TCP 端口是 16 位，所以用 UInt16 掩码即可。
    static var debuggerPorts: [Int] {
        let key: UInt16 = 0x5A5A
        let encoded: [UInt16] = [0x6A63, 0x5373, 0x33F8, 0x33F9, 0x07D0]
        return encoded.map { Int($0 ^ key) }
    }

    /// Suspicious TCP ports reserved for Frida/socket-based detectors.
    static var suspiciousRuntimePorts: [Int] {
        let key: UInt16 = 0x5A5A  // 与 debuggerPorts 共用同一掩码键
        let encoded: [UInt16] = [0x33F8, 0x33F9, 0x4B06]
        return encoded.map { Int($0 ^ key) }
    }

    /// Offline fallback: commonly seen non-default Frida / gadget listen ports (merged + deduped in `DynamicFeatureList`).
    static var suspiciousPortsBuiltinFallback: [Int] {
        let key: UInt16 = 0x5A5A
        // 每个元素都是“端口 ^ 0x5A5A”，防止端口号以明文常量出现在二进制中。
        let encoded: [UInt16] = [
            0x33FB, 0x33FE, 0x78E2, 0x79D8, 0x5F63, 0x2033, 0xFB9C, 0x4B06,
            0xE834, 0x990A, 0x8E6B, 0x8359, 0xA7B2, 0x9A5A, 0x7AA1, 0x20ED,
            0x3075, 0x7D55,
        ]
        return encoded.map { Int($0 ^ key) }
    }

    /// `fish` + `hook` stack needle for `CapabilityProbeEngine` (not a literal `fish` prefix in source).
    static var hookFrameworkFishhookToken: String {
        StringDeobfuscator.xorDecode([0x36, 0x3d, 0x3a, 0x27], key: 0x55)
    }

    /// Honeypot 填充行：无意义随机字节（运行时生成），永不代表真实凭据。
    /// 旧版此处写了形似真实凭据的字符串（“AES-256-Key-…”等），若被内存
    /// 扫描工具 / 崩溃转储捕获，会被误认为真实密钥外泄。蜜罐只靠
    /// PROT_NONE 页面触碰触发 SIGBUS 探测，从不读取/比对内容，
    /// 因此填充内容可以是任意无意义数据。
    static var honeypotBaitRows: [[String]] {
        (0..<3).map { _ in
            (0..<2).map { _ in
                String((0..<24).map { _ in "abcdefghijklmnopqrstuvwxyz0123456789".randomElement()! })
            }
        }
    }

    // MARK: - 多路径共识与调用栈特征

    /// Critical jailbreak paths used by multi-path consensus detectors.
    static var jailbreakConsensusCriticalPaths: [String] {
        [
            StringDeobfuscator.base64Decode("L0FwcGxpY2F0aW9ucy9DeWRpYS5hcHA="),
            StringDeobfuscator.base64Decode("L0FwcGxpY2F0aW9ucy9TaWxlby5hcHA="),
            StringDeobfuscator.base64Decode("L3Zhci9qYg=="),
            StringDeobfuscator.base64Decode("L0xpYnJhcnkvTW9iaWxlU3Vic3RyYXRlL01vYmlsZVN1YnN0cmF0ZS5keWxpYg=="),
        ]
    }

    /// Call-stack substring needles for `RuntimeIntegrityValidator` (stack frame scan).
    /// 调用栈里出现这些框架名，说明注入代码正在执行，比“文件存在”证据更强。
    static var runtimeIntegrityStackSuspiciousNeedles: [String] {
        [
            StringDeobfuscator.base64Decode("TW9iaWxlU3Vic3RyYXRl"),
            StringDeobfuscator.base64Decode("U3Vic3RyYXRlTG9hZGVy"),
            StringDeobfuscator.base64Decode("c3Vic3RpdHV0ZQ=="),
            StringDeobfuscator.base64Decode("RnJpZGFHYWRnZXQ="),
            StringDeobfuscator.base64Decode("ZnJpZGEtYWdlbnQ="),
            StringDeobfuscator.base64Decode("Y3ljcmlwdA=="),
            StringDeobfuscator.base64Decode("U1NMS2lsbFN3aXRjaA=="),
            StringDeobfuscator.base64Decode("bGliUmV2ZWFs"),
            StringDeobfuscator.base64Decode("U2hhZG93LmR5bGli"),
            StringDeobfuscator.base64Decode("VHdlYWtJbmplY3Q="),
        ]
    }

    static var keywordTaskPort: String {
        StringDeobfuscator.base64Decode("dGFza19wb3J0")
    }

    static var keywordVMRemap: String {
        StringDeobfuscator.base64Decode("dm1fcmVtYXA=")
    }

    static var keywordTaskForPid: String {
        StringDeobfuscator.base64Decode("dGFza19mb3JfcGlk")
    }

    // MARK: - Signal / Detector ID（协议稳定值）

    /// Signal/Detector ID 全表：这些字符串会进入上报 JSON 与本地策略。
    /// 必须与服务端约定保持一致；此处在源码中以 Base64 保存，避免明文 ID 被直接检索。
    static var signalJailbreak: String {
        StringDeobfuscator.base64Decode("amFpbGJyZWFr")
    }

    static var signalHookDetected: String {
        StringDeobfuscator.base64Decode("aG9va19kZXRlY3RlZA==")
    }

    static var signalAntiDebugWatchdogAnomaly: String {
        StringDeobfuscator.base64Decode("YW50aV9kZWJ1Z193YXRjaGRvZ19hbm9tYWx5")
    }

    static var signalAntiDebugWatchdogTraced: String {
        StringDeobfuscator.base64Decode("YW50aV9kZWJ1Z193YXRjaGRvZ190cmFjZWQ=")
    }

    static var signalAntiDebugWatchdogDenyAttachFailed: String {
        StringDeobfuscator.base64Decode("YW50aV9kZWJ1Z193YXRjaGRvZ19kZW55X2F0dGFjaF9mYWlsZWQ=")
    }

    static var signalAntiDebugWatchdogExceptionPort: String {
        StringDeobfuscator.base64Decode("YW50aV9kZWJ1Z193YXRjaGRvZ19leGNlcHRpb25fcG9ydA==")
    }

    static var signalAntiDebugWatchdogExceptionQuery: String {
        StringDeobfuscator.base64Decode("YW50aV9kZWJ1Z193YXRjaGRvZ19leGNlcHRpb25fcXVlcnk=")
    }

    /// Protocol-stable `SignalID` values (decoded at runtime; avoid plaintext in `SignalID` enum).
    static var signalAntiDebugWatchdogDyldInjection: String {
        StringDeobfuscator.base64Decode("YW50aV9kZWJ1Z193YXRjaGRvZ19keWxkX2luamVjdGlvbg==")
    }

    static var signalAntiDebugWatchdogDenyAttachVerify: String {
        StringDeobfuscator.base64Decode("YW50aV9kZWJ1Z193YXRjaGRvZ19kZW55X2F0dGFjaF92ZXJpZnk=")
    }

    static var signalAntiDebugWatchdogAMFICsFlags: String {
        StringDeobfuscator.base64Decode("YW50aV9kZWJ1Z193YXRjaGRvZ19hbWZpX2NzX2ZsYWdz")
    }

    static var signalAntiDebugWatchdogGetTaskAllow: String {
        StringDeobfuscator.base64Decode("YW50aV9kZWJ1Z193YXRjaGRvZ19nZXRfdGFza19hbGxvdw==")
    }

    /// Watchdog memcmp prologue drift on objc_msgSend / libdyld (runtime Frida surface).
    static var signalAntiDebugWatchdogCriticalHookSurface: String {
        StringDeobfuscator.base64Decode("YW50aV9kZWJ1Z193YXRjaGRvZ19jcml0aWNhbF9ob29rX3N1cmZhY2U=")
    }

    static var signalAntiDebugWatchdogPacThreadEntry: String {
        StringDeobfuscator.base64Decode("YW50aV9kZWJ1Z193YXRjaGRvZ19wYWNfdGhyZWFkX2VudHJ5")
    }

    static var signalAntiDebugWatchdogVmImageLayoutDrift: String {
        StringDeobfuscator.base64Decode("YW50aV9kZWJ1Z193YXRjaGRvZ192bV9pbWFnZV9sYXlvdXRfZHJpZnQ=")
    }

    static var signalWhiteboxPrfProbeDegraded: String {
        StringDeobfuscator.base64Decode("d2hpdGVib3hfcHJmX3Byb2JlX2RlZ3JhZGVk")
    }

    static var signalSoftwareBreakpointDetected: String {
        StringDeobfuscator.base64Decode("c29mdHdhcmVfYnJlYWtwb2ludF9kZXRlY3RlZA==")
    }

    static var signalExceptionDeliveryTimeout: String {
        StringDeobfuscator.base64Decode("ZXhjZXB0aW9uX2RlbGl2ZXJ5X3RpbWVvdXQ=")
    }

    /// Protocol-stable `SignalID` for CRiskCore libc fallback when direct syscalls are unavailable.
    static var signalLibcDirectSyscallFallback: String {
        StringDeobfuscator.base64Decode("bGliY19kaXJlY3Rfc3lzY2FsbF9mYWxsYmFjaw==")
    }

    /// Evidence `mechanism` value for libc / arc4random fallback (avoid plaintext in binary).
    static var evidenceMechanismLibcDirectSyscallFallback: String {
        StringDeobfuscator.base64Decode(
            "bGliY19vcl9hcmM0X2ZhbGxiYWNrX2FmdGVyX2RpcmVjdF9zeXNjYWxsX3VuYXZhaWxhYmxl"
        )
    }

    static var signalDebuggerDetected: String {
        StringDeobfuscator.base64Decode("ZGVidWdnZXJfZGV0ZWN0ZWQ=")
    }

    static var signalCsopsDebugged: String {
        StringDeobfuscator.base64Decode("Y3NvcHNfZGVidWdnZWQ=")
    }

    static var signalHardwareBreakpointDetected: String {
        StringDeobfuscator.base64Decode("aGFyZHdhcmVfYnJlYWtwb2ludF9kZXRlY3RlZA==")
    }

    static var signalSignalProbeDebugger: String {
        StringDeobfuscator.base64Decode("c2lnbmFsX3Byb2JlX2RlYnVnZ2Vy")
    }

    static var signalAntidebugPlanEscalated: String {
        StringDeobfuscator.base64Decode("YW50aWRlYnVnX3BsYW5fZXNjYWxhdGVk")
    }

    static var signalStalkerJitRWX: String {
        StringDeobfuscator.base64Decode("c3RhbGtlcl9qaXRfcnd4")
    }

    static var signalRwxJitCoexistence: String {
        StringDeobfuscator.base64Decode("cnd4X2ppdF9jb2V4aXN0ZW5jZQ==")
    }

    static var signalMultipathCrossInconsistency: String {
        StringDeobfuscator.base64Decode("bXVsdGlwYXRoX2Nyb3NzX2luY29uc2lzdGVuY3k=")
    }

    static var signalPacDisabled: String {
        StringDeobfuscator.base64Decode("cGFjX2Rpc2FibGVk")
    }

    static var signalPacPointerInvalid: String {
        StringDeobfuscator.base64Decode("cGFjX3BvaW50ZXJfaW52YWxpZA==")
    }

    static var signalDtraceKdebugActivity: String {
        StringDeobfuscator.base64Decode("ZHRyYWNlX2tkZWJ1Z19hY3Rpdml0eQ==")
    }

    static var signalLldbJitSmallRWX: String {
        StringDeobfuscator.base64Decode("bGxkYl9qaXRfc21hbGxfcnd4")
    }

    static var signalDyldSharedCacheIntegrity: String {
        StringDeobfuscator.base64Decode("ZHlsZF9zaGFyZWRfY2FjaGVfaW50ZWdyaXR5")
    }

    static var signalDyldSharedCacheUUIDMismatch: String {
        StringDeobfuscator.base64Decode("ZHlsZF9zaGFyZWRfY2FjaGVfdXVpZF9taXNtYXRjaA==")
    }

    static var signalDyldSharedCacheSlideMismatch: String {
        StringDeobfuscator.base64Decode("ZHlsZF9zaGFyZWRfY2FjaGVfc2xpZGVfbWlzbWF0Y2g=")
    }

    static var signalDyldSharedCacheSymbolMismatch: String {
        StringDeobfuscator.base64Decode("ZHlsZF9zaGFyZWRfY2FjaGVfc3ltYm9sX21pc21hdGNo")
    }

    static var signalDylibInjectImageCountLow: String {
        StringDeobfuscator.base64Decode("ZHlsaWJfaW5qZWN0X2ltYWdlX2NvdW50X2xvdw==")
    }

    static var signalIfaceSpawnPathDivergence: String {
        StringDeobfuscator.base64Decode("aWZhY2Vfc3Bhd25fcGF0aF9kaXZlcmdlbmNl")
    }

    static var signalFridaModuleDetected: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfbW9kdWxlX2RldGVjdGVk")
    }

    static var signalFridaModuleImage: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfbW9kdWxlX2ltYWdl")
    }

    static var signalFridaModuleSection: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfbW9kdWxlX3NlY3Rpb24=")
    }

    static var signalFridaModuleString: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfbW9kdWxlX3N0cmluZw==")
    }

    static var signalVMRemapSharedAnonymous: String {
        StringDeobfuscator.base64Decode("dm1fcmVtYXBfc2hhcmVkX2Fub255bW91c19leGVj")
    }

    static var signalVMRemapImageAlias: String {
        StringDeobfuscator.base64Decode("dm1fcmVtYXBfaW1hZ2VfYWxpYXM=")
    }

    static var signalTaskPortExceptionHijack: String {
        StringDeobfuscator.base64Decode("dGFza19wb3J0X2V4Y2VwdGlvbl9oaWphY2s=")
    }

    static var signalTaskPortRightsAnomaly: String {
        StringDeobfuscator.base64Decode("dGFza19wb3J0X3JpZ2h0c19hbm9tYWx5")
    }

    static var detectorIDTaskPortAudit: String {
        StringDeobfuscator.base64Decode("dGFza19wb3J0X2F1ZGl0")
    }

    static var detectorIDVMRemap: String {
        keywordVMRemap
    }

    static var detectorIDAntiDebugWatchdog: String {
        StringDeobfuscator.base64Decode("YW50aV9kZWJ1Z193YXRjaGRvZw==")
    }

    static var detectorIDAntiTampering: String {
        StringDeobfuscator.base64Decode("YW50aV90YW1wZXJpbmc=")
    }

    static var detectorIDDebugger: String {
        StringDeobfuscator.base64Decode("ZGVidWdnZXI=")
    }

    static var detectorIDObjCSwizzle: String {
        StringDeobfuscator.base64Decode("b2JqY19zd2l6emxl")
    }

    static var detectorIDFridaModule: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfbW9kdWxl")
    }

    static var detectorIDFridaThread: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfdGhyZWFk")
    }

    static var detectorIDFridaHeap: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfaGVhcA==")
    }

    static var detectorIDFridaSocket: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfc29ja2V0")
    }

    static var detectorScopeAntiTamperingProviderCoreChecks: String {
        StringDeobfuscator.base64Decode("YW50aV90YW1wZXJpbmdfcHJvdmlkZXIuY29yZV9jaGVja3M=")
    }

    static var detectorGroupJailbreak: String {
        signalJailbreak
    }

    static var overlapGroupHook: String {
        keywordHook
    }

    static var overlapGroupFrida: String {
        keywordFrida
    }

    static var overlapGroupJailbreakFile: String {
        StringDeobfuscator.base64Decode("amFpbGJyZWFrX2ZpbGU=")
    }

    // MARK: - Method 前缀（证据归类）

    /// method 前缀用于把同类证据聚合到同一个 signal；冒号是前缀与具体位置的天然分隔符。
    static var methodPrefixMultipartHook: String {
        StringDeobfuscator.base64Decode("bXVsdGlwYXJ0X2hvb2s6")
    }

    static var signalMultipathHookDetected: String {
        StringDeobfuscator.base64Decode("bXVsdGlwYXRoX2hvb2tfZGV0ZWN0ZWQ=")
    }

    static var signalMultipathJailbreakFile: String {
        StringDeobfuscator.base64Decode("bXVsdGlwYXRoX2phaWxicmVha19maWxl")
    }

    static var signalMemoryProtectionTampered: String {
        StringDeobfuscator.base64Decode("bWVtb3J5X3Byb3RlY3Rpb25fdGFtcGVyZWQ=")
    }

    static var signalMemoryProtectionSemanticBypass: String {
        StringDeobfuscator.base64Decode("bWVtb3J5X3Byb3RlY3Rpb25fc2VtYW50aWNfYnlwYXNz")
    }

    static var methodPrefixMemoryHook: String {
        StringDeobfuscator.base64Decode("bWVtb3J5X2hvb2s6")
    }

    static var methodPrefixMemoryInline: String {
        StringDeobfuscator.base64Decode("bWVtb3J5X2lubGluZTo=")
    }

    static var signalPrefixHook: String {
        StringDeobfuscator.base64Decode("aG9va18=")
    }

    static var signalPrefixInlineHook: String {
        StringDeobfuscator.base64Decode("aW5saW5lX2hvb2tf")
    }

    static var antiTamperMethodPrefix: String {
        StringDeobfuscator.base64Decode("YW50aV90YW1wZXI6")
    }

    static var methodPrefixFridaEnv: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6ZW52Og==")
    }

    static var methodPrefixFridaPort: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6cG9ydDo=")
    }

    static var methodPrefixFridaProto: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6cHJvdG86")
    }

    static var methodPrefixFridaListen: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6bGlzdGVuOg==")
    }

    static var methodPrefixFridaAnomalousProto: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6YW5vbV9wcm90bzo=")
    }

    /// Neutral prefix for TCP listeners that are not Frida/D-Bus protocol (avoids false "frida" labels).
    static var methodPrefixSuspiciousLocalListen: String {
        StringDeobfuscator.base64Decode("c3VzcGljaW91czpsb2NhbF9saXN0ZW46")
    }

    static var envKeyCpriskFridaAnomScan: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX0ZSSURBX0FOT1NfU0NBTg==")
    }

    static var methodPrefixFridaFile: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6ZmlsZTo=")
    }

    static var methodPrefixFridaSymbol: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6c3ltYm9sOg==")
    }

    static var methodPrefixFridaThread: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6dGhyZWFkOg==")
    }

    static var methodPrefixFridaProcess: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6cHJvY2Vzczo=")
    }

    static var methodPrefixFridaMemorySig: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6bWVtc2lnOg==")
    }

    /// CRiskCore `cprisk_frida_runtime_snapshot` channels (dyld / dlsym / proc).
    static var methodPrefixFridaRuntime: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6cnVudGltZTo=")
    }

    /// `honeypot:` detector method prefix (Swift honeypot module).
    static var methodPrefixHoneypot: String {
        StringDeobfuscator.base64Decode("aG9uZXlwb3Q6")
    }

    /// Emitted when two or more runtime channels agree (higher confidence).
    static var methodPrefixFridaRuntimeFused: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6cnVudGltZV9mdXNlZDo=")
    }

    static var methodPrefixFridaModuleImage: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfbW9kdWxlOmltYWdlOg==")
    }

    static var methodPrefixFridaModuleSection: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfbW9kdWxlOnNlY3Rpb246")
    }

    static var methodPrefixFridaModuleString: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfbW9kdWxlOnN0cmluZzo=")
    }

    static var methodFridaUnavailableSimulator: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6dW5hdmFpbGFibGVfc2ltdWxhdG9y")
    }

    static var methodFridaModuleUnavailableSimulator: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfbW9kdWxlOnVuYXZhaWxhYmxlX3NpbXVsYXRvcg==")
    }

    static var methodFridaClean: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6Y2xlYW4=")
    }

    static var methodPrefixFridaHeap: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfaGVhcDo=")
    }

    static var methodPrefixFridaStalker: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfc3RhbGtlcjo=")
    }

    static var methodPrefixFridaMemoryLayout: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfbWVtb3J5X2xheW91dDo=")
    }

    static var signalFridaMemoryLayoutAnomaly: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfbWVtb3J5X2xheW91dF9hbm9tYWx5")
    }

    static var signalFridaDetected: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfZGV0ZWN0ZWQ=")
    }

    static var signalFridaJSEngineHeap: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfanNfZW5naW5lX2hlYXA=")
    }

    static var signalFridaStalker: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfc3RhbGtlcg==")
    }

    static var signalFridaStalkerJit: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfc3RhbGtlcl9qaXQ=")
    }

    static var signalFridaUnixSocket: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfdW5peF9zb2NrZXQ=")
    }

    static var signalFridaTimingAnomaly: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfdGltaW5nX2Fub21hbHk=")
    }

    static var signalFridaStalkerAmplified: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfc3RhbGtlcl9hbXBsaWZpZWQ=")
    }

    static var signalThreadAnomaly: String {
        StringDeobfuscator.base64Decode("dGhyZWFkX2Fub21hbHk=")
    }

    static var signalFridaExceptionPort: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfZXhjZXB0aW9uX3BvcnQ=")
    }

    static var signalFridaExceptionPortStartupRace: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfZXhjZXB0aW9uX3BvcnRfc3RhcnR1cF9yYWNl")
    }

    static var signalFridaDispatchQueue: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfZGlzcGF0Y2hfcXVldWU=")
    }

    static var signalArmorRuntimeInitFailed: String {
        StringDeobfuscator.base64Decode("YXJtb3JfcnVudGltZV9pbml0X2ZhaWxlZA==")
    }

    static var signalIntegrityRuntimeTampered: String {
        StringDeobfuscator.base64Decode("aW50ZWdyaXR5X3J1bnRpbWVfdGFtcGVyZWQ=")
    }

    static var signalTextSegmentTampered: String {
        StringDeobfuscator.base64Decode("dGV4dF9zZWdtZW50X3RhbXBlcmVk")
    }

    static var signalAppSigningIdentityTampered: String {
        StringDeobfuscator.base64Decode("YXBwX3NpZ25pbmdfaWRlbnRpdHlfdGFtcGVyZWQ=")
    }

    static var signalAppSigningBaselineChanged: String {
        StringDeobfuscator.base64Decode("YXBwX3NpZ25pbmdfYmFzZWxpbmVfY2hhbmdlZA==")
    }

    static var signalKernelHookTimingAnomaly: String {
        StringDeobfuscator.base64Decode("a2VybmVsX2hvb2tfdGltaW5nX2Fub21hbHk=")
    }

    static var signalKernelHookStalkerAmplified: String {
        StringDeobfuscator.base64Decode("a2VybmVsX2hvb2tfc3RhbGtlcl9hbXBsaWZpZWQ=")
    }

    static var detectorIDKernelHookSideChannel: String {
        StringDeobfuscator.base64Decode("a2VybmVsX2hvb2tfc2M=")
    }

    static var detectorNameFridaDetector: String {
        StringDeobfuscator.base64Decode("RnJpZGFEZXRlY3Rvcg==")
    }

    static var detectorNameFridaModuleDetector: String {
        StringDeobfuscator.base64Decode("RnJpZGFNb2R1bGVEZXRlY3Rvcg==")
    }

    static var detectorNameAntiTamperingDetector: String {
        StringDeobfuscator.base64Decode("QW50aVRhbXBlcmluZ0RldGVjdG9y")
    }

    static var detectorNameDebuggerDetector: String {
        StringDeobfuscator.base64Decode("RGVidWdnZXJEZXRlY3Rvcg==")
    }

    static var signalLibcInlineHookDetected: String {
        StringDeobfuscator.base64Decode("bGliY19pbmxpbmVfaG9va19kZXRlY3RlZA==")
    }

    static var signalObjcInlineHookDetected: String {
        StringDeobfuscator.base64Decode("b2JqY19pbmxpbmVfaG9va19kZXRlY3RlZA==")
    }

    static var methodPrefixFridaThreadName: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfdGhyZWFkOg==")
    }

    static var methodPrefixFridaException: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfZXhjZXB0aW9u")
    }

    static var methodPrefixFridaExceptionThreadMask: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfZXhjZXB0aW9uX3BvcnQ6dGhyZWFkX21hc2tf")
    }

    static var methodPrefixFridaExceptionMask: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfZXhjZXB0aW9uX3BvcnQ6bWFza18=")
    }

    static var methodPrefixFridaSocketPath: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfc29ja2V0OnBhdGg6")
    }

    static var methodPrefixFridaSocketTmpEntry: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfc29ja2V0OnRtcF9lbnRyeTo=")
    }

    static var methodPrefixFridaSocketUnixFd: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfc29ja2V0OnVuaXhfZmQ6")
    }

    static var methodPrefixTimingAnomaly: String {
        StringDeobfuscator.base64Decode("dGltaW5nX2Fub21hbHk=")
    }

    static var methodPrefixTimingStalkerAmplified: String {
        StringDeobfuscator.base64Decode("dGltaW5nX3N0YWxrZXJfYW1wbGlmaWVk")
    }

    static var methodPrefixSuspiciousQueue: String {
        StringDeobfuscator.base64Decode("c3VzcGljaW91c19xdWV1ZTo=")
    }

    /// Frida 通过环境变量注入时常见的键名。
    static var fridaEnvKeys: [String] {
        [
            StringDeobfuscator.base64Decode("RlJJREE="),
            StringDeobfuscator.base64Decode("RlJJREFfVkVSU0lPTg=="),
            StringDeobfuscator.base64Decode("RlJJREFfU0NSSVBU"),
            StringDeobfuscator.base64Decode("RFlMRF9JTlNFUlRfTElCUkFSSUVT"),
        ]
    }

    static var fridaEnvNeedleUpper: String {
        StringDeobfuscator.base64Decode("RlJJREE=")
    }

    // MARK: - Frida 检测器调优（进程环境键；取值需与运行环境的 launchd/shell 一致）

    static var envKeyCpriskFridaPortSweep: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX0ZSSURBX1BPUlRfU1dFRVA=")
    }

    static var envKeyCpriskFridaPortSweepAll: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX0ZSSURBX1BPUlRfU1dFRVBfQUxM")
    }

    static var envKeyCpriskFridaPortSweepMax: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX0ZSSURBX1BPUlRfU1dFRVBfTUFY")
    }

    static var envKeyCpriskFridaMemsig: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX0ZSSURBX01FTVNJRw==")
    }

    static var envKeyCpriskFridaMemsigBuiltin: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX0ZSSURBX01FTVNJR19CVUlMVElO")
    }

    static var envKeyCpriskFridaMemsigIntervalMs: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX0ZSSURBX01FTVNJR19JTlRFUlZBTF9NUw==")
    }

    static var envKeyCpriskFridaMemsigMaxPages: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX0ZSSURBX01FTVNJR19NQVhfUEFHRVM=")
    }

    static var envKeyCpriskFridaMemsigMaxRegionBytes: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX0ZSSURBX01FTVNJR19NQVhfUkVHSU9OX0JZVEVT")
    }

    static var envKeyCpriskFridaMemsigChunkBytes: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX0ZSSURBX01FTVNJR19DSFVOS19CWVRFUw==")
    }

    static var envKeyCpriskFridaMemsigMaxRegionIter: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX0ZSSURBX01FTVNJR19NQVhfUkVHSU9OX0lURVI=")
    }

    // MARK: - 协议令牌标签

    /// XOR+SHA256(label) seeds for `FridaDetector.protoToken` (must stay stable vs on-disk enc blobs).
    /// 标签值一旦变化，已落盘的加密探针 blob 将无法解出，发布后不可随意调整。
    static var fridaProtoLabelFnFrida: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX0ZOX0ZSSURB")
    }

    static var fridaProtoLabelGum: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX1BST1RPX0dVTQ==")
    }

    static var fridaProtoLabelReFrida: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX1BST1RPX1JFX0ZSSURB")
    }

    static var fridaProtoLabelDbus: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX1BST1RPX0RCVVM=")
    }

    static var fridaProtoLabelAuth: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX1BST1RPX0FVVEg=")
    }

    static var fridaProtoLabelReject: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX1BST1RPX1JFSkVDVA==")
    }

    static var fridaProtoLabelDbusAuth: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX1BST1RPX0RCVVNfQVVUSA==")
    }

    static var fridaProtoLabelSaslOK: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX1BST1RPX1NBU0xfT0s=")
    }

    static var fridaProtoLabelSaslRej: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX1BST1RPX1NBU0xfUkVK")
    }

    static var fridaProtoLabelDbusWire: String {
        StringDeobfuscator.base64Decode("Q1BSSVNLX1BST1RPX0RCVVNfV0lSRQ==")
    }

    // MARK: - 主动探针载荷

    /// Main-binary `dlsym` probe for honeypot (Mach-O C symbol; not exported by the app when clean).
    static var honeypotFridaAgentMainSymbol: String {
        StringDeobfuscator.base64Decode("X2ZyaWRhX2FnZW50X21haW4=")
    }

    /// Localhost Frida protocol probes (wire bytes; not protocol-stable identifiers).
    static var fridaProtocolProbePayloads: [String] {
        [
            StringDeobfuscator.base64Decode("QVVUSA0K"),
            StringDeobfuscator.base64Decode("R0VUIC8gSFRUUC8xLjANCg0K"),
            StringDeobfuscator.base64Decode("AA=="),
        ]
    }

    /// Active D-Bus/SASL/HTTP/null probes (order matters). Used with per-probe TCP connections in `FridaDetector`.
    static var fridaProtocolActiveWirePayloads: [String] {
        [
            StringDeobfuscator.base64Decode("QVVUSCBFWFRFUk5BTA0K"),
            StringDeobfuscator.base64Decode("QVVUSCBBTk9OWU1PVVMgDQo="),
            StringDeobfuscator.base64Decode("QVVUSA0K"),
            StringDeobfuscator.base64Decode("R0VUIC8gSFRUUC8xLjANCg0K"),
            StringDeobfuscator.base64Decode("AA=="),
        ]
    }

    // MARK: - dyld / libc 符号名

    /// dyld / libc symbol names resolved via `dlsym` for PLT integrity baselines.
    static var symbolSysctl: String {
        StringDeobfuscator.base64Decode("c3lzY3Rs")
    }

    static var symbolStat: String {
        StringDeobfuscator.base64Decode("c3RhdA==")
    }

    static var symbolAccess: String {
        StringDeobfuscator.base64Decode("YWNjZXNz")
    }

    static var symbolDlsym: String {
        StringDeobfuscator.base64Decode("ZGxzeW0=")
    }

    static var symbolGetenv: String {
        StringDeobfuscator.base64Decode("Z2V0ZW52")
    }

    static var symbolDyldImageCount: String {
        StringDeobfuscator.base64Decode("X2R5bGRfaW1hZ2VfY291bnQ=")
    }

    static var symbolDyldGetImageName: String {
        StringDeobfuscator.base64Decode("X2R5bGRfZ2V0X2ltYWdlX25hbWU=")
    }

    static var symbolDyldGetImageHeader: String {
        StringDeobfuscator.base64Decode("X2R5bGRfZ2V0X2ltYWdlX2hlYWRlcg==")
    }

    // MARK: - 父进程 / 环境特征

    /// Parent process / path needles (anti-debug / anti-tamper heuristics).
    static var antiTamperSuspiciousParentNeedles: [String] {
        [
            keywordLldb,
            StringDeobfuscator.base64Decode("Z2Ri"),
            StringDeobfuscator.base64Decode("ZGVidWdzZXJ2ZXI="),
            keywordFrida,
            StringDeobfuscator.base64Decode("aG9wcGVy"),
            StringDeobfuscator.base64Decode("aWRh"),
            StringDeobfuscator.base64Decode("Y3ljcmlwdA=="),
        ]
    }

    /// Standard `DYLD_INSERT_LIBRARIES` env name (dyld injection probes).
    static var envKeyDyldInsertLibraries: String {
        StringDeobfuscator.base64Decode("RFlMRF9JTlNFUlRfTElCUkFSSUVT")
    }

    static var antiTamperingDebugEnvironmentKeys: [String] {
        [
            envKeyDyldInsertLibraries,
            StringDeobfuscator.base64Decode("RFlMRF9GT1JDRV9GTEFUX05BTUVTUEFDRQ=="),
            StringDeobfuscator.base64Decode("TWFsbG9jU3RhY2tMb2dnaW5n"),
            StringDeobfuscator.base64Decode("TlNVbmJ1ZmZlcmVkSU8="),
            StringDeobfuscator.base64Decode("T1NfQUNUSVZJVFlfRFRfTU9ERQ=="),
        ]
    }

    static var debuggerInstrumentationEnvironmentKeys: [String] {
        [
            envKeyDyldInsertLibraries,
            StringDeobfuscator.base64Decode("T1NfQUNUSVZJVFlfRFRfTU9ERQ=="),
            StringDeobfuscator.base64Decode("TlNab21iaWVFbmFibGVk"),
            StringDeobfuscator.base64Decode("TWFsbG9jU3RhY2tMb2dnaW5n"),
        ]
    }

    // MARK: - 镜像 / section / 字符串扫描标记

    /// dyld 镜像名中出现的 Frida / Gum 特征。
    static var fridaModuleMarkers: [String] {
        [
            keywordFrida,
            StringDeobfuscator.base64Decode("ZnJpZGEtYWdlbnQ="),
            StringDeobfuscator.base64Decode("ZnJpZGEtZ2FkZ2V0"),
            StringDeobfuscator.base64Decode("ZnJpZGEtc2VydmVy"),
            StringDeobfuscator.base64Decode("Z2FkZ2V0"),
            StringDeobfuscator.base64Decode("bGliZ3Vt"),
            StringDeobfuscator.base64Decode("Z3VtLWNvcmU="),
            StringDeobfuscator.base64Decode("ZnJpZGFndW0="),
            StringDeobfuscator.base64Decode("Z3VtLWpzLWxvb3A="),
            StringDeobfuscator.base64Decode("Z3VtanM="),
        ]
    }

    static var fridaSectionMarkers: [String] {
        [
            StringDeobfuscator.base64Decode("X19mcmlkYQ=="),
            StringDeobfuscator.base64Decode("X19mcmlkYV9nYWRnZXQ="),
            StringDeobfuscator.base64Decode("X19mcmlkYV9kYXRh"),
            StringDeobfuscator.base64Decode("X19ndW0="),
            StringDeobfuscator.base64Decode("X19ndW1qcw=="),
        ]
    }

    static var fridaStringMarkers: [String] {
        [
            StringDeobfuscator.base64Decode("ZnJpZGE6cnBj"),
            StringDeobfuscator.base64Decode("ZnJpZGEtYWdlbnQ="),
            StringDeobfuscator.base64Decode("ZnJpZGEtZ2FkZ2V0"),
            StringDeobfuscator.base64Decode("Z3VtLWpzLWxvb3A="),
            StringDeobfuscator.base64Decode("Z3VtLWludGVyY2VwdG9y"),
            StringDeobfuscator.base64Decode("Z3VtLWNvcmU="),
            StringDeobfuscator.base64Decode("Z3Vtc3RhbGtlcg=="),
            StringDeobfuscator.base64Decode("bGluamVjdG9y"),
        ]
    }

    static var fridaSocketEntryMarkers: [String] {
        [
            keywordFrida,
            StringDeobfuscator.base64Decode("LmZyaWRh"),
            StringDeobfuscator.base64Decode("bGluamVjdG9y"),
        ]
    }

    static var fridaSocketPathMarkers: [String] {
        [
            keywordFrida,
            StringDeobfuscator.base64Decode("bGluamVjdG9y"),
            StringDeobfuscator.base64Decode("Z3Vt"),
        ]
    }

    static var fridaThreadNameMarkers: [String] {
        [
            StringDeobfuscator.base64Decode("Z3VtLWpzLWxvb3A="),
            StringDeobfuscator.base64Decode("Z21haW4="),
            StringDeobfuscator.base64Decode("Z2RidXM="),
            keywordFrida,
            StringDeobfuscator.base64Decode("Z3VtLWpz"),
            StringDeobfuscator.base64Decode("djg6"),
        ]
    }

    static var fridaQueueLabelMarkers: [String] {
        [
            keywordFrida,
            StringDeobfuscator.base64Decode("Z3VtLWpz"),
            StringDeobfuscator.base64Decode("Z21haW4="),
            StringDeobfuscator.base64Decode("Z2RidXM="),
            StringDeobfuscator.base64Decode("cmUuZnJpZGE="),
            StringDeobfuscator.base64Decode("bGluamVjdG9y"),
        ]
    }

    static var debuggerParentNeedles: [String] {
        [
            StringDeobfuscator.base64Decode("bGxkYg=="),
            StringDeobfuscator.base64Decode("ZGVidWdzZXJ2ZXI="),
            StringDeobfuscator.base64Decode("Z2Ri"),
            StringDeobfuscator.base64Decode("eGNvZGU="),
            keywordFrida,
            StringDeobfuscator.base64Decode("aG9wcGVy"),
            StringDeobfuscator.base64Decode("aWRh"),
        ]
    }

    // MARK: - 注入库 / ObjC 扫描特征

    /// 镜像路径扫描用的注入库 token；比 `suspiciousLibraryTokensForDyld` 更精简。
    static var hookSuspiciousImageTokens: [String] {
        [
            keywordFrida,
            StringDeobfuscator.base64Decode("Z2FkZ2V0"),
            StringDeobfuscator.base64Decode("c3Vic3RyYXRl"),
            StringDeobfuscator.base64Decode("c3Vic3RpdHV0ZQ=="),
            StringDeobfuscator.base64Decode("bGliaG9va2Vy"),
            StringDeobfuscator.base64Decode("ZWxsZWtpdA=="),
            StringDeobfuscator.base64Decode("dHdlYWs="),
            StringDeobfuscator.base64Decode("eHBvc2Vk"),
            keywordHook,
            StringDeobfuscator.base64Decode("cm9vdGhpZGU="),
        ]
    }

    static var hookSuspiciousImageTokensCore: [String] {
        [
            keywordFrida,
            StringDeobfuscator.base64Decode("Z2FkZ2V0"),
            StringDeobfuscator.base64Decode("Z3Vt"),
            StringDeobfuscator.base64Decode("c3Vic3RyYXRl"),
            StringDeobfuscator.base64Decode("c3Vic3RpdHV0ZQ=="),
            StringDeobfuscator.base64Decode("bGliaG9va2Vy"),
            StringDeobfuscator.base64Decode("ZWxsZWtpdA=="),
            StringDeobfuscator.base64Decode("dHdlYWs="),
            keywordHook,
            StringDeobfuscator.base64Decode("cm9vdGhpZGU="),
        ]
    }

    static var hookObjcScanPatterns: [String] {
        [
            StringDeobfuscator.base64Decode("Y3lkaWE="),
            StringDeobfuscator.base64Decode("c2lsZW8="),
            StringDeobfuscator.base64Decode("emVicmE="),
            StringDeobfuscator.base64Decode("ZmlsemE="),
            keywordFrida,
            StringDeobfuscator.base64Decode("Z3Vt"),
            StringDeobfuscator.base64Decode("c3Vic3RyYXRl"),
            StringDeobfuscator.base64Decode("c3Vic3RpdHV0ZQ=="),
            StringDeobfuscator.base64Decode("cHJlZmVyZW5jZWxvYWRlcg=="),
            StringDeobfuscator.base64Decode("YWN0aXZhdG9y"),
            StringDeobfuscator.base64Decode("cm9ja2V0Ym9vdHN0cmFw"),
            StringDeobfuscator.base64Decode("bGliaG9va2Vy"),
            StringDeobfuscator.base64Decode("ZWxsZWtpdA=="),
            StringDeobfuscator.base64Decode("c2hhZG93"),
            StringDeobfuscator.base64Decode("ZG9wYW1pbmU="),
            StringDeobfuscator.base64Decode("cm9vdGhpZGU="),
        ]
    }

    static var hookObjcMethodPrefixes: [String] {
        [
            StringDeobfuscator.base64Decode("amJf"),
            StringDeobfuscator.base64Decode("Y3lkaWFf"),
            StringDeobfuscator.base64Decode("c2lsZW9f"),
            StringDeobfuscator.base64Decode("aG9va18="),
            StringDeobfuscator.base64Decode("cGF0Y2hf"),
            StringDeobfuscator.base64Decode("dHdlYWtf"),
            StringDeobfuscator.base64Decode("c3Vic3RyYXRlXw=="),
            StringDeobfuscator.base64Decode("bXNf"),
        ]
    }

    static var hookSuspiciousProtocolNames: [String] {
        [
            StringDeobfuscator.base64Decode("Q3lkaWFEZWxlZ2F0ZQ=="),
            StringDeobfuscator.base64Decode("U2lsZW9EZWxlZ2F0ZQ=="),
            StringDeobfuscator.base64Decode("U3Vic3RpdHV0ZURlbGVnYXRl"),
            StringDeobfuscator.base64Decode("RnJpZGFIZWxwZXI="),
            StringDeobfuscator.base64Decode("SmFpbGJyZWFrUHJvdG9jb2w="),
        ]
    }

    static var hookSuspiciousObjCClasses: [String] {
        [
            StringDeobfuscator.base64Decode("Q3lkaWFPYmplY3Q="),
            StringDeobfuscator.base64Decode("Q3lkaWE="),
            StringDeobfuscator.base64Decode("Q3lkaWFEZWxlZ2F0ZQ=="),
            StringDeobfuscator.base64Decode("U2lsZW9QYWNrYWdl"),
            StringDeobfuscator.base64Decode("U2lsZW9Tb3VyY2U="),
            StringDeobfuscator.base64Decode("U2lsZW9NYW5hZ2Vy"),
            StringDeobfuscator.base64Decode("RkxFWE1hbmFnZXI="),
            StringDeobfuscator.base64Decode("RkxFWEV4cGxvcmVyVmlld0NvbnRyb2xsZXI="),
            StringDeobfuscator.base64Decode("RkxFWEV4cGxvcmVy"),
            StringDeobfuscator.base64Decode("RkxFWFdpbmRvdw=="),
            StringDeobfuscator.base64Decode("RmlzaEhvb2s="),
            StringDeobfuscator.base64Decode("Q3lkaWFTdWJzdHJhdGU="),
            StringDeobfuscator.base64Decode("U3Vic3RyYXRlTG9hZGVy"),
            StringDeobfuscator.base64Decode("RnJpZGFTZXJ2ZXI="),
            StringDeobfuscator.base64Decode("RnJpZGFHYWRnZXQ="),
            StringDeobfuscator.base64Decode("RnJpZGFBZ2VudA=="),
            StringDeobfuscator.base64Decode("R3VtSW52b2NhdGlvbkNvbnRleHQ="),
            StringDeobfuscator.base64Decode("R3VtSW50ZXJjZXB0b3I="),
            StringDeobfuscator.base64Decode("U1NMS2lsbFN3aXRjaA=="),
            StringDeobfuscator.base64Decode("TGliZXJ0eQ=="),
            StringDeobfuscator.base64Decode("TGliZXJ0eUxpdGU="),
            StringDeobfuscator.base64Decode("QUJ5cGFzcw=="),
            StringDeobfuscator.base64Decode("Um9ja2V0Qm9vdHN0cmFw"),
            StringDeobfuscator.base64Decode("UkJNYW5hZ2Vy"),
            StringDeobfuscator.base64Decode("Q1BEaXN0cmlidXRlZE1lc3NhZ2luZw=="),
            StringDeobfuscator.base64Decode("SEJQcmVmZXJlbmNlcw=="),
            StringDeobfuscator.base64Decode("SEJMT3B0aW9uc0NvbnRyb2xsZXI="),
            StringDeobfuscator.base64Decode("Um9vdEhpZGVNYW5hZ2Vy"),
            StringDeobfuscator.base64Decode("Um9vdEhpZGVQYXRjaGVy"),
            StringDeobfuscator.base64Decode("Um9vdEhpZGVBUEk="),
            StringDeobfuscator.base64Decode("bGliUm9vdEhpZGVy"),
        ]
    }

    // MARK: - 分类、别名与组合特征

    /// 证据分类值 "anti_tamper"。
    static var categoryAntiTamper: String {
        StringDeobfuscator.base64Decode("YW50aV90YW1wZXI=")
    }

    /// 证据键 "hooked"：用已解码的 hook 关键词拼接后缀，避免完整单词出现在字符串表中。
    static var evidenceKeyHooked: String {
        "\(keywordHook)ed"
    }

    /// Category value "jailbreak" (same as signalJailbreak, used where category is intended).
    static var categoryJailbreak: String { signalJailbreak }

    /// "lldb" for parent process / path checks.
    static var keywordLldb: String {
        StringDeobfuscator.base64Decode("bGxkYg==")
    }

    /// Signal id "vpn_active" for scenario requiredSignals.
    static var requiredSignalVpnActive: String {
        StringDeobfuscator.base64Decode("dnBuX2FjdGl2ZQ==")
    }

    /// Suspicious image name patterns for baseline env check (no literal tokens in binary).
    static var suspiciousImagePatternsBaseline: [String] {
        [
            keywordFrida,
            StringDeobfuscator.base64Decode("c3Vic3RyYXRl"),
            StringDeobfuscator.base64Decode("bGliaG9va2Vy"),
            StringDeobfuscator.base64Decode("ZWxsZWtpdA=="),
            StringDeobfuscator.base64Decode("c3Vic3RpdHV0ZQ=="),
        ]
    }

    /// Full suspicious library tokens for dyld image scan (DyldDetector / DynamicFeatureList).
    static var suspiciousLibraryTokensForDyld: [String] {
        [
            keywordFrida,
            StringDeobfuscator.base64Decode("Z2FkZ2V0"),
            StringDeobfuscator.base64Decode("Z3Vt"),
            StringDeobfuscator.base64Decode("c3Vic3RyYXRl"),
            StringDeobfuscator.base64Decode("bGlic3Vic3RyYXRl"),
            StringDeobfuscator.base64Decode("c3Vic3RpdHV0ZQ=="),
            StringDeobfuscator.base64Decode("bGlic3Vic3RpdHV0ZQ=="),
            StringDeobfuscator.base64Decode("Y3ljcmlwdA=="),
            StringDeobfuscator.base64Decode("bGliY3ljcmlwdA=="),
            StringDeobfuscator.base64Decode("bGliaG9va2Vy"),
            StringDeobfuscator.base64Decode("ZWxsZWtpdA=="),
            StringDeobfuscator.base64Decode("c3Nsa2lsbA=="),
            StringDeobfuscator.base64Decode("c3Nsa2lsbCBzd2l0Y2g="),
            StringDeobfuscator.base64Decode("c3Nsa2lsbHN3aXRjaA=="),
            StringDeobfuscator.base64Decode("cHJlZmVyZW5jZWxvYWRlcg=="),
            StringDeobfuscator.base64Decode("ZmxleA=="),
            StringDeobfuscator.base64Decode("cm9ja2V0Ym9vdHN0cmFw"),
            StringDeobfuscator.base64Decode("YWN0aXZhdG9y"),
            StringDeobfuscator.base64Decode("bGliYWN0aXZhdG9y"),
            StringDeobfuscator.base64Decode("Y2VwaGVp"),
            StringDeobfuscator.base64Decode("dHdlYWtpbmplY3Q="),
            StringDeobfuscator.base64Decode("c2hhZG93"),
            StringDeobfuscator.base64Decode("ZG9wYW1pbmU="),
            StringDeobfuscator.base64Decode("cm9vdGhpZGU="),
            StringDeobfuscator.base64Decode("bGliUm9vdEhpZGU="),
        ]
    }

    /// Shorter list for memory/code-signature integrity checks.
    static var suspiciousLibraryTokensForIntegrity: [String] {
        [
            keywordFrida,
            StringDeobfuscator.base64Decode("Z2FkZ2V0"),
            StringDeobfuscator.base64Decode("Z3Vt"),
            StringDeobfuscator.base64Decode("c3Vic3RyYXRl"),
            StringDeobfuscator.base64Decode("c3Vic3RpdHV0ZQ=="),
            StringDeobfuscator.base64Decode("bGliaG9va2Vy"),
            StringDeobfuscator.base64Decode("ZWxsZWtpdA=="),
        ]
    }

    /// For code signature validator: integrity tokens + "tweak", "hook".
    static var suspiciousInjectedLibraryTokens: [String] {
        suspiciousLibraryTokensForIntegrity + [
            StringDeobfuscator.base64Decode("dHdlYWs="),
            keywordHook,
        ]
    }

    /// Keywords for dylib injection detector (path/layout checks).
    static var dylibInjectionSuspiciousKeywords: [String] {
        [
            StringDeobfuscator.base64Decode("c3Vic3RyYXRl"),
            StringDeobfuscator.base64Decode("c3Vic3RpdHV0ZQ=="),
            StringDeobfuscator.base64Decode("ZWxsZWtpdA=="),
            StringDeobfuscator.base64Decode("bGliaG9va2Vy"),
            StringDeobfuscator.base64Decode("Y3luamVjdA=="),
            StringDeobfuscator.base64Decode("c3Bhd24="),
            StringDeobfuscator.base64Decode("dHdlYWtpbmplY3Q="),
            StringDeobfuscator.base64Decode("Y3lkaWFzdWJzdHJhdGU="),
            StringDeobfuscator.base64Decode("c2hhZG93"),
            StringDeobfuscator.base64Decode("bGliYmxhY2tqYWNr"),
            StringDeobfuscator.base64Decode("Y2hvaWN5"),
            StringDeobfuscator.base64Decode("c3Nsa2lsbHN3aXRjaA=="),
            StringDeobfuscator.base64Decode("ZmxleA=="),
            StringDeobfuscator.base64Decode("cmV2ZWFsZGVidWc="),
            StringDeobfuscator.base64Decode("Y3ljcmlwdA=="),
            StringDeobfuscator.base64Decode("cm9vdGhpZGU="),
            StringDeobfuscator.base64Decode("cm9vdGhpZGVy"),
            StringDeobfuscator.base64Decode("cHJvY3Vyc3Vz"),
        ]
    }

    static var detectorIDDylibInjection: String {
        StringDeobfuscator.base64Decode("ZHlsaWJfaW5qZWN0aW9u")
    }

    static var signalWatchdogAdaptiveHint: String {
        StringDeobfuscator.base64Decode("d2F0Y2hkb2dfYWRhcHRpdmVfaGludA==")
    }
}

extension ObfuscatedConstants {
    /// 在受限作用域内使用解密后的字符串，退出时尽力清空引用。
    /// 注意：Swift String 内部可能复制，这里只能缩短本变量的生命周期，不等于立即擦除内存。
    static func withDeobfuscated<T>(_ getter: () -> String, _ body: (String) -> T) -> T {
        var str = getter()
        defer {
            // 尽早释放明文引用（best-effort）。
            str = ""
        }
        return body(str)
    }
}

/// 构建期配置：区分 DEBUG/Release，并在 Release 下关闭日志输出。
enum BuildConfig {
    /// 编译期判定的 Release 标志，避免运行期被动态改写。
    static let isRelease: Bool = {
        #if DEBUG
        return false
        #else
        return true
        #endif
    }()

    /// 是否已完成 Release 配置，保证配置逻辑幂等。
    private(set) static var isConfigured = false

    /// Release 下关闭 Logger，避免检测细节与敏感路径进入系统日志。
    /// 幂等：重复调用不会重复执行配置。
    static func configureForRelease() {
        guard !isConfigured else { return }
        isConfigured = true

        if isRelease {
            Logger.isEnabled = false
        }
    }
}
