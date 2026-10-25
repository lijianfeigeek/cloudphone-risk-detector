// FridaDetector：Frida 家族的总编排检测器，聚合环境变量、本地端口协议指纹、
// 文件路径、运行时镜像/dlsym/进程表、prologue/inline hook 与内存字符串特征等多路侧信道。
// 各通道相互独立又互相印证：单一通道易被定向绕过，多通道同时命中才给高置信结论。
// 最终输出 DetectorResult 交给信号层，命中方法统一带 frida:* 前缀。
import CRiskCore
import CryptoKit
import Darwin
import Foundation

/// Frida 综合检测器。
/// - 线程模型：`detect()` 为同步纯查询，可在任意线程调用；共享的 `hookState` 由 Mutex 保护。
/// - 降级策略：模拟器直接返回 0；C 侧快照不支持、端口不可达、文件被隐藏均静默跳过。
struct FridaDetector: Detector {
    // 补丁类（prologue/inline）命中方法前缀，供信号层区分“代码被改”与“行为异常”。
    static let methodPrefixPatch = "frida:patch:"
    // 行为类（dyld interpose/env/image count）命中方法前缀。
    static let methodPrefixBehavior = "frida:behavior:"

    /// 测试入口：把 C 侧行为位图转换为方法名列表，便于单测断言映射关系。
    internal static func mapRuntimeBehaviorMethodsForTesting(
        flags: UInt32,
        hitCount: UInt32 = 0
    ) -> [String] {
        mapRuntimeBehaviorMethods(flags: flags, hitCount: hitCount)
    }

    /// 解码 XOR+SHA256(label) 混淆后的协议特征 token。
    /// 明文 token 不落二进制，降低攻击者静态搜索/内存扫描定位检测逻辑的概率。
    /// XOR+SHA256(label) decode — matches CRiskCore `cprisk_obf_decode_sha256_label` v1.
    private static func protoToken(label: String, enc: [UInt8]) -> String {
        let d = SHA256.hash(data: Data(label.utf8))
        let digest = Array(d)
        let bytes = enc.enumerated().map { i, b in b ^ digest[i % 32] }
        return String(decoding: bytes, as: UTF8.self)
    }

    // Frida 默认监听端口：27042/27043 是 frida-server 常用端口，23946 见于部分旧版/变体。
    // 候选集很小，因此默认端口探测开销仅取决于端口数 × 单次超时。
    let knownPorts: [Int] = [27042, 27043, 23946]
    // frida-server 常见落盘路径（混淆常量）；命中说明设备上存在 Frida 二进制。
    let knownServerPaths: [String] = ObfuscatedConstants.fridaServerPaths
    // 噪声探针：真实存在的良性系统路径，只用于比对 access/stat 结果是否一致。
    // 它们不参与命中计分，目的是发现“只 hook 了其中一个 API”的文件隐藏行为。
    private let artifactNoisePaths: [String] = [
        "/usr/lib/dyld",
        "/System/Library/CoreServices/SystemVersion.plist",
        "/bin/sh",
    ]
    // 单端口协议探测超时 120ms；端口扫描的总耗时上界由该值决定。
    private let protocolProbeTimeoutMs: Int32 = 120
    // 外部注入的内存签名 hook 列表（仅 DEBUG + 环境变量开启时使用），用于测试或定制扫描。
    private static let hookState = Mutex<[() -> String?]>([])

    /// 最小 D-Bus 方法调用头前缀（小端）。主动发送可诱发 D-Bus 监听端的认证栈回包。
    /// Minimal little-endian D-Bus-shaped wire prefix (method call header); elicits auth-stack replies on D-Bus speakers.
    private static let dbusShapeProbeWire: [UInt8] = [
        0x6c, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]

    /// 注册一个外部内存签名 hook；多个 hook 按注册顺序尝试，返回首个非空命中。
    static func registerMemorySignatureHook(_ hook: @escaping () -> String?) {
        hookState.withLock { $0.append(hook) }
    }

    /// 清空外部内存签名 hook（测试与生命周期收尾使用）。
    static func clearMemorySignatureHooks() {
        hookState.withLock { $0.removeAll() }
    }

    /// 执行全部 Frida 子检测并汇总分数。
    /// - 返回：`DetectorResult.score` 封顶 45，`methods` 记录每个命中通道及细节。
    /// - 失败语义：任何子检测异常都按“未命中”处理，不影响其余通道。
    func detect() throws -> DetectorResult {
// 模拟器缺少真实 dyld/端口/Mach 线程语义，统一跳过避免误报。
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
#else
        // 各通道分数累加；后续按证据强度决定是否再触发高开销扫描。
        var score: Double = 0
        var methods: [String] = []
        // 环境变量侧信道：一次 getenv 即可，成本最低，但攻击者可清理环境变量。
        let envHit = detectFridaEnv()
        // 运行时 hook 表面：复用 prologue/inline/dyld 检测，覆盖代码被改写的情况。
        let hookSurface = detectHookedRuntimeSurfaces()

        if let envHit {
            // 环境变量含 frida 是强指示，单条即给 18 分。
            score += 18
            methods.append("\(ObfuscatedConstants.methodPrefixFridaEnv)\(envHit)")
        }

        // 端口/协议侧信道：Frida 必须监听本地端口才能被 attach，绕过后仍有监听痕迹。
        let portBehavior = detectFridaPortBehaviors()
        score += portBehavior.score
        methods.append(contentsOf: portBehavior.methods)

        score += hookSurface.score
        methods.append(contentsOf: hookSurface.methods)

        // 内存字符串侧信道：进程映射中的 Frida/Gum 标记，覆盖无监听/无环境变量的场景。
        let memorySignatureHit = detectMemorySignatureHit()
        if let memSig = memorySignatureHit {
            score += 10
            methods.append("\(ObfuscatedConstants.methodPrefixFridaMemorySig)\(memSig)")
        }

        // C 侧多路运行时快照（镜像路径、dlsym(Gum)、进程表、行为），返回命中的通道数。
        let runtimeChannelCount = applyFridaRuntimeCRiskSignals(score: &score, methods: &methods)

        // 异常端口扫描开销大（数十次 connect），只在已有弱线索时执行，避免干净设备上的无谓探测。
        if shouldRunAnomalousPortScan(
            envHit: envHit != nil,
            portBehavior: portBehavior,
            hookSurfaceScore: hookSurface.score,
            memorySignatureHit: memorySignatureHit != nil,
            runtimeChannelCount: runtimeChannelCount
        ) {
            let anomalousPorts = detectAnomalousListeningPorts()
            score += anomalousPorts.score
            methods.append(contentsOf: anomalousPorts.methods)
        }

        // 文件路径探测最容易产生噪声，改为“高熵命中后的佐证步骤”，不再无条件执行。
        // Reduce conspicuous Swift-layer path probes on clean devices.
        // File artifact checks become a corroboration step after higher-entropy runtime/behavior hits.
        if shouldProbeFileArtifacts(
            envHit: envHit != nil,
            portBehaviorScore: portBehavior.score,
            runtimeChannelCount: runtimeChannelCount,
            memorySignatureHit: memorySignatureHit != nil,
            hookSurfaceHit: hookSurface.score > 0
        ) {
            let fileArtifact = detectFridaFileArtifactAssessment()
            if fileArtifact.detected {
                score += fileArtifact.score
                methods.append(contentsOf: fileArtifact.methods)
            }
        }

        // 单检测器封顶 45：Frida 结论应与其他反篡改信号共同决定最终风险等级。
        return DetectorResult(score: min(score, 45), methods: methods)
#endif
    }

    /// 检查环境中是否存在 Frida 相关变量。
    /// 返回命中的键名（小写）；未命中返回 nil。
    private func detectFridaEnv() -> String? {
        let keys = ObfuscatedConstants.fridaEnvKeys
        for key in keys {
            guard let value = getenv(key) else { continue }
            let text = String(cString: value).lowercased()
            // 值包含 frida，或键名本身包含 FRIDA，都视为命中。
            if text.contains(ObfuscatedConstants.keywordFrida) || key.contains(ObfuscatedConstants.fridaEnvNeedleUpper) {
                return key.lowercased()
            }
        }
        return nil
    }

    /// 兼容旧接口：只返回文件痕迹检测的布尔结果。
    func detectFridaFileArtifact() -> Bool {
#if targetEnvironment(simulator)
        false
#else
        detectFridaFileArtifactAssessment().detected
#endif
    }

    /// 文件痕迹评估：已知 frida-server 路径命中、以及 access/stat 结果不一致（被隐藏）。
    /// - 返回 (是否命中, 分数, 方法列表)。
    private func detectFridaFileArtifactAssessment() -> (detected: Bool, score: Double, methods: [String]) {
#if targetEnvironment(simulator)
        (false, 0, [])
#else
        // 探针分两类：real=true 参与计分，real=false 只用于检测 API 一致性。
        struct ArtifactProbe {
            let path: String
            let real: Bool
        }

        // 真实路径与噪声路径混洗，避免攻击者按固定顺序 patch 单个探测点。
        var probes = knownServerPaths.map { ArtifactProbe(path: $0, real: true) }
        probes.append(contentsOf: artifactNoisePaths.map { ArtifactProbe(path: $0, real: false) })
        probes.shuffle()

        var hitCount = 0
        var maskedCount = 0

        for probe in probes {
            let accessExists = self.fileExists(path: probe.path)
            let statExists = self.statFileExists(path: probe.path)
            guard probe.real else { continue }

            if accessExists || statExists {
                hitCount += 1
            }
            // access 与 stat 结果不一致说明其中一个被 hook（文件被定向隐藏），单独计分。
            if accessExists != statExists {
                maskedCount += 1
            }
        }

        var score: Double = 0
        var methods: [String] = []
        if hitCount > 0 {
            // 命中基础 18 分，每多一个路径 +4，封顶 26。
            score += min(18 + Double(max(0, hitCount - 1)) * 4, 26)
            methods.append("\(ObfuscatedConstants.methodPrefixFridaFile)artifact_hits_\(hitCount)")
        }
        if maskedCount > 0 {
            // masked 每处 +6，封顶 12。
            score += min(Double(maskedCount) * 6, 12)
            methods.append("\(ObfuscatedConstants.methodPrefixFridaFile)artifact_masked_\(maskedCount)")
        }
        return (hitCount > 0 || maskedCount > 0, score, methods)
#endif
    }

    /// 判断是否值得执行文件路径探测：仅在已有任一运行时/行为线索时为 true。
    internal func shouldProbeFileArtifacts(
        envHit: Bool,
        portBehaviorScore: Double,
        runtimeChannelCount: Int,
        memorySignatureHit: Bool,
        hookSurfaceHit: Bool
    ) -> Bool {
        envHit || portBehaviorScore > 0 || runtimeChannelCount > 0 || memorySignatureHit || hookSurfaceHit
    }

    /// DEBUG 专用：允许扩大端口候选集。Release 恒为 false，防止外部环境变量改变检测行为。
    private var aggressivePortSweepEnabled: Bool {
        #if !DEBUG
        // 环境变量开关仅在 DEBUG 生效：Release 下忽略调用方环境，防止
        // 通过注入环境变量改变检测行为（开启激进端口扫描）。
        return false
        #endif
        guard let raw = ProcessInfo.processInfo.environment[ObfuscatedConstants.envKeyCpriskFridaPortSweep]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() else {
            return false
        }
        return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
    }

    /// DEBUG 专用：全端口扫描（1...65535），开销极大，仅用于调试。
    private var fullPortSweepEnabled: Bool {
        #if !DEBUG
        return false
        #endif
        guard let raw = ProcessInfo.processInfo.environment[ObfuscatedConstants.envKeyCpriskFridaPortSweepAll]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() else {
            return false
        }
        return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
    }

    /// DEBUG 专用：全端口扫描的上界，默认 65535。
    private var fullPortSweepMaxPort: Int {
        #if !DEBUG
        return 65535
        #endif
        guard let raw = ProcessInfo.processInfo.environment[ObfuscatedConstants.envKeyCpriskFridaPortSweepMax]?
            .trimmingCharacters(in: .whitespacesAndNewlines),
              let parsed = Int(raw),
              parsed >= 1 else {
            return 65535
        }
        return min(parsed, 65535)
    }

    /// 可选：外部/测试注入的内存命中（显式 `CPRISK_FRIDA_MEMSIG=1` 才启用，避免与内置扫描耦合）。
    /// 调试用：是否启用外部注入的内存签名扫描（CPRISK_FRIDA_MEMSIG）。
    private var hookMemorySignatureScanEnabled: Bool {
        #if !DEBUG
        return false
        #endif
        guard let raw = ProcessInfo.processInfo.environment[ObfuscatedConstants.envKeyCpriskFridaMemsig]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() else {
            return false
        }
        return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
    }

    /// DEBUG 专用：是否强制启用异常端口扫描。
    private var anomalousPortScanEnvEnabled: Bool {
        #if !DEBUG
        return false
        #endif
        guard let raw = ProcessInfo.processInfo.environment[ObfuscatedConstants.envKeyCpriskFridaAnomScan]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() else {
            return false
        }
        return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
    }

    /// 决定是否执行异常端口扫描。
    /// 触发条件：显式开关、任一运行时命中、或端口协议已确认。
    private func shouldRunAnomalousPortScan(
        envHit: Bool,
        portBehavior: (score: Double, methods: [String], fridaProtocolDetected: Bool),
        hookSurfaceScore: Double,
        memorySignatureHit: Bool,
        runtimeChannelCount: Int
    ) -> Bool {
        if anomalousPortScanEnvEnabled {
            return true
        }
        if envHit || memorySignatureHit || hookSurfaceScore > 0 || runtimeChannelCount > 0 {
            return true
        }
        return portBehavior.fridaProtocolDetected
    }

    /// 测试入口：暴露当前候选端口集合。
    internal func candidatePortsForTesting() -> [Int] {
        candidatePorts()
    }

    /// 测试入口：返回主动 D-Bus 探针与 wire 探针负载。
    internal static func proactiveProtocolPayloadsForTesting() -> [Data] {
        [Data(dbusShapeProbeWire)] + ObfuscatedConstants.fridaProtocolActiveWirePayloads.map { Data($0.utf8) }
    }

    /// 生成端口候选集。
    /// 默认 = 已知端口 ∪ 内置可疑端口；DEBUG 激进模式再叠加动态特征列表。
    private func candidatePorts() -> [Int] {
        // 全端口扫描会产生数万次 connect，仅调试模式下允许。
        if fullPortSweepEnabled {
            return Array(1...fullPortSweepMaxPort)
        }

        // 去重并排序，保证探测顺序稳定、便于复现。
        var ports = Set(knownPorts)
        ObfuscatedConstants.suspiciousPortsBuiltinFallback.forEach {
            if (1...65535).contains($0) {
                ports.insert($0)
            }
        }
        if aggressivePortSweepEnabled {
            // 动态列表可能含误报端口，只有 DEBUG 激进模式才启用。
            DynamicFeatureList.shared.suspiciousPorts.forEach {
                if (1...65535).contains($0) {
                    ports.insert($0)
                }
            }
        }
        return ports.sorted()
    }

    /// 对候选端口做监听与协议指纹检测。
    /// 返回分数、方法列表，以及是否已确认 Frida 协议（用于触发后续扫描）。
    private func detectFridaPortBehaviors() -> (score: Double, methods: [String], fridaProtocolDetected: Bool) {
        var score: Double = 0
        var methods: [String] = []
        var fridaProtocolDetected = false
        let knownPortSet = Set(knownPorts)

        for port in candidatePorts() {
            let probe = probeLocalPort(port, timeoutMs: protocolProbeTimeoutMs)
            guard probe.listening else { continue }

            if let token = probe.fingerprintToken {
                fridaProtocolDetected = true
                // 有协议指纹：已知端口 22 分，未知端口 14 分——指纹本身比端口号更可靠。
                score += knownPortSet.contains(port) ? 22 : 14
                methods.append("\(ObfuscatedConstants.methodPrefixFridaProto)\(port):\(token)")
            } else if knownPortSet.contains(port) {
                // 监听但无指纹：已知端口 12 分，未知动态端口 4 分。
                score += 12
                methods.append("\(ObfuscatedConstants.methodPrefixFridaPort)\(port)")
            } else {
                score += 4
                methods.append("\(ObfuscatedConstants.methodPrefixFridaListen)\(port)")
            }
        }

        return (score, methods, fridaProtocolDetected)
    }

    // 异常端口区间的选取避开常见合法本地服务；命中仅表示“可疑监听”，需协议或 HTTP 排除。
    /// Ranges omit 8080–8090, 1080–1085, 5555–5560 (common legit local services on iOS).
    private static let anomalousPortRanges: [(ClosedRange<Int>)] = [
        9090...9100,
        1337...1340,
        4242...4250,
        6666...6670,
        7777...7780,
        31337...31340,
        42000...42010,
        47000...47010,
    ]

    /// 扫描异常端口区间，寻找非白名单监听。
    /// 有协议指纹直接计分；纯监听只记录方法、不计分，避免把合法本地服务算成攻击。
    private func detectAnomalousListeningPorts() -> (score: Double, methods: [String]) {
        let knownCandidates = Set(candidatePorts())
        // 异常端口用更短超时 50ms，控制整段扫描的累计耗时。
        let anomalousTimeoutMs: Int32 = 50
        var score: Double = 0
        var methods: [String] = []

        for range in Self.anomalousPortRanges {
            for port in range {
                guard !knownCandidates.contains(port) else { continue }
                let probe = probeLocalPort(port, timeoutMs: anomalousTimeoutMs)
                guard probe.listening else { continue }

                // 命中 D-Bus/Frida 协议指纹：16 分，强证据。
                if let token = probe.fingerprintToken {
                    score += 16
                    methods.append("\(ObfuscatedConstants.methodPrefixFridaAnomalousProto)\(port):\(token)")
                    continue
                }

                // 回包像 HTTP 响应，按合法本地服务处理并跳过，降低误报。
                if localServiceRespondsLikeHttp(port: port, timeoutMs: anomalousTimeoutMs) {
                    continue
                }

                // 仅监听、无指纹：只记录可疑本地监听方法，不增加分数。
                methods.append("\(ObfuscatedConstants.methodPrefixSuspiciousLocalListen)\(port)")
            }
        }

        return (score, methods)
    }

    /// 发送最小 HTTP 请求，判断目标是否为普通 HTTP 本地服务。
    private func localServiceRespondsLikeHttp(port: Int, timeoutMs: Int32) -> Bool {
        guard let fd = connectLocalStream(port: port, timeoutMs: timeoutMs) else {
            return false
        }
        defer { _ = cprisk_close_direct(fd, nil) }
        applySocketTimeouts(fd: fd, timeoutMs: timeoutMs)

        let req = "GET / HTTP/1.0\r\n\r\n"
        guard let sent = req.data(using: .utf8) else { return false }
        let writeCount = sent.withUnsafeBytes { raw -> Int in
            guard let base = raw.baseAddress else { return -1 }
            return send(fd, base, sent.count, 0)
        }
        guard writeCount == sent.count else { return false }

        guard waitReadable(fd, timeoutMs: timeoutMs) else { return false }
        var buffer = [UInt8](repeating: 0, count: 64)
        let readCount = recv(fd, &buffer, buffer.count, 0)
        guard readCount > 0 else { return false }
        return Self.bufferLooksLikeHttpResponsePrefix(Array(buffer.prefix(Int(readCount))))
    }

    /// 判断缓冲区前缀是否为 HTTP/1.x 状态行。
    private static func bufferLooksLikeHttpResponsePrefix(_ raw: [UInt8]) -> Bool {
        guard !raw.isEmpty else { return false }
        let head = String(decoding: raw.prefix(min(32, raw.count)), as: UTF8.self)
        return head.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().hasPrefix("http/1.")
    }

    /// 测试入口：对给定响应数据做 HTTP 前缀判断。
    internal static func httpResponseLooksLikeHttpForTesting(_ data: Data) -> Bool {
        bufferLooksLikeHttpResponsePrefix(Array(data))
    }

    /// 探测单个本地端口。
    /// 返回 (是否可连接, 协议指纹 token)。可连接但无指纹时 listening=true、token=nil。
    private func probeLocalPort(_ port: Int, timeoutMs: Int32) -> (listening: Bool, fingerprintToken: String?) {
        guard let fd = connectLocalStream(port: port, timeoutMs: timeoutMs) else {
            return (false, nil)
        }
        defer { _ = cprisk_close_direct(fd, nil) }

        applySocketTimeouts(fd: fd, timeoutMs: timeoutMs)

        // 首连接即主动发送 D-Bus 形状探针：即使监听端去掉了默认 banner，仍可能暴露认证栈。
        // Probe proactively on the first connection so even customized listeners that no longer
        // emit a default banner still expose a live D-Bus/SASL stack.
        if let proactive = tryActiveProbe(fd: fd, payload: Data(Self.dbusShapeProbeWire), timeoutMs: timeoutMs) {
            return (true, proactive)
        }

        // 被动等待 banner（部分 Frida 版本会主动发送握手数据）。
        if let passive = receiveProtocolFingerprint(fd: fd, timeoutMs: timeoutMs) {
            return (true, passive)
        }

        // 再逐个尝试 wire 探针负载。
        for payload in activeWireProbeDatas() {
            if let token = tryActiveProbe(port: port, payload: payload, timeoutMs: timeoutMs) {
                return (true, token)
            }
        }

        // 端口确实可连，但没有任何可识别指纹。
        return (true, nil)
    }

    /// 建立到 127.0.0.1 的非阻塞 TCP 连接，带 poll 超时。
    /// 失败返回 nil；成功返回已连接的 fd，调用方负责关闭。
    private func connectLocalStream(port: Int, timeoutMs: Int32) -> Int32? {
        var rawErrno: CInt = 0
        // 使用 CRiskCore 的直接 syscall 封装，绕过可能被 hook 的 libc socket/connect。
        let fd = cprisk_socket_direct(AF_INET, SOCK_STREAM, 0, &rawErrno)
        guard fd >= 0 else { return nil }

        // 设为非阻塞 + poll，避免连接不可达端口时阻塞调用线程。
        let originalFlags = fcntl(fd, F_GETFL, 0)
        if originalFlags >= 0 {
            _ = fcntl(fd, F_SETFL, originalFlags | O_NONBLOCK)
        }
        defer {
            if originalFlags >= 0 {
                _ = fcntl(fd, F_SETFL, originalFlags)
            }
        }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        // 只连本机回环地址，不触达外网，符合隐私与合规要求。
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        var connectErrno: CInt = 0

        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr -> Int32 in
                return cprisk_connect_direct(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size), &connectErrno)
            }
        }
        if result != 0 {
            // EINPROGRESS/EALREADY 表示连接仍在进行，需要等待可写后再检查 SO_ERROR。
            let errnoValue = connectErrno != 0 ? connectErrno : errno
            if errnoValue != EINPROGRESS && errnoValue != EALREADY {
                _ = cprisk_close_direct(fd, nil)
                return nil
            }
            guard waitWritable(fd, timeoutMs: timeoutMs) else {
                _ = cprisk_close_direct(fd, nil)
                return nil
            }
            var socketError: CInt = 0
            var optLen = socklen_t(MemoryLayout<CInt>.size)
            if getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &optLen) != 0 || socketError != 0 {
                _ = cprisk_close_direct(fd, nil)
                return nil
            }
        }

        return fd
    }

    /// 设置 fd 的发送/接收超时，单位换算为 timeval。
    private func applySocketTimeouts(fd: Int32, timeoutMs: Int32) {
        let sec = Int(timeoutMs / 1000)
        let usec = Int32((timeoutMs % 1000) * 1000)
        var sendTimeout = timeval(tv_sec: sec, tv_usec: usec)
        var recvTimeout = timeval(tv_sec: sec, tv_usec: usec)
        _ = setsockopt(
            fd,
            SOL_SOCKET,
            SO_SNDTIMEO,
            &sendTimeout,
            socklen_t(MemoryLayout<timeval>.size)
        )
        _ = setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &recvTimeout,
            socklen_t(MemoryLayout<timeval>.size)
        )
    }

    /// 构造主动 wire 探针负载列表。
    private func activeWireProbeDatas() -> [Data] {
        ObfuscatedConstants.fridaProtocolActiveWirePayloads.map { Data($0.utf8) }
    }

    /// 等待并读取一次回包，交给协议分类器。
    private func receiveProtocolFingerprint(fd: Int32, timeoutMs: Int32) -> String? {
        guard waitReadable(fd, timeoutMs: timeoutMs) else { return nil }
        var buffer = [UInt8](repeating: 0, count: 256)
        let readCount = recv(fd, &buffer, buffer.count, 0)
        guard readCount > 0 else { return nil }
        return Self.classifyFridaProtocolBytes(Array(buffer.prefix(Int(readCount))))
    }

    /// 在已连接 fd 上发送探针并解析回包。
    private func tryActiveProbe(fd: Int32, payload: Data, timeoutMs: Int32) -> String? {
        payload.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            _ = send(fd, base, payload.count, 0)
        }
        return receiveProtocolFingerprint(fd: fd, timeoutMs: timeoutMs)
    }

    /// 新建连接后发送探针（用于逐个负载重试）。
    private func tryActiveProbe(port: Int, payload: Data, timeoutMs: Int32) -> String? {
        guard let fd = connectLocalStream(port: port, timeoutMs: timeoutMs) else { return nil }
        defer { _ = cprisk_close_direct(fd, nil) }
        applySocketTimeouts(fd: fd, timeoutMs: timeoutMs)
        return tryActiveProbe(fd: fd, payload: payload, timeoutMs: timeoutMs)
    }

    /// poll 等待 fd 可写（连接完成）。
    private func waitWritable(_ fd: Int32, timeoutMs: Int32) -> Bool {
        var descriptor = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        let ready = withUnsafeMutablePointer(to: &descriptor) { ptr in
            poll(ptr, 1, timeoutMs)
        }
        return ready > 0 && (descriptor.revents & Int16(POLLOUT)) != 0
    }

    /// poll 等待 fd 可读；POLLHUP 也视为可读，便于读取对端关闭前的数据。
    private func waitReadable(_ fd: Int32, timeoutMs: Int32) -> Bool {
        var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        let ready = withUnsafeMutablePointer(to: &descriptor) { ptr in
            poll(ptr, 1, timeoutMs)
        }
        let readableMask = Int16(POLLIN | POLLHUP)
        return ready > 0 && (descriptor.revents & readableMask) != 0
    }

    /// 测试入口：对单个 recv 缓冲区做协议分类。
    /// Unit tests: structural + legacy literal classification for one recv buffer.
    internal static func classifyFridaWireResponseForTesting(_ data: Data) -> String? {
        classifyFridaProtocolBytes(Array(data))
    }

    /// 根据回包内容识别 Frida/D-Bus/SASL 协议指纹。
    /// 返回混淆后的 token 字符串；无法识别返回 nil。
    private static func classifyFridaProtocolBytes(_ raw: [UInt8]) -> String? {
        guard !raw.isEmpty else { return nil }

        // 特征 token 运行时解码，明文不驻留二进制常量区。
        let fridaTok = Self.protoToken(label: ObfuscatedConstants.fridaProtoLabelFnFrida, enc: [0x0f, 0x3e, 0x6c, 0x77, 0x8e])
        let gumTok = Self.protoToken(label: ObfuscatedConstants.fridaProtoLabelGum, enc: [0xee, 0xcc, 0x4e])
        let reFridaTok = Self.protoToken(label: ObfuscatedConstants.fridaProtoLabelReFrida, enc: [0x62, 0x0d, 0x3e, 0x3b, 0x52, 0x9d, 0xea, 0xc7])
        let dbusTok = Self.protoToken(label: ObfuscatedConstants.fridaProtoLabelDbus, enc: [0x1e, 0x63, 0xe8, 0xc6])
        let authTok = Self.protoToken(label: ObfuscatedConstants.fridaProtoLabelAuth, enc: [0xca, 0x31, 0x82, 0x18])
        let rejectTok = Self.protoToken(label: ObfuscatedConstants.fridaProtoLabelReject, enc: [0x94, 0x8f, 0xdf, 0x74, 0x92, 0xab])
        let dbusAuthTok = Self.protoToken(label: ObfuscatedConstants.fridaProtoLabelDbusAuth, enc: [0x4b, 0xb0, 0x51, 0x07, 0x01, 0xdf, 0x65, 0x43, 0x6c])

        let saslOkTok = Self.protoToken(label: ObfuscatedConstants.fridaProtoLabelSaslOK, enc: [163, 108, 24, 206, 57, 195, 121])
        let saslRejTok = Self.protoToken(label: ObfuscatedConstants.fridaProtoLabelSaslRej, enc: [84, 17, 246, 115, 133, 52, 33, 250])
        let dbusWireTok = Self.protoToken(label: ObfuscatedConstants.fridaProtoLabelDbusWire, enc: [188, 211, 249, 16, 118, 32, 94, 49, 195])

        // 文本层先做包含匹配，覆盖 Frida/Gum/re:frida 等版本差异。
        let response = String(decoding: raw, as: UTF8.self).lowercased()
        if response.contains(fridaTok) { return fridaTok }
        if response.contains(gumTok) { return gumTok }
        if response.contains(reFridaTok) { return reFridaTok }
        if response.contains(dbusTok) { return dbusTok }
        if response.contains(authTok), response.contains(rejectTok) { return dbusAuthTok }

        // SASL 首行判定：OK / rejected / data 三类认证阶段回包。
        if let firstLine = response.split(separator: "\r", maxSplits: 1, omittingEmptySubsequences: false).first {
            let t = String(firstLine).trimmingCharacters(in: .whitespacesAndNewlines)
            if t == "ok" || t.hasPrefix("ok ") { return saslOkTok }
            if t.hasPrefix("rejected") || t.hasPrefix("error") { return saslRejTok }
            if t == "data" || t.hasPrefix("data ") { return dbusWireTok }
        }

        // D-Bus 报文头结构校验：端序、协议版本、消息类型、体长上限。
        if raw.count >= 16 {
            let endian = raw[0]
            if endian == 0x6c || endian == 0x42 {
                let msgType = raw[1]
                let ver = raw[3]
                if ver == 1, (1...8).contains(msgType) {
                    let bodyLen: UInt32
                    if endian == 0x6c {
                        bodyLen = UInt32(raw[4]) | UInt32(raw[5]) << 8 | UInt32(raw[6]) << 16 | UInt32(raw[7]) << 24
                    } else {
                        bodyLen = UInt32(raw[7]) | UInt32(raw[6]) << 8 | UInt32(raw[5]) << 16 | UInt32(raw[4]) << 24
                    }
                    // 体长上限 128MB，避免畸形长度字段造成误判或后续解析风险。
                    if bodyLen < 128 * 1024 * 1024 {
                        return dbusWireTok
                    }
                }
            }
        }

        return nil
    }

    /// 应用 C 侧多路运行时快照，返回命中的通道数。
    /// 通道：镜像路径、dlsym(Gum)、进程表、行为位图；≥2 通道叠加 runtime_fused。
    /// CRiskCore 多路运行时信号：镜像路径 / dlsym(Gum) / 进程表；双通道及以上叠加 `runtime_fused` 提高置信。
    @discardableResult
    private func applyFridaRuntimeCRiskSignals(score: inout Double, methods: inout [String]) -> Int {
        var snap = cprisk_frida_runtime_snapshot_t()
        // C 侧不支持（旧系统/受限环境）时静默降级为 0，不阻塞其他 Swift 层检测。
        guard cprisk_frida_runtime_snapshot(&snap) == 0, snap.supported != 0 else {
            return 0
        }

        let imageBit = UInt32(CPRISK_FRIDA_RT_IMAGE)
        let dlsymBit = UInt32(CPRISK_FRIDA_RT_DLSYM)
        let procBit = UInt32(CPRISK_FRIDA_RT_PROC)
        let behaviorBit = UInt32(CPRISK_FRIDA_RT_BEHAVIOR)

        // 每个通道独立计分，避免某一通道的权重压过其他证据。
        var channelCount = 0
        if (snap.flags & imageBit) != 0 {
            channelCount += 1
            score += 6
            methods.append(
                "\(ObfuscatedConstants.methodPrefixFridaRuntime)image_hits_\(snap.image_hit_count)"
            )
        }
        if (snap.flags & dlsymBit) != 0 {
            channelCount += 1
            score += 8
            methods.append(
                "\(ObfuscatedConstants.methodPrefixFridaRuntime)dlsym_hits_\(snap.dlsym_hit_count)"
            )
        }
        if (snap.flags & procBit) != 0 {
            channelCount += 1
            score += 7
            methods.append(
                "\(ObfuscatedConstants.methodPrefixFridaRuntime)proc_hits_\(snap.proc_hit_count)"
            )
        }
        if (snap.flags & behaviorBit) != 0 {
            channelCount += 1
            let behaviorMethods = Self.mapRuntimeBehaviorMethods(
                flags: snap.behavior_flags,
                hitCount: snap.behavior_hit_count
            )
            if !behaviorMethods.isEmpty {
                score += min(10 + Double(max(0, behaviorMethods.count - 1)) * 3, 18)
                methods.append(contentsOf: behaviorMethods)
            }
        }
        // 两个及以上通道同时命中说明多个独立侧信道都观察到 Frida，显著提高置信。
        if channelCount >= 2 {
            score += 18
            methods.append(
                "\(ObfuscatedConstants.methodPrefixFridaRuntimeFused)channels_\(channelCount)"
            )
        }
        return channelCount
    }

    /// 汇总 prologue 分支、inline hook、dyld interpose/env 三类运行时表面命中。
    private func detectHookedRuntimeSurfaces() -> DetectorResult {
        // 复用其他检测器并统一映射到 frida:patch / frida:behavior 前缀，避免重复实现。
        let prologueResult = (try? PrologueBranchDetector().detect()) ?? .empty
        let inlineResult = MemoryIntegrityChecker().detectInlineHookTraces()
        let dyldResult = (try? DyldInterposeDetector().detect()) ?? .empty

        let mappedMethods = Self.mapHookSurfaceMethods(
            prologueMethods: prologueResult.methods,
            inlineMethods: inlineResult.methods,
            dyldMethods: dyldResult.methods
        )
        guard !mappedMethods.isEmpty else { return .empty }

        // patch 类命中每项 5 分、behavior 类每项 4 分，封顶 18。
        let patchCount = mappedMethods.filter { $0.hasPrefix(Self.methodPrefixPatch) }.count
        let behaviorCount = mappedMethods.filter { $0.hasPrefix(Self.methodPrefixBehavior) }.count
        let totalScore = min(Double(patchCount) * 5 + Double(behaviorCount) * 4, 18)
        return DetectorResult(score: totalScore, methods: mappedMethods)
    }

    /// 把各检测器的方法名规范化为 Frida 统一前缀。
    internal static func mapHookSurfaceMethods(
        prologueMethods: [String],
        inlineMethods: [String],
        dyldMethods: [String]
    ) -> [String] {
        var mapped = Set<String>()

        for method in prologueMethods {
            if let symbol = method.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: true).last {
                if method.hasPrefix("prologue_branch:") {
                    mapped.insert("\(methodPrefixPatch)prologue_branch:\(symbol)")
                } else if method.hasPrefix("prologue_unreadable:") {
                    mapped.insert("\(methodPrefixPatch)prologue_unreadable:\(symbol)")
                }
            }
        }

        for method in inlineMethods {
            if let detail = method.split(separator: ":", maxSplits: 2, omittingEmptySubsequences: true).last {
                if method.hasPrefix("memory_integrity:inline_hook:") {
                    mapped.insert("\(methodPrefixPatch)inline_hook:\(detail)")
                } else if method.hasPrefix("memory_integrity:unreadable:") {
                    mapped.insert("\(methodPrefixPatch)inline_unreadable:\(detail)")
                }
            }
        }

        for method in dyldMethods {
            if let detail = method.dyldBehaviorDetail {
                if method.hasPrefix("dyld_interpose:") {
                    mapped.insert("\(methodPrefixBehavior)dyld_interpose:\(detail)")
                } else if method.hasPrefix("dyld_env:") {
                    mapped.insert("\(methodPrefixBehavior)dyld_env:\(detail.lowercased())")
                } else if method.hasPrefix("dyld_image_count:") {
                    mapped.insert("\(methodPrefixBehavior)dyld_image_count:\(detail)")
                }
            }
        }

        return mapped.sorted()
    }

    /// 把 C 侧行为位图映射为 frida:behavior:* 方法名。
    private static func mapRuntimeBehaviorMethods(
        flags: UInt32,
        hitCount: UInt32
    ) -> [String] {
        guard flags != 0 else { return [] }

        var mapped = Set<String>()
        if (flags & UInt32(CPRISK_FRIDA_RT_BEHAVIOR_PROLOGUE)) != 0 {
            mapped.insert("\(methodPrefixBehavior)runtime_prologue")
        }
        if (flags & UInt32(CPRISK_FRIDA_RT_BEHAVIOR_TRAMPOLINE)) != 0 {
            mapped.insert("\(methodPrefixBehavior)runtime_trampoline")
        }
        if (flags & UInt32(CPRISK_FRIDA_RT_BEHAVIOR_FOREIGN_EXEC)) != 0 {
            mapped.insert("\(methodPrefixBehavior)runtime_foreign_exec")
        }
        if (flags & UInt32(CPRISK_FRIDA_RT_BEHAVIOR_TRUST_SURFACE)) != 0 {
            mapped.insert("\(methodPrefixBehavior)runtime_trust_surface")
        }
        // 多个表面或多次命中时追加 runtime_multi_surface，作为组合证据。
        if mapped.count >= 2 || hitCount >= 2 {
            mapped.insert("\(methodPrefixBehavior)runtime_multi_surface")
        }
        return mapped.sorted()
    }

    /// 内存签名命中：先试外部 hook，再走内置扫描。
    private func detectMemorySignatureHit() -> String? {
        // 外部 hook 仅在 DEBUG + 环境变量开启时可用。
        if hookMemorySignatureScanEnabled {
            let hooks = Self.hookState.withLock { $0 }
            for hook in hooks {
                guard let hit = hook()?.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines),
                      !hit.isEmpty else {
                    continue
                }
                return hit
            }
        }

        // 内置扫描自带节流，重复调用不会造成高频全内存遍历。
        if let builtinHit = FridaBuiltinMemorySignatureScanner.scanIfNeeded() {
            return builtinHit
        }
        return nil
    }

    /// 通过 CRiskCore 安全直调判断文件存在，绕过 libc access hook。
    private func fileExists(path: String) -> Bool {
        SVCDirectCall.secureAccess(path) == true
    }

    /// 通过 CRiskCore 安全直调判断 stat 成功，与 access 结果交叉验证。
    private func statFileExists(path: String) -> Bool {
        SVCDirectCall.secureStat(path) == true
    }
}

/// String 辅助：从 dyld:* 方法名中提取冒号后的细节。
private extension String {
    /// 返回第二个冒号之后的内容；无细节返回 nil。
    var dyldBehaviorDetail: String? {
        let detail = split(separator: ":", maxSplits: 2, omittingEmptySubsequences: true)
            .dropFirst()
            .joined(separator: ":")
        return detail.isEmpty ? nil : detail
    }
}
