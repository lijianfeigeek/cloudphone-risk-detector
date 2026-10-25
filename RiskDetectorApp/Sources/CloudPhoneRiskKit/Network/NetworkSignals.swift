// 文件职责：采集网络环境信号（接口类型、计费/受限、VPN、代理、运营商、电量）。
// 管道位置：信号采集层，为本地判决提供网络上下文（`SignalCategory.network`）。
// 安全不变量：代理只上报“是否启用 + 类型”，绝不采集主机、端口或 PAC URL。
import CFNetwork
import CoreTelephony
import Darwin
import Foundation
import Network
#if canImport(UIKit)
import UIKit
#endif

/// 信号置信度：用于裁决阶段加权，避免单一弱证据直接定罪。
public enum SignalConfidence: String, Codable, Sendable {
    /// 弱置信：仅作辅助参考。
    case weak
    /// 中等置信：可与同类信号叠加。
    case medium
    /// 强置信：可作为主要证据。
    case strong
}

/// 通用检测结果：是否命中 + 检测方法 + 可编码证据 + 置信度。
public struct DetectionSignal<Evidence: Codable & Sendable>: Codable, Sendable {
    /// 是否检测到目标特征。
    public var detected: Bool
    public var method: String
    /// 结构化证据；nil 表示不附带细节。
    public var evidence: Evidence?
    /// 判定置信度。
    public var confidence: SignalConfidence

    // 单字母键压缩上报体积，并保持历史序列化格式兼容。
    private enum CodingKeys: String, CodingKey {
        case detected = "d"
        case method = "m"
        case evidence = "e"
        case confidence = "c"
    }

    public init(detected: Bool, method: String, evidence: Evidence? = nil, confidence: SignalConfidence) {
        self.detected = detected
        self.method = method
        self.evidence = evidence
        self.confidence = confidence
    }
}

/// 网络接口类型检测结果（取值如 wifi / cellular / ethernet）。
public struct InterfaceTypeSignal: Codable, Sendable {
    /// 接口类型字符串。
    public var value: String
    public var method: String

    // 压缩键名，减少上报体积。
    private enum CodingKeys: String, CodingKey {
        case value = "v"
        case method = "m"
    }

    public init(value: String, method: String) {
        self.value = value
        self.method = method
    }
}

/// 一次网络环境快照，随报告序列化上报。
/// 所有字段均为尽力采集：平台不支持时以 nil/空值降级，不影响主链路。
public struct NetworkSignals: Codable, Sendable {
    /// 当前主用网络接口类型。
    public var interfaceType: InterfaceTypeSignal
    /// 是否为计费网络（蜂窝/个人热点）。
    public var isExpensive: Bool
    /// 是否处于低数据模式。
    public var isConstrained: Bool
    /// VPN 检测结果，证据为命中的隧道接口名。
    public var vpn: DetectionSignal<[String]>
    /// 代理检测结果，证据仅含启用标志与代理类型。
    public var proxy: DetectionSignal<[String: String]>
    /// 移动国家码；用字符串保留前导零。
    public var mcc: String? = nil
    /// 移动网络码；用字符串保留前导零。
    public var mnc: String? = nil

    /// 电量（0.0–1.0）；监控关闭或不可用时为 nil。
    public var batteryLevel: Double? = nil
    /// 充电状态：charging / unplugged / full / unknown；不可用时为 nil。
    public var batteryState: String? = nil

    // 短键减少上报体积。
    private enum CodingKeys: String, CodingKey {
        case interfaceType = "it"
        case isExpensive = "ie"
        case isConstrained = "ic"
        case vpn = "vp"
        case proxy = "px"
        case mcc = "mc"
        case mnc = "mn"
        case batteryLevel = "bl"
        case batteryState = "bs"
    }

    /// 便捷判定：是否检测到 VPN。
    public var isVPNActive: Bool { vpn.detected }
    /// 便捷判定：是否检测到系统代理。
    public var proxyEnabled: Bool { proxy.detected }

    /// 采集当前网络环境快照。
    /// - 模拟器上跳过 VPN/代理启发式，避免宿主机网络造成误报。
    /// - 任一子采集失败都降级为空值，不抛出错误。
    /// - Returns: 可直接编码上报的 `NetworkSignals`。
    public static func current() -> NetworkSignals {
        let path = NetworkPathSnapshot.shared.snapshot()
        #if targetEnvironment(simulator)
        // 模拟器复用 macOS 宿主网络，VPN/代理启发式极易误报，故直接返回不可用。
        let vpnIfaces: [String] = []
        let proxyEvidence: [String: String] = [:]
        let vpnMethod = "unavailable_simulator"
        let proxyMethod = "unavailable_simulator"
        #else
        let vpnIfaces = VPNDetector.detectedTunnelInterfaces()
        let proxyEvidence = ProxyDetector.proxyEvidence()
        let vpnMethod = "ifaddrs_prefix"
        let proxyMethod = "CFNetworkCopySystemProxySettings"
        #endif

        // 从 CoreTelephony 读取 MCC/MNC；用 String? 保留前导零（如 "001"）。
        var mcc: String?
        var mnc: String?
        #if os(iOS)
        if let providers = CTTelephonyNetworkInfo().serviceSubscriberCellularProviders {
            for (_, provider) in providers {
                // 双卡设备可能有多个运营商；只取第一个作为主卡上报。
                mcc = provider.mobileCountryCode
                mnc = provider.mobileNetworkCode
                break
            }
        }
        #endif

        let signals = NetworkSignals(
            interfaceType: InterfaceTypeSignal(value: path.interfaceType, method: "NWPathMonitor"),
            isExpensive: path.isExpensive,
            isConstrained: path.isConstrained,
            vpn: DetectionSignal(
                detected: !vpnIfaces.isEmpty,
                method: vpnMethod,
                evidence: vpnIfaces.isEmpty ? nil : vpnIfaces,
                confidence: .weak
            ),
            proxy: DetectionSignal(
                detected: !proxyEvidence.isEmpty,
                method: proxyMethod,
                evidence: proxyEvidence.isEmpty ? nil : proxyEvidence,
                confidence: .weak
            ),
            mcc: mcc,
            mnc: mnc,
            batteryLevel: nil,
            batteryState: nil
        )

        let (batteryLevel, batteryState) = Self.captureBattery()
        // 构造后再补电量，避免在每个分支重复采集。
        var mutableSignals = signals
        mutableSignals.batteryLevel = batteryLevel
        mutableSignals.batteryState = batteryState

        // 仅调试构建打印采集结果，避免线上日志泄露网络环境。
        #if DEBUG
        Logger.log("network: iface=\(mutableSignals.interfaceType.value) expensive=\(mutableSignals.isExpensive) constrained=\(mutableSignals.isConstrained) vpn=\(mutableSignals.isVPNActive) proxy=\(mutableSignals.proxyEnabled) mcc=\(String(describing: mcc)) mnc=\(String(describing: mnc)) batteryLevel=\(mutableSignals.batteryLevel.map { String(format: "%.2f", $0) } ?? "nil") batteryState=\(mutableSignals.batteryState ?? "nil")")
        #endif
        return mutableSignals
    }

    /// 采集电量与充电状态。
    /// - 非 UIKit 平台或监控不可用时返回 (nil, nil)。
    /// - 临时开启电池监控后恢复原状态，避免影响宿主 App。
    private static func captureBattery() -> (level: Double?, state: String?) {
        #if canImport(UIKit)
        let wasEnabled = UIDevice.current.isBatteryMonitoringEnabled
        UIDevice.current.isBatteryMonitoringEnabled = true
        defer { UIDevice.current.isBatteryMonitoringEnabled = wasEnabled }
        let rawLevel = UIDevice.current.batteryLevel
        // 监控不可用时 batteryLevel 为 -1.0，此时按不可用降级。
        guard rawLevel >= 0 else { return (nil, nil) }
        let state: UIDevice.BatteryState = UIDevice.current.batteryState
        let stateStr: String
        switch state {
        case .unknown: stateStr = "unknown"
        case .unplugged: stateStr = "unplugged"
        case .charging: stateStr = "charging"
        case .full: stateStr = "full"
        @unknown default: stateStr = "unknown"
        }
        return (Double(rawLevel), stateStr)
        #else
        return (nil, nil)
        #endif
    }
}

/// 基于 `NWPathMonitor` 的单例网络路径快照缓存（异步更新，读取不阻塞）。
private final class NetworkPathSnapshot {
    static let shared = NetworkPathSnapshot()
    /// 系统网络路径监控器。
    private let monitor = NWPathMonitor()
    /// 串行队列，驱动 NWPathMonitor 回调。
    private let queue = DispatchQueue(label: "CloudPhoneRiskKit.NetworkPathMonitor")
    /// 保护 `latest` 与 `started`。
    private let lock = UnfairLock()
    /// 最近一次路径更新；尚未收到回调时为 nil。
    private var latest: NWPath?
    /// 保证 monitor 只启动一次。
    private var started = false

    private init() {}

    /// 读取最新路径快照；尚未就绪时返回 unknown/非计费/非受限的保守值。
    /// - Returns: 接口类型字符串、是否计费、是否受限。
    func snapshot() -> (interfaceType: String, isExpensive: Bool, isConstrained: Bool) {
        startIfNeeded()
        let path = lock.withLock { latest }
        guard let path else {
            return ("unknown", false, false)
        }

        // 将 NWPath 接口类型映射为稳定的字符串枚举，未知类型统一为 other。
        let type: String
        if path.usesInterfaceType(.wifi) { type = "wifi" }
        else if path.usesInterfaceType(.cellular) { type = "cellular" }
        else if path.usesInterfaceType(.wiredEthernet) { type = "ethernet" }
        else if path.usesInterfaceType(.loopback) { type = "loopback" }
        else { type = "other" }

        return (type, path.isExpensive, path.isConstrained)
    }

    /// 惰性启动路径监控：首次读取时启动，后续读取直接命中缓存。
    private func startIfNeeded() {
        // 在锁内完成“检查并置位”，避免并发重复启动 monitor。
        let shouldStart = lock.withLock {
            let s = !started
            if s { started = true }
            return s
        }
        guard shouldStart else { return }
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            self.lock.withLock {
                self.latest = path
            }
        }
        monitor.start(queue: queue)
    }
}

/// 代理检测器：读取系统代理配置，仅输出布尔特征与代理类型。
enum ProxyDetector {
    /// 代理证据：只上报是否启用 + 类型（`pac_enabled` / `http_proxy_enabled` /
    /// `proxy_type`），不上报主机、端口、PAC URL。代理主机/端口与完整 PAC URL
    /// 可能泄露用户所用代理服务的身份与配置，属于敏感网络信息，风控判决
    /// 只需要“是否经代理”与代理类型，不需要具体端点。
    static func proxyEvidence() -> [String: String] {
        guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
            return [:]
        }

        let httpEnabled = (settings[kCFNetworkProxiesHTTPEnable as String] as? NSNumber)?.boolValue ?? false
        #if os(macOS)
        let httpsEnabled = (settings[kCFNetworkProxiesHTTPSEnable as String] as? NSNumber)?.boolValue ?? false
        let socksEnabled = (settings[kCFNetworkProxiesSOCKSEnable as String] as? NSNumber)?.boolValue ?? false
        #else
        // HTTPS/SOCKS 独立设置是桌面端 CFNetwork API；
        // iOS 通过下面的键暴露 HTTP 代理与 PAC 配置。
        let httpsEnabled = false
        let socksEnabled = false
        #endif
        let pacEnabled = (settings[kCFNetworkProxiesProxyAutoConfigEnable as String] as? NSNumber)?.boolValue ?? false

        var out: [String: String] = [:]
        if pacEnabled {
            out["pac_enabled"] = "true"
        }
        if httpEnabled || httpsEnabled {
            out["http_proxy_enabled"] = "true"
        }
        if socksEnabled {
            out["socks_proxy_enabled"] = "true"
        }
        var types: [String] = []
        if pacEnabled { types.append("pac") }
        if httpEnabled || httpsEnabled { types.append("http") }
        if socksEnabled { types.append("socks") }
        if !types.isEmpty {
            out["proxy_type"] = types.joined(separator: ",")
        }
        return out
    }
}

/// VPN 检测器：通过 ifaddrs 枚举常见隧道接口名。
enum VPNDetector {
    /// 枚举常见 VPN 隧道接口名（utun/ppp/ipsec 前缀）。
    /// - 仅作为弱信号使用，不单独构成云手机/模拟器判决。
    /// - Returns: 去重并排序的接口名列表；系统调用失败时为空数组。
    static func detectedTunnelInterfaces() -> [String] {
        // 尽力而为：只匹配常见隧道接口名前缀；iOS 沙箱无法深入检查。
        // 这是信号而非判决，需与其他证据联合使用。
        var addresses: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&addresses) == 0, let first = addresses else { return [] }
        // 必须释放 getifaddrs 分配的链表。
        defer { freeifaddrs(addresses) }

        var out: [String] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            let name = String(cString: current.pointee.ifa_name)
            if name.hasPrefix("utun") || name.hasPrefix("ppp") || name.hasPrefix("ipsec") {
                out.append(name)
            }
            cursor = current.pointee.ifa_next
        }
        return Array(Set(out)).sorted()
    }
}
