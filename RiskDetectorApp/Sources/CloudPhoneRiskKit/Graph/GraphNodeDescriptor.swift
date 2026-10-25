// 图节点描述符：端侧向服务端图计算提交的最小关联特征集合。
// 位于“端侧特征采集 → 服务端图计算 → 反馈反哺”链路的出口。
// 隐私边界：所有哈希只是关联提示，不是身份证明，也不能当作租户隔离假名；
// 低熵的 IP/ASN/账号标识刻意不在此结构中。

import Foundation

// MARK: - 图节点描述符
///
/// 客户端声明的关联提示；SHA256 不是隐私保证，也不是可信设备实体。
/// 用于图风控联动：端侧生产特征 → 服务端图计算 → 反哺决策。
public struct GraphNodeDescriptor: Codable, Sendable {
    /// 旧版精确匹配/换机提示；不代表硬件相似度，也不是已解析的设备身份。
    public var hwProfileHash: String

    /// WiFi BSSID 哈希（如可获取，否则省略；iOS 沙箱限制下通常不可用）
    public var bssidHash: String?

    /// 应用安装列表哈希（如可获取，否则省略；iOS 隐私限制下通常不可用）
    public var appListHash: String?

    /// 安装关联提示，与非唯一的硬件相似性属性分开使用。
    public var installationKey: String?
    /// 非唯一的硬件相似性属性（如机型/内核等），仅用于服务端相似度计算。
    public var hardwareAttributes: [String: String]?

    /// 线上编码短键：压缩上报载荷，字段语义保持不变。
    private enum CodingKeys: String, CodingKey {
        case installationKey = "ik"
        case hardwareAttributes = "ha"
        case hwProfileHash = "hp"
        case bssidHash = "bh"
        case appListHash = "al"
    }

    /// 创建图节点描述符。
    /// - Parameters:
    ///   - hwProfileHash: 设备画像哈希（必填，调用方保证非空）。
    ///   - bssidHash/appListHash: 平台无法获取时保持 nil，缺失不得当作“同设备”证据。
    ///   - installationKey: 同一次安装的关联提示。
    ///   - hardwareAttributes: 非唯一硬件属性，供服务端做相似度。
    public init(
        hwProfileHash: String,
        bssidHash: String? = nil,
        appListHash: String? = nil,
        installationKey: String? = nil,
        hardwareAttributes: [String: String]? = nil
    ) {
        self.installationKey = installationKey
        self.hardwareAttributes = hardwareAttributes
        self.hwProfileHash = hwProfileHash
        self.bssidHash = bssidHash
        self.appListHash = appListHash
    }
}
