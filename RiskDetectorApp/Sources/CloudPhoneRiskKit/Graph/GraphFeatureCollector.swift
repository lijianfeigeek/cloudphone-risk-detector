// 图风险特征采集器：把端侧能拿到的设备信息整理成 GraphNodeDescriptor，
// 供服务端图计算（社区发现、设备聚类、PageRank 等）直接入图。
// 注意：这里产出的哈希只是“关联提示”，既不是租户隔离假名，也不是身份证明。
// 低熵的 IP/ASN/账号哈希被刻意省略；账号与网络身份的关联由服务端用租户密钥完成。

import CryptoKit
import Foundation

// MARK: - 图特征采集器
///
/// 自动收集可供图计算的结构化特征，输出 GraphNodeDescriptor，
/// 标准化为服务端可直接入图的格式。
///
/// 客户端摘要仅用于相关性提示，不能当作租户隔离假名或身份证明。
/// 低熵的 IP/ASN/账号哈希被刻意省略；账号与网络身份由服务端使用租户密钥解析。
public enum GraphFeatureCollector {
    /// 硬件画像哈希的域分隔标签：防止同一段输入在不同用途下产生相同摘要。
    /// 该标签是公开常量，不具备盐的保密性。
    private static let hwProfileSaltDomainTag = "cprisk_graph_hwprofile_salt_v1"

    /// 从 RiskSnapshot 与 ServerSignals 收集图节点描述符
    /// - Parameters:
    ///   - snapshot: 风险快照（设备、网络等）
    ///   - serverSignals: 服务端聚合信号（IP、ASN 等；可为 nil）
    ///   - accountId: 已绑定账号 ID（bindAccount；可为 nil）
    /// - Returns: 标准化图节点描述符
    public static func collect(
        snapshot: RiskSnapshot,
        serverSignals: ServerSignals?,
        accountId: String?
    ) -> GraphNodeDescriptor {
        // 硬件画像哈希：由设备 ID + 机型标识 + 型号共同派生，
        // 用于服务端识别“同一硬件画像”的重复出现。
        let hwProfileHash = computeHwProfileHash(
            deviceID: snapshot.deviceID,
            hardwareMachine: snapshot.device.hardwareMachine ?? "",
            model: snapshot.device.model
        )

        // bssidHash / appListHash 在 iOS 沙箱与隐私限制下通常拿不到，
        // 因此保持 nil；服务端不得把缺失当成“同设备”的证据。
        // installationKey 用 deviceID 派生，作为“同一次安装”的关联提示，
        // 与 hardwareAttributes 的非唯一相似性特征分开使用。
        return GraphNodeDescriptor(
            hwProfileHash: hwProfileHash,
            bssidHash: nil,
            appListHash: nil,
            installationKey: sha256Hex("cprisk.installation.v1|\(snapshot.deviceID)"),
            hardwareAttributes: ["hardware_machine": snapshot.device.hardwareMachine ?? "", "model": snapshot.device.model]
        )
    }

    // MARK: - 哈希工具

    /// 设备指纹哈希：SHA256(域标签 + deviceID + hardwareMachine + model)
    ///
    /// 仅用于旧版精确匹配/换机提示；域名标签是公开常量，不是秘密盐。
    /// 判断硬件相似度必须使用 hardwareAttributes，绝不能比较哈希距离。
    private static func computeHwProfileHash(
        deviceID: String,
        hardwareMachine: String,
        model: String
    ) -> String {
        // 用 "|" 分隔各字段，避免字段拼接产生歧义（如 "ab"+"c" 与 "a"+"bc"）。
        let raw = "\(hwProfileSaltDomainTag)|\(deviceID)|\(hardwareMachine)|\(model)"
        return sha256Hex(raw)
    }

    /// 单向 SHA256 哈希，输出小写 hex 字符串。
    /// UTF-8 编码失败时返回空串，调用方需自行处理空值（不要当作有效哈希）。
    private static func sha256Hex(_ input: String) -> String {
        guard let data = input.data(using: .utf8) else { return "" }
        let digest = SHA256.hash(data: data)
        // 每个字节格式化为两位小写十六进制，保证跨平台输出一致。
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
