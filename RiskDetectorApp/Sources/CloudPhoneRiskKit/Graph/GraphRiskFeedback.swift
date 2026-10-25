// 图风控反馈协议：承载服务端图计算返回的风险特征。
// 位于“服务端图计算 → 端侧评分增强”链路的入口，由 ExternalServerAggregateProvider 注入。
// 安全不变量：反馈值可能影响本地判决，必须来自可信/验签通道；
// 本协议只读、不可变，不包含任何设备明文标识。

import Foundation

// MARK: - 图风控反馈协议
///
/// 服务端返回图计算结果后，通过此协议注入 ExternalServerAggregateProvider，
/// 用于增强本地评分与决策。
public protocol GraphRiskFeedback: Sendable {
    /// 所属社区 ID；nil 表示未参与社区划分。
    var communityId: String? { get }
    /// 社区风险密度（0–1 或服务端定义区间）。
    var communityRiskDensity: Double? { get }
    /// 硬件画像在社区图中的度数。
    var hwProfileDegree: Int? { get }
    /// 设备在图中的 PageRank 分值。
    var devicePageRank: Double? { get }
    /// 是否位于高密度子图（风险聚集区）。
    var isInDenseSubgraph: Bool? { get }
    /// 服务端附加的风险标签。
    var riskTags: [String]? { get }
}

// MARK: - 默认实现
/// 图反馈的默认不可变值类型实现；所有字段可选，便于只回传部分结果。
public struct DefaultGraphRiskFeedback: GraphRiskFeedback, Sendable {
    public let communityId: String?
    public let communityRiskDensity: Double?
    public let hwProfileDegree: Int?
    public let devicePageRank: Double?
    public let isInDenseSubgraph: Bool?
    public let riskTags: [String]?

    /// 创建反馈对象；未提供的字段按 nil 处理，不影响本地默认评分逻辑。
    public init(
        communityId: String? = nil,
        communityRiskDensity: Double? = nil,
        hwProfileDegree: Int? = nil,
        devicePageRank: Double? = nil,
        isInDenseSubgraph: Bool? = nil,
        riskTags: [String]? = nil
    ) {
        self.communityId = communityId
        self.communityRiskDensity = communityRiskDensity
        self.hwProfileDegree = hwProfileDegree
        self.devicePageRank = devicePageRank
        self.isInDenseSubgraph = isInDenseSubgraph
        self.riskTags = riskTags
    }
}
