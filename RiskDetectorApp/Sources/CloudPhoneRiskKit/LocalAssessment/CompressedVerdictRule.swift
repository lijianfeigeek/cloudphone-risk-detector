// 压缩摘要快速判决规则：用位掩码直接匹配 SignalCompressor 输出的分层摘要。
// 规则随 ScenarioPolicy 下发，命中后无需展开完整信号即可给出处置动作。
// 适用于低延迟通道，是常规评分链路之外的补充判定。

import Foundation

// MARK: - 压缩摘要快速判决规则
///
/// 纯位向量规则：基于压缩摘要的快速判决通道（1.0=8 字节，1.1=9 字节）。
/// 规则格式：layerIndex (1-4 层摘要、5=crossLayer、6=byte8 行为熵)、bitMask、matchValue、action。
/// 若 (layerValue & bitMask) == matchValue，则规则命中。
///
/// 示例：layer2 & 0x0C != 0 --> block
/// 可配置为 layerIndex=2, bitMask=0x0C, matchValue=0x04 (jailbreak bit), action=block
public struct CompressedVerdictRule: Codable, Sendable {

    /// 规则唯一标识，用于服务端回溯与命中埋点。
    public let id: String
    /// 摘要层号：1–4 对应第 1–4 层单字节摘要，5 表示跨层聚合值，6 表示行为熵字节。
    public let layerIndex: Int
    /// 位掩码，只保留关心的位；按层号自动收窄有效宽度。
    public let bitMask: UInt64
    /// 期望的掩码结果；与 `(层值 & bitMask)` 相等即视为命中。
    public let matchValue: UInt64
    /// 命中后建议的处置动作。
    public let action: RiskAction

    // 单字母键压缩 JSON 体积，属于上报/下发协议的一部分，不可随意改名。
    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case layerIndex = "li"
        case bitMask = "bm"
        case matchValue = "mv"
        case action = "a"
    }

    /// 构造一条位向量规则。
    /// - Parameters:
    ///   - id: 规则标识；- layerIndex: 目标摘要层（1–6）；- bitMask: 关注位；
    ///   - matchValue: 期望位值；- action: 命中后的动作。
    public init(
        id: String,
        layerIndex: Int,
        bitMask: UInt64,
        matchValue: UInt64,
        action: RiskAction
    ) {
        self.id = id
        self.layerIndex = layerIndex
        self.bitMask = bitMask
        self.matchValue = matchValue
        self.action = action
    }

    /// 检查压缩摘要是否命中此规则
    /// - Parameter digest: SignalCompressor 输出的摘要（1.0=8 字节，1.1=9 字节）
    /// - Returns: 是否命中
    public func matches(digest: Data) -> Bool {
        // 1.0/1.1 摘要至少 8 字节；不足说明摘要被截断或版本不匹配，按未命中失败关闭。
        guard digest.count >= 8 else { return false }

        let layerValue: UInt64
        switch layerIndex {
        case 1:
            layerValue = UInt64(digest[0])
        case 2:
            layerValue = UInt64(digest[1])
        case 3:
            layerValue = UInt64(digest[2])
        case 4:
            layerValue = UInt64(digest[3])
        case 5:
            // 跨层聚合：bytes 4-7 按大端拼成 32 位值，便于一次比较多个层的联合结论。
            layerValue = UInt64(digest[4]) << 24
                | UInt64(digest[5]) << 16
                | UInt64(digest[6]) << 8
                | UInt64(digest[7])
        case 6:
            // byte8 行为熵（1.1）：仅当 digest 为 9 字节时有效，否则视为 0
            layerValue = digest.count >= 9 ? UInt64(digest[8]) : 0
        default:
            return false
        }

        // 按层实际位宽截断掩码，防止服务端下发超宽掩码时高位误命中。
        let effectiveMask: UInt64
        let effectiveMatch: UInt64
        if layerIndex >= 1 && layerIndex <= 4 {
            // 单层摘要只有 1 字节。
            effectiveMask = bitMask & 0xFF
            effectiveMatch = matchValue & 0xFF
        } else if layerIndex == 6 {
            effectiveMask = bitMask & 0x07  // byte8 仅 bits 0-2 有效
            effectiveMatch = matchValue & 0x07
        } else {
            // crossLayer 为 32 位聚合值。
            effectiveMask = bitMask & 0xFFFF_FFFF
            effectiveMatch = matchValue & 0xFFFF_FFFF
        }

        // 位与后精确等于期望值才算命中；多余位必须为 0，避免“部分匹配”放宽规则。
        return (layerValue & effectiveMask) == effectiveMatch
    }
}
