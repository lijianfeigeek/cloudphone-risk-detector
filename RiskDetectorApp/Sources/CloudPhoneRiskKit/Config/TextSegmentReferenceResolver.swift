// CloudPhoneRiskKit 远程配置模块：__TEXT.__text 服务端参考哈希的解析抽象。
// 可信哈希由服务端预计算并经配置签名保护后下发，本文件只负责解析与注入扩展点，
// 不自行生成基线，避免越狱设备篡改本地基线后绕过代码段完整性校验。

import Foundation

/// __TEXT.__text 服务端参考哈希的本地解析结果。
///
/// `expectedHash` 应来自服务端预计算结果或其签名缓存，不应来自设备本地基线。
public struct TextSegmentReference: Codable, Sendable {
    /// 服务端计算的可信代码段哈希（hex 字符串）。
    public let expectedHash: String
    /// 哈希来源标识，用于区分服务端预计算、审计缓存等渠道。
    public let source: String
    /// 生成该哈希时的 SDK 版本；`nil` 表示未标注。
    public let version: String?

    // 线协议使用单字母短键以压缩配置体积，Codable 自动完成映射。
    private enum CodingKeys: String, CodingKey {
        case expectedHash = "eh"
        case source = "s"
        case version = "v"
    }

    /// 创建一个参考哈希记录。
    /// - Parameters:
    ///   - expectedHash: 服务端可信的代码段哈希。
    ///   - source: 来源标识，默认 `custom`。
    ///   - version: 对应 SDK 版本，可选。
    public init(expectedHash: String, source: String = "custom", version: String? = nil) {
        self.expectedHash = expectedHash
        self.source = source
        self.version = version
    }
}

/// 可选的参考哈希解析扩展点。
///
/// 默认情况下 SDK 会使用 `RemoteConfig.textSegmentHashReference`。
/// 若业务方已有独立的签名配置中心，可注入该解析器覆盖默认来源。
public protocol TextSegmentReferenceResolving: Sendable {
    /// 返回指定 SDK 版本的可信参考哈希；返回 `nil` 时 SDK 会回退到默认 RemoteConfig 解析。
    ///
    /// 该方法应只访问本地已验证缓存或内存快照，不建议在检测链路中发起网络请求。
    func resolveTextSegmentReference(for sdkVersion: String) -> TextSegmentReference?
}
