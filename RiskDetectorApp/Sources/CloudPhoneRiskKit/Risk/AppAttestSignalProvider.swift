// 上报链路·硬件信任根信号源：探测 App Attest 能力，向评分引擎提供硬件信任信号。
// 本文件不发起网络请求、不参与信封签名；能力缺失时发出 95 分硬信号，信号随报告一起上报。

import Foundation
#if canImport(DeviceCheck)
import DeviceCheck
#endif

/// App Attest 硬件信任根信号提供者（SDK 4.4）。
/// 当 `DCAppAttestService.isSupported` 为 false 时，发出 `hardware_trust_unsupported`（权重 95）。
/// 线程模型：无共享可变状态，可被多个评估任务并发调用。
/// 安全不变量：只证明“系统声称支持”，`true` 不代表证明链有效——真实证明见 `AppAttestSigner` 与实际探针。
final class AppAttestSignalProvider: RiskSignalProvider {

    /// 进程级单例，避免重复探测与重复注册。
    static let shared = AppAttestSignalProvider()
    /// 信号源稳定标识，供注册表与诊断使用。
    let id = "app_attest"

    private init() {}

    /// 返回硬件信任根异常信号；支持 App Attest 时返回空数组。
    /// 信号只在本地参与评分，随后随报告 payload 上报，不包含任何密钥材料。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        // 支持硬件信任根时保持良性路径零噪音；只有明确不支持才判为异常。
        guard !Self.isHardwareTrustSupported else {
            return []
        }
        // 模拟器/黑苹果/QEMU/无效 App ID 通常没有可用的 Secure Enclave，按硬信号处理。
        return [
            RiskSignal(
                id: "hardware_trust_unsupported",
                category: "hardware_trust",
                score: 95,
                evidence: [
                    "reason": "DCAppAttestService.isSupported=false",
                    "hint": "模拟器/黑苹果/QEMU/虚拟机或无效 App ID",
                ],
                state: .hard(detected: true),
                layer: 1,
                weightHint: 95
            )
        ]
    }

    /// 运行时检测：当前环境是否支持 App Attest 硬件信任根。
    /// iOS 14 以下、未链接 DeviceCheck 或能力查询失败时一律按“不支持”处理（fail-closed）。
    static var isHardwareTrustSupported: Bool {
        #if canImport(DeviceCheck)
        if #available(iOS 14.0, macOS 11.0, *) {
            return DCAppAttestService.shared.isSupported
        }
        #endif
        return false
    }
}
