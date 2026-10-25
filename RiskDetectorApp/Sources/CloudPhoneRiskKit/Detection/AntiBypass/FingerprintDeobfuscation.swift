// 指纹去混淆/突变检测：云手机与模拟器常通过 hook 或字段改写把硬件指纹“洗白”，
// 本文件从模拟器特征、虚拟化硬件型号、虚拟化文件痕迹三个角度识别伪造环境，
// 并把设备指纹签名持久化到 Keychain，用跨会话变化检测运行期的指纹篡改。
// 指纹签名只包含机型/内存/CPU/屏幕等粗粒度字段，不含任何用户数据。

import Darwin
import Foundation
import Security
#if canImport(UIKit)
import UIKit
#endif

/// 反绕过检测器：识别“指纹被去混淆/改写”的环境。
///
/// 安全不变量：Keychain 项使用 `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`，
/// 不随 iCloud/备份迁移到其他设备，确保基线只代表本机；设备重置后基线自然重建。
struct FingerprintDeobfuscation: Detector {

    // 服务名/账号是持久化契约，改动会导致旧基线读不到并在下一次评估中重建。
    private static let keychainService = "CloudPhoneRiskKit"
    private static let keychainAccount = "fingerprint_signature_v1"
    private static let keychainAccessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

    /// 读取上一次记录的本机指纹签名；不存在或读取失败返回 nil。
    private static func keychainRead() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// 写入/更新本机指纹签名；先 update 再按需 add，避免覆盖已有 Keychain 项的访问属性。
    private static func keychainWrite(value: String) {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: keychainAccessible,
        ]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var addQuery = query
            addQuery[kSecValueData as String] = data
            addQuery[kSecAttrAccessible as String] = keychainAccessible
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            if addStatus != errSecSuccess {
                Logger.log("FingerprintDeobfuscation.keychainWrite: SecItemAdd failed (status=\(addStatus))")
            }
        }
    }

    /// 汇总四类指纹异常；各项独立加分，便于后端区分攻击维度。
    /// 阈值取舍：指纹变化仅 +12，因为系统升级/外接屏幕也可能改变粗粒度字段，属弱证据。
    func detect() throws -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []

        if isSimulatorLikeEnvironment() {
            score += 30
            methods.append("fingerprint:simulator_like")
        }

        if hasSuspiciousHardwareModel() {
            score += 20
            methods.append("fingerprint:suspicious_hw_model")
        }

        if hasVirtualizationArtifacts() {
            score += 25
            methods.append("fingerprint:virtualization_artifact")
        }

        if hasFingerprintMutation() {
            score += 12
            methods.append("fingerprint:fingerprint_changed")
        }

        return DetectorResult(score: score, methods: methods)
    }

    /// 识别模拟器/X86 运行环境；真机上 hw.machine 应为 arm64 机型标识。
    private func isSimulatorLikeEnvironment() -> Bool {
#if targetEnvironment(simulator)
        return true
#else
        let machine = (Sysctl.string("hw.machine") ?? "").lowercased()
        return machine.contains("x86") || machine.contains("simulator")
#endif
    }

    /// 识别虚拟化平台暴露的硬件型号关键词；空型号视为未知而不加分，避免误伤。
    private func hasSuspiciousHardwareModel() -> Bool {
        let model = (Sysctl.string("hw.model") ?? "").lowercased()
        if model.isEmpty { return false }
        let keywords = ["vmware", "virtualbox", "qemu", "parallels", "kvm"]
        return keywords.contains { model.contains($0) }
    }

    /// 检查虚拟化/Linux 宿主才有的文件路径；iOS 沙箱内正常情况下均不可见。
    private func hasVirtualizationArtifacts() -> Bool {
        let paths = [
            "/sys/hypervisor",
            "/sys/class/dmi/id/product_name",
            "/Applications/Simulator.app"
        ]
        for path in paths {
            if access(path, F_OK) == 0 {
                return true
            }
        }
        return false
    }

    /// 比较当前指纹签名与 Keychain 基线；变化时更新基线并返回 true。
    /// 首次运行只写基线不告警，避免把“首次采集”误报为篡改。
    private func hasFingerprintMutation() -> Bool {
        let fingerprint = collectFingerprintSignature()

        if let old = Self.keychainRead() {
            if old != fingerprint {
                Self.keychainWrite(value: fingerprint)
                return true
            }
            return false
        }

        Self.keychainWrite(value: fingerprint)
        return false
    }

    /// 生成稳定的粗粒度指纹字符串：机型、型号、内存、CPU 核数、屏幕尺寸/缩放。
    /// 刻意不包含序列号、IDFA 等可识别个人的字段，且屏幕信息在非 UIKit 平台降级为 unknown。
    private func collectFingerprintSignature() -> String {
        let machine = Sysctl.string("hw.machine") ?? "unknown"
        let model = Sysctl.string("hw.model") ?? "unknown"
        let memory = Sysctl.int64("hw.memsize") ?? 0
        let cpu = ProcessInfo.processInfo.processorCount

#if canImport(UIKit)
        let bounds = UIScreen.main.bounds
        let scale = UIScreen.main.scale
        let screen = "\(Int(bounds.width))x\(Int(bounds.height))@\(scale)"
#else
        let screen = "unknown"
#endif

        return "\(machine)|\(model)|\(memory)|\(cpu)|\(screen)"
    }
}
