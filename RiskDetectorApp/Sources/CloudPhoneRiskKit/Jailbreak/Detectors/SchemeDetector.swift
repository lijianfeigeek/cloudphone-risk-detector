// URL Scheme 检测器：用 canOpenURL 探测越狱商店/工具的自定义 scheme 是否被安装。
// 位于越狱检测管道中 `enableSchemeDetect` 分支（仅 UIKit 平台），是“越狱应用已安装”的旁证。
// 关键安全不变量：一旦发现 canOpenURL 相关 Hook 面，宁可跳过探测也不采信可能被伪造的 NO 结果。
import Foundation
#if canImport(UIKit)
import UIKit

/// 通过 URL Scheme 探测 Cydia/Sileo/Filza 等越狱应用是否已安装。
/// 检测什么：`cydia://`、`sileo://`、`zbra://`、`filza://`、`undecimus://` 能否被打开。
/// 命中后产生 `scheme:<scheme>` 信号，单项 10–20 分，总分封顶 100。
/// 误报风险：用户可能安装了非越狱用途的同名 scheme 应用；iOS 对 canOpenURL 的配额限制也可能造成波动。
struct SchemeDetector: Detector {
    /// 待探测的 scheme 及权重。
    private let schemes: [(scheme: String, score: Double)] = [
        ("cydia://", 20),
        ("sileo://", 20),
        ("zbra://", 10),
        ("filza://", 15),
        ("undecimus://", 20),
    ]
    /// 表明 `canOpenURL:` 本身可能被 hook 的方法标记集合。
    /// 命中这些标记时，探测结果不可信，应跳过 scheme 检查。
    private static let canOpenURLHookSurfaceIndicators: Set<String> = [
        "objc_imp:uiapp_canOpenURL",
        "runtime_integrity:selector_unresolved:canOpenURL:",
        "runtime_integrity:selector_nil_imp:canOpenURL:",
        "runtime_integrity:selector_imp_outside_system:canOpenURL:",
    ]

    /// 执行 scheme 探测。
    /// - Returns: 累计分数封顶 100 的检测结果。
    /// - Note: 若检测到 canOpenURL 被 hook，返回 0 分并附带 `scheme_probe_skipped:*` 标记，
    ///   避免把被伪造的探测结果当作“未安装”。
    func detect() throws -> DetectorResult {
        let suspiciousSurfaceMethods = canOpenURLHookSurfaceMethods()
        guard suspiciousSurfaceMethods.isEmpty else {
            return DetectorResult(
                score: 0,
                methods: suspiciousSurfaceMethods.map { "scheme_probe_skipped:\($0)" }
            )
        }

        var score: Double = 0
        var methods: [String] = []

        for item in schemes {
            guard let url = URL(string: item.scheme) else { continue }
            if canOpenURL(url) {
                score += item.score
                methods.append("scheme:\(item.scheme)")
                Logger.log("jailbreak.scheme.hit: \(item.scheme) (+\(item.score))")
            }
        }

        return DetectorResult(score: min(score, 100), methods: methods)
    }

    /// 汇总“canOpenURL 可能被 hook”的方法标记。
    /// - Returns: 去重排序后的命中标记；无命中返回空数组。
    private func canOpenURLHookSurfaceMethods() -> [String] {
        var hits = Set<String>()

        // 复用 ObjCIMPDetector 的 IMP 校验结果。
        if let objcResult = try? ObjCIMPDetector().detect() {
            for method in objcResult.methods where Self.canOpenURLHookSurfaceIndicators.contains(method) {
                hits.insert(method)
            }
        }

        // 复用运行时完整性校验结果（选择器缺失/IMP 越界等）。
        if let runtimeResult = try? RuntimeIntegrityValidator().detect() {
            for method in runtimeResult.methods where Self.canOpenURLHookSurfaceIndicators.contains(method) {
                hits.insert(method)
            }
        }

        return hits.sorted()
    }

    /// 线程安全地调用 `UIApplication.canOpenURL`。
    /// - Parameter url: 待探测 URL。
    /// - Returns: 系统报告可打开时返回 `true`。
    /// - Note: UIKit 要求主线程访问；非主线程会同步切到主队列，可能短暂阻塞调用线程。
    private func canOpenURL(_ url: URL) -> Bool {
        if Thread.isMainThread {
            return UIApplication.shared.canOpenURL(url)
        }
        var ok = false
        DispatchQueue.main.sync {
            ok = UIApplication.shared.canOpenURL(url)
        }
        return ok
    }
}
#else

/// 非 UIKit 平台的占位实现：无 scheme 探测能力，返回空结果。
struct SchemeDetector: Detector {
    /// 直接返回空结果，语义为“已执行且无命中”。
    func detect() throws -> DetectorResult { .empty }
}
#endif
