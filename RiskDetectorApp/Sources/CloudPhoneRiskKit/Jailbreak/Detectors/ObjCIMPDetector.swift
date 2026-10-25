// ObjC IMP 检测器：校验关键方法的 IMP 是否仍位于可信系统镜像，以发现方法交换（swizzling）。
// 位于 HookDetector 的子检测器链中；SchemeDetector 也会复用其结果判断 canOpenURL 是否被 hook。
// 关键安全不变量：IMP 落在可疑/非系统镜像才计分，且总分封顶 40，避免单点误报主导判决。
import Darwin
import Foundation
import ObjectiveC.runtime

/// 检测用于隐藏越狱迹象的方法交换：通过校验 IMP 的来源镜像判断方法是否被改写。
/// 检测什么：`NSBundle.bundleIdentifier`、`canOpenURL:`、`identifierForVendor` 等敏感方法的实现落点。
/// 命中后产生 `objc_imp:<id>` 信号，单项 6–8 分，总分封顶 40。
/// 误报风险：应用自身或第三方 SDK 对上述方法做业务性 hook 时会命中。
struct ObjCIMPDetector: Detector {
    /// 待校验的目标方法描述。
    private struct Target {
        /// 方法所属类。
        var cls: AnyClass
        /// 方法选择器。
        var sel: Selector
        /// 上报用标识。
        var id: String
        /// 命中后的分值。
        var score: Double
    }

    /// IMP 允许出现的系统镜像前缀。
    let trustedPathPrefixes: [String] = [
        "/system/library/",
        "/usr/lib/system/",
        "/usr/lib/libsystem",
        "/usr/lib/libobjc.",
    ]

    /// 可疑镜像路径令牌（核心集合）。
    let suspiciousImageTokens: [String] = ObfuscatedConstants.hookSuspiciousImageTokensCore

    /// 执行 IMP 来源校验。
    /// - Returns: 累计分数封顶 40 的检测结果；方法不存在或无法解析镜像时跳过。
    func detect() throws -> DetectorResult {
        var targets: [Target] = []

        // 使用 NSClassFromString 而非直接引用类型，避免在类被隐藏时提前崩溃。
        if let bundle = NSClassFromString("NSBundle") {
            targets.append(Target(cls: bundle, sel: #selector(getter: Bundle.bundleIdentifier), id: "bundle_bundleIdentifier", score: 6))
            targets.append(Target(cls: bundle, sel: #selector(Bundle.object(forInfoDictionaryKey:)), id: "bundle_infoKey", score: 6))
        }

        #if canImport(UIKit)
        // UIKit 独有方法只在支持 UIKit 的平台检查。
        if let app = NSClassFromString("UIApplication") {
            targets.append(Target(cls: app, sel: NSSelectorFromString("canOpenURL:"), id: "uiapp_canOpenURL", score: 8))
        }
        if let dev = NSClassFromString("UIDevice") {
            targets.append(Target(cls: dev, sel: NSSelectorFromString("identifierForVendor"), id: "uidevice_idfv", score: 6))
        }
        #endif

        var score: Double = 0
        var methods: [String] = []

        for t in targets {
            guard let m = class_getInstanceMethod(t.cls, t.sel) else { continue }
            let imp = method_getImplementation(m)
            // 把函数指针转换为可查询地址；bitPattern 为 0 时视为无效。
            let p = UnsafeRawPointer(bitPattern: UInt(bitPattern: imp))
            guard let p else { continue }

            var info = Dl_info()
            guard dladdr(p, &info) != 0, let cPath = info.dli_fname else { continue }
            let path = String(cString: cPath)

            // IMP 不在可信系统镜像中：说明方法实现已被替换或注入。
            if !isTrustedImpImagePath(path) {
                score += t.score
                methods.append("objc_imp:\(t.id)")
                Logger.log("\(ObfuscatedConstants.keywordJailbreak).objcimp.hit: \(t.id) path=\(path) (+\(t.score))")
            }
        }

        // 单项累加可能超过上限，统一裁剪以免误报放大。
        if score > 40 { score = 40 }
        return DetectorResult(score: score, methods: methods)
    }

    /// 判断 IMP 所在镜像是否可信。
    /// - Parameter path: IMP 所属镜像路径。
    /// - Returns: 命中可疑令牌返回 `false`；否则命中系统前缀返回 `true`。
    func isTrustedImpImagePath(_ path: String) -> Bool {
        let normalized = path.lowercased()
        if suspiciousImageTokens.contains(where: { normalized.contains($0) }) {
            return false
        }
        return trustedPathPrefixes.contains(where: { normalized.hasPrefix($0) })
    }
}
