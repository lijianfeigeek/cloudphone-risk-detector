// 复合 Hook 检测器：检查可疑 ObjC 类、关键 C 符号的落点镜像，并串联多个反 Hook 子检测器。
// 位于越狱检测管道中 `enableHookDetect` 分支，是开销最高但覆盖最广的模块。
// 关键安全不变量：关键符号落到非系统镜像即产生证据；子检测器抛错会向上传播并由引擎记为故障。
import Foundation
import Darwin

/// 综合检测 hook 框架（Substrate/Frida/fishhook 等）留下的痕迹。
/// 检测什么：可疑 ObjC 类被注册、`open/stat/dlopen/objc_msgSend` 等符号的镜像路径异常。
/// 命中后产生 `objc_class:*`、`symbol_image_suspicious:*`、`symbol_image_untrusted:*` 信号，分值 8–25。
/// 误报风险：企业分发/监控 SDK 也可能替换部分符号；因此对非系统镜像按比例扣分并整体封顶 100。
struct HookDetector: Detector {
    /// hook 框架常注册的 ObjC 类名（混淆常量表）。
    private let suspiciousObjCClasses = ObfuscatedConstants.hookSuspiciousObjCClasses

    /// 关键符号及其可疑落点分值；这些函数是越狱隐藏与文件检测绕过的核心目标。
    let symbolImageChecks: [(symbol: String, score: Double)] = [
        ("open", 25),
        ("openat", 22),
        ("fopen", 18),
        ("stat", 16),
        ("lstat", 16),
        ("access", 16),
        ("dlopen", 20),
        ("sysctl", 16),
        ("syscall", 20),
        ("__syscall", 20),
        ("objc_msgSend", 18),
    ]

    /// 可疑镜像路径令牌（如 Frida/Substrate 库名）。
    let suspiciousImageTokens: [String] = ObfuscatedConstants.hookSuspiciousImageTokens

    /// 执行复合 Hook 检测。
    /// - Returns: 累计分数封顶 100 的检测结果。
    /// - Throws: 任一子检测器抛出的错误会向上传播，由 JailbreakEngine 记为故障。
    func detect() throws -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []

        for name in suspiciousObjCClasses where NSClassFromString(name) != nil {
            score += 15
            methods.append("objc_class:\(name)")
            Logger.log("jb.guard.hit: objc_class=\(name) (+15)")
        }

        for check in symbolImageChecks {
            guard let path = imagePath(of: check.symbol) else { continue }

            // 符号直接落在可疑库中：高置信度，按完整分值计分。
            if isSuspiciousImagePath(path) {
                score += check.score
                methods.append("symbol_image_suspicious:\(check.symbol):\(path)")
                Logger.log("jb.guard.hit: symbol_image_suspicious \(check.symbol)=\(path) (+\(check.score))")
                continue
            }

            // 符号落在非系统镜像：中等置信度，按分值 70% 计分并夹在 [8,18]。
            if !isTrustedSystemImagePath(path, for: check.symbol) {
                let penalty = min(18, max(8, check.score * 0.7))
                score += penalty
                methods.append("symbol_image_untrusted:\(check.symbol):\(path)")
                Logger.log("jb.guard.hit: symbol_image_untrusted \(check.symbol)=\(path) (+\(penalty))")
            }
        }

        // 高级检查：各子检测器独立累加，任何一个失败都会向上抛出。
        let ptr = try PointerValidationDetector().detect()
        score += ptr.score
        methods.append(contentsOf: ptr.methods)

        let fw = try HookFrameworkSymbolDetector().detect()
        score += fw.score
        methods.append(contentsOf: fw.methods)

        let prologue = try PrologueBranchDetector().detect()
        score += prologue.score
        methods.append(contentsOf: prologue.methods)

        let fishhook = try IndirectSymbolPointerDetector().detect()
        score += fishhook.score
        methods.append(contentsOf: fishhook.methods)

        let objc = try ObjCIMPDetector().detect()
        score += objc.score
        methods.append(contentsOf: objc.methods)

        let meta = try ObjCMetadataDetector().detect()
        score += meta.score
        methods.append(contentsOf: meta.methods)

        return DetectorResult(score: min(score, 100), methods: methods)
    }

    /// 判断镜像路径是否命中可疑库令牌。
    /// - Parameter path: 镜像路径。
    /// - Returns: 命中任一令牌返回 `true`。
    func isSuspiciousImagePath(_ path: String) -> Bool {
        let normalized = path.lowercased()
        return suspiciousImageTokens.contains { normalized.contains($0) }
    }

    /// 判断符号落点是否属于可信任的系统镜像。
    /// - Parameters:
    ///   - path: 符号所在镜像路径。
    ///   - symbol: 符号名；`objc_msgSend` 额外允许 `/usr/lib/libobjc.`。
    /// - Returns: 命中允许前缀返回 `true`。
    func isTrustedSystemImagePath(_ path: String, for symbol: String) -> Bool {
        let normalized = path.lowercased()
        let baseTrustedPrefixes = [
            "/usr/lib/system/",
            "/usr/lib/libsystem_",
            "/system/library/",
        ]
        // objc_msgSend 合法落在 libobjc，普通 C 符号则不应来自该库。
        let objcTrustedPrefixes = baseTrustedPrefixes + [
            "/usr/lib/libobjc.",
        ]
        let trustedPrefixes = symbol == "objc_msgSend" ? objcTrustedPrefixes : baseTrustedPrefixes
        return trustedPrefixes.contains(where: { normalized.hasPrefix($0) })
    }

    /// 解析符号当前落点所在的镜像路径。
    /// - Parameter symbol: C 符号名。
    /// - Returns: 镜像路径；符号不存在或 `dladdr` 失败返回 `nil`。
    private func imagePath(of symbol: String) -> String? {
        // -2 即 RTLD_DEFAULT：在全局符号表中按默认查找顺序解析符号。
        guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), symbol) else { return nil } // RTLD_DEFAULT
        var info = Dl_info()
        guard dladdr(sym, &info) != 0, let cPath = info.dli_fname else { return nil }
        return String(cString: cPath)
    }
}

/// ObjC 元数据扫描：查找可疑类名、协议以及 NSObject 上被注入的分类方法。
/// 该检测器是 HookDetector 的内部子模块，不单独受配置开关控制。
private struct ObjCMetadataDetector: Detector {
    /// 执行 ObjC 运行时元数据扫描。
    /// - Returns: 累计分数封顶 35 的检测结果；每类证据最多上报 3 条以控制日志体积。
    func detect() throws -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []

        let classHits = scanAllLoadedClasses()
        if !classHits.isEmpty {
            score += 15
            for name in classHits.prefix(3) {
                methods.append("objc_scan:\(name)")
            }
            Logger.log("jb.meta.hit: class_scan hits=\(classHits.count) (+15)")
        }

        let protoHits = suspiciousProtocolsFound()
        if !protoHits.isEmpty {
            score += 10
            for p in protoHits.prefix(3) {
                methods.append("objc_proto:\(p)")
            }
            Logger.log("jb.meta.hit: protocols hits=\(protoHits.count) (+10)")
        }

        if let m = suspiciousNSObjectExtensionMethod() {
            score += 8
            methods.append("objc_method:\(m)")
            Logger.log("jb.meta.hit: nsobject_extension method=\(m) (+8)")
        }

        return DetectorResult(score: min(score, 35), methods: methods)
    }

    /// 枚举所有已注册 ObjC 类，按可疑模式匹配类名。
    /// - Returns: 去重并排序后的命中类名（小写），最多 12 个。
    private func scanAllLoadedClasses() -> [String] {
        var count: UInt32 = 0
        guard let classes = objc_copyClassList(&count) else { return [] }
        // objc_copyClassList 返回 malloc 内存，必须手动释放。
        defer { free(UnsafeMutableRawPointer(classes)) }

        let patterns = ObfuscatedConstants.hookObjcScanPatterns

        var hits: [String] = []
        hits.reserveCapacity(8)
        for i in 0..<Int(count) {
            let cls: AnyClass = classes[i]
            let name = String(cString: class_getName(cls)).lowercased()
            if patterns.contains(where: { name.contains($0) }) {
                hits.append(name)
                // 设上限避免异常运行时下长时间遍历。
                if hits.count >= 12 { break }
            }
        }
        return Array(Set(hits)).sorted()
    }

    /// 检查 hook 框架常注册的协议是否存在。
    /// - Returns: 已注册的可疑协议名列表。
    private func suspiciousProtocolsFound() -> [String] {
        let names = ObfuscatedConstants.hookSuspiciousProtocolNames
        var hits: [String] = []
        for n in names {
            if objc_getProtocol(n) != nil { hits.append(n) }
        }
        return hits
    }

    /// 扫描 NSObject 的方法列表，查找带可疑前缀的注入方法。
    /// - Returns: 第一个命中的方法名（小写）；未命中返回 `nil`。
    private func suspiciousNSObjectExtensionMethod() -> String? {
        let cls: AnyClass = NSObject.self
        var methodCount: UInt32 = 0
        guard let methods = class_copyMethodList(cls, &methodCount) else { return nil }
        // class_copyMethodList 返回 malloc 内存，必须手动释放。
        defer { free(methods) }

        let prefixes = ObfuscatedConstants.hookObjcMethodPrefixes

        for i in 0..<Int(methodCount) {
            let sel = method_getName(methods[i])
            let name = NSStringFromSelector(sel).lowercased()
            if prefixes.contains(where: { name.hasPrefix($0) }) {
                return name
            }
        }
        return nil
    }
}
