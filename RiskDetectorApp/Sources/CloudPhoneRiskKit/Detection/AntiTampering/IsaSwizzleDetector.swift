// ObjC Runtime 深度攻击检测：三条独立路径——关键单例对象的 isa 是否被 object_setClass 改指向、
// 关键方法 IMP 是否被替换为 _objc_msgForward 以走 forwardInvocation 劫持、以及关键类的方法数量
// 是否因注入框架而异常膨胀。
// 信号：isa_swizzle_detected / msg_forward_hijack（均判 tampered）/ method_count_anomaly（soft）。
// 模拟器直接降级为 0 分；类或方法不存在时跳过，不做任何假设。

import Darwin
import Foundation
import ObjectiveC

/// ObjC Runtime 深度攻击检测
///
/// 检测比 method swizzling 更深层的 ObjC runtime 攻击：
/// 1. isa swizzling — 攻击者通过 object_setClass() 修改对象的类指针，
///    使得消息分发走向攻击者控制的类
/// 2. 消息转发劫持 — 攻击者将方法 IMP 替换为 _objc_msgForward，
///    然后通过 forwardInvocation: 劫持调用
/// 3. 类方法数量异常 — 注入框架通常会给关键类添加大量方法
struct IsaSwizzleDetector: Detector {

    /// 依次执行三条检测路径并汇总；任一子检测失败都按 0 分处理，不中断整体。
    func detect() throws -> DetectorResult {
        #if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
        #else
        var score: Double = 0
        var methods: [String] = []

        let isa = detectIsaSwizzle()
        score += isa.score
        methods.append(contentsOf: isa.methods)

        let forward = detectMsgForwardHijack()
        score += forward.score
        methods.append(contentsOf: forward.methods)

        let methodCount = detectMethodCountAnomaly()
        score += methodCount.score
        methods.append(contentsOf: methodCount.methods)

        return DetectorResult(score: score, methods: methods)
        #endif
    }

    /// Detect isa swizzling on singleton objects
    /// Compare the runtime class of key singletons with their expected class
    ///
    /// 允许实际类名是预期类的子类（如 `_NSConcreteFileManager` 之于 NSFileManager），
    /// 只有类名完全不相关时才计分；每个异常 15 分，封顶 30。
    private func detectIsaSwizzle() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        // Check well-known singletons
        let checks: [(AnyObject, String)] = [
            (ProcessInfo.processInfo, "NSProcessInfo"),
            (Bundle.main, "NSBundle"),
            (NotificationCenter.default, "NSNotificationCenter"),
        ]

        for (obj, expectedPrefix) in checks {
            let actualClass = object_getClass(obj)
            let actualName = actualClass.map { NSStringFromClass($0) } ?? "nil"

            // The actual class name should start with the expected prefix
            // (could be a subclass like _NSConcreteFileManager, that's OK)
            // But if it's something completely different, that's suspicious
            // 去掉 "NS" 前缀后做包含匹配，兼容私有子类的命名习惯。
            let strippedPrefix = expectedPrefix.replacingOccurrences(of: "NS", with: "")
            if !actualName.contains(strippedPrefix) &&
               !actualName.hasPrefix(expectedPrefix) &&
               !actualName.hasPrefix("_" + expectedPrefix) {
                score += 15
                methods.append("isa_swizzle:\(expectedPrefix)→\(actualName)")
            }
        }

        return (min(score, 30), methods)
    }

    /// Detect methods whose IMP is _objc_msgForward
    /// This is a technique where the attacker replaces the IMP with the forwarding trampoline
    /// and then uses forwardInvocation: to intercept calls
    ///
    /// `dlsym` 使用 `RTLD_DEFAULT`（句柄 -2）在全局符号表查找转发跳板地址。
    /// 每个被劫持方法 18 分，封顶 25。
    private func detectMsgForwardHijack() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        // Get the address of _objc_msgForward for comparison
        guard let msgForwardPtr = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "_objc_msgForward") else {
            // 符号不可用说明运行时布局异常或环境被裁剪，跳过该项而不是误判。
            return (0, [])
        }
        let msgForwardAddr = unsafeBitCast(msgForwardPtr, to: IMP.self)

        // Check critical methods for forwarding hijack
        let methodsToCheck: [(String, String)] = [
            ("NSProcessInfo", "environment"),
            ("NSBundle", "bundlePath"),
            ("NSBundle", "executablePath"),
        ]

        for (className, selName) in methodsToCheck {
            guard let cls = NSClassFromString(className) else { continue }
            let sel = NSSelectorFromString(selName)

            // Check instance method
            if let method = class_getInstanceMethod(cls, sel) {
                let imp = method_getImplementation(method)
                if imp == msgForwardAddr {
                    // IMP 等于转发跳板：消息会进入 forwardInvocation:，调用方可被完全接管。
                    score += 18
                    methods.append("msg_forward:\(className).\(selName)")
                }
            }
        }

        return (min(score, 25), methods)
    }

    /// Detect abnormal method count on critical classes
    /// Hook frameworks often add methods to existing classes
    ///
    /// 范围按 iOS 14+ 给出宽松区间，只检查上界：注入框架通常“只加不减”，
    /// 因此方法数远超上界比低于下界更有指示意义（下界在旧系统上并不可靠）。
    private func detectMethodCountAnomaly() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        // Expected method count ranges (approximate for iOS 14+)
        // These are loose ranges; the actual check is for extreme outliers
        let classChecks: [(String, ClosedRange<UInt32>)] = [
            ("NSProcessInfo", 20...200),
            ("NSBundle", 50...400),
        ]

        for (className, expectedRange) in classChecks {
            guard let cls = NSClassFromString(className) else { continue }
            var count: UInt32 = 0
            if let methodList = class_copyMethodList(cls, &count) {
                // class_copyMethodList 返回的数组由 runtime 分配，必须 free，否则每次检测都会泄漏。
                free(methodList)

                // Check for abnormally high method count (injection adds methods)
                if count > expectedRange.upperBound {
                    score += 8
                    methods.append("method_count_anomaly:\(className):\(count)")
                }
            }
        }

        return (min(score, 15), methods)
    }
}

extension IsaSwizzleDetector {
    /// 将三条检测路径的 methods 前缀分别映射为独立信号。
    /// - isa swizzle：每项 15 分，封顶 30，tampered。
    /// - 消息转发劫持：每项 15 分，封顶 25，tampered。
    /// - 方法数异常：每项 8 分，封顶 15，soft(confidence 0.5)；单独出现时证据较弱。
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        let isaMethods = result.methods.filter { $0.hasPrefix("isa_swizzle") }
        if !isaMethods.isEmpty {
            signals.append(RiskSignal(
                id: "isa_swizzle_detected",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(isaMethods.count) * 15, 30),
                evidence: ["detail": isaMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 82
            ))
        }

        let forwardMethods = result.methods.filter { $0.hasPrefix("msg_forward") }
        if !forwardMethods.isEmpty {
            signals.append(RiskSignal(
                id: "msg_forward_hijack",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(forwardMethods.count) * 15, 25),
                evidence: ["detail": forwardMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 85
            ))
        }

        let countMethods = result.methods.filter { $0.hasPrefix("method_count") }
        if !countMethods.isEmpty {
            // 方法数会随系统版本自然增长，故只给软信号，避免把新版系统的正常差异判成注入。
            signals.append(RiskSignal(
                id: "method_count_anomaly",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(countMethods.count) * 8, 15),
                evidence: ["detail": countMethods.joined(separator: ",")],
                state: .soft(confidence: 0.5),
                layer: 2,
                weightHint: 50
            ))
        }

        return signals
    }
}
