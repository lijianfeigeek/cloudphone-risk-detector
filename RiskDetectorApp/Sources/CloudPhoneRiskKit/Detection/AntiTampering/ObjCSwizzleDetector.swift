// ObjC 方法 IMP 劫持与 Frida GCD 队列检测：对关键系统方法（NSProcessInfo.environment、
// NSURLSession 数据任务、NSBundle.bundlePath、UIDevice 型号/版本/名称）用 dladdr 校验 IMP
// 归属镜像，并在 ARM64 上检查首条指令是否为 B/BL 跳板（内联 Hook）。
// 另扫描线程名中的 Frida 特征队列标签；信号为 objc_method_swizzled / 内联 Hook / Frida dispatch queue。
// PAC 设备上不裸读 IMP 指针，改用 vm_read_overwrite 读指令；读取失败即降级为仅镜像校验。

import Darwin
import Foundation
import ObjectiveC

/// 检测 ObjC 方法实现劫持与 Frida 特征 GCD 队列
///
/// 实现两种检测技术：
/// 1. ObjC 方法 IMP 劫持 — 检测关键 ObjC 方法的 IMP 是否指向预期框架镜像外
/// 2. Dispatch 队列名扫描 — 检测 Frida 特征性 GCD 队列标签（通过线程名）
struct ObjCSwizzleDetector: Detector {

    /// 单个待校验方法：所属类、selector、预期镜像关键字与命中权重。
    struct MethodCheck {
        let className: String
        let selector: String
        let expectedFramework: String  // substring to match in image path
        let score: Double
    }

    /// 关键方法清单：这些都是设备指纹/网络/包信息的上游，最常被 Hook 用于伪造环境。
    private var methodChecks: [MethodCheck] {
        var checks: [MethodCheck] = [
            // Process info (environment variable spoofing)
            MethodCheck(className: "NSProcessInfo", selector: "environment", expectedFramework: "Foundation", score: 12),

            // URL/Network (SSL pinning bypass)
            MethodCheck(className: "NSURLSession", selector: "dataTaskWithRequest:completionHandler:", expectedFramework: "CFNetwork", score: 10),

            // Bundle (path spoofing)
            MethodCheck(className: "NSBundle", selector: "bundlePath", expectedFramework: "Foundation", score: 10),
        ]

        #if canImport(UIKit)
        checks += [
            // Device info (critical for device spoofing)
            MethodCheck(className: "UIDevice", selector: "model", expectedFramework: "UIKit", score: 12),
            MethodCheck(className: "UIDevice", selector: "systemVersion", expectedFramework: "UIKit", score: 10),
            MethodCheck(className: "UIDevice", selector: "name", expectedFramework: "UIKit", score: 10),
        ]
        #endif

        return checks
    }

    /// 执行 IMP 劫持检测与队列名扫描，返回累加结果；模拟器直接降级。
    func detect() throws -> DetectorResult {
        #if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
        #else
        var score: Double = 0
        var methods: [String] = []

        // 1. ObjC method swizzle detection
        let swizzle = detectMethodSwizzle()
        score += swizzle.score
        methods.append(contentsOf: swizzle.methods)

        // 2. Dispatch queue name scanning
        let queue = detectSuspiciousQueues()
        score += queue.score
        methods.append(contentsOf: queue.methods)

        return DetectorResult(score: score, methods: methods)
        #endif
    }

    // MARK: - 1. ObjC 方法 IMP 劫持检测

    /// 遍历关键方法，取 IMP 后交给 `checkIMP` 做镜像归属与内联跳板校验。
    /// - 类或方法不存在时跳过（不同 iOS 版本可能移除 selector）。
    /// - 实例方法优先，找不到再回退到类方法。
    /// - 总分封顶 45，避免多个方法同时被同一框架 Hook 时分值线性膨胀。
    private func detectMethodSwizzle() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        for check in methodChecks {
            guard let cls = NSClassFromString(check.className) else { continue }
            let sel = NSSelectorFromString(check.selector)
            guard let method = class_getInstanceMethod(cls, sel) else {
                // Try class method
                guard let classMethod = class_getClassMethod(cls, sel) else { continue }
                let imp = method_getImplementation(classMethod)
                checkIMP(imp, check: check, score: &score, methods: &methods)
                continue
            }
            let imp = method_getImplementation(method)
            checkIMP(imp, check: check, score: &score, methods: &methods)
        }

        return (min(score, 45), methods)
    }

    /// 校验 IMP 是否被劫持
    ///
    /// ## [4.4.8] PAC 旁路支持 (Swift-only)
    /// 在 A12+ (PAC) 设备上，直接解引用 IMP 指针读取机器码会导致 EXC_BAD_ACCESS。
    /// 策略：先用 dladdr 验证 IMP 是否落在已知镜像内（不涉及指针解引用）；
    /// 仅在非 PAC 环境下才进行首条指令的机器码扫描。
    /// - Note: 内联 Hook 检测在 PAC 设备上为 best-effort，主要依赖 dladdr 的镜像归属校验。
    private func checkIMP(_ imp: IMP, check: MethodCheck, score: inout Double, methods: inout [String]) {
        var info = Dl_info()
        let impRaw = unsafeBitCast(imp, to: UnsafeRawPointer.self)
        let found = dladdr(impRaw, &info)

        // 先做 dladdr 校验，避免任何对 IMP 的裸读（PAC 安全）
        if found == 0 {
            // IMP 不在任何已加载镜像中（匿名内存或 PAC 导致 dladdr 失败）— 视为可疑
            score += check.score
            methods.append("objc_swizzle:\(check.className).\(check.selector):anonymous")
            return
        }

        #if arch(arm64)
        // 仅 ARM64 有固定宽度的 B/BL 编码；x86_64 分支完全不执行，避免误读指令长度。
        if let firstInstruction = safeReadFirstInstruction(at: impRaw) {
            // B:  0x14000000 ~ 0x17FFFFFF（无条件相对跳转）
            // BL: 0x94000000 ~ 0x97FFFFFF（带链接的相对跳转，Hook 常借此保留原函数调用）
            let isB  = firstInstruction >= 0x14000000 && firstInstruction <= 0x17FFFFFF
            let isBL = firstInstruction >= 0x94000000 && firstInstruction <= 0x97FFFFFF
            if isB || isBL {
                // 真实方法通常以栈帧建立/PAC 指令开头，首条即跳转说明已被内联 Hook。
                score += 50
                methods.append("\(ObfuscatedConstants.signalObjcInlineHookDetected):\(check.className).\(check.selector)")
                return
            }
        }
        #endif

        // 校验 IMP 所在镜像是否与预期框架一致
        if let imagePath = info.dli_fname {
            let path = String(cString: imagePath)
            if !path.contains(check.expectedFramework) {
                // IMP 落在非预期镜像（如注入的 dylib）说明实现被替换。
                score += check.score
                methods.append("objc_swizzle:\(check.className).\(check.selector):wrong_image")
            }
        }
    }

    #if arch(arm64)
    /// Read first ARM64 instruction at `addr` via `vm_read_overwrite` to avoid
    /// dereferencing PAC-signed pointers (which would cause EXC_BAD_ACCESS on A12+).
    ///
    /// 返回 nil 表示地址不可读；调用方据此跳过内联 Hook 判定，仅保留 dladdr 结果。
    private func safeReadFirstInstruction(at addr: UnsafeRawPointer) -> UInt32? {
        var buf: UInt32 = 0
        var outSize: vm_size_t = 0
        let kr = withUnsafeMutablePointer(to: &buf) { ptr in
            vm_read_overwrite(
                mach_task_self_,
                vm_address_t(UInt(bitPattern: addr)),
                vm_size_t(MemoryLayout<UInt32>.size),
                vm_address_t(UInt(bitPattern: ptr)),
                &outSize
            )
        }
        guard kr == KERN_SUCCESS, outSize == MemoryLayout<UInt32>.size else { return nil }
        return buf
    }
    #endif

    // MARK: - 2. Dispatch 队列名扫描

    /// 枚举当前 task 的所有线程，读取线程名并匹配 Frida 特征队列标签。
    /// - 每个标签只计一次分（`foundLabels` 去重），避免同名队列放大分值。
    /// - 总分封顶 25：线程名可被伪造，单靠它不足以判篡改。
    private func detectSuspiciousQueues() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []
        var foundLabels: Set<String> = []

        let suspiciousLabels = ObfuscatedConstants.fridaQueueLabelMarkers

        var threadList: thread_act_array_t?
        var threadCount: mach_msg_type_number_t = 0
        let kr = task_threads(mach_task_self_, &threadList, &threadCount)
        guard kr == KERN_SUCCESS, let threads = threadList else { return (0, []) }
        defer {
            // task_threads 返回的端口数组由内核分配，必须显式释放，否则每次评估都会泄漏。
            vm_deallocate(
                mach_task_self_,
                vm_address_t(UInt(bitPattern: threads)),
                vm_size_t(Int(threadCount) * MemoryLayout<thread_act_t>.size)
            )
        }

        for i in 0..<Int(threadCount) {
            let thread = threads[i]
            let pt = pthread_from_mach_thread_np(thread)
            guard let pt = pt else { continue }

            // 线程名上限按 256 字节读取；读取失败或为空则跳过。
            var name = [CChar](repeating: 0, count: 256)
            if pthread_getname_np(pt, &name, 256) == 0 {
                let threadName = String(cString: name).lowercased()
                if threadName.isEmpty { continue }
                for label in suspiciousLabels {
                    if threadName.contains(label) && !foundLabels.contains(label) {
                        foundLabels.insert(label)
                        score += 12
                        methods.append("\(ObfuscatedConstants.methodPrefixSuspiciousQueue)\(label)")
                        break
                    }
                }
            }
        }

        return (min(score, 25), methods)
    }
}

// MARK: - RiskSignal 转换

extension ObjCSwizzleDetector {
    /// 将 methods 前缀归类为三种信号：
    /// - `objc_swizzle` → objc_method_swizzled（每项 12 分，封顶 30，tampered）
    /// - 内联 Hook → 固定 50 分（tampered，weightHint 90）
    /// - Frida 队列 → 每项 10 分，封顶 20（tampered，weightHint 70）
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        let swizzleMethods = result.methods.filter { $0.hasPrefix("objc_swizzle") }
        if !swizzleMethods.isEmpty {
            signals.append(RiskSignal(
                id: "objc_method_swizzled",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(swizzleMethods.count) * 12, 30),
                evidence: [
                    "swizzled_methods": swizzleMethods.joined(separator: ","),
                    "count": "\(swizzleMethods.count)"
                ],
                state: .tampered,
                layer: 2,
                weightHint: 80
            ))
        }

        let inlineHookMethods = result.methods.filter { $0.hasPrefix(ObfuscatedConstants.signalObjcInlineHookDetected) }
        if !inlineHookMethods.isEmpty {
            // 首条指令即 B/BL 的证据很强，固定高分，不随命中方法数放大。
            signals.append(RiskSignal(
                id: ObfuscatedConstants.signalObjcInlineHookDetected,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 50,
                evidence: [
                    "methods": inlineHookMethods.joined(separator: ","),
                    "count": "\(inlineHookMethods.count)"
                ],
                state: .tampered,
                layer: 2,
                weightHint: 90
            ))
        }

        let queueMethods = result.methods.filter { $0.hasPrefix(ObfuscatedConstants.methodPrefixSuspiciousQueue) }
        if !queueMethods.isEmpty {
            signals.append(RiskSignal(
                id: ObfuscatedConstants.signalFridaDispatchQueue,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(queueMethods.count) * 10, 20),
                evidence: ["queues": queueMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 70
            ))
        }

        return signals
    }
}
