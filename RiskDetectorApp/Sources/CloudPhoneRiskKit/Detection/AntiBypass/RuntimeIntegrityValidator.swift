// 运行时完整性校验：从四个维度检测 hook 框架（Frida/Substrate/substitute 等）的介入痕迹：
// 1) ObjC selector 存在性与实现归属；2) 关键函数序言的 inline hook 指令模式；
// 3) dlsym 解析结果的模块归属；4) 调用栈中的注入库帧与异常栈深。
// 四类检查独立计分后封顶 90，既保留单项证据，又避免一次异常直接把总分拉满。

import Darwin
import Foundation
import MachO

/// 运行时完整性检测器：用于发现绕过工具对进程内 API 的替换/拦截。
///
/// 各项检查相互独立，攻击者必须同时绕过 ObjC 方法、C 函数序言、符号归属和调用栈四条线，
/// 才能完全隐身；这比只比对文件是否存在更难绕过。
///
/// 1. **Selector 存在性交叉验证**：确认关键 ObjC selector 仍解析到预期类。绕过工具能 hook
///    方法，但很少能完整复刻类层次结构。
///
/// 2. **指令模式校验**：读取关键安全函数的序言，检测 inline hook 典型的分支指令。
///
/// 3. **符号表一致性**：确认关键符号解析到的地址仍落在预期镜像范围内。
///
/// 4. **栈帧校验**：检查调用栈中是否出现注入库的异常帧。
struct RuntimeIntegrityValidator: Detector {

    /// 依次执行四类检查并累加分数，最终封顶 90。
    /// 模拟器下所有底层语义都不可信（缺少真实 dyld/栈布局），直接返回空结果。
    func detect() throws -> DetectorResult {
        #if targetEnvironment(simulator)
        return .empty
        #else
        var score: Double = 0
        var methods: [String] = []

        // 1. Selector 交叉验证：权重 20，单独命中不足以定性，但与其他证据叠加后指向 ObjC 层篡改。
        let selectorResult = validateSelectorIntegrity()
        if selectorResult.anomalyDetected {
            score += 20
            methods.append(contentsOf: selectorResult.methods)
        }

        // 2. 指令模式校验（inline hook 检测）：权重 25，inline hook 证据最直接。
        let instructionResult = validateInstructionPatterns()
        if instructionResult.anomalyDetected {
            score += 25
            methods.append(contentsOf: instructionResult.methods)
        }

        // 3. 符号表一致性：权重 20，符号被重定向通常意味着 PLT/GOT 或 dyld 层被改动。
        let symbolResult = validateSymbolTableConsistency()
        if symbolResult.anomalyDetected {
            score += 20
            methods.append(contentsOf: symbolResult.methods)
        }

        // 4. 栈帧校验：权重 15，最低是因为符号化栈可能受系统差异影响，噪声相对更大。
        let stackResult = validateStackFrames()
        if stackResult.anomalyDetected {
            score += 15
            methods.append(contentsOf: stackResult.methods)
        }

        // 封顶 90 而非 100：为上游其他检测器保留区分度，也避免单一模块独占总分。
        score = min(score, 90)

        return DetectorResult(score: score, methods: methods)
        #endif
    }

    // MARK: - 检查结果

    /// 单项检查的统一返回结构。
    private struct CheckResult {
        /// 是否发现异常。
        let anomalyDetected: Bool
        /// 具体异常方法标签，直接进入 DetectorResult.methods。
        let methods: [String]
    }

    // MARK: - 1. Selector 存在性交叉验证

    /// 验证常见 ObjC selector 仍解析到预期类。
    /// 绕过工具通常只 hook 单个方法，难以完整复刻类层次；当本应属于 NSFileManager 的
    /// selector 解析到其他类或解析失败时，说明运行期结构被篡改。
    private func validateSelectorIntegrity() -> CheckResult {
        var anomalies: [String] = []

        // 每项：(selector 名, 预期类名, 是否类方法)；类方法必须在元类上查询。
        let expectations: [(String, String, Bool)] = [
            ("fileExistsAtPath:", "NSFileManager", false),
            ("contentsOfDirectoryAtPath:error:", "NSFileManager", false),
            ("canOpenURL:", "UIApplication", false),
            ("dataWithContentsOfFile:", "NSData", true),  // 类方法，不在实例方法表里
        ]

        for (selectorName, expectedClassName, isClassMethod) in expectations {
            let sel = sel_getUid(selectorName)

            guard let expectedClass = NSClassFromString(expectedClassName) else {
                // 关键系统类本身都解析不到，属于强异常（可能被改名或隐藏）。
                anomalies.append("runtime_integrity:selector_class_missing:\(expectedClassName)")
                continue
            }

            // 类方法的实现挂在元类上，后续查询必须使用 object_getClass。
            let targetClass: AnyClass = isClassMethod ? object_getClass(expectedClass)! : expectedClass

            // 类必须仍然响应 selector，否则方法可能被移除或替换。
            let responds = isClassMethod
                ? class_respondsToSelector(object_getClass(expectedClass), sel)
                : class_respondsToSelector(expectedClass, sel)
            if !responds {
                anomalies.append("runtime_integrity:selector_unresolved:\(selectorName)")
                continue
            }

            // 交叉验证 Method 的 IMP 非空，且实现位于系统框架镜像内。
            let method = isClassMethod
                ? class_getClassMethod(expectedClass, sel)
                : class_getInstanceMethod(expectedClass, sel)
            if let method {
                let imp = method_getImplementation(method)
                if imp == nil {
                    anomalies.append("runtime_integrity:selector_nil_imp:\(selectorName)")
                    continue
                }

                // IMP 若落在注入 dylib 而非系统镜像，说明该方法被整体替换。
                if !isAddressInSystemImage(UnsafeRawPointer(imp)) {
                    anomalies.append("runtime_integrity:selector_imp_outside_system:\(selectorName)")
                }
            }
        }

        return CheckResult(
            anomalyDetected: !anomalies.isEmpty,
            methods: anomalies
        )
    }

    // MARK: - 2. 指令模式校验

    /// 检查关键 C 函数序言的前几条指令，识别 inline hook。
    /// arm64 上正常序言通常是压栈（STP、SUB SP），而不是无条件分支（B/BR）或 BRK。
    ///
    /// 常见 arm64 inline hook 形态：
    /// - `B <offset>`（无条件跳转）：opcode 高 6 位为 000101
    /// - `LDR Xn, #8; BR Xn` 跳板序列
    /// - 调试器断点使用的 `BRK`
    private func validateInstructionPatterns() -> CheckResult {
        var anomalies: [String] = []

        // 这些 C 函数是绕过工具最常替换的目标，优先检查其序言。
        let symbolsToCheck: [String] = [
            "_access",
            "_stat",
            "_open",
            "_dlopen",
            "_fopen",
        ]

        // dlopen(nil) 返回主程序句柄，绝不能 dlclose（POSIX 未定义行为，可能破坏进程镜像）。
        guard let handle = dlopen(nil, RTLD_NOW) else {
            return CheckResult(anomalyDetected: false, methods: [])
        }

        for symbolName in symbolsToCheck {
            // dlsym 需要不带下划线的 C 名；下划线只用于符号表展示。
            guard let symAddr = dlsym(handle, String(symbolName.dropFirst())) else {
                continue
            }

            let ptr = UnsafeRawPointer(symAddr)

            if detectInlineHookAtAddress(ptr) {
                anomalies.append("runtime_integrity:inline_hook:\(symbolName)")
            }
        }

        return CheckResult(
            anomalyDetected: !anomalies.isEmpty,
            methods: anomalies
        )
    }

    /// 安全读取一条指令：用 vm_read_overwrite 复制而非直接解引用，避免坏指针触发 EXC_BAD_ACCESS。
    /// 返回 nil 表示地址不可读或读取长度不符。
    private func safeReadInstruction(at address: UnsafeRawPointer) -> UInt32? {
        var instruction: UInt32 = 0
        var outSize: vm_size_t = 0
        let kr = withUnsafeMutablePointer(to: &instruction) { ptr in
            vm_read_overwrite(
                mach_task_self_,
                vm_address_t(UInt(bitPattern: address)),
                vm_size_t(MemoryLayout<UInt32>.size),
                vm_address_t(UInt(bitPattern: ptr)),
                &outSize
            )
        }
        guard kr == KERN_SUCCESS, outSize == vm_size_t(MemoryLayout<UInt32>.size) else {
            return nil
        }
        return instruction
    }

    /// 检查函数入口前两条指令是否构成 inline hook。
    /// 返回 true 表示命中分支/断点/跳板模式；读取失败则保守返回 false（不制造假阳性）。
    private func detectInlineHookAtAddress(_ address: UnsafeRawPointer) -> Bool {
        // 安全读取前两条指令，避免非法地址导致崩溃。
        guard let instruction0 = safeReadInstruction(at: address),
              let instruction1 = safeReadInstruction(at: address.advanced(by: 4)) else {
            return false
        }

        // 无条件分支 B imm26：高 6 位固定为 000101。
        if (instruction0 >> 26) == 0b000101 {
            return true
        }

        // 寄存器分支 BR Xn：掩码 0xFFFFFC1F 后应等于 0xD61F0000。
        if (instruction0 & 0xFFFFFC1F) == 0xD61F0000 {
            return true
        }

        // BRK #imm：高字节 0xD4、bit21 置位、bit0 清零，是调试断点常用编码。
        if (instruction0 & 0xFFE0001F) == 0xD4200000 {
            return true
        }

        // LDR Xt, [PC, #8] 紧跟 BR Xt 的跳板模式；只有两条指令配对才判定为 hook。
        let ldrMask: UInt32 = 0xFFFFFFE0
        let ldrExpected: UInt32 = 0x58000040  // LDR Xn, [PC, #+8]
        if (instruction0 & ldrMask) == ldrExpected {
            let rt = instruction0 & 0x1F
            // 目标寄存器必须一致，避免把无关的 LDR+BR 误判为跳板。
            let expectedBR = 0xD61F0000 | (rt << 5)
            if instruction1 == expectedBR {
                return true
            }
        }

        return false
    }

    // MARK: - 3. 符号表一致性

    /// 验证关键动态符号解析到的地址仍位于预期镜像内。
    /// 若符号被重定向到其他镜像，通常意味着 hook 框架接管了该符号。
    private func validateSymbolTableConsistency() -> CheckResult {
        var anomalies: [String] = []

        // 解析符号并校验其地址仍落在预期镜像边界内。
        // 记录每个符号应归属的系统镜像；路径按子串匹配，适配不同系统版本的库名后缀。
        let symbolChecks: [(symbol: String, expectedImageSubstring: String)] = [
            ("_access", "libsystem_kernel"),
            ("_stat", "libsystem_kernel"),
            ("_dlopen", "libdyld"),
            ("_fopen", "libsystem_c"),
            ("_open", "libsystem_kernel"),
        ]

        // dlopen(nil) 返回主程序句柄，绝不能 dlclose（POSIX 未定义行为）。
        guard let handle = dlopen(nil, RTLD_NOW) else {
            return CheckResult(anomalyDetected: false, methods: [])
        }

        for (symbol, expectedImage) in symbolChecks {
            guard let symAddr = dlsym(handle, String(symbol.dropFirst())) else {
                // 关键符号完全解析不到，本身就是异常（可能被隐藏）。
                anomalies.append("runtime_integrity:symbol_missing:\(symbol)")
                continue
            }

            // 用 dladdr 反查符号实际归属的镜像，而不是信任 dlsym 的返回值。
            var info = Dl_info()
            guard dladdr(symAddr, &info) != 0, let fname = info.dli_fname else {
                anomalies.append("runtime_integrity:symbol_no_image:\(symbol)")
                continue
            }

            let imagePath = String(cString: fname)

            if !imagePath.lowercased().contains(expectedImage.lowercased()) {
                anomalies.append("runtime_integrity:symbol_redirected:\(symbol):\(imagePath)")
            }
        }

        return CheckResult(
            anomalyDetected: !anomalies.isEmpty,
            methods: anomalies
        )
    }

    // MARK: - 4. 栈帧校验

    /// 检查调用栈是否包含已知 hook/注入库的帧。
    /// 合法调用栈不应出现 MobileSubstrate、substitute、FridaGadget 等库。
    private func validateStackFrames() -> CheckResult {
        var anomalies: [String] = []

        let callStack = Thread.callStackSymbols

        let suspiciousPatterns = ObfuscatedConstants.runtimeIntegrityStackSuspiciousNeedles

        for frame in callStack {
            for pattern in suspiciousPatterns {
                if frame.contains(pattern) {
                    anomalies.append("runtime_integrity:suspicious_stack_frame:\(pattern)")
                    break
                }
            }
        }

        // 正常 detect() 调用链不应超过 128 帧；异常深栈可能意味着拦截器链式包装。
        if callStack.count > 128 {
            anomalies.append("runtime_integrity:abnormal_stack_depth:\(callStack.count)")
        }

        return CheckResult(
            anomalyDetected: !anomalies.isEmpty,
            methods: anomalies
        )
    }

    // MARK: - 辅助

    /// 判断指针是否落在系统框架镜像内（/usr/lib 或 /System/Library）。
    /// 注意：系统扩展、App 自身镜像不算，避免把合法自研代码误判为注入。
    private func isAddressInSystemImage(_ address: UnsafeRawPointer) -> Bool {
        var info = Dl_info()
        guard dladdr(address, &info) != 0, let fname = info.dli_fname else {
            return false
        }
        let path = String(cString: fname)
        return path.hasPrefix("/usr/lib") || path.hasPrefix("/System/Library")
    }
}
