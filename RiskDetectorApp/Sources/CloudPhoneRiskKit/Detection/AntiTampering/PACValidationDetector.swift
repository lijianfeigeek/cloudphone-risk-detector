// PAC（指针认证）姿态检测：仅在 A12 及以后、arm64/arm64e 真机上启用。先用 hw.optional.arm64e 与
// hw.optional.arm.FEAT_PAuth 判断 PAC 能力是否被系统/越狱环境关闭，再对 open/stat/sysctl/dlopen/
// objc_msgSend 五个关键符号做 dladdr 镜像归属、vm_read_overwrite 可读性与 Mach-O __TEXT 范围校验。
// 信号：pacDisabled（能力标志被禁用，85 分）/ pacPointerInvalid（指针异常，tampered）。
// 非 PAC 设备、模拟器与非 arm64 架构统一返回 not_applicable，避免产生噪声。

import Darwin
import Foundation

/// 校验 PAC 能力设备上的指针认证姿态。
///
/// 启发式：
/// 1) 能力开关显示被禁用（`hw.optional.arm64e` / `hw.optional.arm.FEAT_PAuth`）
/// 2) 关键函数指针无法通过 `dladdr`/可读性检查
/// 3) 关键函数指针解析到非预期镜像
struct PACValidationDetector: Detector {
    /// 单个符号探针：符号名与允许的镜像路径关键字。
    struct SymbolProbe {
        let symbol: String
        let expectedImageTokens: [String]
    }

    /// 一次采集的原始快照，同时保留被禁用的能力标志，便于服务端复核。
    struct Snapshot {
        let machine: String
        let pacCapable: Bool
        let arm64eFlag: Int?
        let pAuthFlag: Int?
        let unreadablePointers: [String]
        let unexpectedImages: [String]
    }

    /// 计分结果；`pacReportedDisabled` 单独暴露，供信号层生成高置信度信号。
    struct Assessment {
        let score: Double
        let methods: [String]
        let pacCapable: Bool
        let pacReportedDisabled: Bool
        let invalidPointerCount: Int
    }

    /// 关键 libc/ObjC 符号：正常都应落在 libsystem 或 libobjc，被 Hook 时 IMP 常指向匿名页/注入镜像。
    private let probes: [SymbolProbe] = [
        .init(symbol: "open", expectedImageTokens: ["libsystem", "/usr/lib/system"]),
        .init(symbol: "stat", expectedImageTokens: ["libsystem", "/usr/lib/system"]),
        .init(symbol: "sysctl", expectedImageTokens: ["libsystem", "/usr/lib/system"]),
        .init(symbol: "dlopen", expectedImageTokens: ["libsystem", "/usr/lib/system"]),
        .init(symbol: "objc_msgSend", expectedImageTokens: ["libobjc"]),
    ]

    /// 执行检测；模拟器与非 arm64 架构无法体现真机 PAC 语义，直接降级。
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["pac:unavailable_simulator"])
#elseif !(arch(arm64) || arch(arm64e))
        return DetectorResult(score: 0, methods: ["pac:unavailable_arch"])
#else
        let snapshot = collectSnapshot()
        let assessment = assess(snapshot: snapshot)
        return DetectorResult(score: assessment.score, methods: assessment.methods)
#endif
    }

    /// 汇总能力开关与指针异常：
    /// - 能力被禁用：+70（越狱/内核补丁常关闭 PAC 以简化 Hook）。
    /// - ≥2 个指针不可读：从 30 分起每个 +8，封顶 45；仅 1 个只给 8 分（可能是边界情况）。
    /// - 指针落到非预期镜像：从 20 分起每个 +8，封顶 40。
    /// - 能力禁用且指针异常：额外 +10，两个独立表面互证；总分封顶 95。
    func assess(snapshot: Snapshot) -> Assessment {
        guard snapshot.pacCapable else {
            return Assessment(
                score: 0,
                methods: ["pac:not_applicable"],
                pacCapable: false,
                pacReportedDisabled: false,
                invalidPointerCount: 0
            )
        }

        var score: Double = 0
        var methods: [String] = []

        let featureValues = [snapshot.arm64eFlag, snapshot.pAuthFlag].compactMap { $0 }
        // 任一能力标志为 0 即视为系统声称不支持 PAC；两个标志都缺失时不作判断。
        let pacReportedDisabled = !featureValues.isEmpty && featureValues.contains(0)
        if pacReportedDisabled {
            score += 70
            methods.append("pac:feature_disabled")
        }

        let invalidPointerCount = snapshot.unreadablePointers.count
        if invalidPointerCount >= 2 {
            // 多个核心符号同时不可读，几乎不可能是偶发内存映射问题。
            score += min(30 + Double(invalidPointerCount - 2) * 8, 45)
            methods.append("pac:pointer_invalid:\(invalidPointerCount)")
        } else if invalidPointerCount == 1 {
            score += 8
            methods.append("pac:pointer_invalid_hint:1")
        }

        if !snapshot.unexpectedImages.isEmpty {
            score += min(20 + Double(snapshot.unexpectedImages.count - 1) * 8, 40)
            methods.append("pac:pointer_unexpected_image:\(snapshot.unexpectedImages.count)")
        }

        if pacReportedDisabled && (invalidPointerCount > 0 || !snapshot.unexpectedImages.isEmpty) {
            score += 10
            methods.append("pac:disabled_and_pointer_anomaly")
        }

        return Assessment(
            score: min(score, 95),
            methods: methods,
            pacCapable: true,
            pacReportedDisabled: pacReportedDisabled,
            invalidPointerCount: invalidPointerCount
        )
    }

    /// 采集机器型号、能力标志与五个符号的指针状态。
    /// - 非 PAC 设备不再做指针检查，避免在旧设备上产生无意义证据。
    /// - 任何单符号失败只记入对应列表，不影响其余符号。
    private func collectSnapshot() -> Snapshot {
        let machine = (Sysctl.string("hw.machine") ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let pacCapable = isA12OrLater(machine: machine)
        let arm64eFlag = Sysctl.int("hw.optional.arm64e")
        let pAuthFlag = Sysctl.int("hw.optional.arm.FEAT_PAuth")

        guard pacCapable else {
            return Snapshot(
                machine: machine,
                pacCapable: false,
                arm64eFlag: arm64eFlag,
                pAuthFlag: pAuthFlag,
                unreadablePointers: [],
                unexpectedImages: []
            )
        }

        var unreadablePointers: [String] = []
        var unexpectedImages: [String] = []

        for probe in probes {
            // RTLD_DEFAULT（-2）在全局符号表解析；dlsym 失败说明符号被裁剪或运行时异常。
            guard let symbolPtr = dlsym(UnsafeMutableRawPointer(bitPattern: -2), probe.symbol) else {
                unreadablePointers.append("\(probe.symbol):dlsym")
                continue
            }

            var info = Dl_info()
            guard dladdr(symbolPtr, &info) != 0, let imageName = info.dli_fname else {
                // 指针不属于任何已加载镜像：匿名映射或被篡改的指针。
                unreadablePointers.append("\(probe.symbol):dladdr")
                continue
            }

            let path = String(cString: imageName)
            let normalizedPath = path.lowercased()
            if !matchesExpectedImage(path: normalizedPath, expectedTokens: probe.expectedImageTokens) {
                unexpectedImages.append("\(probe.symbol)@\(path)")
            }

            if !isPointerReadable(symbolPtr) {
                // 通过 vm_read_overwrite 验证指针可读，不直接解引用（PAC 指针裸读会崩溃）。
                unreadablePointers.append("\(probe.symbol):vm_read")
                continue
            }

            if let imageBase = info.dli_fbase,
               let textRange = MachOTextRange.textRange(header: UnsafeRawPointer(imageBase)) {
                let address = UInt64(bitPattern: Int64(Int(bitPattern: symbolPtr)))
                // 代码符号必须落在所属镜像的 __TEXT 段内，落在段外说明指针被重定向。
                if address < textRange.lowerBound || address >= textRange.upperBound {
                    unreadablePointers.append("\(probe.symbol):text_range")
                }
            }
        }

        return Snapshot(
            machine: machine,
            pacCapable: true,
            arm64eFlag: arm64eFlag,
            pAuthFlag: pAuthFlag,
            unreadablePointers: unreadablePointers,
            unexpectedImages: unexpectedImages
        )
    }

    /// 读取指针处 4 字节验证可读性；失败返回 false。
    /// 使用 `vm_read_overwrite` 而非解引用，避免 PAC 签名不匹配导致 EXC_BAD_ACCESS。
    private func isPointerReadable(_ pointer: UnsafeMutableRawPointer) -> Bool {
        var instruction: UInt32 = 0
        var outSize: vm_size_t = 0
        let kr = withUnsafeMutablePointer(to: &instruction) { ptr in
            vm_read_overwrite(
                mach_task_self_,
                vm_address_t(UInt(bitPattern: pointer)),
                vm_size_t(MemoryLayout<UInt32>.size),
                vm_address_t(UInt(bitPattern: ptr)),
                &outSize
            )
        }
        return kr == KERN_SUCCESS && outSize == MemoryLayout<UInt32>.size
    }

    /// 镜像路径是否包含任一允许关键字（大小写已在调用方归一化）。
    private func matchesExpectedImage(path: String, expectedTokens: [String]) -> Bool {
        expectedTokens.contains(where: { path.contains($0) })
    }

    /// 按 `hw.machine` 判断是否 A12 或更新芯片：
    /// iPhone 11,x 起、iPad 8,x 起、iPod 9,x 起（对应 A12 世代的型号编号）。
    private func isA12OrLater(machine: String) -> Bool {
        guard let parsed = parseMachine(machine) else { return false }
        switch parsed.family {
        case "iphone":
            return parsed.major >= 11
        case "ipad":
            return parsed.major >= 8
        case "ipod":
            return parsed.major >= 9
        default:
            return false
        }
    }

    /// 解析 `hw.machine`（如 iphone15,2）为家族名与主版本号；无法解析时返回 nil。
    private func parseMachine(_ machine: String) -> (family: String, major: Int)? {
        let lower = machine.lowercased()
        let families = ["iphone", "ipad", "ipod"]
        guard let family = families.first(where: { lower.hasPrefix($0) }) else { return nil }

        let rest = lower.dropFirst(family.count)
        var digits = ""
        for char in rest {
            if char.isNumber {
                digits.append(char)
            } else {
                // 主版本号在首个非数字字符（逗号）处结束。
                break
            }
        }
        guard let major = Int(digits) else { return nil }
        return (family: family, major: major)
    }
}

extension PACValidationDetector {
    /// 生成最多两条信号：
    /// - `pacDisabled`：能力标志被关闭，固定 85 分、tampered、layer 1、weightHint 97。
    /// - `pacPointerInvalid`：≥2 个指针异常或有非预期镜像 → tampered；
    ///   仅 1 个指针异常 → 12 分软信号。
    func asSignals() -> [RiskSignal] {
        let snapshot = collectSnapshot()
        let assessment = assess(snapshot: snapshot)
        guard assessment.score > 0 else { return [] }

        var signals: [RiskSignal] = []
        if assessment.pacReportedDisabled {
            signals.append(
                RiskSignal(
                    id: SignalID.pacDisabled,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 85,
                    evidence: [
                        "machine": snapshot.machine,
                        "arm64e": snapshot.arm64eFlag.map(String.init) ?? "unknown",
                        "pauth": snapshot.pAuthFlag.map(String.init) ?? "unknown",
                    ],
                    state: .tampered,
                    layer: 1,
                    weightHint: 97
                )
            )
        }

        if assessment.invalidPointerCount >= 2 || !snapshot.unexpectedImages.isEmpty {
            signals.append(
                RiskSignal(
                    id: SignalID.pacPointerInvalid,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: min(50 + Double(assessment.invalidPointerCount) * 5, 78),
                    evidence: [
                        "invalid_pointers": snapshot.unreadablePointers.joined(separator: ","),
                        "unexpected_images": snapshot.unexpectedImages.joined(separator: ","),
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 88
                )
            )
        } else if assessment.invalidPointerCount == 1 {
            // 单个指针不可读可能来自边界映射，用软信号保留观察并交给上层加权。
            signals.append(
                RiskSignal(
                    id: SignalID.pacPointerInvalid,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 12,
                    evidence: ["invalid_pointers": snapshot.unreadablePointers.joined(separator: ",")],
                    state: .soft(confidence: 0.55),
                    layer: 2,
                    weightHint: 36
                )
            )
        }

        return signals
    }
}
