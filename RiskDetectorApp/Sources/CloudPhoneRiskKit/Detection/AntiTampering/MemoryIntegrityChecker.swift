// MemoryIntegrityChecker：检查可疑镜像、W+X 内存区域与关键函数 inline hook。
// 作为 FridaDetector 的底层组件之一，也被信号层直接调用；
// 通过首两条指令的跳板模式识别 hook，覆盖 Frida/Dobby 等常见引擎。
import Darwin
import Foundation
import MachO

/// 内存完整性检查器。
/// - 线程模型：同步只读查询 dyld 镜像、vm_region 与函数入口。
/// - 失败语义：地址不可读时按“无法判定”处理，仅给少量惩罚分。
struct MemoryIntegrityChecker: Detector {
    /// 可疑镜像路径 token（混淆常量）。
    var suspiciousImageTokens: [String] { ObfuscatedConstants.suspiciousLibraryTokensForIntegrity }

    // 受监控的高价值函数及其中 hook 时的分值。
    let inlineHookWatchSymbols: [(name: String, score: Double)] = [
        ("malloc", 10),
        ("free", 8),
        ("open", 8),
        ("openat", 10),
        ("dlopen", 10),
        ("syscall", 12),
        ("__syscall", 12),
        ("objc_msgSend", 12),
    ]

    /// 执行镜像、W+X 与 inline hook 三类检查（封顶 100）。
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []

        // 加载了可疑库，20 分。
        if hasSuspiciousImageLoaded() {
            score += 20
            methods.append("memory_integrity:suspicious_image")
        }

        // 存在可写且可执行的区域，25 分。
        if hasWritableExecutableRegion() {
            score += 25
            methods.append("memory_integrity:w_x_region")
        }

        // 关键函数 prologue 出现跳板，按符号权重计分。
        let inline = detectInlineHookTraces()
        score += inline.score
        methods.append(contentsOf: inline.methods)

        return DetectorResult(score: min(score, 100), methods: methods)
#endif
    }

    /// 检查已加载镜像路径是否包含可疑 token。
    func hasSuspiciousImageLoaded() -> Bool {
        let count = _dyld_image_count()
        for index in 0..<count {
            guard let imageName = _dyld_get_image_name(index) else { continue }
            let name = String(cString: imageName).lowercased()
            if suspiciousImageTokens.contains(where: { name.contains($0) }) {
                return true
            }
        }
        return false
    }

    /// 检查 malloc 所在内存区域是否同时可写可执行。
    func hasWritableExecutableRegion() -> Bool {
        // 用 malloc 地址定位其所属 region，避免遍历全进程。
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "malloc") else {
            return false
        }

        var address = vm_address_t(UInt(bitPattern: symbol))
        var size: vm_size_t = 0
        var info = vm_region_basic_info_data_64_t()
        var count = mach_msg_type_number_t(MemoryLayout<vm_region_basic_info_data_64_t>.stride / MemoryLayout<natural_t>.stride)
        var objectName: mach_port_t = 0

        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { rebound in
                vm_region_64(mach_task_self_, &address, &size, VM_REGION_BASIC_INFO_64, rebound, &count, &objectName)
            }
        }

        guard result == KERN_SUCCESS else { return false }
        // W+X 同时置位是 JIT/注入代码的典型特征，正常库不应如此。
        let writable = (info.protection & VM_PROT_WRITE) != 0
        let executable = (info.protection & VM_PROT_EXECUTE) != 0
        return writable && executable
    }

    /// 检查受监控符号的前两条指令是否为跳板。
    func detectInlineHookTraces() -> DetectorResult {
        var total: Double = 0
        var methods: [String] = []

        for item in inlineHookWatchSymbols {
            guard let symbol = resolveSymbol(item.name) else { continue }
            let first = readInstruction(symbol)
            let second = readInstruction(symbol.advanced(by: MemoryLayout<UInt32>.size))
            // literal load + register branch，或直接 register branch，均视为 hook。
            if let first, isHookPattern(firstInstruction: first, secondInstruction: second) {
                total += item.score
                methods.append("memory_integrity:inline_hook:\(item.name)")
            // 指令读取失败也扣分：可能地址被隐藏。
            } else if first == nil {
                let penalty = min(6, item.score * 0.5)
                // 惩罚分为该符号分值的一半，封顶 6。
                total += penalty
                methods.append("memory_integrity:unreadable:\(item.name)")
            }
        }

        return DetectorResult(score: min(total, 40), methods: methods)
    }

    /// 通过 RTLD_DEFAULT 解析符号。
    func resolveSymbol(_ name: String) -> UnsafeRawPointer? {
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), name) else {
            return nil
        }
        return UnsafeRawPointer(symbol)
    }

    /// 从地址读取一条 32 位指令；不可读返回 nil。
    func readInstruction(_ p: UnsafeRawPointer) -> UInt32? {
        // 先确认地址可读，避免非法访问崩溃。
        guard isReadableAddress(p) else { return nil }
        return p.loadUnaligned(as: UInt32.self)
    }

    /// 判断两条指令是否构成 hook 跳板。
    func isHookPattern(firstInstruction: UInt32, secondInstruction: UInt32?) -> Bool {
        if isUnconditionalBranch(firstInstruction) || isRegisterBranch(firstInstruction) {
            return true
        }
        if isLiteralLoad(firstInstruction), let secondInstruction {
            return isRegisterBranch(secondInstruction)
        }
        return false
    }

    /// 判断是否为无条件分支 B/BL。
    func isUnconditionalBranch(_ ins: UInt32) -> Bool {
        let top6 = ins >> 26
        // 高 6 位为 000101（B）或 100101（BL）。
        return top6 == 0b000101 || top6 == 0b100101
    }

    /// 判断是否为寄存器分支 BR/BLR。
    func isRegisterBranch(_ ins: UInt32) -> Bool {
        let mask: UInt32 = 0xFFFFFC1F
        // 掩码后匹配 BR/BLR 编码。
        return (ins & mask) == 0xD61F0000 || (ins & mask) == 0xD63F0000
    }

    /// 判断是否为 LDR literal。
    func isLiteralLoad(_ ins: UInt32) -> Bool {
        // 高 8 位为 0x58 即 LDR literal。
        (ins & 0xFF000000) == 0x58000000
    }

    /// 用 vm_region 判断地址是否可读。
    func isReadableAddress(_ p: UnsafeRawPointer) -> Bool {
        var address = vm_address_t(UInt(bitPattern: p))
        var size: vm_size_t = 0
        var info = vm_region_basic_info_data_64_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<vm_region_basic_info_data_64_t>.stride / MemoryLayout<natural_t>.stride
        )
        var objectName: mach_port_t = 0

        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { rebound in
                vm_region_64(mach_task_self_, &address, &size, VM_REGION_BASIC_INFO_64, rebound, &count, &objectName)
            }
        }
        guard result == KERN_SUCCESS else { return false }
        return (info.protection & VM_PROT_READ) != 0
    }
}
