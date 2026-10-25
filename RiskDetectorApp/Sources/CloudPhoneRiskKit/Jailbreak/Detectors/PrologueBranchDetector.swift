// 函数序言分支检测器：读取关键符号入口的第一条指令，识别被替换为跳转/trampoline 的 hook。
// 位于 HookDetector 的子检测器链中，针对 inline hook（典型如 Frida 的入口跳板）。
// 关键安全不变量：关键符号入口不可读本身也计分，防止攻击者用不可读页实现静默绕过。
import Darwin
import Foundation

/// 通过检查 ARM64 函数入口指令发现 inline hook。
/// 检测什么：入口第一条为无条件跳转/寄存器跳转，或 `LDR literal + BR/BLR` 的 Frida trampoline 形态。
/// 命中后产生 `prologue_branch:<symbol>`（单项 8–15 分）或 `prologue_unreadable:<symbol>`（保底分）。
/// 误报风险：极少见的手写汇编函数可能以跳转开头；仅在 arm64/arm64e 上启用。
struct PrologueBranchDetector: Detector {
    /// 需要检查入口指令的关键符号及分值。
    let symbols: [(name: String, score: Double)] = [
        ("open", 10),
        ("openat", 10),
        ("fopen", 8),
        ("stat", 10),
        ("stat64", 10),
        ("lstat", 10),
        ("lstat64", 10),
        ("statfs", 10),
        ("access", 10),
        ("faccessat", 10),
        ("dlopen", 12),
        ("_dyld_image_count", 12),
        ("sysctl", 10),
        ("syscall", 15),
        ("__syscall", 15),
        ("getenv", 8),
        ("fork", 10),
        ("posix_spawn", 10),
        ("objc_msgSend", 12),
        ("vm_protect", 8),
    ]

    /// 执行序言检查。
    /// - Returns: 累计分数封顶 100 的检测结果；非 ARM64 平台返回空结果。
    func detect() throws -> DetectorResult {
        #if arch(arm64) || arch(arm64e)
        var score: Double = 0
        var methods: [String] = []

        for item in symbols {
            // -2 即 RTLD_DEFAULT。
            guard let addr = dlsym(UnsafeMutableRawPointer(bitPattern: -2), item.name) else { continue } // RTLD_DEFAULT
            let p = UnsafeRawPointer(addr)
            guard let first = readInstruction(p) else {
                // 对关键符号出现不可读页给出告警，避免 read 失败被攻击者用作“静默绕过”。
                let fallbackScore = min(6, item.score * 0.6)
                score += fallbackScore
                methods.append("prologue_unreadable:\(item.name)")
                Logger.log("jailbreak.prologue.unreadable: \(item.name) (+\(fallbackScore))")
                continue
            }
            // 读取第二条指令仅用于识别 LDR literal 跳板；越界/不可读时为 nil。
            let second = readInstruction(p.advanced(by: MemoryLayout<UInt32>.size))
            if isHooked(firstInstruction: first, secondInstruction: second) {
                score += item.score
                methods.append("prologue_branch:\(item.name)")
                Logger.log("jailbreak.prologue.hit: \(item.name) inst=0x\(String(first, radix: 16)) (+\(item.score))")
            }
        }

        return DetectorResult(score: min(score, 100), methods: methods)
        #else
        return .empty
        #endif
    }

    #if arch(arm64) || arch(arm64e)
    /// 读取一条 32 位 ARM64 指令。
    /// - Parameter p: 指令地址。
    /// - Returns: 指令字；地址不可读时返回 `nil`。
    func readInstruction(_ p: UnsafeRawPointer) -> UInt32? {
        guard isReadableAddress(p) else { return nil }
        // 入口地址不保证 4 字节对齐，使用 unaligned load 避免崩溃。
        return p.loadUnaligned(as: UInt32.self)
    }

    /// 判断入口指令是否呈现 hook 特征。
    /// - Parameters:
    ///   - firstInstruction: 入口第一条指令。
    ///   - secondInstruction: 入口第二条指令（可能不可读）。
    /// - Returns: 命中跳转形态返回 `true`。
    func isHooked(firstInstruction: UInt32, secondInstruction: UInt32?) -> Bool {
        // 函数第一条就是无条件跳转或寄存器跳转，几乎不可能是正常 prologue。
        if isUnconditionalBranch(firstInstruction) || isRegisterBranch(firstInstruction) {
            return true
        }
        // 覆盖常见 Frida trampoline：LDR literal + BR/BLR reg + literal target
        if isLiteralLoad(firstInstruction), let secondInstruction {
            return isRegisterBranch(secondInstruction)
        }
        return false
    }

    /// 判断是否为 A64 无条件分支指令。
    /// - Parameter ins: 指令字。
    /// - Returns: `B` 或 `BL` 返回 `true`。
    func isUnconditionalBranch(_ ins: UInt32) -> Bool {
        // A64 编码：
        // B   imm26: op = 0b000101 (bits[31:26] == 0b000101)
        // BL  imm26: op = 0b100101 (bits[31:26] == 0b100101)
        let top6 = ins >> 26
        return top6 == 0b000101 || top6 == 0b100101
    }

    /// 判断是否为寄存器间接分支指令（BR/BLR）。
    /// - Parameter ins: 指令字。
    /// - Returns: 命中 `BR Xn` / `BLR Xn` 返回 `true`。
    func isRegisterBranch(_ ins: UInt32) -> Bool {
        // BR  Xn: 1101011000011111000000nnnnn00000
        // BLR Xn: 1101011000111111000000nnnnn00000
        let mask: UInt32 = 0xFFFFFC1F
        return (ins & mask) == 0xD61F0000 || (ins & mask) == 0xD63F0000
    }

    /// 判断是否为 64 位 literal load（LDR literal）。
    /// - Parameter ins: 指令字。
    /// - Returns: 命中 `0x58xxxxxx` 形态返回 `true`。
    func isLiteralLoad(_ ins: UInt32) -> Bool {
        // LDR (literal, 64-bit) 形态：0x58xxxxxx
        (ins & 0xFF000000) == 0x58000000
    }

    /// 通过 vm_region 查询地址所在页是否可读。
    /// - Parameter p: 待检查地址。
    /// - Returns: 页存在且具备读权限时返回 `true`。
    func isReadableAddress(_ p: UnsafeRawPointer) -> Bool {
        var address = vm_address_t(UInt(bitPattern: p))
        var size: vm_size_t = 0
        var info = vm_region_basic_info_data_64_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<vm_region_basic_info_data_64_t>.stride / MemoryLayout<natural_t>.stride
        )
        var objectName: mach_port_t = 0

        // vm_region_64 要求以 integer_t 指针传出的结构体，这里做内存重绑定。
        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { rebound in
                vm_region_64(mach_task_self_, &address, &size, VM_REGION_BASIC_INFO_64, rebound, &count, &objectName)
            }
        }
        guard result == KERN_SUCCESS else { return false }
        return (info.protection & VM_PROT_READ) != 0
    }
    #endif

    #if !(arch(arm64) || arch(arm64e))
    // 非 ARM64 平台无此检测能力：提供空实现以保持接口一致。
    /// 非 ARM64 平台占位实现。
    func readInstruction(_ p: UnsafeRawPointer) -> UInt32? {
        _ = p
        return nil
    }

    /// 非 ARM64 平台占位实现，始终返回 `false`。
    func isHooked(firstInstruction: UInt32, secondInstruction: UInt32?) -> Bool {
        _ = firstInstruction
        _ = secondInstruction
        return false
    }

    /// 非 ARM64 平台占位实现，始终返回 `false`。
    func isUnconditionalBranch(_ ins: UInt32) -> Bool {
        _ = ins
        return false
    }

    /// 非 ARM64 平台占位实现，始终返回 `false`。
    func isRegisterBranch(_ ins: UInt32) -> Bool {
        _ = ins
        return false
    }

    /// 非 ARM64 平台占位实现，始终返回 `false`。
    func isLiteralLoad(_ ins: UInt32) -> Bool {
        _ = ins
        return false
    }

    /// 非 ARM64 平台占位实现，始终返回 `false`。
    func isReadableAddress(_ p: UnsafeRawPointer) -> Bool {
        _ = p
        return false
    }
    #endif
}
