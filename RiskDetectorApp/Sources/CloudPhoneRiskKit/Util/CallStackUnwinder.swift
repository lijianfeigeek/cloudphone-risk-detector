// 执行流栈回溯（Call Stack Unwinding）：捕获返回地址并逐层验证是否落在可信镜像内。
// 用于在加解密、关键检测或高危篡改信号触发时发现 ROP/栈劫持与 dladdr hook。

import Darwin
import Foundation
import MachO

/// SDK 4.4 Phase 3: 执行流栈回溯 (Call Stack Unwinding & CFI)
///
/// 在核心加解密、关键检测逻辑、抛出高危 tampered 信号的瞬间，触发轻量级栈回溯。
/// 将提取到的返回地址交给多层验证：
///   1) RTLD_NEXT dual-path dladdr（检测 dladdr 自身被 hook）
///   2) 动态信任镜像缓存（启动时快照）
///   3) 严格前缀匹配（含 .framework/ 后缀）
///   4) vm_region_64 交叉验证（匿名可执行内存 = 恶意）
///
/// 纯 Swift 实现，仅使用 import Darwin 调用系统 API，无 C 代码。
public enum CallStackUnwinder {

    // 调用栈中返回地址落在匿名可执行内存 / 不可信镜像时上报的信号 ID。
    public static let ropChainSignalId = "rop_chain_detected"
    // 标准 dladdr 与 RTLD_NEXT 版本结果不一致时上报，说明符号解析被 hook。
    public static let dladdrHookSignalId = "dladdr_hook_detected"

    // 栈异常属于高置信度攻击证据，权重设 90。
    private static let maliciousWeight = 90

    // MARK: - RTLD_NEXT dual-path resolution

    // RTLD_NEXT 的句柄值固定为 -1，用于绕过当前镜像、直接查下一个定义。
    private static let rtldNext = UnsafeMutableRawPointer(bitPattern: -1)

    private typealias DladdrFn = @convention(c) (
        UnsafeRawPointer?, UnsafeMutablePointer<Dl_info>?
    ) -> Int32

    private typealias BacktraceFn = @convention(c) (
        UnsafeMutablePointer<UnsafeMutableRawPointer?>?, Int32
    ) -> Int32

    // 启动时解析一次并缓存函数指针；若解析失败则为 nil，调用方回退到直接符号。
    private static let nextDladdrFn: DladdrFn? = {
        guard let ptr = dlsym(rtldNext, "dladdr") else { return nil }
        return unsafeBitCast(ptr, to: DladdrFn.self)
    }()

    private static let nextBacktraceFn: BacktraceFn? = {
        guard let ptr = dlsym(rtldNext, "backtrace") else { return nil }
        return unsafeBitCast(ptr, to: BacktraceFn.self)
    }()

    // MARK: - Strict system library path prefixes

    // 严格前缀白名单：只认这些目录下的系统库，避免攻击者用相似路径（如 /tmp/usr/lib）冒充。
    private static let knownSystemLibPrefixes: [String] = [
        "/usr/lib/system/",
        "/usr/lib/libsystem",
        "/usr/lib/libobjc",
        "/usr/lib/dyld",
        "/usr/lib/libdispatch",
        "/System/Library/Frameworks/Foundation.framework/",
        "/System/Library/Frameworks/CoreFoundation.framework/",
        "/System/Library/Frameworks/Security.framework/",
        "/System/Library/Frameworks/CFNetwork.framework/",
        "/System/Library/Frameworks/UIKit.framework/",
        "/System/Library/Frameworks/QuartzCore.framework/",
        "/System/Library/Frameworks/Accelerate.framework/",
        "/System/Library/Frameworks/ImageIO.framework/",
        "/System/Library/Frameworks/Metal.framework/",
        "/System/Library/Frameworks/AVFoundation.framework/",
        "/System/Library/Frameworks/CoreGraphics.framework/",
        "/System/Library/Frameworks/CoreText.framework/",
        "/System/Library/PrivateFrameworks/UIKitCore.framework/",
        "/System/Library/PrivateFrameworks/GraphicsServices.framework/",
        "/System/Library/PrivateFrameworks/FrontBoardServices.framework/",
    ]

    // MARK: - Dynamic trusted image cache (snapshot at first access)

    // 首次访问时快照当前已加载镜像：之后新加载的镜像必须经系统路径/vm_region 复核，
    // 防止攻击者在启动后再 dlopen 一个恶意镜像并把它当作“可信”。
    private static let trustedImagePaths: Set<String> = {
        var paths = Set<String>()
        let count = _dyld_image_count()
        for i in 0..<count {
            guard let raw = _dyld_get_image_name(i) else { continue }
            paths.insert(String(cString: raw))
        }
        return paths
    }()

    // MARK: - VM region anonymous-executable tags (shared with RWXMemoryScanner)

    // 这些 user_tag 对应匿名映射（JIT/栈/堆等）；与可执行权限组合时高度可疑。
    private static let anonymousUserTags: Set<UInt32> = [240, 241, 242, 243, 244, 245]

    // MARK: - Public API

    /// 校验当前调用栈合法性
    ///
    /// - Returns: (isMalicious: 是否检测到恶意跳转, signalId: 若恶意则返回信号 ID)
    public static func validateCallStack() -> (isMalicious: Bool, signalId: String?) {
        #if targetEnvironment(simulator)
        // 模拟器地址空间与真机差异大，回溯结果不可靠，直接跳过避免误报。
        return (false, nil)
        #else
        let addresses = captureReturnAddresses()
        guard !addresses.isEmpty else {
            return (false, nil)
        }

        // 可信区间 = 主 App 的 __TEXT + SDK 的 __TEXT；其余地址要经过多层验证。
        var trustedRanges: [Range<UInt64>] = []
        if let main = mainAppTextSegmentRange() {
            trustedRanges.append(main)
        }
        if let sdk = sdkTextSegmentRange() {
            trustedRanges.append(sdk)
        }

        for addr in addresses {
            let result = validateAddress(addr, trustedRanges: trustedRanges)
            // dladdr hook 是更明确的攻击信号，优先上报。
            if result.dladdrHooked {
                return (true, dladdrHookSignalId)
            }
            if !result.legitimate {
                return (true, ropChainSignalId)
            }
        }
        return (false, nil)
        #endif
    }

    /// 校验调用栈并返回 RiskSignal（供 AntiTamperingSignalProvider 等使用）
    public static func validateCallStackAsSignal() -> RiskSignal? {
        let (isMalicious, signalId) = validateCallStack()
        guard isMalicious, let id = signalId else { return nil }
        return RiskSignal(
            id: id,
            category: ObfuscatedConstants.categoryAntiTamper,
            score: 0,
            evidence: [
                "detail": "call_stack_return_address_outside_trusted_regions",
                "mechanism": "dladdr_dual_path_vm_region_validation",
            ],
            state: .tampered,
            layer: 2,
            weightHint: Double(maliciousWeight)
        )
    }

    // MARK: - Stack capture (RTLD_NEXT backtrace to bypass PLT hook)

    private static func captureReturnAddresses() -> [UInt64] {
        // 64 帧足够覆盖 SDK 内部调用链；固定大小避免回溯本身分配大内存。
        var buffer = [UnsafeMutableRawPointer?](repeating: nil, count: 64)

        let count: Int32
        if let fn = nextBacktraceFn {
            // 优先用 RTLD_NEXT 解析到的 backtrace，绕过对当前镜像 PLT 的 hook。
            count = fn(&buffer, Int32(buffer.count))
        } else {
            count = backtrace(&buffer, Int32(buffer.count))
        }

        // 原生回溯失败时退回 Foundation 的符号字符串解析。
        guard count > 0 else {
            return parseAddressesFromThreadCallStackSymbols()
        }

        var addresses: [UInt64] = []
        for i in 0..<Int(count) {
            guard let ptr = buffer[i] else { continue }
            addresses.append(UInt64(bitPattern: Int64(Int(bitPattern: ptr))))
        }

        return addresses.isEmpty ? parseAddressesFromThreadCallStackSymbols() : addresses
    }

    /// 备选：从 Thread.callStackSymbols 解析地址（纯 Swift）
    private static func parseAddressesFromThreadCallStackSymbols() -> [UInt64] {
        let symbols = Thread.callStackSymbols
        var addresses: [UInt64] = []

        for line in symbols {
            let parts = line.split(separator: " ", omittingEmptySubsequences: true)
            for part in parts {
                let s = String(part)
                // 只接受 64 位地址形态（0x + 8..16 个十六进制位），避免误把帧号当地址。
                if s.hasPrefix("0x"), s.count >= 10, s.count <= 18 {
                    if let addr = UInt64(s.dropFirst(2), radix: 16) {
                        addresses.append(addr)
                        break
                    }
                }
            }
        }
        return addresses
    }

    // MARK: - __TEXT segment ranges

    private static func mainAppTextSegmentRange() -> Range<UInt64>? {
        // image 0 是主可执行文件。
        guard let header = _dyld_get_image_header(0) else { return nil }
        return textSegmentRange(header: UnsafeRawPointer(header))
    }

    private static func sdkTextSegmentRange() -> Range<UInt64>? {
        let count = _dyld_image_count()
        for i in 0..<count {
            guard let raw = _dyld_get_image_name(i) else { continue }
            let path = String(cString: raw)
            // 按镜像名识别 SDK；匹配不到时返回 nil，调用方只信主 App 区间。
            if path.lowercased().contains("cloudphoneriskkit") {
                guard let header = _dyld_get_image_header(i) else { continue }
                return textSegmentRange(header: UnsafeRawPointer(header))
            }
        }
        return nil
    }

    /// 遍历 Mach-O load commands，定位名为 __TEXT 的段并返回其虚拟地址区间。
    private static func textSegmentRange(header: UnsafeRawPointer) -> Range<UInt64>? {
        let ptr = header.assumingMemoryBound(to: mach_header_64.self)
        // 只处理 64 位 Mach-O；字节序不匹配说明头不可信。
        guard ptr.pointee.magic == MH_MAGIC_64 || ptr.pointee.magic == MH_CIGAM_64 else {
            return nil
        }
        let imageBase = UInt64(bitPattern: Int64(Int(bitPattern: header)))
        var cmd = header.advanced(by: MemoryLayout<mach_header_64>.size)

        for _ in 0..<ptr.pointee.ncmds {
            let load = cmd.assumingMemoryBound(to: load_command.self).pointee
            // cmdsize 异常（过小）时停止遍历，防止越界读取损坏的 Mach-O。
            guard load.cmdsize >= MemoryLayout<load_command>.size else { break }
            if load.cmd == LC_SEGMENT_64 {
                let seg = cmd.assumingMemoryBound(to: segment_command_64.self).pointee
                if tupleStringEquals(seg.segname, "__TEXT") {
                    let start = imageBase + seg.vmaddr
                    return start..<(start + seg.vmsize)
                }
            }
            cmd = cmd.advanced(by: Int(load.cmdsize))
        }
        return nil
    }

    /// 比较 Mach-O 中定长 C 字符数组（非 NUL 结尾）与目标字符串。
    private static func tupleStringEquals<T>(_ tuple: T, _ target: String) -> Bool {
        withUnsafePointer(to: tuple) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: MemoryLayout<T>.size) { cPtr in
                // 限长比较，避免读取超出定长数组；相等时即前缀完全一致。
                strncmp(cPtr, target, MemoryLayout<T>.size) == 0
            }
        }
    }

    // MARK: - Multi-layer address validation

    private struct AddressValidation {
        // true 表示地址落在可信镜像/文件映射内。
        var legitimate: Bool
        // true 表示标准 dladdr 与 RTLD_NEXT 版本结果不一致，探测到 hook。
        var dladdrHooked: Bool
    }

    /// Layer 1 → trusted __TEXT range
    /// Layer 2 → dual-path dladdr (hook detection)
    /// Layer 3 → trusted image cache (startup snapshot)
    /// Layer 4 → strict system library prefix matching
    /// Layer 5 → vm_region_64 cross-validation
    private static func validateAddress(
        _ addr: UInt64,
        trustedRanges: [Range<UInt64>]
    ) -> AddressValidation {
        // Layer 1: within app / SDK __TEXT
        for range in trustedRanges {
            if range.contains(addr) {
                return AddressValidation(legitimate: true, dladdrHooked: false)
            }
        }

        // 地址无法转换为指针说明是非法/空值。
        guard let rawPtr = UnsafeRawPointer(bitPattern: UInt(addr)) else {
            return AddressValidation(legitimate: false, dladdrHooked: false)
        }

        // Layer 2: dual-path dladdr — compare standard vs RTLD_NEXT
        var stdInfo = Dl_info()
        let stdFound = dladdr(rawPtr, &stdInfo)

        var nextInfo = Dl_info()
        let nextFound: Int32
        if let fn = nextDladdrFn {
            nextFound = fn(rawPtr, &nextInfo)
        } else {
            // 拿不到 RTLD_NEXT 版本时退化为同一结果，无法做 hook 对比但不误报。
            nextFound = stdFound
            nextInfo = stdInfo
        }

        // 两路解析的“是否找到”不一致，说明其中一路被 hook/篡改。
        if stdFound != nextFound {
            return AddressValidation(legitimate: false, dladdrHooked: true)
        }

        if stdFound != 0, nextFound != 0 {
            let stdPath = stdInfo.dli_fname.map { String(cString: $0) }
            let nextPath = nextInfo.dli_fname.map { String(cString: $0) }
            // 两路都找到但镜像名不同，同样视为 hook。
            if stdPath != nextPath {
                return AddressValidation(legitimate: false, dladdrHooked: true)
            }
        }

        let info = nextInfo
        let found = nextFound

        // dladdr could not resolve → cross-validate with vm_region
        // 解析不到镜像名时交给 vm_region：只有文件映射页才可能是合法的延迟加载库。
        guard found != 0, let fname = info.dli_fname else {
            let vmClass = vmRegionClassify(addr)
            let legitimate = vmClass == .fileMapped
            return AddressValidation(legitimate: legitimate, dladdrHooked: false)
        }

        let path = String(cString: fname)

        // Layer 3: trusted image cache (built from startup snapshot)
        if trustedImagePaths.contains(path) {
            return AddressValidation(legitimate: true, dladdrHooked: false)
        }

        // Layer 4: strict system library prefix matching
        if isKnownSystemLibPath(path) {
            return AddressValidation(legitimate: true, dladdrHooked: false)
        }

        // Layer 5: vm_region cross-validation for unknown/suspicious paths.
        // fileMapped  → address backed by a file on disk (legitimate late-loaded framework)
        // anonymousExecutable → shellcode / ROP gadget page (malicious)
        // unknown     → vm_region failed or ambiguous → treat as suspect
        let vmClass = vmRegionClassify(addr)
        return AddressValidation(legitimate: vmClass == .fileMapped, dladdrHooked: false)
    }

    // MARK: - vm_region_64 cross-validation

    private enum VMRegionClass {
        // 有磁盘文件背书的映射（正常的 dylib/framework）。
        case fileMapped
        // 匿名且可执行：shellcode / JIT / ROP gadget 的典型特征。
        case anonymousExecutable
        // 查询失败或信息不完整，按可疑处理。
        case unknown
    }

    private static func vmRegionClassify(_ addr: UInt64) -> VMRegionClass {
        var address = vm_address_t(addr)
        var size: vm_size_t = 0
        var objectName: mach_port_t = 0

        var basicInfo = vm_region_basic_info_data_64_t()
        // 内核要求 count 以 natural_t 为单位，而非结构体字节数。
        var basicCount = mach_msg_type_number_t(
            MemoryLayout<vm_region_basic_info_data_64_t>.stride
                / MemoryLayout<natural_t>.stride
        )

        let result = withUnsafeMutablePointer(to: &basicInfo) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(basicCount)) { rebound in
                vm_region_64(
                    mach_task_self_, &address, &size,
                    VM_REGION_BASIC_INFO_64, rebound, &basicCount, &objectName
                )
            }
        }

        guard result == KERN_SUCCESS else { return .unknown }

        // Verify the returned region actually contains our target address
        // vm_region 返回的是“包含/相邻”区域，必须复核地址确实落在其中。
        guard addr >= UInt64(address), addr < UInt64(address) + UInt64(size) else {
            return .unknown
        }

        let isExecutable = (basicInfo.protection & VM_PROT_EXECUTE) != 0

        var extInfo = vm_region_extended_info_data_t()
        var extCount = mach_msg_type_number_t(
            MemoryLayout<vm_region_extended_info_data_t>.stride
                / MemoryLayout<natural_t>.stride
        )
        var extAddress = vm_address_t(addr)
        var extSize: vm_size_t = 0

        let extResult = withUnsafeMutablePointer(to: &extInfo) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(extCount)) { rebound in
                vm_region_64(
                    mach_task_self_, &extAddress, &extSize,
                    VM_REGION_EXTENDED_INFO, rebound, &extCount, &objectName
                )
            }
        }

        // 扩展信息失败时，至少还能根据可执行权限给出保守判断。
        guard extResult == KERN_SUCCESS else {
            return isExecutable ? .anonymousExecutable : .unknown
        }

        // SM_PRIVATE = 3, SM_EMPTY = 0 → anonymous memory
        // user_tag 命中匿名映射标签时同样视为匿名。
        let isAnonymous = (extInfo.share_mode == 3 || extInfo.share_mode == 0)
            || anonymousUserTags.contains(UInt32(extInfo.user_tag))

        if isAnonymous && isExecutable {
            return .anonymousExecutable
        }

        if !isAnonymous {
            return .fileMapped
        }

        return .unknown
    }

    // MARK: - Path validation (case-sensitive, no normalization)

    private static func isKnownSystemLibPath(_ path: String) -> Bool {
        // 大小写敏感 + 不做路径归一化：避免 `..`/大小写变体绕过前缀检查。
        for prefix in knownSystemLibPrefixes {
            if path.hasPrefix(prefix) {
                return true
            }
        }
        return false
    }
}
