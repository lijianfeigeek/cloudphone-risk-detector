// 直接系统调用 / libc 旁路工具集：为风控检测提供不经过 libc 的 syscall 与符号解析路径。
// arm64 真机上 CRiskCore 用 `svc #0x80` 直调内核（系统调用号放 x16、参数放 x0–x5），
// 避免 Frida/Substrate 对 libc 的 inline hook 直接篡改检测结果；libc 路径保留作对照基线，
// 由 DualPathValidator 比较双路结果识别篡改。非 arm64/模拟器由 C 层回退 libc 并记录掩码。
import CoreFoundation
import CRiskCore
import Darwin
import Foundation

// RTLD_DEFAULT 的等价句柄：告诉 dlsym 在当前进程的全局符号表中查找。
private let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)

/// 敏感 libc 符号的集中解析器。
/// - 符号名以单字节 XOR 保存，运行时还原后经 dlsym 取地址。
/// - 解析结果用 PAC 重新签名并缓存（仅 arm64e 有真实签名，其他架构为空操作）。
/// - 每次调用前验签；失败视为指针被劫持，清缓存并投毒 SVC 通道，调用方降级到直 syscall。
enum DynamicSymbolResolver {
    // 与 libc 完全一致的 C ABI；函数指针必须标 @convention(c)，否则调用约定不匹配。
    typealias SocketFn = @convention(c) (Int32, Int32, Int32) -> Int32
    typealias ConnectFn = @convention(c) (Int32, UnsafePointer<sockaddr>?, socklen_t) -> Int32
    typealias CloseFn = @convention(c) (Int32) -> Int32
    typealias AccessFn = @convention(c) (UnsafePointer<CChar>?, Int32) -> Int32
    typealias SysctlByNameFn = @convention(c) (
        UnsafePointer<CChar>?,
        UnsafeMutableRawPointer?,
        UnsafeMutablePointer<size_t>?,
        UnsafeRawPointer?,
        size_t
    ) -> Int32
    typealias DlopenFn = @convention(c) (UnsafePointer<CChar>?, Int32) -> UnsafeMutableRawPointer?
    typealias TaskForPidFn = @convention(c) (
        mach_port_name_t,
        pid_t,
        UnsafeMutablePointer<mach_port_name_t>?
    ) -> kern_return_t

    /// 可解析符号的逻辑标识；与下方 `recipes` 表一一对应。
    private enum SymbolID: String {
        case sysctlByName
        case socket
        case connect
        case close
        case access
        case dlopen
        case taskForPid
    }

    /// 单个符号的解码配方。
    /// - `encodedSymbol` / `symbolKey`：XOR 编码的符号名。
    /// - `encodedImage` / `imageKey`：可选镜像名；nil 表示在主程序全局符号表查找。
    /// - `discriminatorSalt`：参与生成 PAC 鉴别值，防止签名指针跨符号挪用。
    private struct SymbolRecipe {
        let encodedSymbol: [UInt8]
        let symbolKey: UInt8
        let encodedImage: [UInt8]?
        let imageKey: UInt8
        let discriminatorSalt: UInt64
    }

    /// 缓存项：PAC 签名后的指针 + 生成时使用的鉴别值。
    private struct SignedEntry {
        let signedPointer: UnsafeMutableRawPointer
        let discriminator: UInt
    }

    /// 保护缓存与首次解析，避免并发重复执行 dlsym / PAC 签名。
    private static let lock = UnfairLock()
    /// 符号 -> 已签名指针；解析成功后常驻，验签失败时删除。
    private static var cache: [SymbolID: SignedEntry] = [:]

    /// 符号编码表（每项结构见 `SymbolRecipe`）。
    /// 符号名不以明文出现在 __TEXT，静态扫描无法直接拼出 dlsym 目标。
    private static let recipes: [SymbolID: SymbolRecipe] = [
        .sysctlByName: SymbolRecipe(
            encodedSymbol: [0x45, 0x4F, 0x45, 0x55, 0x42, 0x5A, 0x54, 0x4F, 0x58, 0x57, 0x5B, 0x53],
            symbolKey: 0x36,
            encodedImage: nil,
            imageKey: 0x00,
            discriminatorSalt: 0xA179_F31C_05D2_8441
        ),
        .socket: SymbolRecipe(
            encodedSymbol: [0x5A, 0x46, 0x4A, 0x42, 0x4C, 0x5D],
            symbolKey: 0x29,
            encodedImage: nil,
            imageKey: 0x00,
            discriminatorSalt: 0xFC12_E739_BA9D_0042
        ),
        .connect: SymbolRecipe(
            encodedSymbol: [0x28, 0x24, 0x25, 0x25, 0x2E, 0x28, 0x3F],
            symbolKey: 0x4B,
            encodedImage: nil,
            imageKey: 0x00,
            discriminatorSalt: 0x88D1_7C2A_E963_91D4
        ),
        .close: SymbolRecipe(
            encodedSymbol: [0x10, 0x1F, 0x1C, 0x00, 0x16],
            symbolKey: 0x73,
            encodedImage: nil,
            imageKey: 0x00,
            discriminatorSalt: 0x3E71_2B95_C004_F8AA
        ),
        .access: SymbolRecipe(
            encodedSymbol: [0x34, 0x36, 0x36, 0x30, 0x26, 0x26],
            symbolKey: 0x55,
            encodedImage: nil,
            imageKey: 0x00,
            discriminatorSalt: 0xD7B6_4E51_93CB_262A
        ),
        .dlopen: SymbolRecipe(
            encodedSymbol: [0x7B, 0x73, 0x70, 0x6F, 0x7A, 0x71],
            symbolKey: 0x1F,
            encodedImage: nil,
            imageKey: 0x00,
            discriminatorSalt: 0x4FB9_1887_4602_1CE1
        ),
        .taskForPid: SymbolRecipe(
            encodedSymbol: [0x4D, 0x58, 0x4A, 0x52, 0x66, 0x5F, 0x56, 0x4B, 0x66, 0x49, 0x50, 0x5D],
            symbolKey: 0x39,
            encodedImage: nil,
            imageKey: 0x00,
            discriminatorSalt: 0x6C51_0A9D_14E2_77BC
        )
    ]

    /// 调用 socket(2)：优先使用已验签的 libc 指针，失败则走 CRiskCore 直 syscall。
    /// 参数语义与 libc 一致；直调用不改 errno，返回后由这里补写。
    static func socket(_ domain: Int32, _ type: Int32, _ protocol: Int32) -> Int32 {
        if let socketFn: SocketFn = resolveFunction(for: .socket, as: SocketFn.self) {
            return socketFn(domain, type, `protocol`)
        }

        // 控制流只会落到“解析/验签失败”的分支，此时改用 C 层直调用（非 arm64 由 C 层回退并记录掩码）。
        var rawErrno: CInt = 0
        let fd = cprisk_socket_direct(domain, type, `protocol`, &rawErrno)
        // C 层通过 rawErrno 带出错误码，这里同步到 errno，保持调用方的 libc 习惯。
        if rawErrno != 0 {
            errno = rawErrno
        }
        return fd
    }

    /// 调用 connect(2)：目标地址与长度原样传给内核，失败时同样补写 errno。
    static func connect(_ sockfd: Int32, _ addr: UnsafePointer<sockaddr>?, _ addrlen: socklen_t) -> Int32 {
        if let connectFn: ConnectFn = resolveFunction(for: .connect, as: ConnectFn.self) {
            return connectFn(sockfd, addr, addrlen)
        }

        var rawErrno: CInt = 0
        let rc = cprisk_connect_direct(sockfd, addr, addrlen, &rawErrno)
        if rawErrno != 0 {
            errno = rawErrno
        }
        return rc
    }

    /// 调用 close(2)：仅关闭文件描述符，不额外处理重试语义。
    static func close(_ fd: Int32) -> Int32 {
        if let closeFn: CloseFn = resolveFunction(for: .close, as: CloseFn.self) {
            return closeFn(fd)
        }

        var rawErrno: CInt = 0
        let rc = cprisk_close_direct(fd, &rawErrno)
        if rawErrno != 0 {
            errno = rawErrno
        }
        return rc
    }

    /// 调用 access(2)；`mode` 取 F_OK / R_OK / W_OK / X_OK 或其组合。
    static func access(_ path: UnsafePointer<CChar>?, _ mode: Int32) -> Int32 {
        if let accessFn: AccessFn = resolveFunction(for: .access, as: AccessFn.self) {
            return accessFn(path, mode)
        }

        var rawErrno: CInt = 0
        let rc = cprisk_access_direct(path, mode, &rawErrno)
        if rawErrno != 0 {
            errno = rawErrno
        }
        return rc
    }

    /// 调用 sysctlbyname(3)。
    /// - `oldp`/`oldlenp` 读取参数：先传 nil 查长度，再按长度取内容。
    /// - `newp`/`newlen` 写入参数：本 SDK 只读，调用方通常传 nil/0。
    static func sysctlByName(
        _ name: UnsafePointer<CChar>?,
        _ oldp: UnsafeMutableRawPointer?,
        _ oldlenp: UnsafeMutablePointer<size_t>?,
        _ newp: UnsafeRawPointer?,
        _ newlen: size_t
    ) -> Int32 {
        if let sysctlByNameFn: SysctlByNameFn = resolveFunction(for: .sysctlByName, as: SysctlByNameFn.self) {
            return sysctlByNameFn(name, oldp, oldlenp, newp, newlen)
        }

        var rawErrno: CInt = 0
        let rc = cprisk_sysctlbyname_direct(name, oldp, oldlenp, newp, newlen, &rawErrno)
        if rawErrno != 0 {
            errno = rawErrno
        }
        return rc
    }

    /// 解析并调用 dlopen；该 API 依赖 dyld 内部状态，CRiskCore 没有直 syscall 等价物，
    /// 因此解析失败直接返回 nil，由调用方按“不可用”处理。
    static func dlopen(_ path: UnsafePointer<CChar>?, _ mode: Int32) -> UnsafeMutableRawPointer? {
        if let dlopenFn: DlopenFn = resolveFunction(for: .dlopen, as: DlopenFn.self) {
            return dlopenFn(path, mode)
        }
        return nil
    }

    /// 调用 task_for_pid 获取目标进程的任务端口。
    /// 失败时显式写出 MACH_PORT_NULL 并返回 KERN_FAILURE，避免上层使用未初始化的 port。
    static func taskForPid(
        _ targetTask: mach_port_name_t,
        _ pid: pid_t,
        _ taskOut: UnsafeMutablePointer<mach_port_name_t>?
    ) -> kern_return_t {
        if let taskForPidFn: TaskForPidFn = resolveFunction(for: .taskForPid, as: TaskForPidFn.self) {
            return taskForPidFn(targetTask, pid, taskOut)
        }
        taskOut?.pointee = mach_port_name_t(MACH_PORT_NULL)
        return kern_return_t(KERN_FAILURE)
    }

    /// 取得符号的已签名指针并验签，再按目标 C 函数类型重解释。
    /// 任一步失败返回 nil；`unsafeBitCast` 只负责 void* → C 函数指针，调用约定由 typealias 保证。
    private static func resolveFunction<T>(for symbolID: SymbolID, as type: T.Type) -> T? {
        guard let entry = resolveSignedEntry(for: symbolID) else {
            return nil
        }
        guard let authed = authenticate(entry, for: symbolID) else {
            return nil
        }
        return unsafeBitCast(authed, to: type)
    }

    /// 解析符号：查缓存 → 解码名称 → dlopen/dlsym → PAC 签名 → 写缓存。
    /// 并发首次解析用双检锁，避免重复 dlsym 与重复签名。
    private static func resolveSignedEntry(for symbolID: SymbolID) -> SignedEntry? {
        // 快路径：命中缓存直接返回，不在锁内做昂贵解析。
        if let cached = lock.withLock({ cache[symbolID] }) { return cached }

        guard let recipe = recipes[symbolID] else {
            return nil
        }

        let symbolName = deobfuscate(recipe.encodedSymbol, key: recipe.symbolKey)
        let imageName: String? = recipe.encodedImage.map { deobfuscate($0, key: recipe.imageKey) }
        // 未指定镜像时使用 RTLD_DEFAULT，在主程序全局符号表中查找。
        let handle = imageName.flatMap { name in
            name.withCString { Darwin.dlopen($0, RTLD_NOW | RTLD_LOCAL) }
        } ?? rtldDefault

        // 指定镜像加载失败：该符号在当前环境不可用，交由调用方降级。
        guard let handle else {
            return nil
        }

        guard let symbolPtr = symbolName.withCString({ dlsym(handle, $0) }) else {
            return nil
        }

        let discriminator = makeDiscriminator(symbol: symbolName, image: imageName, salt: recipe.discriminatorSalt)
        // 非 arm64e 架构下 PAC 签名为空操作，仍返回原指针。
        guard let signed = cprisk_pac_sign_function_pointer(symbolPtr, discriminator) else {
            return nil
        }
        let created = SignedEntry(signedPointer: signed, discriminator: discriminator)

        return lock.withLock {
            // 双检锁：并发解析只保留第一个结果，避免覆盖已有缓存。
            let existing = cache[symbolID]
            if existing == nil {
                cache[symbolID] = created
            }
            return cache[symbolID]
        }
    }

    /// 调用前验签，确认缓存指针仍由本进程签名。
    /// 失败说明指针被改写或 PAC 校验被绕过：投毒 SVC 通道让上层 fail-closed，并清缓存以便下次重解析。
    private static func authenticate(_ entry: SignedEntry, for symbolID: SymbolID) -> UnsafeMutableRawPointer? {
        guard let authed = cprisk_pac_auth_function_pointer(entry.signedPointer, entry.discriminator) else {
            // 投毒后 integrity 快照会持续报告异常，而不是只影响这一次调用。
            cprisk_integrity_poison_svc_iface_lane()
            lock.withLock { cache.removeValue(forKey: symbolID) }
            return nil
        }
        return authed
    }

    /// 单字节 XOR 还原符号名；UTF-8 解码失败时产生空串，随后 dlsym 必然失败并走降级。
    @inline(__always)
    private static func deobfuscate(_ bytes: [UInt8], key: UInt8) -> String {
        let decoded = bytes.map { $0 ^ key }
        return String(decoding: decoded, as: UTF8.self)
    }

    /// 生成 PAC 鉴别值：符号名与镜像名的 FNV-1a 哈希异或每符号独立盐值。
    /// 不同符号得到不同鉴别值，签名指针无法被挪用到另一个符号上。
    @inline(__always)
    private static func makeDiscriminator(symbol: String, image: String?, salt: UInt64) -> UInt {
        var state = fnv1a64(symbol)
        if let image {
            state ^= fnv1a64(image)
        }
        // 截断到 UInt（PAC discriminator 宽度），不同架构位宽不同。
        return UInt(truncatingIfNeeded: state ^ salt)
    }

    /// 标准 FNV-1a 64 位哈希；两个常量分别是 FNV 规范的 offset basis 与 prime。
    @inline(__always)
    private static func fnv1a64(_ input: String) -> UInt64 {
        var hash: UInt64 = 0xCBF2_9CE4_8422_2325  // FNV-1a 64 offset basis
        for byte in input.utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 0x0000_0100_0000_01B3    // FNV prime；&* 允许自然溢出
        }
        return hash
    }
}

/// libc 关键函数序言（inline hook trampoline）扫描器。
/// - 读取函数入口前两条 arm64 指令，识别跳转 / 间接跳转等 hook 特征。
/// - 结果带 TTL 与随机重扫，兼顾性能与“晚注入”检出率；线程安全由 UnfairLock 保证。
enum LibcPrologueGuard {
    // 选择“被 hook 后能伪造检测结论”的关键 API：文件探测、系统信息与栈回溯。
    private static let criticalSymbols = [
        "access", "sysctlbyname", "sysctl", "dladdr", "backtrace"
    ]

    /// 保护扫描缓存与时间戳。
    private static let lock = UnfairLock()
    /// 上次扫描结论：true 表示发现入口被改写。
    private static var lastScannedResult: Bool?
    /// 上次扫描时间（CFAbsoluteTime），用于 TTL 判断。
    private static var lastScannedTimestamp: CFTimeInterval?
    /// 每次检查强制完整重扫的概率（百分比）；随机化避免 hook 方预测缓存窗口。
    private static let rescanProbabilityPercent = 50
    /// 距上次扫描超过此秒数强制重扫，缓解晚注入盲区
    private static let rescanIntervalSeconds: CFTimeInterval = 5

    /// 供 DualPathValidator 在检测到 tampered 时调用，清除缓存以强制下次完整扫描
    static func invalidateCache() {
        lock.withLock {
            lastScannedResult = nil
            lastScannedTimestamp = nil
        }
    }

    /// 返回 true 表示任一关键 libc 函数入口被改写（即检测到 inline hook）。
    /// 缓存未命中、超过 TTL 或概率命中时执行完整扫描，否则复用上次结果。
    static func checkAllCritical() -> Bool {
        let now = CFAbsoluteTimeGetCurrent()
        let (cached, lastTs) = lock.withLock { (lastScannedResult, lastScannedTimestamp) }

        // 晚注入可能发生在首次扫描之后，超时强制重扫以覆盖该盲区。
        let timeDecayForced = lastTs.map { now - $0 > rescanIntervalSeconds } ?? true
        // 随机重扫：避免攻击者通过“卡在缓存有效期内”稳定绕过。
        let shouldRescan = timeDecayForced
            || cached == nil
            || arc4random_uniform(100) < UInt32(rescanProbabilityPercent)

        if shouldRescan {
            let result = performFullScan()
            lock.withLock {
                lastScannedResult = result
                lastScannedTimestamp = now
            }
            return result
        }
        return cached ?? false
    }

    /// 全量扫描：任一符号入口异常即返回 true。
    private static func performFullScan() -> Bool {
        for sym in criticalSymbols {
            if isInlineHooked(symbol: sym) {
                return true
            }
        }
        return false
    }

    /// 读取符号入口的 16 字节（2 条指令）判断是否被 inline hook。
    /// 通过 vm_read_overwrite 复制而非直接解引用：页面不可读时只返回错误，不会触发 SIGBUS。
    static func isInlineHooked(symbol: String) -> Bool {
        // dlsym 失败说明符号不可用，按“未 hook”处理，避免把缺符号误判为篡改。
        guard let ptr = dlsym(rtldDefault, symbol) else { return false }
        let addr = UInt(bitPattern: ptr)

        // 2 条 4 字节 arm64 指令足以覆盖常见跳板（B/BL/BR/BLR/LDR+BR）。
        var buf = [UInt8](repeating: 0, count: 16)
        var outSize: vm_size_t = 0

        let kr = buf.withUnsafeMutableBufferPointer { bufPtr -> kern_return_t in
            guard let base = bufPtr.baseAddress else { return KERN_FAILURE }
            // 只读复制入口字节；不做直接内存访问，避免代码页权限问题导致崩溃。
            return vm_read_overwrite(
                mach_task_self_,
                vm_address_t(addr),
                vm_size_t(16),
                vm_address_t(UInt(bitPattern: base)),
                &outSize
            )
        }

        // 至少需要 8 字节才能拼出两条完整指令。
        guard kr == KERN_SUCCESS, outSize >= 8 else { return false }

        // arm64 指令按小端序拼装。
        let insn0 = UInt32(buf[0])
            | (UInt32(buf[1]) << 8)
            | (UInt32(buf[2]) << 16)
            | (UInt32(buf[3]) << 24)

        let insn1 = UInt32(buf[4])
            | (UInt32(buf[5]) << 8)
            | (UInt32(buf[6]) << 16)
            | (UInt32(buf[7]) << 24)

        // 第一条就是跳转/间接跳转：典型 trampoline 入口。
        if isSuspiciousFirstInstruction(insn0) { return true }

        // 两条指令组合：先取目标地址再间接跳转，是更隐蔽的 trampoline 形式。
        if isAdrpOrLdrLiteral(insn0) && isBranchRegister(insn1) { return true }

        return false
    }

    /// 判断单条“入口指令”是否像跳板：立即数跳转或经 x16/x17 的间接跳转。
    private static func isSuspiciousFirstInstruction(_ insn: UInt32) -> Bool {
        if insn & 0xFC00_0000 == 0x1400_0000 { return true }  // B  立即数跳转
        if insn & 0xFC00_0000 == 0x9400_0000 { return true }  // BL 带链接的立即数跳转
        if insn == 0xD61F_0200 { return true }                 // BR  x16（IP0 间接跳转）
        if insn == 0xD61F_0220 { return true }                 // BR  x17（IP1 间接跳转）
        if insn == 0xD63F_0200 { return true }                 // BLR x16
        if insn == 0xD63F_0220 { return true }                 // BLR x17
        if insn & 0xFF00_0000 == 0x5800_0000 && insn & 0x1F == 0x10 { return true }  // LDR x16, literal
        if insn & 0xFF00_0000 == 0x5800_0000 && insn & 0x1F == 0x11 { return true }  // LDR x17, literal
        // 这里不单独把 ADRP 判为可疑：dladdr/backtrace 等复杂函数常以 ADRP 做 PC 相对寻址，
        // 单条 ADRP 会造成大量误报。ADRP + 分支寄存器的组合由 isInlineHooked 的第二项检查处理。
        return false
    }

    /// 判断指令是否是“为目标地址加载”的 ADRP 或 LDR (literal)。
    /// 只有目标寄存器为 x16/x17 时才返回 true：调用方会与 isBranchRegister 配对，
    /// 目标寄存器必须与随后的 BR 寄存器一致，才构成有效跳板；放宽到任意寄存器会误报。
    private static func isAdrpOrLdrLiteral(_ insn: UInt32) -> Bool {
        // ADRP 编码识别；rd 字段是目标寄存器（0x10=x16 IP0，0x11=x17 IP1）。
        if insn & 0x9F00_0000 == 0x9000_0000 {
            let rd = insn & 0x1F
            return rd == 0x10 || rd == 0x11
        }
        // LDR (literal) 编码识别，同样只接受 x16/x17 目标。
        if insn & 0xFF00_0000 == 0x5800_0000 {
            let rd = insn & 0x1F
            if rd == 0x10 || rd == 0x11 { return true }
        }
        return false
    }

    /// 是否为 BR x16 / BR x17（不含链接的间接跳转，trampoline 常用形态）。
    private static func isBranchRegister(_ insn: UInt32) -> Bool {
        insn == 0xD61F_0200 || insn == 0xD61F_0220
    }
}

/// 安全路径封装：优先使用 CRiskCore 的 arm64 直 syscall（SVC）实现，避免 libc 被 hook。
/// - `secureXxx` 失败返回 nil，表示“安全路径不可用”，由 `DualPathValidator` 判定降级/篡改；
///   非 arm64/模拟器由 C 层回退 libc 并置位 fallback 掩码，交由上层上报。
/// - 路径类参数先做随机掩码，避免明文路径在内存或调用栈中可被直接检索。
enum SVCDirectCall {
    /// 标准 libc 路径的探针结果；nil 表示该探针不可用。
    struct StandardPathProbeSnapshot {
        let access: Bool?
        let stat: Bool?
        let fopen: Bool?

        /// 实际可用的探针数量，用于判断样本是否足够。
        var availableProbeCount: Int {
            [access, stat, fopen].filter { $0 != nil }.count
        }

        var availableValues: [Bool] {
            [access, stat, fopen].compactMap { $0 }
        }

        /// 任一探针认为路径存在。
        var existsAny: Bool {
            availableValues.contains(true)
        }
    }

    /// 加固路径（直 syscall）的探针结果；nil 表示该探针未能给出结论。
    struct SecurePathProbeSnapshot {
        let access: Bool?
        let stat: Bool?
        let lstat: Bool?

        var availableProbeCount: Int {
            [access, stat, lstat].compactMap { $0 }.count
        }

        /// 固定 3 个探针；集中写死便于新增探针时同步修改。
        var unavailableProbeCount: Int {
            3 - availableProbeCount
        }

        var anySecureProbeAvailable: Bool {
            availableProbeCount > 0
        }
    }

    /// 掩码后的路径：`bytes` 与 `seed` 必须一起传给 C 层才能还原。
    private struct MaskedPathEnvelope {
        var bytes: [UInt8]
        let seed: UInt32
    }

    /// 生成路径掩码的第 `index` 个密钥字节。
    /// 从 32 位 seed 中按 index 选一个字节，混入两组与下标相关的奇常量并做循环移位，
    /// 使相邻位置密钥不重复，降低“相同路径异或后可被推断”的风险。
    @inline(__always)
    private static func pathMaskLane(seed: UInt32, index: Int) -> UInt8 {
        // 每 4 个下标轮换 seed 的一个字节，保证 32 位 seed 被充分利用。
        let shift = UInt32((index & 3) * 8)
        var lane = UInt8(truncatingIfNeeded: seed >> shift)
        // 混入下标相关常量（奇数 17、0x5D），避免掩码随路径周期重复。
        lane ^= UInt8(truncatingIfNeeded: index &* 17 &+ 0x5D)
        let rot = index & 7
        // rot=0 时跳过，避免 8 位移位在 UInt8 上越界。
        if rot != 0 {
            lane = (lane << rot) | (lane >> (8 - rot))
        }
        // 再混入另一组奇常量（29、0xA7），进一步打散位模式。
        lane ^= UInt8(truncatingIfNeeded: index &* 29 &+ 0xA7)
        return lane
    }

    /// 把 UTF-8 路径编码为掩码 envelope。
    /// seed 由时间戳、arc4random 与长度共同生成，每次调用都不同，C 层用同一 seed 还原。
    /// `utf8CString` 末尾自带 NUL，C 层解密后会校验该终止符，因此长度必须包含 NUL。
    private static func maskedPathEnvelope(_ path: String) -> MaskedPathEnvelope? {
        var bytes = path.utf8CString.map { UInt8(bitPattern: $0) }
        guard !bytes.isEmpty else { return nil }

        // 三路混合：时间保证单调性、arc4random 提供随机性、长度扩散其余位。
        // 0x45D9 为奇数乘子，把长度混入高位，减少同长度路径的种子碰撞。
        let seed = UInt32(truncatingIfNeeded: mach_absolute_time())
            ^ arc4random()
            ^ UInt32(truncatingIfNeeded: bytes.count &* 0x45D9)

        for index in bytes.indices {
            bytes[index] ^= pathMaskLane(seed: seed, index: index)
        }
        return MaskedPathEnvelope(bytes: bytes, seed: seed)
    }

    /// 尽力擦除掩码后的路径字节，缩短敏感路径在堆上的驻留时间。
    /// 注意：Swift 不保证编译器不优化掉清零操作，这里只能降低而非消除泄漏窗口。
    private static func zeroizeMaskedPath(_ bytes: inout [UInt8]) {
        for index in bytes.indices {
            bytes[index] = 0
        }
    }

    /// 通过 CRiskCore 的 arm64 直 syscall 路径调用 sysctlbyname。
    /// 采用标准两段式：先以 oldp=nil 查询长度，再分配缓冲区二次读取；任一步失败返回 nil。
    /// 非 arm64/模拟器由 C 层回退 libc 并记录 fallback 掩码，调用方需结合掩码判断可信度。
    static func secureSysctlbyname(_ name: String) -> String? {
        return name.withCString { cName in
            var size: size_t = 0
            var rawErrno: CInt = 0
            // 第一段：只查询所需长度，不读取内容。
            if cprisk_sysctlbyname_direct(cName, nil, &size, nil, 0, &rawErrno) != 0 || size == 0 {
                return nil
            }
            // 多分配 1 字节用于手动补 NUL，兼容把结果当 C 字符串使用的调用方。
            var buf = [CChar](repeating: 0, count: max(1, Int(size) + 1))
            let result = buf.withUnsafeMutableBufferPointer { buffer in
                cprisk_sysctlbyname_direct(cName, buffer.baseAddress, &size, nil, 0, &rawErrno)
            }
            // 长度必须落在缓冲区内；越界说明返回值竞争或被篡改，按失败处理。
            if result != 0 || size == 0 || Int(size) >= buf.count {
                return nil
            }
            // 显式终止，避免后续 String(cString:) 越界读取。
            buf[Int(size)] = 0
            return String(cString: buf)
        }
    }

    /// 标准 libc sysctl 路径，作为双路校验的对照基线。
    /// 同样两段式调用：先取长度，再按长度读取内容。
    static func standardSysctlData(_ mib: [Int32]) -> Data? {
        var mibCopy = mib
        guard !mibCopy.isEmpty else { return nil }

        var length: size_t = 0
        let sizeResult = mibCopy.withUnsafeMutableBufferPointer { buffer in
            Darwin.sysctl(buffer.baseAddress, u_int(buffer.count), nil, &length, nil, 0)
        }
        guard sizeResult == 0, length > 0 else { return nil }

        var data = Data(count: Int(length))
        let success = data.withUnsafeMutableBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return false }
            // sysctl 会回写实际长度；每次调用都用独立副本，避免影响后续比较。
            var sizeCopy = length
            return mibCopy.withUnsafeMutableBufferPointer { buffer in
                Darwin.sysctl(buffer.baseAddress, u_int(buffer.count), baseAddress, &sizeCopy, nil, 0) == 0 && sizeCopy > 0
            }
        }
        return success ? data : nil
    }

    /// 通过 CRiskCore 的 arm64 直 syscall 路径调用 sysctl（MIB 形式）。
    /// 失败返回 nil，表示安全路径不可用；非 arm64/模拟器由 C 层回退并记录 fallback 掩码。
    static func secureSysctlData(_ mib: [Int32]) -> Data? {
        var mibCopy = mib
        guard !mibCopy.isEmpty else { return nil }

        var length: size_t = 0
        var rawErrno: CInt = 0
        let sizeResult = mibCopy.withUnsafeMutableBufferPointer { buffer in
            cprisk_sysctl_direct(buffer.baseAddress, u_int(buffer.count), nil, &length, nil, 0, &rawErrno)
        }
        guard sizeResult == 0, length > 0 else { return nil }

        var data = Data(count: Int(length))
        let success = data.withUnsafeMutableBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return false }
            // 独立长度副本：C 层会回写实际长度，不能复用第一次的查询结果。
            var sizeCopy = length
            return mibCopy.withUnsafeMutableBufferPointer { buffer in
                cprisk_sysctl_direct(buffer.baseAddress, u_int(buffer.count), baseAddress, &sizeCopy, nil, 0, &rawErrno) == 0
                    && sizeCopy > 0
            }
        }
        return success ? data : nil
    }

    /// 通过 CRiskCore 的 arm64 直 syscall 路径调用 stat。
    /// 返回 true=存在，false=确定不存在（ENOENT/ENOTDIR），nil=安全路径不可用。
    /// 调用失败返回 nil 而不回退；平台不支持时的 C 层回退会被记录为 fallback 掩码。
    static func secureStat(_ path: String) -> Bool? {
        guard var envelope = maskedPathEnvelope(path) else { return nil }
        // 无论成功失败都擦除掩码路径，缩短敏感路径在堆上的驻留时间。
        defer { zeroizeMaskedPath(&envelope.bytes) }
        return envelope.bytes.withUnsafeBufferPointer { buffer in
            var rawErrno: CInt = 0
            let result = cprisk_stat_masked(buffer.baseAddress, buffer.count, envelope.seed, nil, &rawErrno)
            if result == 0 { return true }
            // 只有明确的“不存在”才返回 false；其它错误说明安全路径本身异常。
            if rawErrno == ENOENT || rawErrno == ENOTDIR { return false }
            return nil
        }
    }

    /// 通过 CRiskCore 的 arm64 直 syscall 路径调用 lstat（不跟随符号链接）。
    /// 返回语义同 `secureStat`：true/false 为明确结论，nil 为安全路径不可用。
    static func secureLstat(_ path: String) -> Bool? {
        guard var envelope = maskedPathEnvelope(path) else { return nil }
        defer { zeroizeMaskedPath(&envelope.bytes) }
        return envelope.bytes.withUnsafeBufferPointer { buffer in
            var rawErrno: CInt = 0
            let result = cprisk_lstat_masked(buffer.baseAddress, buffer.count, envelope.seed, nil, &rawErrno)
            if result == 0 { return true }
            // 同 stat：仅把确定性错误映射为 false，其余错误按安全路径失效处理。
            if rawErrno == ENOENT || rawErrno == ENOTDIR { return false }
            return nil
        }
    }

    /// 通过 direct lstat 读取 inode / st_dev / st_size，用于跨时间基线漂移检测。
    /// 三个字段分别是文件唯一标识、所在设备号与文件大小；失败返回 nil，
    /// 由上层回退为“无基线可用”逻辑而非崩溃。
    static func secureLstatDetail(path: String) -> (inode: UInt64, stDev: UInt32, stSize: Int64)? {
        guard var envelope = maskedPathEnvelope(path) else { return nil }
        defer { zeroizeMaskedPath(&envelope.bytes) }
        return envelope.bytes.withUnsafeBufferPointer { buffer in
            var rawErrno: CInt = 0
            var sb = stat()
            let result = cprisk_lstat_masked(buffer.baseAddress, buffer.count, envelope.seed, &sb, &rawErrno)
            guard result == 0 else {
                return nil
            }

            let inode = UInt64(sb.st_ino)
            let stDev = UInt32(truncatingIfNeeded: sb.st_dev)
            let stSize = Int64(sb.st_size)
            return (inode: inode, stDev: stDev, stSize: stSize)
        }
    }

    /// 并行执行 access / stat / lstat 三个安全探针，各自独立返回 Bool?。
    static func securePathProbeSnapshot(_ path: String, mode: CInt = F_OK) -> SecurePathProbeSnapshot {
        SecurePathProbeSnapshot(
            access: secureAccess(path, mode: mode),
            stat: secureStat(path),
            lstat: secureLstat(path)
        )
    }

    /// 由 C 层一次完成 access / stat / fopen 三个标准探针，结果以位掩码返回。
    /// `available_mask` 标记哪些探针真正执行，`exists_mask` 标记哪些返回存在。
    static func standardPathProbeSnapshot(_ path: String) -> StandardPathProbeSnapshot {
        guard var envelope = maskedPathEnvelope(path) else {
            return StandardPathProbeSnapshot(access: nil, stat: nil, fopen: nil)
        }
        defer { zeroizeMaskedPath(&envelope.bytes) }
        var cSnapshot = cprisk_path_probe_snapshot_t(available_mask: 0, exists_mask: 0)
        let status = envelope.bytes.withUnsafeBufferPointer {
            cprisk_probe_path_snapshot_masked($0.baseAddress, $0.count, envelope.seed, &cSnapshot)
        }
        // 整体调用失败时三个探针都视为不可用，避免把 0 掩码误读成“不存在”。
        guard status == 0 else {
            return StandardPathProbeSnapshot(access: nil, stat: nil, fopen: nil)
        }

        // 位掩码解释：未提供该探针返回 nil，提供了则看 exists 位。
        func probeValue(_ probeMask: UInt32) -> Bool? {
            guard (cSnapshot.available_mask & probeMask) != 0 else { return nil }
            return (cSnapshot.exists_mask & probeMask) != 0
        }

        return StandardPathProbeSnapshot(
            access: probeValue(UInt32(CPRISK_PATH_PROBE_ACCESS)),
            stat: probeValue(UInt32(CPRISK_PATH_PROBE_STAT)),
            fopen: probeValue(UInt32(CPRISK_PATH_PROBE_FOPEN))
        )
    }

    /// 通过 CRiskCore 的 arm64 直 syscall 路径调用 access。
    /// 返回 true=可访问，false=确定不可访问，nil=安全路径不可用。
    static func secureAccess(_ path: String, mode: CInt = F_OK) -> Bool? {
        guard var envelope = maskedPathEnvelope(path) else { return nil }
        defer { zeroizeMaskedPath(&envelope.bytes) }
        return envelope.bytes.withUnsafeBufferPointer { buffer in
            var rawErrno: CInt = 0
            let result = cprisk_access_masked(buffer.baseAddress, buffer.count, envelope.seed, mode, &rawErrno)
            if result == 0 { return true }
            // EACCES/EPERM 表示路径存在但当前进程无权限，按“不可访问”返回 false；
            // 其它错误说明安全路径本身异常，返回 nil 交给双路校验判定。
            if rawErrno == ENOENT || rawErrno == ENOTDIR || rawErrno == EACCES || rawErrno == EPERM { return false }
            return nil
        }
    }

    /// 标准 libc access 的原始错误码版本（路径同样掩码）。
    /// 返回 (exists, errno) 而不是 Bool，便于调用方区分 ENOENT 与权限/其它错误。
    static func standardAccessErrnoMasked(_ path: String, mode: CInt = F_OK) -> (exists: Bool, errno: Int32)? {
        guard var envelope = maskedPathEnvelope(path) else { return nil }
        defer { zeroizeMaskedPath(&envelope.bytes) }
        return envelope.bytes.withUnsafeBufferPointer { buffer in
            var rawErrno: CInt = 0
            let result = cprisk_access_masked_libc(buffer.baseAddress, buffer.count, envelope.seed, mode, &rawErrno)
            if result == 0 {
                return (true, 0)
            }
            return (false, rawErrno)
        }
    }
}

/// 双路校验器：标准 libc 与直 syscall 各执行一次并比较结果 / 耗时。
/// - tampered：两路结论不一致（通常 hook 只改了一路）。
/// - bypassed：任一路耗时 < 50ns，像是被 stub 或直接返回。
/// - traced：耗时超过 getpid 基线的 500 倍，疑似 DBI/Stalker 插桩。
/// - inlineHooked：由 libc 函数序言扫描得出。
struct DualPathValidator {
    /// mach 绝对时间到纳秒的换算系数，进程内只取一次。
    static let timebaseInfo: mach_timebase_info_data_t = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info
    }()

    /// 测量闭包执行耗时，返回纳秒。
    /// 先除后乘，避免 elapsed * numer 在长时间测量时溢出 UInt64。
    static func measure(_ block: () -> Void) -> UInt64 {
        let start = mach_absolute_time()
        block()
        let end = mach_absolute_time()
        // 先做除法再乘：代价是极小精度损失，换取大时间差下不溢出。
        let elapsed = end - start
        let denom = UInt64(max(timebaseInfo.denom, 1))
        let numer = UInt64(timebaseInfo.numer)
        return elapsed / denom * numer
    }

    /// 当前是否检测到 libc inline hook（结果由 LibcPrologueGuard 的缓存/重扫策略决定）。
    static var inlineHookDetected: Bool {
        LibcPrologueGuard.checkAllCritical()
    }

    // MARK: - getpid SVC 动态基线（DBI 过慢检测）

    /// 保护基线与时间戳的读写。
    private static let baselineLock = UnfairLock()
    /// 最近一次测得的 getpid 直调用耗时（纳秒）。
    private static var cachedGetpidBaseline: UInt64 = 0
    /// 基线采样时间（CFAbsoluteTime）。
    private static var baselineTimestamp: CFTimeInterval = 0
    /// 基线缓存 5 秒：太短会频繁测量，太长会掩盖突发的插桩。
    private static let baselineCacheDuration: CFTimeInterval = 5.0
    /// 实际 syscall 耗时超过 getpid 基线的此倍数即判定为 DBI traced
    /// 500 倍阈值远高于正常抖动，又能在 Stalker 放大时触发。
    private static let stalkerSlowdownMultiplier: UInt64 = 500

    /// 取得 getpid 直调用的耗时基线；缓存有效期内直接复用。
    /// 用相对基线而非绝对阈值，避免不同设备/负载下的固定阈值误报。
    static var getpidBaseline: UInt64 {
        let now = CFAbsoluteTimeGetCurrent()
        let (cached, ts) = baselineLock.withLock { (cachedGetpidBaseline, baselineTimestamp) }

        if cached > 0 && (now - ts) < baselineCacheDuration {
            return cached
        }
        let baseline = measure { _ = cprisk_getpid_direct() }
        // 下限设为 1，防止测量结果为 0 导致阈值恒为 0、任何调用都被判 traced。
        let value = max(baseline, 1)
        baselineLock.withLock {
            cachedGetpidBaseline = value
            baselineTimestamp = now
        }
        return value
    }

    /// 判断任一耗时是否超过基线 × 500；可变参数便于同时传入两路测量值。
    static func isTracedTiming(_ durations: UInt64...) -> Bool {
        let threshold = getpidBaseline &* stalkerSlowdownMultiplier
        return durations.contains { $0 > threshold }
    }

    /// 同时调用标准 libc 与加固版本，结果不一致则判定为 tampered。
    /// - 两路都失败：返回 nil，不视为篡改（可能是共同的环境限制）。
    /// - 仅一路失败：说明该路径被单独干预，判 tampered。
    /// - 两路都有值但不同：以 secure 为准并判 tampered，同时刷新序言扫描缓存。
    static func validateSysctl(key: String) -> (value: String?, tampered: Bool, bypassed: Bool, traced: Bool, inlineHooked: Bool) {
        let hooked = inlineHookDetected

        // 标准 libc 路径，作为对照。
        var std: String?
        let t1 = measure { std = Sysctl.string(key) }

        // 加固路径：arm64 上走 SVC 直调用，绕过被 hook 的 libc。
        var secure: String?
        let t2 = measure { secure = SVCDirectCall.secureSysctlbyname(key) }

        // 50 纳秒：检测「时序注入绕过」——syscall 异常快（如被 stub 或直接返回）时判定 bypassed。
        let bypassed = t1 < 50 || t2 < 50
        let traced = isTracedTiming(t1, t2)

        if std == nil && secure == nil { return (nil, false, bypassed, traced, hooked) }
        if std == nil || secure == nil { return (secure ?? std, true, bypassed, traced, hooked) }
        let tampered = std != secure
        // 结果冲突说明序言扫描缓存可能已过期，强制下次完整重扫。
        if tampered { LibcPrologueGuard.invalidateCache() }
        return (secure, tampered, bypassed, traced, hooked)
    }

    /// sysctl MIB 版本的双路校验；判定规则与 `validateSysctl` 完全一致。
    static func validateSysctlData(mib: [Int32]) -> (data: Data?, tampered: Bool, bypassed: Bool, traced: Bool, inlineHooked: Bool) {
        let hooked = inlineHookDetected

        var std: Data?
        let t1 = measure { std = SVCDirectCall.standardSysctlData(mib) }

        var secure: Data?
        let t2 = measure { secure = SVCDirectCall.secureSysctlData(mib) }

        // 50 纳秒：检测「时序注入绕过」，非 stat 延迟阈值（见上方 validateSysctl 注释）
        let bypassed = t1 < 50 || t2 < 50
        let traced = isTracedTiming(t1, t2)

        if std == nil && secure == nil { return (nil, false, bypassed, traced, hooked) }
        if std == nil || secure == nil { return (secure ?? std, true, bypassed, traced, hooked) }
        let tampered = std != secure
        if tampered { LibcPrologueGuard.invalidateCache() }
        return (secure ?? std, tampered, bypassed, traced, hooked)
    }

    /// 同时调用 C 层标准路径探针（access/stat/fopen）与加固 access；
    /// 结果不一致或安全路径不可用且标准路径命中时，判定 tampered。
    /// `exists` 汇总两路结论：只要任一路认为存在即返回 true（宁可多报，不漏报）。
    static func validateFileStat(path: String) -> (exists: Bool, tampered: Bool, bypassed: Bool, traced: Bool, inlineHooked: Bool) {
        let hooked = inlineHookDetected

        var standardSnapshot = SVCDirectCall.StandardPathProbeSnapshot(access: nil, stat: nil, fopen: nil)
        let t1 = measure {
            standardSnapshot = SVCDirectCall.standardPathProbeSnapshot(path)
        }

        var secureAccessExists: Bool?
        let t2 = measure { secureAccessExists = SVCDirectCall.secureAccess(path) }

        // 50 纳秒：检测「时序注入绕过」，任一探针异常快则 bypassed。
        let bypassed = t1 < 50 || t2 < 50
        let traced = isTracedTiming(t1, t2)

        // 标准路径可能部分探针不可用；只把有结论的值纳入比较。
        let standardValues = standardSnapshot.availableValues
        let standardExists = standardSnapshot.existsAny

        // 安全路径返回 nil 且标准探针命中：安全路径失效本身即异常，判定 tampered
        let secureUnavailableButStdHasValue =
            secureAccessExists == nil && standardExists
        // 双路均有值时，任一标准探针与 secure 结论冲突则 tampered
        let mismatchWhenBothAvailable =
            secureAccessExists != nil && standardValues.contains { $0 != secureAccessExists }
        let tampered = secureUnavailableButStdHasValue || mismatchWhenBothAvailable
        // 冲突时强制下次重扫 libc 序言，确认是否真的存在 hook。
        if tampered { LibcPrologueGuard.invalidateCache() }
        // 优先采用安全路径结论；安全路径不可用时退回标准路径，避免漏检。
        let exists = (secureAccessExists ?? standardExists) || standardExists
        return (exists, tampered, bypassed, traced, hooked)
    }
}
