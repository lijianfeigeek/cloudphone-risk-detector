// FunctionIntegrityHashDetector：对关键系统函数前 32 字节做基线哈希并在后续比对。
// GumTrampolineDetector 只能识别已知跳板模式，Dobby/Ellekit 或整体重编译会绕过；
// 本检测器只关心“字节是否变化”，因此能覆盖任意 hook 引擎与函数体重写。
// 首次调用只播种基线，不产生判决，避免初始化阶段误报。
import CRiskCore
import Darwin
import Foundation
import MachO

// MARK: - Function Integrity Hash Detector
//
// GumTrampolineDetector 依赖已知的 hook 指令模式（LDR+BR、ADRP+ADD+BR 等），
// 但 Dobby、Ellekit 等非 Frida hook 引擎使用不同的跳板序列，
// 更高级的攻击者可能整体重编译函数代码，完全规避模式匹配。
//
// 本检测器采用"基线快照 + 变更检测"策略：
// 1. SDK 初始化时，对关键系统函数的前 32 字节计算 FNV-1a 哈希作为基线
// 2. 后续评估时重新计算哈希并与基线对比
// 3. 任何字节变化（不管 hook 使用何种指令序列或工具）均触发报警
//
// 覆盖场景：Substrate、Dobby、Ellekit inline hook；函数体重编译；任意非标准 hook 变体

/// Thread-safe baseline storage for prologue hashes.
/// Populated on first `detect()` call; subsequent calls validate against this snapshot.
/// 关键函数 prologue 哈希基线。
/// - 线程安全：内部 NSLock 保护。
/// - 一次性：首次播种后封存，后续 detect 不再改写基线。
private final class PrologueHashBaseline {
    // 进程级单例，保证基线与生命周期一致。
    static let shared = PrologueHashBaseline()
    // 保护 baseline 与 isSealed。
    private let lock = NSLock()
    // symbol -> FNV-1a 64 位哈希。
    private var baseline: [String: UInt64] = [:]
    // 基线完成后封存，防止后续调用把被 hook 的代码写成新基线。
    private var isSealed = false

    private init() {}

    /// 写入单个符号的基线哈希；已封存则忽略。
    func store(symbol: String, hash: UInt64) {
        lock.withLock {
            guard !isSealed else { return }
            baseline[symbol] = hash
        }
    }

    /// 封存基线，之后不再接受写入。
    func seal() {
        lock.withLock { isSealed = true }
    }

    /// 读取符号的基线哈希。
    func hash(for symbol: String) -> UInt64? {
        lock.withLock { baseline[symbol] }
    }

    /// 基线是否已建立且非空。
    var hasBaseline: Bool {
        lock.withLock { isSealed && !baseline.isEmpty }
    }
}

/// 函数完整性哈希检测器。
/// - 线程模型：同步读取；基线访问由 PrologueHashBaseline 加锁。
/// - 失败语义：符号无法解析时不计入变化，但会单独记 missing。
struct FunctionIntegrityHashDetector: Detector {

    // MARK: - Configuration

    /// Number of ARM64 instructions (4 bytes each) to snapshot per function.
    // 每个函数快照 8 条 ARM64 指令（32 字节）。
    private static let prologueInstructions = 8      // 32 bytes
    // 对应的字节数，用于哈希循环。
    private static let prologueByteCount   = prologueInstructions * 4

    /// High-value system functions targeted by hook engines.
    /// Using (name, library) tuples consistent with GumTrampolineDetector.
    // 与 GumTrampolineDetector 对齐的高危符号，便于两类证据交叉印证。
    private static let monitoredSymbols: [(name: String, library: String)] = [
        ("open",          "/usr/lib/system/libsystem_kernel.dylib"),
        ("openat",        "/usr/lib/system/libsystem_kernel.dylib"),
        ("stat",          "/usr/lib/system/libsystem_kernel.dylib"),      // libc stat wrapper — not the raw syscall stub
        ("lstat",         "/usr/lib/system/libsystem_kernel.dylib"),
        ("access",        "/usr/lib/system/libsystem_kernel.dylib"),
        ("dlopen",        "/usr/lib/system/libdyld.dylib"),
        ("dlsym",         "/usr/lib/system/libdyld.dylib"),
        ("mmap",          "/usr/lib/system/libsystem_kernel.dylib"),
        ("mprotect",      "/usr/lib/system/libsystem_kernel.dylib"),
        ("sysctl",        "/usr/lib/system/libsystem_kernel.dylib"),
        ("sysctlbyname",  "/usr/lib/system/libsystem_kernel.dylib"),
        ("pthread_create","/usr/lib/system/libsystem_pthread.dylib"),
        ("fork",          "/usr/lib/system/libsystem_kernel.dylib"),
        ("posix_spawn",   "/usr/lib/system/libsystem_kernel.dylib"),
        ("objc_msgSend",  "/usr/lib/libobjc.A.dylib"),
        ("socket",        "/usr/lib/system/libsystem_kernel.dylib"),
        ("connect",       "/usr/lib/system/libsystem_kernel.dylib"),
    ]

    // MARK: - Detector Protocol

    /// 入口：模拟器直接返回 0，真机进入 `detectKernel()`。
    @inline(never)
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["fih:unavailable_simulator"])
#else
        return detectKernel()
#endif
    }

    /// 首次调用播种基线；之后每次与基线比对。
    @inline(never)
    private func detectKernel() -> DetectorResult {
        let baseline = PrologueHashBaseline.shared

        // 尚无基线：只播种，不产生判决。
        if !baseline.hasBaseline {
            seedBaseline()
            // First call: seed only, no verdict yet — return clean to avoid false positive at init
            // 返回 clean，避免 SDK 初始化阶段误报。
            return DetectorResult(score: 0, methods: ["fih:baseline_seeded"])
        }

        return validateAgainstBaseline()
    }

    // MARK: - Baseline Seeding

    /// 解析所有受监控符号并保存其 prologue 哈希，然后封存。
    private func seedBaseline() {
        let baseline = PrologueHashBaseline.shared
        for sym in Self.monitoredSymbols {
            guard let ptr = resolveSymbol(sym.name, library: sym.library) else { continue }
            let hash = prologueHash(ptr)
            baseline.store(symbol: sym.name, hash: hash)
        }
        baseline.seal()
    }

    // MARK: - Validation

    /// 重新计算哈希并与基线比较。
    private func validateAgainstBaseline() -> DetectorResult {
        let baseline = PrologueHashBaseline.shared
        var score: Double = 0
        var methods: [String] = []
        var changedCount = 0
        var missingCount = 0

        for sym in Self.monitoredSymbols {
            // 基线时无法解析的符号跳过，不参与后续判断。
            guard let expectedHash = baseline.hash(for: sym.name) else {
                // Symbol wasn't resolvable at baseline time — skip
                continue
            }

            // 现在解析不到：库被卸载或符号被隐藏，按可疑处理。
            guard let ptr = resolveSymbol(sym.name, library: sym.library) else {
                // Symbol no longer resolvable — suspicious (library unloaded / address hidden)
                missingCount += 1
                score += 8
                methods.append("fih:missing:\(sym.name)")
                continue
            }

            let currentHash = prologueHash(ptr)
            // 哈希变化：前 32 字节被改写，高置信 hook。
            if currentHash != expectedHash {
                changedCount += 1
                score += 18  // Binary change = high confidence hook
                methods.append("fih:changed:\(sym.name)")
            }
        }

        // Bonus: multiple functions changed → higher confidence
        // 3 个及以上函数同时变化，追加 20 分。
        if changedCount >= 3 {
            score += 20
            methods.append("fih:multi_change:\(changedCount)")
        }
        // 变化 + 缺失组合，追加 10 分。
        if changedCount >= 1 && missingCount >= 1 {
            score += 10
            methods.append("fih:change_and_missing")
        }

        if methods.isEmpty {
            methods.append("fih:clean")
        }

        // 总分封顶 80。
        return DetectorResult(score: min(score, 80), methods: methods)
    }

    // MARK: - Helpers

    /// Resolve a symbol from a specific library using `dlopen` + `dlsym`.
    /// 通过 dlopen(RTLD_NOLOAD)+dlsym 解析指定库中的符号。
    private func resolveSymbol(_ name: String, library: String) -> UnsafeRawPointer? {
        // RTLD_NOLOAD 只查已加载库，不触发加载。
        guard let handle = dlopen(library, RTLD_NOLOAD | RTLD_NOW) else { return nil }
        defer { dlclose(handle) }
        guard let addr = dlsym(handle, name) else { return nil }
        return UnsafeRawPointer(addr)
    }

    /// Compute a 64-bit FNV-1a hash of the first `prologueByteCount` bytes at `ptr`.
    /// FNV-1a is fast and collision-resistant enough for integrity checking.
    /// 计算前 `prologueByteCount` 字节的 FNV-1a 64 位哈希。
    private func prologueHash(_ ptr: UnsafeRawPointer) -> UInt64 {
        let bytes = ptr.assumingMemoryBound(to: UInt8.self)
        // FNV-1a offset basis。
        var hash: UInt64 = 0xcbf29ce484222325
        for i in 0..<Self.prologueByteCount {
            hash ^= UInt64(bytes[i])
            hash &*= 0x100000001b3
        // FNV-1a prime。
        }
        return hash
    }
}

// MARK: - Signal Bridge

/// 信号转换。
extension FunctionIntegrityHashDetector {
    /// 输出 changed/missing 计数与前几个符号，state 为 soft。
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        // 拆出变化与缺失两类方法，分别计数。
        let changed = result.methods.filter { $0.hasPrefix("fih:changed:") }
        let missing = result.methods.filter { $0.hasPrefix("fih:missing:") }

        return [RiskSignal(
            id: "function_integrity_hash_changed",
            category: ObfuscatedConstants.categoryAntiTamper,
            score: result.score,
            evidence: [
                "changed_count": "\(changed.count)",
                "missing_count": "\(missing.count)",
                "symbols": changed.prefix(5).joined(separator: ","),
            ],
            // 置信度随变化函数数量上升，封顶 0.95。
            state: .soft(confidence: min(0.5 + Double(changed.count) * 0.15, 0.95)),
            layer: 2,
            weightHint: 75
        )]
    }
}
