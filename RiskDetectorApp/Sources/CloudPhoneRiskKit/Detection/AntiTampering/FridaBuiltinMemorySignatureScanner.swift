// 内置 Frida/Gum 内存字符串扫描器。
// 扫描本进程 RX/RW 映射中的特征 marker，与端口/环境/模块检测形成互补：
// 即使 Frida 清除了端口和文件痕迹，agent 代码/数据中的字符串仍可能残留。
// 通过节流与页预算把开销限制在可控范围，模拟器上直接跳过。
import Darwin
import Foundation

/// 进程内 RX / RW 映射上的 Frida/Gum 字符串特征扫描（节流 + 可关闭）。
/// 与 `FridaDetector` 的端口/文件/环境检测互补；误报控制依赖较长 marker 与区域/页数预算。
/// 已加载内存中的 Frida/Gum 字符串特征扫描器（节流 + 可配置预算）。
/// 误报控制依赖较长 marker（>=8 字节）和区域/页数上限。
enum FridaBuiltinMemorySignatureScanner {
    // 上次扫描的单调时钟纳秒；0 表示尚未扫描。仅用于节流，不参与判定。
    private static let scanState = Mutex<UInt64>(0)  // lastScanMonotonicNs

    #if DEBUG
    /// 仅用于测试：确认在关闭配置时不会进入 `performScan`。
    /// DEBUG 计数器：确认关闭配置时不会进入 `performScan`。
    private(set) static var debugPerformScanCount: Int = 0

    /// 测试清空调试计数。
    static func resetDebugCountersForTests() {
        debugPerformScanCount = 0
    }

    /// 测试重置节流时间，使下一次调用必然扫描。
    static func resetThrottleStateForTests() {
        scanState.withLock { $0 = 0 }
    }
    #endif

    /// 内置扫描是否启用：默认开启，显式 0/false/off 关闭。
    /// Release 下环境变量被忽略，避免外部关闭扫描。
    /// 内置扫描是否启用（`CPRISK_FRIDA_MEMSIG_BUILTIN` 缺省为开启；显式 `0/false/off` 关闭）。
    internal static func isBuiltinEnabled() -> Bool {
        Configuration.current().enabled
    }

    /// 测试入口：在给定缓冲区中匹配与运行时相同的 needle 集合。
    /// 单元测试：在内存块中匹配与运行时扫描相同的 needle 集合（不访问 `vm_region`）。
    internal static func firstMatchInBufferForTesting(_ data: Data) -> String? {
        let needles = Self.compiledNeedleTable()
        return Self.firstMatch(in: data, needles: needles)
    }

    /// 节流后的扫描入口。
    /// - 返回：命中的 marker 标签；未命中或未启用返回 nil。
    /// - 模拟器恒为 nil，与 `FridaDetector` 行为一致。
    /// 节流后的内置扫描入口；模拟器上恒为 nil（与 `FridaDetector` 一致）。
    static func scanIfNeeded() -> String? {
// 模拟器内存布局与真机差异大，跳过。
#if targetEnvironment(simulator)
        return nil
#else
        let configuration = Configuration.current()
        // 配置关闭时直接返回，不触碰 vm_region。
        guard configuration.enabled else { return nil }

        // Check throttle under lock, but run the heavy scan outside.
        // 节流判断在锁内完成，重扫描在锁外执行，避免长时间持锁阻塞其他线程。
        let shouldScan = scanState.withLock { lastScanMonotonicNs -> Bool in
            let now = monotonicNanoseconds()
            if lastScanMonotonicNs != 0 {
                let delta = now &- lastScanMonotonicNs
                // 距上次扫描不足 minIntervalNs（默认 90s）则跳过，控制整体 CPU 开销。
                if delta < configuration.minIntervalNs {
                    return false
                }
            }
            return true
        }
        guard shouldScan else { return nil }

        let hit = performScan(configuration: configuration)
        // 无论命中与否都更新节流时间，避免连续调用导致重复全量扫描。
        scanState.withLock { $0 = monotonicNanoseconds() }
        return hit
#endif
    }

    // MARK: - Scan core

    /// 真正执行扫描：按 region 遍历，在页预算内读取并匹配特征。
    private static func performScan(configuration: Configuration) -> String? {
        #if DEBUG
        debugPerformScanCount += 1
        #endif

        let needles = compiledNeedleTable()
        guard !needles.isEmpty else { return nil }

        // pagesBudget 是单次扫描的总页数上限，防止大内存进程拖垮主线程。
        let pageSize = vm_size_t(getpagesize())
        var pagesBudget = configuration.maxPagesPerScan

        var address: vm_address_t = 0
        var iteration = 0

        // 最多遍历固定数量的 region，避免异常进程造成长时间循环。
        while iteration < configuration.maxRegionIterations && pagesBudget > 0 {
            var size: vm_size_t = 0
            var objectName: mach_port_t = 0
            var basicInfo = vm_region_basic_info_data_64_t()
            var basicCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_basic_info_data_64_t>.stride / MemoryLayout<natural_t>.stride
            )

            let kr = withUnsafeMutablePointer(to: &basicInfo) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(basicCount)) { rebound in
                    vm_region_64(mach_task_self_, &address, &size, VM_REGION_BASIC_INFO_64, rebound, &basicCount, &objectName)
                }
            }
            guard kr == KERN_SUCCESS else { break }
            if size == 0 { break }

            let regionStart = address
            defer {
                let (next, overflow) = regionStart.addingReportingOverflow(size)
                address = overflow ? vm_address_t.max : next
                iteration += 1
            }

            let prot = basicInfo.protection
            let read = (prot & VM_PROT_READ) != 0
            let exec = (prot & VM_PROT_EXECUTE) != 0
            let write = (prot & VM_PROT_WRITE) != 0
            // 只扫可读且可写或可执行的映射：Frida 代码/数据都落在这类区域。
            guard read && (exec || write) else { continue }

            // 跳过超大 region（默认 64MB），防止单块读取耗时失控。
            if UInt64(size) > configuration.maxRegionBytes { continue }

            var offset: vm_size_t = 0
            while offset < size && pagesBudget > 0 {
                let remaining = size - offset
                let chunk = min(configuration.maxChunkBytes, remaining)
                if chunk == 0 { break }

                // 把 chunk 限制在剩余页预算内，超出部分截断后停止。
                let pagesInChunk = Int((chunk + pageSize - 1) / pageSize)
                if pagesInChunk > pagesBudget {
                    let allowedBytes = vm_size_t(pagesBudget) * pageSize
                    if allowedBytes == 0 { break }
                    let cappedChunk = min(remaining, allowedBytes)
                    if cappedChunk == 0 { break }
                    if let hit = readAndMatch(
                        regionBase: regionStart,
                        offset: offset,
                        chunkSize: cappedChunk,
                        needles: needles
                    ) {
                        return hit
                    }
                    // 预算耗尽，结束本次扫描。
                    pagesBudget = 0
                    break
                }

                if let hit = readAndMatch(
                    regionBase: regionStart,
                    offset: offset,
                    chunkSize: chunk,
                    needles: needles
                ) {
                    return hit
                }

                pagesBudget -= pagesInChunk
                offset += chunk
            }
        }

        return nil
    }

    /// 从目标地址读取一块内存并在其中查找特征。
    private static func readAndMatch(
        regionBase: vm_address_t,
        offset: vm_size_t,
        chunkSize: vm_size_t,
        needles: [(String, Data)]
    ) -> String? {
        var buffer = [UInt8](repeating: 0, count: Int(chunkSize))
        var outSize: vm_size_t = 0
        // vm_read_overwrite 读取失败（区域不可读/被收回）时返回 nil，继续下一块。
        let readAddr = vm_address_t(UInt64(regionBase) + UInt64(offset))
        let kr = buffer.withUnsafeMutableBytes { rawBuf in
            vm_read_overwrite(
                mach_task_self_,
                readAddr,
                vm_size_t(chunkSize),
                vm_address_t(UInt(bitPattern: rawBuf.baseAddress)),
                &outSize
            )
        }
        guard kr == KERN_SUCCESS, outSize > 0 else { return nil }
        let data = Data(buffer.prefix(Int(outSize)))
        return firstMatch(in: data, needles: needles)
    }

    /// 在缓冲区中按顺序查找 needle，返回首个命中的标签。
    private static func firstMatch(in data: Data, needles: [(String, Data)]) -> String? {
        for (label, needle) in needles {
            if needle.isEmpty { continue }
            if data.range(of: needle) != nil {
                return label
            }
        }
        return nil
    }

    /// 构造编译后的 needle 表（标签 + 字节串）。
    private static func compiledNeedleTable() -> [(String, Data)] {
        var rows: [(String, Data)] = []
        for marker in ObfuscatedConstants.fridaStringMarkers {
            // 过短 marker 误报率高；与 FridaModuleDetector 的 string 维度对齐，仅保留 >=8 字节。
            // 过短子串误报率高；与 FridaModuleDetector 的 string 维度对齐，仅保留较长特征
            guard marker.utf8.count >= 8 else { continue }
            rows.append((marker, Data(marker.utf8)))
        }
        return rows
    }

    /// 读取单调时钟并换算为纳秒，用于节流计算。
    private static func monotonicNanoseconds() -> UInt64 {
        var timebase = mach_timebase_info_data_t()
        mach_timebase_info(&timebase)
        let ticks = mach_absolute_time()
        let denom = max(UInt64(timebase.denom), 1)
        let (product, overflow) = ticks.multipliedReportingOverflow(by: UInt64(timebase.numer))
        return overflow ? UInt64.max : product / denom
    }

    // MARK: - Configuration (env)

    /// 扫描配置：开关、节流间隔、页预算、region 大小与遍历上限。
    private struct Configuration {
        let enabled: Bool
        let minIntervalNs: UInt64
        let maxPagesPerScan: Int
        let maxRegionBytes: UInt64
        let maxChunkBytes: vm_size_t
        let maxRegionIterations: Int

        /// 从环境变量读取配置；Release 下全部返回默认值（环境变量被忽略）。
        static func current() -> Configuration {
            let enabled = envBool(key: ObfuscatedConstants.envKeyCpriskFridaMemsigBuiltin, defaultIfUnset: true)
            // 默认值：90s 节流、每次 64 页预算、单 region 64MB、16KB 读取块、最多 4096 个 region。
            let intervalMs = envInt(key: ObfuscatedConstants.envKeyCpriskFridaMemsigIntervalMs, defaultValue: 90_000)
            let maxPages = envInt(key: ObfuscatedConstants.envKeyCpriskFridaMemsigMaxPages, defaultValue: 64)
            let maxRegionBytes = envUInt64(key: ObfuscatedConstants.envKeyCpriskFridaMemsigMaxRegionBytes, defaultValue: 64 * 1024 * 1024)
            let chunkBytes = envInt(key: ObfuscatedConstants.envKeyCpriskFridaMemsigChunkBytes, defaultValue: 16 * 1024)
            let maxIter = envInt(key: ObfuscatedConstants.envKeyCpriskFridaMemsigMaxRegionIter, defaultValue: 4096)

            return Configuration(
                enabled: enabled,
                minIntervalNs: UInt64(max(0, intervalMs)) * 1_000_000,
                maxPagesPerScan: max(1, maxPages),
                maxRegionBytes: max(1024 * 1024, maxRegionBytes),
                maxChunkBytes: vm_size_t(max(4096, chunkBytes)),
                maxRegionIterations: max(64, maxIter)
            )
        }
    }

    // 环境变量开关仅在 DEBUG 生效：Release 下一律返回默认值，防止通过
    // 注入环境变量关闭/放大内存特征扫描。
    // DEBUG 下允许环境变量覆盖；Release 下一律返回默认值，防止注入变量关闭/放大扫描。
    private static func envBool(key: String, defaultIfUnset: Bool) -> Bool {
        #if !DEBUG
        return defaultIfUnset
        #endif
        guard let raw = ProcessInfo.processInfo.environment[key]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased(), !raw.isEmpty else {
            return defaultIfUnset
        }
        if raw == "0" || raw == "false" || raw == "no" || raw == "off" {
            return false
        }
        if raw == "1" || raw == "true" || raw == "yes" || raw == "on" {
            return true
        }
        return defaultIfUnset
    }

    /// 读取整数环境变量；Release 下恒返回默认值。
    private static func envInt(key: String, defaultValue: Int) -> Int {
        #if !DEBUG
        return defaultValue
        #endif
        guard let raw = ProcessInfo.processInfo.environment[key]?.trimmingCharacters(in: .whitespacesAndNewlines),
              let parsed = Int(raw) else {
            return defaultValue
        }
        return parsed
    }

    /// 读取 UInt64 环境变量；Release 下恒返回默认值。
    private static func envUInt64(key: String, defaultValue: UInt64) -> UInt64 {
        #if !DEBUG
        return defaultValue
        #endif
        guard let raw = ProcessInfo.processInfo.environment[key]?.trimmingCharacters(in: .whitespacesAndNewlines),
              let parsed = UInt64(raw) else {
            return defaultValue
        }
        return parsed
    }
}
