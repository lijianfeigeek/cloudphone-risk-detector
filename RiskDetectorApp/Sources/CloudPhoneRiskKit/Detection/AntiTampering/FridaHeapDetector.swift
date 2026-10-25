// FridaHeapDetector：从内存布局侧识别 Frida 内置 JS 引擎与 Stalker JIT 的足迹。
// V8/QuickJS 会申请大量匿名 rw- 区域，Stalker 会生成匿名 r-x 代码页；
// 这两类区域都不属于任何 dyld 镜像，是 Frida 运行期的统计特征。
// 与端口/线程/模块检测互补：不依赖字符串或文件痕迹。
import CRiskCore
import Darwin
import Foundation
import MachO

// 单次扫描最多遍历 500 个内存 region，限制 vm_region_64 的遍历开销。
private let maxIterations = 500
// Mach 匿名映射的 user_tag 集合（240...245）；普通文件映射/镜像通常不在其中。
private let anonymousUserTags: Set<UInt32> = [240, 241, 242, 243, 244, 245]

/// Frida 堆布局检测器。
/// - 线程模型：同步查询，每次 `detect()` 独立遍历内存区域。
/// - 降级：模拟器返回 0；任意区域查询失败即停止遍历，按已收集结果评分。
struct FridaHeapDetector: Detector {

    /// 执行 JS 堆与 Stalker JIT 两条启发式并汇总分数（封顶 80）。
    func detect() throws -> DetectorResult {
// 模拟器不模拟真实 Mach 内存布局。
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: [ObfuscatedConstants.methodFridaUnavailableSimulator])
#else
        // 两条启发式相互独立：堆大但无 JIT、或有 JIT 但堆不大，都可能命中。
        let heapResult = detectJSEngineHeap()
        let stalkerResult = detectStalkerJITPages()

        var score = heapResult.score + stalkerResult.score
        var methods = heapResult.methods + stalkerResult.methods

        if methods.isEmpty {
            return DetectorResult(score: 0, methods: [ObfuscatedConstants.methodFridaClean])
        }

        // 封顶 80：堆特征存在合法大内存应用误报的可能，不单独判死。
        return DetectorResult(score: min(score, 80), methods: methods)
#endif
    }

    // MARK: - V8/QuickJS Heap Detection

    /// 检测 V8/QuickJS 堆：统计不属于任何镜像的大块匿名 rw- 区域。
    /// 返回 (分数, 方法列表)。
    /// Detects Frida's embedded JS engine (V8/QuickJS) memory footprint.
    /// Large anonymous rw- regions not in any loaded image are suspicious.
    private func detectJSEngineHeap() -> (score: Double, methods: [String]) {
#if targetEnvironment(simulator)
        return (0, [])
#else
        var address: vm_address_t = 0
        var largeAnonRWCount = 0
        var totalAnonRWSize: UInt64 = 0
        // 小于 1MB 的匿名区域噪声太大（分配器/缓存），不纳入统计。
        let threshold: UInt64 = 1024 * 1024  // 1MB minimum per region
        var iteration = 0

        while iteration < maxIterations {
            var size: vm_size_t = 0
            var objectName: mach_port_t = 0

            var basicInfo = vm_region_basic_info_data_64_t()
            var basicCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_basic_info_data_64_t>.stride / MemoryLayout<natural_t>.stride
            )

            let basicResult = withUnsafeMutablePointer(to: &basicInfo) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(basicCount)) { rebound in
                    vm_region_64(mach_task_self_, &address, &size, VM_REGION_BASIC_INFO_64, rebound, &basicCount, &objectName)
                }
            }

            guard basicResult == KERN_SUCCESS else { break }

            let prot = basicInfo.protection
            let isRW = (prot & VM_PROT_READ) != 0 &&
                      (prot & VM_PROT_WRITE) != 0 &&
                      (prot & VM_PROT_EXECUTE) == 0

            // 只统计 rw-（可读写、不可执行）且 >=1MB 的区域。
            if isRW && UInt64(size) >= threshold {
                var isAnonymous = false
                var extInfo = vm_region_extended_info_data_t()
                var extCount = mach_msg_type_number_t(
                    MemoryLayout<vm_region_extended_info_data_t>.stride / MemoryLayout<natural_t>.stride
                )
                var extAddress = address
                var extSize: vm_size_t = 0

                let extResult = withUnsafeMutablePointer(to: &extInfo) { ptr in
                    ptr.withMemoryRebound(to: integer_t.self, capacity: Int(extCount)) { rebound in
                        vm_region_64(mach_task_self_, &extAddress, &extSize, VM_REGION_EXTENDED_INFO, rebound, &extCount, &objectName)
                    }
                }
                if extResult == KERN_SUCCESS {
                    // user_tag 属于匿名集合才继续；镜像内的大块 RW 不算。
                    isAnonymous = anonymousUserTags.contains(UInt32(extInfo.user_tag))
                }

                if isAnonymous, address != 0, let ptr = UnsafeRawPointer(bitPattern: UInt(address)) {
                    // 用 cprisk_addr_in_any_image（task_info + dyld_all_image_infos）而非 dladdr，
                    // 即使攻击者 hook 了 dladdr 也无法隐藏匿名内存归属。
                    // Use cprisk_addr_in_any_image (task_info + dyld_all_image_infos) instead of
                    // dladdr — resistant to dladdr hook that could hide anonymous Frida memory.
                    let inImage = cprisk_addr_in_any_image(ptr) != 0
                    if !inImage {
                        largeAnonRWCount += 1
                        totalAnonRWSize += UInt64(size)
                    }
                }
            }

            if size == 0 { break }
            let (next, overflow) = address.addingReportingOverflow(size)
            if overflow { break }
            address = next
            iteration += 1
        }

        var score: Double = 0
        var methods: [String] = []

        // V8 typically allocates 20–100MB of anonymous rw- memory
        // V8 通常申请 20–100MB 匿名内存；超过 30MB 给 20 分。
        if totalAnonRWSize > 30 * 1024 * 1024 {
            score += 20
            methods.append("\(ObfuscatedConstants.methodPrefixFridaHeap)v8_heap_\(totalAnonRWSize / (1024 * 1024))MB")
        // 15MB 以上且多于 5 块：可疑但非强证据，给 12 分。
        } else if totalAnonRWSize > 15 * 1024 * 1024 && largeAnonRWCount > 5 {
            score += 12
            methods.append("\(ObfuscatedConstants.methodPrefixFridaHeap)suspicious_anon_\(largeAnonRWCount)_regions")
        }

        return (score, methods)
#endif
    }

    // MARK: - Stalker JIT Code Page Detection

    /// Detects Frida Stalker's JIT-compiled code pages.
    /// Anonymous r-x regions not in any dylib are Stalker's instrumented blocks.
    /// 检测 Frida Stalker 的 JIT 代码页：匿名、可执行、不属于任何镜像的 r-x 区域。
    /// 返回 (分数, 方法列表)。
    private func detectStalkerJITPages() -> (score: Double, methods: [String]) {
#if targetEnvironment(simulator)
        return (0, [])
#else
        var address: vm_address_t = 0
        var jitPageCount = 0
        var iteration = 0

        while iteration < maxIterations {
            var size: vm_size_t = 0
            var objectName: mach_port_t = 0

            var basicInfo = vm_region_basic_info_data_64_t()
            var basicCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_basic_info_data_64_t>.stride / MemoryLayout<natural_t>.stride
            )

            let basicResult = withUnsafeMutablePointer(to: &basicInfo) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(basicCount)) { rebound in
                    vm_region_64(mach_task_self_, &address, &size, VM_REGION_BASIC_INFO_64, rebound, &basicCount, &objectName)
                }
            }

            guard basicResult == KERN_SUCCESS else { break }

            let prot = basicInfo.protection
            // Stalker 的 instrumented block 位于匿名 r-x 页，正常 App 很少有此类映射。
            let isRX = (prot & VM_PROT_READ) != 0 &&
                      (prot & VM_PROT_EXECUTE) != 0 &&
                      (prot & VM_PROT_WRITE) == 0

            if isRX {
                var isAnonymous = false
                var extInfo = vm_region_extended_info_data_t()
                var extCount = mach_msg_type_number_t(
                    MemoryLayout<vm_region_extended_info_data_t>.stride / MemoryLayout<natural_t>.stride
                )
                var extAddress = address
                var extSize: vm_size_t = 0

                let extResult = withUnsafeMutablePointer(to: &extInfo) { ptr in
                    ptr.withMemoryRebound(to: integer_t.self, capacity: Int(extCount)) { rebound in
                        vm_region_64(mach_task_self_, &extAddress, &extSize, VM_REGION_EXTENDED_INFO, rebound, &extCount, &objectName)
                    }
                }
                if extResult == KERN_SUCCESS {
                    isAnonymous = anonymousUserTags.contains(UInt32(extInfo.user_tag))
                }

                if isAnonymous, address != 0, let ptr = UnsafeRawPointer(bitPattern: UInt(address)) {
                    // Use cprisk_addr_in_any_image (task_info + dyld_all_image_infos) instead of
                    // dladdr — resistant to dladdr hook that could hide anonymous Frida memory.
                    let inImage = cprisk_addr_in_any_image(ptr) != 0
                    if !inImage {
                        jitPageCount += 1
                    }
                }
            }

            if size == 0 { break }
            let (next, overflow) = address.addingReportingOverflow(size)
            if overflow { break }
            address = next
            iteration += 1
        }

        // 超过 3 页给 15 分；1–3 页给 8 分（可能是系统 JIT，降低权重）。
        if jitPageCount > 3 {
            return (15, ["\(ObfuscatedConstants.methodPrefixFridaStalker)jit_pages_\(jitPageCount)"])
        } else if jitPageCount > 0 {
            return (8, ["\(ObfuscatedConstants.methodPrefixFridaStalker)jit_pages_\(jitPageCount)"])
        }

        return (0, [])
#endif
    }
}

// MARK: - Signal Conversion

/// 信号转换：把检测结果映射为 anti-tamper 类 RiskSignal。
extension FridaHeapDetector {
    /// 分别产出 V8 堆与 Stalker JIT 两条信号，命中时 state 为 `.tampered`。
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        // heap 方法统一前缀用于聚合同源证据。
        let heapMethods = result.methods.filter { $0.hasPrefix(ObfuscatedConstants.detectorIDFridaHeap) }
        if !heapMethods.isEmpty {
            signals.append(RiskSignal(
                id: ObfuscatedConstants.signalFridaJSEngineHeap,
                category: ObfuscatedConstants.categoryAntiTamper,
                // 每条 heap 方法 15 分，封顶 25；weightHint 80 表示较强证据。
                score: min(Double(heapMethods.count) * 15, 25),
                evidence: ["detail": heapMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 80
            ))
        }

        // Stalker 方法单独成信号，固定 15 分。
        let stalkerMethods = result.methods.filter { $0.hasPrefix(ObfuscatedConstants.signalFridaStalker) }
        if !stalkerMethods.isEmpty {
            signals.append(RiskSignal(
                id: ObfuscatedConstants.signalFridaStalkerJit,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 15,
                // weightHint 78：JIT 页也可能是合法 JIT，置信略低于堆证据。
                evidence: ["detail": stalkerMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 78
            ))
        }

        return signals
    }
}
