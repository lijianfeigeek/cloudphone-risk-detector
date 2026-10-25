// FridaMemoryLayoutDetector：从虚拟内存布局的统计特征识别 frida-agent。
// 不匹配字符串或符号，而是观察匿名 RX/RW 数量、RX+RW 相邻对、64KB 对齐、
// 非镜像匿名总量等布局指纹，与 Module/Heap/Socket 检测器形成正交证据。
// 布局启发式存在误报可能，因此单项与总分都设上限，并使用 soft 状态。
import CRiskCore
import Darwin
import Foundation
import MachO

// 最多遍历 600 个 region，限制单次布局分析的开销。
private let maxLayoutIterations = 600
// Mach 匿名映射 user_tag 集合；用于区分匿名映射与文件/镜像映射。
private let anonymousUserTagSet: Set<UInt32> = [240, 241, 242, 243, 244, 245]

// 64KB 对齐是 frida-agent 内部 mmap 的统计特征：
// 系统 dylib 与常规 malloc 通常按 4KB/16KB 页对齐。
/// 64 KB alignment constant used by frida-agent's internal mmap calls.
/// System dylibs and standard malloc regions use 4 KB (16 KB on arm64) page alignment.
/// Frida's GLib and V8 allocator frequently requests 64 KB-aligned blocks via mmap,
/// leaving a detectable alignment signature in the virtual memory layout.
private let fridaMmapAlignment: UInt64 = 64 * 1024

/// Minimum total anonymous non-image region size (bytes) to trigger a score contribution.
/// frida-agent with V8 engine typically maps 5-30+ MB of anonymous memory; normal apps
/// rarely exceed a few hundred KB of truly anonymous (non-image) executable regions.
// 5MB 是“可疑”阈值：普通 App 的匿名非镜像区很少超过此量级。
private let anonRegionSizeThreshold5MB: UInt64 = 5 * 1024 * 1024

/// Minimum total anonymous non-image region size (bytes) for the higher-confidence tier.
/// V8 heap + frida-agent code + Stalker JIT pages often total 15+ MB.
// 15MB 是高置信阈值：V8 堆 + agent 代码 + Stalker 页常合计 15MB 以上。
private let anonRegionSizeThreshold15MB: UInt64 = 15 * 1024 * 1024

/// Describes a single virtual memory region collected during the layout scan.
/// 单个虚拟内存区域的快照，供布局统计使用。
private struct MemoryRegion {
    let address: vm_address_t
    let size: vm_size_t
    let protection: vm_prot_t
    let isAnonymous: Bool
    let isInImage: Bool
    let userTag: UInt32
}

/// 基于内存布局的 Frida 检测器。
/// - 线程模型：同步遍历 `vm_region_64`，不修改进程状态。
/// - 误报控制：排除已知 dyld 镜像、用 user_tag 判定匿名、对各项分数设上限。
/// Frida memory layout fingerprint detector.
///
/// Analyzes the process virtual memory layout to detect frida-agent's presence
/// through statistical characteristics of memory regions rather than content matching.
/// This approach is orthogonal to `FridaModuleDetector` (which searches for strings/symbols)
/// and `FridaHeapDetector` (which focuses on large RW heaps and small JIT pages).
///
/// Detection heuristics:
/// - **Anonymous RX region count and total size**: frida-agent code + Gum Stalker JIT pages
/// - **Anonymous RW region count and total size**: frida-agent data + V8 heap
/// - **Consecutive anonymous RX+RW region pairs**: frida-agent's code-data segment layout
/// - **64 KB-aligned anonymous regions**: frida-agent uses 64 KB mmap alignment
/// - **RX regions not belonging to any dyld image**: injected code without backing image
///
/// False positive mitigation:
/// - Excludes regions belonging to known dyld images (via `cprisk_addr_in_any_image`)
/// - Excludes JavaScriptCore/WebKit JIT regions by checking if the address falls in
///   any loaded image (JSC JIT pages are tracked by the dyld image list)
/// - Metal/OpenGL GPU buffers are RW-only (no RX component), so they don't trigger
///   the RX+RW pair heuristic
struct FridaMemoryLayoutDetector: Detector {

    /// 入口：模拟器直接返回 0，真机进入 `detectKernel()`。
    @inline(never)
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: [ObfuscatedConstants.methodFridaUnavailableSimulator])
#else
        return detectKernel()
#endif
    }

    /// Keep the VMP-targeted `detect()` entry narrow and stable in optimized builds.
    /// 收集区域、计算指标并套用五条布局启发式。
    @inline(never)
    private func detectKernel() -> DetectorResult {
        let regions = collectMemoryRegions()
        let metrics = computeMetrics(from: regions)

        var score: Double = 0
        var methods: [String] = []

        // Heuristic 1: Anonymous RX regions not in any image.
        // frida-agent loads as an anonymous mmap (not in dyld image list) with RX protection
        // for its __TEXT segment. Stalker also creates additional small RX JIT pages.
        // Normal apps have very few anonymous RX regions (perhaps a few from system JIT).
        // 启发式 1：匿名 RX 且不属于任何镜像的 region >=3 个。
        if metrics.anonRXNotInImageCount >= 3 {
            score += 15
            methods.append("\(ObfuscatedConstants.methodPrefixFridaMemoryLayout)anon_rx_not_in_image:\(metrics.anonRXNotInImageCount)")
        }

        // Heuristic 2: Consecutive anonymous RX+RW region pairs.
        // frida-agent maps its code (RX) and data (RW) segments as adjacent regions.
        // The pattern of [RX][RW] appearing consecutively in the address space is a
        // strong indicator of a Mach-O loaded via mmap rather than dyld.
        // 启发式 2：连续的 [RX][RW] 匿名区域对 >=2，符合 mmap 加载的 Mach-O 段布局。
        if metrics.consecutiveRXRWPairCount >= 2 {
            score += 12
            methods.append("\(ObfuscatedConstants.methodPrefixFridaMemoryLayout)consecutive_rxrw_pairs:\(metrics.consecutiveRXRWPairCount)")
        }

        // Heuristic 3: 64 KB-aligned anonymous regions.
        // frida-agent's internal allocators (GLib slice allocator, V8 page allocator)
        // use mmap with 64 KB alignment, while system dylibs use 4 KB (arm64: 16 KB)
        // page-aligned segments. A cluster of 64 KB-aligned anonymous regions is unusual.
        // 启发式 3：64KB 对齐的匿名 region >=3 个。
        if metrics.aligned64KBAnonCount >= 3 {
            score += 8
            methods.append("\(ObfuscatedConstants.methodPrefixFridaMemoryLayout)aligned_64kb_anon:\(metrics.aligned64KBAnonCount)")
        }

        // Heuristic 4: Total size of anonymous regions not in any image exceeds threshold.
        // frida-agent with V8 typically maps 5-30 MB of anonymous memory for code + data + JIT.
        // The higher the total, the more confident we are that it's a full agent injection.
        // 启发式 4：非镜像匿名区域总大小超过阈值（15MB 高置信 / 5MB 可疑）。
        if metrics.anonNotInImageTotalSize > anonRegionSizeThreshold15MB {
            score += 18
            let sizeMB = metrics.anonNotInImageTotalSize / (1024 * 1024)
            methods.append("\(ObfuscatedConstants.methodPrefixFridaMemoryLayout)anon_not_in_image_size:\(sizeMB)MB")
        } else if metrics.anonNotInImageTotalSize > anonRegionSizeThreshold5MB {
            score += 10
            let sizeMB = metrics.anonNotInImageTotalSize / (1024 * 1024)
            methods.append("\(ObfuscatedConstants.methodPrefixFridaMemoryLayout)anon_not_in_image_size:\(sizeMB)MB")
        }

        // Heuristic 5: Anonymous RW regions not in any image (V8/QuickJS heap + frida data).
        // frida-agent's V8 engine allocates large anonymous RW regions for its heap.
        // The combination with anonymous RX regions amplifies confidence.
        // 启发式 5：匿名 RW 非镜像区 >=3 且总量 >5MB（V8/agent 数据段）。
        if metrics.anonRWNotInImageCount >= 3 && metrics.anonNotInImageTotalSize > anonRegionSizeThreshold5MB {
            score += 5
            methods.append("\(ObfuscatedConstants.methodPrefixFridaMemoryLayout)anon_rw_not_in_image:\(metrics.anonRWNotInImageCount)")
        }

        // Combination bonus: multiple heuristics firing simultaneously strongly suggests
        // frida-agent rather than any individual false positive source.
        // 组合加分：同时触发多条启发式比任何单条误报源更可信。
        let activeHeuristics = methods.count
        if activeHeuristics >= 3 {
            score += 10
            methods.append("\(ObfuscatedConstants.methodPrefixFridaMemoryLayout)multi_heuristic_combo:\(activeHeuristics)")
        } else if activeHeuristics == 2 {
            score += 4
            methods.append("\(ObfuscatedConstants.methodPrefixFridaMemoryLayout)dual_heuristic_combo")
        }

        if methods.isEmpty {
            return DetectorResult(score: 0, methods: [ObfuscatedConstants.methodFridaClean])
        }

        // 布局启发式封顶 70，避免单独决定最终风险等级。
        // Cap score at 70 -- this is a layout-based heuristic, not a definitive detection.
        // The score should contribute to but not independently determine the final risk level.
        return DetectorResult(score: min(score, 70), methods: methods)
    }

    // MARK: - Memory Region Collection

    /// Iterates through all virtual memory regions of the current task using `vm_region_64`
    /// and collects those with relevant protection flags (RX, RW, RWX).
    ///
    /// The iteration uses `VM_REGION_BASIC_INFO_64` for protection flags and region size,
    /// then `VM_REGION_EXTENDED_INFO` for the `user_tag` field to determine anonymity.
    /// The `cprisk_addr_in_any_image` C function checks whether each region's start address
    /// falls within any known dyld loaded image, which is resistant to `dladdr` hooking.
    /// 遍历当前任务的所有虚拟内存区域，收集可读且可写/可执行的区域。
    /// 使用 BASIC_INFO 取权限、EXTENDED_INFO 取 user_tag，并用 C 侧接口判断镜像归属。
    private func collectMemoryRegions() -> [MemoryRegion] {
#if targetEnvironment(simulator)
        return []
#else
        var regions: [MemoryRegion] = []
        var address: vm_address_t = 0
        var iteration = 0

        while iteration < maxLayoutIterations {
            var size: vm_size_t = 0
            var objectName: mach_port_t = 0

            var basicInfo = vm_region_basic_info_data_64_t()
            var basicCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_basic_info_data_64_t>.stride / MemoryLayout<natural_t>.stride
            )

            let basicResult = withUnsafeMutablePointer(to: &basicInfo) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(basicCount)) { rebound in
                    vm_region_64(
                        mach_task_self_,
                        &address,
                        &size,
                        VM_REGION_BASIC_INFO_64,
                        rebound,
                        &basicCount,
                        &objectName
                    )
                }
            }

            guard basicResult == KERN_SUCCESS else { break }

            let prot = basicInfo.protection
            let isReadable = (prot & VM_PROT_READ) != 0
            let isWritable = (prot & VM_PROT_WRITE) != 0
            let isExecutable = (prot & VM_PROT_EXECUTE) != 0

            // Only collect regions with at least read + one other permission.
            // Pure RO regions and inaccessible regions are not relevant for Frida detection.
            // 只关心可读且可写/可执行的区域；纯只读与不可访问区域与注入无关。
            let isRelevant = isReadable && (isWritable || isExecutable)
            guard isRelevant else {
                if size == 0 { break }
                let (next, overflow) = address.addingReportingOverflow(size)
                if overflow { break }
                address = next
                iteration += 1
                continue
            }

            // Query extended info for user_tag (anonymity detection).
            var isAnonymous = false
            var userTag: UInt32 = 0
            var extInfo = vm_region_extended_info_data_t()
            var extCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_extended_info_data_t>.stride / MemoryLayout<natural_t>.stride
            )
            var extAddress = address
            var extSize: vm_size_t = 0

            let extResult = withUnsafeMutablePointer(to: &extInfo) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(extCount)) { rebound in
                    vm_region_64(
                        mach_task_self_,
                        &extAddress,
                        &extSize,
                        VM_REGION_EXTENDED_INFO,
                        rebound,
                        &extCount,
                        &objectName
                    )
                }
            }
            if extResult == KERN_SUCCESS {
                userTag = UInt32(extInfo.user_tag)
                // user_tag 落入匿名集合才视为匿名映射。
                isAnonymous = anonymousUserTagSet.contains(userTag)
            }

            // Check if the region belongs to any known dyld image.
            // Uses cprisk_addr_in_any_image which walks dyld_all_image_infos --
            // resistant to dladdr hooking that Frida might employ to hide itself.
            // cprisk_addr_in_any_image 遍历 dyld_all_image_infos，抗 dladdr hook。
            var isInImage = false
            if address != 0, let ptr = UnsafeRawPointer(bitPattern: UInt(address)) {
                isInImage = cprisk_addr_in_any_image(ptr) != 0
            }

            regions.append(MemoryRegion(
                address: address,
                size: size,
                protection: prot,
                isAnonymous: isAnonymous,
                isInImage: isInImage,
                userTag: userTag
            ))

            if size == 0 { break }
            let (next, overflow) = address.addingReportingOverflow(size)
            if overflow { break }
            address = next
            iteration += 1
        }

        return regions
#endif
    }

    // MARK: - Metric Computation

    /// Aggregate layout metrics computed from the collected memory regions.
    ///
    /// These metrics capture statistical fingerprints of frida-agent's memory layout:
    /// - Counts of anonymous regions with specific protection flags
    /// - Consecutive RX+RW pairs (frida-agent segment layout pattern)
    /// - 64 KB alignment frequency (frida-agent mmap alignment)
    /// - Total size of non-image anonymous regions
    /// 布局指标：匿名 RX/RW 数量、连续 RX+RW 对数、64KB 对齐数、匿名非镜像总大小。
    private struct LayoutMetrics {
        // 匿名 RX 且非镜像的 region 数量。
        /// Number of anonymous RX (read+execute, no write) regions not in any dyld image.
        var anonRXNotInImageCount: Int = 0
        // 匿名 RW 且非镜像的 region 数量。
        /// Number of anonymous RW (read+write, no execute) regions not in any dyld image.
        var anonRWNotInImageCount: Int = 0
        /// Number of consecutive region pairs where the first is anonymous RX and the second
        // 地址相邻的匿名 RX -> RW 对数量（frida-agent 的段布局）。
        /// is anonymous RW. frida-agent loads its __TEXT (RX) and __DATA (RW) as adjacent
        /// anonymous mmap regions.
        var consecutiveRXRWPairCount: Int = 0
        /// Number of anonymous regions whose start address is aligned to 64 KB.
        // 起始地址 64KB 对齐的匿名 region 数量。
        /// frida-agent uses 64 KB alignment in its mmap calls, unlike system dylibs
        /// which use the platform page size (4 KB or 16 KB).
        var aligned64KBAnonCount: Int = 0
        /// Total combined size (bytes) of all anonymous regions not belonging to any
        // 所有匿名非镜像 region 的字节总量。
        /// known dyld image. frida-agent typically maps 5-30+ MB.
        var anonNotInImageTotalSize: UInt64 = 0
    }

    /// Computes layout metrics from the sorted list of memory regions.
    ///
    /// The consecutive RX+RW pair detection works by iterating regions in address order
    /// and checking if region[i] is anonymous RX and region[i+1] is anonymous RW with
    /// adjacent addresses (region[i].address + region[i].size == region[i+1].address).
    /// 按地址排序后计算各项布局指标。
    private func computeMetrics(from regions: [MemoryRegion]) -> LayoutMetrics {
        var metrics = LayoutMetrics()

        // Sort by address to detect consecutive pairs.
        let sorted = regions.sorted { $0.address < $1.address }

        // 按地址升序，才能判断区域是否相邻。
        for (index, region) in sorted.enumerated() {
            guard region.isAnonymous else { continue }

            let prot = region.protection
            let isRX = (prot & VM_PROT_READ) != 0 &&
                       (prot & VM_PROT_EXECUTE) != 0 &&
                       (prot & VM_PROT_WRITE) == 0
            let isRW = (prot & VM_PROT_READ) != 0 &&
                       (prot & VM_PROT_WRITE) != 0 &&
                       (prot & VM_PROT_EXECUTE) == 0

            // RX 且不属于任何镜像：注入代码的典型特征。
            if isRX && !region.isInImage {
                metrics.anonRXNotInImageCount += 1
                metrics.anonNotInImageTotalSize += UInt64(region.size)
            }

            if isRW && !region.isInImage {
                metrics.anonRWNotInImageCount += 1
                metrics.anonNotInImageTotalSize += UInt64(region.size)
            }

            // Check 64 KB alignment on anonymous regions.
            // frida-agent's mmap calls use MAP_ALIGNED(64KB) or equivalent.
            // 64KB 对齐检查：frida-agent 的 mmap 对齐特征。
            if UInt64(region.address) % fridaMmapAlignment == 0 {
                metrics.aligned64KBAnonCount += 1
            }

            // Detect consecutive anonymous RX -> RW pairs.
            // frida-agent maps __TEXT (RX) immediately followed by __DATA (RW).
            // The next region's address should be exactly current address + size.
            // 检测当前 RX 区域的下一个区域是否为地址紧邻的匿名 RW。
            if isRX && !region.isInImage {
                let nextIndex = index + 1
                if nextIndex < sorted.count {
                    let next = sorted[nextIndex]
                    let expectedNextAddress = region.address + region.size
                    let nextIsRW = (next.protection & VM_PROT_READ) != 0 &&
                                  (next.protection & VM_PROT_WRITE) != 0 &&
                                  (next.protection & VM_PROT_EXECUTE) == 0
                    if next.address == expectedNextAddress &&
                       next.isAnonymous &&
                       nextIsRW &&
                       !next.isInImage {
                        metrics.consecutiveRXRWPairCount += 1
                    }
                }
            }
        }

        return metrics
    }
}

// MARK: - Signal Conversion

/// 信号转换：把布局异常映射为 anti-tamper 信号。
extension FridaMemoryLayoutDetector {
    /// 置信度随命中启发式数量上升，但封顶 0.85（布局特征非确定性证据）。
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        // Compute confidence from the number of distinct heuristics that fired.
        // More heuristics = higher confidence. Maximum 0.85 since this is layout-based
        // and not a definitive content signature.
        // 统计实际触发的布局启发式条数。
        let heuristicCount = result.methods.filter {
            $0.hasPrefix(ObfuscatedConstants.methodPrefixFridaMemoryLayout)
        }.count
        // 0.45 起，每多一条 +0.12，封顶 0.85。
        let confidence = min(0.45 + Double(heuristicCount) * 0.12, 0.85)

        var evidence: [String: String] = [
            "detail": result.methods.joined(separator: ","),
        ]
        // 三条及以上同时命中时打上 multi_heuristic 标记。
        if heuristicCount >= 3 {
            evidence["multi_heuristic"] = "true"
        }

        return [
            RiskSignal(
                id: ObfuscatedConstants.signalFridaMemoryLayoutAnomaly,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: result.score,
                evidence: evidence,
                // 使用 soft 状态：布局异常可能是合法 JIT/大内存应用，需要其他信号佐证。
                state: .soft(confidence: confidence),
                layer: 2,
                weightHint: 65
            ),
        ]
    }
}
