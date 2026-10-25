// RWX 内存扫描器：从地址 0 起用 vm_region_64 遍历本 task 的虚拟内存区域，先按 VM_REGION_BASIC_INFO_64
// 读取保护位，再用 VM_REGION_EXTENDED_INFO 获取 share_mode/user_tag，区分匿名 RWX、匿名可执行 RX
// 与 JIT-like 小块可执行内存（Stalker/Frida 代码缓存特征）。
// 信号：rwx_anonymous / anonymous_executable_memory / stalkerJitRWX / rwxJitCoexistence / rwx_multiple。
// 模拟器返回空结果；遍历有迭代上限并做地址溢出保护，任何查询失败即停止并返回已收集结果。

import CRiskCore
import Darwin
import Foundation
import MachO

/// 读写执行权限位组合：三个位同时置位才是 RWX。
private let rwxProtection = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE
/// 区域遍历迭代上限，防止异常 region 链导致检测线程长时间占用。
private let maxIterations = 500
/// 视为匿名的 VM user_tag（JIT/调试器分配器常用 240~245）。
private let anonymousUserTags: Set<UInt32> = [240, 241, 242, 243, 244, 245]

/// 扫描并分类可疑可执行内存区域。
struct RWXMemoryScanner: Detector {
    /// 单个可疑区域的完整属性，保留原始保护位与共享模式供证据归因。
    struct SuspiciousRegion {
        var address: UInt64
        var size: UInt64
        var protection: vm_prot_t
        var isAnonymous: Bool
        var isAnonymousRX: Bool
        var userTag: UInt32
        var shareMode: UInt32
        var inImage: Bool
        var isJITLike: Bool
    }

    /// 扫描评分结果，按区域类别分别计数。
    struct ScanAssessment {
        var score: Double
        var methods: [String]
        var anonymousRWXCount: Int
        var anonymousRXCount: Int
        var jitLikeCount: Int
        var totalCount: Int
    }

    /// 执行扫描并评分；模拟器下无真机内存布局，直接降级。
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["rwx:unavailable_simulator"])
#else
        let assessment = assess(regions: scanForRWXRegions())
        if assessment.totalCount == 0 {
            return DetectorResult(score: 0, methods: ["rwx:clean"])
        }
        return DetectorResult(score: assessment.score, methods: assessment.methods)
#endif
    }

    /// 按区域类别累加分数：
    /// - 匿名 RWX：+40；匿名可执行 RX：+40。
    /// - JIT-like：从 20 分起每多一块 +5，封顶 30。
    /// - 匿名 RWX 与 JIT-like 共存：+15（两类特征互证）。
    /// - 额外区域：每块 +10，封顶 40。最终封顶 95。
    func assess(regions: [SuspiciousRegion]) -> ScanAssessment {
        if regions.isEmpty {
            return ScanAssessment(
                score: 0,
                methods: [],
                anonymousRWXCount: 0,
                anonymousRXCount: 0,
                jitLikeCount: 0,
                totalCount: 0
            )
        }

        var score: Double = 0
        var methods: [String] = []

        let anonymousRWXCount = regions.filter { region in
            // 必须同时满足“匿名”与三个权限位齐全，宽松匹配会把普通可写堆算进来。
            region.isAnonymous && (region.protection & rwxProtection) == rwxProtection
        }.count
        if anonymousRWXCount > 0 {
            score += 40
            methods.append("rwx:anonymous_rwx")
        }

        let anonymousRXCount = regions.filter(\.isAnonymousRX).count
        if anonymousRXCount > 0 {
            score += 40
            methods.append("rwx:anonymous_executable_memory")
        }

        let jitLikeCount = regions.filter(\.isJITLike).count
        if jitLikeCount > 0 {
            score += min(20 + Double(max(0, jitLikeCount - 1)) * 5, 30)
            methods.append("rwx:jit_rwx_stalker_like")
        }

        if anonymousRWXCount > 0 && jitLikeCount > 0 {
            // 匿名 RWX 与 JIT 缓存同时存在，符合动态插桩框架的双缓冲布局。
            score += 15
            methods.append("rwx:jit_rwx_coexistence")
        }

        let extraCount = regions.count - 1
        if extraCount > 0 {
            score += min(Double(extraCount) * 10, 40)
            if !methods.contains("rwx:anonymous_rwx") {
                methods.append("rwx:rwx_regions")
            }
        }

        return ScanAssessment(
            score: min(score, 95),
            methods: methods,
            anonymousRWXCount: anonymousRWXCount,
            anonymousRXCount: anonymousRXCount,
            jitLikeCount: jitLikeCount,
            totalCount: regions.count
        )
    }

    /// 遍历虚拟内存并返回可疑区域。
    ///
    /// 权限判定：
    /// - RWX：R/W/X 三位同时置位。
    /// - RX：可执行且不可写（JIT 代码页的常见形态）。
    ///
    /// 匿名判定依赖 `share_mode` 与 `user_tag`；RX 区域额外要求位于已加载镜像之外。
    /// 失败语义：单个区域查询失败即结束遍历；地址回绕同样结束。
    func scanForRWXRegions() -> [SuspiciousRegion] {
#if targetEnvironment(simulator)
        return []
#else
        var result: [SuspiciousRegion] = []
        var address: vm_address_t = 0
        var iteration = 0

        while iteration < maxIterations {
            var size: vm_size_t = 0
            var objectName: mach_port_t = 0

            var basicInfo = vm_region_basic_info_data_64_t()
            // 内核按 natural_t 数量校验缓冲区，必须用 stride 换算而非元素个数。
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
            // 三位全置位才是 RWX；RX 要求可执行且不可写，二者分类互斥。
            let isRWX = (prot & rwxProtection) == rwxProtection
            let isRX = (prot & VM_PROT_EXECUTE) != 0 && (prot & VM_PROT_WRITE) == 0

            if isRWX || isRX {
                var isAnonymous = false
                var isAnonymousRX = false
                var userTag: UInt32 = 0
                var shareMode: UInt32 = 0
                var inImage = false

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
                    userTag = UInt32(extInfo.user_tag)
                    shareMode = UInt32(extInfo.share_mode)
                    // 与 LLDBJITDetector 不同，这里只按 user_tag 判定匿名，作为更严格的匿名 RWX 口径。
                    isAnonymous = anonymousUserTags.contains(userTag)
                    if isRX {
                        // 只有 RX 候选才查镜像归属；纯 RWX 段本身不属于正常镜像映射。
                        inImage = UnsafeRawPointer(bitPattern: UInt(extAddress)).map { cprisk_addr_in_any_image($0) != 0 } ?? false
                        let isPrivateOrEmpty = extInfo.share_mode == 3 || extInfo.share_mode == 0
                        if isPrivateOrEmpty && isAnonymous && !inImage {
                            isAnonymousRX = true
                        }
                    }
                }

                if isRWX || (isRX && isAnonymousRX) {
                    // JIT-like：私有匿名、不在镜像内、且块大小 <=512KB（Stalker 代码缓存的典型上限）。
                    let isJITLike = isRX &&
                        isAnonymous &&
                        !inImage &&
                        (shareMode == 0 || shareMode == 3) &&
                        UInt64(size) <= 512 * 1024
                    result.append(SuspiciousRegion(
                        address: UInt64(address),
                        size: UInt64(size),
                        protection: prot,
                        isAnonymous: isAnonymous,
                        isAnonymousRX: isAnonymousRX,
                        userTag: userTag,
                        shareMode: shareMode,
                        inImage: inImage,
                        isJITLike: isJITLike
                    ))
                }
            }

            if size == 0 { break }
            // 地址 + 大小可能回绕到低位地址，必须检测溢出，否则会重复遍历并死循环。
            let (next, overflow) = address.addingReportingOverflow(size)
            if overflow { break }
            address = next
            iteration += 1
        }

        return result
#endif
    }
}

extension RWXMemoryScanner {
    /// 便捷入口：重新扫描后转换为信号。
    func asSignals() -> [RiskSignal] {
        asSignals(regions: scanForRWXRegions())
    }

    /// 将已扫描区域转换为信号；空数组直接返回。
    /// - 匿名 RWX / 匿名可执行内存：各 40 分，tampered（weightHint 90/95）。
    /// - JIT-like：按数量计分（12 + 12*n，封顶 42），tampered，layer 1。
    /// - 匿名 RWX 与 JIT-like 共存：18 分互证信号。
    /// - 区域总数 >1：20 分软信号。
    func asSignals(regions: [SuspiciousRegion]) -> [RiskSignal] {
        if regions.isEmpty {
            return []
        }

        let assessment = assess(regions: regions)
        var signals: [RiskSignal] = []
        let anonymousRegions = regions.filter(\.isAnonymous)
        if !anonymousRegions.isEmpty {
            signals.append(
                RiskSignal(
                    id: "rwx_anonymous",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 40,
                    evidence: [
                        "count": "\(anonymousRegions.count)",
                        // 只上报前 5 个地址，控制 evidence 体积。
                        "addresses": anonymousRegions.prefix(5).map { String(format: "0x%llx", $0.address) }.joined(separator: ","),
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 90
                )
            )
        }

        let anonymousRXRegions = regions.filter(\.isAnonymousRX)
        if !anonymousRXRegions.isEmpty {
            signals.append(
                RiskSignal(
                    id: "anonymous_executable_memory",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 40,
                    evidence: [
                        "count": "\(anonymousRXRegions.count)",
                        "addresses": anonymousRXRegions.prefix(5).map { String(format: "0x%llx", $0.address) }.joined(separator: ","),
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 95
                )
            )
        }

        let jitLikeRegions = regions.filter(\.isJITLike)
        if !jitLikeRegions.isEmpty {
            signals.append(
                RiskSignal(
                    id: SignalID.stalkerJitRWX,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: min(Double(assessment.jitLikeCount) * 12 + 12, 42),
                    evidence: [
                        "count": "\(jitLikeRegions.count)",
                        "addresses": jitLikeRegions.prefix(5).map { String(format: "0x%llx", $0.address) }.joined(separator: ","),
                        // share_mode/user_tag 去重后排序，便于识别具体 JIT 分配器。
                        "share_modes": Set(jitLikeRegions.map { "\($0.shareMode)" }).sorted().joined(separator: ","),
                        "tags": Set(jitLikeRegions.map { "\($0.userTag)" }).sorted().joined(separator: ","),
                    ],
                    state: .tampered,
                    layer: 1,
                    weightHint: 96
                )
            )
        }

        if assessment.anonymousRWXCount > 0 && assessment.jitLikeCount > 0 {
            signals.append(
                RiskSignal(
                    id: SignalID.rwxJitCoexistence,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 18,
                    evidence: [
                        "anonymous_rwx_count": "\(assessment.anonymousRWXCount)",
                        "jit_like_rx_count": "\(assessment.jitLikeCount)",
                    ],
                    state: .tampered,
                    layer: 1,
                    weightHint: 90
                )
            )
        }

        if regions.count > 1 {
            // 多块可疑区域单独成信号，避免被前几条信号的高分掩盖。
            signals.append(
                RiskSignal(
                    id: "rwx_multiple",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 20,
                    evidence: ["count": "\(regions.count)"],
                    state: .soft(confidence: 0.7),
                    layer: 2,
                    weightHint: 60
                )
            )
        }

        return signals
    }
}
