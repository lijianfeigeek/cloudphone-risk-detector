import CRiskCore
import Darwin
import Foundation

// MARK: - VM 重映射探测
//
// 识别 vm_remap 类操作留下的地址空间痕迹：镜像之外出现共享的匿名可执行映射，
// 或已加载镜像内出现匿名可执行别名。这类映射常见于内存马/注入器把代码页
// 映射进目标进程，普通 App 的 JIT/共享缓存不会同时满足"匿名 + 共享 + 可执行"。
// 结果按两个独立信号输出，均为强反篡改证据。

// 遍历上限：真实进程 region 数通常在数百量级，700 足以覆盖且能防止异常地址空间死循环。
private let vmRemapMaxIterations = 700
// 240–245 为系统/运行时常用的匿名映射 user_tag；与 share_mode 一起用于判定匿名性。
private let vmRemapAnonymousTags: Set<UInt32> = [240, 241, 242, 243, 244, 245]

/// 检测可疑的 vm_remap 类痕迹：
/// 1) 已加载镜像之外出现共享的匿名可执行映射；
/// 2) 已加载镜像内部出现匿名可执行映射（别名/重映射症状）。
struct VMRemapDetector: Detector {
    private enum Keys {
        static let prefix = ObfuscatedConstants.keywordVMRemap
    }

    /// 单个 vm_region 的归一化观测结果。
    struct RegionFinding {
        let address: UInt64
        let size: UInt64
        let protection: vm_prot_t
        let userTag: UInt32
        let shareMode: UInt32
        let isAnonymous: Bool
        let inImage: Bool
    }

    /// 汇总后的评分与命中计数。
    struct Assessment {
        let score: Double
        let methods: [String]
        let sharedAnonymousExecutableCount: Int
        let imageAnonymousAliasCount: Int
    }

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        // 模拟器地址空间布局与真机不同，直接降级。
        return DetectorResult(score: 0, methods: ["\(Keys.prefix):unavailable_simulator"])
#else
        let findings = collectFindings()
        let assessment = assess(findings: findings)
        return DetectorResult(score: assessment.score, methods: assessment.methods)
#endif
    }

    /// 根据 region 观测结果计算分数。
    /// - 共享匿名可执行映射 ≥2 个：35 分起，每多一个 +10，封顶 60；
    /// - 镜像内匿名可执行别名：30 分起，每多一个 +12，封顶 55；
    /// - 两类同时出现再加 15（组合证据更强）；总分封顶 95。
    func assess(findings: [RegionFinding]) -> Assessment {
        // 镜像外 + 共享 + 匿名 + 可执行：最典型的注入/重映射形态。
        let sharedAnonymousExecutable = findings.filter {
            isExecutable($0.protection) && $0.isAnonymous && isSharedMode($0.shareMode) && !$0.inImage
        }
        // 镜像内 + 匿名 + 可执行：可能是代码页别名，真机极少出现。
        let imageAnonymousAlias = findings.filter {
            isExecutable($0.protection) && $0.isAnonymous && $0.inImage
        }

        let sharedCount = sharedAnonymousExecutable.count
        let aliasCount = imageAnonymousAlias.count

        guard sharedCount > 0 || aliasCount > 0 else {
            return Assessment(
                score: 0,
                methods: ["\(Keys.prefix):clean"],
                sharedAnonymousExecutableCount: 0,
                imageAnonymousAliasCount: 0
            )
        }

        var score: Double = 0
        var methods: [String] = []

        // 单个共享匿名可执行映射可能是合法 JIT，仅给 12 分提示；≥2 个才按强证据计分。
        if sharedCount >= 2 {
            score += min(35 + Double(sharedCount - 2) * 10, 60)
            methods.append("\(Keys.prefix):shared_anon_exec:\(sharedCount)")
        } else if sharedCount == 1 {
            score += 12
            methods.append("\(Keys.prefix):shared_anon_exec_hint:1")
        }

        if aliasCount > 0 {
            score += min(30 + Double(max(0, aliasCount - 1)) * 12, 55)
            methods.append("\(Keys.prefix):image_alias:\(aliasCount)")
        }

        // 两种痕迹共存说明不只是单一合法 JIT 场景，追加组合分。
        if sharedCount > 0 && aliasCount > 0 {
            score += 15
            methods.append("\(Keys.prefix):coexistence")
        }

        return Assessment(
            score: min(score, 95),
            methods: methods,
            sharedAnonymousExecutableCount: sharedCount,
            imageAnonymousAliasCount: aliasCount
        )
    }

    /// 遍历当前 task 的 vm_region，收集尺寸 ≥16 KB 的 region 观测。
    /// - 同时查询 basic info（保护位）与 extended info（user_tag/share_mode）；
    /// - extended 查询失败时跳过该 region，不影响后续遍历。
    private func collectFindings() -> [RegionFinding] {
        var findings: [RegionFinding] = []
        var address: vm_address_t = 0
        var iteration = 0

        while iteration < vmRemapMaxIterations {
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
            guard basicResult == KERN_SUCCESS, size > 0 else { break }

            // 再取扩展信息：user_tag 与 share_mode 是判断匿名/共享的关键，basic info 不含。
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
                let userTag = UInt32(extInfo.user_tag)
                let shareMode = UInt32(extInfo.share_mode)
                let isAnonymous = isAnonymousRegion(shareMode: shareMode, userTag: userTag)
                let rawPtr = UnsafeRawPointer(bitPattern: UInt(address))
                // 借助 CRiskCore 判断该地址是否落在任一已加载镜像的范围内。
                let inImage = rawPtr.map { cprisk_addr_in_any_image($0) != 0 } ?? false

                // 过滤 <16 KB 的碎片映射：小页多为运行时元数据，噪声大且价值低。
                if size >= 16 * 1024 {
                    findings.append(
                        RegionFinding(
                            address: UInt64(address),
                            size: UInt64(size),
                            protection: basicInfo.protection,
                            userTag: userTag,
                            shareMode: shareMode,
                            isAnonymous: isAnonymous,
                            inImage: inImage
                        )
                    )
                }
            }

            // 地址回绕或溢出时立即停止，防止异常 region 导致无限循环。
            let next = UInt64(address) &+ UInt64(size)
            if next <= UInt64(address) { break }
            address = vm_address_t(next)
            iteration += 1
        }

        return findings
    }

    /// 判断保护位是否包含可执行权限。
    private func isExecutable(_ protection: vm_prot_t) -> Bool {
        (protection & VM_PROT_EXECUTE) != 0
    }

    /// 判断 region 是否为匿名映射。
    /// - `share_mode` 0/3 以及 240–245 的 user_tag 均按匿名处理；
    /// - 该组合覆盖 dyld/JIT 常见的匿名映射标记。
    private func isAnonymousRegion(shareMode: UInt32, userTag: UInt32) -> Bool {
        shareMode == 0 || shareMode == 3 || vmRemapAnonymousTags.contains(userTag)
    }

    /// 判断是否为共享映射（排除 0/3 这两种非共享模式）。
    private func isSharedMode(_ shareMode: UInt32) -> Bool {
        shareMode != 0 && shareMode != 3
    }
}

extension VMRemapDetector {
    /// 将评估结果转换为信号。
    /// - 共享匿名可执行映射 ≥2：`vmRemapSharedAnonymous`，`.tampered`，分数 55+4n（封顶 80）；
    /// - 镜像内匿名别名 >0：`vmRemapImageAlias`，`.tampered`，分数 48+6n（封顶 78）；
    /// - 仅有单条弱证据时回落到 16 分 soft 信号。
    func asSignals() -> [RiskSignal] {
        let findings = collectFindings()
        let assessment = assess(findings: findings)
        guard assessment.score > 0 else { return [] }

        var signals: [RiskSignal] = []
        if assessment.sharedAnonymousExecutableCount >= 2 {
            signals.append(
                RiskSignal(
                    id: SignalID.vmRemapSharedAnonymous,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: min(55 + Double(assessment.sharedAnonymousExecutableCount) * 4, 80),
                    evidence: [
                        "count": "\(assessment.sharedAnonymousExecutableCount)",
                        "detail": assessment.methods.joined(separator: ","),
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 90
                )
            )
        }

        if assessment.imageAnonymousAliasCount > 0 {
            signals.append(
                RiskSignal(
                    id: SignalID.vmRemapImageAlias,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: min(48 + Double(assessment.imageAnonymousAliasCount) * 6, 78),
                    evidence: [
                        "count": "\(assessment.imageAnonymousAliasCount)",
                        "detail": assessment.methods.joined(separator: ","),
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 88
                )
            )
        }

        if signals.isEmpty {
            signals.append(
                RiskSignal(
                    id: SignalID.vmRemapSharedAnonymous,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 16,
                    evidence: ["detail": assessment.methods.joined(separator: ",")],
                    state: .soft(confidence: 0.55),
                    layer: 2,
                    weightHint: 42
                )
            )
        }
        return signals
    }
}
