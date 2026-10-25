import CRiskCore
import Darwin
import Foundation
import MachO

// MARK: - 模拟器内存布局探测
//
// 通过五项真机内存布局不变量识别 unidbg / Unicorn 等 Linux 宿主模拟器：
// dyld 共享缓存缺失、vm_region 数量稀疏、主线程栈地址过低、timebase 比例平直、
// 系统镜像基址异常。各项累加后封顶 60，作为整体风险中的一项布局证据。
// 与 EmulatorBehaviorDetector（进程行为）互补：此处看"地址空间像不像 iOS"。

/// 模拟器内存布局检测器。
/// - 线程模型：同步只读 Mach/dyld 查询，无共享状态。
/// - 误报边界：M 系列 Mac 的 timebase 也是 1/1，故仅在共享缓存同时缺失时计分；
///   Xcode 模拟器直接降级，避免把开发环境判为云手机。
struct EmulatorLayoutDetector: Detector {
    // vm_region_64 要求以 natural_t 个数传入结构体大小，预先换算避免每次迭代重复计算。
    private static let vmRegionBasicInfoCount64 = mach_msg_type_number_t(
        MemoryLayout<vm_region_basic_info_data_64_t>.stride / MemoryLayout<natural_t>.stride
    )

    // MARK: - 分项分值

    private enum Score {
        // 共享缓存缺失是 iOS 上最强的结构性差异，权重最高。
        static let noDyldSharedCache: Double    = 22
        static let slackVMRegionCount: Double   = 12
        static let stackAddressLow: Double      = 14
        static let timbaseRatioFlat: Double     = 8
        static let imageBaseAnomalous: Double   = 10
        // 封顶 60：布局证据可强但不能单独定性，需与其他维度合并。
        static let max: Double                  = 60
    }

    // MARK: - Detector 协议

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        // 模拟器布局与真机本就不同，直接降级为 0 分（开发/CI 不误报）。
        return DetectorResult(score: 0, methods: ["emulator_layout:unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []

        // ── 1. dyld 共享缓存存在性 ─────────────────────────────────────────
        // 真机上 _dyld_shared_cache_contains_path 对任意系统框架都返回 true；
        // unidbg 不提供共享缓存，因此这是最强的单项线索。
        let sharedCacheResult = probeDyldSharedCache()
        if !sharedCacheResult.present {
            score += Score.noDyldSharedCache
            methods.append("emulator_layout:no_shared_cache")
        } else {
            methods.append("emulator_layout:shared_cache_ok(\(sharedCacheResult.detail))")
        }

        // ── 2. vm_region 数量（地址空间稀疏度）───────────────────────────
        let regionCount = countVMRegions()
        // 真机 App 通常有 200–800 个 region（仅共享缓存就贡献数百个映射）；
        // unidbg 进程往往 <30，这里用 40 作为保守阈值。
        if regionCount < 40 {
            score += Score.slackVMRegionCount
            methods.append("emulator_layout:sparse_vm_regions(\(regionCount))")
        } else {
            methods.append("emulator_layout:vm_regions_ok(\(regionCount))")
        }

        // ── 3. 主线程栈地址 ───────────────────────────────────────────────
        // arm64 iOS 主线程栈顶通常 >0x16_0000_0000；Unicorn 默认把栈映射在低地址。
        let stackAddr = currentStackAddress()
        if stackAddr < 0x0001_0000_0000 {   // 低于 4 GB 视为模拟器地址区间
            score += Score.stackAddressLow
            methods.append("emulator_layout:stack_low(0x\(String(stackAddr, radix: 16)))")
        } else {
            methods.append("emulator_layout:stack_ok(0x\(String(stackAddr, radix: 16)))")
        }

        // ── 4. mach_timebase_info 比例 ────────────────────────────────────
        // unidbg 固定返回 1/1；真机 A 系列为 125/3，M 系列虽也是 1/1 但有真实 GPU 时序。
        var tbinfo = mach_timebase_info_data_t()
        mach_timebase_info(&tbinfo)
        let isFlat = (tbinfo.numer == 1 && tbinfo.denom == 1)
        // 仅在共享缓存同时缺失时计分，避免 M 系列 Mac / 特殊环境被误判。
        if isFlat && !sharedCacheResult.present {
            score += Score.timbaseRatioFlat
            methods.append("emulator_layout:timebase_flat_no_cache")
        }

        // ── 5. 镜像基址合理性 ─────────────────────────────────────────────
        // 真机系统框架镜像从共享缓存加载到高地址（>0x180000000）；
        // unidbg 要么未加载，要么放在低地址 stub 区。
        let imageBaseOK = probeSystemImageBases()
        if !imageBaseOK {
            score += Score.imageBaseAnomalous
            methods.append("emulator_layout:image_base_anomalous")
        } else {
            methods.append("emulator_layout:image_base_ok")
        }

        let finalScore = min(score, Score.max)
        return DetectorResult(score: finalScore, methods: methods)
#endif
    }

    // MARK: - 私有探针

    private struct SharedCacheResult {
        let present: Bool
        let detail: String
    }

    /// 探测共享缓存中必然存在的系统库；返回是否命中及可读的细节标记。
    private func probeDyldSharedCache() -> SharedCacheResult {
        // 使用混淆后的路径，避免攻击者通过字符串扫描定位检测逻辑。
        let parts: [UInt8] = [
            // "/usr/lib/libobjc.A.dylib" 经 XOR 0x37 混淆后的字节
            0x1E, 0x44, 0x43, 0x1E, 0x5B, 0x59, 0x4B, 0x1E,
            0x5B, 0x59, 0x4B, 0x5C, 0x48, 0x4A, 0x5E, 0x1E,
            0x5C, 0x0B, 0x1E, 0x47, 0x44, 0x5B, 0x59, 0x4B
        ]
        let path = String(parts.map { Character(UnicodeScalar($0 ^ 0x37)) })
        let inCache = _dyld_shared_cache_contains_path(path)
        return SharedCacheResult(
            present: inCache,
            detail: inCache ? "libobjc_found" : "libobjc_absent"
        )
    }

    /// 遍历当前 task 的 vm_region 并计数。
    /// - 上限 2000 次迭代，防止异常地址空间导致死循环；
    /// - 任一 vm_region_64 调用失败即提前结束，返回已统计数量。
    private func countVMRegions() -> Int {
        var address: vm_address_t = 0
        var count = 0
        var size: vm_size_t = 0
        var info = vm_region_basic_info_data_64_t()
        var infoCount = Self.vmRegionBasicInfoCount64
        var objectName: mach_port_t = 0

        let maxIterations = 2000
        var iterations = 0

        while iterations < maxIterations {
            infoCount = Self.vmRegionBasicInfoCount64
            let kr = withUnsafeMutablePointer(to: &info) { infoPtr in
                infoPtr.withMemoryRebound(to: Int32.self, capacity: Int(Self.vmRegionBasicInfoCount64)) { rawPtr in
                    vm_region_64(
                        mach_task_self_,
                        &address,
                        &size,
                        VM_REGION_BASIC_INFO_64,
                        rawPtr,
                        &infoCount,
                        &objectName
                    )
                }
            }
            guard kr == KERN_SUCCESS else { break }
            count += 1
            address += vm_address_t(size)
            iterations += 1
        }
        return count
    }

    /// 通过局部变量地址近似读取当前栈指针，用于判断栈所在虚拟地址区间。
    private func currentStackAddress() -> UInt64 {
        // 局部变量位于当前栈帧内，其地址可代表栈地址量级。
        var local: UInt8 = 0
        return UInt64(UInt(bitPattern: withUnsafePointer(to: &local) { $0 }))
    }

    /// 检查已加载镜像中高地址（≥6 GB）系统镜像的数量。
    /// - 返回：至少 5 个镜像位于共享缓存高地址区间时为 true；
    /// - 镜像数不足或全部低地址时返回 false（疑似模拟器）。
    private func probeSystemImageBases() -> Bool {
        // 真机共享缓存镜像位于 0x180000000（6 GB）以上；unidbg 未加载或置于 0x100000000 以下。
        let threshold: UInt64 = 0x0001_8000_0000
        let imageCount = _dyld_image_count()
        guard imageCount > 0 else { return false }

        var highAddressCount = 0
        // 只抽查前 80 个镜像，控制检测耗时并避免遍历大型进程的全部镜像。
        let checkCount = min(Int(imageCount), 80)

        for i in 0..<checkCount {
            guard let header = _dyld_get_image_header(UInt32(i)) else { continue }
            let addr = UInt64(UInt(bitPattern: header))
            if addr >= threshold {
                highAddressCount += 1
            }
        }
        // 真机期望至少 5 个系统镜像位于 6 GB 以上；阈值偏低以免少量镜像差异造成误报。
        return highAddressCount >= 5
    }
}
