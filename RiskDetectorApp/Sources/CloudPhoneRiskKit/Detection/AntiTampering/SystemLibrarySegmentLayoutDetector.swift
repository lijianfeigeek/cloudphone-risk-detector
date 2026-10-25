// SystemLibrarySegmentLayoutDetector：校验主 App 与关键系统库的段布局。
// 对比 Mach-O 声明的段/权限与运行期 vm_region 实际映射，识别：
// W+X 映射、__TEXT 可写、__DATA 可执行、匿名可执行区、段数/可执行区数量漂移。
// 这类异常通常意味着镜像被重映射、代码段被改写或注入页被追加。
import Darwin
import Foundation
import MachO

// Mach 匿名映射的 user_tag 集合（240...245）。
private let segmentLayoutAnonymousUserTags: Set<UInt32> = [240, 241, 242, 243, 244, 245]
// 每个镜像最多遍历 128 个 region，限制 vm_region_64 开销。
private let maxRegionIterationsPerImage = 128

/// 系统库/主 App 段布局检测器。
/// - 线程模型：同步只读遍历 dyld 镜像与 vm_region。
/// - 判定：任一关键权限异常直接 tampered；数量漂移使用 soft。
struct SystemLibrarySegmentLayoutDetector: Detector {
    /// 目标类型：主 App 或关键系统库。
    enum TargetKind {
        case mainApp
        case systemLibrary
    }

    /// Mach-O 中声明的段：名称、运行时地址范围、初始权限。
    struct SegmentDescriptor {
        let name: String
        let range: Range<UInt64>
        let initProtection: vm_prot_t
    }

    /// 单个镜像的布局快照。
    struct ImageLayoutSnapshot {
        // 声明段数、运行期 region 数及各类权限计数。
        let id: String
        let displayName: String
        let path: String
        let kind: TargetKind
        let declaredSegmentCount: Int
        let executableSegmentCount: Int
        let runtimeRegionCount: Int
        let executableRegionCount: Int
        let readOnlyRegionCount: Int
        let readWriteRegionCount: Int
        let writableExecutableRegionCount: Int
        let anonymousExecutableRegionCount: Int
        let textWritableRegionCount: Int
        let dataExecutableRegionCount: Int
    }

    /// 待分析的目标镜像。
    private struct TargetImage {
        let id: String
        let displayName: String
        let path: String
        let kind: TargetKind
        let header: UnsafeRawPointer
    }

    /// 一次评估的结果。
    private struct Evaluation {
        let score: Double
        let methods: [String]
        let snapshots: [ImageLayoutSnapshot]
    }

    // 监控对象：dyld、核心系统库、Foundation/CoreFoundation 与主 App。
    private static let targetSuffixes: [(id: String, display: String, suffix: String)] = [
        ("dyld", "dyld", "/usr/lib/dyld"),
        ("libsystem_kernel", "libsystem_kernel", "/usr/lib/system/libsystem_kernel.dylib"),
        ("libsystem_c", "libsystem_c", "/usr/lib/libsystem_c.dylib"),
        ("libobjc", "libobjc", "/usr/lib/libobjc.A.dylib"),
        ("libcxx", "libc++", "/usr/lib/libc++.1.dylib"),
        ("foundation", "Foundation", "Foundation.framework/Foundation"),
        ("corefoundation", "CoreFoundation", "CoreFoundation.framework/CoreFoundation"),
    ]

    /// 入口：模拟器直接返回 0，真机进入评估。
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["segment_layout:unavailable_simulator"])
#else
        let evaluation = evaluate()
        return DetectorResult(score: evaluation.score, methods: evaluation.methods)
#endif
    }

    /// 信号转换：系统库 W+X/匿名可执行/漂移，以及主 App 布局异常。
    func asSignals() throws -> [RiskSignal] {
#if targetEnvironment(simulator)
        return []
#else
        let evaluation = evaluate()
        guard !evaluation.snapshots.isEmpty else { return [] }

        var signals: [RiskSignal] = []
        let systemSnapshots = evaluation.snapshots.filter { $0.kind == .systemLibrary }
        let appSnapshots = evaluation.snapshots.filter { $0.kind == .mainApp }

        // 系统库出现 W+X、__TEXT 可写或 __DATA 可执行：强篡改。
        let wxSystem = systemSnapshots.filter {
            $0.writableExecutableRegionCount > 0 ||
            $0.textWritableRegionCount > 0 ||
            $0.dataExecutableRegionCount > 0
        }
        if !wxSystem.isEmpty {
            signals.append(RiskSignal(
                id: "system_library_wx_mapping",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 85,
                evidence: ["detail": wxSystem.map(Self.snapshotSummary).joined(separator: ";")],
                state: .tampered,
                layer: 2,
                weightHint: 94
            ))
        }

        // 系统库出现匿名可执行区：可能是注入页或 trampoline。
        let anonymousExecSystem = systemSnapshots.filter { $0.anonymousExecutableRegionCount > 0 }
        if !anonymousExecSystem.isEmpty {
            signals.append(RiskSignal(
                id: "system_library_anonymous_exec_region",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 82,
                evidence: ["detail": anonymousExecSystem.map(Self.snapshotSummary).joined(separator: ";")],
                state: .tampered,
                layer: 2,
                weightHint: 92
            ))
        }

        // 系统库段数或可执行区数量漂移：soft 证据。
        let driftSystem = systemSnapshots.filter {
            Self.isRegionCountDriftSuspicious($0) || Self.isExecutableDistributionSuspicious($0)
        }
        if !driftSystem.isEmpty {
            signals.append(RiskSignal(
                id: "system_library_segment_count_drift",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(driftSystem.count) * 18, 45),
                evidence: ["detail": driftSystem.map(Self.snapshotSummary).joined(separator: ";")],
                state: .soft(confidence: 0.72),
                layer: 2,
                weightHint: 68
            ))
        }

        // 主 App 的关键权限异常或段数漂移。
        let appAnomalies = appSnapshots.filter {
            Self.hasCriticalPermissionAnomaly($0) ||
            Self.isRegionCountDriftSuspicious($0) ||
            Self.isExecutableDistributionSuspicious($0)
        }
        if !appAnomalies.isEmpty {
            // 主 App 存在关键权限异常时提高分数与状态。
            let hasCritical = appAnomalies.contains(where: Self.hasCriticalPermissionAnomaly)
            signals.append(RiskSignal(
                id: "app_image_segment_layout_anomaly",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: hasCritical ? 70 : 35,
                evidence: ["detail": appAnomalies.map(Self.snapshotSummary).joined(separator: ";")],
                state: hasCritical ? .tampered : .soft(confidence: 0.7),
                layer: 2,
                weightHint: hasCritical ? 85 : 72
            ))
        }

        return signals
#endif
    }
}

extension SystemLibrarySegmentLayoutDetector {
    /// 关键权限异常：W+X、__TEXT 可写、__DATA 可执行、匿名可执行。
    static func hasCriticalPermissionAnomaly(_ snapshot: ImageLayoutSnapshot) -> Bool {
        snapshot.writableExecutableRegionCount > 0 ||
        snapshot.textWritableRegionCount > 0 ||
        snapshot.dataExecutableRegionCount > 0 ||
        snapshot.anonymousExecutableRegionCount > 0
    }

    /// region 数量漂移：运行期 region 数远超声明段数。
    static func isRegionCountDriftSuspicious(_ snapshot: ImageLayoutSnapshot) -> Bool {
        guard snapshot.declaredSegmentCount > 0 else { return false }
        // 阈值取 max(3×声明段数, 声明段数+4)，避免小镜像的固定噪声。
        let threshold = max(snapshot.declaredSegmentCount * 3, snapshot.declaredSegmentCount + 4)
        return snapshot.runtimeRegionCount >= threshold
    }

    /// 可执行区数量漂移：运行期可执行 region 数远超声明的可执行段数。
    static func isExecutableDistributionSuspicious(_ snapshot: ImageLayoutSnapshot) -> Bool {
        guard snapshot.executableSegmentCount > 0 else { return false }
        // 阈值取 max(3×可执行段数, 可执行段数+3)。
        let threshold = max(snapshot.executableSegmentCount * 3, snapshot.executableSegmentCount + 3)
        return snapshot.executableRegionCount >= threshold
    }
}

private extension SystemLibrarySegmentLayoutDetector {
    /// 评估所有目标镜像并汇总分数（封顶 95）。
    private func evaluate() -> Evaluation {
        let snapshots = collectSnapshots()
        guard !snapshots.isEmpty else {
            return Evaluation(score: 0, methods: ["segment_layout:clean"], snapshots: [])
        }

        var score: Double = 0
        var methods: [String] = []

        for snapshot in snapshots {
            // W+X 映射：+35。
            if snapshot.writableExecutableRegionCount > 0 {
                score += 35
                methods.append("segment_layout:wx:\(snapshot.id):count=\(snapshot.writableExecutableRegionCount)")
            }
            // __TEXT 可写：+25。
            if snapshot.textWritableRegionCount > 0 {
                score += 25
                methods.append("segment_layout:text_writable:\(snapshot.id):count=\(snapshot.textWritableRegionCount)")
            }
            // __DATA 可执行：+25。
            if snapshot.dataExecutableRegionCount > 0 {
                score += 25
                methods.append("segment_layout:data_executable:\(snapshot.id):count=\(snapshot.dataExecutableRegionCount)")
            }
            // 匿名可执行区：+30。
            if snapshot.anonymousExecutableRegionCount > 0 {
                score += 30
                methods.append("segment_layout:anonymous_exec:\(snapshot.id):count=\(snapshot.anonymousExecutableRegionCount)")
            }
            // region 数漂移：+12。
            if Self.isRegionCountDriftSuspicious(snapshot) {
                score += 12
                methods.append("segment_layout:drift:\(snapshot.id):declared=\(snapshot.declaredSegmentCount):runtime=\(snapshot.runtimeRegionCount)")
            }
            // 可执行区分布漂移：+10。
            if Self.isExecutableDistributionSuspicious(snapshot) {
                score += 10
                methods.append("segment_layout:exec_distribution:\(snapshot.id):segments=\(snapshot.executableSegmentCount):regions=\(snapshot.executableRegionCount)")
            }
        }

        // 总分封顶 95。
        return Evaluation(score: min(score, 95), methods: methods, snapshots: snapshots)
    }

    /// 枚举目标镜像并生成快照。
    private func collectSnapshots() -> [ImageLayoutSnapshot] {
        enumerateTargetImages().compactMap(makeSnapshot(for:))
    }

    /// 收集主 App 与关键系统库的 TargetImage。
    private func enumerateTargetImages() -> [TargetImage] {
        var targets: [TargetImage] = []
        var seen = Set<String>()

        // image 0 固定为主可执行文件。
        if let header = _dyld_get_image_header(0) {
            let path = _dyld_get_image_name(0).map { String(cString: $0) } ?? "main_app"
            targets.append(TargetImage(
                id: "main_app",
                displayName: "main_app",
                path: path,
                kind: .mainApp,
                header: UnsafeRawPointer(header)
            ))
            seen.insert("main_app")
        }

        // 按路径后缀匹配关键系统库。
        let count = _dyld_image_count()
        for i in 0..<count {
            guard let rawPath = _dyld_get_image_name(i), let header = _dyld_get_image_header(i) else {
                continue
            }
            let path = String(cString: rawPath)
            for item in Self.targetSuffixes where path.hasSuffix(item.suffix) {
                guard !seen.contains(item.id) else { break }
                targets.append(TargetImage(
                    id: item.id,
                    displayName: item.display,
                    path: path,
                    kind: .systemLibrary,
                    header: UnsafeRawPointer(header)
                ))
                seen.insert(item.id)
                break
            }
        }

        return targets
    }

    /// 解析声明段与运行期 region，生成单个镜像的布局快照。
    private func makeSnapshot(for target: TargetImage) -> ImageLayoutSnapshot? {
        let segments = parseSegments(header: target.header)
        guard !segments.isEmpty else { return nil }

        // 用声明段的最小/最大地址界定镜像范围。
        let imageStart = segments.map { $0.range.lowerBound }.min() ?? 0
        let imageEnd = segments.map { $0.range.upperBound }.max() ?? 0
        guard imageEnd > imageStart else { return nil }

        var runtimeRegionCount = 0
        var executableRegionCount = 0
        var readOnlyRegionCount = 0
        var readWriteRegionCount = 0
        var writableExecutableRegionCount = 0
        var anonymousExecutableRegionCount = 0
        var textWritableRegionCount = 0
        var dataExecutableRegionCount = 0

        var address = vm_address_t(imageStart)
        var iteration = 0

        // 在镜像地址范围内遍历 vm_region。
        while UInt64(address) < imageEnd && iteration < maxRegionIterationsPerImage {
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

            guard basicResult == KERN_SUCCESS, size > 0 else { break }

            let regionStart = UInt64(address)
            let regionEnd = regionStart &+ UInt64(size)
            guard regionEnd >= regionStart else { break }
            if regionStart >= imageEnd {
                break
            }

            // 只统计与镜像范围有重叠的 region。
            let overlapStart = max(regionStart, imageStart)
            let overlapEnd = min(regionEnd, imageEnd)
            if overlapStart < overlapEnd {
                runtimeRegionCount += 1

                let protection = basicInfo.protection
                let writable = (protection & VM_PROT_WRITE) != 0
                let executable = (protection & VM_PROT_EXECUTE) != 0
                let readable = (protection & VM_PROT_READ) != 0

                // 按权限分类统计 region。
                if executable { executableRegionCount += 1 }
                if writable && executable {
                    writableExecutableRegionCount += 1
                } else if writable {
                    readWriteRegionCount += 1
                } else if readable {
                    readOnlyRegionCount += 1
                }

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
                // 可执行且 user_tag 属于匿名集合 -> 匿名可执行区。
                if extResult == KERN_SUCCESS, executable,
                   segmentLayoutAnonymousUserTags.contains(UInt32(extInfo.user_tag)) {
                    anonymousExecutableRegionCount += 1
                }

                // 可写且覆盖 __TEXT -> __TEXT 被改为可写。
                let overlappingSegments = segments.filter { rangesOverlap($0.range, overlapStart..<overlapEnd) }
                if writable && overlappingSegments.contains(where: { $0.name == "__TEXT" }) {
                    textWritableRegionCount += 1
                }
                // 可执行且覆盖 __DATA -> __DATA 被改为可执行。
                if executable && overlappingSegments.contains(where: { $0.name.hasPrefix("__DATA") }) {
                    dataExecutableRegionCount += 1
                }
            }

            let nextAddress = UInt64(address) &+ UInt64(size)
            if nextAddress <= UInt64(address) {
                break
            }
            address = vm_address_t(nextAddress)
            iteration += 1
        }

        return ImageLayoutSnapshot(
            id: target.id,
            displayName: target.displayName,
            path: target.path,
            kind: target.kind,
            declaredSegmentCount: segments.count,
            executableSegmentCount: segments.filter { ($0.initProtection & VM_PROT_EXECUTE) != 0 }.count,
            runtimeRegionCount: runtimeRegionCount,
            executableRegionCount: executableRegionCount,
            readOnlyRegionCount: readOnlyRegionCount,
            readWriteRegionCount: readWriteRegionCount,
            writableExecutableRegionCount: writableExecutableRegionCount,
            anonymousExecutableRegionCount: anonymousExecutableRegionCount,
            textWritableRegionCount: textWritableRegionCount,
            dataExecutableRegionCount: dataExecutableRegionCount
        )
    }

    /// 解析 Mach-O 声明的段，并换算为运行时地址范围。
    private func parseSegments(header: UnsafeRawPointer) -> [SegmentDescriptor] {
        let ptr = header.assumingMemoryBound(to: mach_header_64.self)
        // 仅处理 64 位 Mach-O。
        guard ptr.pointee.magic == MH_MAGIC_64 || ptr.pointee.magic == MH_CIGAM_64 else {
            return []
        }

        var command = header.advanced(by: MemoryLayout<mach_header_64>.size)
        let commandLimit = command.advanced(by: Int(ptr.pointee.sizeofcmds))
        var slide: UInt64 = 0
        var foundText = false

        for _ in 0..<ptr.pointee.ncmds {
            guard command < commandLimit else { break }
            let load = command.assumingMemoryBound(to: load_command.self).pointee
            guard load.cmdsize > 0 else { break }
            if load.cmd == LC_SEGMENT_64 {
                let segment = command.assumingMemoryBound(to: segment_command_64.self).pointee
                let name = Self.segmentName(segment.segname)
                // 用 __TEXT 的运行时地址与 vmaddr 反推 slide。
                if name == "__TEXT" {
                    let runtimeHeader = UInt64(bitPattern: Int64(Int(bitPattern: header)))
                    slide = runtimeHeader &- segment.vmaddr
                    foundText = true
                    break
                }
            }
            command = command.advanced(by: Int(load.cmdsize))
        }

        guard foundText else { return [] }

        var segments: [SegmentDescriptor] = []
        command = header.advanced(by: MemoryLayout<mach_header_64>.size)

        // 第二遍收集所有段，跳过 vmsize 为 0 的段。
        for _ in 0..<ptr.pointee.ncmds {
            guard command < commandLimit else { break }
            let load = command.assumingMemoryBound(to: load_command.self).pointee
            guard load.cmdsize > 0 else { break }
            if load.cmd == LC_SEGMENT_64 {
                let segment = command.assumingMemoryBound(to: segment_command_64.self).pointee
                guard segment.vmsize > 0 else {
                    command = command.advanced(by: Int(load.cmdsize))
                    continue
                }
                let start = segment.vmaddr &+ slide
                let end = start &+ segment.vmsize
                if end > start {
                    segments.append(SegmentDescriptor(
                        name: Self.segmentName(segment.segname),
                        range: start..<end,
                        initProtection: segment.initprot
                    ))
                }
            }
            command = command.advanced(by: Int(load.cmdsize))
        }

        return segments
    }

    /// 从固定长度段名元组中读取以 NUL 结尾的字符串。
    private static func segmentName<T>(_ tuple: T) -> String {
        withUnsafePointer(to: tuple) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: MemoryLayout<T>.size) { cPtr in
                let count = strnlen(cPtr, MemoryLayout<T>.size)
                let raw = UnsafeRawPointer(cPtr).assumingMemoryBound(to: UInt8.self)
                return String(decoding: UnsafeBufferPointer(start: raw, count: count), as: UTF8.self)
            }
        }
    }

    /// 判断两个半开区间是否重叠。
    private func rangesOverlap(_ lhs: Range<UInt64>, _ rhs: Range<UInt64>) -> Bool {
        lhs.lowerBound < rhs.upperBound && rhs.lowerBound < lhs.upperBound
    }

    /// 生成快照摘要，供证据字段使用。
    private static func snapshotSummary(_ snapshot: ImageLayoutSnapshot) -> String {
        "\(snapshot.displayName){declared=\(snapshot.declaredSegmentCount),runtime=\(snapshot.runtimeRegionCount),rx=\(snapshot.executableRegionCount),ro=\(snapshot.readOnlyRegionCount),rw=\(snapshot.readWriteRegionCount),wx=\(snapshot.writableExecutableRegionCount),anonExec=\(snapshot.anonymousExecutableRegionCount),textW=\(snapshot.textWritableRegionCount),dataX=\(snapshot.dataExecutableRegionCount)}"
    }
}
