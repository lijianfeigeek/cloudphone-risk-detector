import Darwin
import Foundation
#if canImport(Metal)
import Metal
#endif

// MARK: - GPU 渲染探测
//
// 云手机常宣称具备 GPU，实际却使用软件渲染或远程渲染。本检测器通过 Metal 设备特征、
// compute/buffer 分配与空命令提交耗时，识别非真实 Apple GPU 的实现。
// 结果以 soft 信号输出，配合传感器/布局检测共同判断。

/// GPU 渲染能力深度探测
///
/// 云手机通常声称有 GPU 但实际使用软件模拟或远程渲染。
/// 通过实际执行 GPU 计算任务并测量延迟来检测：
/// 1. Metal 设备可用性与特性
/// 2. 简单 compute shader 执行时间（真 GPU vs 软件模拟差异巨大）
/// 3. GPU 内存分配特征
struct GPURenderProbe: Detector {

    func detect() throws -> DetectorResult {
        #if targetEnvironment(simulator)
        // 模拟器 GPU 由宿主代理，时序不可比，直接降级避免误判。
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
        #else
        var score: Double = 0
        var methods: [String] = []

        #if canImport(Metal)
        // 1. Metal 设备可用性与特性
        let deviceCheck = checkMetalDevice()
        score += deviceCheck.score
        methods.append(contentsOf: deviceCheck.methods)

        // 2. GPU 计算/提交时序
        let computeCheck = checkComputeTiming()
        score += computeCheck.score
        methods.append(contentsOf: computeCheck.methods)
        #else
        // 编译期没有 Metal：iOS 真机不可能出现，给出固定中等分。
        score += 10
        methods.append("gpu_probe:metal_unavailable")
        #endif

        return DetectorResult(score: score, methods: methods)
        #endif
    }

    #if canImport(Metal)
    /// 检查 Metal 设备名称、特性族与最大 buffer 长度。
    /// - 返回：累加分数与明细方法串。
    private func checkMetalDevice() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        // 无 Metal 设备：真机不可能，直接给 20 分。
        guard let device = MTLCreateSystemDefaultDevice() else {
            score += 20
            methods.append("gpu_probe:no_metal_device")
            return (score, methods)
        }

        let name = device.name.lowercased()

        // 已知虚拟/软件渲染器名称关键字；命中一个即足以说明不是 Apple GPU。
        let virtualGPUKeywords = ["software", "swiftshader", "llvmpipe", "mesa", "virtual", "emulated"]
        for keyword in virtualGPUKeywords {
            if name.contains(keyword) {
                score += 25
                methods.append("gpu_probe:virtual_gpu:\(name)")
                break
            }
        }

        // 真 Apple GPU 支持 apple3 特性族；不支持说明能力被裁剪或为软件实现。
        if !device.supportsFamily(.apple3) {
            score += 8
            methods.append("gpu_probe:low_feature_family")
        }

        // 真机 maxBufferLength 通常远大于 256 MB；过小说明是受限的虚拟实现。
        let maxBuffer = device.maxBufferLength
        if maxBuffer < 256 * 1024 * 1024 { // < 256MB 视为可疑
            score += 10
            methods.append("gpu_probe:small_max_buffer:\(maxBuffer / (1024*1024))MB")
        }

        return (score, methods)
    }

    /// 测量 buffer 分配与空命令提交的耗时，识别软件渲染的高延迟。
    /// - 返回：本项封顶 25 分，避免时序抖动单独推高总分。
    private func checkComputeTiming() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        guard let device = MTLCreateSystemDefaultDevice(),
              let commandQueue = device.makeCommandQueue() else {
            // 无法创建队列时不加分，交由 checkMetalDevice 的设备可用性判定。
            return (0, [])
        }

        // 分配 1 MB 共享内存 buffer，测量分配与写入耗时。
        let bufferSize = 1024 * 1024 // 1MB
        let start = mach_absolute_time()
        guard let buffer = device.makeBuffer(length: bufferSize, options: .storageModeShared) else {
            // 分配失败本身说明实现受限，给少量分后返回。
            score += 8
            methods.append("gpu_probe:buffer_alloc_failed")
            return (score, methods)
        }
        let allocEnd = mach_absolute_time()

        // 逐字节填充，确保真正触碰物理/虚拟内存，而非只做分配记账。
        let ptr = buffer.contents().assumingMemoryBound(to: UInt8.self)
        for i in 0..<bufferSize {
            ptr[i] = UInt8(i & 0xFF)
        }
        let fillEnd = mach_absolute_time()

        // 将 tick 换算为纳秒，timebase 在此环境可能是 1/1。
        var timebaseInfo = mach_timebase_info_data_t()
        mach_timebase_info(&timebaseInfo)
        let denom = Double(max(timebaseInfo.denom, 1))
        let allocNs = Double(allocEnd - start) * Double(timebaseInfo.numer) / denom
        let fillNs = Double(fillEnd - allocEnd) * Double(timebaseInfo.numer) / denom

        // 真机：分配 < 1ms、填充 < 5ms；虚拟实现：分配可能 > 10ms、填充 > 50ms。
        if allocNs > 10_000_000 { // > 10ms
            score += 12
            methods.append("gpu_probe:slow_alloc:\(Int(allocNs / 1_000_000))ms")
        }

        // 提交一个空命令 buffer 并等待完成，测量 GPU 往返响应。
        if let cmdBuffer = commandQueue.makeCommandBuffer() {
            let gpuStart = mach_absolute_time()
            cmdBuffer.commit()
            cmdBuffer.waitUntilCompleted()
            let gpuEnd = mach_absolute_time()
            let gpuNs = Double(gpuEnd - gpuStart) * Double(timebaseInfo.numer) / denom

            // 真机空命令 buffer < 1ms；软件渲染可能 > 5ms。
            if gpuNs > 5_000_000 { // > 5ms
                score += 15
                methods.append("gpu_probe:slow_cmd_buffer:\(Int(gpuNs / 1_000_000))ms")
            }
        }

        // fillNs 目前仅用于测量填充阶段，保留变量以维持原有行为。
        _ = fillNs

        return (min(score, 25), methods)
    }
    #endif
}

extension GPURenderProbe {
    /// 将检测结果转换为 `gpu_render_anomaly` 软信号。
    /// - 置信度按 score/30 线性折算并封顶 1.0；
    /// - layer 1、weightHint 75：GPU 证据仅作辅助，不单独定性。
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }
        
        var signals: [RiskSignal] = []
        
        let gpuMethods = result.methods.filter { $0.hasPrefix("gpu_probe") }
        if !gpuMethods.isEmpty {
            signals.append(RiskSignal(
                id: "gpu_render_anomaly",
                category: "device",
                score: result.score,
                evidence: ["detail": gpuMethods.joined(separator: ",")],
                state: .soft(confidence: min(result.score / 30.0, 1.0)),
                layer: 1,
                weightHint: 75
            ))
        }
        
        return signals
    }
}
