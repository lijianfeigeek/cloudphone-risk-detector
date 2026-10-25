// GPU 渲染指纹 Provider。
// 用 Metal 计算着色器渲染固定 8×8 图案，对像素做 SHA-256 得到渲染指纹。
// 不同 GPU/驱动会产生细微渲染差异，可用于识别云手机虚拟 GPU 与设备聚类；
// 指纹本身不计分，仅上报；Metal 不可用时输出 `gpu_render_unavailable` 弱信号。
#if canImport(Metal) && canImport(UIKit)
import CryptoKit
import Foundation
import Metal

/// 渲染指纹采集器：缓存 5 分钟，避免每次评估都触发 GPU 计算。
final class GPURenderFingerprintProvider: RiskSignalProvider {
    static let shared = GPURenderFingerprintProvider()
    let id = "gpu_render_fingerprint"

    // 缓存访问用自旋锁保护；systemUptime 单调递增，不受用户改系统时间影响。
    private let lock = UnfairLock()
    private var cachedFingerprint: String?
    private var cacheTime: TimeInterval = 0
    private let cacheTTL: TimeInterval = 300

    /// 生成信号：成功时上报指纹（hard detected:false），失败时上报不可用。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        guard let fp = fingerprint() else {
            return [RiskSignal(
                id: SignalID.gpuRenderUnavailable,
                category: SignalCategory.cloudphone,
                score: 0,
                evidence: ["detail": "metal_compute_failed"],
                state: .soft(confidence: 0.5),
                layer: 1,
                weightHint: 70
            )]
        }

        return [RiskSignal(
            id: SignalID.gpuRenderFingerprint,
            category: SignalCategory.cloudphone,
            score: 0,
            evidence: ["fingerprint": fp],
            state: .hard(detected: false),
            layer: 1,
            weightHint: 85
        )]
    }

    /// 读取缓存指纹；过期或不存在时重新渲染。
    /// - 缓存命中直接在锁内返回，避免重复占用 GPU。
    private func fingerprint() -> String? {
        let now = ProcessInfo.processInfo.systemUptime
        let cached: String? = lock.withLock {
            if now - cacheTime < cacheTTL { return cachedFingerprint }
            return nil
        }
        if let cached { return cached }

        guard let result = renderFingerprint() else { return nil }

        lock.withLock {
            cachedFingerprint = result
            cacheTime = ProcessInfo.processInfo.systemUptime
        }
        return result
    }

    /// 执行一次 Metal 计算并返回像素哈希。
    /// - 任一步骤（设备、队列、纹理、库、管线）失败都返回 nil，由上层降级。
    /// - 同步等待 GPU 完成，最多 2s，低于 ProviderRegistry 的 3s 预算。
    private func renderFingerprint() -> String? {
        guard let device = MTLCreateSystemDefaultDevice(),
              let queue = device.makeCommandQueue(),
              let buffer = queue.makeCommandBuffer() else {
            return nil
        }

        let desc = MTLTextureDescriptor.texture2DDescriptor(
            pixelFormat: .rgba8Unorm,
            width: 8,
            height: 8,
            mipmapped: false
        )
        desc.usage = [.shaderRead, .shaderWrite]
        guard let texture = device.makeTexture(descriptor: desc) else { return nil }

        // 使用固定 8×8 RGBA8 纹理，小尺寸可保证低端 GPU 也能快速完成。
        let source = """
        #include <metal_stdlib>
        using namespace metal;
        kernel void fp_kernel(texture2d<float, access::write> out [[texture(0)]],
                              uint2 gid [[thread_position_in_grid]]) {
            float x = float(gid.x) / 7.0;
            float y = float(gid.y) / 7.0;
            float r = sin(x * 3.14159265 * 2.0 + y) * 0.5 + 0.5;
            float g = cos(y * 3.14159265 * 3.0 - x) * 0.5 + 0.5;
            float b = sin((x + y) * 3.14159265 * 1.5) * 0.5 + 0.5;
            out.write(float4(r, g, b, 1.0), gid);
        }
        """

        guard let library = try? device.makeLibrary(source: source, options: nil),
              let function = library.makeFunction(name: "fp_kernel"),
              let pipeline = try? device.makeComputePipelineState(function: function) else {
            return nil
        }

        guard let encoder = buffer.makeComputeCommandEncoder() else { return nil }
        encoder.setComputePipelineState(pipeline)
        encoder.setTexture(texture, index: 0)

        let threadgroupSize = MTLSize(width: 8, height: 8, depth: 1)
        let threadgroups = MTLSize(width: 1, height: 1, depth: 1)
        encoder.dispatchThreadgroups(threadgroups, threadsPerThreadgroup: threadgroupSize)
        encoder.endEncoding()

        let semaphore = DispatchSemaphore(value: 0)
        buffer.addCompletedHandler { _ in semaphore.signal() }
        buffer.commit()
        // 超时 2s（< ProviderRegistry 的 3s），确保不会与注册表的整体截止时间赛跑；
        // 超时即放弃本次指纹，避免阻塞后续 Provider。
        if semaphore.wait(timeout: .now() + 2.0) == .timedOut {
            return nil
        }

        guard buffer.status == .completed else { return nil }

        var pixels = [UInt8](repeating: 0, count: 8 * 8 * 4)
        texture.getBytes(
            &pixels,
            bytesPerRow: 8 * 4,
            from: MTLRegion(
                origin: MTLOrigin(x: 0, y: 0, z: 0),
                size: MTLSize(width: 8, height: 8, depth: 1)
            ),
            mipmapLevel: 0
        )

        let digest = SHA256.hash(data: Data(pixels))
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
#else
import Foundation

/// Metal/UIKit 不可用平台（如部分测试目标）的空实现，不产生任何信号。
final class GPURenderFingerprintProvider: RiskSignalProvider {
    static let shared = GPURenderFingerprintProvider()
    let id = "gpu_render_fingerprint"
    /// Metal/UIKit 不可用时不做任何检测。
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] { [] }
}
#endif
