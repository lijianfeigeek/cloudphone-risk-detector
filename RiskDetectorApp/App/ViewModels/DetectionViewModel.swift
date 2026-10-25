import Foundation
import SwiftUI
import Combine

#if canImport(CloudPhoneRiskAppCore)
import CloudPhoneRiskAppCore
import CloudPhoneRiskKit
#endif

// MARK: - Detection State
public enum DetectionState: Equatable {
    case idle
    case detecting
    case completed
    case error(String)
}

// MARK: - Risk Level (UI only)
public enum RiskLevel: String {
    case low = "低风险"
    case medium = "中风险"
    case high = "高风险"

    public var color: Color {
        switch self {
        case .low: return .green
        case .medium: return .orange
        case .high: return .red
        }
    }

    public var icon: String {
        switch self {
        case .low: return "checkmark.shield.fill"
        case .medium: return "exclamationmark.shield.fill"
        case .high: return "xmark.shield.fill"
        }
    }

    public static func from(score: Double) -> RiskLevel {
        if score < 30 { return .low }
        else if score < 60 { return .medium }
        else { return .high }
    }
}

// MARK: - Detection ViewModel
/// 规范：
/// - 输入：RiskAppConfig（来自 Settings）
/// - 输出：lastDTO, isDetecting, error
/// - 只暴露 DTO，UI 不接触 CPRiskReport
@MainActor
public class DetectionViewModel: ObservableObject {
    // MARK: - Published State
    @Published public var state: DetectionState = .idle
    @Published public var lastDTO: RiskReportDTO?
    @Published public var showResults: Bool = false
    /// 本次检测自动保存后的报告路径；nil 表示尚未保存或保存失败。
    @Published public var lastSavedPath: String?
    /// 保存失败原因（成功后为 nil），供界面展示。
    @Published public var saveError: String?

    // MARK: - Derived (UI convenience)
    public var riskLevel: RiskLevel? {
        guard let dto = lastDTO else { return nil }
        return RiskLevel.from(score: dto.score)
    }

    public var isDetecting: Bool {
        state == .detecting
    }

    // Keep raw report for save operation
    #if canImport(CloudPhoneRiskAppCore)
    private var lastReport: CPRiskReport?
    #endif

    public init() {}

    // MARK: - Actions

    /// 启动采集（App 启动时调用一次）
    public func startIfNeeded() {
        #if canImport(CloudPhoneRiskAppCore)
        RiskDetectionService.shared.start()
        #endif
    }

    /// 执行检测
    /// - Parameter config: 检测配置（来自 SettingsViewModel）
    public func detect(config: RiskAppConfig? = nil) {
        state = .detecting
        lastSavedPath = nil
        saveError = nil

        #if canImport(CloudPhoneRiskAppCore)
        let cfg = config ?? .default
        RiskDetectionService.shared.evaluateAsync(config: cfg) { [weak self] report in
            DispatchQueue.main.async {
                guard let self else { return }
                self.lastReport = report
                self.lastDTO = RiskReportMapper.dto(from: report)
                self.state = .completed
                self.showResults = true
                // 检测完成后自动入库，历史页无需用户再点一次“保存”。
                self.save(config: cfg)
            }
        }
        #else
        // 非 iOS / 无 AppCore 场景：优雅降级，不触发崩溃
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in
            self?.state = .error("CloudPhoneRiskAppCore unavailable in current build target")
            self?.showResults = false
        }
        #endif
    }

    /// 保存报告到本地（自动写 meta.json）
    /// - Returns: 保存路径，nil 表示失败
    @discardableResult
    public func save(config: RiskAppConfig? = nil) -> String? {
        #if canImport(CloudPhoneRiskAppCore)
        guard let report = lastReport, let dto = lastDTO else {
            saveError = "没有可保存的检测结果"
            return nil
        }
        let cfg = config ?? .default
        guard let path = RiskDetectionService.shared.save(report: report, config: cfg) else {
            lastSavedPath = nil
            saveError = "报告保存失败（加密密钥不可用或磁盘写入失败）"
            return nil
        }
        // Write meta for fast History loading
        RiskReportSummaryIO.writeMeta(for: dto, reportPath: path)
        lastSavedPath = path
        saveError = nil
        return path
        #else
        return nil
        #endif
    }

    /// 重置状态
    public func reset() {
        state = .idle
        lastDTO = nil
        showResults = false
        lastSavedPath = nil
        saveError = nil
        #if canImport(CloudPhoneRiskAppCore)
        lastReport = nil
        #endif
    }

}
