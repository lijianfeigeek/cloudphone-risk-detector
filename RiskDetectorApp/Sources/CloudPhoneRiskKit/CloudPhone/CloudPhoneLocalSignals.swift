// 云手机/虚拟环境本地特征：把设备、行为、时序三组判定打包为可上报的
// `CloudPhoneLocalSignals`（短键编码 d/b/t），供服务端做云手机画像与策略决策。
// 每个特征都是 `DetectionSignal`（detected + method + evidence + confidence），
// 强调可解释、可复核，不在本地直接下结论；样本不足时按未命中处理。
import Foundation

/// 云手机本地信号集合：设备（模拟器/老机型）、行为（触摸/运动）、时序（24h 活动）。
public struct CloudPhoneLocalSignals: Codable, Sendable {
    /// 设备层特征
    public var device: CloudPhoneDeviceSignals
    /// 行为层特征
    public var behavior: CloudPhoneBehaviorSignals
    /// 时序层特征
    public var time: CloudPhoneTimeSignals

    // 短键压缩上报体积：d=device、b=behavior、t=time。
    private enum CodingKeys: String, CodingKey {
        case device = "d"
        case behavior = "b"
        case time = "t"
    }

    /// 创建信号集合；三组均为必填，缺省能力由各组内部以 detected=false 表达。
    public init(
        device: CloudPhoneDeviceSignals,
        behavior: CloudPhoneBehaviorSignals,
        time: CloudPhoneTimeSignals
    ) {
        self.device = device
        self.behavior = behavior
        self.time = time
    }
}

/// 设备层特征：模拟器检测与老机型启发式（云手机农场常用旧机型）。
public struct CloudPhoneDeviceSignals: Codable, Sendable {
    /// 是否运行在模拟器（targetEnvironment 或指纹命中）
    public var isSimulator: DetectionSignal<[String: String]>
    /// 老机型启发式；nil 表示机型无法解析或未检测
    public var oldDeviceModel: DetectionSignal<[String: String]>?

    // 短键：is=isSimulator、od=oldDeviceModel。
    private enum CodingKeys: String, CodingKey {
        case isSimulator = "is"
        case oldDeviceModel = "od"
    }

    /// 创建设备层信号；oldDeviceModel 可缺省。
    public init(
        isSimulator: DetectionSignal<[String: String]>,
        oldDeviceModel: DetectionSignal<[String: String]>?
    ) {
        self.isSimulator = isSimulator
        self.oldDeviceModel = oldDeviceModel
    }
}

/// 行为层特征：与 `RiskScorer` 的行为启发式同源，但输出为可上报的判定对象。
public struct CloudPhoneBehaviorSignals: Codable, Sendable {
    /// 触摸坐标离散度过低（落点集中）
    public var touchSpreadLow: DetectionSignal<[String: String]>
    /// 触摸坐标离散度过高（落点发散）
    public var touchSpreadHigh: DetectionSignal<[String: String]>
    /// 点击间隔过于规律
    public var touchIntervalTooRegular: DetectionSignal<[String: String]>
    /// 点击间隔过于混乱
    public var touchIntervalTooChaotic: DetectionSignal<[String: String]>
    /// 滑动轨迹过于笔直
    public var swipeTooLinear: DetectionSignal<[String: String]>
    /// 滑动轨迹过于弯曲
    public var swipeTooCurvy: DetectionSignal<[String: String]>
    /// 设备过于静止
    public var motionTooStill: DetectionSignal<[String: String]>
    /// 触摸与运动弱耦合
    public var touchMotionWeakCoupling: DetectionSignal<[String: String]>

    // 短键：sl/sh/tr/tc/wl/wc/ms/wk，与服务端解析约定一致。
    private enum CodingKeys: String, CodingKey {
        case touchSpreadLow = "sl"
        case touchSpreadHigh = "sh"
        case touchIntervalTooRegular = "tr"
        case touchIntervalTooChaotic = "tc"
        case swipeTooLinear = "wl"
        case swipeTooCurvy = "wc"
        case motionTooStill = "ms"
        case touchMotionWeakCoupling = "wk"
    }

    /// 创建行为层信号；八个特征均需提供（无样本时内部标记 detected=false）。
    public init(
        touchSpreadLow: DetectionSignal<[String: String]>,
        touchSpreadHigh: DetectionSignal<[String: String]>,
        touchIntervalTooRegular: DetectionSignal<[String: String]>,
        touchIntervalTooChaotic: DetectionSignal<[String: String]>,
        swipeTooLinear: DetectionSignal<[String: String]>,
        swipeTooCurvy: DetectionSignal<[String: String]>,
        motionTooStill: DetectionSignal<[String: String]>,
        touchMotionWeakCoupling: DetectionSignal<[String: String]>
    ) {
        self.touchSpreadLow = touchSpreadLow
        self.touchSpreadHigh = touchSpreadHigh
        self.touchIntervalTooRegular = touchIntervalTooRegular
        self.touchIntervalTooChaotic = touchIntervalTooChaotic
        self.swipeTooLinear = swipeTooLinear
        self.swipeTooCurvy = swipeTooCurvy
        self.motionTooStill = motionTooStill
        self.touchMotionWeakCoupling = touchMotionWeakCoupling
    }
}

/// 时序层特征：24 小时窗口内的调用量、活跃小时覆盖、夜间占比与平均间隔。
public struct CloudPhoneTimeSignals: Codable, Sendable {
    /// 24h 事件量过高
    public var highVolume24h: DetectionSignal<[String: String]>
    /// 24h 活跃小时覆盖过宽（近乎全天候）
    public var wideHourCoverage24h: DetectionSignal<[String: String]>
    /// 24h 夜间活动占比过高
    public var nightActivityHigh24h: DetectionSignal<[String: String]>
    /// 24h 事件频率过高（平均间隔过短）
    public var highFrequency24h: DetectionSignal<[String: String]>

    // 短键：hv/wh/na/hf。
    private enum CodingKeys: String, CodingKey {
        case highVolume24h = "hv"
        case wideHourCoverage24h = "wh"
        case nightActivityHigh24h = "na"
        case highFrequency24h = "hf"
    }

    /// 创建时序层信号；无历史时由 builder 填入 detected=false 的低置信度对象。
    public init(
        highVolume24h: DetectionSignal<[String: String]>,
        wideHourCoverage24h: DetectionSignal<[String: String]>,
        nightActivityHigh24h: DetectionSignal<[String: String]>,
        highFrequency24h: DetectionSignal<[String: String]>
    ) {
        self.highVolume24h = highVolume24h
        self.wideHourCoverage24h = wideHourCoverage24h
        self.nightActivityHigh24h = nightActivityHigh24h
        self.highFrequency24h = highFrequency24h
    }
}

/// 从 `DeviceFingerprint`/`BehaviorSignals`/`TimePattern` 构建上报用本地特征。
/// 所有阈值写死以保证跨端一致；样本不足/无历史时返回 detected=false 的低置信度信号。
enum CloudPhoneLocalSignalsBuilder {
    /// 组装三组特征；`timePattern` 为 nil（无历史）时四个时序特征均标记为未检测。
    static func build(device: DeviceFingerprint, behavior: BehaviorSignals, timePattern: TimePattern?) -> CloudPhoneLocalSignals {
        let deviceSignals = CloudPhoneDeviceSignals(
            isSimulator: DetectionSignal(
                detected: device.isSimulator,
                method: "targetEnvironment",
                evidence: compactMap([
                    "is_simulator": "\(device.isSimulator)",
                    "hw.machine": device.hardwareMachine,
                ]),
                confidence: .strong
            ),
            oldDeviceModel: oldDeviceModelSignal(machine: device.hardwareMachine)
        )

        let behaviorSignals = CloudPhoneBehaviorSignals(
            touchSpreadLow: touchSpreadLowSignal(behavior: behavior),
            touchSpreadHigh: touchSpreadHighSignal(behavior: behavior),
            touchIntervalTooRegular: touchIntervalTooRegularSignal(behavior: behavior),
            touchIntervalTooChaotic: touchIntervalTooChaoticSignal(behavior: behavior),
            swipeTooLinear: swipeTooLinearSignal(behavior: behavior),
            swipeTooCurvy: swipeTooCurvySignal(behavior: behavior),
            motionTooStill: motionTooStillSignal(behavior: behavior),
            touchMotionWeakCoupling: touchMotionWeakCouplingSignal(behavior: behavior)
        )

        let timeSignals = CloudPhoneTimeSignals(
            highVolume24h: highVolume24hSignal(pattern: timePattern),
            wideHourCoverage24h: wideHourCoverage24hSignal(pattern: timePattern),
            nightActivityHigh24h: nightActivityHigh24hSignal(pattern: timePattern),
            highFrequency24h: highFrequency24hSignal(pattern: timePattern)
        )

        return CloudPhoneLocalSignals(device: deviceSignals, behavior: behaviorSignals, time: timeSignals)
    }

    /// 老机型启发式：iPhone 代数 ≤11（iPhone X/8 及更早）视为更可能来自设备农场。
    /// - 无法解析机型时返回 detected=false、confidence=.weak，并在 evidence 记录 note。
    private static func oldDeviceModelSignal(machine: String?) -> DetectionSignal<[String: String]>? {
        guard let machine else { return nil }
        guard let family = parseIPhoneFamily(machine) else {
            return DetectionSignal(
                detected: false,
                method: "hw.machine_family",
                evidence: ["machine": machine, "note": "unparsed"],
                confidence: .weak
            )
        }

        // 云手机农场的经验特征：新机型成本高，旧机型占比更高。
        // iPhone10.* 对应 iPhone X/8 时代，目前把 ≤11 视为“老机型”。
        let detected = family <= 11
        return DetectionSignal(
            detected: detected,
            method: "hw.machine_family",
            evidence: [
                "machine": machine,
                "family": "\(family)",
                "threshold_family_le": "11",
            ],
            confidence: detected ? .medium : .weak
        )
    }

    /// 从 "iPhone13,2" 这类 hw.machine 提取主代数（13）；非 iPhone 前缀返回 nil。
    private static func parseIPhoneFamily(_ machine: String) -> Int? {
        guard machine.hasPrefix("iPhone") else { return nil }
        let rest = machine.dropFirst("iPhone".count)
        var digits = ""
        for ch in rest {
            if ch.isNumber { digits.append(ch) } else { break }
        }
        return Int(digits)
    }

    /// 坐标离散度低于 2.0 且点击样本 ≥6：落点过于集中，像脚本固定坐标。
    private static func touchSpreadLowSignal(behavior: BehaviorSignals) -> DetectionSignal<[String: String]> {
        // 至少 6 次点击才统计，避免单点噪声；阈值 2.0 为体验校准值。
        let minTaps = 6
        let threshold = 2.0
        let spread = behavior.touch.coordinateSpread
        let detected = (spread ?? .greatestFiniteMagnitude) < threshold && behavior.touch.tapCount >= minTaps
        return DetectionSignal(
            detected: detected,
            method: "touch_spread",
            evidence: compactMap([
                "spread": spread.map(format),
                "tapCount": "\(behavior.touch.tapCount)",
                "threshold_lt": "\(threshold)",
                "minTapCount": "\(minTaps)",
            ]),
            confidence: .medium
        )
    }

    /// 坐标离散度高于 10.0 且点击样本 ≥6：落点过于发散，像随机注入。
    private static func touchSpreadHighSignal(behavior: BehaviorSignals) -> DetectionSignal<[String: String]> {
        let minTaps = 6
        let threshold = 10.0
        let spread = behavior.touch.coordinateSpread
        let detected = (spread ?? 0) > threshold && behavior.touch.tapCount >= minTaps
        return DetectionSignal(
            detected: detected,
            method: "touch_spread",
            evidence: compactMap([
                "spread": spread.map(format),
                "tapCount": "\(behavior.touch.tapCount)",
                "threshold_gt": "\(threshold)",
                "minTapCount": "\(minTaps)",
            ]),
            confidence: .weak
        )
    }

    /// 点击间隔 CV 低于 0.2 且样本 ≥6：节奏过于机械。
    private static func touchIntervalTooRegularSignal(behavior: BehaviorSignals) -> DetectionSignal<[String: String]> {
        let minTaps = 6
        let threshold = 0.2
        let cv = behavior.touch.intervalCV
        let detected = (cv ?? .greatestFiniteMagnitude) < threshold && behavior.touch.tapCount >= minTaps
        return DetectionSignal(
            detected: detected,
            method: "tap_interval_cv",
            evidence: compactMap([
                "cv": cv.map(format),
                "tapCount": "\(behavior.touch.tapCount)",
                "threshold_lt": "\(threshold)",
                "minTapCount": "\(minTaps)",
            ]),
            confidence: .medium
        )
    }

    /// 点击间隔 CV 高于 0.6 且样本 ≥6：节奏不符合人类操作。
    private static func touchIntervalTooChaoticSignal(behavior: BehaviorSignals) -> DetectionSignal<[String: String]> {
        let minTaps = 6
        let threshold = 0.6
        let cv = behavior.touch.intervalCV
        let detected = (cv ?? 0) > threshold && behavior.touch.tapCount >= minTaps
        return DetectionSignal(
            detected: detected,
            method: "tap_interval_cv",
            evidence: compactMap([
                "cv": cv.map(format),
                "tapCount": "\(behavior.touch.tapCount)",
                "threshold_gt": "\(threshold)",
                "minTapCount": "\(minTaps)",
            ]),
            confidence: .weak
        )
    }

    /// 滑动平均线性度高于 0.98 且样本 ≥3：轨迹近似直线插值。
    private static func swipeTooLinearSignal(behavior: BehaviorSignals) -> DetectionSignal<[String: String]> {
        let minSwipes = 3
        let threshold = 0.98
        let lin = behavior.touch.averageLinearity
        let detected = (lin ?? 0) > threshold && behavior.touch.swipeCount >= minSwipes
        return DetectionSignal(
            detected: detected,
            method: "swipe_linearity",
            evidence: compactMap([
                "avgLinearity": lin.map(format),
                "swipeCount": "\(behavior.touch.swipeCount)",
                "threshold_gt": "\(threshold)",
                "minSwipeCount": "\(minSwipes)",
            ]),
            confidence: .medium
        )
    }

    /// 滑动平均线性度低于 0.90 且样本 ≥3：轨迹过于弯曲或由曲线合成。
    private static func swipeTooCurvySignal(behavior: BehaviorSignals) -> DetectionSignal<[String: String]> {
        let minSwipes = 3
        let threshold = 0.90
        let lin = behavior.touch.averageLinearity
        let detected = (lin ?? 1) < threshold && behavior.touch.swipeCount >= minSwipes
        return DetectionSignal(
            detected: detected,
            method: "swipe_linearity",
            evidence: compactMap([
                "avgLinearity": lin.map(format),
                "swipeCount": "\(behavior.touch.swipeCount)",
                "threshold_lt": "\(threshold)",
                "minSwipeCount": "\(minSwipes)",
            ]),
            confidence: .weak
        )
    }

    /// 静止率高于 0.98 且操作 ≥10：设备几乎不动，常见于真机托管/云手机。
    private static func motionTooStillSignal(behavior: BehaviorSignals) -> DetectionSignal<[String: String]> {
        let minActions = 10
        let threshold = 0.98
        let still = behavior.motion.stillnessRatio
        let actions = behavior.actionCount
        let detected = (still ?? 0) > threshold && actions >= minActions
        return DetectionSignal(
            detected: detected,
            method: "motion_stillness",
            evidence: compactMap([
                "stillnessRatio": still.map(format),
                "actionCount": "\(actions)",
                "threshold_gt": "\(threshold)",
                "minActionCount": "\(minActions)",
            ]),
            confidence: .medium
        )
    }

    /// 触摸-运动相关性低于 0.10、操作 ≥10 且静止率高于 0.95：有触摸输入但传感器无响应。
    private static func touchMotionWeakCouplingSignal(behavior: BehaviorSignals) -> DetectionSignal<[String: String]> {
        let minActions = 10
        let minStillness = 0.95
        let threshold = 0.10
        let corr = behavior.touchMotionCorrelation
        let still = behavior.motion.stillnessRatio
        let actions = behavior.actionCount
        // 三个条件同时成立才命中，降低“用户坐着操作”造成的误报。
        let detected =
            (corr ?? .greatestFiniteMagnitude) < threshold &&
            actions >= minActions &&
            (still ?? 0) > minStillness
        return DetectionSignal(
            detected: detected,
            method: "touch_motion_correlation",
            evidence: compactMap([
                "corr": corr.map(format),
                "stillnessRatio": still.map(format),
                "actionCount": "\(actions)",
                "threshold_lt": "\(threshold)",
                "minStillness_gt": "\(minStillness)",
                "minActionCount": "\(minActions)",
            ]),
            confidence: .medium
        )
    }

    /// 24h 事件量 ≥200 命中；≥500 提升为 strong。
    private static func highVolume24hSignal(pattern: TimePattern?) -> DetectionSignal<[String: String]> {
        guard let pattern else {
            return DetectionSignal(detected: false, method: "history_24h", evidence: ["note": "no_history"], confidence: .weak)
        }
        // 200/500 是分档阈值：普通用户远低于 200，脚本/农场通常数百以上。
        let high = 500
        let medium = 200
        let detected = pattern.events24h >= medium
        let confidence: SignalConfidence = pattern.events24h >= high ? .strong : (detected ? .medium : .weak)
        return DetectionSignal(
            detected: detected,
            method: "history_24h",
            evidence: [
                "events24h": "\(pattern.events24h)",
                "threshold_medium_ge": "\(medium)",
                "threshold_high_ge": "\(high)",
            ],
            confidence: confidence
        )
    }

    /// 活跃小时覆盖 ≥18 且事件 ≥80：近乎全天候活动，不符合个人设备作息。
    private static func wideHourCoverage24hSignal(pattern: TimePattern?) -> DetectionSignal<[String: String]> {
        guard let pattern else {
            return DetectionSignal(detected: false, method: "history_24h", evidence: ["note": "no_history"], confidence: .weak)
        }
        let minEvents = 80
        let threshold = 18
        let detected = pattern.uniqueHours24h >= threshold && pattern.events24h >= minEvents
        return DetectionSignal(
            detected: detected,
            method: "history_24h",
            evidence: [
                "uniqueHours24h": "\(pattern.uniqueHours24h)",
                "events24h": "\(pattern.events24h)",
                "threshold_uniqueHours_ge": "\(threshold)",
                "minEvents_ge": "\(minEvents)",
            ],
            confidence: detected ? .medium : .weak
        )
    }

    /// 夜间事件占比高于 0.4 且事件 ≥80：夜间活动异常，常见于跨时区托管。
    private static func nightActivityHigh24hSignal(pattern: TimePattern?) -> DetectionSignal<[String: String]> {
        guard let pattern else {
            return DetectionSignal(detected: false, method: "history_24h", evidence: ["note": "no_history"], confidence: .weak)
        }
        let minEvents = 80
        let threshold = 0.4
        let night = pattern.nightRatio24h
        let detected = (night ?? 0) > threshold && pattern.events24h >= minEvents
        return DetectionSignal(
            detected: detected,
            method: "history_24h",
            evidence: compactMap([
                "nightRatio24h": night.map(format),
                "events24h": "\(pattern.events24h)",
                "threshold_gt": "\(threshold)",
                "minEvents_ge": "\(minEvents)",
            ]),
            confidence: detected ? .medium : .weak
        )
    }

    /// 平均事件间隔低于 8 秒且事件 ≥80：调用频率过高，像脚本批量操作。
    private static func highFrequency24hSignal(pattern: TimePattern?) -> DetectionSignal<[String: String]> {
        guard let pattern else {
            return DetectionSignal(detected: false, method: "history_24h", evidence: ["note": "no_history"], confidence: .weak)
        }
        let minEvents = 80
        let threshold = 8.0
        let avg = pattern.averageIntervalSeconds24h
        let detected = (avg ?? .greatestFiniteMagnitude) < threshold && pattern.events24h >= minEvents
        return DetectionSignal(
            detected: detected,
            method: "history_24h",
            evidence: compactMap([
                "averageIntervalSeconds24h": avg.map(format),
                "events24h": "\(pattern.events24h)",
                "threshold_lt": "\(threshold)",
                "minEvents_ge": "\(minEvents)",
            ]),
            confidence: detected ? .medium : .weak
        )
    }

    /// 过滤 nil 值，保证 evidence 只包含有效字段。
    private static func compactMap(_ kv: [String: String?]) -> [String: String] {
        var out: [String: String] = [:]
        for (k, v) in kv {
            guard let v else { continue }
            out[k] = v
        }
        return out
    }

    /// 统一保留 4 位小数；NaN/Inf 原样输出，便于服务端识别异常值。
    private static func format(_ d: Double) -> String {
        if d.isNaN || d.isInfinite { return "\(d)" }
        return String(format: "%.4f", d)
    }
}

