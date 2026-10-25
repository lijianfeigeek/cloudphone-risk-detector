// 文件系统检测器：通过路径探测、双路径 syscall 校验与系统配置文件检查发现越狱痕迹。
// 位于越狱检测管道中 `enableFileDetect` 分支，也是证据量最大的检测器。
// 关键安全不变量：所有路径检查保持确定性（同一设备两次评估结果一致），且绕过/追踪证据优先于“文件不存在”。
import CRiskCore
import Darwin
import Foundation

/// 检查越狱相关文件、目录、可写沙盒外路径与系统配置异常。
/// 检测什么：Cydia 等越狱路径、`/private/preboot` 下的 RootHide 引导、沙盒外可写、hosts/fstab/APT 篡改。
/// 命中后产生 `file:*`、`write:*`、`roothide:*`、`sysfiles:*`、`dbi_stalker_traced:*` 等信号，分值 6–35。
/// 误报风险：越狱取证工具残留、企业配置描述文件可能触发部分系统文件信号；模拟器上整体返回不可用标记。
struct FileDetector: Detector {

    /// 执行文件系统综合检测。
    /// - Returns: 未做总分封顶的累计结果；模拟器返回 `unavailable_simulator` 标记。
    /// - Note: 单个路径探测失败不会抛错，只会减少证据；syscall 被致盲则由金丝雀探针单独告警。
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        // 模拟器文件系统不是真实 iOS 沙盒，检测结论无意义，显式标记为不可用。
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []
        var fileExistsMismatchCount = 0
        var lowLevelMismatchCount = 0

        // [4.4.5] 金丝雀探针：在检查越狱文件前执行，若 syscall 被致盲则直接告警
        if let canaryResult = CanaryFileProbe.probe() {
            score += canaryResult.score
            methods.append(contentsOf: canaryResult.methods)
        }

        var suspiciousPermissionScore: Double = 0

        // 沙盒视图隔离（Bind Mount 平行宇宙）防范
        // 当前平台实现固定返回 false，保留调用点以便未来接入挂载表比对。
        if detectSandboxMountIsolation() {
            score += 30
            methods.append("sandbox_mount_isolation_detected")
            Logger.log("jailbreak.file.hit: sandbox_mount_isolation_detected (+30)")
        }

        // ── Anti-Stalker: 确定性全量检查 + 确定性噪声穿插 ─────────────
        // Frida Stalker 可以追踪所有 SVC #0x80 syscall 并一次性提取完整路径列表。
        // 旧实现用 `Int.random(60...70%)` 抽样 + `Bool.random()` 噪声 + 分数补偿
        // 因子 N/X（上限 4.0），导致同一设备两次评估的分数/命中集合不一致。
        // 改为确定性全量检查：遍历全部可疑路径，分数为各路径分数之和，
        // 无补偿因子；噪声 access() 以固定节拍（每 3 次真实检查穿插 1 次）
        // 按声明顺序循环穿插，仍干扰 Stalker 的路径归因，但不影响结果。
        // 顺序固定：`JailbreakEngine` 对 methods 去重排序，最终结果与
        // 检查顺序无关，同一设备两次评估一致。

        let allSuspicious = ObfuscatedConstants.jailbreakSuspiciousPaths
        let suspiciousPaths = allSuspicious

        let noisePaths = ObfuscatedConstants.pathNoisePaths
        var noiseIdx = 0
        var suspiciousPathScore: Double = 0

        for (index, item) in suspiciousPaths.enumerated() {
            // 确定性噪声穿插：每 3 次真实检查前做 1 次噪声 access()。
            // 噪声路径按固定顺序循环，既扰乱 Stalker 归因又保持可复现。
            if index % 3 == 0, !noisePaths.isEmpty {
                _ = SVCDirectCall.secureAccess(noisePaths[noiseIdx % noisePaths.count])
                noiseIdx += 1
            }

            // [4.4.6] EPERM 异常化：path 理应 ENOENT 却返回 EPERM/EACCES (iOS 16+)
            // 该现象可能是内核层沙盒策略被篡改，单独累计但设有上限，防止刷分。
            let (pathExists, pathErrno) = pathAccessWithErrno(item.path)
            if !pathExists && ExpectedBaseline.epermOnProtectedPathIsSuspicious && ExpectedBaseline.isPermissionDeniedErrno(pathErrno) {
                if suspiciousPermissionScore < 75 {
                    suspiciousPermissionScore = min(suspiciousPermissionScore + 15, 75)
                    methods.append("suspicious_permission_denied:\(item.path)")
                }
            }

            let exists = existsAnyWay(item.path)
            if exists.exists {
                suspiciousPathScore += item.score
                methods.append("file:\(item.path)")
                Logger.log("jailbreak.file.hit: \(item.path) (+\(item.score))")
            }

            // 不同探测原语对同一路径给出矛盾结果，说明至少一条路径被 hook。
            if exists.pathProbeMismatch, fileExistsMismatchCount < 3 {
                fileExistsMismatchCount += 1
                suspiciousPathScore += 8
                methods.append("hook:fileExists_mismatch:\(item.path)")
                Logger.log("jailbreak.file.hit: fileExists_mismatch path=\(item.path) (+8)")
            }

            // 高层 API 与底层 syscall 结果不一致，属于更强的 hook 证据。
            if exists.lowLevelPrimitiveMismatch, lowLevelMismatchCount < 4 {
                lowLevelMismatchCount += 1
                suspiciousPathScore += 12
                methods.append("hook:file_primitive_mismatch:\(item.path)")
                Logger.log("jailbreak.file.hit: file_primitive_mismatch path=\(item.path) (+12)")
            }

            // syscall 被短接（short-circuit）通常意味着检测链被主动绕过。
            if exists.bypassed {
                suspiciousPathScore += 20
                methods.append("syscall_bypassed:\(item.path)")
                Logger.log("jailbreak.file.hit: syscall_bypassed path=\(item.path) (+20)")
            }

            // 被 DBI（如 Frida Stalker）追踪属于高置信度对抗行为。
            if exists.traced {
                suspiciousPathScore += 25
                methods.append("dbi_stalker_traced:\(item.path)")
                Logger.log("jailbreak.file.hit: dbi_stalker_traced path=\(item.path) (+25)")
            }
        }

        // 全量检查：分数为各路径分数之和，无抽样补偿因子。
        score += suspiciousPathScore

        if suspiciousPermissionScore > 0 {
            score += suspiciousPermissionScore
            Logger.log("jailbreak.file.hit: suspicious_permission_denied (+\(Int(suspiciousPermissionScore)))")
        }

        // ── Critical paths: 全部检查，确定性顺序 + 确定性噪声穿插 ────
        // 关键路径只做双路径一致性校验，不直接按“文件存在”计分，降低误报。
        let criticalPaths = ObfuscatedConstants.jailbreakCriticalPaths
        let critNoisePaths = ObfuscatedConstants.pathNoisePaths
        var critNoiseIdx = 0
        var mismatchCount = 0
        var bypassCount = 0
        var tracedCount = 0
        for (index, path) in criticalPaths.enumerated() {
            if index % 3 == 0, !critNoisePaths.isEmpty {
                _ = SVCDirectCall.secureAccess(critNoisePaths[critNoiseIdx % critNoisePaths.count])
                critNoiseIdx += 1
            }

            let (_, tampered, bypassed, traced, _) = DualPathValidator.validateFileStat(path: path)
            if tampered {
                mismatchCount += 1
                // 上报时只保留路径末段，避免泄露完整关键路径清单。
                methods.append("dual_path_mismatch:\(path.components(separatedBy: "/").last ?? path)")
                Logger.log("jailbreak.file.hit: dual_path_mismatch path=\(path) (+20)")
            }
            if bypassed {
                bypassCount += 1
                methods.append("syscall_bypassed:\(path.components(separatedBy: "/").last ?? path)")
                Logger.log("jailbreak.file.hit: syscall_bypassed path=\(path) (+20)")
            }
            if traced {
                tracedCount += 1
                methods.append("dbi_stalker_traced:\(path.components(separatedBy: "/").last ?? path)")
                Logger.log("jailbreak.file.hit: dbi_stalker_traced path=\(path) (+25)")
            }
        }
        if mismatchCount > 0 {
            score += Double(mismatchCount) * 20
        }
        if bypassCount > 0 {
            score += Double(bypassCount) * 20
        }
        // 追踪证据最多按 3 条计分，避免长路径列表导致分数无限膨胀。
        if tracedCount > 0 {
            score += Double(min(tracedCount, 3)) * 25
        }

        // 系统配置 / 完整性信号。
        let sys = try SystemConfigDetector().detect()
        score += sys.score
        methods.append(contentsOf: sys.methods)

        // 直接遍历 /Applications 目录，绕过可能被 hook 的 NSFileManager。
        if listApplicationsShowsJailbreakApps() {
            score += 15
            methods.append("dir:/Applications")
            Logger.log("jailbreak.file.hit: /Applications contains jailbreak apps (+15)")
        }

        // 沙盒外可写是强证据：真实未越狱设备无法写入 /private。
        if canWriteOutsideSandbox() {
            score += 35
            methods.append("write:/private/jb_test")
            Logger.log("jailbreak.file.hit: write_outside_sandbox (+35)")
        }

        // RootHide 等新一代越狱会将引导目录藏在 preboot 的随机 UUID 下。
        if hasPrebootJBDirectory() {
            score += 20
            methods.append("file:/private/preboot/*/jb")
            Logger.log("jailbreak.file.hit: preboot_jb (+20)")
        }

        let roothideResult = detectRootHideBootstrap()
        score += roothideResult.score
        methods.append(contentsOf: roothideResult.methods)

        let roothideEnvResult = detectRootHideEnvVars()
        score += roothideEnvResult.score
        methods.append(contentsOf: roothideEnvResult.methods)

        return DetectorResult(score: score, methods: methods)
#endif
    }

    /// access(F_OK) 并返回 errno（用于 [4.4.6] EPERM 异常化）
    /// - Parameter path: 待探测路径。
    /// - Returns: `(是否存在, errno)`；底层 SVC 调用不可用时返回 `(false, EINVAL)`，
    ///   调用方会把 EINVAL 当作普通失败而非权限异常。
    private func pathAccessWithErrno(_ path: String) -> (exists: Bool, errno: Int32) {
        if let result = SVCDirectCall.standardAccessErrnoMasked(path) {
            return result
        }
        return (false, EINVAL)
    }

    /// 单个路径的多原语探测结果。
    private struct ExistenceResult {
        /// 任一探测原语认为路径存在。
        var exists: Bool
        /// 不同原语对同一路径给出矛盾结论（提示 hook）。
        var pathProbeMismatch: Bool
        /// 高层 API 与底层 syscall 结论不一致（更强的 hook 证据）。
        var lowLevelPrimitiveMismatch: Bool
        /// syscall 被短接绕过。
        var bypassed: Bool
        /// 调用处于 DBI/Stalker 追踪之下。
        var traced: Bool
    }

    /// 探测沙盒挂载隔离（Bind Mount 平行宇宙）。
    /// - Returns: 当前实现固定 `false`；保留接口用于后续接入挂载视图比对。
    private func detectSandboxMountIsolation() -> Bool {
        return false
    }

    /// 综合多种原语判断路径是否存在，并汇总对抗性证据。
    /// - Parameter path: 待探测路径。
    /// - Returns: `ExistenceResult`；所有探测均失败时 `exists == false`。
    private func existsAnyWay(_ path: String) -> ExistenceResult {
        let standardSnapshot = SVCDirectCall.standardPathProbeSnapshot(path)
        let low = DualPathValidator.validateFileStat(path: path)
        let standardValues = standardSnapshot.availableValues
        // 同一快照内同时出现 true 与 false，说明标准库探测路径之间互相矛盾。
        let mismatch = standardValues.contains(true) && standardValues.contains(false)
        return ExistenceResult(
            exists: standardSnapshot.existsAny || low.exists,
            pathProbeMismatch: mismatch,
            lowLevelPrimitiveMismatch: low.tampered,
            bypassed: low.bypassed,
            traced: low.traced
        )
    }

    /// 使用底层双路径校验判断路径是否存在。
    /// - Parameter path: 待探测路径。
    /// - Returns: 底层视角的存在性；异常时按不存在处理。
    private func existsLowLevel(_ path: String) -> Bool {
        DualPathValidator.validateFileStat(path: path).exists
    }

    /// 枚举 `/Applications` 目录，查找越狱应用目录名。
    /// - Returns: 命中任一可疑应用名即 `true`；模拟器或目录不可读时 `false`。
    private func listApplicationsShowsJailbreakApps() -> Bool {
#if targetEnvironment(simulator)
        return false
#else
        guard let dir = opendir("/Applications") else { return false }
        defer { closedir(dir) }

        let needles = ObfuscatedConstants.listApplicationsNeedles
        while let ent = readdir(dir) {
            var nameBuf = ent.pointee.d_name
            // d_name 是定长 C 数组，用 strnlen 控制最大读取长度，避免越界。
            let name = withUnsafePointer(to: &nameBuf.0) { ptr in
                let len = strnlen(ptr, 256)
                return (String(data: Data(bytes: ptr, count: len), encoding: .utf8) ?? "").lowercased()
            }
            if needles.contains(where: { name.contains($0) }) {
                return true
            }
        }
        return false
#endif
    }

    /// 尝试在沙盒外写入临时文件，验证是否具备越狱级文件系统权限。
    /// - Returns: 写入并成功删除返回 `true`；模拟器固定 `false`，写入失败也返回 `false`。
    private func canWriteOutsideSandbox() -> Bool {
#if targetEnvironment(simulator)
        // 模拟器不是真实 iOS 沙盒；该检查无意义且可能误报。
        return false
#else
        // 使用随机文件名降低被预先埋点拦截的概率；写入后立即删除，避免留下痕迹。
        let testPath = "/private/jb_test_\(UUID().uuidString)"
        do {
            try "1".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true
        } catch {
            return false
        }
#endif
    }

    /// 检查 `/private/preboot` 下是否存在典型 RootHide 的 `jb` 目录。
    /// - Returns: 找到返回 `true`；目录不可读或只扫描有限条目时返回 `false`。
    private func hasPrebootJBDirectory() -> Bool {
#if targetEnvironment(simulator)
        return false
#else
        let root = "/private/preboot"
        guard DualPathValidator.validateFileStat(path: root).exists else { return false }
        guard let dir = opendir(root) else { return false }
        defer { closedir(dir) }

        // 限制扫描条目数，避免在异常目录结构上长时间阻塞检测线程。
        var scanned = 0
        while scanned < 10, let entry = readdir(dir) {
            var nameBuf = entry.pointee.d_name
            let name = withUnsafePointer(to: &nameBuf.0) { ptr in
                let len = strnlen(ptr, Int(MAXPATHLEN))
                return (String(data: Data(bytes: ptr, count: len), encoding: .utf8) ?? "")
            }
            guard name != "." && name != ".." else { continue }

            let candidate = "\(root)/\(name)/jb"
            if isDirectoryPath(candidate) {
                return true
            }
            scanned += 1
        }
        return false
#endif
    }

    /// 扫描 preboot 下隐藏的 RootHide 引导目录结构。
    /// 判定依据：目录名包含 `procursus`/`roothide`，或同时具备 3 个以上引导标记目录。
    /// - Returns: 命中即 +30/+25 分并提前返回；未命中返回零分结果。
    private func detectRootHideBootstrap() -> DetectorResult {
#if targetEnvironment(simulator)
        return .empty
#else
        var score: Double = 0
        var methods: [String] = []

        let root = "/private/preboot"
        guard DualPathValidator.validateFileStat(path: root).exists else {
            return DetectorResult(score: score, methods: methods)
        }
        guard let dir = opendir(root) else {
            return DetectorResult(score: score, methods: methods)
        }
        defer { closedir(dir) }

        // 正常 bootstrap 应同时具备这些顶层目录；命中越多越像隐藏引导。
        let bootstrapMarkers = ["usr", "Library", "bin", "etc", "var"]

        var scanned = 0
        while scanned < 10, let entry = readdir(dir) {
            var nameBuf = entry.pointee.d_name
            let name = withUnsafePointer(to: &nameBuf.0) { ptr in
                let len = strnlen(ptr, Int(MAXPATHLEN))
                return (String(data: Data(bytes: ptr, count: len), encoding: .utf8) ?? "")
            }
            guard name != "." && name != ".." else { continue }

            let uuidDir = "\(root)/\(name)"
            guard isDirectoryPath(uuidDir) else {
                scanned += 1
                continue
            }
            guard let subDir = opendir(uuidDir) else {
                scanned += 1
                continue
            }
            defer { closedir(subDir) }

            var subScanned = 0
            while subScanned < 20, let subEntry = readdir(subDir) {
                var subNameBuf = subEntry.pointee.d_name
                let subName = withUnsafePointer(to: &subNameBuf.0) { ptr in
                    let len = strnlen(ptr, Int(MAXPATHLEN))
                    return (String(data: Data(bytes: ptr, count: len), encoding: .utf8) ?? "")
                }
                guard subName != "." && subName != ".." else { continue }

                let candidateBase = "\(uuidDir)/\(subName)"
                guard isDirectoryPath(candidateBase) else {
                    subScanned += 1
                    continue
                }

                if subName == "jb" { subScanned += 1; continue }

                let lowerSub = subName.lowercased()
                // 明确的 RootHide/Procursus 命名属于最高置信度证据。
                if lowerSub.contains("procursus") || lowerSub.contains("roothide") {
                    score += 30
                    methods.append("roothide:preboot_bootstrap:\(subName)")
                    Logger.log("jailbreak.file.hit: roothide preboot bootstrap \(subName) (+30)")
                    return DetectorResult(score: score, methods: methods)
                }

                // 目录名被随机化时，退化为结构特征匹配：标记目录数量达到 3 个即命中。
                var markerHits = 0
                for marker in bootstrapMarkers {
                    let markerPath = "\(candidateBase)/\(marker)"
                    if isDirectoryPath(markerPath) {
                        markerHits += 1
                    }
                }
                if markerHits >= 3 {
                    score += 25
                    methods.append("roothide:preboot_hidden_bootstrap:\(subName)")
                    Logger.log("jailbreak.file.hit: roothide hidden bootstrap structure \(subName) markers=\(markerHits) (+25)")
                    return DetectorResult(score: score, methods: methods)
                }

                subScanned += 1
            }
            scanned += 1
        }

        return DetectorResult(score: score, methods: methods)
#endif
    }

    /// 检查 RootHide 相关环境变量是否被设置。
    /// - Returns: 每个命中变量按其权重累加；模拟器返回空结果。
    private func detectRootHideEnvVars() -> DetectorResult {
#if targetEnvironment(simulator)
        return .empty
#else
        var score: Double = 0
        var methods: [String] = []

        for item in ObfuscatedConstants.roothideEnvVars {
            // 值为空串不算命中，避免仅设置空变量造成误报。
            if let val = getenv(item.name), strlen(val) > 0 {
                score += item.score
                methods.append("roothide:env:\(item.name)")
                Logger.log("jailbreak.file.hit: roothide env \(item.name) (+\(item.score))")
            }
        }

        return DetectorResult(score: score, methods: methods)
#endif
    }

    /// 判断路径是否为目录。
    /// - Parameter path: 待判断路径。
    /// - Returns: `stat` 成功且文件类型为 `S_IFDIR` 时返回 `true`。
    /// - Note: 使用 `cprisk_stat_direct` 绕过可能被 hook 的 libc `stat`。
    private func isDirectoryPath(_ path: String) -> Bool {
        path.withCString { cPath in
            var sb = stat()
            guard cprisk_stat_direct(cPath, &sb, nil) == 0 else { return false }
            return (sb.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR)
        }
    }
}

/// 系统配置完整性检测：检查系统文件可读性、hosts/fstab/APT 配置与符号链接是否被篡改。
/// 这些文件在未越狱设备上通常不可写；异常内容或可读性变化提示越狱工具已修改系统。
private struct SystemConfigDetector: Detector {
    /// 执行系统配置检查。
    /// - Returns: 累计分数封顶 60 的检测结果；模拟器返回空结果。
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return .empty
#else
        var score: Double = 0
        var methods: [String] = []

        if checkSystemFileReadability() {
            score += 6
            methods.append("sysfiles:readable")
            Logger.log("jailbreak.sysfiles.hit: readable (+6)")
        }

        if checkHostsFile() {
            score += 18
            methods.append("sysfiles:hosts")
            Logger.log("jailbreak.sysfiles.hit: hosts (+18)")
        }

        if checkFstabConfiguration() {
            score += 18
            methods.append("sysfiles:fstab")
            Logger.log("jailbreak.sysfiles.hit: fstab (+18)")
        }

        if checkAPTConfiguration() {
            score += 22
            methods.append("sysfiles:apt")
            Logger.log("jailbreak.sysfiles.hit: apt (+22)")
        }

        if checkSymlinkIntegrity() {
            score += 15
            methods.append("sysfiles:symlink")
            Logger.log("jailbreak.sysfiles.hit: symlink_integrity (+15)")
        }

        return DetectorResult(score: min(score, 60), methods: methods)
#endif
    }

    /// 检查系统配置文件是否意外可读/存在。
    /// - Returns: 任一配置路径存在或内容非空即返回 `true`。
    private func checkSystemFileReadability() -> Bool {
        let paths = ObfuscatedConstants.systemConfigPaths

        for path in paths {
            if DualPathValidator.validateFileStat(path: path).exists {
                return true
            }
            if let content = try? String(contentsOfFile: path, encoding: .utf8), !content.isEmpty {
                return true
            }
        }
        return false
    }

    /// 检查 `/etc/hosts` 是否包含越狱源或明显被改写（体积异常）。
    /// - Returns: 命中可疑条目或文件大于 2048 字节时返回 `true`。
    private func checkHostsFile() -> Bool {
        let hostsPath = ObfuscatedConstants.hostsPath
        guard let hosts = try? String(contentsOfFile: hostsPath, encoding: .utf8), !hosts.isEmpty else {
            return false
        }

        let suspiciousEntries = ObfuscatedConstants.suspiciousHostsEntries

        for entry in suspiciousEntries {
            if hosts.range(of: entry, options: .caseInsensitive) != nil {
                return true
            }
        }

        // 启发式：被修改过的 hosts 往往体积明显变大。
        if hosts.utf8.count > 2048 {
            return true
        }
        return false
    }

    /// 检查 `/etc/fstab` 是否存在越狱挂载项或行数异常。
    /// - Returns: 命中可疑挂载模式，或有效配置行数超过 5 时返回 `true`。
    private func checkFstabConfiguration() -> Bool {
        let fstabPath = ObfuscatedConstants.fstabPath
        guard let fstab = try? String(contentsOfFile: fstabPath, encoding: .utf8), !fstab.isEmpty else {
            return false
        }

        let suspiciousMounts = ObfuscatedConstants.suspiciousFstabMounts

        for pattern in suspiciousMounts where fstab.contains(pattern) {
            return true
        }

        // 正常 fstab 有效行很少；行数异常提示被追加了自定义挂载项。
        let lines = fstab.components(separatedBy: "\n")
        var validLineCount = 0
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty && !trimmed.hasPrefix("#") { validLineCount += 1 }
        }
        return validLineCount > 5
    }

    /// 检查 APT/dpkg 配置是否存在或被指向越狱源。
    /// - Returns: 任一 APT 路径存在，或 sources.list 命中可疑源时返回 `true`。
    private func checkAPTConfiguration() -> Bool {
        for path in ObfuscatedConstants.aptPaths {
            if DualPathValidator.validateFileStat(path: path).exists { return true }
        }

        let sourcesPath = ObfuscatedConstants.aptSourcesListPath
        if let sourcesList = try? String(contentsOfFile: sourcesPath, encoding: .utf8), !sourcesList.isEmpty {
            let needles = ObfuscatedConstants.aptRepoNeedles
            if needles.contains(where: { sourcesList.range(of: $0, options: .caseInsensitive) != nil }) {
                return true
            }
        }
        return false
    }

    /// 校验 `/etc`、`/var`、`/tmp` 的符号链接目标是否被改写。
    /// - Returns: 任一链接目标与系统预期不一致时返回 `true`；链接不可读则跳过。
    private func checkSymlinkIntegrity() -> Bool {
        // 未越狱 iOS 上这些路径应指向 /private 下的真实目录。
        let expected: [String: String] = [
            "/etc": "/private/etc",
            "/var": "/private/var",
            "/tmp": "/private/tmp",
        ]

        for (path, expectedTarget) in expected {
            guard let actual = readlinkString(path) else { continue }
            if actual != expectedTarget {
                return true
            }
        }
        return false
    }

    /// 读取符号链接目标。
    /// - Parameter path: 符号链接路径。
    /// - Returns: 目标字符串；读取失败或长度非正时返回 `nil`。
    private func readlinkString(_ path: String) -> String? {
        var buf = [CChar](repeating: 0, count: Int(PATH_MAX))
        let len = readlink(path, &buf, Int(PATH_MAX) - 1)
        if len <= 0 { return nil }
        // 手动补 NUL 终止符，保证 String(cString:) 不会读过缓冲区。
        buf[len] = 0
        return String(cString: buf)
    }
}
