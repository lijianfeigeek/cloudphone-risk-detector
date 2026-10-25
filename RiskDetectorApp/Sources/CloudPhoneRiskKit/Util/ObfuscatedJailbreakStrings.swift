// 越狱相关字符串表：路径、进程名、应用名、环境变量与系统配置特征。
// 与 ObfuscatedStrings.swift 同属混淆常量，全部以 Base64 存储，运行时经 b64() 解码。
// 单独拆文件只为按检测场景组织条目；score 是该证据的启发式计分权重。
import Foundation

/// 越狱检测特征集合的扩充。
/// - 二元组 `(path/env, score)` 中的 score 由检测器汇总后与阈值比较，调权会直接影响判决。
/// - 所有条目都惰性解码，源码与二进制中不出现明文路径或变量名。
extension ObfuscatedConstants {

    // MARK: - 可疑文件路径（含权重）

    /// 常见越狱应用 / 工具路径及权重：越专用的工具给分越高（10–30）。
    static var jailbreakSuspiciousPaths: [(path: String, score: Double)] {
        [
            (b64("L0FwcGxpY2F0aW9ucy9DeWRpYS5hcHA="), 30),
            (b64("L0FwcGxpY2F0aW9ucy9TaWxlby5hcHA="), 30),
            (b64("L0FwcGxpY2F0aW9ucy9aZWJyYS5hcHA="), 25),
            (b64("L0FwcGxpY2F0aW9ucy9JbnN0YWxsZXIuYXBw"), 20),
            (b64("L0FwcGxpY2F0aW9ucy9GaWx6YS5hcHA="), 20),
            (b64("L0FwcGxpY2F0aW9ucy9pRmlsZS5hcHA="), 15),
            (b64("L0xpYnJhcnkvTW9iaWxlU3Vic3RyYXRlL01vYmlsZVN1YnN0cmF0ZS5keWxpYg=="), 25),
            (b64("L0xpYnJhcnkvTW9iaWxlU3Vic3RyYXRlL0R5bmFtaWNMaWJyYXJpZXM="), 20),
            (b64("L1VzZXIvTGlicmFyeS9GcmFtZXdvcmtzL0N5ZGlhU3Vic3RyYXRlLmZyYW1ld29yaw=="), 25),
            (b64("L3Vzci9saWIvbGlic3Vic3RyYXRlLmR5bGli"), 20),
            (b64("L3Vzci9saWIvbGlic3Vic3RpdHV0ZS5keWxpYg=="), 20),
            (b64("L3Vzci9saWIvc3Vic3RpdHV0ZQ=="), 25),
            (b64("L3Vzci9saWIvRWxsZUtpdC5keWxpYg=="), 25),
            (b64("L3Vzci9saWIvbGlib29rZXIuZHlsaWI="), 20),
            (b64("L3Zhci9qYg=="), 15),
            (b64("L3Zhci9qYi91c3IvYmluL3NzaA=="), 10),
            (b64("L3Zhci9qYi9BcHBsaWNhdGlvbnMvU2lsZW8uYXBw"), 20),
            (b64("L3Zhci9qYi9MaWJyYXJ5L01vYmlsZVN1YnN0cmF0ZS9Nb2JpbGVTdWJzdHJhdGUuZHlsaWI="), 25),
            (b64("L3Zhci9qYi91c3IvbGliL0VsbGVLaXQuZHlsaWI="), 25),
            (b64("L0FwcGxpY2F0aW9ucy9jaGVja3JhMW4uYXBw"), 25),
            (b64("L0FwcGxpY2F0aW9ucy9vZHlzc2V5LmFwcA=="), 20),
            (b64("L0FwcGxpY2F0aW9ucy91bmMwdmVyLmFwcA=="), 25),
            (b64("L0FwcGxpY2F0aW9ucy9UYXVyaW5lLmFwcA=="), 20),
            (b64("L2V0Yy9hcHQ="), 25),
            (b64("L2V0Yy9hcHQvc291cmNlcy5saXN0"), 20),
            (b64("L2V0Yy9hcHQvc291cmNlcy5saXN0LmQ="), 20),
            (b64("L3Zhci9saWIvYXB0"), 15),
            (b64("L3Vzci9zYmluL3NzaGQ="), 15),
            (b64("L3Vzci9iaW4vc3No"), 10),
            (b64("L2Jpbi9iYXNo"), 10),
            (b64("L3Zhci9tb2JpbGUvLnJvb3RoaWRl"), 30),
            (b64("L3Zhci9tb2JpbGUvLmluc3RhbGxlZF9yb290aGlkZQ=="), 30),
            (b64("L3Zhci9tb2JpbGUvLnByb2N1cnN1c19zdHJhcHBlZA=="), 25),
            (b64("L3Zhci9qYi8ucHJvY3Vyc3VzX3N0cmFwcGVk"), 25),
        ]
    }

    // MARK: - 关键路径与噪声路径

    /// 强证据路径：任一路径可访问即基本可判定越狱。
    static var jailbreakCriticalPaths: [String] {
        [
            b64("L2V0Yy9hcHQ="),
            b64("L0FwcGxpY2F0aW9ucy9DeWRpYS5hcHA="),
            b64("L3Zhci9qYg=="),
            b64("L3Vzci9saWIvRWxsZUtpdC5keWxpYg=="),
            b64("L0xpYnJhcnkvTW9iaWxlU3Vic3RyYXRlL01vYmlsZVN1YnN0cmF0ZS5keWxpYg=="),
            b64("L3Zhci9tb2JpbGUvLnJvb3RoaWRl"),
        ]
    }

    /// 噪声路径：正常系统路径，用于在检查越狱路径前插入 stat 调用，干扰 Stalker 区分检测目标
    static var pathNoisePaths: [String] {
        [
            b64("L3Vzci9saWIvZHlsZA=="),           // /usr/lib/dyld
            b64("L2V0Yy9wYXNzd2Q="),               // /etc/passwd
            b64("L2Rldi9udWxs"),                   // /dev/null
            b64("L3Vzci9saWIvbGliU3lzdGVtLkIuZHlsaWI="),  // /usr/lib/libSystem.B.dylib
            b64("L1N5c3RlbS9MaWJyYXJ5L0NvcmVTZXJ2aWNlcy9TeXN0ZW1WZXJzaW9uLnBsaXN0"),  // SystemVersion.plist
        ]
    }

    // MARK: - 进程名 / 应用名特征

    /// 进程列表中出现的越狱工具、调试器与注入器进程名。
    static var sysctlSuspiciousProcessNeedles: [String] {
        [
            b64("Y3lkaWE="),
            b64("c2lsZW8="),
            b64("ZmlsemE="),
            b64("c3NoZA=="),
            b64("ZHJvcGJlYXI="),
            b64("ZnJpZGE="),
            b64("ZGVidWdzZXJ2ZXI="),
            b64("Y3ljcmlwdA=="),
            b64("c3Vic3RyYXRlZA=="),
            b64("c3Vic3RpdHV0ZQ=="),
            b64("ZWxsZWtpdA=="),
            b64("YXB0"),
            b64("ZHBrZw=="),
            b64("cm9vdGhpZGVpbml0"),
            b64("cm9vdGhpZGVwYXRjaGVy"),
        ]
    }

    /// 父进程名特征：正常 App 的父进程通常是 launchd，出现这些名字说明被调试/注入拉起。
    static var sysctlSuspiciousParentNeedles: [String] {
        [
            b64("Y3lkaWE="),
            b64("c2lsZW8="),
            b64("ZmlsemE="),
            b64("ZnJpZGE="),
            b64("ZGVidWdzZXJ2ZXI="),
            b64("bGxkYg=="),
            b64("Z2Ri"),
        ]
    }

    /// 已安装应用列表中的越狱工具名。
    static var listApplicationsNeedles: [String] {
        [
            b64("c2lsZW8="),
            b64("Y3lkaWE="),
            b64("emVicmE="),
            b64("ZmlsemE="),
            b64("Y2hlY2tyYTFu"),
            b64("dGF1cmluZQ=="),
            b64("dW5jMHZlcg=="),
            b64("Y2hpbWVyYQ=="),
        ]
    }

    // MARK: - 环境变量

    /// roothide 越狱注入的环境变量；命中权重最高（35–40），因为正常进程不会设置这些值。
    static var roothideEnvVars: [(name: String, score: Double)] {
        [
            (b64("SkJST09U"), 40),
            (b64("SkJfUk9PVF9QQVRI"), 40),
            (b64("SkJSQU5E"), 35),
        ]
    }

    /// dyld 注入相关环境变量及权重；`DYLD_INSERT_LIBRARIES` 直接加载外部库，权重 50。
    static var envSuspiciousVars: [(name: String, score: Double)] {
        [
            (b64("RFlMRF9JTlNFUlRfTElCUkFSSUVT"), 50),
            (b64("RFlMRF9MSUJSQVJZX1BBVEg="), 25),
            (b64("RFlMRF9GQUxMQkFDS19MSUJSQVJZX1BBVEg="), 20),
            (b64("RFlMRF9QUklOVF9MSUJSQVJJRVM="), 15),
            (b64("RFlMRF9QUklOVF9TRUdNRU5UUw=="), 12),
            (b64("RFlMRF9QUklOVF9JTklUSUFMSVpFUlM="), 12),
            (b64("RFlMRF9QUklOVF9ET0ZT"), 10),
            (b64("RFlMRF9QUklOVF9BUElT"), 10),
            (b64("RFlMRF9QUklOVF9TVEFUSVNUSUNT"), 10),
            (b64("RFlMRF9QUklOVF9XQVJOSU5HUw=="), 10),
            (b64("RFlMRF9WRVJCT1NF"), 10),
            (b64("RFlMRF9CSU5EX0FUX0xBVU5DSA=="), 10),
            (b64("TExEX0xJQlJBUllfUEFUSA=="), 20),
            (b64("TExEX1BSRU9BRQ=="), 25),
            (b64("RFlMRF9OT19QSUU="), 12),
            (b64("RFlMRF9ESVNBQkxFX1BSRUZFVENI"), 10),
        ]
    }

    // MARK: - 系统配置文件

    /// 越狱环境常见的系统配置文件路径（部分在未越狱设备上也存在，仅作弱证据）。
    static var systemConfigPaths: [String] {
        [
            b64("L2V0Yy9mc3RhYg=="),
            b64("L2V0Yy9ob3N0cw=="),
            b64("L2V0Yy9hcHQvc291cmNlcy5saXN0"),
            b64("L3ByaXZhdGUvZXRjL2ZzdGFi"),
            b64("L3ByaXZhdGUvZXRjL2hvc3Rz"),
        ]
    }

    /// `/etc/hosts` 路径。
    static var hostsPath: String { b64("L2V0Yy9ob3N0cw==") }

    /// apt 包管理器的配置 / 缓存路径（越狱后常见）。
    static var aptPaths: [String] {
        [
            b64("L2V0Yy9hcHQ="),
            b64("L2V0Yy9hcHQvc291cmNlcy5saXN0"),
            b64("L2V0Yy9hcHQvc291cmNlcy5saXN0LmQ="),
            b64("L3Zhci9saWIvYXB0"),
            b64("L3Zhci9jYWNoZS9hcHQ="),
            b64("L1VzZXIvTGlicmFyeS9hcHQ="),
        ]
    }

    /// apt 软件源列表路径。
    static var aptSourcesListPath: String { b64("L2V0Yy9hcHQvc291cmNlcy5saXN0") }

    /// 软件源中的越狱社区仓库名。
    static var aptRepoNeedles: [String] {
        [b64("Y3lkaWE="), b64("YmlnYm9zcw=="), b64("bW9kbXlp")]
    }

    /// `/etc/fstab` 路径；越狱工具常用它让根分区可写。
    static var fstabPath: String { b64("L2V0Yy9mc3RhYg==") }

    // MARK: - hosts / fstab 篡改特征

    /// hosts 中的可疑条目：屏蔽 OTA 更新或指向越狱源。
    static var suspiciousHostsEntries: [String] {
        [
            b64("MTI3LjAuMC4xIG9jc3A="),
            b64("MTI3LjAuMC4xIG9jc3Ay"),
            b64("MTI3LjAuMC4xICouYXBwbGUuY29t"),
            b64("YWRiY29ubmVjdA=="),
            b64("Y3lkaWE="),
            b64("c2lsZW8="),
        ]
    }

    /// fstab 中的异常挂载项（如根分区 rw 或注入框架目录）。
    static var suspiciousFstabMounts: [String] {
        [
            b64("L3Zhcg=="),
            b64("L0FwcGxpY2F0aW9ucy8="),
            b64("L0xpYnJhcnkvTW9iaWxlU3Vic3RyYXRl"),
            b64("cnc="),
            b64("bm9kZXY="),
        ]
    }

    /// 统一的 Base64 查表入口；解码失败时 `base64Decode` 返回空串，调用方按“未命中”处理。
    private static func b64(_ s: String) -> String {
        StringDeobfuscator.base64Decode(s)
    }
}
