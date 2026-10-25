// 文件职责：MTE 能力探测与“软件基线 canary”区域完整性复检接口。
// 在链路中的位置：为加固模块提供“平台是否具备 MTE”的可信判断，并对敏感区域做安装/复检/卸载生命周期管理。
// 安全不变量：本模块不发射 STG/LDG 等硬件标签指令，所谓 canary 是 SHA-256 基线 + 顶字节标签的软件比对。
// 线程模型：能力探测无全局可变状态，可并发；同一 canary state 的 install/verify/remove 必须由调用方串行化。
// 平台限制：仅 arm64 真机且编译开启 CPRISK_MTE_COMPILE_SUPPORT 才可能返回支持；模拟器/非 arm64 一律不支持。
// 失败语义：-2 表示“不支持/无法判定”，调用方绝不能当作成功；-1 表示已确认异常，应升级为风险。
#ifndef cprisk_mte_guard_h
#define cprisk_mte_guard_h

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 单个受保护区域的软件 canary 状态。字段只由本模块维护，调用方不得手改。
typedef struct cprisk_mte_canary_state {
    // 受保护区域起始地址；不拥有内存，调用方保证其生命周期。
    void *guarded_region;
    // 区域字节数；为 0 表示无效。
    size_t region_size;
    // 安装时记录的区域指针顶字节（软件快照，不是硬件 MTE 标签）。
    uint8_t expected_tag;
    // 1 = 已安装；0 = 未安装/已卸载。
    uint8_t installed;
    // 对齐填充，保证后续字段 4 字节对齐。
    uint16_t reserved;
    // 本 state 复检失败累计次数（只增不减，直到 remove 清零）。
    uint32_t verify_failure_count;
    // 安装时整区 SHA-256 基线；属于敏感材料，remove 时安全清零。
    uint8_t baseline_hash[32];
} cprisk_mte_canary_state_t;

// 诊断快照：汇总当前进程的能力探测与 canary 计数，供日志/自检使用。
typedef struct cprisk_mte_guard_snapshot {
    // 进程内活动 canary 数 >0 时为 1，否则 0。
    uint32_t canary_installed;
    // hw.optional.arm.FEAT_MTE 的布尔结果（读失败按 0）。
    uint32_t sysctl_mte;
    // MTE2 或 MTE4 sysctl 任一为真的布尔结果。
    uint32_t sysctl_mte2;
    // 最近一次 cprisk_mte_self_test 的返回值（0/-1/-2）。
    int32_t last_self_test_rc;
    // 进程级 canary 违规累计次数。
    uint32_t canary_violation_count;
} cprisk_mte_guard_snapshot_t;

/// 软件基线 guard（software baseline guard），不是硬件 MTE 保护：本模块
/// 不发射任何 MTE 指令（STG/LDG 等），只做“区域 SHA-256 基线 + 顶字节标签
/// 快照”软件比对。sysctl \c hw.optional.arm.FEAT_MTE 非零且编译开启
/// \c CPRISK_MTE_COMPILE_SUPPORT 时返回 1。模拟器、非 arm64、或 sysctl 键缺失时返回 0。
/// - Returns: 1 = 可用；0 = 不可用。
/// - Thread safety: 只读 sysctl，可并发。
/// - 失败语义: 0 只表示“不可用”，不能据此判断内存安全。
int cprisk_mte_available(void);

/// \c hw.optional.arm.FEAT_MTE2 或 \c hw.optional.arm.FEAT_MTE4（Apple EMTE 系）之一可用时返回 1。
/// - Returns: 1 = 支持新一代同步标签检查；0 = 不支持或探测失败。
/// - Thread safety: 只读 sysctl，可并发。
/// - 失败语义: 键不可读与键为 0 都按“不支持”处理，不区分原因。
int cprisk_mte2_available(void);

/// sysctl 与 \c ID_AA64PFR1_EL1.MTE 字段一致性自检。返回 0 = 一致；
/// -1 = 不一致/探测失败；-2 = 不支持（未编译支持 / 平台不适用），
/// 调用方必须把 -2 当作“不支持”处理，绝不能当成功。
/// 实现不会主动发射 STG/LDG 等内存标记指令（软件基线 guard）。
/// - Returns: 0 = 两侧都报告 MTE；-1 = 两侧矛盾或 sysctl 不可读但 CPU 报告有；-2 = 不支持。
/// - Thread safety: 内部仅写一个进程级自检结果，允许并发调用。
/// - Platform: 仅 arm64 + CPRISK_MTE_COMPILE_SUPPORT 才可能返回 0。
/// - 失败语义: -2 表示“未知”，调用方不得当作通过。
int cprisk_mte_self_test(void);

/// 将 canary 绑定到受保护内存区域。当前实现采用“区域基线摘要 + 顶字节标签快照”的
/// 软件基线方案：在具备 MTE 能力时记录区域 SHA-256 基线，并在复检时比较，避免在旧芯片/
/// 旧工具链上触发 SIGILL。不支持时返回 -2（“不支持”），不再假装成功返回 0。
/// - Parameters:
///   - state: 调用方分配的 canary 状态；不允许 NULL（NULL 返回 -1）。
///   - region: 受保护区域；不允许 NULL；内存所有权仍归调用方。
///   - size: 区域字节数；0 返回 -1。
/// - Returns: 0 = 已安装；-1 = 参数非法；-2 = 编译/平台/能力不支持（state 已清零）。
/// - Thread safety: 同一 state 不可并发安装；不同 state 可并发。
/// - Platform: 不支持时绝不发射 MTE 指令，因此“安装成功”也不代表硬件标签保护生效。
/// - 失败语义: -2 必须按“无法保护”处理；-1 表示参数错误。
int cprisk_mte_canary_install(
    cprisk_mte_canary_state_t *state,
    void *region,
    size_t size
);

/// 基线一致返回 0；基线不一致返回 -1，并递增失败计数；
/// canary 未安装 / 平台不支持返回 -2（“不支持”，不是成功）。
/// - Parameters:
///   - state: 之前成功 install 的状态；NULL 返回 -2。
/// - Returns: 0 = 一致；-1 = 区域非法或摘要/标签不一致（已计违规）；-2 = 未安装/不支持。
/// - Thread safety: 同一 state 的 verify 需串行；内部对差异做全量累积，减少时序侧信道。
/// - 失败语义: -2 表示无法判定，-1 表示已确认篡改，调用方应据此升级风险。
int cprisk_mte_canary_verify(cprisk_mte_canary_state_t *state);

/// 卸载 canary：递减活动计数并安全清零 state（基线摘要属于敏感材料）。
/// - Parameters:
///   - state: 要卸载的状态；允许 NULL（无操作），所有权仍归调用方。
/// - Returns: 无。
/// - Thread safety: 同一 state 需串行；重复调用安全。
/// - 失败语义: 不释放 region（不属于本模块）；失败计数随整体清零一并丢弃。
void cprisk_mte_canary_remove(cprisk_mte_canary_state_t *state);

/// 诊断用：填充当前 MTE / canary 状态（指针可为 NULL 时返回 -1）。
/// - Parameters:
///   - out_state: 输出快照；不允许 NULL，所有权归调用方。
/// - Returns: 0 = 已填充；-1 = out_state 为 NULL。
/// - Thread safety: 读取进程级原子/近似计数，可并发；快照只可能“少报”能力，不会多报。
/// - 失败语义: sysctl 读取失败被忽略（对应位为 0），调用方不能据此判定硬件无 MTE。
int cprisk_mte_guard_snapshot(cprisk_mte_guard_snapshot_t *out_state);

#ifdef __cplusplus
}
#endif

#endif /* cprisk_mte_guard_h */
