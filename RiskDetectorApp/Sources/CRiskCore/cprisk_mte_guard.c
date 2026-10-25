/*
 * CRiskCore — 软件基线 guard（software baseline guard），不是硬件 MTE 保护。
 * 本文件不发射任何 MTE 指令（STG/LDG 等）；所谓 canary 只是“绑定区域的
 * SHA-256 基线摘要 + 顶字节标签快照”软件比对，能发现内存被改写，但不提供
 * 硬件 MTE 的标签化内存隔离/越界拦截能力。不要把本模块的通过当作硬件
 * MTE 已生效的证据。不支持时返回 -2（“不支持”），不再返回 0 冒充成功。
 */

#include "include/cprisk_mte_guard.h"
#include "include/CRiskCore.h"

#include "include/cprisk_secure_zero.h"
#include "include/cprisk_sha256.h"

#include <stdint.h>
#include <string.h>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

// 能力探测键：MTE / MTE2 / MTE4 是 Apple 芯片上不同代的标签化内存特性。
// 只读取 sysctl，不用它推断“当前进程已受 MTE 保护”。
#define CPRISK_SYSCTL_MTE "hw.optional.arm.FEAT_MTE"
#define CPRISK_SYSCTL_MTE2 "hw.optional.arm.FEAT_MTE2"
#define CPRISK_SYSCTL_MTE4 "hw.optional.arm.FEAT_MTE4"

// 进程级诊断计数：当前安装中的 canary 数、累计校验失败数、最近一次自检返回码。
// 均为普通全局变量而非原子量：写入发生在安装/自检路径，调用方需按单线程
// 初始化约定使用；快照读取可能看到短暂不一致，但只用于诊断，不参与判决。
static uint32_t s_active_canary_count;
static uint32_t s_canary_violation_count;
static int32_t s_last_self_test_rc;

// 平台前置判断：模拟器与非 arm64 一律不支持。放在最前面，
// 保证后续 sysctl/MRS 探测不会在不具备语义的环境里产生“幸运命中”。
static int cprisk_mte_platform_ineligible(void) {
#if defined(__APPLE__) && defined(TARGET_OS_SIMULATOR) && TARGET_OS_SIMULATOR
    return 1;
#endif
#if !defined(__aarch64__)
    return 1;
#endif
    return 0;
}

// 读一个 int32 型 sysctl；要求返回长度恰好 4 字节，否则视为不可读（-1）。
// 长度不符常见于键不存在或类型变化，此时调用方应按“不支持”而非“值为 0”处理。
static int cprisk_sysctl_int32_named(const char *name, int32_t *out) {
    if (!name || !out)
        return -1;
    int32_t v = 0;
    size_t len = sizeof(v);
    int err = 0;
    if (cprisk_sysctlbyname_direct(name, &v, &len, NULL, 0, &err) != 0)
        return -1;
    if (len != sizeof(int32_t))
        return -1;
    *out = v;
    return 0;
}

#if defined(__aarch64__) && defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
// 读取 CPU 特性寄存器 ID_AA64PFR1_EL1（含 MTE 字段）。
// 仅真机 arm64 编译；其他环境返回 0，调用方会把 0 解释为“CPU 未报告 MTE”，
// 从而在 sysctl 与寄存器矛盾时选择保守结论。
static uint64_t cprisk_read_id_aa64pfr1_el1(void) {
    uint64_t v = 0;
    __asm__ __volatile__("mrs %0, ID_AA64PFR1_EL1" : "=r"(v));
    return v;
}
#else
static uint64_t cprisk_read_id_aa64pfr1_el1(void) {
    return 0;
}
#endif

// ID_AA64PFR1_EL1[11:8] 是 MTE 字段：0 表示未实现，非 0 表示实现（按值区分 MTE/MTE2/MTE4）。
static unsigned cprisk_id_aa64pfr1_mte_field(uint64_t id_aa64pfr1_el1) {
    return (unsigned)((id_aa64pfr1_el1 >> 8) & 0xFu);
}

// 取指针顶字节中的 4 位标签（arm64 TBI/MTE 约定：bits[59:56]）。
// 这只是“快照”，不是硬件标签校验；指针被改写时它能提供额外一维差异。
static uint8_t cprisk_pointer_tag_i(const void *ptr) {
    return (uint8_t)(((uintptr_t)ptr >> 56) & 0x0Fu);
}

// 对受保护区域做 SHA-256 基线摘要；区域必须由调用方保证在生命周期内可读。
static void cprisk_region_hash_i(
    const void *region,
    size_t size,
    uint8_t out_hash[CPRISK_SHA256_DIGEST_LENGTH]
) {
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, region, size);
    cprisk_sha256_final(&ctx, out_hash);
}

// 同时记入 per-state 与进程级失败计数；state 允许为 NULL（仅累加全局计数）。
static void cprisk_record_canary_violation_i(cprisk_mte_canary_state_t *state) {
    if (state != NULL)
        state->verify_failure_count += 1u;
    s_canary_violation_count += 1u;
}

// 硬 MTE 能力探测：编译开关（Release 才开启）∧ 平台适用 ∧ sysctl 非零，三者缺一即 0。
// 返回 0 只说明“不可用”，调用方不得据此判断内存安全。
int cprisk_mte_available(void) {
#if !defined(CPRISK_MTE_COMPILE_SUPPORT)
    return 0;
#else
    if (cprisk_mte_platform_ineligible())
        return 0;
    int32_t v = 0;
    if (cprisk_sysctl_int32_named(CPRISK_SYSCTL_MTE, &v) != 0)
        return 0;
    return v != 0 ? 1 : 0;
#endif
}

// MTE2/MTE4 合并探测：任一键为真即认为具备更新一代的同步标签检查能力。
// 键不可读与键为 0 都按“不满足”处理，不区分原因。
int cprisk_mte2_available(void) {
#if !defined(CPRISK_MTE_COMPILE_SUPPORT)
    return 0;
#else
    if (cprisk_mte_platform_ineligible())
        return 0;
    int32_t v2 = 0;
    if (cprisk_sysctl_int32_named(CPRISK_SYSCTL_MTE2, &v2) == 0 && v2 != 0)
        return 1;
    int32_t v4 = 0;
    if (cprisk_sysctl_int32_named(CPRISK_SYSCTL_MTE4, &v4) == 0 && v4 != 0)
        return 1;
    return 0;
#endif
}

// sysctl 与 CPU 寄存器的一致性自检。
// 返回 0 = 两者都报告 MTE；-1 = 矛盾（一侧有、一侧无，或 sysctl 不可读但 CPU 报告有）；
// -2 = 不支持（编译未开启/平台不适用/sysctl 为 0 且 CPU 未报告）。
// 注意：-2 与 0 语义不同，调用方必须把 -2 当“未知”，绝不能当“通过”。
int cprisk_mte_self_test(void) {
#if !defined(CPRISK_MTE_COMPILE_SUPPORT)
    /* Unsupported: -2 (not success). Callers must not treat this as pass. */
    s_last_self_test_rc = -2;
    return -2;
#else
    if (cprisk_mte_platform_ineligible()) {
        s_last_self_test_rc = -2;
        return -2;
    }

    int32_t sys_mte = 0;
    const int rc_sys = cprisk_sysctl_int32_named(CPRISK_SYSCTL_MTE, &sys_mte);
    const uint64_t id = cprisk_read_id_aa64pfr1_el1();
    const unsigned mte_field = cprisk_id_aa64pfr1_mte_field(id);

    if (rc_sys != 0) {
        /* sysctl unreadable: if the CPU reports MTE, that is a mismatch
         * (-1); otherwise MTE is simply unsupported (-2), not a pass. */
        s_last_self_test_rc = (mte_field != 0u) ? -1 : -2;
        return s_last_self_test_rc;
    }
    if (sys_mte == 0) {
        s_last_self_test_rc = (mte_field != 0u) ? -1 : -2;
        return s_last_self_test_rc;
    }

    s_last_self_test_rc = (mte_field == 0u) ? -1 : 0;
    return s_last_self_test_rc;
#endif
}

// 安装软件基线 canary：记录区域指针、大小、顶字节标签与 SHA-256 基线。
// 返回 0 = 已安装；-1 = 参数非法；-2 = 编译/平台/能力不支持（state 已清零）。
// 不发射任何 MTE 指令，因此“安装成功”不代表硬件标签保护生效。
int cprisk_mte_canary_install(
    cprisk_mte_canary_state_t *state,
    void *region,
    size_t size
) {
#if !defined(CPRISK_MTE_COMPILE_SUPPORT)
    if (state != NULL)
        memset(state, 0, sizeof(*state));
    (void)region;
    (void)size;
    return -2; /* unsupported, not success */
#else
    if (!state || !region || size == 0u)
        return -1;

    memset(state, 0, sizeof(*state));
    if (cprisk_mte_platform_ineligible())
        return -2; /* unsupported, not success */
    if (cprisk_mte_available() == 0)
        return -2; /* unsupported, not success */

    state->guarded_region = region;
    state->region_size = size;
    state->expected_tag = cprisk_pointer_tag_i(region);
    state->installed = 1u;
    cprisk_region_hash_i(region, size, state->baseline_hash);
    s_active_canary_count += 1u;
    return 0;
#endif
}

// 复检 canary：重新计算区域摘要与标签，逐字节累积差异（不提前返回，减少时序侧信道）。
// 返回 0 = 一致；-1 = 区域非法或摘要/标签不一致（已计一次违规）；-2 = 未安装/不支持。
// 调用方必须把 -2 当“无法判定”，不能当“通过”。
int cprisk_mte_canary_verify(cprisk_mte_canary_state_t *state) {
#if !defined(CPRISK_MTE_COMPILE_SUPPORT)
    (void)state;
    return -2; /* unsupported, not success */
#else
    if (!state || state->installed == 0u)
        return -2; /* not installed / unsupported, not success */
    if (cprisk_mte_available() == 0)
        return -2; /* unsupported, not success */
    if (!state->guarded_region || state->region_size == 0u) {
        cprisk_record_canary_violation_i(state);
        return -1;
    }

    uint8_t current_hash[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_region_hash_i(state->guarded_region, state->region_size, current_hash);

    uint8_t diff = 0u;
    for (size_t i = 0; i < sizeof(current_hash); i++)
        diff |= (uint8_t)(current_hash[i] ^ state->baseline_hash[i]);
    diff |= (uint8_t)(cprisk_pointer_tag_i(state->guarded_region) ^ state->expected_tag);
    cprisk_secure_zero(current_hash, sizeof(current_hash));

    if (diff != 0u) {
        cprisk_record_canary_violation_i(state);
        return -1;
    }
    return 0;
#endif
}

// 卸载 canary：递减活动计数并安全清零 state（基线摘要属于敏感材料）。
// 对未安装的 state 也可调用；失败计数不会被清零，保留诊断信息。
void cprisk_mte_canary_remove(cprisk_mte_canary_state_t *state) {
    if (!state)
        return;
#if defined(CPRISK_MTE_COMPILE_SUPPORT)
    if (state->installed != 0u && s_active_canary_count > 0u)
        s_active_canary_count -= 1u;
#endif
    cprisk_secure_zero(state, sizeof(*state));
}

// 诊断快照：现场读取三个能力键并汇总进程级计数。
// sysctl 读取失败被忽略（值保持 0），因此快照中的能力位只会“少报”不会“多报”；
// 返回 -1 仅表示 out_state 为 NULL。
int cprisk_mte_guard_snapshot(cprisk_mte_guard_snapshot_t *out_state) {
    if (!out_state)
        return -1;
    memset(out_state, 0, sizeof(*out_state));

    int32_t mte = 0;
    int32_t m2 = 0;
    int32_t m4 = 0;
    (void)cprisk_sysctl_int32_named(CPRISK_SYSCTL_MTE, &mte);
    (void)cprisk_sysctl_int32_named(CPRISK_SYSCTL_MTE2, &m2);
    (void)cprisk_sysctl_int32_named(CPRISK_SYSCTL_MTE4, &m4);

    out_state->sysctl_mte = (uint32_t)(mte != 0 ? 1u : 0u);
    out_state->sysctl_mte2 = (uint32_t)((m2 != 0 || m4 != 0) ? 1u : 0u);
    out_state->canary_installed = s_active_canary_count > 0u ? 1u : 0u;
    out_state->last_self_test_rc = s_last_self_test_rc;
    out_state->canary_violation_count = s_canary_violation_count;
    return 0;
}
