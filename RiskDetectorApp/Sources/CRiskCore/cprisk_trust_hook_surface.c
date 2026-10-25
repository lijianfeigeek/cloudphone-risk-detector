/*
 * cprisk_trust_hook_surface.c — 信任/证书固定路径的导出函数序言快照校验。
 * 职责：记录 Security 三个 trust 导出与 dlopen/dlsym 入口前 16 字节，发现 Interceptor 补丁。
 * 机制：constructor(10) 抓首次基线；每次同时比对原始基线（持久 Hook）与上次正常值（瞬时改动）。
 * 线程：快照数组未加锁，验证应串行调用；并发对 last_ok 有数据竞争，最坏一次误报。
 * 平台：仅 __APPLE__ 启用；其他平台 fail-open 返回 1，避免把不支持误判为 Hook。
 * 失败：返回 0 且 mask 置位，并对 watchdog lane 投毒；调用方必须把 mask 非零当风险。
 */

#include "include/CRiskCore.h"

#include <dlfcn.h>
#include <stdatomic.h>
#include <string.h>

#if defined(__APPLE__)

#include <Security/Security.h>

// 每个导出函数抓取的序言字节数：16 字节足以覆盖 arm64 的跳板/前几条指令，
// 又短到可在任意调用频率下低开销 memcmp。
#define CPRISK_THS_PROLOGUE_BYTES 16u
// Security.framework 受监控的导出数量（3 个），与 cprisk_ths_fill_sec_addrs 一一对应。
#define CPRISK_THS_SEC_SLOT_COUNT 3u

// s_ths_sec_ref：首次抓取的原始序言基线（只写一次，之后只读）。
// s_ths_sec_last_ok：上次校验通过的序言；用于发现两次校验之间的瞬时改动。
static uint8_t s_ths_sec_ref[CPRISK_THS_SEC_SLOT_COUNT][CPRISK_THS_PROLOGUE_BYTES];
static uint8_t s_ths_sec_last_ok[CPRISK_THS_SEC_SLOT_COUNT][CPRISK_THS_PROLOGUE_BYTES];
static atomic_uint_fast32_t s_ths_sec_last_ok_valid = 0u;
// 捕获完成标志（原子）：1 表示 ref 数组已初始化，可无锁快速判断。
static atomic_uint_fast32_t s_ths_captured = 0u;

// dlopen 的原始序言与上次正常序言；语义同 Security 槽位。
static uint8_t s_ths_dlopen_ref[CPRISK_THS_PROLOGUE_BYTES];
static uint8_t s_ths_dlopen_last_ok[CPRISK_THS_PROLOGUE_BYTES];
static atomic_uint_fast32_t s_ths_dlopen_last_ok_valid = 0u;

// 填充三个受监控的 Security 导出函数地址。
// 参数：addrs 由调用方提供，长度必须是 CPRISK_THS_SEC_SLOT_COUNT；不可为 NULL。
// 返回：无。线程安全：只写调用方数组，可重入。平台：仅 Apple。
// 不变量：槽位顺序必须与位掩码位序一致（slot i -> bit i）。
static void cprisk_ths_fill_sec_addrs(const void **addrs) {
    addrs[0] = (const void *)&SecTrustEvaluateWithError;
    addrs[1] = (const void *)&SecTrustGetTrustResult;
    addrs[2] = (const void *)&SecTrustCopyKey;
}

// 首次捕获所有序言基线；幂等。
// 参数：无。返回：无。
// 线程安全：用原子标志做快速路径；并发首次调用可能重复 memcpy 相同内容（良性），
// 但 ref 数组未加锁，仍应尽量在单线程初始化阶段调用。
// 平台：仅 Apple；不变量：返回后 s_ths_captured=1，ref 可用于后续比对。
static void cprisk_ths_capture_once_i(void) {
    if (atomic_load(&s_ths_captured) != 0u) {
        return;
    }
    const void *addrs[CPRISK_THS_SEC_SLOT_COUNT];
    cprisk_ths_fill_sec_addrs(addrs);
    for (uint32_t i = 0u; i < CPRISK_THS_SEC_SLOT_COUNT; i++) {
        memcpy(s_ths_sec_ref[i], addrs[i], CPRISK_THS_PROLOGUE_BYTES);
    }
    memcpy(s_ths_dlopen_ref, (const void *)&dlopen, CPRISK_THS_PROLOGUE_BYTES);
    atomic_store(&s_ths_captured, 1u);
}

// constructor(10) 在加载早期抓取基线，尽量早于任何第三方 Hook 安装。
// 无参数/无返回值；失败无声（后续校验会自行补捕获并可能报告差异）。
__attribute__((constructor(10)))
static void cprisk_ths_early_ctor_i(void) {
    cprisk_ths_capture_once_i();
}

// 校验 dlopen 序言是否被修改。
// 参数：mask_out 不可为 NULL，失败位通过 *mask_out |= 写入。
// 返回：1 = 序言与基线/上次正常值一致；0 = 被修改（已投毒）。
// 线程安全：读共享数组，与并发校验存在数据竞争（最坏一次误报）；不应并发调用。
// 平台：仅 Apple。
// 失败语义：新增 DLOPEN 位并调用 cprisk_integrity_poison_watchdog_lane_now()，
// 调用方须把返回 0 当作风险处理，不能静默忽略。
static int cprisk_ths_verify_dlopen_prologue_i(uint32_t *mask_out) {
    if (atomic_load(&s_ths_captured) == 0u) {
        cprisk_ths_capture_once_i();
    }
    uint8_t live[CPRISK_THS_PROLOGUE_BYTES];
    memcpy(live, (const void *)&dlopen, CPRISK_THS_PROLOGUE_BYTES);
    // 第一重：与“上次正常值”比，捕捉两次校验之间挂上又撤掉的瞬时 Hook。
    if (atomic_load_explicit(&s_ths_dlopen_last_ok_valid, memory_order_relaxed) != 0u &&
        memcmp(s_ths_dlopen_last_ok, live, CPRISK_THS_PROLOGUE_BYTES) != 0) {
        *mask_out |= CPRISK_TRUST_HOOK_FAIL_DLOPEN;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    // 第二重：与首次基线比，捕捉持续存在的 Hook；两者都不通过才更新 last_ok。
    if (memcmp(s_ths_dlopen_ref, live, CPRISK_THS_PROLOGUE_BYTES) != 0) {
        *mask_out |= CPRISK_TRUST_HOOK_FAIL_DLOPEN;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    memcpy(s_ths_dlopen_last_ok, live, CPRISK_THS_PROLOGUE_BYTES);
    atomic_store_explicit(&s_ths_dlopen_last_ok_valid, 1u, memory_order_release);
    return 1;
}

// 校验整套信任 Hook 导出面（Security 三个导出 + dlopen + dlsym）。
// 参数：fail_mask_out 可为 NULL；非 NULL 时先清零再写入失败位。
// 返回：1 = 全部一致；0 = 至少一处可疑（mask 非零）。
// 线程安全：可并发调用但会竞争 last_ok 数组，最坏一次误报；建议串行调用。
// 平台：仅 Apple；非 Apple 返回 1（fail-open）。
// 失败语义：Security 槽位用 bit0..bit2；dlopen/dlsym 用专用 FLAG；
// 每个失败点都会投毒 watchdog lane，调用方必须把 0 当作风险。
int cprisk_verify_trust_hook_surface_integrity(uint32_t *fail_mask_out) {
    uint32_t mask = 0u;
    if (fail_mask_out != NULL) {
        *fail_mask_out = 0u;
    }

    cprisk_ths_capture_once_i();

    const void *addrs[CPRISK_THS_SEC_SLOT_COUNT];
    cprisk_ths_fill_sec_addrs(addrs);
    const int have_last =
        atomic_load_explicit(&s_ths_sec_last_ok_valid, memory_order_relaxed) != 0u;
    for (uint32_t i = 0u; i < CPRISK_THS_SEC_SLOT_COUNT; i++) {
        uint8_t live[CPRISK_THS_PROLOGUE_BYTES];
        memcpy(live, addrs[i], CPRISK_THS_PROLOGUE_BYTES);
        // 双重比对（同上）：last_ok 抓瞬时改动，ref 抓持久 Hook。
        if (have_last != 0 &&
            memcmp(s_ths_sec_last_ok[i], live, CPRISK_THS_PROLOGUE_BYTES) != 0) {
            mask |= (1u << i);
            cprisk_integrity_poison_watchdog_lane_now();
        }
        if (memcmp(s_ths_sec_ref[i], live, CPRISK_THS_PROLOGUE_BYTES) != 0) {
            mask |= (1u << i);
            cprisk_integrity_poison_watchdog_lane_now();
        }
        memcpy(s_ths_sec_last_ok[i], live, CPRISK_THS_PROLOGUE_BYTES);
    }
    atomic_store_explicit(&s_ths_sec_last_ok_valid, 1u, memory_order_release);

    if (cprisk_verify_dlsym_prologue() == 0) {
        mask |= CPRISK_TRUST_HOOK_FAIL_DLSYM;
    }
    if (cprisk_ths_verify_dlopen_prologue_i(&mask) == 0) {
        /* mask already updated */
    }

    if (fail_mask_out != NULL) {
        *fail_mask_out = mask;
    }
    return mask == 0u ? 1 : 0;
}

// 非 Apple 平台无 Security.framework/__APPLE__ Mach-O 序言可校验：
// 统一 fail-open 返回成功，避免把“不支持”误判为 Hook。
#else /* !__APPLE__ */

// 失败位输出可选；返回恒为 1。
int cprisk_verify_trust_hook_surface_integrity(uint32_t *fail_mask_out) {
    if (fail_mask_out != NULL) {
        *fail_mask_out = 0u;
    }
    return 1;
}

#endif /* __APPLE__ */
