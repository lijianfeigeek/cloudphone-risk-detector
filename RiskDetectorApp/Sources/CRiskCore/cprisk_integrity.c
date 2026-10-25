// CRiskCore 多路径完整性校验（cprisk-armor ABI v3）。
// 三条独立路径计算 __TEXT.__text 摘要：A=vm_read_overwrite、B=直接指针、C=从 4 个 split anchor lane 重建。
// 合并摘要与 anchor 摘要会进入 CPRisk-MAC 校验和密钥派生，因此任何篡改都会污染派生密钥。
// 线程模型：init/cleanup 由 Swift start() 在并发 evaluate() 之前单线程调用；就绪位为原子发布，运行期读取接受弱一致。
// 失败语义：所有校验与初始化路径 fail-closed——失败时输出 0xFF 占位或就绪位清零，调用方得到欺骗材料或明确错误码。
// 平台/架构：Mach VM 路径仅 Apple 平台；MTE 代码由 CPRISK_MTE_COMPILE_SUPPORT 编译开关控制。

#include "include/CRiskCore.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#ifdef __APPLE__
#include <TargetConditionals.h>
#endif
#include "include/cprisk_macho.h"
#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"
#include "include/cprisk_instruction_cache.h"

// ABI 约束：内联 SHA-256 输出长度必须与 armor 的 32 字节摘要槽一致，
// 否则三路拼接、MAC 校验与 anchor lane 布局都会错位。
_Static_assert(CPRISK_SHA256_DIGEST_LENGTH == CPRISK_ARMOR_HASH_SIZE,
               "inline SHA256 digest size must match armor ABI");

/* ── internal ──────────────────────────────────────────────────────── */

/* Single-thread assumption: cprisk_init_protection / cprisk_prepare_deception_material_i
 * are called from Swift start() before any concurrent evaluate().
 * Init/cleanup are single-threaded by contract (Swift start() runs
 * before any concurrent evaluate()); the ready flags below are _Atomic
 * so concurrent readers observe publication safely (issue 37). */
// 运行时材料：init 成功后由密钥派生链生成，供 cprisk_get_runtime_material 读取。
// ready 为 _Atomic：init 单线程写入，evaluate/并发读线程通过它观察“发布完成”，
// 避免读到半初始化字节（issue 37）。
static uint8_t s_runtime_material[CPRISK_ARMOR_HASH_SIZE];
static _Atomic int s_runtime_material_ready;

/* Hybrid KDF state: three-layer key derivation.
 *   Layer 1: rootKey       (CLI provided)
 *   Layer 2: deviceKey    = CPRisk-MAC(rootKey, deviceSalt)
 *   Layer 3: effectiveRoot = CPRisk-MAC(deviceKey, sessionToken)
 *
 * effectiveRoot is stored in s_effective_root and used in place of
 * root_key for all subsequent derivations (white-box domain evaluation,
 * loader key, runtime material).  This binds the entire key chain to
 * both the physical device and the current session. */
// 三层 Hybrid KDF 状态（由 cprisk_init_hybrid_kdf 单线程填充）：
//   Layer 1 rootKey       = 调用方提供的 32 字节全熵密钥；
//   Layer 2 deviceKey     = CPRisk-MAC(rootKey, deviceSalt)，绑定物理设备；
//   Layer 3 effectiveRoot = CPRisk-MAC(deviceKey, sessionKey)，再绑定当前会话。
// effectiveRoot 取代 rootKey 供动态 white-box 域与后续派生使用。
static uint8_t s_device_key[CPRISK_ARMOR_KEY_SIZE];
static int s_device_key_ready;
// 对外的最终根密钥：任一上游密钥或 __TEXT 完整性被篡改都会让派生值改变，
// 依赖它的解密/签名路径随之失败（fail-closed）。设备绑定失败时保持未就绪。
static uint8_t s_effective_root[CPRISK_ARMOR_KEY_SIZE];
static int s_effective_root_ready;

/* Non-static so cprisk_anti_dump_probe.c can set it when dump/injection is detected. */
// 欺骗模式开关：由反 dump 探针等跨模块置位。置位后所有诊断 getter 返回 0，
// runtime material 输出欺骗值而非真实材料，避免给攻击者提供可验证的 oracle。
volatile int s_integrity_deception_active;
// 欺骗材料缓存：首次需要时派生并以原子 ready 发布；投毒/被调试时作为对外输出。
// 后续 lane 投毒可就地扰动其字节（tweak_deception），使不同攻击路径得到不同假值。
static uint8_t s_deception_material[CPRISK_ARMOR_HASH_SIZE];
static _Atomic int s_deception_material_ready;

// init 时保存的完整性基线，供 cprisk_recheck_integrity 周期性比对。
// saved 标志必须先于并发 recheck 发布；poisoned 是全局“输出不可信”锁存位，
// 一旦置 1 只能由 init/cleanup/测试钩子清除，运行期不会自行恢复。
static uint8_t s_saved_integrity_hash[CPRISK_ARMOR_HASH_SIZE];
static int s_integrity_hash_saved;
static int s_integrity_poisoned;

/* Distinct semantic bookkeeping per poison entry point (anti batch-NOP / single-hook). */
// 投毒语义记账：每条 lane 独立计数，用于诊断“哪条域触发了几次”，
// 也让批量 NOP 掉单一函数或单一 hook 无法同时抹掉所有 lane 的痕迹。
// 这些是弱一致的 volatile/普通读写，不是同步原语；欺骗模式下 getter 统一返回 0。
static volatile uint32_t s_poison_lane_seq[CPRISK_POISON_LANE_COUNT];
static volatile uint32_t s_poison_semantic_breadcrumb;
// rolling 是两字 XOR 折叠累加器，为 deception tweak 提供随 lane 与触发顺序变化的盐；
// breadcrumb 低位记录“哪些 lane 触发过”（lane < 32），高位是每 lane 不同旋转量的折叠。
static uint32_t s_poison_semantic_rolling[2];
/* Poison-wave / ordering state: downstream material mix depends on more than s_integrity_poisoned alone. */
// epoch 每次投毒副作用批 +1；cause_mix 以“lane + 发生顺序”混合。
// 二者会进入 runtime material 输出混合与 high-signal lane 选择，
// 因此下游材料不只取决于 s_integrity_poisoned 一个布尔值。
static volatile uint32_t s_poison_epoch;
static volatile uint64_t s_poison_cause_mix;

/* Staged / deferred poison: weak-signal lanes accumulate opaque hits before full commit.
 * Thresholds are compile-time tunable; partial hits mix into cause/rolling state without
 * incrementing per-lane seq (avoids a linear “distance-to-poison” oracle). */
// staged 阈值（编译期可覆盖）：watchdog/anti-dump 属弱信号，需累计多次才完整投毒。
// watchdog 默认 5：吸收后台拉取/低电量调度抖动；真实攻击信号连续出现仍会在预算内提交。
// anti-dump 默认 4：该探针调用更密集，留余量避免低端机 GC/内存压力造成单迭代误报。
#ifndef CPRISK_POISON_STAGED_WATCHDOG_THRESHOLD
/* Raised 3→5: absorbs transient BG-fetch / low-battery scheduling noise;
 * real attacker signals are consecutive and still commit well within budget. */
#define CPRISK_POISON_STAGED_WATCHDOG_THRESHOLD 5u
#endif
#ifndef CPRISK_POISON_STAGED_ANTI_DUMP_THRESHOLD
/* Raised 2→4: anti-dump probe runs at tighter cadence; extra margin removes
 * GC-pause / memory-pressure single-iteration false positives on low-end devices. */
#define CPRISK_POISON_STAGED_ANTI_DUMP_THRESHOLD 4u
#endif

// staged 命中计数与不透明 tick（原子：探针可能从不同线程累加）。
// 未达阈值时只做 staged_note、不递增 lane seq，避免攻击者通过“还差几次”做线性推断。
static atomic_uint_fast32_t s_staged_watchdog_hits;
static atomic_uint_fast32_t s_staged_anti_dump_hits;
static atomic_uint_fast64_t s_staged_opacity_tick;
/**
 * Staged watchdog slow-poison: after the first time the staged hit counter reaches the threshold,
 * we enter a non-terminal "slow wave" (stronger staged_note / cause_mix only; \c s_integrity_poisoned
 * stays 0). A second threshold completion commits full lane poison. Observability: \c
 * cprisk_get_integrity_watchdog_slow_poison_phase().
 */
// slow wave 阶段：第一个阈值完成后进入非终态“慢波”，加重降级但不置 s_integrity_poisoned；
// 第二个阈值完成才完整提交。对外由 cprisk_get_integrity_watchdog_slow_poison_phase 观测。
static atomic_uint_fast32_t s_staged_watchdog_slow_wave;

#if defined(CPRISK_MTE_COMPILE_SUPPORT)
// MTE 可用时给 runtime material / 保存的完整性基线加 canary。
// recheck 时 -1 表示基线不符（篡改），-2 表示平台不支持/未安装（合法状态，不投毒）。
static cprisk_mte_canary_state_t s_runtime_material_canary;
static cprisk_mte_canary_state_t s_saved_integrity_canary;
#endif

// 最近一次 init 的单调时钟耗时，用于启动时序反调试阈值判断；
// 异常偏慢可能意味着被调试/插桩。非原子，弱一致，仅作诊断。
static uint64_t s_init_elapsed_ns;

/* SDK-configurable anti-debug tier (production vs dev/QA relaxed). */
// SDK 配置的加固档位：生产 / 开发联调 / App Store 安全。
// 档位影响弱信号是否计分以及 init 时序阈值；默认生产档。
static int s_runtime_hardening_mode = CPRISK_RUNTIME_HARDENING_PRODUCTION;
// 测试钩子覆盖的 init 时序阈值（纳秒）；0 表示按机型与档位实时计算。
// 仅 DEBUG 构建可写，Release 下保持 0。
static uint64_t s_init_timing_threshold_override_ns;

// init 时序基线 5s，再按机型代际增加 slack；RELAXED_DEV_QA / APP_STORE_SAFE
// 额外放宽 10s，避免 CI 冷启动或商店审核环境被误判为调试器。
#define CPRISK_INIT_TIMING_BASE_NS 5000000000ULL
#define CPRISK_INIT_TIMING_RELAXED_EXTRA_NS 10000000000ULL

static const struct mach_header_64 *cprisk_own_hdr_i(void);
static uint64_t cprisk_monotonic_ns(void);

// 前向声明：Hybrid KDF 实际实现在独立模块，本文件只负责编排与状态发布。
/* Forward declarations for Hybrid KDF (implemented in separate modules). */
int cprisk_derive_device_key(
    const uint8_t *root_key,
    uint8_t out_device_key[CPRISK_ARMOR_KEY_SIZE]
);
int cprisk_get_session_key(uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]);

// 前向声明：欺骗材料派生/发布（定义见下方），供反调试策略与投毒路径提前调用。
static void cprisk_prepare_deception_material_i(
    const uint8_t *root_material,
    const uint8_t *full_anchor_hash,
    const uint8_t *integrity_hash
);

extern void cprisk_watchdog_note_guard_page_fault(void);

// 极简字节码：仅支持 HALT 与 XOR_IMM，把 loader key / runtime material
// 从明显常量形态改成“运行时解释执行”的形态；未知 opcode 或截断立即数立即停止。
/* Minimal bytecode bootstrap (loader key): single HALT = identity; extend with new opcodes if needed. */
enum {
    CPRISK_MV_OP_HALT = 0,
    CPRISK_MV_OP_XOR_IMM = 1,
};

// 就地解释执行 mini VM：输入 code/len 由调用方拥有，输出写入 32 字节 buf。
// 无内存分配、无错误码、可重入；HALT/未知 opcode/截断都只是提前返回（保留当前值）。
static void cprisk_mini_vm_exec_buf(uint8_t buf[32], const uint8_t *code, size_t len) {
    size_t pc = 0;
    while (pc < len) {
        uint8_t op = code[pc++];
        if (op == CPRISK_MV_OP_HALT)
            return;
        if (op == CPRISK_MV_OP_XOR_IMM && pc < len) {
            uint8_t imm = code[pc++];
            for (size_t i = 0; i < 32; i++)
                buf[i] = (uint8_t)(buf[i] ^ imm);
        } else {
            return;
        }
    }
}

/* Deterministic non-identity bootstrap: XOR_IMM then HALT (was pure HALT). */
// 固定 bootstrap 程序：XOR_IMM(0xA5) 后 HALT，确保变换不是恒等映射，
// 与 producer 端约定一致；改动会破坏数据段解密。
static void cprisk_mini_vm_bootstrap_material32(uint8_t buf[32]) {
    const uint8_t prog[] = {
        CPRISK_MV_OP_XOR_IMM,
        CPRISK_MINI_VM_BOOTSTRAP_XOR,
        CPRISK_MV_OP_HALT
    };
    cprisk_mini_vm_exec_buf(buf, prog, sizeof(prog));
}

// loader key 的 bootstrap 包装；与 cprisk_mini_vm_bootstrap_material32 共用同一程序。
static void cprisk_loader_key_mini_vm_bootstrap(uint8_t key[32]) {
    cprisk_mini_vm_bootstrap_material32(key);
}

// 仅 DEBUG 或显式编译开关下允许用环境变量 CPRISK_DISABLE_MINI_VM_BOOTSTRAP 关闭 bootstrap；
// Release 构建忽略环境，避免攻击者通过环境变量绕过运行时材料变换。
#if (defined(DEBUG) && DEBUG) || defined(CPRISK_ALLOW_MINI_VM_BOOTSTRAP_ENV_BYPASS)
static int cprisk_mini_vm_bootstrap_disabled(void) {
    static int s_cached = -1;
    if (s_cached >= 0)
        return s_cached;
    const char *e = getenv("CPRISK_DISABLE_MINI_VM_BOOTSTRAP");
    s_cached = (e && (e[0] == '1' || e[0] == 'y' || e[0] == 'Y')) ? 1 : 0;
    return s_cached;
}
#else
static int cprisk_mini_vm_bootstrap_disabled(void) {
    /* Release: ignore env; optional unit-test override via compile flag above. */
    return 0;
}
#endif

// 硬崩溃默认关闭：确认调试器时优先“记录 + 投毒 + 欺骗”，
// 避免误报杀掉可能合法的会话；只有显式编译开关才允许 __builtin_trap。
#ifndef CPRISK_ANTI_DEBUG_HARD_CRASH_ON_DEBUGGER
#define CPRISK_ANTI_DEBUG_HARD_CRASH_ON_DEBUGGER 0
#endif

enum {
    // 反调试计划解析结果：写入 plan/snapshot；任何非 OK 都表示该 section 不可用，
    // 但计划缺失在未加固构建中是合法状态，因此解析失败本身不投毒。
    CPRISK_ADBG_PARSE_OK_I = 0u,
    CPRISK_ADBG_PARSE_TRUNCATED_I = 1u,
    CPRISK_ADBG_PARSE_MAGIC_I = 2u,
    CPRISK_ADBG_PARSE_VERSION_I = 3u,
    CPRISK_ADBG_PARSE_LAYOUT_I = 4u,
    CPRISK_ADBG_PARSE_BOUNDS_I = 5u,
    CPRISK_ADBG_PARSE_TOO_MANY_ENTRIES_I = 6u
};

enum {
    // 策略应用触发位：区分 init 成功路径、init 失败、运行期完整性篡改。
    CPRISK_ADBG_TRIGGER_INIT_I = 1u << 0,
    CPRISK_ADBG_TRIGGER_INIT_FAILURE_I = 1u << 1,
    CPRISK_ADBG_TRIGGER_INTEGRITY_TAMPER_I = 1u << 2
};

// 运行期反调试计划（从 __DATA.__objc_data2 解析）：init 单线程填充，运行期只读。
// probe_immediate/seed 参与决定哪些 patch 条目生效，policy_union_bits 是条目策略的并集。
typedef struct cprisk_adbg_runtime_plan_i {
    uint32_t loaded;
    uint32_t section_present;
    uint32_t section_valid;
    uint32_t parse_error;
    uint32_t entry_count;
    uint32_t policy_union_bits;
    uint64_t seed;
    uint64_t text_base_address;
    uint32_t probe_immediate;
} cprisk_adbg_runtime_plan_t;

// 单个 patch site 条目：vm_offset 相对 __text，运行时加 slide 得到真实地址；
// policy_bits 决定该站点响应类型，entry_flags 控制是否允许 inline patch / runtime gate。
typedef struct cprisk_adbg_runtime_entry_i {
    uint64_t identifier_hash;
    uint64_t patch_site_vm_offset;
    uint32_t patch_site_file_offset;
    uint32_t policy_bits;
    uint32_t entry_flags;
    uint32_t scatter_slot;
} cprisk_adbg_runtime_entry_t;

// 计划解析缓存与快照：plan 供运行期只读；snapshot 汇总计数/最近策略，供 Swift 查询。
// reset 只在 init/cleanup/测试单线程路径调用；运行期读取为弱一致。
static cprisk_adbg_runtime_plan_t s_adbg_plan_i;
static cprisk_antidebug_plan_snapshot_t s_adbg_snapshot_i;
static cprisk_adbg_runtime_entry_t s_adbg_entries_i[CPRISK_MAX_ENTRY_COUNT];
static uint32_t s_adbg_entry_count_i = 0u;
// 已写入 BRK 的 gate 站点与原子状态：armed 表示 gate 已生效，tamper 锁存异常；
// 二者用原子存储发布，异常处理线程可并发读取。
static uintptr_t s_adbg_inline_patch_sites_i[CPRISK_MAX_ENTRY_COUNT];
static uint32_t s_adbg_inline_patch_count_i = 0u;
static atomic_uint_fast32_t s_adbg_inline_patch_armed_i = 0u;
static atomic_uint_fast32_t s_adbg_inline_patch_tamper_i = 0u;
// 仅 DEBUG 使用的测试计划注入区；替换/清理时先 secure_zero 再 free，
// 新缓冲区由本模块拥有。非 DEBUG 构建的测试入口直接返回。
static uint8_t *s_test_adbg_plan_i = NULL;
static size_t s_test_adbg_plan_len_i = 0u;

// 手写 32 位 popcount，避免依赖编译器内建或引入额外符号；
// 用于统计强/弱探针的命中数量。
static uint32_t cprisk_popcount32_i(uint32_t value) {
    uint32_t count = 0u;
    while (value != 0u) {
        count += value & 1u;
        value >>= 1u;
    }
    return count;
}

// 乘法溢出检查：失败返回 -1 且不写 *out，
// 防止 entry_count * entry_size 回绕后导致越界解析。
static int cprisk_mul_size_checked_i(size_t lhs, size_t rhs, size_t *out) {
    if (out == NULL)
        return -1;
    if (lhs != 0u && rhs > SIZE_MAX / lhs)
        return -1;
    *out = lhs * rhs;
    return 0;
}

// 清空计划解析状态（含原子 armed/tamper）；仅在 init/cleanup/测试单线程路径调用。
static void cprisk_antidebug_reset_plan_state_i(void) {
    memset(&s_adbg_plan_i, 0, sizeof(s_adbg_plan_i));
    memset(&s_adbg_snapshot_i, 0, sizeof(s_adbg_snapshot_i));
    memset(s_adbg_entries_i, 0, sizeof(s_adbg_entries_i));
    memset(s_adbg_inline_patch_sites_i, 0, sizeof(s_adbg_inline_patch_sites_i));
    s_adbg_entry_count_i = 0u;
    s_adbg_inline_patch_count_i = 0u;
    atomic_store(&s_adbg_inline_patch_armed_i, 0u);
    atomic_store(&s_adbg_inline_patch_tamper_i, 0u);
}

// 优先返回测试注入的计划字节；否则从自身 Mach-O 的 __DATA 段查找反调试 section。
// 返回 0 且 *out_* 为 NULL/0 表示 section 不存在（合法）；返回 -1 表示入参或 header 不可用。
static int cprisk_antidebug_section_bytes_i(const uint8_t **out_bytes, size_t *out_len) {
    if (!out_bytes || !out_len)
        return -1;

    *out_bytes = NULL;
    *out_len = 0u;

    if (s_test_adbg_plan_i != NULL && s_test_adbg_plan_len_i > 0u) {
        *out_bytes = s_test_adbg_plan_i;
        *out_len = s_test_adbg_plan_len_i;
        return 0;
    }

    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    if (!hdr)
        return -1;

    unsigned long sec_size = 0;
    const uint8_t *sec = cprisk_find_section(
        hdr,
        CPRISK_ARMOR_SEGMENT_DATA,
        CPRISK_ARMOR_SECTION_ANTI_DEBUG_PLAN,
        &sec_size);
    if (!sec || sec_size == 0u)
        return 0;

    *out_bytes = sec;
    *out_len = (size_t)sec_size;
    return 0;
}

// 惰性加载并解析反调试计划：loaded 标志保证只解析一次。
// 所有边界（截断/魔数/版本/布局/条目数/乘法溢出）先校验再 memcpy；
// 失败只记录 parse_error，不投毒——计划缺失在未加固构建中合法。
static void cprisk_antidebug_load_plan_i(void) {
    if (s_adbg_plan_i.loaded != 0u)
        return;

    s_adbg_plan_i.loaded = 1u;

    const uint8_t *bytes = NULL;
    size_t bytes_len = 0u;
    if (cprisk_antidebug_section_bytes_i(&bytes, &bytes_len) != 0 || bytes == NULL || bytes_len == 0u) {
        return;
    }

    s_adbg_plan_i.section_present = 1u;
    s_adbg_snapshot_i.section_present = 1u;

    if (bytes_len < sizeof(struct cprisk_armor_antidebug_header)) {
        s_adbg_plan_i.parse_error = CPRISK_ADBG_PARSE_TRUNCATED_I;
        s_adbg_snapshot_i.parse_error = CPRISK_ADBG_PARSE_TRUNCATED_I;
        return;
    }

    struct cprisk_armor_antidebug_header header;
    memcpy(&header, bytes, sizeof(header));

    if (header.magic != CPRISK_ARMOR_ADBG_MAGIC) {
        s_adbg_plan_i.parse_error = CPRISK_ADBG_PARSE_MAGIC_I;
        s_adbg_snapshot_i.parse_error = CPRISK_ADBG_PARSE_MAGIC_I;
        return;
    }
    if (header.version < CPRISK_ARMOR_ADBG_ABI_VERSION) {
        s_adbg_plan_i.parse_error = CPRISK_ADBG_PARSE_VERSION_I;
        s_adbg_snapshot_i.parse_error = CPRISK_ADBG_PARSE_VERSION_I;
        return;
    }
    if (header.header_size < sizeof(struct cprisk_armor_antidebug_header) ||
        header.entry_size < sizeof(struct cprisk_armor_antidebug_entry)) {
        s_adbg_plan_i.parse_error = CPRISK_ADBG_PARSE_LAYOUT_I;
        s_adbg_snapshot_i.parse_error = CPRISK_ADBG_PARSE_LAYOUT_I;
        return;
    }
    if (header.entry_count > CPRISK_MAX_ENTRY_COUNT) {
        s_adbg_plan_i.parse_error = CPRISK_ADBG_PARSE_TOO_MANY_ENTRIES_I;
        s_adbg_snapshot_i.parse_error = CPRISK_ADBG_PARSE_TOO_MANY_ENTRIES_I;
        return;
    }

    size_t entries_bytes = 0u;
    if (cprisk_mul_size_checked_i((size_t)header.entry_count, (size_t)header.entry_size, &entries_bytes) != 0) {
        s_adbg_plan_i.parse_error = CPRISK_ADBG_PARSE_BOUNDS_I;
        s_adbg_snapshot_i.parse_error = CPRISK_ADBG_PARSE_BOUNDS_I;
        return;
    }
    if ((size_t)header.header_size > bytes_len || entries_bytes > bytes_len - (size_t)header.header_size) {
        s_adbg_plan_i.parse_error = CPRISK_ADBG_PARSE_BOUNDS_I;
        s_adbg_snapshot_i.parse_error = CPRISK_ADBG_PARSE_BOUNDS_I;
        return;
    }

    const uint8_t *entry_cursor = bytes + (size_t)header.header_size;
    uint32_t policy_union = 0u;
    uint32_t parsed_entries = 0u;
    for (uint32_t i = 0u; i < header.entry_count; i++) {
        struct cprisk_armor_antidebug_entry entry;
        memcpy(&entry, entry_cursor, sizeof(entry));
        policy_union |= entry.policy_bits;
        if (parsed_entries < CPRISK_MAX_ENTRY_COUNT) {
            s_adbg_entries_i[parsed_entries].identifier_hash = entry.identifier_hash;
            s_adbg_entries_i[parsed_entries].patch_site_vm_offset = entry.patch_site_vm_offset;
            s_adbg_entries_i[parsed_entries].patch_site_file_offset = entry.patch_site_file_offset;
            s_adbg_entries_i[parsed_entries].policy_bits = entry.policy_bits;
            s_adbg_entries_i[parsed_entries].entry_flags = entry.entry_flags;
            s_adbg_entries_i[parsed_entries].scatter_slot = entry.scatter_slot;
            parsed_entries += 1u;
        }
        entry_cursor += (size_t)header.entry_size;
    }
    s_adbg_entry_count_i = parsed_entries;

    s_adbg_plan_i.section_valid = 1u;
    s_adbg_plan_i.parse_error = CPRISK_ADBG_PARSE_OK_I;
    s_adbg_plan_i.entry_count = header.entry_count;
    s_adbg_plan_i.policy_union_bits = policy_union;
    s_adbg_plan_i.seed = header.seed;
    s_adbg_plan_i.text_base_address = header.text_base_address;
    s_adbg_plan_i.probe_immediate = header.probe_immediate;

    s_adbg_snapshot_i.section_valid = 1u;
    s_adbg_snapshot_i.parse_error = CPRISK_ADBG_PARSE_OK_I;
    s_adbg_snapshot_i.entry_count = header.entry_count;
    s_adbg_snapshot_i.policy_union_bits = policy_union;
}

// BRK #imm 编码：0xD4200000 | (imm << 5)，imm 取 CPRISK_BRK_IMM_RUNTIME_GATE。
// 该立即数由运行时写入 __text，异常处理器据此区分“自己的 gate”与外部断点。
#define CPRISK_ADBG_RUNTIME_GATE_BRK_INSTR \
    (0xD4200000u | ((uint32_t)CPRISK_BRK_IMM_RUNTIME_GATE << 5u))

// 判断 addr 及 4 字节指令是否完整落在 __text 内；
// start+size 发生回绕时返回 0（失败即拒绝），防止对段外地址打补丁。
static int cprisk_antidebug_addr_in_text_i(
    uintptr_t addr,
    const uint8_t *text_base,
    size_t text_size
) {
    if (text_base == NULL || text_size < sizeof(uint32_t)) {
        return 0;
    }
    const uintptr_t start = (uintptr_t)text_base;
    const uintptr_t end = start + text_size;
    if (end < start) {
        return 0;
    }
    return (addr >= start && (addr + sizeof(uint32_t)) <= end) ? 1 : 0;
}

// 在 patch_addr 写入 runtime-gate BRK：
// 4 字节对齐 → 已是目标指令则幂等返回 → 发现其它 BRK 视为篡改 →
// 查询原页保护 → 临时 RW → 写入并刷指令缓存 → 恢复保护。
// 任一步失败返回 -1；out_tamper 仅表示“发现他人 BRK”，不表示本次写入失败。
static int cprisk_antidebug_patch_site_i(uintptr_t patch_addr, int *out_tamper) {
    if (out_tamper != NULL) {
        *out_tamper = 0;
    }
    if ((patch_addr & 0x3u) != 0u) {
        return -1;
    }

    uint32_t original_instr = 0u;
    memcpy(&original_instr, (const void *)patch_addr, sizeof(original_instr));
    if (original_instr == CPRISK_ADBG_RUNTIME_GATE_BRK_INSTR) {
        return 0;
    }
    if ((original_instr & 0xFFE00000u) == 0xD4200000u) {
        if (out_tamper != NULL) {
            *out_tamper = 1;
        }
        return -1;
    }

    const uintptr_t page_addr = patch_addr & ~(uintptr_t)0xFFFu;
    int restore_prot = PROT_READ | PROT_EXEC;
    vm_address_t region_addr = (vm_address_t)patch_addr;
    vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;
    if (vm_region_64(mach_task_self(),
                     &region_addr,
                     &region_size,
                     VM_REGION_BASIC_INFO_64,
                     (vm_region_info_t)&info,
                     &info_count,
                     &object_name) == KERN_SUCCESS) {
        if (object_name != MACH_PORT_NULL)
            mach_port_deallocate(mach_task_self(), object_name);
        int queried = (int)info.protection & (PROT_READ | PROT_WRITE | PROT_EXEC);
        if (queried != 0) {
            restore_prot = queried;
        }
    }

    if (cprisk_mprotect_direct((void *)page_addr, 0x1000u, PROT_READ | PROT_WRITE, NULL) != 0) {
        return -1;
    }

    const uint32_t patched_instr = CPRISK_ADBG_RUNTIME_GATE_BRK_INSTR;
    memcpy((void *)patch_addr, &patched_instr, sizeof(patched_instr));
    cprisk_flush_instruction_cache((void *)patch_addr, sizeof(patched_instr));

    if (cprisk_mprotect_direct((void *)page_addr, 0x1000u, restore_prot, NULL) != 0) {
        if (cprisk_mprotect_direct((void *)page_addr, 0x1000u, PROT_READ | PROT_EXEC, NULL) != 0) {
            return -1;
        }
    }
    return 0;
}

// 应用 inline patch gate：只处理同时声明 INLINE_PATCH 与 RUNTIME_GATE 的条目。
// 返回 1=至少打了一个补丁，0=无 section/已 armed/无需处理，
// -1=有失败并已投毒 anti-debug lane。地址越界或页保护失败都会累加 failure 并 fail-closed。
static int cprisk_antidebug_apply_inline_patch_gate_i(void) {
    cprisk_antidebug_load_plan_i();
    if (s_adbg_plan_i.section_valid == 0u) {
        return 0;
    }
    if (atomic_load(&s_adbg_inline_patch_armed_i) != 0u) {
        return 0;
    }

    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    unsigned long text_size_ul = 0u;
    const uint8_t *text_base =
        hdr != NULL ? cprisk_find_section(hdr, "__TEXT", "__text", &text_size_ul) : NULL;
    const size_t text_size = (size_t)text_size_ul;
    if (text_base == NULL || text_size < sizeof(uint32_t)) {
        s_adbg_snapshot_i.inline_patch_failure_count += 1u;
        atomic_store(&s_adbg_inline_patch_tamper_i, 1u);
        s_adbg_snapshot_i.last_inline_patch_tamper = 1u;
        cprisk_integrity_poison_antidebug_lane();
        return -1;
    }

    const intptr_t slide = cprisk_compute_slide(hdr);
    const uintptr_t runtime_text_base =
        (uintptr_t)((intptr_t)s_adbg_plan_i.text_base_address + slide);
    uint32_t patched_count = 0u;
    uint32_t failure_count = 0u;
    int tamper_detected = 0;

    for (uint32_t i = 0u; i < s_adbg_entry_count_i; i++) {
        const cprisk_adbg_runtime_entry_t *entry = &s_adbg_entries_i[i];
        const int allow_inline =
            (entry->entry_flags & CPRISK_ARMOR_ADBG_ENTRY_FLAG_INLINE_PATCH_RESERVED) != 0u;
        const int allow_gate =
            (entry->entry_flags & CPRISK_ARMOR_ADBG_ENTRY_FLAG_RUNTIME_GATE_RESERVED) != 0u ||
            (entry->policy_bits & CPRISK_ARMOR_ADBG_POLICY_RUNTIME_GATE) != 0u;
        if (!allow_inline || !allow_gate) {
            continue;
        }
        if (entry->patch_site_vm_offset > (uint64_t)(UINTPTR_MAX - runtime_text_base)) {
            failure_count += 1u;
            tamper_detected = 1;
            continue;
        }

        const uintptr_t patch_addr = runtime_text_base + (uintptr_t)entry->patch_site_vm_offset;
        if (!cprisk_antidebug_addr_in_text_i(patch_addr, text_base, text_size)) {
            failure_count += 1u;
            tamper_detected = 1;
            continue;
        }

        int tamper_here = 0;
        if (cprisk_antidebug_patch_site_i(patch_addr, &tamper_here) != 0) {
            failure_count += 1u;
            tamper_detected |= tamper_here;
            continue;
        }

        int duplicate = 0;
        for (uint32_t j = 0u; j < patched_count; j++) {
            if (s_adbg_inline_patch_sites_i[j] == patch_addr) {
                duplicate = 1;
                break;
            }
        }
        if (!duplicate && patched_count < CPRISK_MAX_ENTRY_COUNT) {
            s_adbg_inline_patch_sites_i[patched_count] = patch_addr;
            patched_count += 1u;
        }
    }

    s_adbg_inline_patch_count_i = patched_count;
    s_adbg_snapshot_i.inline_patch_count = patched_count;
    s_adbg_snapshot_i.inline_patch_failure_count += failure_count;
    s_adbg_snapshot_i.inline_patch_armed = patched_count > 0u ? 1u : 0u;
    if (tamper_detected) {
        s_adbg_snapshot_i.last_inline_patch_tamper = 1u;
    }
    atomic_store(&s_adbg_inline_patch_armed_i, patched_count > 0u ? 1u : 0u);
    atomic_store(&s_adbg_inline_patch_tamper_i, tamper_detected ? 1u : 0u);

    if (failure_count != 0u) {
        cprisk_integrity_poison_antidebug_lane();
        return -1;
    }
    return patched_count > 0u ? 1 : 0;
}

enum {
    // inline gate 健康检查位：BRK 丢失（被还原）、页可写（保护被改）、站点跑出 __text；
    // 任一位置位都锁存 tamper 并投毒 anti-debug lane。
    CPRISK_ADBG_INLINE_GATE_HEALTH_BRK_MISSING_I = 1u << 0,
    CPRISK_ADBG_INLINE_GATE_HEALTH_PAGE_WRITABLE_I = 1u << 1,
    CPRISK_ADBG_INLINE_GATE_HEALTH_SITE_OUTSIDE_TEXT_I = 1u << 2,
};

// 通过 vm_region_64 查询地址所在区域保护：成功返回 0，*out_prot 为 PROT_* 子集；
// 失败返回 -1。会 deallocate 返回的 object_name，避免 Mach 端口泄漏。
static int cprisk_antidebug_query_page_prot_i(uintptr_t addr, int *out_prot) {
    if (!out_prot) {
        return -1;
    }
    *out_prot = 0;
    vm_address_t region_addr = (vm_address_t)addr;
    vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;
    const kern_return_t kr = vm_region_64(
        mach_task_self(),
        &region_addr,
        &region_size,
        VM_REGION_BASIC_INFO_64,
        (vm_region_info_t)&info,
        &info_count,
        &object_name);
    if (object_name != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), object_name);
    }
    if (kr != KERN_SUCCESS) {
        return -1;
    }
    *out_prot = (int)info.protection & (PROT_READ | PROT_WRITE | PROT_EXEC);
    return 0;
}

// 校验已 armed 的 gate 是否仍然完好；未 armed 时直接返回 0（无 gate 可查）。
// 返回健康位掩码；非 0 时同时锁存 tamper、累加失败计数并投毒 anti-debug lane。
// 线程安全：只读取 patch 站点数组与页保护，可与投毒并发；结果弱一致。
uint32_t cprisk_antidebug_inline_gate_health_mask(void) {
    cprisk_antidebug_load_plan_i();
    if (atomic_load(&s_adbg_inline_patch_armed_i) == 0u || s_adbg_inline_patch_count_i == 0u) {
        return 0u;
    }

    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    unsigned long text_size_ul = 0u;
    const uint8_t *text_base =
        hdr != NULL ? cprisk_find_section(hdr, "__TEXT", "__text", &text_size_ul) : NULL;
    const size_t text_size = (size_t)text_size_ul;
    if (text_base == NULL || text_size < sizeof(uint32_t)) {
        atomic_store(&s_adbg_inline_patch_tamper_i, 1u);
        s_adbg_snapshot_i.last_inline_patch_tamper = 1u;
        s_adbg_snapshot_i.inline_patch_failure_count += 1u;
        cprisk_integrity_poison_antidebug_lane();
        return CPRISK_ADBG_INLINE_GATE_HEALTH_SITE_OUTSIDE_TEXT_I;
    }

    uint32_t mask = 0u;
    for (uint32_t i = 0u; i < s_adbg_inline_patch_count_i; i++) {
        const uintptr_t patch_addr = s_adbg_inline_patch_sites_i[i];
        if (!cprisk_antidebug_addr_in_text_i(patch_addr, text_base, text_size)) {
            mask |= CPRISK_ADBG_INLINE_GATE_HEALTH_SITE_OUTSIDE_TEXT_I;
            continue;
        }

        uint32_t instr = 0u;
        memcpy(&instr, (const void *)patch_addr, sizeof(instr));
        if (instr != CPRISK_ADBG_RUNTIME_GATE_BRK_INSTR) {
            mask |= CPRISK_ADBG_INLINE_GATE_HEALTH_BRK_MISSING_I;
        }

        int prot = 0;
        if (cprisk_antidebug_query_page_prot_i(patch_addr, &prot) == 0 && (prot & PROT_WRITE) != 0) {
            mask |= CPRISK_ADBG_INLINE_GATE_HEALTH_PAGE_WRITABLE_I;
        }
    }

    if (mask != 0u) {
        atomic_store(&s_adbg_inline_patch_tamper_i, 1u);
        s_adbg_snapshot_i.last_inline_patch_tamper = 1u;
        s_adbg_snapshot_i.inline_patch_failure_count += 1u;
        cprisk_integrity_poison_antidebug_lane();
    }
    return mask;
}

// 判断 brk_pc 是否属于本进程写入的 runtime gate 站点；
// 用于异常处理器区分合法 BRK 与外部调试断点。
static int cprisk_antidebug_is_runtime_gate_site_i(uintptr_t brk_pc) {
    if (brk_pc == 0u || s_adbg_inline_patch_count_i == 0u) {
        return 0;
    }
    for (uint32_t i = 0u; i < s_adbg_inline_patch_count_i; i++) {
        if (s_adbg_inline_patch_sites_i[i] == brk_pc) {
            return 1;
        }
    }
    return 0;
}

// 异常处理器入口：只处理 RUNTIME_GATE 立即数。
// 返回 0=不是本模块的 BRK（交回系统），1=已消费并继续执行，
// -1=站点未 armed/不在白名单，或检测到跟踪/交叉校验不一致——
// 此时投毒 anti-debug lane，由调用方决定终止或降级（fail-closed）。
int cprisk_exception_handler_handle_runtime_gate_brk(uint16_t brk_imm, uintptr_t brk_pc) {
    if (brk_imm != (uint16_t)CPRISK_BRK_IMM_RUNTIME_GATE) {
        return 0;
    }

    const int armed = atomic_load(&s_adbg_inline_patch_armed_i) != 0u;
    int tamper = atomic_load(&s_adbg_inline_patch_tamper_i) != 0u;
    if (!armed || !cprisk_antidebug_is_runtime_gate_site_i(brk_pc)) {
        tamper = 1;
    }

    if (tamper || cprisk_is_being_traced_redundant() != 0 || cprisk_trace_crosscheck_inconsistent() != 0) {
        atomic_store(&s_adbg_inline_patch_tamper_i, 1u);
        s_adbg_snapshot_i.last_inline_patch_tamper = 1u;
        s_adbg_snapshot_i.trap_event_count += 1u;
        cprisk_integrity_poison_antidebug_lane();
        return -1;
    }

    /* Clean path: consume runtime-gate BRK and continue execution. */
    return 1;
}

// 按 probe_bits、风险等级与计划 seed 选择本次生效的 policy 位。
// 选择是确定性伪随机门控：RUNTIME_GATE 条目始终启用；高风险约 3/4、低风险约 1/8 条目启用，
// 防止攻击者通过固定 pattern 推断并批量 patch。无匹配时回退到 policy_union_bits。
static uint32_t cprisk_antidebug_select_policy_bits_i(
    uint32_t probe_bits,
    int high_risk,
    uint32_t *out_selected_entries,
    uint64_t *out_identifier_mix
) {
    if (out_selected_entries)
        *out_selected_entries = 0u;
    if (out_identifier_mix)
        *out_identifier_mix = 0u;

    if (s_adbg_entry_count_i == 0u) {
        return s_adbg_plan_i.policy_union_bits;
    }

    const uint64_t selector_seed =
        s_adbg_plan_i.seed ^
        ((uint64_t)probe_bits << 11u) ^
        ((uint64_t)s_adbg_plan_i.probe_immediate << 3u) ^
        0x9E3779B97F4A7C15ULL;

    uint32_t selected_bits = 0u;
    uint32_t selected_count = 0u;
    uint64_t selected_mix = 0u;

    for (uint32_t i = 0u; i < s_adbg_entry_count_i; i++) {
        const cprisk_adbg_runtime_entry_t *entry = &s_adbg_entries_i[i];
        if (entry->policy_bits == 0u) {
            continue;
        }

        const uint64_t gate =
            entry->identifier_hash ^
            selector_seed ^
            ((uint64_t)entry->scatter_slot << 32u) ^
            ((uint64_t)entry->entry_flags << 9u);
        const int always_gate =
            (entry->policy_bits & CPRISK_ARMOR_ADBG_POLICY_RUNTIME_GATE) != 0u;
        const int selected = always_gate != 0
            ? 1
            : (high_risk
                ? ((gate & 0x3u) != 0u)
                : ((gate & 0x7u) == 0u));
        if (!selected) {
            continue;
        }

        selected_bits |= entry->policy_bits;
        selected_count += 1u;
        selected_mix ^= entry->identifier_hash ^ gate;
    }

    if (selected_bits == 0u) {
        selected_bits = s_adbg_plan_i.policy_union_bits;
    }

    if (out_selected_entries)
        *out_selected_entries = selected_count;
    if (out_identifier_mix)
        *out_identifier_mix = selected_mix;
    return selected_bits;
}

// 反调试延迟响应：基础 0.5–2ms；高风险再叠加 20–50ms。
// 用 nanosleep 主动拖慢探测循环，增加动态分析成本；返回值供快照记录实际延迟。
static uint64_t cprisk_antidebug_delay_response_i(uint64_t seed, uint32_t probe_immediate, int high_risk) {
    uint64_t mix = seed ^ ((uint64_t)probe_immediate << 17u) ^ 0x9E3779B97F4A7C15ULL;
    uint64_t delay_ns = 500000ull + (mix % 1500000ull); /* 0.5ms .. 2.0ms */
    if (high_risk)
        delay_ns += 20000000ull + ((mix >> 11u) % 30000000ull); /* +20ms .. +50ms */

    struct timespec req;
    req.tv_sec = (time_t)(delay_ns / 1000000000ull);
    req.tv_nsec = (long)(delay_ns % 1000000000ull);
    (void)nanosleep(&req, NULL);
    return delay_ns;
}

// 从 hw.machine（如 iPhone15,2 / iPad13,4）解析主代际数字。
// 未知前缀或非数字返回 -1 且 *out_major 置 -1，后续按“最宽松”处理。
static int cprisk_parse_apple_hw_major_generation_i(const char *machine, int *out_major) {
    if (!machine || !out_major)
        return -1;
    *out_major = -1;
    const char *p = NULL;
    if (strncmp(machine, "iPhone", 6) == 0)
        p = machine + 6;
    else if (strncmp(machine, "iPad", 4) == 0)
        p = machine + 4;
    else if (strncmp(machine, "iPod", 4) == 0)
        p = machine + 4;
    else if (strncmp(machine, "Mac", 3) == 0)
        p = machine + 3;
    else if (strncmp(machine, "Watch", 5) == 0)
        p = machine + 5;
    else if (strncmp(machine, "Appletv", 7) == 0)
        p = machine + 7;
    else
        return -1;
    if (*p < '0' || *p > '9')
        return -1;
    int v = 0;
    while (*p >= '0' && *p <= '9') {
        v = v * 10 + (*p - '0');
        if (v > 9999)
            return -1;
        p++;
    }
    *out_major = v;
    return 0;
}

// 机型代际越新启动越快，允许的时序 slack 越小；未知机型给 10s、iPhone16+ 给 0。
static uint64_t cprisk_generation_slack_ns_i(int major_gen) {
    if (major_gen < 0)
        return 8000000000ULL;
    if (major_gen >= 16)
        return 0;
    if (major_gen >= 14)
        return 2000000000ULL;
    if (major_gen >= 12)
        return 5000000000ULL;
    return 10000000000ULL;
}

// 计算 init 时序阈值：基线 5s + 代际 slack；
// RELAXED_DEV_QA / APP_STORE_SAFE 档位额外 +10s。
static uint64_t cprisk_compute_init_timing_threshold_ns_for_machine_i(
    const char *machine,
    cprisk_runtime_hardening_mode_t mode
) {
    int m = -1;
    if (machine && machine[0] != '\0')
        (void)cprisk_parse_apple_hw_major_generation_i(machine, &m);
    uint64_t t = CPRISK_INIT_TIMING_BASE_NS + cprisk_generation_slack_ns_i(m);
    if (mode == CPRISK_RUNTIME_HARDENING_RELAXED_DEV_QA ||
        mode == CPRISK_RUNTIME_HARDENING_APP_STORE_SAFE)
        t += CPRISK_INIT_TIMING_RELAXED_EXTRA_NS;
    return t;
}

// 是否处于放宽档位：这些模式下 TTY/开发者磁盘/时序等弱信号不计分，
// 降低开发联调与商店审核环境的误报。
static int cprisk_runtime_relaxed_dev_qa_i(void) {
    return s_runtime_hardening_mode == CPRISK_RUNTIME_HARDENING_RELAXED_DEV_QA ||
        s_runtime_hardening_mode == CPRISK_RUNTIME_HARDENING_APP_STORE_SAFE;
}

// 应用反调试计划策略（init 与 recheck 共用）。
// 采集探针位并计算 strong/weak 命中，形成 debugger_likely/confirmed 判断；
// 再按选中的 policy 执行 RUNTIME_GATE / DELAY_RESPONSE / ESCALATE_INTEGRITY /
// TRAP_ON_TAMPER / CRASH_ON_DEBUGGER。确认风险时统一走“投毒 + 欺骗”（fail-closed），
// 默认不崩溃（issue 42）。写全局 snapshot 与投毒状态；init 单线程调用，运行期调用弱一致。
static void cprisk_antidebug_apply_policies_i(uint32_t trigger_flags, int init_rc_hint, int integrity_rc_hint) {
    cprisk_antidebug_load_plan_i();
    if (s_adbg_plan_i.section_valid == 0u || s_adbg_plan_i.policy_union_bits == 0u)
        return;
    if ((trigger_flags & CPRISK_ADBG_TRIGGER_INIT_I) != 0u) {
        (void)cprisk_antidebug_apply_inline_patch_gate_i();
    }

    // 强信号=单次即可高置信（trap/硬件断点/DBI/异常端口等）；弱信号需要组合或放宽门控。
    const uint32_t strong_probe_mask =
        CPRISK_PROBE_SIGNAL_TRAP |
        CPRISK_PROBE_THREAD_EXCEPTION_PORT |
        CPRISK_PROBE_HARDWARE_BP |
        CPRISK_PROBE_SOFTWARE_BP |
        CPRISK_PROBE_INSTANT_RETURN_PATCH |
        CPRISK_PROBE_CSOPS |
        CPRISK_PROBE_DBI_MARKER |
        CPRISK_PROBE_EXCEPTION_DELIVERY_TIMEOUT |
        CPRISK_PROBE_SUSPICIOUS_THREAD |
        CPRISK_PROBE_TRACE_CROSSCHECK;
    const uint32_t weak_probe_mask =
        CPRISK_PROBE_SINGLE_STEP |
        CPRISK_PROBE_TIMING_ANOMALY |
        CPRISK_PROBE_TTY |
        CPRISK_PROBE_DEVELOPER_DISK;

    const int traced = cprisk_is_being_traced_redundant();
    uint32_t probe_bits = cprisk_run_all_signal_probes();
    if (cprisk_trace_crosscheck_inconsistent() != 0) {
        probe_bits |= CPRISK_PROBE_TRACE_CROSSCHECK;
    }
    const uint32_t strong_hits = cprisk_popcount32_i(probe_bits & strong_probe_mask);
    uint32_t weak_scoring_mask = weak_probe_mask;
    if (cprisk_runtime_relaxed_dev_qa_i()) {
        weak_scoring_mask &= (uint32_t)~(CPRISK_PROBE_TTY |
                                         CPRISK_PROBE_DEVELOPER_DISK |
                                         CPRISK_PROBE_TIMING_ANOMALY);
    }
    const uint32_t weak_hits = cprisk_popcount32_i(probe_bits & weak_scoring_mask);
    // 跟踪状态权重 3，强命中 ×2，弱命中 ×1；>=3 视为可能，>=5 或 2 个强命中视为确认。
    const int debug_strength = (traced ? 3 : 0) + (int)(strong_hits * 2u + weak_hits);
    const int debugger_likely = traced != 0 || debug_strength >= 3;
    const int debugger_confirmed = traced != 0 || debug_strength >= 5 || strong_hits >= 2u;
    const int integrity_tampered =
        (trigger_flags & CPRISK_ADBG_TRIGGER_INTEGRITY_TAMPER_I) != 0u ||
        integrity_rc_hint > 0;
    const int init_failed = init_rc_hint != 0;
    const int high_risk = debugger_likely || integrity_tampered || init_failed;
    uint32_t selected_entries = 0u;
    uint64_t selected_identifier_mix = 0u;
    const uint32_t policy_bits = cprisk_antidebug_select_policy_bits_i(
        probe_bits,
        high_risk,
        &selected_entries,
        &selected_identifier_mix
    );
    uint32_t applied = 0u;

    s_adbg_snapshot_i.consume_count += 1u;
    s_adbg_snapshot_i.last_probe_bits = probe_bits;
    s_adbg_snapshot_i.last_gate_closed = 0u;
    s_adbg_snapshot_i.last_soft_fail_mode = 0u;
    s_adbg_snapshot_i.last_delay_ns = 0u;
    s_adbg_snapshot_i.inline_patch_armed =
        atomic_load(&s_adbg_inline_patch_armed_i) != 0u ? 1u : 0u;
    if (atomic_load(&s_adbg_inline_patch_tamper_i) != 0u) {
        s_adbg_snapshot_i.last_inline_patch_tamper = 1u;
    }
    (void)selected_entries;
    (void)selected_identifier_mix;

    if ((policy_bits & CPRISK_ARMOR_ADBG_POLICY_RUNTIME_GATE) != 0u) {
        applied |= CPRISK_ARMOR_ADBG_POLICY_RUNTIME_GATE;
        cprisk_deny_attach();
        if (debugger_likely) {
            s_adbg_snapshot_i.last_gate_closed = 1u;
            cprisk_prepare_deception_material_i(NULL, NULL, NULL);
            s_integrity_deception_active = 1;
        }
    }

    if ((policy_bits & CPRISK_ARMOR_ADBG_POLICY_DELAY_RESPONSE) != 0u) {
        applied |= CPRISK_ARMOR_ADBG_POLICY_DELAY_RESPONSE;
        s_adbg_snapshot_i.last_delay_ns = cprisk_antidebug_delay_response_i(
            s_adbg_plan_i.seed, s_adbg_plan_i.probe_immediate, high_risk);
    }

    if ((policy_bits & CPRISK_ARMOR_ADBG_POLICY_ESCALATE_INTEGRITY) != 0u && high_risk) {
        applied |= CPRISK_ARMOR_ADBG_POLICY_ESCALATE_INTEGRITY;
        s_adbg_snapshot_i.escalation_count += 1u;
        cprisk_integrity_poison_antidebug_lane();
    }

    if ((policy_bits & CPRISK_ARMOR_ADBG_POLICY_TRAP_ON_TAMPER) != 0u &&
        (integrity_tampered || init_failed || (trigger_flags & CPRISK_ADBG_TRIGGER_INIT_FAILURE_I) != 0u)) {
        applied |= CPRISK_ARMOR_ADBG_POLICY_TRAP_ON_TAMPER;
        s_adbg_snapshot_i.trap_event_count += 1u;
        if (cprisk_probe_exception_delivery_timeout() != 0 || debugger_likely) {
            cprisk_integrity_poison_antidebug_lane();
        }
    }

    if ((policy_bits & CPRISK_ARMOR_ADBG_POLICY_CRASH_ON_DEBUGGER) != 0u && debugger_confirmed) {
        applied |= CPRISK_ARMOR_ADBG_POLICY_CRASH_ON_DEBUGGER;
        s_adbg_snapshot_i.last_soft_fail_mode = 1u;
        /* DEFAULT: no crash (issue 42). The response is record + poison +
         * deception: the output becomes untrustworthy without killing a
         * possibly-legitimate session on a false positive. A hard trap
         * is an EXPLICIT OPT-IN only (build flag
         * CPRISK_ANTI_DEBUG_HARD_CRASH_ON_DEBUGGER=1, default 0). */
        cprisk_integrity_poison_antidebug_lane();
        cprisk_prepare_deception_material_i(NULL, NULL, NULL);
        s_integrity_deception_active = 1;
#if CPRISK_ANTI_DEBUG_HARD_CRASH_ON_DEBUGGER
        if (debug_strength >= 7) {
            __builtin_trap();
        }
#endif
    }

    s_adbg_snapshot_i.last_applied_policy_bits = applied;
}

// 导出计划快照：先把原子 armed/tamper 同步进 snapshot，再整体拷贝。
// 返回 -1 表示 out_snapshot 为 NULL；快照弱一致，不保证与并发投毒严格同步。
int cprisk_get_antidebug_plan_snapshot(cprisk_antidebug_plan_snapshot_t *out_snapshot) {
    if (!out_snapshot)
        return -1;
    s_adbg_snapshot_i.inline_patch_armed =
        atomic_load(&s_adbg_inline_patch_armed_i) != 0u ? 1u : 0u;
    if (atomic_load(&s_adbg_inline_patch_tamper_i) != 0u) {
        s_adbg_snapshot_i.last_inline_patch_tamper = 1u;
    }
    *out_snapshot = s_adbg_snapshot_i;
    return 0;
}

// 测试钩子：复制注入计划并清空解析状态；非 DEBUG 构建直接返回 -1。
// 旧注入缓冲区先 secure_zero 再 free；新缓冲区由本模块拥有。
int cprisk_test_set_antidebug_plan(const uint8_t *plan, size_t plan_len) {
#if !defined(DEBUG) || !DEBUG
    /* Test hook: inert outside DEBUG builds (issue 18). */
    return -1;
#endif
    if (!plan || plan_len == 0u)
        return -1;

    uint8_t *copy = (uint8_t *)malloc(plan_len);
    if (!copy)
        return -1;
    memcpy(copy, plan, plan_len);

    if (s_test_adbg_plan_i != NULL) {
        cprisk_secure_zero(s_test_adbg_plan_i, s_test_adbg_plan_len_i);
        free(s_test_adbg_plan_i);
    }
    s_test_adbg_plan_i = copy;
    s_test_adbg_plan_len_i = plan_len;
    cprisk_antidebug_reset_plan_state_i();
    return 0;
}

// 测试钩子：清零并释放注入计划，重置解析状态；非 DEBUG 构建为空操作。
void cprisk_test_clear_antidebug_plan(void) {
#if !defined(DEBUG) || !DEBUG
    /* Test hook: inert outside DEBUG builds (issue 18). */
    return;
#endif
    if (s_test_adbg_plan_i != NULL) {
        cprisk_secure_zero(s_test_adbg_plan_i, s_test_adbg_plan_len_i);
        free(s_test_adbg_plan_i);
    }
    s_test_adbg_plan_i = NULL;
    s_test_adbg_plan_len_i = 0u;
    cprisk_antidebug_reset_plan_state_i();
}

// 通过本函数的代码地址反查自身 Mach-O header，
// 避免依赖可能被 hook 的 dyld/NSBundle API。
static const struct mach_header_64 *cprisk_own_hdr_i(void) {
    return cprisk_find_own_header((const void *)cprisk_own_hdr_i);
}

/* Fill the 32-byte root material. STRICT length: the caller must supply
 * exactly CPRISK_ARMOR_KEY_SIZE (32) bytes of full-entropy key material.
 * Short keys are NOT zero-padded and long keys are NOT silently truncated
 * — either is a hard failure (returns -1, out is zeroed), because padding
 * collapses entropy and truncation silently discards key bits.
 * No PBKDF2 / Argon2 / scrypt stretching exists in this C layer: the
 * input must already be a full-entropy key, NEVER a human password.
 * Callers holding a password must stretch it with a platform KDF
 * (or HKDF over a high-entropy secret) before calling here; feeding a
 * weak password directly would make the "32-byte key" low-entropy. */
// 填充 32 字节根材料。严格要求长度 == 32：短密钥不补零、长密钥不截断，
// 二者都返回 -1 并清零输出。补零会降低熵，截断会静默丢弃密钥位。
// 本层不做 PBKDF2/Argon2，输入必须是全熵密钥，绝不能是人工口令。
static int cprisk_fill_root_material_i(const uint8_t *root_key,
                                        size_t root_key_len,
                                        uint8_t out[CPRISK_ARMOR_KEY_SIZE]) {
    memset(out, 0, CPRISK_ARMOR_KEY_SIZE);
    if (!root_key || root_key_len != CPRISK_ARMOR_KEY_SIZE)
        return -1;
    memcpy(out, root_key, CPRISK_ARMOR_KEY_SIZE);
    return 0;
}

// 显式小端序列化：派生输入的字节序必须与 producer 端一致，不能依赖主机端序。
static void cprisk_u64_to_le_i(uint64_t value, uint8_t out[8]) {
    out[0] = (uint8_t)(value);
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
    out[4] = (uint8_t)(value >> 32);
    out[5] = (uint8_t)(value >> 40);
    out[6] = (uint8_t)(value >> 48);
    out[7] = (uint8_t)(value >> 56);
}

// 从 8 字节小端还原 u64；用于把 accumulator 摘要转成数值。
static uint64_t cprisk_u64_from_le_i(const uint8_t in[8]) {
    return ((uint64_t)in[0]) |
           ((uint64_t)in[1] << 8) |
           ((uint64_t)in[2] << 16) |
           ((uint64_t)in[3] << 24) |
           ((uint64_t)in[4] << 32) |
           ((uint64_t)in[5] << 40) |
           ((uint64_t)in[6] << 48) |
           ((uint64_t)in[7] << 56);
}

// 64 位循环左移；shift 自动取模 64，shift==0 时直接返回以避免未定义行为。
static uint64_t cprisk_rotl64_i(uint64_t value, unsigned int shift) {
    shift &= 63U;
    if (shift == 0U)
        return value;
    return (value << shift) | (value >> (64U - shift));
}

// 由 seed 折叠出 PAC discriminator：常数 "CPRISKPA" + 最多 16 字节 seed，逐字节 XOR/旋转。
// 该值仅用于 PAC/CFI 自检判别，不参与密钥派生。
static uintptr_t cprisk_pac_discriminator_i(const uint8_t *seed, size_t seed_len) {
    uint64_t acc = 0x43505249534B5041ULL; /* "CPRISKPA" */
    if (seed && seed_len > 0) {
        const size_t take = seed_len > 16 ? 16 : seed_len;
        for (size_t i = 0; i < take; i++) {
            acc ^= ((uint64_t)seed[i]) << ((i & 7u) * 8u);
            acc = cprisk_rotl64_i(acc, 9u) ^ 0x9E3779B97F4A7C15ULL;
        }
    }
    return (uintptr_t)acc;
}

// PAC/CFI 自检：先验证 discriminator 能通过 pac_self_test，再验证核心回调指针有效。
// 返回 -1 表示平台保护被破坏；调用方应视为篡改（init 失败）。
static int cprisk_validate_pac_cfi_i(const uint8_t *seed, size_t seed_len) {
    const uintptr_t discriminator = cprisk_pac_discriminator_i(seed, seed_len);
    if (cprisk_pac_self_test(discriminator) != 0)
        return -1;
    if (cprisk_pac_validate_core_callbacks() != 0)
        return -1;
    return 0;
}

enum {
    // white-box 域 ID：1=anchor tag，2=pass1 字符串密钥，3=anchor accumulator seed，
    // 4=loader key，5=runtime material。域 ID 是 ABI 契约，改动需同步 producer。
    CPRISK_WHITEBOX_DOMAIN_ANCHOR_TAG_I = 1u,
    CPRISK_WHITEBOX_DOMAIN_PASS1_STRING_KEY_I = 2u,
    CPRISK_WHITEBOX_DOMAIN_ANCHOR_ACCUMULATOR_SEED_I = 3u,
    CPRISK_WHITEBOX_DOMAIN_LOADER_KEY_I = 4u,
    CPRISK_WHITEBOX_DOMAIN_RUNTIME_MATERIAL_I = 5u
};

// 前向声明：white-box 域求值实现在独立模块；返回 0 成功，非 0 表示域不可用/校验失败。
int cprisk_whitebox_evaluate_domain(
    uint32_t domain_id,
    const uint8_t input[32],
    uint8_t out[32]
);

// 派生字符串解密密钥：SHA256(label || root_material)，取前 32 字节。
// label 固定为 "cprisk.pass1.key.v1"，必须与构建期加密端一致。
static int cprisk_derive_pass1_string_key_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]
) {
    static const uint8_t label[] = "cprisk.pass1.key.v1";
    uint8_t digest[CPRISK_SHA256_DIGEST_LENGTH];

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, label, sizeof(label) - 1U);
    cprisk_sha256_update(&ctx, root_material, CPRISK_ARMOR_KEY_SIZE);
    cprisk_sha256_final(&ctx, digest);

    memcpy(out_key, digest, CPRISK_ARMOR_KEY_SIZE);
    cprisk_secure_zero(digest, sizeof(digest));
    return 0;
}

// 计算 anchor 绑定累加器：SHA256(label || root || full_anchor_hash || integrity_hash)，
// 取小端首 8 字节再 rotl 7。它把代码摘要与 anchor 摘要耦合进后续 loader/runtime 派生。
static uint64_t cprisk_anchor_bound_accumulator_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    const uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE],
    const uint8_t integrity_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    static const uint8_t label[] = "cprisk.pass1.acc.v2";
    uint8_t digest[CPRISK_SHA256_DIGEST_LENGTH];

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, label, sizeof(label) - 1U);
    cprisk_sha256_update(&ctx, root_material, CPRISK_ARMOR_KEY_SIZE);
    cprisk_sha256_update(&ctx, full_anchor_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_update(&ctx, integrity_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_final(&ctx, digest);

    uint64_t acc = cprisk_u64_from_le_i(digest);
    cprisk_secure_zero(digest, sizeof(digest));
    return cprisk_rotl64_i(acc, 7U);
}

// 混合“稳定上下文”：自身 header 地址、函数地址、pid、init 耗时。
// 这些值在进程内稳定，使欺骗材料可复现，同时随进程/设备不同而变化。
static void cprisk_mix_stable_deception_context_i(cprisk_sha256_ctx *ctx) {
    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    uint8_t hdr_le[8];
    uint8_t self_le[8];
    uint8_t pid_le[8];
    uint8_t elapsed_le[8];

    cprisk_u64_to_le_i((uint64_t)(uintptr_t)hdr, hdr_le);
    cprisk_u64_to_le_i((uint64_t)(uintptr_t)cprisk_get_runtime_material, self_le);
    cprisk_u64_to_le_i((uint64_t)cprisk_getpid_direct(), pid_le);
    cprisk_u64_to_le_i(s_init_elapsed_ns, elapsed_le);

    cprisk_sha256_update(ctx, hdr_le, sizeof(hdr_le));
    cprisk_sha256_update(ctx, self_le, sizeof(self_le));
    cprisk_sha256_update(ctx, pid_le, sizeof(pid_le));
    cprisk_sha256_update(ctx, elapsed_le, sizeof(elapsed_le));

    cprisk_secure_zero(hdr_le, sizeof(hdr_le));
    cprisk_secure_zero(self_le, sizeof(self_le));
    cprisk_secure_zero(pid_le, sizeof(pid_le));
    cprisk_secure_zero(elapsed_le, sizeof(elapsed_le));
}

// 派生欺骗材料（decoy）：label + 可选 root/anchor/integrity + 稳定上下文。
// 缺失输入用固定占位串代替；integrity 占位以 XOR 0x5A 编码，避免明文出现在二进制中。
// 输出 32 字节，临时明文在返回前清零。
static void cprisk_derive_decoy_material_i(
    const uint8_t *root_material,
    const uint8_t *full_anchor_hash,
    const uint8_t *integrity_hash,
    uint8_t out_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    static const uint8_t label[] = "cprisk.runtime.decoy.v1";
    static const uint8_t missing_root[] = "missing-root";
    static const uint8_t missing_anchor[] = "missing-anchor";
    static const uint8_t missing_integrity_enc[] = {
        0x37, 0x33, 0x29, 0x29, 0x33, 0x34, 0x3D, 0x77, 0x33,
        0x34, 0x2E, 0x3F, 0x3D, 0x28, 0x33, 0x2E, 0x23
    };
    uint8_t missing_integrity_dec[sizeof(missing_integrity_enc)];
    for (size_t i = 0; i < sizeof(missing_integrity_enc); i++) {
        missing_integrity_dec[i] = (uint8_t)(missing_integrity_enc[i] ^ 0x5A);
    }

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, label, sizeof(label) - 1U);

    if (root_material)
        cprisk_sha256_update(&ctx, root_material, CPRISK_ARMOR_KEY_SIZE);
    else
        cprisk_sha256_update(&ctx, missing_root, sizeof(missing_root) - 1U);

    if (full_anchor_hash)
        cprisk_sha256_update(&ctx, full_anchor_hash, CPRISK_ARMOR_HASH_SIZE);
    else
        cprisk_sha256_update(&ctx, missing_anchor, sizeof(missing_anchor) - 1U);

    if (integrity_hash)
        cprisk_sha256_update(&ctx, integrity_hash, CPRISK_ARMOR_HASH_SIZE);
    else
        cprisk_sha256_update(&ctx, missing_integrity_dec, sizeof(missing_integrity_dec));

    cprisk_mix_stable_deception_context_i(&ctx);
    cprisk_sha256_final(&ctx, out_hash);
    cprisk_secure_zero(missing_integrity_dec, sizeof(missing_integrity_dec));
}

// 首次需要时派生并以原子 store 发布欺骗材料；ready 已置位则直接返回（幂等）。
// 多线程可能同时进入并重复计算，但读侧只会看到完整发布的结果。
static void cprisk_prepare_deception_material_i(
    const uint8_t *root_material,
    const uint8_t *full_anchor_hash,
    const uint8_t *integrity_hash
) {
    if (atomic_load(&s_deception_material_ready) != 0)
        return;
    cprisk_derive_decoy_material_i(
        root_material, full_anchor_hash, integrity_hash, s_deception_material);
    atomic_store(&s_deception_material_ready, 1);
}

// 是否启用欺骗：被跟踪 / mprotect 被篡改 / init 时序异常。
// 这是“是否把假材料给调用方”的策略判断，本身不修改投毒状态。
static int cprisk_should_activate_deception_i(void) {
    if (cprisk_is_being_traced_redundant())
        return 1;
    if (cprisk_is_mprotect_tampered())
        return 1;
    if (cprisk_check_init_timing())
        return 1;
    return 0;
}

// 重置全部投毒语义状态；仅 init/cleanup/测试单线程调用，
// 确保新一轮保护从零开始，不残留上一轮 lane 计数/指纹。
static void cprisk_integrity_poison_semantic_reset_i(void) {
    memset((void *)&s_poison_lane_seq[0], 0, sizeof(s_poison_lane_seq));
    s_poison_semantic_breadcrumb = 0u;
    s_poison_semantic_rolling[0] = 0u;
    s_poison_semantic_rolling[1] = 0u;
    s_poison_epoch = 0u;
    s_poison_cause_mix = 0u;
}

// lane 投毒副作用（不置全局 poisoned 位）：递增该 lane 序号与 epoch，
// 以顺序敏感方式折叠 cause_mix / rolling / breadcrumb。
// 每条 lane 使用不同常量与不同旋转方向，避免一份通用 patch 抹平所有 lane 语义；
// 末尾把 lane 位 OR 入低 32 位，使“哪些 lane 触发过”仍可观测。
// 越界 lane 归一到 FORCE；函数不做同步，读侧按弱一致处理。
static void cprisk_integrity_poison_lane_sidefx_i(uint32_t lane) {
    if (lane >= (uint32_t)CPRISK_POISON_LANE_COUNT)
        lane = CPRISK_POISON_LANE_FORCE;
    s_poison_lane_seq[lane] += 1u;
    const uint32_t seq = s_poison_lane_seq[lane];
    s_poison_epoch += 1u;
    s_poison_cause_mix = s_poison_cause_mix * 0x9E3779B97F4A7C15ULL;
    s_poison_cause_mix ^= ((uint64_t)(lane + 1u) << 48) ^ (uint64_t)seq ^ ((uint64_t)seq << 32);
    const uint32_t lane_mix = lane * 0x85EBCA6Bu;
    s_poison_semantic_rolling[0] ^= 0x9E3779B9u ^ lane_mix ^ seq;
    s_poison_semantic_rolling[1] ^=
        (uint32_t)(lane + 1u) * 0xC2B2AE3Du ^ (seq << (lane & 7u));

    /* Lane-specific non-linear fold: not a second copy of the same transform (symbol rename only). */
    if (lane == (uint32_t)CPRISK_POISON_LANE_EVT_A) {
        s_poison_semantic_breadcrumb ^= (0xA5C3E971u ^ (seq * 0x9E3779B9u));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb << 11) | (s_poison_semantic_breadcrumb >> 21);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_EVT_B) {
        s_poison_semantic_breadcrumb ^= (0x4B7D8E0Fu ^ (seq * 0x85EBCA6Bu));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb >> 13) | (s_poison_semantic_breadcrumb << 19);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_RECHECK) {
        s_poison_semantic_breadcrumb ^= (0xC0DEF00Du ^ (seq * 0xDEADBEEFu));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb << 7) | (s_poison_semantic_breadcrumb >> 25);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_WATCHDOG) {
        s_poison_semantic_breadcrumb ^= (0xBADC0DE3u ^ (seq * 0x1234567u));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb << 17) | (s_poison_semantic_breadcrumb >> 15);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_CODE_SIGNING) {
        s_poison_semantic_breadcrumb ^= (0x51E9C0DEu ^ (seq * 0xABCDEF01u));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb >> 9) | (s_poison_semantic_breadcrumb << 23);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_SVC_IFACE) {
        s_poison_semantic_breadcrumb ^= (0xFACADE5Au ^ (seq * 0x55AA1100u));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb << 5) | (s_poison_semantic_breadcrumb >> 27);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_ANTIDEBUG) {
        s_poison_semantic_breadcrumb ^= (0xADB6D00Du ^ (seq * 0x10203041u));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb << 3) | (s_poison_semantic_breadcrumb >> 29);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_EXCEPTION) {
        s_poison_semantic_breadcrumb ^= (0xE11CE771u ^ (seq * 0x31415927u));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb >> 7) | (s_poison_semantic_breadcrumb << 25);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_ANTI_DUMP) {
        s_poison_semantic_breadcrumb ^= (0xA17DD00Fu ^ (seq * 0x27182818u));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb << 13) | (s_poison_semantic_breadcrumb >> 19);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_DATA_LOADER) {
        s_poison_semantic_breadcrumb ^= (0xDA7A10ADu ^ (seq * 0x01000193u));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb >> 11) | (s_poison_semantic_breadcrumb << 21);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_TEXT_ENCRYPT) {
        s_poison_semantic_breadcrumb ^= (0x7E87C0DEu ^ (seq * 0x5BD1E995u));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb << 9) | (s_poison_semantic_breadcrumb >> 23);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_WHITEBOX) {
        s_poison_semantic_breadcrumb ^= (0xB01DFACEu ^ (seq * 0x045D9F3Bu));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb >> 5) | (s_poison_semantic_breadcrumb << 27);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_CFF) {
        s_poison_semantic_breadcrumb ^= (0xCFF0A11Eu ^ (seq * 0x7F4A7C15u));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb << 15) | (s_poison_semantic_breadcrumb >> 17);
    }
    /* Low bits record which lanes fired (Swift/tests); applied after folds so they stay observable. */
    if (lane < 32u)
        s_poison_semantic_breadcrumb |= (1u << lane);
}

// 按 lane 就地扰动欺骗材料，使不同攻击路径得到不同假材料。
// 仅在 deception material 已发布时生效；各 lane 使用互不重叠的字节窗口
// （前段/尾段/中段/特定 u32 槽），避免一个 lane 掩盖另一个。
// salt 来自 rolling 与 lane seq，随触发顺序变化。
static void cprisk_integrity_poison_lane_tweak_deception_i(uint32_t lane) {
    if (lane >= (uint32_t)CPRISK_POISON_LANE_COUNT || atomic_load(&s_deception_material_ready) == 0)
        return;
    const uint32_t salt0 = s_poison_semantic_rolling[0] ^ (lane * 0x243F6A88u);
    const uint32_t salt1 = s_poison_semantic_rolling[1] ^ (s_poison_lane_seq[lane] * 7u);
    uint8_t *const m = s_deception_material;

    if (lane == (uint32_t)CPRISK_POISON_LANE_EVT_A) {
        /* Front window: independent from evt_b's tail window. */
        for (size_t i = 0; i < 12u && i < (size_t)CPRISK_ARMOR_HASH_SIZE; i++) {
            m[i] ^= (uint8_t)((salt0 >> ((i % 4u) * 8u)) & 0xFFu) ^ (uint8_t)(0xA5u + (uint8_t)i);
        }
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_EVT_B) {
        for (size_t i = 0; i < 12u && (size_t)CPRISK_ARMOR_HASH_SIZE > 12u; i++) {
            const size_t j = (size_t)CPRISK_ARMOR_HASH_SIZE - 12u + i;
            m[j] ^= (uint8_t)((salt1 >> ((i % 4u) * 8u)) & 0xFFu) ^ (uint8_t)(0x5Au + (uint8_t)i);
        }
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_RECHECK) {
        /* Middle stripe: overlaps neither evt_a front nor evt_b tail windows. */
        for (size_t i = 0; i < 12u && i + 8u <= (size_t)CPRISK_ARMOR_HASH_SIZE; i++) {
            const size_t j = 8u + i;
            m[j] ^= (uint8_t)((salt0 ^ salt1) >> ((i % 4u) * 8u)) ^ (uint8_t)(0x3Cu + (uint8_t)i);
        }
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_WATCHDOG) {
        for (size_t i = 0; i < 8u && i + 4u < (size_t)CPRISK_ARMOR_HASH_SIZE; i++) {
            const size_t j = 4u + i;
            m[j] ^= (uint8_t)(salt0 >> ((i % 4u) * 8u)) ^ (uint8_t)(0x71u + (uint8_t)i);
        }
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_CODE_SIGNING) {
        for (size_t i = 0; i < 6u && i + 20u < (size_t)CPRISK_ARMOR_HASH_SIZE; i++) {
            const size_t j = 20u + i;
            m[j] ^= (uint8_t)(salt1 >> ((i % 4u) * 8u)) ^ (uint8_t)(0xC0u + (uint8_t)i);
        }
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_SVC_IFACE) {
        uint32_t *dm = (uint32_t *)s_deception_material;
        dm[2] ^= salt0 ^ 0xC001D00Du;
        dm[3] ^= salt1 ^ 0xD00DF00Du;
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_ANTIDEBUG) {
        for (size_t i = 0; i < 6u && i + 2u < (size_t)CPRISK_ARMOR_HASH_SIZE; i++) {
            const size_t j = 2u + i;
            m[j] ^= (uint8_t)(salt0 >> ((i % 4u) * 8u)) ^ (uint8_t)(0x44u + (uint8_t)i);
        }
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_EXCEPTION) {
        for (size_t i = 0; i < 6u && i + 14u < (size_t)CPRISK_ARMOR_HASH_SIZE; i++) {
            const size_t j = 14u + i;
            m[j] ^= (uint8_t)(salt1 >> ((i % 4u) * 8u)) ^ (uint8_t)(0x81u + (uint8_t)i);
        }
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_ANTI_DUMP) {
        for (size_t i = 0; i < 6u && i + 24u < (size_t)CPRISK_ARMOR_HASH_SIZE; i++) {
            const size_t j = 24u + i;
            m[j] ^= (uint8_t)((salt0 ^ salt1) >> ((i % 4u) * 8u)) ^ (uint8_t)(0x29u + (uint8_t)i);
        }
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_DATA_LOADER) {
        uint32_t *dm = (uint32_t *)s_deception_material;
        dm[4] ^= salt0 ^ 0xDADA11AAu;
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_TEXT_ENCRYPT) {
        uint32_t *dm = (uint32_t *)s_deception_material;
        dm[5] ^= salt1 ^ 0x7E70C0DEu;
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_WHITEBOX) {
        uint32_t *dm = (uint32_t *)s_deception_material;
        dm[6] ^= (salt0 ^ salt1) ^ 0xB01DB0B0u;
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_CFF) {
        uint32_t *dm = (uint32_t *)s_deception_material;
        dm[7] ^= salt0 ^ 0xCF0CF0CFu;
    } else {
        uint32_t *dm = (uint32_t *)s_deception_material;
        dm[0] ^= salt0;
        dm[1] ^= salt1;
    }
}

// 完整投毒提交：置全局 poisoned，记录 lane 副作用；满足条件时启用欺骗并扰动材料。
// anti-dump lane 始终启用欺骗（与旧探针行为对齐），其余 lane 仅在
// 跟踪/mprotect/时序启发式触发时启用。可并发调用，读侧接受弱一致。
static void cprisk_integrity_poison_lane_full_i(uint32_t lane) {
    if (lane >= (uint32_t)CPRISK_POISON_LANE_COUNT)
        lane = CPRISK_POISON_LANE_FORCE;
    s_integrity_poisoned = 1;
    cprisk_integrity_poison_lane_sidefx_i(lane);
    /* Anti-dump full commit always arms deception material (legacy probe parity); other lanes
     * only when traced / mprotect-tamper / init-timing heuristics fire. */
    if (cprisk_should_activate_deception_i() ||
        lane == (uint32_t)CPRISK_POISON_LANE_ANTI_DUMP) {
        cprisk_prepare_deception_material_i(NULL, NULL, NULL);
        s_integrity_deception_active = 1;
        cprisk_integrity_poison_lane_tweak_deception_i(lane);
    }
}

// staged 不透明记录：未达阈值时不递增 lane seq，只把 tick 折叠进 cause_mix/rolling；
// 若欺骗材料已发布，再混入 tick 噪声，使“仅 staged”响应也随 tick 变化、无法做位级比对。
// tick 为原子自增，可并发调用；这不是完整投毒，s_integrity_poisoned 保持 0。
static void cprisk_integrity_poison_staged_note_i(uint32_t lane) {
    if (lane >= (uint32_t)CPRISK_POISON_LANE_COUNT)
        lane = CPRISK_POISON_LANE_FORCE;
    const uint64_t t = atomic_fetch_add(&s_staged_opacity_tick, 1) + 1ull;
    uint64_t z = t * 0x9E3779B97F4A7C15ULL;
    z ^= (uint64_t)(lane + 1u) << 48;
    z ^= z >> 33;
    z *= 0xff51afd7ed558ccdULL;
    z ^= z >> 33;
    z *= 0xc4ceb9fe1a85ec53ULL;
    z ^= z >> 33;
    z ^= (uint64_t)lane * 0xD6E8FEB86655FD96ULL;
    s_poison_cause_mix ^= z;
    s_poison_semantic_rolling[0] ^= (uint32_t)(z >> 32);
    s_poison_semantic_rolling[1] ^= (uint32_t)z;
    /*
     * Signature-noise: fold staged tick into deception material so staged-only responses are not
     * bitwise stable across ticks (complements lane_tweak_deception_i when full commit is deferred).
     */
    if (atomic_load(&s_deception_material_ready) != 0) {
        const uint32_t tv = (uint32_t)(t & 0xFFFFFFFFu);
        uint32_t *dm = (uint32_t *)s_deception_material;
        dm[0] ^= tv ^ (uint32_t)(z >> 32);
        dm[1] ^= (uint32_t)z ^ ((uint32_t)lane * 0x13579BDFu);
        if ((size_t)CPRISK_ARMOR_HASH_SIZE >= 16u) {
            uint8_t *const m = s_deception_material;
            m[12] ^= (uint8_t)(tv & 0xFFu);
            m[13] ^= (uint8_t)((tv >> 8) & 0xFFu);
            m[14] ^= (uint8_t)((uint32_t)lane ^ (uint32_t)(t >> 40));
            m[15] ^= (uint8_t)((z >> 56) & 0xFFu);
        }
    }
}

// watchdog 第一个阈值完成后先经历 2 个慢波才完整提交；
// 慢波逐步加重输出降级，但保持“尚未 poison”的可否认性。
#ifndef CPRISK_POISON_STAGED_WATCHDOG_SLOW_WAVES_BEFORE_FULL
#define CPRISK_POISON_STAGED_WATCHDOG_SLOW_WAVES_BEFORE_FULL 2u
#endif

// watchdog 慢波：连续三次 staged_note 叠加额外 cause_mix/rolling 熵，
// 使签名/whitebox 链路先出现差异，但全局 poisoned 仍为 0。
static void cprisk_integrity_poison_watchdog_slow_wave_i(void) {
    /*
     * Progressive degradation without flipping global poison: multiple staged_note folds +
     * extra cause_mix entropy so signing / whitebox pressure paths diverge before full commit.
     */
    cprisk_integrity_poison_staged_note_i(CPRISK_POISON_LANE_WATCHDOG);
    cprisk_integrity_poison_staged_note_i(CPRISK_POISON_LANE_WATCHDOG);
    cprisk_integrity_poison_staged_note_i(CPRISK_POISON_LANE_WATCHDOG);
    uint64_t z = s_poison_cause_mix ^ (uint64_t)atomic_load(&s_staged_opacity_tick);
    z ^= z >> 33;
    z *= 0xff51afd7ed558ccdULL;
    z ^= z >> 33;
    z *= 0xc4ceb9fe1a85ec53ULL;
    z ^= z >> 33;
    z ^= 0x510FE511510FE511ULL;
    s_poison_cause_mix ^= z;
    s_poison_semantic_rolling[0] ^= (uint32_t)(z >> 32) ^ 0x514E5546u; /* "PNUF" tag */
    s_poison_semantic_rolling[1] ^= (uint32_t)z ^ 0x57445631u;
}

// watchdog staged 入口：每次命中自增；达阈值后清零计数并推进慢波。
// 慢波未满 2 次只做渐进降级；满 2 次完整提交 watchdog lane。原子计数，可并发。
static void cprisk_integrity_poison_watchdog_lane_staged_i(void) {
    const uint32_t n = atomic_fetch_add(&s_staged_watchdog_hits, 1) + 1u;
    if (n >= CPRISK_POISON_STAGED_WATCHDOG_THRESHOLD) {
        atomic_store(&s_staged_watchdog_hits, 0u);
        const uint32_t wave = atomic_fetch_add(&s_staged_watchdog_slow_wave, 1u) + 1u;
        if (wave < CPRISK_POISON_STAGED_WATCHDOG_SLOW_WAVES_BEFORE_FULL) {
            cprisk_integrity_poison_watchdog_slow_wave_i();
        } else {
            atomic_store(&s_staged_watchdog_slow_wave, 0u);
            cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_WATCHDOG);
        }
    } else {
        cprisk_integrity_poison_staged_note_i(CPRISK_POISON_LANE_WATCHDOG);
    }
}

// anti-dump staged 入口：达到阈值才完整提交 anti-dump lane，否则只做不透明 staged_note。
static void cprisk_integrity_poison_anti_dump_lane_staged_i(void) {
    const uint32_t n = atomic_fetch_add(&s_staged_anti_dump_hits, 1) + 1u;
    if (n >= CPRISK_POISON_STAGED_ANTI_DUMP_THRESHOLD) {
        atomic_store(&s_staged_anti_dump_hits, 0u);
        cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_ANTI_DUMP);
    } else {
        cprisk_integrity_poison_staged_note_i(CPRISK_POISON_LANE_ANTI_DUMP);
    }
}

// 派生数据段 loader key：SHA256(label || root || anchor || integrity || string_acc_le)。
// label 以 XOR 常量编码存储、运行时解码，避免明文标签直接出现在二进制；输出 32 字节密钥。
static void cprisk_derive_loader_key_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    const uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE],
    const uint8_t integrity_hash[CPRISK_ARMOR_HASH_SIZE],
    uint64_t string_acc,
    uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]
) {
    static const uint8_t label_enc_default[] = {
        'c'^CPRISK_SALT_XOR_KEY_DEFAULT, 'p'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'r'^CPRISK_SALT_XOR_KEY_DEFAULT, 'i'^CPRISK_SALT_XOR_KEY_DEFAULT,
        's'^CPRISK_SALT_XOR_KEY_DEFAULT, 'k'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 'p'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'a'^CPRISK_SALT_XOR_KEY_DEFAULT, 's'^CPRISK_SALT_XOR_KEY_DEFAULT,
        's'^CPRISK_SALT_XOR_KEY_DEFAULT, '3'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 'k'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'e'^CPRISK_SALT_XOR_KEY_DEFAULT, 'y'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 'v'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '1'^CPRISK_SALT_XOR_KEY_DEFAULT
    };
    char label[sizeof(label_enc_default) + 1];
    cprisk_decode_salt(label_enc_default, sizeof(label_enc_default),
                       CPRISK_SALT_XOR_KEY_DEFAULT, label);

    uint8_t acc_le[8];
    cprisk_u64_to_le_i(string_acc, acc_le);

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, (const uint8_t *)label, sizeof(label_enc_default));
    cprisk_sha256_update(&ctx, root_material, CPRISK_ARMOR_KEY_SIZE);
    cprisk_sha256_update(&ctx, full_anchor_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_update(&ctx, integrity_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_update(&ctx, acc_le, sizeof(acc_le));
    cprisk_sha256_final(&ctx, out_key);

    cprisk_secure_zero(label, sizeof(label));
    cprisk_secure_zero(acc_le, sizeof(acc_le));
}

// 派生 runtime material：SHA256(label || root || anchor || integrity || string_acc || data_acc)。
// data_acc 来自受保护数据加载器，因此数据段内容也绑定进最终运行时材料。
static void cprisk_derive_runtime_material_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    const uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE],
    const uint8_t integrity_hash[CPRISK_ARMOR_HASH_SIZE],
    uint64_t string_acc,
    uint64_t data_acc,
    uint8_t out_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    static const uint8_t label_enc_default[] = {
        'c'^CPRISK_SALT_XOR_KEY_DEFAULT, 'p'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'r'^CPRISK_SALT_XOR_KEY_DEFAULT, 'i'^CPRISK_SALT_XOR_KEY_DEFAULT,
        's'^CPRISK_SALT_XOR_KEY_DEFAULT, 'k'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 'r'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'u'^CPRISK_SALT_XOR_KEY_DEFAULT, 'n'^CPRISK_SALT_XOR_KEY_DEFAULT,
        't'^CPRISK_SALT_XOR_KEY_DEFAULT, 'i'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'm'^CPRISK_SALT_XOR_KEY_DEFAULT, 'e'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 's'^CPRISK_SALT_XOR_KEY_DEFAULT,
        't'^CPRISK_SALT_XOR_KEY_DEFAULT, 'a'^CPRISK_SALT_XOR_KEY_DEFAULT,
        't'^CPRISK_SALT_XOR_KEY_DEFAULT, 'e'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 'v'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '1'^CPRISK_SALT_XOR_KEY_DEFAULT
    };
    char label[sizeof(label_enc_default) + 1];
    cprisk_decode_salt(label_enc_default, sizeof(label_enc_default),
                       CPRISK_SALT_XOR_KEY_DEFAULT, label);

    uint8_t str_le[8];
    uint8_t data_le[8];
    cprisk_u64_to_le_i(string_acc, str_le);
    cprisk_u64_to_le_i(data_acc, data_le);

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, (const uint8_t *)label, sizeof(label_enc_default));
    cprisk_sha256_update(&ctx, root_material, CPRISK_ARMOR_KEY_SIZE);
    cprisk_sha256_update(&ctx, full_anchor_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_update(&ctx, integrity_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_update(&ctx, str_le, sizeof(str_le));
    cprisk_sha256_update(&ctx, data_le, sizeof(data_le));
    cprisk_sha256_final(&ctx, out_hash);

    cprisk_secure_zero(label, sizeof(label));
    cprisk_secure_zero(str_le, sizeof(str_le));
    cprisk_secure_zero(data_le, sizeof(data_le));
}

// SHA256(a || b) 的便捷封装；把多个摘要/累加器无歧义串接（长度由调用方保证）。
static void cprisk_sha256_concat2_i(
    const uint8_t *a,
    size_t a_len,
    const uint8_t *b,
    size_t b_len,
    uint8_t out_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, a, a_len);
    cprisk_sha256_update(&ctx, b, b_len);
    cprisk_sha256_final(&ctx, out_hash);
}

// SHA256(a || b || c) 的便捷封装；用于 anchor/accumulator 组合派生。
static void cprisk_sha256_concat3_i(
    const uint8_t *a,
    size_t a_len,
    const uint8_t *b,
    size_t b_len,
    const uint8_t *c,
    size_t c_len,
    uint8_t out_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, a, a_len);
    cprisk_sha256_update(&ctx, b, b_len);
    cprisk_sha256_update(&ctx, c, c_len);
    cprisk_sha256_final(&ctx, out_hash);
}

// SHA256(a || b || c || d) 的便捷封装；用于 runtime material 的完整输入串接。
static void cprisk_sha256_concat4_i(
    const uint8_t *a,
    size_t a_len,
    const uint8_t *b,
    size_t b_len,
    const uint8_t *c,
    size_t c_len,
    const uint8_t *d,
    size_t d_len,
    uint8_t out_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, a, a_len);
    cprisk_sha256_update(&ctx, b, b_len);
    cprisk_sha256_update(&ctx, c, c_len);
    cprisk_sha256_update(&ctx, d, d_len);
    cprisk_sha256_final(&ctx, out_hash);
}

// 用 white-box 域 1 校验 anchor tag：读取 __DATA 中 32 字节 tag 区，
// 以 full_hash 为输入求值得到 tag，再做常量时间 MAC 比较。
// 返回 -1 表示 section 缺失/长度不符/求值失败/MAC 不匹配；调用方应投毒并 fail-closed。
static int cprisk_verify_anchor_whitebox_i(
    const uint8_t full_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    if (!hdr)
        return -1;

    unsigned long sz = 0;
    const uint8_t *sec = cprisk_find_section(
        hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_FULL_HASH, &sz);
    if (!sec || sz != CPRISK_ARMOR_HASH_SIZE)
        return -1;

    uint8_t computed_tag[CPRISK_ARMOR_HASH_SIZE];
    if (cprisk_whitebox_evaluate_domain(
            CPRISK_WHITEBOX_DOMAIN_ANCHOR_TAG_I,
            full_hash,
            computed_tag) != 0) {
        return -1;
    }

    const int rc = cprisk_mac_verify(sec, computed_tag, CPRISK_ARMOR_HASH_SIZE);
    cprisk_secure_zero(computed_tag, sizeof(computed_tag));
    return rc;
}

// legacy 初始化路径（white-box 不可用时）：
// 校验 anchor MAC → 派生 pass1/string key → 初始化解密器 → 派生 loader key →
// 加载受保护数据 → 派生 runtime material 并原子发布。
// 返回 0 成功；-4 anchor MAC 失败；-5 字符串解密器失败；-6 loader key/数据加载器失败；
// -7 受保护数据加载失败。任一失败都不发布 runtime material，调用方必须 cleanup。
static int cprisk_init_protection_legacy_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    const uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE],
    const uint8_t integrity[CPRISK_ARMOR_HASH_SIZE]
) {
    uint8_t loader_key[CPRISK_ARMOR_KEY_SIZE];
    uint64_t string_acc = 0;
    int rc = -1;
    memset(loader_key, 0, sizeof(loader_key));

    if (cprisk_verify_anchor_mac(root_material, full_anchor_hash) != 0) {
        rc = -4;
        goto cleanup;
    }

    string_acc = cprisk_anchor_bound_accumulator_i(
        root_material, full_anchor_hash, integrity);

    {
        uint8_t pass1_string_key[CPRISK_ARMOR_KEY_SIZE];
        cprisk_derive_pass1_string_key_i(root_material, pass1_string_key);
        if (cprisk_init_string_decryptor(pass1_string_key, CPRISK_ARMOR_KEY_SIZE) != 0) {
            cprisk_secure_zero(pass1_string_key, sizeof(pass1_string_key));
            rc = -5;
            goto cleanup;
        }
        cprisk_secure_zero(pass1_string_key, sizeof(pass1_string_key));
    }

    cprisk_prepare_deception_material_i(
        root_material, full_anchor_hash, integrity);

    cprisk_derive_loader_key_i(
        root_material,
        full_anchor_hash,
        integrity,
        string_acc,
        loader_key);

    if (!cprisk_mini_vm_bootstrap_disabled())
        cprisk_loader_key_mini_vm_bootstrap(loader_key);

    if (cprisk_init_data_loader(loader_key, CPRISK_ARMOR_KEY_SIZE) != 0) {
        rc = -6;
        goto cleanup;
    }

    if (cprisk_load_protected_data() < 0) {
        cprisk_unload_protected_data();
        rc = -7;
        goto cleanup;
    }

    cprisk_derive_runtime_material_i(
        root_material,
        full_anchor_hash,
        integrity,
        string_acc,
        cprisk_get_data_integrity_accumulator(),
        s_runtime_material);
    if (!cprisk_mini_vm_bootstrap_disabled())
        cprisk_mini_vm_bootstrap_material32(s_runtime_material);
    atomic_store(&s_runtime_material_ready, 1);
    rc = 0;

cleanup:
    cprisk_secure_zero(loader_key, sizeof(loader_key));
    return rc;
}

// white-box 初始化路径：先校验 anchor tag，再逐域求值 pass1 key / anchor accumulator /
// loader key / runtime material；各中间摘要用 SHA256 串接，保证域输入不可混淆。
// 失败码：-4 anchor 校验；-5 pass1 或字符串解密器；-6 accumulator/loader key/数据加载器；
// -7 受保护数据或 runtime material。white-box 求值失败会立即投毒 whitebox lane。
// 所有栈上密钥/摘要最后统一 secure_zero；全部成功后才原子发布 runtime material。
static int cprisk_init_protection_whitebox_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    const uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE],
    const uint8_t integrity[CPRISK_ARMOR_HASH_SIZE]
) {
    uint8_t pass1_key[CPRISK_ARMOR_KEY_SIZE];
    uint8_t acc_digest[CPRISK_ARMOR_HASH_SIZE];
    uint8_t acc_seed[CPRISK_ARMOR_HASH_SIZE];
    uint8_t loader_digest[CPRISK_ARMOR_HASH_SIZE];
    uint8_t loader_key[CPRISK_ARMOR_KEY_SIZE];
    uint8_t runtime_digest[CPRISK_ARMOR_HASH_SIZE];
    uint8_t anchor_acc_le[8];
    uint8_t string_acc_le[8];
    uint8_t data_acc_le[8];
    uint64_t anchor_accumulator = 0;
    int rc = -1;

    memset(pass1_key, 0, sizeof(pass1_key));
    memset(acc_digest, 0, sizeof(acc_digest));
    memset(acc_seed, 0, sizeof(acc_seed));
    memset(loader_digest, 0, sizeof(loader_digest));
    memset(loader_key, 0, sizeof(loader_key));
    memset(runtime_digest, 0, sizeof(runtime_digest));
    memset(anchor_acc_le, 0, sizeof(anchor_acc_le));
    memset(string_acc_le, 0, sizeof(string_acc_le));
    memset(data_acc_le, 0, sizeof(data_acc_le));

    if (cprisk_verify_anchor_whitebox_i(full_anchor_hash) != 0) {
        cprisk_integrity_poison_whitebox_lane();
        rc = -4;
        goto cleanup;
    }

    if (cprisk_whitebox_evaluate_domain(
            CPRISK_WHITEBOX_DOMAIN_PASS1_STRING_KEY_I,
            NULL,
            pass1_key) != 0) {
        cprisk_integrity_poison_whitebox_lane();
        rc = -5;
        goto cleanup;
    }
    if (cprisk_init_string_decryptor(pass1_key, CPRISK_ARMOR_KEY_SIZE) != 0) {
        rc = -5;
        goto cleanup;
    }

    cprisk_prepare_deception_material_i(
        root_material, full_anchor_hash, integrity);

    cprisk_sha256_concat2_i(full_anchor_hash,
                            CPRISK_ARMOR_HASH_SIZE,
                            integrity,
                            CPRISK_ARMOR_HASH_SIZE,
                            acc_digest);
    if (cprisk_whitebox_evaluate_domain(
            CPRISK_WHITEBOX_DOMAIN_ANCHOR_ACCUMULATOR_SEED_I,
            acc_digest,
            acc_seed) != 0) {
        cprisk_integrity_poison_whitebox_lane();
        rc = -6;
        goto cleanup;
    }
    anchor_accumulator = cprisk_rotl64_i(cprisk_u64_from_le_i(acc_seed), 7U);
    cprisk_u64_to_le_i(anchor_accumulator, anchor_acc_le);

    cprisk_sha256_concat3_i(full_anchor_hash,
                            CPRISK_ARMOR_HASH_SIZE,
                            integrity,
                            CPRISK_ARMOR_HASH_SIZE,
                            anchor_acc_le,
                            sizeof(anchor_acc_le),
                            loader_digest);
    if (cprisk_whitebox_evaluate_domain(
            CPRISK_WHITEBOX_DOMAIN_LOADER_KEY_I,
            loader_digest,
            loader_key) != 0) {
        cprisk_integrity_poison_whitebox_lane();
        rc = -6;
        goto cleanup;
    }

    if (!cprisk_mini_vm_bootstrap_disabled())
        cprisk_loader_key_mini_vm_bootstrap(loader_key);

    if (cprisk_init_data_loader(loader_key, CPRISK_ARMOR_KEY_SIZE) != 0) {
        rc = -6;
        goto cleanup;
    }

    if (cprisk_load_protected_data() < 0) {
        cprisk_unload_protected_data();
        rc = -7;
        goto cleanup;
    }

    cprisk_u64_to_le_i(cprisk_get_string_integrity_accumulator(), string_acc_le);
    cprisk_u64_to_le_i(cprisk_get_data_integrity_accumulator(), data_acc_le);
    cprisk_sha256_concat4_i(full_anchor_hash,
                            CPRISK_ARMOR_HASH_SIZE,
                            integrity,
                            CPRISK_ARMOR_HASH_SIZE,
                            string_acc_le,
                            sizeof(string_acc_le),
                            data_acc_le,
                            sizeof(data_acc_le),
                            runtime_digest);
    if (cprisk_whitebox_evaluate_domain(
            CPRISK_WHITEBOX_DOMAIN_RUNTIME_MATERIAL_I,
            runtime_digest,
            s_runtime_material) != 0) {
        cprisk_integrity_poison_whitebox_lane();
        cprisk_unload_protected_data();
        rc = -7;
        goto cleanup;
    }

    if (!cprisk_mini_vm_bootstrap_disabled())
        cprisk_mini_vm_bootstrap_material32(s_runtime_material);
    atomic_store(&s_runtime_material_ready, 1);
    rc = 0;

cleanup:
    cprisk_secure_zero(pass1_key, sizeof(pass1_key));
    cprisk_secure_zero(acc_digest, sizeof(acc_digest));
    cprisk_secure_zero(acc_seed, sizeof(acc_seed));
    cprisk_secure_zero(loader_digest, sizeof(loader_digest));
    cprisk_secure_zero(loader_key, sizeof(loader_key));
    cprisk_secure_zero(runtime_digest, sizeof(runtime_digest));
    cprisk_secure_zero(anchor_acc_le, sizeof(anchor_acc_le));
    cprisk_secure_zero(string_acc_le, sizeof(string_acc_le));
    cprisk_secure_zero(data_acc_le, sizeof(data_acc_le));
    return rc;
}

/* ── Path A: Mach VM read ──────────────────────────────────────────── */

/* vm_size_t is 32-bit on Darwin; avoid truncation when sz > UINT32_MAX */
// Darwin 的 vm_size_t 是 32 位；单次 vm_read_overwrite 不超过 UINT32_MAX，
// 超出部分分块读取，避免长度截断。
#define CPRISK_VM_READ_CHUNK_MAX ((size_t)0xFFFFFFFFUL)

// Path A：用 vm_read_overwrite 把 __text 读入堆缓冲区再计算 SHA256，
// 观察的是内核 VM 暴露的内存视图。读取失败/短读即返回 -1；
// 缓冲区在释放前清零，避免残留代码字节。
static int path_a(const struct mach_header_64 *hdr, uint8_t *out) {
    unsigned long sz = 0;
    const uint8_t *text = cprisk_find_section(hdr, "__TEXT", "__text", &sz);
    if (!text || sz == 0)
        return -1;

    uint8_t *buf = NULL;
    buf = (uint8_t *)malloc(sz);
    if (!buf)
        return -1;

    size_t total_read = 0;
    size_t offset = 0;
    while (offset < sz) {
        size_t to_read = sz - offset;
        if (to_read > CPRISK_VM_READ_CHUNK_MAX)
            to_read = CPRISK_VM_READ_CHUNK_MAX;

        vm_size_t vmsz = (vm_size_t)to_read;
        vm_size_t out_sz = vmsz;
        kern_return_t kr = vm_read_overwrite(
            mach_task_self(),
            (vm_address_t)(text + offset),
            vmsz,
            (vm_address_t)(buf + offset),
            &out_sz);
        if (kr != KERN_SUCCESS) {
            cprisk_secure_zero(buf, total_read);
            free(buf);
            return -1;
        }
        total_read += (size_t)out_sz;
        offset += (size_t)out_sz;
        if (out_sz < vmsz)
            break;
    }

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    size_t rem = total_read;
    const uint8_t *p = buf;
    while (rem > 0) {
        size_t chunk = (rem > 0x40000000UL) ? 0x40000000UL : rem;
        cprisk_sha256_update(&ctx, p, chunk);
        p   += chunk;
        rem -= chunk;
    }
    cprisk_sha256_final(&ctx, out);

    cprisk_secure_zero(buf, total_read);
    free(buf);
    return 0;
}

/* ── Path B: direct pointer read ───────────────────────────────────── */

// Path B：直接按指针读取 __TEXT.__text 计算 SHA256，绕过 VM 读取 API，
// 与 Path A 构成两套独立观察面。分块仅限制单次 update 大小；失败返回 -1。
static int path_b(const struct mach_header_64 *hdr, uint8_t *out) {
    unsigned long sz = 0;
    const uint8_t *text = cprisk_find_section(hdr, "__TEXT", "__text", &sz);
    if (!text || sz == 0)
        return -1;

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    size_t rem = sz;
    const uint8_t *p = text;
    while (rem > 0) {
        size_t chunk = (rem > 0x40000000UL) ? 0x40000000UL : rem;
        cprisk_sha256_update(&ctx, p, chunk);
        p   += chunk;
        rem -= chunk;
    }
    cprisk_sha256_final(&ctx, out);

    return 0;
}

/* ── Path C: reassemble from split anchor sections ─────────────────── */

// Path C：不从代码段读取，而是从 __DATA 的 4 个 anchor lane 重建构建期 __text 摘要。
// 任一 lane 缺失或长度不足即返回 -1；
// 该路径用于检测 anchor 区被裁剪/重排/替换，与 A/B 的运行时内存观察互补。
static int path_c(const struct mach_header_64 *hdr, uint8_t *out) {
    // ABI v3 split anchor：4 条 lane 顺序固定（A/B/C/D），每条 8 字节，拼回 32 字节完整摘要。
    // 顺序是 producer/runtime 契约，重排会改变重建结果。
    static const char *names[CPRISK_ARMOR_ANCHOR_LANE_COUNT] = {
        CPRISK_ARMOR_SECTION_ANCHOR_A,
        CPRISK_ARMOR_SECTION_ANCHOR_B,
        CPRISK_ARMOR_SECTION_ANCHOR_C,
        CPRISK_ARMOR_SECTION_ANCHOR_D
    };
    for (uint32_t i = 0; i < CPRISK_ARMOR_ANCHOR_LANE_COUNT; i++) {
        unsigned long sz = 0;
        const uint8_t *p = cprisk_find_section(
            hdr, CPRISK_ARMOR_SEGMENT_DATA, names[i], &sz);
        if (!p || sz < CPRISK_ARMOR_ANCHOR_LANE_SIZE)
            return -1;
        memcpy(out + i * CPRISK_ARMOR_ANCHOR_LANE_SIZE,
               p,
               CPRISK_ARMOR_ANCHOR_LANE_SIZE);
    }
    return 0;
}

// 无符号绝对差，避免有符号相减溢出导致的未定义行为。
static uint64_t cprisk_abs_u64_i(uint64_t lhs, uint64_t rhs) {
    return lhs >= rhs ? (lhs - rhs) : (rhs - lhs);
}

// 路径耗时 canary：A/B 都成功且样本足够大时，若较慢路径比较快路径慢 48 倍以上
// 且绝对差 >=15ms，说明某一路径可能被 hook/单步拖慢，完整投毒 RECHECK lane。
// 失败路径或样本过小直接返回，避免噪声误报。
static void cprisk_integrity_timing_canary_i(
    int path_a_rc,
    int path_b_rc,
    uint64_t path_a_ns,
    uint64_t path_b_ns
) {
    if (path_a_rc != 0 || path_b_rc != 0 || path_a_ns == 0u || path_b_ns == 0u) {
        return;
    }

    const uint64_t slower = path_a_ns > path_b_ns ? path_a_ns : path_b_ns;
    const uint64_t faster = path_a_ns > path_b_ns ? path_b_ns : path_a_ns;
    if (faster < 5000u) {
        return;
    }

    const double ratio = (double)slower / (double)faster;
    const uint64_t delta_ns = cprisk_abs_u64_i(path_a_ns, path_b_ns);
    if (ratio >= 48.0 && delta_ns >= 15000000ull) {
        cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_RECHECK);
    }
}

/* ── public API ────────────────────────────────────────────────────── */

// 计算最终完整性摘要：
//   ha = Path A（VM 读取）、hb = Path B（直接读）、hc = Path C（anchor 重建）；
//   三段各 32 字节拼接后整体 SHA256，输出 32 字节。
// 多路径的意义：三条路径观测面不同（内核 VM / 原始内存 / 静态 anchor），
// 单点 hook 或局部 patch 很难同时欺骗三者。任一路径失败时用 32 字节 0xFF 占位，
// 使结果仍确定但不可伪造（fail-closed）。
// 返回 -1 仅表示 out_hash 为 NULL 或找不到自身 header。
// 线程安全：只读自身 Mach-O 与全局只读状态，可并发调用（路径内缓冲区独立）。
int cprisk_compute_integrity_hash(uint8_t *out_hash) {
    if (!out_hash)
        return -1;

    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    if (!hdr)
        return -1;

    uint8_t ha[CPRISK_SHA256_DIGEST_LENGTH];
    uint8_t hb[CPRISK_SHA256_DIGEST_LENGTH];
    uint8_t hc[CPRISK_SHA256_DIGEST_LENGTH];

    const uint64_t path_a_start_ns = cprisk_monotonic_ns();
    int ra = path_a(hdr, ha);
    const uint64_t path_a_end_ns = cprisk_monotonic_ns();

    const uint64_t path_b_start_ns = cprisk_monotonic_ns();
    int rb = path_b(hdr, hb);
    const uint64_t path_b_end_ns = cprisk_monotonic_ns();

    int rc = path_c(hdr, hc);
    uint64_t path_a_ns = 0u;
    uint64_t path_b_ns = 0u;
    if (path_a_end_ns >= path_a_start_ns) {
        path_a_ns = path_a_end_ns - path_a_start_ns;
    }
    if (path_b_end_ns >= path_b_start_ns) {
        path_b_ns = path_b_end_ns - path_b_start_ns;
    }
    cprisk_integrity_timing_canary_i(ra, rb, path_a_ns, path_b_ns);

    uint8_t cat[CPRISK_SHA256_DIGEST_LENGTH * 3];
    if (ra == 0)
        memcpy(cat, ha, CPRISK_SHA256_DIGEST_LENGTH);
    else
        memset(cat, 0xFF, CPRISK_SHA256_DIGEST_LENGTH);

    if (rb == 0)
        memcpy(cat + CPRISK_SHA256_DIGEST_LENGTH, hb, CPRISK_SHA256_DIGEST_LENGTH);
    else
        memset(cat + CPRISK_SHA256_DIGEST_LENGTH, 0xFF, CPRISK_SHA256_DIGEST_LENGTH);

    if (rc == 0)
        memcpy(cat + 2 * CPRISK_SHA256_DIGEST_LENGTH, hc, CPRISK_SHA256_DIGEST_LENGTH);
    else
        memset(cat + 2 * CPRISK_SHA256_DIGEST_LENGTH, 0xFF, CPRISK_SHA256_DIGEST_LENGTH);

    cprisk_sha256(cat, sizeof(cat), out_hash);

    cprisk_secure_zero(ha, sizeof(ha));
    cprisk_secure_zero(hb, sizeof(hb));
    cprisk_secure_zero(hc, sizeof(hc));
    cprisk_secure_zero(cat, sizeof(cat));

    return 0;
}

// 读取构建期完整 anchor 摘要：ABI v3 由 4 个 split lane 拼回 32 字节。
// 返回 -1 表示 out_hash 为 NULL 或任一 lane 缺失；调用方应把失败当作 init 失败（-3）。
int cprisk_read_full_anchor_hash(uint8_t *out_hash) {
    if (!out_hash)
        return -1;

    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    if (!hdr)
        return -1;

    /* ABI v2: reconstruct fullHash from split anchor lanes */
    return path_c(hdr, out_hash);
}

// 用 root_material 对 full_hash 计算 CPRisk-MAC，并与 __DATA 中的 32 字节 tag
// 做常量时间比较。返回 -1 表示 header/section 缺失或长度不足；
// 0 表示 MAC 匹配；非 0 表示不匹配。注意：这里只验证 root 与 anchor 的绑定。
int cprisk_verify_anchor_mac(const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
                              const uint8_t full_hash[CPRISK_ARMOR_HASH_SIZE]) {
    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    if (!hdr)
        return -1;

    unsigned long sz = 0;
    const uint8_t *sec = cprisk_find_section(
        hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_FULL_HASH, &sz);
    if (!sec || sz < CPRISK_ARMOR_MAC_FULL_HASH_SECTION_SIZE)
        return -1;

    uint8_t computed_mac[CPRISK_ARMOR_HASH_SIZE];
    cprisk_mac_sha256(root_material, CPRISK_ARMOR_KEY_SIZE,
                       full_hash, CPRISK_ARMOR_HASH_SIZE,
                       computed_mac);

    int result = cprisk_mac_verify(sec, computed_mac, CPRISK_ARMOR_HASH_SIZE);
    cprisk_secure_zero(computed_mac, sizeof(computed_mac));
    return result;
}

// mach_absolute_time 转纳秒的换算表：pthread_once 保证只初始化一次，可并发读取。
static mach_timebase_info_data_t s_integrity_tb;
static pthread_once_t s_integrity_tb_once = PTHREAD_ONCE_INIT;
// 初始化 timebase；denom 异常时后续 monotonic 返回 0，调用方按“样本无效”处理。
static void cprisk_integrity_tb_init(void) {
    mach_timebase_info(&s_integrity_tb);
}

// 单调纳秒时钟：拆分乘除避免 abs_time * numer 溢出；返回无符号值，失败时可能为 0。
static uint64_t cprisk_monotonic_ns(void) {
    pthread_once(&s_integrity_tb_once, cprisk_integrity_tb_init);
    mach_timebase_info_data_t tb = s_integrity_tb;
    if (tb.denom == 0)
        return 0;
    uint64_t abs_time = mach_absolute_time();
    /* Avoid overflow: split multiply to prevent abs_time * numer from wrapping. */
    return abs_time / tb.denom * tb.numer + (abs_time % tb.denom) * tb.numer / tb.denom;
}

/* Start of protection. NOTE (start→seal window, issue 54): the runtime
 * material is published (ready flag set) only after ALL init steps
 * (integrity hash, anchor hash, white-box/legacy init) complete inside
 * this call; callers must treat the process as unsealed until this
 * returns 0, and must call cprisk_cleanup_protection() on failure so no
 * half-initialised material stays live. Keep this function short and
 * single-threaded: concurrent evaluate() calls must wait for it. */
// 启动保护（单线程，必须在并发 evaluate() 之前调用）：
// 严格校验 root key → 计算并保存完整性基线 → PAC/CFI 自检 → 应用初始反调试策略 →
// 重建 anchor 摘要 → white-box/legacy 初始化 → 初始化三层 Hybrid KDF →
// 启动 anti-dump 探针。全部完成后才发布 runtime material（ready=1）。
// 返回：0 成功；-1 root 长度错误或全零；-2 完整性摘要计算失败；-3 anchor 读取失败；
//      -4 anchor MAC/tag 校验失败；-5 字符串解密器/pass1 失败；-6 PAC/CFI/loader key 失败；
//      -7 受保护数据或 runtime material 失败；-8 MTE 自检/canary 失败。
// 失败语义（fail-closed）：清零并撤销 runtime material；调用方必须 cprisk_cleanup_protection()。
// Hybrid KDF 失败不改变返回码，但 effectiveRoot 保持未就绪，依赖路径自行 fail-closed。
// start→seal 窗口：本函数返回 0 之前进程应视为未密封。
int cprisk_init_protection(const uint8_t *root_key, size_t root_key_len) {
    // 每次 init 前彻底清空上一次的保护/投毒状态，避免跨 init 残留导致误判或残留密钥。
    uint64_t t_start = cprisk_monotonic_ns();

    uint8_t root_material[CPRISK_ARMOR_KEY_SIZE];
    uint8_t integrity[CPRISK_ARMOR_HASH_SIZE];
    uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE];
    int rc = -1;

    s_integrity_poisoned = 0;
    cprisk_integrity_poison_semantic_reset_i();
    atomic_store(&s_staged_watchdog_hits, 0u);
    atomic_store(&s_staged_watchdog_slow_wave, 0u);
    atomic_store(&s_staged_anti_dump_hits, 0u);
    atomic_store(&s_staged_opacity_tick, 0ull);
    s_integrity_hash_saved = 0;
    s_integrity_deception_active = 0;
    atomic_store(&s_runtime_material_ready, 0);
    atomic_store(&s_deception_material_ready, 0);
    cprisk_secure_zero(s_runtime_material, sizeof(s_runtime_material));
    cprisk_secure_zero(s_saved_integrity_hash, sizeof(s_saved_integrity_hash));
    cprisk_secure_zero(s_deception_material, sizeof(s_deception_material));
#if defined(CPRISK_MTE_COMPILE_SUPPORT)
    cprisk_mte_canary_remove(&s_runtime_material_canary);
    cprisk_mte_canary_remove(&s_saved_integrity_canary);
#endif
    cprisk_antidebug_reset_plan_state_i();

    // 根材料必须严格 32 字节且非全零；长度错误/全零都在这里拒绝，不补零、不截断。
    if (cprisk_fill_root_material_i(root_key, root_key_len, root_material) != 0) {
        /* Wrong-length root key: hard fail (no zero-pad / no truncation). */
        rc = -1;
        goto cleanup;
    }

    /* Reject NULL or all-zero root keys */
    {
        int all_zero = 1;
        for (int zi = 0; zi < CPRISK_ARMOR_KEY_SIZE; zi++) {
            if (root_material[zi] != 0) { all_zero = 0; break; }
        }
        if (all_zero) {
            rc = -1;
            goto cleanup;
        }
    }

    // 计算并保存完整性基线；失败则无法进入任何派生路径（fail-closed）。
    if (cprisk_compute_integrity_hash(integrity) != 0) {
        rc = -2;
        goto cleanup;
    }

    if (cprisk_validate_pac_cfi_i(root_material, CPRISK_ARMOR_KEY_SIZE) != 0) {
        rc = -6;
        goto cleanup;
    }

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    /* Reuse adaptive baseline from signal-probe single-step detector. */
    if (cprisk_detect_single_stepping()) {
        s_integrity_deception_active = 1;
    }
#endif

    cprisk_antidebug_apply_policies_i(CPRISK_ADBG_TRIGGER_INIT_I, 0, 0);

    // 保存基线供后续 recheck 比对；必须在任何并发读开始前写入。
    memcpy(s_saved_integrity_hash, integrity, CPRISK_ARMOR_HASH_SIZE);
    s_integrity_hash_saved = 1;

    if (cprisk_read_full_anchor_hash(full_anchor_hash) != 0) {
        rc = -3;
        goto cleanup;
    }

    if (cprisk_whitebox_available() != 0) {
        rc = cprisk_init_protection_whitebox_i(
            root_material,
            full_anchor_hash,
            integrity);
    } else {
        rc = cprisk_init_protection_legacy_i(
            root_material,
            full_anchor_hash,
            integrity);
    }

    /* Initialize three-layer Hybrid KDF (device + session binding).
     * This populates s_effective_root which dynamic white-box domains 6-7 consume.
     * Called regardless of the whitebox/legacy init result so that the
     * new domains are available as soon as a valid root_key is provided. */
    /* Hybrid KDF failure (e.g. device binding unavailable) leaves the
     * effective root unready; dependent paths fail closed. Return value
     * is intentionally not fatal to init_protection itself. */
    // 三层 KDF 初始化：成功时填充 effectiveRoot；失败（设备绑定不可用）时保持未就绪，
    // 绝不把原始 rootKey 冒充为绑定密钥——依赖 effectiveRoot 的路径会 fail-closed。
    (void)cprisk_init_hybrid_kdf(root_key);

    if (rc == 0) {
        /* Keep anti-dump probe lifecycle tied to protection lifecycle,
         * while remaining idempotent when watchdog already started it. */
        // 反 dump 探针与保护生命周期绑定；重复启动必须幂等（watchdog 可能已先启动）。
        (void)cprisk_start_anti_dump_probe(5);
        cprisk_apply_deferred_early_injection_policy();
#if defined(CPRISK_MTE_COMPILE_SUPPORT)
        if (cprisk_mte_available() != 0) {
            // MTE 自检或 canary 安装失败：撤销已发布的材料与解密器，
            // 投毒 RECHECK lane，返回 -8（fail-closed）。
            if (cprisk_mte_self_test() != 0) {
                cprisk_secure_zero(s_runtime_material, sizeof(s_runtime_material));
                atomic_store(&s_runtime_material_ready, 0);
                cprisk_unload_protected_data();
                cprisk_cleanup_string_decryptor();
                cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_RECHECK);
                rc = -8;
            } else if (cprisk_mte_canary_install(
                           &s_runtime_material_canary,
                           s_runtime_material,
                           sizeof(s_runtime_material)) != 0 ||
                       cprisk_mte_canary_install(
                           &s_saved_integrity_canary,
                           s_saved_integrity_hash,
                           sizeof(s_saved_integrity_hash)) != 0) {
                cprisk_mte_canary_remove(&s_runtime_material_canary);
                cprisk_mte_canary_remove(&s_saved_integrity_canary);
                cprisk_secure_zero(s_runtime_material, sizeof(s_runtime_material));
                atomic_store(&s_runtime_material_ready, 0);
                cprisk_unload_protected_data();
                cprisk_cleanup_string_decryptor();
                cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_RECHECK);
                rc = -8;
            }
        }
#endif
    }

// 失败收尾：通知反调试策略“init 失败”，并清零未发布的 runtime material；
// 调用方仍需在返回非 0 时调用 cprisk_cleanup_protection()。
cleanup:
    if (rc != 0) {
        cprisk_antidebug_apply_policies_i(
            CPRISK_ADBG_TRIGGER_INIT_FAILURE_I,
            rc,
            rc == -2 ? 1 : 0);
    }
    if (rc != 0) {
        cprisk_secure_zero(s_runtime_material, sizeof(s_runtime_material));
        atomic_store(&s_runtime_material_ready, 0);
    }

    /* Shorten key lifetime (issue 52): stack copies are zeroed as soon
     * as they are no longer needed. Complete eradication is impossible —
     * copies may still exist in the caller's buffer, in registers, in
     * Swift-side material, and in derived values — so zeroing here is
     * hygiene, not a guarantee. The long-lived copies (s_runtime_material
     * etc.) are zeroed by cprisk_cleanup_protection(). */
    // 尽早清零栈上密钥副本（issue 52）。这只是卫生措施，
    // 无法清除寄存器、调用方缓冲区或 Swift 侧副本。
    cprisk_secure_zero(root_material, sizeof(root_material));
    cprisk_secure_zero(integrity, sizeof(integrity));
    cprisk_secure_zero(full_anchor_hash, sizeof(full_anchor_hash));

    // 无论成功失败都记录耗时，供启动时序反调试与诊断使用。
    s_init_elapsed_ns = cprisk_monotonic_ns() - t_start;
    return rc;
}

// 释放保护状态（单线程/生命周期末尾）：移除 MTE canary，清零 runtime/deception/anchor
// 与 Hybrid KDF 密钥，重置投毒记账与加固配置，停止探针并卸载受保护数据。
// 清理后 cprisk_runtime_material_ready() 返回 0，get_runtime_material 返回欺骗材料。
void cprisk_cleanup_protection(void) {
#if defined(CPRISK_MTE_COMPILE_SUPPORT)
    cprisk_mte_canary_remove(&s_runtime_material_canary);
    cprisk_mte_canary_remove(&s_saved_integrity_canary);
#endif
    cprisk_secure_zero(s_runtime_material, sizeof(s_runtime_material));
    cprisk_secure_zero(s_saved_integrity_hash, sizeof(s_saved_integrity_hash));
    atomic_store(&s_runtime_material_ready, 0);
    cprisk_secure_zero(s_deception_material, sizeof(s_deception_material));
    atomic_store(&s_deception_material_ready, 0);
    s_integrity_hash_saved = 0;
    s_integrity_poisoned = 0;
    cprisk_integrity_poison_semantic_reset_i();
    atomic_store(&s_staged_watchdog_hits, 0u);
    atomic_store(&s_staged_anti_dump_hits, 0u);
    atomic_store(&s_staged_opacity_tick, 0ull);
    s_integrity_deception_active = 0;
    s_init_elapsed_ns = 0;
    /* Wipe Hybrid KDF state. */
    cprisk_secure_zero(s_device_key, sizeof(s_device_key));
    cprisk_secure_zero(s_effective_root, sizeof(s_effective_root));
    s_device_key_ready = 0;
    s_effective_root_ready = 0;
    cprisk_clear_session_token();
    cprisk_antidebug_reset_plan_state_i();
    cprisk_stop_anti_dump_probe();
    cprisk_cleanup_string_decryptor();
    cprisk_unload_protected_data();
    s_runtime_hardening_mode = CPRISK_RUNTIME_HARDENING_PRODUCTION;
    s_init_timing_threshold_override_ns = 0;
}

// 投毒输出混合：把 breadcrumb/rolling/epoch/cause_mix 与 32 字节缓冲逐字节混合，
// 使欺骗输出随“哪条 lane、以什么顺序触发”变化；h 耗尽时用黄金比例常数重新播种。
// 仅用于欺骗材料，不是密钥派生。
static void cprisk_poison_runtime_material_output_mix_i(uint8_t buf[32]) {
    uint64_t h = 0xD6E8FEB86655FD96ULL ^ (uint64_t)s_poison_semantic_breadcrumb;
    h ^= (uint64_t)s_poison_semantic_rolling[0] << 32;
    h ^= (uint64_t)s_poison_semantic_rolling[1];
    h ^= (uint64_t)s_poison_epoch * 0x9E3779B97F4A7C15ULL;
    h ^= s_poison_cause_mix;
    for (size_t i = 0; i < 32u; i++) {
        h ^= (uint64_t)buf[i] ^ ((uint64_t)i * 0x100000001B3ULL);
        h ^= h >> 33;
        h *= 0xff51afd7ed558ccdULL;
        h ^= h >> 33;
        h *= 0xc4ceb9fe1a85ec53ULL;
        h ^= h >> 33;
        buf[i] ^= (uint8_t)(h & 0xFFu);
        h >>= 8;
        if (h == 0)
            h = 0x9E3779B97F4A7C15ULL ^ (uint64_t)(i + 1u);
    }
}

// 读取运行时材料（复制到调用方 32 字节缓冲区）。
// 正常路径返回 init 派生的材料；若未就绪/已投毒/欺骗激活，返回经混合的欺骗材料。
// 返回 0 表示已写出 32 字节；-1 表示 out 为 NULL。
// 线程安全：原子 ready + 普通拷贝；调用方必须把结果视为不可信材料，不得用于安全判定。
int cprisk_get_runtime_material(uint8_t out_material[32]) {
    if (!out_material)
        return -1;

    if (s_integrity_poisoned || s_integrity_deception_active || atomic_load(&s_runtime_material_ready) == 0) {
        cprisk_prepare_deception_material_i(NULL, NULL, NULL);
        memcpy(out_material, s_deception_material, CPRISK_ARMOR_HASH_SIZE);
        cprisk_poison_runtime_material_output_mix_i(out_material);
        return 0;
    }

    memcpy(out_material, s_runtime_material, CPRISK_ARMOR_HASH_SIZE);
    return 0;
}

// 原子发布查询：1=init 已完整发布 runtime material；0=未就绪/已清理/init 失败。
int cprisk_runtime_material_ready(void) {
    return atomic_load(&s_runtime_material_ready) != 0 ? 1 : 0;
}

enum {
    // 完整性复查失败原因（折入 cause_mix 高位）：PAC、MTE、摘要计算、基线差异。
    CPRISK_POISON_RECHECK_SUB_PAC = 0xA01u,
    CPRISK_POISON_RECHECK_SUB_MTE = 0xA02u,
    CPRISK_POISON_RECHECK_SUB_COMPUTE = 0xA03u,
    CPRISK_POISON_RECHECK_SUB_DIFF = 0xA04u,
};

// 复查失败的统一投毒入口：置全局 poisoned，把 subreason 折入 cause_mix，
// 记录 RECHECK lane 副作用；满足条件时启用欺骗并扰动材料。
static void cprisk_integrity_poison_from_recheck_i(uint32_t subreason) {
    s_integrity_poisoned = 1;
    s_poison_cause_mix ^= (uint64_t)subreason << 40;
    cprisk_integrity_poison_lane_sidefx_i(CPRISK_POISON_LANE_RECHECK);
    if (cprisk_should_activate_deception_i()) {
        cprisk_prepare_deception_material_i(NULL, NULL, NULL);
        s_integrity_deception_active = 1;
        cprisk_integrity_poison_lane_tweak_deception_i(CPRISK_POISON_LANE_RECHECK);
    }
}

// 周期性完整性复查：
// 未保存基线返回 -1；调试器下返回 0 但静默启用欺骗（不上报，避免暴露检测点）。
// 依次校验 PAC/CFI、MTE canary（-1 才算失败，-2=不支持）、重新计算摘要并与基线逐字节比较。
// 返回 0=一致；1=篡改（PAC/MTE/摘要差异）；-2=无法计算摘要。
// 任何确认篡改的路径都会投毒 RECHECK lane 并通知反调试策略（fail-closed）。
int cprisk_recheck_integrity(void) {
    if (!s_integrity_hash_saved)
        return -1;

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    /* Under debugger: report "all clear" but silently activate deception */
    if (cprisk_is_being_traced_redundant()) {
        cprisk_prepare_deception_material_i(NULL, NULL, NULL);
        s_integrity_deception_active = 1;
        cprisk_antidebug_apply_policies_i(
            CPRISK_ADBG_TRIGGER_INTEGRITY_TAMPER_I,
            0,
            1);
        return 0;
    }
#endif

    if (cprisk_validate_pac_cfi_i(s_saved_integrity_hash, CPRISK_ARMOR_HASH_SIZE) != 0) {
        cprisk_integrity_poison_from_recheck_i(CPRISK_POISON_RECHECK_SUB_PAC);
        cprisk_antidebug_apply_policies_i(
            CPRISK_ADBG_TRIGGER_INTEGRITY_TAMPER_I,
            0,
            1);
        return 1;
    }

#if defined(CPRISK_MTE_COMPILE_SUPPORT)
    /* Only -1 (baseline mismatch) is a failure. -2 means "unsupported /
     * not installed" and must NOT poison: on devices without MTE the
     * canary is legitimately absent. */
    if (cprisk_mte_canary_verify(&s_runtime_material_canary) == -1 ||
        cprisk_mte_canary_verify(&s_saved_integrity_canary) == -1) {
        cprisk_integrity_poison_from_recheck_i(CPRISK_POISON_RECHECK_SUB_MTE);
        cprisk_antidebug_apply_policies_i(
            CPRISK_ADBG_TRIGGER_INTEGRITY_TAMPER_I,
            0,
            1);
        return 1;
    }
#endif

    uint8_t current[CPRISK_ARMOR_HASH_SIZE];
    if (cprisk_compute_integrity_hash(current) != 0) {
        cprisk_integrity_poison_from_recheck_i(CPRISK_POISON_RECHECK_SUB_COMPUTE);
        cprisk_antidebug_apply_policies_i(
            CPRISK_ADBG_TRIGGER_INTEGRITY_TAMPER_I,
            0,
            -2);
        cprisk_secure_zero(current, sizeof(current));
        return -2;
    }

    uint8_t diff = 0;
    for (int i = 0; i < CPRISK_ARMOR_HASH_SIZE; i++)
        diff |= current[i] ^ s_saved_integrity_hash[i];

    cprisk_secure_zero(current, sizeof(current));

    if (diff != 0) {
        cprisk_integrity_poison_from_recheck_i(CPRISK_POISON_RECHECK_SUB_DIFF);
        cprisk_antidebug_apply_policies_i(
            CPRISK_ADBG_TRIGGER_INTEGRITY_TAMPER_I,
            0,
            1);
        return 1;
    }
    return 0;
}

// 返回全局投毒锁存位；欺骗模式激活时恒返回 0（隐藏检测结果，避免 oracle）。
int cprisk_is_integrity_poisoned(void) {
    if (s_integrity_deception_active)
        return 0;
    return s_integrity_poisoned;
}

// 返回 lane 折叠指纹；欺骗模式下返回 0，避免暴露哪些 lane 触发。
uint32_t cprisk_get_integrity_poison_semantic_breadcrumb(void) {
    if (s_integrity_deception_active)
        return 0u;
    return s_poison_semantic_breadcrumb;
}

// 返回指定 lane 的累计事件数；越界或欺骗模式返回 0。
uint32_t cprisk_get_integrity_poison_lane_event_count(unsigned lane) {
    if (lane >= (unsigned)CPRISK_POISON_LANE_COUNT)
        return 0u;
    if (s_integrity_deception_active)
        return 0u;
    return s_poison_lane_seq[lane];
}

// 返回投毒波次计数；欺骗模式下返回 0。
uint32_t cprisk_get_integrity_poison_epoch(void) {
    if (s_integrity_deception_active)
        return 0u;
    return s_poison_epoch;
}

// 返回 watchdog 慢波阶段（0=空闲，1=已过一个阈值但未完整投毒）；欺骗模式下返回 0。
uint32_t cprisk_get_integrity_watchdog_slow_poison_phase(void) {
    if (s_integrity_deception_active)
        return 0u;
    return atomic_load(&s_staged_watchdog_slow_wave);
}

// 返回 (lane, 触发顺序) 折叠指纹；欺骗模式下返回 0。
uint64_t cprisk_get_integrity_poison_cause_mix(void) {
    if (s_integrity_deception_active)
        return 0u;
    return s_poison_cause_mix;
}

// EVT_A lane 完整投毒入口（通用事件 A）。
void cprisk_integrity_poison_evt_a(void) {
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_EVT_A);
}

// EVT_B lane 完整投毒入口（通用事件 B）。
void cprisk_integrity_poison_evt_b(void) {
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_EVT_B);
}

// watchdog lane 分级入口：未达阈值只做 staged，达阈值进入慢波/完整提交。
void cprisk_integrity_poison_watchdog_lane(void) {
    cprisk_integrity_poison_watchdog_lane_staged_i();
}

// 立即完整提交 watchdog lane，并清零 staged/慢波计数（高置信信号走这里）。
void cprisk_integrity_poison_watchdog_lane_now(void) {
    atomic_store(&s_staged_watchdog_hits, 0u);
    atomic_store(&s_staged_watchdog_slow_wave, 0u);
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_WATCHDOG);
}

// 高置信混合投毒：按 path_tag/epoch/cause_mix 轮转选择一条完整投毒 lane，
// 避免所有高置信响应落在同一 lane id 上被单点 patch；欺骗激活后直接返回。
void cprisk_integrity_poison_high_signal_mixed(uint32_t path_tag) {
    if (s_integrity_deception_active)
        return;
    /* Rotate full-lane commits so high-confidence responses are not dominated by a single lane id. */
    const uint32_t pick =
        (path_tag ^ (uint32_t)s_poison_epoch ^ (uint32_t)(s_poison_cause_mix >> 33)) % 5u;
    switch (pick) {
    case 0:
        cprisk_integrity_poison_watchdog_lane_now();
        break;
    case 1:
        cprisk_integrity_poison_antidebug_lane();
        break;
    case 2:
        cprisk_integrity_poison_exception_lane();
        break;
    case 3:
        cprisk_integrity_poison_svc_iface_lane();
        break;
    default:
        cprisk_integrity_poison_data_loader_lane();
        break;
    }
}

// 延迟应用“早期注入环境变量”策略：仅生产档位且确实检测到注入环境变量时，
// 触发一次高置信混合投毒 + watchdog staged 入口。
void cprisk_apply_deferred_early_injection_policy(void) {
    if (cprisk_get_early_injection_env_mask() == 0u) {
        return;
    }
    if (cprisk_get_runtime_hardening_mode() != CPRISK_RUNTIME_HARDENING_PRODUCTION) {
        return;
    }
    cprisk_integrity_poison_high_signal_mixed(0xE11A0001u);
    cprisk_integrity_poison_watchdog_lane();
}

// CODE_SIGNING lane 完整投毒：签名/Team ID/身份校验失败。
void cprisk_integrity_poison_code_signing_lane(void) {
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_CODE_SIGNING);
}

// SVC_IFACE lane 完整投毒：PAC/SVC/签名间接调用接口失败。
void cprisk_integrity_poison_svc_iface_lane(void) {
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_SVC_IFACE);
}

// ANTIDEBUG lane 完整投毒：反调试计划、跟踪交叉校验、运行期 gate 失败。
void cprisk_integrity_poison_antidebug_lane(void) {
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_ANTIDEBUG);
}

// EXCEPTION lane 完整投毒：异常端口指纹漂移/劫持竞态。
void cprisk_integrity_poison_exception_lane(void) {
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_EXCEPTION);
}

// ANTI_DUMP lane 分级入口：未达阈值走 staged，达阈值完整提交。
void cprisk_integrity_poison_anti_dump_lane(void) {
    cprisk_integrity_poison_anti_dump_lane_staged_i();
}

// 立即完整提交 ANTI_DUMP lane，并清零 staged 计数。
void cprisk_integrity_poison_anti_dump_lane_now(void) {
    atomic_store(&s_staged_anti_dump_hits, 0u);
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_ANTI_DUMP);
}

// DATA_LOADER lane 完整投毒：数据段加载器/JIT 解密保护路径失败。
void cprisk_integrity_poison_data_loader_lane(void) {
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_DATA_LOADER);
}

// TEXT_ENCRYPT lane 完整投毒：text 段页加密/重加密/状态迁移域失败。
void cprisk_integrity_poison_text_encrypt_lane(void) {
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_TEXT_ENCRYPT);
}

// WHITEBOX lane 完整投毒：white-box PRF 求值/校验失败。
void cprisk_integrity_poison_whitebox_lane(void) {
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_WHITEBOX);
}

// CFF lane 完整投毒：控制流平坦化默认投毒路径。
void cprisk_integrity_poison_cff_lane(void) {
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_CFF);
}

// 聚合强制投毒：分别提交 EVT_A/EVT_B/FORCE 三条 lane，
// 避免语义退化为单次 store / 单批副作用而被一次 hook 抹掉。
void cprisk_force_integrity_poison(void) {
    /* Aggregate: three independent lane commits so semantics are not a single store / single side-effect batch. */
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_EVT_A);
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_EVT_B);
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_FORCE);
}

// guard page 被访问：置 poisoned、记录 GUARD lane、强制启用欺骗并扰动材料，
// 同时通知 watchdog。调用即视为攻击行为（fail-closed）。
void cprisk_guard_page_fault_notify(void) {
    s_integrity_poisoned = 1;
    cprisk_integrity_poison_lane_sidefx_i(CPRISK_POISON_LANE_GUARD);
    s_integrity_deception_active = 1;
    cprisk_prepare_deception_material_i(NULL, NULL, NULL);
    cprisk_integrity_poison_lane_tweak_deception_i(CPRISK_POISON_LANE_GUARD);
    cprisk_watchdog_note_guard_page_fault();
}

// 返回最近一次 init 的耗时（纳秒）；非原子、弱一致，仅用于诊断/时序判断。
uint64_t cprisk_get_init_elapsed_ns(void) {
    return s_init_elapsed_ns;
}

// 设置加固档位；非法值回退到生产档。应在 init 前设置，运行期修改为弱一致。
void cprisk_set_runtime_hardening_mode(cprisk_runtime_hardening_mode_t mode) {
    if (mode != CPRISK_RUNTIME_HARDENING_PRODUCTION && mode != CPRISK_RUNTIME_HARDENING_RELAXED_DEV_QA &&
        mode != CPRISK_RUNTIME_HARDENING_APP_STORE_SAFE)
        mode = CPRISK_RUNTIME_HARDENING_PRODUCTION;
    s_runtime_hardening_mode = mode;
}

// 返回当前加固档位；未设置时为生产档。
cprisk_runtime_hardening_mode_t cprisk_get_runtime_hardening_mode(void) {
    return (cprisk_runtime_hardening_mode_t)s_runtime_hardening_mode;
}

// 返回当前 init 时序阈值：测试覆盖优先；否则读 hw.machine 并按机型代际 + 档位计算。
// sysctl 失败或机型未知时按最宽松机型处理。
uint64_t cprisk_get_init_timing_threshold_ns(void) {
    if (s_init_timing_threshold_override_ns != 0)
        return s_init_timing_threshold_override_ns;
    char machine[256];
    size_t len = sizeof(machine);
    int err = 0;
    if (cprisk_sysctlbyname_direct("hw.machine", machine, &len, NULL, 0, &err) != 0 || len == 0) {
        return cprisk_compute_init_timing_threshold_ns_for_machine_i(
            NULL,
            cprisk_get_runtime_hardening_mode());
    }
    if (len >= sizeof(machine))
        len = sizeof(machine) - 1;
    machine[len] = '\0';
    return cprisk_compute_init_timing_threshold_ns_for_machine_i(
        machine,
        cprisk_get_runtime_hardening_mode());
}

// 测试钩子：覆盖 init 时序阈值；非 DEBUG 构建为空操作。
void cprisk_test_set_init_timing_threshold_ns_override(uint64_t threshold_ns) {
#if !defined(DEBUG) || !DEBUG
    /* Test hook: inert outside DEBUG builds (issue 18). */
    return;
#endif
    s_init_timing_threshold_override_ns = threshold_ns;
}

/* Last signing-path mix tier + fingerprint (server-visible via GrpcReportPayload output_path_integrity). */
// 最近一次签名中间混合的层级标记（高 4 位）与指纹（低 28 位），
// 供上报/诊断（server-visible output_path_integrity）使用。
static uint32_t s_signing_mix_last_fp;

// 测试钩子：重置 staged 计数、投毒/欺骗状态与签名指纹；非 DEBUG 构建为空操作。
void cprisk_test_reset_staged_poison_for_tests(void) {
#if !defined(DEBUG) || !DEBUG
    /* Test hook: inert outside DEBUG builds (issue 18). */
    return;
#endif
    atomic_store(&s_staged_watchdog_hits, 0u);
    atomic_store(&s_staged_anti_dump_hits, 0u);
    atomic_store(&s_staged_opacity_tick, 0ull);
    atomic_store(&s_staged_watchdog_slow_wave, 0u);
    s_integrity_poisoned = 0;
    s_integrity_deception_active = 0;
    s_signing_mix_last_fp = 0u;
    cprisk_integrity_poison_semantic_reset_i();
}

/* Passive/cached environment binding for signing/whitebox hot paths: no cprisk_run_all_signal_probes(). */
enum {
    // 被动绑定信号位：只读缓存/轻量探测，不触发完整 cprisk_run_all_signal_probes()，
    // 供签名/whitebox 热路径使用；位定义是内部契约。
    CPRISK_PASSIVE_BINDING_TRACE = 1u << 0,
    CPRISK_PASSIVE_BINDING_DBI = 1u << 1,
    CPRISK_PASSIVE_BINDING_TIMING = 1u << 2,
    CPRISK_PASSIVE_BINDING_LIBC_FALLBACK = 1u << 3,
    CPRISK_PASSIVE_BINDING_TTY = 1u << 4,
    CPRISK_PASSIVE_BINDING_DEVELOPER_DISK = 1u << 5,
};

// 汇总被动绑定位（跟踪/DBI/时序/libc 回退/TTY/开发者磁盘）。
// 只读取已有探针状态，不产生新探测；可并发调用。
uint32_t cprisk_collect_passive_signal_binding_bits(void) {
    uint32_t bits = 0u;
    if (cprisk_trace_crosscheck_inconsistent() != 0 || cprisk_is_being_traced_sysctl_only() != 0)
        bits |= CPRISK_PASSIVE_BINDING_TRACE;
    if (cprisk_get_last_dbi_marker_flags() != 0u)
        bits |= CPRISK_PASSIVE_BINDING_DBI;
    if (cprisk_get_last_timing_anomaly_flags() != 0u || cprisk_check_init_timing() != 0)
        bits |= CPRISK_PASSIVE_BINDING_TIMING;
    if (cprisk_get_libc_fallback_used_mask() != 0u)
        bits |= CPRISK_PASSIVE_BINDING_LIBC_FALLBACK;
    if (cprisk_detect_tty_debug() != 0)
        bits |= CPRISK_PASSIVE_BINDING_TTY;
    if (cprisk_detect_developer_disk() != 0)
        bits |= CPRISK_PASSIVE_BINDING_DEVELOPER_DISK;
    return bits;
}

// 记录本次签名混合层级与 28 位指纹；层级写入高 4 位，低 28 位为 seed 折叠值。
static void cprisk_signing_mix_set_fp_i(uint32_t tier_tag28, uint64_t seed) {
    uint32_t h = (uint32_t)(seed ^ (seed >> 32));
    h ^= tier_tag28 * 0x13579BDFu;
    s_signing_mix_last_fp = (tier_tag28 << 28) | (h & 0x0FFFFFFFu);
}

// 签名中间材料分层混合：未就绪/已投毒/欺骗时直接返回；否则按 staged、弱被动信号、
// degraded trace/DBI、ambient hook-surface 的优先级选择一层，
// 用 SHA256(label || seed || buf) 生成掩码并只扰动部分字节（层级越高扰动越多），
// 同时记录指纹。该函数只改签名中间缓冲，不修改原始 runtime bytes。
// 线程安全：可并发调用；竞态仅影响指纹/掩码，不影响内存安全。
void cprisk_signing_runtime_material_intermediate_mix(uint8_t buf[32]) {
    if (!buf)
        return;
    if (atomic_load(&s_runtime_material_ready) == 0)
        return;
    if (s_integrity_poisoned || s_integrity_deception_active)
        return;

    const uint32_t wd = atomic_load(&s_staged_watchdog_hits);
    const uint32_t ad = atomic_load(&s_staged_anti_dump_hits);
    const uint32_t staged_sum = wd + ad;

    int strong_staged = 0;
    int medium_staged = 0;
    uint64_t seed = 0;

    if (wd > 0u || ad > 0u) {
        seed = atomic_load(&s_staged_opacity_tick) ^ s_poison_cause_mix;
        if (staged_sum == 1u) {
            medium_staged = 1;
        } else {
            strong_staged = 1;
        }
    }
    if (!strong_staged && !medium_staged && atomic_load(&s_staged_watchdog_slow_wave) > 0u) {
        seed = atomic_load(&s_staged_opacity_tick) ^ s_poison_cause_mix ^ 0x514E554657445231ULL;
        strong_staged = 1;
    }

    int weak_only = 0;
    int degraded_tier = 0;
    if (!strong_staged && !medium_staged) {
        const uint32_t passive_bits = cprisk_collect_passive_signal_binding_bits();
        const uint32_t weak_mask =
            CPRISK_PASSIVE_BINDING_TIMING |
            CPRISK_PASSIVE_BINDING_LIBC_FALLBACK |
            CPRISK_PASSIVE_BINDING_TTY |
            CPRISK_PASSIVE_BINDING_DEVELOPER_DISK;
        const uint32_t strongish =
            CPRISK_PASSIVE_BINDING_TRACE |
            CPRISK_PASSIVE_BINDING_DBI;
        if ((passive_bits & weak_mask) != 0u && (passive_bits & strongish) == 0u &&
            cprisk_is_being_traced_redundant() == 0) {
            weak_only = 1;
            seed = (uint64_t)passive_bits * 0xD6E8FEB86655FD96ULL ^ 0x9E3779B97F4A7C15ULL;
        } else if (!weak_only) {
            const int has_tr = (passive_bits & CPRISK_PASSIVE_BINDING_TRACE) != 0u;
            const int has_dbi = (passive_bits & CPRISK_PASSIVE_BINDING_DBI) != 0u;
            if (has_tr || has_dbi) {
                seed = (uint64_t)passive_bits * 0xD6E8FEB86655FD96ULL ^
                       (uint64_t)s_poison_cause_mix ^ atomic_load(&s_staged_opacity_tick);
                if (has_tr && has_dbi) {
                    degraded_tier = 6;
                } else if (has_tr) {
                    degraded_tier = 4;
                } else {
                    degraded_tier = 5;
                }
            }
        }
    }

    /* Ambient / hook-surface tier: wb_pressure has trace/VM/mprotect/timing/libc bits (2–7)
     * but staged + passive paths above did not already classify — e.g. Mach↔POSIX mprotect
     * mismatch without TTY/timing weak bucket. Perturbs signing material only (not raw runtime bytes). */
    int ambient = 0;
    if (!strong_staged && !medium_staged && !weak_only && degraded_tier == 0) {
        const uint32_t wp = cprisk_integrity_wb_prf_pressure_mask();
        if ((wp & 0xFCu) != 0u) {
            ambient = 1;
            seed = (uint64_t)wp * 0xD6E8FEB86655FD96ULL;
            seed ^= (uint64_t)cprisk_get_vm_mprotect_crosscheck_mismatch_count() << 32;
            seed ^= (uint64_t)cprisk_get_vm_mprotect_mach_trap_mismatch_count();
            seed ^= atomic_load(&s_staged_opacity_tick);
            seed ^= s_poison_cause_mix;
        }
    }

    if (!strong_staged && !medium_staged && !weak_only && degraded_tier == 0 && !ambient)
        return;

    uint8_t seed_le[8];
    cprisk_u64_to_le_i(seed, seed_le);
    cprisk_sha256_ctx ctx;

    if (strong_staged) {
        // 完整 staged（多个弱信号累积）：全 32 字节混合，层级 3。
        static const uint8_t k_lab[] = "cprisk.sign.intermediate.v1";
        cprisk_sha256_init(&ctx);
        cprisk_sha256_update(&ctx, k_lab, sizeof(k_lab) - 1u);
        cprisk_sha256_update(&ctx, seed_le, sizeof(seed_le));
        cprisk_sha256_update(&ctx, buf, 32);
        uint8_t mask[32];
        cprisk_sha256_final(&ctx, mask);
        for (size_t i = 0; i < 32u; i++) {
            buf[i] ^= mask[i];
        }
        cprisk_secure_zero(mask, sizeof(mask));
        cprisk_signing_mix_set_fp_i(3u, seed);
    } else if (medium_staged) {
        // 单个 staged 命中：仅中间 16 字节混合，层级 2。
        static const uint8_t k_lab_m[] = "cprisk.sign.intermediate.medium.v1";
        cprisk_sha256_init(&ctx);
        cprisk_sha256_update(&ctx, k_lab_m, sizeof(k_lab_m) - 1u);
        cprisk_sha256_update(&ctx, seed_le, sizeof(seed_le));
        cprisk_sha256_update(&ctx, buf, 32);
        uint8_t mask[32];
        cprisk_sha256_final(&ctx, mask);
        for (size_t i = 0; i < 16u; i++) {
            buf[8u + i] ^= mask[i];
        }
        cprisk_secure_zero(mask, sizeof(mask));
        cprisk_signing_mix_set_fp_i(2u, seed);
    } else if (weak_only) {
        // 仅弱被动信号：仅尾部 8 字节混合，层级 1。
        static const uint8_t k_lab_p[] = "cprisk.sign.intermediate.partial.v1";
        cprisk_sha256_init(&ctx);
        cprisk_sha256_update(&ctx, k_lab_p, sizeof(k_lab_p) - 1u);
        cprisk_sha256_update(&ctx, seed_le, sizeof(seed_le));
        cprisk_sha256_update(&ctx, buf, 32);
        uint8_t mask[32];
        cprisk_sha256_final(&ctx, mask);
        for (size_t i = 0; i < 8u; i++) {
            buf[24u + i] ^= mask[i];
        }
        cprisk_secure_zero(mask, sizeof(mask));
        cprisk_signing_mix_set_fp_i(1u, seed);
    } else if (degraded_tier == 6) {
        // 跟踪 + DBI 同时命中：全 32 字节混合，层级 6。
        static const uint8_t k_lab_td[] = "cprisk.sign.intermediate.degraded.trace_dbi.v1";
        cprisk_sha256_init(&ctx);
        cprisk_sha256_update(&ctx, k_lab_td, sizeof(k_lab_td) - 1u);
        cprisk_sha256_update(&ctx, seed_le, sizeof(seed_le));
        cprisk_sha256_update(&ctx, buf, 32);
        uint8_t mask[32];
        cprisk_sha256_final(&ctx, mask);
        for (size_t i = 0; i < 32u; i++) {
            buf[i] ^= mask[i];
        }
        cprisk_secure_zero(mask, sizeof(mask));
        cprisk_signing_mix_set_fp_i(6u, seed);
    } else if (degraded_tier == 4) {
        // 仅跟踪命中：中间 16 字节混合，层级 4。
        static const uint8_t k_lab_tr[] = "cprisk.sign.intermediate.degraded.trace.v1";
        cprisk_sha256_init(&ctx);
        cprisk_sha256_update(&ctx, k_lab_tr, sizeof(k_lab_tr) - 1u);
        cprisk_sha256_update(&ctx, seed_le, sizeof(seed_le));
        cprisk_sha256_update(&ctx, buf, 32);
        uint8_t mask[32];
        cprisk_sha256_final(&ctx, mask);
        for (size_t i = 0; i < 16u; i++) {
            buf[8u + i] ^= mask[i];
        }
        cprisk_secure_zero(mask, sizeof(mask));
        cprisk_signing_mix_set_fp_i(4u, seed);
    } else if (degraded_tier == 5) {
        // 仅 DBI 命中：中间 16 字节混合，层级 5。
        static const uint8_t k_lab_db[] = "cprisk.sign.intermediate.degraded.dbi.v1";
        cprisk_sha256_init(&ctx);
        cprisk_sha256_update(&ctx, k_lab_db, sizeof(k_lab_db) - 1u);
        cprisk_sha256_update(&ctx, seed_le, sizeof(seed_le));
        cprisk_sha256_update(&ctx, buf, 32);
        uint8_t mask[32];
        cprisk_sha256_final(&ctx, mask);
        for (size_t i = 0; i < 16u; i++) {
            buf[8u + i] ^= mask[i];
        }
        cprisk_secure_zero(mask, sizeof(mask));
        cprisk_signing_mix_set_fp_i(5u, seed);
    } else if (ambient) {
        // ambient hook-surface（mprotect 交叉校验不一致等）：头部 8 字节混合，层级 7。
        static const uint8_t k_lab_am[] = "cprisk.sign.intermediate.ambient.v1";
        cprisk_sha256_init(&ctx);
        cprisk_sha256_update(&ctx, k_lab_am, sizeof(k_lab_am) - 1u);
        cprisk_sha256_update(&ctx, seed_le, sizeof(seed_le));
        cprisk_sha256_update(&ctx, buf, 32);
        uint8_t mask[32];
        cprisk_sha256_final(&ctx, mask);
        for (size_t i = 0; i < 8u; i++) {
            buf[i] ^= mask[i];
        }
        cprisk_secure_zero(mask, sizeof(mask));
        cprisk_signing_mix_set_fp_i(7u, seed);
    }
    cprisk_secure_zero(seed_le, sizeof(seed_le));
}

// 返回最近一次签名混合指纹；0 表示尚未混合。
uint32_t cprisk_get_signing_mix_fingerprint(void) {
    return s_signing_mix_last_fp;
}

// 白盒/PRF 压力位掩码：bit0 watchdog staged、bit1 anti-dump staged、bit2 trace/DBI、
// bit3/4 mprotect 交叉校验不一致、bit5 mprotect 篡改、bit6 时序、bit7 TTY/开发者磁盘/libc 回退、
// bit8 watchdog 慢波。位定义是内部契约，改动需同步签名混合分层。
uint32_t cprisk_integrity_wb_prf_pressure_mask(void) {
    uint32_t m = 0u;
    if (atomic_load(&s_staged_watchdog_hits) > 0u)
        m |= 1u;
    if (atomic_load(&s_staged_watchdog_slow_wave) > 0u)
        m |= 256u;
    if (atomic_load(&s_staged_anti_dump_hits) > 0u)
        m |= 2u;
    const uint32_t pb = cprisk_collect_passive_signal_binding_bits();
    if ((pb & (CPRISK_PASSIVE_BINDING_TRACE | CPRISK_PASSIVE_BINDING_DBI)) != 0u)
        m |= 4u;
    if (cprisk_get_vm_mprotect_crosscheck_mismatch_count() > 0u)
        m |= 8u;
    if (cprisk_get_vm_mprotect_mach_trap_mismatch_count() > 0u)
        m |= 16u;
    if (cprisk_is_mprotect_tampered() != 0)
        m |= 32u;
    if ((pb & CPRISK_PASSIVE_BINDING_TIMING) != 0u)
        m |= 64u;
    if ((pb & (CPRISK_PASSIVE_BINDING_TTY | CPRISK_PASSIVE_BINDING_DEVELOPER_DISK |
               CPRISK_PASSIVE_BINDING_LIBC_FALLBACK)) != 0u)
        m |= 128u;
    return m;
}

// 测试钩子：按机型与档位计算阈值；非 DEBUG 构建返回 0。
uint64_t cprisk_test_init_timing_threshold_ns_for_machine(
    const char *machine,
    cprisk_runtime_hardening_mode_t mode
) {
#if !defined(DEBUG) || !DEBUG
    /* Test hook: inert outside DEBUG builds (issue 18). */
    return 0;
#endif
    return cprisk_compute_init_timing_threshold_ns_for_machine_i(machine, mode);
}

// 判断 init 是否超过当前阈值；超过返回 1（可能被插桩/调试），否则 0。
int cprisk_check_init_timing(void) {
    const uint64_t thr = cprisk_get_init_timing_threshold_ns();
    return s_init_elapsed_ns > thr ? 1 : 0;
}

// 测试钩子：暴露 secure_zero；非 DEBUG 构建为空操作。
void cprisk_test_secure_zero(void *buf, size_t len) {
#if !defined(DEBUG) || !DEBUG
    /* Test hook: inert outside DEBUG builds (issue 18). */
    return;
#endif
    cprisk_secure_zero(buf, len);
}

/* ── Hybrid Key Derivation (Three-Layer KDF) ───────────────────────── */

// 初始化三层 Hybrid KDF（单线程，init 路径调用）：
//   Layer 2 deviceKey     = CPRisk-MAC(rootKey, deviceSalt)；
//   Layer 3 effectiveRoot = MAC(deviceKey, sessionKey)（无 session 时退化为 deviceKey）。
// 失败语义（issue 60）：设备绑定失败时没有 effectiveRoot，绝不回退到原始 rootKey；
// 返回 -1 且两个 ready 标志均为 0，调用方必须 fail-closed。
// 每次调用先清零旧状态；不应与并发读取同时进行。
int cprisk_init_hybrid_kdf(const uint8_t *root_key) {
    if (!root_key)
        return -1;

    /* Reset hybrid KDF state. */
    cprisk_secure_zero(s_device_key, sizeof(s_device_key));
    cprisk_secure_zero(s_effective_root, sizeof(s_effective_root));
    s_device_key_ready = 0;
    s_effective_root_ready = 0;

    /* Layer 2: Derive device key.
     * deviceKey = CPRisk-MAC(rootKey, deviceSalt)
     * deviceSalt is sourced from IOKit/Keychain when available;
     * if unavailable, derivation hard-fails (no constant-salt fallback). */
    if (cprisk_derive_device_key(root_key, s_device_key) == 0) {
        s_device_key_ready = 1;
    }

    /* Layer 3: Try to retrieve session key.
     * If no session token is active, we fall through to the
     * device-key-only path. */
    uint8_t session_key[CPRISK_ARMOR_KEY_SIZE];
    cprisk_secure_zero(session_key, sizeof(session_key));
    int has_session = (cprisk_get_session_key(session_key) == 0);

    /* Compute effective root: the key used for dynamic white-box domains 6-7
     * and any subsequent device/session-bound derivations.
     *
     * Note on replay: effective_root MUST stay byte-identical across
     * process starts on the same device with the same session token,
     * because it decrypts material encrypted at build time. We deliberately
     * do NOT mix in a per-process timestamp here — that would diverge
     * runtime keys from the build-time keys and break decryption. Session
     * freshness is enforced at the *session_token* level (caller's
     * responsibility), not at effective_root. */
    if (has_session && s_device_key_ready) {
        /* effectiveRoot = CPRisk-MAC(deviceKey, sessionKey) — binds to device AND session. */
        // 同时绑定设备与会话：session token 变化会得到不同 effectiveRoot，旧会话密钥无法复用。
        // 故意不混入每进程时间戳：effectiveRoot 必须在同设备同 session 下跨进程字节一致，
        // 否则会与构建期加密的材料不匹配。
        cprisk_mac_sha256(s_device_key, CPRISK_ARMOR_KEY_SIZE,
                           session_key, CPRISK_ARMOR_KEY_SIZE,
                           s_effective_root);
        s_effective_root_ready = 1;
    } else if (s_device_key_ready) {
        /* Fallback when no session token: effectiveRoot = deviceKey.
         * Key is still bound to the physical device. */
        // 无 session token 时退化为 deviceKey：仍绑定设备，但不绑定会话。
        memcpy(s_effective_root, s_device_key, CPRISK_ARMOR_KEY_SIZE);
        s_effective_root_ready = 1;
    } else {
        /* NO final fallback (issue 60): when device binding failed there
         * is no effective root. Silently falling back to the raw rootKey
         * would present an unbound key as a device/session-bound one.
         * Callers see s_effective_root_ready == 0 and fail closed. */
        // 无设备绑定：清空 effectiveRoot 并保持未就绪；
        // 不做任何“原始 rootKey”回退，避免把未绑定密钥冒充为设备/会话绑定密钥。
        cprisk_secure_zero(s_effective_root, sizeof(s_effective_root));
        s_effective_root_ready = 0;
        cprisk_secure_zero(session_key, sizeof(session_key));
        return -1;
    }

    cprisk_secure_zero(session_key, sizeof(session_key));

    return 0;
}

// 导出 deviceKey 副本；未就绪或 out 为 NULL 返回 -1（fail-closed，不返回部分密钥）。
int cprisk_get_device_key(uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]) {
    if (!out_key)
        return -1;
    if (!s_device_key_ready)
        return -1;
    memcpy(out_key, s_device_key, CPRISK_ARMOR_KEY_SIZE);
    return 0;
}

// 导出 effectiveRoot 副本；未就绪或 out 为 NULL 返回 -1，调用方应拒绝继续派生。
int cprisk_get_effective_root(uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]) {
    if (!out_key)
        return -1;
    if (!s_effective_root_ready)
        return -1;
    memcpy(out_key, s_effective_root, CPRISK_ARMOR_KEY_SIZE);
    return 0;
}
