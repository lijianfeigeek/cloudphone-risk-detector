// 本文件：CFF（控制流平坦化）公共契约与可内联的状态编解码/迁移原语。
// 职责：状态编码解码、dispatcher 变体、runtime salt、上下文掩码及 CPR_CFF_* 迁移宏。
// 线程模型：context 由单个状态机实例独占；S-box 全局表由 pthread_once 与互斥锁保护。
// 平台：纯 C11，无汇编依赖；Feistel/SPN 表在首次使用时惰性构建。
// 失败语义：迁移或链校验失败一律 poison（trap / 预算清零），不回落明文路径。
#ifndef CPRISK_CFF_H
#define CPRISK_CFF_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

// 编译期总开关：1 时在源码层展开 CFF 状态机；置 0 需由构建系统关闭对应宏使用点。
#ifndef SOURCE_LEVEL_CFF
#define SOURCE_LEVEL_CFF 1
#endif

// 编译期开关：IR 级 CFF 默认关闭，避免与源码级展开重复膨胀代码体积。
#ifndef IR_LEVEL_CFF
#define IR_LEVEL_CFF 0
#endif

// 由 NDEBUG 推导的发布构建标志：参与默认处置动作与假状态可用性的判定。
#if defined(NDEBUG)
#define CPRISK_CFF_RELEASE_BUILD 1
#else
#define CPRISK_CFF_RELEASE_BUILD 0
#endif

// 假状态（decoy state）必须显式 opt-in：配置错误或坏种子不得静默落入误导路径。
/* Fake/decoy states default OFF (issue 44). Previously this defaulted to
 * CPRISK_CFF_RELEASE_BUILD, i.e. decoy states were silently ON in Release.
 * Callers must now opt in explicitly (CPRISK_CFF_ENABLE_FAKE_STATE=1).
 * A configuration error / bad seed must never silently fall through to a
 * decoy path: with fake states off, cprisk_cff_should_visit_fake_state()
 * returns 0 and the real path (or a hard error) is taken. */
#ifndef CPRISK_CFF_ENABLE_FAKE_STATE
#define CPRISK_CFF_ENABLE_FAKE_STATE 0
#endif

// 状态机迭代预算默认值：同时限制死循环与符号执行路径爆炸的上界。
#ifndef CPRISK_CFF_ITERATION_BUDGET
#define CPRISK_CFF_ITERATION_BUDGET 1024u
#endif

// MBA 层数下限：低于 2 层不产生复合身份变换（轻量级函数可显式传 1 退出）。
#ifndef CPRISK_CFF_MBA_LAYERS_MIN
#define CPRISK_CFF_MBA_LAYERS_MIN 2u
#endif

// MBA 层数上限：超过 8 层只增加热路径开销，不提升该威胁模型下的强度。
#ifndef CPRISK_CFF_MBA_LAYERS_MAX
#define CPRISK_CFF_MBA_LAYERS_MAX 8u
#endif

// heavy 档 MBA 层数下限：用于高强度函数，与普通档仅取值范围不同。
#ifndef CPRISK_CFF_MBA_LAYERS_HEAVY_MIN
#define CPRISK_CFF_MBA_LAYERS_HEAVY_MIN 6u
#endif

// heavy 档 MBA 层数上限：与 CPRISK_CFF_MBA_LAYERS_MAX 保持一致，避免越界。
#ifndef CPRISK_CFF_MBA_LAYERS_HEAVY_MAX
#define CPRISK_CFF_MBA_LAYERS_HEAVY_MAX 8u
#endif

// 跨语言 SPN 种子契约：与 Swift 侧 CFFSBoxMaterial / CFFSBoxPermutation256 必须逐位一致。
// 改动该值会使 C 与 Swift 生成的 256 字节置换表失配，破坏 VM×CFF 融合。
/**
 * Canonical Feistel SPN substitution seed — must match:
 * - CloudPhoneRiskKit `CFFSBoxMaterial.canonicalSeed`
 * - cprisk-armor `CFFSBoxPermutation256.generate(seed:)` (SplitMix64 + Fisher–Yates)
 * Mix: FNV-1a("cprisk-armor/CFFSBoxPermutation256/v1") ^ 0xA37C19E45B62D08F (registry root).
 */
// SPN 规范种子（64-bit）：仅在无法从 __DATA 段解析构建种子时作为回退。
#ifndef CPRISK_CFF_SPN_CANONICAL_SEED_U64
#define CPRISK_CFF_SPN_CANONICAL_SEED_U64 0x6AFD56260D3F7F05ull
#endif

// 非法状态/校验失败时的默认处置：fail-closed 保留可继续但预算清零，poison 额外污染完整性通道。
typedef enum cprisk_cff_default_action {
    // 失败即拒绝：把状态钉死为非法哨兵并清零预算，由外层检测器判定风险。
    CPRISK_CFF_DEFAULT_FAIL_CLOSED = 0,
    // 污染：除 fail-closed 行为外，还通过 cprisk_integrity_poison_cff_lane 标记完整性通道。
    CPRISK_CFF_DEFAULT_POISON = 1,
    // 直接 trap：用于不可恢复场景；会终止进程，不返回调用方。
    CPRISK_CFF_DEFAULT_TRAP = 2,
} cprisk_cff_default_action_t;

// 状态编码风格：决定 encode/decode 的代数结构；AUTO 在 init 时解析为具体风格。
typedef enum cprisk_cff_codec_style {
    // AUTO：仅作为配置输入；init 后 context 中不会再保存 AUTO。
    CPRISK_CFF_CODEC_STYLE_AUTO = 0,
    // XOR+旋转：轻量级编码，核心是 XOR（可选 MBA 形式）后循环左移。
    CPRISK_CFF_CODEC_STYLE_XOR_ROTATE = 1,
    // 加法+旋转+XOR：先加常量再旋转，最后与派生掩码异或；解码按相反顺序。
    CPRISK_CFF_CODEC_STYLE_ADD_ROTATE_XOR = 2,
    // GF(2^32) 仿射：奇数乘子保证模 2^32 可逆，配合加法与 XOR 掩码。
    CPRISK_CFF_CODEC_STYLE_AFFINE = 3,
    /**
     * Feistel + byte S-box (SPN-like round function): lookup-heavy, non-linear,
     * not a pure GF(2) XOR chain — materially harder for GAMBA/algebraic MBA
     * simplifiers than layered XOR-MBA identities on the same semantic XOR.
     */
    // Feistel+SPN：8 轮非线性置换，抗代数化简能力最强，AUTO 的主要选择。
    CPRISK_CFF_CODEC_STYLE_FEISTEL_SPN = 4,
} cprisk_cff_codec_style_t;

// dispatcher 变体选择：影响解码入口的分派方式，而非编码结果。
typedef enum cprisk_cff_dispatch_style {
    // AUTO：init 时按种子在 DIRECT 与 FN_TABLE 间确定，COMPUTED_GOTO 不参与 AUTO。
    CPRISK_CFF_DISPATCH_AUTO = 0,
    // 直接调用：解码函数内联/直调，代码最少但调用点单一。
    CPRISK_CFF_DISPATCH_DIRECT = 1,
    // 函数表：每次按上下文派生索引在多个等价解码函数间选择，增加静态定位难度。
    CPRISK_CFF_DISPATCH_FN_TABLE = 2,
    // 计算跳转（computed goto）：部分工具链不稳定，解析时降级为 FN_TABLE。
    CPRISK_CFF_DISPATCH_COMPUTED_GOTO = 3,
} cprisk_cff_dispatch_style_t;

// 初始化配置：所有字段由调用方在 cprisk_cff_init 期间读取，函数不保留指针。
// seed/runtime_salt 为 0 时分别触发默认种子与运行时盐派生。
typedef struct cprisk_cff_config {
    // 状态机主种子；0 表示由 cprisk_cff_default_seed 生成。
    uint32_t seed;
    // 可选的固定运行时盐；非 0 时直接参与派生，0 时按时钟/PID/dyld 现场生成。
    uint32_t runtime_salt;
    // 初始明文状态，必须与调用点 switch 的 case 标签一致。
    uint32_t entry_state;
    // 迭代预算；0 表示使用编译期默认值 CPRISK_CFF_ITERATION_BUDGET。
    uint32_t iteration_budget;
    // 发布构建标志；影响默认处置动作与假状态预算。
    uint8_t release_build;
    // 是否启用假状态；默认 0，必须显式 opt-in（见 CPRISK_CFF_ENABLE_FAKE_STATE）。
    uint8_t enable_fake_states;
    // 编码风格输入；AUTO 会在 init 中解析为具体风格。
    uint8_t codec_style;
    // dispatcher 风格输入；AUTO 会在 init 中解析。
    uint8_t dispatch_style;
    // MBA 层数；0 或越界值按种子自动选取 2..5，1 表示退出 MBA。
    uint8_t mba_layers;
    // 符号执行防护预算基数；0 时触发路径使用默认 8。
    uint8_t symex_guard_budget;
    // 保留字节，必须为 0，用于未来扩展而不改变结构体大小。
    uint8_t reserved1;
    // 非法状态处置动作；发布构建下调用方通常选择 POISON。
    cprisk_cff_default_action_t default_action;
} cprisk_cff_config_t;

// 运行时上下文：所有敏感字段（seed/salt/状态/链/守卫）在内存中均为掩码后的密文形式。
// 掩码依赖 context 地址、sizeof 与 storage_nonce，复制或跨实例重用会导致解码失败。
typedef struct cprisk_cff_context {
    // 掩码后的主种子；明文经 cprisk_cff_ctx_seed_plain 还原。
    uint32_t seed;
    // 掩码后的运行时盐；明文经 cprisk_cff_ctx_salt_plain 还原。
    uint32_t runtime_salt;
    // 当前状态的编码值（已编码再掩码）；解码需 codec_style 与 mba_layers。
    uint32_t encoded_state;
    // 上一明文的第一个份额；与 share_b、split_mask 异或才能还原 last_plain。
    uint32_t state_share_a;
    // 上一明文的第二个份额；单独泄露不暴露明文。
    uint32_t state_share_b;
    // 存储随机数（掩码后）；参与所有字段掩码的派生，变更即令旧密文失效。
    uint32_t storage_nonce;
    // 掩码后的跨函数链快照；每次成功迁移后推进，用于检测重放/跳转。
    uint32_t chain_snapshot;
    // 掩码后的入口守卫；由链值、种子、盐与上一状态共同派生。
    uint32_t entry_guard;
    // 剩余迭代预算；每次循环递减，归零后状态机必须退出。
    uint32_t iteration_budget;
    // 发布构建标志副本；假状态与默认处置会读取。
    uint8_t release_build;
    // 假状态启用标志副本；为 0 时 should_visit_fake_state 恒返回 0。
    uint8_t enable_fake_states;
    // 假状态预算：仅发布构建且显式启用时置 7，否则为 0；当前实现不做递减。
    uint8_t fake_state_budget;
    // 已解析的具体编码风格；运行期不会再出现 AUTO。
    uint8_t codec_style;
    // 已解析的 dispatcher 风格；运行期不会再出现 AUTO。
    uint8_t dispatch_style;
    // 已归一化的 MBA 层数，范围 1..8。
    uint8_t mba_layers;
    // 符号执行防护预算；0 表示由触发函数使用默认值。
    uint8_t symex_guard_budget;
    // 保留字节，保持与配置结构体对应的 ABI 占位。
    uint8_t reserved1;
    // 非法状态处置动作副本。
    cprisk_cff_default_action_t default_action;
} cprisk_cff_context_t;

/// 读取跨函数链值，并混入当前线程指纹。
/// - 返回：非 0 的 32-bit 链值；全局链未初始化时会以 CAS 写入固定哨兵。
/// - 线程安全：原子读 + CAS，可并发调用。
/// - 平台/失败语义：无平台分支；无失败路径。
uint32_t cprisk_cff_get_chain_link(void);

// 32-bit 雪崩混合：双乘法 + 移位异或，保证输入任一 bit 影响输出多位。
// 该内联副本与 cprisk_cff.c 中 static 版本语义一致，供头文件宏展开使用。
/**
 * Inlined opaque transition gate (MBA + runtime-tied mixing). Duplicated at macro call sites so a
 * single hook on a standalone C symbol cannot bypass the guard without patching each expansion.
 */
static inline uint32_t cprisk_cff_hdr_avalanche32(uint32_t value) {
    uint32_t mixed = value;
    mixed ^= mixed >> 16u;
    mixed *= 0x7FEB352Du;
    mixed ^= mixed >> 15u;
    mixed *= 0x846CA68Bu;
    mixed ^= mixed >> 16u;
    return mixed;
}

// 以下三个内联函数在头文件后部定义；先声明以满足调用点顺序。
static inline uint32_t cprisk_cff_hdr_rotate_left32(uint32_t value, uint32_t shift);
static inline uint32_t cprisk_cff_hdr_const32(uint64_t domain, uint32_t seed, uint32_t salt, uint32_t base);
static inline uint32_t cprisk_cff_hdr_const32_odd(uint64_t domain, uint32_t seed, uint32_t salt, uint32_t base);

/// 读取当前 SPN S-box 的构建种子。
/// - 返回：种子值；若表由 install_from_bytes 安装则返回 0。
/// - 线程安全：内部 pthread_once + 原子读，可并发调用。
/// - 失败语义：无失败返回，0 表示“无种子/自定义表”。
uint64_t cprisk_cff_runtime_spn_sbox_seed(void);

// 从头文件可用的 SPN 种子派生 32-bit build seed；种子为 0 时回退规范常量。
static inline uint32_t cprisk_cff_hdr_build_seed32_i(void) {
    uint64_t seed64 = cprisk_cff_runtime_spn_sbox_seed();
    if (seed64 == 0u) {
        seed64 = CPRISK_CFF_SPN_CANONICAL_SEED_U64;
    }
    return cprisk_cff_hdr_avalanche32(
        (uint32_t)seed64 ^
        ((uint32_t)(seed64 >> 32u) << 3) ^
        0x48445242u
    );
}

// 以规范常量为 base，经 domain 分离与 build seed 重新派生常量。
static inline uint32_t cprisk_cff_hdr_base_derive(uint64_t base_domain, uint32_t canonical_base) {
    const uint32_t bs = cprisk_cff_hdr_build_seed32_i();
    return cprisk_cff_hdr_const32(base_domain, bs, bs ^ canonical_base, canonical_base);
}

// 由 context 地址 + sizeof 派生的存储掩码；不读取任何字段，故初始化最早可用。
static inline uint32_t cprisk_cff_ctx_storage_mask(const cprisk_cff_context_t *ctx) {
    const uintptr_t p = (uintptr_t)ctx;
    const uint32_t ptr_mix = (uint32_t)p ^ (uint32_t)(p >> 32);
    return cprisk_cff_hdr_avalanche32(
        ptr_mix ^ cprisk_cff_hdr_const32(
            0x4346465F43545831ull,
            ptr_mix,
            (uint32_t)sizeof(*ctx),
            cprisk_cff_hdr_base_derive(0x4346465F42415331ull, 0xC0FFEE42u)
        )
    );
}

// 还原 storage_nonce；依赖 storage_mask，必须在 context 内存有效后调用。
static inline uint32_t cprisk_cff_ctx_nonce_plain(const cprisk_cff_context_t *ctx) {
    return ctx->storage_nonce ^ cprisk_cff_ctx_storage_mask(ctx);
}

// seed 字段掩码；域标签与 nonce 共同隔离，防止不同字段掩码互换。
static inline uint32_t cprisk_cff_ctx_mask_ptr(const cprisk_cff_context_t *ctx) {
    return cprisk_cff_hdr_avalanche32(
        cprisk_cff_ctx_storage_mask(ctx) ^ cprisk_cff_ctx_nonce_plain(ctx) ^ cprisk_cff_hdr_const32(
            0x4346465F43545832ull,
            cprisk_cff_ctx_storage_mask(ctx),
            cprisk_cff_ctx_nonce_plain(ctx),
            cprisk_cff_hdr_base_derive(0x4346465F42415332ull, 0x71E58D4Bu)
        )
    );
}

// runtime_salt 字段掩码；与 mask_ptr 域分离。
static inline uint32_t cprisk_cff_ctx_mask_salt(const cprisk_cff_context_t *ctx) {
    return cprisk_cff_hdr_avalanche32(
        cprisk_cff_ctx_storage_mask(ctx) ^ cprisk_cff_ctx_nonce_plain(ctx) ^ cprisk_cff_hdr_const32(
            0x4346465F43545833ull,
            cprisk_cff_ctx_storage_mask(ctx),
            cprisk_cff_ctx_nonce_plain(ctx),
            cprisk_cff_hdr_base_derive(0x4346465F42415333ull, 0x0ACC0DECu)
        )
    );
}

// encoded_state 字段掩码；与 last/chain/guard 的派生域不同。
static inline uint32_t cprisk_cff_ctx_mask_enc(const cprisk_cff_context_t *ctx) {
    return cprisk_cff_hdr_avalanche32(
        cprisk_cff_ctx_storage_mask(ctx) ^ cprisk_cff_ctx_nonce_plain(ctx) ^ cprisk_cff_hdr_const32(
            0x4346465F43545834ull,
            cprisk_cff_ctx_storage_mask(ctx),
            cprisk_cff_ctx_nonce_plain(ctx),
            cprisk_cff_hdr_base_derive(0x4346465F42415334ull, 0x5EEDB0E5u)
        )
    );
}

// 还原明文 seed；要求 init 已完成且 context 未被 memset。
static inline uint32_t cprisk_cff_ctx_seed_plain(const cprisk_cff_context_t *ctx) {
    return ctx->seed ^ cprisk_cff_ctx_mask_ptr(ctx);
}

// 还原明文 runtime_salt。
static inline uint32_t cprisk_cff_ctx_salt_plain(const cprisk_cff_context_t *ctx) {
    return ctx->runtime_salt ^ cprisk_cff_ctx_mask_salt(ctx);
}

// 还原编码状态（仍是 codec 密文，不是明文状态）。
static inline uint32_t cprisk_cff_ctx_encoded_plain(const cprisk_cff_context_t *ctx) {
    return ctx->encoded_state ^ cprisk_cff_ctx_mask_enc(ctx);
}

// 还原上一明文状态：两个份额异或后再异或 split_mask。
static inline uint32_t cprisk_cff_ctx_last_plain(const cprisk_cff_context_t *ctx) {
    const uint32_t split_mask = cprisk_cff_hdr_avalanche32(
        cprisk_cff_ctx_mask_enc(ctx) ^ cprisk_cff_ctx_nonce_plain(ctx) ^ cprisk_cff_hdr_const32(
            0x4346465F43545835ull,
            cprisk_cff_ctx_mask_enc(ctx),
            cprisk_cff_ctx_nonce_plain(ctx),
            cprisk_cff_hdr_base_derive(0x4346465F42415335ull, 0x5F3759DFu)
        )
    );
    return ctx->state_share_a ^ ctx->state_share_b ^ split_mask;
}

// 还原链快照明文，用于与全局链观测值比对。
static inline uint32_t cprisk_cff_ctx_chain_plain(const cprisk_cff_context_t *ctx) {
    const uint32_t chain_mask = cprisk_cff_hdr_avalanche32(
        cprisk_cff_ctx_storage_mask(ctx) ^ cprisk_cff_ctx_nonce_plain(ctx) ^ cprisk_cff_hdr_const32(
            0x4346465F43545836ull,
            cprisk_cff_ctx_storage_mask(ctx),
            cprisk_cff_ctx_nonce_plain(ctx),
            cprisk_cff_hdr_base_derive(0x4346465F42415336ull, 0xC11A1E5Eu)
        )
    );
    return ctx->chain_snapshot ^ chain_mask;
}

// 还原入口守卫明文，用于检测跨上下文/跨入口的状态跳转。
static inline uint32_t cprisk_cff_ctx_entry_guard_plain(const cprisk_cff_context_t *ctx) {
    const uint32_t guard_mask = cprisk_cff_hdr_avalanche32(
        cprisk_cff_ctx_storage_mask(ctx) ^ cprisk_cff_ctx_nonce_plain(ctx) ^ cprisk_cff_hdr_const32(
            0x4346465F43545837ull,
            cprisk_cff_ctx_storage_mask(ctx),
            cprisk_cff_ctx_nonce_plain(ctx),
            cprisk_cff_hdr_base_derive(0x4346465F42415337ull, 0xE17A9A5Bu)
        )
    );
    return ctx->entry_guard ^ guard_mask;
}

// 由观测链、种子、盐、nonce 与上一状态计算期望入口守卫；任一分量变化都会失配。
static inline uint32_t cprisk_cff_chain_entry_guard_expected_inline(
    const cprisk_cff_context_t *ctx,
    uint32_t observed_chain
) {
    return cprisk_cff_hdr_avalanche32(
        observed_chain ^
        cprisk_cff_ctx_seed_plain(ctx) ^
        cprisk_cff_ctx_salt_plain(ctx) ^
        cprisk_cff_ctx_nonce_plain(ctx) ^
        cprisk_cff_ctx_last_plain(ctx) ^
        cprisk_cff_hdr_const32(
            0x4346465F43545838ull,
            cprisk_cff_ctx_seed_plain(ctx),
            cprisk_cff_ctx_salt_plain(ctx) ^ observed_chain,
            cprisk_cff_hdr_base_derive(0x4346465F42415338ull, 0xC4A11E5Du)
        )
    );
}

// 校验观测链是否等于 context 内快照；NULL context 返回 0（fail-closed）。
static inline int cprisk_cff_chain_snapshot_verify_inline(
    const cprisk_cff_context_t *ctx,
    uint32_t observed_chain
) {
    if (ctx == NULL) {
        return 0;
    }
    return observed_chain == cprisk_cff_ctx_chain_plain(ctx) ? 1 : 0;
}

// 校验观测链推导出的入口守卫是否与 context 内记录一致；NULL 返回 0。
static inline int cprisk_cff_entry_guard_verify_inline(
    const cprisk_cff_context_t *ctx,
    uint32_t observed_chain
) {
    if (ctx == NULL) {
        return 0;
    }
    return cprisk_cff_chain_entry_guard_expected_inline(ctx, observed_chain) ==
            cprisk_cff_ctx_entry_guard_plain(ctx)
        ? 1
        : 0;
}

// 同时校验链快照与入口守卫；两者都通过才返回 1。
static inline int cprisk_cff_chain_entry_verify_inline(
    const cprisk_cff_context_t *ctx,
    uint32_t observed_chain
) {
    return cprisk_cff_chain_snapshot_verify_inline(ctx, observed_chain) != 0 &&
            cprisk_cff_entry_guard_verify_inline(ctx, observed_chain) != 0
        ? 1
        : 0;
}

// 32-bit 循环左移；shift 先对 32 取模，0 与 32 的倍数原样返回。
static inline uint32_t cprisk_cff_hdr_rotate_left32(uint32_t value, uint32_t shift) {
    const uint32_t amount = shift & 31u;
    if (amount == 0u) {
        return value;
    }
    return (value << amount) | (value >> (32u - amount));
}

// 域分离常量派生：相同 (domain,seed,salt,base) 必得相同结果，不同 domain 互相独立。
static inline uint32_t cprisk_cff_hdr_const32(uint64_t domain, uint32_t seed, uint32_t salt, uint32_t base) {
    const uint32_t lo = (uint32_t)(domain & 0xFFFFFFFFu);
    const uint32_t hi = (uint32_t)(domain >> 32u);
    const uint32_t spin = ((seed ^ hi ^ (salt >> 1u)) & 31u) | 1u;
    const uint32_t lane = cprisk_cff_hdr_rotate_left32(seed ^ base ^ lo, spin);
    const uint32_t mixed0 = cprisk_cff_hdr_avalanche32(seed ^ salt ^ lo ^ base);
    const uint32_t mixed1 = cprisk_cff_hdr_avalanche32(lane ^ salt ^ hi ^ (base * (seed | 1u)));
    return cprisk_cff_hdr_avalanche32(mixed0 ^ mixed1 ^ lo ^ hi) ^ base;
}

// 在 const32 基础上强制最低位为 1；用于需要模 2^32 逆元的乘子。
static inline uint32_t cprisk_cff_hdr_const32_odd(uint64_t domain, uint32_t seed, uint32_t salt, uint32_t base) {
    return cprisk_cff_hdr_const32(domain, seed, salt, base) | 1u;
}

// (a|b)-(a&b) 与 a^b 等价（无符号回绕），作为 MBA 形式的基础恒等式。
static inline uint32_t cprisk_cff_opq_inline_xor_mba_u32(uint32_t a, uint32_t b) {
    return (a | b) - (a & b);
}

// 按 key/layer 派生选择器，在 4 种语义等价的 XOR 形式间切换，抵抗单一模式匹配。
static inline uint32_t cprisk_cff_opq_inline_xor_mba_layer_u32(uint32_t x, uint32_t k, uint32_t layer_ix) {
    const uint32_t selector_mix = cprisk_cff_hdr_const32(
        0x4346465F48445231ull,
        k,
        layer_ix,
        cprisk_cff_hdr_base_derive(0x4346465F42415339ull, 0x13579BDFu)
    );
    const uint32_t sel =
        (layer_ix + cprisk_cff_hdr_avalanche32(k ^ selector_mix) + (k >> 17u)) & 3u;
    switch (sel) {
        case 0u:
            return cprisk_cff_opq_inline_xor_mba_u32(x, k);
        case 1u:
            return (x & ~k) | (~x & k);
        case 2u:
            return x + k - (2u * (x & k));
        default:
            return x ^ k;
    }
}

// 3 层 MBA 链，每层对前一层结果再次 XOR；层数与 cff.c 中内联校验保持一致。
static inline uint32_t cprisk_cff_opq_inline_mba_chain_xor_u32(uint32_t v, uint32_t key, uint32_t salt) {
    uint32_t cur = v;
    for (uint32_t i = 0u; i < 3u; i++) {
        const uint32_t step_mul = cprisk_cff_hdr_const32_odd(
            0x4346465F48445232ull,
            key,
            salt,
            cprisk_cff_hdr_base_derive(0x4346465F42415341ull, 0x9E3779B1u)
        );
        const uint32_t step_xor = cprisk_cff_hdr_const32(
            0x4346465F48445233ull,
            key ^ i,
            salt,
            cprisk_cff_hdr_base_derive(0x4346465F42415342ull, 0xD1B54A35u)
        );
        const uint32_t ki =
            cprisk_cff_hdr_avalanche32(key ^ salt ^ (i * step_mul) ^ step_xor);
        cur = cprisk_cff_opq_inline_xor_mba_layer_u32(cur, ki, i);
    }
    return cur;
}

// 不透明谓词：混合单调时钟、PID 与代数恒等式自检。
// - 返回：1 表示全部恒等式与派生链一致；0 表示环境异常或实现不一致。
// - 线程安全：仅读线程局部时钟/PID 与入参，可重入。
// - 失败语义：任一检查失败立即返回 0，调用方必须走 poison 路径。
static inline int cprisk_cff_opaque_transition_ok_inline(
    uint32_t from_decoded,
    uint32_t to_plain,
    uint32_t seed,
    uint32_t salt
) {
    struct timespec ts;
    uint32_t rt = 0u;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        rt = (uint32_t)ts.tv_nsec ^ ((uint32_t)ts.tv_sec * cprisk_cff_hdr_const32_odd(
            0x4346465F48445234ull,
            seed,
            salt,
            cprisk_cff_hdr_base_derive(0x4346465F42415343ull, 0x9E3779B1u)
        ));
    }
    const uint32_t pid_mix = (uint32_t)getpid();
    const uint32_t a = to_plain ^ salt ^ (rt & 0xFFFFu);
    const uint32_t b = seed ^ from_decoded ^ cprisk_cff_hdr_rotate_left32(pid_mix, 3u);
    const uint32_t x = a ^ b;
    if (cprisk_cff_opq_inline_xor_mba_u32(a, b) != x) {
        return 0;
    }
    if ((((a & ~b) | (~a & b)) != x)) {
        return 0;
    }
    if (cprisk_cff_hdr_avalanche32(x ^ rt) !=
        cprisk_cff_hdr_avalanche32(cprisk_cff_opq_inline_xor_mba_u32(a, b) ^ rt)) {
        return 0;
    }
    {
        const uint32_t chain = cprisk_cff_opq_inline_mba_chain_xor_u32(a, seed, salt);
        uint32_t manual = a;
        for (uint32_t layer = 0u; layer < 3u; layer++) {
            const uint32_t step_mul = cprisk_cff_hdr_const32_odd(
                0x4346465F48445232ull,
                seed,
                salt,
                cprisk_cff_hdr_base_derive(0x4346465F42415341ull, 0x9E3779B1u)
            );
            const uint32_t step_xor = cprisk_cff_hdr_const32(
                0x4346465F48445233ull,
                seed ^ layer,
                salt,
                cprisk_cff_hdr_base_derive(0x4346465F42415342ull, 0xD1B54A35u)
            );
            const uint32_t ki =
                cprisk_cff_hdr_avalanche32(seed ^ salt ^ (layer * step_mul) ^ step_xor);
            manual = cprisk_cff_opq_inline_xor_mba_layer_u32(manual, ki, layer);
        }
        if (chain != manual) {
            return 0;
        }
    }
    const uint32_t h = cprisk_cff_hdr_avalanche32(
        seed ^ cprisk_cff_hdr_rotate_left32(to_plain, 5u) ^ cprisk_cff_hdr_const32(
            0x4346465F48445235ull,
            seed,
            salt ^ to_plain,
            cprisk_cff_hdr_base_derive(0x4346465F42415344ull, 0xABADD00Du)
        ) ^ (rt >> 3u)
    );
    const uint32_t p = 65521u;
    const uint64_t r =
        ((uint64_t)h + (uint64_t)pid_mix) * (uint64_t)(from_decoded ^ cprisk_cff_hdr_const32(
            0x4346465F48445236ull,
            seed,
            salt ^ rt,
            cprisk_cff_hdr_base_derive(0x4346465F42415345ull, 0x13579BDFu)
        ) ^ rt) % (uint64_t)p;
    const uint64_t sq = (r * r) % (uint64_t)p;
    const uint64_t sq_chk = ((uint64_t)r * (uint64_t)r) % (uint64_t)p;
    return sq == sq_chk ? 1 : 0;
}

/// 以 Feistel+SPN 风格编码 32-bit 状态。
/// - 参数：state 明文；key/salt 为 32-bit 派生材料，允许任意值。
/// - 返回：编码后的 32-bit 值；失败无（纯函数）。
/// - 线程安全：只读运行时 S-box，可并发调用。
/// - 平台/失败语义：无平台分支；调用方须保证 key/salt 与解码一致。
uint32_t cprisk_cff_encode_state(uint32_t state, uint32_t key, uint32_t salt);
/// cprisk_cff_encode_state 的严格逆运算；参数与线程语义同上。
/// - 返回：解码后的明文状态。
/// - 失败语义：key/salt 不匹配时返回无意义值，调用方须用状态合法性/链校验兜底。
uint32_t cprisk_cff_decode_state(uint32_t encoded_state, uint32_t key, uint32_t salt);
/// 指定编码风格的 32-bit 状态编码；AUTO 等价于 FEISTEL_SPN。
/// - 参数：style 越界值按 XOR_ROTATE 处理（switch default）。
/// - 返回：编码值；无错误码。
/// - 线程安全：纯函数，可并发。
/// - 平台/失败语义：无平台分支；风格必须与解码端一致。
uint32_t cprisk_cff_encode_state_with_style(uint32_t state, uint32_t key, uint32_t salt, cprisk_cff_codec_style_t style);
/// 指定风格的解码；是 encode_state_with_style 的逆运算。
/// - 失败语义：风格或 key/salt 不匹配时结果无意义，需外层完整性校验。
uint32_t cprisk_cff_decode_state_with_style(uint32_t encoded_state, uint32_t key, uint32_t salt, cprisk_cff_codec_style_t style);
/// 基于种子、运行时提示、时钟/PID/线程指纹/OS/dyld 生成运行时盐。
/// - 参数：seed/runtime_hint 任意；NULL 无（纯值参数）。
/// - 返回：非确定性的 32-bit 盐；时钟不可用时仍由其余分量派生。
/// - 线程安全：读取进程级信息，可并发调用。
/// - 平台：依赖 clock_gettime、getpid、sysctl/dyld；不可用时降级混合。
uint32_t cprisk_cff_runtime_salt(uint32_t seed, uint32_t runtime_hint);

/// 初始化 context：解析风格、归一化层数、派生并掩码所有敏感字段。
/// - 参数：context 必须非 NULL 且可写；config 为 NULL 时使用默认配置。
/// - 返回：无；失败仅通过 context 内字段体现。
/// - 线程安全：context 必须由调用线程独占，不得并发初始化。
/// - 平台/失败语义：非法配置归一化为安全默认值，不返回错误。
void cprisk_cff_init(cprisk_cff_context_t *context, const cprisk_cff_config_t *config);
/// 以 seed/entry_state 构造默认配置并调用 cprisk_cff_init。
/// - 线程安全：同 init，context 独占。
/// - 失败语义：seed 为 0 时按默认种子派生，不会失败。
void cprisk_cff_init_default(cprisk_cff_context_t *context, uint32_t seed, uint32_t entry_state);
/// 解码当前编码状态，并更新 last_plain 份额。
/// - 参数：context 非 NULL；NULL 返回 0。
/// - 返回：明文状态；解码失败无显式错误码。
/// - 线程安全：写 context，不可并发。
/// - 平台：无平台分支。
uint32_t cprisk_cff_current_state(cprisk_cff_context_t *context);
// 快速 peek：按 mba_layers 与 dispatch_style 选择等价解码实现，仍是完整一次解码。
// 仅用于循环热路径；需要新鲜解码时用 cprisk_cff_current_state。
/**
 * CFF loop PEEK hot path: returns the last decoded plain state without running
 * full codec/MBA decode. Kept in sync by cprisk_cff_set_state / set_encoded /
 * init / poison; use cprisk_cff_current_state() when a fresh decode is required.
 */
uint32_t cprisk_cff_current_state_fast(cprisk_cff_context_t *context);
/// 通过函数表在 DIRECT/TABLE 两个等价解码入口间派生选择。
/// - 线程安全：只读 context 并写 last_plain，context 独占。
/// - 失败语义：NULL 返回 0；解码错误由后续链校验发现。
uint32_t cprisk_cff_current_state_dispatch(cprisk_cff_context_t *context);
// 备用解码入口：按已解析的 codec_style 直接解码，不依赖 dispatcher 选择。
/** Alternate decode path: function-pointer dispatch by codec style (not the only gate). */
uint32_t cprisk_cff_current_state_table(cprisk_cff_context_t *context);
/// 应用一次状态迁移：先过不透明谓词，再提交编码/链/TLS/VM token。
/// - 参数：next_state 为调用点 case 标签；必须与当前状态构成合法迁移。
/// - 失败语义：谓词失败调用 poison_default 并返回，不修改为 next_state。
/// - 线程安全：写 context 与全局链/TLS，context 独占。
void cprisk_cff_set_state(cprisk_cff_context_t *context, uint32_t next_state);
/// 直接写入外部提供的编码状态，并重新解码、刷新链与 VM token。
/// - 参数：encoded_state 必须是当前 key/salt/style 下的合法密文。
/// - 失败语义：不校验合法性；错误密文会解码为无意义明文，随后由迁移谓词拦截。
void cprisk_cff_set_encoded_state(cprisk_cff_context_t *context, uint32_t encoded_state);
/// 判定当前状态是否应走假状态 decoy 路径。
/// - 返回：1 表示访问假状态；0 表示禁用、非发布构建、预算为 0 或哈希未命中。
/// - 线程安全：只读 context，可并发（只读）。
/// - 失败语义：任一前置条件不满足即返回 0（不误入 decoy）。
int cprisk_cff_should_visit_fake_state(const cprisk_cff_context_t *context, uint32_t decoded_state);
/// 设置符号执行防护预算；budget 为 0 时保留原值。
void cprisk_cff_arm_symbolic_explosion(cprisk_cff_context_t *context, uint8_t budget);
/// 触发有界的 decoy 计算，消耗符号执行预算并混入运行时熵。
/// - 参数：risk_mask 参与步数上限与混合；0 合法。
/// - 线程安全：只读 context，可并发。
/// - 失败语义：无返回值；上限被硬钳制在 160 步，避免 DoS。
void cprisk_cff_trigger_symbolic_explosion(cprisk_cff_context_t *context, uint32_t risk_mask);
/// 按 context->default_action 执行失败处置（trap/poison/fail-closed）。
/// - 失败语义：Trap 动作不返回；其余动作把状态钉死为 0xFFFF000x 并清零预算。
/// - 线程安全：写 context，独占调用。
void cprisk_cff_poison_default(cprisk_cff_context_t *context);
/// 推进链并清零整个 context；不释放内存（context 由调用方拥有）。
void cprisk_cff_finalize(cprisk_cff_context_t *context);
/// 校验 context 的链快照与入口守卫；NULL 返回 0。
int cprisk_cff_chain_entry_verify(const cprisk_cff_context_t *context);

// 调用方必须已通过不透明谓词；本函数仍会再次校验链快照后才提交。
/** Apply a verified transition (encoded state + VM link token). Caller must have passed opaque gates. */
void cprisk_cff_state_transition_commit(cprisk_cff_context_t *context, uint32_t next_state);

// VM 层可用该 token 做会话混合；它不是策略判决，不能单独作为放行依据。
// 接口边界：CFF 只产出混合 token，不执行 VM self-expect 校验；
// __swift5_mdvsk / CPRISK_VM_M3_SELF_EXPECT 的比对由 VM 解释器负责，CFF 不读取也不替代其结果。
/** Opaque 32-bit token for cross-layer mixing (VM session_mix / dispatch cache); not a policy oracle. */
uint32_t cprisk_cff_get_vm_link_token(void);

// 原子链值的读取入口；混入线程指纹以避免跨线程观测相关性。
/** Cross-function chain link (atomic); complements TLS mix for propagation between CFF regions. */
uint32_t cprisk_cff_get_chain_link(void);

/// 开始一段 CFF 链：把当前全局链混入线程局部 TLS 状态。
/// - 线程安全：TLS 为线程局部；全局链原子读写。
/// - 失败语义：无失败路径。
void cprisk_cff_chain_begin(void);

// 安装种子生成的 SPN 前向表；调用前会先完成 once 初始化。
/**
 * Build-time / runtime: install 256-byte Feistel SPN forward S-box (bijection). Matches
 * `CFFSBoxPermutation256.generate(seed:)` in cprisk-armor / CloudPhoneRiskKit.
 */
void cprisk_cff_spn_sbox_install_from_seed(uint64_t seed);

// 安装预计算前向表；非双射输入被拒绝，保留现有表。
/** Optional: install precomputed forward table (must be a permutation of 0..255). */
void cprisk_cff_spn_sbox_install_from_bytes(const uint8_t forward256[256]);
/// 读取当前 SPN 种子；返回 0 表示表来自 install_from_bytes。
uint64_t cprisk_cff_runtime_spn_sbox_seed(void);
/// 复制当前前向 S-box 快照。
/// - 参数：out_forward256 必须指向至少 256 字节；NULL 返回 -1。
/// - 返回：0 成功；-1 参数非法。
/// - 线程安全：持互斥锁复制，避免并发安装撕裂。
int cprisk_cff_spn_sbox_copy_forward(uint8_t out_forward256[256]);

// 单字节前向查表；首次调用触发惰性初始化。
/**
 * Direct byte-level lookup against the runtime SPN forward S-box. Triggers lazy
 * initialization on first call. Used by VM×CFF fusion to share the same 8-bit
 * permutation as `cprisk_cff_encode_state` / Feistel round function — keeping
 * the per-build randomized table consistent across both subsystems.
 */
uint8_t cprisk_cff_spn_sbox_lookup(uint8_t idx);

// 固定 16 步 decoy 计算，不递归进入状态机；用于扰动执行轨迹。
/** Fake-state decoy work unit: non-semantic avalanche + env mix (watchdog ghost lane). */
void cprisk_cff_run_fake_path_decoy(const cprisk_cff_context_t *context);

/**
 * Dispatch epoch rotation (counter-measure: Capstone L1/L2 cache busting).
 *
 * unidbg魔改版 caches Capstone disassembly per address using L1 (direct-mapped
 * array) + L2 (LRU HashMap).  The cache is only invalidated on SMC (Self-Modifying
 * Code) detection.  Without SMC the SAME instruction-sequence at address X is
 * returned from cache on every subsequent visit — typical in CFF state-machine
 * loops where the dispatcher basic-block is executed millions of times.
 *
 * Solution: mix a per-iteration epoch into `runtime_salt` before calling
 * `cprisk_cff_current_state_dispatch()`.  The encoded state after XOR-mixing
 * now differs each iteration, causing the dispatch function to take a different
 * branch (switchLoop vs ifElseChain vs dualRail) on each pass.  The ARM64
 * instructions that are *executed* therefore come from different addresses each
 * time — defeating the L1/L2 address-keyed cache entirely.
 *
 * cprisk_cff_rotate_dispatch_epoch: advance the per-thread epoch counter.
 *   Call once per state-machine loop iteration, immediately before decoding.
 *
 * cprisk_cff_epoch_mix_salt: derive a one-time salt mask from the current
 *   epoch + context seed.  XOR into runtime_salt before cprisk_cff_current_state.
 */
/// 推进当前线程的 dispatch epoch；每次状态机循环迭代调用一次。
/// - 线程安全：_Thread_local 计数器，无共享写。
/// - 失败语义：无返回值，Weyl 步进不会阻塞。
///
/// 从 epoch 与 context 种子派生一次性盐掩码，供宏异或进 runtime_salt。
/// - 返回：context 为 NULL 时返回 0；否则返回与 epoch 正交的 32-bit 掩码。
void    cprisk_cff_rotate_dispatch_epoch(void);
uint32_t cprisk_cff_epoch_mix_salt(const cprisk_cff_context_t *context);

/**
 * Loop PEEK: hot decode path (dispatch_style + MBA layers) without a stable
 * single-symbol hook on `cprisk_cff_current_state` — implemented in cprisk_cff.c.
 */
// 循环热路径：推进 epoch → 旋转 runtime_salt → 快速解码；每次迭代改变 dispatch 分支。
/* Epoch-rotated state peek: advance per-thread epoch, mix into runtime_salt,
 * then decode.  Each loop iteration uses a different salt → different dispatch
 * branch → different ARM64 code addresses executed → Capstone L1/L2 misses. */
#define CPRISK_CFF_LOOP_STATE_PEEK(ctx) \
    ( cprisk_cff_rotate_dispatch_epoch(), \
      (ctx)->runtime_salt ^= cprisk_cff_epoch_mix_salt((ctx)), \
      cprisk_cff_current_state_fast((ctx)) )

// 直接读取当前状态 fast peek；不推进 epoch，适合非循环的一次性读取。
#define CPRISK_CFF_CTX_STATE_INLINE(ctx) cprisk_cff_current_state_fast((ctx))

// 声明并初始化栈上 CFF 上下文，校验入口链，然后进入预算受控的状态循环。
// case 标签集合即状态迁移表；每个 CPR_CFF_GOTO 是一条允许的边，未列出的状态落入 default。
// 要求调用点随后用 CPR_CFF_CASE 提供各状态分支，并以 CPR_CFF_END 收尾。
#define CPR_CFF_BEGIN(seed, entry) \
    do { \
        cprisk_cff_chain_begin(); \
        cprisk_cff_context_t cpr_cff_storage_; \
        cprisk_cff_context_t *const cpr_cff_ctx = &cpr_cff_storage_; \
        cprisk_cff_init_default(cpr_cff_ctx, (uint32_t)(seed), (uint32_t)(entry)); \
        { \
            const uint32_t cpr_cff_chain_observed_ = cprisk_cff_get_chain_link(); \
            if (cprisk_cff_chain_entry_verify_inline(cpr_cff_ctx, cpr_cff_chain_observed_) == 0) { \
                cprisk_cff_poison_default(cpr_cff_ctx); \
            } \
        } \
        if (cprisk_cff_chain_snapshot_verify_inline(cpr_cff_ctx, cprisk_cff_get_chain_link()) == 0) { \
            cprisk_cff_poison_default(cpr_cff_ctx); \
        } \
        while (cpr_cff_ctx->iteration_budget > 0u) { \
            cpr_cff_ctx->iteration_budget--; \
            const uint32_t cpr_cff_state_ = CPRISK_CFF_LOOP_STATE_PEEK(cpr_cff_ctx); \
            switch (cpr_cff_state_) {

// 同 CPR_CFF_BEGIN，但接受完整 cprisk_cff_config_t 配置值（而非仅 seed/entry）。
#define CPR_CFF_BEGIN_EX(config_value) \
    do { \
        cprisk_cff_chain_begin(); \
        cprisk_cff_context_t cpr_cff_storage_; \
        cprisk_cff_context_t *const cpr_cff_ctx = &cpr_cff_storage_; \
        cprisk_cff_config_t cpr_cff_config_ = (config_value); \
        cprisk_cff_init(cpr_cff_ctx, &cpr_cff_config_); \
        { \
            const uint32_t cpr_cff_chain_observed_ = cprisk_cff_get_chain_link(); \
            if (cprisk_cff_chain_entry_verify_inline(cpr_cff_ctx, cpr_cff_chain_observed_) == 0) { \
                cprisk_cff_poison_default(cpr_cff_ctx); \
            } \
        } \
        if (cprisk_cff_chain_snapshot_verify_inline(cpr_cff_ctx, cprisk_cff_get_chain_link()) == 0) { \
            cprisk_cff_poison_default(cpr_cff_ctx); \
        } \
        while (cpr_cff_ctx->iteration_budget > 0u) { \
            cpr_cff_ctx->iteration_budget--; \
            const uint32_t cpr_cff_state_ = CPRISK_CFF_LOOP_STATE_PEEK(cpr_cff_ctx); \
            switch (cpr_cff_state_) {

// 状态分支标签；参数必须是该状态机合法的明文状态值。
#define CPR_CFF_CASE(x) case (x)

// 请求迁移到状态 x：先校验链快照，再执行不透明谓词，通过后提交迁移。
// 任一校验失败进入 poison 并 continue，不跳转到目标状态。
#define CPR_CFF_GOTO(x) \
    do { \
        if (cprisk_cff_chain_snapshot_verify_inline((cpr_cff_ctx), cprisk_cff_get_chain_link()) == 0) { \
            cprisk_cff_poison_default(cpr_cff_ctx); \
            continue; \
        } \
        if (cprisk_cff_opaque_transition_ok_inline( \
                cprisk_cff_ctx_last_plain((cpr_cff_ctx)), \
                (uint32_t)(x), \
                cprisk_cff_ctx_seed_plain((cpr_cff_ctx)), \
                cprisk_cff_ctx_salt_plain((cpr_cff_ctx))) == 0) { \
            cprisk_cff_poison_default(cpr_cff_ctx); \
            continue; \
        } \
        cprisk_cff_state_transition_commit(cpr_cff_ctx, (uint32_t)(x)); \
        continue; \
    } while (0)

// 返回值前推进链并清零 context；表达式 x 只求值一次。
#define CPR_CFF_RETURN(x) \
    do { \
        cprisk_cff_finalize(cpr_cff_ctx); \
        return (x); \
    } while (0)

// void 返回版本：推进链并清零 context 后返回。
#define CPR_CFF_RETURN_VOID() \
    do { \
        cprisk_cff_finalize(cpr_cff_ctx); \
        return; \
    } while (0)

// 显式进入默认失败处置并继续循环；用于业务分支主动拒绝当前状态。
#define CPR_CFF_POISON_DEFAULT() \
    do { \
        cprisk_cff_poison_default(cpr_cff_ctx); \
        continue; \
    } while (0)

// 关闭 switch 与循环：default 走 poison；预算耗尽后同样 poison 并 finalize。
#define CPR_CFF_END() \
                default: { \
                    CPR_CFF_POISON_DEFAULT(); \
                } \
            } \
        } \
        cprisk_cff_poison_default(cpr_cff_ctx); \
        cprisk_cff_finalize(cpr_cff_ctx); \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* CPRISK_CFF_H */
