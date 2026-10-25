// cprisk_whitebox.c — 白盒 PRF：表驱动 SPN、域标签路由与派生签名密钥。
// 链路位置：位于设备密钥（L2）与会话密钥（L3）之上的“构建期表混淆”层，
// 用镜像内嵌的 S-box 表把 32 字节输入映射为伪随机输出，供绑定校验使用。
// 白盒层只是混淆，不是信任根：表随二进制发布，能被提取即可复现，真正的秘密
// 必须来自硬件密钥/运行时材料（见下方英文说明）。
// 线程模型：正常求值只使用栈与局部堆，可并发；测试 bundle 与 dummy sink 为
// 进程级状态，仅 DEBUG 测试钩子写入。
// 失败语义：表缺失、标签/摘要不符、重算不一致一律 fail-closed（返回 -1）。
/* ════════════════════════════════════════════════════════════════════
 * WHITE-BOX PRF — READ THIS BEFORE TRUSTING IT (issue 47).
 * ────────────────────────────────────────────────────────────────────
 * The lookup tables in the __swift5_mdbdy / __swift5_mddsc sections ship
 * INSIDE the binary. Anyone who can extract the tables can recover the
 * effective key material they encode: the white-box layer is
 * OBFUSCATION, not a trust root and not a substitute for a hardware
 * key / Secure Enclave secret. Treat every value this file derives as
 * "attacker-observable, attacker-reproducible given the binary".
 * The migration path for anything that must actually stay secret is a
 * standard KDF + AEAD: HKDF for derivation and AES-GCM or
 * ChaCha20-Poly1305 for encryption, with the key in hardware-backed
 * storage — not tables embedded in the shipped binary.
 * Self-check tag note: bundle authentication uses a full 32-byte tag;
 * any place that compares only a truncated 32-BIT prefix of a tag has
 * only ~2^32 brute-force cost (a few billions of trials — feasible for
 * a determined attacker), so a truncated comparison must never be the
 * sole authentication check.
 * ════════════════════════════════════════════════════════════════════ */
#include "include/CRiskCore.h"
#include "include/cprisk_cff.h"
#include "include/cprisk_codesign_bind.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif
#ifdef __APPLE__
#include <TargetConditionals.h>
#include <mach/mach_time.h>
#endif

#include "include/cprisk_macho.h"

extern uint32_t cprisk_collect_passive_signal_binding_bits(void);

/* Forward declaration for static inline dummy-read function (defined below) */
static inline void cprisk_whitebox_dummy_reads_i(
    const uint8_t *table,
    uint8_t real_idx,
    size_t position,
    size_t round);

/* CPRISK_WHITEBOX_DOMAIN_COUNT is defined in cprisk_armor_abi.h (via CRiskCore.h).
 * Do NOT redefine it here to avoid macro redefinition conflict. */
/* CPRISK_WHITEBOX_DOMAIN_DEVICE_BOUND through HEADER_ENCRYPTION (6-9) are also
 * defined in cprisk_armor_abi.h and available as macros. */

// SPN 参数：状态 32 字节、4 轮；每轮为 32 条 lane 各配一张 256 项 S-box。
// 单域表布局 = 4 轮 × (32 × 256) = 32768 字节，轮与轮之间按 stride 顺序排列。
// EFFECTIVE_ROUND_TARGET=8 只是对外 ABI 的“有效轮数”，由 2×实际轮数锁定。
#define CPRISK_WHITEBOX_STATE_SIZE 32u
#define CPRISK_WHITEBOX_ROUND_COUNT 4u
#define CPRISK_WHITEBOX_EFFECTIVE_ROUND_TARGET 8u
#define CPRISK_WHITEBOX_TABLE_WIDTH 256u
#define CPRISK_WHITEBOX_TABLE_STRIDE (CPRISK_WHITEBOX_STATE_SIZE * CPRISK_WHITEBOX_TABLE_WIDTH)
#define CPRISK_WHITEBOX_DOMAIN_TABLE_BYTES (CPRISK_WHITEBOX_ROUND_COUNT * CPRISK_WHITEBOX_TABLE_STRIDE)

// 锁定 ABI 约束：对外宣称的有效轮数必须恒为内部 SPN 轮数的两倍，
// 改动任一侧都会在这里编译失败，避免表格式与 ABI 悄悄漂移。
_Static_assert(CPRISK_WHITEBOX_ROUND_COUNT * 2u == CPRISK_WHITEBOX_EFFECTIVE_ROUND_TARGET,
               "effective whitebox rounds must remain 2x ABI rounds");

// 域标签（1..9）：同一套 SPN 表按 domain_id 路由，隔离不同用途的输出，
// 避免一个用途的 PRF 结果被挪用到另一个用途。
//   1 = ANCHOR_TAG，2 = PASS1_STRING_KEY，3 = ANCHOR_ACCUMULATOR_SEED，
//   4 = LOADER_KEY，5 = RUNTIME_MATERIAL。
// 6..9（DEVICE_BOUND / SESSION_BOUND / IMPORT_ENCRYPTION / HEADER_ENCRYPTION）
// 因需要参与预处理宏判断，定义在 cprisk_armor_abi.h，不要在此重复定义。
enum {
    CPRISK_WHITEBOX_DOMAIN_ANCHOR_TAG = 1u,
    CPRISK_WHITEBOX_DOMAIN_PASS1_STRING_KEY = 2u,
    CPRISK_WHITEBOX_DOMAIN_ANCHOR_ACCUMULATOR_SEED = 3u,
    CPRISK_WHITEBOX_DOMAIN_LOADER_KEY = 4u,
    CPRISK_WHITEBOX_DOMAIN_RUNTIME_MATERIAL = 5u
    /* Domains 6-9 are defined as macros in cprisk_armor_abi.h
     * to avoid macro / enum conflicts with the preprocessor. */
};

// 只读哨兵常量：s_empty_byte_i 供“非空指针”约定使用；
// s_zero_state_i 是 NULL 输入的全零替身；s_overall_tag_label_i 是整体标签的域分隔前缀。
static const uint8_t s_empty_byte_i = 0;
static const uint8_t s_zero_state_i[CPRISK_WHITEBOX_STATE_SIZE] = {0};
static const uint8_t s_overall_tag_label_i[] = "cprisk.whitebox.tag.v1";

/* ASLR term g(slide)=h(slide)^h(0), g(0)=0 — mixed into signing KDF when CPRISK_SIGNING_KEY_ASLR_BIND=1 */
// splitmix64 步进：输出 64 位均匀值并推进状态。
// 用于把 slide/构建种子混成不可逆项；调用方不需要密码学强度，但要求结果不可预测。
static uint64_t cprisk_wbx_splitmix64_next_u(uint64_t *state) {
    *state += 0x9E3779B97F4A7C15ULL;
    uint64_t z = *state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

// 计算 ASLR 项 g(slide)=h(slide)^h(0)：slide=0 时恒为 0，便于构建期预置基准值。
// 额外 XOR 运行时 S-box 种子（每构建不同），使攻击者即使知道 slide 也无法离线复算该项。
static uint64_t cprisk_wbx_slide_term_u64(intptr_t slide) {
    uint64_t a = (uint64_t)(slide >= 0 ? slide : -slide);
    /*
     * Mix in the runtime SPN S-box seed (per-build, written by armor into
     * __DATA.__anti_debug_plan / __chain_meta) so an attacker who can
     * compute the ASLR slide cannot also compute slide_term offline
     * without first recovering the build seed. The previous fixed
     * "ASLR7MIX" constant alone made slide_term a pure function of the
     * publicly-visible slide.
     */
    const uint64_t build_secret = cprisk_cff_runtime_spn_sbox_seed();
    uint64_t st_a = a ^ 0x41534C52374D4958ULL ^ build_secret;
    uint64_t st_b = 0ull ^ 0x41534C52374D4958ULL ^ (build_secret + 0x9E3779B97F4A7C15ULL);
    uint64_t ha = cprisk_wbx_splitmix64_next_u(&st_a);
    uint64_t hb = cprisk_wbx_splitmix64_next_u(&st_b);
    return ha ^ hb;
}

// 从 meta 区拷贝白盒头：先把输出清零，再按 min(meta_size, 头部大小) 截断拷贝。
// meta 为空或长度为 0 时只留全零，绝不越界读取。
static void cprisk_whitebox_copy_header_from_meta_i(const uint8_t *meta,
                                                    size_t meta_size,
                                                    struct cprisk_armor_whitebox_header *out) {
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!meta || meta_size == 0)
        return;
    const size_t n = meta_size < sizeof(*out) ? meta_size : sizeof(*out);
    memcpy(out, meta, n);
}

// 生成单个 32 字节 XOR 垫片：SHA256("CPRISK_WB1TB" || slide_term || domain || block)。
// 把域标签与块号一起绑定，防止跨域、跨块重放同一段加扰后的表。
static void cprisk_whitebox_memxor_block_pad_i(uint64_t slide_term,
                                             uint32_t domain_id,
                                             uint32_t block_idx,
                                             uint8_t out32[32]) {
    uint8_t msg[28];
    static const uint8_t lab[12] = {
        'C', 'P', 'R', 'I', 'S', 'K', '_', 'W', 'B', '1', 'T', 'B'
    };
    memcpy(msg, lab, sizeof(lab));
    memcpy(msg + 12, &slide_term, sizeof(slide_term));
    memcpy(msg + 20, &domain_id, sizeof(domain_id));
    memcpy(msg + 24, &block_idx, sizeof(block_idx));
    cprisk_sha256(msg, sizeof(msg), out32);
}

// 用“运行时 slide”与“锚点 slide”两路垫片异或表，原地修改 buf。
// 只有同一镜像布局 + 同一 TeamID 才能得到正确 S-box；重打包时表被静默破坏（不崩溃），
// PRF 输出随之错误，这是构建期绑定在运行时的延伸。len 可非 32 对齐，末块只处理实际字节。
static void cprisk_whitebox_xor_tables_aslr_i(uint8_t *buf,
                                              size_t len,
                                              uint32_t first_block_index,
                                              intptr_t runtime_slide,
                                              uint64_t anchor_slide_u64,
                                              uint32_t domain_id) {
    /* Mix TeamID salt into the runtime slide term so that the XOR pad is
     * correct only when the same Team Identifier is present.  A repackaged
     * app has a different TeamID → different salt → wrong pad → corrupted
     * S-box → silent PRF output corruption, no crash. */
    const uint64_t team_salt = cprisk_codesign_team_salt();
    const uint64_t tr = cprisk_wbx_slide_term_u64(runtime_slide) ^ team_salt;
    const intptr_t anchor_as_int = (intptr_t)anchor_slide_u64;
    const uint64_t ta = cprisk_wbx_slide_term_u64(anchor_as_int) ^ team_salt;

    for (size_t base = 0; base < len; base += 32u) {
        const size_t chunk = (len - base < 32u) ? (len - base) : 32u;
        const uint32_t blk = first_block_index + (uint32_t)(base / 32u);
        uint8_t pr[32], pa[32];
        cprisk_whitebox_memxor_block_pad_i(tr, domain_id, blk, pr);
        cprisk_whitebox_memxor_block_pad_i(ta, domain_id, blk, pa);
        for (size_t k = 0; k < chunk; k++)
            buf[base + k] ^= pr[k] ^ pa[k];
    }
}

// 判断本次求值是否需要运行时解绑 ASLR 表：需编译期未禁用、头部置位且 header 非空。
// 环境变量关闭只在 DEBUG 生效：Release 不允许通过进程环境削弱绑定。
static int cprisk_whitebox_aslr_table_bind_runtime_enabled_i(
    const struct cprisk_armor_whitebox_header *header
) {
#if defined(CPRISK_DISABLE_WHITEBOX_ASLR_TABLE)
    (void)header;
    return 0;
#else
    if (!header)
        return 0;
    if ((header->flags & CPRISK_ARMOR_WHITEBOX_FLAG_ASLR_TABLE_BIND) == 0u)
        return 0;
#if defined(DEBUG) && DEBUG
    /* DEBUG-only override: in Release the environment is never trusted
     * to disable a hardening binding. */
    const char *eb = getenv("CPRISK_WB_ASLR_TABLE_DISABLE");
    if (eb && eb[0] == '1' && eb[1] == '\0')
        return 0;
#endif
    return 1;
#endif
}

// 单个域的磁盘布局（紧凑、小端），由构建期 WhiteBoxProfile 生成，运行时只读。
// 字段顺序与 240 字节总长被下方 _Static_assert 锁死，改动即破坏新旧构建互读。
//   domain_id       域标签 1..9，决定 PRF 输入派生方式；
//   round_count     必须等于 CPRISK_WHITEBOX_ROUND_COUNT；
//   table_offset    S-box 表在 code 区内的字节偏移；
//   table_length    必须等于单域表字节数 32768；
//   permutation     4 轮后的 32 字节换位表，必须是 0..31 的排列；
//   final_mask      每域最终输出掩码，避免两个域输出直接相等；
//   round_constants 4 轮 × 32 字节轮常量；
//   record_digest   对 domain_id 前缀 + 表 + 上述字段的 32 字节摘要。
#pragma pack(push, 1)
struct cprisk_whitebox_domain_record_i {
    uint32_t domain_id;
    uint32_t round_count;
    uint32_t table_offset;
    uint32_t table_length;
    uint8_t permutation[CPRISK_WHITEBOX_STATE_SIZE];
    uint8_t final_mask[CPRISK_WHITEBOX_STATE_SIZE];
    uint8_t round_constants[CPRISK_WHITEBOX_ROUND_COUNT * CPRISK_WHITEBOX_STATE_SIZE];
    uint8_t record_digest[CPRISK_ARMOR_HASH_SIZE];
};
#pragma pack(pop)

// 锁定磁盘 ABI：单条域记录必须恰好 240 字节，否则新旧构建的表无法互读。
_Static_assert(sizeof(struct cprisk_whitebox_domain_record_i) == 240,
               "whitebox domain record ABI drift");

// 运行时只读视图：把四个 Mach-O section（meta/code/data/tag）聚合成一次校验的单位。
// 所有指针均指向镜像或测试包，不拥有所有权，生命周期由调用方保证。
struct cprisk_whitebox_bundle_i {
    struct cprisk_armor_whitebox_header header;
    const uint8_t *code;
    size_t code_len;
    const uint8_t *data;
    size_t data_len;
    const uint8_t *tag;
    const struct cprisk_whitebox_domain_record_i *records;
    size_t record_count;
};

// DEBUG 测试注入包：用堆副本替代真实镜像段落；active=1 时所有读取走这里。
// 所有指针由本模块拥有，替换/清除时先 cprisk_secure_zero 再 free。
struct cprisk_whitebox_test_bundle_i {
    uint8_t *meta;
    size_t meta_len;
    uint8_t *code;
    size_t code_len;
    uint8_t *data;
    size_t data_len;
    uint8_t *tag;
    size_t tag_len;
    int active;
};

// 进程级测试状态：s_test_bundle_i 非 active 时读取真实镜像；
// s_test_force_recompute_mismatch_i 只用于注入“重算不一致”，验证 fail-closed 分支。
static struct cprisk_whitebox_test_bundle_i s_test_bundle_i = {0};
static int s_test_force_recompute_mismatch_i = 0;

// 释放测试包全部堆内存：先清零再 free，避免盐/密钥材料残留在已释放页。
// 本文件未加锁，调用方（测试代码）必须保证不与求值并发。
static void cprisk_test_clear_whitebox_bundle_i(void) {
    if (s_test_bundle_i.meta) {
        cprisk_secure_zero(s_test_bundle_i.meta, s_test_bundle_i.meta_len);
        free(s_test_bundle_i.meta);
    }
    if (s_test_bundle_i.code) {
        cprisk_secure_zero(s_test_bundle_i.code, s_test_bundle_i.code_len);
        free(s_test_bundle_i.code);
    }
    if (s_test_bundle_i.data) {
        cprisk_secure_zero(s_test_bundle_i.data, s_test_bundle_i.data_len);
        free(s_test_bundle_i.data);
    }
    if (s_test_bundle_i.tag) {
        cprisk_secure_zero(s_test_bundle_i.tag, s_test_bundle_i.tag_len);
        free(s_test_bundle_i.tag);
    }
    memset(&s_test_bundle_i, 0, sizeof(s_test_bundle_i));
}

// 深拷贝一段字节到新分配的堆缓冲区；失败时不修改 *out。
// 前置条件：src 非空且 len>0；成功后内存所有权转移给调用方。
static int cprisk_test_copy_bytes_i(uint8_t **out,
                                    const uint8_t *src,
                                    size_t len) {
    if (!out || !src || len == 0)
        return -1;
    uint8_t *copy = (uint8_t *)malloc(len);
    if (!copy)
        return -1;
    memcpy(copy, src, len);
    *out = copy;
    return 0;
}

/// DEBUG 测试钩子：用调用方提供的四段数据替换镜像内白盒 bundle。
/// - 参数/所有权：meta 长度需 >= 头部 V1 大小，code/data/tag 非空且长度非 0；
///   成功时深拷贝，调用方保留原缓冲。
/// - 返回：0 成功；-1 参数非法、内存不足，或非 DEBUG 构建（整函数被编译为直接返回 -1）。
/// - 线程安全：不可并发调用；与 cprisk_whitebox_evaluate_domain 共用全局测试状态。
/// - 平台：仅改变数据来源，不改变真机/模拟器的检测分支。
/// - 失败语义：替换前先清空旧包，失败后保持为空（后续求值返回 -1）。
int cprisk_test_set_whitebox_bundle(
    const uint8_t *meta,
    size_t meta_len,
    const uint8_t *code,
    size_t code_len,
    const uint8_t *data,
    size_t data_len,
    const uint8_t *tag,
    size_t tag_len
) {
#if !defined(DEBUG) || !DEBUG
    /* Test hook: inert outside DEBUG builds (issue 18). */
    return -1;
#endif
    if (!meta || meta_len < CPRISK_ARMOR_WHITEBOX_HEADER_V1_SIZE ||
        !code || code_len == 0 ||
        !data || data_len == 0 ||
        !tag || tag_len == 0) {
        return -1;
    }

    cprisk_test_clear_whitebox_bundle_i();

    if (cprisk_test_copy_bytes_i(&s_test_bundle_i.meta, meta, meta_len) != 0 ||
        cprisk_test_copy_bytes_i(&s_test_bundle_i.code, code, code_len) != 0 ||
        cprisk_test_copy_bytes_i(&s_test_bundle_i.data, data, data_len) != 0 ||
        cprisk_test_copy_bytes_i(&s_test_bundle_i.tag, tag, tag_len) != 0) {
        cprisk_test_clear_whitebox_bundle_i();
        return -1;
    }

    s_test_bundle_i.meta_len = meta_len;
    s_test_bundle_i.code_len = code_len;
    s_test_bundle_i.data_len = data_len;
    s_test_bundle_i.tag_len = tag_len;
    s_test_bundle_i.active = 1;
    return 0;
}

// DEBUG 测试钩子：清空测试包（内部走带清零的释放）。
// 非 DEBUG 构建为空操作，保证测试入口不会把额外逻辑带进生产路径。
void cprisk_test_clear_whitebox_bundle(void) {
#if !defined(DEBUG) || !DEBUG
    /* Test hook: inert outside DEBUG builds (issue 18). */
    return;
#endif
    cprisk_test_clear_whitebox_bundle_i();
}

// DEBUG 测试钩子：enabled=1 时下一次求值会翻转重算结果首字节，用于验证 fail-closed。
// 非 DEBUG 构建为空操作。
void cprisk_test_set_whitebox_recompute_mismatch(int enabled) {
#if !defined(DEBUG) || !DEBUG
    /* Test hook: inert outside DEBUG builds (issue 18). */
    return;
#endif
    s_test_force_recompute_mismatch_i = enabled ? 1 : 0;
}

// 定位本模块所在的 Mach-O 头：传入自身函数地址，避免依赖全局镜像列表。
static const struct mach_header_64 *cprisk_whitebox_hdr_i(void) {
    return cprisk_find_own_header((const void *)cprisk_whitebox_hdr_i);
}

// 空指针替换哨兵：把 NULL 映射到只读空字节，满足底层“非空指针”约定。
static const uint8_t *cprisk_nonnull_bytes_i(const uint8_t *ptr) {
    return ptr ? ptr : &s_empty_byte_i;
}

// 小写十六进制编码；out_hex 至少需要 len*2+1 字节，函数负责写入结尾 NUL。
static void cprisk_hex_encode_i(const uint8_t *src, size_t len, char *out_hex) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out_hex[i * 2] = hex[(src[i] >> 4) & 0x0F];
        out_hex[i * 2 + 1] = hex[src[i] & 0x0F];
    }
    out_hex[len * 2] = '\0';
}

// 有界 strlen：最多扫描 max_len 字节，NULL 视为长度 0。
static size_t cprisk_cstrnlen_i(const char *value, size_t max_len) {
    size_t len = 0;
    if (!value)
        return 0;
    while (len < max_len && value[len] != '\0')
        len++;
    return len;
}

// 常数时间 ASCII 比较：逐字节 OR 累积差异、不提前返回，
// 避免比较耗时泄露期望 MAC 的前缀。返回 0 相等，-1 不等。
static int cprisk_ct_ascii_eq_i(const char *lhs, const char *rhs, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= (uint8_t)lhs[i] ^ (uint8_t)rhs[i];
    return diff == 0 ? 0 : -1;
}

// 8 位循环左移；shift 先对 8 取模，0 位移直接返回原值。
static uint8_t cprisk_rotl8_i(uint8_t value, unsigned int shift) {
    shift &= 7U;
    if (shift == 0U)
        return value;
    return (uint8_t)((value << shift) | (value >> (8U - shift)));
}

/*
 * DCA countermeasure: per-evaluation Fisher-Yates shuffle over [0, STATE_SIZE).
 *
 * Each evaluation generates a random permutation of state-byte indices using a
 * splitmix64 PRNG seeded from the OS CSPRNG (getentropy(2) /
 * arc4random_buf) XOR the first 8 input bytes. The seed is NEVER taken
 * from an observable clock (mach_absolute_time / wall clock): a clock
 * value is observable / predictable by an attacker who can read the same
 * timer, which would let them reconstruct the permutation. If the OS
 * CSPRNG is unavailable, the seed falls back to input bytes + a fixed
 * constant (no clock) — still deterministic for that input, but the
 * shuffle then provides no unpredictability; callers must treat that
 * path as degraded.
 * Mix layers process state bytes in permuted order (still writing to correct
 * output slots — see correctness note in cprisk_whitebox_first_mix_layer_i).
 *
 * Effect: the table access order is different every evaluation.  First-order DCA
 * that correlates "which table index is accessed at position j of the trace" with
 * intermediate state values must now also recover the permutation, which is
 * derived from OS entropy and therefore unknown to the attacker
 * even when input and output are known.
 */
// 每次求值生成一个 0..31 的随机换位表，打乱 S-box 访问顺序以对抗一阶 DCA。
// 种子只取 OS CSPRNG（getentropy/arc4random）与输入前 8 字节，绝不使用可观测时钟；
// CSPRNG 不可用时退化为“输入+常量”，随机性消失，调用方应把该路径视为降级。
static void cprisk_whitebox_gen_shuffle_i(
    uint8_t perm[CPRISK_WHITEBOX_STATE_SIZE],
    const uint8_t input[CPRISK_WHITEBOX_STATE_SIZE]
) {
    /* OS CSPRNG seed (never an observable clock — see comment above). */
    uint64_t seed = 0u;
    uint8_t entropy[8];
    int entropy_ok = 0;
#if defined(__linux__)
    if (getentropy(entropy, sizeof(entropy)) == 0)
        entropy_ok = 1;
#endif
    if (!entropy_ok) {
        arc4random_buf(entropy, sizeof(entropy));
        entropy_ok = 1;
    }
    if (entropy_ok)
        memcpy(&seed, entropy, sizeof(seed));
    cprisk_secure_zero(entropy, sizeof(entropy));
    /* Mix in first 8 bytes of input so same-entropy calls with different inputs diverge */
    uint64_t in64;
    memcpy(&in64, input, sizeof(in64));
    seed ^= in64;
    seed ^= 0x44434120484152Dull; /* "DCA HAR" */

    for (size_t i = 0; i < CPRISK_WHITEBOX_STATE_SIZE; i++)
        perm[i] = (uint8_t)i;

    /* Fisher-Yates with splitmix64 */
    for (size_t i = CPRISK_WHITEBOX_STATE_SIZE - 1u; i > 0u; i--) {
        seed += 0x9E3779B97F4A7C15ULL;
        uint64_t z = seed;
        z = (z ^ (z >> 30u)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27u)) * 0x94D049BB133111EBULL;
        z ^= z >> 31u;
        const size_t j = (size_t)(z % (uint64_t)(i + 1u));
        const uint8_t tmp = perm[i];
        perm[i] = perm[j];
        perm[j] = tmp;
    }
}

// 第一混合层：表查找 + 相邻字节扩散 + 轮常量 + 循环移位。
// 输入 state 只读；输出 out 按 i=perm[j] 写入，因此乱序处理与顺序处理结果一致。
// 真实查表前后各插入一次 dummy 读，把真实访问掩盖在噪声轨迹中。
static void cprisk_whitebox_first_mix_layer_i(
    const uint8_t *round_tables,
    const uint8_t *round_constants,
    const uint8_t state[CPRISK_WHITEBOX_STATE_SIZE],
    size_t round,
    uint8_t out[CPRISK_WHITEBOX_STATE_SIZE],
    const uint8_t perm[CPRISK_WHITEBOX_STATE_SIZE]
) {
    /*
     * Correctness: state[] is read-only within this loop; out[] is indexed by i
     * (= perm[j]).  Since no iteration reads from out[], processing bytes in
     * permuted order yields identical results to sequential order.
     */
    for (size_t j = 0; j < CPRISK_WHITEBOX_STATE_SIZE; j++) {
        const size_t i = perm[j];
        const uint8_t *table = round_tables + i * CPRISK_WHITEBOX_TABLE_WIDTH;
        /* Dummy reads before real lookup */
        cprisk_whitebox_dummy_reads_i(table, state[i], i, round);
        const uint8_t table_value = table[state[i]];
        /* Dummy reads after — real read sandwiched by noise */
        cprisk_whitebox_dummy_reads_i(table, table_value, i ^ 0x1Fu, round ^ 0x3u);
        const uint8_t mixed = (uint8_t)(table_value ^
                                        state[(i + 1u) % CPRISK_WHITEBOX_STATE_SIZE] ^
                                        round_constants[i]);
        out[i] = cprisk_rotl8_i(
            mixed,
            (unsigned int)(((i + round) % 7u) + 1u));
    }
}

// 增强扩散层：每字节与 4 条 lane（轮转 1/3/5 位）及轮常量异或，提高代数次数。
// 仅在头部 ENHANCED_DIFFUSION 标志置位时启用，用于抵抗线性/差分分析。
static void cprisk_whitebox_strong_mix_layer_i(
    const uint8_t in[CPRISK_WHITEBOX_STATE_SIZE],
    const uint8_t *round_constants,
    uint8_t out[CPRISK_WHITEBOX_STATE_SIZE]
) {
    for (size_t i = 0; i < CPRISK_WHITEBOX_STATE_SIZE; i++) {
        const uint8_t rc = round_constants[(i * 7u + 3u) % CPRISK_WHITEBOX_STATE_SIZE];
        const uint8_t lane0 = in[i];
        const uint8_t lane1 = cprisk_rotl8_i(in[(i + 7u) % CPRISK_WHITEBOX_STATE_SIZE], 1u);
        const uint8_t lane2 = cprisk_rotl8_i(in[(i + 13u) % CPRISK_WHITEBOX_STATE_SIZE], 3u);
        const uint8_t lane3 = cprisk_rotl8_i(in[(i + 23u) % CPRISK_WHITEBOX_STATE_SIZE], 5u);
        out[i] = (uint8_t)(lane0 ^ lane1 ^ lane2 ^ lane3 ^ rc);
    }
}

// 第二混合层：与第一层同构，但扩散步长（+5/+13）与移位系数不同，
// 避免轮间结构对称，让 4 轮 SPN 不出现可被约简的重复模式。
static void cprisk_whitebox_second_mix_layer_i(
    const uint8_t *round_tables,
    const uint8_t *round_constants,
    const uint8_t state[CPRISK_WHITEBOX_STATE_SIZE],
    size_t round,
    uint8_t out[CPRISK_WHITEBOX_STATE_SIZE],
    const uint8_t perm[CPRISK_WHITEBOX_STATE_SIZE]
) {
    for (size_t j = 0; j < CPRISK_WHITEBOX_STATE_SIZE; j++) {
        const size_t i = perm[j];
        const uint8_t *table = round_tables + i * CPRISK_WHITEBOX_TABLE_WIDTH;
        cprisk_whitebox_dummy_reads_i(table, state[i], i ^ 0xAu, round + 4u);
        const uint8_t table_value = table[state[i]];
        cprisk_whitebox_dummy_reads_i(table, table_value, i ^ 0x15u, round + 5u);
        const uint8_t mixed = (uint8_t)(
            table_value ^
            state[(i + 5u) % CPRISK_WHITEBOX_STATE_SIZE] ^
            round_constants[(i + 13u) % CPRISK_WHITEBOX_STATE_SIZE]
        );
        out[i] = cprisk_rotl8_i(
            mixed,
            (unsigned int)(((i * 3u + round + 1u) % 7u) + 1u)
        );
    }
}

/*
 * Dummy S-box table-lookup noise.
 *
 * Counter-measure: hexdump-based key-material tracing (unidbg魔改版 `setDisableHexdump`
 * is often left *on* during early analysis; even with hexdump disabled, memory
 * access pattern analysis can identify which table indices are read to deduce
 * the key schedule).
 *
 * Mechanism:
 *   Before and after each genuine per-byte table lookup in the mix layers we
 *   perform N dummy lookups at pseudo-random indices derived from the current
 *   state but whose results are XOR'd with themselves (net zero).  The dummy
 *   reads touch the same S-box table pages as the real reads, creating a
 *   Hamming-weight-balanced read access pattern.  An attacker observing the
 *   memory read log via hexdump sees:
 *     real_read(table, state[i])    → real byte used in computation
 *     dummy_read(table, idx_a) ^ dummy_read(table, idx_a) → discarded
 *     dummy_read(table, idx_b) ^ dummy_read(table, idx_b) → discarded
 *
 *   Because the dummy indices are derived from the evolving state (step counter,
 *   round number, byte position), they are not constant — they look identical to
 *   the real lookups from the outside.  The attacker cannot distinguish real from
 *   noise without re-implementing the full state machine.
 *
 * Performance: 2 extra byte reads per state byte per round (negligible vs the
 * existing SHA-256 CPRisk-MAC overhead).
 *
 * IMPORTANT: volatile sink prevents the compiler from eliding the dummy reads.
 */
// volatile 汇聚点：把 dummy 查表结果真正“用掉”，防止编译器把噪声读优化掉。
static volatile uint8_t s_wb_dummy_sink;   /* global volatile sink */

// 四次数据相关的伪随机查表，结果异或进 sink（净效果为零）。
// 索引由真实索引、位置与轮号共同派生，使噪声读与真实读在访问日志中无法区分。
static inline void cprisk_whitebox_dummy_reads_i(
    const uint8_t *table,
    uint8_t real_idx,
    size_t position,
    size_t round
) {
    /*
     * Derive four dummy indices from position + round + real_idx.
     * Four reads (vs the original two) give the real lookup a 1-in-5 share
     * of the access trace instead of 1-in-3, raising the noise floor for
     * first-order DCA correlation attacks that need to isolate the real read.
     * All indices are data-dependent so they resist constant-folding.
     */
    const uint8_t dummy_a = (uint8_t)((real_idx * 0x9Du) ^ (uint8_t)(position * 0x6Bu) ^ (uint8_t)(round * 0xA3u));
    const uint8_t dummy_b = (uint8_t)((real_idx ^ dummy_a) * 0xC3u ^ (uint8_t)(position + round));
    const uint8_t dummy_c = (uint8_t)((dummy_a * 0x53u) ^ dummy_b ^ (uint8_t)(round * 0x7Fu));
    const uint8_t dummy_d = (uint8_t)((dummy_b * 0x71u) ^ real_idx ^ (uint8_t)(position * 0xB1u));

    const uint8_t ra = table[dummy_a];
    const uint8_t rb = table[dummy_b];
    const uint8_t rc = table[dummy_c];
    const uint8_t rd = table[dummy_d];
    s_wb_dummy_sink = (uint8_t)(s_wb_dummy_sink ^ ra ^ rb ^ rc ^ rd);
}

// 常数时间整块比较：逐字节异或累积、不提前返回。返回 0 相等，-1 不等或空指针。
static int cprisk_ct_mem_diff_i(const uint8_t *lhs, const uint8_t *rhs, size_t len) {
    if (!lhs || !rhs)
        return -1;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= (uint8_t)(lhs[i] ^ rhs[i]);
    return diff == 0 ? 0 : -1;
}

// 读取白盒头：优先测试包，否则从 __DATA 的 whitebox-meta 段取。
// present_out 先清 0，仅在段存在且长度足够时置 1。
// 返回 0 只表示“读取流程完成”，不代表头部内容有效（有效性见 header_valid）。
static int cprisk_read_whitebox_header_i(
    struct cprisk_armor_whitebox_header *out_header,
    int *present_out
) {
    if (present_out)
        *present_out = 0;

    if (s_test_bundle_i.active) {
        if (s_test_bundle_i.meta_len < CPRISK_ARMOR_WHITEBOX_HEADER_V1_SIZE)
            return 0;
        if (present_out)
            *present_out = 1;
        if (out_header) {
            cprisk_whitebox_copy_header_from_meta_i(
                s_test_bundle_i.meta,
                s_test_bundle_i.meta_len,
                out_header);
        }
        return 0;
    }

    const struct mach_header_64 *hdr = cprisk_whitebox_hdr_i();
    if (!hdr)
        return -1;

    unsigned long sec_size = 0;
    const uint8_t *sec = cprisk_find_section(
        hdr,
        CPRISK_ARMOR_SEGMENT_DATA,
        CPRISK_ARMOR_SECTION_WHITEBOX_META,
        &sec_size);
    if (!sec || sec_size < CPRISK_ARMOR_WHITEBOX_HEADER_V1_SIZE)
        return 0;

    if (present_out)
        *present_out = 1;
    if (out_header)
        cprisk_whitebox_copy_header_from_meta_i(sec, (size_t)sec_size, out_header);
    return 0;
}

// 头部结构校验：magic、版本（仅 1..2）、元数据长度、v2 专属长度，
// 以及“置了 ASLR 绑定标志就必须是 v2 且带 v2 头”的一致性。
// 任一不满足返回 0；这是后续所有解析的前置条件。
static int cprisk_whitebox_header_valid_i(
    const struct cprisk_armor_whitebox_header *header,
    size_t meta_size
) {
    if (!header)
        return 0;
    if (header->magic != CPRISK_ARMOR_WHITEBOX_MAGIC)
        return 0;
    if (header->version < 1u || header->version > 2u)
        return 0;
    if (meta_size < CPRISK_ARMOR_WHITEBOX_HEADER_V1_SIZE)
        return 0;
    if (header->version >= 2u && meta_size < CPRISK_ARMOR_WHITEBOX_HEADER_V2_SIZE)
        return 0;
    if ((header->flags & CPRISK_ARMOR_WHITEBOX_FLAG_ASLR_TABLE_BIND) != 0u) {
        if (header->version < 2u || meta_size < CPRISK_ARMOR_WHITEBOX_HEADER_V2_SIZE)
            return 0;
    }
    return 1;
}

// 整体标签校验：长度必须恰为 32 字节，再交给常数时间 MAC 比较；
// 长度不符直接拒绝，避免短 tag 的截断比较降低到可暴力破解的强度。
static int cprisk_whitebox_tag_matches_i(
    const uint8_t expected[CPRISK_ARMOR_HASH_SIZE],
    const uint8_t *actual,
    size_t actual_len
) {
    if (!actual || actual_len != CPRISK_ARMOR_HASH_SIZE)
        return -1;
    return cprisk_mac_verify(expected, actual, CPRISK_ARMOR_HASH_SIZE);
}

// 校验 config_digest：按 Swift build() 的既有格式重建 SHA-256 输入，
// 即 label || len64(code) || code || len64(data) || data || len64(tag) || tag || 1..DOMAIN_COUNT。
// 这是“构建期配置未被替换”的绑定；摘要不符即整包拒绝（fail-closed）。
static int cprisk_whitebox_config_digest_valid_i(
    const struct cprisk_armor_whitebox_header *header,
    const uint8_t *code,
    size_t code_len,
    const uint8_t *data,
    size_t data_len,
    const uint8_t *tag,
    size_t tag_len
) {
    if (!header || !code || !data || !tag)
        return -1;
    if (tag_len != CPRISK_ARMOR_HASH_SIZE)
        return -1;

    /*
     * Mirror the configMaterial format written by WhiteBoxProfile.swift build():
     *
     *   "cprisk.whitebox.config.v2"   (no NUL)     ||
     *   uint64_LE(code_len) || code                 ||
     *   uint64_LE(data_len) || data                 ||
     *   uint64_LE(tag_len)  || tag                  ||
     *   uint32_LE(1) .. uint32_LE(DOMAIN_COUNT)
     *
     * The previous implementation hashed only (code||data||tag) and never
     * matched the Swift-produced configDigest, so whitebox loading always
     * failed at this check.
     *
     * Team-ID binding is handled separately via the ASLR table XOR in
     * cprisk_whitebox_xor_tables_aslr_i (which mixes cprisk_codesign_team_salt
     * into the per-block pad).  The CPRISK_ARMOR_WHITEBOX_FLAG_TEAM_ID_BOUND
     * flag is never set by the current Swift producer, so the old team_salt
     * branch inside this function was dead code — it has been removed.
     */
    static const uint8_t label[] = "cprisk.whitebox.config.v2";

    uint8_t digest[CPRISK_ARMOR_HASH_SIZE];
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);

    cprisk_sha256_update(&ctx, label, sizeof(label) - 1u);

    uint8_t len_le[8];

// 长度字段统一按 64 位小端序列化，避免不同架构/字长造成摘要不一致。
#define CPRISK_WBX_APPEND_LEN64(n) do { \
    uint64_t _n = (uint64_t)(n); \
    len_le[0]=(uint8_t)(_n    ); len_le[1]=(uint8_t)(_n>> 8); \
    len_le[2]=(uint8_t)(_n>>16); len_le[3]=(uint8_t)(_n>>24); \
    len_le[4]=(uint8_t)(_n>>32); len_le[5]=(uint8_t)(_n>>40); \
    len_le[6]=(uint8_t)(_n>>48); len_le[7]=(uint8_t)(_n>>56); \
    cprisk_sha256_update(&ctx, len_le, sizeof(len_le)); \
} while (0)

    CPRISK_WBX_APPEND_LEN64(code_len);
    cprisk_sha256_update(&ctx, code, code_len);

    CPRISK_WBX_APPEND_LEN64(data_len);
    cprisk_sha256_update(&ctx, data, data_len);

    CPRISK_WBX_APPEND_LEN64(tag_len);
    cprisk_sha256_update(&ctx, tag, tag_len);

#undef CPRISK_WBX_APPEND_LEN64

    // 域标签按 1..9 顺序追加，使“域集合本身”也被摘要绑定：少一个域即校验失败。
    for (uint32_t d = 1u; d <= CPRISK_WHITEBOX_DOMAIN_COUNT; d++) {
        uint8_t d_le[4];
        d_le[0] = (uint8_t)(d      );
        d_le[1] = (uint8_t)(d >>  8);
        d_le[2] = (uint8_t)(d >> 16);
        d_le[3] = (uint8_t)(d >> 24);
        cprisk_sha256_update(&ctx, d_le, sizeof(d_le));
    }

    cprisk_sha256_final(&ctx, digest);

    const int rc = cprisk_mac_verify(header->config_digest,
                                      digest,
                                      sizeof(digest));
    cprisk_secure_zero(digest, sizeof(digest));
    return rc;
}

// 校验每个域的 table 区间都落在 code 内、两两不重叠，且所有域长度之和恰好等于 code 长度。
// 防止构建期留下未签名空隙，或让两个域指向同一张表来绕过域隔离。
static int cprisk_whitebox_payload_coverage_valid_i(
    const struct cprisk_whitebox_domain_record_i *records,
    size_t record_count,
    size_t code_len
) {
    size_t total = 0;
    for (size_t i = 0; i < record_count; i++) {
        const size_t start_i = (size_t)records[i].table_offset;
        const size_t len_i = (size_t)records[i].table_length;
        const size_t end_i = start_i + len_i;

        if (start_i > code_len || len_i > code_len - start_i)
            return -1;
        if (total > code_len - len_i)
            return -1;
        total += len_i;

        for (size_t j = i + 1; j < record_count; j++) {
            const size_t start_j = (size_t)records[j].table_offset;
            const size_t len_j = (size_t)records[j].table_length;
            const size_t end_j = start_j + len_j;

            if (start_j > code_len || len_j > code_len - start_j)
                return -1;
            if (!(end_i <= start_j || end_j <= start_i))
                return -1;
        }
    }

    return total == code_len ? 0 : -1;
}

// 校验 32 字节排列：每个值 < 32 且不重复；最终 32 位掩码必须全 1。
// 排列不合法会让换位后的状态丢失或重复字节，必须在使用前拒绝。
static int cprisk_whitebox_permutation_valid_i(const uint8_t permutation[32]) {
    uint32_t seen = 0;
    for (size_t i = 0; i < CPRISK_WHITEBOX_STATE_SIZE; i++) {
        const uint8_t value = permutation[i];
        if (value >= CPRISK_WHITEBOX_STATE_SIZE)
            return -1;
        if ((seen & (1u << value)) != 0u)
            return -1;
        seen |= (1u << value);
    }
    return seen == 0xFFFFFFFFu ? 0 : -1;
}

// 校验单域记录摘要：SHA256(domain_id_u32_LE || 表字节 || permutation || final_mask || round_constants)。
// 域 ID 作为前缀，防止两个内容巧合相同的域被互换后仍通过校验。
static int cprisk_whitebox_record_digest_valid_i(
    const struct cprisk_whitebox_bundle_i *bundle,
    const struct cprisk_whitebox_domain_record_i *record
) {
    uint8_t digest[CPRISK_ARMOR_HASH_SIZE];
    cprisk_sha256_ctx ctx;

    /*
     * Domain-ID-bound digest (matches WhiteBoxProfile.swift). Prefix the
     * domain_id (u32 LE) so two domains with coincidentally identical
     * (tables, permutation, final_mask, round_constants) cannot be swapped
     * past the per-domain routing layer.
     */
    uint8_t domain_id_le[4];
    domain_id_le[0] = (uint8_t)(record->domain_id      );
    domain_id_le[1] = (uint8_t)(record->domain_id >>  8);
    domain_id_le[2] = (uint8_t)(record->domain_id >> 16);
    domain_id_le[3] = (uint8_t)(record->domain_id >> 24);
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, domain_id_le, sizeof(domain_id_le));
    cprisk_sha256_update(&ctx,
                         bundle->code + record->table_offset,
                         (size_t)record->table_length);
    cprisk_sha256_update(&ctx,
                         record->permutation,
                         sizeof(record->permutation));
    cprisk_sha256_update(&ctx,
                         record->final_mask,
                         sizeof(record->final_mask));
    cprisk_sha256_update(&ctx,
                         record->round_constants,
                         sizeof(record->round_constants));
    cprisk_sha256_final(&ctx, digest);

    const int rc = cprisk_mac_verify(record->record_digest,
                                      digest,
                                      sizeof(digest));
    cprisk_secure_zero(digest, sizeof(digest));
    return rc;
}

/// 完整校验并解析白盒 bundle（镜像段或测试包），成功后填 out_bundle。
/// - 参数/所有权：out_bundle 允许 NULL（仅做可用性探测）；内部不保留任何指针所有权。
/// - 返回：0 通过；-1 段落缺失、长度/摘要/标签/域记录任一不符。
/// - 线程安全：只读镜像与测试包，可并发；测试包替换需外部保证不并发。
/// - 平台：通过 cprisk_find_own_header/find_section 读取，模拟器与真机同路径。
/// - 失败语义：fail-closed，调用方必须把 -1 视为“白盒不可用”并降级。
static int cprisk_whitebox_validate_bundle_i(struct cprisk_whitebox_bundle_i *out_bundle) {
    unsigned long meta_size = 0;
    unsigned long code_size = 0;
    unsigned long data_size = 0;
    unsigned long tag_size = 0;
    const uint8_t *meta = NULL;
    const uint8_t *code = NULL;
    const uint8_t *data = NULL;
    const uint8_t *tag = NULL;

    // 测试模式完全绕开 Mach-O，但仍走同一套长度、标签与摘要校验。
    if (s_test_bundle_i.active) {
        meta = s_test_bundle_i.meta;
        meta_size = (unsigned long)s_test_bundle_i.meta_len;
        code = s_test_bundle_i.code;
        code_size = (unsigned long)s_test_bundle_i.code_len;
        data = s_test_bundle_i.data;
        data_size = (unsigned long)s_test_bundle_i.data_len;
        tag = s_test_bundle_i.tag;
        tag_size = (unsigned long)s_test_bundle_i.tag_len;
    } else {
        // 四个 section 必须全部定位成功；tag 的长度会在下方按 32 字节严格校验。
        const struct mach_header_64 *hdr = cprisk_whitebox_hdr_i();
        if (!hdr)
            return -1;
        meta = cprisk_find_section(
            hdr,
            CPRISK_ARMOR_SEGMENT_DATA,
            CPRISK_ARMOR_SECTION_WHITEBOX_META,
            &meta_size);
        code = cprisk_find_section(
            hdr,
            CPRISK_ARMOR_SEGMENT_DATA,
            CPRISK_ARMOR_SECTION_WHITEBOX_CODE,
            &code_size);
        data = cprisk_find_section(
            hdr,
            CPRISK_ARMOR_SEGMENT_DATA,
            CPRISK_ARMOR_SECTION_WHITEBOX_DATA,
            &data_size);
        tag = cprisk_find_section(
            hdr,
            CPRISK_ARMOR_SEGMENT_DATA,
            CPRISK_ARMOR_SECTION_WHITEBOX_TAG,
            &tag_size);
    }

    if (!meta || meta_size < CPRISK_ARMOR_WHITEBOX_HEADER_V1_SIZE)
        return -1;
    if (!code || code_size == 0 || !data || data_size == 0 || !tag)
        return -1;
    /*
     * Tag section must be exactly hash-sized. Without this check, downstream
     * `cprisk_whitebox_tag_matches_i` reads CPRISK_ARMOR_HASH_SIZE bytes from
     * `tag` regardless of the section's actual length. A truncated tag
     * section (sec_size < HASH_SIZE) would read OOB; an over-sized one would
     * silently ignore trailing bytes that may contain attacker-injected
     * content elsewhere on the page.
     */
    /* Full 32-BYTE tag required. Do NOT truncate this comparison to
     * 32 bits: a 32-bit tag check costs only ~2^32 brute-force trials
     * and must never be the sole authentication check. */
    // 段大小必须精确等于 32 字节：短读会越界，长读会忽略同一页上夹带的额外内容。
    if (tag_size != (unsigned long)CPRISK_ARMOR_HASH_SIZE)
        return -1;

    struct cprisk_armor_whitebox_header header_storage;
    cprisk_whitebox_copy_header_from_meta_i(meta, (size_t)meta_size, &header_storage);
    const struct cprisk_armor_whitebox_header *header = &header_storage;
    if (!cprisk_whitebox_header_valid_i(header, (size_t)meta_size))
        return -1;

    const size_t code_len = (size_t)code_size;
    const size_t data_len = (size_t)data_size;
    if (code_len > SIZE_MAX - data_len)
        return -1;
    const size_t payload_len = code_len + data_len;
    /* payload_size covers only the executable white-box payload body (code + data).
       The detached tag section is authenticated independently and excluded from
       this field by the producer. */
    // payload_size 由生产者写入；为 0 表示旧构建未填，跳过等值检查以保持兼容。
    if (header->payload_size != 0u &&
        (size_t)header->payload_size != payload_len)
        return -1;
    if (tag_size != CPRISK_ARMOR_HASH_SIZE)
        return -1;
    if ((data_len % sizeof(struct cprisk_whitebox_domain_record_i)) != 0u)
        return -1;

    // data 区必须恰好是 9 条定长域记录：多一条、少一条或长度非整数倍都拒绝。
    const size_t record_count = data_len / sizeof(struct cprisk_whitebox_domain_record_i);
    if (record_count != CPRISK_WHITEBOX_DOMAIN_COUNT)
        return -1;

    const struct cprisk_whitebox_domain_record_i *records =
        (const struct cprisk_whitebox_domain_record_i *)data;
    struct cprisk_whitebox_bundle_i bundle_view;
    memset(&bundle_view, 0, sizeof(bundle_view));
    memcpy(&bundle_view.header, &header_storage, sizeof(bundle_view.header));
    bundle_view.code = code;
    bundle_view.code_len = code_len;
    bundle_view.data = data;
    bundle_view.data_len = data_len;
    bundle_view.tag = tag;
    bundle_view.records = records;
    bundle_view.record_count = record_count;

    // 先算载荷摘要 SHA256("cprisk.whitebox.tag.v1" || code || data)，
    // 再验证 tag section 是对该摘要的 CPRisk-MAC；任一不符即拒绝。
    uint8_t overall_tag[CPRISK_ARMOR_HASH_SIZE];
    cprisk_sha256_ctx overall_ctx;
    cprisk_sha256_init(&overall_ctx);
    cprisk_sha256_update(&overall_ctx,
                         s_overall_tag_label_i,
                         sizeof(s_overall_tag_label_i) - 1u);
    cprisk_sha256_update(&overall_ctx, code, code_len);
    cprisk_sha256_update(&overall_ctx, data, data_len);
    cprisk_sha256_final(&overall_ctx, overall_tag);
    if (cprisk_whitebox_tag_matches_i(overall_tag, tag, (size_t)tag_size) != 0) {
        cprisk_secure_zero(overall_tag, sizeof(overall_tag));
        return -1;
    }
    cprisk_secure_zero(overall_tag, sizeof(overall_tag));

    if (cprisk_whitebox_config_digest_valid_i(header,
                                              code,
                                              code_len,
                                              data,
                                              data_len,
                                              tag,
                                              (size_t)tag_size) != 0) {
        cprisk_secure_zero(&bundle_view.header, sizeof(bundle_view.header));
        return -1;
    }

    if (cprisk_whitebox_payload_coverage_valid_i(records, record_count, code_len) != 0) {
        cprisk_secure_zero(&bundle_view.header, sizeof(bundle_view.header));
        return -1;
    }

    // 逐域校验：域号范围、轮数、表长、排列、记录摘要，
    // 并用位图确保 1..9 每个域恰好出现一次。
    uint32_t domain_mask = 0;
    int domain_loop_failed = 0;
    for (size_t i = 0; i < record_count; i++) {
        const struct cprisk_whitebox_domain_record_i *record = &records[i];
        if (record->domain_id < CPRISK_WHITEBOX_DOMAIN_ANCHOR_TAG ||
            record->domain_id > CPRISK_WHITEBOX_DOMAIN_HEADER_ENCRYPTION) {
            domain_loop_failed = 1;
            break;
        }
        if (record->round_count != CPRISK_WHITEBOX_ROUND_COUNT) {
            domain_loop_failed = 1;
            break;
        }
        if (record->table_length != CPRISK_WHITEBOX_DOMAIN_TABLE_BYTES) {
            domain_loop_failed = 1;
            break;
        }
        if (cprisk_whitebox_permutation_valid_i(record->permutation) != 0) {
            domain_loop_failed = 1;
            break;
        }
        if (cprisk_whitebox_record_digest_valid_i(&bundle_view, record) != 0) {
            domain_loop_failed = 1;
            break;
        }

        const uint32_t bit = 1u << (record->domain_id - 1u);
        if ((domain_mask & bit) != 0u) {
            domain_loop_failed = 1;
            break;
        }
        domain_mask |= bit;
    }
    if (domain_loop_failed) {
        cprisk_secure_zero(&bundle_view.header, sizeof(bundle_view.header));
        return -1;
    }

    // 位图必须覆盖全部 9 个域；缺域意味着对应 PRF 输出不可用，按失败处理。
    if (domain_mask != ((1u << CPRISK_WHITEBOX_DOMAIN_COUNT) - 1u)) {
        cprisk_secure_zero(&bundle_view.header, sizeof(bundle_view.header));
        return -1;
    }

    // 成功与否都在退出前清零栈上的头部副本，避免 anchor slide 等字段残留。
    if (out_bundle) {
        memcpy(out_bundle, &bundle_view, sizeof(*out_bundle));
    }
    /* Always-on cleanup: previously this only ran on the success path, so
     * any of the above `return -1` exits left the anchor_slide and other
     * header bytes resident on the stack (potentially still mapped under
     * subsequent unrelated frames). Zero on every exit. */
    cprisk_secure_zero(&bundle_view.header, sizeof(bundle_view.header));
    return 0;
}

// 按 domain_id 线性查找记录；未找到返回 NULL，调用方必须拒绝该域而不是回退到别的域。
static const struct cprisk_whitebox_domain_record_i *cprisk_whitebox_record_for_domain_i(
    const struct cprisk_whitebox_bundle_i *bundle,
    uint32_t domain_id
) {
    if (!bundle || !bundle->records)
        return NULL;
    for (size_t i = 0; i < bundle->record_count; i++) {
        if (bundle->records[i].domain_id == domain_id)
            return &bundle->records[i];
    }
    return NULL;
}

/// 单域 SPN 求值：input[32] → 4 轮表查找/混合 → out[32]。
/// - 输入输出均为 32 字节定长缓冲，调用方拥有；域输入派生由 prepare_prf_input 负责。
/// - 返回：0 成功；-1 参数非法、表长异常或堆分配失败。
/// - 线程安全：只用栈与局部堆，可并发；每次调用独立生成 DCA 排列。
/// - 平台：ASLR 解绑依赖运行时 slide，测试包下按 slide=0 处理。
/// - 失败语义：失败时不保证 out 内容，调用方不得使用。
static int cprisk_whitebox_eval_record_i(
    const struct cprisk_whitebox_bundle_i *bundle,
    const struct cprisk_whitebox_domain_record_i *record,
    const uint8_t input[32],
    uint8_t out[32]
) {
    if (!bundle || !record || !input || !out)
        return -1;

    // 表源指向 code 区内该域的 32768 字节表；ASLR 模式会逐轮复制后再解绑。
    const uint8_t *tables_src = bundle->code + record->table_offset;
    const size_t tlen = (size_t)record->table_length;
    int aslr_tables = 0;
#if !defined(CPRISK_DISABLE_WHITEBOX_ASLR_TABLE)
    if (cprisk_whitebox_aslr_table_bind_runtime_enabled_i(&bundle->header))
        aslr_tables = 1;
#endif
    uint8_t *round_heap = NULL;
    if (aslr_tables) {
        // 表长必须精确等于单域表大小：过短会越界读，过长说明布局被改过。
        if (tlen == 0u || tlen > CPRISK_MAX_SECTION_SIZE ||
            tlen != CPRISK_WHITEBOX_DOMAIN_TABLE_BYTES)
            return -1;
        round_heap = (uint8_t *)malloc(CPRISK_WHITEBOX_TABLE_STRIDE);
        if (!round_heap)
            return -1;
    }

    intptr_t rs = (intptr_t)0;
    // 测试包没有真实镜像布局，slide 固定为 0，表按未绑定形式生成。
    if (aslr_tables && !s_test_bundle_i.active) {
        const struct mach_header_64 *mh = cprisk_whitebox_hdr_i();
        if (mh)
            rs = cprisk_compute_slide(mh);
    }

    uint8_t state[CPRISK_WHITEBOX_STATE_SIZE];
    uint8_t next[CPRISK_WHITEBOX_STATE_SIZE];
    uint8_t scratch[CPRISK_WHITEBOX_STATE_SIZE];
    uint8_t dca_perm[CPRISK_WHITEBOX_STATE_SIZE];
    // 增强扩散是可选加固：老构建未置位时保持既有输出，避免兼容性断裂。
    const int enhanced_diffusion =
        (bundle->header.flags & CPRISK_ARMOR_WHITEBOX_FLAG_ENHANCED_DIFFUSION) != 0u;
    memcpy(state, input, sizeof(state));

    /* Generate one per-evaluation shuffle; reused across all rounds so the
     * permutation is stable within a call but random between calls. */
    cprisk_whitebox_gen_shuffle_i(dca_perm, input);

    // 每轮：定位该轮表（必要时原地解绑 ASLR）→ 第一混合 →（可选增强+第二混合）→ 按域排列换位。
    for (size_t round = 0; round < CPRISK_WHITEBOX_ROUND_COUNT; round++) {
        const uint8_t *round_tables = NULL;
        if (aslr_tables) {
            memcpy(
                round_heap,
                tables_src + round * CPRISK_WHITEBOX_TABLE_STRIDE,
                CPRISK_WHITEBOX_TABLE_STRIDE);
            const uint32_t blk_base =
                (uint32_t)((round * CPRISK_WHITEBOX_TABLE_STRIDE) / 32u);
            cprisk_whitebox_xor_tables_aslr_i(
                round_heap,
                CPRISK_WHITEBOX_TABLE_STRIDE,
                blk_base,
                rs,
                bundle->header.aslr_table_anchor_slide,
                record->domain_id);
            round_tables = round_heap;
        } else {
            round_tables = tables_src + round * CPRISK_WHITEBOX_TABLE_STRIDE;
        }
        const uint8_t *round_constants =
            record->round_constants + round * CPRISK_WHITEBOX_STATE_SIZE;

        // 第一混合始终执行；增强扩散打开时再追加两层，提升每轮的非线性度。
        cprisk_whitebox_first_mix_layer_i(round_tables, round_constants, state, round, next, dca_perm);
        if (enhanced_diffusion) {
            cprisk_whitebox_strong_mix_layer_i(next, round_constants, scratch);
            cprisk_whitebox_second_mix_layer_i(
                round_tables,
                round_constants,
                scratch,
                round,
                next,
                dca_perm
            );
        }

        for (size_t i = 0; i < CPRISK_WHITEBOX_STATE_SIZE; i++)
            state[i] = next[record->permutation[i]];

        // 每轮用完立即清零可写表副本，缩短密钥材料在堆上的驻留窗口。
        if (aslr_tables)
            cprisk_secure_zero(round_heap, CPRISK_WHITEBOX_TABLE_STRIDE);
    }

    // 输出 = 最终状态 XOR 域掩码；掩码保证两个域即使内部状态相同也得到不同结果。
    for (size_t i = 0; i < CPRISK_WHITEBOX_STATE_SIZE; i++)
        out[i] = (uint8_t)(state[i] ^ record->final_mask[i]);

    // 清零全部中间状态、下一状态、临时状态与 DCA 排列；堆副本在此清空后释放。
    if (round_heap) {
        cprisk_secure_zero(round_heap, CPRISK_WHITEBOX_TABLE_STRIDE);
        free(round_heap);
    }
    cprisk_secure_zero(state, sizeof(state));
    cprisk_secure_zero(next, sizeof(next));
    cprisk_secure_zero(scratch, sizeof(scratch));
    cprisk_secure_zero(dca_perm, sizeof(dca_perm));
    return 0;
}

// 独立路径重算同一输入：故意走完整求值而非复用结果，
// 使瞬时故障注入必须同时骗过两次完整 PRF 才能不被发现。
static int cprisk_whitebox_eval_record_recompute_i(
    const struct cprisk_whitebox_bundle_i *bundle,
    const struct cprisk_whitebox_domain_record_i *record,
    const uint8_t input[32],
    uint8_t out[32]
) {
    if (!bundle || !record || !input || !out)
        return -1;

    /* Recompute via an independent invocation path so injected transient
       faults must survive two full PRF evaluations to stay undetected. */
    return cprisk_whitebox_eval_record_i(bundle, record, input, out);
}

// 32 位最小值，用于把计数器饱和到 255（单字节编码）。
static uint32_t cprisk_wb_u32_min_i(uint32_t a, uint32_t b) {
    return a < b ? a : b;
}

/* Domains 6-7: when hybrid KDF has produced effectiveRoot, PRF input is
 * SHA256(label || domain_id || input || er); otherwise identity. Domains 8-9
 * encrypt static import/header payloads at build time and therefore must remain
 * build-stable: runtime-only environment material cannot be reproduced by the
 * producer and previously made those payloads undecryptable after init. */
/// 按域派生 SPN 的 32 字节输入。
/// - 域 6/7（DEVICE_BOUND/SESSION_BOUND）在 effectiveRoot 可用时计算
///   SHA256(label || domain_id || 被动信号位 || 计数器 || input || effectiveRoot)。
/// - 其余域以及 effectiveRoot 不可用时：直接透传 input（域 8/9 必须在构建期可复现）。
/// - 返回：恒为 0；input 允许 NULL（按全零处理），out 必填。
/// - 线程安全：只读全局信号/计数器，可并发。
/// - 失败语义：effectiveRoot 缺失时静默降级为透传，由调用方的域策略决定是否接受。
static int cprisk_whitebox_prepare_prf_input_i(
    uint32_t domain_id,
    const uint8_t *input_opt,
    uint8_t out[CPRISK_WHITEBOX_STATE_SIZE]
) {
    const uint8_t *src = input_opt ? input_opt : s_zero_state_i;

    // 只有 6/7 是运行时动态域；1..5 与 8..9 必须保持构建期稳定。
    if (domain_id < CPRISK_WHITEBOX_DOMAIN_DEVICE_BOUND ||
        domain_id > CPRISK_WHITEBOX_DOMAIN_SESSION_BOUND) {
        memcpy(out, src, CPRISK_WHITEBOX_STATE_SIZE);
        return 0;
    }

    uint8_t er[CPRISK_ARMOR_KEY_SIZE];
    // effectiveRoot 是 L2/L3 派生的结果；不可用时不能发明替代密钥，只能透传原始输入。
    if (cprisk_get_effective_root(er) != 0) {
        memcpy(out, src, CPRISK_WHITEBOX_STATE_SIZE);
        return 0;
    }

    // 域分隔标签 + 域号，防止把一个域的输入重放到另一个域。
    static const uint8_t k_bind_label[] = "CPRISK_WB_DOMAIN_ER_BIND_v1";
    uint8_t domain_le[4];
    domain_le[0] = (uint8_t)(domain_id & 0xFFu);
    domain_le[1] = (uint8_t)((domain_id >> 8) & 0xFFu);
    domain_le[2] = (uint8_t)((domain_id >> 16) & 0xFFu);
    domain_le[3] = (uint8_t)((domain_id >> 24) & 0xFFu);
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, k_bind_label, sizeof(k_bind_label) - 1u);
    cprisk_sha256_update(&ctx, domain_le, sizeof(domain_le));
    /* Fold passive/cached environment binding into dynamic domains 6-7 only. */
    // 被动信号与环境压力只折进动态域：它们随运行环境变化，构建期无法预置。
    if (!s_test_bundle_i.active) {
        uint32_t pb = cprisk_collect_passive_signal_binding_bits();
        uint8_t pb_le[4];
        pb_le[0] = (uint8_t)(pb & 0xFFu);
        pb_le[1] = (uint8_t)((pb >> 8) & 0xFFu);
        pb_le[2] = (uint8_t)((pb >> 16) & 0xFFu);
        pb_le[3] = (uint8_t)((pb >> 24) & 0xFFu);
        cprisk_sha256_update(&ctx, pb_le, sizeof(pb_le));
        uint32_t wbp = cprisk_integrity_wb_prf_pressure_mask();
        uint8_t wbp_le[4];
        wbp_le[0] = (uint8_t)(wbp & 0xFFu);
        wbp_le[1] = (uint8_t)((wbp >> 8) & 0xFFu);
        wbp_le[2] = (uint8_t)((wbp >> 16) & 0xFFu);
        wbp_le[3] = (uint8_t)((wbp >> 24) & 0xFFu);
        cprisk_sha256_update(&ctx, wbp_le, sizeof(wbp_le));
        /* Graduated VM/hook-surface signal: bit flags alone are easier to spoof than monotonic counts. */
        // 计数器截断为 1 字节并饱和：既参与环境绑定，又避免整数溢出影响摘要格式。
        {
            uint32_t cc = cprisk_get_vm_mprotect_crosscheck_mismatch_count();
            uint32_t mt = cprisk_get_vm_mprotect_mach_trap_mismatch_count();
            uint8_t cc_b = (uint8_t)cprisk_wb_u32_min_i(cc, 255u);
            uint8_t mt_b = (uint8_t)cprisk_wb_u32_min_i(mt, 255u);
            cprisk_sha256_update(&ctx, &cc_b, 1);
            cprisk_sha256_update(&ctx, &mt_b, 1);
        }
    }
    // 最后才混入原始输入与 effectiveRoot，并立即清零 er，避免派生密钥材料外泄。
    cprisk_sha256_update(&ctx, src, CPRISK_WHITEBOX_STATE_SIZE);
    cprisk_sha256_update(&ctx, er, sizeof(er));
    cprisk_sha256_final(&ctx, out);
    cprisk_secure_zero(er, sizeof(er));
    return 0;
}

// DEBUG 测试钩子：暴露 prepare_prf_input 供测试比对期望输出。
// 非 DEBUG 返回 -1；input 允许 NULL（按全零处理），out 必填。
int cprisk_test_whitebox_prepare_domain_input(
    uint32_t domain_id,
    const uint8_t input[CPRISK_WHITEBOX_STATE_SIZE],
    uint8_t out[CPRISK_WHITEBOX_STATE_SIZE]
) {
#if !defined(DEBUG) || !DEBUG
    /* Test hook: inert outside DEBUG builds (issue 18). */
    return -1;
#endif
    if (!out)
        return -1;
    return cprisk_whitebox_prepare_prf_input_i(
        domain_id,
        input ? input : s_zero_state_i,
        out);
}

// 基线能力位：运行时派生、签名/验签 helper 与白盒框架始终可用，
// 与表是否成功加载无关（表不可用时由调用方按能力位降级）。
static uint32_t cprisk_base_capabilities_i(void) {
    return CPRISK_ARMOR_CAP_RUNTIME_DERIVE_KEY |
           CPRISK_ARMOR_CAP_RUNTIME_SIGN_HELPER |
           CPRISK_ARMOR_CAP_RUNTIME_VERIFY_HELPER |
           CPRISK_ARMOR_CAP_WHITEBOX_FRAMEWORK;
}

/// 返回当前构建 + 运行时的加固能力位图。
/// - SECTION_LAYOUT 只有在完整 bundle 校验通过时才置位；失败仅少一位，不崩溃。
/// - 线程安全：只读镜像与测试包；返回后不保留任何状态。
/// - 平台：模拟器同样执行；ASLR 绑定由头部标志决定。
/// - 失败语义：校验失败视为“白盒段不可用”，调用方应降级到普通 MAC。
uint32_t cprisk_get_armor_capabilities(void) {
    uint32_t capabilities = cprisk_base_capabilities_i();
    struct cprisk_whitebox_bundle_i bundle;
    memset(&bundle, 0, sizeof(bundle));

    if (cprisk_whitebox_validate_bundle_i(&bundle) == 0)
        capabilities |= CPRISK_ARMOR_CAP_WHITEBOX_SECTION_LAYOUT;

    capabilities |= cprisk_vm_query_armor_capability_bits();

    cprisk_secure_zero(&bundle.header, sizeof(bundle.header));
    return capabilities;
}

/// 探测白盒能力，填充 ABI 版本、能力位与状态标志。
/// - out_probe 必填且会被整体清零；失败返回 -1 时不保证内容。
/// - METADATA_PRESENT 只表示段存在；METADATA_VALID/ENGINE_READY 需要完整校验通过。
/// - 线程安全：与求值相同，可并发只读。
/// - 平台：不区分模拟器；无平台专属指令。
/// - 失败语义：只有参数错误返回 -1，其余情况用 flags 表达可用性。
int cprisk_whitebox_probe(struct cprisk_whitebox_probe_result *out_probe) {
    if (!out_probe)
        return -1;

    memset(out_probe, 0, sizeof(*out_probe));
    out_probe->abi_version = CPRISK_ARMOR_WHITEBOX_ABI_VERSION;
    out_probe->capabilities = cprisk_base_capabilities_i();
    out_probe->flags = CPRISK_WHITEBOX_PROBE_FLAG_COMPILED;

    struct cprisk_armor_whitebox_header header;
    int present = 0;
    memset(&header, 0, sizeof(header));

    if (cprisk_read_whitebox_header_i(&header, &present) == 0 && present) {
        out_probe->flags |= CPRISK_WHITEBOX_PROBE_FLAG_METADATA_PRESENT;
        out_probe->metadata_version = header.version;
    }

    struct cprisk_whitebox_bundle_i bundle;
    memset(&bundle, 0, sizeof(bundle));
    if (cprisk_whitebox_validate_bundle_i(&bundle) == 0) {
        out_probe->flags |= CPRISK_WHITEBOX_PROBE_FLAG_METADATA_VALID;
        out_probe->flags |= CPRISK_WHITEBOX_PROBE_FLAG_ENGINE_READY;
        out_probe->capabilities |= CPRISK_ARMOR_CAP_WHITEBOX_SECTION_LAYOUT;
        out_probe->metadata_version = bundle.header.version;
    }

    cprisk_secure_zero(&bundle.header, sizeof(bundle.header));
    cprisk_secure_zero(&header, sizeof(header));
    return 0;
}

// 快速可用性探测：只做一次完整 bundle 校验；失败返回 0，调用方据此降级。
int cprisk_whitebox_available(void) {
    return cprisk_whitebox_validate_bundle_i(NULL) == 0 ? 1 : 0;
}

/// 对外主入口：对指定 domain 执行白盒 PRF，input[32] → out[32]。
/// - input 允许 NULL（按全零处理）；out 必填，调用方拥有。
/// - 返回：0 成功；-1 表示 bundle/域缺失、输入派生失败或重算不一致。
/// - 线程安全：每次调用独立状态，可并发；测试 bundle 替换除外。
/// - 平台：真机在入口/出口检查调试器，模拟器跳过该检查。
/// - 失败语义：fail-closed —— 重算不一致会清零 out、毒化 whitebox lane 并返回 -1。
int cprisk_whitebox_evaluate_domain(
    uint32_t domain_id,
    const uint8_t input[32],
    uint8_t out[32]
) {
#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    /* Entry trace check: deterministic but incorrect PRF output.
     * WARNING: this fake-output behaviour is only as good as the traced
     * detection it depends on. If an attacker hooks the traced detector,
     * the fake output never triggers. Two INDEPENDENT detectors are
     * therefore OR-ed here (sysctl-based cprisk_is_being_traced() and
     * the redundant multi-signal cprisk_is_being_traced_redundant());
     * hooking one alone is not enough. The PRF path additionally has an
     * independent recompute-and-compare check below, which does not
     * depend on traced detection at all. */
    // 调试器在场时返回“确定性但错误”的输出，避免向攻击者暴露真实 PRF 值。
    // 两路独立追踪检测 OR 在一起：hook 掉其中一路仍会被另一路捕获。
    if (!s_test_bundle_i.active &&
        (cprisk_is_being_traced_redundant() || cprisk_is_being_traced())) {
        const uint8_t *src = input ? input : s_zero_state_i;
        cprisk_sha256_ctx pctx;
        cprisk_sha256_init(&pctx);
        cprisk_sha256_update(&pctx, src, CPRISK_WHITEBOX_STATE_SIZE);
        cprisk_sha256_final(&pctx, out);
        return 0;
    }
#endif

    struct cprisk_whitebox_bundle_i bundle;
    memset(&bundle, 0, sizeof(bundle));
    // 每次求值都重新完整校验 bundle，不信任缓存结果，防止运行期内存篡改。
    if (cprisk_whitebox_validate_bundle_i(&bundle) != 0)
        return -1;

    const struct cprisk_whitebox_domain_record_i *record =
        cprisk_whitebox_record_for_domain_i(&bundle, domain_id);
    if (!record) {
        cprisk_secure_zero(&bundle.header, sizeof(bundle.header));
        return -1;
    }

    uint8_t prf_input[CPRISK_WHITEBOX_STATE_SIZE];
    if (cprisk_whitebox_prepare_prf_input_i(domain_id, input, prf_input) != 0) {
        cprisk_secure_zero(prf_input, sizeof(prf_input));
        cprisk_secure_zero(&bundle.header, sizeof(bundle.header));
        return -1;
    }

    const int rc = cprisk_whitebox_eval_record_i(
        &bundle,
        record,
        prf_input,
        out);
    if (rc == 0) {
        // 双算一致性：用独立路径重算同一输入并做常数时间比较；
        // 任何差异都按完整性破坏处理，绝不返回“可能正确”的输出。
        uint8_t recomputed[CPRISK_WHITEBOX_STATE_SIZE];
        const int rc_recompute = cprisk_whitebox_eval_record_recompute_i(
            &bundle,
            record,
            prf_input,
            recomputed);
        if (rc_recompute != 0) {
            cprisk_secure_zero(recomputed, sizeof(recomputed));
            cprisk_secure_zero(out, CPRISK_WHITEBOX_STATE_SIZE);
            cprisk_secure_zero(&bundle.header, sizeof(bundle.header));
            cprisk_integrity_poison_whitebox_lane();
            return -1;
        }
        if (s_test_force_recompute_mismatch_i)
            recomputed[0] ^= 0x5Au;
        if (cprisk_ct_mem_diff_i(out, recomputed, CPRISK_WHITEBOX_STATE_SIZE) != 0) {
            // 重算不一致 = 表/状态被篡改或发生故障注入：清零输出、毒化 lane 并 fail-closed。
            cprisk_secure_zero(recomputed, sizeof(recomputed));
            cprisk_secure_zero(out, CPRISK_WHITEBOX_STATE_SIZE);
            cprisk_secure_zero(&bundle.header, sizeof(bundle.header));
            cprisk_integrity_poison_whitebox_lane();
            return -1;
        }
        cprisk_secure_zero(recomputed, sizeof(recomputed));
    }
    cprisk_secure_zero(prf_input, sizeof(prf_input));
    cprisk_secure_zero(&bundle.header, sizeof(bundle.header));

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    /* Exit trace check: debugger may attach mid-evaluation.
     * Same dual-detector rationale as the entry check above. */
    // 出口再查一次调试器：可能在求值中途 attach；命中时同样替换为假输出。
    if (rc == 0 && !s_test_bundle_i.active &&
        (cprisk_is_being_traced_redundant() || cprisk_is_being_traced())) {
        const uint8_t *src = input ? input : s_zero_state_i;
        cprisk_sha256_ctx pctx;
        cprisk_sha256_init(&pctx);
        cprisk_sha256_update(&pctx, src, CPRISK_WHITEBOX_STATE_SIZE);
        cprisk_sha256_final(&pctx, out);
    }
#endif

    return rc;
}

/// 派生“有效签名密钥”：CPRisk-MAC(runtime_material, base_key)。
/// - 参数/所有权：base_key 允许 NULL 且长度必须为 0；out_key 必填，调用方拥有。
/// - 返回：0 成功；-1 runtime material 未就绪、参数非法或派生失败。
/// - 线程安全：只读取全局 runtime material 的快照，可并发。
/// - 平台：真机上调试器命中会翻转材料，使密钥静默错误；Release 默认绑定 ASLR。
/// - 失败语义：失败时必须拒绝签名/验签，不得回退到 base_key。
static int cprisk_derive_effective_signing_key_core_i(
    const uint8_t *base_key,
    size_t base_key_len,
    const uint8_t *request_binding_digest,
    uint8_t out_key[32]
) {
    if (!out_key)
        return -1;
    // runtime material 未就绪即拒绝派生：没有每安装密钥材料就没有可信的签名根。
    if (cprisk_runtime_material_ready() == 0)
        return -1;
    if (!base_key && base_key_len != 0)
        return -1;

    uint8_t runtime_material[CPRISK_ARMOR_HASH_SIZE];
    if (cprisk_get_runtime_material(runtime_material) != 0)
        return -1;

    /* Intermediate signing tier: weak staged hits / low-confidence probes perturb
     * material only on the signing path (not cprisk_get_runtime_material). */
    // 中间层混合只作用于签名路径，不改变对外暴露的 runtime material 本身。
    cprisk_signing_runtime_material_intermediate_mix(runtime_material);

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    /* Corrupt runtime material under debugger so derived key is silently wrong.
     * Dual-detector (see evaluate_domain entry check): either detector
     * firing is enough, so hooking one detector does not disable this. */
    // 调试器命中时翻转材料：输出仍是“看起来正常”的密钥，但所有签名都会验签失败。
    if (cprisk_is_being_traced_redundant() || cprisk_is_being_traced()) {
        for (size_t pi = 0; pi < CPRISK_ARMOR_HASH_SIZE; pi++)
            runtime_material[pi] ^= 0xA5u;
    }
    /*
     * Bind CPRisk-MAC key material to ASLR slide in release builds by default so
     * offline replay needs both the same runtime material and the same image
     * layout. Debug builds stay opt-in to avoid surprising local fixtures.
     *
     * Override rules:
     *   - CPRISK_SIGNING_KEY_ASLR_BIND=1 => force enable
     *   - CPRISK_SIGNING_KEY_ASLR_BIND=0 => force disable
     *   - unset => enabled on release, disabled on debug
     */
    {
        /* Env override is DEBUG-only: in Release the binding is always
         * on (the environment must not be able to weaken signing). */
        // 只有 DEBUG 允许环境变量覆盖；Release 强制绑定，防止通过进程环境削弱签名。
        int should_bind = 0;
#if defined(DEBUG) && DEBUG
        const char *eb = getenv("CPRISK_SIGNING_KEY_ASLR_BIND");
        if (eb && eb[0] != '\0') {
            should_bind = (eb[0] == '1' || eb[0] == 'y' || eb[0] == 'Y') ? 1 : 0;
        } else {
            should_bind = 0;
        }
#else
        should_bind = 1;
#endif
        if (should_bind) {
            const struct mach_header_64 *mh =
                cprisk_find_own_header((const void *)&cprisk_derive_effective_signing_key);
            if (mh) {
                uint64_t term = cprisk_wbx_slide_term_u64(cprisk_compute_slide(mh));
                uint8_t x[8];
                memcpy(x, &term, sizeof(x));
                for (size_t pi = 0; pi < 8; pi++)
                    runtime_material[pi] ^= x[pi];
            }
        }
    }
#endif

    // 主体派生：以 runtime material 为 MAC 密钥、base_key 为消息，输出 32 字节有效密钥。
    cprisk_mac_sha256(runtime_material,
                       CPRISK_ARMOR_HASH_SIZE,
                       cprisk_nonnull_bytes_i(base_key),
                       base_key_len,
                       out_key);

    // 可选的第二级绑定：用请求摘要再 MAC 一次，把签名密钥固定到单个请求上下文。
    if (request_binding_digest) {
        uint8_t rebound_key[CPRISK_ARMOR_HASH_SIZE];
        cprisk_mac_sha256(out_key,
                           CPRISK_ARMOR_HASH_SIZE,
                           request_binding_digest,
                           CPRISK_ARMOR_HASH_SIZE,
                           rebound_key);
        memcpy(out_key, rebound_key, CPRISK_ARMOR_HASH_SIZE);
        cprisk_secure_zero(rebound_key, sizeof(rebound_key));
    }

    cprisk_secure_zero(runtime_material, sizeof(runtime_material));
    return 0;
}

// 对外包装：不带请求绑定的有效签名密钥派生。
int cprisk_derive_effective_signing_key(
    const uint8_t *base_key,
    size_t base_key_len,
    uint8_t out_key[32]
) {
    return cprisk_derive_effective_signing_key_core_i(
        base_key,
        base_key_len,
        NULL,
        out_key
    );
}

// 对外包装：把请求绑定摘要折入密钥；摘要为 NULL 时直接拒绝。
int cprisk_derive_effective_signing_key_with_request_binding_digest(
    const uint8_t *base_key,
    size_t base_key_len,
    const uint8_t request_binding_digest[32],
    uint8_t out_key[32]
) {
    if (!request_binding_digest)
        return -1;
    return cprisk_derive_effective_signing_key_core_i(
        base_key,
        base_key_len,
        request_binding_digest,
        out_key
    );
}

// 对外包装：派生后输出小写十六进制；内部密钥缓冲用完立即清零。
int cprisk_derive_effective_signing_key_hex(
    const uint8_t *base_key,
    size_t base_key_len,
    char out_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1]
) {
    if (!out_hex)
        return -1;

    uint8_t derived_key[CPRISK_ARMOR_HASH_SIZE];
    if (cprisk_derive_effective_signing_key(base_key, base_key_len, derived_key) != 0)
        return -1;

    cprisk_hex_encode_i(derived_key, sizeof(derived_key), out_hex);
    cprisk_secure_zero(derived_key, sizeof(derived_key));
    return 0;
}

/// 计算 CPRisk-MAC 并输出小写十六进制。
/// - key/msg 允许 NULL 仅当对应长度为 0；out_hex 至少 65 字节，调用方拥有。
/// - 返回：0 成功；参数非法返回 -1（此时不写 out_hex）。
/// - 线程安全：无全局状态，可并发。
/// - 平台：纯软件实现，不依赖硬件指令。
/// - 失败语义：失败时不产生可用签名。
int cprisk_mac_sha256_hex(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *msg,
    size_t msg_len,
    char out_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1]
) {
    if (!out_hex)
        return -1;
    if (!key && key_len != 0)
        return -1;
    if (!msg && msg_len != 0)
        return -1;

    uint8_t digest[CPRISK_ARMOR_HASH_SIZE];
    cprisk_mac_sha256(cprisk_nonnull_bytes_i(key),
                       key_len,
                       cprisk_nonnull_bytes_i(msg),
                       msg_len,
                       digest);
    cprisk_hex_encode_i(digest, sizeof(digest), out_hex);
    cprisk_secure_zero(digest, sizeof(digest));
    return 0;
}

/// 内部签名实现：派生有效密钥 → CPRisk-MAC(msg) → 小写十六进制。
/// - request_binding_digest 为 NULL 时跳过请求绑定；out_hex 必填。
/// - 返回：0 成功；-1 参数非法或派生失败（此时 out_hex 内容不可用）。
/// - 线程安全：可并发；无缓存状态。
/// - 平台：真机上调试器命中会翻转密钥字节，使签名静默无效。
/// - 失败语义：绝不回退到未派生的 base_key。
static int cprisk_sign_with_derived_key_core_i(
    const uint8_t *base_key,
    size_t base_key_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *request_binding_digest,
    char out_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1]
) {
    if (!out_hex)
        return -1;
    if (!msg && msg_len != 0)
        return -1;

    uint8_t derived_key[CPRISK_ARMOR_HASH_SIZE];
    if (cprisk_derive_effective_signing_key_core_i(base_key,
                                                   base_key_len,
                                                   request_binding_digest,
                                                   derived_key) != 0) {
        return -1;
    }

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    /* Flip select key bytes under debugger — signature silently invalid.
     * Dual-detector (see evaluate_domain entry check). */
    // 调试器命中时翻转若干密钥字节：不崩溃、不提示，但签名必然验不过。
    if (cprisk_is_being_traced_redundant() || cprisk_is_being_traced()) {
        derived_key[0]  ^= 0xFFu;
        derived_key[7]  ^= 0xFFu;
        derived_key[15] ^= 0xFFu;
        derived_key[23] ^= 0xFFu;
    }
#endif

    const int rc = cprisk_mac_sha256_hex(derived_key,
                                          sizeof(derived_key),
                                          msg,
                                          msg_len,
                                          out_hex);
    cprisk_secure_zero(derived_key, sizeof(derived_key));
    return rc;
}

// 对外包装：用派生密钥对消息签名，不附带请求绑定。
int cprisk_sign_with_derived_key(
    const uint8_t *base_key,
    size_t base_key_len,
    const uint8_t *msg,
    size_t msg_len,
    char out_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1]
) {
    return cprisk_sign_with_derived_key_core_i(
        base_key,
        base_key_len,
        msg,
        msg_len,
        NULL,
        out_hex
    );
}

// 对外包装：签名时把请求绑定摘要折入密钥；摘要为 NULL 时拒绝。
int cprisk_sign_with_derived_key_and_request_binding_digest(
    const uint8_t *base_key,
    size_t base_key_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t request_binding_digest[32],
    char out_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1]
) {
    if (!request_binding_digest)
        return -1;
    return cprisk_sign_with_derived_key_core_i(
        base_key,
        base_key_len,
        msg,
        msg_len,
        request_binding_digest,
        out_hex
    );
}

/// 验证 CPRisk-MAC 十六进制签名：重新派生密钥并做常数时间比较。
/// - expected_hex 必须恰好 64 个十六进制字符；base_key/msg 规则同签名接口。
/// - 返回：0 匹配；-1 不匹配、长度错误或派生失败。
/// - 线程安全：可并发；本地计算，无全局状态。
/// - 平台：纯软件路径。
/// - 失败语义：任何异常都视为验签失败（fail-closed）。
int cprisk_verify_with_derived_key(
    const uint8_t *base_key,
    size_t base_key_len,
    const uint8_t *msg,
    size_t msg_len,
    const char *expected_hex
) {
    if (!expected_hex)
        return -1;

    // 长度必须精确为 64 个十六进制字符：多余字符会被当成不同签名直接拒绝。
    const size_t expected_len = cprisk_cstrnlen_i(
        expected_hex, CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1);
    if (expected_len != CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE)
        return -1;

    char computed_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1];
    memset(computed_hex, 0, sizeof(computed_hex));
    if (cprisk_sign_with_derived_key(base_key,
                                     base_key_len,
                                     msg,
                                     msg_len,
                                     computed_hex) != 0) {
        cprisk_secure_zero(computed_hex, sizeof(computed_hex));
        return -1;
    }

    // 常数时间比较，避免通过响应时间推断期望签名的前缀。
    const int rc = cprisk_ct_ascii_eq_i(
        computed_hex,
        expected_hex,
        CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE);
    cprisk_secure_zero(computed_hex, sizeof(computed_hex));
    return rc;
}

/// 带请求绑定摘要的验签：先按同一摘要重新派生密钥，再比较签名。
/// - 参数/返回/线程/平台/失败语义与 cprisk_verify_with_derived_key 相同；
///   request_binding_digest 为 NULL 时直接返回 -1。
int cprisk_verify_with_derived_key_and_request_binding_digest(
    const uint8_t *base_key,
    size_t base_key_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t request_binding_digest[32],
    const char *expected_hex
) {
    if (!expected_hex || !request_binding_digest)
        return -1;

    // 同样要求 64 字符定长，避免接受截断或带尾随字符的“近似签名”。
    const size_t expected_len = cprisk_cstrnlen_i(
        expected_hex, CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1);
    if (expected_len != CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE)
        return -1;

    char computed_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1];
    memset(computed_hex, 0, sizeof(computed_hex));
    if (cprisk_sign_with_derived_key_and_request_binding_digest(base_key,
                                                                base_key_len,
                                                                msg,
                                                                msg_len,
                                                                request_binding_digest,
                                                                computed_hex) != 0) {
        cprisk_secure_zero(computed_hex, sizeof(computed_hex));
        return -1;
    }

    const int rc = cprisk_ct_ascii_eq_i(
        computed_hex,
        expected_hex,
        CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE);
    cprisk_secure_zero(computed_hex, sizeof(computed_hex));
    return rc;
}
