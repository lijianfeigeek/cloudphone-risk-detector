/*
 * CRiskCore - Runtime string decryptor for cprisk-armor ABI v2.
 * Consumes the packed string table section using the shared layout defined in
 * include/cprisk_armor_abi.h. Verifies CPRisk-MAC-SHA256 authentication tag before
 * decryption. Side-effect: each decryption updates an integrity accumulator.
 */

/* NOTE (issue 20 — SHA-256-chained XOR keystream, NOT AEAD): the
 * per-entry keystream here is SHA-256(key || id || nonce) chained with
 * XOR. It provides NO authentication by itself (the CPRisk-MAC tag is
 * checked separately) and its security depends entirely on NONCE
 * UNIQUENESS: the same (key, nonce) must never encrypt two different
 * plaintexts, or the keystream is reused and plaintexts XOR together.
 * The producer must guarantee unique nonces; cprisk_data_loader.c
 * additionally refuses a (key, nonce) seen with a different ciphertext.
 * Migration path: replace the XOR keystream with an AEAD
 * (AES-GCM / ChaCha20-Poly1305) carrying the nonce + AAD in the tag. */

// CRiskCore 字符串表运行时解密器（cprisk-armor ABI v2）。
// 从 __DATA 的字符串表按 string_id 查找条目，先验 CPRisk-MAC-SHA256，
// 再用“每条独立密钥 + 多路径密钥流”异或解密到调用方缓冲区。
// 线程模型：初始化、解密、读取累加器、清理全部由 s_string_mutex 串行化。
// 平台：纯内存计算，所有平台可用；被调试时的字节扰动仅在 Apple 非模拟器启用。
// 失败语义：参数/布局/MAC 任一失败返回 -1，调用方缓冲区内容视为不可用。
#include "include/CRiskCore.h"

#include <stdatomic.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#ifdef __APPLE__
#include <TargetConditionals.h>
#endif
#include "include/cprisk_macho.h"
#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

// 摘要长度必须与 armor ABI 的 HASH_SIZE 一致，否则 MAC 与索引布局错位。
_Static_assert(CPRISK_SHA256_DIGEST_LENGTH == CPRISK_ARMOR_HASH_SIZE,
               "inline SHA256 digest size must match armor ABI");

/* ── state ─────────────────────────────────────────────────────────── */

// s_dec_key 为 32 字节根密钥（cleanup 时清零）；s_dec_ready 是原子就绪标志，
// 允许无锁快速判断；s_str_acc 汇总解密明文的哈希；s_dispatch_seed 决定密钥流路径选择。
// s_string_mutex 保护密钥生命周期与累加器。
static uint8_t  s_dec_key[CPRISK_ARMOR_KEY_SIZE];
static _Atomic int s_dec_ready;
static uint64_t s_str_acc;
static uint64_t s_dispatch_seed;
static pthread_mutex_t s_string_mutex = PTHREAD_MUTEX_INITIALIZER;
// 历史说明：旧实现把最近解密的明文缓存在固定 BSS 地址，形成可被内存转储
// 直接定位的明文 oracle；该缓存已移除，lazy 入口仅保留 ABI 兼容转发。
/*
 * The previous lazy-decrypt path kept a 512-byte plaintext buffer
 * (s_lazy_buf) at a stable BSS address. Per the red-team self-audit,
 * this buffer constituted a memory-dump oracle — `vmmap | grep __bss`
 * locates the address, and a single `readByteArray` exfiltrates the
 * most recently decrypted plaintext. The performance benefit was
 * unused (no Swift caller invoked the lazy path), so the cache state
 * has been removed entirely. `cprisk_decrypt_string_lazy` is retained
 * as an ABI-stable alias that delegates to `cprisk_decrypt_string`.
 */

/* ── internal ──────────────────────────────────────────────────────── */

// 64 位循环左移；k 归一到 [0,63] 以避免未定义行为。
static inline uint64_t cprisk_rotl64(uint64_t x, int k) {
    k &= 63;
    return k == 0 ? x : ((x << k) | (x >> (64 - k)));
}

// FNV-1a 单字节混合，用于把密钥/ID/nonce 折叠成路径选择种子。
static inline uint64_t cprisk_fnv_mix_byte(uint64_t hash, uint8_t byte) {
    hash ^= (uint64_t)byte;
    hash *= 0x00000100000001B3ULL;
    return hash;
}

// murmur3 风格的 64 位雪崩混合；结果 0 被替换为 1，避免全零种子。
static uint64_t cprisk_avalanche64(uint64_t value) {
    uint64_t v = value;
    v ^= v >> 33;
    v *= 0xFF51AFD7ED558CCDULL;
    v ^= v >> 33;
    v *= 0xC4CEB9FE1A85EC53ULL;
    v ^= v >> 33;
    return v == 0 ? 1 : v;
}

// 从根密钥派生路径选择种子：逐字节 FNV 后做雪崩，密钥变化会显著改变路径分布。
static uint64_t cprisk_derive_dispatch_seed(const uint8_t *key, size_t key_len) {
    uint64_t hash = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < key_len; i++) {
        hash = cprisk_fnv_mix_byte(hash, key[i]);
    }
    return cprisk_avalanche64(hash);
}

// 用 dispatch_seed、string_id 和 nonce 计算 0..3 的密钥流派生路径编号。
static uint32_t cprisk_select_keystream_variant(uint32_t sid,
                                                const uint8_t *nonce,
                                                size_t nonce_len,
                                                uint64_t dispatch_seed) {
    uint64_t hash = dispatch_seed == 0 ? 0xCBF29CE484222325ULL : dispatch_seed;
    // 以固定小端顺序混入 string_id，再混入 nonce。
    hash = cprisk_fnv_mix_byte(hash, (uint8_t)(sid));
    hash = cprisk_fnv_mix_byte(hash, (uint8_t)(sid >> 8));
    hash = cprisk_fnv_mix_byte(hash, (uint8_t)(sid >> 16));
    hash = cprisk_fnv_mix_byte(hash, (uint8_t)(sid >> 24));

    for (size_t i = 0; i < nonce_len; i++) {
        hash = cprisk_fnv_mix_byte(hash, nonce[i]);
    }

    return (uint32_t)(cprisk_avalanche64(hash) & 0x3u);
}

// 取当前映像的 Mach-O 头（通过函数地址反查，避免依赖 dyld）。
static const struct mach_header_64 *cprisk_own_hdr(void) {
    return cprisk_find_own_header((const void *)cprisk_own_hdr);
}

// 路径 A：seed = key || sid_le4 || nonce，首块 SHA256(seed)，
// 后续块 SHA256(前块 || counter_le4)，counter 从 0 递增。
// Swift 侧镜像必须生成相同字节序与计数器。
static void cprisk_keystream_path_a(const uint8_t *key, uint32_t sid,
                                    const uint8_t *nonce, size_t nonce_len,
                                    uint8_t *out, size_t len) {
    uint8_t seed[CPRISK_ARMOR_KEY_SIZE + 4 + CPRISK_ARMOR_NONCE_SIZE];
    // 种子按 key、sid、nonce 顺序拼接；nonce_len 为 0 时只哈希前 36 字节。
    size_t seed_len = CPRISK_ARMOR_KEY_SIZE + 4 + nonce_len;
    memcpy(seed, key, CPRISK_ARMOR_KEY_SIZE);
    seed[32] = (uint8_t)(sid);
    seed[33] = (uint8_t)(sid >> 8);
    seed[34] = (uint8_t)(sid >> 16);
    seed[35] = (uint8_t)(sid >> 24);
    if (nonce_len > 0) {
        memcpy(seed + 36, nonce, nonce_len);
    }

    uint8_t blk[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_sha256(seed, seed_len, blk);

    // 每 32 字节输出一块；需要下一块时把计数器拼在块尾再哈希。
    /* WB#5: counter-bound extension blocks so each 32-byte chunk is
     * distinguishable from others.  Swift mirror: sha256(block || ctr_le4). */
    uint32_t counter = 0;
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > CPRISK_SHA256_DIGEST_LENGTH) {
            chunk = CPRISK_SHA256_DIGEST_LENGTH;
        }
        memcpy(out + off, blk, chunk);
        off += chunk;
        if (off < len) {
            uint8_t round[CPRISK_SHA256_DIGEST_LENGTH + 4];
            memcpy(round, blk, CPRISK_SHA256_DIGEST_LENGTH);
            round[32] = (uint8_t)(counter      );
            round[33] = (uint8_t)(counter >>  8);
            round[34] = (uint8_t)(counter >> 16);
            round[35] = (uint8_t)(counter >> 24);
            cprisk_sha256(round, sizeof(round), blk);
            cprisk_secure_zero(round, sizeof(round));
            counter++;
        }
    }

    cprisk_secure_zero(seed, sizeof(seed));
    cprisk_secure_zero(blk, sizeof(blk));
}

// 路径 B：seed = nonce || sid_be4 || key（sid 大端），
// 后续块 SHA256(前块 || counter_le4 || nonce)，与路径 A 的输出互不相同。
static void cprisk_keystream_path_b(const uint8_t *key, uint32_t sid,
                                    const uint8_t *nonce, size_t nonce_len,
                                    uint8_t *out, size_t len) {
    uint8_t seed[CPRISK_ARMOR_NONCE_SIZE + 4 + CPRISK_ARMOR_KEY_SIZE];
    // 与路径 A 相比，nonce/key 顺序与 sid 字节序都不同，用于分散静态特征。
    size_t seed_len = nonce_len + 4 + CPRISK_ARMOR_KEY_SIZE;
    if (nonce_len > 0) {
        memcpy(seed, nonce, nonce_len);
    }
    seed[nonce_len + 0] = (uint8_t)(sid >> 24);
    seed[nonce_len + 1] = (uint8_t)(sid >> 16);
    seed[nonce_len + 2] = (uint8_t)(sid >> 8);
    seed[nonce_len + 3] = (uint8_t)(sid);
    memcpy(seed + nonce_len + 4, key, CPRISK_ARMOR_KEY_SIZE);

    uint8_t blk[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_sha256(seed, seed_len, blk);

    uint32_t counter = 0;
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > CPRISK_SHA256_DIGEST_LENGTH) {
            chunk = CPRISK_SHA256_DIGEST_LENGTH;
        }
        memcpy(out + off, blk, chunk);
        off += chunk;
        if (off < len) {
            uint8_t round[CPRISK_SHA256_DIGEST_LENGTH + 4 + CPRISK_ARMOR_NONCE_SIZE];
            memcpy(round, blk, CPRISK_SHA256_DIGEST_LENGTH);
            round[32] = (uint8_t)(counter);
            round[33] = (uint8_t)(counter >> 8);
            round[34] = (uint8_t)(counter >> 16);
            round[35] = (uint8_t)(counter >> 24);
            if (nonce_len > 0) {
                memcpy(round + 36, nonce, nonce_len);
            }
            cprisk_sha256(round, 36 + nonce_len, blk);
            cprisk_secure_zero(round, sizeof(round));
            counter++;
        }
    }

    cprisk_secure_zero(seed, sizeof(seed));
    cprisk_secure_zero(blk, sizeof(blk));
}

// 路径 C：以 CPRisk-MAC(key, sid_le4 || nonce || "CPRI") 作为首块，
// 后续块 SHA256(counter_be4 || 前块 || sid_le4)，counter 从 1 开始。
static void cprisk_keystream_path_c(const uint8_t *key, uint32_t sid,
                                    const uint8_t *nonce, size_t nonce_len,
                                    uint8_t *out, size_t len) {
    uint8_t seed_msg[4 + CPRISK_ARMOR_NONCE_SIZE + 4];
    size_t msg_len = 4 + nonce_len + 4;
    seed_msg[0] = (uint8_t)(sid);
    seed_msg[1] = (uint8_t)(sid >> 8);
    seed_msg[2] = (uint8_t)(sid >> 16);
    seed_msg[3] = (uint8_t)(sid >> 24);
    if (nonce_len > 0) {
        memcpy(seed_msg + 4, nonce, nonce_len);
    }
    seed_msg[4 + nonce_len + 0] = 0x43;
    // 尾部 0x43/0x50/0x52/0x49 即 ASCII "CPRI"，作为该路径的域分隔标签。
    seed_msg[4 + nonce_len + 1] = 0x50;
    seed_msg[4 + nonce_len + 2] = 0x52;
    seed_msg[4 + nonce_len + 3] = 0x49;

    uint8_t blk[CPRISK_SHA256_DIGEST_LENGTH];
    // 首块直接使用带密钥 MAC，而不是普通 SHA-256。
    cprisk_mac_sha256(key, CPRISK_ARMOR_KEY_SIZE, seed_msg, msg_len, blk);

    // 首块已用掉 counter=0 的语义，扩展块从 1 开始，避免与首块形式重合。
    uint32_t counter = 1;
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > CPRISK_SHA256_DIGEST_LENGTH) {
            chunk = CPRISK_SHA256_DIGEST_LENGTH;
        }
        memcpy(out + off, blk, chunk);
        off += chunk;
        if (off < len) {
            uint8_t round[4 + CPRISK_SHA256_DIGEST_LENGTH + 4];
            round[0] = (uint8_t)(counter >> 24);
            round[1] = (uint8_t)(counter >> 16);
            round[2] = (uint8_t)(counter >> 8);
            round[3] = (uint8_t)(counter);
            memcpy(round + 4, blk, CPRISK_SHA256_DIGEST_LENGTH);
            round[36] = (uint8_t)(sid);
            round[37] = (uint8_t)(sid >> 8);
            round[38] = (uint8_t)(sid >> 16);
            round[39] = (uint8_t)(sid >> 24);
            cprisk_sha256(round, sizeof(round), blk);
            cprisk_secure_zero(round, sizeof(round));
            counter++;
        }
    }

    cprisk_secure_zero(seed_msg, sizeof(seed_msg));
    cprisk_secure_zero(blk, sizeof(blk));
}

// 路径 D：key 每字节异或 0x5A，nonce 逆序拼接，sid 小端，
// 后续块用 key 轮转字节作为 lane 掩码，形式与 A/B/C 明显不同。
static void cprisk_keystream_path_d(const uint8_t *key, uint32_t sid,
                                    const uint8_t *nonce, size_t nonce_len,
                                    uint8_t *out, size_t len) {
    /*
     * Seed buffer is sized for at most CPRISK_ARMOR_NONCE_SIZE nonce bytes.
     * If a caller passes nonce_len > CPRISK_ARMOR_NONCE_SIZE the loop below
     * would write past the buffer. Audit pass flagged this as a stack
     * overflow vector if string-table parsing is ever fed adversarial data.
     * Hard-clamp at the contract boundary.
     */
    // 在契约边界硬性钳制 nonce_len，防止伪造字符串表把栈写越界。
    if (nonce_len > CPRISK_ARMOR_NONCE_SIZE) {
        nonce_len = CPRISK_ARMOR_NONCE_SIZE;
    }
    uint8_t seed[CPRISK_ARMOR_KEY_SIZE + 4 + CPRISK_ARMOR_NONCE_SIZE];
    // 先对密钥做常量异或，再逆序写入 nonce；逆序是路径 D 的区分特征。
    for (size_t i = 0; i < CPRISK_ARMOR_KEY_SIZE; i++) {
        seed[i] = key[i] ^ 0x5A;
    }
    seed[32] = (uint8_t)(sid);
    seed[33] = (uint8_t)(sid >> 8);
    seed[34] = (uint8_t)(sid >> 16);
    seed[35] = (uint8_t)(sid >> 24);
    for (size_t i = 0; i < nonce_len; i++) {
        seed[36 + i] = nonce[nonce_len - 1 - i];
    }

    uint8_t blk[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_sha256(seed, CPRISK_ARMOR_KEY_SIZE + 4 + nonce_len, blk);

    uint32_t counter = 0;
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > CPRISK_SHA256_DIGEST_LENGTH) {
            chunk = CPRISK_SHA256_DIGEST_LENGTH;
        }
        memcpy(out + off, blk, chunk);
        off += chunk;
        if (off < len) {
            // lane 从密钥按 counter 轮转取字节，使每块混合材料不同。
            uint8_t lane = key[counter % CPRISK_ARMOR_KEY_SIZE];
            uint8_t round[CPRISK_SHA256_DIGEST_LENGTH + 4];
            for (size_t i = 0; i < CPRISK_SHA256_DIGEST_LENGTH; i++) {
                round[i] = (uint8_t)(blk[i] ^ lane);
            }
            round[32] = (uint8_t)(counter);
            round[33] = (uint8_t)(counter >> 8);
            round[34] = (uint8_t)(counter >> 16);
            round[35] = (uint8_t)(counter >> 24);
            cprisk_sha256(round, sizeof(round), blk);
            cprisk_secure_zero(round, sizeof(round));
            counter++;
        }
    }

    cprisk_secure_zero(seed, sizeof(seed));
    cprisk_secure_zero(blk, sizeof(blk));
}

// 按 variant 选择具体密钥流实现；default 覆盖 3 及异常值，落到路径 D。
static void cprisk_keystream_dispatch_level2(uint32_t variant,
                                             const uint8_t *key, uint32_t sid,
                                             const uint8_t *nonce, size_t nonce_len,
                                             uint8_t *out, size_t len) {
    switch (variant) {
    case 0:
        cprisk_keystream_path_a(key, sid, nonce, nonce_len, out, len);
        break;
    case 1:
        cprisk_keystream_path_b(key, sid, nonce, nonce_len, out, len);
        break;
    case 2:
        cprisk_keystream_path_c(key, sid, nonce, nonce_len, out, len);
        break;
    default:
        cprisk_keystream_path_d(key, sid, nonce, nonce_len, out, len);
        break;
    }
}

// 一级分发：先算出 0..3 的 variant，再交给二级 switch。
// 这里的奇偶分支只改变调用形态，不改变 variant 值，用于打散调用图特征。
static void cprisk_keystream_dispatch_level1(const uint8_t *key, uint32_t sid,
                                             const uint8_t *nonce, size_t nonce_len,
                                             uint8_t *out, size_t len,
                                             uint64_t dispatch_seed) {
    uint32_t variant = cprisk_select_keystream_variant(sid, nonce, nonce_len, dispatch_seed);
    if ((variant & 1u) == 0u) {
        cprisk_keystream_dispatch_level2(variant, key, sid, nonce, nonce_len, out, len);
    } else {
        cprisk_keystream_dispatch_level2(variant ^ 0u, key, sid, nonce, nonce_len, out, len);
    }
}

// 密钥流入口：校验参数后按路径分发。
/// 参数：key/out 非空；nonce_len 必须 <= NONCE_SIZE；len==0 时直接返回（不写 out）。
/// 失败语义：参数违约时静默返回，调用方缓冲区保持调用前内容。
static void cprisk_keystream_distributed(const uint8_t *key, uint32_t sid,
                                         const uint8_t *nonce, size_t nonce_len,
                                         uint8_t *out, size_t len,
                                         uint64_t dispatch_seed) {
    if (!key || !out || nonce_len > CPRISK_ARMOR_NONCE_SIZE || len == 0) {
        return;
    }
    cprisk_keystream_dispatch_level1(key, sid, nonce, nonce_len, out, len, dispatch_seed);
}

/* ── per-string key derivation ─────────────────────────────────────── */

/// 派生单条字符串密钥：CPRisk-MAC(root_key, "cprisk.str.key.v1" || sid_le4 || nonce)。
/// - 域标签隔离本用途，避免与其他 MAC 用途复用同一密钥流。
/// - StringEncryptor.swift 必须使用完全相同的前缀与字节序。
/// - 中间 material 用后清零；out_key 由调用方提供。
static void cprisk_derive_per_string_key(
    uint32_t string_id,
    const uint8_t *nonce,
    uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]
) {
    /*
     * KDF material = "cprisk.str.key.v1" || sid_le4 || nonce
     * Domain label (WB#4) prevents key-confusion with other CPRisk-MAC uses of
     * the same root key. StringEncryptor.swift must use the same prefix.
     */
    static const uint8_t label[] = "cprisk.str.key.v1";
    const size_t label_len = sizeof(label) - 1u;
    uint8_t material[sizeof(label) - 1u + 4u + CPRISK_ARMOR_NONCE_SIZE];
    memcpy(material, label, label_len);
    material[label_len + 0] = (uint8_t)(string_id      );
    material[label_len + 1] = (uint8_t)(string_id >>  8);
    material[label_len + 2] = (uint8_t)(string_id >> 16);
    material[label_len + 3] = (uint8_t)(string_id >> 24);
    memcpy(material + label_len + 4u, nonce, CPRISK_ARMOR_NONCE_SIZE);

    cprisk_mac_sha256(s_dec_key, CPRISK_ARMOR_KEY_SIZE,
                       material, sizeof(material), out_key);
    cprisk_secure_zero(material, sizeof(material));
}

/* ── public API ────────────────────────────────────────────────────── */

/// 初始化字符串解密器：复制 32 字节根密钥、派生路径选择种子并置就绪标志。
/// - key 非空且 key_len == CPRISK_ARMOR_KEY_SIZE，否则返回 -1 且状态不变。
/// - 线程安全：持 s_string_mutex；可与解密并发，但初始化前解密会失败。
int cprisk_init_string_decryptor(const uint8_t *key, size_t key_len) {
    if (!key || key_len != CPRISK_ARMOR_KEY_SIZE)
        return -1;
    pthread_mutex_lock(&s_string_mutex);
    // 密钥与种子一起在锁内更新，避免解密路径看到半更新的状态。
    memcpy(s_dec_key, key, CPRISK_ARMOR_KEY_SIZE);
    s_dispatch_seed = cprisk_derive_dispatch_seed(key, key_len);
    atomic_store(&s_dec_ready, 1);
    s_str_acc = 0;
    pthread_mutex_unlock(&s_string_mutex);
    return 0;
}

/// 解析字符串表并解密一条字符串到调用方缓冲区（调用方必须持有 s_string_mutex）。
/// - string_id：索引中的逻辑 ID；buffer/buffer_size：输出缓冲区及容量（含 NUL）。
/// - 返回明文长度（不含 NUL）；-1 表示未初始化、未找到、布局非法或 MAC 失败。
/// - 成功时 buffer[dlen]='\0'，并更新完整性累加器。
/// - 失败语义：不写 buffer，调用方应视为不可用（fail-closed）。
static int cprisk_decrypt_string_locked_i(uint32_t string_id, char *buffer, size_t buffer_size) {
    // 未初始化或参数非法直接失败；buffer_size 必须能容纳至少 1 字节数据 + NUL。
    if (!atomic_load(&s_dec_ready) || !buffer || buffer_size == 0)
        return -1;

    // 每次调用重新定位映像与段：卸载/重装后旧指针不可复用。
    const struct mach_header_64 *hdr = cprisk_own_hdr();
    if (!hdr)
        return -1;

    unsigned long sec_sz = 0;
    // 字符串表位于 __DATA 的 strtab section。
    const uint8_t *sec = cprisk_find_section(
        hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_STRTAB, &sec_sz);
    // 至少要容纳一个表头，否则后续字段读取越界。
    if (!sec || sec_sz < sizeof(struct cprisk_armor_strtab_header))
        return -1;

    const struct cprisk_armor_strtab_header *th =
        (const struct cprisk_armor_strtab_header *)sec;
    // 魔数/版本不匹配拒绝，防止旧布局或伪造段。
    if (th->magic != CPRISK_ARMOR_STRTAB_MAGIC ||
        th->version != CPRISK_ARMOR_ABI_VERSION)
        return -1;

    uint32_t count = th->count;
    size_t idx_base  = sizeof(struct cprisk_armor_strtab_header);
    // 先做乘法溢出检查，再计算索引区结束位置。
    if (count > (UINT32_MAX /
                 (uint32_t)sizeof(struct cprisk_armor_strtab_index_entry)))
        return -1;
    size_t data_base =
        idx_base + (size_t)count * sizeof(struct cprisk_armor_strtab_index_entry);
    // data_base 是密文数据区起点；索引区必须完整落在 section 内。
    if (data_base > sec_sz)
        return -1;

    const struct cprisk_armor_strtab_index_entry *idx =
        (const struct cprisk_armor_strtab_index_entry *)(sec + idx_base);

    const struct cprisk_armor_strtab_index_entry *ent = NULL;
    // 线性查找 string_id；表由构建期生成，重复 ID 视为数据错误（取第一个）。
    for (uint32_t i = 0; i < count; i++) {
        if (idx[i].string_id == string_id) {
            ent = &idx[i];
            break;
        }
    }
    if (!ent)
        return -1;

    uint32_t dlen = ent->data_length;
    // dlen 必须非 0 且给 NUL 留出空间（dlen < buffer_size）。
    if (dlen == 0 || dlen >= buffer_size)
        return -1;
    // 返回值是 int；dlen 超过 INT_MAX 会让成功返回变成负数。
    /* Moved up from after the buffer write (issue 96): a dlen that does
     * not fit in int would make the trailing (int)dlen return negative.
     * (dlen is uint32_t, so a `dlen > UINT32_MAX` check would be dead.) */
    if (dlen > (uint32_t)INT_MAX)
        return -1;
    size_t data_block_sz = sec_sz - data_base;
    // 数据偏移相对密文区起点，所有边界都以 data_block_sz 为上限。
    size_t data_end = (size_t)ent->data_offset + (size_t)dlen;
    // 加法溢出与回绕检查：data_end 必须同时 >= offset 与 dlen。
    if (data_end < (size_t)dlen || data_end < (size_t)ent->data_offset)
        return -1;
    // offset/dlen/data_end 都必须落在 data_block_sz 内。
    if ((size_t)ent->data_offset >= data_block_sz ||
        (size_t)dlen > data_block_sz ||
        data_end > data_block_sz)
        return -1;

    const uint8_t *enc = sec + data_base + ent->data_offset;

    // MAC 覆盖规范编码；长度字段纳入 MAC 后，截断/扩展无法保持标签有效。
    /*
     * Verify CPRisk-MAC over the canonical encoding written by
     * StringEncryptor.swift:
     *   u32 string_id | u32 nonce_len | nonce[nonce_len] |
     *   u32 ct_len    | ciphertext[ct_len]
     * String_id binding prevents transposition of two encrypted strings;
     * length prefixes prevent truncation/extension that finds a matching
     * length pair against the previous `nonce || ciphertext` scope.
     */
    {
        const size_t mac_msg_len =
            4u + 4u + (size_t)CPRISK_ARMOR_NONCE_SIZE + 4u + (size_t)dlen;
        uint8_t *mac_msg = (uint8_t *)malloc(mac_msg_len);
        // 分配失败即失败返回，不写调用方缓冲区。
        if (!mac_msg)
            return -1;
        size_t mp = 0u;
        const uint32_t sid_le = ent->string_id;
        mac_msg[mp++] = (uint8_t)(sid_le      );
        mac_msg[mp++] = (uint8_t)(sid_le >>  8);
        mac_msg[mp++] = (uint8_t)(sid_le >> 16);
        mac_msg[mp++] = (uint8_t)(sid_le >> 24);
        mac_msg[mp++] = (uint8_t)(CPRISK_ARMOR_NONCE_SIZE      );
        mac_msg[mp++] = (uint8_t)(CPRISK_ARMOR_NONCE_SIZE >>  8);
        mac_msg[mp++] = (uint8_t)(CPRISK_ARMOR_NONCE_SIZE >> 16);
        mac_msg[mp++] = (uint8_t)(CPRISK_ARMOR_NONCE_SIZE >> 24);
        memcpy(mac_msg + mp, ent->nonce, CPRISK_ARMOR_NONCE_SIZE);
        mp += CPRISK_ARMOR_NONCE_SIZE;
        mac_msg[mp++] = (uint8_t)(dlen      );
        mac_msg[mp++] = (uint8_t)(dlen >>  8);
        mac_msg[mp++] = (uint8_t)(dlen >> 16);
        mac_msg[mp++] = (uint8_t)(dlen >> 24);
        memcpy(mac_msg + mp, enc, dlen);

        uint8_t computed_mac[CPRISK_ARMOR_HASH_SIZE];
        // 用根密钥（不是每条密钥）计算 MAC，与生产端一致。
        cprisk_mac_sha256(s_dec_key, CPRISK_ARMOR_KEY_SIZE,
                           mac_msg, mac_msg_len, computed_mac);
        cprisk_secure_zero(mac_msg, mac_msg_len);
        free(mac_msg);

        // 常量时间比较；失败立即返回 -1，不做任何解密。
        if (cprisk_mac_verify(ent->mac_tag, computed_mac,
                               CPRISK_ARMOR_HASH_SIZE) != 0) {
            cprisk_secure_zero(computed_mac, sizeof(computed_mac));
            return -1;
        }
        cprisk_secure_zero(computed_mac, sizeof(computed_mac));
    }

    // 密钥流缓冲与明文等长；先清零，避免后续异常路径残留。
    uint8_t *ks = NULL;
    ks = (uint8_t *)malloc(dlen);
    if (!ks)
        return -1;
    memset(ks, 0, dlen);
    uint8_t per_string_key[CPRISK_ARMOR_KEY_SIZE];
    // 每条字符串使用独立密钥，避免同一 nonce 下的密钥流被跨条目复用。
    cprisk_derive_per_string_key(string_id, ent->nonce, per_string_key);
    cprisk_keystream_distributed(per_string_key, string_id,
                                 ent->nonce, CPRISK_ARMOR_NONCE_SIZE, ks, dlen,
                                 s_dispatch_seed);
    cprisk_secure_zero(per_string_key, sizeof(per_string_key));

    for (uint32_t i = 0; i < dlen; i++)
        buffer[i] = (char)(enc[i] ^ ks[i]);
    // 异或后显式补 NUL，保证调用方拿到 C 字符串。
    buffer[dlen] = '\0';

    uint8_t dh[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_sha256((const uint8_t *)buffer, dlen, dh);
    uint64_t hv;
    memcpy(&hv, dh, sizeof(hv));
    // 明文哈希混入全局累加器，供上层跨调用比对完整性。
    s_str_acc ^= cprisk_rotl64(hv, string_id % 64);

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    // 被调试时翻转所有明文字节并毒化累加器：调用方拿到的是错误内容。
    /* Subtle byte-level corruption under debugger; fixed accumulator poison
       ensures downstream key derivation also silently fails. */
    /* Dual-detector (issue 33): sysctl-based + redundant; hooking one
     * traced detector alone must not disable the corruption. */
    if (cprisk_is_being_traced_redundant() || cprisk_is_being_traced()) {
        for (uint32_t pi = 0; pi < dlen; pi++)
            buffer[pi] ^= 0x01;
        s_str_acc = 0xDEADBEEFCAFEBABEULL;
    }
#endif

    // 密钥流属于敏感派生物，返回前清零并释放。
    cprisk_secure_zero(ks, dlen);
    free(ks);
    cprisk_secure_zero(dh, sizeof(dh));

    return (int)dlen;
}

/// 公开解密入口：加锁后调用 locked 实现。
/// - 参数/返回值语义同 cprisk_decrypt_string_locked_i。
/// - 线程安全：全局串行化，可并发调用（吞吐受锁限制）。
int cprisk_decrypt_string(uint32_t string_id, char *buffer, size_t buffer_size) {
    /* Serialize key lifetime and the integrity accumulator with init/cleanup. */
    pthread_mutex_lock(&s_string_mutex);
    const int result = cprisk_decrypt_string_locked_i(string_id, buffer, buffer_size);
    pthread_mutex_unlock(&s_string_mutex);
    return result;
}

// 读取完整性累加器；加锁保证不会读到更新中的 64 位值（32 位平台尤其重要）。
uint64_t cprisk_get_string_integrity_accumulator(void) {
    pthread_mutex_lock(&s_string_mutex);
    const uint64_t value = s_str_acc;
    pthread_mutex_unlock(&s_string_mutex);
    return value;
}

// 懒加载兼容别名：旧实现曾缓存最近明文，已按红队审计移除；
// 现在每次调用都走完整解密，明文只存在于调用方缓冲区。
/*
 * Lazy alias retained for ABI compatibility. The previous implementation
 * cached the most-recently-decrypted plaintext in a 512-byte BSS buffer,
 * exposing a memory-dump oracle at a stable address. Now this just
 * forwards to the full decrypt path: every call does the SHA256-keyed
 * keystream computation, plaintext lives only in the caller's buffer
 * for the duration of its scope, and no plaintext is retained in any
 * static segment of the runtime.
 */
int cprisk_decrypt_string_lazy(uint32_t string_id, char *buffer, size_t buffer_size) {
    return cprisk_decrypt_string(string_id, buffer, buffer_size);
}

// 历史清理入口：lazy 缓存已移除，保留空实现以维持 ABI/链接兼容。
void cprisk_string_lazy_scrub_all(void) {
    /* No-op: lazy cache was removed. Kept for ABI stability so existing
     * shutdown paths that call this symbol continue to link. */
}

/// 清理解密器：清零根密钥、路径种子与完整性累加器，并清除就绪标志。
/// - 线程安全：持 s_string_mutex；清理后再次解密会返回 -1，需重新 init。
/// - 无返回值；重复调用安全。
void cprisk_cleanup_string_decryptor(void) {
    pthread_mutex_lock(&s_string_mutex);
    // 先清密钥再清标志：避免其他线程在密钥已失效时仍看到 ready=1。
    cprisk_secure_zero(s_dec_key, sizeof(s_dec_key));
    atomic_store(&s_dec_ready, 0);
    /* Use cprisk_secure_zero (volatile + memset) for the integrity
     * accumulator and dispatch seed too — even though both are static
     * uint64s where a plain assignment is observable, the explicit
     * secure_zero matches the pattern used by the rest of the file and
     * documents that "this is sensitive material, scrub it" rather than
     * just "this is a value reset". */
    cprisk_secure_zero(&s_str_acc, sizeof(s_str_acc));
    cprisk_secure_zero(&s_dispatch_seed, sizeof(s_dispatch_seed));
    pthread_mutex_unlock(&s_string_mutex);
}

// DEBUG 专用：返回给定 nonce/seed 下会选择的密钥流路径（0..3）。
/// 非 DEBUG 构建固定返回 0；nonce 为 NULL 时返回 0。用于测试与生产端一致性。
uint32_t cprisk_test_select_string_decrypt_path(
    uint32_t string_id,
    const uint8_t nonce[CPRISK_ARMOR_NONCE_SIZE],
    uint64_t seed
) {
#if !defined(DEBUG) || !DEBUG
    /* Test hook: inert outside DEBUG builds (issue 18). */
    return 0;
#endif
    if (!nonce) {
        return 0;
    }
    return cprisk_select_keystream_variant(
        string_id,
        nonce,
        CPRISK_ARMOR_NONCE_SIZE,
        seed
    );
}
