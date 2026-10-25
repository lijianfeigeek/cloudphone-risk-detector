/*
 * cprisk_header_restore.c — cprisk-armor 的 Mach-O 头运行时解密。
 * 职责：读取 __DATA.__swift5_mhsav（nonce[8]|加密字段[24]|MAC[32]），验 MAC 后写回六个头字段。
 * 时机：constructor(120) 尽早执行以缩短明文头窗口，失败留给运行期重试。
 * 线程：pthread_once 固化首次结果；未成功时由互斥锁串行重试，成功后结果不可变。
 * 失败：无兜底密钥；MAC/WhiteBox 失败按头字段是否合理返回 1（无需恢复）或 -1，绝不写脏数据。
 * 平台：Apple Mach-O arm64；mprotect 优先 SVC 直调，失败回退 libc。
 */

#include "include/CRiskCore.h"

#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <pthread.h>
#include <time.h>
#include <mach-o/dyld.h>

#include "include/cprisk_macho.h"
#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

/* Mirrors cprisk_hdr_mprotect from cprisk_data_loader.c.
 * Uses direct syscall first, falls back to libc mprotect. */
// 页面权限切换：优先 SVC 直调（绕过 libc Hook），失败再回退 mprotect。
// 参数：addr/len/prot 同 mprotect。返回：0 成功，非 0 失败（errno 由底层提供）。
// 线程安全：只改本进程页权限，可并发；调用方负责页对齐。
static inline int cprisk_hdr_mprotect(void *addr, size_t len, int prot) {
    int direct_errno = 0;
    if (cprisk_mprotect_direct(addr, len, prot, &direct_errno) == 0) {
        return 0;
    }
    return mprotect(addr, len, prot);
}

// 旧版 HeaderEncryptor 写入 mach_header.reserved 的固定标记 "CPBH"；
// 新版本改为逐二进制伪装值，但运行期仍兼容旧标记以便平滑升级。
#define CPRISK_HBHDR_LEGACY_MAGIC 0x43504248u  /* "CPBH" */

// 伪装混合常量，必须与 Swift 侧 HeaderEncryptorPass.makeCamouflagedReserved 保持一致；
// 改动会让旧二进制无法识别 reserved，从而拒绝恢复。
#define CPRISK_HBHDR_CAMO_XOR 0xA5C31F27u

// 备份区固定 64 字节：nonce(8) + 加密字段(24) + CPRisk-MAC(32)。
// 头路径使用冻结的 8 字节 nonce，不能换成通用 16 字节，否则与生产者布局错位。
#define CPRISK_HBHDR_SECTION_SIZE 64
#define CPRISK_HBHDR_NONCE_SIZE 8
#define CPRISK_HBHDR_ENC_FIELDS_SIZE 24
// 加密字段布局（均为小端 UInt32）：magic、filetype、ncmds、sizeofcmds、flags、reserved。
/* encrypted fields layout (all little-endian UInt32):
 *   offset  0: magic (UInt32)
 *   offset  4: filetype (UInt32)
 *   offset  8: ncmds (UInt32)
 *   offset 12: sizeofcmds (UInt32)
 *   offset 16: flags (UInt32)
 *   offset 20: reserved (UInt32)
 */

// 用本函数自身的代码地址定位所属 Mach-O 头；返回只读指针，进程生命周期内有效。
static const struct mach_header_64 *cprisk_hdr_restore_own_hdr(void) {
    return cprisk_find_own_header((const void *)cprisk_hdr_restore_own_hdr);
}

// 小端读取 4 字节；ptr 为 NULL 时返回 0（而不是崩溃）。
static inline uint32_t cprisk_read_le32_i(const uint8_t *ptr) {
    if (!ptr)
        return 0u;
    return ((uint32_t)ptr[0]) |
           ((uint32_t)ptr[1] << 8) |
           ((uint32_t)ptr[2] << 16) |
           ((uint32_t)ptr[3] << 24);
}

// 32 位循环左移；shift 先对 32 取模，0 位移直接返回原值（避免 UB）。
static inline uint32_t cprisk_rotl32_i(uint32_t value, uint32_t shift) {
    shift &= 31u;
    if (shift == 0u)
        return value;
    return (value << shift) | (value >> (32u - shift));
}

/* Mirrors HeaderEncryptorPass.makeCamouflagedReserved(). */
// 计算 reserved 的伪装值：original ^ nonce[0..3] ^ rotl(nonce[4..7],7) ^ 常量。
// 参数：original_reserved 为真实值；nonce 为 8 字节，NULL 时原样返回。
// 返回：伪装值；若与真值或旧标记碰撞则再异或 0x01010101 破除碰撞。
// 线程安全：纯函数；不变量：Swift 侧必须使用完全相同的算法。
static uint32_t cprisk_hdr_camouflaged_reserved_i(
    uint32_t original_reserved,
    const uint8_t nonce[CPRISK_HBHDR_NONCE_SIZE]
) {
    if (!nonce)
        return original_reserved;
    const uint32_t n0 = cprisk_read_le32_i(nonce);
    const uint32_t n1 = cprisk_read_le32_i(nonce + 4);
    uint32_t camouflaged = original_reserved ^ n0 ^ cprisk_rotl32_i(n1, 7) ^ CPRISK_HBHDR_CAMO_XOR;
    // 碰撞破除：伪装值不能等于真值（否则攻击者可反推）或旧标记（会误走兼容分支）。
    if (camouflaged == original_reserved || camouflaged == CPRISK_HBHDR_LEGACY_MAGIC)
        camouflaged ^= 0x01010101u;
    return camouflaged;
}

static int cprisk_restore_macho_header_impl_i(void);

// 恢复状态机：
//   s_header_restore_once：保证首次尝试只执行一次；
//   s_header_restore_retry_mutex：串行化首次失败后的重试；
//   s_header_restore_result：-2=未初始化，>=0 为终态成功/无需恢复，-1 可重试。
static pthread_once_t s_header_restore_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t s_header_restore_retry_mutex = PTHREAD_MUTEX_INITIALIZER;
static int s_header_restore_result = -2; /* -2: uninitialized, >=0 terminal success/no-op */

// pthread_once 回调：执行一次实现并把结果固化到 s_header_restore_result。
static void cprisk_restore_macho_header_once_i(void) {
    s_header_restore_result = cprisk_restore_macho_header_impl_i();
}

// 头字段合理性检查：magic/ncmds/sizeofcmds 落在 Mach-O 合法范围。
// 返回：1 合理；0 不合理或 hdr 为 NULL。
// 用途：判断“未恢复但头本身仍可用”，从而区分“无需恢复”(1) 与“损坏”(-1)。
// 不变量：ncmds<=8192、sizeofcmds<=32MB，超出视为损坏，杜绝后续解析越界。
static int cprisk_header_fields_sane_i(const struct mach_header_64 *hdr) {
    if (!hdr)
        return 0;

    if (hdr->magic != MH_MAGIC_64)
        return 0;
    if (hdr->ncmds == 0u || hdr->ncmds > 8192u)
        return 0;
    if (hdr->sizeofcmds == 0u || hdr->sizeofcmds > (32u * 1024u * 1024u))
        return 0;
    return 1;
}

// FNV-1a 混合 kern.osrelease，得到与运行时 OS 版本相关的扰码值。
// 返回：混合值；sysctl 失败时返回固定常量 0xA24BAED5（保持确定性）。
// 线程安全：sysctl 只读，可并发；平台：仅 Apple。
static uint32_t cprisk_runtime_os_mix_i(void) {
    char osrelease[128];
    size_t len = sizeof(osrelease);
    int err = 0;
    if (cprisk_sysctlbyname_direct("kern.osrelease", osrelease, &len, NULL, 0, &err) != 0 || len == 0) {
        return 0xA24BAED5u;
    }
    uint32_t mix = 0x811C9DC5u;
    for (size_t i = 0; i < len && osrelease[i] != '\0'; i++) {
        mix ^= (uint32_t)(uint8_t)osrelease[i];
        mix *= 16777619u;
    }
    return mix;
}

// 用已加载 image 数量生成扰码；返回确定性 32 位值。
// 线程安全：_dyld_image_count 只读，可并发。
static uint32_t cprisk_runtime_dyld_mix_i(void) {
    const uint32_t image_count = _dyld_image_count();
    uint32_t mix = 0x9E3779B9u ^ image_count;
    mix ^= (image_count << 7u) | (image_count >> 3u);
    return mix;
}

// 定时扰动：按 stage/OS/image 数量生成 48..111 次空转，改变恢复路径的耗时形态。
// 参数：stage 为调用点编号（1=派生密钥前，2=改页权限前）。
// 返回：无；clock_gettime 失败时直接返回。
// 线程安全：只用栈变量；平台：CLOCK_MONOTONIC 在所有 Apple 平台可用。
// 用途：增加基于时间的 Hook/断点定位难度，不参与正确性。
static void cprisk_runtime_timing_hook_i(uint32_t stage) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return;
    }

    uint32_t mix = (uint32_t)now.tv_nsec;
    mix ^= cprisk_runtime_os_mix_i();
    mix ^= cprisk_runtime_dyld_mix_i();
    mix ^= stage * 0x45D9F3Bu;
    const uint32_t spin = 48u + (mix & 0x3Fu);
    volatile uint32_t sink = mix;
    for (uint32_t i = 0; i < spin; i++) {
        sink ^= (sink << 7u) + (i * 0x9E37u);
    }
    (void)sink;
}

/* Derive the header encryption key by evaluating build-stable WhiteBox
 * Domain 9 with an all-zero input, matching HeaderEncryptor.swift. */
// 用 WhiteBox 域 9 + 全零输入派生头密钥（与 Swift 构建期一致）。
// 参数：out_key 不可为 NULL，需 32 字节。
// 返回：0 成功；-1 参数非法或 WhiteBox 求值失败（失败时清零 out_key）。
// 线程安全：WhiteBox 求值按实现约定可重入；不缓存密钥，避免常驻内存。
// 失败语义：绝不回退弱密钥；调用方必须把失败视为不可恢复。
static int cprisk_derive_header_key(uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]) {
    if (!out_key)
        return -1;

    // 静态头密文无法依赖运行时绑定数据，因此种子必须全零且构建期稳定。
    uint8_t zero_seed[CPRISK_ARMOR_KEY_SIZE];
    memset(zero_seed, 0, CPRISK_ARMOR_KEY_SIZE);

    /* No fallback key derivation (issue 60/79): if the white-box
     * evaluation fails, header decryption HARD-FAILS. A deterministic
     * fallback key derived from runtime material would silently
     * substitute a weaker, always-available key path. */
    int rc = cprisk_whitebox_evaluate_domain(
        CPRISK_WHITEBOX_DOMAIN_HEADER_ENCRYPTION,
        zero_seed,
        out_key);
    if (rc != 0)
        cprisk_secure_zero(out_key, CPRISK_ARMOR_KEY_SIZE);

    /* zero out the stack copy of the seed */
    cprisk_secure_zero(zero_seed, sizeof(zero_seed));
    return rc;
}

/* Generate a keystream block: SHA256(key || keyID_le[4] || nonce).
 * Returns the first CPRISK_SHA256_DIGEST_LENGTH bytes of the keystream.
 * This mirrors the Swift makeKeystream() logic. The header path uses the
 * FROZEN 8-byte nonce (CPRISK_HBHDR_NONCE_SIZE), NOT the generic 16-byte
 * CPRISK_ARMOR_NONCE_SIZE: the 64-byte backup layout is nonce[8] |
 * encrypted[24] | tag[32], and the producer (HeaderEncryptor) seeds with
 * 8 nonce bytes. Using 16 here would read 8 ciphertext bytes into the
 * seed and never match the producer. */
// 生成密钥流块：SHA256(key || keyID_le4 || nonce[8])。
// 参数：key 32 字节；key_id 小端 4 字节；nonce 必须 8 字节（头路径冻结布局）；
//       out 由调用方提供；len 超过 32 会被截断到单块长度。
// 返回：无；调用方保证 out 至少 len 字节。
// 线程安全：纯函数，仅用栈缓冲并在结束时清零。
// 不变量：必须使用 8 字节 nonce，使用 16 字节会读到密文并导致永不匹配。
static void cprisk_hdr_keystream(
    const uint8_t key[CPRISK_ARMOR_KEY_SIZE],
    uint32_t key_id,
    const uint8_t nonce[CPRISK_HBHDR_NONCE_SIZE],
    uint8_t *out,
    size_t len
) {
    uint8_t seed[CPRISK_ARMOR_KEY_SIZE + 4 + CPRISK_HBHDR_NONCE_SIZE];
    size_t seed_len = CPRISK_ARMOR_KEY_SIZE + 4 + CPRISK_HBHDR_NONCE_SIZE;

    memcpy(seed, key, CPRISK_ARMOR_KEY_SIZE);
    seed[32] = (uint8_t)(key_id);
    seed[33] = (uint8_t)(key_id >> 8);
    seed[34] = (uint8_t)(key_id >> 16);
    seed[35] = (uint8_t)(key_id >> 24);
    memcpy(seed + 36, nonce, CPRISK_HBHDR_NONCE_SIZE);

    /* Produce the first block */
    uint8_t blk[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_sha256(seed, seed_len, blk);
    cprisk_secure_zero(seed, sizeof(seed));

    /* The keystream for our 24-byte payload fits in a single block */
    if (len > CPRISK_SHA256_DIGEST_LENGTH)
        len = CPRISK_SHA256_DIGEST_LENGTH;
    memcpy(out, blk, len);
    cprisk_secure_zero(blk, sizeof(blk));
}

/* Decrypt the 24-byte encrypted header fields in place using XOR keystream.
 * keyID is always 0 for the header backup section. */
// 用 XOR 密钥流原地解密 24 字节头字段。
// 参数：enc_fields 可写；enc_len 为 0 或 >256 时直接返回（防御异常长度）；
//       key/key_id/nonce 语义同 cprisk_hdr_keystream，头路径 key_id 恒为 0。
// 返回：无。
// 线程安全：纯函数；平台：无分支。
// 失败语义：无错误返回；调用方必须先完成 MAC 校验再调用。
static void cprisk_decrypt_header_fields(
    uint8_t *enc_fields,
    size_t enc_len,
    const uint8_t key[CPRISK_ARMOR_KEY_SIZE],
    uint32_t key_id,
    const uint8_t nonce[CPRISK_HBHDR_NONCE_SIZE]
) {
    if (enc_len == 0 || enc_len > 256)
        return;

    uint8_t ks[256];
    size_t to_decrypt = enc_len < sizeof(ks) ? enc_len : sizeof(ks);
    cprisk_hdr_keystream(key, key_id, nonce, ks, to_decrypt);

    for (size_t i = 0; i < to_decrypt; i++)
        enc_fields[i] ^= ks[i];

    cprisk_secure_zero(ks, sizeof(ks));
}

/* Verify CPRisk-MAC over the canonical encoding written by HeaderEncryptor.swift:
 *   u32 nonce_len | nonce[nonce_len] | u32 ct_len | ciphertext[ct_len]
 * with nonce_len = 8 (CPRISK_HBHDR_NONCE_SIZE, frozen 64-byte layout).
 * Returns 0 on match, -1 on mismatch. */
// 校验备份区 MAC，消息编码与 Swift HeaderEncryptor 完全一致：
//   u32 nonce_len(8) | nonce | u32 ct_len | ciphertext。
// 参数：key 32 字节；nonce 8 字节；enc_fields/enc_len 为密文字段；expected_tag 32 字节。
// 返回：0 = 匹配；-1 = 不匹配（常量时间比较）。
// 线程安全：纯函数，只读输入，可并发。
// 失败语义：任何长度/内容不符都返回 -1，调用方不得解密或写回头。
static int cprisk_verify_header_mac(
    const uint8_t key[CPRISK_ARMOR_KEY_SIZE],
    const uint8_t nonce[CPRISK_HBHDR_NONCE_SIZE],
    const uint8_t *enc_fields,
    size_t enc_len,
    const uint8_t expected_tag[CPRISK_ARMOR_HASH_SIZE]
) {
    uint8_t mac_msg[4u + CPRISK_HBHDR_NONCE_SIZE + 4u + CPRISK_HBHDR_ENC_FIELDS_SIZE];
    size_t mp = 0u;
    mac_msg[mp++] = (uint8_t)(CPRISK_HBHDR_NONCE_SIZE      );
    mac_msg[mp++] = (uint8_t)(CPRISK_HBHDR_NONCE_SIZE >>  8);
    mac_msg[mp++] = (uint8_t)(CPRISK_HBHDR_NONCE_SIZE >> 16);
    mac_msg[mp++] = (uint8_t)(CPRISK_HBHDR_NONCE_SIZE >> 24);
    memcpy(mac_msg + mp, nonce, CPRISK_HBHDR_NONCE_SIZE);
    mp += CPRISK_HBHDR_NONCE_SIZE;
    mac_msg[mp++] = (uint8_t)((uint32_t)enc_len      );
    mac_msg[mp++] = (uint8_t)((uint32_t)enc_len >>  8);
    mac_msg[mp++] = (uint8_t)((uint32_t)enc_len >> 16);
    mac_msg[mp++] = (uint8_t)((uint32_t)enc_len >> 24);
    memcpy(mac_msg + mp, enc_fields, enc_len);
    mp += enc_len;

    uint8_t computed_tag[CPRISK_ARMOR_HASH_SIZE];
    cprisk_mac_sha256(key, CPRISK_ARMOR_KEY_SIZE,
                       mac_msg, mp,
                       computed_tag);

    const int rc = cprisk_mac_verify(expected_tag, computed_tag,
                                      CPRISK_ARMOR_HASH_SIZE);
    cprisk_secure_zero(computed_tag, sizeof(computed_tag));
    return rc;
}

/* Write back the six little-endian UInt32 header fields into the Mach-O header.
 * The fields are stored in the same byte order as the original header. */
// 把解密后的 6 个小端 UInt32 字段写回 Mach-O 头。
// 参数：hdr 可写且已解除只读；fields 为 24 字节明文。两者为 NULL 时 no-op。
// 返回：无。
// 线程安全：仅写调用方持有的头页，调用方须保证无并发读取（由 once/mutex 保证）。
// 失败语义：无错误返回；写回前必须已完成 MAC 校验与页权限切换。
static void cprisk_write_header_fields(
    struct mach_header_64 *hdr,
    const uint8_t fields[CPRISK_HBHDR_ENC_FIELDS_SIZE]
) {
    if (!hdr || !fields)
        return;

    uint32_t magic;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;

    /* Read back little-endian fields */
    memcpy(&magic,      fields +  0, 4);
    memcpy(&filetype,   fields +  4, 4);
    memcpy(&ncmds,      fields +  8, 4);
    memcpy(&sizeofcmds, fields + 12, 4);
    memcpy(&flags,      fields + 16, 4);
    memcpy(&reserved,   fields + 20, 4);

    /* Write back to the header */
    hdr->magic      = magic;
    hdr->filetype   = filetype;
    hdr->ncmds      = ncmds;
    hdr->sizeofcmds = sizeofcmds;
    hdr->flags      = flags;
    hdr->reserved   = reserved;
}

/* Restore implementation.
 *
 * Returns  0 on successful restore.
 * Returns  1 when no restore is needed.
 * Returns -1 on verification / runtime failure.
 */
// 恢复实现：定位备份区 -> 派生密钥 -> 验 MAC -> 解密 -> 校验 reserved -> 写回。
// 返回：0 已恢复；1 无需恢复（未加固/已恢复/头仍合理）；-1 校验或运行期失败。
// 线程安全：由 once 或 retry 互斥锁串行调用；内部不持锁。
// 平台：Mach-O/dyld；mprotect 直调失败时回退 libc。
// 失败语义：任何验证失败都不写入头；只有 MAC 与 reserved 均通过才改内存。
static int cprisk_restore_macho_header_impl_i(void) {
    const struct mach_header_64 *hdr_const = cprisk_hdr_restore_own_hdr();
    if (!hdr_const)
        return -1;

    /* Find the backup section */
    unsigned long sec_sz = 0;
    const uint8_t *sec = cprisk_find_section(
        hdr_const,
        CPRISK_ARMOR_SEGMENT_DATA,
        CPRISK_ARMOR_SECTION_HEADER_BACKUP,
        &sec_sz);
    if (!sec)
        return 1; /* Binary is not header-armored. */
    // 备份区短于 64 字节：无法验证；若头本身合理则视为无需恢复，否则判损坏。
    if (sec_sz < CPRISK_HBHDR_SECTION_SIZE)
        return cprisk_header_fields_sane_i(hdr_const) ? 1 : -1;

    /* Parse the backup section layout */
    const uint8_t *nonce       = sec +  0;
    const uint8_t *enc_fields = sec +  CPRISK_HBHDR_NONCE_SIZE;
    const uint8_t *mac_tag   = sec +  CPRISK_HBHDR_NONCE_SIZE
                                    + CPRISK_HBHDR_ENC_FIELDS_SIZE;

    /* Derive the header key via WhiteBox Domain 9 */
    // 派生失败不提供兜底：头若合理则按“未加固/无需恢复”处理，否则判失败。
    uint8_t header_key[CPRISK_ARMOR_KEY_SIZE];
    cprisk_runtime_timing_hook_i(1u);
    if (cprisk_derive_header_key(header_key) != 0) {
        return cprisk_header_fields_sane_i(hdr_const) ? 1 : -1;
    }

    /* Verify CPRisk-MAC before writing any decrypted data */
    // 先验 MAC 再解密：解密后的字段绝不进入头部，除非 MAC 完全匹配。
    if (cprisk_verify_header_mac(header_key, nonce,
                                  enc_fields, CPRISK_HBHDR_ENC_FIELDS_SIZE,
                                  mac_tag) != 0) {
        cprisk_secure_zero(header_key, sizeof(header_key));
        return cprisk_header_fields_sane_i(hdr_const) ? 1 : -1;
    }

    /* Copy encrypted fields to a temporary buffer so we can decrypt in place */
    uint8_t fields_buf[CPRISK_HBHDR_ENC_FIELDS_SIZE];
    memcpy(fields_buf, enc_fields, CPRISK_HBHDR_ENC_FIELDS_SIZE);

    /* Decrypt via XOR keystream (keyID = 0 for header backup) */
    cprisk_decrypt_header_fields(fields_buf, CPRISK_HBHDR_ENC_FIELDS_SIZE,
                                 header_key, 0, nonce);
    cprisk_secure_zero(header_key, sizeof(header_key));

    uint32_t original_reserved = 0u;
    memcpy(&original_reserved, fields_buf + 20, sizeof(original_reserved));

    const uint32_t expected_camouflaged =
        cprisk_hdr_camouflaged_reserved_i(original_reserved, nonce);
    const uint32_t current_reserved = hdr_const->reserved;

    /* Idempotent fast-path:
     * if the original reserved is already present, restoration happened earlier.
     */
    // 幂等快速路径：reserved 已等于真值，说明本次或之前已恢复，直接返回 1。
    if (current_reserved == original_reserved) {
        cprisk_secure_zero(fields_buf, sizeof(fields_buf));
        return 1;
    }

    /* Legacy compatibility:
     * old builds use a fixed marker (CPBH) instead of per-binary camouflage.
     */
    // 既不是期望伪装值也不是旧标记 => 头部可能被篡改/替换，拒绝写回。
    if (current_reserved != expected_camouflaged &&
        current_reserved != CPRISK_HBHDR_LEGACY_MAGIC) {
        cprisk_secure_zero(fields_buf, sizeof(fields_buf));
        return -1;
    }

    /* Make the header page writable */
    uintptr_t page_start = (uintptr_t)hdr_const & ~(uintptr_t)0xFFF;
    cprisk_runtime_timing_hook_i(2u);
    if (cprisk_hdr_mprotect((void *)page_start, 0x1000,
                              PROT_READ | PROT_WRITE) != 0) {
        cprisk_secure_zero(fields_buf, sizeof(fields_buf));
        return -1;
    }

    /* Write decrypted fields back to the header */
    // 只改头所在的那一页（4KB），改完立即恢复只读，缩小可写窗口。
    struct mach_header_64 *hdr = (struct mach_header_64 *)hdr_const;
    cprisk_write_header_fields(hdr, fields_buf);
    cprisk_secure_zero(fields_buf, sizeof(fields_buf));

    /* Restore header page to read-only */
    // 恢复只读失败非致命：页可能已处于特殊状态，但写回已完成，不应回滚。
    if (cprisk_hdr_mprotect((void *)page_start, 0x1000, PROT_READ) != 0) {
        /* Non-fatal: the page might already be in a non-standard state */
    }

    return 0;
}

/* ── public API ─────────────────────────────────────────────────────────── */

/* Restore mach_header_64 fields from __DATA.__swift5_mhsav.
 *
 * Uses one eager attempt (pthread_once) for fast path + stable idempotence.
 * If the eager path fails (for example due to startup ordering), later calls
 * may retry under a mutex until a non-negative result is reached.
 *
 * Returns  0 on success.
 * Returns  1 when no restoration is needed or already restored.
 * Returns -1 on failure.
 */
// 公开入口：从 __DATA.__swift5_mhsav 恢复头字段。
// 参数：无。
// 返回：0 成功；1 无需恢复或已恢复；-1 失败（可重试）。
// 线程安全：pthread_once 快路径无锁读取终态；失败时由 retry 互斥锁串行重试。
// 平台：仅 Apple Mach-O；非加固二进制返回 1。
// 失败语义：失败不会缓存为终态，后续调用可重试；成功结果不可变。
int cprisk_restore_macho_header(void) {
    (void)pthread_once(&s_header_restore_once, cprisk_restore_macho_header_once_i);
    if (s_header_restore_result >= 0)
        return s_header_restore_result;

    if (pthread_mutex_lock(&s_header_restore_retry_mutex) != 0)
        return s_header_restore_result;

    /* Retry while the once path reports failure.
     * We intentionally do not overwrite s_header_restore_result here to keep
     * it immutable after pthread_once initialization. */
    const int out = (s_header_restore_result < 0)
        ? cprisk_restore_macho_header_impl_i()
        : s_header_restore_result;
    pthread_mutex_unlock(&s_header_restore_retry_mutex);
    return out;
}

/* Run as early as possible after image load to shrink plaintext header window.
 * Failures are non-fatal here; the normal runtime path can retry later.
 */
// constructor(120) 尽早触发恢复以缩短明文头窗口；失败留给运行期重试。
// 无参数、无返回值；与主线程早期初始化串行，不创建线程。
__attribute__((constructor(120)))
static void cprisk_restore_macho_header_ctor_i(void) {
    (void)cprisk_restore_macho_header();
}
