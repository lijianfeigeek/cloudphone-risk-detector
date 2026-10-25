/*
 * CRiskCore — __TEXT.__text page encryption consumer (cprisk-armor pass 12).
 * Fail-closed: invalid metadata disables the feature without crashing loops.
 * CPRisk-MAC / content-hash failure: integrity poison + trap-filled page (brk) to
 * avoid infinite EXC_BAD_ACCESS retries on the same faulting PC.
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

// CRiskCore __TEXT.__text 页级加密消费端（cprisk-armor pass 12）。
// 安装时把描述符中的 __text 页置为 PROT_NONE，首次取指触发 JIT 解密；
// 解密前校验 CPRisk-MAC 与 content_hash，失败则写入 BRK 毒页并标记 poison。
// 线程模型：安装/卸载/空闲巡检/JIT 解密全部由 s_text_mutex 串行化。
// 平台：仅 Apple arm64 真机启用；模拟器/tvOS/watchOS 走文件末尾的空实现分支。
// 失败语义：元数据非法则静默禁用；校验失败 fail-closed，避免同一 PC 无限重复异常。
#include "include/CRiskCore.h"
#include "include/cprisk_page_span.h"
#include "include/cprisk_armor_abi.h"
#include "include/cprisk_macho.h"
#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach-o/loader.h>
#include <mach/vm_prot.h>
#include <pthread.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int cprisk_armor_xor_region(uint8_t *target, size_t sz, uint32_t key_id,
                                   const uint8_t *nonce, size_t nonce_len,
                                   const uint8_t *key);
extern void cprisk_armor_derive_chained_key(const uint8_t *parent_key,
                                            uint32_t section_index,
                                            const uint8_t *nonce,
                                            size_t nonce_len,
                                            uint8_t depth,
                                            uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]);
/* Uses loader hidden mprotect: POSIX syscall + Mach vm_region/vm_protect cross-check (cprisk_data_loader.c). */
extern int cprisk_armor_vm_protect(void *addr, size_t len, int prot);

/* Domain 4 = ArmorABI.WhiteBox.Domain.loaderKey — non-hybrid PRF (domains 1–5 bypass
 * effectiveRoot binding). Must match TextSegmentEncryptor mask + XOR mix. */
// 白盒域号 4 对应 ArmorABI.WhiteBox.Domain.loaderKey；域号参与 PRF，
// 必须与 TextSegmentEncryptor 生产端完全一致，否则派生出的掩码不同。
#define CPRISK_TEXT_WB_MASK_DOMAIN 4u

// 构造白盒 PRF 输入：ASCII 标签 || section_index(小端) || 12 字节 nonce。
// 输出 32 字节；标签把本用途与其他白盒域输入隔离开。
static void cprisk_text_mask_prf_input_i(uint32_t section_index,
                                         const uint8_t nonce[CPRISK_ARMOR_NONCE_SIZE],
                                         uint8_t out32[32]) {
    static const uint8_t k_label[] = "CPRISK_WB_TEXT_MASK_v1";
    uint8_t msg[sizeof(k_label) - 1u + 4u + CPRISK_ARMOR_NONCE_SIZE];
    memcpy(msg, k_label, sizeof(k_label) - 1u);
    msg[sizeof(k_label) - 1u + 0] = (uint8_t)(section_index);
    msg[sizeof(k_label) - 1u + 1] = (uint8_t)(section_index >> 8);
    msg[sizeof(k_label) - 1u + 2] = (uint8_t)(section_index >> 16);
    msg[sizeof(k_label) - 1u + 3] = (uint8_t)(section_index >> 24);
    memcpy(msg + sizeof(k_label) - 1u + 4u, nonce, CPRISK_ARMOR_NONCE_SIZE);
    cprisk_sha256(msg, sizeof(msg), out32);
    cprisk_secure_zero(msg, sizeof(msg));
}

/* section_key = chained_key XOR WB_PRF(domain4, SHA256(label||section_index||nonce)).
 * Hooks on cprisk_armor_derive_chained_key alone no longer yield the XOR keystream key. */
// 派生 __TEXT 页的最终密钥：chained_key XOR WB_PRF(domain=4, label||sid||nonce)。
/// 返回值：0 成功；-1 表示白盒域求值失败（调用方需 poison 并中止本次解密）。
/// 所有中间材料（chain/wb_in/wb_out）用后清零，避免密钥残留在栈上。
static int cprisk_text_derive_section_key_i(const uint8_t parent_key[CPRISK_ARMOR_KEY_SIZE],
                                          uint32_t section_index,
                                          const uint8_t *nonce,
                                          size_t nonce_len,
                                          uint8_t depth,
                                          uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]) {
    uint8_t chain[CPRISK_ARMOR_KEY_SIZE];
    uint8_t wb_in[32];
    uint8_t wb_out[32];

    cprisk_armor_derive_chained_key(parent_key, section_index, nonce, nonce_len, depth,
                                    chain);
    cprisk_text_mask_prf_input_i(section_index, nonce, wb_in);
    if (cprisk_whitebox_evaluate_domain(CPRISK_TEXT_WB_MASK_DOMAIN, wb_in, wb_out) != 0) {
        cprisk_secure_zero(chain, sizeof(chain));
        cprisk_secure_zero(wb_in, sizeof(wb_in));
        cprisk_secure_zero(wb_out, sizeof(wb_out));
        return -1;
    }
    for (size_t i = 0; i < CPRISK_ARMOR_KEY_SIZE; i++)
        out_key[i] = (uint8_t)(chain[i] ^ wb_out[i]);
    cprisk_secure_zero(chain, sizeof(chain));
    cprisk_secure_zero(wb_in, sizeof(wb_in));
    cprisk_secure_zero(wb_out, sizeof(wb_out));
    return 0;
}

// 以下实现仅用于 Apple arm64 真机；模拟器、tvOS、watchOS 由文件末尾的空实现替代。
#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__)) && \
    (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR) && \
    (!defined(TARGET_OS_TV) || !TARGET_OS_TV) && \
    (!defined(TARGET_OS_WATCH) || !TARGET_OS_WATCH)

// 描述符 KDF 的固定页单位，取 4KB；不是 VM 实际页大小（真机可能是 16KB）。
#define CPRISK_TEXT_PAGE_SIZE 4096u /* Frozen descriptor KDF index unit, not VM granularity. */
// 蜜罐段大小 16KB：必须与 __cprisk_pad 的实际尺寸与对齐一致。
#define CPRISK_TEXT_HONEYPOT_SIZE 16384u
/* Idle re-encrypt eligibility: min time a page may stay decrypted before XOR+PROT_NONE.
 * Hot __TEXT can remain fault-free for long stretches; pair with watchdog idle cadence
 * (primary + secondary) so plaintext is not gated only on ~1 Hz ticks. */
// 最小明文驻留时间 32ms：到期后由 service_idle 重新加密并置 PROT_NONE。
/* Tighter idle re-encrypt: reduce plaintext dwell between JIT decrypt and service_idle sweep. */
#define CPRISK_TEXT_RECRYPT_NS 32000000ull
// 超过 4 倍驻留时间仍未回写视为异常，自检会上报 STALE。
#define CPRISK_TEXT_STALE_DECRYPT_NS (CPRISK_TEXT_RECRYPT_NS * 4ull)
// __TEXT 页的 KDF 域索引起点，避免与数据段 section_index 冲突。
#define CPRISK_TEXT_SECTION_INDEX_BASE 100000u

// 全局互斥：install/uninstall/service_idle/JIT 解密/自检全部串行化。
// s_timebase 由 s_tb_once 初始化，用于把 mach 绝对时间换算成纳秒。
static pthread_mutex_t s_text_mutex = PTHREAD_MUTEX_INITIALIZER;
static mach_timebase_info_data_t s_timebase;
static pthread_once_t s_tb_once = PTHREAD_ONCE_INIT;

// s_parent_key 是安装时复制的 32 字节根密钥；s_parent_ready 表示可用，
// 未 ready 时所有解密入口立即返回 0。
static uint8_t s_parent_key[CPRISK_ARMOR_KEY_SIZE];
static int s_parent_ready;

// 每个已安装条目的元数据副本；s_entry_count 是实际安装数。
// s_poison 标记“已写入 BRK 毒页”的条目，s_decrypted 标记当前是否明文可执行；
// s_decrypt_ticks 记录解密时刻（mach 时间），s_cipher_hashes 保存安装时的密文 SHA-256。
static struct cprisk_text_encrypt_entry *s_entries = NULL;
static uint32_t s_entry_count;
static uint8_t *s_poison = NULL;
static uint8_t *s_decrypted = NULL;
static uint64_t *s_decrypt_ticks = NULL;
static uint8_t *s_cipher_hashes = NULL;

// 蜜罐页状态：armed=1 时该页已被登记为诱饵并置 PROT_NONE；
// 一旦检测到权限漂移就重新填充随机内容。
static int s_text_honeypot_armed;
static void *s_text_honeypot_page;

// pthread_once 回调：只读取一次 mach 时间基准。
static void cprisk_text_timebase_once(void) {
    (void)mach_timebase_info(&s_timebase);
}

// 把 mach 绝对时间差换算为纳秒；denom 为 0 时返回 0（调用方按 0 处理）。
static uint64_t cprisk_text_ticks_to_ns(uint64_t delta_ticks) {
    (void)pthread_once(&s_tb_once, cprisk_text_timebase_once);
    if (s_timebase.denom == 0)
        return 0;
    uint64_t numer = (uint64_t)s_timebase.numer;
    uint64_t denom = (uint64_t)s_timebase.denom;
    return delta_ticks / denom * numer + (delta_ticks % denom) * numer / denom;
}

// 取当前映像的 Mach-O 头（通过函数地址反查，避免依赖 dyld）。
static const struct mach_header_64 *cprisk_text_own_hdr(void) {
    return cprisk_find_own_header((const void *)cprisk_text_own_hdr);
}

// 计算 target 起 sz 字节覆盖的完整页范围；返回非 0 表示失败。
static int cprisk_text_page_span(uint8_t *target, size_t sz, void **page_out, size_t *len_out) {
    return cprisk_system_page_span_i(target, sz, page_out, len_out);
}

/// 校验条目完全落在 __TEXT.__text 内：页对齐、地址范围、段可执行、nsects 不越界。
/// - 成功返回 0；任何布局/边界违约返回 -1（调用方 poison 并放弃安装）。
/// - 只读 Mach-O 头部，线程安全；不修改任何状态。
static int cprisk_text_validate_bounds(
    const struct mach_header_64 *hdr,
    const struct cprisk_text_encrypt_entry *ent
) {
    if (!hdr || !ent)
        return -1;
    const size_t native_page = cprisk_system_page_size_i();
    // 页对齐是后续 mprotect 的前提；0 长度或非对齐直接拒绝。
    if (!native_page || !ent->size || ent->vm_addr % native_page != 0u ||
        ent->size % native_page != 0u)
        return -1;

    // 头部命令区不能超过一页，否则游标运算可能跨越未映射内存。
    if (native_page < sizeof(*hdr) || hdr->sizeofcmds > native_page - sizeof(*hdr))
        return -1;
    const uint8_t *cursor = (const uint8_t *)(hdr + 1);
    const uint8_t *end = (const uint8_t *)hdr + sizeof(struct mach_header_64) + hdr->sizeofcmds;
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        const size_t remaining = (size_t)(end - cursor);
        if (remaining < sizeof(*lc) || lc->cmdsize < sizeof(*lc) || lc->cmdsize > remaining)
            return -1;
        if (lc->cmd == LC_SEGMENT_64) {
            if (lc->cmdsize < sizeof(struct segment_command_64))
                return -1;
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            // 只处理 __TEXT 段，其他段命令直接跳过。
            if (strncmp(seg->segname, "__TEXT", 16) != 0) {
                cursor += lc->cmdsize;
                continue;
            }
            // nsects 必须能完整放进本条 load command，防止读取越界。
            if (seg->nsects > (lc->cmdsize - sizeof(*seg)) / sizeof(struct section_64))
                return -1;
            const struct section_64 *sections =
                (const struct section_64 *)(cursor + sizeof(*seg));
            for (uint32_t s = 0; s < seg->nsects; s++) {
                const struct section_64 *sec = &sections[s];
                if (strncmp(sec->sectname, "__text", 16) != 0)
                    continue;
                // __text 必须位于可执行段；否则该描述符不是本工具链生成的。
                if ((seg->initprot & VM_PROT_EXECUTE) == 0)
                    return -1;
                uint64_t lo = sec->addr;
                if (sec->addr > UINT64_MAX - sec->size)
                    return -1;
                uint64_t hi = sec->addr + sec->size;
                uint64_t e0 = ent->vm_addr;
                uint64_t e1 = ent->vm_addr + ent->size;
                // 条目必须完整落在 section 内，且 e1>=e0 用于防无符号回绕。
                if (e0 >= lo && e1 <= hi && e1 >= e0)
                    return 0;
                return -1;
            }
        }
        cursor += lc->cmdsize;
    }
    return -1;
}

/// 校验 __DATA 中 __cprisk_text 描述符的魔数、ABI 版本、条目数与总长度。
/// - 成功时 *count_out 写条目数；失败返回 -1。
/// - 纯函数，不信任文件内任何长度值。
static int cprisk_text_parse_descriptor(
    const uint8_t *sec,
    unsigned long sec_sz,
    uint32_t *count_out
) {
    if (!sec || !count_out || sec_sz < sizeof(struct cprisk_text_encrypt_header))
        return -1;
    const struct cprisk_text_encrypt_header *h = (const struct cprisk_text_encrypt_header *)sec;
    // 魔数/版本不符说明布局不兼容或段被伪造，直接拒绝。
    if (h->magic != CPRISK_TEXT_ENCRYPT_MAGIC || h->version != CPRISK_TEXT_ENCRYPT_ABI_VERSION)
        return -1;
    // 条目数上限防止 count*sizeof(entry) 溢出与后续分配过大。
    if (h->count > CPRISK_MAX_ENTRY_COUNT)
        return -1;
    size_t need = sizeof(struct cprisk_text_encrypt_header) +
                  (size_t)h->count * sizeof(struct cprisk_text_encrypt_entry);
    if (need > (size_t)sec_sz)
        return -1;
    *count_out = h->count;
    return 0;
}

// 常量时间比较明文 SHA-256 与期望值；返回 0 匹配、-1 不匹配。中间哈希用后清零。
static int cprisk_text_plain_hash_ok(
    const uint8_t *ptr,
    size_t sz,
    const uint8_t *expect_content_hash
) {
    uint8_t plain_hash[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_sha256(ptr, sz, plain_hash);
    int bad = memcmp(plain_hash, expect_content_hash, CPRISK_ARMOR_HASH_SIZE) != 0;
    cprisk_secure_zero(plain_hash, sizeof(plain_hash));
    return bad ? -1 : 0;
}

// 返回第 entry_index 条的密文哈希槽；索引越界或未分配返回 NULL。
static uint8_t *cprisk_text_cipher_hash_slot_i(uint32_t entry_index) {
    if (s_cipher_hashes == NULL || entry_index >= s_entry_count) {
        return NULL;
    }
    return s_cipher_hashes + ((size_t)entry_index * CPRISK_ARMOR_HASH_SIZE);
}

// 安装时记录当前密文哈希：用于后续判断页面是否被外部改写。
static int cprisk_text_capture_cipher_hash_i(uint32_t entry_index, const uint8_t *ptr, size_t sz) {
    uint8_t *slot = cprisk_text_cipher_hash_slot_i(entry_index);
    if (slot == NULL || ptr == NULL || sz == 0u) {
        return -1;
    }
    cprisk_sha256(ptr, sz, slot);
    return 0;
}

/// 在“页暂时可读”的状态下校验密文哈希，随后无论结果如何都恢复 PROT_NONE。
/// 失败语义：恢复 PROT_NONE 失败会 poison 自检通道并返回 -1。
static int cprisk_text_cipher_hash_ok_locked_i(
    uint32_t entry_index,
    uint8_t *ptr,
    size_t sz,
    void *page,
    size_t span
) {
    uint8_t *expect_cipher_hash = cprisk_text_cipher_hash_slot_i(entry_index);
    if (expect_cipher_hash == NULL || ptr == NULL || sz == 0u || page == NULL || span == 0u) {
        return -1;
    }
    if (cprisk_armor_vm_protect(page, span, PROT_READ) != 0) {
        return -1;
    }
    const int rc = cprisk_text_plain_hash_ok(ptr, sz, expect_cipher_hash);
    if (cprisk_armor_vm_protect(page, span, PROT_NONE) != 0) {
        cprisk_integrity_poison_text_encrypt_lane();
        return -1;
    }
    return rc;
}

// 解除蜜罐：取消登记并把页恢复为可读可执行；未 armed 时为空操作。
static void cprisk_text_honeypot_disarm(void) {
    if (!s_text_honeypot_armed || !s_text_honeypot_page)
        return;
    cprisk_unregister_text_honeypot_page();
    (void)cprisk_armor_vm_protect(s_text_honeypot_page, CPRISK_TEXT_HONEYPOT_SIZE, PROT_READ | PROT_EXEC);
    s_text_honeypot_armed = 0;
    s_text_honeypot_page = NULL;
}

// 用 128 字节批量随机数填充整页：getentropy 失败时退化为 LCG，
// 保证即使熵源被 hook 也不会留下可识别的全零页特征。
/*
 * Replace the build-time zero pad with high-entropy bytes before PROT_NONE so
 * static "all-zero honeypot page" signatures and fixed vm_protect + size
 * heuristics are less reliable for Frida bypass scripts.
 */
static void cprisk_text_honeypot_fill_entropy_i(void *page) {
    uint8_t *p = (uint8_t *)page;
    uint8_t buf[128];
    int err = 0;
    size_t off = 0;
    // 混合页地址与单调时间作为 LCG 种子，避免不同进程生成相同填充。
    uint64_t mix = (uint64_t)(uintptr_t)page ^ (uint64_t)mach_absolute_time();
    while (off < CPRISK_TEXT_HONEYPOT_SIZE) {
        size_t n = CPRISK_TEXT_HONEYPOT_SIZE - off;
        if (n > sizeof(buf)) {
            n = sizeof(buf);
        }
        // 优先使用直接 syscall 获取熵；失败则用确定性 PRNG 兜底（不阻塞启动）。
        if (cprisk_getentropy_direct(buf, n, &err) != 0) {
            for (size_t i = 0; i < n; i++) {
                mix = mix * 6364136223846793005ULL + 1ULL;
                buf[i] = (uint8_t)(mix >> 56);
            }
        }
        memcpy(p + off, buf, n);
        cprisk_secure_zero(buf, sizeof(buf));
        off += n;
    }
}

/// 在 __cprisk_pad 上布设蜜罐页：先置 RW 填充随机字节，再置 PROT_NONE 并登记。
/// - 只有段存在、尺寸足够且按 16KB 对齐时才布设；任何一步失败都回滚为 RX。
/// - 调用方必须持有 s_text_mutex（安装/卸载路径）。
static void cprisk_text_honeypot_arm(const struct mach_header_64 *hdr) {
    cprisk_text_honeypot_disarm();
    if (!hdr)
        return;
    unsigned long psz = 0;
    // 蜜罐依托编译期预留的 __TEXT.__cprisk_pad 段，缺失时静默放弃。
    const uint8_t *p = cprisk_find_section(hdr, "__TEXT", "__cprisk_pad", &psz);
    if (!p || psz < CPRISK_TEXT_HONEYPOT_SIZE)
        return;
    // 必须整段按 HONEYPOT_SIZE 对齐，否则会误伤相邻代码页。
    if (((uintptr_t)p % CPRISK_TEXT_HONEYPOT_SIZE) != 0)
        return;
    void *page = (void *)(uintptr_t)p;
    // 先把页改成可写才能填充随机内容。
    if (cprisk_armor_vm_protect(page, CPRISK_TEXT_HONEYPOT_SIZE, PROT_READ | PROT_WRITE) != 0)
        return;
    cprisk_text_honeypot_fill_entropy_i(page);
    if (cprisk_armor_vm_protect(page, CPRISK_TEXT_HONEYPOT_SIZE, PROT_NONE) != 0) {
        (void)cprisk_armor_vm_protect(page, CPRISK_TEXT_HONEYPOT_SIZE, PROT_READ | PROT_EXEC);
        return;
    }
    // 登记失败时恢复 RX，避免留下不可访问的代码段。
    if (cprisk_register_text_honeypot_page(page, CPRISK_TEXT_HONEYPOT_SIZE) != 0) {
        (void)cprisk_armor_vm_protect(page, CPRISK_TEXT_HONEYPOT_SIZE, PROT_READ | PROT_EXEC);
        return;
    }
    s_text_honeypot_armed = 1;
    s_text_honeypot_page = page;
}

// 用 arm64 的 BRK 指令（0xD4200000）填满条目，尾部不足 4 字节补 0。
// 这样同一故障 PC 再次取指会稳定触发断点异常，而不是无限重复缺页。
static void cprisk_text_fill_poison_brk(uint8_t *ptr, size_t sz) {
    uint32_t brk0 = 0xD4200000u;
    size_t i = 0;
    for (; i + 4 <= sz; i += 4) {
        memcpy(ptr + i, &brk0, sizeof(brk0));
    }
    for (; i < sz; i++)
        ptr[i] = 0;
}

// 把条目内容替换为 BRK 毒页并恢复为 RX；任一步 mprotect 失败都 poison 自检通道。
/// 调用方必须持有 s_text_mutex；本函数会自行把页设为可写。
static void cprisk_text_poison_entry(
    uint8_t *ptr,
    size_t sz,
    void *page,
    size_t span
) {
    if (cprisk_armor_vm_protect(page, span, PROT_READ | PROT_WRITE) != 0) {
        cprisk_integrity_poison_text_encrypt_lane();
        return;
    }
    cprisk_text_fill_poison_brk(ptr, sz);
    if (cprisk_armor_vm_protect(page, span, PROT_READ | PROT_EXEC) != 0)
        cprisk_integrity_poison_text_encrypt_lane();
}

/// 通过 vm_region_64 查询 page 所在区域的实际保护位。
/// - 返回 0 时 *out_prot 为 PROT_* 掩码；查询失败或参数为空返回 -1。
/// - 查询得到的 object_name 必须 deallocate，避免 Mach port 泄漏。
static int cprisk_text_query_page_protection_i(void *page, int *out_prot) {
    if (!page || !out_prot) {
        return -1;
    }
    *out_prot = 0;
    vm_address_t region_addr = (vm_address_t)(uintptr_t)page;
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

// 计算页状态掩码：已解密条目上出现写权限 -> bit0，缺失 RX -> bit1；
// 未解密条目仍可读/写/执行 -> bit2。非 0 即说明保护被外部改动。
static uint32_t cprisk_text_page_state_mask_i(uint32_t entry_index, void *page) {
    int prot = 0;
    if (cprisk_text_query_page_protection_i(page, &prot) != 0) {
        return 0u;
    }
    if (entry_index >= s_entry_count) {
        return 0u;
    }
    if (s_decrypted[entry_index]) {
        uint32_t mask = 0u;
        if ((prot & PROT_WRITE) != 0) {
            mask |= 1u << 0;
        }
        if ((prot & (PROT_READ | PROT_EXEC)) != (PROT_READ | PROT_EXEC)) {
            mask |= 1u << 1;
        }
        return mask;
    }
    return ((prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) != 0) ? (1u << 2) : 0u;
}

/// 空闲巡检：发现保护漂移的页立即毒化；已解密页超过驻留时间则重新加密。
/// - 调用方必须持有 s_text_mutex。
/// - 重新加密前先校验明文哈希，失败则毒化该条目（fail-closed）。
/// - 最后检查蜜罐页是否被改回可访问。
static void cprisk_text_maybe_reencrypt_idle(uint64_t now_ticks) {
    if (!s_entries || !s_decrypted || !s_decrypt_ticks || !s_poison)
        return;
    const struct mach_header_64 *hdr = cprisk_text_own_hdr();
    if (!hdr)
        return;
    intptr_t slide = cprisk_compute_slide(hdr);

    for (uint32_t i = 0; i < s_entry_count; i++) {
        if (s_poison[i])
            continue;
        const struct cprisk_text_encrypt_entry *ent = &s_entries[i];
        uint8_t *ptr = (uint8_t *)((uintptr_t)ent->vm_addr + (uintptr_t)slide);
        void *page = NULL;
        size_t span = 0;
        if (cprisk_text_page_span(ptr, (size_t)ent->size, &page, &span) != 0)
            continue;

        const uint32_t state_mask = cprisk_text_page_state_mask_i(i, page);
        // 先检测权限漂移：被 hook 的 mprotect/vm_protect 会让已解密页重新可写或丢失 RX。
        if (state_mask != 0u) {
            // 漂移说明运行时被篡改：直接毒化并永久标记，后续不再尝试解密。
            cprisk_text_poison_entry(ptr, (size_t)ent->size, page, span);
            s_poison[i] = 1;
            s_decrypted[i] = 0;
            cprisk_integrity_poison_text_encrypt_lane();
            continue;
        }

        if (!s_decrypted[i]) {
            continue;
        }
        uint64_t dt = now_ticks - s_decrypt_ticks[i];
        // 未到最小驻留时间的页继续保留明文，避免频繁缺页拖慢热点代码。
        if (cprisk_text_ticks_to_ns(dt) < CPRISK_TEXT_RECRYPT_NS)
            continue;

        unsigned long text_sz = 0;
        // KDF 的 section_index 以 __text 基址和 4KB 页号计算，必须与生产端一致。
        const uint8_t *text_base = cprisk_find_section(hdr, "__TEXT", "__text", &text_sz);
        if (!text_base || text_sz < ent->size)
            continue;
        uintptr_t text_lo = (uintptr_t)text_base;
        if ((uintptr_t)ptr < text_lo)
            continue;
        uint32_t page_idx = (uint32_t)(((uintptr_t)ptr - text_lo) / CPRISK_TEXT_PAGE_SIZE);
        uint32_t section_index = CPRISK_TEXT_SECTION_INDEX_BASE + page_idx;

        uint8_t section_key[CPRISK_ARMOR_KEY_SIZE];
        // 重新加密使用与解密相同的派生链；失败则 poison，不冒险写页。
        if (cprisk_text_derive_section_key_i(
                s_parent_key,
                section_index,
                ent->nonce,
                CPRISK_ARMOR_NONCE_SIZE,
                1,
                section_key) != 0) {
            cprisk_integrity_poison_text_encrypt_lane();
            continue;
        }

        if (cprisk_armor_vm_protect(page, span, PROT_READ | PROT_WRITE) != 0) {
            cprisk_secure_zero(section_key, sizeof(section_key));
            cprisk_integrity_poison_text_encrypt_lane();
            continue;
        }
        // 只有当前内容确实等于明文哈希才允许异或回密文，防止把错误内容加密。
        if (cprisk_text_plain_hash_ok(ptr, (size_t)ent->size, ent->content_hash) != 0) {
            cprisk_secure_zero(section_key, sizeof(section_key));
            cprisk_text_poison_entry(ptr, (size_t)ent->size, page, span);
            s_poison[i] = 1;
            cprisk_integrity_poison_text_encrypt_lane();
            continue;
        }
        (void)cprisk_armor_xor_region(
            ptr,
            (size_t)ent->size,
            ent->key_id,
            ent->nonce,
            CPRISK_ARMOR_NONCE_SIZE,
            section_key);
        cprisk_secure_zero(section_key, sizeof(section_key));
        // 回写后必须与安装时捕获的密文哈希一致，否则说明密钥/内容不匹配。
        if (cprisk_text_plain_hash_ok(
                ptr,
                (size_t)ent->size,
                cprisk_text_cipher_hash_slot_i(i)) != 0) {
            cprisk_text_poison_entry(ptr, (size_t)ent->size, page, span);
            s_poison[i] = 1;
            s_decrypted[i] = 0;
            cprisk_integrity_poison_text_encrypt_lane();
            continue;
        }
        // 重新置为不可访问，等待下一次缺页触发按需解密。
        if (cprisk_armor_vm_protect(page, span, PROT_NONE) != 0)
            cprisk_integrity_poison_text_encrypt_lane();
        s_decrypted[i] = 0;
    }

    // 蜜罐页若被改回可访问说明有人绕过保护，重新布设并 poison。
    if (s_text_honeypot_armed && s_text_honeypot_page != NULL) {
        int prot = 0;
        if (cprisk_text_query_page_protection_i(s_text_honeypot_page, &prot) == 0 &&
            (prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) != 0) {
            cprisk_integrity_poison_text_encrypt_lane();
            cprisk_text_honeypot_arm(hdr);
        }
    }
}

/// 查询 region 起 len 字节所在 VM 区域的保护位（用于自检）。
/// - 成功返回 0 并写 *prot_out；region/len/prot_out 非法或 vm_region 失败返回 -1。
static int cprisk_text_query_vm_protection_i(void *region, size_t len, vm_prot_t *prot_out) {
    void *page = NULL;
    size_t span = 0u;
    vm_address_t addr = 0;
    vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;
    kern_return_t kr;

    if (region == NULL || len == 0u || prot_out == NULL) {
        return -1;
    }
    // 先求出覆盖 region 的页起点，再查询该页所在区域。
    if (cprisk_text_page_span((uint8_t *)region, len, &page, &span) != 0 || span == 0u) {
        return -1;
    }

    addr = (vm_address_t)(uintptr_t)page;
    memset(&info, 0, sizeof(info));
    kr = vm_region_64(
        mach_task_self(),
        &addr,
        &region_size,
        VM_REGION_BASIC_INFO_64,
        (vm_region_info_t)&info,
        &count,
        &object_name);
    if (object_name != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), object_name);
    }
    // vm_region 可能返回更早的映射起点；起点晚于 page 说明查询结果不可用。
    if (kr != KERN_SUCCESS || addr > (vm_address_t)(uintptr_t)page) {
        return -1;
    }
    *prot_out = info.protection;
    return 0;
}

/// 自检并汇总漂移标志：已解密页应保持 RX 且内容等于明文哈希；
/// 未解密页应保持不可访问且密文哈希不变；超时未回写记为 STALE。
/// - 返回 CPRISK_TEXT_ENCRYPT_SELF_CHECK_FLAG_* 位掩码，0 表示健康。
/// - 调用方必须持有 s_text_mutex；非 0 结果会由上层 poison 通道。
static uint32_t cprisk_text_encrypt_self_check_locked_i(uint64_t now_ticks) {
    uint32_t flags = CPRISK_TEXT_ENCRYPT_SELF_CHECK_FLAG_NONE;
    if (!s_entries || !s_decrypted || !s_decrypt_ticks || s_entry_count == 0u) {
        return flags;
    }

    const struct mach_header_64 *hdr = cprisk_text_own_hdr();
    if (!hdr) {
        return flags;
    }
    intptr_t slide = cprisk_compute_slide(hdr);

    for (uint32_t i = 0u; i < s_entry_count; i++) {
        const struct cprisk_text_encrypt_entry *ent = &s_entries[i];
        uint8_t *ptr = (uint8_t *)((uintptr_t)ent->vm_addr + (uintptr_t)slide);
        vm_prot_t prot = 0;
        if (cprisk_text_query_vm_protection_i(ptr, (size_t)ent->size, &prot) != 0) {
            continue;
        }

        if (s_decrypted[i] != 0u) {
            // 已解密条目：保护位必须是 R+X 且不可写。
            const uint64_t dt = now_ticks >= s_decrypt_ticks[i] ? (now_ticks - s_decrypt_ticks[i]) : 0u;
            const uint64_t dwell_ns = cprisk_text_ticks_to_ns(dt);
            const int rx_ok = ((prot & VM_PROT_READ) != 0) &&
                              ((prot & VM_PROT_EXECUTE) != 0) &&
                              ((prot & VM_PROT_WRITE) == 0);
            if (!rx_ok) {
                flags |= CPRISK_TEXT_ENCRYPT_SELF_CHECK_FLAG_DECRYPTED_PROTECTION_DRIFT;
            }
            if (cprisk_text_plain_hash_ok(ptr, (size_t)ent->size, ent->content_hash) != 0) {
                flags |= CPRISK_TEXT_ENCRYPT_SELF_CHECK_FLAG_DECRYPTED_CONTENT_DRIFT;
            }
            // 超过 4 倍驻留时间仍是明文，说明空闲巡检没有生效。
            if (dwell_ns > CPRISK_TEXT_STALE_DECRYPT_NS) {
                flags |= CPRISK_TEXT_ENCRYPT_SELF_CHECK_FLAG_DECRYPTED_STALE;
            }
        } else {
            // 未解密条目：正常情况下应完全不可访问。
            if ((prot & (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)) != 0) {
                flags |= CPRISK_TEXT_ENCRYPT_SELF_CHECK_FLAG_ENCRYPTED_PROTECTION_DRIFT;
            } else {
                void *page = NULL;
                size_t span = 0u;
                // 不可访问状态下临时改为可读校验密文哈希，校验后恢复 PROT_NONE。
                if (cprisk_text_page_span(ptr, (size_t)ent->size, &page, &span) == 0 &&
                    cprisk_text_cipher_hash_ok_locked_i(i, ptr, (size_t)ent->size, page, span) != 0) {
                    flags |= CPRISK_TEXT_ENCRYPT_SELF_CHECK_FLAG_ENCRYPTED_CONTENT_DRIFT;
                }
            }
        }
    }

    // 蜜罐页应始终不可访问；可读/可写/可执行都是漂移。
    if (s_text_honeypot_armed && s_text_honeypot_page != NULL) {
        vm_prot_t honeypot_prot = 0;
        if (cprisk_text_query_vm_protection_i(s_text_honeypot_page, CPRISK_TEXT_HONEYPOT_SIZE, &honeypot_prot) == 0) {
            if ((honeypot_prot & (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)) != 0) {
                flags |= CPRISK_TEXT_ENCRYPT_SELF_CHECK_FLAG_HONEYPOT_PROTECTION_DRIFT;
            }
        }
    }

    return flags;
}

/// 释放所有条目：对仍解密的页校验明文哈希后异或回密文并恢复 RX，
/// 然后释放数组、清零根密钥与密文哈希。调用方必须持有 s_text_mutex。
/// 这是 uninstall 与重新 install 的公共清理路径。
static void cprisk_text_encrypt_release_locked(void) {
    cprisk_text_honeypot_disarm();

    if (!s_parent_ready)
        return;

    const struct mach_header_64 *hdr = cprisk_text_own_hdr();
    intptr_t slide = hdr ? cprisk_compute_slide(hdr) : 0;

    if (hdr && s_entries && s_entry_count > 0 && s_decrypted && s_poison) {
        for (uint32_t i = 0; i < s_entry_count; i++) {
            // 只处理“已解密且未毒化”的条目；毒化页保持 BRK，不再改回。
            if (s_poison[i])
                continue;
            if (!s_decrypted[i])
                continue;
            const struct cprisk_text_encrypt_entry *ent = &s_entries[i];
            uint8_t *ptr = (uint8_t *)((uintptr_t)ent->vm_addr + (uintptr_t)slide);
            void *page = NULL;
            size_t span = 0;
            if (cprisk_text_page_span(ptr, (size_t)ent->size, &page, &span) != 0)
                continue;

            unsigned long text_sz = 0;
            // 与 JIT 解密一致，用 __text 基址 + 4KB 页号推导 section_index。
            const uint8_t *text_base = cprisk_find_section(hdr, "__TEXT", "__text", &text_sz);
            uint32_t page_idx = 0;
            if (text_base && (uintptr_t)ptr >= (uintptr_t)text_base)
                page_idx = (uint32_t)(((uintptr_t)ptr - (uintptr_t)text_base) / CPRISK_TEXT_PAGE_SIZE);
            uint32_t section_index = CPRISK_TEXT_SECTION_INDEX_BASE + page_idx;

            uint8_t section_key[CPRISK_ARMOR_KEY_SIZE];
            // 派生失败时不写页，只 poison 并跳过该条目。
            if (cprisk_text_derive_section_key_i(
                    s_parent_key,
                    section_index,
                    ent->nonce,
                    CPRISK_ARMOR_NONCE_SIZE,
                    1,
                    section_key) != 0) {
                cprisk_integrity_poison_text_encrypt_lane();
                continue;
            }

            // 无法取得写权限时直接把页恢复为 RX（保持现状），避免锁死。
            if (cprisk_armor_vm_protect(page, span, PROT_READ | PROT_WRITE) == 0) {
                // 只有确认当前是正确明文才加密，防止把已损坏内容固化成密文。
                if (cprisk_text_plain_hash_ok(ptr, (size_t)ent->size, ent->content_hash) != 0) {
                    cprisk_text_poison_entry(ptr, (size_t)ent->size, page, span);
                    s_poison[i] = 1;
                    cprisk_integrity_poison_text_encrypt_lane();
                } else {
                    (void)cprisk_armor_xor_region(
                        ptr,
                        (size_t)ent->size,
                        ent->key_id,
                        ent->nonce,
                        CPRISK_ARMOR_NONCE_SIZE,
                        section_key);
                    // 异或回密文后恢复 R+X。
                    (void)cprisk_armor_vm_protect(page, span, PROT_READ | PROT_EXEC);
                }
            } else {
                (void)cprisk_armor_vm_protect(page, span, PROT_READ | PROT_EXEC);
            }
            cprisk_secure_zero(section_key, sizeof(section_key));
        }
    }

    free(s_entries);
    free(s_poison);
    free(s_decrypted);
    free(s_decrypt_ticks);
    if (s_cipher_hashes != NULL) {
        // 密文哈希是完整性基准，释放前清零。
        cprisk_secure_zero(s_cipher_hashes, (size_t)s_entry_count * CPRISK_ARMOR_HASH_SIZE);
    }
    free(s_cipher_hashes);
    s_entries = NULL;
    s_poison = NULL;
    s_decrypted = NULL;
    s_decrypt_ticks = NULL;
    s_cipher_hashes = NULL;
    s_entry_count = 0;
    // 根密钥清零后，残留条目即使被访问也无法再派生正确密钥。
    cprisk_secure_zero(s_parent_key, sizeof(s_parent_key));
    s_parent_ready = 0;
}

/// 安装 __TEXT 页加密：解析 __DATA.__cprisk_text 描述符，校验所有条目后
/// 记录密文哈希并逐页置 PROT_NONE，最后布设蜜罐页。
/// - loader_key 为 32 字节根密钥；为 NULL 时仅执行清理。
/// - 重复调用先卸载旧状态再重新安装；失败时静默禁用（s_parent_ready=0）。
/// - 线程安全：全程持有 s_text_mutex。
/// - 失败语义：任一布局/边界违约都 poison 通道并放弃安装，绝不部分启用。
void cprisk_text_encrypt_install(const uint8_t loader_key[CPRISK_ARMOR_KEY_SIZE]) {
    pthread_mutex_lock(&s_text_mutex);
    // 先清理上一次安装的状态，保证 install 可重复调用。
    cprisk_text_encrypt_release_locked();

    if (!loader_key) {
        // 空密钥表示只卸载不安装。
        pthread_mutex_unlock(&s_text_mutex);
        return;
    }

    // 复制而非引用调用方缓冲区，调用方随后可释放自己的副本。
    memcpy(s_parent_key, loader_key, CPRISK_ARMOR_KEY_SIZE);
    s_parent_ready = 1;

    const struct mach_header_64 *hdr = cprisk_text_own_hdr();
    if (!hdr) {
        cprisk_secure_zero(s_parent_key, sizeof(s_parent_key));
        s_parent_ready = 0;
        pthread_mutex_unlock(&s_text_mutex);
        return;
    }

    unsigned long sec_sz = 0;
    // 描述符缺失或非法时静默禁用：打包工具未启用该 pass 属于正常情况。
    const uint8_t *sec = cprisk_find_section(
        hdr,
        CPRISK_ARMOR_SEGMENT_DATA,
        CPRISK_ARMOR_SECTION_TEXT_ENCRYPT,
        &sec_sz);
    uint32_t count = 0;
    if (!sec || cprisk_text_parse_descriptor(sec, sec_sz, &count) != 0) {
        cprisk_secure_zero(s_parent_key, sizeof(s_parent_key));
        s_parent_ready = 0;
        pthread_mutex_unlock(&s_text_mutex);
        return;
    }

    if (count == 0) {
        // 0 条目等价于未启用。
        cprisk_secure_zero(s_parent_key, sizeof(s_parent_key));
        s_parent_ready = 0;
        pthread_mutex_unlock(&s_text_mutex);
        return;
    }

    const struct cprisk_text_encrypt_entry *src =
        (const struct cprisk_text_encrypt_entry *)(sec + sizeof(struct cprisk_text_encrypt_header));

    for (uint32_t i = 0; i < count; ++i) {
        // O(n^2) 重叠检查：条目必须互不重叠，否则一页可能被两条目重复解密。
        int invalid = cprisk_text_validate_bounds(hdr, &src[i]) != 0;
        for (uint32_t j = 0; !invalid && j < i; ++j) {
            invalid = src[i].vm_addr < src[j].vm_addr + src[j].size &&
                      src[j].vm_addr < src[i].vm_addr + src[i].size;
        }
        if (invalid) {
            cprisk_integrity_poison_text_encrypt_lane();
            cprisk_secure_zero(s_parent_key, sizeof(s_parent_key));
            s_parent_ready = 0;
            pthread_mutex_unlock(&s_text_mutex);
            return;
        }
    }

    s_entries = (struct cprisk_text_encrypt_entry *)calloc((size_t)count, sizeof(struct cprisk_text_encrypt_entry));
    // 所有运行时数组按最大条目数一次性分配，避免 JIT 路径再分配。
    s_poison = (uint8_t *)calloc((size_t)count, 1);
    s_decrypted = (uint8_t *)calloc((size_t)count, 1);
    s_decrypt_ticks = (uint64_t *)calloc((size_t)count, sizeof(uint64_t));
    s_cipher_hashes = (uint8_t *)calloc((size_t)count, CPRISK_ARMOR_HASH_SIZE);
    if (!s_entries || !s_poison || !s_decrypted || !s_decrypt_ticks || !s_cipher_hashes) {
        free(s_entries);
        free(s_poison);
        free(s_decrypted);
        free(s_decrypt_ticks);
        free(s_cipher_hashes);
        s_entries = NULL;
        s_poison = NULL;
        s_decrypted = NULL;
        s_decrypt_ticks = NULL;
        s_cipher_hashes = NULL;
        cprisk_secure_zero(s_parent_key, sizeof(s_parent_key));
        s_parent_ready = 0;
        pthread_mutex_unlock(&s_text_mutex);
        return;
    }

    intptr_t slide = cprisk_compute_slide(hdr);
    uint32_t installed = 0;

    // 逐条安装：校验失败或改页失败的条目跳过，但保留其余可用条目。
    for (uint32_t i = 0; i < count; i++) {
        struct cprisk_text_encrypt_entry ent = src[i];
        if (cprisk_text_validate_bounds(hdr, &ent) != 0)
            continue;

        uint8_t *ptr = (uint8_t *)((uintptr_t)ent.vm_addr + (uintptr_t)slide);
        void *page = NULL;
        size_t span = 0;
        if (cprisk_text_page_span(ptr, (size_t)ent.size, &page, &span) != 0)
            continue;

        // 在仍为密文时记录哈希，作为后续“页面是否被改写”的基准。
        if (cprisk_text_capture_cipher_hash_i(installed, ptr, (size_t)ent.size) != 0) {
            continue;
        }

        // 置为不可访问后，首次取指会触发缺页并进入 cprisk_text_jit_decrypt。
        if (cprisk_armor_vm_protect(page, span, PROT_NONE) != 0) {
            cprisk_integrity_poison_text_encrypt_lane();
            continue;
        }
        memcpy(&s_entries[installed], &ent, sizeof(ent));
        installed++;
    }

    s_entry_count = installed;
    if (installed == 0) {
        // 没有任何条目安装成功：释放数组并清零根密钥，功能整体禁用。
        free(s_entries);
        free(s_poison);
        free(s_decrypted);
        free(s_decrypt_ticks);
        free(s_cipher_hashes);
        s_entries = NULL;
        s_poison = NULL;
        s_decrypted = NULL;
        s_decrypt_ticks = NULL;
        s_cipher_hashes = NULL;
        cprisk_secure_zero(s_parent_key, sizeof(s_parent_key));
        s_parent_ready = 0;
    } else {
        // 仅在至少安装一页后布设蜜罐，避免无意义的内存改动。
        cprisk_text_honeypot_arm(hdr);
    }

    pthread_mutex_unlock(&s_text_mutex);
}

/// 空闲巡检入口：重新加密超时页、检测保护漂移并触发自检。
/// - 由上层 watchdog 周期性调用；耗时与页数线性相关。
/// - 线程安全：内部持有 s_text_mutex。
/// - 自检标志非 0 时统一 poison 文本加密通道。
void cprisk_text_encrypt_service_idle(void) {
    uint32_t self_check_flags = CPRISK_TEXT_ENCRYPT_SELF_CHECK_FLAG_NONE;
    pthread_mutex_lock(&s_text_mutex);
    const uint64_t now_ticks = mach_absolute_time();
    cprisk_text_maybe_reencrypt_idle(now_ticks);
    self_check_flags = cprisk_text_encrypt_self_check_locked_i(now_ticks);
    pthread_mutex_unlock(&s_text_mutex);
    if (self_check_flags != CPRISK_TEXT_ENCRYPT_SELF_CHECK_FLAG_NONE) {
        cprisk_integrity_poison_text_encrypt_lane();
    }
}

// 对外自检：加锁后执行完整检查并返回标志位；只读，不修改页状态（临时改权限除外）。
uint32_t cprisk_text_encrypt_self_check(void) {
    uint32_t flags = CPRISK_TEXT_ENCRYPT_SELF_CHECK_FLAG_NONE;
    pthread_mutex_lock(&s_text_mutex);
    flags = cprisk_text_encrypt_self_check_locked_i(mach_absolute_time());
    pthread_mutex_unlock(&s_text_mutex);
    return flags;
}

// 卸载 __TEXT 页加密：加锁调用公共释放路径，恢复所有仍解密的页。
void cprisk_text_encrypt_uninstall(void) {
    pthread_mutex_lock(&s_text_mutex);
    cprisk_text_encrypt_release_locked();
    pthread_mutex_unlock(&s_text_mutex);
}

/// 处理 __TEXT 缺页：命中受保护条目时验 MAC、解密、校验明文哈希并恢复 R+X。
/// - 返回 1 表示已处理（解密成功、已解密或已是毒页），0 表示未命中/失败。
/// - fault_addr 为异常地址；NULL 直接返回 0。
/// - 线程安全：同一把 s_text_mutex 同时保护安装/卸载；异常上下文内不可重入。
/// - 失败语义：MAC/哈希/派生失败一律写 BRK 毒页并返回 1（避免同一 PC 反复缺页）。
int cprisk_text_jit_decrypt(void *fault_addr) {
    // 无锁快速路径：未安装或参数为空时直接返回，避免异常上下文抢锁。
    if (!fault_addr || !s_parent_ready || !s_entries || s_entry_count == 0)
        return 0;

    pthread_mutex_lock(&s_text_mutex);

    // 加锁后必须重新检查状态：安装/卸载可能发生在预检查与加锁之间。
    /* Re-check after acquiring the lock -- another thread may have called
     * cprisk_text_encrypt_uninstall() between the pre-check and the lock. */
    if (!s_parent_ready || !s_entries || s_entry_count == 0) {
        pthread_mutex_unlock(&s_text_mutex);
        return 0;
    }

    uint64_t now = mach_absolute_time();
    // 先做一次空闲巡检，顺带把超时页回收，降低热点页长期明文的风险。
    cprisk_text_maybe_reencrypt_idle(now);

    // 每次缺页重新取头部与 slide，卸载后的旧指针不可使用。
    const struct mach_header_64 *hdr = cprisk_text_own_hdr();
    if (!hdr) {
        pthread_mutex_unlock(&s_text_mutex);
        return 0;
    }
    intptr_t slide = cprisk_compute_slide(hdr);

    // 线性查找覆盖 fault_addr 的条目；条目数受 CPRISK_MAX_ENTRY_COUNT 限制。
    for (uint32_t i = 0; i < s_entry_count; i++) {
        const struct cprisk_text_encrypt_entry *ent = &s_entries[i];
        uint8_t *ptr = (uint8_t *)((uintptr_t)ent->vm_addr + (uintptr_t)slide);
        void *page = NULL;
        size_t span = 0;
        if (cprisk_text_page_span(ptr, (size_t)ent->size, &page, &span) != 0)
            continue;

        if ((uintptr_t)fault_addr < (uintptr_t)page ||
            (uintptr_t)fault_addr >= (uintptr_t)page + span)
            continue;

        if (s_poison[i]) {
            // 毒页条目直接返回 1：告诉异常分发器“已处理”，避免重复进入。
            pthread_mutex_unlock(&s_text_mutex);
            return 1;
        }

        if (s_decrypted[i]) {
            // 已是明文（可能刚被其他线程解密）：返回 1，不重复操作。
            pthread_mutex_unlock(&s_text_mutex);
            return 1;
        }

        // 读取密文前必须先获得读权限，否则在异常处理内部再次缺页。
        if (cprisk_armor_vm_protect(page, span, PROT_READ | PROT_WRITE) != 0) {
            pthread_mutex_unlock(&s_text_mutex);
            return 0;
        }

        unsigned long text_sz = 0;
        // section_index = 基数 + 页号；生产端必须用同一公式派生密钥。
        const uint8_t *text_base = cprisk_find_section(hdr, "__TEXT", "__text", &text_sz);
        uint32_t page_idx = 0;
        if (text_base && (uintptr_t)ptr >= (uintptr_t)text_base)
            page_idx = (uint32_t)(((uintptr_t)ptr - (uintptr_t)text_base) / CPRISK_TEXT_PAGE_SIZE);
        uint32_t section_index = CPRISK_TEXT_SECTION_INDEX_BASE + page_idx;

        uint8_t section_key[CPRISK_ARMOR_KEY_SIZE];
        // 白盒域求值失败属于完整性失败：恢复 PROT_NONE 并返回 0。
        if (cprisk_text_derive_section_key_i(
                s_parent_key,
                section_index,
                ent->nonce,
                CPRISK_ARMOR_NONCE_SIZE,
                1,
                section_key) != 0) {
            cprisk_secure_zero(section_key, sizeof(section_key));
            (void)cprisk_armor_vm_protect(page, span, PROT_NONE);
            cprisk_integrity_poison_text_encrypt_lane();
            pthread_mutex_unlock(&s_text_mutex);
            return 0;
        }

        // 进入 MAC 前防 size+NONCE_SIZE 溢出。
        if (ent->size > SIZE_MAX - CPRISK_ARMOR_NONCE_SIZE) {
            cprisk_secure_zero(section_key, sizeof(section_key));
            cprisk_text_poison_entry(ptr, (size_t)ent->size, page, span);
            s_poison[i] = 1;
            cprisk_integrity_poison_text_encrypt_lane();
            pthread_mutex_unlock(&s_text_mutex);
            return 1;
        }
        // 规范编码与数据段/字符串表一致：长度字段本身也纳入 MAC。
        /*
         * CPRisk-MAC over the canonical encoding written by TextSegmentEncryptor.swift:
         *   u32 section_index | u32 nonce_len | nonce[nonce_len] |
         *   u32 ct_len        | ciphertext[ct_len]
         * Section_index binding prevents page transposition; ct_len in the
         * scope means truncation must invalidate the tag (the previous
         * `nonce || ciphertext` form let truncation pass with matched
         * size_field updates).
         */
        const size_t mac_msg_len =
            4u + 4u + (size_t)CPRISK_ARMOR_NONCE_SIZE + 4u + (size_t)ent->size;
        uint8_t *mac_msg = (uint8_t *)malloc(mac_msg_len);
        // 连续缓冲用于规范编码；分配失败时恢复 PROT_NONE（fail-closed）。
        if (!mac_msg) {
            cprisk_secure_zero(section_key, sizeof(section_key));
            (void)cprisk_armor_vm_protect(page, span, PROT_NONE);
            pthread_mutex_unlock(&s_text_mutex);
            return 0;
        }
        size_t mp = 0u;
        mac_msg[mp++] = (uint8_t)(section_index      );
        mac_msg[mp++] = (uint8_t)(section_index >>  8);
        mac_msg[mp++] = (uint8_t)(section_index >> 16);
        mac_msg[mp++] = (uint8_t)(section_index >> 24);
        mac_msg[mp++] = (uint8_t)(CPRISK_ARMOR_NONCE_SIZE      );
        mac_msg[mp++] = (uint8_t)(CPRISK_ARMOR_NONCE_SIZE >>  8);
        mac_msg[mp++] = (uint8_t)(CPRISK_ARMOR_NONCE_SIZE >> 16);
        mac_msg[mp++] = (uint8_t)(CPRISK_ARMOR_NONCE_SIZE >> 24);
        memcpy(mac_msg + mp, ent->nonce, CPRISK_ARMOR_NONCE_SIZE);
        mp += CPRISK_ARMOR_NONCE_SIZE;
        mac_msg[mp++] = (uint8_t)((uint32_t)ent->size      );
        mac_msg[mp++] = (uint8_t)((uint32_t)ent->size >>  8);
        mac_msg[mp++] = (uint8_t)((uint32_t)ent->size >> 16);
        mac_msg[mp++] = (uint8_t)((uint32_t)ent->size >> 24);
        memcpy(mac_msg + mp, ptr, (size_t)ent->size);
        uint8_t computed_mac[CPRISK_ARMOR_HASH_SIZE];
        cprisk_mac_sha256(section_key, CPRISK_ARMOR_KEY_SIZE, mac_msg, mac_msg_len, computed_mac);
        cprisk_secure_zero(mac_msg, mac_msg_len);
        free(mac_msg);

        // 常量时间比较 MAC；失败写 BRK 毒页并标记，防止同一 PC 无限缺页。
        if (cprisk_mac_verify(ent->mac_tag, computed_mac, CPRISK_ARMOR_HASH_SIZE) != 0) {
            cprisk_secure_zero(computed_mac, sizeof(computed_mac));
            cprisk_secure_zero(section_key, sizeof(section_key));
            cprisk_text_poison_entry(ptr, (size_t)ent->size, page, span);
            s_poison[i] = 1;
            cprisk_integrity_poison_text_encrypt_lane();
            pthread_mutex_unlock(&s_text_mutex);
            return 1;
        }
        cprisk_secure_zero(computed_mac, sizeof(computed_mac));

        if (cprisk_armor_xor_region(
                ptr,
                (size_t)ent->size,
                ent->key_id,
                ent->nonce,
                CPRISK_ARMOR_NONCE_SIZE,
                section_key) != 0) {
            // MAC 通过后才解密；异或失败恢复 PROT_NONE。
            cprisk_secure_zero(section_key, sizeof(section_key));
            (void)cprisk_armor_vm_protect(page, span, PROT_NONE);
            pthread_mutex_unlock(&s_text_mutex);
            return 0;
        }
        cprisk_secure_zero(section_key, sizeof(section_key));

        uint8_t plain_hash[CPRISK_SHA256_DIGEST_LENGTH];
        // 解密后再用 content_hash 确认明文，防止密钥派生错误产出垃圾代码。
        cprisk_sha256(ptr, (size_t)ent->size, plain_hash);
        if (memcmp(plain_hash, ent->content_hash, CPRISK_ARMOR_HASH_SIZE) != 0) {
            cprisk_secure_zero(plain_hash, sizeof(plain_hash));
            cprisk_text_poison_entry(ptr, (size_t)ent->size, page, span);
            s_poison[i] = 1;
            cprisk_integrity_poison_text_encrypt_lane();
            pthread_mutex_unlock(&s_text_mutex);
            return 1;
        }
        cprisk_secure_zero(plain_hash, sizeof(plain_hash));

        // 恢复为可读可执行，后续取指不再缺页。
        if (cprisk_armor_vm_protect(page, span, PROT_READ | PROT_EXEC) != 0) {
            cprisk_integrity_poison_text_encrypt_lane();
            pthread_mutex_unlock(&s_text_mutex);
            return 0;
        }

        s_decrypted[i] = 1;
        // 记录解密时刻，供空闲回收与 STALE 自检使用。
        s_decrypt_ticks[i] = now;

        // 概率性立即回写：约 30% 的新解密页把时间戳回拨到过期阈值之外，
        // 使下一次 service_idle 立即重新加密；用于对抗 unidbg 关闭 SMC 检测后的指令缓存。
        /* ── Probabilistic immediate re-encrypt scheduling ────────────────────
         *
         * Counter-measure against unidbg魔改版 `setDisableSMC(true)` optimisation.
         *
         * When the attacker calls setDisableSMC(true), unidbg skips the
         * mem_read + compare step on every instruction, treating all pages as
         * non-self-modifying.  The L1/L2 Capstone cache is then never
         * invalidated and every instruction in a hot loop is served from cache
         * in O(1) — effectively making our page-level encryption invisible to
         * the tracer.
         *
         * By scheduling ~30% of freshly-decrypted pages for *immediate*
         * re-encryption (setting their timestamp to the stale threshold so the
         * next service_idle sweep re-encrypts them within ~32 ms), we force the
         * page content to change while the attacker is executing instructions
         * from it.  This means:
         *   • The page transitions PROT_READ|EXEC → PROT_NONE between
         *     consecutive instruction fetches.
         *   • unidbg with setDisableSMC(true) encounters a fault on a page it
         *     "knows" was just decrypted — forcing it to either crash or fall
         *     back to the slow SMC-aware path.
         *   • With setDisableSMC(false) the mem_read returns different bytes
         *     after re-encryption, invalidating the cached disassembly.
         *
         * Probability is derived from `mach_absolute_time()` low bits so it is
         * non-deterministic and not reproducible across runs.  We use
         * (time ^ ptr_mix) % 10 < 3  (≈30%) — cheap, branch-free-ish, and
         * requires no heap allocation. */
        {
            const uint64_t prob_mix = now ^ (uint64_t)(uintptr_t)ptr ^ (uint64_t)(uintptr_t)page;
            // 概率由时间、页地址混合得到，跨运行不确定，难以被预测或复现。
            if ((prob_mix % 10u) < 3u) {
                // 回拨“过期阈值 + 1 秒”的量，确保下一次巡检必然命中。
                /* Back-date the decrypt timestamp beyond the stale threshold so
                 * the next cprisk_text_maybe_reencrypt_idle() re-encrypts this
                 * page immediately rather than waiting the normal dwell time. */
                const uint64_t ns_to_ticks = (s_timebase.denom > 0u)
                    ? (CPRISK_TEXT_STALE_DECRYPT_NS + 1000000000ULL) * (uint64_t)s_timebase.denom
                      / (uint64_t)s_timebase.numer
                    : 1u;
                s_decrypt_ticks[i] = (now > ns_to_ticks) ? (now - ns_to_ticks) : 0u;
            }
        }

        pthread_mutex_unlock(&s_text_mutex);
        return 1;
    }

    pthread_mutex_unlock(&s_text_mutex);
    return 0;
}

// 按需解密别名：语义与 cprisk_text_jit_decrypt 完全相同，供异常分发器调用。
int cprisk_text_on_demand_decrypt(void *fault_addr) {
    return cprisk_text_jit_decrypt(fault_addr);
}

// 非 Apple arm64 真机（模拟器、tvOS、watchOS）：不启用页加密。
// 所有入口保持签名不变但为空实现，保证上层链接与调用路径一致。
#else /* Simulator / non-arm64 Apple targets */

// 空实现：不支持页加密的平台直接成功返回。
void cprisk_text_encrypt_install(const uint8_t loader_key[CPRISK_ARMOR_KEY_SIZE]) {
    (void)loader_key;
}

// 空实现：无状态可释放。
void cprisk_text_encrypt_uninstall(void) {}

// 空实现：无页需要巡检。
void cprisk_text_encrypt_service_idle(void) {}

// 空实现：不处理缺页，返回 0 表示未命中。
int cprisk_text_jit_decrypt(void *fault_addr) {
    (void)fault_addr;
    return 0;
}

// 空实现别名：与 jit 一致返回 0。
int cprisk_text_on_demand_decrypt(void *fault_addr) {
    return cprisk_text_jit_decrypt(fault_addr);
}

#endif
