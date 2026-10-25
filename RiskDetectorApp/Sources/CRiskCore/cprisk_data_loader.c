/*
 * CRiskCore - Data segment decryptor for cprisk-armor ABI v2.
 * Consumes the packed loader descriptor section, validates each target section
 * against the current image, verifies CPRisk-MAC-SHA256 authentication before
 * decrypting in place, and rolls back all previously applied entries if any
 * step fails.
 *
 * NOTE (issue 20 — SHA-256-chained XOR keystream, NOT AEAD): the keystream
 * is SHA-256(key || id || nonce) XOR. It has no authentication of its own
 * (the CPRisk-MAC tag is checked first) and its security depends entirely
 * on NONCE UNIQUENESS. This file enforces it at decrypt time via
 * cprisk_data_nonce_reuse_check_i(): a (key, nonce) pair seen with a
 * different ciphertext is refused. Migration path: AEAD
 * (AES-GCM / ChaCha20-Poly1305) with nonce + AAD in the tag.
 */

// CRiskCore 数据段解密器（cprisk-armor ABI v2）：读取 __DATA 中的 loader 描述符，
// 校验每个目标 section 与当前 Mach-O 映像的对应关系，先验 CPRisk-MAC-SHA256
// 再原地 XOR 解密；任一步失败即回滚已应用条目并污染完整性通道（fail-closed）。
// 线程模型：初始化/加载/卸载由 s_loader_mutex 串行化，JIT 缺页解密在同一互斥锁内完成。
// 平台限制：页权限操作在 Apple 平台走 SVC 直调 + Mach 交叉校验，不支持时回退 libc。
// 失败语义：返回 -1/0 表示失败或未命中；密钥、明文与 MAC 缓冲用后立即清零。
#include "include/CRiskCore.h"
#include "include/cprisk_page_span.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <mach/vm_prot.h>
#ifdef __APPLE__
#include <TargetConditionals.h>
#endif
#include "include/cprisk_dlsym.h"
#include "include/cprisk_macho.h"

// mprotect/mlock/munlock 的函数指针类型：主路径走 cprisk_mprotect_direct（SVC），
// 失败时才通过 dlsym 找 libc 符号，因此这里统一保存可为空的函数指针。
typedef int (*cprisk_mprotect_func_t)(void *, size_t, int);
typedef int (*cprisk_mlock_func_t)(const void *, size_t);
typedef int (*cprisk_munlock_func_t)(const void *, size_t);

// 延迟解析的 libc 兜底入口，由 s_dlsym_once 保证只初始化一次；
// 解析失败时指针保持 NULL，调用方按“不可用”处理。
static cprisk_mprotect_func_t s_mprotect_fn = NULL;
static cprisk_mlock_func_t s_mlock_fn = NULL;
static cprisk_munlock_func_t s_munlock_fn = NULL;
static pthread_once_t s_dlsym_once = PTHREAD_ONCE_INIT;

// 埋点计数器：直接调用失败、兜底成功、连续全失败（达阈值即判定被篡改），
// 以及 SVC 与 Mach vm_region 交叉校验不一致次数。均为 volatile，允许多线程累加。
static volatile int s_mprotect_tampered = 0;
static volatile uint32_t s_mprotect_direct_failure_count = 0u;
static volatile uint32_t s_mprotect_fallback_success_count = 0u;
static volatile uint32_t s_mprotect_consecutive_full_fail_streak = 0u;
static volatile uint32_t s_vm_mprotect_crosscheck_mismatch = 0u;
static volatile uint32_t s_vm_mprotect_mach_trap_mismatch = 0u;
// 连续失败阈值；0 表示配置缺失，读取时回退到编译期默认值。
static uint32_t s_mprotect_fail_streak_threshold = CPRISK_MPROTECT_FULL_FAIL_STREAK_THRESHOLD;
// 仅 DEBUG 生效的故障注入开关：强制直调失败 / 强制兜底失败，用于覆盖降级路径。
static volatile int s_test_mprotect_force_direct_fail = 0;
static volatile int s_test_mprotect_force_fallback_fail = 0;

// pthread_once 回调：从 libsystem_kernel.dylib 解析三个 libc 符号。
// 解析失败不会中止初始化，只把对应函数指针留为 NULL。
static void init_dlsym_once(void) {
    s_mprotect_fn = (cprisk_mprotect_func_t)cprisk_dlsym("libsystem_kernel.dylib", "mprotect");
    s_mlock_fn = (cprisk_mlock_func_t)cprisk_dlsym("libsystem_kernel.dylib", "mlock");
    s_munlock_fn = (cprisk_munlock_func_t)cprisk_dlsym("libsystem_kernel.dylib", "munlock");
}

/* ── Nonce-reuse detection (issue 20) ────────────────────────────────
 * The per-section keystream is SHA-256(key || id || nonce) XOR: NOT an
 * AEAD, so its security rests entirely on nonce uniqueness. Reusing one
 * (key, nonce) for two different plaintexts reuses the keystream and
 * leaks plaintext XOR. The registry below records (key fingerprint,
 * key_id, nonce) -> ciphertext hash for every successfully MAC-verified
 * section decrypt in this process:
 *   - same (key, nonce, ciphertext) again  -> legitimate re-decrypt, allowed;
 *   - same (key, nonce), DIFFERENT ciphertext -> nonce reuse, REFUSED
 *     (caller treats it like a MAC failure: page stays PROT_NONE + poison).
 * Called with the loader mutex held by the decrypt path; the registry has
 * its own mutex for safety. 64 slots, round-robin eviction: eviction only
 * weakens detection for old entries, never causes a false refusal. */
// 槽位固定为 64 个并环形覆盖；淘汰只会降低对久远条目的检测能力，不会造成误拒绝。
#define CPRISK_DATA_NONCE_REGISTRY_SLOTS 64u
// 每个槽记录一次通过 MAC 校验的解密：(key 指纹, key_id, nonce) -> 密文哈希。
// key_fp/ct_hash 均为 SHA-256，避免在全局状态中留存密钥或明文；valid==0 表示空槽。
typedef struct {
    uint8_t key_fp[CPRISK_ARMOR_HASH_SIZE];
    uint32_t key_id;
    uint8_t nonce[CPRISK_ARMOR_NONCE_SIZE];
    uint8_t ct_hash[CPRISK_ARMOR_HASH_SIZE];
    uint8_t valid;
} cprisk_data_nonce_entry_i;
// 注册表本体、环形写指针与互斥锁；所有读写都在 s_nonce_registry_mutex 内完成。
// 注册表只服务于 nonce 重用检测，本身不参与解密。
static cprisk_data_nonce_entry_i s_nonce_registry[CPRISK_DATA_NONCE_REGISTRY_SLOTS];
static uint32_t s_nonce_registry_next = 0u;
static pthread_mutex_t s_nonce_registry_mutex = PTHREAD_MUTEX_INITIALIZER;

// 检查并登记一次 (key, key_id, nonce) 解密。
// - 返回 0：首次见到，或同一密文重复解密，允许继续；
// - 返回 -1：同一 (key, nonce) 对应不同密文，判定 nonce 重用，调用方按 MAC 失败处理。
// 参数均为借用：key 指向 32 字节密钥，ciphertext 长度由 ct_len 给出。线程安全：内部加锁。
static int cprisk_data_nonce_reuse_check_i(const uint8_t *key, uint32_t key_id,
                                           const uint8_t *nonce,
                                           const uint8_t *ciphertext, size_t ct_len) {
    if (!key || !nonce || !ciphertext)
        return -1;
    // 只保存密钥/密文的指纹，避免在全局状态里留存原始密钥或明文。
    uint8_t key_fp[CPRISK_ARMOR_HASH_SIZE];
    uint8_t ct_hash[CPRISK_ARMOR_HASH_SIZE];
    cprisk_sha256(key, CPRISK_ARMOR_KEY_SIZE, key_fp);
    cprisk_sha256(ciphertext, ct_len, ct_hash);
    int rc = 0;
    int found = 0;
    pthread_mutex_lock(&s_nonce_registry_mutex);
    // 先按 key_id 快速过滤，再比对 nonce 与密钥指纹；命中首个匹配即停止。
    for (uint32_t i = 0; i < CPRISK_DATA_NONCE_REGISTRY_SLOTS; i++) {
        const cprisk_data_nonce_entry_i *e = &s_nonce_registry[i];
        if (e->valid == 0u || e->key_id != key_id)
            continue;
        if (memcmp(e->nonce, nonce, CPRISK_ARMOR_NONCE_SIZE) != 0)
            continue;
        if (memcmp(e->key_fp, key_fp, CPRISK_ARMOR_HASH_SIZE) != 0)
            continue;
        /* Same (key, nonce) seen before: refuse iff ciphertext differs. */
        found = 1;
        if (memcmp(e->ct_hash, ct_hash, CPRISK_ARMOR_HASH_SIZE) != 0)
            rc = -1;
        break;
    }
    /* Re-decrypts must not evict unrelated nonce history. */
    // 未命中的新组合写入下一个环形槽；重复命中不推进写指针，避免冲掉无关历史。
    if (rc == 0 && !found) {
        cprisk_data_nonce_entry_i *slot =
            &s_nonce_registry[s_nonce_registry_next % CPRISK_DATA_NONCE_REGISTRY_SLOTS];
        s_nonce_registry_next++;
        memcpy(slot->key_fp, key_fp, CPRISK_ARMOR_HASH_SIZE);
        slot->key_id = key_id;
        memcpy(slot->nonce, nonce, CPRISK_ARMOR_NONCE_SIZE);
        memcpy(slot->ct_hash, ct_hash, CPRISK_ARMOR_HASH_SIZE);
        slot->valid = 1u;
    }
    pthread_mutex_unlock(&s_nonce_registry_mutex);
    // 指纹属于敏感派生值，离开函数前清零。
    cprisk_secure_zero(key_fp, sizeof(key_fp));
    cprisk_secure_zero(ct_hash, sizeof(ct_hash));
    return rc;
}

// 读取生效的连续失败阈值：0 视为配置缺失，回退到编译期默认值。
static inline uint32_t cprisk_mprotect_effective_fail_threshold(void) {
    uint32_t t = s_mprotect_fail_streak_threshold;
    if (t == 0u)
        t = CPRISK_MPROTECT_FULL_FAIL_STREAK_THRESHOLD;
    return t;
}

// 任意一次页权限操作成功都清零连续失败计数，避免历史失败累积造成误报。
static inline void cprisk_mprotect_on_vm_op_success(void) {
    s_mprotect_consecutive_full_fail_streak = 0u;
}

// 直接与兜底路径都失败时累加连续失败；达到阈值后置篡改标志且不会自动复位，
// 只能通过 DEBUG 下的 cprisk_test_mprotect_reset_tamper_state 清除。
static inline void cprisk_mprotect_record_full_failure(void) {
    uint32_t thr = cprisk_mprotect_effective_fail_threshold();
    uint32_t next = s_mprotect_consecutive_full_fail_streak + 1u;
    s_mprotect_consecutive_full_fail_streak = next;
    if (next >= thr)
        s_mprotect_tampered = 1;
}

/// 修改页权限的隐藏封装：优先 SVC 直调，失败回退 libc mprotect。
/// - 参数与 mprotect(2) 一致；addr/len 由调用方保证页对齐。
/// - 返回 0 成功；-1 表示两条路径均失败（并已累加失败计数）。
/// - 线程安全：计数器为 volatile 累加，函数本身可并发调用。
/// - 平台：Apple 平台在成功后额外做 vm_region/vm_protect 交叉校验，仅计数不改变结果。
static inline int cprisk_hidden_mprotect(void *addr, size_t len, int prot) {
    int direct_errno = 0;
    int direct_ok;
    if (s_test_mprotect_force_direct_fail) {
        direct_ok = 0;
    } else {
        direct_ok = (cprisk_mprotect_direct(addr, len, prot, &direct_errno) == 0);
    }
    if (direct_ok) {
#if defined(__APPLE__)
        // 直调成功后仍做一次 Mach 侧交叉校验：若 SVC 包装被 hook，保护状态可能不一致。
        const int cc = cprisk_vm_crosscheck_mprotect(addr, len, prot);
        if (cc == 1) {
            s_vm_mprotect_crosscheck_mismatch += 1u;
        } else if (cc == 2) {
            s_vm_mprotect_mach_trap_mismatch += 1u;
        }
#endif
        cprisk_mprotect_on_vm_op_success();
        return 0;
    }
    s_mprotect_direct_failure_count += 1u;

    // 直调失败再走 libc 兜底；兜底同样失败才计入“全失败”连击。
    /* Safety fallback: keep legacy path for unsupported platforms/builds. */
    (void)pthread_once(&s_dlsym_once, init_dlsym_once);
    if (s_mprotect_fn) {
        // 记录一次兜底使用，供反绕过检测判断是否存在被 hook 的 mprotect。
        cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_ARMOR_MPROTECT);
        int rc;
        if (s_test_mprotect_force_fallback_fail) {
            rc = -1;
        } else {
            rc = s_mprotect_fn(addr, len, prot);
        }
        if (rc == 0) {
            s_mprotect_fallback_success_count += 1u;
#if defined(__APPLE__)
            const int cc = cprisk_vm_crosscheck_mprotect(addr, len, prot);
            if (cc == 1) {
                s_vm_mprotect_crosscheck_mismatch += 1u;
            } else if (cc == 2) {
                s_vm_mprotect_mach_trap_mismatch += 1u;
            }
#endif
            cprisk_mprotect_on_vm_op_success();
            return 0;
        }
        cprisk_mprotect_record_full_failure();
        return rc;
    }

    // 两条路径都不可用：记录全失败并返回 -1，调用方必须按 fail-closed 处理。
    cprisk_mprotect_record_full_failure();
    (void)direct_errno;
    return -1;
}

// 返回篡改标志：1 表示页权限操作连续失败已达到阈值。
int cprisk_is_mprotect_tampered(void) {
    return s_mprotect_tampered;
}

// 返回 SVC 与 Mach 交叉校验结果不一致的累计次数（只增不减）。
uint32_t cprisk_get_vm_mprotect_crosscheck_mismatch_count(void) {
    return s_vm_mprotect_crosscheck_mismatch;
}

// 返回 Mach trap 路径与 SVC 结果不一致的累计次数。
uint32_t cprisk_get_vm_mprotect_mach_trap_mismatch_count(void) {
    return s_vm_mprotect_mach_trap_mismatch;
}

// 返回 SVC 直调失败的累计次数。
uint32_t cprisk_get_mprotect_direct_failure_count(void) {
    return s_mprotect_direct_failure_count;
}

// 返回 libc 兜底成功的累计次数。
uint32_t cprisk_get_mprotect_fallback_success_count(void) {
    return s_mprotect_fallback_success_count;
}

// 返回当前连续全失败次数（任意一次成功即清零）。
uint32_t cprisk_get_mprotect_consecutive_full_fail_streak(void) {
    return s_mprotect_consecutive_full_fail_streak;
}

// 返回当前生效的连续失败阈值（DEBUG 下可被测试钩子改写）。
uint32_t cprisk_get_mprotect_fail_streak_threshold(void) {
    return cprisk_mprotect_effective_fail_threshold();
}

// DEBUG 专用：强制 SVC 直调失败，用于验证 libc 兜底路径；非 DEBUG 为空操作。
void cprisk_test_mprotect_set_force_direct_fail(int enabled) {
#if !defined(DEBUG) || !DEBUG
    /* Test hook: inert outside DEBUG builds (issue 18). */
    return;
#endif
    s_test_mprotect_force_direct_fail = enabled ? 1 : 0;
}

// DEBUG 专用：强制兜底 mprotect 失败，用于验证 fail-closed 与篡改计数。
void cprisk_test_mprotect_set_force_fallback_fail(int enabled) {
#if !defined(DEBUG) || !DEBUG
    /* Test hook: inert outside DEBUG builds (issue 18). */
    return;
#endif
    s_test_mprotect_force_fallback_fail = enabled ? 1 : 0;
}

// DEBUG 专用：改写连续失败阈值；传 0 恢复默认值。
void cprisk_test_mprotect_set_fail_streak_threshold(uint32_t threshold) {
#if !defined(DEBUG) || !DEBUG
    /* Test hook: inert outside DEBUG builds (issue 18). */
    return;
#endif
    s_mprotect_fail_streak_threshold =
        (threshold == 0u) ? CPRISK_MPROTECT_FULL_FAIL_STREAK_THRESHOLD : threshold;
}

// DEBUG 专用：清空所有 mprotect 埋点、篡改标志与故障注入开关。
void cprisk_test_mprotect_reset_tamper_state(void) {
#if !defined(DEBUG) || !DEBUG
    /* Test hook: inert outside DEBUG builds (issue 18). */
    return;
#endif
    cprisk_reset_libc_fallback_used_mask();
    s_mprotect_tampered = 0;
    s_mprotect_direct_failure_count = 0u;
    s_mprotect_fallback_success_count = 0u;
    s_mprotect_consecutive_full_fail_streak = 0u;
    s_vm_mprotect_crosscheck_mismatch = 0u;
    s_vm_mprotect_mach_trap_mismatch = 0u;
    s_mprotect_fail_streak_threshold = CPRISK_MPROTECT_FULL_FAIL_STREAK_THRESHOLD;
    s_test_mprotect_force_direct_fail = 0;
    s_test_mprotect_force_fallback_fail = 0;
}

// 通过延迟解析的 libc 符号锁定/解锁页；未解析到符号时返回 -1。
// mlock 用于阻止敏感页被换出，配对的 munlock 必须在回滚/卸载路径成对调用。
static inline int cprisk_hidden_mlock(const void *addr, size_t len) {
    (void)pthread_once(&s_dlsym_once, init_dlsym_once);
    if (s_mlock_fn) return s_mlock_fn(addr, len);
    return -1;
}

// 解除 mlock：与 cprisk_hidden_mlock 成对使用；符号未解析时返回 -1。
static inline int cprisk_hidden_munlock(const void *addr, size_t len) {
    (void)pthread_once(&s_dlsym_once, init_dlsym_once);
    if (s_munlock_fn) return s_munlock_fn(addr, len);
    return -1;
}

// 对外暴露的页权限入口；与 cprisk_hidden_mprotect 等价，供其他 CRiskCore 文件复用。
int cprisk_armor_vm_protect(void *addr, size_t len, int prot) {
    return cprisk_hidden_mprotect(addr, len, prot);
}

#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"
#include "include/cprisk_memory_guard.h"

extern void cprisk_text_encrypt_install(const uint8_t loader_key[CPRISK_ARMOR_KEY_SIZE]);
extern void cprisk_text_encrypt_uninstall(void);
extern int cprisk_text_jit_decrypt(void *fault_addr);

// 内联 SHA-256 的摘要长度必须与 armor ABI 的 HASH_SIZE 一致，否则 MAC 与内容哈希布局错位。
_Static_assert(CPRISK_SHA256_DIGEST_LENGTH == CPRISK_ARMOR_HASH_SIZE,
               "inline SHA256 digest size must match armor ABI");

// 解析后的解密目标：segment/section 指向 Mach-O 头部内的只读描述（借用，不释放）；
// slide 为当前进程的 ASLR 偏移，运行时地址 = vm_addr + slide。
struct cprisk_loader_target {
    const struct segment_command_64 *segment;
    const struct section_64 *section;
    intptr_t slide;
};

/* ── state ─────────────────────────────────────────────────────────── */

// 加载器全局状态：s_loader_mutex 串行化加载/JIT 解密/卸载；
// s_erase_header_once 保证 Mach-O 头部恢复最多执行一次。
static pthread_mutex_t s_loader_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t s_erase_header_once = PTHREAD_ONCE_INIT;

// s_ldr_key 是初始化时复制的 32 字节根密钥（卸载时清零）；
// s_ldr_ready 表示已初始化，s_ldr_loaded 表示 loader 描述符已应用；
// s_data_acc 汇总解密内容的完整性值，s_guard_state 供内存陷阱登记使用。
static uint8_t  s_ldr_key[CPRISK_ARMOR_KEY_SIZE];
static int      s_ldr_ready;
static int      s_ldr_loaded;
static uint64_t s_data_acc;
static struct cprisk_guard_state s_guard_state;

/* ── per-section chained key derivation state ────────────────── */
// 链式派生状态：s_chain_initialized=1 表示至少有一个 v3 条目参与链式派生；
// s_prev_section_key 保留上一级链密钥的静态缓冲（当前路径以局部 parent_key 推进，仅做清零维护）；
// s_section_keys 按条目保存 32 字节会话密钥，共 s_entry_count 份。
static int      s_chain_initialized = 0;
static uint8_t  s_prev_section_key[CPRISK_ARMOR_KEY_SIZE];
static uint8_t *s_section_keys = NULL;  /* count * 32 bytes */
static uint32_t s_entry_count = 0;

// s_applied_entries 是已成功置为 PROT_NONE 的描述符副本，s_decrypted_flags
// 按同一下标记录该页是否已完成 JIT 解密；s_applied_count 为已登记条目数。
static struct cprisk_armor_loader_entry *s_applied_entries = NULL;
static int      *s_decrypted_flags = NULL;
static uint32_t s_applied_count = 0;

// 64 位循环左移；k 先归一到 [0,63]，避免移位位数越界触发未定义行为。
static inline uint64_t cprisk_rotl64_l(uint64_t x, int k) {
    k &= 63;  /* avoid UB: shift amount must be in [0, 63] */
    return k == 0 ? x : ((x << k) | (x >> (64 - k)));
}

// 取当前可执行映像的 Mach-O 头；通过函数自身地址反查，避免依赖 dyld API。
static const struct mach_header_64 *cprisk_own_hdr_l(void) {
    return cprisk_find_own_header((const void *)cprisk_own_hdr_l);
}

/* Generate len bytes of keystream starting at byte_offset. Used for chunked XOR.
 * seed = key[32] || sid_le[4] || nonce[nonce_len] */
// 生成从 byte_offset 开始的 len 字节密钥流（供 XOR 使用）。
// 种子布局：key[32] || sid_le[4] || nonce[nonce_len]；
// 第 0 块为 SHA256(seed)，其后每块为 SHA256(前一块)，因此必须按块顺序前进。
// 参数：nonce_len 超过 NONCE_SIZE 时输出全 0；out 由调用方分配且至少 len 字节。
// 线程安全：无全局状态，可重入。
static void cprisk_keystream_at_l(const uint8_t *key, uint32_t sid,
                                  const uint8_t *nonce, size_t nonce_len,
                                  size_t byte_offset,
                                  uint8_t *out, size_t len) {
    // 超长 nonce 说明描述符或调用方违约：输出清零，绝不越界读取 seed_buf。
    if (nonce_len > CPRISK_ARMOR_NONCE_SIZE) {
        if (len > 0) memset(out, 0, len);
        return;
    }
    if (len == 0)
        return;

    uint8_t seed_buf[CPRISK_ARMOR_KEY_SIZE + 4 + CPRISK_ARMOR_NONCE_SIZE];
    size_t seed_len = CPRISK_ARMOR_KEY_SIZE + 4 + nonce_len;
    memcpy(seed_buf, key, CPRISK_ARMOR_KEY_SIZE);
    // 显式按小端写入 sid，保证不同架构上生成相同密钥流。
    seed_buf[32] = (uint8_t)(sid);
    seed_buf[33] = (uint8_t)(sid >> 8);
    seed_buf[34] = (uint8_t)(sid >> 16);
    seed_buf[35] = (uint8_t)(sid >> 24);
    if (nonce_len > 0)
        memcpy(seed_buf + 36, nonce, nonce_len);

    uint8_t blk[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_sha256(seed_buf, seed_len, blk);
    cprisk_secure_zero(seed_buf, sizeof(seed_buf));

    // 先整块快进到目标偏移，再处理块内偏移；哈希链只能前向推进，无法随机跳块。
    /* Fast-forward to byte_offset: advance through full blocks */
    size_t block_offset = byte_offset / CPRISK_SHA256_DIGEST_LENGTH;
    size_t in_block = byte_offset % CPRISK_SHA256_DIGEST_LENGTH;
    for (size_t i = 0; i < block_offset; i++) {
        uint8_t prev[CPRISK_SHA256_DIGEST_LENGTH];
        memcpy(prev, blk, CPRISK_SHA256_DIGEST_LENGTH);
        cprisk_sha256(prev, CPRISK_SHA256_DIGEST_LENGTH, blk);
        cprisk_secure_zero(prev, sizeof(prev));
    }

    size_t out_off = 0;
    // 块内偏移不为 0 时先取当前块的剩余部分，再继续链式生成后续块。
    if (in_block > 0) {
        size_t take = CPRISK_SHA256_DIGEST_LENGTH - in_block;
        if (take > len)
            take = len;
        memcpy(out, blk + in_block, take);
        out_off = take;
        if (out_off < len) {
            uint8_t prev[CPRISK_SHA256_DIGEST_LENGTH];
            memcpy(prev, blk, CPRISK_SHA256_DIGEST_LENGTH);
            cprisk_sha256(prev, CPRISK_SHA256_DIGEST_LENGTH, blk);
            cprisk_secure_zero(prev, sizeof(prev));
        }
    }

    while (out_off < len) {
        size_t chunk = len - out_off;
        if (chunk > CPRISK_SHA256_DIGEST_LENGTH)
            chunk = CPRISK_SHA256_DIGEST_LENGTH;
        memcpy(out + out_off, blk, chunk);
        out_off += chunk;
        if (out_off < len) {
            uint8_t prev[CPRISK_SHA256_DIGEST_LENGTH];
            memcpy(prev, blk, CPRISK_SHA256_DIGEST_LENGTH);
            cprisk_sha256(prev, CPRISK_SHA256_DIGEST_LENGTH, blk);
            cprisk_secure_zero(prev, sizeof(prev));
        }
    }
    cprisk_secure_zero(blk, sizeof(blk));
}

// 从头开始生成密钥流；等价于 byte_offset=0 的 cprisk_keystream_at_l。
static void cprisk_keystream_l(const uint8_t *key, uint32_t sid,
                               const uint8_t *nonce, size_t nonce_len,
                               uint8_t *out, size_t len) {
    cprisk_keystream_at_l(key, sid, nonce, nonce_len, 0, out, len);
}

/* ── per-section chained key derivation ─────────────────────── */

/// 按 section_index + nonce 从父密钥派生下一级 32 字节密钥。
/// 第 1 级：out = CPRisk-MAC(parent, sid_le4 || nonce)；
/// 第 depth 级（depth>1）：再以 "cprisk.chained.v1." 与深度标签做多轮 MAC。
/// 参数：parent_key 借用；nonce_len > NONCE_SIZE 时输出全 0；out_key 由调用方提供。
/// 线程安全：无全局状态，可重入。
/// 失败语义：长度违约时静默产出全 0 密钥，后续 MAC 必然失败（fail-closed）。
void cprisk_armor_derive_chained_key(
    const uint8_t *parent_key,
    uint32_t section_index,
    const uint8_t *nonce,
    size_t nonce_len,
    uint8_t depth,
    uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]
) {
    /* Level 1: CPRisk-MAC(parent, index || nonce) */
    // 第 1 级把 section_index 与 nonce 绑定进 MAC，防止不同 section 复用同一派生结果。
    if (nonce_len > CPRISK_ARMOR_NONCE_SIZE) {
        memset(out_key, 0, CPRISK_ARMOR_KEY_SIZE);
        return;
    }
    uint8_t chain_material[4 + CPRISK_ARMOR_NONCE_SIZE];
    chain_material[0] = (uint8_t)(section_index);
    chain_material[1] = (uint8_t)(section_index >> 8);
    chain_material[2] = (uint8_t)(section_index >> 16);
    chain_material[3] = (uint8_t)(section_index >> 24);
    memcpy(chain_material + 4, nonce, nonce_len);

    cprisk_mac_sha256(parent_key, CPRISK_ARMOR_KEY_SIZE,
                       chain_material, 4 + nonce_len, out_key);
    cprisk_secure_zero(chain_material, sizeof(chain_material));

    /* Depth levels beyond 1: recursive CPRisk-MAC */
    // 深度 > 1 时用固定域标签与深度值再做多轮 MAC；域标签隔离了其他密钥用途。
    for (uint8_t d = 1; d < depth; d++) {
        uint8_t round_key[CPRISK_ARMOR_KEY_SIZE];
        memcpy(round_key, out_key, CPRISK_ARMOR_KEY_SIZE);

        uint8_t label[] = "cprisk.chained.v1.";
        cprisk_mac_sha256(round_key, CPRISK_ARMOR_KEY_SIZE,
                           label, sizeof(label) - 1, out_key);

        uint8_t depth_material[CPRISK_ARMOR_KEY_SIZE + 1];
        memcpy(depth_material, out_key, CPRISK_ARMOR_KEY_SIZE);
        depth_material[CPRISK_ARMOR_KEY_SIZE] = d;
        cprisk_mac_sha256(depth_material, CPRISK_ARMOR_KEY_SIZE + 1,
                           depth_material, CPRISK_ARMOR_KEY_SIZE + 1, out_key);

        cprisk_secure_zero(round_key, sizeof(round_key));
        cprisk_secure_zero(depth_material, sizeof(depth_material));
    }
}

// v3 条目的判定：section_index 非 0。v2 条目该字段恒为 0，回退到全局 loader key。
static int cprisk_is_v3_entry(const struct cprisk_armor_loader_entry *entry) {
    return entry && entry->section_index != 0u;
}

// 仅当 entry 与两个输出指针都非空时读取；调用方需自行保证 entry 来源可信。
static void cprisk_read_v3_fields(
    const struct cprisk_armor_loader_entry *entry,
    uint32_t *out_section_index,
    uint32_t *out_chained_depth
) {
    if (!entry || !out_section_index || !out_chained_depth) {
        return;
    }
    *out_section_index = entry->section_index;
    *out_chained_depth = entry->chained_key_depth;
}

// 把 Mach-O 的 16 字节定长名称复制为 NUL 结尾字符串。
// raw 不保证含 NUL；空名称返回 -1。out 至少 17 字节，由调用方提供。
static int cprisk_copy_fixed_name_l(const char raw[16], char out[17]) {
    size_t len = 0;
    while (len < 16 && raw[len] != '\0')
        len++;
    if (len == 0)
        return -1;
    memcpy(out, raw, len);
    out[len] = '\0';
    return 0;
}

/// 校验 loader section 头部：魔数、ABI 版本、条目数上限与整体长度。
/// - 成功时 *count_out 写入条目数；失败返回 -1 且不写输出。
/// - 只做边界检查，不信任任何来自文件的长度字段。
/// - 线程安全：纯函数，可并发调用。
static int cprisk_parse_loader_descriptor(
    const uint8_t *sec,
    unsigned long sec_sz,
    uint32_t *count_out
) {
    if (!sec || !count_out || sec_sz < sizeof(struct cprisk_armor_loader_header))
        return -1;

    const struct cprisk_armor_loader_header *loader =
        (const struct cprisk_armor_loader_header *)sec;
    // 魔数或版本不匹配即拒绝：防止旧版布局或伪造段被误解析。
    if (loader->magic != CPRISK_ARMOR_LOADER_MAGIC ||
        loader->version != CPRISK_ARMOR_ABI_VERSION)
        return -1;

    uint32_t count = loader->count;
    // 条目数上限防止 count * sizeof(entry) 溢出，也限制后续分配规模。
    if (count > CPRISK_MAX_ENTRY_COUNT)
        return -1;
    size_t entries_base = sizeof(struct cprisk_armor_loader_header);
    size_t entries_sz = (size_t)count * sizeof(struct cprisk_armor_loader_entry);
    // 描述符必须完全落在 section 内；不足则视为截断。
    if (entries_base + entries_sz > (size_t)sec_sz)
        return -1;

    *count_out = count;
    return 0;
}

/// 在已加载的 Mach-O 命令中查找 entry 指向的 segment/section，并校验对齐与权限。
/// - 成功时 out 持有指向头部内描述的借用指针；失败返回 -1。
/// - 要求 vm_addr/size 页对齐、vm_addr 与 section.addr 完全相等、目标段可写。
/// - 遍历时对每条 load command 做剩余长度与 cmdsize 校验，避免越界读取。
/// - 线程安全：只读头部，可并发调用。
static int cprisk_resolve_loader_target(
    const struct mach_header_64 *hdr,
    intptr_t slide,
    const struct cprisk_armor_loader_entry *ent,
    struct cprisk_loader_target *out
) {
    if (!hdr || !ent || !out || ent->size == 0)
        return -1;

    char segment_name[17] = {0};
    char section_name[17] = {0};
    if (cprisk_copy_fixed_name_l(ent->segment_name, segment_name) != 0 ||
        cprisk_copy_fixed_name_l(ent->section_name, section_name) != 0)
        return -1;

    const size_t page_size = cprisk_system_page_size_i();
    // 页对齐与命令区大小是后续 mprotect/指针运算的前提，任一不满足直接拒绝。
    if (page_size < sizeof(struct mach_header_64) ||
        ent->vm_addr % page_size != 0u || ent->size % page_size != 0u ||
        hdr->sizeofcmds > page_size - sizeof(struct mach_header_64))
        return -1;
    const uint8_t *cursor = (const uint8_t *)(hdr + 1);
    const uint8_t *end = (const uint8_t *)hdr + sizeof(struct mach_header_64) + hdr->sizeofcmds;
    // cursor/end 界定 load command 区；每条命令都必须在 end 之前完整结束。
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        size_t remaining = (size_t)(end - cursor);
        if (remaining < sizeof(*lc))
            return -1;
        // cmdsize 必须至少容纳命令头且不超过剩余空间，否则停止解析（不信任后续数据）。
        if (lc->cmdsize < sizeof(*lc) || lc->cmdsize > remaining)
            break;
        if (lc->cmd == LC_SEGMENT_64) {
            if (lc->cmdsize < sizeof(struct segment_command_64))
                return -1;
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)cursor;
            size_t seg_sz = sizeof(struct segment_command_64);
            size_t sect_sz = (size_t)seg->nsects * sizeof(struct section_64);
            // nsects * sizeof(section_64) 必须无溢出且不超出本条命令长度。
            if (sect_sz / sizeof(struct section_64) != (size_t)seg->nsects ||
                seg_sz + sect_sz > (size_t)lc->cmdsize) {
                cursor += lc->cmdsize;
                continue;
            }
            // 只接受名称完全匹配（16 字节定长比较）的段/节，避免前缀混淆。
            if (strncmp(seg->segname, segment_name, 16) == 0) {
                const struct section_64 *sections =
                    (const struct section_64 *)(cursor + sizeof(*seg));
                for (uint32_t s = 0; s < seg->nsects; s++) {
                    const struct section_64 *sec = &sections[s];
                    if (strncmp(sec->sectname, section_name, 16) != 0)
                        continue;
                    // 描述符中的地址/长度必须与当前映像中的 section 一致，防止被重定向到其他内存。
                    if (ent->vm_addr != sec->addr)
                        return -1;
                    if (ent->size > sec->size)
                        return -1;
                    // 目标段必须原本可写；否则后续无法原地解密，直接判定描述符不可信。
                    if ((seg->initprot & VM_PROT_WRITE) == 0)
                        return -1;

                    out->segment = seg;
                    out->section = sec;
                    out->slide = slide;
                    return 0;
                }
            }
        }
        cursor += lc->cmdsize;
    }

    return -1;
}

// 把描述符中的链接时地址转换为运行时地址：vm_addr + slide（范围已由调用方校验）。
static uint8_t *cprisk_target_ptr_l(
    const struct cprisk_loader_target *target,
    const struct cprisk_armor_loader_entry *ent
) {
    if (!target || !ent)
        return NULL;
    return (uint8_t *)((uintptr_t)ent->vm_addr + target->slide);
}

// 分块大小 64KB：限制密钥流与临时缓冲的峰值内存，同时保持缓存友好。
#define CPRISK_XOR_CHUNK_SIZE (64 * 1024)  /* 64KB chunks to limit peak memory */

/// 原地 XOR 加/解密：密钥流为 SHA-256 哈希链（见 cprisk_keystream_at_l）。
/// - target/sz/key 非空；nonce 允许为 NULL 当 nonce_len==0。
/// - 返回 0 成功，-1 表示参数非法或分配失败（此时 target 内容不变）。
/// - 线程安全：无全局状态；但同一区域不可被并发调用。
/// - 每块生成的密钥流用后清零，分块结果与整段一次性生成一致。
int cprisk_armor_xor_region(uint8_t *target, size_t sz, uint32_t key_id,
                               const uint8_t *nonce, size_t nonce_len,
                               const uint8_t *key) {
    if (!target || sz == 0 || !key)
        return -1;

    // 块缓冲按 min(剩余长度, 64KB) 分配；小块解密不会浪费 64KB。
    size_t chunk_sz = (sz < CPRISK_XOR_CHUNK_SIZE) ? sz : CPRISK_XOR_CHUNK_SIZE;
    uint8_t *ks = NULL;
    ks = (uint8_t *)malloc(chunk_sz);
    if (!ks)
        return -1;

    size_t off = 0;
    while (off < sz) {
        size_t todo = sz - off;
        if (todo > chunk_sz)
            todo = chunk_sz;

        // 逐块从同一 byte_offset 生成密钥流，保证与整段一次性生成的结果一致。
        cprisk_keystream_at_l(key, key_id, nonce, nonce_len, off, ks, todo);
        for (size_t i = 0; i < todo; i++)
            target[off + i] ^= ks[i];

        cprisk_secure_zero(ks, todo);
        off += todo;
    }

    cprisk_secure_zero(ks, chunk_sz);
    free(ks);
    return 0;
}

// 计算 target 起 sz 字节所覆盖的完整页范围；返回 0 时 page/span 有效。
static int cprisk_page_span_l(uint8_t *target, size_t sz,
                               void **page_out, size_t *len_out) {
    return cprisk_system_page_span_i(target, sz, page_out, len_out);
}

/// 按登记顺序的逆序回滚已置为 PROT_NONE 的条目：恢复可写、异或回密文、解除 mlock。
/// - 回滚使用全局 s_ldr_key 与条目 nonce 重新异或（此路径不区分 v2/v3 密钥）。
/// - 单步失败不中断：回滚尽力而为，完整性由 poison 通道负责。
/// - 调用方必须持有 s_loader_mutex。
static void cprisk_rollback_l(
    const struct mach_header_64 *hdr,
    intptr_t slide,
    const struct cprisk_armor_loader_entry *applied,
    uint32_t applied_count
) {
    while (applied_count > 0) {
        const struct cprisk_armor_loader_entry *ent = &applied[applied_count - 1];
        struct cprisk_loader_target target;
        if (cprisk_resolve_loader_target(hdr, slide, ent, &target) == 0) {
            uint8_t *ptr = cprisk_target_ptr_l(&target, ent);
            if (ptr) {
                void *page = NULL;
                size_t span = 0;
                if (cprisk_page_span_l(ptr, (size_t)ent->size, &page, &span) == 0) {
                    if (page && span > 0) {
                        // 回滚前先恢复读写权限，否则异或写会触发 EXC_BAD_ACCESS。
                        (void)cprisk_hidden_mprotect(page, span, PROT_READ | PROT_WRITE);
                    }
                    // 再次异或同一密钥流即还原为密文；nonce 长度固定为 ABI 规定的 NONCE_SIZE。
                    (void)cprisk_armor_xor_region(ptr, (size_t)ent->size, ent->key_id,
                                              ent->nonce, CPRISK_ARMOR_NONCE_SIZE,
                                              s_ldr_key);
                    if (page && span > 0)
                        cprisk_hidden_munlock(page, span);
                }
            }
        }
        applied_count--;
    }
}

/* ── public API ────────────────────────────────────────────────────── */

/// 初始化数据加载器：复制 32 字节根密钥并复位加载状态。
/// - key 必须非空且 key_len 恰为 CPRISK_ARMOR_KEY_SIZE，否则返回 -1。
/// - 线程安全：应在任何加载/JIT 解密之前调用；内部未加锁，调用方需保证时序。
/// - 失败语义：返回 -1 时全局状态不变。
int cprisk_init_data_loader(const uint8_t *key, size_t key_len) {
    if (!key || key_len != CPRISK_ARMOR_KEY_SIZE)
        return -1;
    memcpy(s_ldr_key, key, CPRISK_ARMOR_KEY_SIZE);
    s_ldr_ready = 1;
    s_ldr_loaded = 0;
    s_data_acc = 0;
    return 0;
}

/// 扫描并应用 loader 描述符：校验全部条目、锁定目标页、置 PROT_NONE，
/// 等待首次访问触发 JIT 解密。
/// - 返回已登记条目数（>=0）；-1 表示未初始化、头部/描述符非法或验证失败。
/// - 重复调用是幂等的：已加载时直接返回 0。
/// - 线程安全：由 s_loader_mutex 保护状态更新；可在初始化后并发调用。
/// - 失败语义：任一目标校验失败即 poison 完整性通道并返回 -1（fail-closed）。
int cprisk_load_protected_data(void) {
    if (!s_ldr_ready)
        return -1;
    // 已加载则直接返回 0：重复调用不重复改页权限。
    if (s_ldr_loaded)
        return 0;

    const struct mach_header_64 *hdr = cprisk_own_hdr_l();
    if (!hdr)
        return -1;

    unsigned long sec_sz = 0;
    // 描述符位于 __DATA 的 loader section；解析只做布局与上界校验。
    const uint8_t *sec = cprisk_find_section(
        hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_LOADER, &sec_sz);
    uint32_t count = 0;
    if (cprisk_parse_loader_descriptor(sec, sec_sz, &count) != 0)
        return -1;

    const struct cprisk_armor_loader_entry *entries =
        (const struct cprisk_armor_loader_entry *)(sec + sizeof(struct cprisk_armor_loader_header));
    // slide 由实际加载地址与 Mach-O 首选地址之差得到，用于把 vm_addr 映射到运行时地址。
    intptr_t slide = cprisk_compute_slide(hdr);

    // 先整体校验再动权限：任何条目非法都不应留下“部分页已改权限”的中间态。
    /* Validate every range before changing any permissions. Partial-page
     * sections would expose neighboring ciphertext or block unrelated data. */
    for (uint32_t i = 0; i < count; ++i) {
        struct cprisk_loader_target target;
        if (cprisk_resolve_loader_target(hdr, slide, &entries[i], &target) != 0) {
            cprisk_integrity_poison_data_loader_lane();
            return -1;
        }
    }

    // 临时数组先分配成功再替换全局指针，避免分配失败时破坏上一次的已加载状态。
    if (count > 0) {
        struct cprisk_armor_loader_entry *entries_tmp = NULL;
        int *flags_tmp = NULL;
        uint8_t *keys_tmp = NULL;
        entries_tmp = (struct cprisk_armor_loader_entry *)calloc((size_t)count, sizeof(struct cprisk_armor_loader_entry));
        flags_tmp = (int *)calloc((size_t)count, sizeof(*s_decrypted_flags));
        keys_tmp = (uint8_t *)calloc((size_t)count, CPRISK_ARMOR_KEY_SIZE);
        if (!entries_tmp || !flags_tmp || !keys_tmp) {
            free(entries_tmp);
            free(flags_tmp);
            free(keys_tmp);
            return -1;
        }
        // 在锁内替换数组并复位计数；旧数组可能来自上一次安装，先释放。
        pthread_mutex_lock(&s_loader_mutex);
        free(s_applied_entries);
        free(s_decrypted_flags);
        free(s_section_keys);
        s_applied_entries = entries_tmp;
        s_decrypted_flags = flags_tmp;
        s_section_keys = keys_tmp;
        s_applied_count = 0;
        s_entry_count = count;
        pthread_mutex_unlock(&s_loader_mutex);
    }

    // 每次安装都重置链式状态与完整性累加器，保证派生从根密钥重新开始。
    s_data_acc = 0;
    s_chain_initialized = 0;
    cprisk_secure_zero(s_prev_section_key, sizeof(s_prev_section_key));

    // 预计算每个条目的会话密钥：JIT 缺页可能乱序发生，不能依赖“按顺序解密”。
    /* Precompute per-entry chained keys to allow out-of-order JIT faults. */
    if (s_section_keys && count > 0) {
        uint8_t parent_key[CPRISK_ARMOR_KEY_SIZE];
        memcpy(parent_key, s_ldr_key, CPRISK_ARMOR_KEY_SIZE);
        for (uint32_t i = 0; i < count; i++) {
            const struct cprisk_armor_loader_entry *ent = &entries[i];
            uint8_t *key_slot = s_section_keys + (size_t)i * CPRISK_ARMOR_KEY_SIZE;
            // v3 条目用链式密钥（父密钥 = 上一条 v3 的派生结果）；v2 条目直接复用全局密钥。
            if (cprisk_is_v3_entry(ent)) {
                uint32_t sec_idx, chain_depth;
                cprisk_read_v3_fields(ent, &sec_idx, &chain_depth);
                // 深度 0 视为 1，避免生产端漏填导致密钥层级与预期不一致。
                if (chain_depth == 0) chain_depth = 1;
                cprisk_armor_derive_chained_key(parent_key, sec_idx, ent->nonce,
                                          CPRISK_ARMOR_NONCE_SIZE, (uint8_t)chain_depth,
                                          key_slot);
                memcpy(parent_key, key_slot, CPRISK_ARMOR_KEY_SIZE);
                s_chain_initialized = 1;
            } else {
                memcpy(key_slot, s_ldr_key, CPRISK_ARMOR_KEY_SIZE);
            }
        }
        cprisk_secure_zero(parent_key, sizeof(parent_key));
    }

    // 第二阶段逐个锁定并置 PROT_NONE：页内容保持密文，首次取指/读取会触发缺页处理。
    for (uint32_t i = 0; i < count; i++) {
        const struct cprisk_armor_loader_entry *ent = &entries[i];
        struct cprisk_loader_target target;
        if (cprisk_resolve_loader_target(hdr, slide, ent, &target) != 0) {
            continue;
        }

        uint8_t *ptr = cprisk_target_ptr_l(&target, ent);
        if (!ptr) {
            continue;
        }

        void *page = NULL;
        size_t span = 0;
        if (cprisk_page_span_l(ptr, (size_t)ent->size, &page, &span) != 0)
            continue;
        if (page && span > 0) {
            // mlock 防止敏感页被换出；即使 mprotect 失败也要在错误路径 munlock，避免锁计数泄漏。
            (void)cprisk_hidden_mlock(page, span);
            if (cprisk_hidden_mprotect(page, span, PROT_NONE) != 0) {
                cprisk_integrity_poison_data_loader_lane();
                cprisk_hidden_munlock(page, span);
            }
        }

        // 只有成功置为 PROT_NONE 的条目才登记为“已应用”，回滚/卸载时按此清单处理。
        pthread_mutex_lock(&s_loader_mutex);
        if (s_applied_entries && s_decrypted_flags && s_applied_count < count) {
            memcpy(&s_applied_entries[s_applied_count], ent, sizeof(*ent));
            s_applied_count++;
        }
        pthread_mutex_unlock(&s_loader_mutex);
    }

    // 内存守卫状态在每次重新加载时重置，避免沿用旧页地址。
    cprisk_secure_zero(&s_guard_state, sizeof(s_guard_state));

    // 把同一根密钥交给 __TEXT 页加密模块；两套机制共享 loader key。
    cprisk_text_encrypt_install(s_ldr_key);

    // 标记加载完成后再做调试器检测，确保即使被 poison 也保留一致的加载状态。
    s_ldr_loaded = 1;

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    // 被调试时污染完整性累加器并标记通道：下游密钥派生会得到错误材料但不会崩溃。
    /* Poison data accumulator under debugger — downstream key derivation
       silently produces wrong material. */
    /* Dual-detector (issue 33): sysctl-based + redundant. */
    if (cprisk_is_being_traced_redundant() || cprisk_is_being_traced()) {
        s_data_acc ^= 0xDEADBEEFCAFEBABEULL;
        cprisk_integrity_poison_data_loader_lane();
    }
#endif

    return (int)s_applied_count;
}

/// 处理一次缺页：若 fault_addr 落在受保护条目内，则验 MAC、解密并把页恢复为可读可执行。
/// - 返回 1 表示该地址已处理（已解密或已是毒页），0 表示不属于本模块或处理失败。
/// - 参数 fault_addr 为触发异常的运行时地址，允许为任意值。
/// - 线程安全：与加载/卸载共用 s_loader_mutex；异常处理上下文中不可重入。
/// - 失败语义：任一校验失败都将页恢复 PROT_NONE/毒化并返回 0，绝不留下半解密状态。
int cprisk_jit_decrypt_page(void *fault_addr) {
    // 先尝试 __TEXT 页解密；命中则不再走数据段逻辑。
    if (cprisk_text_jit_decrypt(fault_addr))
        return 1;

    pthread_mutex_lock(&s_loader_mutex);
    // 未加载或状态未就绪时直接返回 0，让上层按未处理继续。
    if (!s_ldr_loaded || !s_applied_entries || !s_decrypted_flags) {
        pthread_mutex_unlock(&s_loader_mutex);
        return 0;
    }

    // 每次缺页都重新解析头部/slide：卸载后旧指针不可信。
    const struct mach_header_64 *hdr = cprisk_own_hdr_l();
    if (!hdr) {
        pthread_mutex_unlock(&s_loader_mutex);
        return 0;
    }
    intptr_t slide = cprisk_compute_slide(hdr);

    // 遍历已应用条目，找到覆盖 fault_addr 的页；同一页只处理一次。
    for (uint32_t i = 0; i < s_applied_count; i++) {
        const struct cprisk_armor_loader_entry *ent = &s_applied_entries[i];
        struct cprisk_loader_target target;
        if (cprisk_resolve_loader_target(hdr, slide, ent, &target) != 0)
            continue;

        uint8_t *ptr = cprisk_target_ptr_l(&target, ent);
        if (!ptr) continue;

        void *page = NULL;
        size_t span = 0;
        if (cprisk_page_span_l(ptr, (size_t)ent->size, &page, &span) != 0)
            continue;

        if ((uintptr_t)fault_addr >= (uintptr_t)page && (uintptr_t)fault_addr < (uintptr_t)page + span) {
            // 已解密页不应再触发缺页；返回 1 表示无需重复处理。
            if (s_decrypted_flags[i]) {
                pthread_mutex_unlock(&s_loader_mutex);
                return 1;
            }

            // 必须先把页恢复为可读写再读取密文：此时页是 PROT_NONE，直接读会产生嵌套异常。
            /* Restore read access BEFORE touching ciphertext; the page is
             * PROT_NONE at this point — any user-space read without this
             * would trigger a nested EXC_BAD_ACCESS inside the handler. */
            if (cprisk_hidden_mprotect(page, span, PROT_READ | PROT_WRITE) != 0) {
                pthread_mutex_unlock(&s_loader_mutex);
                return 0;
            }

            /* Determine which key to use: v3 chained key or v2 global key */
            // v3 使用预计算的 section key；v2 回退到全局 loader 密钥。
            uint8_t section_key[CPRISK_ARMOR_KEY_SIZE];
            const uint8_t *decrypt_key;
            if (cprisk_is_v3_entry(ent) && s_section_keys && i < s_entry_count) {
                memcpy(section_key, s_section_keys + (size_t)i * CPRISK_ARMOR_KEY_SIZE, CPRISK_ARMOR_KEY_SIZE);
                decrypt_key = section_key;
            } else {
                /* v2 backward compatibility: use global loader key */
                decrypt_key = s_ldr_key;
            }

            // 先验 MAC 再解密：MAC 覆盖密文，任何篡改都会在写明文之前被拒绝。
            /* Verify CPRisk-MAC-SHA256(key, nonce || ciphertext) before decrypting */
            {
                // 计算 MAC 消息长度前防止 size + NONCE_SIZE 溢出。
                if (ent->size > SIZE_MAX - CPRISK_ARMOR_NONCE_SIZE) {
                    if (cprisk_hidden_mprotect(page, span, PROT_NONE) != 0) {
                        cprisk_integrity_poison_data_loader_lane();
                    }
                    pthread_mutex_unlock(&s_loader_mutex);
                    return 0;
                }
                // 规范编码：section_index/nonce_len/ct_len 均按小端写入，且把长度本身纳入 MAC，
                // 使截断、扩展与跨 section 置换都会改变标签。
                /*
                 * CPRisk-MAC scope binds (section_index, nonce_len, nonce,
                 * ct_len, ciphertext) — must match the canonical encoding
                 * in DataSegmentEncryptor.swift. Without these length
                 * prefixes and the section_index binding, two sections
                 * with identical encrypted payloads produced identical
                 * CPRisk-MACs (transposable) and a truncation/extension could
                 * find a matching length pair.
                 *
                 * Wire layout (little-endian):
                 *   u32 section_index | u32 nonce_len | nonce[nonce_len] |
                 *   u32 ct_len        | ciphertext[ct_len]
                 */
                const size_t mac_msg_len =
                    4u + 4u + (size_t)CPRISK_ARMOR_NONCE_SIZE + 4u + (size_t)ent->size;
                uint8_t *mac_msg = (uint8_t *)malloc(mac_msg_len);
                // 分配失败时恢复 PROT_NONE 并返回 0，保持 fail-closed。
                if (!mac_msg) {
                    if (cprisk_hidden_mprotect(page, span, PROT_NONE) != 0) {
                        cprisk_integrity_poison_data_loader_lane();
                    }
                    pthread_mutex_unlock(&s_loader_mutex);
                    return 0;
                }
                size_t mp = 0u;
                mac_msg[mp++] = (uint8_t)(ent->section_index      );
                mac_msg[mp++] = (uint8_t)(ent->section_index >>  8);
                mac_msg[mp++] = (uint8_t)(ent->section_index >> 16);
                mac_msg[mp++] = (uint8_t)(ent->section_index >> 24);
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
                // 用 CPRisk-MAC（带密钥 SHA-256）计算标签，再与描述符中的 mac_tag 做常量时间比较。
                cprisk_mac_sha256(decrypt_key, CPRISK_ARMOR_KEY_SIZE,
                                   mac_msg, mac_msg_len, computed_mac);
                cprisk_secure_zero(mac_msg, mac_msg_len);
                free(mac_msg);
                if (cprisk_mac_verify(ent->mac_tag, computed_mac,
                                       CPRISK_ARMOR_HASH_SIZE) != 0) {
                    cprisk_secure_zero(computed_mac, sizeof(computed_mac));
                    if (cprisk_hidden_mprotect(page, span, PROT_NONE) != 0) {
                        cprisk_integrity_poison_data_loader_lane();
                    }
                    pthread_mutex_unlock(&s_loader_mutex);
                    return 0;
                }
                cprisk_secure_zero(computed_mac, sizeof(computed_mac));
            }
            // MAC 通过后仍要检查 nonce 是否被复用于不同密文；复用等同于密钥流泄漏。
            /* Nonce-reuse refusal (issue 20): same (key, nonce) with a
             * different ciphertext means the XOR keystream was reused.
             * Refuse exactly like a MAC failure. */
            if (cprisk_data_nonce_reuse_check_i(decrypt_key, ent->key_id,
                                                ent->nonce, ptr,
                                                (size_t)ent->size) != 0) {
                cprisk_integrity_poison_data_loader_lane();
                if (cprisk_hidden_mprotect(page, span, PROT_NONE) != 0) {
                    cprisk_integrity_poison_data_loader_lane();
                }
                pthread_mutex_unlock(&s_loader_mutex);
                return 0;
            }
            // 原地异或解密；成功后还要用 content_hash 再确认明文一致。
            if (cprisk_armor_xor_region(ptr, (size_t)ent->size, ent->key_id,
                                    ent->nonce, CPRISK_ARMOR_NONCE_SIZE,
                                    decrypt_key) == 0) {
                // content_hash 是明文的 SHA-256：它同时作为完整性累加器的输入，便于跨模块汇总。
                uint8_t actual_h[CPRISK_SHA256_DIGEST_LENGTH];
                uint8_t diff[CPRISK_SHA256_DIGEST_LENGTH];
                cprisk_sha256(ptr, (size_t)ent->size, actual_h);
                for (int k = 0; k < CPRISK_SHA256_DIGEST_LENGTH; k++)
                    diff[k] = actual_h[k] ^ ent->content_hash[k];

                uint64_t actual_v = 0;
                uint64_t diff_v = 0;
                memcpy(&actual_v, actual_h, sizeof(actual_v));
                memcpy(&diff_v, diff, sizeof(diff_v));
                // 把解密结果哈希与差异值混入累加器；即使哈希不匹配也留下可观测痕迹。
                s_data_acc ^= cprisk_rotl64_l(actual_v, ent->key_id % 64) ^ diff_v;

                // 明文哈希不匹配：立即异或回密文、恢复 PROT_NONE 并返回失败。
                if (memcmp(actual_h, ent->content_hash, CPRISK_SHA256_DIGEST_LENGTH) != 0) {
                    (void)cprisk_armor_xor_region(ptr, (size_t)ent->size, ent->key_id,
                                              ent->nonce, CPRISK_ARMOR_NONCE_SIZE,
                                              decrypt_key);
                    if (cprisk_hidden_mprotect(page, span, PROT_NONE) != 0) {
                        cprisk_integrity_poison_data_loader_lane();
                    }
                    pthread_mutex_unlock(&s_loader_mutex);
                    return 0;
                }

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
                // 被调试时故意翻转前 4 字节：数据看似已解密但内容错误，增加动态提取成本。
                /* Perturb decrypted plaintext under debugger — data looks
                   decrypted but content is silently wrong. */
                /* Dual-detector (issue 33): sysctl-based + redundant. */
                if (cprisk_is_being_traced_redundant() || cprisk_is_being_traced()) {
                    for (size_t pi = 0; pi < 4 && pi < (size_t)ent->size; pi++)
                        ptr[pi] ^= 0x01;
                    cprisk_integrity_poison_data_loader_lane();
                }
#endif

                // 只有全部校验通过才标记已解密，并恢复为只读（随后再叠加执行权限/守卫）。
                s_decrypted_flags[i] = 1;
                if (cprisk_hidden_mprotect(page, span, PROT_READ) != 0) {
                    cprisk_integrity_poison_data_loader_lane();
                }

                // 交给内存守卫登记页范围，后续越界/写入可被陷阱捕获。
                cprisk_protect_decrypted_pages(ptr, (size_t)ent->size);
                cprisk_install_memory_trap(ptr, (size_t)ent->size, &s_guard_state);
                pthread_mutex_unlock(&s_loader_mutex);
                return 1;
            } else {
                // 异或失败（参数/分配错误）：恢复 PROT_NONE，保持“未解密”状态。
                if (cprisk_hidden_mprotect(page, span, PROT_NONE) != 0) {
                    cprisk_integrity_poison_data_loader_lane();
                }
                pthread_mutex_unlock(&s_loader_mutex);
                return 0;
            }
        }
    }
    pthread_mutex_unlock(&s_loader_mutex);
    return 0;
}

// 返回数据段解密过程中累积的完整性值；0 表示尚未解密或已被重置。
uint64_t cprisk_get_data_integrity_accumulator(void) {
    return s_data_acc;
}

// 返回 1 表示本次加载至少执行过一次 v3 链式密钥派生。
int cprisk_get_chain_status(void) {
    return s_chain_initialized;
}

/// 卸载数据段保护：逆序恢复页权限、对已解密页重新加密、解除 mlock 并清零所有密钥。
/// - 无参数、无返回值；可重复调用（未加载时仅清理状态）。
/// - 线程安全：持有 s_loader_mutex；必须先停掉 __TEXT 模块与内存陷阱。
/// - 失败语义：单页处理失败不中断整体卸载，残留页保持当时的保护状态。
void cprisk_unload_protected_data(void) {
    // 先停用 __TEXT 页加密，避免卸载数据段后仍有人通过 JIT 路径访问共享状态。
    cprisk_text_encrypt_uninstall();

    // 移除内存陷阱后再改页权限，防止守卫把合法的重新加密写入当作违规。
    cprisk_remove_memory_trap(&s_guard_state);

    pthread_mutex_lock(&s_loader_mutex);
    const struct mach_header_64 *hdr = cprisk_own_hdr_l();
    if (hdr && s_ldr_loaded && s_applied_entries && s_decrypted_flags) {
        intptr_t slide = cprisk_compute_slide(hdr);
        // 逆序处理，与加载顺序相反：后登记的先恢复，便于排查部分失败。
        for (uint32_t i = s_applied_count; i > 0; i--) {
            const struct cprisk_armor_loader_entry *ent = &s_applied_entries[i - 1];
            struct cprisk_loader_target target;
            if (cprisk_resolve_loader_target(hdr, slide, ent, &target) != 0)
                continue;

            uint8_t *ptr = cprisk_target_ptr_l(&target, ent);
            if (!ptr)
                continue;

            void *page = NULL;
            size_t span = 0;
            if (cprisk_page_span_l(ptr, (size_t)ent->size, &page, &span) == 0) {
                // 恢复可写是重新异或的前提；未 JIT 解密的页也要 munlock，否则锁计数泄漏。
                /* Restore write permission before any mutation.
                 * Pages that were mlocked+PROT_NONE but never JIT-decrypted must
                 * also be unlocked here; without this, mlock is leaked and the
                 * pages remain unswappable after stop(). */
                if (page && span > 0) {
                    (void)cprisk_hidden_mprotect(page, span, PROT_READ | PROT_WRITE);
                }
                if (s_decrypted_flags[i - 1]) {
                    // 只有真正解密过的页才需要重新异或；选择与解密时相同的 v3/v2 密钥。
                    /* Page was JIT-decrypted: re-encrypt before releasing. */
                    const uint8_t *reencrypt_key = s_ldr_key;
                    uint8_t tmp_key[CPRISK_ARMOR_KEY_SIZE];
                    if (cprisk_is_v3_entry(ent) && s_section_keys && (i - 1) < s_entry_count) {
                        memcpy(tmp_key, s_section_keys + (size_t)(i - 1) * CPRISK_ARMOR_KEY_SIZE, CPRISK_ARMOR_KEY_SIZE);
                        reencrypt_key = tmp_key;
                    }
                    (void)cprisk_armor_xor_region(ptr, (size_t)ent->size, ent->key_id,
                                              ent->nonce, CPRISK_ARMOR_NONCE_SIZE,
                                              reencrypt_key);
                    cprisk_secure_zero(tmp_key, sizeof(tmp_key));
                }
                if (page && span > 0)
                    cprisk_hidden_munlock(page, span);
            }
        }
    }

    if (s_applied_entries) {
        free(s_applied_entries);
        s_applied_entries = NULL;
    }
    if (s_decrypted_flags) {
        free(s_decrypted_flags);
        s_decrypted_flags = NULL;
    }
    if (s_section_keys) {
        // 会话密钥属于敏感材料：释放前先整块清零。
        cprisk_secure_zero(s_section_keys, (size_t)s_entry_count * CPRISK_ARMOR_KEY_SIZE);
        free(s_section_keys);
        s_section_keys = NULL;
    }
    s_entry_count = 0;
    s_applied_count = 0;

    // 根密钥与链状态清零，防止卸载后仍可从内存转储恢复。
    cprisk_secure_zero(s_ldr_key, sizeof(s_ldr_key));
    cprisk_secure_zero(s_prev_section_key, sizeof(s_prev_section_key));
    s_ldr_ready = 0;
    s_ldr_loaded = 0;
    s_data_acc = 0;
    cprisk_reset_libc_fallback_used_mask();
    s_mprotect_direct_failure_count = 0u;
    s_mprotect_fallback_success_count = 0u;
    s_mprotect_consecutive_full_fail_streak = 0u;
    s_mprotect_tampered = 0;
    s_mprotect_fail_streak_threshold = CPRISK_MPROTECT_FULL_FAIL_STREAK_THRESHOLD;

    pthread_mutex_unlock(&s_loader_mutex);
}

// pthread_once 回调：恢复被加密的 Mach-O 头部字段；恢复失败则污染完整性通道。
static void cprisk_erase_macho_header_once(void) {
    /* Legacy path used to zero Mach-O header fields (including magic),
     * which is noisy and can break downstream tooling. The hardened path
     * restores encrypted header fields from __DATA.__swift5_mhsav when present.
     * If restore fails, fail-closed via poison without mutating the header. */
    int rc = cprisk_restore_macho_header();
    if (rc < 0)
        cprisk_integrity_poison_data_loader_lane();
}

// 对外入口：保证头部恢复最多执行一次；重复调用无副作用。
void cprisk_erase_macho_header(void) {
    (void)pthread_once(&s_erase_header_once, cprisk_erase_macho_header_once);
}
