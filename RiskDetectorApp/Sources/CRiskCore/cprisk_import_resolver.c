/*
 * CRiskCore - Import Table Encryption resolver for cprisk-armor ABI.
 *
 * Reads the encrypted import table from __DATA.__swift5_dyrel,
 * verifies CPRisk-MAC-SHA256 integrity, decrypts symbol names via
 * SHA256-based keystream, and resolves them via dlsym.
 *
 * Table layout:
 *   Header (16 bytes):
 *     uint32_t magic      = 0x43494D50 ("CPIM")
 *     uint32_t version    = 1
 *     uint32_t count      = number of symbols
 *     uint32_t reserved   = 0
 *   Index entries (48 bytes each):
 *     uint32_t data_offset   (relative to start of encrypted name data)
 *     uint32_t data_length   (byte length of encrypted name)
 *     uint8_t  nonce[8]      (random nonce used in CPRisk-MAC and keystream)
 *     uint8_t  mac_tag[32]  (CPRisk-MAC-SHA256 over nonce || plaintext_name)
 *   Encrypted name data (variable):
 *     Concatenated encrypted name bytes, in entry order.
 */

#include "include/CRiskCore.h"
#include "include/cprisk_macho.h"
#include "include/cprisk_dlsym.h"
#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <mach-o/dyld.h>

// 文件职责：解析 cprisk-armor 加密导入表，把“索引”还原为可调用符号地址。
// 流程：whitebox 派生密钥 → 定位 __DATA 加密表 → 校验头/索引边界 → SHA-256 密钥流
//   解密符号名 → CPRisk-MAC 校验 → 优先导出 trie、失败再 dlsym → 地址合法性复检 → 缓存。
// 索引语义：普通索引落在 [0, count)；>= CPRISK_SWIFT_BRIDGE_IMPORT_BASE 的高区间
//   不是表内索引，而是 Swift 桥接别名 cpra_NNNN 的稳定编号（见 resolve_swift_bridge_alias）。
// 失败语义：任何一步失败都返回 -1 且 *out_addr 保持 NULL（fail-closed）；
//   解析出可疑地址时额外向 watchdog 通道投毒。
// 线程模型：导入缓存由 s_import_cache_mutex_i 保护；密钥/明文只存在于栈并即时清零。

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

// 兼容性兜底：旧 SDK 头可能未导出 RTLD_DEFAULT；-2 是 dyld 约定的“默认搜索作用域”。
#ifndef RTLD_DEFAULT
#define RTLD_DEFAULT ((void *)(intptr_t)-2)
#endif

/*
 * Optional: compare dlsym(RTLD_DEFAULT) with export-trie resolution (cprisk_dlsym).
 * Mismatch → return NULL for this resolve (fail closed) without global poison,
 * to reduce false positives from DYLD interposition / tooling.
 */
// 编译期开关：iOS 真机默认开启 dlsym/trie 交叉校验，其余平台关闭。
// 关闭时只影响“额外交叉校验”，主解析路径仍然优先走导出 trie。
#ifndef CPRISK_IMPORT_DLSYM_TRIE_CROSSCHECK
#if defined(__APPLE__) && defined(TARGET_OS_IOS) && TARGET_OS_IOS && \
    (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
#define CPRISK_IMPORT_DLSYM_TRIE_CROSSCHECK 1
#else
#define CPRISK_IMPORT_DLSYM_TRIE_CROSSCHECK 0
#endif
#endif

/*
 * dlsym(RTLD_DEFAULT, …) is a high-value hook target: it can steer encrypted
 * imports to attacker stubs while leaving CPRisk-MAC/name decryption intact.
 * cprisk_dlsym() walks the Mach-O export trie from dyld_all_image_infos (no
 * libc dlsym). When trie resolution in known system dylibs yields a unique
 * address that disagrees with dlsym, fail closed.
 */
// 导出 trie 的符号名不带前导下划线（cprisk_dlsym 自己会补 '_'），
// 而解密出的 C 符号名可能自带 '_'，这里统一去掉，避免查成 "__symbol"。
static const char *cprisk_import_trie_sym_i(const char *name_buf) {
    if (!name_buf || name_buf[0] == '\0') {
        return NULL;
    }
    return (name_buf[0] == '_') ? (name_buf + 1) : name_buf;
}

// 允许作为“唯一导出”来源的系统 dylib 白名单。
// 用途有二：一是遍历它们找唯一地址，二是校验最终地址的 dladdr 归属；
// 只列系统库，避免把普通 App/注入库的同名导出当成可信来源。
static const char *const s_import_system_libs_i[] = {
    "libsystem_kernel.dylib",
    "libsystem_c.dylib",
    "libsystem_pthread.dylib",
    "libsystem_info.dylib",
    "libsystem_malloc.dylib",
    "libsystem_platform.dylib",
    "libsystem_blocks.dylib",
    "libsystem_asl.dylib",
    "libsystem_trace.dylib",
};

// 在白名单系统库里逐个用导出 trie 查同一符号。
// 若两个库给出不同地址，说明符号来源歧义（或其中一个被替换），置 AMBIGUOUS 并返回 NULL；
// 只看到一个唯一地址才置 TRIE_UNIQUE 并返回它；全部未命中返回 NULL 且不置位。
// 该函数不做地址合法性复检，复检由调用方统一完成。
static void *cprisk_import_resolve_via_export_trie_i(const char *name_buf, uint32_t *path_flags_out) {
    const char *sym = cprisk_import_trie_sym_i(name_buf);
    if (!sym || sym[0] == '\0') {
        return NULL;
    }

    void *seen = NULL;
    for (size_t i = 0; i < sizeof(s_import_system_libs_i) / sizeof(s_import_system_libs_i[0]); i++) {
        void *candidate = cprisk_dlsym(s_import_system_libs_i[i], sym);
        if (!candidate) {
            continue;
        }
        if (seen == NULL) {
            seen = candidate;
        } else if (seen != candidate) {
            if (path_flags_out) {
                *path_flags_out |= CPRISK_IMPORT_RESOLVE_PATH_TRIE_AMBIGUOUS;
            }
            return NULL;
        }
    }
    if (seen != NULL && path_flags_out) {
        *path_flags_out |= CPRISK_IMPORT_RESOLVE_PATH_TRIE_UNIQUE;
    }
    return seen;
}

// 把 dlsym(RTLD_DEFAULT) 结果与“唯一 trie 地址”比较：
// 只有 trie 唯一命中且地址不同才返回 NULL（该符号解析失败，fail-closed）；
// trie 无唯一结果时无法证伪，保留 dlsym 结果，减少 DYLD interposition 误报。
static void *cprisk_import_crosscheck_dlsym_vs_trie_i(
    const char *name_buf,
    void *rtld_addr
) {
    if (!rtld_addr || !name_buf) {
        return rtld_addr;
    }
    const void *seen = cprisk_import_resolve_via_export_trie_i(name_buf, NULL);
    if (seen != NULL && seen != (const void *)rtld_addr) {
        return NULL;
    }
    return rtld_addr;
}

// 测试钩子：对明文符号名预测本模块会走哪条解析路径，返回 PATH_* 位组合。
// 非 DEBUG 构建直接返回 0，避免在生产二进制里暴露解析策略。
// 返回值只用于测试断言，不参与运行期判决；NULL/空名返回 NONE。
uint32_t cprisk_test_import_resolve_strategy_for_symbol(const char *symbol_name) {
#if !defined(DEBUG) || !DEBUG
    /* Test hook: inert outside DEBUG builds (issue 18). */
    return 0;
#endif
    if (!symbol_name || symbol_name[0] == '\0') {
        return CPRISK_IMPORT_RESOLVE_PATH_NONE;
    }

    uint32_t flags = 0u;
    void *trie_addr = cprisk_import_resolve_via_export_trie_i(symbol_name, &flags);
    if (trie_addr != NULL) {
        return flags;
    }

    flags |= CPRISK_IMPORT_RESOLVE_PATH_RTLD_FALLBACK;
    void *rtld_addr = dlsym(RTLD_DEFAULT, symbol_name);
    if (rtld_addr != NULL &&
        cprisk_import_crosscheck_dlsym_vs_trie_i(symbol_name, rtld_addr) == NULL) {
        flags |= CPRISK_IMPORT_RESOLVE_PATH_CROSSCHECK_FAIL;
    }
    return flags;
}

// 诊断：比较 mprotect 的 dlsym 结果与 libsystem_kernel 导出 trie 结果。
// 返回 -1 = 任一路解析失败（无法比较）；0 = 一致；1 = 不一致（可能被 hook）。
// 该函数不投毒、不改状态，供启动早期快速自检使用。
int cprisk_verify_mprotect_dlsym_matches_export_trie(void) {
    void *a = dlsym(RTLD_DEFAULT, "mprotect");
    void *b = cprisk_dlsym("libsystem_kernel.dylib", "mprotect");
    if (!a || !b) {
        return -1;
    }
    return (a == b) ? 0 : 1;
}

/* CPRISK_IMPORT_MAGIC: "CPIM" = 0x43494D50 */
// 表头 16 字节 = magic + version + count + reserved；索引项 48 字节 =
// data_offset(4) + data_length(4) + nonce(8) + mac_tag(32)。
// 这些尺寸与 Swift 侧打包器逐字节绑定，不能单独修改；version 不匹配即拒绝解析。
#define CPRISK_IMPORT_MAGIC     0x43494D50
#define CPRISK_IMPORT_VERSION   1
#define CPRISK_IMPORT_INDEX_SZ  48
#define CPRISK_IMPORT_HDR_SZ     16
// 缓存槽数固定 32：槽位 = symbol_index % 32，冲突时直接覆盖（见 cache_store）。
// 小容量换取“无堆分配 + 常数时间查找”，偶发覆盖只会导致重新解析。
#define CPRISK_IMPORT_CACHE_SLOTS 32u

// 缓存项：symbol_index 用于识别槽位冲突；addr 是解析结果；tag 是用当前白盒密钥
// 对 (index, addr, 表指纹) 计算的 32 位 MAC，防止攻击者直接改内存伪造缓存；
// path_flags 必须随 addr 一起保存，因为 owner 校验规则依赖“是否唯一 trie 命中”。
// valid 最后写入，读者只在 valid 非 0 时信任其余字段。
typedef struct cprisk_import_cache_entry_i {
    uint32_t symbol_index;
    uintptr_t addr;
    uint32_t tag;
    uint32_t path_flags;
    uint8_t valid;
    uint8_t _reserved[3];
} cprisk_import_cache_entry_i;

// 缓存数组为进程级共享；锁只保护数组读写，不覆盖 dladdr/dlsym 等外部调用。
static pthread_mutex_t s_import_cache_mutex_i = PTHREAD_MUTEX_INITIALIZER;
static cprisk_import_cache_entry_i s_import_cache_i[CPRISK_IMPORT_CACHE_SLOTS];

// 用 dladdr 取地址所属镜像路径，判断是否包含任一预期系统库名。
// 只在“trie 唯一命中”时使用：此时来源应当是系统库，若实际归属不符，视为地址被替换。
// 返回 1 = 归属匹配；0 = 不匹配或 dladdr 失败（失败按不匹配处理，偏保守）。
static int cprisk_import_symbol_owner_matches_i(
    const void *addr,
    const char *const *expected_libs,
    size_t expected_count
) {
    Dl_info info;
    if (addr == NULL || expected_libs == NULL || expected_count == 0u) {
        return 0;
    }
    memset(&info, 0, sizeof(info));
    if (dladdr(addr, &info) == 0 || info.dli_fname == NULL) {
        return 0;
    }
    for (size_t i = 0u; i < expected_count; i++) {
        if (expected_libs[i] != NULL && strstr(info.dli_fname, expected_libs[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

// 解析结果的三重复检，任一失败返回 -1（调用方随后投毒并拒绝该地址）：
//   1) 地址必须落在某个已加载镜像的可执行段内（拒绝裸映射/堆上 trampoline）；
//   2) 入口 16 字节不能是可疑跳板前缀（拒绝 Frida/Gum 的 b/br/adrp 序列）；
//   3) 若来自“唯一 trie 命中”，其 dladdr 归属必须仍是白名单系统库。
// 注意：第 3 条只在 TRIE_UNIQUE 时执行，避免把合法的 DYLD interposition 一律判死。
static int cprisk_import_validate_resolved_addr_i(const void *addr, uint32_t path_flags) {
    if (addr == NULL) {
        return -1;
    }
    if (cprisk_addr_in_any_image_executable(addr) != 1) {
        return -1;
    }
    if (cprisk_scan_arm64_suspicious_trampoline_prefix(addr, 16u) != 0) {
        return -1;
    }
    if ((path_flags & CPRISK_IMPORT_RESOLVE_PATH_TRIE_UNIQUE) != 0u &&
        cprisk_import_symbol_owner_matches_i(
            addr,
            s_import_system_libs_i,
            sizeof(s_import_system_libs_i) / sizeof(s_import_system_libs_i[0])) == 0) {
        return -1;
    }
    return 0;
}

// 系统版本混合值：对 kern.osrelease 做 FNV-1a；不可读时返回固定常量。
// 仅用于给 timing 噪声加一点环境差异，不参与安全判定。
static uint32_t cprisk_import_os_mix_i(void) {
    char osrelease[128];
    size_t len = sizeof(osrelease);
    int err = 0;
    if (cprisk_sysctlbyname_direct("kern.osrelease", osrelease, &len, NULL, 0, &err) != 0 || len == 0) {
        return 0x7F4A7C15u;
    }
    uint32_t mix = 0x811C9DC5u;
    for (size_t i = 0; i < len && osrelease[i] != '\0'; i++) {
        mix ^= (uint32_t)(uint8_t)osrelease[i];
        mix *= 16777619u;
    }
    return mix;
}

// 镜像数量混合值：把“当前加载了多少镜像”折叠进噪声，进程布局变化时噪声也随之变化。
static uint32_t cprisk_import_dyld_mix_i(void) {
    const uint32_t image_count = _dyld_image_count();
    return (image_count << 11u) ^ (image_count >> 3u) ^ 0xA24BAED5u;
}

// 解析阶段的轻量时间噪声：读单调时钟后做 32..95 轮依赖数据的自旋。
// 目的不是密码学防护，而是让 dlsym 调用在时间维度上不那么规整，抬高远程
// 计时观测的难度；开销固定且很小（每符号一次）。
static void cprisk_import_timing_hook_i(uint32_t stage, uint32_t symbol_index) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return;
    }
    uint32_t mix = (uint32_t)ts.tv_nsec
        ^ cprisk_import_os_mix_i()
        ^ cprisk_import_dyld_mix_i()
        ^ (stage * 0x45D9F3Bu)
        ^ (symbol_index * 0x27D4EB2Du);
    volatile uint32_t sink = mix;
    const uint32_t spin = 32u + (mix & 0x3Fu);
    for (uint32_t i = 0; i < spin; i++) {
        sink ^= (sink << 5u) + (i * 0x9E37u);
    }
    (void)sink;
}

// 缓存完整性标签：MAC-SHA256(key, index || addr || table_fingerprint) 后截取前 4 字节。
// key 来自 whitebox，攻击者无法离线伪造；table_fingerprint 确保换表后旧缓存自动失效。
// 中间消息与摘要都清零，避免密钥派生材料残留在栈上。
static uint32_t cprisk_import_cache_tag_i(
    const uint8_t key[CPRISK_ARMOR_KEY_SIZE],
    uint32_t symbol_index,
    uintptr_t addr,
    uint32_t table_fingerprint
) {
    uint8_t msg[4 + sizeof(uintptr_t) + 4];
    memset(msg, 0, sizeof(msg));
    memcpy(msg, &symbol_index, sizeof(symbol_index));
    memcpy(msg + 4, &addr, sizeof(addr));
    memcpy(msg + 4 + sizeof(addr), &table_fingerprint, sizeof(table_fingerprint));

    uint8_t digest[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_mac_sha256(key, CPRISK_ARMOR_KEY_SIZE, msg, sizeof(msg), digest);
    uint32_t tag = 0u;
    memcpy(&tag, digest, sizeof(tag));
    cprisk_secure_zero(digest, sizeof(digest));
    cprisk_secure_zero(msg, sizeof(msg));
    return tag;
}

// 查缓存：锁内按 symbol_index 找槽并重算 tag，命中则拷贝 addr/path_flags 后立即解锁，
// 在锁外做地址复检（dladdr 等外部调用不应持锁）。
// 返回 1 = 命中且复检通过（*out_addr 已写）；0 = 未命中/标签不符/复检失败。
// 复检失败会向 watchdog 通道投毒并清除该槽，但清除前再次核对 index/addr/tag，
// 防止把并发写入的新条目误删（ABA）。
static int cprisk_import_cache_lookup_i(
    const uint8_t key[CPRISK_ARMOR_KEY_SIZE],
    uint32_t symbol_index,
    uint32_t table_fingerprint,
    void **out_addr
) {
    if (!out_addr)
        return 0;

    size_t matched_slot = CPRISK_IMPORT_CACHE_SLOTS;
    uintptr_t matched_addr = 0u;
    uint32_t matched_tag = 0u;
    uint32_t matched_path_flags = 0u;

    pthread_mutex_lock(&s_import_cache_mutex_i);
    for (size_t i = 0; i < CPRISK_IMPORT_CACHE_SLOTS; i++) {
        const cprisk_import_cache_entry_i *entry = &s_import_cache_i[i];
        if (!entry->valid || entry->symbol_index != symbol_index)
            continue;

        const uint32_t expected_tag = cprisk_import_cache_tag_i(
            key, symbol_index, entry->addr, table_fingerprint
        );
        if (expected_tag == entry->tag) {
            matched_slot = i;
            matched_addr = entry->addr;
            matched_tag = entry->tag;
            matched_path_flags = entry->path_flags;
            pthread_mutex_unlock(&s_import_cache_mutex_i);
            if (cprisk_import_validate_resolved_addr_i((const void *)matched_addr, matched_path_flags) == 0) {
                *out_addr = (void *)matched_addr;
                return 1;
            }
            cprisk_integrity_poison_watchdog_lane_now();
            pthread_mutex_lock(&s_import_cache_mutex_i);
            if (matched_slot < CPRISK_IMPORT_CACHE_SLOTS) {
                cprisk_import_cache_entry_i *mut = &s_import_cache_i[matched_slot];
                if (mut->valid &&
                    mut->symbol_index == symbol_index &&
                    mut->addr == matched_addr &&
                    mut->tag == matched_tag) {
                    memset(mut, 0, sizeof(*mut));
                }
            }
            pthread_mutex_unlock(&s_import_cache_mutex_i);
            return 0;
        }
    }
    pthread_mutex_unlock(&s_import_cache_mutex_i);
    return 0;
}

// 写缓存：先复检地址，不合格则投毒并放弃写入（绝不缓存可疑地址）。
// 槽位由 index % 32 决定，冲突时覆盖旧条目；tag 与 addr 一起计算/写入，
// 保证“读到 tag 正确”就意味着 addr/fingerprint 匹配当前密钥与表。
static void cprisk_import_cache_store_i(
    const uint8_t key[CPRISK_ARMOR_KEY_SIZE],
    uint32_t symbol_index,
    uint32_t table_fingerprint,
    void *addr,
    uint32_t path_flags
) {
    if (cprisk_import_validate_resolved_addr_i(addr, path_flags) != 0) {
        cprisk_integrity_poison_watchdog_lane_now();
        return;
    }

    const size_t slot = (size_t)(symbol_index % CPRISK_IMPORT_CACHE_SLOTS);
    const uint32_t tag = cprisk_import_cache_tag_i(
        key, symbol_index, (uintptr_t)addr, table_fingerprint
    );

    pthread_mutex_lock(&s_import_cache_mutex_i);
    s_import_cache_i[slot].symbol_index = symbol_index;
    s_import_cache_i[slot].addr = (uintptr_t)addr;
    s_import_cache_i[slot].tag = tag;
    s_import_cache_i[slot].path_flags = path_flags;
    s_import_cache_i[slot].valid = 1u;
    pthread_mutex_unlock(&s_import_cache_mutex_i);
}

// 用 whitebox 的 Domain-8 从全零种子派生导入表密钥。
// 刻意没有回退派生：白盒求值失败就清零输出并返回错误，让导入解析硬失败；
// 任何“确定性回退密钥”都会变成攻击者可稳定复现的弱路径。
static int cprisk_derive_import_key(uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]) {
    if (!out_key) return -1;

    uint8_t zero_seed[CPRISK_ARMOR_KEY_SIZE];
    memset(zero_seed, 0, sizeof(zero_seed));
    /* No fallback key derivation (issue 60/79): if the white-box
     * evaluation fails, import decryption HARD-FAILS. A deterministic
     * fallback key derived from runtime material would silently
     * substitute a weaker, always-available key path. */
    int rc = cprisk_whitebox_evaluate_domain(
        CPRISK_WHITEBOX_DOMAIN_IMPORT_ENCRYPTION,
        zero_seed,
        out_key
    );
    if (rc != 0)
        cprisk_secure_zero(out_key, CPRISK_ARMOR_KEY_SIZE);
    cprisk_secure_zero(zero_seed, sizeof(zero_seed));
    return rc;
}

/* ── Keystream derivation (matches Swift side) ──────────────────────── */

// 生成与 Swift 打包端一致的密钥流：material = key(32) || index_le32 || nonce(8) || counter_le64，
// SHA256(material) 逐块拼接。index 由调用方传 symbol_index+1（打包端从 1 开始计数），
// 该 +1 是格式契约，改动会导致所有符号名解密错误。
// 输出长度恰为 name_len，调用方需在事后清零。
static void derive_keystream(
    const uint8_t *key, uint32_t index,
    const uint8_t *nonce, size_t name_len,
    uint8_t *out_keystream
) {
    /* SHA256-based keystream:
     * Material: key || index(4) || nonce(8) || counter(8)
     * SHA256(material) repeated as needed. */
    uint8_t material[32 + 4 + 8 + 8];
    size_t mat_len = 0;

    memcpy(material, key, 32);
    mat_len = 32;

    material[mat_len++] = (uint8_t)(index & 0xFF);
    material[mat_len++] = (uint8_t)((index >> 8) & 0xFF);
    material[mat_len++] = (uint8_t)((index >> 16) & 0xFF);
    material[mat_len++] = (uint8_t)((index >> 24) & 0xFF);

    memcpy(material + mat_len, nonce, 8);
    mat_len += 8;

    size_t produced = 0;
    uint64_t counter = 0;

    while (produced < name_len) {
        memcpy(material + mat_len, &counter, 8);
        uint8_t hash[CPRISK_SHA256_DIGEST_LENGTH];
        cprisk_sha256(material, mat_len + 8, hash);

        size_t take = name_len - produced;
        if (take > CPRISK_SHA256_DIGEST_LENGTH)
            take = CPRISK_SHA256_DIGEST_LENGTH;

        memcpy(out_keystream + produced, hash, take);
        produced += take;
        counter += 1;
    }
}

/* ── Own Mach-O header (self-locating) ──────────────────────────────── */

// 自定位本 SDK 的 Mach-O 头：把本函数地址交给解析器，由它反查所属镜像。
// 不依赖 dyld API，避免 dlsym/dladdr 被 hook 后“找不到自己”的降级路径。
static const struct mach_header_64 *cprisk_own_hdr(void) {
    return cprisk_find_own_header((const void *)cprisk_own_hdr);
}

// 由 cprisk_swift_bridge_exports.c 提供：引用别名表，防止链接器把 cpra_NNNN 当作死代码剔除。
void cprisk_swift_bridge_force_link(void);

// Swift 桥接高区间解析：index >= CPRISK_SWIFT_BRIDGE_IMPORT_BASE（0x40000000）时，
// 索引不是加密表行号，而是“BASE + 序号”；序号 0..COUNT-1 一一对应
// cprisk_swift_bridge_exports.c 中的 cpra_0001..cpra_0126 别名。
// 不变量：BASE/COUNT 与 include/cprisk_swift_bridge.h 完全一致；别名只允许追加，
//   禁止重排或复用序号，否则已编译的 Swift 客户端会指到错误函数。
// 返回：0 = 成功写入 *out_addr；-1 = 序号越界、dlsym 序言被改写、别名名生成失败
//   或 dlsym 未找到；1 = 防御性拒绝（传入的 index 其实低于 BASE，不应发生）。
static int cprisk_resolve_swift_bridge_alias_i(uint32_t symbol_index, void **out_addr) {
    if (!out_addr || symbol_index < CPRISK_SWIFT_BRIDGE_IMPORT_BASE) {
        return 1;
    }

    // 先做区间归一化再查表：序号必须严格小于 COUNT，防止越界访问别名表。
    const uint32_t bridge_index = symbol_index - CPRISK_SWIFT_BRIDGE_IMPORT_BASE;
    if (bridge_index >= CPRISK_SWIFT_BRIDGE_IMPORT_COUNT) {
        return -1;
    }

    // 高区间最终仍要经 dlsym 取别名地址；序言被改写时直接失败，不把被 hook 的
    // 解析结果交给调用方（fail-closed）。
    if (cprisk_verify_dlsym_prologue() == 0) {
        return -1;
    }

    // 强制引用别名表：确保护航符号已被链接进镜像，否则 dlsym 找不到 cpra_NNNN。
    cprisk_swift_bridge_force_link();

    // 别名从 1 开始编号（cpra_0001 对应序号 0），格式固定为 4 位十进制；
    // 16 字节缓冲足够容纳 "cpra_" + 4 位 + NUL，snprintf 返回值用于检测截断。
    char alias_name[16];
    const int written = snprintf(
        alias_name,
        sizeof(alias_name),
        "cpra_%04u",
        (unsigned)(bridge_index + 1u)
    );
    if (written <= 0 || (size_t)written >= sizeof(alias_name)) {
        return -1;
    }

    void *addr = dlsym(RTLD_DEFAULT, alias_name);
    *out_addr = addr;
    return (addr != NULL) ? 0 : -1;
}

/* ── Main resolver ─────────────────────────────────────────────────── */

// 主入口：把导入索引解析成可调用地址。
// 返回值：0 = 成功（*out_addr 非 NULL）；-1 = 任何失败（*out_addr 保持 NULL）。
// 所有权：out_addr 由调用方提供，函数先写 NULL 再按成功路径覆盖。
// 线程安全：可并发调用；缓存有锁，密钥/明文为栈局部。
// 高区间语义：index >= BASE 直接走 Swift 桥接别名解析，不读加密表。
// 失败语义：表损坏、MAC 不符、地址复检失败、dlsym 序言被改写都 fail-closed。
int cprisk_resolve_import(uint32_t symbol_index, void **out_addr) {
    if (!out_addr) return -1;
    *out_addr = NULL;

    // 高区间不是表索引：先分流，避免用巨大 index 去计算表内偏移。
    if (symbol_index >= CPRISK_SWIFT_BRIDGE_IMPORT_BASE) {
        return cprisk_resolve_swift_bridge_alias_i(symbol_index, out_addr);
    }

    /* Import table is encrypted with WhiteBox Domain-8 key on the Swift side. */
    // 白盒密钥派生失败即整体失败，不做任何“默认密钥”降级。
    uint8_t key[CPRISK_ARMOR_KEY_SIZE];
    if (cprisk_derive_import_key(key) != 0) return -1;

    // 从自身 Mach-O 里定位加密段；找不到头/段都按失败处理并清零密钥。
    const struct mach_header_64 *hdr = cprisk_own_hdr();
    if (!hdr) {
        cprisk_secure_zero(key, sizeof(key));
        return -1;
    }

    unsigned long sec_sz = 0;
    const uint8_t *sec = cprisk_find_section(
        hdr,
        CPRISK_ARMOR_SEGMENT_DATA,
        CPRISK_ARMOR_SECTION_IMPORT_ENCRYPTED_TABLE,
        &sec_sz
    );

    if (!sec || sec_sz < CPRISK_IMPORT_HDR_SZ) {
        cprisk_secure_zero(key, sizeof(key));
        return -1;
    }

    /* Verify header */
    // 表头四字段按小端读取；magic/version 任一不符即拒绝（防止旧格式或伪造表）。
    uint32_t magic = 0;
    uint32_t version = 0;
    uint32_t count = 0;
    uint32_t reserved = 0;
    memcpy(&magic, sec, 4);
    memcpy(&version, sec + 4, 4);
    memcpy(&count, sec + 8, 4);
    memcpy(&reserved, sec + 12, 4);

    if (magic != CPRISK_IMPORT_MAGIC || version != CPRISK_IMPORT_VERSION || symbol_index >= count) {
        cprisk_secure_zero(key, sizeof(key));
        return -1;
    }

    // count 来自不可信段内容：先做乘法溢出检查，再验证索引表整体落在段内，
    // 防止 count 被改大后越界读取后续内存。
    if (count > (UINT32_MAX / CPRISK_IMPORT_INDEX_SZ)) {
        cprisk_secure_zero(key, sizeof(key));
        return -1;
    }
    const size_t index_table_size = (size_t)count * CPRISK_IMPORT_INDEX_SZ;
    const size_t index_table_end = CPRISK_IMPORT_HDR_SZ + index_table_size;
    if (index_table_end > sec_sz) {
        cprisk_secure_zero(key, sizeof(key));
        return -1;
    }

    // 表指纹把 magic/version/count/reserved/段大小折叠进缓存标签：
    // 表被替换或重打包后，即便 symbol_index 相同，旧缓存也会因标签不符而失效。
    const uint32_t table_fingerprint =
        magic ^
        (version << 7u) ^
        (count * 0x9E3779B1u) ^
        (reserved * 0x45D9F3Bu) ^
        (uint32_t)sec_sz;

    // 缓存命中即返回成功；此处同样先清零密钥再返回，保证任何出口都不留密钥。
    if (cprisk_import_cache_lookup_i(key, symbol_index, table_fingerprint, out_addr) != 0) {
        cprisk_secure_zero(key, sizeof(key));
        return 0;
    }

    /* Read index entry */
    // 索引项内部布局固定：offset(0..3)、length(4..7)、nonce(8..15)、mac(16..47)；
    // nonce/mac 是打包端写入的字段，解析器只按偏移读取，不做结构体映射以规避对齐问题。
    const uint8_t *idx = sec + CPRISK_IMPORT_HDR_SZ
                        + (uintptr_t)symbol_index * CPRISK_IMPORT_INDEX_SZ;

    uint32_t data_off = 0;
    uint32_t data_len = 0;
    memcpy(&data_off, idx, 4);
    memcpy(&data_len, idx + 4, 4);
    const uint8_t *nonce = idx + 8;
    const uint8_t *stored_mac = idx + 16;

    /* Encrypted name data starts after all index entries */
    // data_offset 是相对于“名称数据区起点”的偏移，不是相对段起点；
    // 若误用段起点会导致跨符号读取，后续 MAC 也许仍可能通过（同一密钥流），必须按格式解析。
    const uint8_t *encrypted_names_base = sec + index_table_end;
    const size_t encrypted_names_len = sec_sz - index_table_end;
    const uint8_t *encrypted_name = encrypted_names_base + data_off;

    /* Bounds check */
    // 先保证 offset 本身不越界，再保证 length 不越过剩余长度；两步都用减法形式，
    // 避免 data_off + data_len 的加法溢出。
    if ((size_t)data_off > encrypted_names_len ||
        (size_t)data_len > encrypted_names_len - (size_t)data_off) {
        cprisk_secure_zero(key, sizeof(key));
        return -1;
    }

    /* Decrypt symbol name */
    // 名称上限 512 字节：符号名远短于此，超长视为表损坏并拒绝；
    // 同时保证后续 MAC 输入缓冲（8 + 512）有确定上界。
    char name_buf[512];
    if (data_len >= sizeof(name_buf)) {
        cprisk_secure_zero(key, sizeof(key));
        return -1;
    }

    // 这里的 symbol_index + 1 必须与 Swift 打包端的计数起点一致（见 derive_keystream）。
    uint8_t ks[512];
    derive_keystream(key, symbol_index + 1, nonce, data_len, ks);

    for (uint32_t i = 0; i < data_len; i++) {
        name_buf[i] = (char)(encrypted_name[i] ^ ks[i]);
    }
    name_buf[data_len] = '\0';

    /* Verify CPRisk-MAC-SHA256 over nonce || plaintext_name.
     * CPRisk-MAC input = nonce (8 bytes) || plaintext_name. */
    // MAC 覆盖 nonce 与明文名：既绑定每次加密的随机性，也保证解密出的名字未被篡改；
    // 校验失败说明密钥错误或表被改写，必须清零后 fail-closed。
    uint8_t mac_input[8 + 512];
    memcpy(mac_input, nonce, 8);
    memcpy(mac_input + 8, name_buf, data_len);
    uint8_t computed_mac[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_mac_sha256(key, CPRISK_ARMOR_KEY_SIZE,
                       mac_input, 8 + data_len,
                       computed_mac);

    if (cprisk_mac_verify(stored_mac, computed_mac,
                            CPRISK_SHA256_DIGEST_LENGTH) != 0) {
        /* CPRisk-MAC mismatch — tampered or wrong key */
        cprisk_secure_zero(name_buf, data_len);
        cprisk_secure_zero(ks, data_len < sizeof(ks) ? data_len : sizeof(ks));
        cprisk_secure_zero(key, sizeof(key));
        cprisk_secure_zero(mac_input, sizeof(mac_input));
        cprisk_secure_zero(computed_mac, sizeof(computed_mac));
        return -1;
    }

    /*
     * Prefer export-trie resolution first: this avoids handing the recovered
     * plaintext symbol to hooked RTLD paths when a unique system export exists.
     */
    // 优先 trie：明文名不会传给可能被 hook 的 RTLD_DEFAULT，只有 trie 无唯一结果才回退。
    uint32_t resolve_path_flags = 0u;
    void *addr = cprisk_import_resolve_via_export_trie_i(name_buf, &resolve_path_flags);
    if (addr == NULL) {
        /* dlsym fallback — prologue must match early baseline before trusting RTLD_DEFAULT. */
        if (cprisk_verify_dlsym_prologue() == 0) {
            cprisk_secure_zero(name_buf, data_len);
            cprisk_secure_zero(ks, data_len < sizeof(ks) ? data_len : sizeof(ks));
            cprisk_secure_zero(key, sizeof(key));
            cprisk_secure_zero(mac_input, sizeof(mac_input));
            cprisk_secure_zero(computed_mac, sizeof(computed_mac));
            return -1;
        }
        // 序言检查已通过：标记回退路径、加一点时间噪声，再交给 RTLD_DEFAULT。
        // 该结果仍会经过下方统一地址复检，不会直接信任。
        resolve_path_flags |= CPRISK_IMPORT_RESOLVE_PATH_RTLD_FALLBACK;
        cprisk_import_timing_hook_i(1u, symbol_index);
        addr = dlsym(RTLD_DEFAULT, name_buf);
#if CPRISK_IMPORT_DLSYM_TRIE_CROSSCHECK
        addr = cprisk_import_crosscheck_dlsym_vs_trie_i(name_buf, addr);
        if (addr == NULL) {
            resolve_path_flags |= CPRISK_IMPORT_RESOLVE_PATH_CROSSCHECK_FAIL;
        }
#endif
    }
    // 两条解析路径共用同一出口：地址复检失败则投毒并丢弃结果；
    // 通过才允许写入缓存（cache_store 内部会再复检一次，防止 TOCTOU）。
    if (addr != NULL) {
        if (cprisk_import_validate_resolved_addr_i(addr, resolve_path_flags) != 0) {
            cprisk_integrity_poison_watchdog_lane_now();
            addr = NULL;
        } else {
            cprisk_import_cache_store_i(key, symbol_index, table_fingerprint, addr, resolve_path_flags);
        }
    }

    /* Clean up decrypted name before returning */
    // 单出口统一清零：明文名、密钥流、MAC 输入/结果、白盒密钥，避免残留在栈上。
    cprisk_secure_zero(name_buf, data_len);
    cprisk_secure_zero(ks, data_len < sizeof(ks) ? data_len : sizeof(ks));
    cprisk_secure_zero(mac_input, sizeof(mac_input));
    cprisk_secure_zero(computed_mac, sizeof(computed_mac));
    cprisk_secure_zero(key, sizeof(key));

    *out_addr = addr;
    return (addr != NULL) ? 0 : -1;
}
