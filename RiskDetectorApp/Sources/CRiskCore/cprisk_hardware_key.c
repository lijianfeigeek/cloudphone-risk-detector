// cprisk_hardware_key.c — 第二层设备密钥派生（device-bound key derivation）。
// 链路位置：rootKey（上层提供）→ deviceKey = CPRisk-MAC(rootKey, deviceSalt) → 交给会话层。
// 设备盐来源：macOS 用 IOPlatformUUID + Keychain，iOS 用系统指纹 + Keychain，均无静态回退。
// 线程模型：Keychain/IOKit 读取可并发，s_device_bound_ready 为原子标志，盐本身不缓存。
// 失败语义：平台服务不可用时返回 -1 硬失败，绝不使用公开常量盐伪装设备绑定。
/*
 * cprisk_hardware_key.c — Layer-2 device-key derivation for Hybrid KDF.
 *
 * Three-layer key derivation:
 *   Layer 1: rootKey       (CLI provided)
 *   Layer 2: deviceKey    = CPRisk-MAC(rootKey, deviceSalt)
 *   Layer 3: effectiveRoot = CPRisk-MAC(deviceKey, sessionToken)
 *
 * This file implements Layer-2 (device binding).  Layer-3 (session binding)
 * lives in cprisk_session_token.c.
 *
 * Device salt is sourced from Keychain / IOKit when available. There is
 * NO static / constant fallback salt: if the platform services are
 * unavailable, derivation HARD-FAILS (returns -1) instead of silently
 * binding every device to the same public constant.
 */

#include "include/CRiskCore.h"
#include "include/cprisk_sha256.h"
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#if defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <TargetConditionals.h>
#include <sys/utsname.h>
#endif

#if defined(__APPLE__) && TARGET_OS_OSX && !TARGET_OS_MACCATALYST
#include <IOKit/IOKitLib.h>
#endif

/* No constant fallback salt exists (a public constant salt would bind
 * every device to the same value). 1 = a platform-derived hardware salt
 * was successfully produced; 0 = device binding unavailable (hard fail). */
// 设备绑定就绪标志：1 表示至少成功派生过一次平台盐，0 表示绑定不可用。
// 用原子读写，任意线程可无锁查询 cprisk_is_device_bound()。
static _Atomic int s_device_bound_ready = 0;

/* CPRisk-MAC-SHA256 wrapper that delegates to the inline definition in
 * cprisk_armor_abi.h, which is transitively included via CRiskCore.h. */
// CPRisk-MAC-SHA256 的本地包装：统一到 cprisk_armor_abi.h 的静态内联实现。
static void cprisk_mac_sha256_i(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t out[CPRISK_ARMOR_HASH_SIZE]
) {
    /* cprisk_mac_sha256 is defined as static inline in cprisk_armor_abi.h */
    cprisk_mac_sha256(key, key_len, msg, msg_len, out);
}

#if defined(__APPLE__)
/// 填充随机字节，作为 Keychain 中持久盐的初始值。
/// - 先用 SecRandomCopyBytes；失败时对小缓冲回退到 getentropy 直调。
/// - 返回：0 成功；-1 参数非法或两条熵源都失败（调用方必须硬失败）。
/// - 线程安全：可并发，无全局状态。
/// - 失败语义：绝不返回部分填充或固定值。
static int cprisk_fill_random_i(uint8_t *out, size_t out_len) {
    if (!out || out_len == 0)
        return -1;

    if (SecRandomCopyBytes(kSecRandomDefault, out_len, out) == errSecSuccess)
        return 0;

    // 回退路径限制 256 字节：getentropy(2) 单次上限，也避免为大缓冲引入额外分配。
    if (out_len <= 256) {
        int entropy_err = 0;
        if (cprisk_getentropy_direct(out, out_len, &entropy_err) == 0)
            return 0;
    }
    return -1;
}

// 构造 Keychain 查询：generic password，service/account/label 固定，用于定位设备盐。
// 返回的新字典所有权归调用方（必须 CFRelease）。
static CFMutableDictionaryRef cprisk_create_keychain_query_i(void) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        kCFAllocatorDefault,
        0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );
    if (!query)
        return NULL;

    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, CFSTR("com.cloudphonerisk.cprisk"));
    CFDictionarySetValue(query, kSecAttrAccount, CFSTR("device-salt.v1"));
    CFDictionarySetValue(query, kSecAttrLabel, CFSTR("cprisk-device-salt"));
    return query;
}

/* Returns:
 *   0: salt loaded
 *   1: key missing
 *  -1: keychain unavailable or invalid data */
/// 从 Keychain 读取持久设备盐。
/// - out_salt 必填，恰好 32 字节；返回 0 已加载、1 条目不存在、-1 Keychain 错误或数据长度不符。
/// - 线程安全：Keychain API 可并发；本函数不持有全局状态。
/// - 失败语义：数据长度不是 32 字节时按错误处理，绝不截断或填充。
static int cprisk_keychain_read_salt_i(uint8_t out_salt[CPRISK_ARMOR_KEY_SIZE]) {
    if (!out_salt)
        return -1;

    int rc = -1;
    CFMutableDictionaryRef query = cprisk_create_keychain_query_i();
    if (!query)
        return -1;

    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    if (status == errSecSuccess && result && CFGetTypeID(result) == CFDataGetTypeID()) {
        CFDataRef data_ref = (CFDataRef)result;
        CFIndex data_len = CFDataGetLength(data_ref);
        // 长度必须精确匹配：短读/长读都视为损坏，避免盐被截断或忽略尾部字节。
        if (data_len == CPRISK_ARMOR_KEY_SIZE) {
            memcpy(out_salt, CFDataGetBytePtr(data_ref), CPRISK_ARMOR_KEY_SIZE);
            rc = 0;
        }
    } else if (status == errSecItemNotFound) {
        rc = 1;
    }

    if (result)
        CFRelease(result);
    CFRelease(query);
    return rc;
}

/* Returns:
 *   0: stored
 *   1: duplicate key
 *  -1: add failure */
/// 把新生成的盐写入 Keychain。
/// - 返回：0 成功、1 已存在（调用方应回读现有值）、-1 其它错误。
/// - 线程安全：SecItemAdd 自身同步；并发重复添加由 errSecDuplicateItem 表达。
static int cprisk_keychain_store_salt_i(const uint8_t salt[CPRISK_ARMOR_KEY_SIZE]) {
    if (!salt)
        return -1;

    int rc = -1;
    CFMutableDictionaryRef add_query = cprisk_create_keychain_query_i();
    if (!add_query)
        return -1;

    CFDataRef salt_data = CFDataCreate(kCFAllocatorDefault, salt, CPRISK_ARMOR_KEY_SIZE);
    if (!salt_data) {
        CFRelease(add_query);
        return -1;
    }

    CFDictionarySetValue(add_query, kSecValueData, salt_data);
    OSStatus status = SecItemAdd(add_query, NULL);
    if (status == errSecSuccess) {
        rc = 0;
    } else if (status == errSecDuplicateItem) {
        rc = 1;
    }

    CFRelease(salt_data);
    CFRelease(add_query);
    return rc;
}

/// 读取或首次创建 Keychain 盐。
/// - 已存在则直接返回；不存在则生成 32 字节随机盐并写入。
/// - 返回：0 成功；-1 随机数/Keychain 失败。
/// - 竞争处理：并发创建时后到者收到 duplicate，随后回读赢家的值。
/// - 失败语义：任何一步失败都清零临时盐并硬失败，不回退到常量。
static int cprisk_get_or_create_keychain_salt_i(uint8_t out_salt[CPRISK_ARMOR_KEY_SIZE]) {
    int read_rc = cprisk_keychain_read_salt_i(out_salt);
    if (read_rc == 0)
        return 0;
    if (read_rc != 1)
        return -1;

    uint8_t generated_salt[CPRISK_ARMOR_KEY_SIZE];
    if (cprisk_fill_random_i(generated_salt, sizeof(generated_salt)) != 0) {
        cprisk_secure_zero(generated_salt, sizeof(generated_salt));
        return -1;
    }

    int store_rc = cprisk_keychain_store_salt_i(generated_salt);
    if (store_rc == 0) {
        memcpy(out_salt, generated_salt, CPRISK_ARMOR_KEY_SIZE);
        cprisk_secure_zero(generated_salt, sizeof(generated_salt));
        return 0;
    }

    cprisk_secure_zero(generated_salt, sizeof(generated_salt));
    if (store_rc == 1) {
        // 另一个进程/线程已先写入：丢弃本次生成值，回读已持久化的盐。
        return cprisk_keychain_read_salt_i(out_salt) == 0 ? 0 : -1;
    }
    return -1;
}
#endif

#if defined(__APPLE__)
// 把“标签长度 || 标签 || 数据”写入哈希；ctx/tag 为空或 tag_len=0 时静默跳过。
// 定长标签让字段边界清晰，避免不同字段直接拼接后产生相同摘要。
static void cprisk_sha256_update_tagged_bytes_i(
    cprisk_sha256_ctx *ctx,
    const uint8_t *tag,
    size_t tag_len,
    const uint8_t *bytes,
    size_t len
) {
    if (!ctx || !tag || tag_len == 0)
        return;
    cprisk_sha256_update(ctx, tag, tag_len);
    if (bytes && len > 0) {
        cprisk_sha256_update(ctx, bytes, len);
    }
}

// 同上，但标签与字符串均按 NUL 结尾长度计算；空串不参与哈希。
static void cprisk_sha256_update_tagged_cstr_i(
    cprisk_sha256_ctx *ctx,
    const char *tag,
    const char *str
) {
    if (!ctx || !tag || !str || str[0] == '\0')
        return;
    const size_t tag_len = strlen(tag);
    const size_t str_len = strlen(str);
    cprisk_sha256_update_tagged_bytes_i(
        ctx,
        (const uint8_t *)tag,
        tag_len,
        (const uint8_t *)str,
        str_len
    );
}
#endif

#if defined(__APPLE__) && TARGET_OS_OSX && !TARGET_OS_MACCATALYST
/// 读取 IOPlatformUUID 作为 macOS 的强设备标识。
/// - out_uuid 至少 128 字节；返回 0 成功，-1 服务不存在/类型不符/转换失败。
/// - 失败语义：拿不到 UUID 时整条 macOS 派生路径失败，不使用替代常量。
static int cprisk_get_ioplatform_uuid_i(char out_uuid[128]) {
    if (!out_uuid)
        return -1;

    out_uuid[0] = '\0';

    io_service_t service = IOServiceGetMatchingService(
        kIOMainPortDefault,
        IOServiceMatching("IOPlatformExpertDevice")
    );
    if (service == IO_OBJECT_NULL)
        return -1;

    CFTypeRef uuid_ref = IORegistryEntryCreateCFProperty(
        service,
        CFSTR("IOPlatformUUID"),
        kCFAllocatorDefault,
        0
    );
    IOObjectRelease(service);

    if (!uuid_ref || CFGetTypeID(uuid_ref) != CFStringGetTypeID()) {
        if (uuid_ref)
            CFRelease(uuid_ref);
        return -1;
    }

    Boolean copied = CFStringGetCString(
        (CFStringRef)uuid_ref,
        out_uuid,
        128,
        kCFStringEncodingUTF8
    );
    CFRelease(uuid_ref);
    return (copied && out_uuid[0] != '\0') ? 0 : -1;
}

/// 融合 macOS 设备信号：先算 SHA256(uuid_tag || platform_uuid)，
/// 再以 Keychain 盐为 MAC 密钥对“uuid 摘要 || mix_tag”做 CPRisk-MAC，得到最终设备盐。
/// - 返回：0 成功；-1 参数非法。中间摘要/拼接缓冲用完清零。
static int cprisk_mix_device_and_keychain_salt_i(
    const char *platform_uuid,
    const uint8_t keychain_salt[CPRISK_ARMOR_KEY_SIZE],
    uint8_t out_salt[CPRISK_ARMOR_KEY_SIZE]
) {
    if (!platform_uuid || !keychain_salt || !out_salt)
        return -1;

    uint8_t uuid_digest[CPRISK_ARMOR_HASH_SIZE];
    cprisk_sha256_ctx uuid_ctx;
    cprisk_sha256_init(&uuid_ctx);

    static const uint8_t uuid_tag[] = "cprisk.device.uuid.v1";
    cprisk_sha256_update(&uuid_ctx, uuid_tag, sizeof(uuid_tag) - 1);
    cprisk_sha256_update(&uuid_ctx,
                         (const uint8_t *)platform_uuid,
                         strlen(platform_uuid));
    cprisk_sha256_final(&uuid_ctx, uuid_digest);

    static const uint8_t mix_tag[] = "cprisk.device.mix.v1";
    uint8_t mix_input[CPRISK_ARMOR_KEY_SIZE + sizeof(mix_tag) - 1];
    memcpy(mix_input, uuid_digest, CPRISK_ARMOR_KEY_SIZE);
    memcpy(mix_input + CPRISK_ARMOR_KEY_SIZE, mix_tag, sizeof(mix_tag) - 1);

    cprisk_mac_sha256_i(keychain_salt, CPRISK_ARMOR_KEY_SIZE,
                         mix_input, sizeof(mix_input),
                         out_salt);

    cprisk_secure_zero(uuid_digest, sizeof(uuid_digest));
    cprisk_secure_zero(mix_input, sizeof(mix_input));
    return 0;
}

/* Returns 0 only when the "real" binding path is used:
 * IOPlatformUUID (strong device signal) + keychain persisted salt. */
/// macOS 设备盐入口：要求 IOPlatformUUID + Keychain 盐同时可用。
/// - 返回 0 表示走了“真实绑定”路径；任一来源失败返回 -1（硬失败）。
/// - 所有中间缓冲在每条返回路径上清零。
static int cprisk_get_macos_device_salt_i(uint8_t out_salt[CPRISK_ARMOR_KEY_SIZE]) {
    if (!out_salt)
        return -1;

#if !defined(__APPLE__)
    (void)out_salt;
    return -1;
#else
    char platform_uuid[128];
    uint8_t keychain_salt[CPRISK_ARMOR_KEY_SIZE];

    if (cprisk_get_ioplatform_uuid_i(platform_uuid) != 0) {
        cprisk_secure_zero(keychain_salt, sizeof(keychain_salt));
        return -1;
    }

    if (cprisk_get_or_create_keychain_salt_i(keychain_salt) != 0) {
        cprisk_secure_zero(keychain_salt, sizeof(keychain_salt));
        cprisk_secure_zero(platform_uuid, sizeof(platform_uuid));
        return -1;
    }

    int rc = cprisk_mix_device_and_keychain_salt_i(platform_uuid, keychain_salt, out_salt);
    cprisk_secure_zero(keychain_salt, sizeof(keychain_salt));
    cprisk_secure_zero(platform_uuid, sizeof(platform_uuid));
    return rc;
#endif
}
#endif

#if defined(__APPLE__) && TARGET_OS_IPHONE && !TARGET_OS_MACCATALYST
/// 通过 cprisk_sysctlbyname_direct 读取字符串型 sysctl，结果保证 NUL 结尾。
/// - 返回：0 成功；-1 查询失败或长度为 0。失败时 out[0] 置 NUL。
static int cprisk_sysctl_string_i(const char *name, char *out, size_t out_len) {
    if (!name || !out || out_len == 0)
        return -1;

    size_t len = out_len;
    int err = 0;
    if (cprisk_sysctlbyname_direct(name, out, &len, NULL, 0, &err) != 0 || len == 0) {
        out[0] = '\0';
        return -1;
    }
    if (len >= out_len) {
        len = out_len - 1;
    }
    out[len] = '\0';
    return 0;
}

/// 汇总 iOS 设备指纹：uname + hw.machine/hw.model + hw.memsize + bundle id，
/// 每项带独立长度标签后写入 SHA-256。
/// - 返回：0 成功；-1 仅 out_digest 为空。
/// - 失败语义：单项 sysctl/取 bundle 失败时跳过该项（指纹变弱），但不会崩溃。
static int cprisk_collect_ios_device_fingerprint_i(
    uint8_t out_digest[CPRISK_ARMOR_HASH_SIZE]
) {
    if (!out_digest)
        return -1;

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);

    static const uint8_t root_tag[] = "cprisk.ios.device.v1";
    cprisk_sha256_update(&ctx, root_tag, sizeof(root_tag) - 1);

    struct utsname un;
    memset(&un, 0, sizeof(un));
    if (uname(&un) == 0) {
        // 每一项都带独立标签，避免不同字段直接拼接后产生相同摘要前缀。
        cprisk_sha256_update_tagged_cstr_i(&ctx, "uname.sysname", un.sysname);
        cprisk_sha256_update_tagged_cstr_i(&ctx, "uname.release", un.release);
        cprisk_sha256_update_tagged_cstr_i(&ctx, "uname.version", un.version);
        cprisk_sha256_update_tagged_cstr_i(&ctx, "uname.machine", un.machine);
    }

    char hw_machine[128];
    if (cprisk_sysctl_string_i("hw.machine", hw_machine, sizeof(hw_machine)) == 0) {
        cprisk_sha256_update_tagged_cstr_i(&ctx, "hw.machine", hw_machine);
    }

    char hw_model[128];
    if (cprisk_sysctl_string_i("hw.model", hw_model, sizeof(hw_model)) == 0) {
        cprisk_sha256_update_tagged_cstr_i(&ctx, "hw.model", hw_model);
    }

    uint64_t memsize = 0;
    size_t memsize_len = sizeof(memsize);
    int mem_err = 0;
    // hw.memsize 是数值，按原始 8 字节参与哈希；仅接受完整 sizeof 读取，避免截断。
    if (cprisk_sysctlbyname_direct("hw.memsize", &memsize, &memsize_len, NULL, 0, &mem_err) == 0 &&
        memsize_len == sizeof(memsize)) {
        cprisk_sha256_update_tagged_bytes_i(
            &ctx,
            (const uint8_t *)"hw.memsize",
            sizeof("hw.memsize") - 1,
            (const uint8_t *)&memsize,
            sizeof(memsize)
        );
    }

    // bundle id 把指纹限定到当前 App，降低跨 App 复用同一设备盐的风险。
    char bundle_id[256];
    bundle_id[0] = '\0';
    CFBundleRef bundle = CFBundleGetMainBundle();
    if (bundle) {
        CFStringRef ident = CFBundleGetIdentifier(bundle);
        if (ident && CFStringGetCString(ident, bundle_id, sizeof(bundle_id), kCFStringEncodingUTF8)) {
            cprisk_sha256_update_tagged_cstr_i(&ctx, "bundle.id", bundle_id);
        }
    }

    cprisk_sha256_final(&ctx, out_digest);
    cprisk_secure_zero(&ctx, sizeof(ctx));
    cprisk_secure_zero(hw_machine, sizeof(hw_machine));
    cprisk_secure_zero(hw_model, sizeof(hw_model));
    cprisk_secure_zero(bundle_id, sizeof(bundle_id));
    return 0;
}

/// iOS 设备盐入口：设备指纹 + Keychain 盐，以盐为密钥 MAC 指纹与 mix_tag。
/// - 返回：0 成功；-1 指纹或 Keychain 失败。
/// - 失败语义：失败时清零全部中间材料，不产生任何可用盐。
static int cprisk_get_ios_device_salt_i(uint8_t out_salt[CPRISK_ARMOR_KEY_SIZE]) {
    if (!out_salt)
        return -1;

    uint8_t device_digest[CPRISK_ARMOR_HASH_SIZE];
    if (cprisk_collect_ios_device_fingerprint_i(device_digest) != 0) {
        return -1;
    }

    uint8_t keychain_salt[CPRISK_ARMOR_KEY_SIZE];
    if (cprisk_get_or_create_keychain_salt_i(keychain_salt) != 0) {
        cprisk_secure_zero(device_digest, sizeof(device_digest));
        return -1;
    }

    static const uint8_t mix_tag[] = "cprisk.device.ios.mix.v1";
    uint8_t mix_input[CPRISK_ARMOR_HASH_SIZE + sizeof(mix_tag) - 1];
    memcpy(mix_input, device_digest, CPRISK_ARMOR_HASH_SIZE);
    memcpy(mix_input + CPRISK_ARMOR_HASH_SIZE, mix_tag, sizeof(mix_tag) - 1);

    cprisk_mac_sha256_i(keychain_salt, CPRISK_ARMOR_KEY_SIZE,
                         mix_input, sizeof(mix_input),
                         out_salt);

    cprisk_secure_zero(device_digest, sizeof(device_digest));
    cprisk_secure_zero(keychain_salt, sizeof(keychain_salt));
    cprisk_secure_zero(mix_input, sizeof(mix_input));
    return 0;
}
#endif

/* Platform-specific device-salt retrieval.
 * Returns 0 on success, -1 on failure.
 * On failure the caller HARD-FAILS (no constant-salt fallback). */
// 平台分派：macOS 走 IOPlatformUUID 路径，iOS 走系统指纹路径；
// 其它平台（含 Catalyst 未定义分支）直接返回 -1，不存在常量回退。
static int cprisk_get_device_salt_i(uint8_t out_salt[CPRISK_ARMOR_KEY_SIZE]) {
#if defined(__APPLE__) && TARGET_OS_OSX && !TARGET_OS_MACCATALYST
    return cprisk_get_macos_device_salt_i(out_salt);
#elif defined(__APPLE__) && TARGET_OS_IPHONE && !TARGET_OS_MACCATALYST
    return cprisk_get_ios_device_salt_i(out_salt);
#else
    (void)out_salt;
    return -1;
#endif
}

/// 派生第二层设备密钥：deviceKey = CPRisk-MAC(rootKey, deviceSalt)。
/// - root_key 必填且必须为 32 字节；out_device_key 必填，调用方拥有。
/// - 返回：0 成功；-1 参数非法或无法取得平台设备盐。
/// - 线程安全：可并发；s_device_bound_ready 用 atomic_store 发布结果。
/// - 平台：macOS 需要 IOKit/Keychain，iOS 需要 sysctl/Keychain；模拟器同样走 iOS 路径。
/// - 失败语义：硬失败；绝不使用常量盐，失败时把就绪标志置 0。
int cprisk_derive_device_key(
    const uint8_t *root_key,
    uint8_t out_device_key[CPRISK_ARMOR_KEY_SIZE]
) {
    if (!root_key || !out_device_key)
        return -1;

    uint8_t device_salt[CPRISK_ARMOR_KEY_SIZE];

    /* IOKit/Keychain unavailable => hard fail. Never substitute a
     * constant salt: a public constant would make deviceKey identical
     * on every device and void the device binding. */
    if (cprisk_get_device_salt_i(device_salt) != 0) {
        // 取盐失败即硬失败：公开常量盐会让所有设备得到同一 deviceKey，设备绑定名存实亡。
        cprisk_secure_zero(device_salt, sizeof(device_salt));
        atomic_store(&s_device_bound_ready, 0);
        return -1;
    }
    // 先成功落盐再发布就绪，避免其他线程看到“已就绪但实际无盐”。
    atomic_store(&s_device_bound_ready, 1);

    // 设备盐作为消息、rootKey 作为 MAC 密钥，得到与本次安装绑定的设备密钥。
    /* deviceKey = CPRisk-MAC(rootKey, deviceSalt) */
    cprisk_mac_sha256_i(root_key, CPRISK_ARMOR_KEY_SIZE,
                         device_salt, CPRISK_ARMOR_KEY_SIZE,
                         out_device_key);

    /* Clear intermediate material from stack. */
    cprisk_secure_zero(device_salt, sizeof(device_salt));

    return 0;
}

// 查询是否已成功完成过一次平台盐派生；只读原子标志，不触发任何 Keychain 访问。
int cprisk_is_device_bound(void) {
    return atomic_load(&s_device_bound_ready) ? 1 : 0;
}
