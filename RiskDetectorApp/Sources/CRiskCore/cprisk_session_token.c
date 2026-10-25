// cprisk_session_token.c — 第三层会话密钥绑定（session-bound key derivation）。
// 链路位置：rootKey → deviceKey（cprisk_hardware_key.c）→ effectiveRoot，本文件提供
// 参与第三层派生的会话密钥，密钥由远端证明服务器下发。
// 线程模型：token 字节、有效位与过期时间由 s_session_mutex 保护，读路径持锁拷贝后立即释放。
// 格式约束：只接受 32 字节 token + 32 字节 CPRisk-MAC 的签名格式，裸 token 一律拒绝。
// 失败语义：验签失败、过期或时间异常都会清空内存中的 token，并让调用方 fail-closed。
/*
 * cprisk_session_token.c — Layer-3 session-bound key derivation.
 *
 * Three-layer key derivation:
 *   Layer 1: rootKey        (CLI provided)
 *   Layer 2: deviceKey      = CPRisk-MAC(rootKey, deviceSalt)
 *   Layer 3: effectiveRoot  = CPRisk-MAC(deviceKey, sessionKey)
 *
 * This file implements Layer-3 (session binding).  Session keys are
 * received from the remote attestation server and used to derive a
 * third-layer key bound to the current session.
 *
 * Session tokens carry a 24-hour TTL to limit the impact of key exposure.
 * ONLY the signed token format is accepted:
 *   - signed: 32-byte token + 32-byte CPRisk-MAC(token)
 * A bare 32-byte token is REJECTED unconditionally (it carries no
 * authentication). The verification key is derived at runtime from the
 * runtime material (never a hardcoded / compiled-in key string); if
 * runtime material is unavailable, every token is rejected.
 * The TTL guards against replay even when the caller keeps using
 * stale in-memory material.
 */

#include "include/CRiskCore.h"
#include "include/cprisk_sha256.h"
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <limits.h>

// 会话 token 有效期 24 小时：限制密钥泄露后的可用窗口，过期即视为无 token。
// 签名格式总长 = 32 字节载荷 + 32 字节 MAC；裸 32 字节格式不被接受。
#define CPRISK_SESSION_TOKEN_TTL_SECONDS (24UL * 60 * 60)   /* 24 hours */
#define CPRISK_SESSION_TOKEN_SIGNED_SIZE (CPRISK_ARMOR_KEY_SIZE + CPRISK_ARMOR_HASH_SIZE)

/* Token format (v2 only):
 * - signed: [32-byte token || 32-byte CPRisk-MAC(token)]
 *
 * There is NO hardcoded MAC key anywhere in this file: the verification
 * key is derived from the runtime material at call time (see
 * cprisk_session_mac_key_i). A token without a valid tag is rejected.
 * Local CPRisk-MAC validation is a tamper filter. Server-side attestation remains
 * the source of truth. */

/* Publish/clear token bytes, validity, and expiry as one protected state.
 * An atomic validity flag alone cannot protect concurrent copies/clears. */
// 进程级互斥锁：保护 token、有效位与过期时间；PTHREAD_MUTEX_INITIALIZER 静态初始化。
static pthread_mutex_t s_session_mutex = PTHREAD_MUTEX_INITIALIZER;
// 当前会话 token（32 字节），仅在 s_session_token_valid=1 且未过期时有效。
static uint8_t s_session_token[CPRISK_ARMOR_KEY_SIZE];
// 有效性标志；必须与 token/过期时间在同一把锁下更新，不能单独读。
static int s_session_token_valid = 0;
// 过期时间点（epoch 秒）；0 表示不存在有效会话。
static time_t s_session_token_expires_at;

/* Caller holds s_session_mutex. */
// 在调用方已持有 s_session_mutex 的前提下清空 token 与元数据。
// 先清零字节再置无效，避免出现“有效但内容已被清空”的短暂状态。
static void cprisk_clear_session_token_locked_i(void) {
    cprisk_secure_zero(s_session_token, sizeof(s_session_token));
    s_session_token_valid = 0;
    s_session_token_expires_at = 0;
}

/* CPRisk-MAC-SHA256 wrapper delegating to the static inline in cprisk_armor_abi.h */
// CPRisk-MAC-SHA256 的本地包装：统一调用 cprisk_armor_abi.h 的静态内联实现。
static void cprisk_mac_sha256_i(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t out[CPRISK_ARMOR_HASH_SIZE]
) {
    cprisk_mac_sha256(key, key_len, msg, msg_len, out);
}

/* Derive the token-verification key from runtime material. Returns 0 on
 * success, -1 when runtime material is unavailable (caller must then
 * reject the token — there is no fallback key). */
/// 从运行时材料派生 token 验签密钥：CPRisk-MAC(runtime_material, "cprisk.session.token.mac.v1")。
/// - 无硬编码密钥；runtime material 不可用时返回 -1，调用方必须拒绝 token（无回退密钥）。
/// - 返回：0 成功；-1 运行时材料缺失。out_key 由调用方拥有，用后必须清零。
/// - 线程安全：只读全局 material，可并发。
static int cprisk_session_mac_key_i(uint8_t out_key[CPRISK_ARMOR_HASH_SIZE]) {
    uint8_t runtime_material[CPRISK_ARMOR_HASH_SIZE];
    if (cprisk_get_runtime_material(runtime_material) != 0)
        return -1;
    static const char label[] = "cprisk.session.token.mac.v1";
    cprisk_mac_sha256_i(runtime_material, CPRISK_ARMOR_HASH_SIZE,
                        (const uint8_t *)label, sizeof(label) - 1,
                        out_key);
    cprisk_secure_zero(runtime_material, sizeof(runtime_material));
    return 0;
}

// 过期判定：未标记有效、时间戳非正、当前时间为负、或已严格超过过期点都算过期。
// 返回 1 表示过期/不可用，0 表示仍有效；调用方必须持有 s_session_mutex。
static int cprisk_session_is_expired_i(time_t now) {
    if (s_session_token_valid == 0)
        return 1;
    if (s_session_token_expires_at <= 0)
        return 1;
    if (now < 0)
        return 1;
    return now > s_session_token_expires_at;
}

/// 校验签名 token：长度必须恰为 64 字节，重新计算前 32 字节的 MAC 并常数时间比较。
/// - 返回：0 签名有效；-1 长度错误、密钥派生失败或 MAC 不符。
/// - 线程安全：纯局部计算，不访问会话全局状态，可并发。
/// - 失败语义：验签失败不修改会话状态，由调用方决定是否清空。
static int cprisk_verify_signed_token_i(const uint8_t *token, size_t token_len) {
    if (!token || token_len != CPRISK_SESSION_TOKEN_SIGNED_SIZE)
        return -1;

    // 载荷固定在前 32 字节，MAC 紧随其后；长度已在上面严格限定，不会越界。
    const uint8_t *payload = token;
    const uint8_t *provided_tag = token + CPRISK_ARMOR_KEY_SIZE;
    uint8_t expected_tag[CPRISK_ARMOR_HASH_SIZE];
    uint8_t mac_key[CPRISK_ARMOR_HASH_SIZE];
    if (cprisk_session_mac_key_i(mac_key) != 0)
        return -1;

    // 用运行时派生的密钥重算 MAC；expected_tag 与 mac_key 用后立即清零。
    cprisk_mac_sha256_i(
        mac_key,
        CPRISK_ARMOR_HASH_SIZE,
        payload,
        CPRISK_ARMOR_KEY_SIZE,
        expected_tag
    );
    cprisk_secure_zero(mac_key, sizeof(mac_key));

    const int rc = cprisk_mac_verify(provided_tag, expected_tag, CPRISK_ARMOR_HASH_SIZE);
    cprisk_secure_zero(expected_tag, sizeof(expected_tag));
    return rc == 0 ? 0 : -1;
}

/// 安装并激活会话 token。
/// - token 必填，长度必须恰为 64 字节的签名格式；裸 32 字节 token 无条件拒绝。
/// - 返回：0 安装成功；-1 参数/时间/验签/TTL 溢出失败，失败时会清空既有 token。
/// - 线程安全：验签在锁外完成，状态发布持 s_session_mutex。
/// - 失败语义：验签失败会丢弃旧会话，防止继续使用可能已不可信的状态。
int cprisk_set_session_token(const uint8_t *token, size_t token_len) {
    if (!token)
        return -1;

    time_t now = time(NULL);
    // 系统时间不可信（可能为负或被回拨）时不建立会话，宁可失败。
    if (now < 0)
        return -1;

    /* ONLY signed tokens are accepted. A bare 32-byte token carries no
     * authentication and is rejected unconditionally; anything that is
     * not exactly the signed size is rejected too. */
    if (token_len != CPRISK_SESSION_TOKEN_SIGNED_SIZE)
        return -1;
    if (cprisk_verify_signed_token_i(token, token_len) != 0) {
        // 验签失败必须清掉旧 token，避免攻击者用坏 token 触发失败后旧会话仍被继续使用。
        cprisk_clear_session_token();
        return -1;
    }

    // 先确认 now+TTL 不会超过 time_t 上限，避免溢出成过去时间导致立即过期或永不过期。
    if ((time_t)CPRISK_SESSION_TOKEN_TTL_SECONDS > (time_t)(LONG_MAX - now))
        return -1;

    // 在锁内一次性发布字节、过期时间与有效位，读路径不会看到中间状态。
    pthread_mutex_lock(&s_session_mutex);
    memcpy(s_session_token, token, CPRISK_ARMOR_KEY_SIZE);
    s_session_token_expires_at = now + (time_t)CPRISK_SESSION_TOKEN_TTL_SECONDS;
    s_session_token_valid = 1;
    pthread_mutex_unlock(&s_session_mutex);

    return 0;
}

/// 取出当前会话 token（32 字节），供上层组合 effectiveRoot = MAC(deviceKey, sessionKey)。
/// - out_key 必填，调用方拥有 32 字节缓冲；失败时会被清零。
/// - 返回：0 成功；-1 无有效或已过期的 token。
/// - 线程安全：持锁检查并拷贝，过期时在锁内清空。
/// - 失败语义：过期或时间异常即清空会话并返回 -1（fail-closed）。
int cprisk_get_session_key(uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]) {
    if (!out_key)
        return -1;

    time_t now = time(NULL);
    pthread_mutex_lock(&s_session_mutex);
    if (now < 0 || cprisk_session_is_expired_i(now)) {
        // 过期立即销毁会话：即使调用方仍持有旧引用，内存中的 token 也不应继续可读。
        cprisk_clear_session_token_locked_i();
        cprisk_secure_zero(out_key, CPRISK_ARMOR_KEY_SIZE);
        pthread_mutex_unlock(&s_session_mutex);
        return -1;
    }

    /* Return session token as-is.
     * The caller composes effectiveRoot = CPRisk-MAC(deviceKey, sessionKey). */
    // 返回原始 token 而不做二次派生：Layer-3 组合由调用方完成，保持单一职责。
    memcpy(out_key, s_session_token, CPRISK_ARMOR_KEY_SIZE);
    pthread_mutex_unlock(&s_session_mutex);
    return 0;
}

// 只读查询：有效且未过期返回 1，否则在锁内清空会话并返回 0；不导出密钥材料。
int cprisk_has_session_token(void) {
    time_t now = time(NULL);
    pthread_mutex_lock(&s_session_mutex);
    if (now < 0 || cprisk_session_is_expired_i(now)) {
        // 查询本身也承担过期清理，避免无人调用 get 时陈旧 token 长期驻留。
        cprisk_clear_session_token_locked_i();
        pthread_mutex_unlock(&s_session_mutex);
        return 0;
    }
    pthread_mutex_unlock(&s_session_mutex);
    return 1;
}

// 对外清空会话：加锁后清零 token 与元数据；可在任意线程调用，幂等。
void cprisk_clear_session_token(void) {
    pthread_mutex_lock(&s_session_mutex);
    cprisk_clear_session_token_locked_i();
    pthread_mutex_unlock(&s_session_mutex);
}
