/*
 * cprisk_detection_attest.c — 检测证明链的 C 侧累加器（跨语言防 Hook）。
 * 职责：按实际派发顺序记录 (detector_id, score, methods_hash)，finalize 产出 32 字节 HMAC 标签。
 * 校验：服务端用 WhiteBox PRF（域 5）重放哈希链；缺失、标签错误或计数不符即判定篡改。
 * 线程：begin/record/finalize 由 s_attest_mutex 串行化，可并发调用但同一时刻仅一个会话。
 * 平台：平台无关；SecRandom 不可用时退化为时间戳+计数器 SHA256（非密码学强度）。
 * 失败：密钥派生失败用构建期常量兜底（fail-open）；finalize 无会话返回 -1 并清零输出。
 */

#include "include/CRiskCore.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

#if defined(__APPLE__)
#include <Security/SecRandom.h>
#endif

// 证明密钥使用的 WhiteBox 域号（5 = runtimeMaterial），必须与服务端/Swift 侧一致；
// 改动会令所有既有证明标签失效。
#define CPRISK_ATTEST_KEY_DOMAIN_RUNTIME_MATERIAL 5u

// 会话状态：所有写操作都必须在持有 s_attest_mutex 时进行。
// s_attest_mutex：粗粒度互斥锁，同时保护下列字段，保证并发检测线程看到的顺序一致。
static pthread_mutex_t s_attest_mutex = PTHREAD_MUTEX_INITIALIZER;
// s_attest_key_init：密钥派生完成标志（无锁快速路径读取，值为 1 时 key 只读）。
static _Atomic int     s_attest_key_init;
// s_attest_key：一次性从 WhiteBox 派生的 HMAC 密钥，进程生命周期内不复用其他用途。
static uint8_t         s_attest_key[CPRISK_ARMOR_KEY_SIZE];
// s_attest_running_hash：滚动哈希链 H_n；finalize 后会被清零，必须重新 begin。
static uint8_t         s_attest_running_hash[CPRISK_ARMOR_HASH_SIZE];
// s_attest_session_nonce：每次 begin 重新生成的 16 字节随机数，用于阻断跨会话拼接。
static uint8_t         s_attest_session_nonce[16];
// s_attest_count：本会话已记录的条数，随 finalize 一并参与 MAC 计算。
static uint32_t        s_attest_count;
// s_attest_session_active：0 表示无活动会话，此时 record 为 no-op、finalize 失败。
static int             s_attest_session_active;

// 生成 len 字节随机数写入 out（out 由调用方提供，至少 len 字节）。
// 返回 0 恒成功；Apple 平台优先 SecRandom，失败或非 Apple 时退化。
// 线程安全：退化路径用原子计数器避免并发重放；调用方需持有 s_attest_mutex。
// 安全边界：退化路径只由时间戳+计数器 SHA256 派生，可预测性高于 CSPRNG，
// 但足以让“重放旧 nonce”不可行；不得用于长期密钥。
static int cprisk_attest_random_bytes_i(uint8_t *out, size_t len) {
#if defined(__APPLE__)
    if (SecRandomCopyBytes(kSecRandomDefault, len, out) == errSecSuccess)
        return 0;
#endif
    // 退化随机源：时间戳 + 原子计数器经 SHA256 混合，避免直接暴露时钟序列；
    // 不具密码学强度，但 SecRandom 不可用时仍能阻止跨会话 nonce 重放。
    /* Fallback: timestamp + per-call counter, mixed via SHA256 to avoid
     * leaking the raw clock pattern. Not cryptographically strong but
     * enough to make replay impractical when SecRandom is unavailable. */
    static _Atomic uint64_t ctr;
    uint64_t c = atomic_fetch_add(&ctr, 1ULL);
    uint64_t t = (uint64_t)time(NULL);
    uint8_t seed[24];
    memcpy(seed, &t, 8);
    memcpy(seed + 8, &c, 8);
    memcpy(seed + 16, "ATTESTNONCEFB!\0\0", 8);
    uint8_t digest[CPRISK_ARMOR_HASH_SIZE];
    cprisk_sha256(seed, sizeof(seed), digest);
    size_t n = len < sizeof(digest) ? len : sizeof(digest);
    memcpy(out, digest, n);
    if (len > n) memset(out + n, 0, len - n);
    // 立即擦除种子与中间摘要，避免栈上残留可用于预测 nonce 的材料。
    cprisk_secure_zero(seed, sizeof(seed));
    cprisk_secure_zero(digest, sizeof(digest));
    return 0;
}

// 首次调用时派生会话密钥；此后为无锁只读快速路径。
// 必须在持有 s_attest_mutex 时调用（begin 已持锁），保证派生只执行一次。
// 平台：WhiteBox 域 5 在所有平台可用性不同；失败走构建期兜底常量。
// 失败语义：派生失败不返回错误，而是退化为固定密钥（fail-open），
// 仍可抵抗通用 Swift Hook，但失去“必须攻破 WhiteBox”的强度。
// 不变量：返回后 s_attest_key 内容确定，s_attest_key_init 置 1。
static void cprisk_attest_ensure_key_i(void) {
    if (atomic_load(&s_attest_key_init))
        return;

    /* Derive once: CPRisk-MAC under WhiteBox Domain 5 using a stable label.
     * Subsequent sessions reuse this key. */
    // 密钥派生输入：稳定标签 + 32 字节零填充；标签长度 20 字节，剩余保持 0。
    uint8_t input[32];
    memset(input, 0, sizeof(input));
    static const char label[] = "cprisk.attest.key.v1";
    /* sizeof(label) - 1 == 20, fits in 32 bytes; pad zeros stay. */
    memcpy(input, label, sizeof(label) - 1u);

    uint8_t derived[32];
    if (cprisk_whitebox_evaluate_domain(
            CPRISK_ATTEST_KEY_DOMAIN_RUNTIME_MATERIAL,
            input,
            derived) == 0) {
        memcpy(s_attest_key, derived, sizeof(s_attest_key));
    } else {
        /* WhiteBox unavailable (early boot, test fixture, etc.) — fall
         * back to a build-derived constant. The attestation is still
         * useful against generic Swift hooks but loses the
         * "needs to compromise WhiteBox" property. */
        for (size_t i = 0; i < sizeof(s_attest_key); i++) {
            s_attest_key[i] = (uint8_t)(0xCC ^ (i * 0x37));
        }
    }
    cprisk_secure_zero(derived, sizeof(derived));
    cprisk_secure_zero(input, sizeof(input));
    atomic_store(&s_attest_key_init, 1);
}

// 开始一次证明会话并生成新的 16 字节 nonce。
// 参数：out_nonce 可为 NULL；非 NULL 时必须可写 16 字节，由调用方分配。
// 返回：恒为 0（随机源退化也视为成功）；失败只可能来自内部不可恢复状态。
// 线程安全：持有 s_attest_mutex，可与其他 begin/record/finalize 串行。
// 平台：无差异；Apple 上优先 SecRandom，其他平台走退化随机源。
// 失败语义：重复调用会丢弃上一会话未 finalize 的状态（覆盖 nonce/hash/count）。
// 不变量：返回后会话处于 active，count=0，running_hash 绑定 label+nonce。
int cprisk_attest_session_begin(uint8_t out_nonce[16]) {
    pthread_mutex_lock(&s_attest_mutex);

    cprisk_attest_ensure_key_i();
    cprisk_attest_random_bytes_i(s_attest_session_nonce, sizeof(s_attest_session_nonce));

    /* Initialize the running hash with a domain label and the session
     * nonce so attestation tags from different sessions are not
     * splice-able. */
    // 用域标签+会话 nonce 初始化滚动哈希：不同会话的链起点不同，旧标签无法拼接。
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    static const uint8_t session_label[] = "cprisk.attest.session.v1";
    cprisk_sha256_update(&ctx, session_label, sizeof(session_label) - 1u);
    cprisk_sha256_update(&ctx, s_attest_session_nonce, sizeof(s_attest_session_nonce));
    cprisk_sha256_final(&ctx, s_attest_running_hash);

    s_attest_count = 0;
    s_attest_session_active = 1;

    if (out_nonce) {
        memcpy(out_nonce, s_attest_session_nonce, 16);
    }

    pthread_mutex_unlock(&s_attest_mutex);
    return 0;
}

// 把一个检测结果追加进当前会话的滚动哈希链。
// 参数：
//   - detector_id：1 字节检测器编号，按小端 4 字节编码进链。
//   - score：有符号分数，按 uint32 小端编码（负值以补码参与哈希）。
//   - methods_hash：32 字节方法指纹；允许 NULL，此时以全零哈希参与。
// 返回：无。
// 线程安全：持有 s_attest_mutex，可与 begin/finalize 并发串行。
// 平台：无平台分支；依赖 SHA256 实现。
// 失败语义：无活动会话时直接返回（静默丢弃），不阻塞调用方、不产生脏链。
void cprisk_attest_record(uint8_t detector_id,
                          int32_t score,
                          const uint8_t methods_hash[CPRISK_ARMOR_HASH_SIZE]) {
    pthread_mutex_lock(&s_attest_mutex);

    if (!s_attest_session_active) {
        pthread_mutex_unlock(&s_attest_mutex);
        return;
    }

    /* Hash chain: H_{n+1} = SHA256(H_n || id_le4 || score_le4 || methods_hash[32])
     * Rolling chain, not Merkle, because we want the order of records to
     * matter — server replay must follow the same dispatch order the
     * client used. */
    // 采用滚动链而非 Merkle：服务端必须按客户端实际派发顺序重放，乱序即失配。
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, s_attest_running_hash, CPRISK_ARMOR_HASH_SIZE);

    uint8_t id_le4[4] = { detector_id, 0u, 0u, 0u };
    cprisk_sha256_update(&ctx, id_le4, 4);

    uint32_t score_u = (uint32_t)score;
    uint8_t score_le4[4] = {
        (uint8_t)(score_u),
        (uint8_t)(score_u >> 8),
        (uint8_t)(score_u >> 16),
        (uint8_t)(score_u >> 24),
    };
    cprisk_sha256_update(&ctx, score_le4, 4);

    if (methods_hash) {
        cprisk_sha256_update(&ctx, methods_hash, CPRISK_ARMOR_HASH_SIZE);
    } else {
        uint8_t zero_hash[CPRISK_ARMOR_HASH_SIZE] = {0};
        cprisk_sha256_update(&ctx, zero_hash, CPRISK_ARMOR_HASH_SIZE);
    }

    cprisk_sha256_final(&ctx, s_attest_running_hash);
    s_attest_count++;

    pthread_mutex_unlock(&s_attest_mutex);
}

// 结束当前会话并输出 32 字节 HMAC 证明标签。
// 参数：
//   - out_tag：必填，调用方提供 32 字节缓冲；失败时被清零。
//   - out_count：可为 NULL；非 NULL 时写入本会话记录条数。
// 返回：成功 0；无活动会话或 out_tag 为 NULL 时返回 -1。
// 线程安全：持有 s_attest_mutex；成功后会话置为非活动，后续 record 为 no-op。
// 平台：无差异，HMAC 由 cprisk_mac_sha256 提供。
// 失败语义：返回 -1 时 out_tag 全零、*out_count=0，调用方不得重试旧会话，需重新 begin。
// 不变量：最终标签 = HMAC(key, "cprisk.attest.tag.v1" || nonce || H_n || count_le4)。
int cprisk_attest_session_finalize(uint8_t out_tag[CPRISK_ARMOR_HASH_SIZE],
                                   uint32_t *out_count) {
    pthread_mutex_lock(&s_attest_mutex);

    if (!s_attest_session_active || !out_tag) {
        if (out_tag) memset(out_tag, 0, CPRISK_ARMOR_HASH_SIZE);
        if (out_count) *out_count = 0u;
        pthread_mutex_unlock(&s_attest_mutex);
        return -1;
    }

    /* Final tag = CPRisk-MAC(s_attest_key, "cprisk.attest.tag.v1" || nonce || running_hash || count_le4)
     * Keying the FINAL step (rather than the rolling chain) means the
     * attacker cannot pre-compute partial states without the key. */
    // 只对最终状态做 MAC：攻击者没有 key 就无法预先算出任何中间链状态。
    // msg 布局固定为 label 槽 24B + nonce 16B + hash 32B + count 小端 4B。
    uint8_t msg[24 + 16 + CPRISK_ARMOR_HASH_SIZE + 4];
    static const uint8_t tag_label[] = "cprisk.attest.tag.v1";
    /* sizeof(tag_label)-1 == 20, fits in 24-byte slot; tail two bytes 0. */
    size_t mp = 0;
    memset(msg, 0, sizeof(msg));
    memcpy(msg + mp, tag_label, sizeof(tag_label) - 1u);
    mp += 24;
    memcpy(msg + mp, s_attest_session_nonce, 16);
    mp += 16;
    memcpy(msg + mp, s_attest_running_hash, CPRISK_ARMOR_HASH_SIZE);
    mp += CPRISK_ARMOR_HASH_SIZE;
    msg[mp++] = (uint8_t)(s_attest_count);
    msg[mp++] = (uint8_t)(s_attest_count >> 8);
    msg[mp++] = (uint8_t)(s_attest_count >> 16);
    msg[mp++] = (uint8_t)(s_attest_count >> 24);

    cprisk_mac_sha256(s_attest_key, sizeof(s_attest_key),
                       msg, sizeof(msg), out_tag);

    if (out_count) *out_count = s_attest_count;

    /* End the session — subsequent record() calls without begin() are no-ops. */
    // 结束会话：擦除滚动链并复位计数，防止旧状态被下一次 begin 误用。
    cprisk_secure_zero(s_attest_running_hash, sizeof(s_attest_running_hash));
    s_attest_session_active = 0;
    s_attest_count = 0;
    cprisk_secure_zero(msg, sizeof(msg));

    pthread_mutex_unlock(&s_attest_mutex);
    return 0;
}

// 读取当前会话 nonce 的副本（只读查询，不影响会话状态）。
// 参数：out_nonce 允许 NULL；非 NULL 时必须可写 16 字节。
// 返回：无。
// 线程安全：持有 s_attest_mutex，与 begin/finalize 串行，读取期间 nonce 不会被替换。
// 平台：无平台分支。
// 失败语义：out_nonce 为 NULL 时安全 no-op；无活动会话时仍返回最近一次 nonce，
// 调用方若需要“当前有效 nonce”应自行结合会话状态判断。
void cprisk_attest_get_session_nonce(uint8_t out_nonce[16]) {
    pthread_mutex_lock(&s_attest_mutex);
    if (out_nonce) {
        memcpy(out_nonce, s_attest_session_nonce, 16);
    }
    pthread_mutex_unlock(&s_attest_mutex);
}
