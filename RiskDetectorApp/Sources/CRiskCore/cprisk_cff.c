// 本文件：CFF 运行时实现（状态编码/解码、dispatcher、链与预算、S-box、decoy）。
// 位置：CRiskCore 反篡改层；被 SourceLevel CFF 宏与 VM 融合层共同调用。
// 线程模型：context 由调用线程独占；全局链/VM token 为原子量，TLS 为线程局部。
// 平台：C11 + pthread；SPN 种子可从 Mach-O 段解析，非 Apple 平台回退规范种子。
// 失败语义：链/守卫/谓词校验失败一律走 poison 或 fail-closed，绝不继续明文执行。
#include "include/CRiskCore.h"
#include "include/cprisk_macho.h"

#include <stdatomic.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <mach-o/dyld.h>

// 平台熵源选择：优先 getentropy，Apple 旧 SDK 回退 arc4random_buf。
/*
 * OS entropy hook used by `cprisk_cff_default_seed`. `getentropy(2)` is
 * available on Apple (since iOS 10 / macOS 10.12) and on glibc 2.25+ /
 * musl 1.1.20+, which covers every platform we build for. When unavailable
 * the call returns -1 and `default_seed` falls back to its prior mix.
 */
#if (defined(__APPLE__) || defined(__linux__)) && __has_include(<sys/random.h>)
#include <sys/random.h>
#define CPRISK_CFF_HAVE_GETENTROPY 1
#elif defined(__APPLE__)
#define CPRISK_CFF_HAVE_ARC4RANDOM 1
#endif

// ABI 约束：pthread_t 必须能放入 128 字节指纹缓冲区，否则编译期报错。
/*
 * `cprisk_cff_thread_fingerprint` memcpy's a `pthread_t` into a 128-byte
 * scratch buffer. On Apple targets `pthread_t` is an opaque pointer (8 bytes
 * on arm64/x86_64) — well below the buffer size — but compile-time-assert it
 * to catch future toolchain changes loudly instead of corrupting the stack.
 */
_Static_assert(sizeof(pthread_t) <= 128, "pthread_t exceeds FNV scratch buffer");

// 32-bit 循环左移；shift 自动取模 32，0 位移直接返回。
static uint32_t cprisk_cff_rotate_left32(uint32_t value, uint32_t shift) {
    const uint32_t amount = shift & 31u;
    if (amount == 0u) {
        return value;
    }
    return (value << amount) | (value >> (32u - amount));
}

// 32-bit 循环右移；与 rotate_left32 对称，用于解码路径。
static uint32_t cprisk_cff_rotate_right32(uint32_t value, uint32_t shift) {
    const uint32_t amount = shift & 31u;
    if (amount == 0u) {
        return value;
    }
    return (value >> amount) | (value << (32u - amount));
}

// 32-bit 雪崩混合（Murmur 风格双乘法）；用于所有派生常量的最终扩散。
// 不变量：同输入同输出、无分支、无全局状态。
static uint32_t cprisk_cff_avalanche32(uint32_t value) {
    uint32_t mixed = value;
    mixed ^= mixed >> 16u;
    mixed *= 0x7FEB352Du;
    mixed ^= mixed >> 15u;
    mixed *= 0x846CA68Bu;
    mixed ^= mixed >> 16u;
    return mixed;
}

// 域分离常量派生：domain 区分调用点，seed/salt/base 参与混合。
// 不变量：确定性纯函数；相同四元组必得相同值。
static uint32_t cprisk_cff_derive_const32(uint64_t domain, uint32_t seed, uint32_t salt, uint32_t base) {
    const uint32_t lo = (uint32_t)(domain & 0xFFFFFFFFu);
    const uint32_t hi = (uint32_t)(domain >> 32u);
    const uint32_t spin = ((seed ^ hi ^ (salt >> 1u)) & 31u) | 1u;
    const uint32_t lane = cprisk_cff_rotate_left32(seed ^ base ^ lo, spin);
    const uint32_t mixed0 = cprisk_cff_avalanche32(seed ^ salt ^ lo ^ base);
    const uint32_t mixed1 = cprisk_cff_avalanche32(lane ^ salt ^ hi ^ (base * (seed | 1u)));
    return cprisk_cff_avalanche32(mixed0 ^ mixed1 ^ lo ^ hi) ^ base;
}

// 强制派生值为奇数；模 2^32 下奇数才存在乘法逆元（仿射解码依赖此性质）。
static uint32_t cprisk_cff_derive_const32_odd(uint64_t domain, uint32_t seed, uint32_t salt, uint32_t base) {
    return cprisk_cff_derive_const32(domain, seed, salt, base) | 1u;
}

// 由运行时 SPN 种子派生 build seed；种子为 0 时使用规范常量回退。
/*
 * Hotspot anchors: single-site immediates + domain-tagged derivation to avoid repeating
 * the same u32 literal across chain/TLS/runtime_salt/init paths (static fingerprint noise).
 */
static uint32_t cprisk_cff_build_seed32_i(void) {
    uint64_t seed64 = cprisk_cff_runtime_spn_sbox_seed();
    if (seed64 == 0u) {
        seed64 = CPRISK_CFF_SPN_CANONICAL_SEED_U64;
    }
    return cprisk_cff_avalanche32(
        (uint32_t)seed64 ^
        cprisk_cff_rotate_left32((uint32_t)(seed64 >> 32u), 11u) ^
        0x43464642u
    );
}

// FNV basis/prime 的派生访问器：避免二进制中出现标准 FNV 常量指纹。
/*
 * Derived FNV-1a basis / prime accessors: canonical FNV basis values are
 * replaced by build-seed-derived variants to eliminate static-scannable
 * fingerprints.  The hash quality comes from the prime multiplication, not
 * the specific basis, so an arbitrary non-zero starting point is fine for
 * these internal mixing functions.  Primes are routed through volatile to
 * keep the literal out of optimised call-sites.
 */
// 32-bit FNV-1a 起始 basis；非零且由 build seed 域分离派生。
static uint32_t cprisk_cff_fnv32a_basis_i(void) {
    const uint32_t bs = cprisk_cff_build_seed32_i();
    return cprisk_cff_derive_const32(
        0x4346465F464E5631ull, bs, cprisk_cff_rotate_left32(bs, 5u), bs
    ) | 1u;
}

// 64-bit FNV-1a 起始 basis；高低 32 位分别派生后拼接，保证低位为奇数。
static uint64_t cprisk_cff_fnv64a_basis_i(void) {
    const uint32_t bs = cprisk_cff_build_seed32_i();
    const uint32_t lo = cprisk_cff_derive_const32(
        0x4346465F464E5634ull, bs, cprisk_cff_rotate_left32(bs, 5u), bs
    );
    const uint32_t hi = cprisk_cff_derive_const32(
        0x4346465F464E5635ull, bs, lo, bs ^ lo
    );
    return ((uint64_t)hi << 32) | (uint64_t)(lo | 1u);
}

// 32-bit FNV prime（16777619）经 volatile 拆分计算，防止优化器常量折叠。
static uint32_t cprisk_cff_fnv32a_prime_i(void) {
    volatile uint32_t a = (1u << 24) + (1u << 8);
    volatile uint32_t b = (9u << 4) + 3u;
    return a + b;
}

// 64-bit FNV prime（1099511628211）的 volatile 拆解形式。
static uint64_t cprisk_cff_fnv64a_prime_i(void) {
    volatile uint64_t hi = (1ULL << 40);
    volatile uint64_t lo = 435ULL;
    return hi + lo;
}

// 备用 32-bit 乘子（7096007）；用于 decoy 哈希的第二轮，区别于标准 FNV。
static uint32_t cprisk_cff_fnv_alt_prime_i(void) {
    volatile uint32_t a = 709600u;
    volatile uint32_t b = 7u;
    return a + b;
}

// 链/VM token 的零值替代哨兵；保证哨兵自身非 0 且确定性可复现。
static uint32_t cprisk_cff_chain_fallback_sentinel_u32(void) {
    const uint32_t base = cprisk_cff_derive_const32(
        0x4346465F43484E4Dull,
        0x4E5F434Eull,
        0x4B5F534Eu,
        0x9E3779B9u
    );
    const uint32_t v = cprisk_cff_derive_const32(0x4346465F43484E4Bull, 0u, 0u, base);
    return v == 0u ? 1u : v;
}

// runtime salt 派生的中间 base；把 seed 与 runtime_hint 双层混合。
static uint32_t cprisk_cff_rt_salt_mix_base_u32(uint32_t seed, uint32_t runtime_hint) {
    return cprisk_cff_derive_const32(
        0x4346465F52545334ull,
        seed,
        runtime_hint,
        cprisk_cff_derive_const32(0x4346465F52545335ull, seed ^ runtime_hint, runtime_hint, 0x13579BDFu)
    );
}

// TLS 混合常量基；由 build seed 派生，避免固定立即数。
static uint32_t cprisk_cff_tls_mix_derive_base_u32(void) {
    const uint32_t build_seed32 = cprisk_cff_build_seed32_i();
    const uint32_t base0 = cprisk_cff_derive_const32(
        0x4346465F544C5331ull,
        build_seed32,
        cprisk_cff_rotate_left32(build_seed32, 9u),
        0x9E3779B9u
    );
    return cprisk_cff_derive_const32(
        0x4346465F544C5332ull,
        build_seed32 ^ base0,
        cprisk_cff_rotate_left32(base0, 13u),
        0xA24BAED5u
    );
}

// 对 pthread_t 字节做 FNV-1a，得到线程相关的 64-bit 指纹。
// 注意：pthread_t 不是秘密，仅用于打破跨线程确定性，不承担认证。
static uint64_t cprisk_cff_thread_fingerprint(void) {
    pthread_t current = pthread_self();
    unsigned char bytes[sizeof(pthread_t)];
    uint64_t hash = cprisk_cff_fnv64a_basis_i();
    const uint64_t prime = cprisk_cff_fnv64a_prime_i();
    size_t index = 0u;

    memcpy(bytes, &current, sizeof(pthread_t));
    for (index = 0u; index < sizeof(pthread_t); ++index) {
        hash ^= (uint64_t)bytes[index];
        hash *= prime;
    }

    return hash;
}

// 读取 kern.osrelease 并哈希，混入 OS 版本熵；sysctl 失败时退回 PID/长度混合。
static uint32_t cprisk_cff_os_mix32(void) {
    char osrelease[128];
    size_t len = sizeof(osrelease);
    int err = 0;
    if (cprisk_sysctlbyname_direct("kern.osrelease", osrelease, &len, NULL, 0, &err) != 0 || len == 0) {
        return cprisk_cff_derive_const32(
            0x4346465F4F534D58ull,
            (uint32_t)getpid(),
            (uint32_t)len,
            0xA24BAED5u
        );
    }

    uint32_t hash = cprisk_cff_fnv32a_basis_i();
    const uint32_t prime = cprisk_cff_fnv32a_prime_i();
    for (size_t i = 0; i < len && osrelease[i] != '\0'; i++) {
        hash ^= (uint32_t)(uint8_t)osrelease[i];
        hash *= prime;
    }
    return hash;
}

// 以已加载镜像数量派生熵；数量变化会影响运行时盐与 decode 结果。
static uint32_t cprisk_cff_dyld_mix32(void) {
    const uint32_t bs = cprisk_cff_build_seed32_i();
    const uint32_t dyld_salt_k = cprisk_cff_derive_const32(
        0x4346465F44594C31ull, bs, cprisk_cff_rotate_left32(bs, 7u), bs
    );
    const uint32_t dyld_base_k = cprisk_cff_derive_const32(
        0x4346465F44594C32ull, bs, cprisk_cff_rotate_left32(bs, 13u), bs
    );
    const uint32_t image_count = _dyld_image_count();
    return
        (image_count << 9u) ^
        (image_count >> 5u) ^
        cprisk_cff_derive_const32(0x4346465F44594C44ull, image_count, image_count ^ dyld_salt_k, dyld_base_k);
}

/*
 * Affine codec helpers. Multiplication and addition operate mod 2^32 with
 * unsigned wrap-around (well-defined per C11 6.2.5/9). The codec relies on
 * this exact wrap behavior — the inverse path uses `mod_inverse_odd32` to
 * undo `masked * multiplier` and a plain `unxored - addend` subtraction to
 * undo `+ addend`. Both round-trip exactly under uint32_t arithmetic. The
 * `| 1u` below ensures the multiplier is odd so its mod-2^32 inverse exists.
 */
// 派生仿射乘子并强制奇数；奇数在模 2^32 下必有逆元，编码才可逆。
static uint32_t cprisk_cff_affine_multiplier(uint32_t key, uint32_t salt) {
    const uint32_t mix_const = cprisk_cff_derive_const32(
        0x4346465F53544632ull,
        key,
        salt,
        0xD1B54A35u
    );
    return cprisk_cff_avalanche32(key ^ cprisk_cff_rotate_left32(salt, 7u) ^ mix_const) | 1u;
}

// 派生仿射加数；与 multiplier 使用不同 domain，避免两者相关。
static uint32_t cprisk_cff_affine_addend(uint32_t key, uint32_t salt) {
    const uint32_t mul = cprisk_cff_derive_const32_odd(
        0x4346465F53544633ull,
        key,
        salt,
        0x9E3779B1u
    );
    const uint32_t add_const = cprisk_cff_derive_const32(
        0x4346465F53544634ull,
        key,
        salt,
        0x94D049BBu
    );
    return cprisk_cff_avalanche32((key * mul) ^ salt ^ add_const);
}

// MBA 等价 XOR：利用无符号回绕恒等式 (a|b)-(a&b) == a^b。
/*
 * MBA-equivalent XOR: (a|b) - (a&b) === a ^ b (unsigned wrap).
 * Selected via seed/salt mix to keep decode/encode symmetric.
 */
// MBA XOR 单层实现；编码与解码使用同一定义保证互逆。
static uint32_t cprisk_cff_xor_mba_u32(uint32_t a, uint32_t b) {
    return (a | b) - (a & b);
}

// 复合 MBA 层：每层语义仍是 XOR，但语法在 4 种等价恒等式间轮换。
/*
 * Composite MBA layers (2-5): each layer is semantically XOR with a derived key;
 * syntax rotates across several MBA-equivalent identities to resist pattern
 * matching on a single (a|b)-(a&b) form.
 */
// 按 layer/key 派生选择器；(sel & 3) 决定使用哪种等价形式。
static uint32_t cprisk_cff_xor_mba_layer_u32(uint32_t x, uint32_t k, uint32_t layer_ix) {
    const uint32_t selector_mix = cprisk_cff_derive_const32(
        0x4346465F4D424131ull,
        k,
        layer_ix,
        0x13579BDFu
    );
    const uint32_t sel =
        (layer_ix + cprisk_cff_avalanche32(k ^ selector_mix) + (k >> 17u)) & 3u;
    switch (sel) {
        case 0u:
            return cprisk_cff_xor_mba_u32(x, k);
        case 1u:
            return (x & ~k) | (~x & k);
        case 2u:
            return x + k - (2u * (x & k));
        default:
            return x ^ k;
    }
}

// MBA 链入口：layers < 2 原样返回（轻量级函数显式退出）；上限钳制到 8。
/*
 * MBA chain. `layers == 0 || layers == 1` is the documented "bypass" path
 * and returns `v` unchanged — this is how light-tier and never-tier
 * functions opt out of MBA entirely. Audit pass flagged the silent
 * no-op as a strength regression for light tier; the behavior is
 * intentional (light tier accepts weaker obfuscation in exchange for
 * lower overhead), but the contract is documented here so future
 * readers do not "fix" it by forcing layers >= 2.
 */
// 逐层 XOR 派生密钥；每层 key 由 step_mul/step_xor 与层号共同派生。
static uint32_t cprisk_cff_mba_chain_xor_u32(uint32_t v, uint32_t key, uint32_t salt, uint8_t layers) {
    uint8_t L = layers;
    if (L < 2u) {
        return v;
    }
    if (L > 8u) {
        L = 8u;
    }
    uint32_t cur = v;
    for (uint8_t i = 0u; i < L; i++) {
        const uint32_t step_mul = cprisk_cff_derive_const32_odd(
            0x4346465F4D424132ull,
            key,
            salt,
            0x9E3779B1u
        );
        const uint32_t step_xor = cprisk_cff_derive_const32(
            0x4346465F4D424133ull,
            key ^ (uint32_t)i,
            salt,
            0xD1B54A35u
        );
        const uint32_t ki =
            cprisk_cff_avalanche32(key ^ salt ^ ((uint32_t)i * step_mul) ^ step_xor);
        cur = cprisk_cff_xor_mba_layer_u32(cur, ki, (uint32_t)i);
    }
    return cur;
}

// 归一化 MBA 层数：合法值原样保留；0/越界按种子在 2..5 中确定性选择。
// 用 & 3u 取两位而不是 % 4，避免除法并消除取模偏差。
static uint8_t cprisk_cff_normalize_mba_layers(uint32_t seed, uint8_t requested) {
    if (requested >= 2u && requested <= 5u) {
        return requested;
    }
    if (requested >= CPRISK_CFF_MBA_LAYERS_HEAVY_MIN && requested <= CPRISK_CFF_MBA_LAYERS_HEAVY_MAX) {
        return requested;
    }
    if (requested == 1u) {
        return 1u;
    }
    /*
     * 0 (unset) or out-of-range (>= 9): auto-pick uniformly from {2,3,4,5}.
     * Use `& 3u` to extract two bits (no modulo bias) instead of `% 4u`.
     */
    return (uint8_t)(2u + (cprisk_cff_avalanche32(
        seed ^ cprisk_cff_derive_const32(0x4346465F4D424134ull, seed, requested, 0x51ED270Bu)
    ) & 3u));
}

// 解析 dispatcher 风格：非 AUTO 直接采用；COMPUTED_GOTO 降级为 FN_TABLE；
// AUTO 按种子在 DIRECT/FN_TABLE 间二选一。
static uint8_t cprisk_cff_resolve_dispatch_style_u8(uint32_t seed, uint8_t requested) {
    if (requested == (uint8_t)CPRISK_CFF_DISPATCH_DIRECT ||
        requested == (uint8_t)CPRISK_CFF_DISPATCH_FN_TABLE) {
        return requested;
    }
    if (requested == (uint8_t)CPRISK_CFF_DISPATCH_COMPUTED_GOTO) {
        /* Unstable on some toolchains: use real handler-table dispatch instead. */
        return (uint8_t)CPRISK_CFF_DISPATCH_FN_TABLE;
    }
    /* AUTO */
    return (cprisk_cff_avalanche32(
        seed ^ cprisk_cff_derive_const32(0x4346465F44535031ull, seed, requested, 0xA5A5A5A5u)
    ) & 1u) != 0u
        ? (uint8_t)CPRISK_CFF_DISPATCH_FN_TABLE
        : (uint8_t)CPRISK_CFF_DISPATCH_DIRECT;
}

// 模 2^32 乘法逆元（Newton–Raphson）：每轮正确位数翻倍，6 轮足以覆盖 32 位。
// 前提：输入 odd_value 必须为奇数，否则逆元不存在。
/*
 * Newton–Raphson modular inverse mod 2^32. Convergence is quadratic, doubling
 * the number of correct low-order bits each step. Starting from `odd_value`
 * (which is correct in the lowest bit), 6 iterations guarantee >= 64 correct
 * bits — saturated within the 32-bit width with margin.
 *
 * Precondition: `odd_value` is odd. If even, the modular inverse does not
 * exist mod 2^32 and the iteration silently produces garbage; callers must
 * ensure oddness (see `cprisk_cff_affine_multiplier` / `_odd` helpers which
 * force the low bit set).
 */
// 防御性置最低位；已为奇数时语义不变，偶数输入会得到错误但不会崩溃。
static uint32_t cprisk_cff_mod_inverse_odd32(uint32_t odd_value) {
    /* Defense in depth: force the low bit to avoid silent corruption if a
     * caller miswires this. The cost is one OR; semantics for already-odd
     * inputs are unchanged. */
    const uint32_t v = odd_value | 1u;
    uint32_t inverse = v;
    inverse *= 2u - v * inverse;
    inverse *= 2u - v * inverse;
    inverse *= 2u - v * inverse;
    inverse *= 2u - v * inverse;
    inverse *= 2u - v * inverse;
    inverse *= 2u - v * inverse;
    return inverse;
}

// 运行时 SPN 前向 S-box 及其初始化状态；表是 256 字节双射置换。
// 并发约定：安装路径持互斥锁，热路径无锁读取单字节。
/*
 * SPN byte substitution: 8-bit bijection generated at runtime from a UInt64 seed
 * (CFFSBoxPermutation256 / SplitMix64 + Fisher–Yates). Matches CloudPhoneRiskKit.
 */
static uint8_t g_cff_spn_sbox_fwd[256];
static pthread_once_t g_cff_spn_sbox_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_cff_spn_sbox_mutex = PTHREAD_MUTEX_INITIALIZER;
static atomic_uint_fast32_t g_cff_spn_sbox_custom = 0;
static atomic_uint_fast64_t g_cff_spn_sbox_seed = 0;

// SplitMix64 状态机；state 为 64-bit 递推值，不作为加密随机数使用。
typedef struct cprisk_cff_split_mix64 {
    uint64_t state;
} cprisk_cff_split_mix64_t;

// SplitMix64 初始化：0 种子替换为 1，避免全零退化。
static void cprisk_cff_split_mix64_init(cprisk_cff_split_mix64_t *rng, uint64_t seed) {
    rng->state = seed == 0u ? 1u : seed;
}

// 生成下一个 64-bit 输出；加法步进使用黄金比例常量保证长周期。
static uint64_t cprisk_cff_split_mix64_next(cprisk_cff_split_mix64_t *rng) {
    rng->state += 0x9E3779B97F4A7C15ull;
    uint64_t z = rng->state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

// 无偏区间采样 [0,bound)：拒绝落在阈值以下的样本，消除模偏差。
/*
 * Rejection-sampled uniform draw from [0, bound). Removes modulo bias when
 * `bound` does not divide 2^64. Threshold = 2^64 mod bound, computed as
 * `((uint64_t)0 - bound) % bound` (defined unsigned wrap). For bound <= 256
 * the rejection probability is at most 256/2^64 (≈ 0), but the distribution
 * is mathematically uniform.
 *
 * Cross-language contract: identical algorithm in
 * `cprisk-armor/.../CFFSBoxPermutation.swift` and
 * `CloudPhoneRiskKit/.../CFFSBoxRuntime.swift`.
 */
// bound 为 0 返回 0；阈值 = 2^64 mod bound，拒绝采样后取模。
static uint64_t cprisk_cff_split_mix64_unbiased(cprisk_cff_split_mix64_t *rng, uint64_t bound) {
    if (bound == 0u) {
        return 0u;
    }
    const uint64_t threshold = ((uint64_t)0 - bound) % bound;
    uint64_t r;
    do {
        r = cprisk_cff_split_mix64_next(rng);
    } while (r < threshold);
    return r % bound;
}

// 校验 table 是否为 0..255 的双射；长度必须恰为 256，重复字节即拒绝。
static int cprisk_cff_spn_is_bijection_sized_u8(const uint8_t *table, size_t len) {
    if (table == NULL || len != 256u) {
        return 0;
    }
    uint8_t seen[256];
    memset(seen, 0, sizeof(seen));
    for (size_t i = 0u; i < 256u; ++i) {
        const uint8_t v = table[i];
        if (seen[v] != 0u) {
            return 0;
        }
        seen[v] = 1u;
    }
    return 1;
}

// 固定长度包装；供安装接口做 O(256) 合法性检查。
static int cprisk_cff_spn_is_bijection_u8(const uint8_t table[256]) {
    return cprisk_cff_spn_is_bijection_sized_u8(table, 256u);
}

// Fisher–Yates 洗牌生成双射；使用无偏采样，结果与 Swift 侧逐字节一致。
static void cprisk_cff_spn_sbox_build_from_seed(uint64_t seed) {
    cprisk_cff_split_mix64_t rng;
    cprisk_cff_split_mix64_init(&rng, seed);
    for (size_t i = 0u; i < 256u; ++i) {
        g_cff_spn_sbox_fwd[i] = (uint8_t)i;
    }
    for (size_t i = 255u; i > 0u; --i) {
        const uint64_t j = cprisk_cff_split_mix64_unbiased(&rng, (uint64_t)(i + 1u));
        const uint8_t tmp = g_cff_spn_sbox_fwd[i];
        g_cff_spn_sbox_fwd[i] = g_cff_spn_sbox_fwd[(size_t)j];
        g_cff_spn_sbox_fwd[(size_t)j] = tmp;
    }
}

// 从 __DATA,<section> 解析链元数据头并取出 build_seed。
// - 参数：hdr 必须为当前 Mach-O 头；section_name 为段内节名；out_seed 非 NULL。
// - 返回：1 成功并写 *out_seed；0 节缺失/魔数或 ABI 不符/尺寸溢出。
// - 线程安全：只读 Mach-O 内存，可并发。
static int cprisk_cff_resolve_chain_meta_seed_i(
    const struct mach_header_64 *hdr,
    const char *section_name,
    uint64_t *out_seed
) {
    unsigned long sec_size = 0u;
    const uint8_t *sec = cprisk_find_section(
        hdr,
        CPRISK_ARMOR_SEGMENT_DATA,
        section_name,
        &sec_size
    );
    if (sec == NULL || sec_size < CPRISK_ARMOR_SWIFT_METADATA_SHUFFLE_HEADER_SIZE) {
        return 0;
    }

    // 尺寸计算必须防溢出：恶意 record_count 可让乘法回绕，必须在取节前拒绝。
    struct cprisk_armor_swift_metadata_shuffle_header header;
    memcpy(&header, sec, sizeof(header));
    if (header.magic != CPRISK_ARMOR_SWIFT_METADATA_SHUFFLE_MAGIC ||
        header.abi_version != CPRISK_ARMOR_SWIFT_METADATA_SHUFFLE_ABI_VERSION) {
        return 0;
    }

    // 节大小必须精确等于 header+records，避免容忍截断或尾随注入数据。
    /* Overflow-safe size computation: a malformed header could claim a
     * record_count near UINT32_MAX, multiplying past size_t. */
    size_t records_total = 0u;
    if (__builtin_mul_overflow((size_t)header.record_count,
                               (size_t)CPRISK_ARMOR_SWIFT_METADATA_SHUFFLE_RECORD_SIZE,
                               &records_total)) {
        return 0;
    }
    size_t expected = 0u;
    if (__builtin_add_overflow((size_t)CPRISK_ARMOR_SWIFT_METADATA_SHUFFLE_HEADER_SIZE,
                               records_total,
                               &expected)) {
        return 0;
    }
    /*
     * Section must be EXACTLY the header+records size. Previously
     * `expected > sec_size` accepted any larger section, silently
     * tolerating truncation drift or attacker-injected trailing bytes
     * that downstream consumers might honor. Reject mismatched sizes.
     */
    if (expected != (size_t)sec_size) {
        return 0;
    }

    *out_seed = header.build_seed != 0u ? header.build_seed : CPRISK_CFF_SPN_CANONICAL_SEED_U64;
    return 1;
}

// 解析运行时 SPN 种子：优先 anti-debug 计划段，其次 chain-meta 主/备节。
// - 返回：解析到的非 0 种子；全部失败时回退 CPRISK_CFF_SPN_CANONICAL_SEED_U64。
// - 线程安全：只读 Mach-O；可在 once 初始化内调用。
static uint64_t cprisk_cff_resolve_runtime_spn_seed_i(void) {
    const struct mach_header_64 *hdr =
        cprisk_find_own_header((const void *)(uintptr_t)&cprisk_cff_encode_state);
    if (hdr != NULL) {
        unsigned long sec_size = 0u;
        const uint8_t *sec = cprisk_find_section(
            hdr,
            CPRISK_ARMOR_SEGMENT_DATA,
            CPRISK_ARMOR_SECTION_ANTI_DEBUG_PLAN,
            &sec_size
        );
        if (sec != NULL && sec_size >= sizeof(struct cprisk_armor_antidebug_header)) {
            struct cprisk_armor_antidebug_header header;
            memcpy(&header, sec, sizeof(header));
            if (header.magic == CPRISK_ARMOR_ADBG_MAGIC &&
                header.version == CPRISK_ARMOR_ADBG_ABI_VERSION &&
                header.seed != 0u) {
                return header.seed;
            }
        }

        uint64_t chain_seed = 0u;
        if (cprisk_cff_resolve_chain_meta_seed_i(hdr, CPRISK_ARMOR_SECTION_CHAIN_META, &chain_seed) != 0) {
            return chain_seed;
        }
        if (cprisk_cff_resolve_chain_meta_seed_i(
                hdr,
                CPRISK_ARMOR_SECTION_CHAIN_META_FALLBACK,
                &chain_seed) != 0) {
            return chain_seed;
        }
    }
    return CPRISK_CFF_SPN_CANONICAL_SEED_U64;
}

// S-box 并发模型：首次构建由 pthread_once 串行化；后续安装持互斥锁写入，
// 热路径读取不加锁，最多读到新旧两个合法置换之一，不会读到撕裂表。
/*
 * Concurrency model for the S-box state:
 *
 *  - First read: any caller hitting `cprisk_cff_spn_sbox_ensure()` triggers
 *    `pthread_once` once, which runs `init_default` under the once-lock —
 *    no other thread can read the table during that initial build.
 *  - Subsequent installs (`install_from_seed`, `install_from_bytes`): used
 *    rarely (typically armor-driven, once at startup). The previous code
 *    set `custom=1` BEFORE writing the 256-byte table, which let a
 *    concurrent reader that reached `ensure()` for the first time skip
 *    `init_default` (since `custom!=0`) and observe an uninitialized table.
 *
 * Fix:
 *  - Both installers now (a) ensure the once-init has run, then (b) take
 *    `g_cff_spn_sbox_mutex` and write the table under the mutex. The atomic
 *    `custom` / `seed` flags are stored AFTER the table write so a reader
 *    that misses the lock either sees the prior table or the new one — never
 *    a torn intermediate.
 *  - Hot-path readers (`spn_sbox_byte`) remain lock-free: they only run
 *    after `_ensure()` and accept that during a rare concurrent install
 *    they may read either the old or the new byte, both of which are valid
 *    permutation entries (every byte 0..255 maps to a byte 0..255).
 */

// once 初始化回调：若已有自定义表则跳过；否则解析构建种子并生成默认表。
static void cprisk_cff_spn_sbox_init_default(void) {
    if (atomic_load(&g_cff_spn_sbox_custom) != 0u) {
        return;
    }
    const uint64_t seed = cprisk_cff_resolve_runtime_spn_seed_i();
    atomic_store(&g_cff_spn_sbox_seed, (uint_fast64_t)seed);
    cprisk_cff_spn_sbox_build_from_seed(seed);
}

// 保证 S-box 已初始化；pthread_once 保证回调只执行一次。
static void cprisk_cff_spn_sbox_ensure(void) {
    (void)pthread_once(&g_cff_spn_sbox_once, cprisk_cff_spn_sbox_init_default);
}

// 安装指定种子的 SPN 表；0 种子归一为 1；先确保 once 已运行再加锁写入。
void cprisk_cff_spn_sbox_install_from_seed(uint64_t seed) {
    const uint64_t normalized = seed == 0u ? 1u : seed;
    cprisk_cff_spn_sbox_ensure();
    pthread_mutex_lock(&g_cff_spn_sbox_mutex);
    cprisk_cff_spn_sbox_build_from_seed(normalized);
    atomic_store(&g_cff_spn_sbox_seed, (uint_fast64_t)normalized);
    atomic_store(&g_cff_spn_sbox_custom, 1u);
    pthread_mutex_unlock(&g_cff_spn_sbox_mutex);
}

// 安装外部提供的 256 字节前向表；非双射输入直接拒绝，保留现有表。
void cprisk_cff_spn_sbox_install_from_bytes(const uint8_t forward256[256]) {
    if (forward256 == NULL) {
        return;
    }
    /*
     * Refuse non-bijective input. Previously this fell back to canonical seed,
     * which let an attacker who could call this API force a downgrade from a
     * per-build randomized table to the static canonical permutation. Now we
     * leave whatever table is currently installed; the next consumer that hits
     * `cprisk_cff_spn_sbox_ensure()` triggers the per-build init via
     * `cprisk_cff_resolve_runtime_spn_seed_i()`.
     */
    if (cprisk_cff_spn_is_bijection_u8(forward256) == 0) {
        return;
    }
    cprisk_cff_spn_sbox_ensure();
    pthread_mutex_lock(&g_cff_spn_sbox_mutex);
    memcpy(g_cff_spn_sbox_fwd, forward256, 256u);
    atomic_store(&g_cff_spn_sbox_seed, 0u);
    atomic_store(&g_cff_spn_sbox_custom, 1u);
    pthread_mutex_unlock(&g_cff_spn_sbox_mutex);
}

// 读取当前 SPN 种子；install_from_bytes 安装的表种子为 0。
uint64_t cprisk_cff_runtime_spn_sbox_seed(void) {
    cprisk_cff_spn_sbox_ensure();
    return (uint64_t)atomic_load(&g_cff_spn_sbox_seed);
}

// 复制当前前向 S-box 快照；NULL 返回 -1；持锁保证快照是完整双射。
int cprisk_cff_spn_sbox_copy_forward(uint8_t out_forward256[256]) {
    if (out_forward256 == NULL) {
        return -1;
    }
    cprisk_cff_spn_sbox_ensure();
    /*
     * Take the install-mutex to guarantee a consistent snapshot. Without it,
     * a concurrent `install_from_seed` writing the table could produce a
     * caller-observable mix of the old and new permutation; the result might
     * not be a bijection, breaking any consumer that round-trips through it.
     */
    pthread_mutex_lock(&g_cff_spn_sbox_mutex);
    memcpy(out_forward256, g_cff_spn_sbox_fwd, 256u);
    pthread_mutex_unlock(&g_cff_spn_sbox_mutex);
    return 0;
}

// 热路径单字节查表；假定 ensure 已完成，读到的字节总是合法置换项。
static uint8_t cprisk_cff_spn_sbox_byte(uint8_t idx) {
    cprisk_cff_spn_sbox_ensure();
    return g_cff_spn_sbox_fwd[idx];
}

// 公开单字节查表包装；首次调用触发惰性初始化。
uint8_t cprisk_cff_spn_sbox_lookup(uint8_t idx) {
    return cprisk_cff_spn_sbox_byte(idx);
}

// decoy 混合器：输出只异或进 volatile sink，不影响 Feistel 的真实结果。
/*
 * `shadow_noise16` is a 4-step decoy mixer whose output is XOR'd into a
 * `volatile` sink and then `(void)`'d — i.e. it does not affect the Feistel
 * cipher's mathematical output, only the runtime instruction trace and timing
 * profile. The fixed 4 iterations balance instruction count against per-round
 * Feistel cost; widening the loop slows the hot dispatcher path with no
 * additional security in our threat model (instruction-level deobfuscation,
 * not chosen-plaintext cryptanalysis).
 */
// 固定 4 步的 shadow 计算；用于制造与主流程无关的指令/时序噪声。
static uint16_t cprisk_cff_shadow_noise16(uint16_t r, uint32_t rk, uint32_t salt, uint32_t round) {
    volatile uint32_t sink = ((uint32_t)r << 16u) | (uint32_t)r;
    const uint32_t round_mul = cprisk_cff_derive_const32_odd(
        0x4346465F53484431ull,
        rk,
        salt,
        0x51ED270Bu
    );
    const uint32_t shadow_xor = cprisk_cff_derive_const32(
        0x4346465F53484432ull,
        rk,
        salt,
        0xA5C31F27u
    );
    const uint32_t lane_mul = cprisk_cff_derive_const32_odd(
        0x4346465F53484433ull,
        rk,
        salt,
        0x9E3779B1u
    );
    const uint32_t lane_add = cprisk_cff_derive_const32(
        0x4346465F53484434ull,
        rk,
        salt,
        0x7F4A7C15u
    );
    uint32_t shadow = cprisk_cff_avalanche32(rk ^ salt ^ (round * round_mul) ^ shadow_xor);
    for (uint32_t step = 0u; step < 4u; ++step) {
        const uint32_t lane = cprisk_cff_rotate_left32(
            shadow ^ sink ^ (step * lane_mul),
            (uint32_t)((round + (step * 5u) + 3u) & 31u)
        );
        shadow ^= cprisk_cff_avalanche32(
            lane +
            (sink ^ cprisk_cff_rotate_right32(rk, (uint32_t)((step + 3u) & 31u))) +
            lane_add
        );
        sink ^= lane ^ cprisk_cff_rotate_right32(shadow, (uint32_t)((step + 7u) & 31u));
    }
    sink ^= cprisk_cff_rotate_left32(sink ^ shadow, (uint32_t)(((round * 3u) + 11u) & 31u));
    return (uint16_t)((shadow ^ sink ^ (shadow >> 16u)) & 0xFFFFu);
}

// 8 轮 Feistel：CFF 状态编码原语，不是数据保密密码；前向 S-box 即可完成逆运算。
/*
 * 8-round Feistel network. This is a state-encoding primitive for CFF
 * dispatcher obfuscation, not a data-confidentiality cipher: the round
 * function combines an avalanche permutation, a SplitMix64-derived 256-byte
 * S-box (forward-only — Feistel inversion does not need an inverse table),
 * and double SPN substitution. 8 rounds yields full byte-level diffusion
 * with margin for this attack model (no chosen-plaintext oracle); higher
 * round counts only add latency on a hot dispatcher path.
 */
// 轮数常量：8 轮已实现字节级充分扩散；增加轮数只线性增加热路径延迟。
#define CPRISK_CFF_FEISTEL_ROUNDS 8u

// 单轮轮函数：S-box 双字节代换 + 雪崩 + 两路 shadow decoy。
static uint16_t cprisk_cff_feistel_F(uint16_t r, uint32_t k, uint32_t salt, uint32_t round) {
    const uint32_t round_mul = cprisk_cff_derive_const32_odd(
        0x4346465F46535231ull,
        k,
        salt,
        0x9E3779B9u
    );
    const uint32_t round_xor = cprisk_cff_derive_const32(
        0x4346465F46535232ull,
        k,
        salt,
        0xDEADBEEFu
    );
    uint32_t rk = cprisk_cff_avalanche32(k ^ salt ^ (round * round_mul) ^ round_xor);
    uint8_t b0 = (uint8_t)(r & 0xFFu);
    uint8_t b1 = (uint8_t)((r >> 8) & 0xFFu);
    uint32_t piece = (uint32_t)cprisk_cff_spn_sbox_byte(b0 ^ (uint8_t)(rk & 0xFFu)) ^
        ((uint32_t)cprisk_cff_spn_sbox_byte(b1 ^ (uint8_t)((rk >> 8) & 0xFFu)) << 8u);
    {
        const uint32_t shadow_k_xor = cprisk_cff_derive_const32(
            0x4346465F46535233ull,
            k,
            salt,
            0x6C8E9CF5u
        );
        const uint32_t shadow_s_xor = cprisk_cff_derive_const32(
            0x4346465F46535234ull,
            k,
            salt,
            0x517CC1B7u
        );
        const uint16_t shadow0 = cprisk_cff_shadow_noise16(r, rk, salt, round);
        const uint16_t shadow1 = cprisk_cff_shadow_noise16(
            (uint16_t)(r ^ shadow0),
            rk ^ piece ^ shadow_k_xor,
            salt ^ shadow_s_xor,
            round + 1u
        );
        volatile uint32_t shadow_sink = (uint32_t)shadow0 ^ ((uint32_t)shadow1 << 16u);
        shadow_sink ^= cprisk_cff_rotate_left32(shadow_sink ^ rk, (uint32_t)((round & 7u) + 3u));
        (void)shadow_sink;
    }
    piece ^= rk ^ (rk >> 16);
    piece = cprisk_cff_avalanche32(piece);
    return (uint16_t)((piece ^ (piece >> 16)) & 0xFFFFu);
}

// Feistel 编码核心：前置白化 → 8 轮 (L,R) 迭代 → 后置白化。
static uint32_t cprisk_cff_feistel32_encode_core(uint32_t state, uint32_t key, uint32_t salt) {
    const uint32_t pre_xor = cprisk_cff_derive_const32(0x4346465F46534531ull, key, salt, 0x0F1055A1u);
    const uint32_t post_xor = cprisk_cff_derive_const32(0x4346465F46534532ull, key, salt, 0x0ACC0DECu);
    uint32_t v = state ^ cprisk_cff_avalanche32(key ^ salt ^ pre_xor);
    uint16_t l = (uint16_t)(v >> 16);
    uint16_t r = (uint16_t)(v & 0xFFFFu);
    for (uint32_t rnd = 0u; rnd < CPRISK_CFF_FEISTEL_ROUNDS; rnd++) {
        const uint16_t nl = r;
        const uint16_t nr = (uint16_t)(l ^ cprisk_cff_feistel_F(r, key, salt, rnd));
        l = nl;
        r = nr;
    }
    const uint32_t mid = ((uint32_t)l << 16) | (uint32_t)r;
    return mid ^ cprisk_cff_avalanche32(key ^ salt ^ post_xor);
}

// 解码是编码的严格逆：前后白化常量必须一致，轮循环逆序且复用同一 F。
/*
 * Decode is the strict inverse of `cprisk_cff_feistel32_encode_core`:
 *   - `pre_xor` and `post_xor` use the SAME derivation as encode (must
 *     match exactly, otherwise pre/post whitening is not undone);
 *   - the round loop iterates rounds in REVERSE (R-1 → 0) with the same
 *     `feistel_F` since Feistel inversion does not need an inverse F.
 * Constants `0x0F1055A1` ("FLOSS-A1") and `0x0ACC0DEC` ("ACC0DEC") are
 * retained as call-site bases that get re-mixed through `derive_const32`.
 */
// 逆序执行 8 轮；Feistel 的逆不需要 F 的逆，只需相同的 F。
static uint32_t cprisk_cff_feistel32_decode_core(uint32_t encoded_state, uint32_t key, uint32_t salt) {
    const uint32_t pre_xor = cprisk_cff_derive_const32(0x4346465F46534531ull, key, salt, 0x0F1055A1u);
    const uint32_t post_xor = cprisk_cff_derive_const32(0x4346465F46534532ull, key, salt, 0x0ACC0DECu);
    uint32_t mid = encoded_state ^ cprisk_cff_avalanche32(key ^ salt ^ post_xor);
    uint16_t l = (uint16_t)(mid >> 16);
    uint16_t r = (uint16_t)(mid & 0xFFFFu);
    uint32_t rnd = CPRISK_CFF_FEISTEL_ROUNDS;
    while (rnd > 0u) {
        rnd--;
        const uint16_t pr = l;
        const uint16_t pl = (uint16_t)(r ^ cprisk_cff_feistel_F(l, key, salt, rnd));
        l = pl;
        r = pr;
    }
    const uint32_t v = ((uint32_t)l << 16) | (uint32_t)r;
    return v ^ cprisk_cff_avalanche32(key ^ salt ^ pre_xor);
}

// 解析编码风格：非 AUTO 直接采用；AUTO 以 3/4 概率选 Feistel，其余在三种线性风格中轮换。
static cprisk_cff_codec_style_t cprisk_cff_resolve_style(uint32_t seed, uint32_t entry_state, uint8_t requested_style) {
    const cprisk_cff_codec_style_t requested = (cprisk_cff_codec_style_t)requested_style;
    if (requested == CPRISK_CFF_CODEC_STYLE_XOR_ROTATE ||
        requested == CPRISK_CFF_CODEC_STYLE_ADD_ROTATE_XOR ||
        requested == CPRISK_CFF_CODEC_STYLE_AFFINE ||
        requested == CPRISK_CFF_CODEC_STYLE_FEISTEL_SPN) {
        return requested;
    }

    /* AUTO: strongly bias toward Feistel+S-box (non-linear) vs. XOR-MBA-heavy styles. */
    const uint32_t selector_xor = cprisk_cff_derive_const32(
        0x4346465F5354594Cull,
        seed,
        entry_state,
        0x13579BDFu
    );
    const uint32_t h = cprisk_cff_avalanche32(seed ^ cprisk_cff_rotate_left32(entry_state, 11u) ^ selector_xor);
    if ((h & 3u) != 0u) {
        return CPRISK_CFF_CODEC_STYLE_FEISTEL_SPN;
    }
    switch (h % 3u) {
        case 0u:
            return CPRISK_CFF_CODEC_STYLE_XOR_ROTATE;
        case 1u:
            return CPRISK_CFF_CODEC_STYLE_ADD_ROTATE_XOR;
        default:
            return CPRISK_CFF_CODEC_STYLE_AFFINE;
    }
}

// 线程局部 TLS 混合值；每次迁移/链推进都会改写，用于打破跨线程确定性。
// 全局 VM 链 token 与跨函数链值；原子读写，0 表示尚未初始化。
static _Thread_local uint32_t cprisk_cff_tls_mix32 = 0u;
static atomic_uint_fast32_t s_cff_vm_link_token = 0;
static atomic_uint_fast32_t s_cff_chain_link = 0;

// 读取全局链；为 0 时用 CAS 写入确定性哨兵，避免并发重复初始化。
static uint32_t cprisk_cff_chain_load_i(void) {
    uint_fast32_t chain = atomic_load(&s_cff_chain_link);
    if (chain == 0u) {
        /*
         * Race-free initialization: previously a concurrent caller could
         * race between the load and the store, with both threads computing
         * the sentinel and storing it. Although the value is deterministic
         * (so the race was benign), CAS makes the intent explicit and
         * prevents the second thread from clobbering a value another path
         * may legitimately have stored in between.
         */
        const uint_fast32_t sentinel =
            (uint_fast32_t)cprisk_cff_chain_fallback_sentinel_u32();
        uint_fast32_t expected = 0u;
        if (!atomic_compare_exchange_strong(&s_cff_chain_link, &expected, sentinel)) {
            /* Some other thread already initialized — adopt their value. */
            chain = expected;
        } else {
            chain = sentinel;
        }
    }
    return (uint32_t)chain;
}

// 把明文 last_state 拆成两个份额存储；单看任一字段无法还原明文。
static void cprisk_cff_ctx_set_last_plain_i(cprisk_cff_context_t *context, uint32_t plain) {
    const uint32_t split_mask = cprisk_cff_hdr_avalanche32(
        cprisk_cff_ctx_mask_enc(context) ^ cprisk_cff_ctx_nonce_plain(context) ^ cprisk_cff_hdr_const32(
            0x4346465F43545835ull,
            cprisk_cff_ctx_mask_enc(context),
            cprisk_cff_ctx_nonce_plain(context),
            cprisk_cff_hdr_base_derive(0x4346465F42415335ull, 0x5F3759DFu)
        )
    );
    context->state_share_a = cprisk_cff_avalanche32(
        plain ^ cprisk_cff_ctx_seed_plain(context) ^ cprisk_cff_ctx_nonce_plain(context) ^ cprisk_cff_derive_const32(
            0x4346465F4354583Cull,
            cprisk_cff_ctx_mask_enc(context),
            cprisk_cff_ctx_nonce_plain(context),
            0x1A2B3C4Du
        )
    );
    context->state_share_b = plain ^ context->state_share_a ^ split_mask;
}

// 以 storage/nonce 派生掩码后写入链快照。
static void cprisk_cff_ctx_set_chain_plain_i(cprisk_cff_context_t *context, uint32_t chain) {
    const uint32_t chain_mask = cprisk_cff_hdr_avalanche32(
        cprisk_cff_ctx_storage_mask(context) ^ cprisk_cff_ctx_nonce_plain(context) ^ cprisk_cff_hdr_const32(
            0x4346465F43545836ull,
            cprisk_cff_ctx_storage_mask(context),
            cprisk_cff_ctx_nonce_plain(context),
            cprisk_cff_hdr_base_derive(0x4346465F42415336ull, 0xC11A1E5Eu)
        )
    );
    context->chain_snapshot = chain ^ chain_mask;
}

// 以独立 domain 掩码写入入口守卫。
static void cprisk_cff_ctx_set_entry_guard_plain_i(cprisk_cff_context_t *context, uint32_t guard) {
    const uint32_t guard_mask = cprisk_cff_hdr_avalanche32(
        cprisk_cff_ctx_storage_mask(context) ^ cprisk_cff_ctx_nonce_plain(context) ^ cprisk_cff_hdr_const32(
            0x4346465F43545837ull,
            cprisk_cff_ctx_storage_mask(context),
            cprisk_cff_ctx_nonce_plain(context),
            cprisk_cff_hdr_base_derive(0x4346465F42415337ull, 0xE17A9A5Bu)
        )
    );
    context->entry_guard = guard ^ guard_mask;
}

// 不透明选择器：混合编码态、明文态、codec 风格与 TLS，得到 decoy/分派用的 token。
static uint32_t cprisk_cff_opaque_selector_i(const cprisk_cff_context_t *context, uint32_t decoded_state) {
    const uint32_t seed_p = cprisk_cff_ctx_seed_plain(context);
    const uint32_t salt_p = cprisk_cff_ctx_salt_plain(context);
    const uint32_t salt_golden = salt_p * cprisk_cff_derive_const32_odd(
        0x4346465F4F505132ull,
        seed_p,
        decoded_state,
        0x9E3779B1u
    );
    uint32_t token = cprisk_cff_avalanche32(
        cprisk_cff_ctx_encoded_plain(context) ^
        decoded_state ^
        salt_golden ^
        ((uint32_t)context->codec_style << 24u) ^
        cprisk_cff_derive_const32(
            0x4346465F4F505133ull,
            seed_p,
            decoded_state,
            (uint32_t)context->codec_style ^ (seed_p >> 16u)
        )
    );
    token ^= cprisk_cff_rotate_left32(token, ((seed_p >> 27u) & 31u) | 1u);
    token ^= cprisk_cff_tls_mix32;
    return token;
}

// 由 seed/salt/encoded/last 重算 VM 链 token；结果为 0 时替换为哨兵。
static void cprisk_cff_refresh_vm_link_token_i(const cprisk_cff_context_t *context) {
    const uint32_t mix_const = cprisk_cff_derive_const32(
        0x4346465F4354583Full,
        cprisk_cff_ctx_seed_plain(context),
        cprisk_cff_ctx_salt_plain(context),
        0xC0FFEE42u
    );
    uint32_t t = cprisk_cff_avalanche32(
        cprisk_cff_ctx_seed_plain(context) ^
        cprisk_cff_ctx_encoded_plain(context) ^
        cprisk_cff_ctx_salt_plain(context) ^
        cprisk_cff_ctx_last_plain(context) ^
        mix_const
    );
    if (t == 0u) {
        t = cprisk_cff_chain_fallback_sentinel_u32();
    }
    atomic_store(&s_cff_vm_link_token, (uint_fast32_t)t);
}

// 迁移后推进线程局部混合值；绑定 seed、下一状态与编码态。
static void cprisk_cff_tls_bump_i(const cprisk_cff_context_t *context, uint32_t next_state) {
    const uint32_t bump_const = cprisk_cff_derive_const32(
        0x4346465F43545840ull,
        cprisk_cff_ctx_seed_plain(context),
        next_state,
        cprisk_cff_tls_mix_derive_base_u32()
    );
    cprisk_cff_tls_mix32 = cprisk_cff_avalanche32(
        cprisk_cff_tls_mix32 ^ cprisk_cff_ctx_seed_plain(context) ^ next_state ^ cprisk_cff_ctx_encoded_plain(context) ^
        bump_const
    );
}

// 推进全局链：混合旧链、seed、编码态、盐、basis 与入口守卫，再写回原子量与快照。
static void cprisk_cff_chain_advance_i(cprisk_cff_context_t *context, uint32_t basis) {
    const uint32_t advance_const = cprisk_cff_derive_const32(
        0x4346465F43545841ull,
        cprisk_cff_ctx_seed_plain(context),
        basis ^ cprisk_cff_ctx_nonce_plain(context),
        cprisk_cff_tls_mix_derive_base_u32()
    );
    uint32_t next = cprisk_cff_avalanche32(
        cprisk_cff_ctx_chain_plain(context) ^
        cprisk_cff_ctx_seed_plain(context) ^
        cprisk_cff_ctx_encoded_plain(context) ^
        cprisk_cff_ctx_salt_plain(context) ^
        basis ^
        cprisk_cff_ctx_nonce_plain(context) ^
        cprisk_cff_ctx_entry_guard_plain(context) ^
        advance_const
    );
    if (next == 0u) {
        next = cprisk_cff_chain_fallback_sentinel_u32();
    }
    atomic_store(&s_cff_chain_link, (uint_fast32_t)next);
    cprisk_cff_ctx_set_chain_plain_i(context, next);
}

// finalize 时的链推进；以 last_plain 作为 basis，确保退出路径也参与链演化。
static void cprisk_cff_chain_finalize_i(cprisk_cff_context_t *context) {
    cprisk_cff_chain_advance_i(context, cprisk_cff_ctx_last_plain(context));
}

// 开始 CFF 链：读取全局链并混入本线程 TLS；不改写全局链。
void cprisk_cff_chain_begin(void) {
    const uint32_t g = cprisk_cff_chain_load_i();
    const uint32_t chain_const = cprisk_cff_derive_const32(
        0x4346465F43545842ull,
        g,
        cprisk_cff_tls_mix32,
        0xCFF5B0E5u
    );
    cprisk_cff_tls_mix32 = cprisk_cff_avalanche32(cprisk_cff_tls_mix32 ^ g ^ chain_const);
}

// 返回全局链与线程指纹的混合值；线程指纹仅用于去相关，不承担认证。
uint32_t cprisk_cff_get_chain_link(void) {
    /* Mix in the calling thread's fingerprint so two threads observing the
     * same (deterministic) global chain still see distinct chain values
     * propagating into TLS. Audit flagged the prior version as exposing
     * cross-thread correlation when both threads called this concurrently. */
    return cprisk_cff_chain_load_i() ^ (uint32_t)cprisk_cff_thread_fingerprint();
}

// 原子读取最近一次刷新得到的 VM 链 token。
// 接口边界：该值只用于 VM 会话混合；VM self-expect 的段解析与哈希比对在 cprisk_vm_interpreter.c，
// CFF 不参与该自检，也不把 token 当作自检通过与否的判据。
uint32_t cprisk_cff_get_vm_link_token(void) {
    return (uint32_t)atomic_load(&s_cff_vm_link_token);
}

// 校验 context 的链快照与入口守卫；NULL 返回 0（fail-closed）。
int cprisk_cff_chain_entry_verify(const cprisk_cff_context_t *context) {
    if (context == NULL) {
        return 0;
    }
    const uint32_t observed = cprisk_cff_chain_load_i();
    return cprisk_cff_chain_entry_verify_inline(context, observed);
}

// 固定 16 步 decoy：不递归、不进入状态机；仅扰动寄存器/时序。
/*
 * Flat 16-iteration decoy mixer — does NOT recurse into the CFF state
 * machinery, so there is no stack-blowup vector here despite the function
 * name suggesting "path" exploration. Audit pass flagged a hypothetical
 * recursion guard; the actual implementation only spins on a `volatile`
 * sink and a single `cprisk_cff_os_mix32()` syscall, which is itself
 * bounded by the OS readiness check inside `os_mix32`.
 */
// 执行有界 decoy 计算并做一次 OS 混合；context 为 NULL 时直接返回。
void cprisk_cff_run_fake_path_decoy(const cprisk_cff_context_t *context) {
    if (context == NULL) {
        return;
    }
    const uint32_t decoy_step_mul = cprisk_cff_derive_const32_odd(
        0x4346465F46414B31ull,
        cprisk_cff_ctx_seed_plain(context),
        cprisk_cff_ctx_salt_plain(context),
        0x9E3779B1u
    );
    uint32_t w = cprisk_cff_ctx_seed_plain(context) ^ cprisk_cff_ctx_encoded_plain(context) ^
        cprisk_cff_ctx_salt_plain(context) ^ cprisk_cff_ctx_last_plain(context);
    for (uint32_t i = 0u; i < 16u; i++) {
        w = cprisk_cff_avalanche32(w ^ i ^ (i * decoy_step_mul));
        volatile uint32_t sink = w;
        sink ^= cprisk_cff_rotate_left32(sink, (uint32_t)(i & 31u));
        sink ^= cprisk_cff_avalanche32(sink ^ cprisk_cff_ctx_seed_plain(context) ^ (uint32_t)i);
        (void)sink;
    }
    (void)cprisk_cff_os_mix32();
}

// 把 seed 与 entry_state 混合成内部主种子；entry 乘以奇数派生值以打破线性关系。
static uint32_t cprisk_cff_mix_seed(uint32_t seed, uint32_t entry_state) {
    const uint32_t mix_const = cprisk_cff_derive_const32(
        0x4346465F43545843ull,
        seed,
        entry_state,
        0xA24BAED5u
    );
    const uint32_t entry_golden = entry_state * cprisk_cff_derive_const32_odd(
        0x4346465F4D495834ull,
        seed,
        entry_state,
        0x9E3779B1u
    );
    return cprisk_cff_avalanche32(seed ^ entry_golden ^ mix_const);
}

// 生成默认种子：PID、线程指纹、单调时钟、函数地址与可选 OS 熵共同混合。
// 返回非 0；OS 熵不可用时降级为确定性混合，而不是清零。
static uint32_t cprisk_cff_default_seed(void) {
    struct timespec now;
    uint64_t monotonic_ns = 0u;
    const uint64_t pid = (uint64_t)getpid();
    const uint64_t tid_hash = cprisk_cff_thread_fingerprint();
    const uintptr_t fn_addr_mix = (uintptr_t)&cprisk_cff_default_seed ^ (uintptr_t)&cprisk_cff_encode_state;

    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
        monotonic_ns = ((uint64_t)now.tv_sec * 1000000000ULL) + (uint64_t)now.tv_nsec;
    }

    uint32_t seed = 0u;
    seed ^= (uint32_t)pid;
    seed ^= (uint32_t)(pid >> 32u);
    seed ^= (uint32_t)tid_hash;
    seed ^= (uint32_t)(tid_hash >> 32u);
    seed ^= (uint32_t)monotonic_ns;
    seed ^= (uint32_t)(monotonic_ns >> 29u);
    seed ^= (uint32_t)fn_addr_mix;
    seed ^= (uint32_t)(fn_addr_mix >> 32u);

    // OS 熵仅作为额外输入：getentropy 失败时保留既有混合结果，不阻断初始化。
    /*
     * Mix in 8 bytes of OS entropy when available. The previous derivation
     * was deterministic given fixed pid/tid/clock state (e.g. forensic
     * replay, low-jitter test harnesses), which let an attacker narrow the
     * seed search space. `getentropy` is a one-shot CSPRNG read; we fold it
     * into the existing avalanche so any failure simply degrades to the
     * legacy mix instead of zeroing entropy.
     */
#if defined(CPRISK_CFF_HAVE_GETENTROPY) || defined(CPRISK_CFF_HAVE_ARC4RANDOM)
    {
        uint8_t os_rand[8];
#ifdef CPRISK_CFF_HAVE_GETENTROPY
        if (getentropy(os_rand, sizeof(os_rand)) == 0) {
#else
        arc4random_buf(os_rand, sizeof(os_rand));
#endif
            const uint32_t lo = ((uint32_t)os_rand[0]) |
                                ((uint32_t)os_rand[1] << 8) |
                                ((uint32_t)os_rand[2] << 16) |
                                ((uint32_t)os_rand[3] << 24);
            const uint32_t hi = ((uint32_t)os_rand[4]) |
                                ((uint32_t)os_rand[5] << 8) |
                                ((uint32_t)os_rand[6] << 16) |
                                ((uint32_t)os_rand[7] << 24);
            seed ^= lo ^ cprisk_cff_rotate_left32(hi, 13u);
#ifdef CPRISK_CFF_HAVE_GETENTROPY
        }
#endif
        cprisk_secure_zero(os_rand, sizeof(os_rand));
    }
#endif

    seed = cprisk_cff_avalanche32(seed ^ cprisk_cff_tls_mix_derive_base_u32());
    return seed == 0u ? 1u : seed;
}

// 默认编码入口：固定使用 Feistel+SPN 风格。
uint32_t cprisk_cff_encode_state(uint32_t state, uint32_t key, uint32_t salt) {
    return cprisk_cff_encode_state_with_style(
        state,
        key,
        salt,
        CPRISK_CFF_CODEC_STYLE_FEISTEL_SPN
    );
}

// 默认解码入口：与 encode_state 严格配对。
uint32_t cprisk_cff_decode_state(uint32_t encoded_state, uint32_t key, uint32_t salt) {
    return cprisk_cff_decode_state_with_style(
        encoded_state,
        key,
        salt,
        CPRISK_CFF_CODEC_STYLE_FEISTEL_SPN
    );
}

// 编码实现：按 style 选择 Feistel / 加法旋转 XOR / GF(2^32) 仿射 / XOR+旋转。
static uint32_t cprisk_cff_encode_state_with_style_impl(
    uint32_t state,
    uint32_t key,
    uint32_t salt,
    cprisk_cff_codec_style_t style,
    uint8_t mba_layers
) {
    // AUTO 在编解码层等价于 FEISTEL_SPN；编码与解码必须镜像同一 fall-through。
    /*
     * AUTO is normally resolved to a concrete style by `cprisk_cff_resolve_style`
     * during `cprisk_cff_init`. If a caller passes AUTO directly to
     * `cprisk_cff_encode_state_with_style` the explicit `case AUTO` here keeps
     * the contract documented: AUTO ≡ FEISTEL_SPN at the codec layer. Decode
     * mirrors the same fall-through.
     */
    switch (style) {
        case CPRISK_CFF_CODEC_STYLE_FEISTEL_SPN:
        case CPRISK_CFF_CODEC_STYLE_AUTO:
            return cprisk_cff_feistel32_encode_core(state, key, salt);
        // 编码：先加 addend，再循环左移 shift（保证 1..31），最后与两路派生掩码异或。
        case CPRISK_CFF_CODEC_STYLE_ADD_ROTATE_XOR: {
            const uint32_t addend = cprisk_cff_avalanche32(key + salt + cprisk_cff_derive_const32(
                0x4346465F53544131ull,
                key,
                salt,
                0x7F4A7C15u
            ));
            const uint32_t shift = (((key >> 3u) ^ salt) & 31u) | 1u;
            const uint32_t mixed = cprisk_cff_rotate_left32(state + addend, shift);
            return mixed ^
                cprisk_cff_avalanche32(key ^ cprisk_cff_derive_const32(
                    0x4346465F53544132ull,
                    key,
                    salt,
                    0xA24BAED5u
                )) ^
                (salt * cprisk_cff_derive_const32_odd(
                    0x4346465F53544133ull,
                    key,
                    salt,
                    0x165667B1u
                ));
        }
        // 仿射编码：state 先 XOR mask，再乘奇数 multiplier 并加 addend，最后 XOR 旋转 key。
        // multiplier 为奇数，模 2^32 逆元存在，解码才能精确还原。
        case CPRISK_CFF_CODEC_STYLE_AFFINE: {
            const uint32_t mask = cprisk_cff_avalanche32(key + salt + cprisk_cff_derive_const32(
                0x4346465F53544631ull,
                key,
                salt,
                0x51ED270Bu
            ));
            const uint32_t multiplier = cprisk_cff_affine_multiplier(key, salt);
            const uint32_t addend = cprisk_cff_affine_addend(key, salt);
            const uint32_t masked = state ^ mask;
            return (masked * multiplier + addend) ^ cprisk_cff_rotate_left32(key, (salt & 31u) | 1u);
        }
        // XOR 编码：核心 XOR 可按种子选择 MBA 形式；mba_layers>=2 时再叠加 MBA 链。
        // shift 强制非 0，保证编码/解码旋转方向对称且不退化。
        case CPRISK_CFF_CODEC_STYLE_XOR_ROTATE:
        default: {
            const uint32_t mix = cprisk_cff_avalanche32(key ^ salt ^ cprisk_cff_derive_const32(
                0x4346465F53545831ull,
                key,
                salt,
                0x9E3779B9u
            ));
            const uint32_t shift = (mix & 31u) | 1u;
            const uint32_t saltprod = salt * cprisk_cff_derive_const32_odd(
                0x4346465F53545832ull,
                key,
                salt,
                0x045D9F3Bu
            );
            const uint32_t use_mba =
                (cprisk_cff_avalanche32(key ^ salt ^ cprisk_cff_derive_const32(
                    0x4346465F53545834ull,
                    key,
                    salt,
                    0xEFCAB9A5u
                )) & 1u) != 0u;
            uint32_t core =
                use_mba != 0u ? cprisk_cff_xor_mba_u32(state, mix) : (state ^ mix);
            if (mba_layers >= 2u) {
                core = cprisk_cff_mba_chain_xor_u32(core, key, salt, mba_layers);
            }
            const uint32_t masked = core ^ saltprod;
            return cprisk_cff_rotate_left32(masked, shift) + (key * cprisk_cff_derive_const32_odd(
                0x4346465F53545833ull,
                key,
                salt,
                0x27D4EB2Du
            ));
        }
    }
}

// 公开编码入口：mba_layers 固定传 1，即不叠加 MBA 链。
uint32_t cprisk_cff_encode_state_with_style(
    uint32_t state,
    uint32_t key,
    uint32_t salt,
    cprisk_cff_codec_style_t style
) {
    return cprisk_cff_encode_state_with_style_impl(state, key, salt, style, 1u);
}

// 提交一次合法迁移：再次校验链快照，然后写 last、encoded、chain、VM token 与 TLS。
// 顺序不可交换：encoded 依赖 last 的掩码状态，链推进依赖 encoded。
void cprisk_cff_state_transition_commit(cprisk_cff_context_t *context, uint32_t next_state) {
    if (context == NULL) {
        return;
    }
    {
        const uint32_t observed = cprisk_cff_chain_load_i();
        if (cprisk_cff_chain_snapshot_verify_inline(context, observed) == 0) {
            cprisk_cff_poison_default(context);
            return;
        }
    }
    // 先写 last_plain 份额：后续编码与链推进都读取它。
    cprisk_cff_ctx_set_last_plain_i(context, next_state);
    {
        // 用当前风格重新编码 next_state，再 XOR 字段掩码写入 encoded_state。
        const uint32_t enc_plain = cprisk_cff_encode_state_with_style_impl(
            next_state,
            cprisk_cff_ctx_seed_plain(context),
            cprisk_cff_ctx_salt_plain(context),
            (cprisk_cff_codec_style_t)context->codec_style,
            context->mba_layers
        );
        context->encoded_state = enc_plain ^ cprisk_cff_ctx_mask_enc(context);
    }
    // 链推进必须在 encoded 写入之后，保证链值覆盖新状态。
    cprisk_cff_chain_advance_i(context, next_state);
    cprisk_cff_refresh_vm_link_token_i(context);
    cprisk_cff_tls_bump_i(context, next_state);
}

// 解码实现：与 encode_impl 逐风格对称，仿射用奇数乘子的模逆还原。
static uint32_t cprisk_cff_decode_state_with_style_impl(
    uint32_t encoded_state,
    uint32_t key,
    uint32_t salt,
    cprisk_cff_codec_style_t style,
    uint8_t mba_layers
) {
    switch (style) {
        case CPRISK_CFF_CODEC_STYLE_FEISTEL_SPN:
        case CPRISK_CFF_CODEC_STYLE_AUTO:
            return cprisk_cff_feistel32_decode_core(encoded_state, key, salt);
        // 逆序：先 XOR 掩码，再循环右移，最后减 addend。
        case CPRISK_CFF_CODEC_STYLE_ADD_ROTATE_XOR: {
            const uint32_t addend = cprisk_cff_avalanche32(key + salt + cprisk_cff_derive_const32(
                0x4346465F53544131ull,
                key,
                salt,
                0x7F4A7C15u
            ));
            const uint32_t shift = (((key >> 3u) ^ salt) & 31u) | 1u;
            const uint32_t unmasked =
                encoded_state ^
                cprisk_cff_avalanche32(key ^ cprisk_cff_derive_const32(
                    0x4346465F53544132ull,
                    key,
                    salt,
                    0xA24BAED5u
                )) ^
                (salt * cprisk_cff_derive_const32_odd(
                    0x4346465F53544133ull,
                    key,
                    salt,
                    0x165667B1u
                ));
            return cprisk_cff_rotate_right32(unmasked, shift) - addend;
        }
        // 仿射解码：XOR 旋转 key → 减 addend → 乘奇数乘子的模 2^32 逆元 → XOR mask。
        case CPRISK_CFF_CODEC_STYLE_AFFINE: {
            const uint32_t mask = cprisk_cff_avalanche32(key + salt + cprisk_cff_derive_const32(
                0x4346465F53544631ull,
                key,
                salt,
                0x51ED270Bu
            ));
            const uint32_t multiplier = cprisk_cff_affine_multiplier(key, salt);
            const uint32_t inverse = cprisk_cff_mod_inverse_odd32(multiplier);
            const uint32_t addend = cprisk_cff_affine_addend(key, salt);
            const uint32_t unxored = encoded_state ^ cprisk_cff_rotate_left32(key, (salt & 31u) | 1u);
            const uint32_t unscaled = (unxored - addend) * inverse;
            return unscaled ^ mask;
        }
        // XOR 解码：先减乘性项并右移，再解 saltprod 与可选 MBA 链，最后 XOR mix。
        case CPRISK_CFF_CODEC_STYLE_XOR_ROTATE:
        default: {
            const uint32_t mix = cprisk_cff_avalanche32(key ^ salt ^ cprisk_cff_derive_const32(
                0x4346465F53545831ull,
                key,
                salt,
                0x9E3779B9u
            ));
            const uint32_t shift = (mix & 31u) | 1u;
            const uint32_t saltprod = salt * cprisk_cff_derive_const32_odd(
                0x4346465F53545832ull,
                key,
                salt,
                0x045D9F3Bu
            );
            const uint32_t use_mba =
                (cprisk_cff_avalanche32(key ^ salt ^ cprisk_cff_derive_const32(
                    0x4346465F53545834ull,
                    key,
                    salt,
                    0xEFCAB9A5u
                )) & 1u) != 0u;
            const uint32_t unshifted =
                cprisk_cff_rotate_right32(encoded_state - (key * cprisk_cff_derive_const32_odd(
                    0x4346465F53545833ull,
                    key,
                    salt,
                    0x27D4EB2Du
                )), shift);
            uint32_t core = unshifted ^ saltprod;
            if (mba_layers >= 2u) {
                core = cprisk_cff_mba_chain_xor_u32(core, key, salt, mba_layers);
            }
            return use_mba != 0u ? cprisk_cff_xor_mba_u32(core, mix) : (core ^ mix);
        }
    }
}

// 公开解码入口：mba_layers 固定传 1，与 encode_with_style 配对。
uint32_t cprisk_cff_decode_state_with_style(
    uint32_t encoded_state,
    uint32_t key,
    uint32_t salt,
    cprisk_cff_codec_style_t style
) {
    return cprisk_cff_decode_state_with_style_impl(encoded_state, key, salt, style, 1u);
}

// 生成运行时盐：绑定 seed/hint、PID、单调时钟、线程指纹、OS/dyld 与域分离常量。
// 时钟不可用时 monotonic_ns 保持 0，其余分量仍提供熵。
uint32_t cprisk_cff_runtime_salt(uint32_t seed, uint32_t runtime_hint) {
    struct timespec now;
    uint64_t monotonic_ns = 0u;
    const uint64_t pid = (uint64_t)getpid();
    const uint64_t tid_hash = cprisk_cff_thread_fingerprint();

    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
        monotonic_ns = ((uint64_t)now.tv_sec * 1000000000ULL) + (uint64_t)now.tv_nsec;
    }

    const uint32_t salt_const = cprisk_cff_derive_const32(
        0x4346465F43545844ull,
        seed,
        runtime_hint ^ (uint32_t)(tid_hash >> 17u),
        cprisk_cff_rt_salt_mix_base_u32(seed, runtime_hint)
    );
    return cprisk_cff_avalanche32(
        seed ^
        runtime_hint ^
        (uint32_t)pid ^
        (uint32_t)(monotonic_ns >> 11u) ^
        (uint32_t)(tid_hash >> 17u) ^
        cprisk_cff_os_mix32() ^
        cprisk_cff_dyld_mix32() ^
        salt_const
    );
}

// 初始化 context：解析配置 → 派生 seed/salt/nonce → 解析风格/层数/dispatcher
// → 写入掩码后的字段 → 编码入口状态 → 刷新 VM token 与 TLS。
// 线程安全：context 必须独占；全局链/S-box 按各自并发规则处理。
void cprisk_cff_init(cprisk_cff_context_t *context, const cprisk_cff_config_t *config) {
    cprisk_cff_config_t local_config;

    if (context == NULL) {
        return;
    }

    if (config == NULL) {
        memset(&local_config, 0, sizeof(local_config));
        local_config.seed = cprisk_cff_default_seed();
        local_config.entry_state = 0u;
        local_config.iteration_budget = CPRISK_CFF_ITERATION_BUDGET;
        local_config.release_build = (uint8_t)CPRISK_CFF_RELEASE_BUILD;
        local_config.enable_fake_states = (uint8_t)CPRISK_CFF_ENABLE_FAKE_STATE;
        local_config.codec_style = (uint8_t)CPRISK_CFF_CODEC_STYLE_AUTO;
        local_config.default_action = CPRISK_CFF_RELEASE_BUILD ? CPRISK_CFF_DEFAULT_POISON : CPRISK_CFF_DEFAULT_FAIL_CLOSED;
        config = &local_config;
    }

    // 先清零整个 context：确保 reserved 字段与未使用份额不会携带栈上旧数据。
    memset(context, 0, sizeof(*context));
    /*
     * Init ordering invariant (do not reorder without re-deriving):
     *
     *   1. `storage_nonce` is set BEFORE any setter that resolves
     *      `cprisk_cff_ctx_nonce_plain()` (i.e. `set_chain_plain_i`,
     *      `set_last_plain_i`, `set_entry_guard_plain_i`, and the
     *      `seed`/`runtime_salt`/`encoded_state` masking writes below).
     *   2. `storage_mask` derives only from `(uintptr_t)context` and
     *      `sizeof(*context)`, so it is well-defined the moment the struct
     *      memory exists — no dependency on any field value.
     *   3. The `mask_*` helpers all chain through `storage_mask` and
     *      `nonce_plain`; once both above are valid, every subsequent
     *      setter is order-independent.
     *
     * Audit pass flagged a suspected cycle here; the analysis above shows
     * the actual order is acyclic. Comment retained so future readers do
     * not "fix" the perceived issue by reordering and breaking masking.
     */
    // 初始化顺序不变量：storage_nonce 先于所有依赖 nonce_plain 的 setter；
    // storage_mask 只依赖 context 地址与 sizeof，因此随时可用。
    {
        const uint32_t chain_plain = cprisk_cff_chain_load_i();
        const uint32_t seed_plain = cprisk_cff_mix_seed(
            config->seed ^ cprisk_cff_rotate_left32(chain_plain, 5u),
            config->entry_state ^ chain_plain
        );
        const uint32_t salt_plain = config->runtime_salt != 0u
            ? (config->runtime_salt ^ cprisk_cff_rotate_left32(chain_plain, 7u))
            : cprisk_cff_runtime_salt(
                config->seed ^ chain_plain,
                config->entry_state ^ cprisk_cff_derive_const32(
                    0x4346465F43545845ull,
                    config->seed,
                    chain_plain,
                    0x13579BDFu
                ) ^ cprisk_cff_rotate_left32(chain_plain, 3u)
            );
        const uint32_t raw_nonce = cprisk_cff_avalanche32(
            seed_plain ^
            salt_plain ^
            config->entry_state ^
            chain_plain ^
            cprisk_cff_tls_mix32 ^
            (uint32_t)cprisk_cff_thread_fingerprint() ^
            cprisk_cff_build_seed32_i() ^
            cprisk_cff_derive_const32(
                0x4346465F4E4F4E43ull,
                seed_plain,
                salt_plain ^ chain_plain,
                cprisk_cff_tls_mix32 ^ (uint32_t)cprisk_cff_thread_fingerprint()
            )
        );

        // 预算为 0 时使用默认上限，避免调用方误传导致状态机永不执行。
        context->iteration_budget = config->iteration_budget != 0u
            ? config->iteration_budget
            : CPRISK_CFF_ITERATION_BUDGET;
        // 假状态预算仅在“显式启用 + 发布构建”时非 0；否则彻底关闭 decoy。
        context->release_build = config->release_build;
        context->enable_fake_states = config->enable_fake_states;
        context->fake_state_budget = (uint8_t)((config->enable_fake_states != 0u && config->release_build != 0u) ? 7u : 0u);
        // AUTO 在此解析为具体风格；运行期 context 不再出现 AUTO。
        context->codec_style = (uint8_t)cprisk_cff_resolve_style(
            seed_plain,
            config->entry_state,
            config->codec_style
        );
        // 层数归一化到 1..8；0/越界按种子确定性选择。
        context->mba_layers = cprisk_cff_normalize_mba_layers(seed_plain, config->mba_layers);
        // dispatcher 解析：AUTO 二选一，COMPUTED_GOTO 降级为函数表。
        context->dispatch_style = cprisk_cff_resolve_dispatch_style_u8(seed_plain, config->dispatch_style);
        context->symex_guard_budget = config->symex_guard_budget;
        context->default_action = config->default_action;
        // 先写 storage_nonce：后续所有通道掩码都依赖它还原 nonce_plain。
        context->storage_nonce = raw_nonce ^ cprisk_cff_ctx_storage_mask(context);
        cprisk_cff_ctx_set_chain_plain_i(context, chain_plain);

        // 敏感字段一律“明文 XOR 字段掩码”后存储，内存转储不直接暴露明文。
        context->seed = seed_plain ^ cprisk_cff_ctx_mask_ptr(context);
        context->runtime_salt = salt_plain ^ cprisk_cff_ctx_mask_salt(context);
        cprisk_cff_ctx_set_last_plain_i(context, config->entry_state);
        cprisk_cff_ctx_set_entry_guard_plain_i(
            context,
            cprisk_cff_chain_entry_guard_expected_inline(context, chain_plain)
        );

        // 入口状态也以当前风格编码后存储，保证第一次解码得到 entry_state。
        {
            const uint32_t enc_plain = cprisk_cff_encode_state_with_style_impl(
                config->entry_state,
                seed_plain,
                salt_plain,
                (cprisk_cff_codec_style_t)context->codec_style,
                context->mba_layers
            );
            context->encoded_state = enc_plain ^ cprisk_cff_ctx_mask_enc(context);
        }
    }
    cprisk_cff_refresh_vm_link_token_i(context);
    cprisk_cff_tls_bump_i(context, config->entry_state);
}

// 默认初始化包装：构造最小配置（AUTO 风格、默认预算）后调用 cprisk_cff_init。
void cprisk_cff_init_default(cprisk_cff_context_t *context, uint32_t seed, uint32_t entry_state) {
    cprisk_cff_config_t config;

    memset(&config, 0, sizeof(config));
    config.seed = seed;
    config.entry_state = entry_state;
    config.iteration_budget = CPRISK_CFF_ITERATION_BUDGET;
    config.release_build = (uint8_t)CPRISK_CFF_RELEASE_BUILD;
    config.enable_fake_states = (uint8_t)CPRISK_CFF_ENABLE_FAKE_STATE;
    config.codec_style = (uint8_t)CPRISK_CFF_CODEC_STYLE_AUTO;
    config.default_action = CPRISK_CFF_RELEASE_BUILD ? CPRISK_CFF_DEFAULT_POISON : CPRISK_CFF_DEFAULT_FAIL_CLOSED;
    cprisk_cff_init(context, &config);
}

// 解码当前 encoded_state 并把结果写入 last_plain 份额；NULL 返回 0。
uint32_t cprisk_cff_current_state(cprisk_cff_context_t *context) {
    if (context == NULL) {
        return 0u;
    }

    const uint32_t decoded = cprisk_cff_decode_state_with_style_impl(
        cprisk_cff_ctx_encoded_plain(context),
        cprisk_cff_ctx_seed_plain(context),
        cprisk_cff_ctx_salt_plain(context),
        (cprisk_cff_codec_style_t)context->codec_style,
        context->mba_layers
    );
    cprisk_cff_ctx_set_last_plain_i(context, decoded);
    return decoded;
}

// 函数表备选解码入口：直接按 context 中已解析的 codec_style 解码。
uint32_t cprisk_cff_current_state_table(cprisk_cff_context_t *context) {
    if (context == NULL) {
        return 0u;
    }

    /*
     * Alternate decode path: single resolved codec_style (AUTO is always
     * normalized at init). Avoids masking style to 2 bits, which mis-routed
     * newer styles (e.g. Feistel) to XOR.
     */
    const uint32_t decoded = cprisk_cff_decode_state_with_style_impl(
        cprisk_cff_ctx_encoded_plain(context),
        cprisk_cff_ctx_seed_plain(context),
        cprisk_cff_ctx_salt_plain(context),
        (cprisk_cff_codec_style_t)context->codec_style,
        context->mba_layers
    );
    cprisk_cff_ctx_set_last_plain_i(context, decoded);
    return decoded;
}

// DIRECT dispatcher 目标：内联式解码并更新 last_plain。
static uint32_t cprisk_cff_dispatch_decode_direct_ctx(cprisk_cff_context_t *context) {
    const uint32_t decoded = cprisk_cff_decode_state_with_style_impl(
        cprisk_cff_ctx_encoded_plain(context),
        cprisk_cff_ctx_seed_plain(context),
        cprisk_cff_ctx_salt_plain(context),
        (cprisk_cff_codec_style_t)context->codec_style,
        context->mba_layers
    );
    cprisk_cff_ctx_set_last_plain_i(context, decoded);
    return decoded;
}

// TABLE dispatcher 目标：委托 current_state_table，保持同一解码语义。
static uint32_t cprisk_cff_dispatch_decode_table_ctx(cprisk_cff_context_t *context) {
    return cprisk_cff_current_state_table(context);
}

// 热路径：按 mba_layers 与 dispatch_style 选择等价解码实现，避免统一的单点调用；
// 仍产生一次完整解码，指数级开销来自后续状态机而非本函数。
uint32_t cprisk_cff_current_state_fast(cprisk_cff_context_t *context) {
    if (context == NULL) {
        return 0u;
    }
    if (context->mba_layers <= 1u) {
        if (context->dispatch_style == (uint8_t)CPRISK_CFF_DISPATCH_DIRECT) {
            return cprisk_cff_dispatch_decode_direct_ctx(context);
        }
        if (context->dispatch_style == (uint8_t)CPRISK_CFF_DISPATCH_FN_TABLE) {
            return cprisk_cff_current_state_table(context);
        }
    }
    return cprisk_cff_current_state_dispatch(context);
}

// dual dispatch：由 seed/salt/style/mba_layers 派生 1 bit，在两个等价解码函数间选择。
uint32_t cprisk_cff_current_state_dispatch(cprisk_cff_context_t *context) {
    if (context == NULL) {
        return 0u;
    }
    // 两个解码入口的函数指针类型；表内容在编译期固定，索引在运行期派生。
    typedef uint32_t (*cprisk_cff_dual_dispatch_fn)(cprisk_cff_context_t *);
    static const cprisk_cff_dual_dispatch_fn k_dual[2] = {
        cprisk_cff_dispatch_decode_direct_ctx,
        cprisk_cff_dispatch_decode_table_ctx,
    };
    const uint32_t mix = cprisk_cff_avalanche32(
        cprisk_cff_ctx_seed_plain(context) ^
        cprisk_cff_ctx_salt_plain(context) ^
        cprisk_cff_derive_const32(
            0x4346465F43545846ull,
            cprisk_cff_ctx_seed_plain(context),
            cprisk_cff_ctx_salt_plain(context),
            0x8F82C945u
        )
    );
    const uint32_t pick = (mix ^ (uint32_t)context->codec_style ^ (uint32_t)context->mba_layers) & 1u;
    return k_dual[pick](context);
}

// 设置符号执行预算；budget 为 0 时保持原值不变。
void cprisk_cff_arm_symbolic_explosion(cprisk_cff_context_t *context, uint8_t budget) {
    if (context == NULL) {
        return;
    }
    if (budget != 0u) {
        context->symex_guard_budget = budget;
    }
}

// 有界 decoy：limit = budget(或 8) × (1 + risk_mask 低 8 位)，硬上限 160。
// 上限防止攻击者用大 risk_mask 放大计算量造成 DoS。
void cprisk_cff_trigger_symbolic_explosion(cprisk_cff_context_t *context, uint32_t risk_mask) {
    if (context == NULL) {
        return;
    }
    // 预算基数 0 时取 8：即使未显式 arm，也保留最小扰动。
    uint32_t limit = (uint32_t)context->symex_guard_budget;
    if (limit == 0u) {
        limit = 8u;
    }
    limit *= 1u + (risk_mask & 0xFFu);
    // 硬上限 160：保证该函数最坏情况下仍有界。
    if (limit > 160u) {
        limit = 160u;
    }
    struct timespec ts;
    uint32_t acc = risk_mask ^ cprisk_cff_ctx_encoded_plain(context) ^ cprisk_cff_ctx_seed_plain(context);
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        acc ^= (uint32_t)ts.tv_nsec;
        acc = cprisk_cff_rotate_left32(acc, (uint32_t)(ts.tv_sec & 31u));
    }
    acc ^= (uint32_t)getpid() ^ cprisk_cff_thread_fingerprint();
    const uint32_t step_mul = cprisk_cff_derive_const32_odd(
        0x4346465F43545847ull,
        cprisk_cff_ctx_seed_plain(context),
        risk_mask ^ cprisk_cff_ctx_salt_plain(context),
        0x9E3779B1u
    );
    // 仅当低 4 位与 risk_mask 匹配时才写 volatile sink；分支与数据相关但无副作用。
    for (uint32_t i = 0u; i < limit; i++) {
        acc = cprisk_cff_avalanche32(acc ^ i ^ (uint32_t)(i * step_mul));
        if ((acc & 15u) == (risk_mask & 15u)) {
            volatile uint32_t sink = acc;
            sink ^= cprisk_cff_rotate_left32(sink, (uint32_t)(i & 31u));
            (void)sink;
        }
    }
    (void)cprisk_cff_os_mix32();
}

// 应用一次迁移：不透明谓词失败即 poison；成功则委托 commit 完成编码/链更新。
void cprisk_cff_set_state(cprisk_cff_context_t *context, uint32_t next_state) {
    if (context == NULL) {
        return;
    }

    if (cprisk_cff_opaque_transition_ok_inline(
            cprisk_cff_ctx_last_plain(context),
            next_state,
            cprisk_cff_ctx_seed_plain(context),
            cprisk_cff_ctx_salt_plain(context)) == 0) {
        cprisk_cff_poison_default(context);
        return;
    }

    cprisk_cff_state_transition_commit(context, next_state);
}

// 外部写入编码态：先掩码存储，再按当前 key/salt 解码并更新 last_plain、VM token、TLS。
// 不校验 encoded_state 合法性；非法密文由后续迁移谓词或链校验拦截。
void cprisk_cff_set_encoded_state(cprisk_cff_context_t *context, uint32_t encoded_state) {
    if (context == NULL) {
        return;
    }

    context->encoded_state = encoded_state ^ cprisk_cff_ctx_mask_enc(context);
    {
        const uint32_t decoded = cprisk_cff_decode_state_with_style_impl(
        encoded_state,
        cprisk_cff_ctx_seed_plain(context),
        cprisk_cff_ctx_salt_plain(context),
        (cprisk_cff_codec_style_t)context->codec_style,
        context->mba_layers
        );
        cprisk_cff_ctx_set_last_plain_i(context, decoded);
    }
    cprisk_cff_refresh_vm_link_token_i(context);
    cprisk_cff_tls_bump_i(context, cprisk_cff_ctx_last_plain(context));
}

/*
 * Note on `fake_state_budget`: the field is only initialized in
 * `cprisk_cff_init` (currently at the `7u` literal for release builds)
 * and read here. It is intentionally NOT decremented per visit — fake
 * state selection is gated by `cprisk_cff_opaque_selector_i` and the
 * `% modulo` reduction below, which produce a stable per-context decision
 * keyed on `decoded_state`. If a future change introduces decrement, use
 * a saturating decrement (clamp at zero) — uint8 wrap to 0xFF would
 * re-arm fake-state visits the policy says should be exhausted.
 */
// 假状态判定：仅当启用、发布构建、预算非 0 且选择器取模命中时返回 1。
// 判定只依赖 context 与 decoded_state，同一状态结果稳定，便于复现。
int cprisk_cff_should_visit_fake_state(const cprisk_cff_context_t *context, uint32_t decoded_state) {
    uint32_t mixed = 0u;
    uint32_t modulo = 0u;

    // 任一前置条件不满足立即返回 0：禁用状态绝不误入 decoy。
    if (context == NULL || context->enable_fake_states == 0u || context->release_build == 0u || context->fake_state_budget == 0u) {
        return 0;
    }

    mixed = cprisk_cff_opaque_selector_i(context, decoded_state);
    {
        uint32_t h = cprisk_cff_fnv32a_basis_i();
        h ^= mixed;
        h *= cprisk_cff_fnv32a_prime_i();
        h ^= decoded_state ^ cprisk_cff_ctx_seed_plain(context);
        h *= cprisk_cff_fnv_alt_prime_i();
        mixed ^= cprisk_cff_rotate_left32(h, (uint32_t)(context->codec_style + 3u));
    }
    // modulo ∈ {5,6,7}；用 codec_style 派生，使不同风格的 decoy 频率不同。
    modulo = 5u + ((uint32_t)context->codec_style % 3u);
    if (modulo == 0u)
        modulo = 5u;

    return (mixed % modulo) == 0u;
}

// 默认失败处置：TRAP 直接终止；POISON/FAIL_CLOSED 把状态钉死为非法哨兵并清零预算。
// 0xFFFF0001 表示完整性通道已被污染，0xFFFF0000 表示纯 fail-closed。
void cprisk_cff_poison_default(cprisk_cff_context_t *context) {
    if (context == NULL) {
        return;
    }

    // 处置动作来自 config，运行期只读；Trap 不返回，其余动作不抛异常。
    switch (context->default_action) {
        case CPRISK_CFF_DEFAULT_TRAP:
            __builtin_trap();
            break;
        case CPRISK_CFF_DEFAULT_POISON:
            cprisk_integrity_poison_cff_lane();
            // poison：除 fail-closed 外还调用完整性污染接口，供其他检测器读取。
            context->iteration_budget = 0u;
            cprisk_cff_ctx_set_last_plain_i(context, 0xFFFF0001u);
            {
                const uint32_t enc_plain = cprisk_cff_encode_state_with_style_impl(
                    0xFFFF0001u,
                    cprisk_cff_ctx_seed_plain(context),
                    cprisk_cff_ctx_salt_plain(context),
                    (cprisk_cff_codec_style_t)context->codec_style,
                    context->mba_layers
                );
                context->encoded_state = enc_plain ^ cprisk_cff_ctx_mask_enc(context);
            }
            cprisk_cff_refresh_vm_link_token_i(context);
            break;
        // fail-closed：预算清零 + 非法状态，状态机在下一次循环条件处退出。
        case CPRISK_CFF_DEFAULT_FAIL_CLOSED:
        default:
            context->iteration_budget = 0u;
            cprisk_cff_ctx_set_last_plain_i(context, 0xFFFF0000u);
            {
                const uint32_t enc_plain = cprisk_cff_encode_state_with_style_impl(
                    0xFFFF0000u,
                    cprisk_cff_ctx_seed_plain(context),
                    cprisk_cff_ctx_salt_plain(context),
                    (cprisk_cff_codec_style_t)context->codec_style,
                    context->mba_layers
                );
                context->encoded_state = enc_plain ^ cprisk_cff_ctx_mask_enc(context);
            }
            cprisk_cff_refresh_vm_link_token_i(context);
            break;
    }
}

// finalize 先推进链再整体清零；context 无自有指针，memset 即可清除全部敏感材料。
/*
 * Finalize: clears all sensitive material (seed, salt, encoded state, share
 * splits, nonce, masks). The context struct contains no owning pointers — it
 * is plain old data — so a single `memset` is sufficient. Allocation lifetime
 * (stack / heap / arena) is the caller's responsibility; the macros
 * `CPR_CFF_BEGIN` / `CPR_CFF_BEGIN_EX` use a stack-local context whose storage
 * is naturally reclaimed when the enclosing block ends.
 */
// 公开 finalize：推进链并清零 context；NULL 直接返回。
void cprisk_cff_finalize(cprisk_cff_context_t *context) {
    if (context == NULL) {
        return;
    }

    cprisk_cff_chain_finalize_i(context);
    memset(context, 0, sizeof(*context));
}

// Dispatch epoch 轮换：用每线程计数器打散 runtime_salt，令每次迭代走不同分派分支，
// 使按地址缓存的 Capstone 反汇编结果（L1/L2）持续失效。
/* ── Dispatch Epoch Rotation ────────────────────────────────────────────────
 *
 * Counter-measure against Capstone L1/L2 disassembly-result caching used by
 * optimised unidbg trace engines.
 *
 * The epoch is a per-thread uint32 counter.  On every CFF loop iteration the
 * macro CPRISK_CFF_LOOP_STATE_PEEK calls:
 *   1. cprisk_cff_rotate_dispatch_epoch()   — advance the counter
 *   2. context->runtime_salt ^= cprisk_cff_epoch_mix_salt(ctx)  — blend in
 *   3. cprisk_cff_current_state_fast()      — decode with rotated salt
 *
 * Effect: `cprisk_cff_current_state_fast` computes a different dispatch key
 * each iteration, selecting a different code path through the state machine
 * (switchLoop / ifElseChain / dualRail / splitIndirect).  Because a different
 * ARM64 branch target is executed each iteration the Capstone L1 slot for the
 * dispatcher basic-block is *always* a miss — the slot maps to a different
 * address on every pass.  The L2 LRU fills with diverse entries that are each
 * used only once, driving effective cache utilisation toward zero.
 * ──────────────────────────────────────────────────────────────────────────── */

// 每线程 epoch 计数器；Weyl 序列步进。必须为 _Thread_local，避免线程间碰撞。
/*
 * `_Thread_local` is C11 standard and supported by clang/gcc on every target
 * we ship to (Apple platforms, Linux test hosts, CI). The previous non-Apple
 * fallback to a plain `static` variable silently broke the per-thread epoch
 * invariant under concurrent dispatcher loops on Linux test runs — two
 * threads would collide on the same counter and the Capstone cache-busting
 * property degenerated to round-robin. Use thread-local unconditionally.
 */
static _Thread_local uint32_t s_dispatch_epoch_tl = 0u;

// 推进 epoch：加上奇数常量 0x9E3779B9，遍历全部 2^32 个余数后才重复。
void cprisk_cff_rotate_dispatch_epoch(void) {
    /* Weyl sequence step: additive with an odd constant so the counter visits
     * all 2^32 residues before repeating.  Fast and branch-free. */
    s_dispatch_epoch_tl += 0x9E3779B9u;
}

// 由 epoch 与 context 明文 seed 做一步 SplitMix64，折叠为 32-bit 盐扰动。
// context 为 NULL 时返回 0，调用方宏会退化为无扰动。
uint32_t cprisk_cff_epoch_mix_salt(const cprisk_cff_context_t *context) {
    if (!context) {
        return 0u;
    }
    /* One-step SplitMix64 collapsed to 32 bits.
     * Couples the epoch to the per-function seed so two functions at the same
     * iteration step produce orthogonal salt perturbations. */
    const uint32_t seed_plain = cprisk_cff_ctx_seed_plain(context);
    uint64_t z = ((uint64_t)s_dispatch_epoch_tl ^ (uint64_t)seed_plain) + 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30u)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27u)) * 0x94D049BB133111EBULL;
    z = z ^ (z >> 31u);
    return (uint32_t)(z ^ (z >> 32u));
}
