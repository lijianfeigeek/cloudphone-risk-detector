// 本文件：GF(2) 上 128-bit 仿射变换（128×128 矩阵 + 16 字节平移）。
// 位置：完整性 hash 后处理 / CFF 混淆链路的可选变换层。
// 线程模型：pthread_once 惰性初始化；初始化后矩阵只读，可并发调用。
// 平台：纯 C11，依赖 popcount parity，无架构专用指令要求。
// 失败语义：参数非法时直接返回；self_check 非零表示矩阵被篡改（fail-closed 由调用方裁决）。
// MARK: - GF(2) 128-bit Affine Transform
//
// 借鉴自小红书 x-mini-sig 的 transform_16 设计：在 GF(2)（二元域）上对 128-bit 输入做
// 128×128 矩阵乘法 + 平移向量 = 仿射变换。
//
// 数学上：output[i] = (Σⱼ matrix[i][j] · input[j]) ⊕ translation[i]   （所有运算在 GF(2)）
//
// 等价于 16×8 = 128 个独立的 popcount-parity 计算。
//
// 防御价值：
//  1. 算法本身在汇编层面只产生 AND / XOR / popcount，没有可识别的密码学常量
//     （没有 S-box、没有循环结构、没有魔数），混在花指令里几乎无法被静态识别。
//  2. 若用作完整性 hash 的后处理层（hash → transform_16），攻击者即使用常量替换了
//     SHA-256 的实现也得不到正确的 transform 输出 — 必须同时还原 128×128 矩阵。
//  3. 矩阵运行时由固定种子 + xorshift64 生成，编译产物的 .rodata 里没有矩阵字节，
//     攻击者必须在内存里 dump 出 BSS 段才能拿到矩阵。

#include "include/CRiskCore.h"

#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// 矩阵字节数 = 128 行 × 16 字节/行；每行是一个 128-bit 输出 bit 的线性系数。
#define CPRISK_GF2_MATRIX_BYTES         2048u   // 128 行 × 16 字节
// 平移向量字节数；对应仿射变换的常数项 b（输出 = M·x ⊕ b）。
#define CPRISK_GF2_TRANSLATION_BYTES    16u

// 矩阵和平移向量在 BSS — 由 init_once 用 xorshift64 从下面的种子生成。
// 128×128 GF(2) 矩阵，行主序；BSS 中运行时生成，.rodata 不含矩阵字节。
static uint8_t kCpriskGf2Matrix[CPRISK_GF2_MATRIX_BYTES];
// 16 字节平移向量；与矩阵同种子生成，参与自校验。
static uint8_t kCpriskGf2Translation[CPRISK_GF2_TRANSLATION_BYTES];
// 初始化后立即记录的 FNV-1a 校验值；self_check 时重新计算并比对。
// 初始化后记录的 FNV-1a 校验值；self_check 时重算并比对。
static uint64_t kCpriskGf2InitChecksum = 0u;

// 初始化门闩：保证矩阵只生成一次；之后矩阵视为只读。
static pthread_once_t kCpriskGf2InitOnce = PTHREAD_ONCE_INIT;

// 默认种子是公开常量：生成的矩阵可被完整复现，仅用于混淆而非保密。
// 有根密钥时应使用 cprisk_gf2_init_with_root_key 派生种子。
// 公开种子常量。该值唯一影响矩阵内容，不影响算法正确性。
// 警告：该种子是公开常量（任何人读二进制都能拿到），因此由它生成的
// 矩阵只提供混淆（obfuscation），不提供任何密钥性：攻击者拿到矩阵后
// 即可完整复现该仿射变换。需要密钥绑定的调用方必须改用
// cprisk_gf2_init_with_root_key()，由根密钥派生种子。
// 由根密钥派生的种子在首次初始化前通过 pending 槽位传入（见
// cprisk_gf2_init_with_root_key）；先运行的初始化获胜。
// 默认矩阵种子；仅在 pending 槽位为空时使用。
static const uint64_t kCpriskGf2InitSeed = 0xCAFEBABEDEADBEEFULL;
// 保护种子冻结与 pending 槽位；初始化路径很短，仅覆盖状态切换。
static pthread_mutex_t s_gf2_seed_mutex = PTHREAD_MUTEX_INITIALIZER;
// 一旦 init_real 读取种子即置 1；之后 init_with_root_key 不得再改变种子。
static int s_gf2_seed_frozen = 0;
// 首次初始化前由根密钥派生的候选种子；与 pending_set 配合。
static uint64_t s_gf2_pending_seed = 0u;
// pending 槽位有效标志；只有置位时 init_real 才采用 pending_seed。
static int s_gf2_pending_seed_set = 0;

// 64-bit xorshift 状态转移；仅用于生成矩阵/平移字节，不是密码学 PRNG。
// 不变量：状态不应为 0（全零是固定点），调用方以非零种子起步。
static uint64_t cprisk_gf2_xorshift64(uint64_t s) {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
}

// FNV-1a 64-bit 流式哈希；用于矩阵+平移的完整性校验。
static uint64_t cprisk_gf2_fnv1a(const uint8_t *data, size_t len) {
    uint64_t h = 0xcbf29ce484222325ULL;  // FNV-1a 64-bit offset basis
    for (size_t i = 0u; i < len; ++i) {
        h ^= (uint64_t)data[i];
        h *= 0x100000001b3ULL;            // FNV-1a 64-bit prime
    }
    return h;
}

// 计算矩阵与平移的链式 FNV-1a 校验值；初始化后矩阵只读，可并发调用。
// Exposed via public CRiskCore.h + visibility("default") so the symbol survives
// `-fvisibility=hidden` and Release strip — armor CFF/VMP policies target this name.
// Removing `static` alone is NOT sufficient under -fvisibility=hidden (which makes
// non-static functions N_PEXT and dead-strippable); the explicit attribute promotes
// to N_EXT. v7.7 audit-fix F1+F4 (post-1st-pass: comment was wrong about the mechanism).
// FNV-1a basis/prime are materialized as immediates here — VMP partial covers them.
__attribute__((visibility("default")))
// 返回 FNV-1a 64-bit 校验值；无失败路径，初始化前调用会读到未初始化内存的哈希。
uint64_t cprisk_gf2_compute_full_checksum(void) {
    // 链式 FNV：先 matrix 再 translation，保证两者都被覆盖。
    // 先哈希 2048 字节矩阵，得到整段校验的起点。
    uint64_t h = cprisk_gf2_fnv1a(kCpriskGf2Matrix, CPRISK_GF2_MATRIX_BYTES);
    // 用 matrix hash 当 translation 的 offset basis 续算
    // 平移向量以矩阵 hash 为 offset basis 续算，避免两段独立哈希被分段替换。
    for (size_t i = 0u; i < CPRISK_GF2_TRANSLATION_BYTES; ++i) {
        h ^= (uint64_t)kCpriskGf2Translation[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

// Exposed via public CRiskCore.h + visibility("default") so the symbol survives
// `-fvisibility=hidden` and Release strip — armor CFF/VMP policies target this name.
// Removing `static` alone is NOT sufficient under -fvisibility=hidden (which makes
// non-static functions N_PEXT and dead-strippable); the explicit attribute promotes
// to N_EXT. v7.7 audit-fix F1+F4 (post-1st-pass: comment was wrong about the mechanism).
// Seed kCpriskGf2InitSeed (0xCAFEBABEDEADBEEFULL) is materialized as immediate here —
// VMP partial walks it through VPC to defeat constant-search matrix recovery.
// 由 32 字节根密钥派生矩阵种子：SHA-256(label || root_key) 取前 8 字节（LE）。
// 必须在首次使用变换前调用；先完成初始化者获胜，后调用被忽略。
/* Derive the GF(2) matrix seed from a 32-byte root key:
 * seed = SHA256("cprisk.gf2.seed.v1" || root_key), first 8 bytes LE.
 * Prefer this over the public-constant seed whenever a root key is
 * available: the matrix then depends on secret material instead of a
 * value anyone can read out of the binary. Must be called before the
 * first transform use (pthread_once: whichever init runs first wins). */
static void cprisk_gf2_init_if_needed(void);

__attribute__((visibility("default")))
// 根密钥注入：NULL 直接返回；派生种子经互斥锁写入 pending 槽位，再触发惰性初始化。
void cprisk_gf2_init_with_root_key(const uint8_t root_key[32]) {
    if (root_key == NULL)
        return;
    // 根密钥派生标签；变更会使所有既有根密钥派生出不同矩阵。
    static const char label[] = "cprisk.gf2.seed.v1";
    uint8_t material[sizeof(label) - 1u + 32u];
    memcpy(material, label, sizeof(label) - 1u);
    memcpy(material + sizeof(label) - 1u, root_key, 32u);
    uint8_t digest[32];
    // 用 SHA-256 压缩 label 与根密钥，取前 8 字节作为种子。
    cprisk_sha256(material, sizeof(material), digest);
    cprisk_secure_zero(material, sizeof(material));
    uint64_t seed = 0u;
    memcpy(&seed, digest, sizeof(seed));
    cprisk_secure_zero(digest, sizeof(digest));
    // 极端情况下派生种子为 0 时替换为非零常量，避免 xorshift 全零固定点。
    if (seed == 0u)
        seed = 0x9E3779B97F4A7C15ULL;
    // 只有“尚未冻结且 pending 未占用”时才写入；先到先得，防止运行期换种子。
    pthread_mutex_lock(&s_gf2_seed_mutex);
    if (!s_gf2_seed_frozen && !s_gf2_pending_seed_set) {
        s_gf2_pending_seed = seed;
        s_gf2_pending_seed_set = 1;
    }
    pthread_mutex_unlock(&s_gf2_seed_mutex);
    // 写入 pending 后立即触发初始化；若其他线程已先完成初始化，则本次注入被忽略。
    cprisk_gf2_init_if_needed();
}

// 真正生成矩阵与平移：逐个字节推进 xorshift64；读取 pending 种子或回退公开常量。
// 仅由 pthread_once 调用一次，因此无需在函数内加锁保护写表。
__attribute__((visibility("default")))
void cprisk_gf2_init_real(void) {
    pthread_mutex_lock(&s_gf2_seed_mutex);
    // 在锁内完成种子选择与冻结，保证并发 init_with_root_key 不会改变已选种子。
    uint64_t s = s_gf2_pending_seed_set ? s_gf2_pending_seed : kCpriskGf2InitSeed;
    s_gf2_seed_frozen = 1;
    pthread_mutex_unlock(&s_gf2_seed_mutex);
    // 每字节独立取 xorshift 输出低 8 位；矩阵内容是伪随机的，不等于可逆矩阵。
    for (size_t i = 0u; i < CPRISK_GF2_MATRIX_BYTES; ++i) {
        s = cprisk_gf2_xorshift64(s);
        kCpriskGf2Matrix[i] = (uint8_t)(s & 0xFFu);
    }
    // 平移向量紧接矩阵继续推进同一 xorshift 状态，因此两者由同一序列派生。
    for (size_t i = 0u; i < CPRISK_GF2_TRANSLATION_BYTES; ++i) {
        s = cprisk_gf2_xorshift64(s);
        kCpriskGf2Translation[i] = (uint8_t)(s & 0xFFu);
    }
    // 记录初始化后的校验值；self_check 用它检测 BSS 内矩阵/平移是否被改写。
    kCpriskGf2InitChecksum = cprisk_gf2_compute_full_checksum();
}

// pthread_once 包装：多线程首次调用只执行一次 cprisk_gf2_init_real。
static inline void cprisk_gf2_init_if_needed(void) {
    pthread_once(&kCpriskGf2InitOnce, cprisk_gf2_init_real);
}

// 计算 128-bit 行与输入的内积奇偶性：等价于 GF(2) 上的点积。
// 计算 (a & b) 的 GF(2) 内积奇偶性（popcount mod 2）。
// 用 __builtin_parityll，编译器在 ARM64 上会发 popcount + AND 1，没有循环。
// 参数：row/input 各 16 字节，调用方保证非 NULL；返回 0/1 的奇偶位。
static inline uint8_t cprisk_gf2_inner_parity_128(
    const uint8_t row[16],
    const uint8_t input[16]
) {
    uint64_t row_lo, row_hi, in_lo, in_hi;
    memcpy(&row_lo, row, sizeof(row_lo));
    memcpy(&row_hi, row + 8, sizeof(row_hi));
    memcpy(&in_lo, input, sizeof(in_lo));
    memcpy(&in_hi, input + 8, sizeof(in_hi));
    uint64_t and_lo = row_lo & in_lo;
    uint64_t and_hi = row_hi & in_hi;
    return (uint8_t)((unsigned)__builtin_parityll(and_lo) ^ (unsigned)__builtin_parityll(and_hi));
}

// 公开 API：对 128-bit 输入做 GF(2) 仿射变换。
// 矩阵参数为可选：matrix==NULL 时使用 SDK 默认矩阵（运行时由种子生成）。
// translation==NULL 时使用 SDK 默认平移向量。
//
// 注意：input 与 output 可以是同一缓冲区（先全部读到栈上局部变量再写出）。
// 公开仿射变换：output = M·input ⊕ translation，按位在 GF(2) 上计算。
// - 参数：output/input 各 16 字节；matrix 可选 2048 字节（NULL 用默认），translation 可选 16 字节。
// - 返回：无；output 与 input 可别名，函数先拷贝输入。
// - 线程安全：初始化后矩阵只读，可并发调用；首次调用会触发一次初始化。
// - 可逆性前提：M 必须在 GF(2) 上满秩；本函数不校验，默认矩阵不保证可逆。
// - 失败语义：output/input 为 NULL 时直接返回，不写任何缓冲区。
void cprisk_gf2_affine_transform_16(
    uint8_t output[16],
    const uint8_t input[16],
    const uint8_t *matrix,        // 2048 bytes (128×16); NULL = default
    const uint8_t *translation    // 16 bytes; NULL = default
) {
    // 只做最小参数防护：与 C API 习惯一致，NULL 视为调用方错误并静默返回。
    if (output == NULL || input == NULL) {
        return;
    }

    cprisk_gf2_init_if_needed();

    // 矩阵/平移为 NULL 时使用运行时默认值；显式传入时调用方保证尺寸。
    const uint8_t *m = matrix != NULL ? matrix : kCpriskGf2Matrix;
    const uint8_t *t = translation != NULL ? translation : kCpriskGf2Translation;

    // 先快照输入：允许 output == input，也允许输出与矩阵缓冲区重叠的极端调用。
    // 先把 input 拷贝到栈上的本地缓冲区，允许 input == output 的别名调用。
    uint8_t local_input[16];
    memcpy(local_input, input, sizeof(local_input));

    uint8_t result[16];
    memset(result, 0, sizeof(result));

    // 逐行计算一个输出 bit：行 i 的 16 字节系数与输入做内积，得到 bit i。
    for (int row = 0; row < 128; ++row) {
        const uint8_t *row_ptr = m + (row * 16);
        uint8_t parity = cprisk_gf2_inner_parity_128(row_ptr, local_input);
        if (parity) {
            // 位序为 MSB-first：row/8 定位字节，7-(row%8) 定位位，与 Swift 侧 transform_16 对齐。
            // 输出 bit 编号：row / 8 是字节索引；7 - (row % 8) 是该字节内的 bit（高位优先）。
            int byte_idx = row / 8;
            int bit_idx  = 7 - (row % 8);
            result[byte_idx] = (uint8_t)(result[byte_idx] | (uint8_t)(1u << bit_idx));
        }
    }

    // 仿射常数项：逐字节异或平移向量，完成 output = M·input ⊕ b。
    for (int j = 0; j < 16; ++j) {
        result[j] ^= t[j];
    }

    memcpy(output, result, sizeof(result));
}

// 自校验：重算 FNV-1a 并与 init 时记录值比对；只读矩阵，可并发调用。
// 返回 0 表示一致；非 0 表示 BSS 内的矩阵或平移被改写（或初始化未完成）。
// 自校验：对运行时矩阵 + 平移向量做 FNV-1a，与 init 时记录的值比对。
// 攻击者修改 .bss 任意一字节都会导致 mismatch。
// 返回 0 = OK，非零 = 矩阵被篡改。
// 注意：校验值本身也在 BSS，攻击者可同时改写矩阵与校验值；该检查是篡改证据，不是密码学证明。
int cprisk_gf2_affine_self_check(void) {
    cprisk_gf2_init_if_needed();
    uint64_t now = cprisk_gf2_compute_full_checksum();
    return (now == kCpriskGf2InitChecksum) ? 0 : 1;
}
