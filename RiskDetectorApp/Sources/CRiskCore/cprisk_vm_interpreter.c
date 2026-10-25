// cprisk_vm_interpreter.c —— 自定义 VM 字节码解释器：布局校验、取指解码、语义执行与状态收尾。
// 输入来自 Mach-O 的 __DATA,__swift5_mdvrt（dispatch）/__swift5_mdirt（bytecode）段；
// 本文件把“函数 id”解析成入口，在加密 PC 与加密操作数/立即数之上执行字节码，输出 64 字节状态与 vreg。
// 执行状态全部放在每次 run 独立的 cprisk_vm_interp_frame_t 中；唯一进程级状态是 atomic 缓存的
// session_mix（只写一次，之后并发只读）。任何布局/完整性校验失败都按 fail-closed 处理：
// 置 poison/status 后提前结束，绝不回退到明文或“尽量执行”。
#include "include/CRiskCore.h"
#include "include/cprisk_cff.h"
#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_limits.h"
#include "include/cprisk_vm_interpreter_ops.h"
#include "include/cprisk_macho.h"
#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"
#include "cprisk_vm_hardening.h"
#include "include/cprisk_vm_oph_dead.h"

#include <stdatomic.h>
#include <string.h>

/* Deployment gate: enable only for an image finalized by the CPSV v2 injector.
 * Keep legacy shipping defaults until final-image and device acceptance passes. */
// 线程化（CPSV v2）分发的部署开关：默认 0（走传统解释循环）。仅当镜像由 CPSV v2 injector
// 完成最终化、且真机验收通过后才可置 1；该路径仍属实验性质，打开后必须同时满足 v2 头部与
// CPSH 期望，缺少任一条件都会整段拒绝，而不是回退到旧路径。
#ifndef CPRISK_VM_THREADED_DISPATCH
#define CPRISK_VM_THREADED_DISPATCH 0
#endif
#if CPRISK_VM_THREADED_DISPATCH
#include "include/cprisk_vm_cpsv2_hash.h"
struct cprisk_thread_context_i;
static void cprisk_thread_run_a_i(cprisk_vm_interp_frame_t *);
static void cprisk_thread_run_b_i(cprisk_vm_interp_frame_t *);
static void cprisk_thread_a_nop_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_ret_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_raw_region_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_halt_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_add_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_branch_rel_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_branch_cond_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_call_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_mov_wide_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_adr_add_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_cond_select_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_load_store_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_xor_mix_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_or_lane_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_and_lane_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_rol_acc_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_vm_call_func_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_vreg_mov_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_vreg_alu_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_vreg_mem_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_sub_lane_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_mul_lane_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_add_rol_acc_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_branch_ind_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_poison_i(struct cprisk_thread_context_i *);
static void cprisk_thread_a_unknown_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_nop_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_ret_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_raw_region_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_halt_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_add_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_branch_rel_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_branch_cond_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_call_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_mov_wide_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_adr_add_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_cond_select_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_load_store_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_xor_mix_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_or_lane_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_and_lane_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_rol_acc_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_vm_call_func_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_vreg_mov_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_vreg_alu_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_vreg_mem_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_sub_lane_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_mul_lane_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_add_rol_acc_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_branch_ind_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_poison_i(struct cprisk_thread_context_i *);
static void cprisk_thread_b_unknown_i(struct cprisk_thread_context_i *);
#endif

#if defined(__APPLE__)
#include <TargetConditionals.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#if __has_include(<sys/random.h>)
#include <sys/random.h>
#define CPRISK_VM_HAVE_GETENTROPY 1
#endif
#endif

// 单次 run 的硬步数上限（DoS 防护）。实际预算由 step_limit_cap 在 [MAX-12288, MAX] 内按
// 函数/会话随机收紧，因此这里只是上限兜底，不是常规执行长度。
#define CPRISK_VM_MAX_STEPS 65536u
// dispatch 类别表（class table）一次解码 32 项；缓存按 32 对齐分段，减少重复解密开销。
#define CPRISK_VM_DISPATCH_CACHE_BYTES 32u
// 字节码头部布局：核心 16 字节；M2 追加 vpc_a/vpc_b（16 字节）；V3 可再各追加 8 字节的
// immediate / opcode 种子。读取任何扩展字段前都必须先用 total_bytes 做边界检查。
#define CPRISK_VMP_BYTECODE_HEADER_CORE_BYTES ((size_t)sizeof(cprisk_vmp_bytecode_header_t))
#define CPRISK_VMP_BYTECODE_VPC_EXT_BYTES 16u

/** Re-hash bytecode segment every N steps when \c CPRISK_VMP_BC_FLAG_BC_SEG_RUNTIME_SHA256 is set. */
// 开启 BC_SEG_RUNTIME_SHA256 时，每 256 步重算一次整段字节码哈希；周期过小会被
// 无意义的 SHA256 拖慢热路径，过大则给运行期补丁留出窗口。
#ifndef CPRISK_VM_BC_HASH_PERIOD
#define CPRISK_VM_BC_HASH_PERIOD 256u
#endif
/**
 * Skip redundant periodic SHA256 when the last successful bytecode hash was fewer than this many
 * steps ago (control-flow boundary checks are unaffected).
 */
// 距上次成功哈希不足 32 步时跳过周期性复查；RET/HALT/VM_CALL 等控制流边界不受此限制。
#ifndef CPRISK_VM_BC_HASH_MIN_INTERVAL
#define CPRISK_VM_BC_HASH_MIN_INTERVAL 32u
#endif
/** Minimum interval (in completed steps) for session-domain white-box side effects when not on a hot M3 path. */
// 非 XOR_MIX 热路径上，白盒域副作用的最小间隔（以已完成的步数计）。
#ifndef CPRISK_VM_WB_SIDE_PERIOD
#define CPRISK_VM_WB_SIDE_PERIOD 64u
#endif
/** Strategy 13: run bytecode-loop Diophantine opaque block every N completed steps (anti_symbolic_heavy). */
// 反符号执行策略：每 8 步跑一次完整 Diophantine opaque 块；它是纯噪声计算，不改变 acc。
#ifndef CPRISK_VM_MATH_HALLUC_BC_PERIOD
#define CPRISK_VM_MATH_HALLUC_BC_PERIOD 8u
#endif
/** Strategy 13: polymorphic lane sidefx period (steps); must be > 0. */
// lane 级 Diophantine 副作用的周期；必须 > 0（为 0 时取模会崩溃）。
#ifndef CPRISK_VM_MATH_HALLUC_POLY_PERIOD
#define CPRISK_VM_MATH_HALLUC_POLY_PERIOD 64u
#endif
// 只有 semantic_family 达到该阈值才启用 lane 级数学噪声，避免低族函数承担额外开销。
#ifndef CPRISK_VM_MATH_HALLUC_SEM_FAMILY_MIN
#define CPRISK_VM_MATH_HALLUC_SEM_FAMILY_MIN 2u
#endif

// 从任意地址读取小端 u64；用 memcpy 保证未对齐安全。p == NULL 时返回 0（调用方负责判空语义）。
uint64_t cprisk_read_le_u64_i(const uint8_t *p) {
    uint64_t value = 0;
    if (!p)
        return 0;
    memcpy(&value, p, sizeof(value));
    return value;
}

// 同上的小端 u32 版本；NULL 返回 0。
static uint32_t cprisk_read_le_u32_i(const uint8_t *p) {
    uint32_t value = 0;
    if (!p)
        return 0;
    memcpy(&value, p, sizeof(value));
    return value;
}

/* cprisk_splitmix64_next_i is now provided by cprisk_vm_interpreter_internal.h (inline) */

// 判断头部是否携带 M2 扩展：PER_ENTRY_VPC / HANDLER_VARIANT_SEED / VPC_NONLINEAR
// 任一存在，都意味着核心头部后还有 16 字节 VPC 元数据。
static int cprisk_vmp_bytecode_has_m2_i(const cprisk_vmp_bytecode_header_t *bh) {
    if (!bh)
        return 0;
    return (bh->reserved & CPRISK_VMP_BC_FLAG_PER_ENTRY_VPC) != 0u
        || (bh->reserved & CPRISK_VMP_BC_FLAG_HANDLER_VARIANT_SEED) != 0u
        || (bh->reserved & CPRISK_VMP_BC_FLAG_VPC_NONLINEAR) != 0u;
}

// 计算头部总字节数（核心 + 按标志/版本出现的扩展块），供所有越界检查使用。
static size_t cprisk_vmp_bytecode_header_total_bytes_i(const cprisk_vmp_bytecode_header_t *bh) {
    size_t total = CPRISK_VMP_BYTECODE_HEADER_CORE_BYTES;
    if (cprisk_vmp_bytecode_has_m2_i(bh))
        total += CPRISK_VMP_BYTECODE_VPC_EXT_BYTES;
    if (bh && bh->version >= CPRISK_VMP_VERSION_V3
        && (bh->reserved & CPRISK_VMP_BC_FLAG_ENC_IMMEDIATE) != 0u)
        total += 8u;
    if (bh && bh->version >= CPRISK_VMP_VERSION_V3
        && (bh->reserved & CPRISK_VMP_BC_FLAG_ENC_OPCODE) != 0u)
        total += 8u;
    return total;
}

// 单个入口描述符的步长；置 PER_ENTRY_VPC 时每个入口后追加 16 字节 VPC 数据。
static size_t cprisk_vmp_bytecode_entry_stride_i(const cprisk_vmp_bytecode_header_t *bh) {
    size_t stride = sizeof(cprisk_vmp_bytecode_entry_t);
    if (bh && (bh->reserved & CPRISK_VMP_BC_FLAG_PER_ENTRY_VPC) != 0u)
        stride += CPRISK_VMP_BYTECODE_VPC_EXT_BYTES;
    return stride;
}

// 仅接受 v1/v2/v3；未知版本一律视为不合法字节码。
static int cprisk_vmp_bytecode_version_ok_i(uint32_t v) {
    return v == CPRISK_VMP_VERSION || v == CPRISK_VMP_VERSION_M2 || v == CPRISK_VMP_VERSION_V3;
}

// 读取全局（或调用方指定的）VPC 仿射参数 a,b；无 M2 扩展时返回恒等映射 (1,0)。
// 磁盘上的 a/b 用 SplitMix64(func_id + 固定域常量) 派生的一次性掩码异或，避免明文常量。
// - 参数：b_sec 为字节码段起点；bh 为已校验头部；func_id 参与掩码派生。
// - 输出：out_a/out_b 必须非 NULL（调用方保证）；本函数不做额外布局校验。
void cprisk_vmp_read_vpc_affine_i(const uint8_t *b_sec,
                                       const cprisk_vmp_bytecode_header_t *bh,
                                       uint64_t func_id,
                                       uint64_t *out_a,
                                       uint64_t *out_b) {
    *out_a = 1u;
    *out_b = 0u;
    if (!bh || !b_sec || !cprisk_vmp_bytecode_has_m2_i(bh))
        return;
    uint64_t raw_a = cprisk_read_le_u64_i(b_sec + CPRISK_VMP_BYTECODE_HEADER_CORE_BYTES);
    uint64_t raw_b = cprisk_read_le_u64_i(b_sec + CPRISK_VMP_BYTECODE_HEADER_CORE_BYTES + 8u);
    /* Derive XOR mask from func_id + 0x53504556 ('VPES') via SplitMix64 */
    uint64_t mask_state = func_id + UINT64_C(0x53504556);
    uint64_t mask_a = cprisk_splitmix64_next_i(&mask_state);
    mask_a = (mask_a << 32) | cprisk_splitmix64_next_i(&mask_state);
    uint64_t mask_b = cprisk_splitmix64_next_i(&mask_state);
    mask_b = (mask_b << 32) | cprisk_splitmix64_next_i(&mask_state);
    *out_a = raw_a ^ mask_a;
    *out_b = raw_b ^ mask_b;
}

// 置 VPC_NONLINEAR 时，PC 用 8 轮 Feistel + 标签编码，而非 a*pc+b 仿射。
static int cprisk_vmp_vpc_is_nonlinear_i(const cprisk_vmp_bytecode_header_t *bh) {
    return bh != NULL && (bh->reserved & CPRISK_VMP_BC_FLAG_VPC_NONLINEAR) != 0u;
}

// 前向声明区：主循环按执行 lane 拆分（A=lane0，B=lane1/2），并允许自检窗口按符号取地址。
static uint32_t cprisk_vm_session_mix_i(void);
static void cprisk_vm_interp_loop_a(struct cprisk_vm_interp_frame *fr);
static void cprisk_vm_interp_loop_b(struct cprisk_vm_interp_frame *fr);
static void cprisk_vm_interp_finish_run_lane0_i(cprisk_vm_interp_frame_t *fr);
static void cprisk_vm_interp_finish_run_lane1_i(cprisk_vm_interp_frame_t *fr);
static void cprisk_vm_interp_finish_run_lane2_i(cprisk_vm_interp_frame_t *fr);
static int cprisk_vm_execute_lane0_i(uint64_t func_id,
                                     cprisk_vm_run_result_t *out,
                                     const void *hdr_sym);
static int cprisk_vm_execute_lane1_i(uint64_t func_id,
                                     cprisk_vm_run_result_t *out,
                                     const void *hdr_sym);
static int cprisk_vm_execute_lane2_i(uint64_t func_id,
                                     cprisk_vm_run_result_t *out,
                                     const void *hdr_sym);
// 旧版单一 run 入口的前向声明；当前实际执行由 lane0/1/2 三个变体承担，本符号无定义也无调用。
static void cprisk_vm_run_program_i(const struct mach_header_64 *hdr,
                                    const uint8_t *d_sec,
                                    const cprisk_vmp_dispatch_header_t *dhdr,
                                    const uint8_t *b_sec,
                                    unsigned long bsz,
                                    const cprisk_vmp_bytecode_header_t *bh,
                                    uint32_t path_lane,
                                    uint64_t func_id,
                                    uint8_t acc[32],
                                    cprisk_vm_run_result_t *out);
static void cprisk_vm_run_program_lane0_i(const struct mach_header_64 *hdr,
                                          const uint8_t *d_sec,
                                          const cprisk_vmp_dispatch_header_t *dhdr,
                                          const uint8_t *b_sec,
                                          unsigned long bsz,
                                          const cprisk_vmp_bytecode_header_t *bh,
                                          uint64_t func_id,
                                          uint8_t acc[32],
                                          cprisk_vm_run_result_t *out);
static void cprisk_vm_run_program_lane1_i(const struct mach_header_64 *hdr,
                                          const uint8_t *d_sec,
                                          const cprisk_vmp_dispatch_header_t *dhdr,
                                          const uint8_t *b_sec,
                                          unsigned long bsz,
                                          const cprisk_vmp_bytecode_header_t *bh,
                                          uint64_t func_id,
                                          uint8_t acc[32],
                                          cprisk_vm_run_result_t *out);
static void cprisk_vm_run_program_lane2_i(const struct mach_header_64 *hdr,
                                          const uint8_t *d_sec,
                                          const cprisk_vmp_dispatch_header_t *dhdr,
                                          const uint8_t *b_sec,
                                          unsigned long bsz,
                                          const cprisk_vmp_bytecode_header_t *bh,
                                          uint64_t func_id,
                                          uint8_t acc[32],
                                          cprisk_vm_run_result_t *out);
uint64_t cprisk_vm_entry(uint64_t func_id);
uint64_t cprisk_vm_entry_alt1(uint64_t func_id);
uint64_t cprisk_vm_entry_alt2(uint64_t func_id);

// 32 位循环左/右移：n 先对 32 取模，n == 0 时直接返回，避免移位 UB。
static uint32_t cprisk_vmp_rotl32_i(uint32_t x, uint32_t n) {
    n &= 31u;
    return n == 0u ? x : ((x << n) | (x >> (32u - n)));
}

// 32 位循环右移；与 rotl 一起供 Feistel/混合使用。
static uint32_t cprisk_vmp_rotr32_i(uint32_t x, uint32_t n) {
    n &= 31u;
    return n == 0u ? x : ((x >> n) | (x << (32u - n)));
}

// 32 位 avalanche finalizer（类 xxHash）：只用于扩散/混淆，不是密码学哈希，
// 不能当作 MAC 或抗碰撞承诺使用。
uint32_t cprisk_vmp_avalanche32_i(uint32_t x) {
    x ^= x >> 16u;
    x *= 0x7FEB352Du;
    x ^= x >> 15u;
    x *= 0x846CA68Bu;
    x ^= x >> 16u;
    return x;
}

/* 4-bit nibble permutation stored XOR-masked (no raw permutation vector in rodata). */
// VPC 非线性编码用的 4-bit nibble S-box。表中存的是 XOR 0x5 后的值，运行时再异或还原；
// 目的只是避免在只读段留下可直接提取的置换向量。
static const uint8_t cprisk_vmp_vpc_sbox_enc_i[16] = {
    0x9u, 0x0u, 0x3u, 0xeu, 0xcu, 0x5u, 0xfu, 0x8u,
    0x6u, 0xbu, 0xau, 0xdu, 0x1u, 0x2u, 0x4u, 0x7u,
};
#define CPRISK_VMP_VPC_SBOX_XOR_I 0x5u

// 对 16 位值逐 nibble 查 S-box 并拼回，作为 Feistel F 函数的非线性层。
static uint16_t cprisk_vmp_vpc_sub16_i(uint16_t value) {
    uint16_t out = 0u;
    for (uint32_t nib = 0u; nib < 4u; nib++) {
        const uint16_t idx = (uint16_t)((value >> (nib * 4u)) & 0xFu);
        const uint8_t mapped =
            (uint8_t)(cprisk_vmp_vpc_sbox_enc_i[idx] ^ CPRISK_VMP_VPC_SBOX_XOR_I);
        out |= (uint16_t)mapped << (nib * 4u);
    }
    return out;
}

// 非线性 PC 编码的 Feistel 轮数；8 轮足以抵抗直接反推，同时保持常数时间。
#define CPRISK_VMP_VPC_FEISTEL_ROUNDS 8u

// 由 (a,b) 派生 Feistel 轮密钥与 salt；常量仅作域分离（"VMPC"/"M4VP"）。
static uint32_t cprisk_vmp_vpc_key32_i(uint64_t a, uint64_t b) {
    return cprisk_vmp_avalanche32_i(
        (uint32_t)a ^
        (uint32_t)(a >> 32u) ^
        cprisk_vmp_rotl32_i((uint32_t)b, 7u) ^
        (uint32_t)(b >> 32u) ^
        0x564D5043u
    );
}

// 由 (a,b) 派生 Feistel salt；与 key32 使用不同域常量，确保轮密钥与 salt 独立。
static uint32_t cprisk_vmp_vpc_salt32_i(uint64_t a, uint64_t b) {
    return cprisk_vmp_avalanche32_i(
        (uint32_t)b ^
        (uint32_t)(b >> 32u) ^
        cprisk_vmp_rotl32_i((uint32_t)a, 11u) ^
        (uint32_t)(a >> 32u) ^
        0x4D345650u
    );
}

// 单轮 Feistel 轮函数：轮常量 + avalanche 派生轮密钥，再经 nibble S-box、旋转与再扩散。
static uint16_t cprisk_vmp_vpc_feistel_F_i(uint16_t r, uint32_t key, uint32_t salt, uint32_t round) {
    uint32_t rk = cprisk_vmp_avalanche32_i(key ^ salt ^ (round * 0x9E3779B9u) ^ 0xDEADBEEFu);
    uint16_t piece = (uint16_t)(r ^ (uint16_t)rk ^ (uint16_t)(rk >> 16u));
    piece = cprisk_vmp_vpc_sub16_i(piece);
    piece ^= (uint16_t)cprisk_vmp_rotr32_i(rk, (round & 7u) + 1u);
    return (uint16_t)cprisk_vmp_avalanche32_i((uint32_t)piece ^ rk ^ 0xA5C31F27u);
}

// 8 轮 Feistel 编解码；前后各做一次与 key/salt 绑定的 avalanche 白化。
// decode 必须与 encode 严格互逆，任何不一致都会在 tag 校验处暴露。
static uint32_t cprisk_vmp_vpc_feistel32_encode_i(uint32_t state, uint32_t key, uint32_t salt) {
    uint32_t v = state ^ cprisk_vmp_avalanche32_i(key ^ salt ^ 0xF1055A1u);
    uint16_t l = (uint16_t)(v >> 16);
    uint16_t r = (uint16_t)(v & 0xFFFFu);
    for (uint32_t round = 0u; round < CPRISK_VMP_VPC_FEISTEL_ROUNDS; round++) {
        const uint16_t nl = r;
        const uint16_t nr = (uint16_t)(l ^ cprisk_vmp_vpc_feistel_F_i(r, key, salt, round));
        l = nl;
        r = nr;
    }
    return (((uint32_t)l << 16) | (uint32_t)r)
        ^ cprisk_vmp_avalanche32_i(key ^ salt ^ 0xACC0DECu);
}

// Feistel 解码：逆序回放 8 轮并还原前后白化，必须与 encode 严格互逆。
static uint32_t cprisk_vmp_vpc_feistel32_decode_i(uint32_t encoded_state, uint32_t key, uint32_t salt) {
    uint32_t mid = encoded_state ^ cprisk_vmp_avalanche32_i(key ^ salt ^ 0xACC0DECu);
    uint16_t l = (uint16_t)(mid >> 16);
    uint16_t r = (uint16_t)(mid & 0xFFFFu);
    for (uint32_t round = CPRISK_VMP_VPC_FEISTEL_ROUNDS; round > 0u; round--) {
        const uint32_t idx = round - 1u;
        const uint16_t pr = l;
        const uint16_t pl = (uint16_t)(r ^ cprisk_vmp_vpc_feistel_F_i(l, key, salt, idx));
        l = pl;
        r = pr;
    }
    return (((uint32_t)l << 16) | (uint32_t)r)
        ^ cprisk_vmp_avalanche32_i(key ^ salt ^ 0xF1055A1u);
}

// 为编码后的 PC 生成 32 位标签，绑定 key/salt；decode 时先验标签再解 Feistel。
static uint32_t cprisk_vmp_vpc_tag32_i(uint32_t encoded_pc32, uint32_t key, uint32_t salt) {
    return cprisk_vmp_avalanche32_i(
        encoded_pc32 ^
        cprisk_vmp_rotl32_i(key, 5u) ^
        cprisk_vmp_rotr32_i(salt, 3u) ^
        0xD00DFEEDu
    );
}

// 非线性 PC 编码：把 session_mix 混入 key/salt，返回 (tag32 << 32) | enc32。
// 由于 session_mix 每进程不同，同一份磁盘字节码在不同运行中的 encoded_pc 也不同。
static uint64_t cprisk_vmp_nonlinear_encode_pc_i(uint32_t pc, uint64_t a, uint64_t b) {
    const uint32_t session = cprisk_vm_session_mix_i();
    const uint32_t key = cprisk_vmp_vpc_key32_i(a, b) ^ session;
    const uint32_t salt = cprisk_vmp_vpc_salt32_i(a, b) ^ cprisk_vmp_rotl32_i(session, 9u);
    const uint32_t enc32 = cprisk_vmp_vpc_feistel32_encode_i(pc, key, salt);
    const uint32_t tag32 = cprisk_vmp_vpc_tag32_i(enc32, key, salt);
    return ((uint64_t)tag32 << 32u) | (uint64_t)enc32;
}

// 非线性 PC 解码：重算标签并做常数时间比较；标签不符返回 0（调用方置 BYTECODE 污染）。
static int cprisk_vmp_nonlinear_decode_pc_i(uint64_t encoded_pc,
                                            uint64_t a,
                                            uint64_t b,
                                            uint32_t *out_pc) {
    if (!out_pc) {
        return 0;
    }
    const uint32_t session = cprisk_vm_session_mix_i();
    const uint32_t key = cprisk_vmp_vpc_key32_i(a, b) ^ session;
    const uint32_t salt = cprisk_vmp_vpc_salt32_i(a, b) ^ cprisk_vmp_rotl32_i(session, 9u);
    const uint32_t enc32 = (uint32_t)encoded_pc;
    const uint32_t tag32 = (uint32_t)(encoded_pc >> 32u);
    if (tag32 != cprisk_vmp_vpc_tag32_i(enc32, key, salt)) {
        return 0;
    }
    *out_pc = cprisk_vmp_vpc_feistel32_decode_i(enc32, key, salt);
    return 1;
}

// 把逻辑 PC 编码成 encoded_pc。非线性模式直接走 Feistel；仿射模式做乘法/加法溢出检查，
// 溢出时写 INVALID_BYTECODE/POISON_BYTECODE 并返回 0。out_enc 必须非 NULL。
int cprisk_vm_encode_pc_i(const cprisk_vmp_bytecode_header_t *bh,
                                 uint32_t pc,
                                 uint64_t vpc_a,
                                 uint64_t vpc_b,
                                 uint64_t *out_enc,
                                 cprisk_vm_run_result_t *out) {
    if (!out_enc) {
        return 0;
    }
    if (cprisk_vmp_vpc_is_nonlinear_i(bh)) {
        *out_enc = cprisk_vmp_nonlinear_encode_pc_i(pc, vpc_a, vpc_b);
        return 1;
    }
    uint64_t scaled = 0u;
    if (__builtin_mul_overflow((uint64_t)pc, vpc_a, &scaled) ||
        __builtin_add_overflow(scaled, vpc_b, &scaled)) {
        if (out) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        }
        return 0;
    }
    *out_enc = scaled;
    return 1;
}

// encode 的逆过程。仿射模式要求 encoded_pc >= vpc_b、vpc_a != 0、差值可整除且结果
// 不超过 UINT32_MAX；任一条不满足都置 INVALID_BYTECODE/POISON_BYTECODE 并返回 0。
static int cprisk_vm_decode_pc_i(const cprisk_vmp_bytecode_header_t *bh,
                                 uint64_t encoded_pc,
                                 uint64_t vpc_a,
                                 uint64_t vpc_b,
                                 uint32_t *out_pc,
                                 cprisk_vm_run_result_t *out) {
    if (!out_pc) {
        return 0;
    }
    if (cprisk_vmp_vpc_is_nonlinear_i(bh)) {
        if (!cprisk_vmp_nonlinear_decode_pc_i(encoded_pc, vpc_a, vpc_b, out_pc)) {
            if (out) {
                out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
                out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            }
            return 0;
        }
        return 1;
    }
    if (encoded_pc < vpc_b) {
        if (out) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        }
        return 0;
    }
    const uint64_t numer = encoded_pc - vpc_b;
    if (vpc_a == 0u || numer % vpc_a != 0u) {
        if (out) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        }
        return 0;
    }
    const uint64_t pc64 = numer / vpc_a;
    if (pc64 > (uint64_t)UINT32_MAX) {
        if (out) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        }
        return 0;
    }
    *out_pc = (uint32_t)pc64;
    return 1;
}

// 进程级 session_mix 的一次性缓存。0 是“未初始化”哨兵，因此最终值强制非零；
// 初始化后只读，可被任意线程并发读取（atomic_load/atomic_store，使用默认的 seq_cst 语义）。
static atomic_uint_fast32_t s_vm_session_mix_i = 0;

// 采集单调时钟、pid、内核熵、会话密钥与运行时材料，经 avalanche 得到非零 session_mix。
// 该值不直接决定 acc 语义，但贯穿 PC 编码、dispatch 解密、opaque 链与白盒输入；
// 取不到某项材料时按可用子集继续（熵源 fail-open），而布局/完整性校验仍是 fail-closed。
static uint32_t cprisk_vm_session_mix_i(void) {
    uint32_t cached = (uint32_t)atomic_load(&s_vm_session_mix_i);
    if (cached != 0u) {
        return cached;
    }

    uint32_t mix = 0xA5C31F27u;
#if defined(__APPLE__)
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
        mix ^= (uint32_t)now.tv_nsec;
        mix ^= (uint32_t)now.tv_sec * 0x9E3779B9u;
    }
    mix ^= (uint32_t)getpid() * 0x45D9F3Bu;

    uint32_t entropy_word = 0;
#ifdef CPRISK_VM_HAVE_GETENTROPY
    if (getentropy(&entropy_word, sizeof(entropy_word)) != 0) {
        entropy_word = (uint32_t)mach_absolute_time();
    }
#else
    arc4random_buf(&entropy_word, sizeof(entropy_word));
    if (entropy_word == 0u) {
        entropy_word = (uint32_t)mach_absolute_time();
    }
#endif
    mix ^= entropy_word;
#endif

    uint8_t session_key[CPRISK_ARMOR_KEY_SIZE];
    if (cprisk_get_session_key(session_key) == 0) {
        mix ^= cprisk_read_le_u32_i(session_key);
        mix ^= cprisk_read_le_u32_i(session_key + 12u);
        mix ^= cprisk_read_le_u32_i(session_key + 24u);
        cprisk_secure_zero(session_key, sizeof(session_key));
    }

    if (cprisk_runtime_material_ready() != 0) {
        uint8_t runtime_material[CPRISK_ARMOR_KEY_SIZE];
        if (cprisk_get_runtime_material(runtime_material) == 0) {
            mix ^= cprisk_read_le_u32_i(runtime_material + 4u);
            mix ^= cprisk_read_le_u32_i(runtime_material + 20u);
            cprisk_secure_zero(runtime_material, sizeof(runtime_material));
        }
    }

    mix = cprisk_vmp_avalanche32_i(mix ^ 0x6D2B79F5u);
    if (mix == 0u) {
        mix = 0x6D2B79F5u;
    }
    atomic_store(&s_vm_session_mix_i, mix);
    return mix;
}

// 派生 2-bit（0..3）handler 变体号：由步数、函数 id、逻辑 op、立即数与 session_mix 决定。
// 作用是让同一语义 op 在不同位置选择不同的等价实现路径，增加差分/符号分析成本。
static uint32_t cprisk_vm_handler_variant_i(uint32_t hdr_reserved,
                                          uint64_t func_id,
                                          uint64_t steps,
                                          uint32_t op,
                                          uint64_t imm) {
    uint32_t mix = (uint32_t)(steps ^ (uint32_t)func_id ^ (uint32_t)(func_id >> 32));
    mix ^= (uint32_t)(imm ^ (imm >> 32));
    mix ^= (uint32_t)op * 0x9E3779B9u;
    if ((hdr_reserved & CPRISK_VMP_BC_FLAG_HANDLER_VARIANT_SEED) != 0u)
        mix ^= (hdr_reserved >> 8) & 3u;
    mix ^= cprisk_vm_session_mix_i();
    return mix & 3u;
}

// 32 路 lane 选择器：把 pc/func_id/步数/hvar/semantic_family/session_mix 混成 0..31 的索引，
// 保证全部 switch 分支都可能被走到，而不是总落在少数固定分支上。
/** 32-way semantic lane selector (seed/pc/func/handler — all reachable switch arms). */
static uint32_t cprisk_vm_lane_poly32_i(uint32_t pc,
                                       uint64_t func_id,
                                       uint64_t steps,
                                       uint32_t hvar,
                                       uint32_t semantic_family) {
    uint32_t x = (uint32_t)pc ^ (uint32_t)func_id ^ (uint32_t)(func_id >> 32u);
    x ^= (uint32_t)steps ^ (uint32_t)(steps >> 32u);
    x ^= hvar * 0x9E37u;
    x ^= (semantic_family & 0xFu) * 0xC2B2u;
    x ^= cprisk_vm_session_mix_i() ^ (cprisk_vm_session_mix_i() >> 11);
    return x % 32u;
}

/** Extra no-op staging (semantic identity) before poly 16–31 paths — harder trace slicing vs poly 0–15. */
// 在高半区（poly >= 16）先做一段“语义恒等”的 staging：读改写 acc，但结果不变。
// volatile 读与固定 12 轮循环用于在反汇编/轨迹上制造与低半区不同的形状。
static void cprisk_vm_lane_poly_staging_i(uint8_t acc[32],
                                           uint32_t steps,
                                           uint32_t poly,
                                           uint32_t semantic_family,
                                           uint64_t func_id) {
    volatile uint32_t tag = cprisk_vmp_avalanche32_i(
        poly ^ semantic_family ^ (uint32_t)steps ^ (uint32_t)func_id ^ 0xFAC3E7A2u
    );
    for (uint32_t z = 0u; z < 12u; z++) {
        uint32_t ix = (z * 5u + (tag & 7u) + semantic_family + (uint32_t)(func_id & 7u)) & 31u;
        volatile uint8_t vv = acc[ix];
        uint8_t id = (uint8_t)(vv ^ (uint8_t)(((uint32_t)vv * 2u - (uint32_t)vv - (uint32_t)vv) & 0xFFu));
        acc[ix] = id;
    }
}

// 解析入口描述符 reserved 中的执行 profile：高字节必须是 magic 0xA5。
// 输出 semantic_family（4 bit）、mixed_predicate_profile（4 bit）与 max_subcall_depth（4 bit + 1）。
// 返回 1 表示 magic 有效；返回 0 时调用方应使用 fallback，而不能把 0 当作合法 profile。
int cprisk_vm_entry_profile_decode_i(uint32_t entry_reserved,
                                            uint32_t *semantic_family,
                                            uint32_t *mixed_predicate_profile,
                                            uint32_t *max_subcall_depth) {
    if ((entry_reserved >> 24) != CPRISK_VMP_ENTRY_PROFILE_MAGIC)
        return 0;
    if (semantic_family)
        *semantic_family = ((entry_reserved >> CPRISK_VMP_ENTRY_SEMANTIC_FAMILY_SHIFT) & 0xFu);
    if (mixed_predicate_profile)
        *mixed_predicate_profile = ((entry_reserved >> CPRISK_VMP_ENTRY_MIXED_PRED_SHIFT) & 0xFu);
    if (max_subcall_depth)
        *max_subcall_depth = (((entry_reserved >> CPRISK_VMP_ENTRY_SUBCALL_DEPTH_SHIFT) & 0xFu) + 1u);
    return 1;
}

// profile 缺失或被篡改时的兜底派生。把仅运行期可知的 SPN S-box 种子混入，
// 使攻击者无法仅凭公开的 func_id/头部 reserved 预先算出 (sem, mix, depth) 三元组。
void cprisk_vm_entry_profile_fallback_i(uint64_t func_id,
                                               uint32_t hdr_reserved,
                                               uint32_t *semantic_family,
                                               uint32_t *mixed_predicate_profile,
                                               uint32_t *max_subcall_depth) {
    /*
     * Mix in a runtime-only secret (the per-build SPN S-box seed) so an
     * attacker who corrupts `entry->reserved` to force this fallback path
     * cannot precompute the resulting (sem, mix, depth) triple from
     * `func_id` and `hdr_reserved` alone — both of which are public in
     * the on-disk header. Without this mix, forcing fallback gave a
     * deterministic and externally predictable execution profile.
     */
    const uint64_t runtime_secret = cprisk_cff_runtime_spn_sbox_seed();
    uint64_t st = func_id ^ ((uint64_t)hdr_reserved << 32) ^ 0x45584350524F4631ULL; /* "EXCPROF1" */
    st ^= runtime_secret;
    uint32_t sem = (uint32_t)(cprisk_splitmix64_next_i(&st) % 4u) + 1u;
    uint32_t mix = (uint32_t)(cprisk_splitmix64_next_i(&st) % 8u);
    uint32_t depth = (uint32_t)(cprisk_splitmix64_next_i(&st) % 8u) + 2u;
    if (semantic_family)
        *semantic_family = sem;
    if (mixed_predicate_profile)
        *mixed_predicate_profile = mix;
    if (max_subcall_depth)
        *max_subcall_depth = depth;
}

// 用异或/进位循环实现 8 位加法（不依赖 CPU 的 ADD），是 add_equiv 的等价实现之一。
static uint8_t cprisk_vm_add_byte_bitwise_i(uint8_t a, uint8_t b) {
    while (b != 0u) {
        uint8_t carry = (uint8_t)(a & b);
        a = (uint8_t)(a ^ b);
        b = (uint8_t)(carry << 1u);
    }
    return a;
}

// 16 种 uint8 加法的语义等价写法（含 MBA 恒等式）。style 只改变实现形状，
// 结果始终是 (lhs + rhs) mod 256。
static uint8_t cprisk_vm_add_equiv_i(uint8_t lhs, uint8_t rhs, uint32_t style) {
    const uint32_t L = (uint32_t)lhs;
    const uint32_t R = (uint32_t)rhs;
    switch (style % 16u) {
    case 0u:
        return (uint8_t)(L + R);
    case 1u:
        return cprisk_vm_add_byte_bitwise_i(lhs, rhs);
    case 2u:
        return (uint8_t)(L - (uint32_t)(uint8_t)(~rhs + 1u));
    case 3u:
        return (uint8_t)((L ^ R) + ((L & R) << 1u)); /* a+b mod 256 */
    case 4u:
        return (uint8_t)(cprisk_vm_add_byte_bitwise_i((uint8_t)L, (uint8_t)(R ^ (uint8_t)(L & (uint8_t)(~R)))));
    case 5u:
        return (uint8_t)((L ^ R) + ((L & R) << 1u));
    case 6u:
        return (uint8_t)(L - (~R) - 1u);
    case 7u:
        return (uint8_t)(((L & R) << 1u) + (L ^ R));
    case 8u:
        return (uint8_t)((L ^ R) + ((L & R) << 1u)); /* carry identity */
    case 9u:
        return (uint8_t)(L + R + (L & R) - (L & R)); /* MBA noop */
    case 10u:
        return (uint8_t)(L + ((R ^ 0xFFu) ^ 0xFFu)); /* ≡ L+R */
    case 11u:
        return (uint8_t)(cprisk_vm_add_byte_bitwise_i(lhs, (uint8_t)(R ^ (uint8_t)(L & R))));
    case 12u:
        return (uint8_t)((L & ~R) + R + (L & R));
    case 13u:
        return (uint8_t)(L + (R & 0xFEu) + (R & 1u));
    case 14u:
        return (uint8_t)((L | R) + (L & R) - (L & R));
    default:
        return (uint8_t)((L + R) & 0xFFu);
    }
}

/** lane_family: 0 = ADD polymorphic, 1 = SUB (wrapping), 2 = MUL mod 256. */
// 按 lane_family 选择运算族：0=ADD（多态等价写法）、1=SUB（uint8 回绕）、2=MUL（mod 256）。
static uint8_t cprisk_vm_lane_combine_i(uint8_t lhs, uint8_t rhs, uint32_t style, uint32_t lane_family) {
    if (lane_family == 1u)
        return (uint8_t)(lhs - rhs);
    if (lane_family == 2u)
        return (uint8_t)(lhs * rhs);
    return cprisk_vm_add_equiv_i(lhs, rhs, style);
}

// 16 种 uint8 异或的语义等价写法；结果始终是 lhs ^ rhs，style 仅改变中间表达式。
static uint8_t cprisk_vm_xor_equiv_i(uint8_t lhs, uint8_t rhs, uint32_t style) {
    const uint32_t L = (uint32_t)lhs;
    const uint32_t R = (uint32_t)rhs;
    switch (style % 16u) {
    case 0u:
        return (uint8_t)(L ^ R);
    case 1u:
        return (uint8_t)((lhs | rhs) & (uint8_t)(~(lhs & rhs)));
    case 2u:
        return (uint8_t)(L + R - ((L & R) << 1u));
    case 3u:
        return (uint8_t)((L | R) - (L & R));
    case 4u:
        return (uint8_t)(~(L & R) & (L | R));
    case 5u:
        return (uint8_t)((L & ~R) | (~L & R));
    case 6u:
        return (uint8_t)((L + R) - 2u * (L & R));
    case 7u:
        return (uint8_t)(L ^ R);
    case 8u:
        return (uint8_t)((L | R) & (uint8_t)(~(L & R)));
    case 9u:
        return (uint8_t)(~(L & R) & (L | R));
    case 10u:
        return (uint8_t)((L & R) ^ L ^ R);
    case 11u:
        return (uint8_t)((L | R) ^ (L & R));
    case 12u:
        return (uint8_t)(L ^ R ^ ((L & R) & 0u));
    case 13u:
        return (uint8_t)((L & ~R) | (~L & R));
    case 14u:
        return (uint8_t)(L ^ R);
    default:
        return (uint8_t)(L ^ R);
    }
}

// RAW_REGION 语义：把 imm 的 8 个字节分别 XOR 到 acc 的 8 个 lane。
// lane 索引按步数旋转；多数 poly 分支只改变施加顺序/快照方式，结果等价。
// 注意 case 13 的 (t*2+1)&7 只遍历奇数 lane 且各两次，XOR 下相互抵消，
// 因此该分支并不与其他分支等价；最终结果依赖实际选中的 poly，而非固定语义。
// 失败语义：无（纯字节运算，不触碰 PC、steps 或状态标志）。
void cprisk_vm_raw_region_apply_i(uint8_t acc[32],
                                         uint64_t imm,
                                         uint32_t steps,
                                         uint32_t variant,
                                         uint32_t semantic_family,
                                         uint64_t func_id,
                                         uint32_t pc) {
    uint8_t lanes[8];
    uint8_t idxs[8];
    uint8_t snapshot[8];
    const uint32_t base = (uint32_t)(steps & 0x0Fu);
    for (uint32_t i = 0; i < 8u; i++) {
        lanes[i] = (uint8_t)((imm >> (i * 8u)) & 0xFFu);
        idxs[i] = (uint8_t)((i + base) & 31u);
    }

    uint32_t poly = cprisk_vm_lane_poly32_i(pc, func_id, steps, variant, semantic_family);
    if (poly >= 16u)
        cprisk_vm_lane_poly_staging_i(acc, steps, poly, semantic_family, func_id);
    poly &= 15u;
    switch (poly) {
    case 0u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t style = semantic_family + i;
            acc[idxs[i]] = cprisk_vm_xor_equiv_i(acc[idxs[i]], lanes[i], style);
        }
        break;
    case 1u:
        for (uint32_t i = 0; i < 8u; i++)
            snapshot[i] = acc[idxs[i]];
        for (int i = 7; i >= 0; i--) {
            uint32_t u = (uint32_t)i;
            uint32_t style = variant + semantic_family + u;
            acc[idxs[u]] = cprisk_vm_xor_equiv_i(snapshot[u], lanes[u], style);
        }
        break;
    case 2u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t * 3u + semantic_family) & 7u;
            uint32_t style = variant ^ semantic_family ^ i;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_xor_equiv_i(cur, lanes[i], style);
        }
        break;
    case 3u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t style = (i * 3u) ^ variant ^ (uint32_t)(pc & 0xFu);
            acc[idxs[i]] = cprisk_vm_xor_equiv_i(acc[idxs[i]], lanes[i], style);
        }
        break;
    case 4u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t style = semantic_family + (i ^ 4u);
            acc[idxs[i]] = cprisk_vm_xor_equiv_i(acc[idxs[i]], lanes[i], style);
        }
        break;
    case 5u:
        for (uint32_t i = 0; i < 8u; i++)
            snapshot[i] = acc[idxs[i]];
        for (uint32_t u = 0; u < 8u; u++) {
            uint32_t style = (uint32_t)steps + u + variant;
            acc[idxs[u]] = cprisk_vm_xor_equiv_i(snapshot[u], lanes[u], style);
        }
        break;
    case 6u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t * 5u + variant) & 7u;
            uint32_t style = semantic_family + i * 7u;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_xor_equiv_i(cur, lanes[i], style);
        }
        break;
    case 7u:
        for (int i = 0; i < 8; i += 2) {
            uint32_t style = (uint32_t)i + semantic_family;
            acc[idxs[(uint32_t)i]] = cprisk_vm_xor_equiv_i(acc[idxs[(uint32_t)i]], lanes[(uint32_t)i], style);
        }
        for (int i = 1; i < 8; i += 2) {
            uint32_t style = (uint32_t)i + variant;
            acc[idxs[(uint32_t)i]] = cprisk_vm_xor_equiv_i(acc[idxs[(uint32_t)i]], lanes[(uint32_t)i], style);
        }
        break;
    case 8u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t j = (7u - i);
            uint32_t style = variant + j * 11u;
            acc[idxs[j]] = cprisk_vm_xor_equiv_i(acc[idxs[j]], lanes[j], style);
        }
        break;
    case 9u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t * 7u + semantic_family * 3u) & 7u;
            uint32_t style = (uint32_t)func_id + t;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_xor_equiv_i(cur, lanes[i], style);
        }
        break;
    case 10u:
        for (uint32_t i = 0; i < 8u; i++)
            snapshot[i] = acc[idxs[i]];
        for (uint32_t u = 0; u < 8u; u++) {
            uint32_t k = (u + 4u) & 7u;
            uint32_t style = semantic_family ^ u ^ k;
            acc[idxs[k]] = cprisk_vm_xor_equiv_i(snapshot[k], lanes[k], style);
        }
        break;
    case 11u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t ^ (variant & 7u)) & 7u;
            uint32_t style = (uint32_t)(func_id >> (t & 7u)) ^ semantic_family;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_xor_equiv_i(cur, lanes[i], style);
        }
        break;
    case 12u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t style = pc + i + variant;
            acc[idxs[i]] = cprisk_vm_xor_equiv_i(acc[idxs[i]], lanes[i], style);
        }
        break;
    case 13u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t * 2u + 1u) & 7u;
            uint32_t style = variant + t + (uint32_t)(pc & 3u);
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_xor_equiv_i(cur, lanes[i], style);
        }
        break;
    case 14u:
        for (uint32_t i = 0; i < 8u; i++)
            snapshot[i] = acc[idxs[i]];
        for (int i = 7; i >= 0; i--) {
            uint32_t u = (uint32_t)i;
            uint32_t style = (semantic_family << 1) + u ^ variant;
            acc[idxs[u]] = cprisk_vm_xor_equiv_i(snapshot[u], lanes[u], style);
        }
        break;
    default:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t + (uint32_t)(func_id & 7u)) & 7u;
            uint32_t style = variant + semantic_family + (pc & 7u) + t;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_xor_equiv_i(cur, lanes[i], style);
        }
        break;
    }
}

// 顺序执行时的 PC 推进：decode 当前 encoded_pc → 加一条指令宽度 → 重新 encode。
// 任何 decode/encode 失败都会把错误写进 out（INVALID_BYTECODE / POISON_BYTECODE）。
// 返回 1 成功；0 失败（调用方应返回 CPRISK_VM_FLOW_LEAVE）。
int cprisk_vm_enc_pc_advance_ctx_i(const cprisk_vmp_bytecode_header_t *bh,
                                          uint64_t *enc_pc,
                                          uint64_t vpc_a,
                                          uint64_t vpc_b,
                                          cprisk_vm_run_result_t *out) {
    uint32_t pc = 0u;
    if (!enc_pc || !cprisk_vm_decode_pc_i(bh, *enc_pc, vpc_a, vpc_b, &pc, out)) {
        return 0;
    }
    if ((uint64_t)pc + CPRISK_VM_INSN_WIDTH > (uint64_t)UINT32_MAX) {
        if (out) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        }
        return 0;
    }
    return cprisk_vm_encode_pc_i(
        bh,
        pc + CPRISK_VM_INSN_WIDTH,
        vpc_a,
        vpc_b,
        enc_pc,
        out
    );
}

// 与 raw_region_apply 相同的 lane 布局/poly 选择，但按 lane_family 做 ADD/SUB/MUL。
// 这是 ADD/SUB/MUL 三种 opcode 的共同实现核心；注意 case 13 会重复访问奇数 lane，
// 第二次施加会继续叠加（不是等价重排），实际结果以选中的 poly 为准。
static void cprisk_vm_lane_family_apply_i(uint8_t acc[32],
                                          uint64_t imm,
                                          uint32_t steps,
                                          uint32_t variant,
                                          uint32_t semantic_family,
                                          uint64_t func_id,
                                          uint32_t pc,
                                          uint32_t lane_family) {
    uint8_t lanes[8];
    uint8_t idxs[8];
    uint8_t snapshot[8];
    const uint32_t base = (uint32_t)(steps & 0x0Fu);
    for (uint32_t i = 0; i < 8u; i++) {
        lanes[i] = (uint8_t)((imm >> (i * 8u)) & 0xFFu);
        idxs[i] = (uint8_t)((i + base) & 31u);
    }

    uint32_t poly = cprisk_vm_lane_poly32_i(pc, func_id, steps, variant, semantic_family);
    if (poly >= 16u)
        cprisk_vm_lane_poly_staging_i(acc, steps, poly, semantic_family, func_id);
    poly &= 15u;
    switch (poly) {
    case 0u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t style = semantic_family + i;
            acc[idxs[i]] = cprisk_vm_lane_combine_i(acc[idxs[i]], lanes[i], style, lane_family);
        }
        break;
    case 1u:
        for (uint32_t i = 0; i < 8u; i++)
            snapshot[i] = acc[idxs[i]];
        for (int i = 7; i >= 0; i--) {
            uint32_t u = (uint32_t)i;
            uint32_t style = variant + semantic_family + u;
            acc[idxs[u]] = cprisk_vm_lane_combine_i(snapshot[u], lanes[u], style, lane_family);
        }
        break;
    case 2u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t * 5u + variant + semantic_family) & 7u;
            uint32_t style = variant ^ semantic_family ^ i;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_lane_combine_i(cur, lanes[i], style, lane_family);
        }
        break;
    case 3u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t style = (i * 5u) ^ (uint32_t)(pc & 0x1Fu);
            acc[idxs[i]] = cprisk_vm_lane_combine_i(acc[idxs[i]], lanes[i], style, lane_family);
        }
        break;
    case 4u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t style = semantic_family + (i ^ 3u);
            acc[idxs[i]] = cprisk_vm_lane_combine_i(acc[idxs[i]], lanes[i], style, lane_family);
        }
        break;
    case 5u:
        for (uint32_t i = 0; i < 8u; i++)
            snapshot[i] = acc[idxs[i]];
        for (uint32_t u = 0; u < 8u; u++) {
            uint32_t style = (uint32_t)steps + u * 3u;
            acc[idxs[u]] = cprisk_vm_lane_combine_i(snapshot[u], lanes[u], style, lane_family);
        }
        break;
    case 6u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t * 3u + variant * 2u) & 7u;
            uint32_t style = semantic_family + i * 5u;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_lane_combine_i(cur, lanes[i], style, lane_family);
        }
        break;
    case 7u:
        for (int i = 0; i < 8; i += 2) {
            uint32_t style = (uint32_t)i + variant;
            acc[idxs[(uint32_t)i]] = cprisk_vm_lane_combine_i(acc[idxs[(uint32_t)i]], lanes[(uint32_t)i], style, lane_family);
        }
        for (int i = 1; i < 8; i += 2) {
            uint32_t style = (uint32_t)i + semantic_family;
            acc[idxs[(uint32_t)i]] = cprisk_vm_lane_combine_i(acc[idxs[(uint32_t)i]], lanes[(uint32_t)i], style, lane_family);
        }
        break;
    case 8u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t j = (7u - i);
            uint32_t style = variant + j * 13u;
            acc[idxs[j]] = cprisk_vm_lane_combine_i(acc[idxs[j]], lanes[j], style, lane_family);
        }
        break;
    case 9u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t * 11u + (uint32_t)(func_id & 7u)) & 7u;
            uint32_t style = (uint32_t)func_id + t + semantic_family;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_lane_combine_i(cur, lanes[i], style, lane_family);
        }
        break;
    case 10u:
        for (uint32_t i = 0; i < 8u; i++)
            snapshot[i] = acc[idxs[i]];
        for (uint32_t u = 0; u < 8u; u++) {
            uint32_t k = (u ^ 3u) & 7u;
            uint32_t style = variant ^ u ^ k;
            acc[idxs[k]] = cprisk_vm_lane_combine_i(snapshot[k], lanes[k], style, lane_family);
        }
        break;
    case 11u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t ^ (semantic_family & 7u)) & 7u;
            uint32_t style = (uint32_t)(func_id >> 8) ^ t;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_lane_combine_i(cur, lanes[i], style, lane_family);
        }
        break;
    case 12u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t style = pc + i * 7u;
            acc[idxs[i]] = cprisk_vm_lane_combine_i(acc[idxs[i]], lanes[i], style, lane_family);
        }
        break;
    case 13u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t * 2u + 3u) & 7u;
            uint32_t style = variant + t + (uint32_t)(pc & 5u);
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_lane_combine_i(cur, lanes[i], style, lane_family);
        }
        break;
    case 14u:
        for (uint32_t i = 0; i < 8u; i++)
            snapshot[i] = acc[idxs[i]];
        for (int i = 7; i >= 0; i--) {
            uint32_t u = (uint32_t)i;
            uint32_t style = (semantic_family * 3u) + u ^ variant;
            acc[idxs[u]] = cprisk_vm_lane_combine_i(snapshot[u], lanes[u], style, lane_family);
        }
        break;
    default:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t + variant) & 7u;
            uint32_t style = semantic_family + (uint32_t)(func_id & 0xFFu) + t;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_lane_combine_i(cur, lanes[i], style, lane_family);
        }
        break;
    }
}

// ADD/SUB/MUL 三个入口只是把 lane_family 固定为 0/1/2 的薄封装，
// 供 opcode 层与自检窗口引用。
void cprisk_vm_add_apply_i(uint8_t acc[32],
                                  uint64_t imm,
                                  uint32_t steps,
                                  uint32_t variant,
                                  uint32_t semantic_family,
                                  uint64_t func_id,
                                  uint32_t pc) {
    cprisk_vm_lane_family_apply_i(acc, imm, steps, variant, semantic_family, func_id, pc, 0u);
}

// SUB lane 家族入口：固定 lane_family=1（uint8 回绕减法）。
static void cprisk_vm_sub_apply_i(uint8_t acc[32],
                                  uint64_t imm,
                                  uint32_t steps,
                                  uint32_t variant,
                                  uint32_t semantic_family,
                                  uint64_t func_id,
                                  uint32_t pc) {
    cprisk_vm_lane_family_apply_i(acc, imm, steps, variant, semantic_family, func_id, pc, 1u);
}

// MUL lane 家族入口：固定 lane_family=2（mod 256 乘法）。
static void cprisk_vm_mul_apply_i(uint8_t acc[32],
                                  uint64_t imm,
                                  uint32_t steps,
                                  uint32_t variant,
                                  uint32_t semantic_family,
                                  uint64_t func_id,
                                  uint32_t pc) {
    cprisk_vm_lane_family_apply_i(acc, imm, steps, variant, semantic_family, func_id, pc, 2u);
}

// 三种 lane 家族处理函数的统一签名，用于最终的无分支查表调用。
typedef void (*cprisk_vm_lane_apply_fp_i)(uint8_t acc[32],
                                          uint64_t imm,
                                          uint32_t steps,
                                          uint32_t variant,
                                          uint32_t semantic_family,
                                          uint64_t func_id,
                                          uint32_t pc);

// 对 8 个字节分别取 0-b（uint8 回绕），用于把“加 imm”改写成“减 neg(imm)”等恒等变形。
static uint64_t cprisk_vm_imm_neg_bytes_u64_i(uint64_t imm) {
    uint64_t out = 0u;
    for (unsigned i = 0u; i < 8u; i++) {
        uint8_t lb = (uint8_t)((imm >> (i * 8u)) & 0xFFu);
        out |= (uint64_t)(uint8_t)(0u - lb) << (i * 8u);
    }
    return out;
}

/** Per-byte (uint8) addition used for semantic-equivalent lane decompositions. */
// 对 8 个字节分别做 (a + k) mod 256，用于 ADD/SUB 的常数拆分变形。
static uint64_t cprisk_vm_imm_add_bytes_u64_i(uint64_t imm, uint64_t k) {
    uint64_t out = 0u;
    for (unsigned i = 0u; i < 8u; i++) {
        uint8_t a = (uint8_t)((imm >> (i * 8u)) & 0xFFu);
        uint8_t kb = (uint8_t)((k >> (i * 8u)) & 0xFFu);
        out |= (uint64_t)(uint8_t)(a + kb) << (i * 8u);
    }
    return out;
}

// 由 route/pc/步数/func/family 派生每个字节 lane 各不相同的 64 位常数 k，
// 供 ADD/SUB 的“加 k 再减 k”拆分使用。
static uint64_t cprisk_vm_imm_route_salt_u64_i(
    uint32_t route, uint64_t func_id, uint32_t pc, uint32_t steps, uint32_t family) {
    uint32_t s = cprisk_vmp_avalanche32_i(
        route ^ (uint32_t)func_id ^ (uint32_t)(func_id >> 32u) ^ (steps * 0xD6E8FEB7u) ^ pc
        ^ (family * 0x9E37u));
    uint64_t out = 0u;
    for (unsigned i = 0u; i < 8u; i++) {
        uint8_t b = (uint8_t)((s >> ((i & 3u) * 8u)) & 0xFFu);
        out |= (uint64_t)b << (i * 8u);
    }
    return out;
}

// 语义族入口：family 0/1/2 分别对应 ADD/SUB/MUL；route 决定“用哪种等价实现”。
// route 位语义（每种变形都必须严格保持 uint8 逐 lane 等价）：
//   0x10 — ADD 拆成 (+(imm+k), +(-k))；SUB 拆成 (-(imm+k), +k)；
//   0x20 — MUL 用 a*b ≡ -((-a)*b) 的取负恒等式；
//   0x08 — ADD/SUB 交叉改写（a+b ≡ a-(-b)，a-b ≡ a+(-b)）；
//   0x01 — 直接调用对应家族实现；
//   0x02/0x40 — 只对 imm/variant 做自消的 XOR 混淆，语义不变。
// 其他组合走末尾通用路径；family > 2 直接返回（防御非法 route）。
void cprisk_vm_lane_apply_poly_i(uint8_t acc[32],
                                        uint32_t family,
                                        uint64_t imm,
                                        uint32_t steps,
                                        uint32_t variant,
                                        uint32_t semantic_family,
                                        uint64_t func_id,
                                        uint32_t pc,
                                        uint32_t route) {
    static const cprisk_vm_lane_apply_fp_i s_lane_handlers[3] = {
        cprisk_vm_add_apply_i,
        cprisk_vm_sub_apply_i,
        cprisk_vm_mul_apply_i,
    };
    if (family > 2u)
        return;
    /*
     * Polymorphic semantic routes (strict uint8 lane equivalence):
     * - route bit 0x10: ADD/SUB split with per-lane constant k (add: +(imm+k)+(-k); sub: -(imm+k)+(+k)).
     * - route bit 0x20: MUL via uint8 negation identity a*b ≡ -((-a)*b).
     * - route bit 8: ADD↔SUB cross (a+b ≡ a-(-b), a-b ≡ a+(-b)).
     */
    if (family == 0u && (route & 0x10u) != 0u) {
        const uint64_t k = cprisk_vm_imm_route_salt_u64_i(route, func_id, pc, steps, family);
        const uint64_t imm_k = cprisk_vm_imm_add_bytes_u64_i(imm, k);
        const uint64_t neg_k = cprisk_vm_imm_neg_bytes_u64_i(k);
        cprisk_vm_lane_family_apply_i(
            acc, imm_k, steps, variant, semantic_family, func_id, pc, 0u);
        cprisk_vm_lane_family_apply_i(
            acc, neg_k, steps, variant, semantic_family, func_id, pc, 0u);
        return;
    }
    if (family == 1u && (route & 0x10u) != 0u) {
        const uint64_t k = cprisk_vm_imm_route_salt_u64_i(route, func_id, pc, steps, family);
        const uint64_t imm_pk = cprisk_vm_imm_add_bytes_u64_i(imm, k);
        cprisk_vm_lane_family_apply_i(
            acc, imm_pk, steps, variant, semantic_family, func_id, pc, 1u);
        cprisk_vm_lane_family_apply_i(
            acc, k, steps, variant, semantic_family, func_id, pc, 0u);
        return;
    }
    if (family == 2u && (route & 0x20u) != 0u) {
        for (uint32_t i = 0u; i < 32u; i++)
            acc[i] = (uint8_t)(0u - acc[i]);
        cprisk_vm_lane_family_apply_i(
            acc, imm, steps, variant, semantic_family, func_id, pc, 2u);
        for (uint32_t i = 0u; i < 32u; i++)
            acc[i] = (uint8_t)(0u - acc[i]);
        return;
    }
    /*
     * Branch-level polymorphism (semantic family 0/1): alternate decomposition
     * a+b ≡ a-(-b), a-b ≡ a+(-b) per byte lane (uint8 wrap).
     */
    if (family == 0u && (route & 8u) != 0u) {
        const uint64_t imm_neg = cprisk_vm_imm_neg_bytes_u64_i(imm);
        cprisk_vm_lane_family_apply_i(
            acc, imm_neg, steps, variant, semantic_family, func_id, pc, 1u);
        return;
    }
    if (family == 1u && (route & 8u) != 0u) {
        const uint64_t imm_neg = cprisk_vm_imm_neg_bytes_u64_i(imm);
        cprisk_vm_lane_family_apply_i(
            acc, imm_neg, steps, variant, semantic_family, func_id, pc, 0u);
        return;
    }
    if ((route & 1u) != 0u) {
        s_lane_handlers[family](acc, imm, steps, variant, semantic_family, func_id, pc);
        return;
    }

    uint64_t imm_shadow = imm;
    uint32_t variant_shadow = variant;
    if ((route & 2u) != 0u) {
        const uint32_t salt = cprisk_vmp_avalanche32_i(
            (uint32_t)func_id ^ (uint32_t)(func_id >> 32u) ^ steps ^ route ^ family
        );
        imm_shadow = (imm ^ (uint64_t)salt) ^ (uint64_t)salt;
        variant_shadow = variant ^ (salt & 3u) ^ (salt & 3u);
    }
    if ((route & 0x40u) != 0u) {
        const uint32_t salt2 = cprisk_vmp_avalanche32_i(route ^ pc ^ steps ^ 0xBADC0DEu);
        imm_shadow = (imm_shadow ^ ((uint64_t)salt2 << 32)) ^ ((uint64_t)salt2 << 32);
    }
    cprisk_vm_lane_family_apply_i(
        acc,
        imm_shadow,
        steps,
        variant_shadow,
        semantic_family,
        func_id,
        pc,
        family
    );
}

// OR_LANE / AND_LANE 的直通实现：把 imm 的 8 个字节 OR/AND 进 acc 的 8 个旋转 lane。
// semantic_family 在此被忽略；variant 只影响 OR 的 lane 偏移，不改变位运算语义。
static void cprisk_vm_bitwise_lane_or_i(uint8_t acc[32],
                                        uint64_t imm,
                                        uint32_t steps,
                                        uint32_t variant,
                                        uint32_t semantic_family) {
    uint8_t lanes[8];
    uint8_t idxs[8];
    const uint32_t base = (uint32_t)(steps & 0x0Fu);
    for (uint32_t i = 0; i < 8u; i++) {
        lanes[i] = (uint8_t)((imm >> (i * 8u)) & 0xFFu);
        idxs[i] = (uint8_t)((i + base + (variant & 3u)) & 31u);
    }
    for (uint32_t i = 0; i < 8u; i++) {
        (void)semantic_family;
        (void)variant;
        acc[idxs[i]] = (uint8_t)(acc[idxs[i]] | lanes[i]);
    }
}

// AND_LANE 直通实现：把 imm 的 8 字节 AND 进 acc 的 8 个旋转 lane。
static void cprisk_vm_bitwise_lane_and_i(uint8_t acc[32],
                                         uint64_t imm,
                                         uint32_t steps,
                                         uint32_t variant,
                                         uint32_t semantic_family) {
    uint8_t lanes[8];
    uint8_t idxs[8];
    const uint32_t base = (uint32_t)((steps + 3u) & 0x0Fu);
    for (uint32_t i = 0; i < 8u; i++) {
        lanes[i] = (uint8_t)((imm >> (i * 8u)) & 0xFFu);
        idxs[i] = (uint8_t)((i + base) & 31u);
    }
    for (uint32_t i = 0; i < 8u; i++) {
        (void)variant;
        acc[idxs[i]] = (uint8_t)(acc[idxs[i]] & lanes[i]);
    }
}

// 按 route 选择 OR/AND 的两种等价顺序：位 0 置位时正序直通，否则逆序施加；
// 两者结果完全一致，差异仅用于打乱数据流/轨迹形状。
void cprisk_vm_bitwise_lane_poly_i(uint8_t acc[32],
                                          uint32_t logical,
                                          uint64_t imm,
                                          uint32_t steps,
                                          uint32_t variant,
                                          uint32_t semantic_family,
                                          uint32_t route) {
    if ((route & 1u) != 0u) {
        if (logical == CPRISK_VM_OP_OR_LANE)
            cprisk_vm_bitwise_lane_or_i(acc, imm, steps, variant, semantic_family);
        else
            cprisk_vm_bitwise_lane_and_i(acc, imm, steps, variant, semantic_family);
        return;
    }

    uint8_t lanes[8];
    uint8_t idxs[8];
    const uint32_t base =
        logical == CPRISK_VM_OP_OR_LANE ? (uint32_t)(steps & 0x0Fu) : (uint32_t)((steps + 3u) & 0x0Fu);
    for (uint32_t i = 0u; i < 8u; i++) {
        lanes[i] = (uint8_t)((imm >> (i * 8u)) & 0xFFu);
        idxs[i] = (uint8_t)((i + base + ((logical == CPRISK_VM_OP_OR_LANE) ? (variant & 3u) : 0u)) & 31u);
    }
    for (int32_t i = 7; i >= 0; i--) {
        if (logical == CPRISK_VM_OP_OR_LANE)
            acc[idxs[(uint32_t)i]] = (uint8_t)(acc[idxs[(uint32_t)i]] | lanes[(uint32_t)i]);
        else
            acc[idxs[(uint32_t)i]] = (uint8_t)(acc[idxs[(uint32_t)i]] & lanes[(uint32_t)i]);
    }
}

// 把 32 字节 acc 循环左移 (imm & 31) 字节；先复制快照，保证移位是原子的字节置换。
void cprisk_vm_rol_acc_i(uint8_t acc[32], uint64_t imm) {
    unsigned rot = (unsigned)(imm & 31u);
    uint8_t t[32];
    memcpy(t, acc, sizeof(t));
    for (unsigned i = 0; i < 32u; i++)
        acc[i] = t[(i + rot) % 32u];
}

/** Immediate: dst[2:0], src[5:3], mode[7:6] — 0=rr mov, 1=imm56@(>>8), 2=load 8B from acc[@(>>8)&31]. */
// 虚拟寄存器 MOV，立即数字段布局：dst[2:0]、src[5:3]、mode[7:6]。
// mode 0 = reg→reg；mode 1 = 56 位立即数；mode 2 = 从 acc 的 (imm>>8)&31 起环形读 8 字节。
// vregs/acc 由调用方保证非 NULL；本函数不产生错误码。
void cprisk_vm_vreg_mov_i(uint64_t vregs[8], const uint8_t acc[32], uint64_t imm) {
    uint32_t dst = (uint32_t)(imm & 7u);
    uint32_t src = (uint32_t)((imm >> 3) & 7u);
    uint32_t mode = (uint32_t)((imm >> 6) & 3u);
    if (mode == 0u)
        vregs[dst] = vregs[src];
    else if (mode == 1u)
        vregs[dst] = imm >> 8;
    else {
        uint32_t base = (uint32_t)((imm >> 8) & 31u);
        uint64_t w = 0;
        for (uint32_t i = 0; i < 8u; i++)
            w |= (uint64_t)acc[(base + i) & 31u] << (i * 8u);
        vregs[dst] = w;
    }
}

/** Immediate: dst[2:0], a[5:3], b[8:6], op[11:9] — 0 ADD 1 XOR 2 AND 3 OR. */
// 虚拟寄存器 64 位 ALU：dst[2:0]、a[5:3]、b[8:6]、op[11:9]（0 ADD、1 XOR、2 AND、3 OR）。
// op 取其他值时按 OR 处理，与 opcode 层的编码约定一致，不额外报错。
void cprisk_vm_vreg_alu_i(uint64_t vregs[8], uint64_t imm) {
    uint32_t dst = (uint32_t)(imm & 7u);
    uint32_t a = (uint32_t)((imm >> 3) & 7u);
    uint32_t b = (uint32_t)((imm >> 6) & 7u);
    uint32_t op = (uint32_t)((imm >> 9) & 7u);
    uint64_t va = vregs[a];
    uint64_t vb = vregs[b];
    uint64_t r;
    if (op == 0u)
        r = va + vb;
    else if (op == 1u)
        r = va ^ vb;
    else if (op == 2u)
        r = va & vb;
    else
        r = va | vb;
    vregs[dst] = r;
}

/** Immediate: dst[2:0], acc_base[7:3], store bit[8] — 0=load acc→vreg, 1=store vreg→acc. */
// 虚拟寄存器与 acc 之间的 8 字节搬运：dst[2:0]、base[7:3]、store[8]。
// store=0 从 acc 环形窗口读到 vreg；store=1 把 vreg 写回 acc。越界由 &31 环绕处理。
void cprisk_vm_vreg_mem_i(uint64_t vregs[8], uint8_t acc[32], uint64_t imm) {
    uint32_t dst = (uint32_t)(imm & 7u);
    uint32_t base = (uint32_t)((imm >> 3) & 31u);
    uint32_t st = (uint32_t)((imm >> 8) & 1u);
    if (st == 0u) {
        uint64_t w = 0;
        for (uint32_t i = 0; i < 8u; i++)
            w |= (uint64_t)acc[(base + i) & 31u] << (i * 8u);
        vregs[dst] = w;
    } else {
        uint64_t w = vregs[dst];
        for (uint32_t i = 0; i < 8u; i++)
            acc[(base + i) & 31u] = (uint8_t)(w >> (i * 8u));
    }
}

// 把 32 字节 acc 与 salt 混合成 32 位摘要（旋转 + 加法 + 常量）。仅用于绑定状态/派生索引，
// 不要求密码学强度。
static uint32_t cprisk_vm_mix32_from_acc_i(const uint8_t acc[32], uint32_t salt) {
    uint32_t m = salt ^ 0x9E3779B9u;
    for (uint32_t i = 0; i < 32u; i++) {
        m ^= (uint32_t)acc[i] << ((i & 3u) * 8u);
        m = (m << 5u) | (m >> 27u);
        m += 0x7F4A7C15u ^ (i * 0x45D9F3Bu);
    }
    return m;
}

// 同时混入主 acc 与 acc_aux 两个 bank，最后做 avalanche；用于合并与副作用的种子。
static uint32_t cprisk_vm_mix32_from_banks_i(
    const uint8_t acc[CPRISK_VM_ACC_PRIMARY_BYTES],
    const uint8_t acc_aux[CPRISK_VM_ACC_AUX_BYTES],
    uint32_t salt
) {
    uint32_t m = cprisk_vm_mix32_from_acc_i(acc, salt ^ 0x9E3779B9u);
    for (uint32_t i = 0; i < CPRISK_VM_ACC_AUX_BYTES; ++i) {
        const uint32_t idx = (i * 5u + ((salt >> 3u) & 31u)) & 31u;
        m ^= (uint32_t)acc_aux[idx] << ((i & 3u) * 8u);
        m = cprisk_vmp_rotl32_i(m, 7u);
        m += 0x51ED270Bu ^ (i * 0x27D4EB2Du);
    }
    return cprisk_vmp_avalanche32_i(m ^ salt ^ 0xA24BAED5u);
}

// 把主 acc 与 acc_aux 融合成 32 字节输出：先求联合摘要，再按摘要派生索引与 twist 逐字节混合。
// out 与 acc 不允许别名（当前调用方都写入 out->acc 或独立局部数组）。
static void cprisk_vm_merge_banks_i(
    uint8_t out[CPRISK_VM_ACC_PRIMARY_BYTES],
    const uint8_t acc[CPRISK_VM_ACC_PRIMARY_BYTES],
    const uint8_t acc_aux[CPRISK_VM_ACC_AUX_BYTES],
    uint32_t salt
) {
    uint32_t mix = cprisk_vm_mix32_from_banks_i(acc, acc_aux, salt);
    for (uint32_t i = 0; i < CPRISK_VM_ACC_PRIMARY_BYTES; ++i) {
        const uint32_t aux_idx = (i * 7u + (mix & 31u)) & 31u;
        const uint8_t twist = (uint8_t)cprisk_vmp_rotl32_i(mix ^ (i * 0x45D9F3Bu), i & 7u);
        out[i] = (uint8_t)(acc[i] ^ acc_aux[aux_idx] ^ twist);
        mix = cprisk_vmp_avalanche32_i(mix ^ out[i] ^ (i * 0x9E3779B1u));
    }
}

// 用 session/opaque/func/path 初始化 acc_aux，使副 bank 不是主 acc 的简单拷贝；
// 初始值依赖运行期 session，因此同一输入在不同进程中的中间状态不同。
static void cprisk_vm_aux_init_i(cprisk_vm_interp_frame_t *fr) {
    uint32_t mix = cprisk_vmp_avalanche32_i(
        fr->session_mix ^
        fr->opaque_chain ^
        (uint32_t)fr->func_id ^
        (uint32_t)(fr->func_id >> 32u) ^
        (fr->path_lane * 0x51ED270Bu) ^
        0xC0DEC0DEu
    );
    for (uint32_t i = 0; i < CPRISK_VM_ACC_AUX_BYTES; ++i) {
        const uint32_t src = (i * 5u + (mix & 31u)) & 31u;
        fr->acc_aux[i] = (uint8_t)(fr->acc[src] ^ (uint8_t)(mix >> ((i & 3u) * 8u)));
        mix = cprisk_vmp_avalanche32_i(mix ^ fr->acc_aux[i] ^ (i * 0x27D4EB2Du));
    }
}

// 每步更新 acc_aux 的 8 个 lane，并在 ROL/VREG 类 op 上追加对应副作用。
// 不变量：本函数绝不修改 fr->acc 的语义值（只读取 acc 用于派生），也不推进 PC/steps。
static void cprisk_vm_aux_step_i(
    cprisk_vm_interp_frame_t *fr,
    uint8_t logical,
    uint64_t imm,
    uint32_t pc,
    uint32_t hvar
) {
    uint32_t mix = cprisk_vm_mix32_from_banks_i(
        fr->acc,
        fr->acc_aux,
        fr->session_mix ^ fr->opaque_chain ^ hvar ^ logical ^ pc
    );
    const uint32_t base = (mix ^ pc ^ logical ^ (uint32_t)fr->steps) & 31u;
    for (uint32_t i = 0; i < 8u; ++i) {
        const uint32_t idx = (base + i * 3u + (logical & 7u)) & 31u;
        const uint8_t imm_lane = (uint8_t)(imm >> ((i & 7u) * 8u));
        fr->acc_aux[idx] ^= (uint8_t)(
            fr->acc[(idx + logical + i) & 31u] + imm_lane + (uint8_t)(mix >> ((i & 3u) * 8u))
        );
        mix = cprisk_vmp_avalanche32_i(mix ^ fr->acc_aux[idx] ^ (idx * 0x7F4A7C15u));
    }
    if (logical == CPRISK_VM_OP_ROL_ACC || logical == CPRISK_VM_OP_ADD_ROL_ACC) {
        cprisk_vm_rol_acc_i(fr->acc_aux, imm >> (logical == CPRISK_VM_OP_ADD_ROL_ACC ? 32u : 0u));
    }
    if (logical == CPRISK_VM_OP_VREG_ALU || logical == CPRISK_VM_OP_VREG_MOV || logical == CPRISK_VM_OP_VREG_MEM) {
        const uint32_t rix = (uint32_t)(imm & 7u);
        const uint64_t reg = fr->vregs[rix];
        for (uint32_t i = 0; i < 8u; ++i) {
            fr->acc_aux[(base + i) & 31u] ^= (uint8_t)(reg >> (i * 8u));
        }
    }
}

// 按 AArch64 条件码求值（EQ/NE/CS/.../AL/NV）。输入 flags 来自 acc 派生，而非真实 CPU 标志。
static int cprisk_vm_eval_arm_cond_i(uint32_t cond, uint32_t n, uint32_t z, uint32_t c, uint32_t v) {
    switch (cond & 0xFu) {
    case 0x0u: return z != 0u;                 /* EQ */
    case 0x1u: return z == 0u;                 /* NE */
    case 0x2u: return c != 0u;                 /* CS/HS */
    case 0x3u: return c == 0u;                 /* CC/LO */
    case 0x4u: return n != 0u;                 /* MI */
    case 0x5u: return n == 0u;                 /* PL */
    case 0x6u: return v != 0u;                 /* VS */
    case 0x7u: return v == 0u;                 /* VC */
    case 0x8u: return (c != 0u) && (z == 0u); /* HI */
    case 0x9u: return (c == 0u) || (z != 0u); /* LS */
    case 0xAu: return n == v;                  /* GE */
    case 0xBu: return n != v;                  /* LT */
    case 0xCu: return (z == 0u) && (n == v);  /* GT */
    case 0xDu: return (z != 0u) || (n != v);  /* LE */
    case 0xEu: return 1;                       /* AL */
    default: return 0;                         /* NV */
    }
}

// 从环形 acc 的 lane_seed 起按小端读取 width_bytes 字节（1..8），用于 CBZ/CBNZ 与结果折叠。
static uint64_t cprisk_vm_read_acc_word_i(const uint8_t acc[32], uint32_t lane_seed, uint32_t width_bytes) {
    uint64_t value = 0u;
    uint32_t base = lane_seed & 31u;
    if (width_bytes == 0u)
        width_bytes = 1u;
    for (uint32_t i = 0; i < width_bytes; i++) {
        uint32_t idx = (base + i) & 31u;
        value |= ((uint64_t)acc[idx]) << (i * 8u);
    }
    return value;
}

// 解码并求值条件分支：
// - B.cond：掩码 0xFF000010 == 0x54000000；imm19 为指令数，delta = simm19 * 9 字节。
// - CBZ/CBNZ：掩码 0x7E000000 == 0x34000000；从 acc 读取 rt（与 semantic_family 异或）处的字。
// flags 由 acc + 步数 + insn 混合得出，是确定性的“伪标志”，不依赖宿主 CPU 状态。
// 返回 1 表示识别并求值成功；0 表示不是支持的条件分支（调用方继续尝试其他实现）。
static int cprisk_vm_branch_cond_base_i(uint32_t insn,
                                        const uint8_t acc[32],
                                        uint64_t steps,
                                        uint32_t semantic_family,
                                        int *out_decision,
                                        int64_t *out_delta_bytes) {
    if (!out_decision || !out_delta_bytes)
        return 0;

    if ((insn & 0xFF000010u) == 0x54000000u) { /* B.cond */
        uint32_t imm19 = (insn >> 5u) & 0x7FFFFu;
        int32_t simm19 = ((int32_t)(imm19 << 13u)) >> 13u;
        *out_delta_bytes = (int64_t)simm19 * (int64_t)CPRISK_VM_INSN_WIDTH;

        uint32_t mix = cprisk_vm_mix32_from_acc_i(
            acc,
            (uint32_t)steps ^ (semantic_family * 0x9E37u) ^ (uint32_t)(insn >> 10u)
        );
        uint32_t n = (mix >> 31u) & 1u;
        uint32_t z = ((mix ^ (mix >> 16u)) & 0xFFu) == 0u;
        uint32_t c = (mix + 0x6D2B79F5u) < mix;
        uint32_t v = (((mix ^ (mix << 1u)) >> 31u) & 1u);
        *out_decision = cprisk_vm_eval_arm_cond_i(insn & 0xFu, n, z, c, v);
        return 1;
    }

    if ((insn & 0x7E000000u) == 0x34000000u) { /* CBZ/CBNZ */
        uint32_t imm19 = (insn >> 5u) & 0x7FFFFu;
        int32_t simm19 = ((int32_t)(imm19 << 13u)) >> 13u;
        *out_delta_bytes = (int64_t)simm19 * (int64_t)CPRISK_VM_INSN_WIDTH;
        uint32_t rt = insn & 31u;
        uint32_t is64 = (insn >> 31u) & 1u;
        uint32_t cbnz = (insn >> 24u) & 1u;
        uint64_t rv = cprisk_vm_read_acc_word_i(acc, rt ^ semantic_family, is64 ? 8u : 4u);
        *out_decision = cbnz ? (rv != 0u) : (rv == 0u);
        return 1;
    }

    return 0;
}

// 混合谓词包装：base 是真实判定；mixed_profile 的每个分支都构造为与 base 严格等价
// （g0/g1/g2 只出现在 (x||!x)、(x^x)==0 这类恒等式中），用于增加静态分析噪声。
int cprisk_vm_branch_cond_mixed_eval_i(uint32_t insn,
                                              const uint8_t acc[32],
                                              uint64_t steps,
                                              uint32_t semantic_family,
                                              uint32_t mixed_profile,
                                              int *out_taken,
                                              int64_t *out_delta_bytes) {
    int base = 0;
    if (!cprisk_vm_branch_cond_base_i(insn, acc, steps, semantic_family, &base, out_delta_bytes))
        return 0;
    uint32_t guard_mix = cprisk_vm_mix32_from_acc_i(
        acc,
        (uint32_t)(steps ^ (uint64_t)insn ^ ((uint64_t)mixed_profile << 16u))
    );
    uint32_t g0 = guard_mix & 1u;
    uint32_t g1 = (guard_mix >> 5u) & 1u;
    int decision;
    switch (mixed_profile & 3u) {
    case 0u:
        decision = base;
        break;
    case 1u:
        decision = (base && (int)g0) || (base && !(int)g0); /* ≡ base */
        break;
    case 2u:
        decision = (((base ? 1 : 0) ^ (int)g0) != (int)g0); /* ≡ base */
        break;
    default:
        decision = (base || (int)g1) && (base || !(int)g1); /* ≡ base */
        break;
    }
    if ((mixed_profile & 4u) != 0u) {
        uint32_t g2 = (guard_mix >> 11u) & 1u;
        decision = (decision && ((int)g2 || !(int)g2)); /* extra equivalent stage */
    }
    *out_taken = decision ? 1 : 0;
    return 1;
}

// 设置分支目标 encoded_pc：delta 必须是 9 的整数倍；目标必须落在 [0, blen-9] 且对齐，
// 再用 encode_pc_i 重新加密。失败写 INVALID_BYTECODE/POISON_BYTECODE 并返回 0。
int cprisk_vm_set_branch_target_ctx_i(const cprisk_vmp_bytecode_header_t *bh,
                                             uint64_t *enc_pc,
                                             uint64_t vpc_a,
                                             uint64_t vpc_b,
                                             uint32_t blen,
                                             uint32_t pc,
                                             int64_t delta_bytes,
                                             cprisk_vm_run_result_t *out) {
    if (!enc_pc)
        return 0;
    if (delta_bytes % (int64_t)CPRISK_VM_INSN_WIDTH != 0) {
        if (out) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        }
        return 0;
    }
    int64_t target = 0;
    if (__builtin_add_overflow((int64_t)pc, delta_bytes, &target)
        || target < 0 || target % (int64_t)CPRISK_VM_INSN_WIDTH != 0
        || (uint64_t)target + CPRISK_VM_INSN_WIDTH > (uint64_t)blen) {
        if (out) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        }
        return 0;
    }
    uint64_t target_u = (uint64_t)target;
    return cprisk_vm_encode_pc_i(bh, (uint32_t)target_u, vpc_a, vpc_b, enc_pc, out);
}

// 便捷宏：固定使用当前帧的 bh/vpc_b 推进 encoded_pc。
#define cprisk_vm_enc_pc_advance_i(enc_pc, vpc_a, out) \
    cprisk_vm_enc_pc_advance_ctx_i(fr->bh, enc_pc, vpc_a, fr->vpc_b, out)

// 便捷宏：固定使用当前帧的 bh 调用分支目标编码。
#define cprisk_vm_set_branch_target_i(enc_pc, vpc_a, vpc_b, blen, pc, delta_bytes, out) \
    cprisk_vm_set_branch_target_ctx_i(fr->bh, enc_pc, vpc_a, vpc_b, blen, pc, delta_bytes, out)

// 校验 dispatch / bytecode 两个段的最小 ABI：
// - dispatch：magic/version(V1/V2)/class_table_size；V2 还要容纳表后的 8 字节种子。
// - bytecode：magic/version；只有 V3 才允许 ENC_IMMEDIATE / ENC_OPCODE；entry_count ∈ [1,4096]。
// - 头部、入口表与所有函数体的偏移/长度都必须落在段内、互不重叠，正文长度必须是 9 的倍数。
// 返回 1 且（可选）回填 out_bh；任何不一致返回 0，调用方按 INVALID_DISPATCH fail-closed。
static int cprisk_vmp_headers_ok_i(const uint8_t *d_s,
                                   unsigned long d_sz,
                                   const uint8_t *b_s,
                                   unsigned long b_sz,
                                   const cprisk_vmp_bytecode_header_t **out_bh) {
    if (!d_s || d_sz < sizeof(cprisk_vmp_dispatch_header_t) + CPRISK_VMP_CLASS_TABLE_BYTES)
        return 0;
    const cprisk_vmp_dispatch_header_t *dh = (const cprisk_vmp_dispatch_header_t *)(const void *)d_s;
    if (dh->magic != CPRISK_VMP_MAGIC_DISPATCH)
        return 0;
    if (dh->version != CPRISK_VMP_DISPATCH_V1 && dh->version != CPRISK_VMP_DISPATCH_V2)
        return 0;
    if (dh->class_table_size != CPRISK_VMP_CLASS_TABLE_BYTES)
        return 0;
    {
        size_t d_need = sizeof(cprisk_vmp_dispatch_header_t) + CPRISK_VMP_CLASS_TABLE_BYTES;
        if (dh->version == CPRISK_VMP_DISPATCH_V2)
            d_need += CPRISK_VMP_DISPATCH_SEED_BYTES;
        if (d_sz < d_need)
            return 0;
    }

    if (!b_s || b_sz < CPRISK_VMP_BYTECODE_HEADER_CORE_BYTES)
        return 0;
    const cprisk_vmp_bytecode_header_t *bh = (const cprisk_vmp_bytecode_header_t *)(const void *)b_s;
    if (bh->magic != CPRISK_VMP_MAGIC_BYTECODE || !cprisk_vmp_bytecode_version_ok_i(bh->version))
        return 0;
    if ((bh->reserved & CPRISK_VMP_BC_FLAG_ENC_IMMEDIATE) != 0u
        && bh->version < CPRISK_VMP_VERSION_V3)
        return 0;
    if ((bh->reserved & CPRISK_VMP_BC_FLAG_ENC_OPCODE) != 0u
        && bh->version < CPRISK_VMP_VERSION_V3)
        return 0;
    /* Hard cap on entry_count: 4096 entries per bytecode segment (matches the
     * armor producer's deterministic budget). The cap also prevents the
     * `entry_count * entry_stride` multiply below from overflowing size_t —
     * 4096 * 64 = 262144 bytes, well within size_t on every platform. */
    if (bh->entry_count == 0u || bh->entry_count > 4096u)
        return 0;
    const size_t hdr_total = cprisk_vmp_bytecode_header_total_bytes_i(bh);
    if (b_sz < hdr_total)
        return 0;
    const size_t entry_stride = cprisk_vmp_bytecode_entry_stride_i(bh);
    /* Overflow-checked addition: with entry_count <= 4096 and reasonable
     * stride this cannot actually overflow on any 64-bit target, but
     * downstream readers iterate up to b_sz and the audit pass flagged the
     * implicit assumption. Use __builtin_add_overflow for an explicit guard. */
    size_t needed = 0u;
    if (__builtin_mul_overflow((size_t)bh->entry_count, entry_stride, &needed))
        return 0;
    if (__builtin_add_overflow(needed, hdr_total, &needed))
        return 0;
    if (b_sz < needed)
        return 0;
    /* Validate every body before execution: VM_CALL_FUNC may select an entry
     * other than the initial function. Each body must contain whole wire
     * instructions and must not overlap the header/entry table. */
    for (uint32_t i = 0u; i < bh->entry_count; ++i) {
        cprisk_vmp_bytecode_entry_t entry;
        memcpy(&entry, b_s + hdr_total + (size_t)i * entry_stride, sizeof(entry));
        const uint64_t off = entry.bytecode_offset;
        const uint64_t len = entry.bytecode_length;
        if (off < (uint64_t)needed || off > (uint64_t)b_sz
            || len > (uint64_t)b_sz - off
            || len == 0u || len % CPRISK_VM_INSN_WIDTH != 0u)
            return 0;
    }
    if (out_bh)
        *out_bh = bh;
    return 1;
}

// 能力查询：只有 dispatch/bytecode 两段都通过 headers_ok 才返回 CAP_VMP_RUNTIME，
// 否则返回 0。结果并入 CRiskCore 能力位，供上层判断是否启用 VM 路径。
uint32_t cprisk_vm_query_armor_capability_bits(void) {
    const struct mach_header_64 *hdr =
        cprisk_find_own_header((const void *)&cprisk_vm_query_armor_capability_bits);
    if (!hdr)
        return 0u;
    unsigned long dsz = 0;
    unsigned long bsz = 0;
    const uint8_t *d =
        cprisk_find_section(hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_VMP_DISPATCH, &dsz);
    const uint8_t *b =
        cprisk_find_section(hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_VMP_BYTECODE, &bsz);
    if (cprisk_vmp_headers_ok_i(d, dsz, b, bsz, NULL))
        return CPRISK_ARMOR_CAP_VMP_RUNTIME;
    return 0u;
}

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
// 真机被调试时的诱饵状态：对 acc 做一次 SHA256，使短路返回的结果仍然“像正常输出”；
// 模拟器没有可用的检测路径，对应实现直接 no-op（符号仍保留以稳定自检窗口布局）。
static void cprisk_vm_traced_decoy_acc_i(uint8_t acc[32]) {
    const uint8_t *src = acc;
    cprisk_sha256_ctx pctx;
    cprisk_sha256_init(&pctx);
    cprisk_sha256_update(&pctx, src, 32u);
    cprisk_sha256_final(&pctx, acc);
}
#else
static void __attribute__((unused)) cprisk_vm_traced_decoy_acc_i(uint8_t acc[32]) {
    (void)acc;
}
#endif

// 未知/毒化 opcode 的 acc 污染：按 opcode、类别与字节位置异或固定模式，
// 使短路结果不可能被误认为正常输出。
void cprisk_vm_poison_mix_unknown_i(uint8_t acc[32], uint32_t opcode, uint32_t cls) {
    for (unsigned i = 0; i < 32u; i++) {
        uint8_t b = (uint8_t)(0xA5u ^ (unsigned)opcode ^ (unsigned)cls ^ i);
        acc[i] ^= b;
    }
}

/* M3: FNV-1a over interpreter text (ASLR-independent: bytes only). */
// M3 自检用的 FNV-1a：只对代码字节做哈希（不含地址），因此 ASLR 不影响结果。
static uint32_t cprisk_vm_m3_fnv1a_bytes_i(const volatile uint8_t *p, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) {
        h ^= (uint32_t)p[i];
        h *= 16777619u;
    }
    return h;
}

// FNV-1a 续算：把多个不连续的 TEXT 窗口串成一次滚动哈希。
static uint32_t cprisk_vm_m3_fnv1a_continue_i(uint32_t h, const volatile uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        h ^= (uint32_t)p[i];
        h *= 16777619u;
    }
    return h;
}

// 编译期一致性检查：三个窗口长度之和必须等于自检总长，否则 injector 与运行期会采用
// 不同布局。长度不匹配时用 #error 直接阻断构建，而不是运行期静默降级。
#if CPRISK_VM_M3_SELF_INCLUDE_LOOP
#if CPRISK_VM_M3_SELF_EXEC_BYTES + CPRISK_VM_M3_SELF_LOOP_BYTES + CPRISK_VM_M3_SELF_DISPATCH_BYTES \
    != CPRISK_VM_M3_SELF_BYTES
#error "CPRISK_VM_M3_SELF_EXEC_BYTES + CPRISK_VM_M3_SELF_LOOP_BYTES + CPRISK_VM_M3_SELF_DISPATCH_BYTES must equal CPRISK_VM_M3_SELF_BYTES"
#endif
#endif

void cprisk_vm_interp_loop_a(struct cprisk_vm_interp_frame *fr);
uint8_t cprisk_vm_dispatch_lookup(struct cprisk_vm_interp_frame *fr, uint32_t op, uint32_t pc_index);

// 自检窗口描述 ABI：header(magic/version/count/reserved) + count 个 (vmaddr,length,kind)。
// kind 1/2/3 分别对应 execute / loop_a / dispatch_lookup；构建期 injector 与运行期按此解析。
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t count;
    uint32_t reserved;
} cprisk_vm_selfchk_span_header_t;

typedef struct {
    uint64_t vmaddr;
    uint32_t length;
    uint32_t kind;
} cprisk_vm_selfchk_span_entry_t;

#if CPRISK_VM_THREADED_DISPATCH
#if defined(__APPLE__)
// 线程化构建的 CPSV v2 预留 manifest（CPRISK_CPSV2_BYTES 大小）。未注入时除 12 字节头外
// 全为零，运行期 cprisk_cpsv2_parse 会因 UUID/范围不匹配而拒绝，不会误用半成品镜像。
// 注意：host linker 已负责 8 字节 mdvsk 预留，不要再添加 C 侧贡献，否则段会被拼成 16 字节。
__attribute__((used, section("__DATA," CPRISK_ARMOR_SECTION_VMP_SELF_SPANS)))
#endif
static const uint8_t cprisk_vm_selfchk_spans_i[CPRISK_CPSV2_BYTES] = {
    0x43, 0x50, 0x53, 0x56, 2, 0, 0, 0, 58, 0, 0, 0
}; /* Pointer-free reservation; zero UUID/ranges deliberately reject before injection. */
/* The host linker owns the existing 8-byte mdvsk reservation. Do not add
 * another C contribution: ld concatenates both contributions into 16 bytes. */
#else
#if defined(__APPLE__)
#define CPRISK_VM_SELFCHK_SPAN_SECTION_ATTR "__DATA," CPRISK_ARMOR_SECTION_VMP_SELF_SPANS
__attribute__((used, section(CPRISK_VM_SELFCHK_SPAN_SECTION_ATTR)))
#endif
// 非线程化构建的静态自检窗口布局（__swift5_mdvsi）。三个 entry 依次覆盖 execute、
// interp_loop_a 与 dispatch_lookup；总长由 CPRISK_VM_M3_SELF_BYTES 固定，injector 会按
// 同一 symtab 布局生成期望值。指针在链接后由加载器重定位为真实地址。
static const struct {
    cprisk_vm_selfchk_span_header_t header;
    cprisk_vm_selfchk_span_entry_t entries[3];
} cprisk_vm_selfchk_spans_i = {
    {
        CPRISK_VMP_SELF_SPAN_MAGIC,
        CPRISK_VMP_SELF_SPAN_VERSION,
        3u,
        0u,
    },
    {
        { (uint64_t)(uintptr_t)(const void *)&cprisk_vm_execute,
          (uint32_t)CPRISK_VM_M3_SELF_EXEC_BYTES,
          CPRISK_VMP_SELF_SPAN_KIND_EXEC },
        { (uint64_t)(uintptr_t)(const void *)&cprisk_vm_interp_loop_a,
          (uint32_t)CPRISK_VM_M3_SELF_LOOP_BYTES,
          CPRISK_VMP_SELF_SPAN_KIND_LOOP_A },
        { (uint64_t)(uintptr_t)(const void *)&cprisk_vm_dispatch_lookup,
          (uint32_t)CPRISK_VM_M3_SELF_DISPATCH_BYTES,
          CPRISK_VMP_SELF_SPAN_KIND_DISPATCH },
    },
};

// 锁定 CPSV blob 的 64 字节 ABI；字段、顺序或填充的任何变化都必须同步构建期 injector。
_Static_assert(sizeof(cprisk_vm_selfchk_spans_i) == 64u, "CPSV (__swift5_mdvsi) blob size must match ABI");

#endif

// 解析运行期 __DATA,__swift5_mdvsi 中的 self-span 布局：要求 magic/version/count==3、
// 条目非空，且总长度恰好等于编译期 CPRISK_VM_M3_SELF_BYTES；否则返回 0，
// 调用方回退到“直接按符号地址取三段代码”的 legacy 布局。
static int cprisk_vm_selfchk_span_layout_resolve_i(const struct mach_header_64 *mh,
                                                   const cprisk_vm_selfchk_span_entry_t **out_entries,
                                                   uint32_t *out_count,
                                                   size_t *out_total_bytes) {
    if (out_entries)
        *out_entries = NULL;
    if (out_count)
        *out_count = 0u;
    if (out_total_bytes)
        *out_total_bytes = 0u;
    if (!mh || !out_entries || !out_count)
        return 0;

    unsigned long sz = 0;
    const uint8_t *sec =
        cprisk_find_section(mh, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_VMP_SELF_SPANS, &sz);
    if (!sec || sz < sizeof(cprisk_vm_selfchk_span_header_t))
        return 0;

    const cprisk_vm_selfchk_span_header_t *header =
        (const cprisk_vm_selfchk_span_header_t *)(const void *)sec;
    if (header->magic != CPRISK_VMP_SELF_SPAN_MAGIC ||
        header->version != CPRISK_VMP_SELF_SPAN_VERSION ||
        header->count == 0u) {
        return 0;
    }
    if (header->count != 3u)
        return 0;

    size_t need = sizeof(cprisk_vm_selfchk_span_header_t)
        + (size_t)header->count * sizeof(cprisk_vm_selfchk_span_entry_t);
    if (need > (size_t)sz)
        return 0;

    const cprisk_vm_selfchk_span_entry_t *entries =
        (const cprisk_vm_selfchk_span_entry_t *)(const void *)(sec + sizeof(*header));
    size_t total = 0u;
    for (uint32_t i = 0u; i < header->count; i++) {
        if (entries[i].vmaddr == 0u || entries[i].length == 0u)
            return 0;
        total += (size_t)entries[i].length;
    }

    *out_entries = entries;
    *out_count = header->count;
    if (out_total_bytes)
        *out_total_bytes = total;
    return 1;
}

#if defined(__APPLE__)
/**
 * If `__swift5_mdvsi` is present, it must match the compile-time CPSV blob (tamper / drift detection).
 * Absent section: OK (legacy layout path).
 */
// 若镜像中存在 CPSV 段，则必须与静态 blob 完全一致（magic/version/count、三个地址、
// 三个长度与 kind 顺序）。段缺失返回 0（允许旧布局）；大小或内容不符返回 -1（视为篡改）。
static int cprisk_vm_m3_selfchk_cpsv_image_matches_static_i(const struct mach_header_64 *mh) {
    unsigned long sz = 0;
    const uint8_t *p =
        cprisk_find_section(mh, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_VMP_SELF_SPANS, &sz);
    if (!p)
        return 0;
    if (sz != sizeof(cprisk_vm_selfchk_spans_i))
        return -1;
#if CPRISK_VM_THREADED_DISPATCH
    return -1; /* v2 uses the independent roster below; never this legacy path. */
#else
    const cprisk_vm_selfchk_span_header_t *h = (const void *)p;
    const cprisk_vm_selfchk_span_entry_t *e = (const void *)(p + sizeof(*h));
    const uint64_t addresses[3] = {
        (uint64_t)(uintptr_t)&cprisk_vm_execute,
        (uint64_t)(uintptr_t)&cprisk_vm_interp_loop_a,
        (uint64_t)(uintptr_t)&cprisk_vm_dispatch_lookup
    };
    const uint32_t lengths[3] = { CPRISK_VM_M3_SELF_EXEC_BYTES,
        CPRISK_VM_M3_SELF_LOOP_BYTES, CPRISK_VM_M3_SELF_DISPATCH_BYTES };
    if (h->magic != CPRISK_VMP_SELF_SPAN_MAGIC || h->version != 1u || h->count != 3u || h->reserved)
        return -1;
    for (unsigned i = 0; i < 3; i++)
        if (e[i].vmaddr != addresses[i] || e[i].length != lengths[i] || e[i].kind != i + 1u)
            return -1;
    return 0;
#endif
}
#endif

// 旧布局的消息收集：按编译期常量分别从 execute / loop_a / dispatch_lookup 拷贝代码字节。
// 若 SELF_INCLUDE_LOOP=0，则只覆盖 execute 一段，其余字节保持调用方的零初始化。
static void cprisk_vm_selfchk_legacy_collect_msg_i(uint8_t msg[CPRISK_VM_M3_SELF_BYTES]) {
#if CPRISK_VM_M3_SELF_INCLUDE_LOOP
    memcpy(msg, (const void *)&cprisk_vm_execute, (size_t)CPRISK_VM_M3_SELF_EXEC_BYTES);
    memcpy(msg + CPRISK_VM_M3_SELF_EXEC_BYTES,
           (const void *)&cprisk_vm_interp_loop_a,
           (size_t)CPRISK_VM_M3_SELF_LOOP_BYTES);
    memcpy(
        msg + CPRISK_VM_M3_SELF_EXEC_BYTES + CPRISK_VM_M3_SELF_LOOP_BYTES,
        (const void *)&cprisk_vm_dispatch_lookup,
        (size_t)CPRISK_VM_M3_SELF_DISPATCH_BYTES
    );
#else
    memcpy(msg, (const void *)&cprisk_vm_execute, (size_t)CPRISK_VM_M3_SELF_BYTES);
#endif
}

// 优先使用运行期解析到的 span 布局拼接消息（覆盖实际链接后的代码）；解析失败或总长
// 不符时回退 legacy 符号布局。调用方必须提供 CPRISK_VM_M3_SELF_BYTES 大小的缓冲区。
static void cprisk_vm_selfchk_collect_msg_i(const struct mach_header_64 *hdr,
                                            uint8_t msg[CPRISK_VM_M3_SELF_BYTES]) {
    const cprisk_vm_selfchk_span_entry_t *entries = NULL;
    uint32_t count = 0u;
    size_t total = 0u;
    if (cprisk_vm_selfchk_span_layout_resolve_i(hdr, &entries, &count, &total)
        && total == (size_t)CPRISK_VM_M3_SELF_BYTES) {
        size_t offset = 0u;
        for (uint32_t i = 0u; i < count; i++) {
            size_t len = (size_t)entries[i].length;
            memcpy(msg + offset, (const void *)(uintptr_t)entries[i].vmaddr, len);
            offset += len;
        }
        return;
    }
    cprisk_vm_selfchk_legacy_collect_msg_i(msg);
}

// 计算当前镜像中自检窗口的 FNV 值：span 布局可用时逐段续算，否则按 legacy 符号逐段续算。
static uint32_t cprisk_vm_selfchk_observed_fnv_i(const struct mach_header_64 *hdr) {
    const cprisk_vm_selfchk_span_entry_t *entries = NULL;
    uint32_t count = 0u;
    size_t total = 0u;
    if (cprisk_vm_selfchk_span_layout_resolve_i(hdr, &entries, &count, &total)
        && total == (size_t)CPRISK_VM_M3_SELF_BYTES) {
        uint32_t fnv = 2166136261u;
        for (uint32_t i = 0u; i < count; i++) {
            fnv = cprisk_vm_m3_fnv1a_continue_i(
                fnv,
                (const volatile uint8_t *)(const void *)(uintptr_t)entries[i].vmaddr,
                (size_t)entries[i].length
            );
        }
        return fnv;
    }
#if CPRISK_VM_M3_SELF_INCLUDE_LOOP
    uint32_t fnv = 2166136261u;
    fnv = cprisk_vm_m3_fnv1a_continue_i(
        fnv,
        (const volatile uint8_t *)(const void *)&cprisk_vm_execute,
        (size_t)CPRISK_VM_M3_SELF_EXEC_BYTES
    );
    fnv = cprisk_vm_m3_fnv1a_continue_i(
        fnv,
        (const volatile uint8_t *)(const void *)&cprisk_vm_interp_loop_a,
        (size_t)CPRISK_VM_M3_SELF_LOOP_BYTES
    );
    fnv = cprisk_vm_m3_fnv1a_continue_i(
        fnv,
        (const volatile uint8_t *)(const void *)&cprisk_vm_dispatch_lookup,
        (size_t)CPRISK_VM_M3_SELF_DISPATCH_BYTES
    );
    return fnv;
#else
    return cprisk_vm_m3_fnv1a_bytes_i(
        (const volatile uint8_t *)(const void *)&cprisk_vm_execute,
        (size_t)CPRISK_VM_M3_SELF_BYTES
    );
#endif
}

// 把 32 位摘要扩展成非零 64 位 seal mix；该值会异或进 immediate/opcode 种子，
// 从而把“自检是否通过”与后续解码绑定在一起。
static uint64_t cprisk_vm_m3_seal_mix_from_digest_u32_i(uint32_t d) {
    uint64_t x = (uint64_t)d ^ ((uint64_t)d << 32);
    x ^= 0xC6A4A7935BD1E995ULL;
    x = cprisk_splitmix64_next_i(&x);
    x ^= cprisk_splitmix64_next_i(&x);
    if (x == 0u)
        x = 0xA5A5A5A5CAFEBABEULL;
    return x;
}

/**
 * Bait handlers: wrong VM semantics, only referenced from provably-dead branches.
 * Kept out-of-line so the CFG shows distinct "handler" targets under disassembly.
 */
// M3 死代码诱饵：只在可证明不可达的分支里被调用，故意用错误的 VM 语义改写 acc。
// noinline 让反汇编中出现彼此独立的“handler”目标，干扰基于 CFG 的识别。
__attribute__((noinline)) static void cprisk_vm_m3_dead_bait_xor_i(uint8_t acc[32], uint32_t seed, uint32_t lane) {
    uint32_t x = (seed * 0x9E3779B9u) ^ (lane * 0x85EBCA6Bu);
    uint8_t scratch[32];
    for (unsigned i = 0; i < 32u; i++) {
        x = cprisk_vmp_avalanche32_i(x ^ (uint32_t)i ^ 0xA53C1F27u);
        scratch[(i * 5u) & 31u] = (uint8_t)(acc[i] ^ (uint8_t)x);
        acc[i] ^= (uint8_t)(x >> (i & 7u));
        acc[i] ^= scratch[(i * 5u) & 31u];
    }
}

// 诱饵变体：伪加法 + 局部 scratch，产生看似合法的累加器写操作。
__attribute__((noinline)) static void cprisk_vm_m3_dead_bait_add_i(uint8_t acc[32], uint32_t seed, uint32_t lane) {
    uint32_t x = seed + lane * 0x27d4eb2du;
    uint8_t scratch[16] = {0};
    for (unsigned i = 0; i < 32u; i++) {
        x = cprisk_vmp_avalanche32_i(x + i * 0x9E3779B9u);
        scratch[i & 15u] ^= (uint8_t)(x >> ((i & 3u) * 8u));
        acc[i] = (uint8_t)(acc[i] + (uint8_t)(x + i) + scratch[i & 15u]);
    }
}

// 诱饵变体：以 seed 为旋转量重排 acc，并混入逐字节加法。
__attribute__((noinline)) static void cprisk_vm_m3_dead_bait_roll_i(uint8_t acc[32], uint32_t seed) {
    unsigned rot = (unsigned)(seed & 31u);
    uint8_t t[32];
    memcpy(t, acc, sizeof(t));
    for (unsigned i = 0; i < 32u; i++) {
        const uint8_t lhs = t[(i + rot) & 31u];
        const uint8_t rhs = t[(i * 7u + rot) & 31u];
        acc[i] = (uint8_t)(lhs ^ cprisk_vm_add_byte_bitwise_i(rhs, (uint8_t)(seed + i)));
    }
}

// 诱饵变体：保存/恢复 acc（净效果为恒等），中间做 4 lane 重型混合以拉长 trace。
__attribute__((noinline)) static void cprisk_vm_m3_dead_heavy_shadow_i(uint8_t acc[32], uint32_t seed) {
    uint8_t save[32];
    memcpy(save, acc, sizeof(save));
    uint64_t lane[4];
    memcpy(lane, acc, sizeof(lane));
    for (unsigned j = 0; j < 4u; j++)
        lane[j] ^= (uint64_t)(seed + j * 0x9E3779B9u) * UINT64_C(0xD6E8FEB783278F6B);
    for (unsigned r = 0; r < 4u; r++) {
        for (unsigned i = 0; i < 32u; i++) {
            uint32_t ix = (i + r * 7u + (seed & 0xFFu)) & 31u;
            acc[ix] ^= (uint8_t)((lane[(i / 8u) & 3u] >> ((i % 8u) * 8u)) & 0xFFu);
        }
        lane[0] ^= lane[3] ^ ((uint64_t)seed << (17u + (r & 3u)));
        lane[1] = (lane[1] << 13) | (lane[1] >> 51);
        lane[2] ^= (uint64_t)acc[(seed + r * 3u) & 31u] * UINT64_C(0x100000001B3);
    }
    memcpy(acc, save, sizeof(save));
}

/**
 * Decoys in read-only const data: resemble handler RVA / stream-XOR / class tags.
 * Values are not executable pointers; XOR-mixed into opaque predicates only.
 */
/*
 * Dead-handler decoy: control should never reach this in a well-formed
 * bytecode. It is invoked from the dispatcher only on the unreachable
 * default arm (poisoned/corrupted opcode) and is expected to mutate `acc`
 * with non-semantic noise then return. We do NOT mark it `noreturn` —
 * doing so would let the optimiser drop the dispatcher's fall-through
 * arm entirely, removing the very decoy work units that obscure the
 * dispatcher's shape from a tracer.
 */
// 死处理器诱饵：正常字节码永远不会到达；只在 dispatch 的 default（毒化 opcode）分支被引用。
// 故意不标 noreturn，避免优化器删除 fall-through 臂，从而保留这些诱饵工作单元。
static void cprisk_vm_m3_dead_dispatch_i(uint8_t acc[32], uint32_t hdr_reserved, uint32_t opkind);

// 只读段诱饵表：字段看起来像 handler RVA / 流密码 / class tag，但都不是可执行指针。
// 仅参与 opaque/relro 混合（cprisk_vmp_relro_bait_mix_i），使静态数据扫描难以区分真假分发表。
static const struct {
    uint64_t faux_text_rva;
    uint64_t stream_xor;
    uint32_t class_tag;
    uint16_t dispatch_slot;
    uint8_t lane_tag;
    uint8_t span_tag;
    uint32_t bind_mix;
    uint32_t key_mix;
} cprisk_vmp_relro_handler_decoy[] = {
    { UINT64_C(0x1F0E1D2C3B4A5968), UINT64_C(0xEEDDAABBCCDD0011), 0x4856484Bu, 0x0140u, 0x11u, 0x09u, 0x6D2B79F5u, 0x510E527Fu },
    { UINT64_C(0x2E3D4C5B6A7988A7), UINT64_C(0xFF10FFEEDDCCBBAA), 0x4D455441u, 0x0211u, 0x23u, 0x05u, 0x165667B1u, 0x243F6A88u },
    { UINT64_C(0x4030201080706050), UINT64_C(0xBADCAFE00B01E0E1), 0x4445434Fu, 0x0332u, 0x35u, 0x0Du, 0x85EBCA6Bu, 0x13198A2Eu },
    { UINT64_C(0xF0E1D2C3B4A59687), UINT64_C(0x1122334455667788), 0x42415432u, 0x0443u, 0x47u, 0x11u, 0x27D4EB2Du, 0xA4093822u },
    { UINT64_C(0x7162534415263728), UINT64_C(0x90ABCDEF13572468), 0x534C4F54u, 0x0554u, 0x59u, 0x15u, 0x45D9F3Bu, 0x082EFA98u },
    { UINT64_C(0x89ABCDEF01234567), UINT64_C(0x76543210FEDCBA98), 0x524F5554u, 0x0665u, 0x6Bu, 0x19u, 0x7F4A7C15u, 0xBB67AE85u },
    { UINT64_C(0x55AA33CC77EE1188), UINT64_C(0xCAFED00D0BADBEEF), 0x54414733u, 0x0776u, 0x7Du, 0x1Du, 0xB5297A4Du, 0x3C6EF372u },
    { UINT64_C(0xDEC0AD0B12345678), UINT64_C(0x31415926A5A5C3C3), 0x4C414E45u, 0x0887u, 0x8Fu, 0x21u, 0x31415927u, 0x1F83D9ABu },
    { UINT64_C(0x4E3D2C1B0A998877), UINT64_C(0x0123456789ABCDE0), 0x44534348u, 0x0998u, 0x91u, 0x07u, 0xC3A5C85Cu, 0x5BE0CD19u },
    { UINT64_C(0x93A4B5C6D7E8F901), UINT64_C(0xA1B2C3D4E5F60718), 0x564D4C31u, 0x0AA9u, 0xA3u, 0x17u, 0x9E3779B9u, 0xCBBB9D5Du },
    { UINT64_C(0x1029384756AABBCC), UINT64_C(0x55AA55AA77889900), 0x48564452u, 0x0BBAu, 0xB5u, 0x0Bu, 0xA5C31F27u, 0x6A09E667u },
    { UINT64_C(0xC1D2E3F405162738), UINT64_C(0x0F1E2D3C4B5A6978), 0x44494358u, 0x0CCBu, 0xC7u, 0x13u, 0x0F1055A1u, 0x510E527Fu },
};

typedef struct {
    const void *target;
    uint64_t bias;
    uint32_t salt;
    uint32_t rotate;
    uint32_t class_tag;
    uint32_t stride_tag;
} cprisk_vm_dispatch_bait_meta_t;

#if defined(__APPLE__)
__attribute__((used, section("__DATA_CONST,__const")))
#endif
// 诱饵 handler 元数据：把真实函数地址与 bias/salt/rotate/class tag 绑定，让这些函数体
// 在最终二进制中保持“活”的形态；元数据只用于派生混淆 seed，不改变 VM 语义。
static const cprisk_vm_dispatch_bait_meta_t cprisk_vm_dispatch_bait_meta_i[] = {
    { (const void *)&cprisk_vm_m3_dead_bait_xor_i, UINT64_C(0x6A09E667F3BCC909), 0x9E3779B9u, 5u, 0x22010031u, 0x00100020u },
    { (const void *)&cprisk_vm_m3_dead_bait_add_i, UINT64_C(0xBB67AE8584CAA73B), 0x85EBCA6Bu, 11u, 0x22020042u, 0x00180028u },
    { (const void *)&cprisk_vm_m3_dead_bait_roll_i, UINT64_C(0x3C6EF372FE94F82B), 0xC2B2AE35u, 17u, 0x22030053u, 0x00200030u },
    { (const void *)&cprisk_vm_m3_dead_heavy_shadow_i, UINT64_C(0xA54FF53A5F1D36F1), 0x27D4EB2Du, 23u, 0x23010074u, 0x00280038u },
    { (const void *)&cprisk_vm_m3_dead_dispatch_i, UINT64_C(0x510E527FADE682D1), 0x165667B1u, 3u, 0x23020085u, 0x00300040u },
    { (const void *)&cprisk_vm_dispatch_lookup, UINT64_C(0x1F83D9ABFB41BD6B), 0x7F4A7C15u, 9u, 0x24010096u, 0x00380048u },
    { (const void *)&cprisk_vm_interp_loop_a, UINT64_C(0x5BE0CD19137E2179), 0x045D9F3Bu, 15u, 0x240200A7u, 0x00400050u },
    { (const void *)&cprisk_vm_execute, UINT64_C(0xCBBB9D5DC1059ED8), 0x6D2B79F5u, 21u, 0x250100B8u, 0x00480058u },
};

#if defined(__APPLE__)
__attribute__((used, section("__DATA_CONST,__const")))
#endif
// 辅助诱饵集：额外的 entry/execute 变体，扩大可疑“分发表”的候选面。
static const cprisk_vm_dispatch_bait_meta_t cprisk_vm_dispatch_bait_aux_meta_i[] = {
    { (const void *)&cprisk_vm_entry, UINT64_C(0x243F6A8885A308D3), 0x31415927u, 7u, 0x31010011u, 0x00080018u },
    { (const void *)&cprisk_vm_entry_alt1, UINT64_C(0x13198A2E03707344), 0x27182818u, 13u, 0x31020022u, 0x00100020u },
    { (const void *)&cprisk_vm_entry_alt2, UINT64_C(0xA4093822299F31D0), 0xB5297A4Du, 19u, 0x31030033u, 0x00180028u },
    { (const void *)&cprisk_vm_execute, UINT64_C(0x082EFA98EC4E6C89), 0xC3A5C85Cu, 25u, 0x32010044u, 0x00200030u },
};

#if defined(__APPLE__)
__attribute__((used, section("__DATA_CONST,__const")))
#endif
// lane 诱饵集：包含三个 lane 的 prepare/finish/loop 变体，诱导分析者误判真正入口。
static const cprisk_vm_dispatch_bait_meta_t cprisk_vm_dispatch_bait_lane_meta_i[] = {
    { (const void *)&cprisk_vm_execute_lane0_i, UINT64_C(0x0D6D0185A8B3C4D7), 0x4CF5AD43u, 6u, 0x41010051u, 0x00200060u },
    { (const void *)&cprisk_vm_execute_lane1_i, UINT64_C(0x1F2E3D4C5B6A7988), 0x9B9773E1u, 10u, 0x41020062u, 0x00280068u },
    { (const void *)&cprisk_vm_execute_lane2_i, UINT64_C(0x2233445566778899), 0x6A5D39C7u, 14u, 0x41030073u, 0x00300070u },
    { (const void *)&cprisk_vm_run_program_lane0_i, UINT64_C(0x33445566778899AA), 0xA54FC2D9u, 18u, 0x42010084u, 0x00380078u },
    { (const void *)&cprisk_vm_run_program_lane1_i, UINT64_C(0x445566778899AABB), 0x1B873593u, 22u, 0x42020095u, 0x00400080u },
    { (const void *)&cprisk_vm_run_program_lane2_i, UINT64_C(0x5566778899AABBCC), 0x7F4A7C15u, 26u, 0x420300A6u, 0x00480088u },
    { (const void *)&cprisk_vm_interp_finish_run_lane0_i, UINT64_C(0x3F84D5B5B5470917), 0x19D7A4E3u, 5u, 0x430100B7u, 0x00500090u },
    { (const void *)&cprisk_vm_interp_finish_run_lane1_i, UINT64_C(0x9216D5D98979FB1B), 0x2C1B3D97u, 11u, 0x430200C8u, 0x00580098u },
    { (const void *)&cprisk_vm_interp_finish_run_lane2_i, UINT64_C(0xD1310BA698DFB5AC), 0x5F43E291u, 17u, 0x430300D9u, 0x006000A0u },
    { (const void *)&cprisk_vm_interp_loop_b, UINT64_C(0x66778899AABBCCDD), 0x045D9F3Bu, 30u, 0x440100EAu, 0x006800A8u },
    { (const void *)&cprisk_vm_dispatch_oph_materialized_i, UINT64_C(0x778899AABBCCDDEE), 0x85EBCA6Bu, 4u, 0x440200FBu, 0x007000B0u },
};

// 把一张诱饵元数据表压成 32 位混合值；target 地址也参与，但输出只用作 opaque seed。
static uint32_t cprisk_vm_dispatch_bait_meta_mix_i(const cprisk_vm_dispatch_bait_meta_t *meta,
                                                   size_t count,
                                                   uint32_t basis) {
    uint32_t acc = basis;
    for (size_t i = 0u; i < count; i++) {
        uint64_t x =
            ((uint64_t)(uintptr_t)meta[i].target ^ meta[i].bias) ^
            ((uint64_t)meta[i].salt << ((meta[i].rotate & 15u) + 1u)) ^
            ((uint64_t)meta[i].rotate << 48u) ^
            ((uint64_t)meta[i].class_tag << 7u) ^
            ((uint64_t)meta[i].stride_tag << 19u);
        acc ^= cprisk_vmp_avalanche32_i(
            (uint32_t)x ^
            (uint32_t)(x >> 32u) ^
            meta[i].class_tag ^
            cprisk_vmp_rotl32_i(meta[i].stride_tag, meta[i].rotate & 31u) ^
            ((uint32_t)i * 0x9E3779B9u)
        );
    }
    return cprisk_vmp_avalanche32_i(acc ^ (uint32_t)count * 0x27D4EB2Du);
}

// 汇总 relro 诱饵与三张诱饵元数据表的混合值；结果进入 opaque 状态，绝不影响 acc 语义。
static uint32_t cprisk_vmp_relro_bait_mix_i(void) {
    uint32_t acc = 0u;
    for (size_t i = 0u; i < sizeof(cprisk_vmp_relro_handler_decoy) / sizeof(cprisk_vmp_relro_handler_decoy[0]); i++) {
        const uint64_t sx = cprisk_vmp_relro_handler_decoy[i].stream_xor;
        uint32_t lo = (uint32_t)sx;
        uint32_t hi = (uint32_t)(sx >> 32);
        uint64_t w = cprisk_vmp_relro_handler_decoy[i].faux_text_rva
            ^ ((uint64_t)cprisk_vmp_rotl32_i(lo, 8u) | ((uint64_t)cprisk_vmp_rotr32_i(hi, 9u) << 32u))
            ^ ((uint64_t)cprisk_vmp_relro_handler_decoy[i].dispatch_slot << 17u)
            ^ ((uint64_t)cprisk_vmp_relro_handler_decoy[i].lane_tag << 49u)
            ^ ((uint64_t)cprisk_vmp_relro_handler_decoy[i].span_tag << 43u);
        acc ^= cprisk_vmp_avalanche32_i(
            (uint32_t)w ^
            cprisk_vmp_relro_handler_decoy[i].class_tag ^
            cprisk_vmp_relro_handler_decoy[i].bind_mix ^
            cprisk_vmp_rotl32_i(
                cprisk_vmp_relro_handler_decoy[i].key_mix,
                (cprisk_vmp_relro_handler_decoy[i].lane_tag & 7u) + 1u
            ) ^
            ((uint32_t)i * 0x9E37u)
        );
        acc = cprisk_vmp_rotl32_i(
            acc ^ cprisk_vmp_relro_handler_decoy[i].bind_mix ^ cprisk_vmp_relro_handler_decoy[i].key_mix,
            (cprisk_vmp_relro_handler_decoy[i].span_tag & 7u) + 1u
        );
    }
    acc ^= cprisk_vm_dispatch_bait_meta_mix_i(
        cprisk_vm_dispatch_bait_meta_i,
        sizeof(cprisk_vm_dispatch_bait_meta_i) / sizeof(cprisk_vm_dispatch_bait_meta_i[0]),
        0x6D2B79F5u
    );
    acc ^= cprisk_vm_dispatch_bait_meta_mix_i(
        cprisk_vm_dispatch_bait_aux_meta_i,
        sizeof(cprisk_vm_dispatch_bait_aux_meta_i) / sizeof(cprisk_vm_dispatch_bait_aux_meta_i[0]),
        0xA511E9B3u
    );
    acc ^= cprisk_vm_dispatch_bait_meta_mix_i(
        cprisk_vm_dispatch_bait_lane_meta_i,
        sizeof(cprisk_vm_dispatch_bait_lane_meta_i) / sizeof(cprisk_vm_dispatch_bait_lane_meta_i[0]),
        0x31415927u
    );
    return cprisk_vmp_avalanche32_i(acc ^ 0xC3EF4D27u);
}

// 根据 opkind 选择并执行一组诱饵 handler；仅在死分支调用，用于制造伪 handler 轨迹。
static void cprisk_vm_m3_dead_dispatch_i(uint8_t acc[32], uint32_t hdr_reserved, uint32_t opkind) {
    uint32_t dseed = (hdr_reserved >> 16) & 0xFFu;
    switch (opkind % 6u) {
    case 0u:
        cprisk_vm_m3_dead_bait_xor_i(acc, dseed, opkind);
        break;
    case 1u:
        cprisk_vm_m3_dead_bait_add_i(acc, dseed, opkind);
        break;
    case 2u:
        cprisk_vm_m3_dead_bait_roll_i(acc, dseed);
        break;
    case 3u:
        cprisk_vm_m3_dead_bait_xor_i(acc, dseed ^ 0x55u, opkind + 0x11u);
        cprisk_vm_m3_dead_bait_roll_i(acc, dseed ^ 0xA5u);
        break;
    case 4u:
        cprisk_vm_m3_dead_bait_add_i(acc, dseed ^ 0x3Cu, opkind + 0x29u);
        cprisk_vm_m3_dead_bait_xor_i(acc, dseed ^ 0xC3u, opkind + 0x41u);
        break;
    default:
        cprisk_vm_m3_dead_heavy_shadow_i(acc, dseed ^ (opkind * 0x27D4EB2Du));
        cprisk_vm_m3_dead_bait_roll_i(acc, dseed ^ 0x5Au);
        break;
    }
}

// 由 lane/logical 选择诱饵表项并混合成 32 位 seed。仅服务于 opaque/relro 状态与自检布局，
// 不参与任何 PC/acc 语义；不同 lane/op 得到不同 seed，避免被单一常量指纹识别。
static uint32_t cprisk_vm_dispatch_bait_seed_i(uint32_t lane, uint32_t logical) {
    const cprisk_vm_dispatch_bait_meta_t *meta =
        &cprisk_vm_dispatch_bait_meta_i[
            (lane ^ logical) % (sizeof(cprisk_vm_dispatch_bait_meta_i) / sizeof(cprisk_vm_dispatch_bait_meta_i[0]))
        ];
    const cprisk_vm_dispatch_bait_meta_t *aux =
        &cprisk_vm_dispatch_bait_aux_meta_i[
            (cprisk_vmp_rotl32_i(lane, 3u) ^ logical ^ (lane >> 1u))
            % (sizeof(cprisk_vm_dispatch_bait_aux_meta_i) / sizeof(cprisk_vm_dispatch_bait_aux_meta_i[0]))
        ];
    const cprisk_vm_dispatch_bait_meta_t *lane_meta =
        &cprisk_vm_dispatch_bait_lane_meta_i[
            (cprisk_vmp_rotr32_i(logical, 1u) ^ (lane * 7u) ^ (logical >> 2u))
            % (sizeof(cprisk_vm_dispatch_bait_lane_meta_i) / sizeof(cprisk_vm_dispatch_bait_lane_meta_i[0]))
        ];
    const size_t rel_idx =
        ((size_t)lane * 5u + (size_t)logical * 3u)
        % (sizeof(cprisk_vmp_relro_handler_decoy) / sizeof(cprisk_vmp_relro_handler_decoy[0]));
    uint64_t x =
        ((uint64_t)(uintptr_t)meta->target ^ meta->bias) ^
        ((uint64_t)meta->salt << 32u) ^
        ((uint64_t)meta->rotate << 11u) ^
        ((uint64_t)meta->class_tag << 17u) ^
        ((uint64_t)meta->stride_tag << 29u);
    uint64_t y =
        ((uint64_t)(uintptr_t)aux->target ^ aux->bias) ^
        ((uint64_t)aux->salt << 29u) ^
        ((uint64_t)aux->rotate << 7u) ^
        ((uint64_t)aux->class_tag << 15u) ^
        ((uint64_t)aux->stride_tag << 23u);
    uint64_t w =
        ((uint64_t)(uintptr_t)lane_meta->target ^ lane_meta->bias) ^
        ((uint64_t)lane_meta->salt << 27u) ^
        ((uint64_t)lane_meta->rotate << 19u) ^
        ((uint64_t)lane_meta->class_tag << 9u) ^
        ((uint64_t)lane_meta->stride_tag << 37u);
    uint64_t z =
        cprisk_vmp_relro_handler_decoy[rel_idx].faux_text_rva ^
        cprisk_vmp_relro_handler_decoy[rel_idx].stream_xor ^
        ((uint64_t)cprisk_vmp_relro_handler_decoy[rel_idx].class_tag << 17u) ^
        ((uint64_t)cprisk_vmp_relro_handler_decoy[rel_idx].dispatch_slot << 41u) ^
        ((uint64_t)cprisk_vmp_relro_handler_decoy[rel_idx].lane_tag << 57u) ^
        ((uint64_t)cprisk_vmp_relro_handler_decoy[rel_idx].bind_mix << 3u) ^
        ((uint64_t)cprisk_vmp_relro_handler_decoy[rel_idx].key_mix << 27u);
    x ^= y ^ z ^ w;
    x ^= x >> (meta->rotate & 31u);
    x ^= y >> (aux->rotate & 31u);
    x ^= w >> (lane_meta->rotate & 31u);
    return cprisk_vmp_avalanche32_i((uint32_t)x ^ (uint32_t)(x >> 32u));
}

// 定位 dispatch 类别表：V1 紧跟头部；V2 头部后还有 8 字节 keystream 种子，需要跳过。
static const uint8_t *cprisk_vmp_dispatch_class_table_ptr_i(const uint8_t *d_sec,
                                                            const cprisk_vmp_dispatch_header_t *dh) {
    if (!d_sec || !dh)
        return NULL;
    if (dh->version == CPRISK_VMP_DISPATCH_V2)
        return d_sec + sizeof(cprisk_vmp_dispatch_header_t) + CPRISK_VMP_DISPATCH_SEED_BYTES;
    return d_sec + sizeof(cprisk_vmp_dispatch_header_t);
}

/* P0: one-shot keystream for dispatch v2 (build-time seed parity with VMBytecodeEmitter.dispatchKeystreamBytes). */
// V2 类别表的一次性 keystream（构建期与 injector 对齐的产物）。当前运行期实际走
// fill_cache 内的增量实现；本函数保留用于 ABI/测试对照，标 unused 以免被误用。
static void __attribute__((unused)) cprisk_vmp_dispatch_v2_keystream_i(uint64_t seed,
                                               uint8_t ks_out[CPRISK_VMP_CLASS_TABLE_BYTES]) {
    uint64_t state = seed ^ 0x4D4456544B455953ULL; /* "MDVTKEYS" */
    if (state == 0u)
        state = 0xDEADBEEFCAFEBABEULL;
    for (size_t i = 0; i < CPRISK_VMP_CLASS_TABLE_BYTES; i++)
        ks_out[i] = (uint8_t)cprisk_splitmix64_next_i(&state);
}

// 仅当 dispatch 版本为 V2 且置 CLASS_TABLE_KEYSTREAM 时返回表后 8 字节种子；否则返回 0，
// 表示类别表按明文（V1）处理。
static uint64_t cprisk_vmp_dispatch_keystream_seed_i(const uint8_t *d_sec,
                                                     const cprisk_vmp_dispatch_header_t *dh) {
    if (!d_sec || !dh)
        return 0u;
    if (dh->version != CPRISK_VMP_DISPATCH_V2
        || (dh->flags & CPRISK_VMP_DH_FLAG_CLASS_TABLE_KEYSTREAM) == 0u) {
        return 0u;
    }
    return cprisk_read_le_u64_i(d_sec + sizeof(cprisk_vmp_dispatch_header_t));
}

// 解码故障注入：fault_mask == 0 是“无故障”哨兵，直接返回 0（异或后不改变数据）。
// 非零时用 SplitMix64 派生一个字节，逐指令扰动 opcode/imm，使补丁与单步执行难以对齐语义。
static uint8_t cprisk_vmp_dispatch_fault_byte_i(uint64_t fault_mask,
                                                uint64_t func_id,
                                                uint32_t pc_index,
                                                uint32_t op) {
    if (fault_mask == 0u)
        return 0u;
    uint64_t state =
        fault_mask ^
        func_id ^
        ((uint64_t)pc_index << 17u) ^
        ((uint64_t)op << 33u) ^
        0x4453504641554C54ULL; /* "DSPFAULT" */
    return (uint8_t)cprisk_splitmix64_next_i(&state);
}

// opcode 域的故障字节：先混入域常量再委托 dispatch_fault_byte，保持 0 哨兵语义不变。
static uint8_t cprisk_vmp_opcode_fault_byte_i(uint64_t fault_mask,
                                              uint64_t func_id,
                                              uint32_t pc_index,
                                              uint8_t op_raw) {
    /* Preserve the no-fault sentinel before mixing in the opcode domain. */
    if (fault_mask == 0u)
        return 0u;
    return cprisk_vmp_dispatch_fault_byte_i(
        fault_mask ^ 0x4F50434F4445464AULL, /* "OPCODEFJ" */
        func_id,
        pc_index,
        (uint32_t)op_raw
    );
}

// immediate 域的 64 位故障掩码；同样保留 0 哨兵。
static uint64_t cprisk_vmp_imm_fault_mask_u64_i(uint64_t fault_mask,
                                                uint64_t func_id,
                                                uint32_t pc_index) {
    if (fault_mask == 0u)
        return 0u;
    uint64_t state =
        fault_mask ^
        func_id ^
        ((uint64_t)pc_index << 23u) ^
        0x494D4D4641554C54ULL; /* "IMMFAULT" */
    return cprisk_splitmix64_next_i(&state);
}

/* P1: per-instruction immediate mask (bytecode v3 parity with VMBytecodeEmitter.immediateXorMask). */
// V3 每指令 immediate 的 XOR keystream，与构建期 emitter 的 immediateXorMask 对齐。
// 状态为 0 时替换成固定非零值，避免 SplitMix 退化。
static uint64_t cprisk_vmp_imm_mask_u64_i(uint64_t func_id,
                                          uint32_t pc_index,
                                          uint64_t seed_root) {
    uint64_t state = func_id ^ (uint64_t)pc_index ^ seed_root ^ 0x494D4D584F523152ULL; /* "IMMXOR1R" */
    if (state == 0u)
        state = 0xDEADBEEFCAFEBABEULL;
    return cprisk_splitmix64_next_i(&state);
}

/* P1: wire opcode byte XOR (build/runtime parity with VMBytecodeEmitter.opcodeMixByte). */
// V3 每指令 opcode 字节的 XOR 掩码，与 emitter 的 opcodeMixByte 对齐。
static uint8_t cprisk_vmp_opcode_mix_byte_i(uint64_t func_id, uint32_t pc_index, uint64_t opcode_seed_root) {
    uint64_t state = func_id ^ (uint64_t)pc_index ^ opcode_seed_root ^ 0x4F50434D49583152ULL; /* "OPCMIX1R" */
    if (state == 0u)
        state = 0xDEADBEEFCAFEBABEULL;
    return (uint8_t)cprisk_splitmix64_next_i(&state);
}

/* Extra immediate scrub for rawRegion when dispatch marks opaque VPC category (paired with emitter). */
// RAW_REGION 的附加 lane 掩码（当 dispatch 标记 opaque VPC 类别时与 emitter 配对），
// 作为绑定根参与混淆；不改变 acc 语义。
uint64_t cprisk_vmp_raw_lane_mask_u64_i(uint64_t func_id, uint32_t pc_index, uint64_t bind_root) {
    uint64_t state = func_id ^ (uint64_t)pc_index ^ bind_root ^ 0x5241574C4E4D3130ULL; /* "RAWLNM10" */
    if (state == 0u)
        state = 0xDECAFBAD0BADF00DULL;
    return cprisk_splitmix64_next_i(&state);
}

// 自检失败时的 acc 污染：用 func_id 与字节位置派生噪声，保证失败结果不会与正常输出混淆。
static void cprisk_vm_self_fail_acc_i(uint8_t acc[32], uint64_t func_id) {
    for (unsigned i = 0; i < 32u; i++) {
        uint8_t b = (uint8_t)(0xC3u ^ (unsigned)(func_id >> (i & 15u)) ^ (i * 0x1Du));
        acc[i] ^= b;
    }
}

// 解析编译期常量或 __DATA 中的 CPSF（FNV 期望）blob；都不存在时返回 0（表示无期望）。
static uint32_t cprisk_vm_m3_self_expect_resolve_i(const struct mach_header_64 *mh) {
#if CPRISK_VM_M3_SELF_EXPECT != 0u
    (void)mh;
    return CPRISK_VM_M3_SELF_EXPECT;
#else
    unsigned long sz = 0;
    const uint8_t *p =
        cprisk_find_section(mh, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_VMP_SELF_EXPECT, &sz);
    if (p && sz >= 8u) {
        uint32_t mg = cprisk_read_le_u32_i(p);
        uint32_t fnv = cprisk_read_le_u32_i(p + 4u);
        if (mg == CPRISK_VMP_SELF_EXPECT_MAGIC)
            return fnv;
    }
    return 0u;
#endif
}

// 解析 CPSH（MAC 期望）blob：在段内前 128 字节按 4 字节步长搜索 magic；找不到返回 0。
static uint32_t cprisk_vm_m3_self_expect_mac_resolve_i(const struct mach_header_64 *mh) {
#if CPRISK_VM_M3_SELF_EXPECT != 0u
    (void)mh;
    return 0u;
#else
    unsigned long sz = 0;
    const uint8_t *p =
        cprisk_find_section(mh, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_VMP_SELF_EXPECT, &sz);
    if (!p || sz < 8u)
        return 0u;
    for (size_t o = 0; o + 8 <= sz && o < 128; o += 4) {
        uint32_t mg = cprisk_read_le_u32_i(p + o);
        if (mg == CPRISK_VMP_SELF_EXPECT_MAGIC_MAC)
            return cprisk_read_le_u32_i(p + o + 4u);
    }
    return 0u;
#endif
}

// 自检 MAC 的 KDF：SHA256(runtime_material || label)，label 以 XOR 0x5A 存盘。
// 不绑定 session key，因为构建期 CPSH 期望是固定的；绑定会话会导致每次运行都失败。
static void cprisk_vm_selfchk_mac_key_i(const uint8_t runtime_mat[32], uint8_t key_out[32]) {
    /*
     * KDF: SHA256( runtime_mat || decode(label) )
     * Label bytes are XOR-mixed at rest (no plaintext "CPRISK..." in .text/.rodata).
     * The build-time CPSH expectation is immutable, so binding this KDF to a
     * future session key made every active-session check fail by construction.
     */
    static const uint8_t cprisk_vm_selfchk_lbl_enc[18] = {
        0x19u, 0x0au, 0x08u, 0x13u, 0x09u, 0x11u, 0x05u, 0x0cu, 0x17u, 0x05u, 0x17u, 0x69u,
        0x05u, 0x12u, 0x17u, 0x1bu, 0x19u, 0x5au,
    };
    uint8_t buf[50];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, runtime_mat, 32u);
    for (size_t i = 0; i < sizeof(cprisk_vm_selfchk_lbl_enc); i++)
        buf[32u + i] = cprisk_vm_selfchk_lbl_enc[i] ^ 0x5Au;
    cprisk_sha256(buf, sizeof(buf), key_out);
    cprisk_secure_zero(buf, sizeof(buf));
}

// 自检失败的故障掩码：混入 func_id/头部/期望/实测 + runtime material + session_mix，
// 保证非零并作为后续 decode 的 fault 输入（0 表示无故障，必须避免）。
static uint64_t cprisk_vm_selfchk_fault_mask_i(uint64_t func_id,
                                               uint32_t hdr_reserved,
                                               uint32_t expected_tag,
                                               uint32_t observed_tag) {
    uint64_t state =
        func_id ^
        ((uint64_t)hdr_reserved << 19u) ^
        ((uint64_t)expected_tag << 32u) ^
        (uint64_t)observed_tag ^
        0x53454C464641554CULL; /* "SELFFAUL" */
    if (cprisk_runtime_material_ready() != 0) {
        uint8_t runtime_material[CPRISK_ARMOR_KEY_SIZE];
        if (cprisk_get_runtime_material(runtime_material) == 0) {
            state ^= cprisk_read_le_u64_i(runtime_material + 0u);
            state ^= cprisk_read_le_u64_i(runtime_material + 16u);
            cprisk_secure_zero(runtime_material, sizeof(runtime_material));
        }
    }
    state ^= (uint64_t)cprisk_vm_session_mix_i() << 7u;
    state = cprisk_splitmix64_next_i(&state);
    if (state == 0u)
        state = 0xD9E57B1C4A62F30DULL;
    return state;
}

#if CPRISK_VM_THREADED_DISPATCH
// 线程化分发的 CPSV v2 运行时实现：包含 cpsv2 观测/期望解析与 lane 线程调度。
#include "cprisk_vm_cpsv2_runtime.inc"
#endif

// M3 入口自检：
// - 线程化构建：无条件要求 CPSV2 段与期望值一致，不做 v1/FNV 回退；
// - 传统构建：仅当字节码置 M3_SELFCHK 时执行，可选用 MAC 或 FNV。
// 成功时写 seal_mix（>0）；失败时置 SELF_INTEGRITY|BYTECODE、污染 acc 并写非零 fault_mask。
// out_fault_mask/out_seal_mix 允许为 NULL；两者都非 NULL 时才同步失败 seal。
static void cprisk_vm_m3_selfchk_run_i(const struct mach_header_64 *hdr,
                                       uint8_t acc[32],
                                       uint64_t func_id,
                                       const cprisk_vmp_bytecode_header_t *bh,
                                       cprisk_vm_run_result_t *out,
                                       uint64_t *out_fault_mask,
                                       uint64_t *out_seal_mix) {
    const int want = (bh->reserved & CPRISK_VMP_BC_FLAG_M3_SELFCHK) != 0u;
    if (out_fault_mask)
        *out_fault_mask = 0u;
    if (out_seal_mix)
        *out_seal_mix = 0u;
#if CPRISK_VM_THREADED_DISPATCH
    /* A threaded build always requires v2 plus keyed expectation, even when the
     * bytecode's optional M3 flags are absent. No v1/unhashed fallback. */
    uint32_t observed = 0u;
    const uint32_t expected = cprisk_vm_cpsv2_expect_resolve_i(hdr);
    if (!cprisk_vm_cpsv2_observe_i(hdr, &observed) || !expected || observed != expected) {
        out->poison_flags |= CPRISK_VM_POISON_SELF_INTEGRITY | CPRISK_VM_POISON_BYTECODE;
        cprisk_vm_self_fail_acc_i(acc, func_id);
        if (out_fault_mask)
            *out_fault_mask = cprisk_vm_selfchk_fault_mask_i(func_id, bh->reserved, expected, observed);
        if (out_seal_mix && out_fault_mask) *out_seal_mix = *out_fault_mask;
    } else if (out_seal_mix) {
        *out_seal_mix = cprisk_vm_m3_seal_mix_from_digest_u32_i(observed);
    }
    return;
#endif
    if (!want)
        return;

#if defined(__APPLE__)
    if (hdr != NULL && cprisk_vm_m3_selfchk_cpsv_image_matches_static_i(hdr) != 0) {
        out->poison_flags |= CPRISK_VM_POISON_SELF_INTEGRITY | CPRISK_VM_POISON_BYTECODE;
        cprisk_vm_self_fail_acc_i(acc, func_id);
        if (out_fault_mask)
            *out_fault_mask = cprisk_vm_selfchk_fault_mask_i(func_id, bh->reserved, 0u, 0u);
        if (out_seal_mix && out_fault_mask)
            *out_seal_mix = *out_fault_mask;
        return;
    }
#endif

    const uint32_t exp_fnv = cprisk_vm_m3_self_expect_resolve_i(hdr);
    const uint32_t exp_mac = cprisk_vm_m3_self_expect_mac_resolve_i(hdr);
#if CPRISK_VM_SELFCHK_FORCE_LEGACY_FNV
    const int use_mac = 0;
#else
    const int explicit_mac = (bh->reserved & CPRISK_VMP_BC_FLAG_M3_SELFCHK_MAC) != 0u;
    const int implicit_mac =
        (CPRISK_VM_SELFCHK_PREFER_MAC_WHEN_AMBIGUOUS != 0) && exp_mac != 0u && exp_fnv == 0u;
    const int use_mac = explicit_mac || implicit_mac;
#endif

    if (use_mac) {
        uint8_t rt[32];
        cprisk_get_runtime_material(rt);
        uint8_t hk[32];
        cprisk_vm_selfchk_mac_key_i(rt, hk);
        uint8_t full[32];
        uint8_t msg[CPRISK_VM_M3_SELF_BYTES];
        cprisk_vm_selfchk_collect_msg_i(hdr, msg);
        cprisk_mac_sha256(hk, 32u, msg, sizeof(msg), full);
        cprisk_secure_zero(hk, sizeof(hk));
        uint32_t tag32 = cprisk_read_le_u32_i(full);
        cprisk_secure_zero(full, sizeof(full));
        if (exp_mac == 0u) {
#if CPRISK_VM_SELFCHK_POLICY >= 1
            out->poison_flags |= CPRISK_VM_POISON_SELF_INTEGRITY | CPRISK_VM_POISON_BYTECODE;
            cprisk_vm_self_fail_acc_i(acc, func_id);
            if (out_fault_mask)
                *out_fault_mask = cprisk_vm_selfchk_fault_mask_i(func_id, bh->reserved, exp_mac, tag32);
            if (out_seal_mix && out_fault_mask)
                *out_seal_mix = *out_fault_mask;
#endif
        } else if (tag32 != exp_mac) {
            out->poison_flags |= CPRISK_VM_POISON_SELF_INTEGRITY | CPRISK_VM_POISON_BYTECODE;
            cprisk_vm_self_fail_acc_i(acc, func_id);
            if (out_fault_mask)
                *out_fault_mask = cprisk_vm_selfchk_fault_mask_i(func_id, bh->reserved, exp_mac, tag32);
            if (out_seal_mix && out_fault_mask)
                *out_seal_mix = *out_fault_mask;
        } else {
            if (out_seal_mix)
                *out_seal_mix = cprisk_vm_m3_seal_mix_from_digest_u32_i(tag32);
        }
        return;
    }

    if (exp_fnv == 0u) {
#if CPRISK_VM_SELFCHK_POLICY >= 1
        out->poison_flags |= CPRISK_VM_POISON_SELF_INTEGRITY | CPRISK_VM_POISON_BYTECODE;
        cprisk_vm_self_fail_acc_i(acc, func_id);
        if (out_fault_mask)
            *out_fault_mask = cprisk_vm_selfchk_fault_mask_i(func_id, bh->reserved, exp_fnv, 0u);
        if (out_seal_mix && out_fault_mask)
            *out_seal_mix = *out_fault_mask;
#else
        /* Legacy: flag without golden/section → no-op (pipelines may opt into policy >= 1). */
#endif
    } else {
        uint32_t fnv = cprisk_vm_selfchk_observed_fnv_i(hdr);
        if (fnv != exp_fnv) {
            out->poison_flags |= CPRISK_VM_POISON_SELF_INTEGRITY | CPRISK_VM_POISON_BYTECODE;
            cprisk_vm_self_fail_acc_i(acc, func_id);
            if (out_fault_mask)
                *out_fault_mask = cprisk_vm_selfchk_fault_mask_i(func_id, bh->reserved, exp_fnv, fnv);
            if (out_seal_mix && out_fault_mask)
                *out_seal_mix = *out_fault_mask;
        } else {
            if (out_seal_mix)
                *out_seal_mix = cprisk_vm_m3_seal_mix_from_digest_u32_i(fnv);
        }
    }
}

// 失败/提前返回路径的收尾：把当前 acc 复制到结果、清空 aux，并跑一次 domain-5 白盒变换。
// 白盒返回非 0 时保留原 acc，只记录 rc；返回 0 时用变换结果替换 acc。
static void cprisk_vm_wb_finalize_i(cprisk_vm_run_result_t *out, uint8_t acc[32]) {
    memcpy(out->acc, acc, sizeof(out->acc));
    memset(out->acc_aux, 0, sizeof(out->acc_aux));
    uint8_t wb_out[32];
    int wbr = cprisk_whitebox_evaluate_domain(5u, out->acc, wb_out);
    out->whitebox_domain_rc = wbr;
    if (wbr == 0)
        memcpy(out->acc, wb_out, sizeof(wb_out));
}

// 主循环标记函数：noinline + volatile，仅用于在二进制中形成稳定、可被自检窗口覆盖的
// 代码形状，不参与语义。三个 lane 各调用一个，以拉开控制流布局。
__attribute__((noinline)) static void cprisk_vm_interp_core_marker0_i(void) {
    volatile uint32_t q = 0xC0u;
    q ^= (q << 3);
    (void)q;
}

// 标记函数 1：与 marker0 同职责，换一组常数以形成不同代码形状。
__attribute__((noinline)) static void cprisk_vm_interp_core_marker1_i(void) {
    volatile uint32_t q = 0xC1u;
    q = (q * 7u) ^ 0x9E3779B9u;
    (void)q;
}

// 标记函数 2：与 marker0 同职责，换一组运算以形成不同代码形状。
__attribute__((noinline)) static void cprisk_vm_interp_core_marker2_i(void) {
    volatile uint32_t q = 0xC2u;
    q |= (q >> 1);
    (void)q;
}

// 反符号执行副作用：用 session/func/imm/pc/steps 派生状态，改写 trace_shadow/trace_scratch
// 与 vregs，但最后恢复 acc 与 vregs 的原值 —— 对语义状态是恒等变换，只留下难以切片的轨迹。
// 仅在 m3_dead 或 anti_symbolic_heavy 时调用。
static void cprisk_vm_trace_sidefx_i(cprisk_vm_interp_frame_t *fr,
                                     uint32_t logical,
                                     uint64_t imm,
                                     uint32_t pc,
                                     uint32_t hvar) {
    if (!fr) {
        return;
    }

    uint64_t state =
        fr->func_id ^
        imm ^
        ((uint64_t)logical << 40u) ^
        ((uint64_t)pc << 12u) ^
        fr->steps ^
        (uint64_t)fr->session_mix;
    const uint32_t base = (pc + hvar + (uint32_t)fr->steps) & 31u;
    const uint32_t vreg_idx = (logical ^ hvar ^ fr->session_mix) & 7u;
    uint8_t snapshot[8];
    for (uint32_t i = 0u; i < 8u; i++) {
        snapshot[i] = fr->acc[(base + i) & 31u];
    }
    const uint64_t vreg_orig = fr->vregs[vreg_idx];

    for (uint32_t i = 0u; i < 8u; i++) {
        state = cprisk_splitmix64_next_i(&state);
        const uint32_t lane = (base + ((i * 5u + hvar) & 7u)) & 31u;
        fr->acc[lane] = cprisk_vm_xor_equiv_i(
            snapshot[i],
            (uint8_t)state,
            fr->session_mix + logical + hvar + i
        );
        fr->trace_scratch[(pc + logical + i) & 63u] ^=
            (uint8_t)(state >> ((i & 7u) * 8u));
    }

    fr->vregs[vreg_idx] = vreg_orig ^ state ^ ((uint64_t)logical << 48u);
    fr->trace_shadow[(logical + hvar) & 3u] ^=
        fr->vregs[vreg_idx] + ((uint64_t)pc << 17u) + fr->steps;

    for (uint32_t i = 0u; i < 8u; i++) {
        fr->acc[(base + i) & 31u] = snapshot[i];
    }
    fr->vregs[vreg_idx] = vreg_orig;
}

/**
 * Strategy 11/12 history-dependent behavior: accumulate a rolling hash
 * of recent VM operations. This creates state that depends on the ENTIRE
 * execution history, forcing AI to perfectly track all prior steps.
 * The mix feeds back into opaque_chain for deeper path dependence.
 */
// 把最近一次 opcode/pc/hvar/acc 摘要滚入 opaque_chain，使后续 opaque 谓词依赖完整执行历史。
static void cprisk_vm_history_acc_mix_i(cprisk_vm_interp_frame_t *fr, uint32_t pc, uint32_t hvar) {
    if (!fr || !fr->vm_anti_symbolic_heavy)
        return;
    uint32_t h = fr->opaque_chain;
    h ^= pc * 0x9E3779B9u;
    h ^= hvar * 0x517CC1B7u;
    h ^= (uint32_t)fr->steps * 0x45D9F3Bu;
    for (uint32_t i = 0u; i < 32u; i += 8u) {
        h ^= (uint32_t)fr->acc[i];
        h = (h << 5u) | (h >> 27u);
    }
    h = cprisk_vmp_avalanche32_i(h);
    fr->opaque_chain = h;
}

/**
 * CPRISK_VMP_BC_FLAG_ANTI_SYMBOLIC_HEAVY: drive extra control-flow / work only on trace shadow state.
 * Bytecode hash (when enabled) or raw_bind_root mixes into the fork id so symbolic tools see
 * opaque predicates; self-inverse XOR keeps semantics out of \c fr->acc.
 */
// 反符号 fork：派生 0..31 的 fork id，再执行 16 个 trace 变形分支。
// 所有分支只读写 trace_shadow/trace_scratch，不改变 acc/vregs；部分分支成对自消，
// 部分分支留下一次性的伪状态，用于向符号执行器暴露假的中间状态迁移。
static void cprisk_vm_antisy_equiv_fork_i(cprisk_vm_interp_frame_t *fr, uint32_t pc, uint32_t hvar) {
    if (!fr) {
        return;
    }
    uint32_t d = cprisk_vmp_avalanche32_i(
        (uint32_t)fr->func_id ^ (uint32_t)(fr->func_id >> 32u) ^ pc ^ hvar ^ fr->session_mix ^
        (uint32_t)fr->steps ^ fr->opaque_chain ^ 0x4E54B1D5u);
    if (fr->bc_seg_hash_enabled) {
        d ^= cprisk_vmp_avalanche32_i(
            cprisk_read_le_u32_i(fr->bc_seg_hash_expect)
                ^ cprisk_read_le_u32_i(fr->bc_seg_hash_expect + 12u)
                ^ cprisk_read_le_u32_i(fr->bc_seg_hash_expect + 24u));
    } else {
        d ^= cprisk_vmp_avalanche32_i(
            (uint32_t)fr->raw_bind_root ^ (uint32_t)(fr->raw_bind_root >> 32u));
    }
    const uint32_t fork = d & 31u;
    volatile uint64_t scratch =
        ((uint64_t)d << 32) ^ ((uint64_t)fr->opaque_chain << 1) ^ ((uint64_t)pc * 0x9E3779B97F4A7C15ULL);
    const uint32_t rounds = 2u + (d & 5u);
    for (uint32_t r = 0u; r < rounds; r++) {
        uint32_t mix =
            cprisk_vmp_avalanche32_i(d ^ r ^ fr->opaque_chain ^ (uint32_t)fr->steps ^ 0xC001D00Du);
        scratch ^= (uint64_t)mix * 0xD6E8FEB783278F6BULL;
        scratch ^= scratch >> 17;
        scratch *= 0xFF51AFD7ED558CCDULL;
    }
    switch (fork) {
    case 0u:
        fr->trace_shadow[0] ^= scratch;
        fr->trace_shadow[0] ^= scratch;
        break;
    case 1u:
        fr->trace_shadow[1] ^= scratch ^ (uint64_t)fr->func_id;
        fr->trace_shadow[1] ^= scratch ^ (uint64_t)fr->func_id;
        break;
    case 2u:
        for (uint32_t i = 0u; i < 4u; i++) {
            uint64_t v = fr->trace_shadow[i];
            uint64_t m = (uint64_t)cprisk_vmp_avalanche32_i((uint32_t)v ^ (uint32_t)(v >> 32u) ^ d);
            fr->trace_shadow[i] = v ^ m;
            fr->trace_shadow[i] ^= v ^ m;
        }
        break;
    case 3u:
        for (uint32_t i = 0u; i < 64u; i++) {
            uint8_t t = fr->trace_scratch[i];
            uint32_t mx = cprisk_vmp_avalanche32_i(d ^ i ^ (uint32_t)fr->steps);
            fr->trace_scratch[i] = (uint8_t)(t ^ (uint8_t)mx);
            fr->trace_scratch[i] = (uint8_t)(t ^ (uint8_t)mx);
        }
        break;
    case 4u:
        fr->trace_shadow[2] ^= (uint64_t)hvar ^ ((uint64_t)pc << 20);
        fr->trace_shadow[2] ^= (uint64_t)hvar ^ ((uint64_t)pc << 20);
        break;
    case 5u:
        fr->trace_shadow[3] ^= (uint64_t)fr->session_mix + scratch;
        fr->trace_shadow[3] ^= (uint64_t)fr->session_mix + scratch;
        break;
    case 6u:
        for (uint32_t i = 0u; i < 4u; i++) {
            uint64_t v = fr->trace_shadow[i];
            fr->trace_shadow[i] = v ^ (scratch + (uint64_t)i);
            fr->trace_shadow[i] ^= v ^ (scratch + (uint64_t)i);
        }
        break;
    case 7u:
        for (uint32_t i = 0u; i < 32u; i += 4u) {
            uint8_t t = fr->trace_scratch[i];
            fr->trace_scratch[i] = (uint8_t)(t ^ (uint8_t)(d >> (i & 24u)));
            fr->trace_scratch[i] = (uint8_t)(t ^ (uint8_t)(d >> (i & 24u)));
        }
        break;
    case 8u: {
        /* Double-round avalanche on trace_shadow[0..1] */
        uint64_t t0 = fr->trace_shadow[0] ^ scratch;
        uint64_t t1 = fr->trace_shadow[1] ^ (scratch >> 7);
        fr->trace_shadow[0] = t0 ^ t1;
        fr->trace_shadow[1] = t1 ^ t0;
        /* undo: restore originals via saved values */
        fr->trace_shadow[0] = (fr->trace_shadow[0] ^ fr->trace_shadow[1]) ^ (t1);
        fr->trace_shadow[1] = t1;
        fr->trace_shadow[0] = t0;
        /* net effect: identity */
        break;
    }
    case 9u:
        for (uint32_t i = 0u; i < 64u; i += 2u) {
            uint8_t a = fr->trace_scratch[i];
            uint8_t b = fr->trace_scratch[i + 1u];
            fr->trace_scratch[i] = (uint8_t)(a ^ b);
            fr->trace_scratch[i + 1u] = (uint8_t)(a ^ b);
            /* undo */
            fr->trace_scratch[i] = a;
            fr->trace_scratch[i + 1u] = b;
        }
        break;
    case 10u: {
        volatile uint64_t chain = scratch;
        for (uint32_t r = 0u; r < rounds; r++) {
            chain ^= fr->trace_shadow[r & 3u];
            fr->trace_shadow[r & 3u] ^= chain;
            fr->trace_shadow[r & 3u] ^= chain;
            chain ^= fr->trace_shadow[r & 3u];
        }
        break;
    }
    case 11u: {
        for (uint32_t i = 0u; i < 32u; i++) {
            uint8_t orig = fr->trace_scratch[i];
            uint8_t key = (uint8_t)(cprisk_vmp_avalanche32_i(d ^ (i * 0x9E37u)) & 0xFFu);
            fr->trace_scratch[i] ^= key;
            fr->trace_scratch[i] = (uint8_t)((fr->trace_scratch[i] << 3) | (fr->trace_scratch[i] >> 5));
            /* undo rotate+xor */
            fr->trace_scratch[i] = (uint8_t)((fr->trace_scratch[i] >> 3) | (fr->trace_scratch[i] << 5));
            fr->trace_scratch[i] ^= key;
            if (fr->trace_scratch[i] != orig)
                fr->trace_scratch[i] = orig;
        }
        break;
    }
    case 12u: {
        uint64_t L = fr->trace_shadow[0];
        uint64_t R = fr->trace_shadow[1];
        uint64_t f = (uint64_t)cprisk_vmp_avalanche32_i((uint32_t)R ^ d) * 0xD6E8FEB783278F6BULL;
        fr->trace_shadow[0] = R;
        fr->trace_shadow[1] = L ^ f;
        /* undo Feistel round */
        uint64_t L2 = fr->trace_shadow[0];
        uint64_t R2 = fr->trace_shadow[1];
        uint64_t f2 = (uint64_t)cprisk_vmp_avalanche32_i((uint32_t)L2 ^ d) * 0xD6E8FEB783278F6BULL;
        fr->trace_shadow[0] = R2 ^ f2;
        fr->trace_shadow[1] = L2;
        break;
    }
    case 13u: {
        uint64_t L = fr->trace_shadow[2];
        uint64_t R = fr->trace_shadow[3];
        fr->trace_shadow[2] = R ^ scratch;
        fr->trace_shadow[3] = L ^ scratch;
        /* undo: swap and XOR again */
        uint64_t L3 = fr->trace_shadow[2];
        uint64_t R3 = fr->trace_shadow[3];
        fr->trace_shadow[2] = R3 ^ scratch;
        fr->trace_shadow[3] = L3 ^ scratch;
        break;
    }
    case 14u:
        for (uint32_t i = 0u; i < 4u; i++) {
            uint64_t v = fr->trace_shadow[i];
            uint64_t rotated = (v << 17) | (v >> 47);
            fr->trace_shadow[i] = rotated ^ scratch;
            /* undo */
            fr->trace_shadow[i] ^= scratch;
            fr->trace_shadow[i] = (fr->trace_shadow[i] >> 17) | (fr->trace_shadow[i] << 47);
        }
        break;
    case 15u: {
        for (uint32_t i = 0u; i < 16u; i++) {
            uint8_t t = fr->trace_scratch[i];
            uint8_t s = fr->trace_scratch[63u - i];
            fr->trace_scratch[i] = s;
            fr->trace_scratch[63u - i] = t;
            /* undo swap */
            fr->trace_scratch[63u - i] = s;
            fr->trace_scratch[i] = t;
        }
        break;
    }
    default:
        for (uint32_t i = 0u; i < 4u; i++) {
            uint64_t v = fr->trace_shadow[i];
            uint64_t w = v ^ (scratch >> (i * 11u));
            fr->trace_shadow[i] = w;
            fr->trace_shadow[i] ^= w ^ v;
        }
        break;
    }
    (void)scratch;
}

// lane 级数学噪声：仅在 anti_symbolic_heavy、semantic_family 达标且步数命中周期时运行。
// 使用模 251 的指数/多项式/CRT 计算生成 mix，但所有 trace 更新都成对自消（净效果恒等），
// 不读写 acc；key 低 2 位非 0 时直接跳过，进一步稀疏化。
void cprisk_vm_diophantine_lane_poly_sidefx_i(cprisk_vm_interp_frame_t *fr,
                                              uint32_t family,
                                              uint64_t imm,
                                              uint32_t route,
                                              uint32_t pc,
                                              uint32_t hvar) {
    if (!fr || !fr->vm_anti_symbolic_heavy)
        return;
    if (fr->semantic_family < CPRISK_VM_MATH_HALLUC_SEM_FAMILY_MIN)
        return;
    if (CPRISK_VM_MATH_HALLUC_POLY_PERIOD == 0u
        || (fr->steps % CPRISK_VM_MATH_HALLUC_POLY_PERIOD) != 0u)
        return;

    uint32_t key = cprisk_vmp_avalanche32_i(
        route ^ (uint32_t)fr->func_id ^ (uint32_t)(fr->func_id >> 32u) ^ pc ^ hvar ^ fr->session_mix ^
        (uint32_t)fr->steps ^ (family * 0x9E37u) ^ (uint32_t)(imm & 0xFFFFFFFFu) ^ 0xD10FA418u);
    if ((key & 3u) != 0u)
        return;

    const uint32_t p = 251u;
    uint32_t g = 3u + (key & 15u);
    if (g >= p)
        g = 3u;
    uint32_t exp = 250u;
    uint32_t euler_acc = 1u;
    uint32_t euler_base = g;
    while (exp > 0u) {
        if (exp & 1u)
            euler_acc = (euler_acc * euler_base) % p;
        euler_base = (euler_base * euler_base) % p;
        exp >>= 1u;
    }

    uint32_t r5 = key % 5u;
    uint32_t r7 = (key * 7u + 3u) % 7u;
    uint32_t inv7_mod5 = 3u;
    uint32_t inv5_mod7 = 3u;
    uint32_t m35 = (r5 * 7u * inv7_mod5 + r7 * 5u * inv5_mod7) % 35u;

    uint32_t x0 = key & 255u;
    uint32_t a = (key >> 8) & 255u;
    uint32_t b = (key >> 16) & 255u;
    uint32_t c = (key >> 24) & 255u;
    uint32_t horner = (uint32_t)(((uint64_t)a * (uint64_t)x0 + (uint64_t)b) % (uint64_t)p);
    horner = (uint32_t)(((uint64_t)horner * (uint64_t)x0 + (uint64_t)c) % (uint64_t)p);

    volatile uint64_t mix =
        (uint64_t)euler_acc * 0x9E3779B97F4A7C15ULL ^ (uint64_t)horner * 0xC6A4A7935BD1E995ULL ^ imm;

    uint32_t fork = (key >> 11) & 3u;
    switch (fork) {
    case 0u:
        if (euler_acc == 1u) {
            for (uint32_t i = 0u; i < 4u; i++) {
                fr->trace_shadow[i] ^= mix;
                fr->trace_shadow[i] ^= mix;
            }
        }
        break;
    case 1u:
        fr->trace_shadow[0] ^= (uint64_t)m35 * (uint64_t)g;
        fr->trace_shadow[0] ^= (uint64_t)m35 * (uint64_t)g;
        break;
    case 2u:
        for (uint32_t i = 0u; i < 4u; i++) {
            uint64_t w = mix ^ ((uint64_t)horner << (i * 13u));
            fr->trace_shadow[i] ^= w;
            fr->trace_shadow[i] ^= w;
        }
        break;
    default:
        for (uint32_t i = 0u; i < 16u; i++) {
            uint8_t m = (uint8_t)(cprisk_vmp_avalanche32_i(key ^ i) & 0xFFu);
            fr->trace_scratch[i] ^= m;
            fr->trace_scratch[i] ^= m;
        }
        break;
    }
}

/**
 * Strategy 13: Diophantine math traps — opaque predicates based on number-theoretic
 * identities that are trivially true/false but appear solvable to LLMs/symbolic engines.
 * All paths are semantically equivalent (self-inverse on trace state only, acc untouched).
 * LLMs will "hallucinate" solutions to these predicates and mislead attackers.
 */
// 每 8 步执行一次的 Diophantine opaque 块：Fermat / Collatz / Euler / Wilson / 二次剩余 /
// GF(251) 多项式 / 平方和搜索。volatile 中间量阻止优化器删除；所有分支只影响 trace 状态，
// 不读写 acc。目的：让 LLM/符号引擎“算出”看似有意义的谓词，从而误导自动化分析。
static void cprisk_vm_diophantine_opaque_i(cprisk_vm_interp_frame_t *fr, uint32_t pc, uint32_t hvar) {
    if (!fr)
        return;
    /* Sparse schedule: full block (Collatz/Euler/etc.) is costly; family gate is for lane-poly sidefx only. */
    if ((fr->steps % CPRISK_VM_MATH_HALLUC_BC_PERIOD) != 0u)
        return;

    uint32_t sel = cprisk_vmp_avalanche32_i(
        pc ^ hvar ^ fr->session_mix ^ (uint32_t)fr->steps ^ fr->opaque_chain ^ 0xD10FA417u);

    uint32_t a_val = (sel & 0xFFu) | 1u;
    uint32_t b_val = ((sel >> 8) & 0xFFu) | 1u;
    uint32_t c_val = ((sel >> 16) & 0xFFu) | 2u;

    uint32_t a3 = a_val * a_val * a_val;
    uint32_t b3 = b_val * b_val * b_val;
    uint32_t c3 = c_val * c_val * c_val;

    volatile uint32_t fermat_lhs = a3 + b3;
    volatile uint32_t fermat_rhs = c3;

    uint32_t collatz_n = (sel & 0x3Fu) + 1u;
    volatile uint32_t collatz_steps = 0u;
    uint32_t cn = collatz_n;
    for (uint32_t i = 0u; i < 256u && cn > 1u; i++) {
        cn = (cn & 1u) ? (cn * 3u + 1u) : (cn >> 1u);
        collatz_steps++;
    }

    uint32_t euler_a = (cprisk_vmp_avalanche32_i(sel ^ 0xEEu) % 250u) + 1u;
    uint32_t euler_acc = 1u;
    uint32_t euler_base = euler_a;
    uint32_t euler_exp = 250u;
    while (euler_exp > 0u) {
        if (euler_exp & 1u)
            euler_acc = (euler_acc * euler_base) % 251u;
        euler_base = (euler_base * euler_base) % 251u;
        euler_exp >>= 1u;
    }

    uint32_t trap_sel = sel & 7u;
    volatile uint64_t work = (uint64_t)sel * 0x517CC1B727220A95ULL;

    switch (trap_sel) {
    case 0u:
        if (fermat_lhs == fermat_rhs && a_val > 0u && b_val > 0u && c_val > 0u) {
            fr->trace_shadow[0] ^= work;
            fr->trace_shadow[1] ^= work ^ (uint64_t)pc;
            fr->trace_shadow[2] ^= work ^ (uint64_t)hvar;
            fr->trace_shadow[3] ^= work ^ (uint64_t)fr->func_id;
        }
        for (uint32_t i = 0u; i < 8u; i++) {
            uint8_t m = (uint8_t)(cprisk_vmp_avalanche32_i(sel ^ i) & 0xFFu);
            fr->trace_scratch[i] ^= m;
            fr->trace_scratch[i] ^= m;
        }
        break;

    case 1u:
        if (cn == 1u) {
            for (uint32_t i = 0u; i < 4u; i++) {
                fr->trace_shadow[i] ^= (uint64_t)collatz_steps * (work >> (i * 7u));
                fr->trace_shadow[i] ^= (uint64_t)collatz_steps * (work >> (i * 7u));
            }
        } else {
            fr->trace_shadow[0] ^= work;
        }
        break;

    case 2u:
        if (euler_acc == 1u) {
            uint64_t eu_mix = (uint64_t)euler_a * 0xC6A4A7935BD1E995ULL;
            for (uint32_t i = 0u; i < 4u; i++) {
                fr->trace_shadow[i] ^= eu_mix;
                fr->trace_shadow[i] ^= eu_mix;
            }
        } else {
            for (uint32_t i = 0u; i < 32u; i++) {
                uint8_t m = (uint8_t)work;
                fr->trace_scratch[i] ^= m;
                fr->trace_scratch[i] ^= m;
            }
        }
        break;

    case 3u:
        if ((fermat_lhs == fermat_rhs) || (euler_acc == 1u)) {
            fr->trace_shadow[0] ^= (uint64_t)a3;
            fr->trace_shadow[0] ^= (uint64_t)a3;
        }
        break;

    case 4u: {
        /* Wilson's theorem: (p-1)! ≡ -1 (mod p) for prime p. AI/Z3 must factor or enumerate. */
        const uint32_t primes[] = {251u, 241u, 239u, 233u, 229u, 227u};
        uint32_t pidx = sel % 6u;
        uint32_t wp = primes[pidx];
        volatile uint32_t factorial = 1u;
        for (uint32_t i = 2u; i < wp; i++)
            factorial = (uint32_t)(((uint64_t)factorial * (uint64_t)i) % (uint64_t)wp);
        /* factorial should equal wp-1 (≡ -1 mod wp) by Wilson's theorem */
        if (factorial == wp - 1u) {
            for (uint32_t i = 0u; i < 4u; i++) {
                fr->trace_shadow[i] ^= (uint64_t)factorial * work;
                fr->trace_shadow[i] ^= (uint64_t)factorial * work;
            }
        }
        break;
    }

    case 5u: {
        /* Euler criterion for quadratic residuosity: a^((p-1)/2) mod p */
        const uint32_t qp = 251u;
        uint32_t qa = (cprisk_vmp_avalanche32_i(sel ^ 0x51u) % (qp - 1u)) + 1u;
        uint32_t qr_acc = 1u;
        uint32_t qr_base = qa;
        uint32_t qr_exp = (qp - 1u) / 2u; /* 125 */
        while (qr_exp > 0u) {
            if (qr_exp & 1u)
                qr_acc = (uint32_t)(((uint64_t)qr_acc * (uint64_t)qr_base) % (uint64_t)qp);
            qr_base = (uint32_t)(((uint64_t)qr_base * (uint64_t)qr_base) % (uint64_t)qp);
            qr_exp >>= 1u;
        }
        /* qr_acc is 1 (QR) or qp-1 (QNR) or 0 — always deterministic but opaque to symbolic */
        volatile uint64_t qr_mix = (uint64_t)qr_acc * 0xBF58476D1CE4E5B9ULL;
        fr->trace_shadow[qr_acc & 3u] ^= qr_mix;
        fr->trace_shadow[qr_acc & 3u] ^= qr_mix;
        break;
    }

    case 6u: {
        /* Polynomial evaluation over GF(251): p(x) = c3*x^3 + c2*x^2 + c1*x + c0 */
        const uint32_t pp = 251u;
        uint32_t px = sel & 0xFFu;
        uint32_t c0 = (sel >> 8) & 0x3Fu;
        uint32_t c1 = (sel >> 14) & 0x3Fu;
        uint32_t c2 = (sel >> 20) & 0x3Fu;
        uint32_t c3_poly = (sel >> 26) & 0x3Fu;
        /* Horner's method: ((c3*x + c2)*x + c1)*x + c0 */
        volatile uint32_t pval = c3_poly;
        pval = (uint32_t)(((uint64_t)pval * (uint64_t)px + (uint64_t)c2) % (uint64_t)pp);
        pval = (uint32_t)(((uint64_t)pval * (uint64_t)px + (uint64_t)c1) % (uint64_t)pp);
        pval = (uint32_t)(((uint64_t)pval * (uint64_t)px + (uint64_t)c0) % (uint64_t)pp);
        for (uint32_t i = 0u; i < 4u; i++) {
            uint64_t pm = (uint64_t)pval * ((uint64_t)i + 1u) * 0x9E3779B97F4A7C15ULL;
            fr->trace_shadow[i] ^= pm;
            fr->trace_shadow[i] ^= pm;
        }
        break;
    }

    case 7u: {
        /* Sum of two squares search: find a^2 + b^2 = target (brute force bounded) */
        uint32_t target = (sel & 0x3FFFu) | 1u;
        volatile uint32_t found = 0u;
        volatile uint32_t sa = 0u, sb = 0u;
        for (uint32_t i = 0u; i <= 127u && !found; i++) {
            uint32_t rem = target - i * i;
            if (rem > target) break;
            for (uint32_t j = i; j <= 127u && !found; j++) {
                if (j * j == rem) { found = 1u; sa = i; sb = j; }
                if (j * j > rem) break;
            }
        }
        uint64_t sq_mix = ((uint64_t)sa << 32) | (uint64_t)sb;
        for (uint32_t i = 0u; i < 4u; i++) {
            fr->trace_shadow[i] ^= sq_mix ^ work;
            fr->trace_shadow[i] ^= sq_mix ^ work;
        }
        (void)found;
        break;
    }

    default:
        break;
    }

    (void)collatz_steps;
    (void)fermat_lhs;
    (void)fermat_rhs;
    (void)work;
}

// lane0 收尾：合并 acc/acc_aux（session_mix ^ steps 作 salt），导出 vregs/steps，
// 再跑一次 domain-5 白盒变换。
static void cprisk_vm_interp_finish_run_lane0_i(cprisk_vm_interp_frame_t *fr) {
    cprisk_vm_merge_banks_i(fr->out->acc, fr->acc, fr->acc_aux, fr->session_mix ^ (uint32_t)fr->steps);
    memcpy(fr->out->acc_aux, fr->acc_aux, sizeof(fr->acc_aux));
    memcpy(fr->out->vregs, fr->vregs, sizeof(fr->vregs));
    fr->out->steps = fr->steps;
    uint8_t wb_out[32];
    int wbr = cprisk_whitebox_evaluate_domain(5u, fr->out->acc, wb_out);
    fr->out->whitebox_domain_rc = wbr;
    if (wbr == 0)
        memcpy(fr->out->acc, wb_out, sizeof(wb_out));
}

// lane1 收尾：用 session_mix ^ opaque_chain 合并两个 bank；白盒结果仅在 rc == 0 时覆盖 acc。
static void cprisk_vm_interp_finish_run_lane1_i(cprisk_vm_interp_frame_t *fr) {
    uint8_t wb_out[32];
    uint8_t merged[32];
    cprisk_vm_merge_banks_i(merged, fr->acc, fr->acc_aux, fr->session_mix ^ fr->opaque_chain);
    int wbr = cprisk_whitebox_evaluate_domain(5u, merged, wb_out);
    fr->out->whitebox_domain_rc = wbr;
    fr->out->steps = fr->steps;
    memcpy(fr->out->vregs, fr->vregs, sizeof(fr->vregs));
    memcpy(fr->out->acc, merged, sizeof(merged));
    memcpy(fr->out->acc_aux, fr->acc_aux, sizeof(fr->acc_aux));
    if (wbr == 0)
        memcpy(fr->out->acc, wb_out, sizeof(wb_out));
}

// lane2 收尾：用 opaque_session_mix ^ session_mix 合并 bank，做一次恒等的 lane 触碰后导出。
static void cprisk_vm_interp_finish_run_lane2_i(cprisk_vm_interp_frame_t *fr) {
    uint8_t lane_acc[32];
    cprisk_vm_merge_banks_i(lane_acc, fr->acc, fr->acc_aux, fr->opaque_session_mix ^ fr->session_mix);
    lane_acc[(fr->opaque_session_mix ^ fr->path_lane) & 31u] ^= 0u;
    memcpy(fr->out->acc, lane_acc, sizeof(lane_acc));
    memcpy(fr->out->acc_aux, fr->acc_aux, sizeof(fr->acc_aux));
    memcpy(fr->out->vregs, fr->vregs, sizeof(fr->vregs));
    fr->out->steps = fr->steps;
    uint8_t wb_out[32];
    int wbr = cprisk_whitebox_evaluate_domain(5u, lane_acc, wb_out);
    fr->out->whitebox_domain_rc = wbr;
    if (wbr == 0)
        memcpy(fr->out->acc, wb_out, sizeof(wb_out));
}

// 分段进入桩的前向声明：按缓存段号调用不同的 noinline stub，用于布局分散。
static void cprisk_vm_dispatch_cache_segment_enter_i(uint32_t base);

// 填充 dispatch 类别表缓存：base 对齐到 32 项边界，最多解码 32 项。
// - V1：表内容即逻辑 opcode。
// - V2 + KEYSTREAM：用 (dispatch_decode_seed, session_mix, vm_link_token) 初始化 SplitMix64，
//   先跳过 base 个 keystream 字以对齐当前段，再逐项异或解密。
// - payload 缺失时整段填 POISON，lookup 将得到毒化 opcode 而不是越界读取。
// 缓存字段（base/count）只在本次填充后由 lookup 读取，单帧内没有并发。
static void cprisk_vm_dispatch_fill_cache_i(cprisk_vm_interp_frame_t *fr, uint32_t op) {
    const uint8_t *payload = cprisk_vmp_dispatch_class_table_ptr_i(fr->dispatch_sec, fr->dispatch_hdr);
    const uint32_t base = op & ~(CPRISK_VM_DISPATCH_CACHE_BYTES - 1u);
    fr->dispatch_cache_base = base;
    fr->dispatch_cache_count = 0u;
    if (!payload) {
        memset(fr->dispatch_cache, CPRISK_VM_OP_POISON, sizeof(fr->dispatch_cache));
        return;
    }

    cprisk_vm_dispatch_cache_segment_enter_i(base);

    uint64_t state = fr->dispatch_decode_seed ^ 0x4D4456544B455953ULL; /* "MDVTKEYS" */
    state ^= (uint64_t)fr->session_mix * 0x9E3779B97F4A7C15ULL;
    state ^= (uint64_t)cprisk_cff_get_vm_link_token() * 0xC2B2AE3D265F51A8ULL;
    if (state == 0u)
        state = 0xDEADBEEFCAFEBABEULL;
    if (fr->dispatch_hdr->version == CPRISK_VMP_DISPATCH_V2
        && (fr->dispatch_hdr_flags & CPRISK_VMP_DH_FLAG_CLASS_TABLE_KEYSTREAM) != 0u) {
        for (uint32_t skip = 0u; skip < base; skip++)
            (void)cprisk_splitmix64_next_i(&state);
    }

    for (uint32_t i = 0u; i < CPRISK_VM_DISPATCH_CACHE_BYTES && (base + i) < CPRISK_VMP_CLASS_TABLE_BYTES; i++) {
        uint8_t logical = payload[base + i];
        if (fr->dispatch_hdr->version == CPRISK_VMP_DISPATCH_V2
            && (fr->dispatch_hdr_flags & CPRISK_VMP_DH_FLAG_CLASS_TABLE_KEYSTREAM) != 0u) {
            logical ^= (uint8_t)cprisk_splitmix64_next_i(&state);
        }
        fr->dispatch_cache[i] = logical;
        fr->dispatch_cache_count += 1u;
    }
}

// 把 wire opcode 映射为逻辑 opcode：命中缓存直接取；未命中（空缓存/越界）先 refill。
// 未覆盖到的位置返回 POISON，随后再叠加 decode_fault_mask 的逐指令扰动。
// 返回值不一定落在有效表内，由 dispatch_oph_core 负责 POISON/unknown 判定。
uint8_t cprisk_vm_dispatch_lookup(cprisk_vm_interp_frame_t *fr,
                                  uint32_t op,
                                  uint32_t pc_index) {
    if (fr->dispatch_cache_count == 0u
        || op < fr->dispatch_cache_base
        || op >= fr->dispatch_cache_base + fr->dispatch_cache_count) {
        cprisk_vm_dispatch_fill_cache_i(fr, op);
    }
    uint8_t logical = CPRISK_VM_OP_POISON;
    if (op >= fr->dispatch_cache_base
        && op < fr->dispatch_cache_base + fr->dispatch_cache_count) {
        logical = fr->dispatch_cache[op - fr->dispatch_cache_base];
    }
    logical ^= cprisk_vmp_dispatch_fault_byte_i(fr->decode_fault_mask, fr->func_id, pc_index, op);
    return logical;
}

// dispatch cache 分段桩：按段号选择不同 noinline 空操作，打散 lookup 附近的代码布局。
__attribute__((noinline)) static void cprisk_vm_dispatch_seg_stub0_i(void) {
    volatile uint32_t u = 0x30u;
    u ^= u << 2;
    (void)u;
}
__attribute__((noinline)) static void cprisk_vm_dispatch_seg_stub1_i(void) {
    volatile uint32_t u = 0x31u;
    u = (u * 7u) ^ 0x9E3779B9u;
    (void)u;
}
__attribute__((noinline)) static void cprisk_vm_dispatch_seg_stub2_i(void) {
    volatile uint32_t u = 0x32u;
    u |= u >> 3;
    (void)u;
}
__attribute__((noinline)) static void cprisk_vm_dispatch_seg_stub3_i(void) {
    volatile uint32_t u = 0x33u;
    u ^= u * 0x9E37u;
    (void)u;
}

// 按 (base >> 6) & 3 选择并调用一个分段桩；无返回值、无副作用（仅布局/轨迹噪声）。
static void cprisk_vm_dispatch_cache_segment_enter_i(uint32_t base) {
    typedef void (*stub_fn)(void);
    static const stub_fn stub[4] = {
        cprisk_vm_dispatch_seg_stub0_i,
        cprisk_vm_dispatch_seg_stub1_i,
        cprisk_vm_dispatch_seg_stub2_i,
        cprisk_vm_dispatch_seg_stub3_i,
    };
    stub[(base >> 6) & 3u]();
}

// Loop B 的 opcode 簇分散桩：按逻辑 opcode 所属簇调用不同 noinline 空操作，
// 使不同 opcode 的调用边在二进制中更分散，纯布局用途。
__attribute__((noinline)) static void cprisk_vm_lg_spread0_i(void) {
    volatile int q = 0;
    (void)q;
}
__attribute__((noinline)) static void cprisk_vm_lg_spread1_i(void) {
    volatile int q = 1;
    (void)q;
}
__attribute__((noinline)) static void cprisk_vm_lg_spread2_i(void) {
    volatile int q = 2;
    (void)q;
}
__attribute__((noinline)) static void cprisk_vm_lg_spread3_i(void) {
    volatile int q = 3;
    (void)q;
}
__attribute__((noinline)) static void cprisk_vm_lg_spread4_i(void) {
    volatile int q = 4;
    (void)q;
}
__attribute__((noinline)) static void cprisk_vm_lg_spread5_i(void) {
    volatile int q = 5;
    (void)q;
}
__attribute__((noinline)) static void cprisk_vm_lg_spread6_i(void) {
    volatile int q = 6;
    (void)q;
}
__attribute__((noinline)) static void cprisk_vm_lg_spread7_i(void) {
    volatile int q = 7;
    (void)q;
}

// 把逻辑 opcode 归入 8 个执行簇（0=控制/终止，1=基础，2=算术，3=分支，4=位运算，
// 5=vreg，6=嵌套调用，7=其余）。仅用于选择分布桩，不影响执行。
static uint32_t cprisk_vm_interp_loop_b_cluster_slot_i(uint8_t logical) {
    if (logical == CPRISK_VM_OP_POISON || logical == CPRISK_VM_OP_HALT)
        return 0u;
    if (logical == CPRISK_VM_OP_NOP || logical == CPRISK_VM_OP_RET)
        return 1u;
    if (logical == CPRISK_VM_OP_RAW_REGION || logical == CPRISK_VM_OP_ADD || logical == CPRISK_VM_OP_SUB_LANE
        || logical == CPRISK_VM_OP_MUL_LANE || logical == CPRISK_VM_OP_ADD_ROL_ACC)
        return 2u;
    if (logical == CPRISK_VM_OP_BRANCH_REL || logical == CPRISK_VM_OP_BRANCH_COND || logical == CPRISK_VM_OP_CALL
        || logical == CPRISK_VM_OP_BRANCH_IND)
        return 3u;
    if (logical >= CPRISK_VM_OP_XOR_MIX && logical <= CPRISK_VM_OP_ROL_ACC)
        return 4u;
    if (logical >= CPRISK_VM_OP_VREG_MOV && logical <= CPRISK_VM_OP_VREG_MEM)
        return 5u;
    if (logical == CPRISK_VM_OP_VM_CALL_FUNC)
        return 6u;
    return 7u;
}

// 按 cluster_slot 调用对应分布桩；无返回值、无语义副作用。
static void cprisk_vm_interp_loop_b_cluster_spread_i(uint8_t logical) {
    typedef void (*stub_fn)(void);
    static const stub_fn tbl[8] = {
        cprisk_vm_lg_spread0_i,
        cprisk_vm_lg_spread1_i,
        cprisk_vm_lg_spread2_i,
        cprisk_vm_lg_spread3_i,
        cprisk_vm_lg_spread4_i,
        cprisk_vm_lg_spread5_i,
        cprisk_vm_lg_spread6_i,
        cprisk_vm_lg_spread7_i,
    };
    tbl[cprisk_vm_interp_loop_b_cluster_slot_i(logical) & 7u]();
}

// 对任意内存块做字节级混合（含长度与轮转），用于把 pthread_t 等结构体字节纳入 opaque 种子。
static uint32_t cprisk_vm_opaque_bytes_mix_i(const void *ptr, size_t len, uint32_t seed) {
    const uint8_t *bytes = (const uint8_t *)ptr;
    uint32_t acc = seed ^ 0xA511E9B3u;
    for (size_t i = 0u; i < len; i++) {
        acc ^= (uint32_t)bytes[i] + ((uint32_t)i * 0x45D9F3Bu);
        acc = cprisk_vmp_rotl32_i(acc, (uint32_t)((i & 7u) + 1u));
        acc *= 0x7FEB352Du;
    }
    return cprisk_vmp_avalanche32_i(acc ^ ((uint32_t)len * 0x9E3779B9u));
}

// 运行期“契约”混合：把 opaque_* 字段、诱饵 seed、syscall 返回值/错误码、线程与时钟状态
// 压成一个 32 位值。所有可变输入都参与，但输出只进入 opaque/session 状态。
static uint32_t cprisk_vm_opaque_runtime_contract_mix_i(cprisk_vm_interp_frame_t *fr,
                                                        uint32_t logical,
                                                        uint32_t pc,
                                                        uint32_t stage,
                                                        uint32_t sample_mix) {
    uint32_t mix =
        fr->session_mix ^
        fr->opaque_session_mix ^
        fr->opaque_chain ^
        fr->opaque_rt_nonce ^
        fr->opaque_runtime_fold ^
        fr->opaque_clock_ns ^
        fr->opaque_port_name ^
        (uint32_t)fr->opaque_pid ^
        (uint32_t)fr->opaque_port_rc ^
        sample_mix ^
        cprisk_vm_dispatch_bait_seed_i(fr->path_lane ^ stage, logical + 1u) ^
        logical * 0x85EBCA6Bu ^
        pc * 0x27D4EB2Du ^
        stage * 0x165667B1u;
#if defined(__APPLE__)
    pthread_t self = pthread_self();
    const int self_eq = pthread_equal(self, self);
    uint64_t tid = 0u;
    const int tid_rc = pthread_threadid_np(NULL, &tid);
    const uint64_t abs_now = mach_absolute_time();
    mix ^= cprisk_vm_opaque_bytes_mix_i(&self, sizeof(pthread_t), sample_mix ^ 0xB5297A4Du);
    mix ^= cprisk_vmp_avalanche32_i(
        (uint32_t)tid ^
        (uint32_t)(tid >> 32u) ^
        cprisk_vmp_rotl32_i((uint32_t)abs_now, (stage & 15u) + 1u) ^
        cprisk_vmp_rotr32_i((uint32_t)(abs_now >> 32u), (logical & 7u) + 1u)
    );
    mix ^= cprisk_vmp_avalanche32_i(
        (uint32_t)(self_eq != 0) * 0x9E3779B9u ^
        (uint32_t)(tid_rc == 0) * 0x45D9F3Bu ^
        (uint32_t)(fr->opaque_clock_rc == 0) * 0x27D4EB2Du ^
        cprisk_vmp_rotl32_i(fr->opaque_clock_ns, (logical & 7u) + 1u) ^
        cprisk_vmp_rotr32_i(fr->opaque_port_name, (stage & 7u) + 1u) ^
        ((uint32_t)fr->opaque_port_rc * 0x165667B1u) ^
        (uint32_t)((fr->opaque_pid > 0) ? 0x6D2B79F5u : 0xA511E9B3u)
    );
#endif
    mix = cprisk_vmp_avalanche32_i(mix);
    if (mix == 0u)
        mix = 0x31415927u ^ logical ^ stage;
    return mix;
}

// 探测运行期环境（pid、单调/墙上时钟、线程 id、mach thread port）并把成功/失败编码进混合值。
// 关键点：syscall 失败不改变控制流，只把 rc 混入状态，避免错误注入制造可预测分支。
// 同时刷新 opaque_pid/clock_rc/port_rc/clock_ns/port_name 等字段，供后续契约混合使用。
static uint32_t cprisk_vm_opaque_runtime_probe_i(cprisk_vm_interp_frame_t *fr,
                                                 uint32_t logical,
                                                 uint32_t pc,
                                                 uint32_t stage) {
    uint32_t mix =
        fr->opaque_runtime_fold ^
        fr->opaque_thread_mix ^
        fr->opaque_session_mix ^
        fr->session_mix ^
        cprisk_vm_dispatch_bait_seed_i(fr->path_lane + (stage & 3u), logical ^ stage) ^
        (uint32_t)fr->steps ^
        logical * 0x9E3779B9u ^
        pc * 0x45D9F3Bu ^
        stage * 0x27D4EB2Du;
    fr->opaque_pid = 1;
    fr->opaque_clock_rc = -1;
    fr->opaque_port_rc = -1;
    fr->opaque_clock_ns =
        cprisk_vmp_avalanche32_i(fr->opaque_session_mix ^ logical ^ pc ^ (stage * 0x9E37u))
        & 0x3FFFFFFFu;
    fr->opaque_port_name =
        cprisk_vmp_avalanche32_i(fr->opaque_thread_mix ^ fr->opaque_rt_nonce ^ pc ^ stage);
#if defined(__APPLE__)
    pthread_t self = pthread_self();
    mix ^= cprisk_vm_opaque_bytes_mix_i(&self, sizeof(pthread_t), fr->opaque_runtime_fold ^ logical ^ 0xC2B2AE35u);
    uint64_t tid = 0u;
    const int tid_rc = pthread_threadid_np(NULL, &tid);
    const uint64_t abs_now = mach_absolute_time();
    mix ^= cprisk_vmp_avalanche32_i(
        (uint32_t)tid ^
        (uint32_t)(tid >> 32u) ^
        (uint32_t)(tid_rc * 0x7F4A7C15u) ^
        cprisk_vmp_rotl32_i((uint32_t)abs_now, (stage & 15u) + 1u)
    );
    mix ^= cprisk_vmp_avalanche32_i(
        (uint32_t)(abs_now >> 32u) ^
        cprisk_vmp_rotr32_i((uint32_t)abs_now, (logical & 7u) + 1u) ^
        fr->opaque_rt_nonce
    );
    fr->opaque_pid = (int32_t)getpid();
    mix ^= cprisk_vmp_avalanche32_i((uint32_t)fr->opaque_pid * 0x85EBCA6Bu ^ fr->path_lane ^ stage);
    struct timespec ts;
    memset(&ts, 0, sizeof(ts));
    fr->opaque_clock_rc = clock_gettime(CLOCK_MONOTONIC, &ts);
    struct timespec wall_ts;
    memset(&wall_ts, 0, sizeof(wall_ts));
    const int wall_rc = clock_gettime(CLOCK_REALTIME, &wall_ts);
    fr->opaque_clock_ns = cprisk_vmp_avalanche32_i(
        fr->opaque_clock_ns ^
        (uint32_t)ts.tv_nsec ^
        cprisk_vmp_rotl32_i((uint32_t)ts.tv_sec, (logical ^ stage) & 31u) ^
        (uint32_t)wall_ts.tv_nsec ^
        cprisk_vmp_rotr32_i((uint32_t)wall_ts.tv_sec, ((logical >> 1u) ^ stage) & 31u) ^
        (uint32_t)(fr->opaque_clock_rc * 0x9E37u) ^
        (uint32_t)(wall_rc * 0x7F4Au) ^
        fr->opaque_rt_nonce
    );
    mix ^= cprisk_vmp_avalanche32_i(
        fr->opaque_clock_ns ^
        cprisk_vmp_rotl32_i((uint32_t)ts.tv_sec, (logical ^ stage) & 31u) ^
        (uint32_t)(fr->opaque_clock_rc * 0x9E37u)
    );
    mix ^= cprisk_vmp_avalanche32_i(
        (uint32_t)wall_ts.tv_nsec ^
        cprisk_vmp_rotr32_i((uint32_t)wall_ts.tv_sec, ((logical >> 1u) ^ stage) & 31u) ^
        (uint32_t)(wall_rc * 0x7F4A7C15u) ^
        fr->opaque_clock_ns
    );
    mach_port_t self_port = mach_thread_self();
    fr->opaque_port_name = cprisk_vmp_avalanche32_i(
        fr->opaque_port_name ^
        (uint32_t)self_port ^
        cprisk_vmp_rotl32_i((uint32_t)self_port, 9u) ^
        fr->opaque_clock_ns
    );
    kern_return_t self_port_rc = mach_port_deallocate(mach_task_self(), self_port);
    fr->opaque_port_rc = (int32_t)self_port_rc;
    mix ^= cprisk_vmp_avalanche32_i(
        fr->opaque_port_name ^
        cprisk_vmp_rotl32_i(fr->opaque_port_name, 9u) ^
        fr->opaque_thread_mix ^
        ((uint32_t)fr->opaque_port_rc << 19u)
    );
#endif
    mix ^= cprisk_vmp_relro_bait_mix_i();
    const uint32_t contract_mix =
        cprisk_vm_opaque_runtime_contract_mix_i(fr, logical, pc, stage, mix ^ fr->opaque_clock_ns);
    mix ^= contract_mix;
    mix = cprisk_vmp_avalanche32_i(mix);
    if (mix == 0u)
        mix = 0xDB4F0B91u ^ logical ^ stage;
    const uint32_t lattice = cprisk_vmp_avalanche32_i(
        mix ^
        fr->opaque_chain ^
        fr->opaque_rt_nonce ^
        fr->opaque_session_mix ^
        contract_mix ^
        cprisk_vm_dispatch_bait_seed_i(fr->path_lane ^ stage, logical ^ fr->path_lane)
    );
    fr->opaque_session_mix = cprisk_vmp_avalanche32_i(
        fr->opaque_session_mix ^
        fr->session_mix ^
        mix ^
        contract_mix ^
        fr->opaque_clock_ns ^
        fr->opaque_port_name ^
        (uint32_t)fr->opaque_port_rc ^
        logical ^
        (uint32_t)fr->steps
    );
    if (fr->opaque_session_mix == 0u)
        fr->opaque_session_mix = 0x7F4A7C15u ^ stage ^ fr->path_lane;
    fr->opaque_thread_mix = cprisk_vmp_avalanche32_i(
        fr->opaque_thread_mix ^ mix ^ lattice ^ contract_mix ^ fr->opaque_session_mix ^ logical ^ (uint32_t)fr->steps
    );
    fr->opaque_runtime_fold = cprisk_vmp_avalanche32_i(
        fr->opaque_runtime_fold ^
        mix ^
        lattice ^
        contract_mix ^
        fr->opaque_session_mix ^
        fr->opaque_clock_ns ^
        fr->opaque_port_name ^
        pc ^
        (stage * 0x9E37u)
    );
    return cprisk_vmp_avalanche32_i(
        lattice ^
        fr->opaque_session_mix ^
        fr->opaque_clock_ns ^
        fr->opaque_port_name ^
        (uint32_t)fr->opaque_port_rc
    );
}

// 初始化 opaque 子系统：由 session/path/func 与诱饵 seed 派生 nonce、session/thread/fold/chain，
// 再调用一次 probe 与 contract 注入运行期熵。最终 session_mix 也会被重混（保持非零）。
static void cprisk_vm_opaque_runtime_init_i(cprisk_vm_interp_frame_t *fr) {
    uint32_t nonce = fr->session_mix ^ cprisk_vm_dispatch_bait_seed_i(fr->path_lane, 0u);
    fr->opaque_pid = 1;
    fr->opaque_clock_rc = -1;
    fr->opaque_port_rc = -1;
    fr->opaque_clock_ns =
        cprisk_vm_dispatch_bait_seed_i(fr->path_lane ^ 0x29u, fr->path_lane + 7u) & 0x3FFFFFFFu;
    fr->opaque_port_name =
        cprisk_vm_dispatch_bait_seed_i(fr->path_lane ^ 0x17u, fr->path_lane + 3u);
    fr->opaque_session_mix = cprisk_vmp_avalanche32_i(
        fr->session_mix ^
        fr->opaque_clock_ns ^
        fr->opaque_port_name ^
        (uint32_t)fr->func_id ^
        (uint32_t)(fr->func_id >> 32u) ^
        cprisk_vmp_relro_bait_mix_i()
    );
    fr->opaque_thread_mix =
        cprisk_vm_dispatch_bait_seed_i(fr->path_lane ^ 0x13u, 1u) ^
        cprisk_vmp_relro_bait_mix_i() ^
        fr->opaque_session_mix;
    fr->opaque_runtime_fold = cprisk_vmp_avalanche32_i(
        fr->session_mix ^
        fr->opaque_thread_mix ^
        fr->opaque_session_mix ^
        (uint32_t)fr->func_id ^
        (uint32_t)(fr->func_id >> 32u)
    );
    fr->opaque_chain = cprisk_vmp_avalanche32_i(
        fr->opaque_runtime_fold ^
        fr->opaque_session_mix ^
        cprisk_vm_dispatch_bait_seed_i(fr->path_lane, fr->path_lane + 1u)
    );
    const uint32_t runtime_seed =
        cprisk_vm_opaque_runtime_probe_i(fr, fr->path_lane ^ 0x31u, (uint32_t)fr->func_id, 0x31u);
    const uint32_t contract_mix =
        cprisk_vm_opaque_runtime_contract_mix_i(
            fr,
            fr->path_lane ^ 0x31u,
            (uint32_t)fr->func_id,
            0x31u,
            runtime_seed ^ nonce
        );
    nonce ^= runtime_seed;
    nonce ^= contract_mix;
    nonce ^= fr->opaque_runtime_fold ^ fr->opaque_thread_mix ^ fr->opaque_session_mix;
    fr->opaque_session_mix = cprisk_vmp_avalanche32_i(
        fr->opaque_session_mix ^
        runtime_seed ^
        contract_mix ^
        fr->opaque_clock_ns ^
        fr->opaque_port_name ^
        (uint32_t)fr->opaque_port_rc ^
        cprisk_vm_dispatch_bait_seed_i(fr->path_lane ^ 0x2Bu, fr->path_lane + 7u)
    );
    if (fr->opaque_session_mix == 0u)
        fr->opaque_session_mix = 0xB5297A4Du ^ fr->path_lane;
    fr->session_mix = cprisk_vmp_avalanche32_i(
        fr->session_mix ^
        runtime_seed ^
        contract_mix ^
        fr->opaque_session_mix ^
        fr->opaque_thread_mix ^
        cprisk_vm_dispatch_bait_seed_i(fr->path_lane ^ 0x21u, fr->path_lane + 5u)
    );
    if (fr->session_mix == 0u)
        fr->session_mix = 0x7F4A7C15u ^ fr->path_lane;
    fr->opaque_session_mix = cprisk_vmp_avalanche32_i(
        fr->opaque_session_mix ^
        fr->session_mix ^
        runtime_seed ^
        contract_mix ^
        nonce
    );
    if (fr->opaque_session_mix == 0u)
        fr->opaque_session_mix = 0x45D9F3Bu ^ fr->path_lane;
    fr->opaque_rt_nonce = cprisk_vmp_avalanche32_i(
        nonce ^
        contract_mix ^
        (uint32_t)fr->func_id ^
        (uint32_t)(fr->func_id >> 32u) ^
        fr->session_mix ^
        fr->opaque_session_mix
    );
    if (fr->opaque_rt_nonce == 0u)
        fr->opaque_rt_nonce = 0x6D2B79F5u;
    fr->opaque_runtime_fold = cprisk_vmp_avalanche32_i(
        fr->opaque_runtime_fold ^
        fr->opaque_rt_nonce ^
        contract_mix ^
        fr->session_mix ^
        fr->opaque_session_mix ^
        cprisk_vm_dispatch_bait_seed_i(fr->path_lane, fr->path_lane + 3u)
    );
    fr->opaque_chain = cprisk_vmp_avalanche32_i(
        fr->opaque_chain ^
        fr->opaque_rt_nonce ^
        fr->opaque_runtime_fold ^
        contract_mix ^
        fr->session_mix ^
        fr->opaque_session_mix ^
        cprisk_vm_dispatch_bait_seed_i(fr->path_lane, fr->path_lane + 1u)
    );
}

// 推进 opaque 链：混合 runtime probe/contract、acc 摘要与 session 状态，更新
// session_mix / opaque_rt_nonce / opaque_session_mix / opaque_runtime_fold / opaque_thread_mix，
// 返回新的 opaque_chain。不修改 acc，也不推进 PC/steps。
static uint32_t cprisk_vm_opaque_chain_advance_i(cprisk_vm_interp_frame_t *fr,
                                                 uint32_t logical,
                                                 uint64_t imm,
                                                 uint32_t pc,
                                                 uint32_t stage) {
    const uint32_t runtime_mix = cprisk_vm_opaque_runtime_probe_i(fr, logical, pc, stage);
    const uint32_t runtime_contract =
        cprisk_vm_opaque_runtime_contract_mix_i(
            fr,
            logical,
            pc,
            stage,
            runtime_mix ^ (uint32_t)imm ^ (uint32_t)(imm >> 32u)
        );
    const uint32_t runtime_path = cprisk_vmp_avalanche32_i(
        runtime_mix ^
        runtime_contract ^
        fr->opaque_session_mix ^
        fr->opaque_clock_ns ^
        fr->opaque_port_name ^
        (uint32_t)fr->opaque_port_rc
    );
    uint32_t acc_mix = cprisk_vm_mix32_from_acc_i(
        fr->acc,
        fr->opaque_chain ^ logical ^ pc ^ (stage * 0x45D9F3Bu)
    );
    const uint32_t session_fold = cprisk_vmp_avalanche32_i(
        fr->session_mix ^
        fr->opaque_session_mix ^
        fr->opaque_runtime_fold ^
        fr->opaque_thread_mix ^
        runtime_mix ^
        runtime_contract ^
        runtime_path ^
        cprisk_vm_dispatch_bait_seed_i(fr->path_lane ^ logical, stage)
    );
    fr->session_mix = cprisk_vmp_avalanche32_i(
        fr->session_mix ^
        runtime_mix ^
        runtime_contract ^
        runtime_path ^
        fr->opaque_session_mix ^
        fr->opaque_rt_nonce ^
        cprisk_vmp_rotl32_i(fr->opaque_chain, (logical & 7u) + 1u) ^
        stage
    );
    if (fr->session_mix == 0u)
        fr->session_mix = 0x31415927u ^ logical ^ stage;
    fr->opaque_rt_nonce = cprisk_vmp_avalanche32_i(
        fr->opaque_rt_nonce ^
        runtime_mix ^
        runtime_contract ^
        session_fold ^
        (uint32_t)fr->steps ^
        logical ^
        (uint32_t)imm ^
        (uint32_t)(imm >> 32u) ^
        fr->session_mix ^
        fr->opaque_session_mix ^
        runtime_path
    );
    if (fr->opaque_rt_nonce == 0u)
        fr->opaque_rt_nonce = 0x6D2B79F5u ^ stage;
    uint32_t chain =
        fr->opaque_chain ^
        acc_mix ^
        (uint32_t)imm ^
        (uint32_t)(imm >> 32u) ^
        fr->opaque_rt_nonce ^
        runtime_mix ^
        runtime_contract ^
        runtime_path ^
        session_fold ^
        fr->session_mix ^
        fr->opaque_session_mix ^
        cprisk_vm_dispatch_bait_seed_i(stage ^ logical, fr->path_lane) ^
        cprisk_vmp_relro_bait_mix_i();
    chain = cprisk_vmp_avalanche32_i(chain);
    if (chain == 0u)
        chain = 0xA511E9B3u ^ stage;
    fr->opaque_session_mix = cprisk_vmp_avalanche32_i(
        fr->opaque_session_mix ^
        fr->session_mix ^
        runtime_mix ^
        runtime_contract ^
        runtime_path ^
        session_fold ^
        chain ^
        cprisk_vm_dispatch_bait_seed_i(fr->path_lane + stage, logical ^ (uint32_t)fr->steps)
    );
    if (fr->opaque_session_mix == 0u)
        fr->opaque_session_mix = 0xDB4F0B91u ^ stage ^ logical;
    fr->opaque_runtime_fold = cprisk_vmp_avalanche32_i(
        fr->opaque_runtime_fold ^
        chain ^
        session_fold ^
        runtime_contract ^
        runtime_path ^
        fr->session_mix ^
        fr->opaque_session_mix ^
        pc ^
        logical
    );
    fr->opaque_thread_mix = cprisk_vmp_avalanche32_i(
        fr->opaque_thread_mix ^
        chain ^
        fr->opaque_rt_nonce ^
        runtime_path ^
        fr->opaque_session_mix ^
        logical
    );
    fr->opaque_chain = chain;
    return chain;
}

// opaque 死分支判定：先无条件推进 opaque 链（即使返回 0 也会改变混淆状态），再检查一组
// 在 uint32/运行期语义下不可能成立的条件（例如 p + 0xFFFFFFFF == 0 且 p != 1）。
// 这些条件在正常的 uint32/运行期语义下均不成立，设计上不会真正跳转；保留它们是为了让
// CFG 与执行轨迹更复杂。
// syscall/mach 的失败只被编码进掩码，不会改变返回值。
static int cprisk_vm_opaque_dead_branch_i(cprisk_vm_interp_frame_t *fr,
                                          uint32_t logical,
                                          uint64_t imm,
                                          uint32_t pc,
                                          uint32_t stage) {
    const uint32_t chain = cprisk_vm_opaque_chain_advance_i(fr, logical, imm, pc, stage);
    const uint32_t rel = cprisk_vmp_relro_bait_mix_i();
    const uint32_t runtime_contract =
        cprisk_vm_opaque_runtime_contract_mix_i(
            fr,
            logical ^ (chain & 0xFFu),
            pc,
            stage,
            chain ^ rel ^ (uint32_t)imm ^ (uint32_t)(imm >> 32u)
        );
    const uint32_t runtime_path = cprisk_vmp_avalanche32_i(
        runtime_contract ^
        fr->opaque_session_mix ^
        fr->opaque_clock_ns ^
        fr->opaque_port_name ^
        (uint32_t)fr->opaque_port_rc ^
        chain
    );
    const uint32_t runtime_fold = cprisk_vmp_avalanche32_i(
        fr->opaque_runtime_fold ^
        fr->opaque_thread_mix ^
        fr->opaque_rt_nonce ^
        fr->session_mix ^
        fr->opaque_session_mix ^
        runtime_contract ^
        runtime_path ^
        rel ^
        cprisk_vm_dispatch_bait_seed_i(fr->path_lane + stage, logical)
    );
    uint32_t p = cprisk_vmp_avalanche32_i(
        chain ^
        rel ^
        runtime_fold ^
        runtime_contract ^
        fr->session_mix ^
        fr->opaque_session_mix ^
        runtime_path ^
        stage * 0x9E3779B9u ^
        (uint32_t)pc ^
        (uint32_t)(logical * 0xC2B2u)
    );
    p ^= (uint32_t)(imm ^ (imm >> 32));
    uint32_t q = cprisk_vmp_rotl32_i(
        p ^ runtime_fold ^ runtime_contract ^ fr->opaque_session_mix ^ runtime_path,
        (stage & 15u) + 1u
    ) ^ cprisk_vmp_rotr32_i(
        (uint32_t)(imm >> 11) ^ runtime_fold ^ fr->session_mix ^ fr->opaque_session_mix ^ runtime_path,
        7u
    );
    const uint32_t clock_mask =
        (fr->opaque_clock_rc == 0) ? ((fr->opaque_clock_ns & 7u) | 1u) : 0u;
    const uint32_t port_mask =
        (fr->opaque_port_name != 0u) ? ((fr->opaque_port_name & 7u) | 1u) : 0u;
    const uint32_t rc_mask =
        (fr->opaque_port_rc == 0) ? 1u : 0u;

    if (p != 0u && (p + 0xFFFFFFFFu) == 0u && p != 1u)
        return 1;
    if ((q | 0u) == 0u && q != 0u)
        return 1;
    if ((q * 2u) == 1u)
        return 1;
    if (q != 0u && q < (q - 1u))
        return 1;
    if ((p | p) < (p & p))
        return 1;
    if (clock_mask != 0u
        && cprisk_vmp_rotl32_i(runtime_path ^ runtime_fold, clock_mask & 31u)
            == cprisk_vmp_rotl32_i(runtime_path ^ runtime_fold, clock_mask & 31u) + clock_mask) {
        return 1;
    }
    if (port_mask != 0u && ((runtime_path ^ port_mask) == runtime_path))
        return 1;
    if (rc_mask != 0u && ((runtime_contract + rc_mask) == runtime_contract))
        return 1;
    if (fr->opaque_pid <= 0 && ((runtime_contract ^ fr->opaque_session_mix) & 1u) != 0u)
        return 1;
#if defined(__APPLE__)
    if (fr->opaque_port_rc == KERN_SUCCESS && fr->opaque_port_name == (uint32_t)MACH_PORT_NULL)
        return 1;
    pthread_t self = pthread_self();
    if (pthread_equal(self, self) == 0 && ((runtime_contract ^ fr->opaque_thread_mix) & 1u) != 0u)
        return 1;
    uint64_t tid_now = 0u;
    if (pthread_threadid_np(NULL, &tid_now) == 0
        && tid_now == 0u
        && ((runtime_contract ^ chain) & 2u) != 0u) {
        return 1;
    }
    struct timespec chk_ts;
    memset(&chk_ts, 0, sizeof(chk_ts));
    int chk_rc = clock_gettime(CLOCK_MONOTONIC, &chk_ts);
    if (chk_rc == 0
        && (uint32_t)chk_ts.tv_nsec >= 1000000000u
        && ((runtime_contract ^ fr->opaque_rt_nonce) & 4u) != 0u) {
        return 1;
    }
    if (((runtime_contract ^ stage ^ logical) & 3u) == 0u) {
        mach_port_t dead_port = mach_thread_self();
        kern_return_t dead_port_rc = mach_port_deallocate(mach_task_self(), dead_port);
        if (dead_port_rc == KERN_SUCCESS && dead_port == MACH_PORT_NULL)
            return 1;
    }
#endif
    uint32_t r = cprisk_vmp_avalanche32_i(
        chain ^
        fr->opaque_rt_nonce ^
        rel ^
        runtime_fold ^
        runtime_contract ^
        fr->session_mix ^
        fr->opaque_session_mix ^
        (uint32_t)fr->steps
    );
    if (r != 0u && (r + 0xFFFFFFFFu) == 0u && r != 1u)
        return 1;
    (void)fr->opaque_pid;
    (void)fr->opaque_clock_rc;
    return 0;
}

/* Opcode handlers live in \c cprisk_vm_oph_*.c; single-access materialization lives in \c cprisk_vm_oph_table.c. */

// 32 字节比较：逐字节累积差异、不提前返回（降低时序侧信道），完全相等返回 1。
static int cprisk_vm_ct_memeq32_i(const uint8_t *a, const uint8_t *b) {
    uint8_t d = 0;
    for (size_t i = 0; i < 32u; i++)
        d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0 ? 1 : 0;
}

// 构造白盒 PRF 的 32 字节输入：SHA256(acc || func_id || 状态混合值 || imm || vpc 打包)。
// 输出只用于派生副作用/掩码，不回写 acc 语义。
static void cprisk_vm_wb_sidefx_build_input_i(const cprisk_vm_interp_frame_t *fr,
                                              uint8_t logical,
                                              uint64_t imm,
                                              uint32_t pc,
                                              uint32_t hvar,
                                              uint8_t out32[32]) {
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, fr->acc, sizeof(fr->acc));
    uint8_t le64[8];
    memcpy(le64, &fr->func_id, sizeof(le64));
    cprisk_sha256_update(&ctx, le64, sizeof(le64));
    uint32_t mix =
        fr->opaque_chain ^
        fr->session_mix ^
        fr->opaque_session_mix ^
        (uint32_t)logical ^
        pc ^
        (uint32_t)fr->steps ^
        hvar;
    cprisk_sha256_update(&ctx, (const uint8_t *)&mix, sizeof(mix));
    cprisk_sha256_update(&ctx, (const uint8_t *)&imm, sizeof(imm));
    uint64_t vpc_pack = fr->vpc_a ^ (fr->vpc_b << 1u);
    cprisk_sha256_update(&ctx, (const uint8_t *)&vpc_pack, sizeof(vpc_pack));
    cprisk_sha256_final(&ctx, out32);
}

// 决定本步是否执行白盒副作用：m3_opaque 时每 32 步一次；常规每 WB_SIDE_PERIOD 步一次；
// RET/HALT/VM_CALL_FUNC 边界强制执行（让收尾状态也被绑定）。
static int cprisk_vm_wb_sidefx_should_run_i(const cprisk_vm_interp_frame_t *fr, uint8_t logical) {
    if (fr->m3_opaque != 0u) {
        if ((fr->steps & 31u) == 0u)
            return 1;
    }
    if ((fr->steps % CPRISK_VM_WB_SIDE_PERIOD) == 0u && fr->steps != 0u)
        return 1;
    switch (logical) {
    case CPRISK_VM_OP_RET:
    case CPRISK_VM_OP_HALT:
    case CPRISK_VM_OP_VM_CALL_FUNC:
        return 1;
    default:
        return 0;
    }
}

// 把白盒输出拆成 4 个 32 位字，分别混入 opaque_chain / opaque_session_mix / opaque_rt_nonce
// 与 session_mix，并保证 chain/session 非零。不改变 acc。
static void cprisk_vm_wb_sidefx_apply_out_i(cprisk_vm_interp_frame_t *fr,
                                            uint8_t logical,
                                            const uint8_t wb_out[32]) {
    const uint32_t w0 = cprisk_read_le_u32_i(wb_out);
    const uint32_t w1 = cprisk_read_le_u32_i(wb_out + 4u);
    const uint32_t w2 = cprisk_read_le_u32_i(wb_out + 8u);
    const uint32_t w3 = cprisk_read_le_u32_i(wb_out + 12u);
    fr->opaque_chain = cprisk_vmp_avalanche32_i(
        fr->opaque_chain ^ w0 ^ ((uint32_t)logical * 0x9E3779B9u) ^ (uint32_t)(fr->steps * 0x27D4EB2Du)
    );
    fr->opaque_session_mix = cprisk_vmp_avalanche32_i(fr->opaque_session_mix ^ w1 ^ fr->session_mix ^ w3);
    fr->opaque_rt_nonce = cprisk_vmp_avalanche32_i(
        fr->opaque_rt_nonce ^ w2 ^ fr->opaque_chain ^ (uint32_t)(fr->func_id >> 32u)
    );
    fr->session_mix = cprisk_vmp_avalanche32_i(
        fr->session_mix ^ w3 ^ cprisk_vmp_rotl32_i(w1, (logical & 7u) + 1u) ^ fr->opaque_chain
    );
    if (fr->opaque_chain == 0u)
        fr->opaque_chain = 0x31415927u ^ (uint32_t)logical;
    if (fr->session_mix == 0u)
        fr->session_mix = 0x7F4A7C15u ^ (uint32_t)fr->steps;
}

// 白盒求值失败时的降级：只取输入摘要的两个字混入 chain/session，保证状态仍在推进。
static void cprisk_vm_wb_sidefx_fallback_i(cprisk_vm_interp_frame_t *fr,
                                           uint8_t logical,
                                           const uint8_t digest[32]) {
    const uint32_t w0 = cprisk_read_le_u32_i(digest);
    const uint32_t w1 = cprisk_read_le_u32_i(digest + 8u);
    fr->opaque_chain = cprisk_vmp_avalanche32_i(fr->opaque_chain ^ w0 ^ (uint32_t)logical);
    fr->session_mix = cprisk_vmp_avalanche32_i(fr->session_mix ^ w1 ^ (uint32_t)fr->steps);
}

// acc ^= xorv（32 字节）；XOR 自逆，因此同一掩码应用两次会恢复原值。
static void cprisk_vm_xor_acc32_i(uint8_t acc[32], const uint8_t xorv[32]) {
    for (size_t i = 0u; i < 32u; i++)
        acc[i] ^= xorv[i];
}

/** Derive a full acc XOR mask from white-box output (diffusion; mask is self-inverse under XOR). */
// 从白盒输出派生 32 字节 XOR 掩码：相邻字节与位置常量混合，掩码在 XOR 下自逆。
static void cprisk_vm_wb_derive_xor_mask_from_wb_out_i(const uint8_t wb_out[32], uint8_t mask[32]) {
    for (size_t i = 0u; i < 32u; i++) {
        const size_t j = (i + 13u) % 32u;
        const size_t k = (i + 29u) % 32u;
        mask[i] = (uint8_t)(wb_out[i] ^ wb_out[j] ^ wb_out[k] ^ (uint8_t)(i * 0x1Bu));
    }
}

// 只有 XOR_MIX 在 acc 语义路径上是 XOR 线性的，掩码应用两次可精确抵消；
// 其他 opcode 若做同样的环绕会改变最终语义。
static int cprisk_vm_logical_wb_xor_surround_eligible_i(uint8_t logical) {
    /** Only \c CPRISK_VM_OP_XOR_MIX is XOR-linear on the acc semantic path (mask cancels after handler). */
    return logical == CPRISK_VM_OP_XOR_MIX ? 1 : 0;
}

// opcode 分发的白盒包装层：
// - 非 XOR_MIX：直接调用 materialized handler，再由 post_handler 做周期性白盒副作用；
// - XOR_MIX：先用当前帧状态跑 domain-7 白盒 PRF，派生自逆 XOR 掩码并施加到 acc，
//   执行真实 handler，再用同一掩码还原。由于 XOR_MIX 本身 XOR 线性，最终语义不变，
//   但 acc 的中间值与会话绑定；vm_wb_inline_done 防止 post_handler 重复执行。
// 返回 handler 的 flow（CONTINUE/LEAVE）。
cprisk_vm_flow_t cprisk_vm_dispatch_leaf_wb_wrapped_i(cprisk_vm_interp_frame_t *fr,
                                                      uint8_t op_raw,
                                                      uint8_t logical,
                                                      uint64_t imm,
                                                      uint32_t pc,
                                                      uint32_t hvar,
                                                      cprisk_vm_oph_fn materialized) {
    /**
     * Full domain-7 evaluation + opaque/session updates run on every opcode for \c CPRISK_VM_OP_XOR_MIX:
     * pre-handler PRF drives a self-inverse acc XOR mask (semantics unchanged), so accumulator effects
     * depend on session-bound white-box material. Other opcodes keep periodic WB in \c cprisk_vm_oph_post_handler_i
     * to limit SHA256+PRF cost on hot paths.
     */
    if (cprisk_vm_logical_wb_xor_surround_eligible_i(logical) == 0) {
        const cprisk_vm_flow_t inner = materialized(fr, op_raw, logical, imm, pc, hvar);
        // 非 XOR_MIX 路径：post_handler 可自由执行周期性白盒副作用，因此把 inline 标志清零。
        fr->vm_wb_inline_done = 0u;
        return cprisk_vm_oph_post_handler_i(fr, logical, imm, pc, hvar, inner);
    }

    uint8_t wb_in[32];
    uint8_t wb_out[32];
    uint8_t mask[32];
    int surround = 0;

    cprisk_vm_wb_sidefx_build_input_i(fr, logical, imm, pc, hvar, wb_in);
    const int wbr = cprisk_whitebox_evaluate_domain(CPRISK_VM_WB_HANDLER_SIDE_DOMAIN, wb_in, wb_out);
    if (wbr == 0) {
        cprisk_vm_wb_derive_xor_mask_from_wb_out_i(wb_out, mask);
        cprisk_vm_xor_acc32_i(fr->acc, mask);
        surround = 1;
    }
    const cprisk_vm_flow_t inner = materialized(fr, op_raw, logical, imm, pc, hvar);
    if (surround != 0) {
        cprisk_vm_xor_acc32_i(fr->acc, mask);
        cprisk_secure_zero(mask, sizeof(mask));
    }
    if (wbr == 0)
        cprisk_vm_wb_sidefx_apply_out_i(fr, logical, wb_out);
    else
        cprisk_vm_wb_sidefx_fallback_i(fr, logical, wb_in);
    cprisk_secure_zero(wb_in, sizeof(wb_in));
    cprisk_secure_zero(wb_out, sizeof(wb_out));
    fr->vm_wb_inline_done = 1u;
    return cprisk_vm_oph_post_handler_i(fr, logical, imm, pc, hvar, inner);
}

// 判断本步是否重算字节码段 SHA256：
// - 未启用直接返回 0；
// - 第 1 步强制检查，尽早发现运行期补丁；
// - RET/HALT/VM_CALL_FUNC/BRANCH_IND 边界强制检查；
// - 其余按 256 步周期，且距上次成功哈希至少 32 步（避免重复计算）。
static int cprisk_vm_bc_seg_hash_should_check_i(const cprisk_vm_interp_frame_t *fr, uint8_t logical) {
    if (fr->bc_seg_hash_enabled == 0u)
        return 0;
    if (fr->steps == 0u)
        return 0;
    /** One early check after the first retired step catches runtime patch before the first period boundary. */
    if (fr->steps == 1u)
        return 1;
    switch (logical) {
    case CPRISK_VM_OP_RET:
    case CPRISK_VM_OP_HALT:
    case CPRISK_VM_OP_VM_CALL_FUNC:
    case CPRISK_VM_OP_BRANCH_IND:
        return 1;
    default:
        break;
    }
    if ((fr->steps % CPRISK_VM_BC_HASH_PERIOD) != 0u)
        return 0;
    if (fr->bc_last_hash_step != 0u
        && (uint32_t)fr->steps - fr->bc_last_hash_step < CPRISK_VM_BC_HASH_MIN_INTERVAL) {
        return 0;
    }
    return 1;
}

/* Shared post-handler boundary. Keep the existing callers and operation order:
 * bytecode check, auxiliary step, then optional white-box side effects.
 * noinline preserves an out-of-line code region; it does not fix its byte size
 * across toolchains or optimization levels. V1 omits this region; gated V2
 * measures and covers its full linked extent as roster kind 4. */
__attribute__((noinline))
// 所有 opcode handler 的统一后处理边界，顺序固定为：字节码哈希检查 → aux_step → 可选白盒副作用。
// 哈希失配时写 INVALID_BYTECODE/POISON_BYTECODE、污染 acc 并返回 LEAVE（fail-closed）。
// vm_wb_inline_done 为真时跳过白盒段（XOR_MIX 已在包装层执行过）。
// noinline 保持独立代码区域，供 CPSV v2 按 span 度量；不保证跨工具链的字节大小。
cprisk_vm_flow_t cprisk_vm_oph_post_handler_i(cprisk_vm_interp_frame_t *fr,
                                              uint8_t logical,
                                              uint64_t imm,
                                              uint32_t pc,
                                              uint32_t hvar,
                                              cprisk_vm_flow_t inner) {
    if (!fr || !fr->out)
        return inner;

    if (cprisk_vm_bc_seg_hash_should_check_i(fr, logical)) {
        uint8_t now[32];
        if (fr->code && fr->blen > 0u)
            cprisk_sha256(fr->code, (size_t)fr->blen, now);
        else
            memset(now, 0, sizeof(now));
        const int ok = cprisk_vm_ct_memeq32_i(now, fr->bc_seg_hash_expect);
        cprisk_secure_zero(now, sizeof(now));
        if (!ok) {
            fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            cprisk_vm_self_fail_acc_i(fr->acc, fr->func_id);
            return CPRISK_VM_FLOW_LEAVE;
        }
        fr->bc_last_hash_step = (uint32_t)fr->steps;
    }

    cprisk_vm_aux_step_i(fr, logical, imm, pc, hvar);

    if (fr->vm_wb_inline_done != 0u) {
        return inner;
    }

    if (cprisk_vm_wb_sidefx_should_run_i(fr, logical)) {
        uint8_t wb_in[32];
        uint8_t wb_out[32];
        cprisk_vm_wb_sidefx_build_input_i(fr, logical, imm, pc, hvar, wb_in);
        const int wbr = cprisk_whitebox_evaluate_domain(CPRISK_VM_WB_HANDLER_SIDE_DOMAIN, wb_in, wb_out);
        if (wbr == 0)
            cprisk_vm_wb_sidefx_apply_out_i(fr, logical, wb_out);
        else
            cprisk_vm_wb_sidefx_fallback_i(fr, logical, wb_in);
        cprisk_secure_zero(wb_in, sizeof(wb_in));
        cprisk_secure_zero(wb_out, sizeof(wb_out));
    }

    return inner;
}

// 逻辑 opcode 的三级分发：
// - POISON（0xFF）→ 毒化 handler；
// - >= 24（OPH 表长）→ unknown handler；
// - 其余 → 按族物化 handler（不暴露明文全局函数指针表）。
static cprisk_vm_flow_t cprisk_vm_dispatch_oph_core_i(cprisk_vm_interp_frame_t *fr,
                                                      uint8_t op_raw,
                                                      uint8_t logical,
                                                      uint64_t imm,
                                                      uint32_t pc,
                                                      uint32_t hvar) {
    if (logical == CPRISK_VM_OP_POISON)
        return cprisk_vm_oph_poison(fr, op_raw, logical, imm, pc, hvar);
    if (logical >= CPRISK_VM_OPH_TABLE_LEN)
        return cprisk_vm_oph_unknown(fr, op_raw, logical, imm, pc, hvar);
    return cprisk_vm_dispatch_oph_materialized_i(fr, op_raw, logical, imm, pc, hvar);
}

// 主解释循环 A（lane 0/默认路径）。每次迭代完成一条指令：取指 → 解密/解码 → 语义分发 → 执行。
// 不变量：handler 负责推进 encoded_pc 与 steps；本循环只做预算检查、死分支/加固钩子与 flow 判定。
// 退出条件：预算用尽、decode/边界校验失败（break，status 保持 STEP_LIMIT 或已写错误），
// 或 handler 返回 CPRISK_VM_FLOW_LEAVE（goto vm_leave_a）。退出后统一走 lane0 finish。
void cprisk_vm_interp_loop_a(struct cprisk_vm_interp_frame *fr)
{
    // 步数预算：step_limit_cap 在 prepare 阶段被随机收紧；用尽即结束，防止死循环/DoS。
    while (fr->steps < fr->step_limit_cap) {
        // 每指令重置：默认由 post_handler 决定是否跑白盒；XOR_MIX 包装层会把它置 1。
        fr->vm_wb_inline_done = 0u;
        // 按 lane 调用不同的标记函数，仅用于布局与自检形状。
        if (fr->path_lane == 0u) {
            cprisk_vm_interp_core_marker0_i();
        } else if (fr->path_lane == 1u) {
            cprisk_vm_interp_core_marker1_i();
        } else {
            cprisk_vm_interp_core_marker2_i();
        }
        if (fr->path_lane == 1u) {
            volatile uint32_t pl = (uint32_t)fr->func_id ^ (uint32_t)(fr->steps * 0xB5297A4Du);
            (void)(pl ^ pl);
        } else if (fr->path_lane == 2u) {
            volatile uint32_t pl2 = (uint32_t)(fr->func_id >> 33) ^ (uint32_t)fr->steps;
            (void)(pl2 | 0u);
        }
        // m3_opaque：在取指前插入 3 个恒假的 opaque 分支。条件理论上不可达；
        // 即使可达也只是执行诱饵后 continue，且不推进 steps。
        if (fr->path_lane != 1u) {
            if (fr->m3_opaque != 0u) {
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0x11u,
                        fr->encoded_pc ^ fr->func_id,
                        (uint32_t)fr->steps,
                        0x11u
                    )) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, 0x11u);
                    continue;
                }
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0x22u,
                        fr->encoded_pc + ((uint64_t)fr->session_mix << 17u),
                        (uint32_t)fr->steps,
                        0x22u
                    )) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_bait_xor_i(fr->acc, (fr->bh->reserved >> 8) & 0xFFu, 0x22u);
                    continue;
                }
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0x33u,
                        fr->encoded_pc ^ (uint64_t)fr->opaque_chain,
                        (uint32_t)fr->steps,
                        0x33u
                    )) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_bait_add_i(fr->acc, (fr->bh->reserved >> 16) & 0xFFu, 0x33u);
                    continue;
                }
            } else if (fr->m3_dead != 0u) {
                volatile uint32_t ds = (fr->bh->reserved >> 16) & 0xFFu;
                if ((ds * 2u) == 1u)
                    cprisk_vm_m3_dead_bait_roll_i(fr->acc, ds);
            }
        }

        // 取指前先解码 encoded_pc，并检查 [pc, pc+9) 落在函数正文内；
        // 任一失败都置 INVALID_BYTECODE/POISON_BYTECODE 并退出循环。
        uint32_t pc = 0u;
        if (!cprisk_vm_decode_pc_i(fr->bh, fr->encoded_pc, fr->vpc_a, fr->vpc_b, &pc, fr->out)) {
            break;
        }
        if ((uint64_t)pc + CPRISK_VM_INSN_WIDTH > (uint64_t)fr->blen) {
            fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            break;
        }

        if (fr->path_lane == 1u) {
            if (fr->m3_opaque != 0u) {
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0x11u,
                        fr->encoded_pc ^ fr->func_id,
                        pc,
                        0x41u
                    )) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, 0x11u);
                    continue;
                }
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0x22u,
                        fr->encoded_pc + ((uint64_t)fr->session_mix << 17u),
                        pc,
                        0x42u
                    )) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_bait_xor_i(fr->acc, (fr->bh->reserved >> 8) & 0xFFu, 0x22u);
                    continue;
                }
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0x33u,
                        fr->encoded_pc ^ (uint64_t)fr->opaque_chain,
                        pc,
                        0x43u
                    )) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_bait_add_i(fr->acc, (fr->bh->reserved >> 16) & 0xFFu, 0x33u);
                    continue;
                }
            } else if (fr->m3_dead != 0u) {
                volatile uint32_t ds = (fr->bh->reserved >> 16) & 0xFFu;
                if ((ds * 2u) == 1u)
                    cprisk_vm_m3_dead_bait_roll_i(fr->acc, ds);
            }
        }

        if (fr->m3_opaque != 0u) {
            if (cprisk_vm_opaque_dead_branch_i(fr, 0x44u, fr->encoded_pc ^ fr->blen, pc, 0x44u)) {
                if (fr->m3_dead != 0u)
                    cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, 0x44u);
                continue;
            }
        }

        // 取指与解码流水线：wire opcode 先解 opcode keystream，再叠加 fault 字节，
        // 经 dispatch 类别表映射为逻辑 opcode；立即数按同样方式解密后再交给 handler。
        const uint8_t op_raw = fr->code[pc];
        uint8_t op = op_raw;
            const uint32_t pc_index = pc / CPRISK_VM_INSN_WIDTH;
        if (fr->enc_op != 0u) {
            op = (uint8_t)(op_raw ^ cprisk_vmp_opcode_mix_byte_i(fr->func_id, pc_index, fr->opcode_seed_root));
        }
        // fault_mask == 0 时这一步是恒等变换（无故障哨兵）。
        op ^= cprisk_vmp_opcode_fault_byte_i(fr->decode_fault_mask, fr->func_id, pc_index, op_raw);
        fr->out->last_opcode = (uint32_t)op;
        // 类别表映射：wire opcode → logical opcode；未覆盖项返回 POISON。
        const uint8_t logical = cprisk_vm_dispatch_lookup(fr, (uint32_t)op & 0xFFu, pc_index);
        fr->out->last_dispatch_class = (uint32_t)logical;
        // 指令格式固定为 1 字节 opcode + 8 字节小端立即数；加密与故障掩码都在这里解开。
        uint64_t imm = cprisk_read_le_u64_i(fr->code + pc + 1u);
        if (fr->enc_imm != 0u) {
            imm ^= cprisk_vmp_imm_mask_u64_i(fr->func_id, pc_index, fr->imm_seed_root);
        }
        imm ^= cprisk_vmp_imm_fault_mask_u64_i(fr->decode_fault_mask, fr->func_id, pc_index);
        // handler 变体号：与 semantic_family 的低 2 位混合，决定等价实现分支。
        const uint32_t hvar =
            cprisk_vm_handler_variant_i(fr->bh->reserved, fr->func_id, fr->steps, (uint32_t)op, imm)
            ^ ((fr->semantic_family & 0x3u) << 1u);

        if (fr->m3_opaque != 0u) {
            if (cprisk_vm_opaque_dead_branch_i(fr, (uint32_t)logical, imm, pc, 0x50u)) {
                if (fr->m3_dead != 0u)
                    cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, (uint32_t)op + 0x50u);
                continue;
            }
        }

        // 反符号执行钩子：只在启用 dead handler 或 heavy 模式时维护 trace 状态；
        // 这些状态不会改变 acc 语义。
        if (fr->m3_dead != 0u || fr->vm_anti_symbolic_heavy) {
            cprisk_vm_trace_sidefx_i(fr, (uint32_t)logical, imm, pc, hvar);
        }

        if (fr->vm_anti_symbolic_heavy) {
            cprisk_vm_history_acc_mix_i(fr, pc, hvar);
            cprisk_vm_antisy_equiv_fork_i(fr, pc, hvar);
            cprisk_vm_diophantine_opaque_i(fr, pc, hvar);
        }

        // 加固钩子顺序：解密当前块 → 完整性检查点 → 周期性的路径爆炸/假依赖/CFF 迁移/校验。
        // 这些模块保证失败不崩溃；与语义相关的失败通过 poison/status 体现。
        /* -- Integrated hardening hooks -- */
        /* Task 3: verify bytecode block integrity before fetch */
        cprisk_vm_hardening_ondemand_decrypt(fr, pc);
        /* Task 1: update integrity state after decode */
        cprisk_vm_hardening_integrity_checkpoint(fr, pc, (uint32_t)logical);
        /* Task 4: path explosion checkpoint (periodic) */
        if ((fr->steps & 0xFu) == 0u)
            cprisk_vm_hardening_path_explosion(fr, pc);
        /* Task 2: fake dependency injection (periodic) */
        if ((fr->steps & 0x7u) == 0u)
            cprisk_vm_hardening_fake_dep_inject(fr, pc, hvar);
        /* Task 5: CFF transition (every 32 steps on fall-through) */
        if ((fr->steps & 0x1Fu) == 0u)
            cprisk_vm_hardening_cff_transition(fr, pc, pc + CPRISK_VM_INSN_WIDTH, 0);
        /* Task 5: CFF integrity verify (every 128 steps) */
        if ((fr->steps & 0x7Fu) == 0u)
            cprisk_vm_hardening_cff_verify(fr);
        /* VM sync barrier: inject external data dependency every 64 steps.
         * If the watchdog appears stuck (counter never advances), this is a
         * strong indicator that we are running inside unidbg — OR the flag
         * into emulator_flags and let the emulator_is_hostile check in the
         * hardening layer poison the result. */
        // 同步屏障每 64 步引入一次外部数据依赖；若 watchdog 计数长期不动，
        // 说明执行环境可能在批量指令模拟（如 unidbg），记录 emulator 标志并污染完整性链。
        if (cprisk_vm_sync_barrier_step(&fr->sync_barrier_ctx, fr->acc, pc)) {
            if (cprisk_vm_sync_barrier_watchdog_stuck(&fr->sync_barrier_ctx)) {
                fr->emulator_flags |= CPRISK_EMU_FLAG_WATCHDOG_STUCK;
                /* Poison the integrity chain so the final result is tainted. */
                fr->vm_integrity_checksum ^= 0xDEADBEEFCAFEBABEULL;
                fr->vm_integrity_corrupted = 1;
            }
        }

        {
            // handler 自己负责推进 encoded_pc/steps；这里只看它是否要求退出。
            // CONTINUE 回到循环顶部；LEAVE 跳到统一收尾。
            const cprisk_vm_flow_t flow =
                cprisk_vm_dispatch_oph_core_i(fr, op, logical, imm, pc, hvar);
            if (flow == CPRISK_VM_FLOW_LEAVE)
                goto vm_leave_a;
            continue;
        }

    }
// 统一退出点：合并 bank、导出 vregs/steps，并做 lane0 的白盒收尾。
vm_leave_a:
    cprisk_vm_interp_finish_run_lane0_i(fr);
}


// 主解释循环 B（lane 1/2）。与 loop A 语义相同，但取指顺序（先 imm 后 opcode）、
// 死分支标签、加固钩子间隔与布局分散调用都不同，用于抵抗跨 lane 的差分分析。
// 退出条件与 loop A 一致；退出后按 lane 选择 lane1 或 lane2 的 finish。
static void cprisk_vm_interp_loop_b(struct cprisk_vm_interp_frame *fr)
{
    // 与 loop A 相同的步数预算；lane B 的预算同样来自 prepare 阶段的随机收紧。
    while (fr->steps < fr->step_limit_cap) {
        // 与 loop A 相同的每指令白盒状态重置。
        fr->vm_wb_inline_done = 0u;
        // lane 标记调用与 loop A 相同，仅布局用途。
        if (fr->path_lane == 0u) {
            cprisk_vm_interp_core_marker0_i();
        } else if (fr->path_lane == 1u) {
            cprisk_vm_interp_core_marker1_i();
        } else {
            cprisk_vm_interp_core_marker2_i();
        }
        /* Loop B: volatile dead computation pattern differs from Loop A */
        if (fr->path_lane == 1u) {
            volatile uint32_t pl = (uint32_t)fr->func_id ^ (uint32_t)(fr->steps * 0xB5297A4Du);
            (void)(pl & (~pl));
        } else if (fr->path_lane == 2u) {
            volatile uint32_t pl2 = (uint32_t)(fr->func_id >> 33) ^ (uint32_t)fr->steps;
            (void)(pl2 ^ pl2);
        }
        /* Loop B: different dead branch tags (0xA1, 0xB2, 0xC3) vs Loop A (0x11, 0x22, 0x33) */
        // 与 loop A 同语义的 m3_opaque 死分支，但标签改为 0xA1/0xB2/0xC3。
        if (fr->path_lane != 1u) {
            if (fr->m3_opaque != 0u) {
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0xA1u,
                        fr->encoded_pc ^ fr->func_id,
                        (uint32_t)fr->steps,
                        0xA1u
                    )) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, 0xA1u);
                    continue;
                }
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0xB2u,
                        fr->encoded_pc + ((uint64_t)fr->session_mix << 17u),
                        (uint32_t)fr->steps,
                        0xB2u
                    )) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_bait_xor_i(fr->acc, (fr->bh->reserved >> 8) & 0xFFu, 0xB2u);
                    continue;
                }
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0xC3u,
                        fr->encoded_pc ^ (uint64_t)fr->opaque_chain,
                        (uint32_t)fr->steps,
                        0xC3u
                    )) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_bait_add_i(fr->acc, (fr->bh->reserved >> 16) & 0xFFu, 0xC3u);
                    continue;
                }
            } else if (fr->m3_dead != 0u) {
                volatile uint32_t ds = (fr->bh->reserved >> 16) & 0xFFu;
                if ((ds * 2u) == 1u)
                    cprisk_vm_m3_dead_bait_roll_i(fr->acc, ds);
            }
        }

        // 解码 encoded_pc 并检查指令边界，规则与 loop A 相同。
        uint32_t pc = 0u;
        if (!cprisk_vm_decode_pc_i(fr->bh, fr->encoded_pc, fr->vpc_a, fr->vpc_b, &pc, fr->out)) {
            break;
        }
        if ((uint64_t)pc + CPRISK_VM_INSN_WIDTH > (uint64_t)fr->blen) {
            fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            break;
        }

        /* Loop B: path_lane 1 dead branches with different tags (0xA1/0xB2/0xC3) vs Loop A (0x11/0x22/0x33) */
        if (fr->path_lane == 1u) {
            if (fr->m3_opaque != 0u) {
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0xA1u,
                        fr->encoded_pc ^ fr->func_id,
                        pc,
                        0xA1u
                    )) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, 0xA1u);
                    continue;
                }
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0xB2u,
                        fr->encoded_pc + ((uint64_t)fr->session_mix << 17u),
                        pc,
                        0xB2u
                    )) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_bait_xor_i(fr->acc, (fr->bh->reserved >> 8) & 0xFFu, 0xB2u);
                    continue;
                }
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0xC3u,
                        fr->encoded_pc ^ (uint64_t)fr->opaque_chain,
                        pc,
                        0xC3u
                    )) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_bait_add_i(fr->acc, (fr->bh->reserved >> 16) & 0xFFu, 0xC3u);
                    continue;
                }
            } else if (fr->m3_dead != 0u) {
                volatile uint32_t ds = (fr->bh->reserved >> 16) & 0xFFu;
                if ((ds * 2u) == 1u)
                    cprisk_vm_m3_dead_bait_roll_i(fr->acc, ds);
            }
        }

        /* Loop B: after-decode dead branch tag 0xD4 vs Loop A 0x44 */
        if (fr->m3_opaque != 0u) {
            if (cprisk_vm_opaque_dead_branch_i(fr, 0xD4u, fr->encoded_pc ^ fr->blen, pc, 0xD4u)) {
                if (fr->m3_dead != 0u)
                    cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, 0xD4u);
                continue;
            }
        }

        /*
         * Loop B: alternate fetch/decode path — load immediate first, then opcode (semantically identical;
         * differs from loop A micro-order for static analysis / symbolic tooling).
         */
        // loop B 特有：先取 immediate、再取 opcode（与 loop A 的微顺序相反），
        // 并用一个 volatile 派生存量阻止优化器把两条路径合并。
        volatile uint64_t loop_b_fetch_tag = fr->encoded_pc ^ (fr->steps * 0x5F3759DFu);
        (void)loop_b_fetch_tag;
        // 与 loop A 相同的 immediate 解密/故障注入，只是发生顺序更早。
        uint64_t imm = cprisk_read_le_u64_i(fr->code + pc + 1u);
        const uint32_t pc_index = pc / CPRISK_VM_INSN_WIDTH;
        if (fr->enc_imm != 0u) {
            imm ^= cprisk_vmp_imm_mask_u64_i(fr->func_id, pc_index, fr->imm_seed_root);
        }
        imm ^= cprisk_vmp_imm_fault_mask_u64_i(fr->decode_fault_mask, fr->func_id, pc_index);
        // 与 loop A 相同的 opcode 解密/故障注入流程，只是排在 immediate 之后。
        const uint8_t op_raw = fr->code[pc];
        uint8_t op = op_raw;
        if (fr->enc_op != 0u) {
            op = (uint8_t)(op_raw ^ cprisk_vmp_opcode_mix_byte_i(fr->func_id, pc_index, fr->opcode_seed_root));
        }
        // fault_mask 为 0 时保持恒等。
        op ^= cprisk_vmp_opcode_fault_byte_i(fr->decode_fault_mask, fr->func_id, pc_index, op_raw);
        fr->out->last_opcode = (uint32_t)op;
        // 类别表映射与 loop A 相同；缓存按 32 项段复用。
        const uint8_t logical = cprisk_vm_dispatch_lookup(fr, (uint32_t)op & 0xFFu, pc_index);
        fr->out->last_dispatch_class = (uint32_t)logical;
        // 与 loop A 相同的 handler 变体派生。
        const uint32_t hvar =
            cprisk_vm_handler_variant_i(fr->bh->reserved, fr->func_id, fr->steps, (uint32_t)op, imm)
            ^ ((fr->semantic_family & 0x3u) << 1u);

        /* Loop B: after-dispatch dead branch tag 0xE5 vs Loop A 0x50 */
        if (fr->m3_opaque != 0u) {
            if (cprisk_vm_opaque_dead_branch_i(fr, (uint32_t)logical, imm, pc, 0xE5u)) {
                if (fr->m3_dead != 0u)
                    cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, (uint32_t)op + 0xE5u);
                continue;
            }
        }

        if (fr->m3_dead != 0u || fr->vm_anti_symbolic_heavy) {
            cprisk_vm_trace_sidefx_i(fr, (uint32_t)logical, imm, pc, hvar);
        }

        if (fr->vm_anti_symbolic_heavy) {
            cprisk_vm_history_acc_mix_i(fr, pc, hvar);
            cprisk_vm_antisy_equiv_fork_i(fr, pc, hvar);
            cprisk_vm_diophantine_opaque_i(fr, pc, hvar);
        }

        cprisk_vm_interp_loop_b_cluster_spread_i(logical);

        /* -- Loop B: Integrated hardening hooks (different order and intervals from Loop A) -- */
        /* Task 3: verify bytecode block integrity before fetch */
        cprisk_vm_hardening_ondemand_decrypt(fr, pc);
        /* Task 1: update integrity state after decode */
        cprisk_vm_hardening_integrity_checkpoint(fr, pc, (uint32_t)logical);
        /* Loop B: cff_transition every 48 steps (vs Loop A: path_explosion every 16 steps) */
        if ((fr->steps & 0x2Fu) == 0u)
            cprisk_vm_hardening_cff_transition(fr, pc, pc + CPRISK_VM_INSN_WIDTH, 0);
        /* Loop B: path_explosion every 24 steps (vs Loop A: every 16 steps) */
        if ((fr->steps & 0x17u) == 0u)
            cprisk_vm_hardening_path_explosion(fr, pc);
        /* Loop B: fake_dep every 12 steps (vs Loop A: every 8 steps) */
        if ((fr->steps & 0xBu) == 0u)
            cprisk_vm_hardening_fake_dep_inject(fr, pc, hvar);
        /* Loop B: CFF integrity verify every 192 steps (vs Loop A: every 128 steps) */
        if ((fr->steps & 0xBFu) == 0u)
            cprisk_vm_hardening_cff_verify(fr);

        {
            // 与 loop A 相同：由 handler 推进状态，本循环只处理 CONTINUE/LEAVE。
            const cprisk_vm_flow_t flow =
                cprisk_vm_dispatch_oph_core_i(fr, op, logical, imm, pc, hvar);
            if (flow == CPRISK_VM_FLOW_LEAVE)
                goto vm_leave_b;
            continue;
        }

    }
// 统一退出点：lane1 走 lane1 finish，其余（lane2）走 lane2 finish。
vm_leave_b:
    if (fr->path_lane == 1u)
        cprisk_vm_interp_finish_run_lane1_i(fr);
    else
        cprisk_vm_interp_finish_run_lane2_i(fr);
}

#if CPRISK_VM_THREADED_DISPATCH
// 线程化 lane 调度实现（cprisk_thread_run_a_i/b_i 及各 opcode 线程体）；仅在部署开关打开时编译。
#include "cprisk_vm_threaded.inc"
#endif

// 为一次 run 建立解释器帧：选定函数入口、恢复 VPC/鉴权种子、校验自检，然后初始化
// 64 字节 acc/aux、vreg、opaque 状态、加固模块与同步屏障。成功返回 1 并填满 fr；
// 字段速览：acc/acc_aux 是 32+32 双 bank 累加器；vregs 是 8 个虚拟 64 位寄存器；
// encoded_pc 是加密 PC（取指前 decode，handler 推进后重新 encode）；session_mix 是进程级
// 会话种子；opaque_chain 是逐步推进的混淆链（不直接进入 acc）；path_lane 选择 loop A/B。
// 任何 ABI/布局/自检失败返回 0，out->status/poison_flags 已写好（调用方直接返回，不再执行）。
static int cprisk_vm_prepare_program_i(const struct mach_header_64 *hdr,
                                       const uint8_t *d_sec,
                                       const cprisk_vmp_dispatch_header_t *dhdr,
                                    const uint8_t *b_sec,
                                    unsigned long bsz,
                                    const cprisk_vmp_bytecode_header_t *bh,
                                    uint32_t path_lane,
                                    uint64_t func_id,
                                    uint8_t acc[32],
                                       cprisk_vm_run_result_t *out,
                                       cprisk_vm_interp_frame_t *fr) {
    const size_t bc_hdr_total = cprisk_vmp_bytecode_header_total_bytes_i(bh);
    const size_t entry_stride = cprisk_vmp_bytecode_entry_stride_i(bh);

    uint64_t vpc_a = 1u;
    uint64_t vpc_b = 0u;
    cprisk_vmp_read_vpc_affine_i(b_sec, bh, func_id, &vpc_a, &vpc_b);

    // 选择入口：跳过与头部/入口表重叠或越界的描述符，按 function_id 精确匹配。
    const cprisk_vmp_bytecode_entry_t *selected = NULL;
    const uint64_t table_end =
        (uint64_t)bc_hdr_total + (uint64_t)bh->entry_count * (uint64_t)entry_stride;
    for (uint32_t i = 0; i < bh->entry_count; i++) {
        const uint8_t *ep = b_sec + bc_hdr_total + (size_t)i * entry_stride;
        const cprisk_vmp_bytecode_entry_t *entry = (const cprisk_vmp_bytecode_entry_t *)(const void *)ep;
        const uint64_t off = entry->bytecode_offset;
        const uint64_t len = entry->bytecode_length;
        if (off < table_end)
            continue;
        if (off + len > bsz)
            continue;
        if (entry->function_id == func_id) {
            selected = entry;
            break;
        }
    }
    if (!selected) {
        out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
        out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        cprisk_vm_wb_finalize_i(out, acc);
        return 0;
    }

    // 每入口 VPC 覆盖全局 vpc_a/vpc_b；掩码同样由 func_id 与固定域常量派生。
    if ((bh->reserved & CPRISK_VMP_BC_FLAG_PER_ENTRY_VPC) != 0u) {
        const uint8_t *selp = (const uint8_t *)selected;
        uint64_t pe_raw_a = cprisk_read_le_u64_i(selp + sizeof(cprisk_vmp_bytecode_entry_t));
        uint64_t pe_raw_b = cprisk_read_le_u64_i(selp + sizeof(cprisk_vmp_bytecode_entry_t) + 8u);
        /* Derive XOR mask for per-entry VPC decryption */
        uint64_t pe_mask_state = func_id + UINT64_C(0x53504556);
        uint64_t pe_mask_a = cprisk_splitmix64_next_i(&pe_mask_state);
        pe_mask_a = (pe_mask_a << 32) | cprisk_splitmix64_next_i(&pe_mask_state);
        uint64_t pe_mask_b = cprisk_splitmix64_next_i(&pe_mask_state);
        pe_mask_b = (pe_mask_b << 32) | cprisk_splitmix64_next_i(&pe_mask_state);
        vpc_a = pe_raw_a ^ pe_mask_a;
        vpc_b = pe_raw_b ^ pe_mask_b;
    }

    const uint8_t *code = b_sec + selected->bytecode_offset;
    uint32_t blen = selected->bytecode_length;
    uint64_t encoded_pc = 0u;
    if (!cprisk_vm_encode_pc_i(bh, 0u, vpc_a, vpc_b, &encoded_pc, out)) {
        cprisk_vm_wb_finalize_i(out, acc);
        return 0;
    }
    // profile 默认值用于旧入口（无 magic）；解析失败时走运行期 secret 派生的 fallback，
    // 随后把 family/depth 夹到合法范围，避免 0 或越界值进入执行。
    uint32_t semantic_family = 1u;
    uint32_t mixed_predicate_profile = 0u;
    uint32_t max_subcall_depth = 4u;
    if (!cprisk_vm_entry_profile_decode_i(
            selected->reserved,
            &semantic_family,
            &mixed_predicate_profile,
            &max_subcall_depth
        )) {
        cprisk_vm_entry_profile_fallback_i(
            func_id,
            bh->reserved,
            &semantic_family,
            &mixed_predicate_profile,
            &max_subcall_depth
        );
    }
    if (semantic_family == 0u)
        semantic_family = 1u;
    if (max_subcall_depth == 0u)
        max_subcall_depth = 1u;
    if (max_subcall_depth > CPRISK_VM_MAX_SUBCALL_DEPTH)
        max_subcall_depth = CPRISK_VM_MAX_SUBCALL_DEPTH;

    /* Per-function accumulator lane permutation: 3-bit index in entry->reserved
     * bits [2:0] selects among 3! = 6 permutations of {add_lane, sub_lane, mul_lane}.
     * Index 0 (identity {0,1,2}) is the default for legacy no-magic entries. */
    // 每个函数的 add/sub/mul 家族置换（entry->reserved 低 3 位，仅 magic 入口生效）。
    // 它决定每类 opcode 最终调用的运算家族；构建期生成器必须使用同一置换，错配会改变结果。
    static const uint8_t s_acc_lane_perms[8][3] = {
        {0u, 1u, 2u},  /* 0 — identity (default) */
        {0u, 2u, 1u},  /* 1 */
        {1u, 0u, 2u},  /* 2 */
        {1u, 2u, 0u},  /* 3 */
        {2u, 0u, 1u},  /* 4 */
        {2u, 1u, 0u},  /* 5 */
        {0u, 1u, 2u},  /* 6 — undefined, alias identity */
        {0u, 1u, 2u},  /* 7 — undefined, alias identity */
    };
    const uint32_t lane_perm_idx = ((selected->reserved >> 24u) == CPRISK_VMP_ENTRY_PROFILE_MAGIC)
        ? (selected->reserved & 0x7u) : 0u;

    // vpc_a == 0 会让仿射映射不可逆（decode 无法恢复 PC），直接判非法。
    if (vpc_a == 0u) {
        out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
        out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        cprisk_vm_wb_finalize_i(out, acc);
        return 0;
    }

    // 入口自检同时决定 decode 故障掩码与 seal mix；自检失败会把故障注入之后的每次取指/解密。
    uint64_t decode_fault_mask = 0u;
    uint64_t m3_seal_mix = 0u;
    cprisk_vm_m3_selfchk_run_i(hdr, acc, func_id, bh, out, &decode_fault_mask, &m3_seal_mix);
#if CPRISK_VM_THREADED_DISPATCH
    if (out->poison_flags & CPRISK_VM_POISON_SELF_INTEGRITY) {
        out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
        cprisk_vm_wb_finalize_i(out, acc);
        return 0;
    }
#endif

    // 从头部 reserved 解出各可选特性开关；enc_* 只有在 V3 校验通过后才有意义。
    const uint32_t m3_opaque = (bh->reserved & CPRISK_VMP_BC_FLAG_M3_OPAQUE_CHAIN) != 0u ? 1u : 0u;
    const uint32_t m3_dead = (bh->reserved & CPRISK_VMP_BC_FLAG_M3_DEAD_HANDLERS) != 0u ? 1u : 0u;
    const uint32_t enc_imm = (bh->reserved & CPRISK_VMP_BC_FLAG_ENC_IMMEDIATE) != 0u ? 1u : 0u;
    const uint32_t enc_op = (bh->reserved & CPRISK_VMP_BC_FLAG_ENC_OPCODE) != 0u ? 1u : 0u;
    // V3 种子布局：core（+M2 扩展）之后依次是 immediate seed、opcode seed。
    // 任一步越界都拒绝执行；种子缺失时不猜测默认值。
    uint64_t imm_seed_root = 0u;
    if (enc_imm != 0u) {
        if (bh->version < CPRISK_VMP_VERSION_V3) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            cprisk_vm_wb_finalize_i(out, acc);
            return 0;
        }
        size_t imm_seed_off = CPRISK_VMP_BYTECODE_HEADER_CORE_BYTES;
        if (cprisk_vmp_bytecode_has_m2_i(bh))
            imm_seed_off += CPRISK_VMP_BYTECODE_VPC_EXT_BYTES;
        if (bc_hdr_total < imm_seed_off + 8u || bsz < imm_seed_off + 8u) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            cprisk_vm_wb_finalize_i(out, acc);
            return 0;
        }
        imm_seed_root = cprisk_read_le_u64_i(b_sec + imm_seed_off);
    }
    uint64_t opcode_seed_root = 0u;
    if (enc_op != 0u) {
        if (bh->version < CPRISK_VMP_VERSION_V3) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            cprisk_vm_wb_finalize_i(out, acc);
            return 0;
        }
        size_t op_seed_off = CPRISK_VMP_BYTECODE_HEADER_CORE_BYTES;
        if (cprisk_vmp_bytecode_has_m2_i(bh))
            op_seed_off += CPRISK_VMP_BYTECODE_VPC_EXT_BYTES;
        if (enc_imm != 0u)
            op_seed_off += 8u;
        if (bc_hdr_total < op_seed_off + 8u || bsz < op_seed_off + 8u) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            cprisk_vm_wb_finalize_i(out, acc);
            return 0;
        }
        opcode_seed_root = cprisk_read_le_u64_i(b_sec + op_seed_off);
    }
    if ((bh->reserved & CPRISK_VMP_BC_FLAG_M3_SELFCHK) != 0u && m3_seal_mix != 0u) {
        imm_seed_root ^= m3_seal_mix;
        opcode_seed_root ^= (m3_seal_mix << 1u) ^ (m3_seal_mix >> 61u);
    }
    uint64_t raw_bind_root = imm_seed_root;
    if (raw_bind_root == 0u)
        raw_bind_root = opcode_seed_root;
    if (raw_bind_root == 0u)
        raw_bind_root = func_id ^ ((uint64_t)bh->reserved << 32) ^ 0x524157524F4F5431ULL; /* "RAWROOT1" */

    // 先假定“跑满预算”：若循环因预算退出且没有其他错误，status 保持 STEP_LIMIT。
    // HALT/RET 成功结束时会改成 OK；任何校验失败会改成 INVALID_BYTECODE。
    out->status = CPRISK_VM_STATUS_STEP_LIMIT;

    // heavy 模式的触发条件：高 semantic_family、深子调用，或显式头部标志。
    const int vm_anti_symbolic_heavy =
        (semantic_family >= 10u) ||
        (max_subcall_depth >= 8u) ||
        ((bh->reserved & CPRISK_VMP_BC_FLAG_ANTI_SYMBOLIC_HEAVY) != 0u);

    // 整帧清零：同时初始化 return_stack/vm_snap/vregs/加固上下文，避免未初始化状态。
    memset(fr, 0, sizeof(*fr));
    fr->hdr = hdr;
    fr->b_sec = b_sec;
    fr->bsz = bsz;
    fr->bh = bh;
    fr->dispatch_sec = d_sec;
    fr->dispatch_hdr = dhdr;
    fr->dispatch_hdr_flags = dhdr ? dhdr->flags : 0u;
    fr->dispatch_decode_seed = cprisk_vmp_dispatch_keystream_seed_i(d_sec, dhdr);
    if ((bh->reserved & CPRISK_VMP_BC_FLAG_M3_SELFCHK) != 0u && m3_seal_mix != 0u)
        fr->dispatch_decode_seed ^= m3_seal_mix;
    fr->path_lane = path_lane;
    fr->func_id = func_id;
    fr->out = out;
    fr->bc_hdr_total = bc_hdr_total;
    fr->entry_stride = entry_stride;
    fr->vpc_a = vpc_a;
    fr->vpc_b = vpc_b;
    fr->code = code;
    fr->blen = blen;
    // 若启用运行期字节码哈希，先在入口建立一次 SHA256 基线，后续按周期复查。
    fr->bc_seg_hash_enabled = 0u;
    fr->bc_last_hash_step = 0u;
    memset(fr->bc_seg_hash_expect, 0, sizeof(fr->bc_seg_hash_expect));
    if ((bh->reserved & CPRISK_VMP_BC_FLAG_BC_SEG_RUNTIME_SHA256) != 0u && code != NULL && blen > 0u) {
        cprisk_sha256(code, (size_t)blen, fr->bc_seg_hash_expect);
        fr->bc_seg_hash_enabled = 1u;
    }
    // 以下字段是解释器的不变量来源：入口 PC、VPC、profile、lane 映射、加密种子与绑定根。
    fr->encoded_pc = encoded_pc;
    fr->semantic_family = semantic_family;
    fr->mixed_predicate_profile = mixed_predicate_profile;
    fr->max_subcall_depth = max_subcall_depth;
    fr->acc_lane_map[0] = s_acc_lane_perms[lane_perm_idx][0];
    fr->acc_lane_map[1] = s_acc_lane_perms[lane_perm_idx][1];
    fr->acc_lane_map[2] = s_acc_lane_perms[lane_perm_idx][2];
    /* The frame memset above initializes both stacks, their cursors and vregs.
     * Do not overwrite those zeros with uninitialized local stack storage. */
    fr->enc_imm = enc_imm;
    fr->enc_op = enc_op;
    fr->imm_seed_root = imm_seed_root;
    fr->opcode_seed_root = opcode_seed_root;
    fr->raw_bind_root = raw_bind_root;
    fr->m3_opaque = m3_opaque;
    fr->m3_dead = m3_dead;
    fr->vm_anti_symbolic_heavy = vm_anti_symbolic_heavy;
    // 把进程级 session_mix 与 CFF link token 再混一次，得到本帧的会话种子；0 不允许出现。
    fr->session_mix = cprisk_vm_session_mix_i();
    fr->session_mix = cprisk_vmp_avalanche32_i(
        fr->session_mix ^ (uint32_t)cprisk_cff_get_vm_link_token()
    );
    if (fr->session_mix == 0u)
        fr->session_mix = 0xC3EF4D27u ^ fr->path_lane;
    {
        // 预算随机化：由 func_id/blen/family/session 派生，上限 65536、下限 53248（减 12288）。
        // 固定迭代上限可被追踪器利用；随机上限让“跑多少步”本身依赖运行期状态。
        uint32_t cap_mix = cprisk_vmp_avalanche32_i(
            (uint32_t)func_id ^
            (uint32_t)(func_id >> 32u) ^
            blen ^
            semantic_family ^
            fr->session_mix ^
            0x51ED270Bu
        );
        uint64_t cap = (uint64_t)CPRISK_VM_MAX_STEPS - (uint64_t)(cap_mix % 12288u);
        fr->step_limit_cap = cap;
    }
    // 复制初始 acc（来自 runtime material），初始化副 bank 与 opaque 状态；steps 从 0 开始。
    fr->decode_fault_mask = decode_fault_mask;
    memcpy(fr->acc, acc, sizeof(fr->acc));
    cprisk_vm_aux_init_i(fr);
    cprisk_vm_opaque_runtime_init_i(fr);
    fr->steps = 0u;
    /* Initialize integrated hardening modules */
    // 初始化五个加固模块；dead_touch 保持 16 个死处理器函数体存活并绑定其布局；
    // sync_barrier 为每 64 步的外部数据依赖做准备。
    cprisk_vm_hardening_init(fr);
    /* Fold dead-handler addresses into session_mix: keeps all 16 dead-handler
     * bodies live in the binary and binds their layout to session entropy. */
    cprisk_vm_dead_touch_i(fr);
    /* VM sync barrier: external data dependency to break native batch-trace */
    cprisk_vm_sync_barrier_init(&fr->sync_barrier_ctx);
    return 1;
}

// lane0 运行前奏：把 lane 相关的诱饵 seed 混入 opaque_chain（不改 acc）。
static void cprisk_vm_run_prelude_lane0_i(cprisk_vm_interp_frame_t *fr) {
    fr->opaque_chain = cprisk_vmp_avalanche32_i(
        fr->opaque_chain ^
        cprisk_vm_dispatch_bait_seed_i(0u, fr->semantic_family ^ 0x11u)
    );
}

// lane1 运行前奏：用 lane1 的诱饵 seed 同时刷新 opaque_rt_nonce 与 opaque_chain。
static void cprisk_vm_run_prelude_lane1_i(cprisk_vm_interp_frame_t *fr) {
    const uint32_t lane_mix =
        cprisk_vm_dispatch_bait_seed_i(1u, fr->semantic_family ^ fr->mixed_predicate_profile);
    fr->opaque_rt_nonce = cprisk_vmp_avalanche32_i(
        fr->opaque_rt_nonce ^ lane_mix ^ fr->opaque_thread_mix ^ (uint32_t)fr->func_id
    );
    fr->opaque_chain = cprisk_vmp_avalanche32_i(
        fr->opaque_chain ^ fr->opaque_rt_nonce ^ lane_mix ^ fr->session_mix
    );
}

// lane2 运行前奏：用 max_subcall_depth/func_id 派生 seed，刷新 session/fold/chain。
static void cprisk_vm_run_prelude_lane2_i(cprisk_vm_interp_frame_t *fr) {
    const uint32_t lane_mix =
        cprisk_vm_dispatch_bait_seed_i(2u, fr->max_subcall_depth ^ (uint32_t)(fr->func_id >> 32u));
    fr->session_mix = cprisk_vmp_avalanche32_i(
        fr->session_mix ^ lane_mix ^ fr->opaque_runtime_fold ^ (uint32_t)fr->func_id
    );
    if (fr->session_mix == 0u)
        fr->session_mix = 0xC3EF4D27u ^ fr->path_lane;
    fr->opaque_runtime_fold = cprisk_vmp_avalanche32_i(
        fr->opaque_runtime_fold ^ fr->session_mix ^ lane_mix ^ fr->opaque_rt_nonce
    );
    fr->opaque_chain = cprisk_vmp_avalanche32_i(
        fr->opaque_chain ^ fr->opaque_runtime_fold ^ fr->session_mix ^ lane_mix
    );
}

// lane0 运行收尾：清理加固状态后，用 session_mix ^ opaque_chain 合并两个 bank 到 acc。
static void cprisk_vm_run_finish_lane0_i(cprisk_vm_interp_frame_t *fr, uint8_t acc[32]) {
    cprisk_vm_hardening_cleanup(fr);
    cprisk_vm_merge_banks_i(acc, fr->acc, fr->acc_aux, fr->session_mix ^ fr->opaque_chain);
}

// lane1 运行收尾：先用线程/链状态更新 opaque_thread_mix，再以它为 salt 合并 bank。
static void cprisk_vm_run_finish_lane1_i(cprisk_vm_interp_frame_t *fr, uint8_t acc[32]) {
    cprisk_vm_hardening_cleanup(fr);
    fr->opaque_thread_mix = cprisk_vmp_avalanche32_i(
        fr->opaque_thread_mix ^
        fr->opaque_chain ^
        fr->opaque_rt_nonce ^
        cprisk_vm_dispatch_bait_seed_i(1u, (uint32_t)fr->steps)
    );
    cprisk_vm_merge_banks_i(acc, fr->acc, fr->acc_aux, fr->opaque_thread_mix ^ fr->opaque_chain);
}

// lane2 运行收尾：用运行期 fold 与 session_mix 混合后作为 salt 合并 bank。
static void cprisk_vm_run_finish_lane2_i(cprisk_vm_interp_frame_t *fr, uint8_t acc[32]) {
    cprisk_vm_hardening_cleanup(fr);
    fr->opaque_runtime_fold = cprisk_vmp_avalanche32_i(
        fr->opaque_runtime_fold ^
        fr->opaque_chain ^
        fr->session_mix ^
        cprisk_vm_dispatch_bait_seed_i(2u, fr->path_lane + 3u)
    );
    cprisk_vm_merge_banks_i(acc, fr->acc, fr->acc_aux, fr->opaque_runtime_fold ^ fr->session_mix);
}

// lane0 完整执行：prepare → prelude → loop A（线程化时走 cprisk_thread_run_a_i）→ finish。
// prepare 失败时直接返回；acc 保持 prepare 期间写入的最终状态。
static void cprisk_vm_run_program_lane0_i(const struct mach_header_64 *hdr,
                                          const uint8_t *d_sec,
                                          const cprisk_vmp_dispatch_header_t *dhdr,
                                          const uint8_t *b_sec,
                                          unsigned long bsz,
                                          const cprisk_vmp_bytecode_header_t *bh,
                                          uint64_t func_id,
                                          uint8_t acc[32],
                                          cprisk_vm_run_result_t *out) {
    cprisk_vm_interp_frame_t fr;
    if (!cprisk_vm_prepare_program_i(hdr, d_sec, dhdr, b_sec, bsz, bh, 0u, func_id, acc, out, &fr))
        return;
    cprisk_vm_run_prelude_lane0_i(&fr);
    /* Lane-specific prelude/finish order is preserved. */
#if CPRISK_VM_THREADED_DISPATCH
    cprisk_thread_run_a_i(&fr);
#else
    cprisk_vm_interp_loop_a(&fr);
#endif
    cprisk_vm_run_finish_lane0_i(&fr, acc);
}

// lane1 完整执行：prepare → prelude → loop B（线程化时走 cprisk_thread_run_b_i）→ finish。
static void cprisk_vm_run_program_lane1_i(const struct mach_header_64 *hdr,
                                          const uint8_t *d_sec,
                                          const cprisk_vmp_dispatch_header_t *dhdr,
                                          const uint8_t *b_sec,
                                          unsigned long bsz,
                                          const cprisk_vmp_bytecode_header_t *bh,
                                          uint64_t func_id,
                                          uint8_t acc[32],
                                          cprisk_vm_run_result_t *out) {
    cprisk_vm_interp_frame_t fr;
    if (!cprisk_vm_prepare_program_i(hdr, d_sec, dhdr, b_sec, bsz, bh, 1u, func_id, acc, out, &fr))
        return;
    cprisk_vm_run_prelude_lane1_i(&fr);
    /* Lane-specific prelude/finish order is preserved. */
#if CPRISK_VM_THREADED_DISPATCH
    cprisk_thread_run_b_i(&fr);
#else
    cprisk_vm_interp_loop_b(&fr);
#endif
    cprisk_vm_run_finish_lane1_i(&fr, acc);
}

// lane2 完整执行：prepare → prelude → loop B（与 lane1 共用循环，但 prelude/finish 不同）→ finish。
static void cprisk_vm_run_program_lane2_i(const struct mach_header_64 *hdr,
                                          const uint8_t *d_sec,
                                          const cprisk_vmp_dispatch_header_t *dhdr,
                                          const uint8_t *b_sec,
                                          unsigned long bsz,
                                          const cprisk_vmp_bytecode_header_t *bh,
                                          uint64_t func_id,
                                          uint8_t acc[32],
                                          cprisk_vm_run_result_t *out) {
    cprisk_vm_interp_frame_t fr;
    if (!cprisk_vm_prepare_program_i(hdr, d_sec, dhdr, b_sec, bsz, bh, 2u, func_id, acc, out, &fr))
        return;
    cprisk_vm_run_prelude_lane2_i(&fr);
    /* Lane-specific prelude/finish order is preserved. */
#if CPRISK_VM_THREADED_DISPATCH
    cprisk_thread_run_b_i(&fr);
#else
    cprisk_vm_interp_loop_b(&fr);
#endif
    cprisk_vm_run_finish_lane2_i(&fr, acc);
}

// lane0 顶层入口（调试/普通执行）：清零结果 → 用 runtime material 播种 acc → 独立做
// sysctl/mach/聚合三重反调试检查 → Frida 快照 → 定位自身 Mach-O 与 VMP 段 → 校验头部 → 执行。
// 非模拟器检测到调试时短路返回 0（status=TRACED_SHORTCIRCUIT，结果被 poison/诱饵污染）；
// 参数/布局错误返回 0 并写 INVALID_DISPATCH；只有 out == NULL 返回 -1。
static int cprisk_vm_execute_lane0_i(uint64_t func_id,
                                      cprisk_vm_run_result_t *out,
                                     const void *hdr_sym) {
    if (!out)
        return -1;

    // 结果先清零，并把“未执行”哨兵写成全 1；后续成功路径会覆盖 last_opcode/class。
    memset(out, 0, sizeof(*out));
    out->last_opcode = 0xFFFFFFFFu;
    out->last_dispatch_class = 0xFFFFFFFFu;
    out->whitebox_domain_rc = UINT32_MAX;

    // 初始累加器来自 runtime material 而非全零：同一字节码在不同设备/安装上得到不同结果。
    uint8_t acc[32];
    memset(acc, 0, sizeof(acc));
    (void)cprisk_get_runtime_material(acc);

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    /*
     * Redundant trace probes: sysctl and Mach paths are evaluated independently
     * of the aggregated `cprisk_is_being_traced` return to mitigate single-point
     * hooks returning a false negative.
     */
    // 除聚合探针外再 OR 上 sysctl 与 Mach 两条单独探针，避免单点 hook 让聚合函数返回假阴性。
    if (cprisk_is_being_traced_sysctl_only() != 0 ||
        cprisk_mach_trace_suspicious() != 0 ||
        cprisk_is_being_traced() != 0) {
        out->poison_flags |= CPRISK_VM_POISON_TRACED;
        out->status = CPRISK_VM_STATUS_TRACED_SHORTCIRCUIT;
        cprisk_vm_traced_decoy_acc_i(acc);
        memcpy(out->acc, acc, sizeof(acc));
        uint8_t wb_out[32];
        int wbr = cprisk_whitebox_evaluate_domain(5u, out->acc, wb_out);
        out->whitebox_domain_rc = wbr;
        if (wbr == 0)
            memcpy(out->acc, wb_out, sizeof(wb_out));
        return 0;
    }
#endif

    // Frida 快照失败/不支持时不改变控制流，只把 poison 旗标带上让上层降级处理。
    cprisk_frida_runtime_snapshot_t fr;
    memset(&fr, 0, sizeof(fr));
    if (cprisk_frida_runtime_snapshot(&fr) == 0 && fr.supported != 0u && fr.flags != 0u)
        out->poison_flags |= CPRISK_VM_POISON_FRIDA;

    // 以入口符号反查自身 Mach-O 头，再定位 __DATA 中的 dispatch/bytecode 段。
    const struct mach_header_64 *hdr = cprisk_find_own_header(hdr_sym);
    if (!hdr) {
        out->poison_flags |= CPRISK_VM_POISON_DISPATCH;
        out->status = CPRISK_VM_STATUS_INVALID_DISPATCH;
        memcpy(out->acc, acc, sizeof(acc));
        return 0;
    }

    unsigned long dsz = 0;
    unsigned long bsz = 0;
    const uint8_t *d_sec =
        cprisk_find_section(hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_VMP_DISPATCH, &dsz);
    const uint8_t *b_sec =
        cprisk_find_section(hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_VMP_BYTECODE, &bsz);

    const cprisk_vmp_bytecode_header_t *bh = NULL;
    // 头部/布局校验失败：同时标记 dispatch 与 bytecode，写 INVALID_DISPATCH 并做白盒收尾。
    if (!cprisk_vmp_headers_ok_i(d_sec, dsz, b_sec, bsz, &bh) || !bh) {
        out->poison_flags |= CPRISK_VM_POISON_DISPATCH | CPRISK_VM_POISON_BYTECODE;
        out->status = CPRISK_VM_STATUS_INVALID_DISPATCH;
        memcpy(out->acc, acc, sizeof(acc));
        uint8_t wb_out[32];
        int wbr = cprisk_whitebox_evaluate_domain(5u, out->acc, wb_out);
        out->whitebox_domain_rc = wbr;
        if (wbr == 0)
            memcpy(out->acc, wb_out, sizeof(wb_out));
        return 0;
    }

    const cprisk_vmp_dispatch_header_t *dhdr = (const cprisk_vmp_dispatch_header_t *)(const void *)d_sec;

    cprisk_vm_run_program_lane0_i(hdr, d_sec, dhdr, b_sec, bsz, bh, func_id, acc, out);

    return 0;
}

// lane1 顶层入口：语义同 lane0，但多一个 lane_probe 恒等触碰，并使用 lane1 的 program 路径。
static int cprisk_vm_execute_lane1_i(uint64_t func_id,
                                     cprisk_vm_run_result_t *out,
                                     const void *hdr_sym) {
    if (!out)
        return -1;

    memset(out, 0, sizeof(*out));
    out->last_opcode = 0xFFFFFFFFu;
    out->last_dispatch_class = 0xFFFFFFFFu;
    out->whitebox_domain_rc = UINT32_MAX;

    uint8_t acc[32];
    memset(acc, 0, sizeof(acc));
    (void)cprisk_get_runtime_material(acc);

    // lane1 专属的恒等触碰：派生 lane_probe 后对 acc 异或 0，仅影响寄存器/数据流形状。
    volatile uint32_t lane_probe =
        cprisk_vmp_avalanche32_i((uint32_t)func_id ^ cprisk_vmp_rotl32_i((uint32_t)(func_id >> 32u), 7u));
    lane_probe ^= cprisk_vm_dispatch_bait_seed_i(1u, (uint32_t)func_id);
    acc[(lane_probe >> 3u) & 31u] ^= 0u;

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    if (cprisk_is_being_traced_sysctl_only() != 0 ||
        cprisk_mach_trace_suspicious() != 0 ||
        cprisk_is_being_traced() != 0) {
        out->poison_flags |= CPRISK_VM_POISON_TRACED;
        out->status = CPRISK_VM_STATUS_TRACED_SHORTCIRCUIT;
        cprisk_vm_traced_decoy_acc_i(acc);
        memcpy(out->acc, acc, sizeof(acc));
        uint8_t wb_out[32];
        int wbr = cprisk_whitebox_evaluate_domain(5u, out->acc, wb_out);
        out->whitebox_domain_rc = wbr;
        if (wbr == 0)
            memcpy(out->acc, wb_out, sizeof(wb_out));
    return 0;
}
#endif

    cprisk_frida_runtime_snapshot_t fr;
    memset(&fr, 0, sizeof(fr));
    if (cprisk_frida_runtime_snapshot(&fr) == 0 && fr.supported != 0u && fr.flags != 0u)
        out->poison_flags |= CPRISK_VM_POISON_FRIDA;

    const struct mach_header_64 *hdr = cprisk_find_own_header(hdr_sym);
    if (!hdr) {
        out->poison_flags |= CPRISK_VM_POISON_DISPATCH;
        out->status = CPRISK_VM_STATUS_INVALID_DISPATCH;
        memcpy(out->acc, acc, sizeof(acc));
        return 0;
    }

    unsigned long dsz = 0;
    unsigned long bsz = 0;
    const uint8_t *d_sec =
        cprisk_find_section(hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_VMP_DISPATCH, &dsz);
    const uint8_t *b_sec =
        cprisk_find_section(hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_VMP_BYTECODE, &bsz);

    const cprisk_vmp_bytecode_header_t *bh = NULL;
    if (!cprisk_vmp_headers_ok_i(d_sec, dsz, b_sec, bsz, &bh) || !bh) {
        out->poison_flags |= CPRISK_VM_POISON_DISPATCH | CPRISK_VM_POISON_BYTECODE;
        out->status = CPRISK_VM_STATUS_INVALID_DISPATCH;
        memcpy(out->acc, acc, sizeof(acc));
        uint8_t wb_out[32];
        int wbr = cprisk_whitebox_evaluate_domain(5u, out->acc, wb_out);
        out->whitebox_domain_rc = wbr;
        if (wbr == 0)
            memcpy(out->acc, wb_out, sizeof(wb_out));
        return 0;
    }

    const cprisk_vmp_dispatch_header_t *dhdr = (const cprisk_vmp_dispatch_header_t *)(const void *)d_sec;
    cprisk_vm_run_program_lane1_i(hdr, d_sec, dhdr, b_sec, bsz, bh, func_id, acc, out);
    return 0;
}

// lane2 顶层入口：语义同 lane0，但用 hdr_sym/func_id 派生 lane_stamp 做恒等触碰，
// 并使用 lane2 的 program 路径。
static int cprisk_vm_execute_lane2_i(uint64_t func_id,
                                     cprisk_vm_run_result_t *out,
                                     const void *hdr_sym) {
    if (!out)
        return -1;

    memset(out, 0, sizeof(*out));
    out->last_opcode = 0xFFFFFFFFu;
    out->last_dispatch_class = 0xFFFFFFFFu;
    out->whitebox_domain_rc = UINT32_MAX;

    uint8_t acc[32];
    memset(acc, 0, sizeof(acc));
    (void)cprisk_get_runtime_material(acc);

    // lane2 专属的恒等触碰：把 hdr_sym/func_id 混成 lane_stamp，再对 acc 异或 0。
    volatile uint64_t lane_stamp =
        ((uint64_t)(uintptr_t)hdr_sym ^ func_id ^ UINT64_C(0xA5A5C3C36D2B79F5));
    lane_stamp ^= lane_stamp >> 29u;
    acc[(lane_stamp >> 11u) & 31u] ^= 0u;

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    if (cprisk_is_being_traced_sysctl_only() != 0 ||
        cprisk_mach_trace_suspicious() != 0 ||
        cprisk_is_being_traced() != 0) {
        out->poison_flags |= CPRISK_VM_POISON_TRACED;
        out->status = CPRISK_VM_STATUS_TRACED_SHORTCIRCUIT;
        cprisk_vm_traced_decoy_acc_i(acc);
        memcpy(out->acc, acc, sizeof(acc));
        uint8_t wb_out[32];
        int wbr = cprisk_whitebox_evaluate_domain(5u, out->acc, wb_out);
        out->whitebox_domain_rc = wbr;
        if (wbr == 0)
            memcpy(out->acc, wb_out, sizeof(wb_out));
        return 0;
    }
#endif

    cprisk_frida_runtime_snapshot_t fr;
    memset(&fr, 0, sizeof(fr));
    if (cprisk_frida_runtime_snapshot(&fr) == 0 && fr.supported != 0u && fr.flags != 0u)
        out->poison_flags |= CPRISK_VM_POISON_FRIDA;

    const struct mach_header_64 *hdr = cprisk_find_own_header(hdr_sym);
    if (!hdr) {
        out->poison_flags |= CPRISK_VM_POISON_DISPATCH;
        out->status = CPRISK_VM_STATUS_INVALID_DISPATCH;
        memcpy(out->acc, acc, sizeof(acc));
        return 0;
    }

    unsigned long dsz = 0;
    unsigned long bsz = 0;
    const uint8_t *d_sec =
        cprisk_find_section(hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_VMP_DISPATCH, &dsz);
    const uint8_t *b_sec =
        cprisk_find_section(hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_VMP_BYTECODE, &bsz);

    const cprisk_vmp_bytecode_header_t *bh = NULL;
    if (!cprisk_vmp_headers_ok_i(d_sec, dsz, b_sec, bsz, &bh) || !bh) {
        out->poison_flags |= CPRISK_VM_POISON_DISPATCH | CPRISK_VM_POISON_BYTECODE;
        out->status = CPRISK_VM_STATUS_INVALID_DISPATCH;
        memcpy(out->acc, acc, sizeof(acc));
        uint8_t wb_out[32];
        int wbr = cprisk_whitebox_evaluate_domain(5u, out->acc, wb_out);
        out->whitebox_domain_rc = wbr;
        if (wbr == 0)
            memcpy(out->acc, wb_out, sizeof(wb_out));
        return 0;
    }

    const cprisk_vmp_dispatch_header_t *dhdr = (const cprisk_vmp_dispatch_header_t *)(const void *)d_sec;
    cprisk_vm_run_program_lane2_i(hdr, d_sec, dhdr, b_sec, bsz, bh, func_id, acc, out);
    return 0;
}

// 把 VM 结果折叠成 64 位：acc 前 8 字节 XOR acc_aux 的 lane 7 起的 8 字节。
// 这只是面向 ABI 的摘要，不是密码学承诺；result 为 NULL 时返回 0。
static uint64_t cprisk_vm_fold_result_i(const cprisk_vm_run_result_t *result) {
    uint64_t folded = 0u;
    if (!result)
        return 0u;
    memcpy(&folded, result->acc, sizeof(folded));
    folded ^= cprisk_vm_read_acc_word_i(result->acc_aux, 7u, 8u);
    return folded;
}

// 入口票据：把 func_id、入口符号地址、lane 与会话 mix 绑定。finish 函数会重算并比较，
// 因此调试器不能绕过 entry 直接调用 finish（除非能同步得到当前 session 绑定值）。
typedef struct {
    uint64_t func_id;
    const void *hdr_sym;
    uint32_t lane;
    uint32_t ticket;
} cprisk_vm_entry_ticket_t;

// finish 的两种调用形态：结构体票据 或 (lo,hi,lane,ticket,hdr_sym) 拆包；
// 两者都会重算票据。函数指针间接调用用于 CFF / 链接器 -u 布线。
typedef uint64_t (*cprisk_vm_entry_finish_ticket_fp_i)(const cprisk_vm_entry_ticket_t *ticket);
typedef uint64_t (*cprisk_vm_entry_finish_pack32_fp_i)(uint32_t lo,
                                                       uint32_t hi,
                                                       uint32_t lane,
                                                       uint32_t ticket,
                                                       const void *hdr_sym);

// 调试/测试入口：等价于 lane0 执行。成功返回 0；out == NULL 返回 -1。
// 具体失败原因（检测到调试、布局非法、步数耗尽）体现在 out->status/poison_flags。
int cprisk_vm_execute(uint64_t func_id, cprisk_vm_run_result_t *out) {
    return cprisk_vm_execute_lane0_i(func_id, out, (const void *)&cprisk_vm_execute);
}

// 派生入口票据：混合 func_id、入口符号地址、lane、session_mix 与诱饵 seed；
// 结果为 0 时替换成固定非零值。票据不是秘密，但绑定当前进程的 session。
static uint32_t cprisk_vm_entry_ticket_i(uint64_t func_id, const void *hdr_sym, uint32_t lane) {
    uint32_t mix =
        (uint32_t)func_id ^
        (uint32_t)(func_id >> 32u) ^
        (uint32_t)(uintptr_t)hdr_sym ^
        (uint32_t)(((uintptr_t)hdr_sym) >> 32u) ^
        (lane * 0x9E3779B9u) ^
        cprisk_vm_session_mix_i();
    mix = cprisk_vmp_avalanche32_i(mix ^ cprisk_vm_dispatch_bait_seed_i(lane, lane + 1u));
    if (mix == 0u)
        mix = 0xA5C31F27u ^ lane;
    return mix;
}

// lane0 finish：校验票据 → 执行 lane0 → 折叠 64 位结果。
// 票据为空/不匹配或执行失败时返回 0。
__attribute__((noinline)) static uint64_t cprisk_vm_entry_finish_ticket_lane0_i(const cprisk_vm_entry_ticket_t *ticket) {
    if (!ticket || !ticket->hdr_sym)
        return 0u;
    if (ticket->ticket != cprisk_vm_entry_ticket_i(ticket->func_id, ticket->hdr_sym, ticket->lane))
        return 0u;
    cprisk_vm_run_result_t result;
    if (cprisk_vm_execute_lane0_i(ticket->func_id, &result, ticket->hdr_sym) != 0)
        return 0u;
    return cprisk_vm_fold_result_i(&result);
}

// lane1 finish：由 (hi,lo) 重建 func_id，校验票据后执行 lane1 并折叠结果。
__attribute__((noinline)) static uint64_t cprisk_vm_entry_finish_pack32_lane1_i(uint32_t lo,
                                                                                 uint32_t hi,
                                                                                 uint32_t lane,
                                                                                 uint32_t ticket,
                                                                                 const void *hdr_sym) {
    const uint64_t func_id = ((uint64_t)hi << 32u) | (uint64_t)lo;
    if (ticket != cprisk_vm_entry_ticket_i(func_id, hdr_sym, lane))
        return 0u;
    cprisk_vm_run_result_t result;
    if (cprisk_vm_execute_lane1_i(func_id, &result, hdr_sym) != 0)
        return 0u;
    return cprisk_vm_fold_result_i(&result);
}

// lane2 finish：校验票据 → 执行 lane2 → 折叠结果。
__attribute__((noinline)) static uint64_t cprisk_vm_entry_finish_ticket_lane2_i(const cprisk_vm_entry_ticket_t *ticket) {
    if (!ticket || !ticket->hdr_sym)
        return 0u;
    if (ticket->ticket != cprisk_vm_entry_ticket_i(ticket->func_id, ticket->hdr_sym, ticket->lane))
        return 0u;
    cprisk_vm_run_result_t result;
    if (cprisk_vm_execute_lane2_i(ticket->func_id, &result, ticket->hdr_sym) != 0)
        return 0u;
    return cprisk_vm_fold_result_i(&result);
}

// 对外主入口：保留一段可被 Pass9 重写的副作用前奏，然后构造票据并以直接/间接两种方式
// 调用 lane0 finish（两个调用点用于 CFF/布局）。返回折叠后的 64 位结果。
CPRISK_VM_EXPORT __attribute__((noinline)) uint64_t cprisk_vm_entry(uint64_t func_id) {
#if defined(__aarch64__)
    __asm__ volatile("add x0, x0, #0");
#endif

    /*
     * M3: keep a tiny side-effectful entry prelude so policy-guided Pass9 can
     * still find rewritable entry instructions on this wrapper symbol.
     */
    // 入口前奏：把 func_id 与 session 混合成 volatile 值，为策略重写器留下可改写的指令窗口。
    volatile uint64_t prelude = func_id ^ 0x9E3779B97F4A7C15ULL ^ (uint64_t)cprisk_vm_session_mix_i();
    prelude ^= (prelude >> 17);
    prelude ^= (prelude << 7);
    cprisk_vm_entry_ticket_t ticket;
    ticket.func_id = func_id;
    ticket.hdr_sym = (const void *)&cprisk_vm_entry;
    ticket.lane = 0u;
    // ticket 先与 prelude 异或再异或回来，最终仍等于 cprisk_vm_entry_ticket_i(...)；
    // 中间表达式只用于混淆数据流。
    ticket.ticket = cprisk_vm_entry_ticket_i(func_id, ticket.hdr_sym, ticket.lane) ^ (uint32_t)prelude;
    ticket.ticket ^= (uint32_t)prelude;
    // 奇偶分支选择直接/间接调用；两条路径语义相同，用于制造两个调用点。
    if (((uint32_t)prelude & 1u) == 0u) {
        cprisk_vm_entry_finish_ticket_fp_i fp = cprisk_vm_entry_finish_ticket_lane0_i;
        return fp(&ticket);
    }
    return cprisk_vm_entry_finish_ticket_lane0_i(&ticket);
}

// 备选入口 1：用 (lo,hi) 拆包票据，校验后走 lane1。asm 的 eor x16,x0,x0 是恒等指令，
// 仅作为 CFF/重写锚点。
CPRISK_VM_EXPORT __attribute__((noinline)) uint64_t cprisk_vm_entry_alt1(uint64_t func_id) {
#if defined(__aarch64__)
    __asm__ volatile("eor x16, x0, x0");
#endif
    uint32_t lo = (uint32_t)func_id;
    uint32_t hi = (uint32_t)(func_id >> 32u);
    // 派生一个 volatile ledger，再以 x ^ x 的方式从票据中抵消，保持票据语义不变。
    volatile uint32_t ledger = cprisk_vmp_avalanche32_i(lo ^ cprisk_vmp_rotl32_i(hi, 7u) ^ 0xA5A5C3C3u);
    ledger ^= cprisk_vm_dispatch_bait_seed_i(1u, hi & 3u);
    cprisk_vm_entry_finish_pack32_fp_i fp = cprisk_vm_entry_finish_pack32_lane1_i;
    const uint32_t ticket = cprisk_vm_entry_ticket_i(func_id, (const void *)&cprisk_vm_entry_alt1, 1u)
        ^ ledger ^ ledger;
    return fp(lo, hi, 1u, ticket, (const void *)&cprisk_vm_entry_alt1);
}

// 备选入口 2：先清零票据，再让 func_id 与常量异或两次（恒等），最后走 lane2。
CPRISK_VM_EXPORT __attribute__((noinline)) uint64_t cprisk_vm_entry_alt2(uint64_t func_id) {
#if defined(__aarch64__)
    __asm__ volatile("eor x17, x0, x0");
#endif
    cprisk_vm_entry_ticket_t ticket;
    // memset + 两次异或常量都是显式的数据流噪声；最终 func_id 不变。
    memset(&ticket, 0, sizeof(ticket));
    ticket.func_id = func_id ^ UINT64_C(0x13579BDF2468ACE1);
    ticket.func_id ^= UINT64_C(0x13579BDF2468ACE1);
    ticket.hdr_sym = (const void *)&cprisk_vm_entry_alt2;
    ticket.lane = 2u;
    ticket.ticket = cprisk_vm_entry_ticket_i(func_id, ticket.hdr_sym, ticket.lane);
    if ((ticket.ticket & 1u) != 0u) {
        cprisk_vm_entry_finish_ticket_fp_i fp = cprisk_vm_entry_finish_ticket_lane2_i;
        return fp(&ticket);
    }
    return cprisk_vm_entry_finish_ticket_lane2_i(&ticket);
}
