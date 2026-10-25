// 文件职责：把阈值/魔数/校验值/掩码/密钥材料改为运行时派生，避免立即数留在二进制。
// 现状：未接入主路径（issue 65）；派生失败会退回确定性公式（可预测、非密码学强度）。
// 域号：BASE=10，RND/THRESH/MAGIC/CHECK/MASK/KEY=10..15；实际白盒域为 BASE+(domain%6)。
// 线程模型：唯一可变状态是 .c 内的 _Thread_local PRNG，线程间隔离；帧操作需串行。
// 失败语义：多数派生函数无失败返回（回退公式）；key_material 返回白盒原始错误码。
/* ════════════════════════════════════════════════════════════════════
 * DEPRECATED — 未接入主路径（issue 65）。
 * 本模块经核查无任何生产调用方（仅自身内部引用 / 仅被本模块自身包含），
 * 不属于主防御路径。保留文件仅为兼容（Xcode 工程仍列出本文件），请勿
 * 新接入、请勿将其能力计入防御声明。如需移除，请同步更新工程文件。
 * ════════════════════════════════════════════════════════════════════ */
/*
 *  vm_dynamic_const.h
 *  CRiskCore
 */

#ifndef VM_DYNAMIC_CONST_H
#define VM_DYNAMIC_CONST_H

#include <stdint.h>
#include <stddef.h>

#include "include/cprisk_vm_interpreter.h"
#include "include/cprisk_vm_interpreter_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

// 域常量既用于选择白盒域，也作为派生输入的一部分；改动会使既有常量全部变化。
// 经 %6 映射后 RND 与 BASE 同为 10、THRESH 映射到 15 等，名称与白盒域并非一一对应。
#define VM_CONST_DERIVE_DOMAIN_BASE     10
#define VM_CONST_DERIVE_DOMAIN_RND      10
#define VM_CONST_DERIVE_DOMAIN_THRESH   11
#define VM_CONST_DERIVE_DOMAIN_MAGIC    12
#define VM_CONST_DERIVE_DOMAIN_CHECK    13
#define VM_CONST_DERIVE_DOMAIN_MASK     14
#define VM_CONST_DERIVE_DOMAIN_KEY      15

// VM_OP_DERIVE 的操作类型（imm bits8–15）：LOAD/XOR/ADD/MASK 作用于 acc[0..3]，
// CMP_THRESH 只把派生值写入 trace_scratch，MIX_STATE 更新 opaque/session 链，
// 未知值退化为异或 opaque_chain。数值是字节码立即数协议，不能重排。
typedef enum {
    VM_DERIVE_OP_LOAD_ACC = 0,
    VM_DERIVE_OP_XOR_ACC = 1,
    VM_DERIVE_OP_ADD_ACC = 2,
    VM_DERIVE_OP_CMP_THRESH = 3,
    VM_DERIVE_OP_MASK_ACC = 4,
    VM_DERIVE_OP_MIX_STATE = 5,
} vm_derive_op_type_t;

// 统一派生入口：输入 domain(4)||func_id(8)||seed(4)，先 SHA-256 再按白盒域求值。
// 成功取输出前 4 字节（大端）；失败回退 (func_id>>32)^seed^(domain*0x9E3779B9)。
// 纯栈、可重入；返回值没有错误标志，调用方无法区分成功与回退。
uint32_t vm_const_derive_via_whitebox(uint32_t domain,
                                       uint64_t func_id,
                                       uint32_t seed);

// 阈值派生：seed=(func_id 高低 32 位异或)^threshold_type，再走白盒域 THRESH。
// 纯函数、可并发；无失败路径，返回 32 位阈值且不做范围裁剪。
uint32_t vm_const_derive_cmp_threshold(uint64_t func_id, uint32_t threshold_type);

// 魔数派生：magic_type 直接作为 seed；同一函数下不同类型得到不同值。纯函数。
uint32_t vm_const_derive_magic(uint64_t func_id, uint32_t magic_type);

// 校验值派生：check_type 作为 seed；结果确定可复现，但不是认证凭据。纯函数。
uint32_t vm_const_derive_check_value(uint64_t func_id, uint32_t check_type);

// 掩码派生：取 32 位原始值后按 bit_width 截断；≥32 原样返回，0 返回 0。纯函数。
uint32_t vm_const_derive_mask(uint64_t func_id, uint32_t mask_type, uint8_t bit_width);

// 派生 32 字节密钥材料：白盒域 KEY，输入 func_id||key_index。
// key_out 必须可写 32 字节，仅在返回 0 时有效（失败不清零）。
// 返回白盒原始错误码，没有本地兜底；纯栈、可并发。
int vm_const_derive_key_material(uint64_t func_id,
                                  uint32_t key_index,
                                  uint8_t key_out[32]);

// VM_OP_LOAD_RND：imm bits0–4 目标 acc 槽，bit5=1 走白盒派生、0 走 TLS PRNG。
// PRNG 每次按 (func_id, steps) 重新播种，相同步数重复执行得到同一序列。
// 写 acc[slot]、acc_aux[(slot+16)&31] 并混入 opaque_chain；返回 CONTINUE，fr NULL 返回 LEAVE。
cprisk_vm_flow_t vm_op_load_rnd_execute(cprisk_vm_interp_frame_t *fr,
                                         uint64_t imm);

// VM_OP_DERIVE：imm bits0–7 domain、bits8–15 op_type、bits16–31 seed；
// 实际 seed 再与 steps 低 32 位异或，使同一指令在不同位置得到不同常量。
// 按 op_type 写 acc/trace_scratch/opaque 链；返回 CONTINUE，fr NULL 返回 LEAVE。
cprisk_vm_flow_t vm_op_derive_execute(cprisk_vm_interp_frame_t *fr,
                                       uint64_t imm);

// 计算函数身份指纹：SHA256(func_id || bytecode? || 运行时白盒材料? || 版本标签)。
// bytecode 可为 NULL；hash_out 必须可写 32 字节；恒返回 0（无失败路径）。
// 白盒材料缺失时静默跳过，跨进程哈希可能不同，不要用于跨进程比较。
int vm_const_hash_function_identity(uint64_t func_id,
                                     const uint8_t *bytecode,
                                     size_t bytecode_len,
                                     uint8_t hash_out[32]);

// 从身份哈希取 4 字节常量：offset=(const_index*4)%28，再异或 const_index*黄金比例；
// 索引每 7 个回绕一次。纯函数，无失败路径，返回 32 位值。
uint32_t vm_const_derive_from_identity(uint64_t func_id, uint32_t const_index);

// VM 初始化时写 acc[0..3]、acc_aux[16..19] 与 session 混合值；会覆盖累加器初值，
// 必须在执行第一条指令前调用。fr NULL 时无操作。
void vm_dynamic_const_apply_to_interp(cprisk_vm_interp_frame_t *fr);

// 重置当前线程的 PRNG（清零后用 func_id,pc=0 重新播种）；只影响调用线程。
void vm_dynamic_const_reset_for_func(uint64_t func_id);

// 返回 base_value ^ identity-derived 常量（索引 cmp_type+100）；
// 结果不做范围裁剪，需要上界的调用方必须自行 clamp。纯函数，无失败路径。
uint32_t vm_const_get_func_cmp_threshold(uint64_t func_id,
                                          uint32_t cmp_type,
                                          uint32_t base_value);

#ifdef __cplusplus
}
#endif

#endif
