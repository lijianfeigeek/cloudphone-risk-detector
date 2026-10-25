// cprisk_vm_interpreter_ops.h — 解释器核心与分片 handler 翻译单元之间的内部 API 声明。
// 这些符号统一以 _i 结尾，属于 CRiskCore 内部实现细节，不是公开 ABI，也不导出给 SDK 用户。
// 所有权：指针参数均由调用方持有；函数不分配内存、不缓存指针。
// 返回值契约：返回 int 的 helper 以 0=失败 / 非 0=成功；失败时由 helper 写 out->status/poison_flags。
// 线程模型：无全局可变状态；能否并发取决于调用方是否共享同一个 frame。
#ifndef CPRISK_VM_INTERPRETER_OPS_H
#define CPRISK_VM_INTERPRETER_OPS_H

/**
 * Opcode-handler helpers implemented in \c cprisk_vm_interpreter.c and callable from
 * \c cprisk_vm_oph_*.c translation units. They are intentionally not \c static so the VM
 * core stays in one TU while handler bodies are split for compilation-unit dispersion.
 */

#include "cprisk_vm_interpreter.h"
#include <stdint.h>

struct cprisk_vm_interp_frame;

// 小端读取 8 字节；不要求指针对齐，p 必须指向至少 8 字节可读内存。
uint64_t cprisk_read_le_u64_i(const uint8_t *p);

// 由 func_id 派生 VPC 仿射参数 (out_a, out_b)；两个输出指针都必须非空。
void cprisk_vmp_read_vpc_affine_i(const uint8_t *b_sec,
                                    const cprisk_vmp_bytecode_header_t *bh,
                                    uint64_t func_id,
                                    uint64_t *out_a,
                                    uint64_t *out_b);

// 32 位雪崩混合（纯函数）；用于 route 与间接目标派生，不是密码学哈希。
uint32_t cprisk_vmp_avalanche32_i(uint32_t x);

// 由 (func_id, pc_index, bind_root) 派生 64 位 lane 掩码；
// 仅在分发头启用 opaque-vpc 类别时用于解除 imm 的静态可见性。
uint64_t cprisk_vmp_raw_lane_mask_u64_i(uint64_t func_id, uint32_t pc_index, uint64_t bind_root);

// 把非法 opcode 混入 32 字节 acc；acc 必须指向 CPRISK_VM_ACC_PRIMARY_BYTES 大小的缓冲。
void cprisk_vm_poison_mix_unknown_i(uint8_t acc[32], uint32_t opcode, uint32_t cls);

// encoded_pc 的唯一写入口之一：把明文 pc 按 VPC 仿射参数编码；失败时 out 已置错误并返回 0。
int cprisk_vm_encode_pc_i(const cprisk_vmp_bytecode_header_t *bh,
                          uint32_t pc,
                          uint64_t vpc_a,
                          uint64_t vpc_b,
                          uint64_t *out_enc,
                          cprisk_vm_run_result_t *out);

// 顺序前进一条指令（+CPRISK_VM_INSN_WIDTH）并重新编码；所有 handler 的公共尾部。
int cprisk_vm_enc_pc_advance_ctx_i(const cprisk_vmp_bytecode_header_t *bh,
                                   uint64_t *enc_pc,
                                   uint64_t vpc_a,
                                   uint64_t vpc_b,
                                   cprisk_vm_run_result_t *out);

// 设置分支目标：delta 必须是 9 的整数倍，target 必须落在 [0, blen-INSN_WIDTH] 且无加法溢出。
int cprisk_vm_set_branch_target_ctx_i(const cprisk_vmp_bytecode_header_t *bh,
                                      uint64_t *enc_pc,
                                      uint64_t vpc_a,
                                      uint64_t vpc_b,
                                      uint32_t blen,
                                      uint32_t pc,
                                      int64_t delta_bytes,
                                      cprisk_vm_run_result_t *out);

// 累加器混淆后端：按 imm 的 8 个字节 lane 写 acc。
// variant/semantic_family/func_id/pc 只影响变形路径选择，不改变算子语义；route 只在 poly 版本生效。
void cprisk_vm_raw_region_apply_i(uint8_t acc[32],
                                  uint64_t imm,
                                  uint32_t steps,
                                  uint32_t variant,
                                  uint32_t semantic_family,
                                  uint64_t func_id,
                                  uint32_t pc);

void cprisk_vm_add_apply_i(uint8_t acc[32],
                           uint64_t imm,
                           uint32_t steps,
                           uint32_t variant,
                           uint32_t semantic_family,
                           uint64_t func_id,
                           uint32_t pc);

// lane 家族入口：family 0=加、1=减、2=乘；非法 family 直接返回（保持 acc 不变）。
void cprisk_vm_lane_apply_poly_i(uint8_t acc[32],
                                 uint32_t family,
                                 uint64_t imm,
                                 uint32_t steps,
                                 uint32_t variant,
                                 uint32_t semantic_family,
                                 uint64_t func_id,
                                 uint32_t pc,
                                 uint32_t route);

/**
 * Strategy 13 (polymorphic lane path): Diophantine / mod-field / polynomial mixing on trace only.
 * Invoked after \c cprisk_vm_lane_apply_poly_i when \c fr->vm_anti_symbolic_heavy and step/family gates pass.
 * Does not read or write \c fr->acc.
 */
// Diophantine/模域/多项式诱饵：只写 trace_scratch/trace_shadow，不读写 fr->acc。
// 调用门槛由函数内部判断（vm_anti_symbolic_heavy、semantic_family、steps 周期）。
void cprisk_vm_diophantine_lane_poly_sidefx_i(struct cprisk_vm_interp_frame *fr,
                                              uint32_t family,
                                              uint64_t imm,
                                              uint32_t route,
                                              uint32_t pc,
                                              uint32_t hvar);

// 条件谓词求值：成功返回 1 并写 out_taken/out_delta_bytes；
// 返回 0 表示 opcode 编码非法，调用方负责毒化并按“不跳转”继续。
int cprisk_vm_branch_cond_mixed_eval_i(uint32_t insn,
                                       const uint8_t acc[32],
                                       uint64_t steps,
                                       uint32_t semantic_family,
                                       uint32_t mixed_profile,
                                       int *out_taken,
                                       int64_t *out_delta_bytes);

// OR/AND 的逐字节实现：logical 决定算子；route 的最低位选择整 lane 家族路径或逐字节路径。
void cprisk_vm_bitwise_lane_poly_i(uint8_t acc[32],
                                   uint32_t logical,
                                   uint64_t imm,
                                   uint32_t steps,
                                   uint32_t variant,
                                   uint32_t semantic_family,
                                   uint32_t route);

// 32 字节环形旋转，旋转量取 imm & 31。
void cprisk_vm_rol_acc_i(uint8_t acc[32], uint64_t imm);

// vregs 为 8 个 64 位标量寄存器；imm 是打包位域描述符（dst/src/mode 等，字段定义见 helper 实现）。
// 三者分别模拟寄存器搬移、寄存器 ALU 与 acc↔vreg 的 8 字节存取。
void cprisk_vm_vreg_mov_i(uint64_t vregs[8], const uint8_t acc[32], uint64_t imm);

void cprisk_vm_vreg_alu_i(uint64_t vregs[8], uint64_t imm);

void cprisk_vm_vreg_mem_i(uint64_t vregs[8], uint8_t acc[32], uint64_t imm);

// 解析入口 profile 的三个字段：语义家族、混合谓词 profile、最大子调用深度。
// 返回 0 表示 reserved 未携带 magic（或字段非法），调用方应改用 fallback。
int cprisk_vm_entry_profile_decode_i(uint32_t entry_reserved,
                                     uint32_t *semantic_family,
                                     uint32_t *mixed_predicate_profile,
                                     uint32_t *max_subcall_depth);

// 确定性回退：用 (func_id, 字节码头 reserved) 派生与 decode 同构的三字段，保证无 magic 的旧字节码可执行。
void cprisk_vm_entry_profile_fallback_i(uint64_t func_id,
                                        uint32_t hdr_reserved,
                                        uint32_t *semantic_family,
                                        uint32_t *mixed_predicate_profile,
                                        uint32_t *max_subcall_depth);

#endif /* CPRISK_VM_INTERPRETER_OPS_H */
