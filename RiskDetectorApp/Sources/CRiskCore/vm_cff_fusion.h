// 文件职责：VM 与 CFF 融合——Feistel 编码 PC/状态、轨迹环与不透明度摘要。
// 现状：由 cprisk_vm_hardening.c 调用，是把 CFF 状态机接入 VM 循环的桥接层。
// 编码：32 位状态经 8 轮 16 位 Feistel（8 位 S-box）+ 前后白化，固定 rk 下为双射。
// 线程模型：ctx 单写者；trace_pos 每次 encode 推进，不能跨线程并发调用。
// 失败语义：ctx NULL 静默返回；state_encoded=0 时 encode/decode 原样返回（fail-open）。
/*
 *  vm_cff_fusion.h
 *  CRiskCore
 */

#ifndef VM_CFF_FUSION_H
#define VM_CFF_FUSION_H

#include <stdint.h>
#include <stddef.h>

#include "include/cprisk_vm_interpreter.h"
#include "include/cprisk_vm_interpreter_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

// CFF 融合上下文：rk[8] 为 Feistel 轮密钥，encoded_state 保存最近编码状态，
// cff_magic 为初始化哨兵 0xCFF0CFF0，trace_buffer[16] 是按位置掩码的轨迹环，
// trace_pos 单调递增（取模 16），opaque_chain 为混淆链。state_encoded=0 表示未启用，
// corruption_detected 是粘滞损坏标志，reserved 必须保持 0。
// 所有权：调用方提供，无堆指针；敏感字段由调用方负责清除。
typedef struct {
    uint64_t func_id;
    uint8_t  bytecode_hash[32];
    uint32_t rk[8];
    uint32_t encoded_state;
    uint32_t cff_magic;
    uint32_t trace_buffer[16];
    uint32_t trace_pos;
    uint32_t opaque_chain;
    uint8_t  state_encoded;
    uint8_t  corruption_detected;
    uint8_t  reserved[2];
} vm_cff_fusion_ctx_t;

// 初始化：清零 → 记录 func_id/bytecode_hash → 写魔数与初始状态 → 由 IKM 展开 8 个轮密钥。
// ctx 非 NULL；bytecode_hash 可为 NULL（用 func_id 派生稳定填充）。无返回值。
// 成功置 state_encoded=1；只写 ctx，平台无关。
void vm_cff_fusion_init(vm_cff_fusion_ctx_t *ctx,
                         uint64_t func_id,
                         const uint8_t *bytecode_hash);

// 编码 PC 并把 encoded^keystream(pos) 写入 trace_buffer[pos%16]，随后 pos 递增。
// 返回未加掩码的 encoded 值；ctx NULL 或未启用时原样返回 pc（fail-open）。
// 写轨迹，必须串行。
uint32_t vm_cff_fusion_encode_pc(vm_cff_fusion_ctx_t *ctx, uint32_t pc);

// 解码 encoded_pc；ctx NULL/未启用时原样返回；rk 不一致时得到错误值而非报错。
// 纯查询、不推进轨迹；只读 ctx，可并发读。
uint32_t vm_cff_fusion_decode_pc(vm_cff_fusion_ctx_t *ctx, uint32_t encoded_pc);

// 先解码 current_encoded，再按 branch_hint（0=顺序+1，否则为目标 PC）算下一明文 PC，
// 重新编码写入 *next_encoded，并把旧/新编码值的 SHA-256 前 4 字节混入 opaque_chain。
// ctx/next_encoded 非 NULL；branch_hint 不做范围校验；更新 encoded_state，需串行。
void vm_cff_fusion_transition(vm_cff_fusion_ctx_t *ctx,
                               uint32_t current_encoded,
                               uint32_t *next_encoded,
                               uint32_t branch_hint);

// VM_OP_CFF_ENCODE：imm bits0–4 槽位，bit5=1 时异或 acc[0..3] 组成的值；
// 编码结果按小端写回 slot..slot+3（&31 回绕）。返回 CONTINUE，fr NULL 返回 LEAVE。
// 槽位回绕可能覆盖相邻槽，调用方须预留连续 4 槽。
cprisk_vm_flow_t vm_op_cff_encode_execute(cprisk_vm_interp_frame_t *fr,
                                           uint64_t imm);

// VM_OP_CFF_DECODE：从 slot..slot+3（&31）小端重组编码值，解码后写回同一组槽。
// imm 只有低 5 位有效。返回 CONTINUE，fr NULL 返回 LEAVE；rk 不符得到错误明文。
cprisk_vm_flow_t vm_op_cff_decode_execute(cprisk_vm_interp_frame_t *fr,
                                           uint64_t imm);

// VM_OP_CFF_TRANSITION：把帧内 CFF 字段打包成临时 ctx，执行一次 transition 再写回。
// imm bits0–23 为 PC 提示，bit24=1 时改用 acc[0..2] 拼出的 24 位地址。
// 返回 CONTINUE，fr NULL 返回 LEAVE；临时 ctx 用后 secure_zero。
cprisk_vm_flow_t vm_op_cff_transition_execute(cprisk_vm_interp_frame_t *fr,
                                               uint64_t imm);

// 在帧上启用 CFF：初始化 ctx、拷入轮密钥、编码初始 cff_vpc 并同步轨迹/魔数。
// 应在执行前调用一次；重复调用会把已编码的 vpc 再编码一次。fr NULL 时无操作。
void vm_cff_fusion_apply_to_interp(cprisk_vm_interp_frame_t *fr);

// 自检：常量时间比较 cff_magic；轨迹非空时对最后一条做 decode→encode 往返，
// 差异折叠为 1 位并 OR 进 corruption_detected（粘滞）。不修复状态。
// 是自洽性检查，不是 MAC；ctx NULL 时无操作。
void vm_cff_fusion_verify_integrity(vm_cff_fusion_ctx_t *ctx);

// 汇总 8 个轮密钥、opaque_chain 与 trace_pos 为 32 位确定性摘要（非随机数/凭据）。
// ctx NULL 返回 0；只读，可并发读。
uint32_t vm_cff_fusion_get_opacity(vm_cff_fusion_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif
