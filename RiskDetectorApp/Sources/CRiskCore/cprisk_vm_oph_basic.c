// cprisk_vm_oph_basic.c — VM 基础 opcode：NOP / RET / HALT / RAW_REGION / POISON / UNKNOWN。
// 位于分发表最内层，与 lane/branch/emitter/vreg 各家族处理器同属一个解释器循环。
// 统一契约：处理器只改写 fr 内状态并调用 enc_pc_advance 推进游标；推进失败一律返回 LEAVE。
// 线程模型：单次 run 内串行执行，fr 为非共享可变状态，不可并发复用同一帧。
// 失败语义：PC 编码/越界由 helper 写入 INVALID_BYTECODE / POISON_BYTECODE，调用方按失败即拒绝处理。
#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_ops.h"

#include <string.h>

// 显式 POISON（0xFF）opcode 的处理器：标记本次 run 已被污染，并把原始 opcode 混入累加器。
// 与 unknown 处理器行为一致，二者仅入口条件不同（显式毒化 vs logical 超出分发表长度）。
cprisk_vm_flow_t cprisk_vm_oph_poison(cprisk_vm_interp_frame_t *fr,
                                      uint8_t op_raw,
                                      uint8_t logical,
                                      uint64_t imm,
                                      uint32_t pc,
                                      uint32_t hvar) {
    (void)imm;
    (void)pc;
    (void)hvar;
    // 毒化标记只置位不清零，供 post-handler 与调用方在 run 结束后统一判定。
    fr->out->poison_flags |= CPRISK_VM_POISON_UNKNOWN_OPCODE;
    // 把 (op_raw, logical) 混入 acc，使非法指令在累加器轨迹上可观测、不可被静默忽略。
    cprisk_vm_poison_mix_unknown_i(fr->acc, (uint32_t)op_raw, (uint32_t)logical);
    // 即便已毒化仍推进 PC：保持“一步一条指令”的不变量，避免同一字节码反复触发同一处理器。
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

// logical 超出 0..23 分发表范围的兜底处理器：语义与 poison 相同，防止越界索引分发表。
cprisk_vm_flow_t cprisk_vm_oph_unknown(cprisk_vm_interp_frame_t *fr,
                                       uint8_t op_raw,
                                       uint8_t logical,
                                       uint64_t imm,
                                       uint32_t pc,
                                       uint32_t hvar) {
    (void)imm;
    (void)pc;
    (void)hvar;
    fr->out->poison_flags |= CPRISK_VM_POISON_UNKNOWN_OPCODE;
    cprisk_vm_poison_mix_unknown_i(fr->acc, (uint32_t)op_raw, (uint32_t)logical);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

// NOP：纯空操作，是变体池、死代码填充与指令对齐的基元。
// 语义不变量：acc、vregs、opaque_* 均不变，只 steps+1 并推进 encoded_pc。
cprisk_vm_flow_t cprisk_vm_oph_nop(cprisk_vm_interp_frame_t *fr,
                                   uint8_t op_raw,
                                   uint8_t logical,
                                   uint64_t imm,
                                   uint32_t pc,
                                   uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    (void)imm;
    (void)pc;
    (void)hvar;
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

// HALT：正常终止解释器。推进 PC 后写 status=OK 并返回 LEAVE，属于“成功退出”而非失败路径。
// 与 RET 的兜底分支区别：HALT 不查返回栈/快照，任何位置都会结束整个 run。
cprisk_vm_flow_t cprisk_vm_oph_halt(cprisk_vm_interp_frame_t *fr,
                                    uint8_t op_raw,
                                    uint8_t logical,
                                    uint64_t imm,
                                    uint32_t pc,
                                    uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    (void)imm;
    (void)pc;
    (void)hvar;
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    // 只有真正执行到 HALT 才置 OK；任何 helper 失败都已在上面提前 LEAVE 且保持错误状态。
    fr->out->status = CPRISK_VM_STATUS_OK;
    return CPRISK_VM_FLOW_LEAVE;
}

// RET：三级返回。依次尝试子调用返回栈、跨函数调用快照，最后视为函数自然结束。
cprisk_vm_flow_t cprisk_vm_oph_ret(cprisk_vm_interp_frame_t *fr,
                                   uint8_t op_raw,
                                   uint8_t logical,
                                   uint64_t imm,
                                   uint32_t pc,
                                   uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    (void)imm;
    (void)pc;
    (void)hvar;
    // 第一优先级：普通 CALL 压入的编码返回 PC（同一函数内返回）。
    if (fr->return_sp > 0u) {
        fr->return_sp -= 1u;
        fr->encoded_pc = fr->return_stack[fr->return_sp];
        fr->steps += 1u;
        return CPRISK_VM_FLOW_CONTINUE;
    }
    // 第二优先级：VM_CALL_FUNC 的调用快照，恢复 caller 的 code/blen/VPC/返回栈/vregs/lane 映射。
    if (fr->vm_snap_sp > 0u) {
        fr->vm_snap_sp -= 1u;
        fr->encoded_pc = fr->vm_snap[fr->vm_snap_sp].resume_enc_pc;
        fr->code = fr->vm_snap[fr->vm_snap_sp].snap_code;
        fr->blen = fr->vm_snap[fr->vm_snap_sp].snap_blen;
        fr->vpc_a = fr->vm_snap[fr->vm_snap_sp].snap_vpc_a;
        fr->vpc_b = fr->vm_snap[fr->vm_snap_sp].snap_vpc_b;
        fr->semantic_family = fr->vm_snap[fr->vm_snap_sp].snap_semantic_family;
        fr->mixed_predicate_profile = fr->vm_snap[fr->vm_snap_sp].snap_mixed_predicate_profile;
        fr->max_subcall_depth = fr->vm_snap[fr->vm_snap_sp].snap_max_subcall_depth;
        memcpy(fr->return_stack, fr->vm_snap[fr->vm_snap_sp].snap_ret_stack, sizeof(fr->return_stack));
        fr->return_sp = fr->vm_snap[fr->vm_snap_sp].snap_ret_sp;
        memcpy(fr->vregs, fr->vm_snap[fr->vm_snap_sp].snap_vregs, sizeof(fr->vregs));
        fr->acc_lane_map[0] = fr->vm_snap[fr->vm_snap_sp].snap_acc_lane_map[0];
        fr->acc_lane_map[1] = fr->vm_snap[fr->vm_snap_sp].snap_acc_lane_map[1];
        fr->acc_lane_map[2] = fr->vm_snap[fr->vm_snap_sp].snap_acc_lane_map[2];
        fr->steps += 1u;
        return CPRISK_VM_FLOW_CONTINUE;
    }
    // 兜底：既无返回栈也无快照 => 视为顶层函数正常结束，status=OK 并 LEAVE。
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    fr->out->status = CPRISK_VM_STATUS_OK;
    return CPRISK_VM_FLOW_LEAVE;
}

// RAW_REGION：原始字节混淆区，按 imm 的 8 个字节 lane 对 acc 做整表变形。
// 与 ADD/SUB/MUL lane 不同，它不区分运算家族（semantic_family 仅作为变形样式种子）。
cprisk_vm_flow_t cprisk_vm_oph_raw_region(cprisk_vm_interp_frame_t *fr,
                                          uint8_t op_raw,
                                          uint8_t logical,
                                          uint64_t imm,
                                          uint32_t pc,
                                          uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    uint64_t imm_use = imm;
    // 分发头启用不透明 VPC 类别时，立即数先与 PC/func 绑定的 lane mask 异或；
    // 攻击者即使静态读出 imm 字节，也无法在不重建 raw_bind_root 的情况下还原语义。
    if ((fr->dispatch_hdr_flags & CPRISK_VMP_DH_FLAG_OPAQUE_VPC_CATEGORY) != 0u) {
        const uint32_t pc_index = pc / CPRISK_VM_INSN_WIDTH;
        imm_use ^= cprisk_vmp_raw_lane_mask_u64_i(fr->func_id, pc_index, fr->raw_bind_root);
    }
    // hvar 作为 variant 传入：同一 opcode 在不同分发槽位会选到不同的 lane 变形样式。
    cprisk_vm_raw_region_apply_i(fr->acc, imm_use, (uint32_t)fr->steps, hvar, fr->semantic_family, fr->func_id, pc);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}
