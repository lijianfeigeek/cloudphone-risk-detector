// cprisk_vm_oph_branch.c — 控制流族：BRANCH_REL / BRANCH_IND / BRANCH_COND / CALL。
// 所有分支都通过 cprisk_vm_set_branch_target_ctx_i 设置 encoded_pc，由它统一校验 9 字节对齐、上下界与溢出。
// 目标若直接来自 imm 可被静态还原，因此 IND/COND 会先把 acc/vreg/session 状态混入目标计算。
// 失败语义：非法 delta、越界目标、深度超限、PC 编码失败一律置 INVALID_BYTECODE 并 LEAVE（fail-closed）。
// 线程模型：只读写 fr；CALL 的返回栈与深度上限均为帧内状态，不可跨帧共享。
#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_ops.h"

// 从 acc 的两个窗口（主区连续 8 字节 + aux 区步长 3 采样）、semantic_family、session_mix、
// vregs[vidx] 与 func_id 派生 64 位 q。q 只读不写；同一帧同一位置确定，跨会话/跨函数不可预测。
static uint64_t cprisk_vm_branch_ind_compute_q(const cprisk_vm_interp_frame_t *fr,
                                             uint32_t vidx,
                                             uint32_t acc_byte0) {
    uint64_t mix = 0u;
    uint64_t aux_mix = 0u;
    for (uint32_t i = 0; i < 8u; i++) {
        // &31 回绕保证任意 acc_byte0 都落在 32 字节累加器内；aux 以 i*3 采样第二个寄存器组。
        mix |= (uint64_t)fr->acc[(acc_byte0 + i) & 31u] << (i * 8u);
        aux_mix |= (uint64_t)fr->acc_aux[(acc_byte0 + i * 3u) & 31u] << (i * 8u);
    }
    mix ^= (uint64_t)fr->semantic_family << 48;
    mix ^= aux_mix ^ ((uint64_t)fr->session_mix << 17u);
    uint64_t q = fr->vregs[vidx] ^ mix;
    q ^= fr->func_id ^ (fr->func_id >> 32u);
    return q;
}

// BRANCH_REL：相对分支，imm 直接解释为有符号字节偏移（必须为 9 的整数倍）。
// 目标合法性、对齐与溢出全部交给 set_branch_target_ctx_i，本函数不做二次判断。
cprisk_vm_flow_t cprisk_vm_oph_branch_rel(cprisk_vm_interp_frame_t *fr,
                                          uint8_t op_raw,
                                          uint8_t logical,
                                          uint64_t imm,
                                          uint32_t pc,
                                          uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    (void)hvar;
    int64_t delta = (int64_t)(uint64_t)imm;
    if (!cprisk_vm_set_branch_target_ctx_i(
            fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->blen, pc, delta, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

// BRANCH_IND：间接分支。imm 的编码分三种：semi-identity 空跳、semi-semantic 有界前跳、全量取模跳转。
// 前两种用于混淆控制流图（让静态分析看到“有跳转”但实际作用受限），第三种才是真正的计算型间接跳转。
cprisk_vm_flow_t cprisk_vm_oph_branch_ind(cprisk_vm_interp_frame_t *fr,
                                          uint8_t op_raw,
                                          uint8_t logical,
                                          uint64_t imm,
                                          uint32_t pc,
                                          uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    (void)hvar;
    // 标签命中 => 该指令只是编码层面的占位，等价于顺序前进一格。
    if ((imm & CPRISK_VM_BRANCH_IND_SEMI_IDENTITY_MASK) == CPRISK_VM_BRANCH_IND_SEMI_IDENTITY_TAG) {
        if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
            return CPRISK_VM_FLOW_LEAVE;
        fr->steps += 1u;
        return CPRISK_VM_FLOW_CONTINUE;
    }
    const uint32_t vidx = (uint32_t)(imm & 7u);
    const uint32_t acc_byte0 = (uint32_t)((imm >> 3) & 31u);
    // 半语义模式：前跳 1..(forward_span+1) 条指令，距离由 q 取模决定；上界限幅防止跳出函数体。
    if ((imm & CPRISK_VM_BRANCH_IND_SEMI_SEMANTIC_MASK) == CPRISK_VM_BRANCH_IND_SEMI_SEMANTIC_TAG) {
        uint64_t q = cprisk_vm_branch_ind_compute_q(fr, vidx, acc_byte0);
        const uint32_t forward_span = (uint32_t)((imm >> 8) & 0xFFu);
        const uint32_t skip = (forward_span > 0u)
            ? (uint32_t)(q % (uint64_t)(forward_span + 1u))
            : 0u;
        const int64_t delta = (int64_t)((1u + skip) * CPRISK_VM_INSN_WIDTH);
        if (!cprisk_vm_set_branch_target_ctx_i(
                fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->blen, pc, delta, fr->out))
            return CPRISK_VM_FLOW_LEAVE;
        fr->steps += 1u;
        return CPRISK_VM_FLOW_CONTINUE;
    }
    uint64_t q = cprisk_vm_branch_ind_compute_q(fr, vidx, acc_byte0);
    const uint32_t insn_count = fr->blen / CPRISK_VM_INSN_WIDTH;
    /*
     * Reject single-instruction bytecode here too: with insn_count == 1 the
     * indirect-branch resolves to PC 0 unconditionally, producing a self-loop
     * that would burn the entire iteration budget before LEAVE. Callers that
     * legitimately produce a 1-instruction bytecode never hit this branch
     * (they have no indirect target to compute), so refusing here is a pure
     * defensive guard against malformed/truncated bytecode.
     */
    if (insn_count < 2u) {
        fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
        fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        return CPRISK_VM_FLOW_LEAVE;
    }
    // 全量模式：q 对指令总数取模得到目标指令下标，再换算成相对当前 pc 的字节偏移。
    const uint32_t target_insn = (uint32_t)(q % (uint64_t)insn_count);
    const uint32_t target_pc = target_insn * CPRISK_VM_INSN_WIDTH;
    const int64_t delta = (int64_t)(uint64_t)target_pc - (int64_t)(uint64_t)pc;
    if (!cprisk_vm_set_branch_target_ctx_i(
            fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->blen, pc, delta, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

// BRANCH_COND：条件分支。谓词求值失败不等于执行失败——置毒化标记后按“不跳转”继续，
// 这样恶意字节码不会被静默放过，而正常控制流仍能推进到后续指令（毒化状态由调用方统一裁决）。
cprisk_vm_flow_t cprisk_vm_oph_branch_cond(cprisk_vm_interp_frame_t *fr,
                                           uint8_t op_raw,
                                           uint8_t logical,
                                           uint64_t imm,
                                           uint32_t pc,
                                           uint32_t hvar) {
    (void)hvar;
    int taken = 0;
    int64_t delta = 0;
    if (!cprisk_vm_branch_cond_mixed_eval_i(
            (uint32_t)imm,
            fr->acc,
            fr->steps,
            fr->semantic_family,
            fr->mixed_predicate_profile,
            &taken,
            &delta
        )) {
        fr->out->poison_flags |= CPRISK_VM_POISON_UNKNOWN_OPCODE;
        cprisk_vm_poison_mix_unknown_i(fr->acc, (uint32_t)op_raw, (uint32_t)logical);
        if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
            return CPRISK_VM_FLOW_LEAVE;
        fr->steps += 1u;
        return CPRISK_VM_FLOW_CONTINUE;
    }
    if (taken) {
        // taken 时 delta 由 mixed eval 依据谓词/家族/profile 计算，仍走统一目标校验。
        if (!cprisk_vm_set_branch_target_ctx_i(
                fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->blen, pc, delta, fr->out))
            return CPRISK_VM_FLOW_LEAVE;
    } else {
        if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
            return CPRISK_VM_FLOW_LEAVE;
    }
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

// CALL：先把 pc+INSN_WIDTH 编码后压入返回栈，再复用相对分支逻辑跳转。
// 深度上限取 profile 与静态数组大小的较小者，损坏的 profile 无法撑爆 return_stack。
cprisk_vm_flow_t cprisk_vm_oph_call(cprisk_vm_interp_frame_t *fr,
                                    uint8_t op_raw,
                                    uint8_t logical,
                                    uint64_t imm,
                                    uint32_t pc,
                                    uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    (void)hvar;
    /*
     * `max_subcall_depth` is part of the per-frame profile and would normally
     * be capped at `CPRISK_VM_MAX_SUBCALL_DEPTH` by `cprisk_vm_entry_profile_*`.
     * If a corrupted profile inflates it past the static return_stack size,
     * the upper bound below would let us write OOB. Clamp against the actual
     * array size as a hard ceiling.
     */
    const uint32_t depth_cap = (fr->max_subcall_depth < (uint32_t)CPRISK_VM_MAX_SUBCALL_DEPTH)
        ? fr->max_subcall_depth
        : (uint32_t)CPRISK_VM_MAX_SUBCALL_DEPTH;
    if (fr->return_sp >= depth_cap) {
        fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
        fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        return CPRISK_VM_FLOW_LEAVE;
    }
    uint64_t ret_pc = (uint64_t)pc + CPRISK_VM_INSN_WIDTH;
    uint64_t ret_enc = 0u;
    // 返回 PC 编码失败说明 VPC 上下文损坏，必须在压栈之前失败，避免返回栈残留半状态。
    if (!cprisk_vm_encode_pc_i(fr->bh, (uint32_t)ret_pc, fr->vpc_a, fr->vpc_b, &ret_enc, fr->out)) {
        fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
        fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        return CPRISK_VM_FLOW_LEAVE;
    }
    fr->return_stack[fr->return_sp] = ret_enc;
    fr->return_sp += 1u;
    int64_t delta = (int64_t)(uint64_t)imm;
    if (!cprisk_vm_set_branch_target_ctx_i(
            fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->blen, pc, delta, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}
