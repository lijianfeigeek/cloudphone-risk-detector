// cprisk_vm_oph_lane.c — lane 算术族：ADD / ADD_ROL_ACC / SUB_LANE / MUL_LANE。
// 每个处理器把 imm 的 8 个字节分别加到/减到/乘到 acc 的 8 个 lane，物理 lane 映射由 acc_lane_map 决定。
// 先由 avalanche32(hvar, steps, opaque_chain, session_mix) 派生 route，route 选择逐字节等价变形路径。
// 语义副作用：lane_apply_poly 之后调用 diophantine side-effect，仅在高强度反符号执行模式下写 trace，不改 acc。
// 统一契约：不触碰 vregs，成功时 steps+1 并推进 encoded_pc；helper 失败即 LEAVE。
#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_ops.h"

// ADD：把 imm 的 8 个字节加到 acc 的 8 个 lane（lane 0 家族）。
cprisk_vm_flow_t cprisk_vm_oph_add(cprisk_vm_interp_frame_t *fr,
                                   uint8_t op_raw,
                                   uint8_t logical,
                                   uint64_t imm,
                                   uint32_t pc,
                                   uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    // 0xADD 是 ADD 的域标签，保证与 SUB(0x5B2)/MUL(0x6D3) 在同一帧下派生出不同 route。
    const uint32_t route = cprisk_vmp_avalanche32_i(
        hvar ^ (uint32_t)fr->steps ^ fr->opaque_chain ^ fr->session_mix ^ 0xADDu
    );
    // acc_lane_map[0] 是 add 家族的物理 lane；排列由入口 profile 决定，默认恒等 {0,1,2}。
    cprisk_vm_lane_apply_poly_i(
        fr->acc,
        fr->acc_lane_map[0],
        imm,
        (uint32_t)fr->steps,
        hvar,
        fr->semantic_family,
        fr->func_id,
        pc,
        route
    );
    // 仅在 vm_anti_symbolic_heavy 且语义家族/步数门槛满足时执行；只写 trace 诱饵，不改变 acc。
    cprisk_vm_diophantine_lane_poly_sidefx_i(fr, fr->acc_lane_map[0], imm, route, pc, hvar);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

// ADD_ROL_ACC：融合指令，一次处理“先加后旋”两半语义。
// imm 低 32 位作为加数走 lane 0，高 32 位作为整体旋转量，两半共享同一 route。
cprisk_vm_flow_t cprisk_vm_oph_add_rol_acc(cprisk_vm_interp_frame_t *fr,
                                           uint8_t op_raw,
                                           uint8_t logical,
                                           uint64_t imm,
                                           uint32_t pc,
                                           uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    // 低/高 32 位拆分是 fused 指令的固定 ABI，不能随意重排。
    const uint64_t imm_add = imm & 0xFFFFFFFFu;
    const uint64_t imm_rol = imm >> 32;
    // 0xF15510F0 使融合指令的 route 与普通 ADD 分离，避免同一帧内两条指令共用变形路径。
    const uint32_t route = cprisk_vmp_avalanche32_i(
        hvar ^ (uint32_t)fr->steps ^ fr->opaque_chain ^ fr->session_mix ^ 0xADDu ^ 0xF15510F0u
    );
    cprisk_vm_lane_apply_poly_i(
        fr->acc,
        fr->acc_lane_map[0],
        imm_add,
        (uint32_t)fr->steps,
        hvar,
        fr->semantic_family,
        fr->func_id,
        pc,
        route
    );
    cprisk_vm_diophantine_lane_poly_sidefx_i(fr, fr->acc_lane_map[0], imm_add, route, pc, hvar);
    cprisk_vm_rol_acc_i(fr->acc, imm_rol);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

// SUB_LANE：lane 1 家族的逐字节减法；helper 内部用加法与逐字节补码实现等价语义。
cprisk_vm_flow_t cprisk_vm_oph_sub_lane(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    // 0x5B2 区分 SUB 域，使减法与加法的 route 派生互不相关。
    const uint32_t route = cprisk_vmp_avalanche32_i(
        hvar ^ (uint32_t)fr->steps ^ fr->opaque_chain ^ fr->session_mix ^ 0x5B2u
    );
    cprisk_vm_lane_apply_poly_i(
        fr->acc,
        fr->acc_lane_map[1],
        imm,
        (uint32_t)fr->steps,
        hvar,
        fr->semantic_family,
        fr->func_id,
        pc,
        route
    );
    cprisk_vm_diophantine_lane_poly_sidefx_i(fr, fr->acc_lane_map[1], imm, route, pc, hvar);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

// MUL_LANE：lane 2 家族的逐字节乘法，覆盖 MADD-as-MUL 与 DIV 提升后的乘法用例。
cprisk_vm_flow_t cprisk_vm_oph_mul_lane(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    // 0x6D3 区分 MUL 域；乘法 route 还允许 helper 走“先取负再相乘”的等价路径。
    const uint32_t route = cprisk_vmp_avalanche32_i(
        hvar ^ (uint32_t)fr->steps ^ fr->opaque_chain ^ fr->session_mix ^ 0x6D3u
    );
    cprisk_vm_lane_apply_poly_i(
        fr->acc,
        fr->acc_lane_map[2],
        imm,
        (uint32_t)fr->steps,
        hvar,
        fr->semantic_family,
        fr->func_id,
        pc,
        route
    );
    cprisk_vm_diophantine_lane_poly_sidefx_i(fr, fr->acc_lane_map[2], imm, route, pc, hvar);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}
