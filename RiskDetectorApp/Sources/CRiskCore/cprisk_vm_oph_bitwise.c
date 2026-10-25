// cprisk_vm_oph_bitwise.c — 位运算族 opcode：XOR_MIX / OR_LANE / AND_LANE / ROL_ACC。
// 负责把立即数按“整累加器异或”或“逐字节位运算”两种粒度混入 32 字节 acc。
// 三个 lane 处理器都先用 avalanche32 派生 route，route 决定具体变形路径与映射顺序。
// 统一契约：不触碰 vregs/opaque_*，成功时 steps+1 并推进 encoded_pc，helper 失败即 LEAVE。
// 线程模型：只操作调用方传入的 fr，无全局状态，同一帧不可并发使用。
#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_ops.h"

// XOR_MIX：把 imm 先做 ROTL64(17) 并与 semantic_family 高位混合，再交给 32 字节 raw_region。
// 与 OR/AND 不同，它作用于整个累加器，不区分单条 lane 的运算语义。
cprisk_vm_flow_t cprisk_vm_oph_xor_mix(cprisk_vm_interp_frame_t *fr,
                                       uint8_t op_raw,
                                       uint8_t logical,
                                       uint64_t imm,
                                       uint32_t pc,
                                       uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    // ROTL64(imm,17) 把高位卷回低位，保证 8 个 lane 字节都受 imm 影响；
    // family 写入最高字节，用于区分同一 imm 在不同函数中的轨迹。
    uint64_t mix_imm = imm ^ ((imm << 17u) | (imm >> 47u)) ^ ((uint64_t)fr->semantic_family << 56u);
    // variant/family 各翻转一位，使 XOR_MIX 与 ADD 在同一 (steps,pc) 下落到不同 lane 布局。
    cprisk_vm_raw_region_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps, hvar ^ 1u, fr->semantic_family ^ 1u, fr->func_id, pc);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

// OR_LANE：按字节把 imm 的 8 个 lane 与 acc 做按位或。
// route 的 LSB 决定 cprisk_vm_bitwise_lane_poly_i 走整 lane 家族实现还是逐字节回退路径。
cprisk_vm_flow_t cprisk_vm_oph_or_lane(cprisk_vm_interp_frame_t *fr,
                                       uint8_t op_raw,
                                       uint8_t logical,
                                       uint64_t imm,
                                       uint32_t pc,
                                       uint32_t hvar) {
    (void)op_raw; (void)pc;
    // route 混合 hvar/opaque_chain/session_mix 后 avalanche；0x0F0F 是 OR_LANE 域常量。
    const uint32_t route = cprisk_vmp_avalanche32_i(
        hvar ^ fr->opaque_chain ^ fr->session_mix ^ 0x0F0Fu
    );
    cprisk_vm_bitwise_lane_poly_i(
        fr->acc,
        logical,
        imm,
        (uint32_t)fr->steps,
        hvar,
        fr->semantic_family,
        route
    );
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

// AND_LANE：与 OR_LANE 共用 bitwise_lane_poly 后端，logical 参数把它切换为按位与。
cprisk_vm_flow_t cprisk_vm_oph_and_lane(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar) {
    (void)op_raw; (void)pc;
    // 0xF0F0 与 OR_LANE 的 0x0F0F 互为反码域常量，避免两个 opcode 在同一帧派生相同 route。
    const uint32_t route = cprisk_vmp_avalanche32_i(
        hvar ^ fr->opaque_chain ^ fr->session_mix ^ 0xF0F0u
    );
    cprisk_vm_bitwise_lane_poly_i(
        fr->acc,
        logical,
        imm,
        (uint32_t)fr->steps,
        hvar,
        fr->semantic_family,
        route
    );
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

// ROL_ACC：把 32 字节 acc 当作环形缓冲区整体旋转，旋转量由 imm 决定（helper 内取 &31）。
// 只改 acc，不读取 imm 以外任何运行时上下文，因此常被用作融合指令的第二半。
cprisk_vm_flow_t cprisk_vm_oph_rol_acc(cprisk_vm_interp_frame_t *fr,
                                       uint8_t op_raw,
                                       uint8_t logical,
                                       uint64_t imm,
                                       uint32_t pc,
                                       uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    (void)pc;
    (void)hvar;
    cprisk_vm_rol_acc_i(fr->acc, imm);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}
