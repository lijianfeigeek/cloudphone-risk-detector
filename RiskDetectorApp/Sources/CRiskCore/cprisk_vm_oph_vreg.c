// cprisk_vm_oph_vreg.c — 寄存器族 opcode：VREG_MOV / VREG_ALU / VREG_MEM。
// imm 不是数值而是打包的指令描述符：dst/src/op/base 等字段按固定位域解释（见各 helper）。
// vregs 是 8 个 64 位标量寄存器，与 32 字节 acc 相互独立；这些指令负责二者之间的搬运与 ALU 运算。
// 统一契约：成功后 steps+1 并推进 encoded_pc；helper 不做动态分配，也不访问字节码以外的内存。
// 线程模型：只操作 fr->vregs / fr->acc，无全局状态；同一帧不可并发。
#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_ops.h"

// VREG_MOV：按 mode 在 rr 搬移、imm56 立即数装载、acc 8 字节窗口装载三者间选择，写入 vregs[dst]。
cprisk_vm_flow_t cprisk_vm_oph_vreg_mov(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    (void)pc;
    (void)hvar;
    cprisk_vm_vreg_mov_i(fr->vregs, fr->acc, imm);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

// VREG_ALU：对 vregs[a] 与 vregs[b] 执行 ADD/XOR/AND/OR（op 0..3，其余归为 OR），结果写 vregs[dst]。
cprisk_vm_flow_t cprisk_vm_oph_vreg_alu(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    (void)pc;
    (void)hvar;
    cprisk_vm_vreg_alu_i(fr->vregs, imm);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

// VREG_MEM：load 时把 acc 的 8 字节窗口装入 vreg，store 时反向写回；窗口索引以 32 取模回绕。
cprisk_vm_flow_t cprisk_vm_oph_vreg_mem(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    (void)pc;
    (void)hvar;
    cprisk_vm_vreg_mem_i(fr->vregs, fr->acc, imm);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}
