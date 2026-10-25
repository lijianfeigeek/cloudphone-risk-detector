// cprisk_vm_oph_table.c — opcode 分发表：把 logical opcode 解析到具体 handler 指针并调用。
// 数据结构：两级分派——先按 opcode 数值区间选家族函数，再在家族 switch 内选变体选择器（select_*）。
// 不变量：任何未覆盖的 logical 都必须落到 cprisk_vm_oph_unknown（毒化 + continue），不允许空指针调用。
// 变体选择器都是普通函数指针，不存在全局明文 handler 表；materialize 目前是恒等映射。
// 线程模型：全部为无状态 static 函数，只依赖传入的 fr；同一帧不可并发。
#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_ops.h"
#include "include/cprisk_vm_oph_variants.h"

/* Materialize (issue 61): this used to compute a key, XOR the handler
 * pointer with it, and then XOR it again — (fn ^ key) ^ key == fn, an
 * IDENTITY / no-op. It provided no protection whatsoever and must not
 * be counted as a defense layer. The key derivation and both XORs are
 * removed; the function now returns the handler unchanged and exists
 * only to keep the dispatch call sites stable. */
static cprisk_vm_oph_fn cprisk_vm_oph_materialize_i(const cprisk_vm_interp_frame_t *fr,
                                                    uint8_t logical,
                                                    uint32_t hvar,
                                                    uint32_t stage,
                                                    cprisk_vm_oph_fn fn) {
    // stage/fr/logical/hvar 都不参与运算；保留签名只为稳定调用点，不代表存在隐藏变换。
    (void)fr;
    (void)logical;
    (void)hvar;
    (void)stage;
    return fn;
}

// 统一出口：materialize 后交给 wb wrapper，使 XOR_MIX 的白盒前置副作用与字节码哈希检查
// 对所有家族走同一条路径，避免某个家族绕过完整性检查。
static cprisk_vm_flow_t cprisk_vm_dispatch_leaf_i(cprisk_vm_interp_frame_t *fr,
                                                  uint8_t op_raw,
                                                  uint8_t logical,
                                                  uint64_t imm,
                                                  uint32_t pc,
                                                  uint32_t hvar,
                                                  uint32_t stage,
                                                  cprisk_vm_oph_fn fn) {
    const cprisk_vm_oph_fn materialized =
        cprisk_vm_oph_materialize_i(fr, logical, hvar, stage, fn);
    return cprisk_vm_dispatch_leaf_wb_wrapped_i(fr, op_raw, logical, imm, pc, hvar, materialized);
}

// 家族 0（opcode 0..3）：NOP / RET / RAW_REGION / HALT，控制与终止类指令。
// 这四者没有语义参数需要家族内再分派，但仍走变体池以打散 handler 地址。
static cprisk_vm_flow_t cprisk_vm_dispatch_core_family_i(cprisk_vm_interp_frame_t *fr,
                                                         uint8_t op_raw,
                                                         uint8_t logical,
                                                         uint64_t imm,
                                                         uint32_t pc,
                                                         uint32_t hvar) {
    switch (logical) {
    case CPRISK_VM_OP_NOP:
        /* Polymorphic variant pool: rotates among 3 NOP implementations to
         * defeat Capstone L1/L2 address-keyed disassembly caching. */
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x11u, cprisk_vm_oph_select_nop);
    case CPRISK_VM_OP_RET:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x12u, cprisk_vm_oph_select_ret);
    case CPRISK_VM_OP_RAW_REGION:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x13u, cprisk_vm_oph_select_raw_region);
    case CPRISK_VM_OP_HALT:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x14u, cprisk_vm_oph_select_halt);
    default:
        return cprisk_vm_oph_unknown(fr, op_raw, logical, imm, pc, hvar);
    }
}

// lane 家族：ADD / SUB / MUL / XOR / OR / AND / ROL 与融合 ADD_ROL_ACC。
// 每个 case 的 stage 常量（0x2x）只用于区分分发点，不参与语义。
static cprisk_vm_flow_t cprisk_vm_dispatch_lane_family_i(cprisk_vm_interp_frame_t *fr,
                                                         uint8_t op_raw,
                                                         uint8_t logical,
                                                         uint64_t imm,
                                                         uint32_t pc,
                                                         uint32_t hvar) {
    switch (logical) {
    case CPRISK_VM_OP_ADD:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x21u, cprisk_vm_oph_select_add);
    case CPRISK_VM_OP_ADD_ROL_ACC:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x29u, cprisk_vm_oph_select_add_rol_acc);
    case CPRISK_VM_OP_SUB_LANE:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x22u, cprisk_vm_oph_select_sub_lane);
    case CPRISK_VM_OP_MUL_LANE:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x23u, cprisk_vm_oph_select_mul_lane);
    case CPRISK_VM_OP_XOR_MIX:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x24u, cprisk_vm_oph_select_xor_mix);
    case CPRISK_VM_OP_OR_LANE:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x25u, cprisk_vm_oph_select_or_lane);
    case CPRISK_VM_OP_AND_LANE:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x26u, cprisk_vm_oph_select_and_lane);
    case CPRISK_VM_OP_ROL_ACC:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x27u, cprisk_vm_oph_select_rol_acc);
    default:
        return cprisk_vm_oph_unknown(fr, op_raw, logical, imm, pc, hvar);
    }
}

// 分支家族：REL / IND / COND / CALL。目标合法性校验收敛在 branch 处理器内部，本层只负责选表。
static cprisk_vm_flow_t cprisk_vm_dispatch_branch_family_i(cprisk_vm_interp_frame_t *fr,
                                                           uint8_t op_raw,
                                                           uint8_t logical,
                                                           uint64_t imm,
                                                           uint32_t pc,
                                                           uint32_t hvar) {
    switch (logical) {
    case CPRISK_VM_OP_BRANCH_REL:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x31u, cprisk_vm_oph_select_branch_rel);
    case CPRISK_VM_OP_BRANCH_IND:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x35u, cprisk_vm_oph_select_branch_ind);
    case CPRISK_VM_OP_BRANCH_COND:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x32u, cprisk_vm_oph_select_branch_cond);
    case CPRISK_VM_OP_CALL:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x33u, cprisk_vm_oph_select_call);
    default:
        return cprisk_vm_oph_unknown(fr, op_raw, logical, imm, pc, hvar);
    }
}

// emitter 家族：MOV_WIDE / ADR_ADD / COND_SELECT / LOAD_STORE，均为写 acc 的搬运类指令。
static cprisk_vm_flow_t cprisk_vm_dispatch_emitter_family_i(cprisk_vm_interp_frame_t *fr,
                                                            uint8_t op_raw,
                                                            uint8_t logical,
                                                            uint64_t imm,
                                                            uint32_t pc,
                                                            uint32_t hvar) {
    switch (logical) {
    case CPRISK_VM_OP_MOV_WIDE:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x41u, cprisk_vm_oph_select_mov_wide);
    case CPRISK_VM_OP_ADR_ADD:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x42u, cprisk_vm_oph_select_adr_add);
    case CPRISK_VM_OP_COND_SELECT:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x43u, cprisk_vm_oph_select_cond_select);
    case CPRISK_VM_OP_LOAD_STORE:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x44u, cprisk_vm_oph_select_load_store);
    default:
        return cprisk_vm_oph_unknown(fr, op_raw, logical, imm, pc, hvar);
    }
}

// vreg 家族：VM_CALL_FUNC 与 VREG_MOV/ALU/MEM，操作独立的 8 个 64 位寄存器组。
static cprisk_vm_flow_t cprisk_vm_dispatch_vreg_family_i(cprisk_vm_interp_frame_t *fr,
                                                         uint8_t op_raw,
                                                         uint8_t logical,
                                                         uint64_t imm,
                                                         uint32_t pc,
                                                         uint32_t hvar) {
    switch (logical) {
    case CPRISK_VM_OP_VM_CALL_FUNC:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x51u, cprisk_vm_oph_select_vm_call_func);
    case CPRISK_VM_OP_VREG_MOV:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x52u, cprisk_vm_oph_select_vreg_mov);
    case CPRISK_VM_OP_VREG_ALU:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x53u, cprisk_vm_oph_select_vreg_alu);
    case CPRISK_VM_OP_VREG_MEM:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x54u, cprisk_vm_oph_select_vreg_mem);
    default:
        return cprisk_vm_oph_unknown(fr, op_raw, logical, imm, pc, hvar);
    }
}

// 分派总入口：按 opcode 编号区间选择家族。区间划分依赖 cprisk_vm_interpreter.h 的枚举顺序，
// 调整枚举值必须同步修改下面所有比较，否则会把指令静默路由到错误处理器。
cprisk_vm_flow_t cprisk_vm_dispatch_oph_materialized_i(cprisk_vm_interp_frame_t *fr,
                                                       uint8_t op_raw,
                                                       uint8_t logical,
                                                       uint64_t imm,
                                                       uint32_t pc,
                                                       uint32_t hvar) {
    // 0..3 连续，是核心家族。
    if (logical <= CPRISK_VM_OP_HALT)
        return cprisk_vm_dispatch_core_family_i(fr, op_raw, logical, imm, pc, hvar);
    // lane 家族编号不连续（4/20/21/22 与 12..15），因此显式枚举 + 区间组合。
    if (logical == CPRISK_VM_OP_ADD || logical == CPRISK_VM_OP_SUB_LANE || logical == CPRISK_VM_OP_MUL_LANE
        || logical == CPRISK_VM_OP_ADD_ROL_ACC
        || (logical >= CPRISK_VM_OP_XOR_MIX && logical <= CPRISK_VM_OP_ROL_ACC)) {
        return cprisk_vm_dispatch_lane_family_i(fr, op_raw, logical, imm, pc, hvar);
    }
    // 5..7 连续，间接分支 23 单独列出。
    if ((logical >= CPRISK_VM_OP_BRANCH_REL && logical <= CPRISK_VM_OP_CALL) || logical == CPRISK_VM_OP_BRANCH_IND)
        return cprisk_vm_dispatch_branch_family_i(fr, op_raw, logical, imm, pc, hvar);
    // 8..11 连续。
    if (logical >= CPRISK_VM_OP_MOV_WIDE && logical <= CPRISK_VM_OP_LOAD_STORE)
        return cprisk_vm_dispatch_emitter_family_i(fr, op_raw, logical, imm, pc, hvar);
    // 16 独立，17..19 连续。
    if (logical == CPRISK_VM_OP_VM_CALL_FUNC || (logical >= CPRISK_VM_OP_VREG_MOV && logical <= CPRISK_VM_OP_VREG_MEM))
        return cprisk_vm_dispatch_vreg_family_i(fr, op_raw, logical, imm, pc, hvar);
    // 未匹配值（含 0xFF POISON，正常在外层已拦截）统一毒化，避免任何越界或空指针调用。
    return cprisk_vm_oph_unknown(fr, op_raw, logical, imm, pc, hvar);
}
