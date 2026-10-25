// CRiskCore VM 解释器内部头：定义单次运行的栈上 frame、嵌套快照与 handler 调用约定。
// 仅供 CRiskCore 的 cprisk_vm_*.c 使用，不构成稳定 ABI；字段布局可随实现调整。
// 线程模型：一个 frame 只属于调用它的线程，禁止跨线程共享；不同 frame 可并发。
// 所有 Mach-O/bytecode 指针均为借用（不拥有、不释放），生命周期由镜像和调用方保证。
// 失败语义：通过 out->status/poison_flags 与 CPRISK_VM_FLOW_LEAVE 传播，默认 fail-closed。
#ifndef CPRISK_VM_INTERPRETER_INTERNAL_H
#define CPRISK_VM_INTERPRETER_INTERNAL_H

#include "cprisk_vm_interpreter.h"
#include "cprisk_vm_interpreter_limits.h"
#include "cprisk_vm_sync_barrier.h"
#include "cprisk_emulator_detect.h"

#include <stddef.h>
#include <stdint.h>

// SplitMix64 单步：确定、非密码学 PRNG；state 由调用方拥有并被原地推进。
/** Shared SplitMix64 PRNG step (used by VPC affine mask derivation and other cross-TU utilities). */
static inline uint64_t cprisk_splitmix64_next_i(uint64_t *state) {
    *state += UINT64_C(0x9E3779B97F4A7C15);
    uint64_t z = *state;
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

// 前向声明，避免内部头依赖 Mach-O 细节。
struct mach_header_64;
struct cprisk_vm_interp_frame;
// 解释器 frame 的不透明别名；handler 与内部函数统一用它。
typedef struct cprisk_vm_interp_frame cprisk_vm_interp_frame_t;

// 嵌套 VM_CALL_FUNC 的调用者快照：压栈时保存 code/PC/VPC/语义配置与 vregs，
// 被调函数 RET 时按 LIFO 恢复；字段在本帧内自有，指针仍为借用。
typedef struct {
// 调用者恢复用的加密返回 PC。
    uint64_t resume_enc_pc;
// 调用者 bytecode 基址（借用）。
    const uint8_t *snap_code;
// 调用者 bytecode 长度（字节，INSN_WIDTH 的倍数）。
    uint32_t snap_blen;
// 调用者 VPC 仿射参数 a。
    uint64_t snap_vpc_a;
// 调用者 VPC 仿射参数 b。
    uint64_t snap_vpc_b;
// 调用者语义族 id。
    uint32_t snap_semantic_family;
// 调用者混合谓词 profile id。
    uint32_t snap_mixed_predicate_profile;
// 调用者子调用深度上限。
    uint32_t snap_max_subcall_depth;
// 调用者 CALL 返回栈快照（编码 PC，最多 32 项）。
    uint64_t snap_ret_stack[CPRISK_VM_MAX_SUBCALL_DEPTH];
// 调用者返回栈指针 0..32。
    uint32_t snap_ret_sp;
// 调用者虚拟 GPR 快照。
    uint64_t snap_vregs[8];
// 调用者的 3 个 acc lane 映射（每个元素 0..2）。
    uint8_t snap_acc_lane_map[3]; /* caller's per-function lane permutation */
// 显式对齐填充，保持结构体 8 字节对齐。
    uint8_t snap_acc_lane_pad;   /* explicit alignment pad */
} cprisk_vm_vmcall_snap_t;

// 单次 VM 运行的可变状态。除特别说明外所有字段仅由当前执行线程读写；
// 指针字段均借用自 Mach-O/字节码，frame 本身位于调用方栈上、不负责释放。
struct cprisk_vm_interp_frame {
// 当前镜像的 Mach-O 头（借用）。
    const struct mach_header_64 *hdr;
// bytecode 段起始地址（借用）。
    const uint8_t *b_sec;
// bytecode 段总长度（字节）。
    unsigned long bsz;
// bytecode 段头，指向 b_sec 内部（借用）。
    const cprisk_vmp_bytecode_header_t *bh;
// dispatch 段起始地址（借用）。
    const uint8_t *dispatch_sec;
// dispatch 段头，指向 dispatch_sec 内部（借用）。
    const cprisk_vmp_dispatch_header_t *dispatch_hdr;
// 缓存的 dispatch 头 flags，避免热路径重复解引用。
    uint32_t dispatch_hdr_flags;
// dispatch 类表一次性密钥流种子；由运行材料+头派生。
    uint64_t dispatch_decode_seed;
// 类表缓存覆盖的起始 opcode（按 32 对齐）。
    uint32_t dispatch_cache_base;
// 缓存中有效字节数 0..32。
    uint32_t dispatch_cache_count;
// 缓存的逻辑 opcode 字节，索引 = op - dispatch_cache_base。
    uint8_t dispatch_cache[CPRISK_VM_DISPATCH_CACHE_BYTES];
// 执行 lane 0..2；选择 loop/prelude/finish 变体与内联加固分支。
    uint32_t path_lane;
// 目标函数 ID（条目查找键）。
    uint64_t func_id;
// 调用方提供的运行结果缓冲区（借用，必须非 NULL）。
    cprisk_vm_run_result_t *out;

// bytecode 头总字节数（含 M2/V3 扩展）。
    size_t bc_hdr_total;
// 条目步长（字节）：32，PER_ENTRY_VPC 时 48。
    size_t entry_stride;

// VPC 仿射参数 a；必须非 0。
    uint64_t vpc_a;
// VPC 仿射参数 b。
    uint64_t vpc_b;
// 当前正在解释的 bytecode 起点（嵌套调用时切换）。
    const uint8_t *code;
// 当前 bytecode 长度（字节，必须为 INSN_WIDTH 的倍数）。
    uint32_t blen;
// 加密后的虚拟 PC；每步解码为字节偏移。
    uint64_t encoded_pc;
// 条目 profile 解出的语义族 id；影响反符号执行强度。
    uint32_t semantic_family;
// 混合谓词 profile id；参与分发/不透明链。
    uint32_t mixed_predicate_profile;
// CALL 子调用深度上限 1..32（已收敛）。
    uint32_t max_subcall_depth;
// CALL 返回栈：保存编码 PC，最多 32 项。
    uint64_t return_stack[CPRISK_VM_MAX_SUBCALL_DEPTH];
// 返回栈指针 0..32。
    uint32_t return_sp;
// 嵌套 VM_CALL_FUNC 快照栈，深度 0..8。
    cprisk_vm_vmcall_snap_t vm_snap[CPRISK_VM_MAX_VM_NEST_DEPTH];
// 快照栈指针 0..8。
    uint32_t vm_snap_sp;
// 8 个虚拟 64 位 GPR。
    uint64_t vregs[8];

// 1 = 立即数已 XOR 混淆，需逐指令解混。
    uint32_t enc_imm;
// 1 = wire opcode 已 XOR 混淆。
    uint32_t enc_op;
// V3 立即数种子（8 字节 LE，借用自 bytecode 头扩展）。
    uint64_t imm_seed_root;
// V3 opcode 种子（8 字节 LE）。
    uint64_t opcode_seed_root;
// RAW_REGION 立即数绑定根；无种子时退化为固定串。
    uint64_t raw_bind_root;
// 1 = 启用不透明谓词链。
    uint32_t m3_opaque;
// 1 = 注入死 handler/诱饵路径。
    uint32_t m3_dead;
// 1 = 高负载反符号执行路径（语义族≥10、深度≥8 或显式标志）。
    int vm_anti_symbolic_heavy;
// 本次运行的 32 位会话熵；混合 CFF link token。
    uint32_t session_mix;
// 3 个 acc 物理 lane 的排列：acc_lane_map[family] = physical lane。
    /** Per-function accumulator lane permutation: acc_lane_map[i] maps the i-th
     *  opcode family (0=add, 1=sub, 2=mul) to the physical lane index passed to
     *  cprisk_vm_lane_apply_poly_i.  Decoded from entry->reserved bits [2:0] at
     *  frame init; defaults to identity {0,1,2} for legacy (no-magic) entries. */
    uint8_t acc_lane_map[3];
// 对齐填充，保持 8 字节对齐。
    uint8_t acc_lane_pad; /* alignment */
// 自检失败时产生的解码故障掩码；非 0 时污染 opcode/imm。
    uint64_t decode_fault_mask;
// 不透明运行探针：进程 id。
    int32_t opaque_pid;
// 不透明运行探针：时钟调用返回码。
    int32_t opaque_clock_rc;
// 不透明运行探针：端口/服务探测返回码。
    int32_t opaque_port_rc;
// 不透明运行探针：运行期 nonce。
    uint32_t opaque_rt_nonce;
// 不透明谓词链累积值。
    uint32_t opaque_chain;
// 运行期折叠值。
    uint32_t opaque_runtime_fold;
// 会话混合值。
    uint32_t opaque_session_mix;
// 线程混合值。
    uint32_t opaque_thread_mix;
// 时钟纳秒值（截断为 32 位）。
    uint32_t opaque_clock_ns;
// 端口/服务名哈希。
    uint32_t opaque_port_name;

// 1 = 持有 bytecode SHA256 基线，按步数周期复检。
    /** When non-zero, \c bc_seg_hash_expect is valid; interpreter re-hashes bytecode periodically. */
    uint32_t bc_seg_hash_enabled;
// 上次成功复检的步数，用于节流。
    uint32_t bc_last_hash_step;
// 进入时计算的整段 bytecode SHA256 基线。
    uint8_t bc_seg_hash_expect[32];

// 1 = XOR_MIX 叶子已内联执行过域 7 白盒+不透明副作用，post hook 不再重复。
    /**
     * When non-zero, \c cprisk_vm_dispatch_leaf_wb_wrapped_i already ran domain-7 WB + opaque apply for this insn
     * (currently \c CPRISK_VM_OP_XOR_MIX only); \c cprisk_vm_oph_post_handler_i skips duplicate WB side effects
     * (still runs bytecode hash checks).
     */
    uint32_t vm_wb_inline_done;

// 主累加器 32 字节（VM 语义的主要目标）。
    uint8_t acc[CPRISK_VM_ACC_PRIMARY_BYTES];
// 辅助累加器 32 字节；与 acc 合并后构成 64 字节状态。
    uint8_t acc_aux[CPRISK_VM_ACC_AUX_BYTES];
// 跟踪副作用临时区 64 字节。
    uint8_t trace_scratch[64];
// 跟踪影子状态 4×64 位。
    uint64_t trace_shadow[4];

// 已执行指令数；同时用于周期副作用与上限判断。
    uint64_t steps;
// 每次运行的步数上限；来自 MAX_STEPS 减去 0..12287 的抖动，始终 ≤65536。
    /** Per-run step ceiling (function/session-derived); <= \c CPRISK_VM_MAX_STEPS. */
    uint64_t step_limit_cap;

// 以下为集成加固模块共享上下文（Tasks 1-5）与同步屏障。
    /* ── Integrated hardening modules (Tasks 1-5) ── */

    /** Task 1: VM state integrity (vm_integrity.h) */
// 活动标记 VM_INT_MAGIC_ACTIVE；0 表示未初始化。
    uint32_t vm_integrity_magic;        /* VM_INT_MAGIC_ACTIVE marker */
// 完整性版本种子。
    uint32_t vm_integrity_version;      /* version seed */
// 单调递增的执行计数。
    uint64_t vm_integrity_exec_count;   /* monotonic execution count */
// FNV-1a 变体完整性链。
    uint64_t vm_integrity_checksum;     /* FNV-1a variant chain */
// 完整性标签 8 字节。
    uint8_t  vm_integrity_tag[8];       /* integrity label */
// 1 = 检测到篡改/损坏。
    uint8_t  vm_integrity_corrupted;    /* tamper detected flag */

// Task 3：按基本块运行期解密，使用后立即回写密文。
    /** Task 3: Runtime on-demand decryption context */
// 当前已解密的基本块 ID。
    uint32_t decrypt_current_block;     /* currently decrypted basic block ID */
// 基本块总数。
    uint32_t decrypt_block_count;       /* total basic blocks */
// 由 func_id 派生的每块 XOR 密钥。
    uint64_t decrypt_block_key;         /* per-block XOR key derived from func_id */
// 位图：置位表示该块当前已解密（64 块）。
    uint8_t  decrypt_block_map[64];     /* bit map: block is currently decrypted */
// 解密-执行-回写循环的 256 字节暂存。
    uint8_t  decrypt_code_copy[256];    /* scratch for decrypt-encrypt cycle */

// Task 4：路径爆炸上下文，制造等价分支/诱饵。
    /** Task 4: Path explosion context (vm_path_explosion.h) */
// 路径爆炸所属 function id。
    uint64_t pe_func_id;               /* function id for path explosion */
// bytecode 的压缩哈希。
    uint32_t pe_bytecode_hash;          /* condensed hash of bytecode */
// 已通过的分叉检查点计数。
    uint32_t pe_fork_counter;           /* number of fork checkpoints passed */
// 已执行的诱饵序列计数。
    uint32_t pe_decoy_counter;          /* number of decoy sequences executed */
// MBA（mixed boolean-arithmetic）状态累加器。
    uint32_t pe_mba_accumulator;        /* MBA state accumulator */
// MBA XOR 掩码。
    uint32_t pe_mba_xor_mask;           /* MBA xor mask */
// 每路径标记 32 字节。
    uint8_t  pe_path_marker[32];        /* per-path marker bytes */

// 内联反调试上下文：48 字节不透明存储，按 vm_antidebug_ctx_t* 访问。
    /** Anti-debug inline context (vm_antidebug_inline.h)
     *  Opaque storage sized to hold vm_antidebug_ctx_t; accessed via (vm_antidebug_ctx_t*) cast. */
// 不透明存储，大小 >= sizeof(vm_antidebug_ctx_t)。
    uint8_t  adb_ctx_storage[48];  /* >= sizeof(vm_antidebug_ctx_t), aligned via uint64_t below */
// 停滞/超时计数。
    uint32_t adb_stall_count;
// 对齐填充（保持 8 字节对齐）。
    uint64_t adb_ctx_align_;       /* alignment padding */

// Task 5：VM×CFF 深度融合，编码 PC 跟踪与完整性校验。
    /** Task 5: VM×CFF deep fusion (vm_cff_fusion.h) */
// Feistel 轮密钥 8×32 位。
    uint32_t cff_rk[8];                /* Feistel round keys */
// CFF 编码状态。
    uint32_t cff_encoded_state;        /* CFF encoded state */
// CFF 初始化标记。
    uint32_t cff_magic;                /* CFF init marker */
// 编码 PC 跟踪缓冲 16 项。
    uint32_t cff_trace_buffer[16];     /* encoded PC trace */
// 跟踪缓冲写位置。
    uint32_t cff_trace_pos;            /* trace position */
// 派生 CFF 密钥用的 bytecode 哈希。
    uint8_t  cff_bytecode_hash[32];    /* hash for key derivation */
// 1 = 编码生效。
    uint8_t  cff_state_encoded;        /* 1 if encoding active */
// 1 = 检测到完整性违规。
    uint8_t  cff_corruption_detected;  /* integrity violation flag */
// CFF 管理的虚拟 PC。
    uint64_t cff_vpc;                  /* CFF-managed virtual PC */

// 每 64 步读取一次看门狗计数的同步屏障上下文。
    /** VM sync barrier context: external data dependency every 64 steps */
    cprisk_vm_sync_barrier_ctx_t sync_barrier_ctx;

// C 层模拟器检测标志 CPRISK_EMU_FLAG_*；看门狗卡死时或入 WATCHDOG_STUCK。
    /** C-layer emulator detection flags (CPRISK_EMU_FLAG_* bitmask).
     *  Set during cprisk_vm_hardening_init(); CPRISK_EMU_FLAG_WATCHDOG_STUCK
     *  is OR'd in at runtime when the sync barrier detects a frozen watchdog. */
    uint32_t emulator_flags;
};

// handler 返回流：CONTINUE 让主循环继续取下一条；LEAVE 跳到 vm_leave_* 收尾。
/**
 * Opcode handler return: CONTINUE keeps the main VM loop; LEAVE exits to vm_leave_* (finish_run).
 * Used by indirect dispatch across the split \c cprisk_vm_oph_*.c translation units.
 */
typedef enum {
// 继续解释（通常已推进 encoded_pc 与 steps）。
    CPRISK_VM_FLOW_CONTINUE = 0,
// 离开主循环并执行 lane 对应的 finish_run。
    CPRISK_VM_FLOW_LEAVE = 1,
} cprisk_vm_flow_t;

// handler 统一签名：
// - fr: 当前运行 frame（借用，可读写）；op_raw: wire opcode 原字节；
// - logical: 映射后的逻辑 opcode 0..23；imm: 已解混的 64 位立即数；
// - pc: 当前字节偏移（INSN_WIDTH 的倍数）；hvar: 多态 handler 变体选择器。
// 返回 CPRISK_VM_FLOW_*；handler 不得自行释放/替换 fr。
typedef cprisk_vm_flow_t (*cprisk_vm_oph_fn)(cprisk_vm_interp_frame_t *fr,
                                             uint8_t op_raw,
                                             uint8_t logical,
                                             uint64_t imm,
                                             uint32_t pc,
                                             uint32_t hvar);

// 稠密 handler 表长度 = 24（逻辑 opcode 0..23）；POISON 0xFF 单独处理。
/** Dense logical opcode indices 0..23 (see cprisk_vm_interpreter.h). POISON (0xFF) is not indexed here. */
#define CPRISK_VM_OPH_TABLE_LEN 24u

// 分发入口：先按逻辑 opcode 选择语义族，再只物化当前 handler 指针。
/**
 * Opcode handlers are still split across \c cprisk_vm_oph_*.c, but the runtime no longer exposes a
 * plaintext global handler-pointer table. The dispatcher in \c cprisk_vm_oph_table.c resolves a
 * family first, then materializes only the selected handler pointer for the current access.
 */
cprisk_vm_flow_t cprisk_vm_dispatch_oph_materialized_i(cprisk_vm_interp_frame_t *fr,
                                                       uint8_t op_raw,
                                                       uint8_t logical,
                                                       uint64_t imm,
                                                       uint32_t pc,
                                                       uint32_t hvar);

// 叶子分发包装：XOR_MIX 先做会话绑定白盒 PRF/掩码，其余交给 post hook。
/**
 * Opcode dispatch wrapper: for \c CPRISK_VM_OP_XOR_MIX, session-bound white-box PRF on pre-handler state,
 * self-inverse acc XOR mask derived from PRF output, then materialized handler; opaque/session updates from PRF.
 * Other opcodes delegate to the materialized handler and \c cprisk_vm_oph_post_handler_i (periodic WB).
 */
cprisk_vm_flow_t cprisk_vm_dispatch_leaf_wb_wrapped_i(cprisk_vm_interp_frame_t *fr,
                                                      uint8_t op_raw,
                                                      uint8_t logical,
                                                      uint64_t imm,
                                                      uint32_t pc,
                                                      uint32_t hvar,
                                                      cprisk_vm_oph_fn materialized);

// 后处理钩子：白盒会话副作用 + 可选 bytecode 分段 SHA256 复检；inner 为 handler 返回值。
/**
 * Post-handler hook: session-bound white-box side effect + optional bytecode segment SHA256 checks.
 * \p inner is the flow returned by the materialized opcode handler.
 */
cprisk_vm_flow_t cprisk_vm_oph_post_handler_i(cprisk_vm_interp_frame_t *fr,
                                              uint8_t logical,
                                              uint64_t imm,
                                              uint32_t pc,
                                              uint32_t hvar,
                                              cprisk_vm_flow_t inner);

// 毒化哨兵 handler：置 UNKNOWN_OPCODE 并混合 acc，然后继续。
cprisk_vm_flow_t cprisk_vm_oph_poison(cprisk_vm_interp_frame_t *fr,
                                      uint8_t op_raw,
                                      uint8_t logical,
                                      uint64_t imm,
                                      uint32_t pc,
                                      uint32_t hvar);
// 未知逻辑 opcode handler：与 poison 类似，但用于 >= 表长的值。
cprisk_vm_flow_t cprisk_vm_oph_unknown(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar);

// NOP：仅推进编码 PC/步数。
cprisk_vm_flow_t cprisk_vm_oph_nop(cprisk_vm_interp_frame_t *fr,
                                   uint8_t op_raw,
                                   uint8_t logical,
                                   uint64_t imm,
                                   uint32_t pc,
                                   uint32_t hvar);
// HALT：推进后置 OK 并返回 LEAVE。
cprisk_vm_flow_t cprisk_vm_oph_halt(cprisk_vm_interp_frame_t *fr,
                                    uint8_t op_raw,
                                    uint8_t logical,
                                    uint64_t imm,
                                    uint32_t pc,
                                    uint32_t hvar);
// RET：弹 CALL 返回栈，其次弹 VMCALL 快照，最后结束运行。
cprisk_vm_flow_t cprisk_vm_oph_ret(cprisk_vm_interp_frame_t *fr,
                                   uint8_t op_raw,
                                   uint8_t logical,
                                   uint64_t imm,
                                   uint32_t pc,
                                   uint32_t hvar);
// RAW_REGION：执行本机代码区域；立即数可经 raw_bind_root 解混。
cprisk_vm_flow_t cprisk_vm_oph_raw_region(cprisk_vm_interp_frame_t *fr,
                                          uint8_t op_raw,
                                          uint8_t logical,
                                          uint64_t imm,
                                          uint32_t pc,
                                          uint32_t hvar);
// ADD：按字节 lane 加立即数到 acc。
cprisk_vm_flow_t cprisk_vm_oph_add(cprisk_vm_interp_frame_t *fr,
                                   uint8_t op_raw,
                                   uint8_t logical,
                                   uint64_t imm,
                                   uint32_t pc,
                                   uint32_t hvar);
// ADD_ROL_ACC：低 32 位 ADD + 高 32 位 ROL 的单步融合。
cprisk_vm_flow_t cprisk_vm_oph_add_rol_acc(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw,
                                            uint8_t logical,
                                            uint64_t imm,
                                            uint32_t pc,
                                            uint32_t hvar);
// SUB_LANE：按字节 lane 环绕减法。
cprisk_vm_flow_t cprisk_vm_oph_sub_lane(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar);
// MUL_LANE：按字节 lane 乘模 256。
cprisk_vm_flow_t cprisk_vm_oph_mul_lane(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar);
// BRANCH_REL：无条件相对跳转（有符号字节增量）。
cprisk_vm_flow_t cprisk_vm_oph_branch_rel(cprisk_vm_interp_frame_t *fr,
                                          uint8_t op_raw,
                                          uint8_t logical,
                                          uint64_t imm,
                                          uint32_t pc,
                                          uint32_t hvar);
// BRANCH_IND：由 vreg/acc 混合出的间接目标（支持 0xA1/0xA2 模式）。
cprisk_vm_flow_t cprisk_vm_oph_branch_ind(cprisk_vm_interp_frame_t *fr,
                                          uint8_t op_raw,
                                          uint8_t logical,
                                          uint64_t imm,
                                          uint32_t pc,
                                          uint32_t hvar);
// BRANCH_COND：条件跳转，谓词来自累加器/指令字。
cprisk_vm_flow_t cprisk_vm_oph_branch_cond(cprisk_vm_interp_frame_t *fr,
                                           uint8_t op_raw,
                                           uint8_t logical,
                                           uint64_t imm,
                                           uint32_t pc,
                                           uint32_t hvar);
// CALL：压返回 PC 并跳转，受子调用深度限制。
cprisk_vm_flow_t cprisk_vm_oph_call(cprisk_vm_interp_frame_t *fr,
                                    uint8_t op_raw,
                                    uint8_t logical,
                                    uint64_t imm,
                                    uint32_t pc,
                                    uint32_t hvar);
// XOR_MIX：EOR 语义 + 会话白盒副作用。
cprisk_vm_flow_t cprisk_vm_oph_xor_mix(cprisk_vm_interp_frame_t *fr,
                                       uint8_t op_raw,
                                       uint8_t logical,
                                       uint64_t imm,
                                       uint32_t pc,
                                       uint32_t hvar);
// OR_LANE：按字节 lane 或。
cprisk_vm_flow_t cprisk_vm_oph_or_lane(cprisk_vm_interp_frame_t *fr,
                                       uint8_t op_raw,
                                       uint8_t logical,
                                       uint64_t imm,
                                       uint32_t pc,
                                       uint32_t hvar);
// AND_LANE：按字节 lane 与。
cprisk_vm_flow_t cprisk_vm_oph_and_lane(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar);
// ROL_ACC：32 字节状态循环左移 (imm&31)。
cprisk_vm_flow_t cprisk_vm_oph_rol_acc(cprisk_vm_interp_frame_t *fr,
                                       uint8_t op_raw,
                                       uint8_t logical,
                                       uint64_t imm,
                                       uint32_t pc,
                                       uint32_t hvar);
// VM_CALL_FUNC：保存调用者快照并运行被调 function_id。
cprisk_vm_flow_t cprisk_vm_oph_vm_call_func(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw,
                                            uint8_t logical,
                                            uint64_t imm,
                                            uint32_t pc,
                                            uint32_t hvar);
// VREG_MOV：虚拟 GPR 与立即数/acc 之间移动。
cprisk_vm_flow_t cprisk_vm_oph_vreg_mov(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar);
// VREG_ALU：虚拟 GPR 之间的 64 位 ADD/XOR/AND。
cprisk_vm_flow_t cprisk_vm_oph_vreg_alu(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar);
// VREG_MEM：acc 与 vreg 之间 8 字节 load/store。
cprisk_vm_flow_t cprisk_vm_oph_vreg_mem(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar);
// MOV_WIDE：MOVZ/MOVN/MOVK 语义代理。
cprisk_vm_flow_t cprisk_vm_oph_mov_wide   (cprisk_vm_interp_frame_t *fr, uint8_t op_raw, uint8_t logical, uint64_t imm, uint32_t pc, uint32_t hvar);
// ADR_ADD：ADRP+ADD 语义代理。
cprisk_vm_flow_t cprisk_vm_oph_adr_add   (cprisk_vm_interp_frame_t *fr, uint8_t op_raw, uint8_t logical, uint64_t imm, uint32_t pc, uint32_t hvar);
// COND_SELECT：CSEL/CSET 语义代理。
cprisk_vm_flow_t cprisk_vm_oph_cond_select(cprisk_vm_interp_frame_t *fr, uint8_t op_raw, uint8_t logical, uint64_t imm, uint32_t pc, uint32_t hvar);
// LOAD_STORE：LDR/STR 语义代理。
cprisk_vm_flow_t cprisk_vm_oph_load_store (cprisk_vm_interp_frame_t *fr, uint8_t op_raw, uint8_t logical, uint64_t imm, uint32_t pc, uint32_t hvar);

#endif /* CPRISK_VM_INTERPRETER_INTERNAL_H */
