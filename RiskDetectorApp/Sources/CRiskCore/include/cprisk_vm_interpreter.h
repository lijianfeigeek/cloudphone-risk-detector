// 本文件定义 armored VM（Pass13 VMProtector）的磁盘格式与运行时 ABI。
// 生产者生成 dispatch 段、bytecode 段与函数条目表；CRiskCore 解释器按 func_id
// 查找条目并解释 9 字节定宽指令（1 字节 wire opcode + 8 字节小端立即数）。
// 线程模型：每次运行独占一个栈上 frame，可并发运行不同 func_id；共享运行材料只读。
// 失败语义：非法段/PC/自检失败写入 status 与 poison 位，调用方应视为风险（fail-closed）。
#ifndef CPRISK_VM_INTERPRETER_H
#define CPRISK_VM_INTERPRETER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Build-time producer + runtime consumer ABI (Pass13 VMProtector). */
// dispatch 段魔数，小端 ASCII "CPVD"；解释前用它拒绝段错位或伪造。
#define CPRISK_VMP_MAGIC_DISPATCH 0x44565043u /* "CPVD" little-endian */
// bytecode 段魔数，小端 ASCII "CPVM"；与 dispatch 魔数成对校验。
#define CPRISK_VMP_MAGIC_BYTECODE 0x4D565043u /* "CPVM" little-endian */
// 基础 bytecode 头版本；不含 M2 扩展字段。
#define CPRISK_VMP_VERSION 1u
/** M2: optional VPC affine + extended header (global vpc_a/vpc_b after base header). */
// M2：基础头后附加 16 字节 VPC 仿射参数 vpc_a/vpc_b。
#define CPRISK_VMP_VERSION_M2 2u
/** V3: optional immediate keystream seed appended after M2 extension. */
// V3：在 M2 之后可选追加 8 字节立即数密钥流种子（配合 ENC_IMMEDIATE）。
#define CPRISK_VMP_VERSION_V3 3u
// dispatch 版本 1：256 字节明文类表（旧格式，无密钥流保护）。
/** Dispatch section \c cprisk_vmp_dispatch_header_t::version: plaintext 256-byte class table (legacy). */
#define CPRISK_VMP_DISPATCH_V1 1u
// dispatch 版本 2：256 字节 XOR 保护类表；运行期由运行材料+头派生一次性密钥流。
/**
 * Dispatch section version 2: 256-byte XOR-protected class table; runtime derives a one-shot keystream
 * from root runtime material + header (see CRiskCore interpreter). On-disk table stays non-plaintext.
 */
#define CPRISK_VMP_DISPATCH_V2 2u
// 类表固定 256 字节，索引即 wire opcode（0..255）。
#define CPRISK_VMP_CLASS_TABLE_BYTES 256u
// dispatch 头后附带的密钥流种子长度；8 字节与 SplitMix64 状态宽度一致。
#define CPRISK_VMP_DISPATCH_SEED_BYTES 8u

/** Bitmask in \c cprisk_vmp_bytecode_header_t::reserved (producer may set). */
// 无加固标志；用于兼容旧生产者。
#define CPRISK_VMP_BC_FLAG_NONE 0u
/** When set, \c reserved also carries a 2-bit handler variant seed (see M2). */
// 置位时 reserved 低位携带 2 位 handler 变体种子（多态实现选择）。
#define CPRISK_VMP_BC_FLAG_HANDLER_VARIANT_SEED 0x00000001u
/** Each bytecode entry is followed by 16 bytes: vpc_a, vpc_b (LE uint64 each). */
// 每个条目后附 16 字节 vpc_a/vpc_b（各 LE uint64）；会把条目步长从 32 改为 48。
#define CPRISK_VMP_BC_FLAG_PER_ENTRY_VPC 0x00000002u
/** M3: dispatch loop uses opaque predicate gates (non-linear CFG, semantics unchanged). */
// M3：主循环插入不透明谓词门，改变控制流形态但不改变语义。
#define CPRISK_VMP_BC_FLAG_M3_OPAQUE_CHAIN 0x00000004u
/** M3: inject unreachable / bait handler paths (seed from \c reserved bits 16–23). */
// M3：注入不可达/诱饵 handler 路径；种子取自 reserved 位 16..23。
#define CPRISK_VMP_BC_FLAG_M3_DEAD_HANDLERS 0x00000008u
/** M3: run interpreter entry self-check (rolling hash vs \c CPRISK_VM_M3_SELF_EXPECT). */
// M3：解释器入口自检（滚动哈希对比 CPRISK_VM_M3_SELF_EXPECT）。
#define CPRISK_VMP_BC_FLAG_M3_SELFCHK 0x00000010u
/** P1: immediates in bytecode (8 bytes after opcode) are XOR-mixed; decipher per-instruction before semantics. */
// P1：每指令 8 字节立即数 XOR 混淆，须先解混再解释；要求 V3 头。
#define CPRISK_VMP_BC_FLAG_ENC_IMMEDIATE 0x00000020u
/** P1: raw wire opcode bytes XOR-mixed per insn (requires v3 header + 8-byte opcode seed after optional imm seed). */
// P1：wire opcode 逐指令 XOR 混淆；要求 V3 头并读取 opcode 种子。
#define CPRISK_VMP_BC_FLAG_ENC_OPCODE 0x00000040u
/** Heavy / high-intensity VM paths: enable lightweight anti-symbolic bait (opt-in with semantic family thresholds). */
// 高负载路径：按语义族阈值选择性启用轻量反符号执行诱饵。
#define CPRISK_VMP_BC_FLAG_ANTI_SYMBOLIC_HEAVY 0x00000080u
/** M3: when combined with \c CPRISK_VMP_BC_FLAG_M3_SELFCHK, verify CPRisk-MAC-SHA256 (truncated) vs \c __swift5_mdvsk CPSH blob instead of FNV. */
// 与 SELFCHK 合用：改验 CPRisk-MAC（截断）而非 FNV。
#define CPRISK_VMP_BC_FLAG_M3_SELFCHK_MAC 0x00000100u
/** M4: interpret the 16-byte VPC metadata block as non-linear Feistel/SPN material instead of plain affine A/B. */
// M4：16 字节 VPC 元数据按非线性 Feistel/SPN 解释，而非普通仿射 A/B。
#define CPRISK_VMP_BC_FLAG_VPC_NONLINEAR 0x00000400u
// 运行期周期重算 bytecode SHA256；未置位时完全兼容旧行为，置位才启用复检。
/**
 * When set, runtime takes a SHA256 baseline of each function's bytecode blob at entry and re-checks on a step
 * cadence + selected control-flow boundaries (see CRiskCore VM interpreter). Backward-compatible when unset.
 * Periodic re-hashes are throttled against the last successful check; an early-step check and
 * return/halt/nested-call boundaries run more eagerly.
 */
// 上述标志位属于 cprisk_vmp_bytecode_header_t::reserved 的子集。
#define CPRISK_VMP_BC_FLAG_BC_SEG_RUNTIME_SHA256 0x00000800u

/** White-box PRF domain used for per-dispatch session-bound side effects (feeds opaque/session chain). */
// 白盒 PRF 域编号 7；用于每次分发的会话绑定副作用（不透明链输入）。
#define CPRISK_VM_WB_HANDLER_SIDE_DOMAIN 7u

/** Dispatch header flags (`cprisk_vmp_dispatch_header_t::flags`). */
// dispatch 头：声明存在 handler 复制/多态实现。
#define CPRISK_VMP_DH_FLAG_HANDLER_DUPLICATION 0x00000001u
// dispatch 头：RAW_REGION 等立即数需按分类做 VPC 解混。
#define CPRISK_VMP_DH_FLAG_OPAQUE_VPC_CATEGORY 0x00000002u
// dispatch 头：附带死 handler 元数据（地址/盐/偏移）。
#define CPRISK_VMP_DH_FLAG_DEAD_HANDLER_META 0x00000004u
// dispatch 头：附带 VPC 谓词元数据。
#define CPRISK_VMP_DH_FLAG_VPC_PRED_META 0x00000008u
// dispatch 头：类表用一次性密钥流 XOR 保护（配合 DISPATCH_V2）。
#define CPRISK_VMP_DH_FLAG_CLASS_TABLE_KEYSTREAM 0x00000010u

// 运行状态：0 成功；1/2 输入段非法；3 检测到追踪短路；4 达到步数上限。
enum {
// 解释正常结束（HALT 或顶层 RET）。
    CPRISK_VM_STATUS_OK = 0,
// dispatch 段缺失/头非法/版本不匹配。
    CPRISK_VM_STATUS_INVALID_DISPATCH = 1,
// bytecode 段/条目/PC 非法或嵌套深度超限。
    CPRISK_VM_STATUS_INVALID_BYTECODE = 2,
// 运行前检测到调试器，走诱饵短路并提前返回。
    CPRISK_VM_STATUS_TRACED_SHORTCIRCUIT = 3,
// 达到 step_limit_cap，防止无限循环；结果仍应视为可疑。
    CPRISK_VM_STATUS_STEP_LIMIT = 4,
};

// 毒化位图：可与 status 独立叠加，调用方应把任意非零视为不可信。
enum {
// 无毒化。
    CPRISK_VM_POISON_NONE = 0u,
// 遇到未知/非法 opcode。
    CPRISK_VM_POISON_UNKNOWN_OPCODE = 1u << 0,
// 运行时观察到调试/追踪。
    CPRISK_VM_POISON_TRACED = 1u << 1,
// Frida 特征命中。
    CPRISK_VM_POISON_FRIDA = 1u << 2,
// dispatch 段查找失败。
    CPRISK_VM_POISON_DISPATCH = 1u << 3,
// bytecode/PC 校验失败。
    CPRISK_VM_POISON_BYTECODE = 1u << 4,
// M3 入口自检不匹配（被篡改或布局异常）。
    /** M3: interpreter entry self-check mismatch (tamper / unexpected layout). */
    CPRISK_VM_POISON_SELF_INTEGRITY = 1u << 5,
};

// M3 自检期望值：编译期注入的 FNV-1a(32) 指纹；0 表示禁用自检。
// 覆盖窗口依次为入口、主循环前缀、分发解码路径，三段之和等于总字节数。
/**
 * M3 optional: rolling FNV-1a (32-bit) over three **concatenated** TEXT windows (no address
 * mixing): \c CPRISK_VM_M3_SELF_EXEC_BYTES at \c cprisk_vm_execute, then
 * \c CPRISK_VM_M3_SELF_LOOP_BYTES at \c cprisk_vm_interp_loop_a (main interpret loop prefix),
 * then \c CPRISK_VM_M3_SELF_DISPATCH_BYTES at \c cprisk_vm_dispatch_lookup (dispatch decode path).
 * Loop/dispatch windows are intentionally wider than the legacy 48/32 split so tamper in the
 * hot loop/dispatch path invalidates CPSF/CPSH together with runtime decode seeds (see self-check
 * wiring in the lane-specific VM execute paths).
 * Sum equals \c CPRISK_VM_M3_SELF_BYTES; \c cprisk-armor \c VMSelfExpectInjector hashes the same
 * layout from Mach-O symtab (post-link CPSF/CPSH).
 * When 0, the self-check is skipped even if \c CPRISK_VMP_BC_FLAG_M3_SELFCHK is set.
 * Enable a strict check by defining this at compile time to the fingerprint for your
 * toolchain; re-derive after material interpreter changes.
 *
 * Additional sources (when macro is 0): optional \c CPRISK_ARMOR_SECTION_VMP_SELF_EXPECT
 * section (magic + LE u32 expect value). See \c CPRISK_VMP_SELF_EXPECT_MAGIC.
 *
 * \c CPRISK_VM_SELFCHK_POLICY: 0 = legacy (no expect → skip check). 1 = strict: bytecode flag
 * without any expect source poisons (opt-in for pipelines that always embed expect).
 */
// 期望指纹；默认 0（跳过），由 armor 注入器在最终镜像中改写。
#if !defined(CPRISK_VM_M3_SELF_EXPECT)
#define CPRISK_VM_M3_SELF_EXPECT 0u
#endif
// 自检覆盖总字节数；176 = 入口 48 + 主循环 64 + 分发 64。
#if !defined(CPRISK_VM_M3_SELF_BYTES)
#define CPRISK_VM_M3_SELF_BYTES 176u
#endif
// 三段覆盖窗口的拆分；三者之和必须等于 CPRISK_VM_M3_SELF_BYTES。
/** Split of \c CPRISK_VM_M3_SELF_BYTES: VM entry + main loop prefix + dispatch lookup (must sum to total). */
// VM 入口前缀 48 字节。
#if !defined(CPRISK_VM_M3_SELF_EXEC_BYTES)
#define CPRISK_VM_M3_SELF_EXEC_BYTES 48u
#endif
// 主解释循环前缀 64 字节；比旧的 48/32 拆分更宽以覆盖热路径。
#if !defined(CPRISK_VM_M3_SELF_LOOP_BYTES)
#define CPRISK_VM_M3_SELF_LOOP_BYTES 64u
#endif
// 分发解码路径 64 字节。
#if !defined(CPRISK_VM_M3_SELF_DISPATCH_BYTES)
#define CPRISK_VM_M3_SELF_DISPATCH_BYTES 64u
#endif
// 1 = 计入主循环窗口；0 = 仅覆盖入口+分发（调试兼容）。
#if !defined(CPRISK_VM_M3_SELF_INCLUDE_LOOP)
#define CPRISK_VM_M3_SELF_INCLUDE_LOOP 1
#endif
// 0 = 无期望值则跳过；1 = 严格：有 SELFCHK 标志但无期望值即毒化。
#if !defined(CPRISK_VM_SELFCHK_POLICY)
#define CPRISK_VM_SELFCHK_POLICY 0
#endif
/** If 1, \c CPRISK_VMP_BC_FLAG_M3_SELFCHK without \c CPRISK_VMP_BC_FLAG_M3_SELFCHK_MAC still prefers CPRisk-MAC when a CPSH blob is present (else FNV/CPSF). */
// 1 = 同时存在 CPSH 时优先 MAC 校验；否则回退 FNV/CPSF。
#if !defined(CPRISK_VM_SELFCHK_PREFER_MAC_WHEN_AMBIGUOUS)
#define CPRISK_VM_SELFCHK_PREFER_MAC_WHEN_AMBIGUOUS 1
#endif
/** Force legacy FNV path even when CPRisk-MAC flag is set (toolchain bring-up). */
// 1 = 即使置了 MAC 标志也强制旧 FNV 路径（工具链 bring-up 用）。
#if !defined(CPRISK_VM_SELFCHK_FORCE_LEGACY_FNV)
#define CPRISK_VM_SELFCHK_FORCE_LEGACY_FNV 0
#endif
/** Little-endian magic for the optional \c __swift5_mdvsk self-expect blob (ASCII "CPSF"). */
// 可选 __swift5_mdvsk 自检块的 LE 魔数（ASCII "CPSF"）。
#define CPRISK_VMP_SELF_EXPECT_MAGIC 0x46535043u
/** Little-endian magic for CPRisk-MAC self-expect (ASCII "CPSH") — LE u32 tag (e.g. first 4 bytes of CPRisk-MAC-SHA256). */
// CPRisk-MAC 自检的 LE 魔数（ASCII "CPSH"）。
#define CPRISK_VMP_SELF_EXPECT_MAGIC_MAC 0x48535043u

/* Logical opcode IDs generated by VMProtector/VMIR.swift. */
// 逻辑 opcode 编号（wire 字节经类表映射后得到）；24 个稠密索引 + POISON 哨兵。
enum {
// 0：空操作，仅推进编码 PC 与步数。
    CPRISK_VM_OP_NOP = 0u,
// 1：从 CALL 返回；返回栈空时结束本次运行。
    CPRISK_VM_OP_RET = 1u,
// 2：原样执行一段本机代码区域；立即数描述区域/类别。
    CPRISK_VM_OP_RAW_REGION = 2u,
// 3：正常停机，status 置 OK 并离开主循环。
    CPRISK_VM_OP_HALT = 3u,
// 4：按字节 lane 把立即数加到 32 字节累加器（多等价 handler 路径）。
    /** M2: byte-lane add into acc (multiple semantic-equivalent handler paths). */
    CPRISK_VM_OP_ADD = 4u,
// 5：无条件 PC 相对跳转；立即数为有符号字节增量（AArch64 imm26×9）。
    /** PC-relative branch (unconditional `B`); immediate = signed VM bytecode byte delta (AArch64 imm26×9). */
    CPRISK_VM_OP_BRANCH_REL = 5u,
// 6：条件跳转（B.cond/CBZ/CBNZ）；立即数携带 AArch64 指令字，谓词由累加器导出。
    /** `B.cond` / `CBZ` / `CBNZ` — immediate carries AArch64 insn word; predicate uses accumulator-derived flags. */
    CPRISK_VM_OP_BRANCH_COND = 6u,
// 7：压入返回 PC 后按 BRANCH_REL 跳转；深度受 max_subcall_depth 限制。
    /** `BL` — push return PC then branch like `CPRISK_VM_OP_BRANCH_REL`. */
    CPRISK_VM_OP_CALL = 7u,
// 8：MOVZ/MOVN/MOVK 家族的语义代理。
    /** MOVZ/MOVN/MOVK-family surrogate semantic op. */
    CPRISK_VM_OP_MOV_WIDE = 8u,
// 9：ADRP+ADD 的语义代理。
    /** ADRP+ADD surrogate semantic op. */
    CPRISK_VM_OP_ADR_ADD = 9u,
// 10：CSEL/CSET 的语义代理。
    /** CSEL/CSET surrogate semantic op. */
    CPRISK_VM_OP_COND_SELECT = 10u,
// 11：LDR/STR 的语义代理。
    /** LDR/STR surrogate semantic op. */
    CPRISK_VM_OP_LOAD_STORE = 11u,
// 12：EOR 家族的语义代理；额外走会话绑定白盒 PRF 副作用。
    /** EOR-family surrogate semantic op. */
    CPRISK_VM_OP_XOR_MIX = 12u,
// 13：按字节 lane 或入累加器（多态 lane）。
    /** Byte-lane OR into acc (polymorphic lanes; wire via dispatch table). */
    CPRISK_VM_OP_OR_LANE = 13u,
// 14：按字节 lane 与入累加器。
    /** Byte-lane AND into acc. */
    CPRISK_VM_OP_AND_LANE = 14u,
// 15：把 32 字节状态循环左移 (imm & 31) 位。
    /** Rotate 32-byte acc left by (imm & 31). */
    CPRISK_VM_OP_ROL_ACC = 15u,
// 16：嵌套 VM 调用；立即数为被调 function_id，深度受 MAX_VM_NEST_DEPTH 限制。
    /** Nested VM: immediate = callee \c function_id; runs callee bytecode then resumes (depth-capped). */
    CPRISK_VM_OP_VM_CALL_FUNC = 16u,
// 17：虚拟 GPR 的 mov/立即数/acc 窗口操作。
    /** Virtual GPR mov / imm / acc window (see interpreter immediate layout). */
    CPRISK_VM_OP_VREG_MOV = 17u,
// 18：虚拟 GPR 64 位 ALU（ADD/XOR/AND），结果写 dst。
    /** Virtual GPR 64-bit ALU (ADD/XOR/AND) between two regs, result to dst. */
    CPRISK_VM_OP_VREG_ALU = 18u,
// 19：acc 与 vreg 之间搬 8 字节（最小 load/store）。
    /** Load 8 acc bytes into vreg or store vreg into acc (minimal load/store). */
    CPRISK_VM_OP_VREG_MEM = 19u,
// 20：按字节 lane 环绕减法（uint8），AArch64 SUB 代理。
    /** Byte-lane subtract (wrapping uint8) — AArch64 SUB surrogate. */
    CPRISK_VM_OP_SUB_LANE = 20u,
    /** Byte-lane multiply mod 256 — AArch64 MADD-as-MUL surrogate. */
// 21：按字节 lane 乘模 256，AArch64 MADD-as-MUL 代理。
    CPRISK_VM_OP_MUL_LANE = 21u,
// 22：超级指令；立即数低 32 位执行 ADD、高 32 位执行 ROL(imm&31)，单步完成。
    /**
     * Super-instruction: fused \c CPRISK_VM_OP_ADD (imm low 32) then \c CPRISK_VM_OP_ROL_ACC (imm high 32, rot & 31).
     * Semantics match executing ADD then ROL in sequence at one PC step.
     */
    CPRISK_VM_OP_ADD_ROL_ACC = 22u,
// 23：间接跳转；目标 = mixed(vreg[imm&7], acc[(imm>>3)&31]) mod 指令数。
    /**
     * Indirect unconditional branch: target PC byte offset = mixed(vreg[imm&7], 8 acc bytes at (imm>>3)&31) mod insn_count.
     */
    CPRISK_VM_OP_BRANCH_IND = 23u,
// 0xFF：毒化哨兵，表示类表查找失败；不进入稠密 handler 表。
    CPRISK_VM_OP_POISON = 0xFFu
};

// BRANCH_IND 的保留立即数约定：高字节区分半恒等/半语义两种模式。
/**
 * Reserved immediate contract for \c CPRISK_VM_OP_BRANCH_IND:
 * - high byte \c 0xA1 means semi-identity mode and runtime must fall through by one instruction;
 * - remaining low 56 bits are payload/entropy and must not alter the fallthrough behavior.
 * - high byte \c 0xA2 means semi-semantic mode: runtime evaluates the full mix/vreg/\c acc path
 *   to obtain \c q, then selects a controlled forward target within a producer-supplied nop sled.
 *   Bits 8..15 encode \c forward_span (0..255): the number of nop instructions following the
 *   \c branchInd. Runtime jumps \c (1 + q % (forward_span + 1)) * INSN_WIDTH forward.
 *   All reachable targets are safe (nop or halt).
 */
// 高字节 0xA1：半恒等模式，运行期只前进一条指令。
#define CPRISK_VM_BRANCH_IND_SEMI_IDENTITY_TAG 0xA100000000000000ULL
// 高字节掩码，用于识别 0xA1/0xA2 模式。
#define CPRISK_VM_BRANCH_IND_SEMI_IDENTITY_MASK 0xFF00000000000000ULL
// 低 56 位仅作熵/载荷，不得影响 fallthrough 行为。
#define CPRISK_VM_BRANCH_IND_SEMI_IDENTITY_PAYLOAD_MASK 0x00FFFFFFFFFFFFFFULL

// 高字节 0xA2：半语义模式，在生产者提供的 nop 雪橇内选择前向目标。
#define CPRISK_VM_BRANCH_IND_SEMI_SEMANTIC_TAG 0xA200000000000000ULL
// 同上，取高字节识别模式。
#define CPRISK_VM_BRANCH_IND_SEMI_SEMANTIC_MASK 0xFF00000000000000ULL

// 主累加器 32 字节；VM 语义主要作用于这一块。
#define CPRISK_VM_ACC_PRIMARY_BYTES 32u
// 辅助累加器 32 字节；与主累加器合并成 64 字节视图。
#define CPRISK_VM_ACC_AUX_BYTES 32u
// 合并后总宽度 64 字节；结果折叠/恢复路径都以此为准。
#define CPRISK_VM_ACC_COMBINED_BYTES (CPRISK_VM_ACC_PRIMARY_BYTES + CPRISK_VM_ACC_AUX_BYTES)

// 条目 reserved 的扩展 profile 编码；仅在 bits24..31 == 0xA5 时生效。
/** `cprisk_vmp_bytecode_entry_t::reserved` extended profile marker in bits 24...31. */
// profile 标记 0xA5；缺失时按 legacy 条目处理（恒等 lane、默认参数）。
#define CPRISK_VMP_ENTRY_PROFILE_MAGIC 0xA5u
// bits16..19 存 max_subcall_depth-1（4 位，对应 1..16）。
/** Bits 16...19 encode `(max_subcall_depth - 1)` when profile marker is present. */
#define CPRISK_VMP_ENTRY_SUBCALL_DEPTH_SHIFT 16u
// bits12..15 存 mixed predicate profile id。
/** Bits 12...15 encode mixed predicate profile id when profile marker is present. */
#define CPRISK_VMP_ENTRY_MIXED_PRED_SHIFT 12u
// bits8..11 存 semantic family id；决定反符号执行强度等。
/** Bits 8...11 encode semantic family id when profile marker is present. */
#define CPRISK_VMP_ENTRY_SEMANTIC_FAMILY_SHIFT 8u

// dispatch 段头：位于 dispatch 段起始，描述类表版本/大小与加固开关。
typedef struct cprisk_vmp_dispatch_header {
// 魔数 "CPVD"，用于段合法性校验。
    uint32_t magic;
// 版本 1=明文类表，2=XOR 密钥流类表。
    uint32_t version;
// 类表字节数，当前必须为 256。
    uint32_t class_table_size;
// CPRISK_VMP_DH_FLAG_* 位掩码。
    uint32_t flags;
} cprisk_vmp_dispatch_header_t;

// bytecode 段头：位于段起始，描述版本、条目数与可选的 M2/V3 扩展。
typedef struct cprisk_vmp_bytecode_header {
// 魔数 "CPVM"。
    uint32_t magic;
// 1/2/3，分别对应基础、M2、V3 布局。
    uint32_t version;
// 条目数；每条约 32 字节（PER_ENTRY_VPC 时 48）。
    uint32_t entry_count;
// 位掩码 CPRISK_VMP_BC_FLAG_*；M2 起低位可作 handler 变体种子。
    /** Legacy: 0. M2: \c CPRISK_VMP_BC_FLAG_* ; low bits may select handler variant seed. */
    uint32_t reserved;
} cprisk_vmp_bytecode_header_t;

// 函数条目：按 function_id 线性查找；offset/length 指向 bytecode 段内。
typedef struct cprisk_vmp_bytecode_entry {
// 目标函数标识，与 cprisk_vm_entry(func_id) 对应。
    uint64_t function_id;
// 原函数在 Mach-O 中的 VMA（仅生产期/诊断用）。
    uint64_t original_entry_vma;
// 加固层级/档位，由生产者选择。
    uint32_t tier;
// 字节码相对段起始的偏移；必须 >= 条目表末尾。
    uint32_t bytecode_offset;
// 字节码长度（字节），必须是 INSN_WIDTH(9) 的整数倍。
    uint32_t bytecode_length;
// profile 编码；bits24..31==0xA5 时启用 lane/深度/语义族扩展。
    uint32_t reserved;
} cprisk_vmp_bytecode_entry_t;

// VM 运行结果：status/poison 描述可信度，acc/aux/vregs 是停机时可见状态。
typedef struct cprisk_vm_run_result {
// CPRISK_VM_STATUS_*，0 表示正常结束。
    uint32_t status;
// CPRISK_VM_POISON_* 位图；任意非零表示结果不可信。
    uint32_t poison_flags;
// 白盒域 5 求值返回码；0 成功，UINT32_MAX 表示未执行。
    uint32_t whitebox_domain_rc;
// 主累加器折叠后的 32 字节视图。
    /** Folded / externally visible accumulator view derived from the 64-byte primary+aux state. */
    uint8_t acc[CPRISK_VM_ACC_PRIMARY_BYTES];
// 已执行指令数（含 HALT/RET 自身）。
    uint64_t steps;
// 最后一条 wire opcode；初始哨兵 0xFFFFFFFF。
    uint32_t last_opcode;
// 最后映射出的逻辑 opcode 类；初始哨兵 0xFFFFFFFF。
    uint32_t last_dispatch_class;
// 8 个虚拟 64 位 GPR 的停机快照。
    /** Eight virtual 64-bit GPRs (interpreter-visible state at VM halt). */
    uint64_t vregs[8];
// 辅助 32 字节 bank；与 acc 合成 64 字节合并状态。
    /** Auxiliary 32-byte bank; together with \c acc forms the 64-byte combined VM state. */
    uint8_t acc_aux[CPRISK_VM_ACC_AUX_BYTES];
} cprisk_vm_run_result_t;

// 仅 GCC/Clang 导出符号；其他编译器退化为默认可见性。
#if defined(__GNUC__)
#define CPRISK_VM_EXPORT __attribute__((visibility("default")))
#else
#define CPRISK_VM_EXPORT
#endif

// 按 func_id 执行 VM 字节码，并把主/辅累加器折叠成 64 位返回值（保留 ABI 兼容）。
// - 参数: func_id 为目标函数 ID；无 NULL 形式。
// - 返回: 折叠结果；段/PC/自检失败时返回毒化后的值，不抛错。
// - 线程: 每次调用使用独立栈上 frame，可并发；共享运行材料只读。
// - 平台: Apple 真机走完整检测；模拟器/非 Apple 走降级路径。
// - 失败语义: 失败记录在内部 status/poison 位，调用方无法区分 0 与失败，应按风险处理。
/// Execute VM bytecode for the given function id.
/// Returns a 64-bit value folded from VM accumulator (reserved for ABI compatibility).
CPRISK_VM_EXPORT uint64_t cprisk_vm_entry(uint64_t func_id);

// cprisk_vm_entry 的别名入口（lane1/lane2）；语义相同，供 CFF/linker -u 绑定。
/// Alternate VM entry symbols (same semantics as \c cprisk_vm_entry); kept distinct for CFF / linker \c -u wiring.
CPRISK_VM_EXPORT uint64_t cprisk_vm_entry_alt1(uint64_t func_id);
CPRISK_VM_EXPORT uint64_t cprisk_vm_entry_alt2(uint64_t func_id);

// 调试/测试入口：执行并填充详细结果；out 由调用方拥有，失败返回 -1 且 out 可能被清零。
/// Debug/testing entry: execute VM and emit detailed run result.
/// Returns 0 on success, -1 on invalid input.
int cprisk_vm_execute(uint64_t func_id, cprisk_vm_run_result_t *out);

// 仅当 dispatch/bytecode 两段都通过头部校验时返回 CPRISK_ARMOR_CAP_VMP_RUNTIME；否则 0。
/// Returns \c CPRISK_ARMOR_CAP_VMP_RUNTIME when both VMP sections parse as minimally valid.
uint32_t cprisk_vm_query_armor_capability_bits(void);

#ifdef __cplusplus
}
#endif

#endif /* CPRISK_VM_INTERPRETER_H */
