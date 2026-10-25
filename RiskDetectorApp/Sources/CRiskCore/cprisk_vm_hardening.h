// 文件职责：VM 解释器加固融合层——把完整性链、伪依赖、按需块校验、路径膨胀与 CFF 接入主循环。
// 调用时机：init 每帧一次（prepare_program），hook 在每步/每 8/32/128 步触发，cleanup 在结束时擦除。
// 线程模型：所有函数就地读写调用方帧，无堆分配、无锁；同一 frame 必须单线程顺序驱动。
// 失败语义：NULL 静默返回；异常只置 corrupted/毒化 acc（fail-silent），不崩溃、不返回错误。
// 平台：纯整数运算，无架构分支；模拟器同样执行。
/*
 *  cprisk_vm_hardening.h
 *  CRiskCore
 *
 *  Unified hardening integration layer for the VM interpreter.
 *
 *  This header declares initialization and per-step hook functions that
 *  wire five hardening modules into cprisk_vm_interp_loop_a/b:
 *
 *    1. VM state integrity (FNV-1a checksum chain)
 *    2. Instruction reordering & fake dependencies (runtime pseudo-dep injection)
 *    3. Runtime on-demand bytecode decryption (basic-block XOR + re-encrypt)
 *    4. Path explosion (opaque predicates, MBA decoys, anti-symbolic-execution)
 *    5. VM × CFF deep fusion (Feistel-encoded PC, state transitions)
 */

#ifndef CPRISK_VM_HARDENING_H
#define CPRISK_VM_HARDENING_H

#include "include/cprisk_vm_interpreter.h"
#include "include/cprisk_vm_interpreter_internal.h"
#include "vm_integrity.h"
#include "vm_cff_fusion.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 *  Initialization — called once per VM run from cprisk_vm_prepare_program_i
 * ═══════════════════════════════════════════════════════════════════════════ */

// 初始化帧内五个子模块与模拟器探测；fr NULL 直接返回，无返回值。
// 必须在进入主循环前调用一次；写入多数字段，不能与其他步骤并发。
// 若环境被判定为敌对，只毒化完整性链，不中断执行。
/** Initialize all five hardening sub-modules inside \p fr.
 *  Safe to call even when individual features are compiled out (no-ops). */
void cprisk_vm_hardening_init(cprisk_vm_interp_frame_t *fr);

/* ═══════════════════════════════════════════════════════════════════════════
 *  Per-step hooks — called from the main VM loop bodies
 * ═══════════════════════════════════════════════════════════════════════════ */

// 每步执行后调用：把 (logical_op 低 8 位, pc 低 56 位) 折入 FNV 链并计数。
// fr NULL 或魔数未初始化时跳过；无返回值。发现异常只置 corrupted 并污染 acc。
// 每 256 步刷新 tag；单线程 per-frame。
/** Task 1: Integrity checkpoint — verify VM state consistency.
 *  Called AFTER each instruction execution.
 *  On corruption: silently sets fr->vm_integrity_corrupted = 1 and poisons
 *  opaque_chain / acc state (no crash, no abort). */
void cprisk_vm_hardening_integrity_checkpoint(cprisk_vm_interp_frame_t *fr,
                                               uint32_t pc,
                                               uint32_t logical_op);

// 每 8 步（启用 heavy 时）注入 MBA 伪依赖：扰动 acc[pc&3] 与 opaque_chain。
// fr NULL 时无操作；无返回值、无失败路径；单线程 per-frame。
/** Task 2: Fake dependency injection — mix pseudo-dependencies into acc/opaque.
 *  Called periodically (every 8 steps) when anti_symbolic_heavy is enabled.
 *  Inserts MBA-derived false data dependencies that complicate data-flow analysis. */
void cprisk_vm_hardening_fake_dep_inject(cprisk_vm_interp_frame_t *fr,
                                          uint32_t pc,
                                          uint32_t hvar);

// 取指前调用：按 pc/9 定位 9 字节块，已校验则走快路径，否则计算 FNV 并置位。
// fr NULL 或 blen==0 无操作；越界块静默忽略。块哈希为 0 才置 corrupted，
// 无法发现保持哈希非零的定向改写；单线程。
/** Task 3: On-demand decrypt — ensure current basic block is decrypted.
 *  Called BEFORE instruction fetch.  Uses XOR-based basic-block encryption
 *  with per-block keys derived from func_id + block_id.
 *  Re-encrypts the previous block when transitioning to a new one. */
void cprisk_vm_hardening_ondemand_decrypt(cprisk_vm_interp_frame_t *fr,
                                           uint32_t pc);

// 按帧内 MBA 状态执行不透明谓词、MBA 更新与每 64 步一次的费马诱饵。
// fr NULL 无操作；无返回值；有符号平方依赖溢出行为，不能当可移植语义保证。
/** Task 4: Path explosion checkpoint — opaque predicate + decoy insertion.
 *  Called every VM_PATH_EXPLOSION_DECOY_DENSITY steps.
 *  Inserts opaque predicate checkpoints that force symbolic executors to
 *  explore exponentially many false paths. */
void cprisk_vm_hardening_path_explosion(cprisk_vm_interp_frame_t *fr,
                                         uint32_t pc);

// 分支或每 32 步调用：编码 current_pc 并推进 CFF 状态；is_branch 非 0 才使用 hint。
// fr NULL 或 cff_magic 不匹配时静默返回；结果写回 cff_vpc 与 CFF 字段。
// 纯整数运算，单线程 per-frame。
/** Task 5: CFF fusion transition — encode/decode PC through Feistel network.
 *  Called after each branch or every 32 steps on fall-through.
 *  Maintains an encoded state that binds VM control flow to the CFF layer. */
void cprisk_vm_hardening_cff_transition(cprisk_vm_interp_frame_t *fr,
                                         uint32_t current_pc,
                                         uint32_t next_pc_hint,
                                         int is_branch);

// 每 128 步调用：往返校验 Feistel 状态并检查魔数/轨迹；损坏时只置标志并毒化 acc。
// fr NULL 或未初始化时返回；无返回值。
/** Task 5: CFF fusion integrity — verify Feistel round-trip consistency.
 *  Called periodically (every 128 steps). */
void cprisk_vm_hardening_cff_verify(cprisk_vm_interp_frame_t *fr);

/* ═══════════════════════════════════════════════════════════════════════════
 *  Cleanup — called once per VM run from finish_run
 * ═══════════════════════════════════════════════════════════════════════════ */

// 主循环退出后调用：逐字段 secure_zero 所有加固状态；不释放 frame 本身。
// fr NULL 无操作；重复调用安全；不能与步骤并发。
/** Secure-clear all hardening state from \p fr. */
void cprisk_vm_hardening_cleanup(cprisk_vm_interp_frame_t *fr);

#ifdef __cplusplus
}
#endif

#endif /* CPRISK_VM_HARDENING_H */
