// cprisk_vm_oph_dead.h — 死处理器池声明与设计说明（仅 CRiskCore 内部使用）。
// 池中 32 个 handler 地址在会话初始化时折叠进 session_mix，但其 opcode 永不出现在真实字节码。
// 目的：扩大可达 handler 地址空间，让动态分析无法通过一次执行建立完整的 opcode→地址映射。
// 不变量：dead handler 行为必须与 unknown 一致（LEAVE + POISON），否则可被行为特征筛出。
// 集成约束：cprisk_vm_dead_touch_i 每次会话只能调用一次，且必须早于第一次分发。
// 线程模型：touch 直接异或 fr->session_mix，需在单线程初始化阶段调用。
#ifndef CPRISK_VM_OPH_DEAD_H
#define CPRISK_VM_OPH_DEAD_H

/*
 * cprisk_vm_oph_dead.h
 * CRiskCore
 *
 * Dead handler pool (P1 — handler address space inflation).
 *
 * Problem:
 *   A dynamic analysis tool (Frida, unidbg) that traces the VM can build a
 *   complete opcode→handler-address mapping by executing one instruction of
 *   each logical opcode and recording which function was called.  With the
 *   original dispatch table every live opcode maps to exactly one (or now N,
 *   after v7.5 variant expansion) handler body.  The *total* set of reachable
 *   handler addresses is small and enumerable.
 *
 * Solution:
 *   Inject CPRISK_VM_DEAD_HANDLER_COUNT additional handler functions whose
 *   addresses are folded into session entropy at session-start, but whose
 *   opcode values never appear in real bytecode emitted by the Pass 13 producer.
 *
 *   Effect on an attacker tracing function-pointer resolution:
 *     - The combined handler surface grows from ~40 to ~88+ functions.
 *     - There is no external signal distinguishing live handlers from dead
 *       handlers: both have valid C signatures, both take fr/op/logical/imm/pc/hvar.
 *     - Dead handlers execute CPRISK_VM_FLOW_LEAVE + set POISON_UNKNOWN_OPCODE
 *       when reached, which is also what cprisk_vm_oph_unknown does — so the
 *       attacker cannot reliably distinguish "dead" from "just-not-triggered-yet"
 *       by behaviour alone.
 *
 * v7.5 dispersion (no static fn-pointer table):
 *   The previous design kept a static const cprisk_vm_oph_fn array in __const
 *   so the linker would retain bodies and the touch routine could iterate.
 *   This made the entire dead set enumerable via a single dref pass: "for
 *   offset in __const range, if u64@offset matches a handler-shaped body, it's
 *   a dispatch slot" — exactly the kanxue thread-290993 attack pattern.
 *
 *   The table has been removed.  cprisk_vm_dead_touch_i now takes the address
 *   of each handler inline via &fn at its own ADRP+ADD site, with non-linear
 *   mixing steps interleaved between batches.  Static dref of __const finds no
 *   8-byte fn-pointer constants; recovering the dead set requires reverse-
 *   engineering the touch routine itself, not pattern matching.
 *
 * Integration:
 *   cprisk_vm_entry / cprisk_vm_execute calls cprisk_vm_dead_touch_i() once per
 *   session to derive a fold hash from all 32 inline-referenced handlers,
 *   mixing it into session_mix.  This ensures the dead handler addresses are
 *   loaded at runtime (preventing the linker from stripping bodies via
 *   --gc-sections) and that the hash appears in the session state consumed by
 *   vv_select_index.
 */

#include "cprisk_vm_interpreter_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

// 池大小：必须与 touch 例程中展开的 &handler 数量严格一致；
// 改小会留下未绑定的 handler，改大则覆盖不足，session 熵与布局绑定都会弱化。
#define CPRISK_VM_DEAD_HANDLER_COUNT 32u

// 把全部 handler 地址折叠进 session_mix；不触碰 acc/steps/PC，也不改变执行流。
/*
 * Touch the dead handler table and fold all function-pointer addresses into
 * a 32-bit hash that is XOR'd into fr->session_mix.  Call once per session
 * after the frame is initialised but before the first instruction dispatch.
 */
void cprisk_vm_dead_touch_i(cprisk_vm_interp_frame_t *fr);

#ifdef __cplusplus
}
#endif

#endif /* CPRISK_VM_OPH_DEAD_H */
