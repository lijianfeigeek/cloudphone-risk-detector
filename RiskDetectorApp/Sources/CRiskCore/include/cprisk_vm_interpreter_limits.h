// VM 解释器共享限额：解释器与拆分后的 handler translation unit 必须使用同一组值。
// 这些常量决定 PC 步长、分发缓存粒度与递归深度；改动会改变 bytecode/条目布局。
// 超限行为：PC 越界→INVALID_BYTECODE；子调用/嵌套深度超限→毒化并 LEAVE（fail-closed）。
// 所有值在编译期固定，运行期不做动态放大。
#ifndef CPRISK_VM_INTERPRETER_LIMITS_H
#define CPRISK_VM_INTERPRETER_LIMITS_H

/** Shared with \c cprisk_vm_oph_*.c (must match \c cprisk_vm_interpreter.c). */
// 分发缓存 32 字节：按 op 低 5 位对齐成块，一次填充覆盖相邻 opcode。
#define CPRISK_VM_DISPATCH_CACHE_BYTES 32u
/** One wire opcode byte + 8-byte immediate per instruction. */
// 每条指令 1 字节 wire opcode + 8 字节 LE 立即数 = 9 字节；所有 PC/长度均须是其倍数。
#define CPRISK_VM_INSN_WIDTH 9u
// CALL 返回栈上限 32；条目 profile 只能在此范围内声明更小值。
#define CPRISK_VM_MAX_SUBCALL_DEPTH 32u
// VM_CALL_FUNC 嵌套上限 8；超出即 INVALID_BYTECODE + POISON 并离开。
#define CPRISK_VM_MAX_VM_NEST_DEPTH 8u

#endif /* CPRISK_VM_INTERPRETER_LIMITS_H */
