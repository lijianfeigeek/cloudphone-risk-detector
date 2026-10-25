// 文件职责：把反调试检查与“毒化/误导/自陷”响应内联进 VM 解释器的类型与 opcode 接口。
// 检测面：P_TRACED、arm64 硬件断点、软件断点指令、异常端口劫持、指令计数时序。
// 采样：默认每 32 次检查探测一次，摊薄系统调用开销；非 iOS 平台状态恒为 CLEAN。
// 线程模型：ctx 内嵌在 VM 帧中，随帧单线程使用；无全局状态、无锁。
// 失败语义：“无法判定”返回 -1 且不算命中；响应只改帧状态，CRASH 模式例外。
/*
 *  vm_antidebug_inline.h
 *  CRiskCore
 */

#ifndef VM_ANTIDEBUG_INLINE_H
#define VM_ANTIDEBUG_INLINE_H

#include <stdint.h>
#include <stddef.h>
#include <signal.h>

#include "include/cprisk_vm_interpreter.h"
#include "include/cprisk_vm_interpreter_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

// 检测结果：0=CLEAN，1..5 为具体命中类型，255=ERROR（仅 ctx NULL）。
// 数值会写入 acc[0] 供 VM 分支读取，属于字节码协议，不能重排。
typedef enum {
    VM_ADB_CLEAN = 0,
    VM_ADB_DETECTED_DEBUGGER = 1,
    VM_ADB_DETECTED_HW_BP = 2,
    VM_ADB_DETECTED_SW_BP = 3,
    VM_ADB_DETECTED_EX_PORT = 4,
    VM_ADB_DETECTED_TIMING = 5,
    VM_ADB_ERROR = 255
} vm_antidebug_result_t;

// 响应模式：POISON 静默污染 VM 状态（默认），STALL 增加停顿计数，
// MISLEAD 打乱控制流指针，CRASH 制造空指针写。由初始化或字节码选择。
typedef enum {
    VM_ADB_RESPONSE_POISON = 0,
    VM_ADB_RESPONSE_STALL = 1,
    VM_ADB_RESPONSE_MISLEAD = 2,
    VM_ADB_RESPONSE_CRASH = 3
} vm_antidebug_response_t;

// 自陷类型：SIGTRAP / 非法指令 / BRK / UDF；未知值落到空指针写。
// 仅在检测命中后由字节码显式触发，正常路径不可达。
typedef enum {
    VM_ADB_TRAP_SIGNAL = 0,
    VM_ADB_TRAP_ILLEGAL = 1,
    VM_ADB_TRAP_BRK = 2,
    VM_ADB_TRAP_UDF = 3
} vm_antidebug_trap_type_t;

// 反调试上下文：func_id 绑定函数；check_count/check_interval 控制采样节奏；
// baseline_cycles 是指令计数基线（EWMA，仅 iOS/arm64 有意义）；五个 *_detected 为粘滞标志；
// response_triggered/poison_applied 记录响应是否执行；response_mode 取响应枚举。
// 内联值类型，无所有权问题；由 vm_antidebug_init 清零并初始化。
typedef struct {
    uint64_t func_id;
    uint32_t check_count;
    uint32_t check_interval;
    uint64_t baseline_cycles;
    uint8_t  debugger_detected;
    uint8_t  hw_breakpoint_detected;
    uint8_t  sw_breakpoint_detected;
    uint8_t  exception_port_hijacked;
    uint8_t  timing_anomaly;
    uint8_t  response_triggered;
    uint8_t  poison_applied;
    uint8_t  response_mode;
} vm_antidebug_ctx_t;

// 初始化：清零、绑定 func_id、设置默认间隔 32 与 POISON 响应；iOS 上建立时序基线。
// ctx NULL 时安全返回；无返回值。应在帧开始执行前调用一次。
void vm_antidebug_init(vm_antidebug_ctx_t *ctx, uint64_t func_id);

// 聚合检测：check_count+1，仅在整数倍间隔真正探测；顺序为 P_TRACED → 硬件断点 →
// 异常端口 → 时序，首个命中即返回并置 sticky 标志。ctx NULL 返回 VM_ADB_ERROR，
// 非 iOS 恒返回 VM_ADB_CLEAN。修改 ctx，需单线程。
vm_antidebug_result_t vm_antidebug_check_all(vm_antidebug_ctx_t *ctx);

// 按 response_mode 对帧执行响应；没有任何检测标志时直接返回（零开销）。
// ctx/fr NULL 时安全返回；无返回值。除 CRASH 外不做系统调用。
void vm_antidebug_apply_response(vm_antidebug_ctx_t *ctx,
                                  cprisk_vm_interp_frame_t *fr);

// imm 低 4 位选择检查类型（0 聚合、1 调试器、2 硬件断点、3 异常端口、4 时序），
// bit4–7 保留未用；结果写入 acc[0]，非 CLEAN 时立即触发响应。
// 始终返回 CONTINUE，fr NULL 返回 LEAVE；非 iOS 上所有类型保持 CLEAN。
cprisk_vm_flow_t vm_op_antidebug_check_execute(cprisk_vm_interp_frame_t *fr,
                                                uint64_t imm);

// 按 imm 低字节触发自陷（0 SIGTRAP、1 非法指令、2 BRK、3 UDF，其他=空指针写）。
// 正常情况下不返回；fr NULL 返回 LEAVE。仅在反调试判定后由字节码使用。
cprisk_vm_flow_t vm_op_antidebug_trap_execute(cprisk_vm_interp_frame_t *fr,
                                               uint64_t imm);

// 执行 100 轮位混合并把结果异或进 opaque_chain；decoy_type 保留但未使用。
// 返回 CONTINUE，fr NULL 返回 LEAVE。
cprisk_vm_flow_t vm_op_antidebug_decoy_execute(cprisk_vm_interp_frame_t *fr,
                                                uint64_t imm);

// 用帧的 func_id 初始化内嵌 ctx，并强制 POISON 响应；应在执行前调用一次。
// 重复调用会重置检测状态与基线；fr NULL 时无操作。
void vm_antidebug_apply_to_interp(cprisk_vm_interp_frame_t *fr);

// 把 sticky 标志压缩为位图：0x01 调试器、0x02 硬件断点、0x04 软件断点、
// 0x08 异常端口、0x10 时序、0x80 已响应。ctx NULL 返回 0；只读，可并发。
uint32_t vm_antidebug_get_detected_flags(vm_antidebug_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif
