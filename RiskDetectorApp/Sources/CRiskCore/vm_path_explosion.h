// 文件职责：向 VM 路径注入不透明谓词、诱饵分支与 MBA 运算，制造受控路径爆炸。
// 现状：未接入主路径（issue 65），无生产调用方；头文件枚举与 .c 的实现集合并不一致。
// 预算：MBA ≤4 层、每 16 条指令一个检查点、考拉兹循环 ≤256 步、符号炸弹 ≤4 层。
// 线程模型：ctx 无锁、单写者；apply_to_interp 每次重建局部 ctx，计数不跨调用累积。
// 平台/失败语义：纯 C 无平台分支；NULL 输入静默返回 0，谓词结果均为确定性值。
/* ════════════════════════════════════════════════════════════════════
 * DEPRECATED — 未接入主路径（issue 65）。
 * 本模块经核查无任何生产调用方（仅自身内部引用 / 仅被本模块自身包含），
 * 不属于主防御路径。保留文件仅为兼容（Xcode 工程仍列出本文件），请勿
 * 新接入、请勿将其能力计入防御声明。如需移除，请同步更新工程文件。
 * ════════════════════════════════════════════════════════════════════ */
/*
 *  vm_path_explosion.h
 *  CRiskCore
 *
 *  路径爆炸对抗符号执行 - Path Explosion Countermeasure for Symbolic Execution
 *
 *  本头文件定义了路径爆炸防御的公开API和数据结构。
 *  路径爆炸是通过在VM执行路径中插入不透明谓词和假分支，
 *  使符号执行工具面临指数级路径爆炸的技术。
 */

#ifndef VM_PATH_EXPLOSION_H
#define VM_PATH_EXPLOSION_H

#include <stdint.h>
#include <stddef.h>

#include "include/cprisk_vm_interpreter.h"
#include "include/cprisk_vm_interpreter_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

// 三个预算参数决定分析成本与 VM 每步开销：4 层限制单点计算量，
// 16 是检查点间隔；FORK_COUNT=8 只是设计目标，当前代码未直接使用。
/* 路径爆炸配置参数 */
#define VM_PATH_EXPLOSION_LAYERS        4   /* MBA混淆层数 */
#define VM_PATH_EXPLOSION_FORK_COUNT    8   /* 每个分支点产生的路径数 */
#define VM_PATH_EXPLOSION_DECOY_DENSITY 16  /* 每16条指令插入一个诱饵 */

// 谓词类型 0–7 与 .c 的实现索引一致；.c 另有索引 8（白盒查表）未写入本头文件。
// 数值参与 selector 取模，重排会改变既有函数生成的谓词序列。
/*
 * 不透明谓词类型枚举
 * 每种类型基于不同的数学性质构造
 */
typedef enum {
    VM_OPAQUE_PREDICATE_ALWAYS_TRUE_1 = 0,   /* x*x >= 0 */
    VM_OPAQUE_PREDICATE_ALWAYS_TRUE_2,        /* x + x = 2x */
    VM_OPAQUE_PREDICATE_ALWAYS_FALSE_1,       /* x*x < 0 */
    VM_OPAQUE_PREDICATE_ALWAYS_FALSE_2,       /* x & (~x) != 0 */
    VM_OPAQUE_PREDICATE_FERMAT_STYLE,         /* 基于a^2 + b^2 = c^2无解(非零) */
    VM_OPAQUE_PREDICATE_WILSON_STYLE,         /* (p-1)! mod p = p-1 */
    VM_OPAQUE_PREDICATE_EULER_STYLE,          /* 欧拉准则 */
    VM_OPAQUE_PREDICATE_COLLATZ_STYLE,        /* 考拉兹猜想相关 */
} vm_opaque_predicate_type_t;

// 假分支元数据：两个 target 均为 32 位字节码偏移；is_always_true 非 0 表示谓词恒真；
// mba_layers 应 ≤ VM_PATH_EXPLOSION_LAYERS。当前未实例化，仅保留接口形状。
/*
 * 假分支结构体
 * 描述一个假分支的元数据
 */
typedef struct {
    uint32_t predicate_seed;        /* 谓词生成种子 */
    uint32_t branch_target_fake;    /* 假分支目标地址 */
    uint32_t branch_target_real;    /* 实际分支目标 */
    uint8_t  is_always_true;        /* 谓词是否永真 */
    uint8_t  mba_layers;            /* MBA混淆层数 */
    vm_opaque_predicate_type_t type; /* 谓词类型 */
} vm_fake_branch_t;

// MBA 状态：accumulator 为主状态，xor_mask/add_mask 为两套混合掩码，rotate_count 预留；
// 四者均为 32 位无符号，允许模 2^32 回绕；无所有权或生命周期字段。
/*
 * MBA表达式状态
 * 用于MBA混淆的上下文
 */
typedef struct {
    uint32_t accumulator;
    uint32_t xor_mask;
    uint32_t add_mask;
    uint32_t rotate_count;
} vm_mba_state_t;

// 路径爆炸上下文：func_id/bytecode_hash 决定谓词选择，fork/decoy_counter 记录预算消耗，
// mba 保存混合状态，path_marker 按 pc%32 异或累加（同一槽重复命中会相互抵消）。
// 所有权：调用方提供，无堆指针；单写者、无锁。
/*
 * 路径爆炸上下文
 * 管理整个路径爆炸防御的状态
 */
typedef struct {
    uint64_t func_id;
    uint32_t bytecode_hash;
    uint32_t fork_counter;
    uint32_t decoy_counter;
    vm_mba_state_t mba;
    uint8_t path_marker[32];
} vm_path_explosion_ctx_t;

// 在 pc 处执行一次不透明谓词检查并更新 MBA/路径状态。
// ctx 非 NULL；acc 参数当前未使用。返回 1=进入诱饵路径、0=真实路径；
// 当前实现实际不会返回 1（诱饵路径未触发）。写 ctx，需单写者。
// selector=(pc^bytecode_hash^func_id)%9，稳定可复现。
/*
 * 公开API: 在指定PC位置插入不透明谓词检查点
 *
 * @param ctx 路径爆炸上下文
 * @param pc 当前程序计数器
 * @param acc VM累加器状态
 * @return 0表示应继续执行实际路径，1表示进入诱饵路径
 */
int vm_path_explosion_checkpoint(vm_path_explosion_ctx_t *ctx,
                                  uint32_t pc,
                                  uint8_t acc[32]);

// 执行 4 组语义等价运算（加法抵消、异或自反、双重取反、模幂），结果写入 volatile sink；
// 只递增 decoy_counter，不改变 VM 语义。ctx NULL 时无操作，无返回值。
/*
 * 公开API: 执行NOP装饰指令序列
 *
 * 这些指令在语义上是NOP(不改变最终计算结果)，
 * 但会执行一些中间计算，使符号执行器跟踪额外状态
 */
void vm_path_explosion_nop_decoy(vm_path_explosion_ctx_t *ctx, uint32_t pc);

// 初始化 ctx：清零、记录 func_id，从 32 字节字节码哈希抽样 32 位混合值，
// 再设置 MBA 与 path_marker 初值。bytecode_hash 必须可读 32 字节（函数内不判 NULL）。
// 只写 ctx，无返回值；相同输入结果可复现。
/*
 * 公开API: 初始化路径爆炸上下文
 */
void vm_path_explosion_init(vm_path_explosion_ctx_t *ctx,
                             uint64_t func_id,
                             const uint8_t bytecode_hash[32]);

// 生成 32 字节路径指纹（确定性摘要，不是 MAC）；fingerprint 必须可写 32 字节。
// ctx/fingerprint NULL 时静默返回；只读 mba/path_marker，可并发读。
/*
 * 公开API: 获取当前路径指纹
 * 用于检测符号执行器的路径覆盖
 */
void vm_path_explosion_get_fingerprint(vm_path_explosion_ctx_t *ctx,
                                        uint8_t fingerprint[32]);

// VM 主循环钩子：用帧快照重建局部 ctx，以 steps 低 16 位代理 pc，每 16 条指令检查一次；
// 进入诱饵则执行 NOP 序列，最后把 accumulator 写回 opaque_chain、指纹写入 trace_scratch。
// 局部 ctx 不跨调用保留，计数每次从 steps 重新开始；fr NULL 时无操作。
/*
 * 公开API: 在VM解释器循环中应用路径爆炸防护
 *
 * 此函数应在VM主循环的每个指令周期调用
 */
void vm_path_explosion_apply_to_interp(cprisk_vm_interp_frame_t *fr);

// 按 intensity%4+1 决定 1..4 层，每层构造 a³+b³ 与伪立方根的恒假比较，
// 并把 lhs 混入 opaque_chain。intensity 任意，fr NULL 时无操作；循环有硬上界。
/*
 * 公开API: 触发符号爆炸
 * 当检测到可疑行为时主动增加符号执行负担
 */
void vm_path_explosion_trigger_symex_bomb(cprisk_vm_interp_frame_t *fr,
                                           uint32_t intensity);

// 永真谓词 x*x>=0：int64 乘法在极端输入可能溢出（有符号溢出为 UB），
// 因此结果只用于混淆，不能作为可靠控制流依据。返回 1/0。
/*
 * 快速内联不透明谓词检查 - 用于热路径
 */
static inline int vm_path_explosion_predicate_true_inline(uint32_t seed) {
    /* x*x >= 0 永真 */
    int64_t x = (int64_t)seed;
    return (x * x) >= 0;
}

// 永假谓词 x*x<0：正常输入恒返回 0，同样受有符号溢出影响。
/*
 * 快速内联永假谓词 - 用于热路径
 */
static inline int vm_path_explosion_predicate_false_inline(uint32_t seed) {
    /* x*x < 0 永假 */
    int64_t x = (int64_t)seed;
    return (x * x) < 0;
}

// MBA XOR 内联：(a|b)-(a&b) == a^b（无符号回绕下成立）；纯函数、无状态。
/*
 * MBA混淆内联函数 - 快速版本
 */
static inline uint32_t vm_mba_xor_inline(uint32_t a, uint32_t b) {
    /* MBA: (a|b) - (a&b) = a ^ b */
    return (a | b) - (a & b);
}

#ifdef __cplusplus
}
#endif

#endif /* VM_PATH_EXPLOSION_H */
