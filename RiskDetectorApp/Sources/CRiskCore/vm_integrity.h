// 文件职责：VM 状态完整性校验的累积校验链（FNV-1a 变体）与静默毒化策略接口。
// 覆盖范围：仅 vm_integrity_state_t 自身字段；不覆盖字节码、寄存器或栈内容。
// 现状：vm_integrity_* 函数无生产调用方（issue 65），VMH_* 宏仍被加固层使用。
// 线程模型：state 无锁、单写者；check 只读，但仍须避免与 update 并发。
// 失败语义：不崩溃、不返回异常；检测失败只标记 corrupted 并让后续结果不可信。
/* ════════════════════════════════════════════════════════════════════
 * 部分 DEPRECATED（issue 65）：本头文件的 VMH_* 宏仍被
 * cprisk_vm_hardening.c 使用，但本模块的 vm_integrity_* 函数经核查
 * 无任何生产调用方，未接入主路径。请勿新接入这些函数。
 * ════════════════════════════════════════════════════════════════════ */
/*
 * ============================================================================
 * VM状态完整性校验头文件 (vm_integrity.h)
 * ============================================================================
 *
 * 设计目标:
 * --------
 * 1. 轻量级: 校验操作不应显著影响VM执行性能
 * 2. 无依赖: 不依赖外部库，便于集成到CRiskCore
 * 3. 可恢复: 支持状态保存和恢复，用于异常处理
 * 4. 隐式毒化: 检测到篡改时静默污染，不暴露检测逻辑
 */

#ifndef VM_INTEGRITY_H
#define VM_INTEGRITY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 字段范围：magic 为有效/损坏标记；version_seed 只有高 16 位参与比较；
// execution_count 单调递增（全 1 为溢出哨兵）；checksum_chain 为 64 位 FNV 链；
// integrity_tag 是 8 字节标签但无密钥、不是 MAC。结构体由调用方拥有。
/* 完整性状态结构体
 *
 * 字段说明:
 * - magic: 状态有效性标记
 * - version_seed: 版本兼容性校验
 * - execution_count: 执行指令计数 (单调递增)
 * - checksum_chain: 累积校验链 (FNV-1a变体)
 * - integrity_tag: 完整性标签 (8字节简化CPRisk-MAC)
 */
typedef struct {
    uint32_t magic;              /* 状态魔数 */
    uint32_t version_seed;       /* 版本种子 */
    uint64_t execution_count;    /* 执行计数 */
    uint64_t checksum_chain;     /* 校验链 */
    uint8_t  integrity_tag[8];   /* 完整性标签 */
} vm_integrity_state_t;

// check 的结果分类：OK=0；其余为互斥分类，调用方应按值判断而非按位。
// 该枚举只描述只读检查的结论，不修改状态。
/* 完整性检查结果 */
typedef enum {
    VM_INT_RESULT_OK = 0,                /* 状态正常 */
    VM_INT_RESULT_CORRUPTED = 1,         /* 状态已损坏 */
    VM_INT_RESULT_INVALID = 2,           /* 无效状态 */
    VM_INT_RESULT_VERSION_MISMATCH = 3,  /* 版本不匹配 */
    VM_INT_RESULT_OVERFLOW = 4,          /* 执行计数溢出 */
    VM_INT_RESULT_CHAIN_BROKEN = 5,      /* 校验链断裂 */
    VM_INT_RESULT_TAG_INVALID = 6,       /* 标签无效 */
    VM_INT_RESULT_ERROR = 7              /* 其他错误 */
} vm_integrity_result_t;

// API 错误码：0 成功，负值失败；不要与上面的结果分类混用（正/负值域不同）。
/* 错误码 */
typedef enum {
    VM_INT_OK = 0,
    VM_INT_ERROR_INVALID_PARAM = -1,
    VM_INT_ERROR_CORRUPTED = -2,
    VM_INT_ERROR_STEP_MISMATCH = -3,
    VM_INT_ERROR_CHAIN_UNCHANGED = -4
} vm_integrity_error_t;

// 事件类型：数值进入校验链的高 8 位，改动会使既有链全部失效，不能重排。
/* 完整性事件类型 (用于更新校验链) */
typedef enum {
    VM_INT_EVENT_INIT = 0,       /* 初始化 */
    VM_INT_EVENT_FETCH = 1,      /* 取指 */
    VM_INT_EVENT_DECODE = 2,     /* 解码 */
    VM_INT_EVENT_EXECUTE = 3,    /* 执行 */
    VM_INT_EVENT_MEMORY_READ = 4,  /* 内存读 */
    VM_INT_EVENT_MEMORY_WRITE = 5, /* 内存写 */
    VM_INT_EVENT_BRANCH = 6,     /* 分支跳转 */
    VM_INT_EVENT_CALL = 7,       /* 函数调用 */
    VM_INT_EVENT_RET = 8,        /* 函数返回 */
    VM_INT_EVENT_EXCEPTION = 9   /* 异常 */
} vm_integrity_event_t;

// 违规类型：仅作为毒化时混入链的加数，数值本身无安全含义；未知类型归 UNKNOWN。
/* 完整性违规类型 (用于毒化处理) */
typedef enum {
    VM_INT_VIOLATION_NONE = 0,
    VM_INT_VIOLATION_MAGIC_CHANGED = 1,    /* Magic值被修改 */
    VM_INT_VIOLATION_COUNT_ROLLBACK = 2,   /* 执行计数回滚 */
    VM_INT_VIOLATION_CHAIN_TAMPER = 3,     /* 校验链篡改 */
    VM_INT_VIOLATION_TAG_MISMATCH = 4,     /* 标签不匹配 */
    VM_INT_VIOLATION_UNKNOWN = 5           /* 未知违规 */
} vm_integrity_violation_t;

// 初始化：清零 → 写 magic → 派生 version_seed → 设置 FNV 偏移基 → 生成 tag。
// state 非 NULL，vm_id 用于绑定实例；成功返回 VM_INT_OK，参数错误 INVALID_PARAM。
// 写全部字段，需独占；纯整数运算，平台无关，不写 errno。
/* 初始化VM完整性状态 */
int vm_integrity_init(vm_integrity_state_t *state, uint64_t vm_id);

// 只读自检：magic、版本高 16 位、计数溢出、链非零、tag 非全零。
// 返回具体的 vm_integrity_result_t；state NULL 返回 ERROR。
// 不是来源认证，攻击者可构造同样通过检查的状态；并发读写会读到撕裂状态。
/* 执行校验点检查
 *
 * 应在关键位置调用:
 * - 每条指令执行后
 * - 函数调用/返回时
 * - 内存访问前后
 */
vm_integrity_result_t vm_integrity_check(const vm_integrity_state_t *state);

// 推进一次事件：先自检，再把 (event 高 8 位 | data 低 56 位) 折入 FNV 链并计数。
// 返回 OK / INVALID_PARAM / CORRUPTED；自检失败会把 magic 置 CORRUPTED。
// 读写 state，禁止并发；每 256 次刷新 integrity_tag。
/* 更新完整性状态
 *
 * 在执行操作后调用，更新校验链
 */
int vm_integrity_update(vm_integrity_state_t *state,
                        vm_integrity_event_t event,
                        uint64_t event_data);

// 确认篡改后：置 CORRUPTED、按违规类型污染链与 tag、把计数写为异常哨兵。
// state NULL 时安全返回；无返回值、不崩溃。设计目标是静默产出错误结果。
/* 处理完整性破坏事件
 *
 * 毒化策略: 静默标记状态为损坏，不暴露检测
 */
void vm_integrity_handle_tamper(vm_integrity_state_t *state,
                                vm_integrity_violation_t violation);

// 校验两个快照之间是否恰好执行 expected_step_count 步且链发生变化。
// 返回 OK / INVALID_PARAM / CORRUPTED / STEP_MISMATCH / CHAIN_UNCHANGED。
// 只读；只能证明步数对且链变了，无法证明中间事件序列正确。
/* 验证特定操作序列的完整性 */
int vm_integrity_verify_sequence(const vm_integrity_state_t *state_before,
                                  const vm_integrity_state_t *state_after,
                                  uint32_t expected_step_count);

// export：按内存布局导出，buffer_size ≥ sizeof(state) 且状态自检通过；返回字节数，失败 0。
// import：复制后自检，失败则清零目标并返回 CORRUPTED；长度不足/指针 NULL 返回 INVALID_PARAM。
// 两者均无来源认证，且内存布局依赖端序/版本，跨端不可互通。
/* 导出/导入完整性状态 */
size_t vm_integrity_export(const vm_integrity_state_t *state,
                           uint8_t *out_buffer,
                           size_t buffer_size);
int vm_integrity_import(vm_integrity_state_t *state,
                        const uint8_t *data,
                        size_t data_size);

// secure_zero 整个状态，NULL 安全；擦除后 magic=0，任何 check 返回 INVALID，需重新 init。
/* 安全清除完整性状态 */
void vm_integrity_clear(vm_integrity_state_t *state);

// VM_CHECKPOINT：先 check 再 update 的便捷封装；失败时调用 handle_tamper。
// state 必须可写，event/data 语义同 vm_integrity_update；展开为 do/while(0)。
// 不返回错误码，失败被静默毒化；不要在宏参数里传入带逗号的表达式。
/* VM_CHECKPOINT宏 - 便捷的校验点调用
 *
 * 使用示例:
 *   VM_CHECKPOINT(&state, VM_INT_EVENT_EXECUTE, pc);
 */
#define VM_CHECKPOINT(state, event, data) do { \
    vm_integrity_result_t _r = vm_integrity_check(state); \
    if (_r != VM_INT_RESULT_OK) { \
        vm_integrity_handle_tamper(state, VM_INT_VIOLATION_UNKNOWN); \
    } else { \
        vm_integrity_update(state, event, data); \
    } \
} while(0)

// VM_GUARD：check 失败时执行调用方提供的 poison_code（而不是返回错误）。
// poison_code 必须是完整语句；同样展开为 do/while(0)，无返回值。
/* VM_GUARD宏 - 带毒化的校验点
 *
 * 如果检查失败，执行毒化代码而非返回错误
 */
#define VM_GUARD(state, poison_code) do { \
    if (vm_integrity_check(state) != VM_INT_RESULT_OK) { \
        vm_integrity_handle_tamper(state, VM_INT_VIOLATION_UNKNOWN); \
        poison_code; \
    } \
} while(0)

#ifdef __cplusplus
}
#endif

#endif /* VM_INTEGRITY_H */
