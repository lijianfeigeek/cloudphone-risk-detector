// 文件职责：VM 密钥层级与白盒 PRF 绑定——root → func → 各用途 operation key。
// 现状：未接入主路径（issue 65）；本模块只做 SHA-256 域分离派生，不直接执行 PRF。
// 域标签：ROOT/FUNC/OP 三个 16 字节常量定义在 .c 中，改动会使已派生密钥全部失效。
// 线程模型：无全局可变状态、无堆分配、无锁，可并发调用；输出缓冲归调用方。
// 失败语义：失败返回负错误码且不写 errno；成功时不清零输出，调用方负责清理。
/* ════════════════════════════════════════════════════════════════════
 * DEPRECATED — 未接入主路径（issue 65）。
 * 本模块经核查无任何生产调用方（仅自身内部引用 / 仅被本模块自身包含），
 * 不属于主防御路径。保留文件仅为兼容（Xcode 工程仍列出本文件），请勿
 * 新接入、请勿将其能力计入防御声明。如需移除，请同步更新工程文件。
 * ════════════════════════════════════════════════════════════════════ */
/*
 * ============================================================================
 * VM与白盒PRF深度绑定头文件 (vm_whitebox_bind.h)
 * ============================================================================
 */

#ifndef VM_WHITEBOX_BIND_H
#define VM_WHITEBOX_BIND_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 密钥用途：数值写入操作密钥派生输入的第 33 字节（只取低 8 位），是协议常量，不能重排。
// 各用途共享 func_key，但 key_type 不同使派生输出互不相同。
/* 密钥类型枚举 */
typedef enum {
    VM_WB_KEY_BYTECODE = 0,     /* 字节码编码密钥 */
    VM_WB_KEY_STACK = 1,        /* 栈加密密钥 */
    VM_WB_KEY_MEMORY = 2,       /* 内存加密密钥 */
    VM_WB_KEY_INTEGRITY = 3,    /* 完整性校验密钥 */
    VM_WB_KEY_ANTIDEBUG = 4,    /* 反调试密钥 */
    VM_WB_KEY_POISON = 5        /* 毒化值派生密钥 */
} vm_wb_key_type_t;

// 毒化用途：数值同时作为 poison_key 的字节窗口偏移（要求 ≤24）与高位标识；
// 当前枚举 0..4，不能把任意整数强转后传入，否则会越界读取密钥。
/* 毒化值类型 */
typedef enum {
    VM_WB_POISON_SCORE = 0,     /* 评分毒化 */
    VM_WB_POISON_DEVICE_ID = 1, /* 设备ID毒化 */
    VM_WB_POISON_REPORT = 2,    /* 报告毒化 */
    VM_WB_POISON_CONFIG = 3,    /* 配置毒化 */
    VM_WB_POISON_RANDOM = 4     /* 随机毒化 */
} vm_wb_poison_type_t;

// 绑定参数：func_id 绑定函数，device_binding/whitebox_key 为输入秘密（各 32 字节），
// 由调用方提供并在用完后 secure_zero。结构体为值类型，无堆指针。
/* 绑定参数结构体 */
typedef struct {
    uint64_t func_id;                    /* 函数标识符 */
    uint8_t device_binding[32];          /* 设备绑定值 */
    uint8_t whitebox_key[32];            /* 白盒根密钥 */
} vm_wb_binding_params_t;

// 派生密钥集合：func_key 与六类 operation key 各 32 字节，func_id 为明文回显。
// 所有权：由调用方提供；使用完毕必须调用 vm_wb_clear_derived_keys。
/* 派生密钥集合 */
typedef struct {
    uint64_t func_id;                    /* 函数ID */
    uint8_t func_key[32];                /* 函数专用密钥 */
    uint8_t bytecode_key[32];            /* 字节码密钥 */
    uint8_t stack_key[32];               /* 栈加密密钥 */
    uint8_t memory_key[32];              /* 内存加密密钥 */
    uint8_t integrity_key[32];           /* 完整性密钥 */
    uint8_t antidebug_key[32];           /* 反调试密钥 */
    uint8_t poison_key[32];              /* 毒化密钥 */
} vm_wb_derived_keys_t;

// 编码参数：由 bytecode_key 切片拼装；stream_key 与 perm_seed 尾部字节重叠，
// 不能当作独立熵源。无所有权字段。
/* 编码参数 */
typedef struct {
    uint32_t opcode_xor_key;             /* 操作码异或密钥 */
    uint64_t operand_salt;               /* 操作数盐值 */
    uint64_t dispatch_seed;              /* 调度种子 */
    uint64_t perm_seed;                  /* 置换表种子 */
    uint8_t  stream_key[32];             /* 流加密密钥 */
} vm_wb_encoding_params_t;

// 栈参数：与 vm_stack_crypto 的上下文语义兼容，但切片偏移不同，两套不可混用；
// stack_rot 会被重映射到 8..15，保证移位量合法。
/* 栈加密参数 */
typedef struct {
    uint64_t stack_xor_key;              /* 栈异或密钥 */
    uint8_t  stack_rot;                  /* 旋转量 */
    uint64_t stack_offset;               /* 偏移量 */
    uint64_t secondary_key;              /* 次级密钥 */
} vm_wb_stack_params_t;

// 错误码：0 成功，负值失败；DERIVE_FAILED 预留给将来可能失败的派生实现。
/* 错误码 */
typedef enum {
    VM_WB_OK = 0,
    VM_WB_ERROR_INVALID_PARAM = -1,
    VM_WB_ERROR_DERIVE_FAILED = -2,
    VM_WB_ERROR_NOT_INITIALIZED = -3
} vm_wb_error_t;

// SHA-256(地址 8 || compile_salt 16 || 0…0 8 || LABEL_FUNC 16) → out_hash(32)。
// func_ptr 允许 NULL；compile_salt/out_hash 必须非 NULL；无返回值、无失败路径。
// 结果依赖 PIE/ASLR，同一二进制每次启动不同，不能当持久化 ID；可重入。
/* 计算函数身份哈希
 *
 * 生成函数的唯一标识
 */
void vm_wb_hash_function_identity(void (*func_ptr)(void),
                                   const uint8_t compile_salt[16],
                                   uint8_t out_hash[32]);

// 两阶段 SHA-256 派生根密钥：r1=SHA256(binding||wb||LABEL_ROOT)，root=SHA256(r1||输入)。
// 三参数均非 NULL 且各 32 字节；成功 VM_WB_OK，参数错误 INVALID_PARAM。
// 输出归调用方；无共享状态，可并发；失败不触碰 out_root_key。
/* 派生根密钥 */
int vm_wb_derive_root_key(const uint8_t device_binding[32],
                          const uint8_t whitebox_key[32],
                          uint8_t out_root_key[32]);

// 函数密钥：SHA256(root_key||func_id(8, 主机字节序)||LABEL_FUNC)。
// 跨大端/小端平台结果不同，不能互通。成功 0/失败 INVALID_PARAM，可并发。
/* 派生函数专用密钥 */
int vm_wb_derive_function_key(const uint8_t root_key[32],
                              uint64_t func_id,
                              uint8_t out_func_key[32]);

// 操作密钥：SHA256(func_key||key_type(1)||context(16)||LABEL_OP 前 15 字节)。
// context 提供用途内子域绑定，全 0 合法；成功 0/失败 INVALID_PARAM，可并发。
/* 派生操作密钥 */
int vm_wb_derive_operation_key(const uint8_t func_key[32],
                               vm_wb_key_type_t key_type,
                               const uint8_t context[16],
                               uint8_t out_op_key[32]);

// 一次性派生全套密钥（root 不导出）：root→func_key→六类 operation key，并回显 func_id。
// params/out_keys 非 NULL；成功 VM_WB_OK，失败返回对应负码。
// 失败时 out_keys 可能已部分写入，调用方应 clear 后丢弃；需独占 out_keys。
/* 初始化完整VM密钥派生 */
int vm_wb_init_vm_keys(const vm_wb_binding_params_t *params,
                       vm_wb_derived_keys_t *out_keys);

// 从 bytecode_key 切片拼装编码参数（纯字节操作，无哈希）。
// 参数 NULL 时静默返回；无返回值/错误码；输出由调用方提供，端序影响结果。
/* 派生编码参数 */
void vm_wb_derive_encoding_params(const uint8_t bytecode_key[32],
                                  vm_wb_encoding_params_t *out_params);

// 从 stack_key 与 func_id 派生栈参数；func_id 必须与后续解混淆一致。
// 参数 NULL 时静默返回；无返回值；布局与 vm_stack_crypto 不同，不可混用。
/* 派生栈加密参数 */
void vm_wb_derive_stack_params(const uint8_t stack_key[32],
                               uint64_t func_id,
                               vm_wb_stack_params_t *out_params);

// 从 poison_key 的 8 字节窗口派生 64 位毒化值；key NULL 返回 0xDEADBEEFCAFEBABE。
// poison_type 必须 ≤24（作为字节偏移），否则越界读；无错误码；可并发。
/* 生成毒化值 */
uint64_t vm_wb_derive_poison_value(const uint8_t poison_key[32],
                                    vm_wb_poison_type_t poison_type);

// secure_zero 整个派生密钥集合；NULL 安全，可重复调用。失败或使用完毕后必须调用。
/* 安全清除派生密钥 */
void vm_wb_clear_derived_keys(vm_wb_derived_keys_t *keys);

#ifdef __cplusplus
}
#endif

#endif /* VM_WHITEBOX_BIND_H */
