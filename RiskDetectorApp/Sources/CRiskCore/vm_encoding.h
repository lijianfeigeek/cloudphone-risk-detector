// 文件职责：VMP 多字节码编码方案的参数结构与接口（V0 线性异或 → V3 分层混合）。
// 现状：未接入主路径（issue 65），保留仅为兼容；其能力不应计入防御声明。
// 编码参数全部由 func_id 经白盒 PRF 派生，不同函数不共享密钥。
// 线程模型：ctx 无锁、单写者；编码/解码只读 ctx，V3 级联推进必须串行。
// 平台：纯整数运算，模拟器与 arm64/arm64e 语义一致；失败返回 -1/0，不写 errno。
/* ════════════════════════════════════════════════════════════════════
 * DEPRECATED — 未接入主路径（issue 65）。
 * 本模块经核查无任何生产调用方（仅自身内部引用 / 仅被本模块自身包含），
 * 不属于主防御路径。保留文件仅为兼容（Xcode 工程仍列出本文件），请勿
 * 新接入、请勿将其能力计入防御声明。如需移除，请同步更新工程文件。
 * ════════════════════════════════════════════════════════════════════ */
#ifndef VM_ENCODING_H
#define VM_ENCODING_H

#include <stdint.h>
#include <stddef.h>

/*
 * ============================================================================
 * VMP多字节码编码方案随机化 (Multi-Bytecode Encoding Randomization)
 * ============================================================================
 *
 * 加固原理:
 * --------
 * 1. 对抗静态分析: 每个受保护函数使用不同的字节码编码方案，使攻击者无法建立通用的字节码语义映射
 * 2. 增加逆向成本: 需要针对每个函数单独分析编码方案，无法批量解密
 * 3. 多态性保护: 同一逻辑在不同函数中呈现完全不同的字节码形态
 * 4. 混淆操作语义: 操作码和操作数的编码相互依赖，增加分析复杂度
 *
 * 编码方案V0-V3:
 * ------------
 * V0: 基础线性编码 (向后兼容)
 *     - 操作码简单异或
 *     - 固定长度操作数
 *
 * V1: 置换编码 (Permutation Encoding)
 *     - 操作码查表置换
 *     - 操作数分段加密
 *     - 引入伪指令噪音
 *
 * V2: 流式加密编码 (Stream Cipher Encoding)
 *     - 基于ChaCha20的流式混淆
 *     - 变长操作数编码
 *     - 指令级联依赖
 *
 * V3: 分层混合编码 (Layered Hybrid Encoding)
 *     - 多层加密嵌套
 *     - 上下文敏感编码
 *     - 动态指令重写
 *
 * 安全特性:
 * --------
 * - 每个函数的编码参数通过WhiteBox PRF派生，无法从静态数据中提取
 * - 操作码与操作数使用不同密钥，分离破解
 * - 编码版本与函数ID绑定，防止代码复用攻击
 * - 运行时完整性校验，检测代码篡改
 */

// 编码方案版本：数值会写入字节码头，编解码两侧必须一致。
// V0 最弱（仅异或），V1 加置换，V2 加流式风格与变长，V3 加上下文敏感与级联；
// VM_ENCODING_COUNT 是上界哨兵（合法值 < 4），不可作为方案使用。
/* 编码方案版本枚举 */
typedef enum {
    VM_ENCODING_V0 = 0,  /* 基础线性编码 */
    VM_ENCODING_V1 = 1,  /* 置换编码 */
    VM_ENCODING_V2 = 2,  /* 流式加密编码 */
    VM_ENCODING_V3 = 3,  /* 分层混合编码 */
    VM_ENCODING_COUNT = 4
} vm_encoding_version_t;

// 能力位掩码：由 vm_encoding_init 按版本写入 capabilities，调用方只读；
// 位值固定为协议常量，改动会改变跨版本能力判断。当前主要用于描述，
// 编码器内部仍按 encoding_version 分支。
/* 编码方案能力标志 */
#define VM_ENC_CAP_OPCODE_PERMUTATION   0x01u  /* 操作码置换 */
#define VM_ENC_CAP_OPERAND_ENCRYPTION   0x02u  /* 操作数加密 */
#define VM_ENC_CAP_VARIABLE_LENGTH      0x04u  /* 变长编码 */
#define VM_ENC_CAP_STREAM_CIPHER        0x08u  /* 流式加密 */
#define VM_ENC_CAP_CONTEXT_SENSITIVE    0x10u  /* 上下文敏感 */
#define VM_ENC_CAP_INSTRUCTION_CHAIN    0x20u  /* 指令级联 */

// 编码上下文：由 vm_encoding_init 填充，调用方独占；含密钥，用毕应调用
// vm_encoding_clear_ctx。字段无外部所有权，全部内联。
/* 编码上下文结构体 */
typedef struct {
    uint32_t encoding_version;      /* 编码方案版本 V0-V3 */
    uint32_t opcode_xor_key;        /* 操作码异或密钥 */
    uint64_t operand_salt;          /* 操作数加密盐值 */
    uint64_t dispatch_seed;         /* 调度表随机化种子 */
    // permutation_table 只有 16 项：编码时按操作码低/高半字节各查一次，不是 256 项置换；
    // V0 不使用，V1+ 由 vm_encoding_gen_permutation 生成，相同 seed 可复现。
    uint32_t permutation_table[16]; /* 操作码置换表 (V1+) */
    uint32_t capabilities;          /* 启用的能力标志 */
    // stream_key 仅 V2/V3 有效；V3 的 chain_state 与其尾部字节在 init 中重叠，
    // 两者不是独立随机量（详见 vm_encoding.c 的 init 说明）。
    uint8_t  stream_key[32];        /* 流加密密钥 (V2+) */
    uint32_t chain_state;           /* 级联状态 (V3) */
} vm_encoding_ctx_t;

// 变长编码长度布局（单位：字节），由 vm_encoding_varlen_info 按版本填充。
// 当前实现 opcode_len 恒为 1、operand_len 恒为 8（上限），flag_len 在 V2/V3 为 1。
/* 变长编码长度信息 */
typedef struct {
    uint8_t opcode_len;     /* 操作码字节数: 1-3 */
    uint8_t operand_len;    /* 操作数字节数: 0-8 */
    uint8_t flag_len;       /* 标志字节数: 0-2 */
} vm_varlen_info_t;

// 单条编码指令容器：raw_bytes 固定 16 字节上限，total_len 为有效长度
// （编码成功时 3..10，解码要求 1..16）。original_pc 由调用方维护，编码器置 0。
// 结构体归调用方所有；不含需要单独释放的指针。
/* 编码后的指令 */
typedef struct {
    uint8_t  raw_bytes[16]; /* 最大16字节编码后数据 */
    uint8_t  total_len;     /* 实际编码长度 */
    uint32_t original_pc;   /* 原始程序计数器 */
} vm_encoded_insn_t;

// 初始化编码上下文：校验版本、记录能力位，并从白盒 PRF 派生全部密钥参数。
// ctx 不可为 NULL，version 必须 < VM_ENCODING_COUNT；成功返回 0，失败 -1。
// 只写 ctx；失败时 ctx 已清零，可直接丢弃。不得与同一 ctx 的读写并发。
/*
 * 初始化编码上下文
 * 通过WhiteBox PRF派生所有密钥参数
 */
int vm_encoding_init(vm_encoding_ctx_t *ctx,
                     uint64_t func_id,
                     vm_encoding_version_t version);

// 按 func_id 哈希最低字节选择版本（约 20%/30%/30%/20%），纯函数、无状态，可并发。
// 相同 func_id 必得同一版本，编码端与解码端因此可独立复现选择结果。
/*
 * 自动选择编码版本
 * 基于函数ID和运行时熵源选择最优编码方案
 */
vm_encoding_version_t vm_encoding_select_version(uint64_t func_id);

// 编码一条 (opcode, operand)：opcode 必须 ≤ 0xFF，ctx/out 均不可为 NULL。
// 输出统一大端；total_len 为 V0/V1 9 字节、V2/V3 2+op_len 字节。
// 返回 0 成功，-1 参数非法或版本未知；只读 ctx，V3 级联状态不在此推进。
/*
 * 编码单条指令
 * 根据当前编码方案将原始指令编码为字节码
 */
int vm_encoding_encode_insn(const vm_encoding_ctx_t *ctx,
                            uint32_t opcode,
                            uint64_t operand,
                            vm_encoded_insn_t *out);

// 编码的逆过程：encoded->total_len 须在 [1,16]，V2/V3 长度前缀 > 8 返回 -1。
// 成功返回 0 并写 *opcode_out/*operand_out；入参 NULL 或越界返回 -1。
// V0/V1 固定读 9 字节却只校验 total_len≥1，调用方必须保证实际长度足够。只读，可并发。
/*
 * 解码单条指令
 * 从字节码还原原始指令
 */
int vm_encoding_decode_insn(const vm_encoding_ctx_t *ctx,
                            const vm_encoded_insn_t *encoded,
                            uint32_t *opcode_out,
                            uint64_t *operand_out);

// 返回该版本单条指令的长度布局；ctx 为 NULL 时返回默认 {1,8,0}，不会崩溃。
// opcode 当前未使用，保留给按指令类型优化。返回值按值传递，无所有权转移。
/*
 * 计算变长编码信息
 * 根据指令类型和编码方案确定编码长度
 */
vm_varlen_info_t vm_encoding_varlen_info(const vm_encoding_ctx_t *ctx,
                                         uint32_t opcode);

// 用 SplitMix64 驱动的 Fisher-Yates 生成 16 项置换表；相同 seed 结果可复现。
// 只写 ctx->permutation_table；ctx 不校验 NULL，无返回值，不做线程同步。
/*
 * 生成置换表
 * 为V1编码方案生成操作码置换表
 */
void vm_encoding_gen_permutation(vm_encoding_ctx_t *ctx, uint64_t seed);

// V2/V3 流状态初始化占位：seed 被忽略，当前不修改 ctx（stream_key 已在 init 写入）。
// 保留签名以便后续接入真正的流状态；无返回值，ctx 当前未被解引用。
/*
 * 初始化流加密状态
 * 为V2/V3编码方案初始化ChaCha20状态
 */
void vm_encoding_init_stream(vm_encoding_ctx_t *ctx, uint64_t seed);

// 返回版本对应的能力位图；未知版本返回 0。纯函数、无状态，可并发调用。
/*
 * 获取编码方案能力
 * 返回当前编码方案支持的能力标志位
 */
static inline uint32_t vm_encoding_capabilities(vm_encoding_version_t version) {
    switch (version) {
        case VM_ENCODING_V0:
            return VM_ENC_CAP_OPCODE_PERMUTATION;
        case VM_ENCODING_V1:
            return VM_ENC_CAP_OPCODE_PERMUTATION |
                   VM_ENC_CAP_OPERAND_ENCRYPTION;
        case VM_ENCODING_V2:
            return VM_ENC_CAP_OPCODE_PERMUTATION |
                   VM_ENC_CAP_OPERAND_ENCRYPTION |
                   VM_ENC_CAP_VARIABLE_LENGTH |
                   VM_ENC_CAP_STREAM_CIPHER;
        case VM_ENCODING_V3:
            return VM_ENC_CAP_OPCODE_PERMUTATION |
                   VM_ENC_CAP_OPERAND_ENCRYPTION |
                   VM_ENC_CAP_VARIABLE_LENGTH |
                   VM_ENC_CAP_STREAM_CIPHER |
                   VM_ENC_CAP_CONTEXT_SENSITIVE |
                   VM_ENC_CAP_INSTRUCTION_CHAIN;
        default:
            return 0;
    }
}

// 热路径操作码编码：V0 仅异或；V1+ 先按低/高半字节查表再异或。
// 返回编码后的 8 位操作码；ctx 为 NULL 会解引用，调用方须保证非 NULL。只读 ctx。
/*
 * 快速编码操作码 (内联函数，热路径优化)
 */
static inline uint8_t vm_encoding_encode_opcode_quick(const vm_encoding_ctx_t *ctx,
                                                       uint8_t opcode) {
    /* V0: 简单异或 */
    if (ctx->encoding_version == VM_ENCODING_V0) {
        return opcode ^ (uint8_t)(ctx->opcode_xor_key);
    }
    /* V1+: 置换+异或 */
    uint8_t permuted = (uint8_t)(ctx->permutation_table[opcode & 0x0F] ^
                                  ctx->permutation_table[(opcode >> 4) & 0x0F]);
    return permuted ^ (uint8_t)(ctx->opcode_xor_key);
}

// 热路径操作码解码：V0 用异或自反；V1+ 当前只做异或，没有真正的逆置换表，
// 因此与编码端并非完全互逆（占位实现）。只读 ctx，无失败返回值。
/*
 * 快速解码操作码 (内联函数，热路径优化)
 */
static inline uint8_t vm_encoding_decode_opcode_quick(const vm_encoding_ctx_t *ctx,
                                                       uint8_t encoded) {
    /* V0: 简单异或 (异或的自反性) */
    if (ctx->encoding_version == VM_ENCODING_V0) {
        return encoded ^ (uint8_t)(ctx->opcode_xor_key);
    }
    /* V1+: 异或后反向查表 */
    uint8_t xored = encoded ^ (uint8_t)(ctx->opcode_xor_key);
    /* 查找逆置换 (实际实现需要预计算逆表) */
    return xored; /* 简化实现，实际应查逆表 */
}

// 计算操作数有效字节数（高位零裁剪，0 固定 1 字节）并按版本加密。
// ctx/out_len 为 NULL 时原样返回 operand 且不写 out_len；成功写 *out_len。
// 返回编码值；相同 ctx+输入可复现。只读 ctx，可并发。
/*
 * 编码操作数 (支持变长)
 */
uint64_t vm_encoding_encode_operand(const vm_encoding_ctx_t *ctx,
                                    uint64_t operand,
                                    uint8_t *out_len);

// 将大端字节流还原为整数并做逆变换；data 至少 len 字节，len>8 或指针 NULL 返回 0。
// 失败值 0 与合法值不可区分，调用方须先自行校验长度。只读，可并发。
/*
 * 解码操作数 (支持变长)
 */
uint64_t vm_encoding_decode_operand(const vm_encoding_ctx_t *ctx,
                                    const uint8_t *data,
                                    uint8_t len);

// V3 级联：把 opcode 与操作数折叠值混入 chain_state，并保证结果非零。
// ctx 为 NULL 或版本 < V3 时直接返回；只写 ctx，因顺序敏感必须串行。
/*
 * 更新级联状态 (V3)
 * 每条指令编码后更新，下一条指令依赖此状态
 */
void vm_encoding_update_chain(vm_encoding_ctx_t *ctx,
                              uint32_t opcode,
                              uint64_t operand);

// 以 opcode_xor_key 为初值做滚动校验和，仅检查“非空且结果非零”。
// 没有期望值、没有密钥 MAC，无法发现定向篡改，不得当作认证或 fail-closed 依据。
// 返回 0 通过，-1 参数非法或校验和为 0；只读，可并发。
/*
 * 验证编码完整性
 * 检测编码数据是否被篡改
 */
int vm_encoding_verify_integrity(const vm_encoding_ctx_t *ctx,
                                 const void *encoded_data,
                                 size_t len);

// 原样导出整个上下文（含密钥）；max_len 必须 ≥ sizeof(vm_encoding_ctx_t)。
// 返回写入字节数，失败 0。输出归调用方，必须按敏感数据保护。
// 只读 ctx；与并发写 ctx 竞争时结果不一致。
/*
 * 导出编码上下文 (用于序列化)
 */
size_t vm_encoding_export_ctx(const vm_encoding_ctx_t *ctx,
                              uint8_t *out,
                              size_t max_len);

// 原样导入上下文，不做完整性/版本校验；data 至少 sizeof(vm_encoding_ctx_t) 字节。
// 成功 0，参数非法或长度不足 -1。导入的密钥立即生效，调用方必须信任数据来源。
/*
 * 导入编码上下文 (用于反序列化)
 */
int vm_encoding_import_ctx(vm_encoding_ctx_t *ctx,
                           const uint8_t *data,
                           size_t len);

// 用 secure_zero 清零整个上下文（含密钥）；NULL 安全，可重复调用。
// 之后必须重新 init 才能用于编解码。
/*
 * 安全清除编码上下文
 */
void vm_encoding_clear_ctx(vm_encoding_ctx_t *ctx);

#endif /* VM_ENCODING_H */
