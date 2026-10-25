// 文件职责：实现 VM 函数级上下文——按 func_id 隔离的密钥派生、编码上下文、执行状态机、
// 栈加密/完整性参数与 64 槽上下文池；VMP 进入受保护函数时创建或复用，退出后销毁。
// 现状：对应头文件标注 DEPRECATED（issue 65），当前无生产调用方，仅保留兼容与自检能力。
// 线程模型：ctx 与 pool 内部均无锁，同一 ctx 只允许单线程读写；跨线程共享需调用方加锁。
// 平台：纯 C 实现，不依赖 SVC/PAC/MTE，模拟器与 arm64/arm64e 真机语义一致。
// 失败语义：非法入参、密钥派生或编码初始化失败均返回 -1，状态置 ERROR（fail-closed）。
#include "include/CRiskCore.h"
#include "vm_function_ctx.h"
#include "vm_encoding.h"
#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

#include <string.h>
#include <stdlib.h>

/*
 * ============================================================================
 * VMP函数级VM上下文实现
 * ============================================================================
 *
 * 核心设计:
 * --------
 * 1. 完全隔离: 每个函数拥有独立的密钥、状态、配置
 * 2. 动态派生: 所有敏感数据通过WhiteBox PRF从func_id派生
 * 3. 状态机: 严格的状态转换控制，防止非法操作
 * 4. 审计追踪: 记录执行统计和异常，便于风控分析
 *
 * 安全考虑:
 * --------
 * - 密钥不存储在可读的内存区域，使用后立即清除
 * - 敏感操作有完整性校验
 * - 状态转换需要验证前置条件
 * - 防止重入和竞态条件
 */

/* 内部常量 */
// 上下文魔数 "VMFC"，只用于给 func_hash 加固定扰动，不参与密钥派生，
// 也不能单独作为完整性的证据。
#define VM_FUNC_CTX_MAGIC_INIT 0x564D4643u  /* "VMFC" */
// 默认步数上限 65536：覆盖常规函数规模，同时把死循环/符号执行的单次成本限住；
// CRITICAL 收紧到 32768，关键函数路径更短，异常步数会更早触发。
#define VM_FUNC_MAX_STEPS_DEFAULT 65536u
#define VM_FUNC_MAX_STEPS_CRITICAL 32768u

/*
 * 使用WhiteBox PRF派生函数级密钥
 *
 * 安全原理:
 * - 使用domain 7 (RUNTIME_DERIVE_KEY) 派生
 * - 输入包含函数ID和固定标签，保证唯一性
 * - 输出扩展到64字节，供多个密钥使用
 */
// 从 func_id 派生 64 字节密钥材料（不缓存，调用方负责清零）。
// 输入固定 48 字节：func_id(8) || 标签 "VMFUNC_DERIVE2024"(16) || 全零填充(24)。
// 先用白盒 domain 7 求值；白盒不可用时退化为 SHA256(输入)，安全性降级但保持可用。
// 两轮 SHA256 把 32 字节白盒输出扩展为 64 字节，两半都依赖 whitebox_out，
// 避免 material[0..31] 与 material[32..63] 相互独立可预测。
// 参数：out_material 必须由调用方提供 64 字节可写缓冲区。
// 返回：恒为 0（当前无失败路径）；线程安全：仅使用栈上数据，可重入；平台无关。
static int vm_function_derive_key_material(uint64_t func_id,
                                            uint8_t out_material[64]) {
    uint8_t derive_input[48];

    /* 构建派生输入 */
    memcpy(derive_input, &func_id, sizeof(func_id));

    /* 固定标签: "VMFUNC_DERIVE2024" */
    static const uint8_t label[16] = {
        0x56, 0x4D, 0x46, 0x55, 0x4E, 0x43, 0x5F, 0x44,
        0x45, 0x52, 0x49, 0x56, 0x45, 0x32, 0x30, 0x32
    };
    memcpy(derive_input + 8, label, 16);
    memset(derive_input + 24, 0, 24);

    /* 使用domain 7派生 */
    uint8_t whitebox_out[32];
    if (cprisk_whitebox_evaluate_domain(7u, derive_input, whitebox_out) != 0) {
        cprisk_sha256(derive_input, 48, whitebox_out);
    }

    /* 扩展输出 */
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, whitebox_out, 32);
    cprisk_sha256_update(&ctx, label, 16);
    cprisk_sha256_final(&ctx, out_material);

    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, out_material, 32);
    cprisk_sha256_update(&ctx, whitebox_out, 32);
    cprisk_sha256_final(&ctx, out_material + 32);

    cprisk_secure_zero(whitebox_out, sizeof(whitebox_out));
    return 0;
}

/*
 * 根据保护级别选择编码版本
 *
 * 策略:
 * - NONE: 不使用编码 (直接执行)
 * - BASIC: V0 (简单异或)
 * - STANDARD: V1-V2 (随机选择)
 * - HIGH: V2-V3 (随机选择)
 * - CRITICAL: V3 (强制使用最高级别)
 */
// 按保护级别选择编码版本。
// NONE/BASIC 用 V0；STANDARD 在 V1/V2、HIGH 在 V2/V3 之间二选一；
// CRITICAL 强制 V3。二选一的熵来自 mprotect 交叉校验计数而非随机数，
// 因此同一进程内选择是确定性的，但会随运行时探测结果偏移，增加静态匹配难度。
// 返回：总是合法枚举值；非法 level 回落 V0，不会返回 VM_ENCODING_COUNT。
vm_encoding_version_t vm_function_ctx_select_encoding(vm_protect_level_t level) {
    switch (level) {
        case VM_PROTECT_LEVEL_NONE:
            return VM_ENCODING_V0;

        case VM_PROTECT_LEVEL_BASIC:
            return VM_ENCODING_V0;

        case VM_PROTECT_LEVEL_STANDARD:
            /* 随机选择V1或V2 */
            return (vm_encoding_version_t)(1 + (cprisk_get_vm_mprotect_crosscheck_mismatch_count() % 2));

        case VM_PROTECT_LEVEL_HIGH:
            /* 随机选择V2或V3 */
            return (vm_encoding_version_t)(2 + (cprisk_get_vm_mprotect_mach_trap_mismatch_count() % 2));

        case VM_PROTECT_LEVEL_CRITICAL:
            return VM_ENCODING_V3;

        default:
            return VM_ENCODING_V0;
    }
}

/*
 * 计算函数ID哈希
 */
// 把 func_id 的 SHA256 前 4 字节按大端拼成 32 位，再 XOR 上下文魔数。
// 该值只是上下文自检用的廉价指纹，不是安全哈希，也不泄露密钥材料。
// 返回：任意 func_id 都有确定值；线程安全（纯栈，哈希缓冲用后清零）。
static uint32_t vm_function_hash_id(uint64_t func_id) {
    uint8_t hash[32];
    cprisk_sha256((const uint8_t *)&func_id, sizeof(func_id), hash);
    uint32_t result = ((uint32_t)hash[0] << 24) |
                      ((uint32_t)hash[1] << 16) |
                      ((uint32_t)hash[2] << 8) |
                      (uint32_t)hash[3];
    cprisk_secure_zero(hash, sizeof(hash));
    return result ^ VM_FUNC_CTX_MAGIC_INIT;
}

/*
 * 初始化函数上下文
 *
 * 流程:
 * 1. 清零结构体
 * 2. 设置函数ID和哈希
 * 3. 派生所有密钥参数
 * 4. 初始化编码上下文
 * 5. 根据保护级别初始化额外功能
 */
// 初始化函数上下文：清零 → 写标识/哈希/级别 → 选编码版本 → 派生密钥 →
// 初始化编码上下文 → 设定步数预算 → 按级别启用栈加密/完整性参数。
// 参数：ctx 不可为 NULL；func_id 由编译器分配；level 非法时走 default 分支。
// 返回：0 成功并把 state 置 READY；任一步失败返回 -1 且 state 置 ERROR，
//       调用方不得再进入该上下文（fail-closed）。
// 线程安全：ctx 必须独占；平台无关。失败时 ctx 已被部分写入，
// 调用方应直接丢弃或调用 vm_function_ctx_clear 清理。
int vm_function_ctx_init(vm_function_ctx_t *ctx,
                         uint64_t func_id,
                         vm_protect_level_t level) {
    if (!ctx) {
        return -1;
    }

    /* 清零 */
    memset(ctx, 0, sizeof(*ctx));

    /* 设置标识 */
    ctx->func_id = func_id;
    ctx->func_hash = vm_function_hash_id(func_id);
    ctx->protect_level = level;
    ctx->state = VM_FUNC_CTX_UNINITIALIZED;

    /* 选择编码版本 */
    ctx->encoding_version = (uint32_t)vm_function_ctx_select_encoding(level);

    /* 派生密钥 */
    if (vm_function_ctx_derive_keys(ctx, func_id) != 0) {
        ctx->state = VM_FUNC_CTX_ERROR;
        return -1;
    }

    /* 初始化编码上下文 */
    if (vm_encoding_init(&ctx->encoding, func_id,
                         (vm_encoding_version_t)ctx->encoding_version) != 0) {
        ctx->state = VM_FUNC_CTX_ERROR;
        return -1;
    }

    /* 设置最大步数 */
    switch (level) {
        case VM_PROTECT_LEVEL_NONE:
        case VM_PROTECT_LEVEL_BASIC:
            ctx->max_steps = VM_FUNC_MAX_STEPS_DEFAULT;
            break;
        case VM_PROTECT_LEVEL_STANDARD:
        case VM_PROTECT_LEVEL_HIGH:
            ctx->max_steps = VM_FUNC_MAX_STEPS_DEFAULT;
            break;
        case VM_PROTECT_LEVEL_CRITICAL:
            ctx->max_steps = VM_FUNC_MAX_STEPS_CRITICAL;
            break;
        default:
            ctx->max_steps = VM_FUNC_MAX_STEPS_DEFAULT;
    }

    /* 高级别保护启用栈加密 */
    if (level >= VM_PROTECT_LEVEL_HIGH) {
        ctx->meta_flags |= VM_FUNC_META_NEEDS_STACK_ENC;
        if (vm_function_ctx_init_stack_crypto(ctx) != 0) {
            ctx->state = VM_FUNC_CTX_ERROR;
            return -1;
        }
    }

    /* 关键级别启用完整性校验 */
    if (level >= VM_PROTECT_LEVEL_CRITICAL) {
        ctx->meta_flags |= VM_FUNC_META_NEEDS_INTEGRITY;
        if (vm_function_ctx_init_integrity(ctx) != 0) {
            ctx->state = VM_FUNC_CTX_ERROR;
            return -1;
        }
    }

    ctx->state = VM_FUNC_CTX_READY;
    return 0;
}

/*
 * 从函数ID派生所有密钥参数
 *
 * 派生内容:
 * - opcode_xor_key: 32位操作码异或密钥
 * - operand_salt: 64位操作数加密盐值
 * - dispatch_seed: 64位调度表随机化种子
 * - version_seed: 32位版本校验种子
 * - stack_xor_key: 64位栈异或密钥
 * - stack_rot: 8位栈旋转值
 * - stack_offset: 32位栈偏移值
 */
// 从 64 字节派生材料切分各类密钥，全部为确定性派生，没有静态密钥。
// 字段映射（大端）：material[0..3] opcode_xor_key，[4..11] operand_salt，
// [12..19] dispatch_seed，[20..23] version_seed，[24..31] stack_xor_key，
// [32] stack_rot，[33..36] stack_offset，[40..47] checksum_chain，[48..63] integrity_tag。
// 返回：0 成功（当前仅 ctx 为 NULL 时 -1）；材料用后立即 secure_zero。
// 线程安全：只写 ctx，不共享全局状态。
int vm_function_ctx_derive_keys(vm_function_ctx_t *ctx, uint64_t func_id) {
    if (!ctx) {
        return -1;
    }

    uint8_t material[64];
    if (vm_function_derive_key_material(func_id, material) != 0) {
        return -1;
    }

    /* 提取各个密钥 */
    ctx->opcode_xor_key = ((uint32_t)material[0] << 24) |
                          ((uint32_t)material[1] << 16) |
                          ((uint32_t)material[2] << 8) |
                          (uint32_t)material[3];

    ctx->operand_salt = ((uint64_t)material[4] << 56) |
                        ((uint64_t)material[5] << 48) |
                        ((uint64_t)material[6] << 40) |
                        ((uint64_t)material[7] << 32) |
                        ((uint64_t)material[8] << 24) |
                        ((uint64_t)material[9] << 16) |
                        ((uint64_t)material[10] << 8) |
                        (uint64_t)material[11];

    ctx->dispatch_seed = ((uint64_t)material[12] << 56) |
                         ((uint64_t)material[13] << 48) |
                         ((uint64_t)material[14] << 40) |
                         ((uint64_t)material[15] << 32) |
                         ((uint64_t)material[16] << 24) |
                         ((uint64_t)material[17] << 16) |
                         ((uint64_t)material[18] << 8) |
                         (uint64_t)material[19];

    ctx->version_seed = ((uint32_t)material[20] << 24) |
                        ((uint32_t)material[21] << 16) |
                        ((uint32_t)material[22] << 8) |
                        (uint32_t)material[23];

    ctx->stack_xor_key = ((uint64_t)material[24] << 56) |
                         ((uint64_t)material[25] << 48) |
                         ((uint64_t)material[26] << 40) |
                         ((uint64_t)material[27] << 32) |
                         ((uint64_t)material[28] << 24) |
                         ((uint64_t)material[29] << 16) |
                         ((uint64_t)material[30] << 8) |
                         (uint64_t)material[31];

    // 取模 64 把旋转量约束在 64 位栈值的合法范围内，避免移位量越界。
    ctx->stack_rot = material[32] % 64;  /* 0-63位旋转 */
    ctx->stack_offset = ((uint32_t)material[33] << 24) |
                        ((uint32_t)material[34] << 16) |
                        ((uint32_t)material[35] << 8) |
                        (uint32_t)material[36];

    /* 计算校验和链初始值 */
    ctx->checksum_chain = ((uint64_t)material[40] << 56) |
                          ((uint64_t)material[41] << 48) |
                          ((uint64_t)material[42] << 40) |
                          ((uint64_t)material[43] << 32) |
                          ((uint64_t)material[44] << 24) |
                          ((uint64_t)material[45] << 16) |
                          ((uint64_t)material[46] << 8) |
                          (uint64_t)material[47];

    /* 初始化完整性标签 */
    memcpy(ctx->integrity_tag, material + 48, 16);

    cprisk_secure_zero(material, sizeof(material));
    return 0;
}

/*
 * 设置函数元数据
 */
// 覆盖元数据标志；max_steps 仅在 >0 时生效，0 表示保留初始化时的预算。
// 允许在 READY/EXECUTING 阶段调整，但调用方需自行保证不与执行线程并发。
// 返回：无；ctx 为 NULL 时静默忽略。
void vm_function_ctx_set_metadata(vm_function_ctx_t *ctx,
                                   uint32_t flags,
                                   uint32_t max_steps) {
    if (!ctx) return;

    ctx->meta_flags = flags;
    if (max_steps > 0) {
        ctx->max_steps = max_steps;
    }
}

/*
 * 初始化栈加密参数
 *
 * 栈加密使用三重保护:
 * 1. XOR混淆: 所有栈值与stack_xor_key异或
 * 2. 旋转: 值在写入前旋转stack_rot位
 * 3. 偏移: 逻辑栈位置与实际位置通过stack_offset映射
 */
// 校验并补齐栈加密参数：密钥为 0 时填入固定兜底值，旋转量为 0 时用 17。
// 兜底值只保证算法可运行，不提供真正的随机性；正常路径由 derive_keys 提供非零参数。
// 返回：0 成功；ctx 为 NULL 返回 -1。线程安全：仅写 ctx。
int vm_function_ctx_init_stack_crypto(vm_function_ctx_t *ctx) {
    if (!ctx) return -1;

    /* 密钥已在derive_keys中设置，这里验证有效性 */
    if (ctx->stack_xor_key == 0) {
        ctx->stack_xor_key = 0xA5A5A5A5A5A5A5A5ULL;
    }
    if (ctx->stack_rot == 0) {
        ctx->stack_rot = 17;  /* 默认旋转17位 */
    }

    return 0;
}

/*
 * 初始化完整性校验参数
 */
// 校验完整性参数：version_seed 为 0 时用 32 位黄金比例常量 0x9E3779B9 兜底，
// 保证后续校验链不会因全零种子退化。
// 返回：0 成功；ctx 为 NULL 返回 -1。线程安全：仅写 ctx。
int vm_function_ctx_init_integrity(vm_function_ctx_t *ctx) {
    if (!ctx) return -1;

    /* 设置完整性检查需要的初始值 */
    if (ctx->version_seed == 0) {
        ctx->version_seed = 0x9E3779B9u;
    }

    return 0;
}

/*
 * 进入函数执行状态
 *
 * 状态转换: READY -> EXECUTING
 * 或: SUSPENDED -> EXECUTING
 */
// 进入执行态：只有 READY 或 SUSPENDED 才能进入，其他状态一律拒绝。
// 进入时执行次数 +1，步数与异常标志清零，保证每次执行独立计预算。
// 返回：0 成功；NULL 或非法状态返回 -1，调用方应放弃执行。
// 线程安全：修改 state/step_count，必须与同一 ctx 的其他操作串行。
int vm_function_ctx_enter(vm_function_ctx_t *ctx) {
    if (!ctx) return -1;

    if (ctx->state != VM_FUNC_CTX_READY &&
        ctx->state != VM_FUNC_CTX_SUSPENDED) {
        return -1;
    }

    ctx->state = VM_FUNC_CTX_EXECUTING;
    ctx->execution_count++;
    ctx->step_count = 0;
    ctx->anomaly_flags = 0;

    return 0;
}

/*
 * 退出函数执行状态
 *
 * 状态转换: EXECUTING -> COMPLETED
 */
// 退出执行态：仅 EXECUTING → COMPLETED，其他状态返回 -1。
// last_execution_time 目前只记录执行次数（简化实现），不是真实时间戳。
int vm_function_ctx_exit(vm_function_ctx_t *ctx) {
    if (!ctx) return -1;

    if (ctx->state != VM_FUNC_CTX_EXECUTING) {
        return -1;
    }

    ctx->state = VM_FUNC_CTX_COMPLETED;

    /* 更新最后执行时间戳 (简化实现) */
    ctx->last_execution_time = ctx->execution_count;

    return 0;
}

/*
 * 挂起函数执行
 *
 * 状态转换: EXECUTING -> SUSPENDED
 */
// 挂起执行：仅 EXECUTING → SUSPENDED，用于 yield/中断；其他状态返回 -1。
// 不改变步数预算与执行计数，恢复后继续累计。
int vm_function_ctx_suspend(vm_function_ctx_t *ctx) {
    if (!ctx) return -1;

    if (ctx->state != VM_FUNC_CTX_EXECUTING) {
        return -1;
    }

    ctx->state = VM_FUNC_CTX_SUSPENDED;
    return 0;
}

/*
 * 恢复函数执行
 *
 * 状态转换: SUSPENDED -> EXECUTING
 */
// 恢复执行：仅 SUSPENDED → EXECUTING；其他状态返回 -1。
// 恢复不会重置 step_count，因此挂起前消耗的预算仍然有效。
int vm_function_ctx_resume(vm_function_ctx_t *ctx) {
    if (!ctx) return -1;

    if (ctx->state != VM_FUNC_CTX_SUSPENDED) {
        return -1;
    }

    ctx->state = VM_FUNC_CTX_EXECUTING;
    return 0;
}

/*
 * 获取函数编码上下文
 */
// 返回内部编码上下文指针，借用语义，调用方不得释放。
// 返回：ctx 为 NULL 时 NULL；否则指针在 ctx 生命周期内有效。
// 线程安全：只读；与写 encoding 的并发调用仍需外部同步。
const vm_encoding_ctx_t *vm_function_ctx_get_encoding(const vm_function_ctx_t *ctx) {
    if (!ctx) return NULL;
    return &ctx->encoding;
}

/*
 * 编码函数的字节码
 *
 * 使用函数专属的编码方案对整个函数的字节码进行编码
 */
// 用函数专属编码方案把原始字节码整体编码为自描述缓冲。
// 输出布局：func_id(8, 原生字节序) || encoding_version(1) || protect_level(1) || 指令流。
// 原始输入约定：每条指令固定 9 字节 = opcode(1) + operand(8, 小端)。
// 参数：raw_bytecode/out_encoded/out_len 均不可为 NULL，raw_len 必须 >0；
//       成功时 *out_encoded 由 malloc 分配，所有权转移给调用方（free 释放）。
// 返回：0 成功；参数非法、编码失败或缓冲不足返回 -1，且不写出指针/长度。
// 注意：编码器不调用 vm_encoding_update_chain，V3 的 chain_state 全程不变，
//       因此当前并未真正形成指令级联；线程安全：只读 ctx。
int vm_function_ctx_encode_bytecode(vm_function_ctx_t *ctx,
                                    const uint8_t *raw_bytecode,
                                    size_t raw_len,
                                    uint8_t **out_encoded,
                                    size_t *out_len) {
    if (!ctx || !raw_bytecode || raw_len == 0 || !out_encoded || !out_len) {
        return -1;
    }

    /* 分配输出缓冲区 (估算大小，变长编码可能更小) */
    // 每条 9 字节指令最多编码成 10 字节，2 倍上界足够；
    // 下面的 pos + total_len 检查仍会兜底，防止编码器将来变长。
    size_t max_encoded = raw_len * 2;
    uint8_t *encoded = (uint8_t *)malloc(max_encoded);
    if (!encoded) {
        return -1;
    }

    size_t pos = 0;
    size_t raw_pos = 0;

    /* 编码头部: 函数ID + 编码版本 */
    memcpy(encoded + pos, &ctx->func_id, sizeof(ctx->func_id));
    pos += sizeof(ctx->func_id);

    encoded[pos++] = (uint8_t)ctx->encoding_version;
    encoded[pos++] = (uint8_t)ctx->protect_level;

    /* 逐指令编码 */
    // 不足 9 字节的尾部残片会被静默丢弃，调用方需保证输入按 9 字节对齐。
    while (raw_pos + 9 <= raw_len) {  /* 最小指令9字节 */
        uint32_t opcode = raw_bytecode[raw_pos];
        uint64_t operand = 0;

        // 原始操作数按小端读入，编码输出统一大端，两侧字节序不可混淆。
        /* 读取操作数 (小端序) */
        for (int i = 0; i < 8; i++) {
            operand |= ((uint64_t)raw_bytecode[raw_pos + 1 + i]) << (i * 8);
        }

        /* 编码指令 */
        vm_encoded_insn_t enc_insn;
        if (vm_encoding_encode_insn(&ctx->encoding, opcode, operand, &enc_insn) != 0) {
            free(encoded);
            return -1;
        }

        /* 写入编码后的指令 */
        if (pos + enc_insn.total_len > max_encoded) {
            free(encoded);
            return -1;
        }

        memcpy(encoded + pos, enc_insn.raw_bytes, enc_insn.total_len);
        pos += enc_insn.total_len;

        raw_pos += 9;  /* 原始指令固定9字节 */
    }

    *out_encoded = encoded;
    *out_len = pos;

    return 0;
}

/*
 * 解码函数的字节码 (单条指令)
 */
// 解码单条指令：pc 是编码缓冲内的字节偏移，必须已跳过 8 字节 func_id 与 2 字节头。
// 参数：ctx/encoded_bytecode/opcode_out/operand_out 不可为 NULL；
//       pc ∈ [10, encoded_len)；调用方必须保证从 pc 起至少有 9 字节完整指令。
// 返回：0 成功；NULL、pc 越界或底层解码失败返回 -1。
// 注意：当前实现最多复制 16 字节并把 total_len 设为 min(剩余,16)；
//       剩余不足 9 字节时尾部用零填充，V0/V1 会解出垃圾值而不是报错。
int vm_function_ctx_decode_bytecode(vm_function_ctx_t *ctx,
                                    const uint8_t *encoded_bytecode,
                                    size_t encoded_len,
                                    uint32_t pc,
                                    uint32_t *opcode_out,
                                    uint64_t *operand_out) {
    if (!ctx || !encoded_bytecode || !opcode_out || !operand_out) {
        return -1;
    }

    // 头部长度由 func_id 的宽度 + version/protect_level 两个字节组成，
    // 这里用 sizeof(ctx->func_id) 而不是写死 8，避免结构体变化后静默错位。
    /* 跳过头部 */
    size_t header_len = sizeof(ctx->func_id) + 2;
    if (pc < header_len || pc >= encoded_len) {
        return -1;
    }

    /* 构建编码指令结构 */
    vm_encoded_insn_t enc_insn;
    memset(&enc_insn, 0, sizeof(enc_insn));

    /* 读取变长指令 (简化实现，实际需要解析变长编码) */
    size_t max_insn_len = (encoded_len - pc < 16) ? (encoded_len - pc) : 16;
    memcpy(enc_insn.raw_bytes, encoded_bytecode + pc, max_insn_len);
    enc_insn.total_len = (uint8_t)max_insn_len;
    enc_insn.original_pc = pc;

    /* 解码 */
    return vm_encoding_decode_insn(&ctx->encoding, &enc_insn, opcode_out, operand_out);
}

/*
 * 验证函数上下文完整性
 */
// 上下文自检：状态枚举范围、func_hash 是否与 func_id 重新计算一致、编码版本是否越界。
// 这是防误用/防轻微内存破坏的廉价检查，不是密码学校验；
// 同时篡改 func_id 与 func_hash 的攻击无法被它发现。
// 返回：0 通过；NULL 或任一检查失败返回 -1。
int vm_function_ctx_verify_integrity(const vm_function_ctx_t *ctx) {
    if (!ctx) return -1;

    /* 验证状态合法性 */
    if (ctx->state < VM_FUNC_CTX_UNINITIALIZED ||
        ctx->state > VM_FUNC_CTX_ERROR) {
        return -1;
    }

    /* 验证函数哈希 */
    uint32_t expected_hash = vm_function_hash_id(ctx->func_id);
    if (ctx->func_hash != expected_hash) {
        return -1;
    }

    /* 验证编码版本 */
    if (ctx->encoding_version >= VM_ENCODING_COUNT) {
        return -1;
    }

    return 0;
}

/*
 * 复制函数上下文
 */
// 浅拷贝整个上下文，再为 bytecode_cache 做字节级深拷贝（不解释内容）。
// 参数：dst/src 非 NULL；dst 不能与 src 相同，且 dst 原有 bytecode_cache
//       必须先 clear，否则会被覆盖泄漏。
// 返回：0 成功；参数非法或深拷贝分配失败返回 -1。
// 失败时 dst 已被部分写入，调用方应调用 vm_function_ctx_clear 丢弃，不能继续使用。
// 线程安全：读 src/写 dst，需保证 src 不被并发修改。
int vm_function_ctx_copy(vm_function_ctx_t *dst, const vm_function_ctx_t *src) {
    if (!dst || !src) return -1;

    memcpy(dst, src, sizeof(vm_function_ctx_t));

    /* 深拷贝动态分配的内存 */
    if (src->bytecode_cache && src->bytecode_size > 0) {
        dst->bytecode_cache = malloc(src->bytecode_size);
        if (!dst->bytecode_cache) {
            return -1;
        }
        memcpy(dst->bytecode_cache, src->bytecode_cache, src->bytecode_size);
    }

    return 0;
}

/*
 * 安全清除函数上下文
 */
// 释放并清零 bytecode_cache，再把整个上下文 secure_zero；可重复调用。
// 不释放 ctx 本身（栈/池内对象），也不改动池的空闲位图。
void vm_function_ctx_clear(vm_function_ctx_t *ctx) {
    if (!ctx) return;

    /* 清除动态分配的内存 */
    if (ctx->bytecode_cache) {
        cprisk_secure_zero(ctx->bytecode_cache, ctx->bytecode_size);
        free(ctx->bytecode_cache);
        ctx->bytecode_cache = NULL;
    }

    /* 清除敏感数据 */
    cprisk_secure_zero(ctx, sizeof(*ctx));
}

/* ==================== 上下文池管理实现 ==================== */

/*
 * 初始化上下文池
 */
// 池初始化：清零所有槽与位图，active_count=0。
// 线程模型：池本身不加锁，所有 pool_* 操作必须由调用方串行化。
void vm_function_ctx_pool_init(vm_function_ctx_pool_t *pool) {
    if (!pool) return;

    memset(pool, 0, sizeof(*pool));
    pool->active_count = 0;
}

/*
 * 从池中分配上下文
 */
// 在位图中线性查找第一个空闲槽，置位并 active_count+1，返回前清零该槽。
// 返回：成功返回池内地址（借用，不可 free）；池满或 pool 为 NULL 返回 NULL。
// 不变量：位图第 i 位为 1 ⇔ contexts[i] 已分配；active_count 等于置位数量。
vm_function_ctx_t *vm_function_ctx_pool_alloc(vm_function_ctx_pool_t *pool) {
    if (!pool || pool->active_count >= VM_FUNC_CTX_POOL_SIZE) {
        return NULL;
    }

    /* 查找空闲槽位 */
    for (int i = 0; i < VM_FUNC_CTX_POOL_SIZE; i++) {
        uint32_t word_idx = i / 32;
        uint32_t bit_idx = i % 32;

        if ((pool->used_bitmap[word_idx] & (1u << bit_idx)) == 0) {
            /* 找到空闲槽 */
            pool->used_bitmap[word_idx] |= (1u << bit_idx);
            pool->active_count++;

            vm_function_ctx_t *ctx = &pool->contexts[i];
            memset(ctx, 0, sizeof(*ctx));
            return ctx;
        }
    }

    return NULL;
}

/*
 * 释放上下文回池
 */
// 归还池槽：ctx 必须指向 pool->contexts 数组内部，否则指针差值无意义、直接忽略。
// 先 clear 敏感数据，再清位图位并 active_count-1。
// 注意：对同一槽重复归还会再次递减 active_count，造成计数下溢；
//       调用方必须保证每个槽只归还一次。
void vm_function_ctx_pool_free(vm_function_ctx_pool_t *pool,
                               vm_function_ctx_t *ctx) {
    if (!pool || !ctx) return;

    /* 计算索引 */
    int idx = (int)(ctx - pool->contexts);
    if (idx < 0 || idx >= VM_FUNC_CTX_POOL_SIZE) {
        return;
    }

    /* 清除敏感数据 */
    vm_function_ctx_clear(ctx);

    /* 标记为空闲 */
    uint32_t word_idx = (uint32_t)idx / 32u;
    uint32_t bit_idx = (uint32_t)idx % 32u;
    pool->used_bitmap[word_idx] &= ~(1u << bit_idx);
    pool->active_count--;
}

/*
 * 查找函数的上下文
 */
// 按 func_id 线性扫描已分配槽，返回第一个匹配项或 NULL。
// 复杂度 O(64)，适合小池；不比较 protect_level 或编码版本。
vm_function_ctx_t *vm_function_ctx_pool_find(vm_function_ctx_pool_t *pool,
                                              uint64_t func_id) {
    if (!pool) return NULL;

    for (int i = 0; i < VM_FUNC_CTX_POOL_SIZE; i++) {
        uint32_t word_idx = (uint32_t)i / 32u;
        uint32_t bit_idx = (uint32_t)i % 32u;

        if (pool->used_bitmap[word_idx] & (1u << bit_idx)) {
            if (pool->contexts[i].func_id == func_id) {
                return &pool->contexts[i];
            }
        }
    }

    return NULL;
}

/*
 * 获取或创建函数上下文
 */
// 先查后建：已存在则直接复用（忽略传入的 level）；否则分配新槽并 init。
// 返回：成功返回池内上下文；池满、init 失败或 pool 为 NULL 返回 NULL。
// init 失败会立即归还槽，避免位图泄漏。
vm_function_ctx_t *vm_function_ctx_pool_get_or_create(vm_function_ctx_pool_t *pool,
                                                       uint64_t func_id,
                                                       vm_protect_level_t level) {
    if (!pool) return NULL;

    /* 先查找 */
    vm_function_ctx_t *ctx = vm_function_ctx_pool_find(pool, func_id);
    if (ctx) {
        return ctx;
    }

    /* 创建新的 */
    ctx = vm_function_ctx_pool_alloc(pool);
    if (!ctx) {
        return NULL;
    }

    if (vm_function_ctx_init(ctx, func_id, level) != 0) {
        vm_function_ctx_pool_free(pool, ctx);
        return NULL;
    }

    return ctx;
}

/*
 * 清理池中的所有上下文
 */
// 遍历已分配槽逐一 clear，最后把整个池清零（位图与 active_count 一并复位）。
void vm_function_ctx_pool_clear(vm_function_ctx_pool_t *pool) {
    if (!pool) return;

    for (int i = 0; i < VM_FUNC_CTX_POOL_SIZE; i++) {
        uint32_t word_idx = (uint32_t)i / 32u;
        uint32_t bit_idx = (uint32_t)i % 32u;

        if (pool->used_bitmap[word_idx] & (1u << bit_idx)) {
            vm_function_ctx_clear(&pool->contexts[i]);
        }
    }

    memset(pool, 0, sizeof(*pool));
}
