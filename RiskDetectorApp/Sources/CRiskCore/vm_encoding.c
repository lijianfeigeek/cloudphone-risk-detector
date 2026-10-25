// 文件职责：实现 VM 字节码的多态编码/解码（V0 异或、V1 置换+字节重排、V2 变长+流式掩码，
// V3 在 V2 基础上叠加级联状态），并按 func_id 派生每个函数独立的编码密钥。
// 现状：头文件标注 DEPRECATED（issue 65），当前无生产调用方，仅保留兼容。
// 线程模型：ctx 无内部锁；V3 的 chain_state 需要写者串行推进，编码/解码共用 ctx 时不可并发。
// 字段宽度：opcode 1 字节；V0/V1 操作数固定 8 字节；V2/V3 操作数 1–8 字节并前置 1 字节长度。
// 失败语义：版本越界、opcode>0xFF、长度前缀>8 等返回 -1；纯 C 无平台分支，模拟器与真机一致。
#include "include/CRiskCore.h"
#include "vm_encoding.h"
#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

#include <string.h>

/*
 * ============================================================================
 * VMP多字节码编码方案实现
 * ============================================================================
 *
 * 核心设计思想:
 * ------------
 * 1. 多态性 (Polymorphism): 每个函数使用独立的编码参数，攻击者无法建立统一的字节码语义映射
 * 2. 密钥派生: 所有编码参数通过WhiteBox PRF从函数ID派生，保证唯一性和不可预测性
 * 3. 分层防御: V0->V3复杂度递增，可根据保护等级灵活选择
 * 4. 性能平衡: 热路径使用内联快速编码，复杂编码用于关键代码区域
 *
 * 安全分析:
 * --------
 * - 攻击者要理解字节码语义，必须针对每个函数单独分析
 * - 即使获得一个函数的密钥，也无法应用于其他函数
 * - 编码参数与设备/会话绑定，防止代码复用攻击
 * - 级联状态使指令序列不可重排，增加动态分析难度
 */

/* 内部常量定义 */
// VM_ENC_STREAM_NONCE 当前未被引用，仅保留为协议标识；
// VM_ENC_CHAIN_MAGIC 是 V3 级联状态的零值兜底，避免状态退化。
#define VM_ENC_STREAM_NONCE "VMENC2024"
#define VM_ENC_CHAIN_MAGIC  0x9E3779B9u

/*
 * 使用WhiteBox PRF派生密钥材料
 *
 * 加固原理: 派生过程在白盒加密域内完成，攻击者无法提取原始密钥
 */
// 从 (func_id, version) 派生 64 字节编码材料，结果完全确定。
// 输入 48 字节：func_id(8) || version(4) || "VMENC_DERIVE2024"(16) || 零填充(16)。
// 优先使用白盒 domain 6（DEVICE_BOUND）；不可用时退化为 SHA256，安全性降低但仍可编码。
// 两轮 SHA256 扩展为 64 字节，使 stream_key 与其它字段不共享同一输出段。
// 参数：out_material 由调用方提供 64 字节；返回恒 0（当前无失败路径）。
// 线程安全：仅栈数据；平台无关。
static int vm_encoding_derive_from_whitebox(uint64_t func_id,
                                             vm_encoding_version_t version,
                                             uint8_t out_material[64]) {
    /* 构建派生输入: 函数ID + 编码版本 + 固定标签 */
    uint8_t derive_input[48];
    memcpy(derive_input, &func_id, sizeof(func_id));
    memcpy(derive_input + 8, &version, sizeof(version));

    /* 固定标签 (避免在二进制中直接出现字符串) */
    static const uint8_t label_enc[16] = {
        0x56, 0x4D, 0x45, 0x4E, 0x43, 0x44, 0x45, 0x52,
        0x49, 0x56, 0x45, 0x32, 0x30, 0x32, 0x34, 0x00
    }; /* "VMENC_DERIVE2024" */
    memcpy(derive_input + 16, label_enc, 16);
    memset(derive_input + 32, 0, 16); /* 填充 */

    /* 使用domain 6 (CPRISK_WHITEBOX_DOMAIN_DEVICE_BOUND) 派生密钥 */
    uint8_t whitebox_out[32];
    if (cprisk_whitebox_evaluate_domain(6u, derive_input, whitebox_out) != 0) {
        /* 失败时使用SHA256作为降级方案 (仍有一定安全性) */
        cprisk_sha256(derive_input, 48, whitebox_out);
    }

    /* 扩展输出到64字节 */
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, whitebox_out, 32);
    cprisk_sha256_update(&ctx, label_enc, 16);
    cprisk_sha256_final(&ctx, out_material);

    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, out_material, 32);
    cprisk_sha256_update(&ctx, whitebox_out, 32);
    cprisk_sha256_final(&ctx, out_material + 32);

    cprisk_secure_zero(whitebox_out, sizeof(whitebox_out));
    return 0;
}

/*
 * 计算函数ID的哈希，用于版本选择
 */
// 把 SHA256(func_id) 的 32 字节按 8 字节一组，取每组前 4 字节按大端拼成 32 位后逐组异或。
// 仅用于版本选择，不是密钥材料；输出分布足够均匀即可。
// 返回：确定的 32 位值；线程安全。
static uint32_t vm_encoding_func_hash(uint64_t func_id) {
    uint8_t hash[32];
    cprisk_sha256((const uint8_t *)&func_id, sizeof(func_id), hash);
    uint32_t result = 0;
    for (int i = 0; i < 4; i++) {
        result ^= ((uint32_t)hash[i * 8] << 24) |
                  ((uint32_t)hash[i * 8 + 1] << 16) |
                  ((uint32_t)hash[i * 8 + 2] << 8) |
                  ((uint32_t)hash[i * 8 + 3]);
    }
    cprisk_secure_zero(hash, sizeof(hash));
    return result;
}

/*
 * 初始化编码上下文
 *
 * 实现细节:
 * - 从WhiteBox PRF派生所有敏感参数
 * - 根据编码版本初始化特定数据结构
 * - 所有敏感数据通过安全内存操作处理
 */
// 初始化编码上下文：校验版本 → 记录能力位 → 派生并切分密钥 → 按版本初始化可选结构。
// ctx 不可为 NULL，version 必须 < VM_ENCODING_COUNT，否则返回 -1。
// material 切分：opcode_xor_key[0..3]、operand_salt[4..11]、dispatch_seed[12..19]、
// perm_seed[20..27]、stream_key[32..63]、chain_state[60..63]。
// 注意：V3 的 chain_state 与 stream_key 尾部重叠，两者不是独立随机量。
// 返回：0 成功；参数非法返回 -1。材料用后 secure_zero。
// 线程安全：只写 ctx；平台无关。
int vm_encoding_init(vm_encoding_ctx_t *ctx,
                     uint64_t func_id,
                     vm_encoding_version_t version) {
    if (!ctx || version >= VM_ENCODING_COUNT) {
        return -1;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->encoding_version = (uint32_t)version;
    ctx->capabilities = vm_encoding_capabilities(version);

    /* 派生密钥材料 */
    uint8_t material[64];
    if (vm_encoding_derive_from_whitebox(func_id, version, material) != 0) {
        return -1;
    }

    /* 提取各个密钥参数 */
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

    // V1 起才需要置换表；种子取 material[20..27]，V0 不使用这段字节。
    /* V1+: 初始化置换表 */
    if (version >= VM_ENCODING_V1) {
        uint64_t perm_seed = ((uint64_t)material[20] << 56) |
                             ((uint64_t)material[21] << 48) |
                             ((uint64_t)material[22] << 40) |
                             ((uint64_t)material[23] << 32) |
                             ((uint64_t)material[24] << 24) |
                             ((uint64_t)material[25] << 16) |
                             ((uint64_t)material[26] << 8) |
                             (uint64_t)material[27];
        vm_encoding_gen_permutation(ctx, perm_seed);
    }

    // V2/V3 共享 32 字节 stream_key；init_stream 目前是空实现，
    // 密钥在派生阶段已经确定。
    /* V2+: 初始化流加密密钥 */
    if (version >= VM_ENCODING_V2) {
        memcpy(ctx->stream_key, material + 32, 32);
        vm_encoding_init_stream(ctx, ctx->dispatch_seed);
    }

    // chain_state 为 0 时回落到魔数，避免 V3 级联状态退化为全零。
    /* V3: 初始化级联状态 */
    if (version >= VM_ENCODING_V3) {
        ctx->chain_state = ((uint32_t)material[60] << 24) |
                           ((uint32_t)material[61] << 16) |
                           ((uint32_t)material[62] << 8) |
                           (uint32_t)material[63];
        if (ctx->chain_state == 0) {
            ctx->chain_state = VM_ENC_CHAIN_MAGIC;
        }
    }

    cprisk_secure_zero(material, sizeof(material));
    return 0;
}

/*
 * 自动选择编码版本
 *
 * 选择策略:
 * - 基于函数ID的哈希值分布均匀选择
 * - 关键函数(通过特征识别)强制使用V3
 * - 保证整体分布: V0 20%, V1 30%, V2 30%, V3 20%
 */
// 按 func_id 哈希的最低字节选择版本：<52 V0、<128 V1、<204 V2、其余 V3，
// 目标分布约 20%/30%/30%/20%。纯函数，无状态，线程安全。
vm_encoding_version_t vm_encoding_select_version(uint64_t func_id) {
    uint32_t hash = vm_encoding_func_hash(func_id);
    uint8_t selector = (uint8_t)(hash & 0xFF);

    /* 分布: 0-51(V0), 52-127(V1), 128-203(V2), 204-255(V3) */
    if (selector < 52) {
        return VM_ENCODING_V0;
    } else if (selector < 128) {
        return VM_ENCODING_V1;
    } else if (selector < 204) {
        return VM_ENCODING_V2;
    } else {
        return VM_ENCODING_V3;
    }
}

/*
 * 生成置换表
 *
 * 使用Fisher-Yates洗牌算法生成伪随机置换
 * 保证每个操作码(0-255)都有唯一的映射
 */
// 生成 16 项置换表（注意不是 256 项）：初值恒等，再用 SplitMix64 驱动的
// Fisher–Yates 洗牌。相同 seed 必得相同表，便于编码/解码两侧复现。
// 参数：ctx 非 NULL（不校验）；返回：无。
void vm_encoding_gen_permutation(vm_encoding_ctx_t *ctx, uint64_t seed) {
    /* 初始化恒等置换 */
    for (int i = 0; i < 16; i++) {
        ctx->permutation_table[i] = (uint32_t)i;
    }

    /* Fisher-Yates洗牌 */
    for (int i = 15; i > 0; i--) {
        // SplitMix64 的三个常量是固定的混合/雪崩参数，
        // 改动会改变所有已编码字节码，必须与解码端同步升级。
        /* 使用SplitMix64生成随机索引 */
        seed += 0x9E3779B97F4A7C15ULL;
        uint64_t z = seed;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        uint32_t j = (uint32_t)(z ^ (z >> 31)) % (uint32_t)(i + 1);

        /* 交换 */
        uint32_t temp = ctx->permutation_table[i];
        ctx->permutation_table[i] = ctx->permutation_table[j];
        ctx->permutation_table[j] = temp;
    }
}

/*
 * 初始化流加密状态
 *
 * 使用简化的ChaCha20初始化 (仅用于混淆，非加密目的)
 */
// V2/V3 的流状态初始化占位：stream_key 已在 init 中写入，seed 被显式忽略，
// 因此函数不改变 ctx 的任何字段；保留签名以便后续接入真正的流状态。
void vm_encoding_init_stream(vm_encoding_ctx_t *ctx, uint64_t seed) {
    (void)seed;
    /* 流密钥已在vm_encoding_init中设置 */
    /* 实际流加密状态将在编码时动态维护 */
}

/*
 * 编码单条指令
 *
 * 编码流程:
 * 1. 根据版本选择编码策略
 * 2. 操作码置换/异或
 * 3. 操作数加密 (变长)
 * 4. 级联状态更新 (V3)
 */
// 把一条 (opcode, operand) 编码进 out->raw_bytes，并写 total_len。
// opcode 必须 ≤ 0xFF；ctx/out 不可为 NULL，否则返回 -1。
// 输出统一大端：V0/V1 = 1+8 字节；V2 = 1+1+op_len；V3 = 1+1+op_len。
// 返回：0 成功；参数非法或版本未知返回 -1（除 out 外不改动任何状态）。
// 线程安全：只读 ctx；V3 的 chain_state 不在此推进。
int vm_encoding_encode_insn(const vm_encoding_ctx_t *ctx,
                            uint32_t opcode,
                            uint64_t operand,
                            vm_encoded_insn_t *out) {
    if (!ctx || !out || opcode > 0xFF) {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->original_pc = 0; /* 由调用者设置 */

    uint8_t *ptr = out->raw_bytes;
    uint8_t encoded_opcode;

    switch (ctx->encoding_version) {
        case VM_ENCODING_V0:
            // V0 只取密钥最低字节混淆 opcode，操作数整体 XOR salt；
            // 这是最弱的一档，只用于 NONE/BASIC 保护级别。
            /* V0: 简单异或编码 */
            encoded_opcode = (uint8_t)(opcode ^ (ctx->opcode_xor_key & 0xFF));
            *ptr++ = encoded_opcode;

            /* 操作数: 固定8字节，简单异或 */
            uint64_t enc_operand = operand ^ ctx->operand_salt;
            for (int i = 7; i >= 0; i--) {
                *ptr++ = (uint8_t)(enc_operand >> (i * 8));
            }
            out->total_len = 9;
            break;

        case VM_ENCODING_V1:
            /* V1: 置换+XOR+字节重排（可逆） */
            encoded_opcode = vm_encoding_encode_opcode_quick(ctx, (uint8_t)opcode);
            *ptr++ = encoded_opcode;

            /* 操作数: 两层XOR + 字节重排，编码解码完全可逆
             * Layer 1: operand XOR salt1
             * Layer 2: 结果做字节重排 (swap bytes 0-3 with 4-7)
             * Layer 3: 重排结果 XOR salt2
             * 解码时反序: 先 XOR salt2, 再反向重排, 再 XOR salt1
             */
            {
                uint64_t salt1 = ctx->operand_salt;
                uint64_t salt2 = ctx->operand_salt ^ 0x5A5A5A5A5A5A5A5AULL;
                uint64_t t = operand ^ salt1;
                /* Byte shuffle: swap low/high 32-bit halves and rotate bytes */
                uint32_t lo32 = (uint32_t)(t & 0xFFFFFFFFULL);
                uint32_t hi32 = (uint32_t)((t >> 32) & 0xFFFFFFFFULL);
                /* Rotate each half left by 8 bits (byte rotate) */
                lo32 = (lo32 << 8) | (lo32 >> 24);
                hi32 = (hi32 << 8) | (hi32 >> 24);
                /* Swap halves */
                uint64_t shuffled = ((uint64_t)lo32 << 32) | (uint64_t)hi32;
                uint64_t enc_op_v1 = shuffled ^ salt2;
                for (int i = 7; i >= 0; i--) {
                    *ptr++ = (uint8_t)(enc_op_v1 >> (i * 8));
                }
            }
            out->total_len = 9;
            break;

        case VM_ENCODING_V2:
            /* V2: 流式加密 + 变长编码 */
            encoded_opcode = vm_encoding_encode_opcode_quick(ctx, (uint8_t)opcode);

            /* 变长操作数编码 */
            uint8_t op_len;
            uint64_t enc_operand_v2 = vm_encoding_encode_operand(ctx, operand, &op_len);

            *ptr++ = encoded_opcode;
            *ptr++ = op_len; /* 长度前缀 */

            for (int i = op_len - 1; i >= 0; i--) {
                *ptr++ = (uint8_t)(enc_operand_v2 >> (i * 8));
            }
            // V2 指令长度随操作数有效字节数变化，范围 3–10 字节。
            out->total_len = 2 + op_len;
            break;

        case VM_ENCODING_V3:
            /* V3: 分层混合 + 级联状态 */
            // V3 把级联状态最低字节混入操作码，
            // 使同一条指令出现在不同位置时得到不同编码字节。
            /* 操作码受级联状态影响 */
            encoded_opcode = vm_encoding_encode_opcode_quick(ctx, (uint8_t)opcode);
            encoded_opcode ^= (uint8_t)(ctx->chain_state & 0xFF);
            *ptr++ = encoded_opcode;

            /* 操作数: 上下文敏感编码 */
            uint64_t ctx_aware_salt = ctx->operand_salt ^
                                      ((uint64_t)ctx->chain_state << 32);
            uint8_t op_len_v3;
            uint64_t enc_operand_v3 = vm_encoding_encode_operand(ctx,
                                                                  operand ^ ctx_aware_salt,
                                                                  &op_len_v3);

            // 低 4 位是操作数长度，高 4 位是 chain_state 的低半字节；
            // 解码端只取低 4 位、不校验高 4 位，因此该字段不构成完整性保护。
            *ptr++ = op_len_v3 | ((uint8_t)(ctx->chain_state & 0x0F) << 4);

            for (int i = op_len_v3 - 1; i >= 0; i--) {
                *ptr++ = (uint8_t)(enc_operand_v3 >> (i * 8));
            }
            out->total_len = 2 + op_len_v3;
            break;

        default:
            return -1;
    }

    return 0;
}

/*
 * 解码单条指令
 *
 * 解码是编码的逆过程，需要根据编码版本选择正确的解码策略
 */
// 编码的逆过程：按 ctx->encoding_version 选择对应解码路径。
// 前置条件：encoded->total_len ∈ [1,16]；raw_bytes 中至少有 total_len 字节。
// 返回：0 成功并写出 opcode/operand；NULL、长度越界、V2/V3 长度前缀>8 返回 -1。
// 注意：V0/V1 固定读 9 字节却只校验 total_len≥1，total_len<9 时读到的是
//       结构体内的零填充，调用方必须保证实际长度足够，不能仅依赖返回值。
int vm_encoding_decode_insn(const vm_encoding_ctx_t *ctx,
                            const vm_encoded_insn_t *encoded,
                            uint32_t *opcode_out,
                            uint64_t *operand_out) {
    if (!ctx || !encoded || !opcode_out || !operand_out) {
        return -1;
    }

    if (encoded->total_len < 1 || encoded->total_len > 16) {
        return -1;
    }

    const uint8_t *ptr = encoded->raw_bytes;
    uint8_t encoded_opcode = *ptr++;
    uint32_t opcode;
    uint64_t operand = 0;

    switch (ctx->encoding_version) {
        case VM_ENCODING_V0:
            /* V0: 简单异或解码 */
            opcode = (uint32_t)(encoded_opcode ^ (ctx->opcode_xor_key & 0xFF));

            /* 操作数: 8字节 */
            for (int i = 0; i < 8; i++) {
                operand = (operand << 8) | *ptr++;
            }
            operand ^= ctx->operand_salt;
            break;

        case VM_ENCODING_V1:
            /* V1: 反向置换+XOR+字节重排解码（编码的精确逆操作） */
            opcode = (uint32_t)vm_encoding_decode_opcode_quick(ctx, encoded_opcode);

            /* 操作数: 反向解码 — 反序执行编码的三个步骤 */
            {
                for (int i = 0; i < 8; i++) {
                    operand = (operand << 8) | *ptr++;
                }
                /* Step 3 inverse: XOR salt2 */
                uint64_t salt2 = ctx->operand_salt ^ 0x5A5A5A5A5A5A5A5AULL;
                uint64_t unxored = operand ^ salt2;
                /* Step 2 inverse: reverse byte shuffle (swap halves, rotate right by 8) */
                uint32_t lo32 = (uint32_t)(unxored & 0xFFFFFFFFULL);
                uint32_t hi32 = (uint32_t)((unxored >> 32) & 0xFFFFFFFFULL);
                /* Swap halves back */
                uint64_t swapped = ((uint64_t)lo32 << 32) | (uint64_t)hi32;
                /* Rotate each half right by 8 bits (undo the left rotate) */
                lo32 = (uint32_t)((swapped >> 32) & 0xFFFFFFFFULL);
                hi32 = (uint32_t)(swapped & 0xFFFFFFFFULL);
                lo32 = (lo32 >> 8) | (lo32 << 24);
                hi32 = (hi32 >> 8) | (hi32 << 24);
                uint64_t unshuffled = ((uint64_t)lo32 << 32) | (uint64_t)hi32;
                /* Step 1 inverse: XOR salt1 */
                operand = unshuffled ^ ctx->operand_salt;
            }
            break;

        case VM_ENCODING_V2:
            /* V2: 变长解码 */
            opcode = (uint32_t)vm_encoding_decode_opcode_quick(ctx, encoded_opcode);

            /* 读取长度前缀 */
            uint8_t op_len_v2 = *ptr++;
            if (op_len_v2 > 8) {
                return -1;
            }

            /* 读取操作数 */
            for (int i = 0; i < op_len_v2; i++) {
                operand = (operand << 8) | *ptr++;
            }
            // 注意：这里把 operand 的内存地址（小端字节序）再次交给
            // decode_operand，它会按大端重新拼装；len<8 时与编码端的密钥字节
            // 位置不对应。当前 V2/V3 编解码因此不保证可逆（模块未接入主路径）。
            operand = vm_encoding_decode_operand(ctx, (uint8_t *)&operand, op_len_v2);
            break;

        case VM_ENCODING_V3:
            /* V3: 级联状态相关解码 */
            encoded_opcode ^= (uint8_t)(ctx->chain_state & 0xFF);
            opcode = (uint32_t)vm_encoding_decode_opcode_quick(ctx, encoded_opcode);

            /* 读取带标志的长度前缀 */
            uint8_t len_flags = *ptr++;
            uint8_t op_len_v3 = len_flags & 0x0F;
            /* flags = (len_flags >> 4) & 0x0F; 可用于验证 */

            if (op_len_v3 > 8) {
                return -1;
            }

            for (int i = 0; i < op_len_v3; i++) {
                operand = (operand << 8) | *ptr++;
            }
            // 与 V2 相同：传入的是 &operand 的内存视图，小端平台会反转字节序，
            // 与编码端的逐字节密钥流不匹配，往返不保证还原。
            operand = vm_encoding_decode_operand(ctx, (uint8_t *)&operand, op_len_v3);

            /* 移除上下文感知盐值 */
            uint64_t ctx_aware_salt = ctx->operand_salt ^
                                      ((uint64_t)ctx->chain_state << 32);
            operand ^= ctx_aware_salt;
            break;

        default:
            return -1;
    }

    *opcode_out = opcode;
    *operand_out = operand;
    return 0;
}

/*
 * 计算变长编码信息
 *
 * 根据操作数大小选择最优编码长度，减少字节码体积
 */
// 返回该版本下单条指令的长度布局：
// V0/V1 = 1+8；V2/V3 = 1(opcode)+1(长度前缀)+最多 8(操作数)。
// 返回结构体按值返回；ctx 为 NULL 时返回默认 {1,8,0}，不会崩溃。
// opcode 参数当前未使用，保留给按指令类型做长度优化。
vm_varlen_info_t vm_encoding_varlen_info(const vm_encoding_ctx_t *ctx,
                                         uint32_t opcode) {
    vm_varlen_info_t info = {1, 8, 0};

    if (!ctx) {
        return info;
    }

    switch (ctx->encoding_version) {
        case VM_ENCODING_V0:
        case VM_ENCODING_V1:
            /* 固定长度 */
            info.opcode_len = 1;
            info.operand_len = 8;
            info.flag_len = 0;
            break;

        case VM_ENCODING_V2:
        case VM_ENCODING_V3:
            /* 变长: 操作码1字节 + 长度前缀1字节 + 变长操作数 */
            info.opcode_len = 1;
            info.operand_len = 8; /* 最大8字节 */
            info.flag_len = 1;    /* 长度前缀 */
            break;

        default:
            break;
    }

    (void)opcode; /* 未来可根据操作码类型优化 */
    return info;
}

/*
 * 编码操作数 (变长)
 *
 * 使用简单的压缩编码: 小值使用更少字节
 */
// 计算操作数的有效字节数（去掉高位全零，0 固定占 1 字节），再按版本加密。
// V2+：逐字节与 operand_salt 的对应字节异或；V0/V1：整体异或 operand_salt。
// 参数：out_len 不可为 NULL；ctx 为 NULL 时原样返回 operand 且不写 out_len。
// 返回：编码后的值；同一输入在相同 ctx 下确定可复现。
// 注意：有效字节按“高位为零”裁剪，因此只适用于无符号小端数值语义。
uint64_t vm_encoding_encode_operand(const vm_encoding_ctx_t *ctx,
                                    uint64_t operand,
                                    uint8_t *out_len) {
    if (!ctx || !out_len) {
        return operand;
    }

    /* 计算有效字节数 */
    uint8_t effective_bytes = 8;
    if (operand == 0) {
        effective_bytes = 1;
    } else {
        uint64_t temp = operand;
        while ((temp & 0xFF00000000000000ULL) == 0 && effective_bytes > 1) {
            temp <<= 8;
            effective_bytes--;
        }
    }

    /* 根据编码版本应用不同的加密 */
    uint64_t result = operand;

    if (ctx->encoding_version >= VM_ENCODING_V2) {
        /* 使用流加密风格的分组异或 */
        for (int i = 0; i < effective_bytes; i++) {
            uint8_t key_byte = (uint8_t)(ctx->operand_salt >> ((i % 8) * 8));
            uint8_t data_byte = (uint8_t)(operand >> (i * 8));
            result &= ~(0xFFULL << (i * 8));
            result |= ((uint64_t)(data_byte ^ key_byte)) << (i * 8);
        }
    } else {
        result ^= ctx->operand_salt;
    }

    *out_len = effective_bytes;
    return result;
}

/*
 * 解码操作数 (变长)
 */
// 将大端字节流还原为整数，再执行 encode_operand 的逆变换。
// 参数：data 至少 len 字节；len > 8 或 data/ctx 为 NULL 时返回 0。
// 返回：解码出的 64 位操作数；失败值 0 与合法值不可区分，调用方应先自行校验长度。
uint64_t vm_encoding_decode_operand(const vm_encoding_ctx_t *ctx,
                                    const uint8_t *data,
                                    uint8_t len) {
    if (!ctx || !data || len > 8) {
        return 0;
    }

    uint64_t encoded = 0;
    for (int i = 0; i < len; i++) {
        encoded = (encoded << 8) | data[i];
    }

    uint64_t result = encoded;

    if (ctx->encoding_version >= VM_ENCODING_V2) {
        /* 反向流加密 */
        for (int i = len - 1; i >= 0; i--) {
            uint8_t key_byte = (uint8_t)(ctx->operand_salt >> ((i % 8) * 8));
            uint8_t enc_byte = (uint8_t)(encoded >> (i * 8));
            result &= ~(0xFFULL << (i * 8));
            result |= ((uint64_t)(enc_byte ^ key_byte)) << (i * 8);
        }
    } else {
        result ^= ctx->operand_salt;
    }

    return result;
}

/*
 * 更新级联状态 (V3)
 *
 * 级联状态使每条指令的编码依赖于之前所有指令
 * 攻击者无法重排指令序列而不破坏编码
 */
// 仅 V3 生效：把 opcode 与操作数高低 32 位折叠值混入 chain_state，
// 再做 Murmur 风格的乘法/移位雪崩。
// 不变量：结果恒非零（为 0 时回落 VM_ENC_CHAIN_MAGIC），避免级联状态退化。
// 参数：ctx 为 NULL 或版本 < V3 时直接返回。线程安全：写 ctx，需串行。
void vm_encoding_update_chain(vm_encoding_ctx_t *ctx,
                              uint32_t opcode,
                              uint64_t operand) {
    if (!ctx || ctx->encoding_version < VM_ENCODING_V3) {
        return;
    }

    /* 混合操作码和操作数到级联状态 */
    uint32_t new_state = ctx->chain_state;

    /* 使用类似SplitMix64的混合函数 */
    new_state += VM_ENC_CHAIN_MAGIC;
    new_state ^= opcode * 0x9E3779B9u;

    /* 混合操作数的低32位 */
    uint32_t operand_low = (uint32_t)(operand ^ (operand >> 32));
    new_state ^= operand_low;

    /* 最终混淆 */
    new_state = (new_state ^ (new_state >> 16)) * 0x85EBCA6Bu;
    new_state = (new_state ^ (new_state >> 13)) * 0xC2B2AE35u;
    new_state = new_state ^ (new_state >> 16);

    ctx->chain_state = new_state ? new_state : VM_ENC_CHAIN_MAGIC;
}

/*
 * 验证编码完整性
 *
 * 通过校验和检测编码数据是否被篡改
 */
// 以 opcode_xor_key 为初值做“乘 31 加字节”的滚动校验和。
// 这只是“数据非空且结果非零”的健全性检查：既没有保存期望值，也没有密钥 MAC，
// 无法真正检测篡改；调用方不得把它当作认证或 fail-closed 依据。
// 返回：0 表示通过；NULL、len==0 或校验和为 0 返回 -1。
int vm_encoding_verify_integrity(const vm_encoding_ctx_t *ctx,
                                 const void *encoded_data,
                                 size_t len) {
    if (!ctx || !encoded_data || len == 0) {
        return -1;
    }

    /* 计算简单校验和 */
    const uint8_t *data = (const uint8_t *)encoded_data;
    uint32_t checksum = ctx->opcode_xor_key;

    for (size_t i = 0; i < len; i++) {
        checksum = checksum * 31 + data[i];
    }

    /* 校验和应非零且符合预期模式 */
    if (checksum == 0) {
        return -1;
    }

    return 0;
}

/*
 * 导出编码上下文
 */
// 把整个编码上下文按原样 memcpy 导出（不加密），调用方负责保护输出缓冲区。
// 参数：max_len 必须 ≥ sizeof(vm_encoding_ctx_t)；不满足返回 0。
// 返回：写入字节数；失败 0。ctx 含密钥，序列化后必须按敏感数据处理。
// 线程安全：只读 ctx，但与并发写 ctx 竞争时结果不一致。
size_t vm_encoding_export_ctx(const vm_encoding_ctx_t *ctx,
                              uint8_t *out,
                              size_t max_len) {
    if (!ctx || !out || max_len < sizeof(vm_encoding_ctx_t)) {
        return 0;
    }

    /* 注意: 实际导出应加密敏感字段 */
    memcpy(out, ctx, sizeof(vm_encoding_ctx_t));
    return sizeof(vm_encoding_ctx_t);
}

/*
 * 导入编码上下文
 */
// 按原样 memcpy 导入编码上下文，不做任何完整性/版本校验。
// 参数：data 至少 sizeof(vm_encoding_ctx_t) 字节。
// 返回：0 成功；参数非法或长度不足返回 -1。
// 导入的密钥直接生效，调用方必须信任数据来源。
int vm_encoding_import_ctx(vm_encoding_ctx_t *ctx,
                           const uint8_t *data,
                           size_t len) {
    if (!ctx || !data || len < sizeof(vm_encoding_ctx_t)) {
        return -1;
    }

    memcpy(ctx, data, sizeof(vm_encoding_ctx_t));
    return 0;
}

/*
 * 安全清除编码上下文
 */
// 用 secure_zero 清零整个上下文（含密钥）；ctx 为 NULL 时无操作。
void vm_encoding_clear_ctx(vm_encoding_ctx_t *ctx) {
    if (ctx) {
        cprisk_secure_zero(ctx, sizeof(*ctx));
    }
}
