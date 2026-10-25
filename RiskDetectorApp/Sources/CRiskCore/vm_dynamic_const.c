// 文件职责：把阈值、魔数、校验值、掩码和密钥等关键常量改为运行时派生，
// 通过白盒 PRF、函数身份哈希与线程本地 PRNG 生成，避免立即数留在二进制中。
// 现状：头文件标注 DEPRECATED（issue 65），当前无生产调用方，仅保留兼容。
// 线程模型：唯一的可变全局状态是 _Thread_local PRNG 流，并发线程互不干扰；跨帧共享仍需调用方串行化。
// 确定性与失败语义：相同输入必得同一结果；白盒失败退回固定公式（可预测、非密码学强度），
// 不能当作认证凭据；纯 C，无平台/架构分支。
/*
 *  vm_dynamic_const.c
 *  CRiskCore
 *
 *  常量动态化 - Dynamic Constant Derivation
 *
 *  对抗原理说明:
 *  ==============
 *
 *  传统逆向工程中，关键常量(如阈值、魔数、校验值)通常以立即数形式
 *  硬编码在指令中，攻击者可以通过静态分析轻松提取。
 *
 *  本模块实现"常量动态派生"技术:
 *  1. 关键常量在运行时通过PRF(伪随机函数)派生，不在代码中出现
 *  2. 每个函数的阈值是唯一的，基于函数ID和白盒PRF材料
 *  3. 引入VM_OP_LOAD_RND和VM_OP_DERIVE指令，在VM层面支持动态常量
 *
 *  核心概念:
 *  =========
 *
 *  1. VM_OP_LOAD_RND指令:
 *     - 从白盒PRF的随机流中加载一个32位值到累加器
 *     - 每次执行产生不同的"随机"常量(实际是确定性的PRF输出)
 *     - 攻击者无法静态提取，因为值在运行时计算
 *
 *  2. VM_OP_DERIVE指令:
 *     - 通过WhiteBoxPRF派生特定常量
 *     - 输入: domain(域ID) + seed(种子)
 *     - 输出: 派生值，用于比较、阈值检查等
 *
 *  3. 函数身份哈希:
 *     - 每个函数有唯一的身份指纹
 *     - 基于函数ID、字节码内容、白盒材料计算
 *     - 用于派生函数特定的阈值和常量
 *
 *  安全优势:
 *  =========
 *
 *  1. 抗静态分析: 常量值不出现在二进制中
 *  2. 抗动态分析: 每次执行产生不同序列(绑定到会话)
 *  3. 抗重放攻击: 派生值绑定到白盒PRF材料
 *  4. 抗符号执行: 约束求解需要完整的PRF模型
 *
 *  与现有系统集成:
 *  ==============
 *  - 复用cprisk_whitebox.c中的白盒PRF评估
 *  - 与CFF状态联动，派生值影响状态转换
 *  - 支持VM解释器内联执行
 */

#include "include/CRiskCore.h"
#include "include/cprisk_vm_interpreter.h"
#include "include/cprisk_vm_interpreter_internal.h"
#include "vm_dynamic_const.h"

#include <string.h>

/*
 * 白盒PRF域定义 - 常量派生专用域
 */
// 域号 10–15 是白盒 PRF 的常量派生域；但 vm_const_derive_via_whitebox 会再映射为
// BASE + (domain % 6)，实际求值域始终落在 10..15：RND=10→14、THRESH=11→15、
// MAGIC=12→10、CHECK=13→11、MASK=14→12、KEY=15→13。因此这些常量名不是
// 与白盒域一一对应的命名空间。
#define VM_CONST_DERIVE_DOMAIN_BASE     10  /* 常量派生域起始 */
#define VM_CONST_DERIVE_DOMAIN_RND      10  /* 随机常量域 */
#define VM_CONST_DERIVE_DOMAIN_THRESH   11  /* 阈值派生域 */
#define VM_CONST_DERIVE_DOMAIN_MAGIC    12  /* 魔数派生域 */
#define VM_CONST_DERIVE_DOMAIN_CHECK    13  /* 校验值派生域 */
#define VM_CONST_DERIVE_DOMAIN_MASK     14  /* 掩码派生域 */
#define VM_CONST_DERIVE_DOMAIN_KEY      15  /* 密钥派生域 */

/*
 * 内部状态 - PRF流状态
 */
// 白盒种子驱动的 32 位随机流：state 是 SplitMix64 状态，buffer 一次预生成 8 个值，
// buffer_pos 指向下一个待取值。不变量：只在 pos 到达 8 时整批重填，
// 因此读取顺序严格确定，不依赖未初始化内存。
typedef struct {
    uint64_t state;
    uint32_t buffer[8];      /* 预生成的随机值缓冲区 */
    uint8_t  buffer_pos;     /* 缓冲区当前位置 */
    uint8_t  initialized;    /* 是否已初始化 */
} vm_prng_stream_t;

/*
 * 线程本地存储的PRNG状态
 * 确保多线程安全性
 */
// 每线程独立的 PRNG 流，零初始化；避免全局锁与跨线程状态污染。
// 只由 vm_op_load_rnd_execute 与 reset_for_func 修改，线程退出即销毁，无需显式清理。
static _Thread_local vm_prng_stream_t s_tls_prng_stream = {0};

/*
 * 内部函数: SplitMix64 PRNG
 * 用于生成随机流
 */
// SplitMix64：固定增量 + 两次乘法雪崩，输出 64 位。
// 0x9E3779B97F4A7C15 是 64 位黄金比例增量，其余两个乘法常量是标准 SplitMix 混合参数；
// 改动会改变所有派生值，并可能破坏跨版本复现。返回：每个 state 对应唯一的下一输出。
static uint64_t vm_splitmix64_next(uint64_t *state) {
    *state += 0x9E3779B97F4A7C15ULL;
    uint64_t z = *state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/*
 * 内部函数: 从白盒PRF派生种子
 * 使用白盒PRF的domain 5(运行时材料域)作为种子源
 */
// 由 (func_id, pc) 经白盒 domain 5 派生 64 位种子。
// 输入 32 字节先整体清零，再写入 func_id(8) 与 pc(4)，其余保持 0，避免读取未初始化内存。
// 白盒失败时返回 func_id ^ pc ^ 黄金比例常量：确定性兜底，安全性降级。
// 返回：任意输入均有确定输出；不写 errno；线程安全（纯栈）。
static uint64_t vm_derive_seed_from_whitebox_i(uint64_t func_id, uint32_t pc) {
    uint8_t input[32];
    uint8_t output[32];

    /* 构造输入: func_id + pc */
    memset(input, 0, sizeof(input));
    memcpy(input, &func_id, sizeof(func_id));
    memcpy(input + 8, &pc, sizeof(pc));

    /* 评估白盒PRF domain 5 */
    if (cprisk_whitebox_evaluate_domain(5, input, output) != 0) {
        /* 失败时回退到确定性种子 */
        return func_id ^ pc ^ 0x9E3779B97F4A7C15ULL;
    }

    /* 从输出派生64位种子 */
    uint64_t seed = 0;
    for (int i = 0; i < 8; i++) {
        seed = (seed << 8) | output[i];
    }

    /* 清零敏感数据 */
    cprisk_secure_zero(input, sizeof(input));
    cprisk_secure_zero(output, sizeof(output));

    return seed;
}

/*
 * 内部函数: 初始化PRNG流
 */
// 初始化 PRNG：用白盒种子重置状态，立即预填 8 个 32 位值。
// stream 为 NULL 时静默返回；重复调用会丢弃旧状态，从新种子重新开始。
static void vm_prng_stream_init(vm_prng_stream_t *stream,
                                uint64_t func_id,
                                uint32_t pc) {
    if (!stream) {
        return;
    }

    /* 从白盒PRF派生初始种子 */
    stream->state = vm_derive_seed_from_whitebox_i(func_id, pc);
    stream->buffer_pos = 0;
    stream->initialized = 1;

    /* 预填充缓冲区 */
    for (int i = 0; i < 8; i++) {
        stream->buffer[i] = (uint32_t)vm_splitmix64_next(&stream->state);
    }
}

/*
 * 内部函数: 从PRNG流获取下一个32位值
 */
// 取下一个 32 位值并推进 buffer_pos；取完后整批重填。
// 返回：未初始化或 stream 为 NULL 时返回 0，与真实随机值 0 不可区分，调用方需先 init。
static uint32_t vm_prng_stream_next(vm_prng_stream_t *stream) {
    if (!stream || !stream->initialized) {
        return 0;
    }

    /* 从缓冲区取值 */
    uint32_t value = stream->buffer[stream->buffer_pos];
    stream->buffer_pos++;

    /* 缓冲区耗尽时重新填充 */
    if (stream->buffer_pos >= 8) {
        stream->buffer_pos = 0;
        for (int i = 0; i < 8; i++) {
            stream->buffer[i] = (uint32_t)vm_splitmix64_next(&stream->state);
        }
    }

    return value;
}

/*
 * 公开API: 通过WhiteBoxPRF派生常量
 *
 * @param domain 派生域(用于区分不同类型的常量)
 * @param func_id 函数ID
 * @param seed 派生种子
 * @return 派生的32位常量值
 */
// 常量派生的统一入口：domain 选择用途，func_id 绑定函数，seed 绑定调用点/类型。
// 输入布局：domain(4) || func_id(8) || seed(4)，其余清零；先做 SHA256 再喂白盒，
// 避免把结构化长度直接暴露给 PRF。
// 白盒域 = BASE(10) + (domain % 6)，因此只能落到 10..15。
// 返回：成功时取白盒输出前 4 字节按大端拼成 32 位；失败时返回
//       (func_id>>32) ^ seed ^ (domain*0x9E3779B9)，确定性但非密码学。
// 线程安全：纯栈；输入/输出/哈希用后 secure_zero。
uint32_t vm_const_derive_via_whitebox(uint32_t domain,
                                       uint64_t func_id,
                                       uint32_t seed) {
    uint8_t input[32];
    uint8_t output[32];

    /* 构造输入: domain + func_id + seed */
    memset(input, 0, sizeof(input));
    memcpy(input, &domain, sizeof(domain));
    memcpy(input + 4, &func_id, sizeof(func_id));
    memcpy(input + 12, &seed, sizeof(seed));

    /* 计算输入的哈希作为白盒输入 */
    uint8_t hash[32];
    cprisk_sha256(input, 16, hash);

    /* 评估白盒PRF */
    uint32_t result = 0;
    if (cprisk_whitebox_evaluate_domain(VM_CONST_DERIVE_DOMAIN_BASE + (domain % 6),
                                         hash, output) == 0) {
        /* 从输出派生结果 */
        result = ((uint32_t)output[0] << 24) |
                 ((uint32_t)output[1] << 16) |
                 ((uint32_t)output[2] << 8) |
                 (uint32_t)output[3];
    } else {
        /* 失败时使用备用派生 */
        result = (uint32_t)(func_id >> 32) ^ seed ^ (domain * 0x9E3779B9u);
    }

    /* 清零敏感数据 */
    cprisk_secure_zero(input, sizeof(input));
    cprisk_secure_zero(output, sizeof(output));
    cprisk_secure_zero(hash, sizeof(hash));

    return result;
}

/*
 * 公开API: 派生函数特定的比较阈值
 *
 * 用于FUNC_ID_CMP_THRESH等场景
 *
 * @param func_id 函数ID
 * @param threshold_type 阈值类型(如CMP_THRESH_EQ, CMP_THRESH_GT等)
 * @return 派生的阈值
 */
// 阈值派生：把 func_id 高低 32 位折叠成 seed，再与阈值类型异或，
// 使同一函数的“相等/大于/小于”等阈值互不相同。
// 返回：32 位派生阈值；无失败路径。
uint32_t vm_const_derive_cmp_threshold(uint64_t func_id, uint32_t threshold_type) {
    /* 使用阈值派生域 */
    uint32_t seed = (uint32_t)(func_id ^ (func_id >> 32));
    return vm_const_derive_via_whitebox(VM_CONST_DERIVE_DOMAIN_THRESH,
                                         func_id,
                                         seed ^ threshold_type);
}

/*
 * 公开API: 派生函数特定的魔数
 *
 * @param func_id 函数ID
 * @param magic_type 魔数类型标识
 * @return 派生的魔数
 */
// 魔数派生：类型直接作为 seed，同一 func_id 下不同类型得到不同魔数。
// 返回：32 位派生魔数；无失败路径。
uint32_t vm_const_derive_magic(uint64_t func_id, uint32_t magic_type) {
    return vm_const_derive_via_whitebox(VM_CONST_DERIVE_DOMAIN_MAGIC,
                                         func_id,
                                         magic_type);
}

/*
 * 公开API: 派生校验常量
 *
 * 用于运行时完整性校验
 *
 * @param func_id 函数ID
 * @param check_type 校验类型
 * @return 派生的校验值
 */
// 校验值派生：用于运行时完整性比对；派生是确定性的，可复现。
// 返回：32 位派生校验值；无失败路径。
uint32_t vm_const_derive_check_value(uint64_t func_id, uint32_t check_type) {
    return vm_const_derive_via_whitebox(VM_CONST_DERIVE_DOMAIN_CHECK,
                                         func_id,
                                         check_type);
}

/*
 * 公开API: 派生掩码常量
 *
 * @param func_id 函数ID
 * @param mask_type 掩码类型
 * @param bit_width 需要的位宽
 * @return 派生的掩码
 */
// 掩码派生：先取 32 位原始值，再按 bit_width 截断。
// bit_width >= 32 时原样返回；bit_width == 0 时返回 0。
// 返回：低 bit_width 位有效的掩码；无失败路径。
uint32_t vm_const_derive_mask(uint64_t func_id, uint32_t mask_type, uint8_t bit_width) {
    uint32_t raw = vm_const_derive_via_whitebox(VM_CONST_DERIVE_DOMAIN_MASK,
                                                func_id,
                                                mask_type);
    /* 根据位宽裁剪 */
    if (bit_width >= 32) {
        return raw;
    }
    return raw & ((1u << bit_width) - 1);
}

/*
 * 公开API: 派生密钥材料
 *
 * @param func_id 函数ID
 * @param key_index 密钥索引
 * @param key_out 输出缓冲区(32字节)
 * @return 0成功，非0失败
 */
// 派生 32 字节密钥材料。
// 参数：key_out 必须可写 32 字节，且仅在返回 0 时有效（失败时不会清零 key_out）。
// 返回：白盒求值的原始返回码（0 成功，非 0 失败）；没有本地兜底，调用方必须显式处理失败。
// 线程安全：纯栈；输入/输出用后清零。
int vm_const_derive_key_material(uint64_t func_id,
                                  uint32_t key_index,
                                  uint8_t key_out[32]) {
    uint8_t input[32];
    uint8_t output[32];

    /* 构造输入 */
    memset(input, 0, sizeof(input));
    memcpy(input, &func_id, sizeof(func_id));
    memcpy(input + 8, &key_index, sizeof(key_index));

    /* 评估白盒PRF */
    int rc = cprisk_whitebox_evaluate_domain(VM_CONST_DERIVE_DOMAIN_KEY,
                                              input, output);
    if (rc == 0) {
        memcpy(key_out, output, 32);
    }

    cprisk_secure_zero(input, sizeof(input));
    cprisk_secure_zero(output, sizeof(output));

    return rc;
}

/*
 * 公开API: 执行VM_OP_LOAD_RND指令
 *
 * 从PRNG流加载一个随机常量到累加器
 *
 * @param fr VM解释器帧
 * @param imm 立即数字段(包含派生参数)
 * @return VM_FLOW_CONTINUE
 */
// VM_OP_LOAD_RND：按立即数指定的方式生成一个 32 位“随机”常量并写入帧。
// imm 位域：bit0–4 目标 acc 槽；bit5=1 走白盒派生，=0 走 TLS PRNG。
// 注意：PRNG 路径每次调用都用 (func_id, pc) 重新 init，相同 pc 重复执行会得到
// 同一序列；只有 steps/pc 变化才会换种子。
// 写入：acc[slot] = 低 8 位；acc_aux[(slot+16)&31] = 次 8 位，完整值混入 opaque_chain。
// 返回：fr 为 NULL 时 CPRISK_VM_FLOW_LEAVE；否则 CPRISK_VM_FLOW_CONTINUE。
cprisk_vm_flow_t vm_op_load_rnd_execute(cprisk_vm_interp_frame_t *fr,
                                         uint64_t imm) {
    if (!fr) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    // bit0–4 是槽位（0..31），bit5 是派生方式开关；其余位当前忽略。
    /* 提取参数 */
    uint32_t target_slot = imm & 0x1F;           /* 目标累加器槽位 */
    uint32_t use_whitebox = (imm >> 5) & 1;      /* 是否使用白盒PRF */
    uint32_t pc = (uint32_t)(fr->steps & 0xFFFFFFFF);

    uint32_t value;

    if (use_whitebox) {
        /* 使用白盒PRF派生 */
        value = vm_const_derive_via_whitebox(VM_CONST_DERIVE_DOMAIN_RND,
                                             fr->func_id,
                                             pc);
    } else {
        /* 使用PRNG流 */
        vm_prng_stream_init(&s_tls_prng_stream, fr->func_id, pc);
        value = vm_prng_stream_next(&s_tls_prng_stream);
    }

    /* 存入累加器指定槽位 */
    if (target_slot < 32) {
        fr->acc[target_slot] = (uint8_t)(value & 0xFF);
    }

    /* 同时影响辅助累加器 */
    uint32_t aux_slot = (target_slot + 16) & 31;
    fr->acc_aux[aux_slot] = (uint8_t)((value >> 8) & 0xFF);

    /* 更新不透明链 */
    fr->opaque_chain ^= value;

    return CPRISK_VM_FLOW_CONTINUE;
}

/*
 * 公开API: 执行VM_OP_DERIVE指令
 *
 * 派生一个常量并执行操作
 *
 * @param fr VM解释器帧
 * @param imm 立即数字段
 *        - bits 0-7: 派生域
 *        - bits 8-15: 操作类型
 *        - bits 16-31: 派生种子
 * @return VM_FLOW_CONTINUE
 */
// VM_OP_DERIVE：派生常量并按 op_type 作用到累加器或 VM 状态。
// imm 位域：bits0–7 domain，bits8–15 操作类型，bits16–31 为 16 位 seed；
// 实际派生种子是 seed ^ (steps 低 32 位)，使同一指令在不同执行位置得到不同值。
// op_type 语义：LOAD/XOR/ADD/MASK 作用于 acc[0..3]（低字节在前），
// CMP_THRESH 只把派生值写入 trace_scratch（比较交给后续分支指令），
// MIX_STATE 更新 opaque_chain/session_mix/opaque_session_mix，未知类型退化为混链。
// 返回：fr 为 NULL 时 LEAVE；否则 CONTINUE。所有操作都是确定性的。
cprisk_vm_flow_t vm_op_derive_execute(cprisk_vm_interp_frame_t *fr,
                                       uint64_t imm) {
    if (!fr) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    // domain 只取低 8 位，seed 只取 16 位；高位被截断而不是报错。
    /* 解析立即数 */
    uint32_t domain = imm & 0xFF;
    uint32_t op_type = (imm >> 8) & 0xFF;
    uint32_t seed = (imm >> 16) & 0xFFFF;
    uint32_t pc = (uint32_t)(fr->steps & 0xFFFFFFFF);

    /* 派生常量 */
    uint32_t derived = vm_const_derive_via_whitebox(domain,
                                                     fr->func_id,
                                                     seed ^ pc);

    /* 根据操作类型应用派生值 */
    switch (op_type) {
        case VM_DERIVE_OP_LOAD_ACC: {
            /* 加载到累加器 */
            for (int i = 0; i < 4; i++) {
                fr->acc[i] = (uint8_t)((derived >> (i * 8)) & 0xFF);
            }
            break;
        }

        case VM_DERIVE_OP_XOR_ACC: {
            /* 与累加器XOR */
            for (int i = 0; i < 4; i++) {
                fr->acc[i] ^= (uint8_t)((derived >> (i * 8)) & 0xFF);
            }
            break;
        }

        case VM_DERIVE_OP_ADD_ACC: {
            /* 与累加器ADD(字节级) */
            uint32_t acc_val = 0;
            for (int i = 0; i < 4; i++) {
                acc_val |= ((uint32_t)fr->acc[i]) << (i * 8);
            }
            acc_val += derived;
            for (int i = 0; i < 4; i++) {
                fr->acc[i] = (uint8_t)((acc_val >> (i * 8)) & 0xFF);
            }
            break;
        }

        case VM_DERIVE_OP_CMP_THRESH: {
            /* 比较阈值检查 */
            /* 派生的阈值与累加器值比较，影响条件状态 */
            /* 实际比较逻辑由后续BRANCH_COND指令处理 */
            /* 这里只将派生值存入trace_scratch供后续使用 */
            memcpy(fr->trace_scratch, &derived, sizeof(derived));
            break;
        }

        case VM_DERIVE_OP_MASK_ACC: {
            /* 掩码操作 */
            for (int i = 0; i < 4; i++) {
                fr->acc[i] &= (uint8_t)((derived >> (i * 8)) & 0xFF);
            }
            break;
        }

        case VM_DERIVE_OP_MIX_STATE: {
            /* 混合VM状态 */
            fr->opaque_chain ^= derived;
            fr->session_mix ^= (derived >> 16);
            fr->opaque_session_mix = (fr->opaque_session_mix * 0x9E3779B9u) + derived;
            break;
        }

        default:
            /* 未知操作类型，使用默认值 */
            fr->opaque_chain ^= derived;
            break;
    }

    return CPRISK_VM_FLOW_CONTINUE;
}

/*
 * 公开API: 计算函数身份哈希
 *
 * 基于函数ID、字节码内容和白盒材料计算唯一的函数指纹
 *
 * @param func_id 函数ID
 * @param bytecode 字节码内容(可为NULL)
 * @param bytecode_len 字节码长度
 * @param hash_out 输出缓冲区(32字节)
 * @return 0成功，非0失败
 */
// 计算函数身份指纹：SHA256(func_id || bytecode? || 运行时白盒材料? || 版本标签)。
// 参数：bytecode 可为 NULL（此时只混入 func_id 与白盒材料）；hash_out 必须可写 32 字节。
// 返回：恒 0（当前无失败路径）。白盒材料取不到时静默跳过，因此同一函数在
// 有无运行时材料的进程间指纹可能不同——不要跨进程比较该哈希。
// 线程安全：纯栈 + 只读运行时材料。
int vm_const_hash_function_identity(uint64_t func_id,
                                     const uint8_t *bytecode,
                                     size_t bytecode_len,
                                     uint8_t hash_out[32]) {
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);

    /* 混入函数ID */
    cprisk_sha256_update(&ctx, (const uint8_t *)&func_id, sizeof(func_id));

    /* 混入字节码内容(如果有) */
    if (bytecode && bytecode_len > 0) {
        cprisk_sha256_update(&ctx, bytecode, bytecode_len);
    }

    /* 混入白盒材料(如果可用) */
    uint8_t wb_material[32];
    if (cprisk_get_runtime_material(wb_material) == 0) {
        cprisk_sha256_update(&ctx, wb_material, sizeof(wb_material));
        cprisk_secure_zero(wb_material, sizeof(wb_material));
    }

    /* 混入版本常量 */
    static const uint8_t version_tag[] = "VM_DYNAMIC_CONST_v1";
    cprisk_sha256_update(&ctx, version_tag, sizeof(version_tag) - 1);

    /* 输出哈希 */
    cprisk_sha256_final(&ctx, hash_out);

    return 0;
}

/*
 * 公开API: 从函数身份哈希派生常量
 *
 * @param func_id 函数ID
 * @param const_index 常量索引(用于派生多个常量)
 * @return 派生的常量值
 */
// 从函数身份哈希中按 const_index 取 4 字节常量。
// 偏移 = (const_index*4) % 28，保证 offset+3 ≤ 31 不越界；
// 索引每 7 个回绕一次（7×4=28），不同 const_index 仅靠末尾的黄金比例异或区分。
// 返回：32 位派生值；无失败路径。身份哈希用后清零。
uint32_t vm_const_derive_from_identity(uint64_t func_id, uint32_t const_index) {
    uint8_t identity_hash[32];

    /* 计算函数身份哈希 */
    vm_const_hash_function_identity(func_id, NULL, 0, identity_hash);

    /* 从哈希派生指定索引的常量 */
    uint32_t offset = (const_index * 4) % 28;  /* 确保不越界 */
    uint32_t value = ((uint32_t)identity_hash[offset] << 24) |
                     ((uint32_t)identity_hash[offset + 1] << 16) |
                     ((uint32_t)identity_hash[offset + 2] << 8) |
                     (uint32_t)identity_hash[offset + 3];

    /* 混合索引防止碰撞 */
    value ^= const_index * 0x9E3779B9u;

    cprisk_secure_zero(identity_hash, sizeof(identity_hash));

    return value;
}

/*
 * 公开API: 在VM解释器中应用动态常量
 *
 * 此函数应在VM初始化时调用，设置函数的动态常量
 */
// VM 初始化时把 3 个身份派生常量写入帧：acc[0..3]、acc_aux[16..19]，
// 并把 session_salt 混入 session_mix / opaque_session_mix。
// 参数：fr 为 NULL 时无操作。返回：无。
// 注意：会覆盖累加器初值，必须在执行第一条指令前调用。
void vm_dynamic_const_apply_to_interp(cprisk_vm_interp_frame_t *fr) {
    if (!fr) {
        return;
    }

    /* 派生函数特定的初始常量 */
    uint32_t init_acc = vm_const_derive_from_identity(fr->func_id, 0);
    uint32_t init_aux = vm_const_derive_from_identity(fr->func_id, 1);
    uint32_t session_salt = vm_const_derive_from_identity(fr->func_id, 2);

    // init_acc 的 4 个字节写入 acc[0..3]，init_aux 的 4 个字节写入 acc_aux[16..19]；
    // 两路派生值互不重叠，避免初始化时相互覆盖。
    /* 应用派生值到VM状态 */
    for (int i = 0; i < 4; i++) {
        fr->acc[i] = (uint8_t)((init_acc >> (i * 8)) & 0xFF);
        fr->acc_aux[i + 16] = (uint8_t)((init_aux >> (i * 8)) & 0xFF);
    }

    /* 更新会话混合 */
    fr->session_mix ^= session_salt;
    fr->opaque_session_mix ^= (session_salt >> 16);
}

/*
 * 公开API: 重置动态常量上下文
 * 用于函数调用切换时
 */
// 切换函数时重置当前线程的 PRNG：先整体清零，再用 (func_id, pc=0) 重新播种。
// 只影响调用线程；不触碰其它线程或任何 VM 帧。
void vm_dynamic_const_reset_for_func(uint64_t func_id) {
    /* 重置TLS PRNG状态 */
    memset(&s_tls_prng_stream, 0, sizeof(s_tls_prng_stream));

    /* 预初始化新函数的PRNG */
    vm_prng_stream_init(&s_tls_prng_stream, func_id, 0);
}

/*
 * 公开API: 获取函数特定的比较阈值
 * 用于FUNC_ID_CMP_THRESH场景
 */
// 生成函数特定的比较阈值：派生常量先用 cmp_type+100 作为索引，再与 base_value 异或。
// 注意：结果没有范围裁剪（裁剪代码被注释掉），可能超出调用方预期区间；
//       需要上界的调用方必须自行 clamp。
// 返回：32 位混合阈值；无失败路径。
uint32_t vm_const_get_func_cmp_threshold(uint64_t func_id,
                                          uint32_t cmp_type,
                                          uint32_t base_value) {
    /* 派生函数特定的阈值 */
    uint32_t derived = vm_const_derive_from_identity(func_id, cmp_type + 100);

    /* 将派生值与基础值混合 */
    uint32_t threshold = base_value ^ derived;

    /* 确保阈值在合理范围内(可选) */
    /* threshold = threshold % MAX_THRESHOLD; */

    (void)threshold;
    return threshold;
}
