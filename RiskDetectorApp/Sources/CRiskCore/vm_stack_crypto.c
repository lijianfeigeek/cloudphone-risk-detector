// vm_stack_crypto.c — VM 栈值的混淆/去混淆（是混淆，不是加密）。
// 只用 XOR、循环移位与加法把栈槽搅乱，没有认证、没有密钥扩展；已知明文可
// 直接恢复密钥流，因此只能降低内存 dump 的可读性，不能提供机密性。
// 密钥材料全部由调用方传入的 32 字节 master_key 与 func_id 派生，本文件不
// 生成随机数、不访问硬件。上下文无锁，每个函数一份，由 VM 单线程串行使用。
// 未初始化时各 API 采用 fail-open（原值/明文直通），见各函数说明。

/*
 * ============================================================================
 * VM堆栈混淆保护 (vm_stack_crypto.c)
 * ============================================================================
 *
 * 核心加固原理（混淆，非加密）:
 * ------------
 * 1. 运行时混淆: VM堆栈中的值在存储前混淆，读取时解混淆
 * 2. 每函数独立密钥: 不同函数使用不同的混淆参数，防止密钥复用攻击
 * 3. 混淆存储: 使用旋转+偏移+异或的多层混淆
 * 4. 抗内存Dump: 内存中的栈值始终处于加密状态
 *
 * 对抗技术:
 * --------
 * - 反内存分析: 静态分析无法直接读取栈值
 * - 反动态调试: 调试器看到的栈值是密文
 * - 反Hook: Hook栈操作函数需要同时处理加解密
 * - 抗侧信道: 每层操作都有不同的密钥参数
 */

#include "vm_stack_crypto.h"
#include "include/cprisk_secure_zero.h"
#include <string.h>

/* 内部常量 */
// “已初始化”标记：init 在写完所有密钥字段后才写入；push/pop/load/store 都比对它。
#define VM_STACK_MAGIC_PUSH 0x50555348u  /* "PUSH" */
// 历史遗留的出栈标记，当前实现从未写入或读取；保留仅为兼容旧调用方/ABI。
#define VM_STACK_MAGIC_POP  0x504F5000u  /* "POP" */

// 64 位循环左移。n 必须在 1..63：n==0 会左移 64 位（未定义行为），
// 因此只会传入 init 派生并夹到 8..63 的 stack_rot。
/* 64位循环左移 */
static inline uint64_t vm_rotl64(uint64_t x, uint8_t n) {
    return (x << n) | (x >> (64 - n));
}

// 64 位循环右移，约束同上（n 在 1..63）；与 vm_rotl64 互为逆运算。
/* 64位循环右移 */
static inline uint64_t vm_rotr64(uint64_t x, uint8_t n) {
    return (x >> n) | (x << (64 - n));
}

/* 初始化栈混淆上下文
 *
 * 密钥派生:
 * - 从VM主密钥派生栈专用密钥
 * - 每个函数使用不同的旋转量和偏移量
 */
// 从 32 字节主密钥与 func_id 派生一份栈混淆上下文（四段 8 字节各司其职）。
// - ctx: 输出上下文，函数先 memset 清零；master_key 必须指向至少 32 字节。
// - 返回: VM_STACK_OK；任一指针为 NULL 时返回 VM_STACK_ERROR_INVALID_PARAM。
// - 线程: 写 ctx 全部字段，调用方需独占 ctx；平台: 纯整数运算，无分支差异。
// - 失败语义: 失败不写 errno；ctx 保持全零（未初始化），后续 API 会 fail-open。
int vm_stack_obfuscation_init(vm_stack_obfuscation_ctx_t *ctx,
                         uint64_t func_id,
                         const uint8_t master_key[32]) {
    if (!ctx || !master_key) {
        return VM_STACK_ERROR_INVALID_PARAM;
    }

    memset(ctx, 0, sizeof(*ctx));

    /* 派生栈异或密钥 (前8字节) */
    // 小端拼装前 8 字节，再与 func_id 异或：同主密钥下不同函数得到不同密钥。
    ctx->stack_xor_key = 0;
    for (int i = 0; i < 8; i++) {
        ctx->stack_xor_key |= ((uint64_t)master_key[i]) << (i * 8);
    }
    ctx->stack_xor_key ^= func_id;

    /* 派生旋转量 (第8-15字节) */
    // 取低 6 位得到 0..63；再夹到最小 8，既避开 n==0/64 的未定义移位，
    // 也避免“几乎不旋转”导致明文比特位置基本不变。
    uint64_t rot_seed = 0;
    for (int i = 0; i < 8; i++) {
        rot_seed |= ((uint64_t)master_key[i + 8]) << (i * 8);
    }
    ctx->stack_rot = (uint8_t)(rot_seed ^ func_id) & 0x3F;
    if (ctx->stack_rot < 8) {
        ctx->stack_rot = 8;  /* 最小旋转量 */
    }

    /* 派生偏移量 (第16-23字节) */
    // func_id 左移 1 位后异或，使相邻 func_id 的偏移不会只差最低位。
    uint64_t offset_seed = 0;
    for (int i = 0; i < 8; i++) {
        offset_seed |= ((uint64_t)master_key[i + 16]) << (i * 8);
    }
    ctx->stack_offset = offset_seed ^ (func_id << 1);

    /* 派生次级密钥 (第24-31字节) */
    // 与偏移量使用相反的移位方向（>>1），降低两段派生值同步变化的可能性。
    ctx->secondary_key = 0;
    for (int i = 0; i < 8; i++) {
        ctx->secondary_key |= ((uint64_t)master_key[i + 24]) << (i * 8);
    }
    ctx->secondary_key ^= (func_id >> 1);

    // 最后才置标记：保证任何提前返回都不会留下“看似已初始化”的半成品上下文。
    ctx->initialized = VM_STACK_MAGIC_PUSH;

    return VM_STACK_OK;
}

/* 混淆压栈值
 *
 * 混淆流程: value -> XOR -> ROTL -> ADD_OFFSET
 */
// 按 XOR → ROTL → +offset → XOR(secondary+offset) 四层混淆一个 64 位值。
// - ctx: 只读；value: 明文字。返回: 混淆值。
// - 线程: 只读 ctx，可并发读同一 ctx；平台: 移位量受限于 8..63，避免 UB。
// - 失败语义: ctx 为 NULL 或未初始化时原样返回 value（fail-open，便于无加固路径复用）。
uint64_t vm_stack_obfuscate_push(const vm_stack_obfuscation_ctx_t *ctx, uint64_t value) {
    if (!ctx || ctx->initialized != VM_STACK_MAGIC_PUSH) {
        return value;  /* 未初始化，明文返回 */
    }

    /* 第一层: XOR with key */
    // 先异或再移位：移位负责跨字节扩散，异或负责把密钥拌入每一位。
    uint64_t encrypted = value ^ ctx->stack_xor_key;

    /* 第二层: 循环左移 */
    // 循环移位保证信息不丢失，deobfuscate 可以精确逆转。
    encrypted = vm_rotl64(encrypted, ctx->stack_rot);

    /* 第三层: 加法偏移 */
    // 加法会引入进位，使单比特差异影响更高位，比纯异或更难做差分观察。
    encrypted += ctx->stack_offset;

    /* 第四层: 与次级密钥混合 */
    // 再用 secondary+offset 做一次异或，让密钥与偏移不能分开单独求解。
    encrypted ^= (ctx->secondary_key + ctx->stack_offset);

    return encrypted;
}

/* 解混淆出栈值
 *
 * 解混淆流程: encrypted -> XOR_SECONDARY -> SUB_OFFSET -> ROTR -> XOR
 */
// 逆序撤销 obfuscate_push 的四层变换，恢复原始 64 位值。
// - ctx: 只读；encrypted: 混淆后的值。返回: 明文字。
// - 线程: 只读 ctx，可并发；平台: 与 push 使用同一旋转量，无分支差异。
// - 失败语义: ctx 为 NULL 或未初始化时原样返回 encrypted（fail-open）。
uint64_t vm_stack_deobfuscate_pop(const vm_stack_obfuscation_ctx_t *ctx, uint64_t encrypted) {
    if (!ctx || ctx->initialized != VM_STACK_MAGIC_PUSH) {
        return encrypted;  /* 未初始化，直接返回 */
    }

    uint64_t decrypted = encrypted;

    /* 逆向第四层 */
    // 必须严格逆序：先撤最后一层异或，再撤加法、移位，最后撤第一层异或。
    decrypted ^= (ctx->secondary_key + ctx->stack_offset);

    /* 逆向第三层 */
    decrypted -= ctx->stack_offset;

    /* 逆向第二层: 循环右移 */
    decrypted = vm_rotr64(decrypted, ctx->stack_rot);

    /* 逆向第一层 */
    decrypted ^= ctx->stack_xor_key;

    return decrypted;
}

/* 安全压栈操作
 *
 * 自动混淆值并存储到加密栈 */
// 把 value 混淆后压入 stack[*sp]，并把 *sp 前进一格。
// - ctx/stack/sp 任一为 NULL → INVALID_PARAM；stack_size 是元素个数，不是字节数。
// - 返回: VM_STACK_OK / OVERFLOW（*sp>=stack_size）/ NOT_INITIALIZED。
// - 线程: 就地修改 stack、sp、ctx->access_count，调用方必须独占这三个对象。
// - 平台: 无平台分支；不做地址/对齐校验，容量与越界由调用方保证。
// - 失败语义: 失败时不修改栈与 sp；access_count 只在成功路径自增。
int vm_stack_push_obfuscated(vm_stack_obfuscation_ctx_t *ctx,
                            uint64_t *stack,
                            uint32_t *sp,
                            uint32_t stack_size,
                            uint64_t value) {
    if (!ctx || !stack || !sp) {
        return VM_STACK_ERROR_INVALID_PARAM;
    }

    // 先查溢出再混淆：避免做了无用功，也保证失败路径完全不触碰栈。
    if (*sp >= stack_size) {
        return VM_STACK_ERROR_OVERFLOW;
    }

    if (ctx->initialized != VM_STACK_MAGIC_PUSH) {
        return VM_STACK_ERROR_NOT_INITIALIZED;
    }

    /* 混淆值 */
    uint64_t encrypted = vm_stack_obfuscate_push(ctx, value);

    /* 存储到栈 */
    // 栈内存中只有混淆值；明文 value 仅存在于寄存器/调用栈参数上。
    stack[*sp] = encrypted;
    (*sp)++;

    /* 可选: 更新访问计数用于侧信道防护 */
    // 计数只是让每次操作的外部可见状态略有差异，不参与密钥派生，也不是安全边界。
    ctx->access_count++;

    return VM_STACK_OK;
}

/* 安全出栈操作
 *
 * 从加密栈读取并自动解密
 */
// 从 stack[*sp-1] 取出混淆值并解混淆，然后回退 *sp。
// - 参数同 push；out_value 必须非 NULL，用于接收明文。
// - 返回: VM_STACK_OK / UNDERFLOW（*sp==0）/ NOT_INITIALIZED / INVALID_PARAM。
// - 线程: 就地修改 stack 与 sp，需调用方独占；平台: 无分支差异。
// - 失败语义: 失败时 out_value 与 *sp 均不改；成功后旧槽写入 key^offset 而非 0。
int vm_stack_pop_obfuscated(vm_stack_obfuscation_ctx_t *ctx,
                           uint64_t *stack,
                           uint32_t *sp,
                           uint64_t *out_value) {
    if (!ctx || !stack || !sp || !out_value) {
        return VM_STACK_ERROR_INVALID_PARAM;
    }

    if (*sp == 0) {
        return VM_STACK_ERROR_UNDERFLOW;
    }

    if (ctx->initialized != VM_STACK_MAGIC_PUSH) {
        return VM_STACK_ERROR_NOT_INITIALIZED;
    }

    /* 递减栈指针 */
    // 先回退再读取，使 sp 始终等于“有效元素个数”，异常时也不会越过栈顶。
    (*sp)--;

    /* 读取混淆值 */
    uint64_t encrypted = stack[*sp];

    /* 解密 */
    *out_value = vm_stack_deobfuscate_pop(ctx, encrypted);

    /* 清零栈槽 (抗残留攻击) */
    // 写入 key^offset 这个确定性值，而不是 0：让空槽看起来仍像密文，
    // 但它不是安全擦除（值可预测），真正的清理由 vm_stack_obfuscation_clear 负责。
    stack[*sp] = ctx->stack_xor_key ^ ctx->stack_offset;

    /* 更新访问计数 */
    ctx->access_count++;

    return VM_STACK_OK;
}

/* 窥视栈顶值 (不解密)
 *
 * 用于调试或验证，不修改栈状态
 */
// 只读栈顶原始（仍混淆）值，不改变 sp，也不要求 ctx 已初始化。
// - stack/sp/out_encrypted 非 NULL；sp 为当前栈深（值，不是指针）。
// - 返回: VM_STACK_OK / UNDERFLOW / INVALID_PARAM；线程: 只读，可并发。
// - 平台: 无。失败语义: 失败不写 out_encrypted；ctx 在此仅做非空校验，未使用其字段。
int vm_stack_peek_obfuscated(const vm_stack_obfuscation_ctx_t *ctx,
                            const uint64_t *stack,
                            uint32_t sp,
                            uint64_t *out_encrypted) {
    if (!ctx || !stack || !out_encrypted) {
        return VM_STACK_ERROR_INVALID_PARAM;
    }

    if (sp == 0) {
        return VM_STACK_ERROR_UNDERFLOW;
    }

    // 原样返回密文，调用方若需要明文必须自行调用 deobfuscate。
    *out_encrypted = stack[sp - 1];
    return VM_STACK_OK;
}

/* 从中间位置读取并解密
 *
 * 用于本地变量访问
 */
// 读取 stack[index] 并解混淆，供局部变量读取使用。
// - ctx 必须已初始化；index 不做上界校验，调用方需保证 index < 栈容量。
// - 返回: VM_STACK_OK / NOT_INITIALIZED / INVALID_PARAM；线程: 只读 ctx 与 stack。
// - 平台: 无分支。失败语义: 失败不写 out_value；越界属调用方违约，行为未定义。
int vm_stack_load_obfuscated(const vm_stack_obfuscation_ctx_t *ctx,
                            const uint64_t *stack,
                            uint32_t index,
                            uint64_t *out_value) {
    if (!ctx || !stack || !out_value) {
        return VM_STACK_ERROR_INVALID_PARAM;
    }

    if (ctx->initialized != VM_STACK_MAGIC_PUSH) {
        return VM_STACK_ERROR_NOT_INITIALIZED;
    }

    // index 是槽位编号而非字节偏移；栈元素固定为 uint64_t。
    uint64_t encrypted = stack[index];
    *out_value = vm_stack_deobfuscate_pop(ctx, encrypted);

    return VM_STACK_OK;
}

/* 混淆并存储到中间位置
 *
 * 用于本地变量赋值
 */
// 把 value 混淆后写入 stack[index]，不改变栈指针。
// - ctx 必须已初始化；index 不做上界校验，调用方需保证 index < 栈容量。
// - 返回: VM_STACK_OK / NOT_INITIALIZED / INVALID_PARAM。
// - 线程: 独占写 stack[index]；平台: 无。失败语义: 失败不写栈；覆盖写不会先解旧值。
int vm_stack_store_obfuscated(vm_stack_obfuscation_ctx_t *ctx,
                             uint64_t *stack,
                             uint32_t index,
                             uint64_t value) {
    if (!ctx || !stack) {
        return VM_STACK_ERROR_INVALID_PARAM;
    }

    if (ctx->initialized != VM_STACK_MAGIC_PUSH) {
        return VM_STACK_ERROR_NOT_INITIALIZED;
    }

    // 直接写入新混淆值；旧槽内容不参与运算，因此不需要先解混淆。
    stack[index] = vm_stack_obfuscate_push(ctx, value);
    return VM_STACK_OK;
}

/* 安全清除栈混淆上下文
 *
 * 清除所有密钥参数
 */
// 用 cprisk_secure_zero 擦除整个上下文（密钥、计数、标记），NULL 安全。
// 之后若继续调用 push/pop，会因 initialized==0 而 fail-open 返回明文。
// 线程: 需确保没有并发读者；平台: secure_zero 由外部实现保证不被优化掉。
void vm_stack_obfuscation_clear(vm_stack_obfuscation_ctx_t *ctx) {
    if (ctx) {
        cprisk_secure_zero(ctx, sizeof(*ctx));
    }
}

/* 批量加密栈区域
 *
 * 用于初始化或清理栈内存
 */
// 把 [start, start+count) 每个槽位就地混淆；要求 ctx 已初始化。
// - 不做边界检查：start+count 必须落在调用方分配的栈内，否则越界（未定义）。
// - 返回: OK / INVALID_PARAM / NOT_INITIALIZED；线程: 独占修改 stack；平台: 无。
// - 注意: 对已经是混淆态的槽位再次调用会二次混淆；只有确定是明文时才可使用。
int vm_stack_obfuscate_region(vm_stack_obfuscation_ctx_t *ctx,
                            uint64_t *stack,
                            uint32_t start,
                            uint32_t count) {
    if (!ctx || !stack) {
        return VM_STACK_ERROR_INVALID_PARAM;
    }

    if (ctx->initialized != VM_STACK_MAGIC_PUSH) {
        return VM_STACK_ERROR_NOT_INITIALIZED;
    }

    // count 为 0 时循环不执行，直接返回 OK（合法的空操作）。
    for (uint32_t i = 0; i < count; i++) {
        uint64_t original = stack[start + i];
        stack[start + i] = vm_stack_obfuscate_push(ctx, original);
    }

    return VM_STACK_OK;
}

/* 批量解密栈区域
 *
 * 用于栈转储(仅调试使用)
 */
// 把 [start, start+count) 每个槽位就地解混淆（仅调试转储等场景使用）。
// - 不做边界检查；每个槽位必须恰好处于“混淆一次”的状态，重复解会得到垃圾。
// - 返回: OK / INVALID_PARAM / NOT_INITIALIZED；线程: 独占修改 stack；平台: 无。
// - 注意: 解出的明文会留在栈上，调用方应尽快用 secure_zero 覆盖。
int vm_stack_deobfuscate_region(vm_stack_obfuscation_ctx_t *ctx,
                            uint64_t *stack,
                            uint32_t start,
                            uint32_t count) {
    if (!ctx || !stack) {
        return VM_STACK_ERROR_INVALID_PARAM;
    }

    if (ctx->initialized != VM_STACK_MAGIC_PUSH) {
        return VM_STACK_ERROR_NOT_INITIALIZED;
    }

    // 原地覆盖：不保留密文副本，因此该操作不可逆回混淆态以外的历史内容。
    for (uint32_t i = 0; i < count; i++) {
        stack[start + i] = vm_stack_deobfuscate_pop(ctx, stack[start + i]);
    }

    return VM_STACK_OK;
}

/* 验证栈完整性
 *
 * 检测栈是否被篡改
 */
// 启发式完整性检查：仅扫描 [0, sp) 的原始槽值，不依赖 ctx 的密钥。
// - 返回: OK / INVALID_PARAM / NOT_INITIALIZED / CORRUPTED（出现 0 值）。
// - 判定很弱：popcount 极端（<8 或 >56）只 continue，不报错；因此“OK”不代表未被篡改。
// - 线程: 只读；平台: 无。失败语义: 仅返回错误码，不修改栈。
int vm_stack_verify_integrity(const vm_stack_obfuscation_ctx_t *ctx,
                              const uint64_t *stack,
                              uint32_t sp) {
    if (!ctx || !stack) {
        return VM_STACK_ERROR_INVALID_PARAM;
    }

    if (ctx->initialized != VM_STACK_MAGIC_PUSH) {
        return VM_STACK_ERROR_NOT_INITIALIZED;
    }

    /* 简单验证: 检查栈值是否符合加密特征 */
    // sp 不做上界校验，调用方需保证 sp 不超过 stack 容量。
    for (uint32_t i = 0; i < sp; i++) {
        uint64_t value = stack[i];

        /* 混淆值不应等于明文零 */
        // 全零槽极可能来自 memset/未初始化；直接判损坏。
        if (value == 0) {
            return VM_STACK_ERROR_CORRUPTED;
        }

        /* 混淆值应有良好的比特分布 */
        // 逐位统计 1 的个数；仅用于区分“像随机密文”与“像小整数明文”。
        uint64_t popcount = 0;
        uint64_t temp = value;
        while (temp) {
            popcount += temp & 1;
            temp >>= 1;
        }

        /* 如果0或1的比特数极端，可能是未加密数据 */
        // 这里刻意只 continue 不返回错误：启发式误报率高，且该函数不被主路径使用。
        if (popcount < 8 || popcount > 56) {
            /* 可能是明文，继续检查其他槽位 */
            continue;
        }
    }

    return VM_STACK_OK;
}
