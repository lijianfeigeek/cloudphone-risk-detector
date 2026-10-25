// vm_whitebox_bind.c — VM 密钥层级与白盒 PRF 的绑定（纯密钥派生，不执行 PRF）。
// 层级：device_binding + whitebox_key → root_key → func_key → 各用途 operation_key；
// 每层用 SHA-256 加域标签（ROOT/FUNC/OP）隔离，避免同一密钥材料跨用途复用。
// 所有函数无全局可变状态、不分配堆内存、不持锁，可并发调用；缓冲区由调用方
// 提供并负责清零。失败一律返回负错误码（fail-closed），不写 errno；平台无关。
// 注意：本模块在头文件中标记 DEPRECATED，未接入生产主路径。
/*
 *  vm_whitebox_bind.c
 *  CRiskCore
 */

#include "vm_whitebox_bind.h"
#include "include/cprisk_secure_zero.h"
#include "include/cprisk_sha256.h"
#include <string.h>

// 域分隔标签，ASCII 为 "ROOT_DERIVE_V1" 后接 2 个 0。长度与字节内容都是协议常量；
// 任何改动都会让已派生密钥失效，并破坏与固件/服务端的跨版本一致性。
static const uint8_t LABEL_ROOT[16] = {
    0x52, 0x4F, 0x4F, 0x54, 0x5F, 0x44, 0x45, 0x52,
    0x49, 0x56, 0x45, 0x5F, 0x56, 0x31, 0x00, 0x00
};

// "FUNC_DERIVE_V1" + 2 个 0：函数密钥域，防止与 ROOT/OP 域在相同输入下碰撞。
static const uint8_t LABEL_FUNC[16] = {
    0x46, 0x55, 0x4E, 0x43, 0x5F, 0x44, 0x45, 0x52,
    0x49, 0x56, 0x45, 0x5F, 0x56, 0x31, 0x00, 0x00
};

// "OP_DERIVE_V1" + 3 个 0：操作密钥域。调用处只复制前 15 字节，使
// 32(func_key)+1(key_type)+16(context)+15(label) 恰好等于 64 字节输入缓冲区。
static const uint8_t LABEL_OP[16] = {
    0x4F, 0x50, 0x5F, 0x44, 0x45, 0x52, 0x49, 0x56,
    0x45, 0x5F, 0x56, 0x31, 0x00, 0x00, 0x00, 0x00
};

// 计算函数身份摘要：SHA-256(addr(8) || compile_salt(16) || 0…0(8) || LABEL_FUNC(16))。
// - func_ptr 允许为 NULL（取地址 0 参与哈希）；compile_salt/out_hash 必须非 NULL。
// - 返回: 无；out_hash 由调用方提供 32 字节，函数不校验其大小。
// - 线程: 全部状态在栈上，可重入；平台: 指针→uintptr_t 转换在 Apple 64 位上成立。
// - 注意: PIE/ASLR 使地址每次启动不同，结果不能当持久化 ID；salt 用于跨构建去相关。
// - 失败语义: 无失败路径；结束时擦除 48 字节中间缓冲。
void vm_wb_hash_function_identity(void (*func_ptr)(void),
                                   const uint8_t compile_salt[16],
                                   uint8_t out_hash[32]) {
    uint8_t input[48];
    // 函数地址是运行时值；同一二进制在不同启动/不同设备上会得到不同摘要。
    uint64_t addr = (uint64_t)(uintptr_t)func_ptr;

    // 固定布局：8 字节地址、16 字节构建盐、随后 8 字节零填充 + 16 字节域标签。
    memcpy(input, &addr, sizeof(addr));
    memcpy(input + 8, compile_salt, 16);
    memset(input + 24, 0, 24);

    // 覆盖 input[24..39]，把 LABEL_FUNC 放到固定偏移，剩余 input[40..47] 保持零。
    for (int i = 0; i < 16; i++) {
        input[24 + i] = LABEL_FUNC[i];
    }

    cprisk_sha256(input, 48, out_hash);
    // 地址与盐不是秘密，但仍统一擦除，减少栈上可被转储的身份材料。
    cprisk_secure_zero(input, sizeof(input));
}

// 两阶段派生根密钥：r1=SHA256(device_binding||whitebox_key||LABEL_ROOT)，
// root=SHA256(r1||同一输入)。第二阶段把输出与完整输入再次绑定，避免仅凭 r1 反推用途。
// - 三个指针都必须非 NULL，各 32 字节；out_root_key 由调用方拥有。
// - 返回: VM_WB_OK / VM_WB_ERROR_INVALID_PARAM。
// - 线程: 无共享状态，可并发；平台: SHA-256 实现无关。
// - 失败语义: 参数错误直接返回，不写 errno、不触碰 out_root_key。
int vm_wb_derive_root_key(const uint8_t device_binding[32],
                          const uint8_t whitebox_key[32],
                          uint8_t out_root_key[32]) {
    if (!device_binding || !whitebox_key || !out_root_key) {
        return VM_WB_ERROR_INVALID_PARAM;
    }

    // 80 = 32 设备绑定 + 32 白盒密钥 + 16 域标签；顺序固定，不能重排。
    uint8_t derive_input[80];
    memcpy(derive_input, device_binding, 32);
    memcpy(derive_input + 32, whitebox_key, 32);
    memcpy(derive_input + 64, LABEL_ROOT, 16);

    cprisk_sha256(derive_input, 80, out_root_key);

    // 第二遍把 r1 与完整输入一起再哈希：输出同时依赖“第一遍结果”和“原始材料”。
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, out_root_key, 32);
    cprisk_sha256_update(&ctx, derive_input, 80);
    cprisk_sha256_final(&ctx, out_root_key);

    cprisk_secure_zero(derive_input, sizeof(derive_input));
    return VM_WB_OK;
}

/* 从根密钥派生函数专用密钥
 *
 * 每个受保护函数调用一次
 */
// 从根密钥派生函数专用密钥：SHA256(root_key || func_id(8, 主机字节序) || LABEL_FUNC)。
// - root_key/out_func_key 非 NULL，各 32 字节；func_id 按内存原样参与哈希。
// - 返回: VM_WB_OK / INVALID_PARAM；线程安全、可重入；平台无关。
// - 注意: func_id 未做字节序归一，跨大端/小端平台派生结果不同，不可互通。
// - 失败语义: 参数错误不写输出；成功路径擦除 56 字节中间缓冲。
int vm_wb_derive_function_key(const uint8_t root_key[32],
                              uint64_t func_id,
                              uint8_t out_func_key[32]) {
    if (!root_key || !out_func_key) {
        return VM_WB_ERROR_INVALID_PARAM;
    }

    /* 构造派生输入 */
    // 56 = 32 根密钥 + 8 func_id + 16 域标签；func_id 直接取内存字节，未做归一化。
    uint8_t derive_input[56];
    memcpy(derive_input, root_key, 32);
    memcpy(derive_input + 32, &func_id, sizeof(func_id));
    memcpy(derive_input + 40, LABEL_FUNC, 16);

    cprisk_sha256(derive_input, 56, out_func_key);

    cprisk_secure_zero(derive_input, sizeof(derive_input));
    return VM_WB_OK;
}

/* 从函数密钥派生操作密钥
 *
 * 用于特定的VM操作(编码、加解密等)
 */
// 从函数密钥派生某用途的操作密钥：
// SHA256(func_key || key_type(1) || context(16) || LABEL_OP 前 15 字节)。
// - 非 NULL 要求同前；key_type 只取低 8 位，是用途域的主分隔符。
// - 返回: VM_WB_OK / INVALID_PARAM；线程安全；平台无关（依赖枚举数值稳定）。
// - context 用于同一用途下的子域绑定（如不同阶段），全 0 也是合法输入。
// - 失败语义: 参数错误不写输出；成功时擦除 64 字节中间缓冲。
int vm_wb_derive_operation_key(const uint8_t func_key[32],
                               vm_wb_key_type_t key_type,
                               const uint8_t context[16],
                               uint8_t out_op_key[32]) {
    if (!func_key || !context || !out_op_key) {
        return VM_WB_ERROR_INVALID_PARAM;
    }

    /* 构造派生输入 */
    // 64 = 32 密钥 + 1 类型 + 16 上下文 + 15 标签；标签只取 15 字节以精确填满。
    uint8_t derive_input[64];
    memcpy(derive_input, func_key, 32);
    derive_input[32] = (uint8_t)key_type;
    memcpy(derive_input + 33, context, 16);
    memcpy(derive_input + 49, LABEL_OP, 15);

    cprisk_sha256(derive_input, 64, out_op_key);

    cprisk_secure_zero(derive_input, sizeof(derive_input));
    return VM_WB_OK;
}

/* 初始化VM的完整密钥派生
 *
 * 一键派生所有VM参数
 */
// 一次性派生 frame 所需的全套密钥并写入 out_keys（root 不导出）。
// - params/out_keys 非 NULL；params 内的 device_binding/whitebox_key 由调用方提供。
// - 返回: VM_WB_OK；参数错误或根/函数密钥派生失败时返回对应负错误码。
// - 线程: 无全局状态，可并发，但 out_keys 需由调用方独占；平台无关。
// - 失败语义: 提前返回时已写入的 out_keys 字段不会回滚，调用方应视为不可用并清空。
int vm_wb_init_vm_keys(const vm_wb_binding_params_t *params,
                       vm_wb_derived_keys_t *out_keys) {
    if (!params || !out_keys) {
        return VM_WB_ERROR_INVALID_PARAM;
    }

    /* 派生根密钥 */
    // root_key 只在栈上短暂存在，成功/失败路径都必须擦除（本函数末尾统一处理）。
    uint8_t root_key[32];
    int ret = vm_wb_derive_root_key(params->device_binding,
                                     params->whitebox_key,
                                     root_key);
    if (ret != VM_WB_OK) {
        return ret;
    }

    /* 派生函数专用密钥 */
    ret = vm_wb_derive_function_key(root_key, params->func_id, out_keys->func_key);
    if (ret != VM_WB_OK) {
        cprisk_secure_zero(root_key, sizeof(root_key));
        return ret;
    }

    /* 派生各类操作密钥 */
    // 上下文前 8 字节放 func_id，其余为 0；随后每个用途只改 context[0] 做子域扰动。
    // 真正的域分隔仍靠 key_type 字节，context 只提供额外的函数/阶段绑定。
    uint8_t context[16];
    memset(context, 0, sizeof(context));
    memcpy(context, &params->func_id, sizeof(params->func_id));

    /* 字节码编码密钥 */
    // 以下 derive_operation_key 均只会因 NULL 失败，而此处指针都有效，故忽略返回值；
    // 若将来该函数增加失败条件，必须在此补错误处理。
    vm_wb_derive_operation_key(out_keys->func_key,
                                VM_WB_KEY_BYTECODE,
                                context,
                                out_keys->bytecode_key);

    /* 栈加密密钥 */
    // 注意：0x01/0x02/0x03… 是累积异或（不是赋值），相邻用途的 context[0] 可能相同，
    // 但 key_type 不同，派生输入仍然不同；不要依赖 context 唯一性来做域分隔。
    context[0] ^= 0x01;
    vm_wb_derive_operation_key(out_keys->func_key,
                                VM_WB_KEY_STACK,
                                context,
                                out_keys->stack_key);

    /* 内存加密密钥 */
    context[0] ^= 0x02;
    vm_wb_derive_operation_key(out_keys->func_key,
                                VM_WB_KEY_MEMORY,
                                context,
                                out_keys->memory_key);

    /* 完整性校验密钥 */
    context[0] ^= 0x03;
    vm_wb_derive_operation_key(out_keys->func_key,
                                VM_WB_KEY_INTEGRITY,
                                context,
                                out_keys->integrity_key);

    /* 反调试密钥 */
    context[0] ^= 0x04;
    vm_wb_derive_operation_key(out_keys->func_key,
                                VM_WB_KEY_ANTIDEBUG,
                                context,
                                out_keys->antidebug_key);

    /* 毒化密钥 */
    context[0] ^= 0x05;
    vm_wb_derive_operation_key(out_keys->func_key,
                                VM_WB_KEY_POISON,
                                context,
                                out_keys->poison_key);

    /* 导出func_id */
    // func_id 明文放入结果，便于调用方校验这批密钥确实属于该函数。
    out_keys->func_id = params->func_id;

    /* 清理中间密钥 */
    // 只擦除 root_key；func_key 等输出密钥归调用方所有，生命周期由其管理。
    cprisk_secure_zero(root_key, sizeof(root_key));

    return VM_WB_OK;
}

/* 派生编码专用参数
 *
 * 从字节码密钥派生具体的编码参数
 */
// 从 32 字节字节码密钥切分编码参数（纯字节拼装，无哈希、无失败返回）。
// - 任一参数为 NULL 时静默返回；out_params 由调用方提供完整结构体。
// - 返回: 无；线程: 无共享状态；平台: 依赖小端拼装，跨端结果不同。
// - 失败语义: 无错误码；参数错误时不写 out_params，调用方无法区分。
void vm_wb_derive_encoding_params(const uint8_t bytecode_key[32],
                                  vm_wb_encoding_params_t *out_params) {
    if (!bytecode_key || !out_params) {
        return;
    }

    /* 操作码异或密钥: 前4字节 */
    // 各字段按固定偏移切片，互不重叠（stream_key 的复制来源 24..31 与 perm_seed 部分重叠）。
    out_params->opcode_xor_key = 0;
    for (int i = 0; i < 4; i++) {
        out_params->opcode_xor_key |= ((uint32_t)bytecode_key[i]) << (i * 8);
    }

    /* 操作数盐值: 第4-11字节 */
    out_params->operand_salt = 0;
    for (int i = 0; i < 8; i++) {
        out_params->operand_salt |= ((uint64_t)bytecode_key[i + 4]) << (i * 8);
    }

    /* 调度种子: 第12-19字节 */
    out_params->dispatch_seed = 0;
    for (int i = 0; i < 8; i++) {
        out_params->dispatch_seed |= ((uint64_t)bytecode_key[i + 12]) << (i * 8);
    }

    /* 置换表种子: 第20-27字节 */
    out_params->perm_seed = 0;
    for (int i = 0; i < 8; i++) {
        out_params->perm_seed |= ((uint64_t)bytecode_key[i + 20]) << (i * 8);
    }

    /* 流加密密钥: 第28-32字节复制扩展 */
    // 实际复制的是 key[24..31]（与 perm_seed 尾部重叠），不是注释所说的“第 28-32 字节”；
    // 两者共享字节但用途不同，不会互相破坏，只是不能把这两个字段当作独立熵源。
    memcpy(out_params->stream_key, bytecode_key + 24, 8);
    /* 扩展填充 */
    // 只用到 key[0..7] 与下标 i：key[8..23] 并未参与 stream_key 扩展，熵低于表面长度。
    for (int i = 8; i < 32; i++) {
        out_params->stream_key[i] = bytecode_key[i % 8] ^ (uint8_t)i;
    }
}

/* 派生栈加密参数
 *
 * 从栈密钥派生具体的栈加密参数
 */
// 从 32 字节栈密钥与 func_id 派生与 vm_stack_crypto 兼容的混淆参数。
// - 入参非 NULL；func_id 必须与混淆/去混淆时一致，否则解出的值是垃圾。
// - 返回: 无；参数 NULL 时静默返回。线程安全；平台: 小端拼装。
// - 注意: 与 vm_stack_obfuscation_init 的切片偏移不同，两套上下文不可混用。
// - 失败语义: 无错误码；参数错误时不写 out_params。
void vm_wb_derive_stack_params(const uint8_t stack_key[32],
                               uint64_t func_id,
                               vm_wb_stack_params_t *out_params) {
    if (!stack_key || !out_params) {
        return;
    }

    /* 异或密钥: 前8字节与func_id混合 */
    // 布局：xor_key=[0..7]^func_id；rot=[8]；offset=[9..16]；secondary=[17..24]。
    out_params->stack_xor_key = 0;
    for (int i = 0; i < 8; i++) {
        out_params->stack_xor_key |= ((uint64_t)stack_key[i]) << (i * 8);
    }
    out_params->stack_xor_key ^= func_id;

    /* 旋转量: 第8字节取低6位 */
    // 低 6 位给出 0..63；低于 8 时用 8+(低3位) 重映射到 8..15，避开 0/64 的未定义移位。
    out_params->stack_rot = stack_key[8] & 0x3F;
    if (out_params->stack_rot < 8) {
        out_params->stack_rot = 8 + (stack_key[8] & 0x07);
    }

    /* 偏移量: 第9-16字节 */
    out_params->stack_offset = 0;
    for (int i = 0; i < 8; i++) {
        out_params->stack_offset |= ((uint64_t)stack_key[i + 9]) << (i * 8);
    }
    // func_id 左移 1 位再异或，避免两个连续 func_id 只差最低位。
    out_params->stack_offset ^= (func_id << 1);

    /* 次级密钥: 第17-24字节 */
    out_params->secondary_key = 0;
    for (int i = 0; i < 8; i++) {
        out_params->secondary_key |= ((uint64_t)stack_key[i + 17]) << (i * 8);
    }
    // 与 offset 使用相反的移位方向，降低两段派生值同步变化的相关性。
    out_params->secondary_key ^= (func_id >> 1);
}

/* 生成毒化值
 *
 * 从毒化密钥派生特定用途的毒化值
 */
// 从毒化密钥派生 64 位毒化值（用于污染评分/ID/报告等）。
// - poison_key 为 NULL 时返回固定哨兵 0xDEADBEEFCAFEBABE。
// - 读取起点为 (uint8_t)poison_type 的 8 字节，因此要求 type<=24；否则会越界读
//   （当前枚举只有 0..4，调用方不得把任意整数强转后传入）。
// - 返回: 派生值；无错误码。线程安全；平台: 小端拼装。
// - 失败语义: 无；NULL 输入的哨兵是确定性常量，不可当作安全随机数。
uint64_t vm_wb_derive_poison_value(const uint8_t poison_key[32],
                                    vm_wb_poison_type_t poison_type) {
    if (!poison_key) {
        return 0xDEADBEEFCAFEBABEULL;
    }

    /* 简单派生: 密钥异或 + 类型偏移 */
    // 用类型值作为字节偏移选中密钥的一段；不同毒化用途因此得到不同 8 字节窗口。
    uint64_t poison = 0;
    for (int i = 0; i < 8; i++) {
        poison |= ((uint64_t)poison_key[i + (uint8_t)poison_type]) << (i * 8);
    }

    /* 混合类型标识 */
    // 把类型放到最高字节，再异或固定哨兵，使同一窗口的不同类型也不会得到同值。
    poison ^= ((uint64_t)poison_type << 56);
    poison ^= 0xDEADBEEFCAFEBABEULL;

    return poison;
}

/* 安全清除派生密钥 */
// 用 cprisk_secure_zero 擦除整套派生密钥（含 func_id），NULL 安全。
// 调用方在 vm_wb_init_vm_keys 失败或密钥使用完毕后必须调用；重复调用无副作用。
void vm_wb_clear_derived_keys(vm_wb_derived_keys_t *keys) {
    if (keys) {
        cprisk_secure_zero(keys, sizeof(*keys));
    }
}
