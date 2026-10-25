// vm_integrity.c — VM 状态的“累积校验链”实现（FNV-1a 变体）。
// 覆盖范围仅限 vm_integrity_state_t 自身字段（magic/版本/计数/链/tag），不覆盖
// 字节码、寄存器或栈内容；校验时机由调用方决定（事件后 update、关键点 check）。
// 检测失败不崩溃：标记 corrupted 并毒化链，由服务端或上层观察异常结果。
// 状态无锁，每个 VM 一份，只能单线程读写；平台无关（纯整数运算）。
// 本模块在头文件中标注未接入主路径（DEPRECATED），保留供加固层参考。
/*
 * ============================================================================
 * VM状态完整性校验 (vm_integrity.c)
 * ============================================================================
 *
 * 核心加固原理:
 * ------------
 * 1. 运行时自检: 在VM执行过程中持续验证内部状态的一致性
 * 2. 累积校验链: 每条指令执行后更新校验链，检测中间状态篡改
 * 3. 隐式检测: 校验失败不直接报错，而是污染后续计算结果
 * 4. 多维度验证: 同时验证寄存器、栈、PC、执行计数等多个维度
 *
 * 对抗技术:
 * --------
 * - 反内存Patch: 检测到代码/数据篡改时触发毒化
 * - 反调试: 调试器单步执行会破坏校验链的时间连续性
 * - 反Hook: 函数Hook会改变执行流，被校验链捕获
 */

#include "vm_integrity.h"
#include "include/cprisk_secure_zero.h"
#include <string.h>

/* 内部常量 */
// 有效状态标记；check 只认该值，其他值按 INVALID/CORRUPTED 分类。
#define VM_INT_MAGIC_ACTIVE     0x564D5354u  /* "VMST" */
// 已污染标记；handle_tamper 写入，后续 check 直接短路为 CORRUPTED。
#define VM_INT_MAGIC_CORRUPTED  0xDEADCAFEu
// 版本种子基值；init 时与 vm_id 高 32 位异或，check 只比较高 16 位。
#define VM_INT_VERSION_SEED     0x20240703u

/* 计算校验和更新 */
// FNV-1a 变体的一步累积：chain = (chain ^ value) * FNV_PRIME。
// 无密钥、非密码学哈希；顺序敏感，只有相同事件序列才会得到相同链值。纯函数可重入。
static uint64_t vm_int_update_checksum(uint64_t chain, uint64_t value) {
    /* 使用FNV-1a哈希的变体 */
    // 质数选择沿用 FNV-1a 64 位常量；与 vm_hardening 的链保持同源，便于跨模块比对。
    const uint64_t FNV_PRIME = 0x100000001B3ULL;
    chain ^= value;
    chain *= FNV_PRIME;
    return chain;
}

/* 初始化VM完整性状态
 *
 * 安全设计:
 * - Magic值标记状态有效性
 * - 版本种子用于检测不兼容的状态恢复
 * - 校验链初始化为非零值，防止全零状态被误认为有效
 */
// 初始化完整性状态：清零 → 写 magic → 派生 version_seed → 设置 FNV 偏移基 → 生成 tag。
// - state 必须非 NULL；vm_id 用于把状态绑定到具体 VM 实例。
// - 返回: VM_INT_OK / VM_INT_ERROR_INVALID_PARAM。
// - 线程: 写 state 全部字段，调用方需独占；平台: 纯整数运算，无分支差异。
// - 失败语义: 仅参数错误；不写 errno。checksum 初值非零，避免“全零即有效”的误判。
int vm_integrity_init(vm_integrity_state_t *state, uint64_t vm_id) {
    if (!state) {
        return VM_INT_ERROR_INVALID_PARAM;
    }

    memset(state, 0, sizeof(*state));

    state->magic = VM_INT_MAGIC_ACTIVE;
    // 只用 vm_id 的高 32 位：低 32 位常是自增序号，丢弃可降低不同实例初始状态碰撞。
    state->version_seed = VM_INT_VERSION_SEED ^ (uint32_t)(vm_id >> 32);
    state->execution_count = 0;
    // FNV 偏移基非零；check 依赖“执行过之后链不为 0”来判断清零攻击。
    state->checksum_chain = 0xCBF29CE484222325ULL;  /* FNV偏移基础 */

    /* 初始化完整性标签 (简化CPRisk-MAC) */
    // 注意：这只是 vm_id/版本种子的字节展开，不是 MAC，没有密钥参与，不提供认证。
    uint64_t tag_input = vm_id ^ state->version_seed;
    for (int i = 0; i < 8; i++) {
        state->integrity_tag[i] = (uint8_t)(tag_input >> (i * 8));
    }

    return VM_INT_OK;
}

/* 执行校验点检查
 *
 * 校验内容:
 * 1. Magic值有效性
 * 2. 版本种子一致性
 * 3. 执行计数单调递增
 * 4. 校验链连续性
 * 5. 完整性标签有效性
 */
// 只读校验：按顺序检查 magic、版本高 16 位、计数溢出哨兵、链非零、tag 非全零。
// - state 非 NULL；NULL 返回 VM_INT_RESULT_ERROR。
// - 返回: OK / CORRUPTED / INVALID / VERSION_MISMATCH / OVERFLOW / CHAIN_BROKEN / TAG_INVALID。
// - 线程: 只读，但若与 update/handle_tamper 并发会读到撕裂状态；需外部串行。
// - 平台: 无。失败语义: 只返回分类，不修改 state。
// - 注意: 这是自洽性检查，不验证来源；攻击者可构造同样通过检查的完整状态。
vm_integrity_result_t vm_integrity_check(const vm_integrity_state_t *state) {
    if (!state) {
        return VM_INT_RESULT_ERROR;
    }

    /* 检查Magic值 */
    // magic 是唯一的“状态是否可用”开关；CORRUPTED 与任意其他值分开报告，便于上层统计。
    if (state->magic != VM_INT_MAGIC_ACTIVE) {
        if (state->magic == VM_INT_MAGIC_CORRUPTED) {
            /* 已知损坏状态 */
            return VM_INT_RESULT_CORRUPTED;
        }
        return VM_INT_RESULT_INVALID;
    }

    /* 检查版本种子 */
    // 只比较高 16 位：低 16 位允许承载实例差异，避免版本检查过严导致跨实例误报。
    uint32_t expected_seed = VM_INT_VERSION_SEED;
    if ((state->version_seed & 0xFFFF0000u) != (expected_seed & 0xFFFF0000u)) {
        return VM_INT_RESULT_VERSION_MISMATCH;
    }

    /* 检查执行计数 (防止回滚) */
    // 全 1 作为溢出/中毒哨兵；正常执行远远达不到，出现即视为状态异常。
    if (state->execution_count == 0xFFFFFFFFFFFFFFFFULL) {
        return VM_INT_RESULT_OVERFLOW;
    }

    /* 校验链不应为零 (除非刚初始化) */
    // init 后计数为 0，链允许是初值；只要执行过，FNV 链被清零就说明可能被置零攻击。
    if (state->execution_count > 0 && state->checksum_chain == 0) {
        return VM_INT_RESULT_CHAIN_BROKEN;
    }

    /* 完整性标签基础检查 */
    // 用按位或而不是求和：只要有一个字节非零就认为 tag 存在，避免回绕抵消除。
    uint8_t tag_sum = 0;
    for (int i = 0; i < 8; i++) {
        tag_sum |= state->integrity_tag[i];
    }
    if (tag_sum == 0) {
        return VM_INT_RESULT_TAG_INVALID;
    }

    return VM_INT_RESULT_OK;
}

/* 更新完整性状态
 *
 * 更新内容:
 * - 执行计数递增
 * - 校验链累积当前操作
 * - 定期刷新完整性标签
 */
// 推进一次完整性事件：先自检，再把 (event<<56 | data 低 56 位) 折入链并计数。
// - state 非 NULL；event 只占高 8 位，event_data 超过 56 位的部分被截断。
// - 返回: VM_INT_OK / INVALID_PARAM / VM_INT_ERROR_CORRUPTED。
// - 线程: 读写 state，禁止并发；平台: 无。
// - 失败语义: 自检失败时把 magic 改为 CORRUPTED 并返回错误，不抛异常。
// - 每 256 次刷新 tag（与链和计数绑定），用于发现整段状态回滚。
int vm_integrity_update(vm_integrity_state_t *state,
                        vm_integrity_event_t event,
                        uint64_t event_data) {
    if (!state) {
        return VM_INT_ERROR_INVALID_PARAM;
    }

    /* 先检查当前状态 */
    // 每次更新前自检，把“第一次发现异常”的时刻记在 magic 上，后续更新全部快速失败。
    vm_integrity_result_t check = vm_integrity_check(state);
    if (check != VM_INT_RESULT_OK) {
        /* 状态已损坏，标记并返回 */
        state->magic = VM_INT_MAGIC_CORRUPTED;
        return VM_INT_ERROR_CORRUPTED;
    }

    /* 执行计数递增 */
    state->execution_count++;

    /* 根据事件类型更新校验链 */
    // 高 8 位编码事件类型，低 56 位保留数据；避免不同类型+数据的组合碰撞成同一输入。
    uint64_t value_to_mix = ((uint64_t)event << 56) | (event_data & 0x00FFFFFFFFFFFFFFULL);
    state->checksum_chain = vm_int_update_checksum(state->checksum_chain, value_to_mix);

    /* 每256次执行刷新完整性标签 */
    if ((state->execution_count & 0xFF) == 0) {
        // tag 同时绑定链与计数；逐字节异或 i*0x5A 让 8 个字节不会全部相同。
        uint64_t new_tag_seed = state->checksum_chain ^ state->execution_count;
        for (int i = 0; i < 8; i++) {
            state->integrity_tag[i] = (uint8_t)(new_tag_seed >> (i * 8));
            /* 添加一些混淆 */
            state->integrity_tag[i] ^= (uint8_t)(i * 0x5A);
        }
    }

    return VM_INT_OK;
}

/* 处理完整性破坏事件
 *
 * 毒化策略:
 * - 不立即崩溃或报错
 * - 标记状态为损坏
 * - 后续计算将产生错误结果
 * - 服务端可通过校验和检测异常
 */
// 处理已确认的篡改：置 CORRUPTED，按违规类型污染链/tag，并把计数写成哨兵。
// - state NULL 时无操作；violation 仅作为加数混入，不做范围校验。
// - 返回: 无；线程: 独占写；平台: 无。
// - 失败语义: 设计上不崩溃、不返回错误，让后续计算静默产出错误结果。
void vm_integrity_handle_tamper(vm_integrity_state_t *state,
                                vm_integrity_violation_t violation) {
    if (!state) {
        return;
    }

    /* 标记状态为损坏 */
    state->magic = VM_INT_MAGIC_CORRUPTED;

    /* 污染校验链，使后续验证失败 */
    // 用固定魔数异或 + 违规类型加数：即使攻击者知道违规类型，也无法把链恢复到原值。
    state->checksum_chain ^= 0xDEADBEEFCAFEBABEULL;
    state->checksum_chain += (uint64_t)violation;

    /* 污染完整性标签 */
    // 逐字节取反偏移，确保 tag 不再匹配任何正常刷新结果。
    for (int i = 0; i < 8; i++) {
        state->integrity_tag[i] ^= (uint8_t)(0xFF - i);
    }

    /* 执行计数设置为异常值 */
    // 该值既不是正常计数也不是全 1，后续 verify_sequence 的差值检查会立即失配。
    state->execution_count = 0xDEADBEEFCAFEBABEULL;
}

/* 验证特定操作序列的完整性
 *
 * 用于验证一段字节码执行过程中是否被篡改
 */
// 校验两段状态之间是否恰好执行了 expected_step_count 步，且链确实发生变化。
// - 两个 state 非 NULL 且都必须通过 vm_integrity_check。
// - 返回: OK / INVALID_PARAM / CORRUPTED / STEP_MISMATCH / CHAIN_UNCHANGED。
// - 线程: 只读快照，调用方须保证快照期间无并发更新；平台: 无。
// - 限制: 只检查步数与“链变了”，无法证明中间操作序列正确；计数回绕也会误判。
int vm_integrity_verify_sequence(const vm_integrity_state_t *state_before,
                                  const vm_integrity_state_t *state_after,
                                  uint32_t expected_step_count) {
    if (!state_before || !state_after) {
        return VM_INT_ERROR_INVALID_PARAM;
    }

    /* 检查两个状态都有效 */
    // 任一快照已损坏就无法做差分，直接归为 CORRUPTED 而非 STEP_MISMATCH。
    if (vm_integrity_check(state_before) != VM_INT_RESULT_OK ||
        vm_integrity_check(state_after) != VM_INT_RESULT_OK) {
        return VM_INT_ERROR_CORRUPTED;
    }

    /* 验证执行步数 */
    // 无符号减法：若 after < before（回滚），差值会变成巨大数，从而与期望值失配。
    uint64_t actual_steps = state_after->execution_count - state_before->execution_count;
    if (actual_steps != expected_step_count) {
        return VM_INT_ERROR_STEP_MISMATCH;
    }

    /* 验证校验链连续性 */
    // expected_chain 仅作占位：完整验证需要重放中间事件，这里只做变化性检查。
    uint64_t expected_chain = state_before->checksum_chain;
    /* 这里需要知道中间操作才能完整验证，简化检查 */
    // 执行了指令链却原地不动，通常意味着更新被 Hook 跳过或状态来自旧快照。
    if (state_after->checksum_chain == state_before->checksum_chain) {
        /* 如果执行了指令但校验链未变化，可能是被Hook */
        return VM_INT_ERROR_CHAIN_UNCHANGED;
    }

    return VM_INT_OK;
}

/* 导出完整性状态 (用于持久化或传输) */
// 导出状态原始字节（memcpy 整个结构体），导出前先自检。
// - buffer_size 必须 >= sizeof(state)，否则返回 0；任一指针 NULL 同样返回 0。
// - 返回: 写入字节数；失败 0。线程: 只读 state；平台: 原始内存布局，跨端/跨版本不可互通。
// - 注意: 导出数据无认证，接收方不能仅凭它能通过 check 就相信其来源。
size_t vm_integrity_export(const vm_integrity_state_t *state,
                           uint8_t *out_buffer,
                           size_t buffer_size) {
    if (!state || !out_buffer || buffer_size < sizeof(vm_integrity_state_t)) {
        return 0;
    }

    /* 先验证状态有效 */
    // 导出一个已损坏的状态没有意义，还可能导致接收方误判，因此直接拒绝。
    if (vm_integrity_check(state) != VM_INT_RESULT_OK) {
        return 0;
    }

    // 直接按内存布局复制：magic/计数/链/tag 都会被序列化；整数端序随平台变化。
    memcpy(out_buffer, state, sizeof(vm_integrity_state_t));
    return sizeof(vm_integrity_state_t);
}

/* 导入完整性状态 */
// 导入状态字节并自检；失败时把目标清零，避免留下半有效状态。
// - data_size 必须 >= sizeof(state)；任一指针 NULL 返回 INVALID_PARAM。
// - 返回: VM_INT_OK / INVALID_PARAM / CORRUPTED。
// - 线程: 写 state，需独占；平台: 依赖导出端的内存布局与版本。
// - 失败语义: 校验不通过时 memset 清零并返回错误，不保留攻击者提供的字段。
int vm_integrity_import(vm_integrity_state_t *state,
                        const uint8_t *data,
                        size_t data_size) {
    if (!state || !data || data_size < sizeof(vm_integrity_state_t)) {
        return VM_INT_ERROR_INVALID_PARAM;
    }

    memcpy(state, data, sizeof(vm_integrity_state_t));

    /* 验证导入的状态 */
    // 只做自洽性检查：能构造出自洽状态的攻击者仍可通过，导入数据本身没有来源认证。
    vm_integrity_result_t check = vm_integrity_check(state);
    if (check != VM_INT_RESULT_OK) {
        // 清零而不是保留失败内容：调用方后续若忘记检查返回值，也不会使用半损坏状态。
        memset(state, 0, sizeof(vm_integrity_state_t));
        return VM_INT_ERROR_CORRUPTED;
    }

    return VM_INT_OK;
}

/* 安全清除完整性状态 */
// 用 cprisk_secure_zero 擦除整个状态（含链与 tag），NULL 安全；重复调用无副作用。
// 擦除后 magic 为 0，任何 check 都会返回 INVALID，调用方必须重新 init 才能使用。
void vm_integrity_clear(vm_integrity_state_t *state) {
    if (state) {
        cprisk_secure_zero(state, sizeof(*state));
    }
}

/* 生成调试信息 (仅用于开发调试) */
// 仅当定义 VM_INTEGRITY_DEBUG 时编译；发布构建中该函数不存在，不要无条件引用。
#ifdef VM_INTEGRITY_DEBUG
#include <stdio.h>
// 把状态字段与 check 结果打印到 stdout；state 为 NULL 时打印提示后返回。
// 返回: 无；线程: 直接使用 printf，非线程安全；平台: 仅调试构建可用。
// 失败语义: 无错误处理；仅用于开发诊断，不要在崩溃/信号处理路径调用。
void vm_integrity_dump(const vm_integrity_state_t *state) {
    if (!state) {
        printf("VM Integrity State: NULL\n");
        return;
    }

    printf("=== VM Integrity State ===\n");
    printf("Magic: 0x%08X (%s)\n",
           state->magic,
           state->magic == VM_INT_MAGIC_ACTIVE ? "ACTIVE" :
           state->magic == VM_INT_MAGIC_CORRUPTED ? "CORRUPTED" : "UNKNOWN");
    printf("Version Seed: 0x%08X\n", state->version_seed);
    printf("Execution Count: %llu\n", (unsigned long long)state->execution_count);
    printf("Checksum Chain: 0x%016llX\n", (unsigned long long)state->checksum_chain);
    printf("Integrity Tag: ");
    for (int i = 0; i < 8; i++) {
        printf("%02X", state->integrity_tag[i]);
    }
    printf("\n");

    vm_integrity_result_t check = vm_integrity_check(state);
    printf("Check Result: %d (%s)\n", check,
           check == VM_INT_RESULT_OK ? "OK" :
           check == VM_INT_RESULT_CORRUPTED ? "CORRUPTED" :
           check == VM_INT_RESULT_INVALID ? "INVALID" : "OTHER");
    printf("==========================\n");
}
#endif
