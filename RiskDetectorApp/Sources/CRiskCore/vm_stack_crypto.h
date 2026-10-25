// 文件职责：VM 栈值的 XOR/ROTL/ADD 混淆与去混淆（是混淆，不是加密）。
// 现状：未接入主路径（issue 65）；无认证、无密钥扩展，已知明文可直接恢复密钥流。
// 密钥来源：调用方提供的 32 字节 master_key 与 func_id 派生，本模块不生成随机数。
// 线程模型：ctx 无锁、每函数一份；push/pop 会改 access_count，需单线程串行。
// 失败语义：未初始化/NULL 的纯混淆 API fail-open（原值直通）；带栈操作返回负错误码。
/*
 * ============================================================================
 * VM堆栈混淆保护头文件 (vm_stack_crypto.h)
 * ============================================================================
 * DEPRECATED / 未接入主路径：无生产调用方（仅自身内部调用），不要接入主路径。
 * OBFUSCATION, NOT ENCRYPTION（问题 43）：本模块是 XOR / ROTL / ADD 混淆，
 * 不是加密——没有认证、没有密钥扩展、已知明文下可直接逆推；它只能让栈
 * 内容在内存转储里不那么直观，绝不能当作机密性保护。
 * ============================================================================
 *
 * 设计目标:
 * --------
 * 1. 透明性: VM解释器无需关心加解密细节
 * 2. 安全性: 多层混淆，抗已知明文攻击
 * 3. 性能: 轻量级操作，不影响VM执行速度
 * 4. 兼容性: 与现有VM栈设计兼容
 */

#ifndef VM_STACK_CRYPTO_H
#define VM_STACK_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 栈混淆上下文：三个 64 位混合参数 + 旋转量 + 访问计数 + 初始化标记。
// stack_rot 为循环移位量 0..63（init 实际夹到 8..63）；initialized 为 0x50555348（"PUSH"）。
// 所有权：全部内联，无堆指针。注意这些参数可被内存读取者直接用于逆变换，不是机密性边界。
/* 栈混淆上下文结构体
 *
 * 每个受保护的VM函数拥有独立的上下文
 */
typedef struct {
    uint64_t stack_xor_key;     /* 栈异或密钥 */
    uint8_t  stack_rot;         /* 循环旋转量 (0-63) */
    uint64_t stack_offset;      /* 加法偏移量 */
    uint64_t secondary_key;     /* 次级混合密钥 */
    uint32_t access_count;      /* 访问计数 (侧信道防护) */
    uint32_t initialized;       /* 初始化标记 */
} vm_stack_obfuscation_ctx_t;

// 错误码：0 成功，负值失败；OVERFLOW/UNDERFLOW 只由带 sp 的栈操作返回，
// CORRUPTED 仅由启发式 verify_integrity 返回。
/* 错误码 */
typedef enum {
    VM_STACK_OK = 0,
    VM_STACK_ERROR_INVALID_PARAM = -1,
    VM_STACK_ERROR_NOT_INITIALIZED = -2,
    VM_STACK_ERROR_OVERFLOW = -3,
    VM_STACK_ERROR_UNDERFLOW = -4,
    VM_STACK_ERROR_CORRUPTED = -5
} vm_stack_error_t;

// 从 master_key(32) 与 func_id 派生四段参数并置 initialized；失败时 ctx 保持全零。
// ctx/master_key 非 NULL；成功 0，失败 INVALID_PARAM（后续 API 将 fail-open）。
// 写 ctx 全部字段，需独占；纯整数运算，平台无关。
/* 初始化栈混淆上下文
 *
 * 从主密钥派生所有栈混淆参数
 */
int vm_stack_obfuscation_init(vm_stack_obfuscation_ctx_t *ctx,
                         uint64_t func_id,
                         const uint8_t master_key[32]);

// 四层混淆：XOR → ROTL → +offset → XOR(secondary+offset)；ctx 只读。
// ctx NULL 或未初始化时原样返回 value（fail-open）；无错误码，可并发读同一 ctx。
/* 混淆压栈值
 *
 * 流程: value -> XOR -> ROTL -> ADD -> XOR_SECONDARY
 */
uint64_t vm_stack_obfuscate_push(const vm_stack_obfuscation_ctx_t *ctx, uint64_t value);

// 严格逆序撤销四层变换；ctx NULL 或未初始化时原样返回输入（fail-open）。
// 返回明文 64 位值；只读 ctx，可并发。
/* 解混淆出栈值
 *
 * 流程: encrypted -> XOR_SECONDARY -> SUB -> ROTR -> XOR
 */
uint64_t vm_stack_deobfuscate_pop(const vm_stack_obfuscation_ctx_t *ctx, uint64_t encrypted);

// 混淆 value 后写入 stack[*sp] 并 (*sp)++；stack_size 为元素个数（不是字节）。
// 成功 0；NULL/溢出/未初始化分别返回 INVALID_PARAM/OVERFLOW/NOT_INITIALIZED。
// 失败时不改栈与 sp。就地修改 stack/sp/access_count，需独占。
/* 安全压栈操作
 *
 * 自动混淆并存储到栈
 */
int vm_stack_push_obfuscated(vm_stack_obfuscation_ctx_t *ctx,
                            uint64_t *stack,
                            uint32_t *sp,
                            uint32_t stack_size,
                            uint64_t value);

// 读取 stack[--sp] 并解混淆；失败时 out_value 与 sp 均不改。
// 成功后旧槽写入 key^offset（不是 0），并非安全擦除。
// 返回 0 / INVALID_PARAM / UNDERFLOW / NOT_INITIALIZED；需独占 stack/sp。
/* 安全出栈操作
 *
 * 从栈读取并自动解密
 */
int vm_stack_pop_obfuscated(vm_stack_obfuscation_ctx_t *ctx,
                           uint64_t *stack,
                           uint32_t *sp,
                           uint64_t *out_value);

// 只读 stack[sp-1] 的原始混淆值，不改变 sp，也不检查 initialized。
// 返回 0 / INVALID_PARAM / UNDERFLOW；失败不写 out_encrypted；可并发读。
/* 窥视栈顶值 (不解密) */
int vm_stack_peek_obfuscated(const vm_stack_obfuscation_ctx_t *ctx,
                            const uint64_t *stack,
                            uint32_t sp,
                            uint64_t *out_encrypted);

// 读取 stack[index] 并解混淆，供局部变量读取；index 不做上界校验。
// 返回 0 / INVALID_PARAM / NOT_INITIALIZED；失败不写 out_value；只读 ctx 与 stack。
/* 从中间位置读取并解密 (本地变量访问) */
int vm_stack_load_obfuscated(const vm_stack_obfuscation_ctx_t *ctx,
                            const uint64_t *stack,
                            uint32_t index,
                            uint64_t *out_value);

// 把 value 混淆后写入 stack[index]，不改变 sp；index 不做上界校验。
// 返回 0 / INVALID_PARAM / NOT_INITIALIZED；失败不写栈。需独占写该槽。
/* 混淆并存储到中间位置 (本地变量赋值) */
int vm_stack_store_obfuscated(vm_stack_obfuscation_ctx_t *ctx,
                             uint64_t *stack,
                             uint32_t index,
                             uint64_t value);

// secure_zero 整个 ctx（密钥/计数/标记）；NULL 安全，可重复调用。
// 之后 push/pop 因 initialized=0 而 fail-open，需重新 init 才恢复混淆。
/* 安全清除栈混淆上下文 */
void vm_stack_obfuscation_clear(vm_stack_obfuscation_ctx_t *ctx);

// 就地处理 [start, start+count) 个槽位；不做边界检查，范围必须落在调用方栈内。
// 要求已初始化；返回 0 / INVALID_PARAM / NOT_INITIALIZED。
// 对已混淆槽再次混淆或重复解混淆都会得到错误值；明文应尽快 secure_zero。
/* 批量混淆/解混淆栈区域 */
int vm_stack_obfuscate_region(vm_stack_obfuscation_ctx_t *ctx,
                            uint64_t *stack,
                            uint32_t start,
                            uint32_t count);
int vm_stack_deobfuscate_region(vm_stack_obfuscation_ctx_t *ctx,
                            uint64_t *stack,
                            uint32_t start,
                            uint32_t count);

// 启发式检查 [0, sp)：出现 0 值返回 CORRUPTED；popcount 极端时只跳过、不报错。
// 返回 0 / INVALID_PARAM / NOT_INITIALIZED / CORRUPTED；只读，不改栈。
// 判定很弱，“OK”不代表未被篡改；sp 不做上界校验。
/* 验证栈完整性 */
int vm_stack_verify_integrity(const vm_stack_obfuscation_ctx_t *ctx,
                              const uint64_t *stack,
                              uint32_t sp);

// 四个便捷宏只是对应函数的薄封装，参数与失败语义完全一致；
// 宏本身不带分号，调用方需自行补齐。说明必须写在整段宏之前（宏体是反斜杠续行）。
/* 便捷宏 */
#define VM_STACK_OBF_PUSH(ctx, stack, sp, size, val) \
    vm_stack_push_obfuscated(ctx, stack, sp, size, val)

#define VM_STACK_OBF_POP(ctx, stack, sp, out) \
    vm_stack_pop_obfuscated(ctx, stack, sp, out)

#define VM_STACK_OBF_LOAD(ctx, stack, idx, out) \
    vm_stack_load_obfuscated(ctx, stack, idx, out)

#define VM_STACK_OBF_STORE(ctx, stack, idx, val) \
    vm_stack_store_obfuscated(ctx, stack, idx, val)

#ifdef __cplusplus
}
#endif

#endif /* VM_STACK_CRYPTO_H */
