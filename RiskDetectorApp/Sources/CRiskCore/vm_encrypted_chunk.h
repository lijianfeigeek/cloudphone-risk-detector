// 文件职责：VM 代码块的“按需解密 + execute-only”原型（XOR 混淆，非 AEAD）。
// 现状：未接入主路径；auth_tag 实为带密钥 FNV-1a 校验和，不是 MAC，不能防伪造。
// 布局：chunk 内联 256 KiB 密文，解密到 mmap 内存后尝试 mprotect(PROT_EXEC)。
// 线程模型：所有 API 无锁、无全局状态，同一 chunk/映射只能单线程操作。
// 平台/失败：mmap/mprotect 为 POSIX；Apple W^X 常使降权失败，失败静默降级或返回负码。
/*
 * ============================================================================
 * VM运行时按需解码头文件 (vm_encrypted_chunk.h)
 * ============================================================================
 * DEPRECATED / 未接入主路径：本模块无任何生产调用方（仅自身内部调用），
 * 不要接入主路径。其“认证标签”实际是 FNV-1a 校验和（见下），不是
 * MAC/认证，不提供防篡改；“解密”实际是 XOR 混淆，不是 AEAD 加密。
 * 如需真实认证加密，请使用带 CPRisk-MAC/AEAD 的主路径，不要用本模块。
 */

#ifndef VM_ENCRYPTED_CHUNK_H
#define VM_ENCRYPTED_CHUNK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 256 KiB 是结构体内联数组的固定容量，也是 plaintext_len 的硬上界；
// 增大它会线性抬高每个 chunk 的常驻内存并改变结构体 ABI。
/* 最大代码块大小 (256KB) */
#define VM_CHUNK_MAX_SIZE (256 * 1024)

// 加密块：magic 区分 ENCRYPTED/DECRYPTED；data_len 只统计 encrypted_data 的有效字节；
// nonce(12)/auth_tag(16) 长度固定，nonce 由 chunk_id 确定性派生（非随机）。
// 所有权：结构体由调用方提供，encrypted_data 为内联数组，无堆指针；按值拷贝成本很高。
/* 加密代码块结构体
 *
 * 存储AES-GCM加密的代码块
 */
typedef struct {
    uint32_t magic;              /* 状态魔数 */
    uint32_t chunk_id;           /* 块标识符 */
    uint32_t data_len;           /* 数据长度 */
    uint32_t hotness_counter;    /* 访问热度 */
    uint64_t last_access_time;   /* 最后访问时间 */
    uint8_t  nonce[12];          /* GCM nonce */
    uint8_t  auth_tag[16];       /* FNV-1a 校验和（名字是历史遗留：不是认证标签/MAC） */
    uint8_t  encrypted_data[VM_CHUNK_MAX_SIZE]; /* 加密数据 */
} vm_encrypted_chunk_t;

// 错误码：0 成功，负值失败；AUTH_FAILED 仅表示 FNV 标签不匹配，不是密码学认证失败。
/* 错误码 */
typedef enum {
    VM_CHUNK_OK = 0,
    VM_CHUNK_ERROR_INVALID_PARAM = -1,
    VM_CHUNK_ERROR_INVALID_MAGIC = -2,
    VM_CHUNK_ERROR_AUTH_FAILED = -3,
    VM_CHUNK_ERROR_ALLOC_FAILED = -4,
    VM_CHUNK_ERROR_TOO_LARGE = -5,
    VM_CHUNK_ERROR_NOT_DECRYPTED = -6,
    VM_CHUNK_ERROR_DECRYPT_FAILED = -7
} vm_chunk_error_t;

// 按页对齐 mmap 匿名内存；当前权限为 RW，尚未降权。size 为 0 会失败。
// 返回映射地址，失败 NULL（不设置本模块错误码）。无共享状态；调用方负责释放。
// 注意：真正 execute-only 需随后调用 vm_chunk_make_execute_only。
/* 分配execute-only内存
 *
 * 分配的内存可执行但不可读
 */
void* vm_chunk_alloc_execute_only(size_t size);

// 先清零再 munmap；mem NULL 时直接返回。size 必须与分配时一致（内部重新按页对齐）。
// 调用前必须确保无线程正在执行该映射；若映射已去掉写权限，清零会触发访问异常。
/* 释放execute-only内存 */
void vm_chunk_free_execute_only(void *mem, size_t size);

// mprotect(PROT_EXEC) 移除读写；mem 必须页对齐且 size>0。成功 0，参数错误/平台拒绝 -1。
// 不保存 errno；失败后映射仍为原权限且不可执行，调用方不得跳转。
/* 将内存降级为execute-only */
int vm_chunk_make_execute_only(void *mem, size_t size);

// 把明文 XOR 成密文并生成 FNV 标签，初始化一个 ENCRYPTED chunk。
// chunk/plaintext/key 非 NULL，plaintext_len ≤ VM_CHUNK_MAX_SIZE；成功 0，失败负码。
// 会整块清零旧内容；nonce 由 chunk_id 确定性派生，复用 chunk_id 会复用密钥流。
/* 初始化加密代码块
 *
 * 编译期调用，准备加密数据
 */
int vm_chunk_init(vm_encrypted_chunk_t *chunk,
                  uint32_t chunk_id,
                  const uint8_t *plaintext,
                  size_t plaintext_len,
                  const uint8_t key[32]);

// 校验密文 FNV 标签 → XOR 解出明文到新映射 → 清 I-cache → 尝试降权。
// chunk/key/out_exec_mem 非 NULL 且 magic=ENCRYPTED；成功 0 并写 *out_exec_mem，
// 失败不改 chunk、不写输出。标签不覆盖 nonce/头部，memcmp 非恒定时间。
// 修改 chunk 状态，同一 chunk 不可并发；mprotect 失败被静默忽略。
/* 解密并验证代码块
 *
 * 执行前调用，解密到execute-only内存
 */
int vm_chunk_decrypt_and_verify(vm_encrypted_chunk_t *chunk,
                                const uint8_t key[32],
                                void **out_exec_mem);

// 清零并释放解密映射，把 chunk 恢复为 ENCRYPTED。
// 要求 magic=DECRYPTED 且 exec_mem_size 与分配时一致；成功 0，参数/状态错误返回负码。
// 释放前必须确保没有线程正在执行该映射；映射不可写时清零会触发异常。
/* 重新加密代码块
 *
 * 执行完成后清理
 */
int vm_chunk_reencrypt(vm_encrypted_chunk_t *chunk,
                       void *exec_mem,
                       size_t exec_mem_size);

// 热度计数自增并饱和在 UINT32_MAX（不回绕）；NULL 安全，无锁。
// 计数只用于 should_keep_decrypted 的决策，不参与安全判断。
/* 更新热度计数器 */
void vm_chunk_update_hotness(vm_encrypted_chunk_t *chunk);

// 返回 hotness_counter >= 100（经验阈值：太小频繁重映射，太大长期暴露明文）。
// NULL 视为 0；返回非零表示可跳过本轮重新加密。只读、无锁。
/* 检查是否应保持解密状态 */
int vm_chunk_should_keep_decrypted(const vm_encrypted_chunk_t *chunk);

// 重新计算密文 FNV 标签并比对 auth_tag；要求 magic=ENCRYPTED。
// 返回 0 / INVALID_PARAM / INVALID_MAGIC / AUTH_FAILED；只读、不改 chunk。
// 非恒定时间比较且可伪造，只用于发现意外改写。
/* 验证代码块完整性 */
int vm_chunk_verify_integrity(const vm_encrypted_chunk_t *chunk,
                              const uint8_t key[32]);

// 转调 cprisk_secure_zero；NULL/0 长度语义由底层决定。调用方须保证无并发读写。
/* 安全清零 */
void vm_chunk_secure_zero(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* VM_ENCRYPTED_CHUNK_H */
