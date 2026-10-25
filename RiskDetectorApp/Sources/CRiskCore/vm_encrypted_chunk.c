// vm_encrypted_chunk.c — VM 代码块的“按需解密 + execute-only”原型（已废弃）。
// 实际算法是 XOR 密钥流（key[i%32] ^ nonce[i%12]），不是 AES-GCM；16 字节
// auth_tag 是带密钥的 FNV-1a 校验和，不是 MAC，能发现误改但可被伪造。
// chunk 常驻结构体（内联最大 256 KiB），解密到 mmap 内存后尝试 mprotect 降权。
// 所有 API 无锁、无全局状态；同一 chunk/映射只能由单线程操作。平台相关处
// （mmap/mprotect、Apple 的 W^X 限制）失败时多数路径静默降级或返回负错误码。
/*
 * ============================================================================
 * VM运行时按需解密 (vm_encrypted_chunk.c)
 * ============================================================================
 *
 * 核心加固原理:
 * ------------
 * 1. 按需解密: 字节码在执行前才解密，执行后立即清除
 * 2. Execute-Only内存: 解密后的代码可执行但不可读
 * 3. 热度感知: 高频代码块保持解密状态，低频代码块重新加密
 * 4. 完整性绑定: 每个代码块绑定完整性校验，检测篡改
 *
 * 对抗技术:
 * --------
 * - 抗内存Dump: 攻击者dump时大部分代码仍处于加密状态
 * - 抗静态分析: 静态二进制中代码段是密文
 * - 抗动态Patch: 修改代码块会破坏完整性校验
 */

#include "vm_encrypted_chunk.h"
#include "include/cprisk_secure_zero.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* 内部常量 */
// 加密态标记：只有 ENCRYPTED 的 chunk 允许 decrypt/verify。
#define VM_CHUNK_MAGIC_ENCRYPTED 0x454E4352u  /* "ENCR" */
// 已解密标记：decrypt 成功后写入；reencrypt 要求当前为该状态。
#define VM_CHUNK_MAGIC_DECRYPTED 0x44454352u  /* "DECR" */
// 热度阈值：达到 100 次访问后 should_keep_decrypted 返回真（避免频繁重映射）。
#define VM_CHUNK_HOTNESS_THRESHOLD 100

/* 计算 FNV-1a 校验和（原名 vm_chunk_compute_hmac / "简化 CPRisk-MAC"，实为
 * FNV-1a 哈希，不是 CPRisk-MAC、不是 HMAC、不是认证：知道密钥/数据的人
 * 都能伪造，且 128 位输出无密钥认证语义。仅作误改检测，不要当作防篡改。 */
// 两轮带密钥 FNV-1a，输出 16 字节（每轮取低 64 位的 8 字节）。
// - data/len/key 由调用方保证有效；out 必须能容纳 16 字节。key 按 i%32 循环使用。
// - 返回: 无；线程: 纯函数，可重入；平台: 小端输出，跨端结果不一致。
// - 安全性质: 无认证语义，知道 key 的人可伪造；仅用于发现意外改写/清零。
static void vm_chunk_compute_fnv_checksum(const uint8_t *data, size_t len,
                                   const uint8_t key[32],
                                   uint8_t out[16]) {
    // h1 是累积状态；h2 只是 FNV 质数，命名为 h2 容易误读，实际不做第二次累积。
    uint64_t h1 = 0xCBF29CE484222325ULL;
    uint64_t h2 = 0x100000001B3ULL;

    // 第一轮：数据字节与循环密钥异或后再乘质数，使结果同时依赖内容与密钥。
    for (size_t i = 0; i < len; i++) {
        h1 ^= data[i] ^ key[i % 32];
        h1 *= h2;
    }

    // 先输出第一轮低 8 字节；第二轮会把这 8 字节再作为输入的一部分。
    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)(h1 >> (i * 8));
    }

    /* 第二轮 */
    // 重置偏移基后，把第一轮输出与密钥的另一段（偏移 +8）混合，得到后 8 字节。
    h1 = 0xCBF29CE484222325ULL;
    for (int i = 0; i < 16; i++) {
        h1 ^= out[i] ^ key[(i + 8) % 32];
        h1 *= h2;
    }

    for (int i = 0; i < 8; i++) {
        out[8 + i] = (uint8_t)(h1 >> (i * 8));
    }
}

/* 分配execute-only内存
 *
 * 使用mmap分配PROT_EXEC但不PROT_READ的内存页
 */
// 按页对齐分配 size 字节匿名内存，名义上“execute-only”，实际权限是 RW。
// - size 为 0 时对齐结果为 0，mmap 会以 EINVAL 失败并返回 NULL。
// - 返回: 映射地址；失败返回 NULL（不额外设置本模块错误码）。
// - 线程: 无共享状态；平台: mmap 语义 POSIX，iOS/macOS 同样可用。
// - 失败语义: 调用方必须检查 NULL；本函数不做 mprotect、不清零，真正降权在后续步骤。
void* vm_chunk_alloc_execute_only(size_t size) {
    /* 对齐到页大小 */
    // 向上取整到页边界：mprotect 要求地址与长度都按页对齐。
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    size_t alloc_size = (size + page_size - 1) & ~(page_size - 1);

    /* 分配RW内存 */
    // 先要读写权限才能写入明文；execute-only 只能作为“写完后降权”的后继状态。
    void *mem = mmap(NULL, alloc_size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);

    // MAP_FAILED 是 (void*)-1，不能与 NULL 混淆；两者在本函数里都归一为 NULL 返回。
    if (mem == MAP_FAILED) {
        return NULL;
    }

    /* 注意: 实际execute-only需要在写入后mprotect为PROT_EXEC only
     * 但iOS/macOS可能不支持纯粹的execute-only
     * 这里使用延迟降级策略
     */

    return mem;
}

/* 释放execute-only内存 */
// 先清零再解除映射；mem 为 NULL 时直接返回。
// - size 必须与分配时一致，内部会重新按页对齐；长度不符会导致清零/解映射范围错误。
// - 返回: 无；线程: 调用前必须确保没有线程正在执行该映射；平台: munmap 语义 POSIX。
// - 风险: 若映射已被 mprotect(PROT_EXEC) 去掉写权限，这里先清零会触发访问异常；
//   该函数只适用于仍可写的映射。
void vm_chunk_free_execute_only(void *mem, size_t size) {
    if (!mem) return;

    /* 先清零 */
    // 清零长度为调用方传入的 size，而非对齐后的 alloc_size；尾部页填充不会被擦除。
    cprisk_secure_zero(mem, size);

    /* 解除映射 */
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    size_t alloc_size = (size + page_size - 1) & ~(page_size - 1);

    munmap(mem, alloc_size);
}

/* 将内存区域降级为execute-only
 *
 * 移除读权限，仅保留执行权限
 */
// 对 [mem, mem+size) 调用 mprotect(PROT_EXEC)，即移除 READ/WRITE，仅保留执行。
// - mem 非 NULL 且 size 非 0；mem 必须是页对齐地址，size 由内核向上取整到页。
// - 返回: 0 成功；-1 参数错误或平台拒绝（Apple 的 W^X 常使纯 PROT_EXEC 失败）。
// - 线程: 修改整个进程可见的映射权限，调用期间不得有并发访问。
// - 失败语义: 不保存/转发 errno；失败后映射保持原 RW 权限且不可执行，
//   调用方若直接跳转会崩溃，必须把 -1 当作“不可执行”而不是“仍可执行”。
int vm_chunk_make_execute_only(void *mem, size_t size) {
    if (!mem || size == 0) {
        return -1;
    }

    /* 清除读权限，保留执行权限 */
    // 注意：PROT_EXEC 单独使用会同时移除读与写；在启用了 W^X 的平台上通常直接失败。
    if (mprotect(mem, size, PROT_EXEC) != 0) {
        /* 降级失败，可能是平台不支持 */
        return -1;
    }

    return 0;
}

/* 解密并验证代码块
 *
 * 流程:
 * 1. 验证CPRisk-MAC标签
 * 2. XOR 解混淆（原注释称 AES-GCM 是错误的：本模块从未实现 AEAD）
 * 3. 写入execute-only内存
 * 4. 降级权限
 */
// 校验 chunk 的 FNV 标签，XOR 解出明文到新映射，刷新 I-cache 并尝试降权。
// - chunk/key/out_exec_mem 非 NULL；chunk->magic 必须为 ENCRYPTED。
// - 返回: VM_CHUNK_OK / INVALID_PARAM / INVALID_MAGIC / AUTH_FAILED / ALLOC_FAILED。
// - 线程: 修改 chunk 状态并返回新映射；同一 chunk 不可并发；平台: 需要 mmap 与
//   __builtin___clear_cache（ARM64 必需，x86 为 no-op）。
// - 失败语义: 认证/分配失败时不改 chunk、不写 out_exec_mem；mprotect 失败被静默忽略，
//   映射可能仍可写但不可执行，这是已知降级缺陷。
// - 注意: memcmp 非恒定时间；FNV 标签不抗伪造，不能代替 AEAD。
int vm_chunk_decrypt_and_verify(vm_encrypted_chunk_t *chunk,
                                const uint8_t key[32],
                                void **out_exec_mem) {
    if (!chunk || !key || !out_exec_mem) {
        return VM_CHUNK_ERROR_INVALID_PARAM;
    }

    if (chunk->magic != VM_CHUNK_MAGIC_ENCRYPTED) {
        return VM_CHUNK_ERROR_INVALID_MAGIC;
    }

    /* 验证 FNV-1a 校验和（非认证，仅误改检测） */
    // 对密文计算标签并与存储值比较；标签覆盖 data_len 字节，不含 nonce/magic 等头部。
    uint8_t computed_tag[16];
    vm_chunk_compute_fnv_checksum(chunk->encrypted_data, chunk->data_len,
                           key, computed_tag);

    if (memcmp(computed_tag, chunk->auth_tag, 16) != 0) {
        return VM_CHUNK_ERROR_AUTH_FAILED;
    }

    /* 分配execute-only内存 */
    void *exec_mem = vm_chunk_alloc_execute_only(chunk->data_len);
    if (!exec_mem) {
        return VM_CHUNK_ERROR_ALLOC_FAILED;
    }

    /* 解密数据：XOR 混淆（不是加密/不是 AES-GCM） */
    /* 派生XOR密钥流 */
    // 密钥流只由 key 与 12 字节 nonce 按固定下标循环异或得到；相同 (key,nonce) 必得同一流。
    for (size_t i = 0; i < chunk->data_len; i++) {
        uint8_t keystream = key[i % 32] ^ chunk->nonce[i % 12];
        ((uint8_t*)exec_mem)[i] = chunk->encrypted_data[i] ^ keystream;
    }

    /* 刷新指令缓存 (ARM64需要) */
    // 写入的是数据缓存；若不清理 I-cache，ARM64 可能执行到旧指令（x86 上为 no-op）。
    __builtin___clear_cache(exec_mem, (char*)exec_mem + chunk->data_len);

    /* 尝试降级为execute-only */
    // 失败被刻意吞掉：后续仍把映射当作可执行返回，但实际上可能不可执行（见函数头说明）。
    if (vm_chunk_make_execute_only(exec_mem, chunk->data_len) != 0) {
        /* 降级失败，但内存仍可执行，继续运行 */
    }

    /* 更新状态 */
    // 先改 magic 再返回：调用方拿到映射时状态必须已是 DECRYPTED，否则 reencrypt 会拒绝。
    chunk->magic = VM_CHUNK_MAGIC_DECRYPTED;
    chunk->hotness_counter = 1;
    chunk->last_access_time = 0; /* 应由调用者设置 */

    *out_exec_mem = exec_mem;
    return VM_CHUNK_OK;
}

/* 重新加密代码块
 *
 * 执行完成后清理明文代码
 */
// 清零并释放解密映射，把 chunk 恢复为 ENCRYPTED。
// - chunk/exec_mem 非 NULL；magic 必须为 DECRYPTED；exec_mem_size 必须与分配时一致。
// - 返回: OK / INVALID_PARAM / NOT_DECRYPTED。
// - 线程: 释放前必须确保没有线程正在执行其中代码；平台: munmap 语义 POSIX。
// - 失败语义: 参数/状态不符时不触碰映射；成功后 chunk 可再次解密。
// - 风险: 若 decrypt 时 mprotect 成功移除了写权限，这里的清零会触发访问异常。
int vm_chunk_reencrypt(vm_encrypted_chunk_t *chunk,
                       void *exec_mem,
                       size_t exec_mem_size) {
    if (!chunk || !exec_mem) {
        return VM_CHUNK_ERROR_INVALID_PARAM;
    }

    if (chunk->magic != VM_CHUNK_MAGIC_DECRYPTED) {
        return VM_CHUNK_ERROR_NOT_DECRYPTED;
    }

    /* 清零execute-only内存 */
    // 先擦除明文代码，再交给 free（free 内部会再清一次，重复清零无副作用）。
    cprisk_secure_zero(exec_mem, exec_mem_size);

    /* 释放内存 */
    vm_chunk_free_execute_only(exec_mem, exec_mem_size);

    /* 恢复状态 */
    // 只有释放成功后才回到 ENCRYPTED；本函数无法感知 munmap 失败，失败时状态仍会切换。
    chunk->magic = VM_CHUNK_MAGIC_ENCRYPTED;

    return VM_CHUNK_OK;
}

/* 更新热度计数器 */
// 热度计数自增，饱和在 UINT32_MAX（避免回绕把热块误判为冷块）；NULL 安全。
// 只由调用方在访问后调用；不检查 chunk 状态，也无锁，需与访问路径同一线程。
void vm_chunk_update_hotness(vm_encrypted_chunk_t *chunk) {
    if (!chunk) return;

    // 饱和而不是回绕：回绕会让长期热点的计数突然变小，触发不必要的重新加密/降权。
    if (chunk->hotness_counter < 0xFFFFFFFF) {
        chunk->hotness_counter++;
    }
}

/* 检查代码块是否应保持解密状态
 *
 * 基于热度决定是否重新加密
 */
// 返回 hotness_counter >= VM_CHUNK_HOTNESS_THRESHOLD 的布尔结果；NULL 视为 0。
// 只读、无锁；平台无关。返回非零表示调用方可以跳过本轮重新加密。
int vm_chunk_should_keep_decrypted(const vm_encrypted_chunk_t *chunk) {
    if (!chunk) return 0;

    /* 高频访问的代码块保持解密 */
    // 阈值 100 是经验值：太小会频繁重映射，太大则长期暴露明文代码。
    return chunk->hotness_counter >= VM_CHUNK_HOTNESS_THRESHOLD;
}

/* 初始化加密代码块
 *
 * 在编译期或加载时调用，准备加密数据
 */
// 把明文就地 XOR 成密文并生成 FNV 标签，初始化一个加密态 chunk。
// - chunk/plaintext/key 非 NULL；plaintext_len <= VM_CHUNK_MAX_SIZE，否则 TOO_LARGE。
// - 返回: OK / INVALID_PARAM / TOO_LARGE；线程: 独占 chunk；平台: 无。
// - nonce 由 chunk_id 确定性派生（非随机），同 chunk_id+key 会复用密钥流，只适合原型。
// - 失败语义: 参数/长度错误时不修改 chunk；成功后 hotness=0、last_access=0。
int vm_chunk_init(vm_encrypted_chunk_t *chunk,
                  uint32_t chunk_id,
                  const uint8_t *plaintext,
                  size_t plaintext_len,
                  const uint8_t key[32]) {
    if (!chunk || !plaintext || !key) {
        return VM_CHUNK_ERROR_INVALID_PARAM;
    }

    // 上界检查防止 data_len 截断：chunk 内联数组固定 VM_CHUNK_MAX_SIZE 字节。
    if (plaintext_len > VM_CHUNK_MAX_SIZE) {
        return VM_CHUNK_ERROR_TOO_LARGE;
    }

    // 整块清零：把旧密文、旧标签、旧热度全部丢弃，避免残留影响新块。
    memset(chunk, 0, sizeof(*chunk));

    chunk->magic = VM_CHUNK_MAGIC_ENCRYPTED;
    chunk->chunk_id = chunk_id;
    // 已经过 TOO_LARGE 检查，此处窄化到 uint32 不会截断。
    chunk->data_len = (uint32_t)plaintext_len;

    /* 注意：nonce 是确定性派生的（chunk_id 异或常量），不是真随机；
     * 与 XOR 密钥流组合时不提供 nonce 唯一性保证。本模块已废弃。 */
    // nonce 只是 chunk_id 与固定步长的异或，不保证唯一性；复用 chunk_id 会复用密钥流。
    for (int i = 0; i < 12; i++) {
        chunk->nonce[i] = (uint8_t)(chunk_id ^ (i * 0x5A));
    }

    /* 加密数据 */
    // 与 decrypt 使用完全相同的密钥流构造；必须保持两处下标/长度一致，否则无法还原。
    for (size_t i = 0; i < plaintext_len; i++) {
        uint8_t keystream = key[i % 32] ^ chunk->nonce[i % 12];
        chunk->encrypted_data[i] = plaintext[i] ^ keystream;
    }

    /* 计算 FNV-1a 校验和（非认证标签） */
    // 标签覆盖的是密文，因此解密前即可验证；它不覆盖 nonce，nonce 被改不会被发现。
    vm_chunk_compute_fnv_checksum(chunk->encrypted_data, plaintext_len,
                           key, chunk->auth_tag);

    chunk->hotness_counter = 0;
    chunk->last_access_time = 0;

    return VM_CHUNK_OK;
}

/* 安全清零 */
// 对任意缓冲区调用 cprisk_secure_zero；NULL/0 长度的处理由底层实现决定。
// 线程: 调用方需保证没有并发读写；平台: 底层实现负责防止清零被编译器优化掉。
void vm_chunk_secure_zero(void *ptr, size_t len) {
    cprisk_secure_zero(ptr, len);
}

/* 验证代码块完整性 */
// 重新计算密文的 FNV 标签并比对 auth_tag（memcmp，非恒定时间）。
// - chunk/key 非 NULL；chunk->magic 必须为 ENCRYPTED（已解密状态会被拒绝）。
// - 返回: OK / INVALID_PARAM / INVALID_MAGIC / AUTH_FAILED。
// - 线程: 只读 chunk 与 key；平台: 无。失败语义: 只返回错误，不修改 chunk。
int vm_chunk_verify_integrity(const vm_encrypted_chunk_t *chunk,
                              const uint8_t key[32]) {
    if (!chunk || !key) {
        return VM_CHUNK_ERROR_INVALID_PARAM;
    }

    // 只验证加密态：解密后 encrypted_data 仍是原密文，但状态机不允许在此阶段重复校验。
    if (chunk->magic != VM_CHUNK_MAGIC_ENCRYPTED) {
        return VM_CHUNK_ERROR_INVALID_MAGIC;
    }

    // computed_tag 只存在栈上，不会被写回 chunk；验证是只读操作。
    uint8_t computed_tag[16];
    vm_chunk_compute_fnv_checksum(chunk->encrypted_data, chunk->data_len,
                           key, computed_tag);

    if (memcmp(computed_tag, chunk->auth_tag, 16) != 0) {
        return VM_CHUNK_ERROR_AUTH_FAILED;
    }

    return VM_CHUNK_OK;
}
