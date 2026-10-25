// CPSV2 的流式 CPRisk-MAC：自定义填充 SHA-256（非标准 HMAC），用于 960 字节 manifest
// 加 58 段代码范围的完整性标签。ipad/opad 使用 0x6D/0xA3，仅为与既有服务端/生产者互通。
// 调用前必须先用 cprisk_cpsv2_parse 校验并快照 manifest；本函数只读输入、不分配内存。
// 线程模型：全部状态在栈上，可重入/并发调用；临时缓冲区结束前安全清零。
/* Streaming CPRisk-MAC (custom-pad SHA-256 MAC — NOT standard HMAC-SHA256;
 * non-standard pads ipad 0x6D / opad 0xA3, kept for interop with the existing
 * server/producer; see the banner in cprisk_armor_abi.h). Caller must
 * validate/snapshot the manifest first. */
#ifndef CPRISK_VM_CPSV2_HASH_H
#define CPRISK_VM_CPSV2_HASH_H
#include "cprisk_vm_cpsv2.h"
#include "cprisk_armor_abi.h"
// 计算 32 位 LE 前缀标签。
// - key: 32 字节派生密钥（借用）；snapshot: 960 字节已校验快照；
// - base: 镜像基址；ranges: 58 个已校验范围（rva/length 均有效）。
// - 返回: SHA256 输出的前 4 字节按小端解释；无失败返回值。
// - 所有权: 全部输入只读，调用方负责生命周期；本函数清零内部 pad/hash。
static inline uint32_t cprisk_cpsv2_tag(const uint8_t key[32],
    const uint8_t snapshot[CPRISK_CPSV2_BYTES], uintptr_t base,
    const cprisk_cpsv2_range ranges[CPRISK_CPSV2_COUNT]) {
    uint8_t pad[64], inner[32], digest[32];
// 标记进入密码学原语（供 crypto trace 记录）；不影响结果。
    cprisk_crypto_trace_primitive_enter_i();
    cprisk_sha256_ctx hash;
// 自定义 ipad：前 32 字节为 key，后 32 字节补零，再 XOR 两段常量。
    for (unsigned i = 0; i < 64u; i++)
        pad[i] = (i < 32u ? key[i] : 0u) ^ CPRISK_MAC_IPAD_XOR_A ^ CPRISK_MAC_IPAD_XOR_B;
    cprisk_sha256_init(&hash);
    cprisk_sha256_update(&hash, pad, sizeof(pad));
    cprisk_sha256_update(&hash, snapshot, CPRISK_CPSV2_BYTES);
    for (unsigned i = 0; i < CPRISK_CPSV2_COUNT; i++)
// 流式哈希顺序：ipad → manifest 快照 → roster 顺序的代码范围。
        cprisk_sha256_update(&hash, (const uint8_t *)(base + ranges[i].rva), ranges[i].length);
    cprisk_sha256_final(&hash, inner);
// 自定义 opad 同理；这是非标准 HMAC，不可替换为标准实现。
    for (unsigned i = 0; i < 64u; i++)
        pad[i] = (i < 32u ? key[i] : 0u) ^ CPRISK_MAC_OPAD_XOR_A ^ CPRISK_MAC_OPAD_XOR_B;
    cprisk_sha256_init(&hash);
    cprisk_sha256_update(&hash, pad, sizeof(pad));
    cprisk_sha256_update(&hash, inner, sizeof(inner));
    cprisk_sha256_final(&hash, digest);
// 取摘要前 4 字节作为 32 位标签（小端），与服务端约定一致。
    uint32_t tag = cprisk_cpsv2_u32(digest);
// 清零所有中间密钥材料，避免栈残留。
    cprisk_secure_zero(pad, sizeof(pad));
    cprisk_secure_zero(inner, sizeof(inner));
    cprisk_secure_zero(digest, sizeof(digest));
    cprisk_secure_zero(&hash, sizeof(hash));
    return tag;
}
#endif
