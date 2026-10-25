// CPSV v2 磁盘/线上契约：58 个编译期独立函数身份及其代码范围清单（960 字节）。
// 与全局 armor ABI 和 Mach-O 布局解耦；所有整数小端，磁盘上无指针/链式 fixup。
// 用途：运行时从 __DATA,__swift5_mdvsi 读取快照，校验每个描述符后计算 CPRisk-MAC。
// 调用约束：先完整快照 manifest 再校验/哈希，校验失败时 out 不得被使用。
/* CPSV v2 wire contract. Independent of the global armor ABI and of Mach-O.
 * All integers are little-endian. No pointers or chained-fixup slots on disk.
 * Hash message: complete 960-byte manifest, then code ranges in roster order.
 * Callers must snapshot the manifest before validation and subsequent hashing.
 */
#ifndef CPRISK_VM_CPSV2_H
#define CPRISK_VM_CPSV2_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// 契约版本；必须与 960 字节布局和解析逻辑一致。
#define CPRISK_CPSV2_VERSION 2u
// 身份总数 58 = 6 个固定入口 + 2 条线程 lane × 26 个 opcode。
#define CPRISK_CPSV2_COUNT 58u
// 头部 32 字节：magic(4)+version(4)+count(4)+reserved(4)+uuid(16)。
#define CPRISK_CPSV2_HEADER_BYTES 32u
// manifest 总长 960 = 32 + 58×16；解析器要求 size 精确等于该值。
#define CPRISK_CPSV2_BYTES (CPRISK_CPSV2_HEADER_BYTES + CPRISK_CPSV2_COUNT * 16u)
// 单个函数代码范围上限 64 KiB；生产者按实际函数长度填写。
#define CPRISK_CPSV2_MAX_RANGE 65536u
// 58 个范围总长上限 1 MiB；防止恶意 manifest 造成过量哈希。
#define CPRISK_CPSV2_MAX_TOTAL 1048576u

// 单个代码范围描述符：rva 相对镜像基址（4 字节对齐），length 为字节数（非 0、4 对齐、≤64 KiB），
// kind 为期望的 wire 身份编号（由 cprisk_cpsv2_kind 生成）。
typedef struct { uint64_t rva; uint32_t length, kind; } cprisk_cpsv2_range;

// 读取 LE uint32；调用方必须保证 p 至少有 4 字节（本函数不做边界检查）。
static inline uint32_t cprisk_cpsv2_u32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
// 读取 LE uint64（由两次 u32 拼成）；调用方保证 8 字节可读。
static inline uint64_t cprisk_cpsv2_u64(const uint8_t *p) {
    return cprisk_cpsv2_u32(p) | (uint64_t)cprisk_cpsv2_u32(p+4)<<32;
}
// 把 manifest 索引 i 映射为 wire kind：i<6 为固定 1..6；其后按 lane/op 编码。
static inline uint32_t cprisk_cpsv2_kind(uint32_t i) {
// lane=(i-6)/26，op=(i-6)%26；kind=((lane+1)<<8)|op，op 24/25 分别改 255/254。
    if (i < 6u) return i + 1u;
    uint32_t lane = (i - 6u) / 26u, op = (i - 6u) % 26u;
    return ((lane + 1u) << 8) + (op < 24u ? op : op == 24u ? 255u : 254u);
}

// 校验并解析 960 字节 manifest。
// - p: 只读 manifest，size 必须精确为 CPRISK_CPSV2_BYTES；uuid: 16 字节非全零 LC_UUID。
// - expected_rvas: 由编译期函数身份独立算出的 58 个 RVA，调用方拥有。
// - text_rva/text_size: __TEXT,__text 范围；所有范围必须落在其中。
// - out: 成功时才写入 58 个范围；失败时内容未定义，调用方不得读取。
// - 返回 1 成功 / 0 拒绝；无全局状态，可并发调用（各自缓冲区）。
/* expected_rvas is independently computed from compiled function identities.
 * Validate every descriptor before any caller reads code. Output is usable
 * only on success. Subtraction-based bounds checks reject integer overflow.
 */
static inline int cprisk_cpsv2_parse(const uint8_t *p, size_t size,
                                    const uint8_t uuid[16],
                                    const uint64_t expected_rvas[CPRISK_CPSV2_COUNT],
                                    uint64_t text_rva, uint64_t text_size,
                                    cprisk_cpsv2_range out[CPRISK_CPSV2_COUNT]) {
// 头部字段必须精确匹配（magic "CPVS"、version=2、count=58、reserved=0）。
    if (!p || !uuid || !expected_rvas || !out || size != CPRISK_CPSV2_BYTES
        || text_size > UINT64_MAX - text_rva) return 0;
    if (cprisk_cpsv2_u32(p) != 0x56535043u || cprisk_cpsv2_u32(p+4) != 2u
        || cprisk_cpsv2_u32(p+8) != CPRISK_CPSV2_COUNT || cprisk_cpsv2_u32(p+12)
// UUID 必须与当前镜像 LC_UUID 一致，绑定 manifest 与二进制。
        || memcmp(p+16, uuid, 16)) return 0;
// 全零 UUID 视为无效（防止未注入的占位值通过）。
    unsigned nonzero = 0;
    for (unsigned j=0; j<16; j++) nonzero |= uuid[j];
    if (!nonzero) return 0;
// 累计范围长度，受 MAX_TOTAL 约束。
    size_t total = 0;
    for (uint32_t i=0; i<CPRISK_CPSV2_COUNT; i++) {
        const uint8_t *e = p + CPRISK_CPSV2_HEADER_BYTES + i*16u;
        uint64_t rva = cprisk_cpsv2_u64(e);
        uint32_t len = cprisk_cpsv2_u32(e+8), kind = cprisk_cpsv2_u32(e+12);
// 每个描述符：kind/RVA 精确匹配、4 字节对齐、长度合法且落在 __text 内、总长不超限。
        if (kind != cprisk_cpsv2_kind(i) || rva != expected_rvas[i]
            || (rva & 3u) || (len & 3u) || !len || len > CPRISK_CPSV2_MAX_RANGE
            || rva < text_rva || rva - text_rva > text_size
            || len > text_size - (rva - text_rva)
            || len > CPRISK_CPSV2_MAX_TOTAL - total) return 0;
// 拒绝任意重叠范围，避免同一字节被重复计入哈希。
        for (uint32_t j=0; j<i; j++) {
            if (rva < out[j].rva + out[j].length && out[j].rva < rva + len) return 0;
        }
// 全部校验通过后才写 out；失败路径不会留下部分结果给调用方使用。
        out[i] = (cprisk_cpsv2_range){ rva, len, kind };
        total += len;
    }
    return 1;
}
#endif
