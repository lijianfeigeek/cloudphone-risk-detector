// CPSV v2 运行期观察器：仅在 CPRISK_VM_THREADED_DISPATCH != 0 时被解释器 include。
// 流程：读取 Mach-O LC_UUID 与 __swift5_mdvsi manifest，快照后校验，推导身份 RVA，
// 再用运行材料派生密钥计算 CPRisk-MAC；校验完成前不读取任何代码、不分配内存。
// 失败语义：任何异常/缺失/不匹配都返回 0，调用方按 fail-closed 毒化结果。
/* Included after key derivation. No allocation or code read before validation. */
// 读取 __DATA,__swift5_mdvsk 中的 8 字节 MAC 期望值：magic "CPSH" + LE u32。
// 段缺失、长度不符或 magic 不匹配时返回 0（表示无期望值）。
static uint32_t cprisk_vm_cpsv2_expect_resolve_i(const struct mach_header_64 *hdr) {
    if (!hdr) return 0u;
    unsigned long size = 0;
    const uint8_t *p = cprisk_find_section(hdr, CPRISK_ARMOR_SEGMENT_DATA,
        CPRISK_ARMOR_SECTION_VMP_SELF_EXPECT, &size);
    if (!p || size != 8u || cprisk_cpsv2_u32(p) != CPRISK_VMP_SELF_EXPECT_MAGIC_MAC)
        return 0u;
    return cprisk_cpsv2_u32(p + 4u);
}

// 观察并计算当前镜像的 CPSV2 标签。
// - hdr: 自身 Mach-O 头（借用）；tag: 输出 32 位标签（非 NULL）。
// - 返回 1 成功 / 0 任一步校验失败；失败时不写 tag。
// - 仅 __APPLE__ 有实现；其他平台返回 0（无发布级替代方案）。
// - 无全局可变状态，可在 VM 线程调用；所有临时密钥材料用完即清零。
static int cprisk_vm_cpsv2_observe_i(const struct mach_header_64 *hdr, uint32_t *tag) {
// 非 Apple 平台没有可发布的 Mach-O 替代实现，直接 fail-closed。
#if defined(__APPLE__)
// 先限制 Mach-O 头规模，避免恶意 ncmds/sizeofcmds 导致越界遍历。
    if (!hdr || !tag || hdr->ncmds > 4096u || hdr->sizeofcmds > 0x2000000u) return 0;
    uint8_t uuid[16] = {0};
    unsigned uuid_count = 0;
    const uint8_t *cmds = (const uint8_t *)(hdr + 1);
    size_t offset = 0;
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (offset > hdr->sizeofcmds || hdr->sizeofcmds - offset < 8u) return 0;
        uint32_t kind = cprisk_cpsv2_u32(cmds + offset);
        uint32_t size = cprisk_cpsv2_u32(cmds + offset + 4);
        if (size < 8u || size > hdr->sizeofcmds - offset) return 0;
// 必须恰好一个 LC_UUID（24 字节），且总命令长度与 sizeofcmds 完全一致。
        if (kind == LC_UUID) {
            if (size != 24u || ++uuid_count != 1u) return 0;
            memcpy(uuid, cmds + offset + 8, sizeof(uuid));
        }
        offset += size;
    }
    if (uuid_count != 1u || offset != hdr->sizeofcmds) return 0;
// 取 __DATA,__swift5_mdvsi（必须恰好 960 字节）与 __TEXT,__text 范围。
    unsigned long manifest_size = 0, text_size = 0;
    const uint8_t *manifest = cprisk_find_section(hdr, CPRISK_ARMOR_SEGMENT_DATA,
        CPRISK_ARMOR_SECTION_VMP_SELF_SPANS, &manifest_size);
    const uint8_t *text = cprisk_find_section(hdr, "__TEXT", "__text", &text_size);
    uintptr_t base = (uintptr_t)hdr;
    if (!manifest || manifest_size != CPRISK_CPSV2_BYTES || !text || (uintptr_t)text < base
        || text_size > UINTPTR_MAX - (uintptr_t)text) return 0;
// 先快照 manifest，后续校验/哈希都基于同一份副本，避免 TOCTOU。
    uint8_t snapshot[CPRISK_CPSV2_BYTES];
    memcpy(snapshot, manifest, sizeof(snapshot));
// 身份表与无指针 manifest 分离：取地址同时把每个函数保留在链接镜像中。
    /* Deliberately separate from the pointer-free manifest. Taking these
     * addresses also retains each required function in the linked image. */
    const void *const identities[CPRISK_CPSV2_COUNT] = {
#define CPRISK_CPSV2_IDENTITY(name) (const void *)&name,
#include "cprisk_vm_cpsv2_roster.inc"
#undef CPRISK_CPSV2_IDENTITY
    };
// 由本地函数地址减镜像基址独立计算 RVA；任何低于基址的地址直接拒绝。
    uint64_t expected_rvas[CPRISK_CPSV2_COUNT];
    for (unsigned i = 0; i < CPRISK_CPSV2_COUNT; i++) {
        if ((uintptr_t)identities[i] < base) return 0;
        expected_rvas[i] = (uintptr_t)identities[i] - base;
    }
// 解析并校验 58 个描述符；失败即返回 0，不使用部分结果。
    cprisk_cpsv2_range ranges[CPRISK_CPSV2_COUNT];
    if (!cprisk_cpsv2_parse(snapshot, sizeof(snapshot), uuid, expected_rvas,
                            (uintptr_t)text - base, text_size, ranges)) return 0;

// 从运行材料派生 32 字节密钥，计算标签后立即清零材料与密钥。
    uint8_t material[32] = {0}, key[32];
    if (cprisk_get_runtime_material(material) != 0) {
        cprisk_secure_zero(material, sizeof(material));
        return 0;
    }
    cprisk_vm_selfchk_mac_key_i(material, key);
    cprisk_secure_zero(material, sizeof(material));
    *tag = cprisk_cpsv2_tag(key, snapshot, base, ranges);
    cprisk_secure_zero(key, sizeof(key));
    return 1;
// 非 Apple 构建：没有可用的 Mach-O 观察路径，返回失败。
#else
    (void)hdr; (void)tag;
    return 0; /* No shipping non-Mach-O substitute. */
#endif
}
