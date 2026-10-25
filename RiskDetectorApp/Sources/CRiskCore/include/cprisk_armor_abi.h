// 文件职责：CPRisk 装甲层（字符串/加载器/白盒/文本加密/VMP）的二进制 ABI 契约。
// 在链路中的位置：生产端（打包脚本）按本文件布局写入 __DATA 段，SDK 运行时按同一布局解析并校验。
// 二进制契约：所有结构体 `#pragma pack(push,1)` + 固定字节大小 `_Static_assert` 锁定；两端字节序均为小端。
// 版本策略：CPRISK_ABI_VERSION_* 描述本头文件 ABI；CPRISK_ARMOR_ABI_VERSION 描述装甲载荷格式，二者独立演进。
// 线程模型：本文件只定义类型与内联纯函数，无全局状态；调用方可并发读取同一份只读装甲数据。
// 失败语义：解析方必须校验 magic/version/长度并 fail-closed；版本不匹配应拒绝使用而非猜测布局。

#ifndef CPRISK_ARMOR_ABI_H
#define CPRISK_ARMOR_ABI_H

/* ════════════════════════════════════════════════════════════════════
 * CPRisk-MAC — NOT standard HMAC-SHA256. READ BEFORE TOUCHING.
 * ────────────────────────────────────────────────────────────────────
 * The MAC in this file (cprisk_mac_sha256 / cprisk_mac_verify, pad
 * macros CPRISK_MAC_IPAD_* and CPRISK_MAC_OPAD_*) uses NON-STANDARD pads
 * (ipad = 0x6D, opad = 0xA3; the standard HMAC pads are 0x36 / 0x5C).
 * It is therefore NOT interoperable with any standard HMAC-SHA256
 * implementation, and must never be presented as "HMAC" (the old name
 * was a misnomer, fixed by renaming to CPRisk-MAC).
 *
 * DO NOT "fix" the pads to 0x36/0x5C: that would silently break
 * interop with the existing server/producer side, which uses the same
 * non-standard pads. The migration path is to introduce a protocol /
 * contract version that negotiates standard HMAC-SHA256 (or an AEAD)
 * and to keep CPRisk-MAC only for the legacy contract version.
 * ════════════════════════════════════════════════════════════════════ */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "cprisk_sha256.h"
#include "cprisk_secure_zero.h"

/* ── ABI Semantic Version ─────────────────────────────────────────────
 *  MAJOR: incompatible struct layout or symbol removal
 *  MINOR: backward-compatible additions (new structs, new fields at end)
 *  PATCH: bug-fix only, no layout change
 *
 *  Bump policy:
 *    - Adding a new struct or appending fields → bump MINOR, reset PATCH
 *    - Changing existing struct size/layout or removing a symbol → bump MAJOR
 *    - Internal fix with no ABI surface change → bump PATCH
 *
 *  See docs/ABI_CONTRACT.md for the full compatibility matrix.
 */
// 版本三元组：MAJOR 改布局/删符号、MINOR 兼容新增、PATCH 仅修复；数值本身是契约的一部分。
#define CPRISK_ABI_VERSION_MAJOR 2u
#define CPRISK_ABI_VERSION_MINOR 0u
#define CPRISK_ABI_VERSION_PATCH 0u

// 编码布局固定为 [MAJOR:16][MINOR:8][PATCH:8]，方便运行时单次比较与日志打印。
#define CPRISK_ABI_VERSION_ENCODE(ma, mi, pa) \
    (((uint32_t)(ma) << 16) | ((uint32_t)(mi) << 8) | (uint32_t)(pa))

// 编译期打包的当前版本；不要手工展开，始终通过本宏获取。
#define CPRISK_ABI_VERSION_CURRENT \
    CPRISK_ABI_VERSION_ENCODE(CPRISK_ABI_VERSION_MAJOR, \
                              CPRISK_ABI_VERSION_MINOR, \
                              CPRISK_ABI_VERSION_PATCH)

/** Query the compiled ABI version at runtime.
 *  Returns a packed uint32: (major<<16 | minor<<8 | patch). */
/// 返回编译进当前二进制的 ABI 版本。
/// - Returns: 打包值 (major<<16 | minor<<8 | patch)。
/// - Thread safety: 纯函数，可并发调用。
/// - 用途: 运行时与生产端/服务端协商协议版本，不匹配时应拒绝解析装甲载荷。
static inline __attribute__((always_inline))
uint32_t cprisk_abi_version(void) {
    return CPRISK_ABI_VERSION_CURRENT;
}

// 装甲载荷格式版本（3）：与上面的头文件 ABI 版本相互独立，修改载荷布局时单独递增。
#define CPRISK_ARMOR_ABI_VERSION 3u

// 装甲密钥/哈希/随机数长度（字节）：AES-256 级密钥、SHA-256 摘要、128 位 nonce。
#define CPRISK_ARMOR_KEY_SIZE 32u
#define CPRISK_ARMOR_HASH_SIZE 32u
#define CPRISK_ARMOR_NONCE_SIZE 16u

// 装甲数据统一写入 __DATA 段；section 名伪装成 Swift 5 运行时元数据，降低被工具定向识别的概率。
#define CPRISK_ARMOR_SEGMENT_DATA "__DATA"

// 查找表说明：以下均为 __DATA 段内 section 名，生产端写入、运行时按名查找并校验 magic。
// 名称刻意借用 __swift5_* / __objc_* 前缀，避免与业务段重名并被静态扫描一眼识别。
#define CPRISK_ARMOR_SECTION_STRTAB "__swift5_types2"
#define CPRISK_ARMOR_SECTION_LOADER "__swift5_proto2"
#define CPRISK_ARMOR_SECTION_PROTECTED_DATA "__swift5_mpenum"
#define CPRISK_ARMOR_SECTION_ANCHOR_A "__swift5_aa"
#define CPRISK_ARMOR_SECTION_ANCHOR_B "__swift5_ab"
#define CPRISK_ARMOR_SECTION_ANCHOR_C "__swift5_ac"
#define CPRISK_ARMOR_SECTION_ANCHOR_D "__swift5_ad"
#define CPRISK_ARMOR_SECTION_FULL_HASH "__swift5_acfun"
#define CPRISK_ARMOR_SECTION_WHITEBOX_META "__swift5_mdext"
#define CPRISK_ARMOR_SECTION_WHITEBOX_CODE "__swift5_mdbdy"
#define CPRISK_ARMOR_SECTION_WHITEBOX_DATA "__swift5_mddsc"
#define CPRISK_ARMOR_SECTION_WHITEBOX_TAG "__swift5_mdchk"
#define CPRISK_ARMOR_SECTION_ANTI_DEBUG_PLAN "__objc_data2"
#define CPRISK_ARMOR_SECTION_IMPORT_ENCRYPTED_TABLE "__swift5_dyrel"
#define CPRISK_ARMOR_SECTION_HEADER_BACKUP "__swift5_mhsav"
#define CPRISK_ARMOR_SECTION_CHAIN_META "__swift5_ptmap"
#define CPRISK_ARMOR_SECTION_CHAIN_META_FALLBACK "__sw5_mdmap"
#define CPRISK_ARMOR_SECTION_TEXT_ENCRYPT "__swift5_cgenc"
#define CPRISK_ARMOR_SECTION_VMP_DISPATCH "__swift5_mdvrt"
#define CPRISK_ARMOR_SECTION_VMP_BYTECODE "__swift5_mdirt"
/* Optional dispatch split shard (second-half class table material; runtime reassembles when present). */
// 可选分片：把 dispatch 表后半部分拆到独立 section；缺失时运行时不拼接，保持向后兼容。
#define CPRISK_ARMOR_SECTION_VMP_DISPATCH_SHARD "__swift5_mdvsh"
/** Optional 8-byte blob: magic (LE u32) + expected M3 FNV-1a (LE u32) for \c CPRISK_VMP_BC_FLAG_M3_SELFCHK. */
// 可选 8 字节自检期望值：前 4 字节 magic、后 4 字节 FNV-1a；仅当字节码置 M3_SELFCHK 标志时使用。
#define CPRISK_ARMOR_SECTION_VMP_SELF_EXPECT "__swift5_mdvsk"
/** Optional self-check span map for producer-side expect injection (header + LE records of vmaddr/length/kind). */
// 可选自检区间映射：头部 + 若干小端记录（vmaddr/length/kind），供生产端注入期望值、运行时校验。
#define CPRISK_ARMOR_SECTION_VMP_SELF_SPANS "__swift5_mdvsi"

/** Mini-VM bootstrap XOR applied to loader/runtime material by both producer and runtime. */
// 生产端与运行时共用的 Mini-VM 引导异或值；改动会让两端材料无法互解，属于协议常量。
#define CPRISK_MINI_VM_BOOTSTRAP_XOR 0xA5u

// magic 为 "CPSV" 小端；version 不匹配时整张 span 表应被忽略，而不是按旧格式猜测。
#define CPRISK_VMP_SELF_SPAN_MAGIC 0x56535043u /* "CPSV" little-endian */
#define CPRISK_VMP_SELF_SPAN_VERSION 1u
// span kind：1=可执行区间；2=循环 A 区间；3=dispatch 区间；其余值保留，运行时跳过。
#define CPRISK_VMP_SELF_SPAN_KIND_EXEC 1u
#define CPRISK_VMP_SELF_SPAN_KIND_LOOP_A 2u
#define CPRISK_VMP_SELF_SPAN_KIND_DISPATCH 3u
/** Span byte lengths match \c CPRISK_VM_M3_SELF_* in \c cprisk_vm_interpreter.h (exec+loop+dispatch concat). */
// 三个 span 的字节长度必须与 cprisk_vm_interpreter.h 的 CPRISK_VM_M3_SELF_* 一致（按 exec+loop+dispatch 顺序拼接）。

// 文本加密表："CPTE" 小端 magic + 格式版本；解析方先校验二者再读取条目。
#define CPRISK_TEXT_ENCRYPT_MAGIC 0x45545043u /* "CPTE" little-endian */
#define CPRISK_TEXT_ENCRYPT_ABI_VERSION 1u
// 条目标志位 0：当前无附加语义，保留为“普通条目”。
#define CPRISK_TEXT_ENCRYPT_ENTRY_FLAG_NONE 0u

// 反调试计划表元信息："CPA7" magic；header 48 字节、entry 64 字节、目标名 32 字节，均与下方结构体逐一对应。
#define CPRISK_ARMOR_ADBG_ABI_VERSION 1u
#define CPRISK_ARMOR_ADBG_MAGIC 0x43504137u /* "CPA7" */
#define CPRISK_ARMOR_ADBG_HEADER_SIZE 48u
#define CPRISK_ARMOR_ADBG_ENTRY_SIZE 64u
#define CPRISK_ARMOR_ADBG_TARGET_NAME_SIZE 32u

// 头部 flags：bit0 含符号目标；bit1 含合成目标；bit2 种子来自配置；bit3 种子来自二进制。
#define CPRISK_ARMOR_ADBG_FLAG_HAS_SYMBOL_TARGETS 0x00000001u
#define CPRISK_ARMOR_ADBG_FLAG_HAS_SYNTHETIC_TARGETS 0x00000002u
#define CPRISK_ARMOR_ADBG_FLAG_SEED_FROM_CONFIG 0x00000004u
#define CPRISK_ARMOR_ADBG_FLAG_SEED_FROM_BINARY 0x00000008u

// 条目 flags：bit0 目标为合成（非真实符号）；bit1/bit2 为后续 inline patch/运行时门控预留，当前忽略。
#define CPRISK_ARMOR_ADBG_ENTRY_FLAG_SYNTHETIC_TARGET 0x00000001u
#define CPRISK_ARMOR_ADBG_ENTRY_FLAG_INLINE_PATCH_RESERVED 0x00000002u
#define CPRISK_ARMOR_ADBG_ENTRY_FLAG_RUNTIME_GATE_RESERVED 0x00000004u

// 处置策略位：bit0 运行时门控；bit1 检测到调试器即崩溃；bit2 篡改即 trap；
// bit3 延迟响应（不立即暴露检测）；bit4 升级为完整性风险。多位可组合。
#define CPRISK_ARMOR_ADBG_POLICY_RUNTIME_GATE 0x00000001u
#define CPRISK_ARMOR_ADBG_POLICY_CRASH_ON_DEBUGGER 0x00000002u
#define CPRISK_ARMOR_ADBG_POLICY_TRAP_ON_TAMPER 0x00000004u
#define CPRISK_ARMOR_ADBG_POLICY_DELAY_RESPONSE 0x00000008u
#define CPRISK_ARMOR_ADBG_POLICY_ESCALATE_INTEGRITY 0x00000010u

/** Runtime frontend / probe API level (see \c cprisk_whitebox_probe_result::abi_version). */
// 白盒运行时前端/探测 API 版本；探测结果中的 abi_version 必须与此比较后再解释 capabilities。
#define CPRISK_ARMOR_WHITEBOX_ABI_VERSION 2u
#define CPRISK_ARMOR_WHITEBOX_MAGIC 0x43505742u /* "CPWB" */
// 头部 flags：bit0 引擎就绪；bit1 签名流水线可用；bit2 启用增强扩散；bit3 表字节按 ASLR slide 掩码；bit4 TeamID 绑定。
#define CPRISK_ARMOR_WHITEBOX_FLAG_ENGINE_READY 0x00000001u
#define CPRISK_ARMOR_WHITEBOX_FLAG_SIGNING_PIPELINE 0x00000002u
#define CPRISK_ARMOR_WHITEBOX_FLAG_ENHANCED_DIFFUSION 0x00000004u
/** When set, white-box table bytes in \c __swift5_mdbdy are XOR-masked vs ASLR slide; see \c cprisk_armor_whitebox_header::aslr_table_anchor_slide. */
// 置位时 __swift5_mdbdy 中的表字节按 ASLR slide 掩码，需用头部的 anchor_slide 还原。
#define CPRISK_ARMOR_WHITEBOX_FLAG_ASLR_TABLE_BIND 0x00000008u
/** When set, \c config_digest was produced over \c SHA256(code||data||tag||team_salt_le8).
 *  Runtime re-derives the team salt via \c cprisk_codesign_team_salt() and verifies the digest
 *  at bundle validation time, providing an explicit proactive Team ID self-check. */
// 置位时 config_digest = SHA256(code||data||tag||team_salt_le8)，运行时重算 TeamID 盐并校验，实现主动签名身份自检。
#define CPRISK_ARMOR_WHITEBOX_FLAG_TEAM_ID_BOUND   0x00000010u

/** Minimum on-disk white-box meta size (v1 layout: no anchor tail). */
// v1 白盒元数据最小长度 48 字节（无 anchor 尾部）；读取时按“至少”处理以兼容后续扩展。
#define CPRISK_ARMOR_WHITEBOX_HEADER_V1_SIZE 48u
/** v2 layout: v1 fields + LE \c aslr_table_anchor_slide (mach_vm_address_t-sized; slide value at link/producer time). */
// v2 在 v1 基础上追加 8 字节小端 anchor_slide，总长 56 字节；运行时按实际长度选择解析分支。
#define CPRISK_ARMOR_WHITEBOX_HEADER_V2_SIZE 56u

// 能力位：bit0 运行时可派生密钥；bit1 可生成签名辅助；bit2 可验证辅助；bit4/5 白盒框架与布局；
// bit6 VMP 运行时。调用方只应使用自己理解的位，未知位必须忽略。
#define CPRISK_ARMOR_CAP_RUNTIME_DERIVE_KEY     0x00000001u
#define CPRISK_ARMOR_CAP_RUNTIME_SIGN_HELPER    0x00000002u
#define CPRISK_ARMOR_CAP_RUNTIME_VERIFY_HELPER  0x00000004u
#define CPRISK_ARMOR_CAP_WHITEBOX_FRAMEWORK     0x00000010u
#define CPRISK_ARMOR_CAP_WHITEBOX_SECTION_LAYOUT 0x00000020u
#define CPRISK_ARMOR_CAP_VMP_RUNTIME            0x00000040u

/** Optional 32-byte tail after the M2 VPC affine block in \c __swift5_mdirt (see \c cprisk_vm_interpreter.h). */
// 可选完整性尾块 32 字节，追加在 M2 VPC 仿射块之后；缺失时运行时视为旧格式，不做该段校验。
#define CPRISK_VMP_INTEGRITY_BLOCK_BYTES 32u

// 探测结果 flags：bit0 已编译白盒；bit1 元数据存在；bit2 元数据有效；bit3 引擎就绪。
#define CPRISK_WHITEBOX_PROBE_FLAG_COMPILED         0x00000001u
#define CPRISK_WHITEBOX_PROBE_FLAG_METADATA_PRESENT 0x00000002u
#define CPRISK_WHITEBOX_PROBE_FLAG_METADATA_VALID   0x00000004u
#define CPRISK_WHITEBOX_PROBE_FLAG_ENGINE_READY     0x00000008u

// 十六进制编码后的哈希长度：32 字节摘要 → 64 个 ASCII 字符（不含结尾 NUL）。
#define CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE (CPRISK_ARMOR_HASH_SIZE * 2u)

// 引导字符串在 strtab 中的固定 string_id；运行时启动时按该 ID 取第一条解密材料。
#define CPRISK_ARMOR_BOOTSTRAP_STRING_ID 1u

// Swift 元数据 shuffle 表："CPMD" magic、版本 1、头 32 字节、记录 48 字节；记录数与头部 record_count 必须一致。
#define CPRISK_ARMOR_SWIFT_METADATA_SHUFFLE_MAGIC 0x444D5043u /* "CPMD" */
#define CPRISK_ARMOR_SWIFT_METADATA_SHUFFLE_ABI_VERSION 1u
#define CPRISK_ARMOR_SWIFT_METADATA_SHUFFLE_HEADER_SIZE 32u
#define CPRISK_ARMOR_SWIFT_METADATA_SHUFFLE_RECORD_SIZE 48u

// 各表 magic 哨兵：解析前必须逐字匹配，否则视为表缺失/损坏并 fail-closed。
#define CPRISK_ARMOR_STRTAB_MAGIC 0x43505354u  /* table guard sentinel */
#define CPRISK_ARMOR_LOADER_MAGIC 0x4350524Bu  /* descriptor guard sentinel */
#define CPRISK_ARMOR_IMPORT_MAGIC 0x43494D50u  /* "CPIM" import table sentinel */
// v3 loader 条目固定 144 字节；_Static_assert 会用该常量锁定结构体大小。
#define CPRISK_ARMOR_LOADER_ENTRY_V3_SIZE 144u

// 完整哈希被拆成 4 条 8 字节 anchor lane（4×8=32），分散到 4 个 section 以抵抗单点替换。
#define CPRISK_ARMOR_ANCHOR_LANE_COUNT 4u
#define CPRISK_ARMOR_ANCHOR_LANE_SIZE 8u
#define CPRISK_ARMOR_MAC_FULL_HASH_SECTION_SIZE CPRISK_ARMOR_HASH_SIZE
// 单个 section 上限 256 MiB：足够容纳加密文本，同时挡住损坏长度字段导致的巨量读取/分配。
#define CPRISK_MAX_SECTION_SIZE (256UL * 1024UL * 1024UL)
// 单表最大条目数 64：限制解析与内存占用，超出即视为异常数据。
#define CPRISK_MAX_ENTRY_COUNT 64u

// 关闭结构体填充对齐：装甲数据由生产端逐字节写入，必须与磁盘布局完全一致，
// 不能依赖编译器的自然对齐（否则 32/64 位或不同编译器会产生不同大小）。
#pragma pack(push, 1)

// strtab 头：12 字节 = magic + version + count；count 为后续索引条目数。
struct cprisk_armor_strtab_header {
    // 必须等于 CPRISK_ARMOR_STRTAB_MAGIC，否则整表拒绝解析。
    uint32_t magic;
    // strtab 格式版本，运行时按已知版本分支处理。
    uint32_t version;
    // 索引条目数量；受 CPRISK_MAX_ENTRY_COUNT 约束。
    uint32_t count;
};

// strtab 索引条目：描述一条加密字符串的位置与完整性材料，共 60 字节。
struct cprisk_armor_strtab_index_entry {
    // 字符串 ID（1 = 引导字符串），运行时按 ID 查找。
    uint32_t string_id;
    // 密文相对 strtab 数据区起始的偏移（字节）。
    uint32_t data_offset;
    // 密文长度（字节），不含 nonce/mac。
    uint32_t data_length;
    // 该条目的 16 字节加密 nonce。
    uint8_t  nonce[CPRISK_ARMOR_NONCE_SIZE];
    // CPRisk-MAC 标签（32 字节），校验失败即整表不可信。
    uint8_t  mac_tag[CPRISK_ARMOR_HASH_SIZE];
};

// loader 头：12 字节；count 为 loader entry 数量。
struct cprisk_armor_loader_header {
    // 必须等于 CPRISK_ARMOR_LOADER_MAGIC。
    uint32_t magic;
    // loader 描述符格式版本。
    uint32_t version;
    // 后续 entry 数量，受 CPRISK_MAX_ENTRY_COUNT 约束。
    uint32_t count;
};

// loader 条目 v3：固定 144 字节，描述一个待解密 section 及其链式派生参数。
struct cprisk_armor_loader_entry {
    // 目标 segment 名，NUL 填充，最多 15 字符 + NUL。
    char     segment_name[16];
    // 目标 section 名，NUL 填充，最多 15 字符 + NUL。
    char     section_name[16];
    // 密钥槽 ID，决定使用哪一路派生密钥。
    uint32_t key_id;
    // 条目行为标志，当前保留给解密策略使用。
    uint32_t flags;
    // 目标 section 的链接期虚拟地址（未加 ASLR slide）。
    uint64_t vm_addr;
    // 目标 section 字节数；运行时先与 Mach-O 实际大小比对。
    uint64_t size;
    // 解密后明文的 SHA-256，用于完整性校验。
    uint8_t  content_hash[CPRISK_ARMOR_HASH_SIZE];
    // 本条目的加密 nonce。
    uint8_t  nonce[CPRISK_ARMOR_NONCE_SIZE];
    // 覆盖元数据与密文的 CPRisk-MAC。
    uint8_t  mac_tag[CPRISK_ARMOR_HASH_SIZE];
    uint32_t section_index;       /* v3: 1-based section order for chained KDF */
    uint32_t chained_key_depth;   /* v3: >=1 levels of chaining; 0 treated as 1 */
};

// 反调试计划头：48 字节；描述补丁点数量、代码段基址与探测立即数。
struct cprisk_armor_antidebug_header {
    // 必须等于 CPRISK_ARMOR_ADBG_MAGIC（"CPA7"）。
    uint32_t magic;
    // 计划格式版本，当前为 CPRISK_ARMOR_ADBG_ABI_VERSION。
    uint32_t version;
    // CPRISK_ARMOR_ADBG_FLAG_* 位组合。
    uint32_t flags;
    // 本头长度，用于跨版本兼容与边界检查（固定 48）。
    uint32_t header_size;
    // 生产端种子，运行时用于复算目标哈希/分散槽位。
    uint64_t seed;
    // __TEXT 链接期基址，配合 slide 定位补丁点。
    uint64_t text_base_address;
    // 探测指令立即数，用于识别原始/已补丁代码。
    uint32_t probe_immediate;
    // 后续 entry 数量。
    uint32_t entry_count;
    // 单个 entry 字节数（固定 64），解析时校验。
    uint32_t entry_size;
    // 对齐/未来扩展，必须为 0。
    uint32_t reserved;
};

// 反调试条目：64 字节；一个目标函数/补丁点及其处置策略。
struct cprisk_armor_antidebug_entry {
    // 目标标识（符号/特征）的哈希，避免明文符号名。
    uint64_t identifier_hash;
    // 补丁点相对 __TEXT 基址的虚拟地址偏移。
    uint64_t patch_site_vm_offset;
    // 补丁点在文件中的偏移，供静态改写使用。
    uint32_t patch_site_file_offset;
    // CPRISK_ARMOR_ADBG_POLICY_* 处置策略位。
    uint32_t policy_bits;
    // 分散存储槽位：运行时从多处拼回真实值。
    uint32_t scatter_slot;
    // CPRISK_ARMOR_ADBG_ENTRY_FLAG_* 条目标志。
    uint32_t entry_flags;
    // 目标名（可读诊断用），NUL 填充。
    char target_name[CPRISK_ARMOR_ADBG_TARGET_NAME_SIZE];
};

// Swift 元数据 shuffle 头：32 字节；build_seed 用于可重复的确定性洗牌。
struct cprisk_armor_swift_metadata_shuffle_header {
    // 必须等于 CPRISK_ARMOR_SWIFT_METADATA_SHUFFLE_MAGIC。
    uint32_t magic;
    // shuffle 表格式版本。
    uint32_t abi_version;
    // 预留行为标志，当前应为 0。
    uint32_t flags;
    // 后续记录数量。
    uint32_t record_count;
    // 构建期随机种子；运行时同种子可复现映射。
    uint64_t build_seed;
    // 对齐/未来扩展，必须为 0。
    uint64_t reserved64;
};

// 白盒头：v2 布局固定 56 字节（v1 的 48 字节 + 8 字节 anchor slide）。
struct cprisk_armor_whitebox_header {
    // 必须等于 CPRISK_ARMOR_WHITEBOX_MAGIC（"CPWB"）。
    uint32_t magic;
    // 白盒元数据版本（1 或 2），决定是否读取尾部。
    uint32_t version;
    // CPRISK_ARMOR_WHITEBOX_FLAG_* 位组合。
    uint32_t flags;
    // 后续白盒载荷字节数，用于边界检查。
    uint32_t payload_size;
    // code/data/tag（可选 team salt）的 SHA-256 摘要。
    uint8_t  config_digest[CPRISK_ARMOR_HASH_SIZE];
    /**
     * v2+ optional tail (present when on-disk size >= CPRISK_ARMOR_WHITEBOX_HEADER_V2_SIZE).
     * Interpreting masked table bytes T_store uses:
     *   T_logical[i] = T_store[i] ^ P(i, slide_runtime) ^ P(i, anchor_slide)
     * where P is derived from cprisk_wbx_slide_term_u64(slide) per 32-byte block (see cprisk_whitebox.c).
     * When anchor_slide matches the slide used at build time for masking, T_logical matches the
     * producer's logical tables; digest/CPRisk-MAC over T_store remains stable.
     */
    // v2 尾部：构建期用于掩码表的 slide；运行时用 runtime slide 与它做异或还原逻辑表。
    // 仅当磁盘长度 ≥ 56 且 flags 含 ASLR_TABLE_BIND 时有效；否则必须忽略该字段。
    uint64_t aslr_table_anchor_slide;
};

// 文本加密表头：16 字节；count 为 cprisk_text_encrypt_entry 数量。
struct cprisk_text_encrypt_header {
    // 必须等于 CPRISK_TEXT_ENCRYPT_MAGIC（"CPTE"）。
    uint32_t magic;
    // 表格式版本，当前为 CPRISK_TEXT_ENCRYPT_ABI_VERSION。
    uint32_t version;
    // 条目数量，受 CPRISK_MAX_ENTRY_COUNT 约束。
    uint32_t count;
    // 表级标志，当前仅保留；未知位必须忽略。
    uint32_t flags;
};

// 文本加密条目：104 字节；一个待解密代码区间的地址、长度与完整性材料。
struct cprisk_text_encrypt_entry {
    // 区间链接期虚拟地址（未加 slide）。
    uint64_t vm_addr;
    // 区间字节数，运行时须与 Mach-O 段信息交叉校验。
    uint64_t size;
    // 密钥槽 ID。
    uint32_t key_id;
    // 条目级标志（CPRISK_TEXT_ENCRYPT_ENTRY_FLAG_*）。
    uint32_t flags;
    // 加密 nonce。
    uint8_t  nonce[CPRISK_ARMOR_NONCE_SIZE];
    // 覆盖元数据与密文的 CPRisk-MAC。
    uint8_t  mac_tag[CPRISK_ARMOR_HASH_SIZE];
    // 解密后明文的 SHA-256。
    uint8_t  content_hash[CPRISK_ARMOR_HASH_SIZE];
};

// 白盒探测结果：16 字节，全部为无符号主机端序字段。
struct cprisk_whitebox_probe_result {
    // 产生该结果的 API 版本，必须与 CPRISK_ARMOR_WHITEBOX_ABI_VERSION 兼容。
    uint32_t abi_version;
    // CPRISK_ARMOR_CAP_* 能力位组合。
    uint32_t capabilities;
    // CPRISK_WHITEBOX_PROBE_FLAG_* 状态位。
    uint32_t flags;
    // 实际解析到的白盒元数据版本（1 或 2；0 表示未解析）。
    uint32_t metadata_version;
};

#pragma pack(pop)

// 以下 _Static_assert 锁定磁盘 ABI：任何字段增删/类型变化都会在编译期失败，
// 防止生产端与运行时在“看起来能编译”的情况下产生静默的布局漂移。
_Static_assert(sizeof(struct cprisk_armor_strtab_header) == 12,
               "cprisk strtab header ABI drift");
_Static_assert(sizeof(struct cprisk_armor_strtab_index_entry) == 60,
               "cprisk strtab index ABI drift");
_Static_assert(sizeof(struct cprisk_armor_loader_header) == 12,
               "cprisk loader header ABI drift");
_Static_assert(sizeof(struct cprisk_armor_loader_entry) == CPRISK_ARMOR_LOADER_ENTRY_V3_SIZE,
               "cprisk loader entry ABI drift");
_Static_assert(sizeof(struct cprisk_armor_antidebug_header) == 48,
               "cprisk anti-debug header ABI drift");
_Static_assert(sizeof(struct cprisk_armor_antidebug_entry) == 64,
               "cprisk anti-debug entry ABI drift");
_Static_assert(sizeof(struct cprisk_armor_swift_metadata_shuffle_header) ==
                   CPRISK_ARMOR_SWIFT_METADATA_SHUFFLE_HEADER_SIZE,
               "cprisk swift metadata shuffle header ABI drift");
_Static_assert(sizeof(struct cprisk_armor_whitebox_header) == CPRISK_ARMOR_WHITEBOX_HEADER_V2_SIZE,
               "cprisk whitebox header ABI drift");
_Static_assert(sizeof(struct cprisk_text_encrypt_header) == 16,
               "cprisk text encrypt header ABI drift");
_Static_assert(sizeof(struct cprisk_text_encrypt_entry) == 104,
               "cprisk text encrypt entry ABI drift");
_Static_assert(sizeof(struct cprisk_whitebox_probe_result) == 16,
               "cprisk whitebox probe ABI drift");
// 四个 anchor section 必须能无损拼回一份完整 32 字节哈希，否则完整性校验会误判。
_Static_assert(CPRISK_ARMOR_ANCHOR_LANE_COUNT * CPRISK_ARMOR_ANCHOR_LANE_SIZE ==
                   CPRISK_ARMOR_HASH_SIZE,
               "split anchor sections must reconstruct a 32-byte hash");

/* ── CPRisk-MAC: custom-pad SHA-256 MAC (NOT standard HMAC-SHA256) ──
 * Non-standard pads (ipad 0x6D / opad 0xA3) kept for interop with the
 * existing server/producer. See the banner at the top of this file.
 * Never silently change the pads; migrate via contract-version
 * negotiation instead. */

// CPRisk-MAC 以 64 字节（SHA-256 分组长度）为密钥归一化块大小。
#define CPRISK_MAC_BLOCK_SIZE 64

/* Custom service-coordinated pad bytes; split to avoid a single literal fingerprint. */
// 自定义 pad 常量拆成两半保存：A^B 才等于真实 pad（ipad=0x6D、opad=0xA3），
// 避免单个 0x6D/0xA3 字面量成为静态特征。改动任一半都会与服务端失去互通。
#define CPRISK_MAC_IPAD_XOR_A ((uint8_t)0xD7u)
#define CPRISK_MAC_IPAD_XOR_B ((uint8_t)0xBAu) /* A^B = 0x6D */
#define CPRISK_MAC_OPAD_XOR_A ((uint8_t)0x4Cu)
#define CPRISK_MAC_OPAD_XOR_B ((uint8_t)0xEFu) /* A^B = 0xA3 */

/// 计算 CPRisk-MAC（自定义 pad 的 SHA-256 双层结构，不是标准 HMAC-SHA256）。
/// - Parameters:
///   - key: 密钥；key_len>0 时不允许 NULL。函数只读，不接管所有权。
///   - key_len: 密钥字节数；>64 时先做一次 SHA-256 归一化，≤64 时右补 0。
///   - msg: 消息；msg_len>0 时不允许 NULL。
///   - msg_len: 消息字节数。
///   - out: 32 字节 MAC 输出缓冲区；所有权归调用方。
/// - Returns: 无。
/// - Thread safety: 全部状态在栈上，可重入、可并发。
/// - 互操作: 必须与生产端/服务端使用相同的非标准 pad；不能与标准 HMAC 结果对比。
/// - 副作用: 入口触发一次 crypto trace；结束时用 cprisk_secure_zero 擦除密钥块与中间哈希。
static inline __attribute__((always_inline))
void cprisk_mac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t out[CPRISK_ARMOR_HASH_SIZE]) {
    cprisk_crypto_trace_primitive_enter_i();
    // 先清零，保证短密钥的尾部是确定的 0 填充。
    uint8_t k_norm[CPRISK_MAC_BLOCK_SIZE];
    memset(k_norm, 0, CPRISK_MAC_BLOCK_SIZE);
    if (key_len > CPRISK_MAC_BLOCK_SIZE) {
        cprisk_sha256(key, key_len, k_norm);
    } else {
        memcpy(k_norm, key, key_len);
    }

    uint8_t ipad[CPRISK_MAC_BLOCK_SIZE];
    uint8_t opad[CPRISK_MAC_BLOCK_SIZE];
    for (int i = 0; i < CPRISK_MAC_BLOCK_SIZE; i++) {
        ipad[i] = (uint8_t)(k_norm[i] ^ CPRISK_MAC_IPAD_XOR_A ^ CPRISK_MAC_IPAD_XOR_B);
        opad[i] = (uint8_t)(k_norm[i] ^ CPRISK_MAC_OPAD_XOR_A ^ CPRISK_MAC_OPAD_XOR_B);
    }

    cprisk_sha256_ctx ctx;
    uint8_t inner_hash[CPRISK_SHA256_DIGEST_LENGTH];

    // 内层：SHA256(ipad || msg)；外层：SHA256(opad || inner_hash)。
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, ipad, CPRISK_MAC_BLOCK_SIZE);
    cprisk_sha256_update(&ctx, msg, msg_len);
    cprisk_sha256_final(&ctx, inner_hash);

    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, opad, CPRISK_MAC_BLOCK_SIZE);
    cprisk_sha256_update(&ctx, inner_hash, CPRISK_SHA256_DIGEST_LENGTH);
    cprisk_sha256_final(&ctx, out);

    // 密钥块与内层哈希属于敏感中间态，必须显式擦除（out 由调用方负责）。
    cprisk_secure_zero(k_norm, sizeof(k_norm));
    cprisk_secure_zero(ipad, sizeof(ipad));
    cprisk_secure_zero(opad, sizeof(opad));
    cprisk_secure_zero(inner_hash, sizeof(inner_hash));
}

/* ── compile-time salt obfuscation ──────────────────────────────────── */

/* Legacy default; runtime should derive from root key via
   cprisk_derive_salt_xor_key() and use the result instead. */
// 旧版固定 XOR 键，仅用于兼容旧数据；新代码必须用 cprisk_derive_salt_xor_key() 从根密钥派生。
#define CPRISK_SALT_XOR_KEY_DEFAULT 0xA7

/// 从 32 字节根密钥派生 1 字节盐 XOR 键。
/// - Parameters:
///   - root_key: 32 字节根密钥；不允许 NULL，函数只读。
/// - Returns: 派生出的 1 字节 XOR 键；同一根密钥恒定。
/// - Thread safety: 无共享状态，可重入。
/// - 实现: SHA256(root_key || "salt-xor") 的首字节，避免直接暴露根密钥。
static inline __attribute__((always_inline))
uint8_t cprisk_derive_salt_xor_key(const uint8_t root_key[CPRISK_ARMOR_KEY_SIZE]) {
    uint8_t seed[CPRISK_ARMOR_KEY_SIZE + 8];
    memcpy(seed, root_key, CPRISK_ARMOR_KEY_SIZE);
    // 固定域分隔后缀，防止不同用途的派生结果相同。
    seed[CPRISK_ARMOR_KEY_SIZE + 0] = 's';
    seed[CPRISK_ARMOR_KEY_SIZE + 1] = 'a';
    seed[CPRISK_ARMOR_KEY_SIZE + 2] = 'l';
    seed[CPRISK_ARMOR_KEY_SIZE + 3] = 't';
    seed[CPRISK_ARMOR_KEY_SIZE + 4] = '-';
    seed[CPRISK_ARMOR_KEY_SIZE + 5] = 'x';
    seed[CPRISK_ARMOR_KEY_SIZE + 6] = 'o';
    seed[CPRISK_ARMOR_KEY_SIZE + 7] = 'r';
    uint8_t hash[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_sha256(seed, sizeof(seed), hash);
    uint8_t result = hash[0];
    // 中间材料（含根密钥副本）用完立即擦除。
    cprisk_secure_zero(seed, sizeof(seed));
    cprisk_secure_zero(hash, sizeof(hash));
    return result;
}

/// 用单字节 XOR 键解码盐字符串。
/// - Parameters:
///   - encoded: 编码数据；len>0 时不允许 NULL。
///   - len: 编码字节数。
///   - xor_key: 与编码端一致的 XOR 键。
///   - out: 输出缓冲区，必须至少 len+1 字节（函数会写结尾 NUL）；所有权归调用方。
/// - Returns: 无。
/// - Thread safety: 可重入；out 不能与其他线程共享写入。
/// - 失败语义: 无错误码；缓冲区不足会越界写。
static inline __attribute__((always_inline))
void cprisk_decode_salt(const uint8_t *encoded, size_t len,
                        uint8_t xor_key, char *out) {
    for (size_t i = 0; i < len; i++)
        out[i] = (char)(encoded[i] ^ xor_key);
    out[len] = '\0';
}

/* Constant-time comparison for CPRisk-MAC tags. */
/// 常量时间比较两个 MAC 标签，避免按字节提前返回泄漏匹配前缀。
/// - Parameters:
///   - expected: 期望标签；不允许 NULL。
///   - actual: 实际标签；不允许 NULL。
///   - len: 比较字节数（通常 32）。
/// - Returns: 完全相等返回 0；否则返回 -1。
/// - Thread safety: 只读，可重入。
/// - 失败语义: 无 errno；调用方必须把 -1 当作 MAC 校验失败（fail-closed）。
static inline __attribute__((always_inline))
int cprisk_mac_verify(const uint8_t *expected, const uint8_t *actual, size_t len) {
    // 用按位或累积差异：无论哪一字节不同，循环次数与分支都保持一致。
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= expected[i] ^ actual[i];
    return diff == 0 ? 0 : -1;
}

/* Magic values */
// 链式元数据 magic 前缀 "CPCH"；后 4 字节可承载链序号/变体，解析时先比较前缀。
#define CPRISK_ARMOR_CHAIN_MAGIC_PREFIX 0x43504348  /* "CPCH" */

/* Domains 6-7 are runtime-bound; static import/header domains 8-9 are build-stable. */
// 白盒派生域：6 设备绑定、7 会话绑定（二者运行期变化）；8 import 加密、9 header 加密（构建期固定）。
// COUNT=9 表示域编号上限（0..8 有效，9 为 sentinel），越界 domain 必须被拒绝。

#define CPRISK_WHITEBOX_DOMAIN_DEVICE_BOUND 6
#define CPRISK_WHITEBOX_DOMAIN_SESSION_BOUND 7
#define CPRISK_WHITEBOX_DOMAIN_IMPORT_ENCRYPTION 8
#define CPRISK_WHITEBOX_DOMAIN_HEADER_ENCRYPTION 9
#define CPRISK_WHITEBOX_DOMAIN_COUNT 9

#endif /* CPRISK_ARMOR_ABI_H */
