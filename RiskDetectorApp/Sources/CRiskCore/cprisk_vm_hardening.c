// cprisk_vm_hardening.c — VM 解释器加固融合层（“做什么”与“不做什么”）。
// 本文件把五个子模块挂进 VM 主循环：状态完整性 FNV-1a 链、伪依赖注入、
// 按需代码块校验、路径膨胀、以及 VM×CFF 融合；它不做真正的字节码解密，
// 也不提供可认证的完整性（详见各函数注释）。所有入口就地读写调用方传入的
// cprisk_vm_interp_frame_t，不分配堆内存、不加锁；同一 frame 必须由单线程
// 顺序驱动。全部函数对 NULL 静默返回，失败采用 fail-silent 毒化而非崩溃。

/*
 *  cprisk_vm_hardening.c
 *  CRiskCore
 *
 *  Unified hardening integration layer for the VM interpreter.
 *
 *  This file wires five hardening sub-modules into the VM loop:
 *    1. VM state integrity (FNV-1a checksum chain)
 *    2. Instruction reordering & fake dependencies
 *    3. Runtime on-demand bytecode block integrity verification
 *    4. Path explosion (opaque predicates, MBA decoys, anti-symbolic-execution)
 *    5. VM x CFF deep fusion (Feistel-encoded PC, state transitions)
 */

#include "include/CRiskCore.h"
#include "include/cprisk_vm_interpreter.h"
#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_limits.h"
#include "include/cprisk_secure_zero.h"
#include "include/cprisk_emulator_detect.h"
#include "vm_integrity.h"
#include "vm_cff_fusion.h"
#include "cprisk_vm_hardening.h"

#include <string.h>

/* ── Internal constants ── */

// 完整性状态“已激活”魔数；checkpoint 只在此魔数匹配时继续累积，否则整段跳过。
#define VMH_INT_MAGIC_ACTIVE     0x564D5354u   /* "VMST" */
// 版本种子基值：与 func_id 高 32 位异或后写入，用于识别跨函数的状态复用。
#define VMH_INT_VERSION_SEED     0x20240703u
// FNV-1a 的 64 位偏移基与质数，与 vm_integrity.c 保持同值；改动会使既有校验
// 链全部失效，升级时必须整体重算，不能只改一侧。
#define VMH_FNV_OFFSET_BIAS      0xCBF29CE484222325ULL
#define VMH_FNV_PRIME            0x100000001B3ULL
// CFF 初始化哨兵：transition/verify 只有在该值匹配时才进入 Feistel 路径。
#define VMH_CFF_MAGIC_INIT       0xCFF0CFF0u

/* ═══════════════════════════════════════════════════════════════════════════
 *  CFF fusion bridge helpers
 *
 *  vm_cff_fusion.c operates on vm_cff_fusion_ctx_t but the frame stores CFF
 *  state in flat fields.  These helpers marshal between the two layouts.
 * ═══════════════════════════════════════════════════════════════════════════ */

// 把 frame 中的扁平 CFF 字段搬进 vm_cff_fusion_ctx_t（Feistel 子模块的工作结构）。
// - ctx 由调用方提供且必须非 NULL；fr 也必须非 NULL（无 NULL 检查，属内部约定）。
// - 先整块清零，避免结构体填充字节把旧栈数据带进后续哈希。
// - 返回: 无；线程: 纯内存拷贝，但同一 frame 必须单线程访问；平台: 无分支差异。
static void vmh_cff_load_from_frame(vm_cff_fusion_ctx_t *ctx,
                                     const cprisk_vm_interp_frame_t *fr)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->func_id          = fr->func_id;
    memcpy(ctx->bytecode_hash, fr->cff_bytecode_hash, 32);
    memcpy(ctx->rk, fr->cff_rk, sizeof(ctx->rk));
    ctx->encoded_state    = fr->cff_encoded_state;
    ctx->cff_magic        = fr->cff_magic;
    memcpy(ctx->trace_buffer, fr->cff_trace_buffer, sizeof(ctx->trace_buffer));
    ctx->trace_pos        = fr->cff_trace_pos;
    ctx->opaque_chain     = fr->opaque_chain;
    ctx->state_encoded    = fr->cff_state_encoded;
    ctx->corruption_detected = fr->cff_corruption_detected;
}

// load 的逆过程：把 CFF 子模块更新后的可变状态写回 frame。
// - func_id 与 bytecode_hash 归 frame 所有，这里刻意不回写，避免形成两份可能分叉的副本。
// - fr/ctx 由调用方保证非 NULL；返回: 无；线程: 单线程 per-frame；平台: 无。
static void vmh_cff_store_to_frame(cprisk_vm_interp_frame_t *fr,
                                    const vm_cff_fusion_ctx_t *ctx)
{
    memcpy(fr->cff_rk, ctx->rk, sizeof(fr->cff_rk));
    fr->cff_encoded_state    = ctx->encoded_state;
    fr->cff_magic            = ctx->cff_magic;
    memcpy(fr->cff_trace_buffer, ctx->trace_buffer, sizeof(fr->cff_trace_buffer));
    fr->cff_trace_pos        = ctx->trace_pos;
    fr->opaque_chain         = ctx->opaque_chain;
    fr->cff_state_encoded    = ctx->state_encoded;
    fr->cff_corruption_detected = ctx->corruption_detected;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  FNV-1a hash helpers (inline, for block integrity checks)
 * ═══════════════════════════════════════════════════════════════════════════ */

// 流式 FNV-1a（64 位）：逐字节异或后乘质数，能用返回值继续续算。
// - data 仅在 len==0 时允许为 NULL；hash 为上一段的结果（初始值用 VMH_FNV_OFFSET_BIAS）。
// - 返回: 累积哈希。线程: 纯函数可重入；平台: 无分支差异。
// - 安全性质: 无密钥、抗碰撞能力弱，只用于发现整块清零/误改，不能当认证标签。
static inline uint64_t vmh_fnv1a_u64(uint64_t hash, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint64_t)data[i];
        hash *= VMH_FNV_PRIME;
    }
    return hash;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  cprisk_vm_hardening_init
 * ═══════════════════════════════════════════════════════════════════════════ */

// 初始化一个 VM frame 的全部加固状态，必须在该 frame 进入主循环前调用一次。
// - fr: 调用方拥有的 frame；为 NULL 时直接返回（不做任何事）。
// - 返回: 无。初始化本身不返回错误；若环境被判定为敌对，改为静默毒化校验链。
// - 线程: 仅允许单线程调用；函数写入 frame 的多数字段，不能与其他步骤并发。
// - 平台: 仅额外调用 cprisk_emulator_probe()，无架构分支；模拟器上同样执行。
// - 失败语义: fail-silent。毒化只降低最终结果的可信度，不抛异常、不 abort。
void cprisk_vm_hardening_init(cprisk_vm_interp_frame_t *fr)
{
    if (!fr) return;

    /* ── Task 1: VM state integrity ── */
    fr->vm_integrity_magic      = VMH_INT_MAGIC_ACTIVE;
    // 混入 func_id 高 32 位，使不同函数即使执行相同序列也得到不同的版本/链起点。
    fr->vm_integrity_version    = VMH_INT_VERSION_SEED ^ (uint32_t)(fr->func_id >> 32);
    // 初值必须是 FNV 偏移基而非 0：check 会把“执行过但链为 0”直接判为断裂。
    fr->vm_integrity_checksum   = VMH_FNV_OFFSET_BIAS;
    fr->vm_integrity_exec_count = 0;
    fr->vm_integrity_corrupted  = 0;
    {
        // tag 是 func_id 与版本种子的字节展开，仅用于“状态是否被整体换掉”的廉价检查。
        uint64_t tag_seed = fr->func_id ^ (uint64_t)fr->vm_integrity_version;
        for (int i = 0; i < 8; i++)
            fr->vm_integrity_tag[i] = (uint8_t)(tag_seed >> (i * 8));
    }

    /* ── Task 3: Runtime on-demand decryption context ── */
    {
        // 块密钥只由 func_id 与固定常量派生，不含随机数；因此它可被复现，
        // 只用于让不同函数的块哈希域分离，不能当作秘密密钥。
        uint64_t bk = fr->func_id ^ 0xDEADBEEFCAFEBABEULL;
        /* FNV-1a mix with block_id=0 to warm up */
        bk ^= (bk >> 33);
        bk *= 0xFF51AFD7ED558CCDULL;
        bk ^= (bk >> 33);
        fr->decrypt_block_key   = bk;
        /*
         * Bytecode is laid out as N × 9-byte instructions. A bytecode
         * segment whose length is not a multiple of 9 (and especially one
         * with blen < 9) is malformed. Previously block_count was just
         * `blen / 9`, so a 0..8-byte body silently became `block_count = 0`
         * and the JIT decryption path was left uninitialized. Reject the
         * malformed length up front by leaving the block context empty
         * and setting a sentinel; downstream code already treats
         * decrypt_block_count == 0 as "decryption unavailable" and falls
         * through to the plain interpreter path.
         */
        // 指令定长 9 字节，块数向下取整；blen<9 时块数为 0，下游按“不可用”走明文解释器，
        // 而不是让 0..8 字节的畸形体静默产生 0 个块（见上方英文说明）。
        fr->decrypt_block_count = (fr->blen >= 9u) ? (fr->blen / 9u) : 0u;
        // UINT32_MAX 是“尚无块”的哨兵；与真实块号区分，避免首次块切换时误清位图。
        fr->decrypt_current_block = UINT32_MAX;    /* no block decrypted yet */
        // 位图与明文副本清零：位图记录已校验块，副本目前未使用，但必须防止旧 frame 残留。
        memset(fr->decrypt_block_map, 0, sizeof(fr->decrypt_block_map));
        memset(fr->decrypt_code_copy, 0, sizeof(fr->decrypt_code_copy));
    }

    /* ── Task 4: Path explosion context ── */
    fr->pe_func_id        = fr->func_id;
    fr->pe_fork_counter   = 0;
    fr->pe_decoy_counter  = 0;
    fr->pe_mba_xor_mask   = 0xA5A5A5A5u;
    {
        /*
         * Derive pe_bytecode_hash from bytecode. Mix in `blen` BEFORE the
         * byte loop so two bytecode bodies where one is a strict prefix of
         * the other produce different hashes — a plain FNV-1a chain over
         * the bytes alone would collide on (prefix, prefix||suffix) pairs.
         * This matches the length-prefix discipline used by other digest
         * derivations in the codebase (string CPRisk-MAC ABI, etc.).
         */
        // 先用 4 字节小端长度做前缀，再哈希字节体：否则 (prefix) 与 (prefix||suffix)
        // 的纯 FNV 链会得到相同值，两个不同函数可能共享同一路径膨胀状态。
        uint32_t h = 0x811C9DC5u;
        h ^= (fr->blen      ) & 0xFFu; h *= 0x01000193u;
        h ^= (fr->blen >>  8) & 0xFFu; h *= 0x01000193u;
        h ^= (fr->blen >> 16) & 0xFFu; h *= 0x01000193u;
        h ^= (fr->blen >> 24) & 0xFFu; h *= 0x01000193u;
        const uint8_t *p = fr->code;
        const uint32_t lim = fr->blen;
        for (uint32_t i = 0; i < lim; i++) {
            h ^= p[i];
            h *= 0x01000193u;
        }
        fr->pe_bytecode_hash = h;
        // 累加器/掩码都由字节码哈希派生，保证路径膨胀只依赖函数自身代码，不引入全局熵。
        fr->pe_mba_accumulator = h ^ (uint32_t)fr->func_id;
        fr->pe_mba_xor_mask   ^= h;
    }
    memset(fr->pe_path_marker, 0, sizeof(fr->pe_path_marker));

    /* ── Task 5: CFF fusion ── */
    {
        /* Build a 32-byte bytecode hash for key derivation */
        uint8_t bch[32];
        {
            /* Lightweight hash: FNV-1a over bytecode segment */
            // 不是密码学 KDF：每轮把同一个 func_id 再喂一次只为让 32 个字节彼此不同，
            // 从而避免 CFF 子模块拿到全零/重复的“哈希”。不要把它当抗碰撞承诺。
            uint64_t h64 = VMH_FNV_OFFSET_BIAS;
            h64 = vmh_fnv1a_u64(h64, fr->code, fr->blen);
            for (int i = 0; i < 32; i++) {
                h64 = vmh_fnv1a_u64(h64, (const uint8_t *)&fr->func_id, sizeof(fr->func_id));
                bch[i] = (uint8_t)(h64 >> ((i & 7) * 8));
            }
        }
        memcpy(fr->cff_bytecode_hash, bch, 32);

        vm_cff_fusion_ctx_t ctx;
        vm_cff_fusion_init(&ctx, fr->func_id, bch);
        vmh_cff_store_to_frame(fr, &ctx);

        // 首次转移前没有“已编码 PC”，置 0 只是占位；真实值由 cff_transition 写入。
        fr->cff_vpc = 0;  /* will be set on first transition */
    }

    /* ── C-layer emulator detection ── */
    {
        // 结果写入 frame 供上层读取；探测本身不改全局状态，可在单线程 init 中安全调用。
        const uint32_t emu_flags = cprisk_emulator_probe();
        fr->emulator_flags = emu_flags;

        /* If the environment looks hostile, poison the integrity chain so that
         * the final VM result is subtly corrupted — the attacker's risk score
         * becomes unreliable without a visible crash or assert. */
        if (cprisk_emulator_is_hostile(emu_flags)) {
            /* Mix a deterministic-looking but wrong constant into the FNV chain */
            // 0x9E3779B97F4A7C15 是 64 位黄金分割常量，乘上去让毒化值看起来像正常混合结果；
            // 置 corrupted 后 checkpoint 会在每步持续污染 acc，但不会崩溃或显式报错。
            fr->vm_integrity_checksum ^= (uint64_t)emu_flags * 0x9E3779B97F4A7C15ULL;
            fr->vm_integrity_corrupted = 1;
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Task 1: Integrity checkpoint
 * ═══════════════════════════════════════════════════════════════════════════ */

// 每个逻辑操作后调用：把 (logical_op, pc) 折入 FNV 校验链并推进执行计数。
// - fr: 目标 frame；NULL 或魔数不匹配时静默跳过（未初始化的 frame 不参与校验）。
// - pc: 虚拟 PC，只保留低 56 位；logical_op: 只保留低 8 位（高位被丢弃）。
// - 返回: 无。线程: 每 frame 单线程；无全局状态。平台: 纯整数运算，无分支差异。
// - 失败语义: 发现异常只置 corrupted 并毒化 acc，不向调用方返回错误。
void cprisk_vm_hardening_integrity_checkpoint(cprisk_vm_interp_frame_t *fr,
                                               uint32_t pc,
                                               uint32_t logical_op)
{
    if (!fr) return;
    if (fr->vm_integrity_magic != VMH_INT_MAGIC_ACTIVE) return;

    /* Accumulate checksum_chain with event data */
    // 高 8 位放操作类型、低 56 位放 PC，避免两个不同事件拼出同一 64 位输入。
    uint64_t val = ((uint64_t)(logical_op & 0xFF) << 56) | (pc & 0x00FFFFFFFFFFFFFFULL);
    fr->vm_integrity_checksum ^= val;
    fr->vm_integrity_checksum *= VMH_FNV_PRIME;

    fr->vm_integrity_exec_count++;

    /* Every 256 steps: check for zero chain (indicates corruption) */
    // 每 256 步一次周期性自检：链恰好为 0 的概率极低，被清零/置零攻击会在这里暴露。
    if ((fr->vm_integrity_exec_count & 0xFFu) == 0u) {
        if (fr->vm_integrity_checksum == 0ULL) {
            fr->vm_integrity_corrupted = 1;
        }
        /* Refresh integrity tag */
        // tag = 链 ^ 计数，再逐字节异或 i*0x5A；加入位置相关常量，避免全同字节。
        uint64_t new_tag_seed = fr->vm_integrity_checksum ^ fr->vm_integrity_exec_count;
        for (int i = 0; i < 8; i++)
            fr->vm_integrity_tag[i] = (uint8_t)(new_tag_seed >> (i * 8)) ^ (uint8_t)(i * 0x5Au);
    }

    /* Silent poisoning if corrupted */
    // 用 DE AD BE EF 分别翻转 acc 的 4 个字节：结果继续可运行，但风险评分不再可信。
    if (fr->vm_integrity_corrupted) {
        fr->acc[0] ^= 0xDEu;
        fr->acc[1] ^= 0xADu;
        fr->acc[2] ^= 0xBEu;
        fr->acc[3] ^= 0xEFu;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Task 2: Fake dependency injection
 * ═══════════════════════════════════════════════════════════════════════════ */

// 注入对 acc/opaque_chain 的伪数据依赖，让反编译器误以为结果依赖额外变量。
// - fr: NULL 时无操作；pc/hvar: 参与混合的位置与句柄，均为 32 位、只取低位。
// - 返回: 无；线程: 单线程 per-frame；平台: 无符号移位/乘加定义良好，无架构分支。
// - 失败语义: 无失败路径；最坏情况是 acc 某字节被扰动，由后续步骤/CFF 层吸收。
void cprisk_vm_hardening_fake_dep_inject(cprisk_vm_interp_frame_t *fr,
                                          uint32_t pc,
                                          uint32_t hvar)
{
    if (!fr) return;

    /*
     * Insert pseudo-dependencies into acc and opaque state.
     * MBA obfuscated: result looks data-dependent but is actually
     * a permutation that folds back to the original value.
     */

    /* MBA: (a|b) - (a&b) = a ^ b */
    uint32_t acc_val = ((uint32_t)fr->acc[0]) |
                       (((uint32_t)fr->acc[1]) << 8) |
                       (((uint32_t)fr->acc[2]) << 16) |
                       (((uint32_t)fr->acc[3]) << 24);

    // MBA 恒等式：(a|b) - (a&b) == a^b，用减法形式隐藏“异或”这一明显特征。
    uint32_t mix = (acc_val | pc) - (acc_val & pc);  /* MBA XOR */
    mix ^= hvar;
    // 0x9E3779B9 为 32 位黄金分割常量；右移 8 位丢掉低位，只保留扩散后的中段。
    mix = (mix * 0x9E3779B9u) >> 8;

    /* Fold back: the net effect is a permutation of acc, not destruction */
    // 只翻转 acc 中的一个字节（pc&3 选槽），把扰动限制在可解释范围内，不改变控制流。
    fr->acc[pc & 3u] ^= (uint8_t)(mix >> 16);

    /* Also perturb opaque chain in a reversible way */
    fr->opaque_chain ^= (uint32_t)(pc ^ hvar);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Task 3: On-demand "decrypt" / block integrity verification
 *
 *  Since code is const (read-only mmap), we cannot do real XOR decrypt in
 *  place.  Instead, we verify block integrity via FNV-1a hash comparison.
 *  If the block hash does not match expected value derived from func_id +
 *  block_id, we mark integrity as corrupted.
 * ═══════════════════════════════════════════════════════════════════════════ */

// 取指前调用：确保 pc 所在 9 字节代码块“已处理”，并做一次块级 FNV 探测。
// - fr: NULL 或 blen==0 时无操作；pc 为当前虚拟 PC，块号 = pc/9。
// - 返回: 无；越界块号或位图下标直接忽略（不报错）。
// - 线程: 只改 frame 内的位图与游标，单线程驱动；平台: 纯内存读，无平台分支。
// - 失败语义: 块哈希为 0 时置 corrupted；其余篡改无法识别（见函数末尾的限制说明）。
void cprisk_vm_hardening_ondemand_decrypt(cprisk_vm_interp_frame_t *fr,
                                           uint32_t pc)
{
    if (!fr) return;
    if (fr->blen == 0u) return;

    // 9 是字节码指令的固定长度；pc 只用于定位块，块内偏移不影响校验。
    const uint32_t block_id = pc / 9u;
    if (block_id >= fr->decrypt_block_count) return;

    /* Check if block is already verified (bit set in block_map) */
    // 位图每个块 1 bit；byte_idx 的上界检查同时限制了可跟踪块数（512 字节位图 → 4096 块）。
    uint32_t byte_idx = block_id / 8u;
    uint32_t bit_idx  = block_id % 8u;
    if (byte_idx >= sizeof(fr->decrypt_block_map)) return;

    uint8_t mask = (uint8_t)(1u << bit_idx);
    if (fr->decrypt_block_map[byte_idx] & mask) {
        /* Already verified; check previous block re-encryption concept:
         * If we moved to a new block, mark the previous one as unverified
         * (simulating re-encrypt). */
        if (fr->decrypt_current_block != block_id && fr->decrypt_current_block != UINT32_MAX) {
            // 切换块时清掉上一块的“已校验”位，模拟“离开即重新加密”的生命周期；
            // 若不清，位图会单调膨胀，且无法反映当前只应保留一个活动块。
            uint32_t prev_byte = fr->decrypt_current_block / 8u;
            uint32_t prev_bit  = fr->decrypt_current_block % 8u;
            if (prev_byte < sizeof(fr->decrypt_block_map)) {
                fr->decrypt_block_map[prev_byte] &= ~(uint8_t)(1u << prev_bit);
            }
        }
        fr->decrypt_current_block = block_id;
        return;
    }

    /* Compute FNV-1a hash of the current 9-byte block */
    // 末块可能不足 9 字节：夹到 blen，避免越过只读代码段末尾读取。
    uint32_t block_start = block_id * 9u;
    uint32_t block_end   = block_start + 9u;
    if (block_end > fr->blen) block_end = fr->blen;

    uint64_t block_hash = VMH_FNV_OFFSET_BIAS;
    block_hash = vmh_fnv1a_u64(block_hash, fr->code + block_start, block_end - block_start);

    /* Derive expected hash from func_id + block_id + block_key */
    // 注意：expected 目前只计算、未参与下面的判定（代码未真正加密，没有可比的预计算表）。
    // 保留它用于将来接入“每函数预计算哈希表”；当前判定只看 block_hash 是否为 0。
    uint64_t expected = fr->decrypt_block_key;
    expected ^= (uint64_t)block_id;
    expected *= VMH_FNV_PRIME;
    expected ^= (fr->func_id >> 32) ^ (uint64_t)block_id * 0x100000001B3ULL;

    /*
     * We cannot do an exact comparison because the code is not actually
     * encrypted; we only check that the block is non-trivial (hash != 0).
     * This still detects zeroing-out attacks.  For production, a precomputed
     * hash table per function would be used.
     */
    // 只能发现“整块被清零”这类粗暴改写；定向替换指令且保持哈希非零不会被发现。
    if (block_hash == 0ULL) {
        fr->vm_integrity_corrupted = 1;
    }

    /* Mark as verified */
    // 置位后同一块再次进入会走“已校验”快路径，只有切换块时才清上一块的位。
    fr->decrypt_block_map[byte_idx] |= mask;
    fr->decrypt_current_block = block_id;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Task 4: Path explosion checkpoint
 * ═══════════════════════════════════════════════════════════════════════════ */

// 路径膨胀检查点：插入不透明谓词、MBA 更新与周期性的“费马诱饵”分支。
// - fr: NULL 时无操作；pc 参与混合，决定 path_marker 的槽位。
// - 返回: 无；线程: 单线程 per-frame；平台: 64 位有符号乘法的溢出行为依赖编译器，
//   该谓词“恒真”的前提是不溢出，因此不能把它当成可移植的语义保证。
// - 失败语义: 无显式失败；诱饵分支设计为不可达，若命中只累加 decoy_counter。
void cprisk_vm_hardening_path_explosion(cprisk_vm_interp_frame_t *fr,
                                         uint32_t pc)
{
    if (!fr) return;

    /* Inline opaque predicate: x*x >= 0 (always true for integers) */
    // 不透明谓词：符号执行器必须验证 x*x 非负，而对有符号溢出它无法轻易折叠常量。
    int64_t x = (int64_t)(fr->pe_mba_accumulator ^ pc);
    if (x * x < 0) {
        /* Unreachable — forces symbolic executor to consider this path */
        return;
    }

    /* Update MBA accumulator: MBA XOR = (a|b) - (a&b) */
    // 用位运算恒等式推进累加器，使相邻检查点之间没有可直接消去的线性关系。
    {
        uint32_t a = fr->pe_mba_accumulator;
        uint32_t b = pc;
        fr->pe_mba_accumulator = (a | b) - (a & b);
    }

    /* Update MBA xor_mask with rotation */
    // 循环左移 1 位（无符号，移位量固定为 1/31，均定义良好），让掩码逐检查点变化。
    fr->pe_mba_xor_mask = (fr->pe_mba_xor_mask << 1) | (fr->pe_mba_xor_mask >> 31);

    /* Update path marker */
    // 32 字节路径标记按 pc 取槽，只混入累加器的高字节；用于让不同执行路径留下不同痕迹。
    {
        uint32_t idx = pc % 32u;
        fr->pe_path_marker[idx] ^= (uint8_t)(fr->pe_mba_accumulator >> 24);
    }

    fr->pe_fork_counter++;

    /* Every 64 steps: inline Fermat-style Diophantine constraint bomb */
    // 每 64 步插入一次费马型约束：a,b 强制为奇数（|1），c 由 lhs 派生，
    // lhs == c^3 在整数上无解，符号执行器却必须展开证明，代价高。
    if ((fr->pe_fork_counter & 0x3Fu) == 0u) {
        uint32_t a = (fr->pe_mba_accumulator & 0xFFu) | 1u;
        uint32_t b = ((fr->pe_mba_accumulator >> 8) & 0xFFu) | 1u;

        /* a^3 + b^3 vs c^3 — Fermat's Last Theorem says no solution for n=3 */
        // 乘法前先提升到 uint64，避免 32 位立方溢出；c 取 lhs>>3 只是构造诱饵输入。
        uint64_t lhs = ((uint64_t)a * a * a) + ((uint64_t)b * b * b);
        uint32_t c = (uint32_t)(lhs >> 3);
        uint64_t c_cubed = (uint64_t)c * c * c;

        /* lhs == c_cubed is always false (Fermat), but the symbolic executor
         * must prove it, which is computationally expensive. */
        if (lhs == c_cubed) {
            /* Unreachable decoy path */
            fr->pe_decoy_counter++;
        }

        /* Mix state */
        // 把 lhs 的高低 32 位分别折回链与累加器，保持后续检查点仍依赖本步结果。
        fr->opaque_chain ^= (uint32_t)lhs;
        fr->pe_mba_accumulator ^= (uint32_t)(lhs >> 32);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Task 5: CFF fusion transition
 * ═══════════════════════════════════════════════════════════════════════════ */

// 分支/周期点调用：用 Feistel 网络编码当前 PC，再推进 CFF 状态机。
// - fr: NULL 或 cff_magic 尚未初始化时直接返回；current_pc 为编码输入。
// - next_pc_hint: 仅当 is_branch 非 0 时作为转移提示，否则固定传 0。
// - 返回: 无；结果写回 fr->cff_vpc 与 CFF 字段。线程: 单线程 per-frame。
// - 平台: 纯整数运算，无平台分支。失败语义: 魔数不符即视为“未启用”，静默不转移。
void cprisk_vm_hardening_cff_transition(cprisk_vm_interp_frame_t *fr,
                                         uint32_t current_pc,
                                         uint32_t next_pc_hint,
                                         int is_branch)
{
    if (!fr) return;
    if (fr->cff_magic != VMH_CFF_MAGIC_INIT) return;

    /* Marshal flat frame fields into vm_cff_fusion_ctx_t */
    // 扁平字段与子模块结构体之间的编组是必要的：子模块不依赖 frame 的 ABI 布局。
    vm_cff_fusion_ctx_t ctx;
    vmh_cff_load_from_frame(&ctx, fr);

    /* Encode the current PC through the Feistel network */
    // 编码后的 PC 才参与状态转移，攻击者在 trace 中看到的是编码值而非真实控制流。
    uint32_t current_encoded = vm_cff_fusion_encode_pc(&ctx, current_pc);

    /* Perform the state transition */
    // 只有真实分支才把 hint 交给转移函数；顺序落空传 0，避免伪造分支提示。
    uint32_t next_encoded;
    vm_cff_fusion_transition(&ctx, current_encoded, &next_encoded,
                              is_branch ? next_pc_hint : 0u);

    /* Update CFF-managed virtual PC */
    fr->cff_vpc = (uint64_t)next_encoded;

    /* Write back to frame */
    vmh_cff_store_to_frame(fr, &ctx);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Task 5: CFF fusion integrity verify
 * ═══════════════════════════════════════════════════════════════════════════ */

// CFF 完整性验证：检查 Feistel 状态往返一致性与轨迹/魔数是否被改写。
// - fr: NULL 或魔数未初始化时直接返回；无其他参数。
// - 返回: 无。线程: 单线程 per-frame；平台: 纯整数运算，无分支差异。
// - 失败语义: 检测到损坏只置 cff_corruption_detected 并毒化 acc，不崩溃、不报错。
void cprisk_vm_hardening_cff_verify(cprisk_vm_interp_frame_t *fr)
{
    if (!fr) return;
    if (fr->cff_magic != VMH_CFF_MAGIC_INIT) return;

    /* Marshal into ctx */
    vm_cff_fusion_ctx_t ctx;
    vmh_cff_load_from_frame(&ctx, fr);

    vm_cff_fusion_verify_integrity(&ctx);

    /* Write back */
    // 必须回写：验证过程可能更新轨迹计数/损坏标志，这些状态要留给下一次转移使用。
    vmh_cff_store_to_frame(fr, &ctx);

    /* Silent poisoning if corruption detected */
    // 与 Task 1 使用同一组毒化字节，使上层无法区分“哪一层”检测到了异常。
    if (fr->cff_corruption_detected) {
        fr->acc[0] ^= 0xDEu;
        fr->acc[1] ^= 0xADu;
        fr->acc[2] ^= 0xBEu;
        fr->acc[3] ^= 0xEFu;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Cleanup
 * ═══════════════════════════════════════════════════════════════════════════ */

// 结束一次 VM 运行时调用：用 cprisk_secure_zero 擦除所有密钥/校验/轨迹状态。
// - fr: NULL 时无操作；不释放 frame 本身（所有权在调用方）。
// - 返回: 无；线程: 必须在主循环退出后、frame 被复用/释放前调用，不能与步骤并发。
// - 平台: secure_zero 由外部实现负责防优化；此处无架构分支。
// - 失败语义: 无失败路径；重复调用安全（对已清零内存再清零）。
void cprisk_vm_hardening_cleanup(cprisk_vm_interp_frame_t *fr)
{
    if (!fr) return;

    /* Task 1: integrity state */
    // 逐字段擦除而不是整块 memset：frame 中还有其他子系统的状态，不能一并清掉。
    cprisk_secure_zero(&fr->vm_integrity_magic,    sizeof(fr->vm_integrity_magic));
    cprisk_secure_zero(&fr->vm_integrity_version,  sizeof(fr->vm_integrity_version));
    cprisk_secure_zero(&fr->vm_integrity_exec_count, sizeof(fr->vm_integrity_exec_count));
    cprisk_secure_zero(&fr->vm_integrity_checksum, sizeof(fr->vm_integrity_checksum));
    cprisk_secure_zero(fr->vm_integrity_tag,       sizeof(fr->vm_integrity_tag));
    cprisk_secure_zero(&fr->vm_integrity_corrupted, sizeof(fr->vm_integrity_corrupted));

    /* Task 3: decrypt context */
    // block_key 是派生秘密，必须清零；位图/副本也一并清除，避免泄露“执行过哪些块”。
    cprisk_secure_zero(&fr->decrypt_current_block, sizeof(fr->decrypt_current_block));
    cprisk_secure_zero(&fr->decrypt_block_count,   sizeof(fr->decrypt_block_count));
    cprisk_secure_zero(&fr->decrypt_block_key,     sizeof(fr->decrypt_block_key));
    cprisk_secure_zero(fr->decrypt_block_map,      sizeof(fr->decrypt_block_map));
    cprisk_secure_zero(fr->decrypt_code_copy,      sizeof(fr->decrypt_code_copy));

    /* Task 4: path explosion context */
    // 路径痕迹会泄露实际执行路径与函数标识，退出时必须清掉而非仅重置计数。
    cprisk_secure_zero(&fr->pe_func_id,         sizeof(fr->pe_func_id));
    cprisk_secure_zero(&fr->pe_bytecode_hash,   sizeof(fr->pe_bytecode_hash));
    cprisk_secure_zero(&fr->pe_fork_counter,    sizeof(fr->pe_fork_counter));
    cprisk_secure_zero(&fr->pe_decoy_counter,   sizeof(fr->pe_decoy_counter));
    cprisk_secure_zero(&fr->pe_mba_accumulator, sizeof(fr->pe_mba_accumulator));
    cprisk_secure_zero(&fr->pe_mba_xor_mask,    sizeof(fr->pe_mba_xor_mask));
    cprisk_secure_zero(fr->pe_path_marker,      sizeof(fr->pe_path_marker));

    /* Task 5: CFF fusion context */
    // cff_rk 是 Feistel 轮密钥；cff_magic 一并清零，防止旧 frame 被误认为已初始化。
    cprisk_secure_zero(fr->cff_rk,                sizeof(fr->cff_rk));
    cprisk_secure_zero(&fr->cff_encoded_state,    sizeof(fr->cff_encoded_state));
    cprisk_secure_zero(&fr->cff_magic,            sizeof(fr->cff_magic));
    cprisk_secure_zero(fr->cff_trace_buffer,      sizeof(fr->cff_trace_buffer));
    cprisk_secure_zero(&fr->cff_trace_pos,        sizeof(fr->cff_trace_pos));
    cprisk_secure_zero(fr->cff_bytecode_hash,     sizeof(fr->cff_bytecode_hash));
    cprisk_secure_zero(&fr->cff_state_encoded,    sizeof(fr->cff_state_encoded));
    cprisk_secure_zero(&fr->cff_corruption_detected, sizeof(fr->cff_corruption_detected));
    cprisk_secure_zero(&fr->cff_vpc,              sizeof(fr->cff_vpc));
}
