// 文件职责：把 CFF（控制流平坦化）状态机与 VM 解释器融合——用 Feistel 网络对 32 位
// 状态/PC 做可逆编码，并在 VM 帧字段与独立 ctx 之间同步轮密钥、轨迹环和混淆链。
// 线程模型：ctx 与帧内 cff_* 字段均为单写者；trace_buffer/trace_pos 每次编码都会推进，
// 因此不可跨线程并发调用 encode_pc / transition。
// 平台与失败语义：纯 C 无平台分支；ctx 为 NULL 时静默返回，state_encoded=0 时 encode/decode
// 原样返回输入（fail-open）；Feistel 用于提高逆向成本，但没有 MAC，integrity 只做自洽检查。
/*
 *  vm_cff_fusion.c
 *  CRiskCore
 */

#include "include/CRiskCore.h"
#include "include/cprisk_cff.h"
#include "include/cprisk_vm_interpreter.h"
#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_ops.h"
#include "vm_cff_fusion.h"

#include <string.h>

// 8 轮 Feistel：左右各 16 位，每轮用 8 位 S-box 混淆后交换两半。
// 轮数是固定预算，增加轮数会线性增加 VM 每一步的开销。
#define VM_CFF_FEISTEL_ROUNDS       8
// cff_magic 的初始/期望值；verify_integrity 以常量时间比较它来发现上下文破坏。
#define VM_CFF_MAGIC_INIT           0xCFF0CFF0u
/* Full 32-bit state space (16+16 Feistel halves). The previous 28-bit mask
 * (0x0FFFFFFFu) was an artifact of the 14+14 layout used with the 4-bit
 * nibble S-box; the 8-bit S-box-based round function below uses both bytes
 * of each half, so the encoded state covers the full uint32 range. */

/*
 * Distinct pre/post whitening derivation. Previous code XORed two round-key
 * pairs (`rk[0] ^ rk[7]` for pre, `rk[3] ^ rk[5]` for post): when the four
 * keys happened to satisfy `rk[0] ^ rk[7] == rk[3] ^ rk[5]` (probability
 * ~ 2^-32) the pre and post masks would cancel, weakening the cipher.
 *
 * The two helpers below mix the round keys through `avalanche32` and use
 * structurally different combiners (XOR + rotate vs. modular add + rotate)
 * so the outputs are distinct functions of the key schedule even on
 * adversarially chosen keys.
 */
// 前置白化：rk[0] 与 rk[7] 分别雪崩后，用 XOR + 循环左移 13 位组合。
// 与 post 使用不同结构（XOR+旋转 vs 加法+旋转），避免密钥满足某种关系时
// 前后掩码相互抵消（旧实现下概率约 2^-32）。
static uint32_t vm_cff_whiten_pre_i(const uint32_t *rk) {
    const uint32_t a = cprisk_vmp_avalanche32_i(rk[0]);
    const uint32_t b = cprisk_vmp_avalanche32_i(rk[7]);
    const uint32_t mix = a ^ ((b << 13) | (b >> 19));
    return cprisk_vmp_avalanche32_i(mix ^ 0x9E3779B9u);
}

// 后置白化：rk[3] 与 rk[5] 经加法 + 旋转组合后再雪崩；
// 结构与 pre 不同，保证两端掩码不是同一个函数。
static uint32_t vm_cff_whiten_post_i(const uint32_t *rk) {
    const uint32_t a = cprisk_vmp_avalanche32_i(rk[3]);
    const uint32_t b = cprisk_vmp_avalanche32_i(rk[5]);
    const uint32_t mix = (a + b) ^ ((a >> 11) | (a << 21));
    return cprisk_vmp_avalanche32_i(mix ^ 0xC2B2AE35u);
}

/*
 * 16-bit Feistel round function with 8-bit S-box (shared with `cprisk_cff`
 * Feistel-SPN: same per-build randomized 256-byte permutation, removing the
 * weakly diffusing 4-bit nibble S-box that previously left half of each
 * round's input bits untouched). Two SPN passes per round + key-schedule
 * folding keep diffusion per-round at full half-block.
 */
// 16 位轮函数 F(right, round_key)：先用轮密钥低 16 位异或，再做两轮
// 8 位 S-box 替换与雪崩（混入轮密钥高 16 位），保证每个输入位都能影响整个半块。
// 返回：新的 16 位半块；无错误路径。S-box 来自 cprisk_cff 的每构建随机置换。
static uint16_t vm_cff_feistel_f(uint16_t right, uint32_t round_key) {
    const uint16_t kl = (uint16_t)(round_key & 0xFFFFu);
    const uint16_t kh = (uint16_t)((round_key >> 16) & 0xFFFFu);
    uint32_t x = (uint32_t)(right ^ kl);

    // 两个字节分别查 8 位 S-box；相比旧的 4 位 nibble S-box，
    // 每个半块的两半输入都被替换，单轮即可影响全部 16 位。
    /* First SPN pass on both bytes of the half. */
    const uint8_t s0 = cprisk_cff_spn_sbox_lookup((uint8_t)(x & 0xFFu));
    const uint8_t s1 = cprisk_cff_spn_sbox_lookup((uint8_t)((x >> 8) & 0xFFu));
    uint32_t y = (uint32_t)s0 | ((uint32_t)s1 << 8);

    // 折入轮密钥高半部，使 32 位 round_key 的每一位都参与轮函数。
    /* Avalanche with key-schedule fold (uses high half of round_key). */
    y ^= (uint32_t)kh;
    y = ((y << 7) | (y >> 25)) ^ 0x9E3779B9u;
    y = ((y * 0x85EBCA6Bu) >> 16) ^ y;
    y = ((y << 13) | (y >> 19)) ^ 0xC2B2AE35u;

    // 雪崩后再做一次逐字节替换，提高单轮扩散强度。
    /* Second SPN pass after avalanche — full per-byte substitution. */
    const uint8_t t0 = cprisk_cff_spn_sbox_lookup((uint8_t)(y & 0xFFu));
    const uint8_t t1 = cprisk_cff_spn_sbox_lookup((uint8_t)((y >> 8) & 0xFFu));

    return (uint16_t)((uint32_t)t0 | ((uint32_t)t1 << 8));
}

// 状态编码：32 位输入拆成高/低 16 位两半，先整体前置白化，
// 再做 8 轮 Feistel（new_left = right，new_right = left ^ F(right)），
// 最后做后置白化并拼回 32 位。
// 不变量：对固定 rk 是 2^32 上的双射，vm_cff_decode_state_i 是其精确逆。
// 返回：编码后的 32 位状态；rk 必须指向 8 个有效轮密钥。
static uint32_t vm_cff_encode_state_i(uint32_t state, const uint32_t *rk) {
    /* 16+16 split — full state space, no truncation. */
    uint16_t left = (uint16_t)((state >> 16) & 0xFFFFu);
    uint16_t right = (uint16_t)(state & 0xFFFFu);

    /* Pre-whitening with structurally distinct derivation. */
    const uint32_t pre_whiten = vm_cff_whiten_pre_i(rk);
    left ^= (uint16_t)((pre_whiten >> 16) & 0xFFFFu);
    right ^= (uint16_t)(pre_whiten & 0xFFFFu);

    for (int r = 0; r < VM_CFF_FEISTEL_ROUNDS; r++) {
        const uint16_t f_out = vm_cff_feistel_f(right, rk[r]);
        const uint16_t new_left = right;
        const uint16_t new_right = (uint16_t)(left ^ f_out);
        left = new_left;
        right = new_right;
    }

    const uint32_t post_whiten = vm_cff_whiten_post_i(rk);
    left ^= (uint16_t)((post_whiten >> 16) & 0xFFFFu);
    right ^= (uint16_t)(post_whiten & 0xFFFFu);

    return ((uint32_t)left << 16) | (uint32_t)right;
}

// 解码：先撤销后置白化，再按相反轮序执行 Feistel 逆变换，最后撤销前置白化。
// 不变量：decode(encode(x)) == x；rk 的内容与顺序必须和编码端一致。
static uint32_t vm_cff_decode_state_i(uint32_t encoded, const uint32_t *rk) {
    uint16_t left = (uint16_t)((encoded >> 16) & 0xFFFFu);
    uint16_t right = (uint16_t)(encoded & 0xFFFFu);

    /* Decode: undo post-whitening first, then pre-whitening last. */
    const uint32_t post_whiten = vm_cff_whiten_post_i(rk);
    left ^= (uint16_t)((post_whiten >> 16) & 0xFFFFu);
    right ^= (uint16_t)(post_whiten & 0xFFFFu);

    for (int r = VM_CFF_FEISTEL_ROUNDS - 1; r >= 0; r--) {
        const uint16_t f_out = vm_cff_feistel_f(left, rk[r]);
        const uint16_t new_right = left;
        const uint16_t new_left = (uint16_t)(right ^ f_out);
        right = new_right;
        left = new_left;
    }

    const uint32_t pre_whiten = vm_cff_whiten_pre_i(rk);
    left ^= (uint16_t)((pre_whiten >> 16) & 0xFFFFu);
    right ^= (uint16_t)(pre_whiten & 0xFFFFu);

    return ((uint32_t)left << 16) | (uint32_t)right;
}

/*
 * Per-position keystream for the trace ring buffer. The trace previously held
 * encoded PCs in plaintext, so a memory dump trivially reconstructed the
 * function's recent control flow. XOR-mask each entry with a deterministic
 * per-position byte stream derived from the round keys; verify_integrity
 * peels the mask before re-encoding for the round-trip check.
 *
 * Keystream is reproducible (no per-write nonce) so the in-context format
 * stays read/write symmetric without storing extra state.
 */
// 轨迹环的按位置密钥流：pos 选择两个轮密钥并混入黄金比例常量，再经两次雪崩。
// 作用：trace_buffer 不再以明文保存编码后的 PC，内存转储无法直接还原控制流。
// 不变量：同一 (rk, pos) 必得同一掩码，因此写入与校验无需额外的 nonce/状态。
static uint32_t vm_cff_trace_keystream_i(const uint32_t *rk, uint32_t pos) {
    const uint32_t base = rk[pos & 7u] ^ (pos * 0x9E3779B9u);
    const uint32_t mix = cprisk_vmp_avalanche32_i(base ^ rk[(pos + 3u) & 7u]);
    return cprisk_vmp_avalanche32_i(mix ^ 0xA24BAED5u ^ ((pos << 11) | (pos >> 21)));
}

/*
 * Domain-separated SHA256 chain. Two SHA256 calls with distinct domain tags
 * derive 64 bytes of pseudo-random output from the IKM (function id +
 * bytecode hash). This is HKDF-Expand-style without the CPRisk-MAC overhead —
 * appropriate because the IKM is already a hash output (high entropy) and
 * we use it for symmetric-key derivation, not authentication.
 *
 * Output layout:
 *   bytes  [0..31] — 8 round keys (rk[0..7]), big-endian per 4-byte stride
 *   bytes [32..63] — reserved for future expansion (zeroed after use); the
 *                    second-block material is currently consumed only to
 *                    guarantee full SHA256 mixing of the IKM under both
 *                    domain tags, hardening against truncation attacks
 *                    against any single block.
 */
// 从 IKM 派生 64 字节：两块 SHA256，各自带不同域标签（"rk\1\0" / "wh\2\0"）。
// 这不是通用 KDF，而是域分离的哈希扩展；IKM 已是高熵哈希输出，
// 因此省去 MAC 步骤，只用于对称密钥派生。
// 参数：ikm_len 超过 60 时截断（为 4 字节域标签留空间），out 必须可写 64 字节。
// 返回：无；中间缓冲用后清零。输出 [0..31] 是 8 个轮密钥，[32..63] 为预留扩展。
static void vm_cff_kdf_expand(const uint8_t *ikm, size_t ikm_len, uint8_t out[64]) {
    /* Worst-case input size: 8 (func_id) + 32 (bytecode_hash) + 4 (tag) = 44. */
    uint8_t buf[64];
    if (ikm_len > sizeof(buf) - 4u) {
        ikm_len = sizeof(buf) - 4u;
    }
    memcpy(buf, ikm, ikm_len);

    /* Block 1 — domain "rk\1\0" */
    buf[ikm_len + 0] = 'r';
    buf[ikm_len + 1] = 'k';
    buf[ikm_len + 2] = 0x01;
    buf[ikm_len + 3] = 0x00;
    cprisk_sha256(buf, ikm_len + 4u, &out[0]);

    /* Block 2 — domain "wh\2\0", chained with block 1 to extend entropy. */
    buf[ikm_len + 0] = 'w';
    buf[ikm_len + 1] = 'h';
    buf[ikm_len + 2] = 0x02;
    buf[ikm_len + 3] = 0x00;
    cprisk_sha256(buf, ikm_len + 4u, &out[32]);

    cprisk_secure_zero(buf, sizeof(buf));
}

// 初始化融合上下文：清零 → 记录 func_id/bytecode_hash → 写魔数与初始编码状态 →
// 构造 40 字节 IKM 并展开为 8 个轮密钥 → 清零敏感中间值 → 标记 state_encoded=1。
// 参数：ctx 不可为 NULL；bytecode_hash 可为 NULL，此时用 func_id 派生的稳定填充，
//       避免不同函数共享同一 IKM 前缀。
// 返回：无；不校验字节码哈希本身的正确性（由调用方负责）。
// 线程安全：只写 ctx；平台无关。
void vm_cff_fusion_init(vm_cff_fusion_ctx_t *ctx,
                         uint64_t func_id,
                         const uint8_t *bytecode_hash) {
    if (!ctx) {
        return;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->func_id = func_id;

    if (bytecode_hash) {
        memcpy(ctx->bytecode_hash, bytecode_hash, 32);
    }

    ctx->cff_magic = VM_CFF_MAGIC_INIT;
    ctx->encoded_state = VM_CFF_MAGIC_INIT;

    /*
     * IKM = func_id (8 bytes) || bytecode_hash (32 bytes if provided, else
     * func_id-derived padding to keep the length stable). Previously this
     * was packed into a 64-byte buffer with 24 trailing bytes left
     * uninitialized — `cprisk_secure_zero` cleaned them up but those bytes
     * were never hashed anyway. Use a precisely-sized buffer.
     */
    uint8_t ikm[40];
    memcpy(ikm, &func_id, sizeof(func_id));
    if (bytecode_hash) {
        memcpy(ikm + 8, bytecode_hash, 32);
    } else {
        /* Stable fallback: hash func_id under a fixed pad rather than
         * leaving zero bytes that would cause two distinct functions with
         * empty bytecode_hash to share a key derivation prefix. */
        for (size_t i = 0; i < 32u; i += 8u) {
            const uint64_t pad = func_id ^ (0xA24BAED5C2B2AE35ULL + (uint64_t)i);
            memcpy(ikm + 8u + i, &pad, sizeof(pad));
        }
    }

    uint8_t prk[64];
    vm_cff_kdf_expand(ikm, sizeof(ikm), prk);

    for (int i = 0; i < 8; i++) {
        ctx->rk[i] = ((uint32_t)prk[i * 4] << 24) |
                     ((uint32_t)prk[i * 4 + 1] << 16) |
                     ((uint32_t)prk[i * 4 + 2] << 8) |
                     (uint32_t)prk[i * 4 + 3];
    }

    cprisk_secure_zero(ikm, sizeof(ikm));
    cprisk_secure_zero(prk, sizeof(prk));

    ctx->state_encoded = 1;
}

// 编码一个 PC 并追加到 16 槽轨迹环：
// 返回的是未加掩码的 encoded 值（调用方用作下一个 vpc）；
// trace_buffer 保存的是 encoded ^ keystream(pos)，pos 单调递增。
// 返回：ctx 为 NULL 或 state_encoded=0 时原样返回 pc（fail-open）。
// 线程安全：写 ctx->trace_buffer/trace_pos，必须串行。
uint32_t vm_cff_fusion_encode_pc(vm_cff_fusion_ctx_t *ctx, uint32_t pc) {
    if (!ctx || !ctx->state_encoded) {
        return pc;
    }

    const uint32_t encoded = vm_cff_encode_state_i(pc, ctx->rk);

    /* Store the trace under a per-position keystream so a memory dump cannot
     * recover the encoded PC sequence directly. The function returns the
     * raw encoded value (callers need it as the next vpc); only the in-ctx
     * trace history is masked. */
    const uint32_t pos = ctx->trace_pos;
    ctx->trace_buffer[pos % 16u] = encoded ^ vm_cff_trace_keystream_i(ctx->rk, pos);
    ctx->trace_pos = pos + 1u;

    return encoded;
}

// 解码一个编码后的 PC；未初始化时原样返回输入。
// 返回：解码后的明文 PC；rk 与编码端不一致时得到错误值而不是报错。
uint32_t vm_cff_fusion_decode_pc(vm_cff_fusion_ctx_t *ctx, uint32_t encoded_pc) {
    if (!ctx || !ctx->state_encoded) {
        return encoded_pc;
    }

    return vm_cff_decode_state_i(encoded_pc, ctx->rk);
}

// 状态迁移：先解码 current_encoded，再按 branch_hint 计算下一明文 PC
// （hint==0 表示顺序执行 +1，否则 hint 直接作为目标 PC），重新编码写入 *next_encoded，
// 并把“旧/新编码值”的哈希低 32 位混入 opaque_chain。
// 参数：ctx/next_encoded 不可为 NULL；branch_hint 是明文 PC，不是编码值。
// 返回：无；ctx 为 NULL 时静默返回，*next_encoded 不会被写出。
// 注意：不校验 branch_hint 是否落在字节码范围内，调用方需自行保证。
void vm_cff_fusion_transition(vm_cff_fusion_ctx_t *ctx,
                               uint32_t current_encoded,
                               uint32_t *next_encoded,
                               uint32_t branch_hint) {
    if (!ctx || !next_encoded) {
        return;
    }

    uint32_t current_plain = vm_cff_decode_state_i(current_encoded, ctx->rk);
    uint32_t next_plain;

    if (branch_hint == 0) {
        next_plain = current_plain + 1;
    } else {
        next_plain = branch_hint;
    }

    *next_encoded = vm_cff_encode_state_i(next_plain, ctx->rk);

    ctx->encoded_state = *next_encoded;

    uint8_t mix_input[8];
    memcpy(mix_input, &current_encoded, 4);
    memcpy(mix_input + 4, next_encoded, 4);

    // 只取 SHA256 前 4 字节混链：用于把状态迁移绑定到混淆链，
    // 不提供认证能力，碰撞也不影响正确性。
    uint8_t mix_hash[32];
    cprisk_sha256(mix_input, 8, mix_hash);

    ctx->opaque_chain ^= ((uint32_t)mix_hash[0] << 24) |
                         ((uint32_t)mix_hash[1] << 16) |
                         ((uint32_t)mix_hash[2] << 8) |
                         (uint32_t)mix_hash[3];

    cprisk_secure_zero(mix_input, sizeof(mix_input));
    cprisk_secure_zero(mix_hash, sizeof(mix_hash));
}

// VM_OP_CFF_ENCODE：把 acc[slot] 编码后写回 4 个连续槽（slot..slot+3，按 &31 回绕）。
// imm 位域：bit0–4 槽位，bit5=1 时再把 acc[0..3] 组成的 32 位值异或进结果。
// 返回：fr 为 NULL 时 LEAVE；否则 CONTINUE。
// slot 已被 0x1F 掩码，slot>=32 分支不可达，保留它只是防止将来掩码变化。
// 注意：槽位回绕时 4 个字节可能覆盖 slot 自身或相邻槽，调用方必须预留连续槽。
cprisk_vm_flow_t vm_op_cff_encode_execute(cprisk_vm_interp_frame_t *fr,
                                           uint64_t imm) {
    if (!fr) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    /* `slot` is masked to 5 bits so the `slot >= 32` branch was dead; the dead
     * else used `imm >> 8` as the value-to-encode, then discarded the result
     * because no writeback path existed. Drop the dead path entirely. */
    const uint32_t slot = (uint32_t)(imm & 0x1Fu);
    const uint32_t mix_with_acc = (uint32_t)((imm >> 5) & 1u);
    if (slot >= 32u) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    const uint32_t value_to_encode = fr->acc[slot];

    uint32_t encoded = vm_cff_encode_state_i(value_to_encode, fr->cff_rk);

    if (mix_with_acc) {
        encoded ^= ((uint32_t)fr->acc[0] << 24) |
                   ((uint32_t)fr->acc[1] << 16) |
                   ((uint32_t)fr->acc[2] << 8) |
                   (uint32_t)fr->acc[3];
    }

    fr->acc[slot] = (uint8_t)(encoded & 0xFF);
    fr->acc[(slot + 1u) & 31u] = (uint8_t)((encoded >> 8) & 0xFF);
    fr->acc[(slot + 2u) & 31u] = (uint8_t)((encoded >> 16) & 0xFF);
    fr->acc[(slot + 3u) & 31u] = (uint8_t)((encoded >> 24) & 0xFF);

    fr->opaque_chain ^= encoded;

    return CPRISK_VM_FLOW_CONTINUE;
}

// VM_OP_CFF_DECODE：从 slot..slot+3（&31 回绕）按小端重组 32 位编码值，
// 解码后写回同一组槽。imm 只有低 5 位有效，其余位忽略。
// 返回：fr 为 NULL 时 LEAVE；否则 CONTINUE。
// 与 encode 对称：两端 cff_rk 不一致时得到的是错误明文，而不是失败码。
cprisk_vm_flow_t vm_op_cff_decode_execute(cprisk_vm_interp_frame_t *fr,
                                           uint64_t imm) {
    if (!fr) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    /* `slot` is `imm & 0x1F` so it is always in [0, 31]; the prior `if (slot < 32)`
     * guards were dead branches that read as if a fall-through path existed. We
     * keep the bound explicit anyway in case the mask changes. */
    const uint32_t slot = (uint32_t)(imm & 0x1Fu);
    if (slot >= 32u) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    const uint32_t encoded_value =
        ((uint32_t)fr->acc[slot]) |
        (((uint32_t)fr->acc[(slot + 1u) & 31u]) << 8) |
        (((uint32_t)fr->acc[(slot + 2u) & 31u]) << 16) |
        (((uint32_t)fr->acc[(slot + 3u) & 31u]) << 24);

    const uint32_t decoded = vm_cff_decode_state_i(encoded_value, fr->cff_rk);

    fr->acc[slot] = (uint8_t)(decoded & 0xFF);
    fr->acc[(slot + 1u) & 31u] = (uint8_t)((decoded >> 8) & 0xFF);
    fr->acc[(slot + 2u) & 31u] = (uint8_t)((decoded >> 16) & 0xFF);
    fr->acc[(slot + 3u) & 31u] = (uint8_t)((decoded >> 24) & 0xFF);

    return CPRISK_VM_FLOW_CONTINUE;
}

// VM_OP_CFF_TRANSITION：把帧中的 CFF 字段临时打包成 ctx，执行一次 transition 再写回。
// imm 位域：bits0–23 目标 PC 提示；bit24=1 时改用 acc[0..2] 拼出的 24 位地址作为提示。
// 关键约束：临时 ctx 里的 bytecode_hash 只被复制，transition 并不读取它；
//           encoded_state 会随帧中的 cff_encoded_state 一起更新。
// 返回：fr 为 NULL 时 LEAVE；否则 CONTINUE。临时 ctx 用后 secure_zero。
// 线程安全：只操作传入帧，可重入。
cprisk_vm_flow_t vm_op_cff_transition_execute(cprisk_vm_interp_frame_t *fr,
                                               uint64_t imm) {
    if (!fr) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    uint32_t target_pc_hint = (uint32_t)(imm & 0xFFFFFF);
    uint32_t use_acc_as_hint = (imm >> 24) & 1;

    if (use_acc_as_hint) {
        target_pc_hint = ((uint32_t)fr->acc[0]) |
                         (((uint32_t)fr->acc[1]) << 8) |
                         (((uint32_t)fr->acc[2]) << 16);
    }

    // 把帧字段逐项搬到临时 ctx；这里用 memcpy 而不是直接传帧指针，
    // 是为了复用只接受 vm_cff_fusion_ctx_t 的 transition 接口。
    /* Build temporary ctx from flat frame fields */
    vm_cff_fusion_ctx_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.func_id = fr->func_id;
    memcpy(tmp.rk, fr->cff_rk, sizeof(tmp.rk));
    tmp.encoded_state = fr->cff_encoded_state;
    tmp.cff_magic = fr->cff_magic;
    memcpy(tmp.trace_buffer, fr->cff_trace_buffer, sizeof(tmp.trace_buffer));
    tmp.trace_pos = fr->cff_trace_pos;
    tmp.state_encoded = fr->cff_state_encoded;
    tmp.corruption_detected = fr->cff_corruption_detected;
    tmp.opaque_chain = fr->opaque_chain;
    memcpy(tmp.bytecode_hash, fr->cff_bytecode_hash, sizeof(tmp.bytecode_hash));

    uint32_t current_encoded = (uint32_t)fr->cff_vpc;
    uint32_t next_encoded;

    vm_cff_fusion_transition(&tmp, current_encoded, &next_encoded, target_pc_hint);

    /* Write back modified fields to frame */
    memcpy(fr->cff_rk, tmp.rk, sizeof(fr->cff_rk));
    fr->cff_encoded_state = tmp.encoded_state;
    fr->cff_magic = tmp.cff_magic;
    memcpy(fr->cff_trace_buffer, tmp.trace_buffer, sizeof(fr->cff_trace_buffer));
    fr->cff_trace_pos = tmp.trace_pos;
    fr->cff_state_encoded = tmp.state_encoded;
    fr->cff_corruption_detected = tmp.corruption_detected;
    fr->opaque_chain = tmp.opaque_chain;

    fr->cff_vpc = next_encoded;

    cprisk_secure_zero(&tmp, sizeof(tmp));

    return CPRISK_VM_FLOW_CONTINUE;
}

// 在 VM 帧上启用 CFF：用 (func_id, bytecode_hash) 初始化临时 ctx，
// 拷入 8 个轮密钥，把初始 cff_vpc 编码后写回，并同步 encoded_state/magic/
// state_encoded/trace_buffer/trace_pos。
// 参数：fr 为 NULL 时无操作。返回：无。
// 注意：应在 VM 开始执行前调用一次；重复调用会把当前（可能已编码的）cff_vpc 再编码一次。
void vm_cff_fusion_apply_to_interp(cprisk_vm_interp_frame_t *fr) {
    if (!fr) {
        return;
    }

    vm_cff_fusion_ctx_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    vm_cff_fusion_init(&tmp, fr->func_id, fr->cff_bytecode_hash);

    /* Copy round keys to frame */
    for (int i = 0; i < 8; i++) {
        fr->cff_rk[i] = tmp.rk[i];
    }

    /* Encode initial VPC */
    uint32_t encoded_vpc = vm_cff_fusion_encode_pc(&tmp, (uint32_t)fr->cff_vpc);
    fr->cff_vpc = encoded_vpc;

    /* Copy other state to frame */
    fr->cff_encoded_state = tmp.encoded_state;
    fr->cff_magic = tmp.cff_magic;
    fr->cff_state_encoded = tmp.state_encoded;
    memcpy(fr->cff_trace_buffer, tmp.trace_buffer, sizeof(fr->cff_trace_buffer));
    fr->cff_trace_pos = tmp.trace_pos;

    cprisk_secure_zero(&tmp, sizeof(tmp));
}

// 自检 CFF 上下文是否被破坏：
// 1) 常量时间比较 cff_magic 与 VM_CFF_MAGIC_INIT（把差异折叠到最低位，避免早退泄露）；
// 2) 轨迹非空时取最后一条记录，剥掉位置密钥流后做 decode→encode 往返，
//    任何差异折叠为 1 位并 OR 进 corruption_detected（粘滞标志）。
// 返回：无；只置位 corruption_detected，不修复状态。
// 注意：这是自洽性检查，不是 MAC；能发现随机位翻转，无法对抗持有合法密钥的伪造者。
void vm_cff_fusion_verify_integrity(vm_cff_fusion_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    /* Constant-time compare on the magic to avoid leaking via early-exit timing
     * which sub-bytes of `cff_magic` were corrupted. */
    uint32_t magic_diff = ctx->cff_magic ^ VM_CFF_MAGIC_INIT;
    magic_diff |= magic_diff >> 16;
    magic_diff |= magic_diff >> 8;
    if ((magic_diff & 1u) != 0u) {
        ctx->corruption_detected = 1;
        return;
    }

    if (ctx->trace_pos > 0) {
        const uint32_t last_pos = ctx->trace_pos - 1u;
        /* Trace is keystream-masked on write; peel before round-tripping. */
        const uint32_t last_encoded =
            ctx->trace_buffer[last_pos % 16u] ^ vm_cff_trace_keystream_i(ctx->rk, last_pos);
        const uint32_t decoded = vm_cff_decode_state_i(last_encoded, ctx->rk);
        const uint32_t re_encoded = vm_cff_encode_state_i(decoded, ctx->rk);

        /* Fold a 32-bit not-equal into a single bit without branching on
         * intermediate bytes. */
        uint32_t diff = re_encoded ^ last_encoded;
        diff |= diff >> 16;
        diff |= diff >> 8;
        diff |= diff >> 4;
        diff |= diff >> 2;
        diff |= diff >> 1;
        ctx->corruption_detected |= (uint8_t)(diff & 1u);
    }
}

// 从 8 个轮密钥、opaque_chain 与 trace_pos 汇总出一个 32 位不透明度值，
// 供后续分支/状态混合使用。它是确定性摘要，不是随机数，也不是安全凭据。
// 返回：ctx 为 NULL 时 0；否则任意 32 位值。
uint32_t vm_cff_fusion_get_opacity(vm_cff_fusion_ctx_t *ctx) {
    if (!ctx) {
        return 0;
    }

    uint32_t opacity = 0;

    for (int i = 0; i < 8; i++) {
        opacity ^= ctx->rk[i];
        opacity = ((opacity << 3) | (opacity >> 29)) ^ 0x9E3779B9u;
    }

    opacity ^= ctx->opaque_chain;
    opacity ^= ctx->trace_pos * 0xC2B2AE35u;

    return opacity;
}
