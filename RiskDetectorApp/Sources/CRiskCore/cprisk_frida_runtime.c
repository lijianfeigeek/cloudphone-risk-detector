/*
 * cprisk_frida_runtime.c — Multi-channel Frida / Gum runtime hints (iOS arm64).
 *
 * Sensitive needles are not stored as contiguous ASCII literals; short tokens are
 * reconstructed with SHA256(label) XOR masks (v1). Plaintext exists only briefly
 * on the stack and is cleared after each scan.
 */

// 文件职责：一次性采集 Frida/Gum 的四类运行时线索，填充 cprisk_frida_runtime_snapshot_t。
// 字段来源：image_hit_count = 加载镜像路径关键字命中数；dlsym_hit_count = 已知 Gum
//   导出符号存在数；proc_hit_count = 进程表 p_comm 命中数；behavior_* = 入口序言/
//   跳板前缀/外来可执行地址/信任面 hook 四类行为检查；flags 为各通道“是否命中”的位或。
// 失败语义：所有通道都是线索（fail-open），0 不代表绝对干净；模拟器 supported=0，
//   其余字段全 0，且函数仍返回 0（“采集完成”而非“未发现”）。
// 采样开销：每轮枚举全部镜像/进程并做多次 dlsym 与序言比对，适合低频快照，不可高频调用。
// 线程模型：只读扫描；序言基线由被调模块的原子状态保护，可并发调用。

#include "include/CRiskCore.h"

// 若公共头未声明快照结构，则在此提供 ABI 兼容定义（布局必须与头文件一致）。
// flags 的每一位对应一条已命中的通道；BEHAVIOR 位由四个 behavior 子位聚合而来。
#ifndef CPRISK_FRIDA_RUNTIME_SNAPSHOT_DECLARED
enum {
    CPRISK_FRIDA_RT_IMAGE = 1u << 0,
    CPRISK_FRIDA_RT_DLSYM = 1u << 1,
    CPRISK_FRIDA_RT_PROC = 1u << 2,
    CPRISK_FRIDA_RT_BEHAVIOR = 1u << 3,
};
// 行为层子标志：入口序言与基线不符、跳板前缀命中、关键函数地址不在任何镜像的
// 可执行段内、Security/trust 相关入口被改写。每位置位者都是对应的校验函数。
enum {
    CPRISK_FRIDA_RT_BEHAVIOR_PROLOGUE = 1u << 0,
    CPRISK_FRIDA_RT_BEHAVIOR_TRAMPOLINE = 1u << 1,
    CPRISK_FRIDA_RT_BEHAVIOR_FOREIGN_EXEC = 1u << 2,
    CPRISK_FRIDA_RT_BEHAVIOR_TRUST_SURFACE = 1u << 3,
};
// 字段来源（按采集顺序）：
//   supported = 是否为可执行真实扫描的平台（Apple 真机 1，模拟器/其他 0）；
//   flags = IMAGE/DLSYM/PROC/BEHAVIOR 四个通道命中位的并集；
//   image_hit_count = 路径含关键字的镜像数；dlsym_hit_count = 命中的已知 Gum 符号数；
//   proc_hit_count = 进程名命中数；behavior_flags = BEHAVIOR_* 子位；
//   behavior_hit_count = 行为层命中总权重（序言/外来执行各 1，跳板与 trust 面按命中数累加）。
// 不变量：flags 非 0 当且仅当至少一个 hit_count > 0 或 behavior_flags 非 0。
typedef struct cprisk_frida_runtime_snapshot {
    uint32_t supported;
    uint32_t flags;
    uint32_t image_hit_count;
    uint32_t dlsym_hit_count;
    uint32_t proc_hit_count;
    uint32_t behavior_flags;
    uint32_t behavior_hit_count;
} cprisk_frida_runtime_snapshot_t;
#endif

#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

#include <stdint.h>
#include <strings.h>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach/vm_prot.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/proc.h>
#endif

// v1 标签解码：mask = SHA256(label)，密文按 32 字节循环异或，输出 NUL 结尾明文。
// 要求 out_sz > enc_len（至少留 1 字节给 NUL），否则返回 -1 且不写 out。
// 明文只存在于调用方提供的缓冲中，调用方负责用后清零。
int cprisk_obf_decode_sha256_label(
    const char *label,
    size_t label_len,
    const uint8_t *enc,
    size_t enc_len,
    char *out,
    size_t out_sz
) {
    if (!label || label_len == 0 || !enc || enc_len == 0 || !out || out_sz <= enc_len) {
        return -1;
    }
    uint8_t mask[32];
    cprisk_sha256((const uint8_t *)label, label_len, mask);
    for (size_t i = 0; i < enc_len; i++) {
        out[i] = (char)(enc[i] ^ mask[i % 32u]);
    }
    out[enc_len] = '\0';
    return 0;
}

// v1 标签解码（带域）：mask = SHA256(le32(domain) || le32(key_id))，
// 同一域内不同 key_id 得到不同掩码；tag 的字节序是二进制契约，不可改。
// 参数/返回语义与 label 版本一致：容量不足或空密文返回 -1。
int cprisk_obf_decode_sha256_tag(
    uint32_t domain,
    uint32_t key_id,
    const uint8_t *enc,
    size_t enc_len,
    char *out,
    size_t out_sz
) {
    if (!enc || enc_len == 0 || !out || out_sz <= enc_len) {
        return -1;
    }
    uint8_t tag[8];
    tag[0] = (uint8_t)(domain & 0xffu);
    tag[1] = (uint8_t)((domain >> 8) & 0xffu);
    tag[2] = (uint8_t)((domain >> 16) & 0xffu);
    tag[3] = (uint8_t)((domain >> 24) & 0xffu);
    tag[4] = (uint8_t)(key_id & 0xffu);
    tag[5] = (uint8_t)((key_id >> 8) & 0xffu);
    tag[6] = (uint8_t)((key_id >> 16) & 0xffu);
    tag[7] = (uint8_t)((key_id >> 24) & 0xffu);
    uint8_t mask[32];
    cprisk_sha256(tag, sizeof(tag), mask);
    for (size_t i = 0; i < enc_len; i++) {
        out[i] = (char)(enc[i] ^ mask[i % 32u]);
    }
    out[enc_len] = '\0';
    return 0;
}

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)

// 单条关键字匹配：解码到 96 字节栈缓冲后做子串查找，随即清零。
// 缓冲不足或解码失败返回 0（该关键字本轮不可用），不抛出错误。
static int cprisk_frida_path_needle_hit_i(
    const char *path,
    uint32_t domain,
    uint32_t key_id,
    const uint8_t *enc,
    size_t enc_len
) {
    char buf[96];
    if (enc_len + 1u > sizeof(buf)) {
        return 0;
    }
    if (cprisk_obf_decode_sha256_tag(domain, key_id, enc, enc_len, buf, sizeof(buf)) != 0) {
        return 0;
    }
    const int hit = (strstr(path, buf) != NULL) ? 1 : 0;
    cprisk_secure_zero(buf, sizeof(buf));
    return hit;
}

// 路径关键字总表：7 条大小写敏感子串 + 1 条大小写不敏感（GumJS 常见小写写法）。
// 密文与 key_id 一一对应且已固化在二进制中，新增条目只能追加新的 key_id。
// 返回 1 = 任一关键字命中；0 = 未命中或 path 为空。
static int cprisk_token_in_path(const char *path) {
    if (!path || path[0] == '\0') {
        return 0;
    }
    const uint32_t D = CPRISK_OBF_TAG_DOMAIN_FRIDA_RT;
    static const uint8_t e_frida[] = {0xad, 0x0c, 0x6f, 0xa8, 0x2c};
    static const uint8_t e_frida_cap[] = {0x04, 0x5e, 0x3c, 0x4f, 0xf8};
    static const uint8_t e_gum_js[] = {0xfa, 0x53, 0x66, 0x5a, 0x2e, 0x64};
    static const uint8_t e_agent[] = {
        0x85, 0x46, 0xc9, 0x61, 0xb0, 0x93, 0xa2, 0xf6, 0xf8, 0x85, 0x08};
    static const uint8_t e_gadget[] = {
        0x2d, 0xf1, 0x1f, 0x72, 0x48, 0x9a, 0xfb, 0x9f, 0xb5, 0x16, 0x4a, 0xcc};
    static const uint8_t e_libgum[] = {0xce, 0x86, 0xa1, 0x7c, 0xd3, 0xac};
    static const uint8_t e_server[] = {
        0xe7, 0x62, 0x5c, 0x95, 0x5e, 0x0f, 0x7f, 0x20, 0x52, 0xef, 0xf3, 0xce};
    static const uint8_t e_gumjs_compact[] = {0x8e, 0xca, 0xa1, 0xd3, 0x71};

    if (cprisk_frida_path_needle_hit_i(path, D, 1u, e_frida, sizeof(e_frida)))
        return 1;
    if (cprisk_frida_path_needle_hit_i(path, D, 2u, e_frida_cap, sizeof(e_frida_cap)))
        return 1;
    if (cprisk_frida_path_needle_hit_i(path, D, 3u, e_gum_js, sizeof(e_gum_js)))
        return 1;
    if (cprisk_frida_path_needle_hit_i(path, D, 4u, e_agent, sizeof(e_agent)))
        return 1;
    if (cprisk_frida_path_needle_hit_i(path, D, 5u, e_gadget, sizeof(e_gadget)))
        return 1;
    if (cprisk_frida_path_needle_hit_i(path, D, 6u, e_libgum, sizeof(e_libgum)))
        return 1;
    if (cprisk_frida_path_needle_hit_i(path, D, 7u, e_server, sizeof(e_server)))
        return 1;

    char gumjs_buf[16];
    if (cprisk_obf_decode_sha256_tag(D, 8u, e_gumjs_compact, sizeof(e_gumjs_compact), gumjs_buf, sizeof(gumjs_buf)) ==
        0) {
        const int gj = (strcasestr(path, gumjs_buf) != NULL) ? 1 : 0;
        cprisk_secure_zero(gumjs_buf, sizeof(gumjs_buf));
        if (gj)
            return 1;
    }
    return 0;
}

// 枚举 dyld 已加载镜像名并计数关键字命中；hits > 0 才置 IMAGE 通道位。
// 命中数（而非布尔）保留给上层做置信度加权；无镜像或路径为空时 hits=0。
static void cprisk_frida_scan_dyld_images(uint32_t *flags_out, uint32_t *image_hits_out) {
    uint32_t hits = 0;
    const uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) {
            continue;
        }
        if (cprisk_token_in_path(name)) {
            hits++;
        }
    }
    if (hits > 0 && flags_out) {
        *flags_out |= CPRISK_FRIDA_RT_IMAGE;
    }
    if (image_hits_out) {
        *image_hits_out = hits;
    }
}

// 通过 dlsym(RTLD_DEFAULT) 探测 5 个 Gum 内部符号是否导出（init/deinit/embed/
// agent main/backend）。符号存在才计数；存在本身是线索，不证明实际启用了注入。
// 注意：这里用 libc dlsym，可能被 hook；因此它只作为四通道之一，不单独定性。
static void cprisk_frida_scan_dlsym(uint32_t *flags_out, uint32_t *dlsym_hits_out) {
    static const uint8_t e_gum_init[] = {0x76, 0x13, 0xf9, 0x65, 0x84, 0x20, 0xb7, 0x32};
    static const uint8_t e_gum_deinit[] = {0x34, 0xd0, 0x1a, 0x54, 0xeb, 0x42, 0xaa, 0xb6, 0xc5, 0xaa};
    static const uint8_t e_gum_embed[] = {
        0xea, 0x26, 0x7b, 0xb3, 0xf1, 0xbc, 0x28, 0xb3, 0x94, 0xc3, 0xc8, 0xa5, 0x26, 0x60, 0x9f, 0x8a};
    static const uint8_t e_agent_main[] = {
        0x7b, 0xdf, 0x48, 0x0b, 0x44, 0x1c, 0x74, 0x68, 0x97, 0x12, 0xaf, 0x94, 0x83, 0x21, 0xfd, 0x09};
    static const uint8_t e_gum_backend[] = {
        0x8e, 0xa1, 0x00, 0xf2, 0x08, 0xe7, 0xab, 0xf4, 0xdd, 0x8f, 0x2d, 0x59, 0xbc, 0x05, 0x72, 0x42,
        0x04, 0x4b, 0x65, 0x8f, 0x31, 0x2b, 0x26, 0xd2, 0x99};

    static const struct {
        uint32_t key_id;
        const uint8_t *enc;
        size_t enc_len;
    } rows[] = {
        {16u, e_gum_init, sizeof(e_gum_init)},
        {17u, e_gum_deinit, sizeof(e_gum_deinit)},
        {18u, e_gum_embed, sizeof(e_gum_embed)},
        {19u, e_agent_main, sizeof(e_agent_main)},
        {20u, e_gum_backend, sizeof(e_gum_backend)},
    };

    uint32_t hits = 0;
    const uint32_t D = CPRISK_OBF_TAG_DOMAIN_FRIDA_RT;
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        char sym[40];
        if (rows[i].enc_len + 1u > sizeof(sym)) {
            continue;
        }
        if (cprisk_obf_decode_sha256_tag(
                D,
                rows[i].key_id,
                rows[i].enc,
                rows[i].enc_len,
                sym,
                sizeof(sym)) != 0) {
            continue;
        }
        void *p = dlsym(RTLD_DEFAULT, sym);
        cprisk_secure_zero(sym, sizeof(sym));
        if (p != NULL) {
            hits++;
        }
    }
    if (hits > 0 && flags_out) {
        *flags_out |= CPRISK_FRIDA_RT_DLSYM;
    }
    if (dlsym_hits_out) {
        *dlsym_hits_out = hits;
    }
}

// 进程名判定：p_comm 只有 16 字节（超长被内核截断），因此先做前缀大小写不敏感
// 比较，再退化为子串查找；关键字同样是运行时解码的混淆串。
// 返回 1 = 疑似；0 = 未命中/空串。
static int cprisk_comm_looks_like_frida(const char *comm) {
    if (!comm || comm[0] == '\0') {
        return 0;
    }
    const uint32_t D = CPRISK_OBF_TAG_DOMAIN_FRIDA_RT;
    static const uint8_t e_frida[] = {0xad, 0x0c, 0x6f, 0xa8, 0x2c};
    static const uint8_t e_gum_js[] = {0xfa, 0x53, 0x66, 0x5a, 0x2e, 0x64};

    char fr[16];
    char gj[16];
    if (cprisk_obf_decode_sha256_tag(D, 1u, e_frida, sizeof(e_frida), fr, sizeof(fr)) != 0) {
        return 0;
    }
    if (cprisk_obf_decode_sha256_tag(D, 3u, e_gum_js, sizeof(e_gum_js), gj, sizeof(gj)) != 0) {
        cprisk_secure_zero(fr, sizeof(fr));
        return 0;
    }

    int hit = 0;
    if (strncasecmp(comm, fr, strlen(fr)) == 0) {
        hit = 1;
    } else if (strcasestr(comm, fr) != NULL) {
        hit = 1;
    } else if (strcasestr(comm, gj) != NULL) {
        hit = 1;
    }
    cprisk_secure_zero(fr, sizeof(fr));
    cprisk_secure_zero(gj, sizeof(gj));
    return hit;
}

// 通过直调 sysctl 读取全进程表（KERN_PROC_ALL），解析 p_comm 并统计命中数。
// 采样开销：一次内核查询 + 一次堆分配（大小与进程数成正比，限制在 32MB 内）；
// sysctl 失败或返回尺寸异常时静默返回（hits 保持 0），不视为“干净”的证据。
static void cprisk_frida_scan_proc_table(uint32_t *flags_out, uint32_t *proc_hits_out) {
    // 先问内核需要多大缓冲，再按需分配；中间进程数变化会导致第二次查询失败，
    // 此时直接放弃本轮（fail-open），下一轮快照自然重试。
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t buf_size = 0;
    int err = 0;
    if (cprisk_sysctl_direct(mib, 4, NULL, &buf_size, NULL, 0, &err) != 0) {
        return;
    }
    if (buf_size < sizeof(struct kinfo_proc) || buf_size > 32u * 1024u * 1024u) {
        return;
    }
    uint8_t *buf = (uint8_t *)malloc(buf_size);
    if (!buf) {
        return;
    }
    size_t len = buf_size;
    if (cprisk_sysctl_direct(mib, 4, buf, &len, NULL, 0, &err) != 0) {
        free(buf);
        return;
    }
    size_t count = len / sizeof(struct kinfo_proc);
    struct kinfo_proc *kp = (struct kinfo_proc *)buf;
    uint32_t hits = 0;
    for (size_t i = 0; i < count; i++) {
        if (cprisk_comm_looks_like_frida(kp[i].kp_proc.p_comm)) {
            hits++;
        }
    }
    free(buf);
    if (hits > 0 && flags_out) {
        *flags_out |= CPRISK_FRIDA_RT_PROC;
    }
    if (proc_hits_out) {
        *proc_hits_out = hits;
    }
}

// 判断地址是否位于“某个已加载镜像的可执行段”内。
// 实现：dladdr 只用来取所属镜像基址，再经 _dyld_* 找到对应 header 与 slide，
// 遍历 LC_SEGMENT_64 检查 initprot & EXECUTE 的段区间。
// 返回 1 = 在镜像可执行段内；0 = 不在/无法解析（dladdr 失败、非 64 位镜像等）。
static int cprisk_frida_addr_in_loaded_image_exec_i(const void *addr) {
    if (!addr) {
        return 0;
    }
    Dl_info info;
    if (dladdr(addr, &info) == 0 || !info.dli_fbase) {
        return 0;
    }

    const struct mach_header_64 *hdr = NULL;
    intptr_t slide = 0;
    const uint32_t image_count = _dyld_image_count();
    for (uint32_t i = 0; i < image_count; i++) {
        if ((const void *)_dyld_get_image_header(i) == info.dli_fbase) {
            hdr = (const struct mach_header_64 *)_dyld_get_image_header(i);
            slide = _dyld_get_image_vmaddr_slide(i);
            break;
        }
    }
    if (!hdr || hdr->magic != MH_MAGIC_64) {
        return 0;
    }

    const uint8_t *cursor = (const uint8_t *)(hdr + 1);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            if ((seg->initprot & VM_PROT_EXECUTE) != 0 && seg->vmsize != 0) {
                const uintptr_t start = (uintptr_t)((intptr_t)seg->vmaddr + slide);
                const uintptr_t end = start + (uintptr_t)seg->vmsize;
                const uintptr_t target = (uintptr_t)addr;
                if (target >= start && target < end) {
                    return 1;
                }
            }
        }
        cursor += lc->cmdsize;
    }
    return 0;
}

// 行为层四项检查；每项独立置位并累加命中权重。
// 约定：被调校验函数返回 1 表示“通过”，返回 0 或负值都按失败处理（fail-closed 判定）。
static void cprisk_frida_scan_behavior_i(
    uint32_t *flags_out,
    uint32_t *behavior_flags_out,
    uint32_t *behavior_hits_out
) {
    uint32_t behavior_flags = 0u;
    uint32_t hits = 0u;

    // objc_msgSend/dyld 入口等序言与基线不符：典型的 Frida Interceptor 改写。
    if (cprisk_verify_runtime_hook_surface_prologues() != 1) {
        behavior_flags |= CPRISK_FRIDA_RT_BEHAVIOR_PROLOGUE;
        hits++;
    }

    // 入口前缀扫描：命中数按权重累加，命中越多置信度越高。
    const int trampoline_hits = cprisk_scan_hook_surface_trampoline_prefixes();
    if (trampoline_hits > 0) {
        behavior_flags |= CPRISK_FRIDA_RT_BEHAVIOR_TRAMPOLINE;
        hits += (uint32_t)trampoline_hits;
    }

    // 外来可执行地址：dlsym/dlopen 是编译器/加载器符号，objc_msgSend 来自 libobjc，
    // 三者都必须落在某个已加载镜像的可执行段；任一落空说明地址被替换到裸映射。
    // objc_msgSend 解析失败时不参与判断，避免旧系统/裁剪环境误报。
    void *objc_msgsend_addr = dlsym(RTLD_DEFAULT, "objc_msgSend");
    if (!cprisk_frida_addr_in_loaded_image_exec_i((const void *)dlsym) ||
        !cprisk_frida_addr_in_loaded_image_exec_i((const void *)dlopen) ||
        (objc_msgsend_addr != NULL && !cprisk_frida_addr_in_loaded_image_exec_i(objc_msgsend_addr))) {
        behavior_flags |= CPRISK_FRIDA_RT_BEHAVIOR_FOREIGN_EXEC;
        hits++;
    }

    // Security.framework 信任评估入口与 dlopen/dlsym 序言被改写：
    // 这是针对证书固定/信任链的高价值 hook 面；mask 非 0 时按置位数累加权重，
    // mask 为 0 但整体失败时至少记 1，保证失败不会被权重 0 掩盖。
    uint32_t trust_mask = 0u;
    if (cprisk_verify_trust_hook_surface_integrity(&trust_mask) != 1) {
        behavior_flags |= CPRISK_FRIDA_RT_BEHAVIOR_TRUST_SURFACE;
        hits += (trust_mask != 0u) ? (uint32_t)__builtin_popcount(trust_mask) : 1u;
    }

    if (behavior_flags != 0u && flags_out) {
        *flags_out |= CPRISK_FRIDA_RT_BEHAVIOR;
    }
    if (behavior_flags_out) {
        *behavior_flags_out = behavior_flags;
    }
    if (behavior_hits_out) {
        *behavior_hits_out = hits;
    }
}

#endif /* Apple device */

// 采集一份完整的 Frida 运行时快照：先清零，再依次跑四条通道并把各 hit_count
// 直接写入 out 对应字段；flags 只在通道命中时由各扫描函数置位。
// 返回 -1 仅表示 out 为 NULL；0 表示“采集完成”（可能一条线索都没有）。
// 模拟器/非 Apple：supported=0，其余字段保持 0，仍返回 0——调用方必须看 supported。
int cprisk_frida_runtime_snapshot(cprisk_frida_runtime_snapshot_t *out) {
    if (!out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    out->supported = 1u;
    uint32_t flags = 0u;
    cprisk_frida_scan_dyld_images(&flags, &out->image_hit_count);
    cprisk_frida_scan_dlsym(&flags, &out->dlsym_hit_count);
    cprisk_frida_scan_proc_table(&flags, &out->proc_hit_count);
    cprisk_frida_scan_behavior_i(&flags, &out->behavior_flags, &out->behavior_hit_count);
    out->flags = flags;
#else
    out->supported = 0u;
#endif
    return 0;
}
