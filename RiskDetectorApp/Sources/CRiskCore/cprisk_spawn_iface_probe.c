/*
 * Multi-path resolution checks for the libc process-start helper entry points.
 * Compares RTLD_DEFAULT, explicit libsystem_c handle, and export-trie resolution
 * (bypasses lazy binding / interposed PLT in a different way than dlsym default).
 */

// 文件职责：对 posix_spawn/posix_spawnp 做三路地址一致性检查，发现 RTLD/PLT 层被
// 插入跳板或符号被替换的迹象（子进程启动路径是高价值劫持点）。
// 三路：RTLD_DEFAULT 的 dlsym、显式 dlopen(libsystem_c) 后的 dlsym、导出 trie 直查。
// 失败语义：本函数只采集地址与置位 flags，不做判决、不投毒；参数非法返回 -1。
// 误报抑制：任一路解析为 NULL 时不参与比较（避免句柄缺失被误判成不一致）。
// 采样开销：2 次 dlopen（可缓存）+ 6 次 dlsym + 2 次导出 trie 遍历，适合低频调用。

#include "include/CRiskCore.h"
#include "include/cprisk_dlsym.h"

#include <dlfcn.h>
#include <stdint.h>
#include <string.h>

// 兼容性兜底：部分旧 SDK 头未导出这两个常量。
// RTLD_DEFAULT 的 -2 与 dyld 约定一致；RTLD_NOLOAD 为 0x20，只取已加载句柄。
#ifndef RTLD_DEFAULT
#define RTLD_DEFAULT ((void *)(intptr_t)-2)
#endif
#ifndef RTLD_NOLOAD
#define RTLD_NOLOAD 0x20
#endif

// 不一致标志位：每对“解析路径 A vs 路径 B”单独一位，便于上层定位劫持发生在哪一层。
// bit0..2 对应 posix_spawn，bit3..5 对应 posix_spawnp。
enum {
    CPRISK_SPAWN_IFACE_F_DEFAULT_EXPLICIT_SPAWN = 1u << 0,
    CPRISK_SPAWN_IFACE_F_DEFAULT_TRIE_SPAWN = 1u << 1,
    CPRISK_SPAWN_IFACE_F_EXPLICIT_TRIE_SPAWN = 1u << 2,
    CPRISK_SPAWN_IFACE_F_DEFAULT_EXPLICIT_SPAWNP = 1u << 3,
    CPRISK_SPAWN_IFACE_F_DEFAULT_TRIE_SPAWNP = 1u << 4,
    CPRISK_SPAWN_IFACE_F_EXPLICIT_TRIE_SPAWNP = 1u << 5,
};

// 指针转整数：地址 0 统一表示“该路径未解析出符号”，与 NULL 语义一致。
static uint64_t ptr_to_u64(const void *p) {
    return (uint64_t)(uintptr_t)(void *)p;
}

// 仅当两路都解析成功且地址不同才置位；任一路为 0 说明该路径不可用，
// 此时不下结论，避免把“缺少 libc 句柄”误报成劫持。
static void note_mismatch(
    uint64_t a,
    uint64_t b,
    uint32_t *flags,
    uint32_t bit
) {
    if (a != 0 && b != 0 && a != b) {
        *flags |= bit;
    }
}

// 对同一族的 spawn/spawnp 各取三路地址并两两比较，结果写入调用方提供的 6 个输出。
// RTLD_DEFAULT 可能被 interpose；显式 dlopen 固定到 libsystem_c；cprisk_dlsym
// 直接走 Mach-O 导出 trie，绕过懒绑定与 PLT，因此三者不一致是强信号。
static void probe_one_family(
    const char *sym_spawn,
    const char *sym_spawnp,
    uint64_t *out_def_sp,
    uint64_t *out_exp_sp,
    uint64_t *out_trie_sp,
    uint64_t *out_def_pp,
    uint64_t *out_exp_pp,
    uint64_t *out_trie_pp,
    uint32_t *flags
) {
    void *def_sp = dlsym(RTLD_DEFAULT, sym_spawn);
    void *def_pp = dlsym(RTLD_DEFAULT, sym_spawnp);
    *out_def_sp = ptr_to_u64(def_sp);
    *out_def_pp = ptr_to_u64(def_pp);

    // 优先 RTLD_NOLOAD：只取已加载句柄，不产生加载副作用；未加载时才真正打开。
    void *libc = dlopen("/usr/lib/system/libsystem_c.dylib", RTLD_NOW | RTLD_NOLOAD);
    if (!libc) {
        libc = dlopen("/usr/lib/system/libsystem_c.dylib", RTLD_NOW);
    }
    void *exp_sp = libc ? dlsym(libc, sym_spawn) : NULL;
    void *exp_pp = libc ? dlsym(libc, sym_spawnp) : NULL;
    *out_exp_sp = ptr_to_u64(exp_sp);
    *out_exp_pp = ptr_to_u64(exp_pp);

    void *trie_sp = cprisk_dlsym("libsystem_c.dylib", sym_spawn);
    void *trie_pp = cprisk_dlsym("libsystem_c.dylib", sym_spawnp);
    *out_trie_sp = ptr_to_u64(trie_sp);
    *out_trie_pp = ptr_to_u64(trie_pp);

    note_mismatch(*out_def_sp, *out_exp_sp, flags, CPRISK_SPAWN_IFACE_F_DEFAULT_EXPLICIT_SPAWN);
    note_mismatch(*out_def_sp, *out_trie_sp, flags, CPRISK_SPAWN_IFACE_F_DEFAULT_TRIE_SPAWN);
    note_mismatch(*out_exp_sp, *out_trie_sp, flags, CPRISK_SPAWN_IFACE_F_EXPLICIT_TRIE_SPAWN);

    note_mismatch(*out_def_pp, *out_exp_pp, flags, CPRISK_SPAWN_IFACE_F_DEFAULT_EXPLICIT_SPAWNP);
    note_mismatch(*out_def_pp, *out_trie_pp, flags, CPRISK_SPAWN_IFACE_F_DEFAULT_TRIE_SPAWNP);
    note_mismatch(*out_exp_pp, *out_trie_pp, flags, CPRISK_SPAWN_IFACE_F_EXPLICIT_TRIE_SPAWNP);
}

// 填充 spawn 接口探针结果：先整体清零（所有地址 0、flags 0），再采集一族函数。
// 返回 -1 仅表示 out 为 NULL；否则恒返回 0，结论由 out->flags 表达。
// 调用方应把非零 flags 当作“解析不一致”的线索，并结合运行模式决定处置。
int cprisk_spawn_iface_probe(cprisk_spawn_iface_probe_result_t *out) {
    if (!out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));

    probe_one_family(
        "posix_spawn",
        "posix_spawnp",
        &out->addr_rtld_default_spawn,
        &out->addr_dlopen_libc_spawn,
        &out->addr_export_trie_spawn,
        &out->addr_rtld_default_spawnp,
        &out->addr_dlopen_libc_spawnp,
        &out->addr_export_trie_spawnp,
        &out->flags
    );

    return 0;
}
