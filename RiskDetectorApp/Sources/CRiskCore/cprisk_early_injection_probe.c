/*
 * Earliest feasible dyld-injection environment probes (constructor priority 1).
 * Poison is deferred to cprisk_init_protection via cprisk_apply_deferred_early_injection_policy()
 * so App Store safe / relaxed QA modes skip silent fail-closed poisoning.
 */

// 文件职责：在 constructor 优先级 1 尽量早地读取 dyld 注入相关环境变量，
// 只记录位掩码，不在此时投毒/退出。
// 延迟决策的原因：DYLD_* 在开发、调试、自动化测试中可能合法存在，
// 由 cprisk_init_protection 结合运行模式（App Store / QA）决定是否 fail-closed。
// 线程模型：构造期单线程写入，之后只读；掩码用原子位或，读取用 relaxed。
// 平台限制：仅 arm64 Apple 真机（排除模拟器/tvOS/watchOS）；其余返回 0。

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)

#include <TargetConditionals.h>

#if (defined(__arm64__) || defined(__aarch64__)) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR) && \
    (!defined(TARGET_OS_TV) || !TARGET_OS_TV) && (!defined(TARGET_OS_WATCH) || !TARGET_OS_WATCH)

// 早发现的环境注入位图；构造期写入，之后只读，故只需 relaxed 原子。
static atomic_uint_fast32_t s_early_inject_mask;

// 每个位对应一个环境变量“存在且非空”；位只增不减（构造期一次性快照）。
enum {
    CPRISK_EARLY_INJ_DYLD_INSERT_LIBRARIES = 1u << 0,
    CPRISK_EARLY_INJ_DYLD_INSERT_FRAMEWORKS = 1u << 1,
    CPRISK_EARLY_INJ_DYLD_LIBRARY_PATH = 1u << 2,
    CPRISK_EARLY_INJ_DYLD_FORCE_FLAT_NAMESPACE = 1u << 3,
};

// constructor(1)：在绝大多数其他构造函数之前运行，尽量在注入库有机会清理环境前取样。
// 只调用 getenv 并置位，不分配内存、不加载库、不写日志。
__attribute__((constructor(1)))
static void cprisk_early_injection_env_ctor_i(void) {
    const char *ins = getenv("DYLD_INSERT_LIBRARIES");
    if (ins && ins[0] != '\0') {
        atomic_fetch_or(&s_early_inject_mask, CPRISK_EARLY_INJ_DYLD_INSERT_LIBRARIES);
    }
    const char *fw = getenv("DYLD_INSERT_FRAMEWORKS");
    if (fw && fw[0] != '\0') {
        atomic_fetch_or(&s_early_inject_mask, CPRISK_EARLY_INJ_DYLD_INSERT_FRAMEWORKS);
    }
    const char *lp = getenv("DYLD_LIBRARY_PATH");
    if (lp && lp[0] != '\0') {
        atomic_fetch_or(&s_early_inject_mask, CPRISK_EARLY_INJ_DYLD_LIBRARY_PATH);
    }
    const char *ff = getenv("DYLD_FORCE_FLAT_NAMESPACE");
    if (ff && ff[0] != '\0') {
        atomic_fetch_or(&s_early_inject_mask, CPRISK_EARLY_INJ_DYLD_FORCE_FLAT_NAMESPACE);
    }
}

// 返回构造期采集的注入环境位图；0 表示未观察到（或平台不适用），不是“已验证干净”。
uint32_t cprisk_get_early_injection_env_mask(void) {
    return (uint32_t)atomic_load_explicit(&s_early_inject_mask, memory_order_relaxed);
}

#else /* Simulator / non-arm64 Apple */

// 模拟器与非 arm64 Apple：没有可比对的 dyld 注入语义，恒返回 0。
uint32_t cprisk_get_early_injection_env_mask(void) {
    return 0u;
}

#endif

#else /* !__APPLE__ */

// 非 Apple 平台不支持 dyld 注入探针，恒返回 0（不支持，不代表干净）。
uint32_t cprisk_get_early_injection_env_mask(void) {
    return 0u;
}

#endif
