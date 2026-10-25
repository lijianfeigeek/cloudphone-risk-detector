// 文件职责：arm64e 指针认证（PAC/CFI）的签名、认证、自检与回调 schema 校验。
// 关键概念：编译器/系统 ABI 的 C 函数指针使用 discriminator 0 的 standard schema，
//   本模块存储时改用 ptrauth_blend_discriminator 生成的“storage schema”，进出都要转换。
// 失败语义：PAC 认证是 fail-stop，无效非 NULL 指针可能直接 trap，没有“可空的有效性查询”；
//   可用 cprisk_pac_is_arm64e_supported() 与返回值区分“不支持”和“认证通过”。
// 线程模型：无锁；最近一次操作结果以原子覆盖方式写入 s_last_pac_flags，
//   并发调用只保证“读到某一次完整结果”，不保证与调用顺序对应。
// 平台限制：仅 arm64e 且带 ptrauth.h 时真实执行；其他平台为原样返回的降级桩。

#include "include/CRiskCore.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

#if defined(__has_include)
#if __has_include(<ptrauth.h>)
#include <ptrauth.h>
#define CPRISK_HAS_PTRAUTH_HEADER 1
#else
#define CPRISK_HAS_PTRAUTH_HEADER 0
#endif
#else
#define CPRISK_HAS_PTRAUTH_HEADER 0
#endif

// 只有“arm64e 架构 + 工具链提供 ptrauth.h”才认为 PAC 运行时可用。
// 该宏是编译期常量：为 0 时下面所有签名/认证都退化为原样返回，不能当作验证。
#if defined(__arm64e__) && CPRISK_HAS_PTRAUTH_HEADER
#define CPRISK_PAC_RUNTIME_AVAILABLE 1
#else
#define CPRISK_PAC_RUNTIME_AVAILABLE 0
#endif

// 最近一次 PAC/CFI 操作的状态位（CPRISK_PAC_CFI_FLAG_*）。
// 每次调用整体覆盖而非按位累加；原子类型避免并发写入撕裂。
static atomic_uint_fast32_t s_last_pac_flags = CPRISK_PAC_CFI_FLAG_NONE;

// 自检用已知函数：输入输出确定，便于验证“签名→认证→调用”链路是否完好。
static uint64_t cprisk_pac_probe_callback_i(uint64_t seed) {
    return (seed ^ 0x9E3779B97F4A7C15ULL) + 0xA24BAED4963EE407ULL;
}

// 把调用方提供的 discriminator 与本函数地址混合：地址随 ASLR/进程不同，
// 使同一逻辑用途在不同进程/不同调用点得到不同签名，降低跨进程伪造价值。
static inline uintptr_t cprisk_pac_blend_discriminator(uintptr_t discriminator) {
#if CPRISK_PAC_RUNTIME_AVAILABLE
    return ptrauth_blend_discriminator((void *)&cprisk_pac_blend_discriminator, discriminator);
#else
    return discriminator;
#endif
}

// 把标准 ABI 签名的函数指针转签为“本模块 storage schema”。
// NULL 原样返回；非 arm64e 原样返回（不做签名，调用方需自行判断能力）。
// 认证-重签过程对非法输入是 fail-stop，不会返回一个“看起来有效”的指针。
void *cprisk_pac_sign_function_pointer(const void *ptr, uintptr_t discriminator) {
    if (ptr == NULL) {
        return NULL;
    }
#if CPRISK_PAC_RUNTIME_AVAILABLE
    const uintptr_t blended = cprisk_pac_blend_discriminator(discriminator);
    /* Callers pass standard-ABI C function pointers (including dlsym
     * function results), already signed with discriminator zero. Preserve
     * that authentication when converting to our storage schema. */
    return (void *)ptrauth_auth_and_resign(
        ptr,
        ptrauth_key_function_pointer,
        0,
        ptrauth_key_function_pointer,
        blended);
#else
    (void)discriminator;
    return (void *)ptr;
#endif
}

/* Authenticate a pointer signed with our storage schema and convert it
 * back to the standard C function-pointer schema. PAC authentication is
 * fail-stop: an invalid non-NULL pointer may trap; it is not a nullable
 * validity query. Never probe a deliberately wrong discriminator here.
 * See clang.llvm.org/docs/PointerAuthentication.html.
 * NOTE: on non-arm64e builds this returns the pointer unchanged — that is
 * a no-op fallback, NOT a verification. Callers that need real validation
 * must check cprisk_pac_is_arm64e_supported() / the -1 return of
 * cprisk_pac_validate_indirect_call_target() instead of trusting this. */
// 把本模块 storage schema 的指针认证回标准 ABI 签名，供真正调用使用。
// 非 arm64e 上是 no-op 降级，返回值与输入相同——这不是验证结果；
// 需要“是否可信”的结论时，必须调用 cprisk_pac_validate_indirect_call_target()。
// 对已损坏的非 NULL 签名，ptrauth 可能直接 trap（fail-stop），没有可用的非捕获查询。
void *cprisk_pac_auth_function_pointer(const void *ptr, uintptr_t discriminator) {
    if (ptr == NULL) {
        return NULL;
    }
#if CPRISK_PAC_RUNTIME_AVAILABLE
    const uintptr_t blended = cprisk_pac_blend_discriminator(discriminator);
    return (void *)ptrauth_auth_and_resign(
        ptr,
        ptrauth_key_function_pointer,
        blended,
        ptrauth_key_function_pointer,
        0);
#else
    (void)discriminator;
    return (void *)ptr;
#endif
}

// 编译期能力查询：1 = 真实 PAC 路径；0 = 所有签名/认证都是原样返回的桩。
int cprisk_pac_is_arm64e_supported(void) {
#if CPRISK_PAC_RUNTIME_AVAILABLE
    return 1;
#else
    return 0;
#endif
}

/* REAL validation of an externally-provided (already signed) indirect-call
 * target: authenticate the pointer AS GIVEN with the supplied discriminator.
 * This deliberately does NOT sign-then-authenticate: self-sign + self-auth
 * always succeeds and proves nothing about the supplied pointer (that
 * round-trip is a self-test, see cprisk_pac_self_test()).
 * Returns 0 after authentication, -1 for NULL or an unavailable platform.
 * Invalid non-NULL signatures may trap. There is no supported non-trapping
 * PAC validity query, and no negative-authentication probe is performed. */
// 对“外部已签名”的间接调用目标做真实认证（按传入 discriminator 原样认证）。
// 不做 sign-then-auth：自己签自己验恒成功，证明不了输入指针的任何性质。
// 返回 0 = 认证通过；-1 = NULL 或平台无 PAC（并置 AUTH_FAILED）；
// 非 NULL 的伪造签名可能触发 PAC trap，不会走到返回值。
int cprisk_pac_validate_indirect_call_target(const void *func_ptr, uintptr_t discriminator) {
    if (func_ptr == NULL) {
        atomic_store(&s_last_pac_flags, CPRISK_PAC_CFI_FLAG_AUTH_FAILED);
        return -1;
    }

    uint32_t flags = CPRISK_PAC_CFI_FLAG_NONE;
#if !CPRISK_PAC_RUNTIME_AVAILABLE
    /* No PAC hardware/compiler support: authentication is impossible, so
     * this is a failure, not a success. */
    flags |= CPRISK_PAC_CFI_FLAG_UNAVAILABLE | CPRISK_PAC_CFI_FLAG_AUTH_FAILED;
    atomic_store(&s_last_pac_flags, flags);
    return -1;
#else
    /* Keep the authenticated result observable even when the caller only
     * needs validation, so this cannot reduce to a non-NULL input check. */
    void *volatile authed = cprisk_pac_auth_function_pointer(func_ptr, discriminator);
    if (authed == NULL) {
        flags |= CPRISK_PAC_CFI_FLAG_AUTH_FAILED;
        atomic_store(&s_last_pac_flags, flags);
        return -1;
    }
    atomic_store(&s_last_pac_flags, flags);
    return 0;
#endif
}

/* SELF-TEST ONLY (not validation): signs a known-good internal pointer
 * and authenticates it back. A pass here proves the PAC mechanism works;
 * it says nothing about any externally-supplied pointer. */
// 机制自检（不是指针校验）：内部已知函数 → 签名 → 认证 → 实际调用并比对结果。
// 返回 0 = 通过，或平台无 PAC（此时置 UNAVAILABLE，0 不代表“安全”）；
// 返回 1 = 签名/认证/调用结果任一不符，并置 SELFTEST_FAILED。
int cprisk_pac_self_test(uintptr_t discriminator) {
    uint32_t flags = CPRISK_PAC_CFI_FLAG_NONE;
#if !CPRISK_PAC_RUNTIME_AVAILABLE
    flags |= CPRISK_PAC_CFI_FLAG_UNAVAILABLE;
    atomic_store(&s_last_pac_flags, flags);
    return 0;
#else
    typedef uint64_t (*cprisk_pac_probe_fn_t)(uint64_t);
    const cprisk_pac_probe_fn_t fn = cprisk_pac_probe_callback_i;
    const uint64_t sample = 0x13579BDF2468ACE0ULL;
    const uint64_t expected = cprisk_pac_probe_callback_i(sample);

    void *signed_ptr = cprisk_pac_sign_function_pointer((const void *)fn, discriminator);
    if (signed_ptr == NULL) {
        flags |= CPRISK_PAC_CFI_FLAG_SIGN_FAILED | CPRISK_PAC_CFI_FLAG_SELFTEST_FAILED;
        atomic_store(&s_last_pac_flags, flags);
        return 1;
    }

    void *authed_ptr = cprisk_pac_auth_function_pointer(signed_ptr, discriminator);
    if (authed_ptr == NULL) {
        flags |= CPRISK_PAC_CFI_FLAG_AUTH_FAILED | CPRISK_PAC_CFI_FLAG_SELFTEST_FAILED;
        atomic_store(&s_last_pac_flags, flags);
        return 1;
    }

    const cprisk_pac_probe_fn_t authed_fn = (cprisk_pac_probe_fn_t)authed_ptr;
    if (authed_fn(sample) != expected) {
        flags |= CPRISK_PAC_CFI_FLAG_SELFTEST_FAILED;
    }

    atomic_store(&s_last_pac_flags, flags);
    return (flags & CPRISK_PAC_CFI_FLAG_SELFTEST_FAILED) == 0u ? 0 : 1;
#endif
}

// 对四个内置 C 回调做“storage schema 往返”校验：sign→auth 后必须还原为同一指针。
// 只验证签名编码/解码一致性，不验证回调代码字节或来源，不能当作完整性证明。
// 返回 0 = 通过或平台无 PAC（置 UNAVAILABLE）；1 = 任一失败（置 CALLBACK_VALIDATION_FAILED）。
int cprisk_pac_validate_core_callbacks(void) {
#if !CPRISK_PAC_RUNTIME_AVAILABLE
    atomic_store(&s_last_pac_flags, CPRISK_PAC_CFI_FLAG_UNAVAILABLE);
    return 0;
#else
    // 每个内置回调使用独立的 ASCII 常量 discriminator（"CPRISKF" 起递增），
    // 避免不同回调共用签名、被互相替换后仍能认证通过。
    struct {
        const void *pointer;
        uintptr_t discriminator;
    } callbacks[] = {
        { (const void *)&cprisk_compute_integrity_hash, 0x43505249534B4346ULL }, /* "CPRISKCF" */
        { (const void *)&cprisk_detect_hardware_breakpoints, 0x43505249534B4347ULL },
        { (const void *)&cprisk_detect_thread_exception_ports, 0x43505249534B4348ULL },
        { (const void *)&cprisk_run_all_signal_probes, 0x43505249534B4349ULL },
    };

    uint32_t aggregatedFlags = CPRISK_PAC_CFI_FLAG_NONE;
    bool validationFailed = false;

    /* These compiler-signed C callbacks use the standard ABI schema. This
     * checks a conversion to our storage schema and back, not the code
     * bytes or provenance of an externally supplied callback. */
    for (size_t i = 0; i < (sizeof(callbacks) / sizeof(callbacks[0])); ++i) {
        void *signed_ptr = cprisk_pac_sign_function_pointer(
            callbacks[i].pointer, callbacks[i].discriminator);
        const int rc = (signed_ptr == NULL) ? -1 :
            (cprisk_pac_auth_function_pointer(signed_ptr, callbacks[i].discriminator) != callbacks[i].pointer ? -1 : 0);
        if (rc != 0)
            aggregatedFlags |= CPRISK_PAC_CFI_FLAG_AUTH_FAILED;

        if (rc != 0) {
            validationFailed = true;
        }
    }

    if (validationFailed) {
        aggregatedFlags |= CPRISK_PAC_CFI_FLAG_CALLBACK_VALIDATION_FAILED;
    } else {
        aggregatedFlags &= ~CPRISK_PAC_CFI_FLAG_CALLBACK_VALIDATION_FAILED;
    }

    atomic_store(&s_last_pac_flags, aggregatedFlags);
    return validationFailed ? 1 : 0;
#endif
}

// 读取最近一次 PAC/CFI 操作的状态位；0 表示该次操作无错误，
// 但调用方仍需结合 cprisk_pac_is_arm64e_supported() 判断“无错误”是否来自降级桩。
uint32_t cprisk_get_last_pac_cfi_flags(void) {
    return (uint32_t)atomic_load(&s_last_pac_flags);
}
