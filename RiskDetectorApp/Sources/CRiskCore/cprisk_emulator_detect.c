/*
 * cprisk_emulator_detect.c — C 层模拟器 / 云手机 / unidbg 检测。
 * 职责：执行 dyld 缓存、VM region、栈地址、ostype、线程数、JVM 环境、timebase、CPU 时钟共 8 个探针。
 * 混淆：哨兵字符串以 0x55 异或，_Static_assert 锁死编码字节，改错即编译失败。
 * 误报：单信号不定性，is_hostile 要求总分 >= 25 或命中 dyld/栈地址两个高置信特征。
 * 线程：探针只读可并发；结果缓存用原子变量 + TTL，避免早期干净结果永久掩盖。
 * 平台/失败：仅 Apple 真机探测；probe_status 不可探测时返回 -1 并写 0，不得当作“干净”。
 */

#include "include/cprisk_emulator_detect.h"
#include "include/cprisk_vm_sync_barrier.h"
#include "include/CRiskCore.h"

#if defined(__APPLE__)
#  include <TargetConditionals.h>
#  if !TARGET_OS_SIMULATOR
#    include <mach/vm_map.h>
#    define CPRISK_EMU_HAVE_MACH_VM_REGION 1
#  endif
#endif
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// 编译期校验：断言的 “明文字符 ^ 0x55” 必须等于对应编码数组的首字节；
// 任一常量被误改都会立即编译失败，避免检测逻辑静默失效。
/* ── Compile-time XOR encoding verification ──────────────────────────────────
 * Each _Static_assert verifies that a character XOR the sentinel key equals
 * the first encoded byte used in the corresponding detection array.
 * If any future edit corrupts the byte arrays, the build fails immediately.
 * Key 0x55 sentinels:                                                       */
_Static_assert(('k' ^ 0x55u) == 0x3Eu, "kern.ostype[0] XOR 0x55 mismatch");
_Static_assert(('e' ^ 0x55u) == 0x30u, "kern.ostype[1] XOR 0x55 mismatch");
_Static_assert(('D' ^ 0x55u) == 0x11u, "Darwin[0] XOR 0x55 mismatch");
_Static_assert(('a' ^ 0x55u) == 0x34u, "Darwin[1] XOR 0x55 mismatch");
_Static_assert(('/' ^ 0x55u) == 0x7Au, "libobjc_path[0] XOR 0x55 mismatch");
_Static_assert(('u' ^ 0x55u) == 0x20u, "libobjc_path[1] XOR 0x55 mismatch");
_Static_assert(('J' ^ 0x55u) == 0x1Fu, "JAVA_HOME[0] XOR 0x55 mismatch");
_Static_assert(('A' ^ 0x55u) == 0x14u, "JAVA_HOME[1] XOR 0x55 mismatch");
_Static_assert(('C' ^ 0x55u) == 0x16u, "CLASSPATH[0] XOR 0x55 mismatch");
_Static_assert(('L' ^ 0x55u) == 0x19u, "LD_LIBRARY_PATH[0] XOR 0x55 mismatch");
_Static_assert(('D' ^ 0x55u) == 0x11u, "LD_LIBRARY_PATH[1] XOR 0x55 mismatch");
/* ─────────────────────────────────────────────────────────────────────────── */

#if defined(__APPLE__)
#  include <dlfcn.h>
#  include <mach/mach.h>
#  include <mach/mach_time.h>
#  include <sys/sysctl.h>
#  include <unistd.h>
#endif

/* ── XOR decode helper ───────────────────────────────────────────────────── */

/* Decode an in-place copy of a short XOR-obfuscated string into `out`.
 * `out` must be at least len+1 bytes.  Returns `out`. */
// 把 enc[0..len) 逐字节 ^ key 解码到 out，并补 '\0'。
// 参数：out 由调用方提供，至少 len+1 字节；enc 只读；允许 len 为 0。
// 返回：始终返回 out，便于链式调用。
// 线程安全：只写调用方栈缓冲，无全局状态，可重入。
// 平台：无分支。
// 失败语义：无失败路径（不做长度检查，调用方须保证缓冲足够）。
static char *xor_decode(const uint8_t *enc, size_t len, char *out, uint8_t key) {
    for (size_t i = 0; i < len; i++)
        out[i] = (char)(enc[i] ^ key);
    out[len] = '\0';
    return out;
}

/* ── Probe cache ─────────────────────────────────────────────────────────── */

/* Cache the result after the first call to avoid repeating slow probes.
 * 0xFFFFFFFF == not yet computed. The cache expires after
 * CPRISK_EMULATOR_PROBE_TTL_SECONDS so a stale clean result cannot mask
 * an emulator that appears later (issue 41). */
// 探针结果缓存：0xFFFFFFFF 表示“尚未计算”（不是合法的全零干净值）。
// TTL 到期后强制重探，防止早期干净结果永久掩盖后来出现的模拟器。
// 并发：s_cached_flags 用 release 写、relaxed 读；标记 stuck 时用 CAS 避免覆盖哨兵。
static _Atomic(uint32_t) s_cached_flags = ATOMIC_VAR_INIT(0xFFFFFFFFu);
static _Atomic(uint64_t) s_cached_at_unix = ATOMIC_VAR_INIT(0u);

/* ── Individual probes ───────────────────────────────────────────────────── */

#if defined(__APPLE__)

/*
 * Probe 1: dyld shared cache
 *
 * `_dyld_shared_cache_contains_path("/usr/lib/libobjc.A.dylib")` returns true
 * on every real iOS device; unidbg has no dyld shared cache.
 *
 * Resolved via dlsym to avoid a hard link and make it harder to hook at the
 * import table level.
 *
 * Path "/usr/lib/libobjc.A.dylib" XOR 0x55:
 *   [0x7A,0x20,0x26,0x27,0x7A,0x39,0x3C,0x37,0x7A,0x39,0x3C,0x37,
 *    0x3A,0x37,0x3F,0x36,0x7B,0x14,0x7B,0x31,0x2C,0x39,0x3C,0x37]
 */
// 探针 1：dyld 共享缓存是否包含 libobjc。
// 返回：1 = 真机特征（包含）；0 = 缺失或符号不可用。
// 判定依据：真机必有 dyld shared cache，unidbg 无；用 dlsym 动态解析可避开导入表 Hook。
// 误报边界：符号缺失只记可疑，不单独定罪（无缓存也可能是特殊裁剪环境）。
// 线程安全：无状态，可并发；平台：仅 Apple 真机编译。
static int probe_dyld_cache(void) {
    typedef bool (*fn_t)(const char *);
    /* "_dyld_shared_cache_contains_path" XOR 0x55 is long; look it up by the
     * public symbol name via RTLD_DEFAULT — the linker already resolved it. */
    fn_t fn = (fn_t)dlsym(RTLD_DEFAULT, "_dyld_shared_cache_contains_path");
    if (!fn) return 0; /* symbol absent — itself suspicious but not conclusive */

    static const uint8_t path_enc[] = {
        0x7A,0x20,0x26,0x27,0x7A,0x39,0x3C,0x37,0x7A,0x39,0x3C,0x37,
        0x3A,0x37,0x3F,0x36,0x7B,0x14,0x7B,0x31,0x2C,0x39,0x3C,0x37
    };
    char path[sizeof(path_enc) + 1];
    xor_decode(path_enc, sizeof(path_enc), path, 0x55u);
    return fn(path) ? 1 : 0;
}

/*
 * Probe 2: vm_region_64 count
 *
 * A real iOS process has ≥40 VM regions (ASLR, dyld shared cache segments,
 * stack guard regions, commpage, etc.).  unidbg synthesises a minimal map.
 */
// 探针 2：统计 VM region 数量（最多扫描 200 层/段）。
// 返回：1 = region 数 >= 40（真机）；0 = 过少（疑似最小化映射）。
// 判定依据：真机含 ASLR、共享缓存段、栈守卫、commpage 等，通常 >= 40。
// 误报边界：vm_region 查询失败立即停止并按当前计数判定；非 Apple/模拟器恒返回 1。
// 线程安全：只读本进程映射，可并发；平台：需要 mach/vm_map，模拟器走桩实现。
#ifdef CPRISK_EMU_HAVE_MACH_VM_REGION
static int probe_vm_region_count(void) {
    vm_address_t addr = 0;
    vm_size_t    size = 0;
    natural_t         depth = 0;
    vm_region_submap_info_data_64_t info;
    int regions = 0;

    for (unsigned scans = 0; scans < 200; scans++) {
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = vm_region_recurse_64(
            mach_task_self(), &addr, &size, &depth,
            (vm_region_recurse_info_t)&info, &count);
        if (kr != KERN_SUCCESS) break;
        if (info.is_submap) {
            // 子映射：加深一层继续遍历，而不是计入 region 数。
            depth++;
            continue;
        }
        regions++;
        // 防御 size 为 0 或地址回绕导致的死循环。
        if (size == 0 || addr > UINTPTR_MAX - size) break;
        addr += size;
    }
    /* < 40 is anomalous */
    return (regions < 40) ? 0 : 1;
}
#else
// 非 mach/vm_map 可用平台（模拟器、非 Apple）的桩：恒返回 1，
// 表示“无法证伪”，避免把不支持探测本身误判成模拟器。
static int probe_vm_region_count(void) {
    return 1;
}
#endif

/*
 * Probe 3: main-thread stack address
 *
 * On iOS, the main thread stack is always above 0x0001_0000_0000 (4 GB).
 * unidbg on Linux typically places the emulated stack much lower.
 */
// 探针 3：当前栈指针地址是否位于 iOS 主线程栈区间。
// 返回：1 = SP > 4GB（真机）；0 = 过低（疑似 unidbg/Linux 模拟栈）。
// 判定依据：iOS 主线程栈恒在 0x1_0000_0000 以上；arm64 用内联 asm 读 SP，其他架构取局部变量地址。
// 误报边界：只检查数值区间，不区分线程；调用方应只在主线程早期使用。
// 线程安全：无状态可并发；平台：arm64 读硬件 SP，其余回退取栈变量地址。
static int probe_stack_address(void) {
    volatile uintptr_t sp;
#if defined(__arm64__) || defined(__aarch64__)
    __asm__ __volatile__("mov %0, sp" : "=r"(sp));
#else
    volatile uint8_t local;
    sp = (uintptr_t)&local;
#endif
    return (sp > (uintptr_t)0x0000000100000000ULL) ? 1 : 0;
}

/*
 * Probe 4: kern.ostype sysctl
 *
 * "kern.ostype" XOR 0x55 → [0x3E,0x30,0x27,0x3B,0x7B,0x3A,0x26,0x21,0x2C,0x25,0x30]
 * "Darwin"      XOR 0x55 → [0x11,0x34,0x27,0x22,0x3C,0x3B]
 */
// 探针 4：sysctl kern.ostype 是否为 "Darwin"。
// 返回：1 = Darwin（真机）；0 = 查询失败或值不符。
// 判定依据：伪造/移植的运行环境常返回 Linux 或查询失败；名称与期望值均 XOR 混淆。
// 误报边界：查询失败也返回 0，但该信号权重仅 8，需与其他信号叠加才定罪。
// 线程安全：sysctl 只读，可并发；平台：仅 Apple 分支编译。
static int probe_ostype(void) {
    static const uint8_t name_enc[] = {
        0x3E,0x30,0x27,0x3B,0x7B,0x3A,0x26,0x21,0x2C,0x25,0x30
    };
    static const uint8_t expected_enc[] = { 0x11,0x34,0x27,0x22,0x3C,0x3B };

    char name[sizeof(name_enc) + 1];
    char expected[sizeof(expected_enc) + 1];
    xor_decode(name_enc, sizeof(name_enc), name, 0x55u);
    xor_decode(expected_enc, sizeof(expected_enc), expected, 0x55u);

    char buf[64] = {0};
    size_t bsz = sizeof(buf) - 1; /* leave room for defensive null-terminator */
    if (sysctlbyname(name, buf, &bsz, NULL, 0) != 0) return 0; /* query failed */
    buf[sizeof(buf) - 1] = '\0'; /* ensure null-termination regardless of kernel output */
    return (strcmp(buf, expected) == 0) ? 1 : 0;
}

/*
 * Probe 5: Mach thread count
 *
 * A real iOS app has ≥4 threads at cold start (main, GCD serial, libdispatch
 * worker, CoreFoundation run-loop, etc.).  unidbg JNI harness typically has 1–3.
 */
// 探针 5：Mach 线程数是否达到真机冷启动水平。
// 返回：1 = 线程数 >= 4 或查询失败；0 = 过少（疑似单线程 JNI 宿主）。
// 判定依据：真机冷启动含 main、GCD、libdispatch worker、CF runloop 等。
// 误报边界：task_threads 失败时清理端口并按“正常”返回 1，避免误报。
// 线程安全：只读 task 端口并逐线程释放引用，可并发；平台：仅 Apple。
static int probe_thread_count(void) {
    thread_act_array_t list = NULL;
    mach_msg_type_number_t cnt = 0;
    kern_return_t kr = task_threads(mach_task_self(), &list, &cnt);
    if (kr != KERN_SUCCESS) {
        /* Defensive cleanup: kernel may partially populate list on failure. */
        if (list != NULL && cnt > 0) {
            vm_deallocate(mach_task_self(),
                          (vm_address_t)list,
                          (vm_size_t)cnt * sizeof(thread_t));
        }
        return 1; /* error — treat as ok to avoid false positives */
    }
    int n = (int)cnt;
    for (int i = 0; i < n; i++)
        mach_port_deallocate(mach_task_self(), list[i]);
    vm_deallocate(mach_task_self(),
                  (vm_address_t)list,
                  (vm_size_t)n * sizeof(thread_t));
    return (n >= 4) ? 1 : 0;
}

/*
 * Probe 6: JVM indicator environment variables
 *
 * All names XOR-obfuscated with key 0x55:
 *   "JAVA_HOME"       → [0x1F,0x14,0x03,0x14,0x0A,0x1D,0x1A,0x18,0x10]
 *   "CLASSPATH"       → [0x16,0x19,0x14,0x06,0x06,0x05,0x14,0x01,0x1D]
 *   "LD_LIBRARY_PATH" → [0x19,0x11,0x0A,0x19,0x1C,0x17,0x07,0x14,0x07,
 *                        0x0C,0x0A,0x05,0x14,0x01,0x1D]
 */
// 探针 6：JVM 相关环境变量是否存在（JAVA_HOME / CLASSPATH / LD_LIBRARY_PATH）。
// 返回：1 = 任一存在；0 = 均不存在。
// 判定依据：unidbg 通常由 JVM 启动并保留这些变量；真机 App 不应有。
// 误报边界：用户越狱环境手动注入也可能出现，权重 14，需与其他信号叠加。
// 线程安全：getenv 只读，可并发（不修改环境）；平台：仅 Apple。
static int probe_jvm_env(void) {
    /* Separate static arrays for XOR-encoded JVM env var names */
    static const uint8_t JAVA_HOME_ENC[]   = {0x1F,0x14,0x03,0x14,0x0A,0x1D,0x1A,0x18,0x10};
    static const uint8_t CLASSPATH_ENC[]   = {0x16,0x19,0x14,0x06,0x06,0x05,0x14,0x01,0x1D};
    static const uint8_t LD_LIB_ENC[]      = {0x19,0x11,0x0A,0x19,0x1C,0x17,0x07,0x14,0x07,
                                            0x0C,0x0A,0x05,0x14,0x01,0x1D};
    /* Use separate const size_t variables to avoid initializer complexity */
    static const size_t JAVA_HOME_LEN = 9u;
    static const size_t CLASSPATH_LEN = 9u;
    static const size_t LD_LIB_LEN    = 15u;
    static const struct { const uint8_t *enc; size_t len; } vars[3] = {
        [0] = { JAVA_HOME_ENC,   JAVA_HOME_LEN   },
        [1] = { CLASSPATH_ENC,   CLASSPATH_LEN   },
        [2] = { LD_LIB_ENC,      LD_LIB_LEN      },
    };
    char buf[32];
    for (size_t i = 0; i < 3u; i++) {
        if (vars[i].len >= sizeof(buf)) continue;
        xor_decode(vars[i].enc, vars[i].len, buf, 0x55u);
        if (getenv(buf) != NULL) return 1; /* found — JVM env present */
    }
    return 0;
}

/*
 * Probe 7: mach_timebase_info ratio
 *
 * On real Apple Silicon iOS devices the ratio is typically 125:3 or similar.
 * On unidbg's Linux host the stub often returns 1:1 (numer==denom).
 * We flag 1:1 only when combined with no dyld shared cache.
 */
// 探针 7：mach timebase 是否退化为 1:1。
// 参数：have_dyld_cache 为探针 1 结果；为真时直接返回 0（真机跳过）。
// 返回：1 = 无共享缓存且 numer==denom（疑似桩实现）；0 = 正常或已跳过。
// 判定依据：真机 Apple Silicon 通常为非 1:1；unidbg 桩常返回 1:1。
// 误报边界：必须与“无 dyld 缓存”同时成立，单独 timebase 异常不定罪。
// 线程安全：只读，可并发；平台：仅 Apple。
static int probe_timebase_flat(int have_dyld_cache) {
    if (have_dyld_cache) return 0; /* real device — skip */
    struct mach_timebase_info tb = {0, 0};
    mach_timebase_info(&tb);
    return (tb.numer == tb.denom && tb.numer != 0) ? 1 : 0;
}

/*
 * Probe 8: CLOCK_PROCESS_CPUTIME_ID advance
 *
 * On real devices this clock advances with CPU usage.  unidbg stubs often
 * return 0 or a fixed value.
 */
// 探针 8：CLOCK_PROCESS_CPUTIME_ID 在消耗 CPU 后是否推进。
// 返回：1 = 时钟未推进（疑似冻结/桩）；0 = 正常推进或查询失败。
// 判定依据：真机该时钟随 CPU 时间前进；unidbg 桩常恒为 0 或固定值。
// 误报边界：clock_gettime 失败返回 0（不判风险）；权重 6，为辅助信号。
// 线程安全：只读时钟并做本地忙等，可并发；平台：仅 Apple。
static int probe_cpu_clock_frozen(void) {
    struct timespec t1, t2;
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t1) != 0) return 0;
    /* Burn enough cycles that any real CPU clock must advance */
    // 8192 次乘法足以让真机 CPU 时钟产生可观测增量，同时耗时可忽略。
    volatile uint64_t dummy = 0xDEADBEEFCAFE0000ULL;
    for (int i = 0; i < 8192; i++)
        dummy = dummy * 6364136223846793005ULL + 1442695040888963407ULL;
    (void)dummy;
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t2) != 0) return 0;
    int64_t ns1 = (int64_t)t1.tv_sec * 1000000000LL + t1.tv_nsec;
    int64_t ns2 = (int64_t)t2.tv_sec * 1000000000LL + t2.tv_nsec;
    return (ns2 <= ns1) ? 1 : 0;
}

#endif /* __APPLE__ */

/* ── Public API ──────────────────────────────────────────────────────────── */

// 当前平台是否允许执行真机探针（模拟器与非 Apple 返回 0）。
// 返回：1 = 可探测；0 = 不可探测。
// 线程安全：纯编译期常量，可并发；失败语义：0 时调用方必须视为“未知”而非“干净”。
static int cprisk_emulator_can_probe_i(void) {
#if defined(__APPLE__) && !TARGET_OS_SIMULATOR
    return 1;
#else
    return 0;
#endif
}

// 执行完整探针集合并返回 CPRISK_EMU_FLAG_* 位掩码。
// 参数：无。返回：位掩码，0 表示未发现异常（不代表绝对安全）。
// 线程安全：可并发；缓存读写用原子操作，TTL 内并发调用可能重复探测但结果一致。
// 平台：模拟器/非 Apple 跳过全部探针，仅保留 watchdog 标志。
// 失败语义：单个探针失败按“正常”处理（避免误报），不返回错误码。
uint32_t cprisk_emulator_probe(void) {
    /* Return cached result if available and fresh (TTL re-probe). */
    uint32_t cached = atomic_load_explicit(&s_cached_flags, memory_order_relaxed);
    if (cached != 0xFFFFFFFFu) {
        const uint64_t at = atomic_load_explicit(&s_cached_at_unix, memory_order_relaxed);
        const uint64_t now = (uint64_t)time(NULL);
        if (at != 0u && now >= at && now - at < CPRISK_EMULATOR_PROBE_TTL_SECONDS)
            return cached;
        /* Stale cache: fall through and re-probe. */
    }

    uint32_t flags = 0u;

#if defined(__APPLE__) && !TARGET_OS_SIMULATOR

    int have_dyld_cache = probe_dyld_cache();
    if (!have_dyld_cache)
        flags |= CPRISK_EMU_FLAG_DYLD_CACHE_ABSENT;

    if (!probe_vm_region_count())
        flags |= CPRISK_EMU_FLAG_LOW_VM_REGIONS;

    if (!probe_stack_address())
        flags |= CPRISK_EMU_FLAG_LOW_STACK_ADDR;

    if (!probe_ostype())
        flags |= CPRISK_EMU_FLAG_OSTYPE_NOT_DARWIN;

    if (!probe_thread_count())
        flags |= CPRISK_EMU_FLAG_LOW_THREAD_COUNT;

    if (probe_jvm_env())
        flags |= CPRISK_EMU_FLAG_JVM_ENV_VAR;

    if (probe_timebase_flat(have_dyld_cache))
        flags |= CPRISK_EMU_FLAG_TIMEBASE_FLAT;

    if (probe_cpu_clock_frozen())
        flags |= CPRISK_EMU_FLAG_CPU_CLOCK_FROZEN;

    /* WATCHDOG_STUCK is set externally by the VM interpreter after the sync
     * barrier detects no watchdog advancement; not probed here. */
    // WATCHDOG_STUCK 由 VM 同步屏障置位，此处只读取全局状态合并，不重复探测。

#endif /* __APPLE__ && !SIMULATOR */

    /* Incorporate global watchdog stuck state — set by the VM sync barrier
     * the first time it detects no watchdog advancement. */
    if (cprisk_vm_sync_barrier_global_stuck())
        flags |= CPRISK_EMU_FLAG_WATCHDOG_STUCK;

    atomic_store_explicit(&s_cached_flags, flags, memory_order_release);
    atomic_store_explicit(&s_cached_at_unix, (uint64_t)time(NULL), memory_order_release);
    return flags;
}

// 返回探针状态码并把标志写入 out_flags。
// 参数：out_flags 不可为 NULL，非 NULL 时由调用方提供并写入结果。
// 返回：0 = 已探测且无异常；1 = 已探测且有异常；-1 = 不可探测或参数非法。
// 线程安全：可并发；内部调用 cprisk_emulator_probe 的原子缓存。
// 平台：模拟器/非 Apple 恒返回 -1（并写 0），调用方不得把 0 当干净。
// 失败语义：out_flags 为 NULL 或不可探测时返回 -1，不修改其他状态。
int cprisk_emulator_probe_status(uint32_t *out_flags) {
    if (!out_flags)
        return -1;
    if (!cprisk_emulator_can_probe_i()) {
        *out_flags = 0u;
        return -1; /* not probed — must not be read as "clean" */
    }
    const uint32_t flags = cprisk_emulator_probe();
    *out_flags = flags;
    return flags == 0u ? 0 : 1;
}

// 轻量实时探测：只跑 ostype、栈地址与全局 watchdog 状态。
// 参数：无。返回：与完整探测相同的 CPRISK_EMU_FLAG_* 位掩码。
// 线程安全：无共享写状态，可并发；模式：故意不读/写缓存，攻击者清零缓存也无法绕过。
// 平台：仅 Apple 真机执行；其他平台返回 0。
// 失败语义：探针失败按正常处理；该函数用于签名等高频路径，不做慢速探测。
uint32_t cprisk_emulator_quick_probe(void) {
    /*
     * Re-run only the two lightest probes — no malloc, no syscall with side
     * effects.  Result is NOT cached so an attacker who zeroed s_cached_flags
     * must also defeat this live check on every signing call.
     *
     * Returns a bitmask using the same CPRISK_EMU_FLAG_* constants.
     */
    uint32_t flags = 0u;
#if defined(__APPLE__) && !TARGET_OS_SIMULATOR
    if (!probe_ostype())
        flags |= CPRISK_EMU_FLAG_OSTYPE_NOT_DARWIN;
    if (!probe_stack_address())
        flags |= CPRISK_EMU_FLAG_LOW_STACK_ADDR;
    if (cprisk_vm_sync_barrier_global_stuck())
        flags |= CPRISK_EMU_FLAG_WATCHDOG_STUCK;
#endif
    return flags;
}

// 由 VM 同步屏障在检测到 watchdog 不推进时调用，向缓存 OR 入 stuck 标志。
// 参数：无。返回：无。
// 线程安全：CAS 循环，可并发；不覆盖 0xFFFFFFFF 哨兵，避免把“未计算”误变成“已计算”。
// 平台：无关。
// 失败语义：缓存尚未计算时不写入，后续完整探测会通过全局状态自然带上该标志。
void cprisk_emulator_mark_watchdog_stuck(void) {
    /* OR in the stuck flag without disturbing other cached bits.
     * Uses a compare-and-swap loop so we don't clobber 0xFFFFFFFF
     * (not-yet-computed sentinel) — in that case the full probe will
     * incorporate the stuck flag via cprisk_vm_sync_barrier_global_stuck(). */
    uint32_t current = atomic_load_explicit(&s_cached_flags, memory_order_acquire);
    while (current != 0xFFFFFFFFu) {
        if (current & CPRISK_EMU_FLAG_WATCHDOG_STUCK)
            return; /* already set */
        if (atomic_compare_exchange_weak_explicit(
                &s_cached_flags,
                &current,
                current | CPRISK_EMU_FLAG_WATCHDOG_STUCK,
                memory_order_release,
                memory_order_relaxed))
            return;
    }
    /* Cache not yet populated; the full probe will pick it up from
     * cprisk_vm_sync_barrier_global_stuck() when it eventually runs. */
}

// 把标志位加权成 0..100 的风险分。
// 参数：flags 为 cprisk_emulator_probe 返回的位掩码。
// 返回：累加权重，封顶 100；未知位被忽略。
// 线程安全：只读常量表，可并发。
// 平台：无分支。
// 失败语义：无失败路径；权重与 Swift 层检测器保持镜像，改动需两端同步。
int cprisk_emulator_score(uint32_t flags) {
    /* Weights chosen to mirror the Swift-layer detectors */
    static const struct { uint32_t flag; int weight; } weights[] = {
        { CPRISK_EMU_FLAG_DYLD_CACHE_ABSENT,  22 },
        { CPRISK_EMU_FLAG_LOW_VM_REGIONS,     12 },
        { CPRISK_EMU_FLAG_LOW_STACK_ADDR,     14 },
        { CPRISK_EMU_FLAG_OSTYPE_NOT_DARWIN,   8 },
        { CPRISK_EMU_FLAG_LOW_THREAD_COUNT,    8 },
        { CPRISK_EMU_FLAG_JVM_ENV_VAR,        14 },
        { CPRISK_EMU_FLAG_TIMEBASE_FLAT,       8 },
        { CPRISK_EMU_FLAG_CPU_CLOCK_FROZEN,    6 },
        { CPRISK_EMU_FLAG_WATCHDOG_STUCK,     12 },
    };
    int score = 0;
    for (size_t i = 0; i < sizeof(weights)/sizeof(weights[0]); i++) {
        if (flags & weights[i].flag)
            score += weights[i].weight;
    }
    return score > 100 ? 100 : score;
}

// 判断标志组合是否达到“敌对”阈值。
// 参数：flags 为探测位掩码。返回：1 = 敌对；0 = 未达阈值。
// 判定：总分 >= 25，或命中两个最高置信特征（无 dyld 缓存、栈地址越界）之一。
// 线程安全：纯函数，可并发；平台：无分支。
// 失败语义：无失败路径；未探测平台应先用 probe_status 区分“未探测”。
int cprisk_emulator_is_hostile(uint32_t flags) {
    /* Hostile if score exceeds 25 OR any of the two highest-confidence flags
     * are set (dyld cache absent or stack address out of range). */
    if (cprisk_emulator_score(flags) >= 25) return 1;
    if (flags & (CPRISK_EMU_FLAG_DYLD_CACHE_ABSENT | CPRISK_EMU_FLAG_LOW_STACK_ADDR)) return 1;
    return 0;
}
