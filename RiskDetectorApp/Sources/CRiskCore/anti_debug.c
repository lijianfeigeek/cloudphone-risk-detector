/*
 * CRiskCore - Anti-debug via SVC direct deny-attach syscall.
 * Bypasses user-space hooks by invoking the kernel trap path directly.
 *
 * ARM64 iOS: deny-attach syscall #26, request code = 31.
 * Darwin ABI: x16 = syscall number, x0-x3 = args.
 *
 * Also provides P_TRACED detection via sysctl to detect if the process is
 * currently being traced (debugger attached).
 */

// 本文件是反调试聚合层：直接 SVC 的 deny-attach、sysctl P_TRACED、Mach 异常端口与
// task_for_pid 观测共同构成快慢两条探针路径，并由交叉校验识别 DBI/注入器。
// 线程模型：跨调用状态均为 atomic；deny-attach stub 重定位完成后页面只读，可并发调用。
// 平台：deny-attach 仅 arm64 iOS 真机生效；模拟器与非 arm64 整体降级为返回 0（fail-open）。
// 失败语义：查询失败按“未附加调试器”处理；只有明确的快慢路径不一致才累计 streak 并投毒。
#include "include/CRiskCore.h"

#if defined(__APPLE__)
#include <TargetConditionals.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/mman.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>
#include "include/cprisk_instruction_cache.h"
#endif

// deny-attach 的设备可用性开关：必须同时满足 arm64、iOS 且非模拟器；
// 内核 trap 路径在模拟器上不保证存在，强行走 SVC 会得到不可预期的错误。
#if (defined(__arm64__) || defined(__aarch64__)) && defined(__APPLE__) && \
    (defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE) && \
    (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
#define CPRISK_DENY_ATTACH_DEVICE_AVAILABLE 1
#else
#define CPRISK_DENY_ATTACH_DEVICE_AVAILABLE 0
#endif

/// 尽力拒绝调试器 attach 到当前进程；忽略错误码。
/// - Returns: 无返回值。失败时进程仍继续运行（fail-open），由上层状态接口另行核对。
/// - Thread safety: 只调用无状态的 SVC 包装或重定位后的只读 stub，可并发调用。
void cprisk_deny_attach(void) {
    (void)cprisk_deny_attach_status(NULL);
}

// 捕获/校验的 stub 快照长度（48 字节 = 3 个 16 字节 chunk），覆盖函数入口到 SVC 的关键指令。
#define CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES 48u

/// deny-attach 的 SVC 直调模板，也是重定位与完整性校验的原始副本。
/// - 参数：error_out 可为 NULL；非 NULL 时失败写入内核返回码（即 x0）。
/// - Returns: 成功返回内核返回值（通常 0）；失败返回 -1 并置 error_out。
/// - Thread safety: 无全局状态，可重入。
/// - Platform: 仅 arm64 iOS 真机执行 `svc #0x80`；其他平台写 0 并返回 0。
/// - 说明：绕过 libc/ptrace 等用户态 hook 面，直接走 BSD syscall 路径。
static int cprisk_deny_attach_status_template(int *error_out) {
#if CPRISK_DENY_ATTACH_DEVICE_AVAILABLE
    register long x0 __asm("x0") = 31;  /* PT_DENY_ATTACH */
    register long x1 __asm("x1") = 0;   /* pid = 0 (self) */
    register long x2 __asm("x2") = 0;   /* addr = 0 */
    register long x3 __asm("x3") = 0;   /* data = 0 */
    register long x16 __asm("x16") = 26; /* deny-attach syscall number */
    unsigned int did_error = 0;

    /* SVC #0x80: direct BSD syscall, bypasses libc hook surface */
    __asm__ volatile (
        "svc #0x80\n"
        "cset %w[did_error], cs\n"
        : "+r"(x0), [did_error] "=r"(did_error)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x16)
        : "cc", "memory"
    );

    if (did_error) {
        if (error_out != NULL) {
            *error_out = (int)x0;
        }
        return -1;
    }

    if (error_out != NULL) {
        *error_out = 0;
    }
    return (int)x0;
#else
    /* No-op on simulator, x86_64, or non-Apple */
    if (error_out != NULL) {
        *error_out = 0;
    }
    return 0;
#endif
}

// 当前使用的 deny-attach 实现：初始指向模板；constructor(3) 成功后改指向随机偏移的 RX 副本。
// 写入发生在任何正常调用之前，读取端不加锁；指针本身按机器字对齐，发布是原子的。
static int (*s_deny_attach_fn)(int *) = cprisk_deny_attach_status_template;

#if CPRISK_DENY_ATTACH_DEVICE_AVAILABLE

// 重定位后的 RX stub 页：pg 由本文件拥有且永不释放（进程生命周期），
// size 为映射长度，offset 为 stub 在页内的 4 字节对齐偏移（随机化以对抗签名扫描）。
static void *s_deny_rx_page;
static size_t s_deny_rx_page_size;
static uintptr_t s_deny_rx_offset;
// 页面与 stub 的参考哈希。页面哈希混合了 offset 与固定盐，roll 哈希覆盖 stub 的两个重叠半区，
// 用于发现页内容被改写或 stub 被整体搬移。
static uint64_t s_deny_rx_page_hash_ref;
static uint64_t s_deny_rx_stub_roll_ref;
// 重定位完成标志：constructor(3) 在所有字段发布后置 1；其他线程据此选择 RX 副本或模板。
static volatile int s_deny_reloc_ready;

/// FNV-1a 64 位哈希，用于低成本的页/stub 完整性参考值（非密码学用途）。
/// - Parameters: p/n 为待哈希区间；调用方保证可读。
/// - Returns: 64 位哈希；无分配、无状态，可重入。
static uint64_t cprisk_deny_fnv1a64_i(const void *p, size_t n) {
    const uint8_t *b = (const uint8_t *)p;
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0u; i < n; i++) {
        h ^= (uint64_t)b[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/// constructor(3)：把 deny-attach stub 复制到匿名页的随机偏移，改为 RX 后作为实际实现。
/// - 优先级 3 保证在常规业务 constructor 之前完成；失败时保留模板指针，功能仍然可用。
/// - 步骤：匿名可写页 → 随机 4 字节对齐偏移 → 复制 48 字节 → 刷 I-cache →
///   mprotect(RX) → 计算页/半区哈希 → 发布指针与参考值。
/// - Thread safety: 仅构造期单线程执行；发布后页面只读，读者无锁。
/// - 失败语义：任一系统调用失败即回退模板（fail-open），不终止进程。
__attribute__((constructor(3)))
static void cprisk_deny_attach_rx_reloc_ctor_i(void) {
    const size_t ps = (size_t)getpagesize();
    if (ps < CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES + 64u) {
        return;
    }
    uint64_t r = 0u;
    int ge = 0;
    if (cprisk_getentropy_direct(&r, sizeof(r), &ge) != 0) {
        r = (uint64_t)(uintptr_t)&cprisk_deny_attach_rx_reloc_ctor_i ^ 0x5A5A5A5Au;
    }
    void *pg = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (pg == MAP_FAILED) {
        return;
    }
    memset(pg, 0, ps);
    const uintptr_t max_off = ps - CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES - 8u;
    const uintptr_t off = (uintptr_t)((r % (max_off / 4u)) * 4u);
    memcpy((uint8_t *)pg + off, (const void *)&cprisk_deny_attach_status_template, CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES);
// 必须先刷 I-cache 再改成可执行：否则 CPU 可能执行到该地址上的陈旧指令。
    cprisk_flush_instruction_cache((uint8_t *)pg + off, CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES);

    int mperr = 0;
// 直接 mprotect 避免用户态 hook；失败则丢弃该页并继续使用模板。
    if (cprisk_mprotect_direct(pg, ps, PROT_READ | PROT_EXEC, &mperr) != 0) {
        munmap(pg, ps);
        return;
    }

// 页面哈希混入随机偏移与固定盐，防止攻击者把 stub 原样复制到另一偏移后仍通过校验。
    uint64_t h = cprisk_deny_fnv1a64_i(pg, ps);
    h ^= (uint64_t)off << 40;
    h ^= 0x3D3C2B1A0F0E0D0CULL;

// stub roll 哈希覆盖前半与后半（带重叠），任何局部改写都会改变至少一个半区的哈希。
    const uint8_t *pd = (const uint8_t *)pg + off;
    uint64_t roll = cprisk_deny_fnv1a64_i(pd, CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES);
    roll ^= cprisk_deny_fnv1a64_i(
        pd + CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES / 4u,
        CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES - CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES / 4u);

// 先写页面/哈希等从属字段，最后发布函数指针和 ready 标志，避免读者看到半初始化状态。
    s_deny_rx_page = pg;
    s_deny_rx_page_size = ps;
    s_deny_rx_offset = off;
    s_deny_rx_page_hash_ref = h;
    s_deny_rx_stub_roll_ref = roll;
    s_deny_attach_fn = (int (*)(int *))((uint8_t *)pg + off);
    s_deny_reloc_ready = 1;
}
#endif

/// 调用当前的 deny-attach 实现并返回其结果。
/// - Parameters: error_out 语义同 cprisk_deny_attach_status_template()，允许 NULL。
/// - Returns: 成功为内核返回值；失败为 -1。构造期之前调用会自动落到模板，仍然安全。
/// - Thread safety: 可并发调用；实现指针只在构造期切换一次。
int cprisk_deny_attach_status(int *error_out) {
    return s_deny_attach_fn(error_out);
}

// stub 完整性按 3 个 chunk × 16 字节校验；每次检查 1 个 chunk，每第 4 次做全量。
#define CPRISK_DENY_ATTACH_CHUNKS 3u
#define CPRISK_DENY_ATTACH_CHUNK 16u

// 构造期(8)计算出的每 chunk 期望哈希；text_ready 置位后只读。
static uint64_t s_cprisk_deny_attach_chunk_expected[CPRISK_DENY_ATTACH_CHUNKS];
// 快照采集完成标志：未置位前完整性检查返回 0，避免拿未初始化的期望值误判。
// 单写多读，arm64 上对齐 int 的发布是原子的。
static volatile int s_cprisk_deny_attach_text_ready = 0;
// 检查轮转计数：决定本次校验单个 chunk 还是全部 chunk，兼顾覆盖率与开销。
static atomic_uint_fast32_t s_cprisk_deny_attach_stub_tick;

// SHA-256 参考值与构造期采集逻辑只在 arm64 Apple 上存在；
// 其他平台由文件末尾的桩返回 0/零摘要。
#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
static uint8_t s_deny_page_sha256_ref[32];

/// constructor(8)：在 deny-attach 重定位完成之后，冻结 stub 的完整性参考值。
/// - 源选择：重定位成功则取 RX 页内的实际 stub，否则取 __TEXT 中的模板；
/// - 记录：3 个 chunk 的 FNV 哈希（混入 stub 基址，防止整段搬移）与整页 SHA-256；
/// - 最后置 text_ready，之后参考值不再变化。
/// - Thread safety: 仅构造期单线程执行。
__attribute__((constructor(8)))
static void cprisk_svc_stub_capture_deny_attach_i(void) {
#if CPRISK_DENY_ATTACH_DEVICE_AVAILABLE
    const void *src = (s_deny_reloc_ready != 0 && s_deny_rx_page != NULL)
                           ? (const void *)((const uint8_t *)s_deny_rx_page + s_deny_rx_offset)
                           : (const void *)&cprisk_deny_attach_status_template;
#else
    const void *src = (const void *)&cprisk_deny_attach_status_template;
#endif
    const uintptr_t base = (uintptr_t)src;
    uint8_t snap[CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES];
    memcpy(snap, src, sizeof(snap));
    for (uint32_t c = 0; c < CPRISK_DENY_ATTACH_CHUNKS; c++) {
        s_cprisk_deny_attach_chunk_expected[c] =
            cprisk_svc_stub_chunk_hash_fnv16(snap + (size_t)c * CPRISK_DENY_ATTACH_CHUNK, base);
    }
    cprisk_sha256_text_page(src, s_deny_page_sha256_ref);
    s_cprisk_deny_attach_text_ready = 1;
}
#endif

/// 校验 deny-attach stub 是否仍保持构造期形态。
/// - 检查顺序：页哈希 → stub 半区 roll 哈希 → chunk 哈希（轮转/全量）→ SVC 操作码仍存在；
/// - Returns: 任一不符返回 1（疑似被 patch/hook/搬移）；未初始化或全部通过返回 0。
/// - Thread safety: 只读 RX 页与已发布参考值；轮转计数为 atomic，可并发调用。
/// - 失败语义：无法校验时返回 0，不单独作为风险；调用方应结合其它信号判断。
uint32_t cprisk_deny_attach_stub_integrity_mask(void) {
#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
    if (!s_cprisk_deny_attach_text_ready) {
        return 0u;
    }
#if CPRISK_DENY_ATTACH_DEVICE_AVAILABLE
    if (s_deny_reloc_ready != 0 && s_deny_rx_page != NULL) {
        uint64_t h = cprisk_deny_fnv1a64_i(s_deny_rx_page, s_deny_rx_page_size);
        h ^= (uint64_t)s_deny_rx_offset << 40;
        h ^= 0x3D3C2B1A0F0E0D0CULL;
        if (h != s_deny_rx_page_hash_ref) {
            return 1u;
        }
        const uint8_t *pd = (const uint8_t *)s_deny_rx_page + s_deny_rx_offset;
        uint64_t roll = cprisk_deny_fnv1a64_i(pd, CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES);
        roll ^= cprisk_deny_fnv1a64_i(
            pd + CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES / 4u,
            CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES - CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES / 4u);
        if (roll != s_deny_rx_stub_roll_ref) {
            return 1u;
        }
        uint8_t live[CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES];
        memcpy(live, pd, sizeof(live));
        const uint32_t t =
            atomic_fetch_add_explicit(&s_cprisk_deny_attach_stub_tick, 1u, memory_order_relaxed) + 1u;
        const int full = (t % 4u) == 0u;
        if (full) {
            for (uint32_t c = 0; c < CPRISK_DENY_ATTACH_CHUNKS; c++) {
                const uint64_t ch = cprisk_svc_stub_chunk_hash_fnv16(
                    live + (size_t)c * CPRISK_DENY_ATTACH_CHUNK,
                    (uintptr_t)pd);
                if (ch != s_cprisk_deny_attach_chunk_expected[c]) {
                    return 1u;
                }
            }
        } else {
            const uint32_t idx = (t - 1u) % CPRISK_DENY_ATTACH_CHUNKS;
            const uint64_t ch = cprisk_svc_stub_chunk_hash_fnv16(
                live + (size_t)idx * CPRISK_DENY_ATTACH_CHUNK,
                (uintptr_t)pd);
            if (ch != s_cprisk_deny_attach_chunk_expected[idx]) {
                return 1u;
            }
        }
        if (!cprisk_stub_contains_svc_opcode(pd, CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES)) {
            return 1u;
        }
        return 0u;
    }
#endif
    uint8_t live[CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES];
    memcpy(live, (const void *)&cprisk_deny_attach_status_template, sizeof(live));
    const uintptr_t base = (uintptr_t)(void *)&cprisk_deny_attach_status_template;
    const uint32_t t =
        atomic_fetch_add_explicit(&s_cprisk_deny_attach_stub_tick, 1u, memory_order_relaxed) + 1u;
    const int full = (t % 4u) == 0u;
    if (full) {
        for (uint32_t c = 0; c < CPRISK_DENY_ATTACH_CHUNKS; c++) {
            const uint64_t ch = cprisk_svc_stub_chunk_hash_fnv16(
                live + (size_t)c * CPRISK_DENY_ATTACH_CHUNK,
                base);
            if (ch != s_cprisk_deny_attach_chunk_expected[c]) {
                return 1u;
            }
        }
    } else {
        const uint32_t idx = (t - 1u) % CPRISK_DENY_ATTACH_CHUNKS;
        const uint64_t ch = cprisk_svc_stub_chunk_hash_fnv16(
            live + (size_t)idx * CPRISK_DENY_ATTACH_CHUNK,
            base);
        if (ch != s_cprisk_deny_attach_chunk_expected[idx]) {
            return 1u;
        }
    }
#if CPRISK_DENY_ATTACH_DEVICE_AVAILABLE
    if (!cprisk_stub_contains_svc_opcode((const void *)&cprisk_deny_attach_status_template, sizeof(live))) {
        return 1u;
    }
#endif
    return 0u;
#else
    return 0u;
#endif
}

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
/// 计算当前实际使用的 deny-attach stub 所在文本页的 SHA-256。
/// - Parameters: out_digest 为调用方提供的 32 字节缓冲；NULL 时直接返回。
/// - 源选择：重定位成功取 RX 页内 stub，否则取模板；不可用平台写 32 字节 0。
/// - Thread safety: 只读，可重入。
void cprisk_deny_attach_stub_page_sha256_digest(uint8_t out_digest[32]) {
    if (!out_digest) {
        return;
    }
#if CPRISK_DENY_ATTACH_DEVICE_AVAILABLE
    const void *src =
        (s_deny_reloc_ready != 0 && s_deny_rx_page != NULL)
            ? (const void *)((const uint8_t *)s_deny_rx_page + s_deny_rx_offset)
            : (const void *)&cprisk_deny_attach_status_template;
    cprisk_sha256_text_page(src, out_digest);
#elif (defined(__arm64__) || defined(__aarch64__)) && defined(__APPLE__)
    cprisk_sha256_text_page((const void *)&cprisk_deny_attach_status_template, out_digest);
#else
    memset(out_digest, 0, 32);
#endif
}

/// 比较当前 stub 页的 SHA-256 与构造期参考值。
/// - Returns: 不一致返回 (1u << 5) 作为异常位；一致或不支持返回 0。
uint32_t cprisk_deny_attach_stub_sha256_page_mask(void) {
#if (defined(__arm64__) || defined(__aarch64__)) && defined(__APPLE__)
    uint8_t live[32];
    cprisk_deny_attach_stub_page_sha256_digest(live);
    return memcmp(live, s_deny_page_sha256_ref, 32) != 0 ? (1u << 5) : 0u;
#else
    return 0u;
#endif
}
#else
// 非 arm64 Apple：无法读取/校验 stub 页，摘要写零。
void cprisk_deny_attach_stub_page_sha256_digest(uint8_t out_digest[32]) {
    if (out_digest) {
        memset(out_digest, 0, 32);
    }
}

// 非 arm64 Apple：不产生页级异常位。
uint32_t cprisk_deny_attach_stub_sha256_page_mask(void) {
    return 0u;
}
#endif

// 最近一次 fast/slow 交叉校验是否不一致（1=不一致），供聚合入口无重复探测地读取。
static atomic_uint_fast32_t s_trace_crosscheck_inconsistent = 0u;
// 连续不一致的观测次数；达到 2 次且 slow 路径也判定可疑时触发 anti-debug 通道投毒。
static atomic_uint_fast32_t s_trace_crosscheck_streak = 0u;
/*
 * Anti-debug review weakness #2: previously `s_mach_port_baseline` was
 * latched to the FIRST observation, so an attacker who attached lldb
 * before the first probe ran would seed the baseline with the
 * already-elevated count and never trigger the "surge after attach"
 * detector. The new model takes the MINIMUM of the first N observations
 * as the baseline (an attacker holding port count high across all of
 * those samples cannot drive the baseline DOWN), and refuses to alarm
 * on any of those calibration samples.
 *
 * Calibration size 8 is small enough to settle within ~2 seconds at the
 * watchdog cadence, large enough that a one-shot attach right at boot
 * still has the user's OWN steady state captured as the floor in at
 * least 5–6 of the 8 samples.
 */
#define CPRISK_MACH_PORT_BASELINE_CALIB_SAMPLES 8u
// Mach 端口基线：baseline 为校准后提交的稳态端口数，baseline_min 为校准窗口内的运行最小值，
// baseline_samples 为已完成的校准样本数。最小值模型使攻击者无法通过持续高端口数压低基线。
static atomic_uint_fast32_t s_mach_port_baseline = 0u;
static atomic_uint_fast32_t s_mach_port_baseline_min = 0u;
static atomic_uint_fast32_t s_mach_port_baseline_samples = 0u;
// slow 路径调用计数：用于让线程异常端口检查与 DBI 足迹检查按固定周期抽样，控制开销。
static atomic_uint_fast32_t s_trace_probe_counter = 0u;

/// 仅通过 sysctl(KERN_PROC_PID) 检查 P_TRACED。
/// - Returns: P_TRACED 置位返回 1；未置位或查询失败返回 0（失败不判风险）。
/// - Thread safety: 无全局状态，可并发调用。
/// - 说明：MIB 常量在运行时用 XOR 还原，避免静态整数特征被直接匹配。
int cprisk_is_being_traced_sysctl_only(void) {
#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    int mib[4];
    struct kinfo_proc info;
    size_t size = sizeof(info);

    memset(&info, 0, size);
    /* MIB values constructed at runtime via XOR to avoid static integer-pattern
     * matching (equivalent to DexHelper-style stack string construction for paths).
     * CTL_KERN=1, KERN_PROC=14, KERN_PROC_PID=1 — decoded only during execution. */
    mib[0] = (int)(0x2Au ^ 0x2Bu);          /* CTL_KERN  = 1  */
    mib[1] = (int)(0xF8u ^ 0xF6u);          /* KERN_PROC = 14 */
    mib[2] = (int)(0x55u ^ 0x54u);          /* KERN_PROC_PID = 1 */
    mib[3] = (int)cprisk_getpid_direct();

    if (cprisk_sysctl_direct(mib, 4, &info, &size, NULL, 0, NULL) != 0)
        return 0;  /* assume not traced on query failure */

    return ((info.kp_proc.p_flag & P_TRACED) != 0) ? 1 : 0;
#else
    return 0;
#endif
}

/// Mach 层可疑度聚合：异常端口、task_for_pid 计数、线程端口、端口数量突增。
/// - 计分：task_get_exception_ports 查询失败 +1；extmod 中 task_for_pid_count>0 +1；
///   线程级异常端口不匹配 +2；端口数超过基线 64 个 +1；
/// - 端口基线采用前 8 次观测的最小值，校准窗口内不告警，防止 attach 发生在首次探测前；
/// - Returns: 任一项计分大于 0 返回 1，否则 0。
/// - Thread safety: 校准与基线均为 atomic，CAS 收敛；查询得到的端口权在函数内释放。
int cprisk_mach_trace_suspicious(void) {
#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    int suspicious = 0;

    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;
    const exception_mask_t mask = EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS;
    kern_return_t kr = task_get_exception_ports(
        mach_task_self(),
        mask,
        masks,
        &count,
        ports,
        behaviors,
        flavors);
    if (kr != KERN_SUCCESS) {
        suspicious += 1;
    } else {
        int has_breakpoint_port = 0;
        for (mach_msg_type_number_t i = 0; i < count; i++) {
            if ((masks[i] & EXC_MASK_BREAKPOINT) != 0u &&
                ports[i] != MACH_PORT_NULL) {
                has_breakpoint_port = 1;
            }
            if (ports[i] != MACH_PORT_NULL) {
                mach_port_deallocate(mach_task_self(), ports[i]);
            }
        }
        if (!has_breakpoint_port) {
            /* Weak signal only: missing task-level breakpoint port can happen
               on some builds, so do not score it as a hard anomaly. */
            suspicious += 0;
        }
    }

    task_extmod_info_data_t extmod;
    mach_msg_type_number_t extmod_count = TASK_EXTMOD_INFO_COUNT;
    memset(&extmod, 0, sizeof(extmod));
    if (task_info(
            mach_task_self(),
            TASK_EXTMOD_INFO,
            (task_info_t)&extmod,
            &extmod_count) == KERN_SUCCESS) {
        if (extmod.extmod_statistics.task_for_pid_count > 0) {
            suspicious += 1;
        }
    }

    if (cprisk_detect_thread_exception_ports() > 0) {
        suspicious += 2;
    }

    mach_port_name_array_t names = MACH_PORT_NULL;
    mach_msg_type_number_t names_count = 0;
    mach_port_type_array_t types = MACH_PORT_NULL;
    mach_msg_type_number_t types_count = 0;
    if (mach_port_names(mach_task_self(), &names, &names_count, &types, &types_count) == KERN_SUCCESS) {
        const uint32_t observed_count = (uint32_t)names_count;
        const uint32_t samples = atomic_load(&s_mach_port_baseline_samples);

        if (samples < CPRISK_MACH_PORT_BASELINE_CALIB_SAMPLES) {
            /*
             * Calibration window: maintain a running MIN, increment
             * sample counter, and explicitly DO NOT raise suspicion in
             * this window — an attacker attached before init would seed
             * an inflated baseline if we used first-observation latching.
             *
             * The CAS-based update converges to the actual minimum even
             * with concurrent probe threads racing here.
             */
            uint32_t prev = atomic_load(&s_mach_port_baseline_min);
            if (prev == 0u || observed_count < prev) {
                while (prev == 0u || observed_count < prev) {
                    if (atomic_compare_exchange_weak(
                            &s_mach_port_baseline_min, &prev, observed_count)) {
                        break;
                    }
                }
            }
            uint32_t new_samples = atomic_fetch_add(
                &s_mach_port_baseline_samples, 1u) + 1u;
            if (new_samples >= CPRISK_MACH_PORT_BASELINE_CALIB_SAMPLES) {
                /* Calibration complete — commit min as the working baseline. */
                uint32_t computed = atomic_load(&s_mach_port_baseline_min);
                if (computed > 0u) {
                    atomic_store(&s_mach_port_baseline, computed);
                }
            }
        } else {
            const uint32_t baseline = atomic_load(&s_mach_port_baseline);
            if (baseline > 0u && observed_count > baseline &&
                (observed_count - baseline) > 64u) {
                /* A sudden Mach port surge often appears after debugger/injector attach. */
                suspicious += 1;
            }
        }

        if (names != MACH_PORT_NULL && names_count > 0) {
            vm_deallocate(
                mach_task_self(),
                (vm_address_t)names,
                (vm_size_t)(sizeof(mach_port_name_t) * (size_t)names_count)
            );
        }
        if (types != MACH_PORT_NULL && types_count > 0) {
            vm_deallocate(
                mach_task_self(),
                (vm_address_t)types,
                (vm_size_t)(sizeof(mach_port_type_t) * (size_t)types_count)
            );
        }
    }

    return suspicious > 0 ? 1 : 0;
#else
    return 0;
#endif
}

/// 返回最近一次交叉校验的不一致状态：1=fast/slow 结果相反，0=一致或尚未运行。
int cprisk_trace_crosscheck_inconsistent(void) {
    return atomic_load(&s_trace_crosscheck_inconsistent) != 0u ? 1 : 0;
}

/// fast 路径：只做 sysctl P_TRACED，开销最小，可高频调用。
/// - Returns: 1=已附加调试器，0=未发现或查询失败。
static int cprisk_trace_probe_fast_i(void) {
    return cprisk_is_being_traced_sysctl_only() != 0 ? 1 : 0;
}

/// slow 路径：Mach 可疑度 + 周期性线程异常端口检查 + 周期性 DBI 足迹检查。
/// - 抽样：每第 4 次检查线程异常端口，每第 8 次检查 DBI 标记，兼顾覆盖与开销；
/// - Returns: 1=发现任一可疑信号，0=全部正常。
/// - Thread safety: 计数器 atomic；内部查询均只读。
static int cprisk_trace_probe_slow_i(void) {
    int suspicious = 0;
    if (cprisk_mach_trace_suspicious() != 0) {
        suspicious = 1;
    }

    const uint32_t seq = atomic_fetch_add(&s_trace_probe_counter, 1u) + 1u;
    if ((seq & 3u) == 0u && cprisk_detect_thread_exception_ports() > 0) {
        suspicious = 1;
    }
    /*
     * Sampled DBI footprint check: if markers are present but sysctl P_TRACED is
     * clear (common under DBI / JIT layers), slow vs fast probes disagree and
     * cprisk_trace_crosscheck_inconsistent() surfaces the evasion pattern.
     */
    if ((seq & 7u) == 0u && cprisk_detect_dbi_markers() > 0) {
        suspicious = 1;
    }

    return suspicious;
}

/// fast/slow 聚合与 streak 维护。
/// - inconsistent 时 streak++，连续 2 次且 slow 路径也可疑时调用
///   cprisk_integrity_poison_antidebug_lane()，让绕过方拿到被污染的结果；
/// - 一致时清零 streak；
/// - Returns: fast 或 slow 任一路径判定，或 streak>=2 时返回 1。
/// - Thread safety: 状态均为 atomic；并发调用可能重复投毒，但语义幂等。
static int cprisk_trace_eval_aggregate_i(void) {
#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    const int fast_traced = cprisk_trace_probe_fast_i();
    const int slow_traced = cprisk_trace_probe_slow_i();
    const int inconsistent = (fast_traced != 0) != (slow_traced != 0);
    uint32_t streak = atomic_load(&s_trace_crosscheck_streak);

    atomic_store(&s_trace_crosscheck_inconsistent, inconsistent ? 1u : 0u);
    if (inconsistent) {
        if (streak != UINT32_MAX) {
            streak += 1u;
        }
        atomic_store(&s_trace_crosscheck_streak, streak);
        if (streak >= 2u && slow_traced != 0) {
            cprisk_integrity_poison_antidebug_lane();
        }
    } else {
        streak = 0u;
        atomic_store(&s_trace_crosscheck_streak, 0u);
    }

    return (fast_traced != 0 || slow_traced != 0 || streak >= 2u) ? 1 : 0;
#else
    return 0;
#endif
}

/// 反调试主入口：执行 fast/slow 聚合。
/// - Returns: 1=疑似调试/注入，0=未发现。查询失败不会单独导致 1。
int cprisk_is_being_traced(void) {
    return cprisk_trace_eval_aggregate_i();
}

/*
 * Redundant export: identical semantics via shared static aggregate to dilute
 * single-symbol hook value (call-sites can alternate without changing logic).
 */
/// 与 cprisk_is_being_traced() 同语义的冗余导出；
/// 多一个调用符号可稀释单点 hook 的价值，调用方可交替使用。
int cprisk_is_being_traced_alt(void) {
    return cprisk_trace_eval_aggregate_i();
}

/// 冗余入口：先看 sysctl 与 Mach 直接信号，再回退到聚合入口。
/// - Returns: 任一直接检查命中返回 1；否则返回 cprisk_is_being_traced_alt()。
int cprisk_is_being_traced_redundant(void) {
    const int traced_sys = cprisk_is_being_traced_sysctl_only();
    const int traced_mach = cprisk_mach_trace_suspicious();
    if (traced_sys != 0 || traced_mach != 0) {
        return 1;
    }
    return cprisk_is_being_traced_alt();
}

/// 校验 deny-attach 是否真正生效，并检测 sysctl 读取结果是否稳定。
/// - 参数：deny_attach_rc / deny_attach_errno 来自调用方的 deny-attach 结果；detail_bits_out 可为 NULL。
/// - 检查：连续 3 次读取自身 kinfo_proc 的 pid/flag 一致性、大小、P_TRACED、
///   第 4 次读取的 PID/P_TRACED 是否漂移，以及 deny-attach 是否返回错误。
/// - Returns: detail_bits 非零返回 1（疑似 hook/绕过或 deny-attach 失效）；rc!=0 直接返回 0。
/// - Thread safety: 无共享状态；sysctl 为只读查询，可并发调用。
int cprisk_deny_attach_effective_verify(int deny_attach_rc, int deny_attach_errno, uint32_t *detail_bits_out) {
    uint32_t detail_bits = 0u;
    if (detail_bits_out != NULL) {
        *detail_bits_out = 0u;
    }
#if CPRISK_DENY_ATTACH_DEVICE_AVAILABLE
    if (deny_attach_rc != 0) {
        return 0;
    }

    struct kinfo_proc a;
    struct kinfo_proc b;
    struct kinfo_proc c;
    struct kinfo_proc libc_shadow;
    size_t sz_a = sizeof(a);
    size_t sz_b = sizeof(b);
    size_t sz_c = sizeof(c);
    size_t sz_libc = sizeof(libc_shadow);
    int mib[4];
    const pid_t self_pid = cprisk_getpid_direct();

    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    memset(&c, 0, sizeof(c));
    memset(&libc_shadow, 0, sizeof(libc_shadow));
    mib[0] = (int)(0x2Au ^ 0x2Bu);          /* CTL_KERN  = 1  */
    mib[1] = (int)(0xF8u ^ 0xF6u);          /* KERN_PROC = 14 */
    mib[2] = (int)(0x55u ^ 0x54u);          /* KERN_PROC_PID = 1 */
    mib[3] = (int)self_pid;

    if (cprisk_sysctl_direct(mib, 4, &a, &sz_a, NULL, 0, NULL) != 0) {
        return 0;
    }
    if (cprisk_sysctl_direct(mib, 4, &b, &sz_b, NULL, 0, NULL) != 0) {
        return 0;
    }
    if (cprisk_sysctl_direct(mib, 4, &c, &sz_c, NULL, 0, NULL) == 0) {
        if (a.kp_proc.p_flag != c.kp_proc.p_flag) {
            detail_bits |= CPRISK_DENY_ATTACH_VERIFY_FLAG_MISMATCH;
        }
        if ((pid_t)c.kp_proc.p_pid != self_pid) {
            detail_bits |= CPRISK_DENY_ATTACH_VERIFY_SELF_PID_MISMATCH;
        }
    }
// 第 4 次读取用于发现 sysctl 返回值在多次调用间漂移（典型 hook 特征），
// 命名沿用历史 "libc_shadow"，实际同样走直调包装。
    int libc_sys_err = 0;
    if (cprisk_sysctl_direct(mib, 4, &libc_shadow, &sz_libc, NULL, 0, &libc_sys_err) == 0) {
        if ((pid_t)libc_shadow.kp_proc.p_pid != (pid_t)a.kp_proc.p_pid ||
            ((libc_shadow.kp_proc.p_flag ^ a.kp_proc.p_flag) & (uint32_t)P_TRACED) != 0u) {
            detail_bits |= CPRISK_DENY_ATTACH_VERIFY_LIBC_DIRECT_DIVERGENCE;
        }
    }

    if (a.kp_proc.p_pid != b.kp_proc.p_pid) {
        detail_bits |= CPRISK_DENY_ATTACH_VERIFY_PID_MISMATCH;
    }
    if (a.kp_proc.p_flag != b.kp_proc.p_flag) {
        detail_bits |= CPRISK_DENY_ATTACH_VERIFY_FLAG_MISMATCH;
    }
    if ((pid_t)a.kp_proc.p_pid != self_pid || (pid_t)b.kp_proc.p_pid != self_pid) {
        detail_bits |= CPRISK_DENY_ATTACH_VERIFY_SELF_PID_MISMATCH;
    }
    if (sz_a != sizeof(a) || sz_b != sizeof(b)) {
        detail_bits |= CPRISK_DENY_ATTACH_VERIFY_SIZE_MISMATCH;
    }
    if (((uint32_t)a.kp_proc.p_flag & (uint32_t)P_TRACED) != 0u ||
        ((uint32_t)b.kp_proc.p_flag & (uint32_t)P_TRACED) != 0u) {
        detail_bits |= CPRISK_DENY_ATTACH_VERIFY_TRACE_FLAG_SET;
    }
// deny-attach 自身返回错误也视为失败/绕过信号，而不只是 sysctl 不一致。
    if (deny_attach_errno != 0) {
        detail_bits |= CPRISK_DENY_ATTACH_VERIFY_LIBC_DIRECT_DIVERGENCE;
    }

    if (detail_bits_out != NULL) {
        *detail_bits_out = detail_bits;
    }
    return detail_bits != 0u ? 1 : 0;
#else
    (void)deny_attach_rc;
    (void)deny_attach_errno;
    return 0;
#endif
}

/// AMFI/code-signing 看门狗探针：采集 csops 状态与 task_for_pid 是否意外成功。
/// - 输出（均可为 NULL，进入时先清零）：
///   - cs_flags_out：csops 返回的 CS_* 位；
///   - get_task_allow_suspect_out：task_for_pid(self) 成功时置 1，暗示具备 get-task-allow 类能力；
///   - amfi_anomaly_bits_out：CS_DEBUGGED、CS_VALID/CS_HARD/CS_KILL 缺失等异常位。
/// - Thread safety: 无共享状态，可并发调用。
/// - Platform: 仅 arm64 iOS 真机分支有实际逻辑；其他平台只清零输出。
void cprisk_amfi_entitlement_watchdog_probe(
    uint32_t *cs_flags_out,
    uint32_t *get_task_allow_suspect_out,
    uint32_t *amfi_anomaly_bits_out
) {
    if (cs_flags_out != NULL) {
        *cs_flags_out = 0u;
    }
    if (get_task_allow_suspect_out != NULL) {
        *get_task_allow_suspect_out = 0u;
    }
    if (amfi_anomaly_bits_out != NULL) {
        *amfi_anomaly_bits_out = 0u;
    }

#if CPRISK_DENY_ATTACH_DEVICE_AVAILABLE
// 旧 SDK 兜底定义；数值与 XNU cs_blobs.h 保持一致，仅本文件使用。
#ifndef CS_VALID
#define CS_VALID 0x00000001u
#endif
#ifndef CS_HARD
#define CS_HARD 0x00000100u
#endif
#ifndef CS_KILL
#define CS_KILL 0x00400000u
#endif
#ifndef CS_DEBUGGED
#define CS_DEBUGGED 0x10000000u
#endif

    uint32_t flags = 0u;
    int cs_err = 0;
    if (cprisk_csops_status_flags(&flags, &cs_err) == 0) {
        if (cs_flags_out != NULL) {
            *cs_flags_out = flags;
        }
        if (amfi_anomaly_bits_out != NULL) {
            if ((flags & CS_DEBUGGED) != 0u) {
                *amfi_anomaly_bits_out |= CPRISK_AMFI_PROBE_CS_DEBUGGED;
            }
            if (flags != 0u && (flags & CS_VALID) == 0u) {
                *amfi_anomaly_bits_out |= CPRISK_AMFI_PROBE_CS_VALID_ABSENT;
            }
            if (flags != 0u && (flags & CS_HARD) == 0u) {
                *amfi_anomaly_bits_out |= CPRISK_AMFI_PROBE_CS_HARD_ABSENT;
            }
            if (flags != 0u && (flags & CS_KILL) == 0u) {
                *amfi_anomaly_bits_out |= CPRISK_AMFI_PROBE_CS_KILL_ABSENT;
            }
        }
    }

    mach_port_t tport = MACH_PORT_NULL;
// 正常第三方 App（无 get-task-allow）对自身调用 task_for_pid 也应失败；
// KERN_SUCCESS 说明存在调试类 entitlement 或能力被暴露到用户态，因此记为可疑。
    const kern_return_t kr = task_for_pid(mach_task_self(), cprisk_getpid_direct(), &tport);
// 成功拿到的端口若不是当前任务端口，需要归还端口权，避免端口权泄漏。
    if (tport != MACH_PORT_NULL && tport != mach_task_self()) {
        (void)mach_port_deallocate(mach_task_self(), tport);
    }

    /*
     * Without get-task-allow, task_for_pid is expected to fail for third-party apps.
     * KERN_SUCCESS implies an entitlement-class capability surfaced to user space.
     */
    if (kr == KERN_SUCCESS) {
        if (get_task_allow_suspect_out != NULL) {
            *get_task_allow_suspect_out = 1u;
        }
    }
#else
    (void)0;
#endif
}
