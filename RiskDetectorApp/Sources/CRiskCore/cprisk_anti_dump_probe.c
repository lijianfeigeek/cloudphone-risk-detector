/*
 * CRiskCore - Anti-Dump Active Defense Probe.
 *
 * Runs a background thread that periodically:
 *   1. Scans VM regions via mach_vm_region for shared/external mappings
 *      (signals vm_read_overwrite injection) and RWX JIT regions (Frida Gum).
 *   2. Checks the loaded dylib list for known injection frameworks
 *      (Frida, Cycript, etc.).
 *   3. On detection, activates deception mode silently so the attacker
 *      does not immediately know they have been flagged.
 */

// 文件职责：后台低频巡检线程，为内存 dump / 注入类攻击提供“活性”信号。
// 四条通道：VM 区段（shared+write、RWX）、无镜像归属的匿名 RX、已加载镜像路径、
//   task_for_pid 计数增量；命中后只向完整性层投毒（staged 或 now），不直接崩溃进程。
// 采样开销：每轮一次全地址空间 vm_region 遍历 + 一次 dyld 镜像枚举 + 一次进程表读取，
//   因此默认 5 秒均值、[2,9] 秒抖动区间；停机最坏延迟约 1 秒（1 秒切片睡眠）。
// 误报抑制：检测结果是“线索”而非判决；RWX 对合法 JIT（JavaScriptCore/WebKit）也会命中，
//   由上层结合 staged 通知与运行模式抑制，不在本文件内做白名单放行。
// 线程模型：start/stop 由 s_probe_mutex 串行化；s_probe_running 为原子标志。

#include "include/CRiskCore.h"
#include "include/cprisk_secure_zero.h"
#include <stdatomic.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

// 巡检线程句柄（joinable，stop 时 join）、生命周期互斥锁。
static pthread_t s_probe_thread;
static pthread_mutex_t s_probe_mutex = PTHREAD_MUTEX_INITIALIZER;
// 原子运行标志：巡检线程与 stop 在不同线程读写，避免用普通 int 造成无限等待。
static _Atomic int s_probe_running;
// 是否已成功创建线程；只在持有 s_probe_mutex 时读写，保证 start 幂等。
static int s_probe_started;
/*
 * Anti-debug review weakness #1: a fixed 5-second interval gave the
 * attacker a stable window to perform a memory dump and clean up before
 * the next scan. The new model treats `s_probe_interval_seconds` as the
 * MEAN of a per-iteration draw clamped to [min, max], so any single
 * window the attacker observes does not predict the next.
 */
// 间隔语义：s_probe_interval_seconds 是“均值”，min/max 是每轮均匀采样的闭区间，
// 由 start 按均值 ± 50% 重新计算，保证攻击者观察到的窗口不可预测下一次。
static int s_probe_interval_seconds = 5;
static int s_probe_interval_min = 2;
static int s_probe_interval_max = 9;
// SplitMix64 状态；0 表示尚未播种，首次使用时用地址 + 单调时钟初始化。
static _Atomic uint64_t s_probe_jitter_state;
#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
// 首次读取的 task_for_pid 累计计数，作为后续增量比较的基线；UINT32_MAX 表示未采样。
static atomic_uint_fast32_t s_task_for_pid_baseline = UINT32_MAX;
#endif

/* Encoded needles: mask = SHA256(le32(domain)||le32(key_id)) — no searchable ASCII literals. */
// 注入框架名不以明文出现：每行 enc 是明文与 SHA-256 掩码循环异或后的密文，
// 运行时才解码到栈缓冲并在比对后清零；行列顺序与 key_id 是二进制契约，不可重排。

/*
 * Probe: scan VM regions for suspicious mappings.
 *
 * Checks:
 *   - Shared or external mappings: may indicate vm_read_overwrite being used.
 *   - RWX (read+write+execute) regions: typical of JIT compilers used by Frida Gum.
 *
 * Returns 0 if clean, -1 if suspicious activity detected.
 */
// 遍历本任务所有 VM 区段：shared+write 可能是 vm_read_overwrite 类外读通道；
// RWX 是 Frida Gum/Substrate 跳板与代码重定位的典型形态。
// 注意：本实现不按镜像路径豁免合法 JIT，因此 JIT/脚本引擎也会命中，
// 这是上层按 staged 通知抑制误报的原因；obj_name 只用于释放端口引用，不参与判定。
// 返回 0 = 本轮未发现；-1 = 发现可疑映射（首个命中即返回，控制开销）。
static int cprisk_scan_vm_regions(void) {
    vm_address_t addr = 0;
    vm_size_t size = 0;

    while (1) {
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj_name;

        kern_return_t kr = vm_region_64(
            mach_task_self(),
            &addr,
            &size,
            VM_REGION_BASIC_INFO_64,
            (vm_region_info_t)&info,
            &count,
            &obj_name);

        if (kr != KERN_SUCCESS)
            break;

        /* Shared+write mappings are suspicious for injected dump channels.
         * Plain read-only shared mappings are common for normal dylibs. */
        if (info.shared && (info.protection & VM_PROT_WRITE)) {
            if (obj_name != MACH_PORT_NULL)
                mach_port_deallocate(mach_task_self(), obj_name);
            return -1;
        }

        /* RWX regions are highly suspicious in a non-JIT application.
         * Frida Gum, Substrate, and similar frameworks allocate RWX memory
         * for their trampoline stubs and code relocation. */
        if ((info.protection & VM_PROT_EXECUTE) &&
            (info.protection & VM_PROT_WRITE)) {
            /* Also require that the region is not in a system framework bundle,
             * which legitimately uses JIT for JavaScriptCore/WebKit. */
            if (obj_name != MACH_PORT_NULL)
                mach_port_deallocate(mach_task_self(), obj_name);
            return -1;
        }

        if (obj_name != MACH_PORT_NULL)
            mach_port_deallocate(mach_task_self(), obj_name);

        if (size == 0 || addr > UINTPTR_MAX - size)
            break;
        addr += size;
    }
    return 0;
}

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
// 读取本任务的 TASK_EXTMOD_INFO，统计外部 task_for_pid 调用次数。
// 首次只建立基线；之后允许比基线多 1 次（系统/调试工具的正常噪声），
// 超过才报可疑。task_info 失败返回 0（看不到不等于异常）。
static int cprisk_probe_task_for_pid_escalation(void) {
    task_extmod_info_data_t extmod;
    mach_msg_type_number_t cnt = TASK_EXTMOD_INFO_COUNT;
    memset(&extmod, 0, sizeof(extmod));
    if (task_info(mach_task_self(), TASK_EXTMOD_INFO, (task_info_t)&extmod, &cnt) != KERN_SUCCESS)
        return 0;
    uint32_t cur = (uint32_t)extmod.extmod_statistics.task_for_pid_count;
    uint32_t base = atomic_load(&s_task_for_pid_baseline);
    if (base == UINT32_MAX) {
        atomic_store(&s_task_for_pid_baseline, cur);
        return 0;
    }
    if (cur > base + 1u)
        return -1;
    return 0;
}
#endif

/*
 * SplitMix64 — local PRNG seeded from the static address of the probe
 * thread + first cycle's monotonic clock, so each process's window
 * schedule is unique. Not cryptographic; the goal is to deny the
 * attacker a deterministic time-of-next-scan oracle, not key material.
 */
// SplitMix64 取下一个伪随机数；播种材料含本进程地址与单调时钟，
// 使不同进程/不同启动时刻的窗口序列不同。非密码学用途，只用于时间不可预测性。
static uint64_t cprisk_probe_jitter_next_i(void) {
    uint64_t s = atomic_load(&s_probe_jitter_state);
    if (s == 0u) {
        struct timespec ts;
        if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
            ts.tv_sec = (time_t)time(NULL);
            ts.tv_nsec = 0;
        }
        s = (uint64_t)((uintptr_t)&s_probe_jitter_state) ^
            ((uint64_t)ts.tv_sec << 32) ^ (uint64_t)ts.tv_nsec ^
            0x9E3779B97F4A7C15ull;
        if (s == 0u) s = 0xA5A55A5A5A5AA5A5ull;
        atomic_store(&s_probe_jitter_state, s);
    }
    s += 0x9E3779B97F4A7C15ull;
    uint64_t z = s;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    atomic_store(&s_probe_jitter_state, s);
    return z ^ (z >> 31);
}

/* Per-cycle interval drawn uniformly from [min, max]. Sub-second jitter
 * (0..999 ms) is folded in via an extra nanosleep so even when the mean
 * is small, two consecutive cycles never have identical timing. */
// 在 [min, max] 上均匀取一个整数秒；min/max 已由 start 夹紧到 >=1 且 hi>=lo，
// 这里仍做防御性修正，防止运行期被写坏后出现除零/负数取模。
static int cprisk_probe_pick_interval_i(void) {
    int lo = s_probe_interval_min;
    int hi = s_probe_interval_max;
    if (lo < 1) lo = 1;
    if (hi < lo) hi = lo;
    uint64_t span = (uint64_t)(hi - lo) + 1u;
    uint64_t r = cprisk_probe_jitter_next_i();
    return (int)((r % span) + (uint64_t)lo);
}

// 可取消睡眠：按 1 秒切片检查运行标志，把 stop() 的最坏等待压到约 1 秒；
// 末尾再叠加 0..999ms 的亚秒抖动，使“等满固定整秒再 dump”的启发式失效。
static void cprisk_probe_sleep_cancelable(int total_seconds) {
    if (total_seconds <= 0)
        total_seconds = 1;
    while (s_probe_running && total_seconds-- > 0) {
        struct timespec req;
        req.tv_sec = 1;
        req.tv_nsec = 0;
        (void)nanosleep(&req, NULL);
    }
    /* Sub-second tail jitter (0..999ms) — defeats the "wait full interval
     * then dump" heuristic that fixed-second cadences expose. */
    if (s_probe_running) {
        uint64_t r = cprisk_probe_jitter_next_i();
        long ns = (long)(r % 1000000000ull);
        struct timespec tail;
        tail.tv_sec = 0;
        tail.tv_nsec = ns;
        (void)nanosleep(&tail, NULL);
    }
}

/*
 * Probe: check loaded dylibs for suspicious names.
 *
 * Uses _dyld_image_count / _dyld_get_image_name to enumerate all loaded
 * images and compares each name against a list of known injection-framework
 * patterns. This catches library-level injection even when the process
 * name or VM layout has been obscured.
 *
 * Returns 0 if clean, -1 if injection indicators found.
 */
// 枚举已加载镜像路径，对每个路径尝试匹配 9 个混淆后的注入框架关键字。
// 每个关键字解码到 64 字节栈缓冲（长度不足则跳过该行），比对后立即清零；
// 解码失败按“该关键字不可用”跳过（fail-open），不影响其余关键字。
// 返回 0 = 未命中；-1 = 命中任一关键字。
static int cprisk_check_dylib_injection(void) {
    static const uint8_t e1[] = {0x1c, 0x19, 0x59, 0x9c, 0x06};
    static const uint8_t e2[] = {0xd6, 0xb9, 0x49, 0xc2, 0x2e, 0xf2, 0xf5};
    static const uint8_t e3[] = {
        0x7b, 0x7b, 0x67, 0x7e, 0xb9, 0x56, 0x09, 0x94, 0x3b, 0xc7, 0x6c, 0x87, 0xe4, 0xd0, 0x3b, 0xdd,
        0x04, 0xfd, 0x8a, 0xfc, 0xc4, 0x2d, 0xca, 0x3f, 0x42, 0x75, 0xa5, 0x00, 0xec, 0x85};
    static const uint8_t e4[] = {
        0xdf, 0x08, 0x81, 0x02, 0x5f, 0xd3, 0x19, 0xb6, 0x43, 0x55, 0x2c, 0x16, 0xe5};
    static const uint8_t e5[] = {0x48, 0xb9, 0xc0, 0xdd, 0xee, 0xd7, 0xb2, 0x44, 0x40};
    static const uint8_t e6[] = {0xf7, 0xcf, 0x9e, 0xcc, 0x3c, 0x38, 0x9d, 0x67, 0x8d};
    static const uint8_t e7[] = {
        0xe8, 0x33, 0x91, 0xf5, 0x71, 0x5a, 0x07, 0x60, 0xe4, 0x14, 0x44, 0x46};
    static const uint8_t e8[] = {
        0xc7, 0xac, 0x23, 0x8f, 0x8d, 0xac, 0x3a, 0xfd, 0x3a, 0x84, 0x02};
    static const uint8_t e9[] = {0x98, 0xea, 0x5a, 0x26, 0xaf, 0x89, 0x79, 0x67, 0x6c, 0x30};
    static const struct {
        uint32_t key_id;
        const uint8_t *enc;
        size_t enc_len;
    } rows[] = {
        {1u, e1, sizeof(e1)},
        {2u, e2, sizeof(e2)},
        {3u, e3, sizeof(e3)},
        {4u, e4, sizeof(e4)},
        {5u, e5, sizeof(e5)},
        {6u, e6, sizeof(e6)},
        {7u, e7, sizeof(e7)},
        {8u, e8, sizeof(e8)},
        {9u, e9, sizeof(e9)},
    };
    const uint32_t D = CPRISK_OBF_TAG_DOMAIN_ANTI_DUMP;

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name)
            continue;
        for (size_t j = 0; j < sizeof(rows) / sizeof(rows[0]); j++) {
            char buf[64];
            if (rows[j].enc_len + 1u > sizeof(buf)) {
                continue;
            }
            if (cprisk_obf_decode_sha256_tag(
                    D,
                    rows[j].key_id,
                    rows[j].enc,
                    rows[j].enc_len,
                    buf,
                    sizeof(buf)) != 0) {
                continue;
            }
            if (strstr(name, buf) != NULL) {
                cprisk_secure_zero(buf, sizeof(buf));
                return -1;
            }
            cprisk_secure_zero(buf, sizeof(buf));
        }
    }
    return 0;
}

/*
 * Background probe loop.
 *
 * Sleeps for s_probe_interval_seconds between scans. When a detector
 * fires, it activates deception mode (sets s_integrity_deception_active)
 * rather than crashing immediately, which avoids alerting the attacker
 * to the presence of this probe thread.
 *
 * Runs as a joinable thread so stop() can block until the probe exits,
 * avoiding leaked thread resources across repeated start/stop cycles.
 */
// 巡检主循环：每轮先睡一个抖动区间，再按“VM → 匿名 RX → 镜像路径 → task_for_pid”
// 顺序检查。前三条通道用 staged 投毒（延后生效，避免打草惊蛇），
// 镜像路径命中是强证据，用 now 立即投毒；任一命中后跳过本轮剩余检查。
// 线程返回 NULL，由 stop 通过 pthread_join 回收。
static void *cprisk_probe_main(void *arg) {
    (void)arg;
    while (s_probe_running) {
        /* Per-cycle jittered interval — defeats the fixed 5s window. */
        cprisk_probe_sleep_cancelable(cprisk_probe_pick_interval_i());
        if (!s_probe_running)
            break;

        if (cprisk_scan_vm_regions() != 0) {
            cprisk_integrity_poison_anti_dump_lane();
            continue;
        }

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
        /*
         * Second track: private anonymous RX outside any Mach-O image (Stalker/Gum trace slabs).
         * Stronger than generic RWX-only heuristics when DBI has transitioned to W^X.
         */
        if (cprisk_vm_probe_anonymous_exec_outside_images() != 0) {
            cprisk_integrity_poison_anti_dump_lane();
            continue;
        }
#endif

        if (cprisk_check_dylib_injection() != 0) {
            cprisk_integrity_poison_anti_dump_lane_now();
            continue;
        }

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
        if (cprisk_probe_task_for_pid_escalation() != 0) {
            cprisk_integrity_poison_anti_dump_lane();
            continue;
        }
#endif
    }
    return NULL;
}

/*
 * Start the anti-dump probe thread.
 *
 * interval_seconds: polling interval in seconds (minimum 1). Pass 0 to keep
 * the default (5 seconds). The thread is idempotent: repeated start calls
 * while running only refresh the interval.
 *
 * Returns 0 on success, -1 on thread creation failure.
 */
// 启动巡检线程（幂等）：重复调用只更新间隔参数，不创建第二个线程。
// interval_seconds <= 0 时保持原均值；均值会换算成 [mean-half, mean+half]
// 并夹到 [1, 30] 秒，保证最坏间隔不会大到失去检测意义。
// 返回 0 = 已运行/创建成功；-1 = pthread_create 失败（运行标志已回滚）。
int cprisk_start_anti_dump_probe(int interval_seconds) {
    pthread_mutex_lock(&s_probe_mutex);

    /* Recompute the per-cycle [min, max] band whenever the caller
     * supplies a new mean. The band is mean ± ~50%, clamped to [1, 30s].
     * This makes 5s default span [2, 9]; 10s span [5, 16]; etc. */
    if (interval_seconds > 0) {
        s_probe_interval_seconds = interval_seconds;
    }
    if (s_probe_interval_seconds <= 0)
        s_probe_interval_seconds = 5;

    int half = s_probe_interval_seconds / 2;
    if (half < 1) half = 1;
    s_probe_interval_min = s_probe_interval_seconds - half;
    s_probe_interval_max = s_probe_interval_seconds + half;
    if (s_probe_interval_min < 1) s_probe_interval_min = 1;
    if (s_probe_interval_max > 30) s_probe_interval_max = 30;

    if (s_probe_started) {
        pthread_mutex_unlock(&s_probe_mutex);
        return 0;
    }

    s_probe_running = 1;
    int rc = pthread_create(&s_probe_thread, NULL, cprisk_probe_main, NULL);
    if (rc != 0) {
        s_probe_running = 0;
        pthread_mutex_unlock(&s_probe_mutex);
        return -1;
    }

    s_probe_started = 1;
    pthread_mutex_unlock(&s_probe_mutex);
    return 0;
}

/*
 * Stop the anti-dump probe thread.
 *
 * Sets the volatile flag and lets the sleep() expire naturally.
 * Safe to call even if the thread was never started.
 */
// 停止并 join 巡检线程；未启动时安全返回。
// 先在锁内取走线程句柄并清 started，再在锁外 join，避免持锁等待整轮扫描。
// 最坏等待约 1 秒（睡眠切片）加上当前扫描耗时。
void cprisk_stop_anti_dump_probe(void) {
    pthread_t thread_to_join;

    pthread_mutex_lock(&s_probe_mutex);
    if (!s_probe_started) {
        s_probe_running = 0;
        pthread_mutex_unlock(&s_probe_mutex);
        return;
    }
    s_probe_running = 0;
    thread_to_join = s_probe_thread;
    s_probe_started = 0;
    pthread_mutex_unlock(&s_probe_mutex);

    (void)pthread_join(thread_to_join, NULL);
}
