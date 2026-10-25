// 反调试看门狗：两个后台 worker 以 300ms±100ms 抖动周期轮询调试/注入证据，汇总到全局快照，
// 供 Swift 判决层读取；高置信证据会向完整性模块投毒（staged 或立即提交）。
// 线程模型：pthread 双 worker；全局状态由 s_watchdog_mutex 保护，读侧使用原子变量；
//   快照按值拷贝，读到的是“最近一次完成的迭代”，不是实时状态。
// 平台：仅 iOS arm64/arm64e 真机编译；模拟器/tvOS/watchOS 走文件末尾的 fail-open stub。
// 失败语义：探测本身失败默认 fail-open（只留诊断位）；启动期序言/PAC 校验失败 fail-closed，
//   返回 -1 并留下异常位；高置信异常经 poison/hard-crash 分支 fail-closed。
#include "include/CRiskCore.h"
#include "include/cprisk_dlsym.h"
#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_sync_barrier.h"
#include "include/cprisk_secure_zero.h"
#include "include/cprisk_memory_guard.h"
#include "cprisk_cff.h"

#include <TargetConditionals.h>
#include <errno.h>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <objc/message.h>

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__)) && \
    (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR) && \
    (!defined(TARGET_OS_TV) || !TARGET_OS_TV) && \
    (!defined(TARGET_OS_WATCH) || !TARGET_OS_WATCH)

// 双 worker 设计：主 worker 跑完整检测，副 worker 做轻量交叉采样并监视 peer 存活；
// 任意一个被调试器挂起时，另一个仍能置位 WATCHDOG_PEER_STALL。
#define CPRISK_WATCHDOG_THREAD_COUNT 2u
#define CPRISK_WATCHDOG_PRIMARY_ID 0u
#define CPRISK_WATCHDOG_SECONDARY_ID 1u
// 基线轮询周期 300ms，±100ms 抖动；抖动让 hook 难以预测下一次扫描窗口。
#define CPRISK_WATCHDOG_DEFAULT_INTERVAL_MS 300u
#define CPRISK_WATCHDOG_INTERVAL_JITTER_MS 100u
// 中频检测（硬件断点/csops/时序等）每 3 轮一次，低频检测（tty/开发者磁盘等）每 9 轮一次；
// 一旦上一轮已有异常，中频检查改为每轮都跑，以便尽快确认。
#define CPRISK_WATCHDOG_MID_CADENCE 3u
#define CPRISK_WATCHDOG_LOW_CADENCE 9u
// 已检出异常时缩短到 150–400ms，加快二次确认；下限防止把 CPU 打满。
#define CPRISK_WATCHDOG_SHORT_INTERVAL_MIN_MS 150u
#define CPRISK_WATCHDOG_SHORT_INTERVAL_MAX_MS 400u
// sleep 切成 100ms 片，保证 stop 请求最多 100ms 内被响应，而不是等完整轮询周期。
#define CPRISK_WATCHDOG_SLEEP_SLICE_NS 100000000L
// 固定窗口扫描长度：覆盖每个关键函数的典型序言/前导块。
#define CPRISK_WATCHDOG_SOFTWARE_BP_SCAN_BYTES 256u
/*
 * Anti-debug review weakness #3: previously 8×768=6 KiB sampled per
 * cycle was easy to evade — an attacker placing a single BRK in a
 * function outside the sampled windows had ~99% chance of escaping.
 *
 * Bumped to 24×1024=24 KiB sampled per cycle. With the watchdog cadence
 * of 300ms±100ms, a function-sized region (< 1 KiB on average) is
 * fully covered within ~10 minutes of session uptime in expectation.
 * Combined with the fixed-set scans above (callable list at lines
 * 929–944) which always run, the probability of a single-BRK ambush
 * surviving 60 watchdog cycles is < 1%.
 */
// 随机采样预算：每轮 24 个窗口×1024B；固定窗口 + 随机窗口共同把“单点 BRK 长期不被发现”
// 的概率压到很低（具体推导见上方英文说明）。
#define CPRISK_WATCHDOG_RANDOM_TEXT_WINDOWS 24u
#define CPRISK_WATCHDOG_RANDOM_TEXT_WINDOW_BYTES 1024u
// 单轮累计命中 >=4 才判 SOFTWARE_BP，避免把系统库里的合法 BRK/反汇编字节当成攻击。
#define CPRISK_WATCHDOG_SOFTWARE_BP_STRONG_THRESHOLD 4
// peer 停滞的绝对下限 3.5s：短于此的抖动（调度延迟、GC、锁竞争）不判异常。
#define CPRISK_WATCHDOG_PEER_STALL_MIN_NS 3500000000ull
// start 后最多等 800ms 让 worker 完成首轮；超时才置 STARTUP_LIVENESS。
#define CPRISK_WATCHDOG_START_GRACE_NS 800000000ull
// 主线程心跳超过 10s 未刷新视为 runloop 被阻塞/挂起；需连续 2 次主 worker 观察确认，
// 避免恰好跨过阈值的边界抖动造成误报。
/** Main-thread runloop must refresh faster than this after the first ping (ns). */
#define CPRISK_WATCHDOG_MAIN_THREAD_STALL_NS 10000000000ull
/** Consecutive primary-loop observations with stale heartbeat before latch (reduces boundary races). */
#define CPRISK_WATCHDOG_MAIN_THREAD_STALL_CONFIRM_TICKS 2u
// watchdog_start_path_mask 低 8 位记录主 worker 的启动路径（thunk/bridge/impl），
// 高 8 位记录副 worker；用于诊断 PAC 降级路径是否被攻击者逼迫。
#define CPRISK_WATCHDOG_PATH_THUNK (1u << 0)
#define CPRISK_WATCHDOG_PATH_BRIDGE (1u << 1)
#define CPRISK_WATCHDOG_PATH_IMPL (1u << 2)
#define CPRISK_WATCHDOG_PATH_SECONDARY_SHIFT 8u
// 每个 PAC 候选最多重试 10 次、间隔 100ms：吸收 EAGAIN 与攻击者的 pthread_create 拦截，
// 又不至于在失败路径上长时间忙等。
/* Retry budget for watchdog thread creation: up to CREATE_RETRY_MAX additional attempts per
 * PAC-signed candidate after the first failure.  Absorbs transient EAGAIN (resource depletion)
 * and attacker-induced pthread_create hook/block without busy-spinning the CPU.
 * Pattern mirrors DexHelper's 30-attempt loop but uses shorter inter-attempt sleep. */
#define CPRISK_WATCHDOG_CREATE_RETRY_MAX 10u
#define CPRISK_WATCHDOG_CREATE_RETRY_SLEEP_NS 100000000L  /* 100 ms between retries */

// 立即投毒集合：高置信、且误报代价可接受（或已在别处做抑制）的证据。命中后走
// cprisk_integrity_poison_high_signal_mixed()，不做 staged 升级。
// 注意：VM_IMAGE_WHITELIST 被刻意排除（见下方英文说明），只走 staged 路径。
/* Integrity poison: high-confidence anomalies use immediate lane commit; the bundled weaker
 * probe hits in the primary iteration use staged escalation (see cprisk_integrity.c). */
/* VM_IMAGE_WHITELIST is intentionally excluded from the HIGH_RISK mask: generic
 * image-layout drift caused by crash-reporter / push-notification SDK late-loading
 * is a major production FP source.  It is handled via cprisk_integrity_poison_watchdog_lane()
 * (staged) in the early per-iteration detection block.  Only name-matched jailbreak
 * tools (DYLD_INJECTION) retain zero-tolerance immediate commit. */
#define CPRISK_WD_HIGH_RISK_POISON_MASK \
    (CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_PORT | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED_PROBE_DIVERGENCE | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH_VERIFY | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_AMFI_CS_FLAGS | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GET_TASK_ALLOW | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DYLD_INJECTION | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SVC_STUB_INTEGRITY | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_MPROTECT_MACH_DIVERGENCE | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_VM_TRACE_CORREL | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_PAC_THREAD_ENTRY)

// staged 投毒集合：与 HIGH_RISK 有重叠，但通过 poison_watchdog_lane() 做分级升级；
// 主要用于“单条证据不够硬、但组合出现即高度可疑”的场景。
#define CPRISK_WD_POISON_TRIGGER_BUNDLE_MASK \
    (CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SIGNAL_PROBE | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SOFTWARE_BP | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_INSTANT_RETURN_PATCH | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_HARDWARE_BP | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_CSOPS_DEBUGGED | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_MARKER | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TIMING_SIDECHANNEL | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_DELIVERY_TIMEOUT | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SHADOW_STACK | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DYLD_INJECTION | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED_PROBE_DIVERGENCE | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH_VERIFY | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_AMFI_CS_FLAGS | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GET_TASK_ALLOW | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SVC_STUB_INTEGRITY | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_MPROTECT_MACH_DIVERGENCE | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_VM_TRACE_CORREL)

// Debug 构建的响应抑制开关：默认压制投毒/硬崩溃，但异常位照常采集供诊断；
// 设置环境变量 CPRISK_TEST_HARDENING=1 可恢复与 Release 相同的完整响应。
// Release 下宏展开为常量 0，优化器会完全消除判断，零开销。
/*
 * Debug-only runtime bypass for the hardening response path.
 *
 * Goal: let developers run normal Xcode debug sessions (with debugger attached,
 * GET_TASK_ALLOW entitlement, Frida installed for side research, etc.) without
 * being silently killed by the anti-debug poison, WHILE still allowing them to
 * exercise and verify the full hardening response when they explicitly want to
 * test it.
 *
 * Behaviour:
 *   Release build (CPRISK_WD_POISON_SUPPRESSED() == 0 always):
 *     - Compile-time constant 0; the optimiser fully elides the branch.
 *     - Hardening response is always active; zero overhead over the previous
 *       unconditional call.
 *
 *   Debug build:
 *     - CPRISK_WD_POISON_SUPPRESSED() consults the environment variable
 *       CPRISK_TEST_HARDENING (cached on first read).
 *     - Default (variable unset or "0"): returns 1 → poison is suppressed →
 *       the developer can debug freely; anomaly_flags are still collected and
 *       visible through cprisk_get_watchdog_snapshot() for diagnostics.
 *     - CPRISK_TEST_HARDENING=1 (or y/Y/t/T): returns 0 → full hardening
 *       response is active, exactly as it would be in Release.  Use this mode
 *       in Xcode scheme environment variables when verifying that the
 *       poison lanes, CFF explosion, hard-crash switch, etc. actually fire.
 *
 * The helper is declared here so every watchdog detection path that wants to
 * suppress its response just needs one call: `if (!CPRISK_WD_POISON_SUPPRESSED())`.
 */
// 返回 1 表示应抑制毒化响应；仅 Debug 构建存在。首次读取环境变量后缓存，
// 之后不再 getenv，避免热路径依赖可能被 hook 的 libc。
#if (defined(DEBUG) && DEBUG)
static int cprisk_watchdog_dev_bypass_poison_i(void) {
    static int s_cached = -1;
    if (s_cached >= 0) {
        return s_cached;
    }
    const char *e = getenv("CPRISK_TEST_HARDENING");
    if (e != NULL &&
        (e[0] == '1' || e[0] == 'y' || e[0] == 'Y' || e[0] == 't' || e[0] == 'T')) {
        s_cached = 0;  /* developer opted in → full hardening response active */
    } else {
        s_cached = 1;  /* default in debug → bypass so normal dev workflow works */
    }
    return s_cached;
}
// 统一入口：所有响应路径只判断这一个宏，避免各处重复拼环境变量逻辑。
#define CPRISK_WD_POISON_SUPPRESSED() (cprisk_watchdog_dev_bypass_poison_i() != 0)
#else
// Release/非 Debug：常量 0，表示永不抑制，保证线上始终执行完整响应。
#define CPRISK_WD_POISON_SUPPRESSED() (0)
#endif

// 看门狗状态机：STOPPED→RUNNING→STOPPING→STOPPED；只允许持 s_watchdog_mutex 迁移。
// start 是幂等的：非 STOPPED 时直接返回 0；stop 只对 RUNNING 发起停止，避免重复 join。
enum {
    CPRISK_WATCHDOG_STATE_STOPPED = 0,
    CPRISK_WATCHDOG_STATE_RUNNING = 1,
    CPRISK_WATCHDOG_STATE_STOPPING = 2,
};

// shadow stack 令牌：进入一轮迭代时把返回地址/帧地址混合成一个值，迭代结束前复算；
// 仅用于发现“同一轮内栈帧被改写”的高置信迹象，不替代完整栈保护。
typedef struct cprisk_shadow_token {
    uintptr_t value;
} cprisk_shadow_token_t;

// 全局互斥锁：s_watchdog_snapshot、状态机、线程句柄与 mailbox 端口的写入都必须持锁；
// 检测路径只做短临界区更新，不持锁执行 I/O 或探测。
static pthread_mutex_t s_watchdog_mutex = PTHREAD_MUTEX_INITIALIZER;
// 线程句柄数组按 worker_id 索引；持锁写入（start）或持锁拷贝（stop），join 在解锁后执行。
static pthread_t s_watchdog_threads[CPRISK_WATCHDOG_THREAD_COUNT];
// bit i 表示第 i 个 worker 曾成功创建、需要 join；未创建的 worker 不能 join。
static uint32_t s_watchdog_started_mask = 0u;
// 状态机取值见 CPRISK_WATCHDOG_STATE_*，只允许持锁迁移。
static int s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPED;
// stop 请求用原子变量发布，worker 在轮回开始/结束及 sleep 分片时轮询，保证及时退出。
static atomic_int s_watchdog_stop_requested = 0;
// worker_active=1 表示 worker 已进入主循环；heartbeat 是最近一次循环的单调时间（ns），
// deadline 是本轮预算的绝对截止时间（ns）；均按 worker_id 索引，0 表示未知/未运行。
static atomic_uint_fast32_t s_watchdog_worker_active[CPRISK_WATCHDOG_THREAD_COUNT];
static atomic_uint_fast64_t s_watchdog_heartbeat_ns[CPRISK_WATCHDOG_THREAD_COUNT];
static atomic_uint_fast64_t s_watchdog_deadline_ns[CPRISK_WATCHDOG_THREAD_COUNT];
// xorshift PRNG 的全局状态；用 CAS 推进，多个 worker 并发取随机数不会退化或重复。
static atomic_uint_fast64_t s_watchdog_prng_state = 0u;
// 一次性闩锁：副 worker 或 mailbox 发现 peer 异常时置位，主 worker 下一轮用 atomic_exchange 消费；
// 跨线程证据因此不会因某一轮未采样而丢失。
static atomic_uint_fast32_t s_watchdog_peer_stall_latch = 0u;
static atomic_uint_fast32_t s_watchdog_shadow_stack_latch = 0u;
// mailbox 消息：每个 worker 有独立接收端口，向 peer 发送“我还活着”的心跳与单调序号。
typedef struct {
    mach_msg_header_t header;
    uint32_t worker_id;
    uint32_t sequence;
} cprisk_watchdog_mailbox_msg_t;
// 每个 worker 的接收端口；初始化失败时保持 MACH_PORT_NULL，后续 peer 校验全部跳过（fail-open）。
static mach_port_t s_watchdog_mailbox_ports[CPRISK_WATCHDOG_THREAD_COUNT];
// 最近一次收到 peer mailbox 的时间（ns）；与共享 heartbeat 取较新者判断停滞。
static atomic_uint_fast64_t s_watchdog_mailbox_last_recv_ns[CPRISK_WATCHDOG_THREAD_COUNT];
// 发送序号只由所属 worker 线程递增，故用普通 uint32_t；peer 侧通过序号回退/重复检测重放与伪造。
static uint32_t s_watchdog_mailbox_send_seq[CPRISK_WATCHDOG_THREAD_COUNT];
// mailbox_ready=0 时所有收发与 peer 校验短路，避免半初始化状态产生误报。
static atomic_uint_fast32_t s_watchdog_mailbox_ready = 0u;
static atomic_uint_fast32_t s_watchdog_mailbox_last_peer_seq[CPRISK_WATCHDOG_THREAD_COUNT];
static atomic_uint_fast32_t s_watchdog_mailbox_peer_seq_initialized[CPRISK_WATCHDOG_THREAD_COUNT];

// 每个受监控函数只比对前 16 字节（典型 arm64 序言长度）：足够发现 trampoline/立即返回补丁，
// 又避免把合法的长序言差异误判。
#define CPRISK_WATCHDOG_PROLOGUE_BYTES 16u
/*
 * Monitored symbols: VM/trace/whitebox/deny-attach/signal probe/JIT decrypt/recrypt +
 * watchdog entry wrappers + exception delivery / signal aggregation / import + armor
 * closure paths whose patching can disable the anti-debug chain while leaving the
 * rest of the runtime alive.
 */
// 固定监控 18 个入口：VM/白盒/deny_attach/SVC/信号探测/JIT/异常处理器/导入解析等。
// 任一被 patch 都可能让反调试链路整体失效；顺序必须与 fill_prologue_addrs_i 一致，
// 因为 last_prologue_fail_mask 的低位直接对应数组下标。
#define CPRISK_WATCHDOG_PROLOGUE_SLOTS 18u
/*
 * pthread_create start_routine uses a small thunk so the exported pthread entry is not the
 * watchdog body address. The real worker is reached via PAC-signed (arm64e) or volatile
 * indirection. Peer-liveness is additionally carried over per-worker Mach receive ports,
 * so the stall detector does not rely only on shared-memory heartbeats.
 */
// PAC 区分符（discriminator）必须在签名/认证两端一致；不一致会导致认证失败并置位
// PAC_THREAD_ENTRY，语义上等价于线程入口指针被替换。
/* Intermediate bridge between pthread thunk and worker body (LE: "CPRISKBR") — PAC hop before main_impl. */
#define CPRISK_WATCHDOG_PTHREAD_BRIDGE_PAC_DISC 0x43505249534B4252ULL
/* arm64e: pthread start_routine uses PAC-signed pointer to the thunk (not raw __TEXT address). */
#define CPRISK_WATCHDOG_PTHREAD_THUNK_PAC_DISC 0x43505249534B5448ULL
// last_prologue_fail_mask 的高位扩展位：bit31..bit27 依次对应 libsystem pthread_create、
// libsystem dlsym、objc_msgSend、_dyld_image_count 与内联运行时门禁；低 18 位对应固定槽位。
// 这些位只由 watchdog 置位、由快照消费者读取；下次 start 时随快照清零。
/* Bit in last_prologue_fail_mask when libsystem pthread_create prologue mismatches baseline. */
#define CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_PTHREAD_CREATE (1u << 31)
/* Bit when libsystem/libdyld dlsym (import resolve chain) prologue mismatches baseline. */
#define CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_DLSYM (1u << 30)
/* objc_msgSend (libobjc) — Frida / method swizzling hook surface. */
#define CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_OBJC_MSGSEND (1u << 29)
/* _dyld_image_count — libdyld enumeration entry used by image scans / hook tools. */
#define CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_DYLD_IMAGE_COUNT (1u << 28)
/* Inline runtime-gate BRK sites drifted or became writable after arming. */
#define CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_INLINE_GATE (1u << 27)

// 基线快照：s_*_ref 在 constructor 早期捕获（攻击者尚未有机会装 hook），是“出厂参考”；
// s_*_last_ok 记录上一轮通过校验的字节，用于发现同一进程内的二次漂移。
// valid 原子标志避免把未初始化的 last_ok 当作漂移证据。
static uint8_t s_watchdog_prologue_ref[CPRISK_WATCHDOG_PROLOGUE_SLOTS][CPRISK_WATCHDOG_PROLOGUE_BYTES];
// 固定槽位的上一轮基线；与 ref 双重比对可区分“启动前就被 hook”和“运行中被 hook”。
/* Previous-iteration snapshot for intra-run drift detection (cross-check vs ctor baseline). */
static uint8_t s_watchdog_prologue_last_ok[CPRISK_WATCHDOG_PROLOGUE_SLOTS][CPRISK_WATCHDOG_PROLOGUE_BYTES];
static atomic_uint_fast32_t s_watchdog_prologue_last_ok_valid = 0u;
// libsystem / libobjc / libdyld 入口的独立基线；这些入口常被 Frida、method swizzling、
// 镜像枚举工具替换，单独维护便于把失败归因到具体 hook 面。
static uint8_t s_watchdog_pthread_create_ref[CPRISK_WATCHDOG_PROLOGUE_BYTES];
static uint8_t s_watchdog_pthread_create_last_ok[CPRISK_WATCHDOG_PROLOGUE_BYTES];
static atomic_uint_fast32_t s_watchdog_pthread_create_last_ok_valid = 0u;
static uint8_t s_watchdog_dlsym_ref[CPRISK_WATCHDOG_PROLOGUE_BYTES];
static uint8_t s_watchdog_dlsym_last_ok[CPRISK_WATCHDOG_PROLOGUE_BYTES];
static atomic_uint_fast32_t s_watchdog_dlsym_last_ok_valid = 0u;
static uint8_t s_watchdog_objc_msgsend_ref[CPRISK_WATCHDOG_PROLOGUE_BYTES];
static uint8_t s_watchdog_objc_msgsend_last_ok[CPRISK_WATCHDOG_PROLOGUE_BYTES];
static atomic_uint_fast32_t s_watchdog_objc_msgsend_last_ok_valid = 0u;
static uint8_t s_watchdog_dyld_image_count_ref[CPRISK_WATCHDOG_PROLOGUE_BYTES];
static uint8_t s_watchdog_dyld_image_count_last_ok[CPRISK_WATCHDOG_PROLOGUE_BYTES];
static atomic_uint_fast32_t s_watchdog_dyld_image_count_last_ok_valid = 0u;
// prologue_captured：一次性基线捕获标志；dyld_suspicious_events 为注入事件累计；
// dyld_flags 为命中工具名的位集合；dyld_registered 保证 add-image 回调只注册一次。
static atomic_uint_fast32_t s_watchdog_prologue_captured = 0u;
static atomic_uint_fast64_t s_watchdog_dyld_suspicious_events = 0u;
static atomic_uint_fast32_t s_watchdog_dyld_flags = 0u;
static atomic_uint_fast32_t s_watchdog_dyld_registered = 0u;

// 跨模块依赖：由 VM/异常处理器/文本加密/完整性模块导出。这里只声明不定义，
// 便于 watchdog 在不反向包含其实现头的情况下调用。
extern uint64_t cprisk_get_last_exception_delivery_probe_ns(void);
extern void cprisk_text_encrypt_service_idle(void);
extern uint32_t cprisk_antidebug_inline_gate_health_mask(void);
extern int cprisk_vm_execute(uint64_t func_id, cprisk_vm_run_result_t *out);
extern int cprisk_whitebox_evaluate_domain(
    uint32_t domain_id,
    const uint8_t input[32],
    uint8_t out[32]
);
extern int cprisk_get_last_exception_delivery_probe_handled(void);
extern int cprisk_text_jit_decrypt(void *fault_addr);
extern cprisk_vm_flow_t cprisk_vm_dispatch_leaf_wb_wrapped_i(
    cprisk_vm_interp_frame_t *fr,
    uint8_t op_raw,
    uint8_t logical,
    uint64_t imm,
    uint32_t pc,
    uint32_t hvar,
    cprisk_vm_oph_fn materialized);

// 前置声明：worker 入口与 mailbox/peer 辅助函数互相引用，先声明再定义。
static void *cprisk_watchdog_pthread_thunk(void *arg);
static void *cprisk_watchdog_thread_main_bridge(void *arg);
static void *cprisk_watchdog_thread_main_impl(void *arg);
static void cprisk_watchdog_reset_mailboxes_locked(void);
static int cprisk_watchdog_init_mailboxes_locked(void);
static void cprisk_watchdog_mailbox_send_i(uint32_t worker_id);
static void cprisk_watchdog_mailbox_drain_i(uint32_t worker_id, uint64_t now_ns);
static int cprisk_watchdog_mach_peer_verify_i(uint32_t worker_id);
static void cprisk_watchdog_mark_peer_stall_i(void);
static void cprisk_watchdog_verify_main_thread_heartbeat_i(void);
static void cprisk_watchdog_mark_main_thread_stall_i(void);

// constructor 中签名、start 时重新计算并逐一比对；认证失败意味着线程入口指针被改写。
// 三个指针分别是 thunk、bridge、impl，pthread_create 按此顺序降级尝试。
static void *s_watchdog_bridge_signed_fp;
static void *s_watchdog_thunk_signed_fp;
static void *s_watchdog_impl_signed_fp;
/* Intermediate signed pthread entry for main_impl (LE: "CPRISKIM"). */
#define CPRISK_WATCHDOG_IMPL_PAC_DISC 0x43505249534B494DuLL
// 主线程心跳：main_alive_ns 由主线程 ping 写入；stall_consecutive 记录连续超阈值次数，
// stall_latched 保证一次停滞事件只上报一次，直到心跳恢复才清除。
static atomic_uint_fast64_t s_watchdog_main_alive_ns;
static atomic_uint_fast64_t s_watchdog_main_heartbeat_seq;
static atomic_uint_fast32_t s_watchdog_main_stall_consecutive;
static atomic_uint_fast32_t s_watchdog_main_stall_latched;

// 硬崩溃开关：只影响已命中 HIGH_RISK 的异常；_exit(3) 绕过可能被 hook 的 atexit/信号处理，
// 用于“宁可直接退出也不让进程带毒继续跑”的宿主。默认关闭。
/* Hard-crash mode: when non-zero any HIGH_RISK_POISON_MASK anomaly calls _exit(3) immediately
 * after the standard poison lane commit.  Disabled by default.
 * Enable with cprisk_set_hard_crash_mode(1) for apps that prefer fail-fast over silent corruption. */
static atomic_int s_hard_crash_mode = 0;

// constructor(4)：在多数 CRiskCore 初始化之前，把三个线程入口函数指针用 PAC 签名后缓存。
// 这里只签名不校验；真正校验在 start 时重新计算并比对，避免缓存被篡改后仍被当作合法入口。
__attribute__((constructor(4)))
static void cprisk_watchdog_sign_main_entry_i(void) {
    s_watchdog_bridge_signed_fp = cprisk_pac_sign_function_pointer(
        (const void *)&cprisk_watchdog_thread_main_bridge,
        (uintptr_t)CPRISK_WATCHDOG_PTHREAD_BRIDGE_PAC_DISC);
    s_watchdog_thunk_signed_fp = cprisk_pac_sign_function_pointer(
        (const void *)&cprisk_watchdog_pthread_thunk,
        (uintptr_t)CPRISK_WATCHDOG_PTHREAD_THUNK_PAC_DISC);
    s_watchdog_impl_signed_fp = cprisk_pac_sign_function_pointer(
        (const void *)&cprisk_watchdog_thread_main_impl,
        (uintptr_t)CPRISK_WATCHDOG_IMPL_PAC_DISC);
}

// 全局快照。supported=1 表示本平台编译了 watchdog 实现；interval_seconds 是展示值
// （按毫秒周期向上取整），实际周期由 worker 每轮随机选择。字段语义：
//   last_* = 最近一轮的瞬时结论；*_count/*_total = 启动以来累计；flags/mask/bits = 按位或、粘性。
// 快照不是实时状态：读方通过 cprisk_get_anti_debug_watchdog_snapshot() 持锁按值拷贝，
//   worker 只在每轮固定边界更新，两次读取之间可能完全不变。
// 生命周期：start 时 reset_locked 清零；stop 后保留异常位与计数供取证，只有再次 start 才清空。
static cprisk_anti_debug_watchdog_snapshot_t s_watchdog_snapshot = {
    .supported = 1u,
    .running = 0u,
    .thread_active = 0u,
    .stop_requested = 0u,
    .interval_seconds = 3u,
    .anomaly_flags = CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_NONE,
// 最近一轮的调试跟踪 / 异常端口 / deny_attach 结论（0/1 或 errno/kern_return）。
    .last_traced = 0u,
    .last_exception_port_healthy = 0u,
    .last_exception_query_succeeded = 0u,
    .last_exception_reclaim_attempted = 0u,
    .last_exception_hijack_detected = 0u,
    .last_exception_early_phase_captured = 0u,
    .last_exception_startup_race_detected = 0u,
    .last_deny_attach_result = 0,
    .last_deny_attach_errno = 0,
    .last_exception_query_kern_return = 0,
    .last_exception_register_kern_return = 0,
// 累计计数：迭代次数、跟踪事件、deny_attach 失败、异常端口异常等；只增不减。
    .iteration_count = 0u,
    .traced_event_count = 0u,
    .deny_attach_error_count = 0u,
    .exception_anomaly_count = 0u,
    .last_check_monotonic_ns = 0u,
    .last_exception_verify_count = 0u,
    .last_exception_reclaim_count = 0u,
    .last_exception_startup_delta_ns = 0u,
// 最近一轮断点/单步/tty/开发者磁盘/异常投递探测结果（0/1，部分字段为计数）。
    .last_signal_probe_result = 0u,
    .last_hardware_bp_detected = 0u,
    .last_software_bp_detected = 0u,
    .last_csops_debugged = 0u,
    .last_suspicious_thread_count = 0u,
    .last_single_step_detected = 0u,
    .last_tty_detected = 0u,
    .last_developer_disk_detected = 0u,
    .last_exception_delivery_timeout_detected = 0u,
    .last_exception_delivery_probe_handled = 0u,
    .last_exception_delivery_probe_ns = 0u,
    .signal_probe_anomaly_count = 0u,
    .hardware_bp_anomaly_count = 0u,
    .software_bp_anomaly_count = 0u,
    .csops_anomaly_count = 0u,
    .suspicious_thread_anomaly_count = 0u,
    .exception_delivery_timeout_anomaly_count = 0u,
    .peer_watchdog_anomaly_count = 0u,
    .shadow_stack_anomaly_count = 0u,
    .last_peer_watchdog_stalled = 0u,
    .last_shadow_stack_mismatch = 0u,
// DBI/时序探测的最近结果；对应的 *_flags 是探测模块返回的位掩码，不是 base 异常位。
    .last_dbi_detected = 0u,
    .last_dbi_marker_flags = 0u,
    .last_timing_anomaly_flags = 0u,
    .last_timing_probe_median_ns = 0u,
    .last_timing_probe_max_ns = 0u,
    .last_timing_probe_threshold_ns = 0u,
    .dbi_anomaly_count = 0u,
    .timing_anomaly_count = 0u,
    .prologue_integrity_anomaly_count = 0u,
    .dyld_injection_anomaly_count = 0u,
// 序言/注入/AMFI/get-task-allow 的最近位掩码与累计异常次数。
    .last_prologue_fail_mask = 0u,
    .last_dyld_injection_flags = 0u,
    .last_csops_status_flags = 0u,
    .last_amfi_probe_bits = 0u,
    .last_get_task_allow_suspect = 0u,
    .last_deny_attach_verify_bits = 0u,
    .deny_attach_verify_anomaly_count = 0u,
    .amfi_cs_flags_anomaly_count = 0u,
    .get_task_allow_anomaly_count = 0u,
    .vm_mprotect_crosscheck_mismatch_total = 0u,
    .vm_mprotect_mach_trap_mismatch_total = 0u,
// 启动与活性：worker 实际启动路径、宽限期内是否存活、主线程心跳、早期注入环境位。
    .watchdog_start_path_mask = 0u,
    .watchdog_startup_liveness_ok = 0u,
    .main_thread_alive_monotonic_ns = 0u,
    .early_injection_env_mask = 0u,
// 扩展异常位：base 的 32 位已用满，新语义（主线程停滞/文本加密漂移/导出面漂移）放这里，
// 置位/读取/重置规则与 base anomaly_flags 相同。
    .watchdog_extended_anomaly_flags = 0u,
    .main_thread_heartbeat_seq = 0u,
    .main_thread_heartbeat_stall_count = 0u,
    .last_main_thread_heartbeat_stalled = 0u,
};

// pthread 入口的中间跳板：独立函数体让 thunk 不必直接引用 impl 地址。
// 攻击者只 patch 其中一层入口时，另外两层仍可能完整，从而保留发现篡改的机会。
static void *cprisk_watchdog_thread_main_bridge(void *arg) {
    return cprisk_watchdog_thread_main_impl(arg);
}

// thunk 是 pthread_create 可见的入口。先认证 bridge 指针，成功才调用真正 worker；
// 认证失败说明线程入口被替换：标记 worker 不活跃、置 PAC_THREAD_ENTRY 后直接退出该线程（fail-closed）。
static void *cprisk_watchdog_pthread_thunk(void *arg) {
    void *fn = cprisk_pac_auth_function_pointer(
        s_watchdog_bridge_signed_fp,
        (uintptr_t)CPRISK_WATCHDOG_PTHREAD_BRIDGE_PAC_DISC);
    if (fn == NULL) {
        const uint32_t wid = (uint32_t)(uintptr_t)arg;
        if (wid < CPRISK_WATCHDOG_THREAD_COUNT) {
            atomic_store(&s_watchdog_worker_active[wid], 0u);
        }
        pthread_mutex_lock(&s_watchdog_mutex);
        s_watchdog_snapshot.anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_PAC_THREAD_ENTRY;
        pthread_mutex_unlock(&s_watchdog_mutex);
        return NULL;
    }
    typedef void *(*cprisk_wd_start_fn)(void *);
    return ((cprisk_wd_start_fn)fn)(arg);
}

// 把 AMFI 探测位映射为 base 异常位：任一“签名标志异常”组合都归并到 AMFI_CS_FLAGS，
// 便于 Swift 侧只判断一个位。此处仅映射，不投毒。
static inline uint32_t cprisk_wd_amfi_flags_from_probe_bits_i(uint32_t amfi_probe_bits) {
    uint32_t flags = 0u;
    if ((amfi_probe_bits & CPRISK_AMFI_PROBE_CS_DEBUGGED) != 0u ||
        (amfi_probe_bits & CPRISK_AMFI_PROBE_CS_VALID_ABSENT) != 0u ||
        (amfi_probe_bits & CPRISK_AMFI_PROBE_CS_HARD_ABSENT) != 0u ||
        (amfi_probe_bits & CPRISK_AMFI_PROBE_CS_KILL_ABSENT) != 0u) {
        flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_AMFI_CS_FLAGS;
    }
    return flags;
}

// csops 调试位探测的内联包装：单独成函数，避免探测调用点被轻易定位或整体内联替换。
static inline int cprisk_wd_csops_debug_probe_inline_i(void) {
    return cprisk_csops_debug_check();
}

// 单调时钟（纳秒）。优先直接读 cntfrq_el0/cntpct_el0，绕过可能被 hook 的 clock_gettime；
// 频率只读一次并缓存。返回 0 表示时间不可用，调用方必须把 0 当作“未知”而非“很久以前”（fail-open）。
static uint64_t cprisk_monotonic_time_ns(void) {
    static _Atomic uint64_t s_cntfrq = 0u;
    uint64_t freq = atomic_load_explicit(&s_cntfrq, memory_order_relaxed);
    if (freq == 0u) {
        __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
        atomic_store_explicit(&s_cntfrq, freq, memory_order_relaxed);
    }
    if (freq != 0u) {
        uint64_t ticks = 0u;
        __asm__ volatile("mrs %0, cntpct_el0" : "=r"(ticks));
        return (ticks / freq) * 1000000000ull +
               ((ticks % freq) * 1000000000ull) / freq;
    }

    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0u;
    }
    return ((uint64_t)ts.tv_sec * 1000000000ull) + (uint64_t)ts.tv_nsec;
}

// 按固定顺序填充 18 个受监控入口。顺序即 last_prologue_fail_mask 的低位编号，
// 调整顺序会改变已有 mask 的语义，必须同步更新读取方。
static void cprisk_watchdog_fill_prologue_addrs_i(const void **addrs) {
    addrs[0] = (const void *)&cprisk_vm_execute;
    addrs[1] = (const void *)&cprisk_is_being_traced;
    addrs[2] = (const void *)&cprisk_whitebox_evaluate_domain;
    addrs[3] = (const void *)&cprisk_deny_attach;
    addrs[4] = (const void *)&cprisk_probe_debugger_via_signal;
    addrs[5] = (const void *)&cprisk_text_jit_decrypt;
    addrs[6] = (const void *)&cprisk_watchdog_pthread_thunk;
    addrs[7] = (const void *)&cprisk_watchdog_thread_main_bridge;
    addrs[8] = (const void *)&cprisk_watchdog_thread_main_impl;
    addrs[9] = (const void *)&cprisk_vm_dispatch_leaf_wb_wrapped_i;
    addrs[10] = (const void *)&cprisk_text_encrypt_service_idle;
    addrs[11] = (const void *)&cprisk_restore_macho_header;
    addrs[12] = (const void *)&cprisk_resolve_import;
    addrs[13] = (const void *)&cprisk_deny_attach_status;
    addrs[14] = (const void *)&cprisk_probe_exception_delivery_timeout;
    addrs[15] = (const void *)&cprisk_register_exception_handler;
    addrs[16] = (const void *)&cprisk_verify_exception_handler;
    addrs[17] = (const void *)&cprisk_run_all_signal_probes;
}

// 一次性捕获所有序言基线。只允许第一次调用生效（atomic 标志），
// 避免运行期被诱导重新捕获、把已注入的 trampoline 当成合法新基线。
static void cprisk_watchdog_capture_prologue_once_i(void) {
    if (atomic_load(&s_watchdog_prologue_captured) != 0u) {
        return;
    }
    const void *addrs[CPRISK_WATCHDOG_PROLOGUE_SLOTS];
    cprisk_watchdog_fill_prologue_addrs_i(addrs);
    for (uint32_t i = 0u; i < CPRISK_WATCHDOG_PROLOGUE_SLOTS; i++) {
        memcpy(s_watchdog_prologue_ref[i], addrs[i], CPRISK_WATCHDOG_PROLOGUE_BYTES);
    }
    memcpy(s_watchdog_pthread_create_ref, (const void *)&pthread_create, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    memcpy(s_watchdog_dlsym_ref, (const void *)&dlsym, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    memcpy(s_watchdog_objc_msgsend_ref, (const void *)&objc_msgSend, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    memcpy(s_watchdog_dyld_image_count_ref, (const void *)&_dyld_image_count, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    atomic_store(&s_watchdog_prologue_captured, 1u);
}

// constructor(10)：尽早建立基线，缩小“hook 先于首次快照”的窗口；
// 只读代码字节，不分配内存，也不依赖其他模块的初始化顺序。
/*
 * Early baseline: priority 10 runs before most other CRiskCore constructors (e.g. 101+),
 * shrinking the window where hooks can win before the first snapshot.
 */
__attribute__((constructor(10)))
static void cprisk_watchdog_prologue_early_ctor_i(void) {
    cprisk_watchdog_capture_prologue_once_i();
}

// 校验 libsystem pthread_create 入口。三步：先看是否已变成可疑 trampoline 前缀，
// 再与上一轮通过值比较（运行期漂移），最后与 ctor 基线比较（启动前注入）。
// 任一失败都立即投毒并返回 0；成功则刷新 last_ok。返回值：1=通过，0=异常。
static int cprisk_watchdog_verify_pthread_create_prologue_i(uint32_t *mask_out) {
    if (atomic_load(&s_watchdog_prologue_captured) == 0u) {
        cprisk_watchdog_capture_prologue_once_i();
    }
    if (cprisk_scan_arm64_suspicious_trampoline_prefix((const void *)&pthread_create, 12u) != 0) {
        *mask_out |= CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_PTHREAD_CREATE;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    uint8_t live[CPRISK_WATCHDOG_PROLOGUE_BYTES];
    // 先拷贝到栈上再比较，缩小“比较过程中字节被改写”的 TOCTOU 窗口。
    /* TOCTOU: snapshot libsystem code into a stack shadow before compare (not direct memcmp on r-x). */
    memcpy(live, (const void *)&pthread_create, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    if (atomic_load_explicit(&s_watchdog_pthread_create_last_ok_valid, memory_order_relaxed) != 0u &&
        memcmp(s_watchdog_pthread_create_last_ok, live, CPRISK_WATCHDOG_PROLOGUE_BYTES) != 0) {
        *mask_out |= CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_PTHREAD_CREATE;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    if (memcmp(s_watchdog_pthread_create_ref, live, CPRISK_WATCHDOG_PROLOGUE_BYTES) != 0) {
        *mask_out |= CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_PTHREAD_CREATE;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    memcpy(s_watchdog_pthread_create_last_ok, live, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    atomic_store_explicit(&s_watchdog_pthread_create_last_ok_valid, 1u, memory_order_release);
    return 1;
}

// 同 pthread_create，校验 dlsym 序言；dlsym 被 hook 会同时影响导入解析与后续反调试探测。
// 返回值：1=通过，0=异常（异常细节写入 mask_out，并已立即投毒）。
static int cprisk_watchdog_verify_dlsym_prologue_i(uint32_t *mask_out) {
    if (atomic_load(&s_watchdog_prologue_captured) == 0u) {
        cprisk_watchdog_capture_prologue_once_i();
    }
    uint8_t live[CPRISK_WATCHDOG_PROLOGUE_BYTES];
    memcpy(live, (const void *)&dlsym, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    if (atomic_load_explicit(&s_watchdog_dlsym_last_ok_valid, memory_order_relaxed) != 0u &&
        memcmp(s_watchdog_dlsym_last_ok, live, CPRISK_WATCHDOG_PROLOGUE_BYTES) != 0) {
        *mask_out |= CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_DLSYM;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    if (memcmp(s_watchdog_dlsym_ref, live, CPRISK_WATCHDOG_PROLOGUE_BYTES) != 0) {
        *mask_out |= CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_DLSYM;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    memcpy(s_watchdog_dlsym_last_ok, live, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    atomic_store_explicit(&s_watchdog_dlsym_last_ok_valid, 1u, memory_order_release);
    return 1;
}

// 公开包装：只返回 1/0，供其他模块在自身初始化路径上做一次轻量校验；
// 不暴露 mask，异常细节统一由 watchdog 快照记录。
int cprisk_verify_dlsym_prologue(void) {
    uint32_t mask = 0u;
    return cprisk_watchdog_verify_dlsym_prologue_i(&mask);
}

// 校验 objc_msgSend：Frida / method swizzling 的常见 hook 面。只比较序言字节，
// 不做完整符号解析，保证开销适合每轮调用。
static int cprisk_watchdog_verify_objc_msgsend_prologue_i(uint32_t *mask_out) {
    if (atomic_load(&s_watchdog_prologue_captured) == 0u) {
        cprisk_watchdog_capture_prologue_once_i();
    }
    uint8_t live[CPRISK_WATCHDOG_PROLOGUE_BYTES];
    memcpy(live, (const void *)&objc_msgSend, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    if (atomic_load_explicit(&s_watchdog_objc_msgsend_last_ok_valid, memory_order_relaxed) != 0u &&
        memcmp(s_watchdog_objc_msgsend_last_ok, live, CPRISK_WATCHDOG_PROLOGUE_BYTES) != 0) {
        *mask_out |= CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_OBJC_MSGSEND;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    if (memcmp(s_watchdog_objc_msgsend_ref, live, CPRISK_WATCHDOG_PROLOGUE_BYTES) != 0) {
        *mask_out |= CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_OBJC_MSGSEND;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    memcpy(s_watchdog_objc_msgsend_last_ok, live, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    atomic_store_explicit(&s_watchdog_objc_msgsend_last_ok_valid, 1u, memory_order_release);
    return 1;
}

// 校验 _dyld_image_count：镜像枚举入口被替换时，攻击者可隐藏注入库，
// 因此它同时影响注入检测与完整性判断。
static int cprisk_watchdog_verify_dyld_image_count_prologue_i(uint32_t *mask_out) {
    if (atomic_load(&s_watchdog_prologue_captured) == 0u) {
        cprisk_watchdog_capture_prologue_once_i();
    }
    uint8_t live[CPRISK_WATCHDOG_PROLOGUE_BYTES];
    memcpy(live, (const void *)&_dyld_image_count, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    if (atomic_load_explicit(&s_watchdog_dyld_image_count_last_ok_valid, memory_order_relaxed) != 0u &&
        memcmp(s_watchdog_dyld_image_count_last_ok, live, CPRISK_WATCHDOG_PROLOGUE_BYTES) != 0) {
        *mask_out |= CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_DYLD_IMAGE_COUNT;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    if (memcmp(s_watchdog_dyld_image_count_ref, live, CPRISK_WATCHDOG_PROLOGUE_BYTES) != 0) {
        *mask_out |= CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_DYLD_IMAGE_COUNT;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    memcpy(s_watchdog_dyld_image_count_last_ok, live, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    atomic_store_explicit(&s_watchdog_dyld_image_count_last_ok_valid, 1u, memory_order_release);
    return 1;
}

// 判断入口前 8 字节是否像 hook trampoline：B/BL 立即跳转、br/blr x16/x17、
// adrp+br 或 ldr literal+br。只做模式匹配，可能命中合法 PLT；
// 因此调用方还会结合符号归属（dladdr）与逐库解析结果交叉判断。
static int cprisk_watchdog_is_suspicious_trampoline_i(const void *addr) {
    uint32_t insn0 = 0u;
    uint32_t insn1 = 0u;
    if (addr == NULL) {
        return 0;
    }
    memcpy(&insn0, addr, sizeof(insn0));
    memcpy(&insn1, (const uint8_t *)addr + sizeof(insn0), sizeof(insn1));

    if ((insn0 & 0xFC000000u) == 0x14000000u) {
        return 1;
    }
    if ((insn0 & 0xFC000000u) == 0x94000000u) {
        return 1;
    }
    if (insn0 == 0xD61F0200u || insn0 == 0xD61F0220u ||
        insn0 == 0xD63F0200u || insn0 == 0xD63F0220u) {
        return 1;
    }
    if ((insn0 & 0x9F000000u) == 0x90000000u) {
        const uint32_t rd = insn0 & 0x1Fu;
        if ((rd == 0x10u || rd == 0x11u) &&
            (insn1 == 0xD61F0200u || insn1 == 0xD61F0220u ||
             insn1 == 0xD63F0200u || insn1 == 0xD63F0220u)) {
            return 1;
        }
    }
    if ((insn0 & 0xFF000000u) == 0x58000000u) {
        const uint32_t rd = insn0 & 0x1Fu;
        if ((rd == 0x10u || rd == 0x11u) &&
            (insn1 == 0xD61F0200u || insn1 == 0xD61F0220u ||
             insn1 == 0xD63F0200u || insn1 == 0xD63F0220u)) {
            return 1;
        }
    }
    return 0;
}

// 用 dladdr 判断符号实际归属的镜像是否在预期库列表中。
// dladdr 失败视为“无法判断”并返回 0（fail-open），避免把受限环境下的不可解析误判为劫持。
static int cprisk_watchdog_symbol_owner_mismatch_i(
    const void *addr,
    const char *const *expected_libs,
    size_t expected_count
) {
    Dl_info info;
    if (addr == NULL || expected_libs == NULL || expected_count == 0u) {
        return 0;
    }
    memset(&info, 0, sizeof(info));
    if (dladdr(addr, &info) == 0 || info.dli_fname == NULL) {
        return 0;
    }
    for (size_t i = 0u; i < expected_count; i++) {
        if (expected_libs[i] != NULL && strstr(info.dli_fname, expected_libs[i]) != NULL) {
            return 0;
        }
    }
    return 1;
}

// 通过 cprisk_dlsym 直接向每个预期库解析同名符号；若多个库给出不同地址，说明导出面不一致，
// 返回 NULL 让调用方记录漂移。全都解析不到也返回 NULL（调用方会跳过该符号）。
static void *cprisk_watchdog_resolve_unique_export_i(
    const char *symbol,
    const char *const *expected_libs,
    size_t expected_count
) {
    void *seen = NULL;
    if (symbol == NULL || expected_libs == NULL) {
        return NULL;
    }
    for (size_t i = 0u; i < expected_count; i++) {
        void *candidate = cprisk_dlsym(expected_libs[i], symbol);
        if (candidate == NULL) {
            continue;
        }
        if (seen == NULL) {
            seen = candidate;
        } else if (seen != candidate) {
            return NULL;
        }
    }
    return seen;
}

// 交叉校验高价值 libc/libsystem 导出：dlsym(RTLD_DEFAULT) 的结果必须同时满足
// (a) 与逐库解析一致、(b) 归属预期镜像、(c) 入口不像 trampoline。
// 任一符号失败即 OR 入 mask 并立即投毒；返回值 1=全部通过，0=发现漂移。
static int cprisk_watchdog_verify_runtime_hook_exports_i(uint32_t *mask_out) {
    static const char *const k_kernel_or_c[] = {"libsystem_kernel.dylib", "libsystem_c.dylib"};
    static const char *const k_kernel_or_c_or_pthread[] = {
        "libsystem_kernel.dylib", "libsystem_c.dylib", "libsystem_pthread.dylib"};
    static const char *const k_c_only[] = {"libsystem_c.dylib"};
    static const char *const k_kernel_only[] = {"libsystem_kernel.dylib"};
    struct {
        const char *symbol;
        const char *const *libs;
        size_t lib_count;
        uint32_t mask;
    } checks[] = {
        {"access", k_kernel_or_c, 2u, CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_ACCESS},
        {"stat", k_kernel_or_c, 2u, CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_STAT},
        {"lstat", k_kernel_or_c, 2u, CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_LSTAT},
        {"open", k_kernel_or_c, 2u, CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_OPEN},
        {"socket", k_kernel_or_c_or_pthread, 3u, CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_SOCKET},
        {"connect", k_kernel_or_c, 2u, CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_CONNECT},
        {"dlopen", k_c_only, 1u, CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_DLOPEN},
        {"sysctl", k_kernel_or_c, 2u, CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_SYSCTL},
        {"sysctlbyname", k_kernel_or_c, 2u, CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_SYSCTLBYNAME},
        {"mprotect", k_kernel_only, 1u, CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_MPROTECT},
        {"mach_msg", k_kernel_only, 1u, CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_MACH_MSG},
        {"task_get_exception_ports", k_kernel_only, 1u,
         CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_TASK_GET_EXCEPTION_PORTS},
        {"task_swap_exception_ports", k_kernel_only, 1u,
         CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_TASK_SWAP_EXCEPTION_PORTS},
    };
    uint32_t local_mask = 0u;

    // 逐符号检查，单个符号异常不会中断其余检查，便于一次性收集完整 hook 面。
    for (size_t i = 0u; i < sizeof(checks) / sizeof(checks[0]); i++) {
        void *rtld_addr = dlsym(RTLD_DEFAULT, checks[i].symbol);
        void *trie_addr = cprisk_watchdog_resolve_unique_export_i(
            checks[i].symbol, checks[i].libs, checks[i].lib_count);
        if (rtld_addr == NULL) {
            continue;
        }
        if (trie_addr != NULL && trie_addr != rtld_addr) {
            local_mask |= checks[i].mask;
            continue;
        }
        if (cprisk_watchdog_symbol_owner_mismatch_i(rtld_addr, checks[i].libs, checks[i].lib_count) != 0) {
            local_mask |= checks[i].mask;
            continue;
        }
        if (cprisk_watchdog_is_suspicious_trampoline_i(rtld_addr) != 0) {
            local_mask |= checks[i].mask;
            continue;
        }
    }

    if (mask_out != NULL) {
        *mask_out |= local_mask;
    }
    if (local_mask != 0u) {
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    return 1;
}

// 只读查询：返回导出漂移 mask，不额外修改状态。
// 注意探测函数自身在发现漂移时会立即投毒，这是其固有语义。
uint32_t cprisk_runtime_hook_surface_export_drift_mask(void) {
    uint32_t mask = 0u;
    (void)cprisk_watchdog_verify_runtime_hook_exports_i(&mask);
    return mask;
}

// 公开的组合校验入口：objc_msgSend + _dyld_image_count 序言 + 运行时导出面。
// 非 iOS（macOS 测试宿主）直接返回 1：那里的 dyld/objc 布局与 iOS 生产基线不同，
// 强行比较只会制造误报（fail-open）。
int cprisk_verify_runtime_hook_surface_prologues(void) {
#if !(defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE)
    /* macOS test hosts may run with dyld/objc prologue layouts that differ from iOS production baselines. */
    return 1;
#else
    uint32_t mask = 0u;
    if (cprisk_watchdog_verify_objc_msgsend_prologue_i(&mask) == 0) {
        return 0;
    }
    if (cprisk_watchdog_verify_dyld_image_count_prologue_i(&mask) == 0) {
        return 0;
    }
    if (cprisk_watchdog_verify_runtime_hook_exports_i(&mask) == 0) {
        return 0;
    }
    return 1;
#endif
}

// 校验 18 个固定槽位。每个槽位同时与 last_ok（运行期漂移）和 ref（ctor 基线）比较，
// 失败位按槽位下标写入 mask 低 18 位。即使本轮失败仍会把 live 写入 last_ok：
// 异常已粘性记录，后续比较继续跟踪“当前值”以发现再次变化。
static void cprisk_watchdog_verify_prologue_i(uint32_t *anomaly_out, uint32_t *mask_out) {
    *anomaly_out = 0u;
    *mask_out = 0u;
    if (atomic_load(&s_watchdog_prologue_captured) == 0u) {
        cprisk_watchdog_capture_prologue_once_i();
        return;
    }
    const void *addrs[CPRISK_WATCHDOG_PROLOGUE_SLOTS];
    cprisk_watchdog_fill_prologue_addrs_i(addrs);
    const int have_last =
        atomic_load_explicit(&s_watchdog_prologue_last_ok_valid, memory_order_relaxed) != 0u;
    for (uint32_t i = 0u; i < CPRISK_WATCHDOG_PROLOGUE_SLOTS; i++) {
        uint8_t live[CPRISK_WATCHDOG_PROLOGUE_BYTES];
        /* TOCTOU: compare against shadow snapshot; attacker could otherwise flip bytes mid-memcmp. */
        memcpy(live, addrs[i], CPRISK_WATCHDOG_PROLOGUE_BYTES);
        if (have_last != 0 &&
            memcmp(s_watchdog_prologue_last_ok[i], live, CPRISK_WATCHDOG_PROLOGUE_BYTES) != 0) {
            *anomaly_out |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE;
            *mask_out |= (1u << i);
            cprisk_integrity_poison_watchdog_lane_now();
        }
        if (memcmp(s_watchdog_prologue_ref[i], live, CPRISK_WATCHDOG_PROLOGUE_BYTES) != 0) {
            *anomaly_out |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE;
            *mask_out |= (1u << i);
            cprisk_integrity_poison_watchdog_lane_now();
        }
        memcpy(s_watchdog_prologue_last_ok[i], live, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    }
    atomic_store_explicit(&s_watchdog_prologue_last_ok_valid, 1u, memory_order_release);
}

// 将镜像路径转小写，与混淆存储的工具名做子串匹配；命中位写入 flags_out。
// 覆盖 Frida/Cycript/Substrate/Substitute/libhooker/SSL Kill Switch/QBDI 等常见工具。
// 返回 1 表示至少命中一个名字；flags_out 为按位或结果，由调用方持久化。
static int cprisk_watchdog_dyld_name_suspicious_i(const char *path, uint32_t *flags_out) {
    if (!path || !flags_out) {
        return 0;
    }
    char lowered[256];
    // 路径先转小写，避免大小写差异绕过；固定 256 字节缓冲，超长路径截断后仍可匹配前缀。
    size_t n = 0u;
    for (; path[n] != '\0' && n + 1u < sizeof(lowered); n++) {
        char c = path[n];
        if (c >= 'A' && c <= 'Z') {
            c += (char)('a' - 'A');
        }
        lowered[n] = c;
    }
    lowered[n] = '\0';

    static const uint8_t k_e_frida[] = {0xfc, 0x82, 0x19, 0x6b, 0xa3};
    static const uint8_t k_e_gum_dash[] = {0xdc, 0x33, 0x9b, 0x4d};
    static const uint8_t k_e_cycript[] = {0x69, 0x19, 0x5c, 0x10, 0x02, 0x22, 0xca};
    static const uint8_t k_e_substrate[] = {0x36, 0x91, 0xe4, 0xaa, 0xad, 0xdb, 0xc2, 0xbd, 0x5f};
    static const uint8_t k_e_substitute[] = {
        0x3c, 0x64, 0x41, 0x26, 0x26, 0xd2, 0x4a, 0xf3, 0x5b, 0xbe};
    static const uint8_t k_e_libhooker[] = {0xd0, 0xf0, 0xd3, 0xb4, 0x00, 0x69, 0xc8, 0x8a, 0x7a};
    static const uint8_t k_e_ssl_kill[] = {0x4b, 0x7d, 0xf6, 0x3f, 0x37, 0xc9, 0x51, 0x4a};
    static const uint8_t k_e_sskill[] = {0x3d, 0x14, 0xc2, 0x31, 0x37, 0x4c};
    static const uint8_t k_e_cephei[] = {0x46, 0xdd, 0xc7, 0xe4, 0xb8, 0xbc};
    static const uint8_t k_e_rocket[] = {
        0x7a, 0x0c, 0xe4, 0xff, 0xce, 0x2b, 0xaf, 0x39, 0xa5, 0xe1, 0xf8, 0xdd, 0xba, 0x42, 0x07};
    static const uint8_t k_e_dopamine[] = {0xf4, 0x29, 0x61, 0xdb, 0x74, 0xae, 0x67, 0xef};
    static const uint8_t k_e_ellekit[] = {0x84, 0xa8, 0x44, 0x78, 0x90, 0x96, 0x8a};
    static const uint8_t k_e_qbdi[] = {0x69, 0xe7, 0x05, 0x24};
    static const uint8_t k_e_libqbdi[] = {0xf6, 0x50, 0xdd, 0xc9, 0xac, 0x79, 0x6c};
    static const uint8_t k_e_qbdipreload[] = {
        0xca, 0xa7, 0x88, 0x33, 0xe8, 0xea, 0x4c, 0x36, 0x2b, 0x09, 0x43};

    static const struct {
        uint32_t key_id;
        const uint8_t *enc;
        size_t enc_len;
        uint32_t flag;
    } k_rows[] = {
        {1u, k_e_frida, sizeof(k_e_frida), 1u << 0},
        {2u, k_e_gum_dash, sizeof(k_e_gum_dash), 1u << 1},
        {3u, k_e_cycript, sizeof(k_e_cycript), 1u << 2},
        {4u, k_e_substrate, sizeof(k_e_substrate), 1u << 3},
        {5u, k_e_substitute, sizeof(k_e_substitute), 1u << 4},
        {6u, k_e_libhooker, sizeof(k_e_libhooker), 1u << 5},
        {7u, k_e_ssl_kill, sizeof(k_e_ssl_kill), 1u << 6},
        {8u, k_e_sskill, sizeof(k_e_sskill), 1u << 7},
        {9u, k_e_cephei, sizeof(k_e_cephei), 1u << 8},
        {10u, k_e_rocket, sizeof(k_e_rocket), 1u << 9},
        {11u, k_e_dopamine, sizeof(k_e_dopamine), 1u << 10},
        {12u, k_e_ellekit, sizeof(k_e_ellekit), 1u << 11},
        {13u, k_e_qbdi, sizeof(k_e_qbdi), 1u << 12},
        {14u, k_e_libqbdi, sizeof(k_e_libqbdi), 1u << 13},
        {15u, k_e_qbdipreload, sizeof(k_e_qbdipreload), 1u << 14},
    };

    // 工具名不落明文：每个名字按域分离标签解码到栈缓冲，匹配后立即 secure_zero。
    const uint32_t D = CPRISK_OBF_TAG_DOMAIN_WD_DYLD;
    uint32_t f = 0u;
    for (size_t i = 0u; i < sizeof(k_rows) / sizeof(k_rows[0]); i++) {
        char needle[40];
        memset(needle, 0, sizeof(needle));
        if (k_rows[i].enc_len + 1u > sizeof(needle)) {
            continue;
        }
        if (cprisk_obf_decode_sha256_tag(
                D,
                k_rows[i].key_id,
                k_rows[i].enc,
                k_rows[i].enc_len,
                needle,
                sizeof(needle)) != 0) {
            continue;
        }
        const char *h = lowered;
        const char *nd = needle;
        for (; *h != '\0'; h++) {
            const char *a = h;
            const char *b = nd;
            while (*a != '\0' && *b != '\0' && *a == *b) {
                a++;
                b++;
            }
            if (*b == '\0') {
                f |= k_rows[i].flag;
                break;
            }
        }
        cprisk_secure_zero(needle, sizeof(needle));
    }
    *flags_out = f;
    return f != 0u ? 1 : 0;
}

// _dyld_register_func_for_add_image 回调：新镜像加载时按名称判定是否为已知注入工具。
// 只做名称匹配（高置信），不做通用布局判断；命中即累加位与事件数并提交高信号投毒。
// 回调在 dyld 锁内执行，这里只做定长拷贝/匹配与原子操作，不分配内存。
static void cprisk_watchdog_dyld_add_image_i(const struct mach_header *mh, intptr_t slide) {
    (void)slide;
    const uint32_t count = _dyld_image_count();
    const char *name = NULL;
    for (uint32_t i = 0u; i < count; i++) {
        if (_dyld_get_image_header(i) == mh) {
            name = _dyld_get_image_name(i);
            break;
        }
    }
    uint32_t flags = 0u;
    if (!cprisk_watchdog_dyld_name_suspicious_i(name, &flags)) {
        return;
    }
    atomic_fetch_or(&s_watchdog_dyld_flags, flags);
    atomic_fetch_add(&s_watchdog_dyld_suspicious_events, 1ull);
    // 0xD1A10001 是“镜像名命中注入工具”的投毒事件标签，便于按标签归因。
    cprisk_integrity_poison_high_signal_mixed(0xD1A10001u);
}

// 幂等注册：atomic_exchange 保证即使 start 被并发/重复调用，回调也只挂一次。
static void cprisk_watchdog_register_dyld_observer_once_i(void) {
    if (atomic_exchange(&s_watchdog_dyld_registered, 1u) != 0u) {
        return;
    }
    _dyld_register_func_for_add_image(cprisk_watchdog_dyld_add_image_i);
}

// xorshift64 位混合：状态 0 会退化为全 0，因此先替换为固定非零种子。
// 只用于抖动/采样窗口选择，不用于任何安全密钥。
static uint64_t cprisk_prng_next_i(uint64_t state) {
    if (state == 0u) {
        state = 0x9E3779B97F4A7C15ULL;
    }
    state ^= state << 7u;
    state ^= state >> 9u;
    state ^= state << 8u;
    return state;
}

// 无锁取随机数：首次用 getentropy 播种；失败则退化为时间/栈地址混合（仍是不可预测的低要求场景）。
// CAS 循环保证并发 worker 得到不同序列。getentropy 失败不视为安全异常。
static uint64_t cprisk_watchdog_random_u64_i(void) {
    uint_fast64_t current = atomic_load(&s_watchdog_prng_state);
    if (current == 0u) {
        uint64_t seed = 0u;
        int err = 0;
        if (cprisk_getentropy_direct(&seed, sizeof(seed), &err) != 0 || seed == 0u) {
            seed = cprisk_monotonic_time_ns() ^ (uint64_t)(uintptr_t)&seed ^ 0xA5A5A5A5u;
        }
        atomic_store(&s_watchdog_prng_state, seed);
        current = seed;
    }

    for (;;) {
        const uint_fast64_t next = cprisk_prng_next_i((uint64_t)current);
        uint_fast64_t expected = current;
        if (atomic_compare_exchange_weak(&s_watchdog_prng_state, &expected, next)) {
            return next;
        }
        current = expected;
    }
}

// 软件断点扫描：固定 6 个关键可调用区域每轮都扫（256B）；iOS 真机额外做随机 __TEXT 采样
// （24×1024B），提高单点 BRK 被发现的概率。返回值是命中计数，调用方用 >=4 的阈值判强信号。
static int cprisk_watchdog_scan_software_breakpoints_i(void) {
    int detected = 0;

    detected += cprisk_scan_software_breakpoints(
        (const void *)cprisk_deny_attach,
        CPRISK_WATCHDOG_SOFTWARE_BP_SCAN_BYTES);
    detected += cprisk_scan_software_breakpoints(
        (const void *)cprisk_deny_attach_status,
        CPRISK_WATCHDOG_SOFTWARE_BP_SCAN_BYTES);
    detected += cprisk_scan_software_breakpoints(
        (const void *)cprisk_probe_debugger_via_signal,
        CPRISK_WATCHDOG_SOFTWARE_BP_SCAN_BYTES);
    detected += cprisk_scan_software_breakpoints(
        (const void *)cprisk_probe_exception_delivery_timeout,
        CPRISK_WATCHDOG_SOFTWARE_BP_SCAN_BYTES);
    detected += cprisk_scan_software_breakpoints(
        (const void *)cprisk_register_exception_handler,
        CPRISK_WATCHDOG_SOFTWARE_BP_SCAN_BYTES);
    detected += cprisk_scan_software_breakpoints(
        (const void *)cprisk_verify_exception_handler,
        CPRISK_WATCHDOG_SOFTWARE_BP_SCAN_BYTES);
#if defined(TARGET_OS_IOS) && TARGET_OS_IOS
    // iOS 真机才做随机文本采样；macOS 测试宿主的调试路径含合法 BRK，直接排除以抑制误报。
    /*
     * Randomized full-text sampling is high-value on iOS device binaries,
     * but macOS test binaries often embed intentional BRK opcodes in debug
     * paths and can cause noisy false positives.
     */
    detected += cprisk_scan_software_breakpoints_randomized_text(
        CPRISK_WATCHDOG_RANDOM_TEXT_WINDOWS,
        CPRISK_WATCHDOG_RANDOM_TEXT_WINDOW_BYTES);
#endif

    return detected;
}

// 把返回地址与帧地址混合成令牌；移位与常量让简单线性改写不易同时保持两个输入不变。
static uintptr_t cprisk_shadow_mix_i(uintptr_t ret_addr, uintptr_t frame_addr) {
    return ret_addr ^ (frame_addr << 11u) ^ (frame_addr >> 7u) ^ (uintptr_t)0x7A6CE1B5u;
}

// 采集当前栈帧令牌。若编译器不支持 __builtin_return_address/frame_address，返回 0；
// 后续 check 会直接通过（fail-open），避免在受限构建里产生误报。
static cprisk_shadow_token_t cprisk_shadow_push_i(void) {
    cprisk_shadow_token_t token;
    token.value = 0u;
#if defined(__has_builtin)
#if __has_builtin(__builtin_return_address) && __has_builtin(__builtin_frame_address)
    token.value = cprisk_shadow_mix_i(
        (uintptr_t)__builtin_return_address(0),
        (uintptr_t)__builtin_frame_address(0));
#endif
#endif
    return token;
}

// 复算令牌并比较：1=一致或不可用（fail-open），0=同一轮内栈帧被改写。
// 令牌只在同一轮迭代内使用，不跨线程保存。
static int cprisk_shadow_check_i(cprisk_shadow_token_t token) {
    if (token.value == 0u) {
        return 1;
    }
#if defined(__has_builtin)
#if __has_builtin(__builtin_return_address) && __has_builtin(__builtin_frame_address)
    const uintptr_t now = cprisk_shadow_mix_i(
        (uintptr_t)__builtin_return_address(0),
        (uintptr_t)__builtin_frame_address(0));
    return now == token.value ? 1 : 0;
#endif
#endif
    return 1;
}

// 持 s_watchdog_mutex 调用：把两个 worker 的 active 原子量归并成快照的 thread_active。
// 只在状态变化点调用，避免每轮写快照造成无谓抖动。
static void cprisk_watchdog_refresh_thread_active_locked(void) {
    const uint32_t active0 = atomic_load(&s_watchdog_worker_active[0]) != 0u ? 1u : 0u;
    const uint32_t active1 = atomic_load(&s_watchdog_worker_active[1]) != 0u ? 1u : 0u;
    s_watchdog_snapshot.thread_active = (active0 | active1);
}

// start 时重置快照与运行期状态。只允许持锁调用。
// 不变量：异常位/计数/闩锁全部清零；但 prologue/pthread_create/dlsym 等基线必须保留
// （它们在更早的 constructor 中捕获，是判断“启动前是否已被 hook”的参考）。
static void cprisk_watchdog_reset_locked(void) {
    s_watchdog_snapshot.running = 0u;
    s_watchdog_snapshot.thread_active = 0u;
    s_watchdog_snapshot.stop_requested = 0u;
    s_watchdog_snapshot.interval_seconds = 1u;
    s_watchdog_snapshot.anomaly_flags = CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_NONE;
    s_watchdog_snapshot.last_traced = 0u;
    s_watchdog_snapshot.last_exception_port_healthy = 0u;
    s_watchdog_snapshot.last_exception_query_succeeded = 0u;
    s_watchdog_snapshot.last_exception_reclaim_attempted = 0u;
    s_watchdog_snapshot.last_exception_hijack_detected = 0u;
    s_watchdog_snapshot.last_exception_early_phase_captured = 0u;
    s_watchdog_snapshot.last_exception_startup_race_detected = 0u;
    s_watchdog_snapshot.last_deny_attach_result = 0;
    s_watchdog_snapshot.last_deny_attach_errno = 0;
    s_watchdog_snapshot.last_exception_query_kern_return = 0;
    s_watchdog_snapshot.last_exception_register_kern_return = 0;
    s_watchdog_snapshot.iteration_count = 0u;
    s_watchdog_snapshot.traced_event_count = 0u;
    s_watchdog_snapshot.deny_attach_error_count = 0u;
    s_watchdog_snapshot.exception_anomaly_count = 0u;
    s_watchdog_snapshot.last_check_monotonic_ns = 0u;
    s_watchdog_snapshot.last_exception_verify_count = 0u;
    s_watchdog_snapshot.last_exception_reclaim_count = 0u;
    s_watchdog_snapshot.last_exception_startup_delta_ns = 0u;
    s_watchdog_snapshot.last_signal_probe_result = 0u;
    s_watchdog_snapshot.last_hardware_bp_detected = 0u;
    s_watchdog_snapshot.last_software_bp_detected = 0u;
    s_watchdog_snapshot.last_csops_debugged = 0u;
    s_watchdog_snapshot.last_suspicious_thread_count = 0u;
    s_watchdog_snapshot.last_single_step_detected = 0u;
    s_watchdog_snapshot.last_tty_detected = 0u;
    s_watchdog_snapshot.last_developer_disk_detected = 0u;
    s_watchdog_snapshot.last_exception_delivery_timeout_detected = 0u;
    s_watchdog_snapshot.last_exception_delivery_probe_handled = 0u;
    s_watchdog_snapshot.last_exception_delivery_probe_ns = 0u;
    s_watchdog_snapshot.signal_probe_anomaly_count = 0u;
    s_watchdog_snapshot.hardware_bp_anomaly_count = 0u;
    s_watchdog_snapshot.software_bp_anomaly_count = 0u;
    s_watchdog_snapshot.csops_anomaly_count = 0u;
    s_watchdog_snapshot.suspicious_thread_anomaly_count = 0u;
    s_watchdog_snapshot.exception_delivery_timeout_anomaly_count = 0u;
    s_watchdog_snapshot.peer_watchdog_anomaly_count = 0u;
    s_watchdog_snapshot.shadow_stack_anomaly_count = 0u;
    s_watchdog_snapshot.last_peer_watchdog_stalled = 0u;
    s_watchdog_snapshot.last_shadow_stack_mismatch = 0u;
    s_watchdog_snapshot.last_dbi_detected = 0u;
    s_watchdog_snapshot.last_dbi_marker_flags = 0u;
    s_watchdog_snapshot.last_timing_anomaly_flags = 0u;
    s_watchdog_snapshot.last_timing_probe_median_ns = 0u;
    s_watchdog_snapshot.last_timing_probe_max_ns = 0u;
    s_watchdog_snapshot.last_timing_probe_threshold_ns = 0u;
    s_watchdog_snapshot.dbi_anomaly_count = 0u;
    s_watchdog_snapshot.timing_anomaly_count = 0u;
    s_watchdog_snapshot.prologue_integrity_anomaly_count = 0u;
    s_watchdog_snapshot.dyld_injection_anomaly_count = 0u;
    s_watchdog_snapshot.last_prologue_fail_mask = 0u;
    s_watchdog_snapshot.last_dyld_injection_flags = 0u;
    s_watchdog_snapshot.last_csops_status_flags = 0u;
    s_watchdog_snapshot.last_amfi_probe_bits = 0u;
    s_watchdog_snapshot.last_get_task_allow_suspect = 0u;
    s_watchdog_snapshot.last_deny_attach_verify_bits = 0u;
    s_watchdog_snapshot.deny_attach_verify_anomaly_count = 0u;
    s_watchdog_snapshot.amfi_cs_flags_anomaly_count = 0u;
    s_watchdog_snapshot.get_task_allow_anomaly_count = 0u;
    s_watchdog_snapshot.vm_mprotect_crosscheck_mismatch_total = 0u;
    s_watchdog_snapshot.vm_mprotect_mach_trap_mismatch_total = 0u;
    s_watchdog_snapshot.watchdog_start_path_mask = 0u;
    s_watchdog_snapshot.watchdog_startup_liveness_ok = 0u;
    s_watchdog_snapshot.main_thread_alive_monotonic_ns = 0u;
    s_watchdog_snapshot.early_injection_env_mask = 0u;
    s_watchdog_snapshot.watchdog_extended_anomaly_flags = 0u;
    s_watchdog_snapshot.main_thread_heartbeat_seq = 0u;
    s_watchdog_snapshot.main_thread_heartbeat_stall_count = 0u;
    s_watchdog_snapshot.last_main_thread_heartbeat_stalled = 0u;
    atomic_store(&s_watchdog_main_alive_ns, 0u);
    atomic_store(&s_watchdog_main_heartbeat_seq, 0u);
    atomic_store(&s_watchdog_main_stall_consecutive, 0u);
    atomic_store(&s_watchdog_main_stall_latched, 0u);
    atomic_store(&s_watchdog_dyld_flags, 0u);
    atomic_store(&s_watchdog_dyld_suspicious_events, 0ull);
    cprisk_watchdog_reset_mailboxes_locked();
    /* Intentionally retain prologue / pthread_create / dlsym baselines across restarts (early ctor snapshot). */
}

// worker 轮询停止请求；只读原子量、不持锁，因此可在任意睡眠分片/迭代边界调用。
static int cprisk_watchdog_should_stop(void) {
    return atomic_load(&s_watchdog_stop_requested) != 0;
}

// 公开只读探针：供 VM/文本加密等长任务查询 watchdog 是否正在停止，以便尽快让出。
int cprisk_watchdog_probe_should_stop(void) {
    return cprisk_watchdog_should_stop();
}

// 释放并清空两个 mailbox 接收端口及序号/时间状态。只允许持锁调用。
// 端口用 mach_port_deallocate 归还本进程命名权；置 NULL 后所有 peer 校验短路（fail-open）。
static void cprisk_watchdog_reset_mailboxes_locked(void) {
    atomic_store(&s_watchdog_mailbox_ready, 0u);
    for (uint32_t i = 0u; i < CPRISK_WATCHDOG_THREAD_COUNT; i++) {
        if (s_watchdog_mailbox_ports[i] != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), s_watchdog_mailbox_ports[i]);
            s_watchdog_mailbox_ports[i] = MACH_PORT_NULL;
        }
        atomic_store(&s_watchdog_mailbox_last_recv_ns[i], 0u);
        s_watchdog_mailbox_send_seq[i] = 0u;
        atomic_store(&s_watchdog_mailbox_last_peer_seq[i], 0u);
        atomic_store(&s_watchdog_mailbox_peer_seq_initialized[i], 0u);
    }
}

// 为每个 worker 分配接收端口并插入 SEND 权，供 peer 投递心跳。
// 任一步失败则整体回滚并返回 -1；start 会忽略该失败，watchdog 继续运行，
// 只是 peer mailbox 交叉校验被跳过（fail-open）。
static int cprisk_watchdog_init_mailboxes_locked(void) {
    cprisk_watchdog_reset_mailboxes_locked();
    for (uint32_t i = 0u; i < CPRISK_WATCHDOG_THREAD_COUNT; i++) {
        mach_port_t port = MACH_PORT_NULL;
        kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
        if (kr != KERN_SUCCESS) {
            cprisk_watchdog_reset_mailboxes_locked();
            return -1;
        }
        kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
        if (kr != KERN_SUCCESS) {
            mach_port_deallocate(mach_task_self(), port);
            cprisk_watchdog_reset_mailboxes_locked();
            return -1;
        }
        s_watchdog_mailbox_ports[i] = port;
        atomic_store(&s_watchdog_mailbox_last_recv_ns[i], 0u);
        s_watchdog_mailbox_send_seq[i] = 0u;
        atomic_store(&s_watchdog_mailbox_last_peer_seq[i], 0u);
        atomic_store(&s_watchdog_mailbox_peer_seq_initialized[i], 0u);
    }
    atomic_store(&s_watchdog_mailbox_ready, 1u);
    return 0;
}

// 除共享心跳外的 Mach 层交叉校验：接收端口是否仍归本进程、peer 线程是否可查询、
// suspend_count 是否为 0（调试器 thread_suspend 会使其大于 0）。
// 仅在 mailbox 就绪、peer 已 active 且确实创建过时才检查；任一前置不满足直接返回 0，
// 避免半启动/单 worker 降级模式误报。返回 1=可疑。
/*
 * Mach cross-check beyond pthread heartbeats: receive port ownership, peer thread
 * suspend count (debugger/thread_suspend), and mailbox monotonic sequence (replay).
 */
static int cprisk_watchdog_mach_peer_verify_i(uint32_t worker_id) {
    if (atomic_load_explicit(&s_watchdog_mailbox_ready, memory_order_acquire) == 0u) {
        return 0;
    }
    mach_port_t recv = s_watchdog_mailbox_ports[worker_id];
    if (recv != MACH_PORT_NULL) {
        mach_port_type_t ptypes = 0;
        if (mach_port_type(mach_task_self(), recv, &ptypes) != KERN_SUCCESS ||
            (ptypes & MACH_PORT_TYPE_RECEIVE) == 0) {
            return 1;
        }
    }
    const uint32_t peer_id =
        worker_id == CPRISK_WATCHDOG_PRIMARY_ID
            ? CPRISK_WATCHDOG_SECONDARY_ID
            : CPRISK_WATCHDOG_PRIMARY_ID;
    if (atomic_load(&s_watchdog_worker_active[peer_id]) == 0u) {
        return 0;
    }
    if ((s_watchdog_started_mask & (1u << peer_id)) == 0u) {
        return 0;
    }
    const pthread_t peer_pt = s_watchdog_threads[peer_id];
    thread_t peer_thr = pthread_mach_thread_np(peer_pt);
    if (peer_thr == MACH_PORT_NULL) {
        return 1;
    }
    thread_basic_info_data_t bi;
    mach_msg_type_number_t bicount = THREAD_BASIC_INFO_COUNT;
    if (thread_info(peer_thr, THREAD_BASIC_INFO, (thread_info_t)&bi, &bicount) != KERN_SUCCESS) {
        return 1;
    }
// 被调试器挂起的线程 suspend_count 非 0；这是 peer 停滞最直接的 Mach 证据。
    if (bi.suspend_count != 0) {
        return 1;
    }
    return 0;
}

// 向 peer 的接收端口发送心跳（含 worker_id 与单调序号）。
// 使用 COPY_SEND 与超时为 0 的 MACH_SEND_TIMEOUT，避免阻塞检测线程；发送失败不报错，
// 由接收侧“长时间没收到”统一判定。
static void cprisk_watchdog_mailbox_send_i(uint32_t worker_id) {
    if (atomic_load_explicit(&s_watchdog_mailbox_ready, memory_order_acquire) == 0u) {
        return;
    }
    const uint32_t peer_id =
        worker_id == CPRISK_WATCHDOG_PRIMARY_ID
            ? CPRISK_WATCHDOG_SECONDARY_ID
            : CPRISK_WATCHDOG_PRIMARY_ID;
    mach_port_t remote = s_watchdog_mailbox_ports[peer_id];
    if (remote == MACH_PORT_NULL) {
        return;
    }
    cprisk_watchdog_mailbox_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_size = (mach_msg_size_t)sizeof(msg);
    msg.header.msgh_remote_port = remote;
    msg.header.msgh_local_port = MACH_PORT_NULL;
    msg.header.msgh_id = 0x43505744; /* "CPWD" */
    msg.worker_id = worker_id;
    msg.sequence = ++s_watchdog_mailbox_send_seq[worker_id];
    (void)mach_msg(&msg.header,
                   MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                   msg.header.msgh_size,
                   0,
                   MACH_PORT_NULL,
                   0,
                   MACH_PORT_NULL);
}

// 非阻塞排空本 worker 的接收端口（最多 4 条，超时 0），避免消息积压拖慢一轮检测。
// 校验 msgh_id、worker_id 与序号：id 不对忽略；worker_id 不对或序号不前进说明
// 消息被重放/伪造/乱序，置 peer stall 闩锁。
static void cprisk_watchdog_mailbox_drain_i(uint32_t worker_id, uint64_t now_ns) {
    if (atomic_load_explicit(&s_watchdog_mailbox_ready, memory_order_acquire) == 0u) {
        return;
    }
    mach_port_t recv_port = s_watchdog_mailbox_ports[worker_id];
    if (recv_port == MACH_PORT_NULL) {
        return;
    }
    for (uint32_t i = 0u; i < 4u; i++) {
        cprisk_watchdog_mailbox_msg_t msg;
        memset(&msg, 0, sizeof(msg));
        kern_return_t kr = mach_msg(&msg.header,
                                    MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                    0,
                                    (mach_msg_size_t)sizeof(msg),
                                    recv_port,
                                    0,
                                    MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            break;
        }
        if (msg.header.msgh_id == 0x43505744) {
            const uint32_t peer_id =
                worker_id == CPRISK_WATCHDOG_PRIMARY_ID
                    ? CPRISK_WATCHDOG_SECONDARY_ID
                    : CPRISK_WATCHDOG_PRIMARY_ID;
            if (msg.worker_id != peer_id) {
                cprisk_watchdog_mark_peer_stall_i();
            } else {
                const uint32_t prev = atomic_load_explicit(
                    &s_watchdog_mailbox_last_peer_seq[worker_id], memory_order_relaxed);
                const uint32_t inited = atomic_load_explicit(
                    &s_watchdog_mailbox_peer_seq_initialized[worker_id], memory_order_relaxed);
                if (inited == 0u) {
                    atomic_store_explicit(
                        &s_watchdog_mailbox_last_peer_seq[worker_id], msg.sequence, memory_order_relaxed);
                    atomic_store_explicit(
                        &s_watchdog_mailbox_peer_seq_initialized[worker_id], 1u, memory_order_release);
                } else {
                    if (msg.sequence <= prev) {
                        cprisk_watchdog_mark_peer_stall_i();
                    }
                    atomic_store_explicit(
                        &s_watchdog_mailbox_last_peer_seq[worker_id], msg.sequence, memory_order_relaxed);
                }
            }
            atomic_store(&s_watchdog_mailbox_last_recv_ns[worker_id], now_ns);
        }
    }
}

// 选择下一轮间隔。有异常时用短区间 150–400ms 加快确认；正常时在 300±100ms 抖动，
// 下限夹到 150ms，防止随机偏移把周期压得过短。
static uint32_t cprisk_watchdog_pick_interval_ms_i(uint32_t anomaly_flags) {
    const uint64_t rnd = cprisk_watchdog_random_u64_i();
    if (anomaly_flags != CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_NONE) {
        const uint32_t span =
            CPRISK_WATCHDOG_SHORT_INTERVAL_MAX_MS - CPRISK_WATCHDOG_SHORT_INTERVAL_MIN_MS + 1u;
        return CPRISK_WATCHDOG_SHORT_INTERVAL_MIN_MS + (uint32_t)(rnd % span);
    }

    const uint32_t span = CPRISK_WATCHDOG_INTERVAL_JITTER_MS * 2u + 1u;
    const int32_t offset = (int32_t)(rnd % span) - (int32_t)CPRISK_WATCHDOG_INTERVAL_JITTER_MS;
    int32_t candidate = (int32_t)CPRISK_WATCHDOG_DEFAULT_INTERVAL_MS + offset;
    if (candidate < (int32_t)CPRISK_WATCHDOG_SHORT_INTERVAL_MIN_MS) {
        candidate = (int32_t)CPRISK_WATCHDOG_SHORT_INTERVAL_MIN_MS;
    }
    return (uint32_t)candidate;
}

// 按 100ms 分片睡眠，每片检查 stop 请求；不依赖单次 nanosleep 的精度，
// 也不让 stop 等待完整轮询周期。elapsed 按分片名义值累加，实际时长略长于目标间隔。
static void cprisk_watchdog_sleep_interval_ms_i(uint32_t interval_ms) {
    struct timespec req;
    req.tv_sec = 0;
    req.tv_nsec = CPRISK_WATCHDOG_SLEEP_SLICE_NS;
    uint32_t elapsed = 0u;
    while (elapsed < interval_ms) {
        if (cprisk_watchdog_should_stop()) {
            return;
        }
        nanosleep(&req, NULL);
        elapsed += 100u;
    }
}

// 发布本轮预算的绝对截止时间：3×间隔，且不低于 3.5s。
// peer 侧用该 deadline 判断“已明显超时”，与固定阈值配合降低边界误报。
static void cprisk_watchdog_publish_deadline_i(uint32_t worker_id, uint32_t interval_ms) {
    const uint64_t now_ns = cprisk_monotonic_time_ns();
    uint64_t budget_ns = (uint64_t)interval_ms * 3ull * 1000000ull;
    if (budget_ns < CPRISK_WATCHDOG_PEER_STALL_MIN_NS) {
        budget_ns = CPRISK_WATCHDOG_PEER_STALL_MIN_NS;
    }
    atomic_store(&s_watchdog_deadline_ns[worker_id], now_ns + budget_ns);
}

// 判断 peer 是否停滞。证据取共享 heartbeat 与 mailbox 最近接收时间的较新者；
// peer 未 active、时间未知或时钟倒退时返回 0（fail-open）。
// 阈值：2×间隔且不低于 3.5s；若 peer 自己发布的 deadline 已过且停滞超过阈值一半，
// 可提前判定，减少调度抖动造成的漏报。
static int cprisk_watchdog_peer_stalled_i(uint32_t worker_id, uint32_t interval_ms) {
    const uint32_t peer_id =
        worker_id == CPRISK_WATCHDOG_PRIMARY_ID
            ? CPRISK_WATCHDOG_SECONDARY_ID
            : CPRISK_WATCHDOG_PRIMARY_ID;
    if (atomic_load(&s_watchdog_worker_active[peer_id]) == 0u) {
        return 0;
    }

    const uint64_t now_ns = cprisk_monotonic_time_ns();
    uint64_t peer_ns = atomic_load(&s_watchdog_heartbeat_ns[peer_id]);
    const uint64_t peer_mailbox_ns = atomic_load(&s_watchdog_mailbox_last_recv_ns[worker_id]);
    if (peer_mailbox_ns != 0u && now_ns > peer_mailbox_ns) {
        peer_ns = peer_mailbox_ns;
    }
    const uint64_t peer_deadline_ns = atomic_load(&s_watchdog_deadline_ns[peer_id]);
    if (peer_ns == 0u || now_ns <= peer_ns) {
        return 0;
    }

    uint64_t threshold_ns = (uint64_t)interval_ms * 2ull * 1000000ull;
    if (threshold_ns < CPRISK_WATCHDOG_PEER_STALL_MIN_NS) {
        threshold_ns = CPRISK_WATCHDOG_PEER_STALL_MIN_NS;
    }
    if (peer_deadline_ns != 0u && now_ns > peer_deadline_ns &&
        (now_ns - peer_ns) > (threshold_ns / 2ull)) {
        return 1;
    }
    return (now_ns - peer_ns) > threshold_ns ? 1 : 0;
}

// 置一次性闩锁供主 worker 下一轮消费，同时立即投毒并更新快照。
// 先投毒再拿锁：投毒路径不应被快照锁阻塞；快照更新只是取证。
static void cprisk_watchdog_mark_peer_stall_i(void) {
    atomic_store(&s_watchdog_peer_stall_latch, 1u);
    cprisk_integrity_poison_watchdog_lane_now();

    pthread_mutex_lock(&s_watchdog_mutex);
    s_watchdog_snapshot.anomaly_flags |=
        CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL;
    s_watchdog_snapshot.last_peer_watchdog_stalled = 1u;
    s_watchdog_snapshot.peer_watchdog_anomaly_count += 1u;
    pthread_mutex_unlock(&s_watchdog_mutex);
}

// 主线程停滞只写扩展异常位（base 位已满），并立即 staged 投毒。
// 与 peer stall 不同，这里没有一次性闩锁消费，靠 main_stall_latched 防止重复上报。
static void cprisk_watchdog_mark_main_thread_stall_i(void) {
    pthread_mutex_lock(&s_watchdog_mutex);
    s_watchdog_snapshot.watchdog_extended_anomaly_flags |=
        CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXT_MAIN_THREAD_STALL;
    s_watchdog_snapshot.last_main_thread_heartbeat_stalled = 1u;
    s_watchdog_snapshot.main_thread_heartbeat_stall_count += 1u;
    pthread_mutex_unlock(&s_watchdog_mutex);
    cprisk_integrity_poison_watchdog_lane_now();
}

// 主 worker 每轮调用：比较主线程心跳时间与当前时间。
// 心跳在 10s 内则清除连续计数与闩锁；超过阈值时累计，连续 2 次才置位，
// 并用 atomic_exchange 保证一次停滞只上报一次。时钟倒退或从未 ping 时直接返回（fail-open）。
static void cprisk_watchdog_verify_main_thread_heartbeat_i(void) {
    const uint64_t now_ns = cprisk_monotonic_time_ns();
    const uint64_t last_ns = atomic_load_explicit(&s_watchdog_main_alive_ns, memory_order_acquire);
    if (last_ns == 0u) {
        return;
    }
    if (now_ns < last_ns) {
        return;
    }
    const uint64_t age_ns = now_ns - last_ns;
    if (age_ns <= CPRISK_WATCHDOG_MAIN_THREAD_STALL_NS) {
        atomic_store_explicit(&s_watchdog_main_stall_consecutive, 0u, memory_order_relaxed);
        atomic_store_explicit(&s_watchdog_main_stall_latched, 0u, memory_order_release);
        pthread_mutex_lock(&s_watchdog_mutex);
        s_watchdog_snapshot.last_main_thread_heartbeat_stalled = 0u;
        pthread_mutex_unlock(&s_watchdog_mutex);
        return;
    }
    const uint32_t streak =
        atomic_fetch_add_explicit(&s_watchdog_main_stall_consecutive, 1u, memory_order_relaxed) + 1u;
    if (streak < CPRISK_WATCHDOG_MAIN_THREAD_STALL_CONFIRM_TICKS) {
        return;
    }
    if (atomic_exchange_explicit(&s_watchdog_main_stall_latched, 1u, memory_order_acq_rel) != 0u) {
        return;
    }
    cprisk_watchdog_mark_main_thread_stall_i();
}

// 副 worker 的轻量检测轮：不重复主 worker 的完整探测，只做随机文本 BRK 采样、单步、
// 时序回读与 shadow 检查，并继承主 worker 的 peer-stall 证据。
// 高置信异常立即投毒，其余走 staged；结果合并进快照后返回本轮异常位。
// 设计目的：即使主 worker 被挂起/拦截，副 worker 仍提供独立的采样面。
static uint32_t cprisk_watchdog_run_secondary_iteration_i(uint32_t inherited_flags) {
    // 每轮入口先取 shadow 令牌，用来在函数返回前确认栈帧未被改写。
    const cprisk_shadow_token_t shadow_token = cprisk_shadow_push_i();
    uint32_t anomaly_flags =
        inherited_flags & CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL;

    if (cprisk_is_being_traced_sysctl_only() != 0 || cprisk_mach_trace_suspicious() != 0) {
        anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED;
        cprisk_integrity_poison_high_signal_mixed(0x5EC02u);
    }

    const int software_bp = cprisk_scan_software_breakpoints_randomized_text(
        CPRISK_WATCHDOG_RANDOM_TEXT_WINDOWS / 2u,
        CPRISK_WATCHDOG_RANDOM_TEXT_WINDOW_BYTES / 2u
    );
    const int single_step = cprisk_detect_single_stepping();
    const uint32_t timing_anomaly_flags = cprisk_get_last_timing_anomaly_flags();
    const uint64_t timing_median_ns = cprisk_get_last_timing_probe_median_ns();
    const uint64_t timing_max_ns = cprisk_get_last_timing_probe_max_ns();
    const uint64_t timing_threshold_ns = cprisk_get_last_timing_probe_threshold_ns();
    int shadow_mismatch = 0;

    // 副 worker 只采一半窗口（12×512B），阈值仍是 4：宁可漏报也不引入单条 BRK 的误报。
    if (software_bp >= CPRISK_WATCHDOG_SOFTWARE_BP_STRONG_THRESHOLD) {
        anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SOFTWARE_BP;
    }
    if (cprisk_scan_instant_return_key_symbols_prefix() != 0) {
        anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_INSTANT_RETURN_PATCH;
    }
    if (single_step != 0) {
        anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SINGLE_STEP;
    }
    if (timing_anomaly_flags != 0u) {
        anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TIMING_SIDECHANNEL;
    }
    if (!cprisk_shadow_check_i(shadow_token)) {
        anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SHADOW_STACK;
        shadow_mismatch = 1;
        atomic_store(&s_watchdog_shadow_stack_latch, 1u);
    }

    // 高置信证据立即投毒；其余（如时序/单步）走 staged，避免一次抖动直接触发强响应。
    if (anomaly_flags != CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_NONE) {
        if ((anomaly_flags & CPRISK_WD_HIGH_RISK_POISON_MASK) != 0u) {
            cprisk_integrity_poison_high_signal_mixed(0x5EC12u);
        } else {
            cprisk_integrity_poison_watchdog_lane();
        }
    }

    // 快照更新统一放在锁内，保证读方看不到半更新的计数与位。
    pthread_mutex_lock(&s_watchdog_mutex);
    if ((anomaly_flags & CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SOFTWARE_BP) != 0u) {
        s_watchdog_snapshot.last_software_bp_detected = 1u;
        s_watchdog_snapshot.software_bp_anomaly_count += 1u;
    }
    if ((anomaly_flags & CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SINGLE_STEP) != 0u) {
        s_watchdog_snapshot.last_single_step_detected = 1u;
    }
    s_watchdog_snapshot.last_timing_anomaly_flags = timing_anomaly_flags;
    s_watchdog_snapshot.last_timing_probe_median_ns = timing_median_ns;
    s_watchdog_snapshot.last_timing_probe_max_ns = timing_max_ns;
    s_watchdog_snapshot.last_timing_probe_threshold_ns = timing_threshold_ns;
    if ((anomaly_flags & CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TIMING_SIDECHANNEL) != 0u) {
        s_watchdog_snapshot.timing_anomaly_count += 1u;
    }
    if (shadow_mismatch != 0) {
        s_watchdog_snapshot.last_shadow_stack_mismatch = 1u;
        s_watchdog_snapshot.shadow_stack_anomaly_count += 1u;
    }
    if ((anomaly_flags & CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL) != 0u) {
        s_watchdog_snapshot.last_peer_watchdog_stalled = 1u;
        s_watchdog_snapshot.peer_watchdog_anomaly_count += 1u;
    }
    s_watchdog_snapshot.anomaly_flags |= anomaly_flags;
    pthread_mutex_unlock(&s_watchdog_mutex);

    return anomaly_flags;
}

// 主 worker 的一轮完整检测。组织顺序：先做与 cadence 无关的固定校验（序言/SVC/mprotect），
// 再按 mid/low 节奏执行昂贵探测，最后统一聚合异常位、投毒并写快照。
// 参数 run_mid_checks / run_low_checks 由 thread_main_impl 按 3/9 轮节奏计算；
// dbi 检查在任一节奏命中时执行。返回值是本轮异常位（不含历史 sticky 位）。
// CFF 状态机（0x11→…→0x16，0x18 为假路径）只是控制流混淆，不改变检测语义。
static uint32_t cprisk_watchdog_run_iteration_i(int run_mid_checks, int run_low_checks) {
    // 本轮入口令牌；函数返回前会再校验一次，检测栈帧是否被改写。
    const cprisk_shadow_token_t shadow_token = cprisk_shadow_push_i();
    int deny_errno = 0;
    int deny_result = 0;
    int deny_verify_suspicious = 0;
    uint32_t deny_verify_bits = 0u;
    uint32_t csops_flags_snapshot = 0u;
    uint32_t amfi_probe_bits = 0u;
    uint32_t get_task_allow_suspect = 0u;
    int traced = 0;
    int traced_sys = 0;
    int traced_mach = 0;
    int trace_crosscheck = 0;
    cprisk_exception_handler_snapshot_t exception_snapshot;
    memset(&exception_snapshot, 0, sizeof(exception_snapshot));
    uint32_t anomaly_flags = CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_NONE;
    int signal_probe = 0;
    int software_bp = 0;
    int software_bp_strong = 0;
    int instant_ret_patch = 0;
    int hw_bp = 0;
    int csops_dbg = 0;
    int suspicious_threads = 0;
    int single_step = 0;
    int dbi_markers = 0;
    int tty = 0;
    int dev_disk = 0;
    uint32_t dbi_marker_flags = 0u;
    uint32_t timing_anomaly_flags = 0u;
    uint64_t timing_median_ns = 0u;
    uint64_t timing_max_ns = 0u;
    uint64_t timing_threshold_ns = 0u;
    int exception_delivery_timeout = 0;
    int exception_delivery_probe_handled = 0;
    uint64_t exception_delivery_probe_ns = 0u;
    uint64_t poison_mix = cprisk_monotonic_time_ns();
    // 顺便驱动 __TEXT 加密服务的空闲清扫；不在检测线程里做重活。
    cprisk_text_encrypt_service_idle();
    // 自检漂移只记扩展位、不直接投毒：文本加密状态可能因合法 OTA/热更新短暂变化。
    const uint32_t text_encrypt_self_check_flags = cprisk_text_encrypt_self_check();
    int peer_stall = 0;
    int shadow_mismatch = 0;
    int thread_exception_ports = 0;
    const int mid_checks = run_mid_checks != 0;
    const int low_checks = run_low_checks != 0;
    const int dbi_checks = mid_checks || low_checks;
    const uint32_t seed = 0x6D8E41B7u;
    const uint32_t runtime_hint =
        (uint32_t)atomic_load(&s_watchdog_stop_requested) ^
        (uint32_t)poison_mix ^
        0x13579BDFu;
    uint32_t prologue_anom = 0u;
    uint32_t prologue_mask = 0u;
    // 序言校验每轮都做（固定 18 槽，成本低）；失败会置 FUNCTION_PROLOGUE 并立即投毒。
    cprisk_watchdog_verify_prologue_i(&prologue_anom, &prologue_mask);
    uint32_t dlsym_fail_mask = 0u;
    if (cprisk_watchdog_verify_dlsym_prologue_i(&dlsym_fail_mask) == 0) {
        prologue_anom |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE;
        prologue_mask |= dlsym_fail_mask;
    }
    uint32_t objc_dyld_hook_mask = 0u;
    if (cprisk_watchdog_verify_objc_msgsend_prologue_i(&objc_dyld_hook_mask) == 0) {
        prologue_anom |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE;
    }
    if (cprisk_watchdog_verify_dyld_image_count_prologue_i(&objc_dyld_hook_mask) == 0) {
        prologue_anom |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE;
    }
    if (objc_dyld_hook_mask != 0u) {
        prologue_mask |= objc_dyld_hook_mask;
    }
    uint32_t runtime_hook_export_mask = 0u;
    if (cprisk_watchdog_verify_runtime_hook_exports_i(&runtime_hook_export_mask) == 0) {
        prologue_anom |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE;
        prologue_mask |= runtime_hook_export_mask;
    }
    const uint32_t inline_gate_health_mask = cprisk_antidebug_inline_gate_health_mask();
    // 内联运行时门禁如果漂移/变为可写，说明 BRK 拦截点已被绕过；高置信，立即投毒。
    if (inline_gate_health_mask != 0u) {
        prologue_anom |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE;
        prologue_mask |= CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_INLINE_GATE;
        cprisk_integrity_poison_high_signal_mixed(0xA0ADu ^ inline_gate_health_mask);
    }
    uint32_t svc_stub_anom = 0u;
    // SVC 直调模板/deny-attach stub 的哈希不匹配，意味着系统调用路径可能已被替换。
    if (cprisk_verify_svc_stub_integrity() != 0u) {
        svc_stub_anom = CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SVC_STUB_INTEGRITY;
        cprisk_integrity_poison_high_signal_mixed(0xA001u);
    }
    uint32_t vm_image_whitelist_anom = 0u;
    const uint32_t vm_guard_tick = cprisk_memory_guard_image_vm_tick();
    // 镜像清单变化单独走 staged：推送/IM SDK 延迟加载、OTA 框架更新都会合法地新增 RX 镜像；
    // 只有名称匹配的注入工具（DYLD_INJECTION）才零容忍立即提交。
    if ((vm_guard_tick & (CPRISK_MEM_GUARD_TICK_IMAGE_LIST_CHANGED |
                          CPRISK_MEM_GUARD_TICK_UNKNOWN_EXECUTABLE_RX |
                          CPRISK_MEM_GUARD_TICK_EXECUTABLE_WRITE)) != 0u) {
        vm_image_whitelist_anom = CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_IMAGE_WHITELIST;
        /* Staged (not immediate): push/IM SDK late-loading and OTA framework updates
         * legitimately add new RX images after launch.  Only name-matched jailbreak
         * tools (DYLD_INJECTION) warrant zero-tolerance immediate commit.
         * Debug build default suppresses this through CPRISK_WD_POISON_SUPPRESSED();
         * set CPRISK_TEST_HARDENING=1 to exercise the staged path in dev. */
        if (!CPRISK_WD_POISON_SUPPRESSED()) {
            cprisk_integrity_poison_watchdog_lane();
        }
    }
    if (vm_image_whitelist_anom == 0u && low_checks) {
        const int layout_drift = cprisk_vm_dyld_image_layout_digest_differs_from_baseline();
        if (layout_drift == 1) {
            vm_image_whitelist_anom = CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_IMAGE_WHITELIST;
            /* Same staged rationale as above. */
            if (!CPRISK_WD_POISON_SUPPRESSED()) {
                cprisk_integrity_poison_watchdog_lane();
            }
        }
    }
    const uint32_t vm_cc_total = cprisk_get_vm_mprotect_crosscheck_mismatch_count();
    const uint32_t vm_mt_total = cprisk_get_vm_mprotect_mach_trap_mismatch_count();
    uint32_t vm_mprotect_anom = 0u;
    // POSIX mprotect 与 Mach VM 状态交叉计数不一致，通常意味着 mprotect 只改了表象。
    if (vm_cc_total > 0u || vm_mt_total > 0u) {
        vm_mprotect_anom = CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_MPROTECT_MACH_DIVERGENCE;
        cprisk_integrity_poison_high_signal_mixed(0xA004u);
    }
    const uint32_t dyld_flags_now = (uint32_t)atomic_load(&s_watchdog_dyld_flags);
    cprisk_cff_config_t cff_config;

    // 混淆配置：Feistel+S-box 编解码 + 函数表分派，避免线性 MBA 恒等式被代数化简。
    // symex_guard_budget 只在 Release 开启，Debug 保留可读性以便定位问题。
    memset(&cff_config, 0, sizeof(cff_config));
    cff_config.seed = seed;
    cff_config.runtime_salt = cprisk_cff_runtime_salt(seed, runtime_hint);
    cff_config.entry_state = 0x11u;
    cff_config.iteration_budget = 24u;
    cff_config.release_build = (uint8_t)CPRISK_CFF_RELEASE_BUILD;
    cff_config.enable_fake_states = (uint8_t)CPRISK_CFF_ENABLE_FAKE_STATE;
    /*
     * Prefer the non-linear Feistel+S-box codec on the watchdog hot path so
     * state I/O is no longer dominated by linear XOR-MBA identities that
     * GAMBA-style algebraic simplifiers are designed to collapse. Keep
     * mba_layers pinned high to retain the dual-dispatch decode path instead
     * of the mba_layers <= 1 shortcut.
     */
    cff_config.codec_style = (uint8_t)CPRISK_CFF_CODEC_STYLE_FEISTEL_SPN;
    /* Prefer real per-codec handler table dispatch (not only direct decode). */
    cff_config.dispatch_style = (uint8_t)CPRISK_CFF_DISPATCH_FN_TABLE;
    cff_config.mba_layers = 5u;
    cff_config.symex_guard_budget = CPRISK_CFF_RELEASE_BUILD ? 8u : 0u;
    cff_config.default_action = CPRISK_CFF_RELEASE_BUILD
        ? CPRISK_CFF_DEFAULT_POISON
        : CPRISK_CFF_DEFAULT_FAIL_CLOSED;

    CPR_CFF_BEGIN_EX(cff_config)
        // 状态 0x11：跟踪状态 / deny_attach / AMFI / 异常端口等基础探测。
        CPR_CFF_CASE(0x11u): {
            // deny_attach 是主动反附加；返回非 0 即 DENY_ATTACH。
            deny_result = cprisk_deny_attach_status(&deny_errno);
            traced_sys = cprisk_is_being_traced_sysctl_only();
            traced_mach = cprisk_mach_trace_suspicious();
            traced = cprisk_is_being_traced_redundant();
            trace_crosscheck = cprisk_trace_crosscheck_inconsistent();
            cprisk_amfi_entitlement_watchdog_probe(
                &csops_flags_snapshot,
                &get_task_allow_suspect,
                &amfi_probe_bits
            );
            // DENY_ATTACH_VERIFY：deny_attach 表面成功但事后 sysctl/Mach 校验矛盾，
            // 通常意味着 SVC 被 hook 拦截；这是安全关键位。
            deny_verify_suspicious = cprisk_deny_attach_effective_verify(
                deny_result,
                deny_errno,
                &deny_verify_bits
            );
            if (deny_result != 0) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH;
            }
            if (deny_verify_suspicious != 0) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH_VERIFY;
                if (!CPRISK_WD_POISON_SUPPRESSED()) {
                    cprisk_integrity_poison_high_signal_mixed(0xB101u);
                }
            }
            anomaly_flags |= cprisk_wd_amfi_flags_from_probe_bits_i(amfi_probe_bits);
            if (get_task_allow_suspect != 0u) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GET_TASK_ALLOW;
            }
            /* GET_TASK_ALLOW is always present in Debug/Adhoc entitlements; the
             * CPRISK_WD_POISON_SUPPRESSED() runtime gate prevents 100% false-positive
             * kills in developer builds by default while still allowing
             * CPRISK_TEST_HARDENING=1 to exercise the full response for regression
             * tests.  In Release the macro expands to constant 0 and the optimiser
             * fully elides the branch — same performance as the previous code. */
            // AMFI_CS_FLAGS / GET_TASK_ALLOW 的投毒在 Debug 下默认抑制，
            // 避免开发签名天然带 get-task-allow 造成 100% 误杀；异常位仍会记录。
            if ((anomaly_flags & (CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_AMFI_CS_FLAGS |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GET_TASK_ALLOW)) != 0u) {
                if (!CPRISK_WD_POISON_SUPPRESSED()) {
                    cprisk_integrity_poison_high_signal_mixed(0xB102u);
                }
            }
            // TRACED：冗余/快速/Mach 任一跟踪探测命中；同时累计 traced_event_count。
            if (traced != 0 || traced_sys != 0 || traced_mach != 0) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED;
            }
            // 快探测命中但冗余慢探测未命中，说明探测函数之一被 hook，单独标记 PROBE_DIVERGENCE。
            if ((traced_sys != 0 || traced_mach != 0) && traced == 0) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED_PROBE_DIVERGENCE;
                if (!CPRISK_WD_POISON_SUPPRESSED()) {
                    cprisk_integrity_poison_high_signal_mixed(0xB103u);
                }
            }
            // TRACE_CROSSCHECK：快/慢跟踪路径结论不一致，属于旁证，不单独升级为 HIGH_RISK。
            if (trace_crosscheck != 0) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACE_CROSSCHECK;
            }

            // 按预算随机走一次假状态，制造不可达/重复执行的控制流，干扰反编译。
            if (cprisk_cff_should_visit_fake_state(cpr_cff_ctx, cpr_cff_state_) &&
                cpr_cff_ctx->fake_state_budget != 0u) {
                cpr_cff_ctx->fake_state_budget -= 1u;
                CPR_CFF_GOTO(0x18u);
            }
            CPR_CFF_GOTO(0x12u);
        }

        // 状态 0x12：异常处理器端口校验。
        CPR_CFF_CASE(0x12u): {
            // 异常端口是 BRK/interpose 的核心防线：重新校验注册状态，并取回一致性快照。
            cprisk_verify_exception_handler();
            memset(&exception_snapshot, 0, sizeof(exception_snapshot));
            (void)cprisk_get_exception_handler_snapshot(&exception_snapshot);

            // 任一“端口被换/被回收/启动竞态/归属不符”都归入 EXCEPTION_PORT；
            // 查询失败单独归 EXCEPTION_QUERY。
            if (exception_snapshot.supported != 0u) {
                if (exception_snapshot.last_query_succeeded == 0u) {
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_QUERY;
                }
                if (exception_snapshot.last_hijack_detected != 0u ||
                    exception_snapshot.last_reclaim_attempted != 0u ||
                    exception_snapshot.last_race_detected != 0u ||
                    exception_snapshot.port_matches == 0u) {
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_PORT;
                }
            }
            // 线程级异常端口非 0：可能有人把 EXC_BREAKPOINT 直接挂到具体线程上截获探针。
            thread_exception_ports = cprisk_detect_thread_exception_ports();
            if (thread_exception_ports > 0) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_PORT;
            }
            CPR_CFF_GOTO(0x13u);
        }

        // 状态 0x13：按 cadence 执行断点/线程/DBI 等探测。
        CPR_CFF_CASE(0x13u): {
            // SIGTRAP 探测每轮都做（成本低）；被调试器截获时置 SIGNAL_PROBE。
            signal_probe = cprisk_probe_debugger_via_signal();
            // 昂贵探测只在 cadence 命中时执行，避免每轮都枚举线程/断点寄存器。
            if (mid_checks) {
                software_bp = cprisk_watchdog_scan_software_breakpoints_i();
                software_bp_strong = software_bp >= CPRISK_WATCHDOG_SOFTWARE_BP_STRONG_THRESHOLD;
                instant_ret_patch = cprisk_scan_instant_return_key_symbols_prefix();
                hw_bp = cprisk_detect_hardware_breakpoints();
                csops_dbg = cprisk_wd_csops_debug_probe_inline_i();
                suspicious_threads = cprisk_detect_suspicious_threads();
                single_step = cprisk_detect_single_stepping();
                timing_anomaly_flags = cprisk_get_last_timing_anomaly_flags();
                timing_median_ns = cprisk_get_last_timing_probe_median_ns();
                timing_max_ns = cprisk_get_last_timing_probe_max_ns();
                timing_threshold_ns = cprisk_get_last_timing_probe_threshold_ns();
            }
            // 更低频的 I/O/文件系统探测；仅在 9 轮节奏或被跟踪时执行。
            if (low_checks) {
                tty = cprisk_detect_tty_debug();
                dev_disk = cprisk_detect_developer_disk();
                exception_delivery_timeout = cprisk_probe_exception_delivery_timeout();
                exception_delivery_probe_handled =
                    cprisk_get_last_exception_delivery_probe_handled();
                exception_delivery_probe_ns =
                    cprisk_get_last_exception_delivery_probe_ns();
            }
            // DBI 检查随 mid/low 任一节奏执行：Frida/QBDI 类工具常同时留下标记与匿名 RX slab。
            if (dbi_checks) {
                dbi_markers = cprisk_detect_dbi_markers();
                dbi_marker_flags = cprisk_get_last_dbi_marker_flags();
            }
            CPR_CFF_GOTO(0x14u);
        }

        // 状态 0x14：把本轮局部探测结果统一映射为 base 异常位，并合并固定校验/闩锁证据。
        CPR_CFF_CASE(0x14u): {
            // 每个位只在这里归并，便于审计来源；新增探测位需同步加入 HIGH_RISK 集合。
            if (signal_probe != 0)
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SIGNAL_PROBE;
            // mid 检查位：HARDWARE_BP（调试寄存器）、CSOPS_DEBUGGED、SUSPICIOUS_THREAD、
            // SINGLE_STEP、TIMING_SIDECHANNEL、SOFTWARE_BP、INSTANT_RETURN_PATCH；
            // 只在 cadence 命中时更新，避免每轮枚举线程/断点寄存器。
            if (mid_checks) {
                if (software_bp_strong != 0)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SOFTWARE_BP;
                if (instant_ret_patch != 0)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_INSTANT_RETURN_PATCH;
                if (hw_bp != 0)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_HARDWARE_BP;
                if (csops_dbg != 0)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_CSOPS_DEBUGGED;
                if (suspicious_threads > 0)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SUSPICIOUS_THREAD;
                if (single_step != 0)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SINGLE_STEP;
                if (timing_anomaly_flags != 0u)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TIMING_SIDECHANNEL;
            }
            // low 检查位：TTY、DEVELOPER_DISK、EXCEPTION_DELIVERY_TIMEOUT；
            // 都是 I/O/文件系统级探测，放在 9 轮节奏以降低开销与误报。
            if (low_checks) {
                if (tty != 0)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TTY;
                if (dev_disk != 0)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DEVELOPER_DISK;
                // 异常投递超时：探针本应被自己的异常处理器接住；未接住/超时才说明
                // 投递链路被劫持或走了信号回退。
                if (exception_delivery_timeout != 0)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_DELIVERY_TIMEOUT;
            }
            // DBI 位：DBI_MARKER（工具标记命中）与 DBI_VM_TRACE_CORREL
            // （Stalker 类匿名 RX slab 与线程 PC 交叉关联）；后者是安全关键位。
            if (dbi_checks) {
                if (dbi_markers > 0 && dbi_marker_flags != 0u)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_MARKER;
                if ((dbi_marker_flags & CPRISK_DBI_MARKER_STALKER_CORREL) != 0u ||
                    (dbi_marker_flags & CPRISK_DBI_MARKER_ANON_EXEC_SLAB) != 0u) {
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_VM_TRACE_CORREL;
                }
            }

            // 序言/SVC/mprotect/镜像清单等位由上面的固定校验直接产出，这里统一合并。
            anomaly_flags |=
                prologue_anom | svc_stub_anom | vm_mprotect_anom | vm_image_whitelist_anom;
            if (dyld_flags_now != 0u) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DYLD_INJECTION;
            }

            // 同一轮内 shadow 不匹配：栈帧被改写或返回地址被替换。
            if (!cprisk_shadow_check_i(shadow_token)) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SHADOW_STACK;
                shadow_mismatch = 1;
            }
            // 消费副 worker/mailbox 留下的一次性 peer-stall 闩锁；exchange 保证只上报一次。
            if (atomic_exchange(&s_watchdog_peer_stall_latch, 0u) != 0u) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL;
                peer_stall = 1;
            }
            // 副 worker 发现的 shadow 不匹配同样通过闩锁交给主 worker 汇总。
            if (atomic_exchange(&s_watchdog_shadow_stack_latch, 0u) != 0u) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SHADOW_STACK;
                shadow_mismatch = 1;
            }

            if (cprisk_cff_should_visit_fake_state(cpr_cff_ctx, cpr_cff_state_) &&
                cpr_cff_ctx->fake_state_budget != 0u) {
                cpr_cff_ctx->fake_state_budget -= 1u;
                CPR_CFF_GOTO(0x18u);
            }
            CPR_CFF_GOTO(0x15u);
        }

        // 状态 0x15：按证据等级投毒。CFF 符号爆炸始终执行，真正的投毒/硬崩溃受抑制开关控制。
        CPR_CFF_CASE(0x15u): {
            // 高置信集合：命中即立即投毒。它与 0x11 的探测位一一对应，新增位必须两边同步。
            const uint32_t high_risk_flags =
                (CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_PORT |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED_PROBE_DIVERGENCE |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH_VERIFY |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_AMFI_CS_FLAGS |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GET_TASK_ALLOW |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DYLD_INJECTION |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SVC_STUB_INTEGRITY |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_MPROTECT_MACH_DIVERGENCE |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_VM_TRACE_CORREL |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_PAC_THREAD_ENTRY);
            /* CFF symbolic explosion is obfuscation-only (extra state transitions
             * and fake values) — it does not kill the app, so it stays active in
             * every build configuration.  Only the actual poison commit and the
             * optional hard-crash _exit() are gated by CPRISK_WD_POISON_SUPPRESSED(),
             * which is a compile-time constant 0 in Release and a cached env-var
             * check in Debug (default suppressed; set CPRISK_TEST_HARDENING=1 to
             * exercise the full response path during hardening verification). */
            // 符号爆炸只影响混淆强度、不杀进程，因此不受 CPRISK_WD_POISON_SUPPRESSED 控制。
            if ((anomaly_flags & high_risk_flags) != 0u) {
                cprisk_cff_trigger_symbolic_explosion(cpr_cff_ctx, anomaly_flags & high_risk_flags);
            }
            // 投毒分两级：HIGH_RISK 立即提交；其余组合证据走 staged lane。
            if ((anomaly_flags & (CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SIGNAL_PROBE |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SOFTWARE_BP |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_INSTANT_RETURN_PATCH |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_HARDWARE_BP |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_CSOPS_DEBUGGED |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_MARKER |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TIMING_SIDECHANNEL |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_DELIVERY_TIMEOUT |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SHADOW_STACK |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DYLD_INJECTION |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED_PROBE_DIVERGENCE |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH_VERIFY |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_AMFI_CS_FLAGS |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GET_TASK_ALLOW |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SVC_STUB_INTEGRITY |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_MPROTECT_MACH_DIVERGENCE |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_VM_TRACE_CORREL |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_PAC_THREAD_ENTRY |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_IMAGE_WHITELIST)) != 0u) {
                if (!CPRISK_WD_POISON_SUPPRESSED()) {
                    if ((anomaly_flags & CPRISK_WD_HIGH_RISK_POISON_MASK) != 0u) {
                        cprisk_integrity_poison_high_signal_mixed(0xCFF15u ^ anomaly_flags);
                        // 硬崩溃只在宿主显式开启时执行，且仅针对 HIGH_RISK；
                        // _exit 绕过 atexit/信号处理，避免退出路径本身被 hook。
                        /* Hard-crash mode: explicit _exit(3) after poison commit.
                         * Apps that prefer fail-fast over silent PRF corruption enable this
                         * via cprisk_set_hard_crash_mode(1).  _exit bypasses atexit handlers
                         * (which may be hooked) and delivers an immediate SIGKILL-equivalent. */
                        if (atomic_load_explicit(&s_hard_crash_mode, memory_order_relaxed) != 0) {
                            _exit(3);
                        }
                    } else if ((anomaly_flags & CPRISK_WD_POISON_TRIGGER_BUNDLE_MASK) != 0u) {
                        cprisk_integrity_poison_watchdog_lane();
                    }
                }
            }
            CPR_CFF_GOTO(0x16u);
        }

        // 状态 0x16：统一写快照。先累加计数/位，再覆盖本轮 last_*；临界区不执行探测或 I/O。
        CPR_CFF_CASE(0x16u): {
            pthread_mutex_lock(&s_watchdog_mutex);
            s_watchdog_snapshot.iteration_count += 1u;
            s_watchdog_snapshot.last_check_monotonic_ns = cprisk_monotonic_time_ns();
            s_watchdog_snapshot.last_deny_attach_result = deny_result;
            s_watchdog_snapshot.last_deny_attach_errno = deny_errno;
            s_watchdog_snapshot.last_traced = traced != 0 ? 1u : 0u;
            s_watchdog_snapshot.last_exception_port_healthy =
                (exception_snapshot.port_matches != 0u && thread_exception_ports == 0)
                    ? 1u : 0u;
            s_watchdog_snapshot.last_exception_query_succeeded = exception_snapshot.last_query_succeeded;
            s_watchdog_snapshot.last_exception_reclaim_attempted = exception_snapshot.last_reclaim_attempted;
            s_watchdog_snapshot.last_exception_hijack_detected = exception_snapshot.last_hijack_detected;
            s_watchdog_snapshot.last_exception_early_phase_captured = exception_snapshot.early_phase_captured;
            s_watchdog_snapshot.last_exception_startup_race_detected = exception_snapshot.last_race_detected;
            s_watchdog_snapshot.last_exception_query_kern_return = exception_snapshot.last_query_kern_return;
            s_watchdog_snapshot.last_exception_register_kern_return = exception_snapshot.last_register_kern_return;
            s_watchdog_snapshot.last_exception_verify_count = exception_snapshot.verify_count;
            s_watchdog_snapshot.last_exception_reclaim_count = exception_snapshot.reclaim_count;
            s_watchdog_snapshot.last_exception_startup_delta_ns =
                exception_snapshot.first_register_verify_delta_ns;
            // anomaly_flags 是粘性的：只 OR 不清零，只有下次 start 的 reset_locked 才清空。
            s_watchdog_snapshot.anomaly_flags |= anomaly_flags;
            s_watchdog_snapshot.vm_mprotect_crosscheck_mismatch_total = (uint64_t)vm_cc_total;
            s_watchdog_snapshot.vm_mprotect_mach_trap_mismatch_total = (uint64_t)vm_mt_total;
            if (deny_result != 0) {
                s_watchdog_snapshot.deny_attach_error_count += 1u;
            }
            if (traced != 0 || traced_sys != 0 || traced_mach != 0) {
                s_watchdog_snapshot.traced_event_count += 1u;
            }
            if ((anomaly_flags & (CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_PORT |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_QUERY |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_DELIVERY_TIMEOUT |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACE_CROSSCHECK |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH_VERIFY |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_AMFI_CS_FLAGS |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GET_TASK_ALLOW |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_MPROTECT_MACH_DIVERGENCE)) != 0u) {
                s_watchdog_snapshot.exception_anomaly_count += 1u;
            }
            s_watchdog_snapshot.last_signal_probe_result = signal_probe != 0 ? 1u : 0u;
            if (mid_checks) {
                s_watchdog_snapshot.last_hardware_bp_detected = hw_bp != 0 ? 1u : 0u;
                s_watchdog_snapshot.last_software_bp_detected = software_bp_strong != 0 ? 1u : 0u;
                s_watchdog_snapshot.last_csops_debugged = csops_dbg != 0 ? 1u : 0u;
                s_watchdog_snapshot.last_suspicious_thread_count =
                    (uint32_t)(suspicious_threads > 0 ? suspicious_threads : 0);
                s_watchdog_snapshot.last_single_step_detected = single_step != 0 ? 1u : 0u;
                s_watchdog_snapshot.last_timing_anomaly_flags = timing_anomaly_flags;
                s_watchdog_snapshot.last_timing_probe_median_ns = timing_median_ns;
                s_watchdog_snapshot.last_timing_probe_max_ns = timing_max_ns;
                s_watchdog_snapshot.last_timing_probe_threshold_ns = timing_threshold_ns;
            }
            if (low_checks) {
                s_watchdog_snapshot.last_tty_detected = tty != 0 ? 1u : 0u;
                s_watchdog_snapshot.last_developer_disk_detected = dev_disk != 0 ? 1u : 0u;
                s_watchdog_snapshot.last_exception_delivery_timeout_detected =
                    exception_delivery_timeout != 0 ? 1u : 0u;
                s_watchdog_snapshot.last_exception_delivery_probe_handled =
                    exception_delivery_probe_handled != 0 ? 1u : 0u;
                s_watchdog_snapshot.last_exception_delivery_probe_ns =
                    exception_delivery_probe_ns;
            }
            if (dbi_checks) {
                s_watchdog_snapshot.last_dbi_detected = dbi_markers > 0 ? 1u : 0u;
                s_watchdog_snapshot.last_dbi_marker_flags = dbi_marker_flags;
            }
            s_watchdog_snapshot.last_peer_watchdog_stalled = peer_stall != 0 ? 1u : 0u;
            s_watchdog_snapshot.last_shadow_stack_mismatch = shadow_mismatch != 0 ? 1u : 0u;
            // last_* 每轮覆盖为最新值；与粘性的 anomaly_flags 形成“历史 vs 当前”两层语义。
            s_watchdog_snapshot.last_prologue_fail_mask = prologue_mask;
            s_watchdog_snapshot.last_dyld_injection_flags = dyld_flags_now;
            s_watchdog_snapshot.last_csops_status_flags = csops_flags_snapshot;
            s_watchdog_snapshot.last_amfi_probe_bits = amfi_probe_bits;
            s_watchdog_snapshot.last_get_task_allow_suspect = get_task_allow_suspect;
            s_watchdog_snapshot.last_deny_attach_verify_bits = deny_verify_bits;
            // 文本加密自检漂移只写扩展位 EXT_TEXT_ENCRYPT_DRIFT，不进入 high-risk 投毒。
            if (text_encrypt_self_check_flags != CPRISK_TEXT_ENCRYPT_SELF_CHECK_FLAG_NONE) {
                s_watchdog_snapshot.watchdog_extended_anomaly_flags |=
                    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXT_TEXT_ENCRYPT_DRIFT;
            }
            // 导出面漂移写扩展位 EXT_RUNTIME_HOOK_EXPORT_DRIFT（base 位已满）。
            if (runtime_hook_export_mask != 0u) {
                s_watchdog_snapshot.watchdog_extended_anomaly_flags |=
                    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXT_RUNTIME_HOOK_EXPORT_DRIFT;
            }
            if (deny_verify_suspicious != 0) {
                s_watchdog_snapshot.deny_attach_verify_anomaly_count += 1u;
            }
            if ((anomaly_flags & CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_AMFI_CS_FLAGS) != 0u) {
                s_watchdog_snapshot.amfi_cs_flags_anomaly_count += 1u;
            }
            if ((anomaly_flags & CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GET_TASK_ALLOW) != 0u) {
                s_watchdog_snapshot.get_task_allow_anomaly_count += 1u;
            }
            s_watchdog_snapshot.dyld_injection_anomaly_count =
                (uint64_t)atomic_load(&s_watchdog_dyld_suspicious_events);
            if (prologue_mask != 0u) {
                s_watchdog_snapshot.prologue_integrity_anomaly_count += 1u;
            }
            if (signal_probe != 0)
                s_watchdog_snapshot.signal_probe_anomaly_count += 1u;
            if (mid_checks) {
                if (hw_bp != 0)
                    s_watchdog_snapshot.hardware_bp_anomaly_count += 1u;
                if (software_bp_strong != 0)
                    s_watchdog_snapshot.software_bp_anomaly_count += 1u;
                if (csops_dbg != 0)
                    s_watchdog_snapshot.csops_anomaly_count += 1u;
                if (suspicious_threads > 0)
                    s_watchdog_snapshot.suspicious_thread_anomaly_count += 1u;
                if (timing_anomaly_flags != 0u)
                    s_watchdog_snapshot.timing_anomaly_count += 1u;
            }
            if (low_checks) {
                if (exception_delivery_timeout != 0)
                    s_watchdog_snapshot.exception_delivery_timeout_anomaly_count += 1u;
            }
            if (dbi_checks) {
                if (dbi_markers > 0 && dbi_marker_flags != 0u)
                    s_watchdog_snapshot.dbi_anomaly_count += 1u;
            }
            if (shadow_mismatch != 0)
                s_watchdog_snapshot.shadow_stack_anomaly_count += 1u;
            pthread_mutex_unlock(&s_watchdog_mutex);
            CPR_CFF_RETURN(anomaly_flags);
        }

        // 状态 0x18：假路径。执行无副作用的 decoy 并扰动混入值，增加静态分析难度；
        // 随后回到 0x12 继续正常流程，因此不会跳过任何检测。
        CPR_CFF_CASE(0x18u): {
            cprisk_cff_run_fake_path_decoy(cpr_cff_ctx);
            poison_mix ^= ((uint64_t)anomaly_flags << 17u) ^
                          ((uint64_t)(signal_probe != 0) << 9u) ^
                          0x9E3779B97F4A7C15ULL;
            CPR_CFF_GOTO(0x12u);
        }
    CPR_CFF_END();
    return anomaly_flags;
}

// worker 主循环。启动时标记 active、写首个心跳/预算；每轮：
//   1) 检查 stop；2) 刷新心跳并互发 mailbox；3) Mach 层与时间阈值双重 peer 校验；
//   4) 主 worker 检查主线程心跳；5) 按 3/9 节奏决定 mid/low 检测；
//   6) 主 worker 跑完整迭代，副 worker 跑轻量迭代；7) 选下一轮间隔并分片睡眠。
// 退出前清零 active/心跳/deadline 并刷新快照，保证 stop 的 join 返回后状态一致。
static void *cprisk_watchdog_thread_main_impl(void *arg) {
    const uint32_t worker_id = (uint32_t)(uintptr_t)arg;
    // 先宣告 active 再发布心跳：start 的宽限期检查依赖它们判断 worker 是否真正跑起来。
    atomic_store(&s_watchdog_worker_active[worker_id], 1u);
    atomic_store(&s_watchdog_heartbeat_ns[worker_id], cprisk_monotonic_time_ns());
    cprisk_watchdog_publish_deadline_i(worker_id, CPRISK_WATCHDOG_DEFAULT_INTERVAL_MS);

    pthread_mutex_lock(&s_watchdog_mutex);
    cprisk_watchdog_refresh_thread_active_locked();
    pthread_mutex_unlock(&s_watchdog_mutex);

    uint32_t last_anomaly_flags = CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_NONE;
    uint32_t loop_counter = 0u;

    // 单层循环 + 原子 stop 轮询：不在条件变量上等待，停止请求不会被错过。
    for (;;) {
        if (cprisk_watchdog_should_stop()) {
            break;
        }

        const uint64_t now_ns = cprisk_monotonic_time_ns();
        // 每轮先写心跳，再互发 mailbox；两个证据通道独立，任一被拦截仍可由另一个发现停滞。
        atomic_store(&s_watchdog_heartbeat_ns[worker_id], now_ns);
        cprisk_watchdog_mailbox_send_i(worker_id);
        cprisk_watchdog_mailbox_drain_i(worker_id, now_ns);
        // Mach 层校验优先：端口/线程句柄级异常比时间阈值更直接。
        if (cprisk_watchdog_mach_peer_verify_i(worker_id) != 0) {
            cprisk_watchdog_mark_peer_stall_i();
            last_anomaly_flags |=
                CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL;
        }
        // 时间阈值兜底：对端还 active 但心跳/消息长期不更新，同样判停滞。
        if (cprisk_watchdog_peer_stalled_i(worker_id,
                                           CPRISK_WATCHDOG_DEFAULT_INTERVAL_MS) != 0) {
            cprisk_watchdog_mark_peer_stall_i();
            last_anomaly_flags |=
                CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL;
        }
        // 只有主 worker 负责主线程心跳，避免两个 worker 重复计数导致提前锁存。
        if (worker_id == CPRISK_WATCHDOG_PRIMARY_ID) {
            cprisk_watchdog_verify_main_thread_heartbeat_i();
        }

        // VM 同步屏障：让 VM 解释器的 barrier 步骤拿到新鲜 tick，避免其等待超时。
        /* VM sync barrier: advance external counter so VM barrier step has fresh data */
        cprisk_vm_sync_barrier_note_watchdog_tick();

        // cadence：3 轮一次中频、9 轮一次低频；上一轮有异常时中频改为每轮。
        loop_counter += 1u;
        const int run_mid_checks =
            ((loop_counter % CPRISK_WATCHDOG_MID_CADENCE) == 0u) ||
            (last_anomaly_flags != CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_NONE);
        const int run_low_checks =
            ((loop_counter % CPRISK_WATCHDOG_LOW_CADENCE) == 0u) ||
            ((last_anomaly_flags & (CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED |
                                    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_PORT |
                                    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACE_CROSSCHECK)) != 0u);

        // 主 worker 跑完整检测；副 worker 只跑轻量检测，但同样驱动文本加密空闲清扫。
        if (worker_id == CPRISK_WATCHDOG_PRIMARY_ID) {
            last_anomaly_flags = cprisk_watchdog_run_iteration_i(
                run_mid_checks,
                run_low_checks
            );
        } else {
            /* Pass12 __TEXT: same idle sweep as primary so plaintext pages are not
             * serviced only on the primary thread's jittered interval (~0.35–1.1s). */
            cprisk_text_encrypt_service_idle();
            if (run_mid_checks) {
                last_anomaly_flags = cprisk_watchdog_run_secondary_iteration_i(
                    last_anomaly_flags &
                    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL
                );
            } else {
                last_anomaly_flags &= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL;
            }
        }

        // 迭代可能耗时较长，结束后再检查一次 stop，避免白算下一轮间隔。
        if (cprisk_watchdog_should_stop()) {
            break;
        }

        const uint32_t interval_ms =
            cprisk_watchdog_pick_interval_ms_i(last_anomaly_flags);
        cprisk_watchdog_publish_deadline_i(worker_id, interval_ms);
        if (worker_id == CPRISK_WATCHDOG_PRIMARY_ID) {
            pthread_mutex_lock(&s_watchdog_mutex);
            // interval_seconds 只作展示：把毫秒向上取整为秒，抖动会让相邻读数值跳变。
            s_watchdog_snapshot.interval_seconds = (interval_ms + 999u) / 1000u;
            pthread_mutex_unlock(&s_watchdog_mutex);
        }
        cprisk_watchdog_sleep_interval_ms_i(interval_ms);
    }

    // 退出清理：先清 active/心跳/deadline，再持锁刷新 thread_active；读方随后只会看到未运行。
    atomic_store(&s_watchdog_worker_active[worker_id], 0u);
    atomic_store(&s_watchdog_heartbeat_ns[worker_id], 0u);
    atomic_store(&s_watchdog_deadline_ns[worker_id], 0u);
    pthread_mutex_lock(&s_watchdog_mutex);
    cprisk_watchdog_refresh_thread_active_locked();
    pthread_mutex_unlock(&s_watchdog_mutex);
    return NULL;
}

// 依次尝试三个已签名入口（thunk→bridge→impl），每个候选最多重试
// CPRISK_WATCHDOG_CREATE_RETRY_MAX 次。这样即使某一层入口被 patch/认证失败，
// 仍可能用更内层的合法入口把 watchdog 拉起来；全部失败才返回 -1。
static int cprisk_watchdog_pthread_create_with_fallbacks_i(
    uint32_t worker_id,
    uint32_t *path_bits_out,
    int *last_errno_out
) {
    void *const candidates[3] = {
        s_watchdog_thunk_signed_fp,
        s_watchdog_bridge_signed_fp,
        s_watchdog_impl_signed_fp,
    };
    const uint32_t bits[3] = {
        CPRISK_WATCHDOG_PATH_THUNK,
        CPRISK_WATCHDOG_PATH_BRIDGE,
        CPRISK_WATCHDOG_PATH_IMPL,
    };
    for (uint32_t i = 0u; i < 3u; i++) {
        void *fn = candidates[i];
        if (fn == NULL) {
            continue;
        }
        typedef void *(*cprisk_wd_pthread_fn)(void *);
        int rc = -1;
        // 首次尝试不 sleep，成功路径零延迟；失败后才按 100ms 间隔重试。
        /* Retry loop: absorbs transient EAGAIN and attacker-induced thread-create suppression.
         * Up to CPRISK_WATCHDOG_CREATE_RETRY_MAX additional attempts per candidate with
         * CPRISK_WATCHDOG_CREATE_RETRY_SLEEP_NS sleep between failures.
         * On the first attempt we skip the sleep to avoid adding latency on success paths. */
        for (uint32_t attempt = 0u; attempt <= CPRISK_WATCHDOG_CREATE_RETRY_MAX; attempt++) {
            if (attempt > 0u) {
                struct timespec ts = {0, CPRISK_WATCHDOG_CREATE_RETRY_SLEEP_NS};
                nanosleep(&ts, NULL);
            }
            rc = pthread_create(
                &s_watchdog_threads[worker_id],
                NULL,
                (cprisk_wd_pthread_fn)fn,
                (void *)(uintptr_t)worker_id);
            if (rc == 0) {
                break;
            }
        }
        if (last_errno_out != NULL) {
            *last_errno_out = rc;
        }
        if (rc == 0) {
            // 记录实际成功的入口层，写入 watchdog_start_path_mask 便于诊断降级。
            *path_bits_out |= bits[i];
            return 0;
        }
    }
    return -1;
}

// 启动宽限期检查：800ms 内轮询 iteration_count 或 thread_active，任一满足即认为
// worker 已运行；超时则置 STARTUP_LIVENESS 并 staged 投毒，但不让 start 失败——
// 这是“能检测就检测”的 fail-open 选择，避免慢设备正常启动被误杀。
static void cprisk_watchdog_wait_startup_liveness_i(void) {
    const uint64_t deadline = cprisk_monotonic_time_ns() + CPRISK_WATCHDOG_START_GRACE_NS;
    while (cprisk_monotonic_time_ns() < deadline) {
        pthread_mutex_lock(&s_watchdog_mutex);
        const uint64_t ic = s_watchdog_snapshot.iteration_count;
        const uint32_t ta = s_watchdog_snapshot.thread_active;
        pthread_mutex_unlock(&s_watchdog_mutex);
        if (ic > 0u || ta != 0u) {
            pthread_mutex_lock(&s_watchdog_mutex);
            s_watchdog_snapshot.watchdog_startup_liveness_ok = 1u;
            pthread_mutex_unlock(&s_watchdog_mutex);
            return;
        }
        struct timespec ts = {0, 5000000L};
        // 5ms 轮询粒度：足够及时，又不会在启动路径上忙等。
        nanosleep(&ts, NULL);
    }
    // 超时是攻击者 hook pthread_create 的强信号；这里只 staged，配合创建失败时的 fail-closed 返回。
    pthread_mutex_lock(&s_watchdog_mutex);
    s_watchdog_snapshot.anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_STARTUP_LIVENESS;
    s_watchdog_snapshot.watchdog_startup_liveness_ok = 0u;
    cprisk_integrity_poison_watchdog_lane();
    pthread_mutex_unlock(&s_watchdog_mutex);
}

// 主线程心跳入口：记录单调时间、递增序号，并同步到快照供诊断。
// 可被主线程高频调用：只做原子写与短临界区，不执行探测。
void cprisk_watchdog_note_main_thread_alive(void) {
    uint64_t t = cprisk_monotonic_time_ns();
    atomic_store(&s_watchdog_main_alive_ns, t);
    const uint64_t seq =
        atomic_fetch_add_explicit(&s_watchdog_main_heartbeat_seq, 1ull, memory_order_relaxed) + 1ull;
    pthread_mutex_lock(&s_watchdog_mutex);
    s_watchdog_snapshot.main_thread_alive_monotonic_ns = t;
    s_watchdog_snapshot.main_thread_heartbeat_seq = seq;
    pthread_mutex_unlock(&s_watchdog_mutex);
}

// 启动看门狗。幂等：已在 RUNNING/STOPPING 时直接返回 0。
// 顺序：重置状态→注册 dyld 观察者→分配 mailbox→预检 libsystem 序言/PAC 指针
//   →创建主 worker（必需）→创建副 worker（可选）→记录启动路径→快照布局基线
//   →解锁后等待启动活性→启动 anti-dump 探针→写入首个主线程心跳。
// 失败语义：序言/PAC 预检失败或主 worker 创建失败返回 -1 并置异常位（fail-closed）；
//   副 worker 创建失败只降级为单 worker，仍返回 0；mailbox 分配失败被忽略（fail-open）。
int cprisk_start_anti_debug_watchdog(void) {
    pthread_mutex_lock(&s_watchdog_mutex);
    // 幂等保护：重复 start 不创建第二批线程，也不重置已有异常证据。
    if (s_watchdog_state != CPRISK_WATCHDOG_STATE_STOPPED) {
        pthread_mutex_unlock(&s_watchdog_mutex);
        return 0;
    }

    // 每次真正启动都从干净状态开始；序言/入口基线数组不在此处清空（见 reset_locked）。
    cprisk_watchdog_reset_locked();
    s_watchdog_snapshot.running = 1u;
    s_watchdog_state = CPRISK_WATCHDOG_STATE_RUNNING;
    s_watchdog_started_mask = 0u;
    atomic_store(&s_watchdog_stop_requested, 0);
    atomic_store(&s_watchdog_peer_stall_latch, 0u);
    atomic_store(&s_watchdog_shadow_stack_latch, 0u);
    // 先注册观察者：启动过程中及之后的迟到镜像都能被记录。
    cprisk_watchdog_register_dyld_observer_once_i();
    for (uint32_t i = 0; i < CPRISK_WATCHDOG_THREAD_COUNT; i++) {
        atomic_store(&s_watchdog_worker_active[i], 0u);
        atomic_store(&s_watchdog_heartbeat_ns[i], 0u);
        atomic_store(&s_watchdog_deadline_ns[i], 0u);
    }
    // mailbox 是可选增强；失败时 peer 校验短路，watchdog 仍能靠共享心跳工作。
    (void)cprisk_watchdog_init_mailboxes_locked();

    uint32_t libsys_mask = 0u;
    // 预检 libsystem 关键入口：如果启动前就已被 hook，直接拒绝启动并留下 FUNCTION_PROLOGUE。
    if (cprisk_watchdog_verify_pthread_create_prologue_i(&libsys_mask) == 0) {
        s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPED;
        s_watchdog_snapshot.running = 0u;
        s_watchdog_snapshot.anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE;
        s_watchdog_snapshot.last_prologue_fail_mask = libsys_mask;
        s_watchdog_snapshot.prologue_integrity_anomaly_count += 1u;
        s_watchdog_snapshot.last_deny_attach_result = -1;
        s_watchdog_snapshot.last_deny_attach_errno = EACCES;
        pthread_mutex_unlock(&s_watchdog_mutex);
        return -1;
    }
    if (cprisk_watchdog_verify_dlsym_prologue_i(&libsys_mask) == 0) {
        s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPED;
        s_watchdog_snapshot.running = 0u;
        s_watchdog_snapshot.anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE;
        s_watchdog_snapshot.last_prologue_fail_mask = libsys_mask;
        s_watchdog_snapshot.prologue_integrity_anomaly_count += 1u;
        s_watchdog_snapshot.last_deny_attach_result = -1;
        s_watchdog_snapshot.last_deny_attach_errno = EACCES;
        pthread_mutex_unlock(&s_watchdog_mutex);
        return -1;
    }
    if (cprisk_watchdog_verify_objc_msgsend_prologue_i(&libsys_mask) == 0) {
        s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPED;
        s_watchdog_snapshot.running = 0u;
        s_watchdog_snapshot.anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE;
        s_watchdog_snapshot.last_prologue_fail_mask = libsys_mask;
        s_watchdog_snapshot.prologue_integrity_anomaly_count += 1u;
        s_watchdog_snapshot.last_deny_attach_result = -1;
        s_watchdog_snapshot.last_deny_attach_errno = EACCES;
        pthread_mutex_unlock(&s_watchdog_mutex);
        return -1;
    }
    if (cprisk_watchdog_verify_dyld_image_count_prologue_i(&libsys_mask) == 0) {
        s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPED;
        s_watchdog_snapshot.running = 0u;
        s_watchdog_snapshot.anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE;
        s_watchdog_snapshot.last_prologue_fail_mask = libsys_mask;
        s_watchdog_snapshot.prologue_integrity_anomaly_count += 1u;
        s_watchdog_snapshot.last_deny_attach_result = -1;
        s_watchdog_snapshot.last_deny_attach_errno = EACCES;
        pthread_mutex_unlock(&s_watchdog_mutex);
        return -1;
    }

    {
        // 重新计算 PAC 签名并与 constructor 缓存比对：缓存被改写或入口被替换都视为攻击。
        void *thunk_expect = cprisk_pac_sign_function_pointer(
            (const void *)&cprisk_watchdog_pthread_thunk,
            (uintptr_t)CPRISK_WATCHDOG_PTHREAD_THUNK_PAC_DISC);
        void *bridge_expect = cprisk_pac_sign_function_pointer(
            (const void *)&cprisk_watchdog_thread_main_bridge,
            (uintptr_t)CPRISK_WATCHDOG_PTHREAD_BRIDGE_PAC_DISC);
        void *impl_expect = cprisk_pac_sign_function_pointer(
            (const void *)&cprisk_watchdog_thread_main_impl,
            (uintptr_t)CPRISK_WATCHDOG_IMPL_PAC_DISC);
        if (s_watchdog_thunk_signed_fp != thunk_expect || s_watchdog_bridge_signed_fp != bridge_expect ||
            s_watchdog_impl_signed_fp != impl_expect) {
            s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPED;
            s_watchdog_snapshot.running = 0u;
            s_watchdog_snapshot.anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_PAC_THREAD_ENTRY;
            s_watchdog_snapshot.last_deny_attach_result = -1;
            s_watchdog_snapshot.last_deny_attach_errno = EACCES;
            pthread_mutex_unlock(&s_watchdog_mutex);
            return -1;
        }
    }

    uint32_t path_mask = 0u;
    int last_create_errno = 0;
    // 主 worker 是硬依赖：创建失败说明 pthread_create 被拦截，返回 -1（fail-closed）。
    if (cprisk_watchdog_pthread_create_with_fallbacks_i(
            CPRISK_WATCHDOG_PRIMARY_ID, &path_mask, &last_create_errno) != 0) {
        /*
         * Anti-debug review weakness #4: previously this path returned
         * -1 silently — callers who didn't check the return code would
         * see `running=0` but no explicit anomaly flag, indistinguishable
         * from "watchdog never started". An attacker who hooks
         * pthread_create to refuse watchdog spawn relies on this silent
         * failure mode.
         *
         * Set FUNCTION_PROLOGUE + STARTUP_LIVENESS anomaly flags so
         * snapshot consumers (JailbreakEngineV2, server replay) see a
         * positive signal that the watchdog spawn was actively refused.
         * Combined with the existing prologue verifier flags, this turns
         * "pthread_create unavailable" into a high-confidence attack
         * indicator rather than a quiet feature degradation.
         */
        s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPED;
        s_watchdog_snapshot.running = 0u;
        s_watchdog_snapshot.last_deny_attach_result = -1;
        s_watchdog_snapshot.last_deny_attach_errno = last_create_errno;
        s_watchdog_snapshot.anomaly_flags |=
            (CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_STARTUP_LIVENESS |
             CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE);
        s_watchdog_snapshot.last_prologue_fail_mask = path_mask;
        pthread_mutex_unlock(&s_watchdog_mutex);
        return -1;
    }
    s_watchdog_started_mask |= (1u << CPRISK_WATCHDOG_PRIMARY_ID);

    uint32_t sec_bits = 0u;
    // 副 worker 是增强项：失败只降级为单 worker，不阻断主检测。
    if (cprisk_watchdog_pthread_create_with_fallbacks_i(
            CPRISK_WATCHDOG_SECONDARY_ID, &sec_bits, &last_create_errno) == 0) {
        s_watchdog_started_mask |= (1u << CPRISK_WATCHDOG_SECONDARY_ID);
    } else {
        /* Keep running with primary watchdog as compatibility fallback. */
        s_watchdog_snapshot.last_deny_attach_result = -1;
        s_watchdog_snapshot.last_deny_attach_errno = last_create_errno;
    }
    // 低 8 位主 worker、高 8 位副 worker；0 表示该 worker 未创建。
    path_mask |= (sec_bits << CPRISK_WATCHDOG_PATH_SECONDARY_SHIFT);
    s_watchdog_snapshot.watchdog_start_path_mask = path_mask;

    // 在 worker 开始改动状态前记录镜像布局基线，供后续 low check 比较。
    cprisk_vm_dyld_image_layout_digest_baseline_snapshot();

    // 先解锁再等待，避免 worker 在首轮更新快照时被启动线程长时间持锁阻塞。
    pthread_mutex_unlock(&s_watchdog_mutex);
    cprisk_watchdog_wait_startup_liveness_i();
    // anti-dump 探针与 watchdog 独立；失败不影响 watchdog 运行。
    (void)cprisk_start_anti_dump_probe(5);
    // 播种主线程心跳，避免第一轮就把“从未 ping”误判为停滞。
    cprisk_watchdog_note_main_thread_alive();
    return 0;
}

// 开关硬崩溃模式：原子写，可在任意线程运行期调用；只影响之后命中 HIGH_RISK 的轮次。
void cprisk_set_hard_crash_mode(int enabled) {
    atomic_store_explicit(&s_hard_crash_mode, enabled ? 1 : 0, memory_order_relaxed);
}

// 停止看门狗。只有 RUNNING 才发起停止：切到 STOPPING、置原子 stop 请求，
// 持锁拷贝需要 join 的线程句柄，解锁后再 join——worker 退出路径也要拿这把锁，
// 持锁 join 会死锁。join 后清 running/thread_active/stop_requested/mailbox 等运行期字段；
// anomaly_flags 与累计计数保留，供调用方在停止后继续取证（下次 start 才清零）。
// 未运行/已停止时调用安全，不会重复 join。
void cprisk_stop_anti_debug_watchdog(void) {
    pthread_t threads_to_join[CPRISK_WATCHDOG_THREAD_COUNT];
    uint32_t join_count = 0u;

    pthread_mutex_lock(&s_watchdog_mutex);
    // 只在 RUNNING 时迁移；STOPPING/STOPPED 下 join_count=0，直接走清理。
    if (s_watchdog_state == CPRISK_WATCHDOG_STATE_RUNNING) {
        s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPING;
        s_watchdog_snapshot.stop_requested = 1u;
        atomic_store(&s_watchdog_stop_requested, 1);
        for (uint32_t i = 0; i < CPRISK_WATCHDOG_THREAD_COUNT; i++) {
            if ((s_watchdog_started_mask & (1u << i)) != 0u) {
                threads_to_join[join_count++] = s_watchdog_threads[i];
            }
        }
    }
    pthread_mutex_unlock(&s_watchdog_mutex);

    // join 必须在锁外：worker 退出时要拿 s_watchdog_mutex 清 active。
    for (uint32_t i = 0; i < join_count; i++) {
        pthread_join(threads_to_join[i], NULL);
    }

    pthread_mutex_lock(&s_watchdog_mutex);
    if (s_watchdog_state == CPRISK_WATCHDOG_STATE_STOPPING) {
        s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPED;
        s_watchdog_snapshot.running = 0u;
        s_watchdog_snapshot.thread_active = 0u;
        s_watchdog_snapshot.stop_requested = 0u;
        s_watchdog_started_mask = 0u;
        atomic_store(&s_watchdog_stop_requested, 0);
        for (uint32_t i = 0; i < CPRISK_WATCHDOG_THREAD_COUNT; i++) {
            atomic_store(&s_watchdog_worker_active[i], 0u);
            atomic_store(&s_watchdog_heartbeat_ns[i], 0u);
            atomic_store(&s_watchdog_deadline_ns[i], 0u);
        }
        // 端口在 worker 全部退出后释放，避免 peer 仍在使用悬空端口名。
        cprisk_watchdog_reset_mailboxes_locked();
    }
    pthread_mutex_unlock(&s_watchdog_mutex);

    // anti-dump 探针独立于 worker，即使 watchdog 从未启动也要停止它。
    cprisk_stop_anti_dump_probe();
}

// 蜜罐页访问入口：由内存保护模块在捕获非法访问时调用。
// 置 GUARD_PAGE（安全关键）并计入 signal_probe_anomaly_count；此处不投毒，
// 由调用方或下一轮检测统一处理。
void cprisk_watchdog_note_guard_page_fault(void) {
    pthread_mutex_lock(&s_watchdog_mutex);
    s_watchdog_snapshot.anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GUARD_PAGE;
    s_watchdog_snapshot.signal_probe_anomaly_count += 1u;
    pthread_mutex_unlock(&s_watchdog_mutex);
}

// 导出快照。NULL 返回 -1；否则持锁按值拷贝，保证字段之间的一致性。
// 拷贝后再叠加三个“实时”字段（libc 回退 mask/事件数、早期注入环境位）：
// 它们由其他模块维护，是读取瞬间的最新值；其余字段都是最近一轮迭代的结果。
int cprisk_get_anti_debug_watchdog_snapshot(
    cprisk_anti_debug_watchdog_snapshot_t *out_snapshot
) {
    if (out_snapshot == NULL) {
        return -1;
    }

    pthread_mutex_lock(&s_watchdog_mutex);
    *out_snapshot = s_watchdog_snapshot;
    pthread_mutex_unlock(&s_watchdog_mutex);
    /* Live libc fallback counters (not only on watchdog iteration). */
    out_snapshot->libc_fallback_used_mask = cprisk_get_libc_fallback_used_mask();
    out_snapshot->libc_fallback_event_total = cprisk_get_libc_fallback_event_total();
    out_snapshot->early_injection_env_mask = cprisk_get_early_injection_env_mask();
    return 0;
}

#else

// 非目标平台（模拟器/tvOS/watchOS/macOS x86 等）的 fail-open stub：
// 不启动线程、不做检测；start 仍启动 anti-dump 探针并返回成功，快照清零。
// 上层无需条件编译，也不会因平台不支持而阻断业务。
void cprisk_watchdog_note_main_thread_alive(void) {}

// stub：恒返回 1（视为通过），不做序言校验。
int cprisk_verify_dlsym_prologue(void) {
    return 1;
}

// stub：恒返回 1，视为运行时 hook 面完整。
int cprisk_verify_runtime_hook_surface_prologues(void) {
    return 1;
}

// stub：恒返回 0，表示没有导出漂移。
uint32_t cprisk_runtime_hook_surface_export_drift_mask(void) {
    return 0u;
}

// stub：只启动 anti-dump 探针并返回成功，不创建 worker。
int cprisk_start_anti_debug_watchdog(void) {
    (void)cprisk_start_anti_dump_probe(5);
    return 0;
}

// stub：忽略参数。
void cprisk_set_hard_crash_mode(int enabled) {
    (void)enabled;
}

// stub：停止 anti-dump 探针。
void cprisk_stop_anti_debug_watchdog(void) {
    cprisk_stop_anti_dump_probe();
    (void)0;
}

// stub：空操作。
void cprisk_watchdog_note_guard_page_fault(void) {}

// stub：NULL 返回 -1；否则清零快照并叠加三个实时字段，保持与完整实现的读取契约一致。
int cprisk_get_anti_debug_watchdog_snapshot(
    cprisk_anti_debug_watchdog_snapshot_t *out_snapshot
) {
    if (out_snapshot == NULL) {
        return -1;
    }

    memset(out_snapshot, 0, sizeof(*out_snapshot));
    /* Keep libc fallback observability consistent with the full watchdog path. */
    out_snapshot->libc_fallback_used_mask = cprisk_get_libc_fallback_used_mask();
    out_snapshot->libc_fallback_event_total = cprisk_get_libc_fallback_event_total();
    out_snapshot->early_injection_env_mask = cprisk_get_early_injection_env_mask();
    return 0;
}

#endif
