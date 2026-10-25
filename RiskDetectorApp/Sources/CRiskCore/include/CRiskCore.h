// CRiskCore.h — 云手机风控 SDK 的 C 公共 ABI 头文件。
//
// 职责：暴露 anti-debug、反注入、越狱/模拟器/DBI 检测、代码签名与
//   __TEXT/__DATA 加密加载、WhiteBox PRF、检测证明等 C 层入口；Swift 侧
//   既可直接链接，也可经 cprisk_resolve_import()/cpra_* 别名间接调用。
// ABI 稳定性：导出符号、枚举值、结构体字段顺序与大小均为二进制契约，
//   只能追加，禁止重排/复用/删除；结构体布局由 cprisk_armor_abi.h 的
//   _Static_assert 锁定。
// 生命周期：cprisk_init_protection() → 运行期 evaluate/探测 →
//   cprisk_cleanup_protection()；多数检测函数在 init 前可调用，但结果可能降级。
// 线程模型：初始化/清理由单一所有者串行调用；检测、快照与计数器可并发读取；
//   内部状态由 pthread mutex 或原子变量保护，具体见各函数说明。
// 平台限制：模拟器与非 arm64 构建上 SVC 直调、PAC、MTE、异常端口等能力
//   会退化为 libc 路径或安全空操作。
// 失败语义：默认 fail-open（查询失败视为未检测到）；只有显式标注 fail-closed
//   的初始化/解密/签名路径会拒绝继续。检测结果不得单独作为拒绝依据。
#ifndef CRiskCore_h
#define CRiskCore_h

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cprisk_armor_abi.h"
#include "cprisk_secure_zero.h"
#include "cprisk_memory_guard.h"
#include "cprisk_mte_guard.h"
#include "cprisk_swift_bridge.h"
#include "cprisk_vm_interpreter.h"
#include "cprisk_crypto_trace.h"
#include "cprisk_cff.h"
#include "cprisk_emulator_detect.h"
#include "cprisk_vm_sync_barrier.h"

#ifdef __cplusplus
extern "C" {
#endif

// 做什么：向内核发送 PT_DENY_ATTACH 直调 SVC（arm64 真机 syscall #26），
//   阻止调试器后续 attach；对已 attach 的调试器不生效。
// 参数与所有权：无参数、无内存所有权。
// 返回值：无；错误被丢弃，需要错误码时改用 cprisk_deny_attach_status()。
// 线程安全：可重入、可重复调用；内部只读构造期建好的 RX stub。
// 平台/架构：仅 arm64 iOS 真机真正发 SVC；模拟器/x86_64/非 Apple 为 no-op。
// 失败语义：fail-open —— 失败不阻断流程，由上层检测/告警兜底。
void cprisk_deny_attach(void);

// 做什么：同 cprisk_deny_attach()，但返回 SVC 的真实结果。
// 参数与所有权：error_out 可为 NULL；非 NULL 时由调用方提供 int 空间。
// 返回值：成功 0；失败 -1，并把原始 BSD errno 写入 *error_out（成功写 0）。
// 线程安全：可重入；stub 指针在构造期一次发布，之后只读。
// 平台/架构：仅 arm64 iOS 真机走 SVC；其他平台直接返回 0、*error_out=0。
// 失败语义：fail-open；-1 只表示内核拒绝或参数异常，不代表进程已安全。
int cprisk_deny_attach_status(int *error_out);

// 做什么：聚合快/慢两条路径判断是否被跟踪：快路径读 sysctl KERN_PROC_PID
//   的 P_TRACED；慢路径叠加 Mach 异常端口、线程异常端口与 DBI 标记抽样，
//   两者不一致会累计 streak。
// 参数与所有权：无参数、无内存所有权。
// 返回值：1=检测到跟踪或连续不一致；0=未检测到（含查询失败）。
// 线程安全：可并发调用；跨调用 streak 由原子变量维护。
// 平台/架构：模拟器直接返回 0；依赖 SVC/Mach 的路径在降级构建不可用。
// 失败语义：fail-open；streak>=2 且慢路径命中时会顺带投毒 anti-debug lane。
int cprisk_is_being_traced(void);

// 做什么：与 cprisk_is_being_traced() 共用同一聚合实现，作为备用导出符号，
//   降低单符号 Hook 的收益（调用方可交替使用两个入口）。
// 参数与所有权：无参数、无内存所有权。
// 返回值：1=可疑/被跟踪；0=未检测到。
// 线程安全：可并发调用，与主入口共享原子 streak。
// 平台/架构：同 cprisk_is_being_traced()；模拟器返回 0。
// 失败语义：fail-open。
int cprisk_is_being_traced_alt(void);

// 做什么：先分别跑 sysctl P_TRACED 与 Mach 端口检查，任一命中直接返回 1；
//   都未命中再叠加聚合路径（含线程端口与 DBI 抽样）。
// 参数与所有权：无参数。
// 返回值：1=可疑；0=未检测到（含平台不支持）。
// 线程安全：可并发调用；不修改调用方状态。
// 平台/架构：模拟器返回 0。
// 失败语义：fail-open；用于交叉校验，单个探测器被 Hook 时不至于完全失效。
int cprisk_is_being_traced_redundant(void);

// 做什么：只用 sysctl(KERN_PROC_PID) 读取自身 kinfo_proc 的 P_TRACED 位，
//   不触碰 Mach 端口；作为独立冗余路径使用。
// 参数与所有权：无参数。
// 返回值：1=被跟踪；0=未跟踪或查询失败。
// 线程安全：可并发调用；仅使用栈上 kinfo_proc。
// 平台/架构：模拟器返回 0；真机经 cprisk_sysctl_direct() 直调。
// 失败语义：fail-open —— sysctl 失败按“未跟踪”处理。
int cprisk_is_being_traced_sysctl_only(void);

// 做什么：Mach 侧启发式：task_get_exception_ports 查询失败、线程级异常端口
//   与任务级不一致、task_for_pid 计数增长、Mach port 数量突增等都会加分。
// 参数与所有权：无参数；临时 Mach port 由内部 deallocate。
// 返回值：1=存在可疑跟踪/劫持特征；0=未发现。
// 线程安全：可并发调用；port 基线最小值的标定用原子 CAS 维护。
// 平台/架构：模拟器返回 0；仅在 Apple 平台编译实现。
// 失败语义：fail-open；弱信号（缺少任务级断点端口）不计为硬异常。
int cprisk_mach_trace_suspicious(void);

// 做什么：读取最近一次聚合探测中“快慢路径结论是否不一致”的标志
//   （例如 DBI 掩盖了 P_TRACED）。
// 参数与所有权：无参数。
// 返回值：非 0=不一致；0=一致或尚未运行过聚合探测。
// 线程安全：可并发读取；底层为原子变量。
// 平台/架构：非 Apple/模拟器恒为 0。
// 失败语义：fail-open；只作旁证，不单独触发拒绝。
int cprisk_trace_crosscheck_inconsistent(void);

// 反调试看门狗异常位（base anomaly_flags，32 位已用满）。
// 置位者：仅反调试看门狗工作线程及其调用的探测函数。
// 读取者：cprisk_get_anti_debug_watchdog_snapshot()->anomaly_flags / Swift 判决层。
// 生命周期：按位或累加、跨迭代保持；cprisk_start_anti_debug_watchdog() 清零，
//   stop/cleanup 后快照归零。新增语义请放到 EXT_* 枚举，不要复用已有位。
enum {
// 无异常（初值）。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_NONE = 0u,
// bit0：看门狗观察到 P_TRACED 或聚合跟踪命中。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED = 1u << 0,
// bit1：deny_attach 直调失败或返回异常。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH = 1u << 1,
// bit2：任务级 EXC_BREAKPOINT 端口缺失或被替换。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_PORT = 1u << 2,
// bit3：task_get_exception_ports 查询失败（kern_return 见快照）。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_QUERY = 1u << 3,
// bit4：SIGTRAP 信号探测被调试器截获。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SIGNAL_PROBE     = 1u << 4,
// bit5：线程调试寄存器存在使能的硬件断点/观察点。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_HARDWARE_BP      = 1u << 5,
// bit6：csops CS_OPS_STATUS 报告 CS_DEBUGGED。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_CSOPS_DEBUGGED   = 1u << 6,
// bit7：存在 PC 落在已加载镜像之外的线程。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SUSPICIOUS_THREAD = 1u << 7,
// bit8：时序探测显示单步/DBI 级减速。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SINGLE_STEP      = 1u << 8,
// bit9：stdout 连接 /dev/ttys* 或 /dev/pts*。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TTY              = 1u << 9,
// bit10：Developer Disk Image 工具路径可访问。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DEVELOPER_DISK   = 1u << 10,
// bit11：代码段扫描到非本 SDK 的 BRK 指令。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SOFTWARE_BP      = 1u << 11,
// bit12：保留 BRK 的 Mach 异常投递超时或走了信号回退。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_DELIVERY_TIMEOUT = 1u << 12,
// bit13：看门狗 worker 心跳缺失，疑似被挂起。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL = 1u << 13,
// bit14：shadow stack 快照不匹配。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SHADOW_STACK = 1u << 14,
// bit15：DBI 标记命中（见 CPRISK_DBI_MARKER_*）。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_MARKER = 1u << 15,
// bit16：时序侧信道异常（见 CPRISK_TIMING_ANOMALY_*）。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TIMING_SIDECHANNEL = 1u << 16,
// bit17：快/慢跟踪路径结论不一致。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACE_CROSSCHECK = 1u << 17,
// bit18：重复跟踪探测结果持续分化。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED_PROBE_DIVERGENCE = 1u << 18,
// bit19：受监控函数序言与基线不一致。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE = 1u << 19,
// bit20：dyld 镜像路径或环境中出现注入迹象。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DYLD_INJECTION = 1u << 20,
// bit21（安全关键）：deny_attach 返回成功但随后 sysctl/Mach 一致性校验失败；
//   由 cprisk_deny_attach_effective_verify() 置位，通常意味着 SVC 被 hook 拦截。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH_VERIFY = 1u << 21,
// bit22（安全关键）：csops 签名标志出现异常组合
//   （CS_VALID / CS_HARD / CS_KILL / CS_DEBUGGED 缺失或混杂）。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_AMFI_CS_FLAGS = 1u << 22,
// bit23：task_for_pid(self) 意外成功，进程可能带 get-task-allow 类能力。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GET_TASK_ALLOW = 1u << 23,
// bit24（安全关键）：PROT_NONE 蜜罐页被访问，说明有 dump/扫描行为。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GUARD_PAGE = 1u << 24,
// bit25：受监控符号入口被改成 mov x0,x0; ret 之类立即返回。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_INSTANT_RETURN_PATCH = 1u << 25,
// bit26（安全关键）：SVC 直调模板或 deny-attach stub 的页/块哈希不匹配，
//   直调路径可能已被替换。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SVC_STUB_INTEGRITY = 1u << 26,
// bit27：POSIX mprotect 成功但 Mach VM 状态不一致。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_MPROTECT_MACH_DIVERGENCE = 1u << 27,
// bit28：匿名 RX slab 与线程 PC 交叉关联命中（Stalker 类 trace）。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_VM_TRACE_CORREL = 1u << 28,
// bit29（arm64e 安全关键）：看门狗线程 thunk→bridge 的 PAC 认证失败。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_PAC_THREAD_ENTRY = 1u << 29,
// bit30：dyld 镜像摘要变化，或存在不属于任何镜像的可执行区域。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_IMAGE_WHITELIST = 1u << 30,
// bit31：宽限窗口内 worker 未进入活跃/首轮迭代状态。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_STARTUP_LIVENESS = 1u << 31,
};

// 扩展异常位（watchdog_extended_anomaly_flags）。base anomaly_flags 已用满，
// 新语义一律放这里；置位/读取/重置规则与 base 相同。
enum {
// 无扩展异常（初值）。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXT_NONE = 0u,
// bit0：主线程心跳超过阈值未更新（runloop 阻塞/挂起/被 hook）。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXT_MAIN_THREAD_STALL = 1u << 0,
// bit1：__TEXT 页的加密/保护状态偏离运行期预期。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXT_TEXT_ENCRYPT_DRIFT = 1u << 1,
// bit2：高价值运行时 hook 面的 dlsym/导出 trie 归属或 trampoline 漂移。
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXT_RUNTIME_HOOK_EXPORT_DRIFT = 1u << 2,
};

// AMFI/代码签名探测位（cprisk_amfi_entitlement_watchdog_probe 的 amfi_anomaly_bits）。
// 仅 watchdog 置位，Swift 侧读取；下一次探测重新计算并覆盖。
enum {
// bit0：CS_DEBUGGED 置位。
    CPRISK_AMFI_PROBE_CS_DEBUGGED = 1u << 0,
// bit1：flags 非 0 但缺少 CS_VALID。
    CPRISK_AMFI_PROBE_CS_VALID_ABSENT = 1u << 1,
// bit2：缺少 CS_HARD（内存保护被弱化）。
    CPRISK_AMFI_PROBE_CS_HARD_ABSENT = 1u << 2,
// bit3：缺少 CS_KILL。
    CPRISK_AMFI_PROBE_CS_KILL_ABSENT = 1u << 3,
};

// 异常处理器状态快照（cprisk_get_exception_handler_snapshot 输出）。
// 字段由异常处理器模块在注册/校验时更新；读取方按值复制，不持有内部指针。
typedef struct cprisk_exception_handler_snapshot {
// 1=当前平台支持 Mach 异常端口接管；0=模拟器/降级构建。
    uint32_t supported;
// 1=已成功注册自己的 EXC_BREAKPOINT 处理器。
    uint32_t registered;
// 1=最近一次校验确认端口仍属于本进程处理器。
    uint32_t port_matches;
// 1=最近一次 task_get_exception_ports 查询成功。
    uint32_t last_query_succeeded;
// 1=最近一次校验尝试过重新注册/回收被劫持端口。
    uint32_t last_reclaim_attempted;
// 1=最近一次校验发现端口被替换。
    uint32_t last_hijack_detected;
// 1=已在 __thread_init 早期阶段捕获端口指纹。
    uint32_t early_phase_captured;
// 1=早期指纹与后续校验之间存在竞态/漂移。
    uint32_t last_race_detected;
// 最近一次端口查询的 kern_return_t（0=KERN_SUCCESS）。
    int32_t last_query_kern_return;
// 最近一次注册的 kern_return_t（0=KERN_SUCCESS）。
    int32_t last_register_kern_return;
// 累计校验次数（只增，uint64）。
    uint64_t verify_count;
// 累计重新注册/回收次数。
    uint64_t reclaim_count;
// 首次注册到首次校验的耗时，单位纳秒；0=尚未测量。
    uint64_t first_register_verify_delta_ns;
} cprisk_exception_handler_snapshot_t;

// 单个线程的 PC/镜像归属判定（cprisk_thread_pc_exec_snapshot 输出数组元素）。
// 数组由调用方分配，函数只写入，不保留指针。
typedef struct cprisk_thread_pc_exec_entry {
// Mach thread port 名称，仅诊断用；调用方不要 deallocate。
    uint32_t thread_port;
// 1=PC 落在某个已加载镜像的可执行段；0=落在镜像外。
    uint32_t pc_in_executable_image;
// 采样到的线程 PC 值（虚拟地址）。
    uint64_t pc;
// thread_get_state 的 kern_return_t；非 0 时 pc 无意义。
    int32_t thread_get_state_kern_return;
} cprisk_thread_pc_exec_entry_t;

// cprisk_thread_pc_exec_snapshot 的汇总输出；字段均为本次调用的瞬时值。
typedef struct cprisk_thread_pc_exec_snapshot {
// 结构体版本，当前为 1。
    uint32_t version;
// 枚举到的线程总数。
    uint32_t total_threads;
// PC 落在镜像外的线程数（可疑线程数）。
    uint32_t foreign_exec_threads;
// 实际写入 out_entries 的条数，<= max_entries。
    uint32_t entries_written;
} cprisk_thread_pc_exec_snapshot_t;

// 反调试看门狗完整状态快照（cprisk_get_anti_debug_watchdog_snapshot 输出）。
// 按值复制，调用方拥有 out_snapshot；字段由 watchdog 线程持锁更新。
// *_count / *_ns 为累计值；last_* 为最近一轮结果；*_flags / *_mask / *_bits
// 均为按位或语义，位定义见对应枚举。
typedef struct cprisk_anti_debug_watchdog_snapshot {
// 1=当前平台编译了看门狗实现；0=stub/模拟器。
    uint32_t supported;
// 1=看门狗处于 RUNNING 状态。
    uint32_t running;
// 1=至少一个 worker 已进入活跃状态。
    uint32_t thread_active;
// 1=已请求停止、尚未完成 join。
    uint32_t stop_requested;
// 轮询间隔（秒），默认 5，最小 1。
    uint32_t interval_seconds;
// 累计异常位（CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_*），只增不减直至重启。
    uint32_t anomaly_flags;
// 最近一轮是否判定被跟踪（0/1）。
    uint32_t last_traced;
// 最近一轮异常端口是否健康（0/1）。
    uint32_t last_exception_port_healthy;
// 最近一轮 task_get_exception_ports 是否成功。
    uint32_t last_exception_query_succeeded;
// 最近一轮是否尝试回收端口。
    uint32_t last_exception_reclaim_attempted;
// 最近一轮是否发现端口被劫持。
    uint32_t last_exception_hijack_detected;
// 最近一轮是否已有早期端口指纹。
    uint32_t last_exception_early_phase_captured;
// 最近一轮是否检测到启动期端口竞态。
    uint32_t last_exception_startup_race_detected;
// 最近一次 deny_attach 返回值（0/-1）。
    int32_t last_deny_attach_result;
// 最近一次 deny_attach 的 BSD errno；0=成功。
    int32_t last_deny_attach_errno;
// 最近一次端口查询 kern_return_t。
    int32_t last_exception_query_kern_return;
// 最近一次重新注册 kern_return_t。
    int32_t last_exception_register_kern_return;
// 主 worker 累计迭代次数。
    uint64_t iteration_count;
// 累计“判定被跟踪”事件数。
    uint64_t traced_event_count;
// 累计 deny_attach 失败次数。
    uint64_t deny_attach_error_count;
// 累计异常端口异常次数。
    uint64_t exception_anomaly_count;
// 最近一轮检查的单调时钟时间（纳秒）。
    uint64_t last_check_monotonic_ns;
// 最近一轮前的端口校验累计值（用于做差）。
    uint64_t last_exception_verify_count;
// 最近一轮前的端口回收累计值。
    uint64_t last_exception_reclaim_count;
// 启动到首次端口校验的间隔（纳秒）。
    uint64_t last_exception_startup_delta_ns;
// 最近一次 SIGTRAP 探测结果（1=被调试器截获）。
    uint32_t last_signal_probe_result;
// 最近一次硬件断点槽计数。
    uint32_t last_hardware_bp_detected;
// 最近一次软件 BRK 计数。
    uint32_t last_software_bp_detected;
// 最近一次 CS_DEBUGGED 判定（0/1）。
    uint32_t last_csops_debugged;
// 最近一次镜像外 PC 线程数。
    uint32_t last_suspicious_thread_count;
// 最近一次单步/时序异常判定（0/1）。
    uint32_t last_single_step_detected;
// 最近一次调试 TTY 判定（0/1）。
    uint32_t last_tty_detected;
// 最近一次 Developer Disk 判定（0/1）。
    uint32_t last_developer_disk_detected;
// 最近一次异常投递超时判定（0/1）。
    uint32_t last_exception_delivery_timeout_detected;
// 最近一次探针是否被自己的处理器接住（0/1）。
    uint32_t last_exception_delivery_probe_handled;
// 最近一次异常投递耗时（纳秒）。
    uint64_t last_exception_delivery_probe_ns;
// 累计 SIGTRAP 异常次数。
    uint64_t signal_probe_anomaly_count;
// 累计硬件断点异常次数。
    uint64_t hardware_bp_anomaly_count;
// 累计软件断点异常次数。
    uint64_t software_bp_anomaly_count;
// 累计 csops 异常次数。
    uint64_t csops_anomaly_count;
// 累计可疑线程异常次数。
    uint64_t suspicious_thread_anomaly_count;
// 累计异常投递超时次数。
    uint64_t exception_delivery_timeout_anomaly_count;
// 累计对等 worker 心跳停滞次数。
    uint64_t peer_watchdog_anomaly_count;
// 累计 shadow stack 不匹配次数。
    uint64_t shadow_stack_anomaly_count;
// 最近一次对等 worker 是否停滞（0/1）。
    uint32_t last_peer_watchdog_stalled;
// 最近一次 shadow stack 是否不匹配（0/1）。
    uint32_t last_shadow_stack_mismatch;
// 最近一次 DBI 标记是否命中（0/1）。
    uint32_t last_dbi_detected;
// 最近一次 DBI 标记位（CPRISK_DBI_MARKER_*）。
    uint32_t last_dbi_marker_flags;
// 最近一次时序异常位（CPRISK_TIMING_ANOMALY_*）。
    uint32_t last_timing_anomaly_flags;
// 最近一次时序探测中位数（纳秒）。
    uint64_t last_timing_probe_median_ns;
// 最近一次时序探测最大值（纳秒）。
    uint64_t last_timing_probe_max_ns;
// 最近一次时序探测判定阈值（纳秒）。
    uint64_t last_timing_probe_threshold_ns;
// 累计 DBI 异常次数。
    uint64_t dbi_anomaly_count;
// 累计时序异常次数。
    uint64_t timing_anomaly_count;
// 累计函数序言完整性异常次数。
    uint64_t prologue_integrity_anomaly_count;
// 累计 dyld 注入异常次数。
    uint64_t dyld_injection_anomaly_count;
// 最近一次序言校验失败位（CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_*）。
    uint32_t last_prologue_fail_mask;
// 最近一次 dyld 注入检测位（内部定义）。
    uint32_t last_dyld_injection_flags;
// 最近一次 CS_OPS_STATUS 原始标志。
    uint32_t last_csops_status_flags;
// 最近一次 AMFI 探测位（CPRISK_AMFI_PROBE_*）。
    uint32_t last_amfi_probe_bits;
// 1=task_for_pid(self) 意外成功。
    uint32_t last_get_task_allow_suspect;
// 最近一次 deny_attach 事后校验位（CPRISK_DENY_ATTACH_VERIFY_*）。
    uint32_t last_deny_attach_verify_bits;
// 累计 deny_attach 事后校验异常次数。
    uint64_t deny_attach_verify_anomaly_count;
// 累计 AMFI/CS 标志异常次数。
    uint64_t amfi_cs_flags_anomaly_count;
// 累计 get-task-allow 可疑次数。
    uint64_t get_task_allow_anomaly_count;
// 累计 Mach 与 POSIX mprotect 交叉校验不一致次数。
    uint64_t vm_mprotect_crosscheck_mismatch_total;
// 累计“mprotect 成功但 vm_protect 失败”的 trap 次数（hook 面）。
    uint64_t vm_mprotect_mach_trap_mismatch_total;
// 位掩码：因直调不可用而改走 libc/arc4random 的路径（见 CPRISK_LIBC_FALLBACK_USED_*）。
    uint32_t libc_fallback_used_mask;
// 自上次 mask 重置以来的回退事件数；可能大于 mask 的 popcount。
    uint32_t libc_fallback_event_total;
// 低 8 位=主线程入口路径，次 8 位=备用入口路径（见 CPRISK_WATCHDOG_START_PATH_*）。
    uint32_t watchdog_start_path_mask;
// 1=宽限窗口内至少一个 worker 进入活跃/迭代状态。
    uint32_t watchdog_startup_liveness_ok;
// 最近一次 cprisk_watchdog_note_main_thread_alive() 的单调时间（纳秒）；0=从未 ping。
    uint64_t main_thread_alive_monotonic_ns;
// 启动时 cprisk_get_early_injection_env_mask() 的副本（dyld 注入环境位）。
    uint32_t early_injection_env_mask;
// 扩展异常位（CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXT_*）。
    uint32_t watchdog_extended_anomaly_flags;
// 主线程心跳单调序号，每次 note_alive 加 1。
    uint64_t main_thread_heartbeat_seq;
// 累计“主线程心跳停滞”高置信事件数。
    uint64_t main_thread_heartbeat_stall_count;
// 1=最近一轮主 worker 观察到已锁存的主线程停滞。
    uint32_t last_main_thread_heartbeat_stalled;
} cprisk_anti_debug_watchdog_snapshot_t;

// 反调试计划（嵌入配置段）解析与策略快照。
// 由解析器/策略引擎更新；cprisk_get_antidebug_plan_snapshot 按值复制。
typedef struct cprisk_antidebug_plan_snapshot {
// 1=镜像中存在计划段。
    uint32_t section_present;
// 1=计划段通过 magic/版本/长度校验。
    uint32_t section_valid;
// 0=解析成功；非 0=解析错误码（内部定义）。
    uint32_t parse_error;
// 解析出的条目数。
    uint32_t entry_count;
// 所有条目策略位的并集（见内部 policy 位定义）。
    uint32_t policy_union_bits;
// 最近一次实际应用的策略位。
    uint32_t last_applied_policy_bits;
// 最近一次触发的探针类别位。
    uint32_t last_probe_bits;
// 1=最近一次触发了 fail-closed gate。
    uint32_t last_gate_closed;
// 1=最近一次使用软失败（仅记录/降级）。
    uint32_t last_soft_fail_mode;
// 最近一次策略延时（纳秒）。
    uint64_t last_delay_ns;
// 累计消费的计划条目次数。
    uint64_t consume_count;
// 累计策略升级次数。
    uint64_t escalation_count;
// 累计 trap/BRK 事件次数。
    uint64_t trap_event_count;
// 累计成功的内联补丁次数。
    uint64_t inline_patch_count;
// 累计内联补丁失败次数。
    uint64_t inline_patch_failure_count;
// 1=内联补丁当前处于武装状态。
    uint32_t inline_patch_armed;
// 1=最近一次检测到内联补丁被篡改。
    uint32_t last_inline_patch_tamper;
} cprisk_antidebug_plan_snapshot_t;

// 做什么：在 arm64 Apple 目标上以直接 BSD SVC 调用 sysctlbyname，绕过 libc
//   同名导出；降级构建回退 libc。
// 参数与所有权：name 为 NUL 结尾名称；oldp/oldlenp/newp/newlen 语义同
//   sysctlbyname(3)，缓冲区由调用方提供与释放；error_out 可为 NULL。
// 返回值：成功 0；失败 -1。非 NULL 时 *error_out 为原始 BSD errno
//   （直调）或 libc errno（回退）。
// 线程安全：可并发调用，无共享可变状态；并发写同一 oldp 由调用方负责。
// 平台/架构：直调仅 arm64 Apple；其他平台走 libc 并置位回退掩码。
// 失败语义：fail-open，-1 应视为“查询不可用”而非风险结论。
int cprisk_sysctlbyname_direct(
    const char *name,
    void *oldp,
    size_t *oldlenp,
    const void *newp,
    size_t newlen,
    int *error_out
);

// 做什么：以直接 BSD SVC 调用 sysctl（MIB 数组形式），绕过 libc 导出。
// 参数与所有权：name/namelen/oldp/oldlenp/newp/newlen 同 sysctl(3)；
//   缓冲区归调用方；name 必须指向 namelen 个 int；error_out 可为 NULL。
// 返回值：成功 0；失败 -1，*error_out 为原始 BSD errno 或回退 errno。
// 线程安全：可并发调用；MIB 与输出缓冲区生命周期由调用方管理。
// 平台/架构：直调仅 arm64 Apple；其他平台回退 libc 并记录回退位。
// 失败语义：fail-open。
int cprisk_sysctl_direct(
    int *name,
    unsigned int namelen,
    void *oldp,
    size_t *oldlenp,
    const void *newp,
    size_t newlen,
    int *error_out
);

// 做什么：以 SYS_stat64 直调获取文件元数据，绕过 libc stat Hook。
// 参数与所有权：path 为 NUL 结尾路径（不可 NULL）；sb 由调用方提供，函数先清零，
//   仅在成功时有效；error_out 可为 NULL。
// 返回值：成功 0；失败 -1，*error_out 为 errno。
// 线程安全：可并发调用；sb 的并发读写由调用方负责。
// 平台/架构：直调仅 arm64 Apple；回退构建用 libc stat。
// 失败语义：fail-open；sb 为 NULL 时直调会 EFAULT，回退路径退化为存在性探测。
int cprisk_stat_direct(const char *path, struct stat *sb, int *error_out);
// 做什么：以 SYS_lstat64 直调获取文件元数据，不跟随符号链接。
// 参数与所有权：path 不可 NULL；sb 由调用方提供并先清零；error_out 可为 NULL。
// 返回值：成功 0；失败 -1，*error_out 为 errno；sb 仅成功时有效。
// 线程安全：可并发调用；sb 的并发访问由调用方负责。
// 平台/架构：直调仅 arm64 Apple；回退构建用 libc lstat。
// 失败语义：fail-open；sb 为 NULL 时直调会 EFAULT，回退路径退化为存在性探测。
int cprisk_lstat_direct(const char *path, struct stat *sb, int *error_out);
// 做什么：以 SYS_access 直调检查文件可访问性，绕过 libc access Hook。
// 参数与所有权：path 不可 NULL；amode 取 F_OK/R_OK/W_OK/X_OK 组合；
//   error_out 可为 NULL。
// 返回值：成功 0；失败 -1，*error_out 为 errno。
// 线程安全：可并发调用。
// 平台/架构：直调仅 arm64 Apple；回退构建用 libc access。
// 失败语义：fail-open；-1 与 errno 原样传递。
int cprisk_access_direct(const char *path, int amode, int *error_out);

// 做什么：在受保护/栈内缓冲区解码 XOR 掩码路径后以 stat 直调读取元数据；
//   明文只在短生命周期缓冲区中存在，不暴露给 Swift 调用边界。
// 参数与所有权：masked_path 由调用方提供，masked_len 含结尾 NUL 且 <= PATH_MAX；
//   seed 必须与生成端一致；sb 由调用方提供；error_out 可为 NULL。
// 返回值：成功 0；失败 -1（参数非法、解码后无 NUL、syscall 失败），*error_out 为 errno。
// 线程安全：可并发调用；每次调用独立分配解码缓冲区并安全擦除。
// 平台/架构：解码与平台无关；底层调用在非 arm64 回退 libc。
// 失败语义：fail-open；解码失败不会被误判为“文件存在”。
int cprisk_stat_masked(const uint8_t *masked_path, size_t masked_len, uint32_t seed,
                       struct stat *sb, int *error_out);
// 做什么：解码 XOR 掩码路径后以 lstat 直调读取元数据，不跟随符号链接。
// 参数与所有权：masked_path/masked_len/seed 同上；sb 由调用方提供；error_out 可为 NULL。
// 返回值：成功 0；失败 -1（参数/解码/syscall 失败），*error_out 为 errno。
// 线程安全：可并发调用；解码缓冲区独立分配并擦除。
// 平台/架构：解码平台无关；底层在非 arm64 回退 libc。
// 失败语义：fail-open；解码失败不会被误判为“文件存在”。
int cprisk_lstat_masked(const uint8_t *masked_path, size_t masked_len, uint32_t seed,
                        struct stat *sb, int *error_out);
// 做什么：解码 XOR 掩码路径后以 access 直调检查可访问性。
// 参数与所有权：masked_path/masked_len/seed 同上；amode 同 access(2)；
//   error_out 可为 NULL。
// 返回值：成功 0；失败 -1（参数/解码/syscall 失败），*error_out 为 errno。
// 线程安全：可并发调用；解码缓冲区独立分配并擦除。
// 平台/架构：解码平台无关；底层在非 arm64 回退 libc。
// 失败语义：fail-open；解码失败不会被误判为“存在”。
int cprisk_access_masked(const uint8_t *masked_path, size_t masked_len, uint32_t seed,
                         int amode, int *error_out);
// 做什么：同 cprisk_access_masked，但底层显式走 libc access()，用于与直调
//   结果做 anti-hook 对照，同时仍不在 Swift 边界暴露明文路径。
// 参数与所有权：同 cprisk_access_masked。
// 返回值：成功 0；失败 -1，*error_out 为 libc errno。
// 线程安全：可并发调用。
// 平台/架构：全平台（libc 路径）。
// 失败语义：fail-open；对照结果需与直调路径一起解读。
int cprisk_access_masked_libc(const uint8_t *masked_path, size_t masked_len, uint32_t seed,
                              int amode, int *error_out);

// 路径探测维度位（cprisk_path_probe_snapshot* 的 available/exists 掩码）。
// 置位者：探测函数；读取者：调用方。相对路径按进程 cwd 解析。
enum {
// bit0：用 access(F_OK) 探测。
    CPRISK_PATH_PROBE_ACCESS = 1u << 0,
// bit1：用 stat 探测（跟随符号链接）。
    CPRISK_PATH_PROBE_STAT = 1u << 1,
// bit2：用 open(O_RDONLY) 探测（需要读权限，与 F_OK 语义不同）。
    CPRISK_PATH_PROBE_FOPEN = 1u << 2,
// bit3：用 lstat 探测（不跟随符号链接；仅 secure 变体使用）。
    CPRISK_PATH_PROBE_LSTAT = 1u << 3,
};

// 路径探测结果：available_mask 表示本次实际可用的探测方式，
// exists_mask 表示其中判定“存在”的位。按值输出，调用方拥有。
typedef struct cprisk_path_probe_snapshot {
// 本次实际执行的探测方式位（CPRISK_PATH_PROBE_*）。
    uint32_t available_mask;
// 判定存在的方式位，为 available_mask 的子集。
    uint32_t exists_mask;
} cprisk_path_probe_snapshot_t;

// 做什么：用 access/stat/open 三种方式探测明文路径是否存在，用于越狱/
//   调试工具路径识别。
// 参数与所有权：path 必须非 NULL；out_snapshot 由调用方提供并被覆盖写入。
// 返回值：成功 0；path 或 out_snapshot 为 NULL 时 -1。
// 线程安全：可并发调用；无共享状态。
// 平台/架构：全平台；底层 syscall 在非 arm64 回退 libc。
// 失败语义：单个探测失败只清对应 exists 位，不影响整体返回 0。
int cprisk_probe_path_snapshot(const char *path, cprisk_path_probe_snapshot_t *out_snapshot);
// 做什么：同 cprisk_probe_path_snapshot，但路径以 XOR 掩码传入并在 C 栈内解码。
// 参数与所有权：masked_path/masked_len/seed 同 cprisk_stat_masked；
//   out_snapshot 由调用方提供。
// 返回值：成功 0；参数非法或解码失败 -1。
// 线程安全：可并发调用。
// 平台/架构：解码平台无关，底层探测可回退 libc。
// 失败语义：fail-open（失败不会被当作“存在”）。
int cprisk_probe_path_snapshot_masked(const uint8_t *masked_path, size_t masked_len,
                                      uint32_t seed, cprisk_path_probe_snapshot_t *out_snapshot);
// 做什么：安全路径多探针：在同一个受保护解码窗口内依次执行 access/stat/lstat，
//   缩短明文路径驻留时间并减少解码次数。
// 参数与所有权：同 cprisk_probe_path_snapshot_masked。
// 返回值：成功 0；参数非法 -1。available_mask 只用 ACCESS/STAT/LSTAT 三位。
// 线程安全：可并发调用。
// 平台/架构：底层直调在非 arm64 回退 libc。
// 失败语义：fail-open。
int cprisk_probe_secure_path_snapshot_masked(const uint8_t *masked_path, size_t masked_len,
                                            uint32_t seed, cprisk_path_probe_snapshot_t *out_snapshot);

// posix_spawn/posix_spawnp 入口的三路径解析结果（RTLD_DEFAULT vs
// dlopen(libsystem_c)+dlsym vs 导出 trie）。地址为 0 表示该路径解析失败。
typedef struct cprisk_spawn_iface_probe_result {
// RTLD_DEFAULT 解析到的 posix_spawn 地址；0=失败。
    uint64_t addr_rtld_default_spawn;
// dlopen(libsystem_c.dylib)+dlsym 得到的地址；0=失败。
    uint64_t addr_dlopen_libc_spawn;
// 导出 trie 解析到的地址；0=失败。
    uint64_t addr_export_trie_spawn;
// 同上，posix_spawnp 的 RTLD_DEFAULT 地址。
    uint64_t addr_rtld_default_spawnp;
// 同上，posix_spawnp 的 dlopen+dlsym 地址。
    uint64_t addr_dlopen_libc_spawnp;
// 同上，posix_spawnp 的导出 trie 地址。
    uint64_t addr_export_trie_spawnp;
// 不一致位（内部 CPRISK_SPAWN_IFACE_F_*）：两地址均非 0 且不相等时置位。
    uint32_t flags;
// 保留字段，恒为 0；读取方应忽略。
    uint32_t reserved;
} cprisk_spawn_iface_probe_result_t;

// 做什么：解析 posix_spawn/posix_spawnp 的三条路径并比较地址，识别 PLT/
//   lazy binding/interpose 造成的不一致。
// 参数与所有权：out 必须非 NULL；函数先 memset 再写入，调用方拥有。
// 返回值：成功 0；out 为 NULL 时 -1。解析失败只体现在对应地址为 0。
// 线程安全：可并发调用；内部使用 dlopen/dlsym，无 SDK 共享状态。
// 平台/架构：依赖 dyld 导出 trie，仅 Apple 平台可用。
// 失败语义：fail-open；flags 非 0 仅表示“可疑”，不自动判定风险。
int cprisk_spawn_iface_probe(cprisk_spawn_iface_probe_result_t *out);

// 做什么：以 SYS_getpid 直调返回当前进程 PID，绕过 libc getpid 的 Hook 面。
// 参数与所有权：无参数。
// 返回值：PID（>0）；直调不可用时回退 libc，理论不失败。
// 线程安全：可并发调用。
// 平台/架构：直调仅 arm64 Apple；回退构建用 libc 并记录回退位。
// 失败语义：fail-open；返回 <=0 应视为异常（见 errno 探针）。
pid_t cprisk_getpid_direct(void);

// 做什么：以 SYS_getppid 直调返回父进程 PID。
// 参数与所有权：无参数。
// 返回值：PPID；直调不可用时回退 libc。
// 线程安全：可并发调用。
// 平台/架构：直调仅 arm64 Apple；回退构建用 libc 并记录回退位。
// 失败语义：fail-open。
pid_t cprisk_getppid_direct(void);

// 做什么：以 SYS_getuid 直调返回真实用户 ID。
// 参数与所有权：无参数。
// 返回值：uid；直调不可用时回退 libc。
// 线程安全：可并发调用。
// 平台/架构：直调仅 arm64 Apple；回退构建用 libc 并记录回退位。
// 失败语义：fail-open。
uid_t cprisk_getuid_direct(void);

// 做什么：以 SYS_open 直调打开文件，在 Hook 环境下获得真实 fd。
// 参数与所有权：path 为 NUL 结尾路径（不可 NULL）；flags 同 open(2)；
//   error_out 可为 NULL，非 NULL 时写入 errno。
// 返回值：成功 fd>=0；失败 -1。
// 线程安全：可并发调用；fd 所有权归调用方。
// 平台/架构：直调仅 arm64 Apple；回退构建用 libc open。
// 失败语义：fail-open；调用方必须自行 close。
int cprisk_open_direct(const char *path, int flags, int *error_out);

// 做什么：以 SYS_close 直调关闭 fd。
// 参数与所有权：fd 由调用方拥有；error_out 可为 NULL。
// 返回值：成功 0；失败 -1，*error_out 为 errno。
// 线程安全：可并发调用；同一 fd 的并发 close 属调用方错误。
// 平台/架构：直调仅 arm64 Apple；回退 libc。
// 失败语义：fail-open。
int cprisk_close_direct(int fd, int *error_out);

// 做什么：以 SYS_read 直调读取 fd。
// 参数与所有权：buf 由调用方提供且至少 nbyte 字节；nbyte > SSIZE_MAX 时
//   直接返回 -1/EINVAL。
// 返回值：成功返回实际读取字节数（0=EOF）；失败 -1，*error_out 为 errno。
// 线程安全：可并发调用；并发读同一 fd 的偏移语义由内核决定。
// 平台/架构：直调仅 arm64 Apple；回退 libc。
// 失败语义：fail-open；短读需调用方自行循环。
ssize_t cprisk_read_direct(int fd, void *buf, size_t nbyte, int *error_out);

// 做什么：以 SYS_socket 直调创建套接字。
// 参数与所有权：domain/type/protocol 同 socket(2)；fd 归调用方。
// 返回值：成功 fd>=0；失败 -1，*error_out 为 errno。
// 线程安全：可并发调用。
// 平台/架构：直调仅 arm64 Apple；回退 libc。
// 失败语义：fail-open。
int cprisk_socket_direct(int domain, int type, int protocol, int *error_out);

// 做什么：以 SYS_connect 直调连接套接字。
// 参数与所有权：addr/addrlen 由调用方提供并在调用期间有效。
// 返回值：成功 0；失败 -1，*error_out 为 errno。
// 线程安全：可并发调用；同一 socket 的并发 connect 属调用方错误。
// 平台/架构：直调仅 arm64 Apple；回退 libc。
// 失败语义：fail-open。
int cprisk_connect_direct(int sockfd, const struct sockaddr *addr, socklen_t addrlen, int *error_out);

// 做什么：把标准 ABI 的 C 函数指针（含 dlsym 结果）重新签名到 SDK 的
//   存储 schema，discriminator 由调用方提供。
// 参数与所有权：ptr 可为 NULL（返回 NULL）；非 NULL 时必须已带标准函数指针
//   签名，裸地址不被接受；不接管指针所有权。
// 返回值：成功返回可存储的已签名指针；NULL 输入返回 NULL。
// 线程安全：可并发调用（纯计算）。
// 平台/架构：仅 arm64e 且 ptrauth 头可用时做 auth_and_resign；其他架构原样返回。
// 失败语义：非 arm64e 的“原样返回”是降级而非校验成功，调用方需自查
//   cprisk_pac_is_arm64e_supported()。
void *cprisk_pac_sign_function_pointer(const void *ptr, uintptr_t discriminator);

// 做什么：在调用前认证此前由 cprisk_pac_sign_function_pointer() 签名的指针。
// 参数与所有权：ptr 可为 NULL；discriminator 必须与签名时一致。
// 返回值：NULL 输入返回 NULL；成功返回标准 ABI 可调用指针。
// 线程安全：可并发调用。
// 平台/架构：arm64e 上做 auth_and_resign；无效的非 NULL 签名可能直接 trap，
//   因此这不是“可空有效性查询”；其他架构原样返回。
// 失败语义：fail-open（非 arm64e 无认证）；不要用故意错误的 discriminator 探测。
void *cprisk_pac_auth_function_pointer(const void *ptr, uintptr_t discriminator);

// 做什么：报告当前构建是否编译进 arm64e PAC/ptrauth 支持。
// 参数与所有权：无参数。
// 返回值：1=支持；0=不支持（模拟器、x86_64、非 arm64e）。
// 线程安全：可并发调用（编译期常量）。
// 平台/架构：仅 __arm64e__ + <ptrauth.h> 可用时为 1。
// 失败语义：返回 0 时上层不得把任何 PAC 结果当作已验证。
int cprisk_pac_is_arm64e_supported(void);

// PAC/CFI 状态位（cprisk_get_last_pac_cfi_flags 返回）。
// 置位者：本文件的 sign/auth/self-test API；读取者：调用方/遥测。
// 复位语义：每次调用整体覆盖（不是按位累加），仅反映最近一次结果。
enum {
// 无错误。
    CPRISK_PAC_CFI_FLAG_NONE = 0u,
// bit0：当前平台无 PAC 运行时。
    CPRISK_PAC_CFI_FLAG_UNAVAILABLE = 1u << 0,
// bit1：签名失败。
    CPRISK_PAC_CFI_FLAG_SIGN_FAILED = 1u << 1,
// bit2：认证失败（含 NULL 输入/平台不可用）。
    CPRISK_PAC_CFI_FLAG_AUTH_FAILED = 1u << 2,
// bit3：仅弱绑定（保留位，正常流程不应置位）。
    CPRISK_PAC_CFI_FLAG_WEAK_BINDING = 1u << 3,
// bit4：自检调用结果与预期不一致。
    CPRISK_PAC_CFI_FLAG_SELFTEST_FAILED = 1u << 4,
// bit5：内置回调 schema 往返校验失败（不代表代码完整性）。
    CPRISK_PAC_CFI_FLAG_CALLBACK_VALIDATION_FAILED = 1u << 5,
};

// 做什么：对“已签名”的外部间接调用目标按给定 discriminator 做真实认证；
//   有意不做 sign-then-auth（后者恒成功，证明不了输入指针）。
// 参数与所有权：func_ptr 可为 NULL；非 NULL 时必须已按该 discriminator 签名。
// 返回值：认证通过 0；NULL 或平台不可用 -1。无效非 NULL 签名可能 trap。
// 线程安全：可并发调用；结果原子写入全局 PAC 标志。
// 平台/架构：仅 arm64e；非 arm64e 返回 -1 并置 UNAVAILABLE|AUTH_FAILED。
// 失败语义：fail-closed；-1 时调用方不得调用该指针。
int cprisk_pac_validate_indirect_call_target(const void *func_ptr, uintptr_t discriminator);

// 做什么：用内部已知函数做签名→认证→调用往返，验证 PAC 机制本身可用。
// 参数与所有权：discriminator 由调用方选择；不涉及外部内存。
// 返回值：0=通过或平台无 PAC；1=签名/认证/调用结果不符。
// 线程安全：可并发调用；覆盖全局 PAC 标志。
// 平台/架构：仅 arm64e 实际执行；其他平台直接返回 0 并置 UNAVAILABLE。
// 失败语义：返回 1 表示机制异常；0 在非 arm64e 上不代表“安全”。
int cprisk_pac_self_test(uintptr_t discriminator);

// 做什么：对四个内置 C 回调做“存储 schema 往返”校验，验证签名/认证的
//   编解码一致性；不校验回调代码字节或来源。
// 参数与所有权：无参数。
// 返回值：0=通过或平台无 PAC；1=任一回调往返失败。
// 线程安全：可并发调用；覆盖全局 PAC 标志。
// 平台/架构：仅 arm64e 实际执行；其他平台返回 0 并置 UNAVAILABLE。
// 失败语义：失败置 CALLBACK_VALIDATION_FAILED，供上层降级/告警。
int cprisk_pac_validate_core_callbacks(void);

// 做什么：返回最近一次 PAC/CFI 操作的状态位（CPRISK_PAC_CFI_FLAG_*）。
// 参数与所有权：无参数。
// 返回值：状态位组合；0=最近一次操作无错误。
// 线程安全：原子读取，可并发调用。
// 平台/架构：全平台；非 arm64e 通常含 UNAVAILABLE。
// 失败语义：无；位含义见 CPRISK_PAC_CFI_FLAG_*。
uint32_t cprisk_get_last_pac_cfi_flags(void);

// 做什么：以 SYS_getentropy 直调填充随机字节；回退构建用 arc4random_buf。
// 参数与所有权：buf 由调用方提供且至少 buflen 字节；buflen 必须 <= 256。
// 返回值：成功 0；失败 -1，*error_out 为 errno（回退路径恒 0）。
// 线程安全：可并发调用。
// 平台/架构：直调仅 arm64 Apple；其他平台回退 arc4random。
// 失败语义：fail-closed 于参数校验（>256 直接 EINVAL）；不得使用未填充缓冲区。
int cprisk_getentropy_direct(void *buf, size_t buflen, int *error_out);

// 做什么：以 SYS_csops 直调查询/设置代码签名状态（如 CS_OPS_STATUS）。
// 参数与所有权：pid 通常传 cprisk_getpid_direct()；useraddr/usersize 由
//   调用方提供并按其 ops 语义解释；error_out 可为 NULL。
// 返回值：成功 0；失败 -1。未编译直调时返回 -1/ENOTSUP，且不回落 libc。
// 线程安全：可并发调用。
// 平台/架构：仅 arm64 Apple 有直调；其他构建恒不可用。
// 失败语义：fail-closed（不提供 libc 替代），调用方需把 -1 视为“未知”。
int cprisk_csops_direct(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, int *error_out);

// 做什么：以 SYS_mprotect 直调修改页保护，规避 libc mprotect Hook。
// 参数与所有权：addr/len/prot 语义同 mprotect(2)；不接管内存所有权。
// 返回值：成功 0；失败 -1，*error_out 为 errno。
// 线程安全：可并发调用；并发修改同一区间由调用方同步。
// 平台/架构：直调仅 arm64 Apple；回退构建用 libc mprotect。
// 失败语义：fail-closed（-1 表示保护未改变），调用方不得假设已生效。
int cprisk_mprotect_direct(void *addr, size_t len, int prot, int *error_out);

// libc 回退路径位（cprisk_note_libc_fallback_used / get_mask）。
// 置位者：各直调包装在无法使用 SVC 时；读取者：watchdog 快照与遥测。
// 生命周期：按位或累加，cprisk_reset_libc_fallback_used_mask() 清零；
//   事件总数单独累加，可能大于位图 popcount。
enum {
// bit0：mprotect 回退 libc。
    CPRISK_LIBC_FALLBACK_USED_DIRECT_MPROTECT = 1u << 0,
// bit1：getentropy 回退 arc4random。
    CPRISK_LIBC_FALLBACK_USED_DIRECT_GETENTROPY = 1u << 1,
// bit2：sysctl/sysctlbyname 回退 libc。
    CPRISK_LIBC_FALLBACK_USED_DIRECT_SYSCTL = 1u << 2,
// bit3：stat/lstat/access 路径探测回退 libc。
    CPRISK_LIBC_FALLBACK_USED_DIRECT_STAT_PATH = 1u << 3,
// bit4：open/close/read/socket/connect 等 fd IO 回退 libc。
    CPRISK_LIBC_FALLBACK_USED_DIRECT_FD_IO = 1u << 4,
// bit5：getpid/getppid/getuid 回退 libc。
    CPRISK_LIBC_FALLBACK_USED_DIRECT_IDS = 1u << 5,
// bit6：armor 内部 mprotect 回退 libc（与 bit0 区分调用点）。
    CPRISK_LIBC_FALLBACK_USED_ARMOR_MPROTECT = 1u << 6,
// bit7：构建本身没有进程内 SVC stub（模拟器/非 arm64 等），回退属预期行为。
    CPRISK_LIBC_FALLBACK_USED_UNSUPPORTED_PLATFORM = 1u << 7,
// bit8：本构建无 csops 直调；调用方收到 ENOTSUP，且不做 libc 替代。
    CPRISK_LIBC_FALLBACK_USED_DIRECT_CSOPS_UNAVAILABLE = 1u << 8,
// bit9：直调 stub 意外返回 ENOTSUP（使用包装函数时不应出现），
//   防御性记录以免事件完全静默。
    CPRISK_LIBC_FALLBACK_USED_DIRECT_SYSCALL_STUB_FALLBACK = 1u << 9,
};

// 做什么：记录一次 libc 回退事件（按位或 mask，并累加事件总数）。
// 参数与所有权：bits 取 CPRISK_LIBC_FALLBACK_USED_* 组合。
// 返回值：无。
// 线程安全：mask 为 volatile 按位或、计数为原子加，可并发调用。
// 平台/架构：全平台。
// 失败语义：无失败路径；仅记录，不影响调用结果。
void cprisk_note_libc_fallback_used(uint32_t bits);
// 做什么：读取累计回退位图。
// 参数与所有权：无参数。
// 返回值：CPRISK_LIBC_FALLBACK_USED_* 的按位或。
// 线程安全：可并发读取（volatile，弱一致）。
// 平台/架构：全平台。
// 失败语义：无。
uint32_t cprisk_get_libc_fallback_used_mask(void);
// 做什么：清零回退位图与事件总数（不影响业务状态）。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：非原子写，建议在单线程初始化/测试阶段调用。
// 平台/架构：全平台。
// 失败语义：无。
void cprisk_reset_libc_fallback_used_mask(void);
// 做什么：读取累计回退事件数。
// 参数与所有权：无参数。
// 返回值：自上次清零以来的事件数（uint32，可能回绕）。
// 线程安全：可并发读取（原子）。
// 平台/架构：全平台。
// 失败语义：无。
uint32_t cprisk_get_libc_fallback_event_total(void);

#ifndef CPRISK_MPROTECT_FULL_FAIL_STREAK_THRESHOLD
// 连续“完全失败”阈值：直调与 libc 回退都失败（或无 libc）达到该次数后，
// cprisk_is_mprotect_tampered() 才锁存为 1。取 3 是为了容忍偶发瞬时失败，
// 同时让持续性内核拦截快速显形；调低会增加误报，调高会延长暴露窗口。
// 可在编译期覆盖（外层 #ifndef 保护）。
#define CPRISK_MPROTECT_FULL_FAIL_STREAK_THRESHOLD 3u
#endif

// 做什么：数据加载器的 VM 保护入口：优先直调 mprotect，失败后回退 libc，
//   并累计交叉校验与连续失败计数（达阈值锁存 tampered）。
// 参数与所有权：addr/len/prot 同 mprotect(2)；不接管内存所有权。
// 返回值：成功 0；失败 -1（保护未改变）。
// 线程安全：内部计数器非原子自增，调用方应避免并发调用同一路径。
// 平台/架构：直调仅 arm64 Apple；其他平台走 libc 回退。
// 失败语义：fail-closed；连续失败会触发 cprisk_is_mprotect_tampered()。
int cprisk_armor_vm_protect(void *addr, size_t len, int prot);

// 做什么：注册自己的 EXC_BREAKPOINT 处理器，抢占 Frida/调试器对异常端口的接管。
// 参数与所有权：无参数；注册的 port 由本模块持有并在清理时释放。
// 返回值：无。是否成功需查 cprisk_get_exception_handler_snapshot()。
// 线程安全：内部互斥串行化；可在 start() 后重复调用（幂等）。
// 平台/架构：仅 Apple 真机有效；模拟器/降级构建为空操作。
// 失败语义：fail-open（注册失败只记录快照，不抛出）。
void cprisk_register_exception_handler(void);

// 做什么：捕获早期阶段（__thread_init）异常端口归属指纹，作为后续劫持检测基线。
// 参数与所有权：无参数。
// 返回值：无；结果写入快照 early_phase_captured。
// 线程安全：内部互斥；应在首次注册后、大量线程创建前调用。
// 平台/架构：仅 Apple 真机；其他平台空操作。
// 失败语义：fail-open（查询失败则清空指纹并记录）。
void cprisk_capture_early_exception_ports(void);

// 做什么：校验当前 EXC_BREAKPOINT 端口是否仍属于我们，被替换时尝试重新注册。
// 参数与所有权：无参数。
// 返回值：无；结果见快照 port_matches/last_hijack_detected/reclaim_count。
// 线程安全：内部互斥；可周期调用（watchdog/evaluate）。
// 平台/架构：仅 Apple 真机；其他平台空操作。
// 失败语义：fail-open；检测到劫持由上层决定是否投毒/告警。
void cprisk_verify_exception_handler(void);

// 做什么：复制异常处理器最新状态快照。
// 参数与所有权：out_snapshot 由调用方提供；函数整体覆盖，不保留指针。
// 返回值：成功 0；out_snapshot 为 NULL 时 -1。
// 线程安全：内部持锁复制，可并发调用。
// 平台/架构：全平台（降级构建返回全 0 快照）。
// 失败语义：-1 仅表示参数错误。
int cprisk_get_exception_handler_snapshot(cprisk_exception_handler_snapshot_t *out_snapshot);

// 做什么：启动反调试看门狗线程组（多 worker 互检 + 主动探测）。
// 参数与所有权：无参数；线程资源由模块自持。
// 返回值：成功/已在运行/平台 no-op 返回 0；线程创建失败 -1。
// 线程安全：内部互斥；幂等，运行期重复调用不会创建额外线程。
// 平台/架构：Apple 真机为完整实现；其他平台退化为 anti-dump 或空操作。
// 失败语义：fail-open；序言校验失败时返回 -1 并置 FUNCTION_PROLOGUE。
int cprisk_start_anti_debug_watchdog(void);

// 做什么：开关“硬崩溃模式”。开启后命中 HIGH_RISK 看门狗异常（TRACED、
//   EXCEPTION_PORT、DENY_ATTACH_VERIFY、SVC_STUB_INTEGRITY、DYLD_INJECTION 等）
//   会在完成标准完整性投毒后立即 _exit(3)。
// 参数与所有权：enabled 非 0 开启，0 关闭（默认关闭 = 静默污染模式）。
// 返回值：无。
// 线程安全：原子写，可在 watchdog 启停前后任意时刻调用。
// 平台/架构：全平台；无看门狗实现的平台仅保存标志。
// 失败语义：fail-closed（开启后异常直接终止进程）；App Store 安全模式应保持关闭。
void cprisk_set_hard_crash_mode(int enabled);

// 做什么：主线程/调用方心跳 ping，用于与看门狗互检“主线程是否被挂起”。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：原子更新时间戳并递增序号，可并发调用。
// 平台/架构：全平台；降级构建为空操作。
// 失败语义：无；长期不调用会被 watchdog 记为 MAIN_THREAD_STALL。
void cprisk_watchdog_note_main_thread_alive(void);

// 做什么：返回构造器（priority 1）阶段扫描 getenv 得到的 dyld 注入环境位。
// 参数与所有权：无参数。
// 返回值：bit0=DYLD_INSERT_LIBRARIES、bit1=DYLD_INSERT_FRAMEWORKS、
//   bit2=DYLD_LIBRARY_PATH、bit3=DYLD_FORCE_FLAT_NAMESPACE；0=未命中。
// 线程安全：原子读取，可并发调用。
// 平台/架构：仅 arm64 iOS 真机扫描；模拟器/其他平台恒 0。
// 失败语义：fail-open（恒 0 会被视为“无注入”）。
uint32_t cprisk_get_early_injection_env_mask(void);

// 做什么：按当前 hardening mode 对早期注入位应用 fail-closed 策略；
//   仅 production 真正投毒，App Store safe / relaxed QA 跳过。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：应在 cprisk_init_protection() 流程内单线程调用。
// 平台/架构：全平台；无早期注入数据时为空操作。
// 失败语义：fail-closed（production 命中注入位会污染运行期材料）。
void cprisk_apply_deferred_early_injection_policy(void);

// 做什么：请求看门狗停止并 join 所有 worker，释放邮箱等资源；可重复调用。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：内部互斥；不得在 watchdog worker 自身回调中调用（会自 join 死锁）。
// 平台/架构：全平台；降级构建转发到 anti-dump stop。
// 失败语义：fail-open；join 失败被忽略。
void cprisk_stop_anti_debug_watchdog(void);

// 做什么：复制看门狗完整状态快照，并补入实时 libc 回退与环境注入计数。
// 参数与所有权：out_snapshot 必须非 NULL，由调用方提供并按值接收。
// 返回值：成功 0；NULL 时 -1。
// 线程安全：持锁复制，可并发调用。
// 平台/架构：全平台；无 watchdog 实现时返回全 0（仍填充回退/注入位）。
// 失败语义：-1 仅表示参数错误。
int cprisk_get_anti_debug_watchdog_snapshot(
    cprisk_anti_debug_watchdog_snapshot_t *out_snapshot
);

// 做什么：将 dlsym 及高价值外部符号的入口序言与早期基线快照比对
//   （stack shadow memcpy + memcmp），识别 inline hook。
// 参数与所有权：无参数；基线在构造期捕获。
// 返回值：1=完整；0=不匹配（调用方应投毒）。
// 线程安全：内部原子标志 + 只读快照，可并发调用。
// 平台/架构：仅 iOS 真机；模拟器/不支持构建返回 1（no-op 成功）。
// 失败语义：fail-closed（0 表示完整性受损）。
int cprisk_verify_dlsym_prologue(void);

// 序言校验失败位（watchdog snapshot->last_prologue_fail_mask）。
// 置位者：cprisk_verify_dlsym_prologue / 看门狗；读取者：判决层。
// 每轮重新计算并覆盖，不是累计值；失败同时会触发 watchdog lane 投毒。
// bit0–9：镜像内受监控函数失配时的内部槽位索引（实现定义，外部勿解析）。
// 注意：bit10–bit22 与 bit28–bit31 有定义，bit23–bit27 未使用。
enum {
// bit10：access 序言漂移。
    CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_ACCESS = 1u << 10,
// bit11：stat 序言漂移。
    CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_STAT = 1u << 11,
// bit12：lstat 序言漂移。
    CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_LSTAT = 1u << 12,
// bit13：open 序言漂移。
    CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_OPEN = 1u << 13,
// bit14：socket 序言漂移。
    CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_SOCKET = 1u << 14,
// bit15：connect 序言漂移。
    CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_CONNECT = 1u << 15,
// bit16：dlopen 序言漂移。
    CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_DLOPEN = 1u << 16,
// bit17：sysctl 序言漂移。
    CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_SYSCTL = 1u << 17,
// bit18：sysctlbyname 序言漂移。
    CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_SYSCTLBYNAME = 1u << 18,
// bit19：mprotect 序言漂移。
    CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_MPROTECT = 1u << 19,
// bit20：mach_msg 序言漂移。
    CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_MACH_MSG = 1u << 20,
// bit21：task_get_exception_ports 序言漂移。
    CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_TASK_GET_EXCEPTION_PORTS = 1u << 21,
// bit22：task_swap_exception_ports 序言漂移。
    CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_TASK_SWAP_EXCEPTION_PORTS = 1u << 22,
// bit28：_dyld_image_count 序言漂移。
    CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_DYLD_IMAGE_COUNT = 1u << 28,
// bit29：objc_msgSend 序言漂移。
    CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_OBJC_MSGSEND = 1u << 29,
// bit30：dlsym 序言漂移。
    CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_DLSYM = 1u << 30,
// bit31：pthread_create 序言漂移。
    CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_PTHREAD_CREATE = 1u << 31,
};

// 做什么：校验 objc_msgSend、_dyld_image_count 及高价值运行时导出
//   （含 access/stat/mprotect/异常端口 Mach API）的序言与导出归属是否漂移。
// 参数与所有权：无参数。
// 返回值：1=完整；0=不匹配。模拟器/macOS 测试宿主返回 1。
// 线程安全：只读快照 + 原子标志，可并发调用。
// 平台/架构：仅 iOS 真机；其他平台 no-op 成功。
// 失败语义：fail-closed（0 表示 hook 面受损）。
int cprisk_verify_runtime_hook_surface_prologues(void);
// 做什么：返回最近一次运行时 hook 面导出/归属/trampoline 漂移位。
// 参数与所有权：无参数。
// 返回值：0=干净；非 0=存在漂移（位定义由实现内部维护）。
// 线程安全：原子读取。
// 平台/架构：非真机恒 0。
// 失败语义：fail-open（0 不保证绝对干净，仅表示未观测到漂移）。
uint32_t cprisk_runtime_hook_surface_export_drift_mask(void);

// Security.framework trust API 与 dlopen/dlsym 的序言校验失败位
// （cprisk_verify_trust_hook_surface_integrity 的 fail_mask_out）。
// 置位者：该校验函数；每轮重新计算并覆盖；失败会立即投毒 watchdog lane。
enum {
// bit0：SecTrustEvaluateWithError 序言漂移。
    CPRISK_TRUST_HOOK_FAIL_SEC_TRUST_EVAL_WITH_ERROR = 1u << 0,
// bit1：SecTrustGetTrustResult 序言漂移。
    CPRISK_TRUST_HOOK_FAIL_SEC_TRUST_GET_TRUST_RESULT = 1u << 1,
// bit2：SecTrustCopyKey 序言漂移。
    CPRISK_TRUST_HOOK_FAIL_SEC_TRUST_COPY_KEY = 1u << 2,
// bit3：dlsym 序言漂移。
    CPRISK_TRUST_HOOK_FAIL_DLSYM = 1u << 3,
// bit4：dlopen 序言漂移。
    CPRISK_TRUST_HOOK_FAIL_DLOPEN = 1u << 4,
};

// 做什么：对 TLS pinning 路径使用的 Security trust API 及 dlsym/dlopen
//   做快照 + 序言校验，识别 Frida Interceptor 类补丁。
// 参数与所有权：fail_mask_out 可为 NULL；非 NULL 时写入失败位。
// 返回值：1=完整；0=不匹配。失败时 *fail_mask_out 为 CPRISK_TRUST_HOOK_FAIL_*。
// 线程安全：只读基线 + 原子 last_ok，可并发调用。
// 平台/架构：仅 Apple；非 Apple 构建 no-op 成功（返回 1）。
// 失败语义：fail-closed（失败同时投毒看门狗 lane）。
int cprisk_verify_trust_hook_surface_integrity(uint32_t *fail_mask_out);

// 做什么：复制反调试计划（嵌入配置段）的解析与策略快照。
// 参数与所有权：out_snapshot 必须非 NULL，由调用方提供。
// 返回值：成功 0；NULL 时 -1。
// 线程安全：内部读取一致性快照，可并发调用。
// 平台/架构：全平台；无计划段时字段为 0。
// 失败语义：-1 仅表示参数错误。
int cprisk_get_antidebug_plan_snapshot(
    cprisk_antidebug_plan_snapshot_t *out_snapshot
);

// 做什么：一次性触发 Mach-O 头恢复流程（pthread_once）。名字保留自旧实现，
//   现在不再清零 magic，而是从 __DATA.__swift5_mhsav 还原加密字段；
//   还原失败时走 fail-closed 投毒（data_loader lane），不修改头部。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：pthread_once 保证只执行一次，可并发调用。
// 平台/架构：全平台；无备份段的安全构建为空操作。
// 失败语义：fail-closed（失败投毒），但函数本身不阻塞流程。
void cprisk_erase_macho_header(void);

// 做什么：从 __DATA.__swift5_mhsav 恢复加密的 mach_header_64 字段，
//   支持 legacy 固定 marker 与按二进制伪装的 reserved 值。
// 参数与所有权：无参数；内部对头部页做临时 mprotect。
// 返回值：0=恢复成功；1=无需恢复/已恢复/未加固；-1=校验或写入失败。
// 线程安全：pthread_once + 重试互斥；可重复调用。
// 平台/架构：全平台；构造器(120) 会主动调用一次。
// 失败语义：fail-closed（-1 由调用方决定是否投毒；erase 入口会投毒）。
int cprisk_restore_macho_header(void);

// ── cprisk-armor 运行时支持（ABI v1） ─────────────────────────────

// 做什么：用 32 字节密钥初始化字符串解密器，并重置完整性累加器；
//   密钥用于 CPRisk-MAC 校验与派生的 SHA256 keystream。
// 参数与所有权：key 由调用方提供，内部复制 32 字节，不接管所有权。
// 返回值：成功 0；key 为 NULL 或 key_len != 32 时 -1。
// 线程安全：内部互斥；应在单线程初始化阶段调用。
// 平台/架构：全平台（依赖镜像中的字符串表段）。
// 失败语义：fail-closed（初始化失败后所有解密返回 -1）。
int cprisk_init_string_decryptor(const uint8_t *key, size_t key_len);

// 做什么：按 string_id 从打包字符串表解出明文，并在交付前做 CPRisk-MAC
//   完整性校验；调试器命中时返回按位取反的污染结果。
// 参数与所有权：buffer 由调用方提供，容量 buffer_size；明文含结尾 NUL；
//   函数只写 buffer，不保留指针。
// 返回值：成功返回明文字节数（>=1）；失败 -1（未初始化/未找到/容量不足/
//   MAC 不符或边界异常）。
// 线程安全：内部互斥串行化，可并发调用但吞吐受锁限制。
// 平台/架构：全平台；镜像缺少字符串表时恒 -1。
// 失败语义：fail-closed（校验失败即拒绝），并更新完整性累加器。
int cprisk_decrypt_string(uint32_t string_id, char *buffer, size_t buffer_size);

// 做什么：ABI 兼容别名，现直接转发到 cprisk_decrypt_string()（旧的单槽
//   明文缓存已移除，避免在静态段留下可 dump 的明文）。
// 参数与所有权：同 cprisk_decrypt_string()。
// 返回值：同 cprisk_decrypt_string()。
// 线程安全：同 cprisk_decrypt_string()。
// 平台/架构：同 cprisk_decrypt_string()。
// 失败语义：同 cprisk_decrypt_string()。
int cprisk_decrypt_string_lazy(uint32_t string_id, char *buffer, size_t buffer_size);

// 做什么：历史 lazy 缓存清理入口；缓存已移除，现为空操作，仅为 ABI 稳定保留。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：空操作，可并发调用。
// 平台/架构：全平台。
// 失败语义：无。
void cprisk_string_lazy_scrub_all(void);

// 做什么：读取字符串解密完整性累加器（每次成功解密按 string_id 旋转 XOR）。
// 参数与所有权：无参数。
// 返回值：当前 64 位累加器值；0=尚未解密或已清理。
// 线程安全：内部互斥读取。
// 平台/架构：全平台。
// 失败语义：无；仅作旁证，不应单独作为判决。
uint64_t cprisk_get_string_integrity_accumulator(void);

// 做什么：安全擦除解密密钥、分发种子与完整性累加器，并把 ready 置 0。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：内部互斥；清理后并发解密会返回 -1。
// 平台/架构：全平台。
// 失败语义：无；清理后必须重新 init 才能解密。
void cprisk_cleanup_string_decryptor(void);

// ── 检测证明（cprisk_detection_attest.c） ─────────────────────────────
// 职责：把一次 JailbreakEngineV2 运行中观察到的检测器结果序列绑定成 32 字节
//   tag，随上报一起提交；服务端用同一密钥（WhiteBox Domain 5 =
//   runtimeMaterial 派生）重放，tag 不一致说明 Swift 派发链路被 hook。
// 调用时序：begin() → 每个 detector 完成后 record() → finalize()；
//   finalize 后会话结束，未重新 begin 的 record 为 no-op。
// 线程安全：begin/record/finalize 由同一把互斥锁串行化，允许检测线程并发调用。
// 失败语义：begin 恒返回 0；finalize 在无活动会话或 out_tag 为 NULL 时返回 -1
//   并清零输出；密钥仅在首次使用时派生并缓存。
// 生命周期：begin() 写入 16 字节 nonce；finalize() 输出 32 字节 tag 与实际
//   record 条数；nonce 可回传服务端用于定位重放会话。
// 做什么：开始新的证明会话，生成随机 16 字节 nonce，并以
//   SHA256(label || nonce) 初始化滚动链。
// 参数与所有权：out_nonce 可为 NULL；非 NULL 时写入 16 字节，调用方拥有。
// 返回值：恒 0（随机源失败时退化为时间 + 计数器混合）。
// 线程安全：内部互斥；会覆盖上一会话状态。
// 平台/架构：全平台（随机源优先 SecRandom）。
// 失败语义：无失败路径；重复 begin 会重置链。
int  cprisk_attest_session_begin(uint8_t out_nonce[16]);
// 做什么：把一个检测结果 (detector_id, score, methods_hash) 折叠进滚动链：
//   H' = SHA256(H || id_le4 || score_le4 || hash[32])。
// 参数与所有权：methods_hash 可为 NULL（按 32 字节 0 参与）；不保留指针。
// 返回值：无。无活动会话或 finalize 后调用会被静默忽略。
// 线程安全：内部互斥；顺序即调用顺序，服务端重放必须保持同一顺序。
// 平台/架构：全平台。
// 失败语义：fail-open（记录被忽略时 finalize 的 count/tag 会对不上）。
void cprisk_attest_record(uint8_t detector_id,
                          int32_t score,
                          const uint8_t methods_hash[32]);
// 做什么：结束会话，输出 CPRisk-MAC 保护的 32 字节 tag 与记录条数。
// 参数与所有权：out_tag 必须非 NULL（32 字节）；out_count 可为 NULL；
//   输出缓冲区由调用方提供。
// 返回值：成功 0；无活动会话或 out_tag 为 NULL 时 -1（输出清零）。
// 线程安全：内部互斥；成功后会话失活，后续 record 为 no-op。
// 平台/架构：全平台。
// 失败语义：fail-closed（拿不到 tag 时调用方不应上报“已验证”）。
int  cprisk_attest_session_finalize(uint8_t out_tag[32],
                                    uint32_t *out_count);
// 做什么：读取当前（或最近一次）会话 nonce，供上报回显。
// 参数与所有权：out_nonce 可为 NULL；非 NULL 时写入 16 字节。
// 返回值：无。
// 线程安全：内部互斥。
// 平台/架构：全平台。
// 失败语义：无；无会话时返回上次数据。
void cprisk_attest_get_session_nonce(uint8_t out_nonce[16]);

// 做什么：测试专用：按运行期同一确定性选择器，判断某 string_id 会走哪条
//   解密微路径。
// 参数与所有权：nonce 为 16 字节；seed 由测试提供。
// 返回值：0–3 的路径编号；非 DEBUG 构建或 nonce 为 NULL 时返回 0。
// 线程安全：纯计算，可并发调用。
// 平台/架构：全平台；非 DEBUG 构建为惰性桩。
// 失败语义：无；返回值不作为安全判断。
uint32_t cprisk_test_select_string_decrypt_path(
    uint32_t string_id,
    const uint8_t nonce[CPRISK_ARMOR_NONCE_SIZE],
    uint64_t seed
);

// 做什么：用 32 字节全局密钥初始化受保护 __DATA 段加载器，并重置状态。
// 参数与所有权：key 由调用方提供，内部复制 32 字节。
// 返回值：成功 0；key 为 NULL 或长度 != 32 时 -1。
// 线程安全：内部无锁写（初始化阶段单线程约定）；并发解密前必须完成。
// 平台/架构：全平台；镜像无 loader 段时后续 load 失败。
// 失败语义：fail-closed（初始化失败后 cprisk_load_protected_data 返回 -1）。
int cprisk_init_data_loader(const uint8_t *key, size_t key_len);

// 做什么：按 ABI-v1 loader 描述符解密所有受保护 __DATA 段；解密前校验
//   描述符边界、目标段归属与可写权限，失败会回滚已解密条目。
// 参数与所有权：无参数；密钥来自 cprisk_init_data_loader。
// 返回值：成功返回解密的段数（>=0）；失败 -1。已加载时重复调用返回 0。
// 线程安全：内部 loader 互斥；仅应在初始化阶段调用。
// 平台/架构：依赖本进程 Mach-O 段布局；模拟器可运行但通常无加固段。
// 失败语义：fail-closed（失败回滚并投毒 data_loader lane）。
int cprisk_load_protected_data(void);

// 做什么：在 EXC_BAD_ACCESS 处理路径中按需解密命中的受保护页；先尝试
//   __TEXT 页路径，再匹配 __DATA loader 条目。
// 参数与所有权：fault_addr 为故障地址（不可为 NULL）；不接管内存。
// 返回值：1=页面已解密；0=不是受保护页/未加载/解密失败。
// 线程安全：内部 loader 互斥 + 页级状态，可并发进入但会串行化。
// 平台/架构：全平台（模拟器无保护段时恒 0）。
// 失败语义：fail-closed（返回 0 时页仍为 PROT_NONE，异常会再次触发）。
int cprisk_jit_decrypt_page(void *fault_addr);

// 做什么：在不解引用的情况下解密包含 addr 的 __TEXT 受保护页（Pass12），
//   复用与 fault 路径相同的“使用后按空闲时限重新加密”机制。
// 参数与所有权：addr 为目标地址（不可 NULL）；不接管内存。
// 返回值：1=已解密；0=非保护页/元数据缺失/失败。
// 线程安全：内部 text 互斥，可并发调用。
// 平台/架构：仅 arm64 真机有实际实现；模拟器返回 0。
// 失败语义：fail-open（失败不改变页状态）。
int cprisk_text_on_demand_decrypt(void *addr);

// 做什么：周期服务：对已解密超过空闲时限的 __TEXT 页重新加密，并顺带做
//   自检，异常时投毒 text_encrypt lane。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：内部 text 互斥；适合 watchdog/evaluate 周期调用。
// 平台/架构：模拟器/无 Pass12 元数据时为空操作。
// 失败语义：fail-closed（自检异常即投毒）。
void cprisk_text_encrypt_service_idle(void);

// __TEXT 页加密状态自检位（cprisk_text_encrypt_self_check 返回）。
// 置位者：自检函数；读取者：调用方/服务循环。每轮重新计算，不累计。
enum {
// 无异常。
    CPRISK_TEXT_ENCRYPT_SELF_CHECK_FLAG_NONE = 0u,
// bit0：已解密页驻留超过允许的空闲窗口。
    CPRISK_TEXT_ENCRYPT_SELF_CHECK_FLAG_DECRYPTED_STALE = 1u << 0,
// bit1：应可读的已解密页保护位异常。
    CPRISK_TEXT_ENCRYPT_SELF_CHECK_FLAG_DECRYPTED_PROTECTION_DRIFT = 1u << 1,
// bit2：应 PROT_NONE 的加密页保护位异常。
    CPRISK_TEXT_ENCRYPT_SELF_CHECK_FLAG_ENCRYPTED_PROTECTION_DRIFT = 1u << 2,
// bit3：蜜罐页保护状态漂移。
    CPRISK_TEXT_ENCRYPT_SELF_CHECK_FLAG_HONEYPOT_PROTECTION_DRIFT = 1u << 3,
// bit4：已解密页内容与预期不符。
    CPRISK_TEXT_ENCRYPT_SELF_CHECK_FLAG_DECRYPTED_CONTENT_DRIFT = 1u << 4,
// bit5：加密页内容与预期不符。
    CPRISK_TEXT_ENCRYPT_SELF_CHECK_FLAG_ENCRYPTED_CONTENT_DRIFT = 1u << 5,
};

// 做什么：校验受保护 text 页处于“刚解密 RX”或“加密 PROT_NONE”之一，
//   且没有解密页超过驻留窗口；同时检查内容与保护位。
// 参数与所有权：无参数。
// 返回值：CPRISK_TEXT_ENCRYPT_SELF_CHECK_FLAG_* 的按位或；0=正常。
// 线程安全：内部 text 互斥，可并发调用。
// 平台/架构：模拟器/无元数据时返回 0。
// 失败语义：非 0 由调用方决定投毒/告警（service_idle 会自动投毒）。
uint32_t cprisk_text_encrypt_self_check(void);

// 做什么：读取数据加载完整性累加器（每次成功解密/装载更新）。
// 参数与所有权：无参数。
// 返回值：64 位累加器；0=尚未装载或已卸载。
// 线程安全：普通读取（无锁），弱一致。
// 平台/架构：全平台。
// 失败语义：无；作旁证使用。
uint64_t cprisk_get_data_integrity_accumulator(void);

// 做什么：卸载数据加载器：重新加密已解密段、恢复保护、munlock、擦除密钥与状态。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：内部 loader 互斥；应在停止探测后、单线程清理阶段调用。
// 平台/架构：全平台；未装载时为空操作。
// 失败语义：fail-open（尽力回滚，失败不抛出）。
void cprisk_unload_protected_data(void);

// 做什么：对 __TEXT.__text 做三路径完整性哈希（A/B 直接计算，C 路径从四个
//   拆分 anchor 段重建 32 字节锚摘要），并记录各路径耗时（用于时序探测）。
// 参数与所有权：out_hash 由调用方提供 32 字节。
// 返回值：成功 0；out_hash 为 NULL、找不到本镜像或路径失败 -1。
// 线程安全：只读镜像 + 内部时序状态，可并发调用。
// 平台/架构：全平台（依赖 Mach-O 段布局）。
// 失败语义：fail-closed（-1 表示无法计算，不应视为完整）。
int cprisk_compute_integrity_hash(uint8_t *out_hash);

// 做什么：从四个 8 字节拆分 anchor lane 重建完整 32 字节 anchor hash；
//   ABI v2 的 full-hash 段只存 CPRisk-MAC tag，不再存明文 hash。
// 参数与所有权：out_hash 由调用方提供 32 字节。
// 返回值：成功 0；NULL/镜像或段缺失/长度校验失败 -1。
// 线程安全：只读，可并发调用。
// 平台/架构：全平台（需 armor 段）。
// 失败语义：fail-closed（-1 时 out_hash 内容不可用）。
int cprisk_read_full_anchor_hash(uint8_t *out_hash);

// 做什么：以 root_material 为密钥，校验 full-hash 段中的 CPRisk-MAC tag
//   是否对应传入的 full_hash。
// 参数与所有权：root_material 与 full_hash 均为 32 字节只读缓冲。
// 返回值：0=MAC 匹配；-1=不匹配或段/长度异常。
// 线程安全：纯计算 + 只读段，可并发调用。
// 平台/架构：全平台（需 armor 段）。
// 失败语义：fail-closed（-1 必须视为 anchor 不可信）。
int cprisk_verify_anchor_mac(const uint8_t root_material[32],
                              const uint8_t full_hash[32]);

// SDK 集成用的加固策略档位（cprisk_set_runtime_hardening_mode）。
// 置位者/读取者：Swift 集成层设置，C 层策略与初始化时序检查读取。
// 生命周期：进程级全局；可随时修改，影响后续策略应用；非法值回落 PRODUCTION。
enum {
// 0：生产模式，全部探测按最高强度计分。
    CPRISK_RUNTIME_HARDENING_PRODUCTION = 0,
// 1：开发/QA：TTY、Developer Disk、时序等弱探针不计入调试器评分，
//   初始化时序门槛更宽。
    CPRISK_RUNTIME_HARDENING_RELAXED_DEV_QA = 1,
// 2：App Store/审核友好：弱探针评分同开发模式，Swift 层跳过激进
//   attach/watchdog/dump/header 路径。
    CPRISK_RUNTIME_HARDENING_APP_STORE_SAFE = 2,
};

// 加固模式类型别名；取值必须为上面三个枚举之一。
typedef int cprisk_runtime_hardening_mode_t;

// 做什么：设置进程级加固模式；非法值静默回落 PRODUCTION。
// 参数与所有权：mode 取 CPRISK_RUNTIME_HARDENING_*。
// 返回值：无。
// 线程安全：普通全局写；建议初始化前调用，运行期修改需接受竞态。
// 平台/架构：全平台。
// 失败语义：fail-closed 于非法值（强制 PRODUCTION）。
void cprisk_set_runtime_hardening_mode(cprisk_runtime_hardening_mode_t mode);
// 做什么：读取当前加固模式。
// 参数与所有权：无参数。
// 返回值：CPRISK_RUNTIME_HARDENING_* 之一。
// 线程安全：普通读取，弱一致。
// 平台/架构：全平台。
// 失败语义：无。
cprisk_runtime_hardening_mode_t cprisk_get_runtime_hardening_mode(void);

// 做什么：主初始化：用 root_key 派生锚绑定累加器，再派生 loader key 与
//   runtime material，最后解密受保护 __DATA；同时重置投毒/看门狗状态。
// 参数与所有权：root_key 必须非 NULL 且非全零；内部复制/截断到 32 字节；
//   调用方保留缓冲区所有权。
// 返回值：成功 0；参数非法、全零密钥、镜像/段校验失败返回负值。
// 线程安全：须在单线程、启动早期调用；内部会启停看门狗与 anti-dump。
// 平台/架构：全平台；模拟器缺少加固段时可能返回负值。
// 失败语义：fail-closed（失败后 runtime material 不可用，签名/解密链路拒绝）。
int cprisk_init_protection(const uint8_t *root_key, size_t root_key_len);

// 做什么：拆除全部 armor 运行期状态：擦除 runtime material/device key/session、
//   停止 watchdog 与 anti-dump、卸载受保护数据、清空投毒状态。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：应单线程调用，且确保没有其他线程仍在调用解密/签名 API。
// 平台/架构：全平台；未初始化时为空操作。
// 失败语义：fail-open（尽力清理，不抛出）。
void cprisk_cleanup_protection(void);

// 做什么：取出 32 字节 runtime material 供 Swift 签名/校验使用。真实路径
//   返回派生材料；投毒/欺骗路径返回确定性诱饵字节（用于误导本地 hook 与
//   返回码 oracle）。
// 参数与所有权：out_material 必须非 NULL，由调用方提供 32 字节。
// 返回值：非 NULL 时恒 0；NULL 时 -1。返回值不是真实性 oracle。
// 线程安全：读内部状态并复制，可并发调用（状态可能瞬时变化）。
// 平台/架构：全平台。
// 失败语义：fail-open/欺骗语义——调用方需结合 cprisk_runtime_material_ready()
//   与可见的投毒标志判断，不能依赖返回值。
int cprisk_get_runtime_material(uint8_t out_material[32]);

// 做什么：报告初始化阶段是否成功派生真实 runtime material（不暴露字节）。
// 参数与所有权：无参数。
// 返回值：1=可用；0=不可用/已清理/初始化未完成。
// 线程安全：原子读取，可并发调用。
// 平台/架构：全平台。
// 失败语义：0 表示 fail-closed 状态，上层应降级或拒绝签名。
int cprisk_runtime_material_ready(void);

// ── 导入表加密解析器 ────────────────────────────────────────────────

// 做什么：按索引从加密导入表解析符号：读 __DATA.__swift5_dyrel、校验
//   CPRisk-MAC-SHA256、用 SHA256 keystream 解密符号名，再经 dlsym 解析。
// 参数与所有权：symbol_index 从 0 开始；>= CPRISK_SWIFT_BRIDGE_IMPORT_BASE
//   的索引走 Swift 桥接别名表；out_addr 必须非 NULL，由调用方提供。
// 返回值：成功 0 并写 *out_addr；失败 -1（越界、MAC 不符、dlsym 失败），
//   失败时 *out_addr 置 NULL。
// 线程安全：内部缓存由互斥锁保护，可并发调用。
// 平台/架构：依赖本进程 Mach-O 导入表；无表/模拟器构建返回 -1。
// 失败语义：fail-closed（校验失败即拒绝解析，不回落 RTLD_DEFAULT）。
int cprisk_resolve_import(uint32_t symbol_index, void **out_addr);

// 做什么：诊断用：比较 dlsym(RTLD_DEFAULT,"mprotect") 与导出 trie 解析结果。
// 参数与所有权：无参数。
// 返回值：0=一致；1=不一致；-1=任一查找失败。
// 线程安全：可并发调用。
// 平台/架构：依赖 dyld 导出 trie；非 Apple 构建不可用。
// 失败语义：fail-open；仅测试/诊断，不进入生产判决。
int cprisk_verify_mprotect_dlsym_matches_export_trie(void);

// 导入解析路径分类位（cprisk_test_import_resolve_strategy_for_symbol）。
// 置位者：测试辅助函数；读取者：测试。按位或，每轮重新计算。
enum {
// 无分类（空符号名/非 DEBUG）。
    CPRISK_IMPORT_RESOLVE_PATH_NONE = 0u,
// bit0：导出 trie 唯一命中。
    CPRISK_IMPORT_RESOLVE_PATH_TRIE_UNIQUE = 1u << 0,
// bit1：导出 trie 命中多个候选。
    CPRISK_IMPORT_RESOLVE_PATH_TRIE_AMBIGUOUS = 1u << 1,
// bit2：trie 未命中，回退 RTLD_DEFAULT。
    CPRISK_IMPORT_RESOLVE_PATH_RTLD_FALLBACK = 1u << 2,
// bit3：dlsym 与 trie 结果交叉校验失败。
    CPRISK_IMPORT_RESOLVE_PATH_CROSSCHECK_FAIL = 1u << 3,
};

// 做什么：测试专用：对明文符号名预测导入解析会走的路径。
// 参数与所有权：symbol_name 为 NUL 结尾；NULL 返回 NONE。
// 返回值：CPRISK_IMPORT_RESOLVE_PATH_* 位组合；非 DEBUG 构建恒 0。
// 线程安全：可并发调用（只读解析）。
// 平台/架构：依赖导出 trie，仅 Apple 有效。
// 失败语义：非 DEBUG 时惰性桩，不泄漏解析策略。
uint32_t cprisk_test_import_resolve_strategy_for_symbol(const char *symbol_name);

// ── White-box 前端 / 签名辅助 ───────────────────────────────────────

// 做什么：返回当前 armor 运行时的能力位图，并探测保留 white-box 元数据
//   段是否存在（CPRISK_ARMOR_CAP_*）。
// 参数与所有权：无参数。
// 返回值：能力位组合；无元数据段时只含基础能力。
// 线程安全：只读镜像 + 纯计算，可并发调用。
// 平台/架构：全平台；VM 能力位取决于 VMP 运行时。
// 失败语义：无；位缺失表示能力不可用，不代表错误。
uint32_t cprisk_get_armor_capabilities(void);

// 做什么：填充最小 white-box 探测快照：ABI 版本、能力位、探测状态
//   （COMPILED/METADATA_PRESENT/METADATA_VALID/ENGINE_READY）与元数据版本。
// 参数与所有权：out_probe 必须非 NULL，由调用方提供并整体覆盖。
// 返回值：成功 0；out_probe 为 NULL 时 -1。
// 线程安全：只读镜像，可并发调用。
// 平台/架构：全平台；无元数据段时 flags 仅含 COMPILED。
// 失败语义：fail-open（探测不到元数据只降低 flags，不报错）。
int cprisk_whitebox_probe(struct cprisk_whitebox_probe_result *out_probe);

// 做什么：仅当镜像内嵌有效 white-box 元数据且引擎就绪时返回 1。
// 参数与所有权：无参数。
// 返回值：1=可用；0=不可用（占位构建通常为 0）。
// 线程安全：只读，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-open（0 表示能力缺失，不是错误）。
int cprisk_whitebox_available(void);

// 做什么：对一个 white-box PRF domain 求值：PRF(domain, input) → out。
//   域 6–7 在混合 KDF 成功后把 effectiveRoot、signal 压力位与 VM 计数混入
//   输入；域 8–9 的导入/头部密钥必须使用原样输入，以保证构建期密文可复现。
//   元数据带 ASLR_TABLE_BIND 时，表体按 Mach slide 解掩码后再求值。
// 参数与所有权：input 为 32 字节（可为 NULL，按全 0 处理）；out 必须非 NULL。
// 返回值：成功 0；校验失败、未知 domain、out 为 NULL 时 -1。
// 线程安全：只读内部元数据 + 测试注入状态，可并发调用。
// 平台/架构：全平台；被调试器命中时返回确定性但错误的 PRF 输出（仍返回 0）。
// 失败语义：fail-closed（-1 表示域不可用/元数据无效）。
// 安全边界：表随二进制分发，white-box 只是混淆，不是信任根；提取表即可
//   恢复有效密钥材料，真正的保密需 HKDF + AEAD + 硬件密钥。
// 运行期开关：CPRISK_WB_ASLR_TABLE_DISABLE=1 禁用解掩码；
//   编译期 CPRISK_DISABLE_WHITEBOX_ASLR_TABLE 剥离该路径。
int cprisk_whitebox_evaluate_domain(
    uint32_t domain_id,
    const uint8_t input[32],
    uint8_t out[32]
);

// 做什么：由 runtime material 与调用方 base_key 派生 32 字节有效签名密钥，
//   等价于原 Swift 侧 CPRisk-MAC(runtime_material, base_key)。
//   iOS 真机 release 默认把 ASLR slide 熵 XOR 进 material 前 8 字节；
//   可用 CPRISK_SIGNING_KEY_ASLR_BIND=1/0 强制开关。
// 参数与所有权：base_key 可为 NULL 仅当 base_key_len==0；out_key 由调用方
//   提供 32 字节。
// 返回值：成功 0；参数非法或派生失败 -1。
// 线程安全：只读 material + 纯计算，可并发调用。
// 平台/架构：全平台；非真机无 slide 绑定。
// 失败语义：fail-closed（-1 时 out_key 不可用）。
int cprisk_derive_effective_signing_key(
    const uint8_t *base_key,
    size_t base_key_len,
    uint8_t out_key[32]
);

// 做什么：在 cprisk_derive_effective_signing_key 基础上做请求级重绑定：
//   derived = MAC(runtime_material, base_key)
//   rebound = MAC(derived, request_binding_digest)
// 参数与所有权：request_binding_digest 必须非 NULL（32 字节）；out_key 32 字节。
// 返回值：成功 0；NULL 或派生失败 -1。
// 线程安全：纯计算，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed。
int cprisk_derive_effective_signing_key_with_request_binding_digest(
    const uint8_t *base_key,
    size_t base_key_len,
    const uint8_t request_binding_digest[32],
    uint8_t out_key[32]
);

// 做什么：同 cprisk_derive_effective_signing_key，但输出小写十六进制。
// 参数与所有权：out_hex 由调用方提供，容量必须为 65 字节（64 hex + NUL）。
// 返回值：成功 0；参数非法/派生失败 -1。
// 线程安全：纯计算，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed；失败时 out_hex 内容不可用。
int cprisk_derive_effective_signing_key_hex(
    const uint8_t *base_key,
    size_t base_key_len,
    char out_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1]
);

// 做什么：通用 CPRisk-MAC-SHA256，输出小写十六进制。
// 参数与所有权：key 可为 NULL 仅当 key_len==0；msg 可为 NULL 仅当 msg_len==0；
//   out_hex 容量必须为 65 字节。
// 返回值：成功 0；out_hex 为 NULL 或 key/msg 与长度矛盾 -1。
// 线程安全：纯计算，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed；失败时不保证 out_hex 内容。
int cprisk_mac_sha256_hex(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *msg,
    size_t msg_len,
    char out_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1]
);

// 做什么：在 C 内派生有效签名密钥，再对 msg 做 CPRisk-MAC，输出小写 hex。
//   这是 v2a 类安全信封的首选桥接：Swift 无需持有 runtime material。
// 参数与所有权：base_key/msg 允许 NULL 仅当对应长度为 0；out_hex 65 字节。
// 返回值：成功 0；参数非法/派生失败 -1。
// 线程安全：纯计算 + 只读 material，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed（-1 时不得发送该签名）。
int cprisk_sign_with_derived_key(
    const uint8_t *base_key,
    size_t base_key_len,
    const uint8_t *msg,
    size_t msg_len,
    char out_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1]
);

// 做什么：同 cprisk_sign_with_derived_key，但先用 32 字节请求绑定摘要对
//   有效密钥做直接重绑定。
// 参数与所有权：request_binding_digest 必须非 NULL；out_hex 65 字节。
// 返回值：成功 0；参数非法/派生失败 -1。
// 线程安全：纯计算，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed。
int cprisk_sign_with_derived_key_and_request_binding_digest(
    const uint8_t *base_key,
    size_t base_key_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t request_binding_digest[32],
    char out_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1]
);

// 做什么：重算签名 hex，并与 expected_hex 做常量时间比较。
// 参数与所有权：expected_hex 必须非 NULL 且恰好 64 个 hex 字符；
//   msg 可为 NULL 仅当 msg_len==0。
// 返回值：0=匹配；-1=不匹配或参数/派生失败。
// 线程安全：使用常量时间比较，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed（任何异常都返回 -1，不区分“不匹配”与“错误”）。
int cprisk_verify_with_derived_key(
    const uint8_t *base_key,
    size_t base_key_len,
    const uint8_t *msg,
    size_t msg_len,
    const char *expected_hex
);

// 做什么：同 cprisk_verify_with_derived_key，但签名侧使用请求绑定摘要重绑定。
// 参数与所有权：request_binding_digest 必须非 NULL；expected_hex 64 字符。
// 返回值：0=匹配；-1=不匹配/参数非法/派生失败。
// 线程安全：常量时间比较，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed。
int cprisk_verify_with_derived_key_and_request_binding_digest(
    const uint8_t *base_key,
    size_t base_key_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t request_binding_digest[32],
    const char *expected_hex
);

// ── 混合密钥派生（三层 KDF） ────────────────────────────────────────

// 做什么：从 root key 初始化三层 KDF：
//   Layer2 deviceKey     = MAC(rootKey, deviceSalt)
//   Layer3 effectiveRoot = MAC(deviceKey, sessionToken)
//   结果供动态 white-box 域 6–7 使用；设备盐不可得时 deviceKey 直接失败
//   （不做常量盐回退）。
// 参数与所有权：root_key 必须非 NULL（32 字节）；内部复制派生，不接管。
// 返回值：成功 0；NULL 或设备盐不可用 -1。
// 线程安全：写全局 KDF 状态，应在初始化阶段单线程调用。
// 平台/架构：设备盐依赖 IOKit/Keychain，模拟器可能不可用。
// 失败语义：fail-closed（设备绑定失败则动态域退回 identity 输入）。
int cprisk_init_hybrid_kdf(const uint8_t *root_key);

// 做什么：派生 Layer2 设备密钥：MAC(rootKey, deviceSalt)。
// 参数与所有权：root_key 必须非 NULL；out_device_key 由调用方提供 32 字节。
// 返回值：成功 0 并置 device_bound；设备盐不可用或参数非法 -1。
// 线程安全：读取设备盐并写全局 bound 标志，建议串行调用。
// 平台/架构：盐来自 IOKit/Keychain；不可用时直接失败（无静态盐回退）。
// 失败语义：fail-closed。
int cprisk_derive_device_key(const uint8_t *root_key,
                             uint8_t out_device_key[CPRISK_ARMOR_KEY_SIZE]);

// 做什么：取出已缓存的 Layer2 设备密钥。
// 参数与所有权：out_key 由调用方提供 32 字节。
// 返回值：成功 0；未就绪或 NULL 时 -1（不写输出）。
// 线程安全：读取全局状态，弱一致。
// 平台/架构：全平台。
// 失败语义：fail-closed（-1 表示不可用于派生）。
int cprisk_get_device_key(uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]);

// 做什么：取出 Layer3 effectiveRoot（动态 white-box 域 6–7 的派生密钥）。
// 参数与所有权：out_key 由调用方提供 32 字节。
// 返回值：成功 0；未就绪或 NULL 时 -1。
// 线程安全：读取全局状态，弱一致。
// 平台/架构：全平台。
// 失败语义：fail-closed。
int cprisk_get_effective_root(uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]);

// 做什么：报告当前是否使用真实（非回退）硬件盐。
// 参数与所有权：无参数。
// 返回值：1=设备绑定成立；0=未绑定或盐不可用。
// 线程安全：原子读取。
// 平台/架构：依赖 IOKit/Keychain；模拟器通常为 0。
// 失败语义：0 表示 fail-closed，不应据此生成设备绑定密钥。
int cprisk_is_device_bound(void);

// ── 会话令牌管理 ────────────────────────────────────────────────────

// 做什么：安装 Layer3 会话 token。仅接受签名格式：
//   [32 字节 token || 32 字节 CPRisk-MAC(token)]，共 64 字节；
//   裸 32 字节 token 一律拒绝（无认证）。有效期 24 小时。
//   校验密钥在调用时由 runtime material 派生，无内置常量密钥。
// 参数与所有权：token 由调用方提供，函数只复制前 32 字节；不接管所有权。
// 返回值：成功 0；NULL、长度不符、MAC 不符、runtime material 不可用或
//   时间溢出时 -1；MAC 不符会同时清空现有 token。
// 线程安全：内部互斥保护 token/有效期/有效标志。
// 平台/架构：全平台。
// 失败语义：fail-closed（无有效 token 时 Layer3 退回仅设备密钥路径）。
int cprisk_set_session_token(const uint8_t *token, size_t token_len);

// 做什么：取出当前有效会话密钥（Layer3），供组合 effectiveRoot。
// 参数与所有权：out_key 由调用方提供 32 字节。
// 返回值：成功 0；无有效/未过期 token、时间异常或 NULL 时 -1。
// 线程安全：内部互斥；过期会在读取时自动清除并清零输出。
// 平台/架构：全平台。
// 失败语义：fail-closed。
int cprisk_get_session_key(uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]);

// 做什么：判断是否存在有效且未过期的会话 token（顺带清理过期状态）。
// 参数与所有权：无参数。
// 返回值：1=有效；0=无/已过期/时间异常。
// 线程安全：内部互斥。
// 平台/架构：全平台。
// 失败语义：fail-open（0 仅表示不可用）。
int cprisk_has_session_token(void);

// 做什么：安全擦除已安装的会话 token 并清除有效期。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：内部互斥，可与读取并发。
// 平台/架构：全平台。
// 失败语义：无。
void cprisk_clear_session_token(void);

// ── 反 dump 内存保护 ────────────────────────────────────────────────

// 做什么：启动反 dump 主动防御线程：按间隔扫描 VM 区域中的 shared/RWX 映射、
//   检查注入框架（Frida/Cycript 等），命中后进入欺骗模式。
// 参数与所有权：interval_seconds 最小 1；0 使用默认 5；内部按 ±50% 抖动
//   生成 [min,max] 区间并夹到 [1,30]。
// 返回值：成功/已在运行 0；线程创建失败 -1。
// 线程安全：内部互斥；幂等，重复调用只刷新间隔。
// 平台/架构：Apple 平台完整实现；其他平台可能退化为空操作。
// 失败语义：fail-open；探测失败只记录，不阻断。
int cprisk_start_anti_dump_probe(int interval_seconds);

// 做什么：请求反 dump 线程停止并 join（等待 sleep 自然到期）。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：内部互斥；可从未启动状态调用；不得在探测线程自身调用。
// 平台/架构：全平台。
// 失败语义：fail-open。
void cprisk_stop_anti_dump_probe(void);

// ── 运行时完整性复查 ────────────────────────────────────────────────

// 做什么：重算 __TEXT.__text 哈希并与初始化保存值比对，同时校验 PAC/MTE；
//   被调试时改为激活欺骗模式并返回 0（不暴露本地 oracle）。
// 参数与所有权：无参数。
// 返回值：0=完整（或已进入欺骗）；1=篡改/投毒；-1=无保存基线；-2=计算错误。
// 线程安全：读写全局完整性状态，建议由 watchdog/evaluate 串行调用。
// 平台/架构：全平台；模拟器跳过调试器欺骗分支。
// 失败语义：fail-closed（1/-2 会投毒；-1 表示初始化缺失）。
int cprisk_recheck_integrity(void);

// 做什么：报告完整性复查是否已判定篡改。
// 参数与所有权：无参数。
// 返回值：1=已投毒；0=未投毒或欺骗模式（故意隐藏 oracle）。
// 线程安全：普通读取，弱一致。
// 平台/架构：全平台。
// 失败语义：0 不保证干净；欺骗模式下会刻意返回 0。
int cprisk_is_integrity_poisoned(void);

// 做什么：两个通用完整性投毒入口。最终效果相同（runtime material 被污染），
//   但记账、lane 专属 XOR 窗口与 epoch/cause-mix 不同；诱饵 material 会再
//   与该状态做 XOR 混合。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：写全局投毒状态，可并发调用（状态竞态可接受）。
// 平台/架构：全平台。
// 失败语义：fail-closed（调用即表示上层已判定篡改）。
// 说明：evt_a/evt_b 仅为兼容保留；新调用点应优先用下面按域划分的 lane。
// cprisk_integrity_poison_evt_a：通用 lane A 投毒。
void cprisk_integrity_poison_evt_a(void);
// 做什么：通用 lane B 投毒；最终效果与 evt_a 相同，但记账/cause-mix 不同。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：写全局投毒状态，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed（调用即表示上层已判定篡改）。
void cprisk_integrity_poison_evt_b(void);

// 做什么：中间签名层：在未达到完整投毒时，按弱命中/分级命中/跟踪/DBI 等
//   等级对 buf 做原地 XOR 混合（尾部 8 / 中部 16 / 全 32 字节）。
//   只影响签名派生，不改变 cprisk_get_runtime_material()。
// 参数与所有权：buf 由调用方提供 32 字节，函数原地修改；所有权不变。
// 返回值：无。
// 线程安全：读全局分级状态并原地写 buf；buf 的并发访问由调用方负责。
// 平台/架构：全平台。
// 失败语义：fail-open（不阻塞签名，只降低可复现性）。
void cprisk_signing_runtime_material_intermediate_mix(uint8_t buf[32]);

// 做什么：返回最近一次签名中间混合指纹（高 4 位=等级 1–7，低 28 位=确定性
//   噪声）。该值与签名一起上报服务端，不作为本地通过/失败 oracle。
// 参数与所有权：无参数。
// 返回值：0=未混合；非 0 编码见上。
// 线程安全：原子读取。
// 平台/架构：全平台。
// 失败语义：无。
uint32_t cprisk_get_signing_mix_fingerprint(void);

// 做什么：构造折入 white-box 域 6–9 PRF 输入的压力位图（与被动绑定位一起使用）。
// 参数与所有权：无参数。
// 返回值：bit0=分级 watchdog 命中；bit1=分级 anti-dump；bit2=被动 trace|DBI；
//   bit3=VM mprotect Mach↔POSIX 不一致；bit4=vm_protect trap 不一致；
//   bit5=mprotect tamper 已锁存；bit6=被动时序异常；
//   bit7=TTY/Developer Disk/libc 回退；bit8=watchdog 慢投毒波。
// 线程安全：读取多个原子计数器，弱一致。
// 平台/架构：全平台。
// 失败语义：无；位缺失只代表未观测到。
uint32_t cprisk_integrity_wb_prf_pressure_mask(void);
// 做什么：watchdog 域投毒（分级）；连续命中可升级为完整投毒。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：写全局投毒状态，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed（调用即视为已判定该类篡改）。
void cprisk_integrity_poison_watchdog_lane(void);
// 做什么：watchdog 域立即完整投毒，并重置分级计数（高置信信号专用）。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：写全局投毒状态，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed（调用即视为已判定该类篡改）。
void cprisk_integrity_poison_watchdog_lane_now(void);
// 做什么：高置信投毒，目标 lane 按 path_tag 轮换，降低单一 lane 响应指纹。
// 参数与所有权：path_tag 由调用方提供，仅参与目标 lane 选择/混合，不落盘。
// 返回值：无。
// 线程安全：写全局投毒状态，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed（调用即视为已判定该类篡改）。
void cprisk_integrity_poison_high_signal_mixed(uint32_t path_tag);
// 做什么：代码签名/Team ID/身份校验域的投毒 lane。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：写全局投毒状态，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed（调用即视为已判定该类篡改）。
void cprisk_integrity_poison_code_signing_lane(void);
// 做什么：PAC/SVC/签名间接调用接口失败域的投毒 lane。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：写全局投毒状态，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed（调用即视为已判定该类篡改）。
void cprisk_integrity_poison_svc_iface_lane(void);
// 做什么：反调试计划、跟踪交叉校验与策略升级域的投毒 lane。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：写全局投毒状态，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed（调用即视为已判定该类篡改）。
void cprisk_integrity_poison_antidebug_lane(void);
// 做什么：异常端口指纹漂移/劫持竞态域的投毒 lane。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：写全局投毒状态，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed（调用即视为已判定该类篡改）。
void cprisk_integrity_poison_exception_lane(void);
// 做什么：反 dump VM 扫描/dylib 注入/task_for_pid 域的投毒 lane。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：写全局投毒状态，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed（调用即视为已判定该类篡改）。
void cprisk_integrity_poison_anti_dump_lane(void);
// 做什么：反 dump 域立即完整投毒，并重置分级计数（明确的注入类信号）。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：写全局投毒状态，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed（调用即视为已判定该类篡改）。
void cprisk_integrity_poison_anti_dump_lane_now(void);
// 做什么：数据段加载器/JIT 解密保护失败域的投毒 lane。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：写全局投毒状态，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed（调用即视为已判定该类篡改）。
void cprisk_integrity_poison_data_loader_lane(void);
// 做什么：text 段页加密/重加密/投毒状态迁移域的投毒 lane。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：写全局投毒状态，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed（调用即视为已判定该类篡改）。
void cprisk_integrity_poison_text_encrypt_lane(void);
// 做什么：white-box PRF 求值/校验失败域的投毒 lane。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：写全局投毒状态，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed（调用即视为已判定该类篡改）。
void cprisk_integrity_poison_whitebox_lane(void);
// 做什么：控制流平坦化默认投毒路径的投毒 lane。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：写全局投毒状态，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed（调用即视为已判定该类篡改）。
void cprisk_integrity_poison_cff_lane(void);

// 做什么：返回投毒 lane 的 XOR 折叠记账指纹（诊断/未来策略用）。
// 参数与所有权：无参数。
// 返回值：指纹；欺骗模式激活时恒 0（与 cprisk_is_integrity_poisoned 一致）。
// 线程安全：普通读取。
// 平台/架构：全平台。
// 失败语义：0 不保证未投毒（欺骗模式会隐藏）。
uint32_t cprisk_get_integrity_poison_semantic_breadcrumb(void);

// 投毒 lane 编号（cprisk_get_integrity_poison_lane_event_count 的入参）。
// 置位者：对应域的投毒函数；读取者：诊断/遥测。编号是 ABI 契约，禁止重排。
enum {
// 0：通用 evt_a lane。
    CPRISK_POISON_LANE_EVT_A = 0,
// 1：通用 evt_b lane。
    CPRISK_POISON_LANE_EVT_B = 1,
// 2：聚合强制投毒 lane。
    CPRISK_POISON_LANE_FORCE = 2,
// 3：guard page / 内存陷阱 lane。
    CPRISK_POISON_LANE_GUARD = 3,
// 4：内部完整性复查失败（PAC/MTE/hash），区别于 evt_a/evt_b 调用点。
    CPRISK_POISON_LANE_RECHECK = 4,
// 5：反调试看门狗及相关 C 层强制路径。
    CPRISK_POISON_LANE_WATCHDOG = 5,
// 6：应用签名/Team ID/身份校验（Swift 或策略驱动）。
    CPRISK_POISON_LANE_CODE_SIGNING = 6,
// 7：PAC/SVC/签名间接调用接口失败。
    CPRISK_POISON_LANE_SVC_IFACE = 7,
// 8：反调试计划、跟踪交叉校验、运行期 gate 与策略升级。
    CPRISK_POISON_LANE_ANTIDEBUG = 8,
// 9：异常端口指纹漂移/劫持竞态，区别于通用反调试探针。
    CPRISK_POISON_LANE_EXCEPTION = 9,
// 10：反 dump VM 扫描/dylib 注入/task_for_pid 升级探针。
    CPRISK_POISON_LANE_ANTI_DUMP = 10,
// 11：数据段加载器与 JIT 解密保护路径失败。
    CPRISK_POISON_LANE_DATA_LOADER = 11,
// 12：text 段页加密/重加密/投毒状态迁移。
    CPRISK_POISON_LANE_TEXT_ENCRYPT = 12,
// 13：white-box PRF 求值/校验失败。
    CPRISK_POISON_LANE_WHITEBOX = 13,
// 14：控制流平坦化默认投毒路径。
    CPRISK_POISON_LANE_CFF = 14,
// lane 总数（15）；入参 lane >= 该值返回 0。
    CPRISK_POISON_LANE_COUNT = 15,
};

// 做什么：返回指定 lane 的累计事件数。
// 参数与所有权：lane 取 CPRISK_POISON_LANE_*；越界返回 0。
// 返回值：事件计数；欺骗模式激活时恒 0（避免本地 oracle）。
// 线程安全：普通读取，弱一致。
// 平台/架构：全平台。
// 失败语义：0 不保证无事件。
uint32_t cprisk_get_integrity_poison_lane_event_count(unsigned lane);

// 做什么：返回单调投毒波次计数器（每次投毒副作用批加 1）。
// 参数与所有权：无参数。
// 返回值：波次计数；欺骗模式激活时恒 0。
// 线程安全：普通读取。
// 平台/架构：全平台。
// 失败语义：0 不保证未投毒。
uint32_t cprisk_get_integrity_poison_epoch(void);

// 做什么：返回 watchdog 慢投毒阶段：0=空闲；1=已完成一个阈值（仅渐进混合，
//   尚未完整投毒）。完整提交或 lane_now 会重置为 0。
// 参数与所有权：无参数。
// 返回值：0/1；欺骗模式激活时恒 0。
// 线程安全：原子读取。
// 平台/架构：全平台。
// 失败语义：0 不保证无分级命中。
uint32_t cprisk_get_integrity_watchdog_slow_poison_phase(void);

// 做什么：返回“哪些 lane 按什么顺序触发”的折叠指纹。
// 参数与所有权：无参数。
// 返回值：64 位 cause mix；欺骗模式激活时恒 0。
// 线程安全：普通读取。
// 平台/架构：全平台。
// 失败语义：0 不保证未投毒。
uint64_t cprisk_get_integrity_poison_cause_mix(void);

// 做什么：一次性应用 EVT_A + EVT_B + FORCE 三条 lane 记账的聚合投毒。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：写全局状态，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed。
// 说明：新调用点优先用域专属 lane，避免所有语义汇聚到单一可观测符号。
void cprisk_force_integrity_poison(void);

// 做什么：guard page（PROT_NONE 蜜罐）被访问时调用：进入欺骗、完整性投毒，
//   并置 watchdog 的 GUARD_PAGE 异常位。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：可并发调用（原子/竞态容忍）。
// 平台/架构：全平台。
// 失败语义：fail-closed（调用即视为攻击行为）。
void cprisk_guard_page_fault_notify(void);

// 做什么：报告是否存在安全关键 mprotect 调用失败（内核拦截或 syscall hook），
//   由连续完全失败达到阈值后锁存。
// 参数与所有权：无参数。
// 返回值：1=已锁存篡改；0=未锁存。
// 线程安全：普通读取（非原子），弱一致。
// 平台/架构：全平台；直调路径仅 arm64。
// 失败语义：0 不保证未被 hook，仅表示未达阈值。
int cprisk_is_mprotect_tampered(void);

// 做什么：返回直调 mprotect 累计失败次数。
// 参数与所有权：无参数。
// 返回值：uint32 计数（可能回绕）。
// 线程安全：普通读取。
// 平台/架构：全平台。
// 失败语义：无；计数高但回退成功时未必构成风险。
uint32_t cprisk_get_mprotect_direct_failure_count(void);

// 做什么：返回直调失败后 libc mprotect 回退成功的次数。
// 参数与所有权：无参数。
// 返回值：uint32 计数。
// 线程安全：普通读取。
// 平台/架构：全平台。
// 失败语义：无。
uint32_t cprisk_get_mprotect_fallback_success_count(void);

// 做什么：返回当前“直调与回退都失败（或无回退）”的连续次数。
// 参数与所有权：无参数。
// 返回值：连续失败 streak；达到阈值即锁存 tampered。
// 线程安全：普通读取。
// 平台/架构：全平台。
// 失败语义：无。
uint32_t cprisk_get_mprotect_consecutive_full_fail_streak(void);

// 做什么：返回当前生效的连续失败阈值（受测试覆盖影响）。
// 参数与所有权：无参数。
// 返回值：阈值，默认 CPRISK_MPROTECT_FULL_FAIL_STREAK_THRESHOLD。
// 线程安全：普通读取。
// 平台/架构：全平台。
// 失败语义：无。
uint32_t cprisk_get_mprotect_fail_streak_threshold(void);

// 做什么：测试专用：不真正调用 syscall，强制直调路径报告失败。
// 参数与所有权：enabled 非 0 开启。
// 返回值：无。
// 线程安全：普通全局写；仅测试单线程使用。
// 平台/架构：全平台。
// 失败语义：非 DEBUG 构建为空操作。
void cprisk_test_mprotect_set_force_direct_fail(int enabled);

// 做什么：测试专用：不真正调用 libc，强制回退路径报告失败。
// 参数与所有权：enabled 非 0 开启。
// 返回值：无。
// 线程安全：普通全局写；仅测试单线程使用。
// 平台/架构：全平台。
// 失败语义：非 DEBUG 构建为空操作。
void cprisk_test_mprotect_set_force_fallback_fail(int enabled);

// 做什么：测试专用：覆盖连续失败阈值（0 恢复编译默认）。
// 参数与所有权：threshold 为新的连续失败阈值。
// 返回值：无。
// 线程安全：普通全局写；仅测试单线程使用。
// 平台/架构：全平台。
// 失败语义：非 DEBUG 构建为空操作。
void cprisk_test_mprotect_set_fail_streak_threshold(uint32_t threshold);

// 做什么：测试专用：重置 tamper 标志、计数、streak、阈值覆盖与注入开关。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：仅测试单线程使用。
// 平台/架构：全平台。
// 失败语义：非 DEBUG 构建为空操作。
void cprisk_test_mprotect_reset_tamper_state(void);

// ── 按段链式密钥派生 ────────────────────────────────────────────────

// 做什么：报告是否启用了按段链式密钥（v3 loader 条目已处理）。
// 参数与所有权：无参数。
// 返回值：1=链式密钥生效；0=legacy v2 全局 loader key。
// 线程安全：普通读取。
// 平台/架构：全平台。
// 失败语义：无。
int cprisk_get_chain_status(void);

// 做什么：返回 cprisk_init_protection() 的墙钟耗时（纳秒）。
// 参数与所有权：无参数。
// 返回值：耗时；0=尚未初始化或已清理。
// 线程安全：普通读取。
// 平台/架构：全平台。
// 失败语义：无。
uint64_t cprisk_get_init_elapsed_ns(void);

// 做什么：返回当前可疑初始化阈值（纳秒），已按设备档位与加固模式调整。
// 参数与所有权：无参数。
// 返回值：阈值（测试覆盖优先）。
// 线程安全：普通读取；内部可能触发 sysctl。
// 平台/架构：设备档位来自 hw.machine；模拟器使用默认档。
// 失败语义：fail-open（查询失败回落默认阈值）。
uint64_t cprisk_get_init_timing_threshold_ns(void);

// 做什么：判断初始化是否异常耗时（DBI/Stalker 会让执行慢 10–100 倍）。
// 参数与所有权：无参数。
// 返回值：1=超过阈值（可疑）；0=正常。
// 线程安全：普通读取。
// 平台/架构：全平台；阈值按设备档位而非固定 5 秒。
// 失败语义：fail-open。
int cprisk_check_init_timing(void);

// 做什么：测试专用：覆盖初始化时序阈值（0=关闭覆盖，回到实时计算）。
// 参数与所有权：threshold_ns 为纳秒。
// 返回值：无。
// 线程安全：普通全局写；仅测试使用。
// 平台/架构：全平台。
// 失败语义：非 DEBUG 构建为空操作。
void cprisk_test_set_init_timing_threshold_ns_override(uint64_t threshold_ns);

// 做什么：测试专用：清空分级投毒计数与完整性投毒标志（不拆除 runtime material）。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：仅测试单线程使用。
// 平台/架构：全平台。
// 失败语义：非 DEBUG 构建为空操作。
void cprisk_test_reset_staged_poison_for_tests(void);

// 做什么：测试专用：用合成 hw.machine 字符串计算阈值（不触发 sysctl）。
// 参数与所有权：machine 可为 NULL（按默认档）；mode 取加固模式。
// 返回值：计算出的阈值（纳秒）；非 DEBUG 构建返回 0。
// 线程安全：纯计算，可并发调用。
// 平台/架构：全平台。
// 失败语义：非 DEBUG 构建为空操作。
uint64_t cprisk_test_init_timing_threshold_ns_for_machine(
    const char *machine,
    cprisk_runtime_hardening_mode_t mode
);

// 做什么：测试专用：cprisk_secure_zero 的薄包装。
// 参数与所有权：buf/len 同 cprisk_secure_zero。
// 返回值：无。
// 线程安全：可并发调用（操作调用方缓冲区）。
// 平台/架构：全平台。
// 失败语义：非 DEBUG 构建为空操作。
void cprisk_test_secure_zero(void *buf, size_t len);

// 做什么：测试专用：注入 white-box 测试包，使 probe/available/evaluate 路径
//   无需镜像内保留段即可走真实校验器。
// 参数与所有权：meta/code/data/tag 均为调用方缓冲区；成功时函数复制全部内容
//   并在 clear 前持有副本；失败不接管。
// 返回值：成功 0；参数非法或分配失败 -1。
// 线程安全：写全局测试包状态；仅测试单线程使用。
// 平台/架构：全平台。
// 失败语义：非 DEBUG 构建为空操作（返回 -1）。
int cprisk_test_set_whitebox_bundle(
    const uint8_t *meta,
    size_t meta_len,
    const uint8_t *code,
    size_t code_len,
    const uint8_t *data,
    size_t data_len,
    const uint8_t *tag,
    size_t tag_len
);

// 做什么：测试专用：清除注入的 white-box 包，恢复正常从当前镜像读取。
// 参数与所有权：无参数；内部释放副本并擦除。
// 返回值：无。
// 线程安全：仅测试单线程使用。
// 平台/架构：全平台。
// 失败语义：非 DEBUG 构建为空操作。
void cprisk_test_clear_whitebox_bundle(void);

// 做什么：测试专用：强制 white-box 重算不匹配，验证投毒/fail-closed 行为。
// 参数与所有权：enabled 非 0 开启。
// 返回值：无。
// 线程安全：全局标志写；仅测试使用。
// 平台/架构：全平台。
// 失败语义：非 DEBUG 构建为空操作。
void cprisk_test_set_whitebox_recompute_mismatch(int enabled);

// 做什么：测试专用：镜像域 6–9 的 PRF 输入准备逻辑（混合 KDF 已运行时
//   做 SHA256 绑定，否则 identity）；域 1–5 直接复制输入。
// 参数与所有权：input 32 字节；out 必须非 NULL（32 字节）。
// 返回值：成功 0；out 为 NULL 或非 DEBUG 构建时 -1。
// 线程安全：读全局 KDF 状态，可并发调用。
// 平台/架构：全平台。
// 失败语义：非 DEBUG 构建为惰性桩（返回 -1）。
int cprisk_test_whitebox_prepare_domain_input(
    uint32_t domain_id,
    const uint8_t input[32],
    uint8_t out[32]
);

// 做什么：测试专用：注入反调试计划字节，供解析器/策略校验使用。
// 参数与所有权：plan/plan_len 由调用方提供；成功时函数复制并持有，直到 clear。
// 返回值：成功 0；参数非法或分配失败 -1。
// 线程安全：仅测试单线程使用。
// 平台/架构：全平台。
// 失败语义：非 DEBUG 构建为空操作（-1）。
int cprisk_test_set_antidebug_plan(
    const uint8_t *plan,
    size_t plan_len
);

// 做什么：测试专用：清除注入的反调试计划并释放副本。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：仅测试单线程使用。
// 平台/架构：全平台。
// 失败语义：非 DEBUG 构建为空操作。
void cprisk_test_clear_antidebug_plan(void);

// ── 镜像地址检查（不依赖 dladdr） ────────────────────────────────────

// 做什么：判断 addr 是否落在任一已加载镜像的任一 segment 内。
//   使用 task_info + dyld_all_image_infos 自行解析 Mach-O，不调用 dladdr/_dyld_*，
//   以免 dladdr hook 隐藏匿名内存（如 Frida Stalker JIT）。
// 参数与所有权：addr 可为 NULL/任意值（仅做数值比较）。
// 返回值：1=在镜像内；0=不在或查询失败。
// 线程安全：只读 dyld 结构，可并发调用。
// 平台/架构：依赖 Mach-O 64 位布局；非 Apple 构建不可用。
// 失败语义：fail-open（查询失败按“不在镜像内”处理）。
int cprisk_addr_in_any_image(const void *addr);

// 做什么：同 cprisk_addr_in_any_image，但只匹配可执行映射
//   （initprot/maxprot 含 VM_PROT_EXECUTE，或段名为 __TEXT）。
// 参数与所有权：addr 可为任意值。
// 返回值：1=落在可执行镜像段；0=其他/查询失败。
// 线程安全：只读 dyld 结构，可并发调用。
// 平台/架构：依赖 Mach-O 64 位布局。
// 失败语义：fail-open。
int cprisk_addr_in_any_image_executable(const void *addr);

// 做什么：对 dyld 镜像列表做 SHA-256（v2：镜像数、路径、加载基址、__TEXT
//   运行期边界），供服务端证明/与匿名可执行启发式做差。
// 参数与所有权：out_digest 由调用方提供 32 字节。
// 返回值：成功 0；NULL、task_info 失败、镜像数异常（0 或 >4096）-1。
// 线程安全：只读 dyld 结构，可并发调用。
// 平台/架构：依赖 dyld_all_image_infos。
// 失败语义：fail-closed（-1 表示无法生成可信摘要）。
int cprisk_vm_dyld_image_layout_digest(uint8_t out_digest[32]);

// 做什么：把当前 dyld 布局摘要保存为基线，供差分检测使用。
// 参数与所有权：无参数。
// 返回值：无；内部摘要失败时静默不更新。
// 线程安全：原子有效标志 + 32 字节复制；建议单线程设置。
// 平台/架构：全平台（无 dyld 信息时为空操作）。
// 失败语义：fail-open。
void cprisk_vm_dyld_image_layout_digest_baseline_snapshot(void);

// 做什么：比较当前 dyld 布局摘要与基线。
// 参数与所有权：无参数。
// 返回值：1=不同；0=相同；-1=计算失败。首次调用（无基线）会写入基线并返回 0。
// 线程安全：原子有效标志；建议单线程使用。
// 平台/架构：全平台。
// 失败语义：fail-open（-1 不视为篡改）。
int cprisk_vm_dyld_image_layout_digest_differs_from_baseline(void);

// 做什么：对包含 addr 的整个 R/X 页（页对齐）做 SHA-256，PIC/重定位安全。
// 参数与所有权：addr/out_digest 均不可为 NULL；输出 32 字节由调用方提供。
// 返回值：无；参数为 NULL 时静默返回。
// 线程安全：只读内存，可并发调用。
// 平台/架构：全平台；页大小取 sysconf，异常时回落 4096。
// 失败语义：无；失败不写输出（调用方应预先清零）。
void cprisk_sha256_text_page(const void *addr, uint8_t out_digest[32]);

// 做什么：计算当前生效 deny-attach 入口（RX 重定位 stub 或模板）的整页 SHA-256。
// 参数与所有权：out_digest 由调用方提供 32 字节；NULL 时静默返回。
// 返回值：无。
// 线程安全：只读 stub 页，可并发调用。
// 平台/架构：仅 Apple arm64 有真实 digest；其他平台输出全 0。
// 失败语义：无。
void cprisk_deny_attach_stub_page_sha256_digest(uint8_t out_digest[32]);

// 做什么：比较 deny-attach stub 整页 SHA-256 与启动基线。
// 参数与所有权：无参数。
// 返回值：bit5（1u<<5）置位=不匹配；0=匹配/平台不支持。
// 线程安全：只读，可并发调用。
// 平台/架构：仅 Apple arm64。
// 失败语义：fail-closed（bit5 表示直调 stub 可能被替换）。
uint32_t cprisk_deny_attach_stub_sha256_page_mask(void);

// ── Frida / Gum 运行时线索（dyld 镜像路径、dlsym、进程表） ──────────

// Frida/Gum 运行时命中类别（cprisk_frida_runtime_snapshot.flags）。
// 置位者：快照函数；读取者：Swift 判决层。每轮重新计算。
enum {
// bit0：dyld 镜像路径命中 Frida/Gum 特征。
    CPRISK_FRIDA_RT_IMAGE = 1u << 0,
// bit1：dlsym 命中可疑导出/符号。
    CPRISK_FRIDA_RT_DLSYM = 1u << 1,
// bit2：进程表 comm 命中 Frida 类进程名。
    CPRISK_FRIDA_RT_PROC = 1u << 2,
// bit3：行为层命中（序言漂移/可疑 trampoline/外来可执行 hook 面）。
    CPRISK_FRIDA_RT_BEHAVIOR = 1u << 3,
};

// 行为层细分位（snapshot.behavior_flags，仅当 flags 含 BEHAVIOR 时有效）。
enum {
// bit0：受监控符号序言与基线不一致。
    CPRISK_FRIDA_RT_BEHAVIOR_PROLOGUE = 1u << 0,
// bit1：入口匹配 b/br/ldr+br/adrp+add+br 等 trampoline 形状。
    CPRISK_FRIDA_RT_BEHAVIOR_TRAMPOLINE = 1u << 1,
// bit2：dlsym/dlopen/objc_msgSend 地址落在镜像外可执行区。
    CPRISK_FRIDA_RT_BEHAVIOR_FOREIGN_EXEC = 1u << 2,
// bit3：Security trust 面或 dlsym/dlopen 校验失败。
    CPRISK_FRIDA_RT_BEHAVIOR_TRUST_SURFACE = 1u << 3,
};

// Frida/Gum 运行时探测快照（cprisk_frida_runtime_snapshot 输出）。
// 按值复制，调用方拥有；模拟器 supported=0 且其余字段为 0。
typedef struct cprisk_frida_runtime_snapshot {
// 1=当前平台执行了真实探测；0=模拟器/stub。
    uint32_t supported;
// CPRISK_FRIDA_RT_* 命中位。
    uint32_t flags;
// dyld 镜像路径命中数。
    uint32_t image_hit_count;
// dlsym 命中数。
    uint32_t dlsym_hit_count;
// 进程表命中数。
    uint32_t proc_hit_count;
// 行为层细分位（CPRISK_FRIDA_RT_BEHAVIOR_*），仅当 flags 含 BEHAVIOR 时有效。
    uint32_t behavior_flags;
// 行为层命中计数（可能为各探针命中数之和）。
    uint32_t behavior_hit_count;
} cprisk_frida_runtime_snapshot_t;

// 做什么：填充 Frida/Gum 运行时线索：镜像路径、dlsym、进程表与行为层扫描。
// 参数与所有权：out 必须非 NULL，由调用方提供并整体覆盖。
// 返回值：成功 0；out 为 NULL 时 -1。模拟器 supported=0 但仍返回 0。
// 线程安全：只读快照 + 原子 last_ok，可并发调用。
// 平台/架构：仅 Apple 真机执行真实扫描；模拟器为空。
// 失败语义：fail-open（0 不代表绝对干净）。
int cprisk_frida_runtime_snapshot(cprisk_frida_runtime_snapshot_t *out);
// 编译期哨兵：表示该快照 API 已声明，供 Swift/C 条件编译探测。
#define CPRISK_FRIDA_RUNTIME_SNAPSHOT_DECLARED 1

// 做什么：扫描函数入口前缀，识别 Frida/Gum 常见跳板：入口 b、br x16、
//   ldr x16,literal; br x16、adrp/add; br x16。
// 参数与所有权：func_ptr 必须非 NULL；prefix_bytes 至少 8（建议 12 以覆盖
//   adrp/add 序列）；只读调用方内存。
// 返回值：1=命中；0=未命中/参数非法。
// 线程安全：只读，可并发调用。
// 平台/架构：仅 Apple arm64 实现；其他平台恒 0。
// 失败语义：fail-open。
int cprisk_scan_arm64_suspicious_trampoline_prefix(const void *func_ptr, size_t prefix_bytes);

// 做什么：对 dlsym/dlopen/objc_msgSend/dyld 入口/pthread_create/sysctl/
//   mprotect/mach_msg/异常端口等高价值 hook 面做入口 trampoline 扫描。
// 参数与所有权：无参数。
// 返回值：命中的可疑符号数（0=未发现）。
// 线程安全：只读符号入口，可并发调用。
// 平台/架构：仅 Apple arm64；其他平台恒 0。
// 失败语义：fail-open。
int cprisk_scan_hook_surface_trampoline_prefixes(void);

// 做什么：v1 混淆字符串解码：以 SHA256(label) 为循环 XOR 掩码解出短明文；
//   敏感关键字因此不以连续 ASCII 形式出现在二进制中。
// 参数与所有权：label/label_len 由调用方提供；enc/enc_len 为密文；
//   out/out_sz 由调用方提供，成功时写入 NUL 结尾明文。
// 返回值：成功 0；参数非法、容量不足或解码失败 -1。
// 线程安全：纯计算，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed（-1 时 out 不应被使用）。
int cprisk_obf_decode_sha256_label(
    const char *label,
    size_t label_len,
    const uint8_t *enc,
    size_t enc_len,
    char *out,
    size_t out_sz
);

// 做什么：v2 混淆字符串解码：mask = SHA256(le32(domain) || le32(key_id))，
//   二进制中不出现可搜索的 ASCII label 常量。
// 参数与所有权：domain/key_id 由调用方给出；enc/enc_len 为密文；
//   out/out_sz 由调用方提供。
// 返回值：成功 0；参数非法/容量不足/解码失败 -1。
// 线程安全：纯计算，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed。
int cprisk_obf_decode_sha256_tag(
    uint32_t domain,
    uint32_t key_id,
    const uint8_t *enc,
    size_t enc_len,
    char *out,
    size_t out_sz
);

// v2 混淆域名常量：用于 cprisk_obf_decode_sha256_tag()，固定为 0xC0A119xx 段。
// FRIDA_RT=0xC0A11901、WD_DYLD=0xC0A11902、ANTI_DUMP=0xC0A11903、
// SIGNAL_DBI=0xC0A11904，分别对应 Frida 运行时、watchdog dyld、反 dump、
// 被动 DBI 信号四类混淆字符串。改动会导致已构建密文无法解码（二进制契约）。
#define CPRISK_OBF_TAG_DOMAIN_FRIDA_RT 0xC0A11901u
#define CPRISK_OBF_TAG_DOMAIN_WD_DYLD 0xC0A11902u
#define CPRISK_OBF_TAG_DOMAIN_ANTI_DUMP 0xC0A11903u
#define CPRISK_OBF_TAG_DOMAIN_SIGNAL_DBI 0xC0A11904u

// 做什么：返回 armor mprotect 后 Mach VM 交叉校验的不一致累计数。
// 参数与所有权：无参数。
// 返回值：累计计数。
// 线程安全：普通读取。
// 平台/架构：仅 Apple 执行交叉校验；其他平台恒 0。
// 失败语义：无；非 0 表示 POSIX 与 Mach 视图分歧。
uint32_t cprisk_get_vm_mprotect_crosscheck_mismatch_count(void);
// 做什么：返回“mprotect 返回成功但 vm_protect 失败”的累计数。
// 参数与所有权：无参数。
// 返回值：累计计数。
// 线程安全：普通读取。
// 平台/架构：仅 Apple。
// 失败语义：无；非 0 提示存在 hook 面。
uint32_t cprisk_get_vm_mprotect_mach_trap_mismatch_count(void);

// 做什么：对关键 svc #0x80 直调模板做快照 + 周期校验（syscall6、
//   deny-attach、syscall0），并叠加整页 SHA-256 辅助校验。
// 参数与所有权：无参数。
// 返回值：位掩码：bit0=syscall6 失败、bit1=deny-attach 失败、bit2=syscall0
//   失败；bit3..5=对应 stub 的页 SHA-256 不匹配。0=全部通过。
// 线程安全：内部原子 tick + 只读快照，可并发调用。
// 平台/架构：仅 arm64 Apple 有真实校验；其他平台返回 0。
// 失败语义：fail-closed（任一位表示直调路径可能被篡改）。
uint32_t cprisk_verify_svc_stub_integrity(void);

// 做什么：常量时间比较一个 SHA-256 摘要与打包 pinset（每个 pin 32 字节）。
// 参数与所有权：candidate_digest/candidate_len 由调用方提供（长度必须 32）；
//   packed_pins 为 pin_count*32 字节只读缓冲。
// 返回值（调用方依赖的契约）：
//   -1 = 参数错误（NULL digest、长度不对、pin_count>0 但 packed_pins 为 NULL）；
//    0 = 无 pin 匹配，包括 pin_count==0 的“未配置 pin”；
//    1 = 至少一个 pin 匹配。
// 线程安全：纯计算，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed 于参数错误；0 绝不能当作“匹配”。
int cprisk_pinset_contains_sha256_digest(
    const uint8_t *candidate_digest,
    size_t candidate_len,
    const uint8_t *packed_pins,
    size_t pin_count
);

// 做什么：从 SecCertificateRef 计算 SPKI SHA-256（先按密钥类型/长度补
//   ASN.1 SPKI 头，再哈希），与 openssl 工具链结果对齐。
// 参数与所有权：sec_certificate_ref 由调用方持有（不转移）；out_digest 32 字节。
// 返回值：成功 0；-1 NULL、-2 取不到公钥、-3 外部表示失败、
//   -4 不支持的密钥布局（非 Apple 构建恒 -4）。
// 线程安全：使用 CoreFoundation/Security 只读 API，可并发调用。
// 平台/架构：仅 Apple；支持 RSA2048/4096、P-256/P-384。
// 失败语义：fail-closed（负值表示无法建立 pin 基准）。
int cprisk_spki_sha256_from_sec_certificate(void *sec_certificate_ref, uint8_t out_digest[32]);

// 做什么：分层 pin 匹配：摘要匹配之外还要求 scope 与链位置一致。
// 参数与所有权：candidate_digest 长度必须 32；packed_pins 为 pin_count*32；
//   scopes 为每个 pin 一字节：0=任意位置、1=叶证书(chain_index==0)、
//   2=中间证书(chain_index>=1)。
// 返回值（issue 39 契约）：-1=参数错误；0=无匹配（含 pin_count==0）；
//   1=至少一个 pin 在摘要与 scope 上同时匹配。
// 线程安全：纯计算，可并发调用。
// 平台/架构：非 Apple 构建恒 -1。
// 失败语义：fail-closed 于参数错误；0 绝不是“匹配”。
int cprisk_pinset_match_layered_sha256_digest(
    const uint8_t *candidate_digest,
    size_t candidate_len,
    const uint8_t *packed_pins,
    size_t pin_count,
    const uint8_t *scopes,
    uint32_t chain_index
);

// 做什么：扫描 [fn, fn+len) 是否含有 A64 svc 指令（Darwin syscall ABI）。
// 参数与所有权：fn 由调用方提供（len<4 或 NULL 返回 0）。
// 返回值：1=含 svc；0=不含/参数非法。非 arm64 Apple 构建恒返回 1（不做判断）。
// 线程安全：只读内存。
// 平台/架构：仅 Apple arm64 实际扫描。
// 失败语义：fail-open。
int cprisk_stub_contains_svc_opcode(const void *fn, size_t len);

// 做什么：对 16 字节 stub 文本做 FNV-1a(64)，并把 stub_fn_addr 所在 4 KiB
//   页基址折入结果，用于发现“代码被换成另一页同内容”的情况。
// 参数与所有权：chunk16 必须非 NULL（恰好 16 字节）；stub_fn_addr 用于取页基址。
// 返回值：64 位 FNV 值；chunk16 为 NULL 时 0。
// 线程安全：纯计算，可并发调用。
// 平台/架构：全平台。
// 失败语义：无。
// 安全边界：FNV 只用于发现意外改动，不是抗碰撞、非密钥化，不能证明未被
//   定向篡改；真正的篡改证据来自 cprisk_verify_svc_stub_integrity 的 SHA-256 页掩码。
uint64_t cprisk_svc_stub_chunk_hash_fnv16(const uint8_t *chunk16, uintptr_t stub_fn_addr);

// ── 双路径 syscall 交叉校验 ──────────────────────────────────────────

// syscall 双路径分歧位（cprisk_syscall_crosscheck_probe 返回）。
// 置位者：该探针；读取者：判决层。每轮重新计算。
enum {
// bit0：直调 getpid 与 libc getpid 不一致。
    CPRISK_CROSSCHECK_DIVERGE_PID    = 1u << 0,
// bit1：getuid 不一致。
    CPRISK_CROSSCHECK_DIVERGE_UID    = 1u << 1,
// bit2：getppid 不一致。
    CPRISK_CROSSCHECK_DIVERGE_PPID   = 1u << 2,
// bit3：stat("/") 的 st_dev/st_ino 不一致。
    CPRISK_CROSSCHECK_DIVERGE_STAT   = 1u << 3,
// bit4：access("/",F_OK) 返回值不一致。
    CPRISK_CROSSCHECK_DIVERGE_ACCESS = 1u << 4,
};

// 做什么：对 getpid/getuid/getppid/stat/access 同时走直调与 libc，比较结果，
//   识别 libc 层 hook 插桩。
// 参数与所有权：无参数。
// 返回值：CPRISK_CROSSCHECK_DIVERGE_* 位组合；0=一致。
// 线程安全：可并发调用。
// 平台/架构：模拟器/非 arm64 返回 0（无法交叉校验）。
// 失败语义：fail-open；非 0 仅表示可疑。
uint32_t cprisk_syscall_crosscheck_probe(void);

// ── errno 合理性校验 ────────────────────────────────────────────────

// errno 异常位（cprisk_syscall_errno_probe 返回）；每轮重新计算。
enum {
// bit0：sysctl 返回 EINTR/ERESTART（不应发生）。
    CPRISK_ERRNO_PROBE_SYSCTL_EINTR       = 1u << 0,
// bit1：stat("/") 返回 EINTR。
    CPRISK_ERRNO_PROBE_STAT_EINTR         = 1u << 1,
// bit2：access("/",F_OK) 失败。
    CPRISK_ERRNO_PROBE_ACCESS_ROOT_FAIL   = 1u << 2,
// bit3：直调 getpid 返回 <=0。
    CPRISK_ERRNO_PROBE_PID_INVALID        = 1u << 3,
};

// 做什么：检查直调 syscall 的返回值/errno 是否合理，识别伪造返回值或 hook。
// 参数与所有权：无参数。
// 返回值：CPRISK_ERRNO_PROBE_* 位组合；0=未发现异常。
// 线程安全：可并发调用。
// 平台/架构：模拟器/非 arm64 返回 0。
// 失败语义：fail-open。
uint32_t cprisk_syscall_errno_probe(void);

// ── 蜜罐 syscall 行为探针 ────────────────────────────────────────────

// 蜜罐行为异常位（cprisk_honeypot_syscall_probe 返回）；每轮重新计算。
enum {
// bit0：随机不存在的路径被 access 判定为存在。
    CPRISK_HONEYPOT_PHANTOM_ACCESS_EXISTS   = 1u << 0,
// bit1：随机不存在的路径被 stat 判定为存在。
    CPRISK_HONEYPOT_PHANTOM_STAT_EXISTS     = 1u << 1,
// bit2：access("/") 直调失败但 libc 成功。
    CPRISK_HONEYPOT_ROOT_SVC_LIBC_DIVERGE_A = 1u << 2,
// bit3：access("/") 直调成功但 libc 失败。
    CPRISK_HONEYPOT_ROOT_SVC_LIBC_DIVERGE_B = 1u << 3,
};

// 做什么：用随机不存在的 /tmp 路径做存在性蜜罐，并把 "/" 的直调与 libc
//   结果做交叉校验。
// 参数与所有权：无参数。
// 返回值：CPRISK_HONEYPOT_* 位组合；0=正常。随机源不可用时直接返回 0。
// 线程安全：可并发调用（内部无共享状态）。
// 平台/架构：模拟器/非 arm64 返回 0。
// 失败语义：fail-open。
uint32_t cprisk_honeypot_syscall_probe(void);

// ── 信号探针位图 ────────────────────────────────────────────────────

// 综合信号探针位（cprisk_run_all_signal_probes 返回；也用于 watchdog 内部）。
// 置位者：对应探针；读取者：判决层。每轮重新计算，非累计。
enum {
// bit0：BRK #0xC0DE 的 SIGTRAP 被调试器截获。
    CPRISK_PROBE_SIGNAL_TRAP       = 1u << 0,
// bit1：存在使能的硬件断点/观察点。
    CPRISK_PROBE_HARDWARE_BP       = 1u << 1,
// bit2：代码区扫描到外来 BRK。
    CPRISK_PROBE_SOFTWARE_BP       = 1u << 2,
// bit3：stdout 指向 /dev/ttys* 或 /dev/pts*。
    CPRISK_PROBE_TTY               = 1u << 3,
// bit4：CS_DEBUGGED 置位。
    CPRISK_PROBE_CSOPS             = 1u << 4,
// bit5：时序探测异常（含 DBI 减速）。
    CPRISK_PROBE_SINGLE_STEP       = 1u << 5,
// bit6：PC 落在镜像外的线程。
    CPRISK_PROBE_SUSPICIOUS_THREAD = 1u << 6,
// bit7：Developer Disk 工具路径可访问。
    CPRISK_PROBE_DEVELOPER_DISK    = 1u << 7,
// bit8：异常投递超时或回退为信号投递。
    CPRISK_PROBE_EXCEPTION_DELIVERY_TIMEOUT = 1u << 8,
// bit9：DBI 标记命中。
    CPRISK_PROBE_DBI_MARKER        = 1u << 9,
// bit10：时序异常位非 0。
    CPRISK_PROBE_TIMING_ANOMALY    = 1u << 10,
// bit11：线程级异常端口与任务级不一致。
    CPRISK_PROBE_THREAD_EXCEPTION_PORT = 1u << 11,
// bit12：快/慢跟踪路径结论不一致。
    CPRISK_PROBE_TRACE_CROSSCHECK  = 1u << 12,
// bit13：关键符号入口被改成 mov x0,x0; ret / nop; ret 等立即返回。
    CPRISK_PROBE_INSTANT_RETURN_PATCH = 1u << 13,
};

// 保留 BRK 立即数（A64 brk #imm16）。这些值由本 SDK 的异常/信号处理器识别，
// 必须与处理器端一致；改动会导致探针异常被当作外来断点或被系统终止。
enum {
// 0xC0DE：SIGTRAP 调试器探测。
    CPRISK_BRK_IMM_SIGNAL_PROBE = 0xC0DEu,
// 0xC0DF：异常投递延迟探测。
    CPRISK_BRK_IMM_EXCEPTION_DELIVERY_PROBE = 0xC0DFu,
// 0xC0E0：运行期 gate（完整性/策略检查）。
    CPRISK_BRK_IMM_RUNTIME_GATE = 0xC0E0u,
};

// DBI 标记位（cprisk_detect_dbi_markers / snapshot.last_dbi_marker_flags）。
// 置位者：DBI 探测；读取者：判决层。每轮重新计算。
enum {
// bit0：环境变量命中 DBI/QBDI 关键字。
    CPRISK_DBI_MARKER_ENV = 1u << 0,
// bit1：已加载镜像路径命中 DBI 特征。
    CPRISK_DBI_MARKER_IMAGE = 1u << 1,
// bit2：线程/端口名命中 DBI 特征。
    CPRISK_DBI_MARKER_THREAD = 1u << 2,
// bit3：全 environ 子串扫描命中 DBI/QBDI（补充具名键检查）。
    CPRISK_DBI_MARKER_ENVIRON_SCAN = 1u << 3,
// bit4：存在可写+可执行代码区（DBI/JIT cache 典型特征）。
    CPRISK_DBI_MARKER_EXEC_WRITE = 1u << 4,
// bit5：不属于任何 Mach-O 的私有匿名 RX 映射（Stalker/Gum slab）。
    CPRISK_DBI_MARKER_ANON_EXEC_SLAB = 1u << 5,
// bit6：可疑线程 PC 与匿名 RX slab/RWX JIT 面交叉关联命中。
    CPRISK_DBI_MARKER_STALKER_CORREL = 1u << 6,
// bit7：已加载 dyld 镜像数少于预期（进程被裁剪/异常）。
    CPRISK_DBI_MARKER_DYLD_IMAGE_COUNT_LOW = 1u << 7,
// bit8：非匿名 RX 区中的采样 PC 落在所有 dyld 镜像段之外。
    CPRISK_DBI_MARKER_FOREIGN_MAPPED_EXEC = 1u << 8,
};

// 时序异常位（cprisk_get_last_timing_anomaly_flags / crypto trace）。
// 置位者：单步/时序探针与 crypto trace；读取者：判决层。每轮重新计算。
enum {
// bit0：中位数超过阈值（整体变慢）。
    CPRISK_TIMING_ANOMALY_MEDIAN = 1u << 0,
// bit1：单次采样尖峰超过阈值。
    CPRISK_TIMING_ANOMALY_SPIKE = 1u << 1,
// bit2：抖动异常（方差过大）。
    CPRISK_TIMING_ANOMALY_JITTER = 1u << 2,
// bit3：时钟读数异常/回退。
    CPRISK_TIMING_ANOMALY_CLOCK_SKEW = 1u << 3,
// bit4：CNTPCT_EL0 与 mach_absolute_time 对同一负载的增量不一致（DBI/时间虚拟化）。
    CPRISK_TIMING_ANOMALY_DUAL_CLOCK_DRIFT = 1u << 4,
// bit5：内部 SHA-256/CPRisk-MAC 哨兵明显变慢（Stalker/QBDI trace 放大）。
    CPRISK_TIMING_ANOMALY_CRYPTO_TRACE = 1u << 5,
// bit6：crypto trace 中 CNTPCT 与 Mach 时钟出现偏斜。
    CPRISK_TIMING_ANOMALY_CRYPTO_TRACE_SKEW = 1u << 6,
// bit7：确定性 crypto trace 工作负载摘要不匹配。
    CPRISK_TIMING_ANOMALY_CRYPTO_TRACE_INVARIANT = 1u << 7,
};

// 做什么：安装临时 SIGTRAP handler，执行 BRK #0xC0DE；若调试器先截获 Mach
//   异常，信号 handler 不会触发。
// 参数与所有权：无参数；临时 sigaction 在返回前恢复。
// 返回值：1=信号被调试器截获（可疑）；0=未截获或平台不支持。
// 线程安全：使用静态 sigjmp 状态，禁止多线程并发调用。
// 平台/架构：仅 arm64 iOS 真机有 BRK 语义；其他平台 0。
// 失败语义：fail-open。
int cprisk_probe_debugger_via_signal(void);

// 做什么：枚举 Mach 线程，读取 ARM_DEBUG_STATE64 的 BCR/WCR 使能位，统计
//   已使能的硬件断点/观察点槽。
// 参数与所有权：无参数；线程端口在内部 deallocate。
// 返回值：命中的槽数（0=正常）。
// 线程安全：只读内核线程状态，可并发调用。
// 平台/架构：仅 arm64 Apple；模拟器/其他平台 0。
// 失败语义：fail-open。
int cprisk_detect_hardware_breakpoints(void);

// 做什么：检查每个线程的 EXC_BREAKPOINT/EXC_BAD_ACCESS 端口是否与任务级
//   处理器不同，识别调试器按线程劫持。
// 参数与所有权：无参数。
// 返回值：端口不匹配的线程数；0=正常。
// 线程安全：可并发调用。
// 平台/架构：仅 Apple Mach；其他平台 0。
// 失败语义：fail-open。
int cprisk_detect_thread_exception_ports(void);

// 做什么：扫描指定内存区间的 A64 BRK 指令，排除本 SDK 保留的三个立即数。
// 参数与所有权：func_ptr/size 由调用方提供（size<4 或 NULL 返回 0）；只读。
// 返回值：外来 BRK 数量。
// 线程安全：只读，可并发调用。
// 平台/架构：仅 Apple arm64；其他平台 0。
// 失败语义：fail-open。
int cprisk_scan_software_breakpoints(const void *func_ptr, size_t size);

// 做什么：扫描函数前 prefix_bytes（最小 8）的两条指令，识别
//   mov x0,x0; ret / nop; ret / mov w0,w0; ret 之类立即返回补丁。
// 参数与所有权：func_ptr 非 NULL；prefix_bytes>=8；只读。
// 返回值：1=命中；0=未命中/参数非法。
// 线程安全：只读。
// 平台/架构：仅 Apple arm64；其他平台 0。
// 失败语义：fail-open。
int cprisk_scan_arm64_instant_return_nop_patch_prefix(const void *func_ptr, size_t prefix_bytes);

// 做什么：对与看门狗相同的关键符号（deny_attach、信号探针、异常处理器
//   辅助函数）做入口立即返回补丁扫描。
// 参数与所有权：无参数。
// 返回值：命中的符号数。
// 线程安全：只读代码，可并发调用。
// 平台/架构：仅 Apple arm64。
// 失败语义：fail-open。
int cprisk_scan_instant_return_key_symbols_prefix(void);

// 做什么：在 __TEXT 中随机采样若干窗口扫描软件 BRK，降低固定扫描模式被规避。
// 参数与所有权：sample_windows=0 用默认窗口数，window_size<16 用默认大小。
// 返回值：外来 BRK 数量；找不到本镜像头时 0。
// 线程安全：可并发调用。
// 平台/架构：仅 Apple arm64。
// 失败语义：fail-open。
int cprisk_scan_software_breakpoints_randomized_text(
    size_t sample_windows,
    size_t window_size
);

// 做什么：触发 BRK #0xC0DF，测量 Mach 异常投递延迟；超时或回退为信号投递
//   视为可疑。
// 参数与所有权：无参数；临时 sigaction 在返回前恢复。
// 返回值：1=超时/异常；0=正常。
// 线程安全：使用静态 sigjmp 状态，禁止并发调用。
// 平台/架构：仅 arm64 iOS 真机；其他平台 0。
// 失败语义：fail-open。
int cprisk_probe_exception_delivery_timeout(void);

// 做什么：判断 stdout 是否为 /dev/ttys* 或 /dev/pts* 调试终端。
// 参数与所有权：无参数。
// 返回值：1=是调试 TTY；0=否/查询失败。
// 线程安全：可并发调用（临时路径缓冲在栈上）。
// 平台/架构：全平台（依赖 F_GETPATH）。
// 失败语义：fail-open。
int cprisk_detect_tty_debug(void);

// 做什么：通过直调 csops 读取 CS_OPS_STATUS 并检查 CS_DEBUGGED。
// 参数与所有权：无参数。
// 返回值：1=标记为已调试；0=否/调用失败/平台不支持。
// 线程安全：可并发调用。
// 平台/架构：仅 arm64 Apple 有直调 csops；其他平台 0。
// 失败语义：fail-open。
int cprisk_csops_debug_check(void);

// 做什么：读取完整 CS_OPS_STATUS 标志。
// 参数与所有权：flags_out 可为 NULL；error_out 可为 NULL；均在调用开始时清零。
// 返回值：成功 0 并写 *flags_out；失败 -1（不支持的构建写 ENOTSUP）。
// 线程安全：可并发调用。
// 平台/架构：仅 arm64 Apple 有直调；其他平台 -1/ENOTSUP。
// 失败语义：fail-closed 于读取（-1 时标志不可信）。
int cprisk_csops_status_flags(uint32_t *flags_out, int *error_out);

// deny_attach 事后一致性校验位（cprisk_deny_attach_effective_verify 的
// detail_bits_out）。置位者：该校验；读取者：watchdog/判决层。每轮重新计算。
enum {
// bit0：两次读取的 p_flag 不一致。
    CPRISK_DENY_ATTACH_VERIFY_FLAG_MISMATCH = 1u << 0,
// bit1：返回的 PID 不是自身。
    CPRISK_DENY_ATTACH_VERIFY_SELF_PID_MISMATCH = 1u << 1,
// bit2：直调与 libc/shadow 读取结果分歧。
    CPRISK_DENY_ATTACH_VERIFY_LIBC_DIRECT_DIVERGENCE = 1u << 2,
// bit3：两次读取的 PID 不一致。
    CPRISK_DENY_ATTACH_VERIFY_PID_MISMATCH = 1u << 3,
// bit4：返回长度与 struct 大小不符。
    CPRISK_DENY_ATTACH_VERIFY_SIZE_MISMATCH = 1u << 4,
// bit5：P_TRACED 仍置位。
    CPRISK_DENY_ATTACH_VERIFY_TRACE_FLAG_SET = 1u << 5,
};

// 做什么：deny_attach 返回成功后再读三次 sysctl proc 状态，校验 PID/标志/
//   长度/直调与 libc 一致性及 P_TRACED 是否清除，识别“假成功”hook。
// 参数与所有权：deny_attach_rc/errno 为先前调用结果；detail_bits_out 可为 NULL。
// 返回值：非 0=可疑（detail 位见上）；0=一致或平台不支持。
// 线程安全：可并发调用；使用栈上 kinfo_proc。
// 平台/架构：仅 arm64 iOS 真机；其他平台恒 0。
// 失败语义：fail-open（0 不代表绝对安全）。
int cprisk_deny_attach_effective_verify(int deny_attach_rc, int deny_attach_errno, uint32_t *detail_bits_out);

// 做什么：聚合 AMFI/entitlement 探针：读取 csops 标志并检查
//   CS_VALID/CS_HARD/CS_KILL/CS_DEBUGGED 组合，再用 task_for_pid(self)
//   探测 get-task-allow 类能力。
// 参数与所有权：三个输出指针均可为 NULL；非 NULL 时先清零再写入。
// 返回值：无（结果通过输出参数返回）。
// 线程安全：可并发调用；内核查询无共享状态。
// 平台/架构：仅 arm64 iOS 真机做真实探测；其他平台输出全 0。
// 失败语义：fail-open（查询失败时输出 0，不误报）。
void cprisk_amfi_entitlement_watchdog_probe(
    uint32_t *cs_flags_out,
    uint32_t *get_task_allow_suspect_out,
    uint32_t *amfi_anomaly_bits_out
);

// 做什么：对约 100 条算术指令做时序校准/探测，判断是否被单步或 DBI 放大。
// 参数与所有权：无参数。
// 返回值：1=时序异常；0=正常。
// 线程安全：使用全局校准状态（原子），可并发调用。
// 平台/架构：Apple 平台有时钟源；其他平台 0。
// 失败语义：fail-open。
int cprisk_detect_single_stepping(void);

// 做什么：枚举 Mach 线程并统计 PC 落在已知镜像之外的线程数。
// 参数与所有权：无参数。
// 返回值：可疑线程数；0=正常/枚举失败。
// 线程安全：只读内核线程状态。
// 平台/架构：仅 Apple；其他平台 0。
// 失败语义：fail-open。
int cprisk_detect_suspicious_threads(void);

// 做什么：枚举 Mach 线程，导出每个线程的 PC 与“是否落在可执行镜像内”的判定。
// 参数与所有权：out_entries 由调用方提供，容量 max_entries；max_entries>0 时
//   不可为 NULL；out_snapshot 必须非 NULL 并整体覆盖。
// 返回值：成功 0；参数非法或 task_threads 失败 -1。
// 线程安全：只读线程状态，可并发调用。
// 平台/架构：仅 Apple；模拟器返回全 0 快照且成功。
// 失败语义：fail-open（-1 时调用方应视为“未知”）。
int cprisk_thread_pc_exec_snapshot(
    cprisk_thread_pc_exec_entry_t *out_entries,
    uint32_t max_entries,
    cprisk_thread_pc_exec_snapshot_t *out_snapshot
);

// 做什么：检测 Developer Disk Image 相关路径（debugserver、
//   libMainThreadChecker）是否可访问；路径常量 XOR 混淆。
// 参数与所有权：无参数。
// 返回值：1=可访问；0=不可访问/平台不支持。
// 线程安全：可并发调用（栈上明文缓冲，用后擦除）。
// 平台/架构：仅 Apple；其他平台 0。
// 失败语义：fail-open。
int cprisk_detect_developer_disk(void);

// 做什么：检测 DBI 足迹（Pin/DynamoRIO/Valgrind/QBDI）：环境变量、镜像、
//   线程、全 environ 子串扫描、可写可执行区、匿名 RX slab 与低镜像数。
// 参数与所有权：无参数。
// 返回值：命中的标记数；同时把类别位写入内部 last 快照。
// 线程安全：内部原子快照；可并发调用。
// 平台/架构：仅 Apple 真机有完整探测；模拟器 0。
// 失败语义：fail-open。
int cprisk_detect_dbi_markers(void);

// 做什么：判断是否存在不属于任何已加载镜像的私有匿名可执行（RX）区域。
// 参数与所有权：无参数。
// 返回值：1=存在；0=不存在/不支持。
// 线程安全：可并发调用。
// 平台/架构：仅 Apple 真机；模拟器/stub 恒 0。
// 失败语义：fail-open。
int cprisk_vm_probe_anonymous_exec_outside_images(void);

// 做什么：返回最近一次 DBI 探测的类别位。
// 参数与所有权：无参数。
// 返回值：CPRISK_DBI_MARKER_* 位组合；0=未命中/尚未探测。
// 线程安全：原子读取。
// 平台/架构：全平台（stub 恒 0）。
// 失败语义：0 不保证干净。
uint32_t cprisk_get_last_dbi_marker_flags(void);

// 做什么：返回最近一次 DBI 探测的命中计数。
// 参数与所有权：无参数。
// 返回值：命中数；0=未命中/尚未探测。
// 线程安全：原子读取。
// 平台/架构：全平台（stub 恒 0）。
// 失败语义：0 不保证干净。
int cprisk_get_last_dbi_marker_hit_count(void);

// 做什么：返回最近一次时序异常位，并合并 crypto trace 的慢/时钟偏斜/
//   不变量失败位。
// 参数与所有权：无参数。
// 返回值：CPRISK_TIMING_ANOMALY_* 位组合；0=正常/尚未探测。
// 线程安全：原子读取。
// 平台/架构：全平台（stub 仅返回 crypto trace 位）。
// 失败语义：0 不保证干净。
uint32_t cprisk_get_last_timing_anomaly_flags(void);

// 做什么：返回最近一次时序探测的中位数（纳秒）。
// 参数与所有权：无参数。
// 返回值：中位数；0=尚未探测。
// 线程安全：原子读取。
// 平台/架构：全平台（stub 恒 0）。
// 失败语义：无。
uint64_t cprisk_get_last_timing_probe_median_ns(void);
// 做什么：返回最近一次时序探测的最大值（纳秒）。
// 参数与所有权：无参数。
// 返回值：最大值；0=尚未探测。
// 线程安全：原子读取。
// 平台/架构：全平台（stub 恒 0）。
// 失败语义：无。
uint64_t cprisk_get_last_timing_probe_max_ns(void);
// 做什么：返回最近一次时序探测的判定阈值（纳秒）。
// 参数与所有权：无参数。
// 返回值：阈值；0=尚未探测。
// 线程安全：原子读取。
// 平台/架构：全平台（stub 恒 0）。
// 失败语义：无。
uint64_t cprisk_get_last_timing_probe_threshold_ns(void);

// 做什么：依次运行 SIGTRAP、线程异常端口、硬件断点、软件断点、TTY、
//   单步时序、DBI、可疑线程、Developer Disk 等探针并汇总位图。
// 参数与所有权：无参数。
// 返回值：CPRISK_PROBE_* 位组合；0=未发现异常。
// 线程安全：内部静态 sigjmp/校准状态，禁止多线程并发调用本函数。
// 平台/架构：仅 Apple 真机完整执行；其他平台只做入口补丁扫描或返回 0。
// 失败语义：fail-open。
uint32_t cprisk_run_all_signal_probes(void);

// 做什么：报告 CNTPCT_EL0 硬件单调时钟路径是否可用（读取 CNTFRQ_EL0 != 0）。
// 参数与所有权：无参数。
// 返回值：1=可用；0=不可用/非 arm64。
// 线程安全：只读系统寄存器。
// 平台/架构：仅 arm64 Apple。
// 失败语义：0 时调用方应回落 mach_absolute_time。
int cprisk_is_cntpct_clock_available(void);

// 做什么：由 32 字节根密钥派生 GF(2) 矩阵种子：
//   seed = SHA256("cprisk.gf2.seed.v1" || root_key) 的前 8 字节（LE）。
//   已初始化（pthread_once 先到者胜）时该调用不改变矩阵。
// 参数与所有权：root_key 必须非 NULL（32 字节），只读；NULL 时直接返回。
// 返回值：无。
// 线程安全：种子槽位由互斥锁保护；可并发调用，但只有首次初始化生效。
// 平台/架构：全平台。
// 失败语义：fail-open（晚到调用被忽略）；默认公开种子只提供混淆，不是密钥。
void cprisk_gf2_init_with_root_key(const uint8_t root_key[32]);
// 做什么：在 GF(2) 上对 128-bit 输入做仿射变换：
//   output[i] = XOR_j(matrix[i][j] & input[j]) ^ translation[i]。
//   默认矩阵/平移由种子经 xorshift64 生成，二进制 .rodata 中不含矩阵字节。
// 参数与所有权：output/input 各 16 字节，可为同一缓冲区（内部先拷到栈）；
//   matrix 可选 2048 字节（128 行 × 16 字节），NULL=SDK 默认；
//   translation 可选 16 字节，NULL=SDK 默认；均只读，不接管。
// 返回值：无；output 或 input 为 NULL 时静默返回。
// 线程安全：首次调用经 pthread_once 初始化默认矩阵；之后只读，可并发调用。
// 平台/架构：全平台（ARM64 上 parity 编译为 popcount，无循环）。
// 失败语义：无失败路径；矩阵被篡改由 cprisk_gf2_affine_self_check 发现。
void cprisk_gf2_affine_transform_16(
    uint8_t output[16],
    const uint8_t input[16],
    const uint8_t *matrix,
    const uint8_t *translation
);

// 做什么：对运行时矩阵 + 平移做 FNV-1a 并与初始化时记录值比对。
// 参数与所有权：无参数。
// 返回值：0=一致；非 0=矩阵/平移被篡改。
// 线程安全：只读矩阵 + pthread_once 初始化，可并发调用。
// 平台/架构：全平台。
// 失败语义：fail-closed（非 0 表示变换结果不可信）。
int cprisk_gf2_affine_self_check(void);

// 做什么：用 pending 种子（或公开常量种子）经 xorshift64 生成 2048 字节矩阵
//   与 16 字节平移，并记录 FNV-1a 校验值；同时冻结种子槽位。
// 内部符号：公开可见仅为让 armor CFF/VMP 策略能定位该符号并保护种子立即数；
//   加 -fvisibility=hidden 后需该符号在 Mach-O 符号表中，否则策略条目静默失效。
// 参数与所有权：无参数。
// 返回值：无。
// 线程安全：pthread_once 保证只执行一次；内部互斥保护种子读取。
// 平台/架构：全平台；首次调用约几十微秒，之后无开销。
// 失败语义：无；矩阵生成是纯确定性计算。
void cprisk_gf2_init_real(void);

// 做什么：对 2048 字节矩阵 + 16 字节平移做链式 FNV-1a，得到完整性校验值。
// 内部符号：公开可见原因同上——FNV basis/prime 作为立即数出现，VMP partial
//   会经 VPC 走这些立即数，从而增加常量搜索恢复矩阵的难度。
// 参数与所有权：无参数。
// 返回值：64 位 FNV-1a 校验值。
// 线程安全：只读 BSS 矩阵，可并发调用。
// 平台/架构：全平台。
// 失败语义：无。
uint64_t cprisk_gf2_compute_full_checksum(void);

#ifdef __cplusplus
}
#endif

#endif /* CRiskCore_h */
