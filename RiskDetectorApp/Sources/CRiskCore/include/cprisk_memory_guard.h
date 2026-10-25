// 文件职责：解密完成后的反 dump 内存加固原语（降权、guard 页、复检、恢复、信号接线）。
// 在链路中的位置：文本/数据 section 解密回填后调用保护，重新加密前短暂恢复；由卸载/退出路径撤销。
// 线程模型：同一 cprisk_guard_state 的安装/移除必须由 owner 串行化；不同 state 各有锁保护。
// 平台限制：依赖 Darwin Mach VM（vm_protect/vm_region_64/vm_allocate）与 POSIX 信号；非 Apple 平台多数函数不可用。
// 失败语义：一律 fail-closed——保护/复检失败按“仍可写/不可信”处理；无探测能力不得当作安全。
/*
 * cprisk_memory_guard.h — Anti-dump memory protection primitives.
 *
 * After decryption completes, these routines harden memory pages to prevent
 * runtime tampering and make memory-dump attacks more difficult:
 *   1. cprisk_protect_decrypted_pages() — strips VM_PROT_WRITE from decrypted regions
 *   2. cprisk_install_memory_trap()     — plants guard (honeypot) pages around regions
 *   3. cprisk_register_text_honeypot_page() — optional __TEXT tail PROT_NONE trap (see cprisk_text_tail_honeypot.c)
 *   4. cprisk_unprotect_pages()         — restores VM_PROT_WRITE (for re-encryption)
 *   5. cprisk_remove_memory_trap()      — deallocates guard pages
 *
 * All functions tolerate NULL/0-size inputs. Calls that mutate the same
 * cprisk_guard_state must be serialized by the owner of that state.
 */

#ifndef CPRISK_MEMORY_GUARD_H
#define CPRISK_MEMORY_GUARD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 每个 guard state 最多登记 16 个 trap：一个区域前后各一页，足够覆盖多段敏感数据；
// 上限固定便于结构体内联数组，避免动态分配。
#define CPRISK_GUARD_MAX_TRAPS 16

// 一个已种下的 guard 页描述；addr/size 由本模块分配与释放，调用方只读。
struct cprisk_guard_trap {
    // guard 页起始地址（VM_PROT_NONE），由 vm_allocate 分配。
    void  *addr;
    // guard 页大小（字节），通常等于系统页大小。
    size_t size;
};

// 一次加固会话的状态。owner 负责串行化所有变更；结构体可放在栈上，但撤销前必须保持有效。
struct cprisk_guard_state {
    // 已种下的 guard 页表。
    struct cprisk_guard_trap traps[CPRISK_GUARD_MAX_TRAPS];
    // 有效 trap 数量（0..CPRISK_GUARD_MAX_TRAPS）。
    uint32_t trap_count;
    // 1 = 至少种下一页且保护生效；0 = 未保护。
    int      pages_protected;
    // 1 = 曾有 guard 页保护失败；供诊断，不自动重试。
    int      protect_failed;
    uint8_t  poison_mode_enabled;  /* fatal fault handlers installed; notification is best effort */
};

/// 将解密区域整页降为只读（VM_PROT_READ），阻断解密后的写入注入。
/// - Parameters:
///   - region: 区域起始地址；允许未对齐，按页向外扩张；NULL 返回 -1。
///   - len: 字节数；0 返回 -1。
/// - Returns: 0 = 全范围降权成功；-1 = 参数非法、地址溢出或 vm_protect 失败。
/// - Thread safety: 只操作 VM，可与其他区域并发；不得与同区域 unprotect 并发。
/// - Platform: Darwin Mach VM；不使用 MADV_FREE，保证页内容不被回收。
/// - 失败语义: 返回 -1 时明文可能仍可写，调用方必须视为风险（fail-closed）。
int  cprisk_protect_decrypted_pages(void *region, size_t len);

/// 恢复区域可读可写，仅供重新加密/重写数据段的受控窗口使用。
/// - Parameters:
///   - region: 区域起始地址；NULL 返回 -1。
///   - len: 字节数；0 返回 -1。
/// - Returns: 0 = 成功；-1 = 参数非法或 vm_protect 失败。
/// - Thread safety: 与同区域 protect/verify 互斥由调用方保证。
/// - Platform: Darwin Mach VM。
/// - 失败语义: -1 表示仍有页不可写；不得在未恢复的情况下原地加密写回。
int  cprisk_unprotect_pages(void *region, size_t len);

/// 复检区域是否“可读且不可写”。
/// - Parameters:
///   - region: 区域起始地址；NULL 返回 0。
///   - len: 字节数；0 返回 0。
/// - Returns: 1 = 所有页段都含 READ 且不含 WRITE；0 = 参数非法、空洞、查询失败或权限不符。
/// - Thread safety: 只读查询，可并发；但结果可能被并发的 protect/unprotect 改变。
/// - Platform: Darwin Mach VM；按 vm_region_64 逐段遍历，避免只看首个区段。
/// - 失败语义: 0 一律视为“未通过”，调用方不得把 0 当安全。
int  cprisk_verify_page_protection(void *region, size_t len);

/// 在区域前后各种一页 VM_PROT_NONE guard 页，并把地址登记到 state。
/// - Parameters:
///   - region: 受保护区域；NULL 返回 -1。
///   - len: 字节数；0 返回 -1。
///   - state: 调用方持有的 guard 状态；NULL 返回 -1，所有权仍归调用方。
/// - Returns: 实际种下的 guard 页数（0..2）；-1 表示参数/页大小非法。
/// - Thread safety: 内部用互斥锁保护信号发布；同一 state 的并发安装仍应由 owner 串行化。
/// - Platform: VM_FLAGS_FIXED 复用相邻地址；相邻页已映射时分配失败属正常，返回 0。
/// - 失败语义: 返回 0 表示一页都没种下（不应显示为“已保护”）；处理器安装失败会清 poison 标志但保留 guard 页。
int  cprisk_install_memory_trap(void *region, size_t len,
                                struct cprisk_guard_state *state);

/// 撤销 guard：先摘除信号通知引用，再释放 guard 页，最后整体清零 state。
/// - Parameters:
///   - state: 之前传给 install 的状态；允许 NULL（无操作）。
/// - Returns: 无。
/// - Thread safety: 与 install/信号处理器并发安全；但同一 state 的调用需 owner 串行。
/// - Platform: Darwin Mach VM。
/// - 失败语义: 无错误返回；未安装或重复调用是安全的空操作。
void cprisk_remove_memory_trap(struct cprisk_guard_state *state);

/* Register a single page inside __TEXT (must be page-aligned) for SIGBUS/SIGSEGV honeypot.
 * Returns 0 on success, -1 if signal handlers could not be installed (caller should restore prot). */
/// 把 __TEXT 内的一页登记为蜜罐区间，命中故障时由信号处理器分类。
/// - Parameters:
///   - page: 页对齐地址；NULL/未对齐/长度为 0 会被拒绝。
///   - len: 区间字节数，应为页大小整数倍。
/// - Returns: 0 = 登记成功；-1 = 参数非法或信号处理器无法安装。
/// - Thread safety: 全局单一蜜罐区间，内部互斥；后注册会覆盖先前区间。
/// - Platform: 仅 Darwin；需要可安装的 SIGBUS/SIGSEGV 处理器。
/// - 失败语义: -1 时调用方应恢复页保护并放弃蜜罐，不能假定已受保护。
int cprisk_register_text_honeypot_page(void *page, size_t len);

/// 撤销 __TEXT 蜜罐登记并释放处理器引用；未注册时安全。
/// - Returns: 无。
/// - Thread safety: 内部互斥，可与故障路径并发。
/// - 失败语义: 不恢复页保护，调用方需自行处理。
void cprisk_unregister_text_honeypot_page(void);

/* Drain a best-effort atomic guard-fault notification in normal context.
 * No-op when nothing is pending; must not be called from a signal handler.
 * Faults are fatal: notification delivery before termination is not guaranteed,
 * and previously installed crash handlers are not chained. */
/// 在正常上下文取走 guard 故障通知（best effort）。
/// - Returns: 无。
/// - Thread safety: 原子读写，可并发调用；每项通知只会被取走一次。
/// - 约束: 禁止在信号处理器内调用；故障本身是致命的，投递不保证在终止前完成。
/// - 失败语义: 无事可做时为空操作；不链式调用此前安装的崩溃处理器。
void cprisk_guard_fault_drain_pending(void);

/* Optional SIGBUS guard wiring for active anti-dump trapping.
 * install_memory_trap/remove_memory_trap already call these internally. */
/// 把 guard state 发布给故障分类并确保共享信号处理器已安装（幂等）。
/// - Parameters:
///   - state: 要发布的 guard 状态；NULL 返回 -1。
/// - Returns: 0 = 已发布/已安装；-1 = 参数非法或处理器安装失败。
/// - Thread safety: 内部互斥；可重复调用。
/// - Platform: Darwin 信号机制。
/// - 失败语义: -1 时 guard 页仍存在（访问仍会崩溃），但不会有分类/通知。
int  cprisk_install_sigbus_guard(struct cprisk_guard_state *state);

/// 撤销已发布的 guard state 并释放处理器引用。
/// - Parameters:
///   - state: 期望撤销的 state；传 NULL 表示无条件撤销；传入非当前 state 时静默忽略。
/// - Returns: 无。
/// - Thread safety: 内部互斥；归属校验防止误摘他人的保护。
/// - 失败语义: 未安装时为安全空操作。
void cprisk_remove_sigbus_guard(struct cprisk_guard_state *state);

/*
 * After POSIX mprotect succeeds, verify Mach VM readback + redundant vm_protect.
 * Returns 0 when consistent (or skipped), non-zero on mismatch.
 */
/// mprotect 之后的 Mach 侧复核，防止 BSD 视图与 VM 实际保护位不一致。
/// - Parameters:
///   - addr: 区域地址；NULL 或 len=0 时视为跳过并返回 0。
///   - len: 字节数。
///   - bsd_prot: 期望的 POSIX PROT_* 位组合。
/// - Returns: 0 = 一致或平台跳过；1 = 实际保护位与期望不符；2 = 复核通过但冗余 vm_protect 失败。
/// - Thread safety: 只查询/幂等设置 VM 保护，可并发但结果受并发改权限影响。
/// - Platform: 非 Apple 平台恒返回 0（跳过复核）。
/// - 失败语义: 非 0 表示保护可能未生效，调用方应视为加固失败。
int cprisk_vm_crosscheck_mprotect(void *addr, size_t len, int bsd_prot);

/*
 * Advance saved program counter in a signal ucontext (best effort).
 * Returns 0 on success, -1 when ucontext layout is unavailable.
 */
/// 在信号上下文中前移保存的 PC，用于跳过错点/陷阱指令。
/// - Parameters:
///   - uap: 指向 ucontext_t 的不透明指针；NULL 返回 -1。
///   - advance_bytes: 前进字节数；0 表示使用架构默认值（arm64=4，x86_64=1）。
/// - Returns: 0 = 已修改 PC；-1 = 空 ucontext、无机器上下文或架构不支持。
/// - Thread safety: 只能由处理该信号的线程在处理器内调用，不与其他线程共享 ucontext。
/// - Platform: arm64（含 opaque thread state）与 x86_64；其他架构返回 -1。
/// - 失败语义: 返回 -1 时 PC 未被保证修改，调用方不得继续执行被陷指令。
int cprisk_advance_ucontext_pc(void *uap, uintptr_t advance_bytes);

/*
 * Lightweight dyld / VM consistency tick:
 *   1. Dyld layout digest (v2: paths + bases + __TEXT bounds) vs baseline snapshot
 *   2. VM scan for executable mappings inconsistent with dyld image coverage / user_tag shape
 *      (device-only; anonymous RX from the direct-syscall SVC stub reloc page is allow-listed)
 * Returns bitmask (see CPRISK_MEM_GUARD_TICK_*). Safe to call from hardened loops (watchdog).
 */
// tick 位 0：dyld 镜像布局摘要与基线不同（新增/卸载/基址变化）。
#define CPRISK_MEM_GUARD_TICK_IMAGE_LIST_CHANGED 1u
// tick 位 1：发现不属于任何镜像的可执行 RX 映射（设备端扫描；SVC 跳板页已加入白名单）。
#define CPRISK_MEM_GUARD_TICK_UNKNOWN_EXECUTABLE_RX 2u
/** Writable+executable mapping in the same region (W^X / DBI-style surface). Device-only tick. */
// tick 位 2：同一区段同时可写可执行，W^X 被破坏（设备端；模拟器不扫描）。
#define CPRISK_MEM_GUARD_TICK_EXECUTABLE_WRITE 4u

/// 执行一次轻量 dyld/VM 一致性检查。
/// - Returns: CPRISK_MEM_GUARD_TICK_* 位掩码；0 表示本轮未发现问题（不构成安全证明）。
/// - Thread safety: 内部有跨 tick 游标，可能被并发调用交错；建议由看门狗单线程低频调用。
/// - Platform: 镜像摘要全平台可用；RX/W^X 扫描仅真机，模拟器对应位恒 0。
/// - 失败语义: 探测失败（task_info/vm_region 异常）不置位，避免把“看不到”误报为异常。
uint32_t cprisk_memory_guard_image_vm_tick(void);

#ifdef __cplusplus
}
#endif

#endif /* CPRISK_MEMORY_GUARD_H */
