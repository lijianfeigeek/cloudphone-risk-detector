/*
 * CRiskCore - Anti-dump memory protection.
 *
 * After data-segment decryption, this module:
 *   1. Strips VM_PROT_WRITE from decrypted pages (mach_vm_protect),
 *      preventing post-decryption injection.
 *   2. Optionally plants guard (honeypot) pages with VM_PROT_NONE around
 *      the protected region. Accesses typically raise SIGBUS or SIGSEGV; the
 *      handler terminates with the original signal. A normal-context monitor
 *      may drain a best-effort guard-fault notification before termination.
 */

// 文件职责：数据段解密后的内存加固原语（去写保护、蜜罐 guard 页、页保护复检）。
// 生命周期：解密 → protect_decrypted_pages() 置只读 → 运行期复检 → 需要重加密时
//   unprotect_pages() 恢复可写 → 再次保护；guard 页由 install/remove_memory_trap
//   成对管理，cprisk_guard_state 归调用方所有，同一 state 的变更须由调用方串行化。
// 线程模型/信号语义：模块级状态由 s_sigbus_guard_mutex 串行化；fatal 故障处理器
//   不链式调用旧处理器，通知只是 best effort，检测到 guard 访问即以原信号终止。
// 失败语义：保护与复检失败返回 -1/0（0=未通过），调用方必须 fail-closed 处理。

#include "include/cprisk_memory_guard.h"
#include "include/CRiskCore.h"

#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <mach/mach.h>
#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif
#if defined(__aarch64__)
#include <mach/arm/thread_status.h>
#endif
#if defined(__APPLE__)
#include <mach/vm_prot.h>
#endif

#if defined(__APPLE__)
extern void cprisk_svc_reloc_rx_page_whitelist_bounds(uintptr_t *out_lo, uintptr_t *out_hi);
#endif

// 串行化“故障处理器引用计数 + 已发布 guard state”的全部读改写；信号处理器自身不取锁。
static pthread_mutex_t s_sigbus_guard_mutex = PTHREAD_MUTEX_INITIALIZER;
// 安装时保存的旧信号处置。故意不链式转发：崩溃必须保持原信号的退出状态。
static struct sigaction s_prev_sigbus_action;
static struct sigaction s_prev_sigsegv_action;
// 1 表示 mem-trap 路径已发布 state；state 指针只在处理器已安装时非空。
static int s_sigbus_guard_installed = 0;
// 最近一次发布的 guard state，仅供正常上下文的通知分类使用（处理器不读）。
static struct cprisk_guard_state *s_sigbus_guard_state = NULL;

// 故障处理器是否已安装（mem-trap 与 text-honeypot 两个引用计数共享同一安装状态）。
static int s_fault_handlers_installed = 0;
/* Only a lock-free atomic mailbox is touched by the fatal signal handler.
 * A self-pipe introduces fd close/reuse races and can block when nonblocking
 * setup fails. This optional notification is best effort: termination never
 * waits for a monitoring thread to drain it. */
_Static_assert(ATOMIC_POINTER_LOCK_FREE == 2, "guard fault mailbox must be signal-safe");
// 单槽信箱：只保存最近一次故障地址，后到者覆盖；丢失通知可接受（进程即将终止）。
static _Atomic(void *) s_fault_pending_addr = NULL;
// 两个引用计数共同决定何时安装/卸载共享的 SIGBUS/SIGSEGV 处理器。
static uint32_t s_mem_trap_fault_ref = 0;
static uint32_t s_text_honeypot_fault_ref = 0;
// 已注册的 __TEXT 蜜罐区间 [lo, hi)；lo == 0 表示未注册。volatile 保证正常上下文
// 的轮询能观察到发布/撤销，写侧仍由 s_sigbus_guard_mutex 串行化。
static volatile uintptr_t s_text_honeypot_lo = 0;
static volatile uintptr_t s_text_honeypot_hi = 0;

// 取系统页大小；非 2 的幂或 sysconf 失败返回 0，调用方必须据此拒绝继续（fail-closed）。
static uintptr_t cprisk_guard_page_size_i(void) {
    const long size = sysconf(_SC_PAGESIZE);
    if (size <= 0 || ((uintptr_t)size & ((uintptr_t)size - 1u)) != 0u)
        return 0u;
    return (uintptr_t)size;
}

// 把 [ptr, ptr+len) 向外对齐到整页，返回页面起始地址与覆盖字节数。
// 只做地址运算、不验证映射存在；任何加法溢出或空区间都返回 -1，
// 避免把回绕后的地址交给 vm_protect 造成误保护。
static int page_span(void *ptr, size_t len,
                     vm_address_t *page_out, vm_size_t *span_out) {
    const uintptr_t size = cprisk_guard_page_size_i();
    if (!ptr || len == 0u || !page_out || !span_out || size == 0u)
        return -1;
    const uintptr_t base = (uintptr_t)ptr;
    const uintptr_t mask = size - 1u;
    if (len > UINTPTR_MAX - base)
        return -1;
    const uintptr_t raw_end = base + len;
    if (raw_end > UINTPTR_MAX - mask)
        return -1;
    const uintptr_t start = base & ~mask;
    const uintptr_t end = (raw_end + mask) & ~mask;
    if (end <= start)
        return -1;
    *page_out = (vm_address_t)start;
    *span_out = (vm_size_t)(end - start);
    return 0;
}

// 判断故障地址是否落在任一已种 guard 页内（供正常上下文的通知分类使用）。
// trap_count 先夹到上限，防止被篡改的 state 读出越界；跳过空/零长条目。
static int cprisk_sigbus_addr_in_guard(const struct cprisk_guard_state *state, const void *addr) {
    if (!state || !addr)
        return 0;

    uintptr_t target = (uintptr_t)addr;
    uint32_t limit = state->trap_count;
    if (limit > CPRISK_GUARD_MAX_TRAPS)
        limit = CPRISK_GUARD_MAX_TRAPS;

    for (uint32_t i = 0; i < limit; i++) {
        const void *trap_addr = state->traps[i].addr;
        size_t trap_size = state->traps[i].size;
        if (!trap_addr || trap_size == 0)
            continue;
        const uintptr_t start = (uintptr_t)trap_addr;
        if (start > UINTPTR_MAX - trap_size)
            continue;
        const uintptr_t end = start + trap_size;
        if (target >= start && target < end)
            return 1;
    }
    return 0;
}

// 前向声明：处理器定义在下方，安装函数与 drain 都需要它的地址。
static void cprisk_guard_fault_handler_i(int sig, siginfo_t *info, void *uap);

static int cprisk_addr_in_text_honeypot(const void *addr);

/* Best-effort notification in normal context. Guard faults are fatal, so
 * this is not guaranteed to run before the process terminates. */
// 在正常上下文消费信箱：取走地址、在锁内与已知 guard/蜜罐区间比对，
// 命中才发出一次“已发生 guard 访问”的通知。必须在进程终止前被调用，
// 不可在信号处理器中调用（内部会加锁）。
void cprisk_guard_fault_drain_pending(void) {
    void *addr = atomic_exchange_explicit(&s_fault_pending_addr, NULL, memory_order_acq_rel);
    if (addr == NULL)
        return;
    pthread_mutex_lock(&s_sigbus_guard_mutex);
    const int is_guard = cprisk_sigbus_addr_in_guard(s_sigbus_guard_state, addr) ||
        cprisk_addr_in_text_honeypot(addr);
    pthread_mutex_unlock(&s_sigbus_guard_mutex);
    if (is_guard)
        cprisk_guard_page_fault_notify();
}

/* Previous crash handlers are not chained. The fault is fatal and must retain
 * its signal exit status; signal disposition/mask operations below are
 * async-signal-safe (see Apple's sigaction(2) documentation). */
// 安装 SIGBUS/SIGSEGV 处理器（调用方须持有 s_sigbus_guard_mutex）。
// SA_RESETHAND 保证处理器只执行一次，随后按默认处置退出；
// 若 SIGSEGV 安装失败会回滚 SIGBUS，避免留下半套处置。
static int cprisk_fault_handlers_install_locked(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = cprisk_guard_fault_handler_i;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;

    if (sigaction(SIGBUS, &sa, &s_prev_sigbus_action) != 0)
        return -1;
    if (sigaction(SIGSEGV, &sa, &s_prev_sigsegv_action) != 0) {
        (void)sigaction(SIGBUS, &s_prev_sigbus_action, NULL);
        return -1;
    }
    s_fault_handlers_installed = 1;
    return 0;
}

// 恢复安装前的信号处置；仅在两个引用计数都归零时调用，
// 防止另一使用方（mem-trap / text honeypot）失去保护。
static void cprisk_fault_handlers_uninstall_locked(void) {
    if (!s_fault_handlers_installed)
        return;
    (void)sigaction(SIGBUS, &s_prev_sigbus_action, NULL);
    (void)sigaction(SIGSEGV, &s_prev_sigsegv_action, NULL);
    s_fault_handlers_installed = 0;
}

// mem-trap 侧获取共享处理器：首次获取才真正安装，失败返回 -1 且不增加计数，
// 保证调用方可以安全回滚“已种页但未接线”的中间状态。
static int cprisk_fault_handlers_acquire_mem_trap_locked(void) {
    if (s_mem_trap_fault_ref + s_text_honeypot_fault_ref == 0) {
        if (cprisk_fault_handlers_install_locked() != 0)
            return -1;
    }
    s_mem_trap_fault_ref++;
    return 0;
}

// 释放 mem-trap 侧引用；计数归零时卸载共享处理器。
// 对 0 计数做保护，重复释放不会把计数回绕成很大的值。
static void cprisk_fault_handlers_release_mem_trap_locked(void) {
    if (s_mem_trap_fault_ref > 0)
        s_mem_trap_fault_ref--;
    if (s_mem_trap_fault_ref + s_text_honeypot_fault_ref == 0)
        cprisk_fault_handlers_uninstall_locked();
}

// __TEXT 蜜罐侧获取共享处理器；与 mem-trap 侧复用同一安装，避免互相覆盖处置。
static int cprisk_fault_handlers_acquire_text_honeypot_locked(void) {
    if (s_mem_trap_fault_ref + s_text_honeypot_fault_ref == 0) {
        if (cprisk_fault_handlers_install_locked() != 0)
            return -1;
    }
    s_text_honeypot_fault_ref++;
    return 0;
}

// 释放 __TEXT 蜜罐侧引用；只有两个计数都归零才卸载信号处理器。
static void cprisk_fault_handlers_release_text_honeypot_locked(void) {
    if (s_text_honeypot_fault_ref > 0)
        s_text_honeypot_fault_ref--;
    if (s_mem_trap_fault_ref + s_text_honeypot_fault_ref == 0)
        cprisk_fault_handlers_uninstall_locked();
}

// 判断地址是否落在已注册的 __TEXT 蜜罐区间；未注册（lo==0）或区间退化时返回 0。
// 仅在正常上下文调用（drain 持锁调用），因此无需依赖区间读的原子性。
static int cprisk_addr_in_text_honeypot(const void *addr) {
    if (!addr)
        return 0;
    uintptr_t lo = s_text_honeypot_lo;
    uintptr_t hi = s_text_honeypot_hi;
    if (lo == 0 || hi <= lo)
        return 0;
    uintptr_t t = (uintptr_t)addr;
    return (t >= lo && t < hi) ? 1 : 0;
}

/* No locks, allocation, fd access, or callback forwarding in this handler.
 * Re-deliver the fatal signal to the current thread after unblocking it;
 * kill(getpid(), sig) followed by _Exit otherwise often reports an ordinary
 * exit instead of a signal crash, because sig is blocked during the handler. */
// 处理器只做三件事：把故障地址写入无锁信箱、恢复默认处置并解除阻塞、
// 重新投递原信号；任何一步失败才落到 _Exit(128+sig) 的兜底。
static void cprisk_guard_fault_handler_i(int sig, siginfo_t *info, void *uap) {
    (void)uap;
    atomic_store_explicit(&s_fault_pending_addr,
                          info != NULL ? info->si_addr : NULL,
                          memory_order_release);
    struct sigaction dfl;
    dfl.sa_handler = SIG_DFL;
    dfl.sa_flags = 0;
    sigemptyset(&dfl.sa_mask);
    sigset_t unblocked;
    sigemptyset(&unblocked);
    sigaddset(&unblocked, sig);
    if (sigaction(sig, &dfl, NULL) == 0 &&
        sigprocmask(SIG_UNBLOCK, &unblocked, NULL) == 0)
        (void)raise(sig);
    /* Only a failed re-delivery reaches this fallback. */
    _Exit(128 + sig);
}

// 注册单页 __TEXT 蜜罐：先发布区间，再获取共享处理器引用；
// 获取失败时把区间回滚为未注册，避免留下“看起来已保护”的假象。
// 成功后对页面的访问会触发 fatal 故障（除非调用方先恢复页保护）。
int cprisk_register_text_honeypot_page(void *page, size_t len) {
    if (!page || len == 0)
        return -1;

    pthread_mutex_lock(&s_sigbus_guard_mutex);
    s_text_honeypot_lo = (uintptr_t)page;
    s_text_honeypot_hi = (uintptr_t)page + len;
    if (cprisk_fault_handlers_acquire_text_honeypot_locked() != 0) {
        s_text_honeypot_lo = 0;
        s_text_honeypot_hi = 0;
        pthread_mutex_unlock(&s_sigbus_guard_mutex);
        return -1;
    }
    pthread_mutex_unlock(&s_sigbus_guard_mutex);
    return 0;
}

// 撤销 __TEXT 蜜罐区间并释放处理器引用；可在未注册时安全调用。
// 撤销后不再把该区间内的故障归类为蜜罐命中，页面保护需由调用方自行恢复。
void cprisk_unregister_text_honeypot_page(void) {
    pthread_mutex_lock(&s_sigbus_guard_mutex);
    s_text_honeypot_lo = 0;
    s_text_honeypot_hi = 0;
    cprisk_fault_handlers_release_text_honeypot_locked();
    pthread_mutex_unlock(&s_sigbus_guard_mutex);
}

// 把 mem-trap 路径的 state 发布给故障通知分类，并确保共享处理器已安装。
// 幂等：重复调用只替换 state 并重新置位 poison_mode_enabled，不重复增加引用计数。
// 注意：已安装时替换 state 不会为旧 state 释放引用，旧 state 的移除需自行完成。
int cprisk_install_sigbus_guard(struct cprisk_guard_state *state) {
    if (!state)
        return -1;

    pthread_mutex_lock(&s_sigbus_guard_mutex);
    if (s_sigbus_guard_installed) {
        s_sigbus_guard_state = state;
        state->poison_mode_enabled = 1u;
        pthread_mutex_unlock(&s_sigbus_guard_mutex);
        return 0;
    }

    if (cprisk_fault_handlers_acquire_mem_trap_locked() != 0) {
        pthread_mutex_unlock(&s_sigbus_guard_mutex);
        return -1;
    }

    s_sigbus_guard_installed = 1;
    s_sigbus_guard_state = state;
    state->poison_mode_enabled = 1u;
    pthread_mutex_unlock(&s_sigbus_guard_mutex);
    return 0;
}

// 撤销发布的 guard state 并释放引用。传入非当前 state 时直接返回，
// 防止一个 owner 误摘掉另一个 owner 的保护（state 归属校验）。
void cprisk_remove_sigbus_guard(struct cprisk_guard_state *state) {
    pthread_mutex_lock(&s_sigbus_guard_mutex);
    if (!s_sigbus_guard_installed) {
        pthread_mutex_unlock(&s_sigbus_guard_mutex);
        return;
    }

    if (state != NULL && state != s_sigbus_guard_state) {
        pthread_mutex_unlock(&s_sigbus_guard_mutex);
        return;
    }

    cprisk_fault_handlers_release_mem_trap_locked();
    s_sigbus_guard_installed = 0;
    s_sigbus_guard_state = NULL;
    pthread_mutex_unlock(&s_sigbus_guard_mutex);
}

// 将解密后的区域整页降为只读（VM_PROT_READ），阻断解密后的写入注入。
// 只改保护位、不使用 MADV_FREE/REUSABLE，确保页内容不会被 VM 回收；
// 范围按页向外扩张，因此会连带影响与 region 共享页的相邻数据。
// 返回 -1 表示至少一页未降权，调用方应视为明文仍可写（fail-closed）。
int cprisk_protect_decrypted_pages(void *region, size_t len) {
    if (!region || len == 0)
        return -1;

    vm_address_t page;
    vm_size_t span;
    if (page_span(region, len, &page, &span) != 0)
        return -1;

    /* These pages still contain live plaintext. MADV_FREE/REUSABLE would
     * allow the VM to discard it; changing protection must preserve bytes. */
    kern_return_t kr = vm_protect(
        mach_task_self(),
        page,
        span,
        FALSE,
        VM_PROT_READ);
    if (kr != KERN_SUCCESS)
        return -1;

    return 0;
}

/* Every region intersecting the requested span must satisfy the policy.
 * Querying just its first region can miss writable pages or holes later on. */
// 逐区段校验 [page, page+span) 的保护位：每个区段都必须包含 required 且不含 forbidden。
// 任何查询失败、空洞、非前进的区段都返回 0（未通过），而不是跳过——
// 这样复检失败会朝“更可疑”方向收敛，不会因内核查询异常被当成干净。
static int cprisk_vm_range_has_protection_i(vm_address_t page, vm_size_t span,
                                           vm_prot_t required, vm_prot_t forbidden) {
    if (span == 0u || page > UINTPTR_MAX - span)
        return 0;
    const vm_address_t end = page + span;
    vm_address_t cursor = page;
    while (cursor < end) {
        vm_address_t region = cursor;
        vm_size_t region_size = 0u;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object_name = MACH_PORT_NULL;
        const kern_return_t kr = vm_region_64(
            mach_task_self(), &region, &region_size, VM_REGION_BASIC_INFO_64,
            (vm_region_info_t)&info, &count, &object_name);
        if (object_name != MACH_PORT_NULL)
            mach_port_deallocate(mach_task_self(), object_name);
        if (kr != KERN_SUCCESS || region > cursor || region_size == 0u ||
            region > UINTPTR_MAX - region_size || region + region_size <= cursor)
            return 0;
        if ((info.protection & required) != required || (info.protection & forbidden) != 0)
            return 0;
        cursor = region + region_size;
    }
    return 1;
}

#if defined(__APPLE__)
// 把 BSD 的 PROT_* 位翻译成 Mach 的 VM_PROT_*；只映射读/写/执行三种权限。
static vm_prot_t cprisk_vm_prot_from_bsd_i(int prot) {
    vm_prot_t p = VM_PROT_NONE;
    if ((prot & PROT_READ) != 0)
        p |= VM_PROT_READ;
    if ((prot & PROT_WRITE) != 0)
        p |= VM_PROT_WRITE;
    if ((prot & PROT_EXEC) != 0)
        p |= VM_PROT_EXECUTE;
    return p;
}
#endif

// POSIX mprotect 成功后的 Mach 侧复核：先按“需要位必须全有、其他位必须全无”
// 校验实际保护位，不一致返回 1；一致则再做一次幂等 vm_protect，失败返回 2。
// 返回 0 表示一致（非 Apple 平台视为跳过复核，恒 0）。
int cprisk_vm_crosscheck_mprotect(void *addr, size_t len, int bsd_prot) {
#if !defined(__APPLE__)
    (void)addr;
    (void)len;
    (void)bsd_prot;
    return 0;
#else
    if (!addr || len == 0)
        return 0;

    vm_address_t page = 0;
    vm_size_t span = 0;
    if (page_span(addr, len, &page, &span) != 0)
        return 0;

    const vm_prot_t need = cprisk_vm_prot_from_bsd_i(bsd_prot);

    const vm_prot_t forbidden = (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE) & ~need;
    if (!cprisk_vm_range_has_protection_i(page, span, need, forbidden))
        return 1;

    kern_return_t kr2 = vm_protect(
        mach_task_self(),
        page,
        span,
        FALSE,
        need);
    if (kr2 != KERN_SUCCESS)
        return 2;
    return 0;
#endif
}

// 在信号上下文中前移保存的 PC，供“跳过断点/陷阱指令”的处理器使用。
// arm64 默认前进 4 字节（一条 A64 指令），x86_64 默认 1 字节；
// 不透明 arm64 thread state 必须走 __darwin_arm_thread_state64_* 访问器。
// 无法识别的架构或空 ucontext 返回 -1，调用方不得假设 PC 已改变。
int cprisk_advance_ucontext_pc(void *uap, uintptr_t advance_bytes) {
    if (uap == NULL)
        return -1;

    ucontext_t *uctx = (ucontext_t *)uap;
    if (uctx->uc_mcontext == NULL)
        return -1;

#if defined(__aarch64__)
    uintptr_t step = advance_bytes != 0u ? advance_bytes : 4u;
#if defined(__DARWIN_OPAQUE_ARM_THREAD_STATE64) && __DARWIN_OPAQUE_ARM_THREAD_STATE64
    uintptr_t pc = __darwin_arm_thread_state64_get_pc(uctx->uc_mcontext->__ss);
    pc += step;
    __darwin_arm_thread_state64_set_pc_fptr(uctx->uc_mcontext->__ss, (void *)pc);
#else
    uctx->uc_mcontext->__ss.__pc += (uint64_t)step;
#endif
    return 0;
#elif defined(__x86_64__)
    uint64_t step = (uint64_t)(advance_bytes != 0u ? advance_bytes : 1u);
    uctx->uc_mcontext->__ss.__rip += step;
    return 0;
#else
    (void)advance_bytes;
    return -1;
#endif
}

// 复检区域是否“只读不可写”：所有页段都含 READ 且不含 WRITE 才返回 1。
// 参数非法、对齐失败或查询失败均返回 0（未通过），调用方不能把 0 当安全。
int cprisk_verify_page_protection(void *region, size_t len) {
    if (!region || len == 0)
        return 0;

    vm_address_t page;
    vm_size_t span;
    if (page_span(region, len, &page, &span) != 0)
        return 0;

    return cprisk_vm_range_has_protection_i(page, span, VM_PROT_READ, VM_PROT_WRITE);
}

// 恢复区域可读可写，仅供“重新加密/重写数据段”这一受控窗口使用。
// 返回 -1 表示仍有页未恢复写权限；调用方不应在未恢复的情况下加密写回。
int cprisk_unprotect_pages(void *region, size_t len) {
    if (!region || len == 0)
        return -1;

    vm_address_t page;
    vm_size_t span;
    if (page_span(region, len, &page, &span) != 0)
        return -1;

    kern_return_t kr = vm_protect(
        mach_task_self(),
        page,
        span,
        FALSE,
        VM_PROT_READ | VM_PROT_WRITE);
    return (kr == KERN_SUCCESS) ? 0 : -1;
}

// 在区域前后各种一页 VM_PROT_NONE 的 guard 页，并把地址登记到 state。
// 使用 VM_FLAGS_FIXED 复用相邻地址空间，因此相邻页已被映射时分配会失败，
// 这属于正常情况：只统计真正种下的页数，返回 planted。
// 只有 trap_count > 0 才把 pages_protected 置 1，避免把“一页未种”伪装成已保护；
// 处理器安装失败时清除 poison_mode_enabled，但 guard 页仍保留（访问仍会崩溃）。
int cprisk_install_memory_trap(void *region, size_t len,
                               struct cprisk_guard_state *state) {
    if (!region || len == 0 || !state)
        return -1;

    vm_address_t page;
    vm_size_t span;
    if (page_span(region, len, &page, &span) != 0)
        return -1;

    vm_address_t guard_addrs[2];
    int guard_valid[2];
    const vm_size_t guard_size = (vm_size_t)cprisk_guard_page_size_i();
    if (guard_size == 0u)
        return -1;
    guard_valid[0] = (page >= guard_size);
    guard_addrs[0] = guard_valid[0] ? (page - guard_size) : 0;
    guard_valid[1] = (page + span <= UINTPTR_MAX - guard_size);
    guard_addrs[1] = page + span;

    int planted = 0;
    /* The state may already be published to the normal-context fault drain. */
    pthread_mutex_lock(&s_sigbus_guard_mutex);
    for (int i = 0; i < 2 && state->trap_count < CPRISK_GUARD_MAX_TRAPS; i++) {
        if (!guard_valid[i])
            continue;
        vm_address_t alloc_addr = guard_addrs[i];
        kern_return_t kr = vm_allocate(
            mach_task_self(),
            &alloc_addr,
            guard_size,
            VM_FLAGS_FIXED);

        if (kr != KERN_SUCCESS)
            continue;

        kr = vm_protect(
            mach_task_self(),
            alloc_addr,
            guard_size,
            FALSE,
            VM_PROT_NONE);

        if (kr != KERN_SUCCESS) {
            state->protect_failed = 1;
            vm_deallocate(mach_task_self(), alloc_addr, guard_size);
            continue;
        }

        state->traps[state->trap_count].addr = (void *)alloc_addr;
        state->traps[state->trap_count].size = guard_size;
        state->trap_count++;
        planted++;
    }

    /* Only mark traps as active when at least one guard page was actually
     * installed.  VM_FLAGS_FIXED allocation fails when the adjacent pages are
     * already mapped (standard in any __DATA segment), so planted may be 0.
     * Setting pages_protected=1 unconditionally masks this silent failure and
     * misleads any caller that inspects state->pages_protected. */
    state->pages_protected = (state->trap_count > 0) ? 1 : 0;
    pthread_mutex_unlock(&s_sigbus_guard_mutex);
    if (planted > 0) {
        if (cprisk_install_sigbus_guard(state) != 0)
            state->poison_mode_enabled = 0u;
    }
    return planted;
}

// 撤销 guard：先从信号通知路径摘掉 state（释放处理器引用），再释放 guard 页，
// 最后整体清零 state。顺序不可颠倒，否则处理器可能读到已释放的 trap 地址。
void cprisk_remove_memory_trap(struct cprisk_guard_state *state) {
    if (!state)
        return;

    // Detach published trap metadata before releasing any referenced pages.
    cprisk_remove_sigbus_guard(state);
    uint32_t limit = state->trap_count;
    if (limit > CPRISK_GUARD_MAX_TRAPS)
        limit = CPRISK_GUARD_MAX_TRAPS;
    for (uint32_t i = 0; i < limit; i++) {
        if (state->traps[i].addr && state->traps[i].size > 0) {
            vm_deallocate(
                mach_task_self(),
                (vm_address_t)state->traps[i].addr,
                (vm_size_t)state->traps[i].size);
        }
    }
    memset(state, 0, sizeof(*state));
}

#if defined(__APPLE__)
// 单次 tick 最多扫描的 VM 区段数：把全量扫描摊到多次调用上，避免在加固循环里
// 长时间持锁/占用 CPU。96 是“覆盖常见进程布局且单次耗时可控”的折中。
#define CPRISK_MEM_GUARD_VM_REGION_SCAN_MAX 96u

#if !(defined(TARGET_OS_SIMULATOR) && TARGET_OS_SIMULATOR)
// 跨 tick 的续扫游标：让连续调用从上次中断处继续，最终覆盖整个地址空间。
// 仅真机使用；模拟器每次从头扫，保持行为简单。
static vm_address_t s_cprisk_mem_guard_vm_addr_cursor;
#endif

// XNU 中 240..245 是分析工具与 malloc 系匿名分配的 user_tag；
// 归为“非镜像匿名内存”，用于识别伪装成镜像区间的可执行映射。
static int cprisk_mem_guard_user_tag_is_anonymous_i(unsigned int user_tag) {
    return (user_tag >= 240u && user_tag <= 245u) ? 1 : 0;
}

// 这些 tag 通常由 dyld/共享 pmap 使用；出现在“不属于任何镜像的 RX 区间”上
// 说明镜像归属信息与映射自相矛盾，需要上报镜像列表变化。
static int cprisk_mem_guard_user_tag_is_expected_image_i(unsigned int user_tag) {
#if defined(VM_MEMORY_DYLIB)
    if (user_tag == VM_MEMORY_DYLIB) {
        return 1;
    }
#endif
#if defined(VM_MEMORY_SHARED_PMAP)
    if (user_tag == VM_MEMORY_SHARED_PMAP) {
        return 1;
    }
#endif
    return 0;
}

// 轻量 dyld/VM 一致性 tick，返回 CPRISK_MEM_GUARD_TICK_* 位掩码（不是判决）：
//   1) dyld 布局摘要与基线不一致 → IMAGE_LIST_CHANGED；
//   2) 单次至多扫描 96 个区段（续扫），发现无镜像归属的 RX → UNKNOWN_EXECUTABLE_RX；
//   3) 真机上同一区段可写可执行 → EXECUTABLE_WRITE（W^X 被破坏）。
// 探测失败（task_info/vm_region 异常、摘要返回 -1）不置位，避免把“看不到”当异常；
// 该函数开销与区段数成正比，应由看门狗低频调用。
uint32_t cprisk_memory_guard_image_vm_tick(void) {
    uint32_t flags = 0u;
    // 只把明确“不同”（1）当异常；-1 表示摘要无法计算，保持不置位以免误报。
    const int layout_diff = cprisk_vm_dyld_image_layout_digest_differs_from_baseline();
    if (layout_diff == 1) {
        flags |= CPRISK_MEM_GUARD_TICK_IMAGE_LIST_CHANGED;
    }

#if defined(TARGET_OS_SIMULATOR) && TARGET_OS_SIMULATOR
    vm_address_t addr = 0u;
#else
    vm_address_t addr = s_cprisk_mem_guard_vm_addr_cursor;
#endif
    natural_t depth = 0u;
    for (uint32_t step = 0; step < CPRISK_MEM_GUARD_VM_REGION_SCAN_MAX; step++) {
        vm_size_t sz = 0u;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        vm_address_t a = addr;
        kern_return_t kr = vm_region_recurse_64(
            mach_task_self(),
            &a,
            &sz,
            &depth,
            (vm_region_recurse_info_t)&info,
            &count);
        if (kr != KERN_SUCCESS) {
#if !(defined(TARGET_OS_SIMULATOR) && TARGET_OS_SIMULATOR)
            s_cprisk_mem_guard_vm_addr_cursor = 0u;
#endif
            break;
        }
        // 子映射本身不占地址区间，下钻一层后继续；深度由内核维护。
        if (info.is_submap) {
            depth += 1u;
            continue;
        }
#if !(defined(TARGET_OS_SIMULATOR) && TARGET_OS_SIMULATOR)
        if (sz > 0u &&
            (info.protection & VM_PROT_WRITE) != 0 &&
            (info.protection & VM_PROT_EXECUTE) != 0) {
            flags |= CPRISK_MEM_GUARD_TICK_EXECUTABLE_WRITE;
        }
#endif
        // 对 RX 区段取首/中/尾三点做镜像归属采样：单点可能落在镜像间隙，
        // 三点全在外才判定“无归属”，三点全在内才判定“归属一致”，其余视为跨区段不表态。
        const vm_prot_t rx_need = VM_PROT_READ | VM_PROT_EXECUTE;
        if (sz > 0u && (info.protection & rx_need) == rx_need) {
            const uintptr_t a0 = (uintptr_t)a;
            const uintptr_t a1 = a0 + (uintptr_t)(sz >> 1);
            const uintptr_t a2 = a0 + (uintptr_t)(sz - 1u);
            const int p0_in_image = cprisk_addr_in_any_image_executable((const void *)a0);
            const int p1_in_image = cprisk_addr_in_any_image_executable((const void *)a1);
            const int p2_in_image = cprisk_addr_in_any_image_executable((const void *)a2);
            const int all_in_image = p0_in_image != 0 && p1_in_image != 0 && p2_in_image != 0;
            const int all_outside_image = p0_in_image == 0 && p1_in_image == 0 && p2_in_image == 0;
            if (all_outside_image) {
                uintptr_t wl_lo = 0u;
                uintptr_t wl_hi = 0u;
                cprisk_svc_reloc_rx_page_whitelist_bounds(&wl_lo, &wl_hi);
                const uintptr_t ra = (uintptr_t)a;
                const uintptr_t ra_end = ra + (uintptr_t)sz;
                const int region_is_only_reloc_svc_page =
                    wl_lo != 0u && wl_hi > wl_lo && ra == wl_lo && ra_end == wl_hi;
                // direct_syscall 的 SVC 桩重定位页也是匿名 RX，但它是本 SDK 自己的页；
                // 只有“区间边界与白名单完全相等”才豁免，防止攻击者用相邻映射蹭白名单。
                if (region_is_only_reloc_svc_page) {
                    /* Known anonymous RX from direct_syscall SVC stub relocation — not a foreign slab. */
                } else {
                    if (cprisk_mem_guard_user_tag_is_expected_image_i(info.user_tag) != 0) {
                        flags |= CPRISK_MEM_GUARD_TICK_IMAGE_LIST_CHANGED;
                    }
                    // 命中一个明确的异形 RX 区段即可提前结束本轮（后续 tick 会续扫）。
                    flags |= CPRISK_MEM_GUARD_TICK_UNKNOWN_EXECUTABLE_RX;
                    break;
                }
            }
            // 地址在镜像内、user_tag 却是匿名分配：镜像归属信息与映射元数据矛盾。
            if (all_in_image &&
                cprisk_mem_guard_user_tag_is_anonymous_i(info.user_tag) != 0) {
                flags |= CPRISK_MEM_GUARD_TICK_IMAGE_LIST_CHANGED;
            }
        }
        if (sz == 0u || a + sz < a) {
#if !(defined(TARGET_OS_SIMULATOR) && TARGET_OS_SIMULATOR)
            s_cprisk_mem_guard_vm_addr_cursor = 0u;
#endif
            break;
        }
        addr = a + sz;
    }
#if !(defined(TARGET_OS_SIMULATOR) && TARGET_OS_SIMULATOR)
    s_cprisk_mem_guard_vm_addr_cursor = addr;
#endif
    return flags;
}
#else
// 非 Apple 平台没有 dyld/Mach VM 语义，恒返回 0（不支持，不代表干净）。
uint32_t cprisk_memory_guard_image_vm_tick(void) {
    return 0u;
}
#endif
