// 职责：为 Apple arm64 真机提供 SVC #0x80 直调包装（sysctl/stat/open/mprotect/getentropy/csops 等），
//   绕开 libc 符号，使被 Frida/Substrate hook 时仍能拿到内核真实结果。
// 线程模型：构造函数(3) 重定位模板到 RX 页、构造函数(8) 抓取完整性快照；运行期只读，
//   回退掩码用 volatile、事件计数用原子操作，可并发调用。
// 平台/架构：仅 arm64 iOS 真机启用 SVC；模拟器/非 arm64 构建自动回退 libc 并记录降级位。
// 失败语义：直调失败返回 -1 并经 error_out 回传 errno；完整性与交叉校验探针 fail-open，不阻断调用。

#include "include/CRiskCore.h"
#include "include/cprisk_instruction_cache.h"

/*
 * Direct SVC stubs are arm64-device only. Every libc / arc4random substitute records
 * cprisk_note_libc_fallback_used(...) so libc_fallback_used_mask + event_total are never
 * silently consumed-only-in-C: watchdog snapshot and Swift risk layers read the same bits.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <alloca.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <stdatomic.h>
#include "include/cprisk_secure_zero.h"

#if defined(__APPLE__)
#include <TargetConditionals.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/vm_region.h>
#endif

// 平台闸门：只有 arm64 Apple 真机才启用 SVC 模板。TARGET_OS_IPHONE 覆盖 iOS 类环境，
// 模拟器被显式排除——模拟器的 SVC 并不落入真实内核，行为不能当真机语义使用。
#if (defined(__arm64__) || defined(__aarch64__)) && defined(__APPLE__) && \
    (defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE) && \
    (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
#define CPRISK_DIRECT_SYSCALLS_AVAILABLE 1
#else
#define CPRISK_DIRECT_SYSCALLS_AVAILABLE 0
#endif

// SHA-256 只在真机构建的 stub 重定位与完整性校验中使用；回退构建不引入该依赖，
// 避免把密码学实现带进只跑 libc 的宿主测试。
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
#include "include/cprisk_sha256.h"
#endif

/* Snapshot sizes for SVC templates + RX relocation (keep in sync with integrity section). */
// 模板快照按 16 字节分块做 FNV 滚动校验：syscall6 取 48 字节（3 块），syscall0 取 32 字节（2 块）。
// 这些数字同时决定重定位页布局与校验范围；改动必须与下方 integrity 段落同步，
// 否则快照会截断指令或把相邻数据算进哈希。
#define CPRISK_SVC_STUB_SNAPSHOT_BYTES 48u
#define CPRISK_SVC0_STUB_SNAPSHOT_BYTES 32u
#define CPRISK_SVC_STUB_CHUNK_BYTES 16u
#define CPRISK_SVC_STUB6_CHUNKS 3u
#define CPRISK_SVC_STUB0_CHUNKS 2u

// 页基址掩码取 4 KiB 对齐，比硬件页更细：在 16 KiB 页设备上按它取基址仍落在同一真实页内，
// 不会越界；允许外部覆盖以适配特殊布局。
#ifndef CPRISK_STUB_PAGE_MASK
#define CPRISK_STUB_PAGE_MASK ((uintptr_t)0xFFFu)
#endif

// 不支持直调的构建在进程启动时立即置 bit7：这是“预期降级”，与运行期偶发回退区分，
// 让 watchdog 不会把构建差异误判成被 hook。
#if !CPRISK_DIRECT_SYSCALLS_AVAILABLE
/* Process-wide tag: this build cannot emit SVC syscall templates; libc substitutes are expected. */
__attribute__((constructor))
static void cprisk_direct_syscall_note_unsupported_build(void) {
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_UNSUPPORTED_PLATFORM);
}
#endif

// libc 路径的统一收尾：仅在调用方给了 error_out 时写入，成功写 0、失败写当前线程 errno。
// 返回值原样透传，避免改变调用方对 0/-1（或 fd>=0）的判断。
static int cprisk_finish_errno(int result, int *error_out) {
    if (error_out != NULL) {
        *error_out = (result == 0) ? 0 : errno;
    }
    return result;
}

// libc 回退证据：mask 按位或累积“哪些直调路径走过 libc”，event_total 统计事件次数
//（可大于 mask 的 popcount）。置位者：本文件各 direct 包装及 armor 层；读取者：
//  watchdog 快照（anti_debug_watchdog.c）、cprisk_integrity.c 与 Swift 判决层。
// bit 语义：bit0 mprotect、bit1 getentropy、bit2 sysctl、bit3 stat/lstat/access、
//  bit4 open/close/read/socket/connect、bit5 getpid/getppid/getuid、bit6 armor 内部 mprotect、
//  bit7 构建无 SVC stub（构造期置位，属预期）、bit8 csops 不可用（不降级，直接 ENOTSUP）、
//  bit9 stub 意外走到 ENOTSUP 兜底。
// 重置时机：初始化基线、DEBUG 测试钩子与数据加载器卸载路径都会调用；调用方必须保证
// 此刻没有并发的回退事件（mask 是非原子写，计数是原子写）。
// mask 用 volatile 而非原子：并发写可能丢位（只影响统计精度），但不会撕裂；计数用原子。
static volatile uint32_t s_cprisk_libc_fallback_used_mask = 0u;
static atomic_uint_fast32_t s_cprisk_libc_fallback_event_total;

// 记录一次降级：置位对应 bit 并累加事件数。所有 libc 替代路径都必须调用，
// 否则 mask 会静默不置位，上层将误以为整条链路仍走 SVC 直调。
void cprisk_note_libc_fallback_used(uint32_t bits) {
    s_cprisk_libc_fallback_used_mask |= bits;
    atomic_fetch_add_explicit(&s_cprisk_libc_fallback_event_total, 1u, memory_order_relaxed);
}

// 读取累计回退位图（弱一致）：与 event_total 配合可区分“回退种类”和“回退频率”。
uint32_t cprisk_get_libc_fallback_used_mask(void) {
    return s_cprisk_libc_fallback_used_mask;
}

// 读取累计事件数（原子读）：跨线程只保证看到某个完整快照，不保证实时。
uint32_t cprisk_get_libc_fallback_event_total(void) {
    return (uint32_t)atomic_load_explicit(&s_cprisk_libc_fallback_event_total, memory_order_relaxed);
}

// 清零位图与计数，用于构建/测试基线重置；非原子写，禁止与并发回退同时使用。
void cprisk_reset_libc_fallback_used_mask(void) {
    s_cprisk_libc_fallback_used_mask = 0u;
    atomic_store_explicit(&s_cprisk_libc_fallback_event_total, 0u, memory_order_relaxed);
}

// 直调模板的函数指针类型：签名与模板一致，便于运行期把 active 指针从 __TEXT 模板
// 切换到 mmap 出来的 RX 副本——地址变了，但调用约定不变。
typedef long (*cprisk_svc6_fn_t)(
    long syscall_number,
    long arg0,
    long arg1,
    long arg2,
    long arg3,
    long arg4,
    long arg5,
    int *error_out);

// 0 参数模板只用于 getpid/getppid/getuid 这类不会失败、只返回标量的热路径。
typedef long (*cprisk_svc0_fn_t)(long syscall_number);

// 非 arm64 构建里模板只剩 ENOTSUP 兜底、不会被引用；用 unused 抑制告警，
// 而不是删掉模板，保证两种构建下符号与类型保持一致。
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
#define CPRISK_DIRECT_SYSCALL_MAYBE_UNUSED
#else
#define CPRISK_DIRECT_SYSCALL_MAYBE_UNUSED __attribute__((unused))
#endif

// 六参数直调模板（Darwin arm64 syscall ABI）：x16=系统调用号，x0..x5=参数，
// `svc #0x80` 进入内核。成功时 x0=结果且 carry 清零；失败时 carry 置位且 x0=errno，
// 此时返回 -1 并把 x0 写入 *error_out（不写进程 errno，避免污染 libc 语义）。
// 参数与所有权：error_out 可为 NULL；path/buf 等指针参数不转移所有权，生命周期由调用方保证。
// 线程安全：无共享状态，可从任意线程并发调用。
// 平台/架构：仅 arm64 Apple 真机；其它构建返回 -1、*error_out=ENOTSUP 并置 bit9。
static CPRISK_DIRECT_SYSCALL_MAYBE_UNUSED long cprisk_direct_syscall6_template(
    long syscall_number,
    long arg0,
    long arg1,
    long arg2,
    long arg3,
    long arg4,
    long arg5,
    int *error_out
) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    // 用 register ... __asm("xN") 把局部变量钉到 ABI 指定的物理寄存器，
    // 避免编译器自行分配后再搬运，保证 svc 看到的就是这些值。
    register long x0 __asm("x0") = arg0;
    register long x1 __asm("x1") = arg1;
    register long x2 __asm("x2") = arg2;
    register long x3 __asm("x3") = arg3;
    register long x4 __asm("x4") = arg4;
    register long x5 __asm("x5") = arg5;
    register long x16 __asm("x16") = syscall_number;
    unsigned int did_error = 0;

    // "+r" 是读写约束：内核会改写 x0..x5（失败时 x0 变成 errno），必须声明为可写。
    // cset 读取 svc 之后的条件码（Darwin 用 C=1 表示出错），故需要 "cc" clobber；
    // "memory" 阻止编译器把访存跨越 syscall 重排——内核可能写入参数指向的缓冲区。
    __asm__ volatile(
        "svc #0x80\n"
        "cset %w[did_error], cs\n"
        : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5), [did_error] "=r"(did_error)
        : "r"(x16)
        : "cc", "memory"
    );

    if (did_error) {
        // 失败时 x0 是 errno 而不是返回值；只经 error_out 上报，保持调用方 errno 不变。
        if (error_out != NULL) {
            *error_out = (int)x0;
        }
        return -1;
    }

    if (error_out != NULL) {
        // 成功统一写 0，调用方无需预先清空 error_out。
        *error_out = 0;
    }
    return x0;
#else
    (void)syscall_number;
    (void)arg0;
    (void)arg1;
    (void)arg2;
    (void)arg3;
    (void)arg4;
    (void)arg5;
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_SYSCALL_STUB_FALLBACK);
    if (error_out != NULL) {
        *error_out = ENOTSUP;
    }
    return -1;
#endif
}

/*
 * Zero-argument syscall template – optimised for hot-path calls
 * (getpid / getppid / getuid) that never fail and return a single value.
 */
// 零参数直调模板：x0 只作输出（"=r"，内核不读入参），成功/失败都直接返回 x0。
// 仅用于不会失败的 getpid/getppid/getuid，因此不判 carry、没有 error_out。
// 平台/架构：同六参数模板；非 arm64 返回 -1 并置 bit9。
static CPRISK_DIRECT_SYSCALL_MAYBE_UNUSED long cprisk_direct_syscall0_template(long syscall_number) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    register long x0 __asm("x0");
    register long x16 __asm("x16") = syscall_number;
    __asm__ volatile(
        "svc #0x80\n"
        : "=r"(x0)
        : "r"(x16)
        : "cc", "memory"
    );
    return x0;
#else
    (void)syscall_number;
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_SYSCALL_STUB_FALLBACK);
    return -1;
#endif
}

#undef CPRISK_DIRECT_SYSCALL_MAYBE_UNUSED

#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
// 可切换的间接层：默认指向 __TEXT 模板；重定位成功后被替换为 RX 页中的副本。
// 构造函数(3) 单线程写入，之后只读，因此热路径无需加锁或原子读。
static cprisk_svc6_fn_t s_svc6_active = cprisk_direct_syscall6_template;
static cprisk_svc0_fn_t s_svc0_active = cprisk_direct_syscall0_template;
#endif

#if CPRISK_DIRECT_SYSCALLS_AVAILABLE && defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
// 重定位后的 RX stub 页及其基准值：页面先以 RW 写入模板，刷新 I-cache 后降权为 RX，
// 之后永不恢复写权限（W^X 不变量）。_page_hash_ref/_stub_roll_ref 是构造期快照；
// 两个 offset 记录模板在页内的位置；s_svc_reloc_ready 是唯一就绪标志（构造函数写、运行期读）。
static void *s_svc_rx_page;
static size_t s_svc_rx_page_size;
static uintptr_t s_svc6_rx_offset;
static uintptr_t s_svc0_rx_offset;
static uint64_t s_svc_rx_page_hash_ref;
static uint64_t s_svc_rx_stub_roll_ref;
static uint8_t s_svc6_reloc_body_sha256[32];
static uint8_t s_svc0_reloc_body_sha256[32];
static volatile int s_svc_reloc_ready;

/*
 * Mach readback: ensure the relocated stub page is still mapped RX (no write),
 * covering remaps / mprotect tampering that leaves bytes intact.
 * Also consult vm_region_recurse leaf info so max_prot cannot retain write+exec
 * (W^X / hook remap) even when cur protection looks RX.
 */
static int cprisk_svc_rx_page_mach_leaf_ok_i(void) {
    // 逐层下钻 submap，找到真正持有 stub 的叶 region，并确认：
    //  - 叶 region 完整覆盖 stub 页； - 当前权限含 R+X 且不含 W； - max_protection 也不含 W。
    // 只改当前权限骗不过 max_protection：hook 常先恢复写权限再打补丁。
    // 返回 1=通过；0=不可用或不满足（调用方按篡改处理，fail-closed）。
    if (s_svc_rx_page == NULL || s_svc_rx_page_size == 0u) {
        return 0;
    }
    const uintptr_t stub_lo = (uintptr_t)s_svc_rx_page;
    const uintptr_t stub_hi = stub_lo + s_svc_rx_page_size;
    const uintptr_t page0 = stub_lo & ~CPRISK_STUB_PAGE_MASK;
    vm_address_t addr = (vm_address_t)page0;
    natural_t depth = 0u;
    // 深度上限只是防御：正常映射 1–2 层，超过即视为异常链。
    for (unsigned guard = 0u; guard < 32u; guard++) {
        vm_size_t sz = 0u;
        vm_region_submap_info_data_64_t sub;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = vm_region_recurse_64(
            mach_task_self(),
            &addr,
            &sz,
            &depth,
            (vm_region_recurse_info_t)&sub,
            &count);
        if (kr != KERN_SUCCESS) {
            return 0;
        }
        if (sub.is_submap != 0) {
            // 子映射本身不持有页，继续下钻；addr/depth 由内核推进到子映射范围。
            depth += 1u;
            continue;
        }
        const uintptr_t reg_lo = (uintptr_t)addr;
        const uintptr_t reg_hi = reg_lo + (uintptr_t)sz;
        // 叶 region 必须完整覆盖 stub 页，否则页边界外可能已被拆分或重映射。
        if (reg_lo > stub_lo || stub_hi > reg_hi) {
            return 0;
        }
        const vm_prot_t need = (vm_prot_t)(VM_PROT_READ | VM_PROT_EXECUTE);
        if ((sub.protection & need) != need) {
            return 0;
        }
        if ((sub.protection & VM_PROT_WRITE) != 0) {
            return 0;
        }
        if ((sub.max_protection & VM_PROT_WRITE) != 0) {
            return 0;
        }
        return 1;
    }
    return 0;
}

static int cprisk_svc_rx_page_mach_prot_ok_i(void) {
    // 先用 vm_region_64 取基本权限做快速判定，再委托 leaf 校验复核 max_protection。
    // 返回 1=通过；0=查询失败或权限不符。
    if (s_svc_rx_page == NULL || s_svc_rx_page_size == 0u) {
        return 0;
    }
    const uintptr_t page0 = (uintptr_t)s_svc_rx_page & ~CPRISK_STUB_PAGE_MASK;
    vm_address_t region_addr = (vm_address_t)page0;
    vm_size_t region_sz = 0u;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj_name = MACH_PORT_NULL;
    kern_return_t kr = vm_region_64(
        mach_task_self(),
        &region_addr,
        &region_sz,
        VM_REGION_BASIC_INFO_64,
        (vm_region_info_t)&info,
        &count,
        &obj_name);
    if (kr != KERN_SUCCESS) {
        return 0;
    }
    const uintptr_t stub_lo = (uintptr_t)s_svc_rx_page;
    const uintptr_t stub_hi = stub_lo + s_svc_rx_page_size;
    const uintptr_t reg_hi = (uintptr_t)region_addr + (uintptr_t)region_sz;
    if (stub_lo < (uintptr_t)region_addr || stub_hi > reg_hi) {
        return 0;
    }
    const vm_prot_t need = (vm_prot_t)(VM_PROT_READ | VM_PROT_EXECUTE);
    if ((info.protection & need) != need) {
        return 0;
    }
    if ((info.protection & VM_PROT_WRITE) != 0) {
        return 0;
    }
    if (obj_name != MACH_PORT_NULL) {
        // vm_region 成功时会填充对象端口，必须释放，否则泄漏 send right。
        (void)mach_port_deallocate(mach_task_self(), obj_name);
    }
    // 基本信息的 max_protection 不可靠，必须再用 submap 叶信息复核 W^X。
    if (cprisk_svc_rx_page_mach_leaf_ok_i() == 0) {
        return 0;
    }
    return 1;
}

// 非密码学 FNV-1a(64) 折叠：用于发现意外改动与整页替换，不是抗碰撞证明；
// 真正的篡改证据由 SHA-256 页摘要提供。p 必须可读 n 字节，无分配、无共享状态。
static uint64_t cprisk_fnv1a64_fold_i(const void *p, size_t n) {
    const uint8_t *b = (const uint8_t *)p;
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0u; i < n; i++) {
        h ^= (uint64_t)b[i];
        h *= 1099511628211ULL;
    }
    return h;
}

// 启动期把两份 SVC 模板复制到匿名页并降权为 RX：直调地址因此不出现在 __TEXT 的固定偏移，
// 同时为完整性校验提供一份可独立比对的正文副本。
// 失败语义：页太小 / mmap 失败 / 偏移越界 / mprotect 失败 / 自检 getpid 不一致，任一发生即
//   munmap 后返回，ready 保持 0——调用方继续用 __TEXT 模板，属 fail-open。
// 线程安全：constructor(3) 单线程执行；之后所有全局只读。
// 平台/架构：仅 arm64 Apple 真机（外层 #if 已限定）。
__attribute__((constructor(3)))
static void cprisk_svc_stub_rx_reloc_ctor_i(void) {
    const size_t ps = (size_t)getpagesize();
    // 需容纳两份模板再加 64 字节余量，且页内还要留出随机偏移空间；页太小就放弃重定位。
    const size_t need = CPRISK_SVC_STUB_SNAPSHOT_BYTES + CPRISK_SVC0_STUB_SNAPSHOT_BYTES + 64u;
    if (ps < need + 4u) {
        return;
    }
    uint64_t r = 0u;
    int ge = 0;
    // 用 SVC 直调的 getentropy 取随机种子决定模板偏移；失败时退化为地址派生值，
    // 只损失布局随机性，不影响功能。
    if (cprisk_getentropy_direct(&r, sizeof(r), &ge) != 0) {
        r = (uint64_t)(uintptr_t)&cprisk_svc_stub_rx_reloc_ctor_i ^ 0xA5A5A5A5u;
    }
    // 先以 RW 映射匿名页写入模板，写完刷新 I-cache 再降权为 RX；MAP_PRIVATE|MAP_ANON 不落盘。
    void *pg = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (pg == MAP_FAILED) {
        return;
    }
    memset(pg, 0, ps);
    const uint64_t span = (uint64_t)(ps - need);
    // o6 按 4 字节指令对齐落在页面前 3/4 区域，给 0 参数模板留出空间且两者不重叠。
    const uintptr_t o6 = (uintptr_t)((r % (span / 4u)) * 4u);
    // o0 紧跟 6 参数模板，并用种子高位再做 4 字节粒度微调；越界则退回紧邻布局并二次检查。
    uintptr_t o0 = o6 + CPRISK_SVC_STUB_SNAPSHOT_BYTES + 8u + ((r >> 40) & 15u) * 4u;
    if (o0 + CPRISK_SVC0_STUB_SNAPSHOT_BYTES > ps) {
        o0 = o6 + CPRISK_SVC_STUB_SNAPSHOT_BYTES + 8u;
    }
    if (o0 + CPRISK_SVC0_STUB_SNAPSHOT_BYTES > ps) {
        munmap(pg, ps);
        return;
    }
    // 只复制模板开头的固定字节数（含 svc 指令）；模板必须自包含，不能依赖后续重定位。
    memcpy((uint8_t *)pg + o6, (const void *)&cprisk_direct_syscall6_template, CPRISK_SVC_STUB_SNAPSHOT_BYTES);
    memcpy((uint8_t *)pg + o0, (const void *)&cprisk_direct_syscall0_template, CPRISK_SVC0_STUB_SNAPSHOT_BYTES);
    {
        // 记录重定位后正文的 SHA-256，后续完整性校验用它发现字节级替换（FNV 只做粗筛）。
        cprisk_sha256_ctx ctx6;
        cprisk_sha256_init(&ctx6);
        cprisk_sha256_update(&ctx6, (const uint8_t *)pg + o6, CPRISK_SVC_STUB_SNAPSHOT_BYTES);
        cprisk_sha256_final(&ctx6, s_svc6_reloc_body_sha256);
        cprisk_sha256_ctx ctx0;
        cprisk_sha256_init(&ctx0);
        cprisk_sha256_update(&ctx0, (const uint8_t *)pg + o0, CPRISK_SVC0_STUB_SNAPSHOT_BYTES);
        cprisk_sha256_final(&ctx0, s_svc0_reloc_body_sha256);
    }
    // 页刚被写入，必须对每段模板分别失效 I-cache，否则 CPU 可能执行到旧数据或半写状态。
    cprisk_flush_instruction_cache((uint8_t *)pg + o6, CPRISK_SVC_STUB_SNAPSHOT_BYTES);
    cprisk_flush_instruction_cache((uint8_t *)pg + o0, CPRISK_SVC0_STUB_SNAPSHOT_BYTES);

    int mperr = 0;
    // 收紧为 R+X 且不可再写：既是 W^X 不变量，也是 leaf 校验能通过的前提。
    if (cprisk_mprotect_direct(pg, ps, PROT_READ | PROT_EXEC, &mperr) != 0) {
        munmap(pg, ps);
        return;
    }

    typedef long (*t0)(long);
    // 自检：用重定位后的 0 参数模板真发一次 getpid。地址、指令缓存、mprotect 任一环出错
    // 都会在这里暴露，此时宁可放弃重定位也不能让直调走上有问题的副本。
    t0 test0 = (t0)((uint8_t *)pg + o0);
    const pid_t tp = (pid_t)test0(SYS_getpid);
    if (tp != (pid_t)getpid()) {
        munmap(pg, ps);
        return;
    }

    // 整页 FNV 折叠 + 两个偏移 + 固定盐，作为“页布局未变”的快速基准；
    // 盐同时充当版本标识，改动会使既有基准全部失效。
    uint64_t h = cprisk_fnv1a64_fold_i(pg, ps);
    h ^= (uint64_t)o6 << 48;
    h ^= (uint64_t)o0 << 32;
    h ^= 0x8E61F7A91D3C5B09ULL;

    const uint8_t *p6 = (const uint8_t *)pg + o6;
    const uint8_t *p0 = (const uint8_t *)pg + o0;
    // 滚动基准：先全量哈希 6 参数模板，再从 1/4 处重叠哈希剩余部分，最后并入 0 参数模板；
    // 不同起点让“整体平移/部分覆盖”也能产生差异。
    uint64_t roll = cprisk_fnv1a64_fold_i(p6, CPRISK_SVC_STUB_SNAPSHOT_BYTES);
    roll ^= cprisk_fnv1a64_fold_i(p6 + CPRISK_SVC_STUB_SNAPSHOT_BYTES / 4u,
                                  CPRISK_SVC_STUB_SNAPSHOT_BYTES - CPRISK_SVC_STUB_SNAPSHOT_BYTES / 4u);
    roll ^= cprisk_fnv1a64_fold_i(p0, CPRISK_SVC0_STUB_SNAPSHOT_BYTES) << 1u;

    // 所有全局基准就绪后才置 ready 并切换 active 指针；顺序不可调换，
    // 否则并发校验可能看到半初始化状态而误报。
    s_svc_rx_page = pg;
    s_svc_rx_page_size = ps;
    s_svc6_rx_offset = o6;
    s_svc0_rx_offset = o0;
    s_svc_rx_page_hash_ref = h;
    s_svc_rx_stub_roll_ref = roll;
    s_svc6_active = (cprisk_svc6_fn_t)((uint8_t *)pg + o6);
    s_svc0_active = (cprisk_svc0_fn_t)((uint8_t *)pg + o0);
    s_svc_reloc_ready = 1;
}
#endif

#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
// 热路径跳板：一次函数指针转发，让构造函数能把目标从 __TEXT 模板换成 RX 副本，
// 而所有调用点无需感知地址变化。active 指针在初始化后不再写入，读取无需同步。
static long cprisk_direct_syscall6(
    long syscall_number,
    long arg0,
    long arg1,
    long arg2,
    long arg3,
    long arg4,
    long arg5,
    int *error_out
) {
    return s_svc6_active(
        syscall_number,
        arg0,
        arg1,
        arg2,
        arg3,
        arg4,
        arg5,
        error_out);
}

// 0 参数跳板：同 6 参数版本，仅转发到可切换的 active 指针。
static long cprisk_direct_syscall0(long syscall_number) {
    return s_svc0_active(syscall_number);
}
#endif

// 做什么：按名字读写 sysctl，直调 SYS_sysctlbyname。
// 参数与所有权：name 为 NUL 结尾字符串；oldp/oldlenp/newp/newlen 语义同 sysctlbyname(3)；
//   error_out 可为 NULL。返回值：成功 0；失败 -1 且 *error_out=errno。
// 线程安全：无共享状态，可并发。平台：直调仅 arm64 真机，其它构建走 libc 并置 bit2。
// 失败语义：不自动重试；调用方按 errno 决定降级或视为异常。
int cprisk_sysctlbyname_direct(
    const char *name,
    void *oldp,
    size_t *oldlenp,
    const void *newp,
    size_t newlen,
    int *error_out
) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_sysctlbyname,
        (long)(uintptr_t)name,
        (long)(uintptr_t)oldp,
        (long)(uintptr_t)oldlenp,
        (long)(uintptr_t)newp,
        (long)newlen,
        0,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_SYSCTL);
    return cprisk_finish_errno(sysctlbyname(name, oldp, oldlenp, (void *)newp, newlen), error_out);
#endif
}

// 做什么：按 MIB 数组读写 sysctl，直调 SYS_sysctl；避开 libc sysctl 符号层。
// 参数与所有权：name 指向 namelen 个 int，所有权归调用方；oldp/oldlenp/newp/newlen 同 sysctl(3)。
// 返回值：成功 0；失败 -1 且 *error_out=errno。
// 线程安全：无共享状态，可并发。平台：直调仅 arm64 真机，其它构建走 libc 并置 bit2。
// 失败语义：不自动重试。
int cprisk_sysctl_direct(
    int *name,
    unsigned int namelen,
    void *oldp,
    size_t *oldlenp,
    const void *newp,
    size_t newlen,
    int *error_out
) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_sysctl,
        (long)(uintptr_t)name,
        (long)namelen,
        (long)(uintptr_t)oldp,
        (long)(uintptr_t)oldlenp,
        (long)(uintptr_t)newp,
        (long)newlen,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_SYSCTL);
    return cprisk_finish_errno(sysctl(name, namelen, oldp, oldlenp, (void *)newp, newlen), error_out);
#endif
}

// 做什么：直调 SYS_stat64 取文件元数据；先清零 sb，失败时调用方不会读到栈上残留。
// 参数与所有权：path 为 NUL 结尾字符串；sb 由调用方提供，允许为 NULL。
// 返回值：成功 0；失败 -1 且 *error_out=errno（直调路径下 sb==NULL 会得到 EFAULT）。
// 线程安全：无共享状态，可并发。平台：直调仅 arm64 真机；其它构建走 libc 并置 bit3。
// 失败语义：libc 回退路径在 sb==NULL 时改用 access(F_OK)，只回答“是否存在”，
//   与直调路径的 EFAULT 语义不同，调用方需按自己的 sb 是否为空来解读。
int cprisk_stat_direct(const char *path, struct stat *sb, int *error_out) {
    if (sb != NULL) {
        memset(sb, 0, sizeof(*sb));
    }
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_stat64,
        (long)(uintptr_t)path,
        (long)(uintptr_t)sb,
        0, 0, 0, 0,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_STAT_PATH);
    return cprisk_finish_errno(sb ? stat(path, sb) : access(path, F_OK), error_out);
#endif
}

// 做什么：直调 SYS_lstat64，取不跟随符号链接的元数据；sb 先清零。
// 参数与所有权：path 为 NUL 结尾字符串；sb 允许为 NULL。
// 返回值：成功 0；失败 -1 且 *error_out=errno。
// 线程安全：无共享状态，可并发。平台：直调仅 arm64 真机；其它构建走 libc 并置 bit3。
// 失败语义：同 cprisk_stat_direct——libc 回退在 sb==NULL 时退化为 access(F_OK)。
int cprisk_lstat_direct(const char *path, struct stat *sb, int *error_out) {
    if (sb != NULL) {
        memset(sb, 0, sizeof(*sb));
    }
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_lstat64,
        (long)(uintptr_t)path,
        (long)(uintptr_t)sb,
        0, 0, 0, 0,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_STAT_PATH);
    return cprisk_finish_errno(sb ? lstat(path, sb) : access(path, F_OK), error_out);
#endif
}

// 做什么：直调 SYS_access 做权限/存在性检查。
// 参数与所有权：path 为 NUL 结尾字符串；amode 取 F_OK/R_OK/W_OK/X_OK（可或）。
// 返回值：成功 0；失败 -1 且 *error_out=errno。
// 线程安全：无共享状态，可并发。平台：直调仅 arm64 真机；其它构建走 libc 并置 bit3。
// 失败语义：失败即“不可访问”，调用方不得把 -1 当成路径不存在以外的结论。
int cprisk_access_direct(const char *path, int amode, int *error_out) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_access,
        (long)(uintptr_t)path,
        (long)amode,
        0,
        0,
        0,
        0,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_STAT_PATH);
    return cprisk_finish_errno(access(path, amode), error_out);
#endif
}

// 由 seed 与字节下标派生的 XOR 掩码字节：每 4 字节轮换 seed 的一个字节，
// 再叠加两组与下标有关的常量并做循环移位，使同一路径在不同 seed 下密文不同、
// 相邻字节掩码不重复。纯计算无状态；编码端必须使用完全相同的实现。
static uint8_t cprisk_masked_path_lane_i(uint32_t seed, size_t index) {
    const uint32_t shift = (uint32_t)((index & 3u) * 8u);
    uint8_t lane = (uint8_t)((seed >> shift) & 0xFFu);
    lane ^= (uint8_t)((index * 17u + 0x5Du) & 0xFFu);
    {
        const uint32_t rot = (uint32_t)(index & 7u);
        if (rot != 0u) {
            lane = (uint8_t)((uint8_t)(lane << rot) | (uint8_t)(lane >> (8u - rot)));
        }
    }
    lane ^= (uint8_t)((index * 29u + 0xA7u) & 0xFFu);
    return lane;
}

// 掩码路径的解码缓冲：mapping/mapping_len 非 0 表示匿名映射型，否则是 malloc 的堆缓冲
//（heap_backed=1）。path/path_len 指向实际解码区；release 负责清零并按类型释放。
typedef struct cprisk_masked_path_scratch_i {
    // 匿名映射基址；仅映射型有效，堆型为 NULL。
    void *mapping;
    // 映射总长度（含前后守卫页）；仅映射型有效。
    size_t mapping_len;
    // 解码区起始地址：映射型指向中间页内的随机偏移，堆型指向 malloc 缓冲。
    char *path;
    // 解码区可用长度（等于 masked_len，含结尾 NUL）。
    size_t path_len;
    // 1=堆缓冲（release 用 free），0=匿名映射（release 用 munmap）。
    uint8_t heap_backed;
} cprisk_masked_path_scratch_i;

// 取系统页大小；sysconf 失败时按 4 KiB 兜底，保证 scratch 仍能尝试分配而不是直接失败。
static size_t cprisk_masked_path_page_size_i(void) {
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        return 4096u;
    }
    return (size_t)page_size;
}

// 为解码缓冲选择页内随机偏移：优先 cprisk_getentropy_direct（真机走 SVC，回退 arc4random），
// 失败则退回 mach_absolute_time 与地址/长度混合。非密码学用途——只打散布局，不承担保密职责。
static uint64_t cprisk_masked_path_entropy_i(size_t path_len) {
    uint64_t value = 0u;
    int err = 0;
    if (cprisk_getentropy_direct(&value, sizeof(value), &err) == 0) {
        return value ^ ((uint64_t)path_len * 0x9E3779B97F4A7C15ULL);
    }
    (void)err;
    value = (uint64_t)mach_absolute_time();
    value ^= ((uint64_t)(uintptr_t)&value << 19u);
    value ^= ((uint64_t)path_len << 11u);
    value ^= value >> 7u;
    value ^= value << 13u;
    return value;
}

// 分配解码缓冲：路径不超过一页时映射三页 PROT_NONE，只把中间页设为 RW，并把明文放在
// 页内随机偏移——越界访问会落到守卫页直接崩溃，而不是泄露相邻内存。
// 返回 0=成功；-1=参数非法或分配失败（映射或权限设置失败时退到堆）。
static int cprisk_masked_path_scratch_alloc_i(
    size_t path_len,
    cprisk_masked_path_scratch_i *out_scratch
) {
    if (out_scratch == NULL || path_len == 0u) {
        return -1;
    }
    memset(out_scratch, 0, sizeof(*out_scratch));

    const size_t page_size = cprisk_masked_path_page_size_i();
    if (path_len <= page_size) {
        const size_t mapping_len = page_size * 3u;
        // 前后各一页 PROT_NONE 作为守卫页，使越界读写 fail-fast。
        uint8_t *mapping = (uint8_t *)mmap(
            NULL,
            mapping_len,
            PROT_NONE,
            MAP_PRIVATE | MAP_ANON,
            -1,
            0
        );
        if (mapping != MAP_FAILED) {
            uint8_t *middle = mapping + page_size;
            if (mprotect(middle, page_size, PROT_READ | PROT_WRITE) == 0) {
                const size_t slack = page_size - path_len;
                size_t offset = 0u;
                if (slack > 0u) {
                    // 偏移按 16 字节对齐并限制在 slack 内，保证 path_len 字节完整落在中间页。
                    offset = (size_t)(cprisk_masked_path_entropy_i(path_len) % (uint64_t)(slack + 1u));
                    offset &= ~(size_t)0xFu;
                    if (offset > slack) {
                        offset = slack;
                    }
                }
                // 清零整页：确保路径尾部（含 NUL 之后）不残留上一使用者或映射初值。
                memset(middle, 0, page_size);
                out_scratch->mapping = mapping;
                out_scratch->mapping_len = mapping_len;
                out_scratch->path = (char *)(middle + offset);
                out_scratch->path_len = path_len;
                out_scratch->heap_backed = 0u;
                return 0;
            }
            (void)munmap(mapping, mapping_len);
        }
    }

    // 页映射不可用时退回 malloc；heap_backed 标记决定 release 走 free 还是 munmap。
    char *heap_buf = (char *)malloc(path_len);
    if (heap_buf == NULL) {
        return -1;
    }
    memset(heap_buf, 0, path_len);
    out_scratch->path = heap_buf;
    out_scratch->path_len = path_len;
    out_scratch->heap_backed = 1u;
    return 0;
}

// 释放解码缓冲前先安全清零，避免明文路径残留在堆或匿名页；映射型还要先降权回
// PROT_NONE 再 munmap，缩短可写窗口。scratch 自身也被清零，防止悬垂指针被复用。
static void cprisk_masked_path_scratch_release_i(cprisk_masked_path_scratch_i *scratch) {
    if (scratch == NULL || scratch->path == NULL || scratch->path_len == 0u) {
        return;
    }
    if (scratch->heap_backed != 0u) {
        // 堆缓冲只清零实际长度。
        cprisk_secure_zero(scratch->path, scratch->path_len);
        free(scratch->path);
    } else if (scratch->mapping != NULL && scratch->mapping_len != 0u) {
        const size_t page_size = cprisk_masked_path_page_size_i();
        uint8_t *middle = (uint8_t *)scratch->mapping + page_size;
        // 映射型清零整页：解码区可能只占中间页的一部分。
        cprisk_secure_zero(middle, page_size);
        (void)mprotect(middle, page_size, PROT_NONE);
        (void)munmap(scratch->mapping, scratch->mapping_len);
    }
    memset(scratch, 0, sizeof(*scratch));
}

// 用与编码端一致的 lane 掩码逐字节还原路径，并强制最后一个字节为 NUL。
// 返回 0=成功；-1=参数非法/超长/缺少结尾 NUL（失败时已清零输出，防止半解码明文被误用）。
// 参数与所有权：path_buf 由调用方提供且容量 >= masked_len；函数不分配内存。
static int cprisk_decode_masked_path_i(
    const uint8_t *masked_path,
    size_t masked_len,
    uint32_t seed,
    char *path_buf,
    size_t path_buf_len
) {
    if (masked_path == NULL || masked_len == 0u || masked_len > (size_t)PATH_MAX ||
        path_buf == NULL || path_buf_len < masked_len) {
        return -1;
    }
    for (size_t i = 0u; i < masked_len; i++) {
        path_buf[i] = (char)(masked_path[i] ^ cprisk_masked_path_lane_i(seed, i));
    }
    // 掩码数据含结尾 NUL；解码后不是 NUL 说明 seed/长度不匹配或数据被改动，按失败处理。
    if (path_buf[masked_len - 1u] != '\0') {
        cprisk_secure_zero(path_buf, path_buf_len);
        return -1;
    }
    return 0;
}

// 解码后的统一回调签名：path 指向临时明文缓冲（仅本次调用内有效），ctx 由各包装传入，
// error_out 语义与底层 direct 包装一致；返回 0/-1（探针类可返回其它值）。
typedef int (*cprisk_masked_path_call_i)(const char *path, void *ctx, int *error_out);

// access 回调上下文：携带 amode（F_OK/R_OK/W_OK/X_OK）。
typedef struct cprisk_masked_access_ctx_i {
    // access(2) 的权限模式。
    int amode;
} cprisk_masked_access_ctx_i;

// stat/lstat 回调上下文：携带调用方提供的输出结构；为 NULL 时底层按“仅探测存在”处理。
typedef struct cprisk_masked_stat_ctx_i {
    // 输出结构；NULL 表示只关心存在性。
    struct stat *sb;
} cprisk_masked_stat_ctx_i;

// stat 回调适配：把 ctx 转回 struct stat*，其余语义原样转发。
static int cprisk_masked_call_stat_i(const char *path, void *ctx, int *error_out) {
    cprisk_masked_stat_ctx_i *stat_ctx = (cprisk_masked_stat_ctx_i *)ctx;
    return cprisk_stat_direct(path, stat_ctx ? stat_ctx->sb : NULL, error_out);
}

// lstat 回调适配：不跟随符号链接。
static int cprisk_masked_call_lstat_i(const char *path, void *ctx, int *error_out) {
    cprisk_masked_stat_ctx_i *stat_ctx = (cprisk_masked_stat_ctx_i *)ctx;
    return cprisk_lstat_direct(path, stat_ctx ? stat_ctx->sb : NULL, error_out);
}

// access 回调适配：ctx 为空时按 F_OK 处理（只判存在）。
static int cprisk_masked_call_access_i(const char *path, void *ctx, int *error_out) {
    cprisk_masked_access_ctx_i *access_ctx = (cprisk_masked_access_ctx_i *)ctx;
    const int amode = access_ctx ? access_ctx->amode : F_OK;
    return cprisk_access_direct(path, amode, error_out);
}

// 强制 libc 的 access 适配：用于与直调路径做对照。这是显式选择，不置回退位。
static int cprisk_masked_call_access_libc_i(const char *path, void *ctx, int *error_out) {
    cprisk_masked_access_ctx_i *access_ctx = (cprisk_masked_access_ctx_i *)ctx;
    const int amode = access_ctx ? access_ctx->amode : F_OK;
    return cprisk_finish_errno(access(path, amode), error_out);
}

// open(O_RDONLY) 探针：能打开即视为存在，随后立即关闭；只关心存在性，不读内容。
static int cprisk_masked_call_open_exists_i(const char *path, void *ctx, int *error_out) {
    (void)ctx;
    int fd = cprisk_open_direct(path, O_RDONLY, error_out);
    if (fd < 0) {
        return -1;
    }
    (void)cprisk_close_direct(fd, NULL);
    return 0;
}

// 掩码路径调用骨架：校验参数 → 分配临时明文缓冲 → 解码 → 调回调 → 无论成败都清零释放。
// 返回回调的返回值；参数非法 -1/EINVAL，分配失败 -1/ENOMEM，解码失败 -1/EINVAL。
// 线程安全：全部状态在栈上，可并发调用。
static int cprisk_with_decoded_masked_path_i(
    const uint8_t *masked_path,
    size_t masked_len,
    uint32_t seed,
    cprisk_masked_path_call_i call_fn,
    void *ctx,
    int *error_out
) {
    if (call_fn == NULL || masked_path == NULL || masked_len == 0u ||
        masked_len > (size_t)PATH_MAX) {
        if (error_out != NULL) {
            *error_out = EINVAL;
        }
        return -1;
    }

    cprisk_masked_path_scratch_i scratch;
    if (cprisk_masked_path_scratch_alloc_i(masked_len, &scratch) != 0) {
        if (error_out != NULL) {
            *error_out = ENOMEM;
        }
        return -1;
    }
    if (cprisk_decode_masked_path_i(masked_path, masked_len, seed, scratch.path, scratch.path_len) != 0) {
        if (error_out != NULL) {
            *error_out = EINVAL;
        }
        cprisk_masked_path_scratch_release_i(&scratch);
        return -1;
    }

    // 回调必须同步完成：path 指针只在 scratch 释放前有效，不得被保存。
    const int rc = call_fn(scratch.path, ctx, error_out);
    cprisk_masked_path_scratch_release_i(&scratch);
    return rc;
}

// 标准探测回调：依次用 access(F_OK)、stat、open(O_RDONLY) 探测同一路径。
// available_mask 固定为这三种（每次都会尝试），exists_mask 只置成功位；
// 单项失败不影响其它项，整体恒返回 0（除非参数为空）。
static int cprisk_masked_call_probe_standard_snapshot_i(const char *path, void *ctx, int *error_out) {
    cprisk_path_probe_snapshot_t *snapshot = (cprisk_path_probe_snapshot_t *)ctx;
    if (snapshot == NULL || path == NULL) {
        if (error_out != NULL) {
            *error_out = EINVAL;
        }
        return -1;
    }

    snapshot->available_mask =
        CPRISK_PATH_PROBE_ACCESS | CPRISK_PATH_PROBE_STAT | CPRISK_PATH_PROBE_FOPEN;
    snapshot->exists_mask = 0u;

    if (cprisk_access_direct(path, F_OK, NULL) == 0) {
        snapshot->exists_mask |= CPRISK_PATH_PROBE_ACCESS;
    }

    struct stat sb;
    memset(&sb, 0, sizeof(sb));
    if (cprisk_stat_direct(path, &sb, NULL) == 0) {
        snapshot->exists_mask |= CPRISK_PATH_PROBE_STAT;
    }

    int open_errno = 0;
    int fd = cprisk_open_direct(path, O_RDONLY, &open_errno);
    if (fd >= 0) {
        snapshot->exists_mask |= CPRISK_PATH_PROBE_FOPEN;
        (void)cprisk_close_direct(fd, NULL);
    }
    if (error_out != NULL) {
        *error_out = 0;
    }
    return 0;
}

// secure 探测回调：access + stat + lstat，额外覆盖“不跟随符号链接”的视图，
// 用于识别符号链接伪造。语义同标准回调：逐项探测、位图汇报、整体返回 0。
static int cprisk_masked_call_probe_secure_snapshot_i(const char *path, void *ctx, int *error_out) {
    cprisk_path_probe_snapshot_t *snapshot = (cprisk_path_probe_snapshot_t *)ctx;
    if (snapshot == NULL || path == NULL) {
        if (error_out != NULL) {
            *error_out = EINVAL;
        }
        return -1;
    }

    snapshot->available_mask =
        CPRISK_PATH_PROBE_ACCESS | CPRISK_PATH_PROBE_STAT | CPRISK_PATH_PROBE_LSTAT;
    snapshot->exists_mask = 0u;

    if (cprisk_access_direct(path, F_OK, NULL) == 0) {
        snapshot->exists_mask |= CPRISK_PATH_PROBE_ACCESS;
    }

    struct stat sb;
    memset(&sb, 0, sizeof(sb));
    if (cprisk_stat_direct(path, &sb, NULL) == 0) {
        snapshot->exists_mask |= CPRISK_PATH_PROBE_STAT;
    }

    memset(&sb, 0, sizeof(sb));
    if (cprisk_lstat_direct(path, &sb, NULL) == 0) {
        snapshot->exists_mask |= CPRISK_PATH_PROBE_LSTAT;
    }
    if (error_out != NULL) {
        *error_out = 0;
    }
    return 0;
}

// 做什么：解码掩码路径后直调 stat，路径明文不在调用方栈上长期停留。
// 参数与所有权：masked_path/masked_len（含 NUL）/seed 由调用方给出；sb 可为 NULL；
//   error_out 可为 NULL。返回值：成功 0；失败 -1 且 *error_out=errno 或 EINVAL/ENOMEM。
// 线程安全：栈上 scratch + 只读输入，可并发。平台：直调仅 arm64 真机，其它构建走 libc 并置 bit3。
// 失败语义：解码失败视为参数/数据异常，不重试。
int cprisk_stat_masked(
    const uint8_t *masked_path,
    size_t masked_len,
    uint32_t seed,
    struct stat *sb,
    int *error_out
) {
    cprisk_masked_stat_ctx_i stat_ctx = {.sb = sb};
    return cprisk_with_decoded_masked_path_i(
        masked_path, masked_len, seed, cprisk_masked_call_stat_i, &stat_ctx, error_out);
}

// 做什么：同 cprisk_stat_masked，但直调 lstat（不跟随符号链接）。
// 参数与所有权：同上。返回值：成功 0；失败 -1 且 *error_out=errno/EINVAL/ENOMEM。
// 线程安全：可并发。平台：直调仅 arm64 真机，其它构建走 libc 并置 bit3。
// 失败语义：解码失败不重试。
int cprisk_lstat_masked(
    const uint8_t *masked_path,
    size_t masked_len,
    uint32_t seed,
    struct stat *sb,
    int *error_out
) {
    cprisk_masked_stat_ctx_i stat_ctx = {.sb = sb};
    return cprisk_with_decoded_masked_path_i(
        masked_path, masked_len, seed, cprisk_masked_call_lstat_i, &stat_ctx, error_out);
}

// 做什么：解码掩码路径后直调 access 检查权限。
// 参数与所有权：masked_path/masked_len/seed/amode（F_OK/R_OK/W_OK/X_OK）由调用方给出；
//   error_out 可为 NULL。返回值：成功 0；失败 -1 且 *error_out=errno/EINVAL/ENOMEM。
// 线程安全：可并发。平台：直调仅 arm64 真机，其它构建走 libc 并置 bit3。
// 失败语义：与 access(2) 一致，-1 只表示“当前不可访问”。
int cprisk_access_masked(
    const uint8_t *masked_path,
    size_t masked_len,
    uint32_t seed,
    int amode,
    int *error_out
) {
    cprisk_masked_access_ctx_i access_ctx = {.amode = amode};
    return cprisk_with_decoded_masked_path_i(
        masked_path, masked_len, seed, cprisk_masked_call_access_i, &access_ctx, error_out);
}

// 做什么：与 cprisk_access_masked 相同的解码与参数契约，但强制走 libc access，
//   用作直调路径的对照组（显式对照，不置回退位）。
// 参数与所有权：同 cprisk_access_masked。返回值：成功 0；失败 -1 且 *error_out=errno/EINVAL/ENOMEM。
// 线程安全：可并发。平台：全平台。失败语义：fail-open，结果需与直调路径一起解读。
int cprisk_access_masked_libc(
    const uint8_t *masked_path,
    size_t masked_len,
    uint32_t seed,
    int amode,
    int *error_out
) {
    cprisk_masked_access_ctx_i access_ctx = {.amode = amode};
    return cprisk_with_decoded_masked_path_i(
        masked_path, masked_len, seed, cprisk_masked_call_access_libc_i, &access_ctx, error_out);
}

// 做什么：用 access/stat/open 三种方式探测明文路径是否存在，供越狱/调试工具路径识别。
// 参数与所有权：path 必须非 NULL；out_snapshot 由调用方提供并被覆盖写入。
// 返回值：成功 0；path 或 out_snapshot 为 NULL 时 -1。
// 线程安全：无共享状态，可并发。平台：全平台；底层直调在非 arm64 回退 libc。
// 失败语义：单个探测失败只清对应 exists 位，不影响整体返回 0；相对路径按进程 cwd 解析。
int cprisk_probe_path_snapshot(const char *path, cprisk_path_probe_snapshot_t *out_snapshot) {
    if (path == NULL || out_snapshot == NULL) {
        return -1;
    }

    out_snapshot->available_mask = CPRISK_PATH_PROBE_ACCESS | CPRISK_PATH_PROBE_STAT | CPRISK_PATH_PROBE_FOPEN;
    out_snapshot->exists_mask = 0;

    if (cprisk_access_direct(path, F_OK, NULL) == 0) {
        out_snapshot->exists_mask |= CPRISK_PATH_PROBE_ACCESS;
    }

    struct stat sb;
    memset(&sb, 0, sizeof(sb));
    if (cprisk_stat_direct(path, &sb, NULL) == 0) {
        out_snapshot->exists_mask |= CPRISK_PATH_PROBE_STAT;
    }

    int open_errno = 0;
    int fd = cprisk_open_direct(path, O_RDONLY, &open_errno);
    if (fd >= 0) {
        out_snapshot->exists_mask |= CPRISK_PATH_PROBE_FOPEN;
        (void)cprisk_close_direct(fd, NULL);
    }

    return 0;
}

// 做什么：同 cprisk_probe_path_snapshot，但路径以 XOR 掩码传入并在进程内解码。
// 参数与所有权：masked_path/masked_len/seed 同 cprisk_stat_masked；out_snapshot 由调用方提供。
// 返回值：成功 0；参数非法 -1；解码/分配失败 -1（内部 error_out 传 NULL，不暴露 errno）。
// 线程安全：可并发。平台：直调仅 arm64 真机，其它构建走 libc。
// 失败语义：同明文版本，单探测失败只影响对应位。
int cprisk_probe_path_snapshot_masked(
    const uint8_t *masked_path,
    size_t masked_len,
    uint32_t seed,
    cprisk_path_probe_snapshot_t *out_snapshot
) {
    if (masked_path == NULL || out_snapshot == NULL) {
        return -1;
    }

    return cprisk_with_decoded_masked_path_i(
        masked_path,
        masked_len,
        seed,
        cprisk_masked_call_probe_standard_snapshot_i,
        out_snapshot,
        NULL
    );
}

// 做什么：掩码版安全探测：access + stat + lstat，额外覆盖符号链接视图。
// 参数与所有权：同 cprisk_probe_path_snapshot_masked。返回值：成功 0；参数/解码失败 -1。
// 线程安全：可并发。平台：直调仅 arm64 真机，其它构建走 libc。
// 失败语义：单项失败只影响 exists 位。
int cprisk_probe_secure_path_snapshot_masked(
    const uint8_t *masked_path,
    size_t masked_len,
    uint32_t seed,
    cprisk_path_probe_snapshot_t *out_snapshot
) {
    if (masked_path == NULL || out_snapshot == NULL) {
        return -1;
    }

    return cprisk_with_decoded_masked_path_i(
        masked_path,
        masked_len,
        seed,
        cprisk_masked_call_probe_secure_snapshot_i,
        out_snapshot,
        NULL
    );
}

/* ── getpid / getppid / getuid ─────────────────────────────────────── */

// 做什么：直调 SYS_getpid，用于与 libc 结果交叉校验（libc 被 hook 时两者会分歧）。
// 参数与所有权：无参数。返回值：pid；返回 -1 视为异常（getpid 正常不会失败）。
// 线程安全：可并发。平台：直调仅 arm64 真机，其它构建走 libc 并置 bit5。
// 失败语义：无 error_out；调用方用 errno 探针/交叉校验位判断异常。
pid_t cprisk_getpid_direct(void) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (pid_t)cprisk_direct_syscall0(SYS_getpid);
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_IDS);
    return getpid();
#endif
}

// 做什么：直调 SYS_getppid，用于父进程识别与 libc 交叉校验。
// 参数与所有权：无参数。返回值：ppid；-1 视为异常。线程安全：可并发。
// 平台：直调仅 arm64 真机，其它构建走 libc 并置 bit5。失败语义：同 getpid。
pid_t cprisk_getppid_direct(void) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (pid_t)cprisk_direct_syscall0(SYS_getppid);
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_IDS);
    return getppid();
#endif
}

// 做什么：直调 SYS_getuid，判定进程是否以 root 运行；与 libc 结果交叉校验。
// 参数与所有权：无参数。返回值：uid（0=root）；-1 视为异常。线程安全：可并发。
// 平台：直调仅 arm64 真机，其它构建走 libc 并置 bit5。失败语义：同 getpid。
uid_t cprisk_getuid_direct(void) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (uid_t)cprisk_direct_syscall0(SYS_getuid);
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_IDS);
    return getuid();
#endif
}

/* ── open / close / read ───────────────────────────────────────────── */

// 做什么：直调 SYS_open 打开已有路径（不含创建模式语义）。
// 参数与所有权：path 为 NUL 结尾字符串；flags 同 open(2)；error_out 可为 NULL。
// 返回值：成功 fd>=0；失败 -1 且 *error_out=errno。
// 线程安全：可并发（fd 归调用方所有，需自行 close）。
// 平台：直调仅 arm64 真机，其它构建走 libc 并置 bit4。
// 不变量：第三参数固定传 0，因此不要传 O_CREAT/O_TMPFILE 等需要 mode 的标志。
int cprisk_open_direct(const char *path, int flags, int *error_out) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_open,
        (long)(uintptr_t)path,
        (long)flags,
        0,
        0,
        0,
        0,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_FD_IO);
    int fd = open(path, flags);
    if (error_out != NULL) {
        *error_out = (fd >= 0) ? 0 : errno;
    }
    return fd;
#endif
}

// 做什么：直调 SYS_close 关闭 fd。
// 参数与所有权：fd 由调用方提供，调用后不再有效；error_out 可为 NULL。
// 返回值：成功 0；失败 -1 且 *error_out=errno（EINTR 时 fd 状态不确定，不得盲目重试）。
// 线程安全：可并发，但同一 fd 的并发 close 无定义。平台：直调仅 arm64 真机，其它构建走 libc 并置 bit4。
// 失败语义：失败不自动重试。
int cprisk_close_direct(int fd, int *error_out) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_close,
        (long)fd,
        0,
        0,
        0,
        0,
        0,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_FD_IO);
    return cprisk_finish_errno(close(fd), error_out);
#endif
}

// 做什么：直调 SYS_read 从 fd 读取至多 nbyte 字节。
// 参数与所有权：buf 由调用方提供且至少 nbyte 字节；error_out 可为 NULL。
// 返回值：实际读取字节数（0=EOF）；失败 -1 且 *error_out=errno。
// 线程安全：可并发（不同 fd）；同一 fd 的并发读取顺序由内核串行化。
// 平台：直调仅 arm64 真机，其它构建走 libc 并置 bit4。
// 失败语义：EINTR 需由调用方决定是否重试。
ssize_t cprisk_read_direct(int fd, void *buf, size_t nbyte, int *error_out) {
    if (nbyte > (size_t)SSIZE_MAX) {
        // 先把超长请求挡在用户态：内核上限更小，交给它只会得到含糊的失败；
        // 这里明确返回 EINVAL，也避免后续按 ssize_t 解读时出现负数歧义。
        if (error_out != NULL)
            *error_out = EINVAL;
        return -1;
    }
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (ssize_t)cprisk_direct_syscall6(
        SYS_read,
        (long)fd,
        (long)(uintptr_t)buf,
        (long)nbyte,
        0,
        0,
        0,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_FD_IO);
    ssize_t n = read(fd, buf, nbyte);
    if (error_out != NULL) {
        *error_out = (n >= 0) ? 0 : errno;
    }
    return n;
#endif
}

/* ── socket / connect ──────────────────────────────────────────────── */

// 做什么：直调 SYS_socket 创建套接字。
// 参数与所有权：domain/type/protocol 同 socket(2)；error_out 可为 NULL。
// 返回值：成功 fd>=0；失败 -1 且 *error_out=errno。线程安全：可并发。
// 平台：直调仅 arm64 真机，其它构建走 libc 并置 bit4。失败语义：失败不重试。
int cprisk_socket_direct(int domain, int type, int protocol, int *error_out) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_socket,
        (long)domain,
        (long)type,
        (long)protocol,
        0,
        0,
        0,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_FD_IO);
    int fd = socket(domain, type, protocol);
    if (error_out != NULL) {
        *error_out = (fd >= 0) ? 0 : errno;
    }
    return fd;
#endif
}

// 做什么：直调 SYS_connect 连接套接字。
// 参数与所有权：addr/addrlen 同 connect(2)，所有权归调用方；error_out 可为 NULL。
// 返回值：成功 0；失败 -1 且 *error_out=errno（非阻塞 socket 的 EINPROGRESS 属正常流程）。
// 线程安全：可并发（不同 fd）。平台：直调仅 arm64 真机，其它构建走 libc 并置 bit4。
// 失败语义：失败不自动重试。
int cprisk_connect_direct(int sockfd, const struct sockaddr *addr, socklen_t addrlen, int *error_out) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_connect,
        (long)sockfd,
        (long)(uintptr_t)addr,
        (long)addrlen,
        0,
        0,
        0,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_FD_IO);
    return cprisk_finish_errno(connect(sockfd, addr, addrlen), error_out);
#endif
}

/* ── mprotect ──────────────────────────────────────────────────────── */

// 旧 SDK 可能缺这些常量；这里写死的是 Darwin arm64 的 trap 号，
// 改错会直接把请求打到另一个系统调用上（且不会在编译期报错）。
#ifndef SYS_mprotect
#if defined(__APPLE__)
#define SYS_mprotect 74
#else
#error "SYS_mprotect not defined for this platform"
#endif
#endif

// 做什么：直调 SYS_mprotect 修改页保护，规避 libc mprotect 层 Hook。
// 参数与所有权：addr/len/prot 语义同 mprotect(2)；不接管内存所有权。
// 返回值：成功 0；失败 -1 且 *error_out=errno。
// 线程安全：可并发，但并发修改同一区间需调用方自行同步。
// 平台：直调仅 arm64 真机，其它构建走 libc mprotect 并置 bit0。
// 失败语义：fail-closed——-1 表示保护未改变，调用方不得假设已生效。
int cprisk_mprotect_direct(void *addr, size_t len, int prot, int *error_out) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_mprotect,
        (long)(uintptr_t)addr,
        (long)len,
        (long)prot,
        0,
        0,
        0,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_MPROTECT);
    return cprisk_finish_errno(mprotect(addr, len, prot), error_out);
#endif
}

/* ── getentropy ────────────────────────────────────────────────────── */

// getentropy 的 Darwin arm64 trap 号；与内核 ABI 绑定，不能换成别的随机源编号。
#ifndef SYS_getentropy
#if defined(__APPLE__)
#define SYS_getentropy 500   /* Darwin arm64 getentropy trap number */
#else
#error "SYS_getentropy not defined for this platform"
#endif
#endif

// 做什么：直调 SYS_getentropy 取密码学随机数，绕开可能被 hook 的 arc4random。
// 参数与所有权：buf 由调用方提供且至少 buflen 字节；error_out 可为 NULL。
// 返回值：成功 0；失败 -1 且 *error_out=EINVAL 或 errno。
// 线程安全：可并发。平台：直调仅 arm64 真机；其它构建用 arc4random_buf 并置 bit1。
// 失败语义：失败不自动降级到 ARC4（直调路径），调用方需自行处理。
int cprisk_getentropy_direct(void *buf, size_t buflen, int *error_out) {
    if (buflen > 256) {
        // getentropy(2) 单次上限 256 字节；超过直接 EINVAL，避免内核截断或未定义行为。
        if (error_out != NULL) {
            *error_out = EINVAL;
        }
        return -1;
    }
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_getentropy,
        (long)(uintptr_t)buf,
        (long)buflen,
        0,
        0,
        0,
        0,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_GETENTROPY);
    arc4random_buf(buf, buflen);
    if (error_out != NULL) {
        *error_out = 0;
    }
    return 0;
#endif
}

/* ── csops (code signing) ───────────────────────────────────────────── */

// csops 的 Darwin arm64 trap 号；csops 没有公开 libc 符号，因此只能靠直调。
#ifndef SYS_csops
#if defined(__APPLE__)
#define SYS_csops 169
#else
#error "SYS_csops not defined for this platform"
#endif
#endif

// 做什么：直调 SYS_csops 读取/操作自己的代码签名状态（如 CS_OPS_STATUS）。
// 参数与所有权：pid/ops/useraddr/usersize 语义同 csops(2)；useraddr 由调用方提供。
// 返回值：成功 0；失败 -1 且 *error_out=errno。
// 线程安全：可并发。平台：仅 arm64 真机构建可用；其它构建不降级（无公开 libc 等价物），
//   返回 -1、*error_out=ENOTSUP 并置 bit8。
// 失败语义：ENOTSUP 表示“本平台没有此能力”，调用方不应据此判定篡改。
int cprisk_csops_direct(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, int *error_out) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_csops,
        (long)pid,
        (long)ops,
        (long)(uintptr_t)useraddr,
        (long)usersize,
        0,
        0,
        error_out
    );
#else
    (void)pid;
    (void)ops;
    (void)useraddr;
    (void)usersize;
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_CSOPS_UNAVAILABLE);
    if (error_out != NULL) {
        *error_out = ENOTSUP;
    }
    return -1;
#endif
}

/* ── SVC stub integrity (FNV-1a chunk hashes + rolling verify + SVC scan) ─
 * NOTE (issue 46): the FNV-1a chunk hash below is ACCIDENTAL-CHANGE
 * detection only — FNV is not collision-resistant and not keyed, so it
 * does NOT prove the stub was not deliberately tampered with. Real
 * tamper evidence in this same verify path comes from the SHA-256 page
 * masks (cprisk_svc_stub_sha256_aux_mask_i / deny-attach SHA-256 page
 * mask). Migration path: replace the rolling FNV compare with a
 * CPRisk-MAC (or SHA-256) over (chunk || stub address) and compare
 * against a producer-signed snapshot. */

// deny-attach stub 的完整性来源由 anti_debug.c 维护（位图 / 页摘要 / 摘要导出）；
// 本文件只做聚合，避免反向依赖其实现细节。
extern uint32_t cprisk_deny_attach_stub_integrity_mask(void);
extern uint32_t cprisk_deny_attach_stub_sha256_page_mask(void);
extern void cprisk_deny_attach_stub_page_sha256_digest(uint8_t out_digest[32]);

// 做什么：对 16 字节 stub 块做 FNV-1a(64)，再把 stub 所在的 4 KiB 页基址折入，
//   使“换到另一页但内容相同”的替换也能被发现。
// 参数与所有权：chunk16 必须非 NULL 且可读 16 字节；stub_fn_addr 仅用于取页基址。
// 返回值：哈希值；chunk16 为 NULL 返回 0（调用方应视为不匹配）。
// 线程安全：纯计算，可并发。
// 安全边界：FNV 非抗碰撞、非密钥化，只能发现意外改动；篡改证据由 SHA-256 路径提供。
uint64_t cprisk_svc_stub_chunk_hash_fnv16(const uint8_t *chunk16, uintptr_t stub_fn_addr) {
    const uint64_t fnv_offset = 14695981039346656037ULL;
    const uint64_t fnv_prime = 1099511628211ULL;
    uint64_t h = fnv_offset;
    if (!chunk16) {
        return 0u;
    }
    for (size_t i = 0; i < CPRISK_SVC_STUB_CHUNK_BYTES; i++) {
        h ^= (uint64_t)chunk16[i];
        h *= fnv_prime;
    }
    // 折入页基址而非完整地址：同页内的重新链接不应改变结果，整段搬到别页则会失配。
    const uintptr_t page = stub_fn_addr & ~CPRISK_STUB_PAGE_MASK;
    h ^= (uint64_t)page;
    h *= fnv_prime;
    return h;
}

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
// 判断 A64 指令字是否属于 svc #imm16 家族：高字节固定 0xd4，低 5 位固定 0x1。
// 只做粗判（不校验 imm16 具体值），用于确认模板里仍保留着 SVC 指令。
static inline int cprisk_arm64_word_is_svc_i(uint32_t w) {
    /* A64 `svc #imm` family: top byte 0xd4, low 5 bits 0x1 (imm16 embedded). */
    return ((w & 0xff000000u) == 0xd4000000u) && ((w & 0x1fu) == 0x1u);
}

// 做什么：扫描 [fn, fn+len) 是否含 svc 指令字，按 4 字节步进并用 memcpy 读取以避免未对齐访问。
// 参数与所有权：fn 由调用方提供，只读；len<4 或 fn==NULL 视为不含。
// 返回值：1=含 svc；0=不含/参数非法。
// 线程安全：只读内存。平台：仅 Apple arm64 实际扫描。
int cprisk_stub_contains_svc_opcode(const void *fn, size_t len) {
    if (!fn || len < 4u) {
        return 0;
    }
    const uint8_t *p = (const uint8_t *)fn;
    const size_t n = len / 4u;
    for (size_t i = 0; i < n; i++) {
        uint32_t w;
        memcpy(&w, p + i * 4u, sizeof(w));
        if (cprisk_arm64_word_is_svc_i(w)) {
            return 1;
        }
    }
    return 0;
}
#else
int cprisk_stub_contains_svc_opcode(const void *fn, size_t len) {
    (void)fn;
    (void)len;
    // 非 arm64 没有 SVC 语义，返回 1 表示“不做判断”，避免把构建差异当成篡改。
    return 1;
}
#endif

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
// 期望分块哈希与轮询计数：快照在构造函数(8) 抓取，之后每次校验按 tick 轮转——
// 每 4 次做一次全量（3/2 块）比对，其余只比一块，既摊薄开销又保证每一块最终都会被检查。
// text_ready 保证构造函数完成前校验直接返回 0，不产生误报。
static uint64_t s_cprisk_syscall6_chunk_expected[CPRISK_SVC_STUB6_CHUNKS];
static volatile int s_cprisk_syscall6_text_ready = 0;
static atomic_uint_fast32_t s_cprisk_syscall6_stub_tick;

static uint64_t s_cprisk_syscall0_chunk_expected[CPRISK_SVC_STUB0_CHUNKS];
static volatile int s_cprisk_syscall0_text_ready = 0;
static atomic_uint_fast32_t s_cprisk_syscall0_stub_tick;

// 滚动分块校验：原子 tick 自增后按模决定本次是全量还是单块。
// 返回 1=匹配；0=不匹配。原子 tick 保证并发调用不会总落在同一块上。
static int cprisk_svc_stub_chunks_match_rolling_i(
    const uint8_t *live,
    uintptr_t stub_addr,
    uint32_t nchunks,
    const uint64_t *expected,
    atomic_uint_fast32_t *tick_atom
) {
    const uint32_t t = atomic_fetch_add_explicit(tick_atom, 1u, memory_order_relaxed) + 1u;
    // 每第 4 次做全量比对，其余 3 次各查一块，把 O(n) 校验摊薄到多次调用。
    const int full = (t % 4u) == 0u;
    if (full) {
        for (uint32_t c = 0; c < nchunks; c++) {
            const uint64_t h = cprisk_svc_stub_chunk_hash_fnv16(
                live + (size_t)c * CPRISK_SVC_STUB_CHUNK_BYTES,
                stub_addr);
            if (h != expected[c]) {
                return 0;
            }
        }
        return 1;
    }
    // 单块索引随 tick 轮转，任意块最终都会被覆盖到。
    const uint32_t idx = (t - 1u) % nchunks;
    const uint64_t h = cprisk_svc_stub_chunk_hash_fnv16(
        live + (size_t)idx * CPRISK_SVC_STUB_CHUNK_BYTES,
        stub_addr);
    return h == expected[idx] ? 1 : 0;
}

// 抓取 6 参数模板快照：优先取 RX 页中的重定位副本（真正被调用的代码），
// 重定位未就绪时退回 __TEXT 模板，保证两种部署下基准都对应实际执行地址。
__attribute__((constructor(8)))
static void cprisk_svc_stub_capture_syscall6_i(void) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    const void *src6 = (s_svc_reloc_ready != 0 && s_svc_rx_page != NULL)
                           ? (const void *)((const uint8_t *)s_svc_rx_page + s_svc6_rx_offset)
                           : (const void *)&cprisk_direct_syscall6_template;
#else
    const void *src6 = (const void *)&cprisk_direct_syscall6_template;
#endif
    const uintptr_t base = (uintptr_t)src6;
    uint8_t snap[CPRISK_SVC_STUB_SNAPSHOT_BYTES];
    memcpy(snap, src6, sizeof(snap));
    for (uint32_t c = 0; c < CPRISK_SVC_STUB6_CHUNKS; c++) {
        s_cprisk_syscall6_chunk_expected[c] =
            cprisk_svc_stub_chunk_hash_fnv16(snap + (size_t)c * CPRISK_SVC_STUB_CHUNK_BYTES, base);
    }
    s_cprisk_syscall6_text_ready = 1;
}

// 抓取 0 参数模板快照：地址选择规则与 6 参数版本一致。
__attribute__((constructor(8)))
static void cprisk_svc_stub_capture_syscall0_i(void) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    const void *src0 = (s_svc_reloc_ready != 0 && s_svc_rx_page != NULL)
                           ? (const void *)((const uint8_t *)s_svc_rx_page + s_svc0_rx_offset)
                           : (const void *)&cprisk_direct_syscall0_template;
#else
    const void *src0 = (const void *)&cprisk_direct_syscall0_template;
#endif
    const uintptr_t base = (uintptr_t)src0;
    uint8_t snap[CPRISK_SVC0_STUB_SNAPSHOT_BYTES];
    memcpy(snap, src0, sizeof(snap));
    for (uint32_t c = 0; c < CPRISK_SVC_STUB0_CHUNKS; c++) {
        s_cprisk_syscall0_chunk_expected[c] =
            cprisk_svc_stub_chunk_hash_fnv16(snap + (size_t)c * CPRISK_SVC_STUB_CHUNK_BYTES, base);
    }
    s_cprisk_syscall0_text_ready = 1;
}

// 6 参数 stub 完整性判定：返回 0=通过，1=异常（聚合时作为 bit0）。
// 检查顺序：页仍为 RX 且不可写 → 整页布局指纹 → 模板滚动哈希 → 指令流仍含 SVC → 正文 SHA-256。
// 任一失败立即返回，避免在可疑页上继续读取。
// 线程安全：只读内存 + 原子 tick，可并发调用。
static uint32_t cprisk_direct_syscall6_stub_integrity_mask_i(void) {
    if (!s_cprisk_syscall6_text_ready) {
        return 0u;
    }
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE && defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
    if (s_svc_reloc_ready && s_svc_rx_page != NULL) {
        // 先确认页权限没被改回可写：hook 常先 mprotect RW 打补丁，再恢复 RX。
        if (!cprisk_svc_rx_page_mach_prot_ok_i()) {
            return 1u;
        }
        uint64_t h = cprisk_fnv1a64_fold_i(s_svc_rx_page, s_svc_rx_page_size);
        h ^= (uint64_t)s_svc6_rx_offset << 48;
        h ^= (uint64_t)s_svc0_rx_offset << 32;
        h ^= 0x8E61F7A91D3C5B09ULL;
        // 整页指纹覆盖页内所有字节与模板偏移，能发现整体替换或偏移漂移。
        if (h != s_svc_rx_page_hash_ref) {
            return 1u;
        }
        const uint8_t *p6 = (const uint8_t *)s_svc_rx_page + s_svc6_rx_offset;
        const uint8_t *p0 = (const uint8_t *)s_svc_rx_page + s_svc0_rx_offset;
        // 滚动指纹侧重模板正文，能发现局部覆盖。
        uint64_t roll = cprisk_fnv1a64_fold_i(p6, CPRISK_SVC_STUB_SNAPSHOT_BYTES);
        roll ^= cprisk_fnv1a64_fold_i(
            p6 + CPRISK_SVC_STUB_SNAPSHOT_BYTES / 4u,
            CPRISK_SVC_STUB_SNAPSHOT_BYTES - CPRISK_SVC_STUB_SNAPSHOT_BYTES / 4u);
        roll ^= cprisk_fnv1a64_fold_i(p0, CPRISK_SVC0_STUB_SNAPSHOT_BYTES) << 1u;
        if (roll != s_svc_rx_stub_roll_ref) {
            return 1u;
        }
        uint8_t live[CPRISK_SVC_STUB_SNAPSHOT_BYTES];
        memcpy(live, p6, sizeof(live));
        // 即使哈希被同步改写，也必须确认指令流里仍有 svc——“直调”可能已被替换。
        if (!cprisk_svc_stub_chunks_match_rolling_i(
                live,
                (uintptr_t)p6,
                CPRISK_SVC_STUB6_CHUNKS,
                s_cprisk_syscall6_chunk_expected,
                &s_cprisk_syscall6_stub_tick)) {
            return 1u;
        }
        if (!cprisk_stub_contains_svc_opcode(p6, CPRISK_SVC_STUB_SNAPSHOT_BYTES)) {
            return 1u;
        }
        if (!cprisk_stub_contains_svc_opcode(p0, CPRISK_SVC0_STUB_SNAPSHOT_BYTES)) {
            return 1u;
        }
        // SHA-256 才是抗碰撞证据；FNV 只用来低成本筛掉明显改动。
        uint8_t h6b[32];
        cprisk_sha256_ctx ctxb;
        cprisk_sha256_init(&ctxb);
        cprisk_sha256_update(&ctxb, p6, CPRISK_SVC_STUB_SNAPSHOT_BYTES);
        cprisk_sha256_final(&ctxb, h6b);
        if (memcmp(h6b, s_svc6_reloc_body_sha256, 32) != 0) {
            return 1u;
        }
        uint8_t h0b[32];
        cprisk_sha256_init(&ctxb);
        cprisk_sha256_update(&ctxb, p0, CPRISK_SVC0_STUB_SNAPSHOT_BYTES);
        cprisk_sha256_final(&ctxb, h0b);
        if (memcmp(h0b, s_svc0_reloc_body_sha256, 32) != 0) {
            return 1u;
        }
        return 0u;
    }
#endif
    uint8_t live[CPRISK_SVC_STUB_SNAPSHOT_BYTES];
    memcpy(live, (const void *)&cprisk_direct_syscall6_template, sizeof(live));
    // 未重定位时直接校验 __TEXT 模板本体：可用性降级，但仍能发现编译产物被 patch。
    const uintptr_t base = (uintptr_t)(void *)&cprisk_direct_syscall6_template;
    if (!cprisk_svc_stub_chunks_match_rolling_i(
            live,
            base,
            CPRISK_SVC_STUB6_CHUNKS,
            s_cprisk_syscall6_chunk_expected,
            &s_cprisk_syscall6_stub_tick)) {
        return 1u;
    }
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    if (!cprisk_stub_contains_svc_opcode((const void *)&cprisk_direct_syscall6_template, sizeof(live))) {
        return 1u;
    }
#endif
    return 0u;
}

// 0 参数 stub 完整性判定：返回 0=通过，1=异常（聚合时作为 bit2）。
// 重定位就绪时校验 RX 副本，否则校验 __TEXT 模板；只做分块滚动哈希与 SVC 指令检查
//（页级 SHA-256 由 aux mask 统一覆盖两份模板）。
static uint32_t cprisk_direct_syscall0_stub_integrity_mask_i(void) {
    if (!s_cprisk_syscall0_text_ready) {
        return 0u;
    }
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE && defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
    if (s_svc_reloc_ready && s_svc_rx_page != NULL) {
        const uint8_t *p0 = (const uint8_t *)s_svc_rx_page + s_svc0_rx_offset;
        uint8_t live[CPRISK_SVC0_STUB_SNAPSHOT_BYTES];
        memcpy(live, p0, sizeof(live));
        if (!cprisk_svc_stub_chunks_match_rolling_i(
                live,
                (uintptr_t)p0,
                CPRISK_SVC_STUB0_CHUNKS,
                s_cprisk_syscall0_chunk_expected,
                &s_cprisk_syscall0_stub_tick)) {
            return 1u;
        }
        if (!cprisk_stub_contains_svc_opcode(p0, CPRISK_SVC0_STUB_SNAPSHOT_BYTES)) {
            return 1u;
        }
        return 0u;
    }
#endif
    uint8_t live[CPRISK_SVC0_STUB_SNAPSHOT_BYTES];
    memcpy(live, (const void *)&cprisk_direct_syscall0_template, sizeof(live));
    // 同 6 参数版本：未重定位时退化为校验模板本体。
    const uintptr_t base = (uintptr_t)(void *)&cprisk_direct_syscall0_template;
    if (!cprisk_svc_stub_chunks_match_rolling_i(
            live,
            base,
            CPRISK_SVC_STUB0_CHUNKS,
            s_cprisk_syscall0_chunk_expected,
            &s_cprisk_syscall0_stub_tick)) {
        return 1u;
    }
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    if (!cprisk_stub_contains_svc_opcode((const void *)&cprisk_direct_syscall0_template, sizeof(live))) {
        return 1u;
    }
#endif
    return 0u;
}
#else
// 非 Apple arm64 没有可校验的 SVC 模板，恒返回 0（fail-open，不产生虚假告警）。
static uint32_t cprisk_direct_syscall6_stub_integrity_mask_i(void) {
    return 0u;
}

// 同上：非 Apple arm64 构建恒 0；聚合后 bit2 永远不置位。
static uint32_t cprisk_direct_syscall0_stub_integrity_mask_i(void) {
    return 0u;
}
#endif

#if CPRISK_DIRECT_SYSCALLS_AVAILABLE && defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
// 页级 SHA-256 基准：首轮懒加载时抓取，之后每次调用重算并比较。
// 与上面的 FNV 路径相互独立——FNV 便宜、用于高频粗筛；SHA-256 昂贵、用于低频确证。
static uint8_t s_sha256_pg6_ref[32];
static uint8_t s_sha256_pg0_ref[32];
static int s_sha256_pg_ref_ready;

// 计算三份页级摘要：6 参数模板、0 参数模板、deny-attach stub。
// 源地址与运行期实际调用地址保持一致（重定位就绪时用 RX 副本）。
static void cprisk_svc_stub_resolve_live_page_hashes_i(uint8_t h6[32], uint8_t h0[32], uint8_t hd[32]) {
    const void *src6 = (s_svc_reloc_ready != 0 && s_svc_rx_page != NULL)
                           ? (const void *)((const uint8_t *)s_svc_rx_page + s_svc6_rx_offset)
                           : (const void *)&cprisk_direct_syscall6_template;
    const void *src0 = (s_svc_reloc_ready != 0 && s_svc_rx_page != NULL)
                           ? (const void *)((const uint8_t *)s_svc_rx_page + s_svc0_rx_offset)
                           : (const void *)&cprisk_direct_syscall0_template;
    cprisk_sha256_text_page(src6, h6);
    cprisk_sha256_text_page(src0, h0);
    cprisk_deny_attach_stub_page_sha256_digest(hd);
}

// 首轮抓取基准（惰性、非原子）：只在第一次校验时写入，之后的比较都以它为参照。
// 竞态窗口最多让两个线程写入相同内容，结果一致，因此无需加锁。
static void cprisk_sha256_pg_ref_lazy_i(void) {
    if (s_sha256_pg_ref_ready) {
        return;
    }
    uint8_t h6[32], h0[32], hd[32];
    cprisk_svc_stub_resolve_live_page_hashes_i(h6, h0, hd);
    memcpy(s_sha256_pg6_ref, h6, sizeof(s_sha256_pg6_ref));
    memcpy(s_sha256_pg0_ref, h0, sizeof(s_sha256_pg0_ref));
    (void)hd;
    s_sha256_pg_ref_ready = 1;
}

// 返回 bit3=6 参数模板页摘要变化、bit4=0 参数模板页摘要变化；0=一致。
// deny-attach 的页摘要由它自己的 mask 提供，这里只计算不置位。
static uint32_t cprisk_svc_stub_sha256_aux_mask_i(void) {
    cprisk_sha256_pg_ref_lazy_i();
    uint8_t h6[32], h0[32], hd[32];
    cprisk_svc_stub_resolve_live_page_hashes_i(h6, h0, hd);
    (void)hd;
    uint32_t m = 0u;
    if (memcmp(h6, s_sha256_pg6_ref, 32) != 0) {
        m |= 1u << 3;
    }
    if (memcmp(h0, s_sha256_pg0_ref, 32) != 0) {
        m |= 1u << 4;
    }
    return m;
}

// 滚动摘要链的持久状态：上一轮摘要与单调计数器。普通静态变量而非原子——
// 当前调用方（watchdog）串行调用；并发调用会产生数据竞争，需由调用方自行加锁。
static uint8_t s_stub_sha256_roll[32];
static uint64_t s_stub_sha256_roll_ctr;

// 滚动摘要链：H(prev || h6 || h0 || hd || le64(counter))，把每轮校验串成历史，
// 使“逐次小幅篡改、每次都在当轮基准内”的尝试随时间累积出差异。
// 参数与所有权：三份摘要各 32 字节只读；结果写回 s_stub_sha256_roll。
static void cprisk_svc_stub_sha256_roll_step_i(const uint8_t h6[32], const uint8_t h0[32], const uint8_t hd[32]) {
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, s_stub_sha256_roll, 32);
    cprisk_sha256_update(&ctx, h6, 32);
    cprisk_sha256_update(&ctx, h0, 32);
    cprisk_sha256_update(&ctx, hd, 32);
    s_stub_sha256_roll_ctr++;
    uint8_t le[8];
    // 计数器按小端编码进哈希，确保不同字节序的产物不会生成同一条链。
    for (unsigned i = 0; i < 8; i++) {
        le[i] = (uint8_t)(s_stub_sha256_roll_ctr >> (8u * i));
    }
    cprisk_sha256_update(&ctx, le, 8);
    cprisk_sha256_final(&ctx, s_stub_sha256_roll);
}
#else
// 非 Apple arm64 构建没有页级摘要能力，恒返回 0（该检查被裁剪，不产生告警）。
static uint32_t cprisk_svc_stub_sha256_aux_mask_i(void) {
    return 0u;
}
#endif

// 聚合所有 stub 完整性来源：bit0=syscall6、bit1=deny-attach、bit2=syscall0、
// bit3/bit4=两份模板页 SHA-256，更高位由 deny-attach 页掩码提供。
// 返回 0=全部通过；非 0=fail-closed，调用方应视为直调链路可疑。
// 副作用：每次调用推进一次滚动 SHA-256 链（用于跨时间比对）。
uint32_t cprisk_verify_svc_stub_integrity(void) {
    const uint32_t a = cprisk_direct_syscall6_stub_integrity_mask_i();
    const uint32_t b = cprisk_deny_attach_stub_integrity_mask();
    const uint32_t c = cprisk_direct_syscall0_stub_integrity_mask_i();
    const uint32_t sha_mask = cprisk_svc_stub_sha256_aux_mask_i();
    const uint32_t deny_sha_mask = cprisk_deny_attach_stub_sha256_page_mask();
    // 各来源的位定义不同，这里移位拼成统一掩码：deny-attach 的位整体左移 1。
    const uint32_t m = a | (b << 1) | (c << 2) | sha_mask | deny_sha_mask;
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE && defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
    {
        // 无论本轮结论如何都推进滚动链，让历史异常无法靠“下次改回原样”抹掉。
        uint8_t rh6[32], rh0[32], rhd[32];
        cprisk_svc_stub_resolve_live_page_hashes_i(rh6, rh0, rhd);
        cprisk_svc_stub_sha256_roll_step_i(rh6, rh0, rhd);
    }
#endif
    return m;
}

/*
 * Bounds of the mmap'd RX page holding relocated SVC syscall templates (device arm64 only).
 * memory_guard skips this range when classifying anonymous RX so our own stub slab is not
 * conflated with foreign Stalker/Gum-style executable mappings.
 */
// 输出重定位 RX 页的 [lo, hi) 区间；未重定位时输出 0/0。
// memory_guard 用它把自家 stub 页从“匿名可执行映射”告警中排除。
// 参数与所有权：out_lo/out_hi 可为 NULL；写入的是快照值，调用方不得据此推断映射仍有效。
void cprisk_svc_reloc_rx_page_whitelist_bounds(uintptr_t *out_lo, uintptr_t *out_hi) {
    uintptr_t lo = 0u;
    uintptr_t hi = 0u;
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE && defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
    if (s_svc_reloc_ready && s_svc_rx_page != NULL && s_svc_rx_page_size > 0u) {
        lo = (uintptr_t)s_svc_rx_page;
        hi = lo + (uintptr_t)s_svc_rx_page_size;
    }
#endif
    if (out_lo != NULL) {
        *out_lo = lo;
    }
    if (out_hi != NULL) {
        *out_hi = hi;
    }
}

/* ── Dual-path syscall cross-verification ──────────────────────────── */

// 做什么：对 getpid/getuid/getppid/stat("/")/access("/") 同时走 SVC 直调与 libc，
//   比较返回值（stat 比 st_dev/st_ino），识别 libc 层被 hook 的情况。
// 参数与所有权：无参数。返回值：CPRISK_CROSSCHECK_DIVERGE_* 位组合，0=一致。
// 线程安全：无状态可并发。平台：非 arm64/模拟器恒返回 0（无从比较）。
// 失败语义：fail-open；单个比较失败（如任一侧 stat 失败）不置位。
uint32_t cprisk_syscall_crosscheck_probe(void) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    uint32_t flags = 0u;

    if (cprisk_getpid_direct() != getpid()) {
        flags |= CPRISK_CROSSCHECK_DIVERGE_PID;
    }

    if (cprisk_getuid_direct() != getuid()) {
        flags |= CPRISK_CROSSCHECK_DIVERGE_UID;
    }

    if (cprisk_getppid_direct() != getppid()) {
        flags |= CPRISK_CROSSCHECK_DIVERGE_PPID;
    }

    {
        struct stat sb_svc, sb_libc;
        memset(&sb_svc, 0, sizeof(sb_svc));
        memset(&sb_libc, 0, sizeof(sb_libc));
        if (cprisk_stat_direct("/", &sb_svc, NULL) == 0 && stat("/", &sb_libc) == 0) {
            // 只比设备号与 inode：足以判断“是否同一文件”，又不受权限/时间戳影响。
            if (sb_svc.st_dev != sb_libc.st_dev || sb_svc.st_ino != sb_libc.st_ino) {
                flags |= CPRISK_CROSSCHECK_DIVERGE_STAT;
            }
        }
    }

    {
        int svc_rc = cprisk_access_direct("/", F_OK, NULL);
        int libc_rc = access("/", F_OK);
        // access 直接比返回值：任一侧失败都会体现为分歧。
        if (svc_rc != libc_rc) {
            flags |= CPRISK_CROSSCHECK_DIVERGE_ACCESS;
        }
    }

    return flags;
#else
    return 0u;
#endif
}

/* ── Errno reasonableness validation ───────────────────────────────── */

// 做什么：检查直调返回的 errno 是否合理——正常路径不应出现 EINTR/ERESTART、
//   根目录不可访问或非法 pid。
// 参数与所有权：无参数。返回值：CPRISK_ERRNO_PROBE_* 位组合，0=正常。
// 线程安全：无状态可并发。平台：非 arm64 恒 0。失败语义：fail-open。
uint32_t cprisk_syscall_errno_probe(void) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    uint32_t flags = 0u;

    {
        int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)getpid() };
        struct kinfo_proc kp;
        memset(&kp, 0, sizeof(kp));
        size_t kp_len = sizeof(kp);
        int sysctl_err = 0;
        cprisk_sysctl_direct(mib, 4, &kp, &kp_len, NULL, 0, &sysctl_err);
        // EINTR/ERESTART 说明 syscall 被重放或返回值被伪造；正常调用不应出现。
        if (sysctl_err == EINTR
#ifdef ERESTART
            || sysctl_err == ERESTART
#endif
        ) {
            flags |= CPRISK_ERRNO_PROBE_SYSCTL_EINTR;
        }
    }

    {
        struct stat sb;
        memset(&sb, 0, sizeof(sb));
        int stat_err = 0;
        cprisk_stat_direct("/", &sb, &stat_err);
        if (stat_err == EINTR) {
            flags |= CPRISK_ERRNO_PROBE_STAT_EINTR;
        }
    }

    {
        int rc = cprisk_access_direct("/", F_OK, NULL);
        if (rc == -1) {
            flags |= CPRISK_ERRNO_PROBE_ACCESS_ROOT_FAIL;
        }
    }

    {
        pid_t pid = cprisk_getpid_direct();
        if (pid <= 0) {
            flags |= CPRISK_ERRNO_PROBE_PID_INVALID;
        }
    }

    return flags;
#else
    return 0u;
#endif
}

/* ── Honeypot syscall behavioral probe ─────────────────────────────── */

// 做什么：用随机 8 字节拼出一个必然不存在的 /tmp 路径，若 access/stat 报存在，
//   说明路径解析被 hook；同时把 "/" 的直调与 libc 结果做双向交叉校验。
// 参数与所有权：无参数。返回值：CPRISK_HONEYPOT_* 位组合，0=正常或随机源不可用。
// 线程安全：全部状态在栈上，可并发。平台：非 arm64 恒 0。失败语义：fail-open。
uint32_t cprisk_honeypot_syscall_probe(void) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    uint32_t flags = 0u;

    uint8_t rand_bytes[8];
    int ge = 0;
    // 随机源不可用时直接返回 0：无法保证路径“必然不存在”，宁可放弃探测也不制造假阳性。
    if (cprisk_getentropy_direct(rand_bytes, sizeof(rand_bytes), &ge) != 0) {
        return 0u;
    }

    char hp_path[64];
    // 路径长度固定（前缀 + 16 个 hex + NUL），64 字节栈缓冲足够，不会截断。
    snprintf(hp_path, sizeof(hp_path),
             "/tmp/.cprisk_hp_%02x%02x%02x%02x%02x%02x%02x%02x",
             rand_bytes[0], rand_bytes[1], rand_bytes[2], rand_bytes[3],
             rand_bytes[4], rand_bytes[5], rand_bytes[6], rand_bytes[7]);

    if (cprisk_access_direct(hp_path, F_OK, NULL) == 0) {
        flags |= CPRISK_HONEYPOT_PHANTOM_ACCESS_EXISTS;
    }

    {
        struct stat sb;
        memset(&sb, 0, sizeof(sb));
        if (cprisk_stat_direct(hp_path, &sb, NULL) == 0) {
            flags |= CPRISK_HONEYPOT_PHANTOM_STAT_EXISTS;
        }
    }

    {
        int svc_rc = cprisk_access_direct("/", F_OK, NULL);
        int libc_rc = access("/", F_OK);
        if (svc_rc != 0 && libc_rc == 0) {
            flags |= CPRISK_HONEYPOT_ROOT_SVC_LIBC_DIVERGE_A;
        }
        if (svc_rc == 0 && libc_rc != 0) {
            flags |= CPRISK_HONEYPOT_ROOT_SVC_LIBC_DIVERGE_B;
        }
    }

    // 栈缓冲用完即清零，避免探测路径残留在栈上被后续栈读取复用。
    cprisk_secure_zero(hp_path, sizeof(hp_path));

    return flags;
#else
    return 0u;
#endif
}
