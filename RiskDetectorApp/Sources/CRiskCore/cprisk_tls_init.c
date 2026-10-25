/*
 * cprisk_tls_init.c — TLS 回调阶段的早期加固入口。
 * 职责：在 __DATA,__thread_init 阶段先 deny-attach，再注册异常端口并抓取基线。
 * 线程模型：dyld 单线程加载期执行，早于 constructor / ObjC +load，无并发竞争。
 * 平台：仅 Apple；依赖 __thread_init section，同段回调顺序由链接器决定。
 * 失败语义：各调用内部自处理失败，本回调无返回值；被后来者覆盖由 constructor 101 兜底。
 */

#include "include/CRiskCore.h"
#include <TargetConditionals.h>

/*
 * Early TLS (Thread Local Storage) Callback — TLS 回调时序加固
 *
 * 执行时机：__DATA,__thread_init 在 dyld 加载阶段执行，早于 __mod_init_func
 * （C++ constructor）和 Objective-C +load。
 *
 * 时序风险：Frida gadget 若打包进 IPA，也可使用 __DATA,__thread_init。同一
 * section 内多个回调的调用顺序由链接器决定（通常按 section 中出现顺序）。
 * 若 gadget 的 __thread_init 先于或交错于本回调执行，可能已注册异常端口或
 * 设置 Hook，导致 deny-attach 路径被绕过或异常端口被抢占。
 *
 * 加固策略：
 * 1. deny-attach 优先：使用 SVC 直调绕过 libc Hook，即使 Frida 已 Hook 对应符号也无效。
 * 2. 异常端口：本回调中注册后，由 cprisk_early_exception_port_reclaim（constructor
 *    101）在 __mod_init_func 阶段再次验证；若被 Frida 覆盖则 task_swap_exception_ports
 *    重新抢占。详见 cprisk_exception_handler.c。
 */
// TLS 回调实现：无参数/无返回值/不分配资源。
// 顺序不变量：必须先 deny-attach（SVC 直调抗 Hook），再抢占异常端口；
// 顺序颠倒会给 attach 留出窗口。线程安全：仅 dyld 加载期单线程调用。
static void cprisk_tls_init_callback(void) {
    /* 1. deny-attach 优先：SVC 直调，不经过 libc，抗 Hook */
    cprisk_deny_attach();

    /* 2. 抢占异常端口；若 Frida 后执行覆盖，constructor 阶段会重新抢占 */
    cprisk_register_exception_handler();
    cprisk_capture_early_exception_ports();
}

/* 
 * Register the callback pointer in the __DATA,__thread_init section.
 * The 'used' attribute ensures the compiler doesn't optimize it away.
 */
// 把回调函数指针放入 __DATA,__thread_init，供 dyld 在加载期自动调用。
// used 防止被优化删除；指针只初始化一次，之后只读，无并发写。
#if defined(__APPLE__)
__attribute__((used, section("__DATA,__thread_init")))
static void (*cprisk_tls_init_ptr)(void) = cprisk_tls_init_callback;
#endif
