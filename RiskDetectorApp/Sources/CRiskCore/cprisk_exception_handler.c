/*
 * cprisk_exception_handler.c — Mach EXC_BREAKPOINT/BAD_ACCESS/SOFTWARE 端口接管。
 * 职责：抢占异常端口，处理 BRK 门禁与 JIT 页解密，周期性校验指纹并在被替换时重占。
 * 竞争：注册与进程启动非原子；两次校验之间挂上又撤掉的劫持无法发现（issue 34）。
 * 线程：注册/校验由 s_mutex 串行；处理线程独立阻塞在 mach_msg，不占用主线程。
 * 上下文：处理线程不 malloc、不取 s_mutex；未知异常/flavor 回 KERN_FAILURE 交还系统。
 * 平台：仅 arm64 真机启用；模拟器、tvOS、watchOS 编译为空桩，快照清零。
 */

#include "include/CRiskCore.h"
#include <mach/mach.h>
#include <mach/exception_types.h>
#include <mach/exc.h>
#include <mach/mach_time.h>
#include <mach/ndr.h>
#include <mach/arm/thread_status.h>
#include <mach/thread_status.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <TargetConditionals.h>

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__)) && \
    (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR) && \
    (!defined(TARGET_OS_TV) || !TARGET_OS_TV) && \
    (!defined(TARGET_OS_WATCH) || !TARGET_OS_WATCH)

// 异常端口与注册状态。
// s_exception_port：接收权端口，仅在 s_mutex 下创建/销毁；处理线程只读使用。
// s_registered：原子发布标志，1 表示端口与线程均已就绪，可无锁快速判断。
static mach_port_t s_exception_port = MACH_PORT_NULL;
static atomic_int s_registered = 0;
// s_mutex：串行化注册、校验、重占与快照读取，避免端口生命周期竞态。
static pthread_mutex_t s_mutex = PTHREAD_MUTEX_INITIALIZER;
// s_status：对外快照；所有字段在 s_mutex 下更新，查询时整体拷贝。
static cprisk_exception_handler_snapshot_t s_status = {
    .supported = 1u,
    .registered = 0u,
    .port_matches = 0u,
    .last_query_succeeded = 0u,
    .last_reclaim_attempted = 0u,
    .last_hijack_detected = 0u,
    .early_phase_captured = 0u,
    .last_race_detected = 0u,
    .last_query_kern_return = (int32_t)KERN_FAILURE,
    .last_register_kern_return = (int32_t)KERN_FAILURE,
    .verify_count = 0u,
    .reclaim_count = 0u,
    .first_register_verify_delta_ns = 0u,
};
// s_early_port_fingerprint：启动早期抓取的端口指纹，用于识别“晚阶段被换掉”。
// s_early_port_fingerprint_valid：指纹是否有效；s_late_phase_checked：只比较一次。
// s_first_register_monotonic_ns：首次注册成功的单调时钟，供快照计算注册-校验间隔。
static uint64_t s_early_port_fingerprint = 0u;
static uint32_t s_early_port_fingerprint_valid = 0u;
static uint32_t s_late_phase_checked = 0u;
static uint64_t s_first_register_monotonic_ns = 0u;

// 把 mach_absolute_time 的 tick 转成纳秒；timebase 缓存为 (numer<<32)|denom。
// 返回：纳秒（溢出不做回绕保护，调用方只用差值）。
// 线程安全：timebase 用原子缓存，可并发；失败回退原始 tick，仍单调。
// 平台：仅 Apple；timebase 非法时返回 ticks 避免除零。
static uint64_t cprisk_exception_monotonic_time_ns_i(void) {
    static atomic_uint_fast64_t s_timebase = 0u;
    uint64_t cached = atomic_load(&s_timebase);
    if (cached == 0u) {
        mach_timebase_info_data_t info;
        if (mach_timebase_info(&info) != KERN_SUCCESS || info.numer == 0u || info.denom == 0u) {
            return mach_absolute_time();
        }
        cached = ((uint64_t)info.numer << 32u) | (uint64_t)info.denom;
        atomic_store(&s_timebase, cached);
    }
    const uint32_t numer = (uint32_t)(cached >> 32u);
    const uint32_t denom = (uint32_t)(cached & 0xffffffffu);
    const uint64_t ticks = mach_absolute_time();
    if (denom == 0u) {
        return ticks;
    }
    return (ticks / (uint64_t)denom) * (uint64_t)numer +
           (ticks % (uint64_t)denom) * (uint64_t)numer / (uint64_t)denom;
}

// Mach 异常消息 ID：state_identity 请求及其回复 ID（回复 = 请求 + 100）。
// 这两个值来自 MIG 生成约定，不能随意改动，否则无法与内核/调试器协议对齐。
#define EXC_EXCEPTION_RAISE_STATE_IDENTITY 2403
#define MACH_EXCEPTION_RAISE_STATE_IDENTITY 2407

// 内核 mach_exception_raise_state_identity 消息的本地镜像（4 字节对齐打包）。
// Head/msgh_body/thread/task/NDR：标准 Mach 消息头与端口描述符。
// exception/codeCnt/code[2]：异常类型与两个 64 位异常码（BAD_ACCESS 用 code[1] 作故障地址）。
// flavor/old_stateCnt/old_state[1296]：线程状态 flavor 与足够容纳 arm64 状态的内联缓冲。
#pragma pack(push, 4)
typedef struct {
    mach_msg_header_t Head;
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t NDR;
    exception_type_t exception;
    mach_msg_type_number_t codeCnt;
    int64_t code[2];
    int flavor;
    mach_msg_type_number_t old_stateCnt;
    natural_t old_state[1296];
} __Request__mach_exception_raise_state_identity_t;

// 回复消息镜像：Head/NDR/RetCode 为协议头，flavor/new_stateCnt/new_state 回传
// 修改后的线程状态（例如 PC 已前进 4 字节）。
typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
    int flavor;
    mach_msg_type_number_t new_stateCnt;
    natural_t new_state[1296];
} __Reply__mach_exception_raise_state_identity_t;
#pragma pack(pop)

extern int cprisk_exception_handler_should_passthrough_brk_imm(uint16_t brk_imm);
extern int cprisk_exception_handler_consume_reserved_brk_imm(uint16_t brk_imm);
extern int cprisk_exception_handler_handle_runtime_gate_brk(uint16_t brk_imm, uintptr_t brk_pc);

// MurmurHash3 的 64 位 finalizer：把任意值雪崩混合，用于指纹扰码。
// 参数：任意 64 位值。返回：混合后的 64 位值（确定性）。
// 线程安全：纯函数；平台：无分支。
static uint64_t cprisk_mix64_i(uint64_t value) {
    value ^= value >> 33u;
    value *= 0xff51afd7ed558ccdULL;
    value ^= value >> 33u;
    value *= 0xc4ceb9fe1a85ec53ULL;
    value ^= value >> 33u;
    return value;
}

// 把端口注册表的 (mask, port, behavior, flavor) 压成单个 64 位指纹。
// 参数：四个并行数组与 count，均由调用方提供且长度为 count。
// 返回：确定性指纹；顺序敏感（索引参与混合），端口互换也会改变结果。
// 线程安全：只读输入，纯函数；平台：无分支。
// 用途：启动早期与后续校验各算一次，不等即说明端口被替换（last_race_detected）。
static uint64_t cprisk_exception_port_fingerprint_i(
    const exception_mask_t *masks,
    const mach_port_t *ports,
    const exception_behavior_t *behaviors,
    const thread_state_flavor_t *flavors,
    mach_msg_type_number_t count
) {
    uint64_t fingerprint = 0x43505249534B4558ULL; /* "CPRISKEX" */
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        uint64_t lane = ((uint64_t)(uint32_t)masks[i] << 32u) ^ (uint64_t)(uint32_t)ports[i];
        lane ^= ((uint64_t)(uint32_t)behaviors[i] << 16u);
        lane ^= (uint64_t)(uint32_t)flavors[i];
        lane ^= (uint64_t)i * 0x9E3779B97F4A7C15ULL;
        fingerprint ^= cprisk_mix64_i(lane);
        fingerprint = (fingerprint << 7u) | (fingerprint >> (64u - 7u));
        fingerprint ^= 0xA5A5A5A55A5A5A5AULL;
    }
    return fingerprint ^ ((uint64_t)count << 48u);
}

// 查询当前任务在 query_mask 范围内的异常端口并计算指纹。
// 参数：query_mask 为 EXC_MASK_*；out_fingerprint 不可为 NULL。
// 返回：0 成功（写入指纹）；-1 参数非法或 task_get_exception_ports 失败。
// 线程安全：仅内核查询，不触碰全局状态，可并发；但通常由调用方持 s_mutex。
// 平台：arm64 真机；调用后释放内核返回的端口引用，避免端口权泄漏。
static int cprisk_query_exception_port_fingerprint_i(
    exception_mask_t query_mask,
    uint64_t *out_fingerprint
) {
    if (out_fingerprint == NULL) {
        return -1;
    }

    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;
    kern_return_t kr = task_get_exception_ports(
        mach_task_self(), query_mask, masks, &count, ports, behaviors, flavors);
    if (kr != KERN_SUCCESS) {
        return -1;
    }

    *out_fingerprint = cprisk_exception_port_fingerprint_i(
        masks, ports, behaviors, flavors, count);
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        if (ports[i] != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), ports[i]);
        }
    }
    return 0;
}

// 从异常线程状态中解析 BRK 指令的 16 位立即数（BRK #imm）。
// 参数：flavor/state_count/state 为内核回传的线程状态；out_imm/out_pc 可为 NULL。
// 返回：1 = 成功识别（out_imm 有效，out_pc 为 BRK 地址）；0 = 不适用/不可读/非 BRK。
// 线程安全：纯函数，仅读输入缓冲；平台：要求 ARM_THREAD_STATE64。
// 安全性：解引用前用 vm_region_64 确认页可读，防止处理线程内二次 fault。
// 失败语义：任何异常（flavor 不符、PC 为空、页不可读、指令不匹配）都返回 0 并清空 out_pc。
static int cprisk_breakpoint_immediate_from_state_i(
    int flavor,
    mach_msg_type_number_t state_count,
    const natural_t *state,
    uint16_t *out_imm,
    uintptr_t *out_pc
) {
    if (out_imm == NULL || state == NULL ||
        flavor != ARM_THREAD_STATE64 ||
        state_count < ARM_THREAD_STATE64_COUNT) {
        if (out_pc != NULL) {
            *out_pc = 0u;
        }
        return 0;
    }

    arm_thread_state64_t thread_state;
    memset(&thread_state, 0, sizeof(thread_state));
    memcpy(&thread_state, state, sizeof(thread_state));

    const uintptr_t pc = (uintptr_t)thread_state.__pc;
    if (pc == 0u) {
        if (out_pc != NULL) {
            *out_pc = 0u;
        }
        return 0;
    }

    /* Verify the PC address is readable before dereferencing to avoid
       a nested fault inside the exception handler thread. */
    vm_size_t region_size = 0;
    vm_address_t region_addr = (vm_address_t)pc;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;
    kern_return_t kr = vm_region_64(mach_task_self(), &region_addr, &region_size,
                                     VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info,
                                     &info_count, &object_name);
    if (object_name != MACH_PORT_NULL)
        mach_port_deallocate(mach_task_self(), object_name);
    if (kr != KERN_SUCCESS || region_addr > (vm_address_t)pc ||
        (vm_address_t)pc + sizeof(uint32_t) > region_addr + region_size ||
        !(info.protection & VM_PROT_READ)) {
        if (out_pc != NULL) {
            *out_pc = 0u;
        }
        return 0;
    }

    uint32_t instr = 0u;
    memcpy(&instr, (const void *)pc, sizeof(instr));
    if ((instr & 0xFFE0001Fu) != 0xD4200000u) {
        if (out_pc != NULL) {
            *out_pc = 0u;
        }
        return 0;
    }

    *out_imm = (uint16_t)((instr >> 5) & 0xFFFFu);
    if (out_pc != NULL) {
        *out_pc = pc;
    }
    return 1;
}

// 就地把线程状态的 PC 前进 4 字节，跳过触发异常的 BRK 指令。
// 参数：flavor/state_count/state；state 必须可写且长度足够。
// 返回：1 = 已前进；0 = flavor/长度不匹配或 state 为 NULL。
// 线程安全：只改调用方提供的缓冲；平台：ARM_THREAD_STATE64。
// 失败语义：返回 0 时调用方必须回 KERN_FAILURE，绝不能回成功但 PC 未动（会死循环）。
static int cprisk_advance_thread_pc_i(
    int flavor,
    mach_msg_type_number_t state_count,
    natural_t *state
) {
    if (state == NULL ||
        flavor != ARM_THREAD_STATE64 ||
        state_count < ARM_THREAD_STATE64_COUNT) {
        return 0;
    }

    arm_thread_state64_t thread_state;
    memset(&thread_state, 0, sizeof(thread_state));
    memcpy(&thread_state, state, sizeof(thread_state));
    thread_state.__pc += 4u;
    memcpy(state, &thread_state, sizeof(thread_state));
    return 1;
}

// 异常处理线程主循环：阻塞接收异常消息、构造回复并发送。
// 参数：arg 未使用（兼容 pthread 签名）。返回：仅当端口失效/接收不可恢复时退出。
// 线程安全：单线程独占 s_exception_port 的接收权；不获取 s_mutex，避免与注册/校验互锁。
// 上下文安全：栈上固定缓冲，不 malloc、不加锁；mach_msg 超时 100ms 用于定期检查退出。
// 平台：仅 arm64 真机；回复按 MACH_MSGH_BITS_REMOTE 原路返回，msgh_id 加 100 表示 reply。
// 失败语义：接收超时继续循环；其他接收错误退出线程（s_registered 仍为 1，需由校验路径重注册）。
static void *exception_handler_thread(void *arg) {
    (void)arg;
    char req_buf[sizeof(__Request__mach_exception_raise_state_identity_t)];
    char reply_buf[sizeof(__Reply__mach_exception_raise_state_identity_t)];
    mach_msg_header_t *req = (mach_msg_header_t *)req_buf;
    mach_msg_header_t *reply = (mach_msg_header_t *)reply_buf;

    for (;;) {
        memset(req_buf, 0, sizeof(req_buf));
        req->msgh_local_port = s_exception_port;
        req->msgh_size = sizeof(req_buf);

        kern_return_t kr = mach_msg(req, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                    req->msgh_size, s_exception_port, 100, MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            // 超时是预期的轮询节拍，继续等待；其他错误说明端口已失效，退出线程。
            if (kr == MACH_RCV_TIMED_OUT)
                continue;
            break;
        }

        memset(reply_buf, 0, sizeof(reply_buf));
        reply->msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req->msgh_bits), 0);
        reply->msgh_remote_port = req->msgh_remote_port;
        reply->msgh_local_port = MACH_PORT_NULL;
        reply->msgh_id = req->msgh_id + 100;

        // 协议 ID 校验：只处理 mach_exception_raise_state_identity，其余消息丢弃（不回复）。
        if (req->msgh_id == MACH_EXCEPTION_RAISE_STATE_IDENTITY) {
            const __Request__mach_exception_raise_state_identity_t *r =
                (const __Request__mach_exception_raise_state_identity_t *)req;
            int flavor = r->flavor;
            mach_msg_type_number_t old_stateCnt = r->old_stateCnt;
            const natural_t *old_state = r->old_state;

            __Reply__mach_exception_raise_state_identity_t *rep =
                (__Reply__mach_exception_raise_state_identity_t *)reply;
            rep->NDR = NDR_record;
            rep->RetCode = KERN_SUCCESS;
            rep->flavor = flavor;
            rep->new_stateCnt = 0;

            mach_msg_type_number_t state_count = 0;
            // 只接受 arm64 的两种线程状态 flavor；其余显式 KERN_FAILURE 交还系统。
            if (flavor == ARM_THREAD_STATE64) {
                state_count = ARM_THREAD_STATE64_COUNT;
            } else if (flavor == ARM_THREAD_STATE) {
                state_count = ARM_THREAD_STATE_COUNT;
            } else {
                rep->RetCode = KERN_FAILURE;
            }

            // 内核或恶意发送方可能给出超大计数：截断到内联缓冲容量，防止越界。
            if (old_stateCnt > 1296)
                old_stateCnt = 1296;

            if (state_count > 0 && rep->RetCode == KERN_SUCCESS) {
                // 回复状态长度取两者较小值，确保 memcpy 不越过请求与回复任一缓冲。
                if (old_stateCnt < state_count)
                    state_count = old_stateCnt;
                if (state_count > 1296)
                    state_count = 1296;
                rep->new_stateCnt = state_count;
                memcpy(rep->new_state, old_state, state_count * sizeof(natural_t));
                
                if (r->exception == EXC_BREAKPOINT) {
                    // BRK 处理顺序：先解析立即数，再前进 PC；任何一步失败都必须 KERN_FAILURE，
                    // 否则会回到同一条 BRK 形成死循环。
                    uint16_t brk_imm = 0u;
                    uintptr_t brk_pc = 0u;
                    const int have_brk_imm = cprisk_breakpoint_immediate_from_state_i(
                        flavor, state_count, old_state, &brk_imm, &brk_pc);

                    if (!cprisk_advance_thread_pc_i(flavor, rep->new_stateCnt, rep->new_state)) {
                        rep->RetCode = KERN_FAILURE;
                    } else if (have_brk_imm &&
                               cprisk_exception_handler_should_passthrough_brk_imm(brk_imm)) {
                        // 非本 SDK 保留的 BRK：不消费，回 KERN_FAILURE 让系统/其他处理器看到。
                        rep->RetCode = KERN_FAILURE;
                    } else if (have_brk_imm) {
                        // 保留 BRK：交给运行时门禁；<0 表示校验失败，0 表示已消费。
                        const int gate_action =
                            cprisk_exception_handler_handle_runtime_gate_brk(brk_imm, brk_pc);
                        if (gate_action < 0) {
                            rep->RetCode = KERN_FAILURE;
                        } else if (gate_action == 0) {
                            (void)cprisk_exception_handler_consume_reserved_brk_imm(brk_imm);
                        }
                    }
                } else if (r->exception == EXC_BAD_ACCESS) {
                    // 仅尝试按 JIT 页解密失败地址；成功才回 KERN_SUCCESS，其余交还系统。
                    void *fault_addr = (void *)(uintptr_t)r->code[1];
                    extern int cprisk_jit_decrypt_page(void *fault_addr);
                    if (cprisk_jit_decrypt_page(fault_addr)) {
                        rep->RetCode = KERN_SUCCESS;
                    } else {
                        rep->RetCode = KERN_FAILURE;
                    }
                } else {
                    rep->RetCode = KERN_FAILURE;
                }
            }

            rep->Head.msgh_size = sizeof(mach_msg_header_t) + sizeof(NDR_record_t) +
                sizeof(kern_return_t) + sizeof(int) + sizeof(mach_msg_type_number_t) +
                rep->new_stateCnt * sizeof(natural_t);
            mach_msg(&rep->Head, MACH_SEND_MSG, rep->Head.msgh_size, 0, MACH_PORT_NULL,
                     MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        }
    }
    return NULL;
}

/* Caller must hold s_mutex. */
// 在持锁状态下创建端口、抢占异常端口并启动处理线程。
// 参数：reclaiming 非 0 表示这是“发现劫持后的重占”，会累加 reclaim_count。
// 返回：无；结果写入 s_status（registered / port_matches / last_register_kern_return）。
// 线程安全：调用方必须持有 s_mutex；已在注册状态时直接返回（幂等）。
// 平台：仅 arm64 真机。
// 失败语义：任一步失败都会释放已申请端口、保持 s_registered=0，等待后续重试；不抛异常。
static void register_locked(int reclaiming) {
    if (atomic_load(&s_registered))
        return;

    s_status.last_reclaim_attempted = reclaiming ? 1u : 0u;
    s_status.last_register_kern_return = (int32_t)KERN_FAILURE;
    s_status.registered = 0u;
    s_status.port_matches = 0u;

    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &s_exception_port);
    if (kr != KERN_SUCCESS) {
        s_status.last_register_kern_return = (int32_t)kr;
        return;
    }

    kr = mach_port_insert_right(mach_task_self(), s_exception_port, s_exception_port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        mach_port_mod_refs(mach_task_self(), s_exception_port, MACH_PORT_RIGHT_RECEIVE, -1);
        s_exception_port = MACH_PORT_NULL;
        s_status.last_register_kern_return = (int32_t)kr;
        return;
    }

    /* Claim BREAKPOINT + BAD_ACCESS (existing) plus SOFTWARE.
     * EXC_SOFTWARE covers SIGTRAP-based attach — LLDB's primary iOS attach
     * vector.  Our handler returns KERN_FAILURE for EXC_SOFTWARE events it
     * doesn't own, preserving normal POSIX signal delivery. */
    // 同时声明 SOFTWARE：覆盖基于 SIGTRAP 的 LLDB attach；不属于我们的软件异常
    // 由处理线程回 KERN_FAILURE，POSIX 信号链仍可继续。
    exception_mask_t mask = EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS | EXC_MASK_SOFTWARE;
    exception_mask_t old_masks[EXC_TYPES_COUNT];
    mach_port_t old_ports[EXC_TYPES_COUNT];
    exception_behavior_t old_behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t old_flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t old_count = EXC_TYPES_COUNT;

    kr = task_swap_exception_ports(mach_task_self(), mask, s_exception_port,
                                   EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64,
                                   old_masks, &old_count, old_ports, old_behaviors, old_flavors);
    s_status.last_register_kern_return = (int32_t)kr;

    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), s_exception_port);
        mach_port_mod_refs(mach_task_self(), s_exception_port, MACH_PORT_RIGHT_RECEIVE, -1);
        s_exception_port = MACH_PORT_NULL;
        return;
    }

    for (mach_msg_type_number_t i = 0; i < old_count; i++) {
        if (old_ports[i] != MACH_PORT_NULL)
            mach_port_deallocate(mach_task_self(), old_ports[i]);
    }

    pthread_t th;
    int rc = pthread_create(&th, NULL, exception_handler_thread, NULL);
    if (rc != 0) {
        // 线程创建失败则撤销端口注册，避免“端口被我们占着却无人接收”导致进程卡死。
        mach_port_deallocate(mach_task_self(), s_exception_port);
        mach_port_mod_refs(mach_task_self(), s_exception_port, MACH_PORT_RIGHT_RECEIVE, -1);
        s_exception_port = MACH_PORT_NULL;
        atomic_store(&s_registered, 0);
        return;
    }
    pthread_detach(th);

    atomic_store(&s_registered, 1);
    s_status.registered = 1u;
    s_status.port_matches = 1u;
    if (s_first_register_monotonic_ns == 0u) {
        s_first_register_monotonic_ns = cprisk_exception_monotonic_time_ns_i();
    }
    if (reclaiming) {
        s_status.reclaim_count += 1u;
    }
}

// 公开入口：注册异常端口（幂等）；通常在 TLS 回调/启动早期调用。
// 参数：无。返回：无；结果见 cprisk_get_exception_handler_snapshot。
// 线程安全：内部取 s_mutex，可与 verify 并发；重复调用无副作用。
// 平台：仅 arm64 真机；其他平台为空桩。
// 失败语义：失败不抛出、不终止，保持未注册状态，后续 verify/重占可再次尝试。
void cprisk_register_exception_handler(void) {
    pthread_mutex_lock(&s_mutex);
    register_locked(0);
    pthread_mutex_unlock(&s_mutex);
}

// 启动早期抓取异常端口指纹，作为“是否被晚阶段替换”的基线。
// 参数：无。返回：无；成功时置 early_phase_captured=1，失败则清空基线。
// 线程安全：持 s_mutex；与注册/校验串行。可在注册前后调用，只查询不修改端口。
// 平台：仅 arm64 真机；非真机为空桩。
// 失败语义：查询失败不致命，仅放弃本阶段基线，后续校验仍做实时端口比对。
void cprisk_capture_early_exception_ports(void) {
    const exception_mask_t mask = EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS;
    uint64_t fingerprint = 0u;

    pthread_mutex_lock(&s_mutex);
    if (cprisk_query_exception_port_fingerprint_i(mask, &fingerprint) == 0) {
        s_early_port_fingerprint = fingerprint;
        s_early_port_fingerprint_valid = 1u;
        s_late_phase_checked = 0u;
        s_status.early_phase_captured = 1u;
        s_status.last_race_detected = 0u;
        s_status.first_register_verify_delta_ns = 0u;
    } else {
        s_early_port_fingerprint = 0u;
        s_early_port_fingerprint_valid = 0u;
        s_status.early_phase_captured = 0u;
        s_status.first_register_verify_delta_ns = 0u;
    }
    pthread_mutex_unlock(&s_mutex);
}

/*
 * TLS 回调时序加固：__mod_init_func 阶段早期抢占验证
 *
 * dyld 初始化顺序：__DATA,__thread_init → __mod_init_func（C++ constructor）
 * Frida gadget 若也使用 __thread_init，其回调可能与 CRiskCore 交错执行。
 * 若 Frida 的 __thread_init 在 CRiskCore 之后执行，会覆盖我们已注册的异常端口。
 *
 * 本 constructor(101) 在 __mod_init_func 阶段执行，此时所有 __thread_init 已完成。
 * 调用 cprisk_verify_exception_handler() 检测端口是否被劫持，若发现非自己的端口
 * 则通过 task_swap_exception_ports 再次抢占，确保异常端口最终由 SDK 持有。
 *
 * 不依赖未公开 dyld 行为，仅利用公开的 constructor 在 mod_init_func 之后执行。
 */
// constructor(101) 在 __mod_init_func 阶段执行，此时所有 __thread_init 已完成；
// 只做一次校验+重占，无参数、无返回值，失败由后续常规校验兜底。
__attribute__((constructor(101)))
static void cprisk_early_exception_port_reclaim(void) {
    cprisk_verify_exception_handler();
}

// 校验异常端口归属；发现被替换时记录劫持并重占（释放锁前完成 register_locked）。
// 参数：无。返回：无；结果写入 s_status。
// 线程安全：持 s_mutex；处理线程不取该锁，因此不会与异常投递路径互等。
// 平台：仅 arm64 真机。
// 失败语义：未注册或端口为空时清标志后返回；查询失败保留 registered 但不宣称匹配。
// 副作用：晚阶段指纹变化时调用 cprisk_integrity_poison_exception_lane() 投毒。
void cprisk_verify_exception_handler(void) {
    pthread_mutex_lock(&s_mutex);
    if (!atomic_load(&s_registered) || s_exception_port == MACH_PORT_NULL) {
        s_status.registered = 0u;
        s_status.port_matches = 0u;
        s_status.last_query_succeeded = 0u;
        pthread_mutex_unlock(&s_mutex);
        return;
    }

    s_status.verify_count += 1u;
    s_status.last_query_succeeded = 0u;
    s_status.last_reclaim_attempted = 0u;
    s_status.last_hijack_detected = 0u;
    if (s_status.first_register_verify_delta_ns == 0u && s_first_register_monotonic_ns != 0u) {
        const uint64_t now_ns = cprisk_exception_monotonic_time_ns_i();
        if (now_ns >= s_first_register_monotonic_ns) {
            s_status.first_register_verify_delta_ns = now_ns - s_first_register_monotonic_ns;
        }
    }

    exception_mask_t mask = EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS | EXC_MASK_SOFTWARE;
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;

    kern_return_t kr = task_get_exception_ports(mach_task_self(), mask, masks, &count,
                                                 ports, behaviors, flavors);
    s_status.last_query_kern_return = (int32_t)kr;
    if (kr != KERN_SUCCESS) {
        pthread_mutex_unlock(&s_mutex);
        return;
    }

    s_status.last_query_succeeded = 1u;
    s_status.registered = 1u;
    if (s_early_port_fingerprint_valid != 0u && s_late_phase_checked == 0u) {
        // 只比较一次：早期基线与首个晚阶段校验之间的差异说明端口在启动窗口被换过。
        const uint64_t current_fingerprint = cprisk_exception_port_fingerprint_i(
            masks, ports, behaviors, flavors, count);
        s_late_phase_checked = 1u;
        if (current_fingerprint != s_early_port_fingerprint) {
            s_status.last_race_detected = 1u;
            cprisk_integrity_poison_exception_lane();
        }
    }

    for (mach_msg_type_number_t i = 0; i < count; i++) {
        if ((masks[i] & (EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS | EXC_MASK_SOFTWARE)) && ports[i] != s_exception_port) {
            // 端口不属于我们：标记劫持、销毁旧端口，释放查询引用后立即重占。
            s_status.last_hijack_detected = 1u;
            s_status.port_matches = 0u;
            atomic_store(&s_registered, 0);
            if (s_exception_port != MACH_PORT_NULL) {
                mach_port_deallocate(mach_task_self(), s_exception_port);
                s_exception_port = MACH_PORT_NULL;
            }
            /* 释放 task_get_exception_ports 返回的端口引用后再重新注册 */
            for (mach_msg_type_number_t j = 0; j < count; j++) {
                if (ports[j] != MACH_PORT_NULL)
                    mach_port_deallocate(mach_task_self(), ports[j]);
            }
            register_locked(1);
            pthread_mutex_unlock(&s_mutex);
            return;
        }
        if (ports[i] != MACH_PORT_NULL)
            mach_port_deallocate(mach_task_self(), ports[i]);
    }
    s_status.port_matches = 1u;
    pthread_mutex_unlock(&s_mutex);
}

// 读取异常处理器状态快照（用于上报/诊断）。
// 参数：out_snapshot 不可为 NULL，由调用方提供。
// 返回：0 成功；-1 参数非法（不写输出）。
// 线程安全：持 s_mutex 整体拷贝，避免读到注册过程中的中间态；可并发。
// 平台：非 arm64 真机返回全零快照（supported=0），调用方不得据此判定“已注册”。
int cprisk_get_exception_handler_snapshot(cprisk_exception_handler_snapshot_t *out_snapshot) {
    if (out_snapshot == NULL) {
        return -1;
    }

    pthread_mutex_lock(&s_mutex);
    *out_snapshot = s_status;
    pthread_mutex_unlock(&s_mutex);
    return 0;
}

// 非 arm64 真机（模拟器/tvOS/watchOS）：所有入口退化为安全空桩，
// 快照清零且 supported=0，调用方据此区分“不支持”与“已注册”。
#else

// 空桩：不注册任何端口；线程安全；无失败路径。
void cprisk_register_exception_handler(void) {
    (void)0;
}

// 空桩：不抓取基线；线程安全；无失败路径。
void cprisk_capture_early_exception_ports(void) {
    (void)0;
}

// 空桩：不做校验；线程安全；无失败路径。
void cprisk_verify_exception_handler(void) {
    (void)0;
}

// 快照：参数非法返回 -1，否则清零并返回 0（supported=0）。
// 线程安全：只写调用方缓冲，可并发。
int cprisk_get_exception_handler_snapshot(cprisk_exception_handler_snapshot_t *out_snapshot) {
    if (out_snapshot == NULL) {
        return -1;
    }

    memset(out_snapshot, 0, sizeof(*out_snapshot));
    return 0;
}

#endif
