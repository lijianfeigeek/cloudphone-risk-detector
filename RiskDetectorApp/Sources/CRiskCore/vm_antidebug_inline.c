/*
 *  vm_antidebug_inline.c
 *  CRiskCore
 */

// 文件职责：把反调试检查与“误导/毒化”响应内联进 VM 解释器，作为 opcode 处理器被调用。
// 检测面：PTRACE 标志、arm64 硬件断点寄存器、软件断点指令、异常端口劫持、指令计数时序。
// 采样策略：默认每 32 次 check 才真正探测一次（VM_ADB_CHECK_INTERVAL），
//   把系统调用/寄存器读取开销摊薄到可接受范围。
// 失败语义：检测函数返回 -1 表示“无法判定”，不会被当作命中（避免环境差异误报）；
//   只有明确 >0 才置位并触发响应。非 iOS 平台所有检测编译为空，状态恒为 CLEAN。
// 指令掩码：软件断点只看整条 A64 指令字，不逐条解释指令语义。

#include "include/CRiskCore.h"
#include "include/cprisk_vm_interpreter.h"
#include "include/cprisk_vm_interpreter_internal.h"
#include "vm_antidebug_inline.h"

#include <string.h>

/* Frame stores adb context as opaque bytes; access via cast. */
// 解释器帧用不透明字节数组内嵌反调试上下文，避免公开头文件依赖本模块类型。
// 不变量：adb_ctx_storage 至少 sizeof(vm_antidebug_ctx_t) 且对齐足够；
// 该布局是帧 ABI 的一部分，改动需同步 cprisk_vm_interpreter_internal.h。
#define VM_ADB_CTX_OF(fr_) ((vm_antidebug_ctx_t *)(void *)((fr_)->adb_ctx_storage))

#if defined(__APPLE__)
#include <TargetConditionals.h>
#if defined(TARGET_OS_IOS) && TARGET_OS_IOS
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/task.h>
#endif
#endif

// 毒化魔数：与 VM 状态混合后让后续算术结果静默错误；选择该值无密码学含义，
// 只是显眼且与常见数据模式不同，便于调试时识别。
#define VM_ADB_MAGIC_POISON     0xDEADBEEFu
// 探测间隔：每 32 次 opcode 检查执行一次真实探测，兼顾发现速度与系统调用开销。
#define VM_ADB_CHECK_INTERVAL   32

#if defined(__APPLE__) && defined(TARGET_OS_IOS) && TARGET_OS_IOS
// 通过 sysctl 读取本进程 kinfo_proc，检查 P_TRACED（被 ptrace/调试器附加）。
// 返回 1 = 被跟踪；0 = 未跟踪；-1 = sysctl 失败（无法判定，调用方不当作命中）。
static int vm_adb_is_debugger_attached_i(void) {
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };

    memset(&info, 0, sizeof(info));

    if (sysctl(mib, 4, &info, &info_size, NULL, 0) == -1) {
        return -1;
    }

    return (info.kp_proc.p_flag & P_TRACED) ? 1 : 0;
}

// 读取当前线程的 ARM_DEBUG_STATE64：任一 BVR/BCR（6 组观察点/断点寄存器）非零
// 即认为设置了硬件断点/观察点。返回 1 = 命中；0 = 干净或架构不支持；
// -1 = thread_get_state 失败（无法判定，不当作命中）。
// 每次调用都会获取并释放线程端口，属于系统调用级开销，故受采样间隔限制。
static int vm_adb_check_hw_breakpoint_i(void) {
#if defined(__arm64__) || defined(__aarch64__)
    thread_act_t thread = mach_thread_self();
    arm_debug_state64_t state;
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
    kern_return_t kr;

    kr = thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&state, &count);
    mach_port_deallocate(mach_task_self(), thread);

    if (kr != KERN_SUCCESS) {
        return -1;
    }

    for (int i = 0; i < 6; i++) {
        if (state.__bvr[i] != 0 || state.__bcr[i] != 0) {
            return 1;
        }
    }

    return 0;
#else
    return 0;
#endif
}

// 抽查地址处的 A64 指令字是否被替换成断点类陷阱指令。
// 判定只看“整条指令字 + 掩码”，不解析操作数：
//   - 0xD4A00000 为 HLT #0（调试器常用来暂停执行）；
//   - 0xD4200000 为 BRK #0，且 0xFFE0001F 掩码匹配所有 BRK #imm16。
// 用 memcpy 读 4 字节，避免未对齐地址直接解引用；addr 为 0 时返回 0。
// 返回 1 = 命中；0 = 未命中。
// 集成现状：check_all 未调用本函数，因此 sw_breakpoint_detected 不会由本文件置位；
// 它保留给需要按具体地址抽查的调用路径。
static int vm_adb_check_sw_breakpoint_i(uintptr_t addr) {
    if (addr == 0) {
        return 0;
    }

    uint32_t inst;
    memcpy(&inst, (void *)addr, sizeof(inst));

    // 精确匹配 BRK #0 / HLT #0；掩码分支覆盖 BRK #imm16 的全部编码变体。
    if (inst == 0xD4200000 || inst == 0xD4A00000) {
        return 1;
    }

    if ((inst & 0xFFE0001F) == 0xD4200000) {
        return 1;
    }

    return 0;
}

// 查询任务的异常端口：除本任务自身端口外，任何非空端口都意味着异常可能被
// 外部（调试器/注入框架）先接管。返回 1 = 存在外部端口；0 = 干净；
// -1 = task_get_exception_ports 失败（无法判定，不当作命中）。
// 端口数组按 count 返回，只释放实际返回的条目，避免释放未初始化句柄。
static int vm_adb_check_exception_port_i(void) {
    mach_port_t port = MACH_PORT_NULL;
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = 0;
    kern_return_t kr;

    kr = task_get_exception_ports(mach_task_self(), EXC_MASK_ALL,
                                   masks, &count, ports, behaviors, flavors);

    if (kr != KERN_SUCCESS) {
        return -1;
    }

    int result = 0;
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        if (ports[i] != MACH_PORT_NULL) {
            if (ports[i] != mach_task_self()) {
                result = 1;
            }
            mach_port_deallocate(mach_task_self(), ports[i]);
        }
    }

    return result;
}

// 读取已退休指令计数（PMCCNTR_EL0）。该寄存器只有在 EL0 性能计数器被启用时
// 才有意义；不可用/未启用时返回 0，时序检测会退化为“首轮建基线、永不触发”，
// 因此 0 只能理解为“无时序证据”，不能理解为“时序正常”。
static uint64_t vm_adb_read_instructions_retired_i(void) {
#if defined(__arm64__) || defined(__aarch64__)
    uint64_t value = 0;

    __asm__ __volatile__ (
        "mrs %0, PMCCNTR_EL0" : "=r" (value)
    );

    return value;
#else
    return 0;
#endif
}

// 时序异常：执行固定 100 次迭代的确定性小循环，比较指令计数增量是否超过基线 3 倍。
// 首轮只建立基线；check_count > 5 之前不判定，避开启动期抖动。
// 基线用 EWMA（7/8 旧 + 1/8 新）缓慢跟随频率/负载变化，避免一次异常永久抬高阈值。
// 返回 1 = 明显拖慢（可能被单步/断点拦截）；0 = 正常；-1 = ctx 为空。
static int vm_adb_check_timing_anomaly_i(vm_antidebug_ctx_t *ctx) {
    if (!ctx) {
        return -1;
    }

    uint64_t start_cycles = vm_adb_read_instructions_retired_i();

    volatile uint64_t dummy = 0;
    for (int i = 0; i < 100; i++) {
        dummy ^= (uint64_t)i * 0x9E3779B97F4A7C15ULL;
    }

    (void)dummy;

    uint64_t end_cycles = vm_adb_read_instructions_retired_i();
    uint64_t elapsed = end_cycles - start_cycles;

    if (ctx->baseline_cycles == 0) {
        ctx->baseline_cycles = elapsed;
        return 0;
    }

    uint64_t threshold = ctx->baseline_cycles * 3;
    if (elapsed > threshold && ctx->check_count > 5) {
        return 1;
    }

    ctx->baseline_cycles = (ctx->baseline_cycles * 7 + elapsed) / 8;

    return 0;
}
#endif

// 初始化帧内反调试上下文：清零 → 绑定函数 ID → 设置采样间隔与默认响应模式。
// 默认响应为 POISON（静默毒化）而非 CRASH，避免攻击者立刻察觉被识别。
// iOS 上额外做一次空转测量作为时序基线；ctx 为 NULL 时安全返回。
void vm_antidebug_init(vm_antidebug_ctx_t *ctx, uint64_t func_id) {
    if (!ctx) {
        return;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->func_id = func_id;
    ctx->check_interval = VM_ADB_CHECK_INTERVAL;
    ctx->response_mode = VM_ADB_RESPONSE_POISON;

#if defined(__APPLE__) && defined(TARGET_OS_IOS) && TARGET_OS_IOS
    uint64_t start = vm_adb_read_instructions_retired_i();

    volatile uint64_t temp = 0;
    for (int i = 0; i < 100; i++) {
        temp ^= i;
    }

    (void)temp;

    ctx->baseline_cycles = vm_adb_read_instructions_retired_i() - start;
#endif
}

// 聚合检测入口：每次调用先递增计数，只有计数到达 check_interval 的整数倍才真正探测，
// 其余调用立即返回 CLEAN（这是采样，不是“干净”结论）。
// 探测顺序按“代价/置信度”排列：P_TRACED → 硬件断点 → 异常端口 → 时序；
// 首个命中即返回，并把对应 sticky 标志置 1，后续响应阶段据此决定是否毒化。
// 返回 VM_ADB_ERROR 仅表示 ctx 为 NULL；非 iOS 平台恒为 CLEAN。
vm_antidebug_result_t vm_antidebug_check_all(vm_antidebug_ctx_t *ctx) {
    if (!ctx) {
        return VM_ADB_ERROR;
    }

    ctx->check_count++;

    if ((ctx->check_count % ctx->check_interval) != 0) {
        return VM_ADB_CLEAN;
    }

#if defined(__APPLE__) && defined(TARGET_OS_IOS) && TARGET_OS_IOS
    int debugger = vm_adb_is_debugger_attached_i();
    if (debugger > 0) {
        ctx->debugger_detected = 1;
        return VM_ADB_DETECTED_DEBUGGER;
    }

    int hw_bp = vm_adb_check_hw_breakpoint_i();
    if (hw_bp > 0) {
        ctx->hw_breakpoint_detected = 1;
        return VM_ADB_DETECTED_HW_BP;
    }

    int ex_port = vm_adb_check_exception_port_i();
    if (ex_port > 0) {
        ctx->exception_port_hijacked = 1;
        return VM_ADB_DETECTED_EX_PORT;
    }

    int timing = vm_adb_check_timing_anomaly_i(ctx);
    if (timing > 0) {
        ctx->timing_anomaly = 1;
        return VM_ADB_DETECTED_TIMING;
    }
#endif

    return VM_ADB_CLEAN;
}

// 根据已置位的检测标志执行响应；任何标志都没置位时直接返回（零开销）。
//   各模式共同目标：让 VM 继续“正常”执行但结果错误，或表现为普通崩溃。
// 响应函数只改帧内状态，不做系统调用（除 CRASH 的故意空指针写）。
// ctx 或 fr 为 NULL 时安全返回。
void vm_antidebug_apply_response(vm_antidebug_ctx_t *ctx,
                                  cprisk_vm_interp_frame_t *fr) {
    if (!ctx || !fr) {
        return;
    }

    if (!ctx->debugger_detected && !ctx->hw_breakpoint_detected &&
        !ctx->sw_breakpoint_detected && !ctx->exception_port_hijacked &&
        !ctx->timing_anomaly) {
        return;
    }

    // 四种处置：POISON 静默污染 VM 状态；STALL 拉长解释器停顿；MISLEAD 打乱
    // 控制流指针；CRASH 制造空指针写。默认配置为 POISON，暴露最少。
    switch (ctx->response_mode) {
        case VM_ADB_RESPONSE_POISON: {
            // 同时改链值、会话混合与全部 32 个累加器：即使某一处被攻击者观察到，
            // 其余状态已不可逆污染，恢复原结果需要完整重建 VM 状态。
            fr->opaque_chain ^= VM_ADB_MAGIC_POISON;
            fr->session_mix = (fr->session_mix * 0xC2B2AE35u) ^ VM_ADB_MAGIC_POISON;

            for (int i = 0; i < 32; i++) {
                fr->acc[i] ^= (uint8_t)(VM_ADB_MAGIC_POISON >> ((i % 4) * 8));
                fr->acc_aux[i] ^= (uint8_t)(VM_ADB_MAGIC_POISON >> (((i + 2) % 4) * 8));
            }

            ctx->poison_applied = 1;
            break;
        }

        case VM_ADB_RESPONSE_STALL: {
            fr->adb_stall_count += 1000;
            break;
        }

        case VM_ADB_RESPONSE_MISLEAD: {
            fr->cff_vpc = fr->cff_vpc ^ 0xDEADBEEFu;
            fr->opaque_chain ^= 0xCAFEBABEu;
            break;
        }

        case VM_ADB_RESPONSE_CRASH: {
            *(volatile uint32_t *)0 = 0xDEADBEEF;
            break;
        }

        default:
            break;
    }

    ctx->response_triggered = 1;
}

// opcode 入口：imm 低 4 位选择检查类型（0=聚合，1=调试器，2=硬件断点，3=异常端口，
// 4=时序），bit4..7 为保留的检查深度（当前未使用）。
// 结果写入 acc[0] 供 VM 后续分支使用；非 CLEAN 时立即应用响应。
// 始终返回 CONTINUE（不跳出 VM），避免反调试路径成为控制流特征。
// fr 为 NULL 时返回 LEAVE；非 iOS 平台上所有类型都保持 CLEAN。
cprisk_vm_flow_t vm_op_antidebug_check_execute(cprisk_vm_interp_frame_t *fr,
                                                uint64_t imm) {
    if (!fr) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    uint32_t check_type = imm & 0xF;
    uint32_t check_depth = (imm >> 4) & 0xF;

    (void)check_depth;

    vm_antidebug_result_t result = VM_ADB_CLEAN;

#if defined(__APPLE__) && defined(TARGET_OS_IOS) && TARGET_OS_IOS
    switch (check_type) {
        case 0:
            result = vm_antidebug_check_all(VM_ADB_CTX_OF(fr));
            break;
        case 1:
            result = vm_adb_is_debugger_attached_i() > 0 ? VM_ADB_DETECTED_DEBUGGER : VM_ADB_CLEAN;
            break;
        case 2:
            result = vm_adb_check_hw_breakpoint_i() > 0 ? VM_ADB_DETECTED_HW_BP : VM_ADB_CLEAN;
            break;
        case 3:
            result = vm_adb_check_exception_port_i() > 0 ? VM_ADB_DETECTED_EX_PORT : VM_ADB_CLEAN;
            break;
        case 4:
            result = vm_adb_check_timing_anomaly_i(VM_ADB_CTX_OF(fr)) > 0 ? VM_ADB_DETECTED_TIMING : VM_ADB_CLEAN;
            break;
        default:
            result = VM_ADB_CLEAN;
            break;
    }
#endif

    fr->acc[0] = (uint8_t)result;

    if (result != VM_ADB_CLEAN) {
        vm_antidebug_apply_response(VM_ADB_CTX_OF(fr), fr);
    }

    return CPRISK_VM_FLOW_CONTINUE;
}

// 陷阱 opcode：按 imm 低字节选择自陷方式（SIGTRAP / 非法指令 / BRK / UDF，
// 未知值落到空指针写）。这些指令只在反调试判定后由字节码显式触发，
// 正常执行路径不应到达；选择多种自陷形态是为了让崩溃现场看起来像普通缺陷。
// 函数声明返回 flow，但自陷路径正常情况下不会返回；fr 为 NULL 时返回 LEAVE。
cprisk_vm_flow_t vm_op_antidebug_trap_execute(cprisk_vm_interp_frame_t *fr,
                                               uint64_t imm) {
    if (!fr) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    uint32_t trap_type = imm & 0xFF;

    switch (trap_type) {
        case VM_ADB_TRAP_SIGNAL: {
            raise(SIGTRAP);
            break;
        }

        case VM_ADB_TRAP_ILLEGAL: {
#if defined(__arm64__) || defined(__aarch64__)
            __asm__ __volatile__(".word 0xFFFFFFFF");
#else
            raise(SIGILL);
#endif
            break;
        }

        case VM_ADB_TRAP_BRK: {
#if defined(__arm64__) || defined(__aarch64__)
            __asm__ __volatile__("brk #0xC0DE");
#else
            __builtin_trap();
#endif
            break;
        }

        case VM_ADB_TRAP_UDF: {
#if defined(__arm64__) || defined(__aarch64__)
            __asm__ __volatile__(".word 0x00000000");
#else
            raise(SIGILL);
#endif
            break;
        }

        default: {
            volatile uint32_t *invalid = (volatile uint32_t *)0xDEADBEEF;
            *invalid = 0xCAFEBABE;
            break;
        }
    }

    return CPRISK_VM_FLOW_LEAVE;
}

// 诱饵 opcode：执行与业务无关的 100 轮位混合，把结果异或进 opaque_chain。
// 目的是增加静态/动态分析成本，并让“跳过该 opcode”本身改变 VM 状态。
// decoy_type 保留但当前未分支使用；返回 CONTINUE，fr 为 NULL 时返回 LEAVE。
cprisk_vm_flow_t vm_op_antidebug_decoy_execute(cprisk_vm_interp_frame_t *fr,
                                                uint64_t imm) {
    if (!fr) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    uint32_t decoy_type = imm & 0xF;
    (void)decoy_type;

    volatile uint64_t decoy_var = 0;
    for (int i = 0; i < 100; i++) {
        decoy_var ^= (uint64_t)i * 0x9E3779B97F4A7C15ULL;
        decoy_var = ((decoy_var << 7) | (decoy_var >> 57));
    }

    fr->opaque_chain ^= (uint32_t)(decoy_var ^ (decoy_var >> 32));

    return CPRISK_VM_FLOW_CONTINUE;
}

// 为解释器帧挂接反调试上下文：用帧的 func_id 初始化，并强制 POISON 响应。
// 应在帧开始执行前调用一次；重复调用会重置该帧的检测状态与基线。
void vm_antidebug_apply_to_interp(cprisk_vm_interp_frame_t *fr) {
    if (!fr) {
        return;
    }

    vm_antidebug_init(VM_ADB_CTX_OF(fr), fr->func_id);
    VM_ADB_CTX_OF(fr)->response_mode = VM_ADB_RESPONSE_POISON;
}

// 把 sticky 检测标志压缩成位图：0x01 调试器、0x02 硬件断点、0x04 软件断点、
// 0x08 异常端口、0x10 时序、0x80 已执行响应。
// 注意 0x04 目前没有检测路径会置位（软件断点检查未被 check_all 调用），
// 保留该位是为了与外部协议/历史版本兼容。ctx 为 NULL 返回 0。
uint32_t vm_antidebug_get_detected_flags(vm_antidebug_ctx_t *ctx) {
    if (!ctx) {
        return 0;
    }

    uint32_t flags = 0;
    if (ctx->debugger_detected) flags |= 0x01;
    if (ctx->hw_breakpoint_detected) flags |= 0x02;
    if (ctx->sw_breakpoint_detected) flags |= 0x04;
    if (ctx->exception_port_hijacked) flags |= 0x08;
    if (ctx->timing_anomaly) flags |= 0x10;
    if (ctx->response_triggered) flags |= 0x80;

    return flags;
}
