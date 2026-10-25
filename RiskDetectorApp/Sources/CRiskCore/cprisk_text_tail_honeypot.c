/*
 * cprisk_text_tail_honeypot.c — __TEXT 尾部的一页蜜罐填充，不被任何代码引用。
 * 用途：运行时可将该页 vm_protect(PROT_NONE)，顺序/越界 dump 读到即 fault，暴露扫描行为。
 * 内容（issue 81）：构建期全零，绝不放口令/token/密钥等伪凭据；运行时由系统熵覆盖。
 * 触发：仅在该页被主动保护后读取才异常；未保护时读到的只是随机字节，无信息价值。
 * 线程/平台：纯静态只读数据，无并发访问；随 __TEXT 加载，与架构无关。
 * 失败：无返回值与失败路径；不得写入机密，也不得依赖其内容做任何判定。
 */
#include <stdint.h>

// 16KB（16384 字节）全零页，放入 __TEXT,__cprisk_pad 且按 16KB 对齐：
// aligned(16384) 保证单独占用一页，保护该页时不会波及相邻代码/常量。
// used 防止编译器/linker 把“无人引用”的填充当作死数据裁剪掉。
// 不变量：内容不得参与任何逻辑；运行时熵填充只写这一页，不越过 16KB。
__attribute__((used, section("__TEXT,__cprisk_pad"), aligned(16384)))
static const uint8_t cprisk_text_honeypot_pad[16384] = {0};
