# CRiskCore 已知实现问题规格书

> 文档版本：1.0
> 编写日期：2026-10-25
> 代码基线：`178f1d4`（`docs(core): add Chinese comments to CRiskCore C layer`）
> 审计范围：`RiskDetectorApp/Sources/CRiskCore/**/*.{c,h,inc}`（96 个文件）
> 审计方式：逐文件静态阅读 + 注释补全过程中的交叉核对；**未做动态模糊测试/红队验证**
> 结论口径：本文记录的是“读代码时确认或高度可疑”的问题，严重级别为初步判断；修复前需按条目中的“验证方式”复现确认。

---

## 1. 严重级别

| 级别 | 定义 | 处理建议 |
|------|------|----------|
| **S1 Critical** | 可导致远程可利用、密钥泄露、完整性保护完全失效 | 立即修复，阻断发布 |
| **S2 High** | 可导致检测/加固功能静默失效、内存安全风险、UB | 本迭代修复 |
| **S3 Medium** | 特定配置/路径下功能不正确，或降低对抗强度 | 排期修复 |
| **S4 Low / Defensive** | 理论风险、防御性加固、可观测性问题 | 有空修复 |
| **Info** | 命名/文档与实现不符，不是功能缺陷 | 修正文档或命名 |

---

## 2. 总览

| ID | 级别 | 文件 | 问题摘要 | 主路径 | 状态 |
|----|------|------|----------|--------|------|
| ISSUE-001 | S2 | `vm_function_ctx.c` | 重复 `pool_free` 导致 `active_count` 下溢 | 否 | 待确认 |
| ISSUE-002 | S2 | `vm_path_explosion.c` | `x*x` 有符号溢出 UB | 否 | 确认 |
| ISSUE-003 | S3 | `vm_path_explosion.c` | `is_decoy_path` 恒为 0，诱饵路径不触发 | 否 | 确认 |
| ISSUE-004 | S3 | `vm_path_explosion.h/.c` | 谓词枚举 0–7，但 `.c` 处理 `case 8` | 否 | 确认 |
| ISSUE-005 | S3 | `cprisk_vm_hardening.c` | `expected` 计算后未参与判定，只能发现整块清零 | 是（VM 取指） | 确认 |
| ISSUE-006 | S2 | `vm_encoding.c` | V2/V3 编解码往返不可逆；`chain_state` 从不推进 | 否 | 确认 |
| ISSUE-007 | S3 | `vm_encoding.c` | `verify_integrity` 只是非零校验和，无密钥/无期望值 | 否 | 确认 |
| ISSUE-008 | S2 | `vm_encrypted_chunk.c` | “execute-only” 实际返回 RW；`mprotect` 失败被吞；重加密先清零可能触发访问异常 | 否 | 确认 |
| ISSUE-009 | S3 | `vm_encrypted_chunk.h` | `auth_tag` 是带密钥 FNV-1a，不是 MAC/AEAD | 否 | 确认（命名/语义） |
| ISSUE-010 | Info | `vm_integrity.h` | `integrity_tag` 无密钥、不是 MAC | 否 | 确认（命名/语义） |
| ISSUE-011 | S3 | `vm_cff_fusion.c` | `encode_execute` 4 字节写回可能跨槽覆盖（环形语义待确认） | 否 | 待确认 |
| ISSUE-012 | Info | `vm_cff_fusion.c/.h` | `verify_integrity` 只做自洽往返，无 MAC | 否 | 确认 |
| ISSUE-013 | S4 | `vm_whitebox_bind.c` | `derive_poison_value` 未校验 `poison_type` 上界 | 否 | 防御性 |
| ISSUE-014 | S4 | `vm_whitebox_bind.c` | `stream_key` 扩展只用 `bytecode_key[0..7]`，熵低于表面长度 | 否 | 确认 |
| ISSUE-015 | S4 | `cprisk_vm_sync_barrier.c` | watchdog 计数 relaxed、非严格 release/acquire；stuck 后不复位 | 是（VM） | 部分为设计 |
| ISSUE-016 | S3 | `vm_reorder.h` | `successor_count` 重复声明，头文件无法编译 | 否 | 确认 |
| ISSUE-017 | S4 | `cprisk_vm_interpreter.c` | `poly == 13` 分支只覆盖奇数 lane 且各访问两次，与其他分支不等价 | 是（取决于 poly） | 待确认 |
| ISSUE-018 | S4 | `vm_dynamic_const.c` | `domain % 6` 映射使域 ID 与宏名不一一对应 | 否 | 设计说明 |
| ISSUE-019 | S4 | `vm_dynamic_const.c` | 派生阈值未做范围裁剪，是否由调用方裁剪需确认 | 否 | 待确认 |

---

## 3. 详细条目

### ISSUE-001 · 函数上下文池重复释放导致计数下溢（S2）

**位置**：`vm_function_ctx.c:730-747`（`vm_function_ctx_pool_free`）

**现状**

```c
void vm_function_ctx_pool_free(vm_function_ctx_pool_t *pool,
                               vm_function_ctx_t *ctx) {
    ...
    pool->active_count--;   // 未校验该槽当前是否已分配
}
```

位图已经清零后，再次释放同一槽仍会执行 `active_count--`。

**触发条件**：同一 `ctx` 被释放两次；或调用方在未分配槽上调用 `pool_free`。

**影响**：
- `active_count` 变成负数（无符号下溢为巨大值）后，`pool_alloc` 的 `active_count >= VM_FUNC_CTX_POOL_SIZE` 判断会永久拒绝分配；
- 池状态与位图不一致，后续 `clear_all`/调试快照不可信。

**是否主路径**：未接入主 VM 执行路径，但属于可复用基础设施。

**建议修复**：
1. `pool_free` 先检查位图对应位是否为 1；为 0 直接返回或返回错误码；
2. 或改为“按位图重新计数”，避免增量计数漂移；
3. 增加 `assert`/`-1` 返回，便于测试暴露重复释放。

**验证方式**：单元测试连续调用两次 `pool_free(pool, same_ctx)`，断言 `active_count` 不减少、位图不变。

---

### ISSUE-002 · 不透明谓词中的有符号溢出 UB（S2）

**位置**：`vm_path_explosion.c:195`、`vm_path_explosion.c:229`

**现状**

```c
int64_t squared = x * x;        // x 为 int64_t
...
if (x * x < 0) { ... }          // 永假谓词
```

`x` 由 32 位 seed 扩展而来；当 `x` 接近 `2^32` 时，`x * x` 超过 `INT64_MAX`，有符号溢出在 C 中是未定义行为（UB）。

**触发条件**：`seed/pc` 组合使 `x` 的绝对值大于约 `3.04e9`（`sqrt(INT64_MAX)`）。

**影响**：
- 编译器可以按“有符号溢出不会发生”做优化，谓词结果可能被折叠/删除；
- 在开启 UBSan 的构建中会直接报错；
- 作为混淆谓词，结果不可预测会削弱“永真/永假”的语义保证。

**建议修复**：使用无符号运算再解释符号，或显式做溢出检查：

```c
uint64_t ux = (uint64_t)x;
uint64_t squared_u = ux * ux;        // 无符号回绕有定义
int64_t squared = (int64_t)squared_u; // 如需按位解释
```

或直接用 `__builtin_mul_overflow` 并定义溢出时的分支语义。

**验证方式**：UBSan 构建 + 对 `seed` 取 `0xFFFFFFFF`、`0x80000000` 等边界值跑谓词。

---

### ISSUE-003 · 诱饵路径永远不触发（S3）

**位置**：`vm_path_explosion.c:449-505`

**现状**：`is_decoy_path` 在 `case 1` 之外全部显式置 0；`case 1` 使用 `vm_opaque_predicate_always_false_i()`，该谓词恒为 0，因此 `is_decoy_path = predicate_result` 也恒为 0。

**影响**：路径爆炸/诱饵分支实际上从未生效，攻击者看到的控制流与“没有诱饵”一致，降低反分析强度。

**是否主路径**：否（该模块当前未接入主 VM 路径）。

**建议修复**：明确诱饵触发条件，例如按 `seed` 选择一个“永假谓词但运行时不可静态判定”的分支，或把 `is_decoy_path` 设为“谓词结果为假且满足额外条件”。修复前先确认是否为占位实现。

**验证方式**：构造不同 `seed/pc`，断言至少存在一组输入使 `is_decoy_path == 1`。

---

### ISSUE-004 · 谓词枚举与实现不一致（S3）

**位置**：`vm_path_explosion.h:50-58`、`vm_path_explosion.c:502`

**现状**：头文件 `vm_opaque_predicate_type_t` 只定义 0–7；`.c` 中有 `case 8:`（白盒查表）分支。

**影响**：
- `case 8` 永远不可达（除非调用方强制转换整数传入 8）；
- 头文件与实现语义不一致，后续维护容易误判。

**建议修复**：在枚举中补上 `VM_OPAQUE_PREDICATE_WHITEBOX = 8`，或删除 `case 8` 并说明保留原因。

---

### ISSUE-005 · 块完整性校验的期望值未参与判定（S3）

**位置**：`cprisk_vm_hardening.c:390-404`

**现状**

```c
uint64_t expected = fr->decrypt_block_key;
expected ^= block_id;
expected *= VMH_FNV_PRIME;
...
if (block_hash == 0ULL) { fr->vm_integrity_corrupted = 1; }
```

`expected` 计算后未使用，实际只检测“块哈希为 0”。

**影响**：
- 能发现“整块被清零”，但无法发现定向指令替换（只要哈希非零）；
- 变量未使用可能触发编译警告；注释已说明是预留。

**建议修复**：
1. 短期：删除 `expected` 或标记 `(void)expected`，并在文档中明确当前检测边界；
2. 长期：为每个函数预计算块哈希表（或 MAC），在 TOC/加载时校验表本身的完整性。

**验证方式**：构造“替换一条指令但保持哈希非零”的块，确认当前实现不报警；接入预计算表后应报警。

---

### ISSUE-006 · V2/V3 编解码不可逆、级联状态不推进（S2）

**位置**：`vm_encoding.c:485-515`、`vm_encoding.c:657-684`

**现状**

1. 解码 V2/V3 时把 `operand` 的**内存地址**传给 `decode_operand`，而编码端按**大端**逐字节处理；小端平台上字节序相反，往返不保证还原。
2. `vm_encoding_advance_chain()` 已实现，但仓库内**没有任何调用点**（`grep -rn advance_chain` 为空），V3 的 `chain_state` 在编码/解码路径中从不推进。
3. 代码注释已自认：“当前 V2/V3 编解码因此不保证可逆（模块未接入主路径）”。

**影响**：若后续把该模块接入主路径，编码器产出的字节码可能无法被解码器还原；V3 级联实际上退化为静态 XOR。

**是否主路径**：否。

**建议修复**：
1. 统一字节序：编码/解码都用显式大端读写函数（如 `read_be64/write_be64`），不要依赖主机字节序；
2. 在编码完成、解码开始处调用 `advance_chain`，并保证编码/解码两侧推进顺序一致；
3. 增加 round-trip 属性测试（随机 opcode/operand/长度）。

---

### ISSUE-007 · 编码完整性校验不是完整性校验（S3）

**位置**：`vm_encoding.c:696-714`

**现状**：`vm_encoding_verify_integrity` 用 `checksum = checksum * 31 + byte` 做滚动校验和，只判断结果非零；没有保存期望值，也没有密钥。

**影响**：任何能改字节的人都可以构造出非零校验和；该函数不能作为篡改检测或 fail-closed 依据。

**建议修复**：若需要完整性，改为带密钥的 MAC（如 HMAC-SHA256 截断），并把期望值存于可信基线；否则在头文件中明确标注“仅健全性检查”，避免调用方误用。

---

### ISSUE-008 · “execute-only” 内存分配与降权路径不可靠（S2）

**位置**：`vm_encrypted_chunk.c:88-111`、`138-160`、`240-253`

**现状**

1. `vm_chunk_alloc_execute_only()` 实际以 `PROT_READ | PROT_WRITE` 分配，函数名与行为不符；
2. 后续 `mprotect(PROT_EXEC)` 失败被静默忽略，映射仍保持 RW；
3. `vm_chunk_reencrypt()` 在 `mprotect(PROT_EXEC)` 成功后先 `cprisk_secure_zero()`，此时映射已无写权限，可能触发访问异常；
4. 注释已记录这些风险。

**影响**：
- W^X 加固目标未达成（RW 映射可被改写）；
- 重加密路径在真实设备上可能崩溃，而不是返回错误码。

**是否主路径**：否，但属于 VM chunk 基础设施。

**建议修复**：
1. 重命名或拆分接口：`alloc_rw()` → `protect_exec_only()` → `decrypt_into()`；
2. `mprotect` 失败返回明确错误码，由调用方决定是否继续；
3. 重加密前先 `mprotect(PROT_READ | PROT_WRITE)`，清零后再降权；
4. 增加平台能力探测（iOS 是否允许 `PROT_EXEC` 单独映射）。

---

### ISSUE-009 / ISSUE-010 · `auth_tag` / `integrity_tag` 不是 MAC（S3 / Info）

**位置**：`vm_encrypted_chunk.h:2,32,45,127`、`vm_integrity.h:36,44,51`

**现状**：
- `auth_tag[16]` 实际是**带密钥 FNV-1a 校验和**，不是 MAC/AEAD；
- `integrity_tag[8]` 无密钥，只是简化校验和；
- 两者名字容易被误读为“认证/防篡改”。

**影响**：如果调用方把它当作 MAC 使用，会高估安全属性；FNV 不是抗碰撞的密码学构造。

**建议修复**：
1. 重命名为 `checksum_tag` / `digest_tag`，或在头文件显式写“非 MAC、不可用于认证”；
2. 若设计要求防伪造，改用 HMAC-SHA256 截断，并绑定 chunk_id/长度/nonce。

---

### ISSUE-011 · CFF `encode_execute` 跨槽写回（S3，待确认）

**位置**：`vm_cff_fusion.c:370-390`

**现状**

```c
const uint32_t slot = imm & 0x1Fu;          // 0..31
fr->acc[slot] = ...;
fr->acc[(slot + 1u) & 31u] = ...;
fr->acc[(slot + 2u) & 31u] = ...;
fr->acc[(slot + 3u) & 31u] = ...;
```

当 `slot` 为 29/30/31 时，写回会回绕到 `acc[0..2]`，可能覆盖 `mix_with_acc` 刚读取的 `acc[0..3]`。

**影响**：若这是有意的环形缓冲语义，则不是 bug；若调用方期望“只修改 slot..slot+3 且不回绕”，则会产生跨槽污染。

**待确认**：查看 CFF 字节码生成器是否保证 `slot <= 28`；或在解码端验证对称回绕是否一致。

**建议修复**：在文档中明确环形语义；若不允许回绕，增加 `if (slot + 3 > 31) return LEAVE;`。

---

### ISSUE-012 · CFF `verify_integrity` 只做自洽检查（Info）

**位置**：`vm_cff_fusion.c:529+`

**现状**：`verify_integrity` 重新编码/解码自身状态并比较，无密钥、无 MAC；能发现内存破坏，但不能防定向伪造。

**建议**：文档标注为“自洽性检查”，不要作为安全边界。

---

### ISSUE-013 · whitebox poison 派生未校验上界（S4）

**位置**：`vm_whitebox_bind.c:357-371`

**现状**

```c
poison |= ((uint64_t)poison_key[i + (uint8_t)poison_type]) << (i * 8);
```

若 `poison_type > 24`，`i + poison_type` 最大可到 31 以上，越界读。

**当前风险**：`vm_wb_poison_type_t` 只定义 0–4，正常调用不会越界；但函数接受枚举，C 调用方可以强转任意整数。

**建议修复**：入口处增加 `if ((unsigned)poison_type > 24u) return 0;` 或 `assert`；更稳妥的是用枚举范围检查 + 返回错误码。

---

### ISSUE-014 · whitebox `stream_key` 扩展熵不足（S4）

**位置**：`vm_whitebox_bind.c:295-299`

**现状**

```c
memcpy(out_params->stream_key, bytecode_key + 24, 8);
for (i = 0; i < 32; i++)
    out_params->stream_key[i] = bytecode_key[i % 8] ^ (uint8_t)i;
```

只使用 `bytecode_key[0..7]`，32 字节 `stream_key` 的实际熵上限是 64 bit。

**影响**：降低流密钥强度；如果用于加密/混淆，应使用完整 32 字节密钥。

**建议修复**：使用 `bytecode_key` 的 32 字节全部参与扩展（如 HKDF/ChaCha 派生），或至少使用 16/24 字节窗口。

---

### ISSUE-015 · VM 同步屏障的内存序与 stuck 语义（S4，部分设计）

**位置**：`cprisk_vm_sync_barrier.c:49,55,68,127,162`

**现状**
- watchdog 计数使用 `memory_order_relaxed` 递增/读取；
- step 的 acquire 不构成与 relaxed 写入的严格 release/acquire 配对；
- `s_global_stuck` 一旦置位永不复位（注释说明这是刻意设计）。

**影响**：
- 在弱内存序 CPU 上，watchdog 计数可能延迟可见，导致 stuck 判定偏晚或偶发；
- 若“永不复位”是设计，则不是 bug，但需要在文档中明确生命周期。

**建议修复**：
1. 若计数只用于启发式，可保留 relaxed，但注释说明“允许延迟”；
2. 若需要严格同步，使用 `memory_order_release` 写、`acquire` 读，或改为 `atomic_thread_fence`；
3. 明确 `stuck` 是否应随新会话/新帧复位。

---

### ISSUE-016 · `vm_reorder.h` 无法编译（S3）

**位置**：`vm_reorder.h:126-139`

**现状**：`vm_basic_block_t` 中 `successor_count` 被声明两次；该头文件当前无 `.c` 实现、无任何 `#include`，因此主构建不受影响。

**影响**：未来一旦 include 会直接编译失败；也说明该模块是未完成/废弃状态。

**建议修复**：确认是 `predecessor_count` + `successor_count` 两个字段，改名；或删除未使用头文件并在仓库中标注废弃。

---

### ISSUE-017 · 解释器 `poly == 13` 分支语义不等价（S4，待确认）

**位置**：`cprisk_vm_interpreter.c:905`、`cprisk_vm_interpreter.c:1086`

**现状**

```c
uint32_t i = (t * 2u + 1u) & 7u;   // raw_region
uint32_t i = (t * 2u + 3u) & 7u;   // lane_family
```

`t` 从 0 到 7，`i` 只取奇数（1,3,5,7），每个 lane 被访问两次；其他 poly 分支通常覆盖 0..7 各一次。

**影响**：若 `poly` 是随机选择，结果的叠加次数与其他分支不同；对 XOR 自消，对 ADD/SUB/MUL 会叠加。可能是有意的“路径/权重差异”，也可能是复制粘贴错误。

**待确认**：查看 poly 生成器/测试向量，确认该分支是否设计为“只扰动奇数 lane”。

**建议**：若为设计，注释说明；若为笔误，改为 `(t + offset) & 7` 覆盖全部 lane。

---

### ISSUE-018 · 动态常量域映射不是一一对应（S4，设计说明）

**位置**：`vm_dynamic_const.c:210-241`

**现状**：白盒域 = `VM_CONST_DERIVE_DOMAIN_BASE + (domain % 6)`，实际只落在 10..15；调用方传入的 domain 值（如 0/6/12）会映射到同一域。

**影响**：不同用途的常量可能共享白盒域，域分隔强度低于宏名暗示；确定性仍然成立。

**建议**：若域数量不足，扩白盒域空间；或在文档中明确“最多 6 个派生域”。

---

### ISSUE-019 · 阈值派生未裁剪（S4，待确认）

**位置**：`vm_dynamic_const.c:265-270`

**现状**：`vm_const_derive_cmp_threshold` 返回 32 位派生值，本身不做范围裁剪；是否由调用方裁剪需确认。

**影响**：若调用方直接拿它做比较阈值，可能得到超出预期范围的值，导致比较恒真/恒假。

**建议**：在函数内增加 `min/max` 裁剪，或提供 `..._bounded(min, max)` 变体，并在头文件注明范围。

---

## 4. 建议修复顺序

1. **ISSUE-002**（UB，先消除未定义行为）
2. **ISSUE-001**（池计数下溢，基础设施稳定性）
3. **ISSUE-006 / ISSUE-008**（若相关模块准备接入主路径，必须先修）
4. **ISSUE-003 / ISSUE-005 / ISSUE-016**（对抗强度与可维护性）
5. 其余 S3/S4 按迭代排期

---

## 5. 复现与验证约定

本文所有行号基于 `178f1d4`。修复时建议：

1. 先补一个最小回归测试（单元测试或独立 harness）复现问题；
2. 修复后用 UBSan/ASan 构建复核（至少覆盖 `vm_path_explosion`、`vm_function_ctx`、`vm_encrypted_chunk`）；
3. 对 VM 相关模块增加 round-trip / 边界值属性测试；
4. 若问题属于“设计即如此”，在头文件注释中写明，不要只靠口头约定。

### 常用命令

```bash
# 仅注释校验（防止修复时误改无关代码）
python3 -I RiskDetectorApp/Scripts/verify_c_comments.py "$PWD" <file>

# C 语法检查（arm64e 真机 SDK）
xcrun --sdk iphoneos clang -arch arm64e -miphoneos-version-min=14.0 \
  -fsyntax-only -isysroot "$(xcrun --sdk iphoneos --show-sdk-path)" \
  -I RiskDetectorApp/Sources/CRiskCore/include <file.c>

# SDK 构建
swift build --package-path RiskDetectorApp

# iOS 模拟器构建
xcodebuild -project RiskDetectorApp/RiskDetectorApp.xcodeproj \
  -scheme RiskDetectorApp -configuration Debug \
  -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO build
```

---

## 6. 不在本文范围

- `cprisk-armor`（构建期加固工具，约 2 万行）
- `CloudPhoneRiskAppCore` / Demo App（约 1.8k 行）
- Swift SDK 层（已完成注释，未做实现审计）
- 动态行为、真实设备对抗、红队验证

如果需要对上述范围做同样的审计，建议单独出文档，避免与 C 核心问题混在一起。
