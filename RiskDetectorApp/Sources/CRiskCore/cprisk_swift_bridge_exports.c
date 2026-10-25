// Swift 桥接别名导出表。
//
// 职责：把 `cprisk_swift_bridge.h` 中的导入索引映射为稳定的 `cpra_NNNN` 符号。
// Swift 侧通过 `cprisk_resolve_import(index)` 解析到这些别名，再由别名转发到
// 真正的 `cprisk_*` 实现。
//
// 安全目的：
//   - Swift 二进制中不出现真实 C 符号名，增加静态定位成本；
//   - 同一实现可被多个调用点使用不同别名，降低单点 Hook 的收益；
//   - 别名与索引的对应关系是 ABI 契约，允许追加，禁止重排或复用编号。
//
// 不变量：
//   - `cpra_NNNN` 的 NNNN 必须等于 `CPRISK_SWIFT_BRIDGE_IMPORT_* - BASE + 1`；
//   - 新别名只能追加在表尾，并同步更新头文件索引与 COUNT；
//   - 转发函数的签名必须与目标函数完全一致，否则是未定义行为。

#include "include/CRiskCore.h"

// 确保别名符号在最终二进制中可见且不会被链接器当成未使用代码删除。
// `used` 让编译器保留，`visibility("default")` 让运行期导入解析能查找到。
#if defined(__GNUC__)
#define CPRISK_ALIAS_EXPORT __attribute__((visibility("default"), used))
#else
#define CPRISK_ALIAS_EXPORT
#endif

// 证书固定（pinning）使用的 SHA-256 摘要长度。
#define CPRISK_PIN_SHA256_DIGEST_LENGTH 32u

// 校验候选 SHA-256 摘要是否命中打包的 pinset。
//
// 返回契约：
//   -1 = 参数错误（候选摘要为 NULL 或长度不是 32 字节；pinset 为 NULL 且 pin_count > 0）
//    0 = 未命中（包括 pin_count == 0，即“未配置 pin”）
//    1 = 命中
//
// 参数：
//   - candidate_digest: 候选摘要，必须是 32 字节；调用方保留所有权。
//   - candidate_len: 候选摘要长度，必须等于 32。
//   - packed_pins: 连续排列的 32 字节摘要数组；pin_count 为条目数。
//   - pin_count: pinset 条目数；0 表示未配置，返回 0 而不是错误。
//
// 线程安全：纯函数，无全局状态，可并发调用。
// 平台：全平台可用，无 syscall / 架构依赖。
int cprisk_pinset_contains_sha256_digest(
    const uint8_t *candidate_digest,
    size_t candidate_len,
    const uint8_t *packed_pins,
    size_t pin_count
) {
    size_t pin_index = 0u;
    if (candidate_digest == NULL || candidate_len != CPRISK_PIN_SHA256_DIGEST_LENGTH) {
        return -1;
    }
    if (pin_count == 0u) {
        return 0;
    }
    if (packed_pins == NULL) {
        return -1;
    }
    {
        uint8_t any_match = 0u;
        for (pin_index = 0u; pin_index < pin_count; ++pin_index) {
            const uint8_t *slot = packed_pins + (pin_index * CPRISK_PIN_SHA256_DIGEST_LENGTH);
            uint8_t diff = 0u;
            size_t byte_index = 0u;
            // 常量时间比较：遍历全部 32 字节并累积 XOR，不提前 break，
            // 避免通过比较耗时推断“命中了哪一位”。
            for (byte_index = 0u; byte_index < CPRISK_PIN_SHA256_DIGEST_LENGTH; ++byte_index) {
                diff |= (uint8_t)(candidate_digest[byte_index] ^ slot[byte_index]);
            }
            any_match |= (uint8_t)(diff == 0u);
        }
        return any_match != 0u ? 1 : 0;
    }
}

// 生成一个返回 void 的转发别名。
// - alias:  对外暴露的稳定符号名（cpra_NNNN）
// - target: 真实实现（cprisk_*）
// - decl_args: 别名的参数声明，必须与 target 完全一致
// - call_args: 传给 target 的实参列表
#define CPRISK_ALIAS_VOID(alias, target, decl_args, call_args) \
    CPRISK_ALIAS_EXPORT void alias decl_args {               \
        target call_args;                                   \
    }

// 生成一个带返回值的转发别名；返回值原样透传，不做任何转换或错误码改写。
#define CPRISK_ALIAS_RET(ret, alias, target, decl_args, call_args) \
    CPRISK_ALIAS_EXPORT ret alias decl_args {                    \
        return target call_args;                                \
    }

// 以下别名按目标函数名字母序排列，便于合并与审计；
// 编号一旦分配即冻结，新增条目只能追加到表尾。
//
// MARK: - 直 syscall / 地址与页保护（0001–0008）
CPRISK_ALIAS_RET(int, cpra_0001, cprisk_access_direct,
                 (const char *path, int amode, int *error_out),
                 (path, amode, error_out))
CPRISK_ALIAS_RET(int, cpra_0002, cprisk_addr_in_any_image,
                 (const void *addr),
                 (addr))
CPRISK_ALIAS_RET(int, cpra_0003, cprisk_advance_ucontext_pc,
                 (void *uap, uintptr_t advance_bytes),
                 (uap, advance_bytes))
CPRISK_ALIAS_RET(int, cpra_0004, cprisk_armor_vm_protect,
                 (void *addr, size_t len, int prot),
                 (addr, len, prot))
CPRISK_ALIAS_RET(int, cpra_0005, cprisk_check_init_timing,
                 (void),
                 ())
CPRISK_ALIAS_VOID(cpra_0006, cprisk_cleanup_protection,
                  (void),
                  ())
CPRISK_ALIAS_RET(int, cpra_0007, cprisk_close_direct,
                 (int fd, int *error_out),
                 (fd, error_out))
CPRISK_ALIAS_RET(int, cpra_0008, cprisk_connect_direct,
                 (int sockfd, const struct sockaddr *addr, socklen_t addrlen, int *error_out),
                 (sockfd, addr, addrlen, error_out))
// MARK: - 密码学追踪 / csops 调试状态（0009–0014）
CPRISK_ALIAS_RET(uint32_t, cpra_0009, cprisk_crypto_trace_consume_flags_i,
                 (void),
                 ())
CPRISK_ALIAS_RET(uint64_t, cpra_0010, cprisk_crypto_trace_last_ns_i,
                 (void),
                 ())
CPRISK_ALIAS_RET(uint32_t, cpra_0011, cprisk_crypto_trace_peek_flags_i,
                 (void),
                 ())
CPRISK_ALIAS_VOID(cpra_0012, cprisk_crypto_trace_primitive_enter_i,
                  (void),
                  ())
CPRISK_ALIAS_RET(int, cpra_0013, cprisk_csops_debug_check,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0014, cprisk_csops_status_flags,
                 (uint32_t *flags_out, int *error_out),
                 (flags_out, error_out))
// MARK: - deny-attach / 设备密钥（0015–0017）
CPRISK_ALIAS_VOID(cpra_0015, cprisk_deny_attach,
                  (void),
                  ())
CPRISK_ALIAS_RET(int, cpra_0016, cprisk_deny_attach_status,
                 (int *error_out),
                 (error_out))
CPRISK_ALIAS_RET(int, cpra_0017, cprisk_derive_device_key,
                 (const uint8_t *root_key, uint8_t out_device_key[CPRISK_ARMOR_KEY_SIZE]),
                 (root_key, out_device_key))
// MARK: - 调试/JIT/DBI 探针与 Frida 快照（0018–0026）
CPRISK_ALIAS_RET(int, cpra_0018, cprisk_detect_dbi_markers,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0019, cprisk_detect_developer_disk,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0020, cprisk_detect_hardware_breakpoints,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0021, cprisk_detect_single_stepping,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0022, cprisk_detect_suspicious_threads,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0023, cprisk_detect_thread_exception_ports,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0024, cprisk_detect_tty_debug,
                 (void),
                 ())
CPRISK_ALIAS_VOID(cpra_0025, cprisk_erase_macho_header,
                  (void),
                  ())
CPRISK_ALIAS_RET(int, cpra_0026, cprisk_frida_runtime_snapshot,
                 (cprisk_frida_runtime_snapshot_t *out),
                 (out))
// MARK: - 运行期快照、时序与 mprotect 诊断（0027–0043）
CPRISK_ALIAS_RET(int, cpra_0027, cprisk_get_anti_debug_watchdog_snapshot,
                 (cprisk_anti_debug_watchdog_snapshot_t *out_snapshot),
                 (out_snapshot))
CPRISK_ALIAS_RET(int, cpra_0028, cprisk_get_antidebug_plan_snapshot,
                 (cprisk_antidebug_plan_snapshot_t *out_snapshot),
                 (out_snapshot))
CPRISK_ALIAS_RET(uint64_t, cpra_0029, cprisk_get_init_elapsed_ns,
                 (void),
                 ())
CPRISK_ALIAS_RET(uint32_t, cpra_0030, cprisk_get_last_dbi_marker_flags,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0031, cprisk_get_last_dbi_marker_hit_count,
                 (void),
                 ())
CPRISK_ALIAS_RET(uint32_t, cpra_0032, cprisk_get_last_pac_cfi_flags,
                 (void),
                 ())
CPRISK_ALIAS_RET(uint32_t, cpra_0033, cprisk_get_last_timing_anomaly_flags,
                 (void),
                 ())
CPRISK_ALIAS_RET(uint64_t, cpra_0034, cprisk_get_last_timing_probe_max_ns,
                 (void),
                 ())
CPRISK_ALIAS_RET(uint64_t, cpra_0035, cprisk_get_last_timing_probe_median_ns,
                 (void),
                 ())
CPRISK_ALIAS_RET(uint64_t, cpra_0036, cprisk_get_last_timing_probe_threshold_ns,
                 (void),
                 ())
CPRISK_ALIAS_RET(uint32_t, cpra_0037, cprisk_get_mprotect_consecutive_full_fail_streak,
                 (void),
                 ())
CPRISK_ALIAS_RET(uint32_t, cpra_0038, cprisk_get_mprotect_direct_failure_count,
                 (void),
                 ())
CPRISK_ALIAS_RET(uint32_t, cpra_0039, cprisk_get_mprotect_fail_streak_threshold,
                 (void),
                 ())
CPRISK_ALIAS_RET(uint32_t, cpra_0040, cprisk_get_mprotect_fallback_success_count,
                 (void),
                 ())
CPRISK_ALIAS_RET(cprisk_runtime_hardening_mode_t, cpra_0041, cprisk_get_runtime_hardening_mode,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0042, cprisk_get_runtime_material,
                 (uint8_t out_material[32]),
                 (out_material))
CPRISK_ALIAS_RET(uint32_t, cpra_0043, cprisk_get_vm_mprotect_crosscheck_mismatch_count,
                 (void),
                 ())
// MARK: - 进程身份、KDF 与完整性状态（0044–0057）
CPRISK_ALIAS_RET(uint32_t, cpra_0044, cprisk_get_vm_mprotect_mach_trap_mismatch_count,
                 (void),
                 ())
CPRISK_ALIAS_RET(pid_t, cpra_0045, cprisk_getpid_direct,
                 (void),
                 ())
CPRISK_ALIAS_RET(pid_t, cpra_0046, cprisk_getppid_direct,
                 (void),
                 ())
CPRISK_ALIAS_RET(uid_t, cpra_0047, cprisk_getuid_direct,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0048, cprisk_mac_sha256_hex,
                 (const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                  char out_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1]),
                 (key, key_len, msg, msg_len, out_hex))
CPRISK_ALIAS_RET(int, cpra_0049, cprisk_init_hybrid_kdf,
                 (const uint8_t *root_key),
                 (root_key))
CPRISK_ALIAS_RET(int, cpra_0050, cprisk_init_protection,
                 (const uint8_t *root_key, size_t root_key_len),
                 (root_key, root_key_len))
CPRISK_ALIAS_VOID(cpra_0051, cprisk_integrity_poison_code_signing_lane,
                  (void),
                  ())
CPRISK_ALIAS_VOID(cpra_0052, cprisk_integrity_poison_svc_iface_lane,
                  (void),
                  ())
CPRISK_ALIAS_RET(int, cpra_0053, cprisk_is_being_traced,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0054, cprisk_is_being_traced_redundant,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0055, cprisk_is_cntpct_clock_available,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0056, cprisk_is_device_bound,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0057, cprisk_is_integrity_poisoned,
                 (void),
                 ())
// MARK: - MTE / OBF / PAC 辅助（0058–0065）
CPRISK_ALIAS_RET(int, cpra_0058, cprisk_is_mprotect_tampered,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0059, cprisk_lstat_direct,
                 (const char *path, struct stat *sb, int *error_out),
                 (path, sb, error_out))
CPRISK_ALIAS_RET(int, cpra_0060, cprisk_mte_guard_snapshot,
                 (cprisk_mte_guard_snapshot_t *out_state),
                 (out_state))
CPRISK_ALIAS_RET(int, cpra_0061, cprisk_obf_decode_sha256_tag,
                 (uint32_t domain, uint32_t key_id, const uint8_t *enc, size_t enc_len, char *out, size_t out_sz),
                 (domain, key_id, enc, enc_len, out, out_sz))
CPRISK_ALIAS_RET(void *, cpra_0062, cprisk_pac_auth_function_pointer,
                 (const void *ptr, uintptr_t discriminator),
                 (ptr, discriminator))
CPRISK_ALIAS_RET(int, cpra_0063, cprisk_pac_is_arm64e_supported,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0064, cprisk_pac_self_test,
                 (uintptr_t discriminator),
                 (discriminator))
CPRISK_ALIAS_RET(void *, cpra_0065, cprisk_pac_sign_function_pointer,
                 (const void *ptr, uintptr_t discriminator),
                 (ptr, discriminator))
// MARK: - 信号探针、页保护与完整性重检（0066–0073）
CPRISK_ALIAS_RET(int, cpra_0066, cprisk_pac_validate_core_callbacks,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0067, cprisk_probe_debugger_via_signal,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0068, cprisk_probe_path_snapshot,
                 (const char *path, cprisk_path_probe_snapshot_t *out_snapshot),
                 (path, out_snapshot))
CPRISK_ALIAS_RET(int, cpra_0069, cprisk_protect_decrypted_pages,
                 (void *region, size_t len),
                 (region, len))
CPRISK_ALIAS_RET(int, cpra_0070, cprisk_read_full_anchor_hash,
                 (uint8_t *out_hash),
                 (out_hash))
CPRISK_ALIAS_RET(int, cpra_0071, cprisk_recheck_integrity,
                 (void),
                 ())
CPRISK_ALIAS_VOID(cpra_0072, cprisk_register_exception_handler,
                  (void),
                  ())
CPRISK_ALIAS_RET(int, cpra_0073, cprisk_restore_macho_header,
                 (void),
                 ())
// MARK: - 扫描器、加固模式、签名与生命周期（0074–0087）
CPRISK_ALIAS_RET(uint32_t, cpra_0074, cprisk_run_all_signal_probes,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0075, cprisk_scan_arm64_instant_return_nop_patch_prefix,
                 (const void *func_ptr, size_t prefix_bytes),
                 (func_ptr, prefix_bytes))
CPRISK_ALIAS_RET(int, cpra_0076, cprisk_scan_instant_return_key_symbols_prefix,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0077, cprisk_scan_software_breakpoints,
                 (const void *func_ptr, size_t size),
                 (func_ptr, size))
CPRISK_ALIAS_VOID(cpra_0078, cprisk_set_runtime_hardening_mode,
                  (cprisk_runtime_hardening_mode_t mode),
                  (mode))
CPRISK_ALIAS_RET(int, cpra_0079, cprisk_sign_with_derived_key_and_request_binding_digest,
                 (const uint8_t *base_key, size_t base_key_len, const uint8_t *msg, size_t msg_len,
                  const uint8_t request_binding_digest[32],
                  char out_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1]),
                 (base_key, base_key_len, msg, msg_len, request_binding_digest, out_hex))
CPRISK_ALIAS_RET(int, cpra_0080, cprisk_socket_direct,
                 (int domain, int type, int protocol, int *error_out),
                 (domain, type, protocol, error_out))
CPRISK_ALIAS_RET(int, cpra_0081, cprisk_spawn_iface_probe,
                 (cprisk_spawn_iface_probe_result_t *out),
                 (out))
CPRISK_ALIAS_RET(int, cpra_0082, cprisk_start_anti_debug_watchdog,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0083, cprisk_start_anti_dump_probe,
                 (int interval_seconds),
                 (interval_seconds))
CPRISK_ALIAS_RET(int, cpra_0084, cprisk_stat_direct,
                 (const char *path, struct stat *sb, int *error_out),
                 (path, sb, error_out))
CPRISK_ALIAS_VOID(cpra_0085, cprisk_stop_anti_debug_watchdog,
                  (void),
                  ())
CPRISK_ALIAS_VOID(cpra_0086, cprisk_stop_anti_dump_probe,
                  (void),
                  ())
CPRISK_ALIAS_RET(int, cpra_0087, cprisk_sysctl_direct,
                 (int *name, unsigned int namelen, void *oldp, size_t *oldlenp,
                  const void *newp, size_t newlen, int *error_out),
                 (name, namelen, oldp, oldlenp, newp, newlen, error_out))
// MARK: - 测试注入 / 白盒辅助（0088–0099）
CPRISK_ALIAS_RET(int, cpra_0088, cprisk_sysctlbyname_direct,
                 (const char *name, void *oldp, size_t *oldlenp, const void *newp, size_t newlen, int *error_out),
                 (name, oldp, oldlenp, newp, newlen, error_out))
CPRISK_ALIAS_VOID(cpra_0089, cprisk_test_clear_whitebox_bundle,
                  (void),
                  ())
CPRISK_ALIAS_RET(uint64_t, cpra_0090, cprisk_test_init_timing_threshold_ns_for_machine,
                 (const char *machine, cprisk_runtime_hardening_mode_t mode),
                 (machine, mode))
CPRISK_ALIAS_VOID(cpra_0091, cprisk_test_mprotect_reset_tamper_state,
                  (void),
                  ())
CPRISK_ALIAS_VOID(cpra_0092, cprisk_test_mprotect_set_fail_streak_threshold,
                  (uint32_t threshold),
                  (threshold))
CPRISK_ALIAS_VOID(cpra_0093, cprisk_test_mprotect_set_force_direct_fail,
                  (int enabled),
                  (enabled))
CPRISK_ALIAS_VOID(cpra_0094, cprisk_test_mprotect_set_force_fallback_fail,
                  (int enabled),
                  (enabled))
CPRISK_ALIAS_VOID(cpra_0095, cprisk_test_secure_zero,
                  (void *buf, size_t len),
                  (buf, len))
CPRISK_ALIAS_RET(uint32_t, cpra_0096, cprisk_test_select_string_decrypt_path,
                 (uint32_t string_id, const uint8_t nonce[CPRISK_ARMOR_NONCE_SIZE], uint64_t seed),
                 (string_id, nonce, seed))
CPRISK_ALIAS_RET(int, cpra_0097, cprisk_test_set_antidebug_plan,
                 (const uint8_t *plan, size_t plan_len),
                 (plan, plan_len))
CPRISK_ALIAS_RET(int, cpra_0098, cprisk_test_set_whitebox_bundle,
                 (const uint8_t *meta, size_t meta_len,
                  const uint8_t *code, size_t code_len,
                  const uint8_t *data, size_t data_len,
                  const uint8_t *tag, size_t tag_len),
                 (meta, meta_len, code, code_len, data, data_len, tag, tag_len))
CPRISK_ALIAS_VOID(cpra_0099, cprisk_test_set_whitebox_recompute_mismatch,
                  (int enabled),
                  (enabled))
// MARK: - 校验器、证书固定与白盒（0100–0117）
CPRISK_ALIAS_RET(int, cpra_0100, cprisk_test_whitebox_prepare_domain_input,
                 (uint32_t domain_id, const uint8_t input[32], uint8_t out[32]),
                 (domain_id, input, out))
CPRISK_ALIAS_RET(int, cpra_0101, cprisk_unprotect_pages,
                 (void *region, size_t len),
                 (region, len))
CPRISK_ALIAS_RET(int, cpra_0102, cprisk_verify_dlsym_prologue,
                 (void),
                 ())
CPRISK_ALIAS_VOID(cpra_0103, cprisk_verify_exception_handler,
                  (void),
                  ())
CPRISK_ALIAS_RET(int, cpra_0104, cprisk_verify_mprotect_dlsym_matches_export_trie,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0105, cprisk_verify_page_protection,
                 (void *region, size_t len),
                 (region, len))
CPRISK_ALIAS_RET(uint32_t, cpra_0106, cprisk_verify_svc_stub_integrity,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0107, cprisk_verify_with_derived_key_and_request_binding_digest,
                 (const uint8_t *base_key, size_t base_key_len, const uint8_t *msg, size_t msg_len,
                  const uint8_t request_binding_digest[32], const char *expected_hex),
                 (base_key, base_key_len, msg, msg_len, request_binding_digest, expected_hex))
CPRISK_ALIAS_RET(int, cpra_0108, cprisk_whitebox_available,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0109, cprisk_whitebox_evaluate_domain,
                 (uint32_t domain_id, const uint8_t input[32], uint8_t out[32]),
                 (domain_id, input, out))
CPRISK_ALIAS_RET(int, cpra_0110, cprisk_whitebox_probe,
                 (struct cprisk_whitebox_probe_result *out_probe),
                 (out_probe))
CPRISK_ALIAS_RET(int, cpra_0111, cprisk_pinset_contains_sha256_digest,
                 (const uint8_t *candidate_digest, size_t candidate_len,
                  const uint8_t *packed_pins, size_t pin_count),
                 (candidate_digest, candidate_len, packed_pins, pin_count))
CPRISK_ALIAS_RET(int, cpra_0112, cprisk_spki_sha256_from_sec_certificate,
                 (void *sec_certificate_ref, uint8_t out_digest[32]),
                 (sec_certificate_ref, out_digest))
CPRISK_ALIAS_RET(int, cpra_0113, cprisk_pinset_match_layered_sha256_digest,
                 (const uint8_t *candidate_digest, size_t candidate_len,
                  const uint8_t *packed_pins, size_t pin_count,
                  const uint8_t *scopes, uint32_t chain_index),
                 (candidate_digest, candidate_len, packed_pins, pin_count, scopes, chain_index))
CPRISK_ALIAS_RET(int, cpra_0114, cprisk_verify_trust_hook_surface_integrity,
                 (uint32_t *fail_mask_out),
                 (fail_mask_out))
CPRISK_ALIAS_RET(int, cpra_0115, cprisk_verify_runtime_hook_surface_prologues,
                 (void),
                 ())
CPRISK_ALIAS_VOID(cpra_0116, cprisk_integrity_poison_watchdog_lane,
                  (void),
                  ())
CPRISK_ALIAS_VOID(cpra_0117, cprisk_test_reset_staged_poison_for_tests,
                  (void),
                  ())
// MARK: - VM 摘要、掩码路径探针与线程快照（0118–0126）
CPRISK_ALIAS_RET(int, cpra_0118, cprisk_vm_dyld_image_layout_digest,
                 (uint8_t out_digest[32]),
                 (out_digest))
CPRISK_ALIAS_RET(int, cpra_0119, cprisk_access_masked,
                 (const uint8_t *masked_path, size_t masked_len, uint32_t seed,
                  int amode, int *error_out),
                 (masked_path, masked_len, seed, amode, error_out))
CPRISK_ALIAS_RET(int, cpra_0120, cprisk_access_masked_libc,
                 (const uint8_t *masked_path, size_t masked_len, uint32_t seed,
                  int amode, int *error_out),
                 (masked_path, masked_len, seed, amode, error_out))
CPRISK_ALIAS_RET(int, cpra_0121, cprisk_stat_masked,
                 (const uint8_t *masked_path, size_t masked_len, uint32_t seed,
                  struct stat *sb, int *error_out),
                 (masked_path, masked_len, seed, sb, error_out))
CPRISK_ALIAS_RET(int, cpra_0122, cprisk_lstat_masked,
                 (const uint8_t *masked_path, size_t masked_len, uint32_t seed,
                  struct stat *sb, int *error_out),
                 (masked_path, masked_len, seed, sb, error_out))
CPRISK_ALIAS_RET(int, cpra_0123, cprisk_probe_path_snapshot_masked,
                 (const uint8_t *masked_path, size_t masked_len, uint32_t seed,
                  cprisk_path_probe_snapshot_t *out_snapshot),
                 (masked_path, masked_len, seed, out_snapshot))
CPRISK_ALIAS_RET(uint32_t, cpra_0124, cprisk_runtime_hook_surface_export_drift_mask,
                 (void),
                 ())
CPRISK_ALIAS_RET(int, cpra_0125, cprisk_get_exception_handler_snapshot,
                 (cprisk_exception_handler_snapshot_t *out_snapshot),
                 (out_snapshot))
CPRISK_ALIAS_RET(int, cpra_0126, cprisk_thread_pc_exec_snapshot,
                 (cprisk_thread_pc_exec_entry_t *out_entries,
                  uint32_t max_entries,
                  cprisk_thread_pc_exec_snapshot_t *out_snapshot),
                 (out_entries, max_entries, out_snapshot))

// 别名保活表。
//
// 这些别名只会在运行期被 `cprisk_resolve_import()` 按索引查找，编译期没有
// 任何直接调用点。链接器/Dead Code Stripping 可能因此把别名当成未使用符号
// 删除；这里用取地址的方式建立静态引用，强制它们进入最终二进制。
//
// 不变量：数组元素必须与上面的别名一一对应；新增别名时同步追加，
// 否则新索引在运行期会解析失败。
static const void *const cprisk_swift_bridge_keepalive_i[] = {
    (const void *)&cpra_0001, (const void *)&cpra_0002, (const void *)&cpra_0003,
    (const void *)&cpra_0004, (const void *)&cpra_0005, (const void *)&cpra_0006,
    (const void *)&cpra_0007, (const void *)&cpra_0008, (const void *)&cpra_0009,
    (const void *)&cpra_0010, (const void *)&cpra_0011, (const void *)&cpra_0012,
    (const void *)&cpra_0013, (const void *)&cpra_0014, (const void *)&cpra_0015,
    (const void *)&cpra_0016, (const void *)&cpra_0017, (const void *)&cpra_0018,
    (const void *)&cpra_0019, (const void *)&cpra_0020, (const void *)&cpra_0021,
    (const void *)&cpra_0022, (const void *)&cpra_0023, (const void *)&cpra_0024,
    (const void *)&cpra_0025, (const void *)&cpra_0026, (const void *)&cpra_0027,
    (const void *)&cpra_0028, (const void *)&cpra_0029, (const void *)&cpra_0030,
    (const void *)&cpra_0031, (const void *)&cpra_0032, (const void *)&cpra_0033,
    (const void *)&cpra_0034, (const void *)&cpra_0035, (const void *)&cpra_0036,
    (const void *)&cpra_0037, (const void *)&cpra_0038, (const void *)&cpra_0039,
    (const void *)&cpra_0040, (const void *)&cpra_0041, (const void *)&cpra_0042,
    (const void *)&cpra_0043, (const void *)&cpra_0044, (const void *)&cpra_0045,
    (const void *)&cpra_0046, (const void *)&cpra_0047, (const void *)&cpra_0048,
    (const void *)&cpra_0049, (const void *)&cpra_0050, (const void *)&cpra_0051,
    (const void *)&cpra_0052, (const void *)&cpra_0053, (const void *)&cpra_0054,
    (const void *)&cpra_0055, (const void *)&cpra_0056, (const void *)&cpra_0057,
    (const void *)&cpra_0058, (const void *)&cpra_0059, (const void *)&cpra_0060,
    (const void *)&cpra_0061, (const void *)&cpra_0062, (const void *)&cpra_0063,
    (const void *)&cpra_0064, (const void *)&cpra_0065, (const void *)&cpra_0066,
    (const void *)&cpra_0067, (const void *)&cpra_0068, (const void *)&cpra_0069,
    (const void *)&cpra_0070, (const void *)&cpra_0071, (const void *)&cpra_0072,
    (const void *)&cpra_0073, (const void *)&cpra_0074, (const void *)&cpra_0075,
    (const void *)&cpra_0076, (const void *)&cpra_0077, (const void *)&cpra_0078,
    (const void *)&cpra_0079, (const void *)&cpra_0080, (const void *)&cpra_0081,
    (const void *)&cpra_0082, (const void *)&cpra_0083, (const void *)&cpra_0084,
    (const void *)&cpra_0085, (const void *)&cpra_0086, (const void *)&cpra_0087,
    (const void *)&cpra_0088, (const void *)&cpra_0089, (const void *)&cpra_0090,
    (const void *)&cpra_0091, (const void *)&cpra_0092, (const void *)&cpra_0093,
    (const void *)&cpra_0094, (const void *)&cpra_0095, (const void *)&cpra_0096,
    (const void *)&cpra_0097, (const void *)&cpra_0098, (const void *)&cpra_0099,
    (const void *)&cpra_0100, (const void *)&cpra_0101, (const void *)&cpra_0102,
    (const void *)&cpra_0103, (const void *)&cpra_0104, (const void *)&cpra_0105,
    (const void *)&cpra_0106, (const void *)&cpra_0107, (const void *)&cpra_0108,
    (const void *)&cpra_0109,     (const void *)&cpra_0110, (const void *)&cpra_0111,
    (const void *)&cpra_0112, (const void *)&cpra_0113,
    (const void *)&cpra_0114,
    (const void *)&cpra_0115,
    (const void *)&cpra_0116,
    (const void *)&cpra_0117,
    (const void *)&cpra_0118,
    (const void *)&cpra_0119,
    (const void *)&cpra_0120,
    (const void *)&cpra_0121,
    (const void *)&cpra_0122,
    (const void *)&cpra_0123,
    (const void *)&cpra_0124,
    (const void *)&cpra_0125,
    (const void *)&cpra_0126,
};

// 强制链接锚点：Swift 侧在启动阶段调用一次，确保保活表所在翻译单元
// 不会被整个剔除（某些链接配置下仅存在静态数组仍可能被丢弃）。
// 无副作用；除第 0 个元素外不读取其他别名地址。
void cprisk_swift_bridge_force_link(void) {
    volatile const void *anchor = cprisk_swift_bridge_keepalive_i[0];
    (void)anchor;
}

