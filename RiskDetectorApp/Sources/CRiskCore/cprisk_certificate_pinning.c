/*
 * TLS SPKI SHA-256 pinning helpers (Apple Security.framework).
 * Builds SubjectPublicKeyInfo DER from SecKey external representation to match
 * standard tooling (openssl x509 -pubkey | openssl pkey -pubout -outform der | sha256).
 */

// 文件职责：从 SecCertificate 提取公钥，按 openssl 的 SPKI DER 形态重编码后做 SHA-256，
// 再与 Swift 侧下发的 pin 集合按“证书链位置”匹配，供 TLS 固定校验使用。
// 失败语义（fail-closed）：任何提取/重编码失败都返回负值且不写摘要；
//   匹配函数 -1 表示参数非法、0 表示未命中、1 才表示命中——调用方不得把 -1/0 视为通过。
// 线程模型：纯函数，无全局可变状态，可并发调用。
// 平台限制：仅 Apple 提供真实实现；其他平台返回 -4/-1，等价于“永不匹配”。

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__APPLE__)

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include "include/cprisk_sha256.h"

// pin 长度固定为 SHA-256 摘要 32 字节；packed_pins 按此长度紧密排列。
#define CPRISK_PIN_SHA256_DIGEST_LENGTH 32u

// 固定 ASN.1 SubjectPublicKeyInfo 前缀：只包含算法标识、参数与 BIT STRING 头，
// 后面直接拼接 SecKey 导出的裸公钥字节（RSA: PKCS#1，EC: 未压缩点）。
// 这些前缀与 openssl 输出逐字节对齐，改动会破坏已有 pin 的兼容性。
// 四个数组的字节内容属于整体常量，不逐字节维护。
/* ASN.1 SPKI headers (same constants as former Swift implementation). */
static const uint8_t k_rsa2048_spki_hdr[] = {
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09,
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00
};
static const uint8_t k_rsa4096_spki_hdr[] = {
    0x30, 0x82, 0x02, 0x22, 0x30, 0x0D, 0x06, 0x09,
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0F, 0x00
};
static const uint8_t k_ec_p256_spki_hdr[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
    0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00
};
static const uint8_t k_ec_p384_spki_hdr[] = {
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86,
    0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00
};

// pin 的作用域：ANY 不限制链位置；LEAF 只对 chain[0]；INTERMEDIATE 只对 chain>=1。
// 未知 scope 一律视为不匹配（fail-closed），避免新增枚举值被旧实现误放行。
enum {
    CPRISK_PIN_SCOPE_ANY = 0u,
    CPRISK_PIN_SCOPE_LEAF = 1u,
    CPRISK_PIN_SCOPE_INTERMEDIATE = 2u,
};

// 由 SecKey 属性判断密钥类型，再按裸公钥长度选择 SPKI 前缀，拼接到 out_spki。
// 裸公钥长度是强约束：RSA 2048→270、RSA 4096→526、P-256→65、P-384→97 字节。
// 属性不可用时只按长度回退（兼容旧系统），但这会让“类型正确但长度异常”的密钥失败。
// 返回 0 = 已写入 *out_spki_len；-1 = 未知长度或输出缓冲不足（调用方不得使用部分输出）。
static int cprisk_spki_der_from_pubkey_bytes_i(
    SecKeyRef key,
    const uint8_t *pub_bytes,
    size_t pub_len,
    uint8_t *out_spki,
    size_t out_cap,
    size_t *out_spki_len
) {
    const uint8_t *hdr = NULL;
    size_t hdr_len = 0u;

    CFDictionaryRef attrs = SecKeyCopyAttributes(key);
    if (attrs != NULL) {
        CFTypeRef type = CFDictionaryGetValue(attrs, kSecAttrKeyType);
        if (type != NULL && CFEqual(type, kSecAttrKeyTypeRSA)) {
            if (pub_len == 270u) {
                hdr = k_rsa2048_spki_hdr;
                hdr_len = sizeof(k_rsa2048_spki_hdr);
            } else if (pub_len == 526u) {
                hdr = k_rsa4096_spki_hdr;
                hdr_len = sizeof(k_rsa4096_spki_hdr);
            }
        } else if (type != NULL && CFEqual(type, kSecAttrKeyTypeECSECPrimeRandom)) {
            if (pub_len == 65u) {
                hdr = k_ec_p256_spki_hdr;
                hdr_len = sizeof(k_ec_p256_spki_hdr);
            } else if (pub_len == 97u) {
                hdr = k_ec_p384_spki_hdr;
                hdr_len = sizeof(k_ec_p384_spki_hdr);
            }
        }
        CFRelease(attrs);
    }

    // 属性缺失时才退化为“只看长度”：长度唯一对应一种密钥形态；
    // 若属性存在但类型/长度不匹配，则不会进入该分支，最终在下方返回 -1。
    if (hdr == NULL || hdr_len == 0u) {
        /* Length-only fallback when attributes are unavailable. */
        if (pub_len == 270u) {
            hdr = k_rsa2048_spki_hdr;
            hdr_len = sizeof(k_rsa2048_spki_hdr);
        } else if (pub_len == 526u) {
            hdr = k_rsa4096_spki_hdr;
            hdr_len = sizeof(k_rsa4096_spki_hdr);
        } else if (pub_len == 65u) {
            hdr = k_ec_p256_spki_hdr;
            hdr_len = sizeof(k_ec_p256_spki_hdr);
        } else if (pub_len == 97u) {
            hdr = k_ec_p384_spki_hdr;
            hdr_len = sizeof(k_ec_p384_spki_hdr);
        } else {
            return -1;
        }
    }

    // 先验证容量再拷贝：避免把超长公钥截断后仍产出“有效”摘要（会变成错误 pin）。
    if (hdr_len + pub_len > out_cap) {
        return -1;
    }
    memcpy(out_spki, hdr, hdr_len);
    memcpy(out_spki + hdr_len, pub_bytes, pub_len);
    *out_spki_len = hdr_len + pub_len;
    return 0;
}

// 计算证书公钥的 SPKI SHA-256（32 字节写入 out_digest）。
// 返回：0 成功；-1 参数为 NULL；-2 证书无可用公钥；-3 公钥外部表示导出失败；
// -4 SPKI 重编码失败（未知算法/长度）。
// 失败时 out_digest 不保证被写，调用方必须按“无法证明 pin”处理并拒绝连接（fail-closed）。
int cprisk_spki_sha256_from_sec_certificate(void *sec_certificate_ref, uint8_t out_digest[32]) {
    if (sec_certificate_ref == NULL || out_digest == NULL) {
        return -1;
    }
    SecCertificateRef cert = (SecCertificateRef)sec_certificate_ref;
    SecKeyRef key = SecCertificateCopyKey(cert);
    if (key == NULL) {
        return -2;
    }

    CFErrorRef cf_err = NULL;
    CFDataRef key_data = SecKeyCopyExternalRepresentation(key, &cf_err);
    if (key_data == NULL) {
        if (cf_err != NULL) {
            CFRelease(cf_err);
        }
        CFRelease(key);
        return -3;
    }

    const uint8_t *pub_bytes = CFDataGetBytePtr(key_data);
    size_t pub_len = (size_t)CFDataGetLength(key_data);

    // 640 字节足以容纳最大支持形态 RSA-4096 SPKI（526 + 19 字节头），
    // 栈上固定缓冲避免为每次 pin 校验分配堆内存。
    uint8_t spki_buf[640];
    size_t spki_len = 0u;
    int brc = cprisk_spki_der_from_pubkey_bytes_i(key, pub_bytes, pub_len, spki_buf, sizeof(spki_buf), &spki_len);
    CFRelease(key_data);
    CFRelease(key);

    if (brc != 0 || spki_len == 0u) {
        return -4;
    }

    cprisk_sha256(spki_buf, spki_len, out_digest);
    return 0;
}

// 在 pin 集合中查找与 candidate_digest 相同、且作用域允许当前链位置的条目。
// 参数：packed_pins 是 pin_count 个 32 字节摘要的紧密数组；scopes 是同样长度的作用域数组；
//   chain_index 0 表示叶子证书，>=1 表示中间证书。
// 返回：1 = 命中；0 = 未命中或 pin_count 为 0（“没有可用 pin”，不是“校验通过”）；
//   -1 = 参数非法（NULL 或 candidate_len != 32）。
// 比较使用逐字节 XOR 累积、不提前退出，避免通过耗时推断命中的字节位置。
int cprisk_pinset_match_layered_sha256_digest(
    const uint8_t *candidate_digest,
    size_t candidate_len,
    const uint8_t *packed_pins,
    size_t pin_count,
    const uint8_t *scopes,
    uint32_t chain_index
) {
    // 长度必须精确等于 32；截断/补零的摘要一律拒绝，防止用前缀碰撞放宽策略。
    if (candidate_digest == NULL || candidate_len != CPRISK_PIN_SHA256_DIGEST_LENGTH) {
        return -1;
    }
    // 空 pin 集合表示“未配置”，必须返回 0 让上层决定策略，不能在此默认放行。
    if (pin_count == 0u) {
        return 0;
    }
    if (packed_pins == NULL || scopes == NULL) {
        return -1;
    }

    uint8_t any_match = 0u;
    size_t pin_index = 0u;
    for (pin_index = 0u; pin_index < pin_count; ++pin_index) {
        const uint8_t *slot = packed_pins + (pin_index * CPRISK_PIN_SHA256_DIGEST_LENGTH);
        uint8_t diff = 0u;
        size_t byte_index = 0u;
        for (byte_index = 0u; byte_index < CPRISK_PIN_SHA256_DIGEST_LENGTH; ++byte_index) {
            diff |= (uint8_t)(candidate_digest[byte_index] ^ slot[byte_index]);
        }
        const uint8_t digest_ok = (uint8_t)(diff == 0u);
        const uint8_t scope = scopes[pin_index];
        uint8_t pos_ok = 0u;
        if (scope == CPRISK_PIN_SCOPE_ANY) {
            pos_ok = 1u;
        } else if (scope == CPRISK_PIN_SCOPE_LEAF) {
            pos_ok = (uint8_t)(chain_index == 0u);
        } else if (scope == CPRISK_PIN_SCOPE_INTERMEDIATE) {
            pos_ok = (uint8_t)(chain_index >= 1u);
        } else {
            pos_ok = 0u;
        }
        any_match |= (uint8_t)(digest_ok & pos_ok);
    }
    return any_match != 0u ? 1 : 0;
}

#else /* !__APPLE__ */

// 非 Apple 平台没有 Security.framework：摘要计算恒失败（-4）、匹配恒失败（-1）。
// 两者都是 fail-closed，保证“无法校验”不会被误读成“pin 通过”。
int cprisk_spki_sha256_from_sec_certificate(void *sec_certificate_ref, uint8_t out_digest[32]) {
    (void)sec_certificate_ref;
    (void)out_digest;
    return -4;
}

int cprisk_pinset_match_layered_sha256_digest(
    const uint8_t *candidate_digest,
    size_t candidate_len,
    const uint8_t *packed_pins,
    size_t pin_count,
    const uint8_t *scopes,
    uint32_t chain_index
) {
    (void)candidate_digest;
    (void)candidate_len;
    (void)packed_pins;
    (void)pin_count;
    (void)scopes;
    (void)chain_index;
    return -1;
}

#endif /* __APPLE__ */
