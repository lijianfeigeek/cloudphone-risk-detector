// CFF（控制流平坦化）S-box 的规范种子：Swift 侧与 C 侧必须使用完全相同的常量。
// 位于 Internal/CFF 的密码学基础层，被 CFFSBoxRuntime 用于生成 256 字节置换表。
// 关键安全不变量：种子一旦与 `cprisk_cff.h` 不一致，状态编解码将整体失效，必须双端同步修改。
import Foundation

/// Feistel SPN 字节替换所用的规范 UInt64 种子——必须与以下实现保持一致：
/// - `cprisk_cff.h` 中的 `CPRISK_CFF_SPN_CANONICAL_SEED_U64`
/// - `cprisk_cff_spn_sbox_install_from_seed` / `CFFSBoxPermutation256.generate(seed:)`
///
/// 推导方式：`fnv1a64("cprisk-armor/CFFSBoxPermutation256/v1") ^ 0xA37C19E45B62D08F`
/// （registry root mix）；在 PRNG 中零值会被映射为 1。
internal enum CFFSBoxMaterial {
    /// 规范种子常量；两侧硬编码值必须逐位一致。
    static let canonicalSeed: UInt64 = 0x6AFD56260D3F7F05
}
