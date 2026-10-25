#!/usr/bin/env python3
"""静态校验 ObfuscatedStrings.swift 中混淆常量的解码结果。

背景：这些字符串用于 libc 符号完整性 / hook / 反调试检测
（sysctlbyname、dlopen、ptrace、frida-server 等）。编码方向或字面量
写错不会崩溃，只会让检测静默失效，因此需要一条显式的回归门禁。

校验内容：
1. 源码中每一处 XOR / ROT13 / 逆序 / Caesar 调用都能解出可打印 ASCII；
2. 关键条目解码为预期值。
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE = (
    REPO_ROOT
    / "RiskDetectorApp/Sources/CloudPhoneRiskKit/Util/ObfuscatedStrings.swift"
)

# 每种编码方式下必须出现的明文。缺少任何一个都说明字面量或方向被改坏了。
REQUIRED = {
    "xor": {
        "Apple Para",                 # 半虚拟化设备标识片段
        "vresearch",                  # 云手机厂商域名特征
        "/usr/local/bin/frida-server",  # frida-server 安装路径
        "frIDa",                      # 大小写混合的 Frida 特征
        "gum",                        # gum-js-loop 线程名前缀
        "libhooker",                  # hook 框架
        "fish",                       # fish + hook = fishhook
    },
    "rot13": {
        "virtual ",
        "iphone99",
        "frida-agent",
        "-js-loop",
        "substitute",
    },
    "reverse": {
        "device",
        "paravirtual",
        "frida-server",
        "substrate",
    },
    "caesar": {
        "llvmpipe",
        "sysctlbyname",
        "dlopen",
        "ptrace",     # denyAttachToken
        "gadget",     # fridaMarkers
        "ellekit",    # hookFrameworkPatterns
    },
}

# 源码中的十六进制字面量未统一补零（例如 0x9、0xa），必须允许 1–2 位。
BYTE_PATTERN = re.compile(r"0x([0-9A-Fa-f]{1,2})(?![0-9A-Fa-f])")
PATTERNS = {
    "xor": re.compile(
        r"xorDecode\(\s*\[([^\]]*)\]\s*,\s*key:\s*0x([0-9A-Fa-f]+)\s*\)", re.S
    ),
    "caesar": re.compile(
        r"caesarShift\(\s*\[([^\]]*)\]\s*,\s*shift:\s*(-?\d+)\s*\)", re.S
    ),
    "reverse": re.compile(r"reverseBytes\(\s*\[([^\]]*)\]\s*\)", re.S),
    "rot13": re.compile(r'rot13\("([^"]*)"\)'),
}


def caesar_decode(encoded: list[int], shift: int) -> str:
    """与 Swift `StringDeobfuscator.caesarShift` 保持完全一致。"""
    normalized = shift % 26
    decoded = bytearray()
    for value in encoded:
        if 65 <= value <= 90:
            decoded.append((value - 65 - normalized + 26) % 26 + 65)
        elif 97 <= value <= 122:
            decoded.append((value - 97 - normalized + 26) % 26 + 97)
        else:
            decoded.append(value)
    return decoded.decode("utf-8", errors="replace")


def rot13(text: str) -> str:
    """与 Swift `StringDeobfuscator.rot13` 保持一致。"""
    chars = []
    for char in text:
        value = ord(char)
        if 65 <= value <= 90:
            chars.append(chr((value - 65 + 13) % 26 + 65))
        elif 97 <= value <= 122:
            chars.append(chr((value - 97 + 13) % 26 + 97))
        else:
            chars.append(char)
    return "".join(chars)


def decode_all(text: str) -> dict[str, list[str]]:
    decoded: dict[str, list[str]] = {name: [] for name in PATTERNS}

    for match in PATTERNS["xor"].finditer(text):
        raw, raw_key = match.group(1), match.group(2)
        encoded = [int(value, 16) for value in BYTE_PATTERN.findall(raw)]
        key = int(raw_key, 16)
        decoded["xor"].append(bytes(value ^ key for value in encoded).decode("utf-8", "replace"))

    for match in PATTERNS["caesar"].finditer(text):
        raw, raw_shift = match.group(1), match.group(2)
        encoded = [int(value, 16) for value in BYTE_PATTERN.findall(raw)]
        decoded["caesar"].append(caesar_decode(encoded, int(raw_shift)))

    for match in PATTERNS["reverse"].finditer(text):
        raw = match.group(1)
        encoded = [int(value, 16) for value in BYTE_PATTERN.findall(raw)]
        decoded["reverse"].append(bytes(reversed(encoded)).decode("utf-8", "replace"))

    for match in PATTERNS["rot13"].finditer(text):
        decoded["rot13"].append(rot13(match.group(1)))

    return decoded


def main() -> int:
    if not SOURCE.is_file():
        print(f"error: source not found: {SOURCE}", file=sys.stderr)
        return 2

    decoded = decode_all(SOURCE.read_text(encoding="utf-8"))
    errors: list[str] = []

    for method, values in decoded.items():
        if not values:
            errors.append(f"no {method} entries found")
            continue
        for value in values:
            if not value or not all(32 <= ord(char) < 127 for char in value):
                errors.append(f"{method} decoded to non-ASCII/garbage: {value!r}")
        for expected in sorted(REQUIRED[method] - set(values)):
            errors.append(f"{method} entry decoding to {expected!r} is missing")

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1

    summary = ", ".join(f"{name}={len(values)}" for name, values in decoded.items())
    print(f"OK: obfuscated constants decode as expected ({summary})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
