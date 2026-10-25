#!/usr/bin/env python3
"""校验 Swift 文件改动只包含注释（剥离注释后代码必须与 git HEAD 一致）。

用法:
  python3 -I /tmp/verify_comment_only.py <repo_root> <file1.swift> [file2.swift ...]
  python3 -I /tmp/verify_comment_only.py <repo_root> --all-changed

退出码: 0 全部通过; 1 存在代码改动或语法可疑的文件。
"""
import subprocess
import sys
import re


def strip_swift_comments(text: str) -> str:
    """去掉 Swift 注释，保留字符串字面量内容。支持 - "..." \"\"\"...\"\"\" #"..."# 及插值中的字符串。"""
    out = []
    i = 0
    n = len(text)

    def raw_string_end(start: int) -> int:
        # start 指向第一个 '"' 之前；统计 '#' 的数量
        j = start
        hashes = 0
        while j < n and text[j] == '#':
            hashes += 1
            j += 1
        if j >= n or text[j] != '"':
            return -1
        # 三引号原始字符串
        triple = text.startswith('"""', j)
        quote = '"""' if triple else '"'
        k = j + len(quote)
        closing = quote + ('#' * hashes)
        while k < n:
            if text.startswith(closing, k):
                return k + len(closing)
            k += 1
        return n

    while i < n:
        c = text[i]
        # 行注释
        if c == '/' and i + 1 < n and text[i + 1] == '/':
            # 保留换行
            while i < n and text[i] != '\n':
                i += 1
            continue
        # 块注释（正常情况下不应出现，但兼容旧代码）
        if c == '/' and i + 1 < n and text[i + 1] == '*':
            depth = 1
            i += 2
            while i < n and depth:
                if text.startswith('/*', i):
                    depth += 1
                    i += 2
                elif text.startswith('*/', i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            continue
        # 原始字符串 #"..."# / ##"..."##
        if c == '#':
            end = raw_string_end(i)
            if end != -1:
                out.append(text[i:end])
                i = end
                continue
        # 字符串
        if c == '"':
            triple = text.startswith('"""', i)
            quote = '"""' if triple else '"'
            j = i + len(quote)
            out.append(quote)
            while j < n:
                if text[j] == '\\':
                    out.append(text[j:j + 2])
                    j += 2
                    continue
                if text.startswith(quote, j):
                    out.append(quote)
                    j += len(quote)
                    break
                out.append(text[j])
                j += 1
            i = j
            continue
        out.append(c)
        i += 1
    return ''.join(out)


def normalized(stripped: str) -> list:
    # 去行尾空白；保留非空行（注释删除后留下的空行忽略）
    return [line.rstrip() for line in stripped.splitlines() if line.strip()]


def git_head(repo: str, path: str) -> str:
    try:
        rel = path
        if path.startswith(repo):
            rel = path[len(repo):].lstrip('/')
        return subprocess.run(
            ['git', '-C', repo, 'show', f'HEAD:{rel}'],
            check=True, capture_output=True, text=True
        ).stdout
    except subprocess.CalledProcessError:
        return None  # 新文件


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 2
    repo = args[0]
    files = args[1:]
    if files == ['--all-changed']:
        res = subprocess.run(
            ['git', '-C', repo, 'diff', '--name-only', 'HEAD', '--', '*.swift'],
            check=True, capture_output=True, text=True
        )
        files = [str(__import__('pathlib').Path(repo) / p) for p in res.stdout.splitlines() if p]
    bad = 0
    for path in files:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                new = f.read()
        except OSError as e:
            print(f'[READ-FAIL] {path}: {e}')
            bad += 1
            continue
        old = git_head(repo, path)
        if old is None:
            print(f'[NEW-FILE] {path} (无 HEAD 基线，跳过)')
            continue
        old_lines = normalized(strip_swift_comments(old))
        new_lines = normalized(strip_swift_comments(new))
        if old_lines == new_lines:
            print(f'[OK] {path}')
        else:
            bad += 1
            print(f'[CODE-CHANGED] {path}')
            # 输出首个差异位置
            for idx, (a, b) in enumerate(zip(old_lines, new_lines)):
                if a != b:
                    print(f'  第一处差异 第{idx+1}个代码行:\n    HEAD: {a[:200]}\n    NOW : {b[:200]}')
                    break
            if len(old_lines) != len(new_lines):
                print(f'  代码行数: HEAD={len(old_lines)} NOW={len(new_lines)}')
    print(f'\n结果: {len(files) - bad}/{len(files)} 通过')
    return 0 if bad == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
