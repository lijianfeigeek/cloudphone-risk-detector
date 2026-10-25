#!/usr/bin/env python3
"""校验 C/H 文件改动只包含注释（剥离注释后代码必须与 git HEAD 一致）。

除代码一致性外，还检查一个 C 特有的危险模式：
注释行不能紧跟以反斜杠续行的宏定义，否则注释会被拼进宏体。

用法:
  python3 -I Scripts/verify_c_comments.py <repo_root> <file1> [file2 ...]
  python3 -I Scripts/verify_c_comments.py <repo_root> --all-changed
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

CODE_SUFFIXES = {".c", ".h", ".inc"}


def scan(text: str) -> tuple[str, list[int]]:
    """剥离注释，返回 (stripped, comment_start_lines)。

    正确处理字符串、字符字面量与反斜杠续行；注释位置按 1 起始行号记录。
    """
    out: list[str] = []
    comment_lines: list[int] = []
    i = 0
    n = len(text)
    line = 1

    while i < n:
        ch = text[i]

        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            comment_lines.append(line)
            while i < n and text[i] != "\n":
                i += 1
            continue

        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            comment_lines.append(line)
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                if text[i] == "\n":
                    out.append("\n")
                    line += 1
                i += 1
            i = min(i + 2, n)
            continue

        if ch == '"':
            out.append(ch)
            i += 1
            while i < n:
                if text[i] == "\\" and i + 1 < n:
                    out.append(text[i:i + 2])
                    i += 2
                    continue
                out.append(text[i])
                if text[i] == '"':
                    i += 1
                    break
                if text[i] == "\n":
                    line += 1
                i += 1
            continue

        if ch == "'":
            out.append(ch)
            i += 1
            while i < n:
                if text[i] == "\\" and i + 1 < n:
                    out.append(text[i:i + 2])
                    i += 2
                    continue
                out.append(text[i])
                if text[i] == "'":
                    i += 1
                    break
                if text[i] == "\n":
                    line += 1
                i += 1
            continue

        out.append(ch)
        if ch == "\n":
            line += 1
        i += 1

    return "".join(out), comment_lines


def normalized(stripped: str) -> list[str]:
    return [line.rstrip() for line in stripped.splitlines() if line.strip()]


def git_head(repo: Path, path: Path) -> str | None:
    try:
        rel = path.resolve().relative_to(repo.resolve())
    except ValueError:
        rel = path
    result = subprocess.run(
        ["git", "-C", str(repo), "show", f"HEAD:{rel}"],
        capture_output=True,
        text=True,
    )
    return result.stdout if result.returncode == 0 else None


def check_dangerous_comments(text: str, comment_lines: list[int]) -> list[str]:
    """注释行紧跟反斜杠续行时，宏体会被注释截断。"""
    problems: list[str] = []
    lines = text.splitlines()
    for comment_line in comment_lines:
        index = comment_line - 2  # 上一行（0 起始）
        if index < 0:
            continue
        previous = lines[index].rstrip()
        if previous.endswith("\\"):
            problems.append(
                f"line {comment_line}: comment follows a backslash-continued line; "
                "move it above the whole macro definition"
            )
    return problems


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 2
    repo = Path(args[0])
    files = args[1:]
    if files == ["--all-changed"]:
        result = subprocess.run(
            ["git", "-C", str(repo), "diff", "--name-only", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
        files = [
            str(repo / name)
            for name in result.stdout.splitlines()
            if Path(name).suffix in CODE_SUFFIXES
        ]

    bad = 0
    for raw_path in files:
        path = Path(raw_path)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"[READ-FAIL] {path}: {exc}")
            bad += 1
            continue

        old = git_head(repo, path)
        if old is None:
            print(f"[NEW-FILE] {path} (no HEAD baseline, skipped)")
            continue

        stripped_new, comment_lines = scan(text)
        stripped_old, _ = scan(old)
        old_lines = normalized(stripped_old)
        new_lines = normalized(stripped_new)

        problems: list[str] = []
        if old_lines != new_lines:
            problems.append("code changed (comments-stripped output differs)")
            for index, (before, after) in enumerate(zip(old_lines, new_lines)):
                if before != after:
                    problems.append(f"  first difference at code line {index + 1}:")
                    problems.append(f"    HEAD: {before[:180]}")
                    problems.append(f"    NOW : {after[:180]}")
                    break
            if len(old_lines) != len(new_lines):
                problems.append(
                    f"  code line count: HEAD={len(old_lines)} NOW={len(new_lines)}"
                )
        problems.extend(check_dangerous_comments(text, comment_lines))

        if problems:
            bad += 1
            print(f"[FAIL] {path}")
            for problem in problems:
                print(f"  {problem}")
        else:
            print(f"[OK] {path}")

    print(f"\nresult: {len(files) - bad}/{len(files)} passed")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
