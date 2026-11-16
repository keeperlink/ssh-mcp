#!/usr/bin/env python3
"""Scan source for high-risk credential patterns without exposing their values."""
from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
IGNORED = {
    ".git", ".venv", ".mypy_cache", ".ruff_cache", ".pytest_cache",
    "__pycache__", "build", "dist", "node_modules", ".cache",
}
CREDENTIALS = (
    re.compile(r"ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[A-Z0-9]{16}"),
)
SUFFIXES = {".py", ".js", ".ts", ".css", ".sh", ".md", ".txt",
            ".yaml", ".yml", ".toml", ".json", ".example", ""}


def check(root: Path = ROOT) -> None:
    violations: list[tuple[str, int, str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or set(path.relative_to(root).parts) & IGNORED:
            continue
        if path.suffix not in SUFFIXES:
            continue
        rel = path.relative_to(root).as_posix()
        for number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if any(pattern.search(line) for pattern in CREDENTIALS):
                violations.append((rel, number, "suspected credential"))
    if violations:
        for rel, number, category in violations[:20]:
            print(f"REJECTED: {rel}:{number}: {category}")
        raise RuntimeError(f"Credential-pattern scan failed: {len(violations)} findings")
    print("Credential-pattern scan: PASS")


if __name__ == "__main__":
    check()
