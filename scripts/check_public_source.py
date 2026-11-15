#!/usr/bin/env python3
"""Fail closed on unsafe public-release artifacts and suspicious tokens.

Only reads local source files. Never prints credential values or file contents.
Synthetic malformed credential strings in unit tests exercise separate checks.
"""
from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
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


def check() -> None:
    if (ROOT / "AGENTS.md").exists():
        raise RuntimeError("Private agent instructions present")
    if list((ROOT / "tests").glob("*-dev-profile.json")):
        raise RuntimeError("Internal development profile present")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    if "self-hosted" in workflow or "fromJSON(" in workflow:
        raise RuntimeError("Private/self-hosted CI runner present")
    if workflow.count("runs-on: ubuntu-24.04") != 2:
        raise RuntimeError("Expected both CI jobs to use GitHub-hosted runners")

    violations: list[tuple[str, int, str]] = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or set(path.relative_to(ROOT).parts) & IGNORED:
            continue
        if path.suffix not in SUFFIXES:
            continue
        rel = path.relative_to(ROOT).as_posix()
        for number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if any(pattern.search(line) for pattern in CREDENTIALS):
                violations.append((rel, number, "suspected credential"))
    if violations:
        for rel, number, category in violations[:20]:
            print(f"REJECTED: {rel}:{number}: {category}")
        raise RuntimeError(f"Public disclosure scan failed: {len(violations)} findings")
    print("Public-source file, hosted-runner and high-risk token checks: PASS")


if __name__ == "__main__":
    check()
