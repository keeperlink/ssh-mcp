#!/usr/bin/env python3
"""Reject private files and CI runner settings from public-release source."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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

    print("Public-source file and hosted-runner checks: PASS")


if __name__ == "__main__":
    check()
