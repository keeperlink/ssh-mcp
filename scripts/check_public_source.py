#!/usr/bin/env python3
"""Reject private files and CI runner settings from public-release source."""
from __future__ import annotations

from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def check_no_internal_references() -> None:
    """Reject known private infrastructure markers in tracked public text.

    Report paths, not the matching line or its potentially private values.
    Generic RFC1918 examples and synthetic TEST-N identifiers remain valid.
    """
    forbidden = {
        "private-host": re.compile(
            r"\bskymap(?:[2345]|-(?:dev[23]?|test|lab|backup|ai|ci-[123]))\b",
            re.IGNORECASE,
        ),
        "private-domain": re.compile(
            r"\b(?:[a-z0-9-]+\.)?sky-map\.(?:org|info)\b",
            re.IGNORECASE,
        ),
        "private-org": re.compile(r"\bwikisky[-.]org\b", re.IGNORECASE),
        "private-jira-domain": re.compile(
            r"\bvanino\.atlassian\.net\b", re.IGNORECASE
        ),
        "private-issue": re.compile(r"\bSKY-[0-9]+\b"),
        "private-wireguard": re.compile(r"\b10\.77\.[0-9]{1,3}\.[0-9]{1,3}\b"),
        "private-home": re.compile(r"/home/" + r"gateway/" + r"[^\s]+"),
    }
    tracked = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    ).stdout
    for raw in tracked.split(b"\0"):
        if not raw:
            continue
        relative = raw.decode("utf-8")
        for kind, pattern in forbidden.items():
            if pattern.search(relative):
                raise RuntimeError(f"Private {kind} path in public source: {relative}")
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        try:
            content = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for kind, pattern in forbidden.items():
            if pattern.search(content):
                raise RuntimeError(
                    f"Private {kind} reference in public source: {relative}"
                )


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

    check_no_internal_references()
    print("Public-source file and hosted-runner checks: PASS")


if __name__ == "__main__":
    check()
