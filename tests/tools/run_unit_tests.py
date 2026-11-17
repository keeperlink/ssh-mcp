#!/usr/bin/env python3
"""Discover offline SSH-MCP unit/contract suites or source-only tooling tests.

Real SSH, Docker and native browser tests are intentionally not discoverable
here. Lab runner safety tests have their own explicit offline CI gate.
"""
from __future__ import annotations

import argparse
from collections.abc import Iterator
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests"
SUITES = ("unit", "contracts")
TOOLS_SUITE = ("tools",)
ALL_SUITES = SUITES + TOOLS_SUITE

# This runner is invoked directly by Coverage in the installed-wheel fixture.
# Add only the validation root (which contains no app/ source in that fixture).
# A previous checkout may already be on sys.path ahead of this one.
# Resolve the tests helper from the selected checkout, not an older sibling.
if str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))
from tests.tools._offline_env import isolate_offline_environment  # noqa: E402


def _cases(suite: unittest.TestSuite) -> Iterator[unittest.TestCase]:
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _cases(item)
        elif isinstance(item, unittest.TestCase):
            yield item
        else:
            raise ValueError(f"Invalid discovered test item: {type(item).__name__}")


def discover(*, tests: Path = TESTS, tools_only: bool = False) -> unittest.TestSuite:
    """Fail closed on orphan or duplicate tests; never load integration scripts."""
    admitted = {tests / name for name in ALL_SUITES}
    misplaced = sorted(
        p.relative_to(tests).as_posix()
        for p in tests.rglob("test_*.py")
        if p.parent not in admitted
    )
    if misplaced:
        raise ValueError(
            "Discoverable offline tests must be in tests/unit, tests/contracts or tests/tools: "
            + ", ".join(misplaced[:8])
        )

    isolate_offline_environment()
    if str(tests.parent) not in sys.path:
        sys.path.insert(0, str(tests.parent))
    # Check module names across all admitted suites without importing unselected tests.
    filenames: set[str] = set()
    for name in ALL_SUITES:
        folder = tests / name
        files = sorted(folder.glob("test_*.py"))
        overlap = filenames.intersection(p.name for p in files)
        if overlap:
            raise ValueError("Duplicate test module across suites: " + ", ".join(sorted(overlap)))
        filenames.update(p.name for p in files)

    groups: list[unittest.TestSuite] = []
    identities: set[str] = set()
    for name in TOOLS_SUITE if tools_only else SUITES:
        folder = tests / name
        if not any(folder.glob("test_*.py")):
            raise ValueError(f"Missing or empty offline suite: tests/{name}")
        loader = unittest.TestLoader()
        suite = loader.discover(str(folder), pattern="test_*.py", top_level_dir=str(folder))
        if loader.errors:
            raise ValueError(f"Failed tests/{name} discovery: " + "; ".join(str(error) for error in loader.errors))
        if not suite.countTestCases():
            raise ValueError(f"No test cases discovered in tests/{name}")
        for case in _cases(suite):
            if case.id() in identities:
                raise ValueError("Duplicate discovered test ID: " + case.id())
            identities.add(case.id())
        groups.append(suite)
    return unittest.TestSuite(groups)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools", action="store_true", help="Run only source-checkout tooling tests")
    args = parser.parse_args(argv)
    try:
        suite = discover(tools_only=args.tools)
    except (ImportError, OSError, ValueError) as exc:
        print(f"FAIL: offline test discovery: {exc}", file=sys.stderr)
        return 1
    names = ",".join(TOOLS_SUITE if args.tools else SUITES)
    print(f"OFFLINE_TESTS={suite.countTestCases()} SUITES={names}", flush=True)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
