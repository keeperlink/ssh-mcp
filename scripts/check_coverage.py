"""Enforce SSH-MCP's combined line + branch coverage threshold."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def combined_coverage(path: Path) -> tuple[int, int, float]:
    data = json.loads(path.read_text())
    totals = data["totals"]
    covered = int(totals["covered_lines"]) + int(totals["covered_branches"])
    possible = int(totals["num_statements"]) + int(totals["num_branches"])
    if possible <= 0:
        raise ValueError("Coverage dataset contains no executable lines or branches")
    return covered, possible, covered * 100 / possible


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--min", type=float, default=95)
    args = parser.parse_args()
    covered, possible, percentage = combined_coverage(args.report)
    print(f"Combined coverage: {percentage:.2f}% ({covered}/{possible})")
    if percentage + 1e-9 < args.min:
        parser.error(f"Coverage below required {args.min:.2f}%")


if __name__ == "__main__":
    main()
