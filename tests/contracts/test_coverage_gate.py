"""Coverage formula correctness and fail-closed behavior."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.check_coverage import combined_coverage


class CoverageGateTests(unittest.TestCase):
    def test_coverage_combines_lines_and_branches_not_percentages(self):
        with tempfile.TemporaryDirectory() as path:
            report = Path(path) / "coverage.json"
            report.write_text(json.dumps({"totals": {
                "covered_lines": 90,
                "num_statements": 100,
                "covered_branches": 9,
                "num_branches": 10,
            }}))
            self.assertEqual(combined_coverage(report), (99, 110, 90.0))

    def test_empty_dataset_is_not_success(self):
        with tempfile.TemporaryDirectory() as path:
            report = Path(path) / "coverage.json"
            report.write_text(json.dumps({"totals": {
                "covered_lines": 0,
                "num_statements": 0,
                "covered_branches": 0,
                "num_branches": 0,
            }}))
            with self.assertRaises(ValueError):
                combined_coverage(report)
