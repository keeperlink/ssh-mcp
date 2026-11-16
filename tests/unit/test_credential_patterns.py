"""Verify high-risk source credential patterns without using actual tokens."""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tests.tools.check_credential_patterns import check


class CredentialPatternTests(unittest.TestCase):
    def test_detects_github_token_without_printing_value(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "nested" / "unsafe.py"
            source.parent.mkdir()
            token = "ghp_" + "A" * 20
            source.write_text("header\n" + token + "\n")
            output = StringIO()
            with redirect_stdout(output), self.assertRaisesRegex(
                RuntimeError, "Credential-pattern scan failed: 1 findings"
            ):
                check(root)
            self.assertIn("REJECTED: nested/unsafe.py:2: suspected credential", output.getvalue())
            self.assertNotIn(token, output.getvalue())

    def test_detects_new_github_pat_and_aws_access_keys(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            first = "github_pat_" + "B" * 20
            second = "AKIA" + "C" * 16
            (root / "config.yaml").write_text(first + "\n" + second + "\n")
            with redirect_stdout(StringIO()), self.assertRaisesRegex(
                RuntimeError, "Credential-pattern scan failed: 2 findings"
            ):
                check(root)

    def test_ignores_generated_directories_and_other_file_types(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            token = "ghp_" + "D" * 20
            for directory in (".git", ".venv", "build", "node_modules"):
                target = root / directory / "fixture.py"
                target.parent.mkdir()
                target.write_text(token)
            (root / "thumbnail.png").write_text(token)
            output = StringIO()
            with redirect_stdout(output):
                check(root)
            self.assertEqual(output.getvalue(), "Credential-pattern scan: PASS\n")


if __name__ == "__main__":
    unittest.main()
