"""Generic lab environment contract shared by private and public tests."""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from tests.integration._lab_env import lab_story, lab_url


class LabEnvironmentTests(unittest.TestCase):
    def test_generic_runner_variables(self) -> None:
        with patch.dict(os.environ, {
            "SSH_MCP_TEST_STORY": "TEST-297",
            "SSH_MCP_TEST_URL": "http://fixture:8000",
        }, clear=True):
            self.assertEqual(lab_story(), "TEST-297")
            self.assertEqual(lab_url(), "http://fixture:8000")

    def test_missing_story_fails_closed_even_if_legacy_is_present(self) -> None:
        with patch.dict(os.environ, {
            "SKY_MCP_TEST_STORY": "TEST-297",
            "SKY_MCP_TEST_URL": "http://legacy:8000",
        }, clear=True):
            with self.assertRaisesRegex(RuntimeError, "pinned lab runner"):
                lab_story()
            self.assertEqual(lab_url(), "http://mcp:8000")

    def test_default_url_when_unspecified(self) -> None:
        with patch.dict(os.environ, {
            "SSH_MCP_TEST_STORY": "TEST-297",
        }, clear=True):
            self.assertEqual(lab_story(), "TEST-297")
            self.assertEqual(lab_url(), "http://mcp:8000")


if __name__ == "__main__":
    unittest.main()
