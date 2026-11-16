"""Generic lab environment contracts for public integration tests."""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from tests.integration._lab_env import lab_story, lab_url


class PublicLabEnvironmentTests(unittest.TestCase):
    def test_generic_environment(self) -> None:
        with patch.dict(os.environ, {
            "SSH_MCP_TEST_STORY": "TEST-297",
            "SSH_MCP_TEST_URL": "http://fixture:8000",
        }, clear=True):
            self.assertEqual(lab_story(), "TEST-297")
            self.assertEqual(lab_url(), "http://fixture:8000")

    def test_missing_story_fails_closed(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "pinned lab runner"):
                lab_story()
            self.assertEqual(lab_url(), "http://mcp:8000")


if __name__ == "__main__":
    unittest.main()
