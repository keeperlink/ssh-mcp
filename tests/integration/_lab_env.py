"""Environment contract for independently pinned public integration tests."""
from __future__ import annotations

import os


def lab_story() -> str:
    value = os.environ.get("SSH_MCP_TEST_STORY")
    if not value:
        raise RuntimeError("An approved pinned lab runner must supply a story identifier")
    return value


def lab_url() -> str:
    return os.environ.get("SSH_MCP_TEST_URL") or "http://mcp:8000"
