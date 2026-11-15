"""Synthetic-only environment for offline wheel, unit and contract validation."""
from __future__ import annotations

from collections.abc import Mapping
import os

# Signed runtime selectors, OAuth credentials, SSH inventory, audit storage and
# viewer policy must never be inherited by an offline test import.
_SERVICE_PREFIXES = ("MCP_", "SSH_", "HISTORY_", "SKY_MCP_")
_SERVICE_NAMES = frozenset({
    "REQUEST_TIMEOUT", "WEB_CONCURRENCY", "UVICORN_WORKERS", "PYTHONPATH",
})

SYNTHETIC_ENV = {
    "MCP_ISSUER": "http://localhost",
    "MCP_RESOURCE": "http://localhost/mcp",
    "MCP_CIMD_VALIDATE_REMOTE": "false",
    "MCP_LOGIN_KEY": "synthetic-test-login-" + "a" * 40,
    "MCP_TOKEN_SIGNING_SECRET": "synthetic-test-signing-" + "b" * 40,
    "PYTHONDONTWRITEBYTECODE": "1",
}


def offline_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    """Discard all inherited service configuration before loading app modules."""
    inherited = os.environ if source is None else source
    result = {
        key: value for key, value in inherited.items()
        if not key.startswith(_SERVICE_PREFIXES) and key not in _SERVICE_NAMES
    }
    result.update(SYNTHETIC_ENV)
    return result


def isolate_offline_environment() -> None:
    """Apply the synthetic environment before unittest imports any application."""
    safe = offline_environment()
    os.environ.clear()
    os.environ.update(safe)
