"""Validated runtime configuration with signed service settings and private secrets."""
from __future__ import annotations

import os
import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from urllib.parse import quote

from .control import LEVELS
from .client_registry import clients_from_environment, labels, offline_client
from .sealed_credentials import validate_token_verifier, validate_verifier

# Production mounts are all-or-nothing. Lab environment-file mode remains
# supported by the exact same single image, without separate bootstrap code.
_MOUNTS = ("MCP_CONFIG_FILE", "MCP_INVENTORY_FILE", "MCP_KNOWN_HOSTS_FILE", "MCP_SECRETS_FILE")
if any(os.getenv(name) for name in _MOUNTS):
    if not all(os.getenv(name) for name in _MOUNTS):
        raise RuntimeError("All three signed files and private secrets are required")
    from pathlib import Path
    from .runtime_files import prepare
    os.environ.update(prepare(Path(os.environ["MCP_CONFIG_FILE"]),
                              Path(os.environ["MCP_SECRETS_FILE"]),
                              Path(os.environ["MCP_INVENTORY_FILE"]),
                              Path(os.environ["MCP_KNOWN_HOSTS_FILE"])))


def _csv_env(name: str, default: str = "") -> list[str]:
    return [value.strip() for value in os.getenv(name, default).split(",") if value.strip()]


MCP_LOGIN_KEY = os.getenv("MCP_LOGIN_KEY", "")
MCP_MANAGED_SECRETS_VERSION = os.getenv("MCP_MANAGED_SECRETS_VERSION", "")
MCP_MANAGED_SECRETS_SOURCE = os.getenv("MCP_MANAGED_SECRETS_SOURCE", "")
MCP_MANAGED_SECRETS_DIGEST = os.getenv("MCP_MANAGED_SECRETS_DIGEST", "")
# Sealed-v2 is a supported signed image format. Runtime deployment still
# requires the operator's offline history DB snapshot and cutover on an
# existing legacy installation. ViewerAuth refuses any legacy auth table
# until that separately approved offline operation completes.
SEALED_RUNTIME_READY = True
MCP_LOGIN_VERIFIER = json.loads(os.getenv("MCP_LOGIN_VERIFIER", "null"))
HISTORY_VIEWER_VERIFIER = json.loads(os.getenv("HISTORY_VIEWER_VERIFIER", "null"))
HISTORY_VIEWER_GENERATION = os.getenv("HISTORY_VIEWER_GENERATION", "")
MCP_METRICS_VERIFIER = json.loads(os.getenv("MCP_METRICS_VERIFIER", "null"))
MCP_TOKEN_SIGNING_SECRET = os.getenv("MCP_TOKEN_SIGNING_SECRET", "")
MCP_ENVIRONMENT = os.getenv("MCP_ENVIRONMENT", "lab")
MCP_LOG_LEVEL = os.getenv("MCP_LOG_LEVEL", "INFO")
# The image builder embeds the resolved release tag into the immutable image; local
# development can override it without changing signed deployment settings.
_IMAGE_VERSION = Path("/usr/local/share/ssh-mcp/version")
MCP_SERVICE_VERSION = os.getenv("MCP_SERVICE_VERSION") or (
    _IMAGE_VERSION.read_text("utf-8").strip() if _IMAGE_VERSION.is_file() else ""
)
MCP_ISSUER = os.getenv("MCP_ISSUER", "").rstrip("/")
MCP_RESOURCE = os.getenv("MCP_RESOURCE", f"{MCP_ISSUER}/mcp").rstrip("/")
MCP_SCOPES = ["mcp.access"]
MCP_SSH_SCOPE = "ssh.execute"
MCP_SSH_TOOLS_ENABLED = os.getenv("MCP_SSH_TOOLS_ENABLED", "false").lower() == "true"
MCP_OPERATOR_SUBJECT = os.getenv("MCP_OPERATOR_SUBJECT", "ssh-mcp-operator")
MCP_SESSION_LIFETIMES = (3600, 28800, 86400, 604800, 2592000)
MCP_SESSION_TTL_DEFAULT = int(os.getenv("MCP_SESSION_TTL_DEFAULT", "86400"))
MCP_ACCESS_TOKEN_TTL = int(os.getenv("MCP_ACCESS_TOKEN_TTL", "900"))
MCP_AUTH_CODE_TTL = int(os.getenv("MCP_AUTH_CODE_TTL", "300"))
MCP_CLIENTS = clients_from_environment(os.getenv("MCP_CLIENTS", "{}"))
_OFFLINE = offline_client(MCP_CLIENTS)
MCP_CIMD_CLIENT_ID = (_OFFLINE[0] if _OFFLINE else os.getenv("MCP_CIMD_CLIENT_ID", "https://chatgpt.com/oauth/client.json"))
MCP_CLIENT_LABELS = labels(MCP_CLIENTS)
MCP_CIMD_VALIDATE_REMOTE = os.getenv("MCP_CIMD_VALIDATE_REMOTE", "true").lower() != "false"
MCP_CIMD_CACHE_TTL = int(os.getenv("MCP_CIMD_CACHE_TTL", "3600"))
MCP_DCR_ENABLED = os.getenv("MCP_DCR_ENABLED", "true").lower() == "true"
MCP_ALLOWED_REDIRECT_URIS = set(
    _OFFLINE[1] if _OFFLINE else _csv_env(
        "MCP_ALLOWED_REDIRECT_URIS", "https://chatgpt.com/connector_platform_oauth_redirect")
)
MCP_LOGIN_MAX_FAILURES = int(os.getenv("MCP_LOGIN_MAX_FAILURES", "5"))
MCP_LOGIN_WINDOW_SECONDS = int(os.getenv("MCP_LOGIN_WINDOW_SECONDS", "300"))
MCP_ALLOWED_HOSTS = _csv_env(
    "MCP_ALLOWED_HOSTS",
    "localhost,localhost:*,127.0.0.1,127.0.0.1:*",
)
MCP_ALLOWED_ORIGINS = _csv_env("MCP_ALLOWED_ORIGINS", "https://chatgpt.com")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "10"))

# Configurable operational defaults, with independent source-code safety ceilings.
SSH_DEFAULT_TIMEOUT_SECONDS = int(os.getenv("SSH_DEFAULT_TIMEOUT_SECONDS", "60"))
SSH_MAX_TIMEOUT_SECONDS = int(os.getenv("SSH_MAX_TIMEOUT_SECONDS", "900"))
SSH_OUTPUT_LIMIT_BYTES = int(os.getenv("SSH_OUTPUT_LIMIT_BYTES", "262144"))
SSH_MAX_ARGUMENT_BYTES = int(os.getenv("SSH_MAX_ARGUMENT_BYTES", "32768"))
SSH_MAX_ARGUMENTS = int(os.getenv("SSH_MAX_ARGUMENTS", "32"))
SSH_MAX_CONCURRENT = int(os.getenv("SSH_MAX_CONCURRENT", "4"))
SSH_MAX_ACTIVE_JOBS = int(os.getenv("SSH_MAX_ACTIVE_JOBS", "32"))


def _verify_sealed_database() -> None:
    """Read-only startup preflight, even when the Console routes are disabled."""
    filename = os.getenv("SSH_JOBS_DB", "")
    if not filename:
        return  # Standalone env-mode without a persistent job store.
    path = Path(filename)
    if not path.is_absolute() or path.is_symlink():
        raise RuntimeError("Sealed audit database path must be absolute and not a symlink")
    if not path.exists():
        if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm")):
            raise RuntimeError("Orphan SQLite audit journal requires recovery")
        return  # Fresh database: no legacy credential state to migrate.
    if not path.is_file():
        raise RuntimeError("Sealed audit database must be a regular file")
    try:
        uri = "file:" + quote(str(path), safe="/") + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=0)) as db:
            columns = {row[1] for row in db.execute(
                "PRAGMA table_info(history_auth_state)"
            )}
            if columns and columns != {"id", "generation"}:
                raise RuntimeError("Legacy Console database requires offline sealed cutover")
            if not columns and db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='history_sessions'"
            ).fetchone() and db.execute(
                "SELECT 1 FROM history_sessions LIMIT 1"
            ).fetchone():
                raise RuntimeError("Existing Console sessions require offline sealed cutover")
    except sqlite3.Error as exc:
        raise RuntimeError("Unable to verify sealed audit database safety") from exc


def is_commit_version(value: str) -> bool:
    return re.fullmatch(r"[0-9a-f]{7,40}", value) is not None


def _valid_service_version(value: str) -> bool:
    return not value or is_commit_version(value) or (len(value) <= 40 and re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", value) is not None)


def validate_mcp_config() -> None:
    if MCP_LOG_LEVEL not in LEVELS:
        raise RuntimeError("Invalid MCP_LOG_LEVEL")
    if MCP_ENVIRONMENT not in {"lab", "production"}:
        raise RuntimeError("MCP_ENVIRONMENT must be lab or production")
    if not _valid_service_version(MCP_SERVICE_VERSION):
        raise RuntimeError("MCP_SERVICE_VERSION must be a release version or Git commit hash")
    if MCP_MANAGED_SECRETS_VERSION not in ("", "2"):
        raise RuntimeError("Unsupported managed secret revision")
    if MCP_MANAGED_SECRETS_VERSION == "2":
        if (MCP_LOGIN_KEY or os.getenv("HISTORY_VIEWER_PASSWORD")
                or os.getenv("MCP_METRICS_TOKEN")):
            raise RuntimeError("Sealed mode must not load plaintext login or metrics credentials")
        validate_verifier(MCP_LOGIN_VERIFIER)
        validate_verifier(HISTORY_VIEWER_VERIFIER)
        validate_token_verifier(MCP_METRICS_VERIFIER)
        if re.fullmatch("[0-9a-f]{32}", HISTORY_VIEWER_GENERATION) is None:
            raise RuntimeError("Invalid Console secret generation")
        if not SEALED_RUNTIME_READY:
            raise RuntimeError("Sealed runtime activation disabled")
        _verify_sealed_database()
    elif len(MCP_LOGIN_KEY) < 32:
        raise RuntimeError("MCP_LOGIN_KEY must contain at least 32 characters")
    if len(MCP_TOKEN_SIGNING_SECRET) < 32:
        raise RuntimeError("MCP_TOKEN_SIGNING_SECRET must contain at least 32 characters")
    # Auth, signing, Console and metrics secrets must never share a value.
    # Managed signed config already enforces this; standalone env mode must too.
    if MCP_MANAGED_SECRETS_VERSION != "2":
        credentials = [MCP_LOGIN_KEY, MCP_TOKEN_SIGNING_SECRET]
        if os.getenv("HISTORY_VIEWER_ENABLED", "false").lower() == "true":
            credentials.append(os.getenv("HISTORY_VIEWER_PASSWORD", ""))
        if os.getenv("MCP_METRICS_ENABLED", "false").lower() == "true":
            credentials.append(os.getenv("MCP_METRICS_TOKEN", ""))
        if len(set(credentials)) != len(credentials):
            raise RuntimeError("OAuth, signing, Console and metrics secrets must be distinct")
    if not MCP_ISSUER.startswith("https://") and MCP_ISSUER not in {"http://localhost", "http://127.0.0.1"}:
        raise RuntimeError("MCP_ISSUER must use HTTPS outside local development")
    if MCP_RESOURCE != f"{MCP_ISSUER}/mcp":
        raise RuntimeError("MCP_RESOURCE must exactly match issuer + /mcp")
    if not 0 < MCP_AUTH_CODE_TTL <= 600 or (MCP_ACCESS_TOKEN_TTL != 900 or MCP_SESSION_TTL_DEFAULT not in MCP_SESSION_LIFETIMES):
        raise RuntimeError("Invalid OAuth token lifetime")
    if not MCP_CIMD_CLIENT_ID.startswith("https://") or not MCP_ALLOWED_REDIRECT_URIS:
        raise RuntimeError("Client metadata and redirect allowlist must be configured")
    if MCP_OPERATOR_SUBJECT != "ssh-mcp-operator":
        raise RuntimeError("OAuth subject must be the approved operator identity")
    if (not 1 <= SSH_DEFAULT_TIMEOUT_SECONDS <= SSH_MAX_TIMEOUT_SECONDS <= 36000
            or not 1 <= SSH_OUTPUT_LIMIT_BYTES <= 1048576
            or not 1 <= SSH_MAX_ARGUMENT_BYTES <= 65536
            or not 1 <= SSH_MAX_ARGUMENTS <= 64
            or not 1 <= SSH_MAX_CONCURRENT <= 32
            or not 1 <= SSH_MAX_ACTIVE_JOBS <= 256):
        raise RuntimeError("Invalid operational limits")
