"""Verified OAuth client attribution; never use a display label for authorization."""
from __future__ import annotations

from contextvars import ContextVar
import hashlib
import os
from typing import Mapping

client_id_context: ContextVar[str | None] = ContextVar("oauth_client_id", default=None)
UNKNOWN_AGENT = "unknown"


def approved_dcr_names() -> Mapping[str, str]:
    """Snapshot cached in memory by the DCR registry; never query SQL per History row."""
    if not (os.getenv("SSH_JOBS_DB") or os.getenv("MCP_OAUTH_DB")):
        return {}
    from .oauth import dcr_store  # Lazy import: OAuth also depends on client identity.
    return dcr_store().approved_names


def agent_names_snapshot() -> tuple[str, Mapping[str, str]]:
    """Read names and restart-unique revision from the same published map."""
    if not (os.getenv("SSH_JOBS_DB") or os.getenv("MCP_OAUTH_DB")):
        return "", {}
    from .oauth import dcr_store
    return dcr_store().names_snapshot


def agent_names_revision() -> str:
    return agent_names_snapshot()[0]


def agent_label(client_id: str | None, labels: dict[str, str]) -> str:
    if client_id is None:
        return "Unknown"
    if client_id.startswith("dcr_"):
        return approved_dcr_names().get(client_id, "Unknown")
    return labels.get(client_id, "Unknown")


def agent_disambiguator(client_id: str | None, labels: dict[str, str]) -> str | None:
    """Display-only client fingerprint when an authenticated client lacks a label."""
    if client_id is None or agent_label(client_id, labels) != "Unknown":
        return None
    return hashlib.sha256(client_id.encode("utf-8")).hexdigest()[:12]
