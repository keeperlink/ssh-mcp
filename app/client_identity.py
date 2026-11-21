"""Verified OAuth client attribution; never use a display label for authorization."""
from __future__ import annotations

from contextvars import ContextVar
import hashlib

client_id_context: ContextVar[str | None] = ContextVar("oauth_client_id", default=None)
UNKNOWN_AGENT = "unknown"


def agent_label(client_id: str | None, labels: dict[str, str]) -> str:
    return labels.get(client_id, "Unknown") if client_id is not None else "Unknown"


def agent_disambiguator(client_id: str | None, labels: dict[str, str]) -> str | None:
    """Display-only client fingerprint when an authenticated client lacks a label."""
    if client_id is None or client_id in labels:
        return None
    return hashlib.sha256(client_id.encode("utf-8")).hexdigest()[:12]
