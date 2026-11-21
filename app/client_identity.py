"""Verified OAuth client attribution; never use a display label for authorization."""
from __future__ import annotations

from contextvars import ContextVar
import hashlib
import json
from typing import Any
from .client_metadata import _parts
from .dcr_registry import DCR_CLIENT_ID_PATTERN

client_id_context: ContextVar[str | None] = ContextVar("oauth_client_id", default=None)
UNKNOWN_AGENT = "unknown"


def parse_labels(raw: Any) -> dict[str, str]:
    """Validate bounded, operator-controlled presentation metadata."""
    if not isinstance(raw, dict) or len(raw) > 32:
        raise ValueError("Invalid client labels")
    labels: dict[str, str] = {}
    names = {"unknown"}
    for client_id, label in raw.items():
        # Only explicit, operator-pinned exact DCR IDs can receive labels.
        # A registration's self-asserted client_name grants no identity trust.
        if not isinstance(client_id, str):
            raise ValueError("Invalid client label ID")
        if DCR_CLIENT_ID_PATTERN.fullmatch(client_id) is None:
            _parts(client_id, metadata=True)
        if (not isinstance(label, str) or not 1 <= len(label) <= 32
                or label != label.strip() or not label.isprintable()
                or label.casefold() in names):
            raise ValueError("Invalid or duplicate client label")
        labels[client_id] = label
        names.add(label.casefold())
    return labels


def labels_from_environment(value: str) -> dict[str, str]:
    return parse_labels(json.loads(value))


def legacy_client_id(actor: str, labels: dict[str, str], subject: str,
                     default_client: str) -> str | None:
    # The original operator actor is ambiguous: standalone and legacy calls
    # used it too. Only the unambiguous, client-derived hash can be recovered.
    for client_id in labels:
        if client_id != default_client:
            digest = hashlib.sha256(client_id.encode("utf-8")).hexdigest()
            if actor == f"{subject}@{digest}":
                return client_id
    return None


def resolve_client_id(client_id: str | None, actor: str, labels: dict[str, str],
                      subject: str, default_client: str) -> str | None:
    return client_id or legacy_client_id(actor, labels, subject, default_client)


def agent_label(client_id: str | None, labels: dict[str, str]) -> str:
    return labels.get(client_id, "Unknown") if client_id is not None else "Unknown"


def agent_disambiguator(client_id: str | None, labels: dict[str, str]) -> str | None:
    """Display-only client fingerprint when an authenticated client lacks a label."""
    if client_id is None or client_id in labels:
        return None
    return hashlib.sha256(client_id.encode("utf-8")).hexdigest()[:12]
