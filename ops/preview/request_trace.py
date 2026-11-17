"""Opt-in, preview-only MCP diagnostics; never record credentials or tool payloads."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
from typing import Any

LOG = logging.getLogger("ssh_mcp.preview.http")
MAX_BODY_CAPTURE = 65536
MAX_HEADERS = 256
MAX_VALUE = 1024
# Stable only for this process: unknown values can be correlated without
# disclosing potentially credential-bearing custom headers or metadata.
_FINGERPRINT_KEY = secrets.token_bytes(32)
_SECRET_NAMES = ("authorization", "cookie", "token", "secret", "key", "password",
                 "credential", "csrf", "session-id", "session_id", "signature")
_PUBLIC_HEADERS = frozenset({"host", "accept", "content-type", "content-length",
                             "user-agent", "mcp-protocol-version", "origin"})
_CORRELATION_HEADERS = frozenset({"x-openai-session", "x-ssh-mcp-conversation"})
_CORRELATION_KEYS = frozenset({"thread_id", "turn_id", "conversation_id", "openai/session"})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:-]{0,255}$")


def _secret_name(name: str) -> bool:
    return any(fragment in name.lower() for fragment in _SECRET_NAMES)


def _fingerprint(value: str) -> str:
    return "fingerprint:" + hmac.new(_FINGERPRINT_KEY, value.encode("utf-8"),
                                    hashlib.sha256).hexdigest()[:24]


def _correlation(value: Any) -> Any:
    if isinstance(value, str):
        return value if _IDENTIFIER.fullmatch(value) else _fingerprint(value)
    return value if type(value) is int else "[NOT_AN_IDENTIFIER]"


def _headers(scope: dict[str, Any]) -> list[dict[str, str]]:
    result = []
    for raw_name, raw_value in scope.get("headers", [])[:MAX_HEADERS]:
        name = raw_name.decode("latin-1").lower()
        value = raw_value.decode("latin-1")
        if _secret_name(name):
            visible = "[REDACTED]"
        elif name in _CORRELATION_HEADERS:
            visible = _correlation(value)
        elif name in _PUBLIC_HEADERS:
            visible = value[:MAX_VALUE]
        else:
            visible = _fingerprint(value)
        result.append({"name": name, "value": visible})
    return result


def _metadata(value: Any, depth: int = 0) -> Any:
    """Retain field names/structure and known correlation IDs, not arbitrary data."""
    if depth >= 4:
        return "[MAX_DEPTH]"
    if isinstance(value, dict):
        return {
            str(key)[:120]: (
                "[REDACTED]" if _secret_name(str(key)) else
                _correlation(item) if key in _CORRELATION_KEYS else
                _metadata(item, depth + 1)
            )
            for key, item in list(value.items())[:40]
        }
    if isinstance(value, list):
        return {"type": "list", "length": len(value),
                "items": [_metadata(item, depth + 1) for item in value[:10]]}
    if isinstance(value, str):
        return _fingerprint(value)
    return {"type": type(value).__name__}


def _envelope(body: bytes) -> list[dict[str, Any]]:
    data = json.loads(body)
    calls = data if isinstance(data, list) else [data]
    result = []
    for request in calls[:10]:
        if not isinstance(request, dict):
            continue
        params = request.get("params")
        params = params if isinstance(params, dict) else {}
        arguments = params.get("arguments")
        result.append({
            "method": _correlation(request.get("method")),
            "request_id": _correlation(request.get("id")),
            "top_level_keys": sorted(str(key)[:120] for key in request)[:40],
            "params_keys": sorted(str(key)[:120] for key in params)[:40],
            "tool": _correlation(params.get("name")),
            "argument_keys": sorted(str(key)[:120] for key in arguments)[:40]
            if isinstance(arguments, dict) else [],
            "request_meta": _metadata(request.get("_meta")),
            "params_meta": _metadata(params.get("_meta")),
        })
    return result


class PreviewRequestTrace:
    """Observe bytes as the downstream app consumes them; never alter ASGI traffic."""

    def __init__(self, app: Any):
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        # OAuth forms, callback queries, console credentials, health and
        # metrics requests are deliberately outside the diagnostic scope.
        if scope.get("type") != "http" or scope.get("path") not in {"/mcp", "/mcp/"}:
            await self.app(scope, receive, send)
            return
        body = bytearray()
        total = 0
        complete = False
        emitted = False

        def emit() -> None:
            nonlocal emitted
            if emitted:
                return
            emitted = True
            try:
                entry: dict[str, Any] = {
                    "method": scope.get("method"),
                    "path": scope.get("path"),
                    "headers": _headers(scope),
                    "header_count": len(scope.get("headers", [])),
                    "body": {"size": total, "complete": complete},
                }
                if complete and total <= MAX_BODY_CAPTURE and body:
                    try:
                        entry["body"]["envelope"] = _envelope(bytes(body))
                    except (ValueError, UnicodeError, RecursionError):
                        entry["body"]["parse"] = "invalid_json"
                elif total > MAX_BODY_CAPTURE:
                    entry["body"]["parse"] = "truncated"
                LOG.warning("SSH_MCP_PREVIEW_REQUEST %s", json.dumps(entry, sort_keys=True))
            except Exception:
                # A diagnostic failure must never fail an application request.
                LOG.warning("SSH_MCP_PREVIEW_REQUEST diagnostic_failed")

        async def tracing_receive() -> Any:
            nonlocal total, complete
            event = await receive()
            if event.get("type") == "http.request":
                piece = event.get("body", b"")
                total += len(piece)
                if len(body) < MAX_BODY_CAPTURE:
                    body.extend(piece[:MAX_BODY_CAPTURE - len(body)])
                if not event.get("more_body", False):
                    complete = True
                    emit()
            return event

        if scope.get("method") not in {"POST", "PUT", "PATCH"}:
            emit()
        try:
            await self.app(scope, tracing_receive, send)
        finally:
            emit()
