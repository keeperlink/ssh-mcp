"""DEBUG-only MCP diagnostics; never record credentials or tool payloads."""
from __future__ import annotations

import json
import logging
from typing import Any

LOG = logging.getLogger(__name__)
MAX_BODY_CAPTURE = 65536
MAX_HEADERS = 256
MAX_VALUE = 1024
MAX_METADATA_DEPTH = 8
_SECRET_NAMES = ("authorization", "cookie", "token", "secret", "key", "password",
                 "passwd", "credential", "csrf", "session-id", "session_id", "sessionid",
                 "signature", "code_verifier", "code-verifier", "auth_code", "auth-code")
_SECRET_FIELDS = frozenset({"auth", "authentication", "pwd", "code", "state"})


def _secret_name(name: str) -> bool:
    name = name.lower()
    return name.rsplit("/", 1)[-1] in _SECRET_FIELDS or any(fragment in name for fragment in _SECRET_NAMES)


def _scalar(value: Any) -> Any:
    if isinstance(value, str):
        return value[:MAX_VALUE]
    return value if value is None or type(value) in (bool, int, float) else "[NOT_A_SCALAR]"


def _headers(scope: dict[str, Any]) -> list[dict[str, str]]:
    result = []
    for raw_name, raw_value in scope.get("headers", [])[:MAX_HEADERS]:
        name = raw_name.decode("latin-1").lower()
        value = raw_value.decode("latin-1")
        result.append({"name": name[:MAX_VALUE],
                       "value": "[REDACTED]" if _secret_name(name) else value[:MAX_VALUE]})
    return result


def _metadata(value: Any, depth: int = 0) -> Any:
    """Retain bounded metadata values except credential-like fields."""
    if depth >= MAX_METADATA_DEPTH:
        return "[MAX_DEPTH]"
    if isinstance(value, dict):
        return {
            str(key)[:120]: (
                "[REDACTED]" if _secret_name(str(key)) else _metadata(item, depth + 1)
            )
            for key, item in list(value.items())[:40]
        }
    if isinstance(value, list):
        return [_metadata(item, depth + 1) for item in value[:10]]
    return _scalar(value)


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
            "method": _scalar(request.get("method")),
            "request_id": _scalar(request.get("id")),
            "top_level_keys": sorted(str(key)[:120] for key in request)[:40],
            "params_keys": sorted(str(key)[:120] for key in params)[:40],
            "tool": _scalar(params.get("name")),
            "argument_keys": sorted(str(key)[:120] for key in arguments)[:40]
            if isinstance(arguments, dict) else [],
            "request_meta": _metadata(request.get("_meta")),
            "params_meta": _metadata(params.get("_meta")),
        })
    return result


class RequestTrace:
    """Observe bytes as the downstream app consumes them; never alter ASGI traffic."""

    def __init__(self, app: Any):
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        # OAuth forms, callback queries, console credentials, health and
        # metrics requests are deliberately outside the diagnostic scope.
        if (not LOG.isEnabledFor(logging.DEBUG) or scope.get("type") != "http"
                or scope.get("path") not in {"/mcp", "/mcp/"}):
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
                LOG.debug("SSH_MCP_REQUEST %s", json.dumps(entry, sort_keys=True))
            except Exception:
                # A diagnostic failure must never fail an application request.
                LOG.debug("SSH_MCP_REQUEST diagnostic_failed")

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
