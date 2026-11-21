from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import html
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from functools import lru_cache
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode

import jwt
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from mcp.server.auth.provider import AccessToken

from . import config
from .oauth_sessions import SessionStore
from .client_metadata import ClientMetadataRegistry, redirect_origin, _parts
from .dcr_registry import DCRStore, RegistrationError
from .form_body import read_bounded_body
from .config import (
    MCP_ACCESS_TOKEN_TTL,
    MCP_SESSION_TTL_DEFAULT,
    MCP_ALLOWED_REDIRECT_URIS,
    MCP_AUTH_CODE_TTL,
    MCP_CIMD_CACHE_TTL,
    MCP_CIMD_CLIENT_ID,
    MCP_CIMD_VALIDATE_REMOTE,
    MCP_ISSUER,
    MCP_LOGIN_KEY,
    MCP_LOGIN_MAX_FAILURES,
    MCP_LOGIN_WINDOW_SECONDS,
    MCP_RESOURCE,
    MCP_SCOPES,
    MCP_TOKEN_SIGNING_SECRET,
    REQUEST_TIMEOUT,
)


router = APIRouter()

_SCOPE_SET = frozenset(MCP_SCOPES)


def _supported_scopes() -> list[str]:
    return [*MCP_SCOPES, *([config.MCP_SSH_SCOPE] if config.MCP_SSH_TOOLS_ENABLED else [])]
_AUTHORIZE_AUDIENCE = f"{MCP_ISSUER}/oauth/authorize"
_CIMD_REGISTRY = ClientMetadataRegistry()
_AUTH_CODES: dict[str, "StoredAuthorizationCode"] = {}
_AUTH_CODES_LOCK = asyncio.Lock()
_LOGIN_FAILURES: dict[str, deque[float]] = defaultdict(deque)
_LOGIN_FAILURES_LOCK = asyncio.Lock()
class ActiveOrigins(list[str]):
    """MCP Origin membership follows live authorized sessions, not stale cache."""

    def __contains__(self, origin: object) -> bool:
        if super().__contains__(origin):
            return True  # Explicitly configured origins retain their existing policy.
        if not isinstance(origin, str):
            return False
        try:
            return origin in session_store().active_origins()
        except (OSError, sqlite3.Error, RuntimeError, ValueError):
            return False  # Failure to inspect session state never grants access.




@dataclass(slots=True)
class StoredAuthorizationCode:
    client_id: str
    redirect_uri: str
    code_challenge: str
    scopes: list[str]
    resource: str
    expires_at: float
    session_expires_at: int


def _now() -> int:
    return int(time.time())


def _security_headers(validated_redirect_uri: str | None = None) -> dict[str, str]:
    # Only a redirect previously verified against the client's metadata may
    # reach this call. Unknown/invalid requests retain same-origin-only CSP.
    origin = f" {redirect_origin(validated_redirect_uri)}" if validated_redirect_uri else ""
    return {
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "Content-Security-Policy": (
            "default-src 'none'; style-src 'unsafe-inline'; "
            f"form-action 'self'{origin}; frame-ancestors 'none'; base-uri 'none'"
        ),
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
    }


def _json_no_store(content: dict[str, Any], status_code: int = 200) -> JSONResponse:
    headers = {"Cache-Control": "no-store", "Pragma": "no-cache"}
    return JSONResponse(content, status_code=status_code, headers=headers)


def _oauth_error(error: str, description: str, status_code: int = 400) -> JSONResponse:
    return _json_no_store(
        {"error": error, "error_description": description},
        status_code=status_code,
    )


async def _read_form(request: Request, max_bytes: int = 16384) -> dict[str, str]:
    content_type = request.headers.get("content-type", "")
    if not content_type.lower().startswith("application/x-www-form-urlencoded"):
        raise ValueError("Content-Type must be application/x-www-form-urlencoded")
    raw = await read_bounded_body(request, max_bytes=max_bytes)
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Form body must be UTF-8") from exc
    parsed = parse_qs(decoded, keep_blank_values=True, strict_parsing=False)
    return {key: values[-1] for key, values in parsed.items() if values}


def _redirect_with_params(redirect_uri: str, params: dict[str, str]) -> RedirectResponse:
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(
        redirect_uri + separator + urlencode(params),
        status_code=302,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def _authorization_error_redirect(
    redirect_uri: str,
    state: str | None,
    error: str,
    description: str,
) -> RedirectResponse:
    params = {
        "error": error,
        "error_description": description,
        "iss": MCP_ISSUER,
    }
    if state is not None:
        params["state"] = state
    return _redirect_with_params(redirect_uri, params)


def _normalize_scopes(scope_text: str | None) -> list[str]:
    if not scope_text:
        return _supported_scopes()
    scopes = list(dict.fromkeys(scope_text.split()))
    requested = set(scopes)
    if not requested.issubset(set(_supported_scopes())):
        raise ValueError("Unknown OAuth scope requested")
    if not _SCOPE_SET.issubset(requested):
        raise ValueError("Required MCP access scope is missing")
    if config.MCP_SSH_TOOLS_ENABLED and config.MCP_SSH_SCOPE not in requested:
        raise ValueError("ssh.execute scope is required while SSH tools are enabled")
    return scopes


async def _validate_cimd(client_id: str, redirect_uri: str) -> dict[str, Any]:
    if not MCP_CIMD_VALIDATE_REMOTE:
        # Existing synthetic/offline fixtures and explicitly configured
        # single-client deployments retain their fail-closed allowlist.
        if client_id != MCP_CIMD_CLIENT_ID:
            raise ValueError("Unrecognized OAuth client_id")
        if redirect_uri not in MCP_ALLOWED_REDIRECT_URIS:
            raise ValueError("OAuth redirect_uri is not allowlisted")
        _parts(client_id, metadata=True)
        redirect_origin(redirect_uri)
        return {"client_id": client_id, "client_name": "Configured MCP client",
                "redirect_uris": [redirect_uri]}

    return await _CIMD_REGISTRY.validate(
        client_id, redirect_uri, timeout=REQUEST_TIMEOUT,
        cache_ttl=MCP_CIMD_CACHE_TTL,
    )


@lru_cache(maxsize=4)
def _dcr_store(path: str) -> DCRStore:
    return DCRStore(Path(path))


def dcr_store() -> DCRStore:
    path = os.getenv("SSH_JOBS_DB") or os.getenv("MCP_OAUTH_DB")
    if not path:
        raise RuntimeError("Private SQLite OAuth session database is required")
    return _dcr_store(path)


async def _validate_client(client_id: str, redirect_uri: str) -> dict[str, Any]:
    if client_id.startswith("dcr_"):
        if not config.MCP_DCR_ENABLED:
            raise ValueError("Dynamic client registration is disabled")
        item = dcr_store().get(client_id, redirect_uri)
        if item is None:
            raise ValueError("Unknown client or unregistered redirect_uri")
        return item
    return await _validate_cimd(client_id, redirect_uri)


def _make_authorization_request_token(
    *,
    client_id: str,
    redirect_uri: str,
    state: str | None,
    code_challenge: str,
    scopes: list[str],
    resource: str,
) -> str:
    now = _now()
    payload = {
        "iss": MCP_ISSUER,
        "aud": _AUTHORIZE_AUDIENCE,
        "iat": now,
        "exp": now + MCP_AUTH_CODE_TTL,
        "jti": secrets.token_urlsafe(16),
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "scope": " ".join(scopes),
        "resource": resource,
        "purpose": "authorization_request",
    }
    return jwt.encode(
        payload,
        MCP_TOKEN_SIGNING_SECRET,
        algorithm="HS256",
        headers={"typ": "JWT"},
    )


def _decode_authorization_request_token(token: str) -> dict[str, Any]:
    payload = jwt.decode(
        token,
        MCP_TOKEN_SIGNING_SECRET,
        algorithms=["HS256"],
        audience=_AUTHORIZE_AUDIENCE,
        issuer=MCP_ISSUER,
        options={"require": ["exp", "iat", "iss", "aud", "jti"]},
    )
    if payload.get("purpose") != "authorization_request":
        raise ValueError("Invalid authorization request token")
    return payload


async def _login_allowed(client_ip: str) -> tuple[bool, int]:
    now = time.monotonic()
    cutoff = now - MCP_LOGIN_WINDOW_SECONDS
    async with _LOGIN_FAILURES_LOCK:
        failures = _LOGIN_FAILURES[client_ip]
        while failures and failures[0] < cutoff:
            failures.popleft()
        if len(failures) >= MCP_LOGIN_MAX_FAILURES:
            retry_after = max(1, int(MCP_LOGIN_WINDOW_SECONDS - (now - failures[0])))
            return False, retry_after
        return True, 0


async def _record_login_failure(client_ip: str) -> None:
    now = time.monotonic()
    cutoff = now - MCP_LOGIN_WINDOW_SECONDS
    async with _LOGIN_FAILURES_LOCK:
        failures = _LOGIN_FAILURES[client_ip]
        while failures and failures[0] < cutoff:
            failures.popleft()
        failures.append(now)


async def _clear_login_failures(client_ip: str) -> None:
    async with _LOGIN_FAILURES_LOCK:
        _LOGIN_FAILURES.pop(client_ip, None)


async def _store_authorization_code(
    *,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    scopes: list[str],
    resource: str,
    session_ttl_seconds: int | None = None,
) -> str:
    lifetime = _validated_session_ttl(session_ttl_seconds)
    code = secrets.token_urlsafe(32)
    item = StoredAuthorizationCode(
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        scopes=scopes,
        resource=resource,
        expires_at=time.time() + MCP_AUTH_CODE_TTL,
        session_expires_at=_now() + lifetime,
    )
    async with _AUTH_CODES_LOCK:
        # Opportunistically remove expired one-time codes.
        now = time.time()
        expired = [key for key, value in _AUTH_CODES.items() if value.expires_at <= now]
        for key in expired:
            _AUTH_CODES.pop(key, None)
        _AUTH_CODES[code] = item
    return code


# RFC 7636: 43-128 unreserved characters in the verifier; S256 is a
# canonical 43-character base64url representation of a 32-byte SHA256 digest.
_PKCE_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}\Z", re.ASCII)
_PKCE_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}\Z", re.ASCII)


def _valid_pkce_challenge(challenge: str) -> bool:
    if not _PKCE_CHALLENGE.fullmatch(challenge):
        return False
    try:
        digest = base64.b64decode(challenge + "=", altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        return False
    return (len(digest) == 32 and
            base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii") == challenge)


def _pkce_s256(code_verifier: str) -> str:
    if not _PKCE_VERIFIER.fullmatch(code_verifier):
        raise ValueError("Invalid PKCE code_verifier")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _validated_session_ttl(value: int | None) -> int:
    lifetime = MCP_SESSION_TTL_DEFAULT if value is None else value
    if type(lifetime) is not int or lifetime not in config.MCP_SESSION_LIFETIMES:
        raise ValueError("Unsupported OAuth authorization lifetime")
    return lifetime


def _selected_session_ttl(raw: str | None) -> int:
    if raw is None:
        return _validated_session_ttl(None)
    options = {str(seconds): seconds for seconds in config.MCP_SESSION_LIFETIMES}
    if raw not in options:
        raise ValueError("Invalid OAuth authorization lifetime")
    return options[raw]


@lru_cache(maxsize=4)
def _session_store(path: str) -> SessionStore:
    return SessionStore(Path(path))


def session_store() -> SessionStore:
    path = os.getenv("SSH_JOBS_DB") or os.getenv("MCP_OAUTH_DB")
    if not path:
        raise RuntimeError("Private SQLite OAuth session database is required")
    return _session_store(path)


def _signing_key_id() -> str:
    return hashlib.sha256(MCP_TOKEN_SIGNING_SECRET.encode("utf-8")).hexdigest()


def issue_access_token(
    client_id: str, scopes: list[str], token_ttl_seconds: int | None = None,
    *, session_id: str | None = None, session_expires_at: int | None = None,
) -> tuple[str, int]:
    # The public OAuth endpoint always passes a persisted session_id. Direct
    # invocations by internal synthetic test fixtures remain short-lived.
    if token_ttl_seconds is not None and (type(token_ttl_seconds) is not int
                                          or token_ttl_seconds != MCP_ACCESS_TOKEN_TTL):
        raise ValueError("OAuth access token duration must be 15 minutes")
    if config.MCP_SSH_SCOPE in scopes and not config.MCP_SSH_TOOLS_ENABLED:
        raise ValueError("SSH execution scope is disabled")
    now = _now()
    expires_at = now + MCP_ACCESS_TOKEN_TTL
    if session_expires_at is not None:
        expires_at = min(expires_at, session_expires_at)
    if expires_at <= now:
        raise ValueError("OAuth authorization session has expired")
    claims = {
        "iss": MCP_ISSUER,
        "sub": config.MCP_OPERATOR_SUBJECT,
        "aud": MCP_RESOURCE,
        "iat": now,
        "exp": expires_at,
        "jti": secrets.token_urlsafe(16),
        "ver": 2,  # Reject pre-upgrade long-lived bearer tokens.
        "client_id": client_id,
        "scope": " ".join(scopes),
    }
    if session_id is not None:
        claims["sid"] = session_id
    token = jwt.encode(
        claims, MCP_TOKEN_SIGNING_SECRET, algorithm="HS256",
        headers={"typ": "at+jwt"},
    )
    return token, expires_at


def client_audit_actor(client_id: str) -> str:
    """Partition MCP-visible audit by OAuth client without changing SSH grants.

    Legacy configured ChatGPT/standalone operator retains its existing rows.
    The signed host inventory always authorizes the base operator principal.
    """
    if client_id == MCP_CIMD_CLIENT_ID:
        return config.MCP_OPERATOR_SUBJECT
    digest = hashlib.sha256(client_id.encode("utf-8")).hexdigest()
    return f"{config.MCP_OPERATOR_SUBJECT}@{digest}"


class OAuthTokenVerifier:
    """Verify SSH-MCP OAuth access tokens for the MCP SDK bearer middleware."""

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            claims = jwt.decode(
                token,
                MCP_TOKEN_SIGNING_SECRET,
                algorithms=["HS256"],
                audience=MCP_RESOURCE,
                issuer=MCP_ISSUER,
                options={
                    "require": [
                        "exp",
                        "iat",
                        "iss",
                        "aud",
                        "sub",
                        "client_id",
                        "scope",
                    ]
                },
            )
            if (claims.get("ver") != 2 or
                    int(claims["exp"]) - int(claims["iat"]) > 900 or
                    claims["sub"] != config.MCP_OPERATOR_SUBJECT):
                return None
            scopes = str(claims["scope"]).split()
            if not _SCOPE_SET.issubset(set(scopes)):
                return None
            if config.MCP_SSH_SCOPE in scopes and not config.MCP_SSH_TOOLS_ENABLED:
                return None
            if str(claims["client_id"]).startswith("dcr_"):
                if not config.MCP_DCR_ENABLED or dcr_store().get(str(claims["client_id"])) is None:
                    return None
            sid = claims.get("sid")
            if sid is not None and (
                not isinstance(sid, str) or not 16 <= len(sid) <= 128
                or not re.fullmatch(r"[A-Za-z0-9_-]+", sid)
            ):
                return None
            return AccessToken(
                token=token,
                client_id=str(claims["client_id"]),
                scopes=scopes,
                expires_at=int(claims["exp"]),
                resource=MCP_RESOURCE,
                subject=str(claims["sub"]),
                claims={"iss": str(claims["iss"]), "jti": str(claims.get("jti", "")),
                        **({"sid": sid} if sid is not None else {})},
            )
        except (jwt.PyJWTError, KeyError, TypeError, ValueError):
            return None


@router.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource_metadata() -> JSONResponse:
    return _json_no_store(
        {
            "resource": MCP_RESOURCE,
            "authorization_servers": [MCP_ISSUER],
            "scopes_supported": _supported_scopes(),
        }
    )


@router.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server_metadata() -> JSONResponse:
    return _json_no_store(
        {
            "issuer": MCP_ISSUER,
            "authorization_endpoint": f"{MCP_ISSUER}/oauth/authorize",
            "token_endpoint": f"{MCP_ISSUER}/oauth/token",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": _supported_scopes(),
            "token_endpoint_auth_methods_supported": ["none"],
            "client_id_metadata_document_supported": True,
            **({"registration_endpoint": f"{MCP_ISSUER}/oauth/register"}
               if config.MCP_DCR_ENABLED else {}),
            "authorization_response_iss_parameter_supported": True,
        }
    )


@router.post("/oauth/register")
async def oauth_register(request: Request) -> JSONResponse:
    if not config.MCP_DCR_ENABLED:
        return _oauth_error("invalid_request", "Dynamic registration is disabled", status_code=404)
    if request.headers.get("content-type", "").split(";", 1)[0].lower().strip() != "application/json":
        return _oauth_error("invalid_client_metadata", "Content-Type must be application/json")
    try:
        body = await read_bounded_body(request, max_bytes=16384)
        payload = json.loads(body)
        entry = dcr_store().register(
            payload, request.client.host if request.client else "unknown",
            signing_salt=config.MCP_TOKEN_SIGNING_SECRET,
        )
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, RegistrationError):
            return _oauth_error(exc.error, str(exc), status_code=exc.status)
        return _oauth_error("invalid_client_metadata", "Invalid registration JSON")
    except (OSError, sqlite3.Error, RuntimeError):
        return _oauth_error("server_error", "Registration store unavailable", status_code=503)
    return JSONResponse(entry, status_code=201,
                        headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


@router.get("/oauth/authorize")
async def oauth_authorize_get(request: Request) -> Response:
    query = request.query_params
    client_id = query.get("client_id", "")
    redirect_uri = query.get("redirect_uri", "")
    state = query.get("state")
    response_type = query.get("response_type", "")
    code_challenge = query.get("code_challenge", "")
    code_challenge_method = query.get("code_challenge_method", "")
    resource = query.get("resource", "")
    scope_text = query.get("scope")

    # Validate the redirect target before ever redirecting errors to it.
    try:
        client_metadata = await _validate_client(client_id, redirect_uri)
    except ValueError as exc:
        return HTMLResponse(
            f"<h1>Invalid OAuth request</h1><p>{html.escape(str(exc))}</p>",
            status_code=400,
            headers=_security_headers(),
        )

    if response_type != "code":
        return _authorization_error_redirect(
            redirect_uri, state, "unsupported_response_type", "response_type must be code"
        )
    if code_challenge_method != "S256" or not _valid_pkce_challenge(code_challenge):
        return _authorization_error_redirect(
            redirect_uri, state, "invalid_request", "PKCE S256 is required"
        )
    if resource != MCP_RESOURCE:
        return _authorization_error_redirect(
            redirect_uri, state, "invalid_target", "resource does not match this MCP server"
        )
    try:
        scopes = _normalize_scopes(scope_text)
    except ValueError as exc:
        return _authorization_error_redirect(
            redirect_uri, state, "invalid_scope", str(exc)
        )

    request_token = _make_authorization_request_token(
        client_id=client_id,
        redirect_uri=redirect_uri,
        state=state,
        code_challenge=code_challenge,
        scopes=scopes,
        resource=resource,
    )

    scope_items = "".join(f"<li>{html.escape(scope)}</li>" for scope in scopes)
    # Metadata is client-declared, not a brand-identity attestation.
    client_name = html.escape(str(client_metadata.get("client_name", "Unknown client")))
    client_address = html.escape(client_id)
    client_identity_label = "Registered client ID" if client_id.startswith("dcr_") else "Verified metadata URL"
    callback_address = html.escape(redirect_uri)
    lifetime_labels = ("1 hour", "8 hours", "24 hours", "7 days", "30 days")
    lifetime_options = "".join(
        f'<option value="{seconds}"'
        + (" selected" if seconds == MCP_SESSION_TTL_DEFAULT else "")
        + f">{label}</option>"
        for seconds, label in zip(config.MCP_SESSION_LIFETIMES, lifetime_labels)
    )
    page = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>SSH-MCP Authorization</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 560px; margin: 3rem auto; padding: 0 1rem; }}
    label {{ display: block; font-weight: 600; margin: 1.25rem 0 .35rem; }}
    input, select {{ width: 100%; box-sizing: border-box; padding: .65rem; font: inherit; }}
    button {{ margin-top: 1rem; padding: .7rem 1.1rem; font: inherit; cursor: pointer; }}
    .note {{ color: #555; }}
  </style>
</head>
<body>
  <h1>SSH-MCP Authorization</h1>
  <p>Enter the private MCP login key to authorize this MCP client.</p>
  <p>Requesting client: <strong>{client_name}</strong></p>
  <p class="note">{client_identity_label}: {client_address}</p>
  <p class="note">Authorization callback: {callback_address}</p>
  <p class="note">The displayed name is supplied by the client, not independently verified.</p>
  <form method="post" action="/oauth/authorize" autocomplete="off">
    <input type="hidden" name="request_token" value="{html.escape(request_token, quote=True)}">
    <label for="mcp_login_key">MCP login key</label>
    <input id="mcp_login_key" name="mcp_login_key" type="password" required autofocus>
    <label for="session_ttl_seconds">Authorize for</label>
    <select id="session_ttl_seconds" name="session_ttl_seconds">
      {lifetime_options}
    </select>
    <p class="note">Access tokens expire after at most 15 minutes. Your MCP client may renew them until the selected authorization period ends
    if it supports token refresh. Revocation of a session stops renewal;
    existing access tokens may remain valid for up to 15 minutes.</p>
    <p class="note">Requested permissions:</p>
    <ul>{scope_items}</ul>
    <button type="submit" name="decision" value="grant">Authorize this client</button>
    <button type="submit" name="decision" value="deny" formnovalidate>Cancel</button>
  </form>
</body>
</html>"""
    return HTMLResponse(page, headers=_security_headers(redirect_uri))


@router.post("/oauth/authorize")
async def oauth_authorize_post(request: Request) -> Response:
    client_ip = request.client.host if request.client else "unknown"
    allowed, retry_after = await _login_allowed(client_ip)
    if not allowed:
        return HTMLResponse(
            "<h1>Too many failed attempts</h1><p>Try again later.</p>",
            status_code=429,
            headers={**_security_headers(), "Retry-After": str(retry_after)},
        )

    try:
        form = await _read_form(request)
        request_token = form.get("request_token", "")
        supplied_key = form.get("mcp_login_key", "")
        payload = _decode_authorization_request_token(request_token)
        client_id = str(payload["client_id"])
        redirect_uri = str(payload["redirect_uri"])
        state = payload.get("state")
        code_challenge = str(payload["code_challenge"])
        if not _valid_pkce_challenge(code_challenge):
            raise ValueError("Invalid PKCE code_challenge")
        resource = str(payload["resource"])
        scopes = _normalize_scopes(str(payload["scope"]))
        session_ttl_seconds = _selected_session_ttl(form.get("session_ttl_seconds"))
        await _validate_client(client_id, redirect_uri)
    except (ValueError, KeyError, jwt.PyJWTError):
        return HTMLResponse(
            "<h1>Invalid or expired authorization request</h1><p>Start the connection again from your MCP client.</p>",
            status_code=400,
            headers=_security_headers(),
        )

    if form.get("decision") == "deny":
        return _authorization_error_redirect(
            redirect_uri, str(state) if state is not None else None,
            "access_denied", "The operator declined authorization",
        )
    if form.get("decision", "grant") != "grant":
        return _oauth_error("invalid_request", "Invalid authorization decision")
    required_key = MCP_LOGIN_KEY
    if not required_key or not secrets.compare_digest(supplied_key, required_key):
        await _record_login_failure(client_ip)
        return _authorization_error_redirect(
            redirect_uri,
            str(state) if state is not None else None,
            "access_denied",
            "The MCP login key was not accepted",
        )

    await _clear_login_failures(client_ip)
    code = await _store_authorization_code(
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        scopes=scopes,
        resource=resource,
        session_ttl_seconds=session_ttl_seconds,
    )
    if client_id.startswith("dcr_"):
        dcr_store().used(client_id)
    params = {"code": code, "iss": MCP_ISSUER}
    if state is not None:
        params["state"] = str(state)
    return _redirect_with_params(redirect_uri, params)


@router.post("/oauth/token")
async def oauth_token(request: Request) -> JSONResponse:
    try:
        form = await _read_form(request)
    except ValueError as exc:
        return _oauth_error("invalid_request", str(exc))

    grant_type = form.get("grant_type")
    if grant_type == "refresh_token":
        token = form.get("refresh_token", "")
        client_id = form.get("client_id", "")
        resource = form.get("resource", MCP_RESOURCE)
        scope = form.get("scope") if "scope" in form else None
        if not token or len(token) > 256 or not client_id:
            return _oauth_error("invalid_request", "Missing or invalid refresh grant fields")
        try:
            if client_id.startswith("dcr_"):
                if not config.MCP_DCR_ENABLED or dcr_store().get(client_id) is None:
                    raise ValueError("Unknown registered client")
            else:
                _parts(client_id, metadata=True)
        except ValueError:
            return _oauth_error("invalid_client", "OAuth client validation failed", status_code=401)
        if resource != MCP_RESOURCE:
            return _oauth_error("invalid_grant", "OAuth resource no longer allowed")
        try:
            refreshed = session_store().rotate(
                refresh_token=token, client_id=client_id, resource=MCP_RESOURCE,
                scopes=scope, signing_key_id=_signing_key_id(),
                expected_subject=config.MCP_OPERATOR_SUBJECT,
            )
        except (OSError, sqlite3.Error, RuntimeError, ValueError):
            return _oauth_error("server_error", "OAuth session store unavailable", status_code=503)
        if refreshed is None:
            return _oauth_error("invalid_grant", "Invalid or expired refresh token")
        try:
            scopes = _normalize_scopes(refreshed["scopes"])
            access_token, expires_at = issue_access_token(
                client_id, scopes, session_id=refreshed["session_id"],
                session_expires_at=refreshed["expires_at"],
            )
        except ValueError:
            return _oauth_error("invalid_grant", "OAuth authorization is no longer allowed")
        if client_id.startswith("dcr_"):
            dcr_store().used(client_id)
        return _json_no_store({
            "access_token": access_token,
            "token_type": "Bearer",
            "refresh_token": refreshed["refresh_token"],
            "expires_in": max(0, expires_at - _now()),
            "scope": refreshed["scopes"],
        })
    if grant_type != "authorization_code":
        return _oauth_error("unsupported_grant_type", "Grant type is unsupported")

    code = form.get("code", "")
    client_id = form.get("client_id", "")
    redirect_uri = form.get("redirect_uri", "")
    code_verifier = form.get("code_verifier", "")
    resource = form.get("resource", "")

    if not all((code, client_id, redirect_uri, code_verifier, resource)):
        return _oauth_error("invalid_request", "Missing required token request field")

    try:
        await _validate_client(client_id, redirect_uri)
    except ValueError:
        return _oauth_error("invalid_client", "OAuth client validation failed", status_code=401)

    async with _AUTH_CODES_LOCK:
        item = _AUTH_CODES.get(code)
        if item is None:
            return _oauth_error("invalid_grant", "Unknown or already-used authorization code")
        if item.expires_at <= time.time():
            _AUTH_CODES.pop(code, None)
            return _oauth_error("invalid_grant", "Authorization code expired")
        if (
            item.client_id != client_id
            or item.redirect_uri != redirect_uri
            or item.resource != resource
            or resource != MCP_RESOURCE
        ):
            return _oauth_error("invalid_grant", "Authorization code binding mismatch")
        try:
            computed_challenge = _pkce_s256(code_verifier)
        except ValueError:
            return _oauth_error("invalid_grant", "Invalid PKCE code_verifier")
        if not secrets.compare_digest(computed_challenge, item.code_challenge):
            return _oauth_error("invalid_grant", "PKCE verification failed")

        if item.session_expires_at <= _now():
            _AUTH_CODES.pop(code, None)
            return _oauth_error("invalid_grant", "Authorization session expired")
        # Consume the code only after every binding/PKCE check succeeds.
        _AUTH_CODES.pop(code, None)

    try:
        session_id, refresh_token = session_store().issue(
            client_id=client_id,
            subject=config.MCP_OPERATOR_SUBJECT,
            scopes=" ".join(item.scopes),
            resource=item.resource,
            expires_at=item.session_expires_at,
            signing_key_id=_signing_key_id(),
            redirect_origin=redirect_origin(redirect_uri),
        )
        access_token, expires_at = issue_access_token(
            client_id, item.scopes, session_id=session_id,
            session_expires_at=item.session_expires_at,
        )
    except (OSError, sqlite3.Error, RuntimeError, ValueError):
        return _oauth_error("server_error", "OAuth session store unavailable", status_code=503)
    if client_id.startswith("dcr_"):
        dcr_store().used(client_id)
    return _json_no_store({
        "access_token": access_token,
        "token_type": "Bearer",
        "refresh_token": refresh_token,
        "expires_in": max(0, expires_at - _now()),
        "scope": " ".join(item.scopes),
    })
