"""Bounded, pinned-IP OAuth Client ID Metadata Document discovery.

Unknown client IDs are untrusted URLs. No redirects, proxy use or private-network
connections are permitted; an exact metadata/redirect match is required.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import time
from urllib.parse import SplitResult, urlsplit
from typing import Any

import httpx

MAX_DOCUMENT_BYTES = 32768
MAX_CACHE_CLIENTS = 64
_CLIENT_HOST = re.compile(r"[A-Za-z0-9.-]{1,253}\Z", re.ASCII)
_CLIENT_PATH = re.compile(r"/[^\x00-\x20\x7f]*\Z", re.ASCII)


def _parts(value: str, *, metadata: bool = False) -> SplitResult:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise ValueError("Invalid OAuth URL")
    if any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ValueError("Invalid OAuth URL")
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise ValueError("Invalid OAuth URL") from exc
    if (not hostname or parts.username is not None or parts.password is not None
            or parts.fragment or "%" in parts.netloc or "\\" in parts.netloc):
        # Zone-scoped IPv6 literals and escaped/ambiguous authorities must not
        # enter the browser CSP or the MCP transport Origin allowlist.
        raise ValueError("Invalid OAuth URL")
    if not parts.path.startswith("/") or not _CLIENT_PATH.fullmatch(parts.path):
        raise ValueError("Invalid OAuth URL")
    if metadata and (parts.scheme != "https" or parts.path == "/"):
        raise ValueError("OAuth client_id must be an HTTPS metadata document URL")
    if parts.scheme not in {"https", "http"} or (metadata and parts.scheme != "https"):
        raise ValueError("Invalid OAuth URL scheme")
    if port is not None and port not in range(1, 65536):
        raise ValueError("Invalid OAuth URL port")
    # Internationalized hostnames must use the unambiguous ASCII IDNA form in
    # the client ID, so the document identity is byte-for-byte comparable.
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        if not _CLIENT_HOST.fullmatch(hostname) or any(
            not label or label.startswith("-") or label.endswith("-")
            for label in hostname.split(".")
        ):
            raise ValueError("Invalid OAuth URL hostname")
    if parts.scheme == "http" and hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("Insecure OAuth redirect URI")
    if metadata and parts.scheme != "https":
        raise ValueError("OAuth client ID must be HTTPS")
    return parts


def redirect_origin(value: str) -> str:
    parts = _parts(value)
    assert parts.hostname is not None
    try:
        parsed = ipaddress.ip_address(parts.hostname)
        host = f"[{parsed.compressed}]" if parsed.version == 6 else str(parsed)
    except ValueError:
        host = parts.hostname.lower()
    default_port = 443 if parts.scheme == "https" else 80
    port = f":{parts.port}" if parts.port is not None and parts.port != default_port else ""
    return f"{parts.scheme}://{host}{port}"


async def _public_address(hostname: str, port: int) -> str:
    try:
        records = await asyncio.wait_for(
            asyncio.to_thread(socket.getaddrinfo, hostname, port,
                              type=socket.SOCK_STREAM),
            timeout=5,
        )
        addresses = sorted({str(record[4][0]) for record in records})
        if not addresses or any(not ipaddress.ip_address(addr).is_global
                                for addr in addresses):
            raise ValueError("OAuth client metadata network address is not public")
        return addresses[0]
    except (OSError, asyncio.TimeoutError) as exc:
        raise ValueError("OAuth client metadata DNS lookup failed") from exc


async def _fetch_metadata(client_id: str, timeout: float) -> dict[str, Any]:
    parts = _parts(client_id, metadata=True)
    address = await _public_address(parts.hostname or "", parts.port or 443)
    # Pin the connection to the already-vetted IP. TLS still verifies the
    # original DNS hostname using the SNI extension. No environment proxies.
    authority = f"[{address}]" if ":" in address else address
    url = f"https://{authority}:{parts.port or 443}{parts.path}"
    if parts.query:
        url += f"?{parts.query}"
    try:
        async with httpx.AsyncClient(timeout=min(timeout, 8), trust_env=False,
                                     follow_redirects=False) as client:
            async with client.stream(
                "GET", url,
                headers={"Host": parts.netloc, "Accept": "application/json"},
                extensions={"sni_hostname": parts.hostname},
            ) as response:
                if response.status_code != 200:
                    raise ValueError("OAuth client metadata request rejected")
                chunks = bytearray()
                async for part in response.aiter_bytes():
                    chunks.extend(part)
                    if len(chunks) > MAX_DOCUMENT_BYTES:
                        raise ValueError("OAuth client metadata is too large")
        document = json.loads(chunks)
    except (httpx.HTTPError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Unable to validate OAuth client metadata") from exc
    if not isinstance(document, dict):
        raise ValueError("Invalid OAuth client metadata document")
    return document


def _verify_metadata(client_id: str, redirect_uri: str, document: dict[str, Any]) -> None:
    _parts(client_id, metadata=True)
    redirect_origin(redirect_uri)
    if document.get("client_id") != client_id:
        raise ValueError("CIMD client_id mismatch")
    if not isinstance(document.get("client_name"), str) or not 1 <= len(document["client_name"]) <= 160:
        raise ValueError("CIMD client_name is missing or invalid")
    redirects = document.get("redirect_uris")
    if not isinstance(redirects, list) or not 1 <= len(redirects) <= 32:
        raise ValueError("CIMD redirect_uris are invalid")
    if any(not isinstance(uri, str) or len(uri) > 2048 for uri in redirects):
        raise ValueError("Invalid CIMD redirect URI")
    if redirect_uri not in redirects:
        raise ValueError("CIMD does not allow this redirect_uri")
    response_types = document.get("response_types", ["code"])
    grant_types = document.get("grant_types", ["authorization_code"])
    if not isinstance(response_types, list) or "code" not in response_types:
        raise ValueError("CIMD does not support authorization code responses")
    if not isinstance(grant_types, list) or "authorization_code" not in grant_types:
        raise ValueError("CIMD does not support the authorization_code grant")
    # RFC 7591 uses the singular key; accept the legacy array variant too.
    # Reject malformed or inconsistent declarations, never Python substring
    # matches on strings or TypeError from untrusted JSON values.
    method = document.get("token_endpoint_auth_method", "none")
    methods = document.get("token_endpoint_auth_methods_supported", ["none"])
    if not isinstance(method, str) or method != "none":
        raise ValueError("CIMD requires unsupported client authentication")
    if (not isinstance(methods, list)
            or not all(isinstance(item, str) for item in methods)
            or method not in methods):
        raise ValueError("CIMD requires unsupported client authentication")


class ClientMetadataRegistry:
    """Small, bounded per-client cache. A new redirect still checks the document."""

    def __init__(self) -> None:
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._lock = asyncio.Lock()
        self._fetch_slots = asyncio.Semaphore(6)

    async def validate(self, client_id: str, redirect_uri: str,
                       *, timeout: float, cache_ttl: int) -> dict[str, Any]:
        _parts(client_id, metadata=True)
        redirect_origin(redirect_uri)
        async with self._lock:
            cached = self._cache.get(client_id)
            if cached and cached[0] > time.monotonic():
                _verify_metadata(client_id, redirect_uri, cached[1])
                return cached[1]

        # Never hold the shared cache lock during DNS or network I/O. A total
        # deadline also bounds providers that send one byte per read timeout.
        try:
            async with asyncio.timeout(min(max(timeout, 1.0), 10.0)):
                async with self._fetch_slots:
                    document = await _fetch_metadata(client_id, timeout)
        except TimeoutError as exc:
            raise ValueError("OAuth client metadata discovery timed out") from exc

        _verify_metadata(client_id, redirect_uri, document)
        async with self._lock:
            if len(self._cache) >= MAX_CACHE_CLIENTS and client_id not in self._cache:
                self._cache.pop(next(iter(self._cache)))
            self._cache[client_id] = (
                time.monotonic() + min(max(cache_ttl, 1), 3600), document,
            )
        return document
