"""Optional ChatGPT attached-file capability probe with bounded HTTPS reads.

No SSH file changes, persistence, log payloads or transfer sessions. This tests whether ChatGPT provides a native file param and returns an MCP
binary resource. Only verified public HTTPS endpoints are fetchable, with a
pinned IP per hop, original-host TLS identity and bounded redirects/body.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import logging
import re
import socket
from urllib.parse import urljoin, urlsplit

import httpx
from mcp.types import BlobResourceContents, CallToolResult, EmbeddedResource, TextContent
from pydantic import Field

from .contracts import ChatGPTFileRef, StrictRequest

# The source URL contains a signed bearer capability. httpx/httpcore may
# otherwise include the full URL and query string in INFO/DEBUG logs.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

MAX_PROBE_BYTES = 65536
MAX_REDIRECTS = 3
DNS_TIMEOUT_SECONDS = 3.0


class BinaryProbeRequest(StrictRequest):
    file: ChatGPTFileRef
    reason: str = Field(min_length=1, max_length=200)


class BinaryProbeError(ValueError):
    def __init__(self, message: str, *, http_status: int | None = None):
        super().__init__(message)
        self.http_status = http_status


# Map only known internal literals; never return or persist exception text.
# An arbitrary exception string may contain a signed URL or bearer token.
_SOURCE_FAILURE_CATEGORIES = {
    "file source URL is malformed": "invalid_url",
    "file source is not a public HTTPS URL": "invalid_url",
    "file source DNS lookup failed": "dns_failure",
    "file source resolves to a non-public address": "unsafe_address",
    "file source DNS lookup timed out": "dns_timeout",
    "file redirect has no location": "redirect_invalid",
    "too many file redirects": "redirect_limit",
    "file source returned an unsuccessful response": "http_status",
    "compressed file responses are not supported": "encoding_rejected",
    "invalid file content length": "invalid_content_length",
    "file exceeds the probe's size bound": "size_limit",
    "file source network error": "network_failure",
}


def source_failure_diagnostic(
    exc: BinaryProbeError, download_url: str,
) -> dict[str, str | int]:
    """Return ephemeral, bounded diagnostics; never return a signed URL.

    Only the initial source hostname is shown, never a URL, path, query,
    signed-file identifier, redirect destination or untrusted exception text.
    This object is returned to the OAuth-authorized caller, not stored in audit.
    """
    category = _SOURCE_FAILURE_CATEGORIES.get(str(exc), "unknown")
    detail: dict[str, str | int] = {"category": category}
    try:
        hostname = urlsplit(download_url).hostname
    except ValueError:
        hostname = None
    if hostname is not None:
        host = hostname.lower()
        # Exclude non-DNS, overlong and control-character values. Never show
        # credentials or paths, even if the input URL was malformed.
        if (len(host) <= 253 and
                re.fullmatch(r"[a-z0-9.-]+", host, flags=re.ASCII) and
                all(0 < len(label) <= 63 for label in host.split("."))):
            detail["source_hostname"] = host
    if (category == "http_status" and type(exc.http_status) is int
            and 100 <= exc.http_status <= 599):
        detail["http_status"] = exc.http_status
    return detail


def validate_url(url: str) -> tuple[httpx.URL, str, str]:
    """Resolve *all* addresses, reject unsafe ones, return pinned IP and SNI.

    The actual HTTP/TLS connection MUST use the pinned literal IP, never
    resolve the hostname a second time after this validation.
    """
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
        if (parsed.scheme != "https" or not hostname
                or port not in (None, 443) or parsed.username is not None
                or parsed.password is not None or parsed.fragment):
            raise ValueError("Not a safe HTTPS URL")
        # Keep HTTPX's safe URL construction/IDNA normalization and preserve
        # the original path and signed query bytes when changing only host.
        original = httpx.URL(url)
        tls_host = original.host
        if not tls_host:
            raise ValueError("Missing TLS hostname")
    except (ValueError, httpx.InvalidURL):
        raise BinaryProbeError("file source is not a public HTTPS URL") from None
    # IP literals must be checked directly; never trust DNS to turn a
    # private literal into a public address.
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None:
        if not literal.is_global:
            raise BinaryProbeError("file source resolves to a non-public address")
        return original, tls_host, str(literal)
    # Strict DNS syntax avoids ambiguous authorities, Unicode controls,
    # malformed labels and accidental HTTP Host header injection.
    labels = hostname.split(".")
    if (len(hostname) > 253 or any(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
                         label, flags=re.ASCII) is None
            for label in labels)):
        raise BinaryProbeError("file source is not a public HTTPS URL")
    try:
        addrs = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except OSError:
        raise BinaryProbeError("file source DNS lookup failed") from None
    # Fail closed if even one answer is internal/special, not just the first.
    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        for info in addrs:
            if info[0] not in (socket.AF_INET, socket.AF_INET6):
                raise ValueError("Unsupported address family")
            addr = ipaddress.ip_address(info[4][0])
            if not addr.is_global:
                raise ValueError("Untrusted address")
            ips.append(addr)
    except (ValueError, IndexError, KeyError, TypeError):
        raise BinaryProbeError("file source resolves to a non-public address") from None
    if not ips:
        raise BinaryProbeError("file source resolves to a non-public address")
    return original, tls_host, str(ips[0])


async def validate_url_async(url: str) -> tuple[httpx.URL, str, str]:
    """Bound DNS resolution so slow hostnames cannot block the event loop."""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(validate_url, url),
            timeout=DNS_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        raise BinaryProbeError("file source DNS lookup timed out") from None


async def read_binary_file(
    download_url: str, *,
    max_bytes: int = MAX_PROBE_BYTES,
) -> bytes:
    current = download_url
    for _ in range(MAX_REDIRECTS + 1):
        original, tls_host, public_ip = await validate_url_async(current)
        # Use an IP literal for the socket connection: HTTPX/httpcore cannot
        # resolve a different (potentially private) address after our check.
        # Original Host header AND TLS SNI/certificate identity are retained.
        # Separate client per redirect avoids reusing an IP-keyed TLS session
        # across different hostname identities.
        pinned = original.copy_with(host=public_ip)
        try:
            async with httpx.AsyncClient(
                timeout=15.0, follow_redirects=False, trust_env=False
            ) as client:
                async with client.stream(
                    "GET", pinned,
                    headers={"Accept-Encoding": "identity",
                             "Host": f"[{tls_host}]" if ":" in tls_host else tls_host},
                    extensions={"sni_hostname": tls_host},
                ) as response:
                    if response.status_code in (301, 302, 303, 307, 308):
                        next_url = response.headers.get("location")
                        if not next_url:
                            raise BinaryProbeError("file redirect has no location")
                        current = urljoin(current, next_url)
                        continue
                    if response.status_code != 200:
                        raise BinaryProbeError(
                            "file source returned an unsuccessful response",
                            http_status=response.status_code,
                        )
                    encoding = response.headers.get("content-encoding")
                    if encoding is not None and encoding.strip().lower() != "identity":
                        raise BinaryProbeError("compressed file responses are not supported")
                    declared = response.headers.get("content-length")
                    if declared is not None:
                        try:
                            size = int(declared)
                        except ValueError:
                            raise BinaryProbeError("invalid file content length") from None
                        if size < 0 or size > max_bytes:
                            raise BinaryProbeError("file exceeds the probe's size bound")
                    content = bytearray()
                    async for block in response.aiter_raw(chunk_size=8192):
                        if len(content) + len(block) > max_bytes:
                            raise BinaryProbeError("file exceeds the probe's size bound")
                        content.extend(block)
                    return bytes(content)
        except httpx.RequestError:
            # Never reflect potentially secret-bearing URL/headers from HTTPX.
            raise BinaryProbeError("file source network error") from None
    raise BinaryProbeError("too many file redirects")


def binary_resource_result(data: bytes) -> CallToolResult:
    """Return a real MCP blob, plus model-readable metadata but no content log."""
    if len(data) > MAX_PROBE_BYTES:
        raise BinaryProbeError("probe output exceeds the size bound")
    digest = hashlib.sha256(data).hexdigest()
    return CallToolResult(
        content=[
            TextContent(
                type="text",
                text=f'File attachment probe: {len(data)} bytes, sha256={digest}. '
                     "Check whether ChatGPT exposes the accompanying binary resource "
                     "as a downloadable attachment. This is not an SSH transfer.",
            ),
            EmbeddedResource(
                type="resource",
                resource=BlobResourceContents(
                    uri=f"ssh-mcp-probe://sha256/{digest}",
                    mime_type="application/octet-stream",
                    blob=base64.b64encode(data).decode("ascii"),
                ),
            ),
        ]
    )


async def probe_exchange(arguments: BinaryProbeRequest) -> CallToolResult:
    binary = await read_binary_file(arguments.file.download_url)
    return binary_resource_result(binary)
