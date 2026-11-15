"""Bounded streaming reads for unauthenticated URL-encoded forms."""
from __future__ import annotations

from starlette.requests import Request


async def read_bounded_body(request: Request, *, max_bytes: int) -> bytes:
    """Limit retained bytes and stop reading as soon as a body exceeds the cap."""
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            length = int(declared)
        except ValueError as exc:
            raise ValueError("Invalid form Content-Length") from exc
        if length < 0:
            raise ValueError("Invalid form Content-Length")
        if length > max_bytes:
            raise ValueError("Form body is too large")
    body = bytearray()
    async for chunk in request.stream():
        if len(chunk) > max_bytes - len(body):
            raise ValueError("Form body is too large")
        body.extend(chunk)
    return bytes(body)
