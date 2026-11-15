"""Streaming form limits: reject before buffering and never read later chunks."""
from __future__ import annotations

import unittest

from starlette.requests import Request

from app.form_body import read_bounded_body
from app.oauth import _read_form
from app.history import _form


def request_with_chunks(chunks: list[bytes], *, length: str | None = None
                        ) -> tuple[Request, list[bytes]]:
    received: list[bytes] = []
    pending = iter(chunks)

    async def receive() -> dict[str, object]:
        try:
            chunk = next(pending)
        except StopIteration:
            chunk = b""
        received.append(chunk)
        return {"type": "http.request", "body": chunk,
                "more_body": len(received) < len(chunks)}

    headers = [(b"content-type", b"application/x-www-form-urlencoded")]
    if length is not None:
        headers.append((b"content-length", length.encode("ascii")))
    scope = {"type": "http", "method": "POST", "path": "/oauth/token",
             "headers": headers, "query_string": b"", "http_version": "1.1",
             "scheme": "http", "server": ("localhost", 80), "client": ("127.0.0.1", 1)}
    return Request(scope, receive=receive), received


class BoundedFormTests(unittest.IsolatedAsyncioTestCase):
    async def test_declared_oversize_rejected_without_reading_body(self):
        for length in ("17", "18446744073709551616"):
            with self.subTest(length=length):
                request, reads = request_with_chunks([b"tiny"], length=length)
                with self.assertRaisesRegex(ValueError, "too large"):
                    await read_bounded_body(request, max_bytes=16)
                self.assertEqual(reads, [])

    async def test_bogus_declared_length_is_rejected_without_streaming(self):
        for length in ("bogus", "-1"):
            with self.subTest(length=length):
                request, reads = request_with_chunks([b"tiny"], length=length)
                with self.assertRaisesRegex(ValueError, "Content-Length"):
                    await read_bounded_body(request, max_bytes=16)
                self.assertEqual(reads, [])

    async def test_chunked_oversize_stops_before_reading_further_chunks(self):
        chunks = [b"field=a", b"0123456789", b"must-not-be-read"]
        request, reads = request_with_chunks(chunks)
        with self.assertRaisesRegex(ValueError, "too large"):
            await read_bounded_body(request, max_bytes=16)
        self.assertEqual(reads, chunks[:2])

    async def test_oauth_and_console_have_independent_form_limits(self):
        max_oauth = b"x=" + b"a" * 16382
        request, reads = request_with_chunks([max_oauth[:100], max_oauth[100:]])
        parsed = await _read_form(request)
        self.assertEqual(len(parsed["x"]), 16382)
        self.assertEqual(reads, [max_oauth[:100], max_oauth[100:]])
        request, _ = request_with_chunks([b"x=" + b"a" * 16383])
        with self.assertRaisesRegex(ValueError, "too large"):
            await _read_form(request)
        request, _ = request_with_chunks([b"csrf=" + b"a" * 8187])
        parsed = await _form(request)
        self.assertEqual(len(parsed["csrf"]), 8187)
        request, _ = request_with_chunks([b"csrf=" + b"a" * 8188])
        with self.assertRaisesRegex(ValueError, "too large"):
            await _form(request)

    async def test_short_form_parses_last_value_and_preserves_blanks(self):
        request, _ = request_with_chunks([b"x=1&x=2&empty="])
        parsed = await _read_form(request)
        self.assertEqual(parsed, {"x": "2", "empty": ""})
        request, _ = request_with_chunks([b"x=1&x=2&empty="])
        parsed = await _form(request)
        self.assertEqual(parsed, {"x": "2", "empty": ""})
