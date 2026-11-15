"""TEST-237 plugin-capability experiment: no remote SSH or real user file."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import gzip
import os
import socket
import threading
import tempfile
import unittest
from contextlib import asynccontextmanager
from unittest.mock import patch

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ.setdefault("MCP_ISSUER", "http://localhost")
os.environ.setdefault("MCP_LOGIN_KEY", "synthetic-test-login-" + "a" * 40)
os.environ.setdefault("MCP_TOKEN_SIGNING_SECRET", "synthetic-test-signing-" + "b" * 40)
os.environ.setdefault("MCP_CIMD_VALIDATE_REMOTE", "false")

from app import binary_probe, config, mcp_gateway, oauth
from app.ssh_executor import SSHDenied

CLIENT = "https://chatgpt.com/oauth/client.json"
DOWNLOAD = "https://probe.example.invalid/ephemeral?sig=test"


def public_dns(_host, _port, *, type):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]


def fake_https(handler):
    def streaming_handler(request):
        reply = handler(request)
        # HTTPX's MockTransport with Response(content=...) returns an
        # already-consumed response, unlike real streamed HTTP connections.
        # Wrap fixture bytes in ByteStream for genuine aiter_raw coverage.
        if reply.is_stream_consumed:
            return httpx.Response(reply.status_code, headers=reply.headers,
                                  stream=httpx.ByteStream(reply.content))
        return reply

    transport = httpx.MockTransport(streaming_handler)
    original = httpx.AsyncClient
    def secure_client(**kwargs):
        assert kwargs["trust_env"] is False, "Proxy environment must be ignored"
        assert kwargs["follow_redirects"] is False, "Redirects need a fresh IP check"
        return original(transport=transport, **kwargs)

    return patch.object(binary_probe.httpx, "AsyncClient",
                        side_effect=secure_client)


class BinaryProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_binary_roundtrip_includes_non_text_bytes(self):
        binary = b"TEST-237\x00\xff\xfe" + bytes(range(256)) + bytes(4096)
        self.assertLess(len(binary), binary_probe.MAX_PROBE_BYTES)
        with patch.object(binary_probe.socket, "getaddrinfo", side_effect=public_dns), fake_https(
            lambda request: httpx.Response(200, content=binary)
        ):
            received = await binary_probe.read_binary_file(
                DOWNLOAD
            )
        self.assertEqual(received, binary)
        output = binary_probe.binary_resource_result(received)
        self.assertEqual(len(output.content), 2)
        blob = output.content[1]
        self.assertEqual(blob.type, "resource")
        self.assertEqual(base64.b64decode(blob.resource.blob), binary)
        self.assertEqual(blob.resource.mime_type, "application/octet-stream")
        self.assertIn(hashlib.sha256(binary).hexdigest(), output.content[0].text)
        self.assertNotIn(binary.hex(), str(output.content[0]))

    async def test_reject_private_addresses_and_disallowed_redirects(self):
        with patch.object(binary_probe.socket, "getaddrinfo", return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
        ]):
            with self.assertRaisesRegex(binary_probe.BinaryProbeError, "non-public"):
                binary_probe.validate_url(DOWNLOAD)
        with patch.object(binary_probe.socket, "getaddrinfo", side_effect=public_dns):
            for value in (
                "http://probe.example.invalid/bytes",
                "https://127.0.0.1/secret", "https://[::1]/metadata",
                "https://probe.example.invalid:8443/file",
                "https://user:password@probe.example.invalid/file",
                "https://probe.example.invalid/secret#fragment",
            ):
                with self.subTest(url=value), self.assertRaises(binary_probe.BinaryProbeError):
                    binary_probe.validate_url(value)
            with fake_https(lambda req: httpx.Response(302, headers={
                "location": "https://127.0.0.1/private",
            })):
                with self.assertRaises(binary_probe.BinaryProbeError):
                    await binary_probe.read_binary_file(
                        DOWNLOAD
                    )

    async def test_strict_byte_limit_even_without_content_length(self):
        payload = b"a" * (binary_probe.MAX_PROBE_BYTES + 1)
        with patch.object(binary_probe.socket, "getaddrinfo", side_effect=public_dns):
            with fake_https(lambda req: httpx.Response(200, content=payload)):
                with self.assertRaisesRegex(binary_probe.BinaryProbeError, "size bound"):
                    await binary_probe.read_binary_file(
                        DOWNLOAD
                    )
            with fake_https(lambda req: httpx.Response(200, headers={
                "content-length": str(binary_probe.MAX_PROBE_BYTES + 1),
            })):
                with self.assertRaisesRegex(binary_probe.BinaryProbeError, "size bound"):
                    await binary_probe.read_binary_file(
                        DOWNLOAD
                    )

    async def test_reject_compressed_expansion_before_reading_body(self):
        # A tiny gzip body can expand far above the upload limit; reading
        # decoded HTTPX chunks would allocate the expanded body first.
        compressed = gzip.compress(b"A" * (8 * 1024 * 1024 + 1))
        self.assertLess(len(compressed), 65536)
        received = []

        class GuardedCompressedStream(httpx.AsyncByteStream):
            async def __aiter__(self):
                received.append("read")
                raise AssertionError("encoded body was consumed before rejection")
                yield b""

            async def aclose(self):
                return None

        def respond(request):
            self.assertEqual(request.headers["accept-encoding"], "identity")
            return httpx.Response(200, headers={
                "content-encoding": "gzip",
                "content-length": str(len(compressed)),
            }, stream=GuardedCompressedStream())

        with patch.object(binary_probe.socket, "getaddrinfo", side_effect=public_dns):
            with fake_https(respond):
                with self.assertRaisesRegex(
                    binary_probe.BinaryProbeError, "compressed file responses"
                ):
                    await binary_probe.read_binary_file(
                        DOWNLOAD,
                        max_bytes=8 * 1024 * 1024,
                    )
        self.assertEqual(received, [])

    async def test_identity_and_unencoded_binary_are_exact(self):
        payload = b"\x00\xff\xfe" + bytes(range(256)) * 4
        for encoding in (None, "identity", "IDENTITY"):
            with self.subTest(encoding=encoding):
                headers = {"content-length": str(len(payload))}
                if encoding:
                    headers["content-encoding"] = encoding

                def respond(request):
                    self.assertEqual(request.headers["accept-encoding"], "identity")
                    return httpx.Response(200, content=payload, headers=headers)

                with patch.object(binary_probe.socket, "getaddrinfo", side_effect=public_dns):
                    with fake_https(respond):
                        received = await binary_probe.read_binary_file(
                            DOWNLOAD
                        )
                self.assertEqual(received, payload)

    async def test_reject_unexpected_content_encodings(self):
        for encoding in ("deflate", "br", "gzip, identity", "unknown"):
            with self.subTest(encoding=encoding):
                with patch.object(binary_probe.socket, "getaddrinfo", side_effect=public_dns):
                    with fake_https(lambda req: httpx.Response(
                        200, headers={"content-encoding": encoding},
                        stream=httpx.ByteStream(b"abc")
                    )):
                        with self.assertRaisesRegex(
                            binary_probe.BinaryProbeError, "compressed file responses"
                        ):
                            await binary_probe.read_binary_file(
                                DOWNLOAD
                            )

    async def test_permitted_redirect_preserves_binary_bytes(self):
        binary = bytes(range(256)) * 3
        requests: list[str] = []

        def respond(request):
            requests.append(str(request.url))
            if len(requests) == 1:
                return httpx.Response(302, headers={"location": "/actual"})
            return httpx.Response(200, content=binary, headers={
                "content-length": str(len(binary)),
            })

        with patch.object(binary_probe.socket, "getaddrinfo", side_effect=public_dns):
            with fake_https(respond):
                result = await binary_probe.read_binary_file(
                    DOWNLOAD
                )
        self.assertEqual(result, binary)
        self.assertEqual(len(requests), 2)
        self.assertTrue(requests[1].endswith("/actual"))

    async def test_non_200_and_redirect_loop_are_rejected(self):
        with patch.object(binary_probe.socket, "getaddrinfo", side_effect=public_dns):
            with fake_https(lambda req: httpx.Response(403, content=b"private")):
                with self.assertRaisesRegex(binary_probe.BinaryProbeError, "unsuccessful"):
                    await binary_probe.read_binary_file(
                        DOWNLOAD
                    )
            with fake_https(lambda req: httpx.Response(302, headers={"location": "/again"})):
                with self.assertRaisesRegex(binary_probe.BinaryProbeError, "too many"):
                    await binary_probe.read_binary_file(
                        DOWNLOAD
                    )
            with fake_https(lambda req: httpx.Response(301)):
                with self.assertRaisesRegex(binary_probe.BinaryProbeError, "no location"):
                    await binary_probe.read_binary_file(
                        DOWNLOAD
                    )

    async def test_bad_length_network_failure_and_dns_failure_are_safe(self):
        with patch.object(binary_probe.socket, "getaddrinfo", side_effect=public_dns):
            with fake_https(lambda req: httpx.Response(200, headers={"content-length": "broken"})):
                with self.assertRaisesRegex(binary_probe.BinaryProbeError, "content length"):
                    await binary_probe.read_binary_file(
                        DOWNLOAD
                    )
            def fail(request):
                raise httpx.ConnectError("private TLS detail", request=request)
            with fake_https(fail):
                with self.assertRaisesRegex(binary_probe.BinaryProbeError, "network error"):
                    await binary_probe.read_binary_file(
                        DOWNLOAD
                    )
        with patch.object(binary_probe.socket, "getaddrinfo", side_effect=OSError):
            with self.assertRaisesRegex(binary_probe.BinaryProbeError, "DNS lookup failed"):
                binary_probe.validate_url(DOWNLOAD)

    async def test_probe_failure_diagnostic_is_bounded_and_has_no_signed_url(self):
        signed = ("https://token:secret@probe.example.invalid/private/file-id?"
                  "sig=NEVER_RETURN_SIGNED_TOKEN")
        known = binary_probe.BinaryProbeError(
            "file source returned an unsuccessful response", http_status=403,
        )
        diagnostic = binary_probe.source_failure_diagnostic(known, signed)
        self.assertEqual(diagnostic, {
            "category": "http_status",
            "source_hostname": "probe.example.invalid",
            "http_status": 403,
        })
        unknown = binary_probe.BinaryProbeError("SIGNED_URL_IN_EXCEPTION")
        detail = binary_probe.source_failure_diagnostic(unknown, signed)
        self.assertEqual(detail, {
            "category": "unknown", "source_hostname": "probe.example.invalid",
        })
        for item in (diagnostic, detail):
            text = str(item)
            for forbidden in ("token", "secret", "private", "file-id", "NEVER_RETURN",
                              "SIGNED_URL", "https://"):
                self.assertNotIn(forbidden, text)

        # Untrusted Unicode, oversized or malformed hosts are never reflected.
        for url in ("https://bad_💣.test/path?sig=secret",
                    "https://" + "a" * 64 + ".example/secret",
                    "https://[bad:ipv6/path?sig=secret"):
            with self.subTest(url=url):
                item = binary_probe.source_failure_diagnostic(unknown, url)
                self.assertEqual(item, {"category": "unknown"})

    async def test_http_error_category_reflects_only_status_and_hostname(self):
        with patch.object(binary_probe.socket, "getaddrinfo", side_effect=public_dns):
            with fake_https(lambda req: httpx.Response(401, content=b"token leaked here")):
                with self.assertRaises(binary_probe.BinaryProbeError) as caught:
                    await binary_probe.read_binary_file(
                        DOWNLOAD
                    )
        self.assertEqual(binary_probe.source_failure_diagnostic(
            caught.exception, DOWNLOAD
        ), {
            "category": "http_status", "source_hostname": "probe.example.invalid",
            "http_status": 401,
        })

    async def test_any_public_https_hostname_pins_dns_and_preserves_tls_host(self):
        source = ("https://cdn.example.net/"
                  "private/blob?sig=NEVER_LOG")
        seen = []

        def respond(req):
            seen.append(req)
            self.assertEqual(req.url.host, "8.8.8.8")
            self.assertEqual(req.url.path, "/private/blob")
            self.assertEqual(req.url.query, b"sig=NEVER_LOG")
            self.assertEqual(req.headers["Host"], "cdn.example.net")
            self.assertEqual(req.extensions["sni_hostname"],
                             "cdn.example.net")
            return httpx.Response(200, content=b"PUBLIC_HTTPS_ALLOWED")

        with patch.object(binary_probe.socket, "getaddrinfo", side_effect=public_dns) as dns:
            with fake_https(respond):
                result = await binary_probe.read_binary_file(source)
        self.assertEqual(result, b"PUBLIC_HTTPS_ALLOWED")
        self.assertEqual(dns.call_count, 1)
        self.assertEqual(len(seen), 1)

    async def test_rebinding_dns_does_not_change_pinned_connection(self):
        original = public_dns("example", 443, type=socket.SOCK_STREAM)
        private = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with patch.object(binary_probe.socket, "getaddrinfo",
                          side_effect=[original, private]) as dns:
            with fake_https(lambda req: (
                self.assertEqual(req.url.host, "8.8.8.8") or
                httpx.Response(200, content=b"PINNED")
            )):
                content = await binary_probe.read_binary_file(DOWNLOAD)
        self.assertEqual(content, b"PINNED")
        # A second hostname resolution by the socket would see 127.0.0.1,
        # but HTTPX receives only a vetted literal address.
        self.assertEqual(dns.call_count, 1)

    async def test_global_ipv6_dns_answer_uses_literal_ip_with_original_tls_name(self):
        public_v6 = "2606:4700:4700::1111"
        def v6_dns(host, port, *, type):
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "",
                     (public_v6, 443, 0, 0))]
        def respond(req):
            self.assertEqual(req.url.host, public_v6)
            self.assertEqual(req.headers["host"], "probe.example.invalid")
            self.assertEqual(req.extensions["sni_hostname"], "probe.example.invalid")
            return httpx.Response(200, content=b"IPV6")
        with patch.object(binary_probe.socket, "getaddrinfo", side_effect=v6_dns):
            with fake_https(respond):
                result = await binary_probe.read_binary_file(DOWNLOAD)
        self.assertEqual(result, b"IPV6")

    async def test_removed_env_allowlist_cannot_restrict_public_sources(self):
        with patch.dict(os.environ, {"SSH_FILE_SOURCE_ALLOWED_HOSTS": "blocked.invalid"}):
            with patch.object(binary_probe.socket, "getaddrinfo",
                              side_effect=public_dns):
                with fake_https(lambda req: httpx.Response(200, content=b"OK")):
                    self.assertEqual(await binary_probe.read_binary_file(DOWNLOAD), b"OK")

    async def test_mixed_dns_answers_or_private_literal_cannot_connect(self):
        for unsafe in ("127.0.0.1", "169.254.169.254", "10.0.0.1",
                       "::1", "fe80::1", "fd00::1", "0.0.0.0"):
            with self.subTest(ip=unsafe):
                with patch.object(binary_probe.socket, "getaddrinfo") as dns:
                    with self.assertRaisesRegex(binary_probe.BinaryProbeError,
                                                "non-public"):
                        binary_probe.validate_url(
                            f"https://[{unsafe}]/private" if ":" in unsafe
                            else f"https://{unsafe}/private"
                        )
                    dns.assert_not_called()
        with patch.object(binary_probe.socket, "getaddrinfo", return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.3", 443)),
        ]):
            with fake_https(lambda req: self.fail("should not connect")):
                with self.assertRaisesRegex(binary_probe.BinaryProbeError, "non-public"):
                    await binary_probe.read_binary_file(DOWNLOAD)

    async def test_cross_host_redirect_resolves_pins_and_checks_tls_per_hop(self):
        seen = []
        def dns(host, port, *, type):
            ip = "8.8.8.8" if host == "probe.example.invalid" else "1.1.1.1"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]

        def respond(req):
            seen.append((req.url.host, req.headers["Host"],
                         req.extensions["sni_hostname"]))
            if len(seen) == 1:
                return httpx.Response(302, headers={
                    "location": "https://cdn.example.net/b?sig=x"
                })
            return httpx.Response(200, content=b"REDIRECTED")

        with patch.object(binary_probe.socket, "getaddrinfo", side_effect=dns) as resolver:
            with fake_https(respond):
                result = await binary_probe.read_binary_file(DOWNLOAD)
        self.assertEqual(result, b"REDIRECTED")
        self.assertEqual(resolver.call_count, 2)
        self.assertEqual(seen, [
            ("8.8.8.8", "probe.example.invalid", "probe.example.invalid"),
            ("1.1.1.1", "cdn.example.net",
             "cdn.example.net"),
        ])

    async def test_cross_host_redirect_to_private_dns_rejected(self):
        def dns(host, port, *, type):
            ip = "8.8.8.8" if host == "probe.example.invalid" else "10.0.0.7"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]
        requests = []
        def redirect(req):
            requests.append(req)
            return httpx.Response(302, headers={"location": "https://inside.invalid/secret"})
        with patch.object(binary_probe.socket, "getaddrinfo", side_effect=dns):
            with fake_https(redirect):
                with self.assertRaisesRegex(binary_probe.BinaryProbeError, "non-public"):
                    await binary_probe.read_binary_file(DOWNLOAD)
        self.assertEqual(len(requests), 1)

    async def test_invalid_url_report_does_not_reflect_signed_url(self):
        with self.assertRaisesRegex(binary_probe.BinaryProbeError, "public HTTPS URL"):
            binary_probe.validate_url("https://[bad:ipv6/file")
        with self.assertRaises(binary_probe.BinaryProbeError) as caught:
            binary_probe.validate_url("http://user:SECRET@external.example.invalid/path?sig=PRIVATE")
        detail = binary_probe.source_failure_diagnostic(
            caught.exception,
            "http://user:SECRET@external.example.invalid/path?sig=PRIVATE",
        )
        self.assertEqual(detail, {
            "category": "invalid_url", "source_hostname": "external.example.invalid",
        })
        self.assertNotIn("SECRET", str(detail))
        self.assertNotIn("PRIVATE", str(detail))

    async def test_zero_length_binary_is_exact_and_hashable(self):
        with patch.object(binary_probe.socket, "getaddrinfo", side_effect=public_dns):
            with fake_https(lambda req: httpx.Response(200, content=b"")):
                result = await binary_probe.read_binary_file(
                    DOWNLOAD
                )
        self.assertEqual(result, b"")
        reply = binary_probe.binary_resource_result(result)
        self.assertEqual(base64.b64decode(reply.content[1].resource.blob), b"")
        self.assertIn(hashlib.sha256(b"").hexdigest(), reply.content[0].text)

    async def test_dns_lookup_times_out_without_blocking_event_loop(self):
        entered = threading.Event()
        release = threading.Event()

        def slow_resolver(*args, **kwargs):
            entered.set()
            # The resolver remains blocked until the event-loop test releases
            # it; CI scheduling cannot invalidate a wall-clock speed claim.
            release.wait(timeout=3.0)
            return public_dns(*args, **kwargs)

        async def concurrent_request():
            while not entered.is_set():
                await asyncio.sleep(0.001)
            self.assertFalse(release.is_set())
            return "MCP event loop remained responsive during DNS"

        try:
            with patch.object(binary_probe.socket, "getaddrinfo", side_effect=slow_resolver), patch.object(
                binary_probe, "DNS_TIMEOUT_SECONDS", 0.05
            ):
                request = asyncio.create_task(binary_probe.read_binary_file(
                    DOWNLOAD
                ))
                # The parallel coroutine must run while the resolver thread is
                # still blocked; this test is not about scheduler speed.
                self.assertEqual(
                    await asyncio.wait_for(concurrent_request(), timeout=2.0),
                    "MCP event loop remained responsive during DNS",
                )
                with self.assertRaisesRegex(binary_probe.BinaryProbeError, "DNS lookup timed out"):
                    await request
        finally:
            release.set()

    async def test_resource_cap(self):
        with self.assertRaisesRegex(binary_probe.BinaryProbeError, "output exceeds"):
            binary_probe.binary_resource_result(b"x" * (binary_probe.MAX_PROBE_BYTES + 1))


class BinaryPluginContractTests(unittest.TestCase):
    class FakeSSH:
        access = "always-granted"
        def authorized_host(self, actor, host):
            if actor != "ssh-mcp-operator":
                raise SSHDenied("principal not authorized")

    def make_client(self, enabled: str):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        settings = patch.dict(os.environ, {
            "SSH_BINARY_PROBE_ENABLED": enabled,
            "SSH_JOBS_ENABLED": "false",
        })
        settings.start()
        self.addCleanup(settings.stop)
        scope_flag = patch.object(config, "MCP_SSH_TOOLS_ENABLED", True)
        scope_flag.start()
        self.addCleanup(scope_flag.stop)
        with patch.object(
            mcp_gateway.SSHExecutor, "from_environment", return_value=self.FakeSSH()
        ):
            server, sub_app = mcp_gateway.create_mcp_server()

        @asynccontextmanager
        async def lifespan(_app):
            async with server.session_manager.run():
                yield

        app = FastAPI(lifespan=lifespan)
        app.mount("/", sub_app)
        client = TestClient(app)
        client.__enter__()
        self.addCleanup(lambda: client.__exit__(None, None, None))
        token, _ = oauth.issue_access_token(CLIENT, oauth._supported_scopes())
        return client, token

    def rpc(self, client, token, method, params):
        response = client.post("/mcp", headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream", "Host": "localhost",
        }, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn("error", response.json())
        return response.json()["result"]

    def test_opt_in_descriptor_has_native_file_params(self):
        client, token = self.make_client("true")
        tools = {t["name"]: t for t in self.rpc(client, token, "tools/list", {})["tools"]}
        probe = tools["probe_binary_file_exchange"]
        self.assertEqual(probe["_meta"]["openai/fileParams"], ["file"])
        schema = probe["inputSchema"]
        file_def = schema["$defs"]["ChatGPTFileRef"]
        self.assertEqual(set(file_def["required"]), {"download_url", "file_id"})
        self.assertEqual(set(file_def["properties"]),
                         {"download_url", "file_id", "mime_type", "file_name"})
        self.assertFalse(file_def["additionalProperties"])
        self.assertTrue(probe["annotations"]["readOnlyHint"])
        self.assertTrue(probe["annotations"]["openWorldHint"])

    def test_tool_result_contains_original_bytes_not_database(self):
        client, token = self.make_client("true")
        binary = b"ZIP\x00\xff\xfe\x80" + bytes(range(256))
        args = {"file": {"file_id": "file_synthetic-237",
                         "download_url": DOWNLOAD, "file_name": "sample.bin",
                         "mime_type": "application/octet-stream"},
                "reason": "TEST-237 test"}
        async def simulated_probe(_req):
            return binary_probe.binary_resource_result(binary)
        with patch.object(mcp_gateway, "probe_exchange", new=simulated_probe):
            result = self.rpc(client, token, "tools/call", {
                "name": "probe_binary_file_exchange", "arguments": args,
            })
        self.assertFalse(result.get("isError"), result)
        self.assertEqual(base64.b64decode(result["content"][1]["resource"]["blob"]), binary)
        self.assertEqual(result["content"][1]["resource"]["mimeType"],
                         "application/octet-stream")
        self.assertNotIn("download_url", result["content"][0]["text"])
        self.assertNotIn("file_synthetic-237", result["content"][0]["text"])

    def test_probe_not_advertised_when_disabled(self):
        client, token = self.make_client("false")
        tools = {t["name"] for t in self.rpc(client, token, "tools/list", {})["tools"]}
        self.assertNotIn("probe_binary_file_exchange", tools)
        result = self.rpc(client, token, "tools/call", {
            "name": "probe_binary_file_exchange",
            "arguments": {"file": {"file_id": "file_demo", "download_url": DOWNLOAD},
                          "reason": "do not execute"},
        })
        self.assertTrue(result.get("isError"))


if __name__ == "__main__":
    unittest.main()
