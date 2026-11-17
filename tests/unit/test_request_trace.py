"""DEBUG tracing preserves traffic and redacts credentials and tool payloads."""
from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import patch

from app import request_trace as trace


class TraceTests(unittest.TestCase):
    def capture(self, body: bytes, *, path="/mcp", headers=(), method="POST", consume=True, enabled=True):
        events = [{"type": "http.request", "body": body[:7], "more_body": True},
                  {"type": "http.request", "body": body[7:], "more_body": False}]
        received = []
        sent = []

        async def receive():
            return events.pop(0)

        async def send(event):
            sent.append(event)

        async def app(scope, receive, send):
            if consume:
                while True:
                    event = await receive()
                    received.append(event["body"])
                    if not event.get("more_body", False):
                        break
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"secret-response"})

        with patch.object(trace.LOG, "debug") as log, patch.object(trace.LOG, "isEnabledFor", return_value=enabled):
            asyncio.run(trace.RequestTrace(app)(
                {"type": "http", "path": path, "method": method,
                 "headers": list(headers), "query_string": b"token=hidden-query"}, receive, send))
        self.assertEqual(b"".join(received), body if consume else b"")
        self.assertEqual(sent[-1]["body"], b"secret-response")
        if not log.called:
            return None
        log.assert_called_once()
        return json.loads(log.call_args.args[1])

    def test_trace_preserves_duplicate_headers_and_metadata_values(self):
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "execute_command", "arguments": {"argv": ["secret-argument"]},
            "_meta": {"x-codex-turn-metadata": {"thread_id": "thread-123", "turn_id": "turn-456"},
                      "custom": "custom-metadata", "api_key": "hidden-key",
                      "openai/session": "v1/demo-session", "openai/userLocation": {"city": "Demo"},
                      "timezone_offset_minutes": -300,
                      "capabilities": {"nested": {"enabled": True, "mimeTypes": ["text/html"]}},
                      "nested": [{"token": "hidden-token", "count": 3.5, "value": None}],
                      "oauth": {"code_verifier": "hidden-verifier", "code": "hidden-code"}}}}
        data = self.capture(json.dumps(payload).encode(), headers=[
            (b"authorization", b"Bearer hidden-token"), (b"cookie", b"hidden-cookie"),
            (b"x-unknown", b"custom-value"), (b"x-unknown", b"other-value"),
            (b"x-ssh-mcp-conversation", b"conversation-123"),
            (b"mcp-session-id", b"hidden-session"), (b"user-agent", b"demo-client"),
            (b"x-api-key", b"hidden-api-key"), (b"x-access-token", b"hidden-access-token")])
        self.assertEqual(data["headers"][0]["value"], "[REDACTED]")
        self.assertEqual(data["headers"][1]["value"], "[REDACTED]")
        self.assertEqual(data["headers"][2], {"name": "x-unknown", "value": "custom-value"})
        self.assertEqual(data["headers"][3], {"name": "x-unknown", "value": "other-value"})
        self.assertEqual(data["headers"][4]["value"], "conversation-123")
        self.assertEqual(data["headers"][5]["value"], "[REDACTED]")
        self.assertEqual(data["headers"][6]["value"], "demo-client")
        self.assertEqual(data["headers"][7]["value"], "[REDACTED]")
        self.assertEqual(data["headers"][8]["value"], "[REDACTED]")
        item = data["body"]["envelope"][0]
        self.assertEqual(item["argument_keys"], ["argv"])
        self.assertEqual(item["method"], "tools/call")
        self.assertEqual(item["request_id"], 1)
        self.assertEqual(item["tool"], "execute_command")
        meta = item["params_meta"]
        self.assertEqual(meta, {
            **payload["params"]["_meta"],
            "api_key": "[REDACTED]",
            "nested": [{"token": "[REDACTED]", "count": 3.5, "value": None}],
            "oauth": {"code_verifier": "[REDACTED]", "code": "[REDACTED]"},
        })
        serialized = json.dumps(data)
        self.assertNotIn("fingerprint:", serialized)
        self.assertNotIn("hidden-", serialized)
        self.assertNotIn("secret-argument", serialized)
        self.assertNotIn("secret-response", serialized)

    def test_metadata_and_header_values_remain_bounded(self):
        self.assertEqual(trace._metadata("x" * (trace.MAX_VALUE + 1)), "x" * trace.MAX_VALUE)
        self.assertEqual(trace._metadata(list(range(12))), list(range(10)))
        self.assertEqual(len(trace._metadata({str(k): k for k in range(45)})), 40)
        self.assertEqual(trace._metadata("secret", trace.MAX_METADATA_DEPTH), "[MAX_DEPTH]")
        self.assertEqual(self.capture(b"", method="GET", headers=[
            (b"x-test", b"x" * (trace.MAX_VALUE + 1))])["headers"][0]["value"], "x" * trace.MAX_VALUE)

    def test_oauth_console_requests_not_logged(self):
        for path in ("/oauth/token", "/console", "/health"):
            self.assertIsNone(self.capture(b"secret=hidden-value", path=path))

    def test_bounds_invalid_json_and_unconsumed_request(self):
        self.assertEqual(self.capture(b"not-json")["body"]["parse"], "invalid_json")
        self.assertEqual(self.capture(b"x" * (trace.MAX_BODY_CAPTURE + 1))["body"]["parse"], "truncated")
        self.assertFalse(self.capture(b"secret", consume=False)["body"]["complete"])
        self.assertEqual(len(self.capture(b"", method="GET", headers=[
            (b"x-test", b"v")] * 300)["headers"]), trace.MAX_HEADERS)


    def test_disabled_debug_never_parses_body_or_logs(self):
        with patch.object(trace, "_envelope") as parse, patch.object(trace, "_headers") as hdr:
            self.assertIsNone(self.capture(b"secret", enabled=False))
            parse.assert_not_called()
            hdr.assert_not_called()

    def test_empty_batch_and_nonidentifiers(self):
        data = self.capture(b'[null,3,{"method":"bad method","id":null,"params":{"_meta":{"items":[1,{"a":{"b":{"c":{"d":5}}}}]}}}]')
        result = data["body"]["envelope"][0]
        self.assertEqual(result["method"], "bad method")
        self.assertIsNone(result["request_id"])
        self.assertEqual(result["argument_keys"], [])

    def test_diagnostic_error_never_breaks_forwarding(self):
        with patch.object(trace, "_headers", side_effect=RuntimeError):
            # Diagnostic fallback has a different log format; assert pass through
            # by exercising a downstream app without consuming the request body.
            async def downstream(scope, receive, send):
                await send({"type": "http.response.start", "status": 200, "headers": []})
            sent = []
            async def send(event):
                sent.append(event)
            async def receive():
                return {"type": "http.request", "body": b""}
            with patch.object(trace.LOG, "isEnabledFor", return_value=True), patch.object(trace.LOG, "debug") as log:
                asyncio.run(trace.RequestTrace(downstream)({"type":"http", "path":"/mcp", "method":"POST"}, receive, send))
            self.assertEqual(sent[0]["status"], 200)
            log.assert_called_once_with("SSH_MCP_REQUEST diagnostic_failed")
