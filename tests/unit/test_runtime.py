"""Security edge cases and low-level entrypoint contracts; synthetic fixtures only."""
from __future__ import annotations

import asyncio
import json
import os
import runpy
import time
import unittest
from collections import deque
from unittest.mock import patch, AsyncMock

import jwt

os.environ.setdefault("MCP_ISSUER", "http://localhost")
os.environ.setdefault("MCP_LOGIN_KEY", "synthetic-test-login-" + "a" * 40)
os.environ.setdefault("MCP_TOKEN_SIGNING_SECRET", "synthetic-test-signing-" + "b" * 40)
os.environ.setdefault("MCP_CIMD_VALIDATE_REMOTE", "false")

from app import __main__ as cli, config, contracts, oauth


CLIENT = "https://chatgpt.com/oauth/client.json"
CALLBACK = "https://chatgpt.com/connector_platform_oauth_redirect"


def doc():
    return {
        "client_id": CLIENT,
        "client_name": "Synthetic ChatGPT",
        "redirect_uris": [CALLBACK],
        "response_types": ["code"],
        "grant_types": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["none"],
    }


class RuntimeUnitTests(unittest.TestCase):
    def setUp(self):
        oauth._CIMD_REGISTRY._cache.clear()
        oauth._LOGIN_FAILURES.clear()
        oauth._AUTH_CODES.clear()

    def tearDown(self):
        oauth._CIMD_REGISTRY._cache.clear()

    def test_environment_defaults_to_lab_and_rejects_unknown_value(self):
        self.assertEqual(config.MCP_ENVIRONMENT, "lab")
        with patch.object(config, "MCP_ENVIRONMENT", "production"):
            config.validate_mcp_config()
        with patch.object(config, "MCP_ENVIRONMENT", "development"):
            with self.assertRaisesRegex(RuntimeError, "MCP_ENVIRONMENT"):
                config.validate_mcp_config()

    def test_config_timeout_safety_ceiling_is_ten_hours(self):
        with patch.object(config, "SSH_DEFAULT_TIMEOUT_SECONDS", 60):
            with patch.object(config, "SSH_MAX_TIMEOUT_SECONDS", 36000):
                config.validate_mcp_config()
            with patch.object(config, "SSH_MAX_TIMEOUT_SECONDS", 36001):
                with self.assertRaisesRegex(RuntimeError, "Invalid operational limits"):
                    config.validate_mcp_config()

    def test_local_entrypoint_is_loopback_only_by_default(self):
        with patch.dict(os.environ, {"MCP_BIND_HOST": "", "MCP_BIND_PORT": ""}):
            os.environ.pop("MCP_BIND_HOST", None)
            os.environ.pop("MCP_BIND_PORT", None)
            with patch.object(cli.uvicorn, "run") as mocked:
                cli.main()
            mocked.assert_called_once_with(
                "app.main:app", host="127.0.0.1", port=8000, access_log=False,
            )
        with patch.dict(os.environ, {"MCP_BIND_HOST": "127.0.0.1", "MCP_BIND_PORT": "8055"}):
            with patch.object(cli.uvicorn, "run") as mocked:
                cli.main()
            self.assertEqual(mocked.call_args.kwargs["port"], 8055)
        for bad_port in ("0", "-1", "65536", "invalid"):
            with self.subTest(port=bad_port):
                with patch.dict(os.environ, {"MCP_BIND_PORT": bad_port}):
                    with patch.object(cli.uvicorn, "run") as mocked:
                        with self.assertRaises(ValueError):
                            cli.main()
                        mocked.assert_not_called()

    def test_entrypoint_module_and_contract_export(self):
        with patch.object(cli.uvicorn, "run") as mocked:
            with patch.dict(os.environ, {"MCP_BIND_HOST": "127.0.0.1", "MCP_BIND_PORT": "8000"}):
                runpy.run_module("app.__main__", run_name="__main__")
            mocked.assert_called_once()
        with patch("builtins.print") as printed:
            contracts.main()
            printed.assert_called_once()
            payload = json.loads(printed.call_args.args[0])
            self.assertEqual(payload["contract_version"], contracts.CONTRACT_VERSION)

    def test_scope_defaults_dedupe_and_redirect_query_separator(self):
        self.assertEqual(oauth._normalize_scopes(None), list(config.MCP_SCOPES))
        self.assertEqual(
            oauth._normalize_scopes("mcp.access mcp.access"),
            ["mcp.access"],
        )
        redirect = oauth._redirect_with_params("https://chatgpt.com/cb?a=1", {"b": "2"})
        self.assertIn("?a=1&b=2", redirect.headers["location"])
        error = oauth._authorization_error_redirect(CALLBACK, None, "invalid_request", "bad")
        self.assertNotIn("state=", error.headers["location"])

    def test_auth_request_token_must_have_expected_purpose(self):
        raw = oauth._make_authorization_request_token(
            client_id=CLIENT, redirect_uri=CALLBACK, state=None,
            code_challenge="a" * 43, scopes=list(config.MCP_SCOPES),
            resource=config.MCP_RESOURCE,
        )
        payload = oauth._decode_authorization_request_token(raw)
        self.assertIsNone(payload["state"])
        payload["purpose"] = "unexpected"
        invalid = jwt.encode(
            payload, config.MCP_TOKEN_SIGNING_SECRET, algorithm="HS256"
        )
        with self.assertRaises(ValueError):
            oauth._decode_authorization_request_token(invalid)

    def test_login_failures_are_limited_and_expired_failures_expire(self):
        ip = "synthetic-client"
        allowed, retry = asyncio.run(oauth._login_allowed(ip))
        self.assertTrue(allowed)
        self.assertEqual(retry, 0)
        for _ in range(config.MCP_LOGIN_MAX_FAILURES):
            asyncio.run(oauth._record_login_failure(ip))
        allowed, retry = asyncio.run(oauth._login_allowed(ip))
        self.assertFalse(allowed)
        self.assertGreaterEqual(retry, 1)
        oauth._LOGIN_FAILURES[ip] = deque([time.monotonic() - config.MCP_LOGIN_WINDOW_SECONDS - 10])
        allowed, _ = asyncio.run(oauth._login_allowed(ip))
        self.assertTrue(allowed)
        oauth._LOGIN_FAILURES[ip] = deque([time.monotonic() - config.MCP_LOGIN_WINDOW_SECONDS - 10])
        asyncio.run(oauth._record_login_failure(ip))
        self.assertEqual(len(oauth._LOGIN_FAILURES[ip]), 1)
        asyncio.run(oauth._clear_login_failures(ip))
        self.assertNotIn(ip, oauth._LOGIN_FAILURES)

    def test_cimd_cache_and_all_malformed_metadata_paths(self):
        with patch.object(oauth, "MCP_CIMD_VALIDATE_REMOTE", True):
            oauth._CIMD_REGISTRY._cache[CLIENT] = (time.monotonic() + 100, doc())
            asyncio.run(oauth._validate_cimd(CLIENT, CALLBACK))
            invalid_documents = [
                {**doc(), "client_id": "https://wrong.example"},
                {**doc(), "redirect_uris": "not-a-list"},
                {**doc(), "redirect_uris": ["https://wrong.example/cb"]},
                {**doc(), "response_types": []},
                {**doc(), "grant_types": []},
                {**doc(), "token_endpoint_auth_methods_supported": []},
            ]
            for value in invalid_documents:
                with self.subTest(metadata=value):
                    oauth._CIMD_REGISTRY._cache[CLIENT] = (time.monotonic() + 100, value)
                    with self.assertRaises(ValueError):
                        asyncio.run(oauth._validate_cimd(CLIENT, CALLBACK))

    def test_cimd_remote_network_success_cache_and_denial(self):
        with patch.object(oauth, "MCP_CIMD_VALIDATE_REMOTE", True):
            with patch("app.client_metadata._fetch_metadata", new_callable=AsyncMock,
                       return_value=doc()) as fetch:
                asyncio.run(oauth._validate_cimd(CLIENT, CALLBACK))
                asyncio.run(oauth._validate_cimd(CLIENT, CALLBACK))
                self.assertEqual(fetch.await_count, 1)
            for invalid in (ValueError("unavailable"), ["not", "an", "object"],
                            {**doc(), "client_id": "https://wrong.example"}):
                oauth._CIMD_REGISTRY._cache.clear()
                with self.subTest(invalid=repr(invalid)):
                    if isinstance(invalid, ValueError):
                        with patch("app.client_metadata._fetch_metadata", new_callable=AsyncMock,
                                   side_effect=invalid):
                            with self.assertRaises(ValueError):
                                asyncio.run(oauth._validate_cimd(CLIENT, CALLBACK))
                    else:
                        with patch("app.client_metadata._fetch_metadata", new_callable=AsyncMock,
                                   return_value=invalid):
                            with self.assertRaises((ValueError, TypeError, AttributeError)):
                                asyncio.run(oauth._validate_cimd(CLIENT, CALLBACK))

    def test_invalid_cimd_client_id_and_redirect_cannot_be_overridden(self):
        with patch.object(oauth, "MCP_CIMD_VALIDATE_REMOTE", True):
            with self.assertRaises(ValueError):
                asyncio.run(oauth._validate_cimd("https://evil.example", CALLBACK))
            oauth._CIMD_REGISTRY._cache[CLIENT] = (time.monotonic() + 100, doc())
            with self.assertRaisesRegex(ValueError, "redirect_uri"):
                asyncio.run(oauth._validate_cimd(CLIENT, "https://evil.example/cb"))


if __name__ == "__main__":
    unittest.main()
