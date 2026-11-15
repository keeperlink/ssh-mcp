"""OAuth protocol and harmless MCP-tool tests; only synthetic test secrets."""
from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

import jwt
from fastapi.testclient import TestClient

os.environ["MCP_ISSUER"] = "http://localhost"
os.environ["MCP_LOGIN_KEY"] = "synthetic-test-login-" + "a" * 40
os.environ["MCP_TOKEN_SIGNING_SECRET"] = "synthetic-test-signing-" + "b" * 40
os.environ["MCP_CIMD_VALIDATE_REMOTE"] = "false"

from app import config, oauth
from app.config import MCP_ISSUER, MCP_RESOURCE, MCP_SCOPES
from app.main import app
from app.mcp_gateway import TOOLS, create_mcp_server, handle_tool


CLIENT_ID = "https://chatgpt.com/oauth/client.json"
REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def _request(client: TestClient, **overrides):
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT,
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
        "scope": " ".join(MCP_SCOPES),
        "resource": MCP_RESOURCE,
        "state": "test-state-123",
    }
    params.update(overrides)
    return client.get("/oauth/authorize", params=params, follow_redirects=False)


def _login(client: TestClient):
    response = _request(client)
    assert response.status_code == 200, response.text
    match = re.search(r'name="request_token" value="([^"]+)"', response.text)
    assert match, response.text
    return client.post(
        "/oauth/authorize",
        data={"request_token": match.group(1), "mcp_login_key": config.MCP_LOGIN_KEY},
        follow_redirects=False,
    )


class OAuthAndMCPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._directory = tempfile.TemporaryDirectory()
        cls._env = patch.dict(os.environ, {"MCP_OAUTH_DB": str(Path(cls._directory.name) / "jobs.sqlite")})
        cls._env.start()
        cls._client_context = TestClient(app)
        cls.client = cls._client_context.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls._client_context.__exit__(None, None, None)
        cls._env.stop()
        cls._directory.cleanup()

    def setUp(self):
        oauth._AUTH_CODES.clear()
        oauth._LOGIN_FAILURES.clear()

    def test_config_fails_closed(self):
        config.validate_mcp_config()
        for name, value in (
            ("MCP_LOGIN_KEY", "short"),
            ("MCP_TOKEN_SIGNING_SECRET", "short"),
            ("MCP_RESOURCE", "https://unrelated.example/mcp"),
            ("MCP_OPERATOR_SUBJECT", "legacy-operator"),
            ("MCP_ISSUER", "http://untrusted.example"),
            ("MCP_ACCESS_TOKEN_TTL", -1),
            ("MCP_AUTH_CODE_TTL", 999999),
            ("MCP_CIMD_CLIENT_ID", "http://untrusted.example/client.json"),
            ("MCP_ALLOWED_REDIRECT_URIS", set()),
            ("MCP_CONVERSATION_HEADER_NAME", "Authorization"),
            ("MCP_CONVERSATION_HEADER_NAME", "X-Forwarded-For"),
            ("MCP_CONVERSATION_HEADER_NAME", "X-Real-IP"),
            ("MCP_CONVERSATION_HEADER_NAME", "x-REAL-ip"),
            ("MCP_CONVERSATION_HEADER_NAME", "X-Client-IP"),
            ("MCP_CONVERSATION_HEADER_NAME", "X-Remote-IP"),
            ("MCP_CONVERSATION_HEADER_NAME", "X-Original-Forwarded-For"),
            ("MCP_CONVERSATION_HEADER_NAME", "X-ıd"),
            ("MCP_CONVERSATION_HEADER_NAME", "X-Key"),
            ("MCP_CONVERSATION_HEADER_NAME", "X-Bad Header"),
            ("MCP_CONVERSATION_HEADER_NAME", ""),
        ):
            with self.subTest(name=name):
                with patch.object(config, name, value):
                    with self.assertRaises(RuntimeError):
                        config.validate_mcp_config()

    def test_independent_credentials_required_in_all_configuration_modes(self):
        # Managed signed mounts already reject reuse; standalone mode must too.
        with patch.object(config, "MCP_TOKEN_SIGNING_SECRET", config.MCP_LOGIN_KEY):
            with self.assertRaisesRegex(RuntimeError, "must be distinct"):
                config.validate_mcp_config()
        for env_patch in (
            {"HISTORY_VIEWER_ENABLED": "true",
             "HISTORY_VIEWER_PASSWORD": config.MCP_TOKEN_SIGNING_SECRET},
            {"MCP_METRICS_ENABLED": "true",
             "MCP_METRICS_TOKEN": config.MCP_LOGIN_KEY},
            {"MCP_METRICS_ENABLED": "true",
             "MCP_METRICS_TOKEN": config.MCP_TOKEN_SIGNING_SECRET},
            {"HISTORY_VIEWER_ENABLED": "true",
             "HISTORY_VIEWER_PASSWORD": config.MCP_LOGIN_KEY},
            {"HISTORY_VIEWER_ENABLED": "true", "MCP_METRICS_ENABLED": "true",
             "HISTORY_VIEWER_PASSWORD": "synthetic-audit-shared-secret-" + "x" * 32,
             "MCP_METRICS_TOKEN": "synthetic-audit-shared-secret-" + "x" * 32},
        ):
            with self.subTest(env=tuple(env_patch)):
                with patch.dict(os.environ, env_patch):
                    with self.assertRaisesRegex(RuntimeError, "must be distinct"):
                        config.validate_mcp_config()

    def test_custom_conversation_header_config_is_valid(self):
        with patch.object(config, "MCP_CONVERSATION_HEADER_NAME", "X-SSH-MCP-Conversation"):
            config.validate_mcp_config()

    def test_pkce_rfc7636(self):
        self.assertEqual(oauth._pkce_s256(VERIFIER), CHALLENGE)

    def test_pkce_rejects_invalid_challenges_and_verifiers(self):
        for challenge in (
            "", "x", "a" * 42, "a" * 44, "a" * 43,  # Last example is not canonical S256.
            "!" * 43, CHALLENGE[:-1] + ".", CHALLENGE + "a",
        ):
            with self.subTest(challenge=challenge):
                denied = _request(self.client, code_challenge=challenge)
                self.assertEqual(denied.status_code, 302)
                self.assertEqual(
                    parse_qs(urlparse(denied.headers["location"]).query)["error"],
                    ["invalid_request"],
                )
        for verifier in ("x", "a" * 42, "a" * 129, "a" * 43 + "!", "ø" * 43):
            with self.subTest(verifier=verifier[:12]):
                with self.assertRaises(ValueError):
                    oauth._pkce_s256(verifier)
        self.assertTrue(oauth._valid_pkce_challenge(CHALLENGE))
        self.assertEqual(oauth._pkce_s256(VERIFIER), CHALLENGE)

    def test_post_rejects_legacy_request_token_with_invalid_challenge(self):
        # Even an authentic signed request token must meet current PKCE rules.
        token = oauth._make_authorization_request_token(
            client_id=CLIENT_ID, redirect_uri=REDIRECT, state=None,
            code_challenge="x", scopes=list(MCP_SCOPES), resource=MCP_RESOURCE,
        )
        response = self.client.post("/oauth/authorize", data={
            "request_token": token, "mcp_login_key": config.MCP_LOGIN_KEY,
        }, follow_redirects=False)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(oauth._AUTH_CODES, {})

    def test_malformed_token_verifier_does_not_consume_code(self):
        code = parse_qs(urlparse(_login(self.client).headers["location"]).query)["code"][0]
        payload = {
            "grant_type": "authorization_code", "code": code,
            "client_id": CLIENT_ID, "redirect_uri": REDIRECT,
            "resource": MCP_RESOURCE, "code_verifier": VERIFIER,
        }
        for bad in ("x", "a" * 42, "a" * 129, "a" * 43 + "!", "ø" * 43):
            with self.subTest(verifier=bad[:12]):
                result = self.client.post("/oauth/token", data={
                    **payload, "code_verifier": bad,
                })
                self.assertEqual(result.status_code, 400)
                self.assertEqual(result.json()["error"], "invalid_grant")
        self.assertEqual(self.client.post("/oauth/token", data=payload).status_code, 200)

    def test_ping_unique_and_argument_rejection(self):
        first = json.loads(handle_tool("ping", {}).content[0].text)
        second = json.loads(handle_tool("ping", {}).content[0].text)
        self.assertTrue(first["ok"])
        self.assertNotEqual(first["request_id"], second["request_id"])
        self.assertIsInstance(first["timestamp"], int)
        self.assertTrue(handle_tool("ping", {"bad": 1}).is_error)

    def test_retired_poc_write_is_not_available(self):
        self.assertTrue(handle_tool("test_write", {"marker": "trial"}).is_error)
        self.assertTrue(handle_tool("execute_command", {"command": "id"}).is_error)

    def test_tool_metadata_and_sdk_routes(self):
        self.assertEqual([t.name for t in TOOLS], ["ping"])
        self.assertTrue(TOOLS[0].annotations.read_only_hint)
        for tool in TOOLS:
            self.assertEqual(tool.meta["securitySchemes"][0]["scopes"], MCP_SCOPES)
        _server, mcp_app = create_mcp_server()
        routes = {getattr(route, "path", "") for route in mcp_app.routes}
        self.assertIn("/mcp", routes)
        self.assertIn("/.well-known/oauth-protected-resource/mcp", routes)

    def test_issuer_protected_resource_and_health(self):
        client = self.client
        self.assertEqual(client.get("/health").json(), {"status": "ok"})
        protected = client.get("/.well-known/oauth-protected-resource")
        self.assertEqual(protected.status_code, 200)
        self.assertEqual(protected.json()["resource"], MCP_RESOURCE)
        self.assertEqual(protected.json()["authorization_servers"], [MCP_ISSUER])
        auth = client.get("/.well-known/oauth-authorization-server").json()
        self.assertEqual(auth["issuer"], MCP_ISSUER)
        self.assertIn("S256", auth["code_challenge_methods_supported"])
        self.assertIn("refresh_token", auth["grant_types_supported"])
        self.assertTrue(auth["client_id_metadata_document_supported"])

    def test_mcp_requires_bearer(self):
        client = self.client
        r = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            headers={"accept": "application/json, text/event-stream"},
        )
        self.assertIn(r.status_code, (401, 403))
        self.assertIn("www-authenticate", r.headers)

    def test_oauth_authorize_validates_redirect_client_pkce_scopes_resource(self):
        client = self.client
        self.assertEqual(_request(client, client_id="https://unknown.example").status_code, 400)
        self.assertEqual(_request(client, redirect_uri="https://evil.example/callback").status_code, 400)
        for params, error in [
            ({"response_type": "token"}, "unsupported_response_type"),
            ({"code_challenge_method": "plain"}, "invalid_request"),
            ({"resource": "https://evil.example/mcp"}, "invalid_target"),
            ({"scope": "poc.read"}, "invalid_scope"),
            ({"scope": "wrong.scope"}, "invalid_scope"),
        ]:
            r = _request(client, **params)
            self.assertEqual(r.status_code, 302)
            self.assertEqual(parse_qs(urlparse(r.headers["location"]).query)["error"], [error])
        correct = _request(client)
        self.assertEqual(correct.status_code, 200)
        self.assertIn("mcp_login_key", correct.text)
        self.assertNotIn(config.MCP_LOGIN_KEY, correct.text)

    def test_oauth_invalid_login_denied_without_leaking_key(self):
        client = self.client
        page = _request(client)
        request_token = re.search(r'name="request_token" value="([^"]+)"', page.text).group(1)
        r = client.post(
            "/oauth/authorize",
            data={"request_token": request_token, "mcp_login_key": "incorrect"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 302)
        self.assertEqual(parse_qs(urlparse(r.headers["location"]).query)["error"], ["access_denied"])
        self.assertNotIn(config.MCP_LOGIN_KEY, r.headers["location"])
        bad = client.post("/oauth/authorize", data={"request_token": "garbage", "mcp_login_key": "x"})
        self.assertEqual(bad.status_code, 400)

    def test_oauth_login_token_pkce_wrong_then_correct_replay_denied(self):
        client = self.client
        auth = _login(client)
        self.assertEqual(auth.status_code, 302)
        callback = parse_qs(urlparse(auth.headers["location"]).query)
        self.assertEqual(callback["state"], ["test-state-123"])
        self.assertEqual(callback["iss"], [MCP_ISSUER])
        code = callback["code"][0]
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT,
            "code_verifier": "not-the-verifier",
            "resource": MCP_RESOURCE,
        }
        wrong = client.post("/oauth/token", data=payload)
        self.assertEqual(wrong.status_code, 400)
        self.assertEqual(wrong.json()["error"], "invalid_grant")
        payload["code_verifier"] = VERIFIER
        good = client.post("/oauth/token", data=payload)
        self.assertEqual(good.status_code, 200)
        self.assertEqual(good.json()["token_type"], "Bearer")
        self.assertEqual(
            set(good.json()["scope"].split()), set(MCP_SCOPES)
        )
        self.assertEqual(client.post("/oauth/token", data=payload).json()["error"], "invalid_grant")

    def test_oauth_invalid_grants_rejected(self):
        client = self.client
        self.assertEqual(client.post("/oauth/token", data={"grant_type": "refresh_token"}).json()["error"], "invalid_request")
        self.assertEqual(client.post("/oauth/token", data={"grant_type": "authorization_code"}).json()["error"], "invalid_request")
        common = {
            "grant_type": "authorization_code",
            "code": "nonexistent",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT,
            "code_verifier": VERIFIER,
            "resource": MCP_RESOURCE,
        }
        self.assertEqual(client.post("/oauth/token", data=common).json()["error"], "invalid_grant")
        self.assertEqual(client.post("/oauth/token", data={**common, "client_id": "wrong"}).status_code, 401)
        self.assertEqual(client.post("/oauth/token", json=common).json()["error"], "invalid_request")

    def test_authorization_code_bindings_and_expiry(self):
        client = self.client
        def token_request(code, **overrides):
            return client.post("/oauth/token", data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT,
                "code_verifier": VERIFIER,
                "resource": MCP_RESOURCE,
                **overrides,
            })
        code = parse_qs(urlparse(_login(client).headers["location"]).query)["code"][0]
        self.assertEqual(token_request(code, resource="https://wrong.example/mcp").json()["error"], "invalid_grant")
        self.assertEqual(token_request(code, redirect_uri="https://evil.example/callback").status_code, 401)
        self.assertEqual(token_request(code).status_code, 200)
        expired_code = parse_qs(urlparse(_login(client).headers["location"]).query)["code"][0]
        oauth._AUTH_CODES[expired_code].expires_at = 1
        self.assertEqual(token_request(expired_code).json()["error"], "invalid_grant")

    def test_bearer_rejects_wrong_issuer_audience_expired_missing_scope(self):
        token, _ = oauth.issue_access_token(CLIENT_ID, list(MCP_SCOPES))
        self.assertIsNotNone(asyncio.run(oauth.OAuthTokenVerifier().verify_token(token)))
        claims = jwt.decode(token, config.MCP_TOKEN_SIGNING_SECRET, algorithms=["HS256"], options={"verify_aud": False})
        for change in (
            {"iss": "https://not-issuer.example"},
            {"aud": "https://different.example/mcp"},
            {"exp": 1},
            {"scope": "poc.read"},
        ):
            changed = jwt.encode({**claims, **change}, config.MCP_TOKEN_SIGNING_SECRET, algorithm="HS256")
            self.assertIsNone(asyncio.run(oauth.OAuthTokenVerifier().verify_token(changed)))
        self.assertIsNone(asyncio.run(oauth.OAuthTokenVerifier().verify_token("bad.token.value")))

    def test_invalid_token_request_content_type_and_limits(self):
        client = self.client
        self.assertEqual(client.post("/oauth/token", content=b"x", headers={"content-type": "text/plain"}).status_code, 400)
        self.assertEqual(
            client.post("/oauth/token", content=b"a" * 16385, headers={"content-type": "application/x-www-form-urlencoded"}).status_code,
            400,
        )

    def test_authenticated_mcp_initialize_list_and_call(self):
        # Exercises real SDK/ASGI bearer middleware and callbacks using the
        # shared session manager; no mock direct invocation or host access.
        client = self.client
        token, _ = oauth.issue_access_token(CLIENT_ID, list(MCP_SCOPES))
        headers = {
            "Authorization": "Bearer " + token,
            "Accept": "application/json, text/event-stream",
            "Host": "localhost",
        }

        def rpc(method, req_id, params):
            response = client.post(
                "/mcp",
                headers=headers,
                json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": params},
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertNotIn("error", response.json())
            return response.json()["result"]

        initialized = rpc("initialize", 101, {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "sky206-ci-test", "version": "1"},
        })
        self.assertEqual(initialized["serverInfo"]["name"], "SSH-MCP")
        response = client.post(
            "/mcp", headers=headers,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        self.assertEqual(response.status_code, 202)
        tools = rpc("tools/list", 102, {})
        self.assertEqual({item["name"] for item in tools["tools"]}, {"ping"})
        pong = rpc("tools/call", 103, {"name": "ping", "arguments": {}})
        self.assertTrue(json.loads(pong["content"][0]["text"])["ok"])
        rejected = rpc("tools/call", 104, {"name": "test_write", "arguments": {"marker": "ci"}})
        self.assertTrue(rejected.get("isError"), rejected)
        for denied in ("execute_command", "get_job", "cancel_job"):
            result = rpc("tools/call", 105, {"name": denied, "arguments": {}})
            self.assertTrue(result.get("isError"), result)

    def test_no_state_oauth_callback_expiry_and_login_lockout(self):
        client = self.client
        page = _request(client, state=None)
        self.assertEqual(page.status_code, 200)
        request_token = re.search(r'name="request_token" value="([^"]+)"', page.text).group(1)
        done = client.post("/oauth/authorize", data={
            "request_token": request_token,
            "mcp_login_key": config.MCP_LOGIN_KEY,
        }, follow_redirects=False)
        self.assertEqual(done.status_code, 302)
        self.assertNotIn("state", parse_qs(urlparse(done.headers["location"]).query))
        for _ in range(config.MCP_LOGIN_MAX_FAILURES):
            client.post("/oauth/authorize", data={
                "request_token": request_token, "mcp_login_key": "wrong",
            }, follow_redirects=False)
        blocked = client.post("/oauth/authorize", data={
            "request_token": request_token, "mcp_login_key": config.MCP_LOGIN_KEY,
        }, follow_redirects=False)
        self.assertEqual(blocked.status_code, 429)
        self.assertIn("retry-after", blocked.headers)

    def test_token_exchange_rejects_non_ascii_pkce(self):
        client = self.client
        code = parse_qs(urlparse(_login(client).headers["location"]).query)["code"][0]
        request = {
            "grant_type": "authorization_code", "code": code,
            "client_id": CLIENT_ID, "redirect_uri": REDIRECT,
            "code_verifier": "\u2603", "resource": MCP_RESOURCE,
        }
        response = client.post("/oauth/token", data=request)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "invalid_grant")
        request["code_verifier"] = VERIFIER
        self.assertEqual(client.post("/oauth/token", data=request).status_code, 200)

    def test_invalid_utf8_form_and_expired_codes_are_cleaned(self):
        client = self.client
        bad = client.post(
            "/oauth/token",
            content=b"grant_type=authorization_code&code=\\xff".replace(b"\\xff", bytes([255])),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(bad.json()["error"], "invalid_request")
        # Adding a new code prunes expired entries.
        expired = oauth.StoredAuthorizationCode(
            client_id=CLIENT_ID, redirect_uri=REDIRECT,
            code_challenge=CHALLENGE, scopes=list(MCP_SCOPES),
            resource=MCP_RESOURCE, expires_at=1, session_expires_at=1,
        )
        oauth._AUTH_CODES["expired-fixture"] = expired
        self.assertEqual(_login(client).status_code, 302)
        self.assertNotIn("expired-fixture", oauth._AUTH_CODES)

    def test_local_tool_call_requires_actual_oauth_token(self):
        # SDK transport may reject an MCP call before initialize; this test
        # deliberately verifies HTTP bearer enforcement without simulating ChatGPT.
        client = self.client
        payload = {"jsonrpc": "2.0", "id": 17, "method": "tools/call", "params": {"name": "ping", "arguments": {}}}
        unauthorized = client.post("/mcp", json=payload, headers={"accept": "application/json, text/event-stream"})
        self.assertIn(unauthorized.status_code, (401, 403))
