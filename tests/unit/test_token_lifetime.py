"""TEST-214: selected authorization session life, fixed 15-minute bearer TTL."""
from __future__ import annotations

import asyncio
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import jwt
from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ.setdefault("MCP_ISSUER", "http://localhost")
os.environ.setdefault("MCP_LOGIN_KEY", "synthetic-test-login-" + "a" * 40)
os.environ.setdefault("MCP_TOKEN_SIGNING_SECRET", "synthetic-test-signing-" + "b" * 40)
os.environ.setdefault("MCP_CIMD_VALIDATE_REMOTE", "false")

from app import config, oauth

app = FastAPI()
app.include_router(oauth.router)
CLIENT = "https://chatgpt.com/oauth/client.json"
REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
DURATIONS = (3600, 28800, 86400, 604800, 2592000)


class SessionLifetimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.context = TestClient(app)
        cls.client = cls.context.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.context.__exit__(None, None, None)

    def setUp(self):
        oauth._AUTH_CODES.clear()
        oauth._LOGIN_FAILURES.clear()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        env = patch.dict(os.environ, {"MCP_OAUTH_DB": str(Path(directory.name) / "jobs.sqlite")})
        env.start()
        self.addCleanup(env.stop)

    def form(self, *, ssh=False):
        scope = "mcp.access ssh.execute" if ssh else "mcp.access"
        response = self.client.get("/oauth/authorize", params={
            "client_id": CLIENT, "redirect_uri": REDIRECT,
            "response_type": "code", "code_challenge": CHALLENGE,
            "code_challenge_method": "S256", "resource": config.MCP_RESOURCE,
            "scope": scope, "state": "synthetic-state",
        }, follow_redirects=False)
        self.assertEqual(response.status_code, 200, response.text)
        match = re.search(r'name="request_token" value="([^"]+)"', response.text)
        self.assertIsNotNone(match)
        return match.group(1), response.text

    def login(self, request_token, lifetime=None, key=None):
        data = {"request_token": request_token,
                "mcp_login_key": key or config.MCP_LOGIN_KEY}
        if lifetime is not None:
            data["session_ttl_seconds"] = lifetime
        return self.client.post("/oauth/authorize", data=data, follow_redirects=False)

    def code_from_redirect(self, response):
        self.assertEqual(response.status_code, 302, response.text)
        return parse_qs(urlparse(response.headers["location"]).query)["code"][0]

    def exchange(self, code, **extra):
        return self.client.post("/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "client_id": CLIENT, "redirect_uri": REDIRECT,
            "code_verifier": VERIFIER, "resource": config.MCP_RESOURCE,
            **extra,
        })

    def test_five_session_choices_default_and_access_cap(self):
        self.assertEqual(config.MCP_SESSION_LIFETIMES, DURATIONS)
        self.assertEqual(config.MCP_SESSION_TTL_DEFAULT, 86400)
        self.assertEqual(config.MCP_ACCESS_TOKEN_TTL, 900)
        req, page = self.form()
        self.assertIn('<select id="session_ttl_seconds" name="session_ttl_seconds">', page)
        self.assertIn('<option value="86400" selected>24 hours</option>', page)
        self.assertIn("Access tokens expire after at most 15 minutes", page)
        self.assertNotIn(config.MCP_LOGIN_KEY, page)
        for duration in (*DURATIONS, None):
            with self.subTest(duration=duration):
                req, page = self.form()
                self.assertIn('<option value="2592000"', page)
                code = self.code_from_redirect(self.login(req, None if duration is None else str(duration)))
                selected = 86400 if duration is None else duration
                session_end = oauth._AUTH_CODES[code].session_expires_at
                self.assertAlmostEqual(session_end, oauth._now() + selected, delta=2)
                result = self.exchange(code, session_ttl_seconds="2592000")
                self.assertEqual(result.status_code, 200, result.text)
                body = result.json()
                self.assertEqual(body["token_type"], "Bearer")
                self.assertTrue(body["refresh_token"])
                self.assertGreaterEqual(body["expires_in"], 898)
                self.assertLessEqual(body["expires_in"], 900)
                claims = jwt.decode(body["access_token"], config.MCP_TOKEN_SIGNING_SECRET,
                                    algorithms=["HS256"], audience=config.MCP_RESOURCE,
                                    issuer=config.MCP_ISSUER)
                self.assertEqual(claims["ver"], 2)
                self.assertEqual(claims["exp"] - claims["iat"], 900)
                self.assertLessEqual(claims["exp"], session_end)
                self.assertTrue(claims["sid"])
                self.assertIsNotNone(asyncio.run(oauth.OAuthTokenVerifier().verify_token(
                    body["access_token"])))
                self.assertEqual(self.exchange(code).json()["error"], "invalid_grant")

    def test_invalid_session_choice_is_not_an_access_token_setting(self):
        bad = ("", "-1", "0", "900", "86400.0", "086400", "2592001",
               " 86400 ", "<script>alert(1)</script>", "1h", "999999999999999999")
        for value in bad:
            with self.subTest(value=value):
                request, _ = self.form()
                before = set(oauth._AUTH_CODES)
                result = self.login(request, value)
                self.assertEqual(result.status_code, 400)
                self.assertEqual(set(oauth._AUTH_CODES), before)
        for value in (-1, 0, 3601, 2592001, "86400", True):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    oauth._validated_session_ttl(value)
        for bad_ttl in (-1, 0, 3600, 2592000, "900", True):
            with self.assertRaises(ValueError):
                oauth.issue_access_token(CLIENT, list(config.MCP_SCOPES), bad_ttl)

    def test_code_binds_session_selection_and_pkce(self):
        req, _ = self.form()
        code = self.code_from_redirect(self.login(req, "3600"))
        session_end = oauth._AUTH_CODES[code].session_expires_at
        self.assertEqual(self.exchange(code, code_verifier="invalid").json()["error"],
                         "invalid_grant")
        good = self.exchange(code, session_ttl_seconds="2592000")
        self.assertEqual(good.status_code, 200)
        session = oauth.session_store().list_sessions()[0]
        self.assertEqual(session["expires_at"], session_end)
        self.assertLessEqual(good.json()["expires_in"], 900)

    def test_ssh_scope_uses_same_authorization_and_short_access(self):
        with patch.object(config, "MCP_SSH_TOOLS_ENABLED", True):
            req, _ = self.form(ssh=True)
            code = self.code_from_redirect(self.login(req, "604800"))
            result = self.exchange(code)
            self.assertEqual(result.status_code, 200, result.text)
            self.assertIn("ssh.execute", result.json()["scope"].split())
            self.assertLessEqual(result.json()["expires_in"], 900)

    def test_configuration_rejects_variable_bearer_ttl(self):
        for duration in DURATIONS:
            with patch.object(config, "MCP_SESSION_TTL_DEFAULT", duration):
                config.validate_mcp_config()
        for duration in (-1, 0, 900, 3601, 2592001):
            with patch.object(config, "MCP_SESSION_TTL_DEFAULT", duration):
                with self.assertRaisesRegex(RuntimeError, "OAuth token lifetime"):
                    config.validate_mcp_config()
        with patch.object(config, "MCP_ACCESS_TOKEN_TTL", 3600):
            with self.assertRaises(RuntimeError):
                config.validate_mcp_config()

    def test_old_long_lived_signed_tokens_rejected_on_upgrade(self):
        now = oauth._now()
        old_claims = {"iss": config.MCP_ISSUER, "sub": config.MCP_OPERATOR_SUBJECT,
                      "aud": config.MCP_RESOURCE, "iat": now, "exp": now + 86400,
                      "client_id": CLIENT, "scope": "mcp.access"}
        token = jwt.encode(old_claims, config.MCP_TOKEN_SIGNING_SECRET, algorithm="HS256")
        self.assertIsNone(asyncio.run(oauth.OAuthTokenVerifier().verify_token(token)))


if __name__ == "__main__":
    unittest.main()
