"""Public OAuth Dynamic Client Registration tests with synthetic clients and secrets."""
from __future__ import annotations

import os
import re
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from fastapi.testclient import TestClient

os.environ["MCP_ISSUER"] = "http://localhost"
os.environ["MCP_LOGIN_KEY"] = "synthetic-test-login-" + "a" * 40
os.environ["MCP_TOKEN_SIGNING_SECRET"] = "synthetic-test-signing-" + "b" * 40
os.environ["MCP_CIMD_VALIDATE_REMOTE"] = "false"

from app import config, oauth
from app.main import app

VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
URI = "http://127.0.0.1:3124/callback"


class DCRProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.env = patch.dict(os.environ, {"MCP_OAUTH_DB": str(Path(self.temp.name) / "oauth.sqlite")})
        self.env.start()
        self.addCleanup(self.env.stop)
        oauth._session_store.cache_clear()
        oauth._dcr_store.cache_clear()
        oauth.session_store()
        oauth.dcr_store()
        self.app = TestClient(app)
        oauth._AUTH_CODES.clear()
        oauth._LOGIN_FAILURES.clear()

    def register(self, **updates):
        document = {
            "client_name": "Synthetic CLI",
            "application_type": "native",
            "redirect_uris": [URI],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }
        document.update(updates)
        return self.app.post("/oauth/register", json=document)

    def authorize(self, client_id: str, redirect: str = URI):
        return self.app.get("/oauth/authorize", params={
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect,
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
            "scope": "mcp.access",
            "resource": config.MCP_RESOURCE,
            "state": "synthetic-test",
        }, follow_redirects=False)

    def login(self, client_id: str, redirect: str = URI):
        page = self.authorize(client_id, redirect)
        self.assertEqual(page.status_code, 200, page.text)
        request_token = re.search(r'name="request_token" value="([^"]+)"', page.text)
        self.assertIsNotNone(request_token)
        result = self.app.post("/oauth/authorize",
            data={"request_token": request_token.group(1), "mcp_login_key": config.MCP_LOGIN_KEY},
            follow_redirects=False)
        self.assertEqual(result.status_code, 302)
        code = parse_qs(urlsplit(result.headers["location"]).query)["code"][0]
        return code

    def exchange(self, client_id: str, code: str, redirect: str = URI):
        return self.app.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": redirect,
            "code": code,
            "code_verifier": VERIFIER,
            "resource": config.MCP_RESOURCE,
        })

    def test_metadata_and_registration(self):
        discovery = self.app.get("/.well-known/oauth-authorization-server").json()
        self.assertEqual(discovery["registration_endpoint"], "http://localhost/oauth/register")
        response = self.register()
        self.assertEqual(response.status_code, 201, response.text)
        data = response.json()
        self.assertRegex(data["client_id"], r"^dcr_[A-Za-z0-9_-]{43}$")
        self.assertEqual(data["token_endpoint_auth_method"], "none")
        self.assertNotIn("client_secret", data)
        self.assertEqual(data["redirect_uris"], [URI])
        self.assertEqual(data["client_id_expires_at"], 0)
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_full_browser_pkce_flow_and_refresh(self):
        client = self.register().json()["client_id"]
        page = self.authorize(client)
        self.assertIn("Synthetic CLI", page.text)
        self.assertIn(client, page.text)
        self.assertIn("Registered client ID", page.text)
        code = self.login(client)
        token = self.exchange(client, code)
        self.assertEqual(token.status_code, 200, token.text)
        self.assertEqual(token.json()["scope"], "mcp.access")
        self.assertEqual(self.exchange(client, code).json()["error"], "invalid_grant")
        refreshed = self.app.post("/oauth/token", data={
            "grant_type": "refresh_token",
            "client_id": client,
            "refresh_token": token.json()["refresh_token"],
            "resource": config.MCP_RESOURCE,
        })
        self.assertEqual(refreshed.status_code, 200, refreshed.text)
        self.assertNotEqual(refreshed.json()["refresh_token"], token.json()["refresh_token"])
        self.assertTrue(oauth.dcr_store().get(client))
        # Persistence must survive cache invalidation / simulated restart.
        oauth._dcr_store.cache_clear()
        self.assertTrue(oauth.dcr_store().get(client))

    def test_wrong_pkce_and_cross_client_code_reuse(self):
        one = self.register().json()["client_id"]
        two = self.register().json()["client_id"]
        code = self.login(one)
        bad = self.exchange(two, code)
        self.assertEqual(bad.json()["error"], "invalid_grant")
        self.assertEqual(self.exchange(one, code, URI + "/evil").status_code, 401)
        ok = self.exchange(one, code)
        self.assertEqual(ok.status_code, 200)

    def test_denial_does_not_issue_code(self):
        client = self.register().json()["client_id"]
        page = self.authorize(client)
        token = re.search(r'name="request_token" value="([^"]+)"', page.text).group(1)
        denied = self.app.post("/oauth/authorize", data={"request_token": token,
            "decision": "deny"}, follow_redirects=False)
        self.assertEqual(parse_qs(urlsplit(denied.headers["location"]).query)["error"], ["access_denied"])

    def test_reject_invalid_metadata_and_redirects(self):
        for doc in (
            {"redirect_uris": ["http://192.168.1.1:5000/callback"]},
            {"redirect_uris": ["http://evil.example/callback"]},
            {"redirect_uris": ["file:///tmp/callback"]},
            {"redirect_uris": ["https://valid.example/callback#fragment"]},
            {"redirect_uris": ["https://user:pass@valid.example/callback"]},
            {"redirect_uris": ["http://127.0.0.1:123/callback"], "application_type": "web"},
            {"redirect_uris": []},
            {"token_endpoint_auth_method": "client_secret_basic"},
            {"client_secret": "forged"},
            {"grant_types": ["client_credentials"]},
        ):
            with self.subTest(doc=doc):
                self.assertEqual(self.register(**doc).status_code, 400)
        self.assertEqual(self.register(redirect_uris=["https://callback.example/"]).status_code, 201)

    def test_loopback_port_variation_and_redirect_binding(self):
        client = self.register().json()["client_id"]
        variant = "http://127.0.0.1:47135/callback"
        self.assertEqual(self.authorize(client, variant).status_code, 200)
        self.assertEqual(self.authorize(client, "http://127.0.0.1:47135/other").status_code, 400)
        self.assertEqual(self.authorize(client, "http://localhost:47135/callback").status_code, 400)
        code = self.login(client, variant)
        self.assertEqual(self.exchange(client, code, variant).status_code, 200)

    def test_dcr_disabled_does_not_affect_cimd(self):
        with patch.object(config, "MCP_DCR_ENABLED", False):
            discovery = self.app.get("/.well-known/oauth-authorization-server").json()
            self.assertNotIn("registration_endpoint", discovery)
            self.assertEqual(self.register().status_code, 404)
            self.assertEqual(self.authorize("dcr_unregistered").status_code, 400)
            self.assertEqual(self.authorize(config.MCP_CIMD_CLIENT_ID,
                             "https://chatgpt.com/connector_platform_oauth_redirect").status_code, 200)

    def test_revoke_registration_revokes_token(self):
        client = self.register().json()["client_id"]
        issued = self.exchange(client, self.login(client)).json()
        import asyncio
        verifier = oauth.OAuthTokenVerifier()
        self.assertIsNotNone(asyncio.run(verifier.verify_token(issued["access_token"])))
        self.assertEqual(oauth.dcr_store().revoke(client), 1)
        self.assertIsNone(asyncio.run(verifier.verify_token(issued["access_token"])))
        self.assertEqual(self.authorize(client).status_code, 400)
        self.assertEqual(self.app.post("/oauth/token", data={
            "grant_type": "refresh_token", "client_id": client,
            "refresh_token": issued["refresh_token"]}).status_code, 401)

    def test_90_day_inactivity_and_active_session_protection(self):
        client = self.register().json()["client_id"]
        store = oauth.dcr_store()
        old = int(time.time()) - 91 * 86400
        with store._connect() as db:
            db.execute("UPDATE oauth_dcr_clients SET last_used_at=? WHERE client_id=?", (old, client))
        self.assertEqual(store.prune(), 1)
        self.assertIsNone(store.get(client))
        client = self.register().json()["client_id"]
        self.exchange(client, self.login(client))
        with store._connect() as db:
            db.execute("UPDATE oauth_dcr_clients SET last_used_at=? WHERE client_id=?", (old, client))
        self.assertEqual(store.prune(), 0)
        self.assertIsNotNone(store.get(client))

    def test_invalid_registration_attempts_are_rate_limited(self):
        from app import dcr_registry
        with patch.object(dcr_registry, "PER_IP_RATE", 2):
            self.assertEqual(self.register(grant_types=["client_credentials"]).status_code, 400)
            self.assertEqual(self.register(grant_types=["client_credentials"]).status_code, 400)
            self.assertEqual(self.register().status_code, 429)

    def test_registration_rate_limit(self):
        from app import dcr_registry
        with patch.object(dcr_registry, "PER_IP_RATE", 2):
            self.assertEqual(self.register().status_code, 201)
            self.assertEqual(self.register().status_code, 201)
            self.assertEqual(self.register().status_code, 429)


    def test_admin_cli_list_and_revoke(self):
        import io
        from contextlib import redirect_stdout
        from app.dcr_admin import main
        client = self.register().json()["client_id"]
        path = str(Path(self.temp.name) / "oauth.sqlite")
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["--db", path, "list"]), 0)
        self.assertIn(client, output.getvalue())
        self.assertIn("Synthetic CLI", output.getvalue())
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["--db", path, "revoke", client, "--confirm-id", client]), 0)
        self.assertIn("revoked", output.getvalue())
        self.assertIsNone(oauth.dcr_store().get(client))
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["--db", path, "revoke", client, "--confirm-id", client]), 1)
        self.assertIn("not found", output.getvalue())

    def test_admin_cli_rejects_invalid_database_and_confirmation(self):
        import io
        from contextlib import redirect_stderr
        from app.dcr_admin import main
        path = str(Path(self.temp.name) / "oauth.sqlite")
        client = self.register().json()["client_id"]
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["--db", path, "revoke", client, "--confirm-id", "dcr_other"])
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["--db", path + ".missing", "list"])

    def test_invalid_registration_variants(self):
        from app import dcr_registry
        with patch.object(dcr_registry, "PER_IP_RATE", 100):
            self._check_invalid_registration_variants()

    def _check_invalid_registration_variants(self):
        for update in (
            {"client_name": ""},
            {"client_name": "\x07Hidden"},
            {"grant_types": "authorization_code"},
            {"grant_types": ["authorization_code", "authorization_code"]},
            {"grant_types": ["refresh_token"]},
            {"response_types": ["token"]},
            {"response_types": []},
            {"application_type": "installed"},
            {"redirect_uris": [URI, URI]},
            {"client_id": "hijack"},
            {"registration_access_token": "hijack"},
            {"redirect_uris": ["http://[::1]:0/callback"]},
            {"redirect_uris": ["https://sample.example:99999/"]},
        ):
            with self.subTest(update=update):
                self.assertEqual(self.register(**update).status_code, 400)
        self.assertEqual(self.register(redirect_uris=["http://[::1]:4151/callback"]).status_code, 201)

    def test_native_empty_path_and_https_callback(self):
        self.assertEqual(self.register(redirect_uris=["https://example.org"]).status_code, 201)
        reg = self.register(redirect_uris=["http://127.0.0.1:4231"]).json()
        client = reg["client_id"]
        self.assertEqual(self.authorize(client, "http://127.0.0.1:4231").status_code, 200)
        self.assertEqual(self.authorize(client, "http://127.0.0.1:4233").status_code, 200)

    def test_global_rate_and_registration_capacity(self):
        from app import dcr_registry
        with patch.object(dcr_registry, "GLOBAL_RATE", 1):
            self.assertEqual(self.register().status_code, 201)
            self.assertEqual(self.register().status_code, 429)
        # Separate isolated test fixture; use a new rate epoch for capacity check.
        store = oauth.dcr_store()
        with store._connect() as db:
            db.execute("DELETE FROM oauth_dcr_rates")
        with patch.object(dcr_registry, "MAX_REGISTRATIONS", 1):
            self.assertEqual(self.register().status_code, 429)

    def test_generated_id_collision_is_bounded(self):
        with patch("app.dcr_registry.secrets.token_urlsafe", return_value="A" * 43):
            first = self.register()
            self.assertEqual(first.status_code, 201)
            second = self.register()
            self.assertEqual(second.status_code, 503)
            self.assertEqual(second.json()["error"], "server_error")

    def test_registration_endpoint_rejects_invalid_content_types_and_sizes(self):
        self.assertEqual(self.app.post("/oauth/register", content="{}", headers={
            "content-type": "text/plain"}).status_code, 400)
        self.assertEqual(self.app.post("/oauth/register", content=b"{bad json",
            headers={"content-type": "application/json"}).status_code, 400)
        self.assertEqual(self.app.post("/oauth/register",
            content=b"x" * 16385, headers={"content-type": "application/json"}).status_code, 400)

    def test_unregistered_client_and_admin_listing(self):
        store = oauth.dcr_store()
        self.assertIsNone(store.get("not_a_dcr_client"))
        self.assertIsNone(store.get("dcr_" + "B" * 43))
        self.assertEqual(store.list_clients(), [])
        self.assertEqual(store.revoke("dcr_" + "B" * 43), 0)


if __name__ == "__main__":
    unittest.main()
