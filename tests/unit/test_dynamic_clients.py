"""Focused dynamic-client OAuth, consent and isolation regressions."""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, AsyncMock
from urllib.parse import parse_qs, urlparse

from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ.setdefault("MCP_ISSUER", "http://localhost")
os.environ.setdefault("MCP_LOGIN_KEY", "synthetic-test-login-" + "a" * 40)
os.environ.setdefault("MCP_TOKEN_SIGNING_SECRET", "synthetic-test-signing-" + "b" * 40)
os.environ.setdefault("MCP_CIMD_VALIDATE_REMOTE", "false")

from app import config, oauth
from app.client_metadata import ClientMetadataRegistry, _public_address, _verify_metadata
from app.oauth_sessions import SessionStore
from app.ssh_executor import SSHExecutor
from app.history import HistoryStore

CLIENTS = {
    "https://alpha.example/oauth/client.json":
        ("Alpha client", "https://alpha.example/auth/callback"),
    "https://beta.example/oauth/client.json":
        ("Beta client", "https://beta.example/auth/callback"),
}
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def metadata(client_id):
    name, callback = CLIENTS[client_id]
    return {"client_id": client_id, "client_name": name, "redirect_uris": [callback],
            "response_types": ["code"], "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "none"}


class DynamicOAuthTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "sessions.sqlite"
        patcher = patch.dict(os.environ, {"MCP_OAUTH_DB": str(self.db)})
        patcher.start()
        self.addCleanup(patcher.stop)
        remote = patch.object(oauth, "MCP_CIMD_VALIDATE_REMOTE", True)
        remote.start()
        self.addCleanup(remote.stop)

        async def fake_metadata(client_id, timeout):
            if client_id not in CLIENTS:
                raise ValueError("Unknown synthetic metadata")
            return metadata(client_id)

        from app import client_metadata
        self._fetch_original = client_metadata._fetch_metadata
        fetch = patch("app.client_metadata._fetch_metadata", side_effect=fake_metadata)
        fetch.start()
        self.addCleanup(fetch.stop)
        oauth._CIMD_REGISTRY = ClientMetadataRegistry()
        oauth._AUTH_CODES.clear()
        oauth._LOGIN_FAILURES.clear()
        self.origins = oauth.ActiveOrigins([])
        app = FastAPI()
        app.include_router(oauth.router)
        manager = TestClient(app)
        self.client = manager.__enter__()
        self.addCleanup(lambda: manager.__exit__(None, None, None))

    def authorization(self, client_id):
        callback = CLIENTS[client_id][1]
        params = {"client_id": client_id, "redirect_uri": callback,
                  "response_type": "code", "code_challenge": CHALLENGE,
                  "code_challenge_method": "S256", "resource": config.MCP_RESOURCE,
                  "scope": "mcp.access", "state": "synthetic"}
        page = self.client.get("/oauth/authorize", params=params, follow_redirects=False)
        return page

    def grant(self, client_id):
        page = self.authorization(client_id)
        self.assertEqual(page.status_code, 200, page.text)
        callback = CLIENTS[client_id][1]
        self.assertIn(CLIENTS[client_id][0], page.text)
        self.assertIn(client_id, page.text)
        self.assertIn(callback, page.text)
        self.assertIn(f"form-action 'self' {urlparse(callback).scheme}://{urlparse(callback).netloc}",
                      page.headers["content-security-policy"])
        token = re.search(r'name="request_token" value="([^"]+)"', page.text).group(1)
        post = self.client.post("/oauth/authorize", data={
            "request_token": token, "mcp_login_key": config.MCP_LOGIN_KEY,
            "decision": "grant",
        }, follow_redirects=False)
        self.assertEqual(post.status_code, 302, post.text)
        code = parse_qs(urlparse(post.headers["location"]).query)["code"][0]
        result = self.client.post("/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "client_id": client_id, "redirect_uri": callback,
            "code_verifier": VERIFIER, "resource": config.MCP_RESOURCE,
        })
        self.assertEqual(result.status_code, 200, result.text)
        return result.json()

    def test_two_unknown_clients_consent_independent_refresh_and_csp(self):
        a, b = CLIENTS
        first = self.grant(a)
        second = self.grant(b)
        self.assertNotEqual(first["access_token"], second["access_token"])
        self.assertIn("https://alpha.example", self.origins)
        self.assertIn("https://beta.example", self.origins)
        self.assertEqual(set(SessionStore(self.db).active_origins()),
                         {"https://alpha.example", "https://beta.example"})
        cross = self.client.post("/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": first["refresh_token"],
            "client_id": b,
        })
        self.assertEqual(cross.json()["error"], "invalid_grant")
        valid = self.client.post("/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": first["refresh_token"],
            "client_id": a,
        })
        self.assertEqual(valid.status_code, 200, valid.text)
        # Different OAuth client IDs cannot read one another's audited actor.
        self.assertNotEqual(oauth.client_audit_actor(a), oauth.client_audit_actor(b))
        self.assertEqual(SSHExecutor._inventory_principal(oauth.client_audit_actor(a)),
                         config.MCP_OPERATOR_SUBJECT)
        self.assertEqual(HistoryStore._where({"actor": oauth.client_audit_actor(a)})[0][1],
                         "actor=?")
        self.assertEqual(oauth.client_audit_actor(config.MCP_CIMD_CLIENT_ID),
                         config.MCP_OPERATOR_SUBJECT + "@" +
                         hashlib.sha256(
                             config.MCP_CIMD_CLIENT_ID.encode()).hexdigest())

    def test_denied_client_and_mismatched_redirect_no_tokens(self):
        client_id = next(iter(CLIENTS))
        page = self.authorization(client_id)
        token = re.search(r'name="request_token" value="([^"]+)"', page.text).group(1)
        denial = self.client.post("/oauth/authorize", data={
            "request_token": token, "decision": "deny",
        }, follow_redirects=False)
        self.assertEqual(parse_qs(urlparse(denial.headers["location"]).query)["error"],
                         ["access_denied"])
        wrong = self.client.get("/oauth/authorize", params={
            "client_id": client_id, "redirect_uri": "https://other.example/steal",
        })
        self.assertEqual(wrong.status_code, 400)
        self.assertEqual(SessionStore(self.db).list_sessions(), [])

    def test_loopback_redirect_matching(self):
        from app.client_metadata import redirect_uri_matches
        for registered, requested in (
            ("http://localhost/callback", "http://localhost:60002/callback"),
            ("http://localhost:1111/callback", "http://localhost:65432/callback"),
            ("http://127.0.0.1/callback", "http://127.0.0.1:60002/callback"),
            ("http://127.0.0.2:1111/callback", "http://127.0.0.2:65432/callback"),
            ("http://[::1]/callback?x=1", "http://[::1]:65432/callback?x=1"),
            ("http://localhost", "http://localhost:60002"),
            ("https://example.org", "https://example.org"),
        ):
            with self.subTest(registered=registered, requested=requested):
                self.assertTrue(redirect_uri_matches(registered, requested))
        for registered, requested in (
            ("http://localhost/callback", "http://localhost:60002/other"),
            ("http://localhost/callback", "http://127.0.0.1:60002/callback"),
            ("http://localhost/callback", "http://LOCALHOST:60002/callback"),
            ("http://localhost/callback", "http://localhost.evil.example:60002/callback"),
            ("http://localhost/callback", "http://localhost:60002/callback?"),
            ("http://localhost/callback?x=1", "http://localhost:60002/callback?x=2"),
            ("http://localhost/callback", "http://localhost:0/callback"),
            ("http://localhost/callback", "http://localhost:65536/callback"),
            ("http://localhost/callback", "http://localhost:60002/callback#"),
            ("http://localhost/callback", "http://localhost:/callback"),
            ("http://127.0.0.1/callback", "http://127.0.0.2:60002/callback"),
            ("https://example.org/callback", "https://example.org:60002/callback"),
            ("http://localhost", "http://localhost:60002/"),
            ("http://localhost/callback", "http://localhost@evil.example/callback"),
        ):
            with self.subTest(registered=registered, requested=requested):
                self.assertFalse(redirect_uri_matches(registered, requested))

    def test_cimd_loopback_flow_binds_actual_port_and_origin(self):
        client_id = next(iter(CLIENTS))
        registered = "http://localhost/callback"
        callback = "http://localhost:60002/callback"
        doc = {**metadata(client_id), "redirect_uris": [registered]}
        params = {"client_id": client_id, "redirect_uri": callback,
                  "response_type": "code", "code_challenge": CHALLENGE,
                  "code_challenge_method": "S256", "resource": config.MCP_RESOURCE,
                  "scope": "mcp.access", "state": "synthetic"}
        with patch("app.client_metadata._fetch_metadata", new_callable=AsyncMock,
                   return_value=doc):
            page = self.client.get("/oauth/authorize", params=params, follow_redirects=False)
            self.assertEqual(page.status_code, 200, page.text)
            self.assertIn("form-action 'self' http://localhost:60002",
                          page.headers["content-security-policy"])
            token = re.search(r'name="request_token" value="([^"]+)"', page.text).group(1)
            post = self.client.post("/oauth/authorize", data={
                "request_token": token, "mcp_login_key": config.MCP_LOGIN_KEY,
                "decision": "grant",
            }, follow_redirects=False)
            self.assertEqual(post.status_code, 302, post.text)
            self.assertTrue(post.headers["location"].startswith(callback + "?"))
            code = parse_qs(urlparse(post.headers["location"]).query)["code"][0]
            data = {"grant_type": "authorization_code", "code": code,
                    "client_id": client_id, "code_verifier": VERIFIER,
                    "resource": config.MCP_RESOURCE}
            wrong = self.client.post("/oauth/token", data={
                **data, "redirect_uri": "http://localhost:60003/callback"})
            self.assertEqual(wrong.json()["error"], "invalid_grant")
            result = self.client.post("/oauth/token", data={**data, "redirect_uri": callback})
            self.assertEqual(result.status_code, 200, result.text)
            self.assertIn("http://localhost:60002", self.origins)
            self.assertNotIn("http://localhost:60003", self.origins)

    def test_unnamed_cimd_client_uses_verified_metadata_url(self):
        client_id = next(iter(CLIENTS))
        doc = metadata(client_id)
        del doc["client_name"]
        with patch("app.client_metadata._fetch_metadata", new_callable=AsyncMock,
                   return_value=doc):
            page = self.authorization(client_id)
            self.assertEqual(page.status_code, 200, page.text)
            self.assertIn(client_id, page.text)
        for name in (None, "", 1):
            with self.assertRaises(ValueError):
                _verify_metadata(client_id, CLIENTS[client_id][1],
                                 {**doc, "client_name": name})

    def test_metadata_public_client_requirements(self):
        a = next(iter(CLIENTS))
        correct = metadata(a)
        _verify_metadata(a, CLIENTS[a][1], correct)
        for changes in (
            {"client_id": "https://wrong.example/client.json"},
            {"token_endpoint_auth_method": "client_secret_basic"},
            {"redirect_uris": ["https://other.example/callback"]},
        ):
            with self.subTest(change=changes):
                with self.assertRaises(ValueError):
                    _verify_metadata(a, CLIENTS[a][1], {**correct, **changes})

    def test_chatgpt_cimd_multimethod_preference_uses_public_pkce(self):
        client_id = next(iter(CLIENTS))
        doc = {**metadata(client_id),
               "token_endpoint_auth_method": "private_key_jwt",
               "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"]}
        _verify_metadata(client_id, CLIENTS[client_id][1], doc)
        with patch("app.client_metadata._fetch_metadata", new_callable=AsyncMock,
                   return_value=doc):
            tokens = self.grant(client_id)
        self.assertTrue(tokens["access_token"])
        self.assertTrue(tokens["refresh_token"])

    def test_client_audit_rows_do_not_cross_history_queries(self):
        from app.jobs import JobStore
        from app.contracts import ExecuteCommandRequest
        a, b = CLIENTS
        store = JobStore(self.db, retention_months=12)
        for client_id in (a, b):
            store.create(oauth.client_audit_actor(client_id), ExecuteCommandRequest(
                server="synthetic", argv=["id", "-u"], reason="synthetic audit",
            ), mode="sync")
        history = HistoryStore(store)
        for client_id in (a, b):
            scoped = history.list({"actor": oauth.client_audit_actor(client_id)})
            self.assertEqual(scoped["filtered_total"], 1)
            self.assertEqual(scoped["jobs"][0]["actor"],
                             oauth.client_audit_actor(client_id))
            self.assertEqual(history.hosts(actor=oauth.client_audit_actor(client_id)),
                             ["synthetic"])

    def test_bounded_pinned_metadata_fetch_success_and_failures(self):
        import httpx
        url = "https://alpha.example/oauth/client.json?version=2"
        original_client = httpx.AsyncClient

        def fetch(response):
            seen = []
            def handler(request):
                seen.append(request)
                return response
            def factory(*args, **kwargs):
                return original_client(*args,
                                       transport=httpx.MockTransport(handler), **kwargs)
            with patch("app.client_metadata._public_address",
                       new_callable=AsyncMock, return_value="8.8.8.8"):
                with patch("app.client_metadata.httpx.AsyncClient", side_effect=factory):
                    data = asyncio.run(self._fetch_original(url, 5))
            return data, seen

        result, requests = fetch(httpx.Response(200, json=metadata(next(iter(CLIENTS)))))
        self.assertEqual(result["client_name"], "Alpha client")
        self.assertEqual(requests[0].url.host, "8.8.8.8")
        self.assertEqual(requests[0].headers["host"], "alpha.example")
        self.assertEqual(requests[0].extensions["sni_hostname"], "alpha.example")
        self.assertIn("version=2", str(requests[0].url))

        for response in (httpx.Response(503, json={"error": "unavailable"}),
                         httpx.Response(200, json=["not", "an", "object"]),
                         httpx.Response(200, content=b"not-json"),
                         httpx.Response(200, content=b"{" + b"x" * 33000 + b"}")):
            with self.subTest(status=response.status_code, size=len(response.content)):
                with self.assertRaises(ValueError):
                    fetch(response)

    def test_oauth_url_validation_security_cases(self):
        from app.client_metadata import _parts, redirect_origin
        self.assertEqual(redirect_origin("https://alpha.example:9443/path?x=1"),
                         "https://alpha.example:9443")
        self.assertEqual(redirect_origin("http://127.0.0.1:8888/cb"),
                         "http://127.0.0.1:8888")
        for invalid in (
            "http://alpha.example/cimd.json",
            "https://alpha.example",
            "https://user@alpha.example/client.json",
            "https://alpha.example/client.json#fragment",
            "https://alpha.example:bad/client.json",
            "https://bad_.example/client.json",
            "https://-bad.example/client.json",
            "https://alpha.example/x y",
            "https://alpha.example:0/client.json",
        ):
            with self.subTest(url=invalid):
                with self.assertRaises(ValueError):
                    _parts(invalid, metadata=True)
        with self.assertRaises(ValueError):
            redirect_origin("http://nonlocal.example/cb")

    def test_cimd_legacy_auth_method_and_invalid_types(self):
        client = next(iter(CLIENTS))
        doc = metadata(client)
        del doc["token_endpoint_auth_method"]
        doc["token_endpoint_auth_methods_supported"] = ["none"]
        _verify_metadata(client, CLIENTS[client][1], doc)
        for change in (
            {"token_endpoint_auth_methods_supported": []},
            {"token_endpoint_auth_methods_supported": "none"},
            {"token_endpoint_auth_methods_supported": 5},
            {"token_endpoint_auth_methods_supported": [None]},
            {"token_endpoint_auth_methods_supported": ["client_secret_basic"]},
            {"token_endpoint_auth_method": "private_key_jwt",
             "token_endpoint_auth_methods_supported": ["private_key_jwt"]},
            {"token_endpoint_auth_method": "private_key_jwt",
             "token_endpoint_auth_methods_supported": ["none"]},
            {"token_endpoint_auth_method": None},
            {"token_endpoint_auth_method": ["none"]},
            {"token_endpoint_auth_method": 7},
            {"token_endpoint_auth_method": "none",
             "token_endpoint_auth_methods_supported": ["client_secret_basic"]},
            {"response_types": []},
            {"response_types": "code"},
            {"grant_types": []},
            {"grant_types": "authorization_code"},
            {"client_name": ""},
            {"redirect_uris": "not-a-list"},
            {"redirect_uris": [False]},
        ):
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    _verify_metadata(client, CLIENTS[client][1], {**doc, **change})

    def test_origin_policy_tracks_revocation_expiry_and_shared_clients(self):
        from app.oauth_sessions import SessionStore
        store = SessionStore(self.db)
        a, b = CLIENTS
        origin = "https://alpha.example"
        static = oauth.ActiveOrigins(["https://static.example"])
        self.grant(a)
        first = store.list_sessions()[0]["id"]
        self.grant(a)
        second = next(item["id"] for item in store.list_sessions()
                      if item["id"] != first)
        self.grant(b)
        self.assertIn(origin, self.origins)
        self.assertIn(origin, static)
        self.assertIn("https://static.example", static)
        self.assertEqual(store.revoke(first), 1)
        self.assertIn(origin, self.origins)  # Another active session survives.
        self.assertEqual(store.revoke(second), 1)
        self.assertNotIn(origin, self.origins)
        self.assertIn("https://beta.example", self.origins)
        self.assertIn("https://static.example", static)
        with store._connect() as db:
            db.execute("UPDATE oauth_sessions SET expires_at=? WHERE client_id=?",
                       (0, b))
        self.assertNotIn("https://beta.example", self.origins)
        self.assertNotIn(origin, static)

    def test_metadata_fetch_does_not_block_cached_unrelated_client(self):
        import time
        registry = ClientMetadataRegistry()
        a, b = CLIENTS
        registry._cache[b] = (time.monotonic() + 60, metadata(b))

        async def slow_metadata(client_id, timeout):
            await asyncio.sleep(60)
            return metadata(client_id)

        async def check():
            with patch("app.client_metadata._fetch_metadata", side_effect=slow_metadata):
                slow = asyncio.create_task(registry.validate(
                    a, CLIENTS[a][1], timeout=0.05, cache_ttl=60,
                ))
                try:
                    cached = await asyncio.wait_for(registry.validate(
                        b, CLIENTS[b][1], timeout=1, cache_ttl=60,
                    ), timeout=0.3)
                    self.assertEqual(cached["client_id"], b)
                    with self.assertRaisesRegex(ValueError, "timed out"):
                        await asyncio.wait_for(slow, timeout=2)
                finally:
                    if not slow.done():
                        slow.cancel()
                        await asyncio.gather(slow, return_exceptions=True)

        asyncio.run(check())

    def test_ipv6_zone_authority_cannot_enter_oauth_csp(self):
        from app.client_metadata import redirect_origin
        from app.oauth import _security_headers
        self.assertEqual(redirect_origin("https://EXAMPLE.org:443/cb"),
                         "https://example.org")
        self.assertEqual(redirect_origin("https://[2001:0db8::0001]:443/cb"),
                         "https://[2001:db8::1]")
        for bad in (
            "https://[fe80::1%25eth0]/callback",
            "https://[fe80::1%eth0]/callback",
            "https://[::1%25lo0]:8443/callback",
            "https://%65xample.org/cb",
            "https://example.org\\@evil.invalid/cb",
        ):
            with self.subTest(url=bad):
                with self.assertRaises(ValueError):
                    _security_headers(bad)
                with self.assertRaises(ValueError):
                    redirect_origin(bad)

    def test_client_scoped_service_status_counters(self):
        import time
        from types import SimpleNamespace
        from app.jobs import JobStore
        from app.contracts import ExecuteCommandRequest
        from app.operational import service_status

        store = JobStore(self.db, retention_months=12)
        a, b = CLIENTS
        actors = [oauth.client_audit_actor(client_id) for client_id in (a, b)]
        for index, actor in enumerate(actors):
            for n in range(index + 1):
                store.create(actor, ExecuteCommandRequest(
                    server="synthetic", argv=["id", "-u"], reason="test status",
                ), mode="sync")
        all_status = service_status(SimpleNamespace(store=store),
                                    started_monotonic=time.monotonic())
        first_status = service_status(SimpleNamespace(store=store),
                                      started_monotonic=time.monotonic(),
                                      actor=actors[0])
        second_status = service_status(SimpleNamespace(store=store),
                                       started_monotonic=time.monotonic(),
                                       actor=actors[1])
        self.assertEqual(all_status["storage"]["retained_jobs"], 3)
        self.assertEqual(first_status["storage"]["retained_jobs"], 1)
        self.assertEqual(second_status["storage"]["retained_jobs"], 2)
        self.assertEqual(first_status["jobs"]["queued"], 1)
        self.assertEqual(second_status["jobs"]["queued"], 2)

    def test_metadata_dns_prefers_ipv4_but_checks_every_address(self):
        from app import client_metadata
        records = [(10, 1, 6, "", ("2600::1", 443, 0, 0)),
                   (2, 1, 6, "", ("52.1.2.3", 443))]
        with patch.object(client_metadata.socket, "getaddrinfo", return_value=records):
            self.assertEqual(asyncio.run(client_metadata._public_address("example.org", 443)),
                             "52.1.2.3")
        with patch.object(client_metadata.socket, "getaddrinfo", return_value=records[:1]):
            self.assertEqual(asyncio.run(client_metadata._public_address("example.org", 443)),
                             "2600::1")
        with patch.object(client_metadata.socket, "getaddrinfo",
                          return_value=records + [(2, 1, 6, "", ("127.0.0.1", 443))]):
            with self.assertRaises(ValueError):
                asyncio.run(client_metadata._public_address("example.org", 443))

    def test_private_metadata_address_rejected(self):
        from app import client_metadata
        with patch.object(client_metadata.socket, "getaddrinfo",
                          return_value=[(2, 1, 6, "", ("127.0.0.1", 443))]):
            with self.assertRaisesRegex(ValueError, "not public"):
                asyncio.run(_public_address("unsafe.example", 443))
        with self.assertRaises(ValueError):
            asyncio.run(_public_address("", 0))


if __name__ == "__main__":
    unittest.main()
