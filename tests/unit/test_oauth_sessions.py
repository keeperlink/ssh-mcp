"""TEST-214 persistent refresh token security; all fixtures are synthetic and local."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from contextlib import redirect_stdout
import io
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ.setdefault("MCP_ISSUER", "http://localhost")
os.environ.setdefault("MCP_LOGIN_KEY", "synthetic-test-login-" + "a" * 40)
os.environ.setdefault("MCP_TOKEN_SIGNING_SECRET", "synthetic-test-signing-" + "b" * 40)
os.environ.setdefault("MCP_CIMD_VALIDATE_REMOTE", "false")

from app import config, oauth, oauth_session_cli
from app.jobs import JobStore
from app.oauth_sessions import SessionStore
from app.sealed_credentials import create_verifier
from ops.history_db import backup, restore, verify

CLIENT = "https://chatgpt.com/oauth/client.json"
REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


class SessionStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.db = self.root / "jobs.sqlite"
        JobStore(self.db)
        self.store = SessionStore(self.db)
        self.key = hashlib.sha256(config.MCP_TOKEN_SIGNING_SECRET.encode()).hexdigest()

    def issue(self, **changes):
        props = dict(client_id=CLIENT, subject="ssh-mcp-operator", scopes="mcp.access ssh.execute",
                     resource=config.MCP_RESOURCE, expires_at=int(time.time()) + 3600,
                     signing_key_id=self.key)
        props.update(changes)
        return self.store.issue(**props)

    def rotate(self, token, **changes):
        props = dict(refresh_token=token, client_id=CLIENT,
                     resource=config.MCP_RESOURCE, scopes=None,
                     signing_key_id=self.key, expected_subject=config.MCP_OPERATOR_SUBJECT)
        props.update(changes)
        return self.store.rotate(**props)

    def test_single_use_replay_grace_preserves_successor(self):
        sid, old = self.issue()
        newer = self.rotate(old)
        self.assertIsNotNone(newer)
        self.assertEqual(newer["session_id"], sid)
        self.assertNotEqual(newer["refresh_token"], old)
        self.assertIsNone(self.rotate(old))
        self.assertEqual(self.store.list_sessions()[0]["revoked_at"], None)
        self.assertIsNotNone(self.rotate(newer["refresh_token"]))

    def test_late_replay_revokes_family_and_successor(self):
        sid, old = self.issue()
        newer = self.rotate(old)
        with patch("app.oauth_sessions.time.time", return_value=time.time() + 11):
            self.assertIsNone(self.rotate(old))
        self.assertIsNotNone(self.store.list_sessions()[0]["revoked_at"])
        self.assertIsNone(self.rotate(newer["refresh_token"]))
        self.assertEqual(self.store.revoke(sid), 0)

    def test_cross_client_consumed_token_replay_never_revokes_original_session(self):
        sid, old = self.issue()
        newer = self.rotate(old)
        foreign_client = "https://foreign.example.com/oauth/client.json"
        with patch("app.oauth_sessions.time.time", return_value=time.time() + 15):
            # Foreign client tries to rotate using client's consumed token
            self.assertIsNone(self.rotate(old, client_id=foreign_client))
            # Also test resource or scope mismatch on consumed token
            self.assertIsNone(self.rotate(old, resource="https://other.invalid/mcp"))
            self.assertIsNone(self.rotate(old, scopes="mcp.access different.scope"))
        # Original family must NOT be revoked
        self.assertIsNone(self.store.list_sessions()[0]["revoked_at"])
        # Legitimate successor can still rotate cleanly
        self.assertIsNotNone(self.rotate(newer["refresh_token"]))

    def test_independent_client_refresh_isolated(self):
        client_a = "https://client-a.example.com/oauth/client.json"
        client_b = "https://client-b.example.com/oauth/client.json"
        sid_a, old_a = self.issue(client_id=client_a)
        sid_b, old_b = self.issue(client_id=client_b)

        newer_a = self.rotate(old_a, client_id=client_a)
        newer_b = self.rotate(old_b, client_id=client_b)
        self.assertIsNotNone(newer_a)
        self.assertIsNotNone(newer_b)

        # Cross-client replay of consumed tokens after grace does not revoke
        with patch("app.oauth_sessions.time.time", return_value=time.time() + 15):
            self.assertIsNone(self.rotate(old_a, client_id=client_b))
            self.assertIsNone(self.rotate(old_b, client_id=client_a))

        sessions = {s["id"]: s for s in self.store.list_sessions()}
        self.assertIsNone(sessions[sid_a]["revoked_at"])
        self.assertIsNone(sessions[sid_b]["revoked_at"])

        # Both continue to rotate independently
        self.assertIsNotNone(self.rotate(newer_a["refresh_token"], client_id=client_a))
        self.assertIsNotNone(self.rotate(newer_b["refresh_token"], client_id=client_b))

    def test_two_simultaneous_requests_never_issue_two_successors(self):
        _, old = self.issue()
        gate = Barrier(2)
        def try_refresh():
            gate.wait(timeout=10)
            return self.rotate(old)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(try_refresh) for _ in range(2)]
            results = [f.result(timeout=12) for f in futures]
        self.assertEqual(sum(item is not None for item in results), 1)
        winner = next(item for item in results if item)
        self.assertEqual(self.store.list_sessions()[0]["revoked_at"], None)
        self.assertIsNotNone(self.rotate(winner["refresh_token"]))

    def test_client_resource_scope_binding_fail_closed_without_consumption(self):
        _, old = self.issue()
        for edits in (dict(client_id="https://evil.invalid/client.json"),
                      dict(resource="https://evil.invalid/mcp"),
                      dict(scopes="mcp.access ssh.execute admin"),
                      dict(scopes="mcp.access")):
            self.assertIsNone(self.rotate(old, **edits))
        valid = self.rotate(old, scopes="mcp.access ssh.execute")
        self.assertEqual(valid["scopes"], "mcp.access ssh.execute")

    def test_invalid_secret_does_not_revoke_other_sessions(self):
        sid, old = self.issue()
        self.assertIsNone(self.rotate("stolen-or-fabricated"))
        self.assertIsNotNone(self.rotate(old))
        self.assertIsNone(self.store.list_sessions()[0]["revoked_at"])

    def test_restart_persistence_and_storage_contains_only_hashes(self):
        _, token = self.issue()
        self.assertNotIn(token.encode("ascii"), self.db.read_bytes())
        fresh = SessionStore(self.db)
        refreshed = fresh.rotate(refresh_token=token, client_id=CLIENT,
                                 resource=config.MCP_RESOURCE, scopes=None,
                                 signing_key_id=self.key, expected_subject=config.MCP_OPERATOR_SUBJECT)
        self.assertIsNotNone(refreshed)
        self.assertNotIn(refreshed["refresh_token"].encode("ascii"), self.db.read_bytes())
        self.assertEqual(self.db.stat().st_mode & 0o777, 0o600)

    def test_operator_subject_cutover_revokes_legacy_family_before_consumption(self):
        legacy_id, legacy_token = self.issue(subject="legacy-operator")
        self.assertIsNone(self.rotate(legacy_token))
        with self.store._connect() as db:
            stored = db.execute(
                "SELECT revoked_at FROM oauth_sessions WHERE id=?", (legacy_id,)
            ).fetchone()
            refresh = db.execute(
                "SELECT consumed_at FROM oauth_refresh WHERE token_hash=?",
                (hashlib.sha256(legacy_token.encode("utf-8")).hexdigest(),),
            ).fetchone()
        self.assertIsNotNone(stored["revoked_at"])
        self.assertIsNone(refresh["consumed_at"])
        self.assertIsNone(self.rotate(legacy_token))

    def test_subject_mismatch_also_revokes_new_session_family(self):
        _, token = self.issue(subject=config.MCP_OPERATOR_SUBJECT)
        self.assertIsNone(self.rotate(token, expected_subject="legacy-operator"))
        self.assertIsNotNone(self.store.list_sessions()[0]["revoked_at"])

    def test_key_rotation_revokes_old_families(self):
        _, old = self.issue()
        self.assertIsNone(self.rotate(old, signing_key_id="changed-signing-key"))
        self.assertIsNotNone(self.store.list_sessions()[0]["revoked_at"])
        self.assertIsNone(self.rotate(old))

    def test_absolute_expiry_and_cleanup(self):
        _, old = self.issue(expires_at=int(time.time()) + 1)
        with patch("app.oauth_sessions.time.time", return_value=time.time() + 2):
            self.assertIsNone(self.rotate(old))
        with patch("app.oauth_sessions.time.time", return_value=time.time() + 12):
            self.assertEqual(self.store.prune(), 1)
        self.assertEqual(self.store.list_sessions(), [])

    def _run_cli(self, *arguments: str, database: Path | None = None,
                 signed_mounts: bool = False, use_entrypoint: bool = True):
        executable = Path(sys.executable).parent / "oauth-sessions"
        command = [str(executable)] if use_entrypoint else [sys.executable, "-m", "app.oauth_session_cli"]
        if use_entrypoint:
            self.assertTrue(executable.is_file(), "Installed wheel must expose oauth-sessions")
        environment = os.environ.copy()
        environment["SSH_JOBS_DB"] = str(self.db if database is None else database)
        if signed_mounts:
            # Importing app.config here would try to prepare these deliberately
            # nonexistent signed runtime files and fail before the CLI runs.
            environment.update({
                "MCP_CONFIG_FILE": str(self.root / "signed-service.json"),
                "MCP_SECRETS_FILE": str(self.root / "mounted-secrets.json"),
                "MCP_INVENTORY_FILE": str(self.root / "signed-inventory.json"),
                "MCP_KNOWN_HOSTS_FILE": str(self.root / "signed-known_hosts"),
            })
        return subprocess.run(
            [*command, *arguments], capture_output=True, text=True, env=environment, check=False,
        )

    def test_revoke_one_all_and_operator_cli(self):
        first, first_token = self.issue()
        second, second_token = self.issue()
        listing = self._run_cli("list", signed_mounts=True)
        self.assertEqual(listing.returncode, 0, listing.stderr)
        self.assertEqual({row["id"] for row in json.loads(listing.stdout)}, {first, second})
        self.assertNotIn(first_token, listing.stdout)
        revoked = self._run_cli("revoke", "--", first, signed_mounts=True)
        self.assertEqual(revoked.returncode, 0, revoked.stderr)
        self.assertIn("revoked=1", revoked.stdout)
        self.assertIsNone(self.rotate(first_token))
        self.assertIsNotNone(self.rotate(second_token))
        active = self._run_cli("list", signed_mounts=True)
        self.assertEqual({row["id"] for row in json.loads(active.stdout)}, {second})
        historical = self._run_cli("list", "--all", signed_mounts=True)
        self.assertEqual({row["id"] for row in json.loads(historical.stdout)},
                         {first, second})
        all_result = self._run_cli("revoke-all", signed_mounts=True)
        self.assertEqual(all_result.returncode, 0, all_result.stderr)
        self.assertIn("revoked=1", all_result.stdout)
        self.assertEqual(json.loads(self._run_cli("list").stdout), [])
        self.assertIsNotNone(next(s for s in self.store.list_sessions() if s["id"] == second)["revoked_at"])

    def test_cli_listing_retains_expired_history_without_writes(self):
        active_id, active_token = self.issue()
        expired_id, expired_token = self.issue()
        revoked_id, revoked_token = self.issue()
        now = int(time.time())
        with self.store._connect() as db:
            db.execute("UPDATE oauth_sessions SET expires_at=? WHERE id=?",
                       (now - 3600, expired_id))
            db.execute("UPDATE oauth_sessions SET revoked_at=? WHERE id=?",
                       (now - 10, revoked_id))
            before_sessions = db.execute("SELECT COUNT(*) FROM oauth_sessions").fetchone()[0]
            before_refresh = db.execute("SELECT COUNT(*) FROM oauth_refresh").fetchone()[0]
        before_mtime = self.db.stat().st_mtime_ns

        active_result = self._run_cli("list", signed_mounts=True)
        self.assertEqual(active_result.returncode, 0, active_result.stderr)
        self.assertEqual([row["id"] for row in json.loads(active_result.stdout)], [active_id])

        full_result = self._run_cli("list", "--all", signed_mounts=True)
        self.assertEqual(full_result.returncode, 0, full_result.stderr)
        self.assertEqual({row["id"] for row in json.loads(full_result.stdout)},
                         {active_id, expired_id, revoked_id})
        for secret in (active_token, expired_token, revoked_token):
            self.assertNotIn(secret, full_result.stdout)

        with self.store._connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM oauth_sessions").fetchone()[0],
                             before_sessions)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM oauth_refresh").fetchone()[0],
                             before_refresh)
            self.assertEqual(db.execute("SELECT expires_at FROM oauth_sessions WHERE id=?",
                                        (expired_id,)).fetchone()[0], now - 3600)
        self.assertEqual(self.db.stat().st_mtime_ns, before_mtime,
                         "Listing must not rewrite the live SQLite database")

        revoked = self._run_cli("revoke", "--", active_id, signed_mounts=True)
        self.assertEqual(revoked.returncode, 0, revoked.stderr)
        self.assertIn("revoked=1", revoked.stdout)
        with self.store._connect() as db:
            self.assertIsNotNone(db.execute(
                "SELECT id FROM oauth_sessions WHERE id=?", (expired_id,)).fetchone())

    def test_read_only_listing_never_creates_database_or_accepts_symlinks(self):
        missing = self.root / "new-private-dir" / "jobs.sqlite"
        with self.assertRaises(FileNotFoundError):
            SessionStore.read_sessions(missing)
        self.assertFalse(missing.parent.exists())
        link = self.root / "symlink-db"
        link.symlink_to(self.db)
        with self.assertRaises(ValueError):
            SessionStore.read_sessions(link)

    def test_packaged_cli_entrypoint_listing_and_revoke(self):
        session, token = self.issue()
        def invoke(*operation):
            output = io.StringIO()
            with patch.object(sys, "argv", ["oauth-sessions", *operation]), \
                 patch.dict(os.environ, {"SSH_JOBS_DB": str(self.db)}), redirect_stdout(output):
                oauth_session_cli.main()
            return output.getvalue()
        listing = invoke("list")
        self.assertIn(session, listing)
        self.assertNotIn(token, listing)
        # Random URL-safe session IDs can begin with "-", which argparse
        # otherwise treats as an option instead of the required positional.
        self.assertIn("revoked=1", invoke("revoke", "--", session))
        self.assertIn("revoked=0", invoke("revoke", "--", session))
        self.assertIn("revoked=0", invoke("revoke", "--", "-synthetic-absent-id"))
        self.issue()
        self.assertIn("revoked=1", invoke("revoke-all"))

    def test_cli_fails_closed_without_database_or_on_symlink(self):
        first, _ = self.issue()
        executable = Path(sys.executable).parent / "oauth-sessions"
        self.assertTrue(executable.is_file())
        environment = os.environ.copy()
        environment.pop("SSH_JOBS_DB", None)
        missing = subprocess.run([str(executable), "list"], env=environment,
                                 capture_output=True, text=True)
        self.assertEqual(missing.returncode, 2)
        self.assertIn("SSH_JOBS_DB", missing.stderr)
        link = self.root / "linked-db"
        link.symlink_to(self.db)
        rejected = self._run_cli("revoke", "--", first, database=link, signed_mounts=True)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIsNone(self.store.list_sessions()[0]["revoked_at"])
        self.assertEqual(json.loads(self._run_cli("list").stdout)[0]["id"], first)

    def test_database_backup_restore_invalidates_all_restored_families(self):
        _, original = self.issue()
        archived = self.root / "backup.sqlite"
        backup(self.db, archived)
        verify(archived)
        newer = self.rotate(original)
        self.assertIsNotNone(newer)
        restore(archived, self.db, service_stopped=True)
        reopened = SessionStore(self.db)
        self.assertTrue(all(x["revoked_at"] is not None for x in reopened.list_sessions()))
        self.assertIsNone(reopened.rotate(
            refresh_token=original, client_id=CLIENT, resource=config.MCP_RESOURCE,
            scopes=None, signing_key_id=self.key,
            expected_subject=config.MCP_OPERATOR_SUBJECT))

    def test_issue_refuses_expired_authorization_and_revoke_all(self):
        with self.assertRaises(ValueError):
            self.issue(expires_at=1)
        self.issue()
        self.assertEqual(self.store.revoke(), 1)
        self.assertEqual(self.store.revoke(), 0)

    def test_storage_refuses_untrusted_path(self):
        link = self.root / "symlink"
        link.symlink_to(self.db)
        with self.assertRaises(ValueError):
            SessionStore(link)


class RefreshEndpointTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        env = patch.dict(os.environ, {"MCP_OAUTH_DB": str(Path(temporary.name) / "jobs.sqlite")})
        env.start()
        self.addCleanup(env.stop)
        oauth._AUTH_CODES.clear()
        self.app = FastAPI()
        self.app.include_router(oauth.router)
        context = TestClient(self.app)
        self.client = context.__enter__()
        self.addCleanup(lambda: context.__exit__(None, None, None))

    def authorize(self):
        response = self.client.get("/oauth/authorize", params={
            "client_id": CLIENT, "redirect_uri": REDIRECT,
            "response_type": "code", "code_challenge": CHALLENGE,
            "code_challenge_method": "S256", "resource": config.MCP_RESOURCE,
            "scope": "mcp.access",
        })
        import re
        from urllib.parse import parse_qs, urlparse
        req = re.search(r'name="request_token" value="([^"]+)"', response.text).group(1)
        login = self.client.post("/oauth/authorize", data={
            "request_token": req, "mcp_login_key": config.MCP_LOGIN_KEY,
            "session_ttl_seconds": "2592000",
        }, follow_redirects=False)
        code = parse_qs(urlparse(login.headers["location"]).query)["code"][0]
        result = self.client.post("/oauth/token", data={
            "grant_type": "authorization_code", "client_id": CLIENT,
            "redirect_uri": REDIRECT, "code": code,
            "code_verifier": VERIFIER, "resource": config.MCP_RESOURCE,
        })
        self.assertEqual(result.status_code, 200, result.text)
        return result.json()

    def test_v2_oauth_login_uses_argon2_verifier_not_legacy_key(self):
        verifier = create_verifier(config.MCP_LOGIN_KEY, "oauth-login")
        with (patch.object(config, "MCP_MANAGED_SECRETS_VERSION", "2"),
              patch.object(config, "MCP_LOGIN_VERIFIER", verifier),
              patch.object(oauth, "MCP_LOGIN_KEY", "old-plaintext-must-not-authenticate")):
            issued = self.authorize()
            self.assertIn("access_token", issued)
            self.assertIn("refresh_token", issued)
            response = self.client.get("/oauth/authorize", params={
                "client_id": CLIENT, "redirect_uri": REDIRECT,
                "response_type": "code", "code_challenge": CHALLENGE,
                "code_challenge_method": "S256", "resource": config.MCP_RESOURCE,
                "scope": "mcp.access",
            })
            import re
            token = re.search(r'name="request_token" value="([^"]+)"', response.text).group(1)
            rejected = self.client.post("/oauth/authorize", data={
                "request_token": token, "mcp_login_key": "old-plaintext-must-not-authenticate",
                "session_ttl_seconds": "3600",
            }, follow_redirects=False)
            self.assertIn("access_denied", rejected.headers["location"])

    def test_no_database_configuration_or_unsupported_grant(self):
        with patch.dict(os.environ, {"MCP_OAUTH_DB": "", "SSH_JOBS_DB": ""}):
            with self.assertRaises(RuntimeError):
                oauth.session_store()
            resp = self.client.post("/oauth/token", data={
                "grant_type": "refresh_token", "refresh_token": "synthetic",
                "client_id": CLIENT,
            })
            self.assertEqual(resp.status_code, 503)
        unsupported = self.client.post("/oauth/token", data={"grant_type": "password"})
        self.assertEqual(unsupported.json()["error"], "unsupported_grant_type")

    def test_expired_authorization_code_cannot_create_session(self):
        from urllib.parse import parse_qs, urlparse
        import re
        response = self.client.get("/oauth/authorize", params={
            "client_id": CLIENT, "redirect_uri": REDIRECT,
            "response_type": "code", "code_challenge": CHALLENGE,
            "code_challenge_method": "S256", "resource": config.MCP_RESOURCE,
            "scope": "mcp.access",
        })
        token = re.search(r'name="request_token" value="([^"]+)"', response.text).group(1)
        authorized = self.client.post("/oauth/authorize", data={
            "request_token": token, "mcp_login_key": config.MCP_LOGIN_KEY,
            "session_ttl_seconds": "3600",
        }, follow_redirects=False)
        code = parse_qs(urlparse(authorized.headers["location"]).query)["code"][0]
        oauth._AUTH_CODES[code].session_expires_at = 1
        response = self.client.post("/oauth/token", data={
            "grant_type": "authorization_code", "code": code,
            "client_id": CLIENT, "redirect_uri": REDIRECT,
            "code_verifier": VERIFIER, "resource": config.MCP_RESOURCE,
        })
        self.assertEqual(response.json()["error"], "invalid_grant")

    def test_legacy_persisted_subject_cannot_become_new_operator(self):
        store = oauth.session_store()
        session_id, previous_refresh = store.issue(
            client_id=CLIENT, subject="legacy-operator", scopes="mcp.access",
            resource=config.MCP_RESOURCE, expires_at=int(time.time()) + 3600,
            signing_key_id=oauth._signing_key_id(),
        )
        old_token = oauth.issue_access_token(CLIENT, ["mcp.access"], session_id=session_id)[0]
        # Old v2 bearers with the unchanged issuer/signing key cannot bypass
        # the new subject gate during the remainder of their TTL.
        import asyncio
        import jwt
        claims = jwt.decode(old_token, config.MCP_TOKEN_SIGNING_SECRET,
                            algorithms=["HS256"], audience=config.MCP_RESOURCE,
                            issuer=config.MCP_ISSUER)
        claims["sub"] = "legacy-operator"
        old_bearer = jwt.encode(claims, config.MCP_TOKEN_SIGNING_SECRET, algorithm="HS256")
        self.assertIsNone(asyncio.run(oauth.OAuthTokenVerifier().verify_token(old_bearer)))
        rejected = self.client.post("/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": previous_refresh,
            "client_id": CLIENT, "resource": config.MCP_RESOURCE,
        })
        self.assertEqual(rejected.status_code, 400, rejected.text)
        self.assertEqual(rejected.json()["error"], "invalid_grant")
        with store._connect() as db:
            row = db.execute("SELECT revoked_at FROM oauth_sessions WHERE id=?",
                             (session_id,)).fetchone()
            tokens = db.execute("SELECT COUNT(*) FROM oauth_refresh WHERE session_id=?",
                                (session_id,)).fetchone()[0]
        self.assertIsNotNone(row["revoked_at"])
        self.assertEqual(tokens, 1, "An obsolete session must never issue a refresh successor")

    def test_token_exchange_refresh_and_no_scope_escalation(self):
        initial = self.authorize()
        self.assertIn("refresh_token", initial)
        self.assertLessEqual(initial["expires_in"], 900)
        body = {"grant_type": "refresh_token", "refresh_token": initial["refresh_token"],
                "client_id": CLIENT}
        renewed = self.client.post("/oauth/token", data=body)
        self.assertEqual(renewed.status_code, 200, renewed.text)
        self.assertLessEqual(renewed.json()["expires_in"], 900)
        self.assertNotEqual(renewed.json()["refresh_token"], initial["refresh_token"])
        repeat = self.client.post("/oauth/token", data=body)
        self.assertEqual(repeat.json()["error"], "invalid_grant")
        next_token = renewed.json()["refresh_token"]
        for request in (
            {"client_id": "https://evil.invalid/client"},
            {"scope": "mcp.access ssh.execute"},
            {"resource": "https://evil.invalid/mcp"},
        ):
            rejected = self.client.post("/oauth/token", data={
                "grant_type": "refresh_token", "refresh_token": next_token,
                "client_id": CLIENT, **request,
            })
            self.assertNotEqual(rejected.status_code, 200)
        self.assertEqual(self.client.post("/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": next_token, "client_id": CLIENT,
        }).status_code, 200)

    def test_endpoint_cross_client_consumed_token_replay_does_not_revoke(self):
        initial = self.authorize()
        initial_refresh = initial["refresh_token"]
        body = {"grant_type": "refresh_token", "refresh_token": initial_refresh,
                "client_id": CLIENT}
        renewed = self.client.post("/oauth/token", data=body)
        self.assertEqual(renewed.status_code, 200, renewed.text)
        next_token = renewed.json()["refresh_token"]

        with patch("app.oauth_sessions.time.time", return_value=time.time() + 15):
            # Foreign client replays consumed token
            rejected = self.client.post("/oauth/token", data={
                "grant_type": "refresh_token", "refresh_token": initial_refresh,
                "client_id": "https://evil.invalid/client",
            })
            self.assertEqual(rejected.status_code, 400)
            self.assertEqual(rejected.json()["error"], "invalid_grant")

        # Legitimate client can still rotate using next_token
        valid = self.client.post("/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": next_token,
            "client_id": CLIENT,
        })
        self.assertEqual(valid.status_code, 200, valid.text)


if __name__ == "__main__":
    unittest.main()
