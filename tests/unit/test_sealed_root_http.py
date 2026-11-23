"""Synthetic Console HTTP root approval integration; no real SSH or Docker."""
from __future__ import annotations

import asyncio
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import config
from app.approvals import ApprovalManager
from app.approval_status import ApprovalRejected
from app.history import create_history_router
from app.jobs import JobStore
from app.ssh_executor import SSHDenied
from app.sealed_credentials import create_verifier, seal_sudo

PASSWORD = "synthetic-only-console-credential"
SUDO = "synthetic-only-sudo-credential"
ISSUER = "https://localhost"
HOST = "demo-node-a"
KEY = ("synthetic-session", "synthetic/conversation-a", HOST)
ACTOR = "ssh-mcp-operator"
CLIENT = "dcr_synthetic-http-client"


class _SyntheticReadiness:
    def __init__(self):
        self.safe = True

    def active(self, _host):
        return self.safe

    def password_suspended(self, _host):
        return False

    def snapshot(self):
        return {"hosts": {}, "degraded_count": 0}


class _SyntheticExecutor:
    def __init__(self):
        self.readiness = _SyntheticReadiness()
        self._sealed_sudo = {
            HOST: seal_sudo(PASSWORD, SUDO, deployment="lab", issuer=ISSUER,
                            alias=HOST, username="gateway"),
        }
        self._hosts = {HOST: SimpleNamespace(username="gateway")}
        self.live_checks = 0
        self.sudo_checks = 0
        self.before_proof = None

    async def check_readiness_live(self, _host, *, privileged=False):
        assert not privileged
        self.live_checks += 1
        if not self.readiness.safe:
            raise ValueError("Synthetic safety unconfirmed")

    async def verify_unlocked_sudo(self, _actor, _host, supplied, *, permitted):
        self.sudo_checks += 1
        assert supplied == SUDO
        assert permitted()
        if self.before_proof:
            self.before_proof()
        await asyncio.sleep(0)
        return permitted()


class SealedRootHttpTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.context_mode = patch.multiple(
            config, MCP_MANAGED_SECRETS_VERSION="2",
            HISTORY_VIEWER_VERIFIER=create_verifier(PASSWORD, "console-login"),
            HISTORY_VIEWER_GENERATION="a" * 32, MCP_ENVIRONMENT="lab",
            MCP_ISSUER=ISSUER,
        )
        self.context_mode.start()
        self.addCleanup(self.context_mode.stop)
        self.approvals = ApprovalManager()
        self.store = JobStore(Path(temporary.name) / "history.sqlite")
        self.executor = _SyntheticExecutor()
        manager = SimpleNamespace(executor=self.executor, store=self.store)
        app = FastAPI()
        app.include_router(create_history_router(
            self.store, approved_hosts=[HOST], approvals=self.approvals,
            job_manager=manager,
        ))
        tasks = []

        @app.get("/test/queue")
        async def queue(*, root: bool = True, host: bool = False,
                        request_only: bool = False):
            async def request():
                try:
                    return await self.approvals.require(
                        (KEY[0], "", HOST) if request_only else KEY,
                        tool="execute_command", reason="Synthetic HTTP approval",
                        summary="Synthetic fixed command", host_required=host,
                        root_required=root, client_id=CLIENT, actor=ACTOR,
                    )
                except (ApprovalRejected, SSHDenied):
                    return "denied"
            task = asyncio.create_task(request())
            tasks.append(task)
            await asyncio.sleep(0)
            return {"id": next(reversed(self.approvals.pending))}

        self.context = TestClient(app, base_url=ISSUER, follow_redirects=False)
        self.client = self.context.__enter__()
        self.addCleanup(lambda: self.context.__exit__(None, None, None))
        self.addCleanup(self.approvals.shutdown)
        self.tasks = tasks
        page = self.client.get("/console/login")
        self.assertEqual(page.status_code, 200)
        self.csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        response = self.client.post(
            "/console/login", data={"csrf": self.csrf, "password": PASSWORD},
            headers={"Origin": ISSUER},
        )
        self.assertEqual(response.status_code, 303)

    def _queue(self, *, root=True, host=False, request_only=False):
        result = self.client.get(
            "/test/queue", params={"root": str(root).lower(), "host": str(host).lower(),
                                  "request_only": str(request_only).lower()},
        )
        self.assertEqual(result.status_code, 200)
        return result.json()["id"]

    def _grant(self, request_id, *, password="", duration="once"):
        return self.client.post(
            f"/console/api/approvals/{request_id}/grant",
            data={"csrf": self.csrf, "duration": duration,
                  "console_password": password},
            headers={"Origin": ISSUER},
        )

    def test_wrong_password_retry_same_pending_and_duration(self):
        request_id = self._queue()
        original = self.approvals.pending[request_id].deadline
        response = self._grant(request_id, password="incorrect", duration="5m")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"], "Incorrect Console password.")
        self.assertEqual(self.approvals.pending[request_id].deadline, original)
        self.assertEqual(self.executor.live_checks, 0)
        self.assertEqual(self.executor.sudo_checks, 0)
        response = self._grant(request_id, password=PASSWORD, duration="5m")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn(KEY, self.approvals.root_grants)
        self.assertEqual(self.executor.live_checks, 1)
        self.assertEqual(self.executor.sudo_checks, 1)

    def test_shared_console_password_budget_blocks_sudo_and_grant(self):
        request_id = self._queue()
        for _ in range(5):
            bad = self._grant(request_id, password="incorrect")
            self.assertEqual(bad.status_code, 403)
        blocked = self._grant(request_id, password=PASSWORD)
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(blocked.json()["error"],
                         "Too many incorrect password attempts. Try again later.")
        self.assertIn(request_id, self.approvals.pending)
        self.assertEqual(self.executor.live_checks, 0)
        self.assertEqual(self.executor.sudo_checks, 0)
        self.assertFalse(self.approvals.root_grants)

    def test_plain_host_grant_requires_no_root_password(self):
        request_id = self._queue(root=False, host=True)
        response = self._grant(request_id, password="")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.executor.live_checks, 0)
        self.assertEqual(self.executor.sudo_checks, 0)

    def test_denied_session_during_proof_cannot_issue_root_grant(self):
        request_id = self._queue()
        self.executor.before_proof = lambda: self.approvals.decide(
            request_id, grant=False,
        )
        result = self._grant(request_id, password=PASSWORD, duration="5m")
        self.assertEqual(result.status_code, 409)
        self.assertFalse(self.approvals.root_grants)
        self.assertEqual(self.executor.live_checks, 1)
        self.assertEqual(self.executor.sudo_checks, 1)

    def test_originating_mcp_disconnect_before_sudo_proof_blocks_grant(self):
        request_id = self._queue()

        async def disconnected():
            return True

        self.approvals.pending[request_id].disconnected = disconnected
        response = self._grant(request_id, password=PASSWORD, duration="16h")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.executor.sudo_checks, 0)
        self.assertFalse(self.approvals.root_grants)
        self.assertFalse(self.approvals.root_unlocks._entries)

    def test_originating_mcp_disconnect_during_sudo_proof_blocks_commit(self):
        request_id = self._queue()
        disconnected_now = [False]

        async def disconnected():
            return disconnected_now[0]

        self.approvals.pending[request_id].disconnected = disconnected
        self.executor.before_proof = lambda: disconnected_now.__setitem__(0, True)
        response = self._grant(request_id, password=PASSWORD, duration="16h")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.executor.sudo_checks, 1)
        self.assertFalse(self.approvals.root_grants)
        self.assertFalse(self.approvals.root_unlocks._entries)

    def test_logout_during_sudo_proof_with_no_prior_grants_prevents_commit(self):
        request_id = self._queue()
        self.assertFalse(self.approvals.root_grants)
        self.executor.before_proof = self.approvals.revoke_all_root
        response = self._grant(request_id, password=PASSWORD, duration="16h")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.executor.sudo_checks, 1)
        self.assertFalse(self.approvals.root_grants)
        self.assertFalse(self.approvals.root_unlocks._entries)

    def test_sudo_identity_preflight_denial_returns_409_not_500(self):
        request_id = self._queue()
        from unittest.mock import AsyncMock
        from app.ssh_executor import SSHDenied
        self.executor.verify_unlocked_sudo = AsyncMock(
            side_effect=SSHDenied("Synthetic lost host authorization"),
        )
        response = self._grant(request_id, password=PASSWORD)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"], "Host sudo verification failed")
        self.assertFalse(self.approvals.root_grants)
        self.assertFalse(self.approvals.root_unlocks._entries)

    def test_proof_safety_lost_during_sudo_challenge_fails_closed(self):
        request_id = self._queue()
        self.executor.before_proof = lambda: setattr(self.executor.readiness, "safe", False)
        response = self._grant(request_id, password=PASSWORD, duration="5m")
        self.assertEqual(response.status_code, 409)
        self.assertFalse(self.approvals.root_grants)
        self.assertEqual(self.executor.live_checks, 1)
        self.assertEqual(self.executor.sudo_checks, 1)

    def test_failed_live_safety_probe_blocks_root_grant_without_unlock(self):
        request_id = self._queue()
        from unittest.mock import AsyncMock
        self.executor.check_readiness_live = AsyncMock(
            side_effect=ValueError("Synthetic safety check failed"),
        )
        response = self._grant(request_id, password=PASSWORD)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"], "Host safety verification failed")
        self.assertFalse(self.approvals.root_grants)
        self.assertEqual(self.executor.sudo_checks, 0)

    def test_cannot_commit_grant_when_final_authorization_changes(self):
        request_id = self._queue()
        from unittest.mock import patch
        with patch.object(self.approvals, "decide_unlocked", return_value=False) as decide:
            response = self._grant(request_id, password=PASSWORD)
        self.assertEqual(response.status_code, 404)
        decide.assert_called_once()
        self.assertIn(request_id, self.approvals.pending)
        self.assertFalse(self.approvals.root_grants)

    def test_incorrect_sealed_envelope_is_not_unlocked_by_valid_password(self):
        request_id = self._queue()
        from app.sealed_credentials import seal_sudo
        self.executor._sealed_sudo[HOST] = seal_sudo(
            "another-synthetic-console-password", SUDO,
            deployment="lab", issuer=ISSUER, alias=HOST, username="gateway",
        )
        response = self._grant(request_id, password=PASSWORD)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"], "Protected host credential unavailable")
        self.assertIn(request_id, self.approvals.pending)
        self.assertFalse(self.approvals.root_grants)
        self.assertEqual(self.executor.sudo_checks, 0)

    def test_removed_host_envelope_fails_without_sudo_probe(self):
        request_id = self._queue()
        self.executor._sealed_sudo.pop(HOST)
        response = self._grant(request_id, password=PASSWORD)
        self.assertEqual(response.status_code, 409)
        self.assertFalse(self.approvals.root_grants)
        self.assertEqual(self.executor.sudo_checks, 0)

    def test_denied_approval_does_not_allow_late_password_grant(self):
        request_id = self._queue()
        response = self.client.post(
            f"/console/api/approvals/{request_id}/deny",
            data={"csrf": self.csrf}, headers={"Origin": ISSUER},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self._grant(request_id, password=PASSWORD).status_code, 404)
        self.assertFalse(self.approvals.root_grants)

    def test_invalid_duration_and_missing_csrf_cannot_run_root_proof(self):
        request_id = self._queue()
        response = self._grant(request_id, password=PASSWORD, duration="99h")
        self.assertEqual(response.status_code, 400)
        response = self.client.post(
            f"/console/api/approvals/{request_id}/grant",
            data={"duration": "once", "console_password": PASSWORD},
            headers={"Origin": ISSUER},
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn(request_id, self.approvals.pending)
        self.assertEqual(self.executor.sudo_checks, 0)
        self.assertFalse(self.approvals.root_grants)

    def test_expired_pending_root_request_rejects_late_password(self):
        request_id = self._queue()
        import time
        self.approvals.pending[request_id].deadline = time.monotonic() - 1
        response = self._grant(request_id, password=PASSWORD)
        self.assertEqual(response.status_code, 404)
        self.assertNotIn(request_id, self.approvals.pending)
        self.assertEqual(self.executor.sudo_checks, 0)
        self.assertFalse(self.approvals.root_grants)

    def test_unscoped_request_rejects_timed_root_duration_without_decrypt(self):
        request_id = self._queue(request_only=True)
        response = self._grant(request_id, password=PASSWORD, duration="16h")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.executor.sudo_checks, 0)
        self.assertIn(request_id, self.approvals.pending)
        self.assertEqual(self._grant(request_id, password=PASSWORD, duration="once").status_code,
                         200)

    def test_invalid_host_safety_blocks_sudo_without_grant(self):
        request_id = self._queue()
        self.executor.readiness.safe = False
        response = self._grant(request_id, password=PASSWORD)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.executor.live_checks, 0)
        self.assertEqual(self.executor.sudo_checks, 0)
        self.assertFalse(self.approvals.root_grants)

    def test_logout_clears_root_but_preserves_host_grant(self):
        request_id = self._queue(root=True, host=True)
        self.assertEqual(self._grant(request_id, password=PASSWORD, duration="5m").status_code,
                         200)
        self.assertIn(KEY, self.approvals.root_grants)
        self.assertIn(KEY, self.approvals.grants)
        result = self.client.post(
            "/console/logout", data={"csrf": self.csrf},
            headers={"Origin": ISSUER},
        )
        self.assertEqual(result.status_code, 303)
        self.assertNotIn(KEY, self.approvals.root_grants)
        self.assertIn(KEY, self.approvals.grants)

    def test_unauthenticated_logout_cannot_revoke_anothers_root_grant(self):
        request_id = self._queue()
        self.assertEqual(self._grant(request_id, password=PASSWORD, duration="5m").status_code, 200)
        self.assertIn(KEY, self.approvals.root_grants)
        # The anonymous login form supplies its own same-site CSRF token,
        # but no authenticated Console session.
        self.client.cookies.delete("__Host-ssh-mcp-console")
        response = self.client.post(
            "/console/logout", data={"csrf": self.csrf},
            headers={"Origin": ISSUER},
        )
        self.assertEqual(response.status_code, 303)
        self.assertIn(KEY, self.approvals.root_grants)


if __name__ == "__main__":
    unittest.main()
