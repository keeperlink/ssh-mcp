"""Synthetic live grant and credential handoff tests; no SSH/network access."""
from __future__ import annotations

import asyncio
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from app import config
from app.approval_status import ApprovalCode
from app.approvals import ApprovalManager
from app.batch import BatchManager
from app.contracts import ExecuteCommandRequest, ExecuteCommandsRequest
from app.grant_unlocks import (
    RootAccess, UnlockScope, root_access_context,
)
from app.jobs import JobManager, JobStore
from app.history import ViewerAuth
from app.readiness import ReadinessSettings
from app.sealed_credentials import InvalidCredential, create_verifier, seal_sudo
from app.ssh_executor import (
    HostSpec, ReadinessDenied, SSHDenied, SSHExecutor, SSHResult,
)

CONSOLE = "synthetic-only-operator-password"
SUDO = "synthetic-only-sudo-password"
ISSUER = "https://synthetic.example.invalid"
HOST = "demo-node-a"
ACTOR = "ssh-mcp-operator"
CLIENT = "dcr_synthetic-operator-client"
KEY = ("synthetic-oauth-session", "synthetic/conversation-a", HOST)


class SealedRootGrantTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        mode = patch.object(config, "MCP_MANAGED_SECRETS_VERSION", "2")
        mode.start()
        self.addCleanup(mode.stop)
        self.manager = ApprovalManager()
        self.addCleanup(self.manager.shutdown)
        self.verifier = create_verifier(CONSOLE, "console-login")
        self.sealed = seal_sudo(CONSOLE, SUDO, deployment="lab", issuer=ISSUER,
                                alias=HOST, username="gateway")

    async def pending(self, *, key=KEY, host_required=False,
                      operation_timeout_seconds=300):
        async def request():
            result = await self.manager.require(
                key, tool="execute_command", reason="TEST-347 root admission",
                summary="Synthetic root operation", host_required=host_required,
                root_required=True, client_id=CLIENT, actor=ACTOR,
                operation_timeout_seconds=operation_timeout_seconds,
            )
            return result, root_access_context.get()
        task = asyncio.create_task(request())
        await asyncio.sleep(0.001)
        item = next(reversed(self.manager.pending.values()))
        return task, item

    def prepare(self, request, *, duration="once"):
        return self.manager.root_unlocks.prepare(
            UnlockScope(
                request.key, actor=ACTOR, client_id=CLIENT,
                issuance=request.id,
                operation_id=request.id if duration == "once" else "",
                kind="request" if duration == "once" else "timed",
                generation="synthetic-generation",
            ),
            console_password=CONSOLE, console_verifier=self.verifier,
            sealed_sudo=self.sealed, deployment="lab", issuer=ISSUER,
            username="gateway",
        )

    async def issue(self, duration="once", *, key=KEY, host_required=False,
                    operation_timeout_seconds=300):
        task, pending = await self.pending(
            key=key, host_required=host_required,
            operation_timeout_seconds=operation_timeout_seconds,
        )
        prepared = self.prepare(pending, duration=duration)
        self.assertTrue(self.manager.decide_unlocked(
            pending.id, prepared=prepared, duration=duration,
            still_authorized=lambda: True,
        ))
        self.assertIsNone(prepared.password)
        code, access = await task
        self.assertIsInstance(access, RootAccess)
        self.assertEqual(access.require(host=HOST, actor=ACTOR), SUDO)
        return code, access

    async def test_once_grant_attached_to_exact_request_only(self):
        code, access = await self.issue("once")
        self.assertEqual(code, ApprovalCode.APPROVED_EXPLICIT)
        self.assertEqual(access.scope.operation_id, access.scope.issuance)
        self.assertEqual(access.scope.kind, "request")
        self.assertFalse(self.manager.root_grants)
        second, new_request = await self.pending()
        self.assertNotEqual(new_request.id, access.scope.issuance)
        self.assertIsNone(self.manager._timed_root_access.get(KEY))
        self.assertTrue(self.manager.decide(new_request.id, grant=False))
        with self.assertRaises(Exception):
            await second
        self.assertEqual(access.require(host=HOST, actor=ACTOR), SUDO)
        with self.assertRaises(InvalidCredential):
            access.require(host="demo-node-b", actor=ACTOR)
        with self.assertRaises(InvalidCredential):
            access.require(host=HOST, actor="other-oauth-actor")
        self.manager.revoke_all_root()
        self.assertFalse(access.valid(host=HOST, actor=ACTOR))

    async def test_timed_grant_reused_only_until_revoke(self):
        code, access = await self.issue("5m", host_required=True)
        self.assertEqual(code, ApprovalCode.APPROVED_TIMED)
        self.assertEqual(access.scope.operation_id, "")
        self.assertEqual(access.scope.kind, "timed")
        self.assertTrue(self.manager.grants[KEY] > time.monotonic())
        async def reuse():
            code = await self.manager.require(
                KEY, tool="execute_commands", reason="Second synthetic step",
                summary="Batch", host_required=True, root_required=True,
                client_id=CLIENT, actor=ACTOR,
            )
            return code, root_access_context.get()
        second_code, second = await reuse()
        self.assertEqual(second_code, ApprovalCode.APPROVED_TIMED)
        self.assertIs(second, access)
        self.assertTrue(self.manager.revoke(self.manager.grant_id(KEY, "root")))
        self.assertFalse(access.valid(host=HOST, actor=ACTOR))
        self.assertIn(KEY, self.manager.grants)  # Root revoke does not revoke host.
        task, request = await self.pending(key=KEY, host_required=True)
        prepared = self.prepare(request, duration="5m")
        self.assertTrue(self.manager.decide_unlocked(
            request.id, duration="5m", prepared=prepared,
            still_authorized=lambda: True,
        ))
        _, replacement = await task
        self.assertTrue(replacement.valid(host=HOST, actor=ACTOR))
        self.assertFalse(access.valid(host=HOST, actor=ACTOR))

    async def test_live_revocation_prevents_commit_and_grant(self):
        task, request = await self.pending()
        prepared = self.prepare(request)
        self.manager.root_unlocks.revoke_actor(ACTOR)
        self.assertFalse(self.manager.decide_unlocked(
            request.id, duration="once", prepared=prepared,
            still_authorized=lambda: True,
        ))
        self.assertIsNone(prepared.password)
        self.assertIn(request.id, self.manager.pending)
        with self.assertRaises(Exception):
            self.manager.root_unlocks.require("invalid", prepared.scope)
        self.assertTrue(self.manager.decide(request.id, grant=False))
        with self.assertRaises(Exception):
            await task

    async def test_failed_live_authorization_keeps_original_pending_deadline(self):
        task, request = await self.pending()
        deadline = request.deadline
        prepared = self.prepare(request)
        self.assertFalse(self.manager.decide_unlocked(
            request.id, duration="once", prepared=prepared,
            still_authorized=lambda: False,
        ))
        self.assertIsNone(prepared.password)
        self.assertEqual(self.manager.pending[request.id].deadline, deadline)
        prepared = self.prepare(request)
        self.assertTrue(self.manager.decide_unlocked(
            request.id, duration="once", prepared=prepared,
            still_authorized=lambda: True,
        ))
        code, access = await task
        self.assertEqual(code, ApprovalCode.APPROVED_EXPLICIT)
        self.assertTrue(access.valid(host=HOST, actor=ACTOR))

    async def test_logout_invalidates_root_but_preserves_host_grant(self):
        _, access = await self.issue("5m", host_required=True)
        self.manager.revoke_all_root()
        self.assertIn(KEY, self.manager.grants)
        self.assertNotIn(KEY, self.manager.root_grants)
        self.assertFalse(access.valid(host=HOST, actor=ACTOR))

    async def test_logout_without_prior_grants_invalidates_inflight_prepared_password(self):
        task, pending = await self.pending()
        prepared = self.prepare(pending, duration="5m")
        epoch = self.manager.root_unlocks._epoch
        self.assertFalse(self.manager.root_grants)
        self.manager.revoke_all_root()
        self.assertGreater(self.manager.root_unlocks._epoch, epoch)
        self.assertFalse(self.manager.decide_unlocked(
            pending.id, duration="5m", prepared=prepared,
            still_authorized=lambda: True,
        ))
        self.assertIsNone(prepared.password)
        self.assertFalse(self.manager.root_grants)
        self.assertFalse(self.manager.root_unlocks._entries)
        self.assertTrue(self.manager.decide(pending.id, grant=False))
        with self.assertRaises(Exception):
            await task

    async def test_disconnected_mcp_request_does_not_issue_timed_root_unlock(self):
        task, pending = await self.pending()
        state = [False]

        async def disconnected():
            return state[0]

        pending.disconnected = disconnected
        prepared = self.prepare(pending, duration="16h")
        state[0] = True
        self.assertFalse(await self.manager.decide_unlocked_live(
            pending.id, duration="16h", prepared=prepared,
            still_authorized=lambda: True,
        ))
        self.assertIsNone(prepared.password)
        self.assertFalse(self.manager.root_grants)
        self.assertFalse(self.manager.root_unlocks._entries)
        with self.assertRaises(Exception):
            await task

    async def test_once_grant_covers_long_batch_safety_window_and_releases_on_finish(self):
        _, access = await self.issue("once", operation_timeout_seconds=900)
        entry = self.manager.root_unlocks._entries[access.handle]
        self.assertGreater(entry.expires - time.monotonic(), 900)
        # Simulate 301 seconds elapsed after grant: unlike the former fixed
        # five-minute TTL, the same admitted operation can still use sudo.
        current = self.manager.root_unlocks._clock
        self.manager.root_unlocks._clock = lambda: current() + 301
        try:
            self.assertEqual(access.require(host=HOST, actor=ACTOR), SUDO)
        finally:
            self.manager.root_unlocks._clock = current
        access.finish()
        self.assertFalse(access.valid(host=HOST, actor=ACTOR))
        self.assertNotIn(access.scope.issuance, self.manager._once_root_access)
        self.assertNotIn(access.handle, self.manager.root_unlocks._entries)
        access.finish()  # Idempotent terminal cleanup.

    async def test_invalidated_timed_secret_requires_fresh_root_password(self):
        _, old = await self.issue("5m", host_required=True)
        self.manager.root_unlocks.revoke(old.handle)
        self.assertIn(KEY, self.manager.root_grants)
        self.assertFalse(old.valid(host=HOST, actor=ACTOR))
        task, pending = await self.pending(key=KEY, host_required=True)
        self.assertTrue(pending.grant_root)
        self.assertFalse(pending.grant_host)
        prepared = self.prepare(pending, duration="5m")
        self.assertTrue(self.manager.decide_unlocked(
            pending.id, duration="5m", prepared=prepared,
            still_authorized=lambda: True,
        ))
        _, replacement = await task
        self.assertTrue(replacement.valid(host=HOST, actor=ACTOR))
        self.assertFalse(old.valid(host=HOST, actor=ACTOR))
        self.assertIs(self.manager._timed_root_access[KEY], replacement)

    async def test_invalid_scope_and_deadline_cannot_publish_root_grant(self):
        task, pending = await self.pending()
        prepared = self.prepare(pending)
        self.assertFalse(self.manager.decide_unlocked(
            pending.id, duration="nonsense", prepared=prepared,
            still_authorized=lambda: True,
        ))
        self.assertIsNone(prepared.password)
        self.assertIn(pending.id, self.manager.pending)
        prepared = self.prepare(pending)
        prepared.scope = UnlockScope(
            pending.key, actor="different-actor", client_id=CLIENT,
            issuance=pending.id, operation_id=pending.id,
            generation="synthetic-generation",
        )
        self.assertFalse(self.manager.decide_unlocked(
            pending.id, duration="once", prepared=prepared,
            still_authorized=lambda: True,
        ))
        self.assertIsNone(prepared.password)
        pending.deadline = time.monotonic() - 1
        prepared = self.prepare(pending)
        self.assertFalse(self.manager.decide_unlocked(
            pending.id, duration="once", prepared=prepared,
            still_authorized=lambda: True,
        ))
        self.assertIsNone(prepared.password)
        with self.assertRaises(Exception):
            await task

    async def test_expiring_root_grant_revokes_memory_handle_but_keeps_ssh_grant(self):
        _, access = await self.issue("5m", host_required=True)
        self.manager.root_grants[KEY] = time.monotonic() - 1
        self.manager._expire()
        self.assertFalse(access.valid(host=HOST, actor=ACTOR))
        self.assertNotIn(KEY, self.manager.root_grants)
        self.assertIn(KEY, self.manager.grants)
        self.assertNotIn(KEY, self.manager._timed_root_access)

    async def test_job_tasks_capture_handle_but_unrelated_context_cannot(self):
        _, access = await self.issue()
        self.assertIsNone(root_access_context.get())
        token = root_access_context.set(access)
        try:
            task = asyncio.create_task(self._task_root_access())
        finally:
            root_access_context.reset(token)
        self.assertIs(await task, access)
        self.assertIsNone(root_access_context.get())

    async def _task_root_access(self):
        await asyncio.sleep(0)
        return root_access_context.get()

    async def test_sudo_requires_live_scope_after_capacity_wait_and_before_write(self):
        _, access = await self.issue("5m")
        host = HostSpec(
            alias=HOST, address="synthetic.example.invalid", port=22,
            username="gateway", principals=[ACTOR],
            identity_file=Path("/synthetic/id"), known_hosts_file=Path("/synthetic/known"),
            environment="non-production",
            access="restricted", privileged_access="restricted",
        )
        executor = SSHExecutor(
            {HOST: host}, enabled=True,
            sealed_sudo={HOST: self.sealed},
            readiness_settings=ReadinessSettings(authorized=True),
        )
        self.assertIsNotNone(executor.readiness)
        executor.readiness._states[HOST].last_ssh = time.monotonic()
        executor.readiness._states[HOST].safety_confirmed = True
        command = ExecuteCommandRequest(
            server=HOST, argv=["/usr/bin/id", "-u"], privileged=True,
            reason="TEST-347 synthetic grant execution",
        )
        with patch.object(executor, "authorized_host", return_value=host):
            with patch.object(executor, "_run", new_callable=AsyncMock) as runner:
                runner.return_value = SSHResult(
                    HOST, "succeeded", 0, "0", "", .01, root_started=True,
                )
                token = root_access_context.set(access)
                try:
                    result = await executor._execute_approved_privileged(ACTOR, command)
                finally:
                    root_access_context.reset(token)
                self.assertEqual(result.status, "succeeded")
                self.assertEqual(runner.await_args.kwargs["sudo_password"], SUDO)
                self.assertTrue(runner.await_args.kwargs["password_permitted"]())
                self.assertTrue(self.manager.revoke(self.manager.grant_id(KEY, "root")))
                with self.assertRaises(ReadinessDenied):
                    runner.await_args.kwargs["password_permitted"]()
                runner.reset_mock()
                token = root_access_context.set(access)
                try:
                    with self.assertRaises(SSHDenied):
                        await executor._execute_approved_privileged(ACTOR, command)
                finally:
                    root_access_context.reset(token)
                runner.assert_not_awaited()

    async def test_unlocked_sudo_requires_fixed_successful_fresh_proof(self):
        host = HostSpec(
            alias=HOST, address="synthetic.example.invalid", port=22,
            username="gateway", principals=[ACTOR],
            identity_file=Path("/synthetic/id"), known_hosts_file=Path("/synthetic/known"),
            environment="non-production",
            access="restricted", privileged_access="restricted",
        )
        executor = SSHExecutor(
            {HOST: host}, enabled=True, sealed_sudo={HOST: self.sealed},
            readiness_settings=ReadinessSettings(authorized=True),
        )
        executor.readiness._states[HOST].last_ssh = time.monotonic()
        executor.readiness._states[HOST].safety_confirmed = True
        permitted = [True]
        with patch.object(executor, "authorized_host", return_value=host):
            with patch.object(executor, "_run", new_callable=AsyncMock) as runner:
                runner.return_value = SSHResult(
                    HOST, "succeeded", 0, "0", "", .01, root_started=True,
                )
                self.assertTrue(await executor.verify_unlocked_sudo(
                    ACTOR, HOST, SUDO, permitted=lambda: permitted[0],
                ))
                args = runner.await_args
                self.assertEqual(args.args[1].argv, ["/usr/bin/id", "-u"])
                self.assertTrue(args.kwargs["challenge_password"])
                self.assertTrue(args.kwargs["probe"])
                self.assertEqual(args.kwargs["sudo_password"], SUDO)
                permitted[0] = False
                self.assertFalse(args.kwargs["password_permitted"]())
                self.assertFalse(await executor.verify_unlocked_sudo(
                    ACTOR, HOST, SUDO, permitted=lambda: permitted[0],
                ))
                self.assertEqual(runner.await_count, 1)
                permitted[0] = True
                runner.return_value = SSHResult(
                    HOST, "command_error", 1, "", "", .01,
                    failure_kind="sudo_authentication", password_rejected=True,
                )
                self.assertFalse(await executor.verify_unlocked_sudo(
                    ACTOR, HOST, SUDO, permitted=lambda: permitted[0],
                ))
                self.assertTrue(executor.readiness.password_suspended(HOST))
                self.assertFalse(await executor.verify_unlocked_sudo(
                    ACTOR, HOST, SUDO, permitted=lambda: permitted[0],
                ))
                self.assertEqual(runner.await_count, 2)

    async def test_root_probe_requires_sealed_host_fresh_safe_readiness_and_marker(self):
        host = HostSpec(
            alias=HOST, address="synthetic.example.invalid", port=22,
            username="gateway", principals=[ACTOR], environment="non-production",
            identity_file=Path("/synthetic/id"),
            known_hosts_file=Path("/synthetic/known"), access="restricted",
            privileged_access="restricted",
        )
        executor = SSHExecutor(
            {HOST: host}, enabled=True, sealed_sudo={HOST: self.sealed},
            readiness_settings=ReadinessSettings(authorized=True),
        )
        plain = SSHExecutor({HOST: host}, enabled=True)
        with patch.object(plain, "authorized_host", return_value=host):
            self.assertFalse(await plain.verify_unlocked_sudo(
                ACTOR, HOST, SUDO, permitted=lambda: True,
            ))
        with patch.object(executor, "authorized_host", return_value=host):
            self.assertFalse(await executor.verify_unlocked_sudo(
                ACTOR, HOST, SUDO, permitted=lambda: True,
            ))
            executor.readiness._states[HOST].last_ssh = time.monotonic()
            executor.readiness._states[HOST].safety_confirmed = True
            with patch.object(executor, "_run", new_callable=AsyncMock) as runner:
                for result in (
                    SSHResult(HOST, "succeeded", 0, "0", "", .01),
                    SSHResult(HOST, "succeeded", 0, "not-root", "", .01, root_started=True),
                    SSHResult(HOST, "command_error", 1, "", "", .01),
                ):
                    with self.subTest(result=result.status):
                        runner.return_value = result
                        self.assertFalse(await executor.verify_unlocked_sudo(
                            ACTOR, HOST, SUDO, permitted=lambda: True,
                        ))
                self.assertEqual(runner.await_count, 3)

    async def test_sealed_privileged_execution_denied_without_scope_and_suspended_sudo(self):
        _, access = await self.issue("5m")
        host = HostSpec(
            alias=HOST, address="synthetic.example.invalid", port=22,
            username="gateway", principals=[ACTOR], environment="non-production",
            identity_file=Path("/synthetic/id"),
            known_hosts_file=Path("/synthetic/known"), access="restricted",
            privileged_access="restricted",
        )
        executor = SSHExecutor(
            {HOST: host}, enabled=True, sealed_sudo={HOST: self.sealed},
            readiness_settings=ReadinessSettings(authorized=True),
        )
        executor.readiness._states[HOST].last_ssh = time.monotonic()
        executor.readiness._states[HOST].safety_confirmed = True
        command = ExecuteCommandRequest(
            server=HOST, argv=["/usr/bin/id", "-u"], privileged=True,
            reason="TEST-347 unauthorized root",
        )
        with (patch.object(executor, "authorized_host", return_value=host),
              patch.object(executor, "_run", new_callable=AsyncMock) as runner):
            with self.assertRaisesRegex(SSHDenied, "unlock unavailable"):
                await executor._execute_approved_privileged(ACTOR, command)
            token = root_access_context.set(access)
            try:
                with self.assertRaises(asyncio.CancelledError):
                    await executor._execute_approved_privileged(
                        ACTOR, command, on_admitted=lambda: False,
                    )
                runner.assert_not_awaited()
                executor.readiness.suspend(HOST)
                with self.assertRaisesRegex(SSHDenied, "authentication suspended"):
                    await executor._execute_approved_privileged(ACTOR, command)
                runner.assert_not_awaited()
            finally:
                root_access_context.reset(token)

    async def test_wrong_sudo_password_blocks_future_root_execution(self):
        _, access = await self.issue("5m")
        host = HostSpec(
            alias=HOST, address="synthetic.example.invalid", port=22,
            username="gateway", principals=[ACTOR], environment="non-production",
            identity_file=Path("/synthetic/id"),
            known_hosts_file=Path("/synthetic/known"), access="restricted",
            privileged_access="restricted",
        )
        executor = SSHExecutor(
            {HOST: host}, enabled=True, sealed_sudo={HOST: self.sealed},
            readiness_settings=ReadinessSettings(authorized=True),
        )
        executor.readiness._states[HOST].last_ssh = time.monotonic()
        executor.readiness._states[HOST].safety_confirmed = True
        command = ExecuteCommandRequest(
            server=HOST, argv=["/usr/bin/id", "-u"], privileged=True,
            reason="TEST-347 bad sudo password",
        )
        with (patch.object(executor, "authorized_host", return_value=host),
              patch.object(executor, "_run", new_callable=AsyncMock) as runner):
            runner.return_value = SSHResult(
                HOST, "command_error", 1, "", "", .01,
                failure_kind="sudo_authentication", password_rejected=True,
            )
            token = root_access_context.set(access)
            try:
                result = await executor._execute_approved_privileged(ACTOR, command)
                self.assertEqual(result.status, "command_error")
                self.assertTrue(executor.readiness.password_suspended(HOST))
                with self.assertRaises(SSHDenied):
                    await executor._execute_approved_privileged(ACTOR, command)
                self.assertEqual(runner.await_count, 1)
            finally:
                root_access_context.reset(token)

    async def test_root_grant_revoked_while_capacity_queued_never_starts_ssh(self):
        _, access = await self.issue("5m")
        host = HostSpec(
            alias=HOST, address="synthetic.example.invalid", port=22,
            username="gateway", principals=[ACTOR], environment="non-production",
            identity_file=Path("/synthetic/id"),
            known_hosts_file=Path("/synthetic/known"), access="restricted",
            privileged_access="restricted",
        )
        executor = SSHExecutor(
            {HOST: host}, enabled=True, sealed_sudo={HOST: self.sealed},
            readiness_settings=ReadinessSettings(authorized=True),
        )
        executor.readiness._states[HOST].last_ssh = time.monotonic()
        executor.readiness._states[HOST].safety_confirmed = True
        command = ExecuteCommandRequest(
            server=HOST, argv=["/usr/bin/id", "-u"],
            privileged=True, reason="TEST-347 queue revoke",
        )
        with (patch.object(executor, "authorized_host", return_value=host),
              patch.object(executor, "_run", new_callable=AsyncMock) as runner):
            await executor._semaphores[HOST].acquire()
            token = root_access_context.set(access)
            try:
                queued = asyncio.create_task(executor._execute_approved_privileged(
                    ACTOR, command,
                ))
            finally:
                root_access_context.reset(token)
            await asyncio.sleep(0.01)
            self.assertFalse(queued.done())
            self.assertTrue(self.manager.revoke(self.manager.grant_id(KEY, "root")))
            executor._semaphores[HOST].release()
            with self.assertRaises(SSHDenied):
                await queued
            runner.assert_not_awaited()

    async def test_batch_later_root_step_blocked_after_grant_revocation(self):
        _, access = await self.issue("5m")
        host = HostSpec(
            alias=HOST, address="synthetic.example.invalid", port=22,
            username="gateway", principals=[ACTOR], environment="non-production",
            identity_file=Path("/synthetic/id"),
            known_hosts_file=Path("/synthetic/known"), access="restricted",
            privileged_access="restricted",
        )
        executor = SSHExecutor(
            {HOST: host}, enabled=True, sealed_sudo={HOST: self.sealed},
            readiness_settings=ReadinessSettings(authorized=True),
        )
        executor.readiness._states[HOST].last_ssh = time.monotonic()
        executor.readiness._states[HOST].safety_confirmed = True
        with tempfile.TemporaryDirectory() as d:
            jobs = JobManager(executor, JobStore(Path(d) / "jobs.sqlite"))
            batches = BatchManager(jobs)
            request = ExecuteCommandsRequest.model_validate({
                "server": HOST, "reason": "TEST-347 batch step revocation",
                "privileged": True, "commands": [
                    {"argv": ["/usr/bin/id", "-u"]},
                    {"argv": ["/usr/bin/id", "-u"]},
                ],
            })

            async def first_only(_host, _request, _start, _on_output, **kwargs):
                self.assertTrue(kwargs["password_permitted"]())
                self.manager.revoke(self.manager.grant_id(KEY, "root"))
                return SSHResult(HOST, "succeeded", 0, "0", "", .01, root_started=True)

            with (patch.object(executor, "authorized_host", return_value=host),
                  patch.object(executor, "_run", side_effect=first_only) as runner):
                token = root_access_context.set(access)
                try:
                    result = await batches.execute(ACTOR, request, admitted_root=True)
                finally:
                    root_access_context.reset(token)
                self.assertEqual(runner.call_count, 1)
                self.assertNotEqual(result["status"], "succeeded")
                self.assertEqual(result["steps"][0]["status"], "succeeded")
                self.assertNotEqual(result["steps"][1]["status"], "succeeded")

    async def test_once_root_is_released_after_all_batch_steps_not_first_step(self):
        _, access = await self.issue("once", operation_timeout_seconds=900)
        host = HostSpec(
            alias=HOST, address="synthetic.example.invalid", port=22,
            username="gateway", principals=[ACTOR], environment="non-production",
            identity_file=Path("/synthetic/id"),
            known_hosts_file=Path("/synthetic/known"), access="restricted",
            privileged_access="restricted",
        )
        executor = SSHExecutor(
            {HOST: host}, enabled=True, sealed_sudo={HOST: self.sealed},
            readiness_settings=ReadinessSettings(authorized=True),
        )
        executor.readiness._states[HOST].last_ssh = time.monotonic()
        executor.readiness._states[HOST].safety_confirmed = True
        with tempfile.TemporaryDirectory() as d:
            jobs = JobManager(executor, JobStore(Path(d) / "jobs.sqlite"))
            batches = BatchManager(jobs)
            request = ExecuteCommandsRequest.model_validate({
                "server": HOST, "reason": "TEST-347 once batch lifetime",
                "privileged": True, "timeout_seconds": 900,
                "commands": [
                    {"argv": ["/usr/bin/id", "-u"]},
                    {"argv": ["/usr/bin/id", "-u"]},
                ],
            })
            dispatched = []

            async def completed(_host, _request, _start, _on_output, **kwargs):
                self.assertTrue(kwargs["password_permitted"]())
                self.assertTrue(access.valid(host=HOST, actor=ACTOR))
                dispatched.append(True)
                return SSHResult(HOST, "succeeded", 0, "0", "", .01, root_started=True)

            with (patch.object(executor, "authorized_host", return_value=host),
                  patch.object(executor, "_run", side_effect=completed)):
                token = root_access_context.set(access)
                try:
                    response = await batches.execute(ACTOR, request, admitted_root=True)
                finally:
                    root_access_context.reset(token)
            self.assertEqual(response["status"], "succeeded")
            self.assertEqual(len(dispatched), 2)
            self.assertTrue(access.operation.delegated)
            self.assertTrue(access.operation.finished)
            self.assertFalse(access.valid(host=HOST, actor=ACTOR))
            self.assertNotIn(access.scope.issuance, self.manager._once_root_access)

    async def test_once_root_async_job_releases_only_when_job_finishes(self):
        _, access = await self.issue("once", operation_timeout_seconds=720)
        host = HostSpec(
            alias=HOST, address="synthetic.example.invalid", port=22,
            username="gateway", principals=[ACTOR], environment="non-production",
            identity_file=Path("/synthetic/id"),
            known_hosts_file=Path("/synthetic/known"), access="restricted",
            privileged_access="restricted",
        )
        executor = SSHExecutor(
            {HOST: host}, enabled=True, sealed_sudo={HOST: self.sealed},
            readiness_settings=ReadinessSettings(authorized=True),
        )
        executor.readiness._states[HOST].last_ssh = time.monotonic()
        executor.readiness._states[HOST].safety_confirmed = True
        with tempfile.TemporaryDirectory() as d:
            jobs = JobManager(executor, JobStore(Path(d) / "jobs.sqlite"))
            command = ExecuteCommandRequest(
                server=HOST, argv=["/usr/bin/id", "-u"],
                privileged=True, timeout_seconds=720,
                reason="TEST-347 background once release",
            )
            started = asyncio.Event()
            release = asyncio.Event()

            async def completed(_host, _request, _start, _on_output, **kwargs):
                started.set()
                await release.wait()
                self.assertTrue(kwargs["password_permitted"]())
                return SSHResult(HOST, "succeeded", 0, "0", "", .01, root_started=True)

            with (patch.object(executor, "authorized_host", return_value=host),
                  patch.object(executor, "_run", side_effect=completed)):
                token = root_access_context.set(access)
                try:
                    row = jobs.submit(ACTOR, command, admitted_root=True)
                finally:
                    root_access_context.reset(token)
                self.assertTrue(access.operation.delegated)
                await asyncio.wait_for(started.wait(), timeout=2)
                self.assertFalse(access.operation.finished)
                self.assertTrue(access.valid(host=HOST, actor=ACTOR))
                release.set()
                for _ in range(100):
                    if access.operation.finished:
                        break
                    await asyncio.sleep(.01)
                self.assertEqual(jobs.store.get(ACTOR, row["id"])["status"], "succeeded")
                self.assertTrue(access.operation.finished)
                self.assertFalse(access.valid(host=HOST, actor=ACTOR))


    async def test_closed_manager_disallows_new_root_issuance_and_context_reuse(self):
        _, access = await self.issue("5m")
        self.manager.shutdown()
        self.assertFalse(access.valid(host=HOST, actor=ACTOR))
        self.assertIsNone(self.manager.root_request("missing-request"))
        with self.assertRaises(SSHDenied):
            await self.manager.require(
                KEY, tool="execute_command", reason="Closed manager",
                summary="Synthetic", root_required=True,
                client_id=CLIENT, actor=ACTOR,
            )

    async def test_timed_root_handle_rejects_other_verified_client_actor(self):
        _, granted = await self.issue("5m")
        with self.assertRaisesRegex(SSHDenied, "actor mismatch"):
            await self.manager.require(
                KEY, tool="execute_command", reason="Wrong OAuth client",
                summary="Synthetic", host_required=False, root_required=True,
                client_id="another-oauth-client", actor=ACTOR,
            )
        with self.assertRaisesRegex(SSHDenied, "actor mismatch"):
            await self.manager.require(
                KEY, tool="execute_command", reason="Wrong OAuth actor",
                summary="Synthetic", host_required=False, root_required=True,
                client_id=CLIENT, actor="different-actor",
            )
        self.assertTrue(granted.valid(host=HOST, actor=ACTOR))

    async def test_client_scope_mismatch_preserves_original_pending(self):
        task, pending = await self.pending()
        wrong = self.prepare(pending)
        wrong.scope = UnlockScope(
            pending.key, actor=ACTOR, client_id="another-client-id",
            issuance=pending.id, operation_id=pending.id,
            generation="synthetic-generation",
        )
        self.assertFalse(self.manager.decide_unlocked(
            pending.id, duration="once", prepared=wrong,
            still_authorized=lambda: True,
        ))
        self.assertIsNone(wrong.password)
        self.assertIn(pending.id, self.manager.pending)
        self.assertFalse(self.manager.root_grants)
        correct = self.prepare(pending)
        self.assertTrue(self.manager.decide_unlocked(
            pending.id, duration="once", prepared=correct,
            still_authorized=lambda: True,
        ))
        self.assertEqual((await task)[0], ApprovalCode.APPROVED_EXPLICIT)

    async def test_failed_final_decision_rolls_back_once_and_timed_unseal(self):
        for duration in ("once", "5m"):
            with self.subTest(duration=duration):
                task, pending = await self.pending()
                prepared = self.prepare(pending, duration=duration)
                with patch.object(self.manager, "decide", return_value=False):
                    self.assertFalse(self.manager.decide_unlocked(
                        pending.id, duration=duration, prepared=prepared,
                        still_authorized=lambda: True,
                    ))
                self.assertIsNone(prepared.password)
                self.assertEqual(self.manager.root_unlocks._entries, {})
                self.assertNotIn(pending.id, self.manager._once_root_access)
                self.assertNotIn(KEY, self.manager._timed_root_access)
                self.assertFalse(self.manager.root_grants)
                self.assertTrue(self.manager.decide(pending.id, grant=False))
                with self.assertRaises(Exception):
                    await task


class ConsoleRootPromptThrottleTests(unittest.TestCase):
    def test_login_and_root_prompt_share_attempt_budget(self):
        with tempfile.TemporaryDirectory() as d:
            store = JobStore(Path(d) / "history.sqlite")
            auth = ViewerAuth(
                store, "", verifier=create_verifier(CONSOLE, "console-login"),
                generation="d" * 32,
            )
            self.assertEqual(auth.verify_root_prompt("client-a", "invalid"), "incorrect")
            self.assertIsNone(auth.login("client-a", "invalid"))
            self.assertEqual(auth.verify_root_prompt("client-a", "invalid"), "incorrect")
            self.assertIsNone(auth.login("client-a", "invalid"))
            self.assertEqual(auth.verify_root_prompt("client-a", "invalid"), "incorrect")
            self.assertEqual(auth.verify_root_prompt("client-a", CONSOLE), "throttled")
            self.assertIsNone(auth.login("client-a", CONSOLE))
            self.assertEqual(auth.verify_root_prompt("client-b", CONSOLE), "ok")
            self.assertTrue(auth.login("client-b", CONSOLE))

    def test_legacy_console_has_no_sealed_root_verifier(self):
        with tempfile.TemporaryDirectory() as d:
            auth = ViewerAuth(
                JobStore(Path(d) / "history.sqlite"),
                "synthetic-legacy-console-password",
            )
            self.assertEqual(
                auth.verify_root_prompt("client-a", "synthetic-legacy-console-password"),
                "unavailable",
            )


if __name__ == "__main__":
    unittest.main()
