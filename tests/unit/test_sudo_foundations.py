"""TEST-267: privilege contracts, mandatory durable auditing and root admission."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch

from pydantic import ValidationError

from app.batch import BatchManager, BatchStore
from app.approvals import ApprovalManager
from app.contracts import ExecuteCommandRequest, ExecuteCommandsRequest
from app.history import HistoryStore
from app.jobs import JobManager, JobStore
from app.ssh_executor import HostSpec, SSHDenied, SSHExecutor, SSHResult


def command(privileged: bool = False) -> ExecuteCommandRequest:
    return ExecuteCommandRequest(
        server="demo-node-b", argv=["bash", "-lc", "id -un\nid -u"],
        reason="TEST-267 synthetic privilege contract", privileged=privileged,
    )


def batch(privileged: bool = False) -> ExecuteCommandsRequest:
    return ExecuteCommandsRequest(
        server="demo-node-b", reason="TEST-267 synthetic privilege batch",
        privileged=privileged,
        commands=[{"argv": ["id", "-un"]}, {"argv": ["id", "-u"]}],
    )


class PrivilegeContracts(unittest.TestCase):
    def test_flag_is_optional_strict_and_batch_wide(self):
        self.assertIs(command().privileged, False)
        self.assertIs(batch().privileged, False)
        self.assertIs(command(True).privileged, True)
        requested = batch(True)
        self.assertTrue(all(requested.step_command(i).privileged for i in range(2)))
        self.assertNotIn("privileged", type(requested.commands[0]).model_fields)
        for bad in (1, "true", None, [], {}):
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                ExecuteCommandRequest.model_validate({
                    **command().model_dump(), "privileged": bad,
                })
            with self.subTest(batch=bad), self.assertRaises(ValidationError):
                ExecuteCommandsRequest.model_validate({
                    **batch().model_dump(), "privileged": bad,
                })

    def test_signed_host_privilege_policy_defaults_to_none(self):
        data = {
            "alias": "demo-node-b", "address": "192.0.2.22", "port": 22,
            "username": "gateway", "principals": ["ssh-mcp-operator"],
            "environment": "non-production", "access": "restricted",
            "identity_file": Path("/tmp/synthetic-identity"),
            "known_hosts_file": Path("/tmp/synthetic-pins"),
        }
        self.assertEqual(HostSpec.model_validate(data).privileged_access, "none")
        for policy in ("none", "restricted", "always-granted"):
            self.assertEqual(HostSpec.model_validate({
                **data, "privileged_access": policy,
            }).privileged_access, policy)
        for policy in ("sudo", "always", True, None):
            with self.subTest(policy=policy), self.assertRaises(ValidationError):
                HostSpec.model_validate({**data, "privileged_access": policy})


class DurablePrivilegeAudit(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "private" / "jobs.sqlite"
        self.store = JobStore(self.path)

    def test_job_and_batch_metadata_survive_restart_and_history(self):
        privileged = command(True)
        job_id = self.store.create("alice", privileged, mode="sync")
        regular_id = self.store.create(
            "alice", command(), mode="sync", username="gateway",
        )
        self.assertTrue(self.store.begin(job_id))
        self.store.finish(job_id, "transport_error", exit_code=255)
        batches = BatchStore(self.store)
        batch_id = batches.create("alice", batch(True))

        reopened = JobStore(self.path)
        root = reopened.get("alice", job_id)
        self.assertIs(root["privileged"], True)
        self.assertEqual(root["run_as"], "root")
        self.assertIsNone(root["root_started"])  # Marker belongs to PR2.
        self.assertIs(reopened.get("alice", regular_id)["privileged"], False)
        history = HistoryStore(reopened)
        root_history = history.detail(job_id)
        self.assertIs(root_history["privileged"], True)
        self.assertEqual(root_history["run_as"], "root")
        self.assertEqual(root_history["request"]["argv"], privileged.argv)
        self.assertNotIn("sudo -S", json.dumps(root_history))
        self.assertEqual(HistoryStore(reopened).list({
            "record_kind": "command",
        })["jobs"][0]["run_as"], "gateway")

        restored_batch = BatchStore(reopened)
        summary = restored_batch.get("alice", batch_id)
        self.assertIs(summary["privileged"], True)
        self.assertEqual(summary["run_as"], "root")
        self.assertEqual(summary["status"], "interrupted")
        self.assertIs(restored_batch.list("alice")["batches"][0]["privileged"], True)

    def test_signed_nondefault_username_survives_restart_and_root_requested(self):
        from app.history import HistoryStore

        ordinary_id = self.store.create(
            "alice", command(), mode="sync", username="mcp-agent",
            pending_approval=True,
        )
        root_id = self.store.create(
            "alice", command(True), username="mcp-agent",
            pending_approval=True,
        )
        batches = BatchStore(self.store)
        ordinary_batch = batches.create(
            "alice", batch(), username="mcp-agent", pending_approval=True,
        )
        elevated_batch = batches.create(
            "alice", batch(True), username="mcp-agent", pending_approval=True,
        )
        reopened = JobStore(self.path)
        self.assertEqual(reopened.get("alice", ordinary_id)["run_as"], "mcp-agent")
        self.assertEqual(reopened.get("alice", root_id)["run_as"], "root")
        history = HistoryStore(reopened)
        self.assertEqual(history.detail(ordinary_id)["run_as"], "mcp-agent")
        self.assertEqual(history.detail(root_id)["run_as"], "root")
        restored = BatchStore(reopened)
        self.assertEqual(restored.get("alice", ordinary_batch)["run_as"], "mcp-agent")
        self.assertEqual(restored.list("alice")["batches"][1]["run_as"], "mcp-agent")
        self.assertEqual(restored.get("alice", elevated_batch)["run_as"], "root")
        # All are pending before the restart, so the batch parent appears in
        # unified history after recovery even without a child command.
        self.assertEqual(history.detail("batch_" + ordinary_batch)["run_as"],
                         "mcp-agent")
        self.assertEqual(history.detail("batch_" + elevated_batch)["run_as"], "root")

    def test_recent_ssh_username_migration_preserves_job_and_batch_rows(self):
        original = self.store.create("alice", command())
        batches = BatchStore(self.store)
        original_batch = batches.create("alice", batch())
        with self.store._connect() as db:
            db.execute("DROP VIEW IF EXISTS history_events")
            db.execute("ALTER TABLE jobs DROP COLUMN ssh_username")
            db.execute("ALTER TABLE command_batches DROP COLUMN ssh_username")
        upgraded = JobStore(self.path)
        self.assertIs(upgraded.get("alice", original)["privileged"], False)
        self.assertIsNone(HistoryStore(upgraded).detail(original)["run_as"])
        legacy_batch = BatchStore(upgraded).get("alice", original_batch)
        self.assertIs(legacy_batch["privileged"], False)
        self.assertIsNone(legacy_batch["run_as"])

    def test_unadmitted_root_does_not_submit_jobs_or_batches(self):
        class FakeExecutor:
            def __init__(self):
                self.execute = AsyncMock()
            def list_servers(self, actor):
                return ["demo-node-b"]
            def authorized_host(self, actor, server):
                return self

        executor = FakeExecutor()
        jobs = JobManager(executor, self.store)
        batches = BatchManager(jobs)
        with self.assertRaises(SSHDenied):
            jobs.submit("alice", command(True))
        with self.assertRaises(SSHDenied):
            asyncio.run(jobs.execute_sync("alice", command(True)))
        with self.assertRaises(SSHDenied):
            asyncio.run(batches.execute("alice", batch(True)))
        executor.execute.assert_not_called()
        self.assertEqual(self.store.list("alice"), [])
        self.assertEqual(batches.list("alice")["batches"], [])

    def test_admitted_queued_root_job_survives_later_grant_revocation(self):
        class FakeExecutor:
            def __init__(self):
                async def root_result(_actor, _request, *, on_output=None,
                                      on_admitted=None):
                    if on_admitted is not None:
                        on_admitted()
                    return SSHResult(
                        "demo-node-b", "succeeded", 0, "synthetic-root", "", .01,
                        root_started=True,
                    )
                self._execute_approved_privileged = AsyncMock(side_effect=root_result)

            def list_servers(self, actor):
                return ["demo-node-b"]

        async def exercise():
            approval = ApprovalManager()
            key = ("synthetic-oauth", "synthetic-conversation", "demo-node-b")
            approval.grants[key] = time.monotonic() + 300
            approval.root_grants[key] = time.monotonic() + 300
            executor = FakeExecutor()
            jobs = JobManager(executor, self.store)
            queued = jobs.submit("alice", command(True), admitted_root=True)
            # No event-loop yield between queueing and revocation.
            self.assertTrue(approval.revoke(approval.grant_id(key)))
            self.assertFalse(approval.grants)
            self.assertFalse(approval.root_grants)
            await asyncio.sleep(.05)
            completed = jobs.get("alice", queued["id"])
            self.assertEqual(completed["status"], "succeeded")
            self.assertTrue(completed["root_started"])
            self.assertTrue(completed["privileged"])
            executor._execute_approved_privileged.assert_awaited_once()
            approval.shutdown()

        asyncio.run(exercise())

    def test_audit_failure_never_reaches_ssh(self):
        class FakeExecutor:
            def __init__(self):
                self.execute = AsyncMock()
            def list_servers(self, actor):
                return ["demo-node-b"]
            def authorized_host(self, actor, server):
                return self

        executor = FakeExecutor()
        jobs = JobManager(executor, self.store)
        batches = BatchManager(jobs)
        with patch.object(self.store, "create", side_effect=sqlite3.OperationalError("synthetic")):
            with self.assertRaises(sqlite3.DatabaseError):
                jobs.submit("alice", command())
            with self.assertRaises(sqlite3.DatabaseError):
                asyncio.run(jobs.execute_sync("alice", command()))
        with patch.object(batches.store, "create", side_effect=sqlite3.OperationalError("synthetic")):
            with self.assertRaises(sqlite3.DatabaseError):
                asyncio.run(batches.execute("alice", batch()))
        executor.execute.assert_not_called()
        self.assertEqual(self.store.list("alice"), [])

    def test_executor_prevents_root_dispatch_before_sudo_is_available(self):
        remote = SSHExecutor({}, enabled=True)
        with self.assertRaises(SSHDenied):
            asyncio.run(remote.execute("alice", command(True)))
        with self.assertRaises(SSHDenied):
            asyncio.run(remote.preflight_cwd("alice", command(True)))


if __name__ == "__main__":
    unittest.main()
