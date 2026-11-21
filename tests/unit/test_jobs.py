"""TEST-208 durable job storage, authorization, recovery and cancellation tests."""
from __future__ import annotations

import asyncio
import json
import sqlite3
import base64
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from app.contracts import ExecuteCommandRequest, ExecuteCommandsRequest
from app.batch import BatchManager
from app.jobs import JobManager, JobStore
from app.ssh_executor import HostSpec, SSHDenied, SSHExecutor, SSHResult


class FakeExecutor:
    def __init__(self):
        self.events = []
        self.running = asyncio.Event()
        self.release = asyncio.Event()
        self.cancelled = False

    def list_servers(self, actor):
        return ["demo-node-b"] if actor == "alice" else []

    async def execute(self, actor, request, *, on_output=None, on_admitted=None):
        if on_admitted is not None:
            on_admitted()
        self.events.append((actor, request.argv))
        if request.argv[0] == "timeout":
            return SSHResult(request.server, "timed_out", None, "", "", 1.0)
        if request.argv[0] == "transport":
            return SSHResult(request.server, "transport_error", 255, "", "connect failed", .1)
        if request.argv[0] == "limit":
            return SSHResult(request.server, "output_limit", None, "", "", .1)
        if request.argv[0] == "error":
            return SSHResult(request.server, "command_error", 7, "", "error", .1)
        if request.argv[0] == "native-cwd-failure":
            return SSHResult(request.server, "command_error", 255, "",
                             "Remote cwd changed before execution", .1,
                             exit_accepted=False, failure_kind="cwd_preflight")
        if request.argv[0] == "native-signal":
            return SSHResult(request.server, "command_error", None, "", "", .1,
                             exit_accepted=False, failure_kind="remote_signal")
        if request.argv[0] == "accepted":
            return SSHResult(request.server, "succeeded", 1, "", "", .1,
                             exit_accepted=True, effective_cwd="/home/example/synthetic")
        if request.argv[0] == "denied":
            raise SSHDenied("private path")
        if request.argv[0] == "crash":
            raise RuntimeError("private credential")
        if on_output is not None:
            await on_output("stdout", b"abc")
            await on_output("stderr", b"err")
        self.running.set()
        if request.argv[0] == "hold":
            try:
                await self.release.wait()
            except asyncio.CancelledError:
                self.cancelled = True
                raise
        return SSHResult(request.server, "succeeded", 0, "abc", "err", .2)


def request(*argv):
    return ExecuteCommandRequest(
        server="demo-node-b", argv=list(argv), timeout_seconds=3,
        reason="TEST-208 synthetic test",
    )


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "private" / "jobs.sqlite"
        self.store = JobStore(self.path)

    def test_native_command_failure_kinds_require_failed_terminal_status(self):
        job_id = self.store.create("alice", request("echo"))
        self.assertTrue(self.store.begin(job_id))
        for kind in ("cwd_preflight", "remote_signal"):
            with self.subTest(failure_kind=kind), self.assertRaisesRegex(
                ValueError, "requires failed status",
            ):
                self.store.finish(job_id, "succeeded", failure_kind=kind)
        self.store.finish(job_id, "failed", failure_kind="remote_signal")
        self.assertEqual(self.store.get("alice", job_id)["failure_kind"], "remote_signal")

    def test_accepted_nonzero_cwd_persists_in_job_and_unified_history(self):
        from app.history import HistoryStore
        specified = ExecuteCommandRequest(
            server="demo-node-b", argv=["sh", "-c", "exit 1"],
            reason="TEST-247 audit preservation", story_id="TEST-247",
            cwd="/home/example/link", success_exit_codes=[0, 1],
        )
        job_id = self.store.create("alice", specified, mode="sync")
        self.assertTrue(self.store.begin(job_id))
        self.store.finish(job_id, "succeeded", exit_code=1, elapsed=.1,
                          exit_accepted=True, effective_cwd="/home/example/repo")
        reopened = JobStore(self.path)
        saved = reopened.get("alice", job_id)
        self.assertEqual(saved["status"], "succeeded")
        self.assertEqual(saved["exit_code"], 1)
        self.assertIs(saved["exit_accepted"], True)
        self.assertEqual(saved["effective_cwd"], "/home/example/repo")
        detail = HistoryStore(reopened).detail(job_id)
        self.assertEqual(detail["exit_code"], 1)
        self.assertIs(detail["exit_accepted"], True)
        self.assertEqual(detail["effective_cwd"], "/home/example/repo")
        self.assertEqual(detail["request"]["cwd"], "/home/example/link")
        self.assertEqual(detail["request"]["success_exit_codes"], [0, 1])
        listing = HistoryStore(reopened).list({"record_kind": "command"}, limit=10)
        self.assertIs(listing["jobs"][0]["exit_accepted"], True)

    def test_recent_client_id_schema_migration_keeps_history(self):
        from app.history import HistoryStore
        job_id = self.store.create("alice", request("id"))
        self.store.begin(job_id)
        self.store.finish(job_id, "succeeded", exit_code=0)
        with self.store._connect() as db:
            db.execute("DROP VIEW IF EXISTS history_events")
            db.execute("ALTER TABLE jobs DROP COLUMN client_id")
        upgraded = JobStore(self.path)
        saved = upgraded.get("alice", job_id)
        self.assertEqual(saved["exit_code"], 0)
        self.assertIsNone(saved["exit_accepted"])
        self.assertIsNone(saved["effective_cwd"])
        self.assertEqual(HistoryStore(upgraded).detail(job_id)["status"], "succeeded")
        self.assertIsNone(HistoryStore(upgraded).detail(job_id)["client_id"])

    def test_recent_file_client_id_migration_and_denial_validation(self):
        from app.file_audit import FileAudit
        from app.history import HistoryStore

        # Simulate an existing SQLite file from before the recent client-ID
        # addition without dropping the older, now-baseline audit columns.
        with self.store._connect() as db:
            db.execute("DROP VIEW IF EXISTS history_events")
            db.execute("ALTER TABLE file_operations DROP COLUMN client_id")
        reopened = JobStore(self.path)
        with reopened._connect() as db:
            fields = {row["name"] for row in
                      db.execute("PRAGMA table_info(file_operations)")}
        self.assertIn("conversation_id", fields)
        self.assertIn("approval_status", fields)
        self.assertIn("operation_id", fields)
        self.assertIn("client_id", fields)
        self.assertEqual(HistoryStore(reopened).list({}, limit=10)["filtered_total"], 0)

        audit = FileAudit(reopened)
        with self.assertRaisesRegex(ValueError, "Unsupported file operation"):
            audit.reserve("alice", "demo-node-b", "bogus", "/tmp/test", "TEST-276")
        ignored_id = audit.reserve("alice", "demo-node-b", "read",
                                   "/tmp/test", "TEST-276")
        audit.settle_approval(ignored_id, 5, denied=True)
        history_id = audit.reserve("alice", "demo-node-b", "read",
                                   "/tmp/synthetic", "TEST-276")
        audit.settle_approval(history_id, 8, denied=True)
        self.assertNotEqual(ignored_id, history_id)
        self.assertNotEqual(ignored_id, "operator-provided")
        self.assertNotEqual(history_id, "operator-provided")
        item = HistoryStore(reopened).detail("file_" + history_id)
        self.assertEqual(item["status"], "denied")
        self.assertEqual(item["approval_status"], "denied_revoked")
        self.assertIsNone(item["exit_code"])
        self.assertEqual(item["output_bytes"], 0)

    def test_approval_wait_restart_is_not_recorded_as_remote_execution(self):
        from app.file_audit import FileAudit
        from app.history import HistoryStore

        pending_job = self.store.create("alice", request("hostname"),
                                        mode="sync", pending_approval=True)
        pending_file = FileAudit(self.store).reserve(
            "alice", "demo-node-b", "read", "/tmp/pending", "TEST-276",
        )
        before = HistoryStore(self.store).detail(pending_job)
        self.assertEqual(before["status"], "awaiting_approval")
        self.assertIsNone(before["started_at"])
        self.assertIsNone(before["approval_status"])

        reopened = JobStore(self.path)
        command = reopened.get("alice", pending_job)
        file_row = HistoryStore(reopened).detail("file_" + pending_file)
        self.assertEqual(command["status"], "failed")
        self.assertIs(command["root_started"], False)
        self.assertIsNone(command["started_at"])
        self.assertIsNone(command["approval_status"])
        self.assertIn("before SSH", command["error"])
        self.assertEqual(file_row["status"], "failed")
        self.assertIsNone(file_row["started_at"])
        self.assertIsNone(file_row["approval_status"])
        self.assertEqual(file_row["error_code"], "authorization")

    def test_downgraded_file_writer_cannot_reuse_new_replay_key(self):
        """Simulate previous image's INSERT after rollback with jobs.sqlite kept."""
        import sqlite3
        from app.file_audit import FileAudit
        from app.approval_status import ApprovalCode

        audit = FileAudit(self.store)
        reserved = audit.reserve(
            "alice", "demo-node-b", "write", "/tmp/rollback", "TEST-276",
        )
        audit.settle_approval(reserved, int(ApprovalCode.APPROVED_CONFIG))
        audit.start(
            "alice", "demo-node-b", "write", "/tmp/rollback", "TEST-276",
            "original-replay-2026", precreated_id=reserved,
        )
        audit.finish(reserved, "succeeded")
        # Reopen the retained DB as on a service-image downgrade.
        JobStore(self.path)
        with self.store._connect() as db:
            with self.assertRaisesRegex(sqlite3.IntegrityError,
                                        "duplicate_operation"):
                db.execute(
                    """INSERT INTO file_operations
                       (id,actor,server,operation_kind,path_summary,story_id,
                        status,created_at,updated_at,started_at)
                       VALUES(?,?,?,?,?,?,'running',?,?,?)""",
                    ("original-replay-2026", "alice", "demo-node-b",
                     "write", "rollback", "TEST-276", 100.0, 100.0, 100.0),
                )
            rows = db.execute(
                """SELECT id,operation_id,status FROM file_operations
                   WHERE id=? OR operation_id=?""",
                ("original-replay-2026", "original-replay-2026"),
            ).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], reserved)
        self.assertEqual(rows[0]["status"], "succeeded")
        self.assertEqual(rows[0]["operation_id"], "original-replay-2026")

    def test_preapproval_replay_key_conflicts_with_legacy_file_id(self):
        from app.file_audit import FileAudit
        from app.approval_status import ApprovalCode
        from app.history import HistoryStore

        audit = FileAudit(self.store)
        legacy_id = audit.start("alice", "demo-node-b", "write",
                                "/tmp/old", "TEST-276", "stable-legacy-ID")
        audit.finish(legacy_id, "succeeded")
        reserved = audit.reserve("alice", "demo-node-b", "write",
                                 "/tmp/new", "TEST-276")
        audit.settle_approval(reserved, int(ApprovalCode.APPROVED_CONFIG))
        with self.assertRaisesRegex(ValueError, "duplicate_operation"):
            audit.start("alice", "demo-node-b", "write", "/tmp/new",
                        "TEST-276", "stable-legacy-ID",
                        precreated_id=reserved)
        record = HistoryStore(self.store).detail("file_" + reserved)
        self.assertEqual(record["status"], "failed")
        self.assertIsNone(record["started_at"])
        self.assertEqual(audit.get("alice", legacy_id)["status"], "succeeded")

        accepted = audit.reserve("alice", "demo-node-b", "read",
                                 "/tmp/newer", "TEST-276")
        audit.settle_approval(accepted, int(ApprovalCode.APPROVED_EXPLICIT))
        audit.start("alice", "demo-node-b", "read", "/tmp/newer",
                    "TEST-276", "newer-replay-ID", precreated_id=accepted)
        with self.assertRaisesRegex(ValueError, "duplicate_operation"):
            audit.start("alice", "demo-node-b", "read",
                        "/tmp/newer", "TEST-276", "newer-replay-ID")
        self.assertEqual(audit.get("alice", "newer-replay-ID")["id"], accepted)
        self.assertEqual(audit.replay_history_id("alice", "newer-replay-ID"),
                         "file_" + accepted)
        self.assertIsNone(audit.replay_history_id("bob", "newer-replay-ID"))
        self.assertIsNone(audit.replay_history_id("bob", accepted))
        self.assertEqual(audit.replay_history_id("alice", "stable-legacy-ID"),
                         "file_" + legacy_id)

    def test_preapproval_record_keeps_original_time_and_reuses_file_id(self):
        from app.file_audit import FileAudit
        from app.history import HistoryStore
        from app.approval_status import ApprovalCode

        audit = FileAudit(self.store)
        reservation = audit.reserve("alice", "demo-node-b", "write",
                                    "/tmp/test", "TEST-276")
        before = HistoryStore(self.store).detail("file_" + reservation)
        self.assertEqual(before["status"], "awaiting_approval")
        self.assertIsNone(before["started_at"])
        self.assertIsNone(before["approval_status"])
        audit.settle_approval(reservation, int(ApprovalCode.APPROVED_EXPLICIT))
        operation_id = audit.start("alice", "demo-node-b", "write", "/tmp/test",
                                   "TEST-276", "caller-replay-ID",
                                   precreated_id=reservation)
        self.assertEqual(operation_id, reservation)
        self.assertTrue(audit.operation_id_exists("caller-replay-ID"))
        self.assertEqual(audit.get("alice", "caller-replay-ID")["id"], reservation)
        audit.finish(operation_id, "succeeded")
        final = HistoryStore(self.store).detail("file_" + reservation)
        self.assertEqual(final["status"], "succeeded")
        self.assertEqual(final["approval_status"], "approved_explicit")
        self.assertEqual(final["created_at"], before["created_at"])
        self.assertIsNotNone(final["started_at"])
        self.assertEqual(final["id"], before["id"])

        for _ in range(2):
            denied = audit.reserve("alice", "demo-node-b", "read",
                                   "/tmp/denied", "TEST-276")
            audit.settle_approval(denied, int(ApprovalCode.DENIED_EXPLICIT),
                                  denied=True)
            row = HistoryStore(self.store).detail("file_" + denied)
            self.assertEqual(row["status"], "denied")
            self.assertIsNone(row["started_at"])
            self.assertIsNone(row["root_started"])
            self.assertEqual(row["approval_status"], "denied_explicit")

        duplicate = audit.reserve("alice", "demo-node-b", "write",
                                  "/tmp/duplicate", "TEST-276")
        audit.settle_approval(duplicate, int(ApprovalCode.APPROVED_TIMED))
        with self.assertRaisesRegex(ValueError, "duplicate_operation"):
            audit.start("alice", "demo-node-b", "write", "/tmp/duplicate",
                        "TEST-276", "caller-replay-ID", precreated_id=duplicate)
        self.assertEqual(HistoryStore(self.store).detail("file_" + duplicate)
                         ["status"], "failed")

    def test_preapproval_job_and_file_error_paths_fail_closed(self):
        from app.approval_status import ApprovalCode
        from app.file_audit import FileAudit
        from app.history import HistoryStore

        requested = request("id", "-u")
        waiting = self.store.create("alice", requested, pending_approval=True)
        with self.assertRaisesRegex(ValueError, "approval code"):
            self.store.settle_approval(waiting, None)
        self.store.settle_approval(waiting, int(ApprovalCode.APPROVED_CONFIG))
        self.assertEqual(self.store.get("alice", waiting)["approval_status"],
                         "approved_config")
        with self.assertRaisesRegex(RuntimeError, "cannot be finalized"):
            self.store.settle_approval(waiting, int(ApprovalCode.DENIED_EXPLICIT),
                                       denied=True)

        unknown = self.store.create("alice", requested, pending_approval=True)
        self.store.settle_approval(unknown, None, denied=True)
        failed = self.store.get("alice", unknown)
        self.assertEqual(failed["status"], "failed")
        self.assertIsNone(failed["approval_status"])
        self.assertIsNone(failed["started_at"])
        self.assertIs(failed["root_started"], False)

        audit = FileAudit(self.store)
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            audit.reserve("alice", "demo-node-b", "bogus", "/tmp/a", "TEST-276")
        self.assertFalse(audit.operation_id_exists("free-operation-id"))
        pending = audit.reserve("alice", "demo-node-b", "write",
                                "/tmp/blocked", "TEST-276")
        with self.assertRaisesRegex(ValueError, "approval code"):
            audit.settle_approval(pending, None)
        audit.settle_approval(pending, None, denied=True)
        row = HistoryStore(self.store).detail("file_" + pending)
        self.assertEqual(row["status"], "failed")
        self.assertIsNone(row["approval_status"])
        self.assertIsNone(row["started_at"])
        with self.assertRaisesRegex(RuntimeError, "cannot be finalized"):
            audit.settle_approval(pending, int(ApprovalCode.DENIED_CONFIG),
                                  denied=True)

        denied = audit.reserve("alice", "demo-node-b", "read",
                               "/tmp/denied", "TEST-276")
        audit.settle_approval(denied, int(ApprovalCode.DENIED_CONFIG),
                              denied=True)
        self.assertEqual(HistoryStore(self.store).detail("file_" + denied)
                         ["approval_status"], "denied_config")

        admitted = audit.reserve("alice", "demo-node-b", "read",
                                 "/tmp/accepted", "TEST-276")
        audit.settle_approval(admitted, int(ApprovalCode.APPROVED_CONFIG))
        operation_id = audit.start("alice", "demo-node-b", "read",
                                   "/tmp/accepted", "TEST-276",
                                   "free-operation-id", precreated_id=admitted)
        self.assertEqual(operation_id, admitted)
        self.assertTrue(audit.operation_id_exists("free-operation-id"))
        audit.finish(operation_id, "succeeded")

    def test_durable_metrics_are_idempotent_across_reopen_and_pruning(self):
        job_id = self.store.create("alice", request("echo", "secret-value"))
        self.assertTrue(self.store.begin(job_id))
        with self.assertLogs("app.jobs", level="INFO") as recorded:
            self.store.finish(
                job_id, "transport_error", exit_code=255, elapsed=10.5,
                failure_kind="ssh_banner_timeout",
            )
        self.assertIn('"failure_kind": "ssh_banner_timeout"', recorded.output[0])
        self.assertNotIn("secret-value", recorded.output[0])
        self.assertNotIn(job_id, recorded.output[0])
        # A repeated finish must not double-count, regardless of status.
        self.store.finish(job_id, "transport_error", elapsed=10.5,
                          failure_kind="ssh_banner_timeout")
        with self.store._connect() as db:
            self.assertEqual(db.execute(
                "SELECT total FROM telemetry_outcomes WHERE server=? AND status=?",
                ("demo-node-b", "transport_error"),
            ).fetchone()["total"], 1)
            self.assertEqual(db.execute(
                "SELECT total,sum_seconds FROM telemetry_duration"
            ).fetchone()["total"], 1)
            self.assertEqual(db.execute(
                "SELECT total FROM telemetry_duration_buckets WHERE le='20.0'"
            ).fetchone(), None)  # canonical bucket labels are 20, not 20.0
            self.assertEqual(db.execute(
                "SELECT total FROM telemetry_duration_buckets WHERE le='20'"
            ).fetchone()["total"], 1)
        with self.store._connect() as db:
            db.execute("UPDATE jobs SET ended_at=1 WHERE id=?", (job_id,))
        reopened = JobStore(self.path, retention_seconds=3600)
        self.assertIsNone(reopened.get("alice", job_id))
        with reopened._connect() as db:
            self.assertEqual(db.execute(
                "SELECT total FROM telemetry_outcomes"
            ).fetchone()["total"], 1)
            self.assertEqual(db.execute(
                "SELECT total FROM telemetry_duration"
            ).fetchone()["total"], 1)

    def test_recovery_counts_interrupt_once_and_rejects_bad_kind(self):
        job_id = self.store.create("alice", request("sleep", "secret"))
        self.assertTrue(self.store.begin(job_id))
        with self.assertRaises(ValueError):
            self.store.finish(job_id, "succeeded", failure_kind="ssh_banner_timeout")
        first = JobStore(self.path)
        second = JobStore(self.path)
        self.assertEqual(second.get("alice", job_id)["status"], "interrupted")
        with first._connect() as db:
            row = db.execute(
                "SELECT total FROM telemetry_outcomes WHERE status='interrupted'"
            ).fetchone()
            self.assertEqual(row["total"], 1)

    def test_transport_classification_has_fixed_safe_labels(self):
        from app.jobs import classify_ssh_failure
        self.assertEqual(
            classify_ssh_failure("Connection timed out during banner exchange\n"
                                 "Connection to 172.18.0.2 port 2222 timed out"),
            "ssh_banner_timeout",
        )
        self.assertEqual(
            classify_ssh_failure("Connection to 172.18.0.2 port 2222 timed out"),
            "tcp_connect_timeout",
        )
        self.assertEqual(classify_ssh_failure("Host key verification failed."),
                         "ssh_hostkey_failure")
        self.assertEqual(classify_ssh_failure("Permission denied (publickey)."),
                         "ssh_auth_failure")
        self.assertEqual(classify_ssh_failure("private unexpected stderr"),
                         "ssh_exit_255_ambiguous")

    def test_secure_creation_and_private_full_request_audit(self):
        req = request("sh", "-c", "echo very-private-token")
        job_id = self.store.create("alice", req)
        details = self.store.get("alice", job_id)
        self.assertEqual(details["command"], "sh")
        self.assertEqual(details["argv_count"], 3)
        self.assertEqual(len(details["command_sha256"]), 64)
        self.assertIsNone(self.store.get("bob", job_id))
        self.assertFalse(os.stat(self.path).st_mode & 0o077)
        self.assertFalse(os.stat(self.path.parent).st_mode & 0o077)
        with self.store._connect() as db:
            stored = json.loads(db.execute(
                "SELECT request_json FROM jobs WHERE id=?", (job_id,)
            ).fetchone()["request_json"])
        self.assertEqual(stored["argv"], req.argv)
        self.assertEqual(stored["reason"], req.reason)
        self.assertNotIn("argv", details)  # ordinary actor API exposes only safe summary
        self.assertNotIn("reason", details)
        self.assertEqual(self.store.list("alice")[0]["id"], job_id)
        self.assertEqual(self.store.list("bob"), [])

    def test_incremental_output_byte_cursor_and_restart(self):
        job_id = self.store.create("alice", request("echo"))
        self.assertTrue(self.store.begin(job_id))
        self.assertFalse(self.store.begin(job_id))
        self.store.append(job_id, "stdout", b"hel")
        self.store.append(job_id, "stderr", b"ERR")
        self.store.append(job_id, "stdout", b"lo")
        chunk = self.store.read_output("alice", job_id, max_bytes=4)
        self.assertEqual(chunk["next_cursor"], 4)
        self.assertEqual(chunk["chunks"], [
            {"stream": "stdout", "data_base64": "aGVs"},
            {"stream": "stderr", "data_base64": "RQ=="},
        ])
        self.assertTrue(chunk["truncated"])
        tail = self.store.read_output("alice", job_id, cursor=4, max_bytes=100)
        self.assertEqual(tail["chunks"], [
            {"stream": "stderr", "data_base64": "UlI="},
            {"stream": "stdout", "data_base64": "bG8="},
        ])
        self.assertEqual(tail["next_cursor"], 8)
        self.assertIsNone(self.store.read_output("bob", job_id))
        self.store.finish(job_id, "succeeded", exit_code=0, elapsed=.03)
        reopened = JobStore(self.path)
        self.assertEqual(reopened.get("alice", job_id)["status"], "succeeded")
        self.assertEqual(reopened.read_output("alice", job_id)["next_cursor"], 8)

    def test_utf8_split_across_pages_and_chunks(self):
        job_id = self.store.create("alice", request("printf"))
        self.store.begin(job_id)
        payload = "Aé中🙂Z".encode("utf-8")
        for part in (payload[:2], payload[2:4], payload[4:7], payload[7:]):
            self.store.append(job_id, "stdout", part)
        self.store.finish(job_id, "succeeded")
        pages = []
        cursor = 0
        while cursor < len(payload):
            page = self.store.read_output("alice", job_id, cursor=cursor, max_bytes=1)
            self.assertEqual(page["next_cursor"], cursor + 1)
            self.assertEqual(page["truncated"], cursor + 1 < len(payload))
            pages.extend(base64.b64decode(c["data_base64"], validate=True) for c in page["chunks"])
            cursor = page["next_cursor"]
        self.assertEqual(b"".join(pages), payload)
        self.assertEqual(b"".join(pages).decode("utf-8"), "Aé中🙂Z")

    def test_recovery_does_not_rerun_and_prunes_old_finished_jobs(self):
        running = self.store.create("alice", request("hold"))
        queued = self.store.create("alice", request("queued"))
        ended = self.store.create("bob", request("done"))
        self.assertTrue(self.store.begin(running))
        self.store.finish(ended, "failed")
        with self.store._connect() as db:
            db.execute("UPDATE jobs SET ended_at=? WHERE id=?", (1.0, ended))
        restarted = JobStore(self.path, retention_seconds=3600)
        self.assertEqual(restarted.get("alice", running)["status"], "interrupted")
        self.assertEqual(restarted.get("alice", queued)["status"], "interrupted")
        self.assertIsNone(restarted.get("bob", ended))
        self.assertFalse(restarted.begin(queued))
        self.assertIn("unknown", restarted.get("alice", running)["error"])

    def test_actor_scoping_and_cancel_flag(self):
        job_id = self.store.create("alice", request("hold"))
        self.assertFalse(self.store.request_cancel("bob", job_id))
        self.assertTrue(self.store.request_cancel("alice", job_id))
        self.assertTrue(self.store.get("alice", job_id)["cancellation_requested"])
        self.store.finish(job_id, "cancelled")
        self.assertFalse(self.store.request_cancel("alice", job_id))
        self.assertEqual(self.store.list("alice", status="cancelled")[0]["id"], job_id)
        with self.assertRaises(ValueError):
            self.store.list("alice", status="nonsense")
        with self.assertRaises(ValueError):
            self.store.read_output("alice", job_id, cursor=1)

    def test_rejects_insecure_database_and_directory(self):
        self.path.chmod(0o666)
        with self.assertRaises(PermissionError):
            JobStore(self.path)
        self.path.chmod(0o600)
        self.path.parent.chmod(0o755)
        with self.assertRaises(PermissionError):
            JobStore(self.path)
        self.path.parent.chmod(0o700)
        with self.assertRaises(ValueError):
            JobStore(self.path, retention_seconds=10)
        with self.assertRaises(ValueError):
            self.store.append("no-such-job", "not-stream", b"x")

    def test_private_output_stored_separately_and_wal_integrity(self):
        job_id = self.store.create("alice", request("printf", "x"))
        self.store.begin(job_id)
        self.store.append(job_id, "stdout", b"safe")
        self.store.finish(job_id, "succeeded")
        with self.store._connect() as db:
            rows = db.execute("PRAGMA integrity_check").fetchall()
            self.assertEqual(rows[0][0], "ok")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM output").fetchone()[0], 1)


    def test_pre_execution_rejection_only_allowed_for_failed_jobs(self):
        identifier = self.store.create("alice", request("echo"))
        self.assertTrue(self.store.begin(identifier))
        for status in ("succeeded", "cancelled", "transport_error"):
            with self.subTest(status=status), self.assertRaisesRegex(
                ValueError, "requires failed status",
            ):
                self.store.finish(
                    identifier, status, failure_kind="pre_execution_rejected",
                )
        self.store.finish(identifier, "failed",
                          failure_kind="pre_execution_rejected")
        self.assertEqual(self.store.get("alice", identifier)["failure_kind"],
                         "pre_execution_rejected")

    def test_rejects_path_symlinks_and_invalid_bounds(self):
        from app.jobs import _safe_command
        self.assertEqual(_safe_command(["./shell*"]), "[redacted]")
        with self.assertRaises(ValueError):
            JobStore(Path("relative.sqlite"))
        linked_file = self.path.parent / "linked.sqlite"
        linked_file.symlink_to(self.path)
        with self.assertRaises(ValueError):
            JobStore(linked_file)
        linked_parent = Path(self.temp.name) / "alias"
        linked_parent.symlink_to(self.path.parent, target_is_directory=True)
        with self.assertRaises(ValueError):
            JobStore(linked_parent / "different.sqlite")
        with self.assertRaises(ValueError):
            self.store.list("alice", limit=0)
        job_id = self.store.create("alice", request("printf"))
        with self.assertRaises(ValueError):
            self.store.finish(job_id, "nonsense")
        self.assertIsNone(self.store.get("alice", "nonexistent"))
        with self.assertRaises(ValueError):
            self.store.read_output("alice", job_id, cursor=-1)
        with self.assertRaises(ValueError):
            self.store.read_output("alice", job_id, max_bytes=0)
        with self.assertRaises(RuntimeError):
            self.store.append(job_id, "stdout", b"not-running")
        self.store.begin(job_id)
        self.store.append(job_id, "stdout", b"")
        self.store.append(job_id, "stdout", b"a")
        with self.assertRaises(ValueError):
            self.store.read_output("alice", job_id, cursor=2)


class ManagerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = JobStore(Path(self.temp.name) / "db" / "jobs.sqlite")
        self.executor = FakeExecutor()
        self.manager = JobManager(self.executor, self.store)
        self.addAsyncCleanup(self.manager.shutdown)

    async def wait(self, job_id, wanted):
        for i in range(200):
            item = self.manager.get("alice", job_id)
            if item["status"] in wanted:
                return item
            await asyncio.sleep(.01)
        self.fail(f"Job did not reach {wanted}: {item}")

    async def test_preapproval_command_sync_and_async_reuse_exact_record(self):
        from app.approval_status import ApprovalCode

        for mode in ("sync", "async"):
            with self.subTest(mode=mode):
                command = request("echo", mode)
                identifier = self.store.create("alice", command, mode=mode,
                                               pending_approval=True)
                initial = self.store.get("alice", identifier)
                self.assertEqual(initial["status"], "awaiting_approval")
                self.store.settle_approval(identifier,
                                           int(ApprovalCode.APPROVED_TIMED))
                if mode == "sync":
                    job_id, result = await self.manager.execute_sync(
                        "alice", command, precreated_id=identifier,
                    )
                    self.assertIsNotNone(result)
                    self.assertEqual(result.status, "succeeded")
                else:
                    started = self.manager.submit(
                        "alice", command, precreated_id=identifier,
                    )
                    job_id = started["id"]
                    await self.wait(job_id, {"succeeded"})
                self.assertEqual(job_id, identifier)
                item = self.store.get("alice", job_id)
                self.assertEqual(item["created_at"], initial["created_at"])
                self.assertEqual(item["approval_status"], "approved_timed")
                self.assertIsNotNone(item["started_at"])
                self.assertEqual(len(self.store.list("alice")), 1 if mode == "sync" else 2)

    async def test_success_incremental_output_and_owner_isolation(self):
        item = self.manager.submit("alice", request("echo", "test"))
        self.assertIn(item["status"], ("queued", "running"))
        done = await self.wait(item["id"], {"succeeded"})
        self.assertEqual(done["exit_code"], 0)
        self.assertEqual(done["output_bytes"], 6)
        self.assertEqual(self.manager.output("alice", item["id"])["next_cursor"], 6)
        self.assertIsNone(self.manager.output("bob", item["id"]))
        self.assertIsNone(self.manager.get("bob", item["id"]))
        self.assertEqual(self.manager.list("alice")[0]["id"], item["id"])
        self.assertEqual(self.manager.list("bob"), [])

    async def test_accepted_nonzero_cwd_in_sync_and_async_audit(self):
        specified = ExecuteCommandRequest(
            server="demo-node-b", argv=["accepted"],
            reason="TEST-247 accepted exit", story_id="TEST-247",
            cwd="/home/example/link", success_exit_codes=[0, 1],
        )
        job_id, result = await self.manager.execute_sync("alice", specified)
        self.assertIsNotNone(result)
        self.assertEqual(result.status, "succeeded")
        self.assertIs(result.exit_accepted, True)
        row = self.store.get("alice", job_id)
        self.assertEqual((row["status"], row["exit_code"], row["exit_accepted"]),
                         ("succeeded", 1, True))
        self.assertEqual(row["effective_cwd"], "/home/example/synthetic")
        submitted = self.manager.submit("alice", specified)
        done = await self.wait(submitted["id"], {"succeeded"})
        self.assertEqual((done["status"], done["exit_code"], done["exit_accepted"]),
                         ("succeeded", 1, True))
        self.assertEqual(done["effective_cwd"], "/home/example/synthetic")

    async def test_failure_status_mapping_and_secret_safe_errors(self):
        for cmd, wanted in [
            ("error", "failed"), ("timeout", "timed_out"),
            ("transport", "transport_error"), ("limit", "output_limit"),
            ("denied", "failed"), ("crash", "failed"),
        ]:
            with self.subTest(cmd=cmd):
                item = self.manager.submit("alice", request(cmd))
                done = await self.wait(item["id"], {wanted})
                self.assertEqual(done["status"], wanted)
                self.assertNotIn("private", done["error"])

    async def test_pre_execution_denial_is_distinct_from_generic_failure(self):
        for mode in ("sync", "async"):
            with self.subTest(mode=mode):
                denied = request("denied")
                if mode == "sync":
                    job_id, result = await self.manager.execute_sync(
                        "alice", denied,
                    )
                    self.assertIsNone(result)
                else:
                    job_id = self.manager.submit("alice", denied)["id"]
                    await self.wait(job_id, {"failed"})
                record = self.manager.get("alice", job_id)
                self.assertEqual(record["status"], "failed")
                self.assertEqual(record["failure_kind"], "pre_execution_rejected")
                self.assertIsNone(record["exit_code"])
                self.assertIsNone(record["exit_accepted"])
                self.assertEqual(record["output_bytes"], 0)
                self.assertEqual(record["error"], "SSH authorization was rejected")
        with self.store._connect() as db:
            self.assertEqual(db.execute(
                "SELECT total FROM telemetry_outcomes WHERE status='failed' "
                "AND failure_kind='pre_execution_rejected'"
            ).fetchone()[0], 2)

    async def test_native_cwd_and_signal_failures_finish_durable_jobs(self):
        for mode in ("sync", "async"):
            for command, kind, expected_code in (
                ("native-cwd-failure", "cwd_preflight", 255),
                ("native-signal", "remote_signal", None),
            ):
                with self.subTest(mode=mode, failure_kind=kind):
                    if mode == "sync":
                        job_id, result = await self.manager.execute_sync(
                            "alice", request(command))
                        self.assertIsNotNone(result)
                        self.assertEqual(result.status, "command_error")
                    else:
                        job_id = self.manager.submit("alice", request(command))["id"]
                        await self.wait(job_id, {"failed"})
                    saved = self.store.get("alice", job_id)
                    self.assertEqual(saved["status"], "failed")
                    self.assertEqual(saved["failure_kind"], kind)
                    self.assertEqual(saved["exit_code"], expected_code)
                    self.assertFalse(saved["exit_accepted"])
                    self.assertIsNotNone(saved["ended_at"])
                    self.assertIsNotNone(saved["elapsed_seconds"])
                    with self.store._connect() as db:
                        row = db.execute(
                            "SELECT total FROM telemetry_outcomes "
                            "WHERE server=? AND status='failed' AND failure_kind=?",
                            ("demo-node-b", kind),
                        ).fetchone()
                    self.assertIsNotNone(row)
                    self.assertGreaterEqual(row["total"], 1)

    async def test_running_cancellation_terminates_task(self):
        item = self.manager.submit("alice", request("hold"))
        await self.executor.running.wait()
        self.assertFalse(self.manager.cancel("bob", item["id"]))
        answer = self.manager.cancel("alice", item["id"])
        self.assertTrue(answer["cancellation_requested"])
        done = await self.wait(item["id"], {"cancelled"})
        self.assertEqual(done["status"], "cancelled")
        self.assertTrue(self.executor.cancelled)
        self.assertFalse(self.manager.cancel("alice", item["id"])["cancellation_requested"])

    async def test_invalid_active_cap(self):
        for cap in (0, 257):
            with self.assertRaises(ValueError):
                JobManager(self.executor, self.store, max_active=cap)

    async def test_unknown_host_never_persists_job(self):
        with self.assertRaises(SSHDenied):
            self.manager.submit("bob", request("echo"))
        with self.assertRaises(SSHDenied):
            self.manager.submit("alice", ExecuteCommandRequest(
                server="demo-node2", argv=["echo"], reason="test",
            ))
        self.assertEqual(self.manager.list("alice"), [])

    async def test_queued_cancellation_before_scheduling(self):
        item = self.manager.submit("alice", request("hold"))
        answer = self.manager.cancel("alice", item["id"])
        self.assertEqual(answer["job"]["status"], "cancelled")
        await asyncio.sleep(.05)
        self.assertEqual(self.manager.get("alice", item["id"])["status"], "cancelled")
        self.assertEqual(self.executor.events, [])

    async def test_approved_job_losing_signed_host_is_terminal_before_dispatch(self):
        from app.approval_status import ApprovalCode
        from app.history import HistoryStore

        pending = self.store.create("bob", request("id"), pending_approval=True)
        self.store.settle_approval(pending, int(ApprovalCode.APPROVED_EXPLICIT))
        with self.assertRaises(SSHDenied):
            self.manager.submit("bob", request("id"), precreated_id=pending)
        item = self.store.get("bob", pending)
        self.assertEqual(item["status"], "failed")
        self.assertEqual(item["approval_status"], "approved_explicit")
        self.assertIsNone(item["started_at"])
        self.assertIsNotNone(item["ended_at"])
        self.assertEqual(self.executor.events, [])
        with self.assertRaisesRegex(RuntimeError, "Cannot finalize"):
            self.store.reject_unscheduled(pending, "duplicate completion")
        self.assertEqual(HistoryStore(self.store).detail(pending)["status"], "failed")

    async def test_saturated_manager_finalizes_approved_preexecution_audit(self):
        from app.approval_status import ApprovalCode
        from app.history import HistoryStore
        self.manager.max_active = 1
        active = self.manager.submit("alice", request("hold"))
        await asyncio.wait_for(self.executor.running.wait(), 2)
        waiting = self.store.create(
            "alice", request("echo"), pending_approval=True,
        )
        self.store.settle_approval(waiting, int(ApprovalCode.APPROVED_EXPLICIT))
        with self.assertRaisesRegex(RuntimeError, "Too many active jobs"):
            self.manager.submit("alice", request("echo"), precreated_id=waiting)
        row = self.store.get("alice", waiting)
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["approval_status"], "approved_explicit")
        self.assertIsNone(row["started_at"])
        self.assertIsNotNone(row["ended_at"])
        self.assertIs(row["root_started"], False)
        self.assertEqual(HistoryStore(self.store).detail(waiting)["status"], "failed")
        self.assertEqual(len(self.executor.events), 1)
        self.executor.release.set()
        await self.wait(active["id"], {"succeeded"})

    async def test_active_job_cap_and_shutdown(self):
        other = JobManager(self.executor, self.store, max_active=1)
        item = other.submit("alice", request("hold"))
        with self.assertRaisesRegex(RuntimeError, "active"):
            other.submit("alice", request("again"))
        await other.shutdown()
        self.assertEqual(other.get("alice", item["id"])["status"], "cancelled")


class QueueAdmissionTests(unittest.IsolatedAsyncioTestCase):
    """Real per-host semaphore, synthetic SSH execution; no network or root."""

    async def asyncSetUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        store = JobStore(Path(temp.name) / "private" / "jobs.sqlite")
        host = HostSpec(
            alias="demo-node-b", address="localhost", port=22, username="gateway",
            identity_file=Path("/synthetic/id"), known_hosts_file=Path("/synthetic/pins"),
            principals=["alice"], environment="non-production",
            access="always-granted", privileged_access="restricted", max_parallel=1,
        )
        executor = SSHExecutor(
            {host.alias: host}, enabled=True,
            sudo_passwords={host.alias: "synthetic-password"},
        )
        auth = patch.object(executor, "authorized_host", return_value=host)
        auth.start()
        self.addCleanup(auth.stop)
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.calls = []

        async def remote(_host, command, start, _on_output, *, sudo_password=None,
                         password_permitted=None):
            self.assertIsNone(password_permitted)
            self.calls.append((command.argv[0], sudo_password is not None))
            # The transport's execution clock must begin after semaphore admission.
            self.assertLess(time.monotonic() - start, .2)
            if command.argv[0] == "hold":
                self.entered.set()
                await self.release.wait()
            return SSHResult(
                command.server, "succeeded", 0, "", "", .01,
                root_started=True if command.privileged else None,
            )

        transport = patch.object(executor, "_run", side_effect=remote)
        transport.start()
        self.addCleanup(transport.stop)
        self.manager = JobManager(executor, store)
        self.addAsyncCleanup(self.manager.shutdown)

    def command(self, name, *, privileged=False):
        return ExecuteCommandRequest(
            server="demo-node-b", argv=[name], reason="TEST-278 semaphore test",
            timeout_seconds=1, privileged=privileged,
        )

    async def block_first(self):
        first = self.manager.submit("alice", self.command("hold"))
        await asyncio.wait_for(self.entered.wait(), 2)
        self.assertEqual(self.manager.get("alice", first["id"])["status"], "running")
        return first

    async def test_second_async_job_is_queued_until_host_slot_is_free(self):
        await self.block_first()
        second = self.manager.submit("alice", self.command("second"))
        await asyncio.sleep(.02)
        waiting = self.manager.get("alice", second["id"])
        self.assertEqual(waiting["status"], "queued")
        self.assertIsNone(waiting["started_at"])
        self.assertEqual(self.calls, [("hold", False)])
        # A one-second execution timeout is not spent while in the queue.
        await asyncio.sleep(1.02)
        self.assertEqual(self.manager.get("alice", second["id"])["status"], "queued")
        self.release.set()
        await asyncio.gather(*list(self.manager._tasks.values()))
        finished = self.manager.get("alice", second["id"])
        self.assertEqual(finished["status"], "succeeded")
        self.assertIsNotNone(finished["started_at"])
        self.assertEqual(self.calls, [("hold", False), ("second", False)])

    async def test_privileged_job_stays_queued_and_never_starts_sudo_early(self):
        await self.block_first()
        second = self.manager.submit(
            "alice", self.command("root", privileged=True), admitted_root=True,
        )
        await asyncio.sleep(.02)
        waiting = self.manager.get("alice", second["id"])
        self.assertEqual(waiting["status"], "queued")
        self.assertIsNone(waiting["started_at"])
        self.assertIsNone(waiting["root_started"])
        self.release.set()
        await asyncio.gather(*list(self.manager._tasks.values()))
        self.assertEqual(self.manager.get("alice", second["id"])["status"], "succeeded")
        self.assertEqual(self.calls, [("hold", False), ("root", True)])

    async def test_cancelled_queued_job_never_dispatches(self):
        await self.block_first()
        second = self.manager.submit("alice", self.command("cancelled"))
        await asyncio.sleep(.02)
        self.assertEqual(self.manager.get("alice", second["id"])["status"], "queued")
        self.manager.cancel("alice", second["id"])
        self.release.set()
        await asyncio.gather(*list(self.manager._tasks.values()), return_exceptions=True)
        cancelled = self.manager.get("alice", second["id"])
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertIsNone(cancelled["started_at"])
        self.assertEqual(self.calls, [("hold", False)])

    async def test_synchronous_execution_waits_queued_for_capacity(self):
        await self.block_first()
        sync = asyncio.create_task(
            self.manager.execute_sync("alice", self.command("sync")),
        )
        await asyncio.sleep(.02)
        waiting = next(
            job for job in self.manager.list("alice") if job["mode"] == "sync"
        )
        self.assertEqual(waiting["status"], "queued")
        self.assertIsNone(waiting["started_at"])
        self.release.set()
        job_id, result = await asyncio.wait_for(sync, 2)
        self.assertEqual(result.status, "succeeded")
        self.assertIsNotNone(self.manager.get("alice", job_id)["started_at"])
        self.assertEqual(self.calls, [("hold", False), ("sync", False)])


    async def test_cancel_queued_sync_wakes_waiter_without_starting(self):
        await self.block_first()
        task = asyncio.create_task(
            self.manager.execute_sync("alice", self.command("never-dispatched")),
        )
        await asyncio.sleep(.02)
        queued = next(
            item for item in self.manager.list("alice") if item["mode"] == "sync"
        )
        self.assertEqual(queued["status"], "queued")
        reply = self.manager.cancel("alice", queued["id"])
        self.assertTrue(reply["cancellation_requested"])
        # Must not wait for the occupied SSH slot to become available.
        job_id, result = await asyncio.wait_for(task, .3)
        self.assertEqual(job_id, queued["id"])
        self.assertIsNone(result)
        ended = self.manager.get("alice", job_id)
        self.assertEqual(ended["status"], "cancelled")
        self.assertIsNone(ended["started_at"])
        self.assertIsNone(ended["elapsed_seconds"])
        with self.manager.store._connect() as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM telemetry_duration").fetchone()[0], 0,
            )
        self.assertEqual(self.calls, [("hold", False)])
        self.release.set()

    async def test_sync_cancel_followed_by_outer_timeout_propagates(self):
        await self.block_first()
        sync = asyncio.create_task(
            self.manager.execute_sync("alice", self.command("never-dispatched")),
        )
        await asyncio.sleep(.02)
        child = next(j for j in self.manager.list("alice") if j["mode"] == "sync")
        self.assertTrue(self.manager.cancel("alice", child["id"])["cancellation_requested"])
        # Simulate wait_for's outer timeout in the same loop turn, before the
        # explicit-cancellation exception can be delivered to the child task.
        sync.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await sync
        saved = self.manager.get("alice", child["id"])
        self.assertEqual(saved["status"], "cancelled")
        self.assertIsNone(saved["started_at"])
        self.assertIsNone(saved["elapsed_seconds"])
        self.assertEqual(self.calls, [("hold", False)])
        self.release.set()

    async def test_outer_cancel_before_explicit_sync_cancel_propagates(self):
        await self.block_first()
        sync = asyncio.create_task(
            self.manager.execute_sync("alice", self.command("never-dispatched")),
        )
        await asyncio.sleep(.02)
        child = next(j for j in self.manager.list("alice") if j["mode"] == "sync")
        sync.cancel()
        self.assertTrue(self.manager.cancel("alice", child["id"])["cancellation_requested"])
        with self.assertRaises(asyncio.CancelledError):
            await sync
        self.assertIsNone(self.manager.get("alice", child["id"])["started_at"])
        self.assertEqual(self.calls, [("hold", False)])
        self.release.set()

    async def test_batch_shutdown_overlaps_explicit_child_cancel(self):
        await self.block_first()
        batch = BatchManager(self.manager)
        command = ExecuteCommandsRequest(
            server="demo-node-b", reason="TEST-278 overlapping batch cancellation",
            timeout_seconds=10, commands=[{"argv": ["never"]}],
        )
        caller = asyncio.create_task(batch.execute("alice", command))
        await asyncio.sleep(.05)
        batch_id = batch.list("alice")["batches"][0]["batch_id"]
        child = batch.get("alice", batch_id)["steps"][0]["job_id"]
        self.assertIsNotNone(child)
        self.assertTrue(self.manager.cancel("alice", child)["cancellation_requested"])
        # Mirror an outer batch timeout/shutdown before the child resumes.
        self.assertTrue(batch.cancel("alice", batch_id)["cancellation_requested"])
        with self.assertRaises(asyncio.CancelledError):
            await caller
        item = batch.get("alice", batch_id)
        self.assertEqual(item["status"], "interrupted")
        self.assertEqual(item["failure_kind"], "cancelled")
        self.assertEqual(item["steps"][0]["status"], "not_attempted")
        self.assertEqual(item["steps"][0]["job_id"], child)
        self.assertIsNone(self.manager.get("alice", child)["started_at"])
        self.assertEqual(self.calls, [("hold", False)])
        self.release.set()

    async def test_queued_cancelled_async_has_no_duration_histogram(self):
        await self.block_first()
        queued = self.manager.submit("alice", self.command("never"))
        await asyncio.sleep(.02)
        self.manager.cancel("alice", queued["id"])
        await asyncio.sleep(.02)
        record = self.manager.get("alice", queued["id"])
        self.assertEqual(record["status"], "cancelled")
        self.assertIsNone(record["elapsed_seconds"])
        with self.manager.store._connect() as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM telemetry_duration").fetchone()[0], 0,
            )
        self.release.set()

    async def test_exception_duration_excludes_semaphore_queue(self):
        await self.block_first()
        async def rejected(_host, _command, _start, _on_output, **_kwargs):
            raise SSHDenied("Synthetic authorization rejection")
        with patch.object(self.manager.executor, "_run", side_effect=rejected):
            queued = self.manager.submit("alice", self.command("reject"))
            await asyncio.sleep(.15)
            self.assertEqual(self.manager.get("alice", queued["id"])["status"], "queued")
            self.release.set()
            await asyncio.gather(*list(self.manager._tasks.values()))
        failed = self.manager.get("alice", queued["id"])
        self.assertEqual(failed["status"], "failed")
        self.assertIsNotNone(failed["started_at"])
        self.assertIsNotNone(failed["elapsed_seconds"])
        self.assertLess(failed["elapsed_seconds"], .12)

    async def test_explicit_batch_cancel_while_queued_preserves_nonexecution(self):
        await self.block_first()
        batch = BatchManager(self.manager)
        cmd = ExecuteCommandsRequest(
            server="demo-node-b", reason="TEST-278 queued batch cancellation",
            timeout_seconds=10, commands=[{"argv": ["never"]}],
        )
        pending = asyncio.create_task(batch.execute("alice", cmd))
        await asyncio.sleep(.05)
        batch_id = batch.list("alice")["batches"][0]["batch_id"]
        step = batch.get("alice", batch_id)["steps"][0]
        self.assertFalse(step["attempted"])
        self.assertTrue(batch.cancel("alice", batch_id)["cancellation_requested"])
        with self.assertRaises(asyncio.CancelledError):
            await pending
        finished = batch.get("alice", batch_id)
        self.assertEqual(finished["status"], "interrupted")
        self.assertEqual(finished["steps"][0]["status"], "not_attempted")
        self.assertFalse(finished["steps"][0]["attempted"])
        self.assertEqual(finished["steps"][0]["job_id"], step["job_id"])
        self.assertIsNone(self.manager.get("alice", step["job_id"])["started_at"])
        self.assertEqual(self.calls, [("hold", False)])
        self.release.set()

    async def test_manual_batch_cancel_during_cleanup_after_deadline_is_not_timeout(self):
        await self.block_first()
        batch = BatchManager(self.manager)
        command = ExecuteCommandsRequest(
            server="demo-node-b", reason="TEST-278 cancellation cleanup after deadline",
            timeout_seconds=1, commands=[{"argv": ["never"]}],
        )
        pending = asyncio.create_task(batch.execute("alice", command))
        await asyncio.sleep(.04)
        batch_id = batch.list("alice")["batches"][0]["batch_id"]
        step = batch.get("alice", batch_id)["steps"][0]
        self.assertEqual(step["status"], "not_attempted")
        self.assertIsNotNone(step["job_id"])
        original_uncertain_step = batch.store.uncertain_step
        cleanup_called = []

        def slow_sync_cleanup(*args):
            # Block the event loop during synchronous audit cleanup. The
            # timeout callback cannot fire after the prior manual cancel
            # exits the timeout context, even though wall time crosses 1s.
            cleanup_called.append(True)
            time.sleep(1.08)
            return original_uncertain_step(*args)

        with patch.object(batch.store, "uncertain_step", side_effect=slow_sync_cleanup):
            self.assertTrue(batch.cancel("alice", batch_id)["cancellation_requested"])
            with self.assertRaises(asyncio.CancelledError):
                await pending
        self.assertTrue(cleanup_called)
        self.assertEqual(batch.get("alice", batch_id)["status"], "interrupted")
        self.assertEqual(batch.get("alice", batch_id)["failure_kind"], "cancelled")
        self.assertEqual(batch.get("alice", batch_id)["steps"][0]["status"], "not_attempted")
        self.assertIsNone(self.manager.get("alice", step["job_id"])["started_at"])
        self.assertEqual(self.calls, [("hold", False)])
        self.release.set()

    async def test_batch_deadline_races_explicit_child_cancel_without_masking_timeout(self):
        await self.block_first()
        batch = BatchManager(self.manager)
        command = ExecuteCommandsRequest(
            server="demo-node-b", reason="TEST-278 deadline cancellation collision",
            timeout_seconds=1, commands=[{"argv": ["never"]}],
        )
        called = []
        loop = asyncio.get_running_loop()

        real_timeout_at = asyncio.timeout_at

        def same_deadline(timeout):
            # Register the explicit cancel at the same absolute deadline,
            # immediately before the actual timeout context schedules its
            # own cancellation. Both will fire before the task resumes.
            deadline = loop.time() + timeout

            def cancel_child():
                batch_id = batch.list("alice")["batches"][0]["batch_id"]
                job_id = batch.get("alice", batch_id)["steps"][0]["job_id"]
                assert job_id is not None
                called.append(self.manager.cancel("alice", job_id))

            loop.call_at(deadline, cancel_child)
            return real_timeout_at(deadline)

        with patch("app.batch.asyncio.timeout", side_effect=same_deadline):
            result = await batch.execute("alice", command)
        self.assertEqual(len(called), 1)
        self.assertTrue(called[0]["cancellation_requested"])
        self.assertEqual(result["status"], "timed_out")
        self.assertEqual(result["failure_kind"], "overall_timeout")
        self.assertFalse(result["steps"][0]["attempted"])
        self.assertEqual(result["steps"][0]["status"], "not_attempted")
        child = self.manager.get("alice", result["steps"][0]["job_id"])
        self.assertEqual(child["status"], "cancelled")
        self.assertIsNone(child["started_at"])
        self.assertIsNone(child["elapsed_seconds"])
        self.assertEqual(self.calls, [("hold", False)])
        self.release.set()

    async def test_batch_child_queued_until_admission_then_times_out_unattempted(self):
        await self.block_first()
        batch = BatchManager(self.manager)
        cmd = ExecuteCommandsRequest(
            server="demo-node-b", reason="TEST-278 batch queue deadline",
            timeout_seconds=1, commands=[{"argv": ["never"]}],
        )
        pending = asyncio.create_task(batch.execute("alice", cmd))
        await asyncio.sleep(.05)
        batch_id = batch.list("alice")["batches"][0]["batch_id"]
        step = batch.get("alice", batch_id)["steps"][0]
        self.assertEqual(step["status"], "not_attempted")
        self.assertFalse(step["attempted"])
        self.assertIsNotNone(step["job_id"])
        queued = self.manager.get("alice", step["job_id"])
        self.assertEqual(queued["status"], "queued")
        self.assertIsNone(queued["started_at"])
        outcome = await asyncio.wait_for(pending, 2)
        self.assertEqual(outcome["status"], "timed_out")
        self.assertEqual(outcome["failure_kind"], "overall_timeout")
        self.assertEqual(outcome["steps"][0]["status"], "not_attempted")
        self.assertEqual(outcome["steps"][0]["job_id"], step["job_id"])
        finished = self.manager.get("alice", step["job_id"])
        self.assertEqual(finished["status"], "cancelled")
        self.assertIsNone(finished["started_at"])
        self.assertIsNone(finished["elapsed_seconds"])
        self.assertEqual(self.calls, [("hold", False)])
        self.release.set()


class CancellationAuditTests(unittest.TestCase):
    """Rare cancellation events stay separate from frequently queried jobs."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = JobStore(Path(self.temp.name) / "private" / "jobs.sqlite",
                              retention_seconds=3600)

    def job(self):
        return self.store.create("alice", request("sleep", "30"))

    def audit(self, target_type, identifier):
        with self.store._connect() as db:
            return db.execute(
                "SELECT requested_via,requested_at,reason FROM cancellation_requests "
                "WHERE target_type=? AND target_id=?", (target_type, identifier),
            ).fetchone()

    def test_first_accepted_cancellation_wins_and_preserves_exact_reason(self):
        job = self.job()
        self.assertTrue(self.store.request_cancel(
            "alice", job, via="mcp", reason="Agent reason with punctuation: ; & ø"))
        first = self.audit("job", job)
        self.assertEqual(first["requested_via"], "mcp")
        self.assertEqual(first["reason"], "Agent reason with punctuation: ; & ø")
        self.assertFalse(self.store.request_cancel(
            "alice", job, via="history", reason="Trying to overwrite"))
        self.assertFalse(self.store.request_cancel(
            "bob", job, via="history", reason="Unauthorised"))
        self.assertEqual(self.audit("job", job)["requested_at"], first["requested_at"])
        self.assertEqual(self.audit("job", job)["reason"], first["reason"])
        with self.assertRaises(ValueError):
            self.store.request_cancel("alice", job, via="mcp", reason="x" * 201)
        with self.assertRaises(ValueError):
            self.store.request_cancel("alice", job, via="unknown", reason="not trusted")

    def test_cancellation_record_pruned_with_job_not_before(self):
        job = self.job()
        self.assertTrue(self.store.request_cancel(
            "alice", job, via="mcp", reason="Prune event with completed job"))
        self.store.finish(job, "cancelled")
        self.assertIsNotNone(self.audit("job", job))
        with self.store._connect() as db:
            db.execute("UPDATE jobs SET ended_at=? WHERE id=?",
                       (time.time() - 7200, job))
        self.store.prune()
        self.assertIsNone(self.audit("job", job))

    def test_queued_batch_is_finalized_even_if_task_never_started(self):
        from app.batch import BatchManager
        class PendingTask:
            def __init__(self):
                self.cancelled = False
            def done(self):
                return False
            def cancel(self):
                self.cancelled = True
        jobs = JobManager(FakeExecutor(), self.store)
        batches = BatchManager(jobs)
        req = ExecuteCommandsRequest.model_validate({
            "server": "demo-node-b", "reason": "Synthetic queued batch",
            "commands": [{"argv": ["sleep", "30"]}],
        })
        batch_id = batches.store.create("alice", req)
        pending = PendingTask()
        batches._tasks[batch_id] = pending
        result = batches.cancel("alice", batch_id, via="history",
                                reason="Cancelled from History viewer")
        self.assertTrue(result["cancellation_requested"])
        self.assertEqual(result["status"], "cancelled")
        self.assertTrue(pending.cancelled)
        self.assertEqual(batches.get("alice", batch_id)["status"], "cancelled")
        self.assertEqual(batches.get("alice", batch_id)["steps"][0]["status"], "not_attempted")
        self.assertEqual(self.audit("batch", batch_id)["requested_via"], "history")

    def test_batch_cancellation_event_survives_until_batch_pruned(self):
        from app.batch import BatchStore
        batches = BatchStore(self.store)
        req = ExecuteCommandsRequest.model_validate({
            "server": "demo-node-b", "reason": "Synthetic batch",
            "commands": [{"argv": ["sleep", "30"]}],
        })
        batch = batches.create("alice", req)
        self.assertTrue(batches.begin(batch))
        self.assertTrue(self.store.record_cancellation(
            "batch", "alice", batch, via="history", reason="Cancelled from History viewer"))
        self.assertFalse(self.store.record_cancellation(
            "batch", "alice", batch, via="mcp", reason="Later agent cancellation"))
        self.assertEqual(self.audit("batch", batch)["requested_via"], "history")
        batches.finish(batch, "interrupted", failure_kind="cancelled")
        with self.store._connect() as db:
            db.execute("UPDATE command_batches SET ended_at=? WHERE id=?",
                       (time.time() - 7200, batch))
        self.store.prune()
        self.assertIsNone(self.audit("batch", batch))

    def test_queued_job_and_batch_audit_failure_rolls_back_everything(self):
        from app.batch import BatchStore
        batch_store = BatchStore(self.store)
        req = ExecuteCommandsRequest.model_validate({
            "server": "demo-node-b", "reason": "Synthetic rollback batch",
            "commands": [{"argv": ["sleep", "30"]}],
        })
        job_id = self.job()
        running_id = self.job()
        self.assertTrue(self.store.begin(running_id))
        batch_id = batch_store.create("alice", req)
        with self.store._connect() as db:
            db.execute("""CREATE TRIGGER reject_cancellation_audit
                          BEFORE INSERT ON cancellation_requests
                          BEGIN SELECT RAISE(ABORT,'synthetic audit fault'); END""")
        for target_type, target_id in (
            ("job", job_id), ("job", running_id), ("batch", batch_id)
        ):
            with self.assertRaises(sqlite3.IntegrityError):
                self.store.record_cancellation(
                    target_type, "alice", target_id,
                    via="history", reason="Audit must be all-or-nothing",
                )
            self.assertIsNone(self.audit(target_type, target_id))
        self.assertEqual(self.store.get("alice", job_id)["status"], "queued")
        self.assertFalse(self.store.get("alice", job_id)["cancellation_requested"])
        self.assertEqual(self.store.get("alice", running_id)["status"], "running")
        self.assertFalse(self.store.get("alice", running_id)["cancellation_requested"])
        self.assertEqual(batch_store.get("alice", batch_id)["status"], "queued")
        with self.store._connect() as db:
            db.execute("DROP TRIGGER reject_cancellation_audit")
        # Failed audit must not disable admission or prevent a valid retry.
        self.assertTrue(self.store.record_cancellation(
            "job", "alice", job_id, via="mcp", reason="Valid retry"))
        self.assertTrue(self.store.record_cancellation(
            "batch", "alice", batch_id, via="history", reason="Valid retry"))
        self.assertEqual(self.store.get("alice", job_id)["status"], "cancelled")
        self.assertEqual(batch_store.get("alice", batch_id)["status"], "cancelled")
        self.assertFalse(self.store.begin(job_id))
        self.assertFalse(batch_store.begin(batch_id))
        self.assertIsNotNone(self.store.get("alice", job_id)["ended_at"])
        self.assertIsNotNone(batch_store.get("alice", batch_id)["status"])
        with self.store._connect() as db:
            telemetry = db.execute(
                "SELECT total FROM telemetry_outcomes WHERE server=? AND status=?",
                ("demo-node-b", "cancelled"),
            ).fetchone()
        self.assertEqual(telemetry["total"], 1)

    def test_batch_cancellation_invalidates_active_child_eligibility_and_notifies(self):
        from app.batch import BatchStore
        from app.history import HistoryStore
        batch_store = BatchStore(self.store)
        req = ExecuteCommandsRequest.model_validate({
            "server": "demo-node-b", "reason": "Synthetic parent cancellation",
            "commands": [{"argv": ["sleep", "30"]}],
        })
        batch_id = batch_store.create("alice", req)
        self.assertTrue(batch_store.begin(batch_id))
        child = self.job()
        self.assertTrue(self.store.begin(child))
        batch_store.record_step(batch_id, 0, child)
        batch_store.admitted_step(batch_id, 0, child)
        history = HistoryStore(self.store)
        before = self.store.get("alice", child)["updated_at"]
        self.assertEqual(
            history.eligible_cancellation_ids([child], actor="alice",
                                             approved_hosts={"demo-node-b"},
                                             batches_enabled=True),
            {child},
        )
        self.assertTrue(self.store.record_cancellation(
            "batch", "alice", batch_id, via="mcp", reason="No further steps"))
        self.assertEqual(
            history.eligible_cancellation_ids([child], actor="alice",
                                             approved_hosts={"demo-node-b"},
                                             batches_enabled=True),
            set(),
        )
        self.assertGreater(self.store.get("alice", child)["updated_at"], before)
        self.assertEqual(self.store.get("alice", child)["status"], "running")
        self.assertEqual(history.cancellation_request(child)["requested_via"], "mcp")
        self.assertEqual(history.batch_step_outcome(child)["batch_status"], "running")

    def test_cancellation_eligibility_without_a_batch_table_checks_actor_host_and_state(self):
        from app.history import HistoryStore
        history = HistoryStore(self.store)
        queued = self.job()
        running = self.job()
        self.assertTrue(self.store.begin(running))
        allowed = {"demo-node-b"}
        self.assertEqual(
            history.eligible_cancellation_ids(
                [queued, running, "not-an-id!"],
                actor="alice", approved_hosts=allowed, batches_enabled=True,
            ),
            {queued, running},
        )
        self.assertFalse(history.eligible_cancellation_ids(
            [], actor="alice", approved_hosts=allowed, batches_enabled=True))
        self.assertFalse(history.eligible_cancellation_ids(
            [queued], actor="alice", approved_hosts=set(), batches_enabled=True))
        self.assertFalse(history.eligible_cancellation_ids(
            [queued], actor="bob", approved_hosts=allowed, batches_enabled=True))
        self.assertFalse(history.eligible_cancellation_ids(
            [queued], actor="alice", approved_hosts={"other-host"},
            batches_enabled=True))
        self.assertIsNone(history.batch_step_outcome(queued))
        self.assertIsNone(history.batch_step_outcome("not-an-id!"))
        self.assertTrue(self.store.record_cancellation(
            "job", "alice", queued, via="mcp", reason="Remove queued task"))
        self.assertEqual(self.store.get("alice", queued)["status"], "cancelled")
        self.assertFalse(self.store.begin(queued))
        self.assertFalse(history.eligible_cancellation_ids(
            [queued], actor="alice", approved_hosts=allowed, batches_enabled=True))
        self.assertTrue(self.store.record_cancellation(
            "job", "alice", running, via="mcp", reason="Stop running task"))
        self.assertEqual(self.store.get("alice", running)["status"], "running")
        self.assertTrue(self.store.get("alice", running)["cancellation_requested"])
        self.store.finish(running, "succeeded", exit_code=0)
        self.assertEqual(self.store.get("alice", running)["status"], "succeeded")
        self.assertFalse(history.eligible_cancellation_ids(
            [running], actor="alice", approved_hosts=allowed, batches_enabled=True))

    def test_queued_cancellation_logs_only_after_committed_audit(self):
        queued = self.job()
        with patch("app.jobs.LOG.info") as info:
            self.assertTrue(self.store.record_cancellation(
                "job", "alice", queued, via="history",
                reason="Sensitive audit reason is not a log label",
            ))
            self.assertFalse(self.store.record_cancellation(
                "job", "alice", queued, via="mcp", reason="Duplicate"))
        info.assert_called_once()
        self.assertEqual(info.call_args.args[0], "ssh_mcp_job_completed %s")
        payload = json.loads(info.call_args.args[1])
        self.assertEqual(payload, {
            "server": "demo-node-b", "status": "cancelled",
            "failure_kind": "none", "elapsed_seconds": None,
        })
        self.assertNotIn("Sensitive audit reason", str(info.call_args))

        failed = self.job()
        with self.store._connect() as db:
            db.execute("""CREATE TRIGGER reject_cancel_log_before_commit
                          BEFORE INSERT ON cancellation_requests
                          BEGIN SELECT RAISE(ABORT,'synthetic insert failure'); END""")
        with patch("app.jobs.LOG.info") as info:
            with self.assertRaises(sqlite3.IntegrityError):
                self.store.record_cancellation(
                    "job", "alice", failed, via="history",
                    reason="Do not log a rolled back cancellation",
                )
        info.assert_not_called()
        self.assertEqual(self.store.get("alice", failed)["status"], "queued")
        self.assertIsNone(self.audit("job", failed))

    def test_queued_cancellation_survives_store_reopen_without_restarting(self):
        queued = self.job()
        self.assertTrue(self.store.record_cancellation(
            "job", "alice", queued, via="history",
            reason="Cancelled before first SSH command"))
        reopened = JobStore(self.store.path, retention_seconds=3600)
        self.assertEqual(reopened.get("alice", queued)["status"], "cancelled")
        self.assertFalse(reopened.begin(queued))
        from app.history import HistoryStore
        self.assertEqual(
            HistoryStore(reopened).cancellation_request(queued)["requested_via"],
            "history",
        )
