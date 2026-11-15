"""TEST-210 isolation, private Prometheus metrics, online backup and restore."""
from __future__ import annotations

import asyncio
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

os.environ.setdefault("MCP_ISSUER", "http://localhost")
os.environ.setdefault("MCP_LOGIN_KEY", "synthetic-test-login-" + "a" * 40)
os.environ.setdefault("MCP_TOKEN_SIGNING_SECRET", "synthetic-test-signing-" + "b" * 40)
os.environ.setdefault("MCP_CIMD_VALIDATE_REMOTE", "false")

from app.contracts import ExecuteCommandRequest
from app.jobs import JobStore
from app.oauth_sessions import SessionStore
from app.observability import create_observability_router
from ops import history_db
from ops.history_db import backup, restore, verify
from app import main as main_app


class OperationalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / "private"
        self.state.mkdir(mode=0o700)
        self.db = self.state / "jobs.sqlite"
        self.store = JobStore(self.db)
        self.secret = "metrics-" + "m" * 45

    def job(self, *, status: str = "succeeded") -> str:
        req = ExecuteCommandRequest(
            server="demo-node-b", argv=["hostname", "-s"],
            reason="Safe synthetic operations fixture", timeout_seconds=3
        )
        job_id = self.store.create("test-actor", req)
        self.store.begin(job_id)
        self.store.append(job_id, "stdout", b"synthetic-response\n")
        self.store.finish(job_id, status, exit_code=0, elapsed=0.01)
        return job_id

    def client(self) -> TestClient:
        app = FastAPI()
        app.include_router(create_observability_router(self.store, self.secret))
        return TestClient(app)

    def test_metrics_are_token_required_and_do_not_leak_commands(self):
        self.job()
        self.job(status="failed")
        with self.client() as client:
            self.assertEqual(client.get("/metrics").status_code, 401)
            self.assertEqual(client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code, 401)
            ok = client.get("/metrics", headers={"Authorization": "Bearer " + self.secret})
            self.assertEqual(ok.status_code, 200)
            self.assertIn('ssh_mcp_jobs{status="succeeded"} 1', ok.text)
            self.assertIn('ssh_mcp_jobs{status="failed"} 1', ok.text)
            self.assertIn("ssh_mcp_history_records 2", ok.text)
            self.assertIn(
                'ssh_mcp_jobs_completed_total{server="demo-node-b",'
                'status="succeeded",failure_kind="none"} 1', ok.text,
            )
            self.assertIn(
                'ssh_mcp_jobs_completed_total{server="demo-node-b",'
                'status="failed",failure_kind="none"} 1', ok.text,
            )
            self.assertIn(
                'ssh_mcp_job_duration_seconds_bucket'
                '{server="demo-node-b",le="+Inf"} 2', ok.text,
            )
            self.assertIn(
                'ssh_mcp_job_duration_seconds_count{server="demo-node-b"} 2',
                ok.text,
            )
            self.assertNotIn("hostname", ok.text)
            self.assertNotIn("test-actor", ok.text)
            self.assertEqual(ok.headers["Cache-Control"], "no-store")

    def test_metrics_fail_closed_for_storage_errors_and_bad_token(self):
        with self.assertRaises(RuntimeError):
            create_observability_router(self.store, "short")
        with self.assertRaises(RuntimeError):
            create_observability_router(self.store, os.environ["MCP_LOGIN_KEY"])
        with self.client() as client, patch.object(self.store, "_connect", side_effect=OSError("hidden path")):
            response = client.get("/metrics", headers={"Authorization": "Bearer " + self.secret})
            self.assertEqual(response.status_code, 503)
            self.assertNotIn("hidden path", response.text)

    def test_ready_checks_db_without_spilling_exceptions(self):
        class Registry:
            store = self.store

        with patch.dict(main_app._job_registry, {"jobs": Registry()}):
          with patch.object(main_app, "session_store", return_value=SessionStore(self.db)):
            self.assertEqual(asyncio.run(main_app.ready()), {"status": "ok"})
            with patch.object(self.store, "_connect", side_effect=OSError("secrets")):
                with self.assertRaises(HTTPException) as error:
                    asyncio.run(main_app.ready())
                self.assertEqual(error.exception.status_code, 503)
                self.assertNotIn("secrets", error.exception.detail)

    def test_online_backup_and_offline_restore_with_pre_restore_snapshot(self):
        first = self.job()
        backups = self.root / "backups"
        backups.mkdir(mode=0o700)
        original = backups / "snapshot.sqlite"
        backup(self.db, original)
        verify(original)
        self.assertEqual(original.stat().st_mode & 0o777, 0o600)
        self.job(status="failed")
        with closing(sqlite3.connect(self.db)) as live:
            self.assertEqual(live.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 2)
        previous = restore(original, self.db, service_stopped=True)
        self.assertIsNotNone(previous)
        verify(previous)
        with closing(sqlite3.connect(self.db)) as restored:
            self.assertEqual(restored.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 1)
            self.assertEqual(restored.execute("SELECT id FROM jobs").fetchone()[0], first)
        with closing(sqlite3.connect(previous)) as rollback:
            self.assertEqual(rollback.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 2)

    def test_concurrent_backups_never_replace_an_existing_snapshot(self):
        self.job()
        backups = self.root / "backups"
        backups.mkdir(mode=0o700)
        destination = backups / "same-name.sqlite"
        barrier = Barrier(2)
        allocate = history_db._temporary

        def synchronize_publish(path):
            result = allocate(path)
            barrier.wait(timeout=10)
            return result

        with patch.object(history_db, "_temporary", side_effect=synchronize_publish):
            with ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(backup, self.db, destination)
                second = executor.submit(backup, self.db, destination)
                errors = []
                for future in (first, second):
                    try:
                        future.result(timeout=15)
                    except FileExistsError as error:
                        errors.append(error)
        self.assertEqual(len(errors), 1)
        verify(destination)
        self.assertEqual(list(backups.glob(".skymcp-*")), [])

    def test_backup_and_restore_remove_temporary_sqlite_sidecars(self):
        self.job()
        backups = self.root / "backups"
        backups.mkdir(mode=0o700)
        snapshot = backups / "snapshot.sqlite"
        restored = self.state / "restored.sqlite"
        temps: list[Path] = []
        allocate = history_db._temporary
        sync = history_db._sync_directory

        def capture_temporary(destination):
            fd, temp = allocate(destination)
            temps.append(temp)
            return fd, temp

        def simulate_leftover_sidecars(directory):
            # Sidecars can survive even after the last SQLite handle closes.
            for suffix in ("-wal", "-shm"):
                Path(str(temps[-1]) + suffix).touch(mode=0o600)
            sync(directory)

        with (
            patch.object(history_db, "_temporary", side_effect=capture_temporary),
            patch.object(history_db, "_sync_directory", side_effect=simulate_leftover_sidecars),
        ):
            backup(self.db, snapshot)
            restore(snapshot, restored, service_stopped=True)

        verify(snapshot)
        verify(restored)
        self.assertEqual(len(temps), 2)
        for temp in temps:
            with self.subTest(temp=temp):
                for suffix in ("", "-wal", "-shm"):
                    self.assertFalse(Path(str(temp) + suffix).exists())

    def test_backup_and_restore_clean_temporary_sidecars_after_failure(self):
        self.job()
        backups = self.root / "backups"
        backups.mkdir(mode=0o700)
        source = backups / "valid.sqlite"
        backup(self.db, source)
        temps: list[Path] = []
        allocate = history_db._temporary
        original_verify = history_db.verify

        def capture_temporary(destination):
            fd, temp = allocate(destination)
            temps.append(temp)
            return fd, temp

        def fail_temporary_verification(path):
            if path.name.startswith(".skymcp-"):
                for suffix in ("-wal", "-shm"):
                    Path(str(path) + suffix).touch(mode=0o600)
                raise ValueError("synthetic temporary verification failure")
            original_verify(path)

        failed_backup = backups / "failed.sqlite"
        failed_restore = self.state / "failed-restore.sqlite"
        with (
            patch.object(history_db, "_temporary", side_effect=capture_temporary),
            patch.object(history_db, "verify", side_effect=fail_temporary_verification),
        ):
            with self.assertRaisesRegex(ValueError, "synthetic temporary verification failure"):
                backup(self.db, failed_backup)
            with self.assertRaisesRegex(ValueError, "synthetic temporary verification failure"):
                restore(source, failed_restore, service_stopped=True)

        self.assertFalse(failed_backup.exists())
        self.assertFalse(failed_restore.exists())
        self.assertEqual(len(temps), 2)
        for temp in temps:
            with self.subTest(temp=temp):
                for suffix in ("", "-wal", "-shm"):
                    self.assertFalse(Path(str(temp) + suffix).exists())
        verify(source)

    def test_restore_rejects_dangling_wal_and_shm_symlinks(self):
        self.job()
        snapshot = self.root / "snapshot.sqlite"
        backup(self.db, snapshot)
        # Use an unused destination so no active SQLite writer/sidecar is touched.
        restored = self.state / "restored.sqlite"
        for suffix in ("-wal", "-shm"):
            with self.subTest(suffix=suffix):
                sidecar = Path(str(restored) + suffix)
                sidecar.symlink_to(self.root / ("missing" + suffix))
                try:
                    self.assertFalse(sidecar.exists())
                    self.assertTrue(sidecar.is_symlink())
                    with self.assertRaisesRegex(ValueError, "Existing SQLite WAL/SHM"):
                        restore(snapshot, restored, service_stopped=True)
                    self.assertFalse(restored.exists())
                finally:
                    sidecar.unlink()

    def test_restore_requires_stopped_service_and_refuses_wal(self):
        self.job()
        snapshot = self.root / "snapshot.sqlite"
        backup(self.db, snapshot)
        with self.assertRaises(ValueError):
            restore(snapshot, self.db, service_stopped=False)
        wal = Path(str(self.db) + "-wal")
        wal.touch(mode=0o600)
        with self.assertRaises(ValueError):
            restore(snapshot, self.db, service_stopped=True)
        wal.unlink()

    def test_backups_are_private_and_fail_closed(self):
        self.job()
        snapshot = self.root / "snapshot.sqlite"
        backup(self.db, snapshot)
        with self.assertRaises(FileExistsError):
            backup(self.db, snapshot)
        invalid = self.root / "invalid.sqlite"
        invalid.write_bytes(b"not a database")
        invalid.chmod(0o600)
        with self.assertRaises(sqlite3.DatabaseError):
            verify(invalid)
        link = self.root / "link.sqlite"
        link.symlink_to(snapshot)
        with self.assertRaises(ValueError):
            verify(link)
        with self.assertRaises(ValueError):
            restore(snapshot, link, service_stopped=True)
        public = self.root / "public"
        public.mkdir(mode=0o755)
        public.chmod(0o755)  # A restrictive process umask must not hide the bad mode.
        with self.assertRaises(ValueError):
            backup(self.db, public / "copy.sqlite")


if __name__ == "__main__":
    unittest.main()
