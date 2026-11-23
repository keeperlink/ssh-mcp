"""Synthetic v1 audit-to-sealed Console cutover and rollback acceptance."""
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from app.config import _verify_sealed_database
from app.history import HistoryStore, ViewerAuth
from app.jobs import JobStore
from app.sealed_credentials import create_verifier
from ops.history_db import (
    CutoverUncertain, backup, checkpoint_for_restore, cutover, restore, verify,
)


PASSWORD = "synthetic-console-cutover-password"
GENERATION = "e" * 32
LEGACY_COLUMNS = {"id", "salt", "verifier", "generation"}
SEALED_COLUMNS = {"id", "generation"}


class SealedCutoverTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="sky347-sqlite-cutover-")
        self.addCleanup(temp.cleanup)
        folder = Path(temp.name) / "private"
        folder.mkdir(mode=0o700)
        self.db = folder / "jobs.sqlite"
        self.backup = folder / "pre-sealed-backup.sqlite"
        self.store = JobStore(self.db)
        self.viewer = ViewerAuth(HistoryStore(self.store), PASSWORD)
        self.cookie = self.viewer.login("operator", PASSWORD)
        self.assertIsNotNone(self.cookie)
        self.assertEqual(self.columns(), LEGACY_COLUMNS)

    def columns(self):
        with closing(sqlite3.connect(self.db)) as db:
            return {row[1] for row in db.execute(
                "PRAGMA table_info(history_auth_state)"
            )}

    def snapshot(self):
        return (self.db.read_bytes(), self.columns())

    def test_sealed_start_refuses_legacy_database_without_modifying_it(self):
        before = self.snapshot()
        with patch.dict("os.environ", {"SSH_JOBS_DB": str(self.db)}):
            with self.assertRaisesRegex(RuntimeError, "offline sealed cutover"):
                _verify_sealed_database()
        with self.assertRaisesRegex(RuntimeError, "offline sealed cutover"):
            ViewerAuth(HistoryStore(self.store), "",
                       verifier=create_verifier(PASSWORD, "console-login"),
                       generation=GENERATION)
        self.assertEqual(self.snapshot(), before)
        self.assertTrue(self.viewer.valid(self.cookie))

    def test_explicit_cutover_preserves_backup_and_revokes_old_console_sessions(self):
        cutover(self.db, self.backup, GENERATION, service_stopped=True)
        with patch.dict("os.environ", {"SSH_JOBS_DB": str(self.db)}):
            _verify_sealed_database()
        verify(self.backup)
        self.assertEqual(self.columns(), SEALED_COLUMNS)
        self.assertTrue(self.backup.is_file())
        with closing(sqlite3.connect(self.backup)) as saved:
            self.assertEqual({r[1] for r in saved.execute(
                "PRAGMA table_info(history_auth_state)"
            )}, LEGACY_COLUMNS)
        with closing(sqlite3.connect(self.db)) as active:
            row = active.execute(
                "SELECT generation FROM history_auth_state WHERE id=1"
            ).fetchone()
            self.assertEqual(row, (GENERATION,))
            self.assertEqual(active.execute(
                "SELECT COUNT(*) FROM history_sessions"
            ).fetchone(), (0,))
        sealed = ViewerAuth(HistoryStore(self.store), "",
                            verifier=create_verifier(PASSWORD, "console-login"),
                            generation=GENERATION)
        self.assertFalse(sealed.valid(self.cookie))
        new_cookie = sealed.login("operator", PASSWORD)
        self.assertTrue(sealed.valid(new_cookie))
        self.assertFalse(self.viewer.valid(new_cookie))

    def test_recovery_snapshot_restores_legacy_schema_without_reviving_cookies(self):
        cutover(self.db, self.backup, GENERATION, service_stopped=True)
        sealed = ViewerAuth(HistoryStore(self.store), "",
                            verifier=create_verifier(PASSWORD, "console-login"),
                            generation=GENERATION)
        new_cookie = sealed.login("operator", PASSWORD)
        self.assertTrue(sealed.valid(new_cookie))
        # Restore into a separate recovery path, not a still-open test DB.
        recovered = self.db.parent / "recovered.sqlite"
        restore(self.backup, recovered, service_stopped=True)
        with closing(sqlite3.connect(recovered)) as restored_db:
            self.assertEqual({row[1] for row in restored_db.execute(
                "PRAGMA table_info(history_auth_state)"
            )}, LEGACY_COLUMNS)
        restored = ViewerAuth(HistoryStore(JobStore(recovered)), PASSWORD)
        self.assertFalse(restored.valid(self.cookie))
        self.assertFalse(restored.valid(new_cookie))

    def test_missing_stop_confirmation_or_bad_generation_preserves_source(self):
        before = self.snapshot()
        for stopped, generation in ((False, GENERATION), (True, "invalid")):
            with self.subTest(stopped=stopped, generation=generation):
                with self.assertRaises(ValueError):
                    cutover(self.db, self.backup, generation,
                            service_stopped=stopped)
        self.assertEqual(before, self.snapshot())
        self.assertFalse(self.backup.exists())

    def test_snapshot_failure_preserves_existing_legacy_database(self):
        before = self.snapshot()
        with patch("ops.history_db.backup", side_effect=OSError("synthetic I/O")):
            with self.assertRaises(OSError):
                cutover(self.db, self.backup, GENERATION,
                        service_stopped=True)
        self.assertEqual(before, self.snapshot())
        self.assertFalse(self.backup.exists())

    def test_cutover_closes_read_only_schema_probes(self):
        from ops import history_db

        real_readonly = history_db._readonly
        opened = []

        class TrackedConnection:
            def __init__(self, connection):
                self.connection = connection
                self.closed = False

            def execute(self, *args):
                return self.connection.execute(*args)

            def close(self):
                self.closed = True
                self.connection.close()

            def __getattr__(self, key):
                return getattr(self.connection, key)

        def monitored(path):
            handle = TrackedConnection(real_readonly(path))
            opened.append(handle)
            return handle

        with patch.object(history_db, "_readonly", side_effect=monitored):
            cutover(self.db, self.backup, GENERATION, service_stopped=True)
        self.assertGreaterEqual(len(opened), 3)
        self.assertTrue(all(conn.closed for conn in opened))

    def test_commit_io_error_is_uncertain_not_safe_to_retry(self):
        from ops import history_db

        real_connect = history_db.sqlite3.connect

        class InterruptedCommit:
            def __init__(self, connection):
                self.connection = connection

            def execute(self, sql, *args):
                if sql == "COMMIT":
                    raise sqlite3.OperationalError("synthetic COMMIT I/O interruption")
                return self.connection.execute(sql, *args)

            def close(self):
                self.connection.close()

            def __getattr__(self, key):
                return getattr(self.connection, key)

        def connect(*args, **kwargs):
            connection = real_connect(*args, **kwargs)
            if args and args[0] == self.db and kwargs.get("isolation_level") is None:
                return InterruptedCommit(connection)
            return connection

        with patch.object(history_db.sqlite3, "connect", side_effect=connect):
            with self.assertRaisesRegex(CutoverUncertain, "COMMIT outcome"):
                cutover(self.db, self.backup, GENERATION, service_stopped=True)
        verify(self.backup)
        self.assertEqual(self.columns(), LEGACY_COLUMNS)
        with self.assertRaises((ValueError, FileExistsError)):
            cutover(self.db, self.backup, GENERATION, service_stopped=True)

    def test_refuse_repeated_cutover_and_protect_prior_backup(self):
        cutover(self.db, self.backup, GENERATION, service_stopped=True)
        first_backup = self.backup.read_bytes()
        after = self.snapshot()
        with self.assertRaises(ValueError):
            cutover(self.db, self.backup, GENERATION,
                    service_stopped=True)
        self.assertEqual(after, self.snapshot())
        self.assertEqual(self.backup.read_bytes(), first_backup)

    def test_snapshot_destination_must_not_be_reused(self):
        backup(self.db, self.backup)
        original = self.backup.read_bytes()
        before = self.snapshot()
        with self.assertRaises(FileExistsError):
            cutover(self.db, self.backup, GENERATION,
                    service_stopped=True)
        self.assertEqual(self.backup.read_bytes(), original)
        self.assertEqual(self.snapshot(), before)

    def test_checkpoint_refuses_without_stopped_service(self):
        with self.assertRaises(ValueError):
            checkpoint_for_restore(self.db, service_stopped=False)
        self.assertEqual(self.columns(), LEGACY_COLUMNS)

    def test_readonly_startup_preflight_fails_closed_on_orphan_journal(self):
        phantom = self.db.parent / "missing.sqlite"
        with patch.dict("os.environ", {"SSH_JOBS_DB": str(phantom)}):
            _verify_sealed_database()
            (self.db.parent / "missing.sqlite-wal").write_bytes(b"synthetic")
            with self.assertRaisesRegex(RuntimeError, "Orphan SQLite"):
                _verify_sealed_database()
        with patch.dict("os.environ", {"SSH_JOBS_DB": "relative.sqlite"}):
            with self.assertRaisesRegex(RuntimeError, "absolute"):
                _verify_sealed_database()

    def test_checkpoint_succeeds_when_all_database_handles_are_closed(self):
        isolated = self.db.parent / "offline.sqlite"
        with closing(sqlite3.connect(isolated)) as conn:
            conn.execute("CREATE TABLE fixture(value INTEGER)")
            conn.commit()
        isolated.chmod(0o600)
        checkpoint_for_restore(isolated, service_stopped=True)
        self.assertFalse(Path(str(isolated) + "-wal").exists())
        self.assertFalse(Path(str(isolated) + "-shm").exists())


if __name__ == "__main__":
    unittest.main()
