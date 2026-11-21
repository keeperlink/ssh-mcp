"""Synthetic all-table migration/rollback contract; never open live DBs."""
from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.audit_migration import actor_for, migrate

CHAT = "https://chat.example.test/client.json"
OTHER = "https://other.example.test/client.json"


class AuditActorMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dbpath = self.root / "jobs.sqlite"
        self.config = self.root / "service.json"
        self.config.write_text(json.dumps({"clients": {
             "ChatGPT": {"identities": [CHAT], "conversation_id": {"sources": []},
                        "offline_redirect_uris": ["https://chat.example.test/callback"]},
            "Other": {"identities": [OTHER], "conversation_id": {"sources": []}},
        }}))
        with sqlite3.connect(self.dbpath) as db:
            for table in ("jobs", "command_batches", "file_operations"):
                db.execute(f"CREATE TABLE {table}(id TEXT PRIMARY KEY, actor TEXT NOT NULL, client_id TEXT)")
                db.executemany(f"INSERT INTO {table}(id,actor,client_id) VALUES(?,?,?)", (
                    ("bare", "ssh-mcp-operator", None),
                    ("already", actor_for(CHAT), CHAT),
                    ("recover", actor_for(OTHER), None),
                    ("unknown", "ssh-mcp-operator@" + "a" * 64, None),
                    ("explicit", "ssh-mcp-operator", OTHER),
                ))

    def test_dry_run_then_apply_backup_and_idempotence(self) -> None:
        before = migrate(self.dbpath, self.config)
        self.assertEqual({x["updates"] for x in before.values()}, {3})
        self.assertEqual({x["assumed_chatgpt"] for x in before.values()}, {1})
        with sqlite3.connect(self.dbpath) as db:
            self.assertIsNone(db.execute("SELECT client_id FROM jobs WHERE id='bare'").fetchone()[0])
        backup = self.root / "before.sqlite"
        after = migrate(self.dbpath, self.config, apply=True,
                        backup_path=backup, confirm_stopped=True)
        self.assertEqual(before, after)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        with sqlite3.connect(self.dbpath) as db:
            for table in ("jobs", "command_batches", "file_operations"):
                rows = dict((x[0], (x[1], x[2])) for x in db.execute(
                    f"SELECT id,actor,client_id FROM {table}"))
                self.assertEqual(rows["bare"], (actor_for(CHAT), CHAT))
                self.assertEqual(rows["recover"], (actor_for(OTHER), OTHER))
                self.assertEqual(rows["explicit"], (actor_for(OTHER), OTHER))
                self.assertIsNone(rows["unknown"][1])
        self.assertTrue(all(x.get("updates", 0) == 0 for x in migrate(
            self.dbpath, self.config).values()))
        # Exact database rollback reverts the mutation, including all three tables.
        with sqlite3.connect(backup) as db:
            self.assertIsNone(db.execute("SELECT client_id FROM jobs WHERE id='bare'").fetchone()[0])
        with self.assertRaises(FileExistsError):
            migrate(self.dbpath, self.config, apply=True,
                    backup_path=backup, confirm_stopped=True)

    def test_invalid_actor_mismatch_fails_before_any_update(self) -> None:
        with sqlite3.connect(self.dbpath) as db:
            db.execute("UPDATE jobs SET actor=? WHERE id='explicit'", (actor_for(CHAT),))
        with self.assertRaisesRegex(ValueError, "Inconsistent actor"):
            migrate(self.dbpath, self.config, apply=True,
                    backup_path=self.root / "backup.sqlite", confirm_stopped=True)
        with sqlite3.connect(self.dbpath) as db:
            self.assertIsNone(db.execute("SELECT client_id FROM jobs WHERE id='bare'").fetchone()[0])

    def test_missing_table_or_client_column_is_rejected(self) -> None:
        without_tables = self.root / "empty.sqlite"
        with sqlite3.connect(without_tables) as db:
            db.execute("CREATE TABLE unrelated(id TEXT)")
        with self.assertRaisesRegex(ValueError, "No audit tables"):
            migrate(without_tables, self.config)
        missing_column = self.root / "unmigrated.sqlite"
        with sqlite3.connect(missing_column) as db:
            db.execute("CREATE TABLE jobs(id TEXT, actor TEXT)")
        with self.assertRaisesRegex(ValueError, "Missing migrated client_id"):
            migrate(missing_column, self.config)
        with self.assertRaisesRegex(ValueError, "Backup must differ"):
            migrate(self.dbpath, self.config, apply=True,
                    backup_path=self.dbpath, confirm_stopped=True)

    def test_malformed_config_and_missing_database_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            migrate(self.root / "missing.sqlite", self.config)
        self.config.write_text(json.dumps({"clients": {
            "ChatGPT": {"identities": ["dcr_" + "A" * 43], "conversation_id": {"sources": []},
                        "offline_redirect_uris": ["https://chat.example.test/callback"]},
        }}))
        with self.assertRaisesRegex(ValueError, "Invalid offline client"):
            migrate(self.dbpath, self.config)

    def test_requires_explicit_stop_and_backup(self) -> None:
        with self.assertRaisesRegex(ValueError, "confirm-stopped"):
            migrate(self.dbpath, self.config, apply=True)
        self.assertFalse((self.root / "before.sqlite").exists())


if __name__ == "__main__":
    unittest.main()
