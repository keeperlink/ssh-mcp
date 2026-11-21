#!/usr/bin/env python3
"""Manual, idempotent SKY-344 audit-actor migration. Never invoked at startup.

Dry-run is read-only. Apply requires an independently stopped service, a new
SQLite online-backup snapshot and per-table source equality before transaction.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import sqlite3

from .client_registry import offline_client, parse_clients

TABLES = ("jobs", "command_batches", "file_operations")
SUBJECT = "ssh-mcp-operator"


def actor_for(client_id: str) -> str:
    return SUBJECT + "@" + hashlib.sha256(client_id.encode("utf-8")).hexdigest()


def _configured(config_path: Path) -> tuple[str, dict[str, str]]:
    document = json.loads(config_path.read_text(encoding="utf-8"))
    entries = parse_clients(document["clients"])
    legacy = offline_client(entries)
    if legacy is None:
        raise ValueError("Migration requires an explicit HTTPS offline legacy client")
    client_id, _redirects = legacy
    known = {identity: name for name, spec in entries.items()
             for identity in spec["identities"]}
    return client_id, known


def _tables(db: sqlite3.Connection) -> list[str]:
    available = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    selected = [t for t in TABLES if t in available]
    if not selected:
        raise ValueError("No audit tables found")
    for table in selected:
        columns = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
        if not {"id", "actor", "client_id"} <= columns:
            raise ValueError(f"Missing migrated client_id or actor column in {table}")
    return selected


def _changes(db: sqlite3.Connection, chat: str, known: dict[str, str]
             ) -> tuple[list[tuple[str, str, str, str]], dict[str, Counter[str]]]:
    backward = {actor_for(client_id): client_id for client_id in known}
    mutations = []
    counters = {}
    for table in _tables(db):
        stats: Counter[str] = Counter()
        for row_id, actor, cid in db.execute(f"SELECT id,actor,client_id FROM {table}"):
            stats["rows"] += 1
            if cid:
                wanted = actor_for(cid)
                if actor not in (SUBJECT, wanted):
                    stats["inconsistent_actor"] += 1
                    # Do not silently relabel a record authenticated for another client.
                    continue
                source = cid
            elif actor == SUBJECT:
                source = chat  # Explicit operator-approved legacy attribution decision.
                stats["assumed_chatgpt"] += 1
            elif actor in backward:
                source = backward[actor]
                stats["recovered_hash"] += 1
            else:
                stats["unknown_unchanged"] += 1
                continue
            wanted = actor_for(source)
            if actor != wanted or cid != source:
                mutations.append((table, row_id, wanted, source))
                stats["updates"] += 1
            else:
                stats["already_normalized"] += 1
        counters[table] = stats
    if any(stats["inconsistent_actor"] for stats in counters.values()):
        raise ValueError("Inconsistent actor/client_id records: manual investigation required")
    return mutations, counters


def _fingerprints(db: sqlite3.Connection, tables: list[str]) -> dict[str, str]:
    fingerprints = {}
    for table in tables:
        h = hashlib.sha256()
        for row in db.execute(f"SELECT id,actor,client_id FROM {table} ORDER BY id"):
            h.update(json.dumps(row, separators=(",", ":"), ensure_ascii=False).encode())
            h.update(b"\n")
        fingerprints[table] = h.hexdigest()
    return fingerprints


def migrate(db_path: Path, config_path: Path, *, apply: bool = False,
            backup_path: Path | None = None, confirm_stopped: bool = False
            ) -> dict[str, dict[str, int]]:
    legacy_client, known = _configured(config_path)
    if not db_path.is_file() or not db_path.resolve().is_file():
        raise ValueError("Existing SQLite DB path required")
    if not apply:
        uri = db_path.resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True) as db:
            changed, stats = _changes(db, legacy_client, known)
            assert sum(s["updates"] for s in stats.values()) == len(changed)
        return {table: dict(counter) for table, counter in stats.items()}
    if not confirm_stopped or backup_path is None:
        raise ValueError("Apply requires --confirm-stopped and --backup")
    if backup_path.resolve() == db_path.resolve():
        raise ValueError("Backup must differ from source")
    # Existing backups must never be overwritten, even on a repeat run.
    fd = os.open(backup_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    try:
        with sqlite3.connect(db_path) as db:
            tables = _tables(db)
            expected = _fingerprints(db, tables)
            with sqlite3.connect(backup_path) as snapshot:
                db.backup(snapshot)
                if snapshot.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise ValueError("SQLite backup integrity failed")
                if _fingerprints(snapshot, tables) != expected:
                    raise ValueError("Backup changed during capture")
            db.execute("BEGIN IMMEDIATE")
            try:
                if _fingerprints(db, tables) != expected:
                    raise ValueError("Audit source changed since backup; retry from stopped service")
                changes, stats = _changes(db, legacy_client, known)
                for table, row_id, new_actor, client_id in changes:
                    db.execute(f"UPDATE {table} SET actor=?,client_id=? WHERE id=?",
                               (new_actor, client_id, row_id))
                if _changes(db, legacy_client, known)[0]:
                    raise ValueError("Post-migration verification failed")
                if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise ValueError("Post-migration database integrity failed")
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return {table: dict(counter) for table, counter in stats.items()}
    except BaseException:
        # Preserve backup even when apply fails; it is restricted to mode 0600.
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--backup", type=Path)
    parser.add_argument("--confirm-stopped", action="store_true")
    args = parser.parse_args()
    try:
        result = migrate(args.db, args.config, apply=args.apply,
                         backup_path=args.backup, confirm_stopped=args.confirm_stopped)
    except (ValueError, OSError, sqlite3.Error, KeyError, TypeError) as exc:
        parser.exit(2, f"Migration refused: {exc}\n")
    print(json.dumps({"mode": "apply" if args.apply else "dry_run", "tables": result},
                     sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
