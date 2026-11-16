"""Metadata-only file-operation audit, separate from command and output records.

No payload, patch, request envelope, decoded response or arbitrary error string
is ever inserted into the persistent database.
"""
from __future__ import annotations

import json
import re
import secrets
import sqlite3
import time
from pathlib import PurePosixPath
from typing import Any

from .conversation_access import conversation_id_context
from .approval_status import approval_status_context

KINDS = frozenset({"inspect", "read", "write", "patch", "patch_preview", "upload", "download"})
FILE_STATES = frozenset({"running", "succeeded", "failed", "partial", "unknown"})
_ERRORS = frozenset({
    "not_found", "permission_denied", "invalid_request", "invalid_protocol",
    "unsupported_operation", "payload_limit", "bootstrap_check_failed",
    "bootstrap_failed", "missing_python", "transport_error", "timeout",
    "output_limit", "invalid_response", "filesystem_error", "precondition_failed",
    "invalid_patch", "interrupted", "duplicate_operation", "invalid_cursor",
    "changed_file", "invalid_encoding", "response_limit", "already_exists", "partial",
    "source_unavailable",
})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{8,120}$")


def path_summary(path: str) -> str:
    """Only store a bounded leaf name, not arbitrary user-supplied full paths."""
    leaf = PurePosixPath(path.rstrip("/")).name or "/"
    return leaf[:96]


def init_file_schema(db: sqlite3.Connection) -> None:
    db.executescript("""
        CREATE TABLE IF NOT EXISTS file_operations(
            id TEXT PRIMARY KEY,
            actor TEXT NOT NULL,
            server TEXT NOT NULL,
            operation_kind TEXT NOT NULL,
            path_summary TEXT NOT NULL,
            story_id TEXT,
            conversation_id TEXT,
            status TEXT NOT NULL,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            started_at REAL NOT NULL,
            ended_at REAL,
            elapsed_seconds REAL,
            byte_count INTEGER NOT NULL DEFAULT 0,
            error_code TEXT,
            approval_status INTEGER,
            operation_id TEXT,
            result_metadata TEXT
        );
        CREATE INDEX IF NOT EXISTS file_operations_created
            ON file_operations(created_at DESC,id DESC);
        CREATE INDEX IF NOT EXISTS file_operations_updated
            ON file_operations(updated_at,id);
    """)
    existing = {row["name"] for row in db.execute("PRAGMA table_info(file_operations)")}
    if "conversation_id" not in existing:
        db.execute("ALTER TABLE file_operations ADD COLUMN conversation_id TEXT")
    if "approval_status" not in existing:
        db.execute("ALTER TABLE file_operations ADD COLUMN approval_status INTEGER")
    if "operation_id" not in existing:
        db.execute("ALTER TABLE file_operations ADD COLUMN operation_id TEXT")
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS file_operations_replay_id "
               "ON file_operations(operation_id) WHERE operation_id IS NOT NULL")
    # Rollback images retain jobs.sqlite but used the caller replay ID as the
    # *primary key*. That earlier INSERT does not populate operation_id; the
    # index alone cannot prevent replay after downgrade. Keep this guard in
    # SQLite so the old executable also refuses an already-reserved key.
    db.executescript("""
        CREATE TRIGGER IF NOT EXISTS file_operations_rollback_replay_guard
        BEFORE INSERT ON file_operations
        WHEN EXISTS (
            SELECT 1 FROM file_operations WHERE operation_id=NEW.id
        )
        BEGIN
            SELECT RAISE(ABORT, 'duplicate_operation');
        END;
    """)
    rebuild_history_view(db)
    # A queued approval never started SSH; an already running file operation
    # may have mutated its target before the restart.
    now = time.time()
    db.execute(
        """UPDATE file_operations SET status='failed',error_code='authorization',
           updated_at=?,ended_at=? WHERE status IN ('awaiting_approval','queued')""",
        (now, now),
    )
    db.execute(
        """UPDATE file_operations SET status='unknown',error_code='interrupted',
           updated_at=?,ended_at=?,elapsed_seconds=?-started_at
           WHERE status='running'""", (now, now, now),
    )


def rebuild_history_view(db: sqlite3.Connection) -> None:
    """Keep command/file history plus terminal pre-execution batch requests."""
    batch_exists = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='command_batches'"
    ).fetchone() is not None
    batch_columns = (
        {row["name"] for row in db.execute("PRAGMA table_info(command_batches)")}
        if batch_exists else set()
    )
    # A legacy batch table may not have finished its additive migration yet.
    # BatchStore upgrades it and rebuilds this projection afterwards.
    batches = {
        "id", "actor", "server", "story_id", "conversation_id", "reason",
        "privileged", "failure_kind", "total_steps", "status", "created_at",
        "updated_at", "ended_at",
    } <= batch_columns
    batch_code = "approval_status" if "approval_status" in batch_columns else "NULL"
    batch_username = "ssh_username" if "ssh_username" in batch_columns else "NULL"
    batch_sql = f"""
          UNION ALL
          SELECT 'batch_'||id,actor,server,'execute_commands',total_steps,'',
                 privileged,{batch_username},0,failure_kind,
                 CASE WHEN status='rejected' THEN 'failed' ELSE status END,
                 created_at,updated_at,
                 NULL,ended_at,NULL,NULL,NULL,NULL,
                 CASE WHEN status='denied' THEN 'Approval denied'
                      WHEN failure_kind='cwd_denied' THEN
                           'Working-directory access denied during preflight; no batch steps ran'
                      WHEN failure_kind='cwd_preflight' THEN
                           'Working-directory preflight failed; no batch steps ran'
                      WHEN failure_kind='pre_execution_rejected' THEN
                           'SSH request rejected before command execution; no batch steps ran'
                      WHEN {batch_code} IS NULL THEN
                           'Approval unavailable before batch execution'
                      ELSE 'Approved batch was not scheduled' END,
                 0,0,'batch',story_id,conversation_id,
                 json_object('reason',substr(reason,1,200),'server',server,
                             'total_steps',total_steps),
                 'batch','execute_commands',NULL,0,NULL,NULL,{batch_code}
          FROM command_batches AS b
          WHERE status IN ('denied','rejected')
            AND NOT EXISTS (
              SELECT 1 FROM command_batch_steps AS step
              WHERE step.batch_id=b.id AND step.status!='not_attempted'
            )
            AND NOT EXISTS (
              -- A proven pre-execution rejected child is already a failed
              -- command History event. Other parent rejection causes retain
              -- their existing synthetic approval/scheduling projection.
              SELECT 1 FROM command_batch_steps AS step
              JOIN jobs AS child ON child.id=step.job_id
              WHERE step.batch_id=b.id AND child.status='failed'
                AND child.failure_kind='pre_execution_rejected'
            )
    """ if batches else ""
    db.execute("DROP VIEW IF EXISTS history_events")
    db.executescript("""
        CREATE VIEW history_events AS
          SELECT id,actor,server,command,argv_count,command_sha256,privileged,
                 ssh_username,root_started,failure_kind,status,created_at,updated_at,
                 started_at,ended_at,exit_code,exit_accepted,effective_cwd,
                 elapsed_seconds,error,output_bytes,cancel_requested,mode,
                 story_id,conversation_id,request_json,
                 'command' AS record_kind,NULL AS operation_kind,NULL AS path_summary,
                 0 AS byte_count,NULL AS error_code,NULL AS result_metadata,
                 approval_status
          FROM jobs
          UNION ALL
          SELECT 'file_'||id,actor,server,operation_kind,0,'',0,NULL,NULL,NULL,status,
                 created_at,updated_at,
                 CASE WHEN status IN ('awaiting_approval','queued','denied')
                           OR (status='failed' AND error_code IN
                               ('authorization','duplicate_operation'))
                      THEN NULL ELSE started_at END,
                 ended_at,NULL,NULL,NULL,elapsed_seconds,
                 COALESCE(error_code,''),0,0,'file',story_id,conversation_id,NULL,
                 'file',operation_kind,path_summary,byte_count,error_code,result_metadata,
                 approval_status
          FROM file_operations
    """ + batch_sql + ";")


class FileAudit:
    def __init__(self, store: Any):
        self.store = store

    def operation_id_exists(self, identifier: str) -> bool:
        """Reject already-executed caller IDs before a new approval prompt."""
        with self.store._connect() as db:
            return db.execute(
                "SELECT 1 FROM file_operations WHERE id=? OR operation_id=?",
                (identifier, identifier),
            ).fetchone() is not None

    def replay_history_id(self, actor: str, identifier: str) -> str | None:
        """Resolve the authorized caller's legacy or new replay key to History."""
        with self.store._connect() as db:
            row = db.execute(
                """SELECT id FROM file_operations
                   WHERE actor=? AND (id=? OR operation_id=?)""",
                (actor, identifier, identifier),
            ).fetchone()
        return "file_" + str(row["id"]) if row is not None else None

    def reject_unscheduled(self, identifier: str) -> None:
        """Terminalize an approved file request rejected before remote dispatch."""
        now = time.time()
        with self.store._connect() as db:
            updated = db.execute(
                """UPDATE file_operations SET status='failed',
                   error_code='authorization', updated_at=?,ended_at=?
                   WHERE id=? AND status='queued'
                   AND approval_status IS NOT NULL""",
                (now, now, identifier),
            )
            if updated.rowcount != 1:
                raise RuntimeError("File pre-execution audit cannot be finalized")

    def reserve(self, actor: str, server: str, kind: str,
                path: str, story_id: str | None) -> str:
        """Create the safe metadata record before an operator begins waiting.

        A random audit identity never consumes the caller's replay-protected
        operation_id if this request ends in denial.
        """
        if kind not in KINDS:
            raise ValueError("Unsupported file operation kind")
        identifier = secrets.token_urlsafe(18)
        now = time.time()
        with self.store._connect() as db:
            db.execute(
                """INSERT INTO file_operations
                (id,actor,server,operation_kind,path_summary,story_id,conversation_id,
                 status,created_at,updated_at,started_at)
                VALUES(?,?,?,?,?,?,?,'awaiting_approval',?,?,?)""",
                (identifier, actor, server, kind, path_summary(path), story_id,
                 conversation_id_context.get(), now, now, now),
            )
        return identifier

    def settle_approval(self, identifier: str, code: int | None, *,
                        denied: bool = False) -> None:
        if not denied and code is None:
            raise ValueError("Approved file operation needs an approval code")
        status = ("denied" if code is not None else "failed") if denied else "queued"
        now = time.time()
        with self.store._connect() as db:
            result = db.execute(
                """UPDATE file_operations SET status=?,approval_status=?,
                   error_code=?,ended_at=?,updated_at=?
                   WHERE id=? AND status='awaiting_approval' AND approval_status IS NULL""",
                (status, code, "authorization" if denied else None,
                 now if denied else None, now, identifier),
            )
            if result.rowcount != 1:
                raise RuntimeError("File approval audit cannot be finalized")

    def start(self, actor: str, server: str, kind: str, path: str,
              story_id: str | None, operation_id: str | None = None,
              *, precreated_id: str | None = None) -> str:
        if kind not in KINDS:
            raise ValueError("Unsupported file operation kind")
        # The durable history identity must never change after reservation.
        # A caller's replay ID is an independent unique field.
        identifier = precreated_id or operation_id or secrets.token_urlsafe(18)
        if not _IDENTIFIER.fullmatch(identifier):
            raise ValueError("Invalid file operation identifier")
        if operation_id is not None and not _IDENTIFIER.fullmatch(operation_id):
            raise ValueError("Invalid file operation identifier")
        now = time.time()
        try:
            with self.store._connect() as db:
                if precreated_id is not None:
                    # Preserve the previously exposed History ID; reserve
                    # the replay key under the same SQLite write lock.
                    db.execute("BEGIN IMMEDIATE")
                    if (operation_id is not None and db.execute(
                        """SELECT 1 FROM file_operations
                           WHERE id=? OR operation_id=?""",
                        (operation_id, operation_id),
                    ).fetchone() is not None):
                        raise sqlite3.IntegrityError("duplicate_operation")
                    changed = db.execute(
                        """UPDATE file_operations SET operation_id=?,status='running',
                           started_at=?,updated_at=?
                           WHERE id=? AND actor=? AND status='queued'
                           AND approval_status IS NOT NULL""",
                        (operation_id, now, now, precreated_id, actor),
                    )
                    if changed.rowcount != 1:
                        raise RuntimeError("Reserved file operation was not approved")
                    db.execute("COMMIT")
                    return identifier
                db.execute(
                    "INSERT INTO file_operations "
                    "(id,actor,server,operation_kind,path_summary,story_id,conversation_id,status,"
                    " created_at,updated_at,started_at,approval_status,operation_id)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (identifier,actor,server,kind,path_summary(path),story_id,
                     conversation_id_context.get(),
                     "running",now,now,now,approval_status_context.get(),operation_id),
                )
        except sqlite3.IntegrityError:
            if precreated_id is not None:
                # Preserve this rejected pre-execution row under its separate
                # random audit ID; an existing operation_id may not be reused.
                with self.store._connect() as db:
                    db.execute(
                        """UPDATE file_operations SET status='failed',updated_at=?,
                           ended_at=?,error_code='duplicate_operation'
                           WHERE id=? AND status='queued'""",
                        (now, now, precreated_id),
                    )
            raise ValueError("duplicate_operation") from None
        return identifier

    def finish(self, identifier: str, status: str, *, byte_count: int = 0,
               error_code: str | None = None, outcomes: list[dict[str, Any]] | None = None,
               transfer: dict[str, Any] | None = None) -> None:
        if status not in FILE_STATES - {"running"}:
            raise ValueError("Invalid file operation result")
        if error_code is not None and error_code not in _ERRORS:
            error_code = "filesystem_error"
        if not 0 <= byte_count <= 2**63 - 1:
            raise ValueError("Invalid byte count")
        safe: list[dict[str, Any]] = []
        for outcome in (outcomes or [])[:100]:
            state = outcome.get("status")
            if state not in {"applied", "failed", "not_attempted", "applicable", "unchanged"}:
                raise ValueError("Invalid per-path result")
            action = outcome.get("action")
            moved = outcome.get("moved_to")
            safe.append({
                "path": path_summary(str(outcome.get("path", ""))),
                "action": action if action in {"add", "update", "delete"} else None,
                "moved_to": path_summary(moved) if isinstance(moved, str) else None,
                "status": state,
                "bytes": max(0, min(int(outcome.get("bytes", 0)), 2**63 - 1)),
                "error_code": (outcome.get("error_code")
                               if outcome.get("error_code") in _ERRORS else None),
                "hash_error_code": (outcome.get("hash_error_code")
                                    if outcome.get("hash_error_code") in _ERRORS else None),
            })
        safe_metadata: dict[str, Any] = {"outcomes": safe}
        if transfer is not None:
            # A strict, fixed allowlist: never store signed ChatGPT URLs,
            # file IDs, full remote paths or any binary body.
            direction = transfer.get("direction")
            if direction not in {"upload", "download"}:
                raise ValueError("Invalid transfer direction")
            filtered: dict[str, Any] = {"direction": direction}
            for name in ("sha256", "chunk_sha256"):
                digest = transfer.get(name)
                if isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest):
                    filtered[name] = digest
            for name in ("size", "offset", "next_offset"):
                value = transfer.get(name)
                if type(value) is int and 0 <= value <= 2**63 - 1:
                    filtered[name] = value
            if type(transfer.get("eof")) is bool:
                filtered["eof"] = transfer["eof"]
            if transfer.get("mode") in {"create", "overwrite"}:
                filtered["mode"] = transfer["mode"]
            safe_metadata["transfer"] = filtered
        now = time.time()
        with self.store._connect() as db:
            db.execute(
                "UPDATE file_operations SET status=?,updated_at=?,ended_at=?,"
                " elapsed_seconds=?-started_at,byte_count=?,error_code=?,result_metadata=?"
                " WHERE id=? AND status='running'",
                (status, now, now, now, byte_count, error_code,
                 json.dumps(safe_metadata, separators=(",", ":"))
                 if safe or transfer is not None else None, identifier),
            )

    def get(self, actor: str, identifier: str) -> dict[str, Any] | None:
        with self.store._connect() as db:
            row = db.execute("SELECT id,status,operation_kind,path_summary,server,story_id,"
                             " byte_count,error_code FROM file_operations "
                             "WHERE (id=? OR operation_id=?) AND actor=?",
                             (identifier, identifier, actor)).fetchone()
        return dict(row) if row is not None else None
