"""Durable, actor-scoped SSH jobs.

The actor-scoped MCP job summaries expose only safe metadata; the private
SQLite audit also stores full raw requests and bounded stdout/stderr.
Treat this database as sensitive, including command arguments and reasons:
protect its directory and enforce the configured retention horizon.
"""
from __future__ import annotations

import asyncio
import calendar
import base64
import hashlib
import json
import logging
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .contracts import ExecuteCommandRequest
from .conversation_access import conversation_id_context
from .file_audit import init_file_schema
from .approval_status import approval_status_context, decode
from .output_codec import OutputCorruption, encode as encode_output, decode as decode_output
from .sqlite_support import _ClosingConnection, _prepare_path
from .ssh_executor import SSHDenied, SSHExecutor, SSHResult, OutputLimitExceeded

TERMINAL = frozenset({
    "succeeded", "failed", "cancelled", "timed_out",
    "transport_error", "output_limit", "interrupted", "denied",
})
# Cumulative metrics persist in the private audit SQLite independently of retention.
# No actor, command, argument, identity, endpoint or job id is used as a metric label.
# Uvicorn owns the production stdout logger; plain module INFO logs are silent
# under its default logging configuration. Reuse its existing handler.
LOG = logging.getLogger("uvicorn.error")
DURATION_BUCKETS = (0.1, 0.5, 1, 2, 5, 10, 20, 60, 300)
FAILURE_KINDS = frozenset({
    "none", "tcp_connect_timeout", "ssh_banner_timeout",
    "ssh_auth_failure", "ssh_hostkey_failure",
    "ssh_connection_timeout", "ssh_connection_failure", "ssh_session_refused",
    "ssh_exit_255_ambiguous", "execution_error", "execution_uncertain", "restart",
    "sudo_authentication", "sudo_authorization", "sudo_rejected",
    "root_unconfirmed",
    "root_setup_failed", "cwd_preflight", "remote_signal", "output_incomplete",
    "pre_execution_rejected",
})


def classify_ssh_failure(stderr: str) -> str:
    """Coarse SSH failure classification; never emit the underlying stderr."""
    message = stderr.lower()
    if "timed out during banner exchange" in message:
        return "ssh_banner_timeout"
    if "connection timed out" in message or "connection to " in message and " timed out" in message:
        return "tcp_connect_timeout"
    if "host key verification failed" in message or "remote host identification has changed" in message:
        return "ssh_hostkey_failure"
    if "permission denied" in message or "too many authentication failures" in message:
        return "ssh_auth_failure"
    # OpenSSH 255 is ambiguous (even a remote command can return 255).
    return "ssh_exit_255_ambiguous"


def _record_outcome(db: sqlite3.Connection, server: str, status: str, kind: str,
                    count: int = 1) -> None:
    db.execute(
        """INSERT INTO telemetry_outcomes(server,status,failure_kind,total)
           VALUES(?,?,?,?) ON CONFLICT(server,status,failure_kind)
           DO UPDATE SET total=total+excluded.total""",
        (server, status, kind, count),
    )


OUTCOMES = {
    "succeeded": "succeeded",
    "command_error": "failed",
    "transport_error": "transport_error",
    "timed_out": "timed_out",
    "output_limit": "output_limit",
}


def _iso(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def _safe_command(argv: list[str]) -> str:
    # Never persist arbitrary arguments: shell strings may contain credentials.
    name = Path(argv[0]).name
    return name if re.fullmatch(r"[A-Za-z0-9_.+-]{1,64}", name) else "[redacted]"


class JobStore:
    """SQLite journal, private output chunks, conservative restart recovery."""

    def __init__(
        self, path: Path, *, retention_seconds: int = 604800,
        retention_months: int | None = None,
    ):
        if retention_months is not None:
            if not 1 <= retention_months <= 12:
                raise ValueError("Retention months must be between 1 and 12")
        elif not 3600 <= retention_seconds <= 366 * 86400:
            raise ValueError("Retention must be between one hour and 366 days")
        _prepare_path(path)
        self.path = path
        self.retention_seconds = retention_seconds
        self.retention_months = retention_months
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    actor TEXT NOT NULL,
                    server TEXT NOT NULL,
                    command TEXT NOT NULL,
                    argv_count INTEGER NOT NULL,
                    command_sha256 TEXT NOT NULL,
                    privileged INTEGER NOT NULL DEFAULT 0 CHECK(privileged IN (0,1)),
                    ssh_username TEXT,
                    root_started INTEGER CHECK(root_started IN (0,1)),
                    failure_kind TEXT NOT NULL DEFAULT 'none',
                    approval_status INTEGER,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    started_at REAL,
                    ended_at REAL,
                    exit_code INTEGER,
                    exit_accepted INTEGER,
                    effective_cwd TEXT,
                    elapsed_seconds REAL,
                    error TEXT NOT NULL DEFAULT '',
                    output_bytes INTEGER NOT NULL DEFAULT 0,
                    cancel_requested INTEGER NOT NULL DEFAULT 0,
                    mode TEXT NOT NULL DEFAULT 'async',
                    story_id TEXT,
                    conversation_id TEXT,
                    request_json TEXT
                );
                CREATE INDEX IF NOT EXISTS jobs_actor_time
                    ON jobs(actor, created_at DESC);
                CREATE TABLE IF NOT EXISTS output (
                    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                    offset INTEGER NOT NULL,
                    stream TEXT NOT NULL CHECK(stream IN ('stdout', 'stderr')),
                    data BLOB NOT NULL,
                    encoding TEXT NOT NULL DEFAULT 'raw',
                    raw_length INTEGER,
                    PRIMARY KEY(job_id, offset)
                );
                CREATE TABLE IF NOT EXISTS cancellation_requests (
                    target_type TEXT NOT NULL CHECK(target_type IN ('job','batch')),
                    target_id TEXT NOT NULL,
                    requested_via TEXT NOT NULL CHECK(requested_via IN ('mcp','history')),
                    requested_at REAL NOT NULL,
                    reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 200),
                    PRIMARY KEY(target_type,target_id)
                );
                CREATE TRIGGER IF NOT EXISTS cancellation_job_pruned
                AFTER DELETE ON jobs BEGIN
                    DELETE FROM cancellation_requests
                    WHERE target_type='job' AND target_id=OLD.id;
                END;
            """)
            # Additive migration: legacy output rows default to raw and NULL
            # original length (read via length(data)). Never recompress history.
            # Serialize DDL under SQLite's writer lock for concurrent startup.
            db.execute("BEGIN IMMEDIATE")
            output_columns = {row["name"] for row in db.execute("PRAGMA table_info(output)")}
            if "encoding" not in output_columns:
                db.execute("ALTER TABLE output ADD COLUMN encoding TEXT NOT NULL DEFAULT 'raw'")
            if "raw_length" not in output_columns:
                db.execute("ALTER TABLE output ADD COLUMN raw_length INTEGER")
            db.execute("COMMIT")
            # Upgrade existing databases in place without losing job/output history.
            existing = {row["name"] for row in db.execute("PRAGMA table_info(jobs)")}
            for name, declaration in (
                ("mode", "TEXT NOT NULL DEFAULT 'async'"),
                ("story_id", "TEXT"),
                ("request_json", "TEXT"),
                ("exit_accepted", "INTEGER"),
                ("effective_cwd", "TEXT"),
                ("conversation_id", "TEXT"),
                ("privileged", "INTEGER NOT NULL DEFAULT 0"),
                ("ssh_username", "TEXT"),
                ("root_started", "INTEGER"),
                ("failure_kind", "TEXT NOT NULL DEFAULT 'none'"),
                ("approval_status", "INTEGER"),
            ):
                if name not in existing:
                    db.execute(f"ALTER TABLE jobs ADD COLUMN {name} {declaration}")
            db.execute("CREATE INDEX IF NOT EXISTS jobs_updated ON jobs(updated_at, id)")
            db.execute("CREATE INDEX IF NOT EXISTS jobs_created ON jobs(created_at DESC, id DESC)")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS telemetry_outcomes(
                    server TEXT NOT NULL, status TEXT NOT NULL,
                    failure_kind TEXT NOT NULL, total INTEGER NOT NULL,
                    PRIMARY KEY(server,status,failure_kind)
                );
                CREATE TABLE IF NOT EXISTS telemetry_duration(
                    server TEXT PRIMARY KEY, total INTEGER NOT NULL,
                    sum_seconds REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS telemetry_duration_buckets(
                    server TEXT NOT NULL, le TEXT NOT NULL,
                    total INTEGER NOT NULL, PRIMARY KEY(server,le)
                );
            """)
            # The unified history view has an explicit column projection.
            # Recreate it after additive job migrations so old DBs expose
            # accepted-exit and effective-cwd fields for command and file rows.
            db.execute("DROP VIEW IF EXISTS history_events")
            init_file_schema(db)
            # Interrupted commands must never restart implicitly. Count recovery
            # transitions once, in the same transaction, not once per boot.
            now = time.time()
            db.execute("BEGIN IMMEDIATE")
            awaiting = db.execute(
                "SELECT server, COUNT(*) AS total FROM jobs "
                "WHERE status='awaiting_approval' GROUP BY server"
            ).fetchall()
            db.execute(
                """UPDATE jobs SET status='failed',updated_at=?,ended_at=?,
                   root_started=0,error='Approval interrupted before SSH execution'
                   WHERE status='awaiting_approval'""",
                (now, now),
            )
            for row in awaiting:
                _record_outcome(db, row["server"], "failed", "none", row["total"])
            recovery = db.execute(
                "SELECT server, COUNT(*) AS total FROM jobs "
                "WHERE status IN ('queued','running') GROUP BY server"
            ).fetchall()
            db.execute(
                """UPDATE jobs SET status='interrupted', updated_at=?,
                   ended_at=?, error='Service restarted; remote process status unknown'
                   WHERE status IN ('queued', 'running')""",
                (now, now),
            )
            for row in recovery:
                _record_outcome(db, row["server"], "interrupted", "restart", row["total"])
            db.execute("COMMIT")
        self.prune()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(
            self.path, timeout=5, isolation_level=None, factory=_ClosingConnection
        )
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=5000")
        return db

    def prune(self) -> int:
        if self.retention_months is None:
            cutoff = time.time() - self.retention_seconds
        else:
            # Calendar-accurate month subtraction (not an approximate 365 days).
            now = datetime.now(timezone.utc)
            index = (now.year * 12 + now.month - 1) - self.retention_months
            year, month_zero = divmod(index, 12)
            month = month_zero + 1
            day = min(now.day, calendar.monthrange(year, month)[1])
            cutoff = now.replace(year=year, month=month, day=day).timestamp()
        with self._connect() as db:
            removed = db.execute(
                "DELETE FROM jobs WHERE status NOT IN "
                "('awaiting_approval','queued','running') AND ended_at < ?",
                (cutoff,),
            )
            file_removed = db.execute(
                "DELETE FROM file_operations WHERE status NOT IN ('running')"
                " AND ended_at < ?", (cutoff,),
            )
            batch_removed = 0
            if db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='command_batches'"
            ).fetchone():
                batch_removed = db.execute(
                    """DELETE FROM command_batches WHERE status NOT IN ('queued','running')
                       AND ended_at < ?""", (cutoff,),
                ).rowcount
            return removed.rowcount + file_removed.rowcount + batch_removed

    def create(self, actor: str, request: ExecuteCommandRequest, *, mode: str = "async",
               pending_approval: bool = False, username: str | None = None) -> str:
        if mode not in {"sync", "async"}:
            raise ValueError("Invalid execution mode")
        job_id = secrets.token_urlsafe(18)
        now = time.time()
        fingerprint = hashlib.sha256(
            json.dumps(request.argv, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        with self._connect() as db:
            db.execute(
                """INSERT INTO jobs
                (id,actor,server,command,argv_count,command_sha256,privileged,ssh_username,
                 status,created_at,updated_at,mode,story_id,conversation_id,request_json,approval_status)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (job_id, actor, request.server, _safe_command(request.argv),
                 len(request.argv), fingerprint, int(request.privileged), username,
                 "awaiting_approval" if pending_approval else "queued",
                 now, now, mode, request.story_id,
                 conversation_id_context.get(),
                 json.dumps(request.model_dump(exclude_none=True), separators=(",", ":")),
                 approval_status_context.get()),
            )
        return job_id

    def settle_approval(self, job_id: str, approval_code: int | None, *,
                        denied: bool = False) -> None:
        """Finalize the existing queued pre-gate record; never allocate another."""
        if denied:
            status = "denied" if approval_code is not None else "failed"
            message = ("Approval denied" if approval_code is not None
                       else "Approval unavailable")
        else:
            if approval_code is None:
                raise ValueError("Approved operation needs an approval code")
            status, message = "queued", ""
        now = time.time()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT server FROM jobs WHERE id=? AND status='awaiting_approval' "
                "AND approval_status IS NULL", (job_id,),
            ).fetchone()
            if row is None:
                raise RuntimeError("Approval audit record cannot be finalized")
            db.execute(
                """UPDATE jobs SET approval_status=?,status=?,updated_at=?,
                   ended_at=?,root_started=?,error=?
                   WHERE id=? AND status='awaiting_approval' AND approval_status IS NULL""",
                (approval_code, status, now,
                 now if denied else None,
                 0 if denied else None, message, job_id),
            )
            if denied:
                _record_outcome(db, str(row["server"]), status, "none")
            db.execute("COMMIT")

    def reject_unscheduled(self, job_id: str, message: str) -> None:
        """Finish an admitted pre-gate request if scheduling is refused."""
        now = time.time()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT server FROM jobs WHERE id=? AND status='queued'
                   AND approval_status IS NOT NULL AND started_at IS NULL""",
                (job_id,),
            ).fetchone()
            if row is None:
                raise RuntimeError("Cannot finalize a scheduled or unaudited request")
            updated = db.execute(
                """UPDATE jobs SET status='failed',error=?,root_started=0,
                   updated_at=?,ended_at=? WHERE id=? AND status='queued'
                   AND started_at IS NULL""",
                (message[:200], now, now, job_id),
            )
            if updated.rowcount != 1:
                raise RuntimeError("Pre-execution job state changed unexpectedly")
            _record_outcome(db, str(row["server"]), "failed", "none")
            db.execute("COMMIT")

    def begin(self, job_id: str) -> bool:
        with self._connect() as db:
            updated = db.execute(
                """UPDATE jobs SET status='running', started_at=?, updated_at=?
                   WHERE id=? AND status='queued' AND cancel_requested=0""",
                (time.time(), time.time(), job_id),
            )
            return updated.rowcount == 1

    def append(self, job_id: str, stream: str, data: bytes) -> None:
        if stream not in ("stdout", "stderr"):
            raise ValueError("Invalid output stream")
        if not data:
            return
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT status,output_bytes FROM jobs WHERE id=?", (job_id,)
            ).fetchone()
            if row is None or row["status"] != "running":
                raise RuntimeError("Output received for an inactive job")
            offset = int(row["output_bytes"])
            stored, encoding, raw_length = encode_output(data)
            db.execute(
                """INSERT INTO output(job_id,offset,stream,data,encoding,raw_length)
                   VALUES(?,?,?,?,?,?)""",
                (job_id, offset, stream, stored, encoding, raw_length),
            )
            db.execute(
                "UPDATE jobs SET output_bytes=?,updated_at=? WHERE id=?",
                (offset + len(data), time.time(), job_id),
            )

    def finish(
        self, job_id: str, status: str, *,
        exit_code: int | None = None, elapsed: float | None = None,
        error: str = "", failure_kind: str = "none",
        exit_accepted: bool | None = None, effective_cwd: str | None = None,
        root_started: bool | None = None,
    ) -> None:
        if status not in TERMINAL:
            raise ValueError("Invalid terminal status")
        if failure_kind not in FAILURE_KINDS:
            raise ValueError("Invalid failure classification")
        if status != "transport_error" and failure_kind not in {
            "none", "execution_error", "execution_uncertain", "restart", "sudo_authentication",
            "sudo_authorization", "sudo_rejected", "root_unconfirmed",
            "root_setup_failed", "cwd_preflight", "remote_signal",
            "pre_execution_rejected",
        }:
            raise ValueError("Transport classification requires transport_error status")
        if failure_kind in {"cwd_preflight", "remote_signal",
                            "pre_execution_rejected"} and status != "failed":
            raise ValueError("Command failure classification requires failed status")
        server: str | None = None
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT server FROM jobs WHERE id=? AND status IN ('queued','running')",
                (job_id,),
            ).fetchone()
            if row is not None:
                server = str(row["server"])
                db.execute(
                    """UPDATE jobs SET status=?,updated_at=?,ended_at=?,
                       exit_code=?,elapsed_seconds=?,error=?,
                       exit_accepted=?,effective_cwd=?,root_started=?,failure_kind=?
                       WHERE id=? AND status IN ('queued','running')""",
                    (status, time.time(), time.time(), exit_code, elapsed, error,
                     None if exit_accepted is None else int(exit_accepted),
                     effective_cwd,
                     None if root_started is None else int(root_started),
                     failure_kind, job_id),
                )
                _record_outcome(db, server, status, failure_kind)
                if elapsed is not None:
                    # Single atomic completion also updates the durable
                    # histogram; never infer duration from a missing value.
                    db.execute(
                        """INSERT INTO telemetry_duration(server,total,sum_seconds)
                           VALUES(?,1,?) ON CONFLICT(server) DO UPDATE
                           SET total=total+1, sum_seconds=sum_seconds+excluded.sum_seconds""",
                        (server, max(0.0, elapsed)),
                    )
                    for boundary in DURATION_BUCKETS:
                        if elapsed <= boundary:
                            db.execute(
                                """INSERT INTO telemetry_duration_buckets(server,le,total)
                                   VALUES(?,?,1) ON CONFLICT(server,le) DO UPDATE
                                   SET total=total+1""",
                                (server, str(boundary)),
                            )
            db.execute("COMMIT")
        if server is not None:
            # Fixed, safe fields only. Never log SSH stderr, commands or actors.
            LOG.info("ssh_mcp_job_completed %s", json.dumps({
                "server": server, "status": status, "failure_kind": failure_kind,
                "elapsed_seconds": round(elapsed, 3) if elapsed is not None else None,
            }, sort_keys=True))

    def record_cancellation(
        self, target_type: str, actor: str, target_id: str, *,
        via: str, reason: str,
    ) -> bool:
        """Atomically accept the first request and settle pre-execution targets.

        The durable audit and queued terminal status must commit together:
        an interrupted second write cannot leave a cancelled request queued
        for execution or permanently block retries without stopping work.
        """
        if target_type not in {"job", "batch"} or via not in {"mcp", "history"}:
            raise ValueError("Invalid cancellation provenance")
        if not isinstance(reason, str) or not 1 <= len(reason) <= 200:
            raise ValueError("Cancellation reason must be 1–200 characters")
        now = time.time()
        queued_job_server: str | None = None
        table = "jobs" if target_type == "job" else "command_batches"
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                f"""SELECT status{',server' if target_type == 'job' else ''}
                   FROM {table} WHERE id=? AND actor=?
                   AND status IN ('queued','running')
                   {'AND cancel_requested=0' if target_type == 'job' else ''}
                   AND NOT EXISTS (
                       SELECT 1 FROM cancellation_requests
                       WHERE target_type=? AND target_id=?
                   )""",
                (target_id, actor, target_type, target_id),
            ).fetchone()
            if row is None:
                return False
            if target_type == "job":
                if row["status"] == "queued":
                    db.execute(
                        """UPDATE jobs SET status='cancelled',cancel_requested=1,
                           updated_at=?,ended_at=?
                           WHERE id=? AND actor=? AND status='queued'""",
                        (now, now, target_id, actor),
                    )
                    _record_outcome(db, str(row["server"]), "cancelled", "none")
                    queued_job_server = str(row["server"])
                else:
                    db.execute(
                        """UPDATE jobs SET cancel_requested=1,updated_at=?
                           WHERE id=? AND actor=? AND status='running'""",
                        (now, target_id, actor),
                    )
            elif row["status"] == "queued":
                db.execute(
                    """UPDATE command_batches SET status='cancelled',
                       failure_kind='cancelled',updated_at=?,ended_at=?
                       WHERE id=? AND actor=? AND status='queued'""",
                    (now, now, target_id, actor),
                )
            else:
                db.execute(
                    """UPDATE command_batches SET updated_at=?
                       WHERE id=? AND actor=? AND status='running'""",
                    (now, target_id, actor),
                )
            if target_type == "batch":
                # Child job rows are shown in History, not the parent batch.
                # Emit a normal job update so other viewer sessions promptly
                # hide a now-unavailable × without fetching audit details.
                db.execute(
                    """UPDATE jobs SET updated_at=? WHERE id IN (
                           SELECT job_id FROM command_batch_steps
                           WHERE batch_id=? AND job_id IS NOT NULL
                       ) AND status IN ('queued','running')""",
                    (now, target_id),
                )
            db.execute(
                """INSERT INTO cancellation_requests
                   (target_type,target_id,requested_via,requested_at,reason)
                   VALUES(?,?,?,?,?)""",
                (target_type, target_id, via, now, reason),
            )
        if queued_job_server is not None:
            # Match JobStore.finish's fixed-field completion event, emitted
            # only after the audit and terminal status have both committed.
            # Never log the actor, job ID, cancellation reason, or SQL error.
            LOG.info("ssh_mcp_job_completed %s", json.dumps({
                "server": queued_job_server, "status": "cancelled",
                "failure_kind": "none", "elapsed_seconds": None,
            }, sort_keys=True))
        return True

    def request_cancel(
        self, actor: str, job_id: str, *,
        via: str = "mcp", reason: str = "Cancellation requested",
    ) -> bool:
        return self.record_cancellation(
            "job", actor, job_id, via=via, reason=reason,
        )

    def get(self, actor: str, job_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM jobs WHERE actor=? AND id=?", (actor, job_id)
            ).fetchone()
        return self._summary(row) if row else None

    @staticmethod
    def _summary(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"], "server": row["server"], "status": row["status"],
            "created_at": _iso(row["created_at"]), "updated_at": _iso(row["updated_at"]),
            "mode": row["mode"], "story_id": row["story_id"],
            "conversation_id": row["conversation_id"],
            "started_at": _iso(row["started_at"]),
            "ended_at": _iso(row["ended_at"]),
            "command": row["command"], "argv_count": row["argv_count"],
            "command_sha256": row["command_sha256"],
            "privileged": bool(row["privileged"]),
            "run_as": "root" if row["privileged"] else row["ssh_username"],
            "root_started": (None if row["root_started"] is None
                             else bool(row["root_started"])),
            "failure_kind": row["failure_kind"],
            "approval_status": decode(row["approval_status"]),
            "exit_code": row["exit_code"], "elapsed_seconds": row["elapsed_seconds"],
            "exit_accepted": (None if row["exit_accepted"] is None
                              else bool(row["exit_accepted"])),
            "effective_cwd": row["effective_cwd"],
            "output_bytes": row["output_bytes"], "error": row["error"],
            "cancellation_requested": bool(row["cancel_requested"]),
        }

    def list(self, actor: str, *, limit: int = 20, status: str | None = None) -> list[dict[str, Any]]:
        if not 1 <= limit <= 100:
            raise ValueError("Invalid job list limit")
        if status is not None and status not in TERMINAL | {"queued", "running"}:
            raise ValueError("Invalid job status")
        query = "SELECT * FROM jobs WHERE actor=?"
        args: list[Any] = [actor]
        if status is not None:
            query += " AND status=?"
            args.append(status)
        query += " ORDER BY created_at DESC,id DESC LIMIT ?"
        args.append(limit)
        with self._connect() as db:
            rows = db.execute(query, args).fetchall()
        return [self._summary(row) for row in rows]

    def read_output(
        self, actor: str, job_id: str, *, cursor: int = 0, max_bytes: int = 16384
    ) -> dict[str, Any] | None:
        if cursor < 0 or not 1 <= max_bytes <= 65536:
            raise ValueError("Invalid output cursor or bound")
        with self._connect() as db:
            # A running SSH command can append between SELECTs. One WAL read
            # transaction keeps jobs.output_bytes, the anchor and output rows
            # in the same snapshot; otherwise correct newly committed chunks
            # could appear inconsistent with the earlier recorded total.
            db.execute("BEGIN")
            job = db.execute(
                "SELECT output_bytes,status FROM jobs WHERE actor=? AND id=?",
                (actor, job_id),
            ).fetchone()
            if job is None:
                return None
            total = int(job["output_bytes"])
            if cursor > total:
                raise ValueError("Output cursor past end")
            # Never use untrusted raw_length to select the row containing a
            # cursor: a corrupt/understated value can skip a compressed chunk
            # and leave truncated=true with no progress. Find the nearest
            # start offset instead, then verify raw lengths and continuity.
            anchor = db.execute(
                """SELECT offset FROM output WHERE job_id=? AND offset<=?
                   ORDER BY offset DESC LIMIT 1""", (job_id, cursor),
            ).fetchone() if cursor < total else None
            rows = db.execute(
                """SELECT offset,stream,data,encoding,raw_length FROM output
                   WHERE job_id=? AND offset>=? ORDER BY offset""",
                (job_id, anchor["offset"]),
            ).fetchall() if anchor is not None else []
        if cursor < total and not rows:
            raise OutputCorruption("Invalid or corrupted stored output chunk")
        next_cursor = cursor
        chunks = []
        remaining = max_bytes
        for index, row in enumerate(rows):
            start = int(row["offset"])
            original = decode_output(
                bytes(row["data"]), str(row["encoding"]), row["raw_length"],
            )
            # Every chunk must end at the next original offset (or the job's
            # original-byte total). A corrupt short but valid raw chunk may
            # otherwise create a hole even when the stored codec is 'raw'.
            end = int(rows[index + 1]["offset"]) if index + 1 < len(rows) else total
            if start + len(original) != end or not start <= next_cursor < end:
                raise OutputCorruption("Invalid or corrupted stored output chunk")
            offset = next_cursor - start
            block = original[offset:offset + remaining]
            chunks.append({
                "stream": row["stream"],
                "data_base64": base64.b64encode(block).decode("ascii"),
            })
            next_cursor += len(block)
            remaining -= len(block)
            if remaining == 0:
                break
        if next_cursor < total and remaining:
            raise OutputCorruption("Invalid or corrupted stored output chunk")
        return {
            "job_id": job_id, "cursor": cursor, "next_cursor": next_cursor,
            "chunks": chunks, "truncated": next_cursor < total,
            "status": job["status"],
        }


_EXPLICIT_SYNC_CANCEL = object()


class JobManager:
    """Retain work beyond MCP request disconnects; no job is auto-retried."""

    def __init__(self, executor: SSHExecutor, store: JobStore, *, max_active: int = 32):
        if not 1 <= max_active <= 256:
            raise ValueError("Invalid active-job cap")
        self.executor = executor
        self.store = store
        self.max_active = max_active
        self._tasks: dict[str, asyncio.Task[SSHResult | None]] = {}
        # Synchronous MCP/batch tasks need a cancellation handle too.
        self._sync_tasks: dict[str, asyncio.Task[object]] = {}

    def _signed_username(self, actor: str, server: str) -> str | None:
        # Production executors return a validated HostSpec from signed inventory.
        # Minimal test doubles may not expose that interface; never invent a user.
        lookup = getattr(self.executor, "authorized_host", None)
        if lookup is None:
            return None
        return getattr(lookup(actor, server), "username", None)

    def submit(self, actor: str, request: ExecuteCommandRequest, *,
               admitted_root: bool = False,
               precreated_id: str | None = None) -> dict[str, Any]:
        try:
            if request.privileged and not admitted_root:
                raise SSHDenied("Privileged execution is not enabled")
            if request.server not in self.executor.list_servers(actor):
                raise SSHDenied("SSH host or principal is not authorized")
            if len(self._tasks) >= self.max_active:
                raise RuntimeError("Too many active jobs")
        except (SSHDenied, RuntimeError) as exc:
            if precreated_id is not None:
                self.store.reject_unscheduled(precreated_id, str(exc))
            raise
        self.store.prune()
        job_id = precreated_id or self.store.create(
            actor, request, username=self._signed_username(actor, request.server),
        )
        task = asyncio.create_task(self._run(
            job_id, actor, request, admitted_root=admitted_root,
        ))
        self._tasks[job_id] = task
        task.add_done_callback(lambda _: self._tasks.pop(job_id, None))
        result = self.store.get(actor, job_id)
        assert result is not None
        return result

    async def execute_sync(
        self, actor: str, request: ExecuteCommandRequest, *,
        on_created: Callable[[str], None] | None = None,
        on_started: Callable[[str], None] | None = None,
        max_output_bytes: int | None = None,
        admitted_root: bool = False,
        precreated_id: str | None = None,
    ) -> tuple[str, SSHResult | None]:
        """Run synchronously while recording the same durable audit lifecycle."""
        if request.privileged and not admitted_root:
            raise SSHDenied("Privileged execution is not enabled")
        if request.server not in self.executor.list_servers(actor):
            raise SSHDenied("SSH host or principal is not authorized")
        self.store.prune()
        job_id = precreated_id or self.store.create(
            actor, request, mode="sync",
            username=self._signed_username(actor, request.server),
        )
        current = asyncio.current_task()
        assert current is not None
        self._sync_tasks[job_id] = current
        try:
            if on_created is not None:
                on_created(job_id)
            return job_id, await self._run(
                job_id, actor, request, on_started=on_started,
                max_output_bytes=max_output_bytes, admitted_root=admitted_root,
            )
        finally:
            self._sync_tasks.pop(job_id, None)

    async def _run(
        self, job_id: str, actor: str, request: ExecuteCommandRequest, *,
        max_output_bytes: int | None = None,
        admitted_root: bool = False,
        on_started: Callable[[str], None] | None = None,
    ) -> SSHResult | None:
        start: float | None = None

        def admit() -> bool:
            nonlocal start
            if not self.store.begin(job_id):
                return False
            start = time.monotonic()
            if on_started is not None:
                on_started(job_id)
            return True

        def elapsed() -> float | None:
            return max(0.0, time.monotonic() - start) if start is not None else None

        streamed: set[str] = set()
        captured = 0
        audit_write_failed = False

        async def capture(stream: str, block: bytes) -> None:
            nonlocal captured, audit_write_failed
            available = (len(block) if max_output_bytes is None
                         else max(0, max_output_bytes - captured))
            accepted = block[:available]
            if accepted:
                try:
                    self.store.append(job_id, stream, accepted)
                except Exception:
                    # Remote execution may already have changed state. If
                    # output persistence fails, it is not a command failure.
                    audit_write_failed = True
                    raise
                captured += len(accepted)
                streamed.add(stream)
            if len(block) > available:
                raise OutputLimitExceeded

        try:
            if request.privileged:
                if not admitted_root:
                    raise SSHDenied("Privileged command was not admitted")
                result: SSHResult = await self.executor._execute_approved_privileged(
                    actor, request, on_output=capture,
                    on_admitted=admit,
                )
            else:
                result = await self.executor.execute(
                    actor, request, on_output=capture,
                    on_admitted=admit,
                )
        except asyncio.CancelledError as exc:
            self.store.finish(job_id, "cancelled", elapsed=elapsed())
            # A durable cancel_requested flag is not the cause of this
            # exception. A batch deadline/shutdown can cancel the SAME task
            # after cancel_job, and that outer cancellation must propagate.
            current = asyncio.current_task()
            if (current is not None and
                    self._sync_tasks.get(job_id) is current and
                    current.cancelling() == 1 and exc.args and
                    exc.args[0] is _EXPLICIT_SYNC_CANCEL):
                current.uncancel()
                return None
            raise
        except SSHDenied:
            # A definite authorization/preflight refusal; the caller's argv
            # was never dispatched even if SSH capacity and CWD preflight ran.
            # Persist fixed machine-readable evidence before replying.
            self.store.finish(
                job_id, "failed", elapsed=elapsed(),
                error="SSH authorization was rejected",
                failure_kind="pre_execution_rejected",
            )
        except Exception:
            # Never include exception text, which might include a secret path.
            self.store.finish(
                job_id, "interrupted" if audit_write_failed else "failed",
                elapsed=elapsed(),
                error=("Output audit unavailable; execution outcome uncertain; "
                       "inspect job before retrying") if audit_write_failed
                      else "Execution failed",
                failure_kind="execution_uncertain" if audit_write_failed
                             else "execution_error",
            )
        else:
            # SSHExecutor normally streams both outputs through the callback.
            # Synthetic transport errors (e.g. a failed ssh spawn) can return
            # diagnostic text without invoking it; preserve only missing
            # streams to avoid recording normal command output twice.
            fallback_overflow = False
            for stream in ("stdout", "stderr"):
                if stream not in streamed:
                    message = getattr(result, stream)
                    if message:
                        remaining = (None if max_output_bytes is None else
                                     max(0, max_output_bytes - captured))
                        block = message.encode("utf-8")
                        if remaining is not None:
                            fallback_overflow |= len(block) > remaining
                            block = block[:remaining]
                        if block:
                            self.store.append(job_id, stream, block)
                            captured += len(block)
            if fallback_overflow:
                # Do not report a successful step after a synthetic SSH
                # spawn/preflight diagnostic exceeded the batch output cap.
                result = SSHResult(
                    result.server, "output_limit", None, result.stdout,
                    result.stderr, result.elapsed_seconds,
                    effective_cwd=result.effective_cwd,
                )
            self.store.finish(
                job_id, OUTCOMES[result.status],
                exit_code=result.exit_code, elapsed=result.elapsed_seconds,
                exit_accepted=result.exit_accepted, effective_cwd=result.effective_cwd,
                root_started=result.root_started,
                error=(result.stderr if result.failure_kind in {
                    "sudo_authentication", "sudo_authorization", "sudo_rejected",
                    "root_unconfirmed",
                    "root_setup_failed",
                } else ""),
                failure_kind=(result.failure_kind or
                              (classify_ssh_failure(result.stderr)
                               if result.status == "transport_error" else "none")),
            )
            return result
        return None

    def get(self, actor: str, job_id: str) -> dict[str, Any] | None:
        return self.store.get(actor, job_id)

    def list(self, actor: str, *, limit: int = 20, status: str | None = None) -> list[dict[str, Any]]:
        return self.store.list(actor, limit=limit, status=status)

    def output(
        self, actor: str, job_id: str, *, cursor: int = 0, max_bytes: int = 16384
    ) -> dict[str, Any] | None:
        return self.store.read_output(actor, job_id, cursor=cursor, max_bytes=max_bytes)

    def cancel(
        self, actor: str, job_id: str, *,
        reason: str = "Cancellation requested", via: str = "mcp",
    ) -> dict[str, Any] | None:
        existing = self.store.get(actor, job_id)
        if existing is None:
            return None
        # A running job without an in-process task cannot be confirmed stopped.
        # Fail closed rather than record a false completed cancellation.
        task = self._tasks.get(job_id) or self._sync_tasks.get(job_id)
        if existing["status"] == "running" and task is None:
            return {"job": existing, "cancellation_requested": False}
        requested = self.store.request_cancel(actor, job_id, via=via, reason=reason)
        if requested:
            sync_task = self._sync_tasks.get(job_id)
            task = self._tasks.get(job_id) or sync_task
            # Queued work is already finalized in the audit transaction.
            # A running job is only terminated when the task acknowledges cancel.
            if task is not None:
                if task is sync_task:
                    # Keep explicit operator cancellation distinct from
                    # another caller's deadline or service shutdown.
                    if not task.cancelling():
                        task.cancel(_EXPLICIT_SYNC_CANCEL)
                else:
                    task.cancel()
        return {"job": self.store.get(actor, job_id), "cancellation_requested": requested}

    async def shutdown(self) -> None:
        pending = list(self._tasks.items())
        for _, task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*(task for _, task in pending), return_exceptions=True)
        # Tasks cancelled before their first scheduled step never run _run.
        for job_id, _ in pending:
            self.store.finish(job_id, "cancelled")
