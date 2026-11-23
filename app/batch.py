"""Bounded, non-transactional SSH command batches and durable recovery.

This module never retries a batch. Each attempted step is an existing actor-
scoped JobStore job; step output is retained under the same private, bounded
audited output and exposed through get_job_output for large responses.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import secrets
import sqlite3
import time
from typing import Any

from . import config
from .client_identity import client_id_context
from .conversation_access import conversation_id_context
from .approval_status import approval_status_context, decode
from .grant_unlocks import finish_once_root, root_access_context
from .contracts import ExecuteCommandsRequest
from .jobs import JobManager, JobStore
from .file_audit import rebuild_history_view
from .ssh_executor import ReadinessDenied, SSHDenied, SSHExecutor, SSHResult

MAX_BATCH_RESPONSE_BYTES = min(262144, config.SSH_OUTPUT_LIMIT_BYTES)
# Reserve at least 64 KiB of the overall response/output budget for metadata,
# per-step status, error classifiers and bounded result summaries.
MAX_BATCH_OUTPUT_BYTES = max(1, MAX_BATCH_RESPONSE_BYTES - 65536)
MAX_STEP_PREVIEW_BYTES = 4096
BATCH_TERMINAL = frozenset({
    "succeeded", "failed", "timed_out", "transport_error",
    "output_limit", "interrupted", "cancelled", "rejected", "denied",
})
STEP_TERMINAL = frozenset({
    "succeeded", "failed", "timed_out", "transport_error",
    "output_limit", "unknown", "cancelled",
})


class BatchStore:
    """Actor-isolated, incrementally published SQLite batch manifest."""

    def __init__(self, jobs: JobStore):
        self.jobs = jobs
        with jobs._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS command_batches (
                    id TEXT PRIMARY KEY,
                    actor TEXT NOT NULL,
                    server TEXT NOT NULL,
                    story_id TEXT,
                    conversation_id TEXT,
                    reason TEXT NOT NULL,
                    requested_cwd TEXT,
                    effective_cwd TEXT,
                    strict_bash INTEGER NOT NULL,
                    privileged INTEGER NOT NULL DEFAULT 0 CHECK(privileged IN (0,1)),
                    ssh_username TEXT,
                    approval_status INTEGER,
                    stop_on_error INTEGER NOT NULL,
                    timeout_seconds INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    failure_kind TEXT,
                    error TEXT,
                    failed_step INTEGER,
                    failed_field TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    ended_at REAL,
                    total_steps INTEGER NOT NULL CHECK(total_steps BETWEEN 1 AND 5)
                );
                CREATE INDEX IF NOT EXISTS command_batches_actor_time
                    ON command_batches(actor,created_at DESC,id DESC);
                CREATE TABLE IF NOT EXISTS command_batch_steps (
                    batch_id TEXT NOT NULL REFERENCES command_batches(id) ON DELETE CASCADE,
                    step_index INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'not_attempted',
                    result_status TEXT,
                    command TEXT NOT NULL,
                    command_sha256 TEXT NOT NULL,
                    job_id TEXT,
                    exit_code INTEGER,
                    exit_accepted INTEGER,
                    elapsed_seconds REAL,
                    started_at REAL,
                    ended_at REAL,
                    PRIMARY KEY(batch_id,step_index)
                );
            """)
            existing = {row["name"] for row in db.execute("PRAGMA table_info(command_batches)")}
            # Keep only additive columns introduced on/after 2026-11-15.
            # Other historical columns are included in CREATE TABLE above.
            if "error" not in existing:
                db.execute("ALTER TABLE command_batches ADD COLUMN error TEXT")
            if "ssh_username" not in existing:
                db.execute("ALTER TABLE command_batches ADD COLUMN ssh_username TEXT")
            if "client_id" not in existing:
                db.execute("ALTER TABLE command_batches ADD COLUMN client_id TEXT")
            # Startup recovery never runs work again. A remote command might
            # have completed without the process recording acknowledgement.
            now = time.time()
            db.execute("BEGIN IMMEDIATE")
            # The child may have durably completed a proven pre-dispatch
            # rejection immediately before a process restart. Reconcile that
            # proof before classifying any admitted step as unknown.
            rejected = db.execute(
                """SELECT b.id AS batch_id, step.step_index, step.job_id
                   FROM command_batches AS b
                   JOIN command_batch_steps AS step ON step.batch_id=b.id
                   JOIN jobs AS job ON job.id=step.job_id
                   WHERE b.status IN ('queued','running')
                     AND step.status IN ('running','not_attempted')
                     AND job.status='failed'
                     AND job.failure_kind='pre_execution_rejected'
                   ORDER BY b.id, step.step_index"""
            ).fetchall()
            for row in rejected:
                self._finish_rejected_child_in_tx(
                    db, row["batch_id"], row["step_index"], row["job_id"], now,
                )
            db.execute(
                """UPDATE command_batch_steps SET status='unknown',result_status='interrupted',
                   ended_at=? WHERE (status='running' OR
                        (status='not_attempted' AND job_id IS NOT NULL AND EXISTS(
                            SELECT 1 FROM jobs WHERE jobs.id=command_batch_steps.job_id
                            AND jobs.started_at IS NOT NULL)))
                   AND batch_id IN (SELECT id FROM command_batches
                                    WHERE status IN ('queued','running'))""",
                (now,),
            )
            db.execute(
                """UPDATE command_batches SET status='rejected',
                   failure_kind='approval_interrupted',updated_at=?,ended_at=?
                   WHERE status='awaiting_approval'""", (now, now),
            )
            db.execute(
                """UPDATE command_batches SET status='interrupted',
                   failure_kind='process_restart',updated_at=?,ended_at=?
                   WHERE status IN ('queued','running')""",
                (now, now),
            )
            db.execute("COMMIT")
            db.execute(
                """CREATE TRIGGER IF NOT EXISTS cancellation_batch_pruned
                   AFTER DELETE ON command_batches BEGIN
                       DELETE FROM cancellation_requests
                       WHERE target_type='batch' AND target_id=OLD.id;
                   END"""
            )
            rebuild_history_view(db)
        self.prune()

    def prune(self) -> None:
        if self.jobs.retention_months is None:
            cutoff = time.time() - self.jobs.retention_seconds
        else:
            from datetime import datetime, timezone
            import calendar
            moment = datetime.now(timezone.utc)
            index = moment.year * 12 + moment.month - 1 - self.jobs.retention_months
            year, zero = divmod(index, 12)
            month = zero + 1
            cutoff = moment.replace(
                year=year, month=month,
                day=min(moment.day, calendar.monthrange(year, month)[1]),
            ).timestamp()
        with self.jobs._connect() as db:
            db.execute(
                """DELETE FROM command_batches WHERE status NOT IN
                   ('awaiting_approval','queued','running') AND ended_at < ?""",
                (cutoff,),
            )

    def create(self, actor: str, request: ExecuteCommandsRequest, *,
               pending_approval: bool = False, username: str | None = None) -> str:
        batch_id = secrets.token_urlsafe(18)
        now = time.time()
        with self.jobs._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """INSERT INTO command_batches(
                    id,actor,server,story_id,conversation_id,reason,requested_cwd,
                    strict_bash,privileged,ssh_username,stop_on_error,timeout_seconds,status,
                    created_at,updated_at,total_steps,approval_status,client_id
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (batch_id, actor, request.server, request.story_id,
                 conversation_id_context.get(), request.reason,
                 request.cwd, int(request.strict_bash), int(request.privileged), username,
                 int(request.stop_on_error),
                 request.timeout_seconds,
                 "awaiting_approval" if pending_approval else "queued",
                 now, now, len(request.commands),
                 approval_status_context.get(), client_id_context.get()),
            )
            for index, step in enumerate(request.commands):
                raw = json.dumps(step.argv, ensure_ascii=False, separators=(",", ":"))
                command = step.argv[0].rsplit("/", 1)[-1]
                if not command or len(command) > 64 or not all(
                    c.isascii() and (c.isalnum() or c in "._+-") for c in command
                ):
                    command = "[redacted]"
                db.execute(
                    """INSERT INTO command_batch_steps(
                      batch_id,step_index,command,command_sha256
                    ) VALUES(?,?,?,?)""",
                    (batch_id, index, command, hashlib.sha256(raw.encode()).hexdigest()),
                )
            db.execute("COMMIT")
        return batch_id

    def settle_approval(self, batch_id: str, approval_code: int | None, *,
                        denied: bool = False) -> None:
        """Reconcile the pre-approval manifest without allocating a new batch."""
        if not denied and approval_code is None:
            raise ValueError("Approved batch needs an approval code")
        status = ("denied" if approval_code is not None else "rejected") if denied else "queued"
        now = time.time()
        with self.jobs._connect() as db:
            updated = db.execute(
                """UPDATE command_batches
                   SET approval_status=?,status=?,updated_at=?,
                       ended_at=?,failure_kind=?
                   WHERE id=? AND status='awaiting_approval' AND approval_status IS NULL""",
                (approval_code, status, now, now if denied else None,
                 "authorization" if denied else None, batch_id),
            )
            if updated.rowcount != 1:
                raise RuntimeError("Batch approval audit cannot be finalized")

    def reject_unscheduled(self, batch_id: str, reason: str) -> None:
        """Reject an admitted batch before task allocation, without SSH."""
        now = time.time()
        with self.jobs._connect() as db:
            updated = db.execute(
                """UPDATE command_batches SET status='rejected',
                   failure_kind=?,updated_at=?,ended_at=?
                   WHERE id=? AND status='queued' AND approval_status IS NOT NULL
                   AND NOT EXISTS (
                     SELECT 1 FROM command_batch_steps
                     WHERE batch_id=? AND status!='not_attempted'
                   )""",
                (reason, now, now, batch_id, batch_id),
            )
            if updated.rowcount != 1:
                raise RuntimeError("Cannot reject an already running batch")

    def begin(self, batch_id: str) -> bool:
        with self.jobs._connect() as db:
            changed = db.execute(
                """UPDATE command_batches SET status='running',updated_at=?
                   WHERE id=? AND status='queued'
                   AND NOT EXISTS (
                       SELECT 1 FROM cancellation_requests
                       WHERE target_type='batch' AND target_id=?
                   )""", (time.time(), batch_id, batch_id),
            )
            return changed.rowcount == 1

    def record_step(self, batch_id: str, index: int, job_id: str) -> None:
        """Save the durable child ID without claiming the SSH step started."""
        with self.jobs._connect() as db:
            updated = db.execute(
                """UPDATE command_batch_steps SET job_id=?
                   WHERE batch_id=? AND step_index=? AND status='not_attempted'
                   AND job_id IS NULL""", (job_id, batch_id, index),
            )
            if updated.rowcount != 1:
                raise RuntimeError("Batch child job already recorded")

    def admitted_step(self, batch_id: str, index: int, job_id: str) -> None:
        """Mark attempted only after the child has acquired SSH capacity."""
        now = time.time()
        with self.jobs._connect() as db:
            updated = db.execute(
                """UPDATE command_batch_steps SET status='running',started_at=?
                   WHERE batch_id=? AND step_index=? AND job_id=?
                   AND status='not_attempted'""",
                (now, batch_id, index, job_id),
            )
            if updated.rowcount != 1:
                raise RuntimeError("Cannot admit an unrecorded batch step")
            db.execute(
                "UPDATE command_batches SET updated_at=? WHERE id=?",
                (now, batch_id),
            )

    def completed_step(self, batch_id: str, index: int, *, status: str,
                       result_status: str | None, exit_code: int | None = None,
                       exit_accepted: bool | None = None,
                       elapsed_seconds: float | None = None) -> None:
        if status not in STEP_TERMINAL:
            raise ValueError("Invalid step outcome")
        with self.jobs._connect() as db:
            updated = db.execute(
                """UPDATE command_batch_steps SET status=?,result_status=?,
                   exit_code=?,exit_accepted=?,elapsed_seconds=?,ended_at=?
                   WHERE batch_id=? AND step_index=? AND status='running'""",
                (status, result_status, exit_code,
                 None if exit_accepted is None else int(exit_accepted),
                 elapsed_seconds, time.time(), batch_id, index),
            )
            if updated.rowcount != 1:
                raise RuntimeError("Cannot complete a non-running batch step")
            db.execute(
                "UPDATE command_batches SET updated_at=? WHERE id=?",
                (time.time(), batch_id),
            )

    @staticmethod
    def _finish_rejected_child_in_tx(
        db: sqlite3.Connection, batch_id: str, index: int, job_id: str,
        now: float,
    ) -> None:
        """Atomically record a proven child denial and its batch completion."""
        updated = db.execute(
            """UPDATE command_batch_steps
               SET status='not_attempted',result_status='rejected',ended_at=?
               WHERE batch_id=? AND step_index=? AND job_id=?
                 AND status IN ('running','not_attempted')
                 AND EXISTS (
                     SELECT 1 FROM jobs WHERE id=? AND status='failed'
                       AND failure_kind='pre_execution_rejected')
                 AND EXISTS (
                     SELECT 1 FROM command_batches WHERE id=?
                       AND status IN ('queued','running'))""",
            (now, batch_id, index, job_id, job_id, batch_id),
        )
        if updated.rowcount != 1:
            raise RuntimeError("No durable proof of pre-execution rejection")
        completed = db.execute(
            """UPDATE command_batches
               SET status='rejected',failure_kind='pre_execution_rejected',
                   failed_step=?,updated_at=?,ended_at=?
               WHERE id=? AND status IN ('queued','running')""",
            (index, now, now, batch_id),
        )
        if completed.rowcount != 1:
            raise RuntimeError("Cannot finish unconfirmed batch rejection")

    def finish_rejected_child(self, batch_id: str, index: int, job_id: str) -> None:
        """Keep child and parent consistent across restart/crash boundaries."""
        with self.jobs._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._finish_rejected_child_in_tx(db, batch_id, index, job_id, time.time())
            db.execute("COMMIT")

    def uncertain_step(self, batch_id: str, index: int) -> None:
        """A crash or storage error after dispatch never means not attempted."""
        with self.jobs._connect() as db:
            db.execute(
                """UPDATE command_batch_steps SET status='unknown',
                   result_status='interrupted',ended_at=?
                   WHERE batch_id=? AND step_index=? AND
                   (status='running' OR (status='not_attempted'
                     AND job_id IS NOT NULL AND EXISTS(
                       SELECT 1 FROM jobs
                       WHERE jobs.id=command_batch_steps.job_id
                       AND jobs.started_at IS NOT NULL)))""",
                (time.time(), batch_id, index),
            )

    def finish(self, batch_id: str, status: str, *,
               failure_kind: str | None = None, failed_step: int | None = None,
               failed_field: str | None = None, effective_cwd: str | None = None,
               error: str | None = None) -> None:
        if status not in BATCH_TERMINAL:
            raise ValueError("Invalid batch outcome")
        with self.jobs._connect() as db:
            db.execute(
                """UPDATE command_batches SET status=?,failure_kind=?,failed_step=?,error=?,
                   failed_field=?,effective_cwd=COALESCE(?,effective_cwd),
                   updated_at=?,ended_at=?
                   WHERE id=? AND status IN ('queued','running')""",
                (status, failure_kind, failed_step, error, failed_field, effective_cwd,
                 time.time(), time.time(), batch_id),
            )

    def remember_cwd(self, batch_id: str, canonical: str) -> None:
        with self.jobs._connect() as db:
            db.execute("UPDATE command_batches SET effective_cwd=?,updated_at=? WHERE id=?",
                       (canonical, time.time(), batch_id))

    def get(self, actor: str, batch_id: str, *, cursor: int = 0,
            limit: int = 5) -> dict[str, Any] | None:
        if not 0 <= cursor <= 4 or not 1 <= limit <= 5:
            raise ValueError("Invalid batch pagination")
        with self.jobs._connect() as db:
            batch = db.execute(
                "SELECT * FROM command_batches WHERE id=? AND actor=?",
                (batch_id, actor),
            ).fetchone()
            if batch is None:
                return None
            rows = db.execute(
                """SELECT s.*, j.error AS job_error FROM command_batch_steps s
                   LEFT JOIN jobs j ON j.id=s.job_id
                   WHERE s.batch_id=? AND s.step_index>=? ORDER BY s.step_index LIMIT ?""",
                (batch_id, cursor, limit),
            ).fetchall()
        steps = [{
            "index": row["step_index"],
            "step_id": f"{batch_id}:{row['step_index']}",
            "status": row["status"],
            "result_status": row["result_status"],
            "job_id": row["job_id"],
            "command": row["command"],
            "command_sha256": row["command_sha256"],
            "exit_code": row["exit_code"],
            "exit_accepted": (None if row["exit_accepted"] is None
                              else bool(row["exit_accepted"])),
            "elapsed_seconds": row["elapsed_seconds"],
            "attempted": row["status"] != "not_attempted",
            **({"error": row["job_error"]} if (row["job_error"] or "").startswith("Host readiness unavailable:") else {}),
        } for row in rows]
        total = int(batch["total_steps"])
        following = cursor + len(rows)
        if batch["status"] in {"denied", "rejected"} and not rows:
            following = total  # Legacy denied manifest, no steps were ever inserted.
        return {
            "batch_id": batch["id"], "server": batch["server"],
            "story_id": batch["story_id"],
            "conversation_id": batch["conversation_id"],
            "reason": batch["reason"],
            "status": batch["status"], "failure_kind": batch["failure_kind"],
            **({"error": batch["error"]} if batch["error"] else {}),
            "failed_step": batch["failed_step"],
            "failed_field": batch["failed_field"],
            "requested_cwd": batch["requested_cwd"],
            "effective_cwd": batch["effective_cwd"],
            "strict_bash": bool(batch["strict_bash"]),
            "privileged": bool(batch["privileged"]),
            "run_as": "root" if batch["privileged"] else batch["ssh_username"],
            "stop_on_error": bool(batch["stop_on_error"]),
            "timeout_seconds": batch["timeout_seconds"],
            "total_steps": total, "steps": steps,
            "approval_status": decode(batch["approval_status"]),
            "next_cursor": following if following < total else None,
            "has_more": following < total,
        }

    def list(self, actor: str, *, cursor: int = 0, limit: int = 10) -> dict[str, Any]:
        if not 0 <= cursor <= 1000000 or not 1 <= limit <= 50:
            raise ValueError("Invalid batch pagination")
        with self.jobs._connect() as db:
            rows = db.execute(
                """SELECT id,server,story_id,conversation_id,status,total_steps,created_at,privileged,ssh_username
                   FROM command_batches WHERE actor=? ORDER BY created_at DESC,id DESC
                   LIMIT ? OFFSET ?""",
                (actor, limit + 1, cursor),
            ).fetchall()
        return {
            "batches": [{
                "batch_id": row["id"], "server": row["server"],
                "story_id": row["story_id"],
                "conversation_id": row["conversation_id"],
                "status": row["status"],
                "privileged": bool(row["privileged"]),
                "run_as": "root" if row["privileged"] else row["ssh_username"],
                "total_steps": row["total_steps"], "created_at": row["created_at"],
            } for row in rows[:limit]],
            "next_cursor": cursor + limit if len(rows) > limit else None,
        }


class BatchManager:
    """Shield in-process batch work from MCP disconnect; never auto-replay."""

    def __init__(self, jobs: JobManager):
        self.jobs = jobs
        self.executor: SSHExecutor = jobs.executor
        self.store = BatchStore(jobs.store)
        self._tasks: dict[str, asyncio.Task[None]] = {}

    async def execute(self, actor: str, request: ExecuteCommandsRequest, *,
                      admitted_root: bool = False,
                      precreated_id: str | None = None) -> dict[str, Any]:
        # All Pydantic steps are validated before a durable batch is allocated.
        # Authorize once now and re-authorize for every SSH step via JobManager.
        try:
            if request.privileged and not admitted_root:
                raise SSHDenied("Privileged execution is not enabled")
            host = self.executor.authorized_host(actor, request.server)
            if len(self._tasks) >= self.jobs.max_active:
                raise RuntimeError("Too many active batches")
        except (SSHDenied, RuntimeError) as exc:
            if precreated_id is not None:
                reason = "capacity" if isinstance(exc, RuntimeError) else "authorization"
                self.store.reject_unscheduled(precreated_id, reason)
            raise
        self.store.prune()
        batch_id = precreated_id or self.store.create(
            actor, request, username=getattr(host, "username", None),
        )
        task = asyncio.create_task(self._run(
            actor, batch_id, request, admitted_root=admitted_root,
        ))
        access = root_access_context.get()
        if request.privileged and access is not None:
            access.delegate()
        self._tasks[batch_id] = task
        task.add_done_callback(lambda _: self._tasks.pop(batch_id, None))
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            # The request may have disconnected. Execution remains in the
            # process and is recoverable by list_batches / get_batch.
            raise
        return self.get(actor, batch_id)

    async def _run(self, actor: str, batch_id: str,
                   request: ExecuteCommandsRequest, *,
                   admitted_root: bool = False) -> None:
        try:
            await self._run_inner(actor, batch_id, request, admitted_root=admitted_root)
        finally:
            if request.privileged:
                finish_once_root()

    async def _run_inner(self, actor: str, batch_id: str,
                         request: ExecuteCommandsRequest, *,
                         admitted_root: bool = False) -> None:
        if not self.store.begin(batch_id):
            return
        started = time.monotonic()
        deadline = started + request.timeout_seconds
        failure_seen = False
        first_failed_index: int | None = None
        effective_cwd: str | None = None
        active_index: int | None = None
        step_timeout_scope: asyncio.Timeout | None = None
        try:
            if request.cwd is not None and not request.privileged:
                # Real SSH preflight is read-only and uses the existing pinned
                # host identity/user. Bound *the whole await*, including the
                # global/host semaphore queue, by the overall batch deadline.
                # No command is attempted until preflight succeeds.
                try:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError
                    first_timeout = min(
                        request.commands[0].timeout_seconds or request.timeout_seconds,
                        math.ceil(remaining),
                    )
                    cwd_result = await asyncio.wait_for(
                        self.executor.preflight_cwd(
                            actor, request.step_command(
                                0, timeout_seconds=max(1, first_timeout),
                            ),
                        ),
                        timeout=remaining,
                    )
                except TimeoutError:
                    self.store.finish(
                        batch_id, "timed_out", failure_kind="overall_timeout",
                        failed_field="cwd",
                    )
                    return
                except ReadinessDenied as exc:
                    self.store.finish(batch_id, "rejected", failure_kind="host_readiness",
                                      error=str(exc))
                    return
                except SSHDenied:
                    self.store.finish(batch_id, "rejected", failure_kind="cwd_denied",
                                      failed_field="cwd")
                    return
                if isinstance(cwd_result, SSHResult):
                    self.store.finish(batch_id, cwd_result.status
                                      if cwd_result.status in BATCH_TERMINAL else "rejected",
                                      failure_kind="cwd_preflight",
                                      failed_field="cwd")
                    return
                effective_cwd = cwd_result[0]
                self.store.remember_cwd(batch_id, effective_cwd)

            for index in range(len(request.commands)):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.store.finish(batch_id, "timed_out",
                                      failure_kind="overall_timeout", failed_step=index)
                    return
                total = sum(
                    (self.jobs.store.get(actor, s["job_id"]) or {}).get("output_bytes", 0)
                    for s in (self.store.get(actor, batch_id) or {})["steps"]
                    if s["job_id"]
                )
                remaining_output = max(0, MAX_BATCH_OUTPUT_BYTES - total)
                step = request.commands[index]
                step_timeout = max(1, min(math.ceil(remaining),
                                          step.timeout_seconds or request.timeout_seconds))
                command = request.step_command(index, timeout_seconds=step_timeout)
                active_index = index
                # Keep the real deadline context. Wall-clock elapsed alone
                # cannot distinguish a fired timeout from cancelled cleanup
                # that happens to finish after the deadline.
                step_timeout_scope = asyncio.timeout(
                    max(0.01, deadline - time.monotonic()),
                )
                try:
                    async with step_timeout_scope:
                        job_id, result = await self.jobs.execute_sync(
                            actor, command,
                            on_created=lambda id: self.store.record_step(batch_id, index, id),
                            on_started=lambda id: self.store.admitted_step(batch_id, index, id),
                            max_output_bytes=remaining_output,
                            **({"retain_once_unlock": True}
                               if request.privileged
                               and (root_access_context.get() is not None
                                    and root_access_context.get().scope.kind == "request")
                               else {}),
                            **({"admitted_root": True} if admitted_root else {}),
                        )
                except TimeoutError:
                    self.store.uncertain_step(batch_id, index)
                    active_index = None
                    self.store.finish(batch_id, "timed_out",
                                      failure_kind="overall_timeout",
                                      failed_step=index, effective_cwd=effective_cwd)
                    return
                except Exception:
                    # A queued child job could exist when failure arrives
                    # before started_step; startup recovery remains cautious.
                    self.store.uncertain_step(batch_id, index)
                    self.store.finish(batch_id, "interrupted",
                                      failure_kind="execution_uncertain",
                                      failed_step=index, effective_cwd=effective_cwd)
                    return
                step_timeout_scope = None
                if result is None:
                    child = self.jobs.get(actor, job_id)
                    if (child is not None and child["status"] == "failed"
                            and child["failure_kind"] == "pre_execution_rejected"):
                        # SSH/CWD preflight may have run after capacity admission,
                        # but the requested argv definitely did not execute.
                        # Preserve the child job ID for History and audit.
                        try:
                            self.store.finish_rejected_child(batch_id, index, job_id)
                        except Exception:
                            # The child has already durably proved that caller
                            # argv never ran. A settlement write failure must
                            # not fall into the generic interrupted/unknown
                            # handler, which would erase that evidence. Leave
                            # the running batch for startup reconciliation.
                            active_index = None
                            return
                        active_index = None
                        return
                    # An unconfirmed child that acquired capacity may already
                    # have run argv. Conservatively preserve uncertainty.
                    self.store.uncertain_step(batch_id, index)
                    step_state = self.store.get(actor, batch_id)["steps"][index]["status"]
                    never_admitted = (
                        step_state == "not_attempted" and child is not None
                        and child["started_at"] is None
                    )
                    if never_admitted and child["status"] == "cancelled":
                        outcome, kind = "cancelled", "child_cancelled_before_execution"
                    elif never_admitted and child["status"] == "failed":
                        outcome, kind = "failed", "pre_execution_failure"
                    else:
                        outcome, kind = "interrupted", "execution_uncertain"
                    active_index = None
                    self.store.finish(
                        batch_id, outcome, failure_kind=kind,
                        failed_step=index, effective_cwd=effective_cwd,
                    )
                    return

                mapped = {
                    "succeeded": "succeeded", "command_error": "failed",
                    "timed_out": "timed_out", "transport_error": "transport_error",
                    "output_limit": "output_limit",
                }[result.status]
                self.store.completed_step(
                    batch_id, index, status=mapped, result_status=result.status,
                    exit_code=result.exit_code, exit_accepted=result.exit_accepted,
                    elapsed_seconds=result.elapsed_seconds,
                )
                active_index = None
                if result.effective_cwd is not None:
                    effective_cwd = result.effective_cwd
                    self.store.remember_cwd(batch_id, effective_cwd)
                if result.status != "succeeded":
                    failure_seen = True
                    if first_failed_index is None:
                        first_failed_index = index
                    # A timed-out/transport-uncertain/overflowed step must
                    # never be followed automatically, even if opt-out of
                    # ordinary stop-on-error was explicitly requested.
                    # stop_on_error=false applies to an actual command's
                    # nonaccepted exit, never failed sudo authentication or
                    # root setup: later steps must not retry privilege use.
                    privileged_failure = result.failure_kind in {
                        "sudo_authentication", "sudo_authorization",
                        "sudo_rejected", "root_unconfirmed", "root_setup_failed",
                        "cwd_preflight", "remote_signal",
                    }
                    if (request.stop_on_error or result.status != "command_error"
                            or privileged_failure):
                        self.store.finish(
                            batch_id, mapped,
                            failure_kind=(result.failure_kind if privileged_failure
                                          else result.status),
                            failed_step=index, effective_cwd=effective_cwd,
                        )
                        return

            self.store.finish(
                batch_id, "failed" if failure_seen else "succeeded",
                failure_kind="nonaccepted_exit" if failure_seen else None,
                failed_step=first_failed_index,
                effective_cwd=effective_cwd,
            )
        except asyncio.CancelledError:
            if active_index is not None:
                # The child may still be queued. Unknown is reserved for a
                # started step whose outcome was not acknowledged.
                self.store.uncertain_step(batch_id, active_index)
            if step_timeout_scope is not None and step_timeout_scope.expired():
                # Only a timeout callback that actually fired may win over
                # a simultaneous explicit cancellation. Synchronous cleanup
                # can cross the deadline after an unrelated cancellation.
                self.store.finish(
                    batch_id, "timed_out", failure_kind="overall_timeout",
                    failed_step=active_index, effective_cwd=effective_cwd,
                )
                return
            self.store.finish(batch_id, "interrupted", failure_kind="cancelled",
                              failed_step=active_index, effective_cwd=effective_cwd)
            raise
        except Exception:
            # Do not log secrets or error text; reconciliation is read-only.
            if active_index is not None:
                self.store.uncertain_step(batch_id, active_index)
            self.store.finish(batch_id, "interrupted",
                              failure_kind="execution_uncertain",
                              failed_step=active_index, effective_cwd=effective_cwd)

    def get(self, actor: str, batch_id: str, *, cursor: int = 0,
            limit: int = 5) -> dict[str, Any] | None:
        row = self.store.get(actor, batch_id, cursor=cursor, limit=limit)
        if row is None:
            return None
        for step in row["steps"]:
            job_id = step["job_id"]
            if not job_id:
                continue
            saved = self.jobs.get(actor, job_id)
            if saved is None:
                step["output_unavailable"] = True
                continue
            detail = self.jobs.output(
                actor, job_id, max_bytes=MAX_STEP_PREVIEW_BYTES,
            )
            if detail is None:
                step["output_unavailable"] = True
                continue
            buffers: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
            for chunk in detail["chunks"]:
                buffers[chunk["stream"]].extend(base64.b64decode(chunk["data_base64"]))
            step["stdout"] = buffers["stdout"].decode("utf-8", errors="replace")
            step["stderr"] = buffers["stderr"].decode("utf-8", errors="replace")
            step["output_truncated"] = detail["truncated"]
            step["output_bytes"] = saved["output_bytes"]
            step["output_next_cursor"] = detail["next_cursor"]
        # Full response must remain below the configured aggregate output and
        # metadata cap; summary previews are <=4 KiB per each of <=5 steps.
        if len(json.dumps(row, ensure_ascii=False).encode("utf-8")) > MAX_BATCH_RESPONSE_BYTES:
            raise RuntimeError("Bounded batch response exceeded configured budget")
        return row

    def list(self, actor: str, *, limit: int = 10, cursor: int = 0) -> dict[str, Any]:
        return self.store.list(actor, limit=limit, cursor=cursor)

    def cancel(
        self, actor: str, batch_id: str, *,
        reason: str = "Cancellation requested", via: str = "mcp",
    ) -> dict[str, Any] | None:
        row = self.store.get(actor, batch_id, limit=1)
        if row is None:
            return None
        task = self._tasks.get(batch_id)
        if task is None or task.done():
            return {"batch_id": batch_id, "cancellation_requested": False,
                    "status": row["status"]}
        requested = self.jobs.store.record_cancellation(
            "batch", actor, batch_id, via=via, reason=reason,
        )
        if requested:
            # The atomic event insert also settles queued batches; an
            # in-flight batch is interrupted by its existing task handler.
            task.cancel()
        return {"batch_id": batch_id, "cancellation_requested": requested,
                "status": ("cancelled" if requested and row["status"] == "queued"
                           else row["status"])}

    async def shutdown(self) -> None:
        pending = list(self._tasks.values())
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
