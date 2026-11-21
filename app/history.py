"""Authenticated operator History, with narrowly scoped job cancellation.

The browser never receives an SSH OAuth token or a command-execution endpoint.
Viewer sessions are opaque random tokens, hashed in the private history database.
"""
from __future__ import annotations

import asyncio
import hashlib
import html
import hmac
import json
import os
import re
import secrets
import shlex
import sqlite3
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, AsyncIterator, List, Protocol, cast
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from starlette.concurrency import run_in_threadpool

from . import config
from .client_identity import UNKNOWN_AGENT, agent_label
from .form_body import read_bounded_body
from .approvals import ApprovalManager, DURATIONS
from .jobs import JobStore
from .readiness import ReadinessMonitor

if TYPE_CHECKING:
    from .jobs import JobManager


class BatchCanceller(Protocol):
    """Tiny typed dependency surface; History does not import batch runtime."""

    def cancel(
        self, actor: str, batch_id: str, *,
        reason: str, via: str,
    ) -> dict[str, Any] | None: ...


SESSION_COOKIE = "__Host-ssh-mcp-console"
CSRF_COOKIE = "__Host-ssh-mcp-console-csrf"
LEGACY_SESSION_COOKIE = "__Host-skym-history"
LEGACY_CSRF_COOKIE = "__Host-skym-history-csrf"
IDLE_SECONDS = int(os.getenv('HISTORY_IDLE_TIMEOUT_SECONDS', str(8 * 3600)))
ABSOLUTE_SECONDS = int(os.getenv('HISTORY_ABSOLUTE_TIMEOUT_SECONDS', str(24 * 3600)))
LOGIN_WINDOW = 300
LOGIN_MAX_FAILURES = 5
JOB_ID = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
CURSOR = re.compile(r"^([0-9]{1,14}(?:\.[0-9]{1,9})?):([A-Za-z0-9_-]{1,128})$")
ASSETS = Path(__file__).parent / "assets"
STATES = frozenset({
    "awaiting_approval", "queued", "running", "succeeded", "failed", "cancelled", "timed_out",
    "transport_error", "output_limit", "interrupted", "partial", "unknown", "denied",
})

TIME_RANGES = {"1h": 3600, "8h": 8 * 3600, "24h": 24 * 3600,
               "7d": 7 * 86400, "30d": 30 * 86400, "all": None}


def _headers() -> dict[str, str]:
    return {
        "Cache-Control": "no-store", "Pragma": "no-cache",
        "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
        # "no-referrer" makes browser form POSTs send Origin: null.
        # same-origin preserves CSRF Origin checks without cross-site Referer leakage.
        "Referrer-Policy": "same-origin",
        "Content-Security-Policy": (
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        ),
    }


def _json(payload: dict[str, Any], code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=code, headers=_headers())


def _cursor(raw: str | None) -> tuple[float, str] | None:
    if not raw:
        return None
    match = CURSOR.fullmatch(raw)
    if not match:
        raise ValueError("Invalid history cursor")
    return float(match[1]), match[2]


def _encode_cursor(row: sqlite3.Row | None, field: str) -> str:
    return f"{row[field]:.9f}:{row['id']}" if row else ""


def _date_epoch(value: str | None, *, end: bool) -> float | None:
    if not value:
        return None
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("Invalid date filter")
    date = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return (date + timedelta(days=1) if end else date).timestamp()


def _plain_command(request: dict[str, Any] | None) -> str | None:
    if not request:
        return None
    argv = request.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        return None
    if len(argv) == 3 and Path(argv[0]).name in {"bash", "sh"} and argv[1] in {"-c", "-lc"}:
        return cast(str, argv[2])  # The user's actual terminal-style batch.
    return shlex.join(argv)  # Exact shell-safe reconstruction for direct argv.


class HistoryStore:
    """Admin read model, distinct from the actor-scoped MCP JobStore interface."""

    def __init__(self, jobs: JobStore):
        self.jobs = jobs

    @staticmethod
    def _client_id(client_id: str | None, actor: str) -> str | None:
        # The one-time audit migration normalizes all historical rows.
        # Never infer an OAuth identity from a mutable audit actor.
        return client_id

    @staticmethod
    def _agent_key(client_id: str | None, actor: str) -> str:
        resolved = HistoryStore._client_id(client_id, actor)
        return resolved if resolved is not None and resolved in config.MCP_CLIENT_LABELS else UNKNOWN_AGENT

    def _connect(self) -> sqlite3.Connection:
        db = self.jobs._connect()
        db.create_function("history_agent_key", 2, self._agent_key, deterministic=True)
        return db

    @staticmethod
    def _summary(row: sqlite3.Row) -> dict[str, Any]:
        item = JobStore._summary(row)
        item["actor"] = row["actor"]
        client_id = HistoryStore._client_id(row["client_id"], row["actor"])
        item["agent"] = agent_label(client_id, config.MCP_CLIENT_LABELS)
        item["agent_key"] = HistoryStore._agent_key(row["client_id"], row["actor"])
        item["record_kind"] = row["record_kind"]
        item["operation_kind"] = row["operation_kind"]
        item["path_summary"] = row["path_summary"]
        item["byte_count"] = row["byte_count"]
        item["error_code"] = row["error_code"]
        item["reason"] = None
        if row["record_kind"] == "batch":
            item["command_preview"] = f"execute_commands ({row['argv_count']} steps)"
            item["reason"] = ((json.loads(row["request_json"]) or {}).get("reason")
                              if row["request_json"] else None)
            return item
        if row["record_kind"] == "file":
            item["command_preview"] = f"{row['operation_kind']} {row['path_summary']}"
            return item
        # Use the actual terminal command rather than just argv[0].
        # Keep previews bounded and single-line; full requests stay in detail.
        try:
            request = json.loads(row["request_json"]) if row["request_json"] else None
            full = _plain_command(request)
            if isinstance(request, dict) and isinstance(request.get("reason"), str):
                item["reason"] = request["reason"][:200]
        except (json.JSONDecodeError, TypeError, ValueError):
            full = None
        first = next((line.strip() for line in (full or row["command"]).splitlines()
                      if line.strip()), row["command"])
        item["command_preview"] = first[:287] + "…" if len(first) > 288 else first
        return item

    @staticmethod
    def _totals(db: sqlite3.Connection, time_range: str = "") -> dict[str, int]:
        """Count retained jobs within the chosen time range, ignoring other filters."""
        where, params = HistoryStore._where({"time_range": time_range})
        counts = {
            row["status"]: row["count"]
            for row in db.execute(
                f"SELECT status, COUNT(*) AS count FROM history_events WHERE {' AND '.join(where)} GROUP BY status",
                params,
            )
        }
        return {
            "total": sum(counts.values()),
            "running": counts.get("queued", 0) + counts.get("running", 0),
            "succeeded": counts.get("succeeded", 0),
            "failed": sum(counts.get(kind, 0) for kind in (
                "failed", "timed_out", "transport_error", "output_limit", "interrupted", "partial", "unknown", "denied"
            )),
            "cancelled": counts.get("cancelled", 0),
        }

    def totals(self, time_range: str = "") -> dict[str, int]:
        with self._connect() as db:
            return self._totals(db, time_range)

    def list(self, filters: dict[str, str], *, before: str | None = None,
             limit: int = 50, page: int | None = None) -> dict[str, Any]:
        if not 1 <= limit <= 100 or page is not None and not 1 <= page <= 100000:
            raise ValueError("Invalid history page")
        if page is not None and before is not None:
            raise ValueError("Cannot combine numbered and cursor pagination")
        where, params = self._where(filters)
        # Count with the same filters and snapshot as the selected page. Keep
        # the existing cursor protocol available for older API clients.
        clause = " AND ".join(where)
        with self._connect() as db:
            db.execute("BEGIN")
            filtered_total = int(db.execute(
                f"SELECT COUNT(*) FROM history_events WHERE {clause}", params
            ).fetchone()[0])
            page_count = max(1, (filtered_total + limit - 1) // limit)
            if page is not None:
                page = min(page, page_count)
                rows = db.execute(
                    f"SELECT * FROM history_events WHERE {clause} ORDER BY created_at DESC,id DESC "
                    "LIMIT ? OFFSET ?",
                    (*params, limit, (page - 1) * limit),
                ).fetchall()
            else:
                cursor_where, cursor_params = list(where), list(params)
                bound = _cursor(before)
                if bound is not None:
                    cursor_where.append("(created_at < ? OR (created_at = ? AND id < ?))")
                    cursor_params.extend([bound[0], bound[0], bound[1]])
                rows = db.execute(
                    f"SELECT * FROM history_events WHERE {' AND '.join(cursor_where)} "
                    "ORDER BY created_at DESC,id DESC LIMIT ?",
                    (*cursor_params, limit + 1),
                ).fetchall()
            newest = db.execute(
                "SELECT updated_at,id FROM history_events ORDER BY updated_at DESC,id DESC LIMIT 1"
            ).fetchone()
            totals = self._totals(db, filters.get("time_range", ""))
            db.execute("COMMIT")
        display = rows[:limit]
        result = {
            "jobs": [self._summary(row) for row in display],
            "next_page": _encode_cursor(display[-1], "created_at")
                         if page is None and len(rows) > limit and display else None,
            "changes_cursor": _encode_cursor(newest, "updated_at") or "0:_",
            "totals": totals,
            "filtered_total": filtered_total,
        }
        if page is not None:
            result.update(page=page, page_count=page_count, page_size=limit)
        return result

    @staticmethod
    def _where(filters: dict[str, str]) -> tuple[List[str], List[Any]]:
        where = ["1=1"]
        params: list[Any] = []
        # The browser is an independent authenticated operator view. MCP
        # always injects its server-derived, client-scoped actor here.
        scoped_actor = filters.get("actor")
        if scoped_actor is not None:
            if not isinstance(scoped_actor, str) or not scoped_actor:
                raise ValueError("Invalid audit actor")
            where.append("actor=?")
            params.append(scoped_actor)
        agent = filters.get("agent", "")
        if agent:
            if agent != UNKNOWN_AGENT and agent not in config.MCP_CLIENT_LABELS:
                raise ValueError("Invalid history agent filter")
            where.append("history_agent_key(client_id,actor)=?")
            params.append(agent)
        record_kind = filters.get("record_kind", "all")
        if record_kind not in {"all", "command", "file", "batch"}:
            raise ValueError("Invalid record kind")
        if record_kind != "all":
            where.append("record_kind=?")
            params.append(record_kind)
        for key, column in (("host", "server"), ("status", "status"), ("mode", "mode"),
                            ("story_id", "story_id"), ("conversation_id", "conversation_id")):
            value = filters.get(key, "").strip()
            if not value:
                continue
            if len(value) > (256 if key == "conversation_id" else 80) or (
                key == "status" and value not in STATES
            ) or (
                key == "mode" and value not in {"sync", "async", "file", "batch"}
            ):
                raise ValueError("Invalid history filter")
            if key == "story_id":
                if re.fullmatch(r"[0-9]{1,9}", value):
                    # Numeric shorthand matches any PROJECT-N, not a
                    # formerly hardcoded organization's issue prefix.
                    # Also find native numeric IDs, without losing leading zeros.
                    where.append("(story_id=? OR story_id GLOB ?)")
                    params.extend([value, "*-" + str(int(value))])
                    continue
                if re.fullmatch(r"[A-Z][A-Z0-9]{1,12}-[1-9][0-9]*",
                                value, flags=re.IGNORECASE | re.ASCII):
                    where.append("UPPER(story_id)=?")
                    params.append(value.upper())
                    continue
            where.append(f"{column}=?")
            params.append(value)
        command = filters.get("command", "").strip()
        if command:
            if len(command) > 64:
                raise ValueError("Command filter is too long")
            # Match both executable names and full recorded command arguments.
            # The browser displays only the bounded first-line preview.
            where.append("(LOWER(command) LIKE ? ESCAPE '\\' OR "
                         "LOWER(COALESCE(request_json, '')) LIKE ? ESCAPE '\\' OR "
                         "LOWER(COALESCE(path_summary, '')) LIKE ? ESCAPE '\\')")
            needle = "%" + command.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            params.extend([needle, needle, needle])
        privileged = filters.get("privileged", "")
        if privileged not in {"", "true"}:
            raise ValueError("Invalid privileged history filter")
        if privileged == "true":
            # File operations are not root-execution records. Use the
            # persisted privilege flag, never command text or exit status.
            where.append("record_kind!='file' AND privileged=1")
        time_range = filters.get("time_range", "")
        if time_range:
            if time_range not in TIME_RANGES:
                raise ValueError("Invalid time range")
            seconds = TIME_RANGES[time_range]
            if seconds is not None:
                where.append("created_at>=?")
                params.append(time.time() - seconds)
        after = _date_epoch(filters.get("from_date"), end=False)
        before = _date_epoch(filters.get("to_date"), end=True)
        if after is not None:
            where.append("created_at>=?")
            params.append(after)
        if before is not None:
            where.append("created_at<?")
            params.append(before)
        if after is not None and before is not None and after >= before:
            raise ValueError("Date interval is invalid")
        return where, params

    def hosts(self, *, actor: str | None = None) -> List[str]:
        """Historical aliases, optionally restricted to the authenticated client actor."""
        clause = "WHERE actor=?" if actor is not None else ""
        params = (actor,) if actor is not None else ()
        with self._connect() as db:
            rows = db.execute(
                f"SELECT DISTINCT server FROM history_events {clause} "
                "ORDER BY server LIMIT 501", params
            ).fetchall()
        if len(rows) > 500:
            raise ValueError("History host list exceeds limit")
        return [str(row["server"]) for row in rows]

    def stats(self, filters: dict[str, str], *, group_by: str = "host",
              limit: int = 50) -> dict[str, Any]:
        """Bounded grouped statistics computed from retained history, not telemetry."""
        groups = {
            "host": "server", "status": "status", "story_id": "story_id",
            "day": "strftime('%Y-%m-%d', created_at, 'unixepoch')",
        }
        if group_by not in groups or not 1 <= limit <= 100:
            raise ValueError("Invalid grouping")
        where, params = self._where(filters)
        clause = " AND ".join(where)
        column = groups[group_by]
        with self._connect() as db:
            db.execute("BEGIN")
            row = db.execute(
                f"SELECT COUNT(*) AS total, COUNT(elapsed_seconds) AS timed, "
                f"COALESCE(SUM(elapsed_seconds),0) AS duration "
                f"FROM history_events WHERE {clause}", params,
            ).fetchone()
            status_counts = {
                str(r["status"]): int(r["total"])
                for r in db.execute(
                    f"SELECT status,COUNT(*) AS total FROM history_events "
                    f"WHERE {clause} GROUP BY status", params
                )
            }
            rows = db.execute(
                f"SELECT {column} AS name, COUNT(*) AS total, "
                f"COUNT(elapsed_seconds) AS timed, "
                f"COALESCE(SUM(elapsed_seconds),0) AS duration "
                f"FROM history_events WHERE {clause} "
                f"GROUP BY {column} ORDER BY total DESC,name LIMIT ?",
                (*params, limit + 1),
            ).fetchall()
            db.execute("COMMIT")
        failed = sum(status_counts.get(k, 0) for k in (
            "failed", "timed_out", "transport_error", "output_limit",
            "interrupted", "partial", "unknown", "denied",
        ))
        def duration(total: float, count: int) -> float | None:
            return round(total / count, 3) if count else None
        return {
            "total": int(row["total"]),
            "status_counts": status_counts,
            "failures": failed,
            "transport_errors": status_counts.get("transport_error", 0),
            "average_duration_seconds": duration(float(row["duration"]), int(row["timed"])),
            "duration_sample_count": int(row["timed"]),
            "group_by": group_by,
            "groups": [
                {"name": r["name"], "count": int(r["total"]),
                 "average_duration_seconds": duration(float(r["duration"]), int(r["timed"])),
                 "duration_sample_count": int(r["timed"])}
                for r in rows[:limit]
            ],
            "groups_truncated": len(rows) > limit,
            "time_range": filters.get("time_range", ""),
            "retained_only": True,
        }

    def changes(self, after: str, *, limit: int = 100) -> dict[str, Any]:
        bound = _cursor(after)
        if bound is None:
            raise ValueError("Change cursor is required")
        if not 1 <= limit <= 100:
            raise ValueError("Invalid change limit")
        with self._connect() as db:
            rows = db.execute(
                """SELECT * FROM history_events
                WHERE updated_at > ? OR (updated_at = ? AND id > ?)
                ORDER BY updated_at,id LIMIT ?""",
                (bound[0], bound[0], bound[1], limit + 1),
            ).fetchall()
        items = rows[:limit]
        return {
            "jobs": [self._summary(row) for row in items],
            "changes_cursor": _encode_cursor(items[-1], "updated_at") if items else after,
            "has_more": len(rows) > limit,
        }

    def detail(self, job_id: str) -> dict[str, Any] | None:
        if not JOB_ID.fullmatch(job_id):
            return None
        with self._connect() as db:
            row = db.execute("SELECT * FROM history_events WHERE id=?", (job_id,)).fetchone()
        if row is None:
            return None
        item = self._summary(row)
        client_id = self._client_id(row["client_id"], row["actor"])
        # Unknown metadata URLs may include a client-supplied query. Keep
        # that out of the browser while preserving the exact DB identity.
        item["client_id"] = client_id.split("?", 1)[0] if client_id else None
        if row["record_kind"] == "batch":
            item["request"] = json.loads(row["request_json"]) if row["request_json"] else None
            item["terminal_command"] = item["command_preview"]
            return item
        if row["record_kind"] == "file":
            item["request"] = None
            item["terminal_command"] = None
            item["file_metadata"] = (json.loads(row["result_metadata"])
                                     if row["result_metadata"] else {"outcomes": []})
            return item
        request = json.loads(row["request_json"]) if row["request_json"] is not None else None
        item["request"] = request
        item["terminal_command"] = _plain_command(request)
        return item

    def cancellation_request(self, job_id: str) -> dict[str, Any] | None:
        """Fetch rare cancellation metadata only for an opened detail pane."""
        with self._connect() as db:
            row = db.execute(
                """SELECT target_type,requested_via,requested_at,reason
                   FROM cancellation_requests
                   WHERE target_type='job' AND target_id=?""", (job_id,),
            ).fetchone()
            if row is None and db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='command_batch_steps'"
            ).fetchone():
                row = db.execute(
                    """SELECT c.target_type,c.requested_via,c.requested_at,c.reason
                       FROM command_batch_steps s
                       JOIN cancellation_requests c ON
                            c.target_type='batch' AND c.target_id=s.batch_id
                       WHERE s.job_id=? LIMIT 1""", (job_id,),
                ).fetchone()
        if row is None:
            return None
        return {
            "requested_via": row["requested_via"],
            "requested_at": datetime.fromtimestamp(
                row["requested_at"], timezone.utc,
            ).isoformat(),
            "reason": row["reason"],
            "target_type": row["target_type"],
        }

    def eligible_cancellation_ids(
        self, ids: List[str], *, actor: str, approved_hosts: set[str],
        batches_enabled: bool,
    ) -> set[str]:
        """One bounded status-only eligibility lookup for visible active rows.

        Avoid reading cancellation reasons or timestamps on ordinary History
        polling. Parent batch status and the existence of an accepted request
        must still be checked to avoid showing a stale cancel control.
        """
        if not ids or not approved_hosts:
            return set()
        ids = [identifier for identifier in ids if JOB_ID.fullmatch(identifier)]
        if not ids:
            return set()
        slots = ",".join("?" for _ in ids)
        hosts = ",".join("?" for _ in approved_hosts)
        params = (*ids, actor, *sorted(approved_hosts))
        with self._connect() as db:
            has_batches = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='command_batch_steps'"
            ).fetchone() is not None
            if not has_batches:
                rows = db.execute(
                    f"""SELECT id FROM jobs WHERE id IN ({slots}) AND actor=?
                       AND server IN ({hosts}) AND status IN ('queued','running')
                       AND cancel_requested=0""",
                    params,
                ).fetchall()
            else:
                rows = db.execute(
                    f"""SELECT j.id FROM jobs j
                       LEFT JOIN command_batch_steps s ON s.job_id=j.id
                       LEFT JOIN command_batches b ON b.id=s.batch_id
                       LEFT JOIN cancellation_requests c
                            ON c.target_type='batch' AND c.target_id=s.batch_id
                       WHERE j.id IN ({slots}) AND j.actor=?
                       AND j.server IN ({hosts}) AND j.status IN ('queued','running')
                       AND j.cancel_requested=0
                       AND (s.batch_id IS NULL OR
                            (? AND b.actor=j.actor AND b.server=j.server
                             AND b.status IN ('queued','running') AND c.target_id IS NULL))
                    """,
                    (*params, int(batches_enabled)),
                ).fetchall()
        return {str(row["id"]) for row in rows}

    def batch_step_outcome(self, job_id: str) -> dict[str, Any] | None:
        """Expose the authoritative batch step and parent outcomes in Details."""
        if not JOB_ID.fullmatch(job_id):
            return None
        with self._connect() as db:
            if not db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='command_batch_steps'"
            ).fetchone():
                return None
            row = db.execute(
                """SELECT s.step_index,s.status AS step_status,
                          s.result_status,b.status AS batch_status,
                          b.failure_kind AS batch_failure_kind
                   FROM command_batch_steps s
                   JOIN command_batches b ON b.id=s.batch_id
                   WHERE s.job_id=? LIMIT 1""",
                (job_id,),
            ).fetchone()
        return ({
            "step_index": row["step_index"],
            "step_status": row["step_status"],
            "result_status": row["result_status"],
            "batch_status": row["batch_status"],
            "batch_failure_kind": row["batch_failure_kind"],
        } if row else None)

    def cancellation_target(
        self, job_id: str, *, actor: str, approved_hosts: set[str],
    ) -> dict[str, Any] | None:
        """Resolve browser command rows to actor-owned jobs or parent batches."""
        if not JOB_ID.fullmatch(job_id):
            return None
        with self._connect() as db:
            job = db.execute(
                "SELECT id,actor,server,status,cancel_requested FROM jobs WHERE id=?",
                (job_id,),
            ).fetchone()
            if job is None or job["actor"] != actor or job["server"] not in approved_hosts:
                return None
            target_type, target_id = "job", job_id
            active = job["status"] in {"queued", "running"} and not job["cancel_requested"]
            if db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='command_batch_steps'"
            ).fetchone():
                batch = db.execute(
                    """SELECT b.id,b.status,b.actor,b.server
                       FROM command_batch_steps s JOIN command_batches b ON b.id=s.batch_id
                       WHERE s.job_id=? LIMIT 1""", (job_id,),
                ).fetchone()
                if batch is not None:
                    if batch["actor"] != actor or batch["server"] != job["server"]:
                        return None
                    target_type, target_id = "batch", batch["id"]
                    active = active and batch["status"] in {"queued", "running"}
            if db.execute(
                "SELECT 1 FROM cancellation_requests WHERE target_type=? AND target_id=?",
                (target_type, target_id),
            ).fetchone():
                active = False
        return {"target_type": target_type, "target_id": target_id,
                "available": bool(active)}

    def output(self, job_id: str, *, cursor: int = 0, max_bytes: int = 16384) -> dict[str, Any] | None:
        if not JOB_ID.fullmatch(job_id):
            return None
        with self._connect() as db:
            row = db.execute("SELECT actor,record_kind,status FROM history_events WHERE id=?",
                             (job_id,)).fetchone()
        if row is None:
            return None
        if row["record_kind"] in {"file", "batch"}:
            if cursor or not 1 <= max_bytes <= 65536:
                raise ValueError("File operations have no stored output")
            return {"job_id": job_id, "cursor": 0, "next_cursor": 0,
                    "chunks": [], "truncated": False, "status": row["status"]}
        return self.jobs.read_output(row["actor"], job_id, cursor=cursor, max_bytes=max_bytes)


class ViewerAuth:
    """Separate viewer-password check and revocable, idle-bound sessions."""

    def __init__(self, store: HistoryStore, password: str):
        if len(password) < 16 or password in {config.MCP_LOGIN_KEY}:
            raise RuntimeError("Viewer password must be distinct and contain 16+ characters")
        self.store = store
        self.password = password
        self.failed: dict[str, deque[float]] = defaultdict(deque)
        with self.store._connect() as db:
            # A password change revokes all old cookies, including after a restart.
            # Keep the salted verifier private; never store the password itself.
            db.execute("BEGIN IMMEDIATE")
            db.execute("""CREATE TABLE IF NOT EXISTS history_sessions (
                hash TEXT PRIMARY KEY,
                created_at REAL NOT NULL,
                last_seen REAL NOT NULL,
                generation TEXT NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS history_auth_state (
                id INTEGER PRIMARY KEY CHECK(id=1),
                salt BLOB NOT NULL,
                verifier BLOB NOT NULL,
                generation TEXT NOT NULL
            )""")
            state = db.execute(
                "SELECT salt,verifier,generation FROM history_auth_state WHERE id=1"
            ).fetchone()
            same_password = state is not None and hmac.compare_digest(
                hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes(state["salt"]), 200000),
                bytes(state["verifier"]),
            )
            if same_password:
                self.generation = str(state["generation"])
            else:
                self.generation = secrets.token_hex(16)
                salt = secrets.token_bytes(16)
                verifier = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)
                db.execute("DELETE FROM history_sessions")
                db.execute("""INSERT INTO history_auth_state(id,salt,verifier,generation)
                    VALUES(1,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET
                      salt=excluded.salt,verifier=excluded.verifier,
                      generation=excluded.generation""",
                    (salt, verifier, self.generation),
                )

    def allowed(self, ip: str) -> bool:
        now = time.time()
        failures = self.failed[ip]
        while failures and failures[0] <= now - LOGIN_WINDOW:
            failures.popleft()
        return len(failures) < LOGIN_MAX_FAILURES

    def login(self, ip: str, password: str) -> str | None:
        if not self.allowed(ip):
            return None
        if not secrets.compare_digest(password, self.password):
            self.failed[ip].append(time.time())
            return None
        self.failed.pop(ip, None)
        session = secrets.token_urlsafe(32)
        now = time.time()
        with self.store._connect() as db:
            inserted = db.execute(
                """INSERT INTO history_sessions(hash,created_at,last_seen,generation)
                   SELECT ?,?,?,? WHERE EXISTS(
                       SELECT 1 FROM history_auth_state WHERE id=1 AND generation=?
                   )""",
                (self._digest(session), now, now, self.generation, self.generation),
            )
        return session if inserted.rowcount == 1 else None

    @staticmethod
    def _digest(session: str) -> str:
        return hashlib.sha256(session.encode("utf-8")).hexdigest()

    def valid(self, session: str | None, *, touch: bool = True) -> bool:
        if not session or not 1 <= len(session) <= 128:
            return False
        now = time.time()
        digest = self._digest(session)
        with self.store._connect() as db:
            # Background SSE checks must not count as operator activity or
            # acquire the writer lock just to read session validity.
            if touch:
                db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT s.created_at,s.last_seen FROM history_sessions s
                   JOIN history_auth_state a ON a.id=1 AND a.generation=s.generation
                   WHERE s.hash=? AND s.generation=?""", (digest, self.generation)
            ).fetchone()
            if row is None:
                return False
            if now - row["created_at"] >= ABSOLUTE_SECONDS or now - row["last_seen"] >= IDLE_SECONDS:
                if touch:
                    db.execute("DELETE FROM history_sessions WHERE hash=?", (digest,))
                return False
            if touch and now - row["last_seen"] >= 30:
                db.execute("UPDATE history_sessions SET last_seen=? WHERE hash=?", (now, digest))
        return True

    def logout(self, session: str | None) -> None:
        if session:
            with self.store._connect() as db:
                db.execute("DELETE FROM history_sessions WHERE hash=?", (self._digest(session),))


async def _form(request: Request) -> dict[str, str]:
    if not request.headers.get("content-type", "").lower().startswith("application/x-www-form-urlencoded"):
        raise ValueError("Invalid form type")
    raw = await read_bounded_body(request, max_bytes=8192)
    return {key: value[-1] for key, value in parse_qs(raw.decode("utf-8"), keep_blank_values=True).items()}


def _same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    return origin is not None and origin.rstrip("/") == config.MCP_ISSUER


def _csrf_ok(request: Request, form: dict[str, str]) -> bool:
    cookie = request.cookies.get(CSRF_COOKIE, "")
    received = form.get("csrf", "")
    return bool(cookie and received and len(cookie) < 128 and secrets.compare_digest(cookie, received))


def _login_page(csrf: str, *, failed: bool = False) -> str:
    error = '<p class="login-error" role="alert">Invalid password or too many attempts.</p>' if failed else ""
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<title>SSH-MCP · Operator Console · Sign in</title>'
        '<link rel="stylesheet" href="/console/assets/style.css"></head>'
        '<body class="login-body"><main class="login-card">'
        '<div class="brand-mark">SSH-MCP</div><h1>Operator Console</h1>'
        '<p>Operator console access</p>' + error +
        '<form method="post" action="/console/login">'
        '<input type="hidden" name="csrf" value="' + html.escape(csrf, quote=True) + '">'
        '<label for="password">Console password</label>'
        '<input id="password" type="password" name="password" autocomplete="current-password" '
        'required maxlength="256" autofocus>'
        '<button class="primary" type="submit">Sign in</button></form></main></body></html>'
    )


def _approval_icon(kind: str) -> str:
    """Small decorative inline icons; no external font or inline JavaScript."""
    paths = {
        "sound": '<path d="M11 5 6 9H3v6h3l5 4V5Z"/><path d="M15 9a5 5 0 0 1 0 6M18 6a9 9 0 0 1 0 12"/>',
        "bell": '<path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4"/>',
        "agent": '<rect x="4" y="7" width="16" height="14" rx="3"/><path d="M12 3v4M9 3h6M8 13h1m6 0h1M9 17h6"/>',
        "host": '<rect x="4" y="3" width="16" height="8" rx="2"/><rect x="4" y="13" width="16" height="8" rx="2"/><path d="M8 7h.01M8 17h.01"/>',
        "conversation": '<path d="M4 4h16v13H9l-5 4V4Z"/><path d="M8 10h8"/>',
        "operation": '<circle cx="12" cy="12" r="3"/><path d="M10 2h4l1 3 3 1 3-1 2 4-3 2v2l3 2-2 4-3-1-3 1-1 3h-4l-1-3-3-1-3 1-2-4 3-2v-2L1 9l2-4 3 1 3-1z"/>',
        "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 6v6l4 2"/>',
        "reason": '<path d="M6 3h8l4 4v14H6V3Z"/><path d="M14 3v5h5M9 12h6M9 16h6"/>',
    }
    return ('<svg class="approval-icon" viewBox="0 0 24 24" fill="none"'
            ' stroke="currentColor" stroke-width="1.8" stroke-linecap="round"'
            ' stroke-linejoin="round" aria-hidden="true">' + paths[kind]
            + ('<path class="icon-slash" d="M3 3 21 21"/>' if kind in {"sound", "bell"} else '')
            + '</svg>')


def _history_page(csrf: str) -> str:
    story_chars = int(os.getenv("HISTORY_STORY_ID_MAX_CHARS", "16"))
    story_side = os.getenv("HISTORY_STORY_ID_TRUNCATE_FROM", "end")
    environment_label = {"lab": "LAB", "production": "PROD"}[config.MCP_ENVIRONMENT]
    version = config.MCP_SERVICE_VERSION
    prefix = "" if config.is_commit_version(version) else "v"
    version_label = (f'<span class="brand-version">{prefix}{html.escape(version)}</span>'
                     if version else "")
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>SSH-MCP · Operator Console · {environment_label}</title>'
        '<link rel="stylesheet" href="/console/assets/style.css"></head>'
        '<body><div id="app"><header class="topbar"><div class="brand">'
        '<span class="brand-mark">SSH-MCP</span>'
        f'<span class="brand-sub">{environment_label}</span>'
        f"{version_label}"
        '<h1 class="visually-hidden">SSH-MCP Operator Console</h1></div>'
        '<div class="top-actions"><div id="grant-chips" class="grant-chips"'
        ' aria-label="Active host access grants"></div>'
        '<div id="connection-wrap" class="connection-wrap">'
        '<button type="button" id="connection" class="connection offline" '
        'aria-expanded="false" aria-controls="connection-details">Disconnected</button>'
        '<section id="connection-details" class="connection-details" hidden '
        'aria-label="Host readiness"><strong id="readiness-summary"></strong>'
        '<div id="readiness-hosts"></div></section></div>'
        '<span id="approval-status" class="approval-status" role="alert" hidden></span>'
        '<form method="post" action="/console/logout">'
        '<input type="hidden" name="csrf" value="' + html.escape(csrf, quote=True) + '">'
        '<button type="submit" class="logout" aria-label="Sign out" title="Sign out">'
        '<svg class="logout-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"'
        ' stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"'
        ' aria-hidden="true"><path d="M9 4H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h4"/>'
        '<path d="M14 8l4 4-4 4M18 12H8"/></svg>'
        '</button></form></div></header>'
        '<div class="workspace" id="workspace"><section class="left-pane" id="left-pane">'
        '<section class="overview"><div class="metrics" aria-label="Job totals for selected time range">'
        '<div class="metric-card total"><span class="metric-icon" aria-hidden="true">▤</span>'
        '<span class="metric-caption">Total Records</span><strong id="metric-total">—</strong></div>'
        '<div class="metric-card running"><span class="metric-icon" aria-hidden="true">▷</span>'
        '<span class="metric-caption">Running</span><strong id="metric-running">—</strong></div>'
        '<div class="metric-card succeeded"><span class="metric-icon" aria-hidden="true">✓</span>'
        '<span class="metric-caption">Succeeded</span><strong id="metric-succeeded">—</strong></div>'
        '<div class="metric-card failed"><span class="metric-icon" aria-hidden="true">×</span>'
        '<span class="metric-caption">Failed</span><strong id="metric-failed">—</strong></div>'
        '<div class="metric-card cancelled"><span class="metric-icon" aria-hidden="true">⊘</span>'
        '<span class="metric-caption">Cancelled</span><strong id="metric-cancelled">—</strong></div>'
        '</div><div class="metrics-note" id="metrics-note">'
        'Last 24 hours · independent of other filters</div>'
        '<form class="filters" id="filters" role="search">'
        '<label class="filter-range">Time range<select name="time_range">'
        '<option value="1h">Last 1 hour</option><option value="8h">Last 8 hours</option>'
        '<option value="24h" selected>Last 24 hours</option>'
        '<option value="7d">Last 7 days</option><option value="30d">Last 30 days</option>'
        '<option value="all">All time</option></select></label>'
        '<label class="filter-agent">Agent<select name="agent">'
        '<option value="">All agents</option>' + "".join(
            f'<option value="{html.escape(client_id, quote=True)}">{html.escape(label)}</option>'
            for client_id, label in sorted(config.MCP_CLIENT_LABELS.items(), key=lambda pair: pair[1].casefold())
        ) + '<option value="unknown">Unknown</option></select></label>'
        '<label class="filter-story">Story ID<input name="story_id" placeholder="All stories"'
        ' maxlength="80"></label>'
        '<label class="filter-host">Host<select name="host" aria-label="Filter by registered host">'
        '<option value="">All hosts</option></select></label>'
        '<label class="filter-conversation">Conversation ID<span class="filter-search">'
        '<input name="conversation_id" placeholder="All conversations" maxlength="256"'
        ' aria-label="Filter by conversation ID">'
        '<button id="clear-conversation" type="button"'
        ' aria-label="Clear conversation filter"'
        ' title="Clear conversation filter" hidden>×</button></span></label>'
        '<label class="filter-command" for="command-search">Command<span class="filter-search">'
        '<button id="privileged-filter" class="privileged-filter" type="button"'
        ' aria-label="Show root commands only" aria-pressed="false"'
        ' title="Show root commands only">'
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"'
        ' stroke-width="2" stroke-linejoin="round" aria-hidden="true">'
        '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
        '</svg></button>'
        '<input id="command-search" name="command" placeholder="Search commands"'
        ' aria-label="Search commands" maxlength="64">'
        '<button id="clear-command" type="button" aria-label="Clear command filter"'
        ' title="Clear command filter" hidden>×</button></span></label>'
        '<label class="filter-mode">Mode<select name="mode">'
        '<option value="">All modes</option><option value="sync">Sync</option>'
        '<option value="async">Async</option>'
        '<option value="file">File</option><option value="batch">Batch</option></select></label>'
        '<label class="filter-status">Status<select name="status">'
        '<option value="">All statuses</option><option>awaiting_approval</option>'
        '<option>queued</option><option>running</option>'
        '<option>succeeded</option><option>failed</option><option>denied</option><option>cancelled</option>'
        '<option>timed_out</option><option>transport_error</option>'
        '<option>output_limit</option><option>interrupted</option>'
        '<option>partial</option><option>unknown</option></select></label>'
        '</form>'
        '</section><div class="list-wrap" id="list-wrap"><table class="jobs-table" id="history-table" '
        f'data-story-id-max-chars="{story_chars}" '
        f'data-story-id-truncate-from="{html.escape(story_side, quote=True)}">'
        '<colgroup><col class="col-time"><col class="col-agent"><col class="col-story"><col class="col-host">'
        '<col class="col-command"><col class="col-mode"><col class="col-status">'
        '<col class="col-duration"></colgroup><thead><tr>'
        '<th>Time <button id="time-toggle" class="time-toggle" type="button"'
        ' aria-label="Show relative times" aria-pressed="false"'
        ' title="Switch to relative times">⇄</button></th>'
        '<th>Agent</th><th>Story ID</th><th>Host</th><th>Command / File</th>'
        '<th>Mode</th><th>Status</th><th>Duration</th></tr></thead><tbody id="job-rows"></tbody></table>'
        '<div class="empty" id="empty">Loading history...</div>'
        '<div id="cancel-feedback" class="cancel-feedback" role="alert" hidden></div>'
        '</div><footer class="page-footer" aria-label="History pages">'
        '<button id="new-jobs" class="new-jobs" hidden type="button"></button>'
        '<span id="page-summary" aria-live="polite"></span>'
        '<nav id="pagination" aria-label="History page navigation"></nav>'
        '<label class="page-size">Rows per page: <select id="rows-per-page"'
        ' aria-label="Rows per page"><option value="auto" selected>Auto</option>'
        '<option value="10">10</option><option value="15">15</option>'
        '<option value="20">20</option><option value="25">25</option>'
        '<option value="50">50</option></select></label>'
        '</footer></section><div class="splitter" id="splitter" role="separator" '
        'aria-label="Resize history and details panels" aria-orientation="vertical" tabindex="0">'
        '<span></span></div><section class="right-pane" id="right-pane">'
        '<div id="detail-empty" class="detail-empty">Select a job to inspect its request and response.</div>'
        '<div id="detail" hidden><div class="detail-head"><h2 id="detail-title">Job details</h2>'
        '</div>'
        '<details class="job-info-panel" id="job-info-panel" open>'
        '<summary>Job information</summary>'
        '<div class="detail-meta" id="detail-meta"></div></details>'
        '<div class="detail-reason"><div class="meta-label">Reason</div>'
        '<div id="detail-reason-value"></div></div>'
        '<div class="panel-heading"><h3>Request</h3>'
        '<button id="request-format-toggle" class="time-toggle detail-format-toggle"'
        ' type="button" aria-label="Show request JSON" aria-pressed="false"'
        ' title="Switch to request JSON">⇄</button></div>'
        '<div id="request-readable">'
        '<pre class="terminal request" id="terminal-request"></pre>'
        '<div class="detail-properties" id="request-properties"></div></div>'
        '<pre id="request-json" class="terminal request detail-json" hidden></pre>'
        '<div class="panel-heading"><h3>Response</h3>'
        '<button id="response-format-toggle" class="time-toggle detail-format-toggle"'
        ' type="button" aria-label="Show response JSON" aria-pressed="false"'
        ' title="Switch to response JSON">⇄</button></div>'
        '<div id="response-readable"><div id="job-error" class="job-error" hidden></div>'
        '<div id="file-output-note" class="metrics-note" hidden>'
        'File contents, patches and transfer payloads are never stored in history.</div>'
        '<div id="truncated" class="truncated" hidden>'
        'Output truncated at the SSH capture limit.</div>'
        '<div class="output-label" id="stdout-label">stdout</div><pre class="terminal output" id="stdout"></pre>'
        '<div class="output-label" id="stderr-label">stderr</div><pre class="terminal output" id="stderr"></pre>'
        '</div><pre id="response-json" class="terminal output detail-json" hidden></pre>'
        '<details class="technical-details" id="technical-details"><summary>Technical details</summary>'
        '<div id="technical-metadata" class="technical-metadata"></div>'
        '<div>Command SHA-256: <code id="technical-hash"></code></div></details></div>'
        '</section></div></div><div id="command-tooltip" class="command-tooltip"'
        ' role="tooltip" hidden><pre id="command-tooltip-text"></pre></div>'
        '<div id="approval-layer" class="approval-layer" hidden>'
        '<section class="approval-modal" role="dialog" aria-modal="true"'
        ' aria-labelledby="approval-title" aria-describedby="approval-explainer">'
        '<div class="approval-content"><header class="approval-heading">'
        '<span class="approval-warning" aria-hidden="true">!</span>'
        '<div class="approval-heading-copy">'
        '<div class="approval-kicker">Operator decision required</div>'
        '<h2 id="approval-title">Restricted host access</h2>'
        '<p id="approval-explainer">An agent is waiting for your approval.'
        ' Access will not be granted automatically.</p></div>'
        '<div class="approval-utilities">'
        '<button id="approval-mute" class="approval-icon-button" type="button"'
        ' aria-label="Mute sound" aria-pressed="false" title="Sound on">'
        + _approval_icon("sound") + '</button>'
        '<button id="approval-notifications" class="approval-icon-button"'
        ' type="button" aria-label="Enable desktop notifications"'
        ' aria-pressed="false" title="Desktop notifications off">'
        + _approval_icon("bell") + '</button>'
        '<button id="approval-close" class="approval-close" type="button"'
        ' aria-label="Deny request and close" title="Deny request">×</button></div>'
        '</header>'
        '<dl class="approval-details">'
        '<div><dt>' + _approval_icon("agent") + 'Client</dt><dd id="approval-client">MCP client</dd></div>'
        '<div><dt>' + _approval_icon("host") + 'Host</dt><dd id="approval-host"></dd></div>'
        '<div><dt>' + _approval_icon("conversation") + 'Conversation</dt>'
        '<dd id="approval-conversation"></dd></div>'
        '<div><dt>' + _approval_icon("operation") + 'Operation</dt>'
        '<dd id="approval-tool"></dd></div>'
        '<div><dt>' + _approval_icon("clock") + 'Expires in</dt>'
        '<dd id="approval-expiry" class="approval-expiry" aria-live="off"></dd></div>'
        '</dl>'
        '<section class="approval-reason"><h3>' + _approval_icon("reason")
        + 'Reason</h3><p id="approval-reason"></p></section>'
        '<div class="approval-preview-title"><h3 id="approval-summary-title">'
        'Requested command / paths</h3><span id="approval-sequence" hidden>'
        'Sequential execution</span></div>'
        '<div id="approval-steps" class="approval-steps" hidden></div>'
        '<pre id="approval-summary" class="approval-summary"></pre>'
        '</div>'
        '<div class="approval-footer"><div class="approval-actions">'
        '<fieldset id="approval-durations" class="approval-durations">'
        '<legend>Grant for</legend><div class="approval-duration-options">'
        '<label><input type="radio" name="approval-duration" value="once" checked>'
        ' One request</label>'
        '<label><input type="radio" name="approval-duration" value="5m"> 5 min</label>'
        '<label><input type="radio" name="approval-duration" value="15m"> 15 min</label>'
        '<label><input type="radio" name="approval-duration" value="1h"> 1 h</label>'
        '<label><input type="radio" name="approval-duration" value="8h"> 8 h</label>'
        '<label><input type="radio" name="approval-duration" value="16h"> 16 h</label>'
        '</div><p id="approval-duration-warning" class="approval-duration-warning" hidden>'
        'Timed grants require an authenticated OAuth client or conversation ID.'
        ' Only one request can be authorized.</p></fieldset>'
        '<button id="approval-deny" type="button" class="approval-deny">Deny</button>'
        '<button id="approval-grant" type="button" class="approval-grant">Grant</button>'
        '</div><p id="approval-feedback" class="approval-feedback" role="alert" hidden></p>'
        '</div>'
        '</section></div>'
        '<script src="/console/assets/console.js" defer></script>'
        '<script src="/console/assets/approvals.js" defer></script></body></html>'
    )


def create_history_router(jobs: JobStore, *, approved_hosts: list[str] | None = None,
                          approvals: ApprovalManager | None = None,
                          job_manager: JobManager | None = None,
                          batch_manager: BatchCanceller | None = None,
                          readiness: ReadinessMonitor | None = None) -> APIRouter:
    """Create browser-only routes; operator actions never execute SSH commands."""
    secret = os.getenv("HISTORY_VIEWER_PASSWORD", "")
    store = HistoryStore(jobs)
    auth = ViewerAuth(store, secret)
    router = APIRouter()
    # Serialize logout and final approval decisions; the SQLite check is
    # deliberately off-loop, and mutations occur before releasing this lock.
    decision_lock = asyncio.Lock()
    # Only the already-validated approved aliases, never addresses or secrets.
    hosts = sorted(set(approved_hosts or []))
    approved_set = set(hosts)

    def decorate_jobs(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        candidates = [
            str(item["id"]) for item in items
            if job_manager is not None and item.get("record_kind") == "command"
            and item.get("actor") == config.MCP_OPERATOR_SUBJECT
            and item.get("server") in approved_set
            and item.get("status") in {"queued", "running"}
            and not item.get("cancellation_requested")
        ]
        eligible = store.eligible_cancellation_ids(
            candidates, actor=config.MCP_OPERATOR_SUBJECT,
            approved_hosts=approved_set, batches_enabled=batch_manager is not None,
        ) if candidates else set()
        for item in items:
            item["cancel_available"] = item["id"] in eligible
        return items

    def signed_in(request: Request, *, touch: bool = True) -> bool:
        return auth.valid(request.cookies.get(SESSION_COOKIE), touch=touch)

    def filters(request: Request) -> dict[str, str]:
        return {name: request.query_params.get(name, "") for name in (
            "time_range", "agent", "story_id", "conversation_id", "host", "status", "mode", "command",
            "privileged",
            "from_date", "to_date",
        )}

    @router.get("/console/assets/style.css")
    def css() -> Response:
        return Response((ASSETS / "style.css").read_text(), media_type="text/css", headers=_headers())

    @router.get("/console/assets/console.js")
    def javascript() -> Response:
        return Response(
            (ASSETS / "console.js").read_text(),
            media_type="text/javascript", headers=_headers()
        )

    @router.get("/console/assets/approvals.js")
    def approval_javascript() -> Response:
        return Response(
            (ASSETS / "approvals.js").read_text(),
            media_type="text/javascript", headers=_headers(),
        )

    @router.get("/console/login")
    def login_form(request: Request) -> Response:
        if signed_in(request):
            return RedirectResponse("/console", status_code=303, headers=_headers())
        csrf = secrets.token_urlsafe(24)
        response = HTMLResponse(_login_page(csrf), headers=_headers())
        response.set_cookie(CSRF_COOKIE, csrf, secure=True, httponly=True,
                            samesite="strict", path="/")
        return response

    def clear_legacy_cookies(response: Response) -> None:
        # Both cookies were host-only Secure cookies at Path=/ in the old UI.
        for name in (LEGACY_SESSION_COOKIE, LEGACY_CSRF_COOKIE):
            response.delete_cookie(name, path="/", secure=True, httponly=True, samesite="strict")

    @router.post("/console/login")
    async def login(request: Request) -> Response:
        try:
            data = await _form(request)
        except (ValueError, UnicodeDecodeError):
            return _json({"error": "Invalid login form"}, 400)
        if not _same_origin(request) or not _csrf_ok(request, data):
            return _json({"error": "Request forbidden"}, 403)
        ip = request.client.host if request.client else "unknown"
        session = auth.login(ip, data.get("password", ""))
        if session is None:
            return HTMLResponse(_login_page(data["csrf"], failed=True), status_code=401, headers=_headers())
        # The former /history cookie may still authorize a row in the same
        # SQLite store. Revoke it before completing migration to /console.
        await run_in_threadpool(auth.logout, request.cookies.get(LEGACY_SESSION_COOKIE))
        response = RedirectResponse("/console", status_code=303, headers=_headers())
        response.set_cookie(SESSION_COOKIE, session, max_age=ABSOLUTE_SECONDS,
                            secure=True, httponly=True, samesite="strict", path="/")
        clear_legacy_cookies(response)
        return response

    @router.post("/console/logout")
    async def logout(request: Request) -> Response:
        try:
            data = await _form(request)
        except (ValueError, UnicodeDecodeError):
            return _json({"error": "Invalid logout form"}, 400)
        if not _same_origin(request) or not _csrf_ok(request, data):
            return _json({"error": "Request forbidden"}, 403)
        async with decision_lock:
            await run_in_threadpool(auth.logout, request.cookies.get(SESSION_COOKIE))
            await run_in_threadpool(auth.logout, request.cookies.get(LEGACY_SESSION_COOKIE))
        response = RedirectResponse("/console/login", status_code=303, headers=_headers())
        response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        clear_legacy_cookies(response)
        return response

    @router.get("/console")
    def page(request: Request) -> Response:
        if not signed_in(request):
            return RedirectResponse("/console/login", status_code=303, headers=_headers())
        csrf = request.cookies.get(CSRF_COOKIE)
        response = HTMLResponse(_history_page(csrf or ""), headers=_headers())
        if not csrf:
            csrf = secrets.token_urlsafe(24)
            response = HTMLResponse(_history_page(csrf), headers=_headers())
            response.set_cookie(CSRF_COOKIE, csrf, secure=True, httponly=True,
                                samesite="strict", path="/")
        return response

    @router.get("/console/api/summary")
    def summary(request: Request) -> Response:
        if not signed_in(request):
            return _json({"error": "Unauthorized"}, 401)
        try:
            return _json({"totals": store.totals(request.query_params.get("time_range", ""))})
        except ValueError:
            return _json({"error": "Invalid time range"}, 400)

    @router.get("/console/api/hosts")
    async def registered_hosts(request: Request) -> Response:
        if not await run_in_threadpool(signed_in, request):
            return _json({"error": "Unauthorized"}, 401)
        result: dict[str, Any] = {"hosts": hosts}
        if readiness is not None:
            result["readiness"] = readiness.snapshot()
        return _json(result)

    @router.get("/console/api/jobs")
    def list_jobs(request: Request) -> Response:
        if not signed_in(request):
            return _json({"error": "Unauthorized"}, 401)
        try:
            raw_page = request.query_params.get("page")
            result = store.list(
                filters(request), before=request.query_params.get("before"),
                limit=int(request.query_params.get("limit", "50")),
                page=int(raw_page) if raw_page is not None else None,
            )
        except (ValueError, OverflowError):
            return _json({"error": "Invalid history query"}, 400)
        result["jobs"] = decorate_jobs(result["jobs"])
        return _json(result)

    @router.get("/console/api/changes")
    async def changes(request: Request) -> Response:
        def read_history() -> dict[str, Any] | Response:
            # SQLite session checks and History queries must not block the
            # single event loop responsible for approval deadlines.
            if not signed_in(request):
                return _json({"error": "Unauthorized"}, 401)
            try:
                result = store.changes(request.query_params.get("after", ""))
                # Keep all SQLite work, including cancellation eligibility,
                # off the event loop responsible for approval deadlines.
                result["jobs"] = decorate_jobs(result["jobs"])
                return result
            except (ValueError, OverflowError):
                return _json({"error": "Invalid change cursor"}, 400)

        result = await run_in_threadpool(read_history)
        if isinstance(result, Response):
            return result
        # Visible-tab polling includes approval snapshots; hidden tabs receive
        # approval updates through the separate event stream.
        if approvals is not None:
            result.update(approvals.viewer_snapshot())
        if readiness is not None:
            result["readiness"] = readiness.snapshot()
        return _json(result)

    @router.get("/console/api/approval-events")
    async def approval_events(request: Request) -> Response:
        """Authenticated, bounded memory-only changes for hidden viewer tabs.

        History queries remain on the normal visible-tab polling route. Only
        approval snapshots and keepalives are sent here; each connection
        rechecks its independent viewer session while it remains open.
        """
        if not await run_in_threadpool(signed_in, request, touch=False):
            return _json({"error": "Unauthorized"}, 401)

        async def stream() -> AsyncIterator[str]:
            listener = approvals.subscribe() if approvals is not None else None
            try:
                send_snapshot = True  # Initial/reconnect snapshot exactly once.
                while not await request.is_disconnected():
                    if not await run_in_threadpool(signed_in, request, touch=False):
                        yield "event: logout\ndata: {}\n\n"
                        break
                    if send_snapshot:
                        snapshot = approvals.viewer_snapshot() if approvals is not None else {
                            "pending_approvals": [], "active_grants": [],
                        }
                        yield "event: approval\ndata: " + json.dumps(snapshot, separators=(",", ":")) + "\n\n"
                    if listener is None:
                        await asyncio.sleep(10)
                        send_snapshot = False
                        yield ": keepalive\n\n"
                    else:
                        try:
                            await asyncio.wait_for(listener.get(), timeout=10)
                            send_snapshot = True
                        except TimeoutError:
                            send_snapshot = False
                            yield ": keepalive\n\n"
            finally:
                if listener is not None and approvals is not None:
                    approvals.unsubscribe(listener)

        return StreamingResponse(
            stream(), media_type="text/event-stream",
            headers={**_headers(), "X-Accel-Buffering": "no"},
        )

    async def approval_form(request: Request) -> tuple[dict[str, str] | None, Response | None]:
        if not await run_in_threadpool(signed_in, request):
            return None, _json({"error": "Unauthorized"}, 401)
        try:
            data = await _form(request)
        except (ValueError, UnicodeDecodeError):
            return None, _json({"error": "Invalid approval form"}, 400)
        if not _same_origin(request) or not _csrf_ok(request, data):
            return None, _json({"error": "Request forbidden"}, 403)
        # The body read above is an await point: logout/expiry may have
        # invalidated the session before the operator decision is applied.
        if not await run_in_threadpool(signed_in, request):
            return None, _json({"error": "Unauthorized"}, 401)
        return data, None

    @router.post("/console/api/approvals/{approval_id}/grant")
    async def grant_approval(request: Request, approval_id: str) -> Response:
        data, error = await approval_form(request)
        if error is not None:
            return error
        assert data is not None
        if data.get("duration", "once") not in DURATIONS:
            return _json({"error": "Invalid grant duration"}, 400)
        async with decision_lock:
            if not await run_in_threadpool(signed_in, request):
                return _json({"error": "Unauthorized"}, 401)
            if approvals is None or not await approvals.decide_live(
                approval_id, grant=True, duration=data.get("duration", "once"),
            ):
                return _json({"error": "Approval unavailable or expired"}, 404)
        return _json({"ok": True})

    @router.post("/console/api/approvals/{approval_id}/deny")
    async def deny_approval(request: Request, approval_id: str) -> Response:
        _, error = await approval_form(request)
        if error is not None:
            return error
        async with decision_lock:
            if not await run_in_threadpool(signed_in, request):
                return _json({"error": "Unauthorized"}, 401)
            if approvals is None or not await approvals.decide_live(approval_id, grant=False):
                return _json({"error": "Approval unavailable or expired"}, 404)
        return _json({"ok": True})

    @router.post("/console/api/grants/{grant_id}/revoke")
    async def revoke_grant(request: Request, grant_id: str) -> Response:
        _, error = await approval_form(request)
        if error is not None:
            return error
        async with decision_lock:
            if not await run_in_threadpool(signed_in, request):
                return _json({"error": "Unauthorized"}, 401)
            if approvals is None:
                return _json({"error": "Grant unavailable or expired"}, 404)
            if not approvals.revoke(grant_id):
                return _json({"error": "Grant unavailable or expired",
                              **approvals.viewer_snapshot()}, 404)
            # Return the revisioned state from this exact decision. A
            # concurrent SSE/poll may deliver a newer grant before the POST
            # arrives in the browser; the client must not overwrite it.
            snapshot = approvals.viewer_snapshot()
        return _json({"ok": True, **snapshot})

    @router.post("/console/api/jobs/{job_id}/cancel")
    async def cancel_from_history(request: Request, job_id: str) -> Response:
        # Use the same operator session, Origin and CSRF boundary as grant decisions.
        _, error = await approval_form(request)
        if error is not None:
            return error
        async with decision_lock:
            if not await run_in_threadpool(signed_in, request):
                return _json({"error": "Unauthorized"}, 401)
            if job_manager is None:
                return _json({"error": "Cancellation unavailable"}, 404)
            try:
                target = store.cancellation_target(
                    job_id, actor=config.MCP_OPERATOR_SUBJECT, approved_hosts=approved_set,
                )
                if target is None:
                    return _json({"error": "Job unavailable"}, 404)
                if not target["available"]:
                    return _json({"error": "Job no longer cancellable"}, 409)
                if target["target_type"] == "batch":
                    if batch_manager is None:
                        return _json({"error": "Batch cancellation unavailable"}, 404)
                    result = batch_manager.cancel(
                        config.MCP_OPERATOR_SUBJECT, target["target_id"],
                        reason="Cancelled from History viewer", via="history",
                    )
                else:
                    result = job_manager.cancel(
                        config.MCP_OPERATOR_SUBJECT, target["target_id"],
                        reason="Cancelled from History viewer", via="history",
                    )
            except (sqlite3.DatabaseError, OSError, ValueError):
                return _json({"error": "Cancellation unavailable; inspect job status"}, 503)
            if result is None or not result["cancellation_requested"]:
                return _json({"error": "Job no longer cancellable"}, 409)
        return _json({"ok": True, "cancellation_requested": True,
                      "target_type": target["target_type"]})

    @router.get("/console/api/jobs/{job_id}")
    def detail(request: Request, job_id: str) -> Response:
        if not signed_in(request):
            return _json({"error": "Unauthorized"}, 401)
        item = store.detail(job_id)
        if item is None:
            return _json({"error": "Not found"}, 404)
        item["cancellation_request"] = store.cancellation_request(job_id)
        item["batch_step_outcome"] = store.batch_step_outcome(job_id)
        return _json({"job": decorate_jobs([item])[0]})

    @router.get("/console/api/jobs/{job_id}/output")
    def output(request: Request, job_id: str) -> Response:
        if not signed_in(request):
            return _json({"error": "Unauthorized"}, 401)
        try:
            cursor = int(request.query_params.get("cursor", "0"))
            length = int(request.query_params.get("max_bytes", "16384"))
            item = store.output(job_id, cursor=cursor, max_bytes=length)
        except (ValueError, OverflowError):
            return _json({"error": "Invalid output request"}, 400)
        return _json(item) if item is not None else _json({"error": "Not found"}, 404)

    return router
