"""Bounded local-only MCP readiness and release status, never SSH host probes."""
from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as package_version
import time
from typing import TYPE_CHECKING, Any

from . import config
from .oauth import session_store

if TYPE_CHECKING:
    from .jobs import JobManager

FAILURE_STATES = (
    "failed", "timed_out", "transport_error", "output_limit", "interrupted",
)


def service_version() -> str:
    """Prefer signed image release identity over package development metadata."""
    if config.MCP_SERVICE_VERSION:
        return config.MCP_SERVICE_VERSION
    try:
        return package_version("ssh-mcp")
    except PackageNotFoundError:
        return "unknown"


def service_status(jobs: JobManager | None, *, started_monotonic: float) -> dict[str, Any]:
    """Check local OAuth/audit stores; report degradation without leaking paths."""
    oauth_ready = False
    audit_ready = jobs is None
    retained = 0
    counts: dict[str, int] = {}
    failures_recent = 0
    transport_recent = 0
    try:
        with session_store()._connect() as db:
            db.execute("SELECT id FROM oauth_sessions LIMIT 1").fetchone()
        oauth_ready = True
    except Exception:
        pass
    if jobs is not None:
        try:
            with jobs.store._connect() as db:
                counts = {
                    str(row["status"]): int(row["total"])
                    for row in db.execute(
                        "SELECT status,COUNT(*) AS total FROM jobs GROUP BY status"
                    )
                }
                recent = dict(db.execute(
                    "SELECT status,COUNT(*) AS total FROM jobs "
                    "WHERE ended_at>=? GROUP BY status", (time.time() - 86400,)
                ).fetchall())
            retained = sum(counts.values())
            failures_recent = sum(recent.get(s, 0) for s in FAILURE_STATES)
            transport_recent = recent.get("transport_error", 0)
            audit_ready = True
        except Exception:
            audit_ready = False
    ready = oauth_ready and audit_ready
    return {
        "service": {
            "status": "ready" if ready else "degraded",
            "version": service_version(),
            "environment": config.MCP_ENVIRONMENT,
            "uptime_seconds": max(0, int(time.monotonic() - started_monotonic)),
        },
        "storage": {
            "oauth_ready": oauth_ready,
            "audit_ready": audit_ready,
            "retained_jobs": retained if audit_ready and jobs is not None else None,
        },
        "jobs": {
            "queued": counts.get("queued", 0) if audit_ready else None,
            "running": counts.get("running", 0) if audit_ready else None,
            "failed_last_24h": failures_recent if audit_ready else None,
            "transport_errors_last_24h": transport_recent if audit_ready else None,
        },
        "capabilities": {
            "ssh_execution": config.MCP_SSH_TOOLS_ENABLED,
            "durable_jobs": jobs is not None,
            "history_search": jobs is not None,
        },
    }
