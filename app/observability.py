"""Read-only operational endpoints; no actor or command data."""
from __future__ import annotations

import hmac
from fastapi import APIRouter, Request
from fastapi.responses import Response

from .jobs import JobStore, TERMINAL, DURATION_BUCKETS
from . import config
import os
from typing import Any
from .sealed_credentials import validate_token_verifier, verify_token

STATES = tuple(sorted(TERMINAL | {"queued", "running"}))
PLAIN = "text/plain; version=0.0.4; charset=utf-8"
NO_STORE = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}


def create_observability_router(store: JobStore, token: str, *,
                                verifier: dict[str, Any] | None = None) -> APIRouter:
    if verifier is not None:
        if token:
            raise RuntimeError("Sealed metrics mode cannot receive a plaintext token")
        validate_token_verifier(verifier)
    elif len(token) < 32 or token in {
        config.MCP_LOGIN_KEY, os.getenv("HISTORY_VIEWER_PASSWORD", ""),
    }:
        raise RuntimeError("Metrics require an independent 32+ character bearer secret")
    router = APIRouter()

    @router.get("/metrics")
    def metrics(request: Request) -> Response:
        supplied = request.headers.get("authorization", "")
        accepted = (supplied.startswith("Bearer ") and
                    verify_token(supplied[7:], verifier)) if verifier is not None else (
                    hmac.compare_digest(supplied, "Bearer " + token))
        if not accepted:
            return Response(status_code=401, headers=NO_STORE)
        try:
            with store._connect() as db:
                counts = dict(db.execute(
                    "SELECT status, COUNT(*) FROM jobs GROUP BY status"
                ).fetchall())
                outcomes = db.execute(
                    "SELECT server,status,failure_kind,total FROM telemetry_outcomes "
                    "ORDER BY server,status,failure_kind"
                ).fetchall()
                durations = db.execute(
                    "SELECT server,total,sum_seconds FROM telemetry_duration ORDER BY server"
                ).fetchall()
                buckets = {
                    (r["server"], r["le"]): r["total"] for r in db.execute(
                        "SELECT server,le,total FROM telemetry_duration_buckets"
                    )
                }
        except Exception:
            # Fail closed; never return SQLite paths, SQL errors or secrets.
            return Response(status_code=503, headers=NO_STORE)
        lines = [
            "# HELP ssh_mcp_jobs Current retained jobs by state.",
            "# TYPE ssh_mcp_jobs gauge",
        ]
        for status in STATES:
            lines.append('ssh_mcp_jobs{status="' + status + '"} ' + str(int(counts.get(status, 0))))
        lines.extend([
            "# HELP ssh_mcp_history_records Retained job count.",
            "# TYPE ssh_mcp_history_records gauge",
            "ssh_mcp_history_records " + str(sum(int(counts.get(s, 0)) for s in STATES)),
        ])
        # Labels are fixed lifecycle states/classifications and bounded approved
        # inventory aliases; never include request details, principal or job IDs.
        def label(value: str) -> str:
            return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

        lines.extend([
            "# HELP ssh_mcp_jobs_completed_total Durable completions since instrumentation activation.",
            "# TYPE ssh_mcp_jobs_completed_total counter",
        ])
        for row in outcomes:
            lines.append(
                'ssh_mcp_jobs_completed_total{server="' + label(row["server"])
                + '",status="' + label(row["status"]) + '",failure_kind="'
                + label(row["failure_kind"]) + '"} ' + str(row["total"])
            )
        lines.extend([
            "# HELP ssh_mcp_job_duration_seconds Job execution duration by approved server.",
            "# TYPE ssh_mcp_job_duration_seconds histogram",
        ])
        for row in durations:
            server = row["server"]
            for boundary in DURATION_BUCKETS:
                le = str(boundary)
                lines.append('ssh_mcp_job_duration_seconds_bucket{server="'
                             + label(server) + '",le="' + le + '"} '
                             + str(buckets.get((server, le), 0)))
            lines.append('ssh_mcp_job_duration_seconds_bucket{server="'
                         + label(server) + '",le="+Inf"} ' + str(row["total"]))
            lines.append('ssh_mcp_job_duration_seconds_sum{server="'
                         + label(server) + '"} ' + str(row["sum_seconds"]))
            lines.append('ssh_mcp_job_duration_seconds_count{server="'
                         + label(server) + '"} ' + str(row["total"]))
        return Response("\n".join(lines) + "\n", media_type=PLAIN, headers=NO_STORE)

    return router
