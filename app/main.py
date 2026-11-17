"""OAuth discovery, authorization, health and bearer-protected Streamable HTTP MCP."""
from __future__ import annotations

from contextlib import asynccontextmanager
import asyncio
import logging
import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse

from .config import MCP_LOG_LEVEL, MCP_OPERATOR_SUBJECT, validate_mcp_config
from .control import SOCKET, control_server
from .request_trace import RequestTrace
from .approvals import ApprovalManager
from .jobs import JobStore

# Missing or weak secrets are startup errors, not silent anonymous mode.
validate_mcp_config()

from .mcp_gateway import create_mcp_server  # noqa: E402
from .oauth import router as oauth_router, session_store  # noqa: E402

_job_registry: dict = {}
_approvals = ApprovalManager()
_mcp_server, _mcp_app = create_mcp_server(
    job_registry=_job_registry, approvals=_approvals,
)


async def _prune_loop(store: JobStore | None) -> None:
    """Enforce retention even when no new SSH jobs are submitted."""
    while True:
        await asyncio.sleep(3600)
        try:
            if store is not None:
                store.prune()
            session_store().prune()
        except Exception:
            logging.getLogger(__name__).warning("history_retention_prune_failed")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if any(os.getenv(name, "1") != "1" for name in ("WEB_CONCURRENCY", "UVICORN_WORKERS")):
        raise RuntimeError("Memory-only approvals require a single server worker")
    # Standalone env-mode examples mount this directory read-only. Managed
    # services already provide a private writable tmpfs.
    socket_path = SOCKET if os.getenv("MCP_CONFIG_FILE") else None
    async with control_server(MCP_LOG_LEVEL, socket_path), _mcp_server.session_manager.run():
        jobs = _job_registry.get("jobs")
        # Fail at startup if private session storage cannot initialize.
        session_store()
        cleanup = asyncio.create_task(_prune_loop(jobs.store if jobs is not None else None))
        try:
            yield
        finally:
            _approvals.shutdown()
            batches = _job_registry.get("batches")
            if batches is not None:
                await batches.shutdown()
            if cleanup is not None:
                cleanup.cancel()
                await asyncio.gather(cleanup, return_exceptions=True)


app = FastAPI(
    title="SSH-MCP",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
app.add_middleware(RequestTrace)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/ready")
async def ready():
    """Prove that durable audited history is reachable when jobs are enabled."""
    jobs = _job_registry.get("jobs")
    try:
        with session_store()._connect() as db:
            db.execute("SELECT id FROM oauth_sessions LIMIT 1").fetchone()
        if jobs is not None:
            with jobs.store._connect() as db:
                db.execute("SELECT id FROM jobs LIMIT 1").fetchone()
    except Exception:
        raise HTTPException(status_code=503, detail="Audit storage unavailable") from None
    return {"status": "ok"}


if os.getenv("MCP_METRICS_ENABLED", "false").lower() == "true":
    jobs = _job_registry.get("jobs")
    if jobs is None:
        raise RuntimeError("Metrics require enabled durable jobs")
    from .observability import create_observability_router
    app.include_router(create_observability_router(
        jobs.store, os.getenv("MCP_METRICS_TOKEN", "")
    ))


# Keep authorization and public metadata ahead of the SDK sub-application mount.
app.include_router(oauth_router)
if os.getenv("HISTORY_VIEWER_ENABLED", "false").lower() == "true":
    if _job_registry.get("jobs") is None:
        raise RuntimeError("History viewer requires enabled audited SSH jobs")
    from .history import create_history_router
    manager = _job_registry["jobs"]
    app.include_router(create_history_router(
        manager.store, approved_hosts=manager.executor.list_servers(MCP_OPERATOR_SUBJECT),
        approvals=_approvals, job_manager=manager,
        batch_manager=_job_registry.get("batches"),
    ))

    @app.get("/", include_in_schema=False)
    def console_home():
        return RedirectResponse("/console", status_code=303)
app.mount("/", _mcp_app)
