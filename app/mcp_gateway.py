"""OAuth-protected MCP tools, audited SSH execution and durable job APIs."""
from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import logging
import sqlite3
import os
import re
from pathlib import Path
import secrets
import time
from dataclasses import asdict

from mcp.server import Server
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import (
    BlobResourceContents, CallToolRequestParams, CallToolResult, EmbeddedResource,
    ListToolsResult, TextContent, Tool, ToolAnnotations,
)
from pydantic import ValidationError
from starlette.requests import Request

from . import config
from .client_identity import client_id_context
from .approvals import ApprovalManager
from .approval_status import ApprovalCode, ApprovalRejected, approval_status_context
from .approval_preview import approval_summary, approval_steps
from .conversation_access import (
    conversation_id_context, conversation_id_from_request, require_host_access,
)
from .config import MCP_ALLOWED_HOSTS, MCP_ALLOWED_ORIGINS, MCP_ISSUER, MCP_RESOURCE, MCP_SCOPES
from .contracts import (
    CancelJobRequest, ExecuteCommandRequest, GetJobOutputRequest,
    GetJobRequest, GetJobStatsRequest, ListJobsRequest, ListServersRequest,
    ReadFileRequest, WriteFileRequest, ApplyPatchRequest,
    UploadFileRequest, DownloadFileRequest, TransferFileRequest,
    ExecuteCommandsRequest, GetBatchRequest, ListBatchesRequest, CancelBatchRequest,
)
from .batch import BatchManager
from .grant_unlocks import RootAccess, finish_once_root, root_access_context
from .jobs import JobManager, JobStore
from .file_transfer import BinaryTransferService
from .host_relay import HostRelayService
from .binary_probe import BinaryProbeError, BinaryProbeRequest, probe_exchange
from .history import HistoryStore
from .operational import service_status, service_version
from .oauth import OAuthTokenVerifier, _supported_scopes, client_audit_actor, ActiveOrigins
from .ssh_executor import ReadinessDenied, SSHDenied, SSHExecutor

LOGGER = logging.getLogger(__name__)


def _encode_mcp_cursor(history_cursor: str | None) -> str | None:
    if history_cursor is None:
        return None
    return base64.urlsafe_b64encode(history_cursor.encode("ascii")).decode("ascii").rstrip("=")


def _decode_mcp_cursor(token: str | None) -> str | None:
    if token is None:
        return None
    try:
        decoded = base64.b64decode(
            token + "=" * (-len(token) % 4), altchars=b"-_", validate=True
        ).decode("ascii")
        # Reuse the viewer's strict existing timestamp/job-id cursor validator.
        from .history import _cursor
        if _cursor(decoded) is None:
            raise ValueError("Invalid cursor")
        return decoded
    except (ValueError, UnicodeDecodeError, binascii.Error):
        raise ValueError("Invalid cursor") from None


TOOLS = [
    Tool(
        name="ping",
        description="Return a unique request ID and UTC timestamp, without changing server state.",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        annotations=ToolAnnotations(
            read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
        ),
        meta={"securitySchemes": [{"type": "oauth2", "scopes": list(MCP_SCOPES)}]},
    ),

]

SSH_TOOLS = [
    Tool(
        name="list_servers",
        description="List authorized host aliases mapped to status (active, offline, retired) and sudo_ready. Use only active hosts for execution. Retired hosts are history-only; sudo_ready is not approval.",
        input_schema=ListServersRequest.model_json_schema(),
        annotations=ToolAnnotations(
            read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
        ),
        meta={"securitySchemes": [{"type": "oauth2", "scopes": [*MCP_SCOPES, config.MCP_SSH_SCOPE]}]},
    ),
    Tool(
        name="execute_command",
        description=(
            "Run one argv command on an approved SSH host. "
            "Prefer direct argv for a single executable; do not add a shell just for cd, "
            "set -euo pipefail, or a numbered echo. Set absolute remote cwd for the "
            "working directory; supply required reason as audit context and optional story_id. "
            "For genuine shell syntax use ['bash', '-lc', 'SCRIPT'] and strict_bash=true; "
            "this enables Bash -euo pipefail only for explicit bash -c/-lc, not direct argv or sh. "
            "Returns bounded stdout, stderr, exit code and status synchronously; "
            "Durable job audit is required; no unaudited execution fallback. "
            "Optional privileged=true runs a complete argv/script as root only "
            "when signed host privileged_access policy permits it, a per-host "
            "sudo password is configured, and the operator approval is satisfied "
            "when required. No additional OAuth scope is needed. "
            "Inspect status, exit_code and exit_accepted: isError=false can still "
            "contain command_error for an unaccepted exit. Validation, timeout "
            "and transport errors are tool errors. success_exit_codes defaults "
            f"to [0]; only add known-acceptable nonzero codes. Timeout max is {config.SSH_MAX_TIMEOUT_SECONDS} seconds. "
            "Never send secrets in command arguments, reason or output."
        ),
        input_schema=ExecuteCommandRequest.model_json_schema(),
        annotations=ToolAnnotations(
            read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=False
        ),
        meta={"securitySchemes": [{"type": "oauth2", "scopes": [*MCP_SCOPES, config.MCP_SSH_SCOPE]}]},
    ),
]

def _job_tool(name: str, description: str, model, *, read_only: bool) -> Tool:
    return Tool(
        name=name, description=description,
        input_schema=model.model_json_schema(),
        annotations=ToolAnnotations(
            read_only_hint=read_only, destructive_hint=not read_only,
            idempotent_hint=read_only, open_world_hint=False,
        ),
        meta={"securitySchemes": [{
            "type": "oauth2", "scopes": [*MCP_SCOPES, config.MCP_SSH_SCOPE],
        }]},
    )


JOB_TOOLS = [
    _job_tool(
        "submit_job",
        "Start an audited asynchronous argv job and return its ID. "
        "Use direct argv, absolute cwd for the working directory, required "
        "reason and optional story_id; no numbered echo is needed. "
        "For explicit bash -c/-lc scripts use strict_bash=true rather than "
        "writing set -euo pipefail. Optional privileged=true requires signed host "
        "privilege policy, passworded sudo, and operator approval when restricted. "
        "Poll get_job/get_job_output for results.",
        ExecuteCommandRequest, read_only=False),
    _job_tool("get_job", "Poll the status, metadata and exit code of your SSH job.",
              GetJobRequest, read_only=True),
    _job_tool("get_job_output", "Page through bounded stdout/stderr from your SSH job.",
              GetJobOutputRequest, read_only=True),
    _job_tool("list_jobs", "Search retained jobs using filters and opaque cursor pagination.",
              ListJobsRequest, read_only=True),
    _job_tool("get_job_stats", "Count retained jobs and durations by host, status, story or UTC day.",
              GetJobStatsRequest, read_only=True),
    _job_tool("get_status", "Read service release, local readiness and recent job activity.",
              ListServersRequest, read_only=True),
    _job_tool("cancel_job", "Request cancellation of your queued or running SSH job.",
              CancelJobRequest, read_only=False),
]
JOB_TOOL_NAMES = frozenset(t.name for t in JOB_TOOLS)

BATCH_TOOLS = [
    _job_tool(
        "execute_commands",
        "Run 1-5 sequential argv commands on one authorized host, with shared "
        "absolute cwd, required reason, optional story_id, stop-on-error and "
        "900-second overall timeout. Prefer steps to shell concatenation or cd/echo "
        "boilerplate. strict_bash=true enables -euo pipefail only for explicit "
        "bash -c/-lc steps; direct argv and sh are unchanged. Per-step accepted "
        "exit codes are supported. Entire request and cwd are preflighted before "
        "step 1; this is not a transaction. Each attempted step gets a durable "
        "job ID; response/output capped at 256 KiB. Each step runs in a "
        "separate process: cd, exports and venv activation do not persist "
        "between steps; use shared cwd and direct executable paths. On disconnect, "
        "use get_batch/list_batches to reconcile; never blindly retry uncertain work. "
        "Optional privileged=true applies to every step; one operator approval "
        "admits the whole audited batch. Passworded sudo authenticates each step. "
        "Root execution requires explicit signed host policy and approval when restricted.",
        ExecuteCommandsRequest, read_only=False,
    ),
    _job_tool(
        "get_batch",
        "Read actor-scoped durable batch status, ordered steps, bounded output previews "
        "and associated get_job/get_job_output IDs; 1-5 step cursor pagination.",
        GetBatchRequest, read_only=True,
    ),
    _job_tool(
        "list_batches",
        "Discover your previously submitted batches for recovery after disconnect "
        "or process restart. Bounded paginated summaries; no replay.",
        ListBatchesRequest, read_only=True,
    ),
    _job_tool(
        "cancel_batch",
        "Request cancellation of an active sequential batch; the in-flight step "
        "may already have executed and is marked unknown, never retried.",
        CancelBatchRequest, read_only=False,
    ),
]
BATCH_TOOL_NAMES = frozenset(tool.name for tool in BATCH_TOOLS)

FILE_TOOLS = [
    _job_tool(
        "read_file",
        "Read a bounded text segment from an authorized SSH host. Return text, line/byte "
        "offset, optional whole-file SHA-256, EOF and a directly reusable version-bound cursor. "
        "Content is returned to the caller but never stored in audit/history.",
        ReadFileRequest, read_only=True,
    ),
    _job_tool(
        "write_file",
        "Write UTF text as create (fail if exists), replace (create if missing), or append "
        "(create if missing). Defaults to in-place OS behavior. Optional explicit atomic "
        "replacement, parent creation and pre-image SHA-256; inspect before retrying an "
        "unknown-completion append.",
        WriteFileRequest, read_only=False,
    ),
    _job_tool(
        "apply_patch",
        "Apply a Codex *** Begin Patch / *** End Patch multi-file text patch "
        "(Add/Update/Delete/Move). Stop at first failed path; earlier successful edits "
        "remain. Returns applied/failed/not_attempted per-path metadata and partial status. "
        "Never retry uncertain multi-file changes automatically.",
        ApplyPatchRequest, read_only=False,
    ),
    _job_tool(
        "upload_file",
        "Upload a native ChatGPT attached binary file to an approved SSH host. "
        "The helper stages bounded binary chunks, verifies SHA-256, and publishes "
        "atomically in create or explicit overwrite mode. Do not retry an uncertain "
        "transfer automatically. The attachment URL and bytes are never audited.",
        UploadFileRequest, read_only=False,
    ),
    _job_tool(
        "download_file",
        "Return an SSH file as a bounded binary resource chunk (up to 65536 bytes) "
        "and metadata with a version-bound next cursor. Continue with the cursor "
        "and assemble chunks only after verifying all checksums. The returned MCP "
        "blob is not guaranteed to appear as a downloadable ChatGPT attachment.",
        DownloadFileRequest, read_only=True,
    ),
]
# ChatGPT native uploaded-file parameter is not a generic model-written URL.
FILE_TOOLS[-2].meta = {
    **(FILE_TOOLS[-2].meta or {}), "openai/fileParams": ["file"],
}
FILE_TOOLS.append(_job_tool(
    "transfer_file",
    "Transfer a file from one approved SSH host to another through the server's "
    "bounded memory only; no file contents reach the MCP client, tools or audit. "
    "Supports independent root access, atomic create/overwrite and SHA-256 "
    "preconditions. A large transfer continues asynchronously; poll get_job, "
    "cancel with cancel_job. An uncertain result is never safe to retry blindly.",
    TransferFileRequest, read_only=False,
))
FILE_TOOL_NAMES = frozenset(tool.name for tool in FILE_TOOLS)

# Temporary, opt-in capability test. It is not a binary transfer API and
# must not appear in production's normal tool inventory.
BINARY_PROBE_TOOL = Tool(
    name="probe_binary_file_exchange",
    description=(
        "Optional native ChatGPT capability probe: accept an attached file, "
        "return its byte count and SHA-256 plus an MCP embedded binary resource. "
        "No SSH destination is written. Check whether ChatGPT offers the "
        "returned binary resource as a downloadable attachment."
    ),
    input_schema=BinaryProbeRequest.model_json_schema(),
    annotations=ToolAnnotations(
        read_only_hint=True, destructive_hint=False,
        idempotent_hint=True, open_world_hint=True,
    ),
    meta={
        "securitySchemes": [{"type": "oauth2", "scopes": [*MCP_SCOPES, config.MCP_SSH_SCOPE]}],
        "openai/fileParams": ["file"],
    },
)

def _result(payload: dict[str, object], *, is_error: bool = False) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload, separators=(",", ":")))],
        is_error=is_error,
    )


def _error(message: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=message)], is_error=True)


def handle_tool(name: str, arguments: dict | None) -> CallToolResult:
    """Handle the no-side-effect diagnostic; SSH goes through authenticated dispatcher."""
    args = arguments or {}
    if name == "ping":
        if args:
            return _error("ping does not accept arguments")
        payload = {"ok": True, "request_id": secrets.token_hex(12), "timestamp": int(time.time())}
    else:
        return _error("Unknown MCP tool")
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload, separators=(",", ":")))],
        is_error=False,
    )


def create_mcp_server(*, job_registry: dict | None = None,
                      approvals: ApprovalManager | None = None):
    # The startup gate validates private inventory and explicit alias approval;
    # never infer a target from the tool call or enable SSH solely from OAuth.
    executor = SSHExecutor.from_environment() if config.MCP_SSH_TOOLS_ENABLED else None
    jobs: JobManager | None = None
    batches: BatchManager | None = None
    files: BinaryTransferService | None = None
    relay: HostRelayService | None = None
    if os.getenv("SSH_JOBS_ENABLED") == "true":
        if executor is None:
            raise RuntimeError("Job tools require SSH MCP authorization")
        database = os.getenv("SSH_JOBS_DB", "")
        if not database:
            raise RuntimeError("SSH_JOBS_DB is required when jobs are enabled")
        months = os.getenv("SSH_JOBS_RETENTION_MONTHS")
        seconds = os.getenv("SSH_JOBS_RETENTION_SECONDS")
        if months is not None and seconds is not None:
            raise RuntimeError("Select either month-based or second-based job retention")
        if seconds is not None:
            store = JobStore(Path(database), retention_seconds=int(seconds))
        else:
            store = JobStore(Path(database), retention_months=int(months or "12"))
        jobs = JobManager(executor, store, max_active=config.SSH_MAX_ACTIVE_JOBS)
        batches = BatchManager(jobs)
        files = BinaryTransferService(executor, store)
        relay = HostRelayService(executor, files.audit)
    probe_enabled = os.getenv("SSH_BINARY_PROBE_ENABLED", "false").lower() == "true"
    if probe_enabled and executor is None:
        raise RuntimeError("Binary capability probe requires SSH OAuth authorization")
    if job_registry is not None:
        job_registry["executor"] = executor
        job_registry["jobs"] = jobs
        job_registry["batches"] = batches
        job_registry["relay"] = relay
    history = HistoryStore(jobs.store) if jobs is not None else None
    started_monotonic = time.monotonic()

    async def list_tools(_ctx, _params):
        return ListToolsResult(
            tools=[*TOOLS, *([tool for tool in SSH_TOOLS
                             if tool.name != "execute_command" or jobs is not None]
                            if executor is not None else []),
                   *(JOB_TOOLS if jobs is not None else []),
                   *(BATCH_TOOLS if batches is not None else []),
                   *(FILE_TOOLS if files is not None else []),
                   *([BINARY_PROBE_TOOL] if probe_enabled else [])]
        )

    async def _transfer_tool(_ctx, arguments: dict, actor: str, token):
        if files is None or relay is None or executor is None:
            return _error("Host-to-host file relay requires durable SSH auditing")
        try:
            request = TransferFileRequest.model_validate(arguments)
        except ValidationError:
            return _error("Invalid transfer_file request")
        for alias in (request.source_server, request.dest_server):
            try:
                executor.authorized_host(actor, alias)
            except SSHDenied:
                return _error("Host-to-host SSH access denied")
        if request.operation_id and files.audit.operation_id_exists(request.operation_id):
            return _result({
                "status": "failed", "operation_id": request.operation_id,
                "error": {"code": "duplicate_operation",
                          "message": "Operation ID already exists; inspect job before retry"},
            }, is_error=True)
        audit_id: str | None = None
        try:
            audit_id = files.audit.reserve(
                actor, request.dest_server, "transfer", request.dest_path,
                request.story_id,
            )
            files.audit.set_source(audit_id, request.source_server)
        except (sqlite3.DatabaseError, RuntimeError, ValueError, OSError):
            # Never strand an awaiting_approval row if an additive source
            # metadata write fails after reservation but before the prompt.
            if audit_id is not None:
                try:
                    files.audit.settle_approval(audit_id, None, denied=True)
                except (sqlite3.DatabaseError, RuntimeError, ValueError, OSError):
                    pass
            return _error("Durable transfer auditing unavailable")
        assert audit_id is not None
        roots: list[RootAccess | None] = [None, None]
        authorized = False
        response_code: ApprovalCode | None = None
        sid = (token.claims or {}).get("sid")
        try:
            for index, (alias, path, privileged) in enumerate((
                (request.source_server, request.source_path, request.source_privileged),
                (request.dest_server, request.dest_path, request.dest_privileged),
            )):
                # ContextVar is request-local, but a previous endpoint's
                # sealed unlock must never authorize a different host.
                root_access_context.set(None)
                code = await require_host_access(
                    executor, actor, alias,
                    session_id=sid if isinstance(sid, str) else None,
                    conversation_id=conversation_id_context.get(),
                    approvals=approvals, tool="transfer_file",
                    client_id=token.client_id,
                    reason=request.reason,
                    summary=lambda: approval_summary("transfer_file", arguments),
                    disconnected=(_ctx.request.is_disconnected
                                  if _ctx is not None and
                                  isinstance(_ctx.request, Request) else None),
                    privileged=privileged,
                    operation_timeout_seconds=request.timeout_seconds,
                )
                priority = {
                    ApprovalCode.APPROVED_CONFIG: 0,
                    ApprovalCode.APPROVED_TIMED: 1,
                    ApprovalCode.APPROVED_EXPLICIT: 2,
                }
                if (response_code is None or
                        priority.get(code, -1) > priority.get(response_code, -1)):
                    response_code = code
                if privileged:
                    roots[index] = root_access_context.get()
                root_access_context.set(None)
            files.audit.settle_approval(
                audit_id, int(response_code or ApprovalCode.APPROVED_CONFIG),
            )
            authorized = True
            data = await relay.transfer(actor, request, precreated_id=audit_id,
                                        roots=(roots[0], roots[1]))
            return _result(data, is_error=data["status"] not in {"succeeded", "running"})
        except ApprovalRejected as rejected:
            if not authorized:
                files.audit.settle_approval(
                    audit_id, int(rejected.approval_code), denied=True,
                )
            return _error("SSH host access denied or requires operator approval")
        except asyncio.CancelledError:
            if not authorized:
                files.audit.settle_approval(audit_id, None, denied=True)
            raise
        except (SSHDenied, ReadinessDenied, ValueError, RuntimeError, OSError,
                sqlite3.DatabaseError):
            if authorized:
                # A confirmed pre-scheduling error leaves a queued, approved
                # request; mark it terminal without masking a running operation.
                try:
                    files.audit.reject_unscheduled(audit_id, error_code="transport_error")
                except (sqlite3.DatabaseError, RuntimeError, ValueError, OSError):
                    pass
            else:
                files.audit.settle_approval(audit_id, None, denied=True)
            return _error("Transfer authorization or audit confirmation unavailable")
        finally:
            # The relay delegates request-scoped unlocks when task scheduling
            # succeeds. Finish any handle never transferred to a background task.
            for access in roots:
                if access is not None and not access.operation.delegated:
                    access.finish()

    async def dispatch_tool(_ctx, params: CallToolRequestParams):
        if params.name not in {"list_servers", "execute_command", *JOB_TOOL_NAMES,
                                *BATCH_TOOL_NAMES,
                                *FILE_TOOL_NAMES, "probe_binary_file_exchange"}:
            return handle_tool(params.name, dict(params.arguments or {}))

        # Extract auth exclusively from the SDK's request context. The caller
        # cannot supply or override the principal or request an unlisted host.
        token = get_access_token()
        if (
            executor is None
            or token is None
            or config.MCP_SSH_SCOPE not in token.scopes
            or not token.client_id
            or token.subject != config.MCP_OPERATOR_SUBJECT
        ):
            return _error("SSH tool requires an authenticated ssh.execute grant")

        # The signed operator subject is mandatory for every host/tool method.
        # Client-specific actor partitioning applies only after this gate.
        actor = client_audit_actor(token.client_id)
        arguments = dict(params.arguments or {})
        if params.name == "transfer_file":
            return await _transfer_tool(_ctx, arguments, actor, token)
        # Keep the existing structured validation errors for batches before
        # the shared host gate; no CWD preflight or SSH occurs in this step.
        batch_request: ExecuteCommandsRequest | None = None
        if params.name == "execute_commands":
            try:
                batch_request = ExecuteCommandsRequest.model_validate(arguments)
            except ValidationError as error:
                location = error.errors()[0].get("loc", ())
                index = next((item for item in location if type(item) is int), None)
                field = ".".join(str(piece) for piece in location
                                 if type(piece) is str) if isinstance(location, tuple) else "batch"
                if index is None:
                    message = str(error.errors()[0].get("msg", ""))
                    found = re.search(r"commands\[([0-4])\]\.([a-z_]+)", message)
                    if found is not None:
                        index = int(found.group(1))
                        field = f"commands.{found.group(2)}"
                return _result({
                    "status": "rejected", "failure_kind": "invalid_request",
                    "failed_step": index, "failed_field": field or "commands",
                    "steps_attempted": 0,
                }, is_error=True)
        # Validate the exact command payload BEFORE it can enter the operator
        # queue; admission is bound to this immutable model, not raw fields.
        command_request: ExecuteCommandRequest | None = None
        if params.name in {"execute_command", "submit_job"}:
            try:
                command_request = ExecuteCommandRequest.model_validate(arguments)
            except ValidationError:
                return _error("Invalid SSH request arguments")
        file_request: (ReadFileRequest | WriteFileRequest | ApplyPatchRequest
                       | UploadFileRequest | DownloadFileRequest | None) = None
        if params.name in FILE_TOOL_NAMES:
            model = {
                "read_file": ReadFileRequest, "write_file": WriteFileRequest,
                "apply_patch": ApplyPatchRequest, "upload_file": UploadFileRequest,
                "download_file": DownloadFileRequest,
            }[params.name]
            try:
                file_request = model.model_validate(arguments)
            except ValidationError:
                return _error("Invalid file operation arguments")
        privileged = (batch_request.privileged if batch_request is not None
                      else command_request.privileged if command_request is not None
                      else False)
        # A cached tool definition must not trigger an operator approval for
        # a command that cannot run without durable audit storage.
        if params.name in {"execute_command", "submit_job"} and jobs is None:
            return _error("Durable SSH job auditing is required")
        if params.name == "execute_commands" and batches is None:
            return _error("Durable SSH batch auditing is required")
        # Allocate one durable, timestamped audit record AFTER authentication,
        # model validation and signed-host validation, but BEFORE the operator
        # approval wait. Reuse that record on admission or final denial.
        audit_id: str | None = None
        host_reaching = params.name in {
            "execute_command", "submit_job", "execute_commands", *FILE_TOOL_NAMES,
        }
        file_kind: str | None = None
        def authorization_error() -> CallToolResult:
            if params.name == "execute_commands":
                # Preserve batch client's pre-execution rejection contract.
                return _result({
                    "status": "rejected", "failure_kind": "authorization",
                    "failed_step": None, "failed_field": "server",
                    "steps_attempted": 0,
                }, is_error=True)
            return _error("SSH host access denied or requires operator approval")

        if host_reaching:
            server_name = (batch_request.server if batch_request is not None
                           else arguments.get("server"))
            if not isinstance(server_name, str):
                return _error("Invalid SSH request arguments")
            try:
                host = executor.authorized_host(actor, server_name)
                sid = (token.claims or {}).get("sid")
                if (host.access == "restricted"
                        or privileged and host.privileged_access == "restricted"):
                    # A verified OAuth session is mandatory; missing conversation
                    # context limits approval to this exact suspended request.
                    if not isinstance(sid, str) or not sid:
                        return authorization_error()
                if (file_request is not None and files is not None
                        and file_request.operation_id
                        and files.audit.operation_id_exists(file_request.operation_id)):
                    existing_history_id = files.audit.replay_history_id(
                        actor, file_request.operation_id,
                    )
                    return _result({
                        "status": "failed", "operation_id": file_request.operation_id,
                        **({"history_id": existing_history_id}
                           if existing_history_id is not None else {}),
                        "error": {
                            "code": "duplicate_operation",
                            "message": "Operation ID exists; inspect before retrying",
                        },
                    }, is_error=True)
                if command_request is not None and jobs is not None:
                    audit_id = jobs.store.create(
                        actor, command_request,
                        mode="async" if params.name == "submit_job" else "sync",
                        pending_approval=True, username=host.username,
                    )
                elif batch_request is not None and batches is not None:
                    audit_id = batches.store.create(
                        actor, batch_request, pending_approval=True,
                        username=host.username,
                    )
                elif file_request is not None and files is not None:
                    file_kind = {
                        "read_file": "read", "write_file": "write",
                        "apply_patch": ("patch_preview"
                                        if isinstance(file_request, ApplyPatchRequest)
                                        and file_request.dry_run else "patch"),
                        "upload_file": "upload", "download_file": "download",
                    }[params.name]
                    audit_id = files.audit.reserve(
                        actor, file_request.server, file_kind,
                        file_request.path, file_request.story_id,
                    )
                else:
                    return _error("Durable SSH audit storage is required")
            except SSHDenied:
                return authorization_error()
            except (sqlite3.DatabaseError, RuntimeError, OSError, ValueError):
                return _error("Durable SSH auditing unavailable")

            def settle(code: int | None, *, denied: bool = False) -> None:
                assert audit_id is not None
                if command_request is not None and jobs is not None:
                    jobs.store.settle_approval(audit_id, code, denied=denied)
                elif batch_request is not None and batches is not None:
                    batches.store.settle_approval(audit_id, code, denied=denied)
                else:
                    assert files is not None
                    files.audit.settle_approval(audit_id, code, denied=denied)

            approved = False

            def record_approval(code: ApprovalCode) -> None:
                nonlocal approved
                settle(int(code))
                approved = True
                approval_status_context.set(int(code))

            sid = (token.claims or {}).get("sid")
            try:
                await require_host_access(
                    executor, actor, server_name,
                    session_id=sid if isinstance(sid, str) else None,
                    conversation_id=conversation_id_context.get(),
                    approvals=approvals, tool=params.name, client_id=token.client_id,
                    reason=str(arguments.get("reason") or ""),
                    summary=lambda: approval_summary(
                        params.name, arguments, batch_request,
                    ),
                    steps=(lambda: approval_steps(batch_request or command_request))
                    if (batch_request is not None or command_request is not None) else None,
                    disconnected=(
                        _ctx.request.is_disconnected
                        if _ctx is not None and isinstance(_ctx.request, Request)
                        else None
                    ),
                    privileged=privileged, on_approved=record_approval,
                    operation_timeout_seconds=(
                        batch_request.timeout_seconds if batch_request is not None
                        else command_request.timeout_seconds if command_request is not None
                        else 300
                    ),
                )
            except ApprovalRejected as rejected:
                try:
                    settle(rejected.approval_code, denied=True)
                except (sqlite3.DatabaseError, RuntimeError, OSError, ValueError):
                    return _error("Durable SSH approval audit unavailable")
                if params.name == "execute_commands":
                    return _result({
                        "status": "rejected", "failure_kind": "authorization",
                        "failed_step": None, "failed_field": "server",
                        "steps_attempted": 0,
                    }, is_error=True)
                return _error("SSH host access denied or requires operator approval")
            except ReadinessDenied as exc:
                try:
                    if approved:
                        assert audit_id is not None
                        if command_request is not None and jobs is not None:
                            jobs.store.reject_unscheduled(audit_id, str(exc))
                        elif batch_request is not None and batches is not None:
                            batches.store.finish(audit_id, "rejected",
                                                 failure_kind="host_readiness", error=str(exc))
                            data = batches.get(actor, audit_id)
                            if data is None:
                                raise RuntimeError("Batch audit unavailable")
                            return _result(data, is_error=True)
                        else:
                            assert files is not None
                            files.audit.reject_unscheduled(audit_id, error_code="host_readiness")
                    else:
                        settle(None, denied=True)
                except (sqlite3.DatabaseError, RuntimeError, OSError, ValueError):
                    return _error("Durable SSH approval audit unavailable")
                if params.name == "execute_commands":
                    return _result({
                        "status": "rejected", "failure_kind": "host_readiness",
                        "failed_step": None, "failed_field": None,
                        "steps_attempted": 0, "error": str(exc),
                    }, is_error=True)
                return _error(str(exc))
            except (SSHDenied, ValidationError, ValueError):
                # Manager missing/full/shutdown is operational failure, not
                # operator Deny; store a terminal row with NULL approval code.
                try:
                    settle(None, denied=True)
                except (sqlite3.DatabaseError, RuntimeError, OSError, ValueError):
                    return _error("Durable SSH approval audit unavailable")
                if params.name == "execute_commands":
                    return _result({
                        "status": "rejected", "failure_kind": "authorization",
                        "failed_step": None, "failed_field": "server",
                        "steps_attempted": 0,
                    }, is_error=True)
                return _error("SSH host access denied or requires operator approval")
            except asyncio.CancelledError:
                # Request cancellation while awaiting approval never starts SSH.
                settle(None, denied=True)
                raise
            except (sqlite3.DatabaseError, RuntimeError, OSError):
                # Probe errors and other operational failures are NOT a
                # positive disconnect observation or an operator Deny.
                try:
                    settle(None, denied=True)
                except (sqlite3.DatabaseError, RuntimeError, OSError, ValueError):
                    pass  # No execution; the audit store may be unavailable.
                return _error("Durable SSH approval audit unavailable")
        try:
            if params.name in BATCH_TOOL_NAMES:
                if batches is None:
                    return _error("Durable batches are disabled")
                if params.name == "execute_commands":
                    assert batch_request is not None
                    try:
                        data = await batches.execute(
                            actor, batch_request,
                            admitted_root=batch_request.privileged,
                            precreated_id=audit_id,
                        )
                    except SSHDenied:
                        return _result({
                            "status": "rejected", "failure_kind": "authorization",
                            "failed_step": None, "failed_field": "server",
                            "steps_attempted": 0,
                        }, is_error=True)
                    # Completed steps, even with unaccepted exits, are structured
                    # command results rather than MCP protocol errors.
                    return _result(data, is_error=data["status"] not in {
                        "succeeded", "failed",
                    })
                if params.name == "get_batch":
                    query = GetBatchRequest.model_validate(arguments)
                    data = batches.get(actor, query.batch_id,
                                       cursor=query.cursor, limit=query.limit)
                    return _result(data) if data is not None else _error("Batch unavailable")
                if params.name == "list_batches":
                    query = ListBatchesRequest.model_validate(arguments)
                    return _result(batches.list(actor, cursor=query.cursor,
                                                 limit=query.limit))
                query = CancelBatchRequest.model_validate(arguments)
                data = batches.cancel(actor, query.batch_id, reason=query.reason)
                return _result(data) if data is not None else _error("Batch unavailable")
            if params.name == "list_servers":
                ListServersRequest.model_validate(arguments)
                historical = history.hosts(actor=actor) if history is not None else []
                return _result({
                    "servers": executor.discover_hosts(actor, historical),
                    "history_hosts": historical,
                })
            if params.name == "probe_binary_file_exchange":
                if not probe_enabled:
                    return _error("Binary capability probe is disabled")
                probe_request = BinaryProbeRequest.model_validate(arguments)
                try:
                    return await probe_exchange(probe_request)
                except BinaryProbeError:
                    return _error("Binary capability probe rejected the file or size")
            if params.name in FILE_TOOL_NAMES:
                if files is None:
                    return _error("File operations require durable audit storage")
                if params.name == "upload_file":
                    upload_request = UploadFileRequest.model_validate(arguments)
                    data = await files.upload(actor, upload_request,
                                              precreated_id=audit_id)
                    return _result(data, is_error=data["status"] != "succeeded")
                if params.name == "download_file":
                    download_request = DownloadFileRequest.model_validate(arguments)
                    data = await files.download(actor, download_request,
                                                precreated_id=audit_id)
                    if data["status"] != "succeeded":
                        return _result(data, is_error=True)
                    result = data.get("result")
                    if not isinstance(result, dict):
                        return _error("Invalid binary download response")
                    encoded = result.get("data_base64")
                    if not isinstance(encoded, str):
                        return _error("Missing binary download payload")
                    raw = base64.b64decode(encoded, validate=True)
                    # Present only safe metadata in text; the raw bytes exist
                    # solely in the MCP response resource, never in job history.
                    clean = {**data, "result": {k: v for k, v in result.items()
                                              if k != "data_base64"}}
                    checksum = hashlib.sha256(raw).hexdigest()
                    return CallToolResult(content=[
                        TextContent(type="text", text=json.dumps(clean, separators=(",", ":"))),
                        EmbeddedResource(resource=BlobResourceContents(
                            uri=f"ssh-mcp-file://sha256/{checksum}/part/{result.get('offset', 0)}",
                            mime_type="application/octet-stream",
                            blob=base64.b64encode(raw).decode("ascii"),
                        )),
                    ])
                model = {
                    "read_file": ReadFileRequest,
                    "write_file": WriteFileRequest,
                    "apply_patch": ApplyPatchRequest,
                }[params.name]
                file_request = model.model_validate(arguments)
                payload = file_request.model_dump(exclude_unset=True, exclude={
                    "server", "path", "base_dir", "reason", "story_id", "operation_id",
                }, exclude_none=True)
                operation = {
                    "read_file": "read", "write_file": "write",
                    "apply_patch": "patch",
                }[params.name]
                if params.name == "apply_patch" and file_request.dry_run:
                    operation = "patch_preview"
                data = await files.perform(actor, file_request, operation,
                                           payload, precreated_id=audit_id)
                return _result(data, is_error=data["status"] != "succeeded")
            if params.name in JOB_TOOL_NAMES:
                if jobs is None:
                    return _error("Durable jobs are disabled")
                if params.name == "submit_job":
                    assert command_request is not None
                    return _result({"job": jobs.submit(
                        actor, command_request,
                        admitted_root=command_request.privileged,
                        precreated_id=audit_id,
                    )})
                assert history is not None
                if params.name == "list_jobs":
                    query = ListJobsRequest.model_validate(arguments)
                    filters = query.history_filters()
                    filters["actor"] = actor
                    rows = history.list(filters, before=_decode_mcp_cursor(query.cursor),
                                        limit=query.limit)
                    # Historical actor identities are internal audit metadata.
                    summaries = [
                        {key: value for key, value in row.items() if key not in {"actor", "command_preview", "agent", "agent_key"}}
                        for row in rows["jobs"]
                    ]
                    next_cursor = _encode_mcp_cursor(rows["next_page"])
                    return _result({
                        "jobs": summaries, "next_cursor": next_cursor,
                        "has_more": next_cursor is not None,
                        "total": rows["filtered_total"],
                    })
                if params.name == "get_job_stats":
                    query = GetJobStatsRequest.model_validate(arguments)
                    filters = query.history_filters()
                    filters["actor"] = actor
                    if not any(k in filters for k in ("time_range", "from_date", "to_date")):
                        filters["time_range"] = "24h"
                    return _result(history.stats(filters, group_by=query.group_by,
                                                 limit=query.limit))
                if params.name == "get_status":
                    ListServersRequest.model_validate(arguments)
                    return _result(service_status(
                        jobs, started_monotonic=started_monotonic, actor=actor,
                    ))
                if params.name == "get_job":
                    query = GetJobRequest.model_validate(arguments)
                    item = history.detail(query.job_id)
                    if item is None or item.get("actor") != actor:
                        return _error("Job unavailable")
                    for field in ("actor", "agent", "agent_key", "client_id"):
                        item.pop(field, None)
                    return _result({"job": item}) if item is not None else _error("Job unavailable")
                if params.name == "get_job_output":
                    query = GetJobOutputRequest.model_validate(arguments)
                    detail = history.detail(query.job_id)
                    if detail is None or detail.get("actor") != actor:
                        return _error("Job unavailable")
                    data = history.output(
                        query.job_id, cursor=query.cursor, max_bytes=query.max_bytes,
                    )
                    return _result(data) if data is not None else _error("Job unavailable")
                if params.name == "cancel_job":
                    query = CancelJobRequest.model_validate(arguments)
                    data = (
                        await relay.cancel(actor, query.job_id)
                        if relay is not None and query.job_id.startswith("file_")
                        else jobs.cancel(actor, query.job_id, reason=query.reason)
                    )
                    return _result(data) if data is not None else _error("Job unavailable")
            assert command_request is not None
            request = command_request
        except ValidationError:
            return _error("Invalid SSH request arguments")
        except (SSHDenied, RuntimeError, ValueError, sqlite3.DatabaseError, OSError):
            # Never expose SQL, file paths, requests or output in MCP errors.
            return _error("SSH job request rejected")

        assert jobs is not None  # Rejected before host approval above.
        created_job_id: str | None = None

        def remember_job_id(job_id: str) -> None:
            nonlocal created_job_id
            created_job_id = job_id

        try:
            job_id, result = await jobs.execute_sync(
                actor, request, on_created=remember_job_id,
                admitted_root=request.privileged,
                precreated_id=audit_id,
            )
            if result is None:
                saved = jobs.get(actor, job_id)
                if saved is not None and saved["status"] == "cancelled":
                    return _result({
                        "job_id": job_id, "server": request.server,
                        "status": "cancelled",
                        "execution_started": saved["started_at"] is not None,
                        "failure_kind": "cancelled",
                    }, is_error=True)
                if (saved is not None and saved["status"] == "failed"
                        and saved["failure_kind"] == "pre_execution_rejected"):
                    # started_at is capacity admission, not proof that argv ran.
                    # Never infer a denial from a generic failed status/error.
                    return _result({
                        "job_id": job_id, "server": request.server,
                        "status": "rejected",
                        "failure_kind": "pre_execution_rejected",
                        "execution_started": False,
                        "exit_code": None,
                        "error": saved["error"] or "SSH request rejected before command execution",
                    }, is_error=True)
                return _result({
                    "job_id": job_id, "server": request.server,
                    "status": "unknown", "failure_kind": "execution_unconfirmed",
                    "error": "Execution result unavailable; inspect job before retrying",
                }, is_error=True)
        except SSHDenied:
            return _error("SSH target or principal not authorized")
        except (sqlite3.DatabaseError, OSError, RuntimeError, ValueError):
            # If a job was created, a later audit write may have failed AFTER
            # the SSH command ran. Keep its ID for reconciliation and never
            # mislabel this as a pre-execution rejection or expose DB details.
            if created_job_id is not None:
                return _result({
                    "job_id": created_job_id, "server": request.server,
                    "status": "unknown", "failure_kind": "audit_unavailable",
                    "error": "Audit confirmation unavailable; inspect job before retrying",
                }, is_error=True)
            return _error("Durable SSH auditing unavailable")

        request_id = secrets.token_hex(12)
        # Do not log argv, reason, credentials, stdout or stderr.
        LOGGER.info(
            "direct_ssh request_id=%s principal=%s server=%s status=%s exit_code=%s",
            request_id, actor, result.server, result.status, result.exit_code,
        )
        return _result(
            {"request_id": request_id, **asdict(result),
             "job_id": job_id},
            is_error=result.status not in {"succeeded", "command_error"},
        )

    async def call_tool(_ctx, params: CallToolRequestParams):
        request = _ctx.request if _ctx is not None else None
        access = get_access_token()
        verified_client_id = (
            access.client_id if access is not None
            and access.subject == config.MCP_OPERATOR_SUBJECT
            and config.MCP_SSH_SCOPE in access.scopes else None
        )
        try:
            conversation_id = conversation_id_from_request(
                request.headers if isinstance(request, Request) else None,
                params.meta, client_id=verified_client_id,
            )
        except ValueError:
            return _error("Invalid or conflicting conversation identifier")
        context_token = conversation_id_context.set(conversation_id)
        approval_token = approval_status_context.set(None)
        client_token = client_id_context.set(verified_client_id)
        root_token = root_access_context.set(None)
        try:
            return await dispatch_tool(_ctx, params)
        finally:
            # When no background job/batch accepted ownership, reject any
            # pre-scheduling error path without retaining the once password.
            finish_once_root(unless_delegated=True)
            root_access_context.reset(root_token)
            client_id_context.reset(client_token)
            approval_status_context.reset(approval_token)
            conversation_id_context.reset(context_token)

    server = Server(
        "SSH-MCP",
        version=service_version(),
        title="SSH-MCP",
        description="Authorized audited SSH execution and command history.",
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )
    auth = AuthSettings(
        issuer_url=MCP_ISSUER,
        resource_server_url=MCP_RESOURCE,
        required_scopes=_supported_scopes(),
        validate_token_resource=True,
    )
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=MCP_ALLOWED_HOSTS,
        allowed_origins=MCP_ALLOWED_ORIGINS,
    )
    # Retain signed static Origins while dynamically checking live OAuth
    # sessions for other authorized clients, including revocation and expiry.
    security.allowed_origins = ActiveOrigins(security.allowed_origins)
    mcp_app = server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        transport_security=security,
        auth=auth,
        token_verifier=OAuthTokenVerifier(),
    )
    return server, mcp_app
