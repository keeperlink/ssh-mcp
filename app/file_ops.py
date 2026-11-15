"""Common file-operation service and strict, actor-scoped schemas.

The read/write/patch tools never forward payload bytes to the command-job
recorder or the browser.
"""
from __future__ import annotations

from typing import Any
import base64
import binascii
import hashlib


from .contracts import (
    FileOperationRequest, ReadFileRequest as ReadFileRequest,
    WriteFileRequest as WriteFileRequest,
    ApplyPatchRequest as ApplyPatchRequest,
)
from .file_audit import FileAudit, KINDS
from .file_transport import FileTransport, FileTransportError
from .jobs import JobStore
from .ssh_executor import SSHDenied, SSHExecutor


class FileService:
    def __init__(self, executor: SSHExecutor, store: JobStore,
                 *, transport: FileTransport | None = None):
        self.executor = executor
        self.transport = transport or FileTransport(executor)
        self.audit = FileAudit(store)

    async def perform(self, actor: str, request: FileOperationRequest, kind: str,
                      parameters: dict[str, Any] | None = None, *,
                      precreated_id: str | None = None) -> dict[str, Any]:
        if kind not in KINDS:
            return {"status": "failed", "error": {"code": "unsupported_operation",
                                                   "message": "Unsupported operation"}}
        # Revalidate the signed host before dispatch. Losing authorization
        # after approval must terminate the durable request, not strand it queued.
        try:
            self.executor.authorized_host(actor, request.server)
        except (SSHDenied, OSError, RuntimeError):
            if precreated_id is not None:
                self.audit.reject_unscheduled(precreated_id)
            raise
        try:
            operation_id = self.audit.start(
                actor, request.server, kind, request.path,
                request.story_id, request.operation_id,
                precreated_id=precreated_id,
            )
        except ValueError as exc:
            if str(exc) == "duplicate_operation":
                matching = (self.audit.replay_history_id(actor, request.operation_id)
                            if request.operation_id else None)
                return {"status": "failed", "operation_id": request.operation_id,
                        **({"history_id": matching} if matching else {}),
                        "error": {"code": "duplicate_operation",
                                  "message": "Operation ID already exists; inspect before retrying"}}
            raise
        payload = dict(parameters or {})
        # The common request owns path/base semantics; do not let tool-specific
        # parameters silently change the operation recorded in audit.
        payload.update(path=request.path, base_dir=request.base_dir)
        try:
            result = await self.transport.execute(
                actor, request.server, (
                    "download_chunk" if kind == "download" else
                    "patch" if kind == "patch_preview" else kind
                ),
                payload,
            )
            if kind == "download" and result.get("ok"):
                raw = result.get("data_base64")
                if not isinstance(raw, str):
                    raise FileTransportError("invalid_response", "Missing download chunk")
                try:
                    chunk = base64.b64decode(raw, validate=True)
                except (ValueError, binascii.Error):
                    raise FileTransportError("invalid_response", "Invalid download encoding") from None
                if (result.get("bytes") != len(chunk)
                        or result.get("chunk_sha256") != hashlib.sha256(chunk).hexdigest()):
                    raise FileTransportError("invalid_response", "Download checksum mismatch")
            status = ("succeeded" if result.get("ok") else
                      "unknown" if result.get("unknown") else
                      "partial" if result.get("partial") else "failed")
            error = result.get("error") if isinstance(result.get("error"), dict) else None
            error_code = error.get("code") if error else None
            bytes_count = result.get("bytes", 0)
            if not isinstance(bytes_count, int) or isinstance(bytes_count, bool):
                bytes_count = 0
            outcomes = result.get("outcomes")
            self.audit.finish(
                operation_id, status, byte_count=bytes_count,
                error_code=error_code if isinstance(error_code, str) else None,
                outcomes=outcomes if isinstance(outcomes, list) else None,
                transfer=({
                    "direction": "download", "size": result.get("size"),
                    "offset": result.get("offset"), "next_offset": result.get("next_offset"),
                    "chunk_sha256": result.get("chunk_sha256"),
                    "sha256": result.get("sha256"), "eof": result.get("eof"),
                } if kind == "download" else None),
            )
            return { "operation_id": request.operation_id or operation_id,
                    "history_id": "file_" + operation_id,
                    "status": status, "result": result,
                    **({"change_state": result["change_state"]}
                       if kind == "patch" and result.get("change_state") else {}),
                    **({"retry_guidance": result["retry_guidance"]}
                       if kind == "patch" and result.get("retry_guidance") else {})}
        except FileTransportError as exc:
            status = "unknown" if exc.uncertain else "failed"
            self.audit.finish(operation_id, status, error_code=exc.code)
            return { "operation_id": request.operation_id or operation_id,
                    "history_id": "file_" + operation_id,
                    "status": status,
                    "error": {"code": exc.code, "message": str(exc)},
                    **({"change_state": "outcome_uncertain" if exc.uncertain else "no_changes",
                        "retry_guidance": "reconcile_before_retry" if exc.uncertain
                        else "refresh_preconditions"} if kind == "patch" else {})}
        except BaseException:
            # Cancellation, disconnect or unexpected exception may leave
            # remote write status uncertain. Never automatically replay.
            self.audit.finish(operation_id, "unknown", error_code="interrupted")
            raise
