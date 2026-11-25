"""Bounded binary ingress orchestrated through audited SSH helper.

Bytes come from a native ChatGPT attachment URL (upload_file) or from small
inline base64 content (upload_file_content); both share the same transfer.

The per-call transfer has no independent persistent artifact/session service.
Remote upload staging is owned by the SSH account, published only after a
full SHA-256 verification, and discarded on confirmed failure.
"""
from __future__ import annotations

import base64
import hashlib
from typing import Any

from .binary_probe import BinaryProbeError, read_binary_file, source_failure_diagnostic
from .contracts import DownloadFileRequest, UploadFileContentRequest, UploadFileRequest
from .file_ops import FileService
from .file_helper import MAX_BINARY_CHUNK_BYTES, MAX_BINARY_TRANSFER_BYTES
from .file_transport import FileTransportError
from .ssh_executor import SSHDenied

MAX_TRANSFER_BYTES = MAX_BINARY_TRANSFER_BYTES
TRANSFER_CHUNK_BYTES = MAX_BINARY_CHUNK_BYTES


def _remote_error(result: dict[str, Any], *, mutation: bool) -> FileTransportError:
    if result.get("ok") is True:
        raise ValueError("Expected failed remote operation")
    error = result.get("error")
    code = error.get("code") if isinstance(error, dict) else None
    if not isinstance(code, str):
        code = "invalid_response"
    # An explicit unknown/partial response may mean an SSH-stage operation
    # reached the remote disk, even if its response was not successful.
    return FileTransportError(
        code, "Remote binary transfer step rejected",
        uncertain=mutation and bool(result.get("unknown") or result.get("partial")),
    )


class BinaryTransferService(FileService):
    async def upload(self, actor: str,
                     request: UploadFileRequest | UploadFileContentRequest, *,
                     precreated_id: str | None = None) -> dict[str, Any]:
        try:
            self.executor.authorized_host(actor, request.server)
        except (SSHDenied, OSError, RuntimeError):
            if precreated_id is not None:
                self.audit.reject_unscheduled(precreated_id)
            raise
        try:
            identifier = self.audit.start(
                actor, request.server, "upload", request.path,
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
                                  "message": "Operation ID exists; inspect before retrying"}}
            raise
        started = False
        finish_attempted = False
        session_id: str | None = None
        bytes_written = 0
        source_size = 0
        source_sha256: str | None = None
        root = {"path": request.path, "base_dir": request.base_dir}
        outcome: dict[str, Any]
        source_diagnostic: dict[str, str | int] | None = None
        source_url = (request.file.download_url
                      if isinstance(request, UploadFileRequest) else "")
        try:
            if isinstance(request, UploadFileRequest):
                content = await read_binary_file(source_url, max_bytes=MAX_TRANSFER_BYTES)
            else:
                content = request.content()
            source_size = len(content)
            source_sha256 = hashlib.sha256(content).hexdigest()
            if (request.source_sha256 is not None
                    and source_sha256 != request.source_sha256.lower()):
                raise FileTransportError(
                    "precondition_failed", "Input SHA-256 does not match supplied checksum",
                )
            begin = await self.transport.execute(
                actor, request.server, "upload_start",
                {**root, "mode": request.mode, "create_parents": request.create_parents,
                 "expected_sha256": request.expected_sha256},
            )
            if not begin.get("ok"):
                raise _remote_error(begin, mutation=True)
            session_id = begin.get("session_id")
            if not isinstance(session_id, str) or len(session_id) != 32:
                raise FileTransportError(
                    "invalid_response", "Invalid upload staging response", uncertain=True,
                )
            started = True
            for offset in range(0, source_size, TRANSFER_CHUNK_BYTES):
                chunk = content[offset:offset + TRANSFER_CHUNK_BYTES]
                digest = hashlib.sha256(chunk).hexdigest()
                sent = await self.transport.execute(
                    actor, request.server, "upload_chunk", {
                        **root, "session_id": session_id, "offset": offset,
                        "data_base64": base64.b64encode(chunk).decode("ascii"),
                        "chunk_sha256": digest,
                    },
                )
                if not sent.get("ok"):
                    raise _remote_error(sent, mutation=True)
                if (sent.get("offset") != offset + len(chunk)
                        or sent.get("chunk_sha256") != digest):
                    raise FileTransportError(
                        "invalid_response", "Upload chunk verification failed", uncertain=True,
                    )
                bytes_written += len(chunk)
            finish_attempted = True
            finished = await self.transport.execute(
                actor, request.server, "upload_finish", {
                    **root, "session_id": session_id, "mode": request.mode,
                    "size": source_size, "sha256": source_sha256,
                    "expected_sha256": request.expected_sha256,
                },
            )
            if not finished.get("ok"):
                raise _remote_error(finished, mutation=True)
            if (finished.get("sha256") != source_sha256
                    or finished.get("bytes") != source_size):
                raise FileTransportError(
                    "invalid_response", "Upload publication verification failed", uncertain=True,
                )
            outcome = { "operation_id": request.operation_id or identifier,
                       "history_id": "file_" + identifier,
                       "status": "succeeded",
                       "result": {"path": str(finished.get("path")), "bytes": source_size,
                                  "size": source_size, "sha256": source_sha256,
                                  "mode": request.mode, "atomic": True}}
            self.audit.finish(
                identifier, "succeeded", byte_count=source_size,
                transfer={"direction": "upload", "size": source_size, "sha256": source_sha256,
                          "mode": request.mode},
            )
            return outcome
        except BinaryProbeError as exc:
            source_diagnostic = source_failure_diagnostic(exc, source_url)
            failure = FileTransportError(
                "source_unavailable", "ChatGPT file source unavailable or exceeds transfer limit",
            )
        except FileTransportError as exc:
            failure = exc
        except BaseException:
            self.audit.finish(
                identifier, "unknown", byte_count=bytes_written,
                error_code="interrupted",
                transfer={"direction": "upload", "size": source_size,
                          "sha256": source_sha256, "mode": request.mode},
            )
            raise
        status = "unknown" if failure.uncertain else "failed"
        safe_finish_failure = failure.code in {
            "already_exists", "precondition_failed", "invalid_request", "changed_file",
            "payload_limit", "host_readiness",
        }
        if finish_attempted and not failure.uncertain and not safe_finish_failure:
            # A filesystem/transport failure at publication may have happened
            # after installing the destination; never claim no mutation.
            status = "unknown"
        if started and session_id and not failure.uncertain and failure.code != "host_readiness" and (
            not finish_attempted or safe_finish_failure
        ):
            # Clean only confirmed pre-publish failures. Unknown publication
            # outcomes remain available for inspection and expiry-based GC.
            try:
                cleaned = await self.transport.execute(
                    actor, request.server, "upload_abort",
                    {**root, "session_id": session_id},
                )
                if not cleaned.get("ok"):
                    status = "unknown"
            except FileTransportError:
                status = "unknown"
        self.audit.finish(
            identifier, status, byte_count=bytes_written, error_code=failure.code,
            transfer={"direction": "upload", "size": source_size,
                      "sha256": source_sha256, "mode": request.mode},
        )
        error: dict[str, Any] = {"code": failure.code, "message": str(failure)}
        if failure.code == "host_readiness":
            error["published"] = False
        if source_diagnostic is not None:
            # Caller-only diagnostic. Never pass the hostname to audit.finish,
            # history details, logs or untrusted outbound HTTP exceptions.
            error["diagnostic"] = source_diagnostic
        return { "operation_id": request.operation_id or identifier,
                       "history_id": "file_" + identifier,
                "status": status, "error": error}

    async def download(self, actor: str, request: DownloadFileRequest, *,
                       precreated_id: str | None = None) -> dict[str, Any]:
        payload = request.model_dump(exclude_unset=True, exclude_none=True, exclude={
            "server", "path", "base_dir", "reason", "story_id", "operation_id",
        })
        return await self.perform(actor, request, "download", payload,
                                  precreated_id=precreated_id)
