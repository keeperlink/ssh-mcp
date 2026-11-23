"""Audited constant-RAM transfer between two independently authorized SSH hosts.

The service owns the two SSH channels; file bytes never enter the MCP reply,
durable job history, HTTP response or container filesystem.
"""
from __future__ import annotations

import asyncio
import asyncssh
import hashlib
import json
import posixpath
import secrets
import shlex
import struct
import weakref
from contextlib import AsyncExitStack
from typing import Any

from . import config
from .contracts import TransferFileRequest
from .file_audit import FileAudit
from .grant_unlocks import RootAccess
from .relay_scripts import SOURCE, RECEIVER
from .sealed_credentials import InvalidCredential
from .ssh_channel import ChannelConnectionError, SSHChannelProcess, open_command
from .ssh_executor import SSHDenied, SSHExecutor


class RelayFailure(Exception):
    def __init__(self, code: str, *, uncertain: bool = False):
        super().__init__(code)
        self.code = code
        self.uncertain = uncertain


async def _exact(reader: Any, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        data = await reader.read(size - len(chunks))
        if not data:
            raise RelayFailure("transport_error", uncertain=True)
        chunks.extend(data)
    return bytes(chunks)


async def _ready(reader: Any, token: str) -> None:
    marker = b"\x1e" + token.encode("ascii") + b"\x1e\n"
    pending = bytearray()
    while len(pending) < 4096:
        item = await reader.read(1)
        if not item:
            raise RelayFailure("transport_error")
        pending.extend(item)
        if pending.endswith(marker):
            return
    raise RelayFailure("invalid_response")


def _sudo_prompt(marker: str) -> str:
    return "SSH-MCP-SUDO-CHALLENGE-" + marker + ":"


def _argv(script: str, args: list[str], privileged: bool) -> str:
    command = ["/usr/bin/python3", "-u", "-c", script, *args]
    if privileged:
        # An isolated, unpredictable prompt proves sudo really requested a
        # password. Never supply a secret to an already-running Python command
        # (for instance if root is unexpectedly passwordless).
        if len(args) < 2:
            raise ValueError("Privileged relay marker missing")
        command = [
            "/usr/bin/sudo", "-S", "-k", "-p", _sudo_prompt(args[-2]),
            "-H", "-u", "root", "--", *command,
        ]
    return shlex.join(command)


async def _finish_channel(proc: SSHChannelProcess) -> bool:
    try:
        result = await proc.wait()
        return result == 0 and proc.channel_complete
    except (OSError, RuntimeError):
        return False


async def _close_channel(proc: SSHChannelProcess | None) -> None:
    if proc is None:
        return
    try:
        proc.connection.abort()
        await asyncio.wait_for(proc.connection.wait_closed(), timeout=2)
    except (OSError, RuntimeError, TimeoutError):
        pass


class HostRelayService:
    def __init__(self, executor: SSHExecutor, audit: FileAudit):
        self.executor = executor
        self.audit = audit
        self._active: dict[str, asyncio.Task[dict[str, Any]]] = {}
        self._locks: weakref.WeakValueDictionary[tuple[str, str], asyncio.Lock] = (
            weakref.WeakValueDictionary()
        )

    async def transfer(self, actor: str, req: TransferFileRequest,
                       *, precreated_id: str, roots: tuple[RootAccess | None,
                                                          RootAccess | None]) -> dict[str, Any]:
        try:
            self.executor.authorized_host(actor, req.source_server)
            self.executor.authorized_host(actor, req.dest_server)
            identifier = self.audit.start(
                actor, req.dest_server, "transfer", req.dest_path,
                req.story_id, req.operation_id, precreated_id=precreated_id,
            )
        except ValueError as exc:
            if str(exc) == "duplicate_operation":
                return {"status": "failed", "operation_id": req.operation_id,
                        "error": {"code": "duplicate_operation",
                                  "message": "Operation already exists; inspect before retry"}}
            raise
        history_id = "file_" + identifier
        # Reserve both host slots and create the task before returning to
        # caller; one-request root unlocks must be delegated explicitly.
        task = asyncio.create_task(self._run(actor, req, identifier, roots))
        self._active[history_id] = task
        for root in roots:
            if root is not None:
                root.delegate()
        task.add_done_callback(lambda _: self._active.pop(history_id, None))
        wait = min(req.wait_seconds, req.timeout_seconds)
        if wait:
            try:
                return await asyncio.wait_for(asyncio.shield(task), timeout=wait)
            except asyncio.TimeoutError:
                pass
        return {"status": "running", "history_id": history_id,
                "source_server": req.source_server, "dest_server": req.dest_server,
                "bytes_transferred": 0}

    async def cancel(self, actor: str, job_id: str) -> dict[str, Any] | None:
        if not job_id.startswith("file_"):
            return None
        identifier = job_id[5:]
        item = self.audit.get(actor, identifier)
        if item is None or item["operation_kind"] != "transfer":
            return None
        task = self._active.get(job_id)
        if task is None or task.done():
            return {"job_id": job_id, "cancellation_requested": False,
                    "status": item["status"]}
        task.cancel()
        return {"job_id": job_id, "cancellation_requested": True,
                "status": "running"}

    async def _run(self, actor: str, req: TransferFileRequest, identifier: str,
                   roots: tuple[RootAccess | None, RootAccess | None]) -> dict[str, Any]:
        moved = 0
        total = 0
        sha256: str | None = None
        status = "unknown"
        code: str | None = None
        src: SSHChannelProcess | None = None
        dest: SSHChannelProcess | None = None
        confirmed_cleanup = False
        history_id = "file_" + identifier
        lock_key = (req.dest_server, posixpath.normpath(req.dest_path))
        lock = self._locks.get(lock_key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[lock_key] = lock
        try:
            async with asyncio.timeout(req.timeout_seconds), lock:
                # Only one global permit for the relay, two per-host permits.
                # Sorting aliases prevents reverse-direction AB/BA deadlocks.
                aliases = sorted([req.source_server, req.dest_server])
                async with AsyncExitStack() as stack:
                    await stack.enter_async_context(self.executor._global)
                    for alias in aliases:
                        await stack.enter_async_context(self.executor._semaphores[alias])
                    for alias, privileged, root in (
                        (req.source_server, req.source_privileged, roots[0]),
                        (req.dest_server, req.dest_privileged, roots[1]),
                    ):
                        host = self.executor.authorized_host(actor, alias)
                        if privileged:
                            if host.privileged_access == "none":
                                raise SSHDenied("Privileged transfer disabled")
                            if alias in self.executor._sealed_sudo and root is None:
                                raise SSHDenied("Privileged transfer unlock missing")
                        self.executor.require_ready(
                            alias, privileged=privileged and alias not in self.executor._sealed_sudo,
                        )
                    maximum = config.SSH_TRANSFER_MAX_BYTES
                    chunk = config.SSH_TRANSFER_CHUNK_BYTES
                    nonce = secrets.token_hex(12)
                    src_host = self.executor.authorized_host(actor, req.source_server)
                    src = await open_command(src_host, _argv(
                        SOURCE,
                        [req.source_path, str(maximum), str(chunk), "SRC-" + nonce,
                         "1" if req.source_privileged else "0"],
                        req.source_privileged,
                    ), allow_stdin=req.source_privileged)
                    if req.source_privileged:
                        await self._sudo(src, actor, req.source_server, roots[0],
                                         marker="SRC-" + nonce)
                    await _ready(src.stderr, "SRC-" + nonce)
                    head = await _exact(src.stdout, 40)
                    total = struct.unpack(">Q", head[:8])[0]
                    sha256 = head[8:].hex()
                    if total > maximum or (req.source_sha256 is not None
                                           and sha256 != req.source_sha256.lower()):
                        raise RelayFailure("precondition_failed")
                    # Source digest is established before the destination is opened.
                    dest_host = self.executor.authorized_host(actor, req.dest_server)
                    dest = await open_command(dest_host, _argv(
                        RECEIVER,
                        [req.dest_path, req.mode, "1" if req.create_parents else "0",
                         str(total), sha256, (req.expected_sha256 or "-").lower(),
                         str(chunk), str(config.SSH_MAX_TIMEOUT_SECONDS + 300),
                         "DEST-" + nonce, "1" if req.dest_privileged else "0"],
                        req.dest_privileged,
                    ), allow_stdin=True)
                    if req.dest_privileged:
                        await self._sudo(dest, actor, req.dest_server, roots[1],
                                         marker="DEST-" + nonce, close=False)
                    await _ready(dest.stderr, "DEST-" + nonce)
                    if dest.stdin is None:
                        raise RelayFailure("transport_error", uncertain=True)
                    local = hashlib.sha256()
                    while moved < total:
                        block = await _exact(src.stdout, min(chunk, total - moved))
                        dest.stdin.write(block)
                        await dest.stdin.drain()
                        local.update(block)
                        moved += len(block)
                        self.audit.progress(identifier, moved, total)
                    if local.hexdigest() != sha256:
                        raise RelayFailure("changed_file")
                    # The source must have completed with a confirmed remote
                    # status before sending the *only* commit frame.
                    if await src.stdout.read(1) or not await _finish_channel(src):
                        raise RelayFailure("changed_file", uncertain=True)
                    dest.stdin.write(b"COMMIT!")
                    await dest.stdin.drain()
                    dest.stdin.close()
                    proof = await _exact(dest.stdout, 1)
                    line = proof + await dest.stdout.read(1023)
                    if not await _finish_channel(dest):
                        raise RelayFailure("transport_error", uncertain=True)
                    try:
                        result = json.loads(line)
                        if (result.get("ok") is not True or result.get("size") != total
                                or result.get("sha256") != sha256):
                            raise ValueError()
                    except (ValueError, AttributeError):
                        raise RelayFailure("invalid_response", uncertain=True) from None
                    status = "succeeded"
        except asyncio.CancelledError:
            code = "cancelled"
            # Stop the receiver first so its finally clause unlinks any
            # uncommitted stage. A disconnect is never remote-kill evidence.
            if dest is None:
                confirmed_cleanup = True
            else:
                if dest.stdin is not None:
                    dest.stdin.close()
                try:
                    completion = await asyncio.wait_for(dest.wait(), timeout=2)
                    confirmed_cleanup = completion is not None and (
                        completion != 0 and dest.channel_complete
                    )
                except (asyncssh.Error, OSError, RuntimeError, TimeoutError):
                    confirmed_cleanup = False
            source_stopped = src is None
            if src is not None:
                try:
                    await asyncio.wait_for(src.wait(), timeout=2)
                    source_stopped = src.channel_complete
                except (asyncssh.Error, OSError, RuntimeError, TimeoutError):
                    source_stopped = False
            status = "cancelled" if confirmed_cleanup and source_stopped else "unknown"
        except TimeoutError:
            status, code = "unknown", "timeout"
        except RelayFailure as exc:
            status = "unknown" if exc.uncertain else "failed"
            code = exc.code
        except (OSError, RuntimeError, SSHDenied, InvalidCredential, ValueError,
                ChannelConnectionError, asyncssh.Error):
            status, code = "unknown", "transport_error"
        finally:
            await _close_channel(src)
            await _close_channel(dest)
            for root in roots:
                if root is not None:
                    root.finish()
            self.audit.finish(
                identifier, status, byte_count=moved, error_code=code,
                transfer={"direction": "relay", "sha256": sha256 or "",
                          "size": total, "source_server": req.source_server,
                          "dest_server": req.dest_server,
                          "source_path": req.source_path, "dest_path": req.dest_path,
                          "source_privileged": req.source_privileged,
                          "dest_privileged": req.dest_privileged, "mode": req.mode},
            )
        return {"status": status, "history_id": history_id,
                "source_server": req.source_server, "dest_server": req.dest_server,
                "bytes_transferred": moved, "total_bytes": total,
                **({"sha256": sha256} if sha256 and status == "succeeded" else {}),
                **({"error": {"code": code or "transport_error",
                              "message": "Transfer incomplete; inspect job before retry"}}
                   if status != "succeeded" else {})}

    async def _sudo(self, proc: SSHChannelProcess, actor: str, alias: str,
                    root: RootAccess | None, *, marker: str,
                    close: bool = True) -> None:
        password: str | None
        if alias in self.executor._sealed_sudo:
            if root is None:
                raise SSHDenied("Privileged unlock unavailable")
            password = root.require(host=alias, actor=actor)
        else:
            password = self.executor._sudo_passwords.get(alias)
        if not password or proc.stdin is None:
            raise SSHDenied("Privileged credential missing")
        # sudo's unpredictable prompt must be observed BEFORE the credential
        # is written. In particular, a passwordless sudo configuration must
        # never feed a plaintext password into the destination file stream.
        prompt = _sudo_prompt(marker).encode("ascii")
        ready_marker = b"\x1e" + marker.encode("ascii") + b"\x1e\n"
        received = bytearray()
        for _ in range(4096):
            block = await proc.stderr.read(1)
            if not block:
                raise SSHDenied("Privileged sudo challenge unavailable")
            received.extend(block)
            if received.endswith(ready_marker):
                raise SSHDenied("Privileged sudo prompt was bypassed")
            if received.endswith(prompt):
                break
        else:
            raise SSHDenied("Privileged sudo challenge invalid")
        proc.stdin.write(password.encode("utf-8") + b"\n")
        await proc.stdin.drain()
        password = None
        if close:
            proc.stdin.close()
