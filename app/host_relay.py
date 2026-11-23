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
from .ssh_executor import SSHDenied, SSHExecutor, _supplied_password_rejected


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


def _sudo_challenge_line(data: bytes | bytearray, prompt: bytes) -> bool:
    """Only a real sudo or sudo-rs prompt at the current line can unlock."""
    line = data.rstrip().rsplit(b"\n", 1)[-1]
    native = b"[sudo: " + prompt + b"]"
    return line in (prompt, native) or line.startswith(native + b" ")


async def _ready(reader: Any, token: str, *, sudo_prompt: str | None = None,
                 readiness: Any = None, alias: str | None = None) -> None:
    marker = b"\x1e" + token.encode("ascii") + b"\x1e\n"
    prompt = sudo_prompt.encode("ascii") if sudo_prompt else None
    pending = bytearray()
    while len(pending) < 4096:
        item = await reader.read(1)
        if not item:
            raise RelayFailure("transport_error")
        pending.extend(item)
        if pending.endswith(marker):
            return
        # A rejected sudo password may request a second attempt without
        # closing the binary destination stdin. Do not wait until timeout.
        if prompt is not None and (
            _sudo_challenge_line(pending, prompt)
            or _supplied_password_rejected(bytes(pending))
        ):
            if readiness is not None and alias is not None:
                readiness.suspend(alias)
            raise RelayFailure("permission_denied")
    raise RelayFailure("invalid_response")


async def _receiver_rejection(
    proc: SSHChannelProcess, *, after_commit: bool, receipt: bytes = b"",
) -> None:
    """Trust only an authenticated, fully closed remote helper exit status.

    Exit 73/75 are defined by our fixed receiver and precede publication.
    EOF or an unconfirmed SSH exit cannot establish that no write occurred.
    """
    status = await proc.wait()
    if (proc.channel_complete and not receipt and status in (73, 75)
            and not await proc.stdout.read(1)):
        raise RelayFailure("already_exists" if status == 73 else "precondition_failed")
    raise RelayFailure("transport_error", uncertain=after_commit)


async def _receipt(reader: Any) -> bytes:
    """Read a complete, bounded commit confirmation, never one SSH packet."""
    result = bytearray()
    while True:
        part = await reader.read(1025 - len(result))
        if not part:
            return bytes(result)
        result.extend(part)
        if len(result) > 1024:
            raise RelayFailure("invalid_response", uncertain=True)


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
        self._pending_roots: dict[str, tuple[RootAccess | None, RootAccess | None]] = {}
        self._stopping = False
        self._locks: weakref.WeakValueDictionary[tuple[str, str], asyncio.Lock] = (
            weakref.WeakValueDictionary()
        )

    async def transfer(self, actor: str, req: TransferFileRequest,
                       *, precreated_id: str, roots: tuple[RootAccess | None,
                                                          RootAccess | None]) -> dict[str, Any]:
        if self._stopping:
            raise RuntimeError("Transfer service is shutting down")
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
        self._pending_roots[history_id] = roots
        for root in roots:
            if root is not None:
                root.delegate()
        def complete(_task: asyncio.Task[dict[str, Any]]) -> None:
            self._active.pop(history_id, None)
            pending = self._pending_roots.pop(history_id, ())
            if _task.cancelled():
                # Cancelled before _run ever started: no finally block ran.
                # These updates are idempotent for an already-settled row.
                self.audit.finish(identifier, "unknown", error_code="interrupted")
                for access in pending:
                    if access is not None:
                        access.finish()
        task.add_done_callback(complete)
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

    async def shutdown(self) -> None:
        """Cancel active relays and complete any not-yet-started audit rows."""
        self._stopping = True
        pending = list(self._active.items())
        for _, task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*(task for _, task in pending), return_exceptions=True)
        for job_id, _ in pending:
            # _run finally closes channels when it starts; if cancellation
            # happened before its first step, finish the durable row here.
            self.audit.finish(job_id[5:], "unknown", error_code="interrupted")
            for root in self._pending_roots.pop(job_id, ()):
                if root is not None:
                    root.finish()
            self._active.pop(job_id, None)

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
        last_progress = 0.0
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
                            readiness = getattr(self.executor, "readiness", None)
                            if (alias in self.executor._sealed_sudo
                                    and readiness is not None
                                    and readiness.password_suspended(alias)):
                                raise SSHDenied("Privileged password suspended")
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
                    await _ready(
                        src.stderr, "SRC-" + nonce,
                        sudo_prompt=(_sudo_prompt("SRC-" + nonce)
                                     if req.source_privileged else None),
                        readiness=getattr(self.executor, "readiness", None),
                        alias=req.source_server,
                    )
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
                    try:
                        await _ready(
                            dest.stderr, "DEST-" + nonce,
                            sudo_prompt=(_sudo_prompt("DEST-" + nonce)
                                         if req.dest_privileged else None),
                            readiness=getattr(self.executor, "readiness", None),
                            alias=req.dest_server,
                        )
                    except RelayFailure as exc:
                        if exc.code != "transport_error":
                            raise
                        # EOF before the receiver's ready marker may be its
                        # deliberate, clean refusal of an existing target.
                        await _receiver_rejection(dest, after_commit=False)
                    if dest.stdin is None:
                        raise RelayFailure("transport_error", uncertain=True)
                    local = hashlib.sha256()
                    while moved < total:
                        block = await _exact(src.stdout, min(chunk, total - moved))
                        dest.stdin.write(block)
                        await dest.stdin.drain()
                        local.update(block)
                        moved += len(block)
                        now = asyncio.get_running_loop().time()
                        if now - last_progress >= 1.0:
                            self.audit.progress(identifier, moved, total)
                            last_progress = now
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
                    line = await _receipt(dest.stdout)
                    if not await _finish_channel(dest):
                        # Also handle a concurrent create collision at the
                        # final link(), but never infer failure safety from
                        # an incomplete channel or a partial receipt.
                        await _receiver_rejection(dest, after_commit=True, receipt=line)
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
            # The source is read-only and may be blocked writing to an SSH
            # window we stopped draining. Abort it instead of waiting on EOF.
            if src is not None:
                src.connection.abort()
            # Confirmed destination nonzero exit proves stage cleanup;
            # source termination itself is not a destination write hazard.
            status = "cancelled" if confirmed_cleanup else "unknown"
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
        readiness = getattr(self.executor, "readiness", None)
        if (alias in self.executor._sealed_sudo
                and readiness is not None and readiness.password_suspended(alias)):
            raise SSHDenied("Privileged password suspended")
        received = bytearray()
        for _ in range(4096):
            block = await proc.stderr.read(1)
            if not block:
                raise SSHDenied("Privileged sudo challenge unavailable")
            received.extend(block)
            if received.endswith(ready_marker):
                if readiness is not None:
                    readiness.mark_passwordless_root(alias)
                raise SSHDenied("Privileged sudo prompt was bypassed")
            if _sudo_challenge_line(received, prompt):
                break
        else:
            raise SSHDenied("Privileged sudo challenge invalid")
        if (alias in self.executor._sealed_sudo
                and readiness is not None and readiness.password_suspended(alias)):
            raise SSHDenied("Privileged password suspended")
        proc.stdin.write(password.encode("utf-8") + b"\n")
        await proc.stdin.drain()
        password = None
        if close:
            proc.stdin.close()
