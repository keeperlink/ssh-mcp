"""Unprivileged payload-safe SSH transport and lazy remote helper bootstrap.

No ordinary command/job API, database or logger receives operation payloads.
Normal requests verify and execute in one SSH invocation. A missing or stale
version requests installation before the operation starts, then retries once.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from dataclasses import dataclass
from typing import Any

from . import config
from .contracts import ExecuteCommandRequest
from .ssh_executor import SSHExecutor, HostSpec, _ssh_argv, OutputLimitExceeded

_MAX_STDOUT = 262144
_MAX_STDIN = 1024 * 1024


async def _bounded_bytes(reader: asyncio.StreamReader, cap: int) -> bytes:
    """Capture raw bytes without the lossy UTF-8 decoding of command output."""
    buffer = bytearray()
    while chunk := await reader.read(4096):
        if len(buffer) + len(chunk) > cap:
            raise OutputLimitExceeded
        buffer.extend(chunk)
    return bytes(buffer)


class FileTransportError(RuntimeError):
    def __init__(self, code: str, message: str, *, uncertain: bool = False):
        super().__init__(message)
        self.code = code
        self.uncertain = uncertain


@dataclass(frozen=True)
class RemoteResult:
    stdout: bytes
    stderr: bytes
    exit_code: int


# No user input, file content or caller-supplied path is interpolated here.
# Each remote invocation opens every cache component relative to a trusted
# directory FD, preventing symlink traversal and rename races.
_CACHE = """
import hashlib,os,pathlib,stat
_VERSION=__VERSION__
_DIGEST=__DIGEST__
_FLAGS=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC

def _trusted(fd,private=False,directory=True):
    info=os.fstat(fd)
    mode=info.st_mode
    if info.st_uid!=os.geteuid() or (mode & (0o077 if private else 0o022)):
        raise PermissionError("Untrusted helper cache permissions or ownership")
    if directory and not stat.S_ISDIR(mode):
        raise PermissionError("Helper cache component is not a directory")
    if not directory and (not stat.S_ISREG(mode) or info.st_nlink!=1):
        raise PermissionError("Untrusted helper file or hard link")

def _directory(create=False):
    parent=os.open(str(pathlib.Path.home()),_FLAGS)
    try:
        _trusted(parent)
        # Dedicated private namespace avoids shared .cache/ssh-mcp
        # directories created by unrelated tooling with 0775 permissions.
        for name in ('.ssh-mcp-helper','helpers',_VERSION):
            private=True
            if create:
                try: os.mkdir(name,0o700,dir_fd=parent)
                except FileExistsError: pass
            current=os.open(name,_FLAGS,dir_fd=parent)
            try: _trusted(current,private=private)
            except BaseException:
                os.close(current)
                raise
            os.close(parent)
            parent=current
        return parent
    except BaseException:
        os.close(parent)
        raise

def _read(d):
    fd=os.open('helper.py',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=d)
    try:
        _trusted(fd,private=True,directory=False)
        with os.fdopen(fd,'rb',closefd=False) as f:
            content=f.read(1048577)
        if len(content)>1048576: raise ValueError("Helper too large")
        return content
    finally: os.close(fd)
"""
_INSTALL = _CACHE + """
import fcntl,json,secrets,sys
source=sys.stdin.buffer.read(1048577)
if len(source)>1048576 or hashlib.sha256(source).hexdigest()!=_DIGEST:
    raise SystemExit("Bundled helper checksum mismatch")
d=_directory(create=True)
try:
    lock=os.open('.bootstrap.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,
                 0o600,dir_fd=d)
    try:
        _trusted(lock,private=True,directory=False)
        fcntl.flock(lock,fcntl.LOCK_EX)
        try: existing=_read(d)
        except FileNotFoundError: existing=None
        if existing is None or hashlib.sha256(existing).hexdigest()!=_DIGEST:
            temp='.helper-'+secrets.token_hex(12)
            try:
                fd=os.open(temp,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC,
                           0o600,dir_fd=d)
                try:
                    with os.fdopen(fd,'wb',closefd=False) as f:
                        f.write(source);f.flush();os.fsync(f.fileno())
                finally: os.close(fd)
                # Do not overwrite an existing unsafe file or link.
                try: existing_stat=os.stat('helper.py',dir_fd=d,follow_symlinks=False)
                except FileNotFoundError: existing_stat=None
                if existing_stat is not None and (
                    not stat.S_ISREG(existing_stat.st_mode)
                    or existing_stat.st_uid!=os.geteuid()
                    or existing_stat.st_mode & 0o077 or existing_stat.st_nlink!=1):
                    raise PermissionError("Unsafe existing cached helper")
                os.replace(temp,'helper.py',src_dir_fd=d,dst_dir_fd=d)
            finally:
                try: os.unlink(temp,dir_fd=d)
                except FileNotFoundError: pass
        if hashlib.sha256(_read(d)).hexdigest()!=_DIGEST:
            raise RuntimeError("Installed helper verification failed")
    finally: os.close(lock)
finally: os.close(d)
print(json.dumps({'verified':True}))
"""
_RUN = _CACHE + """
# VERIFY_AND_RUN_FASTPATH: this invocation does not run any operation until
# the trusted cache components and exact helper digest have passed.
import json

def _signal(kind,code):
    print(json.dumps({'bootstrap':kind},separators=(',',':')))
    raise SystemExit(code)

try:
    try:
        d=_directory()
    except FileNotFoundError:
        _signal('install_required',75)
    try:
        try: content=_read(d)
        except FileNotFoundError: content=None
    finally: os.close(d)
except (OSError,ValueError):
    # Unsafe ownership/mode, symlink, hard link, oversized helper, etc.
    # These are *not* repair/install events and must fail closed.
    _signal('verification_failed',76)
if content is None or hashlib.sha256(content).hexdigest()!=_DIGEST:
    _signal('install_required',75)
name=str(pathlib.Path.home()/'.ssh-mcp-helper/helpers'/_VERSION/'helper.py')
# Execute the *verified bytes*, never reopen the pathname after checking.
exec(compile(content,name,'exec'),{'__name__':'__main__','__file__':name})
"""



class FileTransport:
    def __init__(self, executor: SSHExecutor):
        self.executor = executor
        self._host_locks: dict[str, asyncio.Lock] = {}

    @staticmethod
    def helper_source() -> tuple[bytes, str, str]:
        source = Path(__file__).with_name("file_helper.py").read_bytes()
        sha = hashlib.sha256(source).hexdigest()
        return source, sha[:16], sha

    @staticmethod
    def _script(template: str, version: str, digest: str) -> str:
        return template.replace("__VERSION__", repr(version)).replace("__DIGEST__", repr(digest))

    async def _ssh(self, host: HostSpec, argv: list[str], payload: bytes,
                   *, timeout: int = config.SSH_DEFAULT_TIMEOUT_SECONDS) -> RemoteResult:
        if len(payload) > _MAX_STDIN:
            raise FileTransportError("payload_limit", "File message exceeds the transport limit")
        request = ExecuteCommandRequest(
            server=host.alias, argv=argv, reason="Private file helper transport", timeout_seconds=timeout
        )
        command = _ssh_argv(host, request, allow_stdin=True)
        try:
            async with self.executor._global, self.executor._semaphores[host.alias]:
                process = await asyncio.create_subprocess_exec(
                    *command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdin, stdout_pipe, stderr_pipe = process.stdin, process.stdout, process.stderr
                assert stdin is not None and stdout_pipe is not None and stderr_pipe is not None

                async def send() -> None:
                    try:
                        stdin.write(payload)
                        await stdin.drain()
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    finally:
                        stdin.close()

                work = [
                    asyncio.create_task(send()),
                    asyncio.create_task(_bounded_bytes(stdout_pipe, _MAX_STDOUT)),
                    asyncio.create_task(_bounded_bytes(stderr_pipe, 4096)),
                    asyncio.create_task(process.wait()),
                ]
                try:
                    _sent, stdout, stderr, code = await asyncio.wait_for(
                        asyncio.gather(*work), timeout=timeout
                    )
                except BaseException as exc:
                    if process.returncode is None:
                        process.kill()
                    await process.wait()
                    for task in work:
                        if not task.done():
                            task.cancel()
                    await asyncio.gather(*work, return_exceptions=True)
                    if isinstance(exc, TimeoutError):
                        raise FileTransportError("timeout", "Remote file operation timed out",
                                                 uncertain=True) from None
                    if isinstance(exc, OutputLimitExceeded):
                        raise FileTransportError("output_limit", "File response exceeds limit",
                                                 uncertain=True) from None
                    raise
        except FileTransportError:
            raise
        except OSError as exc:
            raise FileTransportError("transport_error", "SSH process could not start", uncertain=True) from exc
        assert isinstance(stdout, bytes) and isinstance(stderr, bytes) and isinstance(code, int)
        return RemoteResult(stdout, stderr, code)

    async def _install(self, host: HostSpec, source: bytes,
                       version: str, digest: str, *,
                       timeout: int = config.SSH_DEFAULT_TIMEOUT_SECONDS) -> None:
        installed = await self._ssh(
            host, ["python3", "-c", self._script(_INSTALL, version, digest)], source,
            timeout=timeout
        )
        if installed.exit_code == 127:
            raise FileTransportError("missing_python", "Python 3 is required on the SSH host")
        if installed.exit_code != 0:
            raise FileTransportError("bootstrap_failed", "Could not install remote helper")
        try:
            if json.loads(installed.stdout)["verified"] is not True:
                raise ValueError("Not verified")
        except (UnicodeError, ValueError, KeyError, TypeError):
            raise FileTransportError("invalid_response", "Invalid helper install response") from None

    async def execute(self, principal: str, server: str, operation: str,
                      data: dict[str, Any], *,
                      timeout: int = config.SSH_DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
        host = self.executor.authorized_host(principal, server)
        payload = json.dumps({**data, "protocol": 1, "operation": operation, "server": host.alias},
                             separators=(",", ":"), ensure_ascii=False).encode()
        source, version, digest = self.helper_source()
        runner = self._script(_RUN, version, digest)
        install_required = b'{"bootstrap":"install_required"}\n'
        verify_failed = b'{"bootstrap":"verification_failed"}\n'

        # Fast path: verify SHA/ownership and execute from verified bytes in
        # the *same* SSH process. A distinct, exact pre-execution response is
        # the only permission to install and retry an operation.
        result = await self._ssh(host, ["python3", "-c", runner], payload, timeout=timeout)
        if result.exit_code == 75 and result.stdout == install_required and not result.stderr:
            # Multiple first-use operations may race. The remote installer
            # additionally holds an advisory flock and rechecks the digest.
            lock = self._host_locks.setdefault(host.alias, asyncio.Lock())
            async with lock:
                await self._install(host, source, version, digest, timeout=timeout)
            result = await self._ssh(
                host, ["python3", "-c", runner], payload, timeout=timeout
            )
            # Never retry a second time: a non-successful retry is final,
            # including a malicious/ambiguous operation response.
        if result.exit_code == 127:
            raise FileTransportError("missing_python", "Python 3 is required on the SSH host")
        if result.exit_code == 76 and result.stdout == verify_failed and not result.stderr:
            raise FileTransportError("bootstrap_check_failed", "Could not verify remote helper")
        if result.exit_code != 0:
            raise FileTransportError("transport_error", "Remote helper failed",
                                     uncertain=True)
        try:
            decoded = json.loads(result.stdout)
        except (UnicodeError, ValueError):
            raise FileTransportError("invalid_response", "Invalid remote helper response",
                                     uncertain=True) from None
        if not isinstance(decoded, dict) or not isinstance(decoded.get("ok"), bool):
            raise FileTransportError("invalid_response", "Invalid remote result", uncertain=True)
        return decoded
