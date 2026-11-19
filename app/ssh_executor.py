"""Live, fail-closed OpenSSH executor with signed host inventory and key pins."""
from __future__ import annotations

import asyncio
import asyncssh
import ipaddress
import json
import os
import re
import secrets
import shlex
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .contracts import ExecuteCommandRequest
from . import config
from .ssh_channel import ChannelConnectionError, SSHChannelProcess, open_command
from .readiness import ProbeKind, ProbeResult, ReadinessMonitor, ReadinessSettings

ResultStatus = Literal["succeeded", "command_error", "transport_error", "timed_out", "output_limit"]
OutputCallback = Callable[[str, bytes], Awaitable[None]]
AdmissionCallback = Callable[[], bool]
_LABEL = r"^[a-z0-9][a-z0-9-]{0,62}$"
_ADDRESS = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9][A-Za-z0-9.-]*$")
_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class SSHDenied(ValueError):
    """Rejected before any SSH subprocess can start."""


class ReadinessDenied(SSHDenied):
    """The authorized host has no fresh matching readiness."""


class OutputLimitExceeded(Exception):
    """Bounded output exceeded the configured cap."""


class ByteReader(Protocol):
    async def read(self, n: int = -1) -> bytes: ...


class ByteWriter(Protocol):
    def write(self, block: bytes) -> None: ...
    async def drain(self) -> None: ...
    def close(self) -> None: ...
    async def wait_closed(self) -> None: ...


async def _close_native_connection(process: Any) -> None:
    """No-op for synthetic processes; close each real SSH channel's connection."""
    closer = getattr(process, "close_connection", None)
    if closer is not None:
        await closer()


def _remote_exit(process: Any, ssh_code: int | None) -> int | None:
    """Require protocol-confirmed 255; preserve older synthetic test fixtures."""
    confirmed = getattr(process, "exit_status", None)
    if type(confirmed) is int and confirmed >= 0:
        return confirmed
    if not hasattr(process, "exit_status") and type(ssh_code) is int and 0 <= ssh_code <= 254:
        return ssh_code
    return None


class HostSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    alias: str = Field(pattern=_LABEL)
    address: str
    port: int = Field(ge=1, le=65535, strict=True)
    username: str
    identity_file: Path
    known_hosts_file: Path
    principals: list[str] = Field(min_length=1, max_length=16)
    # Signed host classification only; authorization remains principal + OAuth scope.
    environment: Literal["non-production", "production"]
    access: Literal["restricted", "always-granted"]
    privileged_access: Literal["none", "restricted", "always-granted"] = "none"
    max_parallel: int = Field(default=1, ge=1, le=32, strict=True)

    @field_validator("address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        if not _ADDRESS.fullmatch(value) or value.startswith("-") or ".." in value:
            raise ValueError("SSH target must be a literal hostname or IPv4 address")
        try:
            ipaddress.ip_address(value)
        except ValueError:
            labels = value.split(".")
            if any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels):
                raise ValueError("Invalid DNS hostname")
        return value

    @field_validator("username")
    @classmethod
    def validate_user(cls, value: str) -> str:
        if not _USER.fullmatch(value):
            raise ValueError("Invalid SSH user")
        return value

    @field_validator("principals")
    @classmethod
    def validate_principals(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)) or any(not re.fullmatch(_LABEL, name) for name in values):
            raise ValueError("Principal IDs must be explicit, unique aliases")
        return values


class InventorySpec(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: Literal[1]
    hosts: list[HostSpec] = Field(min_length=1, max_length=200)


@dataclass(frozen=True, slots=True)
class SSHResult:
    server: str
    status: ResultStatus
    exit_code: int | None
    stdout: str
    stderr: str
    elapsed_seconds: float
    exit_accepted: bool | None = None
    effective_cwd: str | None = None
    # Requested root identity is not evidence that the root wrapper started.
    root_started: bool | None = None
    failure_kind: str | None = None
    password_rejected: bool = False


async def _spawn_ssh_command(
    *ssh_argv: str, host: HostSpec,
    stdin: int, stdout: int, stderr: int,
) -> SSHChannelProcess:
    """Open a native SSH channel with the same fixed quoting as OpenSSH.

    Only the final, already shell-escaped command argument is passed to the
    SSH protocol. The other arguments document the unchanged OpenSSH policy
    and are still used by the independent file-transfer transport.
    """
    if not ssh_argv or stdout != asyncio.subprocess.PIPE or stderr != asyncio.subprocess.PIPE:
        raise ValueError("Unsupported SSH channel invocation")
    if stdin not in (asyncio.subprocess.PIPE, asyncio.subprocess.DEVNULL):
        raise ValueError("Unsupported SSH command stdin")
    return await open_command(host, ssh_argv[-1], allow_stdin=stdin == asyncio.subprocess.PIPE)


def _check_file(path: Path, *, private: bool) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise SSHDenied("SSH configuration paths must be absolute, regular, non-symlink files")
    try:
        details = path.stat()
    except OSError as exc:
        raise SSHDenied("Required SSH configuration file is inaccessible") from exc
    if not stat.S_ISREG(details.st_mode):
        raise SSHDenied("SSH configuration paths must be regular files")
    if private and (details.st_uid != os.geteuid() or details.st_mode & 0o077):
        raise SSHDenied("SSH private key must belong to the service user and have mode 0600")
    if not private and (details.st_uid not in (0, os.geteuid()) or details.st_mode & 0o022):
        raise SSHDenied("SSH known_hosts/inventory must not be writable by group or others")
    if not os.access(path, os.R_OK):
        raise SSHDenied("Required SSH configuration file is not readable")


def load_inventory(path: Path, approved_aliases: frozenset[str]) -> dict[str, HostSpec]:
    """Load an owned, non-world-writable inventory; require a separate alias approval gate."""
    if not approved_aliases or not all(re.fullmatch(_LABEL, item) for item in approved_aliases):
        raise SSHDenied("A nonempty explicit approved-alias set is required")
    _check_file(path, private=False)
    try:
        spec = InventorySpec.model_validate_json(path.read_text())
    except (ValueError, OSError) as exc:
        raise SSHDenied("Invalid SSH inventory") from exc
    mapping: dict[str, HostSpec] = {}
    for host in spec.hosts:
        if host.alias in mapping:
            raise SSHDenied("Duplicate SSH alias")
        if host.alias not in approved_aliases:
            raise SSHDenied("Inventory includes an alias outside explicit approval")
        mapping[host.alias] = host
    return mapping


def _effective_argv(request: ExecuteCommandRequest) -> list[str]:
    """Enable opt-in strict Bash without changing positional parameters or other argv."""
    argv = list(request.argv)
    if (request.strict_bash and argv[0] in {"bash", "/bin/bash", "/usr/bin/bash"}
            and len(argv) >= 3 and argv[1] in {"-c", "-lc"}):
        argv[2] = "set -euo pipefail\n" + argv[2]
    return argv


# This fixed script is passed as a distinct argv value. Never concatenate a
# caller's script into it. sudo -H sets root HOME; env -i prevents all other
# gateway/sudo environment entries from reaching the approved command.
_ROOT_WRAPPER = (
    'exec </dev/null\n'
    # The sudoers default Runas user is configurable; never claim root
    # unless this authenticated process really has effective UID 0.
    'if [ "$(/usr/bin/id -u)" != 0 ]; then exit 126; fi\n'
    # Delimiters are added INSIDE the authenticated root wrapper, never passed
    # in argv. sudoers denial text may quote our argv token but cannot produce
    # this exact framed marker by merely echoing the rejected command line.
    'printf "\\036%s\\036\\n" "$1" >&2\n'
    # stdout has its own boundary. Stderr and stdout are independent SSH
    # channels; a stderr marker cannot distinguish pre-root stdout prelude.
    'printf "\\036%s\\036\\n" "$1"\n'
    'shift\n'
    'exec /usr/bin/env -i "HOME=$HOME" USER=root LOGNAME=root '
    'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin "$@"'
)
_ROOT_MARKER_PREFIX = "SSH-MCP-ROOT-START:"
_ROOT_READY_PREFIX = "SSH-MCP-ROOT-READY:"
_ROOT_FAILED_PREFIX = "SSH-MCP-ROOT-SETUP-FAILED:"
_ROOT_DIAGNOSTIC_CAP = 4096


def _framed_root_marker(token: str) -> bytes:
    return b"\x1e" + token.encode("ascii") + b"\x1e\n"


# A single fixed root-side entrypoint prepares cwd, then execs the actual
# command. Explicit framed setup failure cannot be mistaken for a command
# exit code that the caller intentionally included in success_exit_codes.
_ROOT_EXEC = (
    "import os,sys\n"
    "token=sys.argv[1]\n"
    "def signal(kind):\n"
    " sys.stderr.buffer.write(b'\\x1e'+kind.encode('ascii')+"
    "token.encode('ascii')+b'\\x1e\\n')\n"
    " sys.stderr.buffer.flush()\n"
    "def failed(code):\n"
    f" signal('{_ROOT_FAILED_PREFIX}')\n"
    " sys.exit(code)\n"
    "if sys.argv[2]:\n"
    " try:\n"
    "  fd=os.open(sys.argv[2],os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC)\n"
    "  os.fchdir(fd)\n"
    " except OSError: failed(126)\n"
    f"signal('{_ROOT_READY_PREFIX}')\n"
    "try:\n"
    " os.execvp(sys.argv[3],sys.argv[3:])\n"
    "except FileNotFoundError: failed(127)\n"
    "except OSError: failed(126)\n"
)


def _sudo_argv(command: list[str], marker: str, *, no_password: bool = False,
               prompt: str = "") -> list[str]:
    """No caller input is evaluated by the fixed wrapper's shell script."""
    return ["/usr/bin/sudo", "-n" if no_password else "-S", "-k", "-p", prompt, "-H", "-u", "root", "--", "/bin/sh", "-c",
            _ROOT_WRAPPER, "ssh-mcp-root", marker, *command]


def _usable_sudo_password(password: Any) -> bool:
    if type(password) is not str or any(char in password for char in ("\n", "\r", "\x00")):
        return False
    try:
        return 0 < len(password.encode("utf-8")) <= 4096
    except UnicodeEncodeError:
        return False


def _supplied_password_rejected(diagnostic: bytes) -> bool:
    message = diagnostic.decode("utf-8", errors="replace").lower()
    return (any(word in message for word in (
        "incorrect password", "authentication failure", "sorry, try again",
        # sudo-rs PAM retry warning (LC_ALL=C).
        "authentication failed, try again.",
    )) or re.search(r"\bmaximum [1-9][0-9]* incorrect authentication attempts\b", message)
        is not None)


def _no_password_failure_kind(diagnostic: bytes) -> str:
    message = diagnostic.decode("utf-8", errors="replace").lower()
    if "a password is required" in message:
        return "sudo_password_required"
    if any(word in message for word in (
        "not in the sudoers", "not allowed to execute", "may not run sudo",
        "not allowed to run sudo",
        "command not allowed", "not permitted to run",
    )):
        return "sudo_authorization"
    return "root_unconfirmed"


def _sudo_failure_kind(diagnostic: bytes) -> str:
    """Do not disclose sudo diagnostics; classify only unambiguous patterns."""
    message = diagnostic.decode("utf-8", errors="replace").lower()
    if any(word in message for word in (
        "not in the sudoers", "not allowed to execute", "may not run sudo",
        "not allowed to run sudo", "command not allowed", "not permitted to run", "policy plugin",
    )):
        return "sudo_authorization"
    if _supplied_password_rejected(diagnostic) or any(word in message for word in (
        "a password is required", "no password was provided",
    )):
        return "sudo_authentication"
    if "sudo:" in message:
        return "sudo_rejected"
    # The marker can be missing for reasons other than sudo rejection;
    # absent a recognizable sudo diagnostic, execution is unconfirmed.
    return "root_unconfirmed"


async def _send_sudo_password(writer: ByteWriter, password: str,
                              permitted: Callable[[], bool] | None = None,
                              on_sent: Callable[[], None] | None = None) -> None:
    """Write a single line, close stdin; never hand it to the root command."""
    try:
        if permitted is not None and not permitted():
            return
        writer.write(password.encode("utf-8") + b"\n")
        if on_sent is not None:
            on_sent()
        await writer.drain()
    except (BrokenPipeError, ConnectionResetError):
        # SSH may have already failed; process.wait determines transport status.
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (BrokenPipeError, ConnectionResetError):
            pass


async def _read_root_stderr(
    reader: ByteReader, marker: bytes, cap: int,
    on_output: OutputCallback | None, shared_budget: list[int],
    confirmed: list[bool], diagnostic: bytearray, ready_event: asyncio.Event,
    ready: list[bool], setup_failed: list[bool],
    ready_marker: bytes, failed_marker: bytes, captured: bytearray,
    on_confirmed: Callable[[], None] | None = None,
    on_challenge: Callable[[bytes], None] | None = None,
) -> str:
    """Stream post-readiness stderr without leaking split control frames."""
    pending = bytearray()

    async def forward(block: bytes) -> None:
        available = min(cap - len(captured), cap - shared_budget[0])
        data = block[:max(0, available)]
        if data:
            captured.extend(data)
            shared_budget[0] += len(data)
            if on_output is not None:
                await on_output("stderr", data)
        if len(block) > available:
            raise OutputLimitExceeded

    while block := await reader.read(4096):
        if setup_failed[0]:
            continue  # Never disclose root setup diagnostics.
        if not confirmed[0]:
            pending.extend(block)
            where = pending.find(marker)
            if where < 0:
                if len(pending) > _ROOT_DIAGNOSTIC_CAP:
                    raise OutputLimitExceeded
                if on_challenge is not None:
                    on_challenge(bytes(pending))
                continue
            diagnostic.extend(pending[:where][: _ROOT_DIAGNOSTIC_CAP])
            block = bytes(pending[where + len(marker):])
            pending.clear()
            confirmed[0] = True
            if on_confirmed is not None:
                on_confirmed()
        pending.extend(block)
        if not ready[0]:
            # The fixed root helper emits nothing user-visible before READY.
            # Bound any unexpected pre-ready diagnostic independently.
            if len(pending) > _ROOT_DIAGNOSTIC_CAP + len(ready_marker) + len(failed_marker):
                raise OutputLimitExceeded
            ready_at = pending.find(ready_marker)
            failed_at = pending.find(failed_marker)
            if failed_at >= 0 and (ready_at < 0 or failed_at < ready_at):
                setup_failed[0] = True
                ready_event.set()
                pending.clear()
                continue
            if ready_at < 0:
                continue
            block = bytes(pending[ready_at + len(ready_marker):])
            pending.clear()
            pending.extend(block)
            ready[0] = True
            ready_event.set()
        failed_at = pending.find(failed_marker)
        if failed_at >= 0:
            # A root-side execvp failure may follow the READY frame. Do not
            # mistake it for a caller-accepted exit 126/127 or emit the frame.
            setup_failed[0] = True
            pending.clear()
            continue
        # Hold only a suffix which *could* start a split failure frame.
        # Normal short diagnostics therefore stream immediately, including
        # when a long-running command later times out.
        prefix = 0
        for size in range(min(len(pending), len(failed_marker) - 1), 0, -1):
            if pending[-size:] == failed_marker[:size]:
                prefix = size
                break
        flush_bytes = len(pending) - prefix
        if flush_bytes:
            await forward(bytes(pending[:flush_bytes]))
            del pending[:flush_bytes]
    if not confirmed[0]:
        diagnostic.extend(pending[: _ROOT_DIAGNOSTIC_CAP])
    # Unblock stdout readers also on sudo refusal or interrupted setup.
    ready_event.set()
    # A trailing fragment of an internal failure frame is not user output.
    return (captured.decode("utf-8", errors="replace")
            if ready[0] and not setup_failed[0] else "")


async def _read_root_stdout(
    reader: ByteReader, marker: bytes, cap: int,
    on_output: OutputCallback | None, shared_budget: list[int],
    ready: list[bool], ready_event: asyncio.Event, marker_seen: list[bool],
    captured: bytearray,
    on_confirmed: Callable[[], None] | None = None,
) -> str:
    """Discard independent SSH startup stdout; publish only framed root output."""
    output = captured
    pending = bytearray()
    forwarded = 0

    async def forward(block: bytes) -> None:
        nonlocal forwarded
        available = min(cap - len(output), cap - shared_budget[0])
        data = block[:max(0, available)]
        if data:
            output.extend(data)
            shared_budget[0] += len(data)
        if len(block) > available:
            raise OutputLimitExceeded
        if ready_event.is_set() and ready[0] and on_output is not None:
            await on_output("stdout", bytes(output[forwarded:]))
            forwarded = len(output)

    while block := await reader.read(4096):
        if not marker_seen[0]:
            pending.extend(block)
            where = pending.find(marker)
            if where < 0:
                if len(pending) > _ROOT_DIAGNOSTIC_CAP:
                    raise OutputLimitExceeded
                continue
            block = bytes(pending[where + len(marker):])
            pending.clear()
            marker_seen[0] = True
            if on_confirmed is not None:
                on_confirmed()
        if block:
            await forward(block)
    await ready_event.wait()
    if ready[0] and marker_seen[0]:
        if on_output is not None and forwarded < len(output):
            await on_output("stdout", bytes(output[forwarded:]))
        return output.decode("utf-8", errors="replace")
    return ""


async def _read_cwd_stderr(
    reader: ByteReader, ready_marker: bytes, failed_marker: bytes, cap: int,
    on_output: OutputCallback | None, shared_budget: list[int],
    ready: list[bool], failed: list[bool], captured: bytearray,
) -> str:
    """Hide framed CWD setup control bytes before streaming command stderr."""
    pending = bytearray()
    while block := await reader.read(4096):
        if failed[0]:
            continue
        if not ready[0]:
            pending.extend(block)
            ready_at = pending.find(ready_marker)
            failed_at = pending.find(failed_marker)
            if failed_at >= 0 and (ready_at < 0 or failed_at < ready_at):
                failed[0] = True
                pending.clear()
                continue
            if ready_at < 0:
                if len(pending) > _ROOT_DIAGNOSTIC_CAP:
                    raise OutputLimitExceeded
                continue
            block = bytes(pending[ready_at + len(ready_marker):])
            pending.clear()
            ready[0] = True
        if not block:
            continue
        available = min(cap - len(captured), cap - shared_budget[0])
        data = block[:max(0, available)]
        if data:
            captured.extend(data)
            shared_budget[0] += len(data)
            if on_output is not None:
                await on_output("stderr", data)
        if len(block) > available:
            raise OutputLimitExceeded
    return captured.decode("utf-8", errors="replace") if ready[0] and not failed[0] else ""


# Both helpers execute on the authorized SSH host as its existing unprivileged
# account. Never send request cwd through a shell 'cd', and never use a remote
# login shell's env/cwd for validation. An O_PATH fd pins a directory's identity;
# the actual invocation refuses to run when it has been swapped since preflight.
_CWD_PREFLIGHT = (
    "import json,os,sys\n"
    "p=sys.argv[1]\n"
    "fd=os.open(p,os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC)\n"
    "s=os.fstat(fd)\n"
    "if not os.access(p,os.X_OK): sys.exit(126)\n"
    "canonical=os.path.realpath('/proc/self/fd/'+str(fd))\n"
    "if not canonical.startswith('/') or not os.path.isdir(canonical): sys.exit(126)\n"
    "print(json.dumps({'path':canonical,'dev':s.st_dev,'ino':s.st_ino}))\n"
)
_CWD_READY_PREFIX = "SSH-MCP-CWD-READY:"
_CWD_FAILED_PREFIX = "SSH-MCP-CWD-FAILED:"
_CWD_EXEC = (
    "import os,sys\n"
    "nonce=sys.argv[1]\n"
    "def signal(kind):\n"
    " sys.stderr.buffer.write(b'\\x1e'+kind.encode('ascii')+nonce.encode('ascii')+b'\\x1e\\n')\n"
    " sys.stderr.buffer.flush()\n"
    "def fail():\n"
    f" signal('{_CWD_FAILED_PREFIX}')\n"
    " sys.exit(255)\n"
    "try:\n"
    " p=sys.argv[2]\n"
    " fd=os.open(p,os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC)\n"
    " s=os.fstat(fd)\n"
    " if (s.st_dev,s.st_ino)!=(int(sys.argv[3]),int(sys.argv[4])): fail()\n"
    " if os.path.realpath('/proc/self/fd/'+str(fd))!=p: fail()\n"
    " os.fchdir(fd)\n"
    "except (OSError,ValueError): fail()\n"
    f"signal('{_CWD_READY_PREFIX}')\n"
    "try:\n"
    " os.execvp(sys.argv[5],sys.argv[5:])\n"
    "except FileNotFoundError:\n"
    " print('Command not found',file=sys.stderr)\n"
    " sys.exit(127)\n"
    "except PermissionError:\n"
    " print('Command is not executable',file=sys.stderr)\n"
    " sys.exit(126)\n"
    "except OSError:\n"
    " print('Command could not execute',file=sys.stderr)\n"
    " sys.exit(126)\n"
)


def _ssh_argv(host: HostSpec, request: ExecuteCommandRequest, *,
              allow_stdin: bool = False, remote_argv: list[str] | None = None) -> list[str]:
    # -F /dev/null prevents ~/.ssh/config or system ssh_config ProxyCommand/
    # Match blocks from overriding the approved destination or identity.
    # shlex.join escapes each argument for OpenSSH's remote POSIX shell.
    return [
        "ssh", "-F", "/dev/null", "-T", *([] if allow_stdin else ["-n"]),
        "-p", str(host.port), "-i", str(host.identity_file),
        "-o", "BatchMode=yes",
        "-o", "NumberOfPasswordPrompts=0",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "PreferredAuthentications=publickey",
        "-o", "IdentitiesOnly=yes",
        "-o", "IdentityAgent=none",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UpdateHostKeys=no",
        "-o", f"UserKnownHostsFile={host.known_hosts_file}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "ProxyCommand=none",
        "-o", "ProxyJump=none",
        "-o", "ControlMaster=no",
        "-o", "ClearAllForwardings=yes",
        "-o", "ForwardAgent=no",
        "-o", "PermitLocalCommand=no",
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=2",
        "--", f"{host.username}@{host.address}",
        shlex.join(remote_argv if remote_argv is not None else _effective_argv(request)),
    ]


async def _bounded_read(
    reader: ByteReader,
    cap: int,
    stream: str = "stdout",
    on_output: OutputCallback | None = None,
    shared_budget: list[int] | None = None,
) -> str:
    buffer = bytearray()
    while chunk := await reader.read(4096):
        remaining = cap - len(buffer)
        available = remaining
        if shared_budget is not None:
            available = min(available, cap - shared_budget[0])
        kept = chunk[:max(0, available)]
        if kept:
            if shared_budget is not None:
                shared_budget[0] += len(kept)
            buffer.extend(kept)
            if on_output is not None:
                await on_output(stream, kept)
        if len(chunk) > available:
            raise OutputLimitExceeded
    return buffer.decode("utf-8", errors="replace")


async def _preflight_read(reader: ByteReader, cap: int) -> tuple[bytes, bool]:
    """Drain remote preflight output without retaining more than the fixed cap."""
    collected = bytearray()
    truncated = False
    while chunk := await reader.read(4096):
        remaining = cap - len(collected)
        collected.extend(chunk[:remaining])
        truncated |= len(chunk) > remaining
    return bytes(collected), truncated


class SSHExecutor:
    """Enforces approval, principal, pinning and resource limits before SSH."""

    def __init__(self, hosts: dict[str, HostSpec], *, enabled: bool,
                 output_bytes: int = config.SSH_OUTPUT_LIMIT_BYTES,
                 sudo_passwords: dict[str, Any] | None = None,
                 readiness_settings: ReadinessSettings | None = None):
        if not 1 <= output_bytes <= 1048576:
            raise ValueError("Output byte cap must be between 1 and 1048576")
        self._hosts = hosts
        self._enabled = enabled
        self._output_bytes = output_bytes
        # Read once at process startup. Invalid/missing entries affect ONLY
        # that host's privileged capability; all regular SSH stays usable.
        self._sudo_passwords = {
            alias: password for alias, password in (sudo_passwords or {}).items()
            if alias in hosts and _usable_sudo_password(password)
        }
        self._semaphores = {name: asyncio.Semaphore(host.max_parallel) for name, host in hosts.items()}
        self._global = asyncio.Semaphore(config.SSH_MAX_CONCURRENT)
        # Direct construction is the isolated transport-test seam. All service
        # executors loaded from configuration have a fail-closed monitor.
        self.readiness = (
            ReadinessMonitor(readiness_settings, {
                name: host.privileged_access != "none" for name, host in hosts.items()
            }, self._readiness_probe) if readiness_settings is not None else None
        )

    @classmethod
    def from_environment(cls) -> SSHExecutor:
        if os.getenv("SSH_EXECUTOR_ENABLED") != "true":
            raise SSHDenied("SSH execution is disabled")
        inventory = os.getenv("SSH_INVENTORY_FILE", "")
        aliases = frozenset(item.strip() for item in os.getenv("SSH_APPROVED_ALIASES", "").split(",") if item.strip())
        if not inventory:
            raise SSHDenied("SSH_INVENTORY_FILE is required")
        hosts = load_inventory(Path(inventory), aliases)
        # The existing protected managed secret file is the only credential
        # source. Never copy passwords into environment variables or argv.
        from . import runtime_files
        raw: dict[str, Any] = {}
        if runtime_files.SECRETS.exists():
            try:
                stored = runtime_files._json(runtime_files.SECRETS, 65536)
                value = stored.get("sudo_passwords", {})
                if type(value) is not dict:
                    raise ValueError("Invalid credential mapping")
                raw = value
            except (ValueError, OSError, UnicodeError):
                raise SSHDenied("Protected sudo secret configuration is invalid") from None
        return cls(hosts, enabled=True, sudo_passwords=raw,
                   readiness_settings=ReadinessSettings.from_environment())

    @staticmethod
    def _inventory_principal(principal: str) -> str:
        # OAuth client-specific audit actors are minted internally from
        # validated client IDs. They do not create extra signed SSH principals.
        base = config.MCP_OPERATOR_SUBJECT
        if principal == base or re.fullmatch(re.escape(base) + r"@[a-f0-9]{64}", principal):
            return base
        return principal

    def list_servers(self, principal: str) -> list[str]:
        if not self._enabled or not principal:
            return []
        return sorted(host.alias for host in self._hosts.values() if self._inventory_principal(principal) in host.principals)

    def require_ready(self, server: str, *, privileged: bool = False) -> None:
        if self.readiness is not None:
            denial = self.readiness.denial(server, privileged=privileged)
            if denial is not None:
                raise ReadinessDenied("Host readiness unavailable: " + denial)

    async def check_readiness_live(self, server: str, *, privileged: bool = False) -> None:
        if self.readiness is not None and not await self.readiness.check(
            server, privileged=privileged,
        ):
            raise ReadinessDenied("Host readiness live check failed")

    def discover_hosts(self, principal: str, history_hosts: list[str]) -> dict[str, dict[str, str | bool]]:
        result: dict[str, dict[str, str | bool]] = {}
        for alias in self.list_servers(principal):
            if self.readiness is not None:
                result[alias] = self.readiness.discovery(alias)
            else:
                # Transport-only constructor, not an environment-loaded service.
                result[alias] = {"status": "active", "sudo_ready":
                                 self._hosts[alias].privileged_access != "none"
                                 and alias in self._sudo_passwords}
        for alias in history_hosts:
            if alias not in self._hosts:
                result[alias] = {"status": "retired", "sudo_ready": False}
        return result

    async def _readiness_probe(self, alias: str, kind: ProbeKind) -> ProbeResult:
        host = self._hosts[alias]
        assert self.readiness is not None
        # Independent monitoring authorization is checked by the monitor;
        # additionally verify the same immutable key/pin files on every probe.
        try:
            _check_file(host.identity_file, private=True)
            _check_file(host.known_hosts_file, private=False)
        except SSHDenied:
            return ProbeResult(False, "ssh_configuration")
        password_probe = kind in {"sudo", "sudo_challenge"}
        password = self._sudo_passwords.get(alias) if password_probe else None
        if password_probe and password is None:
            return ProbeResult(False, "sudo_credentials_missing")
        request = ExecuteCommandRequest(
            server=alias, argv=["/usr/bin/id", "-un" if kind == "identity" else "-u"],
            timeout_seconds=min(self.readiness.settings.timeout_seconds, config.SSH_MAX_TIMEOUT_SECONDS),
            reason="Fixed host readiness probe",
        )
        generation = self.readiness.password_generation(alias)
        monitor = self.readiness

        def password_permitted() -> bool:
            return (monitor.password_generation(alias) == generation
                    and monitor.password_probe_permitted(alias))

        async with self._global, self._semaphores[alias]:
            # A real command may have rejected a password while capacity was
            # being acquired. Never resume its suspension implicitly.
            if password_probe and not password_permitted():
                return ProbeResult(False, "sudo_authentication_suspended")
            result = await self._run(
                host, request, time.monotonic(), None,
                sudo_password=password, no_password=kind == "safety", probe=True,
                password_permitted=password_permitted if password_probe else None,
                challenge_password=kind == "sudo_challenge",
            )
        if result.failure_kind == "passwordless_root":
            return ProbeResult(False, "passwordless_root", unsafe=True)
        if kind == "safety":
            if result.root_started is True:
                return ProbeResult(False, "passwordless_root", unsafe=True)
            if (result.status == "command_error" and result.exit_code == 1
                    and result.failure_kind in {"sudo_password_required", "sudo_authorization"}):
                return ProbeResult(True)
            if (result.status == "command_error" and result.exit_code == 1
                    and result.failure_kind == "sudo_refusal_unconfirmed"):
                return ProbeResult(False, "root_unconfirmed", needs_corroboration=True)
        else:
            expected = host.username if kind == "identity" else "0"
            if (result.status == "succeeded" and result.exit_code == 0
                    and result.stdout.strip() == expected
                    and (kind == "identity" or result.root_started is True)):
                return ProbeResult(True)
        return ProbeResult(
            False, result.failure_kind or (
                "unexpected_identity" if result.status == "succeeded" else result.status
            ), password_rejected=result.password_rejected,
        )

    def authorized_host(self, principal: str, server: str) -> HostSpec:
        if not self._enabled:
            raise SSHDenied("SSH execution is disabled")
        host = self._hosts.get(server)
        if not host or not principal or self._inventory_principal(principal) not in host.principals:
            raise SSHDenied("SSH target or principal is not authorized")
        _check_file(host.identity_file, private=True)
        _check_file(host.known_hosts_file, private=False)
        return host

    async def execute(
        self, principal: str, request: ExecuteCommandRequest, *,
        on_output: OutputCallback | None = None,
        on_admitted: AdmissionCallback | None = None,
    ) -> SSHResult:
        # Ordinary execution runs under the configured SSH account and refuses
        # privileged requests. A separate path handles authorized privilege
        # elevation after access-gate admission (interactive approval only
        # where host/root access is restricted).
        if request.privileged:
            raise SSHDenied("Privileged execution is not enabled")
        # Check on every call to detect key/host-pin rotation or removed files.
        host = self.authorized_host(principal, request.server)
        async with self._global, self._semaphores[host.alias]:
            self.require_ready(host.alias)
            # A pending semaphore wait is queued, not running. Audit the actual
            # admission before any remote preflight or command can start.
            if on_admitted is not None and not on_admitted():
                raise asyncio.CancelledError
            return await self._run(host, request, time.monotonic(), on_output)

    async def _execute_approved_privileged(
        self, principal: str, request: ExecuteCommandRequest, *,
        on_output: OutputCallback | None = None,
        on_admitted: AdmissionCallback | None = None,
    ) -> SSHResult:
        """Privileged transport for requests admitted by the MCP access gate.

        Host/root policy determines whether interactive approval is needed.
        This method rechecks SSH authorization and protected sudo credentials;
        it is not itself the MCP caller-authorization gate.
        """
        if not request.privileged:
            raise SSHDenied("Privileged execution must be explicitly requested")
        host = self.authorized_host(principal, request.server)
        if host.privileged_access == "none":
            raise SSHDenied("Privileged execution is disabled for host")
        password = self._sudo_passwords.get(host.alias)
        if password is None:
            raise SSHDenied("Privileged credentials unavailable for host")
        async with self._global, self._semaphores[host.alias]:
            self.require_ready(host.alias, privileged=True)
            if on_admitted is not None and not on_admitted():
                raise asyncio.CancelledError
            monitor = self.readiness
            generation = monitor.password_generation(host.alias) if monitor is not None else None

            def password_permitted() -> bool:
                assert monitor is not None
                self.require_ready(host.alias, privileged=True)
                if monitor.password_generation(host.alias) != generation:
                    raise ReadinessDenied(
                        "Host readiness unavailable: sudo_credential_generation_changed"
                    )
                return True

            # timeout_seconds measures admitted execution, never time in queue.
            result = await self._run(host, request, time.monotonic(), on_output,
                                     sudo_password=password,
                                     password_permitted=password_permitted if monitor is not None else None)
            if result.password_rejected and self.readiness is not None:
                self.readiness.suspend(host.alias)
            return result

    async def preflight_cwd(
        self, principal: str, request: ExecuteCommandRequest,
    ) -> tuple[str, int, int] | SSHResult | None:
        """Read-only whole-batch cwd check; every later step rechecks identity."""
        if request.privileged:
            raise SSHDenied("Privileged execution is not enabled")
        host = self.authorized_host(principal, request.server)
        if request.cwd is None:
            return None
        async with self._global, self._semaphores[host.alias]:
            self.require_ready(host.alias)
            try:
                return await self._resolve_cwd(host, request, time.monotonic())
            except TimeoutError:
                return SSHResult(host.alias, "timed_out", None, "", "", 0.0)

    async def _run(
        self, host: HostSpec, request: ExecuteCommandRequest, start: float,
        on_output: OutputCallback | None,
        *, sudo_password: str | None = None, no_password: bool = False,
        probe: bool = False,
        password_permitted: Callable[[], bool] | None = None,
        challenge_password: bool = False,
    ) -> SSHResult:
        effective_cwd: str | None = None
        command = _effective_argv(request)
        cwd_nonce: str | None = None
        if request.cwd is not None and sudo_password is None:
            try:
                preflight = await self._resolve_cwd(host, request, start)
            except TimeoutError:
                return SSHResult(host.alias, "timed_out", None, "", "",
                                 time.monotonic() - start)
            if isinstance(preflight, SSHResult):
                return preflight
            resolved, device, inode = preflight
            effective_cwd = resolved
            cwd_nonce = secrets.token_hex(16)
            command = ["python3", "-c", _CWD_EXEC, cwd_nonce, resolved,
                       str(device), str(inode), *command]
        marker_token = (_ROOT_MARKER_PREFIX + secrets.token_hex(16)
                        if sudo_password is not None or no_password else None)
        marker = _framed_root_marker(marker_token) if marker_token is not None else None
        nonce = marker_token[len(_ROOT_MARKER_PREFIX):] if marker_token is not None else ""
        # A unique prompt is requested explicitly via sudo -p; sudo implementations
        # can wrap it in their own text. No English refusal text is used as proof.
        prompt = "SSH-MCP-AUTH-" + secrets.token_hex(16) + ":" if challenge_password else ""
        prompt_bytes = prompt.encode("ascii")
        if marker_token is not None:
            # Root-only cwd is prepared after sudo authentication inside the
            # fixed entrypoint; the gateway user never needs to traverse it.
            # The inner helper emits READY/FAILED with the nonce alone, while
            # the outer sudo wrapper emits the full START marker.
            command = _sudo_argv(
                ["python3", "-c", _ROOT_EXEC, nonce, request.cwd or "", *command],
                marker_token, no_password=no_password, prompt=prompt,
            )
            # The privileged timeout includes semaphore wait; never launch
            # SSH after that budget has already expired.
            if time.monotonic() - start >= request.timeout_seconds:
                return SSHResult(host.alias, "timed_out", None, "", "", time.monotonic() - start)
        remaining = request.timeout_seconds - (time.monotonic() - start)
        if remaining <= 0:
            return SSHResult(host.alias, "timed_out", None, "", "",
                             time.monotonic() - start, effective_cwd=effective_cwd)
        if not probe:
            self.require_ready(host.alias, privileged=request.privileged)
        ssh_args = _ssh_argv(host, request, allow_stdin=sudo_password is not None,
                             remote_argv=command)
        if marker is not None:
            # Fixed locale for the sudo launcher, not the caller's root command
            # (whose wrapper already clears the inherited environment).
            ssh_args[-1] = "LC_ALL=C " + ssh_args[-1]
        try:
            process = await asyncio.wait_for(
                _spawn_ssh_command(
                    *ssh_args,
                    host=host,
                    stdin=(asyncio.subprocess.PIPE if sudo_password is not None
                           else asyncio.subprocess.DEVNULL),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ),
                timeout=remaining,
            )
        except TimeoutError:
            return SSHResult(host.alias, "timed_out", None, "", "",
                             time.monotonic() - start, effective_cwd=effective_cwd)
        except ChannelConnectionError as exc:
            return SSHResult(host.alias, "transport_error", None, "", str(exc),
                             time.monotonic() - start, effective_cwd=effective_cwd,
                             failure_kind=exc.failure_kind)
        except OSError:
            return SSHResult(host.alias, "transport_error", None, "", "SSH transport could not start", time.monotonic() - start, effective_cwd=effective_cwd)

        assert process.stdout is not None and process.stderr is not None
        shared_budget = [0]  # One limit across stdout and stderr, not two independent caps.
        confirmed = [False]
        diagnostic = bytearray()
        ready_event = asyncio.Event()
        ready = [False]
        setup_failed = [False]
        cwd_ready = [False]
        cwd_failed = [False]
        stdout_marker_seen = [False]
        stdout_captured = bytearray()
        stderr_captured = bytearray()
        async def capture_plain(stream: str, data: bytes) -> None:
            (stdout_captured if stream == "stdout" else stderr_captured).extend(data)
            if on_output is not None:
                await on_output(stream, data)
        challenge_event = asyncio.Event()
        challenge_seen = False
        password_sent = False
        unsafe_root = False

        def confirmed_root() -> None:
            nonlocal unsafe_root
            if not unsafe_root and (no_password or (challenge_password and not password_sent)):
                unsafe_root = True
                if self.readiness is not None:
                    self.readiness.mark_passwordless_root(host.alias)
            challenge_event.set()

        def observe_challenge(pre_root: bytes) -> None:
            nonlocal challenge_seen
            # The marker must be emitted in the bounded pre-root stream,
            # not supplied by a caller, a root command or an error after it.
            # Traditional sudo renders the custom prompt verbatim. sudo-rs
            # renders "[sudo: <custom prompt>] <PAM prompt>". Match the
            # nonce in these exact prompt positions, not in arbitrary
            # diagnostics (e.g. an echoed rejected argument vector).
            line = pre_root.rstrip().rsplit(b"\n", 1)[-1]
            native_prefix = b"[sudo: " + prompt_bytes + b"]"
            if line == prompt_bytes or line == native_prefix or line.startswith(native_prefix + b" "):
                challenge_seen = True
                challenge_event.set()

        def sent() -> None:
            nonlocal password_sent
            password_sent = True

        async def send_challenge_password(writer: ByteWriter, password: str) -> None:
            def permitted() -> bool:
                return challenge_seen and not unsafe_root and permit_password_write()
            await challenge_event.wait()
            await _send_sudo_password(writer, password, permitted, sent)

        async def finish_stderr(reader: Awaitable[str]) -> str:
            try:
                return await reader
            finally:
                # An ordinary rejection or disconnect must not leave the
                # password sender waiting for a prompt that will never arrive.
                challenge_event.set()

        if marker is not None:
            stderr_reader = _read_root_stderr(
                process.stderr, marker, self._output_bytes, on_output,
                shared_budget, confirmed, diagnostic, ready_event,
                ready, setup_failed,
                _framed_root_marker(_ROOT_READY_PREFIX + nonce),
                _framed_root_marker(_ROOT_FAILED_PREFIX + nonce),
                stderr_captured, on_confirmed=confirmed_root,
                on_challenge=observe_challenge if challenge_password else None,
            )
        elif cwd_nonce is not None:
            stderr_reader = _read_cwd_stderr(
                process.stderr, _framed_root_marker(_CWD_READY_PREFIX + cwd_nonce),
                _framed_root_marker(_CWD_FAILED_PREFIX + cwd_nonce),
                self._output_bytes, on_output, shared_budget,
                cwd_ready, cwd_failed, stderr_captured,
            )
        else:
            stderr_reader = _bounded_read(
                process.stderr, self._output_bytes, "stderr", capture_plain, shared_budget,
            )
        stdout_reader = (
            _read_root_stdout(process.stdout, marker, self._output_bytes, on_output,
                              shared_budget, ready, ready_event, stdout_marker_seen,
                              stdout_captured, on_confirmed=confirmed_root)
            if marker is not None else
            _bounded_read(process.stdout, self._output_bytes, "stdout", capture_plain, shared_budget)
        )
        tasks = [
            asyncio.create_task(stdout_reader),
            asyncio.create_task(finish_stderr(stderr_reader)),
            asyncio.create_task(process.wait()),
        ]
        withheld: ReadinessDenied | None = None

        def permit_password_write() -> bool:
            nonlocal withheld
            try:
                return password_permitted is None or password_permitted()
            except ReadinessDenied as exc:
                # The command has already been dispatched. Close stdin without
                # sending the credential, but keep draining the remote evidence.
                withheld = exc
                return False

        if sudo_password is not None:
            assert process.stdin is not None
            tasks.append(asyncio.create_task(
                send_challenge_password(process.stdin, sudo_password) if challenge_password
                else _send_sudo_password(process.stdin, sudo_password, permit_password_write, sent)
            ))
        try:
            completed = await asyncio.wait_for(
                asyncio.gather(*tasks),
                timeout=max(0.001, request.timeout_seconds - (time.monotonic() - start)),
            )
            stdout, stderr, exit_code = completed[:3]
        except (TimeoutError, OutputLimitExceeded) as exc:
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            await process.wait()
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            status: ResultStatus = "timed_out" if isinstance(exc, TimeoutError) else "output_limit"
            # The readers already bounded and authorized these prefixes.
            # Unconfirmed/pre-root bytes remain private even on termination.
            safe = ((marker is None or (ready[0] and not setup_failed[0]))
                    and (cwd_nonce is None or (cwd_ready[0] and not cwd_failed[0])))
            stdout_partial = (stdout_captured.decode("utf-8", errors="replace")
                              if safe and (marker is None or stdout_marker_seen[0]) else "")
            stderr_partial = (stderr_captured.decode("utf-8", errors="replace")
                              if safe else "")
            confirmed_exit = _remote_exit(process, process.returncode)
            await _close_native_connection(process)
            return SSHResult(host.alias, status, confirmed_exit, stdout_partial, stderr_partial,
                             time.monotonic() - start, effective_cwd=effective_cwd,
                             root_started=(True if confirmed[0] else None),
                             exit_accepted=False if confirmed_exit is not None else None,
                             failure_kind="execution_uncertain" if withheld is not None else None)
        except (OSError, asyncssh.Error):
            if process.returncode is None:
                process.kill()
            await process.wait()
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            known = _remote_exit(process, process.returncode)
            safe = ((marker is None or (ready[0] and not setup_failed[0]))
                    and (cwd_nonce is None or (cwd_ready[0] and not cwd_failed[0])))
            out = stdout_captured.decode("utf-8", errors="replace") if safe else ""
            err = stderr_captured.decode("utf-8", errors="replace") if safe else ""
            await _close_native_connection(process)
            return SSHResult(host.alias,
                             "transport_error",
                             known, out, err, time.monotonic() - start,
                             exit_accepted=False if known is not None else None,
                             effective_cwd=effective_cwd,
                             root_started=True if marker is not None and confirmed[0] else None,
                             failure_kind=("output_incomplete" if known is not None
                                           and (withheld is None or confirmed[0])
                                           else "execution_uncertain"))
        except BaseException:
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            await process.wait()
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await _close_native_connection(process)
            raise

        verified_code = _remote_exit(process, cast(int | None, exit_code))
        signal_received = getattr(process, "exit_signal", None)
        # Completion requires an SSH channel close, not merely the end of
        # local stream readers (which AsyncSSH also signals on TCP loss).
        channel_complete = bool(getattr(process, "channel_complete", True))
        await _close_native_connection(process)
        safe_output = (
            (marker is None or (ready[0] and not setup_failed[0]))
            and (cwd_nonce is None or (cwd_ready[0] and not cwd_failed[0]))
        )
        safe_stdout = (cast(str, stdout) if safe_output
                       and (marker is None or stdout_marker_seen[0]) else "")
        safe_stderr = cast(str, stderr) if safe_output else ""
        if not channel_complete:
            outcome_known = ((verified_code is not None or signal_received is not None)
                             and (withheld is None or confirmed[0]))
            return SSHResult(
                host.alias, "transport_error", verified_code,
                safe_stdout, safe_stderr, time.monotonic() - start,
                exit_accepted=False if outcome_known else None,
                effective_cwd=effective_cwd,
                root_started=True if marker is not None and confirmed[0] else None,
                failure_kind="output_incomplete" if outcome_known else "execution_uncertain",
            )
        if withheld is not None and not confirmed[0]:
            # Only a completed, explicitly rejected sudo invocation proves
            # that withholding the password prevented execution. Missing root
            # frames alone (even with an exit status) cannot prove that.
            diagnostic_lines = bytes(diagnostic).decode("utf-8", errors="replace").lower().splitlines()
            if (not stdout_marker_seen[0] and verified_code == 1
                    and signal_received is None
                    and any(line.strip() in {"sudo: no password was provided",
                                              "sudo: a password is required"}
                            for line in diagnostic_lines)):
                raise withheld
            return SSHResult(
                host.alias, "transport_error", verified_code, "", "",
                time.monotonic() - start, effective_cwd=effective_cwd,
                failure_kind="execution_uncertain",
            )
        if cwd_nonce is not None and cwd_failed[0]:
            return SSHResult(
                host.alias, "command_error", verified_code, "", "Remote cwd changed before execution",
                time.monotonic() - start, exit_accepted=False, effective_cwd=effective_cwd,
                failure_kind="cwd_preflight",
            )
        if cwd_nonce is not None and not cwd_ready[0]:
            return SSHResult(
                host.alias, "transport_error", verified_code, "", "",
                time.monotonic() - start, effective_cwd=effective_cwd,
                failure_kind="execution_uncertain",
            )
        # A complete, exception-free stream drain plus channel wait and a
        # confirmed exit-status is authoritative even if the peer closes the
        # TCP connection before this coroutine resumes. Genuine loss during
        # a drain raises into the transport_error/output_incomplete branch.
        if verified_code is None and signal_received is None:
            if marker is not None and not confirmed[0] and not no_password:
                kind = _sudo_failure_kind(bytes(diagnostic))
                if kind in {"sudo_authentication", "sudo_authorization", "sudo_rejected"}:
                    return SSHResult(
                        host.alias, "command_error", None, "", "Sudo rejected execution",
                        time.monotonic() - start, effective_cwd=effective_cwd,
                        root_started=None, failure_kind=kind,
                        password_rejected=password_sent
                        and _supplied_password_rejected(bytes(diagnostic)),
                    )
            return SSHResult(
                host.alias, "transport_error", None, safe_stdout, safe_stderr,
                time.monotonic() - start, effective_cwd=effective_cwd,
                root_started=True if marker is not None and confirmed[0] else None,
                failure_kind="execution_uncertain",
            )
        if unsafe_root:
            return SSHResult(
                host.alias, "command_error", verified_code, "", "",
                time.monotonic() - start, exit_accepted=False,
                root_started=True, failure_kind="passwordless_root",
            )
        if marker is not None and not confirmed[0]:
            # Unknown diagnostics are candidates for corroboration only on
            # an exact, completely drained noninteractive failure. They
            # never establish safety on their own.
            if no_password and verified_code == 1 and signal_received is None and not stdout_marker_seen[0]:
                kind = _no_password_failure_kind(bytes(diagnostic))
                if kind == "root_unconfirmed":
                    kind = "sudo_refusal_unconfirmed"
            else:
                kind = "root_unconfirmed" if no_password else _sudo_failure_kind(bytes(diagnostic))
            return SSHResult(
                host.alias, "command_error", cast(int, exit_code), "",
                "Sudo rejected execution" if kind != "root_unconfirmed"
                else "Root execution could not be confirmed",
                time.monotonic() - start, effective_cwd=effective_cwd,
                root_started=None, failure_kind=kind,
                password_rejected=(password_sent and _supplied_password_rejected(bytes(diagnostic))),
            )
        if marker is not None and setup_failed[0]:
            # A root-side CWD or execvp error is NOT the requested command's
            # exit status, even when the caller accepts 126 or 127.
            return SSHResult(
                host.alias, "command_error", cast(int, exit_code), "", "Root command setup failed",
                time.monotonic() - start, effective_cwd=effective_cwd,
                exit_accepted=False, root_started=True, failure_kind="root_setup_failed",
            )
        if marker is not None and (not ready[0] or not stdout_marker_seen[0]):
            return SSHResult(
                host.alias, "command_error", cast(int, exit_code), "",
                "Root command output could not be confirmed",
                time.monotonic() - start, effective_cwd=effective_cwd,
                exit_accepted=False, root_started=True, failure_kind="root_unconfirmed",
            )
        if signal_received is not None:
            return SSHResult(
                host.alias, "command_error", None, cast(str, stdout), cast(str, stderr),
                time.monotonic() - start, exit_accepted=False, effective_cwd=effective_cwd,
                root_started=True if marker is not None else None,
                failure_kind="remote_signal",
            )
        if verified_code is None:
            return SSHResult(
                host.alias, "transport_error", None, cast(str, stdout), cast(str, stderr),
                time.monotonic() - start, effective_cwd=effective_cwd,
                root_started=True if marker is not None and confirmed[0] else None,
                failure_kind="execution_uncertain",
            )
        accepted = verified_code != 255 and verified_code in request.success_exit_codes
        completion_status: ResultStatus = "succeeded" if accepted else "command_error"
        return SSHResult(host.alias, completion_status, verified_code, cast(str, stdout),
                         cast(str, stderr), time.monotonic() - start,
                         exit_accepted=accepted,
                         effective_cwd=effective_cwd,
                         root_started=True if marker is not None else None)

    async def _resolve_cwd(
        self, host: HostSpec, request: ExecuteCommandRequest, start: float,
    ) -> tuple[str, int, int] | SSHResult:
        """Preflight remote cwd using the exact authorized SSH account and host pins."""
        assert request.cwd is not None
        # One deadline covers connection establishment AND the preflight
        # command's entire output drain; neither phase gets a fresh 12 seconds.
        deadline = start + min(12, request.timeout_seconds)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        try:
            process = await asyncio.wait_for(
                _spawn_ssh_command(
                    *_ssh_argv(host, request, remote_argv=["python3", "-c", _CWD_PREFLIGHT, request.cwd]),
                    host=host,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                ),
                timeout=remaining,
            )
        except ChannelConnectionError as exc:
            return SSHResult(host.alias, "transport_error", None, "",
                             str(exc), time.monotonic() - start,
                             failure_kind=exc.failure_kind)
        except OSError:
            return SSHResult(
                host.alias, "transport_error", None, "",
                "SSH transport could not start", time.monotonic() - start,
            )
        assert process.stdout is not None and process.stderr is not None
        cap = min(self._output_bytes, 4096)
        tasks = [
            asyncio.create_task(_preflight_read(process.stdout, cap)),
            asyncio.create_task(_preflight_read(process.stderr, cap)),
            asyncio.create_task(process.wait()),
        ]
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            stdout_result, stderr_result, code = await asyncio.wait_for(
                asyncio.gather(*tasks), timeout=remaining,
            )
        except TimeoutError:
            if process.returncode is None:
                process.kill()
            await process.wait()
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await _close_native_connection(process)
            raise
        except (OSError, asyncssh.Error):
            # The preflight probe may have run. A broken channel cannot prove
            # which bytes or status were lost, and cannot authorize user argv.
            if process.returncode is None:
                process.kill()
            await process.wait()
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await _close_native_connection(process)
            return SSHResult(
                host.alias, "transport_error", None, "", "",
                time.monotonic() - start, failure_kind="execution_uncertain",
            )
        except BaseException:
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            await process.wait()
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await _close_native_connection(process)
            raise
        stdout, overflow = cast(tuple[bytes, bool], stdout_result)
        stderr, _ = cast(tuple[bytes, bool], stderr_result)
        verified_code = _remote_exit(process, cast(int | None, code))
        channel_complete = bool(getattr(process, "channel_complete", True))
        await _close_native_connection(process)
        # A preflight exit status without the SSH channel-close frame cannot
        # prove all probe output arrived. Never authorize subsequent argv.
        if not channel_complete or verified_code is None:
            return SSHResult(host.alias, "transport_error", None, "",
                             stderr.decode("utf-8", errors="replace"),
                             time.monotonic() - start,
                             failure_kind="execution_uncertain")
        if verified_code != 0 or overflow:
            raise SSHDenied("Remote cwd unavailable or not accessible")
        try:
            raw = json.loads(stdout)
            canonical, device, inode = raw["path"], raw["dev"], raw["ino"]
            if (not isinstance(canonical, str) or not canonical.startswith("/")
                    or len(canonical.encode("utf-8")) > 4096
                    or any(char in canonical for char in ("\x00", "\n", "\r"))
                    or type(device) is not int or type(inode) is not int
                    or device < 0 or inode < 0):
                raise ValueError("Invalid cwd preflight")
        except (ValueError, TypeError, KeyError) as exc:
            raise SSHDenied("Remote cwd preflight was invalid") from exc
        return canonical, device, inode
