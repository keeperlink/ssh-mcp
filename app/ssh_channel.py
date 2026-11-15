"""Native SSH channel execution; file transfers deliberately retain OpenSSH.

This transport exposes the *remote* SSH exit-status rather than OpenSSH's
overloaded process exit 255. No user payload is ever used as a protocol marker.
"""
from __future__ import annotations

import asyncio
import io
from dataclasses import dataclass
from typing import Any, cast

import asyncssh


class ChannelConnectionError(Exception):
    """Sanitized transport/setup failure, never a remote command result."""

    def __init__(self, failure_kind: str, message: str = "SSH connection could not be established"):
        super().__init__(message)
        self.failure_kind = failure_kind


def _failure_kind(exc: BaseException) -> str:
    if isinstance(exc, asyncssh.PermissionDenied):
        return "ssh_auth_failure"
    if isinstance(exc, asyncssh.HostKeyNotVerifiable):
        return "ssh_hostkey_failure"
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        # The deadline can expire in TCP, banner, KEX, or auth.
        return "ssh_connection_timeout"
    return "ssh_connection_failure"


class _TrackedClientProcess(asyncssh.SSHClientProcess[bytes]):
    """Record an SSH channel close separately from transport disappearance.

    AsyncSSH closes stream readers on either event, so EOF from a reader is
    insufficient proof that the remote output stream completed. Even
    connection_lost(None) is ambiguous: AsyncSSH can issue it when a peer
    disconnects before sending SSH_MSG_CHANNEL_CLOSE. In pinned AsyncSSH
    2.24.1, the channel receive state becomes closed only after processing
    that channel-close packet (and flushing the buffered data).
    """

    def __init__(self) -> None:
        super().__init__()
        self.channel_close_confirmed = False

    def connection_lost(self, exc: Exception | None) -> None:
        # AsyncSSH can call this with exc=None after SSH transport teardown
        # even without a peer CHANNEL_CLOSE. Check channel receive state,
        # which only reaches closed after an actual peer close packet.
        chan = self._chan
        self.channel_close_confirmed = (
            chan is not None
            and getattr(chan, '_recv_state', None) == 'closed'
        )
        super().connection_lost(exc)


class _SudoStdin:
    """Close only SSH stdin; SSHWriter.close() would close the entire channel."""

    def __init__(self, writer: asyncssh.SSHWriter[bytes]):
        self._writer = writer

    def write(self, block: bytes) -> None:
        self._writer.write(block)

    async def drain(self) -> None:
        await self._writer.drain()

    def close(self) -> None:
        self._writer.write_eof()

    async def wait_closed(self) -> None:
        await self._writer.drain()


@dataclass
class SSHChannelProcess:
    """Small process-compatible facade for the existing bounded readers."""

    connection: asyncssh.SSHClientConnection
    process: _TrackedClientProcess
    stdin: _SudoStdin | None
    channel_complete: bool = False
    returncode: int | None = None
    exit_status: int | None = None
    exit_signal: tuple[str, bool, str, str] | None = None

    @property
    def stdout(self) -> asyncssh.SSHReader[bytes]:
        return self.process.stdout

    @property
    def stderr(self) -> asyncssh.SSHReader[bytes]:
        return self.process.stderr

    async def wait(self) -> int | None:
        await self.process.wait_closed()
        self.channel_complete = self.process.channel_close_confirmed
        status = self.process.exit_status
        self.exit_status = status if status is not None and status >= 0 else None
        self.exit_signal = self.process.exit_signal
        self.returncode = self.exit_status
        return self.returncode

    def kill(self) -> None:
        # A disconnected session may have executed the remote command.
        # Aborting a connection is never proof the command was killed remotely.
        self.connection.abort()

    async def close_connection(self) -> None:
        self.connection.close()
        await self.connection.wait_closed()


async def open_command(host: Any, command: str, *, allow_stdin: bool) -> SSHChannelProcess:
    """Open one pinned and explicitly authorized SSH channel.

    Config=None prevents reading ~/.ssh/config, agent_path=None disables
    SSH_AUTH_SOCK, and explicit key/known_hosts disallow ambient identities.
    """
    try:
        conn = await asyncssh.connect(
            host.address, port=host.port, username=host.username,
            config=None,
            known_hosts=str(host.known_hosts_file),
            client_keys=[str(host.identity_file)],
            client_certs=[],
            agent_path=None,
            agent_forwarding=False,
            pkcs11_provider=None,
            gss_kex=False,
            gss_auth=False,
            host_based_auth=False,
            password_auth=False,
            kbdint_auth=False,
            preferred_auth=["publickey"],
            x509_trusted_certs=None,
            canonicalize_hostname=False,
            connect_timeout=10,
            keepalive_interval=5,
            keepalive_count_max=2,
        )
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        raise ChannelConnectionError(_failure_kind(exc)) from None
    try:
        # Use AsyncSSH's documented create_session + redirect primitives
        # (the same path as create_process), but instantiate a client session
        # which can distinguish SSH channel close from connection teardown.
        _, session = await conn.create_session(
            _TrackedClientProcess, command, encoding=None, term_type=None,
        )
        process = cast(_TrackedClientProcess, session)
        await process.redirect(
            asyncssh.PIPE if allow_stdin else asyncssh.DEVNULL,
            asyncssh.PIPE, asyncssh.PIPE,
            io.DEFAULT_BUFFER_SIZE, True, True,
        )
        return SSHChannelProcess(
            conn, process, _SudoStdin(process.stdin) if allow_stdin else None,
        )
    except asyncssh.ChannelOpenError as exc:
        conn.abort()
        # A positive channel-open failure occurred *before* exec. In
        # contrast OPEN_REQUEST_SESSION_FAILED may be fabricated by AsyncSSH
        # while cleaning up a pending exec waiter: no reply was observed.
        pre_exec_rejections = {
            asyncssh.OPEN_ADMINISTRATIVELY_PROHIBITED,
            asyncssh.OPEN_UNKNOWN_CHANNEL_TYPE,
            asyncssh.OPEN_RESOURCE_SHORTAGE,
        }
        if exc.code in pre_exec_rejections:
            raise ChannelConnectionError(
                "ssh_session_refused", "SSH channel was refused before command dispatch",
            ) from None
        raise ChannelConnectionError(
            "execution_uncertain", "SSH exec acknowledgement was not confirmed",
        ) from None
    except (asyncssh.Error, OSError, TimeoutError):
        # A successful connection does NOT mean the exec request was rejected
        # safely: it may have been sent before the response or TCP loss.
        conn.abort()
        raise ChannelConnectionError(
            "execution_uncertain", "SSH exec acknowledgement was not confirmed",
        ) from None
    except BaseException:
        conn.abort()
        raise
