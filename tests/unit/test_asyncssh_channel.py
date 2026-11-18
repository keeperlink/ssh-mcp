"""TEST-265: real local SSH protocol fixture, with generated keys only."""
from __future__ import annotations

import asyncio
import json
import os
import tomllib
import shlex
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import asyncssh
from asyncssh.packet import UInt32

from app.contracts import ExecuteCommandRequest
from app.ssh_executor import (
    HostSpec, SSHExecutor, _CWD_EXEC, _CWD_PREFLIGHT, _CWD_READY_PREFIX,
    _CWD_FAILED_PREFIX, _ROOT_MARKER_PREFIX, _ROOT_READY_PREFIX,
    _ROOT_WRAPPER, _framed_root_marker,
)
from app.ssh_channel import (
    ChannelConnectionError, _TrackedClientProcess, _failure_kind, open_command,
)


class NativeChannelFixture(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.private_key = asyncssh.generate_private_key("ssh-ed25519")
        self.host_key = asyncssh.generate_private_key("ssh-ed25519")
        self.identity = root / "identity"
        self.identity.write_bytes(self.private_key.export_private_key())
        self.identity.chmod(0o600)
        allowed = root / "allowed"
        allowed.write_bytes(self.private_key.export_public_key())
        self.commands: list[str] = []

        async def handle(process):
            argv = shlex.split(process.command or "")
            self.commands.append(process.command or "")
            if argv[:2] == ["LC_ALL=C", "/usr/bin/sudo"]:
                argv = argv[1:]
                self.assertEqual(argv[11], _ROOT_WRAPPER)
                token = argv[13]
                self.assertTrue(token.startswith(_ROOT_MARKER_PREFIX))
                self.assertEqual(await process.stdin.readline(), b"synthetic-sudo-fixture\n")
                if argv[-1] == "root-no-status":
                    process.close()
                    return
                if argv[-1] == "root-start-no-status":
                    process.stderr.write(_framed_root_marker(token))
                    process.stderr.write(_framed_root_marker(
                        _ROOT_READY_PREFIX + token.removeprefix(_ROOT_MARKER_PREFIX)
                    ))
                    process.stdout.write(_framed_root_marker(token) + b"partial output")
                    process.close()
                    return
                process.stderr.write(_framed_root_marker(token))
                process.stderr.write(_framed_root_marker(
                    _ROOT_READY_PREFIX + token.removeprefix(_ROOT_MARKER_PREFIX)
                ))
                process.stderr.write(b"root command stderr")
                process.stdout.write(_framed_root_marker(token) + b"root command stdout")
                process.exit(255)
                return
            if len(argv) >= 4 and argv[:2] == ["python3", "-c"]:
                if argv[2] == _CWD_PREFLIGHT:
                    path = argv[3]
                    if path == "/no-status":
                        process.close()
                        return
                    if path == "/disconnect":
                        process.channel.get_connection().abort()
                        return
                    if path == "/exit-status-no-close":
                        process.stdout.write(json.dumps({
                            "path": path, "dev": 123, "ino": 456,
                        }).encode())
                        # Deliberately send a valid exit-status WITHOUT a
                        # channel close. This reproduces AsyncSSH receiving
                        # connection_lost(None) during transport teardown.
                        process.channel._send_request(b"exit-status", UInt32(0))
                        await asyncio.sleep(0.08)
                        process.channel.get_connection().abort()
                        return
                    process.stdout.write(json.dumps({
                        "path": path, "dev": 123, "ino": 456,
                    }).encode())
                    process.exit(0)
                    return
                if argv[2] == _CWD_EXEC:
                    nonce, path = argv[3:5]
                    if path == "/changed":
                        process.stderr.write(_framed_root_marker(_CWD_FAILED_PREFIX + nonce))
                        process.exit(255)
                        return
                    process.stderr.write(_framed_root_marker(_CWD_READY_PREFIX + nonce))
                    if argv[-1] == "fail255":
                        process.stderr.write(b"nested ssh: temporary DNS error\n")
                        process.exit(255)
                    else:
                        process.stdout.write(b"cwd ok")
                        process.exit(0)
                    return
            if argv and (argv[0] == "ssh" or argv == ["exit", "255"]):
                process.stderr.write(b"ssh: Could not resolve hostname demo-node-a\n")
                process.exit(255)
            elif argv == ["no-status"]:
                process.close()
            elif argv == ["no-status-output"]:
                process.stdout.write(b"authorized stdout before no-status")
                process.stderr.write(b"authorized stderr before no-status")
                process.close()
            elif argv == ["disconnect"]:
                process.stdout.write(b"started")
                process.channel.get_connection().abort()
            elif argv == ["exit-and-close"]:
                process.stdout.write(b"clean output")
                process.exit(255)
                await process.wait_closed()
                process.channel.get_connection().close()
            elif argv == ["exit-status-no-close"]:
                process.stdout.write(b"partial authenticated output")
                process.stderr.write(b"partial authenticated stderr")
                process.channel._send_request(b"exit-status", UInt32(0))
                await asyncio.sleep(0.08)
                process.channel.get_connection().abort()
            elif argv == ["signal"]:
                process.exit_with_signal("TERM")
            elif argv == ["slow"]:
                await asyncio.sleep(3)
                process.exit(0)
            elif argv == ["binary"]:
                process.stdout.write(bytes((0, 255, 10, 42)))
                process.stderr.write(b"stderr\x00bytes")
                process.exit(0)
            elif argv == ["large"]:
                process.stdout.write(b"x" * 16384)
                process.exit(0)
            else:
                process.stdout.write(b"ok\n")
                process.exit(0)

        self.listener = await asyncssh.listen(
            "127.0.0.1", 0, server_host_keys=[self.host_key],
            authorized_client_keys=str(allowed), process_factory=handle,
            encoding=None,
        )
        self.addAsyncCleanup(self.stop_listener)
        self.known_hosts = root / "known_hosts"
        self.known_hosts.write_text(
            f"[127.0.0.1]:{self.listener.get_port()} "
            + self.host_key.export_public_key().decode()
        )
        self.known_hosts.chmod(0o644)
        self.host = HostSpec.model_validate({
            "alias": "local", "address": "127.0.0.1", "port": self.listener.get_port(),
            "username": "gateway", "identity_file": self.identity,
            "known_hosts_file": self.known_hosts, "principals": ["tester"],
            "environment": "non-production", "access": "always-granted",
        })
        self.executor = SSHExecutor({"local": self.host}, enabled=True)

    async def stop_listener(self):
        self.listener.close()
        await self.listener.wait_closed()

    def request(self, *args, **kwargs):
        return ExecuteCommandRequest.model_validate({
            "server": "local", "argv": list(args), "reason": "TEST-265 local SSH fixture",
            "timeout_seconds": 5, **kwargs,
        })

    async def test_remote_exit_255_is_command_error_and_preserves_stderr(self):
        for argv in (("exit", "255"), ("ssh", "gateway@demo-node-a", "hostname")):
            with self.subTest(argv=argv):
                result = await self.executor.execute("tester", self.request(*argv))
                self.assertEqual(result.status, "command_error")
                self.assertEqual(result.exit_code, 255)
                self.assertFalse(result.exit_accepted)
                self.assertIn("Could not resolve hostname", result.stderr)

    async def test_native_exit_status_binary_output_and_signal(self):
        binary = await self.executor.execute("tester", self.request("binary"))
        self.assertEqual(binary.status, "succeeded")
        # The current MCP model exposes replacement-decoded text, while its
        # low-level SSH channel transports the original bytes without framing.
        self.assertEqual(binary.stdout.encode("utf-8", "replace")[:1], b"\x00")
        self.assertIn("stderr", binary.stderr)
        signal = await self.executor.execute("tester", self.request("signal"))
        self.assertEqual(signal.status, "command_error")
        self.assertEqual(signal.failure_kind, "remote_signal")
        self.assertIsNone(signal.exit_code)
        self.assertFalse(signal.exit_accepted)

    async def test_privileged_channel_password_stdin_and_exit_255(self):
        privileged_host = self.host.model_copy(update={"privileged_access": "restricted"})
        executor = SSHExecutor(
            {"local": privileged_host}, enabled=True,
            sudo_passwords={"local": "synthetic-sudo-fixture"},
        )
        result = await executor._execute_approved_privileged(
            "tester", self.request("exit", "255", privileged=True),
        )
        self.assertEqual(result.status, "command_error")
        self.assertEqual(result.exit_code, 255)
        self.assertFalse(result.exit_accepted)
        self.assertTrue(result.root_started)
        self.assertEqual(result.stdout, "root command stdout")
        self.assertEqual(result.stderr, "root command stderr")

    async def test_no_exit_status_is_explicitly_uncertain(self):
        result = await self.executor.execute("tester", self.request("no-status"))
        self.assertEqual(result.status, "transport_error")
        self.assertEqual(result.failure_kind, "execution_uncertain")
        self.assertIsNone(result.exit_code)
        self.assertIsNone(result.exit_accepted)

    async def test_no_status_preserves_bounded_authorized_output(self):
        result = await self.executor.execute("tester", self.request("no-status-output"))
        self.assertEqual(result.status, "transport_error")
        self.assertEqual(result.failure_kind, "execution_uncertain")
        self.assertIsNone(result.exit_code)
        self.assertEqual(result.stdout, "authorized stdout before no-status")
        self.assertEqual(result.stderr, "authorized stderr before no-status")

    async def test_missing_and_broken_preflight_status_never_execute_user_argv(self):
        for cwd in ("/no-status", "/disconnect"):
            with self.subTest(cwd=cwd):
                before = len(self.commands)
                result = await self.executor.execute(
                    "tester", self.request("touch", "must-not-run", cwd=cwd),
                )
                self.assertEqual(result.status, "transport_error")
                self.assertEqual(result.failure_kind, "execution_uncertain")
                self.assertIsNone(result.exit_code)
                self.assertIsNone(result.exit_accepted)
                self.assertEqual(len(self.commands), before + 1)
                self.assertEqual(shlex.split(self.commands[-1])[2], _CWD_PREFLIGHT)

    async def test_privileged_missing_status_never_becomes_sudo_denial(self):
        privileged_host = self.host.model_copy(update={"privileged_access": "restricted"})
        executor = SSHExecutor(
            {"local": privileged_host}, enabled=True,
            sudo_passwords={"local": "synthetic-sudo-fixture"},
        )
        for cmd, root_started in (("root-no-status", None),
                                  ("root-start-no-status", True)):
            with self.subTest(cmd=cmd):
                result = await executor._execute_approved_privileged(
                    "tester", self.request(cmd, privileged=True),
                )
                self.assertEqual(result.status, "transport_error")
                self.assertEqual(result.failure_kind, "execution_uncertain")
                self.assertIsNone(result.exit_code)
                self.assertIsNone(result.exit_accepted)
                self.assertEqual(result.root_started, root_started)
                if root_started is None:
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, "")
                else:
                    self.assertEqual(result.stdout, "partial output")

    async def test_clean_channel_exit_survives_immediate_peer_connection_close(self):
        result = await self.executor.execute("tester", self.request("exit-and-close"))
        self.assertEqual(result.status, "command_error")
        self.assertEqual(result.exit_code, 255)
        self.assertEqual(result.stdout, "clean output")
        self.assertFalse(result.exit_accepted)

    async def test_status_zero_then_disconnect_without_channel_close_is_not_success(self):
        result = await self.executor.execute(
            "tester", self.request("exit-status-no-close"),
        )
        self.assertEqual(result.status, "transport_error")
        self.assertEqual(result.failure_kind, "output_incomplete")
        self.assertEqual(result.exit_code, 0)
        self.assertFalse(result.exit_accepted)
        self.assertEqual(result.stdout, "partial authenticated output")
        self.assertEqual(result.stderr, "partial authenticated stderr")

    async def test_cwd_preflight_status_zero_without_close_never_authorizes_command(self):
        before = len(self.commands)
        result = await self.executor.execute(
            "tester", self.request(
                "touch", "must-not-run", cwd="/exit-status-no-close",
            ),
        )
        self.assertEqual(result.status, "transport_error")
        self.assertEqual(result.failure_kind, "execution_uncertain")
        self.assertIsNone(result.exit_code)
        self.assertEqual(len(self.commands), before + 1)
        self.assertEqual(shlex.split(self.commands[-1])[2], _CWD_PREFLIGHT)

    async def test_ssh_connection_drop_before_exit_status_is_uncertain(self):
        result = await self.executor.execute("tester", self.request("disconnect"))
        self.assertEqual(result.status, "transport_error")
        self.assertEqual(result.failure_kind, "execution_uncertain")
        self.assertIsNone(result.exit_accepted)

    async def test_cwd_guard_failure_and_command_exit_255_are_separate(self):
        rejected = await self.executor.execute("tester", self.request(
            "touch", "should-not-run", cwd="/changed",
        ))
        self.assertEqual(rejected.status, "command_error")
        self.assertEqual(rejected.failure_kind, "cwd_preflight")
        self.assertFalse(rejected.exit_accepted)
        self.assertEqual(rejected.exit_code, 255)
        confirmed = await self.executor.execute("tester", self.request(
            "fail255", cwd="/allowed",
        ))
        self.assertEqual(confirmed.status, "command_error")
        self.assertIsNone(confirmed.failure_kind)
        self.assertEqual(confirmed.exit_code, 255)
        self.assertIn("nested ssh", confirmed.stderr)
        self.assertNotIn("SSH-MCP-CWD", confirmed.stderr)

    async def test_host_key_mismatch_fails_closed_before_command(self):
        other = asyncssh.generate_private_key("ssh-ed25519")
        self.known_hosts.write_text(
            f"[127.0.0.1]:{self.listener.get_port()} "
            + other.export_public_key().decode()
        )
        result = await self.executor.execute("tester", self.request("binary"))
        self.assertEqual(result.status, "transport_error")
        self.assertEqual(result.failure_kind, "ssh_hostkey_failure")
        self.assertEqual(self.commands, [])

    async def test_ambient_config_and_agent_are_disabled(self):
        actual_connect = asyncssh.connect
        seen = []

        def controlled(*args, **kwargs):
            seen.append(kwargs)
            return actual_connect(*args, **kwargs)

        with patch.dict(os.environ, {"SSH_AUTH_SOCK": "/tmp/sky265-nonexistent-agent"}), \
             patch("app.ssh_channel.asyncssh.connect", side_effect=controlled):
            result = await self.executor.execute("tester", self.request("binary"))
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(len(seen), 1)
        self.assertIsNone(seen[0]["config"])
        self.assertIsNone(seen[0]["agent_path"])
        self.assertEqual(seen[0]["client_keys"], [str(self.identity)])
        self.assertFalse(seen[0]["agent_forwarding"])
        self.assertFalse(seen[0]["password_auth"])
        self.assertFalse(seen[0]["gss_auth"])

    async def test_timeout_and_output_cap_do_not_claim_success(self):
        timed = await self.executor.execute("tester", self.request(
            "slow", timeout_seconds=1,
        ))
        self.assertEqual(timed.status, "timed_out")
        limited = SSHExecutor({"local": self.host}, enabled=True, output_bytes=100)
        overflow = await limited.execute("tester", self.request("large"))
        self.assertEqual(overflow.status, "output_limit")
        self.assertFalse(overflow.exit_accepted) if overflow.exit_accepted is not None else None


class ChannelSecurityErrorTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.host = SimpleNamespace(
            address="127.0.0.1", port=2222, username="gateway",
            known_hosts_file=Path("/tmp/synthetic-host-pin"),
            identity_file=Path("/tmp/synthetic-private-key"),
        )

    def test_runtime_asyncssh_pin_guards_private_completion_semantics(self):
        # Runtime Docker builds install directly from pyproject dependencies.
        # The private receive-state contract is reviewed for 2.24.1 only.
        metadata = tomllib.loads((
            Path(__file__).resolve().parents[2] / "pyproject.toml"
        ).read_text(encoding="utf-8"))
        self.assertIn("asyncssh==2.24.1", metadata["project"]["dependencies"])
        self.assertEqual(asyncssh.__version__, "2.24.1")

    def test_connection_lost_none_is_not_channel_close_evidence(self):
        # AsyncSSH calls session.connection_lost(None) after both normal
        # SSH_MSG_CHANNEL_CLOSE and transport teardown without that packet.
        # Test the actual callback, not a manually supplied result flag.
        for recv_state, expected in (
            ("open", False), ("eof_pending", False),
            ("eof", False), ("close_pending", False), ("closed", True),
        ):
            with self.subTest(recv_state=recv_state), patch.object(
                asyncssh.SSHClientProcess, "connection_lost", autospec=True,
            ) as parent:
                proc = _TrackedClientProcess()
                proc._chan = Mock(_recv_state=recv_state)
                proc.connection_lost(None)
                self.assertIs(proc.channel_close_confirmed, expected)
                parent.assert_called_once_with(proc, None)

    def test_connection_lost_none_without_channel_never_confirms_close(self):
        with patch.object(asyncssh.SSHClientProcess, "connection_lost", autospec=True):
            proc = _TrackedClientProcess()
            proc.connection_lost(None)
            self.assertFalse(proc.channel_close_confirmed)

    async def test_cwd_channel_completion_proof_uses_same_callback(self):
        # A valid remote exit 0 is not sufficient to authorize CWD when
        # the peer never sent SSH_MSG_CHANNEL_CLOSE. Exercise the callback
        # and the process facade used by both commands and CWD preflight.
        from app.ssh_channel import SSHChannelProcess
        for state, expected in (("open", False), ("closed", True)):
            with self.subTest(receive_state=state), patch.object(
                asyncssh.SSHClientProcess, "connection_lost", autospec=True,
            ):
                proc = _TrackedClientProcess()
                chan = Mock(_recv_state=state)
                chan.wait_closed = AsyncMock()
                chan.get_exit_status.return_value = 0
                chan.get_exit_signal.return_value = None
                proc._chan = chan
                proc.connection_lost(None)
                wrapped = SSHChannelProcess(Mock(), proc, None)
                self.assertEqual(await wrapped.wait(), 0)
                self.assertIs(wrapped.channel_complete, expected)
                self.assertEqual(wrapped.exit_status, 0)

    def test_connection_error_labels_are_specific_and_bounded(self):
        cases = (
            (asyncssh.PermissionDenied("synthetic auth rejection"), "ssh_auth_failure"),
            (asyncssh.HostKeyNotVerifiable("synthetic host key"), "ssh_hostkey_failure"),
            (TimeoutError("synthetic timeout"), "ssh_connection_timeout"),
            (OSError("synthetic connection lost"), "ssh_connection_failure"),
        )
        for failure, kind in cases:
            with self.subTest(kind=kind):
                self.assertEqual(_failure_kind(failure), kind)

    async def test_connection_failures_are_sanitized(self):
        for exc, kind in (
            (asyncssh.PermissionDenied("a private identity"), "ssh_auth_failure"),
            (asyncssh.HostKeyNotVerifiable("private host key"), "ssh_hostkey_failure"),
            (TimeoutError("private address"), "ssh_connection_timeout"),
            (OSError("private route"), "ssh_connection_failure"),
        ):
            with self.subTest(kind=kind), patch(
                "app.ssh_channel.asyncssh.connect", new=AsyncMock(side_effect=exc),
            ):
                with self.assertRaises(ChannelConnectionError) as ctx:
                    await open_command(self.host, "echo test", allow_stdin=False)
                self.assertEqual(ctx.exception.failure_kind, kind)
                self.assertNotIn("private", str(ctx.exception))

    async def test_session_start_failure_always_aborts_connection(self):
        for failure in (OSError("session unavailable"),
                        asyncssh.ChannelOpenError(asyncssh.OPEN_ADMINISTRATIVELY_PROHIBITED,
                                                  "channel refused"),
                        asyncio.CancelledError()):
            conn = Mock()
            conn.create_session = AsyncMock(side_effect=failure)
            with self.subTest(failure=type(failure).__name__), patch(
                "app.ssh_channel.asyncssh.connect", new=AsyncMock(return_value=conn),
            ):
                expected = (ChannelConnectionError if isinstance(
                    failure, (OSError, asyncssh.ChannelOpenError))
                            else type(failure))
                with self.assertRaises(expected):
                    await open_command(self.host, "echo test", allow_stdin=True)
                conn.abort.assert_called_once()

    async def test_exec_acknowledgement_loss_is_uncertain_not_connection_failure(self):
        for exc in (OSError("private network loss"), TimeoutError("private timed out"),
                    asyncssh.ConnectionLost("private disconnect")):
            conn = Mock()
            conn.create_session = AsyncMock(side_effect=exc)
            with self.subTest(error=type(exc).__name__), patch(
                "app.ssh_channel.asyncssh.connect", new=AsyncMock(return_value=conn),
            ):
                with self.assertRaises(ChannelConnectionError) as ctx:
                    await open_command(self.host, "touch /tmp/possible-side-effect",
                                       allow_stdin=False)
                self.assertEqual(ctx.exception.failure_kind, "execution_uncertain")
                self.assertIn("acknowledgement", str(ctx.exception))
                self.assertNotIn("private", str(ctx.exception))
                conn.abort.assert_called_once()

    async def test_channel_open_refusal_vs_lost_exec_reply(self):
        for code, expected in (
            (asyncssh.OPEN_ADMINISTRATIVELY_PROHIBITED, "ssh_session_refused"),
            (asyncssh.OPEN_REQUEST_SESSION_FAILED, "execution_uncertain"),
            (asyncssh.OPEN_CONNECT_FAILED, "execution_uncertain"),
        ):
            conn = Mock()
            conn.create_session = AsyncMock(side_effect=asyncssh.ChannelOpenError(
                code, "synthetic refusal or lost request reply",
            ))
            with self.subTest(code=code), patch(
                "app.ssh_channel.asyncssh.connect", new=AsyncMock(return_value=conn),
            ):
                with self.assertRaises(ChannelConnectionError) as ctx:
                    await open_command(self.host, "echo test", allow_stdin=False)
                self.assertEqual(ctx.exception.failure_kind, expected)
                conn.abort.assert_called_once()


if __name__ == "__main__":
    unittest.main()
