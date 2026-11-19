"""TEST-267 PR2: synthetic-only sudo transport tests; no real ssh or sudo."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import re
import shlex
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from app.contracts import ExecuteCommandRequest
from app.jobs import JobManager, JobStore
from app.history import HistoryStore
from app import runtime_files
from app.ssh_executor import (
    HostSpec, SSHDenied, SSHExecutor, SSHResult, _ROOT_WRAPPER, _ROOT_EXEC, _sudo_argv,
    _ROOT_MARKER_PREFIX, _ROOT_READY_PREFIX, _ROOT_FAILED_PREFIX,
    _usable_sudo_password, _framed_root_marker,
)


PASSWORD = "synthetic-test-sudo-password-no-production"
ROOT_MARKER = re.compile(r"SSH-MCP-ROOT-START:[0-9a-f]{32}\Z")


def _remote_sudo(raw: str) -> list[str]:
    remote = shlex.split(raw)
    if remote == ["/usr/bin/id", "-un"]:
        return remote
    assert remote[:2] == ["LC_ALL=C", "/usr/bin/sudo"], remote
    return remote[1:]


def _remote_token(remote: list[str]) -> str:
    return remote[13]  # sudo explicitly includes "-u root".


def _root_stdout(token: str, body: bytes = b"") -> bytes:
    return _framed_root_marker(token) + body


def _root_stderr(token: str, body: bytes = b"", *,
                 ready: bool = True, setup_failed: bool = False) -> bytes:
    nonce = token.removeprefix(_ROOT_MARKER_PREFIX)
    return (_framed_root_marker(token)
            + (_framed_root_marker(_ROOT_READY_PREFIX + nonce) if ready else b"")
            + (_framed_root_marker(_ROOT_FAILED_PREFIX + nonce) if setup_failed else b"")
            + body)


class SyntheticStdin:
    def __init__(self, *, broken: bool = False, broken_close: bool = False):
        self.content = bytearray()
        self.closed = False
        self.broken = broken
        self.broken_close = broken_close

    def write(self, block: bytes) -> None:
        self.content.extend(block)

    async def drain(self) -> None:
        if self.broken:
            raise BrokenPipeError

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        if self.broken_close:
            raise BrokenPipeError


class SyntheticProcess:
    def __init__(self, out: bytes, err: bytes, code: int,
                 *, blocked: bool = False, broken_pipe: bool = False):
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.stdout.feed_data(out)
        self.stdout.feed_eof()
        self.stderr.feed_data(err)
        self.stderr.feed_eof()
        self.stdin = SyntheticStdin(broken=broken_pipe)
        self.returncode: int | None = None
        self.exit_status: int | None = None
        self.exit_signal = None
        self.code = code
        self.blocked = blocked
        self.killed = False

    async def wait(self) -> int:
        if self.blocked and not self.killed:
            await asyncio.sleep(10)
        self.returncode = -9 if self.killed else self.code
        self.exit_status = None if self.killed else self.code
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


class SudoTransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        key = self.base / "identity"
        pins = self.base / "known_hosts"
        key.write_text("synthetic-not-a-real-private-key")
        key.chmod(0o600)
        pins.write_text("test.example.invalid ssh-ed25519 SYNTHETIC\n")
        pins.chmod(0o644)
        self.host = HostSpec.model_validate({
            "alias": "test", "address": "test.example.invalid", "port": 22,
            "username": "gateway", "principals": ["operator"],
            "identity_file": key, "known_hosts_file": pins,
            "environment": "non-production", "access": "always-granted",
            "privileged_access": "restricted",
        })
        self.executor = SSHExecutor(
            {"test": self.host}, enabled=True,
            sudo_passwords={"test": PASSWORD},
        )
        self.request = ExecuteCommandRequest(
            server="test", argv=["bash", "-lc", "printf 'hello\\n'"],
            reason="TEST-267 synthetic root transport", privileged=True,
        )

    async def run_synthetic(self, *, rc: int = 0, stdout: bytes = b"ok\n",
                            stderr: bytes = b"user stderr\n", marker: bool = True,
                            pre: bytes = b"", pre_stdout: bytes = b"",
                            setup_failed: bool = False, ready: bool = True,
                            stdout_marker: bool = True,
                            blocked: bool = False,
                            broken_pipe: bool = False,
                            request: ExecuteCommandRequest | None = None,
                            output=None):
        calls: list[list[str]] = []
        processes: list[SyntheticProcess] = []

        async def spawn(*args, **kwargs):
            calls.append(list(args))
            remote = _remote_sudo(args[-1])
            self.assertEqual(remote[:10], [
                "/usr/bin/sudo", "-S", "-k", "-p", "", "-H", "-u", "root", "--", "/bin/sh",
            ])
            self.assertEqual(remote[10], "-c")
            self.assertEqual(remote[11], _ROOT_WRAPPER)
            self.assertEqual(remote[12], "ssh-mcp-root")
            token = _remote_token(remote)
            self.assertRegex(token, ROOT_MARKER)
            self.assertEqual(remote[14:17], ["python3", "-c", _ROOT_EXEC])
            # The inner Python wrapper emits READY/FAILED with nonce only;
            # using the full outer START marker caused real sudo to return
            # root_unconfirmed despite a successful exit code.
            self.assertEqual(remote[17], token.removeprefix(_ROOT_MARKER_PREFIX))
            req = request or self.request
            self.assertEqual(remote[18], req.cwd or "")
            err = pre + (_root_stderr(token, stderr, ready=ready,
                                      setup_failed=setup_failed) if marker else stderr)
            out = pre_stdout + (_root_stdout(token, stdout) if marker and stdout_marker
                                else stdout)
            process = SyntheticProcess(out, err, rc, blocked=blocked,
                                       broken_pipe=broken_pipe)
            processes.append(process)
            self.assertEqual(kwargs["stdin"], asyncio.subprocess.PIPE)
            self.assertIn("-T", args)
            self.assertNotIn("-n", args)
            self.assertNotIn(PASSWORD, repr(args))
            return process

        with patch("app.ssh_executor._spawn_ssh_command",
                   side_effect=spawn):
            result = await self.executor._execute_approved_privileged(
                "operator", request or self.request, on_output=output,
            )
        return result, calls, processes

    async def test_readiness_checks_real_wrappers_and_passwordless_safety(self):
        from app.readiness import ReadinessSettings

        executor = SSHExecutor(
            {"test": self.host}, enabled=True, sudo_passwords={"test": PASSWORD},
            readiness_settings=ReadinessSettings(authorized=True),
        )
        monitor = executor.readiness
        safety_error = b"sudo: a password is required\n"
        password_error = b""
        unsafe = False
        calls = []
        processes = []

        async def spawn(*args, **kwargs):
            remote = _remote_sudo(args[-1])
            if remote == ["/usr/bin/id", "-un"]:
                self.assertEqual(kwargs["stdin"], asyncio.subprocess.DEVNULL)
                calls.append("identity")
                return SyntheticProcess(b"gateway\n", b"", 0)
            self.assertEqual(remote[-2:], ["/usr/bin/id", "-u"])
            self.assertIn("-k", remote)
            self.assertNotIn(PASSWORD, repr(args))
            token = _remote_token(remote)
            if remote[1] == "-n":
                calls.append("safety")
                self.assertEqual(kwargs["stdin"], asyncio.subprocess.DEVNULL)
                if not unsafe:
                    return SyntheticProcess(b"", safety_error, 1)
            else:
                calls.append("sudo")
                self.assertEqual(remote[1], "-S")
                self.assertEqual(kwargs["stdin"], asyncio.subprocess.PIPE)
                if password_error or safety_error == b"sudo: must have a tty\n":
                    proc = SyntheticProcess(b"", password_error or safety_error, 1)
                    processes.append(proc)
                    return proc
            proc = SyntheticProcess(_root_stdout(token, b"0\n"), _root_stderr(token), 0)
            processes.append(proc)
            return proc

        with patch("app.ssh_executor._spawn_ssh_command", side_effect=spawn):
            self.assertTrue(await monitor.check("test", privileged=True))
            self.assertTrue(monitor.sudo_ready("test"))
            self.assertEqual(bytes(processes[-1].stdin.content), PASSWORD.encode() + b"\n")
            safety_error = b"gateway is not in the sudoers file.\n"
            self.assertTrue(await monitor.check("test"))
            safety_error = b"Sorry, user gateway is not allowed to run sudo on fixture.\n"
            self.assertTrue(await monitor.check("test"))
            safety_error = b"sudo: must have a tty\n"
            self.assertFalse(await monitor.check("test"))
            self.assertTrue(monitor.active("test"))
            unsafe = True
            self.assertFalse(await monitor.check("test"))
            self.assertFalse(monitor.active("test"))
            unsafe = False
            safety_error = b"sudo: a password is required\n"
            password_error = b"sudo: 1 incorrect password attempt\n"
            self.assertFalse(await monitor.check("test", privileged=True))
            self.assertTrue(monitor.active("test"))
            self.assertTrue(monitor.password_suspended("test"))
            calls.clear()
            self.assertFalse(await monitor.check("test", privileged=True))
            self.assertEqual(calls, ["identity", "safety"])
            password_error = b"sudo: must have a tty\n"
            calls.clear()
            failed = await monitor.recheck("test")
            self.assertFalse(failed["recheck_ok"])
            self.assertTrue(monitor.password_suspended("test"))
            self.assertEqual(calls, ["identity", "safety", "sudo"])
            calls.clear()
            self.assertFalse(await monitor.check("test", privileged=True))
            self.assertEqual(calls, ["identity", "safety"])
            password_error = b""
            recovered = await monitor.recheck("test")
            self.assertTrue(recovered["recheck_ok"])
            self.assertTrue(recovered["sudo_ready"])
            plain = SSHExecutor(
                {"test": self.host.model_copy(update={"privileged_access": "none"})},
                enabled=True, readiness_settings=ReadinessSettings(authorized=True),
            )
            calls.clear()
            self.assertTrue(await plain.readiness.check("test"))
            self.assertEqual(calls, ["identity", "safety"])
            self.assertFalse(plain.readiness.sudo_ready("test"))

    async def test_unknown_sudo_diagnostic_uses_confirmed_challenge(self):
        from app.readiness import ReadinessSettings
        success_modes = {"challenge", "native_full", "native_split"}
        for mode in ("challenge", "native_full", "native_split", "no_prompt", "echoed_argv",
                     "no_input_rejection", "root_without_input", "wrong_uid", "incomplete",
                     "missing", "unsupported", "no_credential", "ssh_only"):
            with self.subTest(mode=mode):
                host = self.host.model_copy(update={"privileged_access": "none"}) if mode == "ssh_only" else self.host
                executor = SSHExecutor(
                    {"test": host}, enabled=True,
                    sudo_passwords={} if mode == "no_credential" else {"test": PASSWORD},
                    readiness_settings=ReadinessSettings(authorized=True),
                )
                calls = []
                challenge_processes = []

                async def spawn(*args, **kwargs):
                    remote = _remote_sudo(args[-1])
                    if remote == ["/usr/bin/id", "-un"]:
                        return SyntheticProcess(b"gateway\n", b"", 0)
                    calls.append(remote[1])
                    if remote[1] == "-n":
                        proc = SyntheticProcess(b"", b"sudo: interactive authentication is required",
                                                127 if mode == "missing" else 2 if mode == "unsupported" else 1)
                        if mode == "incomplete":
                            proc.channel_complete = False
                        return proc
                    token = _remote_token(remote)
                    prompt = remote[4].encode()
                    self.assertRegex(remote[4], r"^SSH-MCP-AUTH-[0-9a-f]{32}:$")
                    if mode == "no_prompt":
                        proc = SyntheticProcess(b"", b"unknown diagnostic", 1)
                    elif mode == "echoed_argv":
                        proc = SyntheticProcess(b"", b"sudo: rejected command arguments: " + prompt, 1)
                    elif mode == "no_input_rejection":
                        proc = SyntheticProcess(b"", b"sudo: maximum 3 incorrect authentication attempts", 1)
                    elif mode == "root_without_input":
                        proc = SyntheticProcess(_root_stdout(token, b"0\n"), _root_stderr(token), 0)
                    else:
                        proc = SyntheticProcess(b"", b"", 0)
                        proc.stdout = asyncio.StreamReader()
                        proc.stderr = asyncio.StreamReader()
                        native = b"[sudo: " + prompt + b"] Password: "
                        proc.stderr.feed_data(native if mode != "challenge" else prompt)
                        if mode == "native_split":
                            original_read = proc.stderr.read
                            async def split_read(count=-1):
                                return await original_read(7 if count < 0 else min(count, 7))
                            proc.stderr.read = split_read
                        original = proc.stdin.write
                        def respond(block):
                            original(block)
                            response = b"1000\n" if mode == "wrong_uid" else b"0\n"
                            proc.stdout.feed_data(_root_stdout(token, response))
                            proc.stderr.feed_data(_root_stderr(token))
                            proc.stdout.feed_eof()
                            proc.stderr.feed_eof()
                        proc.stdin.write = respond
                    challenge_processes.append(proc)
                    return proc

                with patch("app.ssh_executor._spawn_ssh_command", side_effect=spawn):
                    self.assertEqual(await executor.readiness.check("test", privileged=False), mode in success_modes)
                    self.assertEqual(executor.readiness.sudo_ready("test"), mode in success_modes)
                    if mode in {"incomplete", "missing", "unsupported", "ssh_only"}:
                        self.assertEqual(calls, ["-n"])
                    elif mode == "no_credential":
                        self.assertEqual(calls, ["-n"])
                    else:
                        self.assertEqual(calls, ["-n", "-S"])
                    if mode in {"no_prompt", "echoed_argv", "no_input_rejection", "root_without_input"}:
                        self.assertEqual(challenge_processes[0].stdin.content, b"")
                        self.assertFalse(executor.readiness.password_suspended("test"))
                    if mode == "root_without_input":
                        self.assertEqual(executor.readiness.denial("test"), "passwordless_root")

    async def test_sudo_rs_rejection_suspends_automatic_probe(self):
        from app.readiness import ReadinessSettings

        for diagnostic in (b"Authentication failed, try again.\n",
                           b"sudo: maximum 3 incorrect authentication attempts\n"):
            with self.subTest(diagnostic=diagnostic):
                executor = SSHExecutor(
                    {"test": self.host}, enabled=True, sudo_passwords={"test": PASSWORD},
                    readiness_settings=ReadinessSettings(authorized=True),
                )
                calls = []
                processes = []

                async def spawn(*args, **kwargs):
                    remote = _remote_sudo(args[-1])
                    if remote == ["/usr/bin/id", "-un"]:
                        return SyntheticProcess(b"gateway\n", b"", 0)
                    calls.append(remote[1])
                    if remote[1] == "-n":
                        return SyntheticProcess(b"", b"sudo: interactive authentication is required", 1)
                    proc = SyntheticProcess(b"", b"", 1)
                    proc.stdout = asyncio.StreamReader()
                    proc.stderr = asyncio.StreamReader()
                    proc.stderr.feed_data(b"[sudo: " + remote[4].encode() + b"] Password: ")
                    original = proc.stdin.write
                    def respond(block):
                        original(block)
                        proc.stderr.feed_data(diagnostic)
                        proc.stdout.feed_eof()
                        proc.stderr.feed_eof()
                    proc.stdin.write = respond
                    processes.append(proc)
                    return proc

                with patch("app.ssh_executor._spawn_ssh_command", side_effect=spawn):
                    self.assertFalse(await executor.readiness.check("test"))
                    self.assertTrue(executor.readiness.password_suspended("test"))
                    self.assertFalse(executor.readiness.sudo_ready("test"))
                    self.assertEqual(calls, ["-n", "-S"])
                    self.assertEqual(len(processes[0].stdin.content), len(PASSWORD.encode()) + 1)
                    calls.clear()
                    self.assertFalse(await executor.readiness.check("test"))
                    self.assertEqual(calls, ["-n"])
                    self.assertEqual(len(processes), 1)

    async def test_confirmed_passwordless_root_latches_before_channel_closes(self):
        from app.readiness import ReadinessSettings

        executor = SSHExecutor(
            {"test": self.host}, enabled=True, sudo_passwords={"test": PASSWORD},
            readiness_settings=ReadinessSettings(authorized=True, timeout_seconds=1),
        )
        monitor = executor.readiness
        unsafe = False
        processes = []
        marker_seen = asyncio.Event()
        original = monitor.mark_passwordless_root

        def latch(alias):
            original(alias)
            marker_seen.set()

        async def spawn(*args, **kwargs):
            remote = _remote_sudo(args[-1])
            if remote == ["/usr/bin/id", "-un"]:
                return SyntheticProcess(b"gateway\n", b"", 0)
            if remote[1] == "-n" and not unsafe:
                return SyntheticProcess(b"", b"sudo: a password is required\n", 1)
            token = _remote_token(remote)
            proc = SyntheticProcess(_root_stdout(token, b"0\n"), _root_stderr(token), 0,
                                    blocked=unsafe)
            processes.append(proc)
            return proc

        with patch("app.ssh_executor._spawn_ssh_command", side_effect=spawn), \
                patch.object(monitor, "mark_passwordless_root", side_effect=latch):
            self.assertTrue(await monitor.check("test", privileged=True))
            unsafe = True
            task = asyncio.create_task(monitor.check("test"))
            await asyncio.wait_for(marker_seen.wait(), .5)
            self.assertFalse(task.done())
            self.assertFalse(monitor.active("test"))
            self.assertFalse(monitor.sudo_ready("test"))
            self.assertEqual(monitor.denial("test"), "passwordless_root")
            self.assertFalse(await task)
            self.assertTrue(processes[-1].killed)
            self.assertEqual(monitor.detail("test")["ssh_reason"], "passwordless_root")
            unsafe = False
            self.assertTrue(await monitor.check("test", privileged=True))

    async def test_delayed_sudo_channel_does_not_send_suspended_password(self):
        from app.readiness import ReadinessSettings

        executor = SSHExecutor(
            {"test": self.host}, enabled=True, sudo_passwords={"test": PASSWORD},
            readiness_settings=ReadinessSettings(authorized=True),
        )
        monitor = executor.readiness
        for explicit in (False, True):
            with self.subTest(explicit=explicit):
                connecting = asyncio.Event()
                release = asyncio.Event()
                processes = []
                if explicit:
                    monitor.suspend("test")

                async def spawn(*args, **kwargs):
                    remote = _remote_sudo(args[-1])
                    if remote == ["/usr/bin/id", "-un"]:
                        return SyntheticProcess(b"gateway\n", b"", 0)
                    if remote[1] == "-n":
                        return SyntheticProcess(b"", b"sudo: a password is required\n", 1)
                    connecting.set()
                    await release.wait()
                    proc = SyntheticProcess(b"", b"sudo: no password was provided\n", 1)
                    processes.append(proc)
                    return proc

                with patch("app.ssh_executor._spawn_ssh_command", side_effect=spawn):
                    task = asyncio.create_task(monitor.recheck("test") if explicit else
                                               monitor.check("test", privileged=True))
                    await asyncio.wait_for(connecting.wait(), 1)
                    monitor.suspend("test")
                    release.set()
                    result = await task
                    self.assertFalse(result["recheck_ok"] if explicit else result)
                    self.assertEqual(len(processes), 1)
                    self.assertEqual(bytes(processes[0].stdin.content), b"")
                    self.assertTrue(processes[0].stdin.closed)
                    self.assertTrue(monitor.password_suspended("test"))

    async def test_delayed_privileged_command_refuses_suspended_generation(self):
        from app.readiness import ReadinessSettings

        for recover in (False, True):
            with self.subTest(recover=recover):
                host = self.host.model_copy(update={"max_parallel": 2})
                executor = SSHExecutor(
                    {"test": host}, enabled=True, sudo_passwords={"test": PASSWORD},
                    readiness_settings=ReadinessSettings(authorized=True),
                )
                monitor = executor.readiness
                store = JobStore(self.base / f"race-{recover}.sqlite")
                manager = JobManager(executor, store)
                connecting = asyncio.Event()
                release = asyncio.Event()
                processes = []
                rejected = []
                delayed = self.request.model_copy(update={"argv": ["/usr/bin/true"]})
                rejecting = self.request.model_copy(update={"argv": ["/usr/bin/false"]})

                async def spawn(*args, **kwargs):
                    remote = _remote_sudo(args[-1])
                    if remote == ["/usr/bin/id", "-un"]:
                        return SyntheticProcess(b"gateway\n", b"", 0)
                    if remote[1] == "-n":
                        return SyntheticProcess(b"", b"sudo: a password is required\n", 1)
                    if remote[-1] == "/usr/bin/true":
                        connecting.set()
                        await release.wait()
                        proc = SyntheticProcess(b"", b"sudo: no password was provided\n", 1)
                        processes.append(proc)
                        return proc
                    if remote[-1] == "/usr/bin/false":
                        proc = SyntheticProcess(b"", b"sudo: 1 incorrect password attempt\n", 1)
                        rejected.append(proc)
                        return proc
                    token = _remote_token(remote)
                    return SyntheticProcess(_root_stdout(token, b"0\n"), _root_stderr(token), 0)

                with patch("app.ssh_executor._spawn_ssh_command", side_effect=spawn):
                    self.assertTrue(await monitor.check("test", privileged=True))
                    pending = asyncio.create_task(
                        manager.execute_sync("operator", delayed, admitted_root=True))
                    try:
                        await asyncio.wait_for(connecting.wait(), 1)
                        result = await executor._execute_approved_privileged("operator", rejecting)
                        self.assertTrue(result.password_rejected)
                        self.assertTrue(monitor.password_suspended("test"))
                        self.assertEqual(bytes(rejected[0].stdin.content), PASSWORD.encode() + b"\n")
                        if recover:
                            self.assertTrue((await monitor.recheck("test"))["recheck_ok"])
                        release.set()
                        job_id, result = await pending
                    finally:
                        release.set()
                        if not pending.done():
                            pending.cancel()
                            await asyncio.gather(pending, return_exceptions=True)
                    self.assertIsNone(result)
                    self.assertEqual(bytes(processes[0].stdin.content), b"")
                    self.assertTrue(processes[0].stdin.closed)
                    detail = HistoryStore(store).detail(job_id)
                    self.assertEqual(detail["status"], "failed")
                    self.assertEqual(detail["failure_kind"], "pre_execution_rejected")
                    self.assertIsNone(detail["root_started"])
                    self.assertIn("sudo_credential_generation_changed" if recover else
                                  "sudo_authentication_suspended", detail["error"])

    async def test_post_dispatch_readiness_loss_preserves_execution_evidence(self):
        from app.batch import BatchManager
        from app.contracts import ExecuteCommandsRequest
        from app.readiness import ReadinessSettings

        # A real safety probe can invalidate readiness after the privileged
        # SSH exec request has been sent, but before its stdin is available.
        for outcome in ("success", "refused", "ambiguous", "incomplete",
                        "root_incomplete", "timeout"):
            for batch in (False, True):
                with self.subTest(outcome=outcome, batch=batch):
                    executor = SSHExecutor(
                        {"test": self.host.model_copy(update={"max_parallel": 2})},
                        enabled=True, sudo_passwords={"test": PASSWORD},
                        readiness_settings=ReadinessSettings(authorized=True),
                    )
                    monitor = executor.readiness
                    store = JobStore(self.base / f"dispatch-{outcome}-{batch}.sqlite")
                    manager = JobManager(executor, store)
                    batches = BatchManager(manager)
                    connecting = asyncio.Event()
                    release = asyncio.Event()
                    processes = []
                    unsafe = False
                    command = self.request.model_copy(update={
                        "argv": ["/usr/bin/true"], "timeout_seconds": 1,
                    })

                    async def spawn(*args, **kwargs):
                        remote = _remote_sudo(args[-1])
                        if remote == ["/usr/bin/id", "-un"]:
                            return SyntheticProcess(b"gateway\n", b"", 0)
                        token = _remote_token(remote)
                        if remote[1] == "-n" and not unsafe:
                            return SyntheticProcess(b"", b"sudo: a password is required\n", 1)
                        if remote[-1] != "/usr/bin/true":
                            return SyntheticProcess(_root_stdout(token, b"0\n"),
                                                    _root_stderr(token), 0)
                        connecting.set()
                        await release.wait()
                        if outcome in {"success", "root_incomplete"}:
                            proc = SyntheticProcess(_root_stdout(token, b"executed\n"),
                                                    _root_stderr(token), 0)
                        elif outcome in {"refused", "incomplete"}:
                            proc = SyntheticProcess(b"", b"sudo: no password was provided\n", 1)
                        else:
                            proc = SyntheticProcess(b"", b"unrecognized remote output\n", 1,
                                                    blocked=outcome == "timeout")
                        proc.channel_complete = outcome not in {"incomplete", "root_incomplete"}
                        processes.append(proc)
                        return proc

                    with patch("app.ssh_executor._spawn_ssh_command", side_effect=spawn):
                        self.assertTrue(await monitor.check("test", privileged=True))
                        if batch:
                            req = ExecuteCommandsRequest(
                                server="test", privileged=True, reason="synthetic race",
                                commands=[{"argv": command.argv, "timeout_seconds": 1},
                                          {"argv": ["/usr/bin/false"]}],
                                timeout_seconds=10, stop_on_error=False,
                            )
                            pending = asyncio.create_task(
                                batches.execute("operator", req, admitted_root=True))
                        else:
                            pending = asyncio.create_task(
                                manager.execute_sync("operator", command, admitted_root=True))
                        try:
                            await asyncio.wait_for(connecting.wait(), 1)
                            unsafe = True
                            self.assertFalse(await monitor.check("test"))
                            self.assertEqual(monitor.denial("test"), "passwordless_root")
                            release.set()
                            completed = await pending
                        finally:
                            release.set()
                            if not pending.done():
                                pending.cancel()
                                await asyncio.gather(pending, return_exceptions=True)
                            await batches.shutdown()
                            await manager.shutdown()
                    self.assertEqual(len(processes), 1)
                    self.assertEqual(bytes(processes[0].stdin.content), b"")
                    self.assertTrue(processes[0].stdin.closed)
                    expected = {"success": ("succeeded", "none"),
                                "refused": ("failed", "pre_execution_rejected"),
                                "ambiguous": ("transport_error", "execution_uncertain"),
                                "incomplete": ("transport_error", "execution_uncertain"),
                                "root_incomplete": ("transport_error", "output_incomplete"),
                                "timeout": ("timed_out", "execution_uncertain")}[outcome]
                    if batch:
                        first, second = completed["steps"]
                        self.assertEqual(first["status"], "not_attempted" if outcome == "refused"
                                         else expected[0])
                        self.assertEqual(second["status"], "not_attempted")
                        job_id = first["job_id"]
                    else:
                        job_id, result = completed
                        if outcome == "refused":
                            self.assertIsNone(result)
                        else:
                            self.assertIsNotNone(result)
                            self.assertEqual(result.stdout, "executed\n" if outcome in
                                             {"success", "root_incomplete"} else "")
                    detail = HistoryStore(store).detail(job_id)
                    self.assertEqual((detail["status"], detail["failure_kind"]), expected)
                    self.assertEqual(detail["root_started"], True if outcome in
                                     {"success", "root_incomplete"} else None)
                    if outcome == "refused":
                        self.assertIn("passwordless_root", detail["error"])

    async def test_public_execution_is_still_disabled(self):
        with patch("app.ssh_executor._spawn_ssh_command") as spawn:
            with self.assertRaisesRegex(SSHDenied, "not enabled"):
                await self.executor.execute("operator", self.request)
            with self.assertRaisesRegex(SSHDenied, "not enabled"):
                await self.executor.preflight_cwd("operator", self.request)
            spawn.assert_not_called()

    async def test_sudo_authentication_stdin_exact_argv_and_marker_redaction(self):
        seen: list[tuple[str, bytes]] = []

        async def capture(stream: str, data: bytes):
            seen.append((stream, data))

        result, calls, processes = await self.run_synthetic(
            stdout=b"root stdout\n", stderr=b"root stderr\n",
            pre=b"sudo: login notice\n", output=capture,
        )
        self.assertEqual((result.status, result.exit_code, result.root_started),
                         ("succeeded", 0, True))
        self.assertTrue(result.exit_accepted)
        self.assertEqual(result.stdout, "root stdout\n")
        self.assertEqual(result.stderr, "root stderr\n")
        self.assertEqual(processes[0].stdin.content, (PASSWORD + "\n").encode())
        self.assertTrue(processes[0].stdin.closed)
        self.assertIn(("stdout", b"root stdout\n"), seen)
        self.assertIn(("stderr", b"root stderr\n"), seen)
        self.assertNotIn(b"SSH-MCP-ROOT", repr(seen).encode())
        self.assertNotIn(b"login notice", repr(seen).encode())
        self.assertEqual(len(calls), 1)

    async def test_real_inner_root_helper_frames_match_outer_nonce(self):
        # Unlike mocks that synthesize READY/FAILED from the expected parser
        # values, run the *actual* inner Python helper generated by the
        # transport. An incorrect full START token made the live disposable
        # SSH fixture report root_unconfirmed after exit 0.
        async def spawn(*args, **_kwargs):
            remote = _remote_sudo(args[-1])
            token = _remote_token(remote)
            self.assertRegex(token, ROOT_MARKER)
            assert remote[14:17] == ["python3", "-c", _ROOT_EXEC]
            inner = subprocess.run(
                ["python3", "-c", _ROOT_EXEC, *remote[17:]],
                capture_output=True, check=False, timeout=5,
            )
            return SyntheticProcess(
                _framed_root_marker(token) + inner.stdout,
                _framed_root_marker(token) + inner.stderr,
                inner.returncode,
            )

        with patch("app.ssh_executor._spawn_ssh_command",
                   side_effect=spawn):
            succeeded = await self.executor._execute_approved_privileged(
                "operator", self.request,
            )
            missing = await self.executor._execute_approved_privileged(
                "operator", self.request.model_copy(update={
                    "argv": ["/not-present/sky267-test-program"],
                }),
            )
        self.assertEqual(succeeded.status, "succeeded")
        self.assertEqual(succeeded.exit_code, 0)
        self.assertEqual(succeeded.stdout, "hello\n")
        self.assertTrue(succeeded.root_started)
        self.assertTrue(succeeded.exit_accepted)
        self.assertEqual(missing.status, "command_error")
        self.assertEqual(missing.failure_kind, "root_setup_failed")
        self.assertEqual(missing.exit_code, 127)
        self.assertFalse(missing.exit_accepted)
        self.assertTrue(missing.root_started)
        self.assertEqual(missing.stdout, "")

    async def test_direct_argv_and_strict_multiline_script_are_quoted(self):
        script = "printf '%s\\n' '$HOME ; $(whoami)'\nprintf '%s' \"$1\""
        request = self.request.model_copy(update={
            "argv": ["bash", "-lc", script, "_", "a; $(id) 'quoted'"],
            "strict_bash": True,
        })
        result, calls, _ = await self.run_synthetic(request=request)
        self.assertEqual(result.status, "succeeded")
        remote = _remote_sudo(calls[0][-1])
        self.assertEqual(remote[19:21], ["bash", "-lc"])
        self.assertIn("set -euo pipefail\n" + script, remote)
        self.assertEqual(remote[-2:], ["_", "a; $(id) 'quoted'"])
        self.assertNotIn("$(id)", remote[11])  # Never in fixed root wrapper.

    async def test_sudo_authentication_and_authorization_are_sanitized(self):
        for diagnostic, expected in (
            (b"sudo: 1 incorrect password attempt\n", "sudo_authentication"),
            (b"Authentication failed, try again.\n", "sudo_authentication"),
            (b"sudo: maximum 3 incorrect authentication attempts\n", "sudo_authentication"),
            (b"sudo: gateway is not in the sudoers file\n", "sudo_authorization"),
            (b"sudo: unrecognized refusal\n", "sudo_rejected"),
        ):
            with self.subTest(kind=expected):
                result, _, _ = await self.run_synthetic(
                    rc=1, stdout=b"", stderr=b"", marker=False, pre=diagnostic,
                )
                self.assertEqual(result.status, "command_error")
                self.assertEqual(result.failure_kind, expected)
                self.assertIsNone(result.exit_accepted)
                self.assertIsNone(result.root_started)
                self.assertEqual(result.stderr, "Sudo rejected execution")
                self.assertNotIn("gateway", result.stderr)
                self.assertNotIn("password attempt", result.stderr)

    async def test_sudo_failure_never_publishes_pre_root_stdout_or_stderr(self):
        streamed: list[tuple[str, bytes]] = []
        async def capture(stream: str, data: bytes):
            streamed.append((stream, data))
        result, _, _ = await self.run_synthetic(
            rc=1, marker=False, stdout=b"pre-root sensitive stdout",
            stderr=b"private sudo details", pre=b"sudo: incorrect password",
            output=capture,
        )
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "Sudo rejected execution")
        self.assertEqual(streamed, [])

    async def test_split_marker_is_removed_before_stderr_audit(self):
        streamed: list[tuple[str, bytes]] = []
        async def capture(stream: str, data: bytes):
            streamed.append((stream, data))
        async def spawn(*args, **kwargs):
            remote = _remote_sudo(args[-1])
            token = _remote_token(remote)
            marker = _framed_root_marker(token)
            proc = SyntheticProcess(_root_stdout(token, b"real stdout"), b"", 0)
            proc.stderr = asyncio.StreamReader()
            async def deliver():
                proc.stderr.feed_data(b"sudo: informational notice\n" + marker[:9])
                await asyncio.sleep(0)
                nonce = token.removeprefix(_ROOT_MARKER_PREFIX)
                proc.stderr.feed_data(marker[9:] +
                                      _framed_root_marker(_ROOT_READY_PREFIX + nonce)
                                      + b"real stderr")
                proc.stderr.feed_eof()
            asyncio.create_task(deliver())
            return proc
        with patch("app.ssh_executor._spawn_ssh_command",
                   side_effect=spawn):
            result = await self.executor._execute_approved_privileged(
                "operator", self.request, on_output=capture,
            )
        self.assertEqual(result.status, "succeeded")
        self.assertTrue(result.root_started)
        self.assertEqual(result.stdout, "real stdout")
        self.assertEqual(result.stderr, "real stderr")
        self.assertNotIn("sudo: informational", repr(streamed))
        self.assertNotIn("SSH-MCP-ROOT", repr(streamed))

    async def test_root_only_cwd_is_pinned_inside_single_privileged_exec(self):
        launches: list[tuple[list[str], int]] = []
        async def spawn(*args, **kwargs):
            launches.append((list(args), kwargs["stdin"]))
            remote = _remote_sudo(args[-1])
            token = _remote_token(remote)
            self.assertEqual(remote[14:17], ["python3", "-c", _ROOT_EXEC])
            self.assertEqual(remote[18], "/root/synthetic-private-cwd")
            return SyntheticProcess(_root_stdout(token, b"ready"), _root_stderr(token), 0)
        with patch("app.ssh_executor._spawn_ssh_command",
                   side_effect=spawn):
            req = self.request.model_copy(update={"cwd": "/root/synthetic-private-cwd"})
            result = await self.executor._execute_approved_privileged("operator", req)
        self.assertIsNone(result.effective_cwd)
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(len(launches), 1)
        self.assertEqual(launches[0][1], asyncio.subprocess.PIPE)

    async def test_missing_marker_not_automatically_sudo_rejection(self):
        result, _, _ = await self.run_synthetic(
            rc=0, stdout=b"", stderr=b"", marker=False,
        )
        self.assertEqual(result.failure_kind, "root_unconfirmed")
        self.assertEqual(result.status, "command_error")
        self.assertIsNone(result.root_started)
        result, _, _ = await self.run_synthetic(
            rc=1, stdout=b"", stderr=b"", marker=False,
            pre=b"unexpected executor failure unrelated to sudo\n",
        )
        self.assertEqual(result.failure_kind, "root_unconfirmed")

    async def test_sudoers_echo_of_rejected_argv_cannot_spoof_root_marker(self):
        async def spawn(*args, **kwargs):
            remote = _remote_sudo(args[-1])
            self.assertEqual(remote[0], "/usr/bin/sudo")
            # sudo's policy denial quotes rejected argv, including the
            # unframed token, without ever starting the root wrapper.
            echoed = ("sudo: gateway is not allowed to execute "
                      + shlex.join(remote[9:]) + "\n").encode()
            return SyntheticProcess(b"untrusted pre-root output", echoed, 1)
        observed: list[bytes] = []
        async def capture(stream: str, block: bytes):
            observed.append(block)
        with patch("app.ssh_executor._spawn_ssh_command",
                   side_effect=spawn):
            result = await self.executor._execute_approved_privileged(
                "operator", self.request, on_output=capture,
            )
        self.assertEqual(result.status, "command_error")
        self.assertEqual(result.failure_kind, "sudo_authorization")
        self.assertIsNone(result.root_started)
        self.assertEqual(result.stdout, "")
        self.assertEqual(observed, [])

    async def test_confirmed_root_command_exit_255_is_not_transport_error(self):
        for marker in (True, False):
            with self.subTest(marker=marker):
                result, _, _ = await self.run_synthetic(
                    rc=255, stdout=b"partial", stderr=b"Host key verification failed.",
                    marker=marker,
                )
                self.assertEqual(result.status, "command_error")
                self.assertEqual(result.failure_kind, None if marker else "root_unconfirmed")
                self.assertEqual(result.root_started, True if marker else None)
                self.assertEqual(result.exit_code, 255)
                self.assertFalse(result.exit_accepted) if marker else None
                self.assertNotIn("Host key verification", result.stderr) if not marker else None

    async def test_nonzero_exit_codes_preserved_after_confirmed_root_start(self):
        for code, accepted in ((3, False), (7, True)):
            req = self.request.model_copy(update={"success_exit_codes": [0, 7]})
            result, _, _ = await self.run_synthetic(rc=code, request=req)
            self.assertEqual(result.exit_code, code)
            self.assertEqual(result.exit_accepted, accepted)
            self.assertEqual(result.status, "succeeded" if accepted else "command_error")
            self.assertTrue(result.root_started)

    async def test_passwordless_sudo_still_closes_stdin_and_broken_pipe(self):
        result, _, pipes = await self.run_synthetic(broken_pipe=True)
        self.assertEqual(result.status, "succeeded")
        self.assertTrue(pipes[0].stdin.closed)

    async def test_stdin_close_race_and_ssh_spawn_failure_remain_sanitized(self):
        async def spawn(*args, **kwargs):
            remote = _remote_sudo(args[-1])
            token = _remote_token(remote)
            proc = SyntheticProcess(_root_stdout(token), _root_stderr(token), 0)
            proc.stdin = SyntheticStdin(broken_close=True)
            return proc
        with patch("app.ssh_executor._spawn_ssh_command",
                   side_effect=spawn):
            result = await self.executor._execute_approved_privileged(
                "operator", self.request,
            )
        self.assertEqual(result.status, "succeeded")
        with patch("app.ssh_executor._spawn_ssh_command",
                   side_effect=OSError("secret synthetic OS error")) as factory:
            failed = await self.executor._execute_approved_privileged(
                "operator", self.request,
            )
        factory.assert_called_once()
        self.assertEqual(failed.status, "transport_error")
        self.assertNotIn("secret synthetic", failed.stderr)

    async def test_sudo_pre_auth_output_limit_does_not_leak_diagnostics(self):
        self.executor._output_bytes = 8
        # A huge malicious sudo diagnostic is bounded by its own 4 KiB
        # ceiling without publishing it as normal stderr.
        result, _, _ = await self.run_synthetic(
            marker=False, rc=1, stdout=b"", stderr=b"",
            pre=b"sensitive pre-root text" * 250,
        )
        self.assertEqual(result.status, "output_limit")
        self.assertIsNone(result.root_started)
        self.assertEqual(result.stderr, "")

    async def test_root_stderr_output_limit_excludes_internal_marker(self):
        self.executor._output_bytes = 4
        result, _, _ = await self.run_synthetic(
            stdout=b"", stderr=b"more than four bytes",
        )
        self.assertEqual(result.status, "output_limit")
        self.assertTrue(result.root_started)
        # Preserve only the accepted bounded user-output prefix.
        self.assertEqual(result.stderr, "more")

    async def test_privileged_timeout_streams_early_stderr_without_eof(self):
        seen: list[tuple[str, bytes]] = []
        received = asyncio.Event()
        processes: list[SyntheticProcess] = []

        async def capture(stream: str, chunk: bytes):
            seen.append((stream, chunk))
            if stream == "stderr":
                received.set()

        async def spawn(*args, **kwargs):
            token = _remote_token(_remote_sudo(args[-1]))
            process = SyntheticProcess(_root_stdout(token), b"", 0, blocked=True)
            process.stderr = asyncio.StreamReader()
            # No EOF: the root process is still running when it times out.
            process.stderr.feed_data(_root_stderr(token, b"early diagnostic\n"))
            processes.append(process)
            return process

        with patch("app.ssh_executor._spawn_ssh_command",
                   side_effect=spawn):
            result = await self.executor._execute_approved_privileged(
                "operator", self.request.model_copy(update={"timeout_seconds": 1}),
                on_output=capture,
            )
        self.assertEqual(result.status, "timed_out")
        self.assertTrue(processes[0].killed)
        self.assertTrue(received.is_set(), "stderr must stream before timeout")
        self.assertIn(("stderr", b"early diagnostic\n"), seen)
        self.assertEqual(result.stderr, "early diagnostic\n")
        self.assertTrue(result.root_started)

    async def test_split_failure_control_frame_never_leaks_to_stderr_callback(self):
        streamed: list[bytes] = []

        async def capture(stream: str, chunk: bytes):
            if stream == "stderr":
                streamed.append(chunk)

        async def spawn(*args, **kwargs):
            token = _remote_token(_remote_sudo(args[-1]))
            nonce = token.removeprefix(_ROOT_MARKER_PREFIX)
            failed = _framed_root_marker(_ROOT_FAILED_PREFIX + nonce)
            process = SyntheticProcess(_root_stdout(token), b"", 127)
            process.stderr = asyncio.StreamReader()

            async def deliver():
                process.stderr.feed_data(_root_stderr(token, b""))
                process.stderr.feed_data(failed[:17])
                await asyncio.sleep(0)
                process.stderr.feed_data(failed[17:])
                process.stderr.feed_eof()

            asyncio.create_task(deliver())
            return process

        with patch("app.ssh_executor._spawn_ssh_command",
                   side_effect=spawn):
            result = await self.executor._execute_approved_privileged(
                "operator", self.request.model_copy(update={
                    "success_exit_codes": [0, 127],
                }), on_output=capture,
            )
        self.assertEqual(result.failure_kind, "root_setup_failed")
        self.assertEqual(result.status, "command_error")
        self.assertEqual(result.stderr, "Root command setup failed")
        self.assertEqual(streamed, [])

    async def test_stdout_over_limit_before_marker_fails_closed(self):
        self.executor._output_bytes = 3
        result, _, _ = await self.run_synthetic(
            stdout=b"earliest output exceeds budget", stderr=b"",
        )
        self.assertEqual(result.status, "output_limit")

    async def test_stdout_over_limit_after_marker_is_bounded(self):
        self.executor._output_bytes = 3
        async def spawn(*args, **kwargs):
            remote = _remote_sudo(args[-1])
            token = _remote_token(remote)
            proc = SyntheticProcess(_root_stdout(token), _root_stderr(token), 0)
            proc.stdout = asyncio.StreamReader()
            async def deliver():
                await asyncio.sleep(0)
                await asyncio.sleep(0)
                proc.stdout.feed_data(_root_stdout(token, b"large confirmed output"))
                proc.stdout.feed_eof()
            asyncio.create_task(deliver())
            return proc
        with patch("app.ssh_executor._spawn_ssh_command",
                   side_effect=spawn):
            result = await self.executor._execute_approved_privileged(
                "operator", self.request,
            )
        self.assertEqual(result.status, "output_limit")

    async def test_interleaved_pre_and_post_marker_stdout_is_preserved(self):
        async def spawn(*args, **kwargs):
            remote = _remote_sudo(args[-1])
            token = _remote_token(remote)
            proc = SyntheticProcess(b"", b"", 0)
            proc.stdout = asyncio.StreamReader()
            proc.stderr = asyncio.StreamReader()
            async def deliver():
                proc.stdout.feed_data(b"SSH PRELUDE MUST BE DISCARDED\n")
                await asyncio.sleep(0)
                proc.stdout.feed_data(_root_stdout(token, b"first-"))
                proc.stderr.feed_data(_root_stderr(token))
                proc.stderr.feed_eof()
                await asyncio.sleep(0)
                proc.stdout.feed_data(b"second")
                proc.stdout.feed_eof()
            asyncio.create_task(deliver())
            return proc
        with patch("app.ssh_executor._spawn_ssh_command",
                   side_effect=spawn):
            result = await self.executor._execute_approved_privileged(
                "operator", self.request,
            )
        self.assertEqual(result.stdout, "first-second")
        self.assertTrue(result.root_started)

    async def test_successful_root_command_drops_ssh_stdout_prelude(self):
        captured: list[bytes] = []
        async def record(stream: str, block: bytes):
            if stream == "stdout":
                captured.append(block)
        result, _, _ = await self.run_synthetic(
            pre_stdout=b"SSH welcome banner\n(untrusted startup noise)\n",
            stdout=b"the-first-real-byte-is-preserved",
            output=record,
        )
        self.assertEqual(result.stdout, "the-first-real-byte-is-preserved")
        self.assertEqual(b"".join(captured), b"the-first-real-byte-is-preserved")

    async def test_root_command_without_stdout_boundary_fails_closed(self):
        seen: list[bytes] = []
        async def record(stream: str, block: bytes):
            seen.append(block)
        result, _, _ = await self.run_synthetic(
            stdout_marker=False, pre_stdout=b"SSH prelude\n", stdout=b"unproven",
            output=record,
        )
        self.assertEqual(result.status, "command_error")
        self.assertEqual(result.failure_kind, "root_unconfirmed")
        self.assertFalse(result.exit_accepted)
        self.assertTrue(result.root_started)
        self.assertEqual(result.stdout, "")
        self.assertNotIn(b"unproven", b"".join(seen))

    async def test_root_command_without_setup_ready_boundary_fails_closed(self):
        result, _, _ = await self.run_synthetic(ready=False, rc=0)
        self.assertEqual(result.status, "command_error")
        self.assertEqual(result.failure_kind, "root_unconfirmed")
        self.assertFalse(result.exit_accepted)
        self.assertTrue(result.root_started)
        self.assertEqual(result.stdout, "")

    async def test_failed_root_cwd_and_launch_never_use_accepted_exit_codes(self):
        for code in (126, 127):
            with self.subTest(code=code):
                req = self.request.model_copy(update={
                    "cwd": "/root/synthetic-private-cwd",
                    "success_exit_codes": [0, 126, 127],
                })
                streamed: list[bytes] = []
                async def record(stream: str, block: bytes):
                    streamed.append(block)
                result, _, _ = await self.run_synthetic(
                    rc=code, request=req, setup_failed=True, stdout=b"",
                    stderr=b"root setup detail that must not be published\n",
                    output=record,
                )
                self.assertEqual(result.status, "command_error")
                self.assertEqual(result.failure_kind, "root_setup_failed")
                self.assertIs(result.exit_accepted, False)
                self.assertTrue(result.root_started)
                self.assertEqual(result.stderr, "Root command setup failed")
                self.assertEqual(streamed, [])
        # Genuine command exits of the same codes retain accepted-exit semantics.
        for code in (126, 127):
            with self.subTest(genuine=code):
                result, _, _ = await self.run_synthetic(
                    rc=code, request=self.request.model_copy(update={
                        "success_exit_codes": [0, 126, 127],
                    }),
                )
                self.assertEqual(result.status, "succeeded")
                self.assertTrue(result.exit_accepted)

    async def test_post_denial_stdout_is_suppressed(self):
        async def spawn(*args, **kwargs):
            proc = SyntheticProcess(b"", b"sudo: incorrect password\n", 1)
            proc.stdout = asyncio.StreamReader()
            async def deliver():
                await asyncio.sleep(0)
                await asyncio.sleep(0)
                proc.stdout.feed_data(b"unconfirmed after denial")
                proc.stdout.feed_eof()
            asyncio.create_task(deliver())
            return proc
        with patch("app.ssh_executor._spawn_ssh_command",
                   side_effect=spawn):
            result = await self.executor._execute_approved_privileged(
                "operator", self.request,
            )
        self.assertEqual(result.status, "command_error")
        self.assertEqual(result.stdout, "")

    async def test_sudo_timeout_kills_ssh_and_does_not_retry(self):
        req = self.request.model_copy(update={"timeout_seconds": 1})
        result, calls, processes = await self.run_synthetic(
            request=req, blocked=True,
        )
        self.assertEqual(result.status, "timed_out")
        self.assertTrue(result.root_started)
        self.assertTrue(processes[0].killed)
        self.assertEqual(len(calls), 1)

    async def test_expired_privileged_deadline_does_not_spawn_ssh(self):
        import time
        with patch("app.ssh_executor._spawn_ssh_command") as spawn:
            result = await self.executor._run(
                self.host, self.request, time.monotonic() - 120,
                None, sudo_password=PASSWORD,
            )
            spawn.assert_not_called()
        self.assertEqual(result.status, "timed_out")
        self.assertIsNone(result.root_started)

    async def test_ordinary_ssh_deadline_includes_connection_open_and_execution(self):
        request = self.request.model_copy(update={
            "privileged": False, "timeout_seconds": 3,
        })
        import asyncio as asyncio_library
        actual_wait_for = asyncio_library.wait_for
        limits: list[float] = []

        async def capture_wait_for(awaitable, timeout):
            limits.append(timeout)
            return await actual_wait_for(awaitable, timeout)

        async def spawn(*args, **kwargs):
            self.assertEqual(kwargs["stdin"], asyncio.subprocess.DEVNULL)
            return SyntheticProcess(b"ordinary-output", b"", 0)

        with patch("app.ssh_executor._spawn_ssh_command",
                   side_effect=spawn), patch(
                   "app.ssh_executor.asyncio.wait_for", side_effect=capture_wait_for):
            result = await self.executor.execute("operator", request)
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(result.stdout, "ordinary-output")
        self.assertEqual(len(limits), 2)
        self.assertTrue(all(0 < limit <= 3 for limit in limits))
        self.assertLessEqual(limits[1], limits[0])

    async def test_policy_credentials_and_actor_fail_before_ssh(self):
        for policy, credentials, actor in (
            ("none", {"test": PASSWORD}, "operator"),
            ("restricted", {}, "operator"),
            ("restricted", {"test": ""}, "operator"),
            ("restricted", {"test": 12}, "operator"),
            ("restricted", {"test": PASSWORD}, "other"),
        ):
            with self.subTest(policy=policy,actor=actor,credentials=bool(credentials)):
                host = self.host.model_copy(update={"privileged_access": policy})
                client = SSHExecutor({"test": host}, enabled=True,
                                     sudo_passwords=credentials)
                with patch("app.ssh_executor._spawn_ssh_command") as spawn:
                    with self.assertRaises(SSHDenied):
                        await client._execute_approved_privileged(actor, self.request)
                    spawn.assert_not_called()

    async def test_root_metadata_is_persistent_after_admitted_transport(self):
        store = JobStore(self.base / "jobs" / "audit.sqlite")
        job_id = store.create("operator", self.request, mode="sync")
        manager = JobManager(self.executor, store)
        async def root_mock(actor, request, *, on_output=None, on_admitted=None):
            if on_admitted is not None:
                on_admitted()
            if on_output is not None:
                await on_output("stdout", b"ok\n")
            return SSHResult(
                request.server, "succeeded", 0, "ok\n", "", .01,
                root_started=True,
            )
        with patch.object(self.executor, "_execute_approved_privileged",
                          side_effect=root_mock):
            result = await manager._run(
                job_id, "operator", self.request, admitted_root=True,
            )
        self.assertEqual(result.status, "succeeded")
        reopened = JobStore(store.path)
        detail = HistoryStore(reopened).detail(job_id)
        self.assertTrue(detail["root_started"])
        self.assertTrue(detail["privileged"])
        self.assertEqual(detail["run_as"], "root")
        self.assertEqual(detail["request"]["argv"], self.request.argv)
        self.assertNotIn("sudo -S", json.dumps(detail))

    async def test_root_output_audit_failure_is_uncertain_not_command_failure(self):
        store = JobStore(self.base / "private" / "output-failure.sqlite")
        manager = JobManager(self.executor, store)

        async def root_stream(actor, request, *, on_output=None, on_admitted=None):
            if on_admitted is not None:
                on_admitted()
            self.assertIsNotNone(on_output)
            await on_output("stdout", b"first emitted bytes")
            await on_output("stderr", b"second emitted bytes")
            return SSHResult(
                request.server, "succeeded", 0, "", "", .01,
                root_started=True,
            )

        append = store.append
        writes = 0

        def fail_second_output(job_id, stream, block):
            nonlocal writes
            writes += 1
            if writes == 2:
                raise sqlite3.OperationalError("synthetic private database path")
            return append(job_id, stream, block)

        with (patch.object(self.executor, "_execute_approved_privileged",
                           side_effect=root_stream),
              patch.object(store, "append", side_effect=fail_second_output)):
            submitted = manager.submit("operator", self.request, admitted_root=True)
            await manager._tasks[submitted["id"]]
        saved = JobStore(store.path).get("operator", submitted["id"])
        self.assertEqual(saved["status"], "interrupted")
        self.assertEqual(saved["failure_kind"], "execution_uncertain")
        self.assertIsNone(saved["exit_code"])
        self.assertEqual(saved["output_bytes"], len(b"first emitted bytes"))
        self.assertIn("before retrying", saved["error"])
        self.assertNotIn("private database path", str(saved))
        self.assertEqual(HistoryStore(JobStore(store.path)).detail(submitted["id"])[
            "status"], "interrupted")

    async def test_sudo_auth_error_kind_is_durable_but_diagnostic_is_redacted(self):
        store = JobStore(self.base / "private" / "errors.sqlite")
        job_id = store.create("operator", self.request, mode="sync")
        manager = JobManager(self.executor, store)
        async def refused(actor, request, *, on_output=None, on_admitted=None):
            if on_admitted is not None:
                on_admitted()
            return SSHResult(
                request.server, "command_error", 1, "",
                "Sudo rejected execution", .01,
                failure_kind="sudo_authentication",
            )
        with patch.object(self.executor, "_execute_approved_privileged",
                          side_effect=refused):
            result = await manager._run(
                job_id, "operator", self.request, admitted_root=True,
            )
        self.assertEqual(result.failure_kind, "sudo_authentication")
        detail = HistoryStore(JobStore(store.path)).detail(job_id)
        self.assertEqual(detail["status"], "failed")
        self.assertIsNone(detail["root_started"])
        self.assertEqual(detail["error"], "Sudo rejected execution")
        self.assertEqual(detail["failure_kind"], "sudo_authentication")
        self.assertNotIn("SECRET DETAIL", json.dumps(detail))

    async def test_failure_kind_column_migrates_legacy_jobs(self):
        store = JobStore(self.base / "legacy" / "jobs.sqlite")
        old_id = store.create("operator", self.request)
        with store._connect() as db:
            db.execute("DROP VIEW history_events")
            db.execute("ALTER TABLE jobs DROP COLUMN failure_kind")
        restored = JobStore(store.path)
        self.assertEqual(restored.get("operator", old_id)["failure_kind"], "none")
        self.assertEqual(HistoryStore(restored).detail(old_id)["failure_kind"], "none")


class SudoWrapperTests(unittest.TestCase):
    def test_root_wrapper_verifies_effective_uid_before_markers(self):
        self.assertIn('if [ "$(/usr/bin/id -u)" != 0 ]; then exit 126; fi\n',
                      _ROOT_WRAPPER)
        sudo = _sudo_argv(["id", "-u"], "marker")
        self.assertEqual(sudo[6:8], ["-u", "root"])
        if os.geteuid() != 0:
            proc = subprocess.run(
                ["/bin/sh", "-c", _ROOT_WRAPPER, "ssh-mcp-root", "marker",
                 "sh", "-c", "echo forbidden"],
                capture_output=True, check=False,
            )
            self.assertEqual(proc.returncode, 126)
            self.assertEqual(proc.stdout, b"")
            self.assertNotIn(b"SSH-MCP-ROOT", proc.stderr)

    def test_fixed_wrapper_disowns_stdin_and_clears_inherited_environment(self):
        env = {**os.environ, "SKY267_SENSITIVE_FAKE": "never-reach-command",
               "HOME": "/tmp/synthetic-root-home"}
        script = (
            'printf "%s\\n" "$HOME" "$USER" "$LOGNAME" '
            '"${SKY267_SENSITIVE_FAKE-unset}"; '
            'if read -r line; then printf "LEAK:%s" "$line"; else printf "EOF"; fi'
        )
        # Only strip the UID guard inside this local *unprivileged* test.
        # Production code retains the guard and also requests "-u root".
        guard = 'if [ "$(/usr/bin/id -u)" != 0 ]; then exit 126; fi\n'
        self.assertIn(guard, _ROOT_WRAPPER)
        shell = _ROOT_WRAPPER.replace(guard, "")
        proc = subprocess.run(
            ["/bin/sh", "-c", shell, "ssh-mcp-root", "marker",
             "python3", "-c", _ROOT_EXEC, "marker", "",
             "/bin/sh", "-c", script],
            input=b"not-a-real-password\n", capture_output=True,
            env=env, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stderr, _framed_root_marker("marker")
                         + _framed_root_marker(_ROOT_READY_PREFIX + "marker"))
        self.assertEqual(proc.stdout, _root_stdout(
            "marker", b"/tmp/synthetic-root-home\nroot\nroot\nunset\nEOF"))

    def test_root_cwd_pins_directory_in_same_process(self):
        with tempfile.TemporaryDirectory() as directory:
            inside = subprocess.run(
                ["python3", "-c", _ROOT_EXEC, "nonce", directory, "pwd"],
                capture_output=True, check=False, text=True,
            )
            self.assertEqual(inside.returncode, 0, inside.stderr)
            self.assertEqual(inside.stdout.strip(), directory)
            self.assertEqual(inside.stderr.encode(),
                             _framed_root_marker(_ROOT_READY_PREFIX + "nonce"))
            denied = subprocess.run(
                ["python3", "-c", _ROOT_EXEC, "nonce",
                 directory + "/missing", "echo", "must-not-run"],
                capture_output=True, check=False, text=True,
            )
            self.assertEqual(denied.returncode, 126)
            self.assertEqual(denied.stderr.encode(),
                             _framed_root_marker(_ROOT_FAILED_PREFIX + "nonce"))
            self.assertNotIn("must-not-run", denied.stdout)
            missing_command = subprocess.run(
                ["python3", "-c", _ROOT_EXEC, "nonce", directory,
                 "/definitely/missing/sky267-program"],
                capture_output=True, check=False,
            )
            self.assertEqual(missing_command.returncode, 127)
            self.assertEqual(
                missing_command.stderr,
                _framed_root_marker(_ROOT_READY_PREFIX + "nonce")
                + _framed_root_marker(_ROOT_FAILED_PREFIX + "nonce"),
            )

    def test_passwords_are_bounded_one_line_and_never_in_argv(self):
        for invalid in ("", "line\nbreak", "line\rbreak", "nul\x00", "x" * 4097,
                        "\ud800", "surrogate\udfff", None, 7):
            self.assertFalse(_usable_sudo_password(invalid))
        self.assertTrue(_usable_sudo_password("a;&$' unicode😀"))
        argv = _sudo_argv(["sh", "-c", "echo hi;$(id)"], "marker")
        self.assertNotIn(PASSWORD, repr(argv))
        self.assertIn("exec </dev/null", argv[11])
        self.assertEqual(argv[-3:], ["sh", "-c", "echo hi;$(id)"])

    def test_fixed_secret_file_loads_valid_entries_without_environment_export(self):
        from app.ssh_executor import SSHExecutor
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            key = root / "key"
            pins = root / "known"
            inv = root / "inventory"
            secrets = root / "secrets.json"
            key.write_text("synthetic")
            key.chmod(0o600)
            pins.write_text("host.example.invalid ssh-ed25519 SYNTHETIC\n")
            pins.chmod(0o644)
            inv.write_text(json.dumps({"version": 1, "hosts": [{
                "alias": "lab", "address": "host.example.invalid", "port": 22,
                "username": "gateway", "principals": ["operator"],
                "environment": "non-production", "access": "always-granted",
                "privileged_access": "restricted", "identity_file": str(key),
                "known_hosts_file": str(pins), "max_parallel": 1,
            }]}))
            inv.chmod(0o644)
            secrets.write_text(json.dumps({"sudo_passwords": {
                "lab": PASSWORD, "removed-host": "stale-synthetic",
            }}))
            secrets.chmod(0o600)
            env = {"SSH_EXECUTOR_ENABLED": "true", "SSH_INVENTORY_FILE": str(inv),
                   "SSH_APPROVED_ALIASES": "lab"}
            with patch.dict(os.environ, env, clear=True), patch.object(runtime_files, "SECRETS", secrets):
                executor = SSHExecutor.from_environment()
            self.assertEqual(executor.list_servers("operator"), ["lab"])
            self.assertEqual(executor._sudo_passwords["lab"], PASSWORD)
            self.assertNotIn("removed-host", executor._sudo_passwords)
            self.assertNotIn(PASSWORD, repr(env))
            # A JSON-decodable unpaired surrogate in one host must not take
            # down the service or affect other approved SSH hosts.
            secrets.write_text(json.dumps({"sudo_passwords": {
                "lab": "\ud800", "removed-host": "synthetic-stale",
            }}))
            with patch.dict(os.environ, env, clear=True), patch.object(
                runtime_files, "SECRETS", secrets,
            ):
                still_running = SSHExecutor.from_environment()
            self.assertEqual(still_running.list_servers("operator"), ["lab"])
            self.assertEqual(still_running._sudo_passwords, {})
            secrets.write_text(json.dumps({"sudo_passwords": []}))
            with patch.dict(os.environ, env, clear=True), patch.object(runtime_files, "SECRETS", secrets):
                with self.assertRaisesRegex(SSHDenied, "configuration is invalid"):
                    SSHExecutor.from_environment()


if __name__ == "__main__":
    unittest.main()
