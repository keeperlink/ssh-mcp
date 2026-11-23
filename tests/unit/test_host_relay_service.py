"""Real local source/receiver processes through a fake SSH-channel seam.

No SSH access, root permissions or ambient network are needed.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
import shlex
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.contracts import TransferFileRequest
from app.host_relay import (
    HostRelayService, RelayFailure, _argv, _close_channel, _exact,
    _finish_channel, _ready,
)


class LocalConnection:
    def __init__(self, process: asyncio.subprocess.Process):
        self.process = process

    def abort(self) -> None:
        if self.process.returncode is None:
            self.process.kill()

    async def wait_closed(self) -> None:
        await self.process.wait()


class LocalChannel:
    def __init__(self, process: asyncio.subprocess.Process):
        self.process = process
        self.stdin = process.stdin
        self.stdout = process.stdout
        self.stderr = process.stderr
        self.connection = LocalConnection(process)
        self.channel_complete = False

    async def wait(self) -> int:
        result = await self.process.wait()
        self.channel_complete = True
        return result


async def local_command(_host: object, command: str, *, allow_stdin: bool) -> LocalChannel:
    process = await asyncio.create_subprocess_exec(
        *shlex.split(command),
        stdin=asyncio.subprocess.PIPE if allow_stdin else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    return LocalChannel(process)


class Executor:
    _sudo_passwords: dict[str, str] = {}
    _sealed_sudo: dict[str, str] = {}

    def __init__(self) -> None:
        self._global = asyncio.Semaphore(3)
        self._semaphores = {
            "demo-node-a": asyncio.Semaphore(2),
            "demo-node-b": asyncio.Semaphore(2),
        }

    def authorized_host(self, actor: str, alias: str) -> SimpleNamespace:
        if actor != "operator" or alias not in self._semaphores:
            raise ValueError("Host not authorized")
        return SimpleNamespace(alias=alias, privileged_access="none")

    def require_ready(self, alias: str, *, privileged: bool = False) -> None:
        if privileged:
            raise ValueError("Privileged not authorized")


class Audit:
    def __init__(self) -> None:
        self.status = "running"
        self.byte_count = 0
        self.transfer: dict | None = None

    def start(self, *_args: object, precreated_id: str | None = None) -> str:
        return precreated_id or "relay1"

    def get(self, actor: str, identifier: str) -> dict | None:
        if actor == "operator" and identifier == "relay1":
            return {"operation_kind": "transfer", "status": self.status}
        return None

    def progress(self, identifier: str, byte_count: int, total: int) -> None:
        assert identifier == "relay1" and byte_count <= total
        self.byte_count = byte_count

    def finish(self, identifier: str, status: str, *, byte_count: int = 0,
               error_code: str | None = None, transfer: dict | None = None) -> None:
        assert identifier == "relay1"
        self.status, self.byte_count, self.transfer = status, byte_count, transfer


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.source = self.root / "original"
        self.dest = self.root / "received"
        self.source.write_bytes(b"payload " * 1024)

    def request(self, **overrides: object) -> TransferFileRequest:
        payload = {
            "source_server": "demo-node-a", "source_path": str(self.source),
            "dest_server": "demo-node-b", "dest_path": str(self.dest),
            "reason": "Synthetic transfer unit fixture", "wait_seconds": 30,
        }
        payload.update(overrides)
        return TransferFileRequest.model_validate(payload)

    async def run_transfer(self, req: TransferFileRequest) -> tuple[dict, Audit]:
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]
        with patch("app.host_relay.open_command", local_command):
            result = await service.transfer(
                "operator", req, precreated_id="relay1", roots=(None, None),
            )
        return result, audit

    async def test_end_to_end_integrity_and_no_content_in_result(self) -> None:
        result, audit = await self.run_transfer(self.request())
        self.assertEqual(result["status"], "succeeded", result)
        self.assertEqual(self.dest.read_bytes(), self.source.read_bytes())
        self.assertEqual(audit.byte_count, self.source.stat().st_size)
        self.assertEqual(audit.transfer["direction"], "relay")
        self.assertNotIn("payload", str(result))
        self.assertNotIn(self.source.read_bytes().decode()[:40], str(audit.transfer))

    async def test_checked_overwrite(self) -> None:
        import hashlib

        self.dest.write_bytes(b"before")
        original_sha = hashlib.sha256(b"before").hexdigest()
        result, _ = await self.run_transfer(self.request(
            mode="overwrite", expected_sha256=original_sha,
        ))
        self.assertEqual(result["status"], "succeeded", result)
        self.assertEqual(self.dest.read_bytes(), self.source.read_bytes())

    async def test_wrong_source_checksum_is_fail_closed(self) -> None:
        result, audit = await self.run_transfer(self.request(source_sha256="0" * 64))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(audit.status, "failed")
        self.assertFalse(self.dest.exists())

    async def test_running_poll_and_cancel_before_destination(self) -> None:
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]
        entered = asyncio.Event()

        async def stalled(*_args: object, **_kwargs: object) -> LocalChannel:
            entered.set()
            await asyncio.Future()
            raise AssertionError("not reached")

        with patch("app.host_relay.open_command", stalled):
            result = await service.transfer(
                "operator", self.request(wait_seconds=0),
                precreated_id="relay1", roots=(None, None),
            )
            self.assertEqual(result["status"], "running")
            await asyncio.wait_for(entered.wait(), timeout=3)
            job_id = result["history_id"]
            task = service._active[job_id]
            self.assertEqual(
                (await service.cancel("operator", job_id))["cancellation_requested"], True,
            )
            final = await asyncio.wait_for(task, timeout=5)
            self.assertEqual(final["status"], "cancelled")
            self.assertEqual(audit.status, "cancelled")
            self.assertFalse(self.dest.exists())

    async def test_missing_source_fails_without_publishing(self) -> None:
        self.source.unlink()
        result, audit = await self.run_transfer(self.request())
        self.assertEqual(result["status"], "failed", result)
        self.assertFalse(self.dest.exists())
        self.assertEqual(audit.status, "failed")

    async def test_collision_and_wrong_preimage_preserve_target(self) -> None:
        self.dest.write_bytes(b"existing")
        collision, _ = await self.run_transfer(self.request())
        self.assertEqual(collision["status"], "failed", collision)
        wrong, _ = await self.run_transfer(self.request(
            mode="overwrite", expected_sha256="f" * 64,
        ))
        self.assertEqual(wrong["status"], "failed", wrong)
        self.assertEqual(self.dest.read_bytes(), b"existing")

    async def test_transport_error_before_ssh_open_is_unknown(self) -> None:
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]

        async def broken(*_args: object, **_kwargs: object) -> LocalChannel:
            raise OSError("synthetic network failure")

        with patch("app.host_relay.open_command", broken):
            result = await service.transfer(
                "operator", self.request(), precreated_id="relay1",
                roots=(None, None),
            )
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["error"]["code"], "transport_error")

    async def test_transfer_timeout_is_unknown(self) -> None:
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]

        async def hung(*_args: object, **_kwargs: object) -> LocalChannel:
            await asyncio.Future()
            raise AssertionError("never resumes")

        with patch("app.host_relay.open_command", hung):
            result = await service.transfer(
                "operator", self.request(timeout_seconds=1, wait_seconds=2),
                precreated_id="relay1", roots=(None, None),
            )
        self.assertEqual(result["status"], "running")
        result = await asyncio.wait_for(service._active[result["history_id"]], timeout=5)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["error"]["code"], "timeout")

    async def test_cancellation_missing_or_terminal_job(self) -> None:
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]
        self.assertIsNone(await service.cancel("operator", "wrong_id"))
        self.assertIsNone(await service.cancel("other", "file_relay1"))
        with patch.object(audit, "get", return_value={
            "operation_kind": "read", "status": "running",
        }):
            self.assertIsNone(await service.cancel("operator", "file_relay1"))
        done = asyncio.get_running_loop().create_future()
        done.set_result({})
        service._active["file_relay1"] = done  # type: ignore[assignment]
        audit.status = "succeeded"
        result = await service.cancel("operator", "file_relay1")
        self.assertFalse(result["cancellation_requested"])
        self.assertEqual(result["status"], "succeeded")

    async def test_duplicate_operation_fails_without_remote_calls(self) -> None:
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]
        def duplicate(*_args: object, **_kwargs: object) -> str:
            raise ValueError("duplicate_operation")
        with patch.object(audit, "start", duplicate):
            result = await service.transfer(
                "operator", self.request(operation_id="duplicate_1234"),
                precreated_id="relay1", roots=(None, None),
            )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"]["code"], "duplicate_operation")
        with patch.object(audit, "start", side_effect=ValueError("other")):
            with self.assertRaisesRegex(ValueError, "other"):
                await service.transfer("operator", self.request(),
                                       precreated_id="relay1", roots=(None, None))

    async def test_privilege_policy_and_missing_unlock_fail_closed(self) -> None:
        class RootExecutor(Executor):
            _sealed_sudo = {"demo-node-b": "synthetic"}
            def authorized_host(self, actor: str, alias: str) -> SimpleNamespace:
                host = super().authorized_host(actor, alias)
                host.privileged_access = "restricted"
                return host
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]
        result = await service.transfer(
            "operator", self.request(dest_privileged=True),
            precreated_id="relay1", roots=(None, None),
        )
        self.assertEqual(result["status"], "unknown")
        audit = Audit()
        service = HostRelayService(RootExecutor(), audit)  # type: ignore[arg-type]
        result = await service.transfer(
            "operator", self.request(dest_privileged=True),
            precreated_id="relay1", roots=(None, None),
        )
        self.assertEqual(result["status"], "unknown")

    async def test_source_and_receiver_markers_are_bounded(self) -> None:
        from asyncio import StreamReader

        reader = StreamReader()
        reader.feed_data(b"prefix\\n\\x1ehello\\x1e\\n".decode(
            "unicode_escape").encode())
        reader.feed_eof()
        await _ready(reader, "hello")
        empty = StreamReader()
        empty.feed_eof()
        with self.assertRaisesRegex(RelayFailure, "transport_error"):
            await _ready(empty, "missing")
        big = StreamReader()
        big.feed_data(b"A" * 4096)
        big.feed_eof()
        with self.assertRaisesRegex(RelayFailure, "invalid_response"):
            await _ready(big, "missing")
        binary = StreamReader()
        binary.feed_data(b"AB")
        binary.feed_eof()
        with self.assertRaisesRegex(RelayFailure, "transport_error"):
            await _exact(binary, 4)
        self.assertEqual(await _exact(binary, 0), b"")

    async def test_channel_finish_and_cleanup_exceptions(self) -> None:
        class Channel:
            channel_complete = False
            async def wait(self):
                raise OSError("disconnected")
        self.assertFalse(await _finish_channel(Channel()))  # type: ignore[arg-type]
        self.assertFalse(await _finish_channel(
            SimpleNamespace(wait=lambda: asyncio.sleep(0, result=0),
                            channel_complete=False)  # type: ignore[arg-type]
        ))
        await _close_channel(None)
        class Connection:
            def abort(self):
                raise OSError("connection dropped")
        await _close_channel(SimpleNamespace(connection=Connection()))  # type: ignore[arg-type]

    def test_privileged_command_framing_has_no_password(self) -> None:
        argv = _argv("pass", ["/synthetic/path", "SRC-synthetic", "1"], True)
        self.assertIn("/usr/bin/sudo", argv)
        self.assertIn("-S", argv)
        self.assertIn("--", argv)
        self.assertNotIn("secret-password", argv)
        self.assertIn("/usr/bin/python3", _argv("test", [], False))

    async def test_privileged_stdin_requires_credential_and_unlock(self) -> None:
        class E(Executor):
            _sealed_sudo = {"demo-node-a": "opaque"}
        audit = Audit()
        service = HostRelayService(E(), audit)  # type: ignore[arg-type]
        proc = SimpleNamespace(stdin=SimpleNamespace(
            write=lambda data: None,
            drain=lambda: asyncio.sleep(0),
            close=lambda: None,
        ))
        from app.ssh_executor import SSHDenied
        with self.assertRaises(SSHDenied):
            await service._sudo(proc, "operator", "demo-node-a", None, marker="SRC-fixture")
        class Unlock:
            def require(self, *, host, actor):
                if host == "demo-node-a" and actor == "operator":
                    return "synthetic-password"
                raise ValueError("invalid")
        service.executor._sudo_passwords["demo-node-b"] = "another-password"
        written = []
        proc.stdin.write = lambda data: written.append(data)
        from app.host_relay import _sudo_prompt
        from asyncio import StreamReader
        def challenge(marker):
            stream = StreamReader()
            stream.feed_data(_sudo_prompt(marker).encode("ascii"))
            stream.feed_eof()
            proc.stderr = stream
        challenge("SRC-fixture")
        await service._sudo(proc, "operator", "demo-node-a", Unlock(), marker="SRC-fixture")  # type: ignore[arg-type]
        self.assertEqual(written[-1], b"synthetic-password\\n".decode(
            "unicode_escape").encode())
        challenge("DEST-fixture")
        await service._sudo(proc, "operator", "demo-node-b", None, marker="DEST-fixture", close=False)
        self.assertEqual(written[-1], b"another-password\\n".decode(
            "unicode_escape").encode())
        service.executor._sudo_passwords.clear()
        with self.assertRaises(SSHDenied):
            await service._sudo(proc, "operator", "demo-node-b", None, marker="DEST-fixture")
        service.executor._sudo_passwords["demo-node-b"] = "synthetic-password"
        with self.assertRaises(SSHDenied):
            await service._sudo(SimpleNamespace(stdin=None),
                                "operator", "demo-node-b", None, marker="DEST-fixture")
        service.executor._sudo_passwords.clear()

    async def test_cancelled_after_receiver_open_confirms_stage_cleanup(self) -> None:
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]
        draining = asyncio.Event()

        class SlowStdin:
            def __init__(self, writer):
                self.writer = writer
            def write(self, data):
                self.writer.write(data)
            async def drain(self):
                draining.set()
                await asyncio.Future()
            def close(self):
                self.writer.close()

        async def gated(host, command, *, allow_stdin):
            channel = await local_command(host, command, allow_stdin=allow_stdin)
            if "DEST-" in command:
                channel.stdin = SlowStdin(channel.stdin)
            return channel

        with patch("app.host_relay.open_command", gated):
            result = await service.transfer("operator", self.request(wait_seconds=0),
                                            precreated_id="relay1", roots=(None, None))
            self.assertEqual(result["status"], "running")
            await asyncio.wait_for(draining.wait(), 5)
            task = service._active[result["history_id"]]
            requested = await service.cancel("operator", result["history_id"])
            self.assertTrue(requested["cancellation_requested"])
            final = await asyncio.wait_for(task, 5)
        self.assertIn(final["status"], ("cancelled", "unknown"))
        self.assertEqual(audit.status, final["status"])
        self.assertFalse(self.dest.exists())
        self.assertFalse(list(self.root.glob(".ssh-mcp-transfer-*")))

    async def test_unknown_on_unconfirmed_destination_result(self) -> None:
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]

        class UnconfirmedChannel:
            def __init__(self, channel):
                self.connection = channel.connection
                self.stdin = channel.stdin
                self.stdout = channel.stdout
                self.stderr = channel.stderr
                self.channel_complete = True
                self.channel = channel
            async def wait(self):
                await self.channel.wait()
                return 1

        async def falsify(host, command, *, allow_stdin):
            channel = await local_command(host, command, allow_stdin=allow_stdin)
            if "DEST-" in command:
                return UnconfirmedChannel(channel)
            return channel

        with patch("app.host_relay.open_command", falsify):
            final = await service.transfer("operator", self.request(),
                                           precreated_id="relay1", roots=(None, None))
        self.assertEqual(final["status"], "unknown", final)
        self.assertEqual(final["error"]["code"], "transport_error")

    async def test_untrusted_receiver_success_response_is_unknown(self) -> None:
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]

        class BadResponse:
            def __init__(self, channel):
                self.connection = channel.connection
                self.stdin = channel.stdin
                self.stderr = channel.stderr
                self.channel = channel
                self.channel_complete = False
                self.stdout = self
                self.calls = 0
            async def read(self, n=-1):
                self.calls += 1
                if self.calls == 1:
                    return b"X"
                return b"invalid"
            async def wait(self):
                result = await self.channel.wait()
                self.channel_complete = self.channel.channel_complete
                return result

        async def malformed(host, command, *, allow_stdin):
            channel = await local_command(host, command, allow_stdin=allow_stdin)
            return BadResponse(channel) if "DEST-" in command else channel
        with patch("app.host_relay.open_command", malformed):
            final = await service.transfer("operator", self.request(),
                                           precreated_id="relay1", roots=(None, None))
        self.assertEqual(final["status"], "unknown", final)
        self.assertEqual(final["error"]["code"], "invalid_response")

    async def test_oversized_source_header_rejected_before_dest_open(self) -> None:
        import struct
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]
        opened = []

        class FakeHeader:
            def __init__(self, channel):
                self.channel = channel
                self.stdout = self
                self.stderr = channel.stderr
                self.connection = channel.connection
                self.stdin = channel.stdin
                self.channel_complete = False
                self.replied = False
            async def read(self, n=-1):
                if not self.replied:
                    self.replied = True
                    from app import config
                    return struct.pack(">Q", config.SSH_TRANSFER_MAX_BYTES + 1) + b"0" * 32
                return b""
            async def wait(self):
                result = await self.channel.wait()
                self.channel_complete = self.channel.channel_complete
                return result

        async def corrupt(host, command, *, allow_stdin):
            opened.append(command)
            channel = await local_command(host, command, allow_stdin=allow_stdin)
            return FakeHeader(channel)

        with patch("app.host_relay.open_command", corrupt):
            final = await service.transfer("operator", self.request(),
                                           precreated_id="relay1", roots=(None, None))
        self.assertEqual(final["status"], "failed")
        self.assertEqual(final["error"]["code"], "precondition_failed")
        self.assertEqual(len(opened), 1)

    async def test_unsupported_privileged_credential_never_emitted_to_audit(self) -> None:
        audit = Audit()
        executor = Executor()
        executor._sudo_passwords = {}
        service = HostRelayService(executor, audit)  # type: ignore[arg-type]
        from app.ssh_executor import SSHDenied
        with self.assertRaises(SSHDenied):
            await service._sudo(
                SimpleNamespace(stdin=None), "operator", "demo-node-b", None,
                marker="DEST-fixture",
            )
        self.assertIsNone(audit.transfer)

    async def test_both_privileged_endpoints_carry_independent_handles(self) -> None:
        import app.host_relay as host_relay
        audit = Audit()
        class PrivilegedExecutor(Executor):
            def authorized_host(self, actor: str, alias: str) -> SimpleNamespace:
                host = super().authorized_host(actor, alias)
                host.privileged_access = "always-granted"
                return host
            def require_ready(self, alias: str, *, privileged: bool = False) -> None:
                self.authorized_host("operator", alias)

        service = HostRelayService(PrivilegedExecutor(), audit)  # type: ignore[arg-type]
        class Handle:
            def __init__(self) -> None:
                self.delegated = False
                self.finished = 0
            def delegate(self) -> None:
                self.delegated = True
            def finish(self) -> None:
                self.finished += 1

        first, second = Handle(), Handle()
        original = host_relay._argv
        checked = []
        def unprivileged_fixture(script, args, privileged):
            checked.append(privileged)
            return original(script, [*args[:-1], "0"], False)
        async def approved_sudo(_service, _channel, _actor, alias, root, *, marker, close=True):
            checked.append((alias, root, close))

        with patch("app.host_relay.open_command", local_command), patch(
            "app.host_relay._argv", unprivileged_fixture,
        ), patch.object(HostRelayService, "_sudo", approved_sudo):
            result = await service.transfer(
                "operator", self.request(source_privileged=True, dest_privileged=True),
                precreated_id="relay1", roots=(first, second),  # type: ignore[arg-type]
            )
        self.assertEqual(result["status"], "succeeded", result)
        self.assertEqual(checked, [
            True, ("demo-node-a", first, True),
            True, ("demo-node-b", second, False),
        ])
        self.assertTrue(first.delegated and second.delegated)
        self.assertEqual((first.finished, second.finished), (1, 1))

    async def test_inflight_transfer_returns_after_wait_without_cancelling_worker(self) -> None:
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]
        entered = asyncio.Event()
        async def held(*_args, **_kwargs):
            entered.set()
            await asyncio.Future()
        with patch("app.host_relay.open_command", held):
            result = await service.transfer(
                "operator", self.request(wait_seconds=1, timeout_seconds=5),
                precreated_id="relay1", roots=(None, None),
            )
            self.assertEqual(result["status"], "running")
            await entered.wait()
            self.assertFalse(service._active[result["history_id"]].done())
            self.assertTrue((await service.cancel("operator", result["history_id"]))[
                "cancellation_requested"
            ])
            self.assertEqual(
                (await service._active[result["history_id"]])["status"], "cancelled",
            )

    async def test_unknown_while_receiver_cancellation_not_confirmed(self) -> None:
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]
        staged = asyncio.Event()

        class StallingReceiver:
            def __init__(self, channel):
                self.channel = channel
                self.connection = channel.connection
                self.stdout = channel.stdout
                self.stderr = channel.stderr
                self.stdin = channel.stdin
            async def wait(self):
                await asyncio.Future()
        async def opens(host, command, *, allow_stdin):
            channel = await local_command(host, command, allow_stdin=allow_stdin)
            if "DEST-" in command:
                staged.set()
                return StallingReceiver(channel)
            return channel

        with patch("app.host_relay.open_command", opens):
            result = await service.transfer(
                "operator", self.request(wait_seconds=0), precreated_id="relay1",
                roots=(None, None),
            )
            await asyncio.wait_for(staged.wait(), timeout=4)
            task = service._active[result["history_id"]]
            # The worker might have sent a commit by now: never claim a
            # confirmed cancellation without the receiver's status.
            self.assertTrue((await service.cancel(
                "operator", result["history_id"],
            ))["cancellation_requested"])
            final = await asyncio.wait_for(task, timeout=5)
            self.assertEqual(final["status"], "unknown")
            self.assertFalse(self.dest.exists())

    async def test_missing_destination_stdin_never_publishes(self) -> None:
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]
        class NoStdin:
            def __init__(self, channel):
                self.channel = channel
                self.connection = channel.connection
                self.stdout = channel.stdout
                self.stderr = channel.stderr
                self.stdin = None
                self.channel_complete = False
            async def wait(self):
                result = await self.channel.wait()
                self.channel_complete = self.channel.channel_complete
                return result
        async def opens(host, command, *, allow_stdin):
            channel = await local_command(host, command, allow_stdin=allow_stdin)
            return NoStdin(channel) if "DEST-" in command else channel
        with patch("app.host_relay.open_command", opens):
            final = await service.transfer(
                "operator", self.request(), precreated_id="relay1",
                roots=(None, None),
            )
        self.assertEqual(final["status"], "unknown")
        self.assertEqual(final["error"]["code"], "transport_error")
        self.assertFalse(self.dest.exists())

    async def test_corrupted_in_transit_payload_must_not_publish(self) -> None:
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]

        class CorruptReader:
            def __init__(self, source):
                self.source = source
                self.calls = 0
            async def read(self, n=-1):
                data = await self.source.read(n)
                self.calls += 1
                if self.calls == 2 and data:
                    return bytes([data[0] ^ 1]) + data[1:]
                return data
        async def corrupt(host, command, *, allow_stdin):
            channel = await local_command(host, command, allow_stdin=allow_stdin)
            if "SRC-" in command:
                channel.stdout = CorruptReader(channel.stdout)
            return channel
        with patch("app.host_relay.open_command", corrupt):
            result = await service.transfer("operator", self.request(),
                                            precreated_id="relay1", roots=(None, None))
        self.assertEqual(result["status"], "failed", result)
        self.assertEqual(result["error"]["code"], "changed_file")
        self.assertFalse(self.dest.exists())

    async def test_source_extra_bytes_after_declared_size_rejected(self) -> None:
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]
        class ExtraReader:
            def __init__(self, source):
                self.source = source
            async def read(self, n=-1):
                if n == 1:
                    return b"EXTRA"
                return await self.source.read(n)
        async def extra(host, command, *, allow_stdin):
            channel = await local_command(host, command, allow_stdin=allow_stdin)
            if "SRC-" in command:
                channel.stdout = ExtraReader(channel.stdout)
            return channel
        with patch("app.host_relay.open_command", extra):
            result = await service.transfer("operator", self.request(),
                                            precreated_id="relay1", roots=(None, None))
        self.assertEqual(result["status"], "unknown", result)
        self.assertEqual(result["error"]["code"], "changed_file")
        self.assertFalse(self.dest.exists())

    async def test_destination_success_frame_with_wrong_size_is_untrusted(self) -> None:
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]
        class WrongSize:
            def __init__(self, channel):
                self.channel = channel
                self.connection = channel.connection
                self.stdin = channel.stdin
                self.stderr = channel.stderr
                self.stdout = self
                self.channel_complete = False
                self.packet = b'{"ok":true,"size":999999,"sha256":"' + b"0" * 64 + b'"}\n'
            async def read(self, n=-1):
                data = self.packet[:n]
                self.packet = self.packet[len(data):]
                return data
            async def wait(self):
                result = await self.channel.wait()
                self.channel_complete = self.channel.channel_complete
                return result
        async def bad_reply(host, command, *, allow_stdin):
            channel = await local_command(host, command, allow_stdin=allow_stdin)
            return WrongSize(channel) if "DEST-" in command else channel
        with patch("app.host_relay.open_command", bad_reply):
            result = await service.transfer("operator", self.request(),
                                            precreated_id="relay1", roots=(None, None))
        self.assertEqual(result["status"], "unknown", result)
        self.assertEqual(result["error"]["code"], "invalid_response")

    async def test_canonical_destination_lock_reused_by_concurrent_tasks(self) -> None:
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]
        reached = asyncio.Event()
        async def stalled(*_args, **_kwargs):
            reached.set()
            await asyncio.Future()
        async def run_one(identifier: str, path: str):
            return await service._run(
                "operator", self.request(dest_path=path),
                identifier, (None, None),
            )
        with patch("app.host_relay.open_command", stalled), patch.object(
            audit, "finish", lambda *_args, **_kwargs: None,
        ):
            first = asyncio.create_task(run_one("relay1", str(self.dest)))
            await reached.wait()
            equivalent = str(self.root / "alias" / ".." / "received")
            second = asyncio.create_task(run_one("relay2", equivalent))
            await asyncio.sleep(0.05)
            self.assertEqual(len(service._locks), 1)
            self.assertFalse(first.done() or second.done())
            first.cancel()
            second.cancel()
            answers = await asyncio.gather(first, second)
            self.assertEqual([x["status"] for x in answers],
                             ["cancelled", "cancelled"])

    async def test_cancel_without_receiver_stdin_is_uncertain(self) -> None:
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]
        receiver_ready = asyncio.Event()
        class NeverReady:
            async def read(self, _n=-1):
                receiver_ready.set()
                await asyncio.Future()
        class LostStdin:
            def __init__(self, channel):
                self.channel = channel
                self.connection = channel.connection
                self.stdout = channel.stdout
                self.stderr = NeverReady()
                self.stdin = None
                self.channel_complete = False
            async def wait(self):
                result = await self.channel.wait()
                self.channel_complete = self.channel.channel_complete
                return result
        async def missing_stdin(host, command, *, allow_stdin):
            channel = await local_command(host, command, allow_stdin=allow_stdin)
            return LostStdin(channel) if "DEST-" in command else channel
        with patch("app.host_relay.open_command", missing_stdin):
            started = await service.transfer("operator", self.request(wait_seconds=0),
                                             precreated_id="relay1", roots=(None, None))
            await asyncio.wait_for(receiver_ready.wait(), timeout=5)
            task = service._active[started["history_id"]]
            self.assertTrue((await service.cancel(
                "operator", started["history_id"],
            ))["cancellation_requested"])
            result = await asyncio.wait_for(task, timeout=5)
        self.assertEqual(result["status"], "unknown")
        self.assertFalse(self.dest.exists())

    async def test_passwordless_sudo_marker_never_receives_plaintext_secret(self) -> None:
        from app.host_relay import _sudo_prompt
        class TrustedExecutor(Executor):
            _sudo_passwords = {"demo-node-a": "synthetic-secret"}
        service = HostRelayService(TrustedExecutor(), Audit())  # type: ignore[arg-type]
        from asyncio import StreamReader
        from app.ssh_executor import SSHDenied

        class Stdin:
            def __init__(self):
                self.written = []
            def write(self, data):
                self.written.append(data)
            async def drain(self):
                return None
            def close(self):
                return None

        stdin = Stdin()
        stderr = StreamReader()
        stderr.feed_data(b"\x1eSRC-nopass\x1e\n")
        stderr.feed_eof()
        proc = SimpleNamespace(stdin=stdin, stderr=stderr)
        with self.assertRaisesRegex(SSHDenied, "bypassed"):
            await service._sudo(proc, "operator", "demo-node-a", None,
                                marker="SRC-nopass")
        self.assertEqual(stdin.written, [])
        missing = StreamReader()
        missing.feed_eof()
        proc.stderr = missing
        with self.assertRaisesRegex(SSHDenied, "unavailable"):
            await service._sudo(proc, "operator", "demo-node-a", None,
                                marker="SRC-missing")
        self.assertEqual(stdin.written, [])
        valid = StreamReader()
        valid.feed_data(b"Banner\n" + _sudo_prompt("SRC-valid").encode("ascii"))
        valid.feed_eof()
        proc.stderr = valid
        await service._sudo(proc, "operator", "demo-node-a", None, marker="SRC-valid")
        self.assertEqual(stdin.written, [b"synthetic-secret\n"])

    async def test_native_channel_connection_error_reports_unknown(self) -> None:
        from app.ssh_channel import ChannelConnectionError
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]
        async def failed(*_args, **_kwargs):
            raise ChannelConnectionError("execution_uncertain")
        with patch("app.host_relay.open_command", failed):
            result = await service.transfer("operator", self.request(),
                                            precreated_id="relay1", roots=(None, None))
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["error"]["code"], "transport_error")
        self.assertEqual(audit.status, "unknown")

    def test_invalid_request_is_rejected(self) -> None:
        from pydantic import ValidationError

        for fields in (
            {"dest_server": "demo-node-a"},
            {"dest_path": "\x00bad"},
            {"source_path": "\x00bad"},
            {"mode": "create", "expected_sha256": "a" * 64},
            {"wait_seconds": 61},
        ):
            with self.subTest(fields=fields), self.assertRaises(ValidationError):
                self.request(**fields)


if __name__ == "__main__":
    unittest.main()
