"""Regressions for the six independent SKY-355 security and reliability findings."""
from __future__ import annotations

import ast
import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.host_relay import (
    HostRelayService, RelayFailure, _argv, _receipt, _ready, _receiver_rejection,
    _sudo_challenge_line, _sudo_prompt,
)
from app.relay_scripts import SOURCE, RECEIVER
from app.ssh_executor import SSHDenied
from tests.unit import test_host_relay_service as fixtures

Audit = fixtures.Audit
Executor = fixtures.Executor
local_command = fixtures.local_command


def raw_writer(script: str):
    """Compile only the shipped remote helper's trusted write_all function."""
    module = ast.parse(script)
    method = next(node for node in module.body
                  if isinstance(node, ast.FunctionDef) and node.name == "write_all")
    namespace: dict = {}
    exec(compile(ast.Module(body=[method], type_ignores=[]), "<relay helper>", "exec"),
         namespace)  # noqa: S102 - the fixed, repository-owned helper, no caller data
    return namespace["write_all"]


class RawWriteTests(unittest.TestCase):
    def test_both_helpers_retry_partial_writes(self) -> None:
        class ShortWriter:
            def __init__(self) -> None:
                self.data = bytearray()
                self.calls = 0

            def write(self, block):
                self.calls += 1
                n = min(3, len(block))
                self.data.extend(block[:n])
                return n

        payload = bytes(range(90))
        for script in (SOURCE, RECEIVER):
            with self.subTest(script=script[:30]):
                writer = ShortWriter()
                raw_writer(script)(writer, payload)
                self.assertEqual(writer.data, payload)
                self.assertGreater(writer.calls, 1)

    def test_both_helpers_reject_stalled_raw_writer(self) -> None:
        for script in (SOURCE, RECEIVER):
            for result in (None, 0, -1):
                with self.subTest(script=script[:25], result=result):
                    with self.assertRaises(OSError):
                        raw_writer(script)(SimpleNamespace(write=lambda _: result), b"data")


class FramingTests(unittest.IsolatedAsyncioTestCase):
    async def test_fragmented_receipt_drains_to_eof(self) -> None:
        reader = asyncio.StreamReader()

        async def sender() -> None:
            for fragment in (b'{"ok": ', b'true, "size": ', b'3, "sha256": ',
                             b'"' + b"a" * 64 + b'"}\n'):
                reader.feed_data(fragment)
                await asyncio.sleep(0.02)
            reader.feed_eof()

        task = asyncio.create_task(sender())
        try:
            content = await _receipt(reader)
        finally:
            await task
        self.assertEqual(
            content, b'{"ok": true, "size": 3, "sha256": "' + b"a" * 64 + b'"}\n'
        )

    async def test_receipt_aborts_on_oversized_response(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"a" * 1025)
        reader.feed_eof()
        with self.assertRaises(RelayFailure) as raised:
            await _receipt(reader)
        self.assertTrue(raised.exception.uncertain)
        self.assertEqual(raised.exception.code, "invalid_response")

    def test_sudo_challenge_requires_prompt_position(self) -> None:
        p = _sudo_prompt("DEST-test").encode()
        self.assertFalse(_sudo_challenge_line(b"sudo -p " + p, p))
        self.assertFalse(_sudo_challenge_line(b"sudo failed " + p + b"suffix", p))
        self.assertFalse(_sudo_challenge_line(b"prefix" + p, p))
        self.assertTrue(_sudo_challenge_line(p, p))
        self.assertTrue(_sudo_challenge_line(b"banner\n" + p, p))
        self.assertTrue(_sudo_challenge_line(b"[sudo: " + p + b"] PAM challenge", p))

    async def test_sudo_second_prompt_suspends_and_fails_immediately(self) -> None:
        class Readiness:
            calls = []
            def suspend(self, alias):
                self.calls.append(alias)
        ready = Readiness()
        reader = asyncio.StreamReader()
        reader.feed_data(b"Sorry, try again.\n" + _sudo_prompt("DEST-abc").encode())
        reader.feed_eof()
        with self.assertRaises(RelayFailure) as raised:
            await asyncio.wait_for(_ready(reader, "DEST-abc",
                        sudo_prompt=_sudo_prompt("DEST-abc"),
                        readiness=ready, alias="demo-node-b"), 1)
        self.assertEqual(raised.exception.code, "permission_denied")
        self.assertEqual(ready.calls, ["demo-node-b"])

    async def test_sudo_failure_diagnostic_without_reprompt_suspends(self) -> None:
        class Readiness:
            calls = []
            def suspend(self, alias):
                self.calls.append(alias)
        ready = Readiness()
        reader = asyncio.StreamReader()
        reader.feed_data(b"sudo: authentication failure\n")
        with self.assertRaises(RelayFailure):
            await asyncio.wait_for(_ready(reader, "SRC-abc",
                sudo_prompt=_sudo_prompt("SRC-abc"),
                readiness=ready, alias="demo-node-a"), 1)
        self.assertEqual(ready.calls, ["demo-node-a"])

    async def test_sudo_retry_without_readiness_monitor_fails_closed(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(_sudo_prompt("DEST-no-monitor").encode())
        reader.feed_eof()
        with self.assertRaises(RelayFailure) as raised:
            await _ready(reader, "DEST-no-monitor",
                         sudo_prompt=_sudo_prompt("DEST-no-monitor"))
        self.assertEqual(raised.exception.code, "permission_denied")

    def test_privileged_script_requires_unique_nonce_parameter(self) -> None:
        with self.assertRaisesRegex(ValueError, "marker missing"):
            _argv("pass", [], True)

    async def test_receiver_refusal_requires_confirmed_channel_and_clean_output(self) -> None:
        for code, expected in ((73, "already_exists"), (75, "precondition_failed")):
            for after_commit in (False, True):
                with self.subTest(code=code, after_commit=after_commit):
                    class Receiver:
                        channel_complete = True
                        stdout = asyncio.StreamReader()
                        async def wait(self) -> int:
                            return code
                    receiver = Receiver()
                    receiver.stdout.feed_eof()
                    with self.assertRaises(RelayFailure) as raised:
                        await _receiver_rejection(
                            receiver, after_commit=after_commit,
                        )  # type: ignore[arg-type]
                    self.assertEqual(raised.exception.code, expected)
                    self.assertFalse(raised.exception.uncertain)

        class Receiver:
            channel_complete = False
            stdout = asyncio.StreamReader()
            async def wait(self) -> int:
                return 73
        for receipt, complete in ((b"", False), (b"partial", True)):
            receiver = Receiver()
            receiver.channel_complete = complete
            receiver.stdout.feed_eof()
            with self.assertRaises(RelayFailure) as raised:
                await _receiver_rejection(
                    receiver, after_commit=True, receipt=receipt,
                )  # type: ignore[arg-type]
            self.assertEqual(raised.exception.code, "transport_error")
            self.assertTrue(raised.exception.uncertain)

    async def test_nonprivileged_readiness_unchanged(self) -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x1eSRC-abc\x1e\n")
        reader.feed_eof()
        await _ready(reader, "SRC-abc")


class SudoSafetyTests(unittest.IsolatedAsyncioTestCase):
    async def test_sealed_suspended_host_cannot_write_password(self) -> None:
        class Readiness:
            def password_suspended(self, alias):
                return alias == "demo-node-b"
        class E(Executor):
            _sealed_sudo = {"demo-node-b": "sealed"}
            readiness = Readiness()
        svc = HostRelayService(E(), Audit())  # type: ignore[arg-type]

        class Root:
            def require(self, *, actor, host):
                return "never-write"
        class Stdin:
            writes = []
            def write(self, data):
                self.writes.append(data)
            async def drain(self):
                return None
            def close(self):
                return None
        stdin = Stdin()
        reader = asyncio.StreamReader()
        reader.feed_data(_sudo_prompt("DEST-test").encode())
        with self.assertRaises(SSHDenied):
            await svc._sudo(SimpleNamespace(stderr=reader, stdin=stdin),
                "operator", "demo-node-b", Root(), marker="DEST-test")  # type: ignore[arg-type]
        self.assertEqual(stdin.writes, [])

    async def test_passwordless_root_detected_as_host_safety_violation(self) -> None:
        class Readiness:
            unsafe = []
            def mark_passwordless_root(self, alias):
                self.unsafe.append(alias)
        class E(Executor):
            readiness = Readiness()
        svc = HostRelayService(E(), Audit())  # type: ignore[arg-type]
        svc.executor._sudo_passwords = {"demo-node-b": "fixture"}
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x1eDEST-test\x1e\n")
        reader.feed_eof()
        writes = []
        stdin = SimpleNamespace(write=lambda b: writes.append(b),
            drain=lambda: asyncio.sleep(0), close=lambda: None)
        with self.assertRaises(SSHDenied):
            await svc._sudo(SimpleNamespace(stderr=reader, stdin=stdin),
                "operator", "demo-node-b", None, marker="DEST-test")
        self.assertEqual(svc.executor.readiness.unsafe, ["demo-node-b"])
        self.assertEqual(writes, [])


    async def test_oversized_sudo_prechallenge_diagnostics_fail_closed(self) -> None:
        class E(Executor):
            _sudo_passwords = {"demo-node-b": "fake"}
        svc = HostRelayService(E(), Audit())  # type: ignore[arg-type]
        reader = asyncio.StreamReader()
        reader.feed_data(b"UNTRUSTED-" * 512)
        reader.feed_eof()
        sent = []
        stdin = SimpleNamespace(write=lambda data: sent.append(data),
            drain=lambda: asyncio.sleep(0), close=lambda: None)
        with self.assertRaisesRegex(SSHDenied, "challenge invalid"):
            await svc._sudo(SimpleNamespace(stdin=stdin, stderr=reader),
                            "operator", "demo-node-b", None, marker="DEST-nope")
        self.assertFalse(sent)

    async def test_suspended_after_sudo_challenge_never_sends_credential(self) -> None:
        class Readiness:
            attempts = 0
            def password_suspended(self, _alias):
                self.attempts += 1
                return self.attempts >= 2
        class E(Executor):
            _sealed_sudo = {"demo-node-b": "sealed"}
            readiness = Readiness()
        class Root:
            def require(self, *, host, actor):
                return "never-sent"
        svc = HostRelayService(E(), Audit())  # type: ignore[arg-type]
        reader = asyncio.StreamReader()
        reader.feed_data(_sudo_prompt("DEST-after").encode())
        sent = []
        stdin = SimpleNamespace(write=lambda data: sent.append(data),
            drain=lambda: asyncio.sleep(0), close=lambda: None)
        with self.assertRaisesRegex(SSHDenied, "suspended"):
            await svc._sudo(SimpleNamespace(stdin=stdin, stderr=reader),
                            "operator", "demo-node-b", Root(),
                            marker="DEST-after")  # type: ignore[arg-type]
        self.assertEqual(svc.executor.readiness.attempts, 2)
        self.assertFalse(sent)


class ShutdownAndProgressTests(unittest.IsolatedAsyncioTestCase):
    """Reuse the synthetic host fixture without rerunning its own tests."""
    setUp = fixtures.ServiceTests.setUp
    request = fixtures.ServiceTests.request


    async def test_shutdown_during_transfer_releases_resources(self) -> None:
        class ConditionalAudit(Audit):
            def finish(self, *args, **kwargs):
                if self.status == "running":
                    super().finish(*args, **kwargs)
        audit = ConditionalAudit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]
        entered = asyncio.Event()
        async def stalled(*_args, **_kwargs):
            entered.set()
            await asyncio.Future()
        with patch("app.host_relay.open_command", stalled):
            await service.transfer(
                "operator", self.request(wait_seconds=0),
                precreated_id="relay1", roots=(None, None),
            )
            await asyncio.wait_for(entered.wait(), 2)
            await asyncio.wait_for(service.shutdown(), 5)
        self.assertEqual(audit.status, "cancelled")
        self.assertFalse(service._active)
        with self.assertRaises(RuntimeError):
            await service.transfer("operator", self.request(),
                                   precreated_id="relay1", roots=(None, None))

    async def test_shutdown_immediately_after_schedule_finishes_audit(self) -> None:
        audit = Audit()
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]
        class Root:
            finish_count = 0
            def delegate(self):
                pass
            def finish(self):
                self.finish_count += 1
        root = Root()
        result = await service.transfer("operator", self.request(wait_seconds=0),
            precreated_id="relay1", roots=(root, None))  # type: ignore[arg-type]
        self.assertEqual(result["status"], "running")
        await service.shutdown()
        self.assertEqual(audit.status, "unknown")
        self.assertEqual(root.finish_count, 1)

    async def test_suspended_sealed_host_denied_before_transport(self) -> None:
        class Readiness:
            def password_suspended(self, alias):
                return alias == "demo-node-b"
        class E(Executor):
            _sealed_sudo = {"demo-node-b": "sealed"}
            readiness = Readiness()
            def authorized_host(self, actor, alias):
                host = super().authorized_host(actor, alias)
                host.privileged_access = "restricted"
                return host
        class Root:
            def delegate(self):
                pass
            def finish(self):
                pass
        audit = Audit()
        svc = HostRelayService(E(), audit)  # type: ignore[arg-type]
        with patch("app.host_relay.open_command") as opener:
            result = await svc.transfer("operator",
                self.request(dest_privileged=True),
                precreated_id="relay1",
                roots=(None, Root()))  # type: ignore[arg-type]
            opener.assert_not_called()
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["error"]["code"], "transport_error")

    async def test_large_transfer_throttles_sqlite_progress(self) -> None:
        from app import config
        self.source.write_bytes(b"Q" * (2 * 1024 * 1024))
        audit = Audit()
        calls = []
        original_progress = audit.progress
        def count(identifier, count, total):
            calls.append(count)
            original_progress(identifier, count, total)
        audit.progress = count
        service = HostRelayService(Executor(), audit)  # type: ignore[arg-type]
        with patch("app.host_relay.open_command", local_command), patch.object(
            config, "SSH_TRANSFER_CHUNK_BYTES", 4096,
        ), patch.object(config, "SSH_TRANSFER_MAX_BYTES", 4 * 1024 * 1024):
            result = await service.transfer("operator", self.request(),
                precreated_id="relay1", roots=(None, None))
        self.assertEqual(result["status"], "succeeded", result)
        self.assertEqual(self.dest.read_bytes(), self.source.read_bytes())
        self.assertLess(len(calls), 16)  # 512 chunks, not 512 SQLite commits.
        self.assertEqual(calls[-1], 2 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
