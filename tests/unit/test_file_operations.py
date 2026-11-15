"""TEST-235 file infrastructure: payload-safe transport, audit and mixed viewer."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from app.file_audit import FileAudit, path_summary
from app.file_helper import dispatch, inspect, resolve_path
from app.file_ops import FileOperationRequest, FileService
from app.file_transport import FileTransport, FileTransportError, RemoteResult
from app.history import HistoryStore
from app.jobs import JobStore
from app.ssh_executor import HostSpec, SSHDenied, SSHExecutor


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.store = JobStore(Path(self.root.name) / "private" / "jobs.sqlite")
        self.audit = FileAudit(self.store)
        self.viewer = HistoryStore(self.store)

    def test_mixed_history_and_actor_scoping(self):
        key = self.audit.start("alice", "dev", "read", "/tmp/synthetic/file.txt",
                               "TEST-235", "test-op-001")
        self.audit.finish(key, "succeeded", byte_count=327,
                          outcomes=[{"path": "test.txt", "status": "applied", "bytes": 327}])
        record = self.audit.get("alice", key)
        self.assertEqual(record["path_summary"], "file.txt")
        self.assertEqual(record["byte_count"], 327)
        self.assertIsNone(self.audit.get("bob", key))
        row = self.viewer.list({})["jobs"][0]
        self.assertEqual(row["id"], "file_test-op-001")
        self.assertEqual(row["mode"], "file")
        self.assertEqual(row["record_kind"], "file")
        self.assertEqual(row["story_id"], "TEST-235")
        self.assertEqual(row["command_preview"], "read file.txt")
        details = self.viewer.detail(row["id"])
        self.assertEqual(details["file_metadata"]["outcomes"][0]["status"], "applied")
        self.assertIsNone(details["request"])
        self.assertIsNone(details["terminal_command"])
        self.assertEqual(self.viewer.output(row["id"])["chunks"], [])
        self.assertEqual(self.viewer.totals()["succeeded"], 1)
        self.assertEqual(self.viewer.list({"mode": "file"})["filtered_total"], 1)
        self.assertEqual(self.viewer.list({"command": "file.txt"})["filtered_total"], 1)
        self.assertEqual(self.viewer.list({"command": "read"})["filtered_total"], 1)
        self.assertEqual(self.viewer.list({"story_id": "235"})["filtered_total"], 1)
        self.assertEqual(self.viewer.list({"mode": "async"})["filtered_total"], 0)
        self.assertEqual(self.viewer.changes("0:_")["jobs"][0]["id"], row["id"])

    def test_payload_never_persisted(self):
        secret = "NON-PERSISTENT-TOP-SECRET-CONTENT-123456"
        key = self.audit.start("alice", "dev", "write", "/workspace/example.txt", None)
        self.audit.finish(key, "partial", error_code="precondition_failed",
                          outcomes=[{"path": "ok", "status": "applied", "bytes": 1},
                                    {"path": "bad", "status": "failed",
                                     "error_code": "invalid_patch"},
                                    {"path": "later", "status": "not_attempted"}])
        with self.store._connect() as db:
            rows = db.execute("SELECT * FROM file_operations").fetchall()
            self.assertEqual(len(rows), 1)
            self.assertNotIn(secret, str(dict(rows[0])))
            self.assertEqual(db.execute("SELECT COUNT(*) FROM output").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 0)
        detail = self.viewer.detail("file_" + key)
        self.assertEqual(len(detail["file_metadata"]["outcomes"]), 3)
        self.assertEqual(detail["status"], "partial")
        self.assertEqual(self.viewer.totals()["failed"], 1)
        with self.assertRaises(ValueError):
            self.viewer.output("file_" + key, cursor=1)

    def test_duplicate_operation_rejected_and_restart_unknown(self):
        key = self.audit.start("alice", "dev", "write", "/tmp/x", "TEST-235", "explicit-123")
        with self.assertRaisesRegex(ValueError, "duplicate_operation"):
            self.audit.start("alice", "dev", "write", "/tmp/x", "TEST-235", key)
        newstore = JobStore(self.store.path)
        status = FileAudit(newstore).get("alice", key)
        self.assertEqual(status["status"], "unknown")
        self.assertEqual(status["error_code"], "interrupted")
        with newstore._connect() as db:
            self.assertIsNotNone(db.execute(
                "SELECT ended_at FROM file_operations WHERE id=?", (key,)
            ).fetchone()[0])
        self.assertEqual(HistoryStore(newstore).list({"status": "unknown"})["filtered_total"], 1)

    def test_invalid_metadata_and_retention(self):
        for kind in ("execute", "shell"):
            with self.assertRaises(ValueError):
                self.audit.start("alice", "dev", kind, "/tmp/f", None)
        with self.assertRaises(ValueError):
            self.audit.start("alice", "dev", "read", "/tmp/f", None, "bad!")
        key = self.audit.start("alice", "dev", "read", "/tmp/f", None)
        with self.assertRaises(ValueError):
            self.audit.finish(key, "running")
        with self.assertRaises(ValueError):
            self.audit.finish(key, "succeeded", byte_count=-1)
        with self.assertRaises(ValueError):
            self.audit.finish(key, "failed", outcomes=[{"status": "injected"}])
        self.audit.finish(key, "failed", error_code="SENSITIVE_BOGUS_ERROR")
        self.assertEqual(self.audit.get("alice", key)["error_code"], "filesystem_error")
        with self.store._connect() as db:
            db.execute("UPDATE file_operations SET ended_at=1 WHERE id=?", (key,))
        self.assertEqual(self.store.prune(), 1)
        self.assertEqual(self.viewer.totals()["total"], 0)
        self.assertEqual(path_summary("/root/long/"), "long")

    def test_viewer_template_is_read_only_and_mixed(self):
        from app.history import ASSETS, _history_page
        body = _history_page("synthetic")
        self.assertIn("Command / File", body)
        self.assertIn('value="file"', body)
        self.assertNotIn('type="file"', body)
        js = (ASSETS / "console.js").read_text()
        self.assertIn('job.record_kind === "file"', js)
        self.assertIn("File operation details", js)
        self.assertNotIn("innerHTML", js)


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.path = Path(self.root.name)
        self.file = self.path / "fixture.txt"
        self.file.write_text("sample")

    def test_path_and_inspect(self):
        with patch("app.file_helper.Path.home", return_value=self.path):
            self.assertEqual(resolve_path("fixture.txt"), self.file)
            self.assertEqual(resolve_path("fixture.txt", "."), self.file)
            self.assertEqual(resolve_path("fixture.txt", str(self.path)), self.file)
            self.assertEqual(resolve_path("../fixture.txt", "a").resolve(), self.file)
            self.assertEqual(inspect({"path": "fixture.txt"})["size"], 6)
            self.assertEqual(inspect({"path": "missing"})["error"]["code"], "not_found")
            self.assertEqual(inspect({"path": "."})["kind"], "directory")
            self.assertEqual(dispatch({"protocol": 1, "operation": "inspect",
                                       "path": "fixture.txt"})["ok"], True)
            self.assertEqual(dispatch({"protocol": 2, "operation": "inspect"})["error"]["code"],
                             "invalid_protocol")
            self.assertEqual(dispatch({"protocol": 1, "operation": "unused"})["error"]["code"],
                             "unsupported_operation")
        for invalid in ("", "\x00"):
            with self.assertRaises(ValueError):
                resolve_path(invalid)
        with self.assertRaises(ValueError):
            inspect({"path": ["bad"]})

    def test_cli_does_not_leak_invalid_request(self):
        for raw in (b"not-json", b"[]"):
            process = subprocess.run(
                [sys.executable, "-c", "from app.file_helper import main; raise SystemExit(main())"],
                input=raw, capture_output=True,
            )
            result = json.loads(process.stdout)
            self.assertEqual(result["error"]["code"], "invalid_request")
            self.assertEqual(process.stderr, b"")


class FakeTransport:
    async def execute(self, actor, server, kind, data):
        return {"ok": True, "path": data["path"], "bytes": 7,
                "content": "DO_NOT_PERSIST_THIS_FILE_CONTENT"}


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        root = Path(self.root.name)
        identity = root / "key"
        known = root / "known"
        identity.write_text("synthetic")
        known.write_text("synthetic")
        identity.chmod(0o600)
        known.chmod(0o644)
        self.host = HostSpec(alias="dev", address="localhost", port=22, username="gateway",
                             identity_file=identity, known_hosts_file=known,
                             principals=["alice"], environment="non-production", access="always-granted")
        self.executor = SSHExecutor({"dev": self.host}, enabled=True)
        self.store = JobStore(root / "private" / "jobs.sqlite")
        self.service = FileService(self.executor, self.store, transport=FakeTransport())

    async def test_status_audit_payload_and_reuse(self):
        request = FileOperationRequest(server="dev", path="x.py", reason="synthetic",
                                       story_id="TEST-235", operation_id="my-operation")
        reply = await self.service.perform("alice", request, "inspect")
        self.assertEqual(reply["status"], "succeeded")
        self.assertEqual(reply["result"]["bytes"], 7)
        duplicate = await self.service.perform("alice", request, "inspect")
        self.assertEqual(duplicate["error"]["code"], "duplicate_operation")
        with self.store._connect() as db:
            dumped = "\n".join(db.iterdump())
        self.assertNotIn("DO_NOT_PERSIST_THIS_FILE_CONTENT", dumped)
        self.assertEqual(HistoryStore(self.store).detail(reply["history_id"])["byte_count"], 7)

    async def test_rejected_actor_and_unknown(self):
        req = FileOperationRequest(server="dev", path="x", reason="synthetic")
        with self.assertRaises(SSHDenied):
            await self.service.perform("unauthorized", req, "inspect")
        with self.assertRaises(SSHDenied):
            await self.service.perform("alice", req.model_copy(update={"server": "other"}), "inspect")
        class UnknownTransport:
            async def execute(self, *args, **kwargs):
                raise FileTransportError("timeout", "SSH connection lost", uncertain=True)
        self.service.transport = UnknownTransport()
        result = await self.service.perform("alice", req, "inspect")
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(HistoryStore(self.store).detail(result["history_id"])["error_code"], "timeout")
        self.assertEqual((await self.service.perform("alice", req, "unused"))["status"], "failed")

    async def test_file_error_and_partial(self):
        req = FileOperationRequest(server="dev", path="x", reason="synthetic")
        class ErrorTransport:
            async def execute(self, *args, **kwargs):
                return {"ok": False, "partial": True, "error": {"code": "invalid_patch"},
                        "outcomes": [{"path": "a.py", "status": "applied"},
                                     {"path": "b.py", "status": "failed", "error_code": "invalid_patch"}]}
        self.service.transport = ErrorTransport()
        reply = await self.service.perform("alice", req, "patch")
        self.assertEqual(reply["status"], "partial")
        self.assertEqual(len(HistoryStore(self.store).detail(reply["history_id"])
                             ["file_metadata"]["outcomes"]), 2)


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        root = Path(self.root.name)
        (root / "key").write_text("synthetic")
        (root / "known").write_text("synthetic")
        (root / "key").chmod(0o600)
        (root / "known").chmod(0o644)
        host = HostSpec(alias="dev", address="localhost", port=22, username="gateway",
                        identity_file=root/"key", known_hosts_file=root/"known",
                        principals=["alice"], environment="non-production", access="always-granted")
        self.executor = SSHExecutor({"dev": host}, enabled=True)
        self.transport = FileTransport(self.executor)
        real_spawn = asyncio.create_subprocess_exec
        async def spawn(*argv, **kwargs):
            return await real_spawn(*argv, env={**os.environ, "HOME": str(root)}, **kwargs)
        self.a = patch("app.file_transport._ssh_argv",
                       side_effect=lambda host, req, **kw: req.argv)
        self.b = patch("app.file_transport.asyncio.create_subprocess_exec", side_effect=spawn)
        self.a.start()
        self.b.start()
        self.addCleanup(self.a.stop)
        self.addCleanup(self.b.stop)

    async def test_install_reuse_tamper_remove_and_concurrent_first_use(self):
        root = Path(self.root.name)
        fixture = root / "fixture.txt"
        fixture.write_bytes(b"synthetic bytes")
        results = await asyncio.gather(
            self.transport.execute("alice", "dev", "inspect", {"path": str(fixture)}),
            self.transport.execute("alice", "dev", "inspect", {"path": str(fixture)}),
        )
        self.assertEqual([r["size"] for r in results], [15, 15])
        source, version, digest = self.transport.helper_source()
        remote = root / ".ssh-mcp-helper/helpers" / version / "helper.py"
        self.assertEqual(hashlib.sha256(remote.read_bytes()).hexdigest(), digest)
        self.assertEqual(remote.stat().st_mode & 0o777, 0o600)
        timestamp = remote.stat().st_mtime_ns
        await self.transport.execute("alice", "dev", "inspect", {"path": str(fixture)})
        self.assertEqual(remote.stat().st_mtime_ns, timestamp)
        remote.write_text("tamper")
        await self.transport.execute("alice", "dev", "inspect", {"path": str(fixture)})
        self.assertEqual(remote.read_bytes(), source)
        remote.unlink()
        await self.transport.execute("alice", "dev", "inspect", {"path": str(fixture)})
        self.assertEqual(remote.read_bytes(), source)

    async def test_untrusted_existing_cache_components_fail_closed(self):
        root = Path(self.root.name)
        _, version, _ = self.transport.helper_source()
        for component, permissions in (
            (".ssh-mcp-helper", 0o777),
            (".ssh-mcp-helper/helpers", 0o770),
            (f".ssh-mcp-helper/helpers/{version}", 0o755),
        ):
            with self.subTest(component=component):
                # Reset only synthetic HOME fixtures; never touch the real host.
                import shutil
                shutil.rmtree(root / ".ssh-mcp-helper", ignore_errors=True)
                target = root / component
                target.mkdir(parents=True)
                target.chmod(permissions)
                with self.assertRaises(FileTransportError) as ctx:
                    await self.transport.execute("alice", "dev", "inspect", {"path": "x"})
                self.assertEqual(ctx.exception.code, "bootstrap_check_failed")
                self.assertFalse((root / ".ssh-mcp-helper/helpers"
                                  / version / "helper.py").exists())
        import shutil
        shutil.rmtree(root / ".ssh-mcp-helper", ignore_errors=True)

    async def test_symlinked_cache_and_helper_are_not_accepted(self):
        root = Path(self.root.name)
        _, version, digest = self.transport.helper_source()
        escape = root / "outside"
        escape.mkdir()
        parent = root
        (parent / ".ssh-mcp-helper").symlink_to(
            escape, target_is_directory=True
        )
        with self.assertRaises(FileTransportError) as ctx:
            await self.transport.execute("alice", "dev", "inspect", {"path": "x"})
        self.assertEqual(ctx.exception.code, "bootstrap_check_failed")
        self.assertEqual(list(escape.iterdir()), [])
        (parent / ".ssh-mcp-helper").unlink()
        safe = parent / ".ssh-mcp-helper/helpers" / version
        safe.mkdir(parents=True)
        # The byte-identical file is still unsafe when loaded through symlink.
        outsider = escape / "helper.py"
        outsider.write_bytes(self.transport.helper_source()[0])
        outsider.chmod(0o600)
        (safe / "helper.py").symlink_to(outsider)
        with self.assertRaises(FileTransportError) as ctx:
            await self.transport.execute("alice", "dev", "inspect", {"path": "x"})
        self.assertEqual(ctx.exception.code, "bootstrap_check_failed")
        self.assertTrue((safe / "helper.py").is_symlink())

    async def test_unsafe_cached_helper_permissions_are_not_repaired_silently(self):
        root = Path(self.root.name)
        await self.transport.execute("alice", "dev", "inspect", {"path": str(root)})
        _, version, _ = self.transport.helper_source()
        helper = root / ".ssh-mcp-helper/helpers" / version / "helper.py"
        helper.chmod(0o666)
        with self.assertRaises(FileTransportError) as ctx:
            await self.transport.execute("alice", "dev", "inspect", {"path": str(root)})
        self.assertEqual(ctx.exception.code, "bootstrap_check_failed")
        self.assertEqual(helper.stat().st_mode & 0o777, 0o666)

    async def test_tampered_helper_is_replaced_before_execution(self):
        root = Path(self.root.name)
        await self.transport.execute("alice", "dev", "inspect", {"path": str(root)})
        _, version, digest = self.transport.helper_source()
        helper = root / ".ssh-mcp-helper/helpers" / version / "helper.py"
        victim = root / "must-not-be-created.txt"
        helper.write_text(f"open({str(victim)!r},'w').write('unsafe')\n")
        result = await self.transport.execute("alice", "dev", "inspect", {"path": str(root)})
        self.assertTrue(result["ok"])
        self.assertFalse(victim.exists())
        self.assertEqual(hashlib.sha256(helper.read_bytes()).hexdigest(), digest)

    async def test_legacy_shared_cache_with_group_write_is_ignored(self):
        root = Path(self.root.name)
        legacy = root / ".cache/ssh-mcp"
        legacy.mkdir(parents=True)
        legacy.chmod(0o775)
        source, version, digest = self.transport.helper_source()
        fixture = root / "legacy-ignored"
        fixture.write_bytes(b"safe")
        result = await self.transport.execute(
            "alice", "dev", "inspect", {"path": str(fixture)}
        )
        self.assertTrue(result["ok"], result)
        private = root / ".ssh-mcp-helper/helpers" / version / "helper.py"
        self.assertEqual(hashlib.sha256(private.read_bytes()).hexdigest(), digest)
        self.assertEqual((root / ".ssh-mcp-helper").stat().st_mode & 0o777, 0o700)
        self.assertEqual(legacy.stat().st_mode & 0o777, 0o775)
        self.assertEqual(private.read_bytes(), source)

    async def test_healthy_operation_uses_one_ssh_invocation_and_missing_uses_three(self):
        from unittest.mock import AsyncMock

        root = Path(self.root.name)
        fixture = root / "one-roundtrip"
        fixture.write_text("data")
        source, version, _digest = self.transport.helper_source()
        original = self.transport._ssh
        with patch.object(self.transport, "_ssh", new=AsyncMock(wraps=original)) as spy:
            result = await self.transport.execute(
                "alice", "dev", "inspect", {"path": str(fixture)}
            )
            self.assertTrue(result["ok"])
            self.assertEqual(spy.await_count, 3)  # run-miss, install, verified run
            helper = root / ".ssh-mcp-helper/helpers" / version / "helper.py"
            self.assertEqual(helper.read_bytes(), source)
            spy.reset_mock()
            result = await self.transport.execute(
                "alice", "dev", "inspect", {"path": str(fixture)}
            )
            self.assertTrue(result["ok"])
            self.assertEqual(spy.await_count, 1)  # single verify + execute SSH call

    async def test_configured_maximum_below_sixty_seconds(self):
        # Configuration is captured when contracts are imported. Start a fresh
        # interpreter so this exercises a genuine 30-second deployment policy
        # rather than mutating one module after field validation is constructed.
        program = r"""
import asyncio
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

from app import config
from app.file_transport import FileTransport
from app.ssh_executor import HostSpec, SSHExecutor

assert config.SSH_DEFAULT_TIMEOUT_SECONDS == 30
assert config.SSH_MAX_TIMEOUT_SECONDS == 30

async def verify():
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        key, known = root / "key", root / "known"
        key.write_text("synthetic")
        known.write_text("synthetic")
        key.chmod(0o600)
        known.chmod(0o644)
        host = HostSpec(
            alias="dev", address="localhost", port=22,
            username="gateway", identity_file=key, known_hosts_file=known,
            principals=["alice"], environment="non-production", access="always-granted"
        )
        transport = FileTransport(SSHExecutor({"dev": host}, enabled=True))
        original_spawn = asyncio.create_subprocess_exec

        async def spawn(*argv, **kwargs):
            return await original_spawn(
                *argv, env={**os.environ, "HOME": str(root)}, **kwargs
            )

        with patch("app.file_transport._ssh_argv",
                   side_effect=lambda _host, req, **kw: req.argv), patch(
                       "app.file_transport.asyncio.create_subprocess_exec",
                       side_effect=spawn
                   ):
            # First call installs the helper; second verifies its cached path.
            first = await transport.execute("alice", "dev", "inspect",
                                            {"path": str(root)})
            second = await transport.execute("alice", "dev", "inspect",
                                             {"path": str(root)}, timeout=20)
            assert first["ok"] is True and second["ok"] is True
            assert first["kind"] == "directory" and second["kind"] == "directory"

asyncio.run(verify())
"""
        process = subprocess.run(
            [sys.executable, "-c", program],
            env={**os.environ, "SSH_DEFAULT_TIMEOUT_SECONDS": "30",
                 "SSH_MAX_TIMEOUT_SECONDS": "30"},
            text=True, capture_output=True, timeout=45,
        )
        self.assertEqual(process.returncode, 0, process.stderr[-2000:])

    async def test_binary_stdout_preserved_without_utf8_replacement(self):
        host = self.executor.authorized_host("alice", "dev")
        result = await self.transport._ssh(
            host, ["python3", "-c", "import sys;sys.stdout.buffer.write(bytes([0,255,128,65]))"],
            b"",
        )
        self.assertEqual(result.stdout, bytes([0, 255, 128, 65]))
        self.assertEqual(result.exit_code, 0)

    async def test_error_contract_and_boundaries(self):
        with self.assertRaises(SSHDenied):
            await self.transport.execute("mallory", "dev", "inspect", {"path": "/tmp"})
        with self.assertRaises(FileTransportError) as ctx:
            await self.transport.execute("alice", "dev", "inspect", {"path": "x"*1100000})
        self.assertEqual(ctx.exception.code, "payload_limit")
        with self.assertRaises(FileTransportError) as ctx:
            await self.transport._ssh(self.executor.authorized_host("alice", "dev"),
                                      ["python3", "-c", "import time;time.sleep(2)"],
                                      b"", timeout=1)
        self.assertEqual(ctx.exception.code, "timeout")
        with self.assertRaises(FileTransportError) as ctx:
            await self.transport._ssh(self.executor.authorized_host("alice", "dev"),
                                      ["python3", "-c", "print('x'*300000)"],
                                      b"")
        self.assertEqual(ctx.exception.code, "output_limit")
        with self.assertRaises(FileTransportError) as ctx:
            await self.transport._ssh(self.executor.authorized_host("alice", "dev"),
                                      ["not-a-real-executable"], b"")
        self.assertEqual(ctx.exception.code, "transport_error")

# Additional error-path tests exercise fail-closed behavior and are intentionally
# synthetic. They never bootstrap a real host or use production credentials.
class HelperErrorTests(unittest.TestCase):
    def test_main_json_and_bounded_failure_codes(self):
        import io
        from app import file_helper
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "x"
            fixture.write_bytes(b"abc")
            payloads = [
                (json.dumps({"protocol": 1, "operation": "inspect",
                             "path": str(fixture)}).encode(), True),
                (b"x" * (file_helper.MAX_ENVELOPE_BYTES + 1), False),
                (b"[]", False),
                (b"{broken", False),
            ]
            for raw, ok in payloads:
                with self.subTest(ok=ok, length=len(raw)):
                    fake_stdin = io.TextIOWrapper(io.BytesIO(raw))
                    fake_stdout = io.StringIO()
                    with patch.object(file_helper.sys, "stdin", fake_stdin), \
                         patch.object(file_helper.sys, "stdout", fake_stdout):
                        self.assertEqual(file_helper.main(), 0)
                    result = json.loads(fake_stdout.getvalue())
                    self.assertIs(result["ok"], ok)
                    if len(raw) > file_helper.MAX_ENVELOPE_BYTES:
                        self.assertEqual(result["error"]["code"], "payload_limit")

    def test_helper_rejections_and_system_errors(self):
        import io
        from app import file_helper
        for failure, code in ((PermissionError("denied"), "permission_denied"),
                              (OSError("failed"), "filesystem_error"),
                              (ValueError("invalid"), "invalid_request")):
            with self.subTest(code=code):
                with patch.object(file_helper, "dispatch", side_effect=failure), \
                     patch.object(file_helper.sys, "stdin",
                                  io.TextIOWrapper(io.BytesIO(b"{}"))), \
                     patch.object(file_helper.sys, "stdout", io.StringIO()) as output:
                    self.assertEqual(file_helper.main(), 0)
                self.assertEqual(json.loads(output.getvalue())["error"]["code"], code)
        with tempfile.TemporaryDirectory() as root:
            with patch.object(file_helper.Path, "stat", side_effect=PermissionError):
                self.assertEqual(file_helper.inspect({"path": root})["error"]["code"],
                                 "permission_denied")
            os.mkfifo(str(Path(root) / "pipe"))
            self.assertEqual(file_helper.inspect({"path": str(Path(root) / "pipe")})["kind"],
                             "other")


class TransportErrorTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        p = Path(root.name)
        (p / "key").write_text("synthetic")
        (p / "known").write_text("synthetic")
        (p / "key").chmod(0o600)
        (p / "known").chmod(0o644)
        host = HostSpec(alias="dev", address="localhost", port=22, username="gateway",
                        identity_file=p / "key", known_hosts_file=p / "known",
                        principals=["alice"], environment="non-production", access="always-granted")
        self.executor = SSHExecutor({"dev": host}, enabled=True)
        self.host = host
        self.transport = FileTransport(self.executor)

    async def test_preflight_failures_do_not_install_or_retry(self):
        from unittest.mock import AsyncMock

        for response, code in (
            (RemoteResult(b"", b"", 127), "missing_python"),
            (RemoteResult(b'{"bootstrap":"verification_failed"}\n', b"", 76),
             "bootstrap_check_failed"),
            (RemoteResult(b'{"bootstrap":"install_required"}\n', b"unexpected", 75),
             "transport_error"),
            (RemoteResult(b'{"bootstrap":"install_required"}\n', b"", 7),
             "transport_error"),
            (RemoteResult(b'{"bootstrap":"wrong"}\n', b"", 75),
             "transport_error"),
            (RemoteResult(b"invalid", b"", 0), "invalid_response"),
            (RemoteResult(b"{}", b"", 0), "invalid_response"),
        ):
            with self.subTest(code=code), patch.object(
                self.transport, "_ssh", new=AsyncMock(return_value=response)
            ) as mock:
                with self.assertRaises(FileTransportError) as err:
                    await self.transport.execute("alice", "dev", "inspect", {"path": "x"})
                self.assertEqual(err.exception.code, code)
                self.assertEqual(mock.await_count, 1)

    async def test_install_rejection_and_invalid_confirmation(self):
        from unittest.mock import AsyncMock

        source, version, digest = self.transport.helper_source()
        for installed, code in (
            (RemoteResult(b"", b"", 127), "missing_python"),
            (RemoteResult(b"", b"", 1), "bootstrap_failed"),
            (RemoteResult(b"invalid", b"", 0), "invalid_response"),
            (RemoteResult(b'{"verified":false}', b"", 0), "invalid_response"),
        ):
            with self.subTest(code=code), patch.object(
                self.transport, "_ssh", new=AsyncMock(return_value=installed)
            ):
                with self.assertRaises(FileTransportError) as err:
                    await self.transport._install(self.host, source, version, digest)
                self.assertEqual(err.exception.code, code)

        for result, code in (
            (RemoteResult(b"", b"", 1), "bootstrap_failed"),
            (RemoteResult(b'{"verified":false}', b"", 0), "invalid_response"),
        ):
            with self.subTest(rejection=code), patch.object(
                self.transport, "_ssh",
                new=AsyncMock(side_effect=[
                    RemoteResult(b'{"bootstrap":"install_required"}\n', b"", 75),
                    result,
                ]),
            ) as mock:
                with self.assertRaises(FileTransportError) as err:
                    await self.transport.execute("alice", "dev", "inspect", {"path": "x"})
                self.assertEqual(err.exception.code, code)
                self.assertEqual(mock.await_count, 2)  # never run operation

    async def test_retry_once_only_after_exact_install_required_signal(self):
        from unittest.mock import AsyncMock

        responses = [
            RemoteResult(b'{"bootstrap":"install_required"}\n', b"", 75),
            RemoteResult(b'{"verified":true}', b"", 0),
            RemoteResult(b'{"bootstrap":"install_required"}\n', b"", 75),
        ]
        with patch.object(self.transport, "_ssh", new=AsyncMock(
            side_effect=responses
        )) as mock:
            with self.assertRaises(FileTransportError) as err:
                await self.transport.execute("alice", "dev", "append", {
                    "path": "would-not-replay", "content": "important",
                })
            self.assertEqual(err.exception.code, "transport_error")
            self.assertTrue(err.exception.uncertain)
            self.assertEqual(mock.await_count, 3)

    async def test_execution_response_failure_classes(self):
        from unittest.mock import AsyncMock

        for response, code in (
            (RemoteResult(b"", b"", 127), "missing_python"),
            (RemoteResult(b"", b"", 3), "transport_error"),
            (RemoteResult(b"bad json", b"", 0), "invalid_response"),
            (RemoteResult(b"[]", b"", 0), "invalid_response"),
            (RemoteResult(b'{"ok":1}', b"", 0), "invalid_response"),
        ):
            with self.subTest(code=code), patch.object(
                self.transport, "_ssh", new=AsyncMock(return_value=response)
            ) as mock:
                with self.assertRaises(FileTransportError) as err:
                    await self.transport.execute("alice", "dev", "inspect", {"path": "x"})
                self.assertEqual(err.exception.code, code)
                self.assertEqual(mock.await_count, 1)

    async def test_file_service_confirmed_transport_failure_and_interruption(self):
        from app.file_ops import FileService
        with tempfile.TemporaryDirectory() as folder:
            service = FileService(self.executor, JobStore(Path(folder) / "jobs.sqlite"))
            request = FileOperationRequest(server="dev", path="x", reason="synthetic")
            class ConfirmedError:
                async def execute(self, *args, **kwargs):
                    raise FileTransportError("bootstrap_failed", "helper install failed")
            service.transport = ConfirmedError()
            failed = await service.perform("alice", request, "inspect")
            self.assertEqual(failed["status"], "failed")
            class Cancelled:
                async def execute(self, *args, **kwargs):
                    raise asyncio.CancelledError()
            service.transport = Cancelled()
            with self.assertRaises(asyncio.CancelledError):
                await service.perform("alice", request, "inspect")
            self.assertEqual(HistoryStore(service.audit.store).list(
                {"status": "unknown"})["filtered_total"], 1)

class MixedHistoryAPITests(unittest.TestCase):
    def test_mixed_command_and_file_http_history_metadata(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from app.history import ViewerAuth, create_history_router
        from app.contracts import ExecuteCommandRequest
        with tempfile.TemporaryDirectory() as folder:
            store = JobStore(Path(folder) / "jobs.sqlite")
            command = store.create("alice", ExecuteCommandRequest(
                server="dev", argv=["hostname", "-s"], reason="synthetic",
                story_id="TEST-235"
            ))
            store.begin(command)
            store.finish(command, "succeeded", exit_code=0, elapsed=0.1)
            op = FileAudit(store).start("alice", "dev", "inspect", "safe.txt",
                                        "TEST-235", "read-operation-id")
            FileAudit(store).finish(op, "succeeded", byte_count=3)
            with patch.dict(os.environ, {"HISTORY_VIEWER_PASSWORD": "synthetic-viewer-password-test"}):
                app = FastAPI()
                app.include_router(create_history_router(store, approved_hosts=["dev"]))
            with TestClient(app) as client:
                self.assertEqual(client.get("/console/api/jobs").status_code, 401)
                with patch.object(ViewerAuth, "valid", return_value=True):
                    rows = client.get("/console/api/jobs", params={"page": 1, "limit": 10})
                    self.assertEqual(rows.status_code, 200)
                    data = rows.json()
                    self.assertEqual(data["filtered_total"], 2)
                    self.assertEqual({row["record_kind"] for row in data["jobs"]},
                                     {"command", "file"})
                    self.assertEqual(data["totals"]["succeeded"], 2)
                    selected = client.get("/console/api/jobs",
                                          params={"mode": "file", "command": "safe"})
                    self.assertEqual(selected.json()["filtered_total"], 1)
                    details = client.get("/console/api/jobs/file_" + op).json()["job"]
                    self.assertEqual(details["record_kind"], "file")
                    self.assertIsNone(details["request"])
                    self.assertIsNone(details["terminal_command"])
                    self.assertEqual(details["byte_count"], 3)
                    self.assertEqual(client.get("/console/api/jobs/file_" + op
                                                + "/output").json()["chunks"], [])
                    self.assertEqual(client.get("/console/api/changes",
                                                params={"after": "0:_"}).status_code, 200)
                    self.assertEqual(client.get("/console/api/jobs",
                                                params={"mode": "invalid"}).status_code, 400)
