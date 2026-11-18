"""TEST-237 synthetic binary transfer and metadata-only history."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.file_helper import dispatch
from app.file_transfer import BinaryTransferService
from app.file_transport import FileTransportError
from app.contracts import ChatGPTFileRef, DownloadFileRequest, UploadFileRequest
from app.history import HistoryStore
from app.jobs import JobStore
from app.ssh_executor import HostSpec, SSHDenied, SSHExecutor


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


FILE = ChatGPTFileRef(
    download_url="https://probe.example.invalid/x?secret=DO_NOT_STORE",
    file_id="file-private-237", file_name="blob.bin",
)


class HelperBinaryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.path = str(self.root / "test.bin")

    def call(self, op, **args):
        return dispatch({"protocol": 1, "server": "dev",
                         "operation": op, "path": self.path, **args})

    def test_full_binary_roundtrip_and_cursor_change(self):
        body = b"\x00\xff\xfe" + bytes(range(256)) * 600
        start = self.call("upload_start")
        self.assertTrue(start["ok"], start)
        token = start["session_id"]
        for off in range(0, len(body), 65536):
            chunk = body[off:off + 65536]
            reply = self.call("upload_chunk", session_id=token, offset=off,
                              data_base64=base64.b64encode(chunk).decode(),
                              chunk_sha256=sha(chunk))
            self.assertEqual(reply["offset"], off + len(chunk))
        ended = self.call("upload_finish", session_id=token, size=len(body), sha256=sha(body))
        self.assertTrue(ended["ok"], ended)
        self.assertEqual(Path(self.path).read_bytes(), body)
        self.assertFalse(any(self.root.glob(".ssh-mcp-upload-*")))
        first = self.call("download_chunk", max_bytes=65536, include_sha256=True)
        self.assertEqual(first["sha256"], sha(body))
        self.assertFalse(first["eof"])
        next_part = self.call("download_chunk", cursor=first["next_cursor"])
        self.assertTrue(next_part["ok"], next_part)
        self.assertEqual(base64.b64decode(first["data_base64"] + "==="), body[:65536])
        self.assertEqual(base64.b64decode(next_part["data_base64"] + "==="), body[65536:131072])
        Path(self.path).write_bytes(body + b"changed")
        changed = self.call("download_chunk", cursor=next_part["next_cursor"])
        self.assertEqual(changed["error"]["code"], "changed_file")

    def test_corrupt_chunks_and_hashes_never_publish(self):
        start = self.call("upload_start")
        token = start["session_id"]
        bad = self.call("upload_chunk", session_id=token, offset=0,
                        data_base64="aGk=", chunk_sha256="0" * 64)
        self.assertEqual(bad["error"]["code"], "precondition_failed")
        self.assertTrue(self.call("upload_chunk", session_id=token, offset=0,
                                  data_base64="aGk=", chunk_sha256=sha(b"hi"))["ok"])
        duplicate = self.call("upload_chunk", session_id=token, offset=0,
                              data_base64="aGk=", chunk_sha256=sha(b"hi"))
        self.assertEqual(duplicate["error"]["code"], "precondition_failed")
        end = self.call("upload_finish", session_id=token, size=2, sha256="0" * 64)
        self.assertEqual(end["error"]["code"], "precondition_failed")
        self.assertFalse(Path(self.path).exists())
        self.assertTrue(self.call("upload_abort", session_id=token)["cleaned"])
        self.assertFalse(self.call("upload_abort", session_id=token)["cleaned"])

    def test_create_overwrite_and_empty(self):
        target = Path(self.path)
        target.write_bytes(b"old")
        self.assertEqual(self.call("upload_start")["error"]["code"], "already_exists")
        begun = self.call("upload_start", mode="overwrite", expected_sha256=sha(b"old"))
        token = begun["session_id"]
        inode = target.stat().st_ino
        result = self.call("upload_finish", mode="overwrite", session_id=token,
                           size=0, sha256=sha(b""), expected_sha256=sha(b"old"))
        self.assertTrue(result["ok"], result)
        self.assertEqual(target.read_bytes(), b"")
        self.assertNotEqual(inode, target.stat().st_ino)
        reply = self.call("download_chunk")
        self.assertEqual(reply["bytes"], 0)
        self.assertEqual(reply["data_base64"], "")
        self.assertTrue(reply["eof"])

    def test_invalid_chunk_bounds_and_permissions(self):
        token = self.call("upload_start")["session_id"]
        for args in ({"offset": -1, "data_base64": "YQ=="},
                     {"offset": 0, "data_base64": "invalid"},
                     {"offset": 0, "data_base64": ""}):
            reply = self.call("upload_chunk", session_id=token,
                              chunk_sha256=sha(b"a"), **args)
            self.assertFalse(reply["ok"], reply)
        stage = self.root / (".ssh-mcp-upload-" + token)
        stage.chmod(0o644)
        rejected = self.call("upload_chunk", session_id=token, offset=0,
                             data_base64="YQ==", chunk_sha256=sha(b"a"))
        self.assertEqual(rejected["error"]["code"], "permission_denied")


    def test_remote_helper_invalid_mode_parent_and_session(self):
        for extra in ({"mode": "append"}, {"create_parents": "true"}):
            self.assertEqual(self.call("upload_start", **extra)["error"]["code"],
                             "invalid_request")
        self.path = str(self.root / "missing-parent" / "x")
        self.assertEqual(self.call("upload_start")["error"]["code"], "not_found")
        created = self.call("upload_start", create_parents=True)
        self.assertTrue(created["ok"], created)
        for token in ("", "a" * 10, "Z" * 32, 3):
            self.assertEqual(self.call("upload_abort", session_id=token)["error"]["code"],
                             "invalid_request")
        stage = Path(self.path).parent / (".ssh-mcp-upload-" + created["session_id"])
        self.assertTrue(stage.exists())
        self.assertTrue(self.call("upload_abort", session_id=created["session_id"])["ok"])

    def test_remote_upload_size_offset_and_mode_bounds(self):
        start = self.call("upload_start")
        token = start["session_id"]
        digest = sha(b"abc")
        options = [
            {"offset": 0, "data_base64": "YWJj", "chunk_sha256": digest,
             "session_id": "nope"},
            {"offset": -1, "data_base64": "YWJj", "chunk_sha256": digest,
             "session_id": token},
            {"offset": 0, "data_base64": "YWI", "chunk_sha256": digest,
             "session_id": token},
            {"offset": 0, "data_base64": "", "chunk_sha256": sha(b""),
             "session_id": token},
            {"offset": 8 * 1024 * 1024, "data_base64": "YWJj", "chunk_sha256": digest,
             "session_id": token},
        ]
        for item in options:
            with self.subTest(item=item):
                self.assertFalse(self.call("upload_chunk", **item)["ok"])
        self.assertTrue(self.call("upload_chunk", session_id=token, offset=0,
                                  data_base64="YWJj", chunk_sha256=digest)["ok"])
        self.assertEqual(self.call("upload_finish", session_id=token, size=4,
                                   sha256=digest)["error"]["code"], "precondition_failed")
        for args in ({"size": -1, "sha256": digest},
                     {"size": 3, "sha256": "bad"},
                     {"size": 3, "sha256": digest, "mode": "append"}):
            with self.subTest(args=args):
                self.assertEqual(self.call("upload_finish", session_id=token, **args
                                           )["error"]["code"], "invalid_request")
        self.assertFalse(Path(self.path).exists())
        self.assertTrue(self.call("upload_abort", session_id=token)["cleaned"])

    def test_stale_stage_cleanup_and_symlink_rejection(self):
        import time
        old = self.root / (".ssh-mcp-upload-" + "a" * 32)
        old.write_bytes(b"orphan")
        old.chmod(0o600)
        os.utime(old, (time.time() - 4000, time.time() - 4000))
        rogue = self.root / (".ssh-mcp-upload-" + "b" * 32)
        rogue.symlink_to(old)
        new = self.call("upload_start")
        self.assertTrue(new["ok"])
        self.assertFalse(old.exists())
        self.assertTrue(rogue.is_symlink())
        bad = self.call("upload_finish", session_id="b" * 32,
                        size=0, sha256=sha(b""))
        self.assertEqual(bad["error"]["code"], "filesystem_error")
        self.assertTrue(self.call("upload_abort", session_id=new["session_id"])["ok"])

    def test_orphan_scan_reaches_stage_after_4096_unrelated_entries(self):
        from contextlib import nullcontext
        from itertools import chain
        from types import SimpleNamespace
        import time

        stale = self.root / (".ssh-mcp-upload-" + "a" * 32)
        stale.write_bytes(b"stale-private-payload")
        stale.chmod(0o600)
        os.utime(stale, (time.time() - 4000, time.time() - 4000))
        fresh = self.root / (".ssh-mcp-upload-" + "b" * 32)
        fresh.write_bytes(b"recent-private-payload")
        fresh.chmod(0o600)
        with os.scandir(self.root) as entries:
            stage_entries = {
                entry.name: entry for entry in entries
                if entry.name in {stale.name, fresh.name}
            }
        # The order is deterministic: the orphan must be *after* 4096
        # unrelated entries. Never materialize all scanned entries.
        prefix = (SimpleNamespace(name=f"other-file-{n}") for n in range(4100))
        ordered = chain(prefix, (stage_entries[stale.name], stage_entries[fresh.name]))
        with patch("app.file_helper.os.scandir", return_value=nullcontext(ordered)):
            started = self.call("upload_start")
        self.assertTrue(started["ok"], started)
        self.assertFalse(stale.exists())
        self.assertTrue(fresh.exists())
        self.assertEqual(fresh.read_bytes(), b"recent-private-payload")
        self.assertTrue(self.call("upload_abort", session_id=started["session_id"])["ok"])

    def test_bounded_download_invalid_cursor_and_range(self):
        target = Path(self.path)
        target.write_bytes(b"one" * 100)
        initial = self.call("download_chunk", max_bytes=30)
        self.assertTrue(initial["ok"])
        bad_requests = [
            {"max_bytes": 0}, {"max_bytes": 65537}, {"offset": -1},
            {"offset": 1000}, {"cursor": "broken"},
        ]
        for opts in bad_requests:
            with self.subTest(options=opts):
                self.assertFalse(self.call("download_chunk", **opts)["ok"])
        self.assertEqual(self.call("download_chunk", cursor=initial["next_cursor"],
                                   server="other")["error"]["code"], "invalid_cursor")
        import base64 as b64
        import json
        token = initial["next_cursor"]
        data = json.loads(b64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
        for key, value in (("path_sha256", "0" * 64), ("offset", -1),
                           ("server", "other"), ("offset", 1000000)):
            item = dict(data, **{key: value})
            forged = b64.urlsafe_b64encode(json.dumps(item).encode()).decode()
            error = self.call("download_chunk", cursor=forged)["error"]["code"]
            self.assertIn(error, {"invalid_cursor", "changed_file"})
        self.path = str(self.root)
        self.assertEqual(self.call("download_chunk")["error"]["code"], "invalid_request")

    def test_stage_write_failure_is_unknown_not_success(self):
        token = self.call("upload_start")["session_id"]
        with patch("app.file_helper.os.write", side_effect=OSError("synthetic")):
            result = self.call("upload_chunk", session_id=token, offset=0,
                               data_base64="YQ==", chunk_sha256=sha(b"a"))
        self.assertFalse(result["ok"])
        self.assertTrue(result["unknown"])
        self.assertEqual(result["error"]["code"], "interrupted")
        self.assertFalse(Path(self.path).exists())
        self.assertTrue(self.call("upload_abort", session_id=token)["ok"])


class ServiceBinaryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        key = self.root / "key"
        known = self.root / "known"
        key.write_text("synthetic")
        key.chmod(0o600)
        known.write_text("synthetic")
        known.chmod(0o644)
        host = HostSpec(
            alias="dev", address="localhost", port=22, username="gateway",
            identity_file=key, known_hosts_file=known,
            principals=["alice"], environment="non-production", access="always-granted",
        )
        self.executor = SSHExecutor({"dev": host}, enabled=True)
        self.store = JobStore(self.root / "audit" / "jobs.sqlite")
        self.service = BinaryTransferService(self.executor, self.store)
        self.viewer = HistoryStore(self.store)
        spawn_original = asyncio.create_subprocess_exec

        async def spawn(*argv, **kwargs):
            return await spawn_original(*argv, env={**os.environ, "HOME": str(self.root)}, **kwargs)

        a = patch("app.file_transport._ssh_argv", side_effect=lambda host, req, **kw: req.argv)
        b = patch("app.file_transport.asyncio.create_subprocess_exec", side_effect=spawn)
        a.start()
        b.start()
        self.addCleanup(a.stop)
        self.addCleanup(b.stop)

    def req(self, path, *, operation_id="binary-upload-237", **other):
        return UploadFileRequest(
            server="dev", path=str(path), reason="synthetic binary test",
            story_id="TEST-237", operation_id=operation_id, file=FILE, **other,
        )

    async def upload(self, request, body):
        async def source(_url, **kw):
            self.assertLessEqual(len(body), kw["max_bytes"])
            return body
        with patch("app.file_transfer.read_binary_file", new=source):
            return await self.service.upload("alice", request)

    async def test_real_chunked_transport_and_audit_privacy(self):
        body = b"PRIVATE_BINARY_NEVER_PERSIST-" + bytes(range(256)) * 1600
        destination = self.root / "nested" / "real.bin"
        reply = await self.upload(self.req(destination, create_parents=True), body)
        self.assertEqual(reply["status"], "succeeded", reply)
        self.assertEqual(destination.read_bytes(), body)
        self.assertEqual(reply["result"]["sha256"], sha(body))
        self.assertFalse(any(self.root.rglob(".ssh-mcp-upload-*")))
        first_history = self.viewer.detail(reply["history_id"])
        self.assertEqual(first_history["file_metadata"]["transfer"]["direction"], "upload")
        self.assertEqual(first_history["file_metadata"]["transfer"]["sha256"], sha(body))
        cursor = None
        chunks = []
        while True:
            request = DownloadFileRequest(
                server="dev", path=str(destination),
                reason="synthetic binary download", story_id="TEST-237",
                max_bytes=65536,
                **({"cursor": cursor} if cursor else {"include_sha256": True}),
            )
            downloaded = await self.service.download("alice", request)
            self.assertEqual(downloaded["status"], "succeeded", downloaded)
            result = downloaded["result"]
            if not cursor:
                self.assertEqual(result["sha256"], sha(body))
            chunk = base64.b64decode(result["data_base64"], validate=True)
            self.assertEqual(sha(chunk), result["chunk_sha256"])
            chunks.append(chunk)
            metadata = self.viewer.detail(downloaded["history_id"])["file_metadata"]["transfer"]
            self.assertEqual(metadata["chunk_sha256"], sha(chunk))
            self.assertEqual(metadata["direction"], "download")
            if result["eof"]:
                break
            cursor = result["next_cursor"]
        self.assertEqual(b"".join(chunks), body)
        with self.store._connect() as db:
            audit = "\n".join(db.iterdump())
            self.assertEqual(db.execute("SELECT COUNT(*) FROM output").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 0)
        self.assertNotIn(FILE.download_url, audit)
        self.assertNotIn(FILE.file_id, audit)
        self.assertNotIn("PRIVATE_BINARY_NEVER_PERSIST", audit)
        self.assertEqual(self.viewer.output(reply["history_id"])["chunks"], [])

    async def test_source_mismatch_create_conflict_and_overwrite(self):
        target = self.root / "target.bin"
        broken = await self.upload(self.req(target, source_sha256="0" * 64), b"new")
        self.assertEqual(broken["error"]["code"], "precondition_failed")
        self.assertFalse(target.exists())
        target.write_bytes(b"old")
        collision = await self.upload(self.req(target, operation_id="collide-237"), b"new")
        self.assertEqual(collision["error"]["code"], "already_exists")
        self.assertEqual(target.read_bytes(), b"old")
        old_inode = target.stat().st_ino
        changed = await self.upload(
            self.req(target, operation_id="overwrite-237",
                     mode="overwrite", expected_sha256=sha(b"old")),
            b"new")
        self.assertEqual(changed["status"], "succeeded", changed)
        self.assertEqual(target.read_bytes(), b"new")
        self.assertNotEqual(target.stat().st_ino, old_inode)

    async def test_unknown_finish_does_not_replay_or_publish(self):
        target = self.root / "unknown.bin"
        original = self.service.transport.execute

        async def lose_finish(actor, server, operation, data, **kw):
            if operation == "upload_finish":
                raise FileTransportError("transport_error", "synthetic failure", uncertain=True)
            return await original(actor, server, operation, data, **kw)

        req = self.req(target, operation_id="finish-unknown-237")
        with patch.object(self.service.transport, "execute", side_effect=lose_finish):
            failed = await self.upload(req, b"not published")
        self.assertEqual(failed["status"], "unknown")
        self.assertFalse(target.exists())
        self.assertEqual(len(list(self.root.glob(".ssh-mcp-upload-*"))), 1)
        repeated = await self.upload(req, b"not published")
        self.assertEqual(repeated["error"]["code"], "duplicate_operation")
        self.assertFalse(target.exists())

    async def test_readiness_lost_before_publication_leaves_unpublished_stage(self):
        from app.readiness import ProbeResult, ReadinessMonitor, ReadinessSettings
        from unittest.mock import AsyncMock

        now = [1000.]
        monitor = ReadinessMonitor(ReadinessSettings(authorized=True),
            {"dev": False}, AsyncMock(return_value=ProbeResult(True)), clock=lambda: now[0])
        self.executor.readiness = monitor
        self.assertTrue(await monitor.check("dev"))
        target = self.root / "readiness.bin"
        original = self.service.transport.execute
        operations = []

        async def lose_readiness(actor, server, operation, data, **kw):
            operations.append(operation)
            if operation == "upload_finish":
                now[0] += 300
            return await original(actor, server, operation, data, **kw)

        with patch.object(self.service.transport, "execute", side_effect=lose_readiness):
            failed = await self.upload(self.req(target), b"never published")
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["error"]["code"], "host_readiness")
        self.assertFalse(failed["error"]["published"])
        self.assertFalse(target.exists())
        self.assertEqual(operations, ["upload_start", "upload_chunk", "upload_finish"])
        self.assertEqual(len(list(self.root.glob(".ssh-mcp-upload-*"))), 1)

    async def test_unauthorized_identity_does_not_start_audit(self):
        with self.assertRaises(SSHDenied):
            await self.service.upload(
                "bob", self.req(self.root / "denied"),)
        self.assertEqual(self.viewer.list({})["filtered_total"], 0)

    async def test_source_error_and_unexpected_exception_are_audited_safely(self):
        from app.binary_probe import BinaryProbeError

        async def deny_source(_url, **_kw):
            raise BinaryProbeError("do not log source signed URL")

        with patch("app.file_transfer.read_binary_file", new=deny_source):
            rejected = await self.service.upload(
                "alice", self.req(self.root / "input", operation_id="source-denied-237"))
        self.assertEqual(rejected["status"], "failed")
        self.assertEqual(rejected["error"]["code"], "source_unavailable")
        self.assertNotIn("signed URL", str(rejected))
        self.assertEqual(rejected["error"]["diagnostic"], {
            "category": "unknown",
            "source_hostname": "probe.example.invalid",
        })
        self.assertEqual(self.viewer.detail(rejected["history_id"])["error_code"],
                         "source_unavailable")
        with self.store._connect() as db:
            audit = "\n".join(db.iterdump())
        self.assertNotIn("probe.example.invalid", audit)
        self.assertNotIn(FILE.file_id, audit)
        self.assertNotIn("DO_NOT_STORE", audit)

        async def crash(*_args, **_kw):
            raise RuntimeError("synthetic interrupted service")

        with patch.object(self.service.transport, "execute", side_effect=crash):
            with self.assertRaises(RuntimeError):
                await self.upload(self.req(self.root / "crash",
                                           operation_id="crash-interrupted-237"), b"a")
        item = self.viewer.detail("file_crash-interrupted-237")
        self.assertEqual(item["status"], "unknown")
        self.assertEqual(item["error_code"], "interrupted")

    async def test_private_source_ip_never_starts_ssh_upload(self):
        request = self.req(
            self.root / "never-published",
            operation_id="source-private-ip-rejected-237",
        )
        private_dns = [(2, 1, 6, "", ("169.254.169.254", 443))]
        with patch("app.binary_probe.socket.getaddrinfo", return_value=private_dns):
            with patch.object(self.service.transport, "execute") as remote:
                result = await self.service.upload("alice", request)
                remote.assert_not_called()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"]["code"], "source_unavailable")
        self.assertEqual(result["error"]["diagnostic"], {
            "category": "unsafe_address",
            "source_hostname": "probe.example.invalid",
        })
        self.assertFalse((self.root / "never-published").exists())
        self.assertEqual(self.viewer.detail(result["history_id"])["error_code"],
                         "source_unavailable")
        with self.store._connect() as db:
            audit = "\n".join(db.iterdump())
        self.assertNotIn("probe.example.invalid", audit)
        self.assertNotIn("DO_NOT_STORE", audit)

    async def test_invalid_upload_staging_response_is_unknown(self):
        async def corrupt_start(_actor, _host, operation, _args):
            self.assertEqual(operation, "upload_start")
            return {"ok": True, "session_id": "too-short"}

        with patch.object(self.service.transport, "execute", new=corrupt_start):
            failed = await self.upload(
                self.req(self.root / "bad-stage", operation_id="bad-stage-237"), b"payload")
        self.assertEqual(failed["status"], "unknown")
        self.assertEqual(failed["error"]["code"], "invalid_response")

    async def test_confirmed_chunk_failure_aborts_stage(self):
        sent = []

        async def fake(_actor, _host, operation, _args):
            sent.append(operation)
            if operation == "upload_start":
                return {"ok": True, "session_id": "a" * 32}
            if operation == "upload_chunk":
                return {"ok": False, "error": {"code": "precondition_failed"}}
            return {"ok": True, "cleaned": True}

        with patch.object(self.service.transport, "execute", new=fake):
            failed = await self.upload(
                self.req(self.root / "stage", operation_id="chunk-failed-237"), b"secret")
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(sent, ["upload_start", "upload_chunk", "upload_abort"])

    async def test_unknown_chunk_failure_does_not_abort_or_replay(self):
        calls = []

        async def fake(_actor, _host, operation, _args):
            calls.append(operation)
            if operation == "upload_start":
                return {"ok": True, "session_id": "a" * 32}
            return {"ok": False, "unknown": True,
                    "error": {"code": "interrupted"}}

        with patch.object(self.service.transport, "execute", new=fake):
            result = await self.upload(
                self.req(self.root / "unknown-stage", operation_id="unknown-stage-237"),
                b"secret")
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(calls, ["upload_start", "upload_chunk"])

    async def test_corrupt_chunk_acknowledgement_is_unknown(self):
        async def fake(_actor, _host, operation, _args):
            if operation == "upload_start":
                return {"ok": True, "session_id": "b" * 32}
            return {"ok": True, "offset": 999, "chunk_sha256": "0" * 64}

        with patch.object(self.service.transport, "execute", new=fake):
            result = await self.upload(
                self.req(self.root / "bad-ack", operation_id="bad-chunk-237"), b"secret")
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["error"]["code"], "invalid_response")

    async def test_safe_failed_publication_aborts_staging(self):
        operations = []

        async def fake(_actor, _host, operation, arguments):
            operations.append(operation)
            if operation == "upload_start":
                return {"ok": True, "session_id": "c" * 32}
            if operation == "upload_chunk":
                return {"ok": True, "offset": len(b"one"), "chunk_sha256": sha(b"one")}
            if operation == "upload_finish":
                return {"ok": False, "error": {"code": "already_exists"}}
            return {"ok": True, "cleaned": True}

        with patch.object(self.service.transport, "execute", new=fake):
            result = await self.upload(self.req(
                self.root / "collision", operation_id="finish-collision-237"), b"one")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"]["code"], "already_exists")
        self.assertEqual(operations, [
            "upload_start", "upload_chunk", "upload_finish", "upload_abort",
        ])

    async def test_ambiguous_finish_error_never_claims_clean_failure(self):
        events = []

        async def fake(_actor, _host, operation, _arguments):
            events.append(operation)
            if operation == "upload_start":
                return {"ok": True, "session_id": "d" * 32}
            if operation == "upload_chunk":
                return {"ok": True, "offset": 3, "chunk_sha256": sha(b"one")}
            return {"ok": False, "error": {"code": "filesystem_error"}}

        with patch.object(self.service.transport, "execute", new=fake):
            reply = await self.upload(self.req(
                self.root / "unknown-end", operation_id="finish-failed-237"), b"one")
        self.assertEqual(reply["status"], "unknown")
        self.assertNotIn("upload_abort", events)

    async def test_bad_publication_hash_reports_unknown(self):
        async def fake(_actor, _host, operation, _args):
            if operation == "upload_start":
                return {"ok": True, "session_id": "e" * 32}
            if operation == "upload_chunk":
                return {"ok": True, "offset": 3, "chunk_sha256": sha(b"one")}
            return {"ok": True, "bytes": 3, "sha256": "0" * 64}

        with patch.object(self.service.transport, "execute", new=fake):
            result = await self.upload(
                self.req(self.root / "bad-hash", operation_id="bad-final-hash-237"), b"one")
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["error"]["code"], "invalid_response")

    async def test_abort_transport_failure_reports_unknown(self):
        async def fake(_actor, _host, operation, _args):
            if operation == "upload_start":
                return {"ok": True, "session_id": "f" * 32}
            if operation == "upload_chunk":
                return {"ok": False, "error": {"code": "precondition_failed"}}
            raise FileTransportError("transport_error", "unable to abort", uncertain=True)

        with patch.object(self.service.transport, "execute", new=fake):
            result = await self.upload(
                self.req(self.root / "bad-abort", operation_id="abort-error-237"), b"one")
        self.assertEqual(result["status"], "unknown")

    async def test_download_rejects_invalid_base64_and_hash_before_success_audit(self):
        cases = [
            {"ok": True, "bytes": 1, "chunk_sha256": sha(b"a")},
            {"ok": True, "bytes": 1, "data_base64": "not base64",
             "chunk_sha256": sha(b"a")},
            {"ok": True, "bytes": 4, "data_base64": "YQ==",
             "chunk_sha256": sha(b"a")},
            {"ok": True, "bytes": 1, "data_base64": "YQ==",
             "chunk_sha256": "0" * 64},
        ]
        for number, payload in enumerate(cases):
            with self.subTest(number=number):
                async def fake(*_args):
                    return payload
                with patch.object(self.service.transport, "execute", new=fake):
                    request = DownloadFileRequest(
                        server="dev", path=str(self.root / "bad.bin"),
                        reason="corrupt response", story_id="TEST-237",
                        operation_id=f"corrupt-download-{number}-237",
                    )
                    result = await self.service.download("alice", request)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["error"]["code"], "invalid_response")
                entry = self.viewer.detail(result["history_id"])
                self.assertEqual(entry["status"], "failed")

    async def test_transfer_audit_never_accepts_untrusted_metadata(self):
        from app.file_audit import FileAudit
        audit = FileAudit(self.store)
        key = audit.start("alice", "dev", "download", "/tmp/x", "TEST-237")
        with self.assertRaises(ValueError):
            audit.finish(key, "failed", transfer={"direction": "unknown"})
        audit.finish(key, "succeeded", byte_count=3, transfer={
            "direction": "download", "sha256": sha(b"abc"), "offset": 0,
            "next_offset": 3, "size": 3, "eof": True,
            "download_url": FILE.download_url, "source_id": FILE.file_id,
            "bytes_base64": "YWJj",
        })
        metadata = self.viewer.detail("file_" + key)["file_metadata"]
        self.assertEqual(metadata["transfer"]["sha256"], sha(b"abc"))
        with self.store._connect() as database:
            dump = "\n".join(database.iterdump())
        self.assertNotIn(FILE.download_url, dump)
        self.assertNotIn(FILE.file_id, dump)
        self.assertNotIn("bytes_base64", dump)
