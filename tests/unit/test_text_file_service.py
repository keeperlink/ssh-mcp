"""TEST-236 authorized transport and private-audit acceptance, without live hosts."""
from __future__ import annotations

import asyncio
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.file_ops import (
    ApplyPatchRequest, FileService, ReadFileRequest, WriteFileRequest,
)
from app.file_transport import FileTransportError
from app.history import HistoryStore
from app.jobs import JobStore
from app.ssh_executor import HostSpec, SSHDenied, SSHExecutor


class TextFileServiceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        identity = self.root / "key"
        known = self.root / "known"
        identity.write_text("synthetic")
        known.write_text("synthetic")
        known.chmod(0o644)
        identity.chmod(0o600)
        host = HostSpec(
            alias="dev", address="localhost", port=22, username="gateway",
            identity_file=identity, known_hosts_file=known,
            principals=["alice"], environment="non-production", access="always-granted",
        )
        executor = SSHExecutor({"dev": host}, enabled=True)
        store = JobStore(self.root / "private" / "jobs.sqlite")
        self.service = FileService(executor, store)
        self.store = store
        self.viewer = HistoryStore(store)
        original_spawn = asyncio.create_subprocess_exec

        async def spawn(*argv, **kwargs):
            return await original_spawn(*argv, env={**os.environ, "HOME": str(self.root)}, **kwargs)

        a = patch("app.file_transport._ssh_argv", side_effect=lambda host, req, **kw: req.argv)
        b = patch("app.file_transport.asyncio.create_subprocess_exec", side_effect=spawn)
        a.start()
        b.start()
        self.addCleanup(a.stop)
        self.addCleanup(b.stop)

    async def test_real_write_append_read_patch_and_metadata_only_history(self):
        payload_marker = "PRIVATE-SKY236-NEVER-PERSIST-PAYLOAD-49817"
        file = self.root / "data.txt"
        arguments = {"server": "dev", "path": str(file), "reason": "synthetic files",
                     "story_id": "TEST-236"}
        created = await self.service.perform(
            "alice", WriteFileRequest(**arguments, content=payload_marker + "\n",
                                      mode="create", include_sha256=True),
            "write", {"content": payload_marker + "\n", "mode": "create", "include_sha256": True},
        )
        self.assertEqual(created["status"], "succeeded", created)
        self.assertEqual(created["result"]["sha256"],
                         hashlib.sha256(file.read_bytes()).hexdigest())
        append_request = WriteFileRequest(**arguments, content="second", mode="append",
                                          operation_id="append-sky236-001")
        appended = await self.service.perform(
            "alice", append_request, "write", {"content": "second", "mode": "append"},
        )
        self.assertEqual(appended["status"], "succeeded", appended)
        self.assertEqual(
            (await self.service.perform("alice", append_request, "write",
                                        {"content": "second", "mode": "append"}))["error"]["code"],
            "duplicate_operation",
        )
        self.assertEqual(file.read_bytes().count(b"second"), 1)
        text = await self.service.perform(
            "alice", ReadFileRequest(**arguments, max_bytes=17),
            "read", {"max_bytes": 17},
        )
        self.assertEqual(text["status"], "succeeded", text)
        self.assertTrue(text["result"]["truncated"])
        cursor = text["result"]["next_cursor"]
        follow = await self.service.perform(
            "alice", ReadFileRequest(**arguments, cursor=cursor),
            "read", {"cursor": cursor},
        )
        self.assertEqual(follow["status"], "succeeded", follow)
        self.assertEqual(text["result"]["content"] + follow["result"]["content"],
                         payload_marker + "\nsecond")
        second = self.root / "second.txt"
        patch_body = (f"*** Begin Patch\n*** Add File: {second}\n+{payload_marker}\n"
                      f"*** Update File: {file}\n@@\n-{payload_marker}\n+CHANGED\n"
                      "*** End Patch")
        patched = await self.service.perform(
            "alice", ApplyPatchRequest(
                server="dev", reason="synthetic patch", patch=patch_body,
                path=".", story_id="TEST-236", operation_id="patch-sky236-001"),
            "patch", {"patch": patch_body},
        )
        self.assertEqual(patched["status"], "succeeded", patched)
        self.assertEqual([o["status"] for o in patched["result"]["outcomes"]],
                         ["applied", "applied"])
        self.assertIn("CHANGED", file.read_text())
        # Both request and stdout are private. The audit contains only leaf names,
        # action/status/byte count and a stable code, never payload or patch body.
        with store_connection(self.store) as data:
            self.assertNotIn(payload_marker, data)
            self.assertNotIn("*** Begin Patch", data)
        detail = self.viewer.detail(patched["history_id"])
        self.assertEqual(detail["record_kind"], "file")
        self.assertIsNone(detail["request"])
        self.assertEqual(len(detail["file_metadata"]["outcomes"]), 2)
        self.assertEqual(detail["file_metadata"]["outcomes"][0]["action"], "add")
        self.assertEqual(self.viewer.output(patched["history_id"])["chunks"], [])

    async def test_postwrite_hash_unavailable_is_audited_as_partial(self):
        class HashUnavailable:
            async def execute(self, _actor, _server, _kind, payload):
                return {"ok": False, "partial": True, "mutation_completed": True,
                        "bytes": len(payload["content"]), "path": payload["path"],
                        "error": {"code": "permission_denied",
                                  "message": "Write completed; hash unavailable"}}

        self.service.transport = HashUnavailable()
        marker = "PRIVATE-APPEND-CONTENT-DO-NOT-RETAIN"
        req = WriteFileRequest(server="dev", path=str(self.root / "entry.txt"),
                               reason="synthetic hash failure", content=marker,
                               include_sha256=True, mode="append",
                               operation_id="hash-uncertain-236")
        result = await self.service.perform("alice", req, "write",
                                            {"mode": "append", "content": marker,
                                             "include_sha256": True})
        self.assertEqual(result["status"], "partial", result)
        self.assertTrue(result["result"]["mutation_completed"])
        detail = self.viewer.detail(result["history_id"])
        self.assertEqual(detail["status"], "partial")
        self.assertEqual(detail["error_code"], "permission_denied")
        self.assertEqual(detail["byte_count"], len(marker))
        with self.store._connect() as db:
            dump = "\n".join(db.iterdump())
        self.assertNotIn(marker, dump)
        again = await self.service.perform("alice", req, "write",
                                           {"mode": "append", "content": marker})
        self.assertEqual(again["error"]["code"], "duplicate_operation")

    async def test_unauthorized_identity_rejected_before_audit(self):
        request = WriteFileRequest(server="dev", path=str(self.root / "secret"),
                                   reason="synthetic", content="not-written")
        with self.assertRaises(SSHDenied):
            await self.service.perform("bob", request, "write", {"content": "not-written"})
        self.assertEqual(self.viewer.list({})["filtered_total"], 0)

    async def test_lost_append_response_is_unknown_without_replay(self):
        class LostResponse:
            async def execute(self, *args, **kwargs):
                raise FileTransportError("transport_error", "Synthetic connection loss",
                                         uncertain=True)

        self.service.transport = LostResponse()
        request = WriteFileRequest(server="dev", path=str(self.root / "x"),
                                   reason="synthetic", mode="append", content="secret",
                                   operation_id="lost-append-236")
        result = await self.service.perform("alice", request, "write",
                                            {"mode": "append", "content": "secret"})
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(self.viewer.detail(result["history_id"])["status"], "unknown")
        again = await self.service.perform("alice", request, "write",
                                           {"mode": "append", "content": "secret"})
        self.assertEqual(again["error"]["code"], "duplicate_operation")


class store_connection:
    def __init__(self, store):
        self.store = store

    def __enter__(self):
        with self.store._connect() as db:
            self.dump = "\n".join(db.iterdump())
        return self.dump

    def __exit__(self, *_):
        pass


if __name__ == "__main__":
    unittest.main()
