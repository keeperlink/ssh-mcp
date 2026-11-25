"""TEST-288 inline base64 binary upload for clients without native attachments."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pydantic import ValidationError

from app import config
from app.approval_preview import approval_summary
from app.contracts import UploadFileContentRequest
from app.file_transfer import BinaryTransferService
from app.file_transport import FileTransportError
from app.history import HistoryStore
from app.jobs import JobStore
from app.ssh_executor import HostSpec, SSHDenied, SSHExecutor

PRIVATE = b"INLINE_PRIVATE_NEVER_PERSIST-\x00\xff"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def request(path: str, data: bytes = b"payload", **other: object) -> UploadFileContentRequest:
    fields: dict[str, object] = {
        "server": "dev", "path": path, "reason": "synthetic inline upload",
        "story_id": "TEST-288", "content_base64": encode(data), **other,
    }
    return UploadFileContentRequest.model_validate(fields)


class InlineRequestTests(unittest.TestCase):
    def test_default_cap_is_one_mebibyte(self):
        self.assertEqual(config.SSH_UPLOAD_CONTENT_MAX_BYTES, 1024 * 1024)

    def test_cap_boundary_empty_and_invalid_base64(self):
        limit = config.SSH_UPLOAD_CONTENT_MAX_BYTES
        self.assertEqual(len(request("/tmp/x", b"\x01" * limit).content()), limit)
        self.assertEqual(request("/tmp/x", b"").content(), b"")
        with self.assertRaises(ValidationError):
            request("/tmp/x", b"\x01" * (limit + 1))
        for bad in ("not base64!", "YWJj=", "YQ", "YW Jj"):
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                UploadFileContentRequest.model_validate({
                    "server": "dev", "path": "/tmp/x", "reason": "r",
                    "content_base64": bad,
                })

    def test_configured_smaller_cap_is_enforced(self):
        with patch.object(config, "SSH_UPLOAD_CONTENT_MAX_BYTES", 4):
            self.assertEqual(request("/tmp/x", b"abcd").content(), b"abcd")
            with self.assertRaises(ValidationError):
                request("/tmp/x", b"abcde")
            # Over-long encodings are rejected before decoding.
            with self.assertRaises(ValidationError):
                request("/tmp/x", b"abcdefghijkl")

    def test_strict_fields_and_no_url_parameter(self):
        for extra in ({"file": {"file_id": "x", "download_url": "https://x.invalid/a"}},
                      {"actor": "someone-else"}, {"mode": "append"}):
            with self.subTest(extra=extra), self.assertRaises(ValidationError):
                request("/tmp/x", **extra)
        with self.assertRaises(ValidationError):
            UploadFileContentRequest.model_validate({
                "server": "dev", "path": "/tmp/x", "reason": "r", "content_base64": 3,
            })

    def test_approval_summary_shows_path_not_content(self):
        summary = approval_summary("upload_file_content", {
            "server": "dev", "path": "uploads/blob.bin", "base_dir": "/srv",
            "reason": "r", "content_base64": encode(PRIVATE),
        })
        self.assertEqual(summary, "/srv/uploads/blob.bin")
        self.assertNotIn(encode(PRIVATE), summary)


class InlineServiceTests(unittest.IsolatedAsyncioTestCase):
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
            return await spawn_original(*argv, env={**os.environ, "HOME": str(self.root)},
                                        **kwargs)

        a = patch("app.file_transport._ssh_argv", side_effect=lambda host, req, **kw: req.argv)
        b = patch("app.file_transport.asyncio.create_subprocess_exec", side_effect=spawn)
        a.start()
        b.start()
        self.addCleanup(a.stop)
        self.addCleanup(b.stop)

    async def upload(self, req: UploadFileContentRequest) -> dict:
        async def no_url(*_args, **_kwargs):
            raise AssertionError("inline upload must not fetch a URL")
        with patch("app.file_transfer.read_binary_file", new=no_url):
            return await self.service.upload("alice", req)

    async def test_chunked_inline_upload_publishes_verified_bytes_without_persisting(self):
        body = PRIVATE + bytes(range(256)) * 1200  # Several 128 KiB helper chunks.
        target = self.root / "nested" / "inline.bin"
        reply = await self.upload(request(str(target), body, create_parents=True,
                                          source_sha256=sha(body), operation_id="inline-ok-288"))
        self.assertEqual(reply["status"], "succeeded", reply)
        self.assertEqual(target.read_bytes(), body)
        self.assertEqual(reply["result"]["sha256"], sha(body))
        self.assertEqual(reply["result"]["bytes"], len(body))
        self.assertFalse(any(self.root.rglob(".ssh-mcp-upload-*")))
        detail = self.viewer.detail(reply["history_id"])
        self.assertEqual(detail["file_metadata"]["transfer"]["direction"], "upload")
        self.assertEqual(detail["file_metadata"]["transfer"]["sha256"], sha(body))
        database = b"".join(path.read_bytes() for path in (self.root / "audit").iterdir())
        self.assertNotIn(PRIVATE, database)
        self.assertNotIn(encode(PRIVATE).encode(), database)

    async def test_checksum_create_conflict_and_overwrite(self):
        target = self.root / "target.bin"
        broken = await self.upload(request(str(target), b"new", source_sha256="0" * 64))
        self.assertEqual(broken["status"], "failed")
        self.assertEqual(broken["error"]["code"], "precondition_failed")
        self.assertFalse(target.exists())
        target.write_bytes(b"old")
        collision = await self.upload(request(str(target), b"new", operation_id="collide-288"))
        self.assertEqual(collision["error"]["code"], "already_exists")
        self.assertEqual(target.read_bytes(), b"old")
        replaced = await self.upload(request(
            str(target), b"new", operation_id="overwrite-288",
            mode="overwrite", expected_sha256=sha(b"old")))
        self.assertEqual(replaced["status"], "succeeded", replaced)
        self.assertEqual(target.read_bytes(), b"new")
        self.assertFalse(any(self.root.glob(".ssh-mcp-upload-*")))

    async def test_interrupted_chunk_is_unknown_and_not_aborted(self):
        calls: list[str] = []

        async def fake(_actor, _host, operation, _args):
            calls.append(operation)
            if operation == "upload_start":
                return {"ok": True, "session_id": "a" * 32}
            raise FileTransportError("timeout", "synthetic", uncertain=True)

        with patch.object(self.service.transport, "execute", new=fake):
            reply = await self.upload(request(str(self.root / "chunk"), b"secret"))
        self.assertEqual(reply["status"], "unknown")
        self.assertEqual(calls, ["upload_start", "upload_chunk"])

    async def test_interrupted_finish_is_unknown_and_duplicate_is_rejected(self):
        target = self.root / "finish.bin"
        original = self.service.transport.execute

        async def lose_finish(actor, server, operation, data, **kw):
            if operation == "upload_finish":
                raise FileTransportError("transport_error", "synthetic", uncertain=True)
            return await original(actor, server, operation, data, **kw)

        req = request(str(target), b"not published", operation_id="inline-finish-288")
        with patch.object(self.service.transport, "execute", side_effect=lose_finish):
            failed = await self.upload(req)
        self.assertEqual(failed["status"], "unknown")
        self.assertFalse(target.exists())
        repeated = await self.upload(req)
        self.assertEqual(repeated["status"], "failed")
        self.assertEqual(repeated["error"]["code"], "duplicate_operation")
        self.assertFalse(target.exists())

    async def test_unauthorized_actor_never_starts_audit_or_ssh(self):
        with self.assertRaises(SSHDenied):
            await self.service.upload("mallory", request(str(self.root / "denied")))
        self.assertFalse((self.root / "denied").exists())


if __name__ == "__main__":
    unittest.main()
