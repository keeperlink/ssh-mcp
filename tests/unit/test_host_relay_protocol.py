"""Host relay integration without real SSH: fixed remote subprocess scripts."""
from __future__ import annotations

import hashlib
import os
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from app.relay_scripts import RECEIVER, SOURCE


def invoke(script: str, args: list[str], *, contents: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-u", "-c", script, *args], input=contents,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=15,
    )


class RelayProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)

    def source(self, path: Path, chunk: int = 4096) -> subprocess.CompletedProcess[bytes]:
        return invoke(SOURCE, [str(path), str(1024 * 1024), str(chunk), "SRC-test", "0"])

    def receive(self, target: Path, source: bytes, *, expected: str = "-",
                mode: str = "create", commit: bool = True,
                stale: int = 40000) -> subprocess.CompletedProcess[bytes]:
        digest = hashlib.sha256(source).hexdigest()
        return invoke(RECEIVER, [
            str(target), mode, "0", str(len(source)), digest,
            expected, "4096", str(stale), "DEST-test", "0",
        ], contents=source + (b"COMMIT!" if commit else b""))

    def test_source_and_atomic_destination(self) -> None:
        content = os.urandom(128 * 1024 + 37)
        source = self.root / "source"
        source.write_bytes(content)
        packet = self.source(source)
        self.assertEqual(packet.returncode, 0, packet.stderr)
        self.assertTrue(packet.stderr.endswith(b"\x1eSRC-test\x1e\n"))
        size = struct.unpack(">Q", packet.stdout[:8])[0]
        self.assertEqual(size, len(content))
        self.assertEqual(packet.stdout[8:40], hashlib.sha256(content).digest())
        self.assertEqual(packet.stdout[40:], content)
        target = self.root / "target"
        result = self.receive(target, packet.stdout[40:])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(target.read_bytes(), content)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertFalse(list(self.root.glob(".ssh-mcp-transfer-*")))

    def test_zero_length(self) -> None:
        source = self.root / "empty"
        source.write_bytes(b"")
        self.assertEqual(len(self.source(source).stdout), 40)
        target = self.root / "dest"
        self.assertEqual(self.receive(target, b"").returncode, 0)
        self.assertEqual(target.read_bytes(), b"")

    def test_cancelled_stream_keeps_existing_and_removes_stage(self) -> None:
        target = self.root / "target"
        target.write_bytes(b"existing")
        incoming = b"new payload"
        result = self.receive(target, incoming, mode="overwrite", commit=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_bytes(), b"existing")
        self.assertFalse(list(self.root.glob(".ssh-mcp-transfer-*")))

    def test_preimage_cas_and_create_collision(self) -> None:
        target = self.root / "target"
        target.write_bytes(b"original")
        digest = hashlib.sha256(b"original").hexdigest()
        self.assertNotEqual(self.receive(target, b"abc").returncode, 0)
        self.assertNotEqual(self.receive(target, b"abc", expected="0" * 64,
                                         mode="overwrite").returncode, 0)
        self.assertEqual(target.read_bytes(), b"original")
        self.assertEqual(self.receive(target, b"replacement", expected=digest,
                                      mode="overwrite").returncode, 0)
        self.assertEqual(target.read_bytes(), b"replacement")

    def test_create_collision_after_receiver_ready_is_specific(self) -> None:
        target = self.root / "raced-target"
        payload = b"data waiting for commit"
        digest = hashlib.sha256(payload).hexdigest()
        args = [sys.executable, "-u", "-c", RECEIVER, str(target),
                "create", "0", str(len(payload)), digest, "-", "4096",
                "40000", "DEST-test", "0"]
        with subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as proc:
            assert proc.stderr is not None
            marker = proc.stderr.readline()
            self.assertEqual(marker, b"\x1eDEST-test\x1e\n")
            # Inject a competing publication AFTER the receiver passed its
            # initial exists check and created its private staging file.
            target.write_bytes(b"published by another writer")
            received, errors = proc.communicate(payload + b"COMMIT!", timeout=15)
            self.assertEqual(proc.returncode, 73, errors)
            self.assertEqual(received, b"")
        self.assertEqual(target.read_bytes(), b"published by another writer")
        self.assertFalse(list(self.root.glob(".ssh-mcp-transfer-*")))

    def test_pruner_does_not_remove_locked_stage(self) -> None:
        import fcntl

        stale = self.root / (".ssh-mcp-transfer-" + "0" * 32)
        # Create a fixture with the private 0600 permissions of real stages.
        fd = os.open(str(stale), os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
        os.utime(stale, (1, 1))
        with stale.open("rb") as file:
            fcntl.flock(file.fileno(), fcntl.LOCK_EX)
            self.assertEqual(self.receive(self.root / "first", b"a", stale=1).returncode, 0)
            self.assertTrue(stale.exists())
        self.assertEqual(self.receive(self.root / "second", b"b", stale=1).returncode, 0)
        self.assertFalse(stale.exists())


if __name__ == "__main__":
    unittest.main()
