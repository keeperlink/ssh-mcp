"""TEST-242 lossless output compression, migration, and failure contract tests."""
from __future__ import annotations

import base64
import os
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from app.contracts import ExecuteCommandRequest
from app.jobs import JobStore
from app.output_codec import (
    MAX_RAW_CHUNK, MIN_SIZE, OutputCorruption, RAW, ZLIB_V1, decode, encode,
)
from ops.history_db import backup, restore, verify


def request() -> ExecuteCommandRequest:
    return ExecuteCommandRequest(
        server="demo-node-b", argv=["printf", "synthetic"], reason="Synthetic TEST-242"
    )


def contents(page: dict) -> list[tuple[str, bytes]]:
    return [
        (item["stream"], base64.b64decode(item["data_base64"], validate=True))
        for item in page["chunks"]
    ]


class CodecTests(unittest.TestCase):
    def test_small_incompressible_and_binary_chunks_remain_byte_exact(self):
        for source in (
            b"", b"A" * (MIN_SIZE - 1), os.urandom(MIN_SIZE),
            os.urandom(4096), bytes(range(256)) * 4,
            b"\x00\xff\xfe" * 400,
        ):
            with self.subTest(length=len(source)):
                stored, kind, raw_length = encode(source)
                self.assertEqual(raw_length, len(source))
                self.assertEqual(decode(stored, kind, raw_length), source)
                if len(source) < MIN_SIZE or source in (b"",):
                    self.assertEqual(kind, RAW)

    def test_large_repetitive_and_max_length_are_compressed(self):
        for source in (b"\x00\xffABC" * 1024, b"\xe4\xbd\xa0" * 3000,
                       b"z" * MAX_RAW_CHUNK):
            with self.subTest(length=len(source)):
                stored, kind, raw_length = encode(source)
                self.assertEqual(kind, ZLIB_V1)
                self.assertLessEqual(len(stored), 0.85 * len(source))
                self.assertEqual(raw_length, len(source))
                self.assertEqual(decode(stored, kind, raw_length), source)
        with self.assertRaisesRegex(ValueError, "capture bound"):
            encode(b"x" * (MAX_RAW_CHUNK + 1))

    def test_threshold_is_inclusive_and_zlib_level_six(self):
        with patch("app.output_codec.zlib.compress", return_value=b"x" * 850) as compress:
            raw, kind, _ = encode(b"a" * 1000)
            self.assertEqual(kind, RAW)
            self.assertEqual(len(raw), 1000)
            compress.assert_not_called()
            _, kind, _ = encode(b"a" * 1024)
            self.assertEqual(kind, ZLIB_V1)
            compress.assert_called_once_with(b"a" * 1024, level=6)
        with patch("app.output_codec.zlib.compress", return_value=b"x" * 871):
            self.assertEqual(encode(b"a" * 1024)[1], RAW)
        with patch("app.output_codec.zlib.compress", return_value=b"x" * 870):
            self.assertEqual(encode(b"a" * 1024)[1], ZLIB_V1)

    def test_corrupt_unknown_and_unbounded_inputs_fail_safely(self):
        source = b"SENSITIVE_OUTPUT_TOKEN" * 256
        stored, encoding, raw_length = encode(source)
        assert encoding == ZLIB_V1
        bad = [
            (stored, "unknown-v99", raw_length),
            (source, RAW, len(source) - 1),
            (source, RAW, -1),
            (source, RAW, "unexpected"),
            (source, RAW, True),
            (source, RAW, MAX_RAW_CHUNK + 1),
            (b"not zlib", ZLIB_V1, raw_length),
            (stored[:-1], ZLIB_V1, raw_length),
            (stored + b"trailing", ZLIB_V1, raw_length),
            (stored, ZLIB_V1, raw_length - 1),
            (stored, ZLIB_V1, raw_length + 1),
            (stored, ZLIB_V1, None),
            (stored, ZLIB_V1, MAX_RAW_CHUNK + 1),
            (b"a" * (MAX_RAW_CHUNK + 1), RAW, None),
        ]
        for data, codec, length in bad:
            with self.subTest(codec=codec, raw_length=length, length=len(data)):
                with self.assertRaises(OutputCorruption) as error:
                    decode(data, codec, length)
                self.assertEqual(str(error.exception), "Invalid or corrupted stored output chunk")
                self.assertNotIn("SENSITIVE_OUTPUT_TOKEN", str(error.exception))

    def test_zlib_bomb_never_exceeds_declared_raw_bound(self):
        import zlib
        bomb = zlib.compress(b"A" * (MAX_RAW_CHUNK + 1))
        with self.assertRaises(OutputCorruption):
            decode(bomb, ZLIB_V1, MAX_RAW_CHUNK)
        with self.assertRaises(OutputCorruption):
            decode(bomb, ZLIB_V1, 16)


class StoreCompressionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "private"
        self.root.mkdir(mode=0o700)
        self.path = self.root / "jobs.sqlite"
        self.store = JobStore(self.path)

    def job(self) -> str:
        ident = self.store.create("alice", request())
        self.assertTrue(self.store.begin(ident))
        return ident

    def output_row(self, ident: str, offset: int = 0) -> sqlite3.Row:
        with self.store._connect() as db:
            result = db.execute(
                "SELECT * FROM output WHERE job_id=? AND offset=?", (ident, offset)
            ).fetchone()
        assert result is not None
        return result

    def test_storage_selection_offsets_interleaved_and_binary_page_splits(self):
        ident = self.job()
        compressed = b"\x00\xff\xe2\x82\xac" * 1000
        random_binary = os.urandom(2000)
        parts = [("stdout", b"one"), ("stderr", compressed), ("stdout", random_binary),
                 ("stderr", b"last")]
        for stream, value in parts:
            self.store.append(ident, stream, value)
        self.store.finish(ident, "succeeded", exit_code=0)
        offset = 0
        logical = b"".join(value for _, value in parts)
        with self.store._connect() as db:
            rows = db.execute(
                "SELECT offset,stream,encoding,raw_length,length(data) AS encoded "
                "FROM output WHERE job_id=? ORDER BY offset", (ident,)
            ).fetchall()
            self.assertEqual([row["offset"] for row in rows], [0, 3, 5003, 7003])
            self.assertEqual([row["raw_length"] for row in rows], [3, 5000, 2000, 4])
            self.assertEqual([row["encoding"] for row in rows], [
                RAW, ZLIB_V1, RAW, RAW,
            ])
            self.assertLess(rows[1]["encoded"], 5000)
        collected: list[bytes] = []
        streams: list[str] = []
        while offset < len(logical):
            page = self.store.read_output("alice", ident, cursor=offset, max_bytes=7)
            self.assertIsNotNone(page)
            assert page is not None
            for stream, value in contents(page):
                streams.append(stream)
                collected.append(value)
            self.assertEqual(page["next_cursor"], offset + 7 if offset + 7 <= len(logical)
                             else len(logical))
            offset = page["next_cursor"]
            self.assertEqual(page["truncated"], offset < len(logical))
        self.assertEqual(b"".join(collected), logical)
        self.assertIn("stdout", streams)
        self.assertIn("stderr", streams)
        self.assertIsNone(self.store.read_output("bob", ident))
        self.assertEqual(self.store.get("alice", ident)["output_bytes"], len(logical))
        eof = self.store.read_output("alice", ident, cursor=len(logical))
        self.assertEqual(eof["chunks"], [])
        self.assertFalse(eof["truncated"])
        with self.assertRaisesRegex(ValueError, "past end"):
            self.store.read_output("alice", ident, cursor=len(logical) + 1)

    def test_cursor_inside_large_compressed_block_skips_unrelated_chunk(self):
        ident = self.job()
        self.store.append(ident, "stdout", b"FIRST" * 1024)
        self.store.append(ident, "stderr", b"SECOND" * 1024)
        with patch("app.jobs.decode_output", wraps=decode) as read:
            page = self.store.read_output("alice", ident, cursor=5121, max_bytes=10)
            self.assertEqual(contents(page), [("stderr", b"ECONDSECON")])
            self.assertEqual(read.call_count, 1)  # first chunk never decompressed
        page = self.store.read_output("alice", ident, cursor=5119, max_bytes=4)
        self.assertEqual(contents(page), [("stdout", b"T"), ("stderr", b"SEC")])

    def test_utf8_unsafe_splits_and_exact_capture_length(self):
        ident = self.job()
        data = ("é中🙂".encode("utf-8") * 500) + b"\x00\xff"
        self.store.append(ident, "stdout", data)
        self.assertEqual(self.output_row(ident)["encoding"], ZLIB_V1)
        pieces = []
        for offset in range(len(data)):
            result = self.store.read_output("alice", ident, cursor=offset, max_bytes=1)
            assert result
            pieces.extend(chunk for _, chunk in contents(result))
        self.assertEqual(b"".join(pieces), data)
        self.assertEqual(self.store.get("alice", ident)["output_bytes"], len(data))
        with self.assertRaisesRegex(ValueError, "output cursor"):
            self.store.read_output("alice", ident, max_bytes=65537)

    def test_mixed_historical_raw_null_length_and_restart(self):
        ident = self.job()
        old = b"historical raw uncompressed" * 200
        new = b"new compressed" * 300
        with self.store._connect() as db:
            db.execute(
                "INSERT INTO output(job_id,offset,stream,data) VALUES(?,?,?,?)",
                (ident, 0, "stdout", old),
            )
            db.execute("UPDATE jobs SET output_bytes=? WHERE id=?", (len(old), ident))
        self.store.append(ident, "stderr", new)
        self.store.finish(ident, "succeeded")
        row = self.output_row(ident)
        self.assertEqual(row["encoding"], RAW)
        self.assertIsNone(row["raw_length"])
        self.assertEqual(self.output_row(ident, len(old))["encoding"], ZLIB_V1)
        reopened = JobStore(self.path)
        page = reopened.read_output("alice", ident, cursor=len(old) - 3, max_bytes=9)
        self.assertEqual(contents(page), [
            ("stdout", old[-3:]), ("stderr", new[:6])
        ])
        self.assertIsNone(reopened.read_output("bob", ident))

    def test_corrupt_and_unknown_codec_fail_actor_scoped_without_leaks(self):
        ident = self.job()
        secret = b"never_return_SECRET_STRING" * 100
        self.store.append(ident, "stdout", secret)
        self.assertIsNone(self.store.read_output("bob", ident))
        for kind, data, declared in (
            ("unknown", b"unknown", 1000),
            (ZLIB_V1, b"corrupt SECRET", 3000),
            (ZLIB_V1, self.output_row(ident)["data"], MAX_RAW_CHUNK + 1),
            (RAW, secret, len(secret) - 1),
        ):
            with self.subTest(kind=kind):
                with self.store._connect() as db:
                    db.execute(
                        "UPDATE output SET encoding=?,data=?,raw_length=? WHERE job_id=?",
                        (kind, data, declared, ident),
                    )
                with self.assertRaises(OutputCorruption) as exc:
                    self.store.read_output("alice", ident)
                self.assertEqual(str(exc.exception), "Invalid or corrupted stored output chunk")
                self.assertNotIn("SECRET", str(exc.exception))

    def test_invalid_length_metadata_cannot_silently_hide_a_row(self):
        ident = self.job()
        self.store.append(ident, "stdout", b"x" * 4096)
        for invalid in (-1, 0, "corrupt", MAX_RAW_CHUNK + 1):
            with self.subTest(invalid=invalid):
                with self.store._connect() as db:
                    db.execute("UPDATE output SET raw_length=? WHERE job_id=?",
                               (invalid, ident))
                with self.assertRaises(OutputCorruption) as error:
                    self.store.read_output("alice", ident, cursor=0)
                self.assertEqual(str(error.exception),
                                 "Invalid or corrupted stored output chunk")

    def test_understated_compressed_length_never_skips_a_cursor_page(self):
        # Reviewer P2: a cursor within 4096 logical zlib bytes must never
        # be filtered out by corrupted raw_length metadata (0, text, 10).
        for has_trailing in (False, True):
            with self.subTest(has_trailing=has_trailing):
                ident = self.job()
                data = b"X" * 4096
                self.store.append(ident, "stdout", data)
                self.assertEqual(self.output_row(ident)["encoding"], ZLIB_V1)
                if has_trailing:
                    self.store.append(ident, "stderr", b"Y" * 2048)
                for invalid in (0, "broken", 10):
                    with self.subTest(invalid=invalid):
                        with self.store._connect() as db:
                            db.execute(
                                "UPDATE output SET raw_length=? "
                                "WHERE job_id=? AND offset=0",
                                (invalid, ident),
                            )
                        for cursor in (0, 100, 4095):
                            with self.subTest(cursor=cursor):
                                with self.assertRaises(OutputCorruption) as error:
                                    self.store.read_output(
                                        "alice", ident, cursor=cursor, max_bytes=16,
                                    )
                                self.assertEqual(
                                    str(error.exception),
                                    "Invalid or corrupted stored output chunk",
                                )
                # A real cursor spanning the first valid compressed record
                # and the next one must still return original byte offsets.
                with self.store._connect() as db:
                    db.execute(
                        "UPDATE output SET raw_length=? "
                        "WHERE job_id=? AND offset=0", (len(data), ident),
                    )
                page = self.store.read_output(
                    "alice", ident, cursor=4090, max_bytes=16,
                )
                expected = [("stdout", b"X" * 6)]
                if has_trailing:
                    expected.append(("stderr", b"Y" * 10))
                self.assertEqual(contents(page), expected)
                self.assertEqual(
                    page["next_cursor"], 4106 if has_trailing else 4096,
                )
                self.assertEqual(page["truncated"], has_trailing)

    def test_read_pagination_uses_one_snapshot_during_concurrent_append(self):
        ident = self.job()
        self.store.append(ident, "stdout", b"first" * 400)
        original_connect = self.store._connect
        appended = False

        def connection_with_append_hook() -> sqlite3.Connection:
            db = original_connect()

            def trace(sql: str) -> None:
                nonlocal appended
                if not appended and "SELECT offset FROM output" in sql:
                    appended = True
                    # This separate writer commits while the read transaction
                    # is open. The reader must not mix the old job total with
                    # newly committed output rows from the second SELECT.
                    self.store.append(ident, "stderr", b"later" * 400)

            db.set_trace_callback(trace)
            return db

        with patch.object(self.store, "_connect", side_effect=connection_with_append_hook):
            first = self.store.read_output("alice", ident)
        self.assertTrue(appended)
        self.assertEqual(contents(first), [("stdout", b"first" * 400)])
        self.assertEqual(first["next_cursor"], 2000)
        self.assertFalse(first["truncated"])
        follow = self.store.read_output("alice", ident, cursor=2000)
        self.assertEqual(contents(follow), [("stderr", b"later" * 400)])
        self.assertEqual(follow["next_cursor"], 4000)
        self.assertFalse(follow["truncated"])

    def test_valid_short_chunk_with_gap_never_advances_cursor_incorrectly(self):
        # A malicious/partial raw row can have self-consistent metadata yet
        # disagree with the next offset (or with jobs.output_bytes).
        for has_trailing in (False, True):
            ident = self.job()
            self.store.append(ident, "stdout", b"A" * 4096)
            if has_trailing:
                self.store.append(ident, "stderr", b"B" * 1024)
            with self.store._connect() as db:
                db.execute(
                    "UPDATE output SET encoding='raw',data=?,raw_length=? "
                    "WHERE job_id=? AND offset=0",
                    (b"A" * 10, 10, ident),
                )
            for cursor in (0, 5, 10, 100):
                with self.subTest(trailing=has_trailing, cursor=cursor):
                    with self.assertRaises(OutputCorruption):
                        self.store.read_output(
                            "alice", ident, cursor=cursor, max_bytes=4,
                        )

    def test_missing_or_gapped_first_chunk_fails_without_stalled_page(self):
        ident = self.job()
        self.store.append(ident, "stdout", b"missing first" * 400)
        self.store.append(ident, "stderr", b"valid second" * 300)
        with self.store._connect() as db:
            db.execute("DELETE FROM output WHERE job_id=? AND offset=0", (ident,))
        for cursor in (0, 100):
            with self.assertRaises(OutputCorruption):
                self.store.read_output("alice", ident, cursor=cursor)

    def test_backup_restore_retention_and_wal_with_compressed_rows(self):
        ident = self.job()
        data = b"A" * 4096
        self.store.append(ident, "stdout", data)
        self.store.finish(ident, "succeeded")
        self.assertEqual(self.output_row(ident)["encoding"], ZLIB_V1)
        snap = self.root / "snapshot.sqlite"
        backup(self.path, snap)
        verify(snap)
        restored = self.root / "restored.sqlite"
        self.assertIsNone(restore(snap, restored, service_stopped=True))
        from_backup = JobStore(restored)
        self.assertEqual(contents(from_backup.read_output("alice", ident)),
                         [("stdout", data)])
        with from_backup._connect() as db:
            self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            db.execute("UPDATE jobs SET ended_at=? WHERE id=?", (1, ident))
        pruned = JobStore(restored, retention_seconds=3600)
        self.assertIsNone(pruned.get("alice", ident))
        with pruned._connect() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM output WHERE job_id=?", (ident,)
            ).fetchone()[0], 0)

    def test_aggregate_only_benchmark_does_not_emit_sensitive_output(self):
        import json
        from ops.history_db import measure
        ident = self.job()
        sensitive = b"SENSITIVE_AUDIT_TEXT_DO_NOT_PRINT" * 200
        self.store.append(ident, "stdout", sensitive)
        self.store.append(ident, "stderr", os.urandom(1024))
        self.store.finish(ident, "succeeded")
        data = measure(self.path)
        self.assertEqual(data["chunks"], 2)
        self.assertEqual(data["compressed_chunks"], 1)
        self.assertEqual(data["raw_chunks"], 1)
        self.assertEqual(data["raw_bytes"], len(sensitive) + 1024)
        self.assertGreater(data["projected_saved_percent"], 0)
        self.assertGreater(data["sqlite_pages"], 0)
        self.assertGreater(data["sqlite_page_size"], 0)
        self.assertNotIn("SENSITIVE_AUDIT_TEXT_DO_NOT_PRINT", json.dumps(data))
        self.assertEqual(data["current_blob_bytes"], data["projected_blob_bytes"])
        self.assertGreaterEqual(data["encode_seconds"], 0)
        self.assertGreaterEqual(data["decode_seconds"], 0)

    def test_benchmark_command_requires_no_destination_and_emits_only_stats(self):
        import json
        import subprocess
        import sys
        ident = self.job()
        self.store.append(ident, "stdout", b"NEVER_EXPOSE_THIS_BLOB" * 150)
        self.store.finish(ident, "succeeded")
        result = subprocess.run(
            [sys.executable, "-m", "ops.history_db", "compression-benchmark",
             str(self.path)],
            check=True, text=True, capture_output=True,
        )
        stats = json.loads(result.stdout)
        self.assertEqual(stats["chunks"], 1)
        self.assertEqual(stats["compressed_chunks"], 1)
        self.assertEqual(stats["raw_bytes"], len(b"NEVER_EXPOSE_THIS_BLOB" * 150))
        self.assertNotIn("NEVER_EXPOSE_THIS_BLOB", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_benchmark_accepts_legacy_output_columns_and_invalid_db_fails(self):
        from ops.history_db import measure
        ident = self.job()
        self.store.append(ident, "stdout", b"ABC" * 1024)
        with self.store._connect() as db:
            # It should not interpret stored zlib bytes as legacy raw unless
            # the original raw-only schema is present.
            db.execute(
                "UPDATE output SET data=?,encoding='raw',raw_length=NULL WHERE job_id=?",
                (b"legacy raw" * 200, ident),
            )
        summary = measure(self.path)
        self.assertEqual(summary["chunks"], 1)
        self.assertEqual(summary["raw_bytes"], len(b"legacy raw" * 200))
        with self.assertRaises((FileNotFoundError, ValueError, OSError)):
            measure(self.root / "absent.sqlite")

    def test_ssh_capture_limit_applies_to_raw_bytes_not_compressed_size(self):
        import asyncio
        from app.ssh_executor import OutputLimitExceeded, _bounded_read
        async def run() -> None:
            ident = self.job()
            stream = asyncio.StreamReader()
            stream.feed_data(b"A" * 2048)
            stream.feed_eof()
            async def capture(name: str, chunk: bytes) -> None:
                self.store.append(ident, name, chunk)
            with self.assertRaises(OutputLimitExceeded):
                await _bounded_read(stream, 1024, "stdout", capture, [0])
            self.assertEqual(self.store.get("alice", ident)["output_bytes"], 1024)
            self.assertEqual(self.output_row(ident)["raw_length"], 1024)
            self.assertEqual(self.output_row(ident)["encoding"], ZLIB_V1)
            self.assertEqual(contents(self.store.read_output("alice", ident)),
                             [("stdout", b"A" * 1024)])
            self.store.finish(ident, "output_limit")
            self.assertEqual(self.store.get("alice", ident)["status"], "output_limit")
            self.assertFalse(self.store.read_output("alice", ident)["truncated"])
        asyncio.run(run())

    def test_current_raw_rows_are_not_rewritten_on_reopen(self):
        legacy = self.root / "old.sqlite"
        # The original raw-output schema is now the minimum supported
        # baseline; exercise stored raw chunks in that current schema.
        JobStore(legacy)
        with closing(sqlite3.connect(legacy)) as db:
            current = time.time()
            blob = b"legacy" * 350
            db.execute("""INSERT INTO jobs
                (id,actor,server,command,argv_count,command_sha256,status,
                 created_at,updated_at,ended_at,output_bytes)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                ("legacy", "alice", "demo-node-b", "echo", 1, "0" * 64,
                 "succeeded", current, current, current, len(blob)))
            db.execute("INSERT INTO output(job_id,offset,stream,data) VALUES(?,?,?,?)", ("legacy", 0, "stdout", blob))
            db.commit()
        legacy.chmod(0o600)
        from ops.history_db import measure
        before = measure(legacy)
        self.assertEqual(before["chunks"], 1)
        self.assertEqual(before["raw_bytes"], len(blob))
        upgraded = JobStore(legacy)
        with upgraded._connect() as db:
            row = db.execute(
                "SELECT encoding,raw_length,data FROM output WHERE job_id='legacy'"
            ).fetchone()
            self.assertEqual((row["encoding"], row["raw_length"], bytes(row["data"])),
                             (RAW, None, blob))
            self.assertEqual(db.execute(
                "SELECT request_json FROM jobs WHERE id='legacy'"
            ).fetchone()[0], None)
        self.assertEqual(contents(upgraded.read_output("alice", "legacy")),
                         [("stdout", blob)])
        again = JobStore(legacy)
        self.assertEqual(contents(again.read_output("alice", "legacy")),
                         [("stdout", blob)])
        with again._connect() as db:
            self.assertEqual(len(db.execute("PRAGMA table_info(output)").fetchall()), 6)
