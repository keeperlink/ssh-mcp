"""Guarded, owner-only SQLite online backup and offline restore.

No Docker socket, secrets, or host-wide privileges are needed. Stop the
service before restoring; backups can be taken while it runs.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import tempfile
import time
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from app.output_codec import RAW, decode, encode


def _private_directory(path: Path) -> None:
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise ValueError("Private backup/state directory must exist and be absolute")
    details = path.stat()
    if details.st_uid != os.geteuid() or details.st_mode & 0o077:
        raise ValueError("Private backup/state directory requires current owner and 0700 mode")


def _input(path: Path) -> None:
    _private_directory(path.parent)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Database must be a regular non-symlink file")
    details = path.stat()
    if details.st_uid != os.geteuid() or details.st_mode & 0o077:
        raise ValueError("Database owner and permissions must be private")


def _readonly(path: Path) -> sqlite3.Connection:
    return sqlite3.connect("file:" + quote(str(path), safe="/") + "?mode=ro", uri=True)


def verify(path: Path) -> None:
    _input(path)
    db = _readonly(path)
    try:
        rows = db.execute("PRAGMA integrity_check").fetchall()
        if rows != [("ok",)]:
            raise ValueError("SQLite integrity verification failed")
        names = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        if not {"jobs", "output"}.issubset(names):
            raise ValueError("Backup lacks expected audit tables")
    finally:
        db.close()


def _temporary(destination: Path) -> tuple[int, Path]:
    _private_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Destination already exists; refusing overwrite")
    fd, name = tempfile.mkstemp(prefix=".skymcp-", suffix=".sqlite", dir=destination.parent)
    os.fchmod(fd, 0o600)
    return fd, Path(name)


def _cleanup_temporary(temp: Path) -> None:
    # SQLite can leave WAL/SHM companions after closing the temporary database.
    # Never touch the live jobs.sqlite or its sidecars.
    for suffix in ("-wal", "-shm", ""):
        Path(str(temp) + suffix).unlink(missing_ok=True)


def _sync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def backup(source: Path, destination: Path) -> None:
    """SQLite online backup handles WAL without exposing an inconsistent raw copy."""
    _input(source)
    fd, temp = _temporary(destination)
    os.close(fd)
    try:
        live = _readonly(source)
        try:
            copy = sqlite3.connect(temp)
            try:
                live.backup(copy)
            finally:
                copy.close()
        finally:
            live.close()
        verify(temp)
        # Hard-link publication is atomic: a competing backup cannot replace
        # an already-published recovery snapshot after the initial check.
        with temp.open("rb") as stream:
            os.fsync(stream.fileno())
        os.link(temp, destination)
        _sync_directory(destination.parent)
    finally:
        _cleanup_temporary(temp)


def restore(source: Path, destination: Path, *, service_stopped: bool) -> Path | None:
    """Require an explicit stopped-service assertion, preserve old DB, swap atomically."""
    if not service_stopped:
        raise ValueError("Stop the service and pass --confirm-stopped before restoring")
    verify(source)
    _private_directory(destination.parent)
    if destination.is_symlink():
        raise ValueError("Destination may not be a symlink")
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(destination) + suffix)
        try:
            sidecar.lstat()  # exists() misses dangling symlinks.
        except FileNotFoundError:
            continue
        raise ValueError("Existing SQLite WAL/SHM; stop the service and checkpoint first")
    previous: Path | None = None
    if destination.exists():
        _input(destination)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        previous = destination.parent / (destination.name + ".pre-restore-" + timestamp)
        backup(destination, previous)
    fd, temp = _temporary(destination.parent / (".restore-" + destination.name))
    try:
        with os.fdopen(fd, "wb") as dest, source.open("rb") as orig:
            shutil.copyfileobj(orig, dest)
            dest.flush()
            os.fsync(dest.fileno())
        verify(temp)
        # A restored snapshot may contain superseded refresh tokens.
        # Fail closed by revoking every restored OAuth family before publication.
        imported = sqlite3.connect(temp)
        try:
            with imported:
                if imported.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' "
                    "AND name='oauth_sessions'"
                ).fetchone():
                    imported.execute(
                        "UPDATE oauth_sessions SET revoked_at=? WHERE revoked_at IS NULL",
                        (int(time.time()),),
                    )
        finally:
            imported.close()
        verify(temp)
        os.replace(temp, destination)
        _sync_directory(destination.parent)
    finally:
        _cleanup_temporary(temp)
    return previous


def measure(path: Path) -> dict[str, int | float]:
    """Estimate new encoding against all chunks; bounded one row at a time."""
    _input(path)
    result: dict[str, int | float] = {
        "chunks": 0, "raw_chunks": 0, "compressed_chunks": 0,
        "raw_bytes": 0, "current_blob_bytes": 0, "projected_blob_bytes": 0,
        "projected_saved_bytes": 0, "projected_saved_percent": 0.0,
        "decode_seconds": 0.0, "encode_seconds": 0.0,
        "sqlite_file_bytes": path.stat().st_size, "sqlite_pages": 0,
        "sqlite_page_size": 0, "sqlite_freelist_pages": 0,
    }
    with _readonly(path) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(output)")}
        modern = {"encoding", "raw_length"}.issubset(columns)
        result["sqlite_pages"] = db.execute("PRAGMA page_count").fetchone()[0]
        result["sqlite_page_size"] = db.execute("PRAGMA page_size").fetchone()[0]
        result["sqlite_freelist_pages"] = db.execute("PRAGMA freelist_count").fetchone()[0]
        if modern:
            rows = db.execute("SELECT data,encoding,raw_length FROM output")
        else:
            rows = db.execute("SELECT data FROM output")
        for row in rows:
            data = bytes(row[0])
            encoding = str(row[1]) if modern else RAW
            original = int(row[2]) if modern and row[2] is not None else None
            start = time.perf_counter()
            source = decode(data, encoding, original)
            decode_seconds = time.perf_counter() - start
            start = time.perf_counter()
            candidate, kind, size = encode(source)
            encode_seconds = time.perf_counter() - start
            # Confirm the candidate is byte-exact; never emit or store raw data.
            if decode(candidate, kind, size) != source:
                raise ValueError("Output codec verification failed")
            result["chunks"] += 1
            result["raw_chunks" if kind == RAW else "compressed_chunks"] += 1
            result["raw_bytes"] += len(source)
            result["current_blob_bytes"] += len(data)
            result["projected_blob_bytes"] += len(candidate)
            result["decode_seconds"] += decode_seconds
            result["encode_seconds"] += encode_seconds
    result["projected_saved_bytes"] = result["raw_bytes"] - result["projected_blob_bytes"]
    if result["raw_bytes"]:
        result["projected_saved_percent"] = round(
            100 * result["projected_saved_bytes"] / result["raw_bytes"], 2
        )
    result["decode_seconds"] = round(result["decode_seconds"], 6)
    result["encode_seconds"] = round(result["encode_seconds"], 6)
    return result



def main() -> None:
    parser = argparse.ArgumentParser(
        description="Private audited history backup, restore and output measurement"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for operation in ("backup", "verify", "restore", "compression-benchmark"):
        item = sub.add_parser(operation)
        item.add_argument("source", type=Path)
        if operation not in ("verify", "compression-benchmark"):
            item.add_argument("destination", type=Path)
        if operation == "restore":
            item.add_argument("--confirm-stopped", action="store_true")
    args = parser.parse_args()
    if args.command == "backup":
        backup(args.source, args.destination)
        print("Private SQLite online backup verified")
    elif args.command == "verify":
        verify(args.source)
        print("Private SQLite backup integrity verified")
    elif args.command == "compression-benchmark":
        try:
            data = measure(args.source)
        except (OSError, ValueError, sqlite3.Error):
            print("Benchmark failed: inaccessible or invalid private SQLite audit database",
                  file=sys.stderr)
            raise SystemExit(1) from None
        print(json.dumps(data, sort_keys=True))
    else:
        previous = restore(args.source, args.destination, service_stopped=args.confirm_stopped)
        print("Private SQLite restored and verified")
        if previous is not None:
            print("Pre-restore backup:", previous)


if __name__ == "__main__":
    main()
