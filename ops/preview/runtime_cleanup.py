"""Guarded cleanup of generated SSH identity files for lab Uvicorn reloads.

The production bootstrap intentionally rejects a nonempty private runtime
directory. The temporary preview container retains its tmpfs between worker
restarts, so only verified files from the previous worker can be removed.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat


RUNTIME_DIR = Path("/run/ssh-mcp")
GENERATED = frozenset({"identity", "inventory.json"})


def prepare_for_reload(directory: Path = RUNTIME_DIR) -> None:
    """Remove only expected prior-worker artifacts, or fail closed."""
    directory_stat = directory.lstat()
    if (not stat.S_ISDIR(directory_stat.st_mode)
            or directory_stat.st_uid != os.geteuid()
            or stat.S_IMODE(directory_stat.st_mode) != 0o700):
        raise RuntimeError("Unsafe preview private runtime directory")

    entries = list(directory.iterdir())
    if any(path.name not in GENERATED for path in entries):
        raise RuntimeError("Unexpected preview private runtime entry")
    # Inspect every entry before unlinking any of them. Never follow links.
    for path in entries:
        entry_stat = path.lstat()
        if (not stat.S_ISREG(entry_stat.st_mode)
                or entry_stat.st_uid != os.geteuid()
                or stat.S_IMODE(entry_stat.st_mode) != 0o600
                or entry_stat.st_nlink != 1):
            raise RuntimeError("Unsafe preview private runtime file")
    for path in entries:
        path.unlink()
