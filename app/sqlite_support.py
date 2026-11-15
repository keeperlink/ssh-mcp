"""Configuration-independent, owner-only SQLite helpers for audit and OAuth.

Offline CLI utilities import this module without loading app.config or
preparing signed web-service startup mounts.
"""
from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path
from types import TracebackType
from typing import Literal


def _prepare_path(path: Path, *, create: bool = True) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("Job database path must be absolute and not a symlink")
    parent = path.parent
    if parent.is_symlink():
        raise ValueError("Job database directory must not be a symlink")
    if not parent.exists():
        if not create:
            raise FileNotFoundError("Private database directory does not exist")
        parent.mkdir(mode=0o700)
    pstat = parent.stat()
    if (
        not stat.S_ISDIR(pstat.st_mode)
        or pstat.st_uid != os.geteuid()
        or pstat.st_mode & 0o077
    ):
        raise PermissionError("Job database directory must be private and owned")
    if path.exists():
        details = path.stat()
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_mode & 0o077
        ):
            raise PermissionError("Job database must be a private regular file")
    else:
        if not create:
            raise FileNotFoundError("Private database does not exist")
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(fd)


class _ClosingConnection(sqlite3.Connection):
    """Commit or rollback and close after context exit, including exceptions."""

    def __exit__(
        self, exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        try:
            super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()
        return False
