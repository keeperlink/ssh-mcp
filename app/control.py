"""Local, memory-only service logging control; never an HTTP endpoint."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
import json
import logging
import os
from pathlib import Path
import stat
from typing import Any, AsyncIterator

LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
SOCKET = Path("/run/ssh-mcp/control.sock")
LIMIT = 1024
TIMEOUT = 2.0
LOGGER = logging.getLogger("app")


def configure_logging(level: str) -> None:
    if level not in LEVELS:
        raise ValueError("Invalid logging level")
    # Configure only application loggers; leave SDK, HTTP and SSH library
    # levels untouched so enabling diagnostics cannot enable their wire logs.
    LOGGER.setLevel(level)
    if not LOGGER.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
        LOGGER.addHandler(handler)
    LOGGER.propagate = False


def command(request: Any, configured: str) -> dict[str, str]:
    if type(request) is not dict:
        raise ValueError("Invalid control request")
    action = request.get("action")
    previous = logging.getLevelName(LOGGER.getEffectiveLevel())
    if action in ("get", "reset") and set(request) == {"action"}:
        if action == "reset":
            LOGGER.setLevel(configured)
    elif action == "set" and set(request) == {"action", "level"} and request["level"] in LEVELS:
        LOGGER.setLevel(request["level"])
    else:
        raise ValueError("Invalid control request")
    return {"status": "ok", "configured": configured, "previous": previous,
            "effective": logging.getLevelName(LOGGER.getEffectiveLevel())}


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, configured: str) -> None:
    try:
        try:
            line = await asyncio.wait_for(reader.readuntil(b"\n"), TIMEOUT)
            response = command(json.loads(line), configured)
        except (ValueError, TypeError, asyncio.LimitOverrunError, asyncio.IncompleteReadError,
                TimeoutError, RecursionError):
            response = {"status": "error", "error": "Invalid or incomplete control request"}
        writer.write(json.dumps(response).encode() + b"\n")
        await asyncio.wait_for(writer.drain(), TIMEOUT)
    except (OSError, TimeoutError):
        pass
    finally:
        writer.close()
        with suppress(OSError, TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), TIMEOUT)


@asynccontextmanager
async def control_server(configured: str, path: Path | None) -> AsyncIterator[None]:
    configure_logging(configured)
    if path is None:
        yield
        return
    info = path.parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise RuntimeError("Unsafe control socket directory")
    # Never replace an existing socket or unexpected file.
    if path.exists() or path.is_symlink():
        raise RuntimeError("Control socket already exists")
    async def client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await handle(reader, writer, configured)
    server = await asyncio.start_unix_server(client, path=str(path), limit=LIMIT,
                                             start_serving=False)
    try:
        path.chmod(0o600)
        await server.start_serving()
        yield
    finally:
        server.close()
        await server.wait_closed()
