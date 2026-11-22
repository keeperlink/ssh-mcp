"""Local, memory-only service logging control; never an HTTP endpoint."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
import json
import logging
import os
import sqlite3
from pathlib import Path
import stat
from typing import Any, AsyncIterator, Awaitable, Callable

LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
SOCKET = Path("/run/ssh-mcp/control.sock")
LIMIT = 4096
RECHECK_TIMEOUT = 200.0
Recheck = Callable[[str], Awaitable[dict[str, object]]]
ReloadNames = Callable[[], None]
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


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, configured: str,
                 recheck: Recheck | None = None,
                 reload_names: ReloadNames | None = None) -> None:
    try:
        try:
            line = await asyncio.wait_for(reader.readuntil(b"\n"), TIMEOUT)
            request = json.loads(line)
            response: dict[str, Any]
            if (recheck is not None and isinstance(request, dict)
                    and set(request) == {"action", "alias"} and request["action"] == "recheck-host"
                    and isinstance(request["alias"], str)):
                async with asyncio.timeout(RECHECK_TIMEOUT):
                    response = {"status": "ok", "host": await recheck(request["alias"])}
            elif (reload_names is not None and type(request) is dict
                  and request == {"action": "reload-dcr-names"}):
                # Socket is owner-only; the CLI sends this after its transaction commits.
                await asyncio.to_thread(reload_names)
                response = {"status": "ok"}
            else:
                response = command(request, configured)
        except (OSError, sqlite3.Error):
            response = {"status": "error", "error": "DCR name cache reload failed"}
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
async def control_server(configured: str, path: Path | None,
                         recheck: Recheck | None = None,
                         reload_names: ReloadNames | None = None) -> AsyncIterator[None]:
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
        await handle(reader, writer, configured, recheck, reload_names)
    server = await asyncio.start_unix_server(client, path=str(path), limit=LIMIT,
                                             start_serving=False)
    try:
        path.chmod(0o600)
        await server.start_serving()
        yield
    finally:
        server.close()
        await server.wait_closed()
