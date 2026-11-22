"""Isolated, bounded password verification workers.

Waiting password requests do not occupy Starlette's shared thread pool,
which must remain available to logout, grant management, and status routes.
The cryptographic implementation independently caps memory to two Argon2
derivations across all callers, including offline rekey helpers.
"""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Callable, TypeVar

T = TypeVar("T")

_AUTH_WORKERS = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ssh-mcp-auth")
_ADMISSION = asyncio.Semaphore(2)


async def run_auth(function: Callable[..., T], *args: object) -> T:
    """Wait asynchronously for isolated capacity, then run one password check."""
    async with _ADMISSION:
        return await asyncio.get_running_loop().run_in_executor(
            _AUTH_WORKERS, partial(function, *args),
        )
