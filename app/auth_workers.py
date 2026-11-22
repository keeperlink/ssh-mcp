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
from weakref import WeakKeyDictionary

T = TypeVar("T")

_AUTH_WORKERS = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ssh-mcp-auth")
# An asyncio semaphore binds to the event loop when contended. TestClient and
# offline test harnesses create independent loops; the live service enforces
# one event loop/worker, so only its admission limiter is active in production.
_ADMISSIONS: WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore] = WeakKeyDictionary()


async def run_auth(function: Callable[..., T], *args: object) -> T:
    """Hold admission through actual worker completion, including cancellation.

    Cancelling an asyncio executor Future does not stop a running thread.
    Shield the Future and release its permit only from its completion
    callback; a cancelled HTTP request cannot queue extra password work.
    """
    loop = asyncio.get_running_loop()
    admission = _ADMISSIONS.get(loop)
    if admission is None:
        admission = asyncio.Semaphore(2)
        _ADMISSIONS[loop] = admission
    await admission.acquire()
    try:
        future = loop.run_in_executor(
            _AUTH_WORKERS, partial(function, *args),
        )
    except BaseException:
        admission.release()
        raise
    future.add_done_callback(lambda _done: admission.release())
    return await asyncio.shield(future)
