"""Process-memory-only, issuance-scoped sudo credentials (SKY-347).

This module does not authorize an MCP request on its own. The caller must
independently validate the live OAuth principal, grant issuance, readiness
and operator Console session before creating an unlock. A request must carry
its opaque handle through the actual admitted execution, never durable audit.
"""
from __future__ import annotations

import asyncio
from contextvars import ContextVar
from dataclasses import dataclass, field
import secrets
import threading
import time
from typing import Callable, Literal

from .sealed_credentials import InvalidCredential, unseal_sudo, verify_password

GrantKey = tuple[str, str, str]


@dataclass(frozen=True, slots=True)
class UnlockScope:
    """Fully qualified, nonsecret identity for one authorized root issuance."""

    key: GrantKey
    actor: str
    client_id: str
    issuance: str
    operation_id: str
    generation: str
    kind: Literal["request", "timed"] = "request"

    def __post_init__(self) -> None:
        # ApprovalManager keys are strictly three elements. The second one
        # may be empty for request-only approvals or a full CIMD client ID
        # (up to 2048 bytes) for agent grants.
        if type(self.key) is not tuple or len(self.key) != 3:
            raise InvalidCredential("Invalid root unlock scope")
        bounds = ((self.key[0], 256, False), (self.key[1], 2048, True),
                  (self.key[2], 63, False), (self.actor, 256, False),
                  (self.client_id, 2048, True), (self.issuance, 256, False),
                  (self.generation, 256, False))
        if any(type(value) is not str or len(value) > limit
               or (not allow_empty and not value)
               for value, limit, allow_empty in bounds):
            raise InvalidCredential("Invalid root unlock scope")
        if self.kind == "request":
            if type(self.operation_id) is not str or not 1 <= len(self.operation_id) <= 256:
                raise InvalidCredential("Request unlock requires a specific operation")
        elif self.kind == "timed":
            if not self.key[1] or self.operation_id != "":
                raise InvalidCredential("Timed grant cannot bind a single operation")
        else:
            raise InvalidCredential("Unknown root unlock kind")

    @property
    def host(self) -> str:
        return self.key[2]


@dataclass(slots=True)
class _Unlock:
    scope: UnlockScope
    expires: float
    # Python cannot reliably zeroize immutable strings. Do not log, serialize,
    # place in argv/environment or persist; release references on invalidation.
    password: str = field(repr=False)
    timer: asyncio.TimerHandle = field(repr=False)


@dataclass(slots=True, repr=False, eq=False)
class PreparedUnlock:
    """One-use, uncommitted secret; never a reusable credential proof."""

    scope: UnlockScope
    epoch: int
    owner: object = field(repr=False)
    password: str | None = field(repr=False)

    def discard(self) -> None:
        """Release the plaintext reference if a pending approval is cancelled."""
        self.password = None


class GrantUnlocks:
    """Bounded in-memory handles invalidated by scope, time and clear/restart."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic,
                 maximum: int = 256) -> None:
        if type(maximum) is not int or not 1 <= maximum <= 1024:
            raise ValueError("Invalid grant unlock capacity")
        self._clock = clock
        self._maximum = maximum
        self._entries: dict[str, _Unlock] = {}
        self._closed = False
        self._epoch = 0
        self._lock = threading.RLock()
        self._owner = object()

    def _remove(self, handle: str) -> None:
        entry = self._entries.pop(handle, None)
        if entry is not None:
            entry.timer.cancel()

    def _expire(self) -> None:
        now = self._clock()
        for handle, entry in tuple(self._entries.items()):
            if entry.expires <= now:
                self._remove(handle)

    def prepare(
        self, scope: UnlockScope, *, console_password: str,
        console_verifier: dict[str, object], sealed_sudo: dict[str, str],
        deployment: str, issuer: str, username: str,
    ) -> PreparedUnlock:
        """Worker: do costly verifier/decrypt without issuing a live grant."""
        if type(scope) is not UnlockScope:
            raise InvalidCredential("Invalid root unlock scope")
        with self._lock:
            if self._closed:
                raise InvalidCredential("Root unlock unavailable")
            epoch = self._epoch
        if not verify_password(console_password, console_verifier, "console-login"):
            raise InvalidCredential("Incorrect Console password.")
        password = unseal_sudo(
            console_password, sealed_sudo, deployment=deployment,
            issuer=issuer, alias=scope.host, username=username,
        )
        return PreparedUnlock(
            scope=scope, epoch=epoch, owner=self._owner, password=password,
        )

    def commit(
        self, prepared: PreparedUnlock, *, expires: float,
        still_authorized: Callable[[], bool],
    ) -> str:
        """Event loop: atomically revalidate live authority, expiry and capacity.

        Call ONLY after verifying the pending approval, Console session,
        OAuth principal, grant generation and host safety. No await occurs
        inside this critical section; revocation invalidates prepared work.
        """
        loop = asyncio.get_running_loop()
        with self._lock:
            if (type(prepared) is not PreparedUnlock
                    or prepared.owner is not self._owner
                    or prepared.password is None):
                raise InvalidCredential("Prepared root unlock already consumed or invalid")
            # Consume even when authorization fails: rejected attempts must
            # not retain plaintext or be replayed after a future reapproval.
            password = prepared.password
            prepared.discard()
            self._expire()
            now = self._clock()
            if (self._closed or prepared.epoch != self._epoch
                    or not now < expires or expires - now > 57600
                    or len(self._entries) >= self._maximum):
                raise InvalidCredential("Root unlock unavailable")
            try:
                authorized = still_authorized()
            except Exception:
                authorized = False
            now = self._clock()
            if (authorized is not True or self._closed
                    or prepared.epoch != self._epoch
                    or not now < expires or expires - now > 57600
                    or len(self._entries) >= self._maximum):
                raise InvalidCredential("Root grant or session no longer authorized")
            handle = secrets.token_urlsafe(32)
            timer = loop.call_later(expires - now, self._expire_handle, handle)
            self._entries[handle] = _Unlock(
                prepared.scope, expires, password, timer,
            )
            return handle

    def _expire_handle(self, handle: str) -> None:
        with self._lock:
            entry = self._entries.get(handle)
            if entry is not None:
                if entry.expires <= self._clock():
                    self._remove(handle)
                else:
                    # A monotonic test clock may move independently of the
                    # event loop; never delete a still-valid entry early.
                    entry.timer = asyncio.get_running_loop().call_later(
                        entry.expires - self._clock(), self._expire_handle, handle,
                    )

    def require(self, handle: str, scope: UnlockScope) -> str:
        """Check at capacity admission and immediately before password write."""
        with self._lock:
            self._expire()
            if self._closed or type(handle) is not str or type(scope) is not UnlockScope:
                raise InvalidCredential("Root unlock unavailable")
            entry = self._entries.get(handle)
            if entry is None or entry.scope != scope or entry.expires <= self._clock():
                raise InvalidCredential("Root unlock expired or revoked")
            return entry.password

    def valid(self, handle: str, scope: UnlockScope) -> bool:
        try:
            self.require(handle, scope)
        except InvalidCredential:
            return False
        return True

    def revoke(self, handle: str) -> None:
        with self._lock:
            self._epoch += 1
            self._remove(handle)

    def revoke_scope(self, key: GrantKey) -> None:
        with self._lock:
            self._epoch += 1
            for handle, entry in tuple(self._entries.items()):
                if entry.scope.key == key:
                    self._remove(handle)

    def revoke_actor(self, actor: str) -> None:
        """Explicit Console logout clears this operator's root unlocks only."""
        with self._lock:
            self._epoch += 1
            for handle, entry in tuple(self._entries.items()):
                if entry.scope.actor == actor:
                    self._remove(handle)

    def clear(self) -> None:
        """Password rotation and service shutdown invalidate all handles."""
        with self._lock:
            self._epoch += 1
            for handle in tuple(self._entries):
                self._remove(handle)

    def close(self) -> None:
        with self._lock:
            self.clear()
            self._closed = True


@dataclass(frozen=True, slots=True, repr=False)
class RootAccess:
    """Opaque live capability propagated to a single approved tool task.

    The capability contains only an opaque handle, verified scope and
    non-secret live-authority callback. It is never added to job/SQLite
    records, tool arguments or subprocess environments.
    """

    registry: GrantUnlocks = field(repr=False)
    handle: str = field(repr=False)
    scope: UnlockScope
    authorized: Callable[[], bool] = field(repr=False, compare=False)

    def require(self, *, host: str, actor: str) -> str:
        if (host != self.scope.host or actor != self.scope.actor
                or self.authorized() is not True):
            raise InvalidCredential("Root unlock scope no longer authorized")
        return self.registry.require(self.handle, self.scope)

    def valid(self, *, host: str, actor: str) -> bool:
        try:
            self.require(host=host, actor=actor)
        except InvalidCredential:
            return False
        return True


# Each MCP request gets its own explicit root admission. Background command
# and batch tasks created during that request inherit this immutable capability.
# An unrelated request starts with None, including after previous tools finish.
root_access_context: ContextVar[RootAccess | None] = ContextVar(
    "ssh_mcp_root_access", default=None,
)
