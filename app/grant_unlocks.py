"""Process-memory-only, issuance-scoped sudo credentials (SKY-347).

This module does not authorize an MCP request on its own. The caller must
independently validate the live OAuth principal, grant issuance, readiness
and operator Console session before creating an unlock. A request must carry
its opaque handle through the actual admitted execution, never durable audit.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import secrets
import time
from typing import Callable

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

    def __post_init__(self) -> None:
        values = (*self.key, self.actor, self.client_id, self.issuance,
                  self.operation_id, self.generation)
        if not all(type(value) is str and 1 <= len(value) <= 256 for value in values):
            raise InvalidCredential("Invalid root unlock scope")
        if self.key[2] != self.host:
            raise InvalidCredential("Host alias mismatch")

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

    def _expire(self) -> None:
        now = self._clock()
        for handle, entry in tuple(self._entries.items()):
            if entry.expires <= now:
                self._entries.pop(handle, None)

    def issue(
        self, scope: UnlockScope, *, console_password: str,
        console_verifier: dict[str, object], sealed_sudo: dict[str, str],
        deployment: str, issuer: str, username: str, expires: float,
    ) -> str:
        """Verify password and open *this host only* without persisting a key.

        This Argon2id operation is synchronous: the authenticated web endpoint
        must offload it to the separately bounded auth executor.
        """
        self._expire()
        if (self._closed or not self._clock() < expires
                or expires - self._clock() > 57600
                or len(self._entries) >= self._maximum):
            raise InvalidCredential("Root unlock unavailable")
        if not verify_password(console_password, console_verifier, "console-login"):
            raise InvalidCredential("Incorrect Console password.")
        password = unseal_sudo(
            console_password, sealed_sudo, deployment=deployment,
            issuer=issuer, alias=scope.host, username=username,
        )
        # A concurrent pending approval can only use the handle bound to its
        # own issuance, never the latest grant for a host or actor.
        handle = secrets.token_urlsafe(32)
        self._entries[handle] = _Unlock(scope, expires, password)
        return handle

    def require(self, handle: str, scope: UnlockScope) -> str:
        """Check at capacity admission and immediately before password write."""
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
        self._entries.pop(handle, None)

    def revoke_scope(self, key: GrantKey) -> None:
        for handle, entry in tuple(self._entries.items()):
            if entry.scope.key == key:
                self._entries.pop(handle, None)

    def revoke_actor(self, actor: str) -> None:
        """Explicit Console logout clears this operator's root unlocks only."""
        for handle, entry in tuple(self._entries.items()):
            if entry.scope.actor == actor:
                self._entries.pop(handle, None)

    def clear(self) -> None:
        """Password rotation and service shutdown invalidate all handles."""
        self._entries.clear()

    def close(self) -> None:
        self.clear()
        self._closed = True
