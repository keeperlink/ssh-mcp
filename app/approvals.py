"""Memory-only, single-worker SSH host approvals.

The pending Future holds the *existing* MCP call; no payload is persisted and
no tool can resume work after its waiting caller has disappeared.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import secrets
import time
from typing import Any, Awaitable, Callable, Literal

from . import config
from .client_identity import agent_disambiguator, agent_label
from .ssh_executor import SSHDenied
from .approval_status import ApprovalCode, ApprovalRejected
from .grant_unlocks import (
    GrantUnlocks, PreparedUnlock, RootAccess, root_access_context,
)
from .sealed_credentials import InvalidCredential

GrantKey = tuple[str, str, str]  # OAuth sid + conversation OR agent:actor + client_id, signed alias


def agent_scoped(key: GrantKey) -> bool:
    """Only verified-client keys created by the host-access gate use this namespace."""
    return key[0].startswith("agent:")
Duration = Literal["once", "5m", "15m", "1h", "8h", "16h"]
DURATIONS: dict[str, int | None] = {
    "once": None, "5m": 300, "15m": 900, "1h": 3600,
    "8h": 28800, "16h": 57600,
}
WAIT_SECONDS = 30
MAX_PENDING = 128
MAX_GRANTS = 256


@dataclass
class PendingApproval:
    id: str
    key: GrantKey
    tool: str
    reason: str
    summary: str
    expires_at: float
    deadline: float
    future: asyncio.Future[str]
    waiter: asyncio.Task[Any] | None
    disconnected: Callable[[], Awaitable[bool]] | None = None
    steps: list[dict[str, str | bool]] | None = None
    host_required: bool = True
    root_required: bool = False
    grant_host: bool = True
    grant_root: bool = False
    client_id: str | None = None
    actor: str = ""
    # The generation and deadline observed when admission began. Explicit
    # revocations are distinguishable from natural grant expiry.
    host_revoke_generation: int = 0
    root_revoke_generation: int = 0
    host_expiry_at: float = 0
    root_expiry_at: float = 0

    def public(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id, "host": self.key[2],
            "conversation_id": (None if agent_scoped(self.key)
                                else self.key[1] or None), "tool": self.tool,
            "scope_id": ApprovalManager.grant_id(self.key, "scope") if self.key[1] else None,
            "conversation_scope_id": ApprovalManager.conversation_scope_id(self.key),
            "client_id": self.client_id, "agent": agent_label(self.client_id, config.MCP_CLIENT_LABELS),
            "client_disambiguator": agent_disambiguator(self.client_id, config.MCP_CLIENT_LABELS),
            "grant_scope": "agent" if agent_scoped(self.key) else "conversation" if self.key[1] else "request",
            "timed_grants_allowed": bool(self.key[1]),
            "reason": self.reason, "summary": self.summary,
            "expires_at": time.time() + max(0, self.deadline - time.monotonic()),
            "requires_host": self.grant_host,
            "requires_root": self.grant_root,
            "requires_unlock": self.grant_root and config.MCP_MANAGED_SECRETS_VERSION == "2",
            # Root approval can extend an already-active prerequisite host
            # grant to the root expiry even when no new host approval is due.
            "host_grant_extension_possible": (
                self.host_required and self.root_required
                and not self.grant_host and self.grant_root
            ),
        }
        if self.steps is not None:
            data["steps"] = self.steps
        return data


class ApprovalManager:
    """One event loop owns pending and grants; decisions never await mid-mutation."""

    def __init__(self) -> None:
        self.pending: dict[str, PendingApproval] = {}
        self.grants: dict[GrantKey, float] = {}
        self.root_grants: dict[GrantKey, float] = {}
        self.root_unlocks = GrantUnlocks()
        self._timed_root_access: dict[GrantKey, RootAccess] = {}
        self._once_root_access: dict[str, RootAccess] = {}
        # Presentation only; never used to authorize access.
        self._grant_clients: dict[GrantKey, str] = {}
        # Bounded nonsecret generation counters to distinguish an explicit
        # operator revoke from automatic timed-grant expiry during an await.
        self._revoke_generations: dict[tuple[GrantKey, str], int] = {}
        # Bounded wakeups only; SSE subscribers fetch the current snapshot.
        # Each listener belongs to this single event loop, never a worker.
        self._listeners: set[asyncio.Queue[None]] = set()
        self.instance_id = secrets.token_urlsafe(12)
        self.revision = 0
        self.closed = False

    def subscribe(self) -> asyncio.Queue[None]:
        queue: asyncio.Queue[None] = asyncio.Queue(maxsize=1)
        self._listeners.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[None]) -> None:
        self._listeners.discard(queue)

    def _signal(self) -> None:
        self.revision += 1
        for queue in tuple(self._listeners):
            if queue.empty():
                queue.put_nowait(None)

    def _invalidate_dependents(self, key: GrantKey, *, host: bool = False,
                               root: bool = False, expired: bool = False) -> None:
        # Pending root-only approvals cannot survive revocation and silently
        # become valid again after a new prerequisite grant is issued.
        for request_id, request in tuple(self.pending.items()):
            if request.key == key and (
                host and request.host_required and not request.grant_host
                or root and request.root_required and not request.grant_root
            ):
                self._finish(request_id, "denied_expired" if expired else "denied_revoked")

    def _expire(self) -> None:
        now = time.monotonic()
        for key, expiry in tuple(self.grants.items()):
            if expiry <= now:
                self.grants.pop(key, None)
                root_removed = self.root_grants.pop(key, None) is not None
                if root_removed:
                    self._drop_root(key)
                self._invalidate_dependents(key, host=True, root=root_removed, expired=True)
                self._signal()
        for key, expiry in tuple(self.root_grants.items()):
            if expiry <= now:
                self.root_grants.pop(key, None)
                self._drop_root(key)
                self._invalidate_dependents(key, root=True, expired=True)
                self._signal()
        for request_id, access in tuple(self._once_root_access.items()):
            if not self.root_unlocks.valid(access.handle, access.scope):
                self._once_root_access.pop(request_id, None)
        for key in tuple(self._grant_clients):
            if key not in self.grants and key not in self.root_grants:
                del self._grant_clients[key]
        for request_id, request in tuple(self.pending.items()):
            if request.deadline <= now:
                self._finish(request_id, "denied_expired")
            elif (request.future.done() or request.waiter is not None
                    and (request.waiter.done() or request.waiter.cancelling())):
                self._finish(request_id, "")

    def _finish(self, request_id: str, decision: str) -> bool:
        request = self.pending.pop(request_id, None)
        if request is None:
            return False
        if not request.future.done():
            request.future.set_result(decision)
        self._signal()
        return True

    def snapshot(self) -> dict[str, list[dict[str, str | float]]]:
        self._expire()
        return {
            "pending_approvals": [x.public() for x in self.pending.values()],
            "active_grants": [
                {"host": key[2],
                 "conversation_id": None if agent_scoped(key) else key[1],
                 "id": self.grant_id(key),
                 "scope_id": self.grant_id(key, "scope"),
                 "conversation_scope_id": self.conversation_scope_id(key),
                 "grant_scope": "agent" if agent_scoped(key) else "conversation",
                 "agent": agent_label(self._grant_clients.get(key), config.MCP_CLIENT_LABELS),
                 "client_disambiguator": agent_disambiguator(
                     self._grant_clients.get(key), config.MCP_CLIENT_LABELS),
                 "kind": "host",
                 "expires_at": time.time() + max(0, expires_at - time.monotonic())}
                for key, expires_at in self.grants.items()
            ] + [
                {"host": key[2],
                 "conversation_id": None if agent_scoped(key) else key[1],
                 "id": self.grant_id(key, "root"), "kind": "root",
                 "scope_id": self.grant_id(key, "scope"),
                 "conversation_scope_id": self.conversation_scope_id(key),
                 "grant_scope": "agent" if agent_scoped(key) else "conversation",
                 "agent": agent_label(self._grant_clients.get(key), config.MCP_CLIENT_LABELS),
                 "client_disambiguator": agent_disambiguator(
                     self._grant_clients.get(key), config.MCP_CLIENT_LABELS),
                 "expires_at": time.time() + max(0, expires_at - time.monotonic())}
                for key, expires_at in self.root_grants.items()
            ],
        }

    def viewer_snapshot(self) -> dict[str, Any]:
        """Revisioned snapshot so HTTP polling cannot undo a newer SSE event."""
        result: dict[str, Any] = self.snapshot()
        result["approval_instance"] = self.instance_id
        result["approval_revision"] = self.revision
        return result

    @staticmethod
    def grant_id(key: GrantKey, kind: str = "host") -> str:
        # Stable nonsecret identifier for a viewer revoke action. It must not
        # serve as an authentication credential; viewer auth + CSRF still apply.
        source = "\x00".join(key) if kind == "host" else kind + "\x00" + "\x00".join(key)
        return hashlib.sha256(source.encode("utf-8")).hexdigest()[:24]

    @staticmethod
    def conversation_scope_id(key: GrantKey) -> str | None:
        # Display correlation only: keep OAuth sessions distinct, regardless of host.
        if not key[1] or agent_scoped(key):
            return None
        source = "\x00".join(("conversation", key[0], key[1]))
        return hashlib.sha256(source.encode("utf-8")).hexdigest()[:24]

    def _authorized(self, key: GrantKey, host_required: bool,
                    root_required: bool) -> bool:
        now = time.monotonic()
        return (bool(key[1]) and (not host_required or self.grants.get(key, 0) > now)
                and (not root_required or (
                    self.root_grants.get(key, 0) > now
                    and (config.MCP_MANAGED_SECRETS_VERSION != "2"
                         or self._root_access_ready(key))
                )))

    def _root_access_ready(self, key: GrantKey) -> bool:
        access = self._timed_root_access.get(key)
        return access is not None and self.root_unlocks.valid(access.handle, access.scope)

    def _drop_root(self, key: GrantKey) -> None:
        access = self._timed_root_access.pop(key, None)
        if access is not None:
            self.root_unlocks.revoke(access.handle)
        self.root_unlocks.revoke_scope(key)

    def root_request(self, request_id: str) -> PendingApproval | None:
        """Return only a still-waiting privileged grant for Console approval."""
        self._expire()
        request = self.pending.get(request_id)
        if (self.closed or request is None or not request.grant_root
                or request.future.done() or request.deadline <= time.monotonic()
                or request.waiter is not None
                and (request.waiter.done() or request.waiter.cancelling())):
            return None
        return request

    def decide_unlocked(
        self, request_id: str, *, duration: str, prepared: PreparedUnlock,
        still_authorized: Callable[[], bool],
    ) -> bool:
        """Commit a fresh proved root secret and the matching grant together.

        Runs synchronously in the Console event loop under the decision lock,
        *after* the slow password verifier, decrypt and live sudo proof.
        No await can interleave logout/revoke with issuance.
        """
        request = self.root_request(request_id)
        if (request is None or duration not in DURATIONS
                or prepared.scope.key != request.key
                or prepared.scope.actor != request.actor
                or prepared.scope.client_id != (request.client_id or "")
                or prepared.scope.issuance != request.id
                or prepared.scope.kind != ("request" if duration == "once" else "timed")
                or prepared.scope.operation_id != (request.id if duration == "once" else "")):
            prepared.discard()
            return False
        now = time.monotonic()
        seconds = DURATIONS[duration] or 300
        expires = now + seconds
        try:
            handle = self.root_unlocks.commit(
                prepared, expires=expires,
                still_authorized=lambda: (
                    self.root_request(request_id) is request
                    and still_authorized()
                ),
            )
        except InvalidCredential:
            return False
        key = request.key
        if duration == "once":
            root_generation = self._revoke_generations.get((key, "root"), 0)
            host_generation = self._revoke_generations.get((key, "host"), 0)
            existing_host_required = request.host_required and not request.grant_host
            access = RootAccess(
                self.root_unlocks, handle, prepared.scope,
                lambda: (not self.closed and
                         self._once_root_access.get(request_id) is access
                         and self._revoke_generations.get((key, "root"), 0) == root_generation
                         and self._revoke_generations.get((key, "host"), 0) == host_generation
                         and (not existing_host_required or
                              self.grants.get(key, 0) > time.monotonic())),
            )
            self._once_root_access[request_id] = access
        else:
            generation = self._revoke_generations.get((key, "root"), 0)
            old_access = self._timed_root_access.get(key)
            if old_access is not None:
                # A rotated/invalidated credential must not remain readable
                # merely because another grant for the same scope is issued.
                self.root_unlocks.revoke(old_access.handle)
            access = RootAccess(
                self.root_unlocks, handle, prepared.scope,
                lambda: (not self.closed and
                         self._timed_root_access.get(key) is access
                         and self._revoke_generations.get((key, "root"), 0) == generation
                         and self.root_grants.get(key, 0) > time.monotonic()),
            )
            self._timed_root_access[key] = access
        if not self.decide(request_id, grant=True, duration=duration):
            if duration == "once":
                self._once_root_access.pop(request_id, None)
            else:
                self._timed_root_access.pop(key, None)
            self.root_unlocks.revoke(handle)
            return False
        return True

    def revoke_all_root(self) -> None:
        """Explicit Console logout removes root unlocks, but not SSH grants."""
        for key in tuple(self.root_grants):
            self.root_grants.pop(key, None)
            self._note_revoke(key, "root")
            self._drop_root(key)
            self._invalidate_dependents(key, root=True)
        for request_id, access in tuple(self._once_root_access.items()):
            self.root_unlocks.revoke(access.handle)
            self._once_root_access.pop(request_id, None)
        self._signal()

    def _note_revoke(self, key: GrantKey, kind: str) -> None:
        marker = (key, kind)
        self._revoke_generations[marker] = self._revoke_generations.get(marker, 0) + 1
        if len(self._revoke_generations) > 4096:
            self._revoke_generations.pop(next(iter(self._revoke_generations)))

    def _lost_grant(self, key: GrantKey, *, host_required: bool,
                    root_required: bool, host_expiry: float, root_expiry: float,
                    host_generation: int, root_generation: int) -> ApprovalRejected | None:
        now = time.monotonic()
        for kind, required, current, expected, previous in (
            ("host", host_required, self.grants.get(key, 0),
             host_expiry, host_generation),
            ("root", root_required, self.root_grants.get(key, 0),
             root_expiry, root_generation),
        ):
            if not required:
                continue
            # A replacement timed grant must NOT revive a request that
            # captured an earlier grant before the explicit revoke.
            if self._revoke_generations.get((key, kind), 0) != previous:
                return ApprovalRejected(ApprovalCode.DENIED_REVOKED,
                                        "Required grant explicitly revoked")
            if current > now:
                continue
            if expected > 0 and expected <= now:
                return ApprovalRejected(ApprovalCode.DENIED_EXPIRED,
                                        "Required timed grant expired")
        return None

    async def require(self, key: GrantKey, *, tool: str, reason: str,
                      summary: str | Callable[[], str],
                      steps: Callable[[], list[dict[str, str | bool]]] | None = None,
                      disconnected: Callable[[], Awaitable[bool]] | None = None,
                      host_required: bool = True,
                      root_required: bool = False,
                      client_id: str | None = None,
                      actor: str = "",
                      before_prompt: Callable[[], Awaitable[None]] | None = None) -> ApprovalCode:
        if self.closed:
            raise SSHDenied("Approval manager has stopped")
        self._expire()
        if self._authorized(key, host_required, root_required):
            host_expiry = self.grants.get(key, 0)
            root_expiry = self.root_grants.get(key, 0)
            host_generation = self._revoke_generations.get((key, "host"), 0)
            root_generation = self._revoke_generations.get((key, "root"), 0)
            if disconnected is not None and await disconnected():
                raise ApprovalRejected(ApprovalCode.DENIED_DISCONNECTED, "Request disconnected")
            if self.closed:
                raise SSHDenied("Approval manager has stopped")
            cause = self._lost_grant(
                key, host_required=host_required, root_required=root_required,
                host_expiry=host_expiry, root_expiry=root_expiry,
                host_generation=host_generation, root_generation=root_generation,
            )
            if cause is not None:
                raise cause
            if not self._authorized(key, host_required, root_required):
                raise SSHDenied("Operator grant revoked or expired")
            if root_required and config.MCP_MANAGED_SECRETS_VERSION == "2":
                access = self._timed_root_access.get(key)
                if (access is None or access.scope.actor != actor
                        or access.scope.client_id != (client_id or "")):
                    raise SSHDenied("Root unlock actor mismatch")
                root_access_context.set(access)
            return ApprovalCode.APPROVED_TIMED
        if len(self.pending) >= MAX_PENDING:
            raise SSHDenied("Approval queue is full")
        if before_prompt is not None:
            await before_prompt()
            if self.closed:
                raise SSHDenied("Approval manager has stopped")
            if disconnected is not None and await disconnected():
                raise ApprovalRejected(ApprovalCode.DENIED_DISCONNECTED, "Request disconnected")
            self._expire()
            # A concurrent prompt may already have established the grant.
            if self._authorized(key, host_required, root_required):
                return await self.require(
                    key, tool=tool, reason=reason, summary=summary, steps=steps,
                    disconnected=disconnected, host_required=host_required,
                    root_required=root_required, client_id=client_id, actor=actor,
                )
            if len(self.pending) >= MAX_PENDING:
                raise SSHDenied("Approval queue is full")
        # The operation preview is only needed for a newly queued decision.
        # Existing timed grants must retain normal file validation/auditing.
        summary_text = summary() if callable(summary) else summary
        preview_steps = steps() if steps is not None else None
        request_id = secrets.token_urlsafe(18)
        future: asyncio.Future[str] = asyncio.get_running_loop().create_future()
        request = PendingApproval(
            id=request_id, key=key, tool=tool,
            reason=reason[:200], summary=summary_text[:500],
            expires_at=time.time() + WAIT_SECONDS,
            deadline=time.monotonic() + WAIT_SECONDS, future=future,
            waiter=asyncio.current_task(), disconnected=disconnected,
            steps=preview_steps,
            host_required=host_required, root_required=root_required,
            grant_host=host_required and (not key[1] or self.grants.get(key, 0) <= time.monotonic()),
            grant_root=root_required and (
                not key[1] or self.root_grants.get(key, 0) <= time.monotonic()
                or config.MCP_MANAGED_SECRETS_VERSION == "2"
                and not self._root_access_ready(key)
            ),
            client_id=client_id,
            actor=actor,
            host_revoke_generation=self._revoke_generations.get((key, "host"), 0),
            root_revoke_generation=self._revoke_generations.get((key, "root"), 0),
            host_expiry_at=self.grants.get(key, 0),
            root_expiry_at=self.root_grants.get(key, 0),
        )
        self.pending[request_id] = request
        self._signal()
        async def watch_disconnect() -> None:
            assert disconnected is not None
            while True:
                if await disconnected():
                    # Remove immediately, so a late Grant cannot turn a
                    # disconnected request into a reusable timed grant.
                    self._finish(request_id, "denied_disconnected")
                    return
                await asyncio.sleep(.05)

        watcher = asyncio.create_task(watch_disconnect()) if disconnected else None
        try:
            if watcher is None:
                decision = await asyncio.wait_for(future, WAIT_SECONDS)
            else:
                done, _ = await asyncio.wait(
                    (future, watcher), timeout=WAIT_SECONDS,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if future in done:
                    decision = future.result()
                elif watcher in done:
                    # A failed watcher is not evidence that the client
                    # disconnected. Only its successful _finish is classified.
                    try:
                        watcher.result()
                    except TimeoutError as exc:
                        # A probe timeout is not the operator-approval deadline.
                        raise SSHDenied("Approval watcher timed out") from exc
                    if not future.done():
                        raise SSHDenied("Approval watcher stopped unexpectedly")
                    decision = future.result()
                else:
                    raise ApprovalRejected(ApprovalCode.DENIED_EXPIRED,
                                           "Approval request expired")
        except TimeoutError:
            raise ApprovalRejected(ApprovalCode.DENIED_EXPIRED,
                                   "Approval request expired") from None
        finally:
            # After caller cancellation or disconnect, no pending operation
            # can be authorized later by a stale browser event.
            if self.pending.pop(request_id, None) is not None:
                self._signal()
            if watcher is not None:
                watcher.cancel()
                await asyncio.gather(watcher, return_exceptions=True)
        # Never overwrite a terminal Deny with a later observed disconnect.
        # A positive approval still checks liveness before SSH execution.
        rejected = {
            "denied_explicit": ApprovalCode.DENIED_EXPLICIT,
            "denied_expired": ApprovalCode.DENIED_EXPIRED,
            "denied_disconnected": ApprovalCode.DENIED_DISCONNECTED,
            "denied_revoked": ApprovalCode.DENIED_REVOKED,
        }.get(decision)
        if rejected is not None:
            raise ApprovalRejected(rejected, "Operator denied or approval expired")
        if not decision:
            raise SSHDenied("Approval manager unavailable")
        if disconnected is not None and await disconnected():
            raise ApprovalRejected(ApprovalCode.DENIED_DISCONNECTED,
                                   "Request disconnected")
        if self.closed:
            raise SSHDenied("Approval manager has stopped")
        if request.deadline <= time.monotonic():
            raise ApprovalRejected(ApprovalCode.DENIED_EXPIRED, "Approval request expired")
        # A root-only/host-only pending request must not silently reacquire a
        # prerequisite grant that was revoked while its modal was open.
        check_host = request.host_required and (
            not request.grant_host or decision == "timed"
        )
        check_root = request.root_required and (
            not request.grant_root or decision == "timed"
        )
        cause = self._lost_grant(
            key, host_required=check_host, root_required=check_root,
            host_expiry=request.host_expiry_at,
            root_expiry=request.root_expiry_at,
            host_generation=request.host_revoke_generation,
            root_generation=request.root_revoke_generation,
        )
        if cause is not None:
            raise cause
        if ((check_host and self.grants.get(key, 0) <= time.monotonic())
                or (check_root and self.root_grants.get(key, 0) <= time.monotonic())):
            raise SSHDenied("A prerequisite operator grant is unavailable")
        if root_required and config.MCP_MANAGED_SECRETS_VERSION == "2":
            access = (self._once_root_access.get(request.id)
                      if decision == "once" else self._timed_root_access.get(key))
            if (access is None or access.scope.actor != actor
                    or access.scope.client_id != (client_id or "")
                    or not access.valid(host=key[2], actor=actor)):
                raise SSHDenied("Approved root unlock is no longer valid")
            root_access_context.set(access)
        return (ApprovalCode.APPROVED_EXPLICIT if decision == "once"
                else ApprovalCode.APPROVED_TIMED)

    async def decide_live(self, request_id: str, *, grant: bool,
                          duration: str = "once") -> bool:
        """Recheck the originating HTTP request immediately before Grant.

        No suspension separates the liveness check from the in-memory
        decision, so another task cannot interleave a grant mutation.
        """
        self._expire()
        request = self.pending.get(request_id)
        if request is None:
            return False
        if grant and request.disconnected is not None:
            if await request.disconnected():
                self._finish(request_id, "denied_disconnected")
                return False
        return self.decide(request_id, grant=grant, duration=duration)

    def decide(self, request_id: str, *, grant: bool, duration: str = "once") -> bool:
        self._expire()
        if self.closed or duration not in DURATIONS:
            return False
        request = self.pending.get(request_id)
        if request is None:
            return False
        if (request.future.done() or request.waiter is not None
                and (request.waiter.done() or request.waiter.cancelling())):
            self.pending.pop(request_id, None)
            return False
        if not grant:
            return self._finish(request_id, "denied_explicit")
        if ((request.host_required and not request.grant_host
             and self.grants.get(request.key, 0) <= time.monotonic())
                or (request.root_required and not request.grant_root
                    and self.root_grants.get(request.key, 0) <= time.monotonic())):
            # Never restore revoked SSH access from a sudo-only approval.
            # End the impossible pending request rather than leaving a modal
            # that cannot be granted until its 30-second deadline.
            self._finish(request_id, "denied_revoked")
            return False
        seconds = DURATIONS[duration]
        if seconds is not None:
            if not request.key[1]:
                return False  # No verified OAuth client or conversation.
            count = len(self.grants) + len(self.root_grants)
            additional = int(request.grant_host and request.key not in self.grants)
            additional += int(request.grant_root and request.key not in self.root_grants)
            if count + additional > MAX_GRANTS:
                return False
            expiry = time.monotonic() + seconds
            if request.grant_host:
                self.grants[request.key] = max(self.grants.get(request.key, 0), expiry)
            if request.grant_root:
                self.root_grants[request.key] = max(
                    self.root_grants.get(request.key, 0), expiry,
                )
            if request.client_id:
                self._grant_clients[request.key] = request.client_id
            # A root grant must never outlive a restricted host grant.
            if request.host_required and request.root_required:
                self.grants[request.key] = max(
                    self.grants.get(request.key, 0), self.root_grants.get(request.key, 0),
                )
            self._signal()
            # Timed grants release only callers whose entire permission
            # requirements are satisfied, not unrelated pending permissions.
            for other_id, other in tuple(self.pending.items()):
                if (other.key == request.key
                        and self._authorized(other.key, other.host_required,
                                             other.root_required)):
                    # Permissions obtained by this approval start a fresh
                    # dependency generation. Preserve the original snapshots
                    # only for grants the request already relied on.
                    if other.grant_host:
                        other.host_expiry_at = self.grants.get(other.key, 0)
                        other.host_revoke_generation = self._revoke_generations.get(
                            (other.key, "host"), 0,
                        )
                    if other.grant_root:
                        other.root_expiry_at = self.root_grants.get(other.key, 0)
                        other.root_revoke_generation = self._revoke_generations.get(
                            (other.key, "root"), 0,
                        )
                    self._finish(other_id, "timed")
        else:
            # One request consumes just this exact suspended call.
            self._finish(request_id, "once")
        return True

    def revoke(self, grant_id: str) -> bool:
        self._expire()
        for key in tuple(self.grants):
            if self.grant_id(key) == grant_id:
                del self.grants[key]
                root_removed = self.root_grants.pop(key, None) is not None
                if root_removed:
                    self._drop_root(key)
                self._note_revoke(key, "host")
                if root_removed:
                    self._note_revoke(key, "root")
                self._invalidate_dependents(key, host=True, root=root_removed)
                if key not in self.root_grants:
                    self._grant_clients.pop(key, None)
                self._signal()
                return True
        for key in tuple(self.root_grants):
            if self.grant_id(key, "root") == grant_id:
                del self.root_grants[key]
                self._drop_root(key)
                self._note_revoke(key, "root")
                self._invalidate_dependents(key, root=True)
                if key not in self.grants:
                    self._grant_clients.pop(key, None)
                self._signal()
                return True
        return False

    def shutdown(self) -> None:
        self.closed = True
        for request_id in tuple(self.pending):
            self._finish(request_id, "")
        self.grants.clear()
        self.root_grants.clear()
        self._timed_root_access.clear()
        self._once_root_access.clear()
        self.root_unlocks.close()
        self._grant_clients.clear()
        self._signal()
