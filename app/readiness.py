"""Bounded host readiness checks, independent of agent authorization."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections.abc import Awaitable, Callable, Mapping, Collection
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Literal

LOG = logging.getLogger(__name__)
ProbeKind = Literal["identity", "safety", "sudo", "sudo_challenge"]
HostStatus = Literal["active", "offline", "retired"]


@dataclass(frozen=True, slots=True)
class ReadinessSettings:
    authorized: bool = False
    interval_seconds: int = 30
    timeout_seconds: int = 5
    max_concurrent: int = 5
    stale_seconds: int = 300
    stale_retry_seconds: int = 120

    def __post_init__(self) -> None:
        if type(self.authorized) is not bool:
            raise ValueError("Readiness authorization must be a boolean")
        for value, limit in (
            (self.interval_seconds, 86400), (self.timeout_seconds, 60),
            (self.max_concurrent, 32), (self.stale_seconds, 86400),
            (self.stale_retry_seconds, 86400),
        ):
            if type(value) is not int or not 1 <= value <= limit:
                raise ValueError("Invalid readiness timing or concurrency")
        if self.stale_seconds < self.interval_seconds:
            raise ValueError("Readiness stale threshold must cover the regular interval")

    @classmethod
    def from_mapping(cls, value: object) -> ReadinessSettings:
        if not isinstance(value, dict) or set(value) - set(asdict(cls())):
            raise ValueError("Invalid readiness settings")
        return cls(**value)

    @classmethod
    def from_environment(cls) -> ReadinessSettings:
        values: dict[str, object] = {}
        for key, default in asdict(cls()).items():
            raw = os.getenv("SSH_READINESS_" + key.upper())
            if raw is not None:
                if type(default) is bool:
                    if raw.lower() not in {"true", "false"}:
                        raise ValueError("Invalid readiness authorization setting")
                    values[key] = raw.lower() == "true"
                else:
                    try:
                        values[key] = int(raw)
                    except ValueError:
                        raise ValueError("Invalid readiness timing or concurrency") from None
        return cls.from_mapping(values)

    def environment(self) -> dict[str, str]:
        return {
            "SSH_READINESS_" + key.upper(): (
                str(value).lower() if type(value) is bool else str(value)
            )
            for key, value in asdict(self).items()
        }


@dataclass(frozen=True, slots=True)
class ProbeResult:
    ok: bool
    reason: str = ""
    unsafe: bool = False
    password_rejected: bool = False
    needs_corroboration: bool = False


@dataclass(slots=True)
class HostHealth:
    expects_sudo: bool
    last_ssh: float | None = None
    last_sudo: float | None = None
    last_check: str | None = None
    last_ssh_success: str | None = None
    last_sudo_success: str | None = None
    ssh_reason: str = "pending"
    sudo_reason: str = "pending"
    suspended: bool = False
    unsafe: bool = False
    suspension_generation: int = 0
    recheck_generation: int | None = None
    previous_active: bool = False
    previous_sudo_ready: bool = False
    last_warning: str | None = None
    sealed: bool = False
    safety_confirmed: bool = False


class ReadinessMonitor:
    """One in-memory state machine per configured host; probes are never jobs."""

    def __init__(
        self, settings: ReadinessSettings, hosts: Mapping[str, bool],
        probe: Callable[[str, ProbeKind], Awaitable[ProbeResult]],
        *, clock: Callable[[], float] = time.monotonic,
        sealed_hosts: Collection[str] = (),
    ) -> None:
        if set(sealed_hosts) - set(hosts):
            raise ValueError("Unknown sealed readiness host")
        self.settings = settings
        self._probe = probe
        self._clock = clock
        self._started = clock()
        self._states = {
            alias: HostHealth(
                expects_sudo=expects_sudo,
                sealed=alias in sealed_hosts and expects_sudo,
                ssh_reason="pending" if settings.authorized else "probe_authorization_missing",
                sudo_reason="pending" if expects_sudo else "not_configured",
            )
            for alias, expects_sudo in hosts.items()
        }
        self._locks = {alias: asyncio.Lock() for alias in hosts}
        self._capacity = asyncio.Semaphore(settings.max_concurrent)
        self._tasks: list[asyncio.Task[None]] = []

    @staticmethod
    def _wall() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _fresh(self, success: float | None) -> bool:
        return success is not None and self._clock() - success < self.settings.stale_seconds

    def active(self, alias: str) -> bool:
        state = self._states[alias]
        return (self.settings.authorized and not state.unsafe
                and self._fresh(state.last_ssh)
                and (not state.sealed or state.safety_confirmed))

    def ssh_reachable(self, alias: str) -> bool:
        """Recent pinned SSH identity, distinct from execution eligibility."""
        state = self._states[alias]
        return (self.settings.authorized and not state.unsafe
                and self._fresh(state.last_ssh))

    def password_suspended(self, alias: str) -> bool:
        return self._states[alias].suspended

    def password_generation(self, alias: str) -> int:
        return self._states[alias].suspension_generation

    def password_probe_permitted(self, alias: str) -> bool:
        """Permit only the scoped explicit retry, without lifting suspension."""
        state = self._states[alias]
        return (not state.suspended
                or state.recheck_generation == state.suspension_generation)

    def sudo_ready(self, alias: str) -> bool:
        state = self._states[alias]
        return (self.active(alias) and state.expects_sudo and not state.suspended
                and self._fresh(state.last_sudo))

    def _transitions(self, alias: str) -> None:
        state = self._states[alias]
        active, sudo = self.active(alias), self.sudo_ready(alias)
        if state.previous_active and not active and not state.unsafe:
            if state.sealed and self.ssh_reachable(alias) and not state.safety_confirmed:
                LOG.warning("host_readiness_safety_unconfirmed host=%s", alias)
            else:
                LOG.warning("host_readiness_stale host=%s last_success=%s",
                            alias, state.last_ssh_success)
        if active and not state.previous_active:
            LOG.info("host_readiness_active host=%s", alias)
        if state.previous_sudo_ready and not sudo:
            LOG.warning("host_sudo_unavailable host=%s reason=%s", alias,
                        state.sudo_reason or "stale")
        if sudo and not state.previous_sudo_ready:
            LOG.info("host_sudo_ready host=%s", alias)
        state.previous_active, state.previous_sudo_ready = active, sudo

    def denial(self, alias: str, *, privileged: bool = False) -> str | None:
        self._transitions(alias)
        state = self._states[alias]
        if not self.active(alias):
            return ("probe_authorization_missing" if not self.settings.authorized
                    else "passwordless_root" if state.unsafe
                    else "safety_unconfirmed" if state.sealed
                    and self._fresh(state.last_ssh) and not state.safety_confirmed
                    else "ssh_readiness_stale" if state.last_ssh is not None
                    else state.ssh_reason or "pending")
        if privileged and state.sealed:
            return ("sudo_authentication_suspended" if state.suspended else
                    "sudo_locked" if state.safety_confirmed else "safety_unconfirmed")
        if privileged and not self.sudo_ready(alias):
            return ("sudo_authentication_suspended" if state.suspended
                    else state.sudo_reason or "sudo_readiness_stale")
        return None

    def suspend(self, alias: str) -> None:
        state = self._states[alias]
        if not state.suspended:
            LOG.warning("host_sudo_authentication_suspended host=%s", alias)
        state.suspension_generation += 1
        state.suspended = True
        state.last_sudo = None
        state.sudo_reason = "sudo_authentication_suspended"
        self._transitions(alias)

    async def _attempt(self, alias: str, kind: ProbeKind) -> ProbeResult:
        try:
            async with asyncio.timeout(self.settings.timeout_seconds):
                return await self._probe(alias, kind)
        except TimeoutError:
            return ProbeResult(False, "probe_timeout")
        except Exception:
            # Never record an exception message or raw SSH output.
            return ProbeResult(False, "probe_failed")

    def mark_passwordless_root(self, alias: str) -> None:
        """Latch verified unsafe evidence before transport cleanup can time out."""
        self._ssh_failed(alias, ProbeResult(False, "passwordless_root", unsafe=True))

    def _ssh_failed(self, alias: str, result: ProbeResult) -> None:
        state = self._states[alias]
        # Incomplete subsequent probes must not erase confirmed unsafe evidence.
        if state.unsafe and not result.unsafe:
            return
        state.ssh_reason = result.reason or "probe_failed"
        if result.unsafe:
            if not state.unsafe:
                LOG.warning("host_passwordless_root host=%s", alias)
            state.unsafe = True
            state.last_ssh = state.last_sudo = None
            state.sudo_reason = "passwordless_root"
        elif self.active(alias) and state.last_warning != state.ssh_reason:
            LOG.warning("host_readiness_failed host=%s reason=%s last_success=%s",
                        alias, state.ssh_reason, state.last_ssh_success)
        state.last_warning = state.ssh_reason
        self._transitions(alias)

    async def check(self, alias: str, *, resume: bool = False,
                    privileged: bool | None = None) -> bool:
        if alias not in self._states or not self.settings.authorized:
            return False
        async with self._locks[alias], self._capacity:
            state = self._states[alias]
            self._transitions(alias)
            # A rejection arriving during identity/safety verification must
            # invalidate an earlier operator authorization to retry.
            resume_generation = state.suspension_generation if resume and state.suspended else None
            state.last_check = self._wall()
            identity = await self._attempt(alias, "identity")
            if not identity.ok:
                self._ssh_failed(alias, identity)
                return False
            safety = await self._attempt(alias, "safety")
            if state.sealed:
                # A sealed credential is never opened by readiness polling or
                # the operator's manual recheck. Safety is proven solely from
                # the pinned SSH identity and conclusive no-password sudo
                # refusal. Inconclusive safety blocks root even if SSH works.
                if safety.unsafe:
                    state.safety_confirmed = False
                    self._ssh_failed(alias, safety)
                    return False
                if state.unsafe and not safety.ok:
                    # An inconclusive check cannot undo a prior confirmed
                    # unsafe-passwordless-root latch while locked. Require
                    # new conclusive proof before marking the host active.
                    self._ssh_failed(alias, safety)
                    return False
                if safety.ok:
                    state.safety_confirmed = True
                    self._ssh_succeeded(alias)
                    if not state.suspended:
                        state.sudo_reason = "sudo_locked"
                elif safety.needs_corroboration:
                    state.safety_confirmed = False
                    # Retain verified pinned SSH identity for diagnostics,
                    # but never refresh ordinary execution eligibility.
                    self._ssh_succeeded(alias)
                    state.sudo_reason = "safety_unconfirmed"
                else:
                    state.safety_confirmed = False
                    self._ssh_failed(alias, safety)
                    return False
                self._transitions(alias)
                return self.active(alias) and not privileged
            corroborate = safety.needs_corroboration and not safety.unsafe
            scoped_retry = state.suspended and resume_generation == state.suspension_generation
            may_probe_sudo = state.expects_sudo and (not state.suspended or scoped_retry)
            if not safety.ok and (not corroborate or not may_probe_sudo):
                self._ssh_failed(alias, safety)
                return False
            if safety.ok:
                self._ssh_succeeded(alias)
            sudo_ok = False
            # Unknown noninteractive refusals need proof that the same fixed
            # command really requires a password. Even an ordinary live
            # check needs this evidence before refreshing SSH readiness.
            if (privileged is not False or corroborate) and may_probe_sudo:
                generation = state.suspension_generation
                if scoped_retry:
                    state.recheck_generation = generation
                try:
                    sudo = await self._attempt(alias, "sudo_challenge" if corroborate else "sudo")
                finally:
                    state.recheck_generation = None
                if sudo.unsafe:
                    self._ssh_failed(alias, sudo)
                    return False
                if sudo.password_rejected:
                    self.suspend(alias)
                elif generation == state.suspension_generation:
                    sudo_ok = sudo.ok
                    if sudo.ok:
                        state.suspended = False
                        state.last_sudo = self._clock()
                        state.last_sudo_success = self._wall()
                        state.sudo_reason = ""
                    else:
                        reason = sudo.reason or "probe_failed"
                        if reason != state.sudo_reason:
                            LOG.warning("host_sudo_check_failed host=%s reason=%s", alias, reason)
                        if not state.suspended:
                            state.sudo_reason = reason
            if corroborate:
                if not sudo_ok:
                    self._ssh_failed(alias, safety)
                    return False
                self._ssh_succeeded(alias)
            self._transitions(alias)
            return self.active(alias) and (not privileged or sudo_ok and self.sudo_ready(alias))

    def _ssh_succeeded(self, alias: str) -> None:
        state = self._states[alias]
        state.last_ssh = self._clock()
        state.last_ssh_success = self._wall()
        state.ssh_reason = ""
        state.unsafe = False
        state.last_warning = None
        self._transitions(alias)

    def retry_interval(self, alias: str) -> int:
        state = self._states[alias]
        self._transitions(alias)
        age = self._clock() - (state.last_ssh if state.last_ssh is not None else self._started)
        if age >= self.settings.stale_seconds:
            return self.settings.stale_retry_seconds
        return self.settings.interval_seconds

    async def _loop(self, alias: str) -> None:
        while True:
            await self.check(alias)
            await asyncio.sleep(self.retry_interval(alias))

    def start(self) -> None:
        if not self._tasks and self.settings.authorized:
            self._tasks = [asyncio.create_task(self._loop(alias)) for alias in self._states]

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

    def discovery(self, alias: str) -> dict[str, bool | str]:
        self._transitions(alias)
        state = self._states[alias]
        result: dict[str, bool | str] = {
            "status": "active" if self.active(alias) else "offline",
            "sudo_ready": self.sudo_ready(alias),
        }
        if state.sealed:
            result.update({
                # Keep the external active/offline/retired eligibility
                # contract; expose actual SSH reachability independently.
                "ssh_reachable": self.ssh_reachable(alias),
                "sudo_state": ("safety_unconfirmed"
                               if not state.safety_confirmed and self.ssh_reachable(alias)
                               else "offline" if not self.active(alias) else
                               "suspended" if state.suspended else "locked"),
                "locked": self.active(alias) and state.safety_confirmed
                and not state.suspended,
            })
        return result

    def detail(self, alias: str) -> dict[str, object]:
        state = self._states[alias]
        result: dict[str, object] = dict(self.discovery(alias))
        result.update({
            "sudo_configured": state.expects_sudo,
            "last_check": state.last_check,
            "last_success": state.last_ssh_success,
            "last_sudo_success": state.last_sudo_success,
            "ssh_reason": self.denial(alias) or state.ssh_reason,
            "sudo_reason": (self.denial(alias, privileged=True) or state.sudo_reason
                            if state.expects_sudo else "not_configured"),
            "degraded": (not self.active(alias) or bool(state.ssh_reason)
                         or (state.sealed and
                             (not state.safety_confirmed or state.suspended))
                         or (not state.sealed and state.expects_sudo and (
                             not self.sudo_ready(alias) or bool(state.sudo_reason)))),
        })
        return result

    def snapshot(self) -> dict[str, object]:
        hosts = {alias: self.detail(alias) for alias in sorted(self._states)}
        return {"hosts": hosts,
                "degraded_count": sum(bool(host["degraded"]) for host in hosts.values())}

    async def recheck(self, alias: str) -> dict[str, object]:
        if alias not in self._states or not self.settings.authorized:
            raise ValueError("Host readiness recheck unavailable")
        state = self._states[alias]
        ok = await self.check(
            alias, resume=not state.sealed,
            privileged=state.expects_sudo and not state.sealed,
        )
        return {**self.detail(alias), "recheck_ok": ok}
