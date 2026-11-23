"""Synthetic, deterministic readiness state and integration regression tests."""
from __future__ import annotations

import asyncio
from pathlib import Path
import os
import json
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from app.readiness import ProbeResult, ReadinessMonitor, ReadinessSettings
from app.ssh_executor import SSHExecutor, SSHResult, ReadinessDenied, HostSpec
from app.contracts import ExecuteCommandRequest
from app.approvals import ApprovalManager
from app.conversation_access import require_host_access
from app import control, control_cli


class SettingTests(unittest.TestCase):
    def test_safe_defaults_and_roundtrip(self):
        defaults = ReadinessSettings()
        self.assertFalse(defaults.authorized)
        self.assertEqual((defaults.interval_seconds, defaults.timeout_seconds,
                          defaults.max_concurrent, defaults.stale_seconds,
                          defaults.stale_retry_seconds), (30, 5, 5, 300, 120))
        custom = ReadinessSettings(authorized=True, stale_seconds=20, interval_seconds=2)
        with patch.dict(os.environ, custom.environment(), clear=True):
            self.assertEqual(ReadinessSettings.from_environment(), custom)
        self.assertEqual(ReadinessSettings.from_mapping({"authorized": True}).interval_seconds, 30)

    def test_validation(self):
        for invalid in (None, [], {"unknown": True}, {"authorized": 1},
                        {"timeout_seconds": True}, {"timeout_seconds": 61},
                        {"max_concurrent": 0}, {"stale_seconds": 1}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                ReadinessSettings.from_mapping(invalid)
        for value in ({"SSH_READINESS_AUTHORIZED": "yes"}, {"SSH_READINESS_STALE_SECONDS": "bad"}):
            with patch.dict(os.environ, value, clear=True), self.assertRaises(ValueError):
                ReadinessSettings.from_environment()


class MonitorTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.now = 1000.
        self.probe = AsyncMock(return_value=ProbeResult(True))
        self.m = ReadinessMonitor(ReadinessSettings(authorized=True),
                {"demo-node-a": True, "demo-node-b": False}, self.probe, clock=lambda: self.now)

    async def test_sealed_host_is_locked_not_degraded_and_never_probes_password(self):
        calls: list[str] = []

        async def probe(_alias: str, kind: str) -> ProbeResult:
            calls.append(kind)
            return ProbeResult(True)

        monitor = ReadinessMonitor(
            ReadinessSettings(authorized=True),
            {"demo-node-a": True}, probe, clock=lambda: self.now,
            sealed_hosts=("demo-node-a",),
        )
        self.assertTrue(await monitor.check("demo-node-a"))
        self.assertEqual(calls, ["identity", "safety"])
        self.assertTrue(monitor.active("demo-node-a"))
        self.assertFalse(monitor.sudo_ready("demo-node-a"))
        self.assertEqual(monitor.denial("demo-node-a"), None)
        self.assertEqual(monitor.denial("demo-node-a", privileged=True), "sudo_locked")
        self.assertEqual(monitor.discovery("demo-node-a")["sudo_state"], "locked")
        self.assertTrue(monitor.discovery("demo-node-a")["locked"])
        self.assertFalse(monitor.detail("demo-node-a")["degraded"])
        self.assertEqual(monitor.snapshot()["degraded_count"], 0)
        self.assertFalse((await monitor.recheck("demo-node-a"))["degraded"])
        self.assertEqual(calls, ["identity", "safety", "identity", "safety"])
        self.assertEqual(monitor.settings.interval_seconds, 30)
        with self.assertNoLogs("app.readiness", "WARNING"):
            self.assertTrue(await monitor.check("demo-node-a"))
        monitor.suspend("demo-node-a")
        self.assertEqual(monitor.discovery("demo-node-a")["sudo_state"], "suspended")
        self.assertFalse(monitor.discovery("demo-node-a")["locked"])
        self.assertEqual(monitor.denial("demo-node-a", privileged=True),
                         "sudo_authentication_suspended")
        self.assertTrue(monitor.detail("demo-node-a")["degraded"])
        self.assertTrue((await monitor.recheck("demo-node-a"))["recheck_ok"])
        self.assertNotIn("sudo", calls)
        self.assertNotIn("sudo_challenge", calls)

    async def test_sealed_safety_unconfirmed_never_attempts_sudo_password(self):
        calls: list[str] = []

        async def probe(_alias: str, kind: str) -> ProbeResult:
            calls.append(kind)
            if kind == "safety":
                return ProbeResult(False, "root_unconfirmed", needs_corroboration=True)
            return ProbeResult(True)

        monitor = ReadinessMonitor(
            ReadinessSettings(authorized=True),
            {"demo-node-a": True}, probe, sealed_hosts=("demo-node-a",),
        )
        self.assertFalse(await monitor.check("demo-node-a"))
        self.assertFalse(monitor.active("demo-node-a"))
        self.assertEqual(monitor.denial("demo-node-a"), "safety_unconfirmed")
        self.assertEqual(monitor.denial("demo-node-a", privileged=True), "safety_unconfirmed")
        self.assertEqual(monitor.discovery("demo-node-a")["sudo_state"], "safety_unconfirmed")
        self.assertTrue(monitor.discovery("demo-node-a")["ssh_reachable"])
        self.assertEqual(monitor.discovery("demo-node-a")["status"], "offline")
        self.assertTrue(monitor.detail("demo-node-a")["last_success"])
        self.assertTrue(monitor.detail("demo-node-a")["degraded"])
        result = await monitor.recheck("demo-node-a")
        self.assertFalse(result["recheck_ok"])
        self.assertTrue(result["degraded"])
        self.assertEqual(calls, ["identity", "safety", "identity", "safety"])

    async def test_sealed_transient_safety_failure_retains_recent_locked_state(self):
        now = [1000.0]
        responses = [
            ProbeResult(True),
            ProbeResult(False, "probe_timeout"),
            ProbeResult(False, "connection_failed"),
        ]
        calls: list[str] = []

        async def probe(_alias: str, kind: str) -> ProbeResult:
            calls.append(kind)
            return responses.pop(0) if kind == "safety" else ProbeResult(True)

        monitor = ReadinessMonitor(
            ReadinessSettings(authorized=True, stale_seconds=300),
            {"demo-node-a": True}, probe, clock=lambda: now[0],
            sealed_hosts=("demo-node-a",),
        )
        self.assertTrue(await monitor.check("demo-node-a"))
        original_last_ssh = monitor._states["demo-node-a"].last_ssh
        self.assertEqual(monitor.discovery("demo-node-a")["sudo_state"], "locked")

        now[0] += 30
        with self.assertLogs("app.readiness", level="WARNING") as warnings:
            self.assertFalse(await monitor.check("demo-node-a"))
        self.assertTrue(monitor.active("demo-node-a"))
        self.assertEqual(monitor._states["demo-node-a"].last_ssh, original_last_ssh)
        self.assertEqual(monitor.denial("demo-node-a"), None)
        self.assertEqual(monitor.denial("demo-node-a", privileged=True), "sudo_locked")
        self.assertEqual(monitor.discovery("demo-node-a")["status"], "active")
        self.assertEqual(monitor.discovery("demo-node-a")["sudo_state"], "locked")
        self.assertTrue(monitor.discovery("demo-node-a")["ssh_reachable"])
        self.assertEqual(monitor.detail("demo-node-a")["ssh_reason"], "probe_timeout")
        self.assertTrue(monitor.detail("demo-node-a")["degraded"])
        self.assertTrue(any("host_readiness_failed" in line and "probe_timeout" in line
                            for line in warnings.output))
        self.assertFalse(any("host_readiness_safety_unconfirmed" in line
                             or "host_readiness_stale" in line
                             for line in warnings.output))

        result = await monitor.recheck("demo-node-a")
        self.assertFalse(result["recheck_ok"])
        self.assertEqual(monitor.detail("demo-node-a")["ssh_reason"], "connection_failed")
        self.assertTrue(monitor.active("demo-node-a"))
        self.assertNotIn("sudo", calls)
        self.assertNotIn("sudo_challenge", calls)

        now[0] += 271
        self.assertFalse(monitor.active("demo-node-a"))
        self.assertEqual(monitor.denial("demo-node-a"), "ssh_readiness_stale")

    async def test_sealed_failed_safety_probe_recovers_only_after_conclusive_check(self):
        calls: list[str] = []
        safety = [
            ProbeResult(False, "probe_timeout"),
            ProbeResult(False, "root_unconfirmed", needs_corroboration=True),
            ProbeResult(True),
            ProbeResult(False, "root_unconfirmed", needs_corroboration=True),
            ProbeResult(False, "connection_failed"),
        ]

        async def probe(_alias: str, kind: str) -> ProbeResult:
            calls.append(kind)
            return safety.pop(0) if kind == "safety" else ProbeResult(True)

        monitor = ReadinessMonitor(
            ReadinessSettings(authorized=True), {"demo-node-a": True}, probe,
            sealed_hosts=("demo-node-a",),
        )
        self.assertFalse(await monitor.check("demo-node-a"))
        self.assertEqual(monitor.discovery("demo-node-a")["status"], "offline")
        self.assertEqual(monitor.denial("demo-node-a", privileged=True), "probe_timeout")
        self.assertFalse(await monitor.check("demo-node-a"))
        self.assertEqual(monitor.denial("demo-node-a", privileged=True), "safety_unconfirmed")
        self.assertTrue(monitor.detail("demo-node-a")["degraded"])
        self.assertTrue(await monitor.check("demo-node-a"))
        self.assertEqual(monitor.discovery("demo-node-a")["sudo_state"], "locked")
        self.assertFalse(monitor.detail("demo-node-a")["degraded"])
        with self.assertLogs("app.readiness", level="WARNING") as warnings:
            self.assertFalse(await monitor.check("demo-node-a"))
        self.assertEqual(monitor.denial("demo-node-a", privileged=True), "safety_unconfirmed")
        self.assertTrue(monitor.discovery("demo-node-a")["ssh_reachable"])
        self.assertEqual(monitor.discovery("demo-node-a")["status"], "offline")
        self.assertTrue(any("host_readiness_safety_unconfirmed" in log for log in warnings.output))
        self.assertFalse(any("host_readiness_stale" in log for log in warnings.output))
        self.assertTrue(monitor.detail("demo-node-a")["degraded"])
        self.assertFalse(await monitor.check("demo-node-a"))
        # The previous pinned identity remains fresh even after an
        # inconclusive subsequent probe; it is not execution permission.
        self.assertTrue(monitor.discovery("demo-node-a")["ssh_reachable"])
        self.assertEqual(monitor.discovery("demo-node-a")["status"], "offline")
        self.assertEqual(calls, ["identity", "safety"] * 5)

    async def test_console_marks_reachable_safety_uncertainty_not_offline(self):
        from importlib.resources import files
        source = files("app").joinpath("assets", "console.js").read_text("utf-8")
        self.assertIn('host.ssh_reachable && host.sudo_state === "safety_unconfirmed"', source)
        self.assertIn('"Reachable · safety unconfirmed"', source)
        self.assertIn('? "readiness-warning"', source)

    async def test_sealed_readiness_unknown_alias_rejected_at_setup(self):
        with self.assertRaises(ValueError):
            ReadinessMonitor(
                ReadinessSettings(authorized=True), {"demo-node-a": True},
                self.probe, sealed_hosts=("demo-node-b",),
            )

    async def test_sealed_unsafe_passwordless_sudo_fails_closed(self):
        monitor = ReadinessMonitor(
            ReadinessSettings(authorized=True), {"demo-node-a": True},
            AsyncMock(side_effect=[ProbeResult(True),
                                   ProbeResult(False, "passwordless_root", unsafe=True)]),
            sealed_hosts=("demo-node-a",),
        )
        self.assertFalse(await monitor.check("demo-node-a"))
        self.assertFalse(monitor.active("demo-node-a"))
        self.assertEqual(monitor.denial("demo-node-a"), "passwordless_root")
        self.assertEqual(monitor.discovery("demo-node-a")["sudo_state"], "offline")
        monitor._probe = AsyncMock(side_effect=[
            ProbeResult(True),
            ProbeResult(False, "root_unconfirmed", needs_corroboration=True),
        ])
        self.assertFalse(await monitor.check("demo-node-a"))
        self.assertEqual(monitor.denial("demo-node-a"), "passwordless_root")
        monitor._probe = AsyncMock(side_effect=[ProbeResult(True), ProbeResult(True)])
        self.assertTrue(await monitor.check("demo-node-a"))
        self.assertEqual(monitor.denial("demo-node-a", privileged=True), "sudo_locked")

    async def test_retention_stale_and_recovery(self):
        a = "demo-node-a"
        self.assertEqual(self.m.discovery(a), {"status":"offline","sudo_ready":False})
        self.assertTrue(await self.m.check(a))
        self.assertTrue(self.m.sudo_ready(a))
        self.now += 30
        self.probe.return_value = ProbeResult(False, "connection_failed")
        self.assertFalse(await self.m.check(a))
        self.assertTrue(self.m.active(a))
        self.assertTrue(self.m.sudo_ready(a))
        self.assertTrue(self.m.detail(a)["degraded"])
        self.assertEqual(self.m.detail(a)["ssh_reason"], "connection_failed")
        self.assertEqual(self.m.retry_interval(a), 30)
        with self.assertNoLogs("app.readiness", "WARNING"):
            self.assertFalse(await self.m.check(a))
        self.now += 270
        self.assertEqual(self.m.denial(a), "ssh_readiness_stale")
        self.assertFalse(self.m.active(a))
        self.assertEqual(self.m.retry_interval(a), 120)
        self.probe.return_value = ProbeResult(True)
        self.assertTrue(await self.m.check(a))
        self.assertEqual(self.m.denial(a), None)
        self.assertEqual(self.m.retry_interval(a), 30)

    async def test_unauthorized_never_runs(self):
        m = ReadinessMonitor(ReadinessSettings(), {"demo-node-a": True}, self.probe)
        m.start()
        await m.stop()
        self.assertFalse(await m.check("demo-node-a"))
        self.assertFalse(await m.check("retired"))
        with self.assertRaises(ValueError):
            await m.recheck("demo-node-a")
        self.probe.assert_not_awaited()
        self.assertEqual(m.denial("demo-node-a"), "probe_authorization_missing")
        self.assertEqual(m.snapshot()["degraded_count"], 1)

    async def test_safety_failure_and_sudo_independent(self):
        a = "demo-node-a"
        self.assertTrue(await self.m.check(a))
        self.now += 180
        self.probe.side_effect = [ProbeResult(True), ProbeResult(True), ProbeResult(False, "sudo_rejected")]
        self.assertTrue(await self.m.check(a))
        self.assertTrue(self.m.sudo_ready(a))
        self.now += 120
        self.assertTrue(self.m.active(a))
        self.assertFalse(self.m.sudo_ready(a))
        self.assertEqual(self.m.denial(a, privileged=True), "sudo_rejected")
        self.probe.side_effect = [ProbeResult(True), ProbeResult(False, "passwordless_root", unsafe=True)]
        self.assertFalse(await self.m.check(a))
        self.assertFalse(self.m.active(a))
        self.assertEqual(self.m.denial(a), "passwordless_root")
        self.probe.side_effect = None
        self.assertTrue(await self.m.check(a))

    async def test_corroborated_readiness_respects_suspension_and_recovers_from_unsafe(self):
        a = "demo-node-a"
        unknown = ProbeResult(False, "root_unconfirmed", needs_corroboration=True)
        ok = ProbeResult(True)
        self.m.mark_passwordless_root(a)
        self.probe.side_effect = [ok, unknown, ok]
        self.assertTrue(await self.m.check(a, privileged=False))
        self.assertTrue(self.m.active(a))
        self.assertTrue(self.m.sudo_ready(a))
        self.assertEqual(self.probe.await_args_list[-1].args[1], "sudo_challenge")
        self.m.suspend(a)
        self.probe.reset_mock(side_effect=True)
        self.probe.side_effect = [ok, unknown]
        self.assertFalse(await self.m.check(a))
        self.assertTrue(self.m.active(a))
        self.assertFalse(self.m.sudo_ready(a))
        self.assertEqual([c.args[1] for c in self.probe.await_args_list], ["identity", "safety"])
        self.probe.side_effect = [ok, unknown, ok]
        self.assertTrue((await self.m.recheck(a))["recheck_ok"])
        self.assertFalse(self.m.password_suspended(a))
        self.assertTrue(self.m.sudo_ready(a))
        self.now += 300
        self.probe.side_effect = [ok, unknown, ProbeResult(False, "probe_timeout")]
        self.assertFalse(await self.m.check(a))
        self.assertFalse(self.m.active(a))

    async def test_suspend_and_operator_recheck(self):
        a = "demo-node-a"
        self.probe.side_effect = [ProbeResult(True), ProbeResult(True),
                                  ProbeResult(False, "sudo_authentication", password_rejected=True)]
        self.assertFalse(await self.m.check(a, privileged=True))
        self.assertTrue(self.m.active(a))
        self.assertFalse(self.m.sudo_ready(a))
        self.assertTrue(self.m.password_suspended(a))
        self.probe.reset_mock(side_effect=True)
        self.assertFalse(await self.m.check(a, privileged=True))
        self.assertEqual([c.args[1] for c in self.probe.await_args_list], ["identity", "safety"])
        self.assertEqual(self.m.denial(a, privileged=True), "sudo_authentication_suspended")
        result = await self.m.recheck(a)
        self.assertTrue(result["sudo_ready"])
        with self.assertRaises(ValueError):
            await self.m.recheck("retired")
        self.assertFalse(await self.m.check("retired"))
        b = await self.m.recheck("demo-node-b")
        self.assertFalse(b["sudo_configured"])
        self.assertFalse(b["degraded"])

    async def test_failed_rechecks_retain_suspension_and_skip_future_password_probes(self):
        a = "demo-node-a"
        ok = ProbeResult(True)
        self.assertTrue(await self.m.check(a, privileged=True))
        self.m.suspend(a)
        for responses in (
            [ProbeResult(False, "connection_failed")],
            [ok, ProbeResult(False, "inconclusive_safety")],
            [ok, ok, TimeoutError()],
            [ok, ok, ProbeResult(False, "inconclusive_sudo")],
            [ok, ok, ProbeResult(False, "sudo_authentication", password_rejected=True)],
        ):
            with self.subTest(responses=responses):
                self.probe.side_effect = responses
                failed = await self.m.recheck(a)
                self.assertFalse(failed["recheck_ok"])
                self.assertTrue(self.m.password_suspended(a))
                self.assertFalse(self.m.password_probe_permitted(a))
                self.assertFalse(self.m.sudo_ready(a))
                for privileged in (None, True, False):
                    self.probe.reset_mock(side_effect=True)
                    await self.m.check(a, privileged=privileged)
                    self.assertEqual([c.args[1] for c in self.probe.await_args_list],
                                     ["identity", "safety"])
        result = await self.m.recheck(a)
        self.assertTrue(result["recheck_ok"])
        self.assertTrue(result["sudo_ready"])
        self.assertFalse(self.m.password_suspended(a))

    async def test_cancelled_recheck_revokes_scoped_permission(self):
        a = "demo-node-a"
        self.m.suspend(a)
        entered = asyncio.Event()
        async def probe(alias, kind):
            if kind == "sudo":
                self.assertTrue(self.m.password_suspended(alias))
                self.assertTrue(self.m.password_probe_permitted(alias))
                self.assertFalse(self.m.sudo_ready(alias))
                entered.set()
                await asyncio.Future()
            return ProbeResult(True)
        self.m._probe = probe
        task = asyncio.create_task(self.m.recheck(a))
        await entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(self.m.password_suspended(a))
        self.assertFalse(self.m.password_probe_permitted(a))
        self.m._probe = self.probe
        self.assertFalse(await self.m.check(a, privileged=True))
        self.assertEqual([c.args[1] for c in self.probe.await_args_list],
                         ["identity", "safety"])

    async def test_rejection_during_recheck_invalidates_scoped_retry(self):
        a = "demo-node-a"
        for rejection_at in ("identity", "safety", "sudo"):
            with self.subTest(rejection_at=rejection_at):
                self.m.suspend(a)
                calls = []
                async def probe(alias, kind):
                    calls.append(kind)
                    if kind == rejection_at:
                        if kind == "sudo":
                            self.assertTrue(self.m.password_probe_permitted(alias))
                        self.m.suspend(alias)
                        self.assertFalse(self.m.password_probe_permitted(alias))
                    return ProbeResult(True)
                self.m._probe = probe
                result = await self.m.recheck(a)
                self.assertFalse(result["recheck_ok"])
                self.assertTrue(self.m.password_suspended(a))
                self.assertFalse(self.m.password_probe_permitted(a))
                self.assertEqual(calls, ["identity", "safety", "sudo"]
                                 if rejection_at == "sudo" else ["identity", "safety"])

    async def test_recheck_reports_live_result_separately_from_cached_eligibility(self):
        a, b = "demo-node-a", "demo-node-b"
        await self.m.check(a)
        await self.m.check(b)
        for alias, responses in (
            (b, [ProbeResult(False, "connection_failed")]),
            (a, [ProbeResult(True), ProbeResult(True), ProbeResult(False, "probe_timeout")]),
        ):
            with self.subTest(alias=alias):
                self.probe.side_effect = responses
                result = await self.m.recheck(alias)
                self.assertFalse(result["recheck_ok"])
                self.assertEqual(result["status"], "active")
                self.assertEqual(result["sudo_ready"], alias == a)
                self.assertTrue(result["degraded"])
                self.probe.side_effect = None
        self.assertTrue((await self.m.recheck(a))["recheck_ok"])

    async def test_inflight_success_cannot_undo_new_suspension(self):
        a = "demo-node-a"
        async def probe(alias, kind):
            if kind == "sudo":
                self.m.suspend(alias)
            return ProbeResult(True)
        self.m._probe = probe
        self.assertFalse(await self.m.check(a, privileged=True))
        self.assertFalse(self.m.sudo_ready(a))

    async def test_scheduler_concurrency_serialization_and_shutdown(self):
        active = 0
        peak = 0
        seen = []
        async def probe(alias, kind):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            seen.append((alias, kind))
            await asyncio.sleep(.002)
            active -= 1
            return ProbeResult(True)
        m = ReadinessMonitor(ReadinessSettings(authorized=True, max_concurrent=1),
                {"demo-node-a": False, "demo-node-b": False}, probe)
        m.start()
        m.start()
        await asyncio.gather(m.check("demo-node-a"), m.check("demo-node-b"))
        await m.stop()
        self.assertEqual(peak, 1)
        self.assertEqual(len(seen), 8)
        self.assertEqual(m.snapshot()["degraded_count"], 0)

    async def test_sanitized_unexpected_errors_and_timeout(self):
        self.probe.side_effect = RuntimeError("private output")
        self.assertFalse(await self.m.check("demo-node-b"))
        self.assertEqual(self.m.detail("demo-node-b")["ssh_reason"], "probe_failed")
        self.probe.side_effect = TimeoutError
        self.assertFalse(await self.m.check("demo-node-b"))
        self.assertEqual(self.m.detail("demo-node-b")["ssh_reason"], "probe_timeout")
        self.now += 300
        self.assertEqual(self.m.retry_interval("demo-node-b"), 120)


class TransportReadinessTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.a = "demo-node-a"
        self.host = HostSpec(alias=self.a, address="fixture", port=22, username="fixture",
                identity_file=Path("/fixture/key"), known_hosts_file=Path("/fixture/pins"),
                principals=["fixture"], environment="non-production",
                access="restricted", privileged_access="restricted")
        self.executor = SSHExecutor({self.a: self.host}, enabled=True,
            sudo_passwords={self.a:"synthetic"}, readiness_settings=ReadinessSettings(authorized=True))
        self.check = patch("app.ssh_executor._check_file")
        self.check.start()
        self.addCleanup(self.check.stop)

    def result(self, status="succeeded", code=0, out="fixture", *, root=None, reason=None, rejected=False):
        return SSHResult(self.a,status,code,out,"",.01,root_started=root,
                         failure_kind=reason,password_rejected=rejected)

    async def test_sealed_executor_loads_envelope_and_never_password_probes_in_background(self):
        from app.sealed_credentials import seal_sudo
        sealed = seal_sudo(
            "synthetic-console-password-not-real", "synthetic-sudo-not-real",
            deployment="lab", issuer="https://testing.example.org",
            alias=self.a, username=self.host.username,
        )
        executor = SSHExecutor(
            {self.a: self.host}, enabled=True, sealed_sudo={self.a: sealed},
            readiness_settings=ReadinessSettings(authorized=True),
        )
        self.assertEqual(executor._sudo_passwords, {})
        self.assertIn(self.a, executor._sealed_sudo)
        self.assertNotIn("synthetic-sudo-not-real", repr(executor._sealed_sudo))
        with patch.object(executor, "_run", new_callable=AsyncMock) as run:
            run.side_effect = [
                self.result(out=self.host.username),
                self.result("command_error", 1, "", reason="sudo_password_required"),
            ]
            self.assertTrue(await executor.readiness.check(self.a))
            self.assertEqual([x.args[1].argv for x in run.await_args_list],
                             [["/usr/bin/id", "-un"], ["/usr/bin/id", "-u"]])
            self.assertIsNone(run.await_args_list[1].kwargs["sudo_password"])
            self.assertTrue(run.await_args_list[1].kwargs["no_password"])
            self.assertEqual(executor.discover_hosts("fixture", [])[self.a]["sudo_state"], "locked")
            self.assertEqual(executor.readiness.snapshot()["degraded_count"], 0)
            with self.assertRaisesRegex(ReadinessDenied, "sudo_locked"):
                executor.require_ready(self.a, privileged=True)
            run.reset_mock()
            self.assertEqual((await executor._readiness_probe(self.a, "sudo")).reason,
                             "sudo_locked")
            run.assert_not_awaited()

    async def test_sealed_executors_cannot_mix_plaintext_and_envelopes(self):
        with self.assertRaises(ValueError):
            SSHExecutor({self.a: self.host}, enabled=True,
                        sudo_passwords={self.a: "synthetic"},
                        sealed_sudo={self.a: {"algorithm": "aes-256-gcm"}})
        with self.assertRaises(ValueError):
            SSHExecutor({self.a: self.host}, enabled=True,
                        sealed_sudo={"demo-node-b": {"algorithm": "aes-256-gcm"}})

    async def test_managed_v2_environment_loads_only_current_host_envelopes(self):
        from app import config, runtime_files
        from app.sealed_credentials import from_legacy
        old = {
            "version": 1,
            "oauth_login_key": "synthetic-oauth-" + "a" * 40,
            "oauth_signing_key": "synthetic-signing-" + "b" * 40,
            "viewer_password": "synthetic-console-secret-256",
            "metrics_token": "synthetic-metrics-" + "m" * 40,
            "ssh_private_key": ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                                "synthetic-not-real-key\n"
                                "-----END OPENSSH PRIVATE KEY-----"),
            "sudo_passwords": {
                self.a: "synthetic-sudo-not-real",
                "demo-node-b": "retired-synthetic-sudo-not-real",
            },
        }
        sealed = from_legacy(
            old, console_password=old["viewer_password"], deployment="lab",
            issuer="https://testing.example.org", hosts={
                self.a: self.host.username, "demo-node-b": "gateway",
            },
        )
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / "managed.json"
            source.write_text(json.dumps(sealed))
            source.chmod(0o600)
            with (patch.object(runtime_files, "SECRETS", Path(d) / "unused-default.json"),
                  patch.multiple(
                      config, MCP_MANAGED_SECRETS_VERSION="2",
                      MCP_MANAGED_SECRETS_SOURCE=str(source),
                      MCP_MANAGED_SECRETS_DIGEST=runtime_files.managed_secrets_fingerprint(sealed),
                  ),
                  patch("app.ssh_executor.load_inventory", return_value={self.a: self.host}),
                  patch.dict(os.environ, {
                      "SSH_EXECUTOR_ENABLED": "true",
                      "SSH_INVENTORY_FILE": "/fixture/inventory",
                      "SSH_APPROVED_ALIASES": self.a,
                      "SSH_READINESS_AUTHORIZED": "true",
                  })):
                loaded = SSHExecutor.from_environment()
                self.assertFalse(loaded._sudo_passwords)
                self.assertEqual(set(sealed["sealed_sudo"]), {self.a, "demo-node-b"})
                self.assertEqual(set(loaded._sealed_sudo), {self.a})
                self.assertEqual(loaded._sealed_sudo[self.a], sealed["sealed_sudo"][self.a])
                self.assertTrue(loaded.readiness._states[self.a].sealed)
                self.assertEqual(loaded.discover_hosts("fixture", [])[self.a]["sudo_ready"], False)
                self.assertNotIn("demo-node-b", loaded.discover_hosts("fixture", []))
                # Even stale envelopes are part of the validated snapshot:
                # changing one after bootstrap must fail the digest check.
                altered_stale = json.loads(json.dumps(sealed))
                altered_stale["sealed_sudo"]["demo-node-b"]["ciphertext"] = (
                    altered_stale["sealed_sudo"]["demo-node-b"]["ciphertext"][:-2] + "AA"
                )
                source.write_text(json.dumps(altered_stale))
                with self.assertRaisesRegex(Exception, "Protected sudo secret configuration"):
                    SSHExecutor.from_environment()
                # A different, individually valid v2 revision must never be
                # combined with the bootstrap Console verifier/generation.
                changed = json.loads(json.dumps(sealed))
                changed["viewer_generation"] = "f" * 32
                source.write_text(json.dumps(changed))
                with self.assertRaisesRegex(Exception, "Protected sudo secret configuration"):
                    SSHExecutor.from_environment()
                source.write_text(json.dumps({**sealed, "sudo_passwords": old["sudo_passwords"]}))
                with self.assertRaisesRegex(Exception, "Protected sudo secret configuration"):
                    SSHExecutor.from_environment()
                source.unlink()
                with self.assertRaisesRegex(Exception, "sealed secret file is unavailable"):
                    SSHExecutor.from_environment()
                with patch.object(config, "MCP_MANAGED_SECRETS_DIGEST", ""):
                    with self.assertRaisesRegex(Exception, "secret revision is unavailable"):
                        SSHExecutor.from_environment()

    async def test_fixed_probes_and_transient_failure(self):
        with patch.object(self.executor, "_run", new_callable=AsyncMock) as run:
            run.side_effect = [self.result(), self.result("command_error",1,"",reason="sudo_password_required"),
                               self.result(out="0",root=True)]
            self.assertTrue(await self.executor.readiness.check(self.a, privileged=True))
            calls = run.await_args_list
            self.assertEqual([c.args[1].argv for c in calls],
                             [["/usr/bin/id","-un"],["/usr/bin/id","-u"],["/usr/bin/id","-u"]])
            self.assertTrue(calls[1].kwargs["no_password"])
            self.assertIsNone(calls[1].kwargs["sudo_password"])
            self.assertEqual(calls[2].kwargs["sudo_password"], "synthetic")
            self.executor.require_ready(self.a, privileged=True)
            run.side_effect = None
            run.return_value = self.result(out="wrong")
            self.assertFalse(await self.executor.readiness.check(self.a))
            self.executor.require_ready(self.a)
            self.assertEqual(self.executor.discover_hosts("fixture", ["old-node"]),
                {self.a:{"status":"active","sudo_ready":True},
                 "old-node":{"status":"retired","sudo_ready":False}})
            run.side_effect = [self.result(),self.result(out="0",root=True)]
            self.assertFalse(await self.executor.readiness.check(self.a))
            with self.assertRaisesRegex(ReadinessDenied,"passwordless_root"):
                self.executor.require_ready(self.a)
            self.assertEqual(self.executor.discover_hosts("other", [self.a]), {})

    async def test_dispatch_and_actual_password_failure(self):
        request = ExecuteCommandRequest(server=self.a,argv=["id"],reason="synthetic",privileged=True)
        with patch.object(self.executor, "_run", new_callable=AsyncMock) as run:
            with self.assertRaises(ReadinessDenied):
                await self.executor._execute_approved_privileged("fixture",request)
            run.assert_not_awaited()
            run.side_effect = [self.result(),self.result("command_error",1,"",reason="sudo_authorization"),
                               self.result(out="0",root=True)]
            await self.executor.readiness.check(self.a)
            run.side_effect=None
            run.return_value=self.result("command_error",1,"",reason="sudo_authentication",rejected=True)
            await self.executor._execute_approved_privileged("fixture",request)
            self.assertFalse(self.executor.readiness.sudo_ready(self.a))
            with self.assertRaises(ReadinessDenied):
                await self.executor._execute_approved_privileged("fixture",request)

    async def test_new_approval_live_then_cached_grant(self):
        approvals=ApprovalManager()
        key=("sid","conversation",self.a)
        with patch.object(self.executor,"check_readiness_live",new_callable=AsyncMock) as live, \
                patch.object(self.executor,"require_ready") as cached:
            live.side_effect=ReadinessDenied("fixture denied")
            with self.assertRaises(ReadinessDenied):
                await require_host_access(self.executor,"fixture",self.a,
                    session_id=key[0],conversation_id=key[1],approvals=approvals)
            self.assertFalse(approvals.pending)
            live.side_effect=None
            task=asyncio.create_task(require_host_access(self.executor,"fixture",self.a,
                    session_id=key[0],conversation_id=key[1],approvals=approvals))
            await asyncio.sleep(0)
            approvals.decide(next(iter(approvals.pending)),grant=True,duration="5m")
            await task
            self.assertEqual(live.await_count,2)
            await require_host_access(self.executor,"fixture",self.a,
                    session_id=key[0],conversation_id=key[1],approvals=approvals)
            self.assertEqual(live.await_count,2)
            self.assertEqual(cached.call_count,2)
        approvals.shutdown()


class RecheckSocketTests(unittest.IsolatedAsyncioTestCase):
    async def test_alias_only_and_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            socket=Path(tmp)/"control.sock"
            probe = AsyncMock(return_value=ProbeResult(True))
            m=ReadinessMonitor(ReadinessSettings(authorized=True),{"demo-node-a":False},
                               probe)
            async with control.control_server("INFO",socket,m.recheck):
                result=await asyncio.to_thread(control_cli.request,"recheck-host",path=socket,alias="demo-node-a")
                self.assertEqual(result["host"]["status"],"active")
                self.assertIs(result["host"]["recheck_ok"], True)
                probe.return_value = ProbeResult(False, "connection_failed")
                failed = await asyncio.to_thread(control_cli.request,"recheck-host",path=socket,alias="demo-node-a")
                self.assertEqual(failed["host"]["status"], "active")
                self.assertIs(failed["host"]["recheck_ok"], False)
                with self.assertRaises(ValueError):
                    await asyncio.to_thread(control_cli.request,"recheck-host",path=socket,alias="retired")
                with patch.object(control_cli,"request",return_value=result), patch("builtins.print"):
                    self.assertEqual(control_cli.main(["recheck-host","demo-node-a"]),0)
                    with patch.object(control_cli, "request", return_value=failed):
                        self.assertEqual(control_cli.main(["recheck-host","demo-node-a"]),1)
                    result["host"].pop("recheck_ok")
                    self.assertEqual(control_cli.main(["recheck-host","demo-node-a"]),1)
