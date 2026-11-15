"""Synthetic-only SSH executor tests; no real socket or SSH program is launched."""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

from app.contracts import ExecuteCommandRequest
from app.ssh_executor import (
    HostSpec, SSHDenied, SSHExecutor, OutputLimitExceeded,
    _CWD_EXEC, _CWD_READY_PREFIX, _CWD_FAILED_PREFIX, _read_cwd_stderr,
    _framed_root_marker, _effective_argv, _ssh_argv, _remote_exit, _spawn_ssh_command,
    load_inventory,
)
import shlex

PRINCIPAL = "ssh-mcp-operator"


class SSHFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        p = Path(self.temp.name)
        self.key = p / "id_lab"
        self.keys = p / "known_hosts"
        self.inv = p / "inventory.json"
        self.key.write_text("synthetic-key-placeholder")
        self.key.chmod(0o600)
        self.keys.write_text("lab.example.test ssh-ed25519 synthetic-public-key\n")
        self.keys.chmod(0o644)
        self.host = {
            "alias": "lab", "address": "lab.example.test", "port": 22, "username": "gateway",
            "identity_file": str(self.key), "known_hosts_file": str(self.keys),
            "principals": [PRINCIPAL], "environment": "non-production", "access": "always-granted", "max_parallel": 1,
        }
        self.approved = frozenset(["lab"])

    def inventory(self, hosts=None):
        self.inv.write_text(json.dumps({"version": 1, "hosts": hosts if hosts is not None else [self.host]}))
        return load_inventory(self.inv, self.approved)

    def request(self, **change):
        return ExecuteCommandRequest.model_validate({
            "server": "lab", "argv": ["printf", "%s", "a;$(id)"], "reason": "TEST-207 test",
            **change,
        })


class InventorySecurityTests(SSHFixture):
    def test_signed_host_access_is_required_and_strict(self):
        absent = dict(self.host)
        del absent["access"]
        with self.assertRaises(ValidationError):
            HostSpec.model_validate(absent)
        for invalid in ("", "allowed", "always_granted", None, True):
            with self.subTest(value=invalid), self.assertRaises(ValidationError):
                HostSpec.model_validate({**self.host, "access": invalid})
        self.assertEqual(self.inventory()["lab"].access, "always-granted")

    def test_missing_explicit_approvals_and_extra_alias(self):
        with self.assertRaises(SSHDenied):
            load_inventory(self.inv, frozenset())
        with self.assertRaises(SSHDenied):
            self.inventory([self.host, {**self.host, "alias": "unapproved"}])
        with self.assertRaises(SSHDenied):
            self.inventory([self.host, self.host])
        self.assertEqual(list(self.inventory()), ["lab"])

    def test_executor_loads_200_allowlisted_hosts_but_rejects_201(self):
        hosts = [{**self.host, "alias": f"peer-{i:03d}",
                  "address": f"host-{i:03d}.example.test"} for i in range(200)]
        approvals = frozenset(host["alias"] for host in hosts)
        self.inv.write_text(json.dumps({"version": 1, "hosts": hosts}))
        loaded = load_inventory(self.inv, approvals)
        self.assertEqual(len(loaded), 200)
        executor = SSHExecutor(loaded, enabled=True)
        self.assertEqual(len(executor.list_servers(PRINCIPAL)), 200)
        self.assertEqual(executor.list_servers("unapproved"), [])
        hosts.append({**self.host, "alias": "peer-200",
                      "address": "host-200.example.test"})
        self.inv.write_text(json.dumps({"version": 1, "hosts": hosts}))
        with self.assertRaises(SSHDenied):
            load_inventory(self.inv, approvals | {"peer-200"})

    def test_env_gate_disabled_and_missing_inputs(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SSHDenied):
                SSHExecutor.from_environment()
        with patch.dict(os.environ, {"SSH_EXECUTOR_ENABLED": "true"}, clear=True):
            with self.assertRaises(SSHDenied):
                SSHExecutor.from_environment()
        self.inventory()
        with patch.dict(os.environ, {
            "SSH_EXECUTOR_ENABLED": "true",
            "SSH_INVENTORY_FILE": str(self.inv),
            "SSH_APPROVED_ALIASES": "lab",
        }, clear=True):
            executor = SSHExecutor.from_environment()
            self.assertEqual(executor.list_servers(PRINCIPAL), ["lab"])

    def test_invalid_inventory_and_file_ownership_modes(self):
        self.inv.write_text("not-json")
        with self.assertRaises(SSHDenied):
            load_inventory(self.inv, self.approved)
        self.inv.write_text(json.dumps({"version": 2, "hosts": [self.host]}))
        with self.assertRaises(SSHDenied):
            load_inventory(self.inv, self.approved)
        self.inventory()
        self.inv.chmod(0o666)
        with self.assertRaises(SSHDenied):
            load_inventory(self.inv, self.approved)
        self.inv.chmod(0o600)
        self.inv.unlink()
        self.inv.symlink_to(self.key)
        with self.assertRaises(SSHDenied):
            load_inventory(self.inv, self.approved)

    def test_host_address_and_principal_schema(self):
        for bad in ["-option", "user@host", "host..name", "bad space", "bad/path", "[::1]"]:
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                HostSpec.model_validate_json(json.dumps({**self.host, "address": bad}))
        for invalid in ["-root", "name space", "root@host"]:
            with self.subTest(username=invalid), self.assertRaises(ValidationError):
                HostSpec.model_validate_json(json.dumps({**self.host, "username": invalid}))
        for invalid in ("prod", "lab", "PRODUCTION", "", None, True):
            with self.subTest(environment=invalid), self.assertRaises(ValidationError):
                HostSpec.model_validate_json(json.dumps({**self.host, "environment": invalid}))
        with self.assertRaises(ValidationError):
            HostSpec.model_validate_json(json.dumps({**self.host, "principals": [PRINCIPAL, PRINCIPAL]}))
        with self.assertRaises(ValidationError):
            HostSpec.model_validate_json(json.dumps({**self.host, "max_parallel": 33}))
        self.assertEqual(HostSpec.model_validate_json(json.dumps({**self.host, "address": "192.0.2.10"})).address, "192.0.2.10")

    def test_production_host_classification_preserves_principal_authorization(self):
        prod = {**self.host, "alias": "prod", "environment": "production"}
        self.inv.write_text(json.dumps({"version": 1, "hosts": [self.host, prod]}))
        hosts = load_inventory(self.inv, frozenset({"lab", "prod"}))
        self.assertEqual(hosts["lab"].environment, "non-production")
        self.assertEqual(hosts["prod"].environment, "production")
        executor = SSHExecutor(hosts, enabled=True)
        self.assertEqual(executor.list_servers(PRINCIPAL), ["lab", "prod"])
        self.assertEqual(executor.list_servers("other"), [])
        self.assertEqual(executor.authorized_host(PRINCIPAL, "prod").alias, "prod")
        with self.assertRaises(SSHDenied):
            executor.authorized_host("other", "prod")

    def test_command_argument_escaping_and_ssh_security_flags(self):
        host = HostSpec.model_validate_json(json.dumps(self.host))
        argv = _ssh_argv(host, self.request())
        self.assertEqual(argv[0:3], ["ssh", "-F", "/dev/null"])
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn("IdentityAgent=none", argv)
        self.assertIn("ProxyCommand=none", argv)
        self.assertIn("UserKnownHostsFile=" + str(self.keys), argv)
        self.assertEqual(argv[-2], "gateway@lab.example.test")
        self.assertEqual(argv[-1], "printf %s 'a;$(id)'")
        self.assertEqual(argv[-3], "--")

    def test_strict_bash_script_and_positional_arguments_are_preserved(self):
        for name in ("bash", "/bin/bash", "/usr/bin/bash"):
            for switch in ("-c", "-lc"):
                request = self.request(argv=[name, switch, 'printf "%s" "$1"', "_", "original"],
                                       strict_bash=True)
                prepared = _effective_argv(request)
                self.assertTrue(prepared[2].startswith("set -euo pipefail\n"))
                self.assertEqual(prepared[3:], ["_", "original"])
                self.assertIn("set -euo pipefail", _ssh_argv(
                    HostSpec.model_validate_json(json.dumps(self.host)), request)[-1])
        for argv in (["sh", "-c", "false"], ["echo", "ok"], ["python3", "-c", "print(1)"]):
            self.assertEqual(_effective_argv(self.request(argv=argv, strict_bash=True)), argv)
        for argv in (["bash"], ["bash", "--", "-c", "true"], ["bash", "-e", "true"]):
            with self.assertRaises(ValidationError):
                self.request(argv=argv, strict_bash=True)

    def test_cwd_precondition_script_is_inode_pinned_and_safe(self):
        from subprocess import run
        with tempfile.TemporaryDirectory() as dirname:
            cwd = Path(dirname)
            stat = cwd.stat()
            passed = run(["python3", "-c", _CWD_EXEC, "a" * 32, dirname,
                          str(stat.st_dev), str(stat.st_ino), "pwd"], capture_output=True,
                         text=True, check=False)
            self.assertEqual(passed.returncode, 0, passed.stderr)
            self.assertEqual(passed.stdout.strip(), dirname)
            mismatch = run(["python3", "-c", _CWD_EXEC, "a" * 32, dirname,
                            str(stat.st_dev), str(stat.st_ino + 1), "echo", "must-not-run"],
                           capture_output=True, text=True, check=False)
            self.assertEqual(mismatch.returncode, 255)
            self.assertNotIn("must-not-run", mismatch.stdout)

    def test_cwd_wrapper_keeps_command_launch_failures_as_126_or_127(self):
        from subprocess import run
        with tempfile.TemporaryDirectory() as dirname:
            directory = Path(dirname)
            details = directory.stat()
            args = ["python3", "-c", _CWD_EXEC, "a" * 32, dirname,
                    str(details.st_dev), str(details.st_ino)]
            absent = run([*args, "/definitely/missing/sky247-program"],
                         capture_output=True, text=True, check=False)
            self.assertEqual(absent.returncode, 127, absent.stderr)
            self.assertIn("Command not found", absent.stderr)
            self.assertNotIn("/definitely/missing", absent.stderr)
            file = directory / "non-executable"
            file.write_text("#!/bin/sh\necho must-not-execute\n")
            file.chmod(0o644)
            blocked = run([*args, str(file)], capture_output=True,
                          text=True, check=False)
            self.assertEqual(blocked.returncode, 126, blocked.stderr)
            self.assertIn("not executable", blocked.stderr)
            self.assertNotIn("must-not-execute", blocked.stdout)


class FakeProcess:
    def __init__(self, out=b"ok", err=b"", rc=0, block=False, observed=True):
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.stdout.feed_data(out)
        self.stdout.feed_eof()
        self.stderr.feed_data(err)
        self.stderr.feed_eof()
        self.rc = rc
        self.returncode = None
        self.exit_status = None
        self.exit_signal = None
        self.block = block
        self.observed = observed
        self.channel_complete = True
        self.killed = False

    async def wait(self):
        if self.block and not self.killed:
            await asyncio.sleep(10)
        self.returncode = self.rc if not self.killed else -9
        self.exit_status = self.rc if not self.killed and self.observed and self.rc >= 0 else None
        return self.returncode

    async def communicate(self):
        out = await self.stdout.read()
        err = await self.stderr.read()
        await self.wait()
        return out, err

    def kill(self):
        self.killed = True
        self.returncode = -9


class SSHAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture = SSHFixture()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f = self.fixture
        self.executor = SSHExecutor(self.f.inventory(), enabled=True)
        self.request = self.f.request()

    async def test_no_approval_or_missing_pin_never_launches_subprocess(self):
        with patch("app.ssh_executor._spawn_ssh_command") as spawn:
            with self.assertRaises(SSHDenied):
                await SSHExecutor(self.f.inventory(), enabled=False).execute(PRINCIPAL, self.request)
            with self.assertRaises(SSHDenied):
                await self.executor.execute("unauthorized", self.request)
            with self.assertRaises(SSHDenied):
                await self.executor.execute(PRINCIPAL, self.f.request(server="other"))
            self.f.keys.unlink()
            with self.assertRaises(SSHDenied):
                await self.executor.execute(PRINCIPAL, self.request)
            spawn.assert_not_called()
        self.assertEqual(self.executor.list_servers("unauthorized"), [])
        self.assertEqual(SSHExecutor({}, enabled=False).list_servers(PRINCIPAL), [])

    async def test_private_key_permissions_revalidated_each_call(self):
        self.f.key.chmod(0o644)
        with patch("app.ssh_executor._spawn_ssh_command") as spawn:
            with self.assertRaises(SSHDenied):
                await self.executor.execute(PRINCIPAL, self.request)
            spawn.assert_not_called()

    async def test_normal_success_and_command_failure(self):
        for code, expected in [(0, "succeeded"), (7, "command_error"), (255, "command_error")]:
            with self.subTest(code=code):
                fake = FakeProcess(b"line\n", b"warn", code)
                async def factory(*args, **kwargs):
                    self.assertEqual(args[-2], "gateway@lab.example.test")
                    self.assertEqual(kwargs["stdin"], asyncio.subprocess.DEVNULL)
                    return fake
                with patch("app.ssh_executor._spawn_ssh_command", side_effect=factory):
                    result = await self.executor.execute(PRINCIPAL, self.request)
                self.assertEqual(result.exit_code, code)
                self.assertEqual(result.status, expected)
                self.assertEqual(result.stdout, "line\n")
                self.assertEqual(result.stderr, "warn")

    async def test_accepted_exit_codes_preserve_raw_status_and_255_command_failure(self):
        for code, allowed, expected, accepted in (
            (1, [0, 1], "succeeded", True),
            (2, [0, 1], "command_error", False),
            (255, [0, 254], "command_error", False),
        ):
            async def factory(*_args, **_kwargs):
                return FakeProcess(b"stdout", b"stderr", code)
            with self.subTest(code=code), patch(
                "app.ssh_executor._spawn_ssh_command", side_effect=factory
            ):
                result = await self.executor.execute(
                    PRINCIPAL, self.f.request(success_exit_codes=allowed))
                self.assertEqual((result.exit_code, result.status, result.exit_accepted),
                                 (code, expected, accepted))

    async def test_cleanly_drained_channel_remains_confirmed_after_peer_disconnect(self):
        fake = FakeProcess(b"partial output", b"partial stderr", 255)
        fake.unexpected_disconnect = True
        with patch("app.ssh_executor._spawn_ssh_command", return_value=fake):
            result = await self.executor.execute(PRINCIPAL, self.request)
        self.assertEqual(result.status, "command_error")
        self.assertIsNone(result.failure_kind)
        self.assertEqual(result.exit_code, 255)
        self.assertFalse(result.exit_accepted)
        self.assertEqual(result.stdout, "partial output")
        self.assertEqual(result.stderr, "partial stderr")

    async def test_exit_status_without_channel_close_never_claims_success(self):
        for code, observed, kind, exit_code in (
            (0, True, "output_incomplete", 0),
            (255, True, "output_incomplete", 255),
            (0, False, "execution_uncertain", None),
        ):
            fake = FakeProcess(b"bounded output", b"bounded error", code, observed=observed)
            fake.channel_complete = False
            with self.subTest(code=code, observed=observed), patch(
                "app.ssh_executor._spawn_ssh_command", return_value=fake,
            ):
                result = await self.executor.execute(PRINCIPAL, self.request)
            self.assertEqual(result.status, "transport_error")
            self.assertEqual(result.failure_kind, kind)
            self.assertEqual(result.exit_code, exit_code)
            self.assertIs(result.exit_accepted, False if observed else None)
            self.assertEqual(result.stdout, "bounded output")
            self.assertEqual(result.stderr, "bounded error")

    async def test_preflight_exit_without_channel_close_does_not_dispatch_argv(self):
        fake = FakeProcess(
            b'{"path": "/home/example/repo", "dev": 123, "ino": 456}', b"", 0,
        )
        fake.channel_complete = False
        with patch("app.ssh_executor._spawn_ssh_command", return_value=fake) as spawn:
            result = await self.executor.execute(
                PRINCIPAL, self.f.request(cwd="/home/example/repo", argv=["touch", "must-not-run"]),
            )
        spawn.assert_called_once()
        self.assertEqual(result.status, "transport_error")
        self.assertEqual(result.failure_kind, "execution_uncertain")
        self.assertIsNone(result.exit_code)

    async def test_known_exit_with_failed_output_drain_is_transport_error(self):
        from unittest.mock import AsyncMock
        fake = FakeProcess(b"partial output", b"partial stderr", 255)
        fake.returncode = 255
        fake.exit_status = 255
        fake.stdout.read = AsyncMock(side_effect=[b"partial output", OSError("broken socket")])
        with patch("app.ssh_executor._spawn_ssh_command", return_value=fake):
            result = await self.executor.execute(PRINCIPAL, self.request)
        self.assertEqual(result.status, "transport_error")
        self.assertEqual(result.failure_kind, "output_incomplete")
        self.assertEqual(result.exit_code, 255)
        self.assertFalse(result.exit_accepted)
        self.assertEqual(result.stdout, "partial output")

    async def test_cwd_preflight_resolves_symlink_and_wraps_exact_argv(self):
        created = []
        async def factory(*args, **_kwargs):
            created.append(args)
            if len(created) == 1:
                return FakeProcess(b'{"path": "/home/example/repo", "dev": 123, "ino": 456}',
                                   b"", 0)
            remote = shlex.split(args[-1])
            self.assertEqual(remote[4:8], ["/home/example/repo", "123", "456", "pwd"])
            return FakeProcess(b"/home/example/repo\n",
                               _framed_root_marker(_CWD_READY_PREFIX + remote[3]), 0)
        with patch("app.ssh_executor._spawn_ssh_command", side_effect=factory):
            result = await self.executor.execute(
                PRINCIPAL, self.f.request(argv=["pwd"], cwd="/home/example/link"))
        self.assertEqual(len(created), 2)
        self.assertIn("/home/example/link", created[0][-1])
        self.assertIn("/home/example/repo", created[1][-1])
        self.assertIn(" 123 456 pwd", created[1][-1])
        self.assertEqual(result.effective_cwd, "/home/example/repo")
        self.assertTrue(result.exit_accepted)

    async def test_cwd_preflight_denial_never_starts_user_command(self):
        calls = []
        async def denied(*args, **_kwargs):
            calls.append(args)
            return FakeProcess(b"", b"", 126)
        with patch("app.ssh_executor._spawn_ssh_command", side_effect=denied):
            with self.assertRaises(SSHDenied):
                await self.executor.execute(
                    PRINCIPAL, self.f.request(cwd="/missing", argv=["touch", "/tmp/no"]))
        self.assertEqual(len(calls), 1)

    async def test_cwd_preflight_ssh_255_retains_transport_status_and_stderr(self):
        from app.jobs import JobManager, JobStore
        diagnostic = b"Host key verification failed."
        launches = []

        async def ssh_failure(*args, **_kwargs):
            launches.append(args)
            return FakeProcess(b"", diagnostic, 255, observed=False)

        store = JobStore(Path(self.f.temp.name) / "private" / "jobs.sqlite")
        manager = JobManager(self.executor, store)
        with patch("app.ssh_executor._spawn_ssh_command", side_effect=ssh_failure):
            job_id, result = await manager.execute_sync(
                PRINCIPAL, self.f.request(argv=["echo", "must-not-run"],
                                          cwd="/home/example/repo"))
        self.assertEqual(len(launches), 1)
        self.assertIsNotNone(result)
        self.assertEqual(result.status, "transport_error")
        self.assertIsNone(result.exit_code)
        self.assertEqual(result.stderr, diagnostic.decode())
        saved = store.get(PRINCIPAL, job_id)
        self.assertEqual(saved["status"], "transport_error")
        self.assertIsNone(saved["exit_code"])
        self.assertEqual(store.read_output(PRINCIPAL, job_id)["chunks"][0]["stream"], "stderr")
        with store._connect() as db:
            failure = db.execute(
                "SELECT failure_kind FROM telemetry_outcomes WHERE server=?",
                ("lab",),
            ).fetchone()
            self.assertEqual(failure["failure_kind"], "execution_uncertain")

    async def test_cwd_preflight_ssh_spawn_failure_is_transport_not_denial(self):
        with patch("app.ssh_executor._spawn_ssh_command",
                   side_effect=FileNotFoundError("ssh")) as spawn:
            result = await self.executor.execute(
                PRINCIPAL, self.f.request(argv=["echo", "never"],
                                          cwd="/home/example/repo"))
        self.assertEqual(result.status, "transport_error")
        self.assertIsNone(result.exit_code)
        self.assertIn("SSH transport could not start", result.stderr)
        spawn.assert_called_once()

    async def test_cwd_preflight_bounded_transport_diagnostic(self):
        launches = []

        async def ssh_failure(*args, **_kwargs):
            launches.append(args)
            return FakeProcess(b"", b"Host key verification failed. " + b"x" * 10000, 255,
                               observed=False)

        with patch("app.ssh_executor._spawn_ssh_command", side_effect=ssh_failure):
            result = await self.executor.execute(
                PRINCIPAL, self.f.request(argv=["echo", "never"],
                                          cwd="/home/example/repo"))
        self.assertEqual(len(launches), 1)
        self.assertEqual(result.status, "transport_error")
        self.assertIsNone(result.exit_code)
        self.assertLessEqual(len(result.stderr.encode("utf-8")), 4096)
        self.assertTrue(result.stderr.startswith("Host key verification failed."))

    async def test_cwd_preflight_timeout_terminates_ssh_without_running_command(self):
        fake = FakeProcess(b"", b"", 0, block=True)
        launches = []

        async def factory(*args, **_kwargs):
            launches.append(args)
            return fake

        with patch("app.ssh_executor._spawn_ssh_command", side_effect=factory):
            result = await self.executor.execute(
                PRINCIPAL, self.f.request(argv=["touch", "must-not-run"],
                                          cwd="/home/example/repo", timeout_seconds=1))
        self.assertEqual(result.status, "timed_out")
        self.assertIsNone(result.exit_code)
        self.assertTrue(fake.killed)
        self.assertEqual(len(launches), 1)

    async def test_cwd_preflight_broken_reader_keeps_null_caller_status(self):
        from unittest.mock import AsyncMock
        fake = FakeProcess(b"partial", b"", 0)
        fake.returncode = 0
        fake.exit_status = 0
        fake.stdout.read = AsyncMock(side_effect=OSError("synthetic reader failure"))
        with patch("app.ssh_executor._spawn_ssh_command", return_value=fake) as spawn:
            result = await self.executor.execute(
                PRINCIPAL, self.f.request(cwd="/home/example/repo",
                                          argv=["touch", "must-not-run"]))
        spawn.assert_called_once()
        self.assertEqual(result.status, "transport_error")
        self.assertEqual(result.failure_kind, "execution_uncertain")
        self.assertIsNone(result.exit_code)
        self.assertIsNone(result.exit_accepted)

    async def test_preflight_deadline_expiry_prevents_session_open(self):
        import time
        with patch("app.ssh_executor._spawn_ssh_command") as spawn:
            with self.assertRaises(TimeoutError):
                await self.executor._resolve_cwd(
                    self.f.inventory()["lab"],
                    self.f.request(cwd="/home/example/repo", timeout_seconds=1),
                    time.monotonic() - 5,
                )
            result = await self.executor._run(
                self.f.inventory()["lab"],
                self.f.request(timeout_seconds=1),
                time.monotonic() - 5, None,
            )
        self.assertEqual(result.status, "timed_out")
        self.assertIsNone(result.exit_code)
        spawn.assert_not_called()

    async def test_preflight_connection_and_drain_share_one_deadline(self):
        import time
        actual_wait_for = asyncio.wait_for
        budgets = []

        async def watch(awaitable, timeout):
            budgets.append(timeout)
            return await actual_wait_for(awaitable, timeout)

        async def spawn(*_args, **_kwargs):
            await asyncio.sleep(.10)
            return FakeProcess(
                b'{"path": "/home/example/repo", "dev": 123, "ino": 456}',
                b"", 0,
            )

        with patch("app.ssh_executor._spawn_ssh_command", side_effect=spawn), patch(
            "app.ssh_executor.asyncio.wait_for", side_effect=watch,
        ):
            result = await self.executor._resolve_cwd(
                self.f.inventory()["lab"],
                self.f.request(cwd="/home/example/repo", timeout_seconds=2),
                time.monotonic(),
            )
        self.assertEqual(result, ("/home/example/repo", 123, 456))
        self.assertEqual(len(budgets), 2)
        self.assertGreater(budgets[0] - budgets[1], .08)

    async def test_whole_batch_cwd_preflight_reuses_native_status_contract(self):
        # A batch with no CWD must not open any SSH session.
        with patch("app.ssh_executor._spawn_ssh_command") as spawn:
            self.assertIsNone(await self.executor.preflight_cwd(PRINCIPAL, self.request))
            spawn.assert_not_called()

        cwd = self.f.request(cwd="/home/example/repo")
        native = FakeProcess(
            b'{"path": "/home/example/repo", "dev": 123, "ino": 456}', b"", 0,
        )
        with patch("app.ssh_executor._spawn_ssh_command", return_value=native) as spawn:
            resolved = await self.executor.preflight_cwd(PRINCIPAL, cwd)
            self.assertEqual(resolved, ("/home/example/repo", 123, 456))
            spawn.assert_called_once()

        with patch.object(self.executor, "_resolve_cwd", side_effect=TimeoutError):
            expired = await self.executor.preflight_cwd(PRINCIPAL, cwd)
        self.assertEqual(expired.status, "timed_out")
        self.assertIsNone(expired.exit_code)

    async def test_cwd_preflight_cancellation_kills_ssh_and_does_not_run_command(self):
        fake = FakeProcess(b"", b"", 0, block=True)
        launched = asyncio.Event()
        calls = []

        async def factory(*args, **_kwargs):
            calls.append(args)
            launched.set()
            return fake

        with patch("app.ssh_executor._spawn_ssh_command", side_effect=factory):
            task = asyncio.create_task(self.executor.execute(
                PRINCIPAL, self.f.request(argv=["touch", "must-not-run"],
                                          cwd="/home/example/repo")))
            await launched.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertTrue(fake.killed)
        self.assertEqual(len(calls), 1)

    async def test_cwd_preflight_nontransport_invalid_dir_stays_denied(self):
        for code in (1, 126, 127):
            launches = []

            async def denied(*args, **_kwargs):
                launches.append(args)
                return FakeProcess(b"", b"Directory unavailable", code)

            with self.subTest(code=code), patch(
                "app.ssh_executor._spawn_ssh_command", side_effect=denied
            ):
                with self.assertRaises(SSHDenied):
                    await self.executor.execute(
                        PRINCIPAL, self.f.request(cwd="/missing", argv=["touch", "/tmp/no"]))
            self.assertEqual(len(launches), 1)

    async def test_cwd_preflight_invalid_response_fails_closed(self):
        for payload in (
            b"not-json",
            b'{"path": "relative", "dev": 1, "ino": 2}',
            b'{"path": "/safe", "dev": true, "ino": 2}',
            b'{"path": "/safe", "dev": -1, "ino": 2}',
            b'{"path": "/unsafe\\nnewline", "dev": 1, "ino": 2}',
            b"a" * 5000,
        ):
            calls = []
            async def factory(*args, **_kwargs):
                calls.append(args)
                return FakeProcess(payload, b"", 0)
            with self.subTest(payload=payload[:30]), patch(
                "app.ssh_executor._spawn_ssh_command", side_effect=factory
            ):
                with self.assertRaises(SSHDenied):
                    await self.executor.execute(
                        PRINCIPAL, self.f.request(cwd="/remote/synthetic", argv=["touch", "x"]))
            self.assertEqual(len(calls), 1)

    async def test_cwd_preflight_timeout_is_not_a_command_error(self):
        with patch.object(self.executor, "_resolve_cwd", side_effect=TimeoutError), patch(
            "app.ssh_executor._spawn_ssh_command"
        ) as spawn:
            result = await self.executor.execute(PRINCIPAL, self.f.request(cwd="/slow", argv=["touch", "x"]))
        self.assertEqual(result.status, "timed_out")
        self.assertIsNone(result.exit_code)
        spawn.assert_not_called()

    async def test_bounded_incremental_output_callback(self):
        events = []

        async def capture(stream, data):
            events.append((stream, data))

        async def factory(*args, **kwargs):
            return FakeProcess(b"hello", b"warn", 0)

        with patch("app.ssh_executor._spawn_ssh_command", side_effect=factory):
            result = await self.executor.execute(PRINCIPAL, self.request, on_output=capture)

        self.assertEqual(result.status, "succeeded")
        self.assertCountEqual(events, [("stdout", b"hello"), ("stderr", b"warn")])

        events.clear()
        limited = SSHExecutor(self.f.inventory(), enabled=True, output_bytes=3)

        async def overflow_factory(*args, **kwargs):
            return FakeProcess(b"abcdef", b"", 0, block=True)

        with patch("app.ssh_executor._spawn_ssh_command", side_effect=overflow_factory):
            result = await limited.execute(PRINCIPAL, self.request, on_output=capture)
        self.assertEqual(result.status, "output_limit")
        self.assertLessEqual(sum(len(data) for _, data in events), 3)

    async def test_spawn_error_distinguished_from_command_error(self):
        async def denied(*args, **kwargs):
            raise FileNotFoundError("ssh")
        with patch("app.ssh_executor._spawn_ssh_command", side_effect=denied):
            result = await self.executor.execute(PRINCIPAL, self.request)
        self.assertEqual(result.status, "transport_error")
        self.assertIsNone(result.exit_code)

    async def test_output_cap_enforced_and_process_killed(self):
        fake = FakeProcess(b"a" * 300, b"", 0, block=True)
        async def factory(*args, **kwargs):
            return fake
        executor = SSHExecutor(self.f.inventory(), enabled=True, output_bytes=100)
        with patch("app.ssh_executor._spawn_ssh_command", side_effect=factory):
            result = await executor.execute(PRINCIPAL, self.request)
        self.assertEqual(result.status, "output_limit")
        self.assertTrue(fake.killed)
        self.assertEqual(result.stdout, "a" * 100)

    async def test_timeout_kills_process(self):
        fake = FakeProcess(b"", b"", 0, block=True)
        async def factory(*args, **kwargs):
            return fake
        with patch("app.ssh_executor._spawn_ssh_command", side_effect=factory):
            result = await self.executor.execute(PRINCIPAL, self.f.request(timeout_seconds=1))
        self.assertEqual(result.status, "timed_out")
        self.assertTrue(fake.killed)

    async def test_parallelism_per_host_is_bounded(self):
        current = 0
        max_current = 0
        async def factory(*args, **kwargs):
            nonlocal current, max_current
            current += 1
            max_current = max(max_current, current)
            await asyncio.sleep(0.02)
            current -= 1
            return FakeProcess()
        with patch("app.ssh_executor._spawn_ssh_command", side_effect=factory):
            results = await asyncio.gather(*[self.executor.execute(PRINCIPAL, self.request) for _ in range(5)])
        self.assertEqual(max_current, 1)
        self.assertTrue(all(r.status == "succeeded" for r in results))


class NativeSetupMarkerTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def stream(data: bytes) -> asyncio.StreamReader:
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        return reader

    async def test_cwd_ready_frame_is_removed_and_command_stderr_streams(self):
        nonce = "a" * 32
        ready = _framed_root_marker(_CWD_READY_PREFIX + nonce)
        failed = _framed_root_marker(_CWD_FAILED_PREFIX + nonce)
        delivered = []
        async def send(stream, data):
            delivered.append((stream, data))
        captured = bytearray()
        prepared, rejected = [False], [False]
        result = await _read_cwd_stderr(
            self.stream(b"login shell prelude" + ready + b"command diagnostics"),
            ready, failed, 100, send, [0], prepared, rejected, captured,
        )
        self.assertTrue(prepared[0])
        self.assertFalse(rejected[0])
        self.assertEqual(result, "command diagnostics")
        self.assertEqual(delivered, [("stderr", b"command diagnostics")])

    async def test_cwd_rejected_before_exec_never_releases_prefixed_output(self):
        nonce = "b" * 32
        ready = _framed_root_marker(_CWD_READY_PREFIX + nonce)
        failed = _framed_root_marker(_CWD_FAILED_PREFIX + nonce)
        prepared, rejected = [False], [False]
        delivered = []
        async def send(stream, data):
            delivered.append(data)
        result = await _read_cwd_stderr(
            self.stream(failed + b"must not surface"),
            ready, failed, 64, send, [0], prepared, rejected, bytearray(),
        )
        self.assertEqual(result, "")
        self.assertTrue(rejected[0])
        self.assertFalse(prepared[0])
        self.assertEqual(delivered, [])

    async def test_cwd_unframed_diagnostics_are_bounded(self):
        nonce = "c" * 32
        ready = _framed_root_marker(_CWD_READY_PREFIX + nonce)
        failed = _framed_root_marker(_CWD_FAILED_PREFIX + nonce)
        result = await _read_cwd_stderr(
            self.stream(b"partial startup diagnostic"), ready, failed, 100,
            None, [0], [False], [False], bytearray(),
        )
        self.assertEqual(result, "")
        with self.assertRaises(OutputLimitExceeded):
            await _read_cwd_stderr(
                self.stream(b"x" * 5000), ready, failed, 100,
                None, [0], [False], [False], bytearray(),
            )

    async def test_cwd_post_ready_output_is_bounded(self):
        nonce = "d" * 32
        ready = _framed_root_marker(_CWD_READY_PREFIX + nonce)
        failed = _framed_root_marker(_CWD_FAILED_PREFIX + nonce)
        captured = bytearray()
        with self.assertRaises(OutputLimitExceeded):
            await _read_cwd_stderr(
                self.stream(ready + b"abcde"), ready, failed, 3,
                None, [0], [False], [False], captured,
            )
        self.assertEqual(bytes(captured), b"abc")

    async def test_transport_seam_rejects_unsupported_stream_contract(self):
        with self.assertRaisesRegex(ValueError, "invocation"):
            await _spawn_ssh_command(
                "ssh", host=None, stdin=asyncio.subprocess.DEVNULL,
                stdout=0, stderr=asyncio.subprocess.PIPE,
            )
        with self.assertRaisesRegex(ValueError, "stdin"):
            await _spawn_ssh_command(
                "ssh", host=None, stdin=42,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
        class Legacy:
            pass
        self.assertEqual(_remote_exit(Legacy(), 7), 7)
        self.assertIsNone(_remote_exit(Legacy(), 255))


if __name__ == "__main__":
    unittest.main()
