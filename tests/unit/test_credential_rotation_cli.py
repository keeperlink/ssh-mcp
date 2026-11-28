"""Offline synthetic tests for the operator-only sealed credential utility."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.sealed_credentials import from_legacy, unseal_sudo, verify_password, verify_token
from ssh_mcp_secrets import cli

CONSOLE = "synthetic-console-password-for-unit-tests"
NEW_CONSOLE = "synthetic-replacement-console-password"
OAUTH = "synthetic-oauth-credential-" + "a" * 36
NEW_OAUTH = "synthetic-new-oauth-credential-" + "b" * 36
METRICS = "synthetic-metrics-bearer-" + "c" * 36
NEW_METRICS = "synthetic-new-metrics-bearer-" + "d" * 36
SUDO = "synthetic-sudo-credential"
NEW_SUDO = "synthetic-rotated-sudo-credential"
HOSTS = {"demo-node-a": "gateway", "demo-node-b": "gateway"}
BIND = {"deployment": "lab", "issuer": "https://testing.example.org"}
LEGACY = {
    "version": 1, "oauth_login_key": OAUTH,
    "oauth_signing_key": "synthetic-signing-" + "e" * 40,
    "viewer_password": CONSOLE, "metrics_token": METRICS,
    "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
                       "a" * 96 + "\n-----END OPENSSH PRIVATE KEY-----",
    "sudo_passwords": {"demo-node-a": SUDO, "demo-node-b": SUDO + "-b"},
}


class OperatorRotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sealed = from_legacy(LEGACY, console_password=CONSOLE, hosts=HOSTS, **BIND)

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory(prefix="synthetic-rekey-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.root.chmod(0o700)
        self.source = self.root / "ssh-mcp-secrets"
        self.inventory = self.root / "inventory.json"
        self.write_private(self.source, self.sealed)
        self.inventory.write_text(json.dumps({
            "version": 1,
            "hosts": [{"alias": alias, "username": principal}
                      for alias, principal in HOSTS.items()],
        }))
        self.inventory.chmod(0o644)

    @staticmethod
    def write_private(path: Path, data: object) -> None:
        path.write_text(json.dumps(data, sort_keys=True) + "\n")
        path.chmod(0o600)

    def params(self, operation: str = "console", host: str | None = None) -> dict:
        return {"source": self.source, "inventory": self.inventory,
                "operation": operation, "host": host, **BIND}

    def commit(self, operation: str, *answers: str, host: str | None = None) -> dict:
        with patch.object(cli.getpass, "getpass", side_effect=answers) as prompts:
            digest = cli.apply(**self.params(operation, host))
        self.assertEqual(prompts.call_count, len(answers))
        self.assertEqual(digest, cli._digest(self.source.read_bytes()))
        self.assertEqual(self.source.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.root.glob(".ssh-mcp-commit-*")), [])
        return cli._source(self.source)[0]

    def test_committed_credentials_are_pretty_printed(self):
        sealed = self.commit("metrics", METRICS, NEW_METRICS, NEW_METRICS)
        self.assertEqual(self.source.read_text(), json.dumps(sealed, sort_keys=True, indent=2) + "\n")
        self.assertGreater(len(self.source.read_text().splitlines()), 8)
        self.assertEqual(set(p.name for p in self.root.iterdir()),
                         {"ssh-mcp-secrets", "inventory.json", ".ssh-mcp-secrets.lock"})

    def test_read_only_plan_does_not_make_lock(self):
        before = self.source.read_bytes()
        report = cli.plan(**self.params("sudo", "demo-node-a"))
        self.assertIn("operation=sudo", report)
        self.assertIn("aliases=2", report)
        self.assertNotIn(CONSOLE, report)
        self.assertEqual(self.source.read_bytes(), before)
        self.assertFalse((self.root / ".ssh-mcp-secrets.lock").exists())

    def test_console_rekey_is_complete_and_preserves_other_credentials(self):
        sealed = self.commit("console", CONSOLE, NEW_CONSOLE, NEW_CONSOLE)
        self.assertNotEqual(sealed["viewer_generation"], self.sealed["viewer_generation"])
        self.assertTrue(verify_password(NEW_CONSOLE, sealed["viewer_verifier"], "console-login"))
        self.assertFalse(verify_password(CONSOLE, sealed["viewer_verifier"], "console-login"))
        for alias, principal in HOSTS.items():
            self.assertEqual(
                unseal_sudo(NEW_CONSOLE, sealed["sealed_sudo"][alias], deployment="lab",
                            issuer=BIND["issuer"], alias=alias, username=principal),
                LEGACY["sudo_passwords"][alias],
            )
        for key in ("oauth_login_verifier", "metrics_verifier", "oauth_signing_key", "ssh_private_key"):
            self.assertEqual(sealed[key], self.sealed[key])

    def test_oauth_and_metrics_rotate_independently(self):
        for mode, original, replacement, key in (
            ("oauth", OAUTH, NEW_OAUTH, "oauth_login_verifier"),
            ("metrics", METRICS, NEW_METRICS, "metrics_verifier"),
        ):
            with self.subTest(mode=mode):
                before = cli._source(self.source)[0]
                revised = self.commit(mode, original, replacement, replacement)
                self.assertEqual({k:v for k,v in revised.items() if k != key},
                                 {k:v for k,v in before.items() if k != key})
                if mode == "oauth":
                    self.assertTrue(verify_password(replacement, revised[key], "oauth-login"))
                    self.assertFalse(verify_password(original, revised[key], "oauth-login"))
                else:
                    self.assertTrue(verify_token(replacement, revised[key]))
                    self.assertFalse(verify_token(original, revised[key]))

    def test_host_sudo_rotation_is_scoped_to_one_alias(self):
        revised = self.commit("sudo", CONSOLE, NEW_SUDO, NEW_SUDO, host="demo-node-a")
        self.assertEqual(revised["sealed_sudo"]["demo-node-b"], self.sealed["sealed_sudo"]["demo-node-b"])
        self.assertEqual(unseal_sudo(CONSOLE, revised["sealed_sudo"]["demo-node-a"],
                                    deployment="lab", issuer=BIND["issuer"],
                                    alias="demo-node-a", username="gateway"), NEW_SUDO)

    def enrollment_inventory(self, policy: str = "restricted") -> None:
        inventory = json.loads(self.inventory.read_text())
        inventory["hosts"].append({
            "alias": "demo-node-c", "username": "builder", "privileged_access": policy,
        })
        self.inventory.write_text(json.dumps(inventory))

    def test_add_sudo_exactly_one_envelope_and_commit(self):
        self.enrollment_inventory()
        self.assertIn("operation=add-sudo", cli.plan(**self.params("add-sudo", "demo-node-c")))
        self.assertFalse((self.root / ".ssh-mcp-secrets.lock").exists())
        revised = self.commit("add-sudo", CONSOLE, NEW_SUDO, NEW_SUDO, host="demo-node-c")
        envelope = revised["sealed_sudo"].pop("demo-node-c")
        self.assertEqual(revised, self.sealed)
        self.assertEqual(unseal_sudo(CONSOLE, envelope, **BIND,
                                    alias="demo-node-c", username="builder"), NEW_SUDO)
        for binding in (dict(BIND, deployment="production"),
                        dict(BIND, issuer="https://different.example.org")):
            with self.assertRaises(ValueError):
                unseal_sudo(CONSOLE, envelope, **binding,
                            alias="demo-node-c", username="builder")
        for alias, username in (("demo-node-a", "builder"), ("demo-node-c", "gateway")):
            with self.assertRaises(ValueError):
                unseal_sudo(CONSOLE, envelope, **BIND, alias=alias, username=username)
        self.assertNotIn(NEW_SUDO.encode(), self.source.read_bytes())
        self.assertEqual(cli._source(self.source)[0]["sealed_sudo"]["demo-node-c"], envelope)
        with self.assertRaises(cli.RotationError):
            cli.plan(**self.params("add-sudo", "demo-node-c"))
        self.assertIn("PLAN=PASS", cli.plan(**self.params("sudo", "demo-node-c")))

    def test_add_sudo_rejects_ineligible_targets_and_existing_alias(self):
        for policy in ("none", "invalid"):
            with self.subTest(policy=policy):
                self.enrollment_inventory(policy)
                with self.assertRaises(cli.RotationError):
                    cli.plan(**self.params("add-sudo", "demo-node-c"))
                data = json.loads(self.inventory.read_text())
                data["hosts"].pop()
                self.inventory.write_text(json.dumps(data))
        self.enrollment_inventory()
        data = json.loads(self.inventory.read_text())
        data["hosts"][0]["privileged_access"] = "restricted"
        self.inventory.write_text(json.dumps(data))
        for operation, host in (("add-sudo", "demo-node-a"), ("add-sudo", "unknown"),
                                ("add-sudo", None), ("sudo", "demo-node-c"),
                                ("add-sudo", "demo-node-b")):
            with self.subTest(operation=operation, host=host):
                with self.assertRaises(cli.RotationError):
                    cli.plan(**self.params(operation, host))
        with self.assertRaises(cli.RotationError):
            cli.plan(**dict(self.params("add-sudo", "demo-node-c"), inventory=Path("relative")))
        self.inventory.chmod(0o666)
        with self.assertRaises(cli.RotationError):
            cli.plan(**self.params("add-sudo", "demo-node-c"))
        self.assertEqual(cli._source(self.source)[0], self.sealed)

    def test_add_sudo_invalid_passwords_and_binding_leave_source_intact(self):
        self.enrollment_inventory()
        before = self.source.read_bytes()
        for answers in (("wrong-console", NEW_SUDO, NEW_SUDO),
                        (CONSOLE, NEW_SUDO, "mismatch"),
                        (CONSOLE, CONSOLE, CONSOLE),
                        (CONSOLE, OAUTH, OAUTH),
                        (CONSOLE, METRICS, METRICS),
                        (CONSOLE, "", "")):
            with self.subTest(case=answers[0] == CONSOLE):
                with patch.object(cli.getpass, "getpass", side_effect=answers):
                    with self.assertRaises(ValueError):
                        cli.apply(**self.params("add-sudo", "demo-node-c"))
        for binding in ({"deployment": "production"}, {"issuer": "https://wrong.example.org"}):
            with patch.object(cli.getpass, "getpass", side_effect=(CONSOLE, NEW_SUDO, NEW_SUDO)):
                with self.assertRaises(ValueError):
                    cli.apply(**(self.params("add-sudo", "demo-node-c") | binding))
        self.assertEqual(self.source.read_bytes(), before)
        self.assertEqual(list(self.root.glob(".ssh-mcp-commit-*")), [])

    def test_add_sudo_rejects_inventory_drift_during_apply(self):
        self.enrollment_inventory()
        answers = iter((CONSOLE, NEW_SUDO, NEW_SUDO))

        def prompt(*_args):
            self.inventory.write_bytes(self.inventory.read_bytes() + b" ")
            return next(answers)

        with patch.object(cli.getpass, "getpass", side_effect=prompt):
            with self.assertRaises(cli.RotationError):
                cli.apply(**self.params("add-sudo", "demo-node-c"))
        self.assertEqual(cli._source(self.source)[0], self.sealed)
        self.assertEqual(list(self.root.glob(".ssh-mcp-commit-*")), [])

    def test_add_sudo_to_initial_empty_mapping(self):
        self.enrollment_inventory("always-granted")
        self.write_private(self.source, dict(self.sealed, sealed_sudo={}))
        revised = self.commit("add-sudo", CONSOLE, NEW_SUDO, NEW_SUDO, host="demo-node-c")
        self.assertEqual(set(revised["sealed_sudo"]), {"demo-node-c"})

    def test_legacy_source_is_refused_without_mutation(self):
        self.write_private(self.source, LEGACY)
        before = self.source.read_bytes()
        with self.assertRaises(ValueError), patch.object(cli.getpass, "getpass") as prompt:
            cli.apply(**self.params())
        prompt.assert_not_called()
        self.assertEqual(self.source.read_bytes(), before)

    def test_precommit_failures_leave_source_and_remove_owned_temp(self):
        before = self.source.read_bytes()
        for method in ("fsync", "replace"):
            with self.subTest(method=method):
                with patch.object(cli.os, method, side_effect=OSError("synthetic failure")), \
                     patch.object(cli.getpass, "getpass", side_effect=(METRICS, NEW_METRICS, NEW_METRICS)):
                    with self.assertRaises(OSError):
                        cli.apply(**self.params("metrics"))
                self.assertEqual(self.source.read_bytes(), before)
                self.assertEqual(list(self.root.glob(".ssh-mcp-commit-*")), [])

    def test_concurrent_writer_is_refused_before_prompt(self):
        before = self.source.read_bytes()
        with cli._locked(self.source), patch.object(cli.getpass, "getpass") as prompt:
            with self.assertRaises(BlockingIOError):
                cli.apply(**self.params("metrics"))
        prompt.assert_not_called()
        self.assertEqual(self.source.read_bytes(), before)

    def test_candidate_collision_is_not_removed(self):
        name = self.root / (cli._TEMP_PREFIX + "a" * 24)
        name.write_bytes(b"synthetic-existing-artifact")
        name.chmod(0o600)
        with patch.object(cli.secrets, "token_hex", return_value="a" * 24), \
             patch.object(cli.getpass, "getpass", side_effect=(METRICS, NEW_METRICS, NEW_METRICS)):
            with self.assertRaises(FileExistsError):
                cli.apply(**self.params("metrics"))
        self.assertEqual(name.read_bytes(), b"synthetic-existing-artifact")

    def test_private_file_permissions_symlinks_and_unknown_alias(self):
        self.source.chmod(0o644)
        with self.assertRaises(cli.RotationError):
            cli.plan(**self.params())
        self.source.chmod(0o600)
        with self.assertRaises(cli.RotationError):
            cli.plan(**self.params("sudo", "not-signed"))
        saved = self.root / "saved"
        saved.write_bytes(self.source.read_bytes())
        saved.chmod(0o600)
        self.source.unlink()
        self.source.symlink_to(saved)
        with self.assertRaises(OSError):
            cli.plan(**self.params())

    def test_reused_passwords_and_untrusted_production_binding_fail(self):
        with patch.object(cli.getpass, "getpass", side_effect=(OAUTH, OAUTH, OAUTH)):
            with self.assertRaises(cli.RotationError):
                cli.apply(**self.params("oauth"))
        with patch.object(cli.getpass, "getpass", side_effect=(CONSOLE, CONSOLE, CONSOLE)):
            with self.assertRaises(cli.RotationError):
                cli.apply(**self.params("sudo", "demo-node-a"))
        with patch.object(cli.getpass, "getpass", side_effect=(METRICS, METRICS, METRICS)):
            with self.assertRaises(cli.RotationError):
                cli.apply(**self.params("metrics"))
        with self.assertRaises(cli.RotationError):
            cli.plan(**{**self.params(), "deployment": "production",
                        "issuer": "http://not-a-trusted-issuer.example"})
        self.assertEqual(cli._source(self.source)[0], self.sealed)

    def test_binding_rejects_noncanonical_issuers_before_sealing(self):
        for issuer in (
            "https://testing.example.org/", "https://testing.example.org/mcp",
            "https://testing.example.org/?x=1", "https://testing.example.org/#frag",
            "https://alice@testing.example.org", "https://testing.example.org  ",
            "https://127.0.0.1", "http://testing.example.org",
        ):
            with self.subTest(issuer=issuer):
                with self.assertRaises(cli.RotationError):
                    cli.plan(**{**self.params(), "issuer": issuer})
        self.assertIn("PLAN=PASS", cli.plan(**self.params()))
        self.assertIn("PLAN=PASS", cli.plan(**{**self.params(), "issuer": "http://localhost"}))
        with self.assertRaises(cli.RotationError):
            cli.plan(**{**self.params(), "deployment": "production", "issuer": "http://localhost"})

    def test_cli_cannot_accept_credentials_without_real_terminal(self):
        output = io.StringIO()
        with redirect_stderr(output), patch.object(cli.getpass, "getpass") as prompt:
            self.assertEqual(cli.main([
                "apply", "--source", str(self.source), "--inventory", str(self.inventory),
                "--deployment", "lab", "--issuer", BIND["issuer"],
                "--operation", "console",
            ]), 1)
        prompt.assert_not_called()
        self.assertIn("rejected", output.getvalue())
        self.assertEqual(list(self.root.glob(".ssh-mcp-commit-*")), [])

    def test_uncertain_commit_after_rename(self):
        before = self.source.read_bytes()
        with patch.object(cli.getpass, "getpass", side_effect=(METRICS, NEW_METRICS, NEW_METRICS)), \
             patch.object(cli, "_sync", side_effect=OSError("synthetic I/O interruption")):
            with self.assertRaises(cli.CommitUncertain) as failure:
                cli.apply(**self.params("metrics"))
        self.assertNotEqual(before, self.source.read_bytes())
        self.assertEqual(failure.exception.expected_digest, cli._digest(self.source.read_bytes()))
        self.assertEqual(list(self.root.glob(".ssh-mcp-commit-*")), [])

    def test_rename_then_signal_reports_uncertain(self):
        replace = cli.os.replace
        def interrupted(src, dst):
            replace(src, dst)
            raise KeyboardInterrupt()
        with patch.object(cli.getpass, "getpass", side_effect=(METRICS, NEW_METRICS, NEW_METRICS)), \
             patch.object(cli.os, "replace", side_effect=interrupted):
            with self.assertRaises(cli.CommitUncertain) as failure:
                cli.apply(**self.params("metrics"))
        self.assertEqual(failure.exception.expected_digest, cli._digest(self.source.read_bytes()))

    def test_rejects_untrusted_directories_and_lock(self):
        with self.assertRaises(cli.RotationError):
            cli._private_dir(Path("relative"))
        symlink = self.root / "linked"
        symlink.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(cli.RotationError):
            cli._private_dir(symlink)
        self.root.chmod(0o750)
        with self.assertRaises(cli.RotationError):
            cli._private_dir(self.root)
        self.root.chmod(0o700)
        lock = self.root / ".ssh-mcp-secrets.lock"
        lock.write_bytes(b"lock")
        lock.chmod(0o644)
        with self.assertRaises(cli.RotationError):
            cli.apply(**self.params("console"))

    def test_invalid_json_and_unsigned_inventory_are_rejected(self):
        for raw in (b'{"version":1,"version":1}', b'[]'):
            with self.subTest(raw=raw):
                with self.assertRaises(cli.RotationError):
                    cli._decode(raw)
        self.write_private(self.source, {"version": 99})
        with self.assertRaises(ValueError):
            cli._source(self.source)
        self.write_private(self.source, self.sealed)
        for hosts in (None, [], ["not-object"],
                      [{"alias": "Invalid!", "username": "gateway"}],
                      [{"alias": "demo-node-a", "username": "Invalid!"}]):
            with self.subTest(hosts=hosts):
                self.inventory.write_text(json.dumps({"version": 1, "hosts": hosts}))
                with self.assertRaises(cli.RotationError):
                    cli._read_inventory(self.inventory, 'console', None)
        self.inventory.write_text(json.dumps({"version": 2, "hosts": []}))
        with self.assertRaises(cli.RotationError):
            cli._read_inventory(self.inventory, 'console', None)

    def test_invalid_operation_or_unsigned_host_denied(self):
        for operation, host in (("console", "demo-node-a"),
                                ("sudo", None), ("undefined", None),
                                ("migrate", None), ("sudo", "demo-node-c")):
            with self.subTest(operation=operation, host=host):
                with self.assertRaises(cli.RotationError):
                    cli.plan(**self.params(operation, host))
        self.write_private(self.source, LEGACY)
        altered = dict(LEGACY, sudo_passwords={"unapproved": SUDO})
        self.write_private(self.source, altered)
        with self.assertRaises(ValueError):
            cli.plan(**self.params("migrate"))
        self.write_private(self.source, self.sealed)
        revised = dict(self.sealed, sealed_sudo={
            **self.sealed["sealed_sudo"], "unapproved": self.sealed["sealed_sudo"]["demo-node-a"]
        })
        self.write_private(self.source, revised)
        with self.assertRaises(cli.RotationError):
            cli.plan(**self.params())

    def test_invalid_old_credentials_and_confirmations_preserve_source(self):
        before = self.source.read_bytes()
        for operation in ("oauth", "metrics"):
            with self.subTest(operation=operation):
                with patch.object(cli.getpass, "getpass", return_value="wrong-old-credential"):
                    with self.assertRaises(cli.RotationError):
                        cli.apply(**self.params(operation))
        with patch.object(cli.getpass, "getpass",
                          side_effect=(CONSOLE, NEW_CONSOLE, "different-confirmation")):
            with self.assertRaises(cli.RotationError):
                cli.apply(**self.params("console"))
        self.assertEqual(self.source.read_bytes(), before)
        self.assertEqual(list(self.root.glob(".ssh-mcp-commit-*")), [])

    def test_source_changed_during_rekey_is_rejected_before_staging(self):
        before = self.source.read_bytes()
        real_source = cli._source
        calls = 0

        def changed(path: Path):
            nonlocal calls
            calls += 1
            value, digest = real_source(path)
            return value, digest if calls == 1 else "0" * 64

        with patch.object(cli, "_source", side_effect=changed):
            with patch.object(cli.getpass, "getpass",
                              side_effect=(OAUTH, NEW_OAUTH, NEW_OAUTH)):
                with self.assertRaises(cli.RotationError):
                    cli.apply(**self.params("oauth"))
        self.assertEqual(self.source.read_bytes(), before)
        self.assertEqual(list(self.root.glob(".ssh-mcp-commit-*")), [])

    def test_cli_plan_apply_and_uncertain_dispatch(self):
        output = io.StringIO()
        args = ["--source", str(self.source), "--inventory", str(self.inventory),
                "--deployment", "lab", "--issuer", BIND["issuer"], "--operation", "metrics"]
        with redirect_stdout(output):
            self.assertEqual(cli.main(["plan", *args]), 0)
        self.assertIn("PLAN=PASS", output.getvalue())
        with patch.object(cli.sys.stdin, "isatty", return_value=True), \
             patch.object(cli.sys.stderr, "isatty", return_value=True), \
             patch.object(cli.getpass, "getpass", side_effect=(METRICS, NEW_METRICS, NEW_METRICS)), \
             redirect_stdout(output):
            self.assertEqual(cli.main(["apply", *args]), 0)
        self.assertIn("APPLY=PASS", output.getvalue())
        with redirect_stderr(io.StringIO()) as err, \
             patch.object(cli.sys.stdin, "isatty", return_value=True), \
             patch.object(cli.sys.stderr, "isatty", return_value=True), \
             patch.object(cli, "apply", side_effect=cli.CommitUncertain("synthetic", expected_digest="a"*64)):
            self.assertEqual(cli.main(["apply", *args]), 2)
        self.assertIn("uncertain", err.getvalue())
        self.assertIn("expected_committed_sha256=" + "a"*64, err.getvalue())
        for removed in ("stage", "verify", "activate", "discard"):
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                cli.main([removed, *args])
        self.assertNotIn(NEW_METRICS, output.getvalue())

    def test_stale_expected_digests_rejected_before_prompt(self):
        for key in ("expected_source", "expected_inventory"):
            with self.subTest(key=key), patch.object(cli.getpass, "getpass") as prompt:
                with self.assertRaises(cli.RotationError):
                    cli.apply(**self.params("metrics"), **{key: "a"*64})
                prompt.assert_not_called()

    def test_hardlink_rejected(self):
        import os
        other = self.root / "linked-secret"
        os.link(self.source, other)
        with self.assertRaises(cli.RotationError):
            cli.plan(**self.params())

    def test_jenkins_target_commit_and_controller_readback(self):
        from ssh_mcp_secrets import batch
        directory = self.root / "deployment" / "nonprod"
        directory.mkdir(parents=True)
        self.source = self.source.rename(directory / self.source.name)
        before = self.source.read_bytes()
        self.source.chmod(0o640)
        args = dict(self.params("metrics"), jenkins=True,
                    expected_source=cli._digest(before),
                    expected_inventory=cli._digest(self.inventory.read_bytes()),
                    container="synthetic-controller",
                    container_file="/run/jenkins/secrets/deployment/nonprod/ssh-mcp-secrets")
        with patch.object(cli.os, "geteuid", return_value=0), \
             patch.object(cli.os, "fchown"), \
             patch.object(batch, "_check_jenkins_dir_info"), \
             patch.object(batch, "_trusted_jenkins", side_effect=lambda path: path.read_bytes()), \
             patch.object(cli, "_read_file", side_effect=lambda path, **kw: path.read_bytes()), \
             patch.object(batch, "_postcheck_container") as postcheck, \
             patch.object(cli.getpass, "getpass", side_effect=(METRICS, NEW_METRICS, NEW_METRICS)):
            self.assertIn("PLAN=PASS", cli.plan(**args))
            digest = cli.apply(**args)
        self.assertEqual(self.source.stat().st_mode & 0o777, 0o640)
        self.assertEqual(cli._digest(self.source.read_bytes()), digest)
        self.assertTrue(verify_token(NEW_METRICS, json.loads(self.source.read_text())["metrics_verifier"]))
        postcheck.assert_called_once_with(args["container"], args["container_file"], digest, "nonprod/" + self.source.name)
        self.assertEqual([p.name for p in self.source.parent.iterdir()], [self.source.name])
        self.assertEqual([p.name for p in directory.parent.iterdir()], ["nonprod"])

    def test_jenkins_lock_shared_across_flat_and_scoped_sources(self):
        from ssh_mcp_secrets import batch
        directory = self.root / "deployment"
        directory.mkdir()
        flat = self.source.rename(directory / self.source.name)
        scope = directory / "nonprod"
        scope.mkdir()
        scoped = scope / flat.name
        self.write_private(scoped, self.sealed)
        with patch.object(batch, "_trusted_jenkins", return_value=flat.read_bytes()), \
             patch.object(batch, "_check_jenkins_dir_info"):
            with cli._locked(flat, jenkins=True):
                with self.assertRaises(BlockingIOError), cli._locked(scoped, jenkins=True):
                    self.fail("Unexpected concurrent writer")
            with cli._locked(scoped, jenkins=True):
                with self.assertRaises(BlockingIOError), cli._locked(flat, jenkins=True):
                    self.fail("Unexpected concurrent writer")
        self.assertEqual(set(p.name for p in directory.iterdir()), {flat.name, "nonprod"})
        self.assertEqual([p.name for p in scope.iterdir()], [scoped.name])

    def test_jenkins_target_requires_explicit_pins_and_mount(self):
        args = self.params("metrics")
        with patch.object(cli.getpass, "getpass") as prompt:
            with self.assertRaises(cli.RotationError):
                cli.apply(**args, jenkins=True)
            with self.assertRaises(cli.RotationError):
                cli.apply(**args, container="synthetic-controller")
            with self.assertRaises(cli.RotationError):
                cli.apply(**args, expected_source="bad")
            prompt.assert_not_called()
        with patch.object(cli.os, "geteuid", return_value=0):
            with self.assertRaises(cli.RotationError):
                cli.apply(**args, jenkins=True, container="synthetic-controller",
                          container_file="/run/jenkins/secrets/deployment/ssh-mcp-secrets")

    def test_jenkins_controller_failure_reports_expected_digest(self):
        from ssh_mcp_secrets import batch
        directory = self.root / "deployment"
        directory.mkdir()
        self.source = self.source.rename(directory / self.source.name)
        before = self.source.read_bytes()
        self.source.chmod(0o640)
        args = dict(self.params("metrics"), jenkins=True,
                    expected_source=cli._digest(before),
                    expected_inventory=cli._digest(self.inventory.read_bytes()),
                    container="synthetic-controller",
                    container_file="/run/jenkins/secrets/deployment/ssh-mcp-secrets")
        with patch.object(cli.os, "geteuid", return_value=0), \
             patch.object(cli.os, "fchown"), \
             patch.object(batch, "_check_jenkins_dir_info"), \
             patch.object(batch, "_trusted_jenkins", side_effect=lambda path: path.read_bytes()), \
             patch.object(cli, "_read_file", side_effect=lambda path, **kw: path.read_bytes()), \
             patch.object(batch, "_postcheck_container", side_effect=OSError("synthetic readback failure")), \
             patch.object(cli.getpass, "getpass", side_effect=(METRICS, NEW_METRICS, NEW_METRICS)):
            with self.assertRaises(cli.CommitUncertain) as failure:
                cli.apply(**args)
        self.assertNotEqual(before, self.source.read_bytes())
        self.assertEqual(failure.exception.expected_digest, cli._digest(self.source.read_bytes()))
        self.assertEqual(list(self.root.glob(".ssh-mcp-commit-*")), [])

    def test_precommit_candidate_tampering_detected(self):
        before = self.source.read_bytes()
        read = cli._read_file
        def altered(path, **kw):
            raw = read(path, **kw)
            if path.name.startswith(cli._TEMP_PREFIX):
                return raw + b" "
            return raw
        with patch.object(cli, "_read_file", side_effect=altered), \
             patch.object(cli.getpass, "getpass", side_effect=(METRICS, NEW_METRICS, NEW_METRICS)):
            with self.assertRaises(cli.RotationError):
                cli.apply(**self.params("metrics"))
        self.assertEqual(before, self.source.read_bytes())
        self.assertEqual(list(self.root.glob(".ssh-mcp-commit-*")), [])

if __name__ == "__main__":
    unittest.main()
