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

    def stage(self, operation: str, *answers: str, host: str | None = None) -> Path:
        with patch.object(cli.getpass, "getpass", side_effect=answers) as prompts:
            candidate = cli.stage(**self.params(operation, host))
        self.assertEqual(prompts.call_count, len(answers))
        self.assertEqual(candidate.stat().st_mode & 0o777, 0o600)
        self.assertEqual(candidate.with_name(candidate.name + ".plan").stat().st_mode & 0o777, 0o600)
        return candidate

    def test_read_only_plan_does_not_make_lock(self):
        before = self.source.read_bytes()
        report = cli.plan(**self.params("sudo", "demo-node-a"))
        self.assertIn("operation=sudo", report)
        self.assertIn("aliases=2", report)
        self.assertNotIn(CONSOLE, report)
        self.assertEqual(self.source.read_bytes(), before)
        self.assertFalse((self.root / ".ssh-mcp-secrets.lock").exists())

    def test_console_rekey_is_complete_and_activated_only_with_confirmations(self):
        before = self.source.read_bytes()
        candidate = self.stage("console", CONSOLE, NEW_CONSOLE, NEW_CONSOLE)
        metadata, sealed = cli._prepared(self.source, candidate)
        self.assertEqual(self.source.read_bytes(), before)
        self.assertNotEqual(sealed["viewer_generation"], self.sealed["viewer_generation"])
        self.assertTrue(verify_password(NEW_CONSOLE, sealed["viewer_verifier"], "console-login"))
        self.assertFalse(verify_password(CONSOLE, sealed["viewer_verifier"], "console-login"))
        for alias, principal in HOSTS.items():
            self.assertEqual(
                unseal_sudo(NEW_CONSOLE, sealed["sealed_sudo"][alias], deployment="lab",
                            issuer=BIND["issuer"], alias=alias, username=principal),
                LEGACY["sudo_passwords"][alias],
            )
        with self.assertRaises(cli.RotationError):
            cli.activate(source=self.source, staged=candidate, stopped=True, recovery=False,
                         consumers=True, migration_ready=False)
        self.assertEqual(self.source.read_bytes(), before)
        checksum = cli.activate(source=self.source, staged=candidate, stopped=True,
                                recovery=True, consumers=True, migration_ready=False)
        self.assertEqual(checksum, metadata["stage_sha256"])
        self.assertEqual(cli._source(self.source)[0], sealed)
        self.assertFalse(candidate.exists())
        self.assertFalse(candidate.with_name(candidate.name + ".plan").exists())

    def test_oauth_and_metrics_rotate_independently(self):
        for mode, original, replacement in (
            ("oauth", OAUTH, NEW_OAUTH), ("metrics", METRICS, NEW_METRICS),
        ):
            with self.subTest(mode=mode):
                candidate = self.stage(mode, original, replacement, replacement)
                _, revised = cli._prepared(self.source, candidate)
                self.assertEqual(revised["sealed_sudo"], self.sealed["sealed_sudo"])
                self.assertEqual(revised["viewer_verifier"], self.sealed["viewer_verifier"])
                if mode == "oauth":
                    self.assertTrue(verify_password(replacement, revised["oauth_login_verifier"], "oauth-login"))
                    self.assertFalse(verify_password(original, revised["oauth_login_verifier"], "oauth-login"))
                else:
                    self.assertTrue(verify_token(replacement, revised["metrics_verifier"]))
                    self.assertFalse(verify_token(original, revised["metrics_verifier"]))
                cli.discard(source=self.source, staged=candidate)
                self.assertFalse(candidate.exists())

    def test_host_sudo_rotation_is_scoped_to_one_alias(self):
        candidate = self.stage("sudo", CONSOLE, NEW_SUDO, NEW_SUDO, host="demo-node-a")
        _, revised = cli._prepared(self.source, candidate)
        self.assertEqual(revised["sealed_sudo"]["demo-node-b"], self.sealed["sealed_sudo"]["demo-node-b"])
        self.assertEqual(unseal_sudo(CONSOLE, revised["sealed_sudo"]["demo-node-a"],
                                    deployment="lab", issuer=BIND["issuer"],
                                    alias="demo-node-a", username="gateway"), NEW_SUDO)

    def test_migration_does_not_expose_passwords_or_activate_without_db_gate(self):
        self.write_private(self.source, LEGACY)
        original = self.source.read_bytes()
        candidate = self.stage("migrate", CONSOLE)
        _, revised = cli._prepared(self.source, candidate)
        self.assertEqual(self.source.read_bytes(), original)
        for secret in (CONSOLE, OAUTH, METRICS, SUDO):
            self.assertNotIn(secret.encode(), candidate.read_bytes())
        with self.assertRaises(cli.RotationError):
            cli.activate(source=self.source, staged=candidate, stopped=True,
                         recovery=True, consumers=True, migration_ready=False)
        self.assertEqual(self.source.read_bytes(), original)
        cli.activate(source=self.source, staged=candidate, stopped=True,
                     recovery=True, consumers=True, migration_ready=True)
        self.assertEqual(cli._source(self.source)[0], revised)

    def test_failed_and_interrupted_preparation_never_touch_active(self):
        before = self.source.read_bytes()
        with patch.object(cli.getpass, "getpass", return_value="synthetic-wrong"):
            with self.assertRaises(ValueError):
                cli.stage(**self.params("console"))
        self.assertEqual(list(self.root.glob(".ssh-mcp-stage-*")), [])
        candidate = self.stage("console", CONSOLE, NEW_CONSOLE, NEW_CONSOLE)
        candidate.with_name(candidate.name + ".plan").unlink()
        with self.assertRaises(OSError):
            cli.activate(source=self.source, staged=candidate, stopped=True,
                         recovery=True, consumers=True, migration_ready=False)
        self.assertEqual(self.source.read_bytes(), before)

    def test_source_version_change_and_tampering_fail_closed(self):
        candidate = self.stage("metrics", METRICS, NEW_METRICS, NEW_METRICS)
        self.source.write_bytes(self.source.read_bytes() + b" ")
        with self.assertRaises(cli.RotationError):
            cli._prepared(self.source, candidate)
        self.write_private(self.source, self.sealed)
        altered = json.loads(candidate.read_text())
        altered["viewer_generation"] = "a" * 32
        self.write_private(candidate, altered)
        with self.assertRaises(cli.RotationError):
            cli._prepared(self.source, candidate)

    def test_discard_stale_stage_after_another_revision_activated(self):
        stale = self.stage("metrics", METRICS, NEW_METRICS, NEW_METRICS)
        current = self.stage("oauth", OAUTH, NEW_OAUTH, NEW_OAUTH)
        cli.activate(source=self.source, staged=current, stopped=True,
                     recovery=True, consumers=True, migration_ready=False)
        with self.assertRaises(cli.RotationError):
            cli._prepared(self.source, stale)
        self.assertTrue(stale.is_file())
        cli.discard(source=self.source, staged=stale)
        self.assertFalse(stale.exists())
        self.assertFalse(stale.with_name(stale.name + ".plan").exists())
        self.assertTrue(verify_password(NEW_OAUTH, cli._source(self.source)[0]["oauth_login_verifier"],
                                        "oauth-login"))

    def test_stale_discard_still_rejects_corrupted_stage(self):
        stale = self.stage("metrics", METRICS, NEW_METRICS, NEW_METRICS)
        current = self.stage("oauth", OAUTH, NEW_OAUTH, NEW_OAUTH)
        cli.activate(source=self.source, staged=current, stopped=True,
                     recovery=True, consumers=True, migration_ready=False)
        stale.write_bytes(stale.read_bytes() + b" ")
        with self.assertRaises(cli.RotationError):
            cli.discard(source=self.source, staged=stale)
        self.assertTrue(stale.exists())

    def test_partial_staged_file_is_removed_when_write_or_fsync_fails(self):
        original = self.source.read_bytes()
        for failure in ("write", "fsync"):
            with self.subTest(failure=failure):
                with patch.object(cli.getpass, "getpass",
                                  side_effect=(CONSOLE, NEW_CONSOLE, NEW_CONSOLE)):
                    if failure == "write":
                        real_write = cli._write_new

                        def interrupted_write(path: Path, data: bytes) -> None:
                            if path.name.endswith(".json"):
                                path.write_bytes(data[:16])  # Partial generated key material.
                                path.chmod(0o600)
                                raise OSError("synthetic interrupted stage")
                            real_write(path, data)

                        target = patch.object(cli, "_write_new", side_effect=interrupted_write)
                    else:
                        target = patch.object(cli.os, "fsync", side_effect=OSError("synthetic disk full"))
                    with target:
                        with self.assertRaises(OSError):
                            cli.stage(**self.params("console"))
                self.assertEqual(self.source.read_bytes(), original)
                self.assertEqual(list(self.root.glob(".ssh-mcp-stage-*")), [])

    def test_manifest_write_failure_removes_complete_candidate(self):
        original = self.source.read_bytes()
        real_write = cli._write_new

        def interrupted_manifest(path: Path, data: bytes) -> None:
            if path.name.endswith(".plan"):
                path.write_bytes(data[:12])
                path.chmod(0o600)
                raise OSError("synthetic interrupted manifest")
            real_write(path, data)

        with patch.object(cli.getpass, "getpass",
                          side_effect=(CONSOLE, NEW_CONSOLE, NEW_CONSOLE)):
            with patch.object(cli, "_write_new", side_effect=interrupted_manifest):
                with self.assertRaises(OSError):
                    cli.stage(**self.params("console"))
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(list(self.root.glob(".ssh-mcp-stage-*")), [])

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
                cli.stage(**self.params("oauth"))
        with patch.object(cli.getpass, "getpass", side_effect=(CONSOLE, CONSOLE, CONSOLE)):
            with self.assertRaises(cli.RotationError):
                cli.stage(**self.params("sudo", "demo-node-a"))
        with patch.object(cli.getpass, "getpass", side_effect=(METRICS, METRICS, METRICS)):
            with self.assertRaises(cli.RotationError):
                cli.stage(**self.params("metrics"))
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
                "stage", "--source", str(self.source), "--inventory", str(self.inventory),
                "--deployment", "lab", "--issuer", BIND["issuer"],
                "--operation", "console",
            ]), 1)
        prompt.assert_not_called()
        self.assertIn("rejected", output.getvalue())
        self.assertEqual(list(self.root.glob(".ssh-mcp-stage-*")), [])

    def test_uncertain_activation_after_successful_rename_never_blindly_retries(self):
        candidate = self.stage("console", CONSOLE, NEW_CONSOLE, NEW_CONSOLE)
        source_before = self.source.read_bytes()
        with patch.object(cli, "_sync", side_effect=OSError("synthetic I/O interruption")):
            with self.assertRaises(cli.ActivationUncertain):
                cli.activate(source=self.source, staged=candidate, stopped=True,
                             recovery=True, consumers=True, migration_ready=False)
        self.assertNotEqual(source_before, self.source.read_bytes())
        self.assertFalse(candidate.exists())
        self.assertTrue(candidate.with_name(candidate.name + ".plan").exists())
        with self.assertRaises(OSError):
            cli._prepared(self.source, candidate)

    def test_cli_verify_no_credentials_or_implicit_activation(self):
        candidate = self.stage("console", CONSOLE, NEW_CONSOLE, NEW_CONSOLE)
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(cli.main(["verify", "--source", str(self.source),
                                       "--staged", str(candidate)]), 0)
            self.assertEqual(cli.main(["activate", "--source", str(self.source),
                                       "--staged", str(candidate)]), 1)
        self.assertIn("VERIFY=PASS", output.getvalue())
        self.assertNotIn(CONSOLE, output.getvalue() + errors.getvalue())
        self.assertNotIn(NEW_CONSOLE, output.getvalue() + errors.getvalue())
        self.assertTrue(candidate.exists())

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
            cli.stage(**self.params("console"))

    def test_invalid_json_and_unsigned_inventory_are_rejected(self):
        for raw in (b'{"version":1,"version":1}', b'[]'):
            with self.subTest(raw=raw):
                with self.assertRaises(cli.RotationError):
                    cli._decode(raw)
        self.write_private(self.source, {"version": 99})
        with self.assertRaises(cli.RotationError):
            cli._source(self.source)
        self.write_private(self.source, self.sealed)
        for hosts in (None, [], ["not-object"],
                      [{"alias": "Invalid!", "username": "gateway"}],
                      [{"alias": "demo-node-a", "username": "Invalid!"}]):
            with self.subTest(hosts=hosts):
                self.inventory.write_text(json.dumps({"version": 1, "hosts": hosts}))
                with self.assertRaises(cli.RotationError):
                    cli._hosts(self.inventory)
        self.inventory.write_text(json.dumps({"version": 2, "hosts": []}))
        with self.assertRaises(cli.RotationError):
            cli._hosts(self.inventory)

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
        with self.assertRaises(cli.RotationError):
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
                        cli.stage(**self.params(operation))
        with patch.object(cli.getpass, "getpass",
                          side_effect=(CONSOLE, NEW_CONSOLE, "different-confirmation")):
            with self.assertRaises(cli.RotationError):
                cli.stage(**self.params("console"))
        self.assertEqual(self.source.read_bytes(), before)
        self.assertEqual(list(self.root.glob(".ssh-mcp-stage-*")), [])

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
                    cli.stage(**self.params("oauth"))
        self.assertEqual(self.source.read_bytes(), before)
        self.assertEqual(list(self.root.glob(".ssh-mcp-stage-*")), [])

    def test_prepared_stage_rejects_foreign_path_and_invalid_manifest(self):
        candidate = self.stage("metrics", METRICS, NEW_METRICS, NEW_METRICS)
        bad = self.root / "wrong-name.json"
        with self.assertRaises(cli.RotationError):
            cli._prepared(self.source, bad)
        sidecar = candidate.with_name(candidate.name + ".plan")
        manifest = json.loads(sidecar.read_text())
        manifest["unexpected_key"] = True
        self.write_private(sidecar, manifest)
        with self.assertRaises(cli.RotationError):
            cli._prepared(self.source, candidate)

    def test_cli_plan_stage_activate_and_discard_dispatch(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(cli.main([
                "plan", "--source", str(self.source), "--inventory", str(self.inventory),
                "--deployment", "lab", "--issuer", BIND["issuer"],
                "--operation", "console",
            ]), 0)
        self.assertIn("PLAN=PASS", output.getvalue())
        with patch.object(cli.sys, "stdin") as stdin, patch.object(cli.sys, "stderr") as stderr:
            stdin.isatty.return_value = True
            stderr.isatty.return_value = True
            with patch.object(cli.getpass, "getpass",
                              side_effect=(CONSOLE, NEW_CONSOLE, NEW_CONSOLE)):
                with redirect_stdout(output):
                    self.assertEqual(cli.main([
                        "stage", "--source", str(self.source), "--inventory", str(self.inventory),
                        "--deployment", "lab", "--issuer", BIND["issuer"],
                        "--operation", "console",
                    ]), 0)
        self.assertIn("STAGE=PASS", output.getvalue())
        stages = list(self.root.glob(".ssh-mcp-stage-*.json"))
        self.assertEqual(len(stages), 1)
        with redirect_stdout(output):
            self.assertEqual(cli.main([
                "activate", "--source", str(self.source), "--staged", str(stages[0]),
                "--confirm-stopped", "--confirm-recovery", "--confirm-consumers-ready",
            ]), 0)
        self.assertIn("ACTIVATE=PASS", output.getvalue())
        with patch.object(cli, "activate", side_effect=cli.ActivationUncertain("synthetic")):
            with redirect_stderr(io.StringIO()) as error:
                self.assertEqual(cli.main([
                    "activate", "--source", str(self.source), "--staged", str(stages[0]),
                    "--confirm-stopped", "--confirm-recovery", "--confirm-consumers-ready",
                ]), 2)
            self.assertIn("uncertain", error.getvalue())
        # Exercise discard dispatch using a valid stage pinned to a separate new revision.
        fresh = self.stage("metrics", METRICS, NEW_METRICS, NEW_METRICS)
        with redirect_stdout(output):
            self.assertEqual(cli.main([
                "discard", "--source", str(self.source), "--staged", str(fresh),
            ]), 0)
        self.assertIn("DISCARD=PASS", output.getvalue())

if __name__ == "__main__":
    unittest.main()
