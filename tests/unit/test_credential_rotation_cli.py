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


if __name__ == "__main__":
    unittest.main()
