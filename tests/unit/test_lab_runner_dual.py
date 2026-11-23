"""Offline-only regressions for opt-in isolated two-host transfer acceptance.

All Docker, sudo and Git behavior is mocked. Never touches an actual lab.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from app.sealed_credentials import unseal_sudo, validate_v2_secrets
from tests.lab import runner, sealed_fixture
from tests.unit.test_lab_runner import RUN, SHA, local_state, state_for


class DualHostFixtureTests(unittest.TestCase):
    def test_fixture_image_cannot_bake_shared_ssh_host_private_keys(self) -> None:
        dockerfile = (Path(__file__).resolve().parents[1] /
                      "lab" / "fixture" / "Dockerfile").read_text()
        entrypoint = (Path(__file__).resolve().parents[1] /
                      "lab" / "fixture" / "entrypoint.sh").read_text()
        self.assertIn("rm -f /etc/ssh/ssh_host_*", dockerfile)
        self.assertIn("ssh-keygen -A", entrypoint)

    def test_dual_names_are_additive_and_default_resource_ids_are_unchanged(self) -> None:
        single = runner.names(RUN)
        paired = runner.names(RUN, dual_host=True)
        self.assertEqual(set(single), {"network", "volume", "ssh", "mcp"})
        self.assertEqual(set(paired), set(single) | {"ssh2"})
        for key in single:
            self.assertEqual(paired[key], single[key])
        self.assertTrue(paired["ssh2"].startswith("smt-ssh2-"))

    def test_dual_host_cli_is_opt_in_and_setup_only(self) -> None:
        with patch.object(sys, "argv", [
            "ssh-mcp-test", "setup", "--story", "TEST-358",
            "--commit", SHA, "--dual-host",
        ]):
            self.assertTrue(runner.parse_args().dual_host)
        with patch.object(sys, "argv", [
            "ssh-mcp-test", "setup", "--story", "TEST-358", "--commit", SHA,
        ]):
            self.assertFalse(runner.parse_args().dual_host)
        with patch.object(sys, "argv", [
            "ssh-mcp-test", "run", "--story", "TEST-358",
            "--commit", SHA, "--dual-host",
        ]), self.assertRaises(SystemExit):
            runner.parse_args()

    def test_dual_legacy_secrets_have_distinct_root_creds_and_only_synthetic_hosts(self) -> None:
        with local_state() as root:
            folder = root / "dual"
            folder.mkdir()
            with patch.object(runner, "cmd"):
                runner.create_secrets({
                    "dual_host": True, "access": "always-granted",
                    "privileged_access": "always-granted",
                }, folder)
            secret_dir = folder / "secrets"
            hosts = runner.load_json(secret_dir / "inventory.json")["hosts"]
            self.assertEqual(
                [(h["alias"], h["address"]) for h in hosts],
                [("fixture", "ssh-fixture"), ("fixture-dest", "ssh-fixture-dest")],
            )
            self.assertTrue(all(h["environment"] == "non-production" for h in hosts))
            secrets_file = runner.load_json(secret_dir / "protected" / "ssh-mcp-secrets")
            sudo = secrets_file["sudo_passwords"]
            self.assertEqual(set(sudo), {"fixture", "fixture-dest"})
            self.assertNotEqual(sudo["fixture"], sudo["fixture-dest"])
            self.assertGreater(len(sudo["fixture"]), 32)
            self.assertGreater(len(sudo["fixture-dest"]), 32)
            self.assertEqual(
                (secret_dir / "fixture-dest-sudo-password").read_text().strip(),
                sudo["fixture-dest"],
            )
            self.assertEqual(
                (secret_dir / "fixture-dest-sudo-password").stat().st_mode & 0o777,
                0o600,
            )
            env = (folder / "mcp.env").read_text()
            self.assertIn("SSH_APPROVED_ALIASES=fixture,fixture-dest\n", env)
            self.assertNotIn(sudo["fixture"], env)
            self.assertNotIn(sudo["fixture-dest"], env)

    def test_dual_sealed_sudo_encrypted_per_host_without_plaintext_in_mcp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            private = folder / "secrets"
            (private / "protected").mkdir(parents=True)
            (private / "inventory.json").write_text(json.dumps({
                "hosts": [{
                    "alias": alias, "address": addr, "username": "tester",
                    "environment": "non-production",
                    "privileged_access": "restricted",
                } for alias, addr in (
                    ("fixture", "ssh-fixture"), ("fixture-dest", "ssh-fixture-dest"),
                )],
            }))
            (private / "identity").write_text(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "A" * 120 +
                "\n-----END OPENSSH PRIVATE KEY-----\n",
            )
            passwords = {"fixture": "synthetic-" + "a" * 46,
                         "fixture-dest": "synthetic-" + "b" * 46}
            for alias, password in passwords.items():
                name = "fixture-sudo-password" if alias == "fixture" else "fixture-dest-sudo-password"
                (folder / name).write_text(password + "\n")
            (folder / "mcp.env").write_text(
                "MCP_ENVIRONMENT=lab\nMCP_ISSUER=http://localhost\n"
                "SSH_APPROVED_ALIASES=fixture,fixture-dest\n"
                "MCP_TOKEN_SIGNING_SECRET=" + "d" * 64 + "\n",
            )
            with patch.object(sealed_fixture, "DATA", folder):
                sealed_fixture.main()
            encrypted_text = (private / "protected" / "ssh-mcp-secrets").read_text()
            sealed = json.loads(encrypted_text)
            validate_v2_secrets(sealed)
            self.assertEqual(set(sealed["sealed_sudo"]), set(passwords))
            server = (folder / "mcp.env").read_text()
            client = dict(row.split("=", 1) for row in (folder / "client.env").read_text().splitlines())
            for alias, password in passwords.items():
                self.assertNotIn(password, encrypted_text)
                self.assertNotIn(password, server)
                self.assertNotIn(password, (folder / "client.env").read_text())
                self.assertEqual(unseal_sudo(
                    client["HISTORY_VIEWER_PASSWORD"], sealed["sealed_sudo"][alias],
                    deployment="lab", issuer="http://localhost",
                    alias=alias, username="tester",
                ), password)
                self.assertIn(password, runner.read_secrets(folder))

    def test_dual_start_has_two_containers_two_distinct_host_pins(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            private = folder / "secrets"
            private.mkdir()
            (private / "identity.pub").write_text("ssh-ed25519 " + "a" * 48)
            state = {
                "run_id": RUN, "story": "TEST-358",
                "dual_host": True, "names": runner.names(RUN, dual_host=True),
                "credentials": "legacy", "privileged_access": "none",
                "fixture_image": "smt-synthetic:local", "image": "smt-mcp-synthetic:local",
            }
            calls = []
            def fake_docker(*argv, **kwargs):
                calls.append(argv)
                if argv[:2] == ("network", "inspect"):
                    return json.dumps({
                        "Internal": True, "EnableIPv6": False,
                        "Driver": "bridge",
                        "Options": {
                            "com.docker.network.bridge.gateway_mode_ipv4": "isolated",
                        },
                    })
                if argv[:2] == ("exec", state["names"]["ssh"]) and "cat" in argv:
                    return "ssh-ed25519 " + "a" * 72
                if argv[:2] == ("exec", state["names"]["ssh2"]) and "cat" in argv:
                    return "ssh-ed25519 " + "b" * 72
                if argv[:2] == ("exec", state["names"]["mcp"]) and "ssh" in argv:
                    return "tester"
                return ""
            with (patch.object(runner, "docker", side_effect=fake_docker),
                  patch.object(runner, "cmd", return_value=subprocess.CompletedProcess([], 0)),
                  patch.object(runner, "verify_host_isolation")):
                runner.start_resources(state, folder)
            launched = [call for call in calls if call[0] == "run" and "--name" in call]
            for key in ("ssh", "ssh2"):
                self.assertTrue(any(state["names"][key] in call for call in launched))
            pinned = (private / "known_hosts").read_text().splitlines()
            self.assertEqual(len(pinned), 2)
            self.assertTrue(pinned[0].startswith("ssh-fixture ssh-ed25519 "))
            self.assertTrue(pinned[1].startswith("ssh-fixture-dest ssh-ed25519 "))
            self.assertNotEqual(pinned[0].split()[-1], pinned[1].split()[-1])

    def test_duplicate_ssh_host_key_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "secrets").mkdir()
            (folder / "secrets" / "identity.pub").write_text("ssh-ed25519 " + "a" * 48)
            state = {
                "run_id": RUN, "story": "TEST-358", "dual_host": True,
                "names": runner.names(RUN, dual_host=True),
                "credentials": "legacy", "privileged_access": "none",
                "fixture_image": "smt-synthetic:local",
            }
            def fake_docker(*argv, **_kwargs):
                if argv[:2] == ("network", "inspect"):
                    return json.dumps({
                        "Internal": True, "EnableIPv6": False, "Driver": "bridge",
                        "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
                    })
                if "cat" in argv:
                    return "ssh-ed25519 " + "a" * 72
                return ""
            with patch.object(runner, "docker", side_effect=fake_docker), patch.object(
                runner, "cmd", return_value=subprocess.CompletedProcess([], 0)):
                with self.assertRaisesRegex(runner.LabError, "independent"):
                    runner.start_resources(state, folder)

    def test_dual_cleanup_guards_both_container_ownerships(self) -> None:
        with local_state() as root:
            folder, state = state_for(root)
            state["dual_host"] = True
            state["names"] = runner.names(RUN, dual_host=True)
            runner.save_json(folder / "state.json", state)
            names = state["names"]
            calls = []
            def fake_docker(*argv, **_kwargs):
                calls.append(argv)
                if argv[:2] == ("ps", "-a"):
                    return names["ssh"] + "\n" + names["ssh2"] + "\n" + names["mcp"]
                return ""
            with patch.object(runner, "trusted_runner_sha"), patch.object(
                runner, "docker", side_effect=fake_docker), patch.object(
                runner, "owns", return_value=True), patch.object(
                runner, "ensure_originals"):
                runner.cleanup(argparse.Namespace(run=RUN))
            self.assertTrue(any(call[:3] == ("rm", "-f", "-v") and
                                names["ssh2"] in call for call in calls))
            self.assertFalse(runner.active_path().exists())

    def test_dual_exec_rejects_missing_second_fixture(self) -> None:
        with local_state() as root:
            folder, state = state_for(root)
            state["dual_host"] = True
            state["names"] = runner.names(RUN, dual_host=True)
            runner.save_json(folder / "state.json", state)
            def verify(kind, name, run):
                return name != state["names"]["ssh2"]
            with (patch.object(runner, "owns", side_effect=verify),
                  patch.object(runner, "trusted_runner_sha"),
                  patch.object(runner, "locked"),
                  patch.object(runner, "ensure_no_orphan_clients")):
                with self.assertRaisesRegex(runner.LabError, "ssh2"):
                    runner.execute_test(argparse.Namespace(
                        run=RUN, command=["python3", "/runner/smoke.py"], timeout=10,
                    ))


if __name__ == "__main__":
    unittest.main()
