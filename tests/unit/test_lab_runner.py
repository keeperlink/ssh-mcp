"""Offline safety/lifecycle regressions for the pinned lab runner.

Offline unit discovery includes this harness; never run the lab fixture from unit tests.
Never launches Docker, writes to the real lab, or contacts GitHub.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from tests.lab import runner


SHA = "a" * 40
RUN = "20261109T210000Z-a1b2c3"


@contextmanager
def local_state():
    with tempfile.TemporaryDirectory(prefix="sky249-unit-") as temp:
        root = Path(temp)
        with patch.object(runner, "RESULTS", root / "results"), \
             patch.object(runner, "HOME", root):
            runner.initialize()
            yield root


def state_for(root: Path, status: str = "active") -> tuple[Path, dict]:
    folder = runner.run_folder("TEST-249", RUN)
    folder.mkdir(parents=True, exist_ok=True)
    data = {
        "story": "TEST-249", "commit": SHA, "run_id": RUN,
        "status": status, "started_at": "2026-11-09T20:00:00Z",
        "updated_at": "2026-11-09T20:00:00Z", "tests": [], "stages": [],
        "workspace": str(root / "workspaces" / "TEST-249" / RUN),
        "image": "smt-mcp-aaaaaaaaaaaa:local",
        "original_containers": ["haproxy", "valkey"],
        "names": runner.names(RUN),
    }
    runner.save_json(folder / "state.json", data)
    runner.save_json(runner.active_path(), {"run_id": RUN, "story": "TEST-249"})
    return folder, data


class ValidationTests(unittest.TestCase):
    def test_restricted_fixture_requires_explicit_opt_in_and_private_viewer_secret(self) -> None:
        with local_state() as root:
            for mode in ("always-granted", "restricted"):
                folder = root / ("fixture-" + mode)
                folder.mkdir()
                with patch.object(runner, "cmd"):
                    runner.create_secrets({"access": mode}, folder)
                inventory = runner.load_json(folder / "secrets" / "inventory.json")
                assert inventory["hosts"][0]["alias"] == "fixture"
                self.assertEqual(inventory["hosts"][0]["access"], mode)
                self.assertEqual(inventory["hosts"][0]["privileged_access"], "none")
                self.assertFalse((folder / "secrets" / "fixture-sudo-password").exists())
                self.assertFalse((folder / "secrets" / "protected").exists())
                content = (folder / "mcp.env").read_text()
                self.assertEqual("HISTORY_VIEWER_ENABLED=true" in content,
                                 mode == "restricted")
                secrets = runner.read_secrets(folder)
                if mode == "restricted":
                    viewer = next(x.split("=", 1)[1] for x in content.splitlines()
                                  if x.startswith("HISTORY_VIEWER_PASSWORD="))
                    self.assertEqual(len(viewer), 64)
                    self.assertIn(viewer, secrets)
                    self.assertNotIn(viewer, runner.redact("synthetic: " + viewer, secrets))
                else:
                    self.assertNotIn("HISTORY_VIEWER_PASSWORD", content)

    def test_privileged_fixture_is_test_only_and_uses_protected_files(self) -> None:
        with local_state() as root:
            for policy in ("restricted", "always-granted"):
                folder = root / ("privileged-" + policy)
                folder.mkdir()
                with patch.object(runner, "cmd"):
                    runner.create_secrets(
                        {"access": "always-granted", "privileged_access": policy},
                        folder,
                    )
                private = folder / "secrets"
                inventory = runner.load_json(private / "inventory.json")["hosts"][0]
                self.assertEqual(inventory["privileged_access"], policy)
                self.assertEqual(inventory["alias"], "fixture")
                self.assertEqual(inventory["environment"], "non-production")
                password_file = private / "fixture-sudo-password"
                secret_file = private / "protected" / "ssh-mcp-secrets"
                self.assertEqual(password_file.stat().st_mode & 0o777, 0o600)
                self.assertEqual(secret_file.stat().st_mode & 0o777, 0o600)
                self.assertEqual(secret_file.parent.stat().st_mode & 0o777, 0o700)
                password = password_file.read_text().strip()
                self.assertGreater(len(password), 32)
                self.assertEqual(
                    runner.load_json(secret_file), {"sudo_passwords": {"fixture": password}}
                )
                self.assertNotIn(password, (private / "inventory.json").read_text())
                self.assertNotIn(password, (folder / "mcp.env").read_text())
                self.assertNotIn("sudo_passwords", (folder / "mcp.env").read_text())
                self.assertIn("HISTORY_VIEWER_ENABLED=true", (folder / "mcp.env").read_text())

    def test_privileged_setup_flag_cannot_change_other_runner_actions(self) -> None:
        for mode in ("none", "restricted", "always-granted"):
            with patch.object(sys, "argv", ["ssh-mcp-test", "setup", "--story",
                                            "TEST-267", "--commit", SHA,
                                            "--privileged-access", mode]):
                self.assertEqual(runner.parse_args().privileged_access, mode)
        with patch.object(sys, "argv", ["ssh-mcp-test", "run", "--story",
                                        "TEST-267", "--commit", SHA,
                                        "--privileged-access", "always-granted"]):
            with self.assertRaises(SystemExit):
                runner.parse_args()

    def test_requires_exact_sha_and_structured_ids(self) -> None:
        self.assertEqual(runner.valid_sha(SHA), SHA)
        self.assertEqual(runner.valid_run(RUN), RUN)
        self.assertEqual(runner.valid_story("TEST-249"), "TEST-249")
        for candidate in ("main", "f" * 8, "A" * 40, "a" * 39, "../" + SHA):
            with self.assertRaises(runner.LabError):
                runner.valid_sha(candidate)
        for candidate in ("TEST-0", "test-249", "TEST-247/../other"):
            with self.assertRaises(runner.LabError):
                runner.valid_story(candidate)
        for candidate in ("../state", "", "a" * 20):
            with self.assertRaises(runner.LabError):
                runner.valid_run(candidate)

    def test_test_fixture_resources_are_namespaced(self) -> None:
        names = runner.names(RUN)
        self.assertEqual(set(names), {"network", "volume", "ssh", "mcp"})
        self.assertEqual(len(set(names.values())), 4)
        self.assertTrue(all(value.startswith("smt-") and RUN in value
                            for value in names.values()))

    def test_redacts_keys_and_any_jwt_like_token(self) -> None:
        original = "MCP=" + "secret-value" + " token=eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJ0ZXN0In0.signature"
        clean = runner.redact(original, ["secret-value"])
        self.assertNotIn("secret-value", clean)
        self.assertIn("[REDACTED_TOKEN]", clean)
        self.assertNotIn("eyJ", clean)

    def test_save_json_is_atomic_and_owner_private(self) -> None:
        with local_state() as root:
            path = root / "reports" / "state.json"
            runner.save_json(path, {"run_id": RUN})
            self.assertEqual(runner.load_json(path)["run_id"], RUN)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(list(path.parent.iterdir())), 1)

    def test_refuses_unpinned_workspace_execution(self) -> None:
        with local_state() as root:
            with patch.object(runner, "RUNNER", root / "source" / "tests" / "lab"):
                with self.assertRaisesRegex(runner.LabError, "separately installed"):
                    runner.trusted_runner_sha()

    def test_refuses_tampered_runner_blob(self) -> None:
        with local_state() as root:
            location = root / "tools" / "ssh-mcp-lab" / SHA
            location.mkdir(parents=True)
            (location / "PINNED_COMMIT").write_text(SHA)
            with patch.object(runner, "RUNNER", location), \
                 patch.object(runner, "git", side_effect=lambda *args:
                      "commit" if args[0] == "cat-file" else "correct-git-hash"), \
                 patch.object(runner, "text", return_value="tampered-file-hash"):
                with self.assertRaisesRegex(runner.LabError, "changed since approved"):
                    runner.trusted_runner_sha()


class IsolationTests(unittest.TestCase):
    def test_ownership_check_rejects_mismatched_label(self) -> None:
        result = subprocess.CompletedProcess(["docker"], 0, b"a-different-run\n", b"")
        with patch.object(runner, "cmd", return_value=result):
            with self.assertRaisesRegex(runner.LabError, "unowned"):
                runner.owns("network", "smt-net-" + RUN, RUN)

    def test_ownership_absent_is_safe_and_non_mutating(self) -> None:
        result = subprocess.CompletedProcess(["docker"], 1, b"", b"Error: No such volume: missing")
        with patch.object(runner, "cmd", return_value=result):
            self.assertFalse(runner.owns("volume", "smt-db-" + RUN, RUN))

    def test_missing_network_on_docker_engine_29_is_absent(self) -> None:
        expected = "smt-net-" + RUN
        result = subprocess.CompletedProcess(
            ["docker"], 1, b"[]\n",
            f"Error response from daemon: network {expected} not found\n".encode(),
        )
        with patch.object(runner, "cmd", return_value=result):
            self.assertFalse(runner.owns("network", expected, RUN))

    def test_other_network_missing_error_does_not_bypass_ownership(self) -> None:
        result = subprocess.CompletedProcess(
            ["docker"], 1, b"",
            b"Error response from daemon: network plugin other not found",
        )
        with patch.object(runner, "cmd", return_value=result):
            with self.assertRaisesRegex(runner.LabError, "Cannot verify Docker network"):
                runner.owns("network", "smt-net-" + RUN, RUN)

    def test_cleanup_after_failed_fetch_with_no_docker_resources(self) -> None:
        with local_state() as root, \
             patch.object(runner, "trusted_runner_sha", return_value=SHA), \
             patch.object(runner, "ensure_originals"):
            folder, _ = state_for(root, status="setup_failed")
            def fake_cmd(argv, **_kwargs):
                if argv[:3] == ["docker", "network", "inspect"]:
                    msg = f"Error response from daemon: network {argv[-1]} not found"
                elif argv[:3] == ["docker", "volume", "inspect"]:
                    msg = f"Error response from daemon: get {argv[-1]}: no such volume"
                elif argv[:3] == ["docker", "container", "inspect"]:
                    msg = f"Error response from daemon: No such container: {argv[-1]}"
                else:
                    raise AssertionError(f"Unexpected Docker command: {argv}")
                return subprocess.CompletedProcess(argv, 1, b"[]\n", msg.encode())
            with patch.object(runner, "cmd", side_effect=fake_cmd), \
                 patch.object(runner, "docker", return_value=""):
                self.assertEqual(runner.cleanup(argparse.Namespace(run=RUN)), 0)
            self.assertEqual(runner.load_json(folder / "state.json")["status"], "cleaned")
            self.assertFalse(runner.active_path().exists())

    def test_docker_daemon_error_is_not_mistaken_for_absent_client(self) -> None:
        result = subprocess.CompletedProcess(
            ["docker"], 1, b"", b"Cannot connect to the Docker daemon"
        )
        with patch.object(runner, "cmd", return_value=result):
            with self.assertRaisesRegex(runner.LabError, "Cannot verify Docker"):
                runner.owns("container", f"smt-client-{RUN}-1", RUN)

    def test_internal_bridge_requires_isolated_gateway_and_no_ipv6(self) -> None:
        with local_state() as root:
            folder, state = state_for(root)
            requested: list[tuple[str, ...]] = []

            def docker_mock(*args, **_kwargs):
                requested.append(args)
                if args[:2] == ("network", "inspect"):
                    return json.dumps({
                        "Internal": True, "EnableIPv6": False, "Driver": "bridge",
                        "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
                    })
                if args[:2] == ("volume", "create"):
                    raise runner.LabError("stop before starting fixture")
                return ""

            with patch.object(runner, "docker", side_effect=docker_mock):
                with self.assertRaisesRegex(runner.LabError, "stop before"):
                    runner.start_resources(state, folder)
            creation = requested[0]
            self.assertIn("--internal", creation)
            self.assertIn("--ipv6=false", creation)
            self.assertIn("com.docker.network.bridge.gateway_mode_ipv4=isolated", creation)

    def test_setup_rejects_unisolated_bridge_before_starting_containers(self) -> None:
        with local_state() as root:
            folder, state = state_for(root)
            calls: list[tuple[str, ...]] = []

            def docker_mock(*args, **_kwargs):
                calls.append(args)
                if args[:2] == ("network", "inspect"):
                    return json.dumps({
                        "Internal": True, "EnableIPv6": False, "Driver": "bridge",
                        "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "nat"},
                    })
                return ""

            with patch.object(runner, "docker", side_effect=docker_mock):
                with self.assertRaisesRegex(runner.LabError, "host-isolated"):
                    runner.start_resources(state, folder)
            self.assertFalse(any(args[:2] == ("volume", "create") for args in calls))
            self.assertFalse(any(args[0] == "run" for args in calls))

    def test_live_host_listener_must_be_unreachable_from_mcp(self) -> None:
        with patch.object(runner, "text", return_value="10.77.240.10"), \
             patch.object(runner.socket, "create_connection", return_value=MagicMock()), \
             patch.object(runner, "docker", return_value="HOST_REACHABILITY_BLOCKED") as docker_mock:
            runner.verify_host_isolation("synthetic-mcp")
            argv = docker_mock.call_args.args
            self.assertEqual(argv[:3], ("exec", "synthetic-mcp", "python"))
            self.assertIn("10.77.240.10", argv)

    def test_reachable_host_listener_blocks_setup(self) -> None:
        with patch.object(runner, "text", return_value="10.77.240.10"), \
             patch.object(runner.socket, "create_connection", return_value=MagicMock()), \
             patch.object(runner, "docker", return_value="HOST_REACHABILITY_VIOLATION"):
            with self.assertRaisesRegex(runner.LabError, "unexpectedly reached"):
                runner.verify_host_isolation("synthetic-mcp")

    def test_host_listener_positive_control_required(self) -> None:
        with patch.object(runner, "text", return_value="10.77.240.10"), \
             patch.object(runner.socket, "create_connection",
                          side_effect=ConnectionRefusedError("nothing listening")), \
             patch.object(runner, "docker") as docker_mock:
            with self.assertRaisesRegex(runner.LabError, "control unavailable"):
                runner.verify_host_isolation("synthetic-mcp")
            docker_mock.assert_not_called()

    def test_timeout_terminates_daemon_container_and_checks_absence(self) -> None:
        client_name = f"smt-client-{RUN}-1"
        with patch.object(runner, "owns", side_effect=[True, False]) as check_owner, \
             patch.object(runner, "cmd", return_value=subprocess.CompletedProcess(
                 ["docker"], 0, b"", b"")) as docker_cmd:
            runner.stop_owned_client(RUN, client_name)
        self.assertEqual(check_owner.call_count, 2)
        self.assertEqual(docker_cmd.call_args.args[0],
                         ["docker", "rm", "-f", "-v", client_name])

    def test_termination_failure_prevents_reporting_success(self) -> None:
        client_name = f"smt-client-{RUN}-1"
        with patch.object(runner, "owns", return_value=True), \
             patch.object(runner, "cmd", return_value=subprocess.CompletedProcess(
                 ["docker"], 1, b"", b"failed")):
            with self.assertRaisesRegex(runner.LabError, "still present"):
                runner.stop_owned_client(RUN, client_name)

    def test_orphaned_client_blocks_next_exec(self) -> None:
        with local_state() as root, patch.object(runner, "trusted_runner_sha", return_value=SHA), \
             patch.object(runner, "owns", return_value=True), \
             patch.object(runner, "ensure_no_orphan_clients",
                          side_effect=runner.LabError("Previous test client remains")), \
             patch.object(runner, "cmd") as docker_cmd:
            state_for(root)
            with self.assertRaisesRegex(runner.LabError, "Previous test client remains"):
                runner.execute_test(argparse.Namespace(
                    run=RUN, command=["python3", "/runner/smoke.py"], timeout=10))
            docker_cmd.assert_not_called()

    def test_provisioning_lock_prevents_second_setup(self) -> None:
        with local_state() as root, patch.object(runner, "trusted_runner_sha", return_value=SHA), \
             patch.object(runner, "initial_containers", return_value=["haproxy"]):
            state_for(root, status="provisioning")
            with self.assertRaisesRegex(runner.LabError, "Existing run"):
                runner.setup(argparse.Namespace(story="TEST-249", commit=SHA, pr=None))

    def test_failed_fetch_retains_recoverable_run_metadata(self) -> None:
        with local_state(), patch.object(runner, "trusted_runner_sha", return_value=SHA), \
             patch.object(runner, "initial_containers", return_value=["haproxy"]), \
             patch.object(runner, "fetch_target", side_effect=runner.LabError("offline fixture")):
            rc = runner.setup(argparse.Namespace(story="TEST-249", commit=SHA, pr=None))
            self.assertEqual(rc, 1)
            active = runner.load_json(runner.active_path())
            folder, state = runner.locate(active["run_id"])
            self.assertTrue((folder / "state.json").exists())
            self.assertEqual(state["status"], "setup_failed")
            self.assertEqual(state["failure_kind"], "INFRA_FAILURE")

    def test_build_failure_is_classified_and_does_not_start_containers(self) -> None:
        with local_state(), patch.object(runner, "trusted_runner_sha", return_value=SHA), \
             patch.object(runner, "initial_containers", return_value=["haproxy"]), \
             patch.object(runner, "fetch_target"), \
             patch.object(runner, "checkout"), \
             patch.object(runner, "build_image", side_effect=runner.LabError("broken Dockerfile")), \
             patch.object(runner, "start_resources") as runtime:
            self.assertEqual(
                runner.setup(argparse.Namespace(story="TEST-249", commit=SHA, pr=None)), 1
            )
            active = runner.load_json(runner.active_path())
            _, state = runner.locate(active["run_id"])
            self.assertEqual(state["status"], "setup_failed")
            self.assertEqual(state["failure_kind"], "BUILD_FAILURE")
            runtime.assert_not_called()

    def test_cleanup_never_removes_unowned_containers(self) -> None:
        with local_state() as root, patch.object(runner, "trusted_runner_sha", return_value=SHA):
            state_for(root)
            with patch.object(runner, "docker", return_value="smt-client-" + RUN + "-1"), \
                 patch.object(runner, "owns", side_effect=runner.LabError("unowned")):
                with self.assertRaisesRegex(runner.LabError, "unowned"):
                    runner.cleanup(argparse.Namespace(run=RUN))
            self.assertTrue(runner.active_path().exists())

    def test_idempotent_cleanup_keeps_retained_reports(self) -> None:
        with local_state() as root, patch.object(runner, "trusted_runner_sha", return_value=SHA):
            folder, _ = state_for(root)
            with patch.object(runner, "docker", return_value=""), \
                 patch.object(runner, "owns", return_value=False), \
                 patch.object(runner, "ensure_originals"):
                self.assertEqual(runner.cleanup(argparse.Namespace(run=RUN)), 0)
                self.assertEqual(runner.cleanup(argparse.Namespace(run=RUN)), 0)
            self.assertFalse(runner.active_path().exists())
            self.assertEqual(runner.load_json(folder / "state.json")["status"], "cleaned")

    def test_explicit_reconciliation_records_missing_originals_without_green_cleanup(self) -> None:
        with local_state() as root, \
             patch.object(runner, "trusted_runner_sha", return_value=SHA), \
             patch.object(runner, "owns", return_value=False), \
             patch.object(runner, "docker", return_value="") as docker_calls, \
             patch.object(runner, "initial_containers", return_value=["haproxy"]):
            folder, state = state_for(root)
            state["tests"] = [{"status": "PASS", "index": 1}]
            runner.save_json(folder / "state.json", state)
            args = argparse.Namespace(run=RUN, expect_missing_originals="valkey")
            self.assertEqual(runner.reconcile_cleanup(args), 0)
            revised = runner.load_json(folder / "state.json")
            self.assertEqual(revised["status"], "cleaned_with_missing_originals")
            self.assertEqual(revised["cleanup_exception"], {
                "kind": "original_containers_missing", "missing": ["valkey"],
            })
            self.assertEqual(revised["stages"][-1]["status"], "WARNING")
            self.assertEqual(revised["stages"][-1]["name"], "cleanup_reconciliation")
            self.assertEqual(revised["original_containers"], ["haproxy", "valkey"])
            self.assertEqual(revised["tests"], state["tests"])
            self.assertFalse(runner.active_path().exists())
            self.assertIsNotNone(revised["cleaned_at"])
            self.assertNotIn(("rm",), [c.args for c in docker_calls.call_args_list])
            with self.assertRaisesRegex(runner.LabError, "non-active"):
                runner.reconcile_cleanup(args)

    def test_reconciliation_rejects_mismatch_resources_and_secrets(self) -> None:
        with local_state() as root, patch.object(
            runner, "trusted_runner_sha", return_value=SHA
        ), patch.object(runner, "initial_containers", return_value=["haproxy"]):
            folder, state = state_for(root)
            args = argparse.Namespace(run=RUN, expect_missing_originals="valkey")
            def assert_locked() -> None:
                self.assertEqual(runner.load_json(folder / "state.json")["status"], "active")
                self.assertTrue(runner.active_path().exists())

            with patch.object(runner, "owns", return_value=False), \
                 patch.object(runner, "docker", return_value=""):
                with self.assertRaisesRegex(runner.LabError, "Acknowledged"):
                    runner.reconcile_cleanup(
                        argparse.Namespace(run=RUN, expect_missing_originals="haproxy"))
                assert_locked()
                (folder / "mcp.env").write_text("synthetic")
                with self.assertRaisesRegex(runner.LabError, "credentials remain"):
                    runner.reconcile_cleanup(args)
                assert_locked()
                (folder / "mcp.env").unlink()

            with patch.object(runner, "owns", return_value=True):
                with self.assertRaisesRegex(runner.LabError, "remains"):
                    runner.reconcile_cleanup(args)
            assert_locked()
            with patch.object(runner, "owns", return_value=False), \
                 patch.object(runner, "docker", return_value=f"smt-client-{RUN}-1"):
                with self.assertRaisesRegex(runner.LabError, "Run-labeled"):
                    runner.reconcile_cleanup(args)
            assert_locked()
            with patch.object(runner, "owns", return_value=False), \
                 patch.object(runner, "docker", side_effect=runner.LabError("daemon down")):
                with self.assertRaisesRegex(runner.LabError, "daemon down"):
                    runner.reconcile_cleanup(args)
            assert_locked()
            with patch.object(runner, "owns", return_value=False), \
                 patch.object(runner, "docker", return_value=""), \
                 patch.object(runner, "initial_containers",
                              return_value=["haproxy", "valkey"]):
                with self.assertRaisesRegex(runner.LabError, "normal cleanup"):
                    runner.reconcile_cleanup(args)
            assert_locked()

    def test_reconciliation_never_clears_another_runs_active_marker(self) -> None:
        with local_state() as root, \
             patch.object(runner, "trusted_runner_sha", return_value=SHA), \
             patch.object(runner, "owns", return_value=False), \
             patch.object(runner, "docker", return_value=""), \
             patch.object(runner, "initial_containers", return_value=["haproxy"]):
            folder, _ = state_for(root)
            runner.save_json(runner.active_path(), {
                "run_id": "20261109T210000Z-deadbe", "story": "TEST-249",
            })
            with self.assertRaisesRegex(runner.LabError, "mismatched run"):
                runner.reconcile_cleanup(argparse.Namespace(
                    run=RUN, expect_missing_originals="valkey"))
            self.assertEqual(runner.load_json(folder / "state.json")["status"], "active")
            self.assertTrue(runner.active_path().exists())

    def test_reconciliation_cli_requires_explicit_original_names(self) -> None:
        with patch.object(sys, "argv", [
            "ssh-mcp-test", "reconcile-cleanup", "--run", RUN,
            "--expect-missing-originals", "sky15-gtid-a,sky15-gtid-b,sky15-gtid-c",
        ]):
            args = runner.parse_args()
            self.assertEqual(args.command_name, "reconcile-cleanup")
            self.assertEqual(args.expect_missing_originals,
                             "sky15-gtid-a,sky15-gtid-b,sky15-gtid-c")
        with patch.object(sys, "argv", [
            "ssh-mcp-test", "reconcile-cleanup", "--run", RUN,
        ]):
            with self.assertRaises(SystemExit):
                runner.parse_args()


class SessionTests(unittest.TestCase):
    def test_resumes_active_run_without_chat_history(self) -> None:
        with local_state() as root:
            folder, _ = state_for(root)
            self.assertEqual(runner.locate(RUN)[0], folder)
            with patch.object(runner, "owns", return_value=False):
                self.assertEqual(runner.status(argparse.Namespace(run=None)), 0)
            self.assertEqual(runner.results(argparse.Namespace(
                run=RUN, story=None, limit=1)), 0)

    def test_failed_story_exec_keeps_environment_and_logs(self) -> None:
        with local_state() as root, patch.object(runner, "trusted_runner_sha", return_value=SHA), \
             patch.object(runner, "owns", return_value=True):
            folder, data = state_for(root)
            Path(data["workspace"]).mkdir(parents=True)
            (folder / "mcp.env").write_text("MCP_LOGIN_KEY=secret-token\n")

            def fake_cmd(_argv, **kwargs):
                kwargs["output"].write_text("test failed; token=secret-token\n")
                return subprocess.CompletedProcess(["docker"], 7, b"", b"")

            with patch.object(runner, "cmd", side_effect=fake_cmd), \
                 patch.object(runner, "stop_owned_client"), \
                 patch.object(runner, "ensure_no_orphan_clients"):
                rc = runner.execute_test(argparse.Namespace(
                    run=RUN, command=["--", "python3", "tests/my_story.py"],
                    timeout=10))
            self.assertEqual(rc, 1)
            after = runner.load_json(folder / "state.json")
            self.assertEqual(after["status"], "active")
            self.assertEqual(after["tests"][0]["status"], "TEST_FAILURE")
            self.assertNotIn("secret-token", (folder / "exec-001.log").read_text())

    def test_expired_test_kills_client_before_next_exec(self) -> None:
        with local_state() as root, patch.object(runner, "trusted_runner_sha", return_value=SHA), \
             patch.object(runner, "owns", return_value=True), \
             patch.object(runner, "ensure_no_orphan_clients"), \
             patch.object(runner, "stop_owned_client") as stop_client:
            folder, _ = state_for(root)
            (folder / "mcp.env").write_text("MCP_LOGIN_KEY=synthetic\n")
            with patch.object(runner, "cmd", side_effect=subprocess.TimeoutExpired(
                cmd="docker run", timeout=1)):
                rc = runner.execute_test(argparse.Namespace(
                    run=RUN, command=["python3", "/runner/smoke.py"], timeout=1))
            self.assertEqual(rc, 1)
            stop_client.assert_called_once_with(RUN, f"smt-client-{RUN}-1")
            after = runner.load_json(folder / "state.json")
            self.assertEqual(after["status"], "active")
            self.assertEqual(after["tests"][0]["status"], "TEST_TIMEOUT")
            self.assertEqual(after["tests"][0]["exit_code"], 124)

    def test_unverified_client_termination_marks_run_unusable(self) -> None:
        with local_state() as root, patch.object(runner, "trusted_runner_sha", return_value=SHA), \
             patch.object(runner, "owns", return_value=True), \
             patch.object(runner, "ensure_no_orphan_clients"), \
             patch.object(runner, "stop_owned_client", side_effect=runner.LabError(
                 "still present")):
            folder, _ = state_for(root)
            (folder / "mcp.env").write_text("MCP_LOGIN_KEY=synthetic\n")
            with patch.object(runner, "cmd", return_value=subprocess.CompletedProcess(
                ["docker"], 0, b"", b"")):
                rc = runner.execute_test(argparse.Namespace(
                    run=RUN, command=["python3", "/runner/smoke.py"], timeout=1))
            self.assertEqual(rc, 1)
            after = runner.load_json(folder / "state.json")
            self.assertEqual(after["status"], "client_cleanup_failed")
            self.assertEqual(after["tests"][0]["status"], "INFRA_FAILURE")

    def test_standard_convenience_run_cleans_failed_setup(self) -> None:
        with local_state() as root:
            state_for(root, "setup_failed")
            with patch.object(runner, "setup", return_value=1), \
                 patch.object(runner, "cleanup", return_value=0) as clean:
                self.assertEqual(runner.run_all(argparse.Namespace()), 1)
                clean.assert_called_once_with(argparse.Namespace(run=RUN))


if __name__ == "__main__":
    unittest.main()
