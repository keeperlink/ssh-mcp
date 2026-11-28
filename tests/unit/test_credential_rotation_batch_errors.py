"""Negative-path coverage for offline batch operator tooling, synthetic only."""
from __future__ import annotations

from contextlib import redirect_stdout, redirect_stderr
import hashlib
import io
import json
import subprocess
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ssh_mcp_secrets import apply, batch, cli

_HASH = "$6$abcdefghijklmnop$" + "A" * 86
META = {"version": 1, "source_sha256": "a" * 64,
        "staged_sha256": "b" * 64, "inventory_sha256": "c" * 64}
ENTRY = {"alias": "demo-node-a", "username": "gateway", "hash": _HASH}
BIND = {"deployment": "lab", "issuer": "https://example.invalid"}
CONSOLE = "synthetic-old-console-password-123"
OAUTH = "synthetic-old-oauth-" + "a" * 40
LEGACY = {"version": 1, "oauth_login_key": OAUTH,
          "viewer_password": CONSOLE,
          "oauth_signing_key": "synthetic-sign-" + "x" * 44,
          "metrics_token": "synthetic-metrics-" + "m" * 44,
          "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                             + "a" * 96 + "\n-----END OPENSSH PRIVATE KEY-----",
          "sudo_passwords": {"demo-node-a": "synthetic-sudo-a"}}


class RotationErrorPaths(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="synthetic-batch-errors-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)

    def write(self, name: str, obj: dict[str, object]) -> tuple[Path, str]:
        p = self.root / name
        p.write_text(json.dumps(obj) + "\n")
        p.chmod(0o600)
        return p, hashlib.sha256(p.read_bytes()).hexdigest()

    def test_batch_handoff_rejects_nonroot_and_invalid_hashes(self) -> None:
        fake = self.root / "deployment" / "ssh-mcp-secrets"
        inventory, digest = self.write("inventory.json", {
            "version": 1, "hosts": [{"alias": "demo-node-a", "username": "gateway"}],
        })
        vm_map, _ = self.write("vm.json", {
            "version": 1, "vmids": {"demo-node-a": 100},
        })
        args = dict(jenkins_file=fake, inventory=inventory, vm_map=vm_map,
                    workdir=self.root, deployment="lab", issuer="https://example.invalid",
                    expected_source="a" * 64, expected_inventory=digest,
                    container="controller",
                    container_file="/run/jenkins/secrets/deployment/ssh-mcp-secrets")
        with patch.object(batch.os, "geteuid", return_value=1001), \
             self.assertRaises(cli.RotationError):
            batch.batch_handoff(**args)
        args["expected_source"] = "wrong"
        with patch.object(batch.os, "geteuid", return_value=0), \
             patch.object(batch.cli, "_private_dir"), \
             self.assertRaises(cli.RotationError):
            batch.batch_handoff(**args)
        args["expected_source"] = "a" * 64
        args["expected_inventory"] = "f" * 64
        with patch.object(batch.os, "geteuid", return_value=0), \
             patch.object(batch.cli, "_private_dir"), \
             self.assertRaises(cli.RotationError):
            batch.batch_handoff(**args)

    def test_proxmox_rejects_host_manifest(self) -> None:
        file, digest = self.write("host.json", {**META, "type": "host-hash-only",
                                                "entry": dict(ENTRY)})
        with patch.object(apply.os, "geteuid", return_value=0), \
             patch.object(apply.cli, "_private_dir"), \
             patch.object(apply.cli, "_read_file", side_effect=lambda p, **kw: p.read_bytes()), \
             self.assertRaises(cli.RotationError):
            apply.apply_proxmox(file=file, sha256=digest,
                                controller_host="pre", expected_count=1)

    def test_hash_generator_bad_subprocess_results(self) -> None:
        for output in (
            SimpleNamespace(returncode=1, stdout=b""),
            SimpleNamespace(returncode=0, stdout=b"not-a-hash\n"),
            SimpleNamespace(returncode=0, stdout=b"\xff\n"),
        ):
            with self.subTest(output=output.returncode), \
                 patch.object(batch.subprocess, "run", return_value=output), \
                 self.assertRaises(cli.RotationError):
                batch._hash_sudo("synthetic-password")

    def test_hash_generation_timeouts_are_safe_rotation_rejections(self) -> None:
        for error in (OSError("synthetic openssl missing"),
                      subprocess.TimeoutExpired(["openssl"], 2)):
            with self.subTest(error=type(error).__name__), \
                 patch.object(batch.subprocess, "run", side_effect=error), \
                 self.assertRaises(cli.RotationError):
                batch._hash_sudo("synthetic-password")

    def test_container_validation_rejects_traversal_and_wrong_leaf(self) -> None:
        paths = (
            "/run/jenkins/secrets/deployment/../ssh-mcp-secrets",
            "/run/jenkins/secrets/deployment/./ssh-mcp-secrets",
            "/run/jenkins/secrets/deployment//ssh-mcp-secrets",
            "/run/jenkins/secrets/deployment/subfolder/ssh-mcp-secrets",
            "/run/jenkins/secrets/deployment/other-secret",
        )
        for path in paths:
            with self.subTest(path=path), self.assertRaises(cli.RotationError):
                batch._validate_container("controller", path, "ssh-mcp-secrets")
        batch._validate_container(
            "controller", "/run/jenkins/secrets/deployment/ssh-mcp-secrets", "ssh-mcp-secrets"
        )

    def test_invalid_container_preflight_before_prompt_or_files(self) -> None:
        fake = self.root / "deployment" / "ssh-mcp-secrets"
        args = dict(jenkins_file=fake, inventory=self.root / "inventory.json",
                    vm_map=self.root / "map.json", workdir=self.root,
                    deployment="lab", issuer="https://example.invalid",
                    expected_source="a" * 64, expected_inventory="b" * 64,
                    container="controller", container_file=(
                        "/run/jenkins/secrets/deployment/../ssh-mcp-secrets"
                    ))
        with patch.object(batch.os, "geteuid", return_value=0), \
             patch.object(batch.getpass, "getpass", side_effect=AssertionError("prompted")), \
             patch.object(batch.cli, "_private_dir", side_effect=AssertionError("opened files")), \
             self.assertRaises(cli.RotationError):
            batch.batch_handoff(**args)

    def test_container_postcheck_checks_binding_and_digest(self) -> None:
        for name, path in (("", "/run/jenkins/secrets/deployment/secret"),
                           ("invalid/name", "/run/jenkins/secrets/deployment/secret"),
                           ("controller", "/invalid/path")):
            with self.subTest(name=name, path=path), self.assertRaises(cli.RotationError):
                batch._postcheck_container(name, path, "a" * 64, "secret")
        with patch.object(batch.subprocess, "run",
                          return_value=SimpleNamespace(returncode=0, stdout=b"b" * 64 + b"  path\n")):
            with self.assertRaises(cli.CommitUncertain):
                batch._postcheck_container("controller",
                                           "/run/jenkins/secrets/deployment/secret", "a" * 64, "secret")
        with patch.object(batch.subprocess, "run",
                          return_value=SimpleNamespace(returncode=1, stdout=b"")):
            with self.assertRaises(cli.CommitUncertain):
                batch._postcheck_container("controller",
                                           "/run/jenkins/secrets/deployment/secret", "a" * 64, "secret")
        with patch.object(batch.subprocess, "run",
                          return_value=SimpleNamespace(returncode=0, stdout=b"a" * 64 + b"  path\n")):
            batch._postcheck_container("controller", "/run/jenkins/secrets/deployment/secret", "a" * 64, "secret")

    def test_trusted_jenkins_rejects_untrusted_leaf_and_metadata(self) -> None:
        file = self.root / "bad-name"
        with self.assertRaises(cli.RotationError):
            batch._trusted_jenkins(file)
        d = self.root / "deployment"
        d.mkdir()
        file = d / "ssh-mcp-secrets"
        file.write_text("synthetic")
        file.chmod(0o600)
        with self.assertRaises(cli.RotationError):
            batch._trusted_jenkins(file)
        with patch.object(Path, "stat", return_value=SimpleNamespace(st_uid=0, st_gid=1000,
                                                                      st_mode=0o40750)):
            with self.assertRaises(cli.RotationError):
                batch._trusted_jenkins(file)
        with patch.object(Path, "stat", return_value=SimpleNamespace(st_uid=0, st_gid=1000,
                                                                      st_mode=0o40750)), \
             patch.object(Path, "lstat",
                          return_value=SimpleNamespace(st_mode=0o100640, st_nlink=1,
                                                       st_uid=0, st_gid=1000)), \
             patch.object(cli, "_read_file", return_value=b"synthetic"):
            self.assertEqual(batch._trusted_jenkins(file), b"synthetic")

    def test_jenkins_scoped_path_and_mount_binding(self) -> None:
        root = self.root / "deployment"
        for scope in ("nonprod", "demo-node-a"):
            with self.subTest(scope=scope):
                file = root / scope / "ssh-mcp-secrets"
                relative = scope + "/ssh-mcp-secrets"
                self.assertEqual(batch._jenkins_location(file), (root, relative))
                mount = "/run/jenkins/secrets/deployment/" + relative
                batch._validate_container("controller", mount, relative)
                for wrong in ("/run/jenkins/secrets/deployment/ssh-mcp-secrets",
                              "/run/jenkins/secrets/deployment/other/ssh-mcp-secrets"):
                    with self.assertRaises(cli.RotationError):
                        batch._validate_container("controller", wrong, relative)
                    with self.assertRaises(cli.RotationError):
                        batch._postcheck_container("controller", wrong, "a" * 64, relative)
        for path in (root / "bad_scope" / "ssh-mcp-secrets",
                     root / "nonprod" / "nested" / "ssh-mcp-secrets",
                     root / "-invalid" / "ssh-mcp-secrets"):
            with self.assertRaises(cli.RotationError):
                batch._jenkins_location(path)

    def test_jenkins_scoped_directories_both_validated(self) -> None:
        root = self.root / "deployment"
        scope = root / "nonprod"
        scope.mkdir(parents=True)
        file = scope / "ssh-mcp-secrets"
        file.write_bytes(b"synthetic")
        with patch.object(batch, "_check_jenkins_dir_info") as check, \
             patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=0o100640,
                          st_nlink=1, st_uid=0, st_gid=1000)), \
             patch.object(cli, "_read_file", return_value=b"synthetic"):
            self.assertEqual(batch._trusted_jenkins(file), b"synthetic")
            self.assertEqual(check.call_count, 2)
        linked = root / "demo-node-a"
        linked.symlink_to(scope, target_is_directory=True)
        with patch.object(batch, "_check_jenkins_dir_info"), self.assertRaises(cli.RotationError):
            batch._trusted_jenkins(linked / "ssh-mcp-secrets")

    def test_manifest_rejects_invalid_shapes(self) -> None:
        baseline = {**META, "type": "host-hash-only", "entry": dict(ENTRY)}
        bad_variants = [
            {**baseline, "version": True},
            {**baseline, "version": 2},
            {**baseline, "type": "wrong"},
            {**baseline, "staged_sha256": "bad"},
            {**baseline, "extra": "not-allowed"},
            {**baseline, "entry": "not-an-object"},
            {**baseline, "entry": {**ENTRY, "alias": "bad/alias"}},
            {**baseline, "entry": {**ENTRY, "username": "root"}},
            {**baseline, "entry": {**ENTRY, "hash": "cleartext"}},
            {**baseline, "entry": {**ENTRY, "extra": 1}},
            {**META, "type": "proxmox-hash-only", "entries": []},
            {**META, "type": "proxmox-hash-only", "entries": [{**ENTRY, "vmid": True}]},
            {**META, "type": "proxmox-hash-only", "entries": [{**ENTRY, "vmid": 100},
                                                            {**ENTRY, "vmid": 100,
                                                             "alias": "demo-node-b"}]},
            {**META, "type": "proxmox-hash-only", "entries": [{**ENTRY, "vmid": 100},
                                                            {**ENTRY, "vmid": 200}]},
        ]
        for i, item in enumerate(bad_variants):
            with self.subTest(i=i):
                file, digest = self.write(str(i) + ".json", item)
                with self.assertRaises(cli.RotationError):
                    apply._manifest(file, digest)
        file, digest = self.write("good.json", baseline)
        with self.assertRaises(cli.RotationError):
            apply._manifest(file, "f" * 32)
        with patch.object(apply.cli, "_private_dir", side_effect=cli.RotationError("bad-dir")):
            with self.assertRaises(cli.RotationError):
                apply._manifest(file, digest)

    def test_local_requires_root_exact_alias_and_stdin(self) -> None:
        file, sha = self.write("host.json", {**META, "type": "host-hash-only", "entry": dict(ENTRY)})
        with patch.object(apply.os, "geteuid", return_value=1):
            with self.assertRaises(cli.RotationError):
                apply.apply_local(file=file, sha256=sha, alias="demo-node-a")
        with patch.object(apply.os, "geteuid", return_value=0), \
             patch.object(apply.cli, "_private_dir"), \
             patch.object(apply.cli, "_read_file", side_effect=lambda p, **kw: p.read_bytes()), \
             patch.object(apply.socket, "gethostname", return_value="demo-node-a.example.invalid"), \
             patch.object(apply, "_run") as run:
            self.assertEqual(apply.apply_local(file=file, sha256=sha, alias="demo-node-a"),
                             "demo-node-a")
            args, kw = run.call_args
            self.assertEqual(args[0], ["/usr/sbin/chpasswd", "--encrypted"])
            self.assertEqual(kw["payload"], ("gateway:" + _HASH + "\n").encode())
            with self.assertRaises(cli.RotationError):
                apply.apply_local(file=file, sha256=sha, alias="demo-node-b")
        with patch.object(apply.os, "geteuid", return_value=0), \
             patch.object(apply.cli, "_private_dir"), \
             patch.object(apply.cli, "_read_file", side_effect=lambda p, **kw: p.read_bytes()), \
             patch.object(apply.socket, "gethostname", return_value="wrong"):
            with self.assertRaises(cli.RotationError):
                apply.apply_local(file=file, sha256=sha, alias="demo-node-a")

    def test_low_level_apply_run_fail_closed(self) -> None:
        with patch.object(apply.subprocess, "run",
                          return_value=SimpleNamespace(returncode=2, stdout=b"secret", stderr=b"secret")):
            with self.assertRaises(cli.RotationError):
                apply._run(["/usr/bin/false"])
        with patch.object(apply.subprocess, "run",
                          return_value=SimpleNamespace(returncode=0, stdout=b"safe")):
            self.assertEqual(apply._run(["/usr/bin/true"]), b"safe")

    def test_proxmox_rejects_root_count_and_controller(self) -> None:
        obj = {**META, "type": "proxmox-hash-only",
               "entries": [{**ENTRY, "vmid": 100}]}
        file, sha = self.write("proxmox.json", obj)
        with patch.object(apply.os, "geteuid", return_value=1):
            with self.assertRaises(cli.RotationError):
                apply.apply_proxmox(file=file, sha256=sha,
                                    controller_host="pre", expected_count=1)
        with patch.object(apply.os, "geteuid", return_value=0), \
             patch.object(apply.cli, "_private_dir"), \
             patch.object(apply.cli, "_read_file", side_effect=lambda p, **kw: p.read_bytes()), \
             patch.object(apply.socket, "gethostname", return_value="pre"):
            with self.assertRaises(cli.RotationError):
                apply.apply_proxmox(file=file, sha256=sha,
                                    controller_host="wrong", expected_count=1)
            with self.assertRaises(cli.RotationError):
                apply.apply_proxmox(file=file, sha256=sha,
                                    controller_host="pre", expected_count=2)
            with self.assertRaises(cli.RotationError):
                apply.apply_proxmox(file=file, sha256=sha,
                                    controller_host="pre", expected_count=0)

    def test_proxmox_rejects_inconclusive_guest_status(self) -> None:
        obj = {**META, "type": "proxmox-hash-only", "entries": [{**ENTRY, "vmid": 100}]}
        file, sha = self.write("guest.json", obj)
        for reply in (b"", b"invalid-json", b'{"exited":false}',
                      b'{"exited":1,"exitcode":42}', b'{"exited":1}'):
            with self.subTest(reply=reply), \
                 patch.object(apply.os, "geteuid", return_value=0), \
                 patch.object(apply.cli, "_private_dir"), \
                 patch.object(apply.cli, "_read_file", side_effect=lambda p, **kw: p.read_bytes()), \
                 patch.object(apply.socket, "gethostname", return_value="pre"):
                def run(argv: list[str], *, payload: bytes | None = None,
                        timeout: int = 30) -> bytes:
                    if argv[1] == "config":
                        return b"name: demo-node-a\n"
                    if argv[1:3] == ["guest", "cmd"]:
                        return b""
                    return reply
                with patch.object(apply, "_run", side_effect=run), \
                     self.assertRaises(cli.RotationError):
                    apply.apply_proxmox(file=file, sha256=sha,
                                        controller_host="pre", expected_count=1)

    def test_cli_arg_parsing_rejects_no_tty_and_reports_batch(self) -> None:
        args = ["batch-handoff",
                "--jenkins-file", "/tmp/deployment/ssh-mcp-secrets",
                "--inventory", "/tmp/inventory.json",
                "--vm-map", "/tmp/vm-map.json", "--workdir", "/tmp/work",
                "--deployment", "lab", "--issuer", "https://example.invalid",
                "--expected-source-sha256", "a" * 64,
                "--expected-inventory-sha256", "b" * 64,
                "--jenkins-container", "test-controller",
                "--jenkins-container-file", "/run/jenkins/secrets/deployment/ssh-mcp-secrets"]
        with patch.object(cli.sys.stdin, "isatty", return_value=False), \
             redirect_stderr(io.StringIO()) as err:
            self.assertEqual(cli.main(args), 1)
            self.assertIn("Sealed revision operation rejected", err.getvalue())
        synthetic_result = {"aliases": 2, "vm_count": 1,
                            "staged_sha256": "a" * 64, "hashes_sha256": "b" * 64,
                            "proxmox_sha256": "c" * 64, "hashes_path": "/tmp/secret-hashes",
                            "proxmox_path": "/tmp/proxmox-hashes", "hash_prefix": "/tmp/host-"}
        with patch.object(cli.sys.stdin, "isatty", return_value=True), \
             patch.object(cli.sys.stderr, "isatty", return_value=True), \
             patch.object(batch, "batch_handoff", return_value=synthetic_result), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main(args), 0)
            self.assertIn("BATCH_HANDOFF=COMMITTED", out.getvalue())
            self.assertNotIn(_HASH, out.getvalue())

    def test_apply_cli_dispatch_and_failure(self) -> None:
        with patch.object(apply, "apply_local", return_value="demo-node-a"), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(apply.main(["local", "--file", "/tmp/hashes",
                                         "--expected-sha256", "a" * 64,
                                         "--alias", "demo-node-a"]), 0)
            self.assertIn("LOCAL_APPLIED=demo-node-a", out.getvalue())
        with patch.object(apply, "apply_proxmox", return_value=["demo-node-a"]), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(apply.main(["proxmox", "--file", "/tmp/hashes",
                                         "--expected-sha256", "a" * 64,
                                         "--controller-host", "pre",
                                         "--expected-count", "1"]), 0)
            self.assertIn("PROXMOX_APPLIED=1", out.getvalue())
        with patch.object(apply, "apply_local", side_effect=cli.RotationError("synthetic")), \
             redirect_stderr(io.StringIO()) as err:
            self.assertEqual(apply.main(["local", "--file", "/tmp/hashes",
                                         "--expected-sha256", "a" * 64,
                                         "--alias", "demo-node-a"]), 1)
            self.assertIn("Hash-only password operation rejected", err.getvalue())


if __name__ == "__main__":
    unittest.main()
