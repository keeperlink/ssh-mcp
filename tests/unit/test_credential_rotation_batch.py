"""Synthetic, offline checks for batch batch sealed credential tooling."""
from __future__ import annotations

from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.sealed_credentials import from_legacy, unseal_sudo, verify_password
from ssh_mcp_secrets import apply, batch, cli

CONSOLE = "synthetic-console-password-for-offline-tests"
NEW_CONSOLE = "synthetic-new-console-password-for-tests"
OAUTH = "synthetic-old-oauth-" + "o" * 36
NEW_OAUTH = "synthetic-new-oauth-" + "a" * 36
ISSUER = "https://example.invalid"
HOSTS = {"demo-node-a": "gateway", "demo-node-b": "gateway"}
BIND = {"deployment": "lab", "issuer": ISSUER}
LEGACY = {
    "version": 1, "oauth_login_key": OAUTH,
    "viewer_password": CONSOLE,
    "oauth_signing_key": "synthetic-signing-" + "x" * 40,
    "metrics_token": "synthetic-metrics-" + "m" * 40,
    "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                       + "a" * 96 + "\n-----END OPENSSH PRIVATE KEY-----",
    "sudo_passwords": {"demo-node-a": "synthetic-old-node-a",
                       "demo-node-b": "synthetic-old-node-b"},
}


class BatchRotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = from_legacy(LEGACY, console_password=CONSOLE, hosts=HOSTS, **BIND)

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="synthetic-sky360-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)

    def _generate(self) -> tuple[dict[str, object], dict[str, str]]:
        return batch._generate(self.source, hosts=HOSTS,
                               old_oauth=OAUTH, new_oauth=NEW_OAUTH,
                               old_console=CONSOLE, new_console=NEW_CONSOLE, **BIND)

    def _file(self, name: str, body: dict[str, object]) -> tuple[Path, str]:
        file = self.root / name
        file.write_text(json.dumps(body) + "\n")
        file.chmod(0o600)
        return file, hashlib.sha256(file.read_bytes()).hexdigest()

    def test_generate_all_unique_recoverable_envelopes(self) -> None:
        result, secrets = self._generate()
        self.assertEqual(set(secrets), set(HOSTS))
        self.assertEqual(len(set(secrets.values())), len(HOSTS))
        self.assertTrue(all(len(s) >= 48 for s in secrets.values()))
        self.assertTrue(verify_password(NEW_OAUTH, result["oauth_login_verifier"], "oauth-login"))
        self.assertFalse(verify_password(OAUTH, result["oauth_login_verifier"], "oauth-login"))
        self.assertTrue(verify_password(NEW_CONSOLE, result["viewer_verifier"], "console-login"))
        self.assertFalse(verify_password(CONSOLE, result["viewer_verifier"], "console-login"))
        self.assertEqual(result["metrics_verifier"], self.source["metrics_verifier"])
        self.assertEqual(result["oauth_signing_key"], self.source["oauth_signing_key"])
        self.assertEqual(result["ssh_private_key"], self.source["ssh_private_key"])
        self.assertNotEqual(result["viewer_generation"], self.source["viewer_generation"])
        for alias in HOSTS:
            self.assertEqual(secrets[alias], unseal_sudo(
                NEW_CONSOLE, result["sealed_sudo"][alias],
                alias=alias, username="gateway", **BIND))

    def test_wrong_credentials_rejected_without_output(self) -> None:
        with self.assertRaises(cli.RotationError):
            batch._generate(self.source, hosts=HOSTS, old_oauth="wrong",
                            new_oauth=NEW_OAUTH, old_console=CONSOLE,
                            new_console=NEW_CONSOLE, **BIND)
        with self.assertRaises(cli.RotationError):
            batch._generate(self.source, hosts=HOSTS, old_oauth=OAUTH,
                            new_oauth=NEW_OAUTH, old_console="wrong",
                            new_console=NEW_CONSOLE, **BIND)
        with self.assertRaises(cli.RotationError):
            batch._generate(self.source, hosts=HOSTS, old_oauth=OAUTH,
                            new_oauth=NEW_OAUTH, old_console=CONSOLE,
                            new_console=NEW_OAUTH, **BIND)

    def test_reused_operator_passwords_and_rng_collision_fail_closed(self) -> None:
        for overrides in (
            {"new_oauth": OAUTH},
            {"new_console": CONSOLE},
            {"new_oauth": CONSOLE},
            {"new_console": OAUTH},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(cli.RotationError):
                settings = {"old_oauth": OAUTH, "new_oauth": NEW_OAUTH,
                            "old_console": CONSOLE, "new_console": NEW_CONSOLE}
                settings.update(overrides)
                batch._generate(self.source, hosts=HOSTS, **settings, **BIND)
        with patch.object(batch.secrets, "token_urlsafe", return_value="synthetic-collision"), \
             self.assertRaises(cli.RotationError):
            self._generate()

    def test_signed_host_binding_requires_exact_alias_set(self) -> None:
        for mapping in ({}, {"demo-node-a": "gateway"},
                        {**HOSTS, "unknown-node": "gateway"}):
            with self.subTest(mapping=mapping), self.assertRaises(cli.RotationError):
                batch._generate(self.source, hosts=mapping, old_oauth=OAUTH,
                                new_oauth=NEW_OAUTH, old_console=CONSOLE,
                                new_console=NEW_CONSOLE, **BIND)

    def test_hashes_are_salted_linux_crypt_verifiers(self) -> None:
        first = batch._hash_sudo("synthetic-only-sudo-password")
        second = batch._hash_sudo("synthetic-only-sudo-password")
        self.assertRegex(first, batch._HASH)
        self.assertRegex(second, batch._HASH)
        self.assertNotEqual(first, second)
        self.assertNotIn("synthetic-only", first)

    def test_vm_map_rejects_duplicates_or_extra_aliases(self) -> None:
        for mapping in ({"demo-node-a": 100, "demo-node-b": 100},
                        {"demo-node-a": True},
                        {"unknown-node": 100}):
            with self.subTest(mapping=mapping):
                source, _ = self._file("map.json", {"version": 1, "vmids": mapping})
                with self.assertRaises(cli.RotationError):
                    batch._vm_map(source, HOSTS)

    def test_vm_map_rejects_untrusted_document_shapes(self) -> None:
        for i, document in enumerate((
            {"version": 2, "vmids": {}},
            {"version": 1, "vmids": []},
            {"version": 1, "vmids": {}},
            {"version": 1, "vmids": {"demo-node-a": 99}},
            {"version": 1, "vmids": {"demo-node-a": 100}, "unexpected": 1},
        )):
            with self.subTest(index=i):
                file, _ = self._file("bad-vm-map.json", document)
                with self.assertRaises(cli.RotationError):
                    batch._vm_map(file, HOSTS)

    def test_manifest_exact_sha_and_target_schema(self) -> None:
        sample = batch._hash_sudo("synthetic-node-password")
        fields = {"version": 1, "type": "host-hash-only",
                  "source_sha256": "a" * 64, "staged_sha256": "b" * 64,
                  "inventory_sha256": "c" * 64,
                  "entry": {"alias": "demo-node-a", "username": "gateway", "hash": sample}}
        file, digest = self._file("host.json", fields)
        self.assertEqual(apply._manifest(file, digest)["entry"]["alias"], "demo-node-a")
        with self.assertRaises(cli.RotationError):
            apply._manifest(file, "0" * 64)
        fields["entry"]["username"] = "root"
        file, digest = self._file("other.json", fields)
        with self.assertRaises(cli.RotationError):
            apply._manifest(file, digest)

    def test_proxmox_applies_only_after_all_guests_verified(self) -> None:
        entries = [{"vmid": 100, "alias": "demo-node-a", "username": "gateway",
                    "hash": batch._hash_sudo("synthetic-one")},
                   {"vmid": 200, "alias": "demo-node-b", "username": "gateway",
                    "hash": batch._hash_sudo("synthetic-two")}]
        fields = {"version": 1, "type": "proxmox-hash-only",
                  "source_sha256": "a" * 64, "staged_sha256": "b" * 64,
                  "inventory_sha256": "c" * 64, "entries": entries}
        file, digest = self._file("vm.json", fields)
        commands: list[tuple[list[str], bytes | None]] = []

        def run(argv: list[str], *, payload: bytes | None = None, timeout: int = 30) -> bytes:
            commands.append((argv, payload))
            if argv[1] == "config":
                return ("name: " + ("demo-node-a" if argv[2] == "100"
                                     else "demo-node-b") + "\n").encode()
            if argv[1:3] == ["guest", "cmd"]:
                return b""
            return b'{"exited":1,"exitcode":0}'

        with patch.object(apply.os, "geteuid", return_value=0), \
             patch.object(apply.cli, "_private_dir"), \
             patch.object(apply.cli, "_read_file", side_effect=lambda p, **kw: p.read_bytes()), \
             patch.object(apply.socket, "gethostname", return_value="pre.example.invalid"), \
             patch.object(apply, "_run", side_effect=run):
            self.assertEqual(apply.apply_proxmox(file=file, sha256=digest,
                                                  controller_host="pre", expected_count=2),
                             ["demo-node-a", "demo-node-b"])
        self.assertEqual([c[0][1] for c in commands], ["config", "guest", "config", "guest", "guest", "guest"])
        for argv, payload in commands:
            self.assertFalse(any("$6$" in token for token in argv))
            if payload is not None:
                self.assertIn(b"gateway:$6$", payload)

    def _mock_batch_handoff(
        self, *, check_readback: bool = True,
        postcheck_error: Exception | None = None,
        readback_error: Exception | None = None,
        destination_error: Exception | None = None,
        aliases: tuple[str, ...] = ("demo-node-a", "demo-node-b"),
    ) -> tuple[dict[str, object], Path]:
        directory = self.root / "deployment"
        directory.mkdir()
        (self.root / "output").mkdir()
        source = directory / "ssh-mcp-secrets"
        hosts = {alias: "gateway" for alias in aliases}
        secret = from_legacy(
            {**LEGACY, "sudo_passwords": {a: "synthetic-old-sudo-" + a for a in aliases}},
            console_password=CONSOLE, hosts=hosts, **BIND,
        )
        source.write_text(json.dumps(secret, sort_keys=True) + "\n")
        source.chmod(0o640)
        inventory, inv_sha = self._file("inventory.json", {
            "version": 1,
            "hosts": [{"alias": a, "username": "gateway"} for a in aliases],
        })
        vm_map, _ = self._file("vm-map.json", {
            "version": 1, "vmids": {a: 100 + i for i, a in enumerate(aliases)},
        })
        original = hashlib.sha256(source.read_bytes()).hexdigest()
        workdir = self.root / "output"
        prompts = [OAUTH, NEW_OAUTH, NEW_OAUTH, CONSOLE, NEW_CONSOLE, NEW_CONSOLE]
        def readback(_name: str, _file: str, expected: str) -> None:
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), expected)
            if postcheck_error is not None:
                raise postcheck_error
            if not check_readback:
                raise cli.CommitUncertain("Synthetic readback failure")
        def trusted(path: Path) -> bytes:
            content = path.read_bytes()
            if readback_error is not None and hashlib.sha256(content).hexdigest() != original:
                raise readback_error
            return content
        with patch.object(batch.os, "geteuid", return_value=0), \
             patch.object(batch.os, "fchown", side_effect=destination_error), \
             patch.object(batch, "_trusted_jenkins", side_effect=trusted), \
             patch.object(batch.cli, "_locked", return_value=nullcontext()), \
             patch.object(batch.cli, "_private_dir"), \
             patch.object(batch.cli, "_read_file", side_effect=lambda path, **kw: path.read_bytes()), \
             patch.object(batch.getpass, "getpass", side_effect=prompts), \
             patch.object(batch, "_postcheck_container", side_effect=readback):
            if not check_readback:
                with self.assertRaises(cli.CommitUncertain):
                    batch.batch_handoff(jenkins_file=source, inventory=inventory,
                                        vm_map=vm_map, workdir=workdir,
                                        deployment="lab", issuer=ISSUER,
                                        expected_source=original,
                                        expected_inventory=inv_sha,
                                        container="synthetic-controller",
                                        container_file="/run/jenkins/secrets/deployment/ssh-mcp-secrets")
                return {}, source
            result = batch.batch_handoff(jenkins_file=source, inventory=inventory,
                                         vm_map=vm_map, workdir=workdir,
                                         deployment="lab", issuer=ISSUER,
                                         expected_source=original,
                                         expected_inventory=inv_sha,
                                         container="synthetic-controller",
                                         container_file="/run/jenkins/secrets/deployment/ssh-mcp-secrets")
        return result, source

    def test_one_session_handoff_generates_sealed_and_hash_exports(self) -> None:
        result, jenkins = self._mock_batch_handoff()
        self.assertEqual(result["aliases"], len(HOSTS))
        self.assertEqual(result["vm_count"], 2)
        self.assertEqual(hashlib.sha256(jenkins.read_bytes()).hexdigest(), result["staged_sha256"])
        self.assertTrue(verify_password(NEW_OAUTH, json.loads(jenkins.read_text())["oauth_login_verifier"],
                                        "oauth-login"))
        workdir = self.root / "output"
        files = list(workdir.iterdir())
        self.assertEqual(len(files), 6)
        self.assertTrue(all((p.stat().st_mode & 0o777) == 0o600 for p in files))
        for path in files:
            data = path.read_bytes()
            self.assertNotIn(NEW_CONSOLE.encode(), data)
            self.assertNotIn(NEW_OAUTH.encode(), data)
            self.assertNotIn(b"synthetic-old-node", data)
        hashes = json.loads(Path(str(result["hashes_path"])).read_text())
        self.assertEqual(len(hashes["entries"]), 2)
        self.assertTrue(all(batch._HASH.fullmatch(e["hash"]) for e in hashes["entries"]))

    def test_uncertain_controller_readback_leaves_committed_revision(self) -> None:
        _, jenkins = self._mock_batch_handoff(check_readback=False)
        saved = json.loads(jenkins.read_text())
        self.assertTrue(verify_password(NEW_CONSOLE, saved["viewer_verifier"], "console-login"))
        self.assertTrue(any((self.root / "output").iterdir()))

    def test_reserved_aliases_do_not_replace_batch_exports(self) -> None:
        aliases = ("proxmox", "plan", "sealed", "hashes")
        result, _ = self._mock_batch_handoff(aliases=aliases)
        workdir = self.root / "output"
        self.assertEqual(len(list(workdir.iterdir())), 4 + len(aliases))
        data = json.loads(Path(str(result["proxmox_path"])).read_text())
        self.assertEqual(data["type"], "proxmox-hash-only")
        for alias in aliases:
            file = workdir / (Path(str(result["hash_prefix"])).name + ".host." + alias + ".json")
            self.assertEqual(json.loads(file.read_text())["type"], "host-hash-only")

    def test_postcommit_errors_always_report_uncertain(self) -> None:
        import subprocess
        for error_kind, error in (
            ("docker-io", OSError("synthetic docker unavailable")),
            ("docker-timeout", subprocess.TimeoutExpired(["docker"], 2)),
            ("postcheck-validation", cli.RotationError("synthetic validation failure")),
            ("source-readback", OSError("synthetic source readback failure")),
        ):
            with self.subTest(error_kind=error_kind):
                # Distinct directories to avoid carrying an altered source
                # between independent synthetic postcommit failures.
                self.tmp.cleanup()
                self.tmp = tempfile.TemporaryDirectory(prefix="synthetic-postcommit-")
                self.addCleanup(self.tmp.cleanup)
                self.root = Path(self.tmp.name)
                self.root.chmod(0o700)
                with self.assertRaises(cli.CommitUncertain):
                    if error_kind == "source-readback":
                        self._mock_batch_handoff(readback_error=error)
                    else:
                        self._mock_batch_handoff(postcheck_error=error)
                self.assertTrue(verify_password(
                    NEW_OAUTH,
                    json.loads((self.root / "deployment" / "ssh-mcp-secrets").read_text())[
                        "oauth_login_verifier"],
                    "oauth-login",
                ))

    def test_precommit_jenkins_temp_file_removed_on_write_failure(self) -> None:
        with self.assertRaises(OSError):
            self._mock_batch_handoff(destination_error=OSError("synthetic chown failure"))
        deployment = self.root / "deployment"
        self.assertEqual([p.name for p in deployment.iterdir()], ["ssh-mcp-secrets"])
        self.assertTrue(verify_password(
            OAUTH, json.loads((deployment / "ssh-mcp-secrets").read_text())["oauth_login_verifier"],
            "oauth-login",
        ))

    def test_batch_uses_checked_inventory_bytes_not_second_file_read(self) -> None:
        with patch.object(batch.cli, "_read_inventory", side_effect=AssertionError("unsafe inventory reread")):
            result, _ = self._mock_batch_handoff()
        self.assertEqual(result["aliases"], 2)

    def test_proxmox_identity_preflight_blocks_writes(self) -> None:
        fields = {"version": 1, "type": "proxmox-hash-only",
                  "source_sha256": "a" * 64, "staged_sha256": "b" * 64,
                  "inventory_sha256": "c" * 64,
                  "entries": [{"alias": "demo-node-a", "username": "gateway", "vmid": 100,
                               "hash": batch._hash_sudo("synthetic")}]}
        file, digest = self._file("incorrect.json", fields)
        with patch.object(apply.os, "geteuid", return_value=0), \
             patch.object(apply.cli, "_private_dir"), \
             patch.object(apply.cli, "_read_file", side_effect=lambda p, **kw: p.read_bytes()), \
             patch.object(apply.socket, "gethostname", return_value="pre"), \
             patch.object(apply, "_run", return_value=b"name: unexpected\n") as run:
            with self.assertRaises(cli.RotationError):
                apply.apply_proxmox(file=file, sha256=digest, controller_host="pre",
                                    expected_count=1)
            self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
