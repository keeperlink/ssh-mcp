"""Standalone, secret-free assertions for three signed mounts + private secret."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from app.runtime_files import prepare, managed_secrets_fingerprint
from app.sealed_credentials import from_legacy

ROOT = Path(__file__).resolve().parents[2]


def fixture_secret():
    return {
        "version": 1,
        "oauth_login_key": "synthetic-login-" + "a" * 40,
        "oauth_signing_key": "synthetic-signing-" + "b" * 40,
        "viewer_password": "synthetic-viewer-" + "c" * 40,
        "metrics_token": "synthetic-metrics-" + "d" * 40,
        "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                           "SYNTHETIC-NOT-USABLE\n-----END OPENSSH PRIVATE KEY-----\n",
    }


class SignedConfigurationTests(unittest.TestCase):
    def test_v2_secrets_emit_only_verifiers_and_seal_sudo(self):
        original = {**fixture_secret(), "sudo_passwords": {"demo-node-b": "synthetic-sudo-value"}}
        converted = from_legacy(
            original, console_password=original["viewer_password"],
            deployment=self.settings["environment"], issuer=self.settings["oauth"]["issuer"],
            hosts={"demo-node-b": "gateway"},
        )
        self.write(self.secrets, converted, 0o600)
        env = self.prepare()
        self.assertEqual(env["MCP_MANAGED_SECRETS_VERSION"], "2")
        self.assertEqual(env["MCP_MANAGED_SECRETS_SOURCE"], str(self.secrets.absolute()))
        self.assertEqual(env["MCP_MANAGED_SECRETS_DIGEST"],
                         managed_secrets_fingerprint(converted))
        self.assertEqual(env["HISTORY_VIEWER_GENERATION"], converted["viewer_generation"])
        self.assertEqual(json.loads(env["MCP_LOGIN_VERIFIER"]), converted["oauth_login_verifier"])
        self.assertEqual(json.loads(env["HISTORY_VIEWER_VERIFIER"]), converted["viewer_verifier"])
        self.assertEqual(json.loads(env["MCP_METRICS_VERIFIER"]), converted["metrics_verifier"])
        for field in ("MCP_LOGIN_KEY", "HISTORY_VIEWER_PASSWORD", "MCP_METRICS_TOKEN"):
            self.assertNotIn(field, env)
        output = json.dumps(env) + (self.target / "inventory.json").read_text()
        for secret in (original["oauth_login_key"], original["viewer_password"],
                       original["metrics_token"], original["sudo_passwords"]["demo-node-b"]):
            self.assertNotIn(secret, output)
        self.assertEqual({p.name for p in self.target.iterdir()}, {"identity", "inventory.json"})

    def test_v2_invalid_verifier_fails_before_private_file_creation(self):
        original = fixture_secret()
        converted = from_legacy(
            original, console_password=original["viewer_password"],
            deployment=self.settings["environment"], issuer=self.settings["oauth"]["issuer"],
            hosts={"demo-node-b": "gateway"},
        )
        converted["oauth_login_verifier"]["iterations"] = 100000
        self.write(self.secrets, converted, 0o600)
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(list(self.target.iterdir()), [])

    def test_managed_v2_rejects_duplicate_members_at_any_level(self):
        original = fixture_secret()
        converted = from_legacy(
            original, console_password=original["viewer_password"],
            deployment=self.settings["environment"], issuer=self.settings["oauth"]["issuer"],
            hosts={"demo-node-b": "gateway"},
        )
        converted["sealed_sudo"] = {
            "demo-node-b": from_legacy(
                {**original, "sudo_passwords": {"demo-node-b": "synthetic-sudo"}},
                console_password=original["viewer_password"],
                deployment=self.settings["environment"],
                issuer=self.settings["oauth"]["issuer"],
                hosts={"demo-node-b": "gateway"},
            )["sealed_sudo"]["demo-node-b"]
        }
        prepared = json.dumps(converted)
        for index, malformed in enumerate((
            prepared.replace('"version": 2', '"version": 1, "version": 2', 1),
            prepared.replace('"algorithm": "argon2id"',
                             '"algorithm": "unknown", "algorithm": "argon2id"', 1),
            prepared.replace('"ciphertext": ', '"ciphertext": "bad", "ciphertext": ', 1),
        )):
            with self.subTest(index=index):
                self.secrets.write_text(malformed)
                target = self.root / f"duplicate-v2-{index}"
                target.mkdir(mode=0o700)
                with self.assertRaisesRegex(ValueError, "Invalid mounted JSON"):
                    prepare(self.config, self.secrets, self.inventory, self.known, target)
                self.assertEqual(list(target.iterdir()), [])

    def test_v2_config_accepts_only_sealed_verifiers_and_rejects_mixed_mode(self):
        from app import config
        original = fixture_secret()
        converted = from_legacy(
            original, console_password=original["viewer_password"],
            deployment=self.settings["environment"], issuer=self.settings["oauth"]["issuer"],
            hosts={"demo-node-b": "gateway"},
        )
        with (patch.multiple(
            config,
            MCP_MANAGED_SECRETS_VERSION="2", MCP_LOGIN_KEY="",
            MCP_TOKEN_SIGNING_SECRET=original["oauth_signing_key"],
            MCP_ISSUER=self.settings["oauth"]["issuer"],
            MCP_RESOURCE=self.settings["oauth"]["issuer"] + "/mcp",
            MCP_LOGIN_VERIFIER=converted["oauth_login_verifier"],
            HISTORY_VIEWER_VERIFIER=converted["viewer_verifier"],
            HISTORY_VIEWER_GENERATION=converted["viewer_generation"],
            MCP_METRICS_VERIFIER=converted["metrics_verifier"],
        ), patch.dict(os.environ, {"HISTORY_VIEWER_PASSWORD": "", "MCP_METRICS_TOKEN": ""})):
            self.assertTrue(config.SEALED_RUNTIME_READY)
            config.validate_mcp_config()
            with patch.object(config, "SEALED_RUNTIME_READY", False):
                with self.assertRaisesRegex(RuntimeError, "activation disabled"):
                    config.validate_mcp_config()
            with patch.object(config, "SEALED_RUNTIME_READY", True):
                with patch.object(config, "MCP_LOGIN_KEY", original["oauth_login_key"]):
                    with self.assertRaisesRegex(RuntimeError, "must not load plaintext"):
                        config.validate_mcp_config()
                with patch.object(config, "MCP_LOGIN_VERIFIER", {"algorithm": "unknown"}):
                    with self.assertRaises(ValueError):
                        config.validate_mcp_config()
                with patch.object(config, "HISTORY_VIEWER_GENERATION", "invalid"):
                    with self.assertRaisesRegex(RuntimeError, "generation"):
                        config.validate_mcp_config()


    def test_privileged_access_policy_is_opt_in_and_signed(self):
        doc = json.loads(self.inventory.read_text())
        # Existing signed inventories remain valid but normalized as no sudo.
        self.prepare()
        normalized = json.loads((self.target / "inventory.json").read_text())
        self.assertEqual(normalized["hosts"][0]["privileged_access"], "none")
        for policy in ("none", "restricted", "always-granted"):
            with self.subTest(policy=policy):
                doc["hosts"][0]["privileged_access"] = policy
                self.write(self.inventory, doc)
                target = self.root / f"policy-{policy}"
                target.mkdir(mode=0o700)
                prepare(self.config, self.secrets, self.inventory, self.known, target)
                normalized = json.loads((target / "inventory.json").read_text())
                self.assertEqual(normalized["hosts"][0]["privileged_access"], policy)
        for index, bad in enumerate(("sudo", "always", None, True)):
            with self.subTest(bad=bad):
                doc["hosts"][0]["privileged_access"] = bad
                self.write(self.inventory, doc)
                target = self.root / f"bad-policy-{index}"
                target.mkdir(mode=0o700)
                with self.assertRaises(ValueError):
                    prepare(self.config, self.secrets, self.inventory, self.known, target)
                self.assertEqual(list(target.iterdir()), [])

    def test_optional_per_host_sudo_credentials_are_private_and_nonfatal(self):
        password = "synthetic-not-a-real-password"
        for index, value in enumerate(({}, {"demo-node-b": password},
                                       {"demo-node-b": ""}, {"demo-node-b": 12})):
            with self.subTest(value_type=type(value.get("demo-node-b")).__name__):
                self.write(self.secrets, {**fixture_secret(), "sudo_passwords": value}, 0o600)
                target = self.root / f"sudo-secret-{index}"
                target.mkdir(mode=0o700)
                result = prepare(self.config, self.secrets, self.inventory, self.known, target)
                self.assertNotIn("sudo_passwords", result)
                self.assertNotIn(password, json.dumps(result))
                self.assertNotIn(password, (target / "inventory.json").read_text())
                self.assertEqual({p.name for p in target.iterdir()}, {"identity", "inventory.json"})
        for index, invalid in enumerate(([], None, "password", {"invalid.alias": "pw"})):
            with self.subTest(invalid=invalid):
                self.write(self.secrets, {**fixture_secret(), "sudo_passwords": invalid}, 0o600)
                target = self.root / f"bad-secret-{index}"
                target.mkdir(mode=0o700)
                with self.assertRaises(ValueError):
                    prepare(self.config, self.secrets, self.inventory, self.known, target)
                self.assertEqual(list(target.iterdir()), [])

    def test_removed_signed_host_does_not_block_ordinary_ssh(self):
        # private secrets can lag signed inventory changes. A stale, valid
        # alias has no policy grant and must not take down remaining hosts.
        value = {"demo-node-b": "synthetic-current", "removed-host": "synthetic-stale"}
        self.write(self.secrets, {**fixture_secret(), "sudo_passwords": value}, 0o600)
        result = self.prepare()
        self.assertEqual(result["SSH_APPROVED_ALIASES"], "demo-node-b")
        inventory = (self.target / "inventory.json").read_text()
        self.assertNotIn("removed-host", inventory)
        self.assertNotIn("synthetic-stale", inventory)
        self.assertNotIn("sudo_passwords", json.dumps(result))

    def test_missing_signed_host_access_fails_closed(self):
        item = json.loads(self.inventory.read_text())
        del item["hosts"][0]["access"]
        self.write(self.inventory, item)
        with self.assertRaises(ValueError):
            self.prepare()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.config = self.root / "service.json"
        self.secrets = self.root / "secrets.json"
        self.inventory = self.root / "inventory.json"
        self.known = self.root / "known_hosts"
        self.target = self.root / "private"
        self.target.mkdir(mode=0o700)
        self.settings = json.loads((ROOT / "deploy/service.example.json").read_text())
        self.write(self.config, self.settings)
        self.write(self.secrets, fixture_secret(), 0o600)
        self.write(self.inventory, {"version": 1, "hosts": [{
            "alias": "demo-node-b", "address": "192.0.2.44", "port": 22,
            "username": "gateway", "principals": ["ssh-mcp-operator"],
            "environment": "non-production", "access": "always-granted", "max_parallel": 1,
        }]})
        self.known.write_text("192.0.2.44 ssh-ed25519 SYNTHETIC_KEY_NOT_VALID\n")
        self.known.chmod(0o644)

    @staticmethod
    def write(path, value, mode=0o644):
        path.write_text(json.dumps(value))
        path.chmod(mode)

    def prepare(self):
        return prepare(self.config, self.secrets, self.inventory, self.known, self.target)

    def test_optional_signed_host_relay_limits_and_defaults(self):
        from app.runtime_files import _valid_settings

        _valid_settings(self.settings)
        custom = {**self.settings, "transfer": {
            "max_bytes": 256 * 1024, "chunk_bytes": 4096,
        }}
        _valid_settings(custom)
        self.write(self.config, custom)
        env = self.prepare()
        self.assertEqual(env["SSH_TRANSFER_MAX_BYTES"], "262144")
        self.assertEqual(env["SSH_TRANSFER_CHUNK_BYTES"], "4096")
        self.assertEqual(
            {p.name for p in self.target.iterdir()},
            {"identity", "inventory.json"},
        )

    def test_signed_relay_rejects_invalid_limits_before_private_mount(self):
        from app.runtime_files import _valid_settings

        for limits in (
            None, False, 17, "", [], {},
            {"max_bytes": True, "chunk_bytes": 4096},
            {"max_bytes": 1073741824, "chunk_bytes": False},
            {"max_bytes": 0, "chunk_bytes": 4096},
            {"max_bytes": -1, "chunk_bytes": 4096},
            {"max_bytes": 4 * 1024**3 + 1, "chunk_bytes": 4096},
            {"max_bytes": 65536, "chunk_bytes": 4095},
            {"max_bytes": 65536, "chunk_bytes": 4194305},
            {"max_bytes": 4096, "chunk_bytes": 8192},
            {"max_bytes": 1073741824, "chunk_bytes": 262144, "other": 1},
            {"max_bytes": 1073741824},
        ):
            with self.subTest(limits=limits):
                malformed = {**self.settings, "transfer": limits}
                with self.assertRaisesRegex(ValueError, "Invalid signed SSH transfer"):
                    _valid_settings(malformed)
        self.assertEqual(list(self.target.iterdir()), [])

    def test_signed_settings_and_single_secret(self):
        result = self.prepare()
        self.assertEqual(result["MCP_ENVIRONMENT"], "production")
        self.assertEqual(result["MCP_ISSUER"], "https://mcp.example.com")
        self.assertEqual(result["MCP_OPERATOR_SUBJECT"], "ssh-mcp-operator")
        self.assertEqual(result["MCP_LOGIN_KEY"], fixture_secret()["oauth_login_key"])
        self.assertEqual(result["SSH_MAX_TIMEOUT_SECONDS"], "900")
        self.assertEqual(result["HISTORY_STORY_ID_MAX_CHARS"], "16")
        self.assertEqual(result["HISTORY_STORY_ID_TRUNCATE_FROM"], "end")
        self.assertNotIn("SSH_FILE_SOURCE_ALLOWED_HOSTS", result)
        self.assertEqual(result["SSH_OUTPUT_LIMIT_BYTES"], "262144")
        self.assertEqual(result["SSH_MAX_ARGUMENT_BYTES"], "32768")
        self.assertNotIn("MCP_SSH_LOGIN_KEY", result)
        self.assertEqual(result["SSH_APPROVED_ALIASES"], "demo-node-b")
        self.assertEqual(stat.S_IMODE((self.target / "identity").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.target / "inventory.json").stat().st_mode), 0o600)
        hosts = json.loads((self.target / "inventory.json").read_text())["hosts"]
        self.assertEqual(hosts[0]["known_hosts_file"], str(self.known))
        self.assertEqual(hosts[0]["identity_file"], str(self.target / "identity"))
        with self.assertRaisesRegex(ValueError, "Unsafe private runtime"):
            self.prepare()

    def test_signed_environment_is_explicit_validated_and_reusable(self):
        from app.runtime_files import _valid_settings

        lab = {**self.settings, "environment": "lab"}
        _valid_settings(lab)
        self.write(self.config, lab)
        self.assertEqual(self.prepare()["MCP_ENVIRONMENT"], "lab")
        for bad in ("prod", "test", "LAB", "", None, 1, True, [], {}):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(ValueError, "Invalid service environment"):
                    _valid_settings({**self.settings, "environment": bad})
        missing = dict(self.settings)
        del missing["environment"]
        with self.assertRaisesRegex(ValueError, "Invalid service setting schema"):
            _valid_settings(missing)

    def test_logging_level_defaults_and_signed_value(self):
        from app.runtime_files import _valid_settings

        for bad in (None, {}, {"level": "TRACE"}, {"level": True},
                    {"level": "INFO", "extra": True}):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(ValueError, "Invalid logging settings"):
                    _valid_settings({**self.settings, "logging": bad})
        legacy = dict(self.settings)
        legacy.pop("logging", None)
        self.write(self.config, legacy)
        self.assertEqual(self.prepare()["MCP_LOG_LEVEL"], "INFO")
        target = self.root / "debug-runtime"
        target.mkdir(mode=0o700)
        self.write(self.config, {**self.settings, "logging": {"level": "DEBUG"}})
        self.assertEqual(prepare(self.config, self.secrets, self.inventory, self.known, target)["MCP_LOG_LEVEL"], "DEBUG")

    def test_obsolete_file_source_allowlist_removed_from_signed_schema(self):
        from app.runtime_files import _valid_settings
        for env in ("lab", "production"):
            with self.subTest(environment=env):
                _valid_settings({**self.settings, "environment": env})
        for policy in (
            {"source_allowed_hosts": ["files.oaiusercontent.com"]},
            {"source_allowed_hosts": []},
            {}, None, True, "files.oaiusercontent.com",
        ):
            with self.subTest(policy=policy):
                entry = {**self.settings, "file_transfer": policy}
                self.write(self.config, entry)
                with self.assertRaisesRegex(ValueError, "Invalid service setting schema"):
                    self.prepare()
                self.assertEqual(list(self.target.iterdir()), [])

    def test_fail_closed_secrets_and_unsigned_permissions(self):
        for bad in (
            {"oauth_login_key": "short"}, {"oauth_signing_key": fixture_secret()["oauth_login_key"]},
            {"metrics_token": "short"}, {"ssh_private_key": "bad"}, {"unused": "any"},
        ):
            with self.subTest(bad=bad):
                doc = {**fixture_secret(), **bad}
                self.write(self.secrets, doc, 0o600)
                with self.assertRaises(ValueError):
                    self.prepare()
                self.assertEqual(list(self.target.iterdir()), [])
        self.write(self.secrets, fixture_secret(), 0o666)
        with self.assertRaises(ValueError):
            self.prepare()

    def test_configurable_timeout_accepts_10_hours(self):
        settings = json.loads(json.dumps(self.settings))
        settings["ssh"]["max_timeout_seconds"] = 36000
        self.write(self.config, settings)
        result = self.prepare()
        self.assertEqual(result["SSH_MAX_TIMEOUT_SECONDS"], "36000")
        self.assertEqual(result["SSH_DEFAULT_TIMEOUT_SECONDS"], "60")
        # Load the runtime contracts in a fresh process: Pydantic binds the
        # configured maximum at import, not when the request is constructed.
        env = os.environ.copy()
        for key in ("MCP_CONFIG_FILE", "MCP_INVENTORY_FILE",
                    "MCP_KNOWN_HOSTS_FILE", "MCP_SECRETS_FILE"):
            env.pop(key, None)
        env.update(result)
        script = """
from pydantic import ValidationError
from app import config
from app.contracts import ExecuteCommandRequest, ExecuteCommandsRequest
from app.mcp_gateway import SSH_TOOLS

assert config.SSH_MAX_TIMEOUT_SECONDS == 36000
assert config.SSH_DEFAULT_TIMEOUT_SECONDS == 60
config.validate_mcp_config()
args = dict(server="demo-node-b", argv=["hostname"], reason="TEST-280 bounds")
assert ExecuteCommandRequest(**args, timeout_seconds=36000).timeout_seconds == 36000
try:
    ExecuteCommandRequest(**args, timeout_seconds=36001)
except ValidationError:
    pass
else:
    raise AssertionError("10-hour command safety ceiling was not enforced")
batch = dict(server="demo-node-b", reason="TEST-280 batch ceiling",
             commands=[dict(argv=["hostname"])])
assert ExecuteCommandsRequest(**batch, timeout_seconds=900).timeout_seconds == 900
try:
    ExecuteCommandsRequest(**batch, timeout_seconds=901)
except ValidationError:
    pass
else:
    raise AssertionError("900s batch limit changed")
assert "Timeout max is 36000 seconds." in next(
    tool.description for tool in SSH_TOOLS if tool.name == "execute_command"
)
"""
        run = subprocess.run(
            [sys.executable, "-c", script], env=env, text=True,
            capture_output=True, timeout=25, check=False,
        )
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_signed_config_validation_and_hard_ceiling(self):
        for section, name, bad in (
            ("oauth", "issuer", "http://evil.invalid"),
            ("oauth", "access_token_ttl_seconds", 86400),
            ("oauth", "session_ttl_seconds", 3601),
            ("ssh", "max_timeout_seconds", 36001),
            ("ssh", "max_output_bytes", 1048577),
            ("ssh", "max_argument_bytes", 65537),
            ("ssh", "max_arguments", 65),
            ("jobs", "max_active", 257),
            ("viewer", "enabled", False),
        ):
            with self.subTest(section=section, name=name):
                doc = json.loads((ROOT / "deploy/service.example.json").read_text())
                doc[section][name] = bad
                self.write(self.config, doc)
                with self.assertRaises(ValueError):
                    self.prepare()
                self.assertEqual(list(self.target.iterdir()), [])

    def test_200_host_inventory_allowed_but_201_rejected(self):
        # 200 signed, allowlisted hosts is configuration capacity, not
        # permission for 200 concurrent SSH commands.
        template = json.loads(self.inventory.read_text())["hosts"][0]
        self.settings["ssh"]["max_hosts"] = 200
        self.write(self.config, self.settings)
        hosts = [{**template, "alias": f"peer-{index:03d}",
                  "address": f"host-{index:03d}.example.test"}
                 for index in range(200)]
        self.write(self.inventory, {"version": 1, "hosts": hosts})
        self.known.write_text(
            "".join(f"{host['address']} ssh-ed25519 SYNTHETIC_KEY_NOT_VALID\n"
                    for host in hosts)
        )
        result = self.prepare()
        self.assertEqual(len(result["SSH_APPROVED_ALIASES"].split(",")), 200)
        stored = json.loads((self.target / "inventory.json").read_text())["hosts"]
        self.assertEqual(len(stored), 200)
        self.assertEqual(stored[0]["alias"], "peer-000")
        self.assertEqual(stored[-1]["alias"], "peer-199")
        # Re-run with 201: secure output directory must not be partially populated.
        for entry in self.target.iterdir():
            entry.unlink()
        self.write(self.inventory, {"version": 1, "hosts": [
            *hosts, {**template, "alias": "peer-200", "address": "host-200.example.test"}
        ]})
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(list(self.target.iterdir()), [])

    def test_ssh_host_ceiling_is_not_overridable_in_signed_settings(self):
        self.settings["ssh"]["max_hosts"] = 201
        self.write(self.config, self.settings)
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(list(self.target.iterdir()), [])

    def test_signed_inventory_and_known_hosts_required(self):
        self.known.write_text("# Missing approved host-key pins\n")
        with self.assertRaisesRegex(ValueError, "Missing approved SSH host-key"):
            self.prepare()
        self.known.write_text("192.0.2.44 ssh-ed25519 SYNTHETIC_KEY_NOT_VALID\n")
        self.write(self.inventory, {"version": 1, "hosts": []})
        with self.assertRaises(ValueError):
            self.prepare()

    def test_legacy_viewer_config_uses_defaults_and_custom_values(self):
        config = json.loads(json.dumps(self.settings))
        config["viewer"].pop("story_id_max_chars")
        config["viewer"].pop("story_id_truncate_from")
        self.write(self.config, config)
        result = self.prepare()
        self.assertEqual(result["HISTORY_STORY_ID_MAX_CHARS"], "16")
        self.assertEqual(result["HISTORY_STORY_ID_TRUNCATE_FROM"], "end")
        self.assertIn("ChatGPT", json.loads(result["MCP_CLIENTS"]))
        definitions = {
            "Agent": {
                "identities": ["https://agent.example.org/client.json"],
                "conversation_id": {"sources": []},
            },
            "Grok": {
                "identities": ["dcr_" + "Q" * 43],
                "conversation_id": {"sources": []},
            },
        }
        config["clients"].update(definitions)
        config["viewer"].update({"story_id_max_chars": 9,
                                 "story_id_truncate_from": "start"})
        self.write(self.config, config)
        self.target = self.root / "custom-viewer-target"
        self.target.mkdir(mode=0o700)
        result = self.prepare()
        self.assertEqual(result["HISTORY_STORY_ID_MAX_CHARS"], "9")
        self.assertEqual(result["HISTORY_STORY_ID_TRUNCATE_FROM"], "start")
        self.assertEqual(json.loads(result["MCP_CLIENTS"]), config["clients"])

    def test_fail_closed_service_schema_and_security_allowlists(self):
        changes = (

            ("http", "allowed_origins", ["http://evil.invalid"]),
            ("http", "request_timeout_seconds", 0),
            ("oauth", "operator_subject", "unapproved"),
            ("oauth", "client_metadata_url", "http://evil.invalid/client.json"),
            ("oauth", "authorization_code_ttl_seconds", 601),
            ("oauth", "access_token_ttl_seconds", 900.0),
            ("oauth", "access_token_ttl_seconds", True),
            ("oauth", "access_token_ttl_seconds", "900"),
            ("oauth", "access_token_ttl_seconds", None),
            ("oauth", "session_ttl_seconds", 86400.0),
            ("oauth", "session_ttl_seconds", True),
            ("oauth", "session_ttl_seconds", "86400"),
            ("oauth", "session_ttl_seconds", None),
            ("oauth", "validate_client_metadata", False),
            ("oauth", "allowed_redirect_uris", ["http://evil.invalid/cb"]),
            ("oauth", "login_max_failures", 101),
            ("ssh", "default_timeout_seconds", 901),
            ("ssh", "max_concurrent", 33),
            ("ssh", "enabled", False),
            ("jobs", "database", "/tmp/unreviewed.sqlite"),
            ("jobs", "retention_months", 13),
            ("history", "retention_months", 11),
            ("metrics", "enabled", False),
            ("viewer", "idle_timeout_seconds", 90000),
            ("viewer", "absolute_timeout_seconds", 100),
            ("viewer", "story_id_max_chars", 0),
            ("viewer", "story_id_max_chars", 81),
            ("viewer", "story_id_max_chars", True),
            ("viewer", "story_id_truncate_from", "middle"),
            ("viewer", "client_labels", {"https://agent.example.org/client.json": "Unknown"}),
        )
        for section, field, value in changes:
            with self.subTest(section=section, field=field):
                config = json.loads((ROOT / "deploy/service.example.json").read_text())
                config[section][field] = value
                self.write(self.config, config)
                with self.assertRaises(ValueError):
                    self.prepare()
                self.assertEqual(list(self.target.iterdir()), [])

    def test_signed_https_issuer_client_and_redirects_are_owner_configurable(self):
        # Each signed allowlist item is explicit. The client metadata domain
        # need not match the HTTPS resource or the redirect target.
        cfg = json.loads(json.dumps(self.settings))
        cfg["oauth"]["issuer"] = "https://ssh.example.net:8443"
        cfg["clients"]["ChatGPT"]["identities"] = ["https://agent.example.org/oauth/client.json"]
        cfg["clients"]["ChatGPT"]["offline_redirect_uris"] = [
            "https://agent.example.org/callback?flow=login",
            "https://other.example.com:8443/complete",
        ]
        cfg["http"]["allowed_origins"] = [
            "https://agent.example.org", "https://other.example.com:8443",
        ]
        self.write(self.config, cfg)
        result = self.prepare()
        self.assertEqual(result["MCP_ISSUER"], "https://ssh.example.net:8443")
        self.assertEqual(result["MCP_ALLOWED_HOSTS"].split(",")[:2],
                         ["ssh.example.net", "ssh.example.net:8443"])
        self.assertEqual(result["MCP_CIMD_CLIENT_ID"], "https://agent.example.org/oauth/client.json")
        self.assertEqual(result["MCP_ALLOWED_REDIRECT_URIS"],
                         "https://agent.example.org/callback?flow=login,https://other.example.com:8443/complete")
        self.assertEqual(result["MCP_ALLOWED_ORIGINS"],
                         "https://agent.example.org,https://other.example.com:8443")
        self.assertEqual(result["MCP_OPERATOR_SUBJECT"], "ssh-mcp-operator")
        self.assertEqual(result["MCP_CIMD_VALIDATE_REMOTE"], "true")

    def test_custom_https_issuer_is_accepted(self):
        # Configured HTTPS issuers are accepted without any implicit host trust.
        cfg = json.loads(json.dumps(self.settings))
        cfg["oauth"]["issuer"] = "https://custom-issuer.example.net"
        self.write(self.config, cfg)
        result = self.prepare()
        self.assertEqual(result["MCP_ISSUER"], "https://custom-issuer.example.net")
        self.assertEqual(result["MCP_OPERATOR_SUBJECT"], "ssh-mcp-operator")

    def test_signed_https_urls_and_allowlists_reject_unsafe_inputs(self):
        # Validation must fail before creating private key/inventory files.
        failures = (
            ("oauth", "issuer", "http://mcp.example.com"),
            ("oauth", "issuer", "https://mcp.example.com/path"),
            ("oauth", "issuer", "https://mcp.example.com?x=1"),
            ("oauth", "issuer", "https://user:pass@mcp.example.com"),
            ("oauth", "issuer", "https://mcp.example.com:99999"),
            ("oauth", "issuer", "https://mcp.example.com\\evil"),
            ("oauth", "issuer", "https://-invalid.example.com"),
            ("oauth", "issuer", "https://127.0.0.1"),
            ("oauth", "operator_subject", "legacy-operator"),
            ("oauth", "operator_subject", "agent"),
            ("http", "allowed_origins", ["https://agent,example.com"]),
            ("http", "allowed_origins", []),
            ("http", "allowed_origins", ["*"]),
            ("http", "allowed_origins", ["http://agent.example.com"]),
            ("http", "allowed_origins", ["https://agent.example.com/"]),
            ("http", "allowed_origins", ["https://agent.example.com?x=1"]),
            ("http", "allowed_origins", ["https://agent.example.com"] * 2),
            ("http", "allowed_origins", ["https://agent.example.com", None]),
        )
        for index, (section, field, value) in enumerate(failures):
            with self.subTest(section=section, field=field, value=value):
                cfg = json.loads(json.dumps(self.settings))
                cfg[section][field] = value
                self.write(self.config, cfg)
                target = self.root / f"reject-url-{index}"
                target.mkdir(mode=0o700)
                with self.assertRaises(ValueError):
                    prepare(self.config, self.secrets, self.inventory, self.known, target)
                self.assertEqual(list(target.iterdir()), [])

        # These must reach URL validation inside the new signed clients map,
        # not fail early merely because legacy OAuth keys were removed.
        for field, values in (
            ("identities", [
                ["http://agent.example.com/client.json"],
                ["https://127.0.0.1/client.json"],
                ["https://169.254.169.254/client.json"],
                ["https://localhost/client.json"],
                ["https://agent/client.json"],
                ["https://user@agent.example.com/client.json"],
                ["https://agent.example.com:bad/client.json"],
                ["https://agent.example.com/client.json#fragment"],
                ["https://agent.example.com\\evil/client.json"],
            ]),
            ("offline_redirect_uris", [
                [],
                ["http://127.0.0.1/cb"],
                ["https://127.0.0.1/cb"],
                ["https://localhost/cb"],
                ["https://agent/cb"],
                ["https://user@agent.example.com/cb"],
                ["https://agent.example.com/cb#fragment"],
                ["https://agent.example.com/a,b"],
                ["https://agent.example.com/cb?x=a,b"],
                ["https://agent.example.com\\evil/cb"],
                ["https://agent.example.com/cb"] * 2,
            ]),
        ):
            for index, value in enumerate(values):
                with self.subTest(field=field, case=index):
                    cfg = json.loads(json.dumps(self.settings))
                    cfg["clients"]["ChatGPT"][field] = value
                    self.write(self.config, cfg)
                    target = self.root / f"reject-client-{field}-{index}"
                    target.mkdir(mode=0o700)
                    with self.assertRaises(ValueError):
                        prepare(self.config, self.secrets, self.inventory,
                                self.known, target)
                    self.assertEqual(list(target.iterdir()), [])

    def test_signed_client_registry_rejects_untrusted_sources(self):
        invalid = (
            ("identities", ["http://evil.invalid/client.json"]),
            ("identities", ["https://user@agent.example.org/client.json"]),
            ("identities", ["dcr_*"]),
            ("identities", []),
            ("conversation_id", {"sources": [{"type": "header", "name": "X-Forwarded-For"}]}),
            ("conversation_id", {"sources": [{"type": "header", "name": "Authorization"}]}),
            ("conversation_id", {"sources": [{"type": "metadata", "name": "a", "field": "../secret"}]}),
            ("conversation_id", {"sources": [{"type": "header", "name": "X-Demo"}] * 2}),
            ("offline_redirect_uris", ["http://127.0.0.1/unsafe"]),
            ("offline_redirect_uris", ["https://agent.example.org/a,b"]),
            ("offline_redirect_uris", []),
        )
        for i, (key, value) in enumerate(invalid):
            with self.subTest(key=key, case=i):
                cfg = json.loads(json.dumps(self.settings))
                cfg["clients"]["ChatGPT"][key] = value
                self.write(self.config, cfg)
                with self.assertRaises(ValueError):
                    self.prepare()
                self.assertEqual(list(self.target.iterdir()), [])

    def test_compose_owns_bind_host_and_port(self):
        result = self.prepare()
        self.assertNotIn("MCP_BIND_HOST", result)
        self.assertNotIn("MCP_BIND_PORT", result)
        for name, value in (("bind_host", "127.0.0.1"), ("port", 9999)):
            with self.subTest(name=name):
                settings = json.loads((ROOT / "deploy/service.example.json").read_text())
                settings["http"][name] = value
                self.write(self.config, settings)
                with self.assertRaisesRegex(ValueError, "Invalid service setting schema"):
                    self.prepare()

    def test_signed_inventory_and_private_source_rejections(self):
        inventory = json.loads(self.inventory.read_text())
        for invalid in (
            {"version": 2, "hosts": inventory["hosts"]},
            {"version": 1, "hosts": [inventory["hosts"][0]] * 2},
            {"version": 1, "hosts": [{**inventory["hosts"][0], "alias": "BAD.alias"}]},
            {"version": 1, "hosts": [{**inventory["hosts"][0], "max_parallel": 9}]},
            {"version": 1, "hosts": [{**inventory["hosts"][0], "unexpected": 1}]},
        ):
            with self.subTest(invalid=invalid):
                self.write(self.inventory, invalid)
                with self.assertRaises(ValueError):
                    self.prepare()
                self.assertEqual(list(self.target.iterdir()), [])
        self.write(self.inventory, inventory)
        self.known.unlink()
        self.known.symlink_to(self.config)
        with self.assertRaises(ValueError):
            self.prepare()
        self.known.unlink()
        self.known.write_text("approved-alias ssh-ed25519 SYNTHETIC_KEY\n")
        self.secrets.write_text("{")
        with self.assertRaises(ValueError):
            self.prepare()

    def test_native_app_import_without_bootstrap_executable(self):
        env = dict(os.environ)
        env.update({"MCP_CONFIG_FILE": str(self.config), "MCP_SECRETS_FILE": str(self.secrets),
                    "MCP_INVENTORY_FILE": str(self.inventory),
                    "MCP_KNOWN_HOSTS_FILE": str(self.known)})
        script = ("from pathlib import Path; from app import runtime_files; "
                  f"runtime_files.DEST=Path({str(self.target)!r}); "
                  "from app import config; assert config.MCP_OPERATOR_SUBJECT=='ssh-mcp-operator'; "
                  "print('native_mounts_validated')")
        proc = subprocess.run([sys.executable, "-c", script], env=env,
                              capture_output=True, text=True, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "native_mounts_validated")
        self.assertNotIn("synthetic-login-", proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
