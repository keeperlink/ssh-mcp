"""Synthetic, local tests for v2 managed secret primitives (no real credentials)."""
from __future__ import annotations

import base64
import copy
import unittest

from app.sealed_credentials import (
    InvalidCredential, create_token_verifier, create_verifier, from_legacy,
    rotate_console, rotate_host_sudo, seal_sudo,
    unseal_sudo, validate_sealed_sudo, validate_token_verifier,
    validate_v2_secrets, validate_verifier, verify_password, verify_token,
)

PASSWORD = "synthetic-console-password-not-production"
OAUTH = "synthetic-independent-oauth-password-0123456789"
SUDO = "synthetic-sudo-credential-not-real"
BIND = {"deployment": "lab", "issuer": "https://testing.example.org",
        "alias": "demo-node-a", "username": "gateway"}


class VerifierTests(unittest.TestCase):
    def test_independent_salts_and_domains(self):
        first = create_verifier(PASSWORD, "console-login")
        second = create_verifier(PASSWORD, "console-login")
        oauth = create_verifier(PASSWORD, "oauth-login")
        self.assertNotEqual(first["salt"], second["salt"])
        self.assertNotEqual(first["digest"], second["digest"])
        self.assertTrue(verify_password(PASSWORD, first, "console-login"))
        self.assertFalse(verify_password("incorrect", first, "console-login"))
        self.assertFalse(verify_password(PASSWORD, first, "oauth-login"))
        self.assertTrue(verify_password(PASSWORD, oauth, "oauth-login"))
        self.assertNotIn(PASSWORD, repr(first))
        self.assertNotIn(PASSWORD, repr(second))

    def test_invalid_password_verifier_fails_before_kdf(self):
        valid = create_verifier(PASSWORD, "console-login")
        for changes in (
            {"iterations": True}, {"iterations": 0}, {"iterations": 1000000},
            {"memory_kib": 1}, {"memory_kib": 2147483647},
            {"lanes": 3}, {"algorithm": "pbkdf2"},
            {"salt": "!!!"}, {"salt": base64.b64encode(b"too-short").decode()},
            {"digest": ""}, {"unexpected": "extra"},
        ):
            with self.subTest(changes=changes), self.assertRaises(InvalidCredential):
                validate_verifier({**valid, **changes})
        with self.assertRaises(InvalidCredential):
            create_verifier(PASSWORD, "sudo-wrap")
        for invalid in ("", "\x00", "x" * 257):
            self.assertFalse(verify_password(invalid, valid, "console-login"))

    def test_metrics_token_verification(self):
        original = "synthetic-high-entropy-bearer-" + "a" * 40
        verifier = create_token_verifier(original)
        self.assertTrue(verify_token(original, verifier))
        self.assertFalse(verify_token(original + "x", verifier))
        self.assertNotIn(original, repr(verifier))
        validate_token_verifier(verifier)
        for data in ({"algorithm": "sha256", "digest": "X" * 64},
                     {"algorithm": "argon2id", "digest": verifier["digest"]},
                     {"algorithm": "sha256", "digest": verifier["digest"], "raw": original}):
            with self.assertRaises(InvalidCredential):
                validate_token_verifier(data)


class HostSealingTests(unittest.TestCase):
    def setUp(self):
        self.sealed = seal_sudo(PASSWORD, SUDO, **BIND)

    def test_roundtrip_and_independent_nonce(self):
        self.assertEqual(unseal_sudo(PASSWORD, self.sealed, **BIND), SUDO)
        next_sealed = seal_sudo(PASSWORD, SUDO, **BIND)
        self.assertNotEqual(self.sealed["nonce"], next_sealed["nonce"])
        self.assertNotEqual(self.sealed["salt"], next_sealed["salt"])
        self.assertNotIn(SUDO, repr(self.sealed))
        self.assertNotIn(PASSWORD, repr(self.sealed))

    def test_wrong_password_and_binding_fail_closed(self):
        cases = [
            ("wrong-password", BIND), (PASSWORD, {**BIND, "alias": "demo-node-b"}),
            (PASSWORD, {**BIND, "username": "mcp-agent"}),
            (PASSWORD, {**BIND, "deployment": "production"}),
            (PASSWORD, {**BIND, "issuer": "https://different.example.org"}),
        ]
        for password, binding in cases:
            with self.subTest(binding=binding), self.assertRaises(InvalidCredential):
                unseal_sudo(password, self.sealed, **binding)

    def test_ciphertext_tampering_and_malformed_envelopes(self):
        raw = bytearray(base64.b64decode(self.sealed["ciphertext"]))
        raw[0] ^= 0x80
        altered = {**self.sealed, "ciphertext": base64.b64encode(raw).decode("ascii")}
        with self.assertRaises(InvalidCredential):
            unseal_sudo(PASSWORD, altered, **BIND)
        for changes in (
            {"algorithm": "aes-128-gcm"}, {"salt": "AA=="},
            {"nonce": "AA=="}, {"ciphertext": "AA=="},
            {"ciphertext": "AAAAA="}, {"extra": 42},
        ):
            with self.subTest(changes=changes), self.assertRaises(InvalidCredential):
                validate_sealed_sudo({**self.sealed, **changes})

    def test_v2_schema_rejects_plaintext_legacy_fields(self):
        value = {
            "version": 2,
            "oauth_login_verifier": create_verifier(OAUTH, "oauth-login"),
            "viewer_verifier": create_verifier(PASSWORD, "console-login"),
            "viewer_generation": "a" * 32,
            "metrics_verifier": create_token_verifier("synthetic-metrics-" + "1" * 48),
            "oauth_signing_key": "synthetic-signing-" + "c" * 40,
            "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic-not-a-key\n-----END OPENSSH PRIVATE KEY-----",
            "sealed_sudo": {"demo-node-a": self.sealed},
        }
        validate_v2_secrets(value)
        for changes in (
            {"version": 1}, {"viewer_password": PASSWORD}, {"sudo_passwords": {"demo-node-a": SUDO}},
            {"viewer_generation": "generation"}, {"sealed_sudo": {"BAD.alias": self.sealed}},
        ):
            with self.subTest(changes=changes), self.assertRaises(InvalidCredential):
                validate_v2_secrets({**value, **changes})
        swapped = copy.deepcopy(value)
        swapped["sealed_sudo"]["demo-node-b"] = swapped["sealed_sudo"].pop("demo-node-a")
        validate_v2_secrets(swapped)
        with self.assertRaises(InvalidCredential):
            unseal_sudo(PASSWORD, swapped["sealed_sudo"]["demo-node-b"],
                        **{**BIND, "alias": "demo-node-b"})


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.legacy = {
            "version": 1, "oauth_login_key": OAUTH,
            "viewer_password": PASSWORD,
            "metrics_token": "synthetic-metrics-" + "1" * 48,
            "oauth_signing_key": "synthetic-signing-" + "c" * 40,
            "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic-not-a-key\n-----END OPENSSH PRIVATE KEY-----",
            "sudo_passwords": {"demo-node-a": SUDO},
        }
        self.hosts = {"demo-node-a": "gateway"}

    def convert(self):
        return from_legacy(self.legacy, console_password=PASSWORD,
                           deployment=BIND["deployment"], issuer=BIND["issuer"],
                           hosts=self.hosts)

    def test_conversion_removes_all_recoverable_credentials_except_keys(self):
        import json
        prepared = self.convert()
        serialized = json.dumps(prepared)
        for clear in (OAUTH, PASSWORD, SUDO, self.legacy["metrics_token"]):
            self.assertNotIn(clear, serialized)
        self.assertTrue(verify_password(OAUTH, prepared["oauth_login_verifier"], "oauth-login"))
        self.assertTrue(verify_token(self.legacy["metrics_token"], prepared["metrics_verifier"]))
        self.assertEqual(unseal_sudo(PASSWORD, prepared["sealed_sudo"]["demo-node-a"], **BIND), SUDO)
        self.assertEqual(self.legacy["sudo_passwords"]["demo-node-a"], SUDO)

    def test_conversion_rejects_bad_legacy_or_unknown_host(self):
        with self.assertRaises(InvalidCredential):
            from_legacy(self.legacy, console_password="wrong",
                        deployment=BIND["deployment"], issuer=BIND["issuer"],
                        hosts=self.hosts)
        with self.assertRaises(InvalidCredential):
            from_legacy(self.legacy, console_password=PASSWORD,
                        deployment=BIND["deployment"], issuer=BIND["issuer"],
                        hosts={})
        self.legacy["oauth_login_key"] = PASSWORD
        with self.assertRaises(InvalidCredential):
            self.convert()

    def test_console_password_change_rekeys_all_and_invalidates_generation(self):
        source = self.convert()
        replacement = rotate_console(source, old_password=PASSWORD,
                                     new_password=PASSWORD+"-rotated", hosts=self.hosts,
                                     deployment=BIND["deployment"], issuer=BIND["issuer"])
        self.assertNotEqual(replacement["viewer_generation"], source["viewer_generation"])
        self.assertTrue(verify_password(PASSWORD, source["viewer_verifier"], "console-login"))
        self.assertFalse(verify_password(PASSWORD, replacement["viewer_verifier"], "console-login"))
        self.assertEqual(unseal_sudo(PASSWORD+"-rotated",
                                     replacement["sealed_sudo"]["demo-node-a"], **BIND), SUDO)
        with self.assertRaises(InvalidCredential):
            unseal_sudo(PASSWORD, replacement["sealed_sudo"]["demo-node-a"], **BIND)
        with self.assertRaises(InvalidCredential):
            rotate_console(source, old_password=PASSWORD,
                           new_password=PASSWORD, hosts=self.hosts,
                           deployment=BIND["deployment"], issuer=BIND["issuer"])
        with self.assertRaises(InvalidCredential):
            rotate_console(source, old_password=PASSWORD,
                           new_password=PASSWORD+"-rotated", hosts={},
                           deployment=BIND["deployment"], issuer=BIND["issuer"])

    def test_host_rotation_scoped_without_modifying_input(self):
        source = self.convert()
        replacement = rotate_host_sudo(source, console_password=PASSWORD,
                                       new_sudo_password="synthetic-new-sudo-password",
                                       **BIND)
        self.assertEqual(unseal_sudo(PASSWORD, source["sealed_sudo"]["demo-node-a"], **BIND), SUDO)
        self.assertEqual(unseal_sudo(PASSWORD, replacement["sealed_sudo"]["demo-node-a"], **BIND),
                         "synthetic-new-sudo-password")
        self.assertEqual(source["viewer_verifier"], replacement["viewer_verifier"])
        with self.assertRaises(InvalidCredential):
            rotate_host_sudo(source, console_password=PASSWORD,
                             new_sudo_password=SUDO, **BIND)


if __name__ == "__main__":
    unittest.main()
