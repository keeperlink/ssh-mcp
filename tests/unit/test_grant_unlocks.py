"""Synthetic checks for scoped, memory-only root unlock handles."""
from __future__ import annotations

import asyncio
import threading
import time
import unittest
from unittest.mock import patch

from app.grant_unlocks import GrantUnlocks, UnlockScope
from app.sealed_credentials import (
    InvalidCredential, create_verifier, seal_sudo,
)

PASSWORD = "synthetic-console-password-not-real"
SUDO = "synthetic-host-sudo-password"
BIND = {"deployment": "lab", "issuer": "https://testing.example.org",
        "alias": "demo-node-a", "username": "gateway"}


class ScopedUnlockTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.now = [1000.0]
        self.unlocks = GrantUnlocks(clock=lambda: self.now[0])
        self.scope = UnlockScope(
            ("sid-one", "conversation-abc", "demo-node-a"),
            actor="operator", client_id="dcr_one", issuance="grant-issuance-1",
            operation_id="request-one", generation="v2-secret-generation",
        )
        self.verifier = create_verifier(PASSWORD, "console-login")
        self.envelope = seal_sudo(PASSWORD, SUDO, **BIND)

    def issue(self, scope=None, *, password=PASSWORD, expires=1300.0):
        prepared = self.unlocks.prepare(
            scope or self.scope, console_password=password,
            console_verifier=self.verifier, sealed_sudo=self.envelope,
            deployment=BIND["deployment"], issuer=BIND["issuer"], username=BIND["username"],
        )
        return self.unlocks.commit(prepared, expires=expires, still_authorized=lambda: True)

    async def test_issued_opaque_handle_validates_exact_scope_not_password_in_handle(self):
        handle = self.issue()
        self.assertNotIn(PASSWORD, handle)
        self.assertNotIn(SUDO, handle)
        self.assertEqual(self.unlocks.require(handle, self.scope), SUDO)
        self.assertNotIn(SUDO, repr(self.unlocks._entries[handle]))
        for different in (
            {"client_id": "dcr_other"}, {"actor": "other-operator"},
            {"issuance": "grant-issuance-2"}, {"operation_id": "another-request"},
            {"generation": "rotated-secret"},
        ):
            values = {k: getattr(self.scope, k) for k in (
                "key", "actor", "client_id", "issuance", "operation_id", "generation")}
            values.update(different)
            with self.subTest(different=different), self.assertRaises(InvalidCredential):
                self.unlocks.require(handle, UnlockScope(**values))

    async def test_wrong_password_and_other_host_envelope_fail(self):
        with self.assertRaisesRegex(InvalidCredential, "Incorrect Console password"):
            self.issue(password="incorrect")
        self.assertFalse(self.unlocks._entries)
        other = UnlockScope(
            ("sid-one", "conversation-abc", "demo-node-b"),
            actor="operator", client_id="dcr_one", issuance="grant-issuance-1",
            operation_id="request-one", generation="v2-secret-generation",
        )
        with self.assertRaises(InvalidCredential):
            self.issue(other)

    async def test_expiry_and_revoke_cannot_be_revived_by_another_grant(self):
        handle = self.issue()
        self.now[0] = 1300.0
        self.assertFalse(self.unlocks.valid(handle, self.scope))
        self.now[0] = 1400.0
        new = self.issue(expires=1500.0)
        self.assertNotEqual(handle, new)
        self.assertFalse(self.unlocks.valid(handle, self.scope))
        self.unlocks.revoke_scope(self.scope.key)
        self.assertFalse(self.unlocks.valid(new, self.scope))
        self.unlocks.revoke("nonexistent-handle")
        with self.assertRaises(InvalidCredential):
            self.unlocks.require("", self.scope)
        with self.assertRaises(InvalidCredential):
            self.unlocks.require(new, self.scope)

    async def test_logout_and_rotation_invalidate_only_appropriate_state(self):
        first = self.issue()
        second_scope = UnlockScope(
            ("sid-two", "agent:dcr_two", "demo-node-a"),
            actor="other-operator", client_id="dcr_two", issuance="grant-issuance-2",
            operation_id="request-two", generation="v2-secret-generation",
        )
        second = self.issue(second_scope)
        self.unlocks.revoke_actor("operator")
        self.assertFalse(self.unlocks.valid(first, self.scope))
        self.assertTrue(self.unlocks.valid(second, second_scope))
        self.unlocks.clear()
        self.assertFalse(self.unlocks.valid(second, second_scope))
        self.unlocks.close()
        with self.assertRaises(InvalidCredential):
            self.issue()

    async def test_explicit_handle_revoke_and_wrong_type_never_authorize_root(self):
        handle = self.issue()
        self.assertTrue(self.unlocks.valid(handle, self.scope))
        for invalid in (None, 1, False, [], {}):
            with self.subTest(invalid=invalid), self.assertRaises(InvalidCredential):
                self.unlocks.require(invalid, self.scope)
        with self.assertRaises(InvalidCredential):
            self.unlocks.require(handle, None)
        self.unlocks.revoke(handle)
        self.assertFalse(self.unlocks.valid(handle, self.scope))
        replacement = self.issue()
        self.assertNotEqual(handle, replacement)
        self.assertFalse(self.unlocks.valid(handle, self.scope))
        self.assertEqual(self.unlocks.require(replacement, self.scope), SUDO)
        self.unlocks.close()
        with self.assertRaises(InvalidCredential):
            self.unlocks.require(replacement, self.scope)

    async def test_bounds_and_nonfinite_or_expired_time_fail(self):
        for expires in (900.0, 1000.0, 59000.0, float("inf"), float("nan")):
            with self.subTest(expires=expires), self.assertRaises(InvalidCredential):
                self.issue(expires=expires)
        with self.assertRaises(ValueError):
            GrantUnlocks(maximum=0)
        with self.assertRaises(ValueError):
            GrantUnlocks(maximum=1025)
        with self.assertRaises(InvalidCredential):
            UnlockScope(
                ("sid-one",), actor="operator",
                client_id="dcr_one", issuance="grant-issuance-1",
                operation_id="request-one", generation="v2-secret-generation",
            )
        with self.assertRaises(InvalidCredential):
            UnlockScope(
                ("sid-one", "conversation", "demo-node-a"),
                actor="", client_id="dcr_one", issuance="grant-issuance-1",
                operation_id="request-one", generation="v2-secret-generation",
            )
        small = GrantUnlocks(clock=lambda: self.now[0], maximum=1)
        prepared = small.prepare(
            self.scope, console_password=PASSWORD, console_verifier=self.verifier,
            sealed_sudo=self.envelope, deployment=BIND["deployment"],
            issuer=BIND["issuer"], username=BIND["username"],
        )
        small.commit(prepared, expires=1300.0, still_authorized=lambda: True)
        with self.assertRaises(InvalidCredential):
            small.commit(prepared, expires=1300.0, still_authorized=lambda: True)

    async def test_revoke_during_slow_password_check_rejects_late_commit(self):
        entered = threading.Event()
        release = threading.Event()
        from app.grant_unlocks import verify_password

        def slow_verify(*args):
            entered.set()
            if not release.wait(5):
                raise AssertionError("Timed out waiting for authorization revoke")
            return verify_password(*args)

        with patch("app.grant_unlocks.verify_password", side_effect=slow_verify):
            pending = asyncio.create_task(asyncio.to_thread(
                self.unlocks.prepare, self.scope, console_password=PASSWORD,
                console_verifier=self.verifier, sealed_sudo=self.envelope,
                deployment=BIND["deployment"], issuer=BIND["issuer"],
                username=BIND["username"],
            ))
            self.assertTrue(await asyncio.to_thread(entered.wait, 3))
            self.unlocks.revoke_actor("operator")
            release.set()
            prepared = await pending
        with self.assertRaisesRegex(InvalidCredential, "unavailable"):
            self.unlocks.commit(prepared, expires=1300.0, still_authorized=lambda: True)
        self.assertFalse(self.unlocks._entries)

    async def test_live_check_required_after_kdf_and_before_commit(self):
        def prepare():
            return self.unlocks.prepare(
                self.scope, console_password=PASSWORD,
                console_verifier=self.verifier, sealed_sudo=self.envelope,
                deployment=BIND["deployment"], issuer=BIND["issuer"],
                username=BIND["username"],
            )
        prepared = prepare()
        with self.assertRaisesRegex(InvalidCredential, "no longer authorized"):
            self.unlocks.commit(prepared, expires=1300.0, still_authorized=lambda: False)
        self.assertIsNone(prepared.password)
        with self.assertRaisesRegex(InvalidCredential, "consumed"):
            self.unlocks.commit(prepared, expires=1300.0, still_authorized=lambda: True)
        prepared = prepare()
        with self.assertRaisesRegex(InvalidCredential, "no longer authorized"):
            self.unlocks.commit(prepared, expires=1300.0,
                                still_authorized=lambda: 1 / 0)
        self.assertIsNone(prepared.password)
        prepared = prepare()
        def revoked_during_check() -> bool:
            self.unlocks.revoke_actor("operator")
            return True
        with self.assertRaisesRegex(InvalidCredential, "no longer authorized"):
            self.unlocks.commit(
                prepared, expires=1300.0, still_authorized=revoked_during_check,
            )
        self.assertIsNone(prepared.password)
        prepared = prepare()
        self.assertFalse(self.unlocks._entries)
        self.assertTrue(self.unlocks.require(
            self.unlocks.commit(prepared, expires=1300.0, still_authorized=lambda: True),
            self.scope,
        ))
        self.assertIsNone(prepared.password)

    async def test_idle_expiry_releases_password_without_further_registry_calls(self):
        registry = GrantUnlocks()
        prepared = registry.prepare(
            self.scope, console_password=PASSWORD,
            console_verifier=self.verifier, sealed_sudo=self.envelope,
            deployment=BIND["deployment"], issuer=BIND["issuer"],
            username=BIND["username"],
        )
        handle = registry.commit(
            prepared, expires=time.monotonic() + 0.04,
            still_authorized=lambda: True,
        )
        self.assertIsNone(prepared.password)
        with self.assertRaisesRegex(InvalidCredential, "consumed"):
            registry.commit(
                prepared, expires=time.monotonic() + 0.04,
                still_authorized=lambda: True,
            )
        self.assertIn(handle, registry._entries)
        await asyncio.sleep(0.10)
        self.assertNotIn(handle, registry._entries)
        with self.assertRaisesRegex(InvalidCredential, "consumed"):
            registry.commit(
                prepared, expires=time.monotonic() + 0.04,
                still_authorized=lambda: True,
            )
        registry.close()

    async def test_prepared_unlock_is_not_transferable_to_another_registry(self):
        prepared = self.unlocks.prepare(
            self.scope, console_password=PASSWORD,
            console_verifier=self.verifier, sealed_sudo=self.envelope,
            deployment=BIND["deployment"], issuer=BIND["issuer"],
            username=BIND["username"],
        )
        second = GrantUnlocks(clock=lambda: self.now[0])
        with self.assertRaisesRegex(InvalidCredential, "invalid"):
            second.commit(prepared, expires=1300.0, still_authorized=lambda: True)
        self.assertIsNotNone(prepared.password)
        self.unlocks.commit(prepared, expires=1300.0, still_authorized=lambda: True)
        self.assertIsNone(prepared.password)
        with self.assertRaisesRegex(InvalidCredential, "consumed"):
            self.unlocks.commit(prepared, expires=1300.0, still_authorized=lambda: True)

    async def test_cancelled_preparation_discards_plaintext_reference(self):
        prepared = self.unlocks.prepare(
            self.scope, console_password=PASSWORD,
            console_verifier=self.verifier, sealed_sudo=self.envelope,
            deployment=BIND["deployment"], issuer=BIND["issuer"],
            username=BIND["username"],
        )
        prepared.discard()
        self.assertIsNone(prepared.password)
        with self.assertRaisesRegex(InvalidCredential, "consumed"):
            self.unlocks.commit(prepared, expires=1300.0, still_authorized=lambda: True)

    async def test_real_approval_key_lengths_and_timed_grant_operation_scope(self):
        key = ("agent:operator", "https://example.com/" + "a" * 2010, "demo-node-a")
        scope = UnlockScope(key, actor="operator", client_id=key[1],
                            issuance="timed-grant-one", operation_id="",
                            generation="generation", kind="timed")
        handle = self.issue(scope)
        self.assertEqual(self.unlocks.require(handle, scope), SUDO)
        self.assertEqual(self.unlocks.require(handle, UnlockScope(
            key, actor="operator", client_id=key[1], issuance="timed-grant-one",
            operation_id="", generation="generation", kind="timed",
        )), SUDO)
        with self.assertRaises(InvalidCredential):
            self.unlocks.require(handle, UnlockScope(
                key, actor="operator", client_id=key[1], issuance="timed-grant-one",
                operation_id="different-request", generation="generation",
            ))
        request_key = ("oauth-session", "", "demo-node-a")
        request_scope = UnlockScope(
            request_key, actor="operator", client_id="",
            issuance="request-approval", operation_id="request-token",
            generation="generation",
        )
        request_handle = self.issue(request_scope)
        self.assertEqual(self.unlocks.require(request_handle, request_scope), SUDO)
        with self.assertRaises(InvalidCredential):
            UnlockScope(request_key, actor="operator", client_id="",
                        issuance="timed-approval", operation_id="",
                        generation="generation", kind="timed")
        with self.assertRaises(InvalidCredential):
            UnlockScope(("session", "c" * 2049, "demo-node-a"), actor="operator",
                        client_id="", issuance="request-approval",
                        operation_id="request-token", generation="generation")


if __name__ == "__main__":
    unittest.main()
