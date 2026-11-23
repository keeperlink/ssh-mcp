"""Synthetic checks for scoped, memory-only root unlock handles."""
from __future__ import annotations

import unittest

from app.grant_unlocks import GrantUnlocks, UnlockScope
from app.sealed_credentials import (
    InvalidCredential, create_verifier, seal_sudo,
)

PASSWORD = "synthetic-console-password-not-real"
SUDO = "synthetic-host-sudo-password"
BIND = {"deployment": "lab", "issuer": "https://testing.example.org",
        "alias": "demo-node-a", "username": "gateway"}


class ScopedUnlockTests(unittest.TestCase):
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
        return self.unlocks.issue(
            scope or self.scope, console_password=password,
            console_verifier=self.verifier, sealed_sudo=self.envelope,
            deployment=BIND["deployment"], issuer=BIND["issuer"],
            username=BIND["username"], expires=expires,
        )

    def test_issued_opaque_handle_validates_exact_scope_not_password_in_handle(self):
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

    def test_wrong_password_and_other_host_envelope_fail(self):
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

    def test_expiry_and_revoke_cannot_be_revived_by_another_grant(self):
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

    def test_logout_and_rotation_invalidate_only_appropriate_state(self):
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

    def test_bounds_and_nonfinite_or_expired_time_fail(self):
        for expires in (900.0, 1000.0, 59000.0, float("inf"), float("nan")):
            with self.subTest(expires=expires), self.assertRaises(InvalidCredential):
                self.issue(expires=expires)
        with self.assertRaises(ValueError):
            GrantUnlocks(maximum=0)
        with self.assertRaises(ValueError):
            GrantUnlocks(maximum=1025)
        with self.assertRaises(InvalidCredential):
            UnlockScope(
                ("sid-one", "", "demo-node-a"), actor="operator",
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
        small.issue(self.scope, console_password=PASSWORD,
                    console_verifier=self.verifier, sealed_sudo=self.envelope,
                    deployment=BIND["deployment"], issuer=BIND["issuer"],
                    username=BIND["username"], expires=1300.0)
        with self.assertRaises(InvalidCredential):
            small.issue(self.scope, console_password=PASSWORD,
                        console_verifier=self.verifier, sealed_sudo=self.envelope,
                        deployment=BIND["deployment"], issuer=BIND["issuer"],
                        username=BIND["username"], expires=1300.0)


if __name__ == "__main__":
    unittest.main()
