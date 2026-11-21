"""TEST-263 PR2: single-loop approvals, isolation, cancellation and viewer CSRF."""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import config
from app.approvals import ApprovalManager, DURATIONS
from app.approval_preview import (
    MAX_BATCH_CHARS, MAX_STEP_CHARS, approval_steps, approval_summary,
)
from app.contracts import ExecuteCommandRequest, ExecuteCommandsRequest
from app.conversation_access import require_host_access
from app.history import create_history_router
from app.history import HistoryStore
from app.jobs import JobStore
from app.ssh_executor import SSHDenied

KEY = ("verified-oauth-sid", "v1/conversation-A", "demo-node2")
OTHER_CONVERSATION = (KEY[0], "v1/conversation-B", KEY[2])
OTHER_HOST = (KEY[0], KEY[1], "demo-node3")
OTHER_LOGIN = ("new-oauth-sid", KEY[1], KEY[2])


class ApprovalPreviewTests(unittest.TestCase):
    def test_full_single_command_preview_includes_options_and_script_arguments(self):
        request = ExecuteCommandRequest(
            server="demo-node2", reason="Synthetic exact preview", privileged=True,
            cwd="/root/synthetic", timeout_seconds=87, success_exit_codes=[0, 7],
            argv=["bash", "-lc", "printf '%s\\n' '$HOME'\nwhoami", "_", "tail-argument"],
        )
        steps = approval_steps(request)
        self.assertEqual(len(steps), 1)
        self.assertIn("whoami", steps[0]["command"])
        self.assertIn("tail-argument", steps[0]["options"])
        self.assertIn('"cwd": "/root/synthetic"', steps[0]["options"])
        self.assertIn('"privileged": true', steps[0]["options"])
        self.assertIn('"timeout_seconds": 87', steps[0]["options"])
        self.assertFalse(steps[0]["truncated"])

    def test_oversized_command_preview_fails_closed_without_truncation(self):
        request = ExecuteCommandRequest(
            server="demo-node2", reason="Synthetic oversized approval",
            argv=["bash", "-lc", "a" * 30000, "_" + "b" * 30000,
                  "c" * 22000],
        )
        with self.assertRaisesRegex(ValueError, "Complete command preview"):
            approval_steps(request)
    def test_multiline_batch_step_details_are_ordered_and_preserve_newlines(self):
        script = ("printf '%s\\n' '========== STEP 1: SYSTEM IDENTITY =========='\n"
                  "hostname\n"
                  "date -u '+%Y-%m-%dT%H:%M:%SZ'\n"
                  "<img src=x onerror=alert(1)>")
        batch = ExecuteCommandsRequest.model_validate({
            "server": "demo-node2", "reason": "Review 2 steps",
            "commands": [
                {"argv": ["bash", "-lc", script]},
                {"argv": ["hostname", "-s"]},
            ],
        })
        steps = approval_steps(batch)
        self.assertEqual(len(steps), 2)
        self.assertEqual(steps[0]["title"], "SYSTEM IDENTITY")
        self.assertEqual(steps[0]["interpreter"], "bash -lc")
        self.assertEqual(steps[0]["command"], script)
        self.assertFalse(steps[0]["truncated"])
        self.assertEqual(steps[1]["title"], "Step 2")
        self.assertEqual(steps[1]["interpreter"], "")
        self.assertEqual(steps[1]["command"], "hostname -s")
        self.assertFalse(steps[1]["truncated"])
        self.assertIn('"argv": [', str(steps[0]["options"]))
        self.assertIn('"privileged": false', str(steps[0]["options"]))
        self.assertIn('"batch_timeout_seconds": 60', str(steps[0]["options"]))
        self.assertIn('"stop_on_error": true', str(steps[0]["options"]))
        self.assertIn("\nhostname\ndate", str(steps[0]["command"]))
        self.assertNotIn("file", str(steps[1]["command"]))

    def test_batch_preview_is_complete_bounded_and_never_truncated(self):
        batch = ExecuteCommandsRequest.model_validate({
            "server": "demo-node2", "reason": "bounded preview",
            "commands": [
                {"argv": ["bash", "-lc", "printf 'STEP 1: LARGE'\n" + "a" * 5000]},
                {"argv": ["bash", "-lc", "printf 'STEP 2: LARGE'\n" + "b" * 5000]},
                {"argv": ["bash", "-lc", "printf 'STEP 3: LARGE'\n" + "c" * 5000]},
                {"argv": ["bash", "-lc", "printf 'STEP 4: LARGE'\n" + "d" * 5000]},
                {"argv": ["bash", "-lc", "printf 'STEP 5: LARGE'\n" + "e" * 5000]},
            ],
        })
        steps = approval_steps(batch)
        self.assertEqual(len(steps), 5)
        self.assertLessEqual(sum(len(str(item["command"])) + len(str(item["options"]))
                                 for item in steps), MAX_BATCH_CHARS)
        self.assertTrue(all(len(str(item["command"])) + len(str(item["options"]))
                            <= MAX_STEP_CHARS for item in steps))
        self.assertTrue(all(not item["truncated"] for item in steps))
        self.assertIn("e" * 5000, steps[-1]["command"])

    def test_patch_targets_and_moves_not_patch_body_or_audit_label(self):
        args = {
            "server": "demo-node2", "reason": "Synthetic test",
            "path": "/unrelated/audit-label", "base_dir": "/home/example/project",
            "patch": ("*** Begin Patch\n"
                      "*** Update File: app/config.py\n"
                      "*** Move to: app/config-new.py\n"
                      "@@\n-old\n+API_TOKEN=must-not-display\n"
                      "*** Add File: docs/readme.txt\n+also-private-body\n"
                      "*** End Patch"),
        }
        summary = approval_summary("apply_patch", args)
        self.assertIn("/home/example/project/app/config.py", summary)
        self.assertIn("/home/example/project/app/config-new.py", summary)
        self.assertIn("/home/example/project/docs/readme.txt", summary)
        self.assertNotIn("audit-label", summary)
        self.assertNotIn("must-not-display", summary)
        self.assertNotIn("also-private-body", summary)

    def test_relative_file_paths_and_attachment_metadata_are_not_exposed(self):
        base = {
            "server": "demo-node2", "reason": "Synthetic",
            "base_dir": "/home/example/repo", "path": "data/file.txt",
        }
        self.assertEqual(
            approval_summary("read_file", base),
            "/home/example/repo/data/file.txt",
        )
        summary = approval_summary("upload_file", {
            **base, "file": {
                "file_id": "sensitive-internal-ref",
                "download_url": "https://example.invalid/secret-attachment",
            },
        })
        self.assertEqual(summary, "/home/example/repo/data/file.txt")
        self.assertNotIn("sensitive", summary)

    def test_large_patch_summary_is_bounded_by_real_target_count(self):
        sections = "".join(
            f"*** Add File: components/{i}.txt\n+confidential-data-{i}\n"
            for i in range(7)
        )
        preview = approval_summary("apply_patch", {
            "server": "demo-node2", "reason": "review",
            "patch": "*** Begin Patch\n" + sections + "*** End Patch",
        })
        self.assertIn("components/0.txt", preview)
        self.assertIn("+2 other targets", preview)
        self.assertNotIn("components/6.txt", preview)
        self.assertNotIn("confidential-data", preview)
        self.assertLessEqual(len(preview), 500)

    def test_long_paths_and_moves_keep_names_and_omitted_target_count(self):
        long_dir = "nested/" + "x" * 190 + "/"
        patch_text = "*** Begin Patch\n" + "".join(
            f"*** Update File: {long_dir}source-{i}.txt\n"
            f"*** Move to: {long_dir}destination-{i}.txt\n"
            "@@\n-old\n+secret-content\n"
            for i in range(2)
        ) + "*** Add File: extra.txt\n+secret-content\n*** End Patch"
        preview = approval_summary("apply_patch", {
            "server": "demo-node2", "reason": "review", "patch": patch_text,
        })
        self.assertLessEqual(len(preview), 500)
        self.assertIn("source-0.txt", preview)
        self.assertIn("destination-0.txt", preview)
        self.assertIn("…", preview)
        self.assertIn("+3 other targets", preview)
        self.assertNotIn("source-1.txt", preview)
        self.assertNotIn("destination-1.txt", preview)
        self.assertNotIn("secret-content", preview)

    def test_single_long_file_path_shows_shortening_and_filename(self):
        path = "nested/" + "a" * 200 + "/important.txt"
        preview = approval_summary("read_file", {
            "server": "demo-node2", "reason": "review", "path": path,
        })
        self.assertEqual(len(preview), 180)
        self.assertIn("…", preview)
        self.assertTrue(preview.endswith("/important.txt"))


class InMemoryApprovalTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.manager = ApprovalManager()

    async def asyncTearDown(self):
        self.manager.shutdown()

    async def _root_pending(self, *, host_required=True, root_required=True,
                            key=KEY):
        task = asyncio.create_task(self.manager.require(
            key, tool="execute_command", reason="Synthetic root approval",
            summary="id -u", host_required=host_required,
            root_required=root_required,
        ))
        await asyncio.sleep(0)
        pending = list(self.manager.pending.values())
        self.assertTrue(pending)
        return task, pending[-1].id

    async def test_combined_root_and_host_approval_is_one_pending_and_two_grants(self):
        task, approval_id = await self._root_pending()
        pending = self.manager.pending[approval_id].public()
        self.assertTrue(pending["requires_host"])
        self.assertTrue(pending["requires_root"])
        self.assertEqual(len(self.manager.pending), 1)
        self.assertTrue(self.manager.decide(approval_id, grant=True, duration="15m"))
        await task
        self.assertIn(KEY, self.manager.grants)
        self.assertIn(KEY, self.manager.root_grants)
        visible = self.manager.snapshot()["active_grants"]
        self.assertEqual({entry["kind"] for entry in visible}, {"host", "root"})
        self.assertEqual({entry["scope_id"] for entry in visible}, {pending["scope_id"]})
        self.assertEqual({entry["conversation_scope_id"] for entry in visible},
                         {pending["conversation_scope_id"]})
        self.assertNotIn(KEY[0], str(pending))
        self.assertNotEqual(visible[0]["id"], visible[1]["id"])
        self.assertNotIn(KEY[0], str(visible))
        await self.manager.require(KEY, tool="submit_job", reason="again",
                                   summary="id", host_required=True, root_required=True)
        self.assertFalse(self.manager.pending)

    async def test_grant_pairing_scope_distinguishes_oauth_sessions(self):
        for key in (KEY, OTHER_LOGIN):
            pending, request_id = await self._root_pending(key=key)
            self.assertTrue(self.manager.decide(request_id, grant=True, duration="5m"))
            await pending
        active = self.manager.snapshot()["active_grants"]
        self.assertEqual(len(active), 4)
        self.assertEqual(len({grant["scope_id"] for grant in active}), 2)
        for kind in ("host", "root"):
            self.assertEqual(len([g for g in active if g["kind"] == kind]), 2)
        self.assertNotIn(KEY[0], str(active))
        self.assertNotIn(OTHER_LOGIN[0], str(active))

    async def test_conversation_scope_groups_hosts_not_logins_or_conversations(self):
        scopes = {}
        for key in (KEY, OTHER_HOST, OTHER_LOGIN, OTHER_CONVERSATION):
            task, request_id = await self._root_pending(key=key)
            pending = self.manager.pending[request_id].public()
            scopes[key] = pending["conversation_scope_id"]
            self.assertRegex(scopes[key], r"^[0-9a-f]{24}$")
            self.assertTrue(self.manager.decide(request_id, grant=True, duration="5m"))
            await task
        self.assertEqual(scopes[KEY], scopes[OTHER_HOST])
        self.assertEqual(len(set(scopes.values())), 3)
        active = self.manager.snapshot()["active_grants"]
        self.assertEqual(len(active), 8)
        self.assertEqual(len({g["scope_id"] for g in active}), 4)
        for key, scope in scopes.items():
            pairing = self.manager.grant_id(key, "scope")
            grants = [g for g in active if g["scope_id"] == pairing]
            self.assertEqual({g["conversation_scope_id"] for g in grants}, {scope})
            self.assertEqual({g["kind"] for g in grants}, {"host", "root"})
        self.assertTrue(self.manager.revoke(self.manager.grant_id(KEY)))
        self.assertNotIn(KEY, self.manager.grants)
        self.assertNotIn(KEY, self.manager.root_grants)
        self.assertIn(OTHER_HOST, self.manager.grants)
        self.assertIn(OTHER_HOST, self.manager.root_grants)

    async def test_sudo_only_grant_without_host_timed_chip(self):
        task, request_id = await self._root_pending(host_required=False)
        pending = self.manager.pending[request_id].public()
        self.assertFalse(pending["requires_host"])
        self.assertTrue(pending["requires_root"])
        self.assertFalse(pending["host_grant_extension_possible"])
        self.assertTrue(self.manager.decide(request_id, grant=True, duration="5m"))
        await task
        self.assertEqual(self.manager.grants, {})
        self.assertIn(KEY, self.manager.root_grants)
        root = self.manager.snapshot()["active_grants"]
        self.assertEqual(len(root), 1)
        self.assertEqual(root[0]["kind"], "root")
        self.assertTrue(self.manager.revoke(root[0]["id"]))
        self.assertEqual(self.manager.root_grants, {})

    async def test_sudo_expiry_extends_shorter_host_grant_but_not_longer_one(self):
        self.manager.grants[KEY] = time.monotonic() + 12
        task, request_id = await self._root_pending()
        self.assertFalse(self.manager.pending[request_id].grant_host)
        self.assertTrue(self.manager.pending[request_id].grant_root)
        self.assertTrue(self.manager.pending[request_id].public()["host_grant_extension_possible"])
        self.assertTrue(self.manager.decide(request_id, grant=True, duration="1h"))
        await task
        self.assertGreaterEqual(self.manager.grants[KEY], self.manager.root_grants[KEY])
        self.assertTrue(self.manager.revoke(self.manager.grant_id(KEY, "root")))
        self.assertIn(KEY, self.manager.grants)
        long_expiry = time.monotonic() + 16 * 3600
        self.manager.grants[KEY] = long_expiry
        task, request_id = await self._root_pending()
        self.assertTrue(self.manager.pending[request_id].public()["host_grant_extension_possible"])
        self.assertTrue(self.manager.decide(request_id, grant=True, duration="5m"))
        await task
        self.assertEqual(self.manager.grants[KEY], long_expiry)

    async def test_root_revocation_is_independent_and_host_revocation_cascades(self):
        task, approval_id = await self._root_pending()
        self.manager.decide(approval_id, grant=True, duration="8h")
        await task
        self.assertTrue(self.manager.revoke(self.manager.grant_id(KEY, "root")))
        self.assertIn(KEY, self.manager.grants)
        self.assertNotIn(KEY, self.manager.root_grants)
        root_request, request_id = await self._root_pending()
        self.assertFalse(self.manager.pending[request_id].grant_host)
        self.manager.decide(request_id, grant=True, duration="15m")
        await root_request
        self.assertTrue(self.manager.revoke(self.manager.grant_id(KEY)))
        self.assertNotIn(KEY, self.manager.grants)
        self.assertNotIn(KEY, self.manager.root_grants)

    async def test_revoked_host_while_sudo_only_modal_pending_never_restores_access(self):
        for duration in ("once", "5m"):
            with self.subTest(duration=duration):
                self.manager.grants[KEY] = time.monotonic() + 100
                pending, request_id = await self._root_pending()
                self.assertFalse(self.manager.pending[request_id].grant_host)
                self.assertTrue(self.manager.revoke(self.manager.grant_id(KEY)))
                self.assertFalse(self.manager.decide(
                    request_id, grant=True, duration=duration,
                ))
                self.assertNotIn(KEY, self.manager.grants)
                self.assertNotIn(KEY, self.manager.root_grants)
                self.assertNotIn(request_id, self.manager.pending)
                with self.assertRaises(SSHDenied):
                    await pending

    async def test_revoked_host_closes_dependent_pending_before_regrant(self):
        self.manager.grants[KEY] = time.monotonic() + 120
        waiting, request_id = await self._root_pending()
        self.assertFalse(self.manager.pending[request_id].grant_host)
        self.assertTrue(self.manager.revoke(self.manager.grant_id(KEY)))
        self.assertNotIn(request_id, self.manager.pending)
        self.assertEqual(self.manager.snapshot()["pending_approvals"], [])
        self.manager.grants[KEY] = time.monotonic() + 120
        self.assertFalse(self.manager.decide(request_id, grant=True, duration="16h"))
        with self.assertRaises(SSHDenied):
            await waiting

    async def test_expired_prerequisite_grants_evict_dependent_pending(self):
        for kind in ("host", "root"):
            with self.subTest(kind=kind):
                if kind == "host":
                    self.manager.grants[KEY] = time.monotonic() + 120
                else:
                    self.manager.root_grants[KEY] = time.monotonic() + 120
                waiting, request_id = await self._root_pending()
                dependent = self.manager.pending[request_id]
                self.assertFalse(dependent.grant_host if kind == "host"
                                 else dependent.grant_root)
                grants = (self.manager.grants if kind == "host"
                          else self.manager.root_grants)
                grants[KEY] = time.monotonic() - 1
                self.assertEqual(self.manager.snapshot()["pending_approvals"], [])
                self.assertNotIn(request_id, self.manager.pending)
                self.assertFalse(self.manager.decide(request_id, grant=True))
                with self.assertRaises(SSHDenied):
                    await waiting

    async def test_root_revocation_closes_host_only_pending_without_regrant(self):
        self.manager.root_grants[KEY] = time.monotonic() + 120
        waiting, request_id = await self._root_pending()
        self.assertFalse(self.manager.pending[request_id].grant_root)
        self.assertTrue(self.manager.revoke(self.manager.grant_id(KEY, "root")))
        self.assertNotIn(request_id, self.manager.pending)
        with self.assertRaises(SSHDenied):
            await waiting


    async def test_root_once_admits_only_waiting_request_and_creates_no_timed_grant(self):
        first, first_id = await self._root_pending()
        second, second_id = await self._root_pending()
        self.assertTrue(self.manager.decide(first_id, grant=True, duration="once"))
        await first
        self.assertFalse(second.done())
        self.assertEqual(self.manager.grants, {})
        self.assertEqual(self.manager.root_grants, {})
        self.manager.decide(second_id, grant=False)
        with self.assertRaises(SSHDenied):
            await second

    async def test_timed_host_grant_cannot_release_pending_root_approval(self):
        root, root_id = await self._root_pending()
        host, host_id = await self._root_pending(root_required=False)
        self.assertTrue(self.manager.decide(host_id, grant=True, duration="5m"))
        await host
        self.assertFalse(root.done())
        self.assertIn(root_id, self.manager.pending)
        self.manager.decide(root_id, grant=True, duration="5m")
        await root

    async def test_shutdown_and_expiry_clear_root_grants(self):
        self.manager.root_grants[KEY] = time.monotonic() - 1
        self.assertEqual(self.manager.snapshot()["active_grants"], [])
        self.manager.root_grants[KEY] = time.monotonic() + 100
        self.manager.shutdown()
        self.assertFalse(self.manager.root_grants)

    async def test_timed_grant_skips_operator_preview_generation(self):
        self.manager.grants[KEY] = time.monotonic() + 120

        def should_not_preview():
            self.fail("Existing timed grant must not parse an approval preview")

        await self.manager.require(KEY, tool="apply_patch", reason="audit path",
                                   summary=should_not_preview, steps=should_not_preview)
        self.assertFalse(self.manager.pending)

    async def test_operator_preview_runs_for_a_new_pending_request_only(self):
        previews = []

        def preview():
            previews.append("prepared")
            return "bounded path summary"

        task = asyncio.create_task(self.manager.require(
            KEY, tool="apply_patch", reason="file review", summary=preview,
            steps=lambda: [{"title": "Step 1", "interpreter": "bash -lc",
                            "command": "hostname\nuname -r", "truncated": False}],
        ))
        await asyncio.sleep(0)
        self.assertEqual(previews, ["prepared"])
        self.assertEqual(next(iter(self.manager.pending.values())).summary,
                         "bounded path summary")
        visible = next(iter(self.manager.pending.values())).public()
        self.assertEqual(visible["steps"][0]["command"], "hostname\nuname -r")
        self.assertNotIn(KEY[0], str(visible))  # OAuth sid never reaches viewer.
        self.manager.decide(next(iter(self.manager.pending)), grant=False)
        with self.assertRaises(SSHDenied):
            await task

    async def test_active_grant_checks_disconnect_and_revocation(self):
        self.manager.grants[KEY] = time.monotonic() + 120

        async def already_disconnected():
            return True

        with self.assertRaisesRegex(SSHDenied, "disconnected"):
            await self.manager.require(KEY, tool="execute_command", reason="closed",
                                       summary="hostname", disconnected=already_disconnected)

        async def revoked_while_checking():
            self.manager.revoke(self.manager.grant_id(KEY))
            return False

        from app.approval_status import ApprovalCode, ApprovalRejected
        with self.assertRaises(ApprovalRejected) as rejected:
            await self.manager.require(KEY, tool="execute_command", reason="revoked",
                                       summary="hostname", disconnected=revoked_while_checking)
        self.assertEqual(rejected.exception.approval_code, int(ApprovalCode.DENIED_REVOKED))

        self.manager.grants[KEY] = time.monotonic() + 120

        async def stopped_while_checking():
            self.manager.shutdown()
            return False

        with self.assertRaisesRegex(SSHDenied, "stopped"):
            await self.manager.require(KEY, tool="execute_command", reason="shutdown",
                                       summary="hostname", disconnected=stopped_while_checking)

    async def test_disconnect_watcher_evicts_pending_before_late_grant(self):
        connected = True

        async def disconnected():
            return not connected

        task = asyncio.create_task(self.manager.require(
            KEY, tool="execute_command", reason="disconnect", summary="hostname",
            disconnected=disconnected,
        ))
        await asyncio.sleep(.01)
        request_id = next(iter(self.manager.pending))
        connected = False
        with self.assertRaises(SSHDenied):
            await asyncio.wait_for(task, 1)
        self.assertNotIn(request_id, self.manager.pending)
        self.assertFalse(await self.manager.decide_live(
            request_id, grant=True, duration="16h",
        ))
        self.assertFalse(self.manager.grants)

    async def _queue(self, key=KEY, *, tool="execute_command"):
        task = asyncio.create_task(self.manager.require(
            key, tool=tool, reason="Synthetic operator test", summary="hostname",
        ))
        await asyncio.sleep(0)
        items = [x for x in self.manager.pending.values() if x.key == key]
        self.assertTrue(items)
        return task, items[-1].id

    async def test_one_request_approves_only_one_exact_suspended_call(self):
        first, first_id = await self._queue()
        second, second_id = await self._queue(tool="read_file")
        self.assertTrue(self.manager.decide(first_id, grant=True))
        self.assertFalse(self.manager.decide(first_id, grant=True))
        await first
        self.assertFalse(second.done())
        self.assertIn(second_id, self.manager.pending)
        self.assertEqual(self.manager.grants, {})
        self.assertTrue(self.manager.decide(second_id, grant=False))
        with self.assertRaises(SSHDenied):
            await second
        self.assertEqual(self.manager.snapshot()["pending_approvals"], [])

    async def test_timed_grant_releases_same_key_only_and_survives_later_calls(self):
        first, request_id = await self._queue()
        same, _ = await self._queue(tool="write_file")
        separate = [await self._queue(k) for k in (
            OTHER_CONVERSATION, OTHER_HOST, OTHER_LOGIN,
        )]
        self.assertTrue(self.manager.decide(request_id, grant=True, duration="5m"))
        await asyncio.gather(first, same)
        self.assertEqual(len(self.manager.grants), 1)
        self.assertTrue(all(not task.done() for task, _ in separate))
        await self.manager.require(KEY, tool="download_file", reason="", summary="")
        self.assertEqual(len(self.manager.snapshot()["active_grants"]), 1)
        grant_id = self.manager.snapshot()["active_grants"][0]["id"]
        self.assertTrue(self.manager.revoke(grant_id))
        self.assertFalse(self.manager.revoke(grant_id))
        subsequent, subsequent_id = await self._queue()
        self.assertTrue(self.manager.decide(subsequent_id, grant=False))
        with self.assertRaises(SSHDenied):
            await subsequent
        for pending, _ in separate:
            pending.cancel()
        await asyncio.gather(*(t for t, _ in separate), return_exceptions=True)
        self.assertEqual(self.manager.snapshot()["pending_approvals"], [])

    async def test_all_approved_durations_and_expired_grants(self):
        self.assertEqual(DURATIONS["once"], None)
        for duration in ("5m", "15m", "1h", "8h", "16h"):
            task, request_id = await self._queue()
            start = time.monotonic()
            self.assertTrue(self.manager.decide(request_id, grant=True, duration=duration))
            await task
            expiry = self.manager.grants[KEY]
            self.assertAlmostEqual(expiry - start, DURATIONS[duration], delta=1.0)
            self.manager.grants[KEY] = time.monotonic() - 1
        pending, request_id = await self._queue()
        self.assertFalse(self.manager.decide(request_id, grant=True, duration="99h"))
        self.assertIn(request_id, self.manager.pending)
        self.manager.decide(request_id, grant=False)
        with self.assertRaises(SSHDenied):
            await pending

    async def test_wait_timeout_and_no_late_approval(self):
        with patch("app.approvals.WAIT_SECONDS", 0.02):
            task, request_id = await self._queue()
            with self.assertRaises(SSHDenied):
                await asyncio.wait_for(task, 1)
        self.assertNotIn(request_id, self.manager.pending)
        self.assertFalse(self.manager.decide(request_id, grant=True, duration="8h"))
        self.assertFalse(self.manager.grants)

    async def test_snapshot_expires_pending_and_expired_grant_without_scheduler(self):
        task, request_id = await self._queue()
        self.manager.pending[request_id].deadline = time.monotonic() - 1
        self.manager.grants[OTHER_CONVERSATION] = time.monotonic() - 1
        self.assertEqual(self.manager.snapshot(), {
            "pending_approvals": [], "active_grants": [],
        })
        self.assertFalse(self.manager.decide(request_id, grant=True))
        with self.assertRaises(SSHDenied):
            await task

    async def test_grant_capacity_rejection_leaves_request_pending_for_denial(self):
        with patch("app.approvals.MAX_GRANTS", 1):
            existing, existing_id = await self._queue()
            self.assertTrue(self.manager.decide(existing_id, grant=True, duration="5m"))
            await existing
            other, other_id = await self._queue(OTHER_HOST)
            self.assertFalse(self.manager.decide(other_id, grant=True, duration="8h"))
            self.assertIn(other_id, self.manager.pending)
            self.assertEqual(len(self.manager.grants), 1)
            self.assertTrue(self.manager.decide(other_id, grant=False))
            with self.assertRaises(SSHDenied):
                await other

    async def test_duplicate_future_completion_is_not_replayed(self):
        task, request_id = await self._queue()
        self.manager.pending[request_id].future.set_result("")
        self.assertFalse(self.manager.decide(request_id, grant=True, duration="8h"))
        self.assertFalse(self.manager.grants)
        self.assertFalse(self.manager.decide(request_id, grant=False))
        with self.assertRaises(SSHDenied):
            await task

    async def test_cancelled_waiter_cannot_create_timed_grant_before_cleanup(self):
        task, request_id = await self._queue()
        task.cancel()
        # Deliberately do not yield to the cancelled coroutine yet.
        self.assertFalse(self.manager.decide(request_id, grant=True, duration="16h"))
        self.assertFalse(self.manager.grants)
        with self.assertRaises(asyncio.CancelledError):
            await task

    async def test_shutdown_after_one_shot_grant_before_waiter_runs(self):
        task, request_id = await self._queue()
        self.assertTrue(self.manager.decide(request_id, grant=True))
        self.manager.shutdown()
        with self.assertRaises(SSHDenied):
            await task

    async def test_backward_clock_change_does_not_extend_approval(self):
        task, request_id = await self._queue()
        self.assertTrue(self.manager.decide(request_id, grant=True, duration="5m"))
        await task
        self.manager.grants[KEY] = time.monotonic() - 1
        with patch("app.approvals.time.time", return_value=time.time() - 86400):
            other, next_id = await self._queue()
            self.assertFalse(self.manager.decide(next_id, grant=True, duration="invalid"))
            self.manager.decide(next_id, grant=False)
            with self.assertRaises(SSHDenied):
                await other

    async def test_asgi_http_disconnect_cancels_queued_command_before_dispatch(self):
        # Real Starlette Request reads the same http.disconnect transport
        # event the pinned SDK request_context receives after parsing POST.
        from starlette.requests import Request

        disconnect = asyncio.Queue()

        async def receive():
            return await disconnect.get()

        request = Request({"type": "http", "method": "POST",
                           "path": "/mcp", "headers": []}, receive)
        executed = []

        class RestrictedSSH:
            def require_ready(self, server, *, privileged=False):
                pass

            async def check_readiness_live(self, server, *, privileged=False):
                pass

            def authorized_host(self, actor, server):
                return type("Host", (), {"access": "restricted"})()

            async def execute(self):
                executed.append(True)

        executor = RestrictedSSH()
        async def call():
            await require_host_access(
                executor, "ssh-mcp-operator", "demo-node2",
                session_id=KEY[0], conversation_id=KEY[1],
                approvals=self.manager, tool="execute_command",
                reason="ASGI disconnect regression",
                disconnected=request.is_disconnected,
            )
            await executor.execute()

        task = asyncio.create_task(call())
        await asyncio.sleep(.1)
        self.assertEqual(len(self.manager.pending), 1)
        request_id = next(iter(self.manager.pending))
        await disconnect.put({"type": "http.disconnect"})
        with self.assertRaises(SSHDenied):
            await asyncio.wait_for(task, 2)
        self.assertFalse(self.manager.decide(request_id, grant=True, duration="8h"))
        self.assertEqual(executed, [])

    async def test_disconnect_after_decision_before_waiter_resume(self):
        disconnected = False

        async def check_disconnect():
            return disconnected

        task = asyncio.create_task(self.manager.require(
            KEY, tool="execute_command", reason="synthetic", summary="hostname",
            disconnected=check_disconnect,
        ))
        await asyncio.sleep(.01)
        request_id = next(iter(self.manager.pending))
        self.assertTrue(self.manager.decide(request_id, grant=True))
        disconnected = True
        with self.assertRaises(SSHDenied):
            await task

    async def test_timed_grant_rejects_origin_closed_before_commit(self):
        disconnected = False

        async def check_disconnect():
            return disconnected

        task = asyncio.create_task(self.manager.require(
            KEY, tool="execute_command", reason="origin liveness",
            summary="hostname", disconnected=check_disconnect,
        ))
        await asyncio.sleep(.01)
        request_id = next(iter(self.manager.pending))
        # The connection closed after the last watcher poll; the live
        # decision check must reject it before adding a reusable grant.
        disconnected = True
        self.assertFalse(await self.manager.decide_live(
            request_id, grant=True, duration="16h",
        ))
        self.assertFalse(self.manager.grants)
        with self.assertRaises(SSHDenied):
            await task

    async def test_timed_grant_fast_path_rechecks_connection_and_revocation(self):
        initial, request_id = await self._queue()
        self.assertTrue(self.manager.decide(request_id, grant=True, duration="5m"))
        await initial

        async def is_closed():
            return True

        with self.assertRaisesRegex(SSHDenied, "disconnected"):
            await self.manager.require(
                KEY, tool="execute_command", reason="closed timed request",
                summary="hostname", disconnected=is_closed,
            )

        async def revoked_while_checking():
            self.manager.grants.pop(KEY, None)
            return False

        with self.assertRaisesRegex(SSHDenied, "revoked or expired"):
            await self.manager.require(
                KEY, tool="execute_command", reason="revoked during check",
                summary="hostname", disconnected=revoked_while_checking,
            )
        self.assertEqual(self.manager.snapshot()["active_grants"], [])

    async def test_cached_timed_expiry_is_distinct_from_operator_revoke(self):
        from app.approval_status import ApprovalCode, ApprovalRejected
        self.manager.grants[KEY] = time.monotonic() + .005

        async def check_after_expiry():
            await asyncio.sleep(.02)
            return False

        with self.assertRaises(ApprovalRejected) as expired:
            await self.manager.require(
                KEY, tool="execute_command", reason="timed expiry",
                summary="hostname", disconnected=check_after_expiry,
            )
        self.assertEqual(expired.exception.approval_code,
                         int(ApprovalCode.DENIED_EXPIRED))

    async def test_watcher_probe_timeout_is_not_approval_expiration(self):
        from app.approval_status import ApprovalRejected

        async def timed_out_probe():
            raise TimeoutError("Synthetic connection probe timed out")

        with self.assertRaises(SSHDenied) as caught:
            await self.manager.require(
                KEY, tool="execute_command",
                reason="offline watcher timeout",
                summary="hostname", disconnected=timed_out_probe,
            )
        self.assertNotIsInstance(caught.exception, ApprovalRejected)
        self.assertEqual(self.manager.pending, {})
        self.assertFalse(self.manager.grants)

    async def test_watcher_failure_is_not_classified_as_disconnect(self):
        async def broken_probe():
            raise OSError("synthetic transport probe failure")

        with self.assertRaises(OSError):
            await self.manager.require(
                KEY, tool="execute_command", reason="broken probe",
                summary="hostname", disconnected=broken_probe,
            )
        self.assertFalse(self.manager.pending)

    async def test_explicit_deny_beats_late_disconnect(self):
        from app.approval_status import ApprovalCode, ApprovalRejected
        closed = False

        async def observed():
            return closed

        task = asyncio.create_task(self.manager.require(
            KEY, tool="execute_command", reason="simultaneous denial",
            summary="hostname", disconnected=observed,
        ))
        await asyncio.sleep(.01)
        request_id = next(iter(self.manager.pending))
        self.assertTrue(self.manager.decide(request_id, grant=False))
        closed = True
        with self.assertRaises(ApprovalRejected) as denied:
            await task
        self.assertEqual(denied.exception.approval_code,
                         int(ApprovalCode.DENIED_EXPLICIT))

    async def test_fresh_timed_grant_survives_unrelated_intermediate_revocation(self):
        from app.approval_status import ApprovalCode

        # Both permissions require a new operator decision. A separate host
        # grant can appear and disappear without becoming this request's
        # prerequisite; the eventual timed decision issues fresh grants.
        pending, approval_id = await self._root_pending()
        original = self.manager.pending[approval_id]
        self.assertTrue(original.grant_host)
        self.assertTrue(original.grant_root)
        self.manager.grants[KEY] = time.monotonic() + 120
        self.assertTrue(self.manager.revoke(self.manager.grant_id(KEY)))
        self.assertIn(approval_id, self.manager.pending)
        self.assertNotEqual(
            self.manager._revoke_generations.get((KEY, "host"), 0),
            original.host_revoke_generation,
        )
        self.assertTrue(self.manager.decide(
            approval_id, grant=True, duration="5m",
        ))
        self.assertEqual(await pending, ApprovalCode.APPROVED_TIMED)
        self.assertGreater(self.manager.grants[KEY], time.monotonic())
        self.assertGreater(self.manager.root_grants[KEY], time.monotonic())

    async def test_revoke_and_regrant_cannot_resurrect_cached_timed_request(self):
        from app.approval_status import ApprovalCode, ApprovalRejected

        self.manager.grants[KEY] = time.monotonic() + 120

        async def revoke_then_replace():
            self.assertTrue(self.manager.revoke(self.manager.grant_id(KEY)))
            self.manager.grants[KEY] = time.monotonic() + 120
            return False

        with self.assertRaises(ApprovalRejected) as denied:
            await self.manager.require(
                KEY, tool="execute_command", reason="replaced cached grant",
                summary="hostname", disconnected=revoke_then_replace,
            )
        self.assertEqual(denied.exception.approval_code,
                         int(ApprovalCode.DENIED_REVOKED))
        self.assertGreater(self.manager.grants[KEY], time.monotonic())

    async def test_revoke_and_regrant_cannot_resurrect_pending_root_request(self):
        from app.approval_status import ApprovalCode, ApprovalRejected

        self.manager.grants[KEY] = time.monotonic() + 120
        replaced = False

        async def revoke_after_grant_decision():
            nonlocal replaced
            # A pending request is still in the manager while the watcher
            # checks it. Final liveness happens after it has been dequeued.
            if not self.manager.pending and not replaced:
                replaced = True
                self.assertTrue(self.manager.revoke(self.manager.grant_id(KEY)))
                self.manager.grants[KEY] = time.monotonic() + 120
            return False

        task = asyncio.create_task(self.manager.require(
            KEY, tool="execute_command", reason="replaced prerequisite grant",
            summary="id -u", host_required=True, root_required=True,
            disconnected=revoke_after_grant_decision,
        ))
        for _ in range(20):
            if self.manager.pending:
                break
            await asyncio.sleep(.01)
        self.assertEqual(len(self.manager.pending), 1)
        request_id = next(iter(self.manager.pending))
        self.assertFalse(self.manager.pending[request_id].grant_host)
        self.assertTrue(self.manager.decide(request_id, grant=True, duration="once"))
        with self.assertRaises(ApprovalRejected) as denied:
            await task
        self.assertTrue(replaced)
        self.assertEqual(denied.exception.approval_code,
                         int(ApprovalCode.DENIED_REVOKED))

    async def test_timed_grant_fast_path_rejects_manager_shutdown_during_probe(self):
        task, request_id = await self._queue()
        self.manager.decide(request_id, grant=True, duration="5m")
        await task

        async def close_during_probe():
            self.manager.shutdown()
            return False

        with self.assertRaisesRegex(SSHDenied, "stopped"):
            await self.manager.require(
                KEY, tool="execute_command", reason="shutdown during probe",
                summary="hostname", disconnected=close_during_probe,
            )

    async def test_pending_with_live_transport_times_out_without_grant(self):
        async def connected():
            return False

        with patch("app.approvals.WAIT_SECONDS", .02):
            task = asyncio.create_task(self.manager.require(
                KEY, tool="execute_command", reason="timeout with connection",
                summary="hostname", disconnected=connected,
            ))
            with self.assertRaises(SSHDenied):
                await asyncio.wait_for(task, 2)
        self.assertFalse(self.manager.pending)
        self.assertFalse(self.manager.grants)

    async def test_decide_live_missing_request_and_no_transport_callback(self):
        self.assertFalse(await self.manager.decide_live(
            "nonexistent", grant=True, duration="5m",
        ))
        task, request_id = await self._queue()
        self.assertTrue(await self.manager.decide_live(
            request_id, grant=True, duration="once",
        ))
        await task
        self.assertFalse(await self.manager.decide_live(
            request_id, grant=True, duration="5m",
        ))
        self.assertFalse(self.manager.grants)

    async def test_last_suspension_rechecks_shutdown_and_revocation(self):
        for mode in ("once-shutdown", "timed-revoke", "once-expire"):
            with self.subTest(mode=mode):
                manager = ApprovalManager()
                watcher_cancelled = asyncio.Event()
                release_cleanup = asyncio.Event()
                watching = False

                async def delayed_disconnect():
                    nonlocal watching
                    if not watching:
                        watching = True
                        try:
                            await asyncio.Event().wait()
                        except asyncio.CancelledError:
                            watcher_cancelled.set()
                            await release_cleanup.wait()
                            raise
                    return False

                task = asyncio.create_task(manager.require(
                    KEY, tool="execute_command", reason="cleanup race",
                    summary="hostname", disconnected=delayed_disconnect,
                ))
                await asyncio.sleep(.01)
                request_id = next(iter(manager.pending))
                original_request = manager.pending[request_id]
                duration = "once" if mode.startswith("once-") else "5m"
                self.assertTrue(manager.decide(
                    request_id, grant=True, duration=duration,
                ))
                await asyncio.wait_for(watcher_cancelled.wait(), 2)
                if mode == "once-shutdown":
                    manager.shutdown()
                elif mode == "timed-revoke":
                    grant_id = manager.snapshot()["active_grants"][0]["id"]
                    self.assertTrue(manager.revoke(grant_id))
                else:
                    # A queued call cannot dispatch when its approval
                    # deadline elapses during watcher cancellation.
                    original_request.deadline = time.monotonic() - 1
                release_cleanup.set()
                with self.assertRaises(SSHDenied):
                    await asyncio.wait_for(task, 2)

    async def test_cancellation_and_shutdown_fail_closed(self):
        task, request_id = await self._queue()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(self.manager.decide(request_id, grant=True))
        pending, _ = await self._queue()
        self.manager.shutdown()
        with self.assertRaises(SSHDenied):
            await pending
        self.assertEqual(self.manager.snapshot()["pending_approvals"], [])
        with self.assertRaises(SSHDenied):
            await self.manager.require(KEY, tool="execute_command", reason="", summary="")

    async def test_pending_cap_and_snapshot_never_exposes_verified_sid(self):
        with patch("app.approvals.MAX_PENDING", 1):
            task, request_id = await self._queue()
            with self.assertRaises(SSHDenied):
                await self.manager.require(KEY, tool="execute_command", reason="", summary="")
            snapshot = self.manager.snapshot()
            self.assertNotIn(KEY[0], str(snapshot))
            self.assertNotIn("future", str(snapshot).lower())
            self.manager.decide(request_id, grant=False)
            with self.assertRaises(SSHDenied):
                await task

    async def test_approval_and_revoke_before_waiter_resume_prevents_execution(self):
        task, request_id = await self._queue()
        self.assertTrue(self.manager.decide(request_id, grant=True, duration="1h"))
        grant_id = self.manager.snapshot()["active_grants"][0]["id"]
        self.assertTrue(self.manager.revoke(grant_id))
        with self.assertRaises(SSHDenied):
            await task

    async def test_no_conversation_allows_only_exact_request_including_root(self):
        from app.approval_status import ApprovalCode
        key = (KEY[0], "", KEY[2])
        first, first_id = await self._root_pending(key=key)
        second, second_id = await self._root_pending(key=key)
        pending = self.manager.pending[first_id].public()
        self.assertIsNone(pending["conversation_id"])
        self.assertIsNone(pending["conversation_scope_id"])
        self.assertFalse(pending["timed_grants_allowed"])
        for duration in ("5m", "15m", "1h", "8h", "16h"):
            self.assertFalse(self.manager.decide(first_id, grant=True, duration=duration))
        self.assertEqual(self.manager.snapshot()["active_grants"], [])
        self.assertTrue(self.manager.decide(first_id, grant=True))
        self.assertEqual(await first, ApprovalCode.APPROVED_EXPLICIT)
        self.assertFalse(second.done())
        self.assertTrue(self.manager.decide(second_id, grant=False))
        with self.assertRaises(SSHDenied):
            await second
        self.assertEqual(self.manager.snapshot()["active_grants"], [])

    async def test_verified_agent_without_conversation_reuses_timed_grant_across_logins(self):
        from app.approval_status import ApprovalCode

        class Executor:
            _sudo_passwords = {"demo-node2": "synthetic"}

            def authorized_host(self, actor, server):
                if actor not in ("operator@client-a", "operator@client-b") or server != "demo-node2":
                    raise SSHDenied("Not in signed inventory")
                return type("Host", (), {"access": "restricted",
                                         "privileged_access": "restricted"})()

            async def check_readiness_live(self, server, *, privileged=False):
                pass

            def require_ready(self, server, *, privileged=False):
                pass

        executor = Executor()
        client_a = "https://example.invalid/client-a.json"
        client_b = "https://example.invalid/client-b.json"

        async def request(actor, client, sid, conversation=None, privileged=False):
            return await require_host_access(
                executor, actor, "demo-node2", session_id=sid,
                conversation_id=conversation, approvals=self.manager,
                client_id=client, privileged=privileged,
                tool="execute_command", reason="Synthetic verified OAuth request",
            )

        first = asyncio.create_task(request("operator@client-a", client_a, "oauth-sid-1"))
        await asyncio.sleep(0)
        item = next(iter(self.manager.pending.values()))
        self.assertEqual(item.public()["grant_scope"], "agent")
        self.assertIsNone(item.public()["conversation_id"])
        self.assertIsNone(item.public()["conversation_scope_id"])
        self.assertTrue(item.public()["timed_grants_allowed"])
        self.assertTrue(self.manager.decide(item.id, grant=True, duration="8h"))
        self.assertEqual(await first, ApprovalCode.APPROVED_TIMED)
        self.assertEqual(await request("operator@client-a", client_a, "oauth-sid-2"),
                         ApprovalCode.APPROVED_TIMED)
        self.assertFalse(self.manager.pending)

        grants = self.manager.snapshot()["active_grants"]
        self.assertEqual(len(grants), 1)
        self.assertEqual(grants[0]["grant_scope"], "agent")
        self.assertIsNone(grants[0]["conversation_id"])
        self.assertEqual(grants[0]["scope_id"], item.public()["scope_id"])
        self.assertEqual(len(self.manager.grants), 1)
        self.assertNotIn("oauth-sid-1", str(grants))
        self.assertNotIn(client_a, str(grants))

        other = asyncio.create_task(request("operator@client-b", client_b, "oauth-sid-3"))
        await asyncio.sleep(0)
        self.assertEqual(len(self.manager.pending), 1)
        self.manager.decide(next(iter(self.manager.pending)), grant=False)
        with self.assertRaises(SSHDenied):
            await other

        conversation = asyncio.create_task(request("operator@client-a", client_a,
                                                   "oauth-sid-2", "chat-1"))
        await asyncio.sleep(0)
        self.assertEqual(len(self.manager.pending), 1)
        self.manager.decide(next(iter(self.manager.pending)), grant=False)
        with self.assertRaises(SSHDenied):
            await conversation

        root = asyncio.create_task(request("operator@client-a", client_a,
                                           "oauth-sid-4", privileged=True))
        await asyncio.sleep(0)
        pending = next(iter(self.manager.pending.values()))
        self.assertFalse(pending.grant_host)
        self.assertTrue(pending.grant_root)
        self.assertTrue(pending.public()["host_grant_extension_possible"])
        self.assertTrue(self.manager.decide(pending.id, grant=True, duration="5m"))
        self.assertEqual(await root, ApprovalCode.APPROVED_TIMED)
        self.assertEqual(await request("operator@client-a", client_a, "oauth-sid-5",
                                       privileged=True), ApprovalCode.APPROVED_TIMED)
        active = self.manager.snapshot()["active_grants"]
        self.assertEqual(len(active), 2)
        self.assertEqual({g["kind"] for g in active}, {"host", "root"})
        self.assertEqual(len({g["scope_id"] for g in active}), 1)
        root_grant = next(g for g in active if g["kind"] == "root")
        self.assertTrue(self.manager.revoke(root_grant["id"]))
        again = asyncio.create_task(request("operator@client-a", client_a,
                                            "oauth-sid-6", privileged=True))
        await asyncio.sleep(0)
        self.assertEqual(len(self.manager.pending), 1)
        self.manager.decide(next(iter(self.manager.pending)), grant=False)
        with self.assertRaises(SSHDenied):
            await again
        host_grant = next(g for g in self.manager.snapshot()["active_grants"])
        self.assertTrue(self.manager.revoke(host_grant["id"]))
        self.assertEqual(self.manager.snapshot()["active_grants"], [])

    async def test_two_unlabelled_agent_grants_have_distinct_stable_revoke_identities(self):
        clients = ("https://one.example.invalid/client.json",
                   "https://two.example.invalid/client.json")
        with patch.object(config, "MCP_CLIENT_LABELS", {}):
            for index, client_id in enumerate(clients):
                key = (f"agent:operator-{index}", client_id, "demo-node2")
                task = asyncio.create_task(self.manager.require(
                    key, client_id=client_id, tool="execute_command",
                    reason="Synthetic agent grant", summary="id",
                    host_required=True, root_required=True,
                ))
                await asyncio.sleep(0)
                pending = next(iter(self.manager.pending.values()))
                fingerprint = hashlib.sha256(client_id.encode()).hexdigest()[:12]
                self.assertEqual(pending.public()["client_disambiguator"], fingerprint)
                self.assertTrue(self.manager.decide(pending.id, grant=True, duration="5m"))
                await task
            active = self.manager.snapshot()["active_grants"]
            self.assertEqual(len(active), 4)
            self.assertEqual({g["agent"] for g in active}, {"Unknown"})
            fingerprints = {hashlib.sha256(x.encode()).hexdigest()[:12] for x in clients}
            self.assertEqual({g["client_disambiguator"] for g in active}, fingerprints)
            self.assertEqual(len({g["scope_id"] for g in active}), 2)
            self.assertEqual(len({g["id"] for g in active}), 4)
            for fingerprint in fingerprints:
                pair = [g for g in active if g["client_disambiguator"] == fingerprint]
                self.assertEqual({g["kind"] for g in pair}, {"host", "root"})
                self.assertEqual(len({g["scope_id"] for g in pair}), 1)
            self.assertNotIn(clients[0], str(active))
            self.assertNotIn(clients[1], str(active))
            target = next(g for g in active if g["kind"] == "host")
            self.assertTrue(self.manager.revoke(target["id"]))
            remaining = self.manager.snapshot()["active_grants"]
            self.assertEqual(len(remaining), 2)
            self.assertEqual({g["client_disambiguator"] for g in remaining},
                             fingerprints - {target["client_disambiguator"]})

    async def test_pr1_gate_preserves_signed_host_and_missing_identity_denial(self):
        class Executor:
            def require_ready(self, server, *, privileged=False):
                pass

            async def check_readiness_live(self, server, *, privileged=False):
                pass

            def authorized_host(self, actor, server):
                if actor != "ssh-mcp-operator" or server != "demo-node2":
                    raise SSHDenied("Not in signed inventory")
                return type("Host", (), {"access": "restricted"})()
        executor = Executor()
        for sid, conversation in ((None, KEY[1]), (None, None)):
            with self.assertRaises(SSHDenied):
                await require_host_access(
                    executor, "ssh-mcp-operator", "demo-node2",
                    session_id=sid, conversation_id=conversation, approvals=self.manager,
                )
        task = asyncio.create_task(require_host_access(
            executor, "ssh-mcp-operator", "demo-node2",
            session_id=KEY[0], conversation_id=KEY[1],
            approvals=self.manager, tool="submit_job", reason="Synthetic",
        ))
        await asyncio.sleep(0)
        request_id = next(iter(self.manager.pending))
        self.manager.decide(request_id, grant=True)
        await task
        with self.assertRaises(SSHDenied):
            await require_host_access(
                executor, "other", "demo-node2",
                session_id=KEY[0], conversation_id=KEY[1], approvals=self.manager,
            )


    async def test_observed_disconnect_and_timed_grant_expiry_codes(self):
        from app.approval_status import ApprovalCode, ApprovalRejected
        disconnected = asyncio.Event()

        async def observe_disconnect():
            return disconnected.is_set()

        wait = asyncio.create_task(self.manager.require(
            KEY, tool="execute_command", reason="synthetic disconnect",
            summary="id -u", disconnected=observe_disconnect,
        ))
        await asyncio.sleep(0)
        self.assertTrue(self.manager.pending)
        disconnected.set()
        with self.assertRaises(ApprovalRejected) as result:
            await asyncio.wait_for(wait, 2)
        self.assertEqual(result.exception.approval_code,
                         int(ApprovalCode.DENIED_DISCONNECTED))
        self.assertEqual(self.manager.pending, {})

        self.manager.grants[KEY] = time.monotonic() + 100
        wait, request_id = await self._root_pending()
        self.assertFalse(self.manager.pending[request_id].grant_host)
        self.manager.grants[KEY] = time.monotonic() - 1
        self.manager.snapshot()
        with self.assertRaises(ApprovalRejected) as result:
            await wait
        self.assertEqual(result.exception.approval_code,
                         int(ApprovalCode.DENIED_EXPIRED))

    async def test_approval_return_classification_for_one_shot_timed_reuse(self):
        from app.approval_status import ApprovalCode
        pending, ident = await self._root_pending()
        self.assertTrue(self.manager.decide(ident, grant=True))
        self.assertEqual(await pending, ApprovalCode.APPROVED_EXPLICIT)
        pending, ident = await self._root_pending()
        self.assertTrue(self.manager.decide(ident, grant=True, duration="5m"))
        self.assertEqual(await pending, ApprovalCode.APPROVED_TIMED)
        self.assertEqual(await self.manager.require(
            KEY, tool="execute_command", reason="timed reuse", summary="hostname",
            host_required=True, root_required=True,
        ), ApprovalCode.APPROVED_TIMED)

    async def test_completed_future_cannot_be_granted_again(self):
        from app.approval_status import ApprovalCode, ApprovalRejected

        task, request_id = await self._root_pending()
        pending = self.manager.pending[request_id]
        pending.future.set_result("denied_explicit")
        # Even if expiration/cleanup is briefly deferred by an event-loop
        # race, the operator cannot turn a completed decision into a grant.
        with patch.object(self.manager, "_expire"):
            self.assertFalse(self.manager.decide(
                request_id, grant=True, duration="16h",
            ))
        self.assertNotIn(request_id, self.manager.pending)
        self.assertEqual(self.manager.grants, {})
        self.assertEqual(self.manager.root_grants, {})
        with self.assertRaises(ApprovalRejected) as error:
            await task
        self.assertEqual(error.exception.approval_code,
                         int(ApprovalCode.DENIED_EXPLICIT))

    async def test_revoke_generation_bound_and_missing_pending_decision(self):
        from app.approval_status import ApprovalCode

        # Revocation generations are nonsecret, bounded local state.
        self.assertFalse(self.manager._finish("nonexistent", "denied_explicit"))
        for index in range(4098):
            self.manager._note_revoke(("sid", "conversation", f"host-{index}"), "host")
        self.assertLessEqual(len(self.manager._revoke_generations), 4096)
        self.assertNotIn((("sid", "conversation", "host-0"), "host"),
                         self.manager._revoke_generations)

        self.manager._note_revoke(KEY, "root")
        revoked = self.manager._lost_grant(
            KEY, host_required=False, root_required=True,
            host_expiry=0, root_expiry=time.monotonic() + 120,
            host_generation=0, root_generation=0,
        )
        self.assertIsNotNone(revoked)
        self.assertEqual(revoked.approval_code, int(ApprovalCode.DENIED_REVOKED))

        expired = self.manager._lost_grant(
            KEY, host_required=True, root_required=False,
            host_expiry=time.monotonic() - 1, root_expiry=0,
            host_generation=0, root_generation=0,
        )
        self.assertIsNotNone(expired)
        self.assertEqual(expired.approval_code, int(ApprovalCode.DENIED_EXPIRED))

    async def test_root_timed_fast_path_preserves_revocation_and_expiry(self):
        from app.approval_status import ApprovalCode, ApprovalRejected

        for cause in ("revoked", "expired"):
            with self.subTest(cause=cause):
                manager = ApprovalManager()
                manager.root_grants[KEY] = time.monotonic() + (
                    120 if cause == "revoked" else .005
                )

                async def check_root_permission():
                    if cause == "revoked":
                        self.assertTrue(manager.revoke(manager.grant_id(KEY, "root")))
                    else:
                        await asyncio.sleep(.025)
                    return False

                with self.assertRaises(ApprovalRejected) as result:
                    await manager.require(
                        KEY, tool="execute_command",
                        reason="deterministic root grant loss",
                        summary="id -u", host_required=False,
                        root_required=True, disconnected=check_root_permission,
                    )
                expected = (ApprovalCode.DENIED_REVOKED if cause == "revoked"
                            else ApprovalCode.DENIED_EXPIRED)
                self.assertEqual(result.exception.approval_code, int(expected))
                self.assertEqual(manager.snapshot()["active_grants"], [])
                manager.shutdown()

    async def test_silent_prerequisite_loss_rejects_approval_before_ssh(self):
        from app.approval_status import ApprovalCode, ApprovalRejected

        for kind in ("host", "root"):
            with self.subTest(kind=kind):
                manager = ApprovalManager()
                grants = manager.grants if kind == "host" else manager.root_grants
                grants[KEY] = time.monotonic() + 120
                task = asyncio.create_task(manager.require(
                    KEY, tool="execute_command", reason="prerequisite race",
                    summary="id -u", host_required=True, root_required=True,
                ))
                await asyncio.sleep(0)
                self.assertEqual(len(manager.pending), 1)
                approval_id = next(iter(manager.pending))
                request = manager.pending[approval_id]
                self.assertFalse(request.grant_host if kind == "host"
                                 else request.grant_root)
                # Simulate removal between the pending popup and final
                # decision without relying on timer scheduling.
                del grants[KEY]
                self.assertFalse(manager.decide(
                    approval_id, grant=True, duration="once",
                ))
                self.assertNotIn(approval_id, manager.pending)
                with self.assertRaises(ApprovalRejected) as result:
                    await task
                self.assertEqual(result.exception.approval_code,
                                 int(ApprovalCode.DENIED_REVOKED))
                self.assertEqual(manager.grants, {})
                self.assertEqual(manager.root_grants, {})
                manager.shutdown()

    async def test_missing_grant_has_no_invented_revocation_cause(self):
        missing = self.manager._lost_grant(
            KEY, host_required=True, root_required=True,
            host_expiry=0, root_expiry=0,
            host_generation=0, root_generation=0,
        )
        self.assertIsNone(missing)
        self.manager.grants[KEY] = time.monotonic() + 120
        self.manager.root_grants[KEY] = time.monotonic() + 120
        still_live = self.manager._lost_grant(
            KEY, host_required=True, root_required=True,
            host_expiry=self.manager.grants[KEY],
            root_expiry=self.manager.root_grants[KEY],
            host_generation=0, root_generation=0,
        )
        self.assertIsNone(still_live)

    async def test_compact_outcomes_explicit_expired_and_operator_revoked(self):
        from app.approval_status import ApprovalCode, ApprovalRejected, decode

        self.assertEqual(decode(8), "denied_revoked")
        self.assertIsNone(decode(None))
        self.assertIsNone(decode(99))

        task, ident = await self._root_pending()
        self.assertTrue(self.manager.decide(ident, grant=False))
        with self.assertRaises(ApprovalRejected) as denied:
            await task
        self.assertEqual(denied.exception.approval_code,
                         int(ApprovalCode.DENIED_EXPLICIT))

        task, ident = await self._root_pending()
        self.manager.pending[ident].deadline = time.monotonic() - 1
        self.manager.snapshot()  # runs expiration cleanup
        with self.assertRaises(ApprovalRejected) as expired:
            await task
        self.assertEqual(expired.exception.approval_code,
                         int(ApprovalCode.DENIED_EXPIRED))

        self.manager.grants[KEY] = time.monotonic() + 100
        task, ident = await self._root_pending()
        self.assertFalse(self.manager.pending[ident].grant_host)
        self.assertTrue(self.manager.revoke(self.manager.grant_id(KEY)))
        with self.assertRaises(ApprovalRejected) as revoked:
            await task
        self.assertEqual(revoked.exception.approval_code,
                         int(ApprovalCode.DENIED_REVOKED))

class ApprovalViewerHTTPTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = JobStore(Path(self.directory.name) / "private" / "jobs.sqlite")
        self.manager = ApprovalManager()
        self.secret = "viewer-password-" + "z" * 48
        self.env = patch.dict(os.environ, {"HISTORY_VIEWER_PASSWORD": self.secret})
        self.origin = patch.object(config, "MCP_ISSUER", "https://lab.example.net")
        self.env.start()
        self.origin.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(self.origin.stop)
        app = FastAPI()
        app.include_router(create_history_router(
            self.store, approved_hosts=["demo-node2"], approvals=self.manager,
        ))
        self.tasks: list[asyncio.Task[None]] = []

        @app.get("/test/queue")
        async def queue():
            task = asyncio.create_task(self.manager.require(
                KEY, tool="execute_command", reason="fixture", summary="hostname",
            ))
            self.tasks.append(task)
            await asyncio.sleep(0)
            return {"id": next(reversed(self.manager.pending))}

        @app.get("/test/result")
        async def result():
            await asyncio.sleep(0)
            task = self.tasks[-1]
            if not task.done():
                return {"status": "pending"}
            try:
                await task
                return {"status": "approved"}
            except SSHDenied:
                return {"status": "denied"}

        self.context = TestClient(
            app, base_url="https://lab.example.net", follow_redirects=False,
        )
        self.client = self.context.__enter__()
        self.addCleanup(lambda: self.context.__exit__(None, None, None))

    def login(self):
        response = self.client.get("/console/login")
        csrf = re.search(r'name="csrf" value="([^"]+)"', response.text).group(1)
        answer = self.client.post("/console/login", data={
            "csrf": csrf, "password": self.secret,
        }, headers={"Origin": config.MCP_ISSUER})
        self.assertEqual(answer.status_code, 303)
        return csrf

    def test_malformed_approval_form_cannot_create_a_grant(self):
        request_id = self.client.get("/test/queue").json()["id"]
        csrf = self.login()
        with patch("app.history._form", side_effect=ValueError("bad form")):
            response = self.client.post(
                f"/console/api/approvals/{request_id}/grant",
                data={"csrf": csrf, "duration": "16h"},
                headers={"Origin": config.MCP_ISSUER},
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn(request_id, self.manager.pending)
        self.assertFalse(self.manager.grants)
        self.manager.decide(request_id, grant=False)

    def test_expired_or_unknown_approval_id_never_creates_timed_grant(self):
        csrf = self.login()
        response = self.client.post(
            "/console/api/approvals/nonexistent/grant",
            data={"csrf": csrf, "duration": "16h"},
            headers={"Origin": config.MCP_ISSUER},
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.manager.snapshot()["active_grants"], [])

    def test_grant_revoke_csrf_isolation_and_expiry(self):
        request_id = self.client.get("/test/queue").json()["id"]
        grant_path = f"/console/api/approvals/{request_id}/grant"
        self.assertEqual(self.client.post(grant_path).status_code, 401)
        self.assertEqual(self.client.get("/console/api/changes?after=0:_").status_code, 401)
        csrf = self.login()
        changes = self.client.get("/console/api/changes?after=0:_").json()
        self.assertEqual(changes["pending_approvals"][0]["id"], request_id)
        self.assertEqual(changes["pending_approvals"][0]["host"], KEY[2])
        self.assertNotIn(KEY[0], str(changes))
        self.assertEqual(self.client.post(grant_path, data={
            "csrf": csrf, "duration": "15m",
        }).status_code, 403)
        self.assertEqual(self.client.post(grant_path, data={
            "csrf": "invalid", "duration": "15m",
        }, headers={"Origin": config.MCP_ISSUER}).status_code, 403)
        self.assertEqual(self.client.post(grant_path, data={
            "csrf": csrf, "duration": "2d",
        }, headers={"Origin": config.MCP_ISSUER}).status_code, 400)
        self.assertEqual(self.client.post(grant_path, data={
            "csrf": csrf, "duration": "15m",
        }, headers={"Origin": config.MCP_ISSUER}).status_code, 200)
        self.assertEqual(self.client.get("/test/result").json()["status"], "approved")
        changes = self.client.get("/console/api/changes?after=0:_").json()
        self.assertEqual(changes["pending_approvals"], [])
        self.assertEqual(len(changes["active_grants"]), 1)
        grant_id = changes["active_grants"][0]["id"]
        revoke_path = f"/console/api/grants/{grant_id}/revoke"
        revoked = self.client.post(revoke_path, data={"csrf": csrf},
                                   headers={"Origin": config.MCP_ISSUER})
        self.assertEqual(revoked.status_code, 200)
        self.assertTrue(revoked.json()["ok"])
        self.assertEqual(revoked.json()["active_grants"], [])
        self.assertEqual(revoked.json()["approval_instance"], changes["approval_instance"])
        self.assertGreater(revoked.json()["approval_revision"], changes["approval_revision"])
        missing = self.client.post(revoke_path, data={"csrf": csrf},
                                   headers={"Origin": config.MCP_ISSUER})
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.json()["active_grants"], [])
        self.assertEqual(missing.json()["approval_revision"], revoked.json()["approval_revision"])

    def test_deny_and_single_use_token(self):
        request_id = self.client.get("/test/queue").json()["id"]
        csrf = self.login()
        deny_path = f"/console/api/approvals/{request_id}/deny"
        headers = {"Origin": config.MCP_ISSUER}
        self.assertEqual(self.client.post(deny_path, data={
            "csrf": csrf,
        }, headers=headers).status_code, 200)
        self.assertEqual(self.client.get("/test/result").json()["status"], "denied")
        self.assertEqual(self.client.post(deny_path, data={
            "csrf": csrf,
        }, headers=headers).status_code, 404)
        self.assertEqual(self.manager.snapshot()["active_grants"], [])

    def test_logout_while_body_is_being_read_cannot_approve(self):
        from app import history as history_module

        request_id = self.client.get("/test/queue").json()["id"]
        csrf = self.login()
        original = history_module._form

        async def revoke_during_form(request):
            data = await original(request)
            with self.store._connect() as db:
                db.execute("DELETE FROM history_sessions")
            return data

        with patch("app.history._form", side_effect=revoke_during_form):
            response = self.client.post(
                f"/console/api/approvals/{request_id}/grant",
                data={"csrf": csrf, "duration": "8h"},
                headers={"Origin": config.MCP_ISSUER},
            )
        self.assertEqual(response.status_code, 401)
        self.assertIn(request_id, self.manager.pending)
        self.assertEqual(self.manager.grants, {})
        self.manager.decide(request_id, grant=False)

    def test_logout_commits_before_grant_cannot_use_stale_session(self):
        from app.history import ViewerAuth

        request_id = self.client.get("/test/queue").json()["id"]
        csrf = self.login()
        entered_logout = threading.Event()
        release_logout = threading.Event()
        original = ViewerAuth.logout
        results: dict[str, int] = {}

        def delayed_logout(auth, session):
            entered_logout.set()
            if not release_logout.wait(5):
                raise AssertionError("Logout was not released")
            return original(auth, session)

        def send_logout():
            results["logout"] = self.client.post(
                "/console/logout", data={"csrf": csrf},
                headers={"Origin": config.MCP_ISSUER},
            ).status_code

        def send_grant():
            results["grant"] = self.client.post(
                f"/console/api/approvals/{request_id}/grant",
                data={"csrf": csrf, "duration": "8h"},
                headers={"Origin": config.MCP_ISSUER},
            ).status_code

        with patch.object(ViewerAuth, "logout", delayed_logout):
            outgoing = threading.Thread(target=send_logout)
            outgoing.start()
            try:
                self.assertTrue(entered_logout.wait(3))
                approval = threading.Thread(target=send_grant)
                approval.start()
                # Logout holds the decision lock. Grant must not commit
                # while logout is in progress.
                self.assertFalse(self.manager.grants)
            finally:
                release_logout.set()
                outgoing.join(5)
            approval.join(5)
        self.assertFalse(outgoing.is_alive())
        self.assertFalse(approval.is_alive())
        self.assertEqual(results["logout"], 303)
        self.assertEqual(results["grant"], 401)
        self.assertFalse(self.manager.grants)
        self.assertIn(request_id, self.manager.pending)
        self.manager.decide(request_id, grant=False)

    def test_logged_out_viewer_cannot_deny_or_revoke(self):
        request_id = self.client.get("/test/queue").json()["id"]
        csrf = self.login()
        logout = self.client.post(
            "/console/logout", data={"csrf": csrf},
            headers={"Origin": config.MCP_ISSUER},
        )
        self.assertEqual(logout.status_code, 303)
        for path in (
            f"/console/api/approvals/{request_id}/grant",
            f"/console/api/approvals/{request_id}/deny",
            "/console/api/grants/synthetic-grant/revoke",
        ):
            with self.subTest(path=path):
                response = self.client.post(
                    path, data={"csrf": csrf, "duration": "8h"},
                    headers={"Origin": config.MCP_ISSUER},
                )
                self.assertEqual(response.status_code, 401)
        self.assertFalse(self.manager.grants)
        self.manager.decide(request_id, grant=False)

    def test_slow_sqlite_change_poll_does_not_block_approval_decisions(self):
        request_id = self.client.get("/test/queue").json()["id"]
        csrf = self.login()
        entered = threading.Event()
        release = threading.Event()
        original = HistoryStore.changes

        def delayed_history(store, after, *args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise AssertionError("History poll blocked the approval loop")
            return original(store, after, *args, **kwargs)

        answer = {}

        def poll_history():
            answer["response"] = self.client.get("/console/api/changes?after=0:_")

        with patch.object(HistoryStore, "changes", delayed_history):
            worker = threading.Thread(target=poll_history)
            worker.start()
            try:
                self.assertTrue(entered.wait(3))
                denied = self.client.post(
                    f"/console/api/approvals/{request_id}/deny",
                    data={"csrf": csrf},
                    headers={"Origin": config.MCP_ISSUER},
                )
                self.assertEqual(denied.status_code, 200)
            finally:
                release.set()
                worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(answer["response"].status_code, 200)
