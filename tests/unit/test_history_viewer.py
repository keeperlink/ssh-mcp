"""TEST-209 browser authorization, private history, pagination and sync audit tests."""
from __future__ import annotations

import asyncio
import base64
import os
import re
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ.setdefault("MCP_ISSUER", "http://localhost")
os.environ.setdefault("MCP_LOGIN_KEY", "synthetic-test-login-" + "a" * 40)
os.environ.setdefault("MCP_TOKEN_SIGNING_SECRET", "synthetic-test-signing-" + "b" * 40)
os.environ.setdefault("MCP_CIMD_VALIDATE_REMOTE", "false")

from app import config
from app.contracts import ExecuteCommandRequest
from app.history import (
    ABSOLUTE_SECONDS, CSRF_COOKIE, IDLE_SECONDS, SESSION_COOKIE,
    LEGACY_SESSION_COOKIE, LEGACY_CSRF_COOKIE,
    ASSETS, HistoryStore, ViewerAuth, _cursor, _date_epoch, _plain_command, _history_page,
    create_history_router,
)
from app.jobs import JobManager, JobStore
from app.ssh_executor import SSHDenied, SSHResult


def request(*argv: str, story_id: str | None = "TEST-209") -> ExecuteCommandRequest:
    return ExecuteCommandRequest(
        server="demo-node-b", argv=list(argv), reason="Run history acceptance",
        timeout_seconds=30, story_id=story_id,
    )


class FakeExecutor:
    def list_servers(self, actor):
        return ["demo-node-b"] if actor in {"alice", "bob"} else []

    async def execute(self, actor, job, *, on_output=None, on_admitted=None):
        if on_admitted is not None:
            on_admitted()
        if actor not in {"alice", "bob"}:
            raise SSHDenied("not permitted")
        if on_output:
            await on_output("stdout", "test ✓\n".encode())
            await on_output("stderr", b"note\n")
        return SSHResult(job.server, "succeeded", 0, "test ✓\n", "note\n", .17)


class ApprovalDialogMarkupTests(unittest.TestCase):
    def test_operator_dialog_has_moved_icons_radios_and_safe_preview_containers(self):
        page = _history_page("synthetic-csrf")
        header = page.split("</header>", 1)[0]
        self.assertNotIn('id="approval-mute"', header)
        self.assertNotIn('id="approval-notifications"', header)
        self.assertIn('id="approval-mute"', page)
        self.assertIn('id="approval-notifications"', page)
        self.assertIn('class="icon-slash"', page)
        self.assertIn('aria-label="Deny request and close"', page)
        self.assertIn('An agent is waiting for your approval', page)
        for label in ("Client", "Host", "Conversation", "Operation", "Expires in"):
            self.assertIn(label, page)
        self.assertIn('id="approval-expiry"', page)
        self.assertIn('id="approval-reason"', page)
        self.assertIn('id="approval-steps"', page)
        self.assertIn('id="approval-summary"', page)
        self.assertIn('id="approval-durations"', page)
        self.assertIn('id="approval-duration-warning"', page)
        self.assertIn('Timed grants are disabled because this client did not provide a conversation ID.', page)
        self.assertIn('id="approval-client"', page)
        self.assertNotIn('<select id="approval-duration"', page)
        for value in ("once", "5m", "15m", "1h", "8h", "16h"):
            self.assertIn(f'name="approval-duration" value="{value}"', page)
        self.assertIn('id="grant-chips"', header)
        self.assertIn('type="button" class="approval-grant">Grant</button>', page)


class StoryIdViewerConfigTests(unittest.TestCase):
    def test_table_attributes_follow_config_without_changing_detail_values(self):
        with patch.dict(os.environ, {"HISTORY_STORY_ID_MAX_CHARS": "9",
                                     "HISTORY_STORY_ID_TRUNCATE_FROM": "start"}):
            page = _history_page("test")
        self.assertIn('data-story-id-max-chars="9"', page)
        self.assertIn('data-story-id-truncate-from="start"', page)
        js = (ASSETS / "console.js").read_text()
        self.assertIn("const tableStoryId = (id)", js)
        self.assertIn('td.setAttribute("title", job.story_id)', js)
        self.assertIn('["Story ID", job.story_id || "—"]', js)


class GrantBubbleLayoutTests(unittest.TestCase):
    def test_long_grants_use_rounded_hours_and_header_remaining_width(self):
        """The header strip must expand leftward toward the History title."""
        assets = ASSETS  # Resolve installed-wheel package assets, not test source checkout.
        approvals = (assets / "approvals.js").read_text()
        styles = (assets / "style.css").read_text()
        self.assertIn('if (minutes <= 99) return minutes + "m";', approvals)
        self.assertIn('return Math.round(minutes / 60) + "h";', approvals)
        self.assertNotIn('return hours + "h" + (rest ?', approvals)
        self.assertIn('.top-actions{gap:9px;min-width:0;flex:1 1 0;', styles)
        self.assertIn('.grant-chips{display:flex;flex:1 1 auto;min-width:0;', styles)
        self.assertNotIn('max-width:42vw', styles)
        self.assertNotIn('max-width:38vw', styles)


class HistoryStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "private" / "jobs.sqlite"
        self.store = JobStore(self.path, retention_seconds=366 * 86400)
        self.history = HistoryStore(self.store)

    def save(self, actor="alice", *, story_id="TEST-209", mode="async",
             argv=("sh", "-c", "echo safe\nhostname -s"), status="succeeded",
             privileged=False):
        item = request(*argv, story_id=story_id).model_copy(
            update={"privileged": privileged},
        )
        job_id = self.store.create(actor, item, mode=mode)
        self.store.begin(job_id)
        self.store.append(job_id, "stdout", b"ready\n")
        self.store.finish(job_id, status, exit_code=0, elapsed=.3,
                          root_started=True if privileged else None)
        return job_id

    def test_root_history_filter_uses_persisted_flag_and_combines_existing_filters(self):
        from app.file_audit import FileAudit

        ordinary = self.save(story_id="TEST-267", argv=("sudo", "whoami"))
        root = self.save(story_id="TEST-267", argv=("whoami",), privileged=True)
        other = self.save("bob", story_id="TEST-268", privileged=True)
        file_id = FileAudit(self.store).start("alice", "demo-node-b", "read",
                                              "synthetic.txt", "TEST-267")
        FileAudit(self.store).finish(file_id, "succeeded", byte_count=4)
        listing = self.history.list({"privileged": "true"})
        self.assertEqual({row["id"] for row in listing["jobs"]}, {root, other})
        self.assertEqual(listing["filtered_total"], 2)
        self.assertEqual([j["id"] for j in self.history.list({
            "privileged": "true", "story_id": "TEST-267",
            "command": "whoami",
        })["jobs"]], [root])
        self.assertEqual(self.history.list({"privileged": "true", "mode": "file"})[
            "jobs"], [])
        self.assertIn(ordinary, {row["id"] for row in self.history.list({})["jobs"]})
        self.assertTrue(self.history.detail(root)["privileged"])
        self.assertTrue(self.history.detail(root)["root_started"])
        self.assertEqual(self.history.detail(root)["run_as"], "root")
        self.assertIsNone(self.history.detail(ordinary)["run_as"])
        reopened = HistoryStore(JobStore(self.path))
        self.assertEqual(reopened.list({"privileged": "true"})["filtered_total"], 2)
        self.assertEqual(reopened.detail(root)["run_as"], "root")
        for bad in ("false", "1", "yes", "TRUE"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.history.list({"privileged": bad})

    def test_db_context_closes_descriptors_even_on_error(self):
        with self.store._connect() as db:
            self.assertEqual(db.execute("SELECT 1").fetchone()[0], 1)
        with self.assertRaises(sqlite3.ProgrammingError):
            db.execute("SELECT 1")
        try:
            with self.store._connect() as db_error:
                raise RuntimeError("synthetic failure")
        except RuntimeError:
            pass
        with self.assertRaises(sqlite3.ProgrammingError):
            db_error.execute("SELECT 1")

    def test_admin_lists_all_actors_and_complete_requests(self):
        a = self.save("alice", mode="sync", story_id="TEST-209")
        b = self.save("bob", mode="async", story_id="TEST-208",
                      argv=("hostname", "-s"))
        result = self.history.list({})
        self.assertEqual({j["id"] for j in result["jobs"]}, {a, b})
        self.assertEqual({j["actor"] for j in result["jobs"]}, {"alice", "bob"})
        detail = self.history.detail(a)
        self.assertEqual(detail["mode"], "sync")
        self.assertEqual(detail["story_id"], "TEST-209")
        self.assertEqual(detail["terminal_command"], "echo safe\nhostname -s")
        self.assertEqual(detail["request"]["reason"], "Run history acceptance")
        self.assertEqual(detail["request"]["argv"], ["sh", "-c", "echo safe\nhostname -s"])
        self.assertEqual(self.history.detail(b)["terminal_command"], "hostname -s")
        self.assertEqual(base64.b64decode(self.history.output(b)["chunks"][0]["data_base64"]), b"ready\n")
        self.assertEqual(self.history.output(b, cursor=4)["next_cursor"], 6)
        self.assertIsNone(self.store.get("alice", b))  # MCP remains actor-scoped.
        self.assertIsNone(self.history.detail("INVALID!"))
        self.assertIsNone(self.history.output("INVALID!"))
        self.assertIsNone(self.history.detail("A" * 20))
        self.assertIsNone(self.history.output("A" * 20))

    def test_retained_stats_filter_kind_dates_and_group_limits(self):
        from app.file_audit import FileAudit

        good = self.save("alice", story_id="TEST-243", status="succeeded")
        bad = self.save("bob", story_id="TEST-243", status="transport_error")
        old = self.save("bob", story_id="TEST-191", status="failed")
        audit = FileAudit(self.store)
        file_id = audit.start("bob", "ssh-mcp-archived", "inspect",
                              "/safe/log.txt", "TEST-243")
        audit.finish(file_id, "partial", error_code="not_found", byte_count=1)
        with self.store._connect() as db:
            db.execute("UPDATE jobs SET created_at=? WHERE id=?",
                       (time.time() - 40 * 86400, old))
        self.assertEqual(self.history.hosts(), ["demo-node-b", "ssh-mcp-archived"])
        summary = self.history.list({"record_kind": "all"})
        self.assertEqual(len(summary["jobs"]), 4)
        self.assertTrue(all("reason" in row for row in summary["jobs"]))
        self.assertEqual(self.history.list({"record_kind": "file"})["filtered_total"], 1)
        result = self.history.stats({
            "story_id": "243", "time_range": "all", "record_kind": "all",
        }, group_by="status")
        self.assertEqual(result["total"], 3)
        self.assertEqual(result["failures"], 2)
        self.assertEqual(result["transport_errors"], 1)
        self.assertEqual({item["name"] for item in result["groups"]},
                         {"succeeded", "transport_error", "partial"})
        bounded = self.history.stats({"record_kind": "all", "time_range": "7d"},
                                     group_by="host", limit=1)
        self.assertEqual(bounded["total"], 3)
        self.assertTrue(bounded["groups_truncated"])
        self.assertEqual(len(bounded["groups"]), 1)
        self.assertEqual(self.history.stats({
            "record_kind": "command", "time_range": "7d",
        })["total"], 2)
        self.assertEqual(self.history.stats({
            "record_kind": "command", "time_range": "all",
        })["total"], 3)
        self.assertEqual(self.history.stats({
            "record_kind": "command", "from_date": "2100-01-01",
        })["total"], 0)
        self.assertEqual(self.history.stats({
            "record_kind": "all", "time_range": "all",
        }, group_by="day")["total"], 4)
        self.assertIsNotNone(self.history.detail(good))
        self.assertIsNotNone(self.history.detail(bad))
        for filters in (
            {"record_kind": "invalid"}, {"from_date": "2026-02-30"},
            {"to_date": "1970-01-01", "from_date": "2026-01-01"},
        ):
            with self.subTest(filters=filters), self.assertRaises(ValueError):
                self.history.stats(filters)
        for group_by, limit in (("actor", 5), ("host", 0), ("host", 101)):
            with self.assertRaises(ValueError):
                self.history.stats({}, group_by=group_by, limit=limit)

    def test_dashboard_totals_cover_all_retained_jobs_not_visible_page_or_filters(self):
        statuses = (
            "succeeded", "succeeded", "failed", "timed_out",
            "transport_error", "output_limit", "interrupted", "cancelled",
        )
        for status in statuses:
            self.save(status=status)
        queued = self.store.create("alice", request("hostname", "-s"))
        running = self.store.create("alice", request("hostname", "-s"))
        self.store.begin(running)
        expected = {
            "total": 10, "running": 2, "succeeded": 2, "failed": 5,
            "cancelled": 1,
        }
        self.assertEqual(self.history.totals(), expected)
        self.assertEqual(self.history.list({}, limit=1)["totals"], expected)
        filtered = self.history.list({"status": "succeeded"}, limit=1)
        self.assertEqual(len(filtered["jobs"]), 1)
        self.assertIsNotNone(filtered["next_page"])
        self.assertEqual(filtered["totals"], expected)
        self.assertEqual(self.history.list({"story_id": "TEST-999"})["totals"], expected)
        self.assertIsNotNone(self.store.get("alice", queued))
        self.store.finish(running, "succeeded", exit_code=0)
        self.assertEqual(self.history.totals()["succeeded"], 3)
        self.assertEqual(self.history.totals()["running"], 1)

    def test_time_range_filter_is_rolling_and_validated(self):
        now = time.time()
        newest = self.save(argv=("hostname", "-s"))
        four_hours = self.save(argv=("bash", "-lc", "echo four hours"))
        two_days = self.save(argv=("bash", "-lc", "echo two days"))
        twenty_days = self.save(argv=("bash", "-lc", "echo twenty days"))
        with self.store._connect() as db:
            for job, age in ((four_hours, 4 * 3600),
                             (two_days, 2 * 86400),
                             (twenty_days, 20 * 86400)):
                db.execute("UPDATE jobs SET created_at=? WHERE id=?", (now - age, job))
        def ids(period):
            return {item["id"] for item in
                    self.history.list({"time_range": period})["jobs"]}
        self.assertEqual(ids("1h"), {newest})
        self.assertEqual(ids("8h"), {newest, four_hours})
        self.assertEqual(ids("24h"), {newest, four_hours})
        self.assertEqual(ids("7d"), {newest, four_hours, two_days})
        self.assertEqual(ids("30d"), {newest, four_hours, two_days, twenty_days})
        self.assertEqual(ids("all"), {newest, four_hours, two_days, twenty_days})
        self.assertEqual(self.history.list({"time_range": "1h"})["totals"]["total"], 1)
        self.assertEqual(self.history.list({"time_range": "8h"})["totals"]["total"], 2)
        self.assertEqual(self.history.list({"time_range": "7d"})["totals"]["total"], 3)
        self.assertEqual(self.history.list({"time_range": "all"})["totals"]["total"], 4)
        self.assertEqual(self.history.totals("24h")["total"], 2)
        for period in ("0h", "365d", "yesterday", "7d OR 1=1"):
            with self.subTest(period=period), self.assertRaises(ValueError):
                self.history.list({"time_range": period})

    def test_kpis_use_only_time_range_not_story_host_command_mode_or_status(self):
        self.save(story_id="TEST-191", status="succeeded")
        self.save(story_id="TEST-232", status="transport_error")
        self.save(story_id="TEST-232", status="timed_out")
        self.save(story_id="TEST-232", status="cancelled")
        self.store.create("alice", request("hostname", "-s", story_id="TEST-191"))
        older_success = self.save(story_id="TEST-191", status="succeeded")
        older_failure = self.save(story_id="TEST-191", status="failed")
        with self.store._connect() as db:
            db.execute("UPDATE jobs SET created_at=? WHERE id IN (?,?)",
                       (time.time() - 2 * 86400, older_success, older_failure))
        recent = {"total": 5, "running": 1, "succeeded": 1,
                  "failed": 2, "cancelled": 1}
        all_time = {"total": 7, "running": 1, "succeeded": 2,
                    "failed": 3, "cancelled": 1}
        self.assertEqual(self.history.totals("24h"), recent)
        self.assertEqual(self.history.totals("all"), all_time)
        self.assertEqual(self.history.totals(), all_time)  # Legacy all-time API.
        empty = self.history.list({
            "time_range": "24h", "story_id": "TEST-999",
            "host": "unmatched", "status": "failed", "mode": "sync",
            "command": "unmatched",
        }, page=1, limit=2)
        self.assertEqual(empty["filtered_total"], 0)
        self.assertEqual(empty["jobs"], [])
        self.assertEqual(empty["totals"], recent)
        narrower = self.history.list({"time_range": "24h", "status": "succeeded"},
                                     page=1, limit=1)
        self.assertEqual(narrower["filtered_total"], 1)
        self.assertEqual(narrower["totals"], recent)
        for bad in ("1year", "24h OR 1=1"):
            with self.assertRaises(ValueError):
                self.history.totals(bad)

    def test_first_command_line_preview_is_bounded_and_full_request_preserved(self):
        one = self.save(argv=("bash", "-lc", "echo first line\necho second line"))
        direct = self.save(argv=("hostname", "-s"))
        long_line = "echo " + "x" * 450
        long_id = self.save(argv=("bash", "-lc", long_line + "\necho hidden"))
        listing = {row["id"]: row for row in self.history.list({})["jobs"]}
        self.assertEqual(listing[one]["command_preview"], "echo first line")
        self.assertEqual(listing[direct]["command_preview"], "hostname -s")
        preview = listing[long_id]["command_preview"]
        self.assertEqual(len(preview), 288)
        self.assertEqual(preview[:287], long_line[:287])
        self.assertTrue(preview.endswith("…"))
        self.assertNotIn("hidden", preview)
        self.assertEqual(self.history.detail(one)["terminal_command"],
                         "echo first line\necho second line")
        with self.store._connect() as db:
            db.execute("UPDATE jobs SET request_json=NULL WHERE id=?", (one,))
        self.assertEqual(next(row["command_preview"] for row in
                              self.history.list({})["jobs"] if row["id"] == one), "bash")

    def test_empty_history_starts_polling_and_detects_first_job(self):
        empty = self.history.list({})
        self.assertEqual(empty["jobs"], [])
        self.assertEqual(empty["changes_cursor"], "0:_")
        self.assertEqual(self.history.changes("0:_")["jobs"], [])
        created = self.save()
        result = self.history.changes("0:_")
        self.assertEqual([item["id"] for item in result["jobs"]], [created])

    def test_filters_pagination_and_incremental_cursor(self):
        a = self.save(story_id="TEST-209", mode="sync", argv=("hostname", "-s"))
        time.sleep(.002)
        b = self.save(story_id="TEST-208", mode="async")
        listing = self.history.list({}, limit=1)
        self.assertEqual(listing["jobs"][0]["id"], b)
        old = self.history.list({}, before=listing["next_page"], limit=1)
        self.assertEqual(old["jobs"][0]["id"], a)
        self.assertIsNone(old["next_page"])
        self.assertEqual([x["id"] for x in self.history.list({"story_id": "TEST-209"})["jobs"]], [a])
        self.assertEqual([x["id"] for x in self.history.list({"mode": "sync"})["jobs"]], [a])
        self.assertEqual([x["id"] for x in self.history.list({"status": "succeeded"})["jobs"]], [b, a])
        self.assertEqual([x["id"] for x in self.history.list({"host": "demo-node-b"})["jobs"]], [b, a])
        # Search now includes the saved shell command, not just argv[0].
        self.assertEqual([x["id"] for x in self.history.list({"command": "HOST"})["jobs"]], [b, a])
        self.assertEqual([x["id"] for x in self.history.list({"command": "safe"})["jobs"]], [b])
        self.assertEqual(self.history.list({"command": "not-found"})["jobs"], [])
        self.assertEqual(self.history.list({"from_date": "2100-01-01"})["jobs"], [])
        self.assertEqual(self.history.list({"to_date": "2001-01-01"})["jobs"], [])
        self.assertEqual(len(self.history.list({"from_date": "2020-01-01", "to_date": "2100-01-01"})["jobs"]), 2)
        cursor = listing["changes_cursor"]
        self.assertEqual(self.history.changes(cursor)["jobs"], [])
        time.sleep(.002)
        c = self.save(story_id="TEST-209")
        change = self.history.changes(cursor)
        self.assertEqual([j["id"] for j in change["jobs"]], [c])
        self.assertEqual(self.history.changes(change["changes_cursor"])["jobs"], [])
        self.assertFalse(change["has_more"])
        self.assertEqual(self.history.changes(cursor, limit=1)["jobs"][0]["id"], c)

    def test_numbered_pages_filtered_totals_and_backward_compatible_cursor(self):
        ids = []
        for index in range(13):
            ids.append(self.save(story_id="TEST-191", argv=("echo", str(index))))
        pages = [self.history.list({"story_id": "191"}, page=p, limit=5)
                 for p in (1, 2, 3, 4)]
        self.assertEqual([x["page"] for x in pages], [1, 2, 3, 3])
        self.assertEqual([len(x["jobs"]) for x in pages], [5, 5, 3, 3])
        self.assertTrue(all(x["page_count"] == 3 and x["page_size"] == 5 and
                            x["filtered_total"] == 13 and x["totals"]["total"] == 13
                            for x in pages))
        self.assertEqual(set(x["id"] for page in pages[:3] for x in page["jobs"]), set(ids))
        self.assertTrue(all(x["next_page"] is None for x in pages))
        for story in ("191", "00191", "TEST-191", "test-191"):
            self.assertEqual(self.history.list({"story_id": story}, page=1, limit=5)["jobs"][0]["id"],
                             ids[-1])
        empty = self.history.list({"story_id": "999"}, page=50, limit=5)
        self.assertEqual((empty["page"], empty["page_count"], empty["filtered_total"],
                          empty["jobs"]), (1, 1, 0, []))
        self.assertEqual(empty["totals"]["total"], 13)
        cursor = self.history.list({}, limit=5)
        self.assertEqual(cursor["filtered_total"], 13)
        self.assertIsNotNone(cursor["next_page"])
        self.assertEqual(
            self.history.list({}, before=cursor["next_page"], limit=5)["jobs"][0]["id"], ids[7],
        )
        for bad in (0, -1, 100001, 10**100):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.history.list({}, page=bad)
        with self.assertRaises(ValueError):
            self.history.list({}, page=1, before="0:_")

    def test_numeric_story_filter_accepts_multiple_project_prefixes(self):
        first = self.save(story_id="TEST-243")
        second = self.save(story_id="OTHER-243")
        other = self.save(story_id="OTHER-1243")
        results = self.history.list({"story_id": "00243"})
        self.assertEqual({x["id"] for x in results["jobs"]}, {first, second})
        self.assertNotIn(other, {x["id"] for x in results["jobs"]})
        self.assertEqual([x["id"] for x in
                          self.history.list({"story_id": "other-243"})["jobs"]],
                         [second])

    def test_generic_issue_ids_are_stored_and_filterable_as_strings(self):
        issue_ids = ("#123", "12345", "00012", "owner/repo#123",
                     "other:opaque/issues/" + "x" * 60)
        for story in issue_ids:
            job_id = self.save(story_id=story)
            rows = self.history.list({"story_id": story})["jobs"]
            self.assertEqual([row["id"] for row in rows], [job_id])
            self.assertEqual(rows[0]["story_id"], story)
        # The existing short search must match both TEST-243 and native 243.
        lower = self.save(story_id="eng-123")
        self.assertEqual([row["id"] for row in
                          self.history.list({"story_id": "ENG-123"})["jobs"]], [lower])
        # Unicode lookalikes are generic opaque IDs, not ASCII project keys.
        # Python Unicode re.IGNORECASE accepts these as [A-Z]; SQLite's
        # UPPER() handles ASCII only, so preserve exact UTF-8 matching.
        for unicode_id, ascii_id in (("KA-123", "KA-123"),
                                     ("ıA-123", "IA-123")):
            unicode_job = self.save(story_id=unicode_id)
            ascii_job = self.save(story_id=ascii_id)
            self.assertEqual([x["id"] for x in self.history.list(
                {"story_id": unicode_id})["jobs"]], [unicode_job])
            self.assertEqual([x["id"] for x in self.history.list(
                {"story_id": ascii_id})["jobs"]], [ascii_job])
        numeric = self.save(story_id="243")
        prefixed = self.save(story_id="TEST-243")
        matches = self.history.list({"story_id": "243"})["jobs"]
        self.assertEqual({row["id"] for row in matches}, {numeric, prefixed})

    def test_invalid_queries_are_rejected(self):
        for query in (
            {"status": "nonsense"}, {"mode": "pretend"}, {"story_id": "x" * 100},
            {"command": "x" * 65}, {"from_date": "2026-22-54"},
            {"to_date": "bad"}, {"from_date": "2027-01-01", "to_date": "2026-01-01"},
        ):
            with self.assertRaises(ValueError):
                self.history.list(query)
        for before in ("invalid", "1.3:!", "NaN:Aaaaaaaa", "1.0:" + "a" * 129):
            with self.assertRaises(ValueError):
                self.history.list({}, before=before)
        with self.assertRaises(ValueError):
            self.history.list({}, limit=0)
        with self.assertRaises(ValueError):
            self.history.changes("bad")
        with self.assertRaises(ValueError):
            self.history.changes("")
        with self.assertRaises(ValueError):
            self.history.changes("0:a", limit=101)
        self.assertIsNone(_cursor(""))
        self.assertIsNone(_date_epoch("", end=True))

    def test_command_rendering_and_metadata_history_migration(self):
        self.assertEqual(_plain_command(None), None)
        self.assertEqual(_plain_command({}), None)
        self.assertEqual(_plain_command({"argv": []}), None)
        self.assertEqual(_plain_command({"argv": ["echo", 1]}), None)
        self.assertEqual(_plain_command({"argv": ["printf", "a b", "$HOME"]}),
                         "printf 'a b' '$HOME'")
        self.assertEqual(_plain_command({"argv": ["/bin/bash", "-lc", "echo hello"]}),
                         "echo hello")
        id_ = self.save(mode="sync")
        with self.store._connect() as db:
            db.execute("UPDATE jobs SET request_json=NULL WHERE id=?", (id_,))
        detail = self.history.detail(id_)
        self.assertIsNone(detail["request"])
        self.assertIsNone(detail["terminal_command"])
        with self.assertRaises(ValueError):
            self.store.create("alice", request("echo", "ok"), mode="other")
        with self.assertRaises(ValueError):
            JobStore(self.path, retention_seconds=366 * 86400 + 1)

    def test_calendar_exact_twelve_month_retention(self):
        from datetime import datetime, timezone
        old = self.save()
        boundary = self.save()
        beyond = self.save()
        threshold = datetime(2026, 2, 28, 12, tzinfo=timezone.utc).timestamp()
        with self.store._connect() as db:
            for job, ended in (
                (old, threshold - 1), (boundary, threshold),
                (beyond, threshold + 1),
            ):
                db.execute("UPDATE jobs SET ended_at=? WHERE id=?", (ended, job))
        class FixedDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime(2027, 2, 28, 12, tzinfo=timezone.utc)
        with patch("app.jobs.datetime", FixedDateTime):
            months = JobStore(self.path, retention_months=12)
        self.assertIsNone(months.get("alice", old))
        self.assertIsNotNone(months.get("alice", boundary))
        self.assertIsNotNone(months.get("alice", beyond))
        with self.assertRaises(ValueError):
            JobStore(self.path, retention_months=13)

    def test_existing_schema_upgrades_without_erasing_old_audit(self):
        self.path.unlink()
        with sqlite3.connect(self.path) as db:
            db.executescript("""
                CREATE TABLE jobs (
                  id TEXT PRIMARY KEY,actor TEXT NOT NULL,server TEXT NOT NULL,
                  command TEXT NOT NULL,argv_count INTEGER NOT NULL,command_sha256 TEXT NOT NULL,
                  status TEXT NOT NULL,created_at REAL NOT NULL,updated_at REAL NOT NULL,
                  started_at REAL,ended_at REAL,exit_code INTEGER,elapsed_seconds REAL,
                  error TEXT NOT NULL DEFAULT '',output_bytes INTEGER NOT NULL DEFAULT 0,
                  cancel_requested INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE output (job_id TEXT,offset INTEGER,stream TEXT,data BLOB,
                                     PRIMARY KEY(job_id,offset));
                INSERT INTO jobs(id,actor,server,command,argv_count,command_sha256,status,
                  created_at,updated_at,ended_at)
                VALUES('legacy-job-209','alice','demo-node-b','hostname',2,'abc','succeeded',
                  2000000000,2000000000,2000000000);
            """)
        self.path.chmod(0o600)
        restored = JobStore(self.path, retention_seconds=366 * 86400)
        legacy = HistoryStore(restored).detail("legacy-job-209")
        self.assertEqual(legacy["mode"], "async")
        self.assertIsNone(legacy["request"])
        self.assertIsNone(legacy["story_id"])


class SyncAuditTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = JobStore(Path(self.temp.name) / "private" / "jobs.sqlite")
        self.manager = JobManager(FakeExecutor(), self.store)

    async def test_sync_uses_same_durable_output_and_story_id(self):
        job_id, result = await self.manager.execute_sync("alice", request("hostname", "-s"))
        self.assertEqual(result.status, "succeeded")
        detail = HistoryStore(self.store).detail(job_id)
        self.assertEqual(detail["mode"], "sync")
        self.assertEqual(detail["story_id"], "TEST-209")
        self.assertEqual(detail["status"], "succeeded")
        page = HistoryStore(self.store).output(job_id)
        self.assertEqual(page["next_cursor"], len("test ✓\nnote\n".encode()))
        self.assertEqual([x["stream"] for x in page["chunks"]], ["stdout", "stderr"])

    async def test_failed_ssh_spawn_response_is_audited_for_both_modes(self):
        class FailedSpawn(FakeExecutor):
            async def execute(self, actor, job, *, on_output=None, on_admitted=None):
                if on_admitted is not None:
                    on_admitted()
                return SSHResult(job.server, "transport_error", None, "",
                                 "SSH transport could not start", 0.02)

        manager = JobManager(FailedSpawn(), self.store)
        for mode in ("sync", "async"):
            command = request("hostname", "-s")
            if mode == "sync":
                job_id, result = await manager.execute_sync("alice", command)
                self.assertEqual(result.stderr, "SSH transport could not start")
            else:
                submitted = manager.submit("bob", command)
                job_id = submitted["id"]
                await asyncio.gather(*manager._tasks.values())
            record = HistoryStore(self.store).detail(job_id)
            self.assertEqual(record["status"], "transport_error")
            self.assertEqual(record["mode"], mode)
            chunks = HistoryStore(self.store).output(job_id)["chunks"]
            self.assertEqual([item["stream"] for item in chunks], ["stderr"])
            self.assertEqual(base64.b64decode(chunks[0]["data_base64"]),
                             b"SSH transport could not start")

    async def test_callback_output_is_not_duplicated_by_result_fallback(self):
        class PartialStream(FakeExecutor):
            async def execute(self, actor, job, *, on_output=None, on_admitted=None):
                if on_admitted is not None:
                    on_admitted()
                await on_output("stdout", b"already streamed\n")
                return SSHResult(job.server, "command_error", 1,
                                 "already streamed\n", "generated stderr", 0.01)

        manager = JobManager(PartialStream(), self.store)
        job_id, result = await manager.execute_sync("alice", request("false"))
        self.assertEqual(result.status, "command_error")
        chunks = HistoryStore(self.store).output(job_id)["chunks"]
        self.assertEqual([(item["stream"], base64.b64decode(item["data_base64"]))
                          for item in chunks],
                         [("stdout", b"already streamed\n"), ("stderr", b"generated stderr")])

    async def test_execution_exception_is_available_as_safe_stored_error(self):
        class DeniedExecutor(FakeExecutor):
            async def execute(self, actor, job, *, on_output=None, on_admitted=None):
                if on_admitted is not None:
                    on_admitted()
                raise SSHDenied("synthetic secret details must not be returned")

        manager = JobManager(DeniedExecutor(), self.store)
        job_id, result = await manager.execute_sync("alice", request("hostname"))
        self.assertIsNone(result)
        detail = HistoryStore(self.store).detail(job_id)
        self.assertEqual(detail["status"], "failed")
        self.assertEqual(detail["error"], "SSH authorization was rejected")
        self.assertNotIn("synthetic secret details", str(detail))

    async def test_sync_denies_unapproved_principal_without_storing_job(self):
        with self.assertRaises(SSHDenied):
            await self.manager.execute_sync("not-allowed", request("hostname", "-s"))
        self.assertEqual(HistoryStore(self.store).list({})["jobs"], [])


class BrowserTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = JobStore(Path(self.temp.name) / "private" / "jobs.sqlite")
        self.secret = "viewer-password-" + "v" * 48
        self.env = patch.dict(os.environ, {"HISTORY_VIEWER_PASSWORD": self.secret})
        self.origin = patch.object(config, "MCP_ISSUER", "https://lab.example.net")
        self.env.start()
        self.origin.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(self.origin.stop)
        self.app = FastAPI()
        self.app.include_router(create_history_router(
            self.store, approved_hosts=["demo-sandbox", "demo-node-b", "demo-node-a"],
        ))
        self.client_ctx = TestClient(self.app, base_url="https://lab.example.net",
                                     follow_redirects=False)
        self.client = self.client_ctx.__enter__()
        self.addCleanup(lambda: self.client_ctx.__exit__(None, None, None))

    def login(self, password=None):
        page = self.client.get("/console/login")
        self.assertEqual(page.status_code, 200)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        return self.client.post("/console/login", data={
            "csrf": csrf, "password": self.secret if password is None else password
        }, headers={"Origin": config.MCP_ISSUER})

    def test_revocation_without_approval_manager_fails_closed(self):
        # A read-only viewer may be active without host approvals. Its
        # authenticated revoke endpoint must never invent a grant or version.
        self.assertEqual(self.login().status_code, 303)
        response = self.client.post(
            "/console/api/grants/nonexistent/revoke",
            data={"csrf": self.client.cookies[CSRF_COOKIE]},
            headers={"Origin": config.MCP_ISSUER},
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {"error": "Grant unavailable or expired"})

    def save(self, actor="alice", story="TEST-209"):
        job = self.store.create(actor, request("sh", "-c", "echo '<script>alert(1)</script>'",
                                               story_id=story))
        self.store.begin(job)
        self.store.append(job, "stdout", b"<img src=x onerror=alert(1)>\n")
        self.store.finish(job, "succeeded", exit_code=0)
        return job

    def test_auth_redirect_login_cookie_security_and_logout(self):
        self.assertEqual(self.client.get("/console").status_code, 303)
        self.assertEqual(self.client.get("/console/api/jobs").status_code, 401)
        self.assertEqual(self.client.get("/console/api/hosts").status_code, 401)
        self.assertEqual(self.client.get("/console/api/changes?after=0:xx").status_code, 401)
        self.assertEqual(self.client.get("/console/login").headers["Referrer-Policy"],
                         "same-origin")
        signin = self.client.get("/console/login").text
        self.assertIn("<h1>Operator Console</h1>", signin)
        self.assertIn("Console password", signin)
        self.assertNotIn("demo-node-b", signin)
        self.assertEqual(self.client.get("/console/api/jobs/unknown-id").status_code, 401)
        self.assertEqual(self.client.get("/console/api/jobs/unknown-id/output").status_code, 401)
        result = self.login()
        self.assertEqual(result.status_code, 303)
        self.assertIn(SESSION_COOKIE, result.headers["set-cookie"])
        self.assertIn("httponly", result.headers["set-cookie"].lower())
        self.assertIn("secure", result.headers["set-cookie"].lower())
        self.assertIn("samesite=strict", result.headers["set-cookie"].lower())
        page = self.client.get("/console")
        self.assertEqual(page.status_code, 200)
        self.assertIn("SSH-MCP Operator Console", page.text)
        self.assertIn('data-story-id-max-chars="16"', page.text)
        self.assertIn('data-story-id-truncate-from="end"', page.text)
        self.assertNotIn("SSH Command History", page.text)
        self.assertNotIn("brand-separator", page.text)
        self.assertIn('<h1 class="visually-hidden">', page.text)
        self.assertIn("Content-Security-Policy", page.headers)
        self.assertNotIn("unsafe-inline", page.headers["Content-Security-Policy"])
        self.assertIn("no-store", page.headers["Cache-Control"])
        self.assertNotIn('class="readonly"', page.text)
        self.assertIn('<button type="submit" class="logout" aria-label="Sign out"', page.text)
        self.assertIn('<svg class="logout-icon"', page.text)
        self.assertEqual(self.client.get("/console/api/hosts").json()["hosts"],
                         ["demo-node-a", "demo-node-b", "demo-sandbox"])
        self.assertEqual(self.client.get("/console/assets/console.js").status_code, 200)
        self.assertIn("setTimeout(poll", self.client.get("/console/assets/console.js").text)
        self.assertEqual(self.client.get("/console/assets/style.css").status_code, 200)
        self.assertEqual(self.client.get("/history").status_code, 404)
        self.assertEqual(self.client.get("/history/login").status_code, 404)
        self.assertEqual(self.client.get("/history/api/jobs").status_code, 404)
        csrf = self.client.cookies[CSRF_COOKIE]
        failed = self.client.post("/console/logout", data={"csrf": csrf})
        self.assertEqual(failed.status_code, 403)
        done = self.client.post("/console/logout", data={"csrf": csrf},
                                headers={"Origin": config.MCP_ISSUER})
        self.assertEqual(done.status_code, 303)
        self.assertEqual(self.client.get("/console/api/jobs").status_code, 401)

    def test_upgrade_login_retires_legacy_session_before_rollback(self):
        # The old and new application versions use the same retained SQLite DB.
        before_upgrade = ViewerAuth(HistoryStore(self.store), self.secret)
        legacy_token = before_upgrade.login("synthetic-operator", self.secret)
        self.assertIsNotNone(legacy_token)
        self.assertTrue(before_upgrade.valid(legacy_token, touch=False))
        self.client.cookies.set(LEGACY_SESSION_COOKIE, legacy_token,
                                domain="lab.example.net", path="/")
        self.client.cookies.set(LEGACY_CSRF_COOKIE, "synthetic-old-csrf",
                                domain="lab.example.net", path="/")
        self.assertEqual(self.client.get("/console").status_code, 303)

        signed_in = self.login()
        self.assertEqual(signed_in.status_code, 303)
        new_token = self.client.cookies[SESSION_COOKIE]
        self.assertTrue(before_upgrade.valid(new_token, touch=False))
        self.assertFalse(before_upgrade.valid(legacy_token, touch=False))
        for name in (LEGACY_SESSION_COOKIE, LEGACY_CSRF_COOKIE):
            self.assertNotIn(name, self.client.cookies)
            self.assertTrue(any(
                item.startswith(name + "=") and "max-age=0" in item.lower()
                and "secure" in item.lower() and "httponly" in item.lower()
                for item in signed_in.headers.get_list("set-cookie")
            ), name)
        # Simulate a rollback/restart to the old service with the same database
        # and password: the previously authenticated token stays revoked.
        rollback_auth = ViewerAuth(HistoryStore(self.store), self.secret)
        self.assertFalse(rollback_auth.valid(legacy_token, touch=False))
        self.assertTrue(rollback_auth.valid(new_token, touch=False))

    def test_console_logout_revokes_old_and_new_sessions_on_same_database(self):
        self.assertEqual(self.login().status_code, 303)
        new_token = self.client.cookies[SESSION_COOKIE]
        before_upgrade = ViewerAuth(HistoryStore(self.store), self.secret)
        legacy_token = before_upgrade.login("synthetic-operator", self.secret)
        self.assertIsNotNone(legacy_token)
        self.client.cookies.set(LEGACY_SESSION_COOKIE, legacy_token,
                                domain="lab.example.net", path="/")
        self.client.cookies.set(LEGACY_CSRF_COOKIE, "synthetic-old-csrf",
                                domain="lab.example.net", path="/")
        csrf = self.client.cookies[CSRF_COOKIE]

        forbidden = self.client.post("/console/logout", data={"csrf": csrf})
        self.assertEqual(forbidden.status_code, 403)
        self.assertTrue(before_upgrade.valid(new_token, touch=False))
        self.assertTrue(before_upgrade.valid(legacy_token, touch=False))
        signed_out = self.client.post(
            "/console/logout", data={"csrf": csrf},
            headers={"Origin": config.MCP_ISSUER},
        )
        self.assertEqual(signed_out.status_code, 303)
        self.assertNotIn(SESSION_COOKIE, self.client.cookies)
        for name in (LEGACY_SESSION_COOKIE, LEGACY_CSRF_COOKIE):
            self.assertNotIn(name, self.client.cookies)
            self.assertTrue(any(
                item.startswith(name + "=") and "max-age=0" in item.lower()
                for item in signed_out.headers.get_list("set-cookie")
            ), name)
        rollback_auth = ViewerAuth(HistoryStore(self.store), self.secret)
        self.assertFalse(rollback_auth.valid(new_token, touch=False))
        self.assertFalse(rollback_auth.valid(legacy_token, touch=False))
        self.assertEqual(self.client.get("/console/api/jobs").status_code, 401)

    def test_compact_navigation_uses_validated_environment(self):
        self.assertEqual(self.login().status_code, 303)
        for setting, label in (("lab", "LAB"), ("production", "PROD")):
            with self.subTest(setting=setting), patch.object(config, "MCP_ENVIRONMENT", setting):
                page = self.client.get("/console")
                self.assertEqual(page.status_code, 200)
                self.assertIn(f"<title>SSH-MCP · Operator Console · {label}</title>", page.text)
                self.assertIn(f'<span class="brand-sub">{label}</span>', page.text)
                if config.MCP_SERVICE_VERSION:
                    prefix = "" if config.is_commit_version(config.MCP_SERVICE_VERSION) else "v"
                    self.assertIn(
                        f'<span class="brand-version">{prefix}{config.MCP_SERVICE_VERSION}</span>',
                        page.text,
                    )
                else:
                    self.assertNotIn('brand-version', page.text)  # No false local-development version.
                self.assertEqual(page.text.count('class="brand-title"'), 0)
                self.assertEqual(page.text.count('class="visually-hidden"'), 1)
                self.assertIn('<span class="brand-mark">SSH-MCP</span>', page.text)
                self.assertEqual(page.text.count("<h1"), 1)
                self.assertEqual(page.text.count('class="readonly"'), 0)
                self.assertEqual(page.text.count('aria-label="Sign out"'), 1)
                self.assertIn(
                    '<section class="overview"><div class="metrics" '
                    'aria-label="Job totals for selected time range">',
                    page.text,
                )
                self.assertNotIn('class="section-heading"', page.text)
                self.assertNotIn('heading-readonly', page.text)
                self.assertNotIn('Read-only audit view of all SSH command jobs.', page.text)
                self.assertIn('id="filters"', page.text)
                self.assertIn('id="job-rows"', page.text)
                self.assertIn('id="detail"', page.text)

    def test_version_badge_is_small_validated_and_escaped(self):
        self.assertEqual(self.login().status_code, 303)
        with patch.object(config, "MCP_SERVICE_VERSION", "0.1.7"), patch.object(
                config, "MCP_RESOURCE", config.MCP_ISSUER + "/mcp"):
            markup = self.client.get("/console").text
            self.assertIn('<span class="brand-sub">LAB</span>', markup)
            self.assertIn('<span class="brand-version">v0.1.7</span>', markup)
            self.assertLess(markup.index('class="brand-sub"'), markup.index('class="brand-version"'))
            self.assertTrue(config._valid_service_version(config.MCP_SERVICE_VERSION))
        with patch.object(config, "MCP_SERVICE_VERSION", "abc1234"):
            self.assertIn('<span class="brand-version">abc1234</span>', self.client.get("/console").text)
        for bad in ("<script>", "0.1.${BUILD_NUMBER}", "1.2.3<img", "x" * 41):
            with self.subTest(bad=bad), patch.object(config, "MCP_SERVICE_VERSION", bad), patch.object(
                    config, "MCP_RESOURCE", config.MCP_ISSUER + "/mcp"):
                self.assertFalse(config._valid_service_version(config.MCP_SERVICE_VERSION))
        with patch.object(config, "MCP_SERVICE_VERSION", "<img src=x>"):
            self.assertNotIn('<img src=x>', self.client.get("/console").text)
            self.assertIn('v&lt;img src=x&gt;', self.client.get("/console").text)

    def test_dashboard_has_all_five_kpis_and_authenticated_global_summary(self):
        self.assertEqual(self.client.get("/console/api/summary").status_code, 401)
        self.assertEqual(self.login().status_code, 303)
        self.save("alice", "TEST-209")
        self.save("bob", "TEST-208")
        page = self.client.get("/console")
        self.assertEqual(page.status_code, 200)
        for kind in ("total", "running", "succeeded", "failed", "cancelled"):
            self.assertIn('id="metric-' + kind + '"', page.text)
        self.assertIn('id="technical-hash"', page.text)
        self.assertIn('<th>Duration</th>', page.text)
        self.assertLess(page.text.index('class="workspace"'),
                        page.text.index('class="overview"'))
        self.assertLess(page.text.index('class="left-pane"'),
                        page.text.index('class="overview"'))
        self.assertIn('name="time_range"', page.text)
        self.assertIn('<option value="24h" selected>', page.text)
        self.assertNotIn('name="from_date"', page.text)
        self.assertNotIn('name="to_date"', page.text)
        self.assertIn('id="technical-metadata"', page.text)
        expected = {
            "total": 2, "running": 0, "succeeded": 2,
            "failed": 0, "cancelled": 0,
        }
        self.assertEqual(self.client.get("/console/api/summary").json()["totals"], expected)
        filtered = self.client.get("/console/api/jobs?story_id=TEST-999").json()
        self.assertEqual(filtered["jobs"], [])
        self.assertEqual(filtered["totals"], expected)
        self.assertIn('$("metric-" + kind)', self.client.get("/console/assets/console.js").text)
        self.assertIn('metric-card.succeeded', self.client.get("/console/assets/style.css").text)

    def test_time_scoped_kpis_summary_api_ignores_unrelated_filters(self):
        self.assertEqual(self.login().status_code, 303)
        current = self.save("alice", "TEST-191")
        older = self.save("bob", "TEST-232")
        with self.store._connect() as db:
            db.execute("UPDATE jobs SET created_at=? WHERE id=?",
                       (time.time() - 3 * 86400, older))
        recent = self.client.get(
            "/console/api/summary?time_range=24h&status=failed&story_id=TEST-999"
        )
        self.assertEqual(recent.status_code, 200)
        self.assertEqual(recent.json()["totals"]["total"], 1)
        self.assertEqual(recent.json()["totals"]["succeeded"], 1)
        self.assertEqual(self.client.get("/console/api/summary?time_range=1h")
                         .json()["totals"]["total"], 1)
        self.assertEqual(self.client.get("/console/api/summary?time_range=all")
                         .json()["totals"]["total"], 2)
        self.assertEqual(self.client.get("/console/api/summary")
                         .json()["totals"]["total"], 2)
        recent_jobs = self.client.get("/console/api/jobs?time_range=24h&page=1").json()
        self.assertEqual([job["id"] for job in recent_jobs["jobs"]], [current])
        self.assertEqual(recent_jobs["filtered_total"], 1)
        all_jobs = self.client.get("/console/api/jobs?time_range=all&page=1").json()
        self.assertEqual({job["id"] for job in all_jobs["jobs"]}, {current, older})
        self.assertEqual(all_jobs["filtered_total"], 2)
        self.assertEqual(self.client.get(
            "/console/api/jobs?time_range=24h&story_id=TEST-999"
        ).json()["totals"]["total"], 1)
        self.assertEqual(self.client.get(
            "/console/api/jobs?time_range=24h&story_id=TEST-999"
        ).json()["filtered_total"], 0)
        self.assertEqual(self.client.get("/console/api/summary?time_range=bogus")
                         .status_code, 400)
        self.assertEqual(self.client.get("/console/api/jobs?time_range=bogus")
                         .status_code, 400)
        page = self.client.get("/console").text
        self.assertIn('id="metrics-note"', page)
        self.assertIn("Last 24 hours · independent of other filters", page)
        script = self.client.get("/console/assets/console.js").text
        self.assertIn('function updateMetricsNote()', script)
        self.assertIn('"/console/api/summary?time_range=" + escaped(timeRange)', script)
        self.assertIn('if (generation === state.listGeneration)', script)
        self.assertIn('if (timeRangeChanged)', script)

    def test_auto_apply_filters_follow_table_order_and_keep_time_toggle(self):
        self.assertEqual(self.login().status_code, 303)
        page = self.client.get("/console")
        self.assertEqual(page.status_code, 200)
        self.assertIn('id="time-toggle"', page.text)
        self.assertIn('id="privileged-filter"', page.text)
        self.assertIn('aria-label="Show root commands only" aria-pressed="false"', page.text)
        self.assertLess(page.text.index('id="privileged-filter"'),
                        page.text.index('id="command-search"'))
        self.assertIn('for="command-search"', page.text)
        self.assertIn('aria-label="Show relative times"', page.text)
        self.assertIn('aria-pressed="false"', page.text)
        self.assertIn('type="button" aria-label="Show relative times"', page.text)
        filters = page.text.split('<form class="filters" id="filters" role="search">', 1)[1].split("</form>", 1)[0]
        names = re.findall(r'name="([^"]+)"', filters)
        self.assertEqual(names, [
            "time_range", "agent", "story_id", "host",
            "conversation_id", "command", "mode", "status",
        ])
        self.assertNotIn(">Apply</button>", page.text)
        self.assertEqual(page.text.count('<label class="filter-'), 8)
        self.assertIn('maxlength="64"', filters)
        self.assertIn('maxlength="80"', filters)
        columns = re.findall(r'<col class="([^"]+)"', page.text)
        self.assertEqual(columns, ["col-time", "col-agent", "col-story", "col-host", "col-command",
                                   "col-mode", "col-status", "col-duration"])
        self.assertIn('id="command-tooltip"', page.text)
        self.assertIn('role="tooltip" hidden', page.text)
        css = self.client.get("/console/assets/style.css").text
        for item in ("id=\"job-info-panel\" open", 'id="technical-details"',
                     'id="detail-reason-value"', 'id="request-format-toggle"',
                     'id="response-format-toggle"', 'id="request-json"',
                     'id="response-json"'):
            self.assertIn(item, page.text)
        for item in ('id="copy-command"', 'id="copy-output"', 'id="download-output"',
                     'id="copy-job-id"', 'id="detail-sub"', 'id="detail-footer"'):
            self.assertNotIn(item, page.text)
        self.assertIn('["Actor", job.actor]', self.client.get(
            "/console/assets/console.js").text)
        self.assertIn('isFile ? "Operation ID" : "Job ID", job.id',
                      self.client.get("/console/assets/console.js").text)
        self.assertIn("display:flex;justify-content:flex-start;align-items:center;gap:5px", css)
        self.assertIn(".detail-format-toggle{", css)
        self.assertIn("ssh-mcp-console-job-info-open", self.client.get(
            "/console/assets/console.js").text)
        self.assertIn("ssh-mcp-console-technical-open", self.client.get(
            "/console/assets/console.js").text)
        self.assertIn("table-layout:fixed", css)
        self.assertIn("min-width:865px", css)
        self.assertIn(".jobs-table.relative-time .col-time{width:90px}", css)
        self.assertIn("brand-version{font-size:10px", css)
        self.assertIn(".command-cell:focus-visible", css)
        self.assertIn(".command-tooltip[hidden]{display:none}", css)
        script = self.client.get("/console/assets/console.js").text
        self.assertIn('data.conversation_id = String(data.conversation_id || "").trim()', script)
        self.assertIn("appendConversationMeta(meta, job.conversation_id)", script)
        self.assertIn('value.title = id;', script)
        self.assertIn('id.slice(0, 24) + "…"', script)
        self.assertIn('input.value = id;', script)
        self.assertIn("updateConversationClear()", script)
        self.assertIn('.meta-value.meta-conversation', css)
        for expected in (
            'relativeTime: false', 'formatTableTime(job.created_at)',
            'state.relativeTime = !state.relativeTime',
            'button.setAttribute("aria-pressed", String(state.relativeTime))',
            '$("time-toggle").addEventListener("click", toggleTimeFormat)',
            'if (state.relativeTime) refreshRowTimes()',
            '$("filters").addEventListener("input"',
            '$("filters").addEventListener("change"',
            'filterTimer = setTimeout(applyFilters, 250)',
            'generation !== state.listGeneration',
            r'tooltipText.textContent = command.split(/\r?\n/).slice(0, 15)',
            'cell.setAttribute("aria-describedby", "command-tooltip")',
            'td.addEventListener("focus"',
            'td.addEventListener("mouseleave", hideCommandPreview)',
            'window.addEventListener("resize", hideCommandPreview)',
        ):
            self.assertIn(expected, script)
        self.assertNotIn('td.title =', script)
        for suffix in ("s ago", "m ago", "h ago", "d ago"):
            self.assertIn(suffix, script)

    def test_numbered_history_api_and_accessible_viewer_pagination(self):
        self.save("alice", "TEST-191")
        self.save("bob", "TEST-191")
        self.save("alice", "TEST-232")
        self.assertEqual(self.login().status_code, 303)
        first = self.client.get("/console/api/jobs?story_id=191&page=1&limit=1")
        self.assertEqual(first.status_code, 200)
        body = first.json()
        self.assertEqual((body["page"], body["page_count"], body["page_size"],
                          body["filtered_total"]), (1, 2, 1, 2))
        self.assertEqual(body["totals"]["total"], 3)
        second = self.client.get("/console/api/jobs?story_id=TEST-191&page=2&limit=1")
        self.assertNotEqual(body["jobs"][0]["id"], second.json()["jobs"][0]["id"])
        self.assertEqual(second.json()["page"], 2)
        self.assertEqual(self.client.get("/console/api/jobs?story_id=191&page=9&limit=1")
                         .json()["page"], 2)
        for bad in ("0", "-1", "100001", "not-a-page"):
            self.assertEqual(self.client.get("/console/api/jobs?page=" + bad).status_code, 400)
        self.assertEqual(self.client.get("/console/api/jobs?page=1&before=0:_").status_code, 400)
        markup = self.client.get("/console").text
        for item in (
            '<select name="host" aria-label="Filter by registered host">',
            'id="clear-conversation" type="button"',
            'id="clear-command" type="button" aria-label="Clear command filter"',
            'id="history-table"', 'id="pagination"',
            'id="page-summary" aria-live="polite"', 'id="rows-per-page"',
            'id="new-jobs" class="new-jobs" hidden',
        ):
            self.assertIn(item, markup)
        self.assertNotIn('id="load-more"', markup)
        script = self.client.get("/console/assets/console.js").text
        for fragment in (
            'ssh-mcp-console-time-format', 'localStorage.getItem("ssh-mcp-console-time-format")',
            'loadRegisteredHosts()', 'new Option("All hosts", "")',
            'updateCommandClear()', '$("clear-command").addEventListener("click"',
            'data.story_id = story;',
            'jobStory.endsWith("-" + String(Number(f.story_id)))',
            'const next = Math.max(1, Math.min(state.pageCount, target))',
            'new ResizeObserver(onResize).observe(listWrap)',
            '$("rows-per-page").addEventListener("change"',
            'ssh-mcp-console-rows',
            'syncPageSizeControl()',
            'select.options[0].textContent = String(max)',
            'Math.floor((listWrap.clientHeight - header - 1) / row)',
            'pageButton("«", "First page"', 'pageButton("»", "Last page"',
            'params.set("page", String(state.page))',
            'params.set("limit", String(state.pageSize))',
            'generation !== state.listGeneration',
        ):
            self.assertIn(fragment, script)
        css = self.client.get("/console/assets/style.css").text
        self.assertIn('.list-wrap{overflow-y:hidden;overflow-x:auto}', css)
        self.assertIn('--history-row-height:36px', css)
        self.assertIn('.page-footer', css)

    def test_resizable_history_footer_keeps_pager_and_rows_selector_reachable(self):
        self.login()
        markup = self.client.get("/console").text
        css = self.client.get("/console/assets/style.css").text
        self.assertIn('id="pagination" aria-label="History page navigation"', markup)
        self.assertIn('id="rows-per-page"', markup)
        self.assertIn(".left-pane{container-type:inline-size}", css)
        self.assertIn("@container (max-width:610px)", css)
        self.assertIn("grid-template-columns:minmax(0,1fr) auto", css)
        self.assertIn("grid-column:1/-1;grid-row:1;width:100%", css)
        self.assertIn("grid-column:2;grid-row:2;justify-self:end", css)
        self.assertIn(".page-footer #pagination button{flex-shrink:0}", css)
        self.assertIn("max-width:100%;overflow-x:auto", css)
        workflow = (Path(__file__).resolve().parents[2] /
                    ".github/workflows/ci.yml").read_text()
        self.assertIn("Verify history pager at minimum splitter width in headless Chrome",
                      workflow)
        self.assertIn(".venv/bin/python tests/integration/browser_layout_check.py", workflow)

    def test_viewer_sees_all_actors_but_cannot_execute_or_cancel(self):
        a, b = self.save("alice"), self.save("bob", "TEST-208")
        self.login()
        listing = self.client.get("/console/api/jobs")
        self.assertEqual(listing.status_code, 200)
        self.assertEqual({j["actor"] for j in listing.json()["jobs"]}, {"alice", "bob"})
        detail = self.client.get("/console/api/jobs/" + a)
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["job"]["request"]["argv"][-1],
                         "echo '<script>alert(1)</script>'")
        output = self.client.get("/console/api/jobs/" + b + "/output")
        self.assertEqual(base64.b64decode(output.json()["chunks"][0]["data_base64"]),
                         b"<img src=x onerror=alert(1)>\n")
        self.assertNotIn("<script>alert(1)</script>", self.client.get("/console").text)
        self.assertEqual(self.client.post("/console/api/jobs").status_code, 405)
        self.assertEqual(self.client.post(
            "/console/api/jobs/" + b + "/cancel",
            data={"csrf": self.client.cookies[CSRF_COOKIE]},
            headers={"Origin": config.MCP_ISSUER},
        ).status_code, 404)  # No cancellation manager; viewer fails closed.
        self.assertEqual(self.client.get("/console/api/jobs/invalid!!").status_code, 404)
        self.assertEqual(self.client.get("/console/api/jobs/invalid!!/output").status_code, 404)

    def test_filters_changes_and_invalid_queries(self):
        self.login()
        a = self.save("alice", "TEST-209")
        response = self.client.get("/console/api/jobs?story_id=TEST-209&mode=async")
        self.assertEqual([j["id"] for j in response.json()["jobs"]], [a])
        cursor = response.json()["changes_cursor"]
        self.assertEqual(self.client.get("/console/api/changes?after=" + cursor).json()["jobs"], [])
        b = self.save("bob", "TEST-208")
        data = self.client.get("/console/api/changes?after=" + cursor).json()
        self.assertEqual([j["id"] for j in data["jobs"]], [b])
        root = self.store.create("alice", request("id", "-u").model_copy(
            update={"privileged": True},
        ))
        self.store.begin(root)
        self.store.finish(root, "succeeded", exit_code=0, root_started=True)
        privileged = self.client.get("/console/api/jobs?privileged=true")
        self.assertEqual(privileged.status_code, 200)
        self.assertEqual([j["id"] for j in privileged.json()["jobs"]], [root])
        self.assertTrue(privileged.json()["jobs"][0]["privileged"])
        self.assertEqual(self.client.get("/console/api/jobs?story_id=TEST-100").json()["jobs"], [])
        for url in [
            "/console/api/jobs?privileged=1",
            "/console/api/jobs?status=nonsense",
            "/console/api/jobs?limit=999",
            "/console/api/jobs?from_date=bogus",
            "/console/api/jobs?before=broken",
            "/console/api/changes?after=broken",
            "/console/api/jobs/" + b + "/output?cursor=bad",
            "/console/api/jobs/" + b + "/output?max_bytes=999999",
        ]:
            self.assertEqual(self.client.get(url).status_code, 400, url)

    def test_login_csrf_rate_limit_and_recover(self):
        missing = self.client.post("/console/login", data={"password": self.secret},
                                   headers={"Origin": config.MCP_ISSUER})
        self.assertEqual(missing.status_code, 403)
        login = self.client.get("/console/login")
        self.assertEqual(login.status_code, 200)
        csrf = self.client.cookies[CSRF_COOKIE]
        wrong_origin = self.client.post("/console/login",
                         data={"csrf": csrf, "password": self.secret},
                         headers={"Origin": "https://attacker.test"})
        self.assertEqual(wrong_origin.status_code, 403)
        null_origin = self.client.post("/console/login",
                        data={"csrf": csrf, "password": self.secret},
                        headers={"Origin": "null"})
        self.assertEqual(null_origin.status_code, 403)
        bad_form = self.client.post("/console/login", content=b"password=wrong",
                        headers={"Content-Type": "text/plain", "Origin": config.MCP_ISSUER})
        self.assertEqual(bad_form.status_code, 400)
        for _ in range(6):
            response = self.client.post("/console/login",
                       data={"csrf": csrf, "password": "bad"},
                       headers={"Origin": config.MCP_ISSUER})
            self.assertEqual(response.status_code, 401)
        blocked = self.client.post("/console/login",
                  data={"csrf": csrf, "password": self.secret},
                  headers={"Origin": config.MCP_ISSUER})
        self.assertEqual(blocked.status_code, 401)

    def test_session_idle_absolute_expiration_and_revocation(self):
        auth = ViewerAuth(HistoryStore(self.store), self.secret)
        session = auth.login("test", self.secret)
        self.assertTrue(auth.valid(session))
        self.assertFalse(auth.valid("invalid"))
        self.assertFalse(auth.valid(None))
        auth.logout(session)
        self.assertFalse(auth.valid(session))
        session = auth.login("test", self.secret)
        with self.store._connect() as db:
            db.execute("UPDATE history_sessions SET last_seen=? WHERE hash=?",
                       (time.time() - IDLE_SECONDS - 60, auth._digest(session)))
        self.assertFalse(auth.valid(session))
        session = auth.login("test", self.secret)
        with self.store._connect() as db:
            db.execute("UPDATE history_sessions SET created_at=? WHERE hash=?",
                       (time.time() - ABSOLUTE_SECONDS - 60, auth._digest(session)))
        self.assertFalse(auth.valid(session))
        self.assertEqual(len(self.store._connect().execute("SELECT hash FROM history_sessions").fetchall()), 0)

    def test_viewer_session_refresh_and_login_window_pruning(self):
        from app.history import LOGIN_WINDOW
        auth = ViewerAuth(HistoryStore(self.store), self.secret)
        auth.failed["old-client"].append(time.time() - LOGIN_WINDOW - 20)
        self.assertTrue(auth.allowed("old-client"))
        self.assertEqual(len(auth.failed["old-client"]), 0)
        session = auth.login("old-client", self.secret)
        with self.store._connect() as db:
            db.execute("UPDATE history_sessions SET last_seen=? WHERE hash=?",
                       (time.time() - 100, auth._digest(session)))
        self.assertTrue(auth.valid(session))
        with self.store._connect() as db:
            refreshed = db.execute("SELECT last_seen FROM history_sessions WHERE hash=?",
                                   (auth._digest(session),)).fetchone()[0]
        self.assertGreater(refreshed, time.time() - 5)
        auth.logout(None)
        self.assertFalse(auth.valid("x" * 129))

    def test_passive_session_checks_do_not_extend_idle_expiry(self):
        auth = ViewerAuth(HistoryStore(self.store), self.secret)
        session = auth.login("background-viewer", self.secret)
        assert session is not None
        now = time.time()
        last_activity = now - 100
        with self.store._connect() as db:
            db.execute("UPDATE history_sessions SET last_seen=? WHERE hash=?",
                       (last_activity, auth._digest(session)))
        # Repeated authenticated background events near the idle boundary
        # must never refresh the operator's last genuine viewer activity.
        with patch("app.history.time.time", return_value=now + IDLE_SECONDS - 102):
            for _ in range(4):
                self.assertTrue(auth.valid(session, touch=False))
        with self.store._connect() as db:
            actual = db.execute(
                "SELECT last_seen FROM history_sessions WHERE hash=?",
                (auth._digest(session),),
            ).fetchone()[0]
        self.assertEqual(actual, last_activity)
        with patch("app.history.time.time", return_value=now + IDLE_SECONDS - 99):
            self.assertFalse(auth.valid(session, touch=False))
        # Passive check does not delete the session record either; the next
        # active request owns any cleanup and fails closed.
        with self.store._connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM history_sessions").fetchone()[0], 1)
        with patch("app.history.time.time", return_value=now + IDLE_SECONDS - 99):
            self.assertFalse(auth.valid(session))
        with self.store._connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM history_sessions").fetchone()[0], 0)

    def test_authenticated_login_page_and_missing_csrf_recovery(self):
        self.login()
        self.assertEqual(self.client.get("/console/login").status_code, 303)
        self.client.cookies.delete(CSRF_COOKIE)
        response = self.client.get("/console")
        self.assertEqual(response.status_code, 200)
        self.assertIn(CSRF_COOKIE, response.headers["set-cookie"])
        csrf = self.client.cookies[CSRF_COOKIE]
        invalid = self.client.post(
            "/console/logout", content=b"x" * 9000,
            headers={"Origin": config.MCP_ISSUER, "Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(
            self.client.post("/console/logout", data={"csrf": csrf},
                             headers={"Origin": config.MCP_ISSUER}).status_code, 303
        )

    def test_password_rotation_revokes_old_sessions_and_allows_new_login(self):
        self.assertEqual(self.login().status_code, 303)
        old_token = self.client.cookies[SESSION_COOKIE]
        first = ViewerAuth(HistoryStore(self.store), self.secret)
        self.assertTrue(first.valid(old_token))  # unchanged password survives restart
        second_secret = "rotated-viewer-" + "w" * 45
        rotated = ViewerAuth(HistoryStore(self.store), second_secret)
        self.assertFalse(rotated.valid(old_token))
        self.assertFalse(first.valid(old_token))
        self.assertEqual(self.client.get("/console/api/jobs").status_code, 401)
        self.assertIsNone(first.login("operator", self.secret))  # stale server process fails closed
        new_token = rotated.login("operator", second_secret)
        self.assertIsNotNone(new_token)
        self.assertTrue(rotated.valid(new_token))
        restored = ViewerAuth(HistoryStore(self.store), self.secret)
        self.assertFalse(restored.valid(new_token))
        self.assertFalse(restored.valid(old_token))  # rotation back never revives old tokens
        self.assertTrue(restored.valid(restored.login("operator", self.secret)))

    def test_browser_displays_safe_error_without_interpreting_html(self):
        self.login()
        identifier = self.save("alice")
        with self.store._connect() as db:
            db.execute("UPDATE jobs SET error=? WHERE id=?",
                       ("<script>unsafe</script>", identifier))
        detail = self.client.get("/console/api/jobs/" + identifier)
        self.assertEqual(detail.json()["job"]["error"], "<script>unsafe</script>")
        markup = self.client.get("/console").text
        self.assertIn('id="job-error"', markup)
        self.assertNotIn("<script>unsafe</script>", markup)
        client_js = self.client.get("/console/assets/console.js").text
        self.assertIn('error.textContent = job.error || "";', client_js)

    def test_startup_rejects_weak_or_reused_password(self):
        for bad in ("short", config.MCP_LOGIN_KEY):
            if not bad:
                continue
            with patch.dict(os.environ, {"HISTORY_VIEWER_PASSWORD": bad}):
                with self.assertRaises(RuntimeError):
                    create_history_router(self.store)


if __name__ == "__main__":
    unittest.main()


class HistoryCancellationTests(unittest.TestCase):
    """Authenticated browser cancellation is limited to active operator work."""

    def setUp(self):
        from app.batch import BatchManager
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = JobStore(Path(self.temp.name) / "private" / "jobs.sqlite")
        self.actor = config.MCP_OPERATOR_SUBJECT
        self.manager = JobManager(FakeExecutor(), self.store)
        self.batches = BatchManager(self.manager)
        self.password = "synthetic-cancel-viewer-" + "q" * 32
        self.env = patch.dict(os.environ, {"HISTORY_VIEWER_PASSWORD": self.password})
        self.origin = patch.object(config, "MCP_ISSUER", "https://lab.example.net")
        self.env.start()
        self.origin.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(self.origin.stop)
        self.app = FastAPI()
        self.app.include_router(create_history_router(
            self.store, approved_hosts=["demo-node-b"], job_manager=self.manager,
            batch_manager=self.batches,
        ))
        self.client_context = TestClient(
            self.app, base_url="https://lab.example.net", follow_redirects=False,
        )
        self.client = self.client_context.__enter__()
        self.addCleanup(lambda: self.client_context.__exit__(None, None, None))

    def login(self):
        page = self.client.get("/console/login")
        csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        result = self.client.post("/console/login",
            data={"csrf": csrf, "password": self.password},
            headers={"Origin": config.MCP_ISSUER})
        self.assertEqual(result.status_code, 303)

    def job(self, *, actor=None, server="demo-node-b", running=False):
        req = request("sleep", "30", story_id="TEST-269").model_copy(
            update={"server": server},
        )
        identifier = self.store.create(actor or self.actor, req)
        if running:
            self.assertTrue(self.store.begin(identifier))
        return identifier

    def cancel(self, job_id, **kwargs):
        return self.client.post(
            "/console/api/jobs/" + job_id + "/cancel",
            data={"csrf": self.client.cookies.get(CSRF_COOKIE, "")},
            headers={"Origin": config.MCP_ISSUER}, **kwargs,
        )

    def test_history_cancel_requires_login_origin_csrf_and_active_owned_job(self):
        own = self.job()
        stranger = self.job(actor="other-agent")
        unapproved_host = self.job(server="unknown-host")
        self.assertEqual(self.cancel(own).status_code, 401)
        self.login()
        listing = self.client.get("/console/api/jobs").json()["jobs"]
        by_id = {item["id"]: item for item in listing}
        self.assertTrue(by_id[own]["cancel_available"])
        self.assertFalse(by_id[stranger]["cancel_available"])
        self.assertFalse(by_id[unapproved_host]["cancel_available"])
        self.assertEqual(self.client.post(
            "/console/api/jobs/" + own + "/cancel",
            headers={"Origin": config.MCP_ISSUER}, data={"other": "value"},
        ).status_code, 403)
        self.assertEqual(self.client.post(
            "/console/api/jobs/" + own + "/cancel",
            data={"csrf": self.client.cookies[CSRF_COOKIE]},
            headers={"Origin": "https://malicious.example"},
        ).status_code, 403)
        self.assertEqual(self.cancel(stranger).status_code, 404)
        self.assertEqual(self.cancel(unapproved_host).status_code, 404)
        ok = self.cancel(own)
        self.assertEqual(ok.status_code, 200)
        self.assertTrue(ok.json()["cancellation_requested"])
        self.assertEqual(ok.json()["target_type"], "job")
        self.assertEqual(self.store.get(self.actor, own)["status"], "cancelled")
        detail = self.client.get("/console/api/jobs/" + own).json()["job"]
        self.assertFalse(detail["cancel_available"])
        self.assertEqual(detail["cancellation_request"]["requested_via"], "history")
        self.assertEqual(detail["cancellation_request"]["reason"],
                         "Cancelled from History viewer")
        self.assertTrue(detail["cancellation_request"]["requested_at"])
        self.assertEqual(self.cancel(own).status_code, 409)

    def test_changes_eligibility_query_does_not_block_approval_event_loop(self):
        import threading
        import httpx

        self.login()
        active = self.job()
        reached = threading.Event()
        worker_ids = []
        original = HistoryStore.eligible_cancellation_ids

        def delayed_eligibility(history, *args, **kwargs):
            worker_ids.append(threading.get_ident())
            reached.set()
            time.sleep(.45)  # Simulate a slow SQLite read on a busy host.
            return original(history, *args, **kwargs)

        async def exercise():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=self.app),
                base_url="https://lab.example.net",
                cookies=dict(self.client.cookies.items()),
            ) as client:
                event_thread = threading.get_ident()
                with patch.object(HistoryStore, "eligible_cancellation_ids",
                                  delayed_eligibility):
                    request_task = asyncio.create_task(
                        client.get("/console/api/changes?after=0:_"))
                    self.assertTrue(await asyncio.to_thread(reached.wait, 2))
                    # Approval deadlines on the same asyncio event loop must
                    # continue making progress while History polls SQLite.
                    await asyncio.wait_for(asyncio.sleep(.02), timeout=.2)
                    self.assertFalse(request_task.done())
                    response = await request_task
                self.assertEqual(response.status_code, 200)
                jobs = {job["id"]: job for job in response.json()["jobs"]}
                self.assertTrue(jobs[active]["cancel_available"])
                self.assertEqual(len(worker_ids), 1)
                self.assertNotEqual(worker_ids[0], event_thread)

        asyncio.run(exercise())

    def test_agent_reason_is_retained_without_changing_status_label(self):
        job_id = self.job()
        answer = self.manager.cancel(self.actor, job_id,
                                     reason="Agent requested: no longer needed", via="mcp")
        self.assertTrue(answer["cancellation_requested"])
        self.login()
        detail = self.client.get("/console/api/jobs/" + job_id).json()["job"]
        self.assertEqual(detail["status"], "cancelled")
        self.assertEqual(detail["cancellation_request"]["reason"],
                         "Agent requested: no longer needed")
        self.assertEqual(detail["cancellation_request"]["requested_via"], "mcp")
        self.assertEqual(self.cancel(job_id).status_code, 409)

    def test_batch_step_cancel_targets_parent_not_child(self):
        from app.contracts import ExecuteCommandsRequest
        req = ExecuteCommandsRequest.model_validate({
            "server": "demo-node-b", "reason": "Test History whole batch cancellation",
            "commands": [{"argv": ["sleep", "30"]}, {"argv": ["echo", "after"]}],
        })
        batch_id = self.batches.store.create(self.actor, req)
        self.assertTrue(self.batches.store.begin(batch_id))
        child = self.job(running=True)
        self.batches.store.record_step(batch_id, 0, child)
        self.batches.store.admitted_step(batch_id, 0, child)
        class PendingTask:
            def __init__(self):
                self.cancel_count = 0
            def done(self):
                return False
            def cancel(self):
                self.cancel_count += 1
        task = PendingTask()
        self.batches._tasks[batch_id] = task
        self.login()
        self.assertTrue(next(
            item for item in self.client.get("/console/api/jobs").json()["jobs"]
            if item["id"] == child
        )["cancel_available"])
        reply = self.cancel(child)
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(reply.json()["target_type"], "batch")
        self.assertEqual(task.cancel_count, 1)
        with self.store._connect() as db:
            records = db.execute(
                "SELECT target_type,target_id,requested_via FROM cancellation_requests"
            ).fetchall()
        self.assertEqual([tuple(record) for record in records],
                         [("batch", batch_id, "history")])
        detail = self.client.get("/console/api/jobs/" + child).json()["job"]
        self.assertEqual(detail["cancellation_request"]["target_type"], "batch")
        self.assertEqual(detail["cancellation_request"]["requested_via"], "history")
        self.assertFalse(detail["cancel_available"])
        self.assertEqual(detail["batch_step_outcome"]["batch_status"], "running")
        self.assertFalse(next(
            item for item in self.client.get("/console/api/jobs").json()["jobs"]
            if item["id"] == child
        )["cancel_available"])
        self.assertEqual(self.cancel(child).status_code, 409)
        self.assertEqual(task.cancel_count, 1)
        self.assertEqual(self.store.get(self.actor, child)["status"], "running")

    def test_stale_terminal_and_unaudited_running_are_not_cancelled(self):
        succeeded = self.job(running=True)
        self.store.finish(succeeded, "succeeded", exit_code=0)
        running = self.job(running=True)
        self.login()
        self.assertEqual(self.cancel(succeeded).status_code, 409)
        # A running job without an in-process task cannot be confirmed stopped.
        self.assertEqual(self.cancel(running).status_code, 409)
        self.assertIsNone(HistoryStore(self.store).cancellation_request(running))
        self.assertEqual(self.store.get(self.actor, running)["status"], "running")

    def test_browser_control_and_readable_detail_are_compact(self):
        self.login()
        script = self.client.get("/console/assets/console.js").text
        css = self.client.get("/console/assets/style.css").text
        self.assertIn('class="cancel-feedback"', self.client.get("/console").text)
        self.assertIn('"history-cancel"', script)
        self.assertIn("event.stopPropagation()", script)
        self.assertIn('"Cancelling…"', script)
        self.assertIn('requestCancellation(job)', script)
        self.assertIn('Cancellation requested via', script)
        self.assertIn('Operator (History)', script)
        self.assertNotIn('Cancelled · Operator', script)
        self.assertIn('.history-cancel:focus-visible', css)


    def test_running_request_is_not_proof_of_cancelled_outcome(self):
        running = self.job(running=True)
        class PendingTask:
            def __init__(self):
                self.cancel_calls = 0
            def cancel(self):
                self.cancel_calls += 1
        task = PendingTask()
        self.manager._tasks[running] = task
        self.login()
        accepted = self.cancel(running)
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(task.cancel_calls, 1)
        self.assertEqual(self.store.get(self.actor, running)["status"], "running")
        # The cancellation request can arrive too late. Retain the real result.
        self.store.finish(running, "succeeded", exit_code=0)
        detail = self.client.get("/console/api/jobs/" + running).json()["job"]
        self.assertEqual(detail["status"], "succeeded")
        self.assertEqual(detail["cancellation_request"]["requested_via"], "history")
        self.assertFalse(detail["cancel_available"])
        self.assertEqual(self.cancel(running).status_code, 409)

    def test_expired_viewer_session_cannot_cancel_active_job(self):
        waiting = self.job()
        self.login()
        with self.store._connect() as db:
            db.execute(
                "UPDATE history_sessions SET created_at=?",
                (time.time() - ABSOLUTE_SECONDS - 100,),
            )
        self.assertEqual(self.cancel(waiting).status_code, 401)
        self.assertIsNone(HistoryStore(self.store).cancellation_request(waiting))
        self.assertEqual(self.store.get(self.actor, waiting)["status"], "queued")

    def test_agent_batch_reason_visible_on_child_and_not_overwritten(self):
        from app.contracts import ExecuteCommandsRequest
        req = ExecuteCommandsRequest.model_validate({
            "server": "demo-node-b", "reason": "Synthetic agent batch",
            "commands": [{"argv": ["sleep", "30"]}],
        })
        batch_id = self.batches.store.create(self.actor, req)
        self.assertTrue(self.batches.store.begin(batch_id))
        child = self.job(running=True)
        self.batches.store.record_step(batch_id, 0, child)
        self.batches.store.admitted_step(batch_id, 0, child)
        class PendingTask:
            def __init__(self):
                self.cancel_calls = 0
            def done(self):
                return False
            def cancel(self):
                self.cancel_calls += 1
        task = PendingTask()
        self.batches._tasks[batch_id] = task
        answer = self.batches.cancel(
            self.actor, batch_id, reason="Agent requested: stop remaining steps",
            via="mcp",
        )
        self.assertTrue(answer["cancellation_requested"])
        self.assertEqual(task.cancel_calls, 1)
        self.login()
        self.assertEqual(self.cancel(child).status_code, 409)
        detail = self.client.get("/console/api/jobs/" + child).json()["job"]
        self.assertEqual(detail["cancellation_request"]["target_type"], "batch")
        self.assertEqual(detail["cancellation_request"]["requested_via"], "mcp")
        self.assertEqual(detail["cancellation_request"]["reason"],
                         "Agent requested: stop remaining steps")

    def test_history_audit_error_is_sanitized_without_false_acceptance(self):
        waiting = self.job()
        self.login()
        with patch.object(
            self.store, "record_cancellation",
            side_effect=sqlite3.OperationalError("synthetic-secret-path"),
        ):
            failed = self.cancel(waiting)
        self.assertEqual(failed.status_code, 503)
        self.assertNotIn("synthetic-secret-path", failed.text)
        self.assertIsNone(HistoryStore(self.store).cancellation_request(waiting))
        self.assertEqual(self.store.get(self.actor, waiting)["status"], "queued")
