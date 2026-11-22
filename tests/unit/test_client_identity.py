"""Verified client attribution stays independent of OAuth authorization."""
from __future__ import annotations

import hashlib
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

os.environ.setdefault("MCP_ISSUER", "http://localhost")
os.environ.setdefault("MCP_LOGIN_KEY", "synthetic-test-login-" + "a" * 40)
os.environ.setdefault("MCP_TOKEN_SIGNING_SECRET", "synthetic-test-signing-" + "b" * 40)
os.environ.setdefault("MCP_CIMD_VALIDATE_REMOTE", "false")

from app import config
from app.approvals import PendingApproval
from app.batch import BatchStore
from app.client_identity import agent_disambiguator, client_id_context
from app.client_registry import parse_clients
from app.contracts import ExecuteCommandRequest, ExecuteCommandsRequest
from app.file_audit import FileAudit
from app.history import HistoryStore, _history_page
from app.jobs import JobStore
from app.oauth import client_audit_actor

A = "https://agent-a.example.org/client.json"
B = "https://agent-b.example.org/client.json"
C = "https://agent-c.example.org/client.json?private=synthetic"
DCR = "dcr_" + "Q" * 43
LABELS = {A: "Agent A", B: "Agent B"}


class ClientIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "private" / "jobs.sqlite"
        self.jobs = JobStore(self.path)
        self.batches = BatchStore(self.jobs)
        self.files = FileAudit(self.jobs)
        self.history = HistoryStore(self.jobs)
        labels = patch.object(config, "MCP_CLIENT_LABELS", LABELS)
        clients = patch.object(config, "MCP_CLIENTS", {
            name: {"identities": [cid], "conversation_id": {"sources": []}}
            for cid, name in LABELS.items()
        })
        labels.start()
        clients.start()
        self.addCleanup(labels.stop)
        self.addCleanup(clients.stop)

    def command(self, actor=None):
        return self.jobs.create(actor or config.MCP_OPERATOR_SUBJECT,
                                ExecuteCommandRequest(server="demo-node-a", argv=["id"],
                                                      reason="synthetic", story_id="TEST-1"))

    def test_client_registry_is_bounded_and_validated(self):
        client = {"identities": [A], "conversation_id": {"sources": []}}
        self.assertEqual(parse_clients({"Agent A": client}), {"Agent A": client})
        self.assertEqual(parse_clients({}), {})
        invalid = (
            [], {"Unknown": client}, {"Agent": client, "agent": client},
            {"Agent": {**client, "identities": [B, B]}},
            {"Agent": {**client, "identities": ["dcr_*"]}},
            {"Agent": {**client, "identities": ["http://evil.example/id.json"]}},
            {"Agent": {**client, "conversation_id": {"sources": [
                {"type": "header", "name": "X-Forwarded-For"}]}}},
            {"Agent": {**client, "conversation_id": {"sources": [
                {"type": "metadata", "name": "x-meta", "field": "bad value"}]}}},
            {"Agent": {**client, "conversation_id": {"sources": [
                {"type": "header", "name": "X-A"}] * 2}}},
            {"Agent": {**client, "conversation_id": {"sources": [
                {"type": "header", "name": "X-A"}] * 9}}},
            {"Agent": {**client, "offline_redirect_uris": ["http://127.0.0.1/x"]}},
            {"Agent": {**client, "offline_redirect_uris": ["https://example.com/a,b"]}},
            {"Agent": client, "Also": {**client, "identities": [A]}},
        )
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(ValueError):
                parse_clients(item)

    def test_unlabelled_verified_client_has_stable_display_only_disambiguator(self):
        expected = hashlib.sha256(C.encode("utf-8")).hexdigest()[:12]
        self.assertEqual(agent_disambiguator(C, LABELS), expected)
        self.assertEqual(agent_disambiguator(C, LABELS), expected)
        self.assertIsNone(agent_disambiguator(A, LABELS))
        self.assertIsNone(agent_disambiguator(None, LABELS))
        self.assertNotEqual(agent_disambiguator(C, LABELS),
                            agent_disambiguator("https://other.example.org/client.json", LABELS))

    def test_legacy_attribution_is_not_inferred_at_runtime(self):
        actor_b = config.MCP_OPERATOR_SUBJECT + "@" + hashlib.sha256(B.encode()).hexdigest()
        legacy_b = self.command(actor_b)
        legacy_bare = self.command()
        token = client_id_context.set(A)
        try:
            job_a = self.command(client_audit_actor(A))
        finally:
            client_id_context.reset(token)
        token = client_id_context.set(B)
        try:
            job_b = self.command(actor_b)
        finally:
            client_id_context.reset(token)
        self.assertEqual({x["id"] for x in self.history.list({"agent": B})["jobs"]}, {job_b})
        self.assertEqual({x["id"] for x in self.history.list({"agent": A})["jobs"]}, {job_a})
        self.assertEqual({x["id"] for x in self.history.list({"agent": "unknown"})["jobs"]},
                         {legacy_b, legacy_bare})
        self.assertIsNone(self.history.detail(legacy_b)["client_id"])
        self.assertIsNone(self.history.detail(legacy_bare)["client_id"])
        self.assertEqual(client_audit_actor(A),
                         config.MCP_OPERATOR_SUBJECT + "@" + hashlib.sha256(A.encode()).hexdigest())
        with self.assertRaises(ValueError):
            self.history.list({"agent": "unconfigured"})
        page = _history_page("synthetic")
        self.assertIn('value="Agent A">Agent A</option>', page)

    def test_multi_identity_agent_filter_groups_display_only(self):
        extra_id = "https://agent-a2.example.org/client.json"
        from app.client_registry import labels
        clients = {
            "Agent A": {"identities": [A, extra_id],
                        "conversation_id": {"sources": []}},
            "Agent B": {"identities": [B], "conversation_id": {"sources": []}},
        }
        with patch.object(config, "MCP_CLIENTS", clients), patch.object(
                config, "MCP_CLIENT_LABELS", labels(clients)):
            created = {}
            for name, cid in (("first", A), ("second", extra_id), ("third", B)):
                token = client_id_context.set(cid)
                try:
                    created[name] = self.command(client_audit_actor(cid))
                finally:
                    client_id_context.reset(token)
            ids = {x["id"] for x in self.history.list({"agent": "Agent A"})["jobs"]}
            self.assertEqual(ids, {created["first"], created["second"]})
            self.assertEqual({x["id"] for x in self.history.list({"agent": A})["jobs"]},
                             {created["first"]})
            self.assertEqual({x["id"] for x in self.history.list({"agent": "Agent B"})["jobs"]},
                             {created["third"]})
            page = _history_page("synthetic")
            self.assertEqual(page.count('value="Agent A">Agent A</option>'), 1)
            self.assertNotIn('value="' + extra_id + '">Agent A</option>', page)
            self.assertNotEqual(client_audit_actor(A), client_audit_actor(extra_id))

    def test_dcr_signed_label_is_not_trusted_without_operator_approval(self):
        with patch.object(config, "MCP_CLIENT_LABELS", {**LABELS, DCR: "Grok"}):
            actor = client_audit_actor(DCR)
            context = client_id_context.set(DCR)
            try:
                job = self.command(actor)
            finally:
                client_id_context.reset(context)
            self.assertEqual(self.history.detail(job)["agent"], "Unknown")
            self.assertEqual(self.history.list({"agent": "unknown"})["jobs"][0]["id"], job)
            with patch("app.client_identity.approved_dcr_names", return_value={DCR: "Grok"}), (
                    patch("app.history.approved_dcr_names", return_value={DCR: "Grok"})), (
                    patch("app.history.agent_names_snapshot", return_value=("v-identity", {DCR: "Grok"}))):
                items = self.history.list({"agent": "Grok"})["jobs"]
                self.assertEqual({item["id"] for item in items}, {job})
                self.assertEqual(items[0]["agent"], "Grok")
                self.assertEqual(self.history.detail(job)["agent"], "Grok")
                self.assertIsNone(agent_disambiguator(DCR, config.MCP_CLIENT_LABELS))
                self.assertEqual(self.history.list({"agent": A})["filtered_total"], 0)
                page = _history_page("synthetic")
                self.assertIn('value="Grok">Grok</option>', page)
        self.assertEqual(self.history.detail(job)["agent"], "Unknown")

    def test_approved_dcr_name_is_display_only_in_pending_approvals(self):
        with patch.object(config, "MCP_CLIENT_LABELS", {**LABELS, DCR: "Untrusted"}):
            pending = PendingApproval(
                id="synthetic-approval", key=("agent:operator", DCR, "demo-node-a"),
                tool="execute_command", reason="synthetic", summary="hostname",
                expires_at=time.time() + 40, deadline=time.monotonic() + 40,
                future=MagicMock(), waiter=None, client_id=DCR,
            )
            self.assertEqual(pending.public()["agent"], "Unknown")
            with patch("app.client_identity.approved_dcr_names", return_value={DCR: "Grok"}):
                display = pending.public()
                self.assertEqual(display["agent"], "Grok")
                self.assertEqual(display["client_id"], DCR)
                self.assertEqual(display["grant_scope"], "agent")
                self.assertIsNone(display["conversation_id"])
                self.assertIsNone(display["client_disambiguator"])
            self.assertEqual(pending.public()["agent"], "Unknown")

    def test_all_durable_kinds_retain_identity_at_admission_and_after_reopen(self):
        actor = client_audit_actor(B)
        token = client_id_context.set(B)
        try:
            command = self.command(actor)
            reserved_file = self.files.reserve(actor, "demo-node-a", "read", "/tmp/test", "TEST-1")
            started_file = self.files.start(actor, "demo-node-a", "read", "/tmp/test", "TEST-1")
            batch = self.batches.create(actor, ExecuteCommandsRequest.model_validate({
                "server": "demo-node-a", "reason": "synthetic",
                "commands": [{"argv": ["id"]}],
            }), pending_approval=True)
        finally:
            client_id_context.reset(token)
        self.files.settle_approval(reserved_file, 5, denied=True)
        self.files.finish(started_file, "succeeded", byte_count=1)
        self.batches.settle_approval(batch, 5, denied=True)
        reopened = JobStore(self.path)
        BatchStore(reopened)
        history = HistoryStore(reopened)
        ids = {command, "file_" + reserved_file, "file_" + started_file, "batch_" + batch}
        self.assertEqual({x["id"] for x in history.list({"agent": B})["jobs"]}, ids)
        for identifier in ids:
            item = history.detail(identifier)
            self.assertEqual(item["client_id"], B)
            self.assertEqual(item["agent"], "Agent B")
        self.assertIsNone(client_id_context.get())
