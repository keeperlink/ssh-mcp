"""Verified client attribution stays independent of OAuth authorization."""
from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("MCP_ISSUER", "http://localhost")
os.environ.setdefault("MCP_LOGIN_KEY", "synthetic-test-login-" + "a" * 40)
os.environ.setdefault("MCP_TOKEN_SIGNING_SECRET", "synthetic-test-signing-" + "b" * 40)
os.environ.setdefault("MCP_CIMD_VALIDATE_REMOTE", "false")

from app import config
from app.batch import BatchStore
from app.client_identity import (agent_disambiguator, client_id_context,
                                 parse_labels, labels_from_environment)
from app.contracts import ExecuteCommandRequest, ExecuteCommandsRequest
from app.file_audit import FileAudit
from app.history import HistoryStore, _history_page
from app.jobs import JobStore
from app.oauth import client_audit_actor

A = "https://agent-a.example.org/client.json"
B = "https://agent-b.example.org/client.json"
C = "https://agent-c.example.org/client.json?private=synthetic"
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
        default = patch.object(config, "MCP_CIMD_CLIENT_ID", A)
        labels.start()
        default.start()
        self.addCleanup(labels.stop)
        self.addCleanup(default.stop)

    def command(self, actor=None):
        return self.jobs.create(actor or config.MCP_OPERATOR_SUBJECT,
                                ExecuteCommandRequest(server="demo-node-a", argv=["id"],
                                                      reason="synthetic", story_id="TEST-1"))

    def test_configuration_is_bounded_and_validated(self):
        self.assertEqual(parse_labels(LABELS), LABELS)
        self.assertEqual(labels_from_environment("{}"), {})
        for bad in (
            [], {A: "Unknown"}, {A: "Agent", B: "agent"}, {A: "Agent\n"},
            {A: "x" * 33}, {"http://agent.example.org/client.json": "Agent"},
            {"https://user@agent.example.org/client.json": "Agent"},
            {"https://agent.example.org:bad/client.json": "Agent"},
            {A: 12}, {f"https://agent-{i}.example.org/client.json": str(i) for i in range(33)},
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_labels(bad)
        with self.assertRaises(ValueError):
            labels_from_environment("{")

    def test_unlabelled_verified_client_has_stable_display_only_disambiguator(self):
        expected = hashlib.sha256(C.encode("utf-8")).hexdigest()[:12]
        self.assertEqual(agent_disambiguator(C, LABELS), expected)
        self.assertEqual(agent_disambiguator(C, LABELS), expected)
        self.assertIsNone(agent_disambiguator(A, LABELS))
        self.assertIsNone(agent_disambiguator(None, LABELS))
        self.assertNotEqual(agent_disambiguator(C, LABELS),
                            agent_disambiguator("https://other.example.org/client.json", LABELS))

    def test_legacy_inference_is_conservative_and_filter_uses_resolved_identity(self):
        actor_b = config.MCP_OPERATOR_SUBJECT + "@" + hashlib.sha256(B.encode()).hexdigest()
        legacy_b = self.command(actor_b)
        legacy_ambiguous = self.command()
        mismatch = self.command("someone-else@" + hashlib.sha256(B.encode()).hexdigest())
        token = client_id_context.set(A)
        try:
            new_a = self.command()
        finally:
            client_id_context.reset(token)
        token = client_id_context.set(B)
        try:
            new_b = self.command(actor_b)
        finally:
            client_id_context.reset(token)
        token = client_id_context.set(C)
        try:
            unknown = self.command()
        finally:
            client_id_context.reset(token)
        self.assertEqual({x["id"] for x in self.history.list({"agent": A})["jobs"]}, {new_a})
        self.assertEqual({x["id"] for x in self.history.list({"agent": B})["jobs"]}, {new_b, legacy_b})
        self.assertEqual({x["id"] for x in self.history.list({"agent": "unknown"})["jobs"]},
                         {unknown, legacy_ambiguous, mismatch})
        self.assertEqual(self.history.detail(legacy_b)["client_id"], B)
        self.assertIsNone(self.history.detail(legacy_ambiguous)["client_id"])
        self.assertEqual(self.history.detail(unknown)["client_id"], C.split("?")[0])
        self.assertEqual(self.history.detail(unknown)["agent"], "Unknown")
        self.assertEqual(self.history.list({"actor": actor_b, "agent": A})["filtered_total"], 0)
        with self.assertRaises(ValueError):
            self.history.list({"agent": "unconfigured"})
        with patch.object(config, "MCP_CLIENT_LABELS", {A: "Renamed", B: "Agent B"}):
            self.assertEqual(self.history.detail(new_a)["agent"], "Renamed")
        with self.jobs._connect() as db:
            self.assertIsNone(db.execute("SELECT client_id FROM jobs WHERE id=?", (legacy_b,)).fetchone()[0])
            self.assertEqual(db.execute("SELECT client_id FROM jobs WHERE id=?", (unknown,)).fetchone()[0], C)
        page = _history_page("synthetic")
        self.assertIn('value="' + A + '">Agent A</option>', page)
        self.assertIn('value="unknown">Unknown</option>', page)

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
