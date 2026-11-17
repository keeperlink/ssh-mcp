"""TEST-263 PR1: request identity and signed-host access never imply approval."""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app import config

from app.batch import BatchStore
from app.contracts import ExecuteCommandRequest, ExecuteCommandsRequest
from app.conversation_access import (
    conversation_id_context, conversation_id_from_headers, conversation_id_from_request, require_host_access,
)
from app.file_audit import FileAudit
from app.history import HistoryStore
from app.jobs import JobStore
from app.ssh_executor import SSHDenied


class ConversationAccessTests(unittest.TestCase):
    def test_http_header_is_correlation_not_authorization(self):
        self.assertIsNone(conversation_id_from_headers(None))
        self.assertIsNone(conversation_id_from_headers({}))
        self.assertEqual(
            conversation_id_from_headers({"x-openai-session": "v1/dialog-123_AB"}),
            "v1/dialog-123_AB",
        )
        for invalid in ("", " spaces ", "v1/\nentry", "x" * 257, "é", "../?"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                conversation_id_from_headers({"x-openai-session": invalid})

    def test_configured_conversation_header_is_used_without_fallback(self):
        with patch.object(config, "MCP_CONVERSATION_HEADER_NAME", "X-SSH-MCP-Conversation"):
            self.assertEqual(
                conversation_id_from_headers({"x-ssh-mcp-conversation": "agent/workflow-7"}),
                "agent/workflow-7",
            )
            # Do not accept a different provider header as a fallback.
            self.assertIsNone(
                conversation_id_from_headers({"x-openai-session": "v1/old"})
            )
            with self.assertRaises(ValueError):
                conversation_id_from_headers({"x-ssh-mcp-conversation": "bad value"})

    def test_neutral_and_codex_sources_are_validated_and_conflicts_rejected(self):
        codex = {"x-codex-turn-metadata": {"thread_id": "thread-123", "turn_id": "turn-1"}}
        self.assertEqual(conversation_id_from_request(None, codex), "thread-123")
        self.assertEqual(conversation_id_from_request({"x-ssh-mcp-conversation": "thread-123"}), "thread-123")
        self.assertEqual(conversation_id_from_request(
            {"x-openai-session": "thread-123", "x-ssh-mcp-conversation": "thread-123"}, codex),
            "thread-123")
        self.assertIsNone(conversation_id_from_request(None, {"x-codex-turn-metadata": {"turn_id": "turn-only"}}))
        self.assertIsNone(conversation_id_from_request({"mcp-session-id": "transport-only"}, {}))
        for headers, metadata in (
            ({"x-openai-session": "different"}, codex),
            ({"x-openai-session": "thread-1", "x-ssh-mcp-conversation": "thread-2"}, None),
            ({"x-openai-session": "thread-123", "x-ssh-mcp-conversation": ""}, codex),
            (None, {"x-codex-turn-metadata": "not-an-object"}),
            (None, {"x-codex-turn-metadata": {"thread_id": None}}),
            (None, {"x-codex-turn-metadata": {"thread_id": "bad id"}}),
        ):
            with self.subTest(headers=headers, metadata=metadata), self.assertRaises(ValueError):
                conversation_id_from_request(headers, metadata)

    def test_restricted_host_fails_closed_for_every_auth_identity(self):
        class FakeSSH:
            def __init__(self, access: str):
                self.host = SimpleNamespace(access=access)
                self.calls = 0

            def authorized_host(self, actor: str, server: str):
                self.calls += 1
                if actor != "ssh-mcp-operator" or server != "demo-node2":
                    raise SSHDenied("unknown signed host")
                return self.host

        async def verify() -> None:
            restricted = FakeSSH("restricted")
            for sid, conversation in (
                (None, None), ("verified-sid", None), (None, "v1/dialog"),
                ("verified-sid", "v1/dialog"),
            ):
                with self.assertRaises(SSHDenied):
                    await require_host_access(
                        restricted, "ssh-mcp-operator", "demo-node2",
                        session_id=sid, conversation_id=conversation,
                    )
            allowed = FakeSSH("always-granted")
            await require_host_access(
                allowed, "ssh-mcp-operator", "demo-node2",
                session_id=None, conversation_id=None,
            )
            with self.assertRaises(SSHDenied):
                await require_host_access(
                    allowed, "ssh-mcp-operator", "demo-node3",
                    session_id="verified", conversation_id="v1/dialog",
                )
        asyncio.run(verify())

    def test_command_file_and_batch_audit_share_one_request_scoped_conversation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = JobStore(Path(directory) / "private" / "jobs.sqlite")
            batches = BatchStore(store)
            audit = FileAudit(store)
            command = ExecuteCommandRequest(
                server="demo-node-b", argv=["hostname"], reason="fixture",
            )
            batch = ExecuteCommandsRequest(
                server="demo-node-b", commands=[{"argv": ["hostname"]}],
                reason="fixture",
            )
            active = conversation_id_context.set("v1/conversation-A")
            try:
                command_id = store.create("ssh-mcp-operator", command)
                file_id = audit.start(
                    "ssh-mcp-operator", "demo-node-b", "read", "/tmp/test.txt", None,
                )
                batch_id = batches.create("ssh-mcp-operator", batch)
            finally:
                conversation_id_context.reset(active)

            store.finish(command_id, "succeeded")
            audit.finish(file_id, "succeeded")
            history = HistoryStore(store)
            filtered = history.list({"conversation_id": "v1/conversation-A", "record_kind": "all"})
            self.assertEqual(filtered["filtered_total"], 2)
            self.assertEqual(
                {row["conversation_id"] for row in filtered["jobs"]},
                {"v1/conversation-A"},
            )
            self.assertEqual(history.list({"conversation_id": "v1/other"})["filtered_total"], 0)
            self.assertEqual(history.detail(command_id)["conversation_id"], "v1/conversation-A")
            self.assertEqual(history.detail("file_" + file_id)["conversation_id"], "v1/conversation-A")
            with store._connect() as db:
                saved = db.execute(
                    "SELECT conversation_id FROM command_batches WHERE id=?", (batch_id,)
                ).fetchone()
                self.assertEqual(saved["conversation_id"], "v1/conversation-A")
            self.assertEqual(
                batches.get("ssh-mcp-operator", batch_id)["conversation_id"],
                "v1/conversation-A",
            )
            self.assertEqual(
                batches.list("ssh-mcp-operator")["batches"][0]["conversation_id"],
                "v1/conversation-A",
            )
            with store._connect() as db:
                db.execute(
                    "UPDATE command_batches SET conversation_id=NULL WHERE id=?", (batch_id,)
                )
            # Historical batches predating conversation correlation remain readable.
            self.assertIsNone(
                batches.get("ssh-mcp-operator", batch_id)["conversation_id"]
            )
            self.assertIsNone(
                batches.list("ssh-mcp-operator")["batches"][0]["conversation_id"]
            )
            self.assertIsNone(conversation_id_context.get())
