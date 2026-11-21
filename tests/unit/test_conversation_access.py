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


CHAT = "https://chat.example.org/client.json"
ANTI = "https://anti.example.org/client.json"
CUSTOM = "https://custom.example.org/client.json"


class ConversationAccessTests(unittest.TestCase):
    def setUp(self):
        clients = {
            "ChatGPT": {"identities": [CHAT], "conversation_id": {
                "sources": [{"type": "header", "name": "X-OpenAI-Session"},
                            {"type": "metadata", "name": "x-codex-turn-metadata",
                             "field": "thread_id"}]}},
            "Antigravity": {"identities": [ANTI], "conversation_id": {
                "sources": [{"type": "metadata", "name": "antigravity.google/conversation_id"}]}},
            "Custom": {"identities": [CUSTOM], "conversation_id": {
                "sources": [{"type": "header", "name": "X-SSH-MCP-Conversation"}]}},
        }
        patcher = patch.object(config, "MCP_CLIENTS", clients)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_only_configured_client_header_is_used(self):
        self.assertIsNone(conversation_id_from_headers(None, client_id=CHAT))
        self.assertIsNone(conversation_id_from_headers({}, client_id=CHAT))
        self.assertEqual(conversation_id_from_headers(
            {"x-openai-session": "v1/dialog-123_AB"}, client_id=CHAT), "v1/dialog-123_AB")
        self.assertIsNone(conversation_id_from_headers(
            {"x-openai-session": "v1/dialog-123_AB"}, client_id=None))
        self.assertIsNone(conversation_id_from_headers(
            {"x-ssh-mcp-conversation": "v1/dialog-123_AB"}, client_id=CHAT))
        self.assertEqual(conversation_id_from_headers(
            {"x-ssh-mcp-conversation": "custom-5"}, client_id=CUSTOM), "custom-5")
        for invalid in ("", " spaces ", "v1/\\nentry", "x" * 257, "é", "../?"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                conversation_id_from_headers({"x-openai-session": invalid}, client_id=CHAT)
        self.assertIsNone(conversation_id_from_headers(
            {"x-openai-session": "valid"}, client_id="https://unknown.example/client.json"))

    def test_codex_metadata_and_header_agreement(self):
        codex = {"x-codex-turn-metadata": {"thread_id": "thread-123", "turn_id": "turn-1"}}
        self.assertEqual(conversation_id_from_request(None, codex, client_id=CHAT), "thread-123")
        self.assertEqual(conversation_id_from_request(
            {"x-openai-session": "thread-123"}, codex, client_id=CHAT), "thread-123")
        self.assertIsNone(conversation_id_from_request(None, codex, client_id=ANTI))
        self.assertIsNone(conversation_id_from_request(None, {"x-codex-turn-metadata": {
            "turn_id": "turn-only"}}, client_id=CHAT))
        for headers, meta in (
            ({"x-openai-session": "different"}, codex),
            (None, {"x-codex-turn-metadata": "not-an-object"}),
            (None, {"x-codex-turn-metadata": {"thread_id": None}}),
            (None, {"x-codex-turn-metadata": {"thread_id": "bad id"}}),
        ):
            with self.subTest(headers=headers, meta=meta), self.assertRaises(ValueError):
                conversation_id_from_request(headers, meta, client_id=CHAT)

    def test_antigravity_exact_conversation_only(self):
        cid = "12345678-1234-4234-8234-123456789abc"
        metadata = {
            "antigravity.google/conversation_id": cid,
            "antigravity.google/root_conversation_id": "different-root",
        }
        self.assertEqual(conversation_id_from_request(
            None, metadata, client_id=ANTI), cid)
        self.assertIsNone(conversation_id_from_request(None, {
            "antigravity.google/root_conversation_id": cid}, client_id=ANTI))
        self.assertEqual(conversation_id_from_request(
            {"x-openai-session": "different"}, metadata, client_id=ANTI), cid)
        for invalid in ("", None, 42, {}, "bad id", "x" * 257):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                conversation_id_from_request(None, {
                    **metadata, "antigravity.google/conversation_id": invalid}, client_id=ANTI)

    def test_restricted_host_fails_closed_for_every_auth_identity(self):
        class FakeSSH:
            def __init__(self, access: str):
                self.host = SimpleNamespace(access=access)
                self.calls = 0

            def require_ready(self, server, *, privileged=False):
                pass

            async def check_readiness_live(self, server, *, privileged=False):
                pass

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
