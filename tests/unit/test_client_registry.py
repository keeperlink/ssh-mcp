"""Strict operator-pinned client registry contracts, independent of OAuth grants."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from app import config
from app.client_registry import (
    clients_from_environment, labels, offline_client, parse_clients, sources_for,
)
from app.conversation_access import conversation_id_from_request

CHAT = "https://chat.example.org/client.json"
DCR = "dcr_" + "A" * 43
OTHER = "https://other.example.org/client.json"


class ClientRegistryTests(unittest.TestCase):
    def setUp(self):
        self.entry = {
            "identities": [CHAT],
            "conversation_id": {"sources": [
                {"type": "header", "name": "X-Synthetic-Thread"},
                {"type": "metadata", "name": "custom/conversation", "field": "thread_id"},
            ]},
            "offline_redirect_uris": ["https://chat.example.org/callback"],
        }

    def test_exact_identity_lookup_and_no_fallback(self):
        client = parse_clients({"Synthetic": {**self.entry, "identities": [CHAT, DCR]}})
        self.assertEqual(labels(client), {CHAT: "Synthetic", DCR: "Synthetic"})
        self.assertEqual(offline_client(client), (CHAT, ["https://chat.example.org/callback"]))
        self.assertEqual(sources_for(DCR, client), self.entry["conversation_id"]["sources"])
        self.assertEqual(sources_for(CHAT, client), self.entry["conversation_id"]["sources"])
        self.assertEqual(sources_for(OTHER, client), [])
        self.assertEqual(sources_for(None, client), [])
        with patch.object(config, "MCP_CLIENTS", client):
            self.assertEqual(conversation_id_from_request(
                {"x-synthetic-thread": "thread-1"}, {"custom/conversation": {"thread_id": "thread-1"}},
                client_id=DCR), "thread-1")
            self.assertIsNone(conversation_id_from_request(
                {"x-synthetic-thread": "thread-1"}, client_id=OTHER))
            self.assertIsNone(conversation_id_from_request(
                {"x-ssh-mcp-conversation": "thread-1"}, client_id=DCR))
            with self.assertRaisesRegex(ValueError, "Conflicting"):
                conversation_id_from_request(
                    {"x-synthetic-thread": "thread-1"},
                    {"custom/conversation": {"thread_id": "thread-2"}},
                    client_id=DCR)

    def test_scalar_metadata_source_and_no_offline_client(self):
        entry = {"identities": [OTHER], "conversation_id": {
            "sources": [{"type": "metadata", "name": "custom/conversation"}]}}
        clients = clients_from_environment(json.dumps({"Other": entry}))
        self.assertIsNone(offline_client(clients))
        with patch.object(config, "MCP_CLIENTS", clients):
            self.assertEqual(conversation_id_from_request(
                None, {"custom/conversation": "thread-10"}, client_id=OTHER), "thread-10")
            with self.assertRaisesRegex(ValueError, "Invalid conversation"):
                conversation_id_from_request(None, {"custom/conversation": {"bad": True}},
                                             client_id=OTHER)

    def test_repeated_starlette_header_conflict(self):
        from starlette.datastructures import Headers
        clients = parse_clients({"Synthetic": self.entry})
        with patch.object(config, "MCP_CLIENTS", clients):
            headers = Headers(raw=[(b"x-synthetic-thread", b"thread-1"),
                                   (b"x-synthetic-thread", b"thread-2")])
            with self.assertRaisesRegex(ValueError, "Conflicting"):
                conversation_id_from_request(headers, client_id=CHAT)
            headers = Headers(raw=[(b"x-synthetic-thread", b"thread-1"),
                                   (b"x-synthetic-thread", b"")])
            with self.assertRaisesRegex(ValueError, "Invalid conversation"):
                conversation_id_from_request(headers, client_id=CHAT)

    def test_bad_client_definitions_fail_closed(self):
        valid = self.entry
        variants = (
            None, [], 3, {"unknown": valid}, {"Bad\nName": valid},
            {"Long" * 9: valid}, {"X": []}, {"X": {}},
            {"X": {"identities": [CHAT]}},
            {"X": {**valid, "other": True}},
            {"X": {**valid, "identities": [CHAT] * 2}},
            {"X": {**valid, "identities": [CHAT] * 17}},
            {"X": {**valid, "identities": [True]}},
            {"X": {**valid, "identities": ["dcr_A"]}},
            {"X": {**valid, "identities": ["https://user@host.example.org/id.json"]}},
            {"X": valid, "x": {**valid, "identities": [OTHER]}},
            {"X": valid, "Y": {**valid, "identities": [CHAT]}},
            {"X": {**valid, "conversation_id": []}},
            {"X": {**valid, "conversation_id": {"wrong": []}}},
            {"X": {**valid, "conversation_id": {"sources": "not a list"}}},
            {"X": {**valid, "conversation_id": {"sources": [{}]}}},
            {"X": {**valid, "conversation_id": {"sources": [{"type": "header"}]}}},
            {"X": {**valid, "conversation_id": {"sources": [{"type": "header", "name": "X-Forwarded-Proto"}]}}},
            {"X": {**valid, "conversation_id": {"sources": [{"type": "header", "name": "X-Real-IP"}]}}},
            {"X": {**valid, "conversation_id": {"sources": [{"type": "header", "name": "X-Test", "field": "wrong"}]}}},
            {"X": {**valid, "conversation_id": {"sources": [{"type": "metadata", "name": ""}]}}},
            {"X": {**valid, "conversation_id": {"sources": [{"type": "metadata", "name": "meta", "field": None}]}}},
            {"X": {**valid, "conversation_id": {"sources": [{"type": "metadata", "name": "meta", "field": "bad field"}]}}},
            {"X": {**valid, "offline_redirect_uris": "bad"}},
            {"X": {**valid, "offline_redirect_uris": [5]}},
            {"X": {**valid, "offline_redirect_uris": ["https://chat.example.org/#"]}},
            {"X": {**valid, "offline_redirect_uris": ["https://chat.example.org/cb"] * 2}},
            {"X": {**valid, "offline_redirect_uris": ["http://127.0.0.1/cb"]}},
            {"X": valid, "Y": {**valid, "identities": [OTHER]}},
        )
        for item in variants[:-1]:
            with self.subTest(item=repr(item)[:90]), self.assertRaises(ValueError):
                parse_clients(item)
        with self.assertRaises(ValueError):
            clients_from_environment("{")

    def test_missing_nested_metadata_and_consistent_duplicate_header(self):
        entry = {"identities": [CHAT], "conversation_id": {"sources": [
            {"type": "metadata", "name": "nested", "field": "thread"},
            {"type": "header", "name": "X-Thread"},
        ]}}
        clients = parse_clients({"Synthetic": entry})
        from starlette.datastructures import Headers
        with patch.object(config, "MCP_CLIENTS", clients):
            self.assertIsNone(conversation_id_from_request(
                None, {"nested": {"turn": "value"}}, client_id=CHAT))
            self.assertIsNone(conversation_id_from_request(
                None, {}, client_id=CHAT))
            two = Headers(raw=[(b"x-thread", b"same"), (b"X-THREAD", b"same")])
            self.assertEqual(conversation_id_from_request(two, client_id=CHAT), "same")

    def test_offline_identity_cannot_start_with_dcr(self):
        with self.assertRaisesRegex(ValueError, "Invalid offline client"):
            parse_clients({"Synthetic": {
                **self.entry, "identities": [DCR, CHAT],
            }})

    def test_duplicate_offline_fallback_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_clients({"First": self.entry, "Second": {
                **self.entry, "identities": [OTHER]}})
        self.assertEqual(parse_clients({}), {})


if __name__ == "__main__":
    unittest.main()
