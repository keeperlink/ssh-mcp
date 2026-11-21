"""PR2 live-like HTTP MCP approval flow; no real SSH or network is used."""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ.setdefault("MCP_ISSUER", "http://localhost")
os.environ.setdefault("MCP_LOGIN_KEY", "synthetic-test-login-" + "a" * 40)
os.environ.setdefault("MCP_TOKEN_SIGNING_SECRET", "synthetic-test-signing-" + "b" * 40)
os.environ.setdefault("MCP_CIMD_VALIDATE_REMOTE", "false")

from app import config, mcp_gateway, oauth
from app.approvals import ApprovalManager
from app.history import create_history_router
from app.ssh_executor import SSHDenied, SSHResult

CLIENT = "https://chatgpt.com/oauth/client.json"
CONVERSATION = "v1/pr2-synthetic-A"


class FakeRestrictedSSH:
    access = "restricted"
    privileged_access = "restricted"
    username = "mcp-agent"

    def __init__(self):
        self.calls = 0
        self.root_calls = 0
        self.after_root_step = None
        self._sudo_passwords = {"demo-node2": "synthetic-not-real-sudo"}

    def require_ready(self, server, *, privileged=False):
        pass

    async def check_readiness_live(self, server, *, privileged=False):
        pass

    def authorized_host(self, actor, server):
        if actor != oauth.client_audit_actor(CLIENT) or server != "demo-node2":
            raise SSHDenied("Not an approved signed host")
        return self

    def discover_hosts(self, actor, history_hosts):
        result = {alias: {'status': 'active', 'sudo_ready': False}
                  for alias in self.list_servers(actor)}
        result.update({alias: {'status': 'retired', 'sudo_ready': False}
                       for alias in history_hosts if alias not in result})
        return result

    def list_servers(self, actor):
        return ["demo-node2"] if actor == oauth.client_audit_actor(CLIENT) else []

    async def execute(self, actor, request, *, on_output=None, on_admitted=None):
        if on_admitted is not None:
            on_admitted()
        self.authorized_host(actor, request.server)
        self.calls += 1
        if on_output is not None:
            await on_output("stdout", b"synthetic-approved\n")
        return SSHResult(request.server, "succeeded", 0, "synthetic-approved\n", "", .01)

    async def _execute_approved_privileged(self, actor, request, *, on_output=None, on_admitted=None):
        if on_admitted is not None:
            on_admitted()
        self.authorized_host(actor, request.server)
        if not request.privileged:
            raise AssertionError("Never dispatch ordinary commands through sudo")
        self.root_calls += 1
        if self.after_root_step is not None:
            self.after_root_step(self.root_calls)
        if on_output is not None:
            await on_output("stdout", b"synthetic-root\n")
        return SSHResult(
            request.server, "succeeded", 0, "synthetic-root\n", "", .01,
            root_started=True,
        )


class MCPApprovalHTTPTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.env = patch.dict(os.environ, {
            "SSH_JOBS_ENABLED": "true",
            "SSH_JOBS_DB": str(Path(tmp.name) / "private" / "jobs.sqlite"),
            "HISTORY_VIEWER_PASSWORD": "synthetic-viewer-" + "x" * 48,
        })
        self.client_settings = patch.object(config, "MCP_CLIENTS", {
            "Synthetic": {
                "identities": [CLIENT],
                "conversation_id": {"sources": [
                    {"type": "header", "name": "X-OpenAI-Session"},
                    {"type": "header", "name": "X-SSH-MCP-Conversation"},
                    {"type": "metadata", "name": "x-codex-turn-metadata",
                     "field": "thread_id"},
                    {"type": "metadata", "name": "antigravity.google/conversation_id"},
                ]},
            },
        })
        self.client_settings.start()
        self.addCleanup(self.client_settings.stop)
        self.scope = patch.object(config, "MCP_SSH_TOOLS_ENABLED", True)
        self.origin = patch.object(config, "MCP_ISSUER", "https://localhost")
        self.env.start()
        self.scope.start()
        self.origin.start()
        for setting in (self.origin, self.scope, self.env):
            self.addCleanup(setting.stop)
        self.manager = ApprovalManager()
        self.executor = FakeRestrictedSSH()
        registry = {}
        with patch.object(
            mcp_gateway.SSHExecutor, "from_environment", return_value=self.executor
        ):
            server, sub_app = mcp_gateway.create_mcp_server(
                job_registry=registry, approvals=self.manager,
            )

        @asynccontextmanager
        async def lifespan(_app):
            async with server.session_manager.run():
                yield

        app = FastAPI(lifespan=lifespan)
        app.include_router(create_history_router(
            registry["jobs"].store, approved_hosts=["demo-node2"],
            approvals=self.manager,
        ))
        app.mount("/", sub_app)
        self.context = TestClient(app, base_url="https://localhost", follow_redirects=False)
        self.client = self.context.__enter__()
        self.addCleanup(lambda: self.context.__exit__(None, None, None))
        self.token, _ = oauth.issue_access_token(
            CLIENT, oauth._supported_scopes(), session_id="synthetic-oauth-sid-1234567890",
        )
        self.csrf = self._login()

    def _login(self):
        page = self.client.get("/console/login")
        self.assertEqual(page.status_code, 200)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        signed_in = self.client.post("/console/login", data={
            "csrf": csrf, "password": os.environ["HISTORY_VIEWER_PASSWORD"],
        }, headers={"Origin": "https://localhost"})
        self.assertEqual(signed_in.status_code, 303)
        return csrf

    def _rpc(self, *, conversation=CONVERSATION, tool="execute_command",
             arguments=None, header="X-OpenAI-Session", metadata=None, extra_headers=()):
        headers = [
            ("Authorization", f"Bearer {self.token}"),
            ("Accept", "application/json, text/event-stream"),
            ("Host", "localhost"),
        ]
        if conversation is not None and header is not None:
            headers.append((header, conversation))
        headers.extend(extra_headers)
        params = {"name": tool, "arguments": arguments or {
            "server": "demo-node2", "argv": ["hostname"],
            "reason": "TEST-263 offline MCP operator approval test",
        }}
        if metadata is not None:
            params["_meta"] = metadata
        response = self.client.post("/mcp", headers=headers, json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params,
        })
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn("error", response.json())
        return response.json()["result"]

    def _start_call(self, *, conversation=CONVERSATION, tool="execute_command",
                    arguments=None, header="X-OpenAI-Session", metadata=None):
        box = {}

        def execute():
            try:
                box["result"] = self._rpc(conversation=conversation, tool=tool,
                                          arguments=arguments, header=header, metadata=metadata)
            except BaseException as exc:
                box["exception"] = exc

        thread = threading.Thread(target=execute)
        thread.start()
        for _ in range(100):
            data = self.client.get("/console/api/changes?after=0:_").json()
            pending = [entry for entry in data["pending_approvals"]
                       if entry["conversation_id"] == conversation]
            if pending:
                return thread, box, pending[-1]["id"]
            time.sleep(0.02)
        thread.join(1)
        self.fail("Restricted MCP call did not enter approval queue")

    def _decision(self, request_id, decision, duration="once"):
        url = f"/console/api/approvals/{request_id}/{decision}"
        return self.client.post(url, data={
            "csrf": self.csrf, "duration": duration,
        }, headers={"Origin": "https://localhost"})

    def _result(self, thread, box):
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertNotIn("exception", box)
        return box["result"]

    @staticmethod
    def _root_arguments(*, argv=None):
        return {
            "server": "demo-node2", "argv": argv or ["bash", "-lc", "id -u\nwhoami"],
            "reason": "TEST-267 synthetic operator root approval", "privileged": True,
            "cwd": "/root/synthetic", "timeout_seconds": 30,
        }

    def test_repeated_workflow_headers_validate_all_wire_values(self):
        # A duplicate field must not hide a conflicting or malformed value.
        for header in ("X-OpenAI-Session", "X-SSH-MCP-Conversation"):
            for second in ("different", "bad value", ""):
                with self.subTest(header=header, second=second):
                    result = self._rpc(conversation="workflow-1", header=header,
                                       extra_headers=[(header, second)])
                    self.assertTrue(result.get("isError"), result)
                    self.assertEqual(self.manager.snapshot()["pending_approvals"], [])
        self.assertEqual(self.executor.calls, 0)
        thread, box, approval_id = self._start_call(conversation="workflow-1")
        self.assertEqual(self._decision(approval_id, "grant", "5m").status_code, 200)
        self.assertFalse(self._result(thread, box).get("isError"))
        for header in ("X-OpenAI-Session", "X-SSH-MCP-Conversation"):
            self.assertFalse(self._rpc(conversation="workflow-1", header=header,
                                       extra_headers=[(header, "workflow-1")]).get("isError"))
            # Even an existing timed grant cannot bypass validation.
            self.assertTrue(self._rpc(conversation="workflow-1", header=header,
                                      extra_headers=[(header, "other")]).get("isError"))
        self.assertEqual(self.executor.calls, 3)

    def test_headerless_client_gets_agent_scoped_timed_host_and_root_grants(self):
        for privileged in (False, True):
            with self.subTest(privileged=privileged):
                thread, box, request_id = self._start_call(
                    conversation=None, arguments=self._root_arguments() if privileged else None,
                )
                pending = self.manager.pending[request_id].public()
                self.assertIsNone(pending["conversation_id"])
                self.assertIsNotNone(pending["scope_id"])
                self.assertEqual(pending["grant_scope"], "agent")
                self.assertIsNone(pending["conversation_scope_id"])
                self.assertEqual(pending["client_id"], CLIENT)
                self.assertTrue(pending["timed_grants_allowed"])
                self.assertEqual(self._decision(request_id, "grant", "5m").status_code, 200)
                response = self._result(thread, box)
                self.assertFalse(response.get("isError"), response)
                data = json.loads(response["content"][0]["text"])
                details = self.client.get(f"/console/api/jobs/{data['job_id']}").json()["job"]
                self.assertIsNone(details["conversation_id"])
                self.assertEqual(details["approval_status"], "approved_timed")
                self.assertFalse(self._rpc(conversation=None,
                    arguments=self._root_arguments() if privileged else None).get("isError"))
        self.assertEqual(self.executor.calls, 2)
        self.assertEqual(self.executor.root_calls, 2)
        grants = self.manager.snapshot()["active_grants"]
        self.assertEqual(len(grants), 2)
        self.assertEqual({g["kind"] for g in grants}, {"host", "root"})
        self.assertEqual({g["grant_scope"] for g in grants}, {"agent"})
        self.assertEqual(len({g["scope_id"] for g in grants}), 1)

    def test_codex_and_neutral_conversation_ids_allow_scoped_timed_grants(self):
        for conversation, header, metadata in (
            ("thread-123", None, {"x-codex-turn-metadata": {"thread_id": "thread-123", "turn_id": "a"}}),
            ("neutral-123", "X-SSH-MCP-Conversation", None),
        ):
            with self.subTest(conversation=conversation):
                thread, box, request_id = self._start_call(
                    conversation=conversation, header=header, metadata=metadata,
                )
                self.assertTrue(self.manager.pending[request_id].public()["timed_grants_allowed"])
                self.assertEqual(self._decision(request_id, "grant", "5m").status_code, 200)
                self.assertFalse(self._result(thread, box).get("isError"))
                self.assertFalse(self._rpc(conversation=conversation, header=header, metadata=metadata).get("isError"))
        self.assertEqual(self.executor.calls, 4)
        self.assertEqual(len(self.manager.snapshot()["active_grants"]), 2)
        self.assertTrue(self._rpc(conversation="conflicting", metadata={
            "x-codex-turn-metadata": {"thread_id": "thread-123"},
        }).get("isError"))
        self.assertEqual(self.executor.calls, 4)
        thread, box, request_id = self._start_call(conversation=None)
        self.assertEqual(self._decision(request_id, "deny").status_code, 200)
        self.assertTrue(self._result(thread, box).get("isError"))
        self.assertEqual(self.executor.calls, 4)

    def test_antigravity_timed_grant_is_scoped_and_audited_by_conversation(self):
        conversation = "12345678-1234-4234-8234-123456789abc"
        other = "87654321-1234-4234-8234-123456789abc"
        root = "shared-root"
        metadata = {
            "antigravity.google/conversation_id": conversation,
            "antigravity.google/root_conversation_id": root,
            "io.modelcontextprotocol/clientInfo": {"name": "antigravity-client", "version": "v1.0.0"},
        }
        thread, box, request_id = self._start_call(
            conversation=conversation, header=None, metadata=metadata,
        )
        pending = self.manager.pending[request_id].public()
        self.assertEqual(pending["conversation_id"], conversation)
        self.assertTrue(pending["timed_grants_allowed"])
        self.assertEqual(self._decision(request_id, "grant", "5m").status_code, 200)
        result = self._result(thread, box)
        self.assertFalse(result.get("isError"), result)
        job_id = json.loads(result["content"][0]["text"])["job_id"]
        details = self.client.get(f"/console/api/jobs/{job_id}").json()["job"]
        self.assertEqual(details["conversation_id"], conversation)
        self.assertFalse(self._rpc(header=None, metadata=metadata).get("isError"))
        self.assertEqual(self.executor.calls, 2)
        # Even if a grant exists, conflicting correlation sources fail closed.
        self.assertTrue(self._rpc(conversation="conflicting", metadata=metadata).get("isError"))
        for target, meta in (
            (other, {**metadata, "antigravity.google/conversation_id": other}),
            (None, {"antigravity.google/root_conversation_id": root}),
        ):
            thread, box, request_id = self._start_call(
                conversation=target, header=None, metadata=meta,
            )
            self.assertEqual(self.executor.calls, 2)
            self.assertTrue(self.manager.pending[request_id].public()["timed_grants_allowed"])
            self.assertEqual(self.manager.pending[request_id].public()["grant_scope"],
                             "agent" if target is None else "conversation")
            self.assertEqual(self._decision(request_id, "deny").status_code, 200)
            self.assertTrue(self._result(thread, box).get("isError"))
        self.assertEqual(self.executor.calls, 2)

    def test_combined_root_approval_previews_exact_request_and_audits_root(self):
        thread, box, approval_id = self._start_call(
            arguments=self._root_arguments(),
        )
        self.assertEqual(self.executor.root_calls, 0)
        pending = self.client.get("/console/api/changes?after=0:_").json()["pending_approvals"]
        self.assertEqual(len(pending), 1)
        self.assertTrue(pending[0]["requires_host"])
        self.assertTrue(pending[0]["requires_root"])
        self.assertEqual(len(pending[0]["steps"]), 1)
        full = pending[0]["steps"][0]
        self.assertIn("whoami", full["command"])
        self.assertIn('"cwd": "/root/synthetic"', full["options"])
        self.assertIn('"privileged": true', full["options"])
        self.assertFalse(full["truncated"])
        self.assertEqual(self._decision(approval_id, "grant").status_code, 200)
        response = self._result(thread, box)
        self.assertFalse(response.get("isError"), response)
        self.assertEqual(self.executor.root_calls, 1)
        data = json.loads(response["content"][0]["text"])
        self.assertEqual(data["status"], "succeeded")
        self.assertTrue(data["root_started"])
        details = self.client.get(f"/console/api/jobs/{data['job_id']}").json()
        self.assertTrue(details["job"]["privileged"])
        self.assertEqual(details["job"]["run_as"], "root")
        self.assertTrue(details["job"]["root_started"])
        self.assertNotIn("sudo -S", json.dumps(details))
        self.assertEqual(self.manager.snapshot()["active_grants"], [])

    def test_timed_host_grant_then_root_only_and_independent_revoke(self):
        ordinary, box, id_host = self._start_call()
        self.assertEqual(self._decision(id_host, "grant", "5m").status_code, 200)
        self.assertFalse(self._result(ordinary, box).get("isError"))
        old_expiry = max(self.manager.grants.values())
        root, box, id_root = self._start_call(arguments=self._root_arguments())
        pending = self.manager.pending[id_root].public()
        self.assertFalse(pending["requires_host"])
        self.assertTrue(pending["requires_root"])
        self.assertEqual(self._decision(id_root, "grant", "15m").status_code, 200)
        self.assertFalse(self._result(root, box).get("isError"))
        self.assertGreaterEqual(max(self.manager.grants.values()), old_expiry)
        self.assertGreaterEqual(max(self.manager.grants.values()),
                                max(self.manager.root_grants.values()))
        # Cached same-session root grant should not require a second popup.
        self.assertFalse(self._rpc(arguments=self._root_arguments()).get("isError"))
        self.assertEqual(self.executor.root_calls, 2)
        grants = self.client.get("/console/api/changes?after=0:_").json()["active_grants"]
        sudo_id = next(x["id"] for x in grants if x["kind"] == "root")
        response = self.client.post(
            f"/console/api/grants/{sudo_id}/revoke",
            data={"csrf": self.csrf}, headers={"Origin": "https://localhost"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.manager.grants)
        self.assertFalse(self.manager.root_grants)
        self.assertFalse(self._rpc().get("isError"))  # SSH host access is intact.
        waiting, box, request_id = self._start_call(arguments=self._root_arguments())
        self.assertEqual(self._decision(request_id, "deny").status_code, 200)
        self.assertTrue(self._result(waiting, box).get("isError"))
        self.assertEqual(self.executor.root_calls, 2)

    def test_root_only_when_host_unrestricted_and_no_root_prompt_when_always_granted(self):
        self.executor.access = "always-granted"
        root, box, request_id = self._start_call(arguments=self._root_arguments())
        pending = self.manager.pending[request_id].public()
        self.assertFalse(pending["requires_host"])
        self.assertTrue(pending["requires_root"])
        self.assertEqual(self._decision(request_id, "grant", "5m").status_code, 200)
        self.assertFalse(self._result(root, box).get("isError"))
        self.assertFalse(self.manager.grants)
        self.assertTrue(self.manager.root_grants)
        self.manager.root_grants.clear()
        self.executor.privileged_access = "always-granted"
        self.assertFalse(self._rpc(arguments=self._root_arguments()).get("isError"))
        self.assertFalse(self.manager.pending)
        self.assertFalse(self.manager.root_grants)

    def test_root_policy_none_or_no_credential_rejects_without_popup(self):
        self.executor.privileged_access = "none"
        response = self._rpc(arguments=self._root_arguments())
        self.assertTrue(response.get("isError"))
        self.assertFalse(self.manager.pending)
        self.executor.privileged_access = "restricted"
        self.executor._sudo_passwords.clear()
        response = self._rpc(arguments=self._root_arguments())
        self.assertTrue(response.get("isError"))
        self.assertFalse(self.manager.pending)
        self.assertEqual(self.executor.root_calls, 0)

    def test_durable_privileged_batch_requires_single_approval_for_two_steps(self):
        args = {
            "server": "demo-node2", "reason": "Two synthetic privileged commands",
            "privileged": True,
            "commands": [
                {"argv": ["id", "-un"]},
                {"argv": ["id", "-u"]},
            ],
        }
        thread, box, request_id = self._start_call(
            tool="execute_commands", arguments=args,
        )
        pending = self.manager.pending[request_id].public()
        self.assertEqual(len(pending["steps"]), 2)
        self.assertTrue(pending["requires_root"])
        self.assertEqual(self._decision(request_id, "grant", "once").status_code, 200)
        response = self._result(thread, box)
        self.assertFalse(response.get("isError"), response)
        self.assertEqual(self.executor.root_calls, 2)
        result = json.loads(response["content"][0]["text"])
        self.assertEqual(result["status"], "succeeded")
        self.assertTrue(result["privileged"])
        self.assertEqual([step["status"] for step in result["steps"]],
                         ["succeeded", "succeeded"])
        self.assertFalse(self.manager.root_grants)
        rows = self.client.get("/console/api/jobs?time_range=all").json()["jobs"]
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(self.client.get("/console/api/jobs/" + row["id"]).json()["job"]["client_id"], CLIENT)

    def test_admitted_root_batch_continues_after_host_grant_revocation(self):
        args = {
            "server": "demo-node2", "reason": "Admitted batch after revocation",
            "privileged": True, "commands": [
                {"argv": ["id", "-u"]},
                {"argv": ["id", "-un"]},
            ],
        }

        def revoke_on_first_step(index):
            if index == 1:
                key = next(iter(self.manager.grants))
                self.assertTrue(self.manager.revoke(
                    self.manager.grant_id(key),
                ))
                self.assertFalse(self.manager.grants)
                self.assertFalse(self.manager.root_grants)

        self.executor.after_root_step = revoke_on_first_step
        thread, box, approval_id = self._start_call(
            tool="execute_commands", arguments=args,
        )
        self.assertEqual(self._decision(approval_id, "grant", "15m").status_code, 200)
        result = self._result(thread, box)
        self.assertFalse(result.get("isError"), result)
        batch = json.loads(result["content"][0]["text"])
        self.assertEqual(batch["status"], "succeeded")
        self.assertEqual([step["status"] for step in batch["steps"]],
                         ["succeeded", "succeeded"])
        self.assertEqual(self.executor.root_calls, 2)
        self.assertFalse(self.manager.grants)
        self.assertFalse(self.manager.root_grants)

    def test_held_mcp_call_executes_only_after_grant_and_denial_never_executes(self):
        thread, box, request_id = self._start_call()
        self.assertEqual(self.executor.calls, 0)
        waiting = self.client.get("/console/api/jobs?time_range=all").json()["jobs"][0]
        self.assertEqual(waiting["status"], "awaiting_approval")
        self.assertEqual(waiting["run_as"], "mcp-agent")
        self.assertEqual(self._decision(request_id, "grant").status_code, 200)
        reply = self._result(thread, box)
        self.assertFalse(reply.get("isError"), reply)
        executed = json.loads(reply["content"][0]["text"])
        self.assertEqual(executed["status"], "succeeded")
        self.assertEqual(self.executor.calls, 1)
        job = self.client.get("/console/api/jobs?time_range=all").json()["jobs"][0]
        self.assertEqual(job["conversation_id"], CONVERSATION)
        self.assertEqual(job["run_as"], "mcp-agent")
        self.assertEqual(self.manager.snapshot()["active_grants"], [])

        thread, box, request_id = self._start_call()
        self.assertEqual(self.executor.calls, 1)
        self.assertEqual(self._decision(request_id, "deny").status_code, 200)
        denied = self._result(thread, box)
        self.assertTrue(denied.get("isError"))
        self.assertEqual(self.executor.calls, 1)

    def test_timed_grant_allows_same_conversation_only_and_revoke(self):
        thread, box, request_id = self._start_call()
        self.assertEqual(self._decision(request_id, "grant", "5m").status_code, 200)
        self.assertFalse(self._result(thread, box).get("isError"))
        # A subsequent call with the same validated OAuth sid + conversation
        # is automatically permitted while the timed grant remains active.
        self.assertFalse(self._rpc().get("isError"))
        self.assertEqual(self.executor.calls, 2)

        other, box, request_id = self._start_call(conversation="v1/pr2-other")
        self.assertEqual(self.executor.calls, 2)
        self.assertEqual(self._decision(request_id, "deny").status_code, 200)
        self.assertTrue(self._result(other, box).get("isError"))

        grant = self.client.get("/console/api/changes?after=0:_").json()["active_grants"][0]
        answer = self.client.post(f"/console/api/grants/{grant['id']}/revoke", data={
            "csrf": self.csrf,
        }, headers={"Origin": "https://localhost"})
        self.assertEqual(answer.status_code, 200)
        pending, box, request_id = self._start_call()
        self.assertEqual(self.executor.calls, 2)
        self.assertEqual(self._decision(request_id, "deny").status_code, 200)
        self.assertTrue(self._result(pending, box).get("isError"))
        self.assertEqual(self.executor.calls, 2)

    def test_durable_denied_command_and_file_share_operator_and_agent_history(self):
        pending, box, request_id = self._start_call(
            arguments=self._root_arguments(argv=["id", "-u"]))
        early_command = self.client.get("/console/api/jobs?time_range=all").json()["jobs"][0]
        self.assertEqual(early_command["status"], "awaiting_approval")
        self.assertEqual(self.client.get("/console/api/jobs/" + early_command["id"]).json()["job"]["client_id"], CLIENT)
        self.assertIsNone(early_command["approval_status"])
        self.assertIsNone(early_command["started_at"])
        self.assertEqual(self._decision(request_id, "deny").status_code, 200)
        self.assertTrue(self._result(pending, box).get("isError"))
        self.assertEqual(self.executor.root_calls, 0)

        pending, box, request_id = self._start_call(
            tool="read_file", arguments={"server": "demo-node2",
                                          "path": "/tmp/synthetic",
                                          "reason": "TEST-276 synthetic file denial"})
        early_file = self.client.get("/console/api/jobs?time_range=all").json()["jobs"][0]
        self.assertEqual(early_file["status"], "awaiting_approval")
        self.assertEqual(self.client.get("/console/api/jobs/" + early_file["id"]).json()["job"]["client_id"], CLIENT)
        self.assertIsNone(early_file["approval_status"])
        self.assertIsNone(early_file["started_at"])
        self.assertEqual(self._decision(request_id, "deny").status_code, 200)
        self.assertTrue(self._result(pending, box).get("isError"))
        self.assertEqual(self.executor.calls, 0)

        page = self.client.get("/console/api/jobs?time_range=all").json()
        self.assertEqual(page["filtered_total"], 2)
        after = {row["id"]: row for row in page["jobs"]}
        for initial in (early_command, early_file):
            self.assertIn(initial["id"], after)
            self.assertEqual(after[initial["id"]]["created_at"], initial["created_at"])
        self.assertEqual([row["status"] for row in page["jobs"]], ["denied", "denied"])
        self.assertEqual({row["record_kind"] for row in page["jobs"]}, {"command", "file"})
        self.assertEqual({row["approval_status"] for row in page["jobs"]},
                         {"denied_explicit"})
        self.assertEqual(page["totals"]["failed"], 2)
        stats_reply = self._rpc(tool="get_job_stats",
                                arguments={"record_kind": "all", "time_range": "all"})
        self.assertFalse(stats_reply.get("isError"), stats_reply)
        stats = json.loads(stats_reply["content"][0]["text"])
        self.assertEqual(stats["failures"], 2)
        for row in page["jobs"]:
            detail = self.client.get("/console/api/jobs/" + row["id"]).json()["job"]
            self.assertEqual(detail["approval_status"], "denied_explicit")
            self.assertEqual(detail["client_id"], CLIENT)
            self.assertIsNone(detail["exit_code"])
            self.assertIsNot(detail["root_started"], True)
            self.assertEqual(detail["output_bytes"], 0)
        root = next(row for row in page["jobs"] if row["record_kind"] == "command")
        self.assertTrue(root["privileged"])
        self.assertIs(root["root_started"], False)
        agent = self._rpc(tool="list_jobs",
                          arguments={"record_kind": "all", "time_range": "all"})
        self.assertFalse(agent.get("isError"), agent)
        data = json.loads(agent["content"][0]["text"])
        self.assertEqual(data["total"], 2)
        self.assertEqual({x["approval_status"] for x in data["jobs"]},
                         {"denied_explicit"})
        detail_rpc = self._rpc(tool="get_job", arguments={"job_id": root["id"]})
        self.assertEqual(json.loads(detail_rpc["content"][0]["text"])["job"]
                         ["approval_status"], "denied_explicit")

    def test_approved_explicit_timed_and_config_codes_in_execution_records(self):
        first, box, ident = self._start_call()
        self.assertEqual(self._decision(ident, "grant").status_code, 200)
        self.assertFalse(self._result(first, box).get("isError"))
        first_row = self.client.get("/console/api/jobs?time_range=all").json()["jobs"][0]
        self.assertEqual(first_row["approval_status"], "approved_explicit")

        pending, box, ident = self._start_call()
        self.assertEqual(self._decision(ident, "grant", "5m").status_code, 200)
        self.assertFalse(self._result(pending, box).get("isError"))
        self.assertFalse(self._rpc().get("isError"))
        latest = self.client.get("/console/api/jobs?time_range=all").json()["jobs"]
        self.assertEqual([x["approval_status"] for x in latest[:2]],
                         ["approved_timed", "approved_timed"])

        self.executor.access = "always-granted"
        self.executor.privileged_access = "always-granted"
        self.assertFalse(self._rpc().get("isError"))
        latest = self.client.get("/console/api/jobs?time_range=all").json()["jobs"][0]
        self.assertEqual(latest["approval_status"], "approved_config")

    def test_denied_submit_and_write_file_use_existing_audit_tables(self):
        task, box, request_id = self._start_call(tool="submit_job")
        self.assertEqual(self._decision(request_id, "deny").status_code, 200)
        self.assertTrue(self._result(task, box).get("isError"))

        task, box, request_id = self._start_call(
            tool="write_file",
            arguments={"server": "demo-node2", "path": "/tmp/offline-denied",
                       "content": "synthetic", "reason": "TEST-276 denied write"})
        self.assertEqual(self._decision(request_id, "deny").status_code, 200)
        self.assertTrue(self._result(task, box).get("isError"))
        self.assertEqual(self.executor.calls, 0)
        rows = self.client.get("/console/api/jobs?time_range=all").json()["jobs"]
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["mode"] for row in rows}, {"async", "file"})
        self.assertTrue(all(row["approval_status"] == "denied_explicit" for row in rows))
        self.assertTrue(all(row["status"] == "denied" for row in rows))

    def test_readiness_refusal_after_operator_grant_preserves_approval(self):
        from app.ssh_executor import ReadinessDenied

        message = "Host readiness unavailable: ssh_readiness_stale"
        specs = (
            ("execute_command", {"server": "demo-node2", "argv": ["id"], "reason": "synthetic"}),
            ("submit_job", {"server": "demo-node2", "argv": ["id"], "reason": "synthetic"}),
            ("execute_commands", {"server": "demo-node2", "reason": "synthetic",
                                  "commands": [{"argv": ["id"]}, {"argv": ["pwd"]}]}),
            ("read_file", {"server": "demo-node2", "path": "/tmp/synthetic", "reason": "synthetic"}),
        )
        for index, (tool, arguments) in enumerate(specs):
            with self.subTest(tool=tool), patch.object(
                    self.executor, "require_ready", side_effect=ReadinessDenied(message)):
                thread, box, identifier = self._start_call(
                    tool=tool, arguments=arguments, conversation=f"readiness-{index}",
                )
                self.assertEqual(self._decision(identifier, "grant", "5m").status_code, 200)
                response = self._result(thread, box)
                self.assertTrue(response.get("isError"), response)
                if tool == "execute_commands":
                    result = json.loads(response["content"][0]["text"])
                    self.assertEqual(result["failure_kind"], "host_readiness")
                    self.assertEqual(result["error"], message)
                    self.assertTrue(all(not step["attempted"] for step in result["steps"]))
                rows = self.client.get("/console/api/jobs?time_range=all").json()["jobs"]
                row = next(r for r in rows if r["conversation_id"] == f"readiness-{index}")
                self.assertEqual(row["status"], "failed")
                self.assertEqual(row["approval_status"], "approved_timed")
                self.assertIsNone(row["started_at"])
                self.assertEqual(self.executor.calls, 0)
                self.assertEqual(self.executor.root_calls, 0)

    def test_approval_unavailable_is_durable_with_null_code_not_denied(self):
        from app import approvals as approvals_module

        with patch.object(approvals_module, "MAX_PENDING", 0):
            answer = self._rpc()
        self.assertTrue(answer.get("isError"))
        self.assertEqual(self.executor.calls, 0)
        row = self.client.get("/console/api/jobs?time_range=all").json()["jobs"][0]
        self.assertEqual(row["status"], "failed")
        self.assertIsNone(row["approval_status"])
        self.assertIsNone(row["started_at"])
        self.assertEqual(row["output_bytes"], 0)

    def test_repeated_file_denial_does_not_consume_operation_id(self):
        ids = []
        for _ in range(2):
            pending, box, request_id = self._start_call(
                tool="read_file", arguments={"server": "demo-node2",
                    "path": "/tmp/no-such-file", "reason": "replay safety",
                    "operation_id": "same-request-id"})
            self.assertEqual(self._decision(request_id, "deny").status_code, 200)
            self.assertTrue(self._result(pending, box).get("isError"))
            ids.append(self.client.get("/console/api/jobs?time_range=all")
                       .json()["jobs"][0]["id"])
        self.assertEqual(len(set(ids)), 2)
        self.assertTrue(all(value != "file_same-request-id" for value in ids))
        self.assertEqual(self.executor.calls, 0)

    def test_all_file_routes_audit_denial_before_payload_execution(self):
        specs = (
            ("apply_patch", {
                "server": "demo-node2", "path": "/tmp/synthetic-patch",
                "patch": "*** Begin Patch\n*** Add File: first.txt\n+synthetic\n*** End Patch",
                "reason": "synthetic denied patch",
            }, "patch"),
            ("upload_file", {
                "server": "demo-node2", "path": "/tmp/synthetic-upload",
                "file": {"file_id": "synthetic-ref",
                         "download_url": "https://example.invalid/input"},
                "reason": "synthetic denied upload",
            }, "upload"),
            ("download_file", {
                "server": "demo-node2", "path": "/tmp/synthetic-download",
                "reason": "synthetic denied download",
            }, "download"),
        )
        for tool, arguments, kind in specs:
            with self.subTest(tool=tool):
                pending, box, identifier = self._start_call(
                    tool=tool, arguments=arguments,
                )
                self.assertEqual(self._decision(identifier, "deny").status_code, 200)
                self.assertTrue(self._result(pending, box).get("isError"))
                self.assertEqual(self.executor.calls, 0)
                listing = self.client.get("/console/api/jobs?time_range=all").json()
                row = listing["jobs"][0]
                self.assertEqual(row["status"], "denied")
                self.assertEqual(row["record_kind"], "file")
                self.assertEqual(row["operation_kind"], kind)
                self.assertEqual(row["approval_status"], "denied_explicit")
                self.assertIsNone(row["started_at"])

    def test_early_batch_authorization_keeps_structured_rejection(self):
        arguments = {
            "server": "demo-node2", "reason": "synthetic batch rejection",
            "commands": [{"argv": ["hostname"]}],
        }
        for label, fields in (
            ("invalid_signed_host", {**arguments, "server": "demo-node-b"}),
            ("missing_verified_session", arguments),
        ):
            with self.subTest(label=label):
                previous = self.token
                try:
                    if label == "missing_verified_session":
                        self.token, _ = oauth.issue_access_token(
                            CLIENT, oauth._supported_scopes(), session_id=None,
                        )
                    result = self._rpc(
                        tool="execute_commands", arguments=fields,
                    )
                finally:
                    self.token = previous
                self.assertTrue(result.get("isError"), result)
                data = json.loads(result["content"][0]["text"])
                self.assertEqual(data["status"], "rejected")
                self.assertEqual(data["failure_kind"], "authorization")
                self.assertEqual(data["failed_field"], "server")
                self.assertEqual(data["steps_attempted"], 0)
                self.assertIsNone(data["failed_step"])
        self.assertEqual(self.executor.calls, 0)
        listed = self._rpc(tool="list_batches", arguments={"cursor": 0})
        self.assertEqual(json.loads(listed["content"][0]["text"])["batches"], [])

    def test_approved_file_keeps_reserved_history_id_with_caller_replay_key(self):
        from app.file_transport import FileTransport

        arguments = {
            "server": "demo-node2", "reason": "synthetic stable History ID",
            "path": "/tmp/test-file", "operation_id": "caller-replay-SKY276",
        }
        async def fake_read(_transport, _actor, _server, _operation, _payload):
            return {"ok": True, "content": "synthetic", "bytes": 9}

        with patch.object(FileTransport, "execute", fake_read):
            thread, box, approval_id = self._start_call(
                tool="read_file", arguments=arguments,
            )
            before = self.client.get("/console/api/jobs?time_range=all").json()["jobs"][0]
            self.assertEqual(before["status"], "awaiting_approval")
            history_id = before["id"]
            self.assertEqual(self._decision(approval_id, "grant").status_code, 200)
            result = self._result(thread, box)
            self.assertFalse(result.get("isError"), result)
        data = json.loads(result["content"][0]["text"])
        self.assertEqual(data["operation_id"], arguments["operation_id"])
        self.assertEqual(data["history_id"], history_id)
        details = self.client.get("/console/api/jobs/" + history_id).json()["job"]
        self.assertEqual(details["status"], "succeeded")
        self.assertEqual(details["approval_status"], "approved_explicit")
        self.assertEqual(details["created_at"], before["created_at"])
        self.assertIsNotNone(details["started_at"])
        rows = self.client.get("/console/api/jobs?time_range=all").json()["jobs"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], history_id)
        # A client that lost the original success response only knows its
        # caller-provided replay ID. The duplicate refusal must allow it to
        # recover the immutable History ID without another SSH call/prompt.
        duplicate = self._rpc(tool="read_file", arguments=arguments)
        self.assertTrue(duplicate.get("isError"))
        duplicate_data = json.loads(duplicate["content"][0]["text"])
        self.assertEqual(duplicate_data["error"]["code"], "duplicate_operation")
        self.assertEqual(duplicate_data["history_id"], history_id)
        recovered = self._rpc(tool="get_job",
                              arguments={"job_id": duplicate_data["history_id"]})
        self.assertFalse(recovered.get("isError"), recovered)
        self.assertEqual(json.loads(recovered["content"][0]["text"])["job"]["id"],
                         history_id)
        self.assertFalse(self.manager.pending)

    def test_file_revalidation_failure_finalizes_approved_rows_without_ssh(self):
        cases = (
            ("read_file", {
                "server": "demo-node2", "path": "/tmp/revalidation",
                "reason": "offline file host revalidation",
                "operation_id": "revalidation-file-read",
            }),
            ("upload_file", {
                "server": "demo-node2", "path": "/tmp/revalidation-upload",
                "reason": "offline upload host revalidation",
                "operation_id": "revalidation-file-upload",
                "file": {"file_id": "synthetic-ref",
                         "download_url": "https://example.invalid/input"},
            }),
        )
        for tool, args in cases:
            with self.subTest(tool=tool):
                thread, box, pending_id = self._start_call(
                    tool=tool, arguments=args,
                )
                pending_row = self.client.get(
                    "/console/api/jobs?time_range=all"
                ).json()["jobs"][0]
                self.assertEqual(pending_row["status"], "awaiting_approval")
                with patch.object(
                    self.executor, "authorized_host",
                    side_effect=SSHDenied("synthetic signed host revalidation failed"),
                ):
                    self.assertEqual(self._decision(pending_id, "grant").status_code, 200)
                    response = self._result(thread, box)
                self.assertTrue(response.get("isError"), response)
                row = self.client.get(
                    f"/console/api/jobs/{pending_row['id']}"
                ).json()["job"]
                self.assertEqual(row["id"], pending_row["id"])
                self.assertEqual(row["status"], "failed")
                self.assertEqual(row["approval_status"], "approved_explicit")
                self.assertIsNone(row["started_at"])
                self.assertIsNotNone(row["ended_at"])
                self.assertEqual(row["error_code"], "authorization")
                self.assertEqual(self.executor.calls, 0)
        self.assertFalse(self.manager.pending)

    def test_denied_config_persists_without_popup(self):
        self.executor.privileged_access = "none"
        denied = self._rpc(arguments=self._root_arguments())
        self.assertTrue(denied.get("isError"))
        self.assertEqual(self.executor.root_calls, 0)
        self.assertEqual(self.manager.snapshot()["pending_approvals"], [])
        row = self.client.get("/console/api/jobs?time_range=all").json()["jobs"][0]
        self.assertEqual(row["status"], "denied")
        self.assertEqual(row["approval_status"], "denied_config")

    def test_batch_preview_and_denial_preserve_preexecution_rejection(self):
        result = {}

        def invoke_batch():
            try:
                response = self.client.post("/mcp", headers={
                    "Authorization": f"Bearer {self.token}",
                    "Accept": "application/json, text/event-stream",
                    "Host": "localhost",
                    "X-OpenAI-Session": CONVERSATION,
                }, json={
                    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "execute_commands", "arguments": {
                        "server": "demo-node2", "reason": "Synthetic gated batch",
                        "commands": [
                            {"argv": ["echo", "first"]},
                            {"argv": ["echo", "second"]},
                        ],
                    }},
                })
                result["response"] = response.json()["result"]
            except BaseException as exc:
                result["exception"] = exc

        thread = threading.Thread(target=invoke_batch)
        thread.start()
        pending = None
        for _ in range(100):
            items = self.client.get(
                "/console/api/changes?after=0:_"
            ).json()["pending_approvals"]
            if items:
                pending = items[0]
                break
            time.sleep(.02)
        self.assertIsNotNone(pending)
        assert pending is not None
        self.assertEqual(pending["tool"], "execute_commands")
        self.assertIn("echo first", pending["summary"])
        self.assertIn("echo second", pending["summary"])
        self.assertEqual(self.executor.calls, 0)
        queued = self._rpc(tool="list_batches", arguments={"cursor": 0})
        self.assertFalse(queued.get("isError"), queued)
        preview = json.loads(queued["content"][0]["text"])["batches"][0]
        self.assertEqual(preview["status"], "awaiting_approval")
        self.assertEqual(preview["total_steps"], 2)
        waiting_id = preview["batch_id"]
        self.assertEqual(self._decision(pending["id"], "deny").status_code, 200)
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertNotIn("exception", result)
        response = result["response"]
        self.assertTrue(response.get("isError"))
        rejected = json.loads(response["content"][0]["text"])
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(rejected["failure_kind"], "authorization")
        self.assertEqual(rejected["failed_field"], "server")
        self.assertEqual(rejected["steps_attempted"], 0)
        self.assertEqual(self.executor.calls, 0)
        got_batch = self._rpc(tool="get_batch",
                              arguments={"batch_id": waiting_id, "cursor": 0, "limit": 5})
        self.assertFalse(got_batch.get("isError"), got_batch)
        outcome = json.loads(got_batch["content"][0]["text"])
        self.assertEqual(outcome["batch_id"], waiting_id)
        self.assertEqual(outcome["status"], "denied")
        self.assertEqual(outcome["approval_status"], "denied_explicit")
        self.assertEqual(outcome["total_steps"], 2)
        self.assertTrue(all(step["status"] == "not_attempted"
                            and not step["attempted"] for step in outcome["steps"]))
        self.assertIsNone(outcome["next_cursor"])
        self.assertFalse(outcome["has_more"])
        page = self.client.get("/console/api/jobs?time_range=all").json()
        denied_batches = [x for x in page["jobs"] if x["record_kind"] == "batch"]
        self.assertEqual(len(denied_batches), 1)
        batch_row = denied_batches[0]
        self.assertEqual(batch_row["mode"], "batch")
        self.assertEqual(batch_row["status"], "denied")
        self.assertEqual(batch_row["approval_status"], "denied_explicit")
        self.assertEqual(batch_row["argv_count"], 2)
        self.assertIsNone(batch_row["started_at"])
        detail = self.client.get("/console/api/jobs/" + batch_row["id"]).json()["job"]
        self.assertEqual(detail["approval_status"], "denied_explicit")
        self.assertEqual(detail["request"]["total_steps"], 2)
        agent = self._rpc(tool="list_jobs",
                          arguments={"record_kind": "batch", "time_range": "all"})
        self.assertFalse(agent.get("isError"), agent)
        self.assertEqual(json.loads(agent["content"][0]["text"])["total"], 1)
