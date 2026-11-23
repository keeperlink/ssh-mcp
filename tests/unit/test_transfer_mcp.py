"""Authenticated two-host MCP relay admission and durable history contracts."""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ.setdefault("MCP_ISSUER", "http://localhost")
os.environ.setdefault("MCP_LOGIN_KEY", "synthetic-transfer-login-" + "a" * 40)
os.environ.setdefault("MCP_TOKEN_SIGNING_SECRET", "synthetic-transfer-signing-" + "b" * 40)
os.environ.setdefault("MCP_CIMD_VALIDATE_REMOTE", "false")

from app import config, mcp_gateway, oauth  # noqa: E402
from app.ssh_executor import SSHDenied  # noqa: E402

CLIENT = "https://chatgpt.com/oauth/client.json"


class HostFixture:
    def __init__(self) -> None:
        self.restricted: set[str] = set()
        self.privileged: set[str] = set()
        self._sealed_sudo: dict[str, str] = {}
        self._sudo_passwords: dict[str, str] = {}
        self.hosts = {"demo-node-a", "demo-node-b"}

    def authorized_host(self, actor: str, alias: str) -> SimpleNamespace:
        if actor != oauth.client_audit_actor(CLIENT) or alias not in self.hosts:
            raise SSHDenied("Host unavailable")
        return SimpleNamespace(
            alias=alias, username="demo",
            access="restricted" if alias in self.restricted else "always-granted",
            privileged_access="always-granted" if alias in self.privileged else "none",
        )

    def require_ready(self, _server: str, *, privileged: bool = False) -> None:
        if privileged:
            raise SSHDenied("Root unavailable")


class TransferToolTests(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.db = str(Path(folder.name) / "jobs.sqlite")
        env = patch.dict(os.environ, {
            "SSH_JOBS_ENABLED": "true", "SSH_JOBS_DB": self.db,
        })
        env.start()
        self.addCleanup(env.stop)
        clients = {"ChatGPT": {
            "identities": [CLIENT], "conversation_id": {
                "sources": [{"type": "header", "name": "X-OpenAI-Session"}],
            },
        }}
        cp = patch.object(config, "MCP_CLIENTS", clients)
        mp = patch.object(config, "MCP_SSH_TOOLS_ENABLED", True)
        cp.start()
        mp.start()
        self.addCleanup(cp.stop)
        self.addCleanup(mp.stop)
        self.executor = HostFixture()
        with patch.object(mcp_gateway.SSHExecutor, "from_environment",
                          return_value=self.executor):
            self.registry: dict = {}
            server, app = mcp_gateway.create_mcp_server(job_registry=self.registry)

        @asynccontextmanager
        async def lifespan(_app):
            async with server.session_manager.run():
                yield

        fastapi = FastAPI(lifespan=lifespan)
        fastapi.mount("/", app)
        self.ctx = TestClient(fastapi)
        self.client = self.ctx.__enter__()
        self.addCleanup(lambda: self.ctx.__exit__(None, None, None))
        self.token, _ = oauth.issue_access_token(CLIENT, oauth._supported_scopes())

        async def admitted(relay, actor, req, *, precreated_id, roots):
            identifier = relay.audit.start(
                actor, req.dest_server, "transfer", req.dest_path, req.story_id,
                req.operation_id, precreated_id=precreated_id,
            )
            relay.audit.finish(identifier, "succeeded", byte_count=2,
                transfer={"direction": "relay", "size": 2,
                          "source_server": req.source_server,
                          "dest_server": req.dest_server,
                          "source_path": req.source_path, "dest_path": req.dest_path})
            return {"history_id": "file_" + identifier,
                    "status": "succeeded", "bytes_transferred": 2}

        mock = patch.object(mcp_gateway.HostRelayService, "transfer", admitted)
        mock.start()
        self.addCleanup(mock.stop)

    def rpc(self, method: str, params: dict) -> dict:
        response = self.client.post("/mcp", headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json, text/event-stream",
            "Host": "localhost",
        }, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["result"]

    def tool(self, name: str, args: dict) -> tuple[dict, object]:
        result = self.rpc("tools/call", {"name": name, "arguments": args})
        body = result["content"][0]["text"]
        try:
            data = json.loads(body)
        except ValueError:
            data = body
        return result, data

    def request(self, **kwargs) -> dict:
        request = {
            "source_server": "demo-node-a", "source_path": "/private/source.key",
            "dest_server": "demo-node-b", "dest_path": "/private/dest.key",
            "reason": "TEST-N vetted metadata-only transfer", "operation_id": "synthetic_REPLAY1",
        }
        request.update(kwargs)
        return request

    def test_tool_schema_admission_audit_and_two_host_filters(self) -> None:
        names = {tool["name"] for tool in self.rpc("tools/list", {})["tools"]}
        self.assertIn("transfer_file", names)
        result, data = self.tool("transfer_file", self.request())
        self.assertFalse(result.get("isError"), result)
        self.assertEqual(data["status"], "succeeded")
        with sqlite3.connect(self.db) as db:
            row = db.execute(
                "SELECT server,source_server,path_summary,status,result_metadata "
                "FROM file_operations WHERE operation_id='synthetic_REPLAY1'",
            ).fetchone()
            self.assertEqual(row[:4], ("demo-node-b", "demo-node-a", "dest.key", "succeeded"))
            self.assertNotIn("/private/", str(row))
            self.assertNotIn("source.key", row[2])
        for host in ("demo-node-a", "demo-node-b"):
            listing, data = self.tool("list_jobs", {"time_range": "all", "host": host, "record_kind": "file"})
            self.assertFalse(listing.get("isError"))
            self.assertEqual(data["total"], 1, (host, data))
            self.assertEqual(data["jobs"][0]["source_server"], "demo-node-a")
        detail, data = self.tool("get_job", {"job_id": data["jobs"][0]["id"]})
        self.assertFalse(detail.get("isError"))
        self.assertEqual(data["job"]["file_metadata"]["transfer"]["source_path"], "source.key")

    def test_replay_rejected_before_new_approval(self) -> None:
        self.assertFalse(self.tool("transfer_file", self.request())[0].get("isError"))
        rejected, data = self.tool("transfer_file", self.request())
        self.assertTrue(rejected.get("isError"))
        self.assertEqual(data["error"]["code"], "duplicate_operation")
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM file_operations").fetchone()[0], 1)

    def test_strict_validation_and_no_unauthorized_remote(self) -> None:
        for values in (
            {"source_server": "demo-node-b"},
            {"source_path": "\x00"},
            {"mode": "create", "expected_sha256": "a" * 64},
            {"wait_seconds": "30"},
            {"extra_field": "not allowed"},
            {"source_server": "demo-node-c"},
        ):
            with self.subTest(values=values):
                result, _ = self.tool("transfer_file", self.request(**values))
                self.assertTrue(result.get("isError"))

    def test_source_and_dest_approvals_independently_required(self) -> None:
        for restricted in ("demo-node-a", "demo-node-b"):
            with self.subTest(host=restricted):
                self.executor.restricted = {restricted}
                result, _ = self.tool("transfer_file", self.request(
                    operation_id="synthetic_" + restricted.replace("-", "_"),
                ))
                self.assertTrue(result.get("isError"))
                with sqlite3.connect(self.db) as db:
                    self.assertEqual(db.execute(
                        "SELECT status,source_server FROM file_operations "
                        "WHERE operation_id IS NULL ORDER BY created_at DESC LIMIT 1"
                    ).fetchone()[0], "failed")
        self.executor.restricted.clear()

    def test_privileged_authorization_denied_without_host_policy(self) -> None:
        result, _ = self.tool("transfer_file", self.request(
            source_privileged=True,
        ))
        self.assertTrue(result.get("isError"))
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute(
                "SELECT count(*) FROM file_operations WHERE status IN ('failed','denied')"
            ).fetchone()[0], 1)

    def test_cancel_file_routes_to_relay_manager(self) -> None:
        async def active(relay, actor, req, *, precreated_id, roots):
            identifier = relay.audit.start(
                actor, req.dest_server, "transfer", req.dest_path,
                req.story_id, req.operation_id, precreated_id=precreated_id,
            )
            return {"status": "running", "history_id": "file_" + identifier}

        async def cancelled(_relay, _actor, _id):
            return {"cancellation_requested": True, "status": "running"}

        with patch.object(mcp_gateway.HostRelayService, "transfer", active), patch.object(
            mcp_gateway.HostRelayService, "cancel", cancelled,
        ):
            result, data = self.tool("transfer_file", self.request())
            self.assertFalse(result.get("isError"))
            self.assertEqual(data["status"], "running")
            result, data = self.tool("cancel_job", {
                "job_id": data["history_id"], "reason": "Operator cancels synthetic transfer",
            })
            self.assertFalse(result.get("isError"))
            self.assertTrue(data["cancellation_requested"])


    def test_unavailable_durable_audit_fails_before_approval(self) -> None:
        from app.file_audit import FileAudit
        with patch.object(FileAudit, "reserve", side_effect=sqlite3.OperationalError("synthetic DB")):
            result, body = self.tool("transfer_file", self.request())
        self.assertTrue(result.get("isError"))
        self.assertIn("audit", body.lower())
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM file_operations").fetchone()[0], 0)

    def test_source_audit_write_failure_finalizes_awaiting_request(self) -> None:
        from app.file_audit import FileAudit
        with patch.object(FileAudit, "set_source", side_effect=OSError("unavailable")):
            result, body = self.tool("transfer_file", self.request())
        self.assertTrue(result.get("isError"))
        self.assertIn("audit", body.lower())
        with sqlite3.connect(self.db) as db:
            states = db.execute("SELECT status FROM file_operations").fetchall()
        self.assertEqual(states, [("failed",)])

    def test_rejection_of_second_host_preserves_first_approval_boundary(self) -> None:
        from app.approval_status import ApprovalCode, ApprovalRejected
        called = []
        async def guarded(*_args, **kwargs):
            called.append(kwargs["tool"])
            if len(called) == 2:
                raise ApprovalRejected(ApprovalCode.DENIED_CONFIG, "private operator deny")
            return ApprovalCode.APPROVED_CONFIG

        with patch.object(mcp_gateway, "require_host_access", guarded):
            result, body = self.tool("transfer_file", self.request())
        self.assertTrue(result.get("isError"))
        self.assertIn("approval", body)
        self.assertEqual(called, ["transfer_file", "transfer_file"])
        with sqlite3.connect(self.db) as db:
            row = db.execute("SELECT status,approval_status,source_server FROM file_operations").fetchone()
        self.assertEqual(row[0], "denied")
        self.assertEqual(row[2], "demo-node-a")

    def test_readiness_loss_after_first_host_approval_finalizes(self) -> None:
        from app.approval_status import ApprovalCode
        from app.ssh_executor import ReadinessDenied
        calls = []
        async def guarded(*_args, **kwargs):
            calls.append(kwargs)
            if len(calls) == 2:
                raise ReadinessDenied("synthetic unavailable")
            return ApprovalCode.APPROVED_CONFIG

        with patch.object(mcp_gateway, "require_host_access", guarded):
            result, body = self.tool("transfer_file", self.request())
        self.assertTrue(result.get("isError"))
        self.assertIn("confirmation", body)
        with sqlite3.connect(self.db) as db:
            row = db.execute("SELECT status FROM file_operations").fetchone()
        self.assertEqual(row, ("failed",))

    def test_exception_during_approved_dispatch_marks_queued_terminal(self) -> None:
        async def crashed(*_args, **_kwargs):
            raise OSError("synthetic scheduling failed")
        with patch.object(mcp_gateway.HostRelayService, "transfer", crashed):
            result, body = self.tool("transfer_file", self.request())
        self.assertTrue(result.get("isError"))
        self.assertIn("confirmation", body)
        with sqlite3.connect(self.db) as db:
            row = db.execute("SELECT status,error_code FROM file_operations").fetchone()
        self.assertEqual(row, ("failed", "transport_error"))

    def test_relay_failed_result_remains_structured(self) -> None:
        async def failed(relay, actor, req, *, precreated_id, roots):
            identifier = relay.audit.start(
                actor, req.dest_server, "transfer", req.dest_path,
                req.story_id, req.operation_id, precreated_id=precreated_id,
            )
            relay.audit.finish(identifier, "unknown", error_code="transport_error")
            return {"status": "unknown", "history_id": "file_" + identifier,
                    "error": {"code": "transport_error"}}
        with patch.object(mcp_gateway.HostRelayService, "transfer", failed):
            result, body = self.tool("transfer_file", self.request())
        self.assertTrue(result.get("isError"))
        self.assertEqual(body["status"], "unknown")
        self.assertIn("history_id", body)

    def test_approved_both_hosts_preserves_distinct_privileged_unlocks(self) -> None:
        from app.approval_status import ApprovalCode
        from app.grant_unlocks import root_access_context
        self.executor.privileged.update(["demo-node-a", "demo-node-b"])
        self.executor._sudo_passwords.update({
            "demo-node-a": "fixture", "demo-node-b": "fixture"
        })
        captured = []
        class FakeOperation:
            delegated = False
        class Unlock:
            def __init__(self, host):
                self.host = host
                self.operation = FakeOperation()
                self.finished = 0
            def finish(self):
                if not self.operation.delegated and self.finished == 0:
                    self.finished += 1
        unlocks = []
        async def admitted(*_args, **kwargs):
            if kwargs["privileged"]:
                new_root = Unlock(_args[2])
                unlocks.append(new_root)
                root_access_context.set(new_root)
            return ApprovalCode.APPROVED_CONFIG

        async def captured_transfer(relay, actor, req, *, precreated_id, roots):
            captured.extend(roots)
            identifier = relay.audit.start(
                actor, req.dest_server, "transfer", req.dest_path,
                req.story_id, req.operation_id, precreated_id=precreated_id,
            )
            relay.audit.finish(identifier, "succeeded")
            return {"status": "succeeded", "history_id": "file_" + identifier}

        with patch.object(mcp_gateway, "require_host_access", admitted), patch.object(
            mcp_gateway.HostRelayService, "transfer", captured_transfer,
        ):
            result, _ = self.tool("transfer_file", self.request(
                source_privileged=True, dest_privileged=True,
            ))
        self.assertFalse(result.get("isError"))
        self.assertEqual(len(captured), 2)
        self.assertIsNot(captured[0], captured[1])
        self.assertEqual([r.finished for r in unlocks], [1, 1])

    def test_approval_audit_preserves_source_explicit_when_dest_config(self) -> None:
        from app.approval_status import ApprovalCode
        codes = [ApprovalCode.APPROVED_EXPLICIT, ApprovalCode.APPROVED_CONFIG]
        async def mixed(*_args, **_kwargs):
            return codes.pop(0)
        with patch.object(mcp_gateway, "require_host_access", mixed):
            response, body = self.tool("transfer_file", self.request())
        self.assertFalse(response.get("isError"), body)
        with sqlite3.connect(self.db) as db:
            code = db.execute(
                "SELECT approval_status FROM file_operations"
            ).fetchone()[0]
        self.assertEqual(code, int(ApprovalCode.APPROVED_EXPLICIT))

    def test_approval_audit_preserves_timed_when_other_is_config(self) -> None:
        from app.approval_status import ApprovalCode
        codes = [ApprovalCode.APPROVED_TIMED, ApprovalCode.APPROVED_CONFIG]
        async def mixed(*_args, **_kwargs):
            return codes.pop(0)
        with patch.object(mcp_gateway, "require_host_access", mixed):
            response, body = self.tool("transfer_file", self.request())
        self.assertFalse(response.get("isError"), body)
        with sqlite3.connect(self.db) as db:
            code = db.execute(
                "SELECT approval_status FROM file_operations"
            ).fetchone()[0]
        self.assertEqual(code, int(ApprovalCode.APPROVED_TIMED))

    def test_root_context_never_leaks_from_sealed_source_to_other_host(self) -> None:
        from app.approval_status import ApprovalCode
        from app.grant_unlocks import root_access_context
        self.executor.privileged.update(("demo-node-a", "demo-node-b"))
        sealed_root = SimpleNamespace(operation=SimpleNamespace(delegated=False),
                                       finish=lambda: None)
        observed = []
        async def admitted(*args, **_kwargs):
            observed.append((args[2], root_access_context.get()))
            if args[2] == "demo-node-a":
                root_access_context.set(sealed_root)
            # Legacy destination approval intentionally leaves ContextVar alone.
            return ApprovalCode.APPROVED_TIMED
        captures = []
        async def capture(relay, actor, req, *, precreated_id, roots):
            captures.extend(roots)
            identifier = relay.audit.start(
                actor, req.dest_server, "transfer", req.dest_path,
                req.story_id, req.operation_id, precreated_id=precreated_id,
            )
            relay.audit.finish(identifier, "succeeded")
            return {"status": "succeeded", "history_id": "file_" + identifier}
        with patch.object(mcp_gateway, "require_host_access", admitted), patch.object(
            mcp_gateway.HostRelayService, "transfer", capture,
        ):
            response, body = self.tool("transfer_file", self.request(
                source_privileged=True, dest_privileged=True,
            ))
        self.assertFalse(response.get("isError"), body)
        self.assertEqual([x[0] for x in observed], ["demo-node-a", "demo-node-b"])
        self.assertEqual([x[1] for x in observed], [None, None])
        self.assertIs(captures[0], sealed_root)
        self.assertIsNone(captures[1])

    def test_error_during_privileged_admission_releases_unlock(self) -> None:
        from app.approval_status import ApprovalCode, ApprovalRejected
        from app.grant_unlocks import root_access_context
        self.executor.privileged.add("demo-node-a")
        self.executor._sudo_passwords["demo-node-a"] = "fixture"
        class Unlock:
            class Op:
                delegated = False
            operation = Op()
            finished = 0
            def finish(self):
                if self.finished == 0:
                    self.finished += 1
        first = Unlock()
        calls = []
        async def guarded(*_args, **kwargs):
            calls.append(kwargs)
            if len(calls) == 1:
                root_access_context.set(first)
                return ApprovalCode.APPROVED_CONFIG
            raise ApprovalRejected(ApprovalCode.DENIED_CONFIG, "synthetic operator deny")
        with patch.object(mcp_gateway, "require_host_access", guarded):
            result, _ = self.tool("transfer_file", self.request(source_privileged=True))
        self.assertTrue(result.get("isError"))
        self.assertEqual(first.finished, 1)

if __name__ == "__main__":
    unittest.main()
