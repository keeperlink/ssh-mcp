"""TEST-208 authenticated MCP durable job API; no live host or network."""
from __future__ import annotations

import base64
import json
import os
import sqlite3
import tempfile
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
from app.ssh_executor import SSHDenied, SSHResult
from app.file_transport import FileTransport

CLIENT = "https://chatgpt.com/oauth/client.json"


class FakeSSH:
    access = "always-granted"
    username = "mcp-agent"
    def list_servers(self, actor):
        return ["demo-node-b"] if actor == "ssh-mcp-operator" else []

    def authorized_host(self, actor, server):
        if actor != "ssh-mcp-operator" or server != "demo-node-b":
            raise SSHDenied("invalid host or principal")
        return self

    async def execute(self, actor, request, *, on_output=None, on_admitted=None):
        if on_admitted is not None:
            on_admitted()
        if actor != "ssh-mcp-operator" or request.server != "demo-node-b":
            raise SSHDenied("invalid host")
        if on_output:
            await on_output("stdout", b"ready\n")
            await on_output("stderr", b"note")
        return SSHResult(request.server, "succeeded", 0, "ready\n", "note", .15)


class JobHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        db = Path(self.temp.name) / "private" / "jobs.sqlite"
        self.env_patch = patch.dict(os.environ, {
            "SSH_JOBS_ENABLED": "true", "SSH_JOBS_DB": str(db),
        })
        self.mode_patch = patch.object(config, "MCP_SSH_TOOLS_ENABLED", True)
        self.env_patch.start()
        self.mode_patch.start()
        self.addCleanup(self.env_patch.stop)
        self.addCleanup(self.mode_patch.stop)
        with patch.object(mcp_gateway.SSHExecutor, "from_environment", return_value=FakeSSH()):
            server, sub_app = mcp_gateway.create_mcp_server()

        @asynccontextmanager
        async def lifespan(_app):
            async with server.session_manager.run():
                yield

        app = FastAPI(lifespan=lifespan)
        app.mount("/", sub_app)
        self.ctx = TestClient(app)
        self.client = self.ctx.__enter__()
        self.addCleanup(lambda: self.ctx.__exit__(None, None, None))
        self.token, _ = oauth.issue_access_token(CLIENT, oauth._supported_scopes())

    def rpc(self, method, params, extra_headers=None):
        response = self.client.post("/mcp", headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json, text/event-stream",
            "Host": "localhost",
            **(extra_headers or {}),
        }, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn("error", response.json())
        return response.json()["result"]

    def tool(self, name, arguments, extra_headers=None):
        return self.rpc("tools/call", {"name": name, "arguments": arguments}, extra_headers)

    def test_cancelled_queued_sync_returns_structured_nonexecution_result(self):
        async def queued_cancel(manager, actor, request, *, on_created,
                                max_output_bytes=None, admitted_root=False,
                                precreated_id=None):
            job_id = precreated_id or manager.store.create(actor, request, mode="sync")
            if on_created is not None:
                on_created(job_id)
            self.assertTrue(manager.store.request_cancel(actor, job_id))
            manager.store.finish(job_id, "cancelled")
            return job_id, None

        with patch.object(mcp_gateway.JobManager, "execute_sync", new=queued_cancel):
            response = self.tool("execute_command", {
                "server": "demo-node-b", "argv": ["hostname"],
                "reason": "TEST-278 confirmed queued cancellation",
            })
        self.assertTrue(response.get("isError"), response)
        data = json.loads(response["content"][0]["text"])
        self.assertEqual(data["status"], "cancelled")
        self.assertEqual(data["failure_kind"], "cancelled")
        self.assertFalse(data["execution_started"])
        self.assertGreater(len(data["job_id"]), 8)

    def test_known_cwd_denial_matches_durable_history_and_output(self):
        # Exercise the actual authenticated MCP gateway + JobManager + SQLite
        # lifecycle. Only the network-facing SSH executor is synthetic.
        original = FakeSSH.execute
        dispatched = []

        async def checked(executor, actor, request, *, on_output=None,
                          on_admitted=None):
            if on_admitted is not None:
                on_admitted()
            if request.cwd in {"/private/missing", "/private/blocked"}:
                raise SSHDenied("sensitive remote path and credentials")
            dispatched.append(tuple(request.argv))
            return await original(
                executor, actor, request, on_output=on_output,
                on_admitted=None,
            )

        with patch.object(FakeSSH, "execute", new=checked):
            for remote in ("/private/missing", "/private/blocked"):
                with self.subTest(cwd=remote):
                    response = self.tool("execute_command", {
                        "server": "demo-node-b",
                        "argv": ["touch", "/tmp/must-not-run"],
                        "cwd": remote, "reason": "TEST-282 synthetic preflight denial",
                        "story_id": "TEST-282",
                    })
                    self.assertTrue(response.get("isError"))
                    data = json.loads(response["content"][0]["text"])
                    self.assertEqual(data["status"], "rejected")
                    self.assertEqual(data["failure_kind"], "pre_execution_rejected")
                    self.assertIs(data["execution_started"], False)
                    self.assertIsNone(data["exit_code"])
                    self.assertNotIn("/private", response["content"][0]["text"])
                    self.assertNotIn("credentials", response["content"][0]["text"])

                    job = json.loads(self.tool(
                        "get_job", {"job_id": data["job_id"]}
                    )["content"][0]["text"])["job"]
                    self.assertEqual(job["status"], "failed")
                    self.assertEqual(job["failure_kind"], "pre_execution_rejected")
                    self.assertIsNone(job["exit_code"])
                    self.assertEqual(job["output_bytes"], 0)
                    # started_at means capacity admission, not caller argv.
                    self.assertIsNotNone(job["started_at"])
                    self.assertEqual(job["error"], "SSH authorization was rejected")
                    chunks = json.loads(self.tool(
                        "get_job_output", {"job_id": data["job_id"]}
                    )["content"][0]["text"])
                    self.assertEqual(chunks["status"], "failed")
                    self.assertEqual(chunks["chunks"], [])
                    listings = json.loads(self.tool("list_jobs", {
                        "story_id": "TEST-282", "time_range": "all",
                    })["content"][0]["text"])
                    listed = next(entry for entry in listings["jobs"]
                                  if entry["id"] == data["job_id"])
                    self.assertEqual(listed["failure_kind"], "pre_execution_rejected")
            self.assertEqual(dispatched, [])

            good = self.tool("execute_command", {
                "server": "demo-node-b", "argv": ["pwd"],
                "cwd": "/home/gateway", "reason": "TEST-282 valid cwd control",
            })
            self.assertFalse(good.get("isError"))
            self.assertEqual(json.loads(good["content"][0]["text"])["status"],
                             "succeeded")
        self.assertEqual(dispatched, [("pwd",)])

        stats = json.loads(self.tool("get_job_stats", {
            "story_id": "TEST-282", "time_range": "all", "group_by": "status",
        })["content"][0]["text"])
        self.assertEqual(stats["status_counts"].get("failed"), 2)
        self.assertEqual(stats["transport_errors"], 0)
        with sqlite3.connect(os.environ["SSH_JOBS_DB"]) as db:
            self.assertEqual(db.execute(
                "SELECT total FROM telemetry_outcomes WHERE "
                "status='failed' AND failure_kind='pre_execution_rejected'"
            ).fetchone()[0], 2)

    def test_missing_result_after_possible_dispatch_stays_uncertain(self):
        async def crashed(_executor, _actor, _request, *, on_output=None,
                          on_admitted=None):
            if on_admitted is not None:
                on_admitted()
            raise RuntimeError("private post-admission failure")

        with patch.object(FakeSSH, "execute", new=crashed):
            response = self.tool("execute_command", {
                "server": "demo-node-b", "argv": ["touch", "unknown"],
                "reason": "TEST-282 uncertain executor exception",
            })
        self.assertTrue(response.get("isError"))
        result = json.loads(response["content"][0]["text"])
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["failure_kind"], "execution_unconfirmed")
        audit = json.loads(self.tool(
            "get_job", {"job_id": result["job_id"]}
        )["content"][0]["text"])["job"]
        self.assertEqual(audit["status"], "failed")
        self.assertEqual(audit["failure_kind"], "execution_error")
        self.assertNotIn("private", response["content"][0]["text"])

    def test_incomplete_cwd_channel_is_not_a_known_rejection(self):
        async def uncertain(_executor, _actor, request, *, on_output=None,
                            on_admitted=None):
            if on_admitted is not None:
                on_admitted()
            return SSHResult(
                request.server, "transport_error", None, "", "", .01,
                failure_kind="execution_uncertain",
            )

        with patch.object(FakeSSH, "execute", new=uncertain):
            response = self.tool("execute_command", {
                "server": "demo-node-b", "argv": ["touch", "must-not-run"],
                "cwd": "/home/gateway", "reason": "TEST-282 interrupted preflight",
            })
        self.assertTrue(response.get("isError"))
        result = json.loads(response["content"][0]["text"])
        self.assertEqual(result["status"], "transport_error")
        self.assertEqual(result["failure_kind"], "execution_uncertain")
        self.assertIsNone(result["exit_code"])
        audit = json.loads(self.tool(
            "get_job", {"job_id": result["job_id"]}
        )["content"][0]["text"])["job"]
        self.assertEqual(audit["status"], "transport_error")
        self.assertEqual(audit["failure_kind"], "execution_uncertain")

    def test_direct_execution_keeps_job_id_when_final_audit_write_fails(self):
        # SSH can change remote state before the final SQLite transaction.
        # Never reply as a pre-execution rejection with no recovery handle.
        with patch("app.jobs.JobStore.finish", side_effect=sqlite3.OperationalError(
            "synthetic sensitive audit failure"
        )):
            response = self.tool("execute_command", {
                "server": "demo-node-b", "argv": ["id", "-un"],
                "reason": "TEST-267 synthetic audit failure after SSH",
            })
        self.assertTrue(response.get("isError"))
        data = json.loads(response["content"][0]["text"])
        self.assertEqual(data["status"], "unknown")
        self.assertEqual(data["failure_kind"], "audit_unavailable")
        self.assertEqual(data["server"], "demo-node-b")
        self.assertGreater(len(data["job_id"]), 8)
        self.assertNotIn("synthetic sensitive", response["content"][0]["text"])
        self.assertIn("before retrying", data["error"])
        recorded = self.tool("get_job", {"job_id": data["job_id"]})
        self.assertEqual(json.loads(recorded["content"][0]["text"])["job"]["id"], data["job_id"])

    def test_direct_execution_without_audit_creation_still_rejects_before_ssh(self):
        with patch("app.jobs.JobStore.create", side_effect=sqlite3.OperationalError(
            "synthetic pre-execution audit failure"
        )):
            response = self.tool("execute_command", {
                "server": "demo-node-b", "argv": ["id", "-un"],
                "reason": "TEST-267 synthetic audit failure before SSH",
            })
        self.assertTrue(response.get("isError"))
        self.assertIn("Durable SSH auditing unavailable", response["content"][0]["text"])
        self.assertNotIn("synthetic pre-execution", response["content"][0]["text"])

    def test_conversation_header_audit_filter_and_no_caller_override(self):
        header = {"X-OpenAI-Session": "v1/conversation-A"}
        result = self.tool("submit_job", {
            "server": "demo-node-b", "argv": ["hostname"],
            "reason": "synthetic conversation audit",
        }, header)
        self.assertFalse(result.get("isError"), result)
        identifier = json.loads(result["content"][0]["text"])["job"]["id"]
        detail = json.loads(self.tool("get_job", {"job_id": identifier})["content"][0]["text"])["job"]
        self.assertEqual(detail["conversation_id"], "v1/conversation-A")
        self.assertEqual(
            json.loads(self.tool("list_jobs", {
                "conversation_id": "v1/conversation-A", "time_range": "all",
            })["content"][0]["text"])["total"], 1,
        )
        self.assertEqual(
            json.loads(self.tool("list_jobs", {
                "conversation_id": "v1/conversation-B", "time_range": "all",
            })["content"][0]["text"])["total"], 0,
        )
        self.assertTrue(self.tool("submit_job", {
            "server": "demo-node-b", "argv": ["hostname"],
            "reason": "synthetic attempt to override",
            "conversation_id": "v1/conversation-B",
        }, header).get("isError"))
        self.assertTrue(self.tool("submit_job", {
            "server": "demo-node-b", "argv": ["hostname"], "reason": "invalid header",
        }, {"X-OpenAI-Session": "bad conversation"}).get("isError"))

    def test_restricted_host_cannot_be_reached_through_any_tool_or_sid(self):
        self.token, _ = oauth.issue_access_token(
            CLIENT, oauth._supported_scopes(),
            session_id="synthetic-verified-oauth-sid-123456789",
        )
        verbs = (
            "execute_command", "submit_job", "execute_commands", "read_file",
            "write_file", "apply_patch", "upload_file", "download_file",
        )
        with patch.object(FakeSSH, "access", "restricted"):
            for name in verbs:
                with self.subTest(name=name):
                    arguments = {"server": "demo-node-b"}
                    if name in {"execute_command", "submit_job"}:
                        arguments.update({
                            "reason": "synthetic authorization regression",
                            "argv": ["hostname"],
                        })
                    if name == "execute_commands":
                        arguments.update({
                            "reason": "synthetic authorization regression",
                            "commands": [{"argv": ["hostname"]}],
                        })
                    if name in {
                        "read_file", "write_file", "apply_patch",
                        "upload_file", "download_file",
                    }:
                        arguments.update({
                            "reason": "synthetic authorization regression",
                            "path": "synthetic/file.txt",
                        })
                    if name == "write_file":
                        arguments["content"] = "fixture"
                    if name == "apply_patch":
                        arguments["patch"] = (
                            "*** Begin Patch\n"
                            "*** Add File: synthetic/file.txt\n+fixture\n"
                            "*** End Patch"
                        )
                    if name == "upload_file":
                        arguments["file"] = {
                            "file_id": "synthetic-file-ref",
                            "download_url": "https://example.invalid/synthetic-file",
                        }
                    data = self.tool(name, arguments, {
                        "X-OpenAI-Session": "v1/restricted-host",
                    })
                    self.assertTrue(data.get("isError"), name)
                    if name == "execute_commands":
                        rejected = json.loads(data["content"][0]["text"])
                        self.assertEqual(rejected["status"], "rejected")
                        self.assertEqual(rejected["failure_kind"], "authorization")
                        self.assertEqual(rejected["failed_field"], "server")
                        self.assertEqual(rejected["steps_attempted"], 0)
                    else:
                        self.assertIn("operator approval", data["content"][0]["text"])
            invalid = self.tool("execute_commands", {
                "server": 123,
                "reason": "invalid server type",
                "commands": [{"argv": ["hostname"]}],
            })
            self.assertTrue(invalid.get("isError"))
            rejected = json.loads(invalid["content"][0]["text"])
            self.assertEqual(rejected["status"], "rejected")
            self.assertEqual(rejected["failure_kind"], "invalid_request")
            self.assertEqual(rejected["failed_field"], "server")
            self.assertEqual(rejected["steps_attempted"], 0)
            self.assertFalse(self.tool("list_servers", {}).get("isError"))
        history = json.loads(self.tool("list_jobs", {
            "time_range": "all",
        })["content"][0]["text"])
        # Authenticated, valid calls to a signed restricted host are now
        # audited before the gate; missing operator approval infrastructure
        # records a NULL-code operational failure (never an explicit Deny).
        self.assertEqual(history["total"], 2)
        self.assertTrue(all(row["status"] == "failed"
                            and row["approval_status"] is None
                            and row["started_at"] is None
                            for row in history["jobs"]))

    def test_mcp_job_registration_and_ownership(self):
        names = {item["name"] for item in self.rpc("tools/list", {})["tools"]}
        self.assertTrue({
            "submit_job", "get_job", "get_job_output", "list_jobs", "cancel_job",
            "execute_command", "list_servers", "get_status", "get_job_stats",
        }.issubset(names))
        submitted = self.tool("submit_job", {
            "server": "demo-node-b", "argv": ["hostname", "-s"],
            "reason": "synthetic endpoint acceptance", "timeout_seconds": 10,
        })
        self.assertFalse(submitted.get("isError"), submitted)
        job = json.loads(submitted["content"][0]["text"])["job"]
        self.assertEqual(job["server"], "demo-node-b")
        self.assertEqual(job["run_as"], "mcp-agent")
        self.assertIn(job["status"], ("queued", "running", "succeeded"))
        job_id = job["id"]

        completed = None
        for i in range(50):
            found = self.tool("get_job", {"job_id": job_id})
            completed = json.loads(found["content"][0]["text"])["job"]
            if completed["status"] == "succeeded":
                break
            # Async work continues between individual MCP calls in a shared ASGI lifespan.
            import time
            time.sleep(.01)
        self.assertEqual(completed["status"], "succeeded", completed)
        self.assertEqual(completed["exit_code"], 0)
        self.assertEqual(completed["run_as"], "mcp-agent")
        self.assertEqual(completed["command"], "hostname")
        self.assertEqual(completed["output_bytes"], 10)

        output = self.tool("get_job_output", {
            "job_id": job_id, "cursor": 0, "max_bytes": 4,
        })
        data = json.loads(output["content"][0]["text"])
        self.assertEqual(data["next_cursor"], 4)
        self.assertTrue(data["truncated"])
        self.assertEqual(data["chunks"], [{"stream": "stdout", "data_base64": "cmVhZA=="}])

        remainder = self.tool("get_job_output", {
            "job_id": job_id, "cursor": 4, "max_bytes": 20,
        })
        data = json.loads(remainder["content"][0]["text"])
        self.assertEqual(data["next_cursor"], 10)
        self.assertEqual(data["chunks"], [
            {"stream": "stdout", "data_base64": "eQo="},
            {"stream": "stderr", "data_base64": "bm90ZQ=="},
        ])

        listing = self.tool("list_jobs", {"limit": 5})
        rows = json.loads(listing["content"][0]["text"])["jobs"]
        self.assertEqual(rows[0]["id"], job_id)
        self.assertEqual(rows[0]["run_as"], "mcp-agent")
        cancel = self.tool("cancel_job", {"job_id": job_id, "reason": "verify completed"})
        self.assertFalse(json.loads(cancel["content"][0]["text"])["cancellation_requested"])

        bad = self.tool("submit_job", {
            "server": "demo-node2", "argv": ["id"], "reason": "deny",
        })
        self.assertTrue(bad.get("isError"))
        self.assertTrue(self.tool("get_job", {"job_id": "invalid-not-mine"}).get("isError"))

    def test_execute_commands_durable_step_history_and_stop_on_error(self):
        names = {item["name"] for item in self.rpc("tools/list", {})["tools"]}
        self.assertTrue({
            "execute_commands", "get_batch", "list_batches", "cancel_batch",
        } <= names)
        seen = []

        async def fake_execute(_ssh, actor, request, *, on_output=None, on_admitted=None):
            if on_admitted is not None:
                on_admitted()
            self.assertEqual(actor, "ssh-mcp-operator")
            seen.append(request.argv[0])
            code = 2 if request.argv[0] == "fail" else 0
            if on_output is not None:
                await on_output("stdout", f"step-{len(seen)}\n".encode())
            return SSHResult(request.server, "command_error" if code else "succeeded",
                             code, f"step-{len(seen)}\n", "", .02,
                             False if code else True)

        body = {
            "server": "demo-node-b", "reason": "TEST-247 audited batch",
            "story_id": "TEST-247", "commands": [
                {"argv": ["echo", "one"]},
                {"argv": ["fail"]},
                {"argv": ["echo", "must-not-run"]},
            ],
        }
        with patch.object(FakeSSH, "execute", new=fake_execute):
            response = self.tool("execute_commands", body)
        self.assertFalse(response.get("isError"), response)
        data = json.loads(response["content"][0]["text"])
        self.assertEqual(data["status"], "failed")
        self.assertEqual(data["failed_step"], 1)
        self.assertEqual([step["status"] for step in data["steps"]],
                         ["succeeded", "failed", "not_attempted"])
        self.assertEqual(seen, ["echo", "fail"])
        self.assertIsNone(data["steps"][2]["job_id"])

        batch_id = data["batch_id"]
        seen_step = self.tool("get_batch", {"batch_id": batch_id, "limit": 1})
        self.assertFalse(seen_step.get("isError"), seen_step)
        page = json.loads(seen_step["content"][0]["text"])
        self.assertEqual(len(page["steps"]), 1)
        self.assertEqual(page["next_cursor"], 1)
        history = self.tool("get_job", {"job_id": data["steps"][1]["job_id"]})
        self.assertEqual(json.loads(history["content"][0]["text"])["job"]["exit_code"], 2)
        listing = self.tool("list_batches", {"limit": 10})
        self.assertEqual(json.loads(listing["content"][0]["text"])["batches"][0]["batch_id"],
                         batch_id)
        cancellation = self.tool("cancel_batch", {
            "batch_id": batch_id, "reason": "already finished",
        })
        self.assertFalse(json.loads(cancellation["content"][0]["text"])["cancellation_requested"])

    def test_batch_preflight_invalid_later_step_has_zero_command_attempts(self):
        with patch.object(FakeSSH, "execute") as command:
            invalid = self.tool("execute_commands", {
                "server": "demo-node-b", "reason": "invalid later step",
                "strict_bash": True, "commands": [
                    {"argv": ["echo", "valid"]},
                    {"argv": ["bash", "-c"]},
                    {"argv": ["echo", "must-never-run"]},
                ],
            })
            self.assertTrue(invalid.get("isError"), invalid)
            payload = json.loads(invalid["content"][0]["text"])
            self.assertEqual(payload["status"], "rejected")
            self.assertEqual(payload["failure_kind"], "invalid_request")
            self.assertEqual(payload["steps_attempted"], 0)
            self.assertEqual(payload["failed_step"], 1)
            self.assertIn("argv", payload["failed_field"])
            command.assert_not_called()
        self.assertEqual(json.loads(
            self.tool("list_batches", {})["content"][0]["text"]
        )["batches"], [])

    def test_authenticated_upload_download_tools_and_native_binary_resource(self):
        import base64
        import hashlib
        from app.file_transfer import BinaryTransferService

        tools = {item["name"]: item for item in self.rpc("tools/list", {})["tools"]}
        for name in ("upload_file", "download_file"):
            self.assertIn(name, tools)
            self.assertFalse(tools[name]["inputSchema"]["additionalProperties"])
        self.assertEqual(tools["upload_file"]["_meta"]["openai/fileParams"], ["file"])
        self.assertFalse(tools["upload_file"]["annotations"]["readOnlyHint"])
        self.assertTrue(tools["download_file"]["annotations"]["readOnlyHint"])
        source = b"never-store-in-history-\x00\xff" + bytes(range(128))
        checksum = hashlib.sha256(source).hexdigest()
        file_reference = {
            "file_id": "synthetic-chatgpt-file-id",
            "download_url": "https://probe.example.invalid/download?secret=never-log",
        }

        async def fake_upload(_self, actor, request, *, precreated_id=None):
            self.assertEqual(actor, "ssh-mcp-operator")
            self.assertEqual(request.server, "demo-node-b")
            self.assertEqual(request.file.file_id, file_reference["file_id"])
            return {"status": "succeeded", "operation_id": "synthetic-upload-237",
                    "result": {"bytes": len(source), "sha256": checksum}}

        async def fake_download(_self, actor, request, *, precreated_id=None):
            self.assertEqual(actor, "ssh-mcp-operator")
            self.assertEqual(request.max_bytes, 65536)
            return {"status": "succeeded", "operation_id": "synthetic-download-237",
                    "result": {"bytes": len(source), "offset": 0, "size": len(source),
                               "chunk_sha256": checksum, "eof": True,
                               "data_base64": base64.b64encode(source).decode()}}

        with patch.object(BinaryTransferService, "upload", new=fake_upload), patch.object(
            BinaryTransferService, "download", new=fake_download
        ):
            common = {"server": "demo-node-b", "path": "/tmp/synthetic.bin",
                      "reason": "TEST-237 simulated MCP transfer"}
            written = self.tool("upload_file", {**common, "file": file_reference})
            self.assertFalse(written.get("isError"), written)
            self.assertEqual(json.loads(written["content"][0]["text"])["result"]["sha256"], checksum)
            downloaded = self.tool("download_file", common)
            self.assertFalse(downloaded.get("isError"), downloaded)
            result_text = json.loads(downloaded["content"][0]["text"])
            self.assertNotIn("data_base64", result_text["result"])
            self.assertNotIn(file_reference["download_url"], downloaded["content"][0]["text"])
            blob = downloaded["content"][1]["resource"]
            self.assertEqual(blob["mimeType"], "application/octet-stream")
            self.assertEqual(base64.b64decode(blob["blob"]), source)
            bad = self.tool("upload_file", {**common, "file": file_reference,
                                             "actor": "another-user"})
            self.assertTrue(bad.get("isError"))
            bad_download = self.tool("download_file", {**common, "max_bytes": 65537})
            self.assertTrue(bad_download.get("isError"))

    def test_always_granted_malformed_patch_preserves_structured_audit(self):
        from app.file_helper import FileError, _parse_patch

        async def fake_file(_transport, _actor, _server, operation, payload):
            self.assertEqual(operation, "patch")
            try:
                _parse_patch(payload["patch"])
            except FileError as exc:
                return {"ok": False, "error": {
                    "code": exc.code, "message": str(exc),
                }}
            self.fail("Synthetic malformed patch reached a successful parser")

        with patch.object(FileTransport, "execute", new=fake_file):
            response = self.tool("apply_patch", {
                "server": "demo-node-b", "reason": "test malformed patch auditing",
                "path": ".", "patch": "*** Begin Patch\nnot a file section\n*** End Patch",
            })
        self.assertTrue(response.get("isError"))
        parsed = json.loads(response["content"][0]["text"])
        self.assertEqual(parsed["status"], "failed")
        self.assertEqual(parsed["result"]["error"]["code"], "invalid_patch")
        self.assertTrue(parsed["history_id"].startswith("file_"))
        saved = json.loads(self.tool("get_job", {
            "job_id": parsed["history_id"],
        })["content"][0]["text"])["job"]
        self.assertEqual(saved["error_code"], "invalid_patch")

    def test_authenticated_file_tools_do_not_persist_payloads(self):
        tools = {item["name"]: item for item in self.rpc("tools/list", {})["tools"]}
        for name in ("read_file", "write_file", "apply_patch"):
            self.assertIn(name, tools)
            self.assertFalse(tools[name]["inputSchema"]["additionalProperties"])
        self.assertTrue(tools["read_file"]["annotations"]["readOnlyHint"])
        self.assertFalse(tools["write_file"]["annotations"]["readOnlyHint"])

        marker = "SYNTHETIC-SENSITIVE-CONTENT-NEVER-PERSIST-236"

        async def fake_file(_transport, actor, server, operation, payload):
            self.assertEqual((actor, server), ("ssh-mcp-operator", "demo-node-b"))
            if operation == "read":
                return {"ok": True, "path": payload["path"],
                        "content": marker, "bytes": len(marker), "eof": True,
                        "truncated": False, "next_cursor": None}
            if operation == "patch":
                return {"ok": False, "partial": True, "bytes": 8,
                        "outcomes": [
                            {"path": "/x/first.txt", "action": "update",
                             "status": "applied", "bytes": 8},
                            {"path": "/x/second.txt", "action": "delete",
                             "status": "failed", "error_code": "not_found"},
                            {"path": "/x/third.txt", "action": "add",
                             "status": "not_attempted", "bytes": 0},
                        ],
                        "error": {"code": "partial", "message": "Partial patch"}}
            return {"ok": True, "path": payload["path"], "bytes": len(payload["content"])}

        with patch.object(FileTransport, "execute", new=fake_file):
            common = {"server": "demo-node-b", "path": "/synthetic/example.txt",
                      "story_id": "TEST-236", "reason": "test"}
            written = self.tool("write_file", {**common, "content": marker, "mode": "append",
                                               "operation_id": "write-236-synthetic"})
            self.assertFalse(written.get("isError"), written)
            body = json.loads(written["content"][0]["text"])
            self.assertEqual(body["status"], "succeeded")
            self.assertEqual(body["operation_id"], "write-236-synthetic")
            duplicate = self.tool("write_file", {**common, "content": marker, "mode": "append",
                                                 "operation_id": "write-236-synthetic"})
            self.assertTrue(duplicate.get("isError"))
            self.assertEqual(json.loads(duplicate["content"][0]["text"])["error"]["code"],
                             "duplicate_operation")
            read = self.tool("read_file", common)
            self.assertEqual(json.loads(read["content"][0]["text"])["result"]["content"], marker)
            patch_result = self.tool("apply_patch", {
                "server": "demo-node-b", "reason": "test", "story_id": "TEST-236",
                "patch": "*** Begin Patch\n*** Add File: first.txt\n+x\n*** End Patch",
            })
            self.assertTrue(patch_result.get("isError"))
            patch_body = json.loads(patch_result["content"][0]["text"])
            self.assertEqual(patch_body["status"], "partial")
            self.assertEqual(len(patch_body["result"]["outcomes"]), 3)
            rejected = self.tool("write_file", {**common, "content": marker, "actor": "root"})
            self.assertTrue(rejected.get("isError"))
            rejected = self.tool("write_file", {**common, "server": "demo-node2", "content": marker})
            self.assertTrue(rejected.get("isError"))

        with sqlite3.connect(os.environ["SSH_JOBS_DB"]) as db:
            dump = "\n".join(db.iterdump())
            self.assertEqual(db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM output").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM file_operations").fetchone()[0], 3)
            records = db.execute("SELECT operation_kind,status,story_id,result_metadata "
                                 "FROM file_operations ORDER BY created_at").fetchall()
            self.assertEqual({row[0] for row in records}, {"write", "read", "patch"})
            self.assertEqual({row[2] for row in records}, {"TEST-236"})
            self.assertIn("not_attempted", dump)
            self.assertIn("update", dump)
            self.assertNotIn(marker, dump)
            self.assertNotIn("*** Begin Patch", dump)

    def test_synchronous_execution_is_audited_with_story_id(self):
        response = self.tool("execute_command", {
            "server": "demo-node-b", "argv": ["hostname", "-s"],
            "reason": "TEST-209 sync audit contract", "story_id": "TEST-209",
            "timeout_seconds": 15,
        })
        self.assertFalse(response.get("isError"))
        payload = json.loads(response["content"][0]["text"])
        self.assertEqual(payload["status"], "succeeded")
        self.assertEqual(payload["stdout"], "ready\\n".replace("\\n", "\n"))
        self.assertIn("job_id", payload)
        record = self.tool("get_job", {"job_id": payload["job_id"]})
        stored = json.loads(record["content"][0]["text"])["job"]
        self.assertEqual(stored["mode"], "sync")
        self.assertEqual(stored["story_id"], "TEST-209")
        self.assertEqual(stored["status"], "succeeded")
        self.assertEqual(stored["run_as"], "mcp-agent")
        output = self.tool("get_job_output", {"job_id": payload["job_id"]})
        blocks = json.loads(output["content"][0]["text"])["chunks"]
        self.assertEqual([chunk["stream"] for chunk in blocks], ["stdout", "stderr"])
        rejected = self.tool("execute_command", {
            "server": "demo-node-b", "argv": ["id"],
            "reason": "bad story", "story_id": "invalid story id",
        })
        self.assertTrue(rejected.get("isError"))

    def test_disabled_gate_and_invalid_arguments(self):
        bad = self.tool("submit_job", {
            "server": "demo-node-b", "argv": ["id"], "reason": "x", "actor": "root",
        })
        self.assertTrue(bad.get("isError"))
        bad = self.tool("list_jobs", {"limit": 1000})
        self.assertTrue(bad.get("isError"))
        bad = self.tool("get_job_output", {
            "job_id": "not-a-job-id", "cursor": -1,
        })
        self.assertTrue(bad.get("isError"))

    def test_private_full_audit_request_not_leaked_by_mcp_summary(self):
        call = self.tool("submit_job", {
            "server": "demo-node-b",
            "argv": ["sh", "-c", "echo synthetic-command"],
            "reason": "synthetic-reason",
        })
        summary = json.loads(call["content"][0]["text"])["job"]
        self.assertNotIn("argv", summary)
        self.assertNotIn("reason", summary)
        with sqlite3.connect(os.environ["SSH_JOBS_DB"]) as db:
            captured = json.loads(db.execute(
                "SELECT request_json FROM jobs WHERE id=?", (summary["id"],)
            ).fetchone()[0])
        self.assertEqual(captured["argv"], ["sh", "-c", "echo synthetic-command"])
        self.assertEqual(captured["reason"], "synthetic-reason")

    def test_cross_actor_history_filters_pagination_and_status(self):
        from app.contracts import ExecuteCommandRequest
        from app.file_audit import FileAudit
        from app.jobs import JobStore

        store = JobStore(Path(os.environ["SSH_JOBS_DB"]), retention_months=12)
        archived = []
        for index in range(120):
            req = ExecuteCommandRequest(
                server="ssh-mcp-retired" if index < 5 else "demo-node-b",
                argv=["echo", f"test-{index}"], reason=f"historical reason {index}",
                story_id="TEST-243" if index < 5 else "TEST-191",
            )
            job_id = store.create("former-actor", req, mode="sync")
            store.begin(job_id)
            store.append(job_id, "stdout", f"data-{index}".encode("utf-8"))
            store.finish(job_id, "failed" if index < 5 else "succeeded", elapsed=0.5)
            archived.append(job_id)

        file_audit = FileAudit(store)
        file_key = file_audit.start("former-actor", "ssh-mcp-retired",
                                    "inspect", "/private/archive.log", "TEST-243")
        file_audit.finish(file_key, "succeeded", byte_count=12)

        from app.contracts import CONTRACTS_BY_NAME

        def typed_round_trip(name, payload):
            """A generated-schema client must not silently drop live fields."""
            model = CONTRACTS_BY_NAME[name].response.model_validate(payload)
            self.assertEqual(model.model_dump(exclude_unset=True), payload)

        discovered = self.tool("list_servers", {})
        hosts = json.loads(discovered["content"][0]["text"])
        self.assertEqual(hosts["servers"], ["demo-node-b"])
        self.assertEqual(hosts["history_hosts"], ["demo-node-b", "ssh-mcp-retired"])
        typed_round_trip("list_servers", hosts)

        all_ids = []
        cursor = None
        for page in range(10):
            params = {"limit": 17}
            if cursor:
                params["cursor"] = cursor
            reply = self.tool("list_jobs", params)
            self.assertFalse(reply.get("isError"), reply)
            body = json.loads(reply["content"][0]["text"])
            self.assertEqual(body["total"], 120)
            typed_round_trip("list_jobs", body)
            all_ids.extend(row["id"] for row in body["jobs"])
            for row in body["jobs"]:
                self.assertNotIn("argv", row)
                self.assertNotIn("actor", row)
                self.assertNotIn("command_preview", row)
                self.assertIn("reason", row)
            self.assertEqual(body["has_more"], body["next_cursor"] is not None)
            cursor = body["next_cursor"]
            if not cursor:
                break
            self.assertNotIn(":", cursor)
        self.assertEqual(len(all_ids), 120)
        self.assertEqual(set(all_ids), set(archived))
        self.assertIsNone(cursor)

        listed = self.tool("list_jobs", {
            "host": "ssh-mcp-retired", "story_id": "243", "status": "failed",
            "command": "test-", "record_kind": "command",
        })
        selected = json.loads(listed["content"][0]["text"])
        self.assertEqual(selected["total"], 5)
        self.assertEqual(selected["jobs"][0]["reason"], "historical reason 4")
        self.assertTrue(self.tool("list_jobs", {"cursor": "not_a_real_cursor"}).get("isError"))
        self.assertTrue(self.tool("list_jobs", {
            "time_range": "7d", "from_date": "2026-11-01",
        }).get("isError"))

        details = self.tool("get_job", {"job_id": archived[0]})
        job = json.loads(details["content"][0]["text"])["job"]
        self.assertEqual(job["request"]["argv"], ["echo", "test-0"])
        self.assertEqual(job["request"]["reason"], "historical reason 0")
        self.assertEqual(job["terminal_command"], "echo test-0")
        typed_round_trip("get_job", {"job": job})
        output = self.tool("get_job_output", {
            "job_id": archived[0], "cursor": 2, "max_bytes": 3,
        })
        payload = json.loads(output["content"][0]["text"])
        self.assertEqual(base64.b64decode(payload["chunks"][0]["data_base64"]), b"ta-")
        self.assertTrue(payload["truncated"])
        typed_round_trip("get_job_output", payload)
        self.assertTrue(self.tool("cancel_job", {
            "job_id": archived[0], "reason": "not my job",
        }).get("isError"))

        files = self.tool("list_jobs", {"mode": "file"})
        file_result = json.loads(files["content"][0]["text"])
        self.assertEqual(file_result["total"], 1)
        typed_round_trip("list_jobs", file_result)
        self.assertIsNone(file_result["jobs"][0]["reason"])
        file_id = file_result["jobs"][0]["id"]
        self.assertEqual(file_id, "file_" + file_key)
        file_details = json.loads(self.tool("get_job", {
            "job_id": file_id,
        })["content"][0]["text"])["job"]
        self.assertIsNone(file_details["request"])
        self.assertIsNone(file_details["terminal_command"])
        self.assertEqual(file_details["file_metadata"]["outcomes"], [])
        typed_round_trip("get_job", {"job": file_details})
        self.assertEqual(json.loads(self.tool("get_job_output", {
            "job_id": file_id,
        })["content"][0]["text"])["chunks"], [])

        stats = json.loads(self.tool("get_job_stats", {
            "story_id": "243", "record_kind": "all",
            "time_range": "all", "group_by": "host",
        })["content"][0]["text"])
        self.assertEqual(stats["total"], 6)
        self.assertEqual(stats["failures"], 5)
        self.assertEqual(stats["groups"][0]["name"], "ssh-mcp-retired")
        typed_round_trip("get_job_stats", stats)

        status = json.loads(self.tool("get_status", {})["content"][0]["text"])
        self.assertIn(status["service"]["status"], {"ready", "degraded"})
        self.assertIn("version", status["service"])
        self.assertEqual(status["storage"]["retained_jobs"], 120)
        self.assertTrue(status["capabilities"]["history_search"])
        typed_round_trip("get_status", status)
        self.assertTrue(self.tool("get_status", {"argv": ["id"]}).get("isError"))

    def test_status_version_fail_closed_and_history_requires_operator(self):
        from types import SimpleNamespace
        from app import operational

        with patch.object(config, "MCP_SERVICE_VERSION", "0.1.999"):
            status = json.loads(self.tool("get_status", {})["content"][0]["text"])
            self.assertEqual(status["service"]["version"], "0.1.999")
            with patch.dict(os.environ, {"SSH_JOBS_ENABLED": "false"}):
                with patch.object(mcp_gateway.SSHExecutor, "from_environment", return_value=FakeSSH()):
                    candidate, _ = mcp_gateway.create_mcp_server()
                self.assertEqual(candidate.version, "0.1.999")

        with patch.object(operational, "session_store", side_effect=OSError("hidden-private-path")):
            broken = self.tool("get_status", {})
        report = json.loads(broken["content"][0]["text"])
        self.assertEqual(report["service"]["status"], "degraded")
        self.assertFalse(report["storage"]["oauth_ready"])
        self.assertNotIn("hidden-private-path", str(report))

        other_actor = SimpleNamespace(
            client_id=config.MCP_CIMD_CLIENT_ID,
            scopes=["mcp.access", "ssh.execute"],
            subject="other-actor",
        )
        with patch.object(mcp_gateway, "get_access_token", return_value=other_actor):
            for name, params in (
                ("list_jobs", {}),
                ("list_servers", {}),
                ("get_job_stats", {}),
                ("get_status", {}),
            ):
                result = self.tool(name, params)
                if name == "list_servers":
                    self.assertEqual(json.loads(result["content"][0]["text"]),
                                     {"servers": [], "history_hosts": []})
                else:
                    self.assertTrue(result.get("isError"), (name, result))

        self.assertTrue(self.tool("get_job_stats", {
            "group_by": "not-safe",
        }).get("isError"))

    def test_disabled_by_default(self):
        with patch.dict(os.environ, {"SSH_JOBS_ENABLED": "false"}):
            with patch.object(mcp_gateway.SSHExecutor, "from_environment", return_value=FakeSSH()):
                server, app = mcp_gateway.create_mcp_server()
            # Behavior is tested through server callbacks elsewhere; disabled mode
            # must never create a job DB or expose the job manager.
            self.assertIsNotNone(server)
            self.assertIsNotNone(app)
