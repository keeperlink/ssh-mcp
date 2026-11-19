"""Inactive TEST-206 contract validation (no SSH, filesystem or network calls)."""
from __future__ import annotations

import json
import unittest

from pydantic import ValidationError

from app.contracts import (
    CONTRACT_VERSION,
    CONTRACTS,
    CONTRACTS_BY_NAME,
    CancelJobRequest,
    CancelBatchRequest,
    ExecuteCommandsRequest,
    ExecuteCommandsResponse,
    GetBatchRequest,
    GetBatchResponse,
    ListBatchesRequest,
    ListBatchesResponse,
    CancelBatchResponse,
    ExecuteCommandRequest,
    GetJobOutputRequest,
    GetJobStatsRequest,
    JobSummary,
    ListJobsRequest,
    ListServersRequest,
    ReadFileRequest,
    contract_document,
    validate_request,
)
from app.mcp_gateway import TOOLS, SSH_TOOLS, JOB_TOOLS, BATCH_TOOLS, handle_tool


class ContractTests(unittest.TestCase):
    def test_agent_command_tool_guidance_uses_structured_parameters(self):
        command_tools = {
            tool.name: tool
            for tool in (*SSH_TOOLS, *JOB_TOOLS, *BATCH_TOOLS)
        }
        for name in ("execute_command", "submit_job", "execute_commands"):
            with self.subTest(tool=name):
                description = command_tools[name].description
                for field in ("argv", "cwd", "reason", "story_id", "strict_bash"):
                    self.assertIn(field, description)
                self.assertIn("echo", description)
                self.assertIn("bash -c/-lc", description)
        single = command_tools["execute_command"].description
        self.assertIn("Durable job audit is required", single)
        for name in ("execute_command", "submit_job", "execute_commands"):
            self.assertEqual(command_tools[name].input_schema["properties"]["privileged"]["default"], False)
        self.assertIn("exit_accepted", single)
        self.assertIn("isError=false", single)
        self.assertIn("command_error", single)
        self.assertIn("success_exit_codes", single)
        from app import config
        self.assertIn(f"Timeout max is {config.SSH_MAX_TIMEOUT_SECONDS} seconds.", single)
        batch = command_tools["execute_commands"].description
        self.assertIn("separate", batch)
        self.assertIn("do not persist", batch)
        self.assertEqual(
            command_tools["execute_command"].input_schema["properties"]["cwd"]["default"],
            None,
        )

    def test_versioned_contracts_are_complete_and_stable(self):
        expected = [
            "list_servers",
            "get_status",
            "execute_command",
            "get_job",
            "get_job_output",
            "list_jobs",
            "get_job_stats",
            "cancel_job",
            "execute_commands",
            "get_batch",
            "list_batches",
            "cancel_batch",
            "read_file", "write_file", "apply_patch",
            "upload_file", "download_file",
        ]
        self.assertEqual([t.name for t in CONTRACTS], expected)
        self.assertEqual(len(CONTRACTS_BY_NAME), len(expected))
        self.assertEqual(CONTRACT_VERSION, "2.0")
        self.assertEqual([t.read_only for t in CONTRACTS], [
            True, True, False, True, True, True, True, False,
            False, True, True, False,
            True, False, False, False, True,
        ])
        doc = contract_document()
        self.assertEqual(doc["status"], "active")
        self.assertEqual(doc["contract_version"], "2.0")
        self.assertEqual([t["name"] for t in doc["tools"]], expected)
        self.assertEqual(json.loads(json.dumps(doc)), doc)

    def test_published_response_schemas_include_history_and_analytics_fields(self):
        schemas = {
            tool["name"]: tool["outputSchema"] for tool in contract_document()["tools"]
        }
        detail = schemas["get_job"]
        self.assertIn("JobDetail", detail["$defs"])
        self.assertTrue({"request", "terminal_command", "file_metadata"} <=
                        set(detail["$defs"]["JobDetail"]["properties"]))
        self.assertIn("FileHistoryMetadata", detail["$defs"])
        self.assertIn("TransferHistoryMetadata", detail["$defs"])
        self.assertIn("transfer", detail["$defs"]["FileHistoryMetadata"]["properties"])
        stats = schemas["get_job_stats"]
        self.assertTrue({
            "total", "status_counts", "failures", "transport_errors",
            "average_duration_seconds", "duration_sample_count", "group_by",
            "groups", "groups_truncated", "time_range", "retained_only",
        } <= set(stats["properties"]))
        self.assertIn("JobStatsGroup", stats["$defs"])
        status = schemas["get_status"]
        self.assertIn("ServiceStatus", status["$defs"])
        self.assertIn("StorageStatus", status["$defs"])
        self.assertIn("JobActivityStatus", status["$defs"])

    def test_pr2_batch_tools_match_live_schema_and_are_typed(self):
        document = {entry["name"]: entry for entry in contract_document()["tools"]}
        for tool in BATCH_TOOLS:
            with self.subTest(tool=tool.name):
                self.assertIn(tool.name, document)
                self.assertEqual(tool.input_schema, document[tool.name]["inputSchema"])
                self.assertEqual(document[tool.name]["outputSchema"]["type"], "object")
                self.assertEqual(
                    tool.annotations.read_only_hint,
                    document[tool.name]["readOnly"],
                )
        args = {
            "server": "demo-node-b", "reason": "TEST-247 contract acceptance",
            "commands": [{"argv": ["echo", "first"]},
                         {"argv": ["sh", "-c", "exit 2"]}],
            "stop_on_error": True,
        }
        accepted = validate_request("execute_commands", args)
        self.assertIsInstance(accepted, ExecuteCommandsRequest)
        self.assertEqual(accepted.model_dump()["commands"][1]["argv"][-1], "exit 2")
        self.assertEqual(ExecuteCommandsRequest.model_validate_json(
            accepted.model_dump_json()).model_dump(), accepted.model_dump())
        for name, params, expected_type in (
            ("get_batch", {"batch_id": "batch_abcdefgh", "cursor": 1}, GetBatchRequest),
            ("list_batches", {"limit": 5, "cursor": 0}, ListBatchesRequest),
            ("cancel_batch", {"batch_id": "batch_abcdefgh", "reason": "stop"}, CancelBatchRequest),
        ):
            with self.subTest(name=name):
                item = validate_request(name, params)
                self.assertIsInstance(item, expected_type)
                self.assertEqual(
                    expected_type.model_validate_json(item.model_dump_json()).model_dump(),
                    item.model_dump(),
                )
                with self.assertRaises(ValidationError):
                    validate_request(name, {**params, "unknown_parameter": "unsafe"})

        rejection = ExecuteCommandsResponse.model_validate({
            "status": "rejected", "failure_kind": "invalid_request",
            "failed_step": 1, "failed_field": "commands.argv",
            "steps_attempted": 0,
        })
        self.assertEqual(
            ExecuteCommandsResponse.model_validate_json(
                rejection.model_dump_json()).model_dump(), rejection.model_dump(),
        )
        self.assertIsNone(rejection.batch_id)

        batch = {
            "batch_id": "batch_abcdefgh", "server": "demo-node-b",
            "reason": "TEST-247 contract acceptance", "story_id": "TEST-247",
            "status": "failed", "failure_kind": "command_error", "failed_step": 1,
            "failed_field": None, "requested_cwd": None, "effective_cwd": None,
            "strict_bash": False, "stop_on_error": True, "timeout_seconds": 30,
            "total_steps": 2, "next_cursor": None, "has_more": False,
            "steps": [{
                "index": index, "step_id": f"batch_abcdefgh:{index}",
                "status": "failed" if index else "succeeded",
                "result_status": "command_error" if index else "succeeded",
                "job_id": f"job_abcdefgh{index}", "command": "sh",
                "command_sha256": "a" * 64, "exit_code": 2 if index else 0,
                "exit_accepted": False if index else True, "elapsed_seconds": .25,
                "attempted": True, "stdout": "", "stderr": "",
                "output_truncated": False, "output_bytes": 0, "output_next_cursor": 0,
            } for index in range(2)],
        }
        for model in (GetBatchResponse, ExecuteCommandsResponse):
            with self.subTest(model=model.__name__):
                decoded = model.model_validate(batch)
                self.assertEqual(
                    model.model_validate_json(decoded.model_dump_json()).model_dump(),
                    decoded.model_dump(),
                )
        listing = ListBatchesResponse.model_validate({
            "batches": [{
                "batch_id": "batch_abcdefgh", "server": "demo-node-b",
                "story_id": "TEST-247", "status": "failed",
                "total_steps": 2, "created_at": 100.0,
            }], "next_cursor": 1,
        })
        self.assertEqual(ListBatchesResponse.model_validate_json(
            listing.model_dump_json()).model_dump(), listing.model_dump())
        cancelled = CancelBatchResponse.model_validate({
            "batch_id": "batch_abcdefgh", "status": "interrupted",
            "cancellation_requested": True,
        })
        self.assertEqual(CancelBatchResponse.model_validate_json(
            cancelled.model_dump_json()).model_dump(), cancelled.model_dump())

    def test_request_schemas_are_closed_and_response_schemas_exist(self):
        for contract in CONTRACTS:
            with self.subTest(name=contract.name):
                input_schema = contract.request.model_json_schema()
                output_schema = contract.response.model_json_schema()
                self.assertEqual(input_schema["additionalProperties"], False)
                self.assertEqual(output_schema["type"], "object")
                self.assertTrue(contract.description)
        self.assertEqual(ListServersRequest.model_validate({}).model_dump(), {})
        with self.assertRaises(ValidationError):
            ListServersRequest.model_validate({"server": "demo-sandbox"})

    def test_execute_requires_logical_host_argv_and_audit_reason(self):
        valid = {"server": "demo-sandbox", "argv": ["uptime"], "reason": "TEST-207 lab check"}
        obj = validate_request("execute_command", valid)
        self.assertIsInstance(obj, ExecuteCommandRequest)
        self.assertEqual(obj.timeout_seconds, 60)
        for invalid in [
            {**valid, "server": "192.168.2.1"},
            {**valid, "server": "lab;id"},
            {**valid, "server": ""},
            {**valid, "server": "A" * 65},
            {**valid, "argv": []},
            {**valid, "argv": [""]},
            {**valid, "argv": ["x" * 32769]},
            {**valid, "argv": "uptime"},
            {**valid, "reason": ""},
            {**valid, "timeout_seconds": 0},
            {**valid, "timeout_seconds": 901},
            {**valid, "timeout_seconds": "60"},
            {**valid, "shell": "bash -c id"},
            {"server": "demo-sandbox", "argv": ["uptime"]},
        ]:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValidationError):
                    ExecuteCommandRequest.model_validate(invalid)

    def test_tracker_independent_story_ids(self):
        requests = (
            (ExecuteCommandRequest, {"server": "demo-sandbox", "argv": ["uptime"],
                                     "reason": "Synthetic test"}),
            (ExecuteCommandsRequest, {"server": "demo-sandbox",
                                      "commands": [{"argv": ["uptime"]}],
                                      "reason": "Synthetic test"}),
            (ReadFileRequest, {"server": "demo-sandbox", "path": "test.txt",
                               "reason": "Synthetic test"}),
        )
        supported = ("TEST-308", "#123", "12345", "owner/repo#123",
                     "issue:workspace/ref-123", "x" * 80, "KA-123", "ıA-123")
        invalid = ("", "x" * 81, "two words", "a\nb", "a\tb", "a\x00b",
                   "a\x1fb", "a\x7fb", "a\x80b", "a\x81b", "a\x8fb", "a\x9fb")
        for request_type, base in requests:
            for story in supported:
                with self.subTest(request=request_type.__name__, story=story):
                    self.assertEqual(request_type.model_validate(
                        {**base, "story_id": story}).story_id, story)
            for story in invalid:
                with self.subTest(request=request_type.__name__, invalid=story):
                    with self.assertRaises(ValidationError):
                        request_type.model_validate({**base, "story_id": story})
            with self.assertRaises(ValidationError):
                request_type.model_validate({**base, "story_id": 12345})

    def test_pr1_cwd_strict_bash_and_accepted_exit_contracts(self):
        args = {"server": "demo-sandbox", "argv": ["bash", "-lc", "false"],
                "reason": "TEST-247 accepted request"}
        default = ExecuteCommandRequest.model_validate(args)
        self.assertEqual(default.success_exit_codes, [0])
        self.assertIsNone(default.cwd)
        self.assertFalse(default.strict_bash)
        valid = ExecuteCommandRequest.model_validate({
            **args, "cwd": "/home/demo/repo link",
            "success_exit_codes": [0, 1, 254], "strict_bash": True,
        })
        self.assertTrue(valid.strict_bash)
        self.assertEqual(valid.success_exit_codes, [0, 1, 254])
        for additions in (
            {"cwd": "relative"},
            {"cwd": ""},
            {"cwd": "/tmp\nunsafe"},
            {"cwd": "/tmp\x00unsafe"},
            {"success_exit_codes": []},
            {"success_exit_codes": [255]},
            {"success_exit_codes": [0, 1, 1]},
            {"success_exit_codes": [-1]},
            {"success_exit_codes": [True]},
            {"success_exit_codes": ["0"]},
            {"success_exit_codes": list(range(17))},
            {"strict_bash": "true"},
            {"argv": ["bash", "-i"], "strict_bash": True},
            {"argv": ["bash", "-c"], "strict_bash": True},
        ):
            with self.subTest(additions=additions), self.assertRaises(ValidationError):
                ExecuteCommandRequest.model_validate({**args, **additions})

    def test_job_id_cursor_and_status_are_bounded(self):
        valid = {"job_id": "job_abcdefgh", "cursor": 0, "max_bytes": 16384}
        self.assertEqual(GetJobOutputRequest.model_validate(valid).cursor, 0)
        for invalid in [
            {**valid, "job_id": "../escape"},
            {**valid, "job_id": "short"},
            {**valid, "cursor": -1},
            {**valid, "max_bytes": 65537},
            {**valid, "max_bytes": 0},
            {**valid, "cursor": "0"},
        ]:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValidationError):
                    GetJobOutputRequest.model_validate(invalid)
        self.assertEqual(ListJobsRequest.model_validate({}).limit, 20)
        self.assertEqual(ListJobsRequest.model_validate({}).record_kind, "command")
        self.assertEqual(ListJobsRequest.model_validate({"story_id": "243"}).story_id, "243")
        self.assertEqual(GetJobStatsRequest.model_validate({}).group_by, "host")
        self.assertEqual(ListJobsRequest.model_validate({"mode": "file"}).record_kind, "file")
        for bad in (
            {"cursor": ""},
            {"cursor": "bad!"},
            {"record_kind": "unsafe"},
            {"record_kind": "command", "mode": "file"},
            {"time_range": "bad"},
            {"time_range": "7d", "from_date": "2026-11-01"},
            {"from_date": "bad"},
            {"group_by": "principal"},
        ):
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                if "group_by" in bad:
                    GetJobStatsRequest.model_validate(bad)
                else:
                    ListJobsRequest.model_validate(bad)
        with self.assertRaises(ValidationError):
            ListJobsRequest.model_validate({"status": "invalid"})
        with self.assertRaises(ValidationError):
            ListJobsRequest.model_validate({"limit": 101})
        self.assertEqual(CancelJobRequest.model_validate({"job_id": "job_abcdefgh", "reason": "operator"}).reason, "operator")
        with self.assertRaises(ValidationError):
            CancelJobRequest.model_validate({"job_id": "job_abcdefgh"})

    def test_response_contracts_validate_states(self):
        ok = JobSummary.model_validate({
            "id": "job_abcdefgh", "server": "demo-sandbox", "status": "queued",
            "created_at": "2026-11-04T15:00:00Z",
        })
        self.assertEqual(ok.status, "queued")
        self.assertEqual(JobSummary.model_validate({
            **ok.model_dump(), "status": "unknown",
        }).status, "unknown")  # File-operation recovery status.
        with self.assertRaises(ValidationError):
            JobSummary.model_validate({**ok.model_dump(), "status": "invalid"})

    def test_ssh_tools_are_neither_discovered_nor_executable(self):
        offered = {tool.name for tool in TOOLS}
        self.assertEqual(offered, {"ping"})
        self.assertFalse(offered.intersection(CONTRACTS_BY_NAME))
        for contract in CONTRACTS:
            with self.subTest(name=contract.name):
                result = handle_tool(contract.name, {"server": "demo-sandbox", "argv": ["id"]})
                self.assertTrue(result.is_error)
                self.assertIn("Unknown", result.content[0].text)
        # A valid request is *only* data, even when the caller supplies a command.
        parsed = validate_request("execute_command", {
            "server": "demo-sandbox", "argv": ["id"], "reason": "offline contract test",
        })
        self.assertEqual(parsed.argv, ["id"])


if __name__ == "__main__":
    unittest.main()
