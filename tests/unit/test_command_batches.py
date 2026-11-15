"""TEST-247 PR2: isolated sequential batch safety, audit and recovery tests."""
from __future__ import annotations

import asyncio
import json
import sqlite3
import time
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from pydantic import ValidationError

from app.batch import (
    BatchManager, BatchStore, MAX_BATCH_OUTPUT_BYTES, MAX_BATCH_RESPONSE_BYTES,
)
from app.contracts import ExecuteCommandsRequest
from app.jobs import JobManager, JobStore
from app.ssh_executor import SSHDenied, SSHResult, OutputLimitExceeded


def request(
    argv: list[list[str]] | None = None, **kwargs: object,
) -> ExecuteCommandsRequest:
    commands = argv or [["echo", "one"], ["echo", "two"], ["echo", "three"]]
    return ExecuteCommandsRequest.model_validate({
        "server": "demo-node-b", "reason": "TEST-247 synthetic batch tests",
        "story_id": "TEST-247", "commands": [{"argv": args} for args in commands],
        **kwargs,
    })


class FakeExecutor:
    """No SSH/network/host side effects; stream only synthetic output."""

    def __init__(self):
        self.calls: list[str] = []
        self.cwd_calls = 0
        self.delay = asyncio.Event()
        self.started = asyncio.Event()
        self.cancellations = 0
        self.preflight_error: Exception | SSHResult | None = None
        self.output_payload = b""

    def authorized_host(self, actor: str, server: str):
        if actor != "alice" or server != "demo-node-b":
            raise SSHDenied("not an approved identity")
        return self

    def list_servers(self, actor: str) -> list[str]:
        return ["demo-node-b"] if actor == "alice" else []

    async def preflight_cwd(self, actor: str, req):
        self.authorized_host(actor, req.server)
        self.cwd_calls += 1
        if isinstance(self.preflight_error, Exception):
            raise self.preflight_error
        if self.preflight_error:
            return self.preflight_error
        return ("/home/alice/resolved", 100, 101)

    async def execute(self, actor: str, req, *, on_output=None, on_admitted=None):
        if on_admitted is not None:
            on_admitted()
        self.authorized_host(actor, req.server)
        cmd = req.argv[0]
        self.calls.append(cmd)
        if cmd == "block":
            self.started.set()
            try:
                await self.delay.wait()
            except asyncio.CancelledError:
                self.cancellations += 1
                raise
        if cmd == "timeout":
            self.started.set()
            try:
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                self.cancellations += 1
                raise
        if cmd == "transport":
            return SSHResult(req.server, "transport_error", 255, "", "SSH failure", .01)
        if cmd == "uncertain":
            return SSHResult(req.server, "transport_error", None, "", "", .01,
                             failure_kind="execution_uncertain")
        if cmd == "exit255":
            return SSHResult(req.server, "command_error", 255, "", "nested ssh DNS failed", .01,
                             exit_accepted=False)
        if cmd == "overflow":
            if on_output:
                try:
                    await on_output("stdout", self.output_payload)
                except OutputLimitExceeded:
                    return SSHResult(req.server, "output_limit", None, "", "", .02)
            return SSHResult(req.server, "succeeded", 0, "", "", .02, True)
        if on_output:
            await on_output("stdout", (cmd + ": output\n").encode())
        if cmd == "exit1" or cmd == "exit2":
            code = 1 if cmd == "exit1" else 2
            accepted = code in req.success_exit_codes
            return SSHResult(req.server, "succeeded" if accepted else "command_error",
                             code, cmd + ": output\n", "", .02, accepted,
                             req.cwd and "/home/alice/resolved")
        return SSHResult(req.server, "succeeded", 0, cmd + ": output\n", "", .02,
                         True, req.cwd and "/home/alice/resolved")


class BatchValidationTests(unittest.TestCase):
    def test_defaults_bounds_and_unique_accepted_codes(self):
        item = request()
        self.assertTrue(item.stop_on_error)
        self.assertFalse(item.strict_bash)
        self.assertEqual(item.timeout_seconds, 60)
        self.assertEqual(len(item.commands), 3)
        self.assertEqual(item.step_command(0).success_exit_codes, [0])
        self.assertEqual(item.step_command(1).reason, item.reason)
        self.assertEqual(item.step_command(2).server, item.server)

        for kwargs in (
            {"commands": []}, {"commands": [{"argv": ["echo"]}] * 6},
            {"timeout_seconds": 901}, {"timeout_seconds": 0},
            {"cwd": "relative"}, {"strict_bash": "true"},
            {"stop_on_error": "false"}, {"commands": [
                {"argv": ["echo", "ok"]}, {"argv": ["bash", "-c"], "success_exit_codes": [0]},
            ], "strict_bash": True},
            {"commands": [
                {"argv": ["echo", "ok"]}, {"argv": ["echo"], "success_exit_codes": [0, 0]},
            ]},
            {"commands": [{"argv": ["echo"], "success_exit_codes": [255]}]},
            {"commands": [{"argv": ["echo"], "timeout_seconds": 901}]},
            {"commands": [{"argv": ["echo", "x" * 33000]}]},
        ):
            with self.subTest(kwargs=str(kwargs)[:60]), self.assertRaises(ValidationError):
                ExecuteCommandsRequest.model_validate({
                    "server": "demo-node-b", "reason": "synthetic",
                    "commands": [{"argv": ["echo", "ok"]}], **kwargs,
                })

    def test_shared_strict_bash_and_step_timeout(self):
        command = request(
            [["bash", "-lc", "false | true"], ["sh", "-c", "echo ok"]],
            cwd="/home/alice/dir", strict_bash=True, timeout_seconds=120,
            commands=[
                {"argv": ["bash", "-lc", "false | true"], "success_exit_codes": [0, 1],
                 "timeout_seconds": 5},
                {"argv": ["sh", "-c", "echo ok"]},
            ],
        )
        self.assertEqual(command.step_command(0).timeout_seconds, 5)
        self.assertEqual(command.step_command(1).timeout_seconds, 120)
        self.assertTrue(command.step_command(0).strict_bash)
        self.assertEqual(command.step_command(0).cwd, "/home/alice/dir")

    def test_aggregate_encoded_batch_size_is_bounded(self):
        with self.assertRaises(ValidationError):
            request(commands=[{"argv": ["echo", "x" * 20000]},
                              {"argv": ["echo", "y" * 20000]}])


class BatchRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_privileged_setup_or_sudo_denial_never_continues_batch(self):
        for kind, exit_code in (("root_setup_failed", 126),
                                ("sudo_authentication", 1),
                                ("sudo_authorization", 1),
                                ("sudo_rejected", 1),
                                ("root_unconfirmed", 255)):
            with self.subTest(failure_kind=kind):
                executor = self.fake
                async def root_result(_actor, _request, *, on_output=None,
                                      on_admitted=None):
                    if on_admitted is not None:
                        on_admitted()
                    return SSHResult(
                        "demo-node-b", "command_error", exit_code,
                        "", "Synthetic root refusal", .01,
                        exit_accepted=False, failure_kind=kind,
                    )
                root_exec = AsyncMock(side_effect=root_result)
                with patch.object(executor, "_execute_approved_privileged",
                                  root_exec, create=True):
                    result = await self.batch.execute(
                        "alice", request(
                            argv=[["first"], ["second"]], privileged=True,
                            stop_on_error=False,
                        ), admitted_root=True,
                    )
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["failure_kind"], kind)
                self.assertEqual(result["failed_step"], 0)
                self.assertEqual([s["status"] for s in result["steps"]],
                                 ["failed", "not_attempted"])
                root_exec.assert_awaited_once()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = JobStore(Path(self.temp.name) / "private" / "jobs.sqlite")
        self.fake = FakeExecutor()
        self.jobs = JobManager(self.fake, self.store)  # type: ignore[arg-type]
        self.batch = BatchManager(self.jobs)

    async def asyncTearDown(self):
        await self.batch.shutdown()
        await self.jobs.shutdown()

    async def test_preapproval_batch_reuses_parent_and_restart_is_no_execution(self):
        from app.approval_status import ApprovalCode
        from app.history import HistoryStore

        cmd = request(argv=[["echo", "first"], ["echo", "second"]])
        waiting = self.batch.store.create("alice", cmd, pending_approval=True)
        before = self.batch.get("alice", waiting)
        self.assertEqual(before["status"], "awaiting_approval")
        self.assertEqual(before["total_steps"], 2)
        self.assertTrue(all(s["status"] == "not_attempted" for s in before["steps"]))

        self.batch.store.settle_approval(waiting,
                                         int(ApprovalCode.DENIED_REVOKED),
                                         denied=True)
        denied = self.batch.get("alice", waiting)
        self.assertEqual(denied["status"], "denied")
        self.assertEqual(denied["approval_status"], "denied_revoked")
        self.assertEqual(denied["total_steps"], 2)
        self.assertIsNone(denied["next_cursor"])
        self.assertFalse(denied["has_more"])
        self.assertTrue(all(not s["attempted"] for s in denied["steps"]))
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(HistoryStore(self.store).detail("batch_" + waiting)
                         ["approval_status"], "denied_revoked")

        pending_restart = self.batch.store.create(
            "alice", request(argv=[["echo", "never"]]), pending_approval=True,
        )
        BatchStore(self.store)  # startup recovery has no SSH execution
        after = self.batch.store.get("alice", pending_restart)
        self.assertEqual(after["status"], "rejected")
        self.assertEqual(after["failure_kind"], "approval_interrupted")
        self.assertIsNone(after["approval_status"])
        self.assertTrue(all(not s["attempted"] for s in after["steps"]))
        self.assertEqual(self.fake.calls, [])

        legacy = self.batch.store.create(
            "alice", request(argv=[["echo", "legacy"]]), pending_approval=True,
        )
        self.batch.store.settle_approval(legacy, 5, denied=True)
        # A database upgraded from the old implementation could have
        # a denied manifest with no child-step rows.
        with self.store._connect() as db:
            db.execute("DELETE FROM command_batch_steps WHERE batch_id=?", (legacy,))
        legacy_details = self.batch.get("alice", legacy)
        self.assertEqual(legacy_details["status"], "denied")
        self.assertEqual(legacy_details["steps"], [])
        self.assertEqual(legacy_details["total_steps"], 1)
        self.assertIsNone(legacy_details["next_cursor"])
        self.assertFalse(legacy_details["has_more"])

    async def test_preapproval_batch_fail_closed_error_branches(self):
        from app.approval_status import ApprovalCode
        cmd = request(argv=[["hostname"]])
        pending = self.batch.store.create("alice", cmd, pending_approval=True)
        with self.assertRaisesRegex(ValueError, "approval code"):
            self.batch.store.settle_approval(pending, None)
        self.batch.store.settle_approval(pending, None, denied=True)
        result = self.batch.store.get("alice", pending)
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["failure_kind"], "authorization")
        self.assertIsNone(result["approval_status"])
        self.assertFalse(result["steps"][0]["attempted"])
        with self.assertRaisesRegex(RuntimeError, "cannot be finalized"):
            self.batch.store.settle_approval(
                pending, int(ApprovalCode.DENIED_CONFIG), denied=True,
            )

        admitted = self.batch.store.create("alice", cmd, pending_approval=True)
        self.batch.store.settle_approval(admitted, int(ApprovalCode.APPROVED_CONFIG))
        self.assertEqual(self.batch.get("alice", admitted)["status"], "queued")
        self.assertEqual(self.batch.get("alice", admitted)["approval_status"],
                         "approved_config")
        self.assertEqual(self.fake.calls, [])

    async def test_approved_batch_reuses_original_manifest_for_execution(self):
        from app.approval_status import ApprovalCode
        cmd = request(argv=[["echo", "first"], ["echo", "second"]])
        batch_id = self.batch.store.create("alice", cmd, pending_approval=True)
        initial = self.batch.get("alice", batch_id)
        self.assertEqual(initial["status"], "awaiting_approval")
        self.batch.store.settle_approval(batch_id, int(ApprovalCode.APPROVED_EXPLICIT))
        completed = await self.batch.execute(
            "alice", cmd, precreated_id=batch_id,
        )
        self.assertEqual(completed["batch_id"], batch_id)
        self.assertEqual(completed["status"], "succeeded")
        self.assertEqual(completed["approval_status"], "approved_explicit")
        self.assertEqual(len(completed["steps"]), 2)
        self.assertTrue(all(step["attempted"] for step in completed["steps"]))
        self.assertEqual(len(self.batch.list("alice")["batches"]), 1)
        self.assertEqual(self.fake.calls, ["echo", "echo"])

    async def test_success_retains_all_steps_and_private_child_jobs(self):
        result = await self.batch.execute("alice", request())
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual([x["status"] for x in result["steps"]], ["succeeded"] * 3)
        self.assertEqual(self.fake.calls, ["echo", "echo", "echo"])
        for step in result["steps"]:
            self.assertTrue(step["attempted"])
            self.assertTrue(step["job_id"])
            self.assertEqual(step["exit_code"], 0)
            self.assertEqual(step["exit_accepted"], True)
            self.assertEqual(step["stdout"], "echo: output\n")
            self.assertEqual(self.store.get("alice", step["job_id"])["status"], "succeeded")
            self.assertIsNone(self.store.get("bob", step["job_id"]))
        self.assertIsNone(self.batch.get("bob", result["batch_id"]))
        self.assertEqual(self.batch.list("bob")["batches"], [])

    async def test_stop_on_second_failure_never_starts_third(self):
        result = await self.batch.execute("alice", request(
            [["echo", "one"], ["exit2"], ["echo", "never"]],
        ))
        self.assertEqual(result["status"], "failed")
        # Preserve the pre-root-approval batch error contract for normal
        # commands, including after reopening the durable SQLite audit.
        self.assertEqual(result["failure_kind"], "command_error")
        reopened = BatchStore(JobStore(self.store.path)).get(
            "alice", result["batch_id"],
        )
        self.assertIsNotNone(reopened)
        self.assertEqual(reopened["failure_kind"], "command_error")
        self.assertEqual(result["failed_step"], 1)
        self.assertEqual([x["status"] for x in result["steps"]],
                         ["succeeded", "failed", "not_attempted"])
        self.assertFalse(result["steps"][2]["attempted"])
        self.assertIsNone(result["steps"][2]["job_id"])
        self.assertEqual(result["steps"][1]["exit_code"], 2)
        self.assertEqual(result["steps"][1]["exit_accepted"], False)
        self.assertEqual(self.fake.calls, ["echo", "exit2"])

    async def test_success_exit_codes_allow_continuation(self):
        cmd = request(commands=[
            {"argv": ["echo", "one"]},
            {"argv": ["exit1"], "success_exit_codes": [0, 1]},
            {"argv": ["echo", "three"]},
        ])
        result = await self.batch.execute("alice", cmd)
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual([x["exit_code"] for x in result["steps"]], [0, 1, 0])
        self.assertTrue(result["steps"][1]["exit_accepted"])
        self.assertEqual(self.fake.calls, ["echo", "exit1", "echo"])

    async def test_stop_on_error_false_only_continues_after_known_failure(self):
        result = await self.batch.execute(
            "alice", request([["exit2"], ["echo", "works"]], stop_on_error=False),
        )
        self.assertEqual(result["status"], "failed")
        self.assertEqual([x["status"] for x in result["steps"]],
                         ["failed", "succeeded"])
        self.assertEqual(self.fake.calls, ["exit2", "echo"])
        result = await self.batch.execute(
            "alice", request([["transport"], ["echo", "never"]], stop_on_error=False),
        )
        self.assertEqual(result["status"], "transport_error")
        self.assertEqual(result["steps"][1]["status"], "not_attempted")
        self.assertEqual(self.fake.calls[-1], "transport")

    async def test_confirmed_exit_255_continues_but_uncertain_exit_stops(self):
        completed = await self.batch.execute(
            "alice", request([["exit255"], ["echo", "after"]], stop_on_error=False),
        )
        self.assertEqual(completed["status"], "failed")
        self.assertEqual([step["status"] for step in completed["steps"]],
                         ["failed", "succeeded"])
        self.assertEqual(completed["steps"][0]["exit_code"], 255)
        self.assertFalse(completed["steps"][0]["exit_accepted"])
        self.assertEqual(self.fake.calls[-2:], ["exit255", "echo"])
        stopped = await self.batch.execute(
            "alice", request([["uncertain"], ["echo", "never"]], stop_on_error=False),
        )
        self.assertEqual(stopped["status"], "transport_error")
        self.assertEqual([step["status"] for step in stopped["steps"]],
                         ["transport_error", "not_attempted"])
        self.assertEqual(self.fake.calls[-1], "uncertain")

    async def test_valid_cwd_preflight_once_then_same_cwd_per_step(self):
        result = await self.batch.execute("alice", request(
            [["echo"], ["exit1"]],
            commands=[{"argv": ["echo"]}, {"argv": ["exit1"], "success_exit_codes": [0, 1]}],
            cwd="/home/alice/link", strict_bash=True,
        ))
        self.assertEqual(self.fake.cwd_calls, 1)
        self.assertEqual(result["effective_cwd"], "/home/alice/resolved")
        self.assertEqual(result["requested_cwd"], "/home/alice/link")
        self.assertTrue(result["strict_bash"])
        self.assertEqual(result["status"], "succeeded")
        for step in result["steps"]:
            self.assertEqual(self.store.get("alice", step["job_id"])["effective_cwd"],
                             "/home/alice/resolved")

    async def test_preflight_denial_has_no_attempted_steps(self):
        self.fake.preflight_error = SSHDenied("private path")
        result = await self.batch.execute("alice", request(cwd="/root"))
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["failed_field"], "cwd")
        self.assertTrue(all(not s["attempted"] for s in result["steps"]))
        self.assertEqual(self.fake.calls, [])

    async def test_ssh_preflight_transport_error_preserves_zero_attempts(self):
        self.fake.preflight_error = SSHResult(
            "demo-node-b", "transport_error", 255, "", "Host key failed", .01,
        )
        result = await self.batch.execute("alice", request(cwd="/home/alice"))
        self.assertEqual(result["status"], "transport_error")
        self.assertEqual(result["failed_field"], "cwd")
        self.assertEqual(self.fake.calls, [])
        self.assertTrue(all(x["status"] == "not_attempted" for x in result["steps"]))

    async def test_actor_denial_has_no_batch_created(self):
        with self.assertRaises(SSHDenied):
            await self.batch.execute("bob", request())
        self.assertEqual(self.batch.list("alice")["batches"], [])

    async def test_step_cursor_and_lost_batch_id_list_recovery(self):
        result = await self.batch.execute("alice", request())
        first = self.batch.get("alice", result["batch_id"], cursor=0, limit=2)
        self.assertEqual(len(first["steps"]), 2)
        self.assertEqual(first["next_cursor"], 2)
        rest = self.batch.get("alice", result["batch_id"], cursor=2, limit=2)
        self.assertEqual(len(rest["steps"]), 1)
        self.assertEqual(rest["steps"][0]["index"], 2)
        self.assertFalse(rest["has_more"])
        listing = self.batch.list("alice")
        self.assertEqual(listing["batches"][0]["batch_id"], result["batch_id"])
        self.assertIsNone(self.batch.get("bob", result["batch_id"]))

    async def test_aggregate_output_cap_and_preview_pagination(self):
        self.fake.output_payload = b"x" * (MAX_BATCH_OUTPUT_BYTES + 5000)
        result = await self.batch.execute("alice", request(
            [["overflow"], ["echo", "never"]],
        ))
        self.assertEqual(result["status"], "output_limit")
        self.assertEqual(result["steps"][0]["status"], "output_limit")
        self.assertEqual(result["steps"][1]["status"], "not_attempted")
        self.assertEqual(result["steps"][0]["output_bytes"], MAX_BATCH_OUTPUT_BYTES)
        self.assertTrue(result["steps"][0]["output_truncated"])
        self.assertLessEqual(len(json.dumps(result).encode()), MAX_BATCH_RESPONSE_BYTES)
        output = self.jobs.output("alice", result["steps"][0]["job_id"], max_bytes=65536)
        self.assertEqual(output["next_cursor"], 65536)
        self.assertTrue(output["truncated"])

    async def test_timeout_after_step1_marks_step2_unknown_never_retried(self):
        result = await self.batch.execute("alice", request(
            [["echo", "first"], ["timeout"], ["echo", "never"]],
            timeout_seconds=1,
        ))
        self.assertEqual(result["status"], "timed_out")
        self.assertEqual([x["status"] for x in result["steps"]],
                         ["succeeded", "unknown", "not_attempted"])
        self.assertEqual(self.fake.calls, ["echo", "timeout"])
        self.assertGreaterEqual(self.fake.cancellations, 1)

    async def test_disconnected_mcp_waiter_does_not_cancel_batch(self):
        task = asyncio.create_task(self.batch.execute(
            "alice", request([["echo"], ["block"], ["echo"]], timeout_seconds=10),
        ))
        await asyncio.wait_for(self.fake.started.wait(), timeout=2)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        listing = self.batch.list("alice")
        self.assertEqual(listing["batches"][0]["status"], "running")
        self.fake.delay.set()
        for _ in range(200):
            await asyncio.sleep(.01)
            item = self.batch.get("alice", listing["batches"][0]["batch_id"])
            if item["status"] != "running":
                break
        self.assertEqual(item["status"], "succeeded")
        self.assertEqual([s["status"] for s in item["steps"]], ["succeeded"] * 3)

    async def test_explicit_cancel_marks_inflight_unknown(self):
        task = asyncio.create_task(self.batch.execute(
            "alice", request([["echo"], ["block"], ["echo"]], timeout_seconds=10),
        ))
        await asyncio.wait_for(self.fake.started.wait(), timeout=2)
        batch_id = self.batch.list("alice")["batches"][0]["batch_id"]
        self.assertTrue(self.batch.cancel("alice", batch_id)["cancellation_requested"])
        with self.assertRaises(asyncio.CancelledError):
            await task
        item = self.batch.get("alice", batch_id)
        self.assertEqual(item["status"], "interrupted")
        self.assertEqual([s["status"] for s in item["steps"]],
                         ["succeeded", "unknown", "not_attempted"])
        from app.history import HistoryStore
        child_id = item["steps"][1]["job_id"]
        child = self.jobs.get("alice", child_id)
        self.assertEqual(child["status"], "cancelled")
        history = HistoryStore(self.store)
        observed = history.batch_step_outcome(child_id)
        self.assertEqual(observed["batch_status"], "interrupted")
        self.assertEqual(observed["step_status"], "unknown")
        self.assertEqual(observed["result_status"], "interrupted")
        self.assertEqual(history.cancellation_request(child_id)["requested_via"], "mcp")
        self.assertGreater(self.fake.cancellations, 0)
        self.assertIsNone(self.batch.cancel("bob", batch_id))

    async def test_restart_reconciles_running_without_replay(self):
        # Construct in-flight state without actual execution to simulate
        # process termination between remote dispatch and acknowledgement.
        cmd = request([["echo"], ["block"], ["echo"]])
        batch_id = self.batch.store.create("alice", cmd)
        self.batch.store.begin(batch_id)
        job_id = self.store.create("alice", cmd.step_command(1), mode="sync")
        self.batch.store.record_step(batch_id, 1, job_id)
        self.store.begin(job_id)
        self.batch.store.admitted_step(batch_id, 1, job_id)
        restarted_jobs = JobStore(self.store.path)
        restarted_batch = BatchStore(restarted_jobs)
        result = restarted_batch.get("alice", batch_id)
        self.assertEqual(result["status"], "interrupted")
        self.assertEqual([s["status"] for s in result["steps"]],
                         ["not_attempted", "unknown", "not_attempted"])
        self.assertEqual(restarted_jobs.get("alice", job_id)["status"], "interrupted")
        self.assertEqual(self.fake.calls, [])

    async def test_restart_preserves_queued_child_and_job_id_without_attempt(self):
        command = request([["echo", "queued"]])
        batch_id = self.batch.store.create("alice", command)
        self.batch.store.begin(batch_id)
        job_id = self.store.create("alice", command.step_command(0), mode="sync")
        self.batch.store.record_step(batch_id, 0, job_id)
        before = self.batch.get("alice", batch_id)["steps"][0]
        self.assertFalse(before["attempted"])
        self.assertEqual(before["job_id"], job_id)
        restarted_jobs = JobStore(self.store.path)
        restarted_batch = BatchStore(restarted_jobs)
        result = restarted_batch.get("alice", batch_id)
        self.assertEqual(result["status"], "interrupted")
        self.assertEqual(result["steps"][0]["status"], "not_attempted")
        self.assertEqual(result["steps"][0]["job_id"], job_id)
        self.assertIsNone(restarted_jobs.get("alice", job_id)["started_at"])

    async def test_restart_reconciles_child_admitted_before_step_update(self):
        command = request([["echo", "admitted"]])
        batch_id = self.batch.store.create("alice", command)
        self.batch.store.begin(batch_id)
        job_id = self.store.create("alice", command.step_command(0), mode="sync")
        self.batch.store.record_step(batch_id, 0, job_id)
        # Simulate process death in the narrow gap after child admission.
        self.store.begin(job_id)
        restarted_jobs = JobStore(self.store.path)
        restarted_batch = BatchStore(restarted_jobs)
        result = restarted_batch.get("alice", batch_id)
        self.assertEqual(result["status"], "interrupted")
        self.assertEqual(result["steps"][0]["status"], "unknown")
        self.assertTrue(result["steps"][0]["attempted"])
        self.assertEqual(result["steps"][0]["job_id"], job_id)

    async def test_retention_reclaims_completed_batches_not_active(self):
        result = await self.batch.execute("alice", request())
        with self.store._connect() as db:
            db.execute(
                "UPDATE command_batches SET ended_at=0 WHERE id=?",
                (result["batch_id"],),
            )
            self.batch.store.prune()
        self.assertIsNone(self.batch.get("alice", result["batch_id"]))

    async def test_sanitize_command_metadata_without_storing_script(self):
        result = await self.batch.execute("alice", request([
            ["sh", "-c", "synthetic secret that must not appear in batch metadata"],
            ["name:with:punctuation"], ["/a/" + "x" * 65],
        ]))
        self.assertEqual([s["command"] for s in result["steps"]],
                         ["sh", "[redacted]", "[redacted]"])
        with self.store._connect() as db:
            records = db.execute(
                "SELECT command,command_sha256 FROM command_batch_steps WHERE batch_id=?",
                (result["batch_id"],),
            ).fetchall()
        self.assertEqual(len(records), 3)
        self.assertNotIn("synthetic secret", str([dict(row) for row in records]))

    async def test_invalid_store_transitions_and_pagination_fail_closed(self):
        batch_id = self.batch.store.create("alice", request())
        self.assertTrue(self.batch.store.begin(batch_id))
        self.assertFalse(self.batch.store.begin(batch_id))
        with self.assertRaisesRegex(RuntimeError, "unrecorded"):
            self.batch.store.admitted_step(batch_id, 0, "synthetic-job")
        self.batch.store.record_step(batch_id, 0, "synthetic-job")
        with self.assertRaisesRegex(RuntimeError, "already recorded"):
            self.batch.store.record_step(batch_id, 0, "duplicate")
        self.batch.store.admitted_step(batch_id, 0, "synthetic-job")
        with self.assertRaisesRegex(RuntimeError, "Cannot admit"):
            self.batch.store.admitted_step(batch_id, 0, "synthetic-job")
        with self.assertRaisesRegex(ValueError, "step outcome"):
            self.batch.store.completed_step(
                batch_id, 0, status="created", result_status=None,
            )
        self.batch.store.completed_step(
            batch_id, 0, status="succeeded", result_status="succeeded",
            exit_code=0, exit_accepted=True,
        )
        with self.assertRaisesRegex(RuntimeError, "non-running"):
            self.batch.store.completed_step(
                batch_id, 0, status="succeeded", result_status="succeeded",
            )
        with self.assertRaisesRegex(ValueError, "batch outcome"):
            self.batch.store.finish(batch_id, "not_a_status")
        for cursor, limit in ((-1, 1), (0, 0), (5, 1)):
            with self.assertRaisesRegex(ValueError, "pagination"):
                self.batch.get("alice", batch_id, cursor=cursor, limit=limit)
        for cursor, limit in ((-1, 1), (0, 0), (0, 51), (1000001, 1)):
            with self.assertRaisesRegex(ValueError, "pagination"):
                self.batch.list("alice", cursor=cursor, limit=limit)

    async def test_approved_batch_losing_signed_host_is_terminal_before_dispatch(self):
        from app.approval_status import ApprovalCode
        from app.history import HistoryStore

        command = request(argv=[["echo", "must-not-run"]])
        pending = self.batch.store.create("bob", command, pending_approval=True)
        self.batch.store.settle_approval(pending, int(ApprovalCode.APPROVED_TIMED))
        with self.assertRaises(SSHDenied):
            await self.batch.execute("bob", command, precreated_id=pending)
        item = self.batch.store.get("bob", pending)
        self.assertEqual(item["status"], "rejected")
        self.assertEqual(item["failure_kind"], "authorization")
        self.assertEqual(item["approval_status"], "approved_timed")
        self.assertEqual(item["steps"][0]["status"], "not_attempted")
        self.assertFalse(item["has_more"])
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(HistoryStore(self.store).detail("batch_" + pending)
                         ["status"], "failed")
        with self.assertRaisesRegex(RuntimeError, "Cannot reject"):
            self.batch.store.reject_unscheduled(pending, "capacity")

    async def test_saturated_batch_finalizes_preapproved_manifest_in_history(self):
        from app.approval_status import ApprovalCode
        from app.history import HistoryStore

        self.jobs.max_active = 1
        first = asyncio.create_task(self.batch.execute(
            "alice", request([["block"], ["echo"]], timeout_seconds=10),
        ))
        await asyncio.wait_for(self.fake.started.wait(), 2)
        command = request([["echo", "never"]])
        waiting = self.batch.store.create("alice", command, pending_approval=True)
        self.batch.store.settle_approval(
            waiting, int(ApprovalCode.APPROVED_TIMED),
        )
        with self.assertRaisesRegex(RuntimeError, "Too many active batches"):
            await self.batch.execute("alice", command, precreated_id=waiting)
        saved = self.batch.get("alice", waiting)
        self.assertEqual(saved["status"], "rejected")
        self.assertEqual(saved["failure_kind"], "capacity")
        self.assertEqual(saved["approval_status"], "approved_timed")
        self.assertEqual(saved["steps"][0]["status"], "not_attempted")
        self.assertFalse(saved["has_more"])
        listed = HistoryStore(self.store).list(
            {"record_kind": "all", "time_range": "all"},
        )["jobs"]
        self.assertEqual(
            [row["status"] for row in listed if row["id"] == "batch_" + waiting],
            ["failed"],
        )
        self.assertEqual(len(self.fake.calls), 1)
        self.fake.delay.set()
        self.assertEqual((await first)["status"], "succeeded")

    async def test_working_directory_rejection_reports_actual_preflight_cause(self):
        from app.history import HistoryStore
        for kind, expected in (
            ("cwd_denied", "Working-directory access denied during preflight"),
            ("cwd_preflight", "Working-directory preflight failed"),
        ):
            with self.subTest(kind=kind):
                req = request([["echo", "must-not-run"]], cwd="/tmp/preflight")
                batch_id = self.batch.store.create("alice", req)
                self.batch.store.finish(
                    batch_id, "rejected", failure_kind=kind, failed_field="cwd",
                )
                history = HistoryStore(self.store).detail("batch_" + batch_id)
                self.assertEqual(history["status"], "failed")
                self.assertEqual(history["failure_kind"], kind)
                self.assertIn(expected, history["error"])
                self.assertIn("no batch steps ran", history["error"])
                self.assertIsNone(history["started_at"])
                self.assertFalse(self.batch.get("alice", batch_id)["steps"][0]["attempted"])
        self.assertEqual(self.fake.calls, [])

    async def test_unavailable_preexecution_batch_remains_visible_in_history(self):
        from app.history import HistoryStore

        pending = self.batch.store.create(
            "alice", request([["echo", "never"]]), pending_approval=True,
        )
        self.batch.store.settle_approval(pending, None, denied=True)
        item = self.batch.get("alice", pending)
        self.assertEqual(item["status"], "rejected")
        self.assertIsNone(item["approval_status"])
        self.assertEqual(item["failure_kind"], "authorization")
        all_rows = HistoryStore(self.store).list(
            {"record_kind": "all", "time_range": "all"},
        )
        self.assertEqual(all_rows["filtered_total"], 1)
        row = all_rows["jobs"][0]
        self.assertEqual(row["id"], "batch_" + pending)
        self.assertEqual(row["status"], "failed")
        self.assertEqual(HistoryStore(self.store).list(
            {"status": "failed", "time_range": "all"},
        )["filtered_total"], 1)
        self.assertEqual(HistoryStore(self.store).stats({
            "time_range": "all",
        })["failures"], 1)
        self.assertEqual(HistoryStore(self.store).totals()["failed"], 1)
        self.assertIsNone(row["approval_status"])
        self.assertIsNone(row["started_at"])
        self.assertEqual(self.fake.calls, [])

    async def test_active_batch_limit_prevents_allocation(self):
        self.jobs.max_active = 1
        first = asyncio.create_task(self.batch.execute(
            "alice", request([["block"], ["echo"]], timeout_seconds=10),
        ))
        await asyncio.wait_for(self.fake.started.wait(), timeout=2)
        with self.assertRaisesRegex(RuntimeError, "Too many active batches"):
            await self.batch.execute("alice", request())
        self.assertEqual(len(self.batch.list("alice")["batches"]), 1)
        self.fake.delay.set()
        self.assertEqual((await first)["status"], "succeeded")

    async def test_known_failure_keeps_first_failed_index_even_when_continuing(self):
        result = await self.batch.execute("alice", request(
            [["exit2"], ["echo", "ok"], ["exit1"]], stop_on_error=False,
        ))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failed_step"], 0)
        self.assertEqual([s["status"] for s in result["steps"]],
                         ["failed", "succeeded", "failed"])

    async def test_overall_deadline_consumed_by_preflight_has_zero_steps(self):
        async def slow(_actor, _request):
            await asyncio.sleep(1.03)
            return ("/home/alice/resolved", 3, 4)
        with patch.object(self.fake, "preflight_cwd", side_effect=slow):
            result = await self.batch.execute(
                "alice", request(cwd="/home/alice/link", timeout_seconds=1),
            )
        self.assertEqual(result["status"], "timed_out")
        self.assertIsNone(result["failed_step"])
        self.assertEqual(result["failed_field"], "cwd")
        self.assertEqual(self.fake.calls, [])
        self.assertTrue(all(not s["attempted"] for s in result["steps"]))

    async def test_busy_ssh_preflight_semaphore_respects_overall_deadline(self):
        """A queued host/global semaphore cannot bypass a 1-second deadline."""
        semaphore = asyncio.Semaphore(1)
        await semaphore.acquire()
        waiting = asyncio.Event()
        cancelled = asyncio.Event()

        async def blocked(_actor, _request):
            waiting.set()
            try:
                async with semaphore:
                    return ("/home/alice/should-not-be-resolved", 12, 13)
            except asyncio.CancelledError:
                cancelled.set()
                raise

        began = asyncio.get_running_loop().time()
        try:
            with patch.object(self.fake, "preflight_cwd", side_effect=blocked):
                result = await self.batch.execute(
                    "alice", request(cwd="/home/alice/queued", timeout_seconds=1),
                )
        finally:
            semaphore.release()
        elapsed = asyncio.get_running_loop().time() - began
        self.assertTrue(waiting.is_set())
        self.assertTrue(cancelled.is_set())
        self.assertGreaterEqual(elapsed, .85)
        self.assertLess(elapsed, 1.8)
        self.assertEqual(result["status"], "timed_out")
        self.assertEqual(result["failure_kind"], "overall_timeout")
        self.assertEqual(result["failed_field"], "cwd")
        self.assertEqual(self.fake.calls, [])
        self.assertTrue(all(s["status"] == "not_attempted" for s in result["steps"]))
        self.assertTrue(all(s["job_id"] is None for s in result["steps"]))

    async def test_batch_preflight_step_timeout_is_clamped_to_remaining_deadline(self):
        observed: list[int] = []

        async def observed_preflight(_actor, command):
            observed.append(command.timeout_seconds)
            return ("/home/alice/resolved", 5, 6)

        command = request(
            cwd="/home/alice/link", timeout_seconds=1,
            commands=[{"argv": ["echo", "first"], "timeout_seconds": 30}],
        )
        with patch.object(self.fake, "preflight_cwd", side_effect=observed_preflight):
            result = await self.batch.execute("alice", command)
        self.assertEqual(observed, [1])
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(len(self.fake.calls), 1)

    async def test_step_executor_unexpected_exception_is_not_safe_to_retry(self):
        async def broken(actor, command, *, on_created, on_started, max_output_bytes):
            job_id = self.store.create(actor, command, mode="sync")
            on_created(job_id)
            self.store.begin(job_id)
            on_started(job_id)
            raise OSError("synthetic SSH command transport failure")
        with patch.object(self.jobs, "execute_sync", side_effect=broken):
            result = await self.batch.execute("alice", request())
        self.assertEqual(result["status"], "interrupted")
        self.assertEqual(result["failed_step"], 0)
        self.assertEqual([s["status"] for s in result["steps"]],
                         ["unknown", "not_attempted", "not_attempted"])

    async def test_admitted_child_cwd_rejection_is_known_without_dispatch(self):
        # The probe may use SSH after capacity admission, but caller argv is
        # never run. Keep the child job ID; do not label its step unknown.
        async def denied_after_admission(_actor, _request, *, on_output=None,
                                         on_admitted=None):
            if on_admitted is not None:
                on_admitted()
            raise SSHDenied("sensitive remote cwd")

        with patch.object(self.fake, "execute", side_effect=denied_after_admission):
            result = await self.batch.execute(
                "alice", request(
                    [["touch", "never-run"], ["echo", "never-run"]],
                    stop_on_error=False,
                ),
            )
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["failure_kind"], "pre_execution_rejected")
        self.assertEqual(result["failed_step"], 0)
        first, second = result["steps"]
        self.assertEqual(first["status"], "not_attempted")
        self.assertEqual(first["result_status"], "rejected")
        self.assertFalse(first["attempted"])
        self.assertTrue(first["job_id"])
        self.assertEqual(second["status"], "not_attempted")
        self.assertFalse(second["attempted"])
        self.assertEqual(self.fake.calls, [])
        child = self.jobs.get("alice", first["job_id"])
        self.assertEqual(child["status"], "failed")
        self.assertEqual(child["failure_kind"], "pre_execution_rejected")
        self.assertIsNotNone(child["started_at"])
        self.assertEqual(child["output_bytes"], 0)
        self.assertEqual(self.batch.get("alice", result["batch_id"]), result)
        from app.history import HistoryStore
        history = HistoryStore(self.store)
        displayed = history.list({"record_kind": "all", "time_range": "all"})
        self.assertEqual(displayed["filtered_total"], 1)
        self.assertEqual([row["id"] for row in displayed["jobs"]], [first["job_id"]])
        self.assertEqual(displayed["jobs"][0]["failure_kind"],
                         "pre_execution_rejected")
        self.assertIsNone(history.detail("batch_" + result["batch_id"]))
        self.assertEqual(history.stats({"time_range": "all"})["failures"], 1)
        self.assertEqual(history.totals()["failed"], 1)
        with self.store._connect() as db:
            self.assertEqual(db.execute(
                "SELECT total FROM telemetry_outcomes WHERE status='failed' "
                "AND failure_kind='pre_execution_rejected'"
            ).fetchone()[0], 1)

    async def test_restart_recovers_proven_child_denial_before_unknown(self):
        from app.history import HistoryStore

        for step_was_admitted in (False, True):
            with self.subTest(admitted=step_was_admitted):
                req = request([["touch", "must-not-run"], ["echo", "later"]])
                batch_id = self.batch.store.create("alice", req)
                self.assertTrue(self.batch.store.begin(batch_id))
                job_id = self.store.create(
                    "alice", req.step_command(0), mode="sync",
                )
                self.batch.store.record_step(batch_id, 0, job_id)
                self.assertTrue(self.store.begin(job_id))
                if step_was_admitted:
                    self.batch.store.admitted_step(batch_id, 0, job_id)
                # Crash after durable child completion, before batch
                # reconciliation. The admitted bit never proves argv ran.
                self.store.finish(
                    job_id, "failed", error="SSH authorization was rejected",
                    failure_kind="pre_execution_rejected",
                )
                self.assertEqual(self.batch.get("alice", batch_id)["status"], "running")
                rebooted_jobs = JobStore(self.store.path)
                rebooted = BatchStore(rebooted_jobs)
                result = rebooted.get("alice", batch_id)
                self.assertEqual(result["status"], "rejected")
                self.assertEqual(result["failure_kind"], "pre_execution_rejected")
                self.assertEqual(result["failed_step"], 0)
                self.assertEqual(result["steps"][0]["status"], "not_attempted")
                self.assertEqual(result["steps"][0]["result_status"], "rejected")
                self.assertFalse(result["steps"][0]["attempted"])
                self.assertEqual(result["steps"][0]["job_id"], job_id)
                self.assertEqual(result["steps"][1]["status"], "not_attempted")
                self.assertEqual(rebooted_jobs.get("alice", job_id)["status"], "failed")
                history = HistoryStore(rebooted_jobs)
                self.assertEqual(
                    [r["id"] for r in history.list({
                        "record_kind": "all", "time_range": "all",
                    })["jobs"] if r["id"] in (job_id, "batch_" + batch_id)],
                    [job_id],
                )
                # Repeated cold-start recovery cannot revise this evidence.
                again = BatchStore(JobStore(self.store.path))
                self.assertEqual(again.get("alice", batch_id), result)
                self.assertEqual(self.fake.calls, [])

    async def test_rejected_child_and_parent_commit_atomically(self):
        req = request([["touch", "must-not-run"]])
        batch_id = self.batch.store.create("alice", req)
        self.assertTrue(self.batch.store.begin(batch_id))
        job_id = self.store.create("alice", req.step_command(0), mode="sync")
        self.batch.store.record_step(batch_id, 0, job_id)
        self.assertTrue(self.store.begin(job_id))
        self.batch.store.admitted_step(batch_id, 0, job_id)
        self.store.finish(job_id, "failed",
                          failure_kind="pre_execution_rejected")
        with self.store._connect() as db:
            db.execute("""CREATE TRIGGER reject_parent_update
                          BEFORE UPDATE OF status ON command_batches
                          WHEN NEW.status='rejected'
                          BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END""")
        with self.assertRaises(sqlite3.DatabaseError):
            self.batch.store.finish_rejected_child(batch_id, 0, job_id)
        # The failing parent UPDATE rolled back the child step UPDATE too.
        after_failure = self.batch.get("alice", batch_id)
        self.assertEqual(after_failure["status"], "running")
        self.assertEqual(after_failure["steps"][0]["status"], "running")
        self.assertIsNone(after_failure["steps"][0]["result_status"])
        with self.store._connect() as db:
            db.execute("DROP TRIGGER reject_parent_update")
        restored = BatchStore(JobStore(self.store.path)).get("alice", batch_id)
        self.assertEqual(restored["status"], "rejected")
        self.assertEqual(restored["failure_kind"], "pre_execution_rejected")
        self.assertEqual(restored["steps"][0]["status"], "not_attempted")
        self.assertEqual(restored["steps"][0]["result_status"], "rejected")

    async def test_live_settlement_failure_preserves_child_proof_until_recovery(self):
        from app.history import HistoryStore

        async def denied_after_admission(_actor, _request, *, on_output=None,
                                         on_admitted=None):
            if on_admitted is not None:
                on_admitted()
            raise SSHDenied("sensitive remote cwd")

        # Inject failure at the same parent UPDATE used in the live _run path.
        # It must roll back step settlement without turning proven denial
        # into interrupted/unknown while the process is still running.
        with self.store._connect() as db:
            db.execute("""CREATE TRIGGER reject_live_parent_update
                          BEFORE UPDATE OF status ON command_batches
                          WHEN NEW.status='rejected'
                          BEGIN SELECT RAISE(ABORT, 'sensitive write failure'); END""")
        with patch.object(self.fake, "execute", side_effect=denied_after_admission):
            result = await self.batch.execute(
                "alice", request([["touch", "never-run"], ["echo", "later"]],
                                 stop_on_error=False),
            )

        self.assertEqual(result["status"], "running")
        self.assertIsNone(result["failure_kind"])
        self.assertEqual(result["steps"][0]["status"], "running")
        self.assertIsNone(result["steps"][0]["result_status"])
        job_id = result["steps"][0]["job_id"]
        self.assertTrue(job_id)
        child = self.jobs.get("alice", job_id)
        self.assertEqual(child["status"], "failed")
        self.assertEqual(child["failure_kind"], "pre_execution_rejected")
        self.assertEqual(result["steps"][1]["status"], "not_attempted")
        self.assertEqual(self.fake.calls, [])
        with self.store._connect() as db:
            db.execute("DROP TRIGGER reject_live_parent_update")

        # The terminal parent was deliberately not falsified. A real restart
        # can finish it from the already-durable child result, without replay.
        rebooted_jobs = JobStore(self.store.path)
        rebooted = BatchStore(rebooted_jobs)
        recovered = rebooted.get("alice", result["batch_id"])
        self.assertEqual(recovered["status"], "rejected")
        self.assertEqual(recovered["failure_kind"], "pre_execution_rejected")
        self.assertEqual(recovered["failed_step"], 0)
        self.assertEqual(recovered["steps"][0]["status"], "not_attempted")
        self.assertEqual(recovered["steps"][0]["result_status"], "rejected")
        self.assertEqual(recovered["steps"][0]["job_id"], job_id)
        self.assertEqual(recovered["steps"][1]["status"], "not_attempted")
        self.assertEqual(self.fake.calls, [])
        history = HistoryStore(rebooted_jobs).list({
            "record_kind": "all", "time_range": "all",
        })
        self.assertEqual(history["filtered_total"], 1)
        self.assertEqual([entry["id"] for entry in history["jobs"]], [job_id])

    async def test_history_retained_parent_after_rejected_child_expires(self):
        from app.history import HistoryStore

        async def denied_after_admission(_actor, _request, *, on_output=None,
                                         on_admitted=None):
            if on_admitted is not None:
                on_admitted()
            raise SSHDenied("sensitive remote cwd")

        with patch.object(self.fake, "execute", side_effect=denied_after_admission):
            result = await self.batch.execute(
                "alice", request([["touch", "never-run"], ["echo", "later"]]),
            )
        self.assertEqual(result["status"], "rejected")
        child_id = result["steps"][0]["job_id"]
        batch_id = result["batch_id"]
        history = HistoryStore(self.store)
        retained = history.list({"record_kind": "all", "time_range": "all"})
        self.assertEqual(retained["filtered_total"], 1)
        self.assertEqual(retained["jobs"][0]["id"], child_id)

        # A child completed earlier than a parent settled after recovery.
        # Expire only the child with the real retention cleanup, leaving
        # the still-recent batch manifest and its fixed failure_kind.
        with self.store._connect() as db:
            db.execute(
                "UPDATE jobs SET ended_at=? WHERE id=?",
                (time.time() - 8 * 86400, child_id),
            )
        self.assertEqual(self.store.prune(), 1)
        self.assertIsNone(self.store.get("alice", child_id))
        parent = self.batch.get("alice", batch_id)
        self.assertEqual(parent["status"], "rejected")
        self.assertEqual(parent["failure_kind"], "pre_execution_rejected")

        fallback = history.list({"record_kind": "all", "time_range": "all"})
        self.assertEqual(fallback["filtered_total"], 1)
        row = fallback["jobs"][0]
        self.assertEqual(row["id"], "batch_" + batch_id)
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["failure_kind"], "pre_execution_rejected")
        detail = history.detail("batch_" + batch_id)
        self.assertIn("rejected before command execution", detail["error"])
        self.assertIn("no batch steps ran", detail["error"])
        self.assertNotIn("Approval", detail["error"])
        self.assertNotIn("scheduled", detail["error"])
        self.assertEqual(history.stats({"time_range": "all"})["failures"], 1)
        self.assertEqual(history.totals()["failed"], 1)
        self.assertEqual(self.fake.calls, [])

    async def test_failure_before_admission_is_not_reported_as_cancellation(self):
        async def denied_before_slot(_actor, _request, *, on_output=None,
                                     on_admitted=None):
            raise SSHDenied("Synthetic pre-execution authorization rejection")

        with patch.object(self.fake, "execute", side_effect=denied_before_slot):
            result = await self.batch.execute("alice", request())
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["failure_kind"], "pre_execution_rejected")
        self.assertEqual(result["failed_step"], 0)
        step = result["steps"][0]
        self.assertEqual(step["result_status"], "rejected")
        self.assertFalse(step["attempted"])
        self.assertEqual(step["status"], "not_attempted")
        self.assertIsNotNone(step["job_id"])
        child = self.jobs.get("alice", step["job_id"])
        self.assertEqual(child["status"], "failed")
        self.assertIsNone(child["started_at"])
        self.assertIsNone(child["elapsed_seconds"])
        self.assertEqual(self.fake.calls, [])

    async def test_other_failed_child_before_admission_is_known_nonexecution(self):
        async def failed_before_slot(_actor, _request, *, on_output=None,
                                     on_admitted=None):
            raise RuntimeError("Synthetic local failure before SSH admission")

        with patch.object(self.fake, "execute", side_effect=failed_before_slot):
            result = await self.batch.execute("alice", request())
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure_kind"], "pre_execution_failure")
        self.assertEqual(result["steps"][0]["status"], "not_attempted")
        self.assertFalse(result["steps"][0]["attempted"])
        self.assertEqual(self.fake.calls, [])

    async def test_unacknowledged_child_result_remains_unknown(self):
        async def no_result(actor, command, *, on_created, on_started, max_output_bytes):
            job_id = self.store.create(actor, command, mode="sync")
            on_created(job_id)
            self.store.begin(job_id)
            on_started(job_id)
            self.store.finish(job_id, "failed")
            return job_id, None
        with patch.object(self.jobs, "execute_sync", side_effect=no_result):
            result = await self.batch.execute("alice", request())
        self.assertEqual(result["status"], "interrupted")
        self.assertEqual(result["steps"][0]["status"], "unknown")
        self.assertEqual(result["steps"][1]["status"], "not_attempted")

    async def test_unexpected_preflight_failure_is_audited_not_retried(self):
        with patch.object(self.fake, "preflight_cwd",
                          side_effect=RuntimeError("internal failure")):
            result = await self.batch.execute("alice", request(cwd="/home/alice"))
        self.assertEqual(result["status"], "interrupted")
        self.assertTrue(all(not s["attempted"] for s in result["steps"]))

    async def test_partial_step_commit_error_reconciles_unknown(self):
        def fail_once(*args, **kwargs):
            raise RuntimeError("synthetic SQLite update failure")
        with patch.object(self.batch.store, "completed_step", side_effect=fail_once):
            result = await self.batch.execute("alice", request())
        self.assertEqual(result["status"], "interrupted")
        self.assertEqual(result["steps"][0]["status"], "unknown")
        self.assertEqual(self.fake.calls, ["echo"])

    async def test_missing_child_output_is_marked_unavailable(self):
        result = await self.batch.execute("alice", request())
        first_id = result["steps"][0]["job_id"]
        with self.store._connect() as db:
            db.execute("DELETE FROM jobs WHERE id=?", (first_id,))
        restored = self.batch.get("alice", result["batch_id"])
        self.assertTrue(restored["steps"][0]["output_unavailable"])
        self.assertEqual(restored["steps"][1]["status"], "succeeded")
        with patch.object(self.jobs, "output", return_value=None):
            restored = self.batch.get("alice", result["batch_id"])
        self.assertTrue(restored["steps"][1]["output_unavailable"])

    async def test_result_response_size_gate_and_actor_paging(self):
        await self.batch.execute("alice", request())
        result = await self.batch.execute("alice", request())
        page = self.batch.list("alice", cursor=0, limit=1)
        self.assertEqual(page["next_cursor"], 1)
        self.assertEqual(len(self.batch.list("alice", cursor=1, limit=1)["batches"]), 1)
        with patch("app.batch.MAX_BATCH_RESPONSE_BYTES", 5):
            with self.assertRaisesRegex(RuntimeError, "response exceeded"):
                self.batch.get("alice", result["batch_id"])

    async def test_fallback_diagnostic_above_budget_is_output_limit(self):
        async def synthetic(_actor, req, *, on_output=None, on_admitted=None):
            if on_admitted is not None:
                on_admitted()
            return SSHResult(req.server, "transport_error", 255, "",
                             "Host key verification failed. " + "x" * 200,
                             .01)
        with patch("app.batch.MAX_BATCH_OUTPUT_BYTES", 4), patch.object(
            self.fake, "execute", side_effect=synthetic,
        ):
            result = await self.batch.execute("alice", request())
        self.assertEqual(result["status"], "output_limit")
        self.assertEqual(result["steps"][0]["status"], "output_limit")
        self.assertEqual(result["steps"][0]["output_bytes"], 4)

    async def test_shutdown_cancels_running_batch_without_auto_replay(self):
        running = asyncio.create_task(self.batch.execute(
            "alice", request([["block"], ["echo"]], timeout_seconds=10),
        ))
        await asyncio.wait_for(self.fake.started.wait(), timeout=2)
        batch_id = self.batch.list("alice")["batches"][0]["batch_id"]
        await self.batch.shutdown()
        with self.assertRaises(asyncio.CancelledError):
            await running
        result = self.batch.get("alice", batch_id)
        self.assertEqual(result["status"], "interrupted")
        self.assertEqual(result["steps"][0]["status"], "unknown")
        self.assertEqual(result["steps"][1]["status"], "not_attempted")


if __name__ == "__main__":
    unittest.main()
