"""End-to-end bounded command batches using the disposable SSH lab fixture.

Execute only through the separately installed, pinned runner.
"""
from __future__ import annotations

import base64
import json
import os
import time

from client import LabClient

passed = 0
failed = 0


def check(name, fn):
    global passed, failed
    start = time.monotonic()
    try:
        detail = fn()
    except Exception as exc:
        failed += 1
        print(f"RESULT {name}=FAIL ms={1000*(time.monotonic()-start):.0f} "
              f"error={type(exc).__name__}: {str(exc)[:180]}", flush=True)
    else:
        passed += 1
        print(f"RESULT {name}=PASS ms={1000*(time.monotonic()-start):.0f} "
              f"detail={detail or 'ok'}", flush=True)


def step(argv, **opts):
    return {"argv": argv, **opts}


with LabClient() as c:
    c.authorize()

    def batch(commands, **opts):
        return c.call("execute_commands", {
            "server": "fixture", "commands": commands,
            "reason": "TEST-247: isolated batch acceptance",
            "story_id": os.environ["SSH_MCP_TEST_STORY"], **opts,
        })

    def absent(path):
        result, value = c.call("execute_command", c.execute_args(["test", "!", "-e", path]))
        assert not result.get("isError") and value["status"] == "succeeded", value

    def ordered_audit():
        r, b = batch([step(["printf", "one"]), step(["sh", "-c", "echo two >&2"]),
                      step(["pwd"])], cwd="/home/tester")
        assert not r.get("isError") and b["status"] == "succeeded", b
        assert [s["status"] for s in b["steps"]] == ["succeeded"] * 3, b
        assert b["effective_cwd"] == "/home/tester", b
        assert b["steps"][0]["stdout"] == "one", b
        assert "two" in b["steps"][1]["stderr"], b
        assert b["steps"][2]["stdout"].strip() == "/home/tester", b
        for s in b["steps"]:
            assert s["job_id"] and s["exit_accepted"] is True, s
            r, job = c.call("get_job", {"job_id": s["job_id"]})
            assert not r.get("isError") and job["job"]["status"] == "succeeded", job
        return "ordered_and_persisted=3"

    check("three_ordered_steps_and_job_history", ordered_audit)

    def stop_on_second_failure():
        path = "/home/tester/sky247-pr2-should-not-create"
        r, b = batch([step(["printf", "ok"]), step(["sh", "-c", "exit 2"]),
                      step(["touch", path])])
        assert not r.get("isError") and b["status"] == "failed", b
        assert b["failed_step"] == 1, b
        assert [s["status"] for s in b["steps"]] == [
            "succeeded", "failed", "not_attempted"], b
        assert b["steps"][1]["exit_code"] == 2, b
        assert b["steps"][2]["job_id"] is None, b
        absent(path)
        return "step3=not_attempted"

    check("second_failure_stops_third", stop_on_second_failure)

    def accepted_nonzero_continues():
        r, b = batch([step(["sh", "-c", "exit 1"], success_exit_codes=[0, 1]),
                      step(["printf", "continued"])])
        assert not r.get("isError") and b["status"] == "succeeded", b
        assert b["steps"][0]["exit_code"] == 1 and b["steps"][0]["exit_accepted"], b
        assert b["steps"][1]["stdout"] == "continued", b
        return "accepted_exit1"

    check("accepted_exit_code", accepted_nonzero_continues)

    def keep_going_explicitly():
        r, b = batch([step(["sh", "-c", "exit 2"]), step(["printf", "continued"])],
                     stop_on_error=False)
        assert not r.get("isError") and b["status"] == "failed", b
        assert [s["status"] for s in b["steps"]] == ["failed", "succeeded"], b
        return "known_failure_followed_by_success"

    check("explicit_continue_on_known_failure", keep_going_explicitly)

    def bash_strict():
        path = "/home/tester/sky247-pr2-strict-not-created"
        r, b = batch([step(["bash", "-lc", "false | true; echo not-shown"]),
                      step(["touch", path])], strict_bash=True)
        assert not r.get("isError") and b["status"] == "failed", b
        assert b["steps"][1]["status"] == "not_attempted", b
        assert "not-shown" not in b["steps"][0]["stdout"], b
        absent(path)
        return "pipefail_and_stop"

    check("strict_bash_shared", bash_strict)

    def invalid_later_step():
        path = "/home/tester/sky247-pr2-invalid-must-not-create"
        r, b = batch([step(["touch", path]), step(["bash", "-c"]),
                      step(["printf", "never"])], strict_bash=True)
        assert r.get("isError") and b["status"] == "rejected", b
        assert b["steps_attempted"] == 0 and b["failed_step"] == 1, b
        absent(path)
        return "preflight_zero_attempts"

    check("later_step_invalid_without_side_effects", invalid_later_step)

    def denied_cwd():
        r, b = batch([step(["touch", "/home/tester/sky247-pr2-private"]),
                      step(["pwd"])], cwd="/root")
        assert r.get("isError") and b["status"] == "rejected", b
        assert b["failed_field"] == "cwd", b
        assert all(s["status"] == "not_attempted" for s in b["steps"]), b
        return "inaccessible_cwd_did_not_execute"

    check("remote_cwd_preflight", denied_cwd)

    def recovery_and_pagination():
        r, b = batch([step(["printf", "alpha"]), step(["printf", "beta"]),
                      step(["printf", "gamma"])])
        assert not r.get("isError") and b["status"] == "succeeded", b
        batch_id = b["batch_id"]
        r, first = c.call("get_batch", {"batch_id": batch_id, "limit": 2})
        assert not r.get("isError") and first["next_cursor"] == 2, first
        r, last = c.call("get_batch", {"batch_id": batch_id, "cursor": 2})
        assert not r.get("isError") and len(last["steps"]) == 1, last
        r, found = c.call("list_batches", {"limit": 10})
        assert not r.get("isError") and any(
            s["batch_id"] == batch_id for s in found["batches"]), found
        r, output = c.call("get_job_output", {
            "job_id": b["steps"][0]["job_id"], "max_bytes": 64,
        })
        assert not r.get("isError"), r
        data = b"".join(base64.b64decode(ch["data_base64"])
                        for ch in output["chunks"])
        assert data == b"alpha", data
        return "batch_id_and_step_job_recovered"

    check("get_batch_list_batches_and_output", recovery_and_pagination)

    def max_five():
        r, b = batch([step(["printf", str(i)]) for i in range(5)])
        assert not r.get("isError") and b["status"] == "succeeded", b
        assert b["total_steps"] == 5 and len(b["steps"]) == 5, b
        assert "".join(s["stdout"] for s in b["steps"]) == "01234", b
        return "five_steps_sequential"

    check("maximum_five_steps", max_five)

    def timeout_stops():
        path = "/home/tester/sky247-pr2-timeout-not-created"
        r, b = batch([step(["printf", "before"]), step(["sleep", "3"], timeout_seconds=1),
                      step(["touch", path])], timeout_seconds=5)
        assert r.get("isError") and b["status"] == "timed_out", b
        assert b["failed_step"] == 1 and b["steps"][2]["status"] == "not_attempted", b
        absent(path)
        return "timeout_then_skip"

    check("timeout_without_unsafe_retry", timeout_stops)

    def bounded_large_output():
        r, b = batch([step(["python3", "-c", "import sys;sys.stdout.write('x'*210000)"]),
                      step(["printf", "never"])])
        assert r.get("isError") and b["status"] == "output_limit", b
        assert b["steps"][0]["status"] == "output_limit", b
        assert b["steps"][1]["status"] == "not_attempted", b
        assert b["steps"][0]["output_truncated"], b
        assert len(json.dumps(b).encode()) <= 262144, b
        return "aggregate_response_bounded"

    check("bounded_aggregate_output", bounded_large_output)

    def unauthorized_host():
        r, b = c.call("execute_commands", {
            "server": "demo-fixture", "commands": [step(["id", "-un"])],
            "reason": "TEST-247 synthetic denied host",
            "story_id": os.environ["SSH_MCP_TEST_STORY"],
        })
        assert r.get("isError"), r
        return "unapproved_host_denied"

    check("real_host_not_authorized", unauthorized_host)

print(f"PR2_SUMMARY passed={passed} failed={failed} "
      f"story={os.environ.get('SSH_MCP_TEST_STORY','unknown')}", flush=True)
raise SystemExit(1 if failed else 0)
