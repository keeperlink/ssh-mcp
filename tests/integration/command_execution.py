"""End-to-end SSH command execution using the disposable lab fixture.

Executed through the separately installed, pinned runner; no real host access.
"""
from __future__ import annotations

import os
import time

from client import LabClient

passed = 0
failed = 0


def case(name: str, callback) -> None:
    global passed, failed
    start = time.monotonic()
    try:
        value = callback()
    except Exception as exc:
        failed += 1
        print(f"RESULT {name}=FAIL elapsed_ms={1000*(time.monotonic()-start):.0f} "
              f"error={type(exc).__name__}: {str(exc)[:160]}", flush=True)
    else:
        passed += 1
        print(f"RESULT {name}=PASS elapsed_ms={1000*(time.monotonic()-start):.0f} "
              f"detail={value or 'ok'}", flush=True)


with LabClient() as client:
    client.authorize()

    def execute(argv: list[str], **opts):
        return client.call("execute_command", client.execute_args(argv, **opts))

    def nonzero_result():
        result, value = execute(["sh", "-c", "echo synthetic-diagnostic >&2; exit 2"])
        assert not result.get("isError"), result
        assert value and value["status"] == "command_error", value
        assert value["exit_code"] == 2 and value["exit_accepted"] is False, value
        assert "synthetic-diagnostic" in value["stderr"], value
        assert value["job_id"] and value["request_id"], value
        return "status=command_error exit=2 isError=false"

    case("structured_nonzero_exit", nonzero_result)

    def accepted_nonzero():
        result, value = execute(
            ["sh", "-c", "exit 1"], success_exit_codes=[0, 1],
        )
        assert not result.get("isError") and value, value
        assert value["status"] == "succeeded" and value["exit_code"] == 1, value
        assert value["exit_accepted"] is True, value
        history, saved = client.call("get_job", {"job_id": value["job_id"]})
        assert not history.get("isError") and saved, saved
        assert saved["job"]["status"] == "succeeded", saved
        assert saved["job"]["exit_code"] == 1 and saved["job"]["exit_accepted"] is True, saved
        assert saved["job"]["request"]["success_exit_codes"] == [0, 1], saved
        return "exit=1 accepted=true persisted=true"

    case("accepted_nonzero_and_history", accepted_nonzero)

    def strict_pipeline():
        result, value = execute(
            ["bash", "-lc", "false | true; echo should-not-appear"],
            strict_bash=True,
        )
        assert not result.get("isError") and value, value
        assert value["status"] == "command_error" and value["exit_code"] != 0, value
        assert "should-not-appear" not in value["stdout"], value
        return "pipeline_failed_before_following_statement"

    case("strict_bash_pipefail", strict_pipeline)

    def default_bash():
        result, value = execute(
            ["bash", "-lc", "false | true; echo default-keeps-going"],
        )
        assert not result.get("isError") and value, value
        assert value["status"] == "succeeded" and value["exit_code"] == 0, value
        assert "default-keeps-going" in value["stdout"], value
        return "default_preserved"

    case("default_bash_compatibility", default_bash)

    def strict_nounset():
        result, value = execute(
            ["bash", "-c", 'echo "$SKY247_NOT_DEFINED"; echo should-not-appear'],
            strict_bash=True,
        )
        assert not result.get("isError") and value, value
        assert value["status"] == "command_error" and value["exit_code"] != 0, value
        assert "should-not-appear" not in value["stdout"], value
        return "unset_variable_rejected"

    case("strict_bash_unset_variable", strict_nounset)

    def canonical_cwd():
        result, value = execute(["pwd"], cwd="/home/tester")
        assert not result.get("isError") and value, value
        assert value["stdout"].strip() == "/home/tester", value
        assert value["effective_cwd"] == "/home/tester", value
        assert value["exit_accepted"] is True, value
        return "effective_cwd=/home/tester"

    case("remote_cwd", canonical_cwd)

    def absent_command_with_cwd():
        result, value = execute(
            ["/home/tester/sky247-program-does-not-exist"], cwd="/home/tester",
        )
        assert not result.get("isError") and value, value
        assert value["status"] == "command_error" and value["exit_code"] == 127, value
        assert value["exit_accepted"] is False, value
        assert "Command not found" in value["stderr"], value
        history, saved = client.call("get_job", {"job_id": value["job_id"]})
        assert not history.get("isError") and saved, saved
        assert saved["job"]["status"] == "failed" and saved["job"]["exit_code"] == 127, saved
        return "exit=127 command_error isError=false history=failed"

    case("cwd_missing_command_is_not_transport", absent_command_with_cwd)

    def accepted_absent_command():
        result, value = execute(
            ["/home/tester/sky247-program-does-not-exist"],
            cwd="/home/tester", success_exit_codes=[0, 127],
        )
        assert not result.get("isError") and value, value
        assert value["status"] == "succeeded" and value["exit_code"] == 127, value
        assert value["exit_accepted"] is True, value
        return "exit=127 accepted=true"

    case("cwd_missing_command_accepted", accepted_absent_command)

    def nonexecutable_command_with_cwd():
        path = "/home/tester/sky247-not-executable"
        result, value = execute(["touch", path])
        assert not result.get("isError") and value["status"] == "succeeded", value
        result, value = execute(["chmod", "0644", path])
        assert not result.get("isError") and value["status"] == "succeeded", value
        result, value = execute([path], cwd="/home/tester")
        assert not result.get("isError") and value, value
        assert value["status"] == "command_error" and value["exit_code"] == 126, value
        assert value["exit_accepted"] is False, value
        assert "not executable" in value["stderr"], value
        return "exit=126 command_error isError=false"

    case("cwd_nonexecutable_command_is_not_transport", nonexecutable_command_with_cwd)

    def accepted_nonexecutable_command():
        result, value = execute(
            ["/home/tester/sky247-not-executable"],
            cwd="/home/tester", success_exit_codes=[0, 126],
        )
        assert not result.get("isError") and value, value
        assert value["status"] == "succeeded" and value["exit_code"] == 126, value
        assert value["exit_accepted"] is True, value
        return "exit=126 accepted=true"

    case("cwd_nonexecutable_command_accepted", accepted_nonexecutable_command)

    def safe_symlink():
        result, created = execute(["ln", "-sfn", "/home/tester", "/home/tester/sky247-link"])
        assert not result.get("isError") and created["status"] == "succeeded", created
        result, value = execute(["pwd"], cwd="/home/tester/sky247-link")
        assert not result.get("isError") and value, value
        assert value["stdout"].strip() == "/home/tester", value
        assert value["effective_cwd"] == "/home/tester", value
        return "symlink_resolved_and_audited"

    case("resolved_cwd_symlink", safe_symlink)

    def path_with_space():
        result, made = execute(["mkdir", "-p", "/home/tester/sky247 dir"])
        assert not result.get("isError") and made["status"] == "succeeded", made
        result, value = execute(["pwd"], cwd="/home/tester/sky247 dir")
        assert not result.get("isError") and value, value
        assert value["stdout"].strip() == "/home/tester/sky247 dir", value
        assert value["effective_cwd"] == "/home/tester/sky247 dir", value
        return "argv_quoted_and_path_preserved"

    case("cwd_path_with_spaces", path_with_space)

    def denied_cwd():
        result, value = execute(["touch", "/home/tester/sky247-should-not-exist"],
                                cwd="/root")
        assert result.get("isError"), result
        result, check = execute(["test", "!", "-e", "/home/tester/sky247-should-not-exist"])
        assert not result.get("isError") and check["status"] == "succeeded", check
        return "blocked_before_command_execution"

    case("inaccessible_cwd_rejected", denied_cwd)

    def invalid_relative_cwd():
        result, _ = execute(["pwd"], cwd="relative")
        assert result.get("isError"), result
        return "relative_cwd_validation_rejected"

    case("invalid_relative_cwd", invalid_relative_cwd)

    def reject_exit_255():
        result, _ = execute(["sh", "-c", "exit 255"], success_exit_codes=[0, 255])
        assert result.get("isError"), result
        return "255_cannot_be_accepted"

    case("reject_ssh_exit_255", reject_exit_255)

    def async_accepted_cwd():
        result, data = client.call(
            "submit_job",
            client.execute_args(
                ["sh", "-c", "exit 1"],
                cwd="/home/tester/sky247-link",
                success_exit_codes=[0, 1],
                strict_bash=False,
            ),
        )
        assert not result.get("isError") and data, data
        job_id = data["job"]["id"]
        for _ in range(70):
            time.sleep(.07)
            result, history = client.call("get_job", {"job_id": job_id})
            assert not result.get("isError") and history, history
            job = history["job"]
            if job["status"] not in ("running", "queued"):
                break
        assert job["status"] == "succeeded", job
        assert job["exit_code"] == 1 and job["exit_accepted"] is True, job
        assert job["effective_cwd"] == "/home/tester", job
        assert job["request"]["cwd"] == "/home/tester/sky247-link", job
        return "async_exit_accepted_and_cwd_audit=true"

    case("async_accepted_exit_with_cwd", async_accepted_cwd)

    def unauthorized_real_host():
        request = client.execute_args(["id", "-un"])
        request["server"] = "demo-fixture"
        result, _ = client.call("execute_command", request)
        assert result.get("isError"), result
        return "real_lab_host_denied"

    case("real_host_denied", unauthorized_real_host)

print(f"PR1_SUMMARY passed={passed} failed={failed} story={os.environ.get('SSH_MCP_TEST_STORY','unknown')}",
      flush=True)
raise SystemExit(1 if failed else 0)
