"""Privileged SSH acceptance across disposable host and root policy modes.

Execute only through the separately installed, pinned lab runner.
"""
from __future__ import annotations

from tests.integration._lab_env import lab_story

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import time
from urllib.parse import quote

import httpx

from client import LabClient
from _approval_client import decision, queue, snapshot, viewer_session


def check(label: str, detail: str = "") -> None:
    print("RESULT " + label + "=PASS" + (" detail=" + detail if detail else ""), flush=True)


def call(token: str, conversation: str, name: str, args: dict) -> tuple[dict, dict | None]:
    with LabClient() as client:
        client.token = token
        client.http.headers["X-OpenAI-Session"] = conversation
        client.http.timeout = httpx.Timeout(45)
        return client.call(name, args)


def command(token: str, conversation: str, argv: list[str], *,
            privileged: bool = False, **options: object) -> tuple[dict, dict | None]:
    return call(token, conversation, "execute_command",
                LabClient.execute_args(argv, privileged=privileged, **options))


def succeeded(result: tuple[dict, dict | None], expected: str) -> str:
    envelope, data = result
    assert not envelope.get("isError") and isinstance(data, dict), "SSH command rejected"
    assert data.get("status") == "succeeded" and data.get("exit_code") == 0
    assert data.get("stdout", "").strip() == expected, "Wrong disposable SSH identity"
    if expected == "root":
        assert data.get("root_started") is True
    else:
        assert data.get("root_started") is not True
    output = str(data.get("stdout", "")) + str(data.get("stderr", ""))
    assert "SSH-MCP-ROOT-" not in output and "\x1e" not in output, "Root marker leaked"
    return str(data["job_id"])


def audited(token: str, conversation: str, job_id: str) -> None:
    result, data = call(token, conversation, "get_job", {"job_id": job_id})
    assert not result.get("isError") and data and isinstance(data.get("job"), dict)
    job = data["job"]
    assert job["privileged"] is True and job["run_as"] == "root"
    assert job["root_started"] is True
    assert job["request"]["argv"] == ["id", "-un"], "Audit contains wrapper, not original"


def run_unrestricted(token: str, mode: str) -> None:
    conversation = "v1/sky267-" + mode
    succeeded(command(token, conversation, ["id", "-un"]), "tester")
    check("ordinary_gateway_behavior")
    if mode == "none":
        result, _ = command(token, conversation, ["id", "-un"], privileged=True)
        assert result.get("isError"), "Missing privileged policy unexpectedly executed root"
        check("missing_root_policy_denied_before_ssh")
        return

    denied, data = command(token, conversation, ["sudo", "-n", "id", "-un"])
    assert not denied.get("isError") and data and data["status"] == "command_error", (
        "Disposable tester gained passwordless sudo"
    )
    check("passwordless_sudo_unavailable")
    job_id = succeeded(command(token, conversation, ["id", "-un"], privileged=True), "root")
    audited(token, conversation, job_id)
    check("passworded_root_and_retained_audit")
    browser, _ = viewer_session()
    with closing(browser):
        # In all-automatic policy no approval manager is instantiated;
        # History may omit approval snapshot keys entirely.
        assert not snapshot(browser).get("active_grants", [])
    check("always_granted_root_has_no_timed_approval")

    result, data = call(token, conversation, "submit_job",
                        LabClient.execute_args(["id", "-un"], privileged=True))
    assert not result.get("isError") and data and data["job"]["id"]
    submitted = data["job"]["id"]
    for _ in range(90):
        _, fetched = call(token, conversation, "get_job", {"job_id": submitted})
        if fetched and fetched["job"]["status"] in {"succeeded", "failed", "timed_out"}:
            break
        time.sleep(.1)
    else:
        raise AssertionError("Durable privileged job did not terminate")
    assert fetched and fetched["job"]["status"] == "succeeded"
    assert fetched["job"]["run_as"] == "root" and fetched["job"]["root_started"] is True
    check("durable_privileged_submit_job")

    result, data = call(token, conversation, "execute_commands", {
        "server": "fixture", "privileged": True, "reason": "isolated privileged batch",
        "story_id": lab_story(), "commands": [{"argv": ["id", "-un"]},
                                             {"argv": ["id", "-un"]}],
    })
    assert not result.get("isError") and data and data["status"] == "succeeded"
    assert len(data["steps"]) == 2
    for step in data["steps"]:
        assert step["status"] == "succeeded" and step["attempted"]
        assert step["job_id"] and step["exit_accepted"] is True
        audited(token, conversation, step["job_id"])
    check("two_step_passworded_privileged_batch")


def root_request(token: str, conversation: str) -> tuple[dict, dict | None]:
    return command(token, conversation, ["id", "-un"], privileged=True)


def run_restricted(token: str, mode: str) -> None:
    combined = mode == "combined"
    conversation = "v1/sky267-" + mode
    browser, csrf = viewer_session()
    with closing(browser), ThreadPoolExecutor(max_workers=4) as pool:
        initial = pool.submit(root_request, token, conversation)
        pending = queue(browser, initial, conversation)
        assert pending["host"] == "fixture"
        assert pending["requires_root"] is True
        assert pending["requires_host"] is combined
        assert pending["steps"] and pending["steps"][0]["command"]
        check("root_approval_scope_and_complete_preview", mode)
        decision(browser, csrf, pending["id"], "grant", "5m")
        root_job = succeeded(initial.result(timeout=8), "root")
        audited(token, conversation, root_job)
        grants = snapshot(browser)["active_grants"]
        assert len(grants) == (2 if combined else 1)
        assert {g["kind"] for g in grants} == ({"host", "root"} if combined else {"root"})
        if combined:
            assert grants[0]["scope_id"] == grants[1]["scope_id"]
        check("timed_root_grant_and_paired_host_scope", mode)
        succeeded(root_request(token, conversation), "root")
        check("same_conversation_reuses_timed_root_grant")

        other = conversation + "-other"
        unrelated = pool.submit(root_request, token, other)
        waiting = queue(browser, unrelated, other)
        decision(browser, csrf, waiting["id"], "deny")
        assert unrelated.result(timeout=8)[0].get("isError")
        check("root_grant_does_not_cross_conversations")

        root = next(g for g in grants if g["kind"] == "root")
        removed = browser.post("/console/api/grants/" + quote(root["id"], safe="") + "/revoke",
                               data={"csrf": csrf}, headers={"Origin": "http://localhost"})
        assert removed.status_code == 200
        assert isinstance(removed.json()["approval_revision"], int)
        assert not any(g["kind"] == "root" for g in snapshot(browser)["active_grants"])
        if combined:
            assert any(g["kind"] == "host" for g in snapshot(browser)["active_grants"])
        check("revoke_root_does_not_revoke_host")

        again = pool.submit(root_request, token, conversation)
        waiting = queue(browser, again, conversation)
        assert waiting["requires_root"] is True and waiting["requires_host"] is False
        decision(browser, csrf, waiting["id"], "deny")
        assert again.result(timeout=8)[0].get("isError")
        check("root_revoke_blocks_subsequent_execution")

        succeeded(command(token, conversation, ["id", "-un"]), "tester")
        if combined:
            host = next(g for g in snapshot(browser)["active_grants"] if g["kind"] == "host")
            response = browser.post("/console/api/grants/" + quote(host["id"], safe="") +
                                    "/revoke", data={"csrf": csrf},
                                    headers={"Origin": "http://localhost"})
            assert response.status_code == 200
            assert snapshot(browser)["active_grants"] == []
            check("host_revoke_clears_access_after_root_revoke")
        else:
            assert snapshot(browser)["active_grants"] == []
            check("sudo_only_revoke_preserves_ordinary_host")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True,
                        choices=("none", "auto", "sudo-only", "combined"))
    mode = parser.parse_args().mode
    assert lab_story(), "Run via the isolated lab test runner"
    with LabClient() as bootstrap:
        bootstrap.authorize()
        assert bootstrap.token
        if mode in {"none", "auto"}:
            run_unrestricted(bootstrap.token, mode)
        else:
            run_restricted(bootstrap.token, mode)
    check("sky267_isolated_privileged_acceptance", mode)


if __name__ == "__main__":
    main()
