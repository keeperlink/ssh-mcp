"""Live sealed-v2 acceptance against the disposable LAB SSH and MCP fixtures.

Requires ssh-mcp-test setup --credentials sealed-v2 --access restricted
--privileged-access restricted. Uses only generated passwords and the pinned
test client's internal-only network; never contacts a real SSH host.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import os
from urllib.parse import quote

import httpx

from client import LabClient
from _approval_client import ORIGIN, queue, snapshot, viewer_session
from tests.integration._lab_env import lab_story, lab_url


def check(name: str) -> None:
    print(f"RESULT {name}=PASS", flush=True)


def root_request(token: str, conversation: str) -> tuple[dict, dict | None]:
    with LabClient() as client:
        client.token = token
        client.http.headers["X-OpenAI-Session"] = conversation
        client.http.timeout = httpx.Timeout(45)
        return client.call(
            "execute_command",
            client.execute_args(["id", "-un"], privileged=True),
        )


def root_succeeded(result: tuple[dict, dict | None]) -> None:
    envelope, data = result
    assert not envelope.get("isError") and data is not None, "Sealed root command denied"
    assert data["status"] == "succeeded" and data["exit_code"] == 0
    assert data["stdout"].strip() == "root" and data["root_started"] is True


def decide(browser: httpx.Client, csrf: str, approval_id: str, *,
           duration: str, password: str, grant: bool = True) -> httpx.Response:
    action = "grant" if grant else "deny"
    return browser.post(
        "/console/api/approvals/" + quote(approval_id, safe="") + "/" + action,
        data={"csrf": csrf, "duration": duration, "console_password": password},
        headers={"Origin": ORIGIN},
    )


def metrics_acceptance() -> None:
    token = os.environ["MCP_METRICS_TOKEN"]
    with httpx.Client(base_url=lab_url(), trust_env=False,
                      headers={"Host": "localhost"}, timeout=8) as client:
        denied = client.get("/metrics")
        wrong = client.get("/metrics", headers={"Authorization": "Bearer " + token + "wrong"})
        valid = client.get("/metrics", headers={"Authorization": "Bearer " + token})
    assert denied.status_code == 401 and wrong.status_code == 401
    assert valid.status_code == 200 and "ssh_mcp_jobs" in valid.text
    check("sealed_metrics_bearer_verifier")


def main() -> None:
    assert lab_story(), "Run only via the pinned disposable LAB harness"
    metrics_acceptance()
    with LabClient() as bootstrap:
        bootstrap.authorize()
        token = bootstrap.token
        assert token, "Sealed OAuth verifier rejected synthetic login"
        check("sealed_oauth_login_verifier")
        status, data = bootstrap.call("list_servers", {})
        assert not status.get("isError") and data
        assert "fixture" in data["servers"] and data["servers"]["fixture"]["status"] == "active"
        check("sealed_locked_host_remains_ssh_discoverable")
        browser, csrf = viewer_session()
        with closing(browser), ThreadPoolExecutor(max_workers=4) as pool:
            check("sealed_console_login_verifier")
            conversation = "v1/sky347-sealed-v2"
            pending_root = pool.submit(root_request, token, conversation)
            pending = queue(browser, pending_root, conversation)
            assert pending["requires_root"] is True
            assert pending["requires_host"] is True
            original_id = pending["id"]
            original_deadline = pending["expires_at"]
            bad = decide(browser, csrf, original_id, duration="5m",
                         password="wrong-synthetic-console-password")
            assert bad.status_code == 403 and bad.json()["error"] == "Incorrect Console password."
            current = next(p for p in snapshot(browser)["pending_approvals"]
                           if p["id"] == original_id)
            assert current["expires_at"] == original_deadline
            assert not pending_root.done()
            check("sealed_wrong_password_keeps_pending_deadline")
            allowed = decide(browser, csrf, original_id, duration="5m",
                             password=os.environ["HISTORY_VIEWER_PASSWORD"])
            assert allowed.status_code == 200, "Fresh sealed sudo proof refused"
            root_succeeded(pending_root.result(timeout=10))
            check("sealed_fresh_console_unlock_and_sudo_proof")

            root_succeeded(root_request(token, conversation))
            check("sealed_reuse_of_same_timed_grant")
            other = conversation + "-other"
            cross = pool.submit(root_request, token, other)
            cross_pending = queue(browser, cross, other)
            denied = decide(browser, csrf, cross_pending["id"], duration="once",
                            password="", grant=False)
            assert denied.status_code == 200 and cross.result(timeout=10)[0].get("isError")
            check("sealed_cross_conversation_isolation")

            with LabClient() as worker:
                worker.token = token
                worker.http.headers["X-OpenAI-Session"] = conversation
                worker.http.timeout = httpx.Timeout(45)
                result, data = worker.call("execute_commands", {
                    "server": "fixture", "privileged": True,
                    "reason": "synthetic sealed root batch",
                    "story_id": lab_story(), "commands": [
                        {"argv": ["id", "-un"]}, {"argv": ["id", "-un"]},
                    ],
                })
            assert not result.get("isError") and data
            assert data["status"] == "succeeded" and len(data["steps"]) == 2
            assert all(step["status"] == "succeeded"
                       and step["root_started"] is True for step in data["steps"])
            check("sealed_timed_grant_two_step_root_batch")

            grants = snapshot(browser)["active_grants"]
            assert {g["kind"] for g in grants} == {"host", "root"}
            root = next(g for g in grants if g["kind"] == "root")
            revoked = browser.post(
                "/console/api/grants/" + quote(root["id"], safe="") + "/revoke",
                data={"csrf": csrf}, headers={"Origin": ORIGIN},
            )
            assert revoked.status_code == 200
            assert not any(g["kind"] == "root" for g in snapshot(browser)["active_grants"])
            check("sealed_revocation_discards_root_unlock")
            again = pool.submit(root_request, token, conversation)
            second_pending = queue(browser, again, conversation)
            denied = decide(browser, csrf, second_pending["id"], duration="once",
                            password="", grant=False)
            assert denied.status_code == 200 and again.result(timeout=10)[0].get("isError")
            check("sealed_revoked_issuance_cannot_be_reused")

            root_only = pool.submit(root_request, token, conversation)
            third_pending = queue(browser, root_only, conversation)
            correct = decide(browser, csrf, third_pending["id"], duration="5m",
                             password=os.environ["HISTORY_VIEWER_PASSWORD"])
            assert correct.status_code == 200
            root_succeeded(root_only.result(timeout=10))
            logout = browser.post("/console/logout", data={"csrf": csrf},
                                  headers={"Origin": ORIGIN})
            assert logout.status_code == 303
            check("sealed_console_logout_revokes_root_grant")
            with closing(viewer_session()[0]) as fresh:
                current = snapshot(fresh)["active_grants"]
                assert not any(g["kind"] == "root" for g in current)
                assert any(g["kind"] == "host" for g in current)
            check("sealed_logout_preserves_ordinary_host_grant")
    check("sealed_v2_synthetic_lab_acceptance_summary")


if __name__ == "__main__":
    main()
