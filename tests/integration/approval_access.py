"""Live restricted host approval and SSE acceptance on the disposable SSH fixture.

Invoke only via the separately pinned lab runner, never against real hosts.
"""
from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import closing
import json
import time
from urllib.parse import quote

import httpx

from client import LabClient
from _approval_client import ORIGIN, decision, queue, snapshot, viewer_session



def check(name: str, fn):
    start = time.monotonic()
    value = fn()
    print(f"RESULT {name}=PASS elapsed_ms={int((time.monotonic()-start)*1000)}"
          + (f" detail={value}" if value else ""), flush=True)
    return value








def rpc_request(token: str, conversation: str, argv: list[str]) -> tuple[dict, dict | None]:
    with LabClient() as worker:
        worker.token = token
        worker.http.headers["X-OpenAI-Session"] = conversation
        worker.http.timeout = httpx.Timeout(42)
        return worker.call("execute_command", worker.execute_args(argv))




def approved(future: Future) -> None:
    result, data = future.result(timeout=8)
    assert not result.get("isError") and data, "Approved request failed"
    assert data["status"] == "succeeded" and data["stdout"].strip() == "tester", (
        "Approved request did not execute on the disposable SSH fixture"
    )


def denied(future: Future) -> None:
    result, _ = future.result(timeout=8)
    assert result.get("isError"), "Denied request unexpectedly executed"


def next_sse_approval(lines) -> dict:
    for line in lines:
        if line == "event: approval":
            raw = next(lines)
            assert raw.startswith("data: "), "SSE event lacks JSON"
            return json.loads(raw[6:])
    raise AssertionError("SSE approval stream ended unexpectedly")


def sse_initial(browser: httpx.Client) -> None:
    with browser.stream("GET", "/console/api/approval-events", timeout=8) as response:
        assert response.status_code == 200, "SSE viewer authorization rejected"
        assert response.headers.get("content-type", "").startswith("text/event-stream")
        payload = next_sse_approval(response.iter_lines())
        assert "pending_approvals" in payload and "active_grants" in payload
        assert "approval_instance" in payload and "approval_revision" in payload


def sse_queued(browser: httpx.Client, pool: ThreadPoolExecutor, token: str,
               conversation: str) -> tuple[Future, dict]:
    # The SSE connection must already exist when the queued operation arrives.
    # This verifies an actual push, not just the reconnect snapshot.
    with browser.stream("GET", "/console/api/approval-events", timeout=8) as response:
        assert response.status_code == 200, "SSE viewer session rejected"
        events = response.iter_lines()
        initial = next_sse_approval(events)
        assert "approval_revision" in initial
        future = pool.submit(rpc_request, token, conversation, ["id", "-un"])
        changed = next_sse_approval(events)
        matches = [item for item in changed["pending_approvals"]
                   if item["conversation_id"] == conversation]
        assert len(matches) == 1, "SSE did not push new pending approval"
        assert changed["approval_revision"] > initial["approval_revision"]
        assert not future.done(), "SSH executed before SSE operator decision"
        return future, matches[0]


def main() -> None:
    with LabClient() as bootstrap:
        bootstrap.authorize()
        token = bootstrap.token
        assert token, "OAuth login did not return approved test token"
        with ThreadPoolExecutor(max_workers=3) as pool:
            browser, csrf = viewer_session()
            # viewer_session already used this client to log in. httpx
            # refuses a second __enter__; close the existing client instead.
            with closing(browser):
                check("viewer_login_and_sse_initial", lambda: sse_initial(browser))
                assert browser.post("/console/api/grants/bogus/revoke",
                                    data={"csrf": csrf}).status_code == 403
                check("grant_requires_same_origin", lambda: "csrf_guarded")

                first = "v1/sky263-restricted-once"
                call, request = sse_queued(browser, pool, token, first)
                assert request["host"] == "fixture" and request["tool"] == "execute_command"
                assert request["summary"] and request["expires_at"] > time.time()
                check("live_sse_push_and_ssh_wait_before_grant", lambda: "host=fixture")
                decision(browser, csrf, request["id"], "grant")
                check("one_request_grant_executes_real_ssh", lambda: approved(call))

                denied_call = pool.submit(rpc_request, token, first, ["id", "-un"])
                blocked = queue(browser, denied_call, first)
                decision(browser, csrf, blocked["id"], "deny")
                check("one_shot_consumed_then_deny", lambda: denied(denied_call))
                assert snapshot(browser)["active_grants"] == []

                timed = "v1/sky263-restricted-timed"
                pending_call = pool.submit(rpc_request, token, timed, ["id", "-un"])
                queued = queue(browser, pending_call, timed)
                decision(browser, csrf, queued["id"], "grant", "5m")
                check("timed_grant_executes_real_ssh", lambda: approved(pending_call))
                # Same verified OAuth sid and conversation may reuse this exact grant.
                immediate = pool.submit(rpc_request, token, timed, ["id", "-un"])
                check("same_conversation_reuses_timed_grant", lambda: approved(immediate))
                grant_list = snapshot(browser)["active_grants"]
                assert len(grant_list) == 1 and grant_list[0]["host"] == "fixture"

                other = "v1/sky263-restricted-other"
                cross_call = pool.submit(rpc_request, token, other, ["id", "-un"])
                cross = queue(browser, cross_call, other)
                decision(browser, csrf, cross["id"], "deny")
                check("cross_conversation_grant_isolation", lambda: denied(cross_call))

                grant_id = quote(grant_list[0]["id"], safe="")
                revoked = browser.post(f"/console/api/grants/{grant_id}/revoke",
                                       data={"csrf": csrf}, headers={"Origin": ORIGIN})
                assert revoked.status_code == 200
                assert snapshot(browser)["active_grants"] == []
                after_revoke = pool.submit(rpc_request, token, timed, ["id", "-un"])
                expired = queue(browser, after_revoke, timed)
                decision(browser, csrf, expired["id"], "deny")
                check("revoke_prevents_new_ssh_execution", lambda: denied(after_revoke))
                check("restricted_acceptance_summary", lambda: "all_passed")


if __name__ == "__main__":
    main()
