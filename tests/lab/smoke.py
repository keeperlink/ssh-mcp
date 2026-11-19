"""Standard isolated OAuth/MCP/SSH smoke; story-specific tests run separately."""
from __future__ import annotations

import os
import sys
import time

from client import LabClient

failed = 0
passed = 0


def check(name: str, callback) -> None:
    global failed, passed
    start = time.monotonic()
    try:
        detail = callback()
    except Exception as exc:
        failed += 1
        print(f"RESULT {name}=FAIL elapsed_ms={1000*(time.monotonic()-start):.0f} "
              f"error={type(exc).__name__}: {str(exc)[:180]}", flush=True)
    else:
        passed += 1
        print(f"RESULT {name}=PASS elapsed_ms={1000*(time.monotonic()-start):.0f}"
              + (f" detail={detail}" if detail else ""), flush=True)


with LabClient() as c:
    def health(path: str) -> str:
        r = c.http.get(path)
        assert r.status_code == 200 and r.json()["status"] == "ok", r.status_code
        return "http=200"

    check("health", lambda: health("/health"))
    check("readiness", lambda: health("/ready"))

    def unauthorized() -> str:
        r = c.http.post("/mcp", headers={
            "Accept": "application/json, text/event-stream",
        }, json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
        })
        assert r.status_code in (401, 403), r.status_code
        return f"expected_http={r.status_code}"

    check("unauthorized_rejected", unauthorized)
    check("oauth_pkce_and_token", lambda: (c.authorize(), "granted")[1])

    if c.token:
        def tools_list() -> str:
            names = {t["name"] for t in c.rpc("tools/list", {})["tools"]}
            assert {"execute_command", "list_servers", "read_file"} <= names, names
            return f"available_tools={len(names)}"

        check("tools_list", tools_list)

        def servers() -> str:
            deadline = time.monotonic() + 30
            while True:
                r, payload = c.call("list_servers", {})
                assert not r.get("isError") and payload, r
                fixture = payload["servers"].get("fixture", {})
                if fixture.get("status") == "active":
                    break
                assert time.monotonic() < deadline, fixture
                time.sleep(.25)
            return "servers=fixture"

        check("list_servers", servers)

        def remote_success() -> str:
            r, value = c.call("execute_command", c.execute_args(["id", "-un"]))
            assert not r.get("isError") and value, value
            assert value["status"] == "succeeded" and value["stdout"].strip() == "tester", value
            return "remote_user=tester"

        check("real_ssh_command", remote_success)

        def nonzero() -> str:
            r, value = c.call("execute_command", c.execute_args(["sh", "-c", "exit 7"]))
            assert not r.get("isError") and value, value
            assert value["status"] == "command_error" and value["exit_code"] == 7, value
            return "expected_exit=7"

        check("expected_nonzero_exit", nonzero)

        def unapproved() -> str:
            args = c.execute_args(["id", "-un"])
            args["server"] = "demo-fixture"
            r, _ = c.call("execute_command", args)
            assert r.get("isError"), "real lab host should never be reachable"
            return "denied"

        check("unapproved_host_rejected", unapproved)

        def timeout() -> str:
            r, value = c.call("execute_command", c.execute_args(["sleep", "2"], timeout_seconds=1))
            assert r.get("isError") and value, value
            assert value["status"] == "timed_out", value
            return "expected_timeout=1s"

        check("expected_timeout", timeout)

        def file_roundtrip() -> str:
            marker = "synthetic lab smoke\n"
            r, result = c.call("write_file", {
                "server": "fixture", "path": "sky-lab-smoke.txt",
                "content": marker, "mode": "replace",
                "reason": "synthetic smoke file", "story_id": os.environ["SSH_MCP_TEST_STORY"],
            })
            assert not r.get("isError") and result and result["status"] == "succeeded", result
            r, result = c.call("read_file", {
                "server": "fixture", "path": "sky-lab-smoke.txt",
                "reason": "synthetic smoke file", "story_id": os.environ["SSH_MCP_TEST_STORY"],
            })
            assert not r.get("isError") and result and result["status"] == "succeeded", result
            assert result["result"]["content"] == marker, result
            return "write/read=verified"

        check("ssh_file_write_read", file_roundtrip)

        def service_status() -> str:
            r, payload = c.call("get_status", {})
            assert not r.get("isError") and payload, payload
            return "ok"

        check("service_status_tool", service_status)
    else:
        failed += 1
        print("RESULT dependent_mcp_tests=FAIL oauth_not_available", flush=True)

print(f"SMOKE_SUMMARY passed={passed} failed={failed}", flush=True)
sys.exit(1 if failed else 0)
