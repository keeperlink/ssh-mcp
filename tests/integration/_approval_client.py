"""Browser and approval controls shared by disposable SSH integration tests.

Import only from explicit integration entrypoints, never from the offline suite.
"""
from __future__ import annotations

from concurrent.futures import Future
import os
import re
import time
from urllib.parse import quote

import httpx

BASE = os.environ.get("SSH_MCP_TEST_URL", "http://mcp:8000")
CSRF = "__Host-ssh-mcp-console-csrf"
SESSION = "__Host-ssh-mcp-console"
ORIGIN = "http://localhost"



def viewer_session() -> tuple[httpx.Client, str]:
    browser = httpx.Client(base_url=BASE, trust_env=False, follow_redirects=False,
                           timeout=8, headers={"Host": "localhost"})
    page = browser.get("/console/login")
    assert page.status_code == 200, "Viewer login is unavailable"
    match = re.search(r'name="csrf" value="([^"]+)"', page.text)
    assert match is not None, "Missing viewer CSRF field"
    csrf = match.group(1)
    csrf_cookie = page.cookies.get(CSRF)
    assert csrf_cookie == csrf, "CSRF cookie does not match form"
    login = browser.post("/console/login",
                         data={"csrf": csrf, "password": os.environ["HISTORY_VIEWER_PASSWORD"]},
                         headers={"Origin": ORIGIN, "Cookie": f"{CSRF}={csrf_cookie}"})
    assert login.status_code == 303, "Synthetic viewer authentication failed"
    session = login.cookies.get(SESSION)
    assert session, "Viewer session cookie missing"
    # The test transport is internal HTTP, not a browser HTTPS surface. Secure
    # browser cookies are attached explicitly; server-side auth/CSRF remain real.
    browser.headers["Cookie"] = f"{SESSION}={session}; {CSRF}={csrf_cookie}"
    return browser, csrf


def snapshot(browser: httpx.Client) -> dict:
    response = browser.get("/console/api/changes?after=0:_")
    assert response.status_code == 200, "Authenticated approval snapshot rejected"
    return response.json()


def queue(browser: httpx.Client, future: Future, conversation: str) -> dict:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        requests = [x for x in snapshot(browser)["pending_approvals"]
                    if x["conversation_id"] == conversation]
        if requests:
            assert not future.done(), "Restricted SSH completed before operator decision"
            return requests[0]
        assert not future.done(), "Restricted SSH did not enter approval queue"
        time.sleep(0.05)
    raise AssertionError("Restricted SSH approval did not become pending")


def decision(browser: httpx.Client, csrf: str, approval_id: str,
             action: str, duration: str = "once") -> None:
    path = "/console/api/approvals/" + quote(approval_id, safe="") + "/" + action
    result = browser.post(path, data={"csrf": csrf, "duration": duration},
                          headers={"Origin": ORIGIN})
    assert result.status_code == 200, f"Operator {action} rejected: HTTP {result.status_code}"
