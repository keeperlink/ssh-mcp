"""Test-only OAuth/MCP client for an isolated SSH-MCP lab test network.

Use from a test client container, never from a production connector or host.
The client's access token stays in memory and is never part of test reports.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from urllib.parse import parse_qs, urlparse

import httpx

CLIENT_ID = "https://chatgpt.com/oauth/client.json"
REDIRECT_URI = "https://chatgpt.com/connector_platform_oauth_redirect"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"


class LabClient:
    """Authenticated JSON-RPC over the internal-only MCP HTTP endpoint."""

    def __init__(self) -> None:
        self.http = httpx.Client(
            base_url=os.environ.get("SSH_MCP_TEST_URL", "http://mcp:8000"),
            timeout=20.0,
            follow_redirects=False,
            trust_env=False,
            headers={"Host": "localhost"},
        )
        self.token: str | None = None
        self.next_id = 1

    def __enter__(self) -> LabClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.http.close()

    def authorize(self) -> None:
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(VERIFIER.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        resource = "http://localhost/mcp"
        params = {
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": resource,
            "scope": "mcp.access ssh.execute",
        }
        page = self.http.get("/oauth/authorize", params=params)
        page.raise_for_status()
        claim = re.search(r'name="request_token" value="([^"]+)"', page.text)
        if claim is None:
            raise AssertionError("OAuth authorization form missing signed request")
        grant = self.http.post("/oauth/authorize", data={
            "request_token": claim.group(1),
            "mcp_login_key": os.environ["MCP_LOGIN_KEY"],
        })
        if grant.status_code not in (302, 303):
            raise AssertionError(f"OAuth consent failed: HTTP {grant.status_code}")
        code = parse_qs(urlparse(grant.headers["location"]).query)["code"][0]
        response = self.http.post("/oauth/token", data={
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": VERIFIER,
            "resource": resource,
        })
        response.raise_for_status()
        document = response.json()
        if "ssh.execute" not in document["scope"].split():
            raise AssertionError("OAuth token missing approved SSH scope")
        self.token = document["access_token"]

    def rpc(self, method: str, params: dict) -> dict:
        if not self.token:
            raise AssertionError("Call authorize() before using MCP tools")
        self.next_id += 1
        response = self.http.post("/mcp", headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/json, text/event-stream",
        }, json={
            "jsonrpc": "2.0", "id": self.next_id,
            "method": method, "params": params,
        })
        response.raise_for_status()
        body = response.json()
        if "result" not in body:
            raise AssertionError(f"MCP JSON-RPC error: {body.get('error')}")
        return body["result"]

    def call(self, name: str, arguments: dict) -> tuple[dict, dict | None]:
        result = self.rpc("tools/call", {"name": name, "arguments": arguments})
        content = result.get("content", [])
        if not content or content[0].get("type") != "text":
            raise AssertionError(f"MCP {name} did not return text content")
        try:
            payload = json.loads(content[0]["text"])
        except (ValueError, TypeError):
            payload = None  # Expected authorization denials may be plain text.
        return result, payload

    @staticmethod
    def execute_args(argv: list[str], **kwargs: object) -> dict:
        return {
            "server": "fixture",
            "argv": argv,
            "reason": "isolated SSH-MCP lab integration test",
            "story_id": os.environ.get("SSH_MCP_TEST_STORY", "TEST-249"),
            **kwargs,
        }
