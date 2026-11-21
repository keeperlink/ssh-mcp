"""TEST-212: optional authenticated live MCP tool binding; all SSH subprocesses mocked."""
from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ.setdefault("MCP_ISSUER", "http://localhost")
os.environ.setdefault("MCP_LOGIN_KEY", "synthetic-test-login-" + "a" * 40)
os.environ.setdefault("MCP_TOKEN_SIGNING_SECRET", "synthetic-test-signing-" + "b" * 40)
os.environ.setdefault("MCP_CIMD_VALIDATE_REMOTE", "false")

from app import config, mcp_gateway, oauth
from app.ssh_executor import SSHDenied, SSHResult

CLIENT = "https://chatgpt.com/oauth/client.json"
REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
SSH_SECRET = "synthetic-test-ssh-" + "c" * 40


class FakeExecutor:
    def __init__(self):
        self.calls = []
        self.access = "always-granted"
        self.privileged_access = "none"
        self.username = "gateway"
        self._sudo_passwords = {}

    def discover_hosts(self, actor, history_hosts):
        result = {alias: {'status': 'active', 'sudo_ready': False}
                  for alias in self.list_servers(actor)}
        result.update({alias: {'status': 'retired', 'sudo_ready': False}
                       for alias in history_hosts if alias not in result})
        return result

    def list_servers(self, principal):
        return ["demo-node-b"] if principal == oauth.client_audit_actor(CLIENT) else []

    def require_ready(self, server, *, privileged=False):
        pass

    async def check_readiness_live(self, server, *, privileged=False):
        pass

    def authorized_host(self, principal, server):
        if principal != oauth.client_audit_actor(CLIENT) or server != "demo-node-b":
            raise SSHDenied("unauthorized")
        return self

    async def execute(self, principal, request, *, on_output=None, on_admitted=None):
        if on_admitted is not None:
            on_admitted()
        self.calls.append((principal, request))
        if principal != oauth.client_audit_actor(CLIENT) or request.server != "demo-node-b":
            raise SSHDenied("unauthorized")
        if request.argv[0] == "fail":
            return SSHResult(request.server, "command_error", 7, "", "failed", 0.02)
        if request.argv[0] == "timeout":
            return SSHResult(request.server, "timed_out", None, "", "", 1.0)
        return SSHResult(request.server, "succeeded", 0, "gateway\n", "", 0.03)


def make_app(fake):
    with patch.object(config, "MCP_SSH_TOOLS_ENABLED", True):
        with patch.dict(os.environ, {
            "SSH_JOBS_ENABLED": "true", "SSH_JOBS_DB": os.environ["MCP_OAUTH_DB"],
        }), patch.object(mcp_gateway.SSHExecutor, "from_environment", return_value=fake):
            server, sub_app = mcp_gateway.create_mcp_server()

    @asynccontextmanager
    async def lifespan(_app):
        async with server.session_manager.run():
            yield

    app = FastAPI(lifespan=lifespan)
    app.include_router(oauth.router)
    app.mount("/", sub_app)
    return app


class DirectSSHMCPTests(unittest.TestCase):
    def setUp(self):
        oauth._AUTH_CODES.clear()
        oauth._LOGIN_FAILURES.clear()
        state = tempfile.TemporaryDirectory()
        self.addCleanup(state.cleanup)
        db = Path(state.name) / "jobs.sqlite"
        change = patch.dict(os.environ, {"MCP_OAUTH_DB": str(db)})
        change.start()
        self.addCleanup(change.stop)

    def test_one_login_key_and_scoped_ssh_tools(self):
        with patch.object(config, "MCP_SSH_TOOLS_ENABLED", False):
            self.assertNotIn("ssh.execute", oauth._supported_scopes())
            with self.assertRaises(ValueError):
                oauth._normalize_scopes("mcp.access ssh.execute")
            with self.assertRaises(ValueError):
                oauth.issue_access_token(CLIENT, ["mcp.access", "ssh.execute"])
        with patch.object(config, "MCP_SSH_TOOLS_ENABLED", True):
            config.validate_mcp_config()
            self.assertEqual(oauth._normalize_scopes("mcp.access ssh.execute"),
                             ["mcp.access", "ssh.execute"])
            self.assertIn("ssh.execute", oauth._supported_scopes())
            self.assertEqual(oauth._normalize_scopes(None), oauth._supported_scopes())
            with self.assertRaisesRegex(ValueError, "ssh.execute"):
                oauth._normalize_scopes("mcp.access")
            token, _ = oauth.issue_access_token(CLIENT, oauth._supported_scopes())
            self.assertIsNotNone(asyncio.run(oauth.OAuthTokenVerifier().verify_token(token)))
        with patch.object(config, "MCP_SSH_TOOLS_ENABLED", False):
            self.assertIsNone(asyncio.run(oauth.OAuthTokenVerifier().verify_token(token)))

    def test_ssh_requires_executor_env_even_if_mcp_opted_in(self):
        with patch.object(config, "MCP_SSH_TOOLS_ENABLED", True):
            with patch.dict(os.environ, {"SSH_EXECUTOR_ENABLED": "false"}):
                with self.assertRaises(SSHDenied):
                    mcp_gateway.create_mcp_server()

    def test_one_oauth_login_authorizes_explicit_ssh_scope(self):
        with patch.object(config, "MCP_SSH_TOOLS_ENABLED", True):
            app = FastAPI()
            app.include_router(oauth.router)
            with TestClient(app) as client:
                params = {
                    "client_id": CLIENT, "redirect_uri": REDIRECT,
                    "response_type": "code", "code_challenge": CHALLENGE,
                    "code_challenge_method": "S256",
                    "resource": config.MCP_RESOURCE, "scope": "mcp.access ssh.execute",
                }

                def login(key):
                    page = client.get("/oauth/authorize", params=params)
                    self.assertEqual(page.status_code, 200)
                    claim = re.search(r'name="request_token" value="([^"]+)"', page.text)
                    self.assertIsNotNone(claim)
                    return client.post("/oauth/authorize", data={
                        "request_token": claim.group(1), "mcp_login_key": key,
                    }, follow_redirects=False)

                missing_scope = client.get("/oauth/authorize", params={
                    **params, "scope": "mcp.access",
                }, follow_redirects=False)
                self.assertEqual(
                    parse_qs(urlparse(missing_scope.headers["location"]).query)["error"],
                    ["invalid_scope"],
                )
                denied = login("not-the-real-authorization-password")
                self.assertEqual(
                    parse_qs(urlparse(denied.headers["location"]).query)["error"],
                    ["access_denied"],
                )
                granted = login(config.MCP_LOGIN_KEY)
                code = parse_qs(urlparse(granted.headers["location"]).query)["code"][0]
                response = client.post("/oauth/token", data={
                    "client_id": CLIENT, "redirect_uri": REDIRECT,
                    "grant_type": "authorization_code", "code": code,
                    "code_verifier": VERIFIER, "resource": config.MCP_RESOURCE,
                })
                self.assertEqual(response.status_code, 200)
                self.assertIn("ssh.execute", response.json()["scope"].split())
                self.assertNotIn(config.MCP_LOGIN_KEY, response.text)

    def test_http_mcp_scoped_execution_bound_to_verified_principal(self):
        fake = FakeExecutor()
        app = make_app(fake)
        with patch.object(config, "MCP_SSH_TOOLS_ENABLED", True), TestClient(app) as client:
            def rpc(token, method, params, req_id=1):
                response = client.post(
                    "/mcp", headers={
                        "Authorization": "Bearer " + token,
                        "Accept": "application/json, text/event-stream",
                        "Host": "localhost",
                    }, json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": params},
                )
                self.assertEqual(response.status_code, 200, response.text)
                return response.json()["result"]

            weak, _ = oauth.issue_access_token(CLIENT, list(config.MCP_SCOPES))
            strong, _ = oauth.issue_access_token(CLIENT, oauth._supported_scopes())
            tools = rpc(strong, "tools/list", {})
            self.assertTrue({"ping", "list_servers", "execute_command", "submit_job"}
                            <= {tool["name"] for tool in tools["tools"]})
            self.assertEqual(
                next(item for item in tools["tools"] if item["name"] == "execute_command")["inputSchema"]["additionalProperties"],
                False,
            )
            # Under SSH activation, the MCP bearer challenge requires the
            # SSH scope, so POC-only tokens fail at HTTP authentication.
            denied = client.post(
                "/mcp", headers={
                    "Authorization": "Bearer " + weak,
                    "Accept": "application/json, text/event-stream",
                    "Host": "localhost",
                }, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            )
            self.assertIn(denied.status_code, (401, 403))
            self.assertEqual(fake.calls, [])
            discovery = rpc(strong, "tools/call", {"name": "list_servers", "arguments": {}})
            self.assertEqual(json.loads(discovery["content"][0]["text"])["servers"], {"demo-node-b": {"status": "active", "sudo_ready": False}})
            invalid = rpc(strong, "tools/call", {"name": "execute_command", "arguments": {
                "server": "demo-node-b", "argv": ["id"], "reason": "ci", "principal": "admin",
            }})
            self.assertTrue(invalid.get("isError"))
            self.assertEqual(fake.calls, [])
            request = {"name": "execute_command", "arguments": {
                "server": "demo-node-b", "argv": ["id", "-un"], "reason": "ci",
            }}
            good = rpc(strong, "tools/call", request)
            payload = json.loads(good["content"][0]["text"])
            self.assertEqual(payload["status"], "succeeded")
            self.assertEqual(payload["stdout"], "gateway\n")
            self.assertEqual(fake.calls[0][0], oauth.client_audit_actor(CLIENT))
            self.assertEqual(len(payload["request_id"]), 24)
            # A legacy host without privileged_access remains disabled by
            # signed policy even though the root executor now exists.
            attempted = len(fake.calls)
            for name in ("execute_command", "submit_job", "execute_commands"):
                with self.subTest(name=name):
                    privileged_args = {
                        "server": "demo-node-b", "reason": "synthetic root rejected",
                        "privileged": True,
                    }
                    if name == "execute_commands":
                        privileged_args["commands"] = [{"argv": ["id", "-un"]}]
                    else:
                        privileged_args["argv"] = ["id", "-un"]
                    rejected = rpc(strong, "tools/call", {
                        "name": name, "arguments": privileged_args,
                    })
                    self.assertTrue(rejected.get("isError"), name)
                    detail = rejected["content"][0]["text"].lower()
                    if name == "execute_commands":
                        self.assertIn('"failure_kind":"authorization"', detail)
                    else:
                        self.assertIn("denied", detail)
                    self.assertEqual(len(fake.calls), attempted)
            for command, state in [("fail", "command_error"), ("timeout", "timed_out")]:
                request["arguments"]["argv"] = [command]
                result = rpc(strong, "tools/call", request)
                self.assertEqual(bool(result.get("isError")), state == "timed_out")
                self.assertEqual(json.loads(result["content"][0]["text"])["status"], state)
            request["arguments"]["server"] = "demo-node2"
            bad_server = rpc(strong, "tools/call", request)
            self.assertTrue(bad_server.get("isError"))
            # The central signed-host gate must reject before the remote
            # SSH executor sees any unapproved target.
            self.assertEqual(fake.calls[-1][1].server, "demo-node-b")

            # A JWT signed with the same local key but an unapproved
            # subject must fail at HTTP bearer verification, not merely
            # produce an empty inventory after authentication.
            import jwt
            body = jwt.decode(strong, config.MCP_TOKEN_SIGNING_SECRET, algorithms=["HS256"],
                              options={"verify_aud": False})
            body["sub"] = "unknown-principal"
            alternate = jwt.encode(body, config.MCP_TOKEN_SIGNING_SECRET, algorithm="HS256")
            attempted = len(fake.calls)
            for name, arguments in (
                ("list_servers", {}),
                ("execute_command", {"server": "demo-node-b", "argv": ["id"], "reason": "ci"}),
            ):
                denied = client.post("/mcp", headers={
                    "Authorization": "Bearer " + alternate,
                    "Accept": "application/json, text/event-stream",
                    "Host": "localhost",
                }, json={"jsonrpc": "2.0", "id": 9,
                         "method": "tools/call", "params": {
                             "name": name, "arguments": arguments,
                         }})
                self.assertIn(denied.status_code, (401, 403))
            self.assertEqual(len(fake.calls), attempted)

    def test_request_auth_context_is_missing_when_not_http_authenticated(self):
        # In-process invocation cannot borrow a previous request's OAuth token.
        self.assertIsNone(mcp_gateway.get_access_token())

    def test_missing_audit_disables_direct_ssh_and_hides_execution_tool(self):
        fake = FakeExecutor()
        with patch.object(config, "MCP_SSH_TOOLS_ENABLED", True), patch.dict(os.environ, {
            "SSH_JOBS_ENABLED": "false", "SSH_BINARY_PROBE_ENABLED": "false",
        }), patch.object(mcp_gateway.SSHExecutor, "from_environment", return_value=fake):
            server, sub_app = mcp_gateway.create_mcp_server()

        @asynccontextmanager
        async def lifespan(_app):
            async with server.session_manager.run():
                yield

        app = FastAPI(lifespan=lifespan)
        app.mount("/", sub_app)
        with patch.object(config, "MCP_SSH_TOOLS_ENABLED", True), TestClient(app) as client:
            token, _ = oauth.issue_access_token(CLIENT, oauth._supported_scopes())

            def call(name, arguments=None):
                result = client.post("/mcp", headers={
                    "Authorization": "Bearer " + token,
                    "Accept": "application/json, text/event-stream", "Host": "localhost",
                }, json={
                    "jsonrpc": "2.0", "id": 1, "method": name,
                    "params": (arguments or {}),
                })
                self.assertEqual(result.status_code, 200, result.text)
                return result.json()["result"]

            available = {item["name"] for item in call("tools/list")["tools"]}
            self.assertEqual(available, {"ping", "list_servers"})
            with patch.object(mcp_gateway, "require_host_access", new_callable=AsyncMock) as approval:
                for name in ("execute_command", "submit_job", "execute_commands"):
                    with self.subTest(name=name):
                        arguments = {"server": "demo-node-b", "reason": "synthetic no audit"}
                        if name == "execute_commands":
                            arguments["commands"] = [{"argv": ["id"]}]
                        else:
                            arguments["argv"] = ["id"]
                        denied = call("tools/call", {"name": name, "arguments": arguments})
                        self.assertTrue(denied.get("isError"))
                        self.assertIn("Durable SSH", denied["content"][0]["text"])
                approval.assert_not_awaited()
            self.assertEqual(fake.calls, [])


if __name__ == "__main__":
    unittest.main()
