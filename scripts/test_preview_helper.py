"""Non-Docker regression tests for the source-only preview tool."""
from __future__ import annotations

import asyncio
from contextlib import closing, redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch, call

HELPER = Path(__file__).resolve().parents[1] / "ops" / "preview"
sys.path.insert(0, str(HELPER))
try:
    import lab_preview as preview
    import request_trace as trace
    from runtime_cleanup import prepare_for_reload
finally:
    sys.path.remove(str(HELPER))


def original():
    env = {
        "MCP_CONFIG_FILE": "/etc/ssh-mcp/service.json",
        "MCP_INVENTORY_FILE": "/etc/ssh-mcp/inventory.json",
        "MCP_KNOWN_HOSTS_FILE": "/etc/ssh-mcp/known_hosts",
        "MCP_SECRETS_FILE": "/run/secrets/ssh-mcp-secrets",
        "SSH_JOBS_DB": "/var/lib/ssh-mcp/jobs.sqlite",
    }
    return {"Id": "a" * 64, "Image": "sha256:" + "b" * 64,
            "Mounts": [
                {"Destination": path, "Source": "/synthetic/" + key,
                 "Type": "bind", "RW": False}
                for key, path in preview.DESTINATIONS.items()
            ] + [{"Destination": "/var/lib/ssh-mcp", "Type": "volume",
                  "Name": "demo-state", "RW": True}],
            "HostConfig": {"PortBindings": {"8000/tcp": [
                {"HostIp": "10.77.10.1", "HostPort": "8014"}]},
                "Tmpfs": {"/run/ssh-mcp": "", "/tmp": ""}},
            "NetworkSettings": {"Networks": {
                "demo-ingress": {"IPAddress": "172.20.0.2"},
                "demo-transit": {"IPAddress": "172.21.0.2"}}},
            "Config": {"Image": "registry.example.invalid/ssh-mcp:1.2.3@sha256:" + "c" * 64,
                       "User": "10001:10001",
                       "Env": [f"{key}={value}" for key, value in env.items()]},
            "State": {"Status": "running"}}


class PreviewTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        root.chmod(0o755)
        self.root = root
        (root / "app").mkdir(mode=0o755)
        (root / "ops/preview").mkdir(parents=True, mode=0o755)
        (root / "app/main.py").write_text("# synthetic source")
        (root / "app/main.py").chmod(0o644)
        for key, value in {
            "SOURCE": root, "STATE": root / "state", "MARKER": root / "state/switch.json",
            "STANDARD": "demo-service", "PREVIEW": "demo-service-dev",
            "PROJECT": "demo-service-preview", "PROXY": "demo-proxy",
            "NETWORK": "demo-ingress", "BACKENDS": ("demo/server",),
            "TRACE": False, "SOURCE_PREVIEW": False,
        }.items():
            p = patch.object(preview, key, value)
            p.start()
            self.addCleanup(p.stop)

    def test_derive_current_mounts_and_modes(self):
        env = preview.preview_environment(original())
        self.assertEqual(env["SSH_MCP_PREVIEW_STATE_VOLUME"], "demo-state")
        self.assertEqual(env["SSH_MCP_PREVIEW_TRANSIT"], "demo-transit")
        self.assertEqual(env["SSH_MCP_PREVIEW_ORIGINAL_ID"], "a" * 64)
        self.assertEqual(env["SSH_MCP_PREVIEW_TRACE"], "0")
        self.assertEqual(env["SSH_MCP_PREVIEW_SOURCE_MODE"], "0")
        with patch.object(preview, "TRACE", True), patch.object(preview, "SOURCE_PREVIEW", True):
            env = preview.preview_environment(original())
            self.assertEqual(env["SSH_MCP_PREVIEW_TRACE"], "1")
            self.assertEqual(env["SSH_MCP_PREVIEW_SOURCE_MODE"], "1")

    def test_reject_incorrect_mounts_image_port_and_networks(self):
        for mutate in (
            lambda d: d["Mounts"].pop(),
            lambda d: d["Mounts"][0].update(RW=True),
            lambda d: d["Mounts"][0].update(Destination="/etc/old/service.json"),
            lambda d: d["Config"].update(Image="demo:latest"),
            lambda d: d["HostConfig"]["PortBindings"]["8000/tcp"][0].update(HostIp="0.0.0.0"),
            lambda d: d["HostConfig"]["PortBindings"]["8000/tcp"][0].update(HostPort="99999"),
            lambda d: d["NetworkSettings"]["Networks"].pop("demo-ingress"),
            lambda d: d["Config"].update(User="0:0"),
            lambda d: d["Config"].update(Env=[]),
        ):
            with self.subTest(mutate=mutate):
                value = original()
                mutate(value)
                with self.assertRaises(preview.PreviewError):
                    preview.preview_environment(value)

    def test_docker_environment_cannot_redirect_or_override(self):
        with patch.dict(os.environ, {"DOCKER_HOST": "tcp://bad.invalid",
                                    "DOCKER_CONTEXT": "remote", "COMPOSE_FILE": "wrong",
                                    "SSH_MCP_PREVIEW_IMAGE": "wrong", "SAFE_TEST": "yes"}):
            env = preview.docker_environment()
            self.assertEqual(env["SAFE_TEST"], "yes")
            self.assertFalse(any(k.startswith(("DOCKER_", "COMPOSE_", "SSH_MCP_PREVIEW_")) for k in env))
            self.assertEqual(preview.docker_argv(("docker", "inspect", "demo")),
                             ("docker", "--host", "unix:///var/run/docker.sock", "inspect", "demo"))

    def test_source_assets_and_symlink(self):
        assets = self.root / "app/assets"
        assets.mkdir(mode=0o755)
        css = assets / "view.css"
        css.write_text("body {}")
        css.chmod(0o600)
        with patch.object(preview, "_container_can_read",
                          side_effect=lambda path: path != css or bool(path.stat().st_mode & 4)):
            with self.assertRaises(preview.PreviewError):
                preview.verify_source_access()
            preview.verify_source_access(repair=True)
        self.assertTrue(css.stat().st_mode & 4)
        css.unlink()
        css.symlink_to(self.root / "app/main.py")
        with self.assertRaises(preview.PreviewError):
            preview.verify_source_access()

    def test_all_three_active_tables_counted(self):
        db_file = self.root / "jobs.sqlite"
        with closing(sqlite3.connect(db_file)) as db, db:
            for table in ("jobs", "file_operations", "command_batches"):
                db.execute(f"CREATE TABLE {table}(status TEXT)")
                db.executemany(f"INSERT INTO {table} VALUES (?)",
                               [(s,) for s in ("awaiting_approval", "queued", "running", "succeeded")])
        query = preview.DRAIN_QUERY.replace("/var/lib/ssh-mcp/jobs.sqlite", str(db_file))
        with redirect_stdout(StringIO()) as out:
            exec(query, {})
        self.assertEqual(out.getvalue().strip(), "3 3 3")
        for counts in ("1 0 0", "0 1 0", "0 0 1", "0 0", "broken"):
            with patch.object(preview, "run", return_value=counts), self.assertRaises(preview.PreviewError):
                preview.check_active_jobs("demo-service")
        with patch.object(preview, "run", return_value="0 0 0"):
            preview.check_active_jobs("demo-service")

    def test_proxy_must_point_at_exact_single_original(self):
        row = "1 demo 2 server 172.20.0.2 2 0"
        with patch.object(preview, "haproxy_command", return_value=row):
            preview.check_haproxy(original())
        for bad in ("", row.replace("172.20.0.2", "172.20.0.3"),
                    row + "\n" + row.replace("demo", "other"),
                    row[:-1] + "1"):
            with patch.object(preview, "haproxy_command", return_value=bad), self.assertRaises(preview.PreviewError):
                preview.check_haproxy(original())

    def test_refuses_production_before_ingress_mutation(self):
        with patch.object(preview, "inspect", return_value=None), \
             patch.object(preview, "run", return_value="production"), \
             patch.object(preview, "backend_state") as gate, \
             patch.object(preview, "mark_transition") as marker:
            with self.assertRaisesRegex(preview.PreviewError, "not lab"):
                preview.start(original())
            gate.assert_not_called()
            marker.assert_not_called()

    def test_switch_order_and_single_container(self):
        with patch.object(preview, "inspect", return_value=None), \
             patch.object(preview, "run", side_effect=["lab", original()["Image"], ""]) as run, \
             patch.object(preview, "check_haproxy"), \
             patch.object(preview, "compose") as compose, \
             patch.object(preview, "mark_transition") as mark, \
             patch.object(preview, "backend_state") as gate, \
             patch.object(preview, "wait_idle") as idle, \
             patch.object(preview, "backup_live_db", return_value="snapshot") as backup, \
             patch.object(preview, "wait_ready", return_value={"preview": True}) as ready, \
             patch.object(preview, "route_to") as route, redirect_stdout(StringIO()):
            events = Mock()
            for name, child in (("run", run), ("compose", compose), ("mark", mark), ("gate", gate),
                                ("idle", idle), ("backup", backup), ("ready", ready), ("route", route)):
                events.attach_mock(child, name)
            preview.start(original())
            selected = [c for c in events.mock_calls if c[0] not in ("run", "compose") or
                        c[0] == "run" and c.args[:2] == ("docker", "stop") or
                        c[0] == "compose" and len(c.args) > 1 and c.args[1] == "up"]
            self.assertEqual(selected, [
                call.mark("starting"), call.gate("maint"), call.idle("demo-service"),
                call.backup(), call.idle("demo-service"), call.run("docker", "stop", "demo-service"),
                call.compose(original(), "up", "--detach", "--no-deps", "--pull", "never"),
                call.ready("demo-service-dev"), call.route({"preview": True}),
                call.gate("ready"), call.mark("preview_active")])

    def test_failed_switch_restores_original(self):
        with patch.object(preview, "inspect", return_value=None), \
             patch.object(preview, "run", side_effect=["lab", original()["Image"]]), \
             patch.object(preview, "check_haproxy"), patch.object(preview, "compose"), \
             patch.object(preview, "mark_transition"), patch.object(preview, "backend_state"), \
             patch.object(preview, "wait_idle", side_effect=preview.PreviewError("busy")), \
             patch.object(preview, "restore_standard") as restore, \
             patch.object(preview, "clear_transition") as clear, redirect_stderr(StringIO()):
            with self.assertRaisesRegex(preview.PreviewError, "original lab service restored"):
                preview.start(original())
            restore.assert_called_once_with(original())
            clear.assert_called_once()

    def test_recovery_marker_binds_container_and_proxy(self):
        def inspect(name, **kwargs):
            return {"Id": "original" if name == "demo-service" else "proxy"}
        with patch.object(preview, "inspect", side_effect=inspect):
            preview.mark_transition("starting")
            preview.verify_transition()
            with patch.object(preview, "PROXY", "other"):
                with self.assertRaisesRegex(preview.PreviewError, "does not match"):
                    preview.verify_transition()
        self.assertEqual(preview.MARKER.stat().st_mode & 0o777, 0o600)

    def test_refuse_unrelated_preview_before_mutating_ingress(self):
        with patch.object(preview, "verify_transition"), \
             patch.object(preview, "inspect", return_value={"Config": {"Labels": {}}}), \
             patch.object(preview, "backend_state") as state, patch.object(preview, "run") as run:
            with self.assertRaisesRegex(preview.PreviewError, "unrelated"):
                preview.restore_standard(original())
            state.assert_not_called()
            run.assert_not_called()

    def test_reload_cleanup_removes_only_verified_files(self):
        d = self.root / "runtime"
        d.mkdir(mode=0o700)
        d.chmod(0o700)
        for name in ("identity", "inventory.json"):
            f = d / name
            f.write_text("synthetic")
            f.chmod(0o600)
        unexpected = d / "unexpected"
        unexpected.write_text("synthetic")
        with self.assertRaises(RuntimeError):
            prepare_for_reload(d)
        self.assertTrue((d / "identity").exists())
        unexpected.unlink()
        prepare_for_reload(d)
        self.assertEqual(list(d.iterdir()), [])


class TraceTests(unittest.TestCase):
    def capture(self, body: bytes, *, path="/mcp", headers=(), method="POST", consume=True):
        events = [{"type": "http.request", "body": body[:7], "more_body": True},
                  {"type": "http.request", "body": body[7:], "more_body": False}]
        received = []
        sent = []

        async def receive():
            return events.pop(0)

        async def send(event):
            sent.append(event)

        async def app(scope, receive, send):
            if consume:
                while True:
                    event = await receive()
                    received.append(event["body"])
                    if not event.get("more_body", False):
                        break
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"secret-response"})

        with patch.object(trace.LOG, "warning") as log:
            asyncio.run(trace.PreviewRequestTrace(app)(
                {"type": "http", "path": path, "method": method,
                 "headers": list(headers), "query_string": b"token=hidden-query"}, receive, send))
        self.assertEqual(b"".join(received), body if consume else b"")
        self.assertEqual(sent[-1]["body"], b"secret-response")
        if not log.called:
            return None
        log.assert_called_once()
        return json.loads(log.call_args.args[1])

    def test_trace_preserves_duplicate_headers_and_known_metadata(self):
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "execute_command", "arguments": {"argv": ["hidden-argument"]},
            "_meta": {"x-codex-turn-metadata": {"thread_id": "thread-123", "turn_id": "turn-456"},
                      "custom": "hidden-metadata", "api_key": "hidden-key"}}}
        data = self.capture(json.dumps(payload).encode(), headers=[
            (b"authorization", b"Bearer hidden-token"), (b"cookie", b"hidden-cookie"),
            (b"x-unknown", b"hidden-custom"), (b"x-unknown", b"hidden-custom"),
            (b"x-ssh-mcp-conversation", b"conversation-123"),
            (b"mcp-session-id", b"hidden-session"), (b"user-agent", b"demo-client")])
        self.assertEqual(data["headers"][0]["value"], "[REDACTED]")
        self.assertEqual(data["headers"][1]["value"], "[REDACTED]")
        self.assertEqual(data["headers"][2], data["headers"][3])
        self.assertTrue(data["headers"][2]["value"].startswith("fingerprint:"))
        self.assertEqual(data["headers"][4]["value"], "conversation-123")
        self.assertEqual(data["headers"][5]["value"], "[REDACTED]")
        self.assertEqual(data["headers"][6]["value"], "demo-client")
        item = data["body"]["envelope"][0]
        self.assertEqual(item["argument_keys"], ["argv"])
        self.assertEqual(item["params_meta"]["x-codex-turn-metadata"]["thread_id"], "thread-123")
        self.assertNotIn("hidden-", json.dumps(data))
        self.assertNotIn("secret-response", json.dumps(data))

    def test_oauth_console_requests_not_logged(self):
        for path in ("/oauth/token", "/console", "/health"):
            self.assertIsNone(self.capture(b"secret=hidden-value", path=path))

    def test_bounds_invalid_json_and_unconsumed_request(self):
        self.assertEqual(self.capture(b"not-json")["body"]["parse"], "invalid_json")
        self.assertEqual(self.capture(b"x" * (trace.MAX_BODY_CAPTURE + 1))["body"]["parse"], "truncated")
        self.assertFalse(self.capture(b"secret", consume=False)["body"]["complete"])
        self.assertEqual(len(self.capture(b"", method="GET", headers=[
            (b"x-test", b"v")] * 300)["headers"]), trace.MAX_HEADERS)


if __name__ == "__main__":
    unittest.main()
