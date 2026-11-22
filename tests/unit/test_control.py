"""Real local socket tests for in-process log-level changes."""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch, Mock, AsyncMock

from app import control, control_cli


class ControlTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        logger = control.LOGGER
        old = logger.level, list(logger.handlers), logger.propagate
        def restore():
            logger.setLevel(old[0])
            logger.handlers[:] = old[1]
            logger.propagate = old[2]
        self.addCleanup(restore)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "control.sock"

    async def test_real_socket_lifecycle_and_cli(self):
        sdk_level = logging.getLogger("httpx").level
        async with control.control_server("INFO", self.path):
            self.assertTrue(self.path.is_socket())
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
            for action, level, effective in (("get", None, "INFO"),
                                              ("set", "DEBUG", "DEBUG"),
                                              ("set", "CRITICAL", "CRITICAL"),
                                              ("reset", None, "INFO")):
                with self.subTest(action=action, level=level):
                    result = await asyncio.to_thread(control_cli.request, action, level, path=self.path)
                    self.assertEqual(result["configured"], "INFO")
                    self.assertEqual(result["effective"], effective)
                    self.assertEqual(control.LOGGER.getEffectiveLevel(), getattr(logging, effective))
            self.assertEqual(logging.getLogger("httpx").level, sdk_level)
        self.assertFalse(self.path.exists())
        async with control.control_server("WARNING", self.path):
            self.assertEqual(control.LOGGER.getEffectiveLevel(), logging.WARNING)

    async def test_admin_cli_revocation_refreshes_running_process_and_noop(self):
        from app.dcr_registry import DCRStore
        from app.oauth_sessions import SessionStore
        from app import dcr_admin
        database = self.path.parent / "oauth.sqlite"
        SessionStore(database)
        running = DCRStore(database)
        client = running.register({
            "client_name": "Synthetic CLI",
            "application_type": "native",
            "redirect_uris": ["http://127.0.0.1:3131/callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        })["client_id"]
        running.approve_name(client, "Grok")
        self.assertEqual(running.approved_names[client], "Grok")
        async with control.control_server(
                "INFO", self.path, reload_names=running.reload_names):
            with patch.object(dcr_admin, "SOCKET", self.path):
                before = running.names_revision
                result = await asyncio.to_thread(
                    dcr_admin.main, ["--db", str(database), "revoke", client,
                                     "--confirm-id", client])
                self.assertEqual(result, 0)
                self.assertNotEqual(running.names_revision, before)
                self.assertEqual(dict(running.approved_names), {})
                before = running.names_revision
                result = await asyncio.to_thread(
                    dcr_admin.main, ["--db", str(database), "revoke", client,
                                     "--confirm-id", client])
                self.assertEqual(result, 1)
                self.assertNotEqual(running.names_revision, before)
                self.assertEqual(dict(running.approved_names), {})

    async def test_cli_missing_socket_requires_explicit_offline_mode(self):
        from io import StringIO
        from contextlib import redirect_stderr
        from app.dcr_registry import DCRStore
        from app.oauth_sessions import SessionStore
        from app import dcr_admin
        database = self.path.parent / "offline.sqlite"
        SessionStore(database)
        store = DCRStore(database)
        payload = {
            "client_name": "Synthetic CLI", "application_type": "native",
            "redirect_uris": ["http://127.0.0.1:3131/callback"],
            "grant_types": ["authorization_code"], "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }
        client = store.register(payload)["client_id"]
        error = StringIO()
        with patch.object(dcr_admin, "SOCKET", self.path), redirect_stderr(error):
            self.assertEqual(dcr_admin.main(["--db", str(database), "revoke",
                                            client, "--confirm-id", client]), 2)
        self.assertIsNone(store.get(client))  # Commit took effect despite missing control.
        self.assertIn("Restart SSH-MCP", error.getvalue())
        client = store.register(payload)["client_id"]
        error = StringIO()
        with patch.object(dcr_admin, "SOCKET", self.path), redirect_stderr(error):
            self.assertEqual(dcr_admin.main(["--db", str(database), "revoke",
                                            client, "--confirm-id", client, "--offline"]), 0)
        self.assertIsNone(store.get(client))
        self.assertIn("Offline revocation", error.getvalue())

    async def test_control_name_reload_is_restricted_to_available_handler(self):
        async with control.control_server("INFO", self.path):
            with self.assertRaises(ValueError):
                await asyncio.to_thread(control_cli.request,
                                        "reload-dcr-names", path=self.path)

    async def test_invalid_oversized_and_incomplete_requests(self):
        async with control.control_server("INFO", self.path):
            for payload in (b'not json\n', b'[]\n', b'{"action":"set","level":"TRACE"}\n',
                            b'{"action":"get","extra":1}\n', b'x' * (control.LIMIT + 2) + b'\n'):
                with self.subTest(payload=payload[:30]):
                    reader, writer = await asyncio.open_unix_connection(str(self.path))
                    writer.write(payload)
                    await writer.drain()
                    self.assertEqual(json.loads(await reader.readline())["status"], "error")
                    writer.close()
                    await writer.wait_closed()
            with patch.object(control, "TIMEOUT", 0.02):
                reader, writer = await asyncio.open_unix_connection(str(self.path))
                writer.write(b'{')
                await writer.drain()
                self.assertEqual(json.loads(await reader.readline())["status"], "error")
                writer.close()
                await writer.wait_closed()
            self.assertEqual(control.LOGGER.getEffectiveLevel(), logging.INFO)

    async def test_directory_and_existing_socket_safety(self):
        self.path.parent.chmod(0o755)
        with self.assertRaisesRegex(RuntimeError, "Unsafe"):
            async with control.control_server("INFO", self.path):
                self.fail("unexpected socket")
        self.path.parent.chmod(0o700)
        self.path.write_text("preserve")
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            async with control.control_server("INFO", self.path):
                self.fail("unexpected socket")
        self.assertEqual(self.path.read_text(), "preserve")
        self.path.unlink()
        self.path.symlink_to(self.path.parent / "missing")
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            async with control.control_server("INFO", self.path):
                self.fail("unexpected socket")

    async def test_standalone_without_control_socket(self):
        control.LOGGER.handlers[:] = []
        async with control.control_server("DEBUG", None):
            self.assertEqual(control.LOGGER.level, logging.DEBUG)
            self.assertTrue(control.LOGGER.handlers)
            self.assertFalse(self.path.exists())
        with self.assertRaises(ValueError):
            control.configure_logging("TRACE")

    async def test_disconnect_during_response_is_nonfatal(self):
        writer = Mock()
        writer.drain = AsyncMock(side_effect=BrokenPipeError)
        writer.wait_closed = AsyncMock(side_effect=BrokenPipeError)
        reader = Mock()
        reader.readuntil = AsyncMock(return_value=b'{"action":"get"}\n')
        await control.handle(reader, writer, "INFO")
        writer.close.assert_called_once()


class CliTests(unittest.TestCase):
    def test_cli_actions_and_failure(self):
        with patch.object(control_cli, "request", return_value={"configured":"INFO", "effective":"DEBUG"}) as req, patch("builtins.print") as output:
            self.assertEqual(control_cli.main(["set", "logging-level", "DEBUG"]), 0)
            req.assert_called_once_with("set", "DEBUG")
            self.assertIn("Effective: DEBUG", output.call_args.args[0])
            self.assertEqual(control_cli.main(["get", "logging-level"]), 0)
            self.assertEqual(control_cli.main(["reset", "logging-level"]), 0)
            req.side_effect = OSError
            self.assertEqual(control_cli.main(["get", "logging-level"]), 1)

    def test_bad_response(self):
        for payload in (b"bad", b'{"status":"error"}\n', b"x" * (control.LIMIT+1), b"not json\n"):
            with patch.object(control_cli.socket, "socket") as factory:
                client = factory.return_value.__enter__.return_value
                client.makefile.return_value.__enter__.return_value.readline.return_value = payload
                with self.assertRaises(ValueError):
                    control_cli.request("get")
