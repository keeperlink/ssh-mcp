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
