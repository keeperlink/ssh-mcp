"""TEST-209 periodic audit retention and explicit viewer startup safety gates."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import os
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

os.environ.setdefault("MCP_ISSUER", "http://localhost")
os.environ.setdefault("MCP_LOGIN_KEY", "synthetic-test-login-" + "a" * 40)
os.environ.setdefault("MCP_TOKEN_SIGNING_SECRET", "synthetic-test-signing-" + "b" * 40)
os.environ.setdefault("MCP_CIMD_VALIDATE_REMOTE", "false")

from app import main


class PeriodicPruneTests(unittest.IsolatedAsyncioTestCase):
    async def test_hourly_cleanup_recovers_after_audit_store_failure(self):
        class FakeStore:
            calls = 0

            def prune(self):
                self.calls += 1
                if self.calls == 1:
                    raise RuntimeError("synthetic datastore interruption")
                return 1

        store = FakeStore()
        calls = []

        async def next_hour(seconds):
            self.assertEqual(seconds, 3600)
            calls.append(seconds)
            if len(calls) == 3:
                raise asyncio.CancelledError()

        with patch.object(main, "session_store", return_value=SimpleNamespace(prune=lambda: 0)):
          with patch.object(main.asyncio, "sleep", next_hour):
              with self.assertLogs("app.main", level="WARNING") as messages:
                  with self.assertRaises(asyncio.CancelledError):
                      await main._prune_loop(store)
        self.assertEqual(store.calls, 2)
        self.assertIn("history_retention_prune_failed", str(messages.output))


class MainHistoryIntegrationTests(unittest.TestCase):
    def test_multiple_workers_fail_closed_for_in_memory_approvals(self):
        async def startup():
            async with main.lifespan(main.app):
                self.fail("Multiple workers must never start with in-memory approvals")

        for setting in ("WEB_CONCURRENCY", "UVICORN_WORKERS"):
            with self.subTest(setting=setting):
                with patch.dict(os.environ, {
                    "WEB_CONCURRENCY": "1", "UVICORN_WORKERS": "1", setting: "2",
                }):
                    with self.assertRaisesRegex(RuntimeError, "single server worker"):
                        asyncio.run(startup())

    def test_lifespan_starts_and_cancels_retention_task(self):
        @asynccontextmanager
        async def scoped_session_manager():
            yield

        fake_jobs = SimpleNamespace(store=SimpleNamespace(prune=lambda: 0))
        with patch.dict(main._job_registry, {"jobs": fake_jobs}):
            # The SDK manager is explicitly single-use; test our background task
            # independently without consuming the real manager used by test_poc.
            with patch.object(main._mcp_server.session_manager, "run", side_effect=scoped_session_manager):
              with patch.object(main, "session_store", return_value=SimpleNamespace(prune=lambda: 0)):
                with TestClient(main.app) as client:
                    response = client.get("/health")
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.json(), {"status": "ok"})

    def test_history_cannot_enable_without_durable_jobs(self):
        env = {
            **os.environ,
            "HISTORY_VIEWER_ENABLED": "true",
            "MCP_SSH_TOOLS_ENABLED": "false",
            "SSH_JOBS_ENABLED": "false",
            "MCP_ISSUER": "http://localhost",
        }
        result = subprocess.run(
            [sys.executable, "-c", "import app.main"],
            cwd=os.getcwd(), env=env, capture_output=True, text=True, timeout=20,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("History viewer requires enabled audited SSH jobs", result.stderr)


if __name__ == "__main__":
    unittest.main()
