"""TEST-263 PR3: authenticated approval SSE lifecycle without a live SSH server."""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from fastapi import Request
from fastapi.routing import APIRoute
from fastapi.responses import JSONResponse, StreamingResponse

from app.approvals import ApprovalManager
from app.history import IDLE_SECONDS, SESSION_COOKIE, HistoryStore, ViewerAuth, create_history_router
from app.jobs import JobStore

KEY = ("synthetic-verified-sid", "synthetic-conversation", "demo-node2")


def fake_request(session: str | None = None) -> Request:
    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request({
        "type": "http", "method": "GET",
        "path": "/console/api/approval-events",
        "headers": [(b"cookie", (SESSION_COOKIE + "=" + session).encode())] if session else [],
        "scheme": "https", "server": ("lab.invalid", 443),
    }, receive)


def event_data(event: str) -> dict[str, Any]:
    assert event.startswith("event: approval\ndata: ")
    return cast(dict[str, Any], json.loads(event.split("data: ", 1)[1]))


class ApprovalEventTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manager = ApprovalManager()
        store = JobStore(Path(self.temp.name) / "jobs.sqlite")
        self.store = store
        self.password = "synthetic-viewer-password-123456789"
        with patch.dict(os.environ, {"HISTORY_VIEWER_PASSWORD": self.password}):
            router = create_history_router(store, approvals=self.manager)
        self.events = next(route.endpoint for route in router.routes
                           if isinstance(route, APIRoute)
                           and route.path == "/console/api/approval-events")

    async def asyncTearDown(self) -> None:
        self.manager.shutdown()

    async def test_unauthorized_event_stream_has_no_subscription(self) -> None:
        with patch.object(ViewerAuth, "valid", return_value=False):
            response = await self.events(fake_request())
        self.assertIsInstance(response, JSONResponse)
        self.assertEqual(response.status_code, 401)
        self.assertFalse(self.manager._listeners)

    async def test_sse_creation_grant_revoke_and_subscriber_cleanup(self) -> None:
        with patch.object(ViewerAuth, "valid", return_value=True):
            response = await self.events(fake_request())
            self.assertIsInstance(response, StreamingResponse)
            self.assertEqual(response.media_type, "text/event-stream")
            self.assertEqual(response.headers["cache-control"], "no-store")
            self.assertEqual(response.headers["x-accel-buffering"], "no")
            stream = response.body_iterator
            first = event_data(await asyncio.wait_for(anext(stream), 2))
            self.assertEqual(first["pending_approvals"], [])
            self.assertEqual(first["active_grants"], [])
            self.assertNotIn(KEY[0], str(first))
            self.assertEqual(len(self.manager._listeners), 1)

            next_event = asyncio.create_task(anext(stream))
            waiting = asyncio.create_task(self.manager.require(
                KEY, tool="execute_command", reason="synthetic",
                summary="hostname",
            ))
            queued = event_data(await asyncio.wait_for(next_event, 2))
            self.assertEqual(len(queued["pending_approvals"]), 1)
            request_id = queued["pending_approvals"][0]["id"]
            self.assertEqual(queued["pending_approvals"][0]["host"], KEY[2])

            next_event = asyncio.create_task(anext(stream))
            self.assertTrue(self.manager.decide(request_id, grant=True, duration="5m"))
            granted = event_data(await asyncio.wait_for(next_event, 2))
            self.assertEqual(granted["pending_approvals"], [])
            self.assertEqual(len(granted["active_grants"]), 1)
            self.assertGreater(granted["approval_revision"], queued["approval_revision"])
            await asyncio.wait_for(waiting, 2)

            next_event = asyncio.create_task(anext(stream))
            grant_id = granted["active_grants"][0]["id"]
            self.assertTrue(self.manager.revoke(grant_id))
            revoked = event_data(await asyncio.wait_for(next_event, 2))
            self.assertEqual(revoked["active_grants"], [])

            await stream.aclose()
            self.assertFalse(self.manager._listeners)

    async def test_stream_stops_on_viewer_session_revocation(self) -> None:
        signed_in = {"value": True}
        with patch.object(ViewerAuth, "valid", side_effect=lambda _, **kwargs: signed_in["value"]):
            response = await self.events(fake_request())
            stream = response.body_iterator
            await asyncio.wait_for(anext(stream), 2)
            signed_in["value"] = False
            self.manager._signal()
            reply = await asyncio.wait_for(anext(stream), 2)
            self.assertEqual(reply, "event: logout\ndata: {}\n\n")
            with self.assertRaises(StopAsyncIteration):
                await asyncio.wait_for(anext(stream), 2)
            self.assertFalse(self.manager._listeners)

    async def test_passive_sse_events_do_not_refresh_session_and_revoke_after_idle(self) -> None:
        auth = ViewerAuth(HistoryStore(self.store), self.password)
        session = auth.login("background", self.password)
        assert session is not None
        previous_activity = time.time() - 120
        with self.store._connect() as db:
            db.execute("UPDATE history_sessions SET last_seen=? WHERE hash=?",
                       (previous_activity, auth._digest(session)))
        response = await self.events(fake_request(session))
        self.assertIsInstance(response, StreamingResponse)
        stream = response.body_iterator
        self.assertIn("pending_approvals", event_data(await asyncio.wait_for(anext(stream), 2)))
        for _ in range(3):
            self.manager._signal()
            self.assertIn("approval_revision", event_data(await asyncio.wait_for(anext(stream), 2)))
        with self.store._connect() as db:
            last_seen = db.execute("SELECT last_seen FROM history_sessions WHERE hash=?",
                                   (auth._digest(session),)).fetchone()[0]
        self.assertEqual(last_seen, previous_activity)
        # Simulate a hidden tab spanning the entire idle interval without
        # waiting hours or depending on browser background timers.
        with self.store._connect() as db:
            db.execute("UPDATE history_sessions SET last_seen=? WHERE hash=?",
                       (time.time() - IDLE_SECONDS - 1, auth._digest(session)))
        self.manager._signal()
        self.assertEqual(await asyncio.wait_for(anext(stream), 2),
                         "event: logout\ndata: {}\n\n")
        with self.assertRaises(StopAsyncIteration):
            await asyncio.wait_for(anext(stream), 2)
        self.assertFalse(self.manager._listeners)

    async def test_event_coalescing_is_bounded_for_slow_browser(self) -> None:
        listener = self.manager.subscribe()
        for _ in range(200):
            self.manager._signal()
        self.assertEqual(listener.qsize(), 1)
        self.manager.unsubscribe(listener)
        self.assertFalse(self.manager._listeners)
