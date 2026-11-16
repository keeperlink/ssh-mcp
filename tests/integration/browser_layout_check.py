"""Headless Chrome desktop/narrow and mixed command/file history UI acceptance.

Synthetic read-only local API; no SSH transport, credentials or browser edits.
Runs only in the GitHub Actions browser host gate, not the runtime OCI image.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from threading import Thread
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

# Make the fixture independent of developer and production environment secrets.
os.environ.setdefault("MCP_ISSUER", "http://localhost")
os.environ.setdefault("MCP_LOGIN_KEY", "synthetic-test-login-" + "a" * 40)
os.environ.setdefault("MCP_TOKEN_SIGNING_SECRET", "synthetic-test-signing-" + "b" * 40)
os.environ.setdefault("MCP_CIMD_VALIDATE_REMOTE", "false")

from app.history import _history_page  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime.now(timezone.utc).isoformat()
JOBS = [
    {
        "id": f"synthetic-{index}", "created_at": NOW, "updated_at": NOW,
        "server": "demo-node-a", "story_id": "TEST-232",
        "command_preview": f"echo synthetic-{index}", "command": f"echo synthetic-{index}",
        "status": "succeeded", "mode": "sync", "elapsed_seconds": 0.2, "exit_code": 0,
        "output_bytes": 0,
    }
    for index in range(250)
]
JOBS[3]["story_id"] = "owner/repo#12345678901234567890"
JOBS[240]["story_id"] = "KA-123"  # Not equal to ASCII KA-123.
JOBS[241]["story_id"] = "KA-123"
# Root execution is explicit audit metadata, never inferred from a command
# containing the word sudo. Include confirmed and unconfirmed retained jobs.
JOBS[5].update({"privileged": True, "root_started": True, "run_as": "root"})
JOBS[8].update({"privileged": True, "root_started": None, "run_as": "root"})
JOBS[11].update({"privileged": True, "root_started": True, "run_as": "root",
                 "status": "failed", "failure_kind": "root_setup_failed",
                 "error": "Privileged command setup failed"})
# Include read/write/patch/transfer outcomes alongside the 247 existing
# command records. File payloads and signed URLs NEVER belong in the API.
_FILE_ROWS = [
    ("upload", "binary.bin", "succeeded", 10550, {
        "transfer": {
            "direction": "upload", "mode": "create", "size": 10550,
            "sha256": "a" * 64, "eof": True,
        },
    }),
    ("patch", "notes.txt", "partial", 19, {
        "outcomes": [
            {"path": "/tmp/notes.txt", "action": "update",
             "status": "applied", "bytes": 19},
            {"path": "/tmp/missing.txt", "action": "delete",
             "status": "failed", "error_code": "not_found"},
            {"path": "/tmp/later.txt", "action": "add",
             "status": "not_attempted"},
        ],
    }),
    ("read", "notes.txt", "failed", 0, {}),
]
for index, (operation, leaf, status, size, metadata) in enumerate(_FILE_ROWS):
    JOBS[index].update({
        "id": "file-sky238-" + operation,
        "server": "demo-node-b", "story_id": "TEST-238",
        "command": operation, "command_preview": operation + " " + leaf,
        "mode": "file", "record_kind": "file", "operation_kind": operation,
        "path_summary": leaf, "status": status, "byte_count": size,
        "output_bytes": 0, "file_metadata": metadata,
        "error_code": "partial" if status == "partial" else (
            "permission_denied" if status == "failed" else None),
        "error": "partial" if status == "partial" else (
            "permission_denied" if status == "failed" else ""),
    })
# Long opaque IDs are synthetic: browser tests must filter on the complete
# value even though the details panel renders only a short clickable prefix.
SYNTHETIC_CONVERSATION = "v1/2TCYJpYfTRn20j4gmoj" + "q9w3e8r7t6y5u4i3o2p1"
for index in (0, 3):
    JOBS[index]["conversation_id"] = SYNTHETIC_CONVERSATION
TOTALS = {"total": 250, "running": 0, "succeeded": 247, "failed": 2, "cancelled": 0}
LIVE_JOB = {
    **JOBS[0], "id": "file-sky238-live", "command": "download",
    "command_preview": "download new-synthetic.bin",
    "operation_kind": "download", "path_summary": "new-synthetic.bin",
    "byte_count": 4096, "file_metadata": {
        "transfer": {"direction": "download", "offset": 0, "size": 4096,
                     "next_offset": 4096, "eof": True,
                     "sha256": "b" * 64, "chunk_sha256": "b" * 64},
    },
}
LIVE_STATE = {"inserted": False, "touched": False, "overlap_complete": False}
LIVE_EVENTS: list[dict[str, object]] = []
# More than twelve 16 KiB pages: the old viewer silently stopped short.
LARGE_OUTPUT = b"x" * (13 * 16384) + b"END_OF_CAPTURE"
JOBS[3]["output_bytes"] = len(LARGE_OUTPUT)
FINAL_OUTPUT = b"OUTPUT_AFTER_COMPLETION"
def viewer_page() -> bytes:
    return _history_page("synthetic-csrf").replace(
        "</body>", '<output id="layout-test-result">PENDING</output>'
        '<script src="/layout_fixture.js" defer></script></body>',
    ).encode("utf-8")


PAGE = viewer_page()
with patch.dict(os.environ, {"HISTORY_STORY_ID_MAX_CHARS": "11",
                             "HISTORY_STORY_ID_TRUNCATE_FROM": "start"}):
    PAGE_START = viewer_page()
with patch.dict(os.environ, {"HISTORY_STORY_ID_MAX_CHARS": "1",
                             "HISTORY_STORY_ID_TRUNCATE_FROM": "start"}):
    PAGE_ONE = viewer_page()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        pass  # No user data or authentication headers in fixture logs.

    def do_GET(self) -> None:
        url = urlsplit(self.path)
        if url.path == "/console":
            trim = parse_qs(url.query).get("trim", ["end"])[0]
            self.send(PAGE_ONE if trim == "one" else
                      PAGE_START if trim == "start" else PAGE, "text/html")
        elif url.path == "/console/assets/style.css":
            self.send((ROOT / "app/assets/style.css").read_bytes(), "text/css")
        elif url.path == "/console/assets/console.js":
            self.send((ROOT / "app/assets/console.js").read_bytes(), "text/javascript")
        elif url.path == "/console/assets/approvals.js":
            self.send((ROOT / "app/assets/approvals.js").read_bytes(), "text/javascript")
        elif url.path == "/console/api/approval-events":
            # This fixture verifies the actual shipped client against
            # synthetic snapshots; it deliberately opens no long-lived
            # authenticated stream or real service.
            self.send_response(204)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
        elif url.path == "/layout_fixture.js":
            self.send((ROOT / "tests/fixtures/browser_layout_fixture.js").read_bytes(), "text/javascript")
        elif url.path == "/console/api/hosts":
            self.json('{"hosts":["demo-node-a","demo-node-b","demo-sandbox"]}')
        elif url.path == "/console/api/test-publish":
            import json
            if not LIVE_STATE["inserted"]:
                LIVE_STATE["inserted"] = True
                JOBS.insert(0, LIVE_JOB)
                TOTALS["total"] += 1
                TOTALS["succeeded"] += 1
                LIVE_EVENTS.append(dict(LIVE_JOB))
            self.json(json.dumps({"ok": True}))
        elif url.path == "/console/api/test-touch":
            import json
            JOBS[3]["status"] = "running"
            LIVE_STATE["touched"] = True
            LIVE_EVENTS.append(dict(JOBS[3]))
            self.json(json.dumps({"ok": True}))
        elif url.path == "/console/api/test-overlap-start":
            import json
            JOBS[6]["status"] = "running"
            JOBS[6]["output_bytes"] = 0
            LIVE_STATE["overlap_complete"] = False
            self.json(json.dumps({"ok": True}))
        elif url.path == "/console/api/test-overlap-complete":
            import json
            JOBS[6]["status"] = "succeeded"
            JOBS[6]["output_bytes"] = len(FINAL_OUTPUT)
            LIVE_STATE["overlap_complete"] = True
            LIVE_EVENTS.append(dict(JOBS[6]))
            self.json(json.dumps({"ok": True}))
        elif url.path == "/console/api/test-parent-running":
            # A completed step remains selected while later batch steps run.
            # Parent changes do not emit new events for that terminal child.
            LIVE_STATE["parent_status"] = "running"
            self.json('{"ok":true}')
        elif url.path == "/console/api/test-parent-finished":
            LIVE_STATE["parent_status"] = "interrupted"
            self.json('{"ok":true}')
        elif url.path == "/console/api/test-cancel-start":
            import json
            if not LIVE_STATE.get("cancel_demo"):
                template = next(j for j in JOBS if j["id"] == "synthetic-10")
                records = [{
                    **template, "id": f"sky269-demo-{i:02d}",
                    "story_id": "TEST-269", "command": "sleep",
                    "command_preview": f"sleep {30+i}", "status": "running",
                    "mode": "async", "record_kind": "command",
                    "cancel_available": True, "elapsed_seconds": None,
                } for i in range(24)]
                JOBS[:0] = records
                TOTALS["total"] += 24
                TOTALS["running"] += 24
                LIVE_STATE["cancel_demo"] = True
            self.json(json.dumps({"ok": True}))
        elif url.path == "/console/api/test-cancel-touch":
            import json
            job_id = parse_qs(url.query).get("id", [""])[0]
            job = next((j for j in JOBS if j["id"] == job_id), None)
            if job is not None:
                job["updated_at"] = datetime.now(timezone.utc).isoformat()
                LIVE_EVENTS.append(dict(job))
            self.json(json.dumps({"ok": job is not None}))
        elif url.path == "/console/api/test-cancel-terminal":
            import json
            job_id = parse_qs(url.query).get("id", [""])[0]
            job = next((j for j in JOBS if j["id"] == job_id), None)
            if job is not None and job["status"] == "running":
                job["status"] = "cancelled"
                job["cancel_available"] = False
                job["updated_at"] = datetime.now(timezone.utc).isoformat()
                LIVE_EVENTS.append(dict(job))
                TOTALS["running"] -= 1
                TOTALS["cancelled"] += 1
            self.json(json.dumps({"ok": job is not None}))
        elif url.path == "/console/api/test-cancel-cleanup":
            import json
            if LIVE_STATE.pop("cancel_demo", False):
                JOBS[:] = [job for job in JOBS
                           if not job["id"].startswith("sky269-demo-")]
                TOTALS["total"] -= 24
                TOTALS["running"] -= 23
                TOTALS["cancelled"] -= 1
            self.json(json.dumps({"ok": True}))
        elif url.path == "/console/api/jobs":
            import json
            q = parse_qs(url.query)
            limit = int(q.get("limit", ["15"])[0])
            page = int(q.get("page", ["1"])[0])
            filtered = JOBS
            for key, attr in (("mode", "mode"), ("host", "server"),
                              ("story_id", "story_id"), ("status", "status"),
                              ("conversation_id", "conversation_id")):
                requested = q.get(key, [""])[0]
                if key == "story_id":
                    requested = requested.strip()
                if requested:
                    if key == "story_id" and requested.isascii() and requested.isdigit() and len(requested) <= 9:
                        suffix = "-" + str(int(requested))
                        filtered = [job for job in filtered
                                    if str(job.get(attr) or "").endswith(suffix)]
                    else:
                        if key == "story_id":
                            import re
                            if re.fullmatch(r"[A-Z][A-Z0-9]{1,12}-[1-9][0-9]*",
                                            requested, flags=re.IGNORECASE | re.ASCII):
                                requested = requested.upper()
                                filtered = [job for job in filtered if
                                            str(job.get(attr) or "").isascii() and
                                            str(job.get(attr) or "").upper() == requested]
                                continue
                        filtered = [job for job in filtered if job.get(attr) == requested]
            command = q.get("command", [""])[0].lower()
            if command:
                filtered = [job for job in filtered if command in
                            (job.get("command_preview") or job["command"]).lower()]
            if q.get("privileged", [""])[0] == "true":
                filtered = [job for job in filtered
                            if job.get("record_kind") != "file"
                            and job.get("privileged") is True]
            page_count = max(1, (len(filtered) + limit - 1) // limit)
            page = min(page, page_count)
            start = (page - 1) * limit
            self.json(json.dumps({
                "jobs": filtered[start:start + limit],
                "page": page, "page_size": limit, "page_count": page_count,
                "filtered_total": len(filtered), "totals": TOTALS,
                "changes_cursor": str(len(LIVE_EVENTS)) + ":_",
                "next_page": None,
            }))
        elif url.path == "/console/api/summary":
            import json
            self.json(json.dumps({"totals": TOTALS}))
        elif url.path == "/console/api/changes":
            import json
            since = parse_qs(url.query).get("after", ["0:_"])[0]
            offset = int(since.split(":")[0])
            new = LIVE_EVENTS[offset:]
            self.json(json.dumps({
                "jobs": new, "has_more": False,
                "changes_cursor": str(len(LIVE_EVENTS)) + ":_",
            }))
        elif url.path.startswith("/console/api/jobs/") and url.path.endswith("/output"):
            import json
            job_id = url.path.split("/")[-2]
            query = parse_qs(url.query)
            offset = int(query.get("cursor", ["0"])[0])
            limit = min(16384, int(query.get("max_bytes", ["16384"])[0]))
            capture = (LARGE_OUTPUT if job_id == "synthetic-3" else
                       FINAL_OUTPUT if job_id == "synthetic-6"
                       and LIVE_STATE["overlap_complete"] else b"")
            chunk = capture[offset:offset + limit]
            next_cursor = offset + len(chunk)
            self.json(json.dumps({
                "chunks": ([{"stream": "stdout",
                             "data_base64": base64.b64encode(chunk).decode("ascii")}]
                           if chunk else []),
                "next_cursor": next_cursor,
                "truncated": next_cursor < len(capture),
            }))
        elif url.path.startswith("/console/api/jobs/"):
            import json
            job_id = url.path.split("/")[-1]
            job = next((item for item in JOBS if item["id"] == job_id), JOBS[0])
            file_job = job.get("record_kind") == "file"
            details = dict(job)
            if job_id == "synthetic-4" and LIVE_STATE.get("parent_status"):
                details["batch_step_outcome"] = {
                    "batch_status": LIVE_STATE["parent_status"],
                    "step_status": "succeeded",
                    "step_index": 0, "result_status": "succeeded",
                    "batch_failure_kind": (
                        "cancelled" if LIVE_STATE["parent_status"] == "interrupted"
                        else None
                    ),
                }
                if LIVE_STATE["parent_status"] == "interrupted":
                    details["cancellation_request"] = {
                        "target_type": "batch", "requested_via": "history",
                        "requested_at": NOW, "reason": "Cancelled from History viewer",
                    }
            if not file_job:
                details.update({
                    "terminal_command": job["command"],
                    "request": {
                        "argv": ["echo", job_id], "reason": "Synthetic layout test",
                        "timeout_seconds": 60,
                    },
                })
            self.json(json.dumps({"job": details}))
        else:
            self.send_response(404)
            self.end_headers()

    def json(self, content: str) -> None:
        self.send(content.encode("utf-8"), "application/json")

    def send(self, content: bytes, mime: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def main() -> None:
    chrome = next((shutil.which(name) for name in
                   ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser")
                   if shutil.which(name)), None)
    if not chrome:
        raise RuntimeError("Headless Chrome/Chromium required for narrow-pane browser acceptance")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for profile, window, trim in (("narrow", "900,1050", "end"),
                                      ("desktop", "1440,1050", "start"),
                                      ("desktop", "1440,1050", "one")):
            with tempfile.TemporaryDirectory(prefix="sky238-layout-") as user_data:
                result = subprocess.run([
                    chrome, "--headless=new", "--no-sandbox", "--disable-gpu",
                    "--disable-dev-shm-usage", "--no-first-run",
                    "--no-default-browser-check", "--hide-scrollbars",
                    "--disable-extensions", f"--window-size={window}",
                    "--virtual-time-budget=15000",
                    f"--user-data-dir={user_data}", "--dump-dom",
                    f"http://127.0.0.1:{server.server_port}/console?layout={profile}&trim={trim}",
                ], text=True, capture_output=True, timeout=65, check=False)
            if (result.returncode or
                    f'<output id="layout-test-result">PASS {profile}</output>'
                    not in result.stdout):
                import re
                marker = re.search(r'<output id="layout-test-result">([^<]*)',
                                   result.stdout)
                raise AssertionError(
                    f"Browser {profile} failed: code={result.returncode}, "
                    f"result={marker.group(1) if marker else 'not-reached'}, "
                    f"Chrome stderr tail={result.stderr[-700:]}"
                )
            print(f"PASS: {profile} ({trim}) mixed command/file metadata, filters, "
                  "pagination, keyboard, refresh, read-only controls")
            if LIVE_STATE["inserted"]:
                JOBS.remove(LIVE_JOB)
                LIVE_STATE["inserted"] = False
                TOTALS["total"] = 250
                TOTALS["succeeded"] = 248
            JOBS[3]["status"] = "succeeded"
            JOBS[6]["status"] = "succeeded"
            JOBS[6]["output_bytes"] = 0
            LIVE_STATE["touched"] = False
            LIVE_STATE["overlap_complete"] = False
            LIVE_EVENTS.clear()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    main()
