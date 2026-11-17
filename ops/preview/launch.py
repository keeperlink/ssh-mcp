"""Nonproduction-only entrypoint; use the installed wheel unless source mode is explicit."""
from __future__ import annotations

import os

import uvicorn


def main() -> None:
    source_mode = os.environ.get("SSH_MCP_PREVIEW_SOURCE_MODE") == "1"
    if source_mode:
        os.environ["PYTHONPATH"] = "/opt/ssh-mcp-helper:/opt/ssh-mcp-preview"
        # The reloader child inherits Python's sys.path as well as environment.
        import sys
        sys.path.insert(0, "/opt/ssh-mcp-preview")
    uvicorn.run("reload_app:app", host="0.0.0.0", port=8000,
                access_log=False, reload=source_mode,
                reload_dirs=["/opt/ssh-mcp-preview/app"] if source_mode else None)


if __name__ == "__main__":
    main()
