"""Local development entry point. Never binds to a public interface by default."""
from __future__ import annotations

import os

import uvicorn


def main() -> None:
    host = os.getenv("MCP_BIND_HOST", "127.0.0.1")
    port = int(os.getenv("MCP_BIND_PORT", "8000"))
    if not 1 <= port <= 65535:
        raise ValueError("MCP_BIND_PORT must be between 1 and 65535")
    uvicorn.run("app.main:app", host=host, port=port, access_log=False)


if __name__ == "__main__":
    main()
