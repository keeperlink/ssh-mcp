"""Preview-only ASGI entrypoint; never imported by the normal service."""
import os

from runtime_cleanup import prepare_for_reload

prepare_for_reload()

from app.main import app  # noqa: E402

if os.environ.get("SSH_MCP_PREVIEW_TRACE") == "1":
    from request_trace import PreviewRequestTrace
    app.add_middleware(PreviewRequestTrace)
