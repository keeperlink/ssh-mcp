"""Per-request conversation correlation and fail-closed host-access gate."""
from __future__ import annotations

from contextvars import ContextVar
import re
from typing import Awaitable, Callable, Mapping

from . import config
from .approvals import ApprovalManager
from .approval_status import ApprovalCode, ApprovalRejected
from .ssh_executor import SSHDenied, SSHExecutor

_CONVERSATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:-]{0,255}$")
conversation_id_context: ContextVar[str | None] = ContextVar("conversation_id", default=None)


def conversation_id_from_headers(headers: Mapping[str, str] | None) -> str | None:
    """Return a bounded opaque correlation ID, never an authorization identity."""
    if headers is None:
        return None
    value = headers.get(config.MCP_CONVERSATION_HEADER_NAME.lower())
    if value is None:
        return None
    if not _CONVERSATION.fullmatch(value):
        raise ValueError("Invalid conversation header")
    return value


async def require_host_access(
    executor: SSHExecutor, actor: str, server: str,
    *, session_id: str | None, conversation_id: str | None,
    approvals: ApprovalManager | None = None, tool: str = "",
    reason: str = "", summary: str | Callable[[], str] = "",
    steps: Callable[[], list[dict[str, str | bool]]] | None = None,
    disconnected: Callable[[], Awaitable[bool]] | None = None,
    privileged: bool = False,
) -> ApprovalCode:
    """One entry gate for every host-reaching MCP method.

    Existing principal/key/pin checks remain enforced by SSHExecutor.
    Without a configured live approval manager restricted hosts fail closed.
    """
    host = executor.authorized_host(actor, server)
    if privileged and host.privileged_access == "none":
        raise ApprovalRejected(ApprovalCode.DENIED_CONFIG,
                               "Privileged host access is disabled")
    if privileged and server not in executor._sudo_passwords:
        raise SSHDenied("Privileged credentials are unavailable")
    host_required = host.access == "restricted"
    root_required = privileged and host.privileged_access == "restricted"
    if host_required or root_required:
        if not session_id or not conversation_id:
            raise SSHDenied("Restricted host requires authenticated conversation")
        if approvals is None:
            raise SSHDenied("Restricted host requires operator approval")
        return await approvals.require(
            (session_id, conversation_id, server),
            tool=tool, reason=reason,
            summary=summary,
            steps=steps,
            disconnected=disconnected,
            host_required=host_required, root_required=root_required,
        )
    return ApprovalCode.APPROVED_CONFIG
