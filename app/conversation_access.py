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
    """Read the configured provider header and optional neutral workflow header."""
    return conversation_id_from_request(headers)


def conversation_id_from_request(
    headers: Mapping[str, str] | None, metadata: Mapping[str, object] | None = None,
) -> str | None:
    """Validate all supplied correlation sources; never resolve ambiguous IDs."""
    values: list[str] = []

    def add(value: object) -> None:
        if not isinstance(value, str) or not _CONVERSATION.fullmatch(value):
            raise ValueError("Invalid conversation identifier")
        values.append(value)

    if headers is not None:
        for name in dict.fromkeys((
            config.MCP_CONVERSATION_HEADER_NAME.lower(), "x-ssh-mcp-conversation",
        )):
            if name in headers:
                add(headers[name])
    if metadata is not None and "x-codex-turn-metadata" in metadata:
        turn = metadata["x-codex-turn-metadata"]
        if not isinstance(turn, dict):
            raise ValueError("Invalid Codex conversation metadata")
        if "thread_id" in turn:
            add(turn["thread_id"])
    if len(set(values)) > 1:
        raise ValueError("Conflicting conversation identifiers")
    return values[0] if values else None


async def require_host_access(
    executor: SSHExecutor, actor: str, server: str,
    *, session_id: str | None, conversation_id: str | None,
    approvals: ApprovalManager | None = None, tool: str = "",
    reason: str = "", summary: str | Callable[[], str] = "",
    steps: Callable[[], list[dict[str, str | bool]]] | None = None,
    disconnected: Callable[[], Awaitable[bool]] | None = None,
    privileged: bool = False, client_id: str | None = None,
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
        if not session_id:
            raise SSHDenied("Restricted host requires authenticated OAuth session")
        if approvals is None:
            raise SSHDenied("Restricted host requires operator approval")
        return await approvals.require(
            (session_id, conversation_id or "", server),
            tool=tool, reason=reason, client_id=client_id,
            summary=summary,
            steps=steps,
            disconnected=disconnected,
            host_required=host_required, root_required=root_required,
        )
    return ApprovalCode.APPROVED_CONFIG
