"""Per-request conversation correlation and fail-closed host-access gate."""
from __future__ import annotations

from contextvars import ContextVar
import re
from typing import Awaitable, Callable, Mapping

from starlette.datastructures import Headers

from . import config
from .approvals import ApprovalManager
from .approval_status import ApprovalCode, ApprovalRejected
from .ssh_executor import SSHDenied, SSHExecutor

_CONVERSATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:-]{0,255}$")
conversation_id_context: ContextVar[str | None] = ContextVar("conversation_id", default=None)


def conversation_id_from_headers(
    headers: Mapping[str, str] | None, *, client_id: str | None = None,
) -> str | None:
    """Only explicitly configured sources for the authenticated client count."""
    return conversation_id_from_request(headers, client_id=client_id)


def conversation_id_from_request(
    headers: Mapping[str, str] | None,
    metadata: Mapping[str, object] | None = None,
    *, client_id: str | None = None,
) -> str | None:
    """Fail closed on conflicting values from a client's explicit selectors."""
    from .client_registry import sources_for

    values: list[str] = []

    def add(value: object) -> None:
        if not isinstance(value, str) or not _CONVERSATION.fullmatch(value):
            raise ValueError("Invalid conversation identifier")
        values.append(value)

    for source in sources_for(client_id, config.MCP_CLIENTS):
        name = source["name"]
        if source["type"] == "header" and headers is not None:
            if isinstance(headers, Headers):
                values_for_name = headers.getlist(name)
            else:
                values_for_name = [value for key, value in headers.items()
                                   if key.lower() == name.lower()]
            for value in values_for_name:
                add(value)
        elif source["type"] == "metadata" and metadata is not None and name in metadata:
            raw_value = metadata[name]
            if "field" in source:
                if not isinstance(raw_value, dict):
                    raise ValueError("Invalid conversation metadata")
                if source["field"] not in raw_value:
                    continue
                raw_value = raw_value[source["field"]]
            add(raw_value)
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
    on_approved: Callable[[ApprovalCode], None] | None = None,
) -> ApprovalCode:
    """One entry gate for every host-reaching MCP method.

    Existing principal/key/pin checks remain enforced by SSHExecutor.
    Without a configured live approval manager restricted hosts fail closed.
    """
    host = executor.authorized_host(actor, server)
    if privileged and host.privileged_access == "none":
        raise ApprovalRejected(ApprovalCode.DENIED_CONFIG,
                               "Privileged host access is disabled")
    sealed_root = privileged and server in getattr(executor, "_sealed_sudo", {})
    if privileged and not sealed_root and server not in executor._sudo_passwords:
        raise SSHDenied("Privileged credentials are unavailable")
    host_required = host.access == "restricted"
    root_required = privileged and (
        host.privileged_access == "restricted" or sealed_root
    )
    if host_required or root_required:
        if not session_id:
            raise SSHDenied("Restricted host requires authenticated OAuth session")
        if approvals is None:
            raise SSHDenied("Restricted host requires operator approval")
        async def before_prompt() -> None:
            await executor.check_readiness_live(server, privileged=privileged and not sealed_root)

        # A verified OAuth client without a chat identifier gets an agent-wide
        # grant, reusable across that operator's OAuth sessions. The actor is
        # derived from the verified operator subject and OAuth client identity.
        # A client that supplies a conversation ID keeps its session-scoped key.
        key = ((session_id, conversation_id, server) if conversation_id else
               (f"agent:{actor}", client_id, server) if client_id else
               (session_id, "", server))
        code = await approvals.require(
            key,
            tool=tool, reason=reason, client_id=client_id,
            summary=summary,
            steps=steps,
            disconnected=disconnected,
            host_required=host_required, root_required=root_required,
            actor=actor,
            before_prompt=before_prompt,
        )
    else:
        code = ApprovalCode.APPROVED_CONFIG
    if on_approved is not None:
        on_approved(code)
    executor.require_ready(server, privileged=privileged and not sealed_root)
    return code
