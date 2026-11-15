"""Stable compact approval audit codes; keep storage and API representations distinct."""
from __future__ import annotations

from contextvars import ContextVar
from enum import IntEnum

from .ssh_executor import SSHDenied


class ApprovalCode(IntEnum):
    APPROVED_CONFIG = 1
    APPROVED_EXPLICIT = 2
    APPROVED_TIMED = 3
    DENIED_CONFIG = 4
    DENIED_EXPLICIT = 5
    DENIED_EXPIRED = 6
    DENIED_DISCONNECTED = 7
    DENIED_REVOKED = 8


def decode(code: int | None) -> str | None:
    """Translate stable integer storage to the public API string."""
    if code is None:
        return None
    try:
        value = ApprovalCode(code)
    except ValueError:
        return None
    return value.name.lower()


# Set by the authenticated dispatcher only; reset at the MCP request boundary.
approval_status_context: ContextVar[int | None] = ContextVar(
    "approval_status", default=None,
)


class ApprovalRejected(SSHDenied):
    """Known terminal permission refusal, not a failure of an SSH command."""

    def __init__(self, code: ApprovalCode, message: str):
        super().__init__(message)
        self.approval_code = int(code)
