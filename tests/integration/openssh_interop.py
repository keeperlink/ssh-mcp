"""Native OpenSSH interoperability against the isolated disposable fixture.

Run only inside a separately authorized rootless Docker fixture network.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from app.contracts import ExecuteCommandRequest
from app.ssh_executor import HostSpec, SSHExecutor


async def main() -> None:
    host = HostSpec.model_validate({
        "alias": "fixture",
        "address": "ssh-mcp-interop-sshd",
        "port": 22,
        "username": "tester",
        "identity_file": Path("/keys/identity"),
        "known_hosts_file": Path("/keys/known_hosts"),
        "principals": ["tester"],
        "environment": "non-production",
        "access": "always-granted",
        "privileged_access": "always-granted",
    })
    credential = Path("/keys/sudo-password").read_text(encoding="utf-8").strip()
    executor = SSHExecutor(
        {"fixture": host}, enabled=True,
        sudo_passwords={"fixture": credential},
    )

    def request(*argv: str, cwd: str | None = None,
                privileged: bool = False) -> ExecuteCommandRequest:
        return ExecuteCommandRequest(
            server="fixture", argv=list(argv), cwd=cwd,
            reason="TEST-265 disposable OpenSSH SSHD fixture acceptance",
            timeout_seconds=20, privileged=privileged,
        )

    ordinary = await executor.execute("tester", request("id", "-un"))
    assert (ordinary.status, ordinary.exit_code, ordinary.stdout.strip()) == (
        "succeeded", 0, "tester",
    ), ordinary
    print("OPENSSH_ORDINARY=PASS", flush=True)

    nested = await executor.execute("tester", request(
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=2",
        "-o", "StrictHostKeyChecking=yes", "-p", "1", "127.0.0.1", "true",
    ))
    assert nested.status == "command_error", nested
    assert nested.exit_code == 255 and nested.exit_accepted is False, nested
    assert "connection refused" in nested.stderr.lower(), nested
    print("OPENSSH_NESTED_EXIT_255=PASS", flush=True)

    cwd = await executor.execute("tester", request("pwd", cwd="/home/tester"))
    assert cwd.status == "succeeded" and cwd.stdout.strip() == "/home/tester", cwd
    assert cwd.effective_cwd == "/home/tester", cwd
    print("OPENSSH_INODE_PINNED_CWD=PASS", flush=True)

    privileged = await executor._execute_approved_privileged(
        "tester", request("id", "-un", privileged=True),
    )
    assert privileged.status == "succeeded" and privileged.exit_code == 0, privileged
    assert privileged.stdout.strip() == "root" and privileged.root_started is True, privileged
    print("OPENSSH_PASSWORD_SUDO_ROOT=PASS", flush=True)

    root255 = await executor._execute_approved_privileged(
        "tester", request("sh", "-c", "exit 255", privileged=True),
    )
    assert root255.status == "command_error" and root255.exit_code == 255, root255
    assert root255.exit_accepted is False and root255.root_started is True, root255
    print("OPENSSH_PRIVILEGED_EXIT_255=PASS", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
