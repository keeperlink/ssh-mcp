"""Create disposable sealed-v2 credentials inside the isolated LAB image.

Invoked only by the independently pinned lab runner, using a networkless
container and a bind-mounted, run-owned directory. No credential is passed
through argv, environment, stdout, image layers or the application checkout.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets

from app.runtime_files import managed_secrets_fingerprint
from app.sealed_credentials import from_legacy

DATA = Path("/lab-data")
SOURCE = "/run/ssh-mcp/protected/ssh-mcp-secrets"


def _write_new(path: Path, value: str) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        output.write(value)


def main() -> None:
    private = DATA / "secrets"
    base = DATA / "mcp.env"
    if (not private.is_dir() or private.is_symlink() or
            not base.is_file() or base.is_symlink() or
            (DATA / "client.env").exists()):
        raise RuntimeError("Invalid disposable LAB fixture directory")
    env = dict(line.split("=", 1) for line in base.read_text().splitlines())
    aliases = env.get("SSH_APPROVED_ALIASES")
    if (env.get("MCP_ENVIRONMENT") != "lab"
            or env.get("MCP_ISSUER") != "http://localhost"
            or aliases not in {"fixture", "fixture,fixture-dest"}
            or set(env) & {"MCP_LOGIN_KEY", "HISTORY_VIEWER_PASSWORD",
                           "MCP_METRICS_TOKEN", "MCP_MANAGED_SECRETS_VERSION"}):
        raise RuntimeError("Refusing non-synthetic LAB credential source")
    inventory = json.loads((private / "inventory.json").read_text())
    hosts = inventory.get("hosts")
    expected = [("fixture", "ssh-fixture")]
    if aliases == "fixture,fixture-dest":
        expected.append(("fixture-dest", "ssh-fixture-dest"))
    if (not isinstance(hosts, list) or len(hosts) != len(expected)
            or any(not isinstance(host, dict)
                   or host.get("alias") != alias
                   or host.get("address") != address
                   or host.get("username") != "tester"
                   or host.get("environment") != "non-production"
                   for host, (alias, address) in zip(hosts, expected))):
        raise RuntimeError("Refusing non-synthetic SSH hosts")
    sudo_passwords = {}
    for host in hosts:
        alias = host["alias"]
        file_name = ("fixture-sudo-password" if alias == "fixture"
                     else "fixture-dest-sudo-password")
        sudo_path = DATA / file_name
        sudo = sudo_path.read_text().strip() if sudo_path.is_file() else None
        if ((host["privileged_access"] != "none") != (sudo is not None)
                or (sudo is not None and len(sudo) < 32)):
            raise RuntimeError("Synthetic sudo fixture mismatch")
        if sudo is not None:
            sudo_passwords[alias] = sudo
    if len(sudo_passwords) == 2 and len(set(sudo_passwords.values())) != 2:
        raise RuntimeError("Synthetic sudo passwords must be independent")
    login = secrets.token_hex(32)
    console = secrets.token_urlsafe(36)
    metrics = secrets.token_hex(32)
    legacy = {
        "version": 1, "oauth_login_key": login,
        "oauth_signing_key": env["MCP_TOKEN_SIGNING_SECRET"],
        "viewer_password": console, "metrics_token": metrics,
        "ssh_private_key": (private / "identity").read_text(),
        "sudo_passwords": sudo_passwords,
    }
    sealed = from_legacy(legacy, console_password=console, deployment="lab",
                         issuer="http://localhost",
                         hosts={host["alias"]: "tester" for host in hosts})
    protected = private / "protected"
    if not protected.is_dir() or protected.is_symlink():
        raise RuntimeError("Missing isolated protected secret directory")
    _write_new(protected / "ssh-mcp-secrets",
               json.dumps(sealed, sort_keys=True, separators=(",", ":")) + "\n")
    extra = {
        "MCP_MANAGED_SECRETS_VERSION": "2",
        "MCP_MANAGED_SECRETS_SOURCE": SOURCE,
        "MCP_MANAGED_SECRETS_DIGEST": managed_secrets_fingerprint(sealed),
        "MCP_LOGIN_VERIFIER": json.dumps(sealed["oauth_login_verifier"], separators=(",", ":")),
        "HISTORY_VIEWER_VERIFIER": json.dumps(sealed["viewer_verifier"], separators=(",", ":")),
        "HISTORY_VIEWER_GENERATION": sealed["viewer_generation"],
        "MCP_METRICS_VERIFIER": json.dumps(sealed["metrics_verifier"], separators=(",", ":")),
        "HISTORY_VIEWER_ENABLED": "true",
        "MCP_METRICS_ENABLED": "true",
    }
    _write_new(DATA / "mcp.sealed.env",
               base.read_text() + "".join(f"{key}={value}\n" for key, value in extra.items()))
    os.replace(DATA / "mcp.sealed.env", base)
    _write_new(DATA / "client.env",
               f"MCP_LOGIN_KEY={login}\nHISTORY_VIEWER_PASSWORD={console}\n"
               f"MCP_METRICS_TOKEN={metrics}\n")


if __name__ == "__main__":
    main()
