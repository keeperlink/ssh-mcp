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
    if (env.get("MCP_ENVIRONMENT") != "lab"
            or env.get("MCP_ISSUER") != "http://localhost"
            or env.get("SSH_APPROVED_ALIASES") != "fixture"
            or set(env) & {"MCP_LOGIN_KEY", "HISTORY_VIEWER_PASSWORD",
                           "MCP_METRICS_TOKEN", "MCP_MANAGED_SECRETS_VERSION"}):
        raise RuntimeError("Refusing non-synthetic LAB credential source")
    inventory = json.loads((private / "inventory.json").read_text())
    host = inventory["hosts"][0]
    if (len(inventory["hosts"]) != 1 or host["alias"] != "fixture"
            or host["address"] != "ssh-fixture" or host["username"] != "tester"
            or host["environment"] != "non-production"):
        raise RuntimeError("Refusing non-synthetic SSH host")
    sudo_path = DATA / "fixture-sudo-password"
    sudo = sudo_path.read_text().strip() if sudo_path.is_file() else None
    if (host["privileged_access"] != "none") != (sudo is not None):
        raise RuntimeError("Synthetic sudo fixture mismatch")
    login = secrets.token_hex(32)
    console = secrets.token_urlsafe(36)
    metrics = secrets.token_hex(32)
    legacy = {
        "version": 1, "oauth_login_key": login,
        "oauth_signing_key": env["MCP_TOKEN_SIGNING_SECRET"],
        "viewer_password": console, "metrics_token": metrics,
        "ssh_private_key": (private / "identity").read_text(),
        "sudo_passwords": {"fixture": sudo} if sudo is not None else {},
    }
    sealed = from_legacy(legacy, console_password=console, deployment="lab",
                         issuer="http://localhost", hosts={"fixture": "tester"})
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
