"""Root-only hash-file application for local Linux accounts and Proxmox guests.

Never accept a password or hash in argv. The input file is transferred
privately using a bounded opaque host-to-host channel and is consumed locally.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
from typing import Any

from ssh_mcp_secrets import cli

_HASH = re.compile(r"\$6\$[./a-zA-Z0-9]{1,16}\$[./a-zA-Z0-9]{86}\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")


def _manifest(path: Path, expected_sha256: str) -> dict[str, Any]:
    if _SHA.fullmatch(expected_sha256) is None:
        raise cli.RotationError("Missing exact hash-file digest")
    cli._private_dir(path.parent)
    raw = cli._read_file(path, private=True, maximum=65536)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise cli.RotationError("Transferred hash-file digest mismatch")
    data = cli._decode(raw)
    if (type(data.get("version")) is not int or data["version"] != 1
            or data.get("type") not in ("host-hash-only", "proxmox-hash-only")
            or type(data.get("source_sha256")) is not str
            or _SHA.fullmatch(data["source_sha256"]) is None
            or type(data.get("staged_sha256")) is not str
            or _SHA.fullmatch(data["staged_sha256"]) is None
            or type(data.get("inventory_sha256")) is not str
            or _SHA.fullmatch(data["inventory_sha256"]) is None):
        raise cli.RotationError("Untrusted hash-file metadata")
    expected = {"version", "type", "source_sha256", "staged_sha256", "inventory_sha256"}
    expected.add("entry" if data["type"] == "host-hash-only" else "entries")
    if set(data) != expected:
        raise cli.RotationError("Unexpected hash-file fields")
    entries = [data["entry"]] if "entry" in data else data["entries"]
    if type(entries) is not list or not 1 <= len(entries) <= 200:
        raise cli.RotationError("Invalid host hash entries")
    aliases: set[str] = set()
    vmids: set[int] = set()
    for entry in entries:
        if type(entry) is not dict or type(entry.get("alias")) is not str:
            raise cli.RotationError("Malformed host hash entry")
        alias = entry["alias"]
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", alias):
            raise cli.RotationError("Invalid host alias")
        if (entry.get("username") != "gateway" or
                type(entry.get("hash")) is not str or
                _HASH.fullmatch(entry["hash"]) is None or alias in aliases):
            raise cli.RotationError("Invalid gateway hash or duplicate alias")
        required = {"alias", "username", "hash"}
        if data["type"] == "proxmox-hash-only":
            required.add("vmid")
            vmid = entry.get("vmid")
            if type(vmid) is not int or not 100 <= vmid <= 999999 or vmid in vmids:
                raise cli.RotationError("Invalid Proxmox VMID")
            vmids.add(vmid)
        if set(entry) != required:
            raise cli.RotationError("Unexpected host hash entry field")
        aliases.add(alias)
    return data


def _run(argv: list[str], *, payload: bytes | None = None, timeout: int = 30) -> bytes:
    # Reject output from the remote command rather than printing it; all
    # stdout/stderr are potentially sensitive until independently inspected.
    result = subprocess.run(argv, input=payload, capture_output=True,
                            check=False, timeout=timeout)
    if result.returncode:
        raise cli.RotationError("Password update or guest-agent validation failed")
    return result.stdout


def apply_local(*, file: Path, sha256: str, alias: str) -> str:
    if os.geteuid() != 0:
        raise cli.RotationError("Root is required")
    info = _manifest(file, sha256)
    if info["type"] != "host-hash-only" or info["entry"]["alias"] != alias:
        raise cli.RotationError("Hash file not bound to this host")
    if socket.gethostname().split(".", 1)[0] != alias:
        raise cli.RotationError("Host identity does not match requested alias")
    _run(["/usr/sbin/chpasswd", "--encrypted"],
         payload=("gateway:" + info["entry"]["hash"] + "\n").encode("ascii"))
    return alias


def apply_proxmox(*, file: Path, sha256: str,
                  controller_host: str, expected_count: int) -> list[str]:
    if os.geteuid() != 0:
        raise cli.RotationError("Root is required")
    info = _manifest(file, sha256)
    if info["type"] != "proxmox-hash-only":
        raise cli.RotationError("Proxmox hash-file type required")
    if socket.gethostname().split(".", 1)[0] != controller_host:
        raise cli.RotationError("Proxmox controller identity mismatch")
    entries = info["entries"]
    if expected_count <= 0 or len(entries) != expected_count:
        raise cli.RotationError("Unexpected VM target count")
    # All identities verified before changing any guest password.
    for entry in entries:
        vmid, alias = entry["vmid"], entry["alias"]
        config = _run(["/usr/sbin/qm", "config", str(vmid), "--current"])
        expected = "name: " + alias
        if expected not in config.decode("utf-8", errors="replace").splitlines():
            raise cli.RotationError("VMID does not match expected guest hostname")
        _run(["/usr/sbin/qm", "guest", "cmd", str(vmid), "ping"])
    done: list[str] = []
    for entry in entries:
        vmid, alias = entry["vmid"], entry["alias"]
        payload = ("gateway:" + entry["hash"] + "\n").encode("ascii")
        output = _run([
            "/usr/sbin/qm", "guest", "exec", str(vmid),
            "--pass-stdin", "1", "--timeout", "30", "--", "/usr/sbin/chpasswd", "--encrypted",
        ], payload=payload, timeout=45)
        try:
            response = json.loads(output)
        except (ValueError, UnicodeDecodeError, TypeError):
            raise cli.RotationError("Guest command outcome not confirmed") from None
        if (type(response) is not dict or response.get("exited") != 1
                or response.get("exitcode") != 0):
            raise cli.RotationError("Guest password update failed or is uncertain")
        done.append(alias)
        print("APPLIED=" + alias, flush=True)
    return done


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    local = sub.add_parser("local")
    vm = sub.add_parser("proxmox")
    for item in (local, vm):
        item.add_argument("--file", type=Path, required=True)
        item.add_argument("--expected-sha256", required=True)
    local.add_argument("--alias", required=True)
    vm.add_argument("--controller-host", required=True)
    vm.add_argument("--expected-count", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode == "local":
            print("LOCAL_APPLIED=" + apply_local(file=args.file, sha256=args.expected_sha256,
                                                  alias=args.alias))
        else:
            completed = apply_proxmox(file=args.file, sha256=args.expected_sha256,
                                      controller_host=args.controller_host,
                                      expected_count=args.expected_count)
            print("PROXMOX_APPLIED=" + str(len(completed)))
        return 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired):
        print("Hash-only password operation rejected; inspect target and recovery status",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
