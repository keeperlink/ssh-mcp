"""Manage service logging and host rechecks through its private local socket."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import sys
from typing import Any

from .control import LEVELS, LIMIT, SOCKET, TIMEOUT, RECHECK_TIMEOUT


def request(action: str, level: str | None = None, *, path: Path = SOCKET,
            alias: str | None = None) -> dict[str, Any]:
    message = {"action": action}
    if level is not None:
        message["level"] = level
    if alias is not None:
        message["alias"] = alias
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(RECHECK_TIMEOUT + TIMEOUT if alias is not None else TIMEOUT)
        client.connect(str(path))
        client.sendall(json.dumps(message).encode() + b"\n")
        with client.makefile("rb") as stream:
            line = stream.readline(LIMIT + 1)
    if len(line) > LIMIT or not line.endswith(b"\n"):
        raise ValueError("Invalid control response")
    result = json.loads(line)
    if type(result) is not dict or result.get("status") != "ok":
        raise ValueError("Control request rejected")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    for action in ("get", "set", "reset"):
        sub = actions.add_parser(action)
        sub.add_argument("setting", choices=("logging-level",))
        if action == "set":
            sub.add_argument("level", choices=LEVELS)
    actions.add_parser("recheck-host").add_argument("alias")
    args = parser.parse_args(argv)
    try:
        if args.action == "recheck-host":
            result = request(args.action, alias=args.alias)
        else:
            result = request(args.action, getattr(args, "level", None))
    except (OSError, ValueError):
        print("Local control unavailable or request rejected", file=sys.stderr)
        return 1
    if args.action == "recheck-host":
        host = result["host"]
        print(json.dumps(host, sort_keys=True))
        return 0 if host.get("recheck_ok") is True else 1
    print(f"Configured: {result['configured']}\nEffective: {result['effective']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
