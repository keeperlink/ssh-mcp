"""Local administrative list/revoke for public-client DCR registrations.

Run only with administrative file access to the persistent private OAuth database.
No HTTP registration-management endpoint or client credential is exposed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .dcr_registry import DCRStore
from .control import SOCKET
from .control_cli import request as control_request


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage local public-client DCR registrations")
    parser.add_argument("--db", type=Path, required=True, help="existing private jobs.sqlite")
    subs = parser.add_subparsers(dest="action", required=True)
    subs.add_parser("list", help="list registered client IDs and last use")
    remove = subs.add_parser("revoke", help="remove a registration and revoke its OAuth sessions")
    remove.add_argument("client_id")
    remove.add_argument("--confirm-id", required=True,
                        help="repeat exactly the client ID being revoked")
    remove.add_argument("--offline", action="store_true",
                        help="explicit offline DB maintenance; restart service before relying on names")
    args = parser.parse_args(argv)
    if args.db.is_symlink() or not args.db.is_file():
        parser.error("OAuth database must already exist and must not be a symlink")
    store = DCRStore(args.db)
    if args.action == "list":
        print(json.dumps(store.list_clients(), indent=2, sort_keys=True))
        return 0
    if args.client_id != args.confirm_id or not args.client_id.startswith("dcr_"):
        parser.error("Client ID confirmation mismatch")
    deleted = store.revoke(args.client_id)
    if args.offline:
        print("Offline revocation committed; restart SSH-MCP before relying on displayed names.",
              file=sys.stderr)
    else:
        try:
            control_request("reload-dcr-names", path=SOCKET)
        except (OSError, ValueError):
            print("Registration change committed; running service cache refresh unavailable. "
                  "Restart SSH-MCP before relying on displayed names.", file=sys.stderr)
            return 2
    print("Registration revoked" if deleted else "Registration not found")
    return 0 if deleted else 1


if __name__ == "__main__":
    raise SystemExit(main())
