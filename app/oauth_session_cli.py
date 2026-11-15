"""Local-only OAuth session administration, independent of signed web startup."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .oauth_sessions import SessionStore


def main() -> None:
    parser = argparse.ArgumentParser(description="Private OAuth session inventory and revocation")
    actions = parser.add_subparsers(dest="action", required=True)
    listing = actions.add_parser("list", help="List active sessions")
    listing.add_argument("--all", action="store_true", help="Also show revoked/inactive sessions")
    revoke = actions.add_parser("revoke", help="Revoke one authorization session")
    revoke.add_argument("session_id")
    actions.add_parser("revoke-all", help="Revoke all authorization sessions")
    args = parser.parse_args()

    database = os.getenv("SSH_JOBS_DB")
    if not database:
        parser.error("SSH_JOBS_DB must identify an existing private SQLite database")
    db_path = Path(database)
    if not db_path.is_absolute() or not db_path.is_file():
        parser.error("SSH_JOBS_DB must identify an existing private SQLite database")

    if args.action == "list":
        # No schema initialization, expired-row pruning or database writes.
        # Never print refresh-token hashes, bearer tokens or login credentials.
        print(json.dumps(SessionStore.read_sessions(db_path, active_only=not args.all), indent=2))
    else:
        # Revocation is intentional; avoid deleting unrelated expired records.
        store = SessionStore(db_path, prune_on_init=False)
        if args.action == "revoke":
            print(f"revoked={store.revoke(args.session_id)}")
        else:
            print(f"revoked={store.revoke()}")


if __name__ == "__main__":
    main()
