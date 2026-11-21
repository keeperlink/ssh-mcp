"""Persistent, single-instance OAuth session families in the existing private jobs.sqlite.

Never store bearer or refresh token plaintext. Deliberately reject duplicate
refreshes for 10 seconds without family revocation, then revoke on late replay.
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

from .sqlite_support import _ClosingConnection, _prepare_path

REFRESH_REPLAY_GRACE_SECONDS = 10


class ClientRegistrationRevoked(ValueError):
    """DCR client was removed before the session transaction could commit."""



def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _refresh_token() -> str:
    return secrets.token_urlsafe(48)


class SessionStore:
    """Per-operation SQLite transactions; no process-local token state."""

    def __init__(self, path: Path, *, prune_on_init: bool = True):
        _prepare_path(path)
        self.path = path
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS oauth_sessions (
                    id TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    signing_key_id TEXT NOT NULL,
                    revoked_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS oauth_refresh (
                    token_hash TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL REFERENCES oauth_sessions(id) ON DELETE CASCADE,
                    created_at INTEGER NOT NULL,
                    consumed_at INTEGER
                );
                CREATE INDEX IF NOT EXISTS oauth_sessions_expiry
                    ON oauth_sessions(expires_at);
                CREATE INDEX IF NOT EXISTS oauth_refresh_session
                    ON oauth_refresh(session_id);
            """)
        # Safe, additive migration for OAuth clients authorized before this
        # release. Old ChatGPT sessions retain their existing signed origins.
        with self._connect() as db:
            columns = {row["name"] for row in db.execute("PRAGMA table_info(oauth_sessions)")}
            if "redirect_origin" not in columns:
                db.execute("ALTER TABLE oauth_sessions ADD COLUMN redirect_origin TEXT")
        if prune_on_init:
            self.prune()

    def active_origins(self) -> list[str]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT DISTINCT redirect_origin FROM oauth_sessions "
                "WHERE redirect_origin IS NOT NULL AND revoked_at IS NULL AND expires_at>?",
                (int(time.time()),),
            ).fetchall()
        return [str(row[0]) for row in rows if row[0]]

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None,
                             factory=_ClosingConnection)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA secure_delete=ON")
        return db

    def prune(self) -> int:
        with self._connect() as db:
            return db.execute(
                "DELETE FROM oauth_sessions WHERE expires_at <= ?",
                (int(time.time()) - REFRESH_REPLAY_GRACE_SECONDS,)
            ).rowcount

    @staticmethod
    def _touch_dcr_client(db: sqlite3.Connection, client_id: str, now: int) -> bool:
        """Check registration and record use inside the session's write transaction."""
        return db.execute(
            "UPDATE oauth_dcr_clients SET last_used_at=? WHERE client_id=? RETURNING client_id",
            (now, client_id),
        ).fetchone() is not None

    def issue(self, *, client_id: str, subject: str, scopes: str, resource: str,
              expires_at: int, signing_key_id: str,
              redirect_origin: str | None = None, registered_client: bool = False,
              allow_refresh: bool = True) -> tuple[str, str | None]:
        now = int(time.time())
        if expires_at <= now:
            raise ValueError("OAuth session already expired")
        session_id = secrets.token_urlsafe(24)
        refresh_token = _refresh_token() if allow_refresh else None
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if registered_client and not self._touch_dcr_client(db, client_id, now):
                raise ClientRegistrationRevoked("OAuth registration was revoked")
            db.execute(
                """INSERT INTO oauth_sessions
                   (id,client_id,subject,scopes,resource,expires_at,created_at,signing_key_id,redirect_origin)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (session_id, client_id, subject, scopes, resource, expires_at,
                 now, signing_key_id, redirect_origin),
            )
            if refresh_token is not None:
                db.execute(
                    "INSERT INTO oauth_refresh(token_hash,session_id,created_at) VALUES(?,?,?)",
                    (_digest(refresh_token), session_id, now),
                )
        return session_id, refresh_token

    def rotate(self, *, refresh_token: str, client_id: str, resource: str,
               scopes: str | None, signing_key_id: str,
               expected_subject: str, registered_client: bool = False) -> dict[str, Any] | None:
        """Return only one successor; late replay revokes family atomically.

        Invalid or concurrent uses return None, never token values. A duplicate
        within the grace window does not revoke, even across server processes.

        Client/resource/scope binding is validated before replay-triggered
        revocation so that a foreign client presenting a consumed token from
        another family cannot revoke that family's session.
        """
        now = int(time.time())
        successor = _refresh_token()
        outcome: dict[str, Any] | None = None
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT t.consumed_at, s.id, s.client_id, s.subject, s.scopes,
                          s.resource, s.expires_at, s.revoked_at, s.signing_key_id
                   FROM oauth_refresh t JOIN oauth_sessions s ON s.id=t.session_id
                   WHERE t.token_hash=?""",
                (_digest(refresh_token),),
            ).fetchone()
            if row is None:
                return None
            if row["revoked_at"] is not None or row["expires_at"] <= now:
                return None
            if (row["signing_key_id"] != signing_key_id or
                    row["subject"] != expected_subject):
                # A signed operator-identity cutover must never turn a stored
                # legacy session into a new principal by rotating its token.
                # Revoke the family before consuming/minting any successor.
                db.execute("UPDATE oauth_sessions SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
                           (now, row["id"]))
            elif (row["client_id"] != client_id or row["resource"] != resource
                  or (scopes is not None and row["scopes"] != scopes)):
                # Binding mismatch: reject silently without revoking or
                # consuming the token. The presenting client has no standing
                # over this family regardless of whether the token is fresh
                # or already consumed.
                return None
            elif row["consumed_at"] is not None:
                # Same client, but token already consumed. Revoke the family
                # only if the grace window has passed; within it, treat as a
                # benign duplicate and return None without side-effects.
                if now > row["consumed_at"] + REFRESH_REPLAY_GRACE_SECONDS:
                    db.execute(
                        "UPDATE oauth_sessions SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
                        (now, row["id"]),
                    )
            else:
                # Serialize with administrative DCR revocation and update activity
                # before consuming the old refresh credential. If another writer
                # removed the registration, leave the token family untouched.
                if registered_client and not self._touch_dcr_client(db, client_id, now):
                    return None
                db.execute("UPDATE oauth_refresh SET consumed_at=? WHERE token_hash=?",
                           (now, _digest(refresh_token)))
                db.execute(
                    "INSERT INTO oauth_refresh(token_hash,session_id,created_at) VALUES(?,?,?)",
                    (_digest(successor), row["id"], now),
                )
                outcome = {
                    "session_id": row["id"], "client_id": row["client_id"],
                    "subject": row["subject"], "scopes": row["scopes"],
                    "resource": row["resource"], "expires_at": row["expires_at"],
                    "refresh_token": successor,
                }
        return outcome

    @staticmethod
    def _list_from_db(db: sqlite3.Connection, *, active_only: bool) -> list[dict[str, Any]]:
        query = """SELECT id,client_id,subject,scopes,resource,created_at,expires_at,revoked_at
                   FROM oauth_sessions"""
        params: tuple[int, ...] = ()
        if active_only:
            query += " WHERE revoked_at IS NULL AND expires_at > ?"
            params = (int(time.time()),)
        query += " ORDER BY created_at DESC,id"
        return [dict(row) for row in db.execute(query, params).fetchall()]

    @classmethod
    def read_sessions(cls, path: Path, *, active_only: bool = False) -> list[dict[str, Any]]:
        """Inspect an existing private database without schema setup or expiration pruning."""
        _prepare_path(path, create=False)
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5,
                             factory=_ClosingConnection) as db:
            db.row_factory = sqlite3.Row
            return cls._list_from_db(db, active_only=active_only)

    def list_sessions(self, *, active_only: bool = False) -> list[dict[str, Any]]:
        with self._connect() as db:
            return self._list_from_db(db, active_only=active_only)

    def revoke(self, session_id: str | None = None) -> int:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            args: tuple[int | str, ...]
            if session_id is None:
                query, args = ("UPDATE oauth_sessions SET revoked_at=? WHERE revoked_at IS NULL",
                               (int(time.time()),))
            else:
                query, args = (
                    "UPDATE oauth_sessions SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
                    (int(time.time()), session_id),
                )
            return db.execute(query, args).rowcount
