"""Durable RFC 7591 public-client registration for optional MCP legacy compatibility.

A registration is not authentication, operator consent or SSH authorization.
Opaque client IDs are deliberately distinct from HTTPS CIMD client identities.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .client_metadata import _parts, redirect_uri_matches
from .sqlite_support import _ClosingConnection, _prepare_path

MAX_REGISTRATIONS = 4096
MAX_REMOVAL_AUDIT = 4096
REMOVAL_AUDIT_SECONDS = 365 * 86400
RATE_WINDOW_SECONDS = 60
PER_IP_RATE = 12
GLOBAL_RATE = 120
DCR_CLIENT_ID_PATTERN = re.compile(r"dcr_[A-Za-z0-9_-]{32,64}\Z", re.ASCII)
_CLIENT_ID = DCR_CLIENT_ID_PATTERN  # Preserve existing registry-internal reference.


class RegistrationError(ValueError):
    def __init__(self, error: str, description: str, status: int = 400):
        super().__init__(description)
        self.error = error
        self.status = status


def _valid_redirect(value: Any, *, native: bool) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise RegistrationError("invalid_redirect_uri", "Invalid redirect URI")
    try:
        # Validate the original bytes: urlsplit strips leading C0 controls
        # and would otherwise accept a different URI than the one stored.
        parts = _parts(value)
    except ValueError as exc:
        raise RegistrationError("invalid_redirect_uri", "Invalid redirect URI") from exc
    if parts.scheme == "http" and not native:
        raise RegistrationError("invalid_redirect_uri", "HTTP redirect requires native loopback")
    if parts.scheme not in {"https", "http"}:
        raise RegistrationError("invalid_redirect_uri", "Unsupported redirect scheme")


def _validated_document(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise RegistrationError("invalid_client_metadata", "Registration must be a JSON object")
    if len(document) > 32:
        raise RegistrationError("invalid_client_metadata", "Too many client metadata fields")
    if document.get("token_endpoint_auth_method", "none") != "none":
        raise RegistrationError("invalid_client_metadata", "Only public clients are supported")
    if "application_type" in document and document["application_type"] not in ("web", "native"):
        raise RegistrationError("invalid_client_metadata", "Unsupported application_type")
    grants = document.get("grant_types", ["authorization_code", "refresh_token"])
    responses = document.get("response_types", ["code"])
    if (not isinstance(grants, list) or not grants
            or any(not isinstance(x, str) or not x for x in grants)
            or len(grants) != len(set(grants))
            or "authorization_code" not in grants
            or not isinstance(responses, list) or not responses
            or any(not isinstance(x, str) or not x for x in responses)
            or len(responses) != len(set(responses))
            or "code" not in responses):
        raise RegistrationError("invalid_client_metadata", "Only authorization-code/PKCE clients are supported")
    redirects = document.get("redirect_uris")
    if (not isinstance(redirects, list) or not 1 <= len(redirects) <= 16
            or len(set(map(str, redirects))) != len(redirects)):
        raise RegistrationError("invalid_redirect_uri", "One to sixteen unique redirect URIs required")
    application_type = document.get("application_type")
    # RFC 7591 clients need not send the OIDC application_type extension.
    # Permit inference only when it was omitted, and still validate every URI.
    if application_type is None:
        application_type = "native" if any(
            isinstance(uri, str) and uri.lower().startswith("http://")
            for uri in redirects
        ) else "web"
    for redirect in redirects:
        _valid_redirect(redirect, native=application_type == "native")
    client_name = document.get("client_name", "Unidentified MCP client")
    if (not isinstance(client_name, str) or not 1 <= len(client_name) <= 160
            or any(ord(c) < 32 for c in client_name)):
        raise RegistrationError("invalid_client_metadata", "Invalid client_name")
    try:
        client_name.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise RegistrationError("invalid_client_metadata", "Invalid client_name") from exc
    # No client-supplied client_id/secret can overwrite the issued registration.
    if any(key in document for key in ("client_id", "client_secret", "registration_access_token",
                                       "registration_client_uri")):
        raise RegistrationError("invalid_client_metadata", "Client credentials cannot be supplied")
    return {
        "client_name": client_name,
        "redirect_uris": redirects,
        "application_type": application_type,
        "grant_types": [grant for grant in ("authorization_code", "refresh_token")
                        if grant in grants],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }


def _redirect_matches(meta: dict[str, Any], redirect: str) -> bool:
    try:
        _valid_redirect(redirect, native=meta["application_type"] == "native")
    except RegistrationError:
        return False
    return any(redirect_uri_matches(saved, redirect) for saved in meta["redirect_uris"])


class DCRStore:
    def __init__(self, path: Path):
        _prepare_path(path)
        self.path = path
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS oauth_dcr_clients (
                    client_id TEXT PRIMARY KEY,
                    metadata TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    last_used_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS oauth_dcr_activity ON oauth_dcr_clients(last_used_at);
                CREATE TABLE IF NOT EXISTS oauth_dcr_rates (
                    identity TEXT PRIMARY KEY,
                    window_start INTEGER NOT NULL,
                    count INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS oauth_dcr_removals (
                    id INTEGER PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    removed_at INTEGER NOT NULL
                );
            """)
        self._mutation_lock = threading.RLock()
        self._names_state: tuple[str, Mapping[str, str]] = ("", MappingProxyType({}))
        self.reload_names()

    @property
    def names_snapshot(self) -> tuple[str, Mapping[str, str]]:
        """One immutable name map and restart-unique version, read together."""
        return self._names_state

    @property
    def approved_names(self) -> Mapping[str, str]:
        return self._names_state[1]

    @property
    def names_revision(self) -> str:
        return self._names_state[0]

    @staticmethod
    def _snapshot(db: sqlite3.Connection) -> Mapping[str, str]:
        """Read and validate the whole map in the *mutation transaction*."""
        rows = db.execute("SELECT client_id,metadata FROM oauth_dcr_clients").fetchall()
        names: dict[str, str] = {}
        for row in rows:
            label = json.loads(row["metadata"]).get("operator_name")
            if isinstance(label, str) and 1 <= len(label) <= 64 and label.isprintable():
                names[row["client_id"]] = label
        return MappingProxyType(names)

    def _publish_names(self, snapshot: Mapping[str, str]) -> None:
        # Random revision is also unique across service restarts, without a
        # persistent sequence or schema migration. Publish both as one object.
        self._names_state = (secrets.token_hex(16), snapshot)

    def reload_names(self) -> None:
        """Refresh after startup/external mutation; never publish a partial map."""
        with self._mutation_lock:
            with self._connect() as db:
                snapshot = self._snapshot(db)
            self._publish_names(snapshot)

    def approve_name(self, client_id: str, name: str) -> None:
        """Only the operator-authenticated OAuth consent handler may invoke this."""
        if (not _CLIENT_ID.fullmatch(client_id) or not isinstance(name, str)
                or name != name.strip() or not 1 <= len(name) <= 64
                or not name.isprintable() or name.casefold() == "unknown"):
            raise ValueError("Invalid approved agent name")
        with self._mutation_lock:
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT metadata FROM oauth_dcr_clients WHERE client_id=?",
                                 (client_id,)).fetchone()
                if row is None:
                    raise ValueError("Unknown DCR client")
                metadata = json.loads(row["metadata"])
                metadata["operator_name"] = name
                db.execute("UPDATE oauth_dcr_clients SET metadata=? WHERE client_id=?",
                           (json.dumps(metadata, ensure_ascii=False, separators=(",", ":")), client_id))
                snapshot = self._snapshot(db)
            self._publish_names(snapshot)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None, factory=_ClosingConnection)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA secure_delete=ON")
        return db

    def _prune(self, db: sqlite3.Connection, now: int) -> int:
        # Registered identities and their approved names persist until explicit revocation.
        db.execute("DELETE FROM oauth_dcr_rates WHERE window_start < ?", (now - 2 * RATE_WINDOW_SECONDS,))
        db.execute("DELETE FROM oauth_dcr_removals WHERE removed_at < ?",
                   (now - REMOVAL_AUDIT_SECONDS,))
        return 0

    def prune(self) -> int:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            return self._prune(db, int(time.time()))

    @staticmethod
    def _rate_check(db: sqlite3.Connection, identity: str, limit: int, now: int) -> None:
        row = db.execute("SELECT window_start,count FROM oauth_dcr_rates WHERE identity=?", (identity,)).fetchone()
        if row is None or row["window_start"] <= now - RATE_WINDOW_SECONDS:
            db.execute("""INSERT INTO oauth_dcr_rates(identity,window_start,count) VALUES (?,?,1)
                        ON CONFLICT(identity) DO UPDATE SET window_start=excluded.window_start,count=1""",
                       (identity, now))
        elif row["count"] >= limit:
            raise RegistrationError("invalid_client_metadata", "Registration rate limit exceeded", 429)
        else:
            db.execute("UPDATE oauth_dcr_rates SET count=count+1 WHERE identity=?", (identity,))

    def charge_attempt(self, remote_ip: str, *, signing_salt: str) -> None:
        """Count every HTTP registration attempt, even invalid content or JSON."""
        now = int(time.time())
        # Do not persist source IPs; only a keyed digest.
        identity = hashlib.sha256((signing_salt + remote_ip).encode()).hexdigest()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM oauth_dcr_rates WHERE window_start < ?",
                       (now - 2 * RATE_WINDOW_SECONDS,))
            self._rate_check(db, "global", GLOBAL_RATE, now)
            self._rate_check(db, "ip:" + identity, PER_IP_RATE, now)

    def register(self, document: Any) -> dict[str, Any]:
        now = int(time.time())
        metadata = _validated_document(document)
        with self._mutation_lock:
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                self._prune(db, now)
                count = db.execute("SELECT COUNT(*) FROM oauth_dcr_clients").fetchone()[0]
                if count >= MAX_REGISTRATIONS:
                    raise RegistrationError("invalid_client_metadata", "Registration capacity exceeded", 429)
                for _ in range(3):
                    client_id = "dcr_" + secrets.token_urlsafe(32)
                    try:
                        db.execute("""INSERT INTO oauth_dcr_clients(client_id,metadata,issued_at,last_used_at)
                                      VALUES (?,?,?,?)""",
                                   (client_id, json.dumps(metadata, separators=(",", ":")), now, now))
                        break
                    except sqlite3.IntegrityError:
                        continue
                else:
                    raise RuntimeError("Unable to allocate unique client ID")
                snapshot = self._snapshot(db)
            self._publish_names(snapshot)
        return {**metadata, "client_id": client_id, "client_id_issued_at": now,
                "client_id_expires_at": 0}

    def get(self, client_id: str, redirect: str | None = None) -> dict[str, Any] | None:
        if not _CLIENT_ID.fullmatch(client_id):
            return None
        with self._connect() as db:
            row = db.execute("SELECT metadata FROM oauth_dcr_clients WHERE client_id=?",
                             (client_id,)).fetchone()
        if row is None:
            return None
        metadata: dict[str, Any] = json.loads(row[0])
        if redirect is not None and not _redirect_matches(metadata, redirect):
            return None
        return {**metadata, "client_id": client_id}

    def list_clients(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT client_id,metadata,issued_at,last_used_at FROM oauth_dcr_clients ORDER BY issued_at"
            ).fetchall()
        return [
            {"client_id": row["client_id"], "client_name": json.loads(row["metadata"])["client_name"],
             "issued_at": row["issued_at"], "last_used_at": row["last_used_at"]}
            for row in rows
        ]

    def revoke(self, client_id: str) -> int:
        """Explicit cancellation; durable session revocation and complete snapshot reload."""
        with self._mutation_lock:
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                now = int(time.time())
                db.execute("UPDATE oauth_sessions SET revoked_at=? WHERE client_id=? AND revoked_at IS NULL",
                           (now, client_id))
                removed = db.execute("DELETE FROM oauth_dcr_clients WHERE client_id=?", (client_id,)).rowcount
                if removed:
                    db.execute("INSERT INTO oauth_dcr_removals(client_id,removed_at) VALUES (?,?)",
                               (client_id, now))
                    db.execute("DELETE FROM oauth_dcr_removals WHERE removed_at < ?",
                               (now - REMOVAL_AUDIT_SECONDS,))
                    db.execute("""DELETE FROM oauth_dcr_removals WHERE id NOT IN
                                  (SELECT id FROM oauth_dcr_removals ORDER BY id DESC LIMIT ?)""",
                               (MAX_REMOVAL_AUDIT,))
                snapshot = self._snapshot(db)
            self._publish_names(snapshot)
        return removed
