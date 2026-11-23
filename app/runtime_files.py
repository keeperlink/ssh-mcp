"""Normal application startup: signed non-secret files and one protected secret.

All config assets are independently read-only, tracked in the signed release
closure, and never written to a host volume. Only the SSH private key and
normalized inventory are written to service-owned tmpfs.
"""
from __future__ import annotations

import ipaddress
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any
from urllib.parse import urlsplit

from .control import LEVELS
from .client_registry import parse_clients, offline_client
from .readiness import ReadinessSettings
from .sealed_credentials import validate_v2_secrets

CONFIG = Path("/etc/ssh-mcp/service.json")
INVENTORY = Path("/etc/ssh-mcp/inventory.json")
KNOWN_HOSTS = Path("/etc/ssh-mcp/known_hosts")
SECRETS = Path("/run/secrets/ssh-mcp-secrets")
DEST = Path("/run/ssh-mcp")
SECRETS_KEYS = {"version", "oauth_login_key", "oauth_signing_key",
                "viewer_password", "metrics_token", "ssh_private_key"}
OPTIONAL_SECRETS_KEYS = {"sudo_passwords"}
ALIAS = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
SECTIONS = {
    "http": {"allowed_origins", "request_timeout_seconds"},
    "oauth": {"issuer", "operator_subject", "access_token_ttl_seconds", "session_ttl_seconds",
              "authorization_code_ttl_seconds",
              "validate_client_metadata", "client_metadata_cache_seconds",
              "login_max_failures", "login_window_seconds"},
    "ssh": {"enabled", "default_timeout_seconds", "max_timeout_seconds",
            "max_output_bytes", "max_argument_bytes", "max_arguments",
            "max_concurrent", "max_hosts"},
    "jobs": {"enabled", "database", "retention_months", "max_active"},
    "history": {"enabled", "retention_months"},
    "metrics": {"enabled"},
    "viewer": {"enabled", "idle_timeout_seconds", "absolute_timeout_seconds"},
}
OAUTH_OPTIONAL = {"dcr_enabled"}
VIEWER_OPTIONAL = {"story_id_max_chars", "story_id_truncate_from"}
HARD = {"max_timeout_seconds": 36000, "max_output_bytes": 1048576,
        "max_argument_bytes": 65536, "max_arguments": 64,
        "max_concurrent": 32, "max_hosts": 200, "max_active": 256}


# Signed settings choose an explicit OAuth origin and client. They are not
# limited to this repository owner's domains; all supported URLs must be
# HTTPS and free from embedded credentials, fragments and ambiguous syntax.
_HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")


def _https_url(value: Any, *, origin_only: bool = False) -> bool:
    if (type(value) is not str or not 1 <= len(value) <= 2048 or
            not value.startswith("https://") or
            any(not 33 <= ord(char) <= 126 or char == "\\" for char in value)):
        return False
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        return False
    if (parts.scheme != "https" or not hostname or parts.username is not None
            or parts.password is not None or parts.fragment or
            (port is not None and not 1 <= port <= 65535)):
        return False
    # This is a DNS-hostname policy for signed public HTTPS endpoints:
    # no userinfo, wildcards, raw IP literals or malformed host labels.
    if (len(hostname) > 253 or "." not in hostname or
            not all(_HOST_LABEL.fullmatch(label) for label in hostname.split("."))):
        return False
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        return False
    if "#" in value or (origin_only and (parts.path or "?" in value)):
        return False
    return True


def _https_allowlist(value: Any, *, origin_only: bool) -> bool:
    # Managed signed URL lists are serialized to comma-separated environment
    # variables before config._csv_env parses them. Reject delimiter bytes
    # rather than silently authorizing extra callback URLs after splitting.
    return (type(value) is list and 1 <= len(value) <= 16
            and len(set(item for item in value if type(item) is str)) == len(value)
            and all(type(item) is str and "," not in item
                    and _https_url(item, origin_only=origin_only) for item in value))


def _read(path: Path, limit: int) -> str:
    if (path.is_symlink() or not path.is_file() or
            path.stat().st_mode & 0o022 or not 0 < path.stat().st_size <= limit):
        raise ValueError("Invalid mounted configuration file")
    return path.read_text("utf-8")


def _unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate member in managed JSON")
        result[key] = value
    return result


def managed_secrets_fingerprint(secrets: dict[str, Any]) -> str:
    """Fingerprint the validated complete revision without exporting secrets."""
    canonical = json.dumps(
        secrets, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _json(path: Path, limit: int, *, reject_duplicates: bool = False) -> dict[str, Any]:
    try:
        value = json.loads(_read(path, limit),
                           object_pairs_hook=_unique_members if reject_duplicates else None)
    except (ValueError, OSError, UnicodeError) as exc:
        raise ValueError("Invalid mounted JSON configuration") from exc
    if type(value) is not dict:
        raise ValueError("Invalid mounted JSON schema")
    return value


def _positive(value: Any, maximum: int) -> bool:
    return type(value) is int and 1 <= value <= maximum


def _valid_settings(settings: dict[str, Any]) -> None:
    required = {"version", "environment", "clients", *SECTIONS}
    if (not required <= set(settings) <= required | {"logging", "readiness", "transfer"}
            or settings["version"] != 1 or
            any(type(settings[section]) is not dict or
                not (keys <= set(settings[section]) <= (keys | VIEWER_OPTIONAL)
                     if section == "viewer" else
                     keys <= set(settings[section]) <= (keys | OAUTH_OPTIONAL)
                     if section == "oauth" else set(settings[section]) == keys)
                for section, keys in SECTIONS.items())):
        raise ValueError("Invalid service setting schema")
    transfer = settings.get("transfer", {"max_bytes": 1073741824, "chunk_bytes": 262144})
    if (type(transfer) is not dict or set(transfer) != {"max_bytes", "chunk_bytes"}
            or type(transfer["max_bytes"]) is not int
            or type(transfer["chunk_bytes"]) is not int
            or not 1 <= transfer["max_bytes"] <= 4 * 1024**3
            or not 4096 <= transfer["chunk_bytes"] <= 4194304
            or transfer["chunk_bytes"] > transfer["max_bytes"]):
        raise ValueError("Invalid signed SSH transfer limits")
    ReadinessSettings.from_mapping(settings.get("readiness", {}))
    clients = parse_clients(settings["clients"])
    for definition in clients.values():
        for identity in definition["identities"]:
            # Retain DNS-only, no-IP, no-single-label and no-backslash
            # managed HTTPS policy from the previous signed settings.
            if identity.startswith("https://") and not _https_url(identity):
                raise ValueError("Invalid signed OAuth client identity URL")
        for redirect in definition.get("offline_redirect_uris", []):
            if not _https_url(redirect) or "," in redirect:
                raise ValueError("Invalid signed OAuth offline redirect URL")
    if offline_client(clients) is None:
        raise ValueError("Managed service requires an explicit offline fallback client")
    logging_settings = settings.get("logging", {"level": "INFO"})
    if (type(logging_settings) is not dict or set(logging_settings) != {"level"}
            or logging_settings["level"] not in LEVELS):
        raise ValueError("Invalid logging settings")
    if type(settings["environment"]) is not str or settings["environment"] not in {"lab", "production"}:
        raise ValueError("Invalid service environment")
    http, oauth, ssh = settings["http"], settings["oauth"], settings["ssh"]
    jobs, history = settings["jobs"], settings["history"]
    metrics, viewer = settings["metrics"], settings["viewer"]
    issuer = oauth["issuer"]
    if not _https_url(issuer, origin_only=True):
        raise ValueError("Invalid HTTPS OAuth issuer")
    if (oauth["operator_subject"] != "ssh-mcp-operator" or
            not _positive(oauth["authorization_code_ttl_seconds"], 600) or
            type(oauth["access_token_ttl_seconds"]) is not int or
            oauth["access_token_ttl_seconds"] != 900 or
            type(oauth["session_ttl_seconds"]) is not int or
            oauth["session_ttl_seconds"] not in
            (3600, 28800, 86400, 604800, 2592000) or
            not _positive(oauth["client_metadata_cache_seconds"], 86400) or
            not _positive(oauth["login_max_failures"], 100) or
            not _positive(oauth["login_window_seconds"], 3600)):
        raise ValueError("Invalid OAuth settings")
    if type(oauth.get("dcr_enabled", True)) is not bool:
        raise ValueError("Invalid OAuth DCR toggle")
    if (type(oauth["validate_client_metadata"]) is not bool or
            oauth["validate_client_metadata"] is not True):
        raise ValueError("Invalid OAuth redirect allowlist")
    if (not _https_allowlist(http["allowed_origins"], origin_only=True) or
            type(http["request_timeout_seconds"]) not in (int, float) or
            not 1 <= http["request_timeout_seconds"] <= 60):
        raise ValueError("Invalid HTTP settings")
    if any(type(section["enabled"]) is not bool
           for section in (ssh, jobs, history, metrics, viewer)):
        raise ValueError("Invalid feature flags")
    if (not ssh["enabled"] or not jobs["enabled"] or not history["enabled"] or
            not metrics["enabled"] or not viewer["enabled"]):
        raise ValueError("Managed service requires audit, SSH and metrics")
    for field, cap in HARD.items():
        section = jobs if field == "max_active" else ssh
        if not _positive(section[field], cap):
            raise ValueError("Configured operational bound exceeds safety ceiling")
    if (not _positive(ssh["default_timeout_seconds"], ssh["max_timeout_seconds"]) or
            not _positive(jobs["retention_months"], 12) or
            not _positive(history["retention_months"], 12) or
            history["retention_months"] != jobs["retention_months"] or
            not isinstance(jobs["database"], str) or
            jobs["database"] != "/var/lib/ssh-mcp/jobs.sqlite" or
            not _positive(viewer["idle_timeout_seconds"], 86400) or
            not _positive(viewer["absolute_timeout_seconds"], 604800) or
            viewer["absolute_timeout_seconds"] <= viewer["idle_timeout_seconds"] or
            not _positive(viewer.get("story_id_max_chars", 16), 80) or
            viewer.get("story_id_truncate_from", "end") not in ("start", "end")):
        raise ValueError("Invalid execution or persistence settings")


def _secret(value: Any, length: int) -> bool:
    return type(value) is str and length <= len(value) <= 8192 and "\x00" not in value


def _write_private(path: Path, content: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)


def prepare(config_source: Path = CONFIG, secrets_source: Path = SECRETS,
            inventory_source: Path = INVENTORY, known_source: Path = KNOWN_HOSTS,
            target: Path | None = None) -> dict[str, str]:
    """Validate all inputs before creating private tmpfs SSH identity."""
    if target is None:
        target = DEST
    os.umask(0o077)
    cfg = _json(config_source, 65536)
    _valid_settings(cfg)
    secrets = _json(secrets_source, 65536, reject_duplicates=True)
    sealed = type(secrets.get("version")) is int and secrets["version"] == 2
    if sealed:
        validate_v2_secrets(secrets)
        auth_env = {
            "MCP_MANAGED_SECRETS_VERSION": "2",
            "MCP_MANAGED_SECRETS_SOURCE": str(secrets_source.absolute()),
            "MCP_MANAGED_SECRETS_DIGEST": managed_secrets_fingerprint(secrets),
            "MCP_LOGIN_VERIFIER": json.dumps(secrets["oauth_login_verifier"], sort_keys=True),
            "HISTORY_VIEWER_VERIFIER": json.dumps(secrets["viewer_verifier"], sort_keys=True),
            "HISTORY_VIEWER_GENERATION": secrets["viewer_generation"],
            "MCP_METRICS_VERIFIER": json.dumps(secrets["metrics_verifier"], sort_keys=True),
        }
    else:
        # Legacy managed layout remains usable only during the staged
        # development migration; strict v2-only cutover is a later stage.
        if (set(secrets) not in (SECRETS_KEYS, SECRETS_KEYS | OPTIONAL_SECRETS_KEYS)
                or secrets["version"] != 1):
            raise ValueError("Invalid managed secrets schema")
        for name, minimum in (("oauth_login_key", 32), ("oauth_signing_key", 32),
                              ("viewer_password", 16), ("metrics_token", 32)):
            if not _secret(secrets[name], minimum):
                raise ValueError("Invalid private credential")
        if len({secrets[k] for k in
                ("oauth_login_key", "oauth_signing_key", "viewer_password", "metrics_token")}) != 4:
            raise ValueError("Independent credentials must be distinct")
        auth_env = {
            "MCP_LOGIN_KEY": secrets["oauth_login_key"],
            "HISTORY_VIEWER_PASSWORD": secrets["viewer_password"],
            "MCP_METRICS_TOKEN": secrets["metrics_token"],
        }
    identity = secrets["ssh_private_key"]
    if (type(identity) is not str or len(identity) > 100000 or
            not identity.startswith("-----BEGIN OPENSSH PRIVATE KEY-----") or
            not identity.rstrip().endswith("-----END OPENSSH PRIVATE KEY-----") or
            "\x00" in identity):
        raise ValueError("Invalid SSH identity")
    inventory = _json(inventory_source, 262144)
    if (set(inventory) != {"version", "hosts"} or inventory["version"] != 1 or
            type(inventory["hosts"]) is not list or
            not 1 <= len(inventory["hosts"]) <= cfg["ssh"]["max_hosts"]):
        raise ValueError("Invalid signed SSH inventory")
    known = _read(known_source, 262144)
    if not known.strip() or all(line.lstrip().startswith("#") or not line.strip()
                                for line in known.splitlines()):
        raise ValueError("Missing approved SSH host-key pin")
    aliases = []
    for host in inventory["hosts"]:
        if (type(host) is not dict or
                set(host) not in (
                    {"alias", "address", "port", "username", "principals",
                     "environment", "access", "max_parallel"},
                    {"alias", "address", "port", "username", "principals",
                     "environment", "access", "max_parallel", "privileged_access"},
                ) or
                host["access"] not in ("restricted", "always-granted") or
                host.get("privileged_access", "none") not in
                ("none", "restricted", "always-granted") or
                type(host["alias"]) is not str or not ALIAS.fullmatch(host["alias"])
                or host["max_parallel"] > cfg["ssh"]["max_concurrent"]):
            raise ValueError("Invalid signed SSH host entry")
        aliases.append(host["alias"])
    if len(set(aliases)) != len(aliases):
        raise ValueError("Duplicate SSH host alias")
    sudo_passwords = {} if sealed else secrets.get("sudo_passwords", {})
    if (type(sudo_passwords) is not dict or
            any(type(alias) is not str or not ALIAS.fullmatch(alias)
                for alias in sudo_passwords)):
        raise ValueError("Invalid per-host sudo credential mapping")
    # Stale aliases may remain after a signed host is removed. They confer no
    # authorization and must not break ordinary SSH for remaining hosts.
    if (target.is_symlink() or not target.is_dir() or
            target.stat().st_uid != os.geteuid() or
            stat.S_IMODE(target.stat().st_mode) != 0o700 or any(target.iterdir())):
        raise ValueError("Unsafe private runtime directory")
    key_path = target / "identity"
    for host in inventory["hosts"]:
        host.setdefault("privileged_access", "none")
        host["identity_file"] = str(key_path)
        host["known_hosts_file"] = str(known_source)
    _write_private(key_path, identity)
    _write_private(target / "inventory.json", json.dumps(inventory, sort_keys=True) + "\n")
    http, oauth, ssh, jobs = (cfg[part] for part in ("http", "oauth", "ssh", "jobs"))
    offline = offline_client(parse_clients(cfg["clients"]))
    if offline is None:
        raise ValueError("No configured offline OAuth client")
    issuer = oauth["issuer"]
    return {
        **ReadinessSettings.from_mapping(cfg.get("readiness", {})).environment(),
        "MCP_ENVIRONMENT": cfg["environment"],
        "MCP_LOG_LEVEL": cfg.get("logging", {"level": "INFO"})["level"],
        "MCP_ISSUER": issuer, "MCP_RESOURCE": issuer + "/mcp",
        "MCP_ALLOWED_HOSTS": (urlsplit(issuer).hostname + "," +
            urlsplit(issuer).hostname + f":{urlsplit(issuer).port or 443},"
            "localhost,localhost:*,127.0.0.1,127.0.0.1:*"),
        "MCP_ALLOWED_ORIGINS": ",".join(http["allowed_origins"]),
        "REQUEST_TIMEOUT": str(http["request_timeout_seconds"]),
        "MCP_TOKEN_SIGNING_SECRET": secrets["oauth_signing_key"],
        "MCP_OPERATOR_SUBJECT": oauth["operator_subject"],
        "MCP_ACCESS_TOKEN_TTL": str(oauth["access_token_ttl_seconds"]),
        "MCP_SESSION_TTL_DEFAULT": str(oauth["session_ttl_seconds"]),
        "MCP_AUTH_CODE_TTL": str(oauth["authorization_code_ttl_seconds"]),
        "MCP_CIMD_CLIENT_ID": offline[0],
        "MCP_CLIENTS": json.dumps(cfg["clients"], sort_keys=True),
        "MCP_CIMD_VALIDATE_REMOTE": "true" if oauth["validate_client_metadata"] else "false",
        "MCP_CIMD_CACHE_TTL": str(oauth["client_metadata_cache_seconds"]),
        "MCP_DCR_ENABLED": "true" if oauth.get("dcr_enabled", True) else "false",
        "MCP_ALLOWED_REDIRECT_URIS": ",".join(offline[1]),
        "MCP_LOGIN_MAX_FAILURES": str(oauth["login_max_failures"]),
        "MCP_LOGIN_WINDOW_SECONDS": str(oauth["login_window_seconds"]),
        "MCP_SSH_TOOLS_ENABLED": "true", "SSH_EXECUTOR_ENABLED": "true",
        "SSH_JOBS_ENABLED": "true", "SSH_JOBS_DB": jobs["database"],
        "SSH_JOBS_RETENTION_MONTHS": str(jobs["retention_months"]),
        "SSH_INVENTORY_FILE": str(target / "inventory.json"),
        "SSH_APPROVED_ALIASES": ",".join(aliases),
        "SSH_OUTPUT_LIMIT_BYTES": str(ssh["max_output_bytes"]),
        "SSH_MAX_CONCURRENT": str(ssh["max_concurrent"]),
        "SSH_TRANSFER_MAX_BYTES": str(cfg.get("transfer", {}).get("max_bytes", 1073741824)),
        "SSH_TRANSFER_CHUNK_BYTES": str(cfg.get("transfer", {}).get("chunk_bytes", 262144)),
        "SSH_MAX_TIMEOUT_SECONDS": str(ssh["max_timeout_seconds"]),
        "SSH_DEFAULT_TIMEOUT_SECONDS": str(ssh["default_timeout_seconds"]),
        "SSH_MAX_ARGUMENT_BYTES": str(ssh["max_argument_bytes"]),
        "SSH_MAX_ARGUMENTS": str(ssh["max_arguments"]),
        "SSH_MAX_ACTIVE_JOBS": str(jobs["max_active"]),
        "HISTORY_VIEWER_ENABLED": "true",
        "HISTORY_IDLE_TIMEOUT_SECONDS": str(cfg["viewer"]["idle_timeout_seconds"]),
        "HISTORY_ABSOLUTE_TIMEOUT_SECONDS": str(cfg["viewer"]["absolute_timeout_seconds"]),
        "HISTORY_STORY_ID_MAX_CHARS": str(cfg["viewer"].get("story_id_max_chars", 16)),
        "HISTORY_STORY_ID_TRUNCATE_FROM": cfg["viewer"].get("story_id_truncate_from", "end"),
        "MCP_METRICS_ENABLED": "true",
        **auth_env,
    }
