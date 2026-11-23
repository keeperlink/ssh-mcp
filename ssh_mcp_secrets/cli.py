"""Offline SKY-347 sealed credential staging; never connects to SSH or a service.

The operator supplies credentials through a real terminal. Stage, verify and
activate are independent steps; this program does not deploy, change host sudo,
revoke sessions, update metrics consumers or select a rollback image.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import Any, Iterator

from app.runtime_files import managed_secrets_fingerprint
from app.sealed_credentials import (
    create_token_verifier, create_verifier, from_legacy,
    rotate_console, rotate_host_sudo, validate_v2_secrets, verify_password,
    verify_token,
)

_OPERATIONS = ("migrate", "oauth", "console", "sudo", "metrics")
_STAGE_PREFIX = ".ssh-mcp-stage-"
_ALIAS = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_USERNAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")


class RotationError(ValueError):
    """Fail closed, without surfacing a protected credential value."""


class ActivationUncertain(RuntimeError):
    """The complete revision might already be active; reconcile before retry."""


def _binding(deployment: str, issuer: str) -> None:
    if (deployment not in ("lab", "production") or type(issuer) is not str
            or not 8 <= len(issuer) <= 2048
            or not issuer.startswith("https://") and not (
                deployment == "lab" and issuer == "http://localhost"
            )):
        raise RotationError("Invalid or non-HTTPS deployment binding")


def _private_dir(folder: Path) -> None:
    if not folder.is_absolute() or folder.is_symlink():
        raise RotationError("A private absolute directory is required")
    info = folder.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077):
        raise RotationError("Credential directory must be owned by operator and mode 0700")


def _read_file(path: Path, *, private: bool, maximum: int = 65536) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size < 1 or info.st_size > maximum
                or info.st_mode & (0o077 if private else 0o022)
                or (private and info.st_uid != os.geteuid())):
            raise RotationError("Untrusted file owner, permissions, size or links")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        if len(data) != info.st_size:
            raise RotationError("Source changed while reading")
        return data
    finally:
        os.close(fd)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise RotationError("Duplicate JSON member")
        obj[key] = value
    return obj


def _decode(data: bytes) -> dict[str, Any]:
    value = json.loads(data, object_pairs_hook=_unique)
    if type(value) is not dict:
        raise RotationError("Expected JSON object")
    return value


def _source(path: Path) -> tuple[dict[str, Any], str]:
    _private_dir(path.parent)
    data = _read_file(path, private=True)
    value = _decode(data)
    if value.get("version") == 2:
        validate_v2_secrets(value)
    elif value.get("version") != 1:
        raise RotationError("Unsupported managed credential revision")
    return value, hashlib.sha256(data).hexdigest()


def _hosts(path: Path) -> dict[str, str]:
    # Caller independently verifies the inventory's signed provenance.
    data = _decode(_read_file(path, private=False, maximum=1048576))
    hosts = data.get("hosts")
    if data.get("version") != 1 or type(hosts) is not list or not 1 <= len(hosts) <= 200:
        raise RotationError("Invalid approved host inventory")
    result: dict[str, str] = {}
    for host in hosts:
        if type(host) is not dict:
            raise RotationError("Invalid approved host")
        alias, username = host.get("alias"), host.get("username")
        if (type(alias) is not str or _ALIAS.fullmatch(alias) is None
                or type(username) is not str or _USERNAME.fullmatch(username) is None
                or alias in result):
            raise RotationError("Duplicate or invalid signed host identity")
        result[alias] = username
    return result


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def _sync(folder: Path) -> None:
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def _locked(source: Path) -> Iterator[None]:
    _private_dir(source.parent)
    lock = source.parent / ".ssh-mcp-secrets.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise RotationError("Untrusted credential operation lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def _prompt(label: str, *, confirm: bool = False) -> str:
    value = getpass.getpass(label + ": ")
    if confirm and value != getpass.getpass("Confirm " + label + ": "):
        raise RotationError("Credential confirmation did not match")
    return value


def _select(value: dict[str, Any], *, operation: str, host: str | None,
            hosts: dict[str, str]) -> None:
    if operation not in _OPERATIONS or ((operation == "sudo") != (host is not None)):
        raise RotationError("Invalid rotation operation or host selection")
    if operation == "migrate":
        if value.get("version") != 1:
            raise RotationError("Migration requires a legacy source")
        if set(value.get("sudo_passwords", {})) - set(hosts):
            raise RotationError("Source contains unsigned sudo host")
    else:
        validate_v2_secrets(value)
        if set(value["sealed_sudo"]) - set(hosts):
            raise RotationError("Source contains unsigned sudo host")
        if operation == "sudo" and host not in value["sealed_sudo"]:
            raise RotationError("Target host has no sealed sudo entry")


def _transform(value: dict[str, Any], *, operation: str, host: str | None,
               hosts: dict[str, str], deployment: str, issuer: str) -> dict[str, Any]:
    if operation == "migrate":
        old = _prompt("Existing Console password")
        return from_legacy(value, console_password=old, deployment=deployment,
                           issuer=issuer, hosts=hosts)
    if operation == "console":
        old = _prompt("Existing Console password")
        new = _prompt("New Console password", confirm=True)
        return rotate_console(value, old_password=old, new_password=new,
                              deployment=deployment, issuer=issuer, hosts=hosts)
    if operation == "sudo":
        assert host is not None
        old = _prompt("Existing Console password")
        new = _prompt("New sudo credential for selected host", confirm=True)
        if (new == old or new == value["oauth_signing_key"]
                or verify_password(new, value["oauth_login_verifier"], "oauth-login")
                or verify_token(new, value["metrics_verifier"])):
            raise RotationError("New host credential is reused")
        return rotate_host_sudo(value, console_password=old, new_sudo_password=new,
                                deployment=deployment, issuer=issuer,
                                alias=host, username=hosts[host])
    if operation == "oauth":
        old = _prompt("Existing OAuth password")
        if not verify_password(old, value["oauth_login_verifier"], "oauth-login"):
            raise RotationError("Existing OAuth password rejected")
        new = _prompt("New OAuth password", confirm=True)
        if (old == new or new == value["oauth_signing_key"]
                or verify_password(new, value["viewer_verifier"], "console-login")
                or verify_token(new, value["metrics_verifier"])):
            raise RotationError("New OAuth credential is reused")
        result = dict(value)
        result["oauth_login_verifier"] = create_verifier(new, "oauth-login")
        return result
    if operation == "metrics":
        old = _prompt("Existing metrics bearer token")
        if not verify_token(old, value["metrics_verifier"]):
            raise RotationError("Existing metrics token rejected")
        new = _prompt("New metrics bearer token", confirm=True)
        if (new == old or new == value["oauth_signing_key"]
                or verify_password(new, value["viewer_verifier"], "console-login")
                or verify_password(new, value["oauth_login_verifier"], "oauth-login")):
            raise RotationError("New metrics credential is reused")
        result = dict(value)
        result["metrics_verifier"] = create_token_verifier(new)
        return result
    raise RotationError("Unsupported operation")


def plan(*, source: Path, inventory: Path, deployment: str, issuer: str,
         operation: str, host: str | None) -> str:
    value, sha = _source(source)
    hosts = _hosts(inventory)
    _select(value, operation=operation, host=host, hosts=hosts)
    _binding(deployment, issuer)
    return f"PLAN=PASS operation={operation} host={host or '-'} aliases={len(hosts)} source_sha256={sha}"


def stage(*, source: Path, inventory: Path, deployment: str, issuer: str,
          operation: str, host: str | None) -> Path:
    with _locked(source):
        value, original = _source(source)
        hosts = _hosts(inventory)
        _select(value, operation=operation, host=host, hosts=hosts)
        _binding(deployment, issuer)
        changed = _transform(value, operation=operation, host=host, hosts=hosts,
                             deployment=deployment, issuer=issuer)
        validate_v2_secrets(changed)
        if _source(source)[1] != original:
            raise RotationError("Active revision changed during preparation")
        raw = (json.dumps(changed, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(raw) > 65536:
            raise RotationError("Prepared sealed revision exceeds size bound")
        name = _STAGE_PREFIX + secrets.token_hex(12) + ".json"
        staged = source.parent / name
        manifest = staged.with_name(name + ".plan")
        metadata = {
            "format": 1, "source": source.name, "source_sha256": original,
            "stage_sha256": _digest(raw), "operation": operation, "host": host,
            "sealed_digest": managed_secrets_fingerprint(changed),
        }
        _write_new(staged, raw)
        try:
            _write_new(manifest, (json.dumps(metadata, sort_keys=True) + "\n").encode())
            _sync(source.parent)
        except BaseException:
            # An interrupted/failed stage can never activate without its valid manifest.
            manifest.unlink(missing_ok=True)
            staged.unlink(missing_ok=True)
            raise
        return staged


def _prepared(source: Path, staged: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    _private_dir(source.parent)
    if (staged.parent != source.parent or not staged.name.startswith(_STAGE_PREFIX)
            or not re.fullmatch(r"\.ssh-mcp-stage-[a-f0-9]{24}\.json", staged.name)):
        raise RotationError("Stage must be a generated sibling of active source")
    manifest = staged.with_name(staged.name + ".plan")
    info = _decode(_read_file(manifest, private=True, maximum=4096))
    if (set(info) != {"format", "source", "source_sha256", "stage_sha256",
                      "operation", "host", "sealed_digest"}
            or info["format"] != 1 or info["source"] != source.name
            or info["operation"] not in _OPERATIONS
            or type(info["source_sha256"]) is not str or _SHA.fullmatch(info["source_sha256"]) is None
            or type(info["stage_sha256"]) is not str or _SHA.fullmatch(info["stage_sha256"]) is None
            or type(info["sealed_digest"]) is not str or _SHA.fullmatch(info["sealed_digest"]) is None):
        raise RotationError("Invalid stage metadata")
    raw = _read_file(staged, private=True)
    data = _decode(raw)
    validate_v2_secrets(data)
    if _digest(raw) != info["stage_sha256"] or managed_secrets_fingerprint(data) != info["sealed_digest"]:
        raise RotationError("Staged revision integrity failed")
    if _source(source)[1] != info["source_sha256"]:
        raise RotationError("Active source changed: restage required")
    return info, data


def activate(*, source: Path, staged: Path, stopped: bool,
             recovery: bool, consumers: bool, migration_ready: bool) -> str:
    if not all((stopped, recovery, consumers)):
        raise RotationError("Service stop, independent recovery and consumer handoff confirmations required")
    with _locked(source):
        info, _ = _prepared(source, staged)
        if info["operation"] == "migrate" and not migration_ready:
            raise RotationError("Migration requires independently verified database cutover readiness")
        # All persistent writes before this line are staged and nonactive.
        os.replace(staged, source)
        try:
            _sync(source.parent)
            staged.with_name(staged.name + ".plan").unlink()
            _sync(source.parent)
        except OSError:
            raise ActivationUncertain("Revision may already be active; inspect source digest") from None
        return str(info["stage_sha256"])


def discard(*, source: Path, staged: Path) -> None:
    with _locked(source):
        _prepared(source, staged)
        staged.unlink()
        staged.with_name(staged.name + ".plan").unlink()
        _sync(source.parent)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="command", required=True)
    for cmd in ("plan", "stage"):
        sub = actions.add_parser(cmd)
        sub.add_argument("--source", type=Path, required=True)
        sub.add_argument("--inventory", type=Path, required=True)
        sub.add_argument("--deployment", required=True, choices=("lab", "production"))
        sub.add_argument("--issuer", required=True)
        sub.add_argument("--operation", required=True, choices=_OPERATIONS)
        sub.add_argument("--host")
    for cmd in ("verify", "activate", "discard"):
        sub = actions.add_parser(cmd)
        sub.add_argument("--source", type=Path, required=True)
        sub.add_argument("--staged", type=Path, required=True)
        if cmd == "activate":
            sub.add_argument("--confirm-stopped", action="store_true")
            sub.add_argument("--confirm-recovery", action="store_true")
            sub.add_argument("--confirm-consumers-ready", action="store_true")
            sub.add_argument("--confirm-db-ready", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            print(plan(source=args.source, inventory=args.inventory,
                       deployment=args.deployment, issuer=args.issuer,
                       operation=args.operation, host=args.host))
        elif args.command == "stage":
            if not (sys.stdin.isatty() and sys.stderr.isatty()):
                raise RotationError("Trusted interactive terminal required for credential entry")
            result = stage(source=args.source, inventory=args.inventory,
                           deployment=args.deployment, issuer=args.issuer,
                           operation=args.operation, host=args.host)
            print(f"STAGE=PASS path={result}")
        elif args.command == "verify":
            info, _ = _prepared(args.source, args.staged)
            print(f"VERIFY=PASS operation={info['operation']} host={info['host'] or '-'} "
                  f"expected_source={info['source_sha256']} staged_sha256={info['stage_sha256']}")
        elif args.command == "activate":
            digest = activate(source=args.source, staged=args.staged,
                              stopped=args.confirm_stopped, recovery=args.confirm_recovery,
                              consumers=args.confirm_consumers_ready,
                              migration_ready=args.confirm_db_ready)
            print(f"ACTIVATE=PASS sha256={digest}; redeploy and independently verify consumers")
        else:
            discard(source=args.source, staged=args.staged)
            print("DISCARD=PASS")
        return 0
    except ActivationUncertain:
        print("Activation outcome uncertain: compare source revision before any retry",
              file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, BlockingIOError):
        print("Sealed revision operation rejected; inspect permissions, source and procedure",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
