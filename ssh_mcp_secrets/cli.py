"""Atomic offline sealed credential changes through a trusted terminal.

Never deploys, changes host passwords, or restarts the running service.
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
from typing import Any, Callable, Iterator

from app.runtime_files import _https_url
from app.sealed_credentials import (
    add_host_sudo, create_token_verifier, create_verifier,
    rotate_console, rotate_host_sudo, validate_v2_secrets, verify_password,
    verify_token,
)

_OPERATIONS = ("oauth", "console", "sudo", "add-sudo", "metrics")
_TEMP_PREFIX = ".ssh-mcp-commit-"
_ALIAS = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_USERNAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")


class RotationError(ValueError):
    """Fail closed, without surfacing a protected credential value."""


class CommitUncertain(RuntimeError):
    """The complete revision might already be committed; reconcile before retry."""

    def __init__(self, message: str, *, expected_digest: str | None = None) -> None:
        super().__init__(message)
        self.expected_digest = expected_digest


def _binding(deployment: str, issuer: str) -> None:
    if (deployment not in ("lab", "production") or type(issuer) is not str
            or not (_https_url(issuer, origin_only=True)
                    or (deployment == "lab" and issuer == "http://localhost"))):
        raise RotationError("Invalid or non-HTTPS deployment binding")


def _private_dir(folder: Path) -> None:
    if not folder.is_absolute() or folder.is_symlink():
        raise RotationError("A private absolute directory is required")
    info = folder.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise RotationError("Credential directory must be owned by operator and mode 0700")


def _read_file(path: Path, *, private: bool, maximum: int = 65536,
               jenkins: bool = False) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size < 1 or info.st_size > maximum
                or info.st_mode & (0o077 if private else 0o022)
                or (private and (info.st_uid != os.geteuid()
                                 or stat.S_IMODE(info.st_mode) != 0o600))
                or (jenkins and (info.st_uid != 0 or info.st_gid != 1000
                                 or stat.S_IMODE(info.st_mode) != 0o640))):
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
    validate_v2_secrets(value)
    return value, hashlib.sha256(data).hexdigest()


def _parse_hosts(raw: bytes) -> dict[str, str]:
    # Parse precisely the bytes whose SHA-256 was checked by the caller.
    data = _decode(raw)
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


def _enrollment_inventory(path: Path, host: str | None) -> tuple[dict[str, str], str]:
    """Read and pin the exact operator-verified inventory for enrollment."""
    if not path.is_absolute():
        raise RotationError("Enrollment inventory must be an absolute path")
    raw = _read_file(path, private=False, maximum=1048576)
    hosts = _parse_hosts(raw)
    if host not in hosts:
        raise RotationError("Target host is not in the approved inventory")
    target = next(entry for entry in _decode(raw)["hosts"] if entry["alias"] == host)
    if target.get("privileged_access") not in ("restricted", "always-granted"):
        raise RotationError("Target host does not permit privileged access")
    return hosts, _digest(raw)


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
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
def _locked(source: Path, *, jenkins: bool = False) -> Iterator[None]:
    if jenkins:
        from ssh_mcp_secrets.batch import _trusted_jenkins
        _trusted_jenkins(source)
    else:
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
    if operation not in _OPERATIONS or ((operation in ("sudo", "add-sudo")) != (host is not None)):
        raise RotationError("Invalid rotation operation or host selection")
    validate_v2_secrets(value)
    if set(value["sealed_sudo"]) - set(hosts):
        raise RotationError("Source contains unsigned sudo host")
    if operation == "sudo" and host not in value["sealed_sudo"]:
        raise RotationError("Target host has no sealed sudo entry")
    if operation == "add-sudo" and (host not in hosts or host in value["sealed_sudo"]):
        raise RotationError("Target host is unknown or already has a sealed sudo entry")


def _transform(value: dict[str, Any], *, operation: str, host: str | None,
               hosts: dict[str, str], deployment: str, issuer: str) -> dict[str, Any]:
    if operation == "console":
        old = _prompt("Existing Console password")
        new = _prompt("New Console password", confirm=True)
        return rotate_console(value, old_password=old, new_password=new,
                              deployment=deployment, issuer=issuer, hosts=hosts)
    if operation in ("sudo", "add-sudo"):
        assert host is not None
        old = _prompt("Existing Console password")
        new = _prompt("New sudo credential for selected host", confirm=True)
        if (new == old or new == value["oauth_signing_key"]
                or verify_password(new, value["oauth_login_verifier"], "oauth-login")
                or verify_token(new, value["metrics_verifier"])):
            raise RotationError("New host credential is reused")
        if operation == "add-sudo":
            return add_host_sudo(value, console_password=old, new_sudo_password=new,
                                 deployment=deployment, issuer=issuer, alias=host, hosts=hosts)
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


def _read_inventory(inventory: Path, operation: str, host: str | None) -> tuple[dict[str, str], str]:
    if not inventory.is_absolute():
        raise RotationError("Absolute approved inventory required")
    if operation == "add-sudo":
        return _enrollment_inventory(inventory, host)
    raw = _read_file(inventory, private=False, maximum=1048576)
    return _parse_hosts(raw), _digest(raw)


def _read_target(source: Path, jenkins: bool) -> tuple[dict[str, Any], str]:
    if not jenkins:
        return _source(source)
    from ssh_mcp_secrets.batch import _trusted_jenkins
    raw = _trusted_jenkins(source)
    value = _decode(raw)
    validate_v2_secrets(value)
    return value, _digest(raw)


def _target_options(source: Path, jenkins: bool, expected_source: str | None,
                    expected_inventory: str | None, container: str | None,
                    container_file: str | None) -> None:
    if not source.is_absolute():
        raise RotationError("Absolute credential source required")
    if jenkins:
        from ssh_mcp_secrets.batch import _validate_container
        if os.geteuid() != 0 or container is None or container_file is None:
            raise RotationError("Root and explicit Jenkins controller mount required")
        _validate_container(container, container_file, source.name)
        if expected_source is None or expected_inventory is None:
            raise RotationError("Expected Jenkins source and inventory checksums required")
    elif container is not None or container_file is not None:
        raise RotationError("Controller options require a Jenkins target")
    for checksum in (expected_source, expected_inventory):
        if checksum is not None and _SHA.fullmatch(checksum) is None:
            raise RotationError("Invalid expected checksum")


def _check_expected(actual: str, expected: str | None) -> None:
    if expected is not None and actual != expected:
        raise RotationError("Approved source or inventory changed")


def plan(*, source: Path, inventory: Path, deployment: str, issuer: str,
         operation: str, host: str | None, jenkins: bool = False,
         expected_source: str | None = None, expected_inventory: str | None = None,
         container: str | None = None, container_file: str | None = None) -> str:
    _target_options(source, jenkins, expected_source, expected_inventory, container, container_file)
    value, sha = _read_target(source, jenkins)
    hosts, inventory_sha = _read_inventory(inventory, operation, host)
    _check_expected(sha, expected_source)
    _check_expected(inventory_sha, expected_inventory)
    _select(value, operation=operation, host=host, hosts=hosts)
    _binding(deployment, issuer)
    return (f"PLAN=PASS operation={operation} host={host or '-'} aliases={len(hosts)} "
            f"source_sha256={sha} inventory_sha256={inventory_sha}")


def _commit(source: Path, raw: bytes, *, jenkins: bool,
            precheck: Callable[[], None], readback: Callable[[], str],
            postcheck: Callable[[], None]) -> str:
    """Caller holds the common directory lock; never roll back after rename."""
    digest = _digest(raw)
    if len(raw) > 65536:
        raise RotationError("Prepared sealed revision exceeds size bound")
    validate_v2_secrets(_decode(raw))
    temp = source.parent / (_TEMP_PREFIX + secrets.token_hex(12))
    owned = False
    committed = False
    replacing = False
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        owned = True
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            if jenkins:
                os.fchown(stream.fileno(), 0, 1000)
                os.fchmod(stream.fileno(), 0o640)
            else:
                os.fchmod(stream.fileno(), 0o600)
            os.fsync(stream.fileno())
        if _digest(_read_file(temp, private=not jenkins, jenkins=jenkins)) != digest:
            raise RotationError("Prepared revision integrity failed")
        precheck()
        replacing = True
        os.replace(temp, source)
        committed = True
        _sync(source.parent)
        if readback() != digest:
            raise CommitUncertain("Committed source readback differs")
        postcheck()
        return digest
    except BaseException:
        # A signal immediately after rename can arrive before the assignment
        # above. If the owned candidate disappeared during rename, fail uncertain.
        if committed or (replacing and not temp.exists()):
            committed = True
            raise CommitUncertain("Offline commit may have succeeded; compare source digest",
                                  expected_digest=digest) from None
        raise
    finally:
        if owned and not committed:
            temp.unlink(missing_ok=True)


def apply(*, source: Path, inventory: Path, deployment: str, issuer: str,
          operation: str, host: str | None, jenkins: bool = False,
          expected_source: str | None = None, expected_inventory: str | None = None,
          container: str | None = None, container_file: str | None = None) -> str:
    _target_options(source, jenkins, expected_source, expected_inventory, container, container_file)
    with _locked(source, jenkins=jenkins):
        value, original = _read_target(source, jenkins)
        hosts, inventory_sha = _read_inventory(inventory, operation, host)
        _check_expected(original, expected_source)
        _check_expected(inventory_sha, expected_inventory)
        _select(value, operation=operation, host=host, hosts=hosts)
        _binding(deployment, issuer)
        changed = _transform(value, operation=operation, host=host, hosts=hosts,
                             deployment=deployment, issuer=issuer)
        validate_v2_secrets(changed)
        if operation == "add-sudo":
            unchanged = dict(changed, sealed_sudo={
                alias: envelope for alias, envelope in changed["sealed_sudo"].items()
                if alias != host
            })
            if host not in changed["sealed_sudo"] or unchanged != value:
                raise RotationError("Enrollment changed unrelated credentials")
        raw = (json.dumps(changed, sort_keys=True, indent=2) + "\n").encode()

        def precheck() -> None:
            _check_expected(_read_target(source, jenkins)[1], original)
            _check_expected(_read_inventory(inventory, operation, host)[1], inventory_sha)

        def postcheck() -> None:
            if jenkins:
                from ssh_mcp_secrets.batch import _postcheck_container
                assert container is not None and container_file is not None
                _postcheck_container(container, container_file, _digest(raw))

        return _commit(source, raw, jenkins=jenkins, precheck=precheck,
                       readback=lambda: _read_target(source, jenkins)[1], postcheck=postcheck)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="command", required=True)
    for cmd in ("plan", "apply"):
        sub = actions.add_parser(cmd)
        target = sub.add_mutually_exclusive_group(required=True)
        target.add_argument("--source", type=Path)
        target.add_argument("--jenkins-file", type=Path)
        sub.add_argument("--expected-source-sha256")
        sub.add_argument("--expected-inventory-sha256")
        sub.add_argument("--jenkins-container")
        sub.add_argument("--jenkins-container-file")
        sub.add_argument("--inventory", type=Path, required=True)
        sub.add_argument("--deployment", required=True, choices=("lab", "production"))
        sub.add_argument("--issuer", required=True)
        sub.add_argument("--operation", required=True, choices=_OPERATIONS)
        sub.add_argument("--host")
    batch = actions.add_parser("batch-handoff")
    batch.add_argument("--jenkins-file", type=Path, required=True)
    batch.add_argument("--inventory", type=Path, required=True)
    batch.add_argument("--vm-map", type=Path, required=True)
    batch.add_argument("--workdir", type=Path, required=True)
    batch.add_argument("--deployment", choices=("lab", "production"), required=True)
    batch.add_argument("--issuer", required=True)
    batch.add_argument("--expected-source-sha256", required=True)
    batch.add_argument("--expected-inventory-sha256", required=True)
    batch.add_argument("--jenkins-container", required=True)
    batch.add_argument("--jenkins-container-file", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "batch-handoff":
            if not (sys.stdin.isatty() and sys.stderr.isatty()):
                raise RotationError("Trusted interactive terminal required for credential entry")
            from ssh_mcp_secrets.batch import batch_handoff
            batch_result = batch_handoff(
                jenkins_file=args.jenkins_file, inventory=args.inventory,
                vm_map=args.vm_map, workdir=args.workdir,
                deployment=args.deployment, issuer=args.issuer,
                expected_source=args.expected_source_sha256,
                expected_inventory=args.expected_inventory_sha256,
                container=args.jenkins_container,
                container_file=args.jenkins_container_file,
            )
            print("BATCH_HANDOFF=COMMITTED aliases={aliases} vms={vm_count} "
                  "staged_sha256={staged_sha256} hashes_sha256={hashes_sha256} "
                  "proxmox_sha256={proxmox_sha256} hashes_path={hashes_path} "
                  "proxmox_path={proxmox_path} hash_prefix={hash_prefix}".format(**batch_result))
        else:
            params = dict(source=args.source or args.jenkins_file, inventory=args.inventory,
                          deployment=args.deployment, issuer=args.issuer, operation=args.operation,
                          host=args.host, jenkins=args.jenkins_file is not None,
                          expected_source=args.expected_source_sha256,
                          expected_inventory=args.expected_inventory_sha256,
                          container=args.jenkins_container, container_file=args.jenkins_container_file)
            if args.command == "plan":
                print(plan(**params))
            else:
                if not (sys.stdin.isatty() and sys.stderr.isatty()):
                    raise RotationError("Trusted interactive terminal required for credential entry")
                digest = apply(**params)
                print(f"APPLY=PASS sha256={digest}; deploy separately and independently verify consumers")
        return 0
    except CommitUncertain as exc:
        print("Offline commit outcome uncertain: compare source revision before any retry",
              file=sys.stderr)
        if exc.expected_digest is not None and _SHA.fullmatch(exc.expected_digest):
            print(f"expected_committed_sha256={exc.expected_digest}", file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, KeyError, EOFError, KeyboardInterrupt):
        print("Sealed revision operation rejected; inspect permissions, source and procedure",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
