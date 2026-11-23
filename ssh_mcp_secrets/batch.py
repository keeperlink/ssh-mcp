"""Offline one-session sealed credential rotation and hash-only host handoff.

Run only in an operator-owned interactive terminal. Never log credentials,
hashes, stage contents, or copy cleartext sudo passwords to persistent media.
"""
from __future__ import annotations

import getpass
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
from typing import Any

from app.sealed_credentials import (
    create_verifier, seal_sudo, unseal_sudo, validate_v2_secrets,
    verify_password, verify_token,
)
from ssh_mcp_secrets import cli

_HASH = re.compile(r"\$6\$[./a-zA-Z0-9]{1,16}\$[./a-zA-Z0-9]{86}\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")


def _json(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _trusted_jenkins(path: Path) -> bytes:
    # Jenkins consumes a host file via the existing read-only controller mount.
    if not path.is_absolute() or path.name != "skymap-ssh-mcp-secrets":
        raise cli.RotationError("Expected the approved production secretFile leaf")
    if path.parent.name != "deployment" or path.parent.is_symlink():
        raise cli.RotationError("Untrusted deployment secret directory")
    parent = path.parent.stat()
    if (parent.st_uid != 0 or parent.st_gid != 1000 or
            stat.S_IMODE(parent.st_mode) != 0o750):
        raise cli.RotationError("Untrusted Jenkins deployment directory")
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_uid != 0 or info.st_gid != 1000 or
            stat.S_IMODE(info.st_mode) != 0o640):
        raise cli.RotationError("Untrusted Jenkins secretFile")
    return cli._read_file(path, private=False)


def _hash_sudo(password: str) -> str:
    # OpenSSL generates an independently random salt; password travels via stdin.
    proc = subprocess.run(
        ["openssl", "passwd", "-6", "-stdin"],
        input=(password + "\n").encode(), capture_output=True, timeout=20, check=False,
    )
    if proc.returncode != 0:
        raise cli.RotationError("Linux shadow hash generation failed")
    try:
        result = proc.stdout.decode("ascii").strip()
    except UnicodeDecodeError:
        raise cli.RotationError("Invalid Linux password hash") from None
    if _HASH.fullmatch(result) is None:
        raise cli.RotationError("Unsupported Linux password hash output")
    return result


def _vm_map(path: Path, hosts: dict[str, str]) -> dict[str, int]:
    # Operator owns this static mapping, never infer VMID from aliases.
    info = cli._decode(cli._read_file(path, private=False, maximum=16384))
    if set(info) != {"version", "vmids"} or info["version"] != 1 or type(info["vmids"]) is not dict:
        raise cli.RotationError("Invalid approved VM mapping")
    mapping = info["vmids"]
    if (not mapping or set(mapping) - set(hosts)
            or any(type(k) is not str or type(v) is not int or v < 100 or v > 999999
                   for k, v in mapping.items())
            or len(set(mapping.values())) != len(mapping)):
        raise cli.RotationError("Invalid VM identity mapping")
    return mapping


def _generate(old: dict[str, Any], *, hosts: dict[str, str],
              deployment: str, issuer: str,
              old_oauth: str, new_oauth: str, old_console: str,
              new_console: str) -> tuple[dict[str, Any], dict[str, str]]:
    validate_v2_secrets(old)
    if (set(hosts) != set(old["sealed_sudo"]) or not hosts
            or any(username != "gateway" for username in hosts.values())):
        raise cli.RotationError("Production gateway inventory not exact")
    if not verify_password(old_oauth, old["oauth_login_verifier"], "oauth-login"):
        raise cli.RotationError("Existing OAuth credential rejected")
    if not verify_password(old_console, old["viewer_verifier"], "console-login"):
        raise cli.RotationError("Existing Console credential rejected")
    if (old_oauth == new_oauth or old_console == new_console
            or new_oauth == new_console or new_oauth == old_console
            or new_console == old_oauth or
            new_oauth == old["oauth_signing_key"] or
            new_console == old["oauth_signing_key"] or
            verify_token(new_oauth, old["metrics_verifier"]) or
            verify_token(new_console, old["metrics_verifier"])):
        raise cli.RotationError("Operator passwords are not independent")
    # Create first: validation fails before any new file is installed.
    oauth_verifier = create_verifier(new_oauth, "oauth-login")
    console_verifier = create_verifier(new_console, "console-login")
    # Authenticate each old sealed entry and binding before rekeying.
    for alias, username in hosts.items():
        unseal_sudo(old_console, old["sealed_sudo"][alias],
                    deployment=deployment, issuer=issuer,
                    alias=alias, username=username)
    passwords: dict[str, str] = {}
    for alias in sorted(hosts):
        candidate = secrets.token_urlsafe(48)
        if (candidate in passwords.values() or
                candidate in (new_oauth, new_console, old_oauth, old_console)):
            raise cli.RotationError("Generated sudo credential collision")
        passwords[alias] = candidate
    new = dict(old)
    new["oauth_login_verifier"] = oauth_verifier
    new["viewer_verifier"] = console_verifier
    new["viewer_generation"] = secrets.token_hex(16)
    new["sealed_sudo"] = {
        alias: seal_sudo(new_console, password, deployment=deployment,
                         issuer=issuer, alias=alias, username=hosts[alias])
        for alias, password in passwords.items()
    }
    validate_v2_secrets(new)
    return new, passwords


def _postcheck_container(name: str, file: str, expected: str) -> None:
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", name):
        raise cli.RotationError("Jenkins container readback is mandatory")
    if not file.startswith("/run/jenkins/secrets/deployment/") or file.endswith("/"):
        raise cli.RotationError("Invalid mounted Jenkins secret path")
    proc = subprocess.run(
        ["docker", "exec", name, "sha256sum", file],
        capture_output=True, timeout=20, check=False,
    )
    if proc.returncode or not proc.stdout.decode("ascii", "replace").startswith(expected + " "):
        raise cli.ActivationUncertain("Jenkins container credential handoff not confirmed")


def batch_handoff(*, jenkins_file: Path, inventory: Path, vm_map: Path,
                  workdir: Path, deployment: str, issuer: str,
                  expected_source: str, expected_inventory: str,
                  container: str, container_file: str) -> dict[str, Any]:
    """Stage complete sealed successor plus hash exports, then atomically replace Jenkins secret.

    No host password is modified, no application is restarted, and no backup
    copy is written. All output hashes are crypt verifiers, not raw passwords.
    """
    if os.geteuid() != 0:
        raise cli.RotationError("Operator must be root")
    if _SHA.fullmatch(expected_source) is None or _SHA.fullmatch(expected_inventory) is None:
        raise cli.RotationError("Expected source and inventory checksums required")
    cli._private_dir(workdir)
    cli._binding(deployment, issuer)
    approved_inventory = cli._read_file(inventory, private=False, maximum=1048576)
    if cli._digest(approved_inventory) != expected_inventory:
        raise cli.RotationError("Approved inventory changed")
    hosts = cli._hosts(inventory)
    vms = _vm_map(vm_map, hosts)
    original = _trusted_jenkins(jenkins_file)
    if cli._digest(original) != expected_source:
        raise cli.RotationError("Jenkins secret changed; do not rotate")
    old = cli._decode(original)
    validate_v2_secrets(old)
    # Complete all prompts before creating any side-effecting output.
    old_oauth = getpass.getpass("Existing OAuth password: ")
    new_oauth = getpass.getpass("New OAuth password: ")
    if new_oauth != getpass.getpass("Confirm New OAuth password: "):
        raise cli.RotationError("OAuth confirmation mismatch")
    old_console = getpass.getpass("Existing Console password: ")
    new_console = getpass.getpass("New Console password: ")
    if new_console != getpass.getpass("Confirm New Console password: "):
        raise cli.RotationError("Console confirmation mismatch")
    updated, passwords = _generate(
        old, hosts=hosts, deployment=deployment, issuer=issuer,
        old_oauth=old_oauth, new_oauth=new_oauth,
        old_console=old_console, new_console=new_console,
    )
    stage = _json(updated)
    stage_sha = cli._digest(stage)
    hash_entries = {
        alias: {"alias": alias, "username": hosts[alias],
                "hash": _hash_sudo(password)}
        for alias, password in passwords.items()
    }
    stamp = secrets.token_hex(12)
    prefix = "ssh-mcp-batch-" + stamp
    metadata = {
        "version": 1, "source_sha256": expected_source, "staged_sha256": stage_sha,
        "inventory_sha256": expected_inventory,
    }
    contents: dict[Path, bytes] = {
        workdir / (prefix + ".sealed.json"): stage,
        workdir / (prefix + ".plan.json"): _json({
            **metadata, "aliases": sorted(hosts),
            "generation": updated["viewer_generation"],
        }),
        workdir / (prefix + ".hashes.json"): _json({
            **metadata, "type": "hash-only", "entries": list(hash_entries.values()),
        }),
        workdir / (prefix + ".proxmox.json"): _json({
            **metadata, "type": "proxmox-hash-only",
            "entries": [{**hash_entries[a], "vmid": vid} for a, vid in sorted(vms.items())],
        }),
    }
    for alias, entry in hash_entries.items():
        contents[workdir / (prefix + "." + alias + ".json")] = _json({
            **metadata, "type": "host-hash-only", "entry": entry,
        })
    # Preserve private stage/manifest for explicit recovery; never overwrite or
    # automatically roll back a committed Jenkins handoff.
    try:
        for path, raw in contents.items():
            cli._write_new(path, raw)
        cli._sync(workdir)
        if cli._digest(_trusted_jenkins(jenkins_file)) != expected_source:
            raise cli.RotationError("Jenkins source changed after stage")
        for path, raw in contents.items():
            if cli._digest(cli._read_file(path, private=True)) != cli._digest(raw):
                raise cli.RotationError("Incomplete hash export or stage")
        # Commit on the Jenkins filesystem, preserving root:1000 / 0640.
        destination_temp = jenkins_file.parent / (".ssh-mcp-batch-" + stamp)
        fd = os.open(destination_temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
        try:
            os.fchown(fd, 0, 1000)
            os.fchmod(fd, 0o640)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(stage)
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        committed = False
        try:
            if cli._digest(_trusted_jenkins(jenkins_file)) != expected_source:
                raise cli.RotationError("Jenkins source changed before commit")
            os.replace(destination_temp, jenkins_file)
            committed = True
            cli._sync(jenkins_file.parent)
        except OSError:
            if committed:
                raise cli.ActivationUncertain("Jenkins handoff may be committed; compare source digest") from None
            raise
        finally:
            destination_temp.unlink(missing_ok=True)
        if cli._digest(_trusted_jenkins(jenkins_file)) != stage_sha:
            raise cli.ActivationUncertain("Jenkins credential replacement uncertain")
        _postcheck_container(container, container_file, stage_sha)
    except Exception:
        # Prepared files remain available to reconcile an uncertain handoff.
        raise
    return {
        "staged_sha256": stage_sha,
        "staged_path": str(workdir / (prefix + ".sealed.json")),
        "hashes_path": str(workdir / (prefix + ".hashes.json")),
        "proxmox_path": str(workdir / (prefix + ".proxmox.json")),
        "hashes_sha256": cli._digest(contents[workdir / (prefix + ".hashes.json")]),
        "proxmox_sha256": cli._digest(contents[workdir / (prefix + ".proxmox.json")]),
        "hash_prefix": str(workdir / prefix),
        "aliases": len(hosts), "vm_count": len(vms),
    }
