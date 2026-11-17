#!/usr/bin/env python3
"""Temporarily replace a managed Docker service with its live-source clone."""
from __future__ import annotations

import argparse
from copy import deepcopy
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import subprocess
import sys
import tempfile
from typing import Any, cast
from urllib.parse import urlencode

SOURCE = Path(__file__).resolve().parents[2] / "app"
SOCKET = "/var/run/docker.sock"
LABEL = "org.ssh-mcp.preview.original"
VERSION = "/usr/local/share/ssh-mcp/version"
TEMP_PREFIX = "ssh-mcp-preview-"


def docker(*args: str) -> str:
    # Never allow inherited Docker settings to select a remote daemon.
    env = {k: v for k, v in os.environ.items() if not k.startswith("DOCKER_")}
    result = subprocess.run(
        ["docker", "--host", f"unix://{SOCKET}", *args],
        env=env, capture_output=True, text=True,
    )
    if result.returncode:
        raise RuntimeError(f"Docker {args[0]} failed (exit {result.returncode})")
    return result.stdout.strip()


class EngineConnection(http.client.HTTPConnection):
    """Only container creation needs the Engine API rather than the CLI."""

    def __init__(self) -> None:
        super().__init__("localhost", timeout=60)

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(SOCKET)


def create(name: str, config: dict[str, Any]) -> str:
    version = docker("version", "--format", "{{.Server.APIVersion}}")
    if not re.fullmatch(r"1\.[0-9]+", version):
        raise RuntimeError("Unrecognized Docker Engine API version")
    conn = EngineConnection()
    try:
        conn.request("POST", f"/v{version}/containers/create?{urlencode({'name': name})}",
                     body=json.dumps(config), headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        if response.status != 201:
            # The daemon error may include inspected private configuration.
            raise RuntimeError(f"Docker create failed (HTTP {response.status})")
        result = json.loads(response.read())
        identifier = result["Id"]
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-f0-9]{64}", identifier):
            raise RuntimeError("Invalid Docker container ID")
        return identifier
    finally:
        conn.close()


def inspect(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(docker("inspect", "--type", "container", name))[0])


def running(item: dict[str, Any]) -> bool:
    return bool(item["State"]["Running"])


def fixture_exists(name: str) -> bool:
    return name in docker("container", "ls", "-a", "--format", "{{.Names}}").splitlines()


def package_path(name: str) -> str:
    path = docker("exec", name, "python", "-c",
                  "from importlib.util import find_spec; from pathlib import Path; "
                  "print(Path(find_spec('app').origin).parent)")
    if not PurePosixPath(path).is_absolute() or PurePosixPath(path).name != "app" or "\n" in path:
        raise RuntimeError("Cannot locate the installed app package")
    return path


def commit_version() -> str:
    result = subprocess.run(
        ["git", "-C", str(SOURCE.parent), "rev-parse", "--short=7", "HEAD"],
        capture_output=True, text=True,
    )
    value = result.stdout.strip()
    if result.returncode or not re.fullmatch(r"[0-9a-f]{7,40}", value):
        raise RuntimeError("Cannot determine checkout commit")
    return value


def write_version(path: Path) -> None:
    # Update the same inode: it is directly bind-mounted into the fixture.
    path.write_text(commit_version() + "\n", encoding="ascii")
    path.chmod(0o644)


def new_version_file() -> Path:
    path = Path(tempfile.mkdtemp(prefix=TEMP_PREFIX, dir="/tmp")) / "version"
    try:
        write_version(path)
    except (OSError, RuntimeError):
        remove_version_file(path)
        raise
    return path


def remove_version_file(path: Path) -> None:
    path.unlink(missing_ok=True)
    if path.parent.exists():
        path.parent.rmdir()


def mounted_version_file(item: dict[str, Any]) -> Path | None:
    for mount in item.get("Mounts", []):
        if mount["Destination"] == VERSION:
            path = Path(mount["Source"])
            if (mount["Type"] != "bind" or mount["RW"] or path.name != "version"
                    or path.parent.parent != Path("/tmp")
                    or not path.parent.name.startswith(TEMP_PREFIX)
                    or path.parent.is_symlink() or path.is_symlink()
                    or (path.parent.exists() and path.parent.stat().st_uid != os.geteuid())
                    or (path.exists() and (not path.is_file() or path.stat().st_uid != os.geteuid()))):
                raise RuntimeError("Unexpected preview version mount")
            return path
    return None


def clone_config(original: dict[str, Any], name: str, target: str, version_file: Path) -> dict[str, Any]:
    """Clone creation settings, not inspection-only runtime state."""
    config = deepcopy(original["Config"])
    host = deepcopy(original["HostConfig"])
    if host.get("AutoRemove") or host.get("VolumesFrom"):
        raise RuntimeError("Cannot retain an auto-removing container or volumes-from lifecycle")
    config["Image"] = original["Image"]
    # Docker normally supplies a hostname derived from the new container ID.
    if config.get("Hostname") == original["Id"][:12]:
        config.pop("Hostname", None)
    config.pop("MacAddress", None)
    config["Labels"] = {
        k: v for k, v in (config.get("Labels") or {}).items()
        if not k.startswith("com.docker.compose.")
    }
    config["Labels"][LABEL] = original["Id"]
    host["RestartPolicy"] = {"Name": "no", "MaximumRetryCount": 0}
    if host.get("ContainerIDFile"):
        host["ContainerIDFile"] = ""

    # Retain every existing volume's actual identity, even for anonymous
    # volumes declared by the image or mounted without an explicit name.
    volumes = {m["Destination"]: m for m in original["Mounts"] if m["Type"] == "volume"}
    binds = host.get("Binds") or []
    mounts = host.get("Mounts") or []
    covered = set()
    for index, bind in enumerate(binds):
        parts = bind.split(":")
        destination = parts[1] if len(parts) > 1 else parts[0]
        covered.add(destination)
        if destination in volumes:
            volume = volumes[destination]
            binds[index] = ":".join([volume["Name"], destination, *parts[2:]]) if len(parts) > 1 else (
                f"{volume['Name']}:{destination}" + ("" if volume["RW"] else ":ro"))
    host["Binds"] = binds
    for mount in mounts:
        destination = mount["Target"]
        covered.add(destination)
        if mount["Type"] == "volume":
            mount["Source"] = volumes[destination]["Name"]
    for destination, volume in volumes.items():
        if destination not in covered:
            mounts.append({"Type": "volume", "Source": volume["Name"], "Target": destination,
                           "ReadOnly": not volume["RW"], "VolumeOptions": {"NoCopy": True}})
    occupied = covered | {m["Destination"] for m in original["Mounts"]} | set(host.get("Tmpfs") or {})
    for source, destination in ((SOURCE, target), (version_file, VERSION)):
        if destination in occupied:
            raise RuntimeError("Preview target is already a mount target")
        mounts.append({"Type": "bind", "Source": str(source), "Target": destination, "ReadOnly": True})
    host["Mounts"] = mounts

    endpoints = {}
    for network, endpoint in original["NetworkSettings"]["Networks"].items():
        # These are configurable endpoint fields; do not copy IP/MAC addresses,
        # DNSNames, gateways, endpoint IDs or other assigned network state.
        settings = {k: deepcopy(endpoint[k]) for k in ("IPAMConfig", "Links", "DriverOpts", "GwPriority")
                    if k in endpoint and endpoint[k] is not None}
        if network not in {"bridge", "host", "none"}:
            settings["Aliases"] = list(dict.fromkeys([*(endpoint.get("Aliases") or []), name]))
        endpoints[network] = settings
    return {**config, "HostConfig": host, "NetworkingConfig": {"EndpointsConfig": endpoints}}


def operate(action: str, name: str) -> None:
    original = inspect(name)
    dev = name + "-dev"
    exists = fixture_exists(dev)
    if action == "status":
        print(f"{name}: {original['State']['Status']}")
        print(f"{dev}: {inspect(dev)['State']['Status'] if exists else 'absent'}")
        return
    if action == "start":
        if exists or not running(original):
            raise RuntimeError("Need running original and no existing fixture")
        if not (SOURCE / "__init__.py").is_file():
            raise RuntimeError("Missing checked-out app package")
        target = package_path(original["Id"])
        version_file = new_version_file()
        try:
            config = clone_config(original, name, target, version_file)
            identifier = create(dev, config)
        except (OSError, ValueError, KeyError, RuntimeError, http.client.HTTPException):
            # Retain the bind source if create succeeded but its response was lost.
            if not fixture_exists(dev):
                remove_version_file(version_file)
            raise
        # Validate by creating a stopped fixture first; only then stop the
        # original. Never start two containers sharing the audit database.
        docker("stop", original["Id"])
        docker("start", identifier)
        return
    if not exists:
        raise RuntimeError("Fixture is absent; inspect status and restart original manually if necessary")
    item = inspect(dev)
    labels = item["Config"].get("Labels") or {}
    if labels.get(LABEL) != original["Id"]:
        raise RuntimeError("Unexpected fixture")
    if running(original) and (running(item) or action == "restart"):
        raise RuntimeError("Original is running")
    mounted_version = mounted_version_file(item)
    if action == "restart":
        if mounted_version is None or not mounted_version.is_file():
            raise RuntimeError("Missing preview version mount; stop and recreate fixture")
        if not any(m["Type"] == "bind" and m["Source"] == str(SOURCE)
                   for m in item["Mounts"]):
            raise RuntimeError("Restart from the checkout mounted in the fixture")
        write_version(mounted_version)
        docker("restart", item["Id"])
    elif action == "stop":
        if running(item):
            docker("stop", item["Id"])
        docker("rm", item["Id"])
        try:
            if not running(original):
                docker("start", original["Id"])
        finally:
            if mounted_version is not None:
                remove_version_file(mounted_version)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "stop", "restart", "status"))
    parser.add_argument("--container", default="ssh-mcp")
    args = parser.parse_args()
    if os.geteuid() == 0 or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", args.container):
        parser.error("Require valid container name and non-root user")
    try:
        operate(args.action, args.container)
    except (OSError, ValueError, KeyError, RuntimeError, http.client.HTTPException) as exc:
        print(f"Preview failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
