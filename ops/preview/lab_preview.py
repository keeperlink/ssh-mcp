#!/usr/bin/env python3
"""Operator-invoked nonproduction preview; never deploys or signs a release.

Only the existing lab SSH MCP Docker container is inspected/reused. The original
container is stopped, never deleted or recreated. Docker/HAProxy changes happen
only on an explicitly selected nonproduction host.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from typing import Any, Iterator, Literal, cast, overload


STANDARD = ""
PREVIEW = ""
PROJECT = ""
PROXY = ""
NETWORK = ""
BACKENDS: tuple[str, ...] = ()
TRACE = False
SOURCE_PREVIEW = False
COMPOSE = Path(__file__).with_name("compose.yml")
SOURCE = Path(__file__).resolve().parents[2]
STATE = Path.home() / ".cache" / "ssh-mcp-preview"
MARKER = STATE / "switch.json"
SOCKET = "UNIX-CONNECT:/usr/local/etc/haproxy/haproxy.sock"
DockerObject = dict[str, Any]
DESTINATIONS = {
    "SSH_MCP_PREVIEW_CONFIG": "/etc/ssh-mcp/service.json",
    "SSH_MCP_PREVIEW_INVENTORY": "/etc/ssh-mcp/inventory.json",
    "SSH_MCP_PREVIEW_KNOWN_HOSTS": "/etc/ssh-mcp/known_hosts",
    "SSH_MCP_PREVIEW_SECRETS": "/run/secrets/ssh-mcp-secrets",
}


class PreviewError(RuntimeError):
    """Preflight or Docker/HAProxy operation failed."""


def docker_environment() -> dict[str, str]:
    # Never let an inherited Docker context or Compose variable redirect the
    # operation or override values inspected from the local original.
    return {key: value for key, value in os.environ.items()
            if not key.startswith(("DOCKER_", "COMPOSE_", "SSH_MCP_PREVIEW_"))}


def docker_argv(argv: tuple[str, ...]) -> tuple[str, ...]:
    if argv and argv[0] == "docker":
        return ("docker", "--host", "unix:///var/run/docker.sock", *argv[1:])
    return argv


def run(*argv: str, input_text: str | None = None) -> str:
    # Prevent an interrupted docker stop/start child from racing our rollback.
    with subprocess.Popen(
        docker_argv(argv), stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
        env=docker_environment(),
    ) as process:
        try:
            stdout, _ = process.communicate(input_text)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass  # Child exited between interruption and signal.
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
            raise
    if process.returncode:
        # Never include raw environment, container inspect output or secrets.
        raise PreviewError(f"{argv[0]} action failed (exit {process.returncode})")
    return stdout.strip()


@overload
def inspect(name: str, *, required: Literal[True] = True) -> DockerObject: ...


@overload
def inspect(name: str, *, required: Literal[False]) -> DockerObject | None: ...


def inspect(name: str, *, required: bool = True) -> DockerObject | None:
    result = subprocess.run(
        docker_argv(("docker", "inspect", "--type", "container", name)),
        text=True, capture_output=True, check=False, env=docker_environment(),
    )
    if result.returncode:
        if required:
            raise PreviewError(f"Expected Docker container {name!r} is absent")
        return None
    try:
        return cast(DockerObject, json.loads(result.stdout)[0])
    except (KeyError, ValueError, IndexError, TypeError) as exc:
        raise PreviewError(f"Invalid Docker metadata for {name}") from exc


def container_status(item: DockerObject | None) -> str:
    return str(item.get("State", {}).get("Status", "unknown")) if item else "absent"


def source_paths() -> list[Path]:
    """Only Python modules and their parent directories, never secrets."""
    roots = (SOURCE / "app", SOURCE / "ops" / "preview")
    paths: list[Path] = list(roots)
    for root in roots:
        if not root.is_dir() or root.is_symlink():
            raise PreviewError(f"Missing or unsafe preview source directory: {root}")
        for parent, dirs, files in os.walk(root, followlinks=False):
            # Bytecode/test caches are intentionally not runtime inputs.
            dirs[:] = [name for name in dirs if name not in {
                "__pycache__", ".mypy_cache", ".pytest_cache",
            }]
            paths.extend(Path(parent) / name for name in dirs)
            paths.extend(Path(parent) / name for name in files
                         if name.endswith((".py", ".css", ".js")))
    return list(dict.fromkeys(paths))


def _container_can_read(path: Path) -> bool:
    """The preview image runs as UID/GID 10001 with a read-only bind mount."""
    entry = path.lstat()
    directory = stat.S_ISDIR(entry.st_mode)
    if not directory and not stat.S_ISREG(entry.st_mode):
        raise PreviewError(f"Unsafe source entry (link or special file): {path}")
    if entry.st_uid == 10001:
        permission = stat.S_IXUSR if directory else stat.S_IRUSR
    elif entry.st_gid == 10001:
        permission = stat.S_IXGRP if directory else stat.S_IRGRP
    else:
        permission = stat.S_IXOTH if directory else stat.S_IROTH
    return bool(entry.st_mode & permission)


def verify_source_access(*, repair: bool = False) -> None:
    """Fail before Docker stop, or explicitly repair only source modules."""
    # Docker mounts only app/ and ops/preview/; the container cannot traverse
    # host parent directories or read the rest of the checkout.
    paths = source_paths()
    for path in paths:
        if _container_can_read(path):
            continue
        if not repair:
            raise PreviewError(
                f"Unreadable bind-mounted Python source for container UID 10001: {path}. "
                "Use 'lab_preview.py fix-source' before switching or after edits"
            )
        entry = path.lstat()
        if entry.st_uid != os.geteuid() or (stat.S_ISREG(entry.st_mode) and entry.st_nlink != 1):
            raise PreviewError(f"Cannot safely repair ownership/link count: {path}")
        needed = (stat.S_IROTH | stat.S_IXOTH) if stat.S_ISDIR(entry.st_mode) else stat.S_IROTH
        path.chmod(stat.S_IMODE(entry.st_mode) | needed)
        if not _container_can_read(path):
            raise PreviewError(f"Source still inaccessible after permission repair: {path}")


def preview_environment(standard: DockerObject) -> dict[str, str]:
    """Only derive paths/ports from the installed lab container, not secrets."""
    mounts = {item["Destination"]: item for item in standard["Mounts"]}
    required = (*DESTINATIONS.values(), "/var/lib/ssh-mcp")
    if set(mounts) != set(required):
        raise PreviewError("Original SSH MCP bind mounts or state volume are missing")
    for path in DESTINATIONS.values():
        if mounts[path]["Type"] != "bind":
            raise PreviewError(f"Expected original bind mount at {path}")
    state = mounts["/var/lib/ssh-mcp"]
    if state["Type"] != "volume" or not state.get("Name") or not state.get("RW"):
        raise PreviewError("Expected original writable SQLite state volume")
    if any(mounts[path].get("RW") is not False for path in DESTINATIONS.values()):
        raise PreviewError("Original managed inputs must be read-only")
    networks = standard.get("NetworkSettings", {}).get("Networks", {})
    if len(networks) != 2 or NETWORK not in networks:
        raise PreviewError("Expected ingress network and separate SSH transit network")
    transit = next(name for name in networks if name != NETWORK)
    if standard["Config"].get("User") != "10001:10001":
        raise PreviewError("Expected the hardened runtime UID/GID")
    if {"/run/ssh-mcp", "/tmp"} != set(standard["HostConfig"].get("Tmpfs") or {}):
        raise PreviewError("Expected current managed runtime tmpfs paths")
    config_env = dict(item.split("=", 1) for item in standard["Config"].get("Env", []) if "=" in item)
    required_env = {
        "MCP_CONFIG_FILE": DESTINATIONS["SSH_MCP_PREVIEW_CONFIG"],
        "MCP_INVENTORY_FILE": DESTINATIONS["SSH_MCP_PREVIEW_INVENTORY"],
        "MCP_KNOWN_HOSTS_FILE": DESTINATIONS["SSH_MCP_PREVIEW_KNOWN_HOSTS"],
        "MCP_SECRETS_FILE": DESTINATIONS["SSH_MCP_PREVIEW_SECRETS"],
        "SSH_JOBS_DB": "/var/lib/ssh-mcp/jobs.sqlite",
    }
    if any(config_env.get(key) != value for key, value in required_env.items()):
        raise PreviewError("Original is not using the expected managed runtime")
    bindings = standard["HostConfig"]["PortBindings"]["8000/tcp"]
    if (len(bindings) != 1 or not str(bindings[0].get("HostPort", "")).isdecimal()
            or not 1 <= int(bindings[0]["HostPort"]) <= 65535):
        raise PreviewError("Unexpected original SSH MCP host port bindings")
    address = ipaddress.ip_address(bindings[0]["HostIp"])
    if (address.version != 4 or address.is_unspecified or address.is_multicast or address.is_reserved
            or not (address.is_private or address.is_loopback)):
        raise PreviewError("Refusing a public, wildcard or non-unicast host bind for preview")
    bind_ip = str(address)
    image = str(standard["Config"]["Image"])
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-f]{64}", image):
        raise PreviewError("Original image must have an immutable SHA-256 registry pin")
    env = {
        "SSH_MCP_PREVIEW_IMAGE": image,
        "SSH_MCP_PREVIEW_BIND_IP": bind_ip,
        "SSH_MCP_PREVIEW_BIND_PORT": bindings[0]["HostPort"],
        "SSH_MCP_PREVIEW_SOURCE": str(SOURCE),
        "SSH_MCP_PREVIEW_NAME": PREVIEW,
        "SSH_MCP_PREVIEW_ALIAS": STANDARD,
        "SSH_MCP_PREVIEW_ORIGINAL_ID": standard["Id"],
        "SSH_MCP_PREVIEW_INGRESS": NETWORK,
        "SSH_MCP_PREVIEW_TRANSIT": transit,
        "SSH_MCP_PREVIEW_STATE_VOLUME": state["Name"],
        "SSH_MCP_PREVIEW_TRACE": "1" if TRACE else "0",
        "SSH_MCP_PREVIEW_SOURCE_MODE": "1" if SOURCE_PREVIEW else "0",
    }
    for key, destination in DESTINATIONS.items():
        env[key] = mounts[destination]["Source"]
    # Compose env-file parsing is not a shell; refuse ambiguous interpolation.
    if any(re.search(r"[\n\r\x00$#'\"\\]", value) or value != value.strip()
           for value in env.values()):
        raise PreviewError("Preview path or value requires unsupported env escaping")
    if not (SOURCE / "app" / "main.py").is_file():
        raise PreviewError("Source checkout is missing app/main.py")
    verify_source_access()
    return env


@contextmanager
def compose_env(standard: DockerObject) -> Iterator[Path]:
    env = preview_environment(standard)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, raw = tempfile.mkstemp(prefix="compose-", suffix=".env", dir=STATE)
    path = Path(raw)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write("".join(f"{key}={value}\n" for key, value in env.items()))
        yield path
    finally:
        path.unlink(missing_ok=True)


def compose(standard: DockerObject, *args: str) -> str:
    with compose_env(standard) as env:
        return run("docker", "compose", "--project-name", PROJECT, "-f",
                   str(COMPOSE), "--env-file", str(env), *args)


def haproxy_command(command: str) -> str:
    result = run("docker", "exec", "-i", PROXY, "socat", "-", SOCKET,
                 input_text=command + "\n")
    if re.search(r"(?i)\b(error|unknown|invalid|permission denied|not found)\b", result):
        raise PreviewError(f"HAProxy rejected runtime operation: {result[:160]}")
    return result


def check_haproxy(standard: DockerObject) -> None:
    state = haproxy_command("show servers state")
    rows = [line.split() for line in state.splitlines() if not line.startswith("#")]
    for backend in BACKENDS:
        name, server = backend.split("/")
        matching = [
            row for row in rows
            if len(row) >= 7 and row[1] == name and row[3] == server
        ]
        expected_ip = standard["NetworkSettings"]["Networks"][NETWORK]["IPAddress"]
        same_address = [row for row in rows if len(row) >= 7 and row[4] == expected_ip]
        if (len(matching) != 1 or len(same_address) != 1
                or matching[0][6] != "0" or matching[0][4] != expected_ip):
            raise PreviewError(
                f"Lab HAProxy backend {backend} is missing or already in maintenance/drain"
            )


def backend_state(state: str) -> None:
    """Block new HAProxy requests before draining SQLite operations."""
    if state not in {"maint", "ready"}:
        raise ValueError("Invalid HAProxy administrative state")
    for backend in BACKENDS:
        haproxy_command(f"set server {backend} state {state}")
    rows = [line.split() for line in haproxy_command("show servers state").splitlines()
            if not line.startswith("#")]
    for backend in BACKENDS:
        name, server = backend.split("/")
        matching = [row for row in rows
                    if len(row) >= 7 and row[1] == name and row[3] == server]
        # HAProxy srv_admin_state: 0=ready; 1=forced maintenance (other
        # administrative bits are forbidden for this controlled switch).
        expected = "1" if state == "maint" else "0"
        if len(matching) != 1 or matching[0][6] != expected:
            raise PreviewError(f"HAProxy {backend} did not enter {state} state")


def route_to(container: DockerObject) -> None:
    ip = container["NetworkSettings"]["Networks"][NETWORK]["IPAddress"]
    ip = str(ipaddress.ip_address(ip))
    for backend in BACKENDS:
        haproxy_command(f"set server {backend} addr {ip} port 8000")
    state = haproxy_command("show servers state")
    rows = [line.split() for line in state.splitlines() if not line.startswith("#")]
    for backend in BACKENDS:
        backend_name, server_name = backend.split("/")
        matching = [
            row for row in rows
            if len(row) >= 5 and row[1] == backend_name and row[3] == server_name
        ]
        if len(matching) != 1 or matching[0][4] != ip:
            raise PreviewError(f"HAProxy backend address verification failed for {backend}")


def wait_ready(name: str) -> DockerObject:
    for _ in range(60):
        item = inspect(name)
        health = item.get("State", {}).get("Health", {}).get("Status")
        if container_status(item) == "running" and health == "healthy":
            return item
        if container_status(item) in {"exited", "dead"} or health == "unhealthy":
            raise PreviewError(f"{name} did not become healthy")
        time.sleep(0.5)
    raise PreviewError(f"{name} readiness timed out")


DRAIN_QUERY = (
    "import sqlite3; db=sqlite3.connect("
    "'file:/var/lib/ssh-mcp/jobs.sqlite?mode=ro',uri=True); "
    "print(*[db.execute('SELECT COUNT(*) FROM '+table+' WHERE status IN (?,?,?)', "
    "('awaiting_approval','queued','running')).fetchone()[0] "
    "for table in ('jobs','file_operations','command_batches')]); db.close()"
)


def check_active_jobs(container: str) -> None:
    snippet = DRAIN_QUERY
    counts = run("docker", "exec", container, "python", "-c", snippet).split()
    if len(counts) != 3 or not all(value.isdecimal() for value in counts):
        raise PreviewError("Unable to verify active command, file and batch operations")
    jobs, files, batches = map(int, counts)
    if jobs or files or batches:
        raise PreviewError(
            f"Refusing to interrupt {jobs} command jobs, {files} file operations and {batches} batches"
        )


def wait_idle(container: str, *, seconds: int = 30) -> None:
    """Bounded drain; the caller must already have blocked ingress."""
    deadline = time.monotonic() + seconds
    while True:
        try:
            check_active_jobs(container)
            return
        except PreviewError as exc:
            if not str(exc).startswith("Refusing to interrupt ") or time.monotonic() >= deadline:
                raise
            time.sleep(0.5)


def mark_transition(phase: str) -> None:
    """Durable, private recovery marker, written before any ingress changes."""
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".switch-", dir=STATE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"phase": phase, **target_identity()}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, MARKER)
        directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temp).unlink(missing_ok=True)


def target_identity() -> dict[str, object]:
    return {"standard": STANDARD, "preview": PREVIEW, "proxy": PROXY,
            "network": NETWORK, "backend": list(BACKENDS),
            "container_id": inspect(STANDARD)["Id"], "proxy_id": inspect(PROXY)["Id"]}


def verify_transition() -> None:
    data = json.loads(MARKER.read_text())
    if any(data.get(key) != value for key, value in target_identity().items()):
        raise PreviewError("Recovery marker does not match the selected original container and ingress")


def clear_transition() -> None:
    MARKER.unlink(missing_ok=True)


def backup_live_db() -> Path:
    """Use SQLite's online backup API (WAL-consistent); preserve off-volume copy."""
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup_dir = STATE / "backups"
    backup_dir.mkdir(mode=0o700, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    suffix = uuid.uuid4().hex
    tmp = f"/var/lib/ssh-mcp/.preview-snapshot-{suffix}.sqlite"
    dest = backup_dir / f"{stamp}-{suffix}.sqlite"
    backup_code = (
        "import os,sqlite3,sys; "
        "source=sqlite3.connect('file:/var/lib/ssh-mcp/jobs.sqlite?mode=ro',uri=True); "
        "target=sqlite3.connect(sys.argv[1]); "
        "source.backup(target); target.close(); source.close(); "
        "os.chmod(sys.argv[1],0o600)"
    )
    try:
        run("docker", "exec", STANDARD, "python", "-c", backup_code, tmp)
        run("docker", "cp", f"{STANDARD}:{tmp}", str(dest))
        dest.chmod(0o600)
        with sqlite3.connect(f"file:{dest}?mode=ro", uri=True) as db:
            if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise PreviewError("Lab database snapshot integrity check failed")
    finally:
        run("docker", "exec", STANDARD, "python", "-c",
            "import pathlib,sys; pathlib.Path(sys.argv[1]).unlink(missing_ok=True)", tmp)
    return dest


def owned_preview(item: DockerObject) -> bool:
    labels = item.get("Config", {}).get("Labels") or {}
    return (labels.get("com.docker.compose.project") == PROJECT
            and labels.get("com.docker.compose.service") == "preview"
            and labels.get("org.ssh-mcp.preview.original") == inspect(STANDARD)["Id"])


def restore_standard(standard: DockerObject) -> None:
    # The original container is not recreated, so its original configuration,
    # secret mounts, image, and Docker restart policy remain untouched.
    verify_transition()
    item = inspect(PREVIEW, required=False)
    if item is not None and not owned_preview(item):
        raise PreviewError("Preview name is occupied by an unrelated container")
    backend_state("maint")
    if item is not None:
        run("docker", "stop", PREVIEW)
        run("docker", "rm", PREVIEW)
    if container_status(inspect(STANDARD)) != "running":
        run("docker", "start", STANDARD)
    route_to(wait_ready(STANDARD))
    backend_state("ready")


def start(standard: DockerObject) -> None:
    if MARKER.exists():
        raise PreviewError("Incomplete prior preview switch: use recover, not start")
    if container_status(standard) != "running":
        raise PreviewError("Original container is not running; refusing ambiguous switch")
    if inspect(PREVIEW, required=False) is not None:
        raise PreviewError("Preview container already exists; inspect or stop first")
    preview_environment(standard)
    environment = run("docker", "exec", STANDARD, "python", "-c",
                      "import json; print(json.load(open('/etc/ssh-mcp/service.json')).get('environment'))")
    if environment != "lab":
        raise PreviewError("Refusing preview: original service configuration is not lab")
    check_haproxy(standard)
    if run("docker", "image", "inspect", "--format", "{{.Id}}", standard["Config"]["Image"]) != standard["Image"]:
        raise PreviewError("Local pinned image does not match the original container")
    compose(standard, "config", "--quiet")
    mark_transition("starting")
    try:
        # Selected service ingress goes through the backend. Blocking
        # it before the SQLite checks prevents new submissions during backup.
        backend_state("maint")
        wait_idle(STANDARD)
        snapshot = backup_live_db()
        print(f"VERIFIED_LAB_SQLITE_BACKUP={snapshot}")
        # Capture a request that completed/started during snapshot before stop.
        wait_idle(STANDARD)
        print("Stopping original lab container; no Compose recreate or image publishing")
        run("docker", "stop", STANDARD)
        compose(standard, "up", "--detach", "--no-deps", "--pull", "never")
        route_to(wait_ready(PREVIEW))
        backend_state("ready")
        mark_transition("preview_active")
    except BaseException as exc:
        print(f"PREVIEW_SWITCH_FAILED={exc}", file=sys.stderr)
        try:
            restore_standard(standard)
            clear_transition()
        except BaseException as rollback:
            raise PreviewError(f"Switch failed AND rollback failed: {rollback}") from exc
        raise PreviewError("Preview switch failed; original lab service restored") from exc
    print("PREVIEW=ACTIVE; original container stopped; HAProxy now targets the preview")


def stop(standard: DockerObject) -> None:
    verify_transition()
    item = inspect(PREVIEW, required=False)
    if item is None:
        raise PreviewError("No preview container exists; refusing unrelated changes")
    if not owned_preview(item):
        raise PreviewError("Preview name is occupied by an unexpected container")
    mark_transition("restoring")
    try:
        backend_state("maint")
        if container_status(item) == "running":
            wait_idle(PREVIEW)
    except BaseException as exc:
        # Draining failed before touching the preview container. Restore its
        # ingress instead of leaving the still-running lab endpoint offline.
        try:
            backend_state("ready")
            mark_transition("preview_active")
        except BaseException as restoration:
            raise PreviewError(
                f"Preview still running but ingress recovery failed: {restoration}"
            ) from exc
        raise PreviewError(f"Preview remains active; stop postponed: {exc}") from exc
    try:
        restore_standard(standard)
        clear_transition()
    except BaseException as exc:
        # The recovery marker remains, even across SIGKILL or process loss.
        raise PreviewError("Restore incomplete; use recover to restore original lab "
                           f"container: {exc}") from exc
    print("PREVIEW=STOPPED; original lab container restarted and HAProxy restored")
    print("NOTE: database contents were NOT rolled back; restore snapshot separately if required")


def recover(standard: DockerObject) -> None:
    """Explicit operator recovery after an interrupted switch or restore."""
    if not MARKER.exists():
        raise PreviewError("No incomplete/active preview recorded; nothing to recover")
    verify_transition()
    # Emergency recovery: operations still active in a stranded preview may
    # have uncertain outcomes. Never automatically restore SQLite.
    restore_standard(standard)
    clear_transition()
    print("RECOVERY=RESTORED; original lab container running; HAProxy backends ready")


def main() -> int:
    global STANDARD, PREVIEW, PROJECT, PROXY, NETWORK, BACKENDS, STATE, MARKER, TRACE, SOURCE_PREVIEW
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "stop", "status", "recover", "fix-source"))
    parser.add_argument("--test-host", required=True, help="Exact approved nonproduction hostname")
    parser.add_argument("--container", required=True, help="Original managed service container")
    parser.add_argument("--proxy", required=True, help="HAProxy container")
    parser.add_argument("--backend", required=True, help="Exact HAProxy backend/server")
    parser.add_argument("--network", required=True, help="Original ingress Docker network")
    parser.add_argument("--trace", action="store_true", help="Log redacted MCP request headers and metadata")
    parser.add_argument("--source-preview", action="store_true", help="Opt in to reviewed local app source and reload")
    args = parser.parse_args()
    name_pattern = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}"
    if (socket.gethostname().split(".")[0] != args.test_host or os.geteuid() == 0
            or not all(re.fullmatch(name_pattern, value)
                       for value in (args.test_host, args.container, args.proxy, args.network))
            or not re.fullmatch(name_pattern + "/" + name_pattern, args.backend)):
        parser.error("Require exact approved nonproduction hostname, non-root user and valid target names")
    STANDARD, PREVIEW, PROJECT = args.container, args.container + "-dev", args.container + "-preview"
    if args.proxy in (STANDARD, PREVIEW):
        parser.error("Proxy and service containers must be distinct")
    PROXY, NETWORK, BACKENDS = args.proxy, args.network, (args.backend,)
    TRACE, SOURCE_PREVIEW = args.trace, args.source_preview
    STATE = STATE / STANDARD
    MARKER = STATE / "switch.json"
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    entry = STATE.lstat()
    if not stat.S_ISDIR(entry.st_mode) or entry.st_uid != os.geteuid() or stat.S_IMODE(entry.st_mode) != 0o700:
        parser.error("Unsafe private state directory")
    def interrupted(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt("Preview switch interrupted; recover if necessary")

    signal.signal(signal.SIGTERM, interrupted)
    with (STATE / "switch.lock").open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            standard = inspect(STANDARD)
            if args.action == "fix-source":
                verify_source_access(repair=True)
                print("SOURCE_PERMISSIONS=READY_FOR_UID_10001")
            elif args.action == "status":
                print(f"STANDARD={container_status(standard)}")
                print(f"PREVIEW={container_status(inspect(PREVIEW, required=False))}")
                print(f"RECOVERY_REQUIRED={'yes' if MARKER.exists() else 'no'}")
            elif args.action == "start":
                start(standard)
            elif args.action == "stop":
                stop(standard)
            else:
                recover(standard)
        except (PreviewError, OSError, ValueError, KeyError, KeyboardInterrupt) as exc:
            print(f"PREVIEW_ERROR={exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
