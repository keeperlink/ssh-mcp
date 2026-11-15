#!/usr/bin/env python3
"""Pinned, project-owned integration-test lifecycle on the isolated SSH-MCP lab.

No GitHub writes, service deployment, registry pushes, signing or real SSH hosts.
The runner MUST be installed from a separately reviewed immutable revision;
it must never be executed from a candidate PR checkout.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import time
from typing import Iterator

ORIGIN = "https://github.com/keeperlink/ssh-mcp.git"
REPO = ORIGIN.rsplit("/", 1)[-1].removesuffix(".git")
RUNNER = Path(__file__).resolve().parent
HOME = Path.home()
RESULTS = HOME / "test-results" / REPO
CACHE = HOME / "repos" / (REPO + ".git")
WORKSPACES = HOME / "workspaces" / REPO
STORY = re.compile(r"[A-Z][A-Z0-9]{1,12}-[1-9][0-9]*\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
RUN = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}\Z")
OWNER_LABEL = "org.sshmcp.lab-run"
STORY_LABEL = "org.sshmcp.lab-story"
IMAGE_LABEL = "org.sshmcp.lab-commit"
FIXTURE_LABEL = "org.sshmcp.lab-fixture-sha"


class LabError(RuntimeError):
    """An expected, classified setup/test/cleanup failure."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def valid_story(value: str) -> str:
    if not STORY.fullmatch(value):
        raise LabError("Story must be PROJECT-N (uppercase key and positive integer)")
    return value


def valid_run(value: str) -> str:
    if not RUN.fullmatch(value):
        raise LabError("Invalid test run ID")
    return value


def valid_sha(value: str) -> str:
    if not COMMIT.fullmatch(value):
        raise LabError("Commit must be a full, lowercase 40-character Git SHA")
    return value


def trusted_runner_sha() -> str:
    """Refuse runtime mutations from the source checkout under test.

    The lab's pinned runner is installed from a separately reviewed commit
    at ~/tools/ssh-mcp-lab/FULL_SHA/. The active symlink is not a
    trust anchor: both the canonical directory and marker must agree.
    """
    base = HOME / "tools" / "ssh-mcp-lab"
    if RUNNER.parent != base:
        raise LabError("Use a separately installed pinned runner, not a PR worktree")
    sha = valid_sha(RUNNER.name)
    marker = RUNNER / "PINNED_COMMIT"
    if not marker.is_file() or marker.is_symlink() or marker.read_text().strip() != sha:
        raise LabError("Runner installation lacks a matching reviewed source marker")
    if git("cat-file", "-t", sha) != "commit":
        raise LabError("Pinned runner commit missing from local Git cache")
    for rel in ("runner.py", "client.py", "smoke.py",
                "fixture/Dockerfile", "fixture/entrypoint.sh"):
        expected = git("rev-parse", f"{sha}:tests/lab/{rel}")
        actual = text(["git", "hash-object", "--no-filters", str(RUNNER / rel)])
        if expected != actual:
            raise LabError(f"Runner file changed since approved commit: {rel}")
    return sha


def initialize() -> None:
    RESULTS.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(RESULTS, 0o700)


def save_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + ".tmp." + secrets.token_hex(4))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(data, out, indent=2, sort_keys=True)
            out.write("\n")
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        obj = json.load(stream)
    if not isinstance(obj, dict):
        raise LabError(f"Invalid state document: {path.name}")
    return obj


def active_path() -> Path:
    return RESULTS / ".active.json"


@contextmanager
def locked() -> Iterator[None]:
    initialize()
    fd = os.open(RESULTS / ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LabError("Another lab test operation is active; retry later") from exc
        yield
    finally:
        os.close(fd)


def run_folder(story: str, run: str) -> Path:
    return RESULTS / valid_story(story) / valid_run(run)


def locate(run: str) -> tuple[Path, dict]:
    valid_run(run)
    files = list(RESULTS.glob(f"*-*/{run}/state.json"))
    if len(files) != 1:
        raise LabError(f"Unknown or ambiguous run: {run}")
    path = files[0].parent
    state = load_json(files[0])
    if state.get("run_id") != run or path != run_folder(state.get("story", ""), run):
        raise LabError("Run metadata does not match its owned path")
    return path, state


def cmd(argv: list[str], *, cwd: Path | None = None, output: Path | None = None,
        timeout: int | None = None, check: bool = True) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
    if output:
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as stream:
            result = subprocess.run(argv, cwd=cwd, env=env, stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=timeout,
                                    check=False)
    else:
        result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True,
                                timeout=timeout, check=False)
    if check and result.returncode:
        raise LabError(
            f"Command {argv[0]} failed (exit={result.returncode})"
            + (f"; see {output}" if output else "")
            + (("; " + result.stderr.decode(errors="replace")[:200]) if result.stderr else "")
        )
    return result


def text(argv: list[str], *, timeout: int = 30) -> str:
    return cmd(argv, timeout=timeout).stdout.decode("utf-8", errors="replace").strip()


def git(*args: str) -> str:
    return text(["git", "--git-dir", str(CACHE), "-c", "core.hooksPath=/dev/null",
                 "-c", "filter.lfs.smudge=", "-c", "filter.lfs.process=", *args], timeout=90)


def docker(*args: str, timeout: int = 60) -> str:
    return text(["docker", *args], timeout=timeout)


def record(state_path: Path, state: dict, name: str, started: float,
           outcome: str = "PASS", detail: str = "") -> None:
    elapsed_ms = round((time.monotonic() - started) * 1000)
    state.setdefault("stages", []).append({
        "name": name, "status": outcome, "elapsed_ms": elapsed_ms,
        **({"detail": detail} if detail else {}),
    })
    state["updated_at"] = now()
    save_json(state_path, state)
    print(f"STAGE {name}={outcome} elapsed_ms={elapsed_ms}"
          + (f" detail={detail}" if detail else ""), flush=True)


def run_stage(path: Path, state: dict, name: str, operation) -> None:
    start = time.monotonic()
    try:
        operation()
    except Exception as exc:
        record(path, state, name, start, "FAIL", type(exc).__name__)
        raise
    else:
        record(path, state, name, start)


def owns(kind: str, name: str, run: str) -> bool:
    forms = {"container": "inspect", "network": "network", "volume": "volume"}
    if kind not in forms:
        raise LabError("Unsupported Docker resource")
    if kind == "container":
        args = ["docker", "container", "inspect", "-f",
                f"{{{{index .Config.Labels \"{OWNER_LABEL}\"}}}}", name]
    else:
        args = ["docker", kind, "inspect", "-f",
                f"{{{{index .Labels \"{OWNER_LABEL}\"}}}}", name]
    result = cmd(args, check=False)
    if result.returncode:
        # A lost Docker connection, permission error, or daemon failure is
        # NOT evidence that the container is gone. Only a definite Docker
        # "no such" response proves resource absence, particularly after a
        # timed-out client subprocess was killed.
        failure = result.stderr.decode("utf-8", errors="replace").lower()
        if any(marker in failure for marker in (
            "no such object", "no such container", "no such network",
            "no such volume",
        )):
            return False
        # Docker Engine 29 returns "Error response from daemon: network
        # <exact name> not found" for a missing bridge, unlike volume and
        # container inspect, which return "No such ...". Match the exact
        # requested network name: unrelated daemon errors must fail closed.
        if kind == "network" and f"network {name.lower()} not found" in failure:
            return False
        raise LabError(f"Cannot verify Docker {kind} ownership: {name}")
    found = result.stdout.decode().strip()
    if found != run:
        raise LabError(f"Refusing to touch unowned {kind} {name}")
    return True


def names(run: str) -> dict[str, str]:
    return {
        "network": f"smt-net-{run}",
        "volume": f"smt-db-{run}",
        "ssh": f"smt-ssh-{run}",
        "mcp": f"smt-mcp-{run}",
    }


def stop_owned_client(run: str, client_name: str) -> None:
    """Never allow a daemon-managed test client to outlive its exec call.

    A subprocess.run timeout kills the Docker CLI but does NOT stop the
    container. Check exact ownership before each removal, then wait until
    the daemon confirms absence. Fail closed if removal cannot be verified.
    """
    if not client_name.startswith(f"smt-client-{valid_run(run)}-"):
        raise LabError("Refusing to stop a client outside the requested run")
    for _ in range(6):
        if not owns("container", client_name, run):
            return
        cmd(["docker", "rm", "-f", "-v", client_name], timeout=30, check=False)
        time.sleep(0.2)
    if owns("container", client_name, run):
        raise LabError(f"Timed-out test container is still present: {client_name}; cleanup required")


def ensure_no_orphan_clients(run: str) -> None:
    """Block another exec when a crashed session left a live test client."""
    for name in docker("ps", "-a", "--filter", "label=" + OWNER_LABEL + "=" + run,
                       "--format", "{{.Names}}").splitlines():
        if name.startswith(f"smt-client-{run}-"):
            if not owns("container", name, run):
                raise LabError(f"Test client ownership missing: {name}")
            raise LabError(f"Previous test client remains: {name}; explicit cleanup required")


def initial_containers() -> list[str]:
    return sorted(x for x in docker("ps", "--format", "{{.Names}}").splitlines()
                  if not x.startswith("smt-"))


def ensure_originals(state: dict) -> None:
    actual = set(initial_containers())
    missing = set(state["original_containers"]) - actual
    if missing:
        raise LabError("Original lab containers stopped or disappeared: " + ", ".join(sorted(missing)))


def checkout(state: dict) -> None:
    if not CACHE.is_dir() or git("rev-parse", "--is-bare-repository") != "true":
        raise LabError(f"Missing trusted bare repository cache: {CACHE}")
    if git("config", "--get", "remote.origin.url") != ORIGIN:
        raise LabError("Unexpected lab source origin")
    if git("config", "--get", "remote.origin.pushurl") != "disabled://lab-read-only":
        raise LabError("Lab Git cache is missing push-denial guard")
    sha = state["commit"]
    if git("cat-file", "-t", sha) != "commit":
        raise LabError("Requested SHA is not an available commit")
    worktree = Path(state["workspace"])
    worktree.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if worktree.exists():
        raise LabError(f"Worktree already exists: {worktree}")
    git("worktree", "add", "--detach", str(worktree), sha)
    if text(["git", "-C", str(worktree), "rev-parse", "HEAD"]) != sha:
        raise LabError("Exact checkout verification failed")


def fetch_target(state: dict, pr: int | None) -> None:
    # Require an exact reviewed commit, not a moving main branch.
    ref = (f"refs/pull/{pr}/head" if pr is not None else state["commit"])
    cmd(["git", "--git-dir", str(CACHE), "-c", "core.hooksPath=/dev/null",
         "fetch", "--no-tags", "origin", ref], timeout=180)
    if git("rev-parse", "FETCH_HEAD") != state["commit"]:
        raise LabError("Fetched GitHub commit differs from the approved SHA")


def build_image(state: dict, folder: Path) -> None:
    image = f"smt-mcp-{state['commit'][:12]}:local"
    state["image"] = image
    cmd(["docker", "build", "--progress=plain",
         "--label", IMAGE_LABEL + "=" + state["commit"],
         "-t", image, state["workspace"]],
        output=folder / "build.log", timeout=900)
    if docker("image", "inspect", image, "--format",
              f"{{{{index .Config.Labels \"{IMAGE_LABEL}\"}}}}") != state["commit"]:
        raise LabError("Local application image SHA label mismatch")
    state["image_id"] = docker("image", "inspect", image, "--format", "{{.Id}}")


def build_fixture(state: dict, folder: Path) -> None:
    fixture = RUNNER / "fixture"
    for required in ("Dockerfile", "entrypoint.sh"):
        if not (fixture / required).is_file():
            raise LabError(f"Trusted runner fixture missing: {required}")
    material = b"".join((fixture / x).read_bytes() for x in ("Dockerfile", "entrypoint.sh"))
    fixture_sha = hashlib.sha256(material).hexdigest()
    image = "smt-sshd-" + fixture_sha[:12] + ":local"
    state["fixture_image"] = image
    probe = cmd(["docker", "image", "inspect", image, "--format",
                 f"{{{{index .Config.Labels \"{FIXTURE_LABEL}\"}}}}"], check=False)
    if probe.returncode == 0:
        if probe.stdout.decode().strip() != fixture_sha:
            raise LabError("Cached fixture image does not match trusted runner")
        return
    cmd(["docker", "build", "--progress=plain", "--label", FIXTURE_LABEL + "=" + fixture_sha,
         "-t", image, str(fixture)], output=folder / "fixture-build.log", timeout=600)


def create_secrets(state: dict, folder: Path) -> None:
    private = folder / "secrets"
    private.mkdir(mode=0o700)
    cmd(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
         "disposable-ssh-mcp-mcp-lab", "-f", str(private / "identity")])
    inventory = {
        "version": 1,
        "hosts": [{
            "alias": "fixture", "address": "ssh-fixture", "port": 22,
            "username": "tester", "identity_file": "/run/ssh-mcp/identity",
            "known_hosts_file": "/run/ssh-mcp/known_hosts",
            "principals": ["ssh-mcp-operator"], "environment": "non-production",
            "access": state.get("access", "always-granted"),
            "privileged_access": state.get("privileged_access", "none"),
            "max_parallel": 1,
        }],
    }
    save_json(private / "inventory.json", inventory)
    if state.get("privileged_access", "none") != "none":
        # Generate only disposable per-run sudo credentials. The SSH fixture
        # receives the password via a single read-only file; the MCP service
        # receives it through its existing protected JSON path. Never put
        # this value in Docker argv, environment, logs or signed inventory.
        password = secrets.token_urlsafe(36)
        fd = os.open(private / "fixture-sudo-password",
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(password + "\n")
        (private / "protected").mkdir(mode=0o700)
        save_json(private / "protected" / "ssh-mcp-secrets",
                  {"sudo_passwords": {"fixture": password}})
    env = {
        "MCP_LOGIN_KEY": secrets.token_hex(32),
        "MCP_TOKEN_SIGNING_SECRET": secrets.token_hex(32),
        "MCP_ENVIRONMENT": "lab",
        "MCP_ISSUER": "http://localhost",
        "MCP_RESOURCE": "http://localhost/mcp",
        "MCP_CIMD_VALIDATE_REMOTE": "false",
        "MCP_ALLOWED_HOSTS": "localhost,localhost:*,127.0.0.1,127.0.0.1:*",
        "MCP_BIND_HOST": "0.0.0.0",
        "MCP_BIND_PORT": "8000",
        "MCP_SSH_TOOLS_ENABLED": "true",
        "SSH_EXECUTOR_ENABLED": "true",
        "SSH_JOBS_ENABLED": "true",
        "SSH_JOBS_DB": "/var/lib/ssh-mcp/jobs.sqlite",
        "SSH_INVENTORY_FILE": "/run/ssh-mcp/inventory.json",
        "SSH_APPROVED_ALIASES": "fixture",
    }
    if (state.get("access") == "restricted"
            or state.get("privileged_access", "none") != "none"):
        # Isolated test-only operator credentials, never reused by the
        # installed lab service or published to logs.
        env["HISTORY_VIEWER_ENABLED"] = "true"
        env["HISTORY_VIEWER_PASSWORD"] = secrets.token_hex(32)
    path = folder / "mcp.env"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        for key, value in env.items():
            handle.write(f"{key}={value}\n")


def start_resources(state: dict, folder: Path) -> None:
    run = state["run_id"]
    nn = state["names"]
    labels = ["--label", OWNER_LABEL + "=" + run,
              "--label", STORY_LABEL + "=" + state["story"]]
    docker("network", "create", "--internal", "--driver", "bridge", "--ipv6=false",
           "--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated",
           *labels, nn["network"])
    network = json.loads(docker("network", "inspect", nn["network"],
                                "--format", "{{json .}}"))
    if (network.get("Internal") is not True
            or network.get("EnableIPv6") is not False
            or network.get("Driver") != "bridge"
            or network.get("Options", {}).get(
                "com.docker.network.bridge.gateway_mode_ipv4") != "isolated"):
        raise LabError("Docker did not establish the required host-isolated IPv4-only bridge")
    docker("volume", "create", *labels, nn["volume"])
    key = (folder / "secrets" / "identity.pub").read_text(encoding="utf-8").strip()
    root_enabled = state.get("privileged_access", "none") != "none"
    fixture_sudo_mount = (
        ["--mount", "type=bind,source=" + str(folder / "secrets" / "fixture-sudo-password")
         + ",target=/run/fixture-sudo-password,readonly"] if root_enabled else []
    )
    docker("run", "-d", "--name", nn["ssh"], "--network", nn["network"],
           "--network-alias", "ssh-fixture", *labels, "--restart", "no",
           "--pids-limit", "128", "--memory", "256m",
           *fixture_sudo_mount, "--env", "SSH_AUTHORIZED_KEY=" + key,
           state["fixture_image"])
    for _ in range(40):
        probe = cmd(["docker", "exec", nn["ssh"], "sh", "-c",
                     "test -s /etc/ssh/ssh_host_ed25519_key.pub && pgrep -x sshd >/dev/null"],
                    check=False)
        if probe.returncode == 0:
            break
        time.sleep(0.2)
    else:
        raise LabError("Disposable SSH fixture never became ready")
    pub = docker("exec", nn["ssh"], "cat", "/etc/ssh/ssh_host_ed25519_key.pub")
    if not pub.startswith("ssh-ed25519 "):
        raise LabError("Unexpected disposable SSH host key")
    pinned = folder / "secrets" / "known_hosts"
    pinned.write_text("ssh-fixture " + pub + "\n", encoding="utf-8")
    os.chmod(pinned, 0o600)
    # Docker is the already-authorized lab privilege path; this helper is --rm.
    docker("run", "--rm", "--network", "none", "--user", "0:0",
           "--mount", "type=bind,source=" + str(folder / "secrets") + ",target=/cfg",
           "--entrypoint", "/usr/bin/chown", state["image"],
           "-R", "10001:10001", "/cfg", timeout=60)
    docker("run", "--rm", "--network", "none", "--user", "0:0",
           "--mount", "type=volume,source=" + nn["volume"] + ",target=/var/lib/ssh-mcp",
           "--entrypoint", "/usr/bin/chown", state["image"],
           "10001:10001", "/var/lib/ssh-mcp", timeout=60)
    docker("run", "-d", "--name", nn["mcp"], "--network", nn["network"],
           "--network-alias", "mcp", *labels, "--restart", "no",
           "--user", "10001:10001", "--read-only", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges:true",
           "--pids-limit", "128", "--memory", "512m",
           "--mount", "type=volume,source=" + nn["volume"] + ",target=/var/lib/ssh-mcp",
           "--mount", "type=bind,source=" + str(folder / "secrets")
           + ",target=/run/ssh-mcp,readonly",
           *(
               ["--mount", "type=bind,source=" + str(folder / "secrets" / "protected")
                + ",target=/run/secrets,readonly"] if root_enabled else []
           ),
           "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
           "--env-file", str(folder / "mcp.env"), state["image"])
    ready = False
    for _ in range(80):
        probe = cmd(["docker", "exec", nn["mcp"], "python", "-c",
                     "from urllib.request import urlopen; "
                     "assert urlopen('http://127.0.0.1:8000/ready',timeout=2).status == 200"],
                    check=False)
        if probe.returncode == 0:
            ready = True
            break
        time.sleep(0.2)
    if not ready:
        raise LabError("Disposable MCP never reached HTTP readiness")
    verify_host_isolation(nn["mcp"])
    result = docker(
        "exec", nn["mcp"], "ssh", "-F", "/dev/null", "-T", "-n",
        "-i", "/run/ssh-mcp/identity",
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=/run/ssh-mcp/known_hosts",
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ProxyCommand=none",
        "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
        "-o", "ConnectTimeout=5", "--", "tester@ssh-fixture", "id -un",
    )
    if result != "tester":
        raise LabError("Pinned SSH login into disposable fixture failed")


def verify_host_isolation(mcp_name: str) -> None:
    """Positive host-listener control and negative in-container reachability.

    Unlike a plain --internal bridge, gateway_mode_ipv4=isolated removes
    the host's bridge-side address. A live host TCP listener ensures a failed
    connection from the candidate is meaningful, not merely a closed port.
    No service endpoint is modified or queried beyond the TCP handshake.
    """
    host_ips: list[str] = []
    for candidate in text(["hostname", "-I"]).split():
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if isinstance(ip, ipaddress.IPv4Address) and not ip.is_loopback:
            host_ips.append(candidate)
    target: tuple[str, int] | None = None
    for address in host_ips:
        for port in (81, 80, 443):
            try:
                with socket.create_connection((address, port), timeout=0.25):
                    target = (address, port)
                    break
            except OSError:
                continue
        if target is not None:
            break
    if target is None:
        raise LabError("Host-isolation control unavailable: no reachable existing host TCP listener")
    probe = (
        "import socket,sys\n"
        "try:\n"
        "    sock=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=1)\n"
        "except OSError:\n"
        "    print('HOST_REACHABILITY_BLOCKED')\n"
        "else:\n"
        "    sock.close()\n"
        "    print('HOST_REACHABILITY_VIOLATION')\n"
        "    sys.exit(9)\n"
    )
    observed = docker("exec", mcp_name, "python", "-c", probe,
                      target[0], str(target[1]))
    if observed != "HOST_REACHABILITY_BLOCKED":
        raise LabError("MCP container unexpectedly reached a lab host listener")


def setup(args: argparse.Namespace) -> int:
    story, sha = valid_story(args.story), valid_sha(args.commit)
    trusted_runner_sha()
    with locked():
        if active_path().exists():
            old = load_json(active_path())
            raise LabError(f"Existing run {old.get('run_id')} must be cleaned up first")
        original = initial_containers()
        run = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)
        folder = run_folder(story, run)
        folder.mkdir(parents=True, mode=0o700)
        state = {
            "story": story, "run_id": run, "commit": sha,
            "pr": args.pr, "status": "provisioning", "started_at": now(),
            "access": getattr(args, "access", "always-granted"),
            "privileged_access": getattr(args, "privileged_access", "none"),
            "updated_at": now(), "stages": [], "tests": [],
            "workspace": str(WORKSPACES / story / run),
            "names": names(run), "original_containers": original,
        }
        state_path = folder / "state.json"
        save_json(state_path, state)
        save_json(active_path(), {"run_id": run, "story": story})
        try:
            run_stage(state_path, state, "github_fetch", lambda: fetch_target(state, args.pr))
            run_stage(state_path, state, "source_checkout", lambda: checkout(state))
            run_stage(state_path, state, "docker_build", lambda: build_image(state, folder))
            run_stage(state_path, state, "fixture_build", lambda: build_fixture(state, folder))
            run_stage(state_path, state, "synthetic_secrets", lambda: create_secrets(state, folder))
            run_stage(state_path, state, "isolated_runtime_ready", lambda: start_resources(state, folder))
            run_stage(state_path, state, "original_lab_services", lambda: ensure_originals(state))
            state["status"] = "active"
            save_json(state_path, state)
        except Exception as exc:
            state["status"] = "setup_failed"
            state["failure_kind"] = "BUILD_FAILURE" if state["stages"][-1]["name"] == "docker_build" else "INFRA_FAILURE"
            state["last_error"] = f"{type(exc).__name__}: {str(exc)[:280]}"
            save_json(state_path, state)
            print(f"SETUP=FAIL run_id={run} class={state['failure_kind']} "
                  f"reason={state['last_error']}; cleanup --run {run}", file=sys.stderr)
            return 1
        print(f"SETUP=PASS story={story} run_id={run} commit={sha} "
              f"image={state['image_id']} endpoint=http://mcp:8000 "
              f"network=internal-only")
        return 0


def read_secrets(path: Path) -> list[str]:
    env = path / "mcp.env"
    if not env.is_file():
        return []
    return [s.split("=", 1)[1].strip() for s in env.read_text().splitlines()
            if s.startswith(("MCP_LOGIN_KEY=", "MCP_TOKEN_SIGNING_SECRET=",
                             "HISTORY_VIEWER_PASSWORD="))]


def redact(text_value: str, secret_values: list[str]) -> str:
    for value in secret_values:
        if value:
            text_value = text_value.replace(value, "[REDACTED]")
    # Mask JWT-shaped tokens even if a story test accidentally logs one.
    return re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
                  "[REDACTED_TOKEN]", text_value)


def execute_test(args: argparse.Namespace) -> int:
    trusted_runner_sha()
    run = valid_run(args.run)
    argv = args.command
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        raise LabError("exec requires a test-client command after --")
    with locked():
        folder, state = locate(run)
        if state["status"] != "active":
            raise LabError("Run is not active; inspect status and cleanup/recreate")
        nn = state["names"]
        for key in ("network", "ssh", "mcp"):
            kind = "network" if key == "network" else "container"
            if not owns(kind, nn[key], run):
                raise LabError(f"Test resource disappeared: {nn[key]}")
        ensure_no_orphan_clients(run)
        index = len(state["tests"]) + 1
        output = folder / f"exec-{index:03d}.log"
        client_name = f"smt-client-{run}-{index}"
        docker_args = [
            "docker", "run", "--rm", "--name", client_name,
            "--network", nn["network"], "--label", OWNER_LABEL + "=" + run,
            "--label", STORY_LABEL + "=" + state["story"],
            "--restart", "no", "--user", f"{os.getuid()}:{os.getgid()}",
            "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--pids-limit", "128", "--memory", "512m",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "--mount", "type=bind,source=" + state["workspace"] + ",target=/source,readonly",
            "--mount", "type=bind,source=" + str(RUNNER) + ",target=/runner,readonly",
            "--workdir", "/source",
            "--env-file", str(folder / "mcp.env"),
            "--env", "SSH_MCP_TEST_URL=http://mcp:8000",
            "--env", "SSH_MCP_TEST_STORY=" + state["story"],
            "--env", "PYTHONPATH=/runner:/source",
            "--entrypoint", argv[0], state["image"], *argv[1:],
        ]
        started = time.monotonic()
        try:
            result = cmd(docker_args, output=output, timeout=args.timeout, check=False)
            rc = result.returncode
            reason = "TEST_FAILURE" if rc else "PASS"
        except subprocess.TimeoutExpired:
            rc = 124
            reason = "TEST_TIMEOUT"
        except KeyboardInterrupt:
            rc = 130
            reason = "TEST_INTERRUPTED"
        except Exception as exc:
            rc = 1
            reason = "INFRA_FAILURE"
            output.write_text(f"{type(exc).__name__}: {str(exc)[:200]}\n")
        finally:
            try:
                stop_owned_client(run, client_name)
            except Exception as exc:
                rc = 1
                reason = "INFRA_FAILURE"
                state["status"] = "client_cleanup_failed"
                state["last_error"] = "Test client termination not verified; explicit cleanup required"
                with output.open("a", encoding="utf-8") as log:
                    log.write(f"Cleanup failure: {type(exc).__name__}\n")
        # Restrict audit output and redact locally generated test credentials.
        raw = output.read_text(encoding="utf-8", errors="replace") if output.exists() else ""
        cleaned = redact(raw, read_secrets(folder))
        output.write_text(cleaned, encoding="utf-8")
        os.chmod(output, 0o600)
        elapsed = round((time.monotonic() - started) * 1000)
        state["tests"].append({
            "index": index, "command": argv,
            "status": reason, "exit_code": rc, "elapsed_ms": elapsed,
            "log": output.name, "timestamp": now(),
        })
        state["updated_at"] = now()
        save_json(folder / "state.json", state)
        print(f"TEST={reason} run_id={run} index={index} elapsed_ms={elapsed} "
              f"exit={rc} log={output}")
        for line in cleaned.splitlines():
            if line.startswith(("RESULT ", "SMOKE_SUMMARY ")):
                print(line)
        return 0 if rc == 0 else 1


def status(args: argparse.Namespace) -> int:
    initialize()
    if args.run:
        folder, state = locate(args.run)
    elif active_path().exists():
        selected = load_json(active_path())
        folder, state = locate(selected["run_id"])
    else:
        print("ACTIVE_RUN=none")
        return 0
    print(f"RUN_ID={state['run_id']} STORY={state['story']} "
          f"STATUS={state['status']} COMMIT={state['commit']} "
          f"STARTED={state['started_at']}")
    print(f"STATE_FILE={folder / 'state.json'} TESTS={len(state['tests'])}")
    for key, name in state["names"].items():
        kind = "volume" if key == "volume" else "network" if key == "network" else "container"
        try:
            present = owns(kind, name, state["run_id"])
            label = "present" if present else "missing"
        except LabError:
            label = "UNOWNED"
        print(f"RESOURCE {key}={label} name={name}")
    return 0


def results(args: argparse.Namespace) -> int:
    initialize()
    if args.run:
        folders = [locate(args.run)[0]]
    elif args.story:
        folders = sorted((p.parent for p in (RESULTS / valid_story(args.story)).glob("*/state.json")),
                         reverse=True)
    else:
        folders = sorted((p.parent for p in RESULTS.glob("*-*/*/state.json")), reverse=True)
    if not folders:
        print("RESULTS=none")
        return 0
    for folder in folders[:args.limit]:
        state = load_json(folder / "state.json")
        tests = state.get("tests", [])
        print(f"RUN={state['run_id']} STORY={state['story']} "
              f"STATUS={state['status']} COMMIT={state['commit'][:12]} "
              f"TESTS={len(tests)} PASSED={sum(x['status']=='PASS' for x in tests)} "
              f"FAILED={sum(x['status']!='PASS' for x in tests)} "
              f"REPORT={folder / 'state.json'}")
        for test in tests:
            print(f"  EXEC={test['index']} STATUS={test['status']} "
                  f"ELAPSED_MS={test['elapsed_ms']} LOG={folder / test['log']}")
    return 0


def cleanup(args: argparse.Namespace) -> int:
    trusted_runner_sha()
    with locked():
        folder, state = locate(args.run)
        run = state["run_id"]
        nn = state["names"]
        started = time.monotonic()
        # Never touch a resource unless its exact run ownership label matches.
        # Check predictable container names too, including names that would
        # be absent from a run-label-filtered listing after an ownership change.
        for expected in (nn["ssh"], nn["mcp"]):
            owns("container", expected, run)
        for name in docker("ps", "-a", "--filter", "label=" + OWNER_LABEL + "=" + run,
                           "--format", "{{.Names}}").splitlines():
            if not name.startswith("smt-") or not owns("container", name, run):
                raise LabError("Refusing to remove an unknown container")
            docker("rm", "-f", "-v", name)
        if owns("volume", nn["volume"], run):
            docker("volume", "rm", nn["volume"])
        if owns("network", nn["network"], run):
            docker("network", "rm", nn["network"])
        private = folder / "secrets"
        if private.exists():
            if (private.is_symlink() or private.parent != folder
                    or private.name != "secrets"):
                raise LabError("Refusing unsafe synthetic-key cleanup")
            # Files are owned by UID 10001, their parent is owned by gateway.
            # Limit this operation to the exact, validated run-owned directory.
            cmd(["sudo", "-n", "/bin/rm", "-rf", "--", str(private)])
        (folder / "mcp.env").unlink(missing_ok=True)
        ensure_originals(state)
        state["status"] = "cleaned"
        state["cleaned_at"] = now()
        elapsed = round((time.monotonic() - started) * 1000)
        record(folder / "state.json", state, "cleanup", started)
        if active_path().exists():
            active = load_json(active_path())
            if active.get("run_id") == run:
                active_path().unlink()
        print(f"CLEANUP=PASS run_id={run} elapsed_ms={elapsed} "
              "containers=0 network=removed volume=removed credentials=removed")
        return 0


def reconcile_cleanup(args: argparse.Namespace) -> int:
    """Retire a resource-free run blocked by unrelated original-container loss.

    This is NOT a successful preservation check and never invokes Docker
    deletion or touches original containers. The operator must acknowledge
    the exact observed missing names; retain the discrepancy in durable
    state as a warning rather than silently rewriting the original snapshot.
    """
    trusted_runner_sha()
    with locked():
        folder, state = locate(args.run)
        run = state["run_id"]
        active = active_path()
        if (active.is_symlink() or not active.is_file()
                or load_json(active) != {"story": state["story"], "run_id": run}):
            raise LabError("Refusing to reconcile a non-active or mismatched run")
        if state["status"] not in {"active", "setup_failed", "client_cleanup_failed"}:
            raise LabError("Only incomplete cleanup may be reconciled")
        if state["names"] != names(run):
            raise LabError("Run resource names do not match their namespace")

        # Check both predictable names and every resource with the run label.
        # A daemon failure or an occupied unowned name must fail closed.
        for key, name in state["names"].items():
            kind = "volume" if key == "volume" else (
                "network" if key == "network" else "container")
            if owns(kind, name, run):
                raise LabError(f"Run-owned {kind} remains; use normal cleanup")
        owner = "label=" + OWNER_LABEL + "=" + run
        if (docker("ps", "-a", "--filter", owner, "--format", "{{.Names}}")
                or docker("volume", "ls", "-q", "--filter", owner)
                or docker("network", "ls", "-q", "--filter", owner)):
            raise LabError("Run-labeled Docker resources remain; use normal cleanup")
        for path in (folder / "secrets", folder / "mcp.env"):
            if path.exists() or path.is_symlink():
                raise LabError("Run-private credentials remain; use normal cleanup")

        missing = sorted(set(state["original_containers"]) - set(initial_containers()))
        if not missing:
            raise LabError("Original containers are present; use normal cleanup")
        acknowledged = args.expect_missing_originals.split(",")
        if (len(acknowledged) != len(set(acknowledged))
                or sorted(acknowledged) != missing):
            raise LabError("Acknowledged original-container names do not match")

        started = time.monotonic()
        state["status"] = "cleaned_with_missing_originals"
        state["cleaned_at"] = now()
        state["cleanup_exception"] = {
            "kind": "original_containers_missing",
            "missing": missing,
        }
        record(folder / "state.json", state, "cleanup_reconciliation",
               started, outcome="WARNING", detail="originals_missing=" + ",".join(missing))
        active.unlink()
        print(f"RECONCILE=WARNING run_id={run} original_containers_missing="
              + ",".join(missing)
              + " resources=absent credentials=absent active_lock=released")
        return 0


def run_all(args: argparse.Namespace) -> int:
    start = time.monotonic()
    result = setup(args)
    if result:
        # setup itself preserves failed resources for diagnosis; the
        # convenience run command, unlike setup, always attempts cleanup.
        if active_path().exists():
            try:
                failed_run = load_json(active_path())["run_id"]
                cleanup(argparse.Namespace(run=failed_run))
            except Exception as exc:
                print(f"AUTOMATIC_CLEANUP=FAIL reason={type(exc).__name__}",
                      file=sys.stderr)
        return result
    active = load_json(active_path())
    run = active["run_id"]
    try:
        result = execute_test(argparse.Namespace(
            run=run, command=["python3", "/runner/smoke.py"],
            timeout=args.timeout,
        ))
    finally:
        try:
            cleanup(argparse.Namespace(run=run))
        except Exception as exc:
            print(f"AUTOMATIC_CLEANUP=FAIL run_id={run} reason={exc}", file=sys.stderr)
            result = 1
    print(f"FULL_RUN={'PASS' if result == 0 else 'FAIL'} "
          f"elapsed_ms={round((time.monotonic()-start)*1000)} run_id={run}")
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ssh-mcp-test",
        description="Trusted pinned-runner test orchestration; no application deployment.",
    )
    sub = parser.add_subparsers(dest="command_name", required=True)
    for name in ("setup", "run"):
        p = sub.add_parser(name)
        p.add_argument("--story", required=True)
        p.add_argument("--commit", required=True)
        p.add_argument("--pr", type=int, help="Optional PR number: fetch exact PR head, verify SHA")
        if name == "setup":
            p.add_argument("--access", default="always-granted",
                           choices=("always-granted", "restricted"),
                           help="Only the disposable SSH fixture's signed access policy")
            p.add_argument("--privileged-access", default="none",
                           choices=("none", "restricted", "always-granted"),
                           help="Only disposable fixture root policy; uses generated password")
        if name == "run":
            p.add_argument("--timeout", type=int, default=180)
    p = sub.add_parser("exec")
    p.add_argument("--run", required=True)
    p.add_argument("--timeout", type=int, default=900)
    p.add_argument("command", nargs=argparse.REMAINDER)
    p = sub.add_parser("cleanup")
    p.add_argument("--run", required=True)
    p = sub.add_parser("reconcile-cleanup")
    p.add_argument("--run", required=True)
    p.add_argument("--expect-missing-originals", required=True,
                   help="Comma-separated exact names from the original container snapshot")
    p = sub.add_parser("status")
    p.add_argument("--run")
    p = sub.add_parser("results")
    p.add_argument("--run")
    p.add_argument("--story")
    p.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()
    if args.command_name in ("setup", "run"):
        valid_story(args.story)
        valid_sha(args.commit)
        if args.pr is not None and not 1 <= args.pr <= 999999:
            parser.error("--pr must be a valid positive PR number")
    if args.command_name == "exec" and not 1 <= args.timeout <= 3600:
        parser.error("--timeout must be between 1 and 3600 seconds")
    return args


def main() -> int:
    os.umask(0o077)
    args = parse_args()
    try:
        return {
            "setup": setup,
            "run": run_all,
            "exec": execute_test,
            "status": status,
            "results": results,
            "cleanup": cleanup,
            "reconcile-cleanup": reconcile_cleanup,
        }[args.command_name](args)
    except (LabError, subprocess.TimeoutExpired, OSError, ValueError) as exc:
        print(f"LAB_RUNNER=FAIL {type(exc).__name__}: {str(exc)[:400]}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
