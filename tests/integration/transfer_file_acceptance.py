"""Real, synthetic two-host SSH-MCP relay acceptance in a pinned isolated LAB.

Must execute only from the reviewed ssh-mcp-test --dual-host runner. All file
contents, SSH identities and sudo secrets are generated for this run only.
"""
from __future__ import annotations

import argparse
import time

from client import LabClient
from tests.integration._lab_env import lab_story

parser = argparse.ArgumentParser()
parser.add_argument("--privileged", action="store_true")
args = parser.parse_args()
story = lab_story()
source = "/root/synthetic-relay-source" if args.privileged else "/home/tester/synthetic-relay-source"
destination = "/root/synthetic-relay-target" if args.privileged else "/home/tester/synthetic-relay-target"
extra = "/root/synthetic-relay-extra" if args.privileged else "/home/tester/synthetic-relay-extra"


def check(name: str, detail: str = "") -> None:
    print(f"RESULT transfer_{name}=PASS" +
          (f" detail={detail}" if detail else ""), flush=True)


with LabClient() as client:
    client.authorize()

    def command(alias: str, code: str, *, root: bool = False):
        result, data = client.call("execute_command", {
            **client.execute_args(["python3", "-c", code], privileged=root),
            "server": alias,
        })
        if result.get("isError") or not data or data.get("status") != "succeeded":
            raise AssertionError(f"SSH fixture command failed on {alias}: {data}")
        return data.get("stdout", "").strip()

    def transfer(**options):
        request = {
            "source_server": "fixture", "source_path": source,
            "dest_server": "fixture-dest", "dest_path": destination,
            "source_privileged": args.privileged,
            "dest_privileged": args.privileged,
            "reason": "Isolated two-host LAB acceptance, synthetic bytes only",
            "story_id": story, "wait_seconds": 30, "timeout_seconds": 180,
            **options,
        }
        return client.call("transfer_file", request)

    def poll(result, data):
        if not data or "status" not in data:
            raise AssertionError(f"Malformed transfer response: {data}")
        if data["status"] != "running":
            return data["status"], data.get("history_id")
        identifier = data["history_id"]
        deadline = time.monotonic() + 165
        while time.monotonic() < deadline:
            response, saved = client.call("get_job", {"job_id": identifier})
            if response.get("isError") or not saved or "job" not in saved:
                raise AssertionError("Lost durable relay job")
            current = saved["job"]["status"]
            if current not in {"running", "awaiting_approval"}:
                return current, identifier
            time.sleep(0.25)
        raise AssertionError("Synthetic relay never reached a terminal state")

    def digest(alias: str, path: str, *, root: bool = False) -> str:
        script = (
            "from pathlib import Path; import hashlib,stat; "
            f"p=Path({path!r}); s=p.stat(); "
            "assert stat.S_ISREG(s.st_mode) and (s.st_mode & 0o777)==0o600; "
            f"assert {'s.st_uid==0' if root else 's.st_uid==1000'}; "
            "print(hashlib.sha256(p.read_bytes()).hexdigest())"
        )
        return command(alias, script, root=root)

    def materialize(path: str, seed: int, *, size: int = 131081):
        script = (
            "from pathlib import Path; import hashlib; "
            f"p=Path({path!r}); "
            f"data=(bytes(range(256))*{size // 256 + 1})[:{size}]; "
            f"data=bytes(x^{seed} for x in data); "
            "p.write_bytes(data); p.chmod(0o600); "
            "print(hashlib.sha256(data).hexdigest())"
        )
        return command("fixture", script, root=args.privileged)

    # Distinct host connections with two pinned host keys, different file
    # namespaces, and separately authorized source/destination aliases.
    sha = materialize(source, 7)
    envelope, data = transfer(source_sha256=sha)
    status, history_id = poll(envelope, data)
    assert not envelope.get("isError") and status == "succeeded", data
    assert digest("fixture-dest", destination, root=args.privileged) == sha
    check("two_host_binary_integrity", "size=131081 root=" + str(args.privileged))

    # The durable result must not include file bytes or absolute source paths.
    assert history_id
    response, saved = client.call("get_job", {"job_id": history_id})
    assert not response.get("isError") and saved
    audit = str(saved)
    assert "/home/tester/synthetic-relay-source" not in audit
    assert "/root/synthetic-relay-source" not in audit
    assert "bytes(range(256))" not in audit
    for alias in ("fixture", "fixture-dest"):
        response, listing = client.call("list_jobs", {
            "host": alias, "record_kind": "file", "time_range": "all",
        })
        assert not response.get("isError") and listing
        assert any(job.get("id") == history_id for job in listing.get("jobs", []))
    check("metadata_only_dual_host_audit")

    # Create is fail closed; both source mismatch and a stale destination
    # preimage must leave existing destination bytes unchanged.
    bad, wrong = transfer(source_sha256="0" * 64,
                          dest_path=extra)
    state, _ = poll(bad, wrong)
    assert state == "failed", wrong
    collided, collision_data = transfer()
    state, _ = poll(collided, collision_data)
    assert state == "failed", collision_data
    assert digest("fixture-dest", destination, root=args.privileged) == sha
    check("create_collision_source_preconditions")

    sha_next = materialize(source, 21, size=131081)
    wrong, wrong_data = transfer(
        mode="overwrite", expected_sha256="0" * 64, source_sha256=sha_next,
    )
    state, _ = poll(wrong, wrong_data)
    assert state == "failed", wrong_data
    assert digest("fixture-dest", destination, root=args.privileged) == sha
    good, complete = transfer(
        mode="overwrite", expected_sha256=sha, source_sha256=sha_next,
    )
    state, _ = poll(good, complete)
    assert state == "succeeded", complete
    assert digest("fixture-dest", destination, root=args.privileged) == sha_next
    check("atomic_verified_overwrite")

    invalid, _ = client.call("transfer_file", {
        "source_server": "fixture", "dest_server": "fixture",
        "source_path": source, "dest_path": destination,
        "reason": "Reject same-host request", "story_id": story,
    })
    assert invalid.get("isError"), "Same-host request was not rejected"
    invalid, _ = client.call("transfer_file", {
        "source_server": "fixture", "dest_server": "production",
        "source_path": source, "dest_path": destination,
        "reason": "Reject non-fixture host", "story_id": story,
    })
    assert invalid.get("isError"), "Undeclared host was not rejected"
    check("unapproved_host_rejected")

    if not args.privileged:
        # Deliberately async: cancel before final commit where possible. Any
        # uncertain outcome must remain uncertain, not falsely guaranteed.
        cancel_sha = materialize(source, 31, size=16 * 1024 * 1024)
        queued, active = transfer(
            source_sha256=cancel_sha, dest_path=extra,
            wait_seconds=0,
        )
        assert not queued.get("isError") and active and active["status"] == "running"
        command_response, outcome = client.call("cancel_job", {
            "job_id": active["history_id"],
            "reason": "Synthetic LAB cancellation acceptance",
        })
        assert not command_response.get("isError") and outcome
        state, _ = poll(queued, active)
        assert state in {"cancelled", "unknown", "succeeded"}, state
        if state == "succeeded":
            assert digest("fixture-dest", extra) == cancel_sha
        if state == "cancelled":
            missing = command("fixture-dest", (
                "from pathlib import Path; "
                f"print(not Path({extra!r}).exists())"
            ))
            assert missing == "True"
        check("async_cancellation_conservative", "status=" + state)

    check("complete", "privileged=" + str(args.privileged))
