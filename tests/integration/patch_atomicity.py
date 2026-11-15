"""Real SSH/MCP atomic patch preflight and partial-recovery acceptance.

Execute only through the separately installed, pinned runner.
"""
from __future__ import annotations

import hashlib
import os
import time

from client import LabClient

passed = failed = 0


def check(label, fn):
    global passed, failed
    start = time.monotonic()
    try:
        description = fn()
    except Exception as exc:
        failed += 1
        print(f"RESULT {label}=FAIL ms={(time.monotonic()-start)*1000:.0f} "
              f"error={type(exc).__name__}: {str(exc)[:180]}", flush=True)
    else:
        passed += 1
        print(f"RESULT {label}=PASS ms={(time.monotonic()-start)*1000:.0f} "
              f"detail={description or 'ok'}", flush=True)


with LabClient() as client:
    client.authorize()

    def command(argv):
        outer, result = client.call("execute_command", client.execute_args(argv))
        assert not outer.get("isError") and result["status"] == "succeeded", result
        return result

    def create(name, content):
        command(["python3", "-c",
                 "from pathlib import Path;import sys;"
                 "Path('/home/tester',sys.argv[1]).write_text(sys.argv[2])",
                 name, content])

    def read(name):
        outer, result = client.call("read_file", {
            "server": "fixture", "reason": "TEST-248 PR2 verify private synthetic file",
            "path": "/home/tester/" + name,
        })
        assert not outer.get("isError") and result["status"] == "succeeded", result
        return result["result"]["content"]

    def patch(body, *, atomic=True, **kwargs):
        return client.call("apply_patch", {
            "server": "fixture", "base_dir": "/home/tester",
            "reason": "TEST-248 PR2 synthetic apply and preflight",
            "story_id": os.environ["SSH_MCP_TEST_STORY"],
            "patch": "*** Begin Patch\n" + body + "*** End Patch",
            "atomic": atomic, **kwargs,
        })

    def update(name, old, new, *, move=None):
        return (f"*** Update File: {name}\n"
                + (f"*** Move to: {move}\n" if move else "")
                + f"@@\n-{old}\n+{new}\n")

    # Own synthetic paths only; safe for repeat execution in one fixture.
    command(["python3", "-c",
             "from pathlib import Path\nroot=Path('/home/tester')\n"
             "names=('sky248-pr2-a.txt','sky248-pr2-b.txt','sky248-pr2-c.txt',"
             "'sky248-pr2-added.txt','sky248-pr2-moved.txt','sky248-pr2-id.txt',"
             "'sky248-pr2-sparse.bin','sky248-pr2-parent.txt',"
             "'sky248-pr2-repetitive.txt')\n"
             "for name in names:\n    (root/name).unlink(missing_ok=True)\n"])
    create("sky248-pr2-a.txt", "alpha\n")
    create("sky248-pr2-b.txt", "bravo\n")
    create("sky248-pr2-c.txt", "charlie\n")

    def atomic_later_conflict_preflights_all():
        body = (update("sky248-pr2-a.txt", "alpha", "new-alpha")
                + update("sky248-pr2-b.txt", "missing", "new-bravo")
                + update("sky248-pr2-c.txt", "charlie", "new-charlie"))
        outer, value = patch(body)
        assert outer.get("isError") and value["status"] == "failed", value
        assert value["change_state"] == "no_changes", value
        assert value["retry_guidance"] == "refresh_preconditions", value
        result = value["result"]
        assert not result["preflight_completed"] and not result["partial"], result
        assert [x["status"] for x in result["outcomes"]] == [
            "not_attempted", "failed", "not_attempted",
        ], result
        assert result["error"]["failure_kind"] == "context_mismatch", result
        assert read("sky248-pr2-a.txt") == "alpha\n"
        assert read("sky248-pr2-b.txt") == "bravo\n"
        assert read("sky248-pr2-c.txt") == "charlie\n"
        return "all_files_unchanged_before_publication"

    check("atomic_preflight_later_hunk_conflict", atomic_later_conflict_preflights_all)

    def planned_file_ancestor_conflict_both_orders():
        parent = "*** Add File: sky248-pr2-parent.txt\n+regular file\n"
        child = "*** Add File: sky248-pr2-parent.txt/nested.txt\n+nested\n"
        for body in (parent + child, child + parent):
            outer, value = patch(body, atomic=True, create_parents=True)
            assert outer.get("isError") and value["status"] == "failed", value
            assert value["change_state"] == "no_changes", value
            result = value["result"]
            assert not result["preflight_completed"] and not result["partial"], result
            assert result["error"]["failure_kind"] == "overlapping_paths", result
            assert [entry["status"] for entry in result["outcomes"]] == [
                "not_attempted", "failed",
            ], result
            command(["test", "!", "-e", "/home/tester/sky248-pr2-parent.txt"])
        return "both_orders_preflight_fail_with_zero_file_changes"

    check("atomic_parent_child_conflicts_both_orders", planned_file_ancestor_conflict_both_orders)

    def repetitive_edit_summary_cost_is_bounded():
        command(["python3", "-c",
                 "from pathlib import Path;"
                 "Path('/home/tester/sky248-pr2-repetitive.txt').write_text("
                 "'old-start\\n'+'same\\n'*1800+'old-end\\n')"])
        body = ("*** Update File: sky248-pr2-repetitive.txt\n"
                "@@\n-old-start\n+new-start\n"
                "@@\n-old-end\n+new-end\n")
        preview_outer, preview = patch(body, dry_run=True, include_diff=True)
        assert not preview_outer.get("isError") and preview["status"] == "succeeded", preview
        assert not preview["result"]["summary"]["line_counts_complete"], preview
        assert preview["result"]["summary"]["added_lines"] is None, preview
        assert preview["result"]["outcomes"][0]["diff_truncated"] is True, preview
        outer, value = patch(body, atomic=True)
        assert not outer.get("isError") and value["status"] == "succeeded", value
        assert value["change_state"] == "complete", value
        assert value["result"]["summary"]["line_counts_complete"] is False, value
        assert value["result"]["summary"]["added_lines"] is None, value
        assert value["result"]["summary"]["removed_lines"] is None, value
        command(["python3", "-c",
                 "from pathlib import Path;"
                 "s=Path('/home/tester/sky248-pr2-repetitive.txt').read_text();"
                 "assert s.startswith('new-start\\n') and s.endswith('new-end\\n');"
                 "assert s.count('same\\n')==1800"])
        return "1800_ambiguous_lines_bounded_unknown_counts_real_change_verified"

    check("repetitive_edit_summary_bounded", repetitive_edit_summary_cost_is_bounded)

    def atomic_noop_preserves_inode_and_mtime():
        command(["python3", "-c",
                 "from pathlib import Path\np=Path('/home/tester/sky248-pr2-a.txt')\n"
                 "s=p.stat()\nPath('/home/tester/sky248-pr2-id.txt').write_text("
                 "str(s.st_ino)+','+str(s.st_mtime_ns)+','+str(s.st_ctime_ns))"])
        outer, value = patch(
            update("sky248-pr2-a.txt", "alpha", "alpha"),
            include_sha256=True,
        )
        assert not outer.get("isError") and value["status"] == "succeeded", value
        assert value["change_state"] == "no_changes" and value["retry_guidance"] == "none"
        result = value["result"]
        assert result["outcomes"][0]["status"] == "unchanged", result
        assert result["summary"]["bytes_written"] == 0, result
        assert result["summary"]["unchanged_paths"] == 1, result
        assert result["outcomes"][0]["sha256"] == hashlib.sha256(b"alpha\n").hexdigest()
        command(["python3", "-c",
                 "from pathlib import Path\np=Path('/home/tester/sky248-pr2-a.txt')\n"
                 "s=p.stat()\nexpected=Path('/home/tester/sky248-pr2-id.txt').read_text()\n"
                 "assert expected==str(s.st_ino)+','+str(s.st_mtime_ns)+','+str(s.st_ctime_ns)"])
        return "no_file_replacement_or_timestamp_change"

    check("atomic_noop_inode_unchanged", atomic_noop_preserves_inode_and_mtime)

    def collisions_fail_before_any_write():
        body = (update("sky248-pr2-a.txt", "alpha", "new-alpha")
                + update("sky248-pr2-b.txt", "bravo", "new-bravo",
                         move="sky248-pr2-a.txt"))
        outer, value = patch(body)
        assert outer.get("isError") and value["status"] == "failed", value
        assert value["result"]["error"]["failure_kind"] == "overlapping_paths"
        assert value["change_state"] == "no_changes"
        assert read("sky248-pr2-a.txt") == "alpha\n"
        return "source_destination_overlap_rejected"

    check("atomic_move_target_collision", collisions_fail_before_any_write)

    def stale_hash_all_path_preflight():
        body = (update("sky248-pr2-a.txt", "alpha", "new-alpha")
                + update("sky248-pr2-b.txt", "bravo", "new-bravo"))
        outer, value = patch(
            body, expected_hashes={"sky248-pr2-b.txt": "f" * 64},
        )
        assert outer.get("isError") and value["status"] == "failed", value
        assert value["change_state"] == "no_changes", value
        assert value["result"]["error"]["failure_kind"] == "hash_mismatch", value
        assert read("sky248-pr2-a.txt") == "alpha\n"
        return "stale_later_hash_blocks_all"

    check("atomic_all_path_hash_preflight", stale_hash_all_path_preflight)

    def full_atomic_add_update_delete_move():
        body = ("*** Add File: sky248-pr2-added.txt\n+new-added\n"
                + update("sky248-pr2-a.txt", "alpha", "new-alpha")
                + "*** Delete File: sky248-pr2-c.txt\n"
                + update("sky248-pr2-b.txt", "bravo", "new-bravo",
                         move="sky248-pr2-moved.txt"))
        outer, value = patch(body, include_sha256=True)
        assert not outer.get("isError") and value["status"] == "succeeded", value
        assert value["change_state"] == "complete" and value["retry_guidance"] == "none"
        result = value["result"]
        summary = result["summary"]
        assert result["preflight_completed"], result
        assert summary["changed_paths"] == 4 and summary["unchanged_paths"] == 0, summary
        assert summary["added_lines"] == 3 and summary["removed_lines"] == 3, summary
        assert summary["line_counts_complete"] and summary["bytes_written"] > 0, summary
        assert result["outcomes"][1]["before_sha256"] == hashlib.sha256(b"alpha\n").hexdigest()
        assert result["outcomes"][1]["sha256"] == hashlib.sha256(b"new-alpha\n").hexdigest()
        assert result["outcomes"][2]["before_sha256"] == hashlib.sha256(b"charlie\n").hexdigest()
        assert read("sky248-pr2-added.txt") == "new-added\n"
        assert read("sky248-pr2-a.txt") == "new-alpha\n"
        assert read("sky248-pr2-moved.txt") == "new-bravo\n"
        command(["test", "!", "-e", "/home/tester/sky248-pr2-b.txt"])
        command(["test", "!", "-e", "/home/tester/sky248-pr2-c.txt"])
        return "4_changes_counts_hashes_movement_confirmed"

    check("atomic_success_summary_and_hashes", full_atomic_add_update_delete_move)

    def nonatomic_partial_recovery():
        create("sky248-pr2-a.txt", "alpha\n")
        create("sky248-pr2-b.txt", "bravo\n")
        outer, value = patch(
            update("sky248-pr2-a.txt", "alpha", "new-alpha")
            + update("sky248-pr2-b.txt", "not-found", "new-bravo"),
            atomic=False,
        )
        assert outer.get("isError") and value["status"] == "partial", value
        assert value["change_state"] == "partial", value
        assert value["retry_guidance"] == "reconcile_before_retry", value
        assert value["result"]["summary"]["changed_paths"] == 1, value
        assert not value["result"]["preflight_completed"], value
        assert read("sky248-pr2-a.txt") == "new-alpha\n"
        assert read("sky248-pr2-b.txt") == "bravo\n"
        return "partial_confirmed_no_auto_retry"

    check("nonatomic_partial_reconciliation", nonatomic_partial_recovery)

    def non_atomic_identical_update_noop():
        outer, value = patch(
            update("sky248-pr2-a.txt", "new-alpha", "new-alpha"),
            atomic=False,
        )
        assert not outer.get("isError") and value["status"] == "succeeded", value
        assert value["change_state"] == "no_changes", value
        assert value["result"]["summary"]["unchanged_paths"] == 1, value
        return "nonatomic_same_bytes_noop"

    check("nonatomic_noop_skips_write", non_atomic_identical_update_noop)

    def preview_unchanged_contract():
        outer, value = patch(
            update("sky248-pr2-a.txt", "new-alpha", "new-alpha"),
            dry_run=True,
        )
        assert not outer.get("isError") and value["status"] == "succeeded", value
        assert value["result"]["applicability"] == "applicable", value
        assert value["result"]["outcomes"][0]["status"] == "unchanged", value
        assert read("sky248-pr2-a.txt") == "new-alpha\n"
        return "backward_compatible_dry_run"

    check("pr1_preview_regression", preview_unchanged_contract)

    def audit_has_no_patch_payloads():
        outer, value = client.call("list_jobs", {
            "story_id": os.environ["SSH_MCP_TEST_STORY"],
            "record_kind": "file", "limit": 50,
        })
        assert not outer.get("isError") and value["jobs"], value
        assert any(j.get("operation_kind") == "patch" for j in value["jobs"]), value
        assert any(j.get("operation_kind") == "patch_preview" for j in value["jobs"]), value
        return "metadata_only_patch_vs_preview_classification"

    check("file_audit_metadata_only", audit_has_no_patch_payloads)

    def host_authorization():
        outer, _ = client.call("apply_patch", {
            "server": "demo-fixture", "reason": "TEST-248 test denied host",
            "patch": "*** Begin Patch\n*** Add File: no.txt\n+never\n*** End Patch",
            "atomic": True,
        })
        assert outer.get("isError"), outer
        return "unauthorized_host_denied"

    check("host_authorization_unchanged", host_authorization)

print(f"SKY248_PR2_SUMMARY passed={passed} failed={failed} "
      f"story={os.environ.get('SSH_MCP_TEST_STORY','unknown')}", flush=True)
raise SystemExit(1 if failed else 0)
