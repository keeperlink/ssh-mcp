"""Real SSH/MCP patch preview and nonmutation acceptance on disposable files.

Execute only through the separately installed, pinned runner.
"""
from __future__ import annotations

import hashlib
import os
import time

from client import LabClient

passed = 0
failed = 0


def check(label, fn):
    global passed, failed
    start = time.monotonic()
    try:
        value = fn()
    except Exception as exc:
        failed += 1
        print(f"RESULT {label}=FAIL ms={(time.monotonic()-start)*1000:.0f} "
              f"error={type(exc).__name__}: {str(exc)[:140]}", flush=True)
    else:
        passed += 1
        print(f"RESULT {label}=PASS ms={(time.monotonic()-start)*1000:.0f} "
              f"detail={value or 'ok'}", flush=True)


with LabClient() as client:
    client.authorize()

    def command(argv):
        wrapper, value = client.call("execute_command", client.execute_args(argv))
        assert not wrapper.get("isError") and value["status"] == "succeeded", value
        return value

    def create(name, content):
        command(["python3", "-c",
                 "import pathlib,sys;pathlib.Path('/home/tester/'+sys.argv[1]).write_text(sys.argv[2])",
                 name, content])

    def read(name):
        wrapper, value = client.call("read_file", {
            "server": "fixture", "reason": "TEST-248 verify synthetic source",
            "path": "/home/tester/" + name,
        })
        assert not wrapper.get("isError") and value["status"] == "succeeded", value
        return value["result"]["content"]

    def patch(body, *, preview=True, **options):
        return client.call("apply_patch", {
            "server": "fixture",
            "base_dir": "/home/tester", "reason": "TEST-248 preview acceptance",
            "story_id": os.environ["SSH_MCP_TEST_STORY"],
            "dry_run": preview,
            "atomic": True,
            "patch": "*** Begin Patch\n" + body + "*** End Patch",
            **options,
        })

    def edit(name, before, after, moved=None):
        return (f"*** Update File: {name}\n"
                + (f"*** Move to: {moved}\n" if moved else "")
                + f"@@\n-{before}\n+{after}\n")

    # Re-running against the same isolated SSH fixture must be deterministic.
    # Remove only synthetic files owned by this test (not fixture state,
    # helpers, credentials, or other story resources).
    command(["python3", "-c",
             "from pathlib import Path\n"
             "root=Path('/home/tester')\n"
             "names=('sky248-source.txt','sky248-delete.txt','sky248-move.txt',"
             "'sky248-added.txt','sky248-moved.txt','sky248-secret.txt',"
             "'sky248-prefix.txt','sky248-large-sparse.log')\n"
             "for name in names:\n"
             "    (root/name).unlink(missing_ok=True)\n"])

    create("sky248-source.txt", "first\nold\nthird\n")
    create("sky248-delete.txt", "to delete\n")
    create("sky248-move.txt", "migrate\n")
    source_sha = hashlib.sha256(b"first\nold\nthird\n").hexdigest()

    body = ("*** Add File: sky248-added.txt\n+added\n"
            + edit("sky248-source.txt", "old", "new")
            + "*** Delete File: sky248-delete.txt\n"
            + edit("sky248-move.txt", "migrate", "migrated",
                   moved="sky248-moved.txt"))

    batch_id = None

    def preview_four_actions():
        global batch_id
        wrapper, value = patch(
            body, include_sha256=True,
            expected_hashes={"sky248-source.txt": source_sha},
        )
        assert not wrapper.get("isError") and value["status"] == "succeeded", value
        result = value["result"]
        batch_id = value["operation_id"]
        assert result["dry_run"] and result["applicability"] == "applicable", result
        assert [s["status"] for s in result["outcomes"]] == ["applicable"] * 4, result
        assert result["summary"]["total_paths"] == 4, result
        assert result["summary"]["changed_paths"] == 4, result
        assert result["outcomes"][0]["prospective_sha256"] == hashlib.sha256(
            b"added\n").hexdigest(), result
        assert result["outcomes"][1]["before_sha256"] == source_sha, result
        assert read("sky248-source.txt") == "first\nold\nthird\n"
        assert read("sky248-delete.txt") == "to delete\n"
        assert read("sky248-move.txt") == "migrate\n"
        wrapper, checkfile = client.call(
            "execute_command",
            client.execute_args(["test", "!", "-e", "/home/tester/sky248-added.txt"]),
        )
        assert not wrapper.get("isError") and checkfile["status"] == "succeeded", checkfile
        return "all_four_advisory_and_unchanged"

    check("four_action_preview_no_mutation", preview_four_actions)

    def preview_audit_not_write():
        assert batch_id is not None
        wrapper, listing = client.call("list_jobs", {
            "story_id": os.environ["SSH_MCP_TEST_STORY"], "record_kind": "file",
            "limit": 40,
        })
        assert not wrapper.get("isError"), wrapper
        # History is metadata only; do not expose the source patch.
        matching = [event for event in listing["jobs"]
                    if event.get("id") == "file_" + batch_id]
        assert matching, listing
        assert matching[0]["operation_kind"] == "patch_preview", matching
        return "history_kind=patch_preview"

    check("preview_audited_as_preview", preview_audit_not_write)

    def no_op():
        wrapper, value = patch(edit("sky248-source.txt", "old", "old"))
        assert not wrapper.get("isError"), value
        assert value["result"]["outcomes"][0]["status"] == "unchanged", value
        assert value["result"]["summary"]["changed_paths"] == 0
        assert read("sky248-source.txt") == "first\nold\nthird\n"
        return "no_op_detected"

    check("preview_noop", no_op)

    def collision_is_rejected_before_any_edits():
        wrapper, value = patch(
            edit("sky248-source.txt", "old", "first")
            + edit("sky248-source.txt", "old", "second"),
        )
        assert wrapper.get("isError") and value["status"] == "failed", value
        result = value["result"]
        assert result["error"]["failure_kind"] == "overlapping_paths", result
        assert result["summary"]["changed_paths"] == 0, result
        assert read("sky248-source.txt") == "first\nold\nthird\n"
        return "overlap_rejected_without_change"

    check("duplicate_target_preflight", collision_is_rejected_before_any_edits)

    def invalid_hunk_does_not_mutate_earlier_path():
        wrapper, value = patch(
            edit("sky248-source.txt", "old", "hypothetical")
            + edit("sky248-move.txt", "missing", "changed"),
        )
        assert wrapper.get("isError") and value["status"] == "failed", value
        outcome = value["result"]["outcomes"]
        assert [s["status"] for s in outcome] == ["applicable", "failed"], outcome
        assert value["result"]["error"]["conflict"]["hunk"] == 1, value
        assert read("sky248-source.txt") == "first\nold\nthird\n"
        return "failed_later_path_preserves_original"

    check("later_hunk_rejection_no_changes", invalid_hunk_does_not_mutate_earlier_path)

    def authorized_diff_redacted():
        create("sky248-secret.txt", "password=SYNTHETIC_PRIVATE_VALUE\nold\n")
        wrapper, value = patch(
            edit("sky248-secret.txt", "old", "new"),
            include_diff=True, max_diff_bytes=2048,
        )
        assert not wrapper.get("isError") and value["status"] == "succeeded", value
        rendered = value["result"]["outcomes"][0]["diff"]
        assert "[REDACTED]" in rendered, rendered
        assert "SYNTHETIC_PRIVATE_VALUE" not in rendered, rendered
        assert "+new" in rendered, rendered
        assert read("sky248-secret.txt") == "password=SYNTHETIC_PRIVATE_VALUE\nold\n"
        return "bounded_authorized_diff_redacted"

    check("diff_opt_in_redaction", authorized_diff_redacted)

    def header_lookalike_diff_lines_are_redacted():
        original = "--password=SYNTHETIC_OLD_SECRET\n++token=SYNTHETIC_OLD_TOKEN\n"
        create("sky248-prefix.txt", original)
        body = ("*** Update File: sky248-prefix.txt\n@@\n"
                "---password=SYNTHETIC_OLD_SECRET\n"
                "+--password=SYNTHETIC_NEW_SECRET\n"
                "-++token=SYNTHETIC_OLD_TOKEN\n"
                "+++token=SYNTHETIC_NEW_TOKEN\n")
        wrapper, value = patch(body, include_diff=True, max_diff_bytes=2048)
        assert not wrapper.get("isError") and value["status"] == "succeeded", value
        snippet = value["result"]["outcomes"][0]["diff"]
        assert "-[REDACTED]" in snippet and "+[REDACTED]" in snippet, snippet
        for sensitive in ("SYNTHETIC_OLD_SECRET", "SYNTHETIC_NEW_SECRET",
                          "SYNTHETIC_OLD_TOKEN", "SYNTHETIC_NEW_TOKEN"):
            assert sensitive not in snippet, sensitive
        assert read("sky248-prefix.txt") == original
        return "header_lookalikes_redacted_no_mutation"

    check("header_lookalike_diff_redaction", header_lookalike_diff_lines_are_redacted)

    def large_delete_is_bounded_without_content_reads():
        # Sparse file in isolated synthetic SSH home: requires no large disk
        # allocation and must never materialize its 1 GiB logical contents.
        command(["python3", "-c",
                 "from pathlib import Path;"
                 "f=Path('/home/tester/sky248-large-sparse.log').open('wb');"
                 "f.truncate(1024**3);f.close()"])
        body = "*** Delete File: sky248-large-sparse.log\n"
        for opts in ({}, {"include_diff": True, "max_diff_bytes": 2048}):
            wrapper, value = patch(body, **opts)
            assert not wrapper.get("isError") and value["status"] == "succeeded", value
            result = value["result"]
            assert result["outcomes"][0]["status"] == "applicable", result
            assert result["summary"]["removed_lines"] is None, result
            assert result["summary"]["line_counts_complete"] is False, result
            assert "removed_lines" not in result["outcomes"][0], result
            if opts:
                assert result["outcomes"][0]["diff_truncated"] is True, result
                assert "diff" not in result["outcomes"][0], result
        wrapper, data = client.call(
            "execute_command",
            client.execute_args(["stat", "-c", "%s", "/home/tester/sky248-large-sparse.log"]),
        )
        assert not wrapper.get("isError") and data["status"] == "succeeded", data
        return "1GiB_sparse_delete_no_memory_materialization"

    check("large_delete_bounded_memory", large_delete_is_bounded_without_content_reads)

    def would_create_parent_without_mkdir():
        wrapper, value = patch(
            "*** Add File: sky248-absent-dir/child.txt\n+new\n",
            create_parents=True,
        )
        assert not wrapper.get("isError") and value["result"]["outcomes"][0]["status"] == "applicable", value
        wrapper, checkfile = client.call(
            "execute_command",
            client.execute_args(["test", "!", "-e", "/home/tester/sky248-absent-dir"]),
        )
        assert not wrapper.get("isError") and checkfile["status"] == "succeeded", checkfile
        return "preview_did_not_mkdir"

    check("create_parents_no_mutation", would_create_parent_without_mkdir)

    def stale_expected_hash_is_rejected():
        wrapper, value = patch(
            edit("sky248-source.txt", "old", "new"),
            expected_hashes={"sky248-source.txt": "f" * 64},
        )
        assert wrapper.get("isError") and value["status"] == "failed", value
        assert value["result"]["error"]["failure_kind"] == "hash_mismatch", value
        assert read("sky248-source.txt") == "first\nold\nthird\n"
        return "hash_precondition_checked_in_preview"

    check("stale_hash_preview_rejection", stale_expected_hash_is_rejected)

    def actual_apply_matches_preview():
        wrapper, value = patch(body, preview=False,
                               expected_hashes={"sky248-source.txt": source_sha})
        assert not wrapper.get("isError") and value["status"] == "succeeded", value
        assert read("sky248-source.txt") == "first\nnew\nthird\n"
        assert read("sky248-added.txt") == "added\n"
        assert read("sky248-moved.txt") == "migrated\n"
        wrapper, missing = client.call(
            "execute_command",
            client.execute_args(["test", "!", "-e", "/home/tester/sky248-delete.txt"]),
        )
        assert not wrapper.get("isError") and missing["status"] == "succeeded"
        return "real_apply_parity_and_success"

    check("apply_after_preview_reruns_preconditions", actual_apply_matches_preview)

    def real_host_is_denied():
        wrapper, _ = client.call("apply_patch", {
            "server": "demo-fixture", "reason": "TEST-248 isolated security test",
            "patch": "*** Begin Patch\n*** Add File: rejected.txt\n+no\n*** End Patch",
            "dry_run": True,
        })
        assert wrapper.get("isError"), wrapper
        return "unauthorized_host_denied"

    check("real_host_authorization_guard", real_host_is_denied)

print(f"SKY248_PR1_SUMMARY passed={passed} failed={failed} "
      f"story={os.environ.get('SSH_MCP_TEST_STORY','unknown')}", flush=True)
raise SystemExit(1 if failed else 0)
