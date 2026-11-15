"""Real SSH/MCP patch-conflict diagnostics against disposable fixture files.

Execute only through the separately installed, pinned runner.
"""
from __future__ import annotations

import json
import os
import time

from client import LabClient

passed = 0
failed = 0


def case(name, fn):
    global passed, failed
    start = time.monotonic()
    try:
        detail = fn()
    except Exception as exc:
        failed += 1
        print(f"RESULT {name}=FAIL ms={1000*(time.monotonic()-start):.0f} "
              f"error={type(exc).__name__}: {str(exc)[:140]}", flush=True)
    else:
        passed += 1
        print(f"RESULT {name}=PASS ms={1000*(time.monotonic()-start):.0f} "
              f"detail={detail or 'ok'}", flush=True)


with LabClient() as client:
    client.authorize()

    def command(argv):
        wrapper, value = client.call("execute_command", client.execute_args(argv))
        assert not wrapper.get("isError") and value["status"] == "succeeded", value
        return value

    def write(name, content):
        command(["python3", "-c", "import pathlib,sys;"
                 "pathlib.Path(sys.argv[1]).write_text(sys.argv[2])",
                 "/home/tester/" + name, content])

    def read(name):
        wrapper, value = client.call("read_file", {
            "server": "fixture", "reason": "TEST-247 verify synthetic patch file",
            "path": "/home/tester/" + name,
        })
        assert not wrapper.get("isError") and value["status"] == "succeeded", value
        return value["result"]["content"]

    def apply(body, **kwargs):
        patch = "*** Begin Patch\n" + body + "*** End Patch"
        return client.call("apply_patch", {
            "server": "fixture", "reason": "TEST-247 synthetic patch diagnostic",
            "story_id": os.environ["SSH_MCP_TEST_STORY"],
            "base_dir": "/home/tester", "atomic": True,
            "patch": patch, **kwargs,
        })

    def update(name, before, after):
        return f"*** Update File: {name}\n@@\n-{before}\n+{after}\n"

    def missing_context():
        write("pr3-stale.txt", "first\nsecond\nthird\n")
        w, value = apply(update("pr3-stale.txt", "not-in-file", "changed"))
        assert w.get("isError") and value["status"] == "failed", value
        result = value["result"]
        assert not result["partial"] and result["bytes"] == 0, result
        assert result["error"]["failed_path"].endswith("pr3-stale.txt"), result
        assert result["error"]["failure_kind"] == "context_mismatch", result
        detail = result["error"]["conflict"]
        assert detail["hunk"] == 1 and detail["line_hint"] == 1, detail
        assert detail["expected_context"] == ["not-in-file"], detail
        assert detail["actual_excerpt"][0] == {"line": 1, "text": "first"}, detail
        assert read("pr3-stale.txt") == "first\nsecond\nthird\n"
        return "hunk1_read_authorized_and_no_mutation"

    case("missing_context_with_line_numbers", missing_context)

    def second_hunk_after_insertion_uses_actual_disk_lines():
        write("pr3-multihunk.txt", "first\nsecond\nthird\nfourth\n")
        body = ("*** Update File: pr3-multihunk.txt\n"
                "@@\n-first\n+invented-first\n+invented-second\n"
                "@@\n-does-not-match\n+changed\n")
        wrapper, value = apply(body)
        assert wrapper.get("isError") and value["status"] == "failed", value
        conflict = value["result"]["error"]["conflict"]
        assert conflict["failure_kind"] == "context_mismatch", conflict
        assert conflict["hunk"] == 2 and conflict["line_hint"] == 2, conflict
        assert conflict["actual_excerpt"][0] == {"line": 2, "text": "second"}, conflict
        assert conflict["actual_excerpt"][1] == {"line": 3, "text": "third"}, conflict
        assert "invented-" not in json.dumps(value), value
        assert read("pr3-multihunk.txt") == "first\nsecond\nthird\nfourth\n"
        return "original_line2=second, no_in_memory_excerpts"

    case("second_hunk_after_insertion_original_lines", second_hunk_after_insertion_uses_actual_disk_lines)

    def second_hunk_after_deletion_uses_actual_disk_lines():
        write("pr3-multihunk.txt", "first\nsecond\nthird\nfourth\n")
        body = ("*** Update File: pr3-multihunk.txt\n"
                "@@\n-first\n-second\n"
                "@@\n-missing-after-delete\n+changed\n")
        wrapper, value = apply(body)
        assert wrapper.get("isError") and value["status"] == "failed", value
        conflict = value["result"]["error"]["conflict"]
        assert conflict["failure_kind"] == "context_mismatch", conflict
        assert conflict["hunk"] == 2 and conflict["line_hint"] == 3, conflict
        assert conflict["actual_excerpt"][0] == {"line": 3, "text": "third"}, conflict
        assert read("pr3-multihunk.txt") == "first\nsecond\nthird\nfourth\n"
        return "original_line3=third, unchanged_file"

    case("second_hunk_after_deletion_original_lines", second_hunk_after_deletion_uses_actual_disk_lines)

    def hash_precondition():
        w, value = apply(
            update("pr3-stale.txt", "first", "changed"),
            expected_hashes={"pr3-stale.txt": "f" * 64},
        )
        assert w.get("isError") and value["status"] == "failed", value
        error = value["result"]["error"]
        assert error["code"] == "precondition_failed", error
        assert error["failure_kind"] == "hash_mismatch", error
        assert error["conflict"]["actual_excerpt"] == [], error
        assert read("pr3-stale.txt") == "first\nsecond\nthird\n"
        return "hash_mismatch_without_file_excerpt"

    case("hash_conflict_and_no_mutation", hash_precondition)

    def missing_section():
        body = "*** Update File: pr3-stale.txt\n@@ this-section-not-present\n-first\n+changed\n"
        w, value = apply(body)
        assert w.get("isError") and value["status"] == "failed", value
        detail = value["result"]["error"]["conflict"]
        assert detail["failure_kind"] == "missing_section" and detail["hunk"] == 1, detail
        assert read("pr3-stale.txt") == "first\nsecond\nthird\n"
        return "missing_section_hunk1"

    case("section_anchor_diagnostic", missing_section)

    def sensitive_context_redacted():
        write("pr3-sensitive.txt",
              "password=synthetic-supersecret-value\nsafe line\n"
              "Authorization: Bearer synthetic-private-value\n")
        w, value = apply(update("pr3-sensitive.txt",
                                "token=synthetic-input-secret", "changed"))
        assert w.get("isError") and value["status"] == "failed", value
        detail = value["result"]["error"]["conflict"]
        assert detail["expected_context"] == ["[REDACTED]"], detail
        assert detail["actual_excerpt"][0]["text"] == "[REDACTED]", detail
        result_json = json.dumps(value)
        for secret in ("synthetic-supersecret-value", "synthetic-private-value",
                       "synthetic-input-secret"):
            assert secret not in result_json, secret
        return "expected_and_actual_redacted"

    case("sensitive_excerpt_redaction", sensitive_context_redacted)

    def partial_no_rollback():
        write("pr3-early.txt", "old\n")
        write("pr3-later.txt", "untouched\n")
        body = (update("pr3-early.txt", "old", "updated")
                + update("pr3-stale.txt", "missing", "changed")
                + update("pr3-later.txt", "untouched", "changed"))
        w, value = apply(body)
        assert w.get("isError") and value["status"] == "partial", value
        result = value["result"]
        assert result["partial"] is True, result
        assert [x["status"] for x in result["outcomes"]] == [
            "applied", "failed", "not_attempted"], result
        assert result["error"]["failure_kind"] == "context_mismatch", result
        assert read("pr3-early.txt") == "updated\n"
        assert read("pr3-stale.txt") == "first\nsecond\nthird\n"
        assert read("pr3-later.txt") == "untouched\n"
        return "earlier_applied_later_not_attempted"

    case("partial_multi_file_truthful", partial_no_rollback)

    def no_excerpts_for_unreadable_path():
        write("pr3-unreadable.txt", "private value\n")
        command(["chmod", "0200", "/home/tester/pr3-unreadable.txt"])
        w, value = apply(update("pr3-unreadable.txt", "absent", "changed"))
        assert w.get("isError") and value["status"] == "failed", value
        error = value["result"]["error"]
        assert error["failure_kind"] == "permission_denied", error
        assert error.get("conflict") is None, error
        command(["chmod", "0600", "/home/tester/pr3-unreadable.txt"])
        return "permission_denied_with_no_actual_excerpt"

    case("unreadable_target_does_not_leak", no_excerpts_for_unreadable_path)

    def successful_patch_still_works():
        w, value = apply(update("pr3-stale.txt", "second", "updated"))
        assert not w.get("isError") and value["status"] == "succeeded", value
        assert read("pr3-stale.txt") == "first\nupdated\nthird\n"
        return "successful_patch_unchanged"

    case("existing_patch_success_backward_compatible", successful_patch_still_works)

    def no_real_host_access():
        w, _ = client.call("apply_patch", {
            "server": "demo-fixture",
            "reason": "TEST-247 synthetic denied host",
            "patch": "*** Begin Patch\n*** Add File: denied.txt\n+bad\n*** End Patch",
        })
        assert w.get("isError"), w
        return "real_lab_host_unavailable"

    case("real_host_authorization_guard", no_real_host_access)

print(f"PR3_SUMMARY passed={passed} failed={failed} "
      f"story={os.environ.get('SSH_MCP_TEST_STORY','unknown')}", flush=True)
raise SystemExit(1 if failed else 0)
