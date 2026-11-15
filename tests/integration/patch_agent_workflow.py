"""End-to-end source, tests and documentation patch workflow over real SSH.

Runs with a disposable fixture and the separately reviewed, pinned lab runner.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid

from client import LabClient

passed = failed = 0


def check(label, fn):
    global passed, failed
    start = time.monotonic()
    try:
        detail = fn()
    except Exception as exc:
        failed += 1
        print(f"RESULT {label}=FAIL ms={(time.monotonic()-start)*1000:.0f} "
              f"error={type(exc).__name__}: {str(exc)[:190]}", flush=True)
    else:
        passed += 1
        print(f"RESULT {label}=PASS ms={(time.monotonic()-start)*1000:.0f} "
              f"detail={detail or 'ok'}", flush=True)


ROOT = "/home/tester/agent-patch-workflow"
OLD_SOURCE = (
    'def greeting(name: str) -> str:\n'
    '    return f"Hello, {name}!"\n'
)
NEW_SOURCE = OLD_SOURCE.replace("Hello", "Welcome")
OLD_TEST = (
    "import unittest\n\n"
    "from greeting import greeting\n\n\n"
    "class GreetingTest(unittest.TestCase):\n"
    "    def test_greeting(self):\n"
    '        self.assertEqual(greeting("MCP"), "Hello, MCP!")\n'
)
NEW_TEST = OLD_TEST.replace("Hello", "Welcome")
OLD_DOC = "Greeting: Hello, MCP!\n"
NEW_DOC = "Greeting: Welcome, MCP!\n"
EXTERNAL_DOC = "Greeting: Externally modified, MCP!\n"
FILES = {
    "greeting.py": (OLD_SOURCE, NEW_SOURCE),
    "tests/test_greeting.py": (OLD_TEST, NEW_TEST),
    "docs/usage.md": (OLD_DOC, NEW_DOC),
}
PATCH = (
    "*** Begin Patch\n"
    "*** Update File: greeting.py\n"
    "@@\n"
    '-    return f"Hello, {name}!"\n'
    '+    return f"Welcome, {name}!"\n'
    "*** Update File: tests/test_greeting.py\n"
    "@@\n"
    '-        self.assertEqual(greeting("MCP"), "Hello, MCP!")\n'
    '+        self.assertEqual(greeting("MCP"), "Welcome, MCP!")\n'
    "*** Update File: docs/usage.md\n"
    "@@\n"
    "-Greeting: Hello, MCP!\n"
    "+Greeting: Welcome, MCP!\n"
    "*** End Patch"
)
STORY = os.environ["SSH_MCP_TEST_STORY"]
NAMESPACE = uuid.uuid4().hex[:12]
state = {"hashes": {}, "preview": None, "apply": None, "ids": {}}


def sha(content):
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


with LabClient() as client:
    client.authorize()

    def command(argv, **fields):
        outer, result = client.call(
            "execute_command", client.execute_args(argv, **fields),
        )
        assert not outer.get("isError") and result["status"] == "succeeded", result
        return result

    def read(relative):
        outer, result = client.call("read_file", {
            "server": "fixture", "path": relative, "base_dir": ROOT,
            "reason": "TEST-248 PR3 read synthetic source hash",
            "story_id": STORY, "include_sha256": True,
        })
        assert not outer.get("isError") and result["status"] == "succeeded", result
        assert result["result"]["eof"], result
        return result["result"]

    def patch(body, *, preview, hashes=None, label="patch", **options):
        operation_id = f"sky248-pr3-{NAMESPACE}-{label}"
        return client.call("apply_patch", {
            "server": "fixture", "base_dir": ROOT,
            "reason": "TEST-248 PR3 audited synthetic multi-file workflow",
            "story_id": STORY, "operation_id": operation_id,
            "atomic": True, "dry_run": preview, "include_sha256": True,
            "expected_hashes": hashes if hashes is not None else state["hashes"],
            "patch": body, **options,
        })

    def history():
        outer, value = client.call("list_jobs", {
            "story_id": STORY, "record_kind": "file", "limit": 100,
        })
        assert not outer.get("isError") and value["jobs"], value
        return value["jobs"]

    # Only remove the candidate test's exact fixture-owned path, never
    # another story's directory or any lab service/volume.
    setup = (
        "from pathlib import Path\n"
        "import shutil\n"
        f"root=Path({ROOT!r})\n"
        "assert root.parent == Path('/home/tester')\n"
        "assert not root.is_symlink()\n"
        "if root.exists(): shutil.rmtree(root)\n"
        "root.mkdir(mode=0o700)\n"
        "for name in ('tests','docs'):(root/name).mkdir(mode=0o700)\n"
        f"data={dict((k, v[0]) for k,v in FILES.items())!r}\n"
        "for name,content in data.items(): (root/name).write_text(content)\n"
    )
    command(["python3", "-c", setup])

    def baseline_project_tests():
        command(["python3", "-m", "unittest", "discover", "-s", "tests", "-v"],
                cwd=ROOT)
        return "original_synthetic_unittest_passed"

    check("initial_unittest_before_change", baseline_project_tests)

    def three_read_file_hashes():
        initial = {}
        for relative, (before, _) in FILES.items():
            result = read(relative)
            assert result["content"] == before, (relative, result)
            assert result["sha256"] == sha(before), relative
            initial[relative] = result["sha256"]
        state["hashes"] = initial
        return "read_file_sha256_all_three_sources"

    check("read_three_original_hashes", three_read_file_hashes)

    def preview_all_three_with_guard():
        outer, value = patch(PATCH, preview=True, label="preview")
        assert not outer.get("isError") and value["status"] == "succeeded", value
        result = value["result"]
        assert result["dry_run"] is True and result["applicability"] == "applicable", result
        assert result["bytes"] == 0 and result["summary"]["total_paths"] == 3, result
        assert result["summary"]["changed_paths"] == 3, result
        assert [o["status"] for o in result["outcomes"]] == ["applicable"] * 3, result
        for i, (relative, (_, after)) in enumerate(FILES.items()):
            item = result["outcomes"][i]
            assert item["before_sha256"] == state["hashes"][relative], item
            assert item["prospective_sha256"] == sha(after), item
        state["preview"] = result
        state["ids"]["preview"] = value["history_id"]
        return "3_way_preview_applicable_prospective_hashes"

    check("preview_code_tests_docs", preview_all_three_with_guard)

    def preview_must_not_modify_any_file():
        for relative, (before, _) in FILES.items():
            contents = read(relative)
            assert contents["content"] == before, relative
            assert contents["sha256"] == state["hashes"][relative], relative
        return "files_and_hashes_unchanged_after_preview"

    check("preview_no_on_disk_changes", preview_must_not_modify_any_file)

    def preview_history_classified_as_preview():
        expected = state["ids"]["preview"]
        matches = [job for job in history() if job.get("id") == expected]
        assert matches and matches[0]["operation_kind"] == "patch_preview", matches
        snippet = json.dumps(matches)
        assert "*** Begin Patch" not in snippet
        assert "Welcome, MCP!" not in snippet
        return "file_history_kind_patch_preview_metadata_only"

    check("preview_metadata_audit", preview_history_classified_as_preview)

    def stale_later_doc_guard_blocks_all_files():
        command([
            "python3", "-c",
            "from pathlib import Path;"
            f"Path({ROOT + '/docs/usage.md'!r}).write_text({EXTERNAL_DOC!r})",
        ])
        outer, value = patch(PATCH, preview=False, label="stale-apply")
        assert outer.get("isError") and value["status"] == "failed", value
        assert value["change_state"] == "no_changes", value
        assert value["retry_guidance"] == "refresh_preconditions", value
        result = value["result"]
        assert not result["preflight_completed"], result
        assert result["error"]["failure_kind"] == "hash_mismatch", result
        assert [o["status"] for o in result["outcomes"]] == [
            "not_attempted", "not_attempted", "failed",
        ], result
        assert read("greeting.py")["content"] == OLD_SOURCE
        assert read("tests/test_greeting.py")["content"] == OLD_TEST
        assert read("docs/usage.md")["content"] == EXTERNAL_DOC
        return "stale_guard_no_earlier_code_or_test_changes"

    check("stale_docs_preflight_blocks_all", stale_later_doc_guard_blocks_all_files)

    def reconcile_with_fresh_raw_hashes():
        fresh = {}
        for relative in FILES:
            fresh[relative] = read(relative)["sha256"]
        state["hashes"] = fresh
        state["reconciled_patch"] = PATCH.replace(
            "-Greeting: Hello, MCP!", "-Greeting: Externally modified, MCP!",
        )
        outer, value = patch(
            state["reconciled_patch"], preview=True,
            label="refreshed-preview",
        )
        assert not outer.get("isError") and value["status"] == "succeeded", value
        assert value["result"]["applicability"] == "applicable", value
        assert value["result"]["summary"]["changed_paths"] == 3, value
        state["preview"] = value["result"]
        state["ids"]["refreshed_preview"] = value["history_id"]
        return "re_read_three_sha_and_new_preview"

    check("stale_guard_reconcile_new_preview", reconcile_with_fresh_raw_hashes)

    def apply_exact_reconciled_patch():
        outer, value = patch(
            state["reconciled_patch"], preview=False,
            label="reconciled-apply",
        )
        assert not outer.get("isError") and value["status"] == "succeeded", value
        assert value["change_state"] == "complete" and value["retry_guidance"] == "none", value
        result = value["result"]
        assert result["preflight_completed"] and not result["partial"], result
        assert result["summary"]["total_paths"] == 3, result
        assert result["summary"]["changed_paths"] == 3, result
        assert [x["status"] for x in result["outcomes"]] == ["applied"] * 3, result
        for i, (relative, (_, after)) in enumerate(FILES.items()):
            assert result["outcomes"][i]["before_sha256"] == state["hashes"][relative], result
            assert result["outcomes"][i]["sha256"] == sha(after), result
            assert result["outcomes"][i]["sha256"] == state["preview"]["outcomes"][i]["prospective_sha256"]
        state["apply"] = result
        state["ids"]["apply"] = value["history_id"]
        return "three_files_confirmed_hashes_and_apply_status"

    check("reconciled_three_file_apply", apply_exact_reconciled_patch)

    def read_all_postimage_hashes():
        for relative, (_, after) in FILES.items():
            result = read(relative)
            assert result["content"] == after, relative
            assert result["sha256"] == sha(after), relative
        return "byte_exact_greeting_source_test_docs"

    check("postimage_read_sha_verification", read_all_postimage_hashes)

    def run_updated_project_unit_tests():
        command(["python3", "-m", "unittest", "discover", "-s", "tests", "-v"],
                cwd=ROOT)
        return "updated_unittest_green"

    check("post_apply_unittest_validation", run_updated_project_unit_tests)

    def noop_reapply_identical_content():
        noop = (
            "*** Begin Patch\n"
            "*** Update File: greeting.py\n"
            "@@\n"
            '-    return f"Welcome, {name}!"\n'
            '+    return f"Welcome, {name}!"\n'
            "*** Update File: tests/test_greeting.py\n"
            "@@\n"
            '-        self.assertEqual(greeting("MCP"), "Welcome, MCP!")\n'
            '+        self.assertEqual(greeting("MCP"), "Welcome, MCP!")\n'
            "*** Update File: docs/usage.md\n"
            "@@\n"
            "-Greeting: Welcome, MCP!\n"
            "+Greeting: Welcome, MCP!\n"
            "*** End Patch"
        )
        new_hashes = {relative: read(relative)["sha256"] for relative in FILES}
        outer, value = patch(noop, preview=False, hashes=new_hashes, label="noop")
        assert not outer.get("isError") and value["status"] == "succeeded", value
        assert value["change_state"] == "no_changes" and value["retry_guidance"] == "none", value
        assert value["result"]["summary"]["bytes_written"] == 0, value
        assert value["result"]["summary"]["unchanged_paths"] == 3, value
        assert [o["status"] for o in value["result"]["outcomes"]] == ["unchanged"] * 3
        state["ids"]["noop"] = value["history_id"]
        return "three_noop_file_inodes_preserved_by_engine"

    check("three_file_noop_after_success", noop_reapply_identical_content)

    def original_patch_is_not_safely_replayable():
        outer, value = patch(PATCH, preview=False, label="stale-replay")
        assert outer.get("isError") and value["status"] == "failed", value
        assert value["change_state"] == "no_changes", value
        assert value["retry_guidance"] == "refresh_preconditions", value
        assert read("greeting.py")["content"] == NEW_SOURCE
        assert read("tests/test_greeting.py")["content"] == NEW_TEST
        return "old_preimage_hash_does_not_match_new_source"

    check("stale_replay_fails_closed", original_patch_is_not_safely_replayable)

    def duplicate_operation_id_cannot_replay():
        # Use the exact same operation_id as a completed apply; even a
        # syntactically valid patch is not an exactly-once retry mechanism.
        outer, value = patch(
            state["reconciled_patch"], preview=False, label="reconciled-apply",
        )
        assert outer.get("isError"), (outer, value)
        if value is not None:
            assert value["status"] == "failed", value
            assert value["error"]["code"] == "duplicate_operation", value
        assert read("greeting.py")["content"] == NEW_SOURCE
        return "duplicate_operation_refused_not_automatically_replayed"

    check("operation_id_duplicate_protection", duplicate_operation_id_cannot_replay)

    def audit_separates_preview_and_actual_without_content():
        rows = history()
        by_id = {record["id"]: record for record in rows}
        assert by_id[state["ids"]["preview"]]["operation_kind"] == "patch_preview"
        assert by_id[state["ids"]["refreshed_preview"]]["operation_kind"] == "patch_preview"
        assert by_id[state["ids"]["apply"]]["operation_kind"] == "patch"
        assert by_id[state["ids"]["noop"]]["operation_kind"] == "patch"
        for identity in state["ids"].values():
            text = json.dumps(by_id[identity])
            assert "*** Begin Patch" not in text
            assert 'return f"Welcome' not in text
            assert "Externally modified" not in text
        return "four_metadata_only_file_history_records_verified"

    check("preview_apply_separate_history_kinds", audit_separates_preview_and_actual_without_content)

    def non_fixture_host_cannot_be_written():
        outer, _ = client.call("apply_patch", {
            "server": "demo-fixture", "reason": "TEST-248 synthetic denied host",
            "story_id": STORY, "atomic": True, "patch": PATCH,
        })
        assert outer.get("isError"), outer
        return "real_lab_host_authorization_denied"

    check("host_scope_authorization_unchanged", non_fixture_host_cannot_be_written)


print(f"SKY248_PR3_SUMMARY passed={passed} failed={failed} "
      f"story={STORY}", flush=True)
raise SystemExit(1 if failed else 0)
