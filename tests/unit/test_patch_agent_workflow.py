"""TEST-248 PR3: end-to-end source + tests + docs agent editing workflow.

Uses the shipping file helper and an isolated Python unittest project; no
GitHub write, SSH host, production deployment or alternate patch engine.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch as mock_patch

from app.contracts import ApplyPatchRequest, ApplyPatchResponse, contract_document
from app.file_helper import dispatch


SOURCE_OLD = (
    'def greeting(name: str) -> str:\n'
    '    return f"Hello, {name}!"\n'
)
SOURCE_NEW = SOURCE_OLD.replace("Hello", "Welcome")
TEST_OLD = (
    "import unittest\n\n"
    "from greeting import greeting\n\n\n"
    "class GreetingTest(unittest.TestCase):\n"
    "    def test_greeting(self):\n"
    '        self.assertEqual(greeting("MCP"), "Hello, MCP!")\n'
)
TEST_NEW = TEST_OLD.replace("Hello", "Welcome")
DOC_OLD = "Greeting: Hello, MCP!\n"
DOC_NEW = "Greeting: Welcome, MCP!\n"
FILES = (
    ("greeting.py", SOURCE_OLD, SOURCE_NEW),
    ("tests/test_greeting.py", TEST_OLD, TEST_NEW),
    ("docs/usage.md", DOC_OLD, DOC_NEW),
)
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


def sha(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def snapshot(path: Path) -> tuple[bytes, int, int, int, int]:
    st = path.stat()
    # Read-side access timestamps are not asserted.
    return path.read_bytes(), st.st_ino, st.st_mode, st.st_mtime_ns, st.st_ctime_ns


class AgentWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="sky248-pr3-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for relative, before, _ in FILES:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(before)

    def read(self, relative: str) -> dict:
        result = dispatch({
            "protocol": 1, "operation": "read", "server": "fixture",
            "path": relative, "base_dir": str(self.root),
            "include_sha256": True,
        })
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["eof"])
        self.assertEqual(result["sha256"], sha((self.root / relative).read_bytes()))
        return result

    def hashes(self) -> dict[str, str]:
        return {relative: self.read(relative)["sha256"] for relative, _, _ in FILES}

    def edit(
        self, *, body: str = PATCH, expected: dict[str, str] | None = None,
        dry_run: bool = False, include_diff: bool = False,
    ) -> dict:
        return dispatch({
            "protocol": 1, "operation": "patch",
            "base_dir": str(self.root), "server": "fixture",
            "patch": body, "expected_hashes": expected if expected is not None else self.hashes(),
            "atomic": True, "dry_run": dry_run,
            "include_sha256": True, "include_diff": include_diff,
        })

    def validate_tests(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
            cwd=self.root, text=True, capture_output=True, timeout=25, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_source_test_docs_three_file_preview_apply_validate(self) -> None:
        self.validate_tests()
        preconditions = self.hashes()
        originals = {
            relative: snapshot(self.root / relative) for relative, _, _ in FILES
        }
        preview = self.edit(expected=preconditions, dry_run=True)
        self.assertTrue(preview["ok"], preview)
        self.assertTrue(preview["dry_run"])
        self.assertFalse(preview["partial"])
        self.assertEqual(preview["bytes"], 0)
        self.assertEqual(preview["applicability"], "applicable")
        self.assertEqual(preview["summary"]["total_paths"], 3)
        self.assertEqual(preview["summary"]["changed_paths"], 3)
        self.assertEqual([x["status"] for x in preview["outcomes"]],
                         ["applicable"] * 3)
        self.assertEqual(
            [x["before_sha256"] for x in preview["outcomes"]],
            [preconditions[r] for r, _, _ in FILES],
        )
        for relative, _, _ in FILES:
            self.assertEqual(snapshot(self.root / relative), originals[relative])
        actual = self.edit(expected=preconditions)
        self.assertTrue(actual["ok"], actual)
        self.assertTrue(actual["preflight_completed"])
        self.assertEqual(actual["change_state"], "complete")
        self.assertEqual(actual["retry_guidance"], "none")
        self.assertEqual([x["status"] for x in actual["outcomes"]], ["applied"] * 3)
        self.assertEqual(actual["summary"]["changed_paths"], 3)
        self.assertEqual(actual["summary"]["bytes_written"], actual["bytes"])
        self.assertTrue(actual["summary"]["line_counts_complete"])
        for i, (relative, _, updated) in enumerate(FILES):
            result = self.read(relative)
            self.assertEqual(result["content"], updated)
            self.assertEqual(result["sha256"], preview["outcomes"][i]["prospective_sha256"])
            self.assertEqual(result["sha256"], actual["outcomes"][i]["sha256"])
        self.validate_tests()

    def test_stale_later_docs_hash_blocks_all_then_fresh_patch_recovers(self) -> None:
        original = self.hashes()
        self.assertTrue(self.edit(expected=original, dry_run=True)["ok"])
        external = "Greeting: Externally modified, MCP!\n"
        (self.root / "docs/usage.md").write_text(external)
        failed = self.edit(expected=original)
        self.assertFalse(failed["ok"], failed)
        self.assertEqual(failed["change_state"], "no_changes")
        self.assertEqual(failed["retry_guidance"], "refresh_preconditions")
        self.assertFalse(failed["preflight_completed"])
        self.assertEqual(failed["error"]["failure_kind"], "hash_mismatch")
        self.assertEqual([x["status"] for x in failed["outcomes"]],
                         ["not_attempted", "not_attempted", "failed"])
        self.assertEqual((self.root / "greeting.py").read_text(), SOURCE_OLD)
        self.assertEqual((self.root / "tests/test_greeting.py").read_text(), TEST_OLD)
        self.assertEqual((self.root / "docs/usage.md").read_text(), external)
        new_patch = PATCH.replace("-Greeting: Hello, MCP!",
                                  "-Greeting: Externally modified, MCP!")
        fresh = self.hashes()
        self.assertTrue(self.edit(body=new_patch, expected=fresh, dry_run=True)["ok"])
        outcome = self.edit(body=new_patch, expected=fresh)
        self.assertTrue(outcome["ok"], outcome)
        self.assertEqual(outcome["change_state"], "complete")
        self.validate_tests()
        self.assertEqual((self.root / "docs/usage.md").read_text(), DOC_NEW)

    def test_unmatched_final_hunk_is_non_mutating_for_earlier_source_and_test(self) -> None:
        failing = PATCH.replace("-Greeting: Hello, MCP!", "-Greeting: not present")
        initial = {rel: snapshot(self.root / rel) for rel, _, _ in FILES}
        result = self.edit(body=failing)
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["change_state"], "no_changes")
        self.assertEqual(result["error"]["failure_kind"], "context_mismatch")
        self.assertEqual([x["status"] for x in result["outcomes"]],
                         ["not_attempted", "not_attempted", "failed"])
        for relative, _, _ in FILES:
            self.assertEqual(snapshot(self.root / relative), initial[relative])
        self.validate_tests()

    def test_identical_updates_are_noops_across_all_three_files(self) -> None:
        unchanged = (
            "*** Begin Patch\n"
            "*** Update File: greeting.py\n"
            "@@\n"
            '-    return f"Hello, {name}!"\n'
            '+    return f"Hello, {name}!"\n'
            "*** Update File: tests/test_greeting.py\n"
            "@@\n"
            '-        self.assertEqual(greeting("MCP"), "Hello, MCP!")\n'
            '+        self.assertEqual(greeting("MCP"), "Hello, MCP!")\n'
            "*** Update File: docs/usage.md\n"
            "@@\n"
            "-Greeting: Hello, MCP!\n"
            "+Greeting: Hello, MCP!\n"
            "*** End Patch"
        )
        original = {r: snapshot(self.root / r) for r, _, _ in FILES}
        preview = self.edit(body=unchanged, dry_run=True)
        self.assertTrue(preview["ok"], preview)
        self.assertEqual([v["status"] for v in preview["outcomes"]], ["unchanged"] * 3)
        result = self.edit(body=unchanged)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["change_state"], "no_changes")
        self.assertEqual(result["retry_guidance"], "none")
        self.assertEqual(result["summary"]["bytes_written"], 0)
        self.assertEqual(result["summary"]["unchanged_paths"], 3)
        self.assertEqual([v["status"] for v in result["outcomes"]], ["unchanged"] * 3)
        for relative, _, _ in FILES:
            self.assertEqual(snapshot(self.root / relative), original[relative])

    def test_uncertain_second_publication_requires_reconciliation(self) -> None:
        from app import file_helper
        original = file_helper._publish
        calls = 0

        def interrupted(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise PermissionError("synthetic failure after publication may begin")
            return original(*args, **kwargs)

        with mock_patch("app.file_helper._publish", side_effect=interrupted):
            result = self.edit()
        self.assertFalse(result["ok"], result)
        self.assertTrue(result["unknown"])
        self.assertTrue(result["partial"])
        self.assertEqual(result["change_state"], "outcome_uncertain")
        self.assertEqual(result["retry_guidance"], "reconcile_before_retry")
        self.assertEqual([v["status"] for v in result["outcomes"]],
                         ["applied", "failed", "not_attempted"])
        self.assertEqual((self.root / "greeting.py").read_text(), SOURCE_NEW)
        self.assertEqual((self.root / "tests/test_greeting.py").read_text(), TEST_OLD)
        self.assertEqual((self.root / "docs/usage.md").read_text(), DOC_OLD)
        # The operation result is not evidence that it is safe to replay.
        self.assertNotEqual(self.hashes()["greeting.py"], sha(SOURCE_OLD.encode()))

    def test_typed_contract_accepts_agent_workflow_preview_and_apply(self) -> None:
        self.assertEqual(contract_document()["contract_version"], "1.9")
        values = self.hashes()
        request = ApplyPatchRequest(
            server="demo-node-b", reason="TEST-248 related source test docs",
            story_id="TEST-248", base_dir=str(self.root), patch=PATCH,
            expected_hashes=values, atomic=True, dry_run=True,
            include_sha256=True,
        )
        self.assertTrue(request.dry_run)
        preview = self.edit(expected=values, dry_run=True)
        wrapped = ApplyPatchResponse.model_validate({
            "status": "succeeded", "operation_id": "sky248-preview-1",
            "history_id": "file_sky248-preview-1", "result": preview,
        })
        self.assertEqual(wrapped.result.applicability, "applicable")
        self.assertEqual(ApplyPatchResponse.model_validate_json(
            wrapped.model_dump_json()).model_dump(), wrapped.model_dump())
        actual = self.edit(expected=values)
        wrapped_apply = ApplyPatchResponse.model_validate({
            "status": "succeeded", "operation_id": "sky248-apply-1",
            "history_id": "file_sky248-apply-1", "result": actual,
            "change_state": actual["change_state"],
            "retry_guidance": actual["retry_guidance"],
        })
        self.assertEqual(wrapped_apply.change_state, "complete")
        self.assertEqual(wrapped_apply.result.summary["changed_paths"], 3)


if __name__ == "__main__":
    unittest.main()
