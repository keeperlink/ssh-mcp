"""TEST-248 PR2: all-file atomic preflight, change certainty and compact apply outcomes."""
from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.file_helper import dispatch
from app.contracts import ApplyPatchResponse, contract_document


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def apply(body: str, *, base: Path, atomic: bool = True, **kwargs: object) -> dict:
    return dispatch({
        "protocol": 1, "operation": "patch",
        "patch": "*** Begin Patch\n" + body + "*** End Patch",
        "base_dir": str(base), "atomic": atomic, **kwargs,
    })


def update(path: str, old: str, new: str, *, move: str | None = None) -> str:
    return (f"*** Update File: {path}\n"
            + (f"*** Move to: {move}\n" if move else "")
            + f"@@\n-{old}\n+{new}\n")


class AtomicApplyTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.a = self.root / "a.txt"
        self.b = self.root / "b.txt"
        self.c = self.root / "c.txt"
        self.a.write_bytes(b"old-a\n")
        self.b.write_bytes(b"old-b\n")
        self.c.write_bytes(b"old-c\n")

    def test_later_context_failure_preflights_all_and_writes_nothing(self):
        original = self.a.stat()
        body = (update("a.txt", "old-a", "new-a")
                + update("b.txt", "absent", "new-b")
                + update("c.txt", "old-c", "new-c"))
        with patch("app.file_helper._publish",
                   side_effect=AssertionError("atomic preflight must not publish")):
            result = apply(body, base=self.root, atomic=True)
        self.assertFalse(result["ok"], result)
        self.assertFalse(result["partial"])
        self.assertEqual(result["change_state"], "no_changes")
        self.assertEqual(result["retry_guidance"], "refresh_preconditions")
        self.assertFalse(result["preflight_completed"])
        self.assertEqual(result["error"]["failure_kind"], "context_mismatch")
        self.assertEqual([entry["status"] for entry in result["outcomes"]],
                         ["not_attempted", "failed", "not_attempted"])
        self.assertEqual(result["summary"]["changed_paths"], 0)
        self.assertEqual(self.a.read_bytes(), b"old-a\n")
        self.assertEqual(self.a.stat().st_ino, original.st_ino)
        self.assertEqual(self.b.read_bytes(), b"old-b\n")
        self.assertEqual(self.c.read_bytes(), b"old-c\n")

    def test_atomic_create_parents_does_not_mkdir_until_all_preflight_passes(self):
        body = ("*** Add File: missing/subdir/new.txt\n+new\n"
                + update("b.txt", "missing", "bad"))
        result = apply(body, base=self.root, create_parents=True)
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["change_state"], "no_changes")
        self.assertFalse((self.root / "missing").exists())
        self.assertEqual(self.b.read_bytes(), b"old-b\n")

    def test_atomic_directory_delete_fails_preflight_without_prior_mutation(self):
        folder = self.root / "subdir"
        folder.mkdir()
        result = apply(
            update("a.txt", "old-a", "new-a")
            + "*** Delete File: subdir\n",
            base=self.root, atomic=True,
        )
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["error"]["code"], "invalid_request")
        self.assertEqual(result["change_state"], "no_changes")
        self.assertEqual(self.a.read_bytes(), b"old-a\n")
        self.assertTrue(folder.is_dir())

    def test_atomic_path_collision_rejected_without_any_changes(self):
        body = (update("a.txt", "old-a", "new-a")
                + update("b.txt", "old-b", "new-b", move="a.txt"))
        result = apply(body, base=self.root)
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["error"]["failure_kind"], "overlapping_paths")
        self.assertEqual(result["change_state"], "no_changes")
        self.assertEqual(result["summary"]["changed_paths"], 0)
        self.assertEqual(self.a.read_bytes(), b"old-a\n")
        self.assertEqual(self.b.read_bytes(), b"old-b\n")

    def test_atomic_nested_add_conflicts_both_orders_without_publication(self):
        parent = "*** Add File: created.txt\n+regular file\n"
        child = "*** Add File: created.txt/nested.txt\n+nested\n"
        for body in (parent + child, child + parent):
            with self.subTest(order=body.startswith(parent)):
                with patch("app.file_helper._publish",
                           side_effect=AssertionError("ancestor conflict must preflight")):
                    result = apply(body, base=self.root, atomic=True,
                                   create_parents=True)
                self.assertFalse(result["ok"], result)
                self.assertEqual(result["change_state"], "no_changes")
                self.assertEqual(result["retry_guidance"], "refresh_preconditions")
                self.assertEqual(result["error"]["failure_kind"], "overlapping_paths")
                self.assertEqual([item["status"] for item in result["outcomes"]],
                                 ["not_attempted", "failed"])
                self.assertEqual(result["summary"]["changed_paths"], 0)
                self.assertFalse((self.root / "created.txt").exists())
                self.assertEqual(self.a.read_bytes(), b"old-a\n")

    def test_ancestor_conflict_detected_with_interleaved_sibling_prefix(self):
        body = ("*** Add File: created.txt\n+parent\n"
                "*** Add File: created.txt-other\n+sibling\n"
                "*** Add File: created.txt/nested.txt\n+child\n")
        result = apply(body, base=self.root, atomic=True, create_parents=True)
        self.assertEqual(result["error"]["failure_kind"], "overlapping_paths")
        self.assertEqual([x["status"] for x in result["outcomes"]],
                         ["not_attempted", "not_attempted", "failed"])
        self.assertFalse((self.root / "created.txt").exists())
        self.assertFalse((self.root / "created.txt-other").exists())

    def test_move_destination_ancestor_conflict_preflight(self):
        body = (update("a.txt", "old-a", "new-a", move="created.txt")
                + "*** Add File: created.txt/nested.txt\n+child\n")
        result = apply(body, base=self.root, atomic=True, create_parents=True)
        self.assertEqual(result["error"]["failure_kind"], "overlapping_paths")
        self.assertEqual(result["change_state"], "no_changes")
        self.assertEqual(self.a.read_bytes(), b"old-a\n")
        self.assertFalse((self.root / "created.txt").exists())

    def test_preview_ancestor_conflicts_are_nonmutating(self):
        body = ("*** Add File: created.txt\n+parent\n"
                "*** Add File: created.txt/nested.txt\n+child\n")
        for options in ({"atomic": False, "dry_run": True},
                        {"atomic": True, "dry_run": True}):
            with self.subTest(options=options):
                result = apply(body, base=self.root, create_parents=True, **options)
                self.assertFalse(result["ok"], result)
                self.assertEqual(result["error"]["failure_kind"], "overlapping_paths")
                self.assertFalse((self.root / "created.txt").exists())

    def test_nonoverlapping_similar_prefixes_still_allowed(self):
        body = ("*** Add File: created.txt\n+file\n"
                "*** Add File: created.txt-other\n+other\n")
        result = apply(body, base=self.root, atomic=True, create_parents=True)
        self.assertTrue(result["ok"], result)
        self.assertEqual((self.root / "created.txt").read_text(), "file\n")
        self.assertEqual((self.root / "created.txt-other").read_text(), "other\n")

    def test_repetitive_line_delta_is_skipped_before_quadratic_matching(self):
        path = self.root / "repetitive.txt"
        contents = "old-start\n" + "same\n" * 1800 + "old-end\n"
        path.write_text(contents)
        body = ("*** Update File: repetitive.txt\n"
                "@@\n-old-start\n+new-start\n"
                "@@\n-old-end\n+new-end\n")
        with patch("app.file_helper.difflib.SequenceMatcher",
                   side_effect=AssertionError("quadratic matching forbidden")):
            preview = apply(body, base=self.root, atomic=True,
                            dry_run=True, include_diff=True)
            result = apply(body, base=self.root, atomic=True)
        self.assertTrue(preview["ok"], preview)
        self.assertTrue(result["ok"], result)
        self.assertEqual(preview["outcomes"][0]["diff"], "")
        self.assertTrue(preview["outcomes"][0]["diff_truncated"])
        for outcome in (preview["outcomes"][0], result["outcomes"][0]):
            self.assertNotIn("added_lines", outcome)
            self.assertNotIn("removed_lines", outcome)
        for summary in (preview["summary"], result["summary"]):
            self.assertFalse(summary["line_counts_complete"])
            self.assertIsNone(summary["added_lines"])
            self.assertIsNone(summary["removed_lines"])
        self.assertEqual(path.read_text(),
                         contents.replace("old-start", "new-start")
                                 .replace("old-end", "new-end"))

    def test_repetitive_line_budget_spans_all_patch_paths(self):
        # Each 275-line file is individually below the work ceiling,
        # but combined ambiguous matching exceeds the request budget.
        for i in range(4):
            name = f"repeated-{i}.txt"
            (self.root / name).write_text("start\n" + "same\n" * 275 + "end\n")
        # Use the two-sided delta explicitly to make the long middle costly.
        body = "".join(
            f"*** Update File: repeated-{i}.txt\n"
            f"@@\n-start\n+changed-{i}\n"
            f"@@\n-end\n+finished-{i}\n"
            for i in range(4)
        )
        result = apply(body, base=self.root, atomic=True)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["summary"]["changed_paths"], 4)
        self.assertFalse(result["summary"]["line_counts_complete"])
        self.assertIsNone(result["summary"]["added_lines"])
        self.assertIsNone(result["summary"]["removed_lines"])
        self.assertTrue(all(x["status"] == "applied" for x in result["outcomes"]))
        self.assertTrue(any("added_lines" not in x for x in result["outcomes"]))

    def test_nonatomic_path_collision_rejected_before_first_write(self):
        result = apply(update("a.txt", "old-a", "new-a")
                       + update("a.txt", "old-a", "again"),
                       base=self.root, atomic=False)
        self.assertEqual(result["error"]["code"], "invalid_patch")
        self.assertEqual(result["change_state"], "no_changes")
        self.assertEqual(self.a.read_bytes(), b"old-a\n")

    def test_multi_action_atomic_success_compact_counts_and_hashes(self):
        before_b = self.b.read_bytes()
        body = ("*** Add File: added.txt\n+new-add\n"
                + update("a.txt", "old-a", "new-a")
                + "*** Delete File: c.txt\n"
                + update("b.txt", "old-b", "new-b", move="moved.txt"))
        result = apply(body, base=self.root, include_sha256=True)
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["preflight_completed"])
        self.assertEqual(result["change_state"], "complete")
        self.assertEqual(result["retry_guidance"], "none")
        self.assertEqual([o["status"] for o in result["outcomes"]], ["applied"] * 4)
        self.assertEqual(result["summary"]["changed_paths"], 4)
        self.assertEqual(result["summary"]["failed_paths"], 0)
        self.assertEqual(result["summary"]["unchanged_paths"], 0)
        self.assertEqual(result["summary"]["added_lines"], 3)
        self.assertEqual(result["summary"]["removed_lines"], 3)
        self.assertTrue(result["summary"]["line_counts_complete"])
        self.assertEqual(result["summary"]["bytes_written"], result["bytes"])
        self.assertEqual(result["outcomes"][1]["before_sha256"], sha(b"old-a\n"))
        self.assertEqual(result["outcomes"][1]["sha256"], sha(b"new-a\n"))
        self.assertEqual(result["outcomes"][3]["before_sha256"], sha(before_b))
        self.assertEqual(result["outcomes"][3]["sha256"], sha(b"new-b\n"))
        self.assertEqual(result["outcomes"][2]["before_sha256"], sha(b"old-c\n"))
        self.assertNotIn("sha256", result["outcomes"][2])
        self.assertEqual((self.root / "added.txt").read_bytes(), b"new-add\n")
        self.assertEqual(self.a.read_bytes(), b"new-a\n")
        self.assertEqual((self.root / "moved.txt").read_bytes(), b"new-b\n")
        self.assertFalse(self.b.exists())
        self.assertFalse(self.c.exists())

    def test_noop_atomic_and_nonatomic_do_not_replace_inode(self):
        for atomic in (True, False):
            with self.subTest(atomic=atomic):
                before = self.a.stat()
                result = apply(update("a.txt", "old-a", "old-a"),
                               base=self.root, atomic=atomic, include_sha256=True)
                after = self.a.stat()
                self.assertTrue(result["ok"], result)
                self.assertEqual(result["change_state"], "no_changes")
                self.assertEqual(result["retry_guidance"], "none")
                self.assertEqual(result["summary"]["bytes_written"], 0)
                self.assertEqual(result["summary"]["changed_paths"], 0)
                self.assertEqual(result["summary"]["unchanged_paths"], 1)
                self.assertEqual(result["outcomes"][0]["status"], "unchanged")
                self.assertEqual(result["outcomes"][0]["added_lines"], 0)
                self.assertEqual(result["outcomes"][0]["removed_lines"], 0)
                self.assertEqual(result["outcomes"][0]["sha256"], sha(b"old-a\n"))
                self.assertEqual(
                    (before.st_ino, before.st_mtime_ns, before.st_ctime_ns),
                    (after.st_ino, after.st_mtime_ns, after.st_ctime_ns),
                )

    def test_move_same_text_is_not_a_noop(self):
        result = apply(update("a.txt", "old-a", "old-a", move="moved.txt"),
                       base=self.root, atomic=True)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["change_state"], "complete")
        self.assertEqual(result["outcomes"][0]["status"], "applied")
        self.assertFalse(self.a.exists())
        self.assertEqual((self.root / "moved.txt").read_bytes(), b"old-a\n")

    def test_nonatomic_prior_success_failure_is_partial_and_reconcile(self):
        result = apply(update("a.txt", "old-a", "new-a")
                       + update("b.txt", "missing", "never"),
                       base=self.root, atomic=False)
        self.assertFalse(result["ok"], result)
        self.assertTrue(result["partial"])
        self.assertEqual(result["change_state"], "partial")
        self.assertEqual(result["retry_guidance"], "reconcile_before_retry")
        self.assertEqual(result["error"]["code"], "partial")
        self.assertEqual(result["outcomes"][0]["status"], "applied")
        self.assertEqual(result["outcomes"][1]["status"], "failed")
        self.assertEqual(self.a.read_bytes(), b"new-a\n")
        self.assertEqual(self.b.read_bytes(), b"old-b\n")

    def test_atomic_revalidates_file_changed_during_preflight(self):
        body = update("a.txt", "old-a", "new-a") + update("b.txt", "old-b", "new-b")
        from app import file_helper
        original = file_helper._preview_patch
        def external_write(*args, **kwargs):
            result = original(*args, **kwargs)
            self.b.write_text("external-b\n")
            return result
        with patch("app.file_helper._preview_patch", side_effect=external_write), \
             patch("app.file_helper._publish",
                   side_effect=AssertionError("changed preflight cannot publish")):
            result = apply(body, base=self.root)
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["change_state"], "no_changes")
        self.assertEqual(result["error"]["code"], "changed_file")
        self.assertEqual(self.a.read_bytes(), b"old-a\n")
        self.assertEqual(self.b.read_bytes(), b"external-b\n")

    def test_atomic_detects_symlink_referent_change_after_preflight(self):
        link = self.root / "linked.txt"
        link.symlink_to(self.a)
        body = (update("b.txt", "old-b", "new-b")
                + update("linked.txt", "old-a", "new-a"))
        from app import file_helper
        original = file_helper._preview_patch

        def external_target_write(*args, **kwargs):
            plan = original(*args, **kwargs)
            self.a.write_text("external\n")
            return plan

        with patch("app.file_helper._preview_patch", side_effect=external_target_write):
            result = apply(body, base=self.root, atomic=True)
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["error"]["code"], "changed_file")
        self.assertEqual(result["change_state"], "no_changes")
        self.assertEqual(self.b.read_bytes(), b"old-b\n")
        self.assertEqual(self.a.read_text(), "external\n")
        self.assertTrue(link.is_symlink())

    def test_atomic_midpublication_error_is_uncertain_no_automatic_retry(self):
        from app import file_helper
        original = file_helper._publish
        calls = 0
        def flaky(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise PermissionError("Synthetic failure at stage or commit")
            return original(*args, **kwargs)
        with patch("app.file_helper._publish", side_effect=flaky):
            result = apply(update("a.txt", "old-a", "new-a")
                           + update("b.txt", "old-b", "new-b")
                           + update("c.txt", "old-c", "new-c"),
                           base=self.root)
        self.assertFalse(result["ok"], result)
        self.assertTrue(result["unknown"])
        self.assertTrue(result["partial"])
        self.assertEqual(result["change_state"], "outcome_uncertain")
        self.assertEqual(result["retry_guidance"], "reconcile_before_retry")
        self.assertEqual(result["error"]["code"], "interrupted")
        self.assertEqual([o["status"] for o in result["outcomes"]],
                         ["applied", "failed", "not_attempted"])
        self.assertEqual(self.a.read_bytes(), b"new-a\n")
        self.assertEqual(self.b.read_bytes(), b"old-b\n")
        self.assertEqual(self.c.read_bytes(), b"old-c\n")

    def test_first_unlink_permission_error_is_uncertain_with_real_error_code(self):
        with patch("app.file_helper.Path.unlink", side_effect=PermissionError):
            result = apply("*** Delete File: a.txt\n", base=self.root,
                           atomic=False)
        self.assertFalse(result["ok"], result)
        self.assertTrue(result["unknown"])
        self.assertTrue(result["partial"])
        self.assertEqual(result["change_state"], "outcome_uncertain")
        self.assertEqual(result["retry_guidance"], "reconcile_before_retry")
        self.assertEqual(result["outcomes"][0]["error_code"], "permission_denied")
        self.assertEqual(result["outcomes"][0]["failure_kind"], "outcome_uncertain")
        self.assertEqual(self.a.read_bytes(), b"old-a\n")

    def test_partial_after_confirmed_hash_unavailable(self):
        from app import file_helper
        original = file_helper._sha
        def flaky(target):
            if target == self.a:
                raise PermissionError("Synthetic postpublish hash inaccessible")
            return original(target)
        with patch("app.file_helper._sha", side_effect=flaky):
            result = apply(update("a.txt", "old-a", "new-a"), base=self.root,
                           atomic=False, include_sha256=True)
        self.assertFalse(result["ok"], result)
        self.assertTrue(result["partial"])
        self.assertEqual(result["change_state"], "partial")
        self.assertEqual(result["retry_guidance"], "reconcile_before_retry")
        self.assertEqual(result["outcomes"][0]["status"], "applied")
        self.assertEqual(result["outcomes"][0]["hash_error_code"], "permission_denied")
        self.assertEqual(self.a.read_bytes(), b"new-a\n")

    def test_unreadable_large_delete_counts_are_unknown_not_zero(self):
        big = self.root / "sparse.txt"
        with big.open("wb") as handle:
            handle.truncate(2 * 1024 ** 3)
        result = apply("*** Delete File: sparse.txt\n", base=self.root, atomic=True)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["change_state"], "complete")
        self.assertFalse(result["summary"]["line_counts_complete"])
        self.assertIsNone(result["summary"]["removed_lines"])
        self.assertNotIn("removed_lines", result["outcomes"][0])
        self.assertFalse(big.exists())

    def test_typed_contract_and_response_support_change_state(self):
        self.assertEqual(contract_document()["contract_version"], "1.9")
        result = apply(update("a.txt", "old-a", "old-a"), base=self.root)
        typed = ApplyPatchResponse.model_validate({
            "status": "succeeded",
            "operation_id": "test-atomic-apply",
            "history_id": "file_test-atomic-apply",
            "result": result,
            "change_state": result["change_state"],
            "retry_guidance": result["retry_guidance"],
        })
        self.assertEqual(typed.change_state, "no_changes")
        self.assertEqual(typed.result.change_state, "no_changes")
        self.assertEqual(ApplyPatchResponse.model_validate_json(
            typed.model_dump_json()).model_dump(), typed.model_dump())


if __name__ == "__main__":
    unittest.main()
