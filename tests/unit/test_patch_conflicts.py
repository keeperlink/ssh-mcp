"""TEST-247 PR3: actionable, read-gated patch conflicts without mutation or leaks."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.file_helper import dispatch, _safe_patch_line
from app.contracts import ApplyPatchResponse, contract_document


def update(path: str, *, section: str = "", before: str = "old", after: str = "new",
           eof: bool = False) -> str:
    header = "@@ " + section if section else "@@"
    suffix = "\n*** End of File" if eof else ""
    return f"*** Update File: {path}\n{header}\n-{before}\n+{after}{suffix}\n"


def request(actions: str, **extra) -> dict:
    return {"protocol": 1, "operation": "patch",
            "patch": "*** Begin Patch\n" + actions + "*** End Patch",
            **extra}


class PatchConflictDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.original = self.root / "source.txt"
        self.original.write_text("first\nsecond\nthird\nfourth\n", encoding="utf-8")
        self.before = self.original.read_bytes()

    def test_missing_context_with_authorized_actual_excerpt(self):
        result = dispatch(request(update(str(self.original), before="not-present")))
        self.assertFalse(result["ok"], result)
        self.assertFalse(result["partial"])
        self.assertEqual(result["error"]["code"], "precondition_failed")
        self.assertEqual(result["error"]["failed_path"], str(self.original))
        self.assertEqual(result["error"]["failure_kind"], "context_mismatch")
        self.assertEqual(result["outcomes"][0]["status"], "failed")
        diagnostic = result["error"]["conflict"]
        self.assertEqual(diagnostic["hunk"], 1)
        self.assertEqual(diagnostic["expected_context"], ["not-present"])
        self.assertEqual(diagnostic["line_hint"], 1)
        self.assertTrue(diagnostic["excerpt_available"])
        self.assertEqual(diagnostic["actual_excerpt"][0], {"line": 1, "text": "first"})
        self.assertEqual(self.original.read_bytes(), self.before)

    def test_missing_section_and_eof_conflict_are_hunk_indexed(self):
        for body, kind in (
            (update(str(self.original), section="missing-section"), "missing_section"),
            (update(str(self.original), before="first", eof=True), "eof_mismatch"),
        ):
            with self.subTest(kind=kind):
                result = dispatch(request(body))
                conflict = result["error"]["conflict"]
                self.assertEqual(conflict["failure_kind"], kind)
                self.assertEqual(conflict["hunk"], 1)
                self.assertGreaterEqual(conflict["line_hint"], 1)
                self.assertEqual(self.original.read_bytes(), self.before)

    def test_later_hunk_failure_is_file_atomic_before_mutation(self):
        hunks = f"*** Update File: {self.original}\n@@\n-first\n+updated\n@@\n-missing\n+updated\n"
        result = dispatch(request(hunks, atomic=True))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["conflict"]["hunk"], 2)
        self.assertEqual(self.original.read_bytes(), self.before)

    def test_later_hunk_after_insertion_uses_original_numbered_lines(self):
        # Hunk 1 changes the mutable buffer to two new first lines, while
        # hunk 2 conflicts. Neither invented line may appear as actual disk.
        hunks = (f"*** Update File: {self.original}\n"
                 "@@\n-first\n+TWO new lines one\n+TWO new lines two\n"
                 "@@\n-missing-context\n+changed\n")
        result = dispatch(request(hunks, atomic=True))
        self.assertFalse(result["ok"])
        conflict = result["error"]["conflict"]
        self.assertEqual(conflict["failure_kind"], "context_mismatch")
        self.assertEqual(conflict["hunk"], 2)
        self.assertEqual(conflict["line_hint"], 2)
        self.assertEqual(conflict["actual_excerpt"][:2], [
            {"line": 2, "text": "second"}, {"line": 3, "text": "third"},
        ])
        self.assertNotIn("TWO new lines", json.dumps(result))
        self.assertEqual(self.original.read_bytes(), self.before)

    def test_later_hunk_after_deletion_uses_original_numbered_lines(self):
        hunks = (f"*** Update File: {self.original}\n"
                 "@@\n-first\n-second\n"
                 "@@\n-unmatched\n+changed\n")
        result = dispatch(request(hunks, atomic=True))
        conflict = result["error"]["conflict"]
        self.assertEqual(conflict["hunk"], 2)
        self.assertEqual(conflict["line_hint"], 3)
        self.assertEqual(conflict["actual_excerpt"][0], {"line": 3, "text": "third"})
        self.assertEqual(self.original.read_bytes(), self.before)

    def test_later_section_and_eof_mismatch_never_display_working_buffer(self):
        for suffix, kind in (
            ("@@ nowhere\n-third\n+updated\n", "missing_section"),
            ("@@\n-absent-at-eof\n+updated\n*** End of File\n",
             "eof_mismatch"),
        ):
            with self.subTest(kind=kind):
                hunks = (f"*** Update File: {self.original}\n"
                         "@@\n-first\n+invented-1\n+invented-2\n" + suffix)
                result = dispatch(request(hunks))
                conflict = result["error"]["conflict"]
                self.assertEqual(conflict["failure_kind"], kind)
                self.assertEqual(conflict["hunk"], 2)
                self.assertTrue(conflict["actual_excerpt"])
                original = self.before.decode().splitlines()
                for entry in conflict["actual_excerpt"]:
                    self.assertEqual(entry["text"], original[entry["line"] - 1])
                self.assertNotIn("invented-", json.dumps(result))
                self.assertEqual(self.original.read_bytes(), self.before)

    def test_unchanged_context_keeps_correct_original_provenance(self):
        hunks = (f"*** Update File: {self.original}\n"
                 "@@\n first\n-second\n+replacement-1\n+replacement-2\n"
                 "@@\n-missing\n+changed\n")
        result = dispatch(request(hunks))
        conflict = result["error"]["conflict"]
        self.assertEqual(conflict["line_hint"], 3)
        self.assertEqual(conflict["actual_excerpt"][0], {"line": 3, "text": "third"})
        self.assertEqual(self.original.read_bytes(), self.before)

    def test_conflict_after_replacing_every_original_line_uses_disk_excerpt(self):
        # No original line survives in the working buffer. Diagnostic must
        # still quote the original file, not uncommitted replacement text.
        hunks = (f"*** Update File: {self.original}\n"
                 "@@\n-first\n-second\n-third\n-fourth\n"
                 "+invented-first\n+invented-second\n"
                 "@@\n-unmatched\n+changed\n")
        result = dispatch(request(hunks))
        conflict = result["error"]["conflict"]
        self.assertEqual(conflict["hunk"], 2)
        self.assertEqual(conflict["line_hint"], 1)
        self.assertEqual(conflict["actual_excerpt"][0], {"line": 1, "text": "first"})
        self.assertNotIn("invented-", json.dumps(result))
        self.assertEqual(self.original.read_bytes(), self.before)

    def test_conflict_after_replacing_last_line_has_original_eof_hint(self):
        hunks = (f"*** Update File: {self.original}\n"
                 "@@\n-fourth\n+invented-final\n"
                 "@@\n-unmatched\n+changed\n")
        result = dispatch(request(hunks))
        conflict = result["error"]["conflict"]
        self.assertEqual(conflict["hunk"], 2)
        self.assertEqual(conflict["line_hint"], 4)
        self.assertEqual(conflict["actual_excerpt"][0], {"line": 4, "text": "fourth"})
        self.assertNotIn("invented-final", json.dumps(result))
        self.assertEqual(self.original.read_bytes(), self.before)

    def test_hash_precondition_reports_kind_without_file_excerpt(self):
        wrong = "f" * 64
        result = dispatch(request(
            update(str(self.original)), expected_hashes={str(self.original): wrong},
        ))
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["error"]["code"], "precondition_failed")
        self.assertEqual(result["error"]["failure_kind"], "hash_mismatch")
        self.assertEqual(result["error"]["conflict"]["actual_excerpt"], [])
        self.assertEqual(self.original.read_bytes(), self.before)
        missing = self.root / "gone.txt"
        result = dispatch(request(update(str(missing)),
                                  expected_hashes={str(missing): wrong}))
        self.assertEqual(result["error"]["failure_kind"], "missing_file")
        self.assertFalse(missing.exists())

    def test_unreadable_target_gates_actual_excerpt(self):
        with patch("app.file_helper.os.access", return_value=False):
            result = dispatch(request(update(str(self.original), before="absent")))
        self.assertFalse(result["ok"])
        conflict = result["error"]["conflict"]
        self.assertFalse(conflict["excerpt_available"])
        self.assertEqual(conflict["actual_excerpt"], [])
        self.assertEqual(self.original.read_bytes(), self.before)

    def test_excerpt_and_expected_context_redact_secret_lines(self):
        self.original.write_text(
            "password=ultra-sensitive-test-value\n"
            "safe line\n"
            "Authorization: Bearer private-test-abcdef\n"
            "api_key=really_sensitive\n"
            "last safe\n", encoding="utf-8",
        )
        result = dispatch(request(update(str(self.original),
                                         before="token=sensitive-in-request")))
        details = result["error"]["conflict"]
        self.assertEqual(details["expected_context"], ["[REDACTED]"])
        self.assertEqual(details["actual_excerpt"][0]["text"], "[REDACTED]")
        self.assertEqual(details["actual_excerpt"][2]["text"], "[REDACTED]")
        self.assertEqual(details["actual_excerpt"][3]["text"], "[REDACTED]")
        encoded = json.dumps(result)
        for forbidden in ("ultra-sensitive-test-value", "private-test-abcdef",
                          "really_sensitive", "sensitive-in-request"):
            self.assertNotIn(forbidden, encoded)

    def test_bounded_excerpt_and_hunk_expected_context(self):
        self.original.write_text("a" * 1000 + "\n" + "\n".join(f"line {n}" for n in range(20)),
                                 encoding="utf-8")
        body = (f"*** Update File: {self.original}\n@@\n"
                + "".join(f"-expected {i}\n" for i in range(10))
                + "+new\n")
        result = dispatch(request(body))
        diagnostic = result["error"]["conflict"]
        self.assertLessEqual(len(diagnostic["actual_excerpt"]), 4)
        self.assertLessEqual(len(diagnostic["expected_context"]), 4)
        for entry in diagnostic["actual_excerpt"]:
            self.assertLessEqual(len(entry["text"]), 121)
        self.assertLess(len(json.dumps(result).encode()), 4096)
        self.assertEqual(_safe_patch_line("\x01" + "x" * 200)[:1], "?")

    def test_nonatomic_partial_prior_file_preserved_and_future_file_not_attempted(self):
        earlier = self.root / "one.txt"
        earlier.write_text("before\n")
        later = self.root / "three.txt"
        later.write_text("safe\n")
        result = dispatch(request(
            update(str(earlier), before="before", after="after")
            + update(str(self.original), before="absent")
            + update(str(later), before="safe", after="unsafe"),
            atomic=False,
        ))
        self.assertFalse(result["ok"], result)
        self.assertTrue(result["partial"])
        self.assertEqual(result["error"]["code"], "partial")
        self.assertEqual(result["error"]["failure_kind"], "context_mismatch")
        self.assertEqual([item["status"] for item in result["outcomes"]],
                         ["applied", "failed", "not_attempted"])
        self.assertEqual(earlier.read_text(), "after\n")
        self.assertEqual(self.original.read_bytes(), self.before)
        self.assertEqual(later.read_text(), "safe\n")

    def test_success_behavior_unchanged_and_crlf_preserved(self):
        self.original.write_bytes(b"first\r\nsecond\r\n")
        result = dispatch(request(update(str(self.original), before="second", after="new"),
                                  atomic=True))
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.original.read_bytes(), b"first\r\nnew\r\n")
        self.assertFalse(result["partial"])

    def test_permission_and_missing_paths_are_classified(self):
        with patch("app.file_helper.Path.read_bytes", side_effect=PermissionError):
            result = dispatch(request(update(str(self.original))))
        self.assertEqual(result["error"]["failure_kind"], "permission_denied")
        self.assertEqual(result["outcomes"][0]["status"], "failed")
        missing = self.root / "absent.txt"
        result = dispatch(request(update(str(missing))))
        self.assertEqual(result["error"]["failure_kind"], "not_found")
        self.assertEqual(self.original.read_bytes(), self.before)

    def test_no_raw_patch_context_persisted_in_file_audit(self):
        # Audit metadata is whitelisted: operation path leaves, failure codes
        # and per-file statuses only. The actual patch body and excerpts never
        # become searchable retained history.
        from app.file_audit import FileAudit
        from app.jobs import JobStore
        store = JobStore(self.root / "audit" / "jobs.sqlite")
        audit = FileAudit(store)
        operation = audit.start("alice", "dev3", "patch", str(self.original),
                                "TEST-247")
        error = dispatch(request(update(str(self.original),
                                        before="nonexistent-synthetic-token")))
        audit.finish(operation, "failed", error_code=error["error"]["code"],
                     outcomes=error["outcomes"])
        with store._connect() as db:
            saved = db.execute(
                "SELECT result_metadata FROM file_operations WHERE id=?",
                (operation,),
            ).fetchone()["result_metadata"]
        self.assertNotIn("nonexistent-synthetic-token", saved)
        self.assertNotIn("actual_excerpt", saved)

    def test_published_patch_contract_typed_roundtrip_matches_response(self):
        document = {t["name"]: t for t in contract_document()["tools"]}
        self.assertEqual(contract_document()["contract_version"], "1.9")
        self.assertIn("PatchConflictDiagnostic",
                      document["apply_patch"]["outputSchema"]["$defs"])
        raw = dispatch(request(update(str(self.original), before="missing")))
        wire = {"status": "failed", "operation_id": "synthetic-test-op",
                "history_id": "file_synthetic-test-op", "result": raw}
        typed = ApplyPatchResponse.model_validate(wire)
        self.assertEqual(typed.result.error.conflict.hunk, 1)
        self.assertEqual(typed.result.outcomes[0].failure_kind, "context_mismatch")
        self.assertEqual(
            ApplyPatchResponse.model_validate_json(typed.model_dump_json()).model_dump(),
            typed.model_dump(),
        )


if __name__ == "__main__":
    unittest.main()
