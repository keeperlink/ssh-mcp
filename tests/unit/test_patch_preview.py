"""TEST-248 PR1: preview/apply parity, strict immutability and metadata-only audit."""
from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.contracts import ApplyPatchRequest, ApplyPatchResponse, contract_document
from app.file_helper import dispatch


def wrap(body: str, **opts: object) -> dict:
    return {"protocol": 1, "operation": "patch",
            "patch": "*** Begin Patch\n" + body + "*** End Patch", **opts}


def edit(name: str, old: str, new: str, *, moved: str | None = None) -> str:
    return (f"*** Update File: {name}\n"
            + (f"*** Move to: {moved}\n" if moved else "")
            + f"@@\n-{old}\n+{new}\n")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class PreviewTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)
        self.source = self.root / "source.py"
        self.source.write_bytes(b"first\nsecond\nthird\n")
        self.other = self.root / "other.py"
        self.other.write_bytes(b"old\n")
        self.delete = self.root / "delete.py"
        self.delete.write_bytes(b"remove\n")
        self.add = self.root / "created.py"
        self.move = self.root / "moved.py"

    def state(self) -> dict[str, tuple[bytes, int, int, int, int]]:
        return {
            str(path): (path.read_bytes(), path.stat().st_mode,
                        path.stat().st_ino, path.stat().st_mtime_ns, path.stat().st_ctime_ns)
            for path in self.root.iterdir() if path.is_file()
        }

    def test_four_actions_all_previewed_without_mutation_and_apply_parity(self):
        before = self.state()
        body = ("*** Add File: created.py\n+added\n"
                + edit("source.py", "second", "replacement")
                + "*** Delete File: delete.py\n"
                + edit("other.py", "old", "new", moved="moved.py"))
        opts = {"base_dir": str(self.root), "atomic": True, "include_sha256": True,
                "expected_hashes": {"source.py": digest(self.source.read_bytes()),
                                    "other.py": digest(self.other.read_bytes()),
                                    "delete.py": digest(self.delete.read_bytes())}}
        planned = dispatch(wrap(body, dry_run=True, **opts))
        self.assertTrue(planned["ok"], planned)
        self.assertTrue(planned["dry_run"])
        self.assertEqual(planned["applicability"], "applicable")
        self.assertEqual([v["status"] for v in planned["outcomes"]], ["applicable"] * 4)
        self.assertEqual(planned["summary"]["total_paths"], 4)
        self.assertEqual(planned["summary"]["changed_paths"], 4)
        self.assertEqual(self.state(), before)
        self.assertFalse(self.add.exists())
        self.assertFalse(self.move.exists())
        self.assertEqual(planned["outcomes"][0]["prospective_sha256"], digest(b"added\n"))
        self.assertEqual(planned["outcomes"][1]["before_sha256"], digest(b"first\nsecond\nthird\n"))
        self.assertEqual(planned["outcomes"][1]["prospective_sha256"],
                         digest(b"first\nreplacement\nthird\n"))
        self.assertEqual(planned["outcomes"][3]["moved_to"], str(self.move))
        applied = dispatch(wrap(body, **opts))
        self.assertTrue(applied["ok"], applied)
        self.assertEqual(self.source.read_bytes(), b"first\nreplacement\nthird\n")
        self.assertEqual(self.add.read_bytes(), b"added\n")
        self.assertFalse(self.delete.exists())
        self.assertFalse(self.other.exists())
        self.assertEqual(self.move.read_bytes(), b"new\n")
        for path, actual in ((self.add, 0), (self.source, 1), (self.move, 3)):
            self.assertEqual(digest(path.read_bytes()),
                             planned["outcomes"][actual]["prospective_sha256"])

    def test_noop_preview_reports_unchanged_and_does_not_replace_inode(self):
        before = self.state()
        plan = dispatch(wrap(edit("source.py", "second", "second"),
                             base_dir=str(self.root), atomic=True,
                             dry_run=True, include_sha256=True))
        self.assertTrue(plan["ok"], plan)
        self.assertEqual(plan["outcomes"][0]["status"], "unchanged")
        self.assertEqual(plan["summary"]["changed_paths"], 0)
        self.assertEqual(plan["outcomes"][0]["prospective_sha256"],
                         digest(b"first\nsecond\nthird\n"))
        self.assertEqual(self.state(), before)

    def test_invalid_later_hunk_stops_preview_without_any_changes(self):
        before = self.state()
        plan = dispatch(wrap(
            edit("source.py", "second", "replacement") +
            edit("other.py", "nonexistent", "updated") +
            "*** Add File: created.py\n+never\n",
            base_dir=str(self.root), dry_run=True, atomic=True))
        self.assertFalse(plan["ok"], plan)
        self.assertFalse(plan["partial"])
        self.assertEqual(plan["applicability"], "not_applicable")
        self.assertEqual([x["status"] for x in plan["outcomes"]],
                         ["applicable", "failed", "not_attempted"])
        self.assertEqual(plan["error"]["failure_kind"], "context_mismatch")
        self.assertEqual(self.state(), before)
        self.assertFalse(self.add.exists())

    def test_collision_duplicated_targets_avoids_any_planning_or_writes(self):
        before = self.state()
        plan = dispatch(wrap(
            edit("source.py", "second", "a") +
            edit("source.py", "second", "b"),
            base_dir=str(self.root), dry_run=True))
        self.assertFalse(plan["ok"], plan)
        self.assertEqual(plan["error"]["failure_kind"], "overlapping_paths")
        self.assertEqual([x["status"] for x in plan["outcomes"]],
                         ["not_attempted", "failed"])
        self.assertEqual(self.state(), before)
        self.assertEqual(plan["summary"]["changed_paths"], 0)

    def test_move_collision_with_add_is_detected(self):
        plan = dispatch(wrap(
            edit("source.py", "first", "new", moved="created.py")
            + "*** Add File: created.py\n+collision\n",
            base_dir=str(self.root), dry_run=True))
        self.assertEqual(plan["error"]["failure_kind"], "overlapping_paths")
        self.assertFalse(self.move.exists())
        self.assertFalse(self.add.exists())

    def test_existing_move_destination_fails_without_mutation(self):
        before = self.state()
        result = dispatch(wrap(edit("source.py", "first", "new", moved="other.py"),
                               base_dir=str(self.root), dry_run=True))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "already_exists")
        self.assertEqual(self.state(), before)

    def test_unreadable_delete_does_not_disclose_bytes_or_diff(self):
        original = os.access
        def deny_read(path, mode, **options):
            if Path(path) == self.delete and mode == os.R_OK:
                return False
            return original(path, mode, **options)
        with patch("app.file_helper.os.access", side_effect=deny_read):
            result = dispatch(wrap("*** Delete File: delete.py\n",
                                   base_dir=str(self.root), dry_run=True,
                                   include_diff=True, include_sha256=True))
        self.assertTrue(result["ok"], result)
        outcome = result["outcomes"][0]
        self.assertNotIn("before_sha256", outcome)
        self.assertNotIn("diff", outcome)
        self.assertNotIn("removed_lines", outcome)
        self.assertEqual(self.delete.read_bytes(), b"remove\n")

    def test_nonatomic_update_denied_write_without_mutation(self):
        before = self.state()
        original = os.access
        def deny_target_write(path, mode, **options):
            if Path(path) == self.source and mode == os.W_OK:
                return False
            return original(path, mode, **options)
        with patch("app.file_helper.os.access", side_effect=deny_target_write):
            result = dispatch(wrap(edit("source.py", "second", "new"),
                                   base_dir=str(self.root), dry_run=True))
        self.assertEqual(result["error"]["code"], "permission_denied")
        self.assertEqual(self.state(), before)

    def test_atomic_update_denied_parent_write_without_mutation(self):
        original = os.access
        def deny_parent_write(path, mode, **options):
            if Path(path) == self.root and mode == os.W_OK:
                return False
            return original(path, mode, **options)
        with patch("app.file_helper.os.access", side_effect=deny_parent_write):
            result = dispatch(wrap(edit("source.py", "second", "new"),
                                   base_dir=str(self.root), dry_run=True, atomic=True))
        self.assertEqual(result["error"]["code"], "permission_denied")
        self.assertEqual(self.source.read_bytes(), b"first\nsecond\nthird\n")

    def test_parent_is_not_directory(self):
        result = dispatch(wrap("*** Add File: source.py/child.txt\n+new\n",
                               base_dir=str(self.root), dry_run=True))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "not_found")

    def test_deleted_target_missing_and_no_mutation(self):
        result = dispatch(wrap("*** Delete File: absent.txt\n",
                               base_dir=str(self.root), dry_run=True))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "not_found")
        self.assertEqual(self.source.read_bytes(), b"first\nsecond\nthird\n")

    def test_missing_expected_hash_precondition_classification(self):
        result = dispatch(wrap(edit("absent.txt", "old", "new"),
                               base_dir=str(self.root), dry_run=True,
                               expected_hashes={"absent.txt": "a" * 64}))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["failure_kind"], "missing_file")
        self.assertEqual(result["error"]["conflict"]["actual_excerpt"], [])

    def test_unreadable_update_fails_closed_without_revealing_contents(self):
        original = os.access
        def deny_read(path, mode, **options):
            if Path(path) == self.source and mode == os.R_OK:
                return False
            return original(path, mode, **options)
        with patch("app.file_helper.os.access", side_effect=deny_read):
            result = dispatch(wrap(edit("source.py", "second", "new"),
                                   base_dir=str(self.root), dry_run=True))
        self.assertEqual(result["error"]["code"], "permission_denied")
        self.assertNotIn("actual_excerpt", str(result))

    def test_bounded_diff_on_large_patch_has_no_memory_spike(self):
        text = "".join(f"line-{i}\n" for i in range(10005)) + "old-last\n"
        self.source.write_text(text)
        result = dispatch(wrap(edit("source.py", "old-last", "new-last"),
                               base_dir=str(self.root), dry_run=True, include_diff=True))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["outcomes"][0]["diff"], "")
        self.assertTrue(result["outcomes"][0]["diff_truncated"])
        self.assertIn("old-last\n", self.source.read_text())

    def test_dry_run_with_create_parents_never_mkdir(self):
        nested = self.root / "absent" / "nested"
        with patch("app.file_helper.Path.mkdir", side_effect=AssertionError("mkdir forbidden")), \
             patch("app.file_helper._publish", side_effect=AssertionError("publish forbidden")):
            result = dispatch(wrap("*** Add File: absent/nested/new.txt\n+new\n",
                                   base_dir=str(self.root), dry_run=True,
                                   create_parents=True, atomic=True))
        self.assertTrue(result["ok"], result)
        self.assertFalse(nested.exists())
        self.assertEqual(result["outcomes"][0]["status"], "applicable")

    def test_noncreate_missing_directory_fails_without_mutation(self):
        result = dispatch(wrap("*** Add File: absent/new.txt\n+new\n",
                               base_dir=str(self.root), dry_run=True))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "not_found")
        self.assertFalse((self.root / "absent").exists())

    def test_stale_preview_is_advisory_and_real_apply_rechecks_hash(self):
        previous = digest(self.source.read_bytes())
        patch_body = edit("source.py", "second", "replacement")
        plan = dispatch(wrap(patch_body, dry_run=True, atomic=True,
                             base_dir=str(self.root),
                             expected_hashes={"source.py": previous}))
        self.assertTrue(plan["ok"])
        self.source.write_text("first\nsecond\nthird\nexternal\n")
        actual = dispatch(wrap(patch_body, base_dir=str(self.root), atomic=True,
                               expected_hashes={"source.py": previous}))
        self.assertFalse(actual["ok"], actual)
        self.assertEqual(actual["error"]["failure_kind"], "hash_mismatch")
        self.assertEqual(self.source.read_text(), "first\nsecond\nthird\nexternal\n")

    def test_optional_diff_is_redacted_bounded_and_explicit(self):
        self.source.write_text("password=example-secret-value\nsafe\n")
        without = dispatch(wrap(edit("source.py", "safe", "changed"),
                                base_dir=str(self.root), dry_run=True))
        self.assertNotIn("diff", without["outcomes"][0])
        with_diff = dispatch(wrap(edit("source.py", "safe", "changed"),
                                  base_dir=str(self.root), dry_run=True,
                                  include_diff=True, max_diff_bytes=1000))
        text = with_diff["outcomes"][0]["diff"]
        self.assertIn("[REDACTED]", text)
        self.assertNotIn("example-secret-value", text)
        self.assertIn("+changed", text)
        limited = dispatch(wrap(edit("source.py", "safe", "changed"),
                                base_dir=str(self.root), dry_run=True,
                                include_diff=True, max_diff_bytes=8))
        self.assertTrue(limited["outcomes"][0]["diff_truncated"])

    def test_changed_diff_lines_mimicking_headers_are_always_redacted(self):
        # Difflib prefixes deleted/added content with -/+; source lines
        # beginning with -- or ++ must not be mistaken for file headers.
        original = ("--password=PRIVATE_OLD_VALUE\n"
                    "++token=PRIVATE_OLD_TOKEN\n")
        self.source.write_text(original)
        body = ("*** Update File: source.py\n@@\n"
                "---password=PRIVATE_OLD_VALUE\n"
                "+--password=PRIVATE_NEW_VALUE\n"
                "-++token=PRIVATE_OLD_TOKEN\n"
                "+++token=PRIVATE_NEW_TOKEN\n")
        result = dispatch(wrap(body, base_dir=str(self.root), dry_run=True,
                               include_diff=True, max_diff_bytes=4096))
        self.assertTrue(result["ok"], result)
        snippet = result["outcomes"][0]["diff"]
        self.assertIn("-[REDACTED]", snippet)
        self.assertIn("+[REDACTED]", snippet)
        for secret in ("PRIVATE_OLD_VALUE", "PRIVATE_NEW_VALUE",
                       "PRIVATE_OLD_TOKEN", "PRIVATE_NEW_TOKEN"):
            self.assertNotIn(secret, snippet)
        self.assertEqual(self.source.read_text(), original)

    def test_gigabyte_sparse_delete_never_reads_file_without_optional_hash(self):
        huge = self.root / "huge-sparse.log"
        with huge.open("wb") as output:
            output.truncate(2 * 1024 ** 3)
        before = huge.stat()
        body = "*** Delete File: huge-sparse.log\n"
        with patch("app.file_helper.Path.open",
                   side_effect=AssertionError("Delete preview must not open large files")), \
             patch("app.file_helper.Path.read_bytes",
                   side_effect=AssertionError("Delete preview must not read file bytes")):
            no_diff = dispatch(wrap(body, base_dir=str(self.root), dry_run=True))
            with_diff = dispatch(wrap(
                body, base_dir=str(self.root), dry_run=True,
                include_diff=True, max_diff_bytes=2048,
            ))
        for preview in (no_diff, with_diff):
            self.assertTrue(preview["ok"], preview)
            self.assertEqual(preview["outcomes"][0]["status"], "applicable")
            self.assertNotIn("removed_lines", preview["outcomes"][0])
            self.assertIsNone(preview["summary"]["removed_lines"])
            self.assertFalse(preview["summary"]["line_counts_complete"])
        self.assertNotIn("diff", no_diff["outcomes"][0])
        self.assertNotIn("diff", with_diff["outcomes"][0])
        self.assertTrue(with_diff["outcomes"][0]["diff_truncated"])
        after = huge.stat()
        self.assertEqual(
            (before.st_size, before.st_ino, before.st_mtime_ns, before.st_ctime_ns),
            (after.st_size, after.st_ino, after.st_mtime_ns, after.st_ctime_ns),
        )

    def test_delete_preview_streams_optional_sha_without_read_bytes(self):
        target = self.root / "large-delete.txt"
        content = b"safe line\n" * (1024 * 750)
        target.write_bytes(content)
        with patch("app.file_helper.Path.read_bytes",
                   side_effect=AssertionError("Stream SHA; no read_bytes")):
            result = dispatch(wrap(
                "*** Delete File: large-delete.txt\n",
                base_dir=str(self.root), dry_run=True, include_sha256=True,
            ))
        self.assertTrue(result["ok"], result)
        outcome = result["outcomes"][0]
        self.assertEqual(outcome["before_sha256"], hashlib.sha256(content).hexdigest())
        self.assertNotIn("diff", outcome)
        self.assertNotIn("removed_lines", outcome)
        self.assertIsNone(result["summary"]["removed_lines"])
        self.assertEqual(target.stat().st_size, len(content))

    def test_small_delete_opt_in_diff_and_known_line_counts(self):
        self.delete.write_text("line one\nline two\n")
        result = dispatch(wrap(
            "*** Delete File: delete.py\n",
            base_dir=str(self.root), dry_run=True, include_diff=True,
            include_sha256=True,
        ))
        self.assertTrue(result["ok"], result)
        outcome = result["outcomes"][0]
        self.assertEqual(outcome["removed_lines"], 2)
        self.assertEqual(outcome["before_sha256"], digest(b"line one\nline two\n"))
        self.assertIn("-line one", outcome["diff"])
        self.assertTrue(result["summary"]["line_counts_complete"])
        self.assertEqual(result["summary"]["removed_lines"], 2)
        self.assertEqual(self.delete.read_text(), "line one\nline two\n")

    def test_no_diff_without_file_read_authorization(self):
        # Pretend the SSH identity cannot read parent content while it can
        # still add files. Preview must not expose the user-supplied add diff.
        original_access = os.access
        def access(path, mode, **kwargs):
            if Path(path) == self.root and mode == os.R_OK:
                return False
            return original_access(path, mode, **kwargs)
        with patch("app.file_helper.os.access", side_effect=access):
            result = dispatch(wrap("*** Add File: created.py\n+new\n",
                                   base_dir=str(self.root), dry_run=True, include_diff=True))
        self.assertTrue(result["ok"], result)
        self.assertNotIn("diff", result["outcomes"][0])

    def test_preview_never_follows_dangling_symlink_as_add(self):
        link = self.root / "link.txt"
        link.symlink_to(self.root / "absent")
        before = os.readlink(link)
        result = dispatch(wrap("*** Add File: link.txt\n+created\n",
                               base_dir=str(self.root), dry_run=True))
        self.assertEqual(result["error"]["code"], "already_exists")
        self.assertEqual(os.readlink(link), before)

    def test_invalid_preview_options_fail_closed(self):
        for opts in ({"dry_run": "true"}, {"dry_run": True, "include_diff": "yes"},
                     {"dry_run": True, "max_diff_bytes": 0},
                     {"include_diff": True}, {"dry_run": True, "max_diff_bytes": 16385}):
            with self.subTest(opts=opts):
                result = dispatch(wrap(edit("source.py", "second", "new"),
                                       base_dir=str(self.root), **opts))
                self.assertFalse(result["ok"])
                self.assertEqual(result["error"]["code"], "invalid_request")

    def test_preview_contract_1_7_typed_response(self):
        doc = contract_document()
        self.assertEqual(doc["contract_version"], "2.0")
        schema = next(x for x in doc["tools"] if x["name"] == "apply_patch")
        self.assertIn("dry_run", schema["inputSchema"]["properties"])
        self.assertIn("max_diff_bytes", schema["inputSchema"]["properties"])
        req = ApplyPatchRequest(server="demo-node-b", reason="test",
                                patch="*** Begin Patch\n*** Add File: abc\n+x\n*** End Patch",
                                dry_run=True)
        self.assertEqual(req.dry_run, True)
        preview = dispatch(wrap(edit("source.py", "second", "new"),
                                base_dir=str(self.root), dry_run=True))
        typed = ApplyPatchResponse.model_validate({
            "status": "succeeded", "operation_id": "pr1-preview",
            "history_id": "file_pr1-preview", "result": preview,
        })
        self.assertEqual(typed.result.applicability, "applicable")
        self.assertEqual(ApplyPatchResponse.model_validate_json(
            typed.model_dump_json()).model_dump(), typed.model_dump())


class PreviewAuditTests(unittest.IsolatedAsyncioTestCase):
    async def test_preview_is_classified_as_preview_not_write_and_never_persisted(self):
        from app.file_ops import FileService
        from app.jobs import JobStore
        from app.history import HistoryStore
        from app.ssh_executor import SSHExecutor, HostSpec
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            key, known = directory / "key", directory / "known_hosts"
            key.write_text("test")
            known.write_text("test")
            key.chmod(0o600)
            known.chmod(0o644)
            host = HostSpec(alias="dev", address="127.0.0.1", port=22,
                            username="gateway", identity_file=key,
                            known_hosts_file=known, principals=["alice"],
                            environment="non-production", access="always-granted")
            class PreviewTransport:
                async def execute(self, actor, server, kind, data):
                    self.kind, self.body = kind, data
                    return {"ok": True, "dry_run": True, "applicability": "applicable",
                            "partial": False, "bytes": 0, "outcomes": [{
                                "path": str(directory / "test.txt"), "action": "update",
                                "status": "applicable", "bytes": 5,
                                "diff": "SENSITIVE_NOT_PERSISTED"
                            }]}
            transport = PreviewTransport()
            store = JobStore(directory / "private" / "jobs.sqlite")
            executor = SSHExecutor({"dev": host}, enabled=True)
            service = FileService(executor, store, transport=transport)
            req = ApplyPatchRequest(
                server="dev", reason="synthetic", story_id="TEST-248",
                patch="*** Begin Patch\n*** Add File: a.txt\n+new\n*** End Patch",
                dry_run=True,
            )
            result = await service.perform("alice", req, "patch_preview",
                                           {"patch": req.patch, "dry_run": True})
            self.assertEqual(result["status"], "succeeded")
            self.assertEqual(transport.kind, "patch")
            self.assertEqual(transport.body["dry_run"], True)
            item = HistoryStore(store).detail(result["history_id"])
            self.assertEqual(item["operation_kind"], "patch_preview")
            self.assertEqual(item["file_metadata"]["outcomes"][0]["status"], "applicable")
            listing = HistoryStore(store).list({
                "record_kind": "file", "story_id": "TEST-248",
            })["jobs"]
            self.assertEqual(len(listing), 1)
            self.assertEqual(listing[0]["id"], result["history_id"])
            self.assertEqual(listing[0]["operation_kind"], "patch_preview")
            with store._connect() as db:
                content = "\n".join(db.iterdump())
            self.assertNotIn("SENSITIVE_NOT_PERSISTED", content)
            self.assertNotIn("*** Begin Patch", content)


if __name__ == "__main__":
    unittest.main()
