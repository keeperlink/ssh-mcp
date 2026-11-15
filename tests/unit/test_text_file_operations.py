"""TEST-236 local helper semantics; synthetic temporary files only."""
from __future__ import annotations

import hashlib
import io
import base64
import json
from unittest.mock import patch
from pathlib import Path
import tempfile
import unittest

from app.file_helper import dispatch


def request(operation: str, **params):
    return dispatch({"protocol": 1, "operation": operation, **params})


class TextFileTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)

    def test_chunked_read_cursor_detects_change_and_eof(self):
        file = self.root / "huge.txt"
        original = "".join(f"line {i:04d} café\n" for i in range(300))
        file.write_text(original)
        pieces = []
        cursor = None
        while True:
            reply = request("read", path=str(file), server="dev",
                            max_bytes=37, **({"cursor": cursor} if cursor else {}))
            self.assertTrue(reply["ok"], reply)
            self.assertLessEqual(reply["bytes"], 37)
            pieces.append(reply["content"])
            if reply["eof"]:
                self.assertIsNone(reply["next_cursor"])
                break
            self.assertTrue(reply["truncated"])
            cursor = reply["next_cursor"]
            self.assertIsNotNone(cursor)
        self.assertEqual("".join(pieces), original)
        first = request("read", path=str(file), server="dev", max_bytes=12,
                        include_sha256=True)
        self.assertEqual(first["sha256"], hashlib.sha256(file.read_bytes()).hexdigest())
        self.assertFalse(first["eof"])
        self.assertEqual(request("read", path=str(file), server="other",
                         cursor=first["next_cursor"])["error"]["code"], "invalid_cursor")
        file.write_text(original + "changed")
        self.assertEqual(request("read", path=str(file), server="dev",
                         cursor=first["next_cursor"])["error"]["code"], "changed_file")

    def test_read_lines_and_invalid_encoding(self):
        file = self.root / "lines.txt"
        file.write_bytes(b"first\nsecond\nthird\nfourth\n")
        result = request("read", path=str(file), start_line=2, end_line=3)
        self.assertTrue(result["ok"])
        self.assertEqual(result["content"], "second\nthird\n")
        self.assertTrue(result["eof"])
        file.write_bytes(b"\xff\xfe\x80")
        self.assertEqual(request("read", path=str(file))["error"]["code"], "invalid_encoding")

    def test_create_replace_append_parent_and_hash(self):
        target = self.root / "nested" / "data.txt"
        self.assertEqual(request("write", path=str(target), content="test",
                                 mode="create")["error"]["code"], "not_found")
        added = request("write", path=str(target), content="one\n", mode="create",
                        create_parents=True, include_sha256=True)
        self.assertTrue(added["ok"])
        self.assertEqual(added["sha256"], hashlib.sha256(target.read_bytes()).hexdigest())
        self.assertEqual(request("write", path=str(target), content="bad", mode="create"
                                 )["error"]["code"], "already_exists")
        appended = request("write", path=str(target), content="two", mode="append",
                           include_sha256=True)
        self.assertTrue(appended["ok"])
        self.assertEqual(target.read_text(), "one\ntwo")
        self.assertEqual(appended["sha256"], hashlib.sha256(b"one\ntwo").hexdigest())
        self.assertEqual(request("write", path=str(target), content="bad",
                                 expected_sha256="0" * 64)["error"]["code"],
                         "precondition_failed")
        self.assertTrue(request("write", path=str(target), content="new", mode="replace",
                                include_sha256=True)["ok"])
        self.assertEqual(target.read_text(), "new")
        self.assertEqual(request("write", path=str(self.root / "fresh.txt"),
                                 content="hello", mode="append")["ok"], True)

    def test_inplace_atomic_and_symlink(self):
        target = self.root / "target"
        link = self.root / "link"
        target.write_text("old")
        link.symlink_to(target)
        inode = target.stat().st_ino
        self.assertTrue(request("write", path=str(link), mode="replace", content="new")["ok"])
        self.assertTrue(link.is_symlink())
        self.assertEqual(target.stat().st_ino, inode)
        self.assertTrue(request("write", path=str(target), mode="replace",
                                content="replaced", atomic=True)["ok"])
        self.assertNotEqual(target.stat().st_ino, inode)
        self.assertTrue(request("write", path=str(link), mode="replace",
                                content="separate", atomic=True)["ok"])
        self.assertFalse(link.is_symlink())
        self.assertEqual(target.read_text(), "replaced")

    def test_multifile_patch_success_and_first_failure_outcomes(self):
        first = self.root / "first.txt"
        first.write_text("a\nb\nc\n")
        patch_text = (f"*** Begin Patch\n*** Update File: {first}\n@@\n a\n-b\n+B\n c\n"
                      f"*** Add File: {self.root / 'second.txt'}\n+hello\n+world\n"
                      f"*** End Patch")
        good = request("patch", path=".", patch=patch_text, include_sha256=True)
        self.assertTrue(good["ok"], good)
        self.assertEqual(first.read_text(), "a\nB\nc\n")
        self.assertEqual((self.root / "second.txt").read_text(), "hello\nworld\n")
        self.assertEqual(len(good["outcomes"]), 2)
        failed = request("patch", path=".",
                         patch=(f"*** Begin Patch\n*** Delete File: {first}\n"
                                f"*** Delete File: {self.root / 'notthere'}\n"
                                f"*** Add File: {self.root / 'later.txt'}\n+x\n*** End Patch"))
        self.assertFalse(failed["ok"])
        self.assertTrue(failed["partial"])
        self.assertEqual([item["status"] for item in failed["outcomes"]],
                         ["applied", "failed", "not_attempted"])
        self.assertFalse(first.exists())
        self.assertFalse((self.root / "later.txt").exists())

    def test_patch_preserves_bom_crlf_and_move(self):
        original = self.root / "original.txt"
        moved = self.root / "moved.txt"
        original.write_bytes(b"\xef\xbb\xbfone\r\ntwo\r\n")
        result = request("patch", path=".",
                         patch=(f"*** Begin Patch\n*** Update File: {original}\n"
                                f"*** Move to: {moved}\n@@\n one\n-two\n+TWO\n*** End Patch"))
        self.assertTrue(result["ok"], result)
        self.assertFalse(original.exists())
        self.assertEqual(moved.read_bytes(), b"\xef\xbb\xbfone\r\nTWO\r\n")

    def test_patch_errors_no_content_returned(self):
        bad = request("patch", path=".", patch="print('not a patch')")
        self.assertEqual(bad["error"]["code"], "invalid_patch")
        target = self.root / "a"
        target.write_text("secret")
        stale = request("patch", path=".",
                        patch=f"*** Begin Patch\n*** Update File: {target}\n@@\n-incorrect\n+new\n*** End Patch")
        self.assertFalse(stale["ok"])
        self.assertEqual(stale["outcomes"][0]["error_code"], "precondition_failed")
        self.assertNotIn("secret", str(stale))
        self.assertEqual(target.read_text(), "secret")

    def test_utf16_bom_and_cursor_direct_reuse(self):
        for codec in ("utf-16", "utf-16-le", "utf-16-be", "utf-8-sig"):
            with self.subTest(codec=codec):
                target = self.root / f"format-{codec}.txt"
                source = "alpha\nbéta\ngamma\n"
                target.write_bytes(source.encode(codec))
                pieces = []
                cursor = None
                for _ in range(120):
                    args = {"path": str(target), "server": "dev", "max_bytes": 9}
                    if cursor:
                        args["cursor"] = cursor
                    else:
                        args["encoding"] = codec
                    reply = request("read", **args)
                    self.assertTrue(reply["ok"], reply)
                    pieces.append(reply["content"])
                    if reply["eof"]:
                        break
                    cursor = reply["next_cursor"]
                else:
                    self.fail("No cursor progress for encoded file")
                self.assertEqual("".join(pieces), source)
                result = request("read", path=str(target), encoding=codec,
                                 start_line=2, end_line=2)
                self.assertTrue(result["ok"], result)
                self.assertEqual(result["content"], "béta\n")

    def test_long_paths_have_bounded_reusable_cursors(self):
        folder = self.root
        for index in range(14):
            folder = folder / (f"segment{index:02d}-" + "x" * 160)
        folder.mkdir(parents=True)
        target = folder / "long-file.txt"
        target.write_text("first\nsecond\nthird\n")
        self.assertGreater(len(str(target)), 2048)
        first = request("read", path=str(target), server="dev", max_bytes=7)
        self.assertTrue(first["ok"], first.get("error"))
        self.assertLess(len(first["next_cursor"]), 2048)
        second = request("read", path=str(target), server="dev",
                         cursor=first["next_cursor"])
        self.assertTrue(second["ok"], second.get("error"))
        self.assertEqual(first["content"] + second["content"], target.read_text())

    def test_small_read_must_not_split_text_bom(self):
        for codec, text in (("utf-8-sig", "hello"), ("utf-16", "hello")):
            with self.subTest(codec=codec):
                target = self.root / ("bom-" + codec)
                target.write_bytes(text.encode(codec))
                for size in (1, 2) if codec == "utf-8-sig" else (1,):
                    result = request("read", path=str(target), encoding=codec,
                                     max_bytes=size)
                    self.assertFalse(result["ok"], result)
                    self.assertEqual(result["error"]["code"], "response_limit")
                enough = request("read", path=str(target), encoding=codec, max_bytes=4)
                self.assertTrue(enough["ok"], enough)
                self.assertTrue(enough["content"])
                self.assertLess(len(enough["next_cursor"]), 2048)

    def test_json_output_budget_long_line_and_codepoints(self):
        target = self.root / "long.txt"
        text = "\x00" * 49000 + "🚀" * 10000 + "\n"
        target.write_text(text)
        response = request("read", path=str(target), max_bytes=131072)
        self.assertTrue(response["ok"], response.get("error"))
        self.assertLess(len(json.dumps(response).encode()), 262144)
        self.assertTrue(response["truncated"])
        cursor = response["next_cursor"]
        self.assertTrue(cursor)
        pieces = [response["content"]]
        for _ in range(30):
            response = request("read", path=str(target), cursor=cursor,
                               max_bytes=131072)
            self.assertTrue(response["ok"], response.get("error"))
            pieces.append(response["content"])
            if response["eof"]:
                break
            self.assertNotEqual(response["next_cursor"], cursor)
            cursor = response["next_cursor"]
        else:
            self.fail("Large escaped text did not advance")
        self.assertEqual("".join(pieces), text)

    def test_read_invalid_options_and_cursors(self):
        target = self.root / "short"
        target.write_bytes(b"one\ntwo")
        for options in (
            {"max_bytes": 0}, {"max_bytes": 131073},
            {"start_line": 0}, {"end_line": 0},
            {"start_line": 3, "end_line": 2},
        ):
            with self.subTest(options=options):
                self.assertEqual(request("read", path=str(target), **options)["error"]["code"],
                                 "invalid_request")
        for cursor in (123, "", "not base64!", base64.urlsafe_b64encode(b"[]").decode()):
            self.assertEqual(request("read", path=str(target), cursor=cursor)["error"]["code"],
                             "invalid_cursor")
        first = request("read", path=str(target), server="dev", max_bytes=2)
        self.assertTrue(first["ok"])
        token = first["next_cursor"]
        parsed = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
        for item, value in (("offset", -1), ("line", 0), ("path_sha256", "0" * 64)):
            changed = dict(parsed, **{item: value})
            forged = base64.urlsafe_b64encode(json.dumps(changed).encode()).decode()
            self.assertEqual(request("read", path=str(target), server="dev",
                                     cursor=forged)["error"]["code"], "invalid_cursor")
        self.assertEqual(request("read", path=str(target), max_bytes=1,
                                 start_line=9)["bytes"], 0)
        self.assertEqual(request("read", path=str(target), encoding="latin1"
                                 )["error"]["code"], "invalid_encoding")
        target.write_text("é")
        self.assertEqual(request("read", path=str(target), max_bytes=1)["error"]["code"],
                         "response_limit")
        self.assertEqual(request("read", path=str(self.root / "missing"))["error"]["code"],
                         "not_found")
        self.assertEqual(request("read", path=str(self.root))["error"]["code"],
                         "invalid_request")

    def test_write_flags_formats_and_preconditions(self):
        target = self.root / "writing.txt"
        for options in (
            {"mode": "invalid"}, {"atomic": "yes"}, {"create_parents": "true"},
            {"mode": "append", "atomic": True}, {"newline": "bogus"},
            {"encoding": "latin1"}, {"expected_sha256": "bad"},
        ):
            with self.subTest(options=options):
                result = request("write", path=str(target), content="hi", **options)
                self.assertFalse(result["ok"])
        self.assertEqual(request("write", path=str(target), content=4)["error"]["code"],
                         "invalid_request")
        self.assertEqual(request("write", path=str(target), content="bad",
                                 expected_sha256="0" * 64)["error"]["code"],
                         "precondition_failed")
        self.assertEqual(request("write", path=str(target), content="\ud800"
                                 )["error"]["code"], "invalid_encoding")
        result = request("write", path=str(target), content="a\nb\n",
                         mode="create", encoding="utf-16", newline="crlf",
                         include_sha256=True)
        self.assertTrue(result["ok"], result)
        self.assertEqual(target.read_bytes(), "a\r\nb\r\n".encode("utf-16"))
        self.assertEqual(result["sha256"], hashlib.sha256(target.read_bytes()).hexdigest())
        self.assertEqual(request("write", path=str(target), mode="replace",
                                 content="a\nb", newline="lf")["ok"], True)
        self.assertEqual(target.read_bytes(), b"a\nb")
        fresh = self.root / "new-atomic"
        self.assertTrue(request("write", path=str(fresh), content="x",
                                mode="create", atomic=True)["ok"])
        self.assertEqual(request("write", path=str(fresh), content="y",
                                 mode="create", atomic=True)["error"]["code"],
                         "already_exists")

    def test_patch_context_move_only_conflicts(self):
        target = self.root / "scope.txt"
        target.write_text("begin\nneedle\nold\nend\n")
        changed = request("patch", path=".", patch=(
            f"*** Begin Patch\n*** Update File: {target}\n"
            "@@ needle\n-old\n+new\n*** End Patch"))
        self.assertTrue(changed["ok"], changed)
        self.assertEqual(target.read_text(), "begin\nneedle\nnew\nend\n")
        moved = self.root / "nested" / "relocated.txt"
        move = request("patch", path=".", create_parents=True, patch=(
            f"*** Begin Patch\n*** Update File: {target}\n"
            f"*** Move to: {moved}\n*** End Patch"))
        self.assertTrue(move["ok"], move)
        self.assertEqual(moved.read_text(), "begin\nneedle\nnew\nend\n")
        self.assertFalse(target.exists())
        conflict = request("patch", path=".", patch=(
            f"*** Begin Patch\n*** Add File: {moved}\n+conflict\n*** End Patch"))
        self.assertEqual(conflict["outcomes"][0]["error_code"], "already_exists")
        self.assertEqual(moved.read_text(), "begin\nneedle\nnew\nend\n")
        self.assertEqual(request("patch", path=".", patch=(
            f"*** Begin Patch\n*** Update File: {moved}\n"
            "@@ absent\n-old\n+new\n*** End Patch"
        ))["outcomes"][0]["error_code"], "precondition_failed")

    def test_patch_format_errors_and_partial_OS_failure(self):
        target = self.root / "file"
        target.write_text("hello\n")
        invalid = (
            "*** Begin Patch\nno-file\n*** End Patch",
            "*** Begin Patch\n*** End Patch",
            f"*** Begin Patch\n*** Update File: {target}\n*** End Patch",
            f"*** Begin Patch\n*** Update File: {target}\n!bad\n*** End Patch",
            f"*** Begin Patch\n*** Add File: {target}\ninvalid\n*** End Patch",
        )
        for body in invalid:
            with self.subTest(body=body):
                self.assertEqual(request("patch", path=".", patch=body)["error"]["code"],
                                 "invalid_patch")
        first = self.root / "new"
        result = request("patch", path=".", patch=(
            f"*** Begin Patch\n*** Add File: {first}\n+yes\n"
            f"*** Delete File: {self.root}\n*** Add File: {self.root / 'third'}\n+late\n"
            "*** End Patch"))
        self.assertEqual([x["status"] for x in result["outcomes"]],
                         ["applied", "failed", "not_attempted"])
        self.assertTrue(result["partial"])
        self.assertEqual(result["outcomes"][1]["error_code"], "filesystem_error")
        self.assertFalse((self.root / "third").exists())
        bad = request("patch", path=".", patch=(
            f"*** Begin Patch\n*** Delete File: {self.root / 'notfound'}\n*** End Patch"))
        self.assertEqual(bad["outcomes"][0]["error_code"], "not_found")

    def test_patch_bom_no_final_newline_expected_hash(self):
        target = self.root / "utf16"
        target.write_bytes("foo\r\nbar".encode("utf-16"))
        stale = request("patch", path=".", expected_hashes={str(target): "0" * 64},
                        patch=(f"*** Begin Patch\n*** Update File: {target}\n"
                               "@@\n-foo\n+FOO\n*** End Patch"))
        self.assertEqual(stale["outcomes"][0]["error_code"], "precondition_failed")
        good = request("patch", path=".", atomic=True, include_sha256=True,
                       expected_hashes={str(target): hashlib.sha256(target.read_bytes()).hexdigest()},
                       patch=(f"*** Begin Patch\n*** Update File: {target}\n"
                              "@@\n-foo\n+FOO\n\\ No newline at end of file\n*** End Patch"))
        self.assertTrue(good["ok"], good)
        self.assertEqual(target.read_bytes(), "FOO\r\nbar".encode("utf-16"))
        self.assertEqual(good["outcomes"][0]["sha256"],
                         hashlib.sha256(target.read_bytes()).hexdigest())


    def test_utf16_big_endian_and_missing_bom(self):
        target = self.root / "utf16be.txt"
        text = "un\ndeux\ntrois\n"
        target.write_bytes(b"\xfe\xff" + text.encode("utf-16-be"))
        first = request("read", path=str(target), encoding="utf-16",
                        max_bytes=8, end_line=2)
        self.assertTrue(first["ok"], first)
        second = request("read", path=str(target), cursor=first["next_cursor"],
                         max_bytes=12)
        self.assertTrue(second["ok"], second)
        self.assertTrue(second["eof"])
        self.assertEqual(first["content"] + second["content"], "un\ndeux\n")
        plain = self.root / "no-bom"
        plain.write_bytes(text.encode("utf-16-be"))
        self.assertEqual(request("read", path=str(plain),
                                 encoding="utf-16")["error"]["code"], "invalid_encoding")
        self.assertTrue(request("read", path=str(plain),
                                encoding="utf-16-be")["ok"])
        self.assertTrue(request("read", path=str(self.root / "short"),
                                encoding="utf-8-sig")["error"]["code"] == "not_found")
        ascii_target = self.root / "plain"
        ascii_target.write_text("plain text")
        self.assertEqual(request("read", path=str(ascii_target),
                                 encoding="utf-8-sig")["content"], "plain text")

    def test_patch_explicit_encoding_newline_conversion(self):
        created = self.root / "new-encoded.txt"
        result = request("patch", path=".", encoding="utf-16",
                         newline="crlf", patch=(
                             f"*** Begin Patch\n*** Add File: {created}\n"
                             "+first\n+second\n*** End Patch"))
        self.assertTrue(result["ok"], result)
        self.assertEqual(created.read_bytes(), "first\r\nsecond\r\n".encode("utf-16"))
        changed = request("patch", path=".", encoding="utf-8-sig",
                          newline="lf", patch=(
                              f"*** Begin Patch\n*** Update File: {created}\n"
                              "@@\n-first\n+FIRST\n*** End Patch"))
        self.assertTrue(changed["ok"], changed)
        self.assertEqual(created.read_bytes(), "FIRST\nsecond\n".encode("utf-8-sig"))
        self.assertEqual(request("patch", path=".", newline="not-an-option",
                                 patch=(f"*** Begin Patch\n"
                                        f"*** Delete File: {created}\n*** End Patch")
                                 )["error"]["code"], "invalid_request")

    def test_patch_insertion_without_context_and_missing_parent(self):
        target = self.root / "add-context.txt"
        target.write_text("top\nbottom\n")
        result = request("patch", path=".", patch=(
            f"*** Begin Patch\n*** Update File: {target}\n+new-first\n"
            "*** End Patch"))
        self.assertTrue(result["ok"], result)
        self.assertEqual(target.read_text(), "new-first\ntop\nbottom\n")
        target2 = self.root / "deep" / "new.txt"
        added = request("patch", path=".", create_parents=True, patch=(
            f"*** Begin Patch\n*** Add File: {target2}\n+data\n*** End Patch"))
        self.assertTrue(added["ok"], added)
        self.assertEqual(target2.read_text(), "data\n")
        source = self.root / "moving"
        source.write_text("source")
        dest = self.root / "destination"
        dest.write_text("existing")
        move = request("patch", path=".", patch=(
            f"*** Begin Patch\n*** Update File: {source}\n"
            f"*** Move to: {dest}\n*** End Patch"))
        self.assertEqual(move["outcomes"][0]["error_code"], "already_exists")
        self.assertEqual(source.read_text(), "source")

    def test_patch_invalid_options_size_and_encoded_content(self):
        target = self.root / "input"
        target.write_bytes(b"invalid\xffbytes")
        p = f"*** Begin Patch\n*** Update File: {target}\n@@\n-old\n+new\n*** End Patch"
        self.assertEqual(request("patch", path=".", patch=p)["outcomes"][0]["error_code"],
                         "invalid_encoding")
        for options in ({"base_dir": 7}, {"atomic": "true"},
                        {"create_parents": 1}, {"expected_hashes": []}):
            with self.subTest(options=options):
                self.assertEqual(request("patch", path=".", patch=p, **options)["error"]["code"],
                                 "invalid_request")
        target.write_text("small\n")
        with patch("app.file_helper.MAX_PATCH_BYTES", 3):
            self.assertEqual(request("patch", path=".", patch=p)["outcomes"][0]["error_code"],
                             "payload_limit")

    def test_patch_os_permission_denied_and_first_failed_file(self):
        target = self.root / "unlink-denied"
        target.write_text("preserve")
        with patch("app.file_helper.Path.unlink", side_effect=PermissionError):
            result = request("patch", path=".", patch=(
                f"*** Begin Patch\n*** Delete File: {target}\n*** End Patch"))
        self.assertEqual(result["outcomes"][0]["error_code"], "permission_denied")
        self.assertEqual(target.read_text(), "preserve")
        with patch("app.file_helper.os.link", side_effect=FileExistsError):
            creation = request("write", path=str(self.root / "race"),
                               mode="create", content="x", atomic=True)
        self.assertEqual(creation["error"]["code"], "already_exists")
        self.assertFalse((self.root / "race").exists())

    def test_ambiguous_write_error_reports_unknown_completion(self):
        target = self.root / "uncertain.txt"
        target.write_text("original")
        with patch("app.file_helper._publish", side_effect=OSError("synthetic disk-full")):
            response = request("write", path=str(target), content="new",
                               mode="replace", atomic=True)
        self.assertFalse(response["ok"])
        self.assertTrue(response["unknown"])
        self.assertEqual(response["error"]["code"], "interrupted")
        self.assertEqual(target.read_text(), "original")

    def test_first_action_patch_permission_denial_reports_potential_change(self):
        target = self.root / "cannot-delete"
        target.write_text("original")
        with patch("app.file_helper.Path.unlink", side_effect=PermissionError):
            result = request("patch", path=".", patch=(
                f"*** Begin Patch\n*** Delete File: {target}\n*** End Patch"))
        self.assertFalse(result["ok"])
        self.assertTrue(result["partial"])
        self.assertEqual(result["outcomes"][0]["error_code"], "permission_denied")
        self.assertEqual(target.read_text(), "original")

    def test_helper_dispatch_maps_OS_errors_without_payload_leaks(self):
        error_types = (
            (FileExistsError, "already_exists"),
            (FileNotFoundError, "not_found"),
            (IsADirectoryError, "invalid_request"),
            (PermissionError, "permission_denied"),
            (UnicodeError, "invalid_encoding"),
            (OSError, "filesystem_error"),
        )
        for exception, code in error_types:
            with self.subTest(exception=exception):
                with patch("app.file_helper.inspect", side_effect=exception):
                    response = request("inspect", path="unused")
                self.assertEqual(response["error"]["code"], code)
                self.assertNotIn("traceback", str(response).lower())


    def test_symlink_parent_dotdot_uses_kernel_lookup(self):
        real = self.root / "actual"
        nested = real / "sub"
        nested.mkdir(parents=True)
        (real / "config").write_text("correct")
        (self.root / "config").write_text("wrong")
        link = self.root / "shortcut"
        link.symlink_to(nested, target_is_directory=True)
        requested = link / ".." / "config"
        self.assertIn("/../", str(requested))
        reply = request("read", path=str(requested))
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(reply["content"], "correct")
        replaced = request("write", path=str(requested), content="updated")
        self.assertTrue(replaced["ok"], replaced)
        self.assertEqual((real / "config").read_text(), "updated")
        self.assertEqual((self.root / "config").read_text(), "wrong")
        patched = request("patch", path=".", patch=(
            f"*** Begin Patch\n*** Update File: {requested}\n"
            "@@\n-updated\n+patched\n*** End Patch"
        ))
        self.assertTrue(patched["ok"], patched)
        self.assertEqual((real / "config").read_text(), "patched")
        self.assertEqual((self.root / "config").read_text(), "wrong")

    def test_encoded_append_preserves_one_bom_and_utf16_endianness(self):
        cases = [
            ("utf-8-sig", "utf-8-sig", "one".encode("utf-8-sig"),
             "two".encode("utf-8")),
            ("utf-16", "utf-16", "one".encode("utf-16"),
             "two".encode("utf-16-le")),
        ]
        for codec, append_codec, original, tail in cases:
            with self.subTest(codec=codec):
                target = self.root / codec
                made = request("write", path=str(target), mode="create",
                               encoding=codec, content="one")
                self.assertTrue(made["ok"], made)
                result = request("write", path=str(target), mode="append",
                                 encoding=append_codec, content="two")
                self.assertTrue(result["ok"], result)
                self.assertEqual(target.read_bytes(), original + tail)
                self.assertEqual(target.read_bytes().decode(codec), "onetwo")
        be = self.root / "utf16-be-original"
        be.write_bytes(b"\xfe\xff" + "one".encode("utf-16-be"))
        ok = request("write", path=str(be), mode="append",
                     encoding="utf-16", content="two")
        self.assertTrue(ok["ok"], ok)
        self.assertEqual(be.read_bytes(), b"\xfe\xff" + "onetwo".encode("utf-16-be"))
        conflict = request("write", path=str(be), mode="append",
                           encoding="utf-16-le", content="not-appended")
        self.assertEqual(conflict["error"]["code"], "invalid_encoding")
        self.assertEqual(be.read_bytes(), b"\xfe\xff" + "onetwo".encode("utf-16-be"))

    def test_utf16_be_patch_update_and_move_preserve_exact_bom(self):
        original = self.root / "big-endian"
        moved = self.root / "big-endian-moved"
        original.write_bytes(b"\xfe\xff" + "old\r\nnext".encode("utf-16-be"))
        result = request("patch", path=".", patch=(
            f"*** Begin Patch\n*** Update File: {original}\n"
            "@@\n-old\n+NEW\n*** End Patch"))
        self.assertTrue(result["ok"], result)
        self.assertEqual(original.read_bytes(),
                         b"\xfe\xff" + "NEW\r\nnext".encode("utf-16-be"))
        move = request("patch", path=".", patch=(
            f"*** Begin Patch\n*** Update File: {original}\n"
            f"*** Move to: {moved}\n*** End Patch"))
        self.assertTrue(move["ok"], move)
        self.assertFalse(original.exists())
        self.assertEqual(moved.read_bytes(),
                         b"\xfe\xff" + "NEW\r\nnext".encode("utf-16-be"))

    def test_indented_section_context_is_not_stripped(self):
        file = self.root / "module.py"
        file.write_text("class Example:\n    def method(self):\n        return 1\n")
        patch_result = request("patch", path=".", patch=(
            f"*** Begin Patch\n*** Update File: {file}\n"
            "@@     def method(self):\n"
            "-        return 1\n+        return 2\n*** End Patch"
        ))
        self.assertTrue(patch_result["ok"], patch_result)
        self.assertEqual(file.read_text(),
                         "class Example:\n    def method(self):\n        return 2\n")

    def test_codex_eof_marker_targets_last_occurrence(self):
        file = self.root / "repeated.txt"
        file.write_text("repeat\nintermediate\nrepeat\n")
        patch_result = request("patch", path=".", patch=(
            f"*** Begin Patch\n*** Update File: {file}\n"
            "@@\n-repeat\n+last\n*** End of File\n*** End Patch"
        ))
        self.assertTrue(patch_result["ok"], patch_result)
        self.assertEqual(file.read_text(), "repeat\nintermediate\nlast\n")
        conflict = request("patch", path=".", patch=(
            f"*** Begin Patch\n*** Update File: {file}\n"
            "@@\n-repeat\n+wrong\n*** End of File\n*** End Patch"
        ))
        self.assertEqual(conflict["outcomes"][0]["error_code"], "precondition_failed")
        self.assertEqual(file.read_text(), "repeat\nintermediate\nlast\n")

    def test_hash_failure_after_write_reports_completed_mutation(self):
        file = self.root / "append-file"
        file.write_text("first")
        with patch("app.file_helper._sha", side_effect=PermissionError):
            result = request("write", path=str(file), mode="append", content="second",
                             include_sha256=True)
        self.assertFalse(result["ok"])
        self.assertTrue(result["partial"])
        self.assertTrue(result["mutation_completed"])
        self.assertEqual(result["bytes"], 6)
        self.assertEqual(result["error"]["code"], "permission_denied")
        self.assertEqual(file.read_text(), "firstsecond")
        with patch("app.file_helper._sha", side_effect=PermissionError):
            patch_reply = request("patch", path=".", include_sha256=True, patch=(
                f"*** Begin Patch\n*** Update File: {file}\n"
                "@@\n-firstsecond\n+third\n*** End Patch"
            ))
        self.assertTrue(patch_reply["partial"], patch_reply)
        self.assertEqual(patch_reply["outcomes"][0]["status"], "applied")
        self.assertEqual(patch_reply["outcomes"][0]["hash_error_code"], "permission_denied")
        self.assertEqual(file.read_text(), "third")

    def test_oversized_patch_result_preflight_leaves_destinations_untouched(self):
        base = self.root
        for number in range(19):
            base = base / (f"folder{number:02d}-" + "z" * 148)
        base.mkdir(parents=True)
        self.assertGreater(len(str(base)), 3000)
        patch_body = ("*** Begin Patch\n"
                      + "".join(f"*** Add File: new-{i:03d}.txt\n+test\n" for i in range(100))
                      + "*** End Patch")
        response = request("patch", path=".", base_dir=str(base), patch=patch_body)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "response_limit")
        self.assertEqual(list(base.iterdir()), [])

    def test_skip_lines_never_allocates_full_large_line(self):
        from app.file_helper import _skip_lines

        class LimitReader(io.BytesIO):
            def __init__(self, source):
                super().__init__(source)
                self.maximum = 0

            def read(self, size=-1):
                if size < 0 or size > 65536:
                    raise AssertionError("unbounded read in line seek")
                self.maximum = max(self.maximum, size)
                return super().read(size)

            def readline(self, size=-1):
                if size < 0 or size > 65536:
                    raise AssertionError("unbounded readline in line seek")
                self.maximum = max(self.maximum, size)
                return super().readline(size)

        cases = [
            ("utf-8", b"x" * (3 * 1024 * 1024) + b"\nnext"),
            ("utf-16-le", ("x" * (1024 * 1024) + "\nnext").encode("utf-16-le")),
            ("utf-16-be", ("x" * (1024 * 1024) + "\nnext").encode("utf-16-be")),
        ]
        for codec, source in cases:
            with self.subTest(codec=codec):
                stream = LimitReader(source)
                self.assertEqual(_skip_lines(stream, codec, 2), 2)
                self.assertEqual(stream.tell(), source.index(
                    b"\n" if codec == "utf-8" else
                    b"\n\x00" if codec.endswith("le") else b"\x00\n"
                ) + (1 if codec == "utf-8" else 2))
                self.assertLessEqual(stream.maximum, 65536)



if __name__ == "__main__":
    unittest.main()
