"""Bundled unprivileged SSH file helper. JSON payloads never enter command history.

Runs as the authorized SSH user; OS permissions (including ordinary symlinks)
are authoritative. No application workspace/path allowlist is imposed.
"""
from __future__ import annotations

import base64
import binascii
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time
import stat
import sys
import tempfile
from typing import Any

HELPER_PROTOCOL = 1
MAX_ENVELOPE_BYTES = 1024 * 1024
MAX_READ_BYTES = 131072
MAX_PATCH_BYTES = 32 * 1024 * 1024
MAX_BINARY_TRANSFER_BYTES = 8 * 1024 * 1024
MAX_BINARY_CHUNK_BYTES = 131072
_UPLOAD_STALE_SECONDS = 3600
_UPLOAD_PREFIX = ".ssh-mcp-upload-"
_SESSION_RE = re.compile(r"^[0-9a-f]{32}$")
_HASH_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_SENSITIVE_CONTEXT = re.compile(
    r"(?i)(?:password|passwd|secret|token|credential|authorization|"
    r"api[_-]?key|private[_-]?key|session[_-]?key|cookie|bearer|"
    r"-----BEGIN|ssh-rsa|://[^\s/@]+:[^\s/@]+@)"
)
_CONTEXT_LIMIT = 4
_CONTEXT_LINE_LIMIT = 120


class FileError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class PatchConflict(FileError):
    """One reusable, bounded patch conflict record for apply and future preview.

    It contains no raw file content unless the caller's SSH user can read the
    file, and is never stored by the file-operation audit.
    """

    def __init__(self, failure_kind: str, *, hunk: int | None = None,
                 expected: list[str] | None = None,
                 actual: list[dict[str, Any]] | None = None,
                 line_hint: int | None = None, excerpt_available: bool = False):
        super().__init__("precondition_failed", "Patch precondition or context mismatch")
        self.diagnostic: dict[str, Any] = {
            "failure_kind": failure_kind,
            "hunk": hunk,
            "line_hint": line_hint,
            "expected_context": [_safe_patch_line(item) for item in (expected or [])[:_CONTEXT_LIMIT]],
            "actual_excerpt": actual or [],
            "excerpt_available": excerpt_available,
        }


def _safe_patch_line(value: str) -> str:
    """Bound and redact sensitive-looking lines, including request context."""
    if _SENSITIVE_CONTEXT.search(value):
        return "[REDACTED]"
    clean = "".join(c if c.isprintable() else "?" for c in value)
    return clean[:_CONTEXT_LINE_LIMIT] + ("…" if len(clean) > _CONTEXT_LINE_LIMIT else "")


def _patch_excerpt(lines: list[str], start: int, *, can_read: bool) -> list[dict[str, Any]]:
    if not can_read:
        return []
    begin = max(0, min(start, len(lines) - 1))
    return [
        {"line": offset + 1, "text": _safe_patch_line(lines[offset])}
        for offset in range(begin, min(len(lines), begin + _CONTEXT_LIMIT))
    ]


def resolve_path(path: str, base_dir: str | None = None) -> Path:
    """Resolve against SSH HOME, retaining the final symlink for OS semantics."""
    if not isinstance(path, str) or not path or "\x00" in path:
        raise ValueError("Invalid path")
    home = Path.home()
    base = home if base_dir is None else Path(base_dir).expanduser()
    if not base.is_absolute():
        base = home / base
    target = Path(path).expanduser()
    if not target.is_absolute():
        target = base / target
    # Do not call abspath/normpath/resolve here: lexical folding of a symlink
    # parent followed by ".." changes the object the kernel would address.
    return target


def _target(request: dict[str, Any]) -> Path:
    path, base = request.get("path"), request.get("base_dir")
    if not isinstance(path, str) or (base is not None and not isinstance(base, str)):
        raise FileError("invalid_request", "Invalid path or base_dir")
    return resolve_path(path, base)


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as src:
        for chunk in iter(lambda: src.read(131072), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _version(info: os.stat_result) -> list[int]:
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def _cursor_encode(data: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).decode().rstrip("=")


def _cursor_decode(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, str) or len(raw) > 2048:
        raise FileError("invalid_cursor", "Invalid continuation cursor")
    try:
        decoded = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except (ValueError, UnicodeError):
        raise FileError("invalid_cursor", "Invalid continuation cursor") from None
    if not isinstance(decoded, dict):
        raise FileError("invalid_cursor", "Invalid continuation cursor")
    return decoded


def _codec(name: Any) -> str:
    if name not in {"utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"}:
        raise FileError("invalid_encoding", "Unsupported text encoding")
    return str(name)


def inspect(request: dict[str, Any]) -> dict[str, Any]:
    target = _target(request)
    try:
        details = target.stat()
    except FileNotFoundError:
        return {"ok": False, "error": {"code": "not_found", "message": "Path not found"},
                "path": str(target)}
    except PermissionError:
        return {"ok": False, "error": {"code": "permission_denied", "message": "Permission denied"},
                "path": str(target)}
    kind = "file" if stat.S_ISREG(details.st_mode) else "directory" if stat.S_ISDIR(details.st_mode) else "other"
    return {"ok": True, "path": str(target), "kind": kind,
            "size": details.st_size, "mode": stat.S_IMODE(details.st_mode)}


def _skip_lines(file: Any, codec: str, requested: int) -> int:
    """Seek LF-delimited lines in fixed-size chunks, never materializing a line."""
    line = 1
    if codec.startswith("utf-16"):
        marker = b"\n\x00" if codec.endswith("le") else b"\x00\n"
        while line < requested:
            start = file.tell()
            block: bytes = file.read(65536)
            if not block:
                break
            # Inspect only aligned UTF-16 code units; blocks are even sized.
            for offset in range(0, len(block) - 1, 2):
                if block[offset:offset + 2] == marker:
                    line += 1
                    if line >= requested:
                        file.seek(start + offset + 2)
                        break
    else:
        while line < requested:
            block = bytes(file.readline(65536))
            if not block:
                break
            if block.endswith(b"\n"):
                line += 1
    return line


def read_file(request: dict[str, Any]) -> dict[str, Any]:
    target = _target(request)
    path_digest = hashlib.sha256(os.fsencode(target)).hexdigest()
    raw_cursor = request.get("cursor")
    cursor = _cursor_decode(raw_cursor) if raw_cursor is not None else None
    codec = _codec(request.get("encoding", cursor.get("encoding", "utf-8") if cursor else "utf-8"))
    maximum = request.get("max_bytes", 65536)
    start = request.get("start_line", 1)
    stop = request.get("end_line", cursor.get("end_line") if cursor else None)
    if (type(maximum) is not int or not 1 <= maximum <= MAX_READ_BYTES
            or type(start) is not int or start < 1
            or (stop is not None and (type(stop) is not int or stop < start))):
        raise FileError("invalid_request", "Invalid read range or response limit")
    with target.open("rb") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise FileError("invalid_request", "Text read requires a regular file")
        ver = _version(info)
        endian = codec
        prefix = b""
        if codec == "utf-16":
            prefix = file.read(2)
            if prefix == b"\xff\xfe":
                endian = "utf-16-le"
            elif prefix == b"\xfe\xff":
                endian = "utf-16-be"
            else:
                raise FileError("invalid_encoding", "UTF-16 file must have a BOM")
        elif codec == "utf-8-sig":
            prefix = file.read(3)
            if prefix == b"\xef\xbb\xbf":
                endian = "utf-8"
            else:
                prefix = b""
                endian = "utf-8"
        file.seek(0)
        if cursor is not None:
            if (cursor.get("path_sha256") != path_digest
                    or cursor.get("server") != request.get("server")
                    or cursor.get("encoding") != codec
                    or cursor.get("end_line") != stop):
                raise FileError("invalid_cursor", "Continuation cursor does not match file or options")
            if cursor.get("version") != ver:
                raise FileError("changed_file", "File changed since previous read")
            offset, line = cursor.get("offset"), cursor.get("line")
            if (type(offset) is not int or not 0 <= offset <= info.st_size
                    or type(line) is not int or line < 1):
                raise FileError("invalid_cursor", "Invalid continuation offset")
            file.seek(offset)
        else:
            line = 1
            if codec == "utf-16":
                file.seek(2)
            line = _skip_lines(file, endian, start)
            if start == 1:
                file.seek(0)
        current_offset = file.tell()
        if stop is not None and line > stop:
            data = b""
        else:
            data = file.read(min(maximum, info.st_size - current_offset))
            if current_offset == 0 and prefix and len(data) < len(prefix):
                raise FileError("response_limit", "Read limit cannot fit the file BOM")
            # Preserve codepoint boundaries; UTF-16 uses two-byte units and
            # UTF-8/UTF-8-SIG may end in a partial multibyte character.
            while data:
                try:
                    probe = data[len(prefix):] if current_offset == 0 else data
                    probe.decode(endian)
                    break
                except UnicodeDecodeError as exc:
                    if exc.reason not in ("unexpected end of data", "truncated data"):
                        raise FileError("invalid_encoding", "File is not valid text") from None
                    data = data[:-1]
            if not data and file.tell() > current_offset:
                raise FileError("response_limit", "Read limit cannot fit one character")
        initial_prefix = prefix if current_offset == 0 else b""
        try:
            content = data[len(initial_prefix):].decode(endian)
        except UnicodeError:
            raise FileError("invalid_encoding", "File is not valid text") from None
        if stop is not None:
            remaining = stop - line + 1
            if remaining <= 0:
                content = ""
            elif content.count("\n") >= remaining:
                index = -1
                for _ in range(remaining):
                    index = content.index("\n", index + 1)
                content = content[:index + 1]
        # The helper transport caps stdout; JSON escapes can be much larger
        # than the decoded bytes (e.g. NUL, emoji). Return a smaller chunk
        # with a reusable cursor instead of failing with unknown completion.
        while content and len(json.dumps(content, ensure_ascii=True).encode()) > 180000:
            content = content[:max(1, len(content) // 2)]
        if not content and data and len(initial_prefix) < len(data):
            raise FileError("response_limit", "Read limit cannot fit one character")
        data = initial_prefix + content.encode(endian)
        offset = current_offset + len(data)
        next_line = line + content.count("\n")
        eof = offset >= info.st_size or (stop is not None and next_line > stop)
        try:
            if (_version(os.fstat(file.fileno())) != ver
                    or _version(target.stat()) != ver):
                raise FileError("changed_file", "File changed during read")
        except FileNotFoundError:
            raise FileError("changed_file", "File removed during read") from None
    result: dict[str, Any] = {
        "ok": True, "path": str(target), "content": content, "bytes": len(data),
        "offset": current_offset, "start_line": line, "next_line": next_line,
        "size": ver[2], "eof": eof, "truncated": not eof,
        "next_cursor": None if eof else _cursor_encode({
            "path_sha256": path_digest, "server": request.get("server"),
            "encoding": codec, "end_line": stop, "version": ver,
            "offset": offset, "line": next_line,
        }),
    }
    if request.get("include_sha256") is True:
        result["sha256"] = _sha(target)
        if _version(target.stat()) != ver:
            raise FileError("changed_file", "File changed while hashing")
    return result


def _expected(target: Path, expected: Any) -> None:
    if expected is None:
        return
    if not isinstance(expected, str) or not _HASH_RE.fullmatch(expected):
        raise FileError("invalid_request", "Invalid expected SHA-256")
    try:
        actual = _sha(target)
    except FileNotFoundError:
        raise FileError("precondition_failed", "Precondition requires an existing file") from None
    if actual.lower() != expected.lower():
        raise FileError("precondition_failed", "Existing file does not match expected SHA-256")


def _encode_text(content: Any, codec: str, newline: Any = None) -> bytes:
    if not isinstance(content, str):
        raise FileError("invalid_request", "File content must be a text string")
    content_text: str = content
    if newline not in (None, "lf", "crlf"):
        raise FileError("invalid_request", "Invalid newline selection")
    if newline is not None:
        content_text = content_text.replace("\r\n", "\n").replace("\r", "\n")
        if newline == "crlf":
            content_text = content_text.replace("\n", "\r\n")
    try:
        return content_text.encode(codec)
    except (UnicodeError, LookupError):
        raise FileError("invalid_encoding", "Cannot encode text") from None


def _publish(target: Path, data: bytes, *, atomic: bool, create: bool = False) -> None:
    if not atomic:
        with target.open("xb" if create else "wb") as output:
            output.write(data)
        return
    temporary: str | None = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".ssh-mcp-file-", dir=target.parent)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        if create:
            os.link(temporary, target)
        else:
            os.replace(temporary, target)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def write_file(request: dict[str, Any]) -> dict[str, Any]:
    target = _target(request)
    mode = request.get("mode", "replace")
    if mode not in ("create", "replace", "append"):
        raise FileError("invalid_request", "Invalid write mode")
    atomic = request.get("atomic", False)
    create_parents = request.get("create_parents", False)
    if type(atomic) is not bool or type(create_parents) is not bool:
        raise FileError("invalid_request", "Invalid write flags")
    if atomic and mode == "append":
        raise FileError("invalid_request", "Atomic append is unsupported")
    newline = request.get("newline")
    if newline is None and not os.path.lexists(target):
        newline = "lf"
    codec = _codec(request.get("encoding", "utf-8"))
    if mode == "append" and target.exists() and target.stat().st_size:
        if codec == "utf-8-sig":
            # A BOM belongs to the beginning of the file only.
            codec = "utf-8"
        elif codec.startswith("utf-16"):
            with target.open("rb") as source:
                signature = source.read(2)
            actual = ("utf-16-le" if signature == b"\xff\xfe" else
                      "utf-16-be" if signature == b"\xfe\xff" else None)
            if codec == "utf-16":
                if actual is None:
                    raise FileError("invalid_encoding", "Cannot append UTF-16 without a BOM")
                codec = actual
            elif actual is not None and codec != actual:
                raise FileError("invalid_encoding", "Append UTF-16 byte order conflicts with file")
    encoded = _encode_text(request.get("content"), codec, newline)
    if create_parents:
        target.parent.mkdir(parents=True, exist_ok=True)
    _expected(target, request.get("expected_sha256"))
    if mode == "create" and os.path.lexists(target):
        raise FileError("already_exists", "Destination already exists")
    # Filesystem errors during a non-atomic write can leave bytes modified.
    # Never claim a confirmed failure or replay an uncertain append.
    try:
        if atomic:
            _publish(target, encoded, atomic=True, create=mode == "create")
        elif mode == "replace" and target.exists():
            # Ordinary in-place replacement retains inode, symlinks and hard links.
            with target.open("r+b") as output:
                output.seek(0)
                output.write(encoded)
                output.truncate()
        else:
            with target.open("ab" if mode == "append" else "xb" if mode == "create" else "wb") as output:
                output.write(encoded)
    except FileExistsError:
        raise FileError("already_exists", "Destination already exists") from None
    except FileNotFoundError:
        raise FileError("not_found", "Path not found") from None
    except PermissionError:
        raise FileError("permission_denied", "Permission denied") from None
    except OSError:
        return {"ok": False, "unknown": True, "path": str(target), "bytes": 0,
                "error": {"code": "interrupted",
                          "message": "Write completion uncertain; inspect destination before retry"}}
    result = {"ok": True, "path": str(target), "bytes": len(encoded), "mode": mode,
              "atomic": atomic}
    if request.get("include_sha256") is True:
        try:
            result["sha256"] = _sha(target)
        except OSError as exc:
            code = "permission_denied" if isinstance(exc, PermissionError) else "filesystem_error"
            return {**result, "ok": False, "partial": True, "mutation_completed": True,
                    "error": {"code": code,
                              "message": "Write completed, but result hash is unavailable"}}
    return result


def _text_format(data: bytes) -> tuple[str, str, bytes, str, bool]:
    """Detect text, retaining the original BOM bytes and UTF-16 endian."""
    if data.startswith(b"\xef\xbb\xbf"):
        bom, encoding = b"\xef\xbb\xbf", "utf-8"
    elif data.startswith(b"\xff\xfe"):
        bom, encoding = b"\xff\xfe", "utf-16-le"
    elif data.startswith(b"\xfe\xff"):
        bom, encoding = b"\xfe\xff", "utf-16-be"
    else:
        bom, encoding = b"", "utf-8"
    try:
        text = data[len(bom):].decode(encoding)
    except UnicodeError:
        raise FileError("invalid_encoding", "Patch target is not valid text") from None
    newline = "\r\n" if "\r\n" in text else "\n"
    return (text.replace("\r\n", "\n").replace("\r", "\n"), encoding, bom,
            newline, text.endswith(("\n", "\r")))


def _encode_lines(lines: list[str], codec: str, newline: str, final: bool) -> bytes:
    content = "\n".join(lines) + ("\n" if final else "")
    return content.replace("\n", newline).encode(codec)


def _parse_patch(body: Any) -> list[dict[str, Any]]:
    if not isinstance(body, str) or not body.startswith("*** Begin Patch\n") or not body.rstrip().endswith("*** End Patch"):
        raise FileError("invalid_patch", "Expected Codex-style patch markers")
    lines = body.splitlines()
    actions: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in lines[1:-1]:
        header = re.match(r"\*\*\* (Add|Update|Delete) File: (.+)", line)
        if header:
            current = {"kind": header.group(1).lower(), "path": header.group(2),
                       "move": None, "chunks": [], "final": None}
            actions.append(current)
        elif current is None:
            raise FileError("invalid_patch", "Patch content precedes a file header")
        elif line.startswith("*** Move to: ") and current["kind"] == "update":
            current["move"] = line[len("*** Move to: "):]
        elif line.startswith("@@") and current["kind"] == "update":
            current["chunks"].append({
                "section": line[3:] if line.startswith("@@ ") else line[2:],
                "lines": [], "eof": False,
            })
        elif line == "*** End of File" and current["kind"] == "update":
            if not current["chunks"] or current["chunks"][-1]["eof"]:
                raise FileError("invalid_patch", "EOF marker requires a preceding update hunk")
            current["chunks"][-1]["eof"] = True
        elif line == "\\ No newline at end of file":
            current["final"] = False
        elif line.startswith(("+", "-", " ")) and current["kind"] == "update":
            if not current["chunks"]:
                current["chunks"].append({"section": "", "lines": [], "eof": False})
            current["chunks"][-1]["lines"].append((line[0], line[1:]))
        elif line.startswith("+") and current["kind"] == "add":
            current["chunks"].append(line[1:])
        elif current["kind"] == "delete" and not line:
            continue
        else:
            raise FileError("invalid_patch", "Malformed patch file section")
    if not actions or len(actions) > 100:
        raise FileError("invalid_patch", "Patch must contain 1 to 100 files")
    for action in actions:
        if not action["path"] or (action["kind"] == "update"
                                  and not action["chunks"] and not action["move"]):
            raise FileError("invalid_patch", "Empty patch file or update")
    return actions


def _apply_chunks(
    lines: list[str], chunks: list[dict[str, Any]], *, can_read: bool = False,
) -> list[str]:
    result = lines[:]
    # Track provenance separately from the mutable working buffer. The patch
    # is not published until all hunks match, so a conflict must quote only
    # original on-disk lines, never the hypothetical result of prior hunks.
    origins: list[int | None] = list(range(len(lines)))

    def original_position(working_position: int) -> int:
        for origin in origins[max(0, working_position):]:
            if origin is not None:
                return origin
        # At the end of the working buffer, anchor just after the last
        # original line that still survives. Deleted/replaced lines have no
        # provenance, so this remains a hint rather than an exact match.
        for origin in reversed(origins[:max(0, working_position)]):
            if origin is not None:
                return min(origin + 1, max(0, len(lines) - 1))
        return 0

    def original_excerpt(working_position: int) -> tuple[int, list[dict[str, Any]]]:
        position = original_position(working_position)
        return position + 1, _patch_excerpt(lines, position, can_read=can_read)

    cursor = 0
    for hunk, chunk in enumerate(chunks, 1):
        section = chunk["section"]
        if section:
            try:
                cursor = result.index(section, cursor) + 1
            except ValueError:
                hint, excerpt = original_excerpt(cursor)
                raise PatchConflict(
                    "missing_section", hunk=hunk, expected=[section],
                    actual=excerpt, line_hint=hint, excerpt_available=can_read,
                ) from None
        old = [text for marker, text in chunk["lines"] if marker in (" ", "-")]
        new = [text for marker, text in chunk["lines"] if marker in (" ", "+")]
        if chunk["eof"]:
            position = len(result) - len(old)
            if position < cursor or result[position:position + len(old)] != old:
                hint, excerpt = original_excerpt(max(0, position))
                raise PatchConflict(
                    "eof_mismatch", hunk=hunk, expected=old,
                    actual=excerpt, line_hint=hint, excerpt_available=can_read,
                )
        elif not old:
            position = cursor
        else:
            position = -1
            for index in range(cursor, len(result) - len(old) + 1):
                if result[index:index + len(old)] == old:
                    position = index
                    break
            if position < 0:
                hint, excerpt = original_excerpt(cursor)
                raise PatchConflict(
                    "context_mismatch", hunk=hunk, expected=old,
                    actual=excerpt, line_hint=hint, excerpt_available=can_read,
                )
        # Unchanged (' ') context retains its original line identity. Added
        # and replacement text is deliberately never attributed to disk.
        replacements: list[int | None] = []
        old_offset = 0
        for marker, _ in chunk["lines"]:
            if marker == " ":
                replacements.append(origins[position + old_offset])
                old_offset += 1
            elif marker == "-":
                old_offset += 1
            else:
                replacements.append(None)
        result[position:position + len(old)] = new
        origins[position:position + len(old)] = replacements
        cursor = position + len(new)
    return result


def _render_patch_bytes(
    action: dict[str, Any], target: Path,
    override_encoding: str | None, override_newline: str | None,
    *, can_read: bool,
) -> tuple[bytes, bytes | None, list[str], list[str]]:
    """Shared, non-mutating render for preview and actual Add/Update.

    Keep all encoding, newlines, content matching and original provenance in
    one place so the preview cannot disagree with the actual patch renderer.
    """
    if action["kind"] == "add":
        data = _encode_lines(
            action["chunks"], override_encoding or "utf-8",
            "\r\n" if override_newline == "crlf" else "\n",
            action["final"] is not False,
        )
        return data, None, [], action["chunks"]
    if action["kind"] != "update":
        raise ValueError("Only Add/Update actions render replacement bytes")
    if target.stat().st_size > MAX_PATCH_BYTES:
        raise FileError("payload_limit", "Patch target exceeds memory bound")
    raw = target.read_bytes()
    if len(raw) > MAX_PATCH_BYTES:
        raise FileError("payload_limit", "Patch target exceeds memory bound")
    text, codec, original_bom, newline, final = _text_format(raw)
    original_lines = text.split("\n")
    if final:
        original_lines.pop()
    changed = _apply_chunks(original_lines, action["chunks"], can_read=can_read)
    data = _encode_lines(
        changed, override_encoding or codec,
        ("\r\n" if override_newline == "crlf"
         else "\n" if override_newline == "lf" else newline),
        final if action["final"] is None else action["final"],
    )
    if override_encoding is None:
        data = original_bom + data
    return data, raw, original_lines, changed


def _patch_path_key(path: Path) -> str:
    """Compare parent filesystem identities while preserving final symlinks."""
    return os.path.join(os.path.realpath(os.fspath(path.parent)), path.name)


def _check_patch_collisions(
    paths: list[tuple[dict[str, Any], Path, Path | None]],
    *, ancestors: bool = True,
) -> tuple[int, str] | None:
    # All patch endpoints represent files, never directories. A file entry
    # must not be an ancestor of another planned endpoint: Add file "a"
    # plus Add "a/b" would otherwise both pass advisory preflight and fail
    # after the first publication. Check lexical and real-parent aliases;
    # walk exact ancestors to avoid false positives for sibling prefixes.
    lexical: list[tuple[str, int]] = []
    canonical: list[tuple[str, int]] = []
    for index, (_, target, moved) in enumerate(paths):
        for path in (target, moved) if moved is not None else (target,):
            lexical.append((os.path.normpath(os.fspath(path)), index))
            canonical.append((_patch_path_key(path), index))
    failure: int | None = None
    for group in (lexical, canonical):
        endpoints: dict[str, int] = {}
        for identity, index in group:
            if identity in endpoints:
                candidate = max(index, endpoints[identity])
                failure = candidate if failure is None else min(failure, candidate)
            else:
                endpoints[identity] = index
        if not ancestors:
            continue
        for identity, index in endpoints.items():
            ancestor = os.path.dirname(identity)
            while ancestor != identity:
                if ancestor in endpoints:
                    candidate = max(index, endpoints[ancestor])
                    failure = candidate if failure is None else min(failure, candidate)
                    break
                identity, ancestor = ancestor, os.path.dirname(ancestor)
    if failure is not None:
        return failure, str(paths[failure][1])
    return None


def _preview_parent(path: Path, *, create_parents: bool) -> None:
    parent = path.parent
    if not create_parents and not parent.is_dir():
        raise FileError("not_found", "Parent directory missing")
    while not parent.exists():
        if not create_parents:
            raise FileError("not_found", "Parent directory missing")
        if parent == parent.parent:
            raise FileError("permission_denied", "No accessible parent directory")
        parent = parent.parent
    if not parent.is_dir():
        raise FileError("not_found", "Parent is not a directory")
    if not (os.access(parent, os.W_OK, effective_ids=True)
            and os.access(parent, os.X_OK, effective_ids=True)):
        raise FileError("permission_denied", "Cannot write target directory")


def _preview_diff(old: list[str], new: list[str], *, maximum: int) -> tuple[str, bool]:
    # Bound input size as well as the output; an optional preview should not
    # construct a massive unified diff for a large but otherwise valid patch.
    if (len(old) + len(new) > 10000
            or _patch_delta_cost(old, new) > _PATCH_DELTA_WORK_LIMIT):
        return "", True
    collected: list[str] = []
    budget = maximum
    for index, line in enumerate(difflib.unified_diff(old, new, lineterm="")):
        # Only the first two records are file headers. Changed content can
        # legitimately begin with '--' or '++', yielding diff records that
        # begin with '---' or '+++' and must still be redacted.
        if index < 2 or line.startswith("@@ "):
            rendered = line
        else:
            rendered = line[:1] + _safe_patch_line(line[1:])
        item = rendered + "\n"
        width = len(item.encode("utf-8"))
        if width > budget:
            return "".join(collected), True
        collected.append(item)
        budget -= width
    return "".join(collected), False


def _preview_patch(
    request: dict[str, Any],
    paths: list[tuple[dict[str, Any], Path, Path | None]],
    *,
    create_parents: bool,
    atomic: bool,
    expected: dict[str, str],
    override_encoding: str | None,
    override_newline: str | None,
) -> dict[str, Any]:
    """Non-mutating advisory plan: no mkdir, rename, unlink, chmod or write."""
    collisions = _check_patch_collisions(paths)
    outcomes: list[dict[str, Any]] = []
    failure: dict[str, Any] | None = None
    total_added = total_removed = changed = 0
    line_counts_complete = True
    summary_work_left = _PATCH_DELTA_WORK_LIMIT
    diff_budget = request.get("max_diff_bytes", 8192)
    include_diff = request.get("include_diff", False)
    if collisions is not None:
        conflict_index, conflict_path = collisions
        for index, (action, target, _) in enumerate(paths):
            outcomes.append({
                "path": str(target), "action": action["kind"],
                "status": "failed" if index == conflict_index else "not_attempted",
                "bytes": 0,
                **({"error_code": "invalid_patch", "failure_kind": "overlapping_paths"}
                   if index == conflict_index else {}),
            })
        return {
            "ok": False, "partial": False, "bytes": 0,
            "dry_run": True, "applicability": "not_applicable",
            "outcomes": outcomes,
            "summary": {"total_paths": len(paths), "changed_paths": 0,
                        "added_lines": 0, "removed_lines": 0,
                        "preview_only": True},
            "error": {"code": "invalid_patch",
                      "message": "Overlapping patch source/destination paths",
                      "failure_kind": "overlapping_paths",
                      "failed_path": conflict_path},
        }
    for index, (action, target, moved) in enumerate(paths):
        if failure is not None:
            outcomes.append({"path": str(target), "action": action["kind"],
                             "status": "not_attempted", "bytes": 0})
            continue
        try:
            try:
                _expected(target, expected.get(action["path"]))
            except FileError as exc:
                if exc.code == "precondition_failed":
                    raise PatchConflict(
                        "missing_file" if not target.exists() else "hash_mismatch"
                    ) from None
                raise
            if moved is not None:
                if os.path.lexists(moved):
                    raise FileError("already_exists", "Move destination already exists")
                _preview_parent(moved, create_parents=create_parents)
                _preview_parent(target, create_parents=False)
            if action["kind"] == "add":
                if os.path.lexists(target):
                    raise FileError("already_exists", "Patch addition already exists")
                _preview_parent(target, create_parents=create_parents)
                data, old_raw, old_lines, new_lines = _render_patch_bytes(
                    action, target, override_encoding, override_newline, can_read=False,
                )
                readable = os.access(target.parent, os.R_OK, effective_ids=True)
            elif action["kind"] == "delete":
                if not os.path.lexists(target):
                    raise FileError("not_found", "Patch target not found")
                if target.is_dir() and not target.is_symlink():
                    raise FileError(
                        "invalid_request" if atomic else "filesystem_error",
                        "Cannot delete a directory with a file patch",
                    )
                _preview_parent(target, create_parents=False)
                readable = os.access(target, os.R_OK, effective_ids=True)
                # A delete preview needs no file body unless a diff is
                # requested. Even then never materialize a large file;
                # optional SHA-256 is streamed separately below.
                old_raw = None
                if readable and include_diff and target.is_file():
                    if target.stat().st_size <= MAX_READ_BYTES:
                        with target.open("rb") as source:
                            candidate = source.read(MAX_READ_BYTES + 1)
                        if len(candidate) <= MAX_READ_BYTES:
                            old_raw = candidate
                old_lines = (old_raw.decode("utf-8", errors="replace").splitlines()
                             if old_raw is not None else [])
                new_lines = []
                data = b""
            else:
                readable = os.access(target, os.R_OK, effective_ids=True)
                if not readable:
                    raise FileError("permission_denied", "Patch input cannot be read")
                if atomic or moved is not None:
                    _preview_parent(target, create_parents=False)
                elif not os.access(target, os.W_OK, effective_ids=True):
                    raise FileError("permission_denied", "Patch target is not writable")
                data, old_raw, old_lines, new_lines = _render_patch_bytes(
                    action, target, override_encoding, override_newline, can_read=readable,
                )
            unchanged = (action["kind"] == "update" and moved is None
                         and old_raw == data)
            if not unchanged:
                changed += 1
            added: int | None
            removed: int | None
            known_lines = readable and (action["kind"] != "delete" or old_raw is not None)
            if known_lines:
                added, removed, used = _patch_line_delta(
                    old_lines, new_lines, budget=summary_work_left,
                )
                summary_work_left -= used
            else:
                added = len(new_lines) if action["kind"] == "add" else None
                removed = None
            if added is not None:
                total_added += added
            if removed is not None:
                total_removed += removed
            else:
                line_counts_complete = False
            if added is None:
                line_counts_complete = False
            outcome: dict[str, Any] = {
                "path": str(target), "action": action["kind"],
                "status": "unchanged" if unchanged else "applicable",
                "bytes": len(data) if action["kind"] != "delete" else 0,
            }
            if moved:
                outcome["moved_to"] = str(moved)
            if added is not None:
                outcome["added_lines"] = added
            if removed is not None:
                outcome["removed_lines"] = removed
            if request.get("include_sha256") is True:
                if old_raw is not None and readable:
                    outcome["before_sha256"] = hashlib.sha256(old_raw).hexdigest()
                elif action["kind"] == "delete" and readable and target.is_file():
                    # _sha hashes in bounded blocks; no read_bytes/decode.
                    outcome["before_sha256"] = _sha(target)
                if action["kind"] != "delete":
                    outcome["prospective_sha256"] = hashlib.sha256(data).hexdigest()
            if include_diff and readable:
                remaining = max(0, diff_budget)
                if action["kind"] == "delete" and old_raw is None:
                    # Large or unsupported delete target: no unbounded read.
                    outcome["diff_truncated"] = True
                elif remaining:
                    snippet, truncated = _preview_diff(old_lines, new_lines, maximum=remaining)
                    outcome["diff"] = snippet
                    outcome["diff_truncated"] = truncated
                    diff_budget -= len(snippet.encode("utf-8"))
                else:
                    outcome["diff_truncated"] = True
            outcomes.append(outcome)
        except (FileError, FileExistsError, FileNotFoundError, PermissionError, OSError) as exc:
            code = (exc.code if isinstance(exc, FileError)
                    else "already_exists" if isinstance(exc, FileExistsError)
                    else "not_found" if isinstance(exc, FileNotFoundError)
                    else "permission_denied" if isinstance(exc, PermissionError)
                    else "filesystem_error")
            kind = (exc.diagnostic["failure_kind"] if isinstance(exc, PatchConflict) else code)
            outcome = {"path": str(target), "action": action["kind"],
                       "status": "failed", "bytes": 0,
                       "error_code": code, "failure_kind": kind}
            if isinstance(exc, PatchConflict):
                outcome["conflict"] = exc.diagnostic
            outcomes.append(outcome)
            failure = {"code": code, "message": "Patch preview is not applicable",
                       "failed_path": str(target), "failure_kind": kind,
                       **({"conflict": exc.diagnostic} if isinstance(exc, PatchConflict) else {})}
    return {
        "ok": failure is None, "partial": False, "bytes": 0,
        "dry_run": True, "applicability": "applicable" if failure is None else "not_applicable",
        "outcomes": outcomes,
        "summary": {"total_paths": len(paths), "changed_paths": changed,
                    "added_lines": total_added if line_counts_complete else None,
                    "removed_lines": total_removed if line_counts_complete else None,
                    "line_counts_complete": line_counts_complete,
                    "preview_only": True},
        **({"error": failure} if failure is not None else {}),
    }


def _patch_version(path: Path) -> list[int] | None:
    """Snapshot both directory-entry identity and symlink referent content.

    The entry's lstat alone is insufficient: an ordinary symlink can keep
    the same inode while its target is edited after preflight.
    """
    try:
        entry = _version(path.lstat())
    except FileNotFoundError:
        return None
    try:
        return entry + _version(path.stat())
    except FileNotFoundError:
        # A dangling symlink is still a real directory entry.
        return entry + [-1, -1, -1, -1, -1]


_PATCH_DELTA_WORK_LIMIT = 250_000


def _patch_delta_trim(old: list[str], new: list[str]) -> tuple[list[str], list[str]]:
    """Ignore identical prefix/suffix before computing an edit cost bound."""
    prefix = 0
    while prefix < min(len(old), len(new)) and old[prefix] == new[prefix]:
        prefix += 1
    suffix = 0
    while (suffix < min(len(old), len(new)) - prefix
           and old[len(old) - suffix - 1] == new[len(new) - suffix - 1]):
        suffix += 1
    return (old[prefix:len(old) - suffix if suffix else len(old)],
            new[prefix:len(new) - suffix if suffix else len(new)])


def _patch_delta_cost(old: list[str], new: list[str]) -> int:
    """Conservative worst-case pairwise match cost, including linear scans."""
    left, right = _patch_delta_trim(old, new)
    return len(old) + len(new) + len(left) * len(right)


def _patch_line_delta(
    old: list[str], new: list[str], *, budget: int,
) -> tuple[int | None, int | None, int]:
    """Only perform exact matching when worst-case work fits request budget."""
    left, right = _patch_delta_trim(old, new)
    estimated_work = len(old) + len(new) + len(left) * len(right)
    if estimated_work > budget:
        return None, None, 0
    added = removed = 0
    for kind, start, stop, next_start, next_stop in difflib.SequenceMatcher(
        a=left, b=right, autojunk=False,
    ).get_opcodes():
        if kind != "equal":
            removed += stop - start
            added += next_stop - next_start
    return added, removed, estimated_work


def _patch_summary(
    paths: list[tuple[dict[str, Any], Path, Path | None]],
    outcomes: list[dict[str, Any]],
    *,
    bytes_written: int, preflight_completed: bool,
) -> dict[str, Any]:
    known = [item for item in outcomes if item["status"] in {"applied", "unchanged"}]
    counts_complete = all(
        item.get("added_lines") is not None and item.get("removed_lines") is not None
        for item in known
    )
    return {
        "total_paths": len(paths),
        "changed_paths": sum(item["status"] == "applied" for item in outcomes),
        "unchanged_paths": sum(item["status"] == "unchanged" for item in outcomes),
        "failed_paths": sum(item["status"] == "failed" for item in outcomes),
        "not_attempted_paths": sum(item["status"] == "not_attempted" for item in outcomes),
        "bytes_written": bytes_written,
        "added_lines": (sum(item["added_lines"] for item in known)
                        if counts_complete else None),
        "removed_lines": (sum(item["removed_lines"] for item in known)
                          if counts_complete else None),
        "line_counts_complete": counts_complete,
        "preflight_completed": preflight_completed,
    }


def _preflight_failed(
    paths: list[tuple[dict[str, Any], Path, Path | None]],
    error: dict[str, Any],
) -> dict[str, Any]:
    """A failed atomic preflight guarantees no files were published by us."""
    failed_path = error.get("failed_path")
    failed_index = next(
        (i for i, (_, path, _) in enumerate(paths) if str(path) == failed_path), 0,
    )
    outcomes = [
        {
            "path": str(target), "action": action["kind"], "bytes": 0,
            "status": "failed" if i == failed_index else "not_attempted",
            **({"error_code": error.get("code"), "failure_kind": error.get("failure_kind")}
               if i == failed_index else {}),
            **({"conflict": error["conflict"]}
               if i == failed_index and "conflict" in error else {}),
        }
        for i, (action, target, _) in enumerate(paths)
    ]
    return {
        "ok": False, "partial": False, "bytes": 0,
        "outcomes": outcomes, "error": error,
        "preflight_completed": False, "change_state": "no_changes",
        "retry_guidance": "refresh_preconditions",
        "summary": _patch_summary(
            paths, outcomes, bytes_written=0, preflight_completed=False,
        ),
    }


def apply_patch(request: dict[str, Any]) -> dict[str, Any]:
    actions = _parse_patch(request.get("patch"))
    base = request.get("base_dir")
    if base is not None and not isinstance(base, str):
        raise FileError("invalid_request", "Invalid patch base directory")
    create_parents = request.get("create_parents", False)
    atomic = request.get("atomic", False)
    dry_run = request.get("dry_run", False)
    include_diff = request.get("include_diff", False)
    max_diff_bytes = request.get("max_diff_bytes", 8192)
    expected = request.get("expected_hashes", {})
    if (type(create_parents) is not bool or type(atomic) is not bool
            or type(dry_run) is not bool or type(include_diff) is not bool
            or type(max_diff_bytes) is not int or not 1 <= max_diff_bytes <= 16384
            or (include_diff and not dry_run)
            or not isinstance(expected, dict)):
        raise FileError("invalid_request", "Invalid patch options")
    override_encoding = request.get("encoding")
    override_newline = request.get("newline")
    if override_encoding is not None:
        _codec(override_encoding)
    if override_newline not in (None, "lf", "crlf"):
        raise FileError("invalid_request", "Invalid patch newline")
    paths: list[tuple[dict[str, Any], Path, Path | None]] = []
    for action in actions:
        target = resolve_path(action["path"], base)
        moved = resolve_path(action["move"], base) if action["move"] else None
        paths.append((action, target, moved))
    # Reserve room for worst-case per-path statistics and error metadata
    # before any change. All returned field names/values are bounded.
    metadata_bound = sum(
        len(json.dumps(str(target))) + len(json.dumps(str(moved or ""))) + 880
        for _, target, moved in paths
    )
    if metadata_bound + 4096 > 200000:
        raise FileError("response_limit", "Patch result metadata exceeds output limit; split patch")
    if dry_run:
        return _preview_patch(
            request, paths, create_parents=create_parents, atomic=atomic,
            expected=expected, override_encoding=override_encoding,
            override_newline=override_newline,
        )

    # Exact path duplicates/move conflicts are rejected in all modes.
    # Atomic mode must also reject planned file/ancestor conflicts before
    # publication. Non-atomic mode retains legacy sequential partial edits.
    collisions = _check_patch_collisions(paths, ancestors=atomic)
    if collisions is not None:
        return _preflight_failed(paths, {
            "code": "invalid_patch", "message": "Overlapping patch source/destination paths",
            "failed_path": collisions[1], "failure_kind": "overlapping_paths",
        })
    snapshots: list[tuple[list[int] | None, list[int] | None]] = []
    if atomic:
        # Capture the entire source/destination state, then run the
        # non-mutating preview planner. Nothing is published if any path fails.
        snapshots = [
            (_patch_version(target), _patch_version(moved) if moved is not None else None)
            for _, target, moved in paths
        ]
        plan = _preview_patch(
            {**request, "include_diff": False, "include_sha256": False},
            paths, create_parents=create_parents, atomic=True, expected=expected,
            override_encoding=override_encoding, override_newline=override_newline,
        )
        if not plan["ok"]:
            return _preflight_failed(paths, plan["error"])
        for index, (_, target, moved) in enumerate(paths):
            if snapshots[index] != (
                _patch_version(target), _patch_version(moved) if moved is not None else None
            ):
                return _preflight_failed(paths, {
                    "code": "changed_file", "message": "File changed during atomic preflight",
                    "failed_path": str(target), "failure_kind": "changed_file",
                })

    outcomes: list[dict[str, Any]] = []
    bytes_written = 0
    summary_work_left = _PATCH_DELTA_WORK_LIMIT
    failed = False
    uncertain_change = False
    inflight = False
    for index, (action, target, moved) in enumerate(paths):
        if failed:
            outcomes.append({"path": str(target), "action": action["kind"],
                             "status": "not_attempted", "bytes": 0})
            continue
        try:
            if atomic and snapshots[index] != (
                _patch_version(target), _patch_version(moved) if moved is not None else None
            ):
                raise FileError("changed_file", "Path changed since atomic preflight")
            try:
                _expected(target, expected.get(action["path"]))
            except FileError as exc:
                if exc.code == "precondition_failed":
                    raise PatchConflict(
                        "missing_file" if not target.exists() else "hash_mismatch"
                    ) from None
                raise

            can_read = (os.access(target, os.R_OK, effective_ids=True)
                        and os.access(target.parent, os.X_OK, effective_ids=True))
            status = "applied"
            old_raw: bytes | None = None
            added: int | None = 0
            removed: int | None = 0
            before_hash: str | None = None
            after_hash: str | None = None
            data = b""
            if action["kind"] == "add":
                if os.path.lexists(target):
                    raise FileError("already_exists", "Patch addition already exists")
                data, _, _, new_lines = _render_patch_bytes(
                    action, target, override_encoding, override_newline,
                    can_read=False,
                )
                added = len(new_lines)
                if create_parents:
                    inflight = True
                    target.parent.mkdir(parents=True, exist_ok=True)
                inflight = True
                _publish(target, data, atomic=atomic, create=True)
                inflight = False
            elif action["kind"] == "delete":
                if not os.path.lexists(target):
                    raise FileError("not_found", "Patch target not found")
                if atomic and target.is_dir() and not target.is_symlink():
                    raise FileError("invalid_request", "Cannot delete a directory with a file patch")
                if can_read and target.is_file():
                    if target.stat().st_size <= MAX_READ_BYTES:
                        with target.open("rb") as source:
                            old_raw = source.read(MAX_READ_BYTES + 1)
                        if len(old_raw) > MAX_READ_BYTES:
                            old_raw = None
                    if request.get("include_sha256") is True:
                        before_hash = _sha(target)
                if old_raw is None:
                    removed = None
                else:
                    removed = len(old_raw.decode("utf-8", errors="replace").splitlines())
                inflight = True
                target.unlink()
                inflight = False
            else:
                data, old_raw, old_lines, new_lines = _render_patch_bytes(
                    action, target, override_encoding, override_newline,
                    can_read=can_read,
                )
                assert old_raw is not None
                if can_read and request.get("include_sha256") is True:
                    before_hash = hashlib.sha256(old_raw).hexdigest()
                if moved and os.path.lexists(moved):
                    raise FileError("already_exists", "Patch move destination already exists")
                if moved is None and old_raw == data:
                    # Never replace an inode or touch mtime for identical bytes.
                    status = "unchanged"
                    data = b""
                else:
                    added, removed, used = _patch_line_delta(
                        old_lines, new_lines, budget=summary_work_left,
                    )
                    summary_work_left -= used
                    if moved:
                        if create_parents:
                            inflight = True
                            moved.parent.mkdir(parents=True, exist_ok=True)
                        inflight = True
                        _publish(moved, data, atomic=atomic, create=True)
                        target.unlink()
                        inflight = False
                    elif atomic:
                        inflight = True
                        _publish(target, data, atomic=True)
                        inflight = False
                    else:
                        inflight = True
                        with target.open("r+b") as output:
                            output.write(data)
                            output.truncate()
                        inflight = False
                if status == "unchanged":
                    added = removed = 0

            if status == "applied":
                bytes_written += len(data)
            outcome: dict[str, Any] = {
                "path": str(target), "action": action["kind"], "status": status,
                "bytes": len(data) if status == "applied" else 0,
            }
            if moved:
                outcome["moved_to"] = str(moved)
            if added is not None:
                outcome["added_lines"] = added
            if removed is not None:
                outcome["removed_lines"] = removed
            if request.get("include_sha256") is True:
                if before_hash is not None:
                    outcome["before_sha256"] = before_hash
                if action["kind"] != "delete":
                    try:
                        after_hash = _sha(moved or target)
                        outcome["sha256"] = after_hash
                    except OSError as exc:
                        outcome["hash_error_code"] = (
                            "permission_denied" if isinstance(exc, PermissionError)
                            else "filesystem_error"
                        )
                        failed = True
            outcomes.append(outcome)
        except (FileError, FileExistsError, FileNotFoundError, PermissionError, OSError) as exc:
            was_inflight = inflight
            inflight = False
            failed = True
            code = (exc.code if isinstance(exc, FileError)
                    else "already_exists" if isinstance(exc, FileExistsError)
                    else "not_found" if isinstance(exc, FileNotFoundError)
                    else "permission_denied" if isinstance(exc, PermissionError)
                    else "filesystem_error")
            if was_inflight:
                uncertain_change = True
                kind = "outcome_uncertain"
            else:
                kind = (exc.diagnostic["failure_kind"]
                        if isinstance(exc, PatchConflict) else code)
            outcome = {"path": str(target), "action": action["kind"],
                       "status": "failed", "bytes": 0,
                       "error_code": code, "failure_kind": kind}
            if isinstance(exc, PatchConflict) and not was_inflight:
                outcome["conflict"] = exc.diagnostic
            outcomes.append(outcome)

    known_changed = any(item["status"] == "applied" for item in outcomes)
    # Preserve the legacy partial flag for a first-path mutation attempt
    # whose completion is uncertain, even if no write is confirmed.
    partial = failed and (known_changed or uncertain_change)
    change_state = (
        "outcome_uncertain" if uncertain_change else
        "partial" if partial else
        "no_changes" if not known_changed else "complete"
    )
    guidance = (
        "reconcile_before_retry" if change_state in {"outcome_uncertain", "partial"}
        else "refresh_preconditions" if failed else "none"
    )
    failure = next((item for item in outcomes if item["status"] == "failed"), None)
    error: dict[str, Any] | None = None
    if failure is not None:
        code = ("interrupted" if uncertain_change else
                "partial" if partial else failure["error_code"])
        error = {
            "code": code, "message": (
                "File completion uncertain; reconcile the affected paths before retry"
                if uncertain_change else "Patch stopped after first failed path"
            ),
            "failed_path": failure["path"],
            "failure_kind": failure["failure_kind"],
            **({"conflict": failure["conflict"]} if "conflict" in failure else {}),
        }
    return {
        "ok": not failed, "partial": partial, "unknown": uncertain_change,
        "bytes": bytes_written, "outcomes": outcomes,
        "preflight_completed": atomic,
        "change_state": change_state, "retry_guidance": guidance,
        "summary": _patch_summary(
            paths, outcomes, bytes_written=bytes_written, preflight_completed=atomic,
        ),
        **({"error": error} if error is not None else {}),
    }


def _stage(request: dict[str, Any]) -> tuple[Path, Path]:
    target = _target(request)
    session_id = request.get("session_id")
    if not isinstance(session_id, str) or not _SESSION_RE.fullmatch(session_id):
        raise FileError("invalid_request", "Invalid upload session identifier")
    return target, target.parent / (_UPLOAD_PREFIX + session_id)


def _secure_stage(stage: Path, *, writable: bool = False) -> int:
    flags = (os.O_WRONLY if writable else os.O_RDONLY) | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(stage, flags)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        os.close(fd)
        raise FileError("permission_denied", "Upload stage ownership or permissions invalid")
    return fd


def _prune_stages(parent: Path) -> None:
    """Clean orphaned private stages on the next authorized upload in this dir."""
    try:
        with os.scandir(parent) as entries:
            # scandir streams directory entries without materializing them.
            # A fixed entry cap would strand stages behind large numbers of
            # unrelated files on every later upload.
            for item in entries:
                if not item.name.startswith(_UPLOAD_PREFIX):
                    continue
                token = item.name[len(_UPLOAD_PREFIX):]
                if not _SESSION_RE.fullmatch(token):
                    continue
                try:
                    info = item.stat(follow_symlinks=False)
                    if (stat.S_ISREG(info.st_mode)
                            and info.st_uid == os.geteuid()
                            and stat.S_IMODE(info.st_mode) == 0o600
                            and info.st_nlink == 1
                            and time.time() - info.st_mtime > _UPLOAD_STALE_SECONDS):
                        os.unlink(item.path)
                except (FileNotFoundError, PermissionError):
                    continue
    except (FileNotFoundError, PermissionError):
        pass


def upload_start(request: dict[str, Any]) -> dict[str, Any]:
    target = _target(request)
    mode = request.get("mode", "create")
    if mode not in ("create", "overwrite"):
        raise FileError("invalid_request", "Upload mode must be create or overwrite")
    create_parents = request.get("create_parents", False)
    if type(create_parents) is not bool:
        raise FileError("invalid_request", "Invalid create_parents flag")
    if create_parents:
        target.parent.mkdir(parents=True, exist_ok=True)
    if mode == "create" and os.path.lexists(target):
        raise FileError("already_exists", "Destination already exists")
    expected = request.get("expected_sha256")
    _expected(target, expected)
    _prune_stages(target.parent)
    session_id = secrets.token_hex(16)
    stage = target.parent / (_UPLOAD_PREFIX + session_id)
    fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    os.close(fd)
    return {"ok": True, "session_id": session_id, "bytes": 0, "path": str(target)}


def upload_chunk(request: dict[str, Any]) -> dict[str, Any]:
    target, stage = _stage(request)
    offset = request.get("offset")
    source = request.get("data_base64")
    if (type(offset) is not int or offset < 0 or offset > MAX_BINARY_TRANSFER_BYTES
            or not isinstance(source, str)
            or len(source) > ((MAX_BINARY_CHUNK_BYTES + 2) // 3) * 4):
        raise FileError("invalid_request", "Invalid upload chunk offset or length")
    try:
        data = base64.b64decode(source, validate=True)
    except (ValueError, binascii.Error):
        raise FileError("invalid_request", "Invalid base64 upload chunk") from None
    if not data or len(data) > MAX_BINARY_CHUNK_BYTES or offset + len(data) > MAX_BINARY_TRANSFER_BYTES:
        raise FileError("payload_limit", "Upload chunk exceeds allowed size")
    digest = hashlib.sha256(data).hexdigest()
    if request.get("chunk_sha256") != digest:
        raise FileError("precondition_failed", "Upload chunk SHA-256 mismatch")
    fd = _secure_stage(stage, writable=True)
    try:
        if os.fstat(fd).st_size != offset:
            raise FileError("precondition_failed", "Unexpected upload offset")
        os.lseek(fd, offset, os.SEEK_SET)
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("Incomplete stage write")
                view = view[written:]
            os.fsync(fd)
        except OSError:
            return {"ok": False, "unknown": True, "bytes": 0,
                    "error": {"code": "interrupted",
                              "message": "Stage chunk completion uncertain; abort or inspect"}}
    finally:
        os.close(fd)
    return {"ok": True, "path": str(target), "bytes": len(data),
            "offset": offset + len(data), "chunk_sha256": digest}


def upload_finish(request: dict[str, Any]) -> dict[str, Any]:
    target, stage = _stage(request)
    requested_size = request.get("size")
    digest = request.get("sha256")
    mode = request.get("mode", "create")
    if (type(requested_size) is not int or not 0 <= requested_size <= MAX_BINARY_TRANSFER_BYTES
            or not isinstance(digest, str) or not _HASH_RE.fullmatch(digest)
            or mode not in ("create", "overwrite")):
        raise FileError("invalid_request", "Invalid upload completion parameters")
    fd = _secure_stage(stage)
    try:
        stat_before = os.fstat(fd)
        if stat_before.st_size != requested_size:
            raise FileError("precondition_failed", "Upload size mismatch")
        hashed = hashlib.sha256()
        with os.fdopen(os.dup(fd), "rb") as source:
            for block in iter(lambda: source.read(65536), b""):
                hashed.update(block)
        if hashed.hexdigest() != digest.lower():
            raise FileError("precondition_failed", "Upload SHA-256 mismatch")
        # Recheck the stage pathname before publication, after reading the
        # exact file descriptor, to reject a replaced staged inode.
        live = stage.stat(follow_symlinks=False)
        if (live.st_dev, live.st_ino) != (stat_before.st_dev, stat_before.st_ino):
            raise FileError("changed_file", "Upload stage changed before publication")
        _expected(target, request.get("expected_sha256"))
        if mode == "create":
            os.link(stage, target, follow_symlinks=False)
            os.unlink(stage)
        else:
            os.replace(stage, target)
    finally:
        os.close(fd)
    return {"ok": True, "path": str(target), "bytes": requested_size, "size": requested_size,
            "sha256": digest.lower(), "mode": mode, "atomic": True}


def upload_abort(request: dict[str, Any]) -> dict[str, Any]:
    target, stage = _stage(request)
    try:
        fd = _secure_stage(stage)
    except FileNotFoundError:
        return {"ok": True, "path": str(target), "cleaned": False}
    else:
        os.close(fd)
    stage.unlink()
    return {"ok": True, "path": str(target), "cleaned": True}


def download_chunk(request: dict[str, Any]) -> dict[str, Any]:
    target = _target(request)
    limit = request.get("max_bytes", 65536)
    cursor_token = request.get("cursor")
    offset = request.get("offset", 0)
    if (type(limit) is not int or not 1 <= limit <= 65536
            or type(offset) is not int or offset < 0):
        raise FileError("invalid_request", "Invalid download offset or length")
    with target.open("rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise FileError("invalid_request", "Download requires a regular file")
        version = _version(info)
        path_hash = hashlib.sha256(os.fsencode(target)).hexdigest()
        if cursor_token is not None:
            previous = _cursor_decode(cursor_token)
            if (previous.get("path_sha256") != path_hash
                    or previous.get("server") != request.get("server")):
                raise FileError("invalid_cursor", "Download cursor does not match host or path")
            if previous.get("version") != version:
                raise FileError("changed_file", "File changed since previous download")
            offset = previous.get("offset")
            if type(offset) is not int or not 0 <= offset <= info.st_size:
                raise FileError("invalid_cursor", "Invalid download cursor offset")
        elif offset > info.st_size:
            raise FileError("invalid_request", "Download offset exceeds file size")
        source.seek(offset)
        data = source.read(limit)
        if _version(os.fstat(source.fileno())) != version or _version(target.stat()) != version:
            raise FileError("changed_file", "File changed during download")
        next_offset = offset + len(data)
        eof = next_offset == info.st_size
        response: dict[str, Any] = {
            "ok": True, "path": str(target), "bytes": len(data), "size": info.st_size,
            "offset": offset, "next_offset": next_offset, "eof": eof,
            "chunk_sha256": hashlib.sha256(data).hexdigest(),
            "data_base64": base64.b64encode(data).decode("ascii"),
            "next_cursor": None if eof else _cursor_encode({
                "path_sha256": path_hash, "server": request.get("server"),
                "offset": next_offset, "version": version,
            }),
        }
        if request.get("include_sha256") is True:
            # Optional full-file digest; use same opened descriptor to avoid
            # confusing an unrelated replacement with this version.
            source.seek(0)
            checksum = hashlib.sha256()
            for block in iter(lambda: source.read(65536), b""):
                checksum.update(block)
            if _version(os.fstat(source.fileno())) != version or _version(target.stat()) != version:
                raise FileError("changed_file", "File changed during download hashing")
            response["sha256"] = checksum.hexdigest()
        return response


def dispatch(request: dict[str, Any]) -> dict[str, Any]:
    if request.get("protocol") != HELPER_PROTOCOL:
        return {"ok": False, "error": {"code": "invalid_protocol", "message": "Helper protocol mismatch"}}
    try:
        operation = request.get("operation")
        if operation == "inspect":
            return inspect(request)
        if operation == "read":
            return read_file(request)
        if operation == "write":
            return write_file(request)
        if operation == "patch":
            return apply_patch(request)
        if operation == "upload_start":
            return upload_start(request)
        if operation == "upload_chunk":
            return upload_chunk(request)
        if operation == "upload_finish":
            return upload_finish(request)
        if operation == "upload_abort":
            return upload_abort(request)
        if operation == "download_chunk":
            return download_chunk(request)
        return {"ok": False, "error": {"code": "unsupported_operation", "message": "Unknown helper operation"}}
    except FileError as exc:
        return {"ok": False, "error": {"code": exc.code, "message": str(exc)}}
    except FileExistsError:
        return {"ok": False, "error": {"code": "already_exists", "message": "Destination already exists"}}
    except FileNotFoundError:
        return {"ok": False, "error": {"code": "not_found", "message": "Path not found"}}
    except IsADirectoryError:
        return {"ok": False, "error": {"code": "invalid_request", "message": "Expected a regular file"}}
    except PermissionError:
        return {"ok": False, "error": {"code": "permission_denied", "message": "Permission denied"}}
    except UnicodeError:
        return {"ok": False, "error": {"code": "invalid_encoding", "message": "Invalid file encoding"}}
    except OSError:
        return {"ok": False, "error": {"code": "filesystem_error", "message": "Filesystem operation failed"}}


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_ENVELOPE_BYTES + 1)
        if len(raw) > MAX_ENVELOPE_BYTES:
            result = {"ok": False, "error": {"code": "payload_limit", "message": "Envelope too large"}}
        else:
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("Envelope must be an object")
            result = dispatch(data)
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        result = {"ok": False, "error": {"code": "invalid_request", "message": "Invalid helper request"}}
    except PermissionError:
        result = {"ok": False, "error": {"code": "permission_denied", "message": "Permission denied"}}
    except OSError:
        result = {"ok": False, "error": {"code": "filesystem_error", "message": "Filesystem operation failed"}}
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
