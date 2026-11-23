"""Fixed, remote Python source/receiver scripts for the SSH-MCP RAM relay.

These are not a general remote-execution interface. User paths are distinct,
quoted argv parameters; only the pinned SSH inventory selects remote hosts.
File bytes are never returned in a tool response, log or durable audit row.
"""
from __future__ import annotations

SOURCE = r'''
import hashlib, os, stat, struct, sys

path, maximum, chunk, marker, root = sys.argv[1:]
maximum, chunk = int(maximum), int(chunk)
path = path if os.path.isabs(path) else os.path.join(os.path.expanduser("~"), path)
if root == "1" and os.geteuid() != 0:
    sys.exit(126)
def fingerprint(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
try:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb", buffering=0) as f:
        start = os.fstat(f.fileno())
        if not stat.S_ISREG(start.st_mode) or start.st_size > maximum:
            sys.exit(65)
        os.set_blocking(f.fileno(), True)
        h = hashlib.sha256()
        while True:
            data = f.read(chunk)
            if not data:
                break
            h.update(data)
        if fingerprint(os.fstat(f.fileno())) != fingerprint(start):
            sys.exit(76)
        f.seek(0)
        sys.stderr.buffer.write(b"\x1e"+marker.encode("ascii")+b"\x1e\n")
        sys.stderr.buffer.flush()
        sys.stdout.buffer.write(struct.pack(">Q", start.st_size)+h.digest())
        remaining = start.st_size
        actual = hashlib.sha256()
        while remaining:
            data = f.read(min(chunk, remaining))
            if not data:
                sys.exit(76)
            sys.stdout.buffer.write(data)
            actual.update(data)
            remaining -= len(data)
        sys.stdout.buffer.flush()
        if actual.digest() != h.digest() or fingerprint(os.fstat(f.fileno())) != fingerprint(start):
            sys.exit(76)
except OSError:
    sys.exit(74)
'''

RECEIVER = r'''
import fcntl, hashlib, json, os, secrets, stat, sys, time

(path, mode, parents, size_text, digest, expected, chunk_text, stale_text, marker, root) = sys.argv[1:]
size, chunk, stale = int(size_text), int(chunk_text), int(stale_text)
if root == "1" and os.geteuid() != 0:
    sys.exit(126)
path = path if os.path.isabs(path) else os.path.join(os.path.expanduser("~"), path)
parent = os.path.dirname(path)
stage = None
fd = None
def preimage():
    if expected == "-":
        return
    try:
        existing_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(existing_fd, "rb", buffering=0) as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise ValueError()
            h = hashlib.sha256()
            while True:
                block = f.read(65536)
                if not block:
                    break
                h.update(block)
            if h.hexdigest() != expected:
                raise ValueError()
    except (OSError, ValueError):
        sys.exit(75)
try:
    if parents == "1":
        os.makedirs(parent, exist_ok=True)
    if mode == "create" and os.path.lexists(path):
        sys.exit(73)
    preimage()
    # Cleanup is safe against currently locked stages even when stale.
    # The cutoff always exceeds the maximum configured transfer duration.
    with os.scandir(parent) as entries:
        for item in entries:
            if not item.name.startswith(".ssh-mcp-transfer-"):
                continue
            try:
                statinfo = item.stat(follow_symlinks=False)
                if (not stat.S_ISREG(statinfo.st_mode) or
                    statinfo.st_uid != os.geteuid() or
                    stat.S_IMODE(statinfo.st_mode) != 0o600 or
                    statinfo.st_nlink != 1 or
                    time.time() - statinfo.st_mtime <= stale):
                    continue
                candidate = os.open(item.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    fcntl.flock(candidate, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    if os.fstat(candidate).st_ino == statinfo.st_ino:
                        os.unlink(item.path)
                except BlockingIOError:
                    pass
                finally:
                    os.close(candidate)
            except (FileNotFoundError, PermissionError, OSError):
                continue
    stage = os.path.join(parent, ".ssh-mcp-transfer-" + secrets.token_hex(16))
    fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    original = os.fstat(fd)
    if stat.S_IMODE(original.st_mode) != 0o600:
        sys.exit(74)
    sys.stderr.buffer.write(b"\x1e"+marker.encode("ascii")+b"\x1e\n")
    sys.stderr.buffer.flush()
    h = hashlib.sha256()
    remaining = size
    with os.fdopen(fd, "wb", buffering=0, closefd=False) as target:
        while remaining:
            block = sys.stdin.buffer.read(min(chunk, remaining))
            if not block:
                sys.exit(76)
            target.write(block)
            h.update(block)
            remaining -= len(block)
        os.fsync(fd)
    # Only an explicit post-source-verification COMMIT may publish.
    if h.hexdigest() != digest or sys.stdin.buffer.read(7) != b"COMMIT!":
        sys.exit(76)
    if os.fstat(fd).st_ino != os.stat(stage, follow_symlinks=False).st_ino:
        sys.exit(76)
    preimage()
    if mode == "create":
        os.link(stage, path, follow_symlinks=False)
        os.unlink(stage)
    else:
        os.replace(stage, path)
    stage = None
    print(json.dumps({"ok": True, "size": size, "sha256": digest}), flush=True)
except (OSError, ValueError):
    sys.exit(74)
finally:
    if fd is not None:
        os.close(fd)
    if stage is not None:
        try:
            os.unlink(stage)
        except OSError:
            pass
'''
