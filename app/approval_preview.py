"""Bounded operator previews derived from validated MCP request targets.

Never copy file contents, patch hunks, attachment URLs or credentials into
approval metadata. Patch target paths reuse the actual helper parser.
"""
from __future__ import annotations

from pathlib import PurePosixPath
import json
import re
import shlex
from typing import Any

from .contracts import (
    ApplyPatchRequest, DownloadFileRequest, ExecuteCommandRequest, ExecuteCommandsRequest,
    ReadFileRequest, UploadFileContentRequest, UploadFileRequest, WriteFileRequest,
)
from .file_helper import _parse_patch

FILE_REQUESTS = {
    "read_file": ReadFileRequest,
    "write_file": WriteFileRequest,
    "upload_file": UploadFileRequest,
    "upload_file_content": UploadFileContentRequest,
    "download_file": DownloadFileRequest,
}

# Approval details are transient, browser-only metadata. Never include file
# bodies, patch contents or binary attachments here. Bound each script and the
# whole batch so an approval queue cannot amplify arbitrarily large argv.
MAX_STEP_CHARS = 65536
MAX_BATCH_CHARS = 131072


def approval_steps(request: ExecuteCommandRequest | ExecuteCommandsRequest
                   ) -> list[dict[str, str | bool]]:
    """Show *all* validated command text and execution options, or fail closed.

    Do not grant a command whose complete argv/script cannot be shown.
    """
    remaining = MAX_BATCH_CHARS
    steps: list[dict[str, str | bool]] = []
    if isinstance(request, ExecuteCommandsRequest):
        commands = [request.step_command(i) for i in range(len(request.commands))]
    else:
        commands = [request]
    for index, step in enumerate(commands, 1):
        argv = step.argv
        shell = (len(argv) == 3 and argv[0] in {
            "bash", "/bin/bash", "/usr/bin/bash", "sh", "/bin/sh", "/usr/bin/sh",
        } and argv[1] in {"-c", "-lc"})
        command = argv[2] if shell else shlex.join(argv)
        interpreter = f"{PurePosixPath(argv[0]).name} {argv[1]}" if shell else ""
        # Recognize a descriptive banner only when the script explicitly
        # provides one. Never attempt to infer the effect of arbitrary code.
        match = re.search(r"STEP\s+\d+\s*:\s*([A-Za-z][A-Za-z0-9 /_-]{1,60})", command[:250])
        title = match.group(1).strip(" =-") if match else ""
        execution = {
            "argv": argv,
            "cwd": step.cwd,
            "timeout_seconds": step.timeout_seconds,
            "success_exit_codes": step.success_exit_codes,
            "strict_bash": step.strict_bash,
            "privileged": step.privileged,
        }
        if isinstance(request, ExecuteCommandsRequest):
            execution["batch_timeout_seconds"] = request.timeout_seconds
            execution["stop_on_error"] = request.stop_on_error
        options = json.dumps(execution, ensure_ascii=True, indent=2)
        if (len(command) + len(options) > MAX_STEP_CHARS
                or len(command) + len(options) > remaining):
            raise ValueError("Complete command preview exceeds operator limit")
        steps.append({
            "title": title or f"Step {index}",
            "interpreter": interpreter,
            "command": command,
            "options": options,
            "truncated": False,
        })
        remaining -= len(command) + len(options)
    return steps


def _display_path(path: str, base_dir: str | None) -> str:
    if base_dir and not PurePosixPath(path).is_absolute() and not path.startswith("~"):
        path = base_dir.rstrip("/") + "/" + path
    path = "".join(c if c.isprintable() else "?" for c in path)
    # Keep the filename visible, and make any shortening obvious to the operator.
    return path[:90] + "…" + path[-89:] if len(path) > 180 else path


def approval_summary(name: str, arguments: dict[str, Any],
                     batch: ExecuteCommandsRequest | None = None) -> str:
    if batch is not None:
        return " | ".join(
            " ".join(arg[:90] for arg in step.argv[:6])
            for step in batch.commands
        )[:500]
    if name == "transfer_file":
        source = _display_path(str(arguments.get("source_path", "")), None)
        dest = _display_path(str(arguments.get("dest_path", "")), None)
        src_host = str(arguments.get("source_server", ""))[:64]
        dest_host = str(arguments.get("dest_server", ""))[:64]
        src_root = " (root)" if arguments.get("source_privileged") is True else ""
        dest_root = " (root)" if arguments.get("dest_privileged") is True else ""
        return f"transfer_file: {src_host}:{source}{src_root} -> {dest_host}:{dest}{dest_root}"
    if name == "apply_patch":
        request = ApplyPatchRequest.model_validate(arguments)
        actions = _parse_patch(request.patch)
        shown: list[str] = []
        total_targets = sum(1 + bool(action["move"]) for action in actions)
        shown_targets = 0
        for action in actions[:5]:
            path = _display_path(action["path"], request.base_dir)
            if action["move"]:
                path += " → " + _display_path(action["move"], request.base_dir)
            entry = action["kind"] + " " + path
            entry_targets = 1 + bool(action["move"])
            omitted = total_targets - shown_targets - entry_targets
            candidate = shown + [entry]
            if omitted:
                candidate.append(f"+{omitted} other targets")
            if len(" | ".join(candidate)) > 500:
                break
            shown.append(entry)
            shown_targets += entry_targets
        if total_targets > shown_targets:
            shown.append(f"+{total_targets - shown_targets} other targets")
        return " | ".join(shown)
    if name in FILE_REQUESTS:
        request = FILE_REQUESTS[name].model_validate(arguments)
        return _display_path(request.path, request.base_dir)
    argv = arguments.get("argv")
    if isinstance(argv, list):
        return " ".join(str(arg)[:160] for arg in argv[:8])[:500]
    return ""
