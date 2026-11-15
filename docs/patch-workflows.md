# Safe multi-file editing

Use `apply_patch` for related source, tests and
documentation changes on an **authorized remote host**.
A single patch may Add, Update, Delete and Move files.
A normal patch stops at the first failed file; earlier
applied changes remain unless an explicitly requested
and applicable atomic workflow rolls them back.

The tool does not confer GitHub repository write
permissions, SSH privileges or extra OS rights.
Use a dedicated worktree and the approved remote
account's existing permissions.

## Recommended workflow

1. Discover the approved target with `list_servers`,
   choose a stable `base_dir` and record a non-secret
   `reason` and unique operation ID.
2. Use `read_file(include_sha256=true)` for **each
   existing patch source**, including delete and move
   sources; continue any returned opaque cursors. Record
   complete raw-file SHA-256 values.
3. Prepare one Codex patch with `*** Begin Patch` and
   `*** End Patch` markers. Provide `expected_hashes`
   keyed by the **original input path strings**.
4. Run `apply_patch` with `dry_run=true`,
   `atomic=true` and `include_sha256=true`. Require
   overall success, `applicability=applicable`, and
   check every per-path result. The preview does not
   lock files or reserve future permissions.
5. Optionally request `include_diff=true` for a
   bounded human-readable preview; avoid exposing
   secrets through returned diffs.
6. Apply the **same** patch and preconditions with
   `atomic=true` and a **new unique** operation ID.
   Compare `prospective_sha256` from the preview with
   actual output hashes; verify important destinations
   with a fresh read.
7. Run relevant project validation with
   `execute_command` and the correct absolute `cwd`.
   Do not launch unchecked, untrusted build scripts.

Example structure:

~~~text
*** Begin Patch
*** Add File: notes.txt
+new content
*** Update File: config.txt
@@
-old value
+new value
*** End Patch
~~~

## Preview, conflict and atomic semantics

Preview is advisory: it reports whether additions,
moves, deletion and context anchors are applicable,
as well as line counts and prospective hashes.
Invalid or ambiguous hunk anchors, changed hashes,
file/ancestor collisions, move destination conflicts
and encoding problems are reported as actionable
path-scoped outcomes. The preview is not a
transactional reservation; **apply repeats preflight**.

`atomic=true` preflights the whole plan before
mutation and has best-effort rollback semantics for
approved filesystem changes, but concurrent writers,
unexpected I/O errors, hard links and external side
effects can make recovery uncertain. Never equate
"atomic" with a distributed filesystem transaction.
Existing encodings, BOM, line endings and final
newline states are preserved unless explicitly
changed; new files default to UTF-8/LF.

For ordinary stop-on-first-error patches, inspect
`applied`, `failed` and `not_attempted` per path.
Do not replay the entire patch automatically when
some paths were already applied.

## Interrupted response / retry

An operation ID identifies an audited attempt and
duplicate IDs are refused. It is not a lease or
idempotent write transaction across a disconnected
SSH call. If the client sees `partial`, `unknown`,
`transport_error`, a timeout or a missing response:

1. Find the original operation in durable audit.
2. Read affected files and compare hashes/contents
   with the expected pre/post images.
3. Determine which changes committed and whether
   a rollback was confirmed.
4. Author a **new, minimal** reconciliation patch
   with fresh preconditions, not a blind replay.

See [File operations](file-operations.md),
[Commands and jobs](commands-jobs.md) and
[Security](security.md).
