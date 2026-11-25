# SSH text files and binary transfer

File tools use the **same** authorized OAuth actor, `ssh.execute`
scope, host inventory, verified host key and remote account as
`execute_command`. They do not create a new access policy, grant
additional directory permissions or silently elevate privileges.
The remote operating system decides what the account may read,
write and delete.

## Paths and the remote helper

`server` is an approved alias from `list_servers`. `path` can be
absolute or relative to the connected SSH user's HOME;
`base_dir` optionally gives one explicit base for related paths.
Every mutation should have a concise, non-sensitive `reason`,
optional `story_id` and a unique `operation_id` for correlating
audit/recovery. An operation ID is **not** a promise of
exactly-once execution.

The first authorized file operation lazily installs a
SHA-256-verified, versioned Python 3 helper under the target
account's private home directory. Reuse requires matching
digest and safe permissions; unsafe symlinks or ownership fail
closed. Ordinary SSH commands and startup do not install the
helper. The target must have Python 3; the service does not
use sudo to install host packages.

## Read text and follow cursors

`read_file` returns a bounded text segment, line/byte offsets,
optional complete-file SHA-256, EOF and a version-bound opaque
`next_cursor`. Typical fields:

~~~yaml
read_file:
  server: demo
  path: notes.txt
  max_bytes: 32768
  include_sha256: true
  reason: Inspect approved text file
~~~

If `truncated=true` and `eof=false`, pass the returned cursor
without calculating offsets. If the file changes, the cursor
fails with `changed_file`; restart the read. Supported text
encodings include UTF-8, UTF-8-SIG and UTF-16 variants. Binary
data should use `download_file` instead.

## Write text safely

`write_file` supports `mode=create` (fail if exists),
`replace` (default; create if missing) and `append`
(create if missing), with opt-in parent creation and
`include_sha256`. An optional `expected_sha256` verifies
the pre-image; this does **not** lock the file against other
writers. Text uses UTF-8/LF by default, with explicit
encoding/newline options. Inputs are bounded by the
private SSH payload envelope.

`atomic=true` on create/replace publishes a new inode and
may affect hard-link identity, ownership/mode and final
symlink behavior. The default in-place write has different
filesystem semantics; append is not an atomic replacement.
Inspect the current file before repeating an uncertain
append or overwrite.

## Patches

`apply_patch` accepts Codex-style `*** Begin Patch` /
`*** End Patch` syntax for Add/Update/Delete/Move.
Provide pre-image digests for all existing sources and
prefer `dry_run=true` with `atomic=true`, followed by the
same patch with a fresh operation ID after reviewing
the preview. Stops/rollbacks and stale-content
diagnostics are described in [Patch workflows](patch-workflows.md).

## Host-to-host relay (`transfer_file`)

`transfer_file` copies one ordinary file from **one approved SSH host to
another**. The SSH-MCP service opens two independently pinned SSH sessions,
streams fixed-size chunks through bounded process memory, and never includes
binary data in MCP tool results or SQLite. Neither host needs SSH keys
or direct network access to the other. Source and destination have independent
normal/root approvals; a grant for one host does not authorize the other.
Root access requires the current per-host sudo unlock policy.

~~~yaml
transfer_file:
  source_server: demo-node-a
  source_path: artifacts/candidate.deb
  dest_server: demo-node-b
  dest_path: artifacts/candidate.deb
  mode: create
  create_parents: false
  wait_seconds: 30
  timeout_seconds: 900
  reason: Copy a previously verified package
  story_id: EXAMPLE-123
  operation_id: unique-approved-copy-001
~~~

Paths may be absolute or relative to the effective remote user's HOME.
`source_privileged` and `dest_privileged` default to `false`; privileged
destination files belong to root, and ordinary destination files belong to
the connected SSH user. New files always use `0600`. Optional
`source_sha256` checks the immutable source bytes; `expected_sha256`
checks an existing destination before **overwrite** and is rejected
for `mode=create`. Default create mode fails if the destination exists.

The relay verifies the source digest before beginning the destination
write. A temporary private file in the destination directory is committed
atomically only after full-size and digest verification, a confirmed complete
source SSH exchange, and destination pre-image revalidation. Transfers to
the same normalized destination path are serialized within the service.
No transfer deletes the source. File contents never pass through the model
or MCP client.

Small transfers return `succeeded` directly. If still active after
`wait_seconds` (0–60, default 30), the tool returns `running` with a durable
`file_...` history ID. Use `get_job`, `list_jobs` or the Operator Console
to monitor. `cancel_job` requests cancellation and closes both channels;
a confirmed incomplete receiver removes its private stage. If cancellation
or publication cannot be confirmed, the terminal result is `unknown`, not
a guarantee that the destination is untouched. **Inspect the destination
before retrying**, particularly after an overwrite. The service removes
orphaned, unlocked private stages on later authorized transfers, never stages
still held by a live transfer.

Managed signed `service.json` may include an optional `transfer` section:

~~~json
{"transfer": {"max_bytes": 1073741824, "chunk_bytes": 262144}}
~~~

Standalone mode uses `SSH_TRANSFER_MAX_BYTES` and
`SSH_TRANSFER_CHUNK_BYTES`. Defaults are 1 GiB maximum file size and
256 KiB chunks; hard ceilings are 4 GiB and 4 MiB respectively, with
chunks no larger than the maximum file size. Transfer execution also obeys
the existing SSH timeout and host/global concurrency limits. No temporary
relay files are written inside the SSH-MCP container.

## Binary upload

Two tools share the same staged, SHA-256-verified transfer described below:

- `upload_file` takes a **native ChatGPT attached file** (ChatGPT clients).
- `upload_file_content` takes the file inline as base64 `content_base64`, for
  any MCP client without native attachments (for example Claude Code, Cursor
  or scripts). It accepts the same `server`, `path`, `base_dir`, `mode`,
  `create_parents`, `source_sha256`, `expected_sha256`, `reason`, `story_id`
  and `operation_id` fields. The decoded size is capped by
  `SSH_UPLOAD_CONTENT_MAX_BYTES` (standalone) or the optional signed
  `{"upload": {"content_max_bytes": 1048576}}` section; the default is
  **1 MiB** and the hard ceiling is 8 MiB. Oversized or invalid base64 is
  rejected before any SSH call. Content is never written to logs, audit or
  history. A model writes every byte into its tool call, so keep inline
  uploads small.

### Native ChatGPT attachments

`upload_file` uses a **native ChatGPT attached file** in the
`file` parameter (`openai/fileParams`). It is not an
arbitrary HTTPS URL supplied by the model and is not a
generic upload parameter supported by every MCP client.
The service fetches the temporary signed HTTPS source
and performs public-IP DNS pinning, TLS certificate
verification, restricted port/redirect checks and
bounded time/size reads; it never logs signed URLs.

Attachment upload limit: **8 MiB**, transferred in 128-KiB SHA-256-
verified chunks to a private staging file on the target.
The helper verifies the whole digest before atomic
publication. Default `mode=create` refuses existing
targets; explicit `mode=overwrite` replaces. An
interrupted upload is not resumable; an old private
stage may be cleaned on the next authorized upload
into that directory. Never claim an interrupted
transfer succeeded before inspecting the destination.

`download_file` emits at most **65,536 bytes per chunk**
as MCP binary resource data with size, offset,
chunk hash, optional full-file hash and version-bound
`next_cursor`. Reassemble only after checking each
chunk. MCP resource delivery does not guarantee a
particular client's UI renders it as a downloadable
attachment.

Do not advertise `upload_file` as universal; non-ChatGPT
clients use `upload_file_content`.

## Audit and recovery

File audits store operation kind, alias, path summary,
status, byte counts and safe hashes. They omit file
bodies, patches, binary payloads, temporary signed
URLs and SSH helper stdin. The Operator Console has
no file upload/download action.

Typical errors include `not_found`, `already_exists`,
`invalid_cursor`, `changed_file`,
`precondition_failed`, `payload_limit`,
`duplicate_operation`, `partial` and `unknown`.
A lost response may follow an actual successful
mutation: reconcile the operation ID, audit record
and destination state before deciding to retry.
