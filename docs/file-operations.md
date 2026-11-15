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

## Native binary upload (current client limitation)

`upload_file` uses a **native ChatGPT attached file** in the
`file` parameter (`openai/fileParams`). It is not an
arbitrary HTTPS URL supplied by the model and is not a
generic upload parameter supported by every MCP client.
The service fetches the temporary signed HTTPS source
and performs public-IP DNS pinning, TLS certificate
verification, restricted port/redirect checks and
bounded time/size reads; it never logs signed URLs.

Upload limit: **8 MiB**, transferred in 128-KiB SHA-256-
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

A vendor-neutral upload workflow is planned separately;
do not advertise this ChatGPT adapter as universal.

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
