# Nonproduction live preview

Use this operator-only helper to temporarily switch an existing managed,
digest-pinned SSH-MCP service behind HAProxy to a separate preview container.
Use **only an explicitly approved nonproduction host and maintenance window**.
The source must be reviewed and compatible with the signed runtime and SQLite
schema. This is not a release deployment, production diagnostic, or substitute
for isolated integration acceptance.

## Select the exact target

On the approved host, stage the reviewed source checkout accessible to the
container UID 10001. Supply the exact local hostname, original container,
HAProxy container, backend/server from its admin socket, and original ingress
Docker network. Verify that all MCP/Console ingress uses that backend and
that there will be no direct access to the private port during the switch.
No private identifiers or credentials belong in the checkout. Do not run
deployment, Docker daemon restarts, HAProxy reloads or other lifecycle
operations concurrently with a preview.

Example with synthetic names (replace with the reviewed nonproduction values):

```bash
preview=(python3 ops/preview/lab_preview.py
  --test-host demo-test
  --container ssh-mcp
  --proxy haproxy
  --backend ssh_mcp/ssh_mcp_demo
  --network demo-ingress)
"${preview[@]}" status
"${preview[@]}" fix-source
"${preview[@]}" start --trace
docker logs --since 5m ssh-mcp-dev 2>&1 | grep SSH_MCP_PREVIEW_REQUEST
"${preview[@]}" stop
```

The default runs the **original installed wheel**, with only the preview
entrypoint and diagnostic middleware added. It cannot accidentally use an
older checkout's application. Use `start --source-preview` explicitly for a
reviewed local application edit and Uvicorn reload; add `--trace` if needed.
Reloads interrupt in-memory approvals and operations; do not edit while they
are active. Mount only the app source and preview tooling, read-only.
`fix-source` repairs readability of source files only; it refuses symlinks,
special files and unsafe ownership. Never use it on a source tree containing
credentials. The normal service does not import the preview entrypoint.

## Request diagnostics

`--trace` logs MCP request method, path, repeated HTTP header names/values,
and bounded JSON-RPC envelope and metadata. Known protocol headers and
validated correlation IDs are visible; credential-like header values are
redacted, unknown values are fingerprinted with a process-local random key
so identical values can be compared without exposing a possible credential.
Known correlation metadata includes Codex thread/turn IDs. Only argument
names, never arbitrary tool arguments, are recorded. No bearer/cookie values,
OAuth form values, query strings, response bodies or raw request body are
logged. Capture at most 64 KiB of a consumed request body and 256 headers.
Logs are sensitive nonproduction diagnostic data; restrict access and stop
the preview when finished. The trace is off by default.

## Switch and recover

The helper checks that the original configuration declares the lab environment,
uses the local Docker socket, and checks the signed-managed configuration mounts, current
private runtime paths, immutable local image ID, restricted private port,
state volume, two original networks and the exact selected HAProxy server
address. It never modifies the original container, image or release lock.
Before stopping it, put the selected server in maintenance, wait for
`awaiting_approval`, `queued`, and `running` commands, file operations and
batches to drain, and create a mode-0600 integrity-checked SQLite online
backup under the mode-0700 user cache. Check work again after snapshot.
A private persistent marker binds the original container and proxy IDs and the exact
selected routing target. The helper stops the original (never removes it),
starts the temporary hardened preview using the same state volume, verifies
health, then redirects only the selected HAProxy server via its admin socket.
No HAProxy configuration rewrite or daemon restart occurs.
Before using this version, restore any active older preview with its original
helper; never switch tooling while an earlier switch is incomplete.

Use the same target options for `stop` or `recover`. Stop drains preview work,
removes only the identified preview container, starts the intact original,
checks readiness and restores the server address/ready state. Failed switches
attempt restoration; if interrupted or restoration fails, inspect `status`
and use `recover`. Never blindly retry start. Recovery may interrupt active
operations; restoring SQLite itself is deliberately not automatic. Only one
container may access the volume at any time. The backup contains sensitive
audit/OAuth state; keep it private, and separately authorize restoration or
deletion. Schema changes can make rollback incompatible: do not use this
helper to experiment with migrations against persistent state.
