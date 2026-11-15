# Security and authorization model

SSH-MCP is an authenticated remote-execution tool, **not** a command
sandbox. A caller with SSH execution permission can run commands
with the full operating-system rights of its approved remote SSH
account, including invoking a shell. Use dedicated, least-privilege
accounts, narrowly scoped hosts and independently pinned SSH keys.

## Security boundaries

1. **HTTPS and client identity:** validate issuer, client metadata,
   exact callback URIs, PKCE and OAuth scopes. Do not expose the
   internal HTTP port or permit unsigned/untrusted client redirect
   fallback.
2. **Separate operator authentication:** OAuth login uses one strong
   credential and JWT signing secret. The Console uses a different
   password, secure cookie, CSRF token and same-origin checks.
   Access tokens are short-lived and refresh-token revocation is
   recorded in durable private SQLite.
3. **Host inventory and keys:** authorized host aliases, remote
   account names and key paths come from operator-controlled files.
   Require a verified known_hosts pin for every target. The MCP
   caller cannot change them through tool arguments.
4. **Restricted approvals:** host and root permission grants are
   separately scoped to the authenticated OAuth session, exact
   validated conversation, host and action kind. They are timed
   and memory-only; a restart clears them. Missing correlation
   metadata never creates an unrestricted grant.
5. **Remote privileges:** file paths, CWD and process execution obey
   the remote account's OS permissions. No implicit sudo, chroot,
   arbitrary path restriction or command allowlist is applied.
6. **Durable audit:** command argv, reason, status and bounded output
   may contain sensitive data and must be protected. File bodies,
   binary payloads, signed upload URLs and sudo passwords are
   excluded from file audits.

## Host and root settings

For initial deployment use `access: "restricted"` and
`privileged_access: "none"`. `access: "always-granted"`
removes interactive host approval but still requires OAuth,
`ssh.execute`, inventory membership and pinned host keys.

Root execution is a separate opt-in `privileged: true` request.
It requires a signed/approved host policy allowing privileged
access, a protected host-specific sudo password, a valid root
approval where restricted and a confirmed root readiness marker.
A host grant is not automatically a root grant. Passworded sudo
uses a fixed wrapper and an isolated environment; unavailable
root confirmation is an error/uncertain result, not proof of root.
None of the public examples provides a sudo password.

## Fail-closed state changes

- A partial multi-file patch can leave earlier successful files;
  `atomic=true` adds local rollback but is not a distributed
  transaction. Inspect file versions after disconnects.
- Binary upload uses bounded chunks, staging and SHA-256 before
  atomic publication. The native upload schema currently depends
  on ChatGPT's attached-file mechanism.
- Cancellation is a request, **not** evidence that remote side
  effects were undone. Native remote exit codes, SSH transport
  failures and missing completion evidence are distinct outcomes.
- A timeout, disconnected client or missing response does not
  prove a write failed. Use durable job IDs, operation IDs and
  actual target state to reconcile before any retry.

## Deployment and secret hygiene

- Keep SSH keys owner-only (0600) with independently verified
  host pins. Never use `StrictHostKeyChecking=no` or agent forwarding.
- Keep OAuth, signing, Console and optional metrics secrets
  distinct; store private files outside Git. Docker administrators
  can inspect container environment variables.
- Every example runs MCP as UID 10001 with read-only SSH
  credentials and private durable state. Basic/hardened bind HTTP
  **only to host loopback** behind an existing HTTPS proxy;
  optional Caddy publishes 80/443 without exposing app HTTP.
  The hardened and Caddy variants additionally use read-only
  container roots and drop Linux capabilities. Update OS,
  Docker, image dependencies and SSH servers.
- Store SQLite/WAL and backup copies privately. If using the
  optional Caddy stack, also preserve its TLS certificate volume.
  Audit may contain full command requests and output.
  Only enable metrics with an independent bearer token over a
  private route.
- Run one application worker: operator approval queues/grants
  are process-local, not shared across instances.
- No merged source change authorizes a live service rollout or
  GitHub repository visibility change. The current repository and
  full Git history are not yet audited for public disclosure.

See [Configuration](configuration.md),
[Operator Console](operator-console.md),
[File operations](file-operations.md) and
[Operations](operations.md).
