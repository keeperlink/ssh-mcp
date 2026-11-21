# Troubleshooting

Run only read-only diagnostics until the source of a
failed or uncertain operation is understood. Avoid
repeating SSH commands, uploads or patches after
network errors without reconciling their durable IDs.

## Startup and Compose

- **Compose reports an unset variable:** choose the matching
  example's `.env` file. Basic/hardened need an unused
  `MCP_BRIDGE_SUBNET` and `MCP_DOCKER_GATEWAY`;
  optional Caddy also needs `MCP_PUBLIC_HOST`,
  `MCP_PROXY_SUBNET`, `MCP_PROXY_DYNAMIC_RANGE` and
  `MCP_CADDY_IP` with no dynamic/static address overlap.
  `MCP_PRIVATE_ENV` and `MCP_SSH_CONFIG_DIR` must be
  absolute, operator-owned paths. Compose syntax checks
  cannot prove these files' semantics.
- **MCP container fails to start:** check `MCP_ISSUER`,
  valid independent secrets, one-worker settings, the
  named data volume's UID 10001 ownership and
  `SSH_INVENTORY_FILE`/`SSH_APPROVED_ALIASES`.
  The sample `REPLACE_ME` credentials intentionally
  fail startup until replaced.
- **SSH inventory or private key refused:** use
  container-visible absolute paths and regular files,
  verify UID 10001 owns identity (0600) and can read
  non-writable inventory/known_hosts; ensure exact
  alias, principal and server/port match.
- **No public HTTPS:** basic/hardened require a separately
  configured **existing reverse proxy on the same host**;
  an HTTP loopback port is not a public HTTPS service.
  In the optional Caddy variant check DNS, TCP 80/443,
  ACME issuance, `MCP_PUBLIC_HOST` and `MCP_ISSUER`.
  Do not expose the app's HTTP port publicly to fix
  routing or certificate problems.

## OAuth and client access

- **Wrong issuer/resource or callback:** client URI
  must equal `MCP_ISSUER + "/mcp"` and callback must
  appear exactly in `MCP_ALLOWED_REDIRECT_URIS`.
  Do not disable remote client metadata validation.
- **No SSH tools:** OAuth scopes must include
  `ssh.execute` and both SSH execution flags must
  be enabled; an inventory host must include the
  configured operator principal.
- **Restricted SSH denied without a dialog:** review the signed/approved
  host policy, current OAuth session, and any malformed or conflicting
  conversation identifiers. A client with no conversation identifier can
  receive an agent-wide timed grant **only** with a verified OAuth client
  identity; approval is otherwise limited to one request.
- **Console cannot sign in:** use the independent
  Console password via HTTPS and correct same-origin
  CSRF form; an OAuth login credential is not valid
  for the Console. Legacy `/history` paths were
  removed in favor of `/console`.
- **Lost refresh session:** authorization has an
  absolute expiry, and revocation blocks renewal.
  Reauthorize deliberately, without weakening
  callback or signer checks.

## SSH execution and result recovery

- **Host key mismatch:** stop and compare with the
  server operator's independently verified public
  key; do not use `ssh-keyscan` as proof, or turn
  off strict checking.
- **Permission denied:** check the *remote* account
  and target path/command permissions, rather than
  granting root as a workaround.
- **Timeout, transport error, truncated output:** read
  `get_job` and paged `get_job_output`. Differentiate
  known command exit, missing completion, output
  delivery failure and interrupted remote state.
- **Unknown patch/upload outcome:** find the
  operation ID and inspect actual target hashes.
  Never blindly replay a write or assume cancellation
  reverted side effects.
- **Database not ready:** inspect private state/WAL
  and ownership; do not delete WAL files while
  the service is running. Use verified online backup
  and stopped restore procedures in [Operations](operations.md).

## Public endpoint checks

With basic/hardened, your **existing** proxy must allow
OAuth discovery, `/oauth/*`, `/mcp` and `/console`
but block public `/ready`, `/health` and `/metrics`.
The optional Caddy example implements those restrictions
in its Caddyfile. An external 404 for an internal health
route is intended; test private readiness **inside**
the app container.

For tool behavior details see
[Commands and jobs](commands-jobs.md),
[File operations](file-operations.md) and
[Operator Console](operator-console.md).
