# Configuration and SSH inventory

The [basic application example](getting-started.md) uses the
**environment-file** startup path. Caddy is **optional**, not
required by SSH-MCP: use an existing HAProxy/Nginx/Traefik HTTPS proxy
or [add the separate Caddy example](reverse-proxies.md).
The [hardened example](hardening.md) adds extra container restrictions.

For basic/hardened the app binds HTTP on host loopback only, with a
dedicated Docker bridge `MCP_BRIDGE_SUBNET` and gateway
`MCP_DOCKER_GATEWAY`. Uvicorn's `FORWARDED_ALLOW_IPS` trusts only
that gateway for a **same-host HTTPS proxy**. Your proxy must
replace untrusted X-Forwarded-For and preserve HTTPS origin headers.
For the separate Caddy example, `MCP_PROXY_SUBNET` and
`MCP_PROXY_DYNAMIC_RANGE` separate dynamic app addresses
from Caddy's fixed `MCP_CADDY_IP`. Never trust an entire proxy
subnet or `*` by default.

The OAuth authorization browser page currently supports ChatGPT
callback origins; a different OAuth client metadata URL alone does
not extend its CSP. Environment-file startup does not require
internal signing or deployment manifests. Preserve separately
managed production configurations.

## Inputs and persistence

| Location | Purpose |
| --- | --- |
| `examples/basic/.env` (or `examples/hardened/.env`, `examples/standalone/.env`) | Per-example Compose settings and absolute private paths; no secrets |
| `$MCP_PRIVATE_ENV` | Mode-0600 credentials and application settings |
| `$MCP_SSH_CONFIG_DIR/inventory.json` | Explicit list of allowed SSH hosts |
| `$MCP_SSH_CONFIG_DIR/known_hosts` | Independently verified SSH host-key pins |
| `$MCP_SSH_CONFIG_DIR/identity` | SSH private key owned by container UID 10001, mode 0600 |
| `mcp-state` volume | Persistent OAuth sessions, durable jobs and browser history |

The three SSH files are read-only inside the container under
`/run/ssh-mcp/`. The current database path is
`/var/lib/ssh-mcp/jobs.sqlite`. This path changed in the source cleanup;
see [upgrade compatibility](upgrade-compatibility.md) before replacing an
existing installation.
Never mount two service instances to the same database.

## Environment keys

| Key | Behavior |
| --- | --- |
| `MCP_ISSUER` | Public HTTPS origin, without path/trailing slash; resource equals issuer + `/mcp` |
| `MCP_ALLOWED_HOSTS` | Explicit public host plus private localhost health checks |
| `MCP_ALLOWED_ORIGINS` | Restrict allowed MCP/HTTP origins to the configured client |
| `MCP_CIMD_CLIENT_ID` | One HTTPS OAuth client metadata URL per deployment |
| `MCP_ALLOWED_REDIRECT_URIS` | Exact callback URI allowlist for that client |
| `MCP_CIMD_VALIDATE_REMOTE` | Keep `true` to validate client metadata |
| `MCP_LOGIN_KEY` | Independent 32+ char OAuth login credential |
| `MCP_TOKEN_SIGNING_SECRET` | Different 32+ char JWT signing secret |
| `HISTORY_VIEWER_PASSWORD` | Different 16+ char operator-console password |
| `MCP_SSH_TOOLS_ENABLED` + `SSH_EXECUTOR_ENABLED` | Both `true` to enable SSH methods |
| `SSH_INVENTORY_FILE` | Absolute in-container JSON inventory path |
| `SSH_APPROVED_ALIASES` | Explicit comma-separated aliases, not dynamic DNS targets |
| `SSH_JOBS_ENABLED`, `SSH_JOBS_DB` | Durable, auditable SSH execution with a persistent SQLite path |
| `SSH_JOBS_RETENTION_MONTHS` | Calendar-month audit retention, 3 in sample |
| `HISTORY_VIEWER_ENABLED` | Enable the separate password-protected `/console` |
| `HISTORY_STORY_ID_MAX_CHARS`, `HISTORY_STORY_ID_TRUNCATE_FROM` | Optional console table display settings (16, end by default); managed installations set them via viewer.story_id_max_chars and viewer.story_id_truncate_from in signed service.json |
| `MCP_METRICS_ENABLED` | Disabled in example; enabling needs a distinct 32+ char `MCP_METRICS_TOKEN` |
| `MCP_CONVERSATION_HEADER_NAME` | Optional dedicated workflow header; default `X-OpenAI-Session` |
| `WEB_CONCURRENCY` / `UVICORN_WORKERS` | Both must be 1; grants and approval queue are in-process |

Do **not** set legacy `SSH_JOBS_RETENTION_SECONDS` alongside
`SSH_JOBS_RETENTION_MONTHS`. Weak/missing secrets and mismatched
issuer/resource are startup failures; no anonymous SSH fallback is
provided. Token expiration is fixed at 15 minutes, while operator
authorization sessions have bounded absolute lifetimes.

## Inventory host schema

`inventory.json` has `version: 1` and a nonempty `hosts` array. Each
host must supply lowercase unique `alias`, DNS/IPv4 `address`,
numeric `port`, remote `username`, absolute `identity_file` and
`known_hosts_file`, list of `principals`, `environment`
(`non-production` or `production`), `access`
(`restricted` or `always-granted`) and `max_parallel`.
`privileged_access` is `none` by default, optionally
`restricted` or `always-granted`.

The fixed authorization subject is `ssh-mcp-operator`. It is
the OAuth actor and inventory `principals` identity, **not** the
remote SSH username. Installations using a previous operator identity
must plan a coordinated, separately approved change to signed service
configuration and inventory. Old OAuth sessions must reauthorize;
actor-scoped history/grants are not silently migrated or reassigned.
MCP callers choose an approved alias returned by `list_servers` and
cannot supply an arbitrary host address, remote username or SSH key.

`restricted` hosts require a valid conversation identifier plus a
timed operator decision before execution. `always-granted` bypasses
only this *additional* approval, not OAuth, principal membership or
host-key verification. For a starter host choose `restricted` and
`privileged_access: "none"`.

Private SSH keys must be service-UID-owned and mode 0600, not symlinks.
Known hosts and inventory must be regular readable files not writable
by group/others. Never pin a key using only unauthenticated
`ssh-keyscan` output. Remote OS rights, not a file-name filter,
govern SSH actions.

## Managed deployment mode is separate

Setting **any** of `MCP_CONFIG_FILE`, `MCP_INVENTORY_FILE`,
`MCP_KNOWN_HOSTS_FILE` or `MCP_SECRETS_FILE` selects the
managed file loader and requires all four. This mode requires a
strict signed JSON schema, a DNS-based HTTPS issuer (no path, query,
userinfo or fragment), a separately approved HTTPS client metadata
URL with remote verification enabled, explicit nonempty HTTPS
redirect/CORS-origin allowlists, and the fixed `ssh-mcp-operator` subject.
Wildcard, malformed or comma-containing callback URLs are rejected
before any SSH identity is written. Commas are reserved as delimiters
in the environment-variable allowlist representation. The issuer,
metadata client and redirect origins are **not restricted to
any project-specific domains**. This does not provide multiple
simultaneous OAuth clients, and the login-page browser CSP still
permits only ChatGPT callback origins (see [OAuth clients](oauth-clients.md)).
Do not use signed managed startup mode with public Compose examples.

For production, the issuer and subject are security boundaries:
update signed service.json, inventory principals and any client
configuration together in a reviewed release. Changing an issuer
invalidates existing tokens; changing the subject requires new
authorization and an explicit actor-history migration or historical
read-only access policy. Legacy-subject refresh attempts now revoke
their stored session and legacy-subject bearer tokens fail verification.
Existing audit history is not reassigned. Neither data migration nor
live deployment happens automatically.

For **environment-file** installations, no public Host is implicitly
trusted. Set `MCP_ALLOWED_HOSTS` explicitly to your HTTPS hostname
(and port, when applicable) plus locally needed loopback health hosts.
Use the example for the selected HTTPS proxy in `examples/basic/` or
`examples/standalone/` and set the issuer's hostname and port explicitly.
A healthy local readiness probe does not prove public MCP requests
pass Host validation.

This source version renames the Python distribution, data/mount paths,
metrics and remote file helper namespace. These are **breaking changes**
for existing deployments; see [upgrade compatibility](upgrade-compatibility.md).
