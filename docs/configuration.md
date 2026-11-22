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

The OAuth authorization page supports any HTTPS CIMD client whose
metadata and requested callback pass validation and whose consent is
approved by the operator. Its CSP permits only the verified callback
origin for that authorization request, not an arbitrary client origin. Environment-file startup does not require
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
| `MCP_LOG_LEVEL` | Application logging level in environment-file mode (default INFO) |
| `MCP_ISSUER` | Public HTTPS origin, without path/trailing slash; resource equals issuer + `/mcp` |
| `MCP_ALLOWED_HOSTS` | Explicit public host plus private localhost health checks |
| `MCP_ALLOWED_ORIGINS` | Initial trusted HTTP Origins; active consented clients add exact approved callback origins, which persist in OAuth sessions |
| `MCP_CIMD_CLIENT_ID` | Standalone offline fallback client identity; managed signed service derives it from clients |
| `MCP_ALLOWED_REDIRECT_URIS` | Standalone offline fallback redirects; managed service derives them from clients |
| `MCP_CIMD_VALIDATE_REMOTE` | Keep `true` for dynamic HTTPS CIMD discovery; disabling enforces the single configured legacy client |
| `MCP_DCR_ENABLED` | Default `true`: enable RFC 7591 public-client DCR; managed signed service optional `oauth.dcr_enabled` toggles this feature independently of CIMD |
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
| `WEB_CONCURRENCY` / `UVICORN_WORKERS` | Both must be 1; grants and approval queue are in-process |

Do **not** set legacy `SSH_JOBS_RETENTION_SECONDS` alongside
`SSH_JOBS_RETENTION_MONTHS`. Weak/missing secrets and mismatched
issuer/resource are startup failures; no anonymous SSH fallback is
provided. Token expiration is fixed at 15 minutes, while operator
authorization sessions have bounded absolute lifetimes.

## Signed client identities and conversation selectors

The managed signed configuration has one top-level `clients` object, keyed
by operator-approved display name. Standalone environment mode uses
`MCP_CLIENTS` with the same JSON object. For example:

```json
{
  "clients": {
    "ChatGPT": {
      "identities": ["https://chatgpt.com/oauth/client.json"],
      "conversation_id": {"sources": [
        {"type": "header", "name": "X-OpenAI-Session"},
        {"type": "metadata", "name": "x-codex-turn-metadata", "field": "thread_id"}
      ]},
      "offline_redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"]
    },
    "Custom": {
      "identities": ["https://custom.example.org/oauth/client.json"],
      "conversation_id": {"sources": [
        {"type": "header", "name": "X-Custom-Conversation"}
      ]}
    }
  }
}
```

Signed `clients` entries identify CIMD clients and define explicit
conversation-ID selectors. For DCR clients, only a name confirmed by the
operator at OAuth authorization is trusted for display. The server persists
`operator_name` in the existing `oauth_dcr_clients.metadata` JSON and caches
all approved DCR names in memory. Unapproved DCR identities display Unknown;
signed client-label mappings are **not** a fallback for DCR names. The same
display name may group multiple exact IDs in History, but OAuth tokens, audit
actors, host/root grants and revocation remain isolated per verified ID.
Missing conversation selectors mean agent-wide grants. Conflicting configured
sources fail closed, and unconfigured headers/metadata are ignored: **no global
X-SSH-MCP-Conversation fallback**. The signed `clients` map is not an OAuth
allowlist. The global `oauth.dcr_enabled` bool defaults to true.

### Audit actor isolation and database upgrades

The current release associates each audit record with the verified OAuth
`client_id`. Its authorization `actor` is
`ssh-mcp-operator@SHA256(client_id)`, regardless of the client's display name.
CIMD labels come from the signed `clients` registry; DCR labels come from
operator-approved registration names. Neither provides authorization.

All SKY-344 historical audit-actor corrections on the managed test and
production installations have been completed and independently verified.
The old one-time migrator is no longer distributed or invoked at startup.

For a new installation, initialize a fresh SQLite volume with the current
application. If retaining a database from before client-scoped actors, do
not use it with the new runtime unchanged: stop all writers, verify the exact
historical actors and client IDs, take a consistent SQLite backup, and
coordinate a separately reviewed offline data conversion and image/config
transition. There is no supported automatic legacy-actor reassignment.
Downgrading the runtime likewise requires restoring a matching database
snapshot and signed configuration together, not merely changing the image.

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

`restricted` hosts require an authenticated OAuth session and an
operator decision before execution. Timed grants require a validated
conversation identifier; otherwise only the exact request may be
approved. `always-granted` bypasses
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
in the environment-variable allowlist representation. The issuer and initial configuration contain **no project-specific
domain restriction**. Online dynamic CIMD validation accepts multiple
simultaneously authorized clients; the browser CSP follows the exact
verified redirect on each authorization request. The configured
single-client values remain for compatibility, not as an allowlist
(see [OAuth clients](oauth-clients.md)).
Do not use signed managed startup mode with public Compose examples.

Managed `service.json` optionally includes `"logging": {"level": "INFO"}`.
Supported levels are DEBUG, INFO, WARNING, ERROR and CRITICAL. Existing
signed files without this section retain INFO. The signed default takes
precedence over the inherited environment. See [runtime logging control](operations.md)
for an in-memory override.

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


## Host readiness

Explicitly authorize the service's fixed probes before enabling access to hosts.
In managed mode set the signed service.json readiness.authorized to true.
In standalone mode set SSH_READINESS_AUTHORIZED=true in the protected environment
file. Missing authorization leaves all configured aliases offline; there is no
fallback to unverified execution. The following settings are available in the
readiness object (standalone uses the corresponding uppercase
SSH_READINESS_ prefix):

| Key | Default |
| --- | --- |
| authorized | false |
| interval_seconds | 30 |
| timeout_seconds | 5 |
| max_concurrent | 5 |
| stale_seconds | 300 |
| stale_retry_seconds | 120 |

Fixed probes verify the pinned SSH identity, then run the fixed sudo wrapper
noninteractively with cached credentials ignored and no password provided.
The supported target sudo executable is /usr/bin/sudo. The fixed launcher
uses LC_ALL=C for deterministic diagnostics, including password rejection;
ordinary root command execution retains the existing sanitized environment.
Verify the installed absolute executable during host onboarding.
An explicit password requirement or policy denial confirms this safety check.
An otherwise unidentified, fully completed noninteractive exit 1 needs
corroboration: on an authorized sudo-capable host the service requests a
unique sudo password prompt, sends its configured password only after the
prompt is observed, and requires framed root execution and UID 0. No new
OS-specific refusal diagnostics are required. Unknown refusals without an
available credential, recognized authentication challenge or confirmed root
result stay inconclusive; SSH-only hosts retain the conservative explicit
refusal check. Passwordless root execution disables the host immediately. Review the
effective sudo policy at onboarding and after policy changes: one fixed probe
cannot establish that every command-specific NOPASSWD rule is absent.
Configured privileged hosts also verify their protected password using the
fixed root identity probe. Rejected supplied passwords suspend further
password attempts until restart or explicit local operator recheck.

An active alias remains active until its last successful SSH safety check
expires, even after transient probe failures. Sudo readiness expires
independently. New approval prompts require a live check; previously admitted
operations use cached readiness, rechecked before dispatch and each batch step
or file call. No monitoring probe creates an approval grant.
The Console connection indicator reports aggregate configured host health.

Run ssh-mcp-ctl recheck-host ALIAS inside the service to retry immediately.
A suspended password gets one explicitly authorized verification attempt;
suspension clears only after success. The returned recheck_ok boolean and
CLI exit status report the live verification result, not cached eligibility
(which still follows the stale threshold). In standalone deployments the local control
socket can be enabled using SSH_CONTROL_SOCKET pointing to the default
/run/ssh-mcp/control.sock in a writable service-owned mode-0700 directory.
Only authorized fixed probes can run; no arbitrary command or grant is exposed.
