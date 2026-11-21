# OAuth clients and tokens

The MCP Streamable HTTP endpoint is `/mcp`. The server publishes
metadata at `/.well-known/oauth-authorization-server` and
`/.well-known/oauth-protected-resource`, with authorization and
token exchange under `/oauth/authorize` and `/oauth/token`.

**Unknown clients can connect without preregistration.** For each HTTPS URL-form
OAuth `client_id`, SSH-MCP retrieves the Client ID Metadata Document (CIMD)
over certificate-validated HTTPS, validates its exact client ID and redirect URI,
and displays the client name, document URL and callback before asking the
operator to authorize it with the private login key. The claimed client name
is **not** independently attested. Inspect the actual metadata and callback
origin before approving an unfamiliar client.

The server accepts several approved OAuth clients concurrently. Their codes,
refresh sessions and MCP audit views are client-bound. The Operator Console
remains the separately password-protected view of all host activity.
Signed SSH inventory, restricted-host approvals and sudo policy still apply:
OAuth consent alone does not authorize arbitrary SSH access.

The login page derives a narrow `form-action` CSP origin from the **verified
callback for that request**, not from untrusted parameters or a global
allowlist. Origins associated with valid authorized sessions survive restart.
The metadata fetch is bounded, pins publicly routable IPs and rejects HTTP,
redirects and private-network endpoints. The configured legacy client ID
and static redirect/origin values remain for offline fixtures and existing
ChatGPT audit compatibility; with remote validation enabled they **do not**
limit which new CIMD clients can request authorization.

MCP clients without HTTPS CIMD may use the optional default-enabled
RFC 7591 Dynamic Client Registration compatibility endpoint described below.

## Connection procedure

1. Put the server behind authenticated HTTPS, set `MCP_ISSUER` to
   the exact proxy origin, and connect to issuer + `/mcp`.
2. Keep remote CIMD metadata validation **enabled**. The example's
   ChatGPT settings remain backward-compatible, but other HTTPS CIMD
   clients no longer require adding a client ID or origin to configuration.
   Unknown clients must pass metadata and redirect checks and must be
   approved separately on the OAuth consent page.
3. Request `mcp.access` for `ping` and `ssh.execute` for SSH,
   job, batch and file tools. A tool cannot override inventory hosts.
4. Enter `MCP_LOGIN_KEY` on the OAuth screen. It is **not** the
   Console password or the remote SSH identity.
5. The client exchanges a PKCE authorization code for a bearer token
   using S256 and an RFC 7636-compliant 43–128 character verifier.
   The server rejects malformed challenges and verifiers rather than
   issuing tokens for weak one-character proofs. If supported, the
   client rotates refresh tokens within its authorized absolute session.

Access tokens expire within 15 minutes. Supported absolute session
periods include 1 hour, 8 hours, 1 day, 7 days and 30 days.
Refresh tokens are hashed in private SQLite and bound to their
originating client/session; revocation blocks renewal. Previously
issued access tokens can remain active until their own expiry.

## Conversation- and agent-scoped grants

Restricted host or root operations always require a verified OAuth session
and operator approval. When a client supplies a validated conversation
identifier from one of these sources, timed grants are conversation-scoped:

- The configured dedicated header (`X-OpenAI-Session` by default).
- Codex tool-call `params._meta["x-codex-turn-metadata"].thread_id`.
- Antigravity tool-call `params._meta["antigravity.google/conversation_id"]`
  (not the root conversation ID).
- The optional `X-SSH-MCP-Conversation` header, if a client supplies it.

The identifier is **correlation**, not authentication. Malformed or
conflicting supplied identifiers are rejected; no transport session ID,
connection, IP address or request ID substitutes for a conversation.
Timed grants are scoped to the authenticated OAuth session, exact
conversation ID, host and permission type. Give each workflow its own
identifier; a static custom header does not separate conversations.

If a client sends **no conversation identifier**, timed grants instead apply
to the authenticated **operator + OAuth client identity**, across that agent's
conversations and OAuth logins, for the selected host and duration. The Console
shows the agent without a conversation number (for example, `demo-node-a[Claude]`)
and explains the wider scope. Other agents never inherit that grant. When a
conversation ID is present, grants remain bound to the **specific OAuth
session + conversation**; the Console shows a local numeric label such as
`demo-node-b[ChatGPT-1]`. These labels are for display, not authorization.
Verified clients without a configured label display as
`demo-node-b[Unknown-<fingerprint>]`, using a short, stable display-only hash
of the OAuth client ID to distinguish their individual grant/revoke controls;
the original client ID is not shown in the chip.

Host and root grants remain independently approved, expiring and revocable.
When approving timed root access on a restricted host with an existing shorter
SSH host grant, that prerequisite host grant is extended to the root grant's
expiry. It remains active if the root grant alone is revoked; revoke the host
grant separately to end SSH access. The approval dialog discloses this.
Agent-wide root grants are as broad as agent-wide host grants, so review
duration accordingly. Without a verified OAuth client identity, timed grants
remain unavailable and an explicit one-request approval is required.
Transport sessions, IPs, request IDs and untrusted client headers are never
used as grant identities. Generic binary upload remains a separate enhancement.

## Reverse proxy

Allow `/mcp`, `/oauth/*`, OAuth `/.well-known/oauth-*` and
`/console` with its subpaths. Preserve incoming HTTPS scheme and
Host, and forward the client-supplied conversation header unchanged.
Never substitute `X-Forwarded-For` or a request ID for a conversation.
Do not expose `/metrics`, `/ready` or `/health` publicly.
An existing proxy must implement this allowlist itself. The
[optional Caddy example](../examples/standalone/Caddyfile)
demonstrates equivalent routing.

## Dynamic Client Registration (DCR) compatibility

OAuth 2.0 Dynamic Client Registration (RFC 7591) is an optional legacy-client
interoperability path, **enabled by default**. The recommended method for
modern clients remains HTTPS Client ID Metadata Documents (CIMD). Setting
`MCP_DCR_ENABLED=false` disables DCR's endpoint and discovery advertisement,
without disabling CIMD. Managed signed installations may set
`oauth.dcr_enabled: false` in the non-secret service settings; absent means true.

When enabled, authorization-server discovery advertises
`registration_endpoint: https://YOUR_ISSUER/oauth/register`. This endpoint
accepts bounded RFC 7591 `application/json` for public clients using
`authorization_code`, `refresh_token`, `response_types: ["code"]` and
`token_endpoint_auth_method: "none"`. It returns HTTP 201 with an opaque
persistent `dcr_...` client ID; it returns **no client secret, access token,
SSH privilege or approval**. Confidential-client authentication and RFC 7592
remote registration modification/deletion are not implemented.

Clients registering `grant_types: ["authorization_code"]` receive **no refresh
token**, and subsequent refresh attempts are refused. A registration that
includes `"refresh_token"` in its grant types can rotate refresh credentials
within the operator-approved session. Existing CIMD refresh behavior is unchanged.

Registration redirects require HTTPS except HTTP loopback callbacks for
`application_type: "native"` clients. The server checks the client ID,
registered callback, issuer, resource and PKCE S256 at authorization/code
exchange. A native client's loopback IP/host, path and query must match the
registration; only its local port may vary, including when the saved native
loopback callback omitted a port. Untrusted LAN HTTP callbacks,
userinfo, fragments, unspecified schemes and open redirects are rejected.

On the browser authorization page, review the **exact registered client ID**,
self-asserted name, callback and requested OAuth scopes before entering the
separate private login key. A DCR client cannot assert ownership of a software
brand merely by choosing a name. Its registered client ID is not a secret;
a fresh OAuth login still requires operator consent. Unapproved registration
alone never grants SSH access, operator or privileged permissions. Existing
conversation-scoped or agent-wide timed grants follow the same per-operator,
verified OAuth client identity rules as CIMD.

Registrations persist in the existing private SQLite OAuth database across
restarts. Every HTTP registration attempt (including invalid Content-Type, malformed
JSON and oversized bodies) is charged against per-source and global minute
limits; a registration cap prevents unbounded storage. Registrations inactive for 90
days are removed automatically only when no active OAuth session exists.
Successful authorization/token refresh updates last use. Existing sessions
retain their independent absolute expiry. The private backup of the existing
database now includes DCR registrations; do not discard this database during
upgrade or rollback.

### Operator-pinned dynamically registered identities

The DCR `client_name` is self-asserted. A verified exact `dcr_...` ID may be
added under the signed top-level `clients` mapping, for example:

```json
{
  "Grok": {
    "identities": ["dcr_QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"],
    "conversation_id": {"sources": []}
  }
}
```

This is a synthetic example, not a live registration. Client display labels
never authorize OAuth or SSH. Separate registered IDs remain isolated even
when grouped under one label. A newly registered ID must be independently
verified and pinned in a separately signed configuration release.
See [the unified client registry and migration](configuration.md).

### Administrative inspection and revocation

From a trusted host/container environment with the project package available
and the private SQLite file accessible, list registrations:

```sh
python -m app.dcr_admin --db /PATH/TO/jobs.sqlite list
```

To revoke a verified client ID and all its active OAuth sessions:

```sh
python -m app.dcr_admin --db /PATH/TO/jobs.sqlite revoke dcr_EXACT_ID --confirm-id dcr_EXACT_ID
```

Use the exact returned ID, not the self-reported display name. A successful
administrative removal is committed with a durable, sanitized audit record
containing only the opaque client ID and removal time. This record is retained
for at most 365 days and bounded to the most recent 4096 removals. No ordinary
client can invoke this administrative capability through HTTP. Revoking a DCR
registration prevents subsequent DCR bearer verification and refresh. Existing
CIMD registrations, OAuth tokens and consent remain unaffected. Before
production deployment, verify database backup, upgrade/rollback compatibility,
OAuth discovery, registration and existing CIMD clients in the test environment.
