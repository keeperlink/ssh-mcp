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

MCP clients that lack HTTPS CIMD support may require a separately supported
registration mechanism; Dynamic Client Registration is not enabled.

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

## Workflow-scoped grants

When a host or permitted root operation is `restricted`, the MCP
request must carry an opaque, validated workflow identifier in the
dedicated configured header (`X-OpenAI-Session` by default).
The identifier is **correlation**, not authentication. A grant is
scoped to the authenticated OAuth session, exact conversation ID,
host and permission type. Without a header, a restricted request
fails closed: no implicit shared conversation is created.

Not every MCP client supports the existing header or ChatGPT-native
binary attachment parameter. Provider-neutral restricted approvals and
generic binary upload remain separate enhancements. Unknown clients
that cannot send the configured workflow header cannot reach restricted
SSH hosts even after successful OAuth authorization.

## Reverse proxy

Allow `/mcp`, `/oauth/*`, OAuth `/.well-known/oauth-*` and
`/console` with its subpaths. Preserve incoming HTTPS scheme and
Host, and forward the client-supplied conversation header unchanged.
Never substitute `X-Forwarded-For` or a request ID for a conversation.
Do not expose `/metrics`, `/ready` or `/health` publicly.
An existing proxy must implement this allowlist itself. The
[optional Caddy example](../examples/standalone/Caddyfile)
demonstrates equivalent routing.
