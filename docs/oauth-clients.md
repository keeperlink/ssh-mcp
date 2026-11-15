# OAuth clients and tokens

The MCP Streamable HTTP endpoint is `/mcp`. The server publishes
metadata at `/.well-known/oauth-authorization-server` and
`/.well-known/oauth-protected-resource`, with authorization and
token exchange under `/oauth/authorize` and `/oauth/token`.

**One client ID per deployment:** the server checks an operator
configured HTTPS client metadata document and exact callback allowlist.
The standalone example targets **ChatGPT**, the currently supported
browser authorization flow. Although client metadata and callback
allowlists are configurable, `app/oauth.py` currently restricts
the authorization page's CSP `form-action` to `'self'` and
`https://chatgpt.com`. Browsers may enforce this on the POST
redirect, preventing callbacks to other origins. **Do not assume
a non-ChatGPT client will authenticate by changing metadata
and redirect settings alone.** That needs an independently
reviewed allowlisted CSP change and browser acceptance tests,
not disabling CSP or adding a wildcard. Simultaneous authorization
for two different client IDs is not implemented.

## Connection procedure

1. Put the server behind authenticated HTTPS, set `MCP_ISSUER` to
   the exact proxy origin, and connect to issuer + `/mcp`.
2. For the supported example, keep the **ChatGPT metadata,
   redirect URI and allowed origin**. Keep remote metadata
   validation enabled. Other clients need separately verified
   browser callback/CSP support.
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
binary attachment parameter. Multiple OAuth clients, provider-neutral
restricted approvals and generic binary upload have separate
future enhancement tracks; renaming the server metadata alone does
not provide those capabilities.

## Reverse proxy

Allow `/mcp`, `/oauth/*`, OAuth `/.well-known/oauth-*` and
`/console` with its subpaths. Preserve incoming HTTPS scheme and
Host, and forward the client-supplied conversation header unchanged.
Never substitute `X-Forwarded-For` or a request ID for a conversation.
Do not expose `/metrics`, `/ready` or `/health` publicly.
An existing proxy must implement this allowlist itself. The
[optional Caddy example](../examples/standalone/Caddyfile)
demonstrates equivalent routing.
