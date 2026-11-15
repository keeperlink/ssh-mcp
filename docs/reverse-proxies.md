# HTTPS and reverse proxies

SSH-MCP **requires a trusted public HTTPS endpoint** for OAuth and
browser sessions. The Python server itself listens on HTTP port 8000.
TLS termination can be performed by **your existing HAProxy, Nginx,
Traefik or equivalent**. Caddy is offered only as a convenience when
you do not already have a reverse proxy; it is not an application
dependency.

## Existing HTTPS infrastructure (recommended when available)

Start the [basic Compose application](getting-started.md) or the
[hardened application](hardening.md). These **do not create a
public HTTPS service**. They publish HTTP only to
`127.0.0.1:MCP_LOCAL_PORT` on the Linux Docker host, for use
by a reverse proxy on that **same host**. This isolation
**requires Docker Engine 28.0.0 or newer**. On older versions,
other hosts in the same Layer 2 network can reach
localhost-published ports and bypass proxy TLS and path checks.
Verify the Docker **server** version before starting either
app-only example; [Docker documents this behavior](https://docs.docker.com/engine/network/port-publishing/).
Do not regard a functioning localhost curl as proof of network isolation.

The existing proxy must:
- Serve a valid TLS certificate for the public hostname used in
  `MCP_ISSUER=https://YOUR_DOMAIN`, forwarding the original HTTP
  `Host` and reporting `X-Forwarded-Proto: https`.
- Route only `/`, `/mcp`, `/mcp/*`, `/oauth/*`,
  `/.well-known/oauth-*`, `/console` and `/console/*`.
  Other paths such as `/ready`, `/health` and `/metrics`
  must not be exposed on the public listener.
- **Remove incoming client-supplied `X-Forwarded-For`** and
  replace it with the actual peer address from the trusted
  connection; do not trust or forward an arbitrary header chain.
- Preserve the client's configured conversation header and OAuth
  request headers unchanged. Do not invent conversation IDs.
- Proxy HTTP requests, redirects and authenticated long-lived
  responses without disabling its normal TLS, CSRF or Origin checks.
- Enforce a **16,384-byte maximum request body** on POST
  `/oauth/authorize`, `/oauth/token` and `/console/*` before forwarding
  to the application. The Console further limits its own form bodies to
  8,192 bytes; the OAuth endpoints limit them to 16,384 bytes.
  **Do not apply this small form limit to `/mcp`**, where authenticated
  binary transfers can legitimately require larger request bodies.

The basic/hardened Docker network assigns a fixed bridge
`MCP_DOCKER_GATEWAY` (example `172.30.245.1`). The container's
`FORWARDED_ALLOW_IPS` trusts **that exact gateway** as the
source of forwarded headers, not arbitrary Docker peers. This
assumes a rootful Linux Docker host with the HTTPS proxy reaching
the loopback-published port through Docker NAT. Confirm the actual
upstream peer and per-client login throttling in your deployment:
rootless/user-namespace and non-Docker proxy variants may differ.
Do **not** set `FORWARDED_ALLOW_IPS=*` or publicly expose
`0.0.0.0:8000` as a workaround.

A minimal illustration for an **already-existing** HAProxy HTTPS
frontend is below. Integrate it into your own frontend rules rather
than copying it as a complete HAProxy configuration:

~~~haproxy
# In the existing HTTPS frontend after its TLS bind:
acl ssh_mcp_host hdr(host) -i mcp.example.com
acl ssh_mcp_path path -i / /mcp /console
acl ssh_mcp_prefix path_beg /mcp/ /oauth/ /console/ /.well-known/oauth-
http-request deny deny_status 404 if ssh_mcp_host !ssh_mcp_path !ssh_mcp_prefix
http-request del-header X-Forwarded-For if ssh_mcp_host
http-request set-header X-Forwarded-For %[src] if ssh_mcp_host
http-request set-header X-Forwarded-Proto https if ssh_mcp_host
use_backend ssh_mcp_local if ssh_mcp_host

backend ssh_mcp_local
    server local_mcp 127.0.0.1:8000
~~~

The host ACL must **also route only the allowed paths** to the
backend; other traffic for that hostname should be denied or
handled according to your existing proxy policy. Real proxies
may have multiple external network hops; set the client IP at
the trusted edge instead of accepting arbitrary incoming XFF.
This snippet is illustrative: review with your existing routing
and authentication policies before use.

If your HTTPS proxy is on **another host**, the loopback binding
cannot be reached remotely. Use an explicitly protected private
connection/overlay and a separately reviewed binding/firewall
policy, not an unprotected published HTTP port. A public hostname
alone never makes an HTTP backend safe.

## Optional HTTPS with Caddy

[Standalone Caddy Compose](../examples/standalone/compose.yaml)
is for users without an existing HTTPS proxy. It starts two
containers: SSH-MCP (private Docker network only) and
[Caddy](https://caddyserver.com/) (public ports 80/443).
Caddy is an open-source reverse proxy that automatically
obtains and renews HTTPS certificates. **Nothing in SSH-MCP
requires Caddy**; HAProxy/Nginx/Traefik can provide the same
public-facing functions.

If using this **instead of** basic/hardened:

1. Follow [Getting started](getting-started.md), particularly its
   private-configuration and SSH identity/host-key preparation
   sections, before starting the standalone example. Use the synthetic
   `examples/standalone/service.env.example` and
   `inventory.json.example` files.
2. Copy `examples/standalone/site.env.example` to
   `examples/standalone/.env`. Set `MCP_PUBLIC_HOST` to
   the real public DNS hostname and absolute private file paths.
   Choose an unused `MCP_PROXY_SUBNET`, a smaller
   `MCP_PROXY_DYNAMIC_RANGE` **excluding** `MCP_CADDY_IP`,
   and a Caddy IP within the overall subnet. Defaults:
   `172.30.244.0/28`, `172.30.244.8/29`, `172.30.244.2`.
3. In `service.env` set `MCP_ISSUER` and allowed hosts to that
   public HTTPS origin; replace invalid placeholder secrets.
   Open only TCP 80/443 for certificate issuance and HTTPS.
4. From the repository root:

   ~~~sh
   docker compose --env-file examples/standalone/.env -f examples/standalone/compose.yaml config --quiet
   docker compose --env-file examples/standalone/.env -f examples/standalone/compose.yaml build
   docker compose --env-file examples/standalone/.env -f examples/standalone/compose.yaml up -d --no-build
   ~~~

Caddy's example routes MCP, OAuth and Console paths; it blocks
public readiness/health/metrics routes. It scrubs untrusted
`X-Forwarded-For` and Uvicorn trusts only Caddy's fixed bridge IP.
The shipped Caddyfile enforces the form-only POST limit at the HTTPS
edge; this check is distinct from authenticated `/mcp` payload limits.
The Caddy certificate and app audit volumes are persistent and
must be backed up as appropriate. Confirm a trusted certificate,
`https://YOUR_DOMAIN/.well-known/oauth-authorization-server`
and `https://YOUR_DOMAIN/console`, plus expected 404 responses
for public `/ready`, `/health` and `/metrics`. Verify backend
readiness **inside** the MCP container.

This is a separate Compose project: do not launch it alongside
basic/hardened on the same public name or reuse another running
instance's database. The optional Caddy container does not
modify an established HAProxy deployment.

## Acceptance and safety

In each installation test real HTTPS issuer/discovery, OAuth,
browser login, per-client throttling, denial paths, pinned host
keys and durable audit in an isolated nonproduction environment.
Offline `docker compose config` validates configuration syntax,
not working certificates or real proxy/SSH behavior.
