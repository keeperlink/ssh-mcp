# Getting started: SSH-MCP with an existing HTTPS proxy

Begin with the [basic one-service Compose example](../examples/basic/compose.yaml).
It starts **only SSH-MCP**, not a new web server. Use it when you already
have HAProxy, Nginx, Traefik or another **HTTPS reverse proxy on the same
Linux host**. The app's port 8000 is bound exclusively to `127.0.0.1`;
a remote MCP client cannot reach it until the existing HTTPS proxy is
configured. For a host without a reverse proxy, use the
[optional Caddy example](reverse-proxies.md#optional-https-with-caddy).
For additional app container protections, see [Hardening](hardening.md).

This guide covers the app prerequisites shared by **all three** examples.
Each Compose file is a separate choice; do not start two examples using
the same local port or database simultaneously.

## 1. Prepare your hostname, credentials and private files

Use Linux with **Docker Engine 28.0.0 or newer** and the Compose v2
plugin for the **Basic or Hardened** examples. Verify the **server**
version (not only the Docker CLI or Compose version) before proceeding:

~~~sh
docker version --format '{{.Server.Version}}'
~~~

**Do not start Basic or Hardened on an older Docker Engine.**
Before 28.0.0, other machines on the same Layer 2 network can reach
ports published to `127.0.0.1`, potentially bypassing the HTTPS
reverse proxy and its route restrictions. Upgrade Docker first;
a custom firewall isolation policy would require its own security
review. See [Docker's port-publishing warning](https://docs.docker.com/engine/network/port-publishing/).
The [optional Caddy example](reverse-proxies.md#optional-https-with-caddy)
does not publish the app's HTTP port to the host and therefore
does not depend on loopback publishing for that boundary.

Choose your public HTTPS hostname, such as `mcp.example.com`.
Your existing reverse proxy must terminate TLS with a trusted certificate
and forward approved
MCP/OAuth/Console endpoints to the application over the **host loopback**.
If the proxy runs on another machine, do not bind the application to
`0.0.0.0` as a shortcut: design a separately authenticated private
transport instead. See [HTTPS and reverse proxies](reverse-proxies.md).

From the repository root copy `examples/basic/site.env.example` to
`examples/basic/.env`. Choose an **unused Docker bridge subnet**
`MCP_BRIDGE_SUBNET` and its gateway `MCP_DOCKER_GATEWAY`.
The defaults (`172.30.245.0/28` and `172.30.245.1`) are examples,
not globally reserved addresses. The host proxy's connection to the
published loopback port reaches Uvicorn via that gateway. Uvicorn
trusts forwarded client-IP headers **only from this exact gateway**;
the host proxy must overwrite, not pass through, untrusted incoming
`X-Forwarded-For` headers.

Create a private directory **outside Git** with `ssh` and
`service.env`, using the samples
`examples/basic/service.env.example` and
`examples/basic/inventory.json.example`. Set the **absolute** paths
to the service env file and SSH directory in `MCP_PRIVATE_ENV` and
`MCP_SSH_CONFIG_DIR`. Set service env mode `0600` and SSH directory
mode `0700`. Edit service env:
`MCP_ISSUER=https://YOUR_DOMAIN` (without path/trailing slash)
and `MCP_ALLOWED_HOSTS` with the matching hostname. The public HTTPS
hostname must match the proxy's certificate and OAuth issuer.

Replace all `REPLACE_ME` placeholders with **three independent secrets**:
`MCP_LOGIN_KEY` and `MCP_TOKEN_SIGNING_SECRET` (32+ characters each),
`HISTORY_VIEWER_PASSWORD` (16+ characters). Use a private editor,
not shell command arguments or Git. These invalid placeholders prevent
a ready-to-copy example from silently starting with public credentials.
Docker administrators can inspect environment variables; use a
separately reviewed secret-management integration when that boundary
is unsuitable.

## 2. Configure a dedicated SSH identity and verified target

Prepare a dedicated **non-root, no-sudo** SSH service account on a
target you control. Generate a new Ed25519 identity with
`ssh-keygen -t ed25519 -a 64`, saving it as `identity` in the
private SSH directory; permit that public key only for the dedicated
remote account. Unattended passphrase-less keys require careful
filesystem protection. Disable unnecessary agent and port forwarding.

Copy `examples/basic/inventory.json.example` to the private SSH
directory as `inventory.json` and replace the synthetic address,
port and remote username. Keep its sample alias `demo` aligned
with `SSH_APPROVED_ALIASES`, its authorization principal
`ssh-mcp-operator` (the fixed OAuth/inventory principal, **not** the SSH user),
`access: "restricted"` and `privileged_access: "none"`.

Verify the target SSH public-key fingerprint **out of band** with a
trusted source before writing `known_hosts`. Never rely only on
`ssh-keyscan` output or disable strict checking. The known_hosts
entry must match the inventory hostname and SSH port; use
`[host]:port` notation for a custom port.

Both images execute as UID/GID `10001:10001`. With Linux rootful
Docker, arrange container-visible ownership of **only the new
private SSH directory and its three files** to UID/GID 10001.
Use 0700 for that directory, 0600 for `identity`, and
0644 or tighter readable modes for inventory and known_hosts.
The executor refuses invalid ownership/modes. Do not recursively
change ownership of shared paths. With rootless Docker/user
namespaces, account for the daemon's UID mapping without weakening
SSH checks. The state volume is initialized from the UID-10001
image directory.

After verifying the dedicated account, host-key pin and sudo policy, explicitly
authorize the service's fixed readiness probes: set
\`SSH_READINESS_AUTHORIZED=true\` in your private \`service.env\`.
The supplied example deliberately defaults to disabled. See
[Host readiness](configuration.md#host-readiness) for the required policy and
probe settings. Wait for the configured alias to become active in the Console
or \`list_servers\` before your first SSH command.

## 3. Validate and start the single-service example

From the repository root, after preparing your private configuration in
steps 1–2, **use the published Linux AMD64 image** without building from
source:

~~~sh
docker pull keeperlink/ssh-mcp:0.1.1
docker image tag keeperlink/ssh-mcp:0.1.1 ssh-mcp:basic
docker compose --env-file examples/basic/.env -f examples/basic/compose.yaml config --quiet
docker compose --env-file examples/basic/.env -f examples/basic/compose.yaml up -d --no-build --pull never
~~~

The basic Compose example names its local image `ssh-mcp:basic`. The
`docker image tag` command assigns that **local alias** to the already
pulled Docker Hub image; it does not rebuild or republish anything.
`--no-build --pull never` ensures the service uses the locally pulled,
versioned image, even though the example Compose file also includes
a `build:` definition. If the published image is not present locally,
the command fails instead of silently building another image. For
reproducible production deployments, record and pin the resolved digest.

**Alternatively**, to build the image from your reviewed checkout
instead of using the published release:

~~~sh
docker compose --env-file examples/basic/.env -f examples/basic/compose.yaml config --quiet
docker compose --env-file examples/basic/.env -f examples/basic/compose.yaml build
docker compose --env-file examples/basic/.env -f examples/basic/compose.yaml up -d --no-build
~~~

The `config` command checks Compose syntax and interpolation, **not**
real SSH host keys, credentials, DNS, certificates or proxy routing.
The basic Compose file exposes `127.0.0.1:8000` **only on the host**
(or a different loopback port if configured). It is HTTP behind a
future/existing HTTPS proxy, **not a secure public MCP endpoint**. Never forward this loopback port to the internet.

Check readiness locally on the Docker host (or from inside the container):

~~~sh
docker compose --env-file examples/basic/.env -f examples/basic/compose.yaml exec -T mcp python -c "from urllib.request import urlopen; print(urlopen('http://127.0.0.1:8000/ready',timeout=3).status)"
~~~

Expect `200`. Next configure the [existing reverse proxy](reverse-proxies.md)
and verify that public HTTPS discovery, OAuth and Console endpoints work
and that health/metrics are not exposed publicly.

## 4. Authorize an MCP client and test a harmless command

The example preconfigures ChatGPT for compatibility, but other HTTPS
CIMD-compatible clients can connect to the same `https://YOUR_DOMAIN/mcp`
without pre-registration. Request scopes `mcp.access` and
`ssh.execute` as appropriate. Verify the client metadata URL and
callback on the consent screen before authorizing. The OAuth page accepts
`MCP_LOGIN_KEY`; the Operator Console at
`https://YOUR_DOMAIN/console` uses the independent
`HISTORY_VIEWER_PASSWORD`.

The sample SSH host requires operator approval in an authenticated
OAuth session. A validated conversation ID enables conversation-scoped timed
approvals; verified clients without a conversation identifier can also receive
timed grants scoped to their operator and OAuth client identity across logins.
OAuth callback CSP origins are
derived from validated client metadata, not an unrestricted wildcard.
See [OAuth clients](oauth-clients.md).

Before connecting sensitive systems, verify a harmless command, denied
authorization, mismatched host-key rejection, audit persistence and
re-login in a **nonproduction** test environment.

## Next steps

Use [Caddy](reverse-proxies.md#optional-https-with-caddy) if there is
no existing HTTPS proxy, or select the
[separate hardened app example](hardening.md) for defense in depth.
The three examples are **alternatives**, not layers to combine.
Preserve the SQLite volume and record image provenance before upgrades;
never use `docker compose down -v` unless deletion of audit data is
intentional. See [Operations](operations.md).

None of these examples modifies the separate signed managed deployment.
GitHub publication, licensing and full history audit remain independent
release gates.
