# Hardened Compose example

The [basic example](../examples/basic/compose.yaml) is intentionally
small. For a stricter application-container boundary, use the
[separate hardened Compose example](../examples/hardened/compose.yaml)
**instead of** the basic file. It assumes an **existing same-host
HTTPS proxy**, just like basic. It is not a standalone public
HTTPS endpoint and does not include Caddy. **Docker Engine
28.0.0 or newer is required**: the loopback-published backend
may be reachable from the same Layer 2 network on older Engines.
Check the server version as described in
[Getting started](getting-started.md#1-prepare-your-hostname-credentials-and-private-files).

Both examples preserve mandatory protections: OAuth client
authorization, pinned SSH host keys, a dedicated least-privilege
remote account, separately protected runtime secrets and a
persistent private audit database. Hardening is **defense in
depth**, not an alternative to those controls.

## What the hardened variant adds

| Protection | Basic | Hardened |
| --- | --- | --- |
| Non-root UID 10001 | Yes | Yes |
| Host loopback HTTP binding only | Yes | Yes |
| Read-only mounted SSH inputs | Yes | Yes |
| Persistent SQLite data volume | Yes | Yes |
| Read-only container root filesystem | No | Yes |
| Drop Linux capabilities | No additional cap drop | All |
| Prevent privilege escalation | Default container settings | `no-new-privileges` |
| Bounded processes/memory | Engine defaults | PID 128; memory 512 MiB |
| Isolated temporary writable directory | Default image filesystem | 16 MiB tmpfs, noexec,nosuid |
| Graceful stop/init | Basic container settings | `init` and 45-second stop grace |

To use the hardened variant, copy
`examples/hardened/site.env.example` to
`examples/hardened/.env`. Use the **same private service env
and SSH directory format** as in
[Getting started](getting-started.md); do not copy real
credentials into Git.

~~~sh
docker compose --env-file examples/hardened/.env -f examples/hardened/compose.yaml config --quiet
docker compose --env-file examples/hardened/.env -f examples/hardened/compose.yaml build
docker compose --env-file examples/hardened/.env -f examples/hardened/compose.yaml up -d --no-build
~~~

The hardened configuration binds only
`127.0.0.1:MCP_LOCAL_PORT`. Configure your existing
[HTTPS reverse proxy](reverse-proxies.md) separately,
including trusted forwarding-header handling. Do not start
basic and hardened concurrently against the same local port
or shared state volume.

For environments without an HTTPS proxy, the
[optional Caddy example](reverse-proxies.md#optional-https-with-caddy)
already includes many container restrictions (non-root,
read-only root, dropped capabilities and private backend).
It is **another complete example**, not an overlay to add
on top of hardened.

## Further host controls

Assess rootless/user-namespace Docker, host firewall policy,
SSH egress isolation, filesystem quotas, read-only host paths,
secret rotation, off-host encrypted database backups and
authentic container image provenance according to your
environment. These are **operator decisions**, not safety
guarantees from a Compose example.

A read-only **container root filesystem** does not make the
remote SSH target read-only: a permitted MCP client can still
mutate that remote host with its assigned SSH account rights.
Always verify approval/denial, key pinning, logout, audit
persistence and restart recovery before production adoption.
