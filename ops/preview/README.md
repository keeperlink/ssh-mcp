# Live-source development fixture

The operator selects the host and service, and is responsible for approval
and source compatibility with the installed image and retained database.
Stop all active work first. The original and fixture share the database;
never run both simultaneously or run a deployment concurrently.
No backup, migration or automatic rollback is performed by this helper.

The proxy must independently follow the Docker service DNS alias (for
HAProxy, configure a Docker resolver at `127.0.0.11:53` and attach it to the
server). The fixture never communicates with or modifies the proxy.

From the reviewed checkout on the selected host (substitute the actual
container name):

```bash
preview=(python3 ops/preview/preview.py --container ssh-mcp)
"${preview[@]}" start
"${preview[@]}" status
docker exec ssh-mcp-dev python -m app.control_cli set logging-level DEBUG
docker logs --since 5m ssh-mcp-dev 2>&1 | grep SSH_MCP_REQUEST
# After a source edit:
"${preview[@]}" restart
# DEBUG is reset on restart; enable it again if needed.
"${preview[@]}" stop
```

The running original is the source of truth: the helper inspects its Docker
configuration, keeps the local image ID, actual volume identities, input
mounts, environment, command, health check, security settings, ports and
network configuration. It locates the installed app package without importing
it and binds the checkout's app/ directory directly over that package, read-only.
A temporary file containing the checkout's short HEAD commit is mounted over
`/usr/local/share/ssh-mcp/version` read-only, refreshed in place on restart and
removed on stop. The Console and MCP report this commit instead of the release
version (an explicit inherited MCP_SERVICE_VERSION override still takes precedence).
Uncommitted edits do not change the HEAD commit. Run restart from the same checkout.
No Compose file, environment changes or image rebuild are needed. The clone adds
the original name as a network alias on user-defined networks, uses a -dev
container name, replaces Compose ownership labels with a fixture identity label,
and disables automatic restart. Docker-generated IDs, hostname and assigned
network addresses are not reused. Explicit IPAM settings are retained.
Auto-removing containers and volumes-from configurations are not supported.
The source must be readable by the service UID and contain no credentials.
Restart the container to load changes.

The helper creates a stopped fixture before stopping the original, then
starts the fixture. If a switch fails, use `status` and inspect the
containers. `stop` removes the owned fixture and starts the intact original
if needed; a stopped fixture can also be removed while the original remains
running. If no fixture exists and the original is stopped, manually start it
with `docker start ssh-mcp` (substitute the actual name).
Never start the original while the fixture is running. A brief interruption
is expected during switching and DNS/health-check convergence.

`python -m app.control_cli` works even when the installed base wheel predates
the `ssh-mcp-ctl` console entry point.
