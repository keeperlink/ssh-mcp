# Operations, persistence and recovery

All three [Compose examples](getting-started.md) use the same
private application SQLite state directory
`/var/lib/ssh-mcp/jobs.sqlite`. The
`mcp-state` named volume must survive container replacement.
The [basic](../examples/basic/compose.yaml) and
[hardened](../examples/hardened/compose.yaml) variants expect
your established same-host HTTPS proxy; the
[optional Caddy](../examples/standalone/compose.yaml) variant
also stores public TLS certificates in the separate
`caddy-data` volume. Keep that volume across upgrades.

## Runtime logging control

Managed installations provide a private Unix socket at
`/run/ssh-mcp/control.sock` (mode 0600 inside the existing mode-0700 tmpfs).
The service UID can use the installed CLI without restarting:

```bash
docker exec ssh-mcp ssh-mcp-ctl get logging-level
docker exec ssh-mcp ssh-mcp-ctl set logging-level DEBUG
docker exec ssh-mcp ssh-mcp-ctl reset logging-level
```

Substitute your actual container name. Overrides take effect immediately,
remain in memory only and reset at container restart. The signed
configuration is not modified. The utility is available in managed mode;
standalone environment-file deployments set `MCP_LOG_LEVEL` at startup
(their SSH configuration directory is mounted read-only).

DEBUG captures MCP HTTP headers, correlation IDs and bounded JSON-RPC
metadata with actual values. Authorization, cookies, session credentials,
tokens, API keys, passwords and other credential-like field names are
redacted recursively. Tool argument values, OAuth forms, query strings,
responses and raw bodies are not logged. The application level does not
enable third-party wire logging. DEBUG output can contain personal data
and custom metadata; name-based redaction cannot detect every arbitrary
credential value. Protect the logs and reset the level when finished.

## Health and logs

- `GET /health`: basic application liveness.
- `GET /ready`: checks OAuth/audit database accessibility.
- `GET /metrics`: optional private bearer-authenticated
  Prometheus output when `MCP_METRICS_ENABLED=true` and a
  distinct `MCP_METRICS_TOKEN` is configured.
- `get_status`: authenticated MCP service/release and job
  activity; `get_job_stats`: scoped aggregate history data.
- The Operator Console at `/console` shows retained
  commands, file operations, results, failures, grants
  and approval state.

Your existing HTTPS proxy (or the optional Caddy example) **must
not expose** health or metrics publicly. Run readiness inside the container
as shown in
[Getting started](getting-started.md). Use `docker compose ps`
and scoped `docker compose logs` for container diagnostics,
but keep credentials, command bodies and audit output out of
support tickets and pasted logs. Start with one Uvicorn worker;
a second process cannot share pending grants.

## Backup the audit database

The image ships `ssh-mcp-history-db`, a guarded CLI
using SQLite's **online backup API** to include committed
WAL content. It checks directory ownership/modes, rejects
symlinks and existing backup destinations, and verifies
integrity. Create a mode-0700 `backups` directory in the
persistent state volume and run the image's CLI:

~~~sh
docker compose --env-file examples/basic/.env   -f examples/basic/compose.yaml exec -T mcp   mkdir -p -m 0700 /var/lib/ssh-mcp/backups
docker compose --env-file examples/basic/.env   -f examples/basic/compose.yaml exec -T mcp   python /usr/local/bin/ssh-mcp-history-db   backup /var/lib/ssh-mcp/jobs.sqlite   /var/lib/ssh-mcp/backups/snapshot.sqlite
docker compose --env-file examples/basic/.env   -f examples/basic/compose.yaml exec -T mcp   python /usr/local/bin/ssh-mcp-history-db   verify /var/lib/ssh-mcp/backups/snapshot.sqlite
~~~

The commands above target **basic**. Replace the two example
paths consistently when operating the hardened or Caddy variant,
and protect backup outputs from unauthorized users.

The destination must be new. Use unique dated names for later
snapshots; do **not** overwrite or delete an existing backup in
place. Copy verified snapshots to encrypted off-host storage
under an explicit backup-retention policy. Database backups
contain sensitive command argv/output and OAuth session state.
Do not mistake online SQLite backup for a container image
snapshot or copy only the main `.sqlite` file while the WAL
is active.

## Restore (planned downtime)

Stop the application first; take a separate verified
pre-restore snapshot. A qualified operator should mount the
same private volume in an **isolated** image/container without
starting the MCP server and run the guarded restore CLI with
`--confirm-stopped` after verifying no active WAL/SHM writers.
The restore tool makes a pre-restore backup and refuses an
active WAL. Never delete WAL files or restore over a running
database. After restart verify `/ready`, Console login and
retained records before accepting new SSH mutations.

## Retention and size

`SSH_JOBS_RETENTION_MONTHS` controls calendar-month audit
retention in the example; the application prunes on writes
and through an hourly periodic task. It is not backup
retention. SQL output compression reduces eligible retained
payloads but does not guarantee the DB file immediately
shrinks. Keep enough persistent capacity for the WAL,
indices, history and backups; monitor disk space separately.

## Upgrade or rollback

The source-level identifier cleanup requires [a coordinated migration](upgrade-compatibility.md).
Do not replace an installed image until
its signed mount paths, persistent database volume and monitoring
consumers have been reconciled.

1. Preserve the current source commit, built image digest,
   active private configuration and verified database backup.
2. Review changes to OAuth, SSH inventory and persistent
   schema. Changing cookie names may require fresh Console
   login and reset local browser preferences.
3. Build the candidate independently and verify required
   tests/CI and a nonproduction runtime acceptance plan.
4. Explicitly recreate/replace only this approved Compose
   stack. Source merge by itself does not deploy anything.
5. Verify HTTPS discovery/authorization, host-key pinning,
   denied and accepted SSH operations, Console approval
   and database persistence/restart behavior.
6. For rollback, restore the matching image and documented
   configuration. Some additive DB/audit changes persist
   across image rollback; do not erase or downgrade the
   database blindly to force an old image to start.

Never run `docker compose down -v` unless the operator
explicitly chooses to remove the **audit and TLS volumes**.
The managed production service has separate signed manifest,
authorization and release procedures not replaced by this
standalone guide.

See [Troubleshooting](troubleshooting.md),
[Security](security.md) and [Configuration](configuration.md).
