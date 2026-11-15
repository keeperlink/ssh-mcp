# Operator utilities

The service image includes a guarded SQLite utility installed as
`/usr/local/bin/ssh-mcp-history-db`. It backs up the live audit
database through SQLite's online backup API, verifies snapshots and
supports carefully controlled **stopped-service** restore. The backing
Python source is `ops/history_db.py`.

For safe private-state handling, database ownership, backups, restore,
retention, health probes and upgrade/rollback behavior, follow
[Operations](../docs/operations.md). Never copy a live SQLite file
without its WAL, delete WAL/SHM while the server is running, or restore
over an active service. Audit data may contain sensitive command
arguments and output.

Use [Getting started](../docs/getting-started.md) and the
[basic app-only example](../examples/basic/compose.yaml), or choose
[optional Caddy](../docs/reverse-proxies.md) and
[hardened Compose](../docs/hardening.md) for new self-hosted instances. Managed existing deployments retain their
independently controlled configuration and release process.
