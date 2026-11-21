# Upgrade compatibility and state migration

Changing application version, names or state paths may require a coordinated
migration. **Do not replace a running image without first checking its
persistent data and authorization policy.** Review and back up the existing
installation before switching images or signed configuration.

## Changed identifiers

| Area | New identifier or location | Required migration |
| --- | --- | --- |
| Python distribution | `ssh-mcp` | Use a fresh Python environment; do not overlay old and new distributions that install the same module files |
| Container version | `/usr/local/share/ssh-mcp/version` | Align the build producer and any release metadata readers |
| Signed configuration | `/etc/ssh-mcp/{service.json,inventory.json,known_hosts}` | Update signed manifests and read-only mounts together |
| Private secrets | `/run/secrets/ssh-mcp-secrets` | Update the privately supplied secretFile mount without copying credentials |
| Runtime SSH identity | `/run/ssh-mcp/` | Update inventory identity paths and writable tmpfs mount |
| Persistent audit database | `/var/lib/ssh-mcp/jobs.sqlite` | Preserve the original SQLite volume and update its configured database path, not just the volume mount |
| Database backup utility | `/usr/local/bin/ssh-mcp-history-db` | Update operator scripts and offline restore procedures |
| Remote file helper | `~/.ssh-mcp-helper/helpers/` | New versioned remote helpers are installed on demand; handle previous helpers only under separate remote cleanup approval |
| Prometheus metrics | `ssh_mcp_*` | Update Prometheus rules, dashboards and alerts before switching scrape targets |
| File result identifiers | `ssh-mcp-file://` and `ssh-mcp-probe://` | Update consumers that parse resource URI schemes |
| Isolated test runner | `ssh-mcp-test`, `~/tools/ssh-mcp-lab/` | Keep pinned versions available until each disposable run is cleaned up |
| Compose projects | `ssh-mcp-basic` / `ssh-mcp-standalone` | Preserve explicitly named volumes; changing a Compose project name can create an empty new state volume |

## Direct Python wheel installations

The distribution name changed, but both the previous and current wheels install
the same Python `app` package and `oauth-sessions` script. **Create a fresh,
separate virtual environment or new image** for the new `ssh-mcp` wheel. Do
not install it on top of the previous distribution in an existing environment,
and do not uninstall the old distribution after the new install: overlapping
installed-file records can remove modules or entry points belonging to the
new installation. Keep the previous environment intact for rollback and switch
the invoking service explicitly after isolated verification.

## Database setting and volume migration

Moving a persistent volume to `/var/lib/ssh-mcp` is not sufficient when the
old private configuration still selects its previous database path. Update
**`SSH_JOBS_DB=/var/lib/ssh-mcp/jobs.sqlite`** in the operator-maintained
private service environment file for *environment-file/Compose* installations,
and update **`jobs.database`** to `/var/lib/ssh-mcp/jobs.sqlite` in the
reviewed **signed `service.json`** for managed installations. Update the
corresponding volume target and configuration together, without creating an
empty replacement volume or overwriting its contents.

Before startup, in an isolated stopped-service view of the retained volume,
verify the existing `jobs.sqlite` is present and readable, and that it
contains the expected audit records and OAuth session state. After starting
the candidate, verify it opens **that same retained database**, not a newly
created empty file at either path. Preserve the matching mount layout and
database configuration for rollback.

## Required preflight and acceptance

1. Inventory the deployed image digest, Git SHA, container mount points,
   Compose project, persistent volume name, signed policy and client settings.
2. Stop any candidate rollout until an online SQLite backup has been
   created, verified, and stored securely off-host. Do not copy only an
   active SQLite database file without its WAL.
3. Preserve the **existing volume data and OAuth audit records**. Do not
   delete volumes or silently create an empty replacement with a new project
   name. When remapping the volume mount target, verify its actual SQLite
   contents from an isolated, stopped-service view.
4. Update the signed service settings, mounted file paths, SSH inventory
   principals, secrets mount, image version readers, client configuration
   and monitoring consumers as one reviewed deployment change.
5. Plan for OAuth reauthorization after the operator identity cutover.
   Existing legacy-subject tokens are rejected and refresh families revoked.
   The audit history remains associated with its original recorded actor.
6. Test the exact candidate in an isolated nonproduction environment with
   denied/allowed SSH operations, OAuth login and refresh, uploads/downloads,
   privileged-operation policy, persisted history, and dashboard metrics.
7. Capture an explicit rollback plan for both the previous image and its
   original mount/layout configuration. Never erase history to make a
   rolled-back image start.

**Source compatibility does not authorize production changes.** Signing,
host filesystem changes, service replacement, credential rotation and
volume migration require separate approval and recovery evidence.

## Console client labels and audit attribution

The client-attribution upgrade adds nullable `client_id` columns to jobs,
batch manifests and file operation audit rows. Keep the same persistent
SQLite volume; the migration does not rewrite or discard old records.
Legacy rows retain their old actors and are resolved conservatively at read
time. An older runtime can ignore the additive columns; restoring the newer
runtime recreates the current history projection. If rolling back to a
runtime that predates `viewer.client_labels`, restore the previously signed
service configuration together with the previously signed image.

## SKY-344 signed client registry and mandatory one-time audit conversion

The updated runtime requires a top-level signed `clients` object.
Old `viewer.client_labels` and global conversation-header configurations
are no longer supported. Before the image upgrade on any retained audit DB,
run the reviewed `app.audit_migration` dry run, stop the original service,
capture an independent SQLite backup, and apply the migration once manually.
Restore the prior SQLite snapshot **with** the prior signed image/config on
rollback; never mix the new actor format with the previous runtime. Verify
ChatGPT, Antigravity, Claude and Grok on test before production release.
