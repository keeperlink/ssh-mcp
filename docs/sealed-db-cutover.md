# Sealed-v2 SQLite state and recovery

Sealed v2 is the supported credential and Console session format. Fresh
databases initialize directly in v2, with a random session generation
instead of a legacy password verifier. **Do not repeat the one-time v1
cutover on an existing v2 service.**

## Current deployment and safe rollback

- Preserve the current SQLite audit/OAuth volume and its configured path.
  An image update must not silently create an empty replacement volume.
- Verify the generation-only Console state schema (history_auth_state has
  id and generation), the SQLite integrity result, and audit continuity.
  WAL and SHM are normal live SQLite sidecars and must not be deleted
  from an active database.
- Before recovery, verify an independently protected consistent backup,
  an approved signed **v2-compatible** image, and a matching *current*
  sealed credential revision and signed host inventory.
- After rotation, **never** restore legacy-v1-only images, plaintext
  credential revisions or retired host sudo passwords. Recovery must
  match the current host passwords and Console generation.
- Offline restore requires separately authorized service isolation,
  stopped database writers, reviewed history-db commands, and
  reconciliation of any uncertain journal/transaction outcome.
- Verify image, sealed credential fingerprint, Console generation,
  audit history, OAuth/Console login, root proof and metrics scrape
  after the recovery.

## Historical legacy-v1 migration (not a current-state operation)

An unmigrated legacy-v1 database cannot start v2 authentication without
a separately authorized offline conversion. The application rejects
legacy Console verifier state. A historical migration requires a protected
consistent snapshot, stopped writers, matching verified v2 Console generation,
reviewed history-db cutover, session revocation, WAL checkpoint, VACUUM
and integrity verification. Reconcile interruption before retrying.

Historical pre-rotation rollback recipes are **not** valid for a live
rotated sealed-v2 installation. Inventory and retire legacy snapshots
under approved retention; they may hold old password material and are
not valid post-rotation recovery authority.
