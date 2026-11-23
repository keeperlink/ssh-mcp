# SKY-347: safe sealed-v2 database cutover and recovery

This procedure is for an **explicitly approved operator**. A passing
synthetic LAB test, source merge, Docker image build, or signed PLAN is not
authorization to rotate live credentials, sign or deploy any service.

## Preconditions

- The target must have a **reviewed signed sealed-v2-capable image** and a
  verified matching sealed-v2 credential revision, with independent OAuth,
  Console, metrics and host-sudo recovery access. Do not use an old v1-only
  signed image as a rollback for a *rotated* v2 credential bundle.
- Keep the original v1 credential revision and existing signed release for
  immediate **pre-rotation** rollback only. Once any old credential is
  rotated or revoked, a rollback must instead use a signed v2-compatible
  image and a matching current sealed revision.
- Review the intended deployment target and the actual running digest.
  Use the approved deployment orchestrator and the independent
  administrator recovery channel. Never copy real secret contents to Git,
  a CI job, logs, shell arguments or chat.
- Run the database maintenance utility from reviewed code as the owner of
  the private SQLite source. Its directory and backup destination directory
  must both exist, belong to the same user and have mode **0700**; database
  and snapshot must be private **0600** regular files. Never relax these
  controls or use unreviewed code to gain access.

## Authorized sequence for an existing v1 installation

1. Independently verify protected source and remote recovery, then stage
   and verify the full sealed-v2 revision with `ssh-mcp-secrets` in a
   trusted interactive operator terminal. Preserve its stage/manifest
   and bind its **Console generation** to the pending database cutover.
   Do not activate the sealed source while the legacy service is live.
2. Stop and isolate the **specific** service and every database writer
   through its approved controller. Confirm no active service processes
   or background writers. Do not pause unrelated lab services.
3. Run `python -m ops.history_db cutover SOURCE_DB SNAPSHOT_DB
   --generation VALIDATED_STAGE_GENERATION --confirm-stopped`.
   Here `SOURCE_DB` and `SNAPSHOT_DB` are **absolute paths** to
   protected private files. The cutover refuses legacy state that is
   missing or malformed, an existing snapshot, invalid generation,
   insufficient file ownership/permissions, or a missing stopped-service
   confirmation. It takes a **new, verified SQLite online backup before
   any mutation**. That backup includes legacy password-verifier material:
   keep it protected, never distribute it and retire it when the
   post-cutover rotation/retention policy allows.
4. Under a database-exclusive transaction, the tool removes the legacy
   PBKDF2 Console state, clears old Console sessions, writes a generation-only
   state row and revokes existing OAuth session rows. It then checkpoints
   and truncates WAL, runs `VACUUM` to remove residual legacy verifier
   bytes from the active file, checkpoints WAL again, and verifies database
   integrity. A missing or changed post-snapshot WAL is rejected under
   an exclusive database lock. If anything fails after COMMIT, the outcome
   may be **uncertain**: the CLI exits with status `2` and an explicit
   reconciliation warning (versus status `1` for a rejected operation).
   Inspect the active schema and recovery snapshot; **do not retry blindly**.
5. Verify the new schema is `(id,generation)` and the expected generation,
   the retained snapshot passes `python -m ops.history_db verify SNAPSHOT_DB`,
   and all other audit tables survive. Then, with the same stopped-service
   and independent-recovery checks, activate the prepared complete sealed
   revision. Preserve the encrypted source and its verified digest.
6. Deploy/recreate **only the approved service** with the reviewed signed
   v2-compatible image and unchanged authorized inventory/host keys.
   Check actual loaded revision, readiness, OAuth login/refresh revocation,
   Console login/cookie invalidation, metrics scrape, locked SSH status,
   root-grant approval and real sudo on approved targets. Do not assume
   an HTTP 200 response is sufficient acceptance.

## Failed deployment and rollback

If deployment fails **before host password/consumer rotation** and the
operator explicitly elects v1 rollback, stop every database writer and
verify that the v1 credential revision still matches the original signed
image. Run `python -m ops.history_db checkpoint SOURCE_DB
--confirm-stopped` to close SQLite WAL/SHM, then the existing guarded
`python -m ops.history_db restore SNAPSHOT_DB SOURCE_DB
--confirm-stopped`. This restore creates another private backup of the
current database, revokes restored OAuth sessions, clears restored Console
sessions, and never overwrites a backup silently. Verify the restored v1
authentication schema and redeploy its **matching** signed image and secret.
Do not reactivate old root grants or credentials after any actual rotation.

After any credentials were changed, v1 rollback is **forbidden**. Retain the
sealed current revision and use only a verified signed **v2-compatible**
rollback image with matching private secret and current host passwords.
The old image cannot reconstruct retired credentials. Record the selected
`rollbackOnFailure` or explicit `RECOVER` policy and independently
verify the actual post-recovery active image, secret generation and audit
continuity.

## Fresh databases and limitations

Fresh installations with no legacy authentication state and no existing
Console sessions may initialize directly in sealed mode. An existing
legacy authentication table is *not* upgraded automatically at startup:
the service fails closed until the offline operation above is completed.
This tool cannot prove the service is stopped; the explicit attestation and
independent deployment/host checks remain required. SQLite's secure
deletion and WAL checkpoint do not erase old protected backups or all
copies in storage snapshots. Old passwords must still be rotated.
