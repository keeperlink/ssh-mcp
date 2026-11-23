# Offline sealed credential preparation and recovery (SKY-347)

This guide covers **offline preparation only**. The operator tool does not
restart SSH-MCP, change remote sudo passwords, update OAuth or metrics clients,
revoke sessions, sign images, or select a rollback image. Production requires
independent change approval and recovery access. Never run this from Jenkins,
an SSH MCP job, a shell transcript logger or a noninteractive automation.

The operator uses the installed `ssh-mcp-secrets` command from a reviewed
wheel, in a trusted terminal on the designated administration host. The signed
inventory, deployment environment and OAuth issuer must have been checked
independently against the approved deployed configuration. The utility reads
the inventory but **does not validate its digital signature**.

## Protected inputs and restrictions

The active JSON file and its parent must be owned by the executing operator.
The parent must be a real directory with mode **0700**; the active file must
be a regular, single-link, non-symlink **0600** file. The inventory must be a
regular non-symlink file, not group/other writable. Do not loosen access
controls to make the tool work. Use absolute paths; keep the generated stage
and its manifest in the same protected directory. Never expose protected
file contents, passwords or the generated stage through chat, audit logs,
environment variables, argv, history, shell trace or CI.

For example, set shell variables to **paths and public binding values only**
(never passwords):

```sh
SOURCE=/path/to/private/ssh-mcp-secrets
INVENTORY=/path/to/approved/signed-inventory.json
DEPLOYMENT=production
ISSUER=https://your-approved-oauth-issuer.example
```

The read-only plan identifies the selected operation, host alias count and
source revision without prompting for passwords or changing files:

```sh
ssh-mcp-secrets plan --source "$SOURCE" --inventory "$INVENTORY" \
  --deployment "$DEPLOYMENT" --issuer "$ISSUER" --operation console
```

For `--operation`, choose exactly **migrate**, **oauth**, **console**,
**sudo**, or **metrics**. For sudo rotation also add
`--host APPROVED_ALIAS`; use the actual signed inventory, not a guessed
alias. Migration accepts only legacy v1 source; other modes require v2.

## Stage, verify, and explicitly activate

1. Run the same arguments with `stage` instead of `plan` in a real
   interactive terminal. The utility uses hidden, confirmed password entry.
   It never takes password values in CLI flags or environment variables.
   It prepares a **complete** new sealed JSON revision, fsyncs its 0600
   stage and matching private manifest, and leaves the active source intact.
2. Record the returned stage **path** (not its contents). Independently
   verify it:

   ```sh
   ssh-mcp-secrets verify --source "$SOURCE" --staged "$STAGED_PATH"
   ```

   The manifest pins the exact active source SHA-256 and complete staged
   revision. An incomplete stage, changed active source, damaged artifact,
   missing sidecar, bad ownership or permissions is rejected. A failed or
   interrupted stage leaves the active revision untouched. To discard an
   intact staged pair, use `ssh-mcp-secrets discard --source "$SOURCE"
   --staged "$STAGED_PATH"`. Discard also permits obsolete stages after
   the active revision has changed, but it always verifies stage integrity
   and the protected directory first.
3. Confirm independently: administrative recovery and retained backups;
   the correct sealed-format-compatible signed target and rollback image;
   downstream consumer handoff; stopped application and stopped database
   writers. For v1 migration, complete the approved database cutover and
   rollback snapshot procedure in
   [sealed credentials](sealed-credentials.md) **before** activation.
   The tool does not independently verify stopped service or downstream
   readiness: these flags are explicit operator attestations.
4. Only after the separately approved handoff, run:

   ```sh
   ssh-mcp-secrets activate --source "$SOURCE" --staged "$STAGED_PATH" \
     --confirm-stopped --confirm-recovery --confirm-consumers-ready
   ```

   For a legacy-to-v2 migration also supply `--confirm-db-ready`.
   Activation rechecks the source hash and staged integrity under a private
   advisory lock, atomically renames the complete stage over the source
   and fsyncs its directory. **The utility does not create a previous
   source backup**; independently protected recovery copies are mandatory,
   and prior legacy plaintext backups require retirement and rotation.
   If an I/O failure occurs after the rename, the utility reports an
   *uncertain activation outcome*. Compare the active digest before taking
   another action; never blindly repeat an uncertain activation.
5. Rebuild/deploy the approved sealed-compatible service with environment
   and verifier exports derived from the **new active revision**, recreate
   it and verify its actual loaded fingerprint, OAuth/Console login,
   granted sudo, audit continuity, and metrics consumers. Clear/revoke
   sessions and old client tokens as required. A file replacement alone
   does not reload the running service.

## Rotation handoffs and interrupted recovery

- **OAuth:** verify the old password interactively, stage the new independent
  verifier, then coordinate consent and session revocation with deployment.
- **Console:** enter the old and a new password; every signed host's sealed
  sudo entry is re-encrypted, the session generation changes, and prior
  unlocks must be invalidated on restart. A lost old Console password
  requires independent administrative re-enrollment, not a backdoor.
- **Host sudo:** choose one verified alias and confirm independent admin
  recovery access. Stage the encrypted new value **before** changing the
  remote password. Pause that host's privileged work, change its password
  through independent administration, then activate the prepared revision
  and verify new-password success / old-password rejection. If interrupted
  between host and service changes, **do not rollback to mismatched secrets**:
  maintain the host isolation, inspect stage and active hashes and complete
  the matching handoff through the independent recovery channel.
- **Metrics:** stage the new bearer verifier and coordinate the protected
  scraper-side replacement. Verify both new-token acceptance and old-token
  rejection after deployment.
- **Migration:** the v1 source is left untouched until separately authorized
  activation. No plaintext staging copy is produced; separately existing
  v1 backups still require explicit inventory and retirement.

An interrupted rekey must not leave a partially activated secret: a complete
staged file and manifest are required for activation. The tool never alters
remote credentials by itself. Production rotation, signed-image rollback,
database restoration and acceptance of all old-credential revocations remain
separate, mandatory SKY-347 gates. **Never restore an old plaintext image or
credential bundle after sealed cutover**. Retain compatible signed image
digests and the current sealed revision in the operator-approved rollback plan.
