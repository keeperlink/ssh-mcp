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

## SKY-360 one-session batch rotation (optional)

The reviewed `ssh-mcp-secrets batch-handoff` command combines private
preparation and a guarded **production Jenkins secretFile** handoff. Run
only in an operator-controlled root terminal, never through SSH-MCP,
a Jenkins pipeline, a logged remote command or CI. The existing service
keeps using its currently loaded credentials until explicitly redeployed.

The operator prepares a **nonsecret** JSON mapping of approved Proxmox
aliases to VMIDs inside the trusted workdir (use real VMIDs, never infer
them from the host name):

```json
{"version": 1, "vmids": {"demo-node-a": 100, "demo-node-b": 200}}
```

The mapping is required by the batch command; the operator independently
checks the signed inventory and exact inventory/source SHA-256, and uses a
protected **0700 workdir** for generated outputs. The default production
Jenkins secretFile has to be a regular, single-link, root:1000 mode-0640
file in a root:1000 mode-0750 `deployment` directory; the host must have a
reviewed installed wheel and the `openssl` executable. Use exactly one
interactive invocation (set all paths, expected checksums and issuer to
their independently verified values):

```sh
ssh-mcp-secrets batch-handoff \
  --jenkins-file /path/to/jenkins/secrets/deployment/skymap-ssh-mcp-secrets \
  --inventory /path/to/approved/production/inventory.json \
  --vm-map /private/operator/rotation/vm-map.json \
  --workdir /private/operator/rotation \
  --deployment production --issuer https://approved-issuer.example \
  --expected-source-sha256 EXPECTED_64_HEX_SHA256 \
  --expected-inventory-sha256 EXPECTED_64_HEX_SHA256 \
  --jenkins-container APPROVED_CONTROLLER_CONTAINER
```

The tool requires a real TTY; it prompts privately once for old/new
OAuth and old/new Console passwords (both replacements confirmed),
generates unique high-entropy sudo credentials for **every signed host**,
and writes a complete encrypted v2 stage plus **independently salted
SHA-512 crypt verifiers only** for each host and a Proxmox subset.
It validates file ownership, hashes, source fingerprint and host bindings
before atomically replacing the production Jenkins file. It verifies the
new bytes inside the Jenkins controller mount. Output includes only
file paths, alias counts and SHA-256 fingerprints, never passwords or
crypt verifiers. The `skymap-test` scoped credential is untouched.
A missing/failed controller readback is **not PASS**; inspect current
source digest after an uncertain post-commit failure and never rerun
blindly. The protected staged source and exports remain for reconciliation.

After `BATCH_HANDOFF=COMMITTED`, the operator can start Jenkins
JCasC/job provisioning while a separately authorized operator uses the
**production** SSH-MCP opaque `transfer_file` to place each private,
hash-only file on its intended host with a source/destination root grant
and exact SHA-256 preconditions. Do **not** place hash values in shell
argv, ChatGPT text, SSH-MCP audit logs or Git. A source/destination
file transfer is not permission to apply the password.

On the selected host, use the installed root-only apply entrypoint,
passing only protected file paths and their exact SHA-256:

```sh
ssh-mcp-secrets-apply local --file /protected/host-hashes.json \
  --expected-sha256 VERIFIED_FILE_SHA256 --alias APPROVED_HOST_ALIAS

ssh-mcp-secrets-apply proxmox --file /protected/proxmox-hashes.json \
  --expected-sha256 VERIFIED_FILE_SHA256 \
  --controller-host APPROVED_PROXMOX_HOST --expected-count APPROVED_VM_COUNT
```

Both modes require root. Local mode verifies the actual host identity
and uses `chpasswd --encrypted` via stdin, not argv. Proxmox mode
verifies **every** configured VMID/guest name and running guest-agent
reachability before any writes, then sends only hash-bearing stdin via
`qm guest exec --pass-stdin` to guest `chpasswd --encrypted`.
It stops on failure, reporting only host aliases. Guest-agent timeouts
may mean an operation completed despite no acknowledgment: investigate
before retrying. Hash-only files are sensitive and must be cleaned up
after accepted rotations.

For a controller hosting VMs, rotate all guest passwords, verify/clean
up, then rotate the controller's **own** account last among operations
performed there. Rotate the administration host's own account **last
overall**, **before** signed production SSH-MCP deployment. During the
interim, new passwords on hosts will not work with the old running
sealed SSH-MCP credential; preserve independent administrative access.
Only after all host changes and successful Jenkins provisioning should
the operator approve/redeploy SSH-MCP and verify OAuth, Console and all
sudo grants. Never perform deployment in the batch helper.

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
   [sealed database cutover](sealed-db-cutover.md) **before** activation.
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
