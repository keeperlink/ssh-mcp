# Offline sealed credential preparation and recovery

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

## One-session full-fleet enrollment (optional)

The reviewed full-fleet batch-handoff is an optional **initial enrollment**
and collective-rotation operation, not routine maintenance of one credential.
It combines private preparation and a guarded Jenkins secretFile handoff. Run
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
  --jenkins-file /path/to/jenkins/secrets/deployment/ssh-mcp-secrets \
  --inventory /path/to/approved/production/inventory.json \
  --vm-map /private/operator/rotation/vm-map.json \
  --workdir /private/operator/rotation \
  --deployment production --issuer https://approved-issuer.example \
  --expected-source-sha256 EXPECTED_64_HEX_SHA256 \
  --expected-inventory-sha256 EXPECTED_64_HEX_SHA256 \
  --jenkins-container APPROVED_CONTROLLER_CONTAINER \
  --jenkins-container-file /run/jenkins/secrets/deployment/ssh-mcp-secrets
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
crypt verifiers. Other environment-scoped credentials remain untouched.
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

Run the reviewed installed utility in a trusted real TTY, after independently
verifying signed inventory provenance, deployment, issuer, correct target,
recovery access and downstream handoff. Prepare any recovery backups yourself:
the utility never creates, manages, restores or retains previous revisions.
Do not pass credentials in command arguments, environment variables, logs or
chat. Use absolute paths. Before upgrading from the former stage/activation
workflow, reconcile each existing protected staged pair with the current
source and its intended consumers, then retire obsolete artifacts through
operator-controlled cleanup. The new utility does not consume old stages.

For a standalone protected offline source, the parent directory must be owned
by the operator and mode 0700; the source must be a regular single-link
non-symlink file mode 0600. Do not point the utility at a running service mount.

Set shell variables to paths and binding information only:

```sh
SOURCE=/path/to/private/ssh-mcp-secrets
INVENTORY=/path/to/approved/signed-inventory.json
DEPLOYMENT=production
ISSUER=https://your-approved-oauth-issuer.example

ssh-mcp-secrets plan --source "$SOURCE" --inventory "$INVENTORY" \
  --deployment "$DEPLOYMENT" --issuer "$ISSUER" --operation console

ssh-mcp-secrets apply --source "$SOURCE" --inventory "$INVENTORY" \
  --deployment "$DEPLOYMENT" --issuer "$ISSUER" --operation console
```

Choose exactly **oauth**, **console**, **sudo**, **add-sudo**, or **metrics**
for `--operation`. For sudo rotation/enrollment supply `--host APPROVED_ALIAS`.
Only sealed-v2 sources are supported. The optional read-only plan reports the
selected operation and the source/inventory SHA-256 values without prompts or
writes. Independently check the signed inventory and exact target; optional
`--expected-source-sha256` and `--expected-inventory-sha256` pin those bytes.

## Direct Jenkins secretFile changes

For a Jenkins-managed offline source use the same apply operation as root,
selecting the correct environment-specific file explicitly. Provide the
independently verified digests and controller mount, as in batch-handoff:

```sh
ssh-mcp-secrets apply \
  --jenkins-file /path/to/jenkins/secrets/deployment/ssh-mcp-secrets \
  --inventory "$INVENTORY" --deployment "$DEPLOYMENT" --issuer "$ISSUER" \
  --expected-source-sha256 EXPECTED_64_HEX_SHA256 \
  --expected-inventory-sha256 EXPECTED_64_HEX_SHA256 \
  --jenkins-container APPROVED_CONTROLLER_CONTAINER \
  --jenkins-container-file /run/jenkins/secrets/deployment/ssh-mcp-secrets \
  --operation add-sudo --host APPROVED_ALIAS
```

Flat or one-level scoped paths (e.g. `deployment/nonprod/<leaf>` or
`deployment/demo-node-a/<leaf>`) are supported; the controller mount must
match the complete relative path under deployment, not just the leaf.
The deployment directory and any scope directory must be root:1000 mode
0750 and not symlinks; the single-link regular
secretFile must be root:1000 mode 0640. The utility verifies the source and
inventory, takes an advisory flock on the existing deployment directory inode shared
by flat and scoped writes and batch-handoff (no persistent lockfile), prepares
and validates the full sealed revision in memory, writes a securely created
sibling temporary file, fsyncs it, rechecks source/inventory fingerprints, and
atomically replaces only the selected file. It preserves the required file
owner/mode, fsyncs the directory, verifies the committed bytes and checks the
controller-visible digest. The local-file target follows the same guarded
commit procedure with owner-only permissions.

`APPLY=PASS` means the offline source was committed and verified; it does not
mean Jenkins provisioning, service deployment, consumer updates or remote
password changes have occurred. The running service continues using its
existing immutable revision until separately redeployed. Before applying,
confirm the selected source really is independent of the running service and
coordinate with other operators and downstream consumers; the advisory lock
serializes cooperating tool invocations, not arbitrary external writers.

A precommit failure leaves the source unchanged and removes the tool-owned
temporary file. Exit code 2 means the commit outcome is uncertain: compare
the actual offline source and controller-visible digests with the reported
expected committed SHA-256 before retrying. Reconcile an interrupted
operation through independent access; never blindly repeat a password
rotation or restore an older mismatched revision.

## Rotation handoffs and interrupted recovery

- **OAuth:** enter the old password and confirm the new independent password.
  Coordinate consent, token/session revocation and deployment separately.
- **Console:** enter the old and confirmed new password. All existing sealed
  sudo envelopes are re-encrypted and the session generation changes in one
  commit. Prior unlocks are invalidated on restart. Loss of the old Console
  password requires independent administrative re-enrollment, not a backdoor.
- **Host sudo:** confirm independent recovery access and pause privileged work
  for the selected host. Commit the new encrypted value first, then change
  the matching remote password through independent administration. Do not
  restore a mismatched older revision if the handoff is interrupted.
- **Add host sudo:** independently verify the signed inventory and explicit
  privileged policy, select the intended protected source, and enter the
  existing Console password and a new unique host password twice. The tool
  adds exactly one envelope and preserves existing entries. Set the exact
  password independently, confirm password-required sudo and rejection of
  passwordless sudo, then deploy the approved inventory and matching revision.
  No database migration or Console rekey is needed.
- **Metrics:** commit the new bearer verifier and separately coordinate the
  protected scraper-side replacement. Verify new-token acceptance and
  old-token rejection after deployment.

Separately approve Jenkins provisioning, signed service deployment and
consumer changes. Verify loaded fingerprint, login, sudo proof, audit
continuity and metrics after deployment. Do not repeat legacy database
conversion on healthy v2 installations; actual offline database recovery
requires stopped writers and protected snapshots as described in
[SQLite state and recovery](sealed-db-cutover.md). Never restore retired
passwords or legacy plaintext credentials over a rotated sealed-v2 service.
Document waived acceptance tests as skipped, not PASS.
