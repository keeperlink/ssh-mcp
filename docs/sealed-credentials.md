# Sealed managed credential format (SKY-347)

For the separately reviewed operator-only offline preparation and guarded
activation procedure, see [operator sealed rotation](operator-sealed-rotation.md).

The v2 verifier, privileged approval and in-memory unlock support are
implemented. The application image can accept sealed v2 input only after a
separately approved offline history database snapshot and cutover for a
legacy service. A merge is **not** a deployment or signing authorization.
Read [the sealed database cutover procedure](sealed-db-cutover.md) before
preparing a signed image or attempting any live upgrade.

The signed managed reader accepts a v2 secret revision and passes only
one-way verifiers and a Console session-generation marker to authentication
and metrics code. It never exports the original OAuth, Console or metrics
credential in process environment variables. The Console's durable session
state replaces the old auxiliary PBKDF2 verifier with a generation-only row
only at an explicitly approved v2 cutover; new generations invalidate
previous cookies. Password checks run in two dedicated, admission-controlled
workers, outside Starlette's shared pool. OAuth per-IP throttling counts
in-flight verification alongside recent failures.

**Database cutover guard:** `ViewerAuth` refuses an existing legacy
Console password verifier table in sealed mode, without deleting its rows.
The independent stopped-service `ops.history_db cutover` operation must
first take and verify an owner-only recovery snapshot and convert only the
authentication table transactionally. Fresh databases can initialize v2
directly. There is no environment variable that bypasses this check.

### Stage 3A: in-memory grant handles and sealed readiness

`app.grant_unlocks.GrantUnlocks` adds a bounded, process-memory-only
credential registry. Each high-entropy opaque handle is bound to the exact
operator actor, up-to-2048-character verified OAuth client ID, existing
three-field agent-or-conversation approval key (including empty conversation
for request-only grants), signed host alias, root issuance and secret
generation. Request-only grants additionally bind one operation; timed grants
can be reused by later authorized operations under the same grant issuance.
All handles have a monotonic maximum 16-hour deadline, with event-loop
timers that release idle expired credentials without another request.
Callers must recheck the handle at capacity admission and immediately before
sudo password submission.
The password verifier and host-envelope decryption happen in the isolated
worker via `prepare()`, producing only an uncommitted memory object.
`commit()` runs on the service event loop, atomically rechecks a mandatory
live authority callback (pending approval, session, actor, grant generation,
host readiness), expiry, capacity and the registry revocation epoch before
publishing a handle. Revoked/logged-out/cancelled work cannot publish late
plaintext after password verification finishes.
Revocation and operator logout clear the affected handles; credential
rotation and service shutdown clear all handles. Immutable Python strings
cannot be guaranteed to be zeroized after use. There are **no persistent
unlock handles, derived keys or sudo passwords**.

The signed bootstrap binds the complete validated v2 secret revision to a
source path and SHA-256 fingerprint. The SSH executor reads that same
protected source and rejects a missing, replaced or independently valid
but different secret revision instead of combining unrelated verifier and
sudo-envelope material. After full revision validation, sealed entries for
host aliases retired from the signed inventory are ignored; the in-memory
executor only retains envelopes for current authorized hosts. OAuth and
Console passwords, the metrics bearer token, and host sudo passwords are
not exported into environment variables. The
recoverable JWT signing key remains supplied as `MCP_TOKEN_SIGNING_SECRET`.
Its 30-second readiness monitor performs only pinned-identity
SSH and noninteractive passwordless-root safety checks while sealed.
Conclusive safe refusal displays **Locked**, not Offline/Degraded; ambiguous
evidence displays **Safety unconfirmed** and distinct recent SSH reachability,
blocks all SSH command admission
and cannot make operator recheck succeed until conclusive safety proof; confirmed
unsafe passwordless-root remains latched until conclusive safe evidence.
Transient safety transport/timeout failures do not erase a previously
conclusive safe result: ordinary SSH remains eligible until the existing
readiness stale deadline, with the actual failure reason and warning shown.
The failed live probe and explicit recheck still report failure. Confirmed
unsafe or ambiguous safety evidence remains immediately fail-closed.
Operator rechecks also remain password-free while locked. The Console uses
the same status vocabulary without labeling recently reachable hosts Offline
or raising stale-SSH warnings merely because safety confirmation is missing.
The external active/offline/retired eligibility contract is unchanged.

### Stage 3B: interactive root approval and command handoff

Stage 3B wires these handles to the existing privileged approval flow.
The root-only modal prompts for the Operator Console password on **each new
root-grant interval**, including the signed
`privileged_access: always-granted` policy. Ordinary SSH grants retain
their previous behavior without a password prompt; v1 remains unchanged.
Incorrect passwords leave the request and selected duration pending and
show **Incorrect Console password.**. The prompt shares the Console login
per-IP five-failure/five-minute throttle and displays **Too many incorrect
password attempts. Try again later.** when exhausted. No root grant, decrypt
or sudo probe occurs on wrong or throttled input.

After a checked Console session and password verification on the bounded
auth executor, the password derives its separate Argon2id sudo-wrap key
and opens only the selected host's signed envelope into an uncommitted,
single-use memory object. A fixed fresh sudo probe uses a nonce-bound
prompt and the root-only `id -u` marker. The original pending grant,
Console session and sealed-host safety are checked before the credential
write and again at atomic grant issuance, along with approval deadline,
the originating MCP request's live disconnect state, client/actor scope
and revocation generation. Every authenticated Console logout invalidates
even in-flight prepared credentials, whether or not any root grant exists.

The opaque capability follows one request's task context into queued jobs
and sequential batches without being stored in their audit records.
Execution rechecks the live capability **after capacity admission** and
immediately before each actual sudo password submission. An expired or
revoked grant cannot be revived by a later issuance; a started command can
finish normally but later batch steps are rejected. Explicit authenticated
Console logout revokes all root unlocks without removing ordinary host
grants. Passive cookie expiry does not shorten timed grants. Immutable
Python strings cannot be guaranteed to be physically zeroized.

A one-request credential's safety expiry covers the validated operation
timeout plus a bounded 60-second margin (never longer than 16 hours), not
a fixed five-minute lease. The process releases its plaintext memory
reference immediately after the single command, accepted asynchronous
job, or **whole** batch finishes, including failure/cancellation. A
successfully queued job or shielded batch owns that release; otherwise
the originating MCP tool request releases the credential before returning.
Timed root grants continue to expire/revoke only by their approved scope.
The Console clears its root-password input on every submission and error.

**Independent rollout approval remains mandatory:** signed release/image
publication, database backup and cutover, credential rotation and host
deployments are separate operations. Actual sudo implementations must
independently pass LAB
conclusive safety and fresh root-proof tests. DB recovery/cutover, offline
rekey and mandatory rotation of old plaintext credentials remain separate
gates before declaring SKY-347 complete.

### Stage 3C: disposable LAB-only sealed activation fixture

The separately installed, immutable `tests/lab/runner.py` can prepare
`--credentials sealed-v2` with only synthetic SSH identities and host
aliases. It builds a clearly labeled disposable **derivative** of the
reviewed application image with a single source-verified activation
override in the installed wheel. The committed application and normal
production release image still refuse v2 at startup; no environment
variable can enable it in the normal image. Generated OAuth/Console
passwords and metrics bearer values reach the synthetic test client only,
while the sudo fixture password reaches only the SSH test host. The
sealed service reads verifiers and a per-host AES-GCM envelope in its
protected source file. All artifacts require owner-checked LAB cleanup.

Stage/activate the new **eight-file** runner only after paired merges
and separate LAB approval. `tests/integration/sealed_v2_acceptance.py`
covers live synthetic OAuth, Console, metrics, Locked host discovery,
sudo unlocks and revocation. This is LAB-only evidence, not approval for
Jenkins credential changes, signing, deployment, remote password
rotation or production sealed-mode cutover and rollback.

**Temporary compatibility boundary:** the old managed v1 schema remains
accepted solely to preserve existing offline fixtures and current deployed
behavior during staged development. The final sealed cutover must reject v1
without fallback; root operation while v2 is sealed cannot be accepted until
the separately reviewed unlock/readiness implementation lands.

## Console bounds and database recovery

- The Console password must contain at least **16 Unicode scalar values**
  and at most **256 UTF-16 code units** (the browser's `maxlength` rule).
  NUL and CR/LF are rejected because password inputs strip line breaks.
  Only valid UTF-8 strings are accepted. These checks apply at conversion,
  verifier creation, rekey and verification, and fit the HTTPS form's
  `maxlength=256` and 8192-byte request cap, even for supplementary Unicode.
  The independent OAuth password and metrics token retain their existing
  8192-character legacy bounds.
- Stage 2 **cannot activate v2**. Before a future approved cutover, create
  and verify a private *pre-cutover* SQLite snapshot using the existing
  `ops.history_db backup` and `verify` facilities. Test a restore
  of that same snapshot in an independent recovery environment with
  the previous v1 image and matching credential revision; do not rely on
  rolling an image back without also restoring the old database schema.
- During the approved future cutover, stop all database writers before
  activating the generation-only schema. Enable
  `PRAGMA secure_delete=ON` before dropping the legacy verifier table,
  checkpoint/truncate the WAL, run `VACUUM`, then checkpoint again
  **while the service remains stopped**. Verify active SQLite pages,
  WAL/SHM files and newly created snapshots no longer contain the
  retired auxiliary PBKDF2 verifier. Dropping a table alone does not
  guarantee historical data retirement; separately account for old
  backups and WAL files under the approved retention/rotation plan.
- Rollback to a v1 image requires that *verified pre-cutover* snapshot
  and compatible legacy credentials. Use guarded `ops.history_db restore`
  only with the service stopped, with WAL/SHM reconciled; restore
  revokes persisted OAuth sessions **and all restored Console sessions**,
  so an older cookie never becomes valid again. The v1 snapshot is strictly
  for **pre-cutover recovery**. Once a sealed-only cutover succeeds, rollback
  requires a **sealed-compatible** image and an appropriate protected secret
  revision, even *before* host sudo passwords are rotated. Never reintroduce
  plaintext values as a silent fallback.

## Threat boundary

- The OAuth and Console passwords use independent Argon2id verifiers with
  different salts and domain-separated inputs.
- Sudo passwords are encrypted separately per alias with AES-256-GCM.
  The key is derived from a newly entered Console password, not from the
  stored Console verifier. The AEAD associated data binds the deployment
  environment, OAuth issuer, host alias and expected SSH username.
- The metrics bearer credential is represented by its SHA-256 digest; only
  high-entropy, independently generated tokens are suitable.
- Argon2id parameters are fixed and validated before allocation: 64 MiB
  memory, three iterations, one lane, at most two simultaneous derivations.
  Random salts are 16 bytes; random AES-GCM nonces are 12 bytes.
- JWT signing keys and SSH authentication private keys remain recoverable
  by necessity. Sealing sudo does not protect against a live compromised
  runtime that can observe typed passwords or running command execution.

## Prepared v2 JSON

`version: 2` requires exactly these fields:

| Field | Value |
| --- | --- |
| `oauth_login_verifier` | Argon2id verifier for OAuth authorization form |
| `viewer_verifier` | Different Argon2id verifier for Console login |
| `viewer_generation` | Random 16-byte session-invalidating generation, hex |
| `metrics_verifier` | Constant-time-checked SHA-256 bearer token digest |
| `sealed_sudo` | Mapping of host aliases to independently salted AES-GCM envelopes |
| `oauth_signing_key` | Protected, recoverable JWT signing key |
| `ssh_private_key` | Protected, recoverable SSH client private key |

`from_legacy` converts only a trusted, explicitly supplied v1 source and
trusted signed-host username mappings, **in memory**. Unknown sudo aliases,
invalid source credentials and wrong Console passwords fail. It never
changes or writes the source; the caller must implement safe, staged
permissions and atomic activation.

`rotate_console` returns an independently prepared copy, re-encrypting
**all** existing per-host entries and changing the Console generation in
one step. `rotate_host_sudo` returns a copy with one host's new sealed
password. Neither function changes a remote host password, authorizes a
deployment or writes to a live secret mount.

Follow the SKY-347 operator procedure for interactive provisioning, complete
credential rotation, prior-secret retirement, recovery and sealed-compatible
rollback. Those steps require separately approved LAB and production work.
