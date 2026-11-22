# Sealed managed credential format (SKY-347)

The v2 cryptographic primitives and **OAuth, Console, and metrics verifier
wiring** are implemented as separate development stages. This is **not yet
deployable**: the privileged grant popup, per-scope in-memory sudo unlock,
locked readiness checks, operator provisioning and LAB acceptance are still
required. Do not put v2 secrets into a running SSH-MCP deployment or sign an
image for rollout until the remaining SKY-347 gates are met.

The signed managed reader accepts a v2 secret revision and passes only
one-way verifiers and a Console session-generation marker to authentication
and metrics code. It never exports the original OAuth, Console or metrics
credential in process environment variables. The Console's durable session
state replaces the old auxiliary PBKDF2 verifier with a generation-only row
only at an explicitly approved v2 cutover; new generations invalidate
previous cookies. Password checks run in two dedicated, admission-controlled
workers, outside Starlette's shared pool. OAuth per-IP throttling counts
in-flight verification alongside recent failures.

**Activation guard:** `app.config.SEALED_RUNTIME_READY` remains hardcoded
`False` in Stage 2. Even a valid v2 mount cannot start a service or
change the audit database, and this cannot be overridden by environment.
The later reviewed root-unlock/readiness and explicit database-recovery
stage must remove this guard before any v2 production activation.

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
