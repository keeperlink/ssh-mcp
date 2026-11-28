# Sealed managed credential format

For the separately reviewed operator-only atomic offline credential change
procedure, see [operator sealed rotation](operator-sealed-rotation.md).

Sealed v2 is the supported managed credential format: independent one-way
OAuth, Console and metrics verifiers, plus per-host encrypted sudo credentials
unlocked by the approved operator. Fresh databases initialize v2 directly.
A genuinely unmigrated legacy-v1 database requires separately authorized
offline conversion, not repeated migration of an already healthy v2 system.
A source merge is not authorization to sign or deploy.
See [SQLite state and recovery](sealed-db-cutover.md).

The signed managed reader accepts a v2 secret revision and passes only
one-way verifiers and a Console session-generation marker to authentication
and metrics code. It never exports the original OAuth, Console or metrics
credential in process environment variables. The Console's durable session state uses a generation-only row;
new generations invalidate old cookies. Password checks run in two dedicated, admission-controlled
workers, outside Starlette's shared pool. OAuth per-IP throttling counts
in-flight verification alongside recent failures.

**Database cutover guard:** `ViewerAuth` refuses an existing legacy
Console password verifier table in sealed mode, without deleting its rows.
The independent stopped-service `ops.history_db cutover` operation must
first take and verify an owner-only recovery snapshot and convert only the
authentication table transactionally. Fresh databases can initialize v2
directly. There is no environment variable that bypasses this check.

### In-memory grant handles and sealed readiness

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

### Interactive root approval and command handoff

Memory-only grant handles integrate with the existing privileged approval flow.
The root-only modal prompts for the Operator Console password on **each new
root-grant interval**, including the signed
`privileged_access: always-granted` policy. Ordinary SSH grants retain
their previous behavior without a password prompt. Legacy-v1 auth requires separate migration.
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

**Independent approval remains mandatory** for signing, live credential
changes, host deployment, and database recovery. Confirm safe locked-state
readiness and fresh root-proof against the installed sudo implementation.

### Disposable synthetic sealed-v2 acceptance

The separately authorized immutable lab runner provides disposable synthetic
OAuth, Console, SSH, metrics and sudo credentials. Its isolated acceptance
tests cover authentication, locked-host discovery, scoped grants and
revocation. Remove generated credentials and containers with run-owned
cleanup. Test derivative images must never be published to production.
This is a reusable test fixture, not an unfinished implementation phase
or a requirement to repeat initial production conversion.

## Console bounds and database recovery

- The Console password must contain at least **16 Unicode scalar values**
  and at most **256 UTF-16 code units** (the browser's `maxlength` rule).
  NUL and CR/LF are rejected because password inputs strip line breaks.
  Only valid UTF-8 strings are accepted. These checks apply at conversion,
  verifier creation, rekey and verification, and fit the HTTPS form's
  `maxlength=256` and 8192-byte request cap, even for supplementary Unicode.
  The independent OAuth password and metrics token retain their existing
  8192-character legacy bounds.
- Existing v2 deployments preserve their current SQLite database; do not
  repeat historical v1 conversion. A genuinely unmigrated v1 database
  needs a separately approved, stopped-writer conversion with protected
  snapshots, session revocation, WAL checkpoint/VACUUM cleanup, and
  independently verified recovery. See
  [SQLite state and recovery](sealed-db-cutover.md).
- Post-rotation recovery requires a signed **sealed-v2-compatible** image,
  the matching current protected credential revision and compatible audit
  database. Never restore legacy plaintext credentials, retired host
  passwords or a legacy-v1 image. Offline database restore requires stopped
  writers, journal reconciliation, and subsequent authentication and
  audit-continuity validation.

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
changes or writes the source; the caller must implement safe temporary-file
permissions and atomic source replacement.

`rotate_console` returns an independently prepared copy, re-encrypting
**all** existing per-host entries and changing the Console generation in
one step. `rotate_host_sudo` returns a copy with one host's new sealed
password. `add_host_sudo` returns a copy with exactly one additional host's
sealed password, never overwriting an existing envelope. None of these
functions changes a remote host password, authorizes a
deployment or writes to a live secret mount.

Follow [operator sealed rotation](operator-sealed-rotation.md) for future
credential changes and [SQLite state and recovery](sealed-db-cutover.md)
for stopped-service restore. Retire obsolete stages and snapshots under
separate approval; deployment remains a distinct action.
