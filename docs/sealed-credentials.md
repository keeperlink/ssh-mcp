# Sealed managed credential format (SKY-347)

The v2 primitives in `app/sealed_credentials.py` are the **first, offline
development stage**, not yet a deployed authentication mechanism. Do not put
v2 secrets into a running SSH-MCP deployment until the signed-config reader,
OAuth/Console/metrics authentication, privileged approval flow and readiness
monitor support v2 and complete LAB acceptance. The current production image
does not consume the new format.

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
