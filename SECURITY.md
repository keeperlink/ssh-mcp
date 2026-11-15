# Security policy

## Supported versions

Security fixes are developed for the current `main` branch. Security
updates for older releases are not guaranteed.

## Reporting vulnerabilities

**Do not submit exploit details, tokens, credentials, host data, or
unpatched vulnerabilities in a public issue.** Use GitHub's
[private vulnerability reporting](https://github.com/keeperlink/ssh-mcp/security/advisories/new)
for this repository when enabled. If the private reporting link is not
available, ask the maintainer for a private reporting channel without
sharing the vulnerability itself in a public discussion.

Include a minimal reproduction using synthetic hosts and credentials,
the affected commit or image digest, relevant configuration mode and
the potential impact. Do not test against systems you do not own.

## Security boundaries

This software runs commands on explicitly authorized remote SSH hosts.
It is **not** a remote command sandbox. Use dedicated least-privilege
SSH users, pinned host keys, HTTPS, carefully scoped OAuth clients,
secure runtime secrets, and durable audit storage. Read
[Security](docs/security.md) and [Hardening](docs/hardening.md) before
deployment.
