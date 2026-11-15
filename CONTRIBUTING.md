# Contributing to SSH-MCP

Contributions, bug fixes and documentation improvements are welcome.

## Local development

Use Python 3.12 and a fresh virtual environment. From a source checkout:

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
python tests/tools/validate.py
python scripts/check_public_docs.py
```

The validator runs Ruff, strict mypy, offline unit and contract tests,
installed-wheel tests and enforces at least 95% combined coverage.
The rootless Docker/OpenSSH integration test is opt-in and must be run
only on infrastructure you are authorized to use.

Changes to authentication, approvals, SSH execution, file operations,
secrets or auditing should include negative tests and fail-closed
coverage. Submit focused pull requests with a clear description,
tests run and any compatibility implications.

Never commit secrets, real SSH keys, production inventories, internal
addresses or private historical logs. Use synthetic fixtures only.
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

The project is licensed under [Apache-2.0](LICENSE); by contributing,
you agree to license your contribution under those terms.
