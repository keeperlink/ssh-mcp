# SSH-MCP tests

The suite separates offline unit and contract checks from explicit integration tests. Choose the suite based on **dependencies and execution authority**, not the issue or pull request that introduced the test.

| Suite | Responsibility | Invocation |
| --- | --- | --- |
| [unit/](unit/) | Deterministic application/runtime/security tests with synthetic inputs and mocked external calls | python tests/tools/run_unit_tests.py |
| [contracts/](contracts/) | MCP/OAuth, coverage, validation, OCI and CI interface contracts | Same offline runner |
| [integration/](integration/) | Real disposable OAuth/SSH and OpenSSH acceptance, and the separately gated headless-browser check | Explicit only; see [integration instructions](integration/README.md) |
| [fixtures/](fixtures/) | Browser and other synthetic test data, not discoverable tests | As needed |
| [tools/](tools/) | Offline suite runner, installed-wheel validator, coverage and test tools | python tests/tools/validate.py |
| [lab/](lab/) | Separately reviewed **pinned** Docker/SSH orchestrator, client, fixture ; its offline safety tests live in unit/ | python -m unittest tests.unit.test_lab_runner -q |

## Naming and ownership

- Offline test modules use test_<behavior>.py in exactly one of unit/ or contracts/. Test classes use *Tests names.
- Shared Python helpers use _*.py, not discoverable test modules. Do not import reusable helpers from another test module.
- The offline runner rejects any `test_*.py` file outside the immediate `unit/` and `contracts/` directories (including `lab/`, `tools/`, nested folders and the root), duplicate module names/test identities, and missing suites.
- Integration entrypoints have feature-oriented names without the test_ prefix. They are never invoked by offline installed-wheel discovery.
- The installed wheel is exercised from site-packages; the source checkout is not imported as the application. The **95% combined line+branch coverage requirement** remains mandatory, including the hardened OCI image.

## Offline validation

From a reviewed unprivileged development checkout with the pinned Python 3.12 environment:

~~~
python tests/tools/run_unit_tests.py
python -m unittest tests.unit.test_lab_runner -q
python tests/tools/validate.py
python scripts/check_public_docs.py
~~~

The full validator builds a wheel and tests it in a temporary isolated Python environment against the same unit+contracts discovery as the OCI image's mandatory runtime-tests stage. Lab runner safety is an independent offline CI gate; the Chrome layout check is a separate native GitHub-hosted gate.

Neither ordinary offline discovery nor the OCI test stage starts Docker, accesses a real SSH host or executes an integration script. The standalone runner and validator child processes discard inherited managed-service mount, OAuth, SSH, history and database environment settings before importing the application, replacing them with synthetic test settings.

## Isolation and operator approval

The [pinned lab runner](lab/README.md) is installed from an independently reviewed immutable Git SHA. It creates disposable SSH fixtures, synthetic credentials, a read-only candidate source mount and an isolated network without published host ports. The [integration scripts](integration/README.md) are candidate test data, **never the trusted orchestrator**. Native Docker/OpenSSH acceptance needs its own rootless Docker approval; the browser CI fixture uses a synthetic local API.

Successful unit/CI validation does not authorize Docker access, sudo, network changes, production execution, signing or deployment.
