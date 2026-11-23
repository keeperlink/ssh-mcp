# Isolated SSH-MCP integration tests

The lab runner exercises OAuth, MCP commands, files, History approvals and
privileged access against an entirely **synthetic SSH fixture**. It is a
maintainer tool, not a deployment guide. For installation of the actual
service, see [Getting started](../../docs/getting-started.md).
Individual test programs are indexed in
[integration tests](../integration/README.md).

## Safety and source trust

- Use an approved, nonproduction test host and follow its access policy.
  Source changes and PR reviews belong in an unprivileged development
  workspace, not on the test host.
- **Never execute the candidate checkout's `tests/lab/runner.py` as the
  orchestrator.** Install the runner separately from an independently
  reviewed, merged, immutable full Git commit SHA.
- The installed runner verifies its pinned marker and the Git blob hashes
  of its executable and fixture files before any mutating operation.
  Review the candidate application SHA and test scripts independently;
  choosing a SHA is not permission to execute it.
- Use only generated credentials, disposable Docker resources and the
  fixture SSH host. Do not mount real SSH keys, the host Docker socket,
  deployment secrets or shared service volumes; do not access real SSH
  hosts or modify other containers.
- Each run is isolated and requires explicit cleanup. No external host TCP
  ports are published by the runner.

## Host preflight for an approved integration run

The selected test host must be authorized for Docker integration testing.
Follow local host documentation for host identity,
provisioning and privilege policy; do not embed a real host inventory in
this reusable project guide. This preflight checks capability, not approval.

Set `REPO_NAME` to the independently reviewed repository slug.
The preflight verifies that the slug, bare cache and reviewed
`tests/lab/source.json` agree, without importing untrusted candidate code.

Before staging or executing a runner, independently verify:

- The source cache is a bare repository, its `origin` URL **exactly matches**
  the reviewed runner's `ORIGIN`, and its push URL is the deliberate
  `disabled://lab-read-only` guard. Do not alter the cache to get around
  a mismatch.
- The selected nonroot account can reach the Docker daemon, and Docker
  supports isolated internal bridges (IPv4 `gateway_mode_ipv4=isolated`
  and IPv6 disabled). Setup must verify effective isolation rather than
  assuming that `--internal` alone blocks host services.
- The approved noninteractive `sudo -n /bin/rm` **permission** is available
  only for the runner's validated, generated-secret cleanup path; do not
  run the deletion command as a preflight.
- At least one *already-running* host TCP listener on port 81, 80 or 443 is
  reachable through a non-loopback IPv4 address. The runner requires a
  positive host-side control and a negative container-to-host connection;
  an unavailable positive control is a fail-closed test setup, not a reason
  to create or expose a new listener.
- Existing running containers and installed pinned runners are inventoried;
  never replace a launcher or modify existing services during a run.

Read-only preflight examples, on the separately approved test host:

```sh
(
  set -euo pipefail
  REPO_NAME=REVIEWED_REPOSITORY_SLUG
  cache="$HOME/repos/$REPO_NAME.git"
  test "$(git --git-dir="$cache" rev-parse --is-bare-repository)" = true
  # Use a previously reviewed, already-cached exact runner SHA as the origin
  # trust anchor. Never fetch from a cache whose configured origin is unchecked.
  REFERENCE_SHA=FULL_REVIEWED_CACHED_RUNNER_SHA
  python3 - "$cache" "$REFERENCE_SHA" "$REPO_NAME" <<'PYCODE'
import json
import re
import subprocess
import sys

cache, sha, repo_name = sys.argv[1:]
def git(*args):
    result = subprocess.run(["git", "--git-dir=" + cache, *args],
                            capture_output=True, text=True, check=False)
    if result.returncode:
        raise SystemExit("SOURCE_ORIGIN=FAIL")
    return result.stdout.strip()

if not re.fullmatch(r"[0-9a-f]{40}", sha):
    raise SystemExit("SOURCE_ORIGIN=FAIL")
if not re.fullmatch(r"[A-Za-z0-9_.-]+", repo_name):
    raise SystemExit("SOURCE_ORIGIN=FAIL")
if git("cat-file", "-t", sha) != "commit":
    raise SystemExit("SOURCE_ORIGIN=FAIL")
try:
    source = json.loads(git("show", f"{sha}:tests/lab/source.json"))
    expected = source["origin"]
except (ValueError, TypeError, KeyError):
    raise SystemExit("SOURCE_ORIGIN=FAIL") from None
if (set(source) != {"origin"} or not isinstance(expected, str)
        or not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git", expected)
        or expected.rsplit("/", 1)[-1].removesuffix(".git") != repo_name
        or git("config", "--get", "remote.origin.url") != expected):
    raise SystemExit("SOURCE_ORIGIN=FAIL")
print("SOURCE_ORIGIN=PASS")
PYCODE
  test "$(git --git-dir="$cache" config --get remote.origin.pushurl)" = "disabled://lab-read-only"
  id -nG
  docker version --format '{{.Server.Version}}'
  sudo -n -l
  hostname -I
  ss -ltn
)
```

Supply a **previously reviewed SHA already in the trusted local cache**,
never a moving branch. The preflight compares the configured source URL to
that reviewed Git object's `tests/lab/source.json` origin without echoing either URL,
including on failure. If no reviewed SHA is cached, stop and use the private
trusted-cache bootstrap procedure before fetching. Check listener reachability
from the **selected lab host**, not from a development peer. Missing prerequisites
are not grounds for weakening isolation or escalating access.

## Stage and activate a reviewed runner separately

The current runner uses an existing bare Git cache and the exact reviewed
commit. Staging a new immutable pin **must not overwrite** the launcher;
that matters when an interrupted run is still owned by an older pin.
Only use an independently reviewed, merged 40-character SHA.

**Stage the reviewed files**, without changing `~/bin/ssh-mcp-test`:

```sh
RUNNER_SHA=FULL_REVIEWED_40_CHARACTER_COMMIT_SHA
REPO_NAME=REVIEWED_REPOSITORY_SLUG
(
  set -euo pipefail
  cache="$HOME/repos/$REPO_NAME.git"
  install="$HOME/tools/ssh-mcp-lab/$RUNNER_SHA"
  test "${#RUNNER_SHA}" -eq 40
  git --git-dir="$cache" fetch --no-tags origin refs/heads/main:refs/remotes/origin/main
  git --git-dir="$cache" merge-base --is-ancestor "$RUNNER_SHA" refs/remotes/origin/main
  test ! -e "$install"
  mkdir -p "$install"
  git --git-dir="$cache" archive "$RUNNER_SHA" tests/lab |
    tar -x -C "$install" --strip-components=2
  printf '%s\n' "$RUNNER_SHA" > "$install/PINNED_COMMIT"
  case "$RUNNER_SHA" in *[!0123456789abcdef]*|"") exit 1;; esac
  test "${#RUNNER_SHA}" -eq 40
  test ! -L "$install" && test ! -L "$install/fixture"
  test -f "$install/PINNED_COMMIT" && test ! -L "$install/PINNED_COMMIT"
  test "$(cat "$install/PINNED_COMMIT")" = "$RUNNER_SHA"
  test "$(git --git-dir="$cache" cat-file -t "$RUNNER_SHA")" = commit
  for file in runner.py source.json client.py smoke.py fixture/Dockerfile fixture/entrypoint.sh; do
    test -f "$install/$file" && test ! -L "$install/$file"
    expected=$(git --git-dir="$cache" rev-parse "$RUNNER_SHA:tests/lab/$file")
    actual=$(git hash-object --no-filters "$install/$file")
    test "$expected" = "$actual"
  done
  printf 'RUNNER_PIN=PASS\n'
  python3 "$install/runner.py" status
)
```

The shell and Git checks independently verify the approved SHA, pin marker,
and all six source/fixture blobs **before** invoking runner Python.
The runner's `status` command reports state only; it does not validate
its own pin. Stage and verify a new reviewed pin without changing the
launcher while an older run is still active.

**Activate** the new launcher only after the **current** runner reports
`ACTIVE_RUN=none`, no jobs are executing and the reviewed runner's own
absolute-path `status` check succeeds. The active-state check and atomic
launcher replacement must hold the **same lab-runner lock**, with
the independent SHA/marker/blob check repeated inside that lock:

```sh
RUNNER_SHA=FULL_REVIEWED_40_CHARACTER_COMMIT_SHA
REPO_NAME=REVIEWED_REPOSITORY_SLUG
(
  set -euo pipefail
  install="$HOME/tools/ssh-mcp-lab/$RUNNER_SHA"
  state_dir="$HOME/test-results/$REPO_NAME"
  test -d "$state_dir"
  cache="$HOME/repos/$REPO_NAME.git"
  mkdir -p "$HOME/bin"
  temp=$(mktemp "$HOME/bin/.ssh-mcp-test.XXXXXX")
  trap 'rm -f "$temp"' EXIT
  printf '#!/bin/sh\nexec python3 "%s/runner.py" "$@"\n' "$install" > "$temp"
  chmod 0755 "$temp"
  (
    flock -n 9
    test ! -e "$state_dir/.active.json"
    case "$RUNNER_SHA" in *[!0123456789abcdef]*|"") exit 1;; esac
    test "${#RUNNER_SHA}" -eq 40
    test ! -L "$install" && test ! -L "$install/fixture"
    test -f "$install/PINNED_COMMIT" && test ! -L "$install/PINNED_COMMIT"
    test "$(cat "$install/PINNED_COMMIT")" = "$RUNNER_SHA"
    test "$(git --git-dir="$cache" cat-file -t "$RUNNER_SHA")" = commit
    for file in runner.py source.json client.py smoke.py fixture/Dockerfile fixture/entrypoint.sh; do
      test -f "$install/$file" && test ! -L "$install/$file"
      expected=$(git --git-dir="$cache" rev-parse "$RUNNER_SHA:tests/lab/$file")
      actual=$(git hash-object --no-filters "$install/$file")
      test "$expected" = "$actual"
    done
    printf 'RUNNER_PIN=PASS\n'
    python3 "$install/runner.py" status
    mv -f "$temp" "$HOME/bin/ssh-mcp-test"
  ) 9>"$state_dir/.lock"
  "$HOME/bin/ssh-mcp-test" status
)
```

A busy lock or active marker means **do not repoint** the launcher.
Keep the previous pinned version available for interrupted-run cleanup
and retain the old runner/launcher until the authorized run is complete.
Record both the previous and new SHA with the acceptance evidence.

## Setup, execute and clean up

Set `ISSUE_KEY` to an approved PROJECT-N test identifier accepted by the
installed pinned runner. Older versions may accept narrower keys or legacy
environment variables; upgrade those runners separately before using shared
tests. Set `FULL_SHA` to the reviewed candidate's full commit SHA.
For an open PR provide `--pr PR_NUMBER`; omit it after merge.

```sh
ssh-mcp-test setup --story ISSUE_KEY --commit FULL_SHA --pr PR_NUMBER
ssh-mcp-test exec --run RUN_ID -- python3 /runner/smoke.py
ssh-mcp-test results --run RUN_ID
ssh-mcp-test cleanup --run RUN_ID
ssh-mcp-test status
```

Setup creates an isolated Docker network, generated SSH identity,
synthetic SSH server, nonroot MCP application, temporary SQLite volume,
and run-private credentials. It builds the candidate application image
only after validating the selected SHA. The network is internal-only,
with isolated bridge gateway mode and IPv6 disabled; setup verifies
host-service isolation using a negative TCP probe with a positive
control from the host. If the control cannot be established, setup
fails closed.

After setup, run any separately reviewed integration test repeatedly
against the same disposable filesystem and SQLite database:

```sh
ssh-mcp-test exec --run RUN_ID -- \
  python3 /source/tests/integration/patch_agent_workflow.py
ssh-mcp-test exec --run RUN_ID -- python3 /runner/smoke.py
ssh-mcp-test results --run RUN_ID
ssh-mcp-test cleanup --run RUN_ID
```

The test client is a separate nonroot container. Only the reviewed
candidate and pinned test harness are mounted read-only. Each
invocation verifies test-client termination. If the test client cannot
be removed, further execution is blocked until explicit cleanup.

For unattended use after separately approving the run:

```sh
ssh-mcp-test run --story ISSUE_KEY --commit FULL_SHA --pr PR_NUMBER
```

This performs setup, the standard OAuth/MCP/SSH smoke checks, and
ordinary cleanup (including on test failure). It does not verify
public HTTPS, browser UI behavior or production SSH authorization.

## Restricted-host and privileged fixture tests

The `fixture` alias is a nonroot synthetic SSH host. It is the **only**
target allowed in these tests; no real host names are in the inventory.
For approvals, setup accepts `--access restricted` and a temporary
Console password. Test the authenticated Grant/Deny, session expiry,
revoke and SSE workflow using the reviewed source script:

The generated LAB-only `MCP_CLIENTS` configuration permits the
`X-OpenAI-Session` conversation header for the fixture client's explicit
OAuth identity. Production continues to ignore unregistered headers and
use agent-scoped grants without an approved conversation selector.

```sh
ssh-mcp-test setup --story ISSUE_KEY --commit FULL_SHA \
  --access restricted
ssh-mcp-test exec --run RUN_ID -- \
  python3 /source/tests/integration/approval_access.py
ssh-mcp-test cleanup --run RUN_ID
```

Do not run the normal smoke suite on the restricted fixture: its
requests deliberately do not carry operator approval.

Privileged SSH tests require a **separately reviewed and installed**
runner revision supporting `--privileged-access`. Test its modes
**one at a time**, cleaning each run before starting the next:

| SSH access | Privileged access | Reviewed test |
| --- | --- | --- |
| `always-granted` | `none` | `privileged_access.py --mode none` |
| `always-granted` | `always-granted` | `privileged_access.py --mode auto` |
| `always-granted` | `restricted` | `privileged_access.py --mode sudo-only` |
| `restricted` | `restricted` | `privileged_access.py --mode combined` |

Use the corresponding `--access` and `--privileged-access` flags at
setup, then invoke the appropriate reviewed test:

```sh
ssh-mcp-test setup --story ISSUE_KEY --commit FULL_SHA \
  --access SSH_ACCESS --privileged-access PRIVILEGED_ACCESS
ssh-mcp-test exec --run RUN_ID -- \
  python3 /source/tests/integration/privileged_access.py --mode TEST_MODE
ssh-mcp-test results --run RUN_ID
ssh-mcp-test cleanup --run RUN_ID
```


The fixture requires password-protected sudo; the random per-run sudo
secret is kept in a read-only private file, not printed in arguments,
inventory, logs or environment. Direct root login and SSH password
authentication remain disabled. Default privileged access is `none`.

## Interrupted runs and cleanup reconciliation

```sh
ssh-mcp-test status
ssh-mcp-test status --run RUN_ID
ssh-mcp-test results --story ISSUE_KEY
ssh-mcp-test results --run RUN_ID
ssh-mcp-test cleanup --run RUN_ID
```

The runner allows only one active run, retains sanitized stage
results under `~/test-results/REPO_NAME/ISSUE_KEY/RUN_ID/`, and
uses run-ownership labels to delete **only** its own test containers,
volumes, network and generated credentials. Ordinary cleanup is
idempotent. It preserves source caches, built images, source worktrees
and review evidence; never use global Docker prune to substitute for
run-specific cleanup.

Cleanup intentionally fails if an unrelated container from the
original host snapshot disappeared. Do not rewrite the snapshot,
manually delete the active marker, or restart unrelated services.
See the explicit **staging-only** reconciliation procedure below;
never repoint an active launcher as a recovery shortcut.

### Reconcile cleanup blocked by unrelated host-container loss

A fresh **reviewed and merged** runner pin may include the explicit
`reconcile-cleanup` operation even when the old launcher still owns an
incomplete run. **Stage** that new pin using the procedure above, but
do **not activate it** while the active marker exists. Verify that the
run-owned resources and generated secrets are truly absent and identify
the exact names of unrelated containers that disappeared from the
preserved original snapshot; preserve the audit trail.

Only then, after independent review and approval, **repeat the
independent SHA/marker/five-blob verification above** for this exact
staged pin before invoking it. Use the pinned runner **directly by its
absolute path**, without changing the launcher:

```sh
PIN="$HOME/tools/ssh-mcp-lab/FULL_REVIEWED_40_CHARACTER_COMMIT_SHA"
python3 "$PIN/runner.py" reconcile-cleanup --run RUN_ID --expect-missing-originals NAME1,NAME2
```

The pinned runner's `status` alone is not proof of integrity; confirm
the independent verification result before running reconciliation.
Successful reconciliation records `cleaned_with_missing_originals`
as a warning, never a clean PASS. It does not remove unrelated host
containers or alter the original snapshot. When the old launcher reports
`ACTIVE_RUN=none` afterward, use the separately locked activation
procedure to select the new pin. Preserve the previous pin for rollback.

## Maintainer verification

Before lab acceptance, run offline source checks on an approved
development host:

```sh
python3 -m unittest tests.unit.test_lab_runner -v
python3 -m py_compile tests/lab/runner.py tests/lab/client.py tests/lab/smoke.py
```

Record the reviewed candidate commit, installed runner pin, run IDs,
negative isolation result, smoke/integration outcomes and cleanup
status. Test actual HTTPS/OAuth with an external client separately
under an explicitly approved nonproduction setup.
