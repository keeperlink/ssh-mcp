# Explicit SSH-MCP integration tests

These feature-oriented entrypoints execute **outside** offline unit discovery. Use the independently pinned disposable lab runner in [../lab/README.md](../lab/README.md), never a runner from an unreviewed PR checkout. The runner mounts candidate source read-only at /source and the trusted client at /runner, with isolated SSH/OAuth services and no published host ports.

| Entrypoint | Unique end-to-end scope |
| --- | --- |
| transfer_file_acceptance.py | Two isolated synthetic SSH hosts, binary integrity, atomic copy/overwrite, fail-closed authorization, async cancellation, metadata-only audit and opt-in root endpoints |
| command_execution.py | Real SSH argv, strict Bash, working directories, exits and authorization |
| command_batches.py | Durable ordered steps, known failures, limits, recovery and audit |
| patch_conflicts.py | Patch diagnostics, original line positions and secret redaction |
| patch_preview.py | Nonmutating preview, diff safety and hash preconditions |
| patch_atomicity.py | Atomic preflight, collisions, no-op, move and partial recovery |
| patch_agent_workflow.py | Full source/test/docs preview, reconciliation and apply over SSH |
| approval_access.py | Live SSE + browser approvals gating real SSH, expiry and revocation |
| privileged_access.py | Real sudo in four host/root policy combinations with durable audit |
| sealed_v2_acceptance.py | LAB-only sealed-v2 OAuth/Console/metrics, Locked readiness, scoped sudo grants and revocation on synthetic credentials |
| browser_layout_check.py | Native headless Chrome check using synthetic local API in CI |
| run_openssh_interop.sh | Separately authorized rootless Docker/OpenSSH interoperability |

_approval_client.py is an **undiscoverable shared integration helper**, not an executable test suite. The trusted lab orchestrator, OAuth client and SSH fixture remain at tests/lab because their installed immutable runner pin must not change implicitly. Synthetic browser data lives in tests/fixtures/browser_layout_fixture.js.

## Example isolated lab run

After approving a specific reviewed full commit SHA, set APPROVED_STORY_KEY to
a valid approved identifier accepted by the separately installed runner.
Invoke that pinned runner on the approved lab. Replace FULL_REVIEWED_COMMIT_SHA
and RUN_ID with the reviewed commit and setup result:

~~~
ssh-mcp-test setup --story "$APPROVED_STORY_KEY" --commit FULL_REVIEWED_COMMIT_SHA
ssh-mcp-test exec --run RUN_ID -- python3 /source/tests/integration/command_execution.py
ssh-mcp-test exec --run RUN_ID -- python3 /source/tests/integration/command_batches.py
ssh-mcp-test exec --run RUN_ID -- python3 /source/tests/integration/patch_preview.py
ssh-mcp-test exec --run RUN_ID -- python3 /source/tests/integration/patch_atomicity.py
ssh-mcp-test exec --run RUN_ID -- python3 /source/tests/integration/patch_conflicts.py
ssh-mcp-test exec --run RUN_ID -- python3 /source/tests/integration/patch_agent_workflow.py
ssh-mcp-test cleanup --run RUN_ID
~~~

For restricted approval coverage, set up a separate run with --access restricted and execute approval_access.py. For root access, use the four host/root policy pairs in the [lab runbook](../lab/README.md), invoking privileged_access.py --mode none, auto, sudo-only or combined. The selected mode must match the policy chosen during setup.

For native OpenSSH acceptance, operator approval for rootless Docker is required separately:

~~~
bash tests/integration/run_openssh_interop.sh
~~~

The native browser fixture runs in GitHub-hosted CI (not in the SSH lab runner):

~~~
python tests/integration/browser_layout_check.py
~~~

Never move these entrypoints into unit/ or contracts/ or give them test_*.py names; that would risk executing Docker/SSH work during unprivileged installed-wheel validation.
