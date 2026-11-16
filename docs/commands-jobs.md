# SSH commands, jobs and batches

Every SSH operation uses `ssh.execute` OAuth scope, a configured
operator principal, an approved host alias and pinned SSH identity/key.
If the host requires approval, an operator grants it **before** the
SSH operation begins. All commands require durable auditing; there is
no unaudited execution fallback.

## Single synchronous commands

`execute_command` accepts `server` (approved alias), an argv array,
required non-sensitive `reason`, optional `story_id`, timeout,
optional absolute `cwd` and explicit `strict_bash`/`privileged` flags.
The optional story ID is a string of up to 80 characters, not a Jira-only
number. Common tracker values such as SKY-308, #123, 12345 and
owner/repo#123 are accepted; whitespace and control characters are not.
IDs are retained verbatim in audit storage; only their table display can
be shortened through the Console configuration.

Prefer direct argv for one executable:

~~~yaml
execute_command:
  server: demo
  argv: ["id", "-u"]
  reason: Confirm the dedicated SSH account identity
  story_id: TASK-123
~~~

The required `reason` is audit metadata, not a shell comment. Do not
embed passwords, tokens or secret values in argv/reason/output.
Do not add an unnecessary shell just to run `cd`, `echo`, or
`set -euo pipefail`. Use an absolute `cwd` when needed; the server
performs a separate preflight and records the effective directory
only when verified.

`strict_bash=true` injects Bash fail-fast behavior only for
`bash -c` or `bash -lc` scripts; it does not affect ordinary argv
or `sh`. A nonzero exit can be explicitly accepted with
`success_exit_codes`; default is `[0]`. Always inspect
`status`, `exit_code` and `exit_accepted`, not just a transport
tool wrapper's success flag. Process exit 255 can be a genuine remote
exit; native SSH channel completion and output delivery decide
whether the outcome is an ordinary command error or a transport issue.

## Async execution and durable results

`submit_job` returns a durable ID without waiting for completion.
`get_job` polls status and exit code; `get_job_output` pages through
bounded stdout and stderr using returned cursors. `list_jobs` and
`get_job_stats` search retained jobs. `get_status` reports
service/job health; `list_servers` returns aliases the OAuth operator
is authorized to see.

An immediate synchronous `execute_command` result may use
`status=command_error` for an unaccepted remote exit, but
the durable `get_job`/`list_jobs` status is `failed`, with
`exit_code` and `failure_kind` separately recorded.
Durable states include queued, running, succeeded, failed,
`transport_error`, `timed_out`, `output_limit`,
interrupted, cancelled and uncertain/partial results.

A **known CWD preflight refusal** (missing/inaccessible path)
is a definite pre-execution denial: synchronous response
`status=rejected`, `failure_kind=pre_execution_rejected`,
no caller exit code; matching durable audit
`status=failed` / `failure_kind=pre_execution_rejected`.
It is distinct from a broken SSH channel with uncertain
execution. A disconnected client
may not know whether execution happened; **recover by ID** and
inspect actual host state before retrying any mutation.
Logs/audit can contain original command arguments and bounded output;
protect access to the database.

## Sequential batches

`execute_commands` executes **one to five ordered steps** on one
approved server with a shared `cwd`, `reason` and bounds.
`stop_on_error` defaults to true. Steps are separate remote processes:
shell exports and `cd` do not persist between them. The batch gets
durable parent/step IDs; each step has a separately recorded result.

`get_batch` and `list_batches` recover state after disconnect/restart.
`cancel_batch` requests stop; already-running steps can have uncertain
side effects and future steps may not run. A batch is **not**
a transaction and does not roll back previously completed steps.
Batch results and total output are bounded; paginate rather than
requesting unbounded history.

## Cancellation and privileged execution

`cancel_job` requests stopping a queued/running actor-owned job.
Cancellation cannot undo side effects of an already running
command or a detached remote process. The Console has a separate
authenticated cancellation action for eligible job/batch rows;
see [Operator Console](operator-console.md).

`privileged=true` is optional and must be separately permitted
by inventory `privileged_access` and a protected per-host sudo
credential. It requires scoped operator approval when restricted;
the server verifies that root actually started. Do not infer root
success from the request flag or from an unconfirmed frame.
The [Security](security.md) guide covers the trust boundary.

## Retry safety checklist

1. Record the returned job/batch/operation ID and authoritative state.
2. For disconnect/timeout, query stored results and inspect the
   target before deciding whether to retry.
3. Never equate missing output with a command that did not run.
4. Use a new ID only when the earlier state has been reconciled.
5. Use a separate, explicit authorization for sensitive environments.

The server does not automatically retry interrupted SSH mutations.
