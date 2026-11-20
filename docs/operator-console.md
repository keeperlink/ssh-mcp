# Operator Console

Open `https://YOUR_DOMAIN/console`. This is a password-protected
browser interface, **separate from MCP OAuth**. It shows retained
job/batch/file history, pending restricted-access decisions and
active timed host/root grants. It cannot submit new SSH commands.

The browser title is `SSH-MCP · Operator Console · LAB/PROD`. The
header shows environment/version, connection status, grant chips
and sign-out. A hidden accessible heading replaces the older visible
History label to leave room for grants.

## Session security

The Console uses its own strong password, Secure/HttpOnly/SameSite
cookies, a CSRF token, exact-origin checks and a restrictive CSP.
Default session limits are eight hours idle and 24 hours absolute,
configurable separately. A successful password change revokes old
sessions. Signing out deletes/revokes the active Console session.

The older `/history` browser route is **removed**, not redirected.
Upgrades require fresh login and reset stored browser preferences.
Sessions from the old cookie name are revoked when a legacy cookie
is presented during successful login or sign-out; never use a
browser cookie as an API bearer token.

## Browsing and diagnostics

Browse records by time window (1h, 8h, 24h, 7d, 30d or all),
host, status, story ID, conversation, command and mode. Pagination
sizes fit the viewport, and the latest change cursor permits
bounded polling. Relative/absolute time format, filters, splitter
width and panel preferences are saved **only in that browser**.
Story IDs support common tracker formats such as TEST-308, #123, 12345
and owner/repo#123. The table shortens long IDs using the signed
viewer.story_id_max_chars (default 16, including the ellipsis) and
viewer.story_id_truncate_from (end keeps the beginning, start keeps
the ending). The complete ID is available on hover and in record details;
stored values and history filters are never truncated. These viewer keys
are optional in existing signed configurations for upgrade compatibility.

Details expose request/result, sanitized failure classification,
command output pagination, relevant root-start evidence, and
recorded batch/step outcome. File-operation details omit file
contents, patch body and signed attachment URL.

## Restricted-access decisions

A host with `access: "restricted"`, or permitted root with
`privileged_access: "restricted"`, can pause an MCP call until an
operator grants/denies its unchanged request. Approvals are bound
to the authenticated client session, conversation, host and
permission kind. The Console presents requested host, reason,
tool, paths/commands and remaining deadline; it does not rewrite
the request. A pending decision expires (normally within 30s)
without automatically executing SSH.

"One request" is the default grant. Explicit temporary choices
include 5m, 15m, 1h, 8h and 16h. Active grants appear near
`Connected` and can be revoked; revocation blocks **future**
operations, not ones already running. Operator audio/desktop
notifications are opt-in and need an open browser tab; hidden-tab
approval updates use authenticated SSE. New approvals use a distinctive
500 ms sonar alert with a bounded peak amplitude and no overlapping
playback. The existing sound toggle and browser autoplay restrictions
still apply.

## Eligible cancellation

Queued/running command rows may show an accessible × inside
their status pill. Clicking it sends one authenticated, CSRF- and
Origin-checked request. The server verifies the operator's
approved actor/host and durable state before recording acceptance.
A batch child maps to its parent cancellation target. The UI may
say `Cancelling…`, but this is **not** a terminal result or proof
of rollback. File and completed rows cannot be cancelled through
this browser control.

Cancellation provenance records whether the request came from
the Console or MCP, with a timestamp and bounded reason.
See [Commands and jobs](commands-jobs.md) and
[Security](security.md).
