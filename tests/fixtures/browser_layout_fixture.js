/* Browser acceptance against the shipped viewer JS/CSS and a LOCAL synthetic
   metadata-only API. No OAuth credentials, SSH transport or real file bodies. */
"use strict";
(async () => {
  const out = document.getElementById("layout-test-result");
  const profile = new URLSearchParams(location.search).get("layout") || "narrow";
  const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  async function waitFor(predicate, label) {
    for (let tries = 0; tries < 170; tries++) {
      if (predicate()) return;
      await pause(35);
    }
    throw new Error("Timed out: " + label);
  }
  function assert(condition, message) {
    if (!condition) throw new Error(message);
  }
  function assertVisibleControls() {
    const pane = document.getElementById("left-pane").getBoundingClientRect();
    const footer = document.querySelector(".page-footer").getBoundingClientRect();
    const nav = document.getElementById("pagination");
    const navRect = nav.getBoundingClientRect();
    const rows = document.getElementById("rows-per-page").getBoundingClientRect();
    const summary = document.getElementById("page-summary").getBoundingClientRect();
    const filters = document.getElementById("filters");
    const labels = [...filters.querySelectorAll(":scope > label")];
    assert(labels.length === 7, "Expected seven History filter controls");
    const positions = labels.map((label) => label.getBoundingClientRect());
    assert(positions.every((rect) => Math.abs(rect.top - positions[0].top) <= 2),
      "History filters must stay on one row without wrapping Mode/Status");
    assert(positions.every((rect, i) => i === 0 || rect.left > positions[i - 1].left),
      "History filters must retain their original left-to-right order");
    if (filters.scrollWidth > filters.clientWidth + 2) {
      filters.scrollLeft = filters.scrollWidth;
      const last = labels.at(-1).getBoundingClientRect();
      const bounds = filters.getBoundingClientRect();
      assert(last.right <= bounds.right + 2,
        "Last History filter is clipped instead of horizontally scrollable");
      filters.scrollLeft = 0;
    }
    if (profile === "narrow") {
      assert(pane.width >= 320 && pane.width <= 380,
        "Requires 330px narrow pane, actual " + pane.width);
      assert(getComputedStyle(document.querySelector(".page-footer")).display === "grid",
        "Compact footer did not switch to pane-relative grid");
    } else {
      assert(pane.width > 610, "Desktop must exceed 610px compact breakpoint: " + pane.width);
    }
    assert(navRect.left >= pane.left && navRect.right <= pane.right + 1,
      "Pager container clipped by history pane");
    assert(nav.scrollWidth <= nav.clientWidth + 2,
      "Pager navigation requires horizontal scrolling");
    for (const button of nav.querySelectorAll("button")) {
      const rect = button.getBoundingClientRect();
      assert(rect.left >= pane.left - 1 && rect.right <= pane.right + 1,
        "Navigation button clipped: " + button.getAttribute("aria-label"));
      assert(rect.top >= footer.top - 1 && rect.bottom <= footer.bottom + 1,
        "Navigation button outside visible footer");
    }
    for (const [name, rect] of [["Rows per page", rows], ["Page count", summary]]) {
      assert(rect.left >= pane.left - 1 && rect.right <= pane.right + 1,
        name + " clipped by left history pane");
      assert(rect.top >= footer.top - 1 && rect.bottom <= footer.bottom + 1,
        name + " outside footer bounds");
    }
  }
  function verifyStoryIdTruncation() {
    const full = "owner/repo#12345678901234567890";
    const table = document.getElementById("history-table");
    const max = Number(table.dataset.storyIdMaxChars);
    const side = table.dataset.storyIdTruncateFrom;
    const expected = max === 1 ? "…" : side === "start"
      ? "…" + Array.from(full).slice(-(max - 1)).join("")
      : Array.from(full).slice(0, max - 1).join("") + "…";
    const cell = document.querySelector('#job-rows tr[data-id="synthetic-3"] td.story-id');
    assert(cell, "Long generic ID row missing");
    assert(cell.textContent === expected && cell.textContent.length === max,
      "Table did not truncate from configured side within character budget");
    assert(cell.title === full, "Table tooltip must preserve the full issue ID");
  }
  function fileDetailsAreReadOnly() {
    assert(document.getElementById("detail-title").textContent === "File operation details",
      "File operation must show file-specific detail");
    for (const id of ["copy-output", "download-output", "copy-command"]) {
      assert(!document.getElementById(id), "Removed copy/download button still exists: " + id);
    }
    for (const id of ["stdout-label", "stderr-label", "stdout", "stderr"]) {
      assert(document.getElementById(id).hidden, "File detail exposed command output: " + id);
    }
    assert(!document.getElementById("file-output-note").hidden,
      "File detail needs metadata-only explanation");
    assert(!document.querySelector('input[type="file"]'),
      "Viewer must not offer a browser file upload");
    assert(!document.querySelector('textarea'),
      "Viewer must not offer a file or command editor");
    assert(!document.getElementById("request-properties").textContent.includes("FILE_BODY_SECRET"),
      "File body leaked into viewer details");
  }
  async function checkMixedHistoryAndKeyboard() {
    const first = document.querySelector('#job-rows tr[data-id="file-sky238-upload"]');
    assert(first && first.textContent.includes("File"), "Upload file row missing");
    assert(document.querySelector('#job-rows tr[data-id="synthetic-3"]'),
      "Command row missing from mixed command/file page");
    await waitFor(() => document.getElementById("detail").dataset.jobId ===
      "file-sky238-upload", "automatic file detail selection");
    fileDetailsAreReadOnly();
    const info = document.getElementById("job-info-panel");
    const tech = document.getElementById("technical-details");
    assert(info.open && !tech.open, "Job info should default open; technical details closed");
    assert(!document.getElementById("copy-job-id")
      && !document.getElementById("detail-sub")
      && !document.getElementById("detail-footer"),
    "Job ID should no longer appear in the heading, footer or copy button");
    assert(tech.textContent.includes("Operation ID")
      && tech.textContent.includes("file-sky238-upload"),
      "File operation ID must appear inside Technical details");
    const reqToggle = document.getElementById("request-format-toggle");
    const rspToggle = document.getElementById("response-format-toggle");
    assert(reqToggle.textContent === "⇄" && rspToggle.textContent === "⇄",
      "JSON toggles should use the same arrows as the time column");
    for (const button of [reqToggle, rspToggle]) {
      const heading = button.previousElementSibling;
      assert(heading.tagName === "H3" && heading.parentElement === button.parentElement,
        "JSON toggle must sit directly after its section heading");
      const left = button.getBoundingClientRect().left;
      const right = heading.getBoundingClientRect().right;
      assert(left >= right && left - right < 18,
        "JSON arrow should appear beside its heading, not at the far right");
      assert(getComputedStyle(button).borderTopStyle === "none",
        "JSON arrow must be an unboxed inline control");
    }
    reqToggle.click(); rspToggle.click();
    assert(document.getElementById("request-readable").hidden
      && document.getElementById("response-readable").hidden,
      "JSON mode must hide human-readable request and response");
    const fileReq = JSON.parse(document.getElementById("request-json").textContent);
    const fileRes = JSON.parse(document.getElementById("response-json").textContent);
    assert(fileReq.note === "File request payload not retained"
      && fileRes.file_metadata.transfer.direction === "upload",
      "File JSON must use metadata only, never invent original payload");
    assert(!document.getElementById("detail").textContent.includes("FILE_BODY_SECRET"),
      "File JSON mode leaked file body");
    reqToggle.click(); rspToggle.click();
    assert(!document.getElementById("request-readable").hidden
      && !document.getElementById("response-readable").hidden,
      "Arrows must switch back to readable request and response");
    info.open = false;
    tech.open = true;
    await waitFor(() => localStorage.getItem("ssh-mcp-console-job-info-open") === "false"
      && localStorage.getItem("ssh-mcp-console-technical-open") === "true",
      "Both disclosure states must persist in browser storage");
    const details = document.getElementById("request-properties").textContent;
    for (const field of ["Operation", "Path summary", "Bytes", "Direction",
                         "Transfer mode", "Total file bytes", "File SHA-256"]) {
      assert(details.includes(field), "Transfer detail missing " + field);
    }
    const cell = document.querySelector(
      '#job-rows tr[data-id="file-sky238-patch"] .command-cell');
    assert(cell && cell.tabIndex === 0 && cell.getAttribute("aria-label"),
      "Patch cell lacks keyboard focus or accessible label");
    cell.focus();
    assert(document.activeElement === cell, "File operation cell did not receive focus");
    cell.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    await waitFor(() => document.getElementById("detail").dataset.jobId ===
      "file-sky238-patch", "Enter opens patch detail");
    fileDetailsAreReadOnly();
    assert(!info.open && tech.open,
      "Changing jobs must preserve both independently remembered disclosure states");
    info.open = true; tech.open = false;
    await waitFor(() => localStorage.getItem("ssh-mcp-console-job-info-open") === "true"
      && localStorage.getItem("ssh-mcp-console-technical-open") === "false",
      "Restored disclosure states must be saved");
    const patch = document.getElementById("request-properties").textContent;
    assert(patch.includes("File result") && patch.includes("not_attempted")
      && patch.includes("not_found"), "Partial per-path patch results missing");
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    assert(document.getElementById("command-tooltip").hidden,
      "Escape did not hide operation tooltip");
    const splitter = document.getElementById("splitter");
    assert(splitter.getAttribute("role") === "separator",
      "Splitter needs accessible separator role");
    const root = document.documentElement;
    const before = parseFloat(getComputedStyle(root).getPropertyValue("--left-width"));
    splitter.dispatchEvent(new KeyboardEvent("keydown", {
      key: "ArrowRight", bubbles: true, cancelable: true
    }));
    const after = parseFloat(getComputedStyle(root).getPropertyValue("--left-width"));
    assert(after > before, "Keyboard splitter did not move right");
    assert(Number(localStorage.getItem("ssh-mcp-console-split")) === after,
      "Keyboard splitter setting did not persist");
    await pause(120);
  }
  async function checkUnicodeStoryFilters() {
    const story = document.getElementById("filters").elements.namedItem("story_id");
    for (const [value, jobId] of [["KA-123", "synthetic-240"],
                                 ["KA-123", "synthetic-241"],
                                 ["ka-123", "synthetic-241"]]) {
      story.value = value;
      story.dispatchEvent(new Event("input", { bubbles: true }));
      await waitFor(() => document.getElementById("page-summary").textContent ===
        "Showing 1–1 of 1" && document.querySelectorAll("#job-rows tr").length === 1
        && document.querySelector('#job-rows tr[data-id="' + jobId + '"]'),
      "Unicode/ASCII issue ID filter unexpectedly folded " + value);
    }
    // Preserve the typed whitespace for editing but send a trimmed generic ID
    // to the API. A mismatched live filter caused each poll to reload the list.
    const padded = "  owner/repo#12345678901234567890  ";
    story.value = padded;
    story.dispatchEvent(new Event("input", { bubbles: true }));
    await waitFor(() => document.getElementById("page-summary").textContent ===
      "Showing 1–1 of 1" && document.querySelectorAll("#job-rows tr").length === 1
      && document.querySelector('#job-rows tr[data-id="synthetic-3"]'),
    "padded generic issue ID filter");
    assert(story.value === padded && JSON.parse(
      localStorage.getItem("ssh-mcp-console-filters")).story_id === padded,
    "The entered generic issue ID must remain verbatim in the form and preferences");
    const originalFetch = window.fetch;
    let reloaded = 0;
    window.fetch = (...args) => {
      if (String(args[0]).startsWith("/console/api/jobs?")) reloaded++;
      return originalFetch(...args);
    };
    try {
      await pause(2200);
      assert(reloaded === 0, "Untrimmed live filter is reloading History every poll");
    } finally {
      window.fetch = originalFetch;
    }
    story.value = "";
    story.dispatchEvent(new Event("input", { bubbles: true }));
    await waitFor(() => document.getElementById("page-summary").textContent
      .includes("of 250"), "clear Unicode issue ID filter");
  }
  async function checkFiltersAndLiveRefresh() {
    const form = document.getElementById("filters");
    const mode = form.elements.namedItem("mode");
    const story = form.elements.namedItem("story_id");
    const status = form.elements.namedItem("status");
    const host = form.elements.namedItem("host");
    mode.value = "file";
    mode.dispatchEvent(new Event("change", { bubbles: true }));
    await waitFor(() => document.getElementById("page-summary").textContent ===
      "Showing 1–3 of 3", "file-only filter");
    assert(document.querySelectorAll("#job-rows tr").length === 3,
      "File-only filter included command row");
    story.value = "238";
    story.dispatchEvent(new Event("input", { bubbles: true }));
    await waitFor(() => document.getElementById("page-summary").textContent ===
      "Showing 1–3 of 3", "numeric story filter");
    host.value = "demo-node-a";
    host.dispatchEvent(new Event("change", { bubbles: true }));
    await waitFor(() => document.getElementById("page-summary").textContent ===
      "Showing 0–0 of 0", "host filter empty state");
    assert(!document.getElementById("empty").hidden, "Empty filtered state hidden");
    host.value = "demo-node-b";
    host.dispatchEvent(new Event("change", { bubbles: true }));
    await waitFor(() => document.getElementById("page-summary").textContent ===
      "Showing 1–3 of 3", "host filtered file rows");
    status.value = "partial";
    status.dispatchEvent(new Event("change", { bubbles: true }));
    await waitFor(() => document.getElementById("page-summary").textContent ===
      "Showing 1–1 of 1", "partial status file filter");
    assert(document.querySelector('#job-rows tr[data-id="file-sky238-patch"]'),
      "Partial patch missing from status filter");
    status.value = "";
    status.dispatchEvent(new Event("change", { bubbles: true }));
    await waitFor(() => document.getElementById("page-summary").textContent ===
      "Showing 1–3 of 3", "clear status filter");
    story.value = "999999";
    story.dispatchEvent(new Event("input", { bubbles: true }));
    await waitFor(() => document.getElementById("page-summary").textContent ===
      "Showing 0–0 of 0", "nonexistent story empty state");
    story.value = "238";
    story.dispatchEvent(new Event("input", { bubbles: true }));
    await waitFor(() => document.getElementById("page-summary").textContent ===
      "Showing 1–3 of 3", "restore story filter");
    await fetch("/console/api/test-publish", { cache: "no-store" });
    await waitFor(() => document.querySelector('#job-rows tr[data-id="file-sky238-live"]')
      && document.getElementById("page-summary").textContent ===
         "Showing 1–4 of 4", "polling picks up synthetic new file record");
    assert(document.getElementById("new-jobs").hidden,
      "Active first page should refresh rather than leave a stale banner");
    assertVisibleControls();
  }
  async function checkConversationClickAndClear() {
    // Test the command-specific Timeout/Arguments/Method fields on a
    // command job, not on the file record left selected by the prior test.
    const commandRow = document.querySelector('#job-rows tr[data-id="synthetic-3"]');
    assert(commandRow, "Synthetic command row needed for metadata/JSON acceptance");
    commandRow.click();
    await waitFor(() => document.getElementById("detail").dataset.jobId === "synthetic-3",
      "command job selected for conversation and JSON checks");
    const technical = document.getElementById("technical-metadata").textContent;
    assert(technical.includes("Job ID") && technical.includes("synthetic-3"),
      "Command Job ID must appear only in technical metadata");
    const form = document.getElementById("filters");
    const input = form.elements.namedItem("conversation_id");
    const clear = document.getElementById("clear-conversation");
    const button = document.querySelector("#detail-meta .meta-conversation");
    const meta = document.getElementById("detail-meta").textContent;
    for (const field of ["Status", "Host", "Story ID", "Timeout", "Arguments", "Method"]) {
      assert(meta.includes(field), "Job info panel missing metadata: " + field);
    }
    assert(!document.getElementById("request-properties").textContent.includes("Reason"),
      "Reason must not appear in the request properties grid");
    assert(document.getElementById("detail-reason-value").textContent.includes("Synthetic layout test"),
      "Reason should display in its own full-width area before Request");
    const req = document.getElementById("request-format-toggle");
    const rsp = document.getElementById("response-format-toggle");
    req.click(); rsp.click();
    assert(JSON.parse(document.getElementById("request-json").textContent).reason
      === "Synthetic layout test", "Request JSON must show stored original request");
    const response = JSON.parse(document.getElementById("response-json").textContent);
    assert(response.server === "demo-node-a" && response.status === "succeeded"
      && Object.hasOwn(response, "stdout") && Object.hasOwn(response, "stderr"),
      "Response JSON must contain recorded status and captured output fields");
    await waitFor(() => {
      const loaded = JSON.parse(document.getElementById("response-json").textContent);
      return loaded.output_fully_loaded && loaded.stdout.endsWith("END_OF_CAPTURE");
    }, "all output pages loaded beyond former twelve-page cap");
    const complete = JSON.parse(document.getElementById("response-json").textContent);
    assert(complete.stdout.length === 13 * 16384 + "END_OF_CAPTURE".length
      && complete.output_load_error === null,
      "Response JSON must expose complete multi-page capture without silent truncation");
    req.click(); rsp.click();
    const fullId = "v1/2TCYJpYfTRn20j4gmoj" + "q9w3e8r7t6y5u4i3o2p1";
    assert(button && button.tagName === "BUTTON" && button.type === "button",
      "Conversation ID in job details should be a keyboard-focusable button");
    assert(button.title === fullId && button.textContent.endsWith("…")
      && button.textContent.length <= 25 && !button.textContent.includes("q9w3"),
    "Conversation detail must show one-line abbreviated ID with full tooltip");
    assert(getComputedStyle(button).whiteSpace === "nowrap",
      "Conversation detail ID must never wrap to a second line");
    button.focus();
    assert(document.activeElement === button, "Conversation button must be focusable");
    await fetch("/console/api/test-touch", { cache: "no-store" });
    await waitFor(() => document.getElementById("detail-meta").textContent.includes("Running"),
      "selected job updated by live polling");
    assert(document.activeElement === document.querySelector("#detail-meta .meta-conversation"),
      "Live detail refresh must preserve keyboard focus on the conversation button");
    document.querySelector("#detail-meta .meta-conversation").click();
    await waitFor(() => document.getElementById("page-summary").textContent ===
      "Showing 1–2 of 2", "clicking job conversation filters history");
    assert(input.value === fullId && !clear.hidden && document.activeElement === input,
      "Conversation click must populate exact ID and show focused clear control");
    assert(document.querySelectorAll("#job-rows tr").length === 2,
      "Clicking conversation must not use the truncated display value as filter");
    clear.click();
    await waitFor(() => document.getElementById("page-summary").textContent.includes("of 250"),
      "clearing conversation ID restores history");
    assert(input.value === "" && clear.hidden && document.activeElement === input,
      "Conversation x must clear and reapply filter");
    input.value = fullId;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await waitFor(() => !clear.hidden &&
      document.getElementById("page-summary").textContent === "Showing 1–2 of 2",
    "manually entering conversation ID filters immediately");
    clear.click();
    await waitFor(() => document.getElementById("page-summary").textContent.includes("of 250"),
      "second conversation clear restores unfiltered history");
  }
  async function checkDetailIsolationAndErrors() {
    // Intercept only the synthetic detail endpoints; the shipped viewer stays
    // in control of selection and its normal loading/error rendering.
    const originalFetch = window.fetch;
    let release;
    window.fetch = (url, options) => {
      const path = String(url);
      if (path.endsWith("/console/api/jobs/synthetic-4"))
        return new Promise((resolve) => {
          release = () => resolve(originalFetch(url, options));
        });
      if (path.endsWith("/console/api/jobs/synthetic-5"))
        return Promise.resolve(new Response("Synthetic detail fetch failure", { status: 503 }));
      return originalFetch(url, options);
    };
    try {
      const request = document.getElementById("request-format-toggle");
      const response = document.getElementById("response-format-toggle");
      request.click(); response.click();
      assert(document.getElementById("response-json").textContent.includes("END_OF_CAPTURE"),
        "Prior JSON capture must exist to test stale-data isolation");
      document.querySelector('#job-rows tr[data-id="synthetic-4"]').click();
      await waitFor(() => Boolean(release), "delayed synthetic detail request");
      assert(document.getElementById("detail").hidden
        && document.getElementById("detail-empty").textContent.includes("Loading job details")
        && document.getElementById("request-json").textContent === ""
        && document.getElementById("response-json").textContent === "",
      "Changing jobs must immediately hide and clear previous job JSON");
      release(); release = null;
      await waitFor(() => document.getElementById("detail").dataset.jobId === "synthetic-4",
        "delayed detail fetch completed");
      document.querySelector('#job-rows tr[data-id="synthetic-5"]').click();
      await waitFor(() => document.getElementById("detail-empty").textContent
        .includes("Unable to load job details"), "failed detail fetch explains retry");
      assert(document.getElementById("detail").hidden
        && document.getElementById("request-json").textContent === ""
        && document.getElementById("response-json").textContent === "",
      "Failed detail fetch must never show the previous job's metadata or JSON");
    } finally {
      if (release) release();
      window.fetch = originalFetch;
    }
  }
  async function checkCompletionDuringOutputFetch() {
    // Hold an older running-job output snapshot while the normal History poll
    // observes the final job detail and its larger recorded output_bytes.
    const originalFetch = window.fetch;
    let releaseOldSnapshot;
    let intercepted = false;
    window.fetch = (url, options) => {
      if (!intercepted && String(url).includes("/console/api/jobs/synthetic-6/output?")) {
        intercepted = true;
        return new Promise((resolve) => {
          releaseOldSnapshot = () => resolve(new Response(JSON.stringify({
            chunks: [], next_cursor: 0, truncated: false,
          }), { status: 200, headers: { "Content-Type": "application/json" } }));
        });
      }
      return originalFetch(url, options);
    };
    try {
      await originalFetch("/console/api/test-overlap-start", { cache: "no-store" });
      document.querySelector('#job-rows tr[data-id="synthetic-6"]').click();
      await waitFor(() => releaseOldSnapshot
        && document.getElementById("detail").dataset.jobId === "synthetic-6",
      "running job output fetch intercepted");
      if (document.getElementById("response-json").hidden)
        document.getElementById("response-format-toggle").click();
      await originalFetch("/console/api/test-overlap-complete", { cache: "no-store" });
      await waitFor(() => document.getElementById("detail-meta").textContent
        .includes("Succeeded"), "terminal job refreshed while earlier output is pending");
      const before = JSON.parse(document.getElementById("response-json").textContent);
      assert(before.output_fully_loaded === false && before.stdout === "",
        "Terminal status must not claim the delayed running snapshot is complete");
      releaseOldSnapshot();
      releaseOldSnapshot = null;
      await waitFor(() => {
        const final = JSON.parse(document.getElementById("response-json").textContent);
        return final.stdout === "OUTPUT_AFTER_COMPLETION"
          && final.output_fully_loaded === true;
      }, "final output reloaded after stale response without another terminal event");
      assert(JSON.parse(document.getElementById("response-json").textContent)
        .output_load_error === null, "Completed output should not report a load error");
    } finally {
      if (releaseOldSnapshot) releaseOldSnapshot();
      window.fetch = originalFetch;
    }
  }
  async function checkPrivilegedHistory() {
    const form = document.getElementById("filters");
    const toggle = document.getElementById("privileged-filter");
    const command = form.elements.namedItem("command");
    assert(toggle?.type === "button" && toggle.getAttribute("aria-pressed") === "false"
      && toggle.querySelector("svg") && toggle.nextElementSibling === command,
    "Accessible shield toggle must precede Command search in the existing filter row");
    for (const name of ["story_id", "host", "conversation_id", "command", "mode", "status"])
      form.elements.namedItem(name).value = "";
    form.elements.namedItem("time_range").value = "all";
    form.elements.namedItem("mode").dispatchEvent(new Event("change", { bubbles: true }));
    await waitFor(() => document.getElementById("page-summary").textContent.includes("of 251"),
      "Reset all ordinary History filters before testing privileged-only mode");
    toggle.focus();
    assert(document.activeElement === toggle, "Privileged filter must be keyboard-focusable");
    toggle.click();
    await waitFor(() => document.getElementById("page-summary").textContent ===
      "Showing 1–3 of 3", "Privileged-only filter must use persisted execution metadata");
    assert(toggle.getAttribute("aria-pressed") === "true"
      && toggle.classList.contains("is-active"), "Enabled shield must be visibly red");
    assert(JSON.parse(localStorage.getItem("ssh-mcp-console-filters")).privileged === "true",
      "Privileged-only filter setting must be remembered");
    assert([...document.querySelectorAll("#job-rows tr[data-id]")].every((row) =>
      row.querySelector(".command-cell .root-shield")),
    "Privileged-only History page must show root shields on every result");
    assert(!document.querySelector('#job-rows tr[data-id="synthetic-3"]')
      && !document.querySelector('#job-rows tr[data-id="file-sky238-upload"]'),
    "Ordinary commands and file records must not pass root-only filter");
    command.value = "synthetic-5";
    command.dispatchEvent(new Event("input", { bubbles: true }));
    await waitFor(() => document.getElementById("page-summary").textContent ===
      "Showing 1–1 of 1", "Root-only filter must combine with Command search");
    assert(document.querySelector('#job-rows tr[data-id="synthetic-5"]'),
      "Confirmed privileged record missing after combined filtering");
    command.value = "";
    command.dispatchEvent(new Event("input", { bubbles: true }));
    await waitFor(() => document.getElementById("page-summary").textContent ===
      "Showing 1–3 of 3", "Clearing Command must retain root-only filter");
    document.querySelector('#job-rows tr[data-id="synthetic-5"]').click();
    await waitFor(() => document.getElementById("detail").dataset.jobId === "synthetic-5",
      "Confirm selected root job details");
    assert(document.getElementById("detail-meta").textContent.includes("Run asroot")
      && document.getElementById("detail-meta").textContent.includes("Root wrapper startupConfirmed"),
    "Confirmed root wrapper startup must not claim command execution");
    document.querySelector('#job-rows tr[data-id="synthetic-8"]').click();
    await waitFor(() => document.getElementById("detail").dataset.jobId === "synthetic-8",
      "Inspect root request without execution marker");
    assert(document.getElementById("detail-meta").textContent.includes("Run asroot")
      && document.getElementById("detail-meta").textContent.includes("Root wrapper startupUnconfirmed"),
    "Unconfirmed root start must not be represented as a confirmed root execution");
    document.querySelector('#job-rows tr[data-id="synthetic-11"]').click();
    await waitFor(() => document.getElementById("detail").dataset.jobId === "synthetic-11",
      "Inspect failed root setup with wrapper marker");
    const failureMeta = document.getElementById("detail-meta").textContent;
    assert(failureMeta.includes("StatusFailed") && failureMeta.includes("Run asroot")
      && failureMeta.includes("Root wrapper startupConfirmed")
      && !failureMeta.includes("Root executionConfirmed"),
    "A root setup failure with root_started=true must never claim command execution");
    toggle.click();
    await waitFor(() => document.getElementById("page-summary").textContent.includes("of 251"),
      "Disabling shield restores ordinary and file History records");
    assert(toggle.getAttribute("aria-pressed") === "false"
      && !toggle.classList.contains("is-active"),
    "Disabled shield must return to neutral gray");
  }
  async function checkApprovalControls() {
    const layer = document.getElementById("approval-layer");
    const grant = document.getElementById("approval-grant");
    const duration = (value) => layer.querySelector(
      'input[name="approval-duration"][value="' + value + '"]');
    const chips = document.getElementById("grant-chips");
    assert(layer.hidden && document.querySelector('[role="dialog"][aria-modal="true"]'),
      "Approval dialog must be accessible but initially hidden");
    assert(chips.nextElementSibling?.id === "connection",
      "Active grants belong immediately left of Connected");
    assert(layer.contains(document.getElementById("approval-notifications"))
      && !document.querySelector(".topbar #approval-notifications"),
      "Notification icon must be inside the approval dialog only");
    const mute = document.getElementById("approval-mute");
    mute.click();
    assert(localStorage.getItem("ssh-mcp-console-approval-muted") === "true",
      "Mute preference was not saved");
    assert(mute.classList.contains("is-off") && mute.querySelector(".icon-slash"),
      "Muted icon must be visually crossed");
    mute.click();
    assert(localStorage.getItem("ssh-mcp-console-approval-muted") === "false",
      "Unmute preference was not saved");
    assert(!mute.classList.contains("is-off"), "Enabled sound icon must not be crossed");

    const originalFetch = window.fetch;
    const posts = [];
    let serverRevision = 0, serverPending = [], serverGrants = [];
    let holdRevokeId = null, releaseHeldRevoke = null;
    window.fetch = (path, options) => {
      if (options?.method === "POST" && String(path).startsWith("/console/api/")) {
        posts.push({ path, fields: new URLSearchParams(options.body) });
        if (String(path).endsWith("/revoke")) {
          const grantId = decodeURIComponent(String(path).split("/").at(-2));
          const removed = serverGrants.find((item) => item.id === grantId);
          const nextGrants = serverGrants.filter((item) =>
            item.id !== grantId && !(removed?.kind !== "root"
              && item.kind === "root" && item.scope_id === removed.scope_id));
          const status = removed ? 200 : 404;
          if (removed) {
            serverGrants = nextGrants;
            serverRevision++;
          }
          const reply = new Response(JSON.stringify({
            ...(removed ? { ok: true } : { error: "Grant unavailable or expired" }),
            approval_instance: "browser-fixture-1",
            approval_revision: serverRevision,
            pending_approvals: serverPending, active_grants: serverGrants,
          }), { status, headers: { "Content-Type": "application/json" } });
          if (grantId === holdRevokeId) {
            holdRevokeId = null;
            return new Promise((resolve) => {
              releaseHeldRevoke = () => resolve(reply);
            });
          }
          return Promise.resolve(reply);
        }
        return Promise.resolve(new Response('{"ok":true}', {
          status: 200, headers: { "Content-Type": "application/json" }
        }));
      }
      return originalFetch(path, options);
    };
    try {
      const deadline = Date.now() / 1000 + 28;
      const requests = [
        { id: "synthetic-a", host: "demo-node-a", conversation_id: "dialog-test-A-12345",
          scope_id: "synthetic-session-grant-scope",
          tool: "execute_commands", reason: "synthetic fixture",
          summary: "fallback only", expires_at: deadline,
          steps: [
            { title: "System identity", interpreter: "bash -lc",
              command: "printf 'STEP 1: SYSTEM IDENTITY'\nhostname\n<img src=x onerror=alert(1)>",
              truncated: false },
            { title: "Memory and CPU", interpreter: "bash -lc",
              command: "free -h\ncat /proc/loadavg", truncated: false },
            { title: "Disk checks", interpreter: "bash -lc",
              command: "df -h /\ndf -i /", truncated: false },
            { title: "Service state", interpreter: "bash -lc",
              command: "systemctl is-active ssh", truncated: false },
            { title: "Final verification", interpreter: "bash -lc",
              command: "hostname\npwd", truncated: false },
          ] },
        { id: "synthetic-b", host: "demo-node-b", conversation_id: "dialog-test-B-12345",
          scope_id: "synthetic-other-scope",
          tool: "read_file", reason: "second waiting command",
          summary: "/tmp/synthetic.txt", expires_at: deadline },
      ];
      const send = (revision, pending, grants = []) => {
        if (revision >= serverRevision) {
          serverRevision = revision;
          serverPending = pending;
          serverGrants = grants;
        }
        document.dispatchEvent(new CustomEvent("ssh-mcp-approvals-snapshot", { detail: {
          approval_instance: "browser-fixture-1", approval_revision: revision,
          pending_approvals: pending, active_grants: grants,
        } }));
      };
      send(1, requests);
      await waitFor(() => !layer.hidden && document.getElementById("approval-host").textContent
        === "demo-node-a", "first approval appears in centered dialog");
      const rect = document.querySelector(".approval-modal").getBoundingClientRect();
      assert(Math.abs(rect.left + rect.width / 2 - innerWidth / 2) < 15,
        "Approval modal is not horizontally centered");
      assert(Math.abs(rect.top + rect.height / 2 - innerHeight / 2) < 15,
        "Approval modal is not vertically centered");
      assert(getComputedStyle(document.querySelector(".approval-modal")).backgroundColor
        !== getComputedStyle(document.body).backgroundColor,
      "Approval modal must contrast with history background");
      assert(document.querySelectorAll("#approval-steps details").length === 5
        && document.querySelector("#approval-steps details").open
        && !document.querySelector("#approval-steps details:nth-child(2)").open,
      "Five independent sequential steps must be expandable, first step initially open");
      assert(!document.querySelector("#approval-steps img")
        && document.querySelector("#approval-steps pre").textContent.includes("<img")
        && document.querySelector("#approval-steps pre").textContent.includes("\nhostname\n"),
      "Multiline command preview must preserve lines as inert text only");
      assert(document.getElementById("approval-conversation").textContent === "Conversation #1",
        "Viewer must show local numeric conversation label instead of opaque ID");
      assert(document.getElementById("approval-expiry").textContent.endsWith("s")
        && grant.textContent === "Grant" && document.activeElement === grant,
        "Expiry belongs in the metadata row, not on the Grant button");
      assert([...layer.querySelectorAll('input[name="approval-duration"]')]
        .map((item) => item.value).join(",") === "once,5m,15m,1h,8h,16h",
      "Approval radio duration choices mismatch");
      duration("15m").click();
      send(1, requests);
      assert(duration("15m").checked, "Duplicate snapshots must not reset radio choice");
      // Stale visible History polls must not revert newer SSE state.
      send(2, [requests[1]]);
      send(1, requests);
      assert(document.getElementById("approval-host").textContent === "demo-node-b",
        "Out-of-order poll restored a removed pending request");
      send(3, []);
      send(4, requests);
      document.getElementById("approval-deny").click();
      await waitFor(() => posts.length && document.getElementById("approval-host").textContent
        === "demo-node-b", "Deny advances to second queued request");
      assert(posts[0].path.endsWith("/synthetic-a/deny")
        && posts[0].fields.get("csrf") === "synthetic-csrf",
      "Deny did not use CSRF-protected same-origin POST");
      assert(document.getElementById("approval-summary").textContent.includes("/tmp/synthetic.txt"),
        "Nonbatch file paths must retain safe fallback summary");
      assert(document.getElementById("approval-conversation").textContent === "Conversation #2",
        "Second conversation must use next numeric label");
      duration("8h").click();
      grant.click();
      await waitFor(() => layer.hidden && posts.length === 2,
        "Grant clears the final queued request");
      assert(posts[1].path.endsWith("/synthetic-b/grant")
        && posts[1].fields.get("duration") === "8h",
      "Grant did not send requested duration");
      const timed = [{ id: "synthetic-grant", host: "demo-node-b",
        scope_id: requests[1].scope_id, conversation_id: "dialog-test-B-12345",
        expires_at: Date.now() / 1000 + 453 * 60 + 20 }];
      send(5, [], timed);
      assert(chips.textContent.includes("demo-node-b")
        && chips.textContent.includes("[2]") && chips.textContent.includes("8h")
        && !chips.textContent.includes("dialog-test-B"),
        "Long timed-grant countdown should show rounded whole hours");
      send(6, [], [{ ...timed[0], expires_at: Date.now() / 1000 + 98 * 60 + 20 }]);
      assert(chips.querySelector(".grant-countdown").textContent === "99m",
        "Under 100 minutes should display minutes");
      send(7, [], [{ ...timed[0], expires_at: Date.now() / 1000 + 99 * 60 + 20 }]);
      assert(chips.querySelector(".grant-countdown").textContent === "2h",
        "Above 99 minutes should display rounded whole hours");
      chips.querySelector("button").click();
      await waitFor(() => !chips.children.length && posts.length === 3,
        "Grant chip immediate revoke");
      assert(posts[2].path.endsWith("/synthetic-grant/revoke"),
        "Revoke endpoint was not called");
      const scope = "synthetic-session-grant-scope";
      const sameExpiry = Date.now() / 1000 + 2 * 3600;
      const hostGrant = { id: "synthetic-host-grant", kind: "host",
        scope_id: scope, host: "demo-node-a",
        conversation_id: "dialog-test-A-12345", expires_at: sameExpiry };
      const rootGrant = { id: "synthetic-root-grant", kind: "root",
        scope_id: scope, host: "demo-node-a",
        conversation_id: "dialog-test-A-12345", expires_at: sameExpiry };
      send(8, [], [hostGrant, rootGrant]);
      assert(chips.children.length === 1
        && chips.firstElementChild.classList.contains("grant-chip")
        && !chips.firstElementChild.classList.contains("grant-root")
        && chips.querySelector(".grant-root-detail .root-shield")
        && chips.querySelector(":scope > .grant-chip > .grant-countdown").hidden
        && chips.querySelector(".grant-root-detail .grant-countdown").textContent,
      "Equal lifetime host/root grants must nest red shield with one red countdown");
      assert(chips.querySelectorAll("button").length === 2
        && [...chips.querySelectorAll("button")].some((button) =>
          button.getAttribute("aria-label")?.startsWith("Revoke root"))
        && !chips.textContent.toLowerCase().includes("sudo"),
      "Nested grants need independent red and green revoke controls, without sudo label");
      send(9, [], [hostGrant, { ...rootGrant, scope_id: "different-oauth-session" }]);
      assert(chips.children.length === 2
        && chips.querySelectorAll(".grant-root-detail").length === 1,
      "Grants from different OAuth sessions must never be nested together");
      const longerHost = { ...hostGrant, expires_at: Date.now() / 1000 + 3 * 3600 };
      const shorterRoot = { ...rootGrant, expires_at: Date.now() / 1000 + 15 * 60 };
      send(10, [], [longerHost, shorterRoot]);
      const combined = chips.querySelector('[data-id="synthetic-host-grant"]');
      assert(chips.children.length === 1
        && !combined.querySelector(":scope > .grant-countdown").hidden
        && combined.querySelectorAll(".grant-countdown").length === 2,
      "Longer SSH grant must retain both green and red remaining durations");
      combined.querySelector(".grant-root-detail button").click();
      await waitFor(() => posts.length === 4
        && !chips.querySelector(".grant-root-detail")
        && chips.children.length === 1,
      "Revoking root must leave its green host grant visible");
      assert(posts[3].path.endsWith("/synthetic-root-grant/revoke"),
        "Nested red x must revoke only root access");
      send(11, [], [longerHost, shorterRoot]);
      chips.querySelector('[aria-label^="Revoke host access"]').click();
      await waitFor(() => posts.length === 5 && chips.children.length === 0,
        "Revoking host must immediately clear its nested root grant");
      assert(posts[4].path.endsWith("/synthetic-host-grant/revoke"),
        "Green x must revoke SSH host access");
      const sudoOnly = { ...rootGrant, id: "synthetic-sudo-only",
        scope_id: "no-ssh-grant", host: "demo-node4" };
      send(12, [], [sudoOnly]);
      assert(chips.children.length === 1
        && chips.firstElementChild.classList.contains("grant-root")
        && chips.textContent.includes("demo-node4")
        && chips.querySelector(".grant-root-detail .root-shield")
        && chips.querySelectorAll("button").length === 1
        && chips.querySelector("button").getAttribute("aria-label")
          .startsWith("Revoke root"),
      "Sudo-only approval must show host-named red bubble with no green SSH revoke");
      chips.querySelector("button").click();
      await waitFor(() => posts.length === 6 && chips.children.length === 0,
        "Revoking sudo-only bubble must clear it without affecting connection");
      assert(document.getElementById("connection").textContent === "Connected"
        && posts[5].path.endsWith("/synthetic-sudo-only/revoke"),
      "Sudo-only revocation must not disconnect the viewer");
      // The POST is processed at revision 14 but its HTTP response is held.
      // A fresh host/root grant then arrives at revision 15 via SSE. The
      // older POST must never hide that newer scope, even after a duplicate
      // polling snapshot of the same current revision.
      send(13, [], [longerHost, shorterRoot]);
      holdRevokeId = hostGrant.id;
      chips.querySelector('[aria-label^="Revoke host access"]').click();
      await waitFor(() => typeof releaseHeldRevoke === "function",
        "Synthetic revoke response must be held after server mutation");
      const refreshedHost = { ...longerHost, expires_at: Date.now() / 1000 + 5 * 3600 };
      const refreshedRoot = { ...shorterRoot, expires_at: Date.now() / 1000 + 4 * 3600 };
      send(15, [], [refreshedHost, refreshedRoot]);
      assert(chips.querySelector('[data-id="synthetic-host-grant"] .grant-root-detail'),
        "Newer SSE snapshot should show restored nested root grant");
      releaseHeldRevoke();
      await pause(80);
      assert(chips.querySelector('[data-id="synthetic-host-grant"] .grant-root-detail'),
        "Older revoke POST response hid root grant from newer SSE snapshot");
      send(15, [], [refreshedHost, refreshedRoot]);
      assert(chips.querySelector('[data-id="synthetic-host-grant"] .grant-root-detail'),
        "Duplicate current revision must not suppress active root grant");
      assert(posts[6].path.endsWith("/synthetic-host-grant/revoke"),
        "Deferred revoke must target the prior host grant");
      send(16, [], []);
      send(17, [{ ...requests[0], id: "synthetic-root",
        requires_host: true, requires_root: true,
        expires_at: Date.now() / 1000 + 28 }]);
      await waitFor(() => !layer.hidden && layer.classList.contains("is-root"),
        "Root approval must use the shared dialog");
      assert(duration("16h") && !duration("16h").disabled,
        "16-hour root duration must be selectable");
      duration("16h").click();
      grant.click();
      await waitFor(() => layer.hidden && posts.length === 8,
        "Root grant must close its approval modal");
      assert(posts[7].path.endsWith("/synthetic-root/grant")
        && posts[7].fields.get("duration") === "16h",
        "Root grant did not submit the selected 16-hour duration");
      send(18, [{ ...requests[0], id: "synthetic-expiring",
        expires_at: Date.now() / 1000 + 0.25 }]);
      await waitFor(() => layer.hidden, "Expired approval remains in modal");
      send(19, [{ ...requests[0], id: "synthetic-headerless",
        conversation_id: null, scope_id: null, timed_grants_allowed: false,
        client_id: "https://example.invalid/client.json",
        expires_at: Date.now() / 1000 + 28 }]);
      await waitFor(() => !layer.hidden, "Headerless approval appears");
      assert(duration("once").checked && !duration("once").disabled
        && ["5m", "15m", "1h", "8h", "16h"].every((value) => duration(value).disabled),
      "Missing conversation must disable all timed grant choices");
      assert(!document.getElementById("approval-duration-warning").hidden
        && document.getElementById("approval-duration-warning").textContent.includes("conversation ID")
        && document.getElementById("approval-client").textContent === "https://example.invalid/client.json",
      "Headerless approval must explain the limitation and identify its client");
      grant.click();
      await waitFor(() => layer.hidden && posts.length === 9, "One-shot approval completes");
      assert(posts[8].path.endsWith("/synthetic-headerless/grant")
        && posts[8].fields.get("duration") === "once", "Headerless request sends only once");
      send(21, [{ ...requests[0], id: "synthetic-conversation-again",
        timed_grants_allowed: true, expires_at: Date.now() / 1000 + 28 }]);
      await waitFor(() => !layer.hidden, "Conversation approval appears after headerless");
      assert(!duration("5m").disabled && document.getElementById("approval-duration-warning").hidden,
        "Conversation approval must restore timed options and hide warning");
      send(22, []);
      // Identical raw conversation and host: each authorization scope gets
      // its own label, consistently in the popup and active grant controls.
      const sameConversation = { ...requests[0], id: "synthetic-other-client",
        scope_id: "separate-session-for-same-workflow",
        client_id: "https://other.invalid/client.json",
        expires_at: Date.now() / 1000 + 28 };
      send(23, [sameConversation], [hostGrant]);
      const firstLabel = chips.querySelector(".grant-name").textContent;
      const secondNumber = document.getElementById("approval-conversation").textContent
        .replace("Conversation #", "");
      assert(firstLabel.endsWith("[1]") && secondNumber !== "1" && secondNumber,
        "Popup must distinguish the other session using the same raw conversation");
      send(24, [], [hostGrant, { ...hostGrant, id: "synthetic-other-host-grant",
        scope_id: sameConversation.scope_id }]);
      const labels = [...chips.querySelectorAll(".grant-name")].map((node) => node.textContent);
      const revokeLabels = [...chips.querySelectorAll("button")].map((node) => node.getAttribute("aria-label"));
      assert(labels.length === 2 && new Set(labels).size === 2
        && labels.some((label) => label.endsWith("[" + secondNumber + "]"))
        && new Set(revokeLabels).size === 2,
      "Concurrent grants sharing host/conversation must have distinct matching revoke labels");
      send(25, []);
    } finally {
      window.fetch = originalFetch;
    }
  }
  async function checkCancelFocusAndFilteredPages() {
    const form = document.getElementById("filters");
    const story = form.elements.namedItem("story_id");
    const status = form.elements.namedItem("status");
    const mode = form.elements.namedItem("mode");
    const host = form.elements.namedItem("host");
    const command = form.elements.namedItem("command");
    await fetch("/console/api/test-cancel-start", { cache: "no-store" });
    mode.value = ""; host.value = ""; command.value = "";
    story.value = "269"; status.value = "running";
    status.dispatchEvent(new Event("change", { bubbles: true }));
    await waitFor(() => document.getElementById("page-summary").textContent ===
      "Showing 1–10 of 24", "synthetic active jobs on first filtered page");
    const firstId = "sky269-demo-00";
    const first = document.querySelector(
      '#job-rows tr[data-id="' + firstId + '"] .history-cancel');
    assert(first && first.type === "button",
      "Running status bubble must contain an accessible cancel control");
    first.focus();
    assert(document.activeElement === first, "Cancel button cannot receive focus");
    await fetch("/console/api/test-cancel-touch?id=" + firstId, { cache: "no-store" });
    await waitFor(() => {
      const current = document.querySelector(
        '#job-rows tr[data-id="' + firstId + '"] .history-cancel');
      return current && current !== first && document.activeElement === current;
    }, "polling and first-page refresh preserve cancel keyboard focus");
    document.querySelector('#pagination button[aria-label="Next page"]').click();
    await waitFor(() => document.getElementById("page-summary").textContent ===
      "Showing 11–20 of 24", "second filtered Running page");
    const later = "sky269-demo-11";
    assert(document.querySelector(
      '#job-rows tr[data-id="' + later + '"] .history-cancel'),
      "Second page must expose its active cancellation controls");
    await fetch("/console/api/test-cancel-terminal?id=" + later,
      { cache: "no-store" });
    await waitFor(() => document.getElementById("page-summary").textContent ===
      "Showing 11–20 of 23" &&
      !document.querySelector('#job-rows tr[data-id="' + later + '"]'),
    "second-page terminal update leaves Running filter without stuck Cancelling status");
    assert(!document.getElementById("job-rows").textContent.includes("Cancelling…"),
      "Terminal filtered row left a stale Cancelling… indication");
    await fetch("/console/api/test-cancel-cleanup", { cache: "no-store" });
    story.value = ""; status.value = "";
    status.dispatchEvent(new Event("change", { bubbles: true }));
    await waitFor(() => document.getElementById("page-summary").textContent
      .includes("of 251"), "synthetic cancel fixture removed");
  }
  async function checkSelectedCompletedStepFollowsActiveParent() {
    const form = document.getElementById("filters");
    const story = form.elements.namedItem("story_id");
    const status = form.elements.namedItem("status");
    await fetch("/console/api/test-parent-running", { cache: "no-store" });
    story.value = "232"; status.value = "succeeded";
    status.dispatchEvent(new Event("change", { bubbles: true }));
    await waitFor(() => document.querySelector(
      '#job-rows tr[data-id="synthetic-4"]'),
    "previously completed child visible under Succeeded filter");
    document.querySelector('#job-rows tr[data-id="synthetic-4"]').click();
    await waitFor(() => {
      const meta = document.getElementById("detail-meta").textContent;
      return document.getElementById("detail").dataset.jobId === "synthetic-4"
        && meta.includes("StatusSucceeded")
        && meta.includes("Parent batch outcomeRunning");
    }, "completed child detail displays active parent outcome");
    await fetch("/console/api/test-parent-finished", { cache: "no-store" });
    // No child status change or History change event. Polling must still
    // update selected Details until the parent becomes terminal.
    await waitFor(() => {
      const meta = document.getElementById("detail-meta").textContent;
      return meta.includes("Parent batch outcomeInterrupted")
        && meta.includes("Cancellation requested viaOperator (History)")
        && meta.includes("Cancellation reasonCancelled from History viewer");
    }, "parent terminal outcome and cancellation reason refresh without child event");
  }
  async function checkRetainedBatchRejectionDetails() {
    // Emulate the API's surviving synthetic batch parent after its failed
    // child has been pruned. Exercise the actual shipped renderDetail() path.
    const form = document.getElementById("filters");
    for (const name of ["story_id", "host", "conversation_id", "command", "mode", "status"])
      form.elements.namedItem(name).value = "";
    form.elements.namedItem("time_range").value = "all";
    form.elements.namedItem("mode").dispatchEvent(new Event("change", { bubbles: true }));
    await waitFor(() => document.querySelector('#job-rows tr[data-id="synthetic-3"]'),
      "synthetic command row for retained-batch detail projection");
    const originalFetch = window.fetch;
    window.fetch = (url, options) => {
      if (String(url).split("?")[0].endsWith("/console/api/jobs/synthetic-3")) {
        const job = {
          id: "synthetic-3", server: "demo-node-a", story_id: "TEST-282",
          record_kind: "batch", mode: "batch", status: "failed",
          command: "execute_commands", command_preview: "execute_commands (2 steps)",
          failure_kind: "pre_execution_rejected", output_bytes: 0,
          error: "SSH request rejected before command execution; no batch steps ran",
          request: { reason: "Synthetic retained batch after child retention",
                     total_steps: 2 },
          terminal_command: "execute_commands (2 steps)",
        };
        return Promise.resolve(new Response(JSON.stringify({ job }), {
          status: 200, headers: { "Content-Type": "application/json" },
        }));
      }
      return originalFetch(url, options);
    };
    try {
      document.querySelector('#job-rows tr[data-id="synthetic-3"]').click();
      await waitFor(() => document.getElementById("detail").dataset.jobId ===
        "synthetic-3" && document.getElementById("detail-title").textContent ===
        "Batch request details", "surviving rejected batch detail selected");
      const note = document.getElementById("file-output-note");
      assert(!note.hidden && note.textContent ===
        "SSH request rejected before command execution; no batch command steps executed.",
        "History Details note must describe the proven pre-execution rejection");
      assert(!/approval|scheduling/i.test(note.textContent),
        "History Details note must not mislabel a retained batch as approval/scheduling failure");
      assert(document.getElementById("detail-meta").textContent.includes(
        "pre_execution_rejected"),
        "Batch Details must preserve the durable pre-execution rejection kind");
    } finally {
      window.fetch = originalFetch;
    }
  }
  try {
    await waitFor(() => document.querySelector('#pagination button[aria-label="Last page"]')
      && document.getElementById("page-summary").textContent.includes("of 250"),
    "initial mixed paginated history");
    document.documentElement.style.setProperty("--left-width",
      profile === "narrow" ? "28%" : "48%");
    await waitFor(() => {
      const width = document.getElementById("left-pane").getBoundingClientRect().width;
      return profile === "narrow" ? width <= 380 : width > 610;
    }, "configured pane width");
    await pause(160);
    assertVisibleControls();
    verifyStoryIdTruncation();
    await checkUnicodeStoryFilters();
    await checkMixedHistoryAndKeyboard();
    await checkConversationClickAndClear();
    await checkDetailIsolationAndErrors();
    await checkCompletionDuringOutputFetch();
    assertVisibleControls();
    document.querySelector('#pagination button[aria-label="Last page"]').click();
    await waitFor(() => {
      const page = document.querySelector('#pagination button[aria-current="page"]');
      return page && Number(page.textContent) > 1 &&
        document.getElementById("page-summary").textContent.includes("of 250");
    }, "last numbered history page");
    assertVisibleControls();
    const select = document.getElementById("rows-per-page");
    assert(!select.querySelector('option[value="10"]').disabled,
      "At least ten rows must fit in the selected browser height");
    select.value = "10";
    select.dispatchEvent(new Event("change", { bubbles: true }));
    await waitFor(() => document.getElementById("page-summary").textContent ===
      "Showing 1–10 of 250", "ten-row selector");
    assertVisibleControls();
    document.querySelector('#pagination button[aria-label="Next page"]').click();
    await waitFor(() => document.getElementById("page-summary").textContent ===
      "Showing 11–20 of 250", "next numbered page");
    assertVisibleControls();
    document.querySelector('#pagination button[aria-label="First page"]').click();
    await waitFor(() => document.getElementById("page-summary").textContent ===
      "Showing 1–10 of 250", "first numbered page");
    assertVisibleControls();
    await checkFiltersAndLiveRefresh();
    await checkPrivilegedHistory();
    await checkApprovalControls();
    await checkCancelFocusAndFilteredPages();
    await checkSelectedCompletedStepFollowsActiveParent();
    await checkRetainedBatchRejectionDetails();
    out.textContent = "PASS " + profile;
  } catch (error) {
    out.textContent = "FAIL " + profile + ": " + error.message;
  }
})();
